package store

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"vsf/internal/filter"
	"vsf/internal/snapshot"
)

func saveSmallSnapshot(t *testing.T, s *Store, seed uint64) int64 {
	t.Helper()

	keys := make([]uint64, 1000)
	for i := range keys {
		keys[i] = uint64(i)*0x9e3779b97f4a7c15 + seed
	}

	f, err := filter.BuildBinaryFuse8(filter.DedupeSorted(keys))
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if _, _, err := snapshot.Encode(&buf, f, s.Snapshots().Domain(), "7", 1); err != nil {
		t.Fatal(err)
	}

	id, err := s.Snapshots().Save(context.Background(), snapshot.Meta{Kind: snapshot.KindBinaryFuse8, Items: f.Items, CursorXID: "7", CursorSeq: 1}, &buf)
	if err != nil {
		t.Fatal(err)
	}

	return id
}

// F2: MarkCorrupt removes a snapshot from LatestID/ListUsable/Load/LoadLatest; the next older one becomes the latest.
func TestPGSnapshotMarkCorruptHidesItAndListUsableOrder(t *testing.T) {
	s := newTestStore(t)
	ensureStatusColumn(t, s)
	ctx := context.Background()
	snaps := s.Snapshots()

	a, b, c := saveSmallSnapshot(t, s, 1), saveSmallSnapshot(t, s, 2), saveSmallSnapshot(t, s, 3)

	ids, err := snaps.ListUsable(ctx)
	if err != nil || len(ids) != 3 || ids[0] != c || ids[1] != b || ids[2] != a {
		t.Fatalf("ListUsable = %v, %v; want [%d %d %d]", ids, err, c, b, a)
	}

	if err := snaps.MarkCorrupt(ctx, c, "test"); err != nil {
		t.Fatal(err)
	}

	if latest, err := snaps.LatestID(ctx); err != nil || latest != b {
		t.Fatalf("LatestID = %d, %v; want %d", latest, err, b)
	}

	if _, _, err := snaps.Load(ctx, c); !errors.Is(err, snapshot.ErrNoSnapshot) {
		t.Fatalf("Load(corrupt) = %v", err)
	}

	meta, rc, err := snaps.LoadLatest(ctx)
	if err != nil || meta.ID != b {
		t.Fatalf("LoadLatest = %d, %v", meta.ID, err)
	}

	_ = rc.Close()

	// Prune keeps the newest N usable ones; the corrupt row is kept for a day for forensics.
	if n, err := snaps.Prune(ctx, 1); err != nil || n != 1 {
		t.Fatalf("Prune = %d, %v; want 1 (snapshot %d)", n, err, a)
	}

	var corrupt bool
	if err := s.write.QueryRow(ctx, `SELECT corrupt FROM filter_snapshots WHERE id=$1`, c).Scan(&corrupt); err != nil || !corrupt {
		t.Fatalf("flagged row must survive Prune: %v %v", corrupt, err)
	}
}

// F2: a missing chunk is reported as ErrCorrupt (so the syncer flags it), not as a transient error.
func TestPGSnapshotMissingChunkIsCorrupt(t *testing.T) {
	s := newTestStore(t)
	ensureStatusColumn(t, s)
	ctx := context.Background()

	id := saveSmallSnapshot(t, s, 9)
	if _, err := s.write.Exec(ctx, `DELETE FROM filter_snapshot_chunks WHERE snapshot_id=$1`, id); err != nil {
		t.Fatal(err)
	}

	_, rc, err := s.Snapshots().Load(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	if _, err := snapshot.Decode(rc); !errors.Is(err, snapshot.ErrCorrupt) {
		t.Fatalf("Decode over a missing chunk = %v, want ErrCorrupt", err)
	}
}

// F3: with any number of pods asking at once, exactly one request is recorded; handled releases the next one.
func TestPGRebuildRequestIsRecordedOnce(t *testing.T) {
	s := newTestStore(t)
	ensureStatusColumn(t, s)
	ctx := context.Background()
	snaps := s.Snapshots()

	if _, err := s.write.Exec(ctx, `UPDATE filter_rebuild_requests SET requests=0, handled=0`); err != nil {
		t.Fatal(err)
	}

	var recorded atomic.Int32

	var wg sync.WaitGroup

	for range 16 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			if ok, err := snaps.RequestRebuild(ctx); err != nil {
				t.Error(err)
			} else if ok {
				recorded.Add(1)
			}
		}()
	}

	wg.Wait()

	if recorded.Load() != 1 {
		t.Fatalf("%d of 16 concurrent requests were recorded, want exactly 1", recorded.Load())
	}

	req, handled, err := snaps.RebuildState(ctx)
	if err != nil || req != 1 || handled != 0 {
		t.Fatalf("state %d/%d %v", req, handled, err)
	}

	// Still pending: another ask is a no-op.
	if ok, _ := snaps.RequestRebuild(ctx); ok {
		t.Fatal("a request while one is pending must not be recorded")
	}

	if err := snaps.MarkRebuildHandled(ctx, 1); err != nil {
		t.Fatal(err)
	}

	// handled never goes backwards.
	if err := snaps.MarkRebuildHandled(ctx, 0); err != nil {
		t.Fatal(err)
	}

	if _, handled, _ := snaps.RebuildState(ctx); handled != 1 {
		t.Fatalf("handled = %d, want 1", handled)
	}

	if ok, _ := snaps.RequestRebuild(ctx); !ok {
		t.Fatal("after handled catches up a new request must be recorded")
	}
}

var _ io.Reader = (*bytes.Buffer)(nil)
