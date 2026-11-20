package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"vsf/internal/changefeed"
	"vsf/internal/filter"
	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/snapshot"
)

// ensureStatusColumn: blacklist_entries.status comes from a migration owned by another change; make the tests here
// independent of merge order. No-op once that migration exists.
func ensureStatusColumn(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.write.Exec(context.Background(),
		`ALTER TABLE blacklist_entries ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'BLACKLIST'`); err != nil {
		t.Fatal(err)
	}

	if _, err := s.write.Exec(context.Background(), `DELETE FROM filter_snapshots`); err != nil {
		t.Fatal(err)
	}
}

func seedSnapPhones(t *testing.T, s *Store, n int) []normalize.Key {
	t.Helper()
	keys := make([]normalize.Key, 0, n)

	for i := 0; i < n; i++ {
		k := mustKey(t, normalize.TypePhone, "", fmt.Sprintf("09%08d", 10_000_000+i))
		if _, err := s.CreateEntry(context.Background(), k, model.EntryInput{Category: "spam"}, actor); err != nil {
			t.Fatal(err)
		}

		keys = append(keys, k)
	}

	return keys
}

func TestScanBlacklistHashesAllPartitionsSkipsWhitelist(t *testing.T) {
	s := newTestStore(t)
	ensureStatusColumn(t, s)
	ctx := context.Background()

	seedSnapPhones(t, s, 500)

	if _, err := s.write.Exec(ctx, `UPDATE blacklist_entries SET status='WHITELIST' WHERE id % 5 = 0`); err != nil {
		t.Fatal(err)
	}

	var want []uint64
	rows, _ := s.write.Query(ctx, `SELECT value_hash FROM blacklist_entries WHERE status='BLACKLIST'`)
	for rows.Next() {
		var h int64
		_ = rows.Scan(&h)
		want = append(want, uint64(h))
	}
	rows.Close()

	old := scanOpts
	SetScanOptions(ScanOptions{Batch: 7, Pause: 0}) // many keyset pages per partition
	t.Cleanup(func() { scanOpts = old })

	var got []uint64
	if err := s.ScanBlacklistHashes(ctx, func(h uint64) { got = append(got, h) }); err != nil {
		t.Fatal(err)
	}

	slices.Sort(want)
	slices.Sort(got)

	if len(want) < 300 || !slices.Equal(want, got) {
		t.Fatalf("scan mismatch: want %d hashes, got %d", len(want), len(got))
	}
}

func TestPGSnapshotRoundTripMultiChunkAndCorruption(t *testing.T) {
	s := newTestStore(t)
	ensureStatusColumn(t, s)
	ctx := context.Background()
	snaps := s.Snapshots()

	if _, _, err := snaps.LoadLatest(ctx); !errors.Is(err, snapshot.ErrNoSnapshot) {
		t.Fatalf("empty: %v", err)
	}

	// ~5.6 MB of fingerprints → 2 chunks of 4 MB.
	keys := make([]uint64, 5_000_000)
	for i := range keys {
		keys[i] = uint64(i)*0x9e3779b97f4a7c15 + 1
	}

	keys = filter.DedupeSorted(keys)
	f, err := filter.BuildBinaryFuse8(keys)
	if err != nil {
		t.Fatal(err)
	}

	pr, pw := io.Pipe()
	go func() {
		_, _, err := snapshot.Encode(pw, f, snaps.Domain(), "4242", 17)
		_ = pw.CloseWithError(err)
	}()

	id, err := snaps.Save(ctx, snapshot.Meta{Kind: snapshot.KindBinaryFuse8, Items: f.Items, CursorXID: "4242", CursorSeq: 17}, pr)
	if err != nil {
		t.Fatal(err)
	}

	if latest, _ := snaps.LatestID(ctx); latest != id {
		t.Fatalf("latest %d != %d", latest, id)
	}

	var chunks int
	_ = s.write.QueryRow(ctx, `SELECT chunks FROM filter_snapshots WHERE id=$1`, id).Scan(&chunks)
	if chunks < 2 {
		t.Fatalf("expected multiple chunks, got %d", chunks)
	}

	meta, rc, err := snaps.LoadLatest(ctx)
	if err != nil {
		t.Fatal(err)
	}

	d, err := snapshot.Decode(rc)
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}

	if d.Checksum != meta.Checksum || meta.CursorXID != "4242" || meta.CursorSeq != 17 || meta.Items != f.Items {
		t.Fatalf("meta %+v decoded checksum %x", meta, d.Checksum)
	}

	for _, k := range keys[:100_000] {
		if !d.Filter.Contains(k) {
			t.Fatal("false negative after Postgres round trip")
		}
	}

	// Corrupt one byte of the second chunk: decode must fail.
	if _, err := s.write.Exec(ctx, `UPDATE filter_snapshot_chunks SET data = set_byte(data, 100, (get_byte(data, 100) # 1))
		WHERE snapshot_id=$1 AND idx=1`, id); err != nil {
		t.Fatal(err)
	}

	_, rc, _ = snaps.LoadLatest(ctx)
	if _, err := snapshot.Decode(rc); !errors.Is(err, snapshot.ErrChecksum) {
		t.Fatalf("corrupt chunk: want checksum error, got %v", err)
	}
	rc.Close()

	// Prune keeps the newest N.
	for i := 0; i < 3; i++ {
		small, _ := filter.BuildBinaryFuse8([]uint64{uint64(i) + 1})
		pr, pw := io.Pipe()
		go func() { _, _, err := snapshot.Encode(pw, small, snaps.Domain(), "1", 1); _ = pw.CloseWithError(err) }()
		if _, err := snaps.Save(ctx, snapshot.Meta{Kind: snapshot.KindBinaryFuse8, Items: 1, CursorXID: "1", CursorSeq: 1}, pr); err != nil {
			t.Fatal(err)
		}
	}

	if n, err := snaps.Prune(ctx, 2); err != nil || n != 2 {
		t.Fatalf("prune deleted %d err=%v", n, err)
	}

	var left, leftChunks int
	_ = s.write.QueryRow(ctx, `SELECT count(*) FROM filter_snapshots`).Scan(&left)
	_ = s.write.QueryRow(ctx, `SELECT count(*) FROM filter_snapshot_chunks WHERE snapshot_id=$1`, id).Scan(&leftChunks)
	if left != 2 || leftChunks != 0 {
		t.Fatalf("after prune: %d snapshots, %d chunks of pruned one", left, leftChunks)
	}
}

func TestPGSnapshotSaveFailureLeavesNothing(t *testing.T) {
	s := newTestStore(t)
	ensureStatusColumn(t, s)
	ctx := context.Background()

	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write(make([]byte, SnapshotChunkSize+10))
		_ = pw.CloseWithError(errors.New("encoder died"))
	}()

	if _, err := s.Snapshots().Save(ctx, snapshot.Meta{Kind: snapshot.KindBinaryFuse8, CursorXID: "1"}, pr); err == nil {
		t.Fatal("expected error")
	}

	var n int
	_ = s.write.QueryRow(ctx, `SELECT count(*) FROM filter_snapshots`).Scan(&n)
	if n != 0 {
		t.Fatal("failed save must roll back completely")
	}
}

func TestAdvisoryLeaderSingleHolder(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	a, b := s.Leader(SnapshotLeaderLockID), s.Leader(SnapshotLeaderLockID)

	if ok, err := a.TryAcquire(ctx); !ok || err != nil {
		t.Fatalf("a: %v %v", ok, err)
	}

	if ok, err := a.TryAcquire(ctx); !ok || err != nil {
		t.Fatal("holder must keep leadership")
	}

	if ok, _ := b.TryAcquire(ctx); ok {
		t.Fatal("two leaders at once")
	}

	a.Release()

	if ok, _ := b.TryAcquire(ctx); !ok {
		t.Fatal("b must take over after a releases")
	}

	b.Release()
}

func TestAdvisoryLeaderLostSessionHandsOver(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	a, b := s.Leader(SnapshotLeaderLockID), s.Leader(SnapshotLeaderLockID)

	if ok, _ := a.TryAcquire(ctx); !ok {
		t.Fatal("a must lead")
	}

	// Kill a's session from the server side (like a network partition / pod crash).
	a.mu.Lock()
	pid := a.conn.Conn().PgConn().PID()
	a.mu.Unlock()

	if _, err := s.write.Exec(ctx, `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if ok, _ := b.TryAcquire(ctx); ok {
			break
		}

		if time.Now().After(deadline) {
			t.Fatal("b never took over after a's session died")
		}

		time.Sleep(50 * time.Millisecond)
	}

	if ok, _ := a.TryAcquire(ctx); ok {
		t.Fatal("a must notice it lost leadership")
	}

	b.Release()
}

// End to end on Postgres: leader full-builds and publishes; changes after; a second pod boots from the snapshot
// (no table scan) and replays change_log after the cursor.
func TestSyncerEndToEndOnPostgres(t *testing.T) {
	s := newTestStore(t)
	ensureStatusColumn(t, s)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	keys := seedSnapPhones(t, s, 50)

	feedA := changefeed.New(s, filter.NewManager(), log)
	leaderA := s.Leader(SnapshotLeaderLockID)
	syncA := snapshot.NewSyncer(s.Snapshots(), feedA, leaderA, log, snapshot.Config{PollEvery: 20 * time.Millisecond})

	if err := syncA.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	defer leaderA.Release()

	if feedA.Filter().Source().SnapshotID == 0 {
		t.Fatal("leader must have published a snapshot")
	}

	extra := mustKey(t, normalize.TypePhone, "", "0988777666")
	if _, err := s.CreateEntry(ctx, extra, model.EntryInput{Category: "spam"}, actor); err != nil {
		t.Fatal(err)
	}

	scanned := &countingSource{Store: s}
	feedB := changefeed.New(scanned, filter.NewManager(), log)
	syncB := snapshot.NewSyncer(s.Snapshots(), feedB, s.Leader(SnapshotLeaderLockID), log, snapshot.Config{PollEvery: 20 * time.Millisecond})

	if err := syncB.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}

	if scanned.scans != 0 {
		t.Fatal("second pod must boot from the snapshot, not scan the table")
	}

	m := feedB.Filter()
	rows, err := s.write.Query(ctx, `SELECT value_hash FROM blacklist_entries`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var h int64
		_ = rows.Scan(&h)
		n++
		if !m.Test(uint64(h)) {
			t.Fatalf("false negative for hash %d", h)
		}
	}

	if n != len(keys)+1 {
		t.Fatalf("expected %d rows, got %d", len(keys)+1, n)
	}
}

type countingSource struct {
	*Store
	scans int
}

func (c *countingSource) ScanBlacklistHashes(ctx context.Context, emit func(uint64)) error {
	c.scans++
	return c.Store.ScanBlacklistHashes(ctx, emit)
}

// FILTER_SCAN_BATCH bị chặn trần MaxScanBatch: trang lớn hơn làm mỗi query quét nặng cho DB.
func TestSetScanOptionsCapsBatch(t *testing.T) {
	old := scanOpts
	t.Cleanup(func() { scanOpts = old })

	for in, want := range map[int]int{0: MaxScanBatch, -1: MaxScanBatch, 3000: 3000, MaxScanBatch: MaxScanBatch, 10000: MaxScanBatch} {
		SetScanOptions(ScanOptions{Batch: in})
		if scanOpts.Batch != want {
			t.Errorf("Batch %d: got %d, want %d", in, scanOpts.Batch, want)
		}
	}
}
