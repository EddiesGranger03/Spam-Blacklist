package store

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"vsf/internal/changefeed"
	"vsf/internal/filter"
	"vsf/internal/seal"
	"vsf/internal/snapshot"
)

// G1: after RotatePepper every value_hash changes. A pod restarted with the new pepper must never install a filter
// snapshot built under the old pepper (its checksum is still valid), or every blacklisted number reads as safe.
func TestSnapshotNotUsedAfterPepperRotation(t *testing.T) {
	s := newTestStore(t)
	ensureStatusColumn(t, s)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	oldSl := s.sealer

	seedSnapPhones(t, s, 40)

	// Pod A (old pepper) publishes a snapshot.
	leaderA := s.Leader(SnapshotLeaderLockID)
	syncA := snapshot.NewSyncer(s.Snapshots(), changefeed.New(s, filter.NewManager(), log), leaderA, log,
		snapshot.Config{PollEvery: 20 * time.Millisecond})
	if err := syncA.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	leaderA.Release()

	// Offline rotation to a new pepper.
	newSl, err := seal.New("0123456789abcdef0123456789abcdef-data", "another-pepper-0123456789abcdef-new", 1)
	if err != nil {
		t.Fatal(err)
	}
	s.SetSealer(newSl)
	t.Cleanup(func() { s.SetSealer(oldSl) })

	if res, err := s.RotatePepper(ctx, actor, PepperRotateOptions{OldBlind: oldSl.Blind}); err != nil || res.Rewritten != 40 || res.SnapshotsDropped != 1 {
		t.Fatalf("rotate: %+v %v", res, err)
	}

	// Pod B restarts with the new pepper.
	leaderB := s.Leader(SnapshotLeaderLockID)
	defer leaderB.Release()
	feedB := changefeed.New(s, filter.NewManager(), log)
	syncB := snapshot.NewSyncer(s.Snapshots(), feedB, leaderB, log, snapshot.Config{PollEvery: 20 * time.Millisecond})
	if err := syncB.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}

	rows, err := s.write.Query(ctx, `SELECT value_hash FROM blacklist_entries`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	n, missed := 0, 0
	for rows.Next() {
		var h int64
		_ = rows.Scan(&h)
		n++
		if !feedB.Filter().Test(uint64(h)) {
			missed++
		}
	}

	if n != 40 || missed != 0 {
		t.Fatalf("after pepper rotation: %d of %d blacklisted hashes are false negatives (snapshot %d)",
			missed, n, feedB.Filter().Source().SnapshotID)
	}
}

// A snapshot of another hash domain is invisible to listing (no rotation run: e.g. a pod started with the wrong
// pepper), and Prune keeps it only for a day so a correct pod can still use it meanwhile.
func TestPGSnapshotsListOnlyOwnDomain(t *testing.T) {
	s := newTestStore(t)
	ensureStatusColumn(t, s)
	ctx := context.Background()
	oldSl := s.sealer

	f, err := filter.BuildBinaryFuse8([]uint64{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}

	pr, pw := io.Pipe()
	go func() { _, _, e := snapshot.Encode(pw, f, s.Snapshots().Domain(), "1", 1); _ = pw.CloseWithError(e) }()

	id, err := s.Snapshots().Save(ctx, snapshot.Meta{Kind: snapshot.KindBinaryFuse8, Items: f.Items, CursorXID: "1", CursorSeq: 1}, pr)
	if err != nil {
		t.Fatal(err)
	}

	if ids, _ := s.Snapshots().ListUsable(ctx); len(ids) != 1 || ids[0] != id {
		t.Fatalf("own domain: %v", ids)
	}

	other, err := seal.New("0123456789abcdef0123456789abcdef-data", "another-pepper-0123456789abcdef-new", 1)
	if err != nil {
		t.Fatal(err)
	}
	s.SetSealer(other)
	t.Cleanup(func() { s.SetSealer(oldSl) })

	if s.Snapshots().Domain() == 0 || s.Snapshots().Domain() == oldSl.FilterDomain() {
		t.Fatal("different peppers must give different, non-zero domains")
	}

	if ids, _ := s.Snapshots().ListUsable(ctx); len(ids) != 0 {
		t.Fatalf("foreign-domain snapshot listed: %v", ids)
	}

	if _, err := s.Snapshots().LatestID(ctx); err != snapshot.ErrNoSnapshot {
		t.Fatalf("LatestID: %v", err)
	}

	if n, _ := s.Snapshots().Prune(ctx, 1); n != 0 {
		t.Fatal("a fresh foreign snapshot must survive Prune")
	}

	_, _ = s.write.Exec(ctx, `UPDATE filter_snapshots SET created_at = now() - interval '2 days' WHERE id=$1`, id)
	if n, _ := s.Snapshots().Prune(ctx, 1); n != 1 {
		t.Fatal("an old foreign snapshot must be pruned")
	}
}
