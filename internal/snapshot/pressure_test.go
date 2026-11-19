package snapshot

import (
	"context"
	"testing"
	"time"

	"vsf/internal/filter"
)

func fillDelta(t *testing.T, m *filter.Manager, n int, base uint64) {
	t.Helper()
	l := m.Current()
	for i := range uint64(n) { // #nosec G115 -- test
		l.Add(base + i)
	}
}

// F10: an import between two scheduled snapshots fills the delta layer; the leader must rebuild early (not wait for
// the 1h interval), but never more often than MinRebuildGap, and never during the F1 backoff.
func TestF10LeaderRebuildsEarlyWhenDeltaFull(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	st := &memStore{}
	db := newFakeFeed(1, 2, 3)
	s := newClockSyncer(st, db, leaderOf(), Config{Interval: time.Hour, PollEvery: time.Millisecond}, clk)

	if err := s.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}
	if db.scans != 1 {
		t.Fatalf("scans = %d", db.scans)
	}

	ctx := context.Background()

	// Below the threshold: no early build.
	fillDelta(t, db.m, filter.MinDeltaCapacity/2, 1<<40)
	clk.advance(10 * time.Minute)
	s.Tick(ctx)
	if db.scans != 1 {
		t.Fatal("rebuilt below the fill threshold")
	}

	// Past 0.7: the leader rebuilds now, 50 minutes before the interval.
	fillDelta(t, db.m, filter.MinDeltaCapacity/4, 2<<40)
	s.Tick(ctx)
	if db.scans != 2 {
		t.Fatalf("leader did not rebuild early when the delta was full (scans=%d)", db.scans)
	}
	if r, _ := db.m.DeltaPressure(); r != 0 {
		t.Fatalf("new snapshot must start with an empty delta, fill=%.3f", r)
	}

	// The import keeps going: the delta fills again right away, but MinRebuildGap (5m default) holds.
	fillDelta(t, db.m, filter.MinDeltaCapacity, 3<<40)
	clk.advance(time.Minute)
	s.Tick(ctx)
	if db.scans != 2 {
		t.Fatal("rebuilt again inside MinRebuildGap (rebuild storm)")
	}

	clk.advance(4 * time.Minute)
	s.Tick(ctx)
	if db.scans != 3 {
		t.Fatalf("no rebuild once the gap passed (scans=%d)", db.scans)
	}
	if got := s.Status().PressureBuilds; got != 2 {
		t.Fatalf("PressureBuilds = %d, want 2", got)
	}
}

func TestF10LeaderRebuildsWhenRemovedSetLarge(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	db := newFakeFeed(1)
	s := newClockSyncer(&memStore{}, db, leaderOf(), Config{Interval: time.Hour, RemovedRebuildMax: 100}, clk)

	if err := s.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}

	l := db.m.Current()
	for i := range uint64(100) {
		l.Remove(i + 10)
	}

	clk.advance(10 * time.Minute)
	s.Tick(context.Background())
	if db.scans != 2 {
		t.Fatalf("removed-set past its limit must trigger a rebuild (scans=%d)", db.scans)
	}
}

func TestF10PressureRebuildHonoursBackoff(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	db := newFakeFeed(1)
	s := newClockSyncer(&memStore{}, db, leaderOf(), Config{Interval: time.Hour, RetryBase: time.Hour, RetryMax: time.Hour}, clk)

	if err := s.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}

	fillDelta(t, db.m, filter.MinDeltaCapacity, 1<<40)
	db.scanErr = context.DeadlineExceeded
	clk.advance(10 * time.Minute)
	s.Tick(context.Background()) // fails, arms 1h backoff
	clk.advance(10 * time.Minute)
	s.Tick(context.Background())
	if db.scans != 3-1 {
		t.Fatalf("pressure rebuild ignored the failure backoff (scans=%d)", db.scans)
	}
}

func TestF10DisabledByZeroRatio(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	db := newFakeFeed(1)
	s := newClockSyncer(&memStore{}, db, leaderOf(), Config{Interval: time.Hour, DeltaRebuildRatio: -1, RemovedRebuildMax: -1}, clk)

	if err := s.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}

	fillDelta(t, db.m, filter.MinDeltaCapacity*2, 1<<40)
	clk.advance(10 * time.Minute)
	s.Tick(context.Background())
	if db.scans != 1 {
		t.Fatal("negative ratio must disable pressure rebuilds")
	}
}
