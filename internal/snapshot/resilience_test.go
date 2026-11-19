package snapshot

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually advanced clock for the Syncer.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newClockSyncer(st Store, feed Installer, l Leader, cfg Config, clk *fakeClock) *Syncer {
	s := NewSyncer(st, feed, l, quiet(), cfg)
	s.now = clk.now
	s.rnd = func() float64 { return 1 } // no jitter: delay = full computed value, keeps assertions exact

	return s
}

func leaderOf() *fakeLeader {
	free := true
	return &fakeLeader{free: &free}
}

// F1: a Save that keeps failing must not rescan the table: the built filter is kept and only Save is retried, with
// an exponential, capped backoff.
func TestF1SaveFailureRetriesSaveOnlyWithBackoff(t *testing.T) {
	ctx := context.Background()
	st := &memStore{saveErr: errors.New("disk full")}
	db := newFakeFeed(1, 2, 3)
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	s := newClockSyncer(st, db, leaderOf(), Config{RetryBase: 10 * time.Second, RetryMax: 40 * time.Second, Interval: time.Hour}, clk)

	var delays []time.Duration

	for range 5 {
		s.Tick(ctx)

		stt := s.Status()
		delays = append(delays, stt.NextAttempt.Sub(clk.now()))

		before := st.saveTry
		s.Tick(ctx) // still inside the backoff window: nothing may happen

		if st.saveTry != before {
			t.Fatalf("Save retried during the backoff window")
		}

		clk.advance(stt.NextAttempt.Sub(clk.now()) + time.Millisecond)
	}

	if db.scans != 1 {
		t.Fatalf("table scanned %d times for 5 failed Saves; want exactly 1", db.scans)
	}

	if st.saveTry != 5 {
		t.Fatalf("Save attempts = %d, want 5", st.saveTry)
	}

	want := []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 40 * time.Second, 40 * time.Second}
	for i := range want {
		if delays[i] != want[i] {
			t.Fatalf("backoff delays %v, want %v (doubling, capped at RetryMax)", delays, want)
		}
	}

	if stt := s.Status(); !stt.PendingSave || stt.SaveFailures != 5 || stt.Consecutive != 5 {
		t.Fatalf("status while failing: %+v", stt)
	}

	// Disk recovers: the held build is saved without another scan, and the failure state clears.
	st.mu.Lock()
	st.saveErr = nil
	st.mu.Unlock()
	s.Tick(ctx)

	if st.saves != 1 || db.scans != 1 {
		t.Fatalf("after recovery: saves=%d scans=%d, want 1 and 1", st.saves, db.scans)
	}

	if stt := s.Status(); stt.PendingSave || stt.Consecutive != 0 || !stt.NextAttempt.IsZero() || stt.SnapshotID != 1 {
		t.Fatalf("status after recovery: %+v", stt)
	}
}

// F1: a failing table scan is also subject to the backoff (the old loop retried every poll).
func TestF1BuildFailureBacksOff(t *testing.T) {
	ctx := context.Background()
	st := &memStore{}
	db := newFakeFeed(1)
	db.scanErr = errors.New("connection refused")
	clk := &fakeClock{t: time.Unix(2_000_000, 0)}
	s := newClockSyncer(st, db, leaderOf(), Config{RetryBase: 30 * time.Second, Interval: time.Hour}, clk)

	s.Tick(ctx)
	s.Tick(ctx)
	s.Tick(ctx)

	if db.scans != 1 {
		t.Fatalf("scans = %d inside the backoff window, want 1", db.scans)
	}

	clk.advance(31 * time.Second)
	s.Tick(ctx)

	if db.scans != 2 || s.Status().BuildFailures != 2 {
		t.Fatalf("scans=%d status=%+v", db.scans, s.Status())
	}
}

// F1: Bootstrap's leader path honours the same backoff (it used to rescan every 5s forever).
func TestF1BootstrapLeaderHonoursBackoff(t *testing.T) {
	st := &memStore{saveErr: errors.New("disk full")}
	db := newFakeFeed(1)
	s := NewSyncer(st, db, leaderOf(), quiet(), Config{PollEvery: 5 * time.Millisecond, RetryBase: time.Hour})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if err := s.Bootstrap(ctx); err == nil {
		t.Fatal("Bootstrap must not succeed while Save fails")
	}

	if db.scans != 1 || st.saveTry != 1 {
		t.Fatalf("Bootstrap retried inside the backoff: scans=%d saveTry=%d (want 1 and 1)", db.scans, st.saveTry)
	}
}

func buildTwo(t *testing.T, st *memStore) (*fakeFeed, *Syncer) {
	t.Helper()

	db := newFakeFeed(1, 2, 3)
	s := NewSyncer(st, db, leaderOf(), quiet(), Config{})

	if err := s.BuildAndPublish(context.Background()); err != nil {
		t.Fatal(err)
	}

	db.write(50, false)

	if err := s.BuildAndPublish(context.Background()); err != nil {
		t.Fatal(err)
	}

	return db, s
}

func corruptSnap(st *memStore, idx int) {
	st.mu.Lock()
	defer st.mu.Unlock()

	b := st.snaps[idx].data
	b[len(b)/2] ^= 0xFF
}

// F2: the newest snapshot is corrupt: flag it, use the next older good one, replay on top; never retry the bad one.
func TestF2FallsBackToOlderSnapshotAndFlagsCorrupt(t *testing.T) {
	ctx := context.Background()
	st := &memStore{}
	db, _ := buildTwo(t, st)
	corruptSnap(st, 1)

	db.write(99, false) // after both cursors: must come from the replay

	other := &fakeFeed{table: db.table, changes: db.changes, m: filtermgr()}
	pod := NewSyncer(st, other, &fakeLeader{free: new(bool)}, quiet(), Config{})

	ok, err := pod.LoadNewer(ctx)
	if err != nil || !ok {
		t.Fatalf("LoadNewer = %v, %v; want it to fall back to snapshot 1", ok, err)
	}

	if other.Filter().Source().SnapshotID != 1 || other.scans != 0 {
		t.Fatalf("source %+v scans %d", other.Filter().Source(), other.scans)
	}

	if !other.Filter().Test(1) || !other.Filter().Test(50) || !other.Filter().Test(99) {
		t.Fatal("older snapshot + replay must still contain everything")
	}

	if !st.snaps[1].corrupt || st.snaps[0].corrupt {
		t.Fatalf("only the corrupt snapshot may be flagged: %+v %+v", st.snaps[0].corrupt, st.snaps[1].corrupt)
	}

	if stt := pod.Status(); stt.Fallbacks != 1 || stt.CorruptMarked != 1 {
		t.Fatalf("status %+v", stt)
	}

	// A second pod never even opens the flagged snapshot.
	before := st.loads
	third := &fakeFeed{table: db.table, changes: db.changes, m: filtermgr()}

	if ok, err := NewSyncer(st, third, &fakeLeader{free: new(bool)}, quiet(), Config{}).LoadNewer(ctx); err != nil || !ok {
		t.Fatalf("third pod: %v %v", ok, err)
	}

	if st.loads-before != 1 {
		t.Fatalf("third pod opened %d snapshots, want 1 (the flagged one must be skipped)", st.loads-before)
	}
}

// F2: if every snapshot is corrupt there is nothing to install; all are flagged.
func TestF2AllCorruptInstallsNothing(t *testing.T) {
	st := &memStore{}
	db, _ := buildTwo(t, st)
	corruptSnap(st, 0)
	corruptSnap(st, 1)

	other := &fakeFeed{table: db.table, changes: db.changes, m: filtermgr()}
	pod := NewSyncer(st, other, &fakeLeader{free: new(bool)}, quiet(), Config{})

	ok, err := pod.LoadNewer(context.Background())
	if ok || err == nil || other.Filter().Ready() {
		t.Fatalf("ok=%v err=%v ready=%v", ok, err, other.Filter().Ready())
	}

	if !st.snaps[0].corrupt || !st.snaps[1].corrupt {
		t.Fatal("both must be flagged")
	}
}

// F2: a transient read error (database down) must not flag a healthy snapshot as corrupt.
func TestF2TransientErrorDoesNotFlag(t *testing.T) {
	st := &memStore{}
	db, _ := buildTwo(t, st)
	st.loadErr = errors.New("connection reset")

	pod := NewSyncer(st, &fakeFeed{table: db.table, changes: db.changes, m: filtermgr()}, &fakeLeader{free: new(bool)}, quiet(), Config{})

	if ok, err := pod.LoadNewer(context.Background()); ok || err == nil {
		t.Fatalf("ok=%v err=%v", ok, err)
	}

	if st.snaps[0].corrupt || st.snaps[1].corrupt {
		t.Fatal("a transient error flagged a good snapshot")
	}
}

// F2: a snapshot older than the change_log retention is skipped, not flagged.
func TestF2StaleIsSkippedNotFlagged(t *testing.T) {
	st := &memStore{}
	db, _ := buildTwo(t, st)
	corruptSnap(st, 1)
	st.snaps[0].meta.CreatedAt = time.Now().Add(-48 * time.Hour)

	pod := NewSyncer(st, &fakeFeed{table: db.table, changes: db.changes, m: filtermgr()}, &fakeLeader{free: new(bool)}, quiet(), Config{})

	ok, err := pod.LoadNewer(context.Background())
	if ok || !errors.Is(err, ErrStale) {
		t.Fatalf("ok=%v err=%v, want ErrStale", ok, err)
	}

	if st.snaps[0].corrupt {
		t.Fatal("a stale snapshot must not be flagged corrupt")
	}
}

// F3: the leader is already running (so nobody else will build) and the newest snapshot is corrupt. Many new pods start:
// each rejects it, together they record ONE request, and the leader builds exactly once and the pods come up.
func TestF3RebuildRequestStormBuildsOnce(t *testing.T) {
	st := &memStore{}
	db := newFakeFeed(1, 2, 3)
	free := true
	leaderLock := &fakeLeader{free: &free}
	lead := NewSyncer(st, db, leaderLock, quiet(), Config{PollEvery: 5 * time.Millisecond, Interval: time.Hour})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := lead.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}

	corruptSnap(st, 0)

	const pods = 6

	feeds := make([]*fakeFeed, pods)

	var wg sync.WaitGroup

	for i := range pods {
		feeds[i] = &fakeFeed{table: db.table, changes: db.changes, m: filtermgr()}
		p := NewSyncer(st, feeds[i], &fakeLeader{free: new(bool)}, quiet(), Config{PollEvery: 5 * time.Millisecond})

		wg.Add(1)

		go func() {
			defer wg.Done()

			if err := p.Bootstrap(ctx); err != nil {
				t.Errorf("pod %d: %v", i, err)
			}
		}()
	}

	done := make(chan struct{})

	go func() { wg.Wait(); close(done) }()

	for waiting := true; waiting; {
		select {
		case <-done:
			waiting = false
		case <-time.After(10 * time.Millisecond):
			lead.Tick(ctx)
		}
	}

	lead.Tick(ctx)
	lead.Tick(ctx)

	if st.saves != 2 {
		t.Fatalf("saves = %d: %d pods asking must cause exactly one extra build", st.saves, pods)
	}

	if st.requests != 1 || st.handled != 1 {
		t.Fatalf("requests=%d handled=%d, want 1 and 1", st.requests, st.handled)
	}

	for i, f := range feeds {
		if f.scans != 0 || !f.Filter().Ready() {
			t.Fatalf("pod %d: scans=%d ready=%v", i, f.scans, f.Filter().Ready())
		}
	}

	if stt := lead.Status(); stt.RebuildServed != 1 || !stt.Leader {
		t.Fatalf("leader status %+v", stt)
	}
}

// F3: a rebuild request does not bypass the failure backoff.
func TestF3RequestStillHonoursBackoff(t *testing.T) {
	ctx := context.Background()
	st := &memStore{saveErr: errors.New("disk full"), requests: 1}
	db := newFakeFeed(1)
	clk := &fakeClock{t: time.Unix(3_000_000, 0)}
	s := newClockSyncer(st, db, leaderOf(), Config{RetryBase: time.Minute, Interval: time.Hour}, clk)

	s.Tick(ctx)
	s.Tick(ctx)
	s.Tick(ctx)

	if st.saveTry != 1 {
		t.Fatalf("saveTry = %d with a pending request and a failing Save; want 1 inside the backoff", st.saveTry)
	}
}

// F4: Status reflects leadership, the installed snapshot and the build/save outcome.
func TestF4Status(t *testing.T) {
	st := &memStore{}
	db := newFakeFeed(1, 2)
	s := NewSyncer(st, db, leaderOf(), quiet(), Config{Interval: 7 * time.Minute})

	if stt := s.Status(); stt.Leader || stt.SnapshotID != 0 {
		t.Fatalf("before bootstrap %+v", stt)
	}

	if err := s.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}

	stt := s.Status()
	if !stt.Leader || stt.SnapshotID != 1 || stt.LastSaveOK.IsZero() || stt.LastBuildOK.IsZero() || stt.SnapshotAt.IsZero() ||
		stt.Interval != 7*time.Minute || stt.Consecutive != 0 || stt.PendingSave {
		t.Fatalf("after bootstrap %+v", stt)
	}
}
