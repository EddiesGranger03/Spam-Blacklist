package snapshot

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"vsf/internal/filter"
)

func keys(n int, seed uint64) []uint64 {
	rng := rand.New(rand.NewPCG(seed, 1))
	k := make([]uint64, n)
	for i := range k {
		k[i] = rng.Uint64()
	}

	return filter.DedupeSorted(k)
}

func build(t *testing.T, k []uint64) *filter.BinaryFuse8 {
	t.Helper()
	f, err := filter.BuildBinaryFuse8(k)
	if err != nil {
		t.Fatal(err)
	}

	return f
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	k := keys(200_000, 1)
	f := build(t, k)

	var buf bytes.Buffer
	sum, size, err := Encode(&buf, f, PlainDomain, "123456", 789)
	if err != nil {
		t.Fatal(err)
	}

	if size != int64(buf.Len()) {
		t.Fatalf("size %d != written %d", size, buf.Len())
	}

	d, err := Decode(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	if d.CursorXID != "123456" || d.CursorSeq != 789 || d.Checksum != sum || d.Kind != KindBinaryFuse8 {
		t.Fatalf("decoded header %+v", d)
	}

	for _, h := range k {
		if !d.Filter.Contains(h) {
			t.Fatal("false negative after round trip")
		}
	}
}

func TestDecodeRejectsCorruption(t *testing.T) {
	f := build(t, keys(10_000, 2))

	var buf bytes.Buffer
	if _, _, err := Encode(&buf, f, PlainDomain, "9", 1); err != nil {
		t.Fatal(err)
	}

	good := buf.Bytes()

	// Flip one bit anywhere in the body (header, fingerprints) or the trailer: must be rejected.
	for _, pos := range []int{5, 20, len(good) / 2, len(good) - 20, len(good) - 1} {
		bad := bytes.Clone(good)
		bad[pos] ^= 0x10

		if _, err := Decode(bytes.NewReader(bad)); err == nil {
			t.Fatalf("corruption at byte %d not detected", pos)
		}
	}

	if _, err := Decode(bytes.NewReader(good[:len(good)/2])); err == nil {
		t.Fatal("truncated snapshot must be rejected")
	}

	bad := bytes.Clone(good)
	bad[len(good)/2] ^= 1
	if _, err := Decode(bytes.NewReader(bad)); !errors.Is(err, ErrChecksum) {
		t.Fatalf("fingerprint corruption should be a checksum error, got %v", err)
	}

	if _, err := Decode(bytes.NewReader(append(bytes.Clone(good), 0))); err == nil {
		t.Fatal("trailing data must be rejected")
	}
}

// --- Syncer with in-memory fakes ---

type memStore struct {
	mu       sync.Mutex
	snaps    []memSnap
	saves    int
	saveErr  error // returned (after draining the stream) while non-nil
	saveTry  int   // Save calls, including failed ones
	loads    int
	loadErr  error // returned by Load while non-nil (a transient failure, not corruption)
	requests int64
	handled  int64
	domain   uint64 // hash domain of this process; 0 = PlainDomain. ListUsable deliberately ignores it (tests the Syncer check)
}

func (m *memStore) Domain() uint64 {
	if m.domain == 0 {
		return PlainDomain
	}

	return m.domain
}

type memSnap struct {
	meta    Meta
	data    []byte
	corrupt bool
}

func (m *memStore) Save(ctx context.Context, meta Meta, r io.Reader) (int64, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.saveTry++

	if m.saveErr != nil {
		return 0, m.saveErr
	}

	m.saves++
	meta.ID = int64(len(m.snaps) + 1)
	meta.CreatedAt = time.Now()
	meta.SizeBytes = int64(len(b))
	m.snaps = append(m.snaps, memSnap{meta: meta, data: b})

	return meta.ID, nil
}

func (m *memStore) ListUsable(ctx context.Context) ([]int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var ids []int64

	for i := len(m.snaps) - 1; i >= 0; i-- {
		if !m.snaps[i].corrupt {
			ids = append(ids, m.snaps[i].meta.ID)
		}
	}

	return ids, nil
}

func (m *memStore) LatestID(ctx context.Context) (int64, error) {
	ids, _ := m.ListUsable(ctx)
	if len(ids) == 0 {
		return 0, ErrNoSnapshot
	}

	return ids[0], nil
}

func (m *memStore) Load(ctx context.Context, id int64) (Meta, io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loads++

	if m.loadErr != nil {
		return Meta{}, nil, m.loadErr
	}

	for _, s := range m.snaps {
		if s.meta.ID == id && !s.corrupt {
			return s.meta, io.NopCloser(bytes.NewReader(s.data)), nil
		}
	}

	return Meta{}, nil, ErrNoSnapshot
}

func (m *memStore) LoadLatest(ctx context.Context) (Meta, io.ReadCloser, error) {
	ids, _ := m.ListUsable(ctx)
	if len(ids) == 0 {
		return Meta{}, nil, ErrNoSnapshot
	}

	return m.Load(ctx, ids[0])
}

func (m *memStore) MarkCorrupt(ctx context.Context, id int64, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for i := range m.snaps {
		if m.snaps[i].meta.ID == id {
			m.snaps[i].corrupt = true
		}
	}

	return nil
}

func (m *memStore) Prune(ctx context.Context, keep int) (int64, error) { return 0, nil }

func (m *memStore) RebuildState(ctx context.Context) (int64, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.requests, m.handled, nil
}

func (m *memStore) RequestRebuild(ctx context.Context) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.requests > m.handled {
		return false, nil
	}

	m.requests++

	return true, nil
}

func (m *memStore) MarkRebuildHandled(ctx context.Context, upTo int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handled = max(m.handled, upTo)

	return nil
}

type fakeLeader struct {
	mu   sync.Mutex
	held bool
	free *bool // shared "lock is free" flag between fake pods
}

func (l *fakeLeader) TryAcquire(ctx context.Context) (bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held {
		return true, nil
	}

	if *l.free {
		*l.free = false
		l.held = true
	}

	return l.held, nil
}

func (l *fakeLeader) Release() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held {
		l.held = false
		*l.free = true
	}
}

// fakeFeed implements Installer: a table of hashes + a change log; Install replays changes after the cursor.
type fakeFeed struct {
	mu      sync.Mutex
	table   map[uint64]bool
	changes []change // seq = index+1
	scans   int
	scanErr error // returned by BuildStatic while non-nil (after counting the scan)
	m       *filter.Manager
	cursor  int64
}

type change struct {
	h      uint64
	remove bool
}

func newFakeFeed(hs ...uint64) *fakeFeed {
	f := &fakeFeed{table: map[uint64]bool{}, m: filter.NewManager()}
	for _, h := range hs {
		f.table[h] = true
	}

	return f
}

func (f *fakeFeed) write(h uint64, remove bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if remove {
		delete(f.table, h)
	} else {
		f.table[h] = true
	}

	f.changes = append(f.changes, change{h, remove})
}

func (f *fakeFeed) BuildStatic(ctx context.Context, _ uint64) (*filter.BinaryFuse8, string, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scans++

	if f.scanErr != nil {
		return nil, "", 0, f.scanErr
	}

	var k []uint64
	for h := range f.table {
		k = append(k, h)
	}

	st, err := filter.BuildBinaryFuse8(filter.DedupeSorted(k))
	return st, "1", int64(len(f.changes)), err
}

func (f *fakeFeed) Install(ctx context.Context, l *filter.Layered, src filter.Source) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.changes[src.CursorSeq:] {
		if c.remove {
			l.Remove(c.h)
		} else {
			l.Add(c.h)
		}
	}

	f.cursor = int64(len(f.changes))
	f.m.Swap(l, src)

	return nil
}

func (f *fakeFeed) sync() {
	f.mu.Lock()
	defer f.mu.Unlock()
	l := f.m.Current()
	for _, c := range f.changes[f.cursor:] {
		if c.remove {
			l.Remove(c.h)
		} else {
			l.Add(c.h)
		}
	}

	f.cursor = int64(len(f.changes))
}

func (f *fakeFeed) Filter() *filter.Manager { return f.m }

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestBootstrapLeaderBuildsOthersLoad(t *testing.T) {
	st := &memStore{}
	free := true
	db := newFakeFeed(1, 2, 3)

	leaderPod := NewSyncer(st, db, &fakeLeader{free: &free}, quiet(), Config{PollEvery: 10 * time.Millisecond})
	if err := leaderPod.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}

	if db.scans != 1 || st.saves != 1 {
		t.Fatalf("leader must scan and save once: scans=%d saves=%d", db.scans, st.saves)
	}

	// Changes after the snapshot cursor, then another pod starts: it must load the snapshot (no scan) and replay.
	db.write(100, false)
	db.write(2, true)

	other := &fakeFeed{table: db.table, changes: db.changes, m: filter.NewManager()}
	pod := NewSyncer(st, other, &fakeLeader{free: &free}, quiet(), Config{PollEvery: 10 * time.Millisecond})

	if err := pod.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}

	if other.scans != 0 {
		t.Fatal("non-leader must not scan the table")
	}

	m := other.Filter()
	if !m.Ready() || !m.Test(1) || !m.Test(3) || !m.Test(100) || m.Test(2) {
		t.Fatal("snapshot + replay after cursor gave the wrong set")
	}

	if m.Source().SnapshotID != 1 {
		t.Fatalf("source %+v", m.Source())
	}
}

func TestBootstrapNonLeaderWaitsForSnapshot(t *testing.T) {
	st := &memStore{}
	free := false // someone else is leader
	db := newFakeFeed(7)

	pod := NewSyncer(st, db, &fakeLeader{free: &free}, quiet(), Config{PollEvery: 5 * time.Millisecond, WaitTimeout: 10 * time.Millisecond})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- pod.Bootstrap(ctx) }()

	time.Sleep(50 * time.Millisecond)

	if db.Filter().Ready() {
		t.Fatal("non-leader must stay not ready without a snapshot")
	}

	if db.scans != 0 {
		t.Fatal("non-leader must not scan")
	}

	// The leader (another pod) publishes.
	other := newFakeFeed(7)
	freeL := true
	if err := NewSyncer(st, other, &fakeLeader{free: &freeL}, quiet(), Config{}).BuildAndPublish(ctx); err != nil {
		t.Fatal(err)
	}

	if err := <-done; err != nil {
		t.Fatal(err)
	}

	if !db.Filter().Ready() || !db.Filter().Test(7) {
		t.Fatal("pod must become ready from the leader's snapshot")
	}
}

func TestStaleSnapshotRefusedAndLeaderRebuilds(t *testing.T) {
	st := &memStore{}
	free := true
	db := newFakeFeed(5)

	s := NewSyncer(st, db, &fakeLeader{free: &free}, quiet(), Config{MaxAge: time.Hour})
	if err := s.BuildAndPublish(context.Background()); err != nil {
		t.Fatal(err)
	}

	st.snaps[0].meta.CreatedAt = time.Now().Add(-2 * time.Hour)

	fresh := newFakeFeed(5)
	pod := NewSyncer(st, fresh, &fakeLeader{free: new(bool)}, quiet(), Config{MaxAge: time.Hour})
	if _, err := pod.LoadNewer(context.Background()); !errors.Is(err, ErrStale) {
		t.Fatalf("want ErrStale, got %v", err)
	}

	if fresh.Filter().Ready() {
		t.Fatal("stale snapshot must not be installed")
	}

	// The leader sees the stale snapshot as overdue and rebuilds on its next tick.
	s2 := NewSyncer(st, newFakeFeed(5), &fakeLeader{free: &free}, quiet(), Config{MaxAge: time.Hour, Interval: time.Hour})
	free = true
	s2.noteBuilt(st.snaps[0].meta.CreatedAt)
	s2.Tick(context.Background())

	if st.saves != 2 {
		t.Fatalf("leader must rebuild an overdue snapshot, saves=%d", st.saves)
	}
}

func TestNewSnapshotSwapsAndResetsDeltaOnlyUpToCursor(t *testing.T) {
	st := &memStore{}
	free := true
	db := newFakeFeed(1, 2)
	leader := NewSyncer(st, db, &fakeLeader{free: &free}, quiet(), Config{})

	if err := leader.BuildAndPublish(context.Background()); err != nil {
		t.Fatal(err)
	}

	pod := &fakeFeed{table: db.table, m: filter.NewManager()}
	podSync := NewSyncer(st, pod, &fakeLeader{free: new(bool)}, quiet(), Config{})
	if err := podSync.Bootstrap(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Changes go into the pod's delta/removed layers.
	db.write(50, false)
	db.write(1, true)
	pod.changes = db.changes
	pod.sync()

	if s := pod.Filter().Current().Stats(); s.DeltaItems != 1 || s.Removed != 1 {
		t.Fatalf("before new snapshot: %+v", s)
	}

	// Leader builds a new snapshot (folds both changes), then one more change happens after its cursor.
	if err := leader.BuildAndPublish(context.Background()); err != nil {
		t.Fatal(err)
	}

	db.write(60, false)
	pod.changes = db.changes

	if ok, err := podSync.LoadNewer(context.Background()); !ok || err != nil {
		t.Fatalf("LoadNewer ok=%v err=%v", ok, err)
	}

	m := pod.Filter()
	if m.Source().SnapshotID != 2 {
		t.Fatalf("not swapped: %+v", m.Source())
	}

	if s := m.Current().Stats(); s.DeltaItems != 1 || s.Removed != 0 {
		t.Fatalf("delta/removed must only hold changes after the new cursor: %+v", s)
	}

	if !m.Test(2) || !m.Test(50) || !m.Test(60) || m.Test(1) {
		t.Fatal("wrong membership after swap")
	}

	if ok, _ := podSync.LoadNewer(context.Background()); ok {
		t.Fatal("same snapshot must not be reinstalled")
	}
}

func TestChecksumMismatchWithMetaRejected(t *testing.T) {
	st := &memStore{}
	free := true
	db := newFakeFeed(1)
	if err := NewSyncer(st, db, &fakeLeader{free: &free}, quiet(), Config{}).BuildAndPublish(context.Background()); err != nil {
		t.Fatal(err)
	}

	st.snaps[0].meta.Checksum = 12345 // metadata disagrees with the file

	pod := newFakeFeed()
	if _, err := NewSyncer(st, pod, &fakeLeader{free: new(bool)}, quiet(), Config{}).LoadNewer(context.Background()); !errors.Is(err, ErrChecksum) {
		t.Fatalf("want checksum error, got %v", err)
	}
}

func filtermgr() *filter.Manager { return filter.NewManager() }
