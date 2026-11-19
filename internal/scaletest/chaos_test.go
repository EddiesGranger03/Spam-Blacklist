//go:build scale

package scaletest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"

	"vsf/internal/changefeed"
	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/snapshot"
	"vsf/internal/store"
)

// ---------------- helpers ----------------

// ensureSnapshot returns once a valid snapshot exists, building it with a leader pod if needed.
func ensureSnapshot(t *testing.T, dsn string, expected uint64) int64 {
	t.Helper()

	admin := rawPool(t, dsn)

	var id int64
	if err := admin.QueryRow(context.Background(), `SELECT COALESCE(max(id),0) FROM filter_snapshots WHERE complete`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	if id > 0 {
		return id
	}

	p := newPod(t, dsn, "snapshot-builder", podOpts{expected: expected})

	start := time.Now()
	p.bootstrap(context.Background(), podOpts{})

	if p.readyErr != nil {
		t.Fatal(p.readyErr)
	}

	// Free the leader lock so the test's own pods can elect themselves.
	p.stop()
	p.stop = nil
	p.leader.Release()

	t.Logf("built base snapshot #%d in %s", p.m.Source().SnapshotID, time.Since(start).Truncate(time.Millisecond))

	return p.m.Source().SnapshotID
}

func phone(prefix string) normalize.Key {
	n := rand.IntN(10_000_000)
	k, err := normalize.NormalizeEntry(normalize.TypePhone, normalize.MatchExact, fmt.Sprintf("%s%07d", prefix, n), "VN")
	if err != nil {
		panic(err)
	}

	return k
}

var actor = model.Actor{Email: "scale-test"}

func in(status string) model.EntryInput {
	return model.EntryInput{Status: status, Category: "spam", RiskScore: 1, Note: "n"}
}

func createUnique(t testing.TB, st *store.Store, prefix string, status string) (model.Entry, normalize.Key) {
	t.Helper()

	for range 20 {
		k := phone(prefix)

		e, err := st.CreateEntry(context.Background(), k, in(status), actor)
		if err == nil {
			return e, k
		}

		if !errors.Is(err, store.ErrDuplicate) {
			t.Fatal(err)
		}
	}

	t.Fatal("could not create a unique entry")

	return model.Entry{}, normalize.Key{}
}

func cleanupEntries(t *testing.T, dsn string) {
	t.Helper()
	t.Cleanup(func() {
		p := rawPool(t, dsn)
		_, _ = p.Exec(context.Background(), `DELETE FROM blacklist_entries WHERE created_by='scale-test'`)
	})
}

// spinUntil busy-polls cond (Windows timers are too coarse for sub-ms measurement) and returns how long it took.
func spinUntil(limit time.Duration, cond func() bool) (time.Duration, bool) {
	start := time.Now()

	for time.Since(start) < limit {
		if cond() {
			return time.Since(start), true
		}

		runtime.Gosched()
	}

	return time.Since(start), false
}

func has(p *pod, k normalize.Key) bool { return p.m.Test(uint64(k.Hash)) } // #nosec G115 -- bit pattern

// tcpProxy is a restartable TCP forwarder used to take Redis "down" without touching the container.
type tcpProxy struct {
	addr, target string

	mu    sync.Mutex
	ln    net.Listener
	conns map[net.Conn]struct{}
}

func startProxy(t *testing.T, target string) *tcpProxy {
	t.Helper()

	p := &tcpProxy{target: target, conns: map[net.Conn]struct{}{}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	p.addr = ln.Addr().String()
	p.serve(ln)
	t.Cleanup(p.down)

	return p
}

func (p *tcpProxy) serve(ln net.Listener) {
	p.mu.Lock()
	p.ln = ln
	p.mu.Unlock()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}

			u, err := net.Dial("tcp", p.target)
			if err != nil {
				_ = c.Close()
				continue
			}

			p.mu.Lock()
			p.conns[c], p.conns[u] = struct{}{}, struct{}{}
			p.mu.Unlock()

			go func() { _, _ = io.Copy(u, c); _ = u.Close(); _ = c.Close() }()
			go func() { _, _ = io.Copy(c, u); _ = u.Close(); _ = c.Close() }()
		}
	}()
}

func (p *tcpProxy) down() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.ln != nil {
		_ = p.ln.Close()
		p.ln = nil
	}

	for c := range p.conns {
		_ = c.Close()
	}

	p.conns = map[net.Conn]struct{}{}
}

func (p *tcpProxy) up(t *testing.T) {
	t.Helper()

	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		t.Fatal(err)
	}

	p.serve(ln)
}

// ---------------- 1. leader killed in the middle of writing a snapshot ----------------

// killReader terminates every "idle in transaction" backend once more than `after` bytes were read, i.e. while Save
// is between two chunk INSERTs: exactly what a kill -9 of the leader pod looks like to Postgres.
type killReader struct {
	r     io.Reader
	n     int
	after int
	kill  func()
	done  bool
}

func (k *killReader) Read(b []byte) (int, error) {
	n, err := k.r.Read(b)
	k.n += n

	if !k.done && k.n > k.after {
		k.done = true
		k.kill()
	}

	return n, err
}

func TestChaosLeaderKilledMidSnapshotWrite(t *testing.T) {
	dsn := scaleDSN(t)
	blacklist := ensureSeed(t, dsn, rowsDefault())
	admin := rawPool(t, dsn)
	ctx := context.Background()

	resetSnapshots(t, admin)
	s1 := ensureSnapshot(t, dsn, uint64(blacklist))

	// Re-encode S1's filter and "write it as S2", killing the writer's session after the first 4 MiB chunk.
	reader := newPod(t, dsn, "reader", podOpts{})
	st := reader.st

	meta, rc, err := st.Snapshots().LoadLatest(ctx)
	if err != nil {
		t.Fatal(err)
	}

	d, err := snapshot.Decode(rc)
	_ = rc.Close()

	if err != nil {
		t.Fatal(err)
	}

	pr, pw := io.Pipe()

	go func() {
		_, _, e := snapshot.Encode(pw, d.Filter, d.Domain, d.CursorXID, d.CursorSeq)
		_ = pw.CloseWithError(e)
	}()

	kr := &killReader{r: pr, after: store.SnapshotChunkSize + 1024, kill: func() {
		tag, err := admin.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity
			WHERE datname = current_database() AND state LIKE 'idle in transaction%' AND pid <> pg_backend_pid()`)
		if err != nil {
			t.Error(err)
		}

		t.Logf("killed %d writer backend(s) between chunk 1 and chunk 2", tag.RowsAffected())
	}}

	_, saveErr := st.Snapshots().Save(ctx, snapshot.Meta{Kind: meta.Kind, Items: d.Filter.Items, CursorXID: d.CursorXID, CursorSeq: d.CursorSeq}, kr)
	_ = pr.CloseWithError(errors.New("save finished"))

	if saveErr == nil {
		t.Fatal("Save must fail when its session is killed mid-write")
	}

	t.Logf("Save returned: %v", saveErr)

	var incomplete, orphanChunks, total int64
	_ = admin.QueryRow(ctx, `SELECT count(*) FILTER (WHERE NOT complete), count(*) FROM filter_snapshots`).Scan(&incomplete, &total)
	_ = admin.QueryRow(ctx, `SELECT count(*) FROM filter_snapshot_chunks WHERE snapshot_id NOT IN (SELECT id FROM filter_snapshots)`).Scan(&orphanChunks)

	t.Logf("after kill: filter_snapshots rows=%d (incomplete=%d), orphan chunks=%d", total, incomplete, orphanChunks)

	if incomplete != 0 || total != 1 || orphanChunks != 0 {
		t.Errorf("the half-written snapshot must be rolled back completely (rows=%d incomplete=%d orphans=%d)", total, incomplete, orphanChunks)
	}

	latest, err := st.Snapshots().LatestID(ctx)
	if err != nil || latest != s1 {
		t.Fatalf("latest snapshot must still be S1=%d, got %d (%v)", s1, latest, err)
	}

	// A pod starting now uses S1, not the torn write.
	p := newPod(t, dsn, "after-kill", podOpts{})
	s0, r0 := tableReads(t, admin)
	p.bootstrap(ctx, podOpts{})

	if p.readyErr != nil {
		t.Fatal(p.readyErr)
	}

	sa, ra := tableReads(t, admin)
	t.Logf("pod after the kill: ready in %s from snapshot #%d (rows read from blacklist_entries: %d)",
		p.readyAfter.Truncate(time.Millisecond), p.m.Source().SnapshotID, ra-r0)

	if p.m.Source().SnapshotID != s1 || sa-s0 != 0 {
		t.Errorf("pod should have loaded S1 without scanning (snapshot=%d queries=%d)", p.m.Source().SnapshotID, sa-s0)
	}

	verifySample(t, p, dsn)
}

// A leader whose Postgres session dies (pod killed, network cut) loses the advisory lock; another pod takes over.
func TestChaosLeaderLockFailover(t *testing.T) {
	dsn := scaleDSN(t)
	admin := rawPool(t, dsn)
	ctx := context.Background()

	a := newPod(t, dsn, "leader-A", podOpts{})
	b := newPod(t, dsn, "candidate-B", podOpts{})

	okA, err := a.leader.TryAcquire(ctx)
	if err != nil || !okA {
		t.Fatalf("A must become leader: %v %v", okA, err)
	}

	if okB, _ := b.leader.TryAcquire(ctx); okB {
		t.Fatal("B must not become leader while A holds the lock")
	}

	var pid int
	if err := admin.QueryRow(ctx, `SELECT pid FROM pg_locks WHERE locktype='advisory' AND objid=$1 AND granted`, int64(store.SnapshotLeaderLockID)).Scan(&pid); err != nil {
		t.Fatal(err)
	}

	killedAt := time.Now()
	if _, err := admin.Exec(ctx, `SELECT pg_terminate_backend($1)`, pid); err != nil {
		t.Fatal(err)
	}

	d, ok := spinUntil(5*time.Second, func() bool { got, _ := b.leader.TryAcquire(ctx); return got })
	if !ok {
		t.Fatal("B never became leader after A's session was killed")
	}

	t.Logf("A's session killed; B took the lock after %s (first TryAcquire after the kill; production polls every FILTER_SNAPSHOT_POLL)", d.Truncate(time.Millisecond))

	if okA, _ := a.leader.TryAcquire(ctx); okA {
		t.Error("A must notice it lost leadership (its session is gone) and not report leader")
	}

	_ = killedAt
}

// ---------------- 2. corrupted snapshots ----------------

func TestChaosCorruptSnapshotFallsBack(t *testing.T) {
	dsn := scaleDSN(t)
	blacklist := ensureSeed(t, dsn, rowsDefault())
	admin := rawPool(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	resetSnapshots(t, admin)
	s1 := ensureSnapshot(t, dsn, uint64(blacklist))

	cases := []struct {
		name    string
		corrupt string
		wantErr error
	}{
		{"flipped byte inside the filter payload", `UPDATE filter_snapshot_chunks SET data = set_byte(data, 5000, get_byte(data, 5000) # 255) WHERE snapshot_id=$1 AND idx=0`, snapshot.ErrChecksum},
		{"last chunk missing (truncated)", `DELETE FROM filter_snapshot_chunks WHERE snapshot_id=$1 AND idx=(SELECT max(idx) FROM filter_snapshot_chunks WHERE snapshot_id=$1)`, nil},
		{"metadata checksum does not match file", `UPDATE filter_snapshots SET checksum = checksum + 1 WHERE id=$1`, snapshot.ErrChecksum},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := admin.Exec(ctx, c.corrupt, s1); err != nil {
				t.Fatal(err)
			}

			// 1. A fresh pod must refuse the snapshot (and say why).
			probe := newPod(t, dsn, "probe", podOpts{})
			used, err := probe.sync.LoadNewer(ctx)
			t.Logf("LoadNewer on the corrupt snapshot: installed=%v err=%v", used, err)

			if used || err == nil {
				t.Fatal("a corrupt snapshot must not be installed")
			}

			if c.wantErr != nil && !errors.Is(err, c.wantErr) {
				t.Errorf("want %v, got %v", c.wantErr, err)
			}

			if probe.m.Ready() {
				t.Fatal("filter must stay not-ready after rejecting a corrupt snapshot")
			}

			// 2. Two pods starting together: one leads and rebuilds from the table, the other waits for the new snapshot.
			p1 := newPod(t, dsn, "pod-1", podOpts{expected: uint64(blacklist)})
			p2 := newPod(t, dsn, "pod-2", podOpts{expected: uint64(blacklist)})
			s0, r0 := tableReads(t, admin)

			var wg sync.WaitGroup

			start := time.Now()

			for _, p := range []*pod{p1, p2} {
				wg.Add(1)

				go func() { defer wg.Done(); p.bootstrap(ctx, podOpts{}) }()
			}

			wg.Wait()

			sa, ra := tableReads(t, admin)

			for _, p := range []*pod{p1, p2} {
				if p.readyErr != nil {
					t.Fatalf("%s: %v", p.name, p.readyErr)
				}

				t.Logf("  %s ready after %s using snapshot #%d", p.name, p.readyAfter.Truncate(time.Millisecond), p.m.Source().SnapshotID)

				if p.m.Source().SnapshotID == s1 {
					t.Errorf("%s used the corrupt snapshot", p.name)
				}
			}

			t.Logf("fallback: both ready in %s; one full scan = %d queries, %d rows", time.Since(start).Truncate(time.Millisecond), sa-s0, ra-r0)
			verifySample(t, p1, dsn)

			// Leave a clean state for the next case.
			p1.stop()
			p2.stop()
			p1.leader.Release()
			p2.leader.Release()
			resetSnapshots(t, admin)
			s1 = ensureSnapshot(t, dsn, uint64(blacklist))
		})
	}
}

// ---------------- 3. pub/sub propagation latency ----------------

func TestChaosPubSubLatency(t *testing.T) {
	dsn := scaleDSN(t)
	blacklist := ensureSeed(t, dsn, rowsDefault())
	addr := redisAddr(t)
	ctx := context.Background()
	cleanupEntries(t, dsn)

	ensureSnapshot(t, dsn, uint64(blacklist))

	ch := fmt.Sprintf("vsf:scale:lat:%d", time.Now().UnixNano())
	oa := podOpts{redisAddr: addr, channel: ch, publish: true, safety: time.Hour}
	ob := podOpts{redisAddr: addr, channel: ch, safety: time.Hour}

	a := newPod(t, dsn, "A", oa)
	b := newPod(t, dsn, "B", ob)

	a.bootstrap(ctx, oa)
	b.bootstrap(ctx, ob)

	if a.readyErr != nil || b.readyErr != nil {
		t.Fatal(a.readyErr, b.readyErr)
	}

	if d, ok := spinUntil(5*time.Second, func() bool { return b.feed.Live() && a.feed.Live() }); !ok {
		t.Fatalf("pods never became live on pub/sub (%s)", d)
	}

	const rounds = 300

	var create, flipOff, flipOn, valueMove, writeDur []time.Duration

	measure := func(label string, write func(), cond func() bool, into *[]time.Duration) {
		t0 := time.Now()
		write()
		wd := time.Since(t0)

		d, ok := spinUntil(3*time.Second, cond)
		if !ok {
			t.Fatalf("%s: B did not converge within 3s", label)
		}

		*into = append(*into, wd+d)
		writeDur = append(writeDur, wd)
	}

	for range rounds {
		var e model.Entry

		var k normalize.Key

		// create (BLACKLIST): B must see the new hash
		measure("create", func() { e, k = createUnique(t, a.st, "095", model.StatusBlacklist) }, func() bool { return has(b, k) }, &create)

		// BLACKLIST -> WHITELIST: B must drop the hash (needs the change_log read, not the message hint)
		measure("to WHITELIST", func() {
			if _, err := a.st.UpdateEntry(ctx, e.ID, in(model.StatusWhitelist), actor); err != nil {
				t.Fatal(err)
			}
		}, func() bool { return !has(b, k) }, &flipOff)

		// WHITELIST -> BLACKLIST: back on
		measure("to BLACKLIST", func() {
			if _, err := a.st.UpdateEntry(ctx, e.ID, in(model.StatusBlacklist), actor); err != nil {
				t.Fatal(err)
			}
		}, func() bool { return has(b, k) }, &flipOn)

		// change the VALUE: old hash must disappear, new hash must appear (one transaction: remove + add)
		var nk normalize.Key

		measure("value change", func() {
			for {
				nk = phone("096")
				if _, err := a.st.UpdateEntryKey(ctx, e.ID, in(model.StatusBlacklist), &nk, actor); err == nil {
					return
				} else if !errors.Is(err, store.ErrDuplicate) {
					t.Fatal(err)
				}
			}
		}, func() bool { return has(b, nk) && !has(b, k) }, &valueMove)
	}

	report := func(name string, d []time.Duration) {
		p50, p90, p99, mx := summarize(d)
		t.Logf("LATENCY %-34s n=%d  p50=%-9s p90=%-9s p99=%-9s max=%s", name, len(d), p50.Truncate(10*time.Microsecond),
			p90.Truncate(10*time.Microsecond), p99.Truncate(10*time.Microsecond), mx.Truncate(10*time.Microsecond))
	}

	report("create -> visible on B", create)
	report("BLACKLIST->WHITELIST -> gone on B", flipOff)
	report("WHITELIST->BLACKLIST -> visible on B", flipOn)
	report("value change -> old gone & new on B", valueMove)
	report("(reference) write call alone (A)", writeDur)

	// Same writes with NO Redis: B only has the 1s fallback poll.
	oc := podOpts{fallback: time.Second}
	c := newPod(t, dsn, "C-no-redis", oc)
	c.bootstrap(ctx, oc)

	var noRedis []time.Duration

	for range 20 {
		_, k := createUnique(t, a.st, "097", model.StatusBlacklist)
		t0 := time.Now()

		if _, ok := spinUntil(5*time.Second, func() bool { return has(c, k) }); !ok {
			t.Fatal("C (no redis) did not converge")
		}

		noRedis = append(noRedis, time.Since(t0))
	}

	report("create -> visible, NO redis (poll 1s)", noRedis)
}

// ---------------- 4. Redis down mid-run, then back ----------------

func TestChaosRedisDownAndRecover(t *testing.T) {
	dsn := scaleDSN(t)
	blacklist := ensureSeed(t, dsn, rowsDefault())
	addr := redisAddr(t)
	ctx := context.Background()
	cleanupEntries(t, dsn)

	ensureSnapshot(t, dsn, uint64(blacklist))

	pxA, pxB := startProxy(t, addr), startProxy(t, addr)
	ch := fmt.Sprintf("vsf:scale:down:%d", time.Now().UnixNano())

	oa := podOpts{redisAddr: pxA.addr, channel: ch, publish: true, safety: time.Hour, fallback: time.Second}
	ob := podOpts{redisAddr: pxB.addr, channel: ch, safety: time.Hour, fallback: time.Second}

	a, b := newPod(t, dsn, "A", oa), newPod(t, dsn, "B", ob)
	a.bootstrap(ctx, oa)
	b.bootstrap(ctx, ob)

	if a.readyErr != nil || b.readyErr != nil {
		t.Fatal(a.readyErr, b.readyErr)
	}

	if _, ok := spinUntil(5*time.Second, b.feed.Live); !ok {
		t.Fatal("B never live")
	}

	// baseline while Redis is up
	t0 := time.Now()
	_, k0 := createUnique(t, a.st, "098", model.StatusBlacklist)

	d0, ok := spinUntil(2*time.Second, func() bool { return has(b, k0) })
	if !ok {
		t.Fatal("baseline write not seen")
	}

	t.Logf("redis UP     : write visible on B after %s (total incl. write %s)", d0.Truncate(10*time.Microsecond), time.Since(t0).Truncate(time.Millisecond))

	// ---- Redis dies for both pods ----
	pxA.down()
	pxB.down()

	dd, ok := spinUntil(10*time.Second, func() bool { return !b.feed.Live() })
	if !ok {
		t.Fatal("B never noticed Redis is down")
	}

	t.Logf("redis DOWN   : B switched to fallback polling after %s", dd.Truncate(time.Millisecond))

	var wdur, seen []time.Duration

	for range 5 {
		tw := time.Now()
		_, k := createUnique(t, a.st, "099", model.StatusBlacklist) // A's publish fails; the write must still succeed
		wdur = append(wdur, time.Since(tw))

		d, ok := spinUntil(5*time.Second, func() bool { return has(b, k) })
		if !ok {
			t.Fatal("B did not converge during the outage: fallback poll is broken")
		}

		seen = append(seen, d)
	}

	_, _, _, wmax := summarize(wdur)
	p50, _, _, smax := summarize(seen)
	t.Logf("redis DOWN   : 5 writes on A all succeeded (slowest write call %s, includes the %s publish timeout); B converged via fallback poll: p50=%s max=%s (poll interval 1s)",
		wmax.Truncate(time.Millisecond), "250ms", p50.Truncate(time.Millisecond), smax.Truncate(time.Millisecond))

	// ---- Redis comes back ----
	pxA.up(t)
	pxB.up(t)

	dl, ok := spinUntil(30*time.Second, b.feed.Live)
	if !ok {
		t.Fatal("B never re-subscribed")
	}

	t.Logf("redis BACK   : B live again after %s (resubscribe backoff)", dl.Truncate(10*time.Millisecond))

	var after []time.Duration

	for range 20 {
		_, k := createUnique(t, a.st, "091", model.StatusBlacklist)

		d, ok := spinUntil(3*time.Second, func() bool { return has(b, k) })
		if !ok {
			t.Fatal("B not converging after Redis recovery")
		}

		after = append(after, d)
	}

	p50, _, p99, _ := summarize(after)
	t.Logf("redis BACK   : propagation after recovery p50=%s p99=%s", p50.Truncate(10*time.Microsecond), p99.Truncate(10*time.Microsecond))
}

// ---------------- 5. lost pub/sub message -> safety poll ----------------

type dropNotifier struct{}

func (dropNotifier) NotifyChanges(context.Context, int64, []model.Change) {}

func TestChaosSafetyPollCatchesLostMessage(t *testing.T) {
	dsn := scaleDSN(t)
	blacklist := ensureSeed(t, dsn, rowsDefault())
	addr := redisAddr(t)
	ctx := context.Background()
	cleanupEntries(t, dsn)

	ensureSnapshot(t, dsn, uint64(blacklist))

	const safety = 2 * time.Second

	ch := fmt.Sprintf("vsf:scale:lost:%d", time.Now().UnixNano())
	ob := podOpts{redisAddr: addr, channel: ch, safety: safety, fallback: time.Hour}

	a := newPod(t, dsn, "A", podOpts{})
	a.st.SetChangeNotifier(dropNotifier{}) // every message is "lost"

	b := newPod(t, dsn, "B", ob)
	b.bootstrap(ctx, ob)

	if b.readyErr != nil {
		t.Fatal(b.readyErr)
	}

	if _, ok := spinUntil(5*time.Second, b.feed.Live); !ok {
		t.Fatal("B never live")
	}

	var got []time.Duration

	for range 8 {
		_, k := createUnique(t, a.st, "092", model.StatusBlacklist)
		t0 := time.Now()

		d, ok := spinUntil(2*safety+time.Second, func() bool { return has(b, k) })
		if !ok {
			t.Fatalf("lost message never recovered by the safety poll (waited %s)", time.Since(t0))
		}

		got = append(got, d)
	}

	p50, _, _, mx := summarize(got)
	t.Logf("LOST MESSAGE : B converged via safety poll (SAFETY_POLL_INTERVAL=%s): p50=%s max=%s over %d writes (bound = interval + one query)",
		safety, p50.Truncate(time.Millisecond), mx.Truncate(time.Millisecond), len(got))

	if mx > safety+500*time.Millisecond {
		t.Errorf("slowest convergence %s exceeds the safety interval %s by more than 500ms", mx, safety)
	}
}

var (
	_ = bytes.MinRead
	_ = changefeed.DefaultChannel
)

// ---------------- 6. snapshot Save keeps failing: does the leader hammer the table? ----------------

// failSave drains the stream like a real Save would, then fails (e.g. disk full on the primary).
type failSave struct{ snapshot.Store }

func (failSave) Save(_ context.Context, _ snapshot.Meta, r io.Reader) (int64, error) {
	_, _ = io.Copy(io.Discard, r)

	return 0, errors.New("simulated: could not write snapshot (disk full)")
}

// TestChaosSaveFailureRescanLoop is the F1 reproduction: the leader can scan but cannot save. Before the fix Bootstrap
// rescanned the table back to back (3.9 scans in 45s); now it must scan once and only retry Save with backoff.
func TestChaosSaveFailureRescanLoop(t *testing.T) {
	dsn := scaleDSN(t)
	blacklist := ensureSeed(t, dsn, rowsDefault())
	admin := rawPool(t, dsn)
	resetSnapshots(t, admin)

	p := newPod(t, dsn, "leader-failing-save", podOpts{expected: uint64(blacklist)})
	s := snapshot.NewSyncer(failSave{p.st.Snapshots()}, p.feed, p.leader, quiet(), snapshot.Config{PollEvery: 250 * time.Millisecond, Expected: uint64(blacklist)})

	s0, r0 := tableReads(t, admin)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)

	defer cancel()

	err := s.Bootstrap(ctx)
	_ = err

	s1, r1 := tableReads(t, admin)
	table := int64(rowsDefault())

	scans := float64(r1-r0) / float64(table)
	t.Logf("SAVE ALWAYS FAILS, 45s of Bootstrap: %d queries, %d rows read from blacklist_entries = %.1f full scans of the table; pod ready=%v; status=%+v",
		s1-s0, r1-r0, scans, p.m.Ready(), s.Status())

	if scans > 1.5 {
		t.Errorf("F1 regression: %.1f full scans while Save keeps failing (want 1: build once, retry only Save)", scans)
	}
}

// ---------------- 7. corrupt snapshot while a leader is already running ----------------

// TestChaosCorruptSnapshotWithLiveLeader: the previous test starts every pod fresh, so one of them becomes leader and
// rebuilds at once. In a real deploy a leader is usually ALREADY running. A pod starting now rejects the corrupt
// snapshot and must wait for that leader, whose rebuild is scheduled by time (FILTER_SNAPSHOT_INTERVAL), not by the
// snapshot being unusable. We shorten the interval to 25s and measure how long the new pod stays not-ready.
func TestChaosCorruptSnapshotWithLiveLeader(t *testing.T) {
	dsn := scaleDSN(t)
	blacklist := ensureSeed(t, dsn, rowsDefault())
	admin := rawPool(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)

	defer cancel()

	resetSnapshots(t, admin)

	const interval = 25 * time.Second

	lo := podOpts{expected: uint64(blacklist), snapEvery: interval}
	leader := newPod(t, dsn, "live-leader", lo)
	leader.bootstrap(ctx, lo)

	if leader.readyErr != nil {
		t.Fatal(leader.readyErr)
	}

	var sid int64

	if err := admin.QueryRow(ctx, `SELECT max(id) FROM filter_snapshots WHERE complete`).Scan(&sid); err != nil {
		t.Fatal(err)
	}

	if _, err := admin.Exec(ctx, `UPDATE filter_snapshot_chunks SET data = set_byte(data, 5000, get_byte(data, 5000) # 255) WHERE snapshot_id=$1 AND idx=0`, sid); err != nil {
		t.Fatal(err)
	}

	corruptAt := time.Now()

	x := newPod(t, dsn, "new-pod", podOpts{expected: uint64(blacklist)})
	x.bootstrap(ctx, podOpts{})

	if x.readyErr != nil {
		t.Fatal(x.readyErr)
	}

	waited := time.Since(corruptAt)
	t.Logf("CORRUPT SNAPSHOT #%d + LIVE LEADER (rebuild interval %s): new pod became ready %s after the corruption, using snapshot #%d (status %+v)",
		sid, interval, waited.Truncate(100*time.Millisecond), x.m.Source().SnapshotID, leader.sync.Status())

	if waited > interval-5*time.Second {
		t.Errorf("F3 regression: the new pod waited %s, i.e. for the scheduled rebuild (%s) instead of a requested one", waited, interval)
	}
}

// ---------------- 8. F2: newest snapshot corrupt, an older good one exists ----------------

// TestChaosCorruptNewestFallsBackToOlder: with two snapshots and the newest corrupt, a new pod starts from the older one
// (plus change_log replay) without reading blacklist_entries, and the bad one is flagged so nobody retries it.
func TestChaosCorruptNewestFallsBackToOlder(t *testing.T) {
	dsn := scaleDSN(t)
	blacklist := ensureSeed(t, dsn, rowsDefault())
	admin := rawPool(t, dsn)
	ctx := context.Background()

	resetSnapshots(t, admin)

	lo := podOpts{expected: uint64(blacklist)}
	l := newPod(t, dsn, "builder", lo)
	l.bootstrap(ctx, lo) // snapshot 1

	if l.readyErr != nil {
		t.Fatal(l.readyErr)
	}

	if err := l.sync.BuildAndPublish(ctx); err != nil { // snapshot 2
		t.Fatal(err)
	}

	l.stop()
	l.stop = nil
	l.leader.Release()

	var older, newest int64

	if err := admin.QueryRow(ctx, `SELECT min(id), max(id) FROM filter_snapshots WHERE complete`).Scan(&older, &newest); err != nil {
		t.Fatal(err)
	}

	if _, err := admin.Exec(ctx, `UPDATE filter_snapshot_chunks SET data = set_byte(data, 5000, get_byte(data, 5000) # 255) WHERE snapshot_id=$1 AND idx=0`, newest); err != nil {
		t.Fatal(err)
	}

	p := newPod(t, dsn, "after-corruption", podOpts{})
	s0, r0 := tableReads(t, admin)
	p.bootstrap(ctx, podOpts{})

	if p.readyErr != nil {
		t.Fatal(p.readyErr)
	}

	s1, r1 := tableReads(t, admin)

	var flagged bool
	_ = admin.QueryRow(ctx, `SELECT corrupt FROM filter_snapshots WHERE id=$1`, newest).Scan(&flagged)

	t.Logf("F2: newest #%d corrupt, older #%d good: pod ready in %s from snapshot #%d; blacklist_entries: %d queries, %d rows; flagged=%v; status=%+v",
		newest, older, p.readyAfter.Truncate(time.Millisecond), p.m.Source().SnapshotID, s1-s0, r1-r0, flagged, p.sync.Status())

	if p.m.Source().SnapshotID != older || r1-r0 != 0 || !flagged {
		t.Errorf("want fallback to #%d with 0 rows read and the bad snapshot flagged", older)
	}

	verifySample(t, p, dsn)
}
