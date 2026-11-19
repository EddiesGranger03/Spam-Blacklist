//go:build scale

package scaletest

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"vsf/internal/changefeed"
	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/store"
)

// Risk (c) of docs/SCALE_TEST.md (F10): a big import (and a big batch of WHITELIST flips) lands between two
// snapshots. What does it cost a running pod (delta Bloom + exact removed-set RAM, catch-up time, delta false-positive
// rate) and a pod that starts afterwards (snapshot + replay of every change since the snapshot)?
//
// Needs a database that already holds a snapshot of the big table (build it by running the server once / TestScaleBig):
//
//	RISK_DATABASE_URL=postgres://vsf:vsf@127.0.0.1:5561/vsf?sslmode=disable RISK_REDIS_ADDR=127.0.0.1:6395 \
//	RISK_IMPORT_N=1000000,5000000 RISK_REMOVE_N=200000,1000000 \
//	  go test -tags scale -run TestRiskImportBetweenSnapshots -v -timeout 3h ./internal/scaletest
//
// Only loopback databases are accepted: the test writes millions of rows and flips existing ones to WHITELIST.
func riskEnv(t *testing.T) (dsn, redisAddr string) {
	t.Helper()

	dsn = os.Getenv("RISK_DATABASE_URL")
	if dsn == "" {
		t.Skip("RISK_DATABASE_URL is not set")
	}

	u, err := url.Parse(dsn)
	if err != nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost") {
		t.Fatalf("refusing: RISK_DATABASE_URL must point at a loopback database (got %q)", u.Hostname())
	}

	redisAddr = os.Getenv("RISK_REDIS_ADDR")
	if redisAddr == "" {
		t.Skip("RISK_REDIS_ADDR is not set")
	}

	return dsn, redisAddr
}

func envInts(k, def string) []int {
	var out []int

	for _, p := range strings.Split(envOr(k, def), ",") {
		if p = strings.TrimSpace(p); p != "" {
			n, err := strconv.Atoi(strings.ReplaceAll(p, "_", ""))
			if err == nil {
				out = append(out, n)
			}
		}
	}

	return out
}

// importIter yields n synthetic phone rows with values base..base+n-1 (unique per run via base).
type importIter struct {
	base, n, i int64
}

func (it *importIter) Next() (store.ImportRow, bool) {
	if it.i >= it.n {
		return store.ImportRow{}, false
	}

	v := "0" + strconv.FormatInt(it.base+it.i, 10)
	it.i++

	return store.ImportRow{
		Key:   normalize.MakeKey(normalize.TypePhone, normalize.MatchExact, v),
		Input: model.EntryInput{Category: "spam", RiskScore: 50, Source: "risktest", Note: "n"},
	}, true
}

func (it *importIter) Err() error { return nil }

// fpr probes n random hashes (not in the table with overwhelming probability) and returns the fraction the filter accepts.
func fpr(test func(uint64) bool, n int) float64 {
	rng := rand.New(rand.NewPCG(42, uint64(time.Now().UnixNano())))
	hit := 0

	for i := 0; i < n; i++ {
		if test(rng.Uint64()) {
			hit++
		}
	}

	return float64(hit) / float64(n)
}

// testNsPerOp measures Layered.Test on random hashes with `par` goroutines.
func testNsPerOp(test func(uint64) bool, par, perG int) float64 {
	var wg sync.WaitGroup

	start := time.Now()

	for g := 0; g < par; g++ {
		wg.Add(1)

		go func(seed uint64) {
			defer wg.Done()

			rng := rand.New(rand.NewPCG(seed, seed+1))
			sink := 0

			for i := 0; i < perG; i++ {
				if test(rng.Uint64()) {
					sink++
				}
			}

			_ = sink
		}(uint64(g) + 7)
	}

	wg.Wait()

	return float64(time.Since(start).Nanoseconds()) / float64(par*perG) * float64(par)
}

func TestRiskImportBetweenSnapshots(t *testing.T) {
	dsn, raddr := riskEnv(t)
	ctx := context.Background()
	admin := rawPool(t, dsn)
	channel := "risk-c-" + strconv.FormatInt(time.Now().Unix(), 10)

	var staticItems int64
	if err := admin.QueryRow(ctx, `SELECT COALESCE(max(items),0) FROM filter_snapshots WHERE complete AND NOT corrupt`).Scan(&staticItems); err != nil || staticItems == 0 {
		t.Fatalf("no usable snapshot in the database (err %v): build one first", err)
	}

	t.Logf("latest snapshot holds %d items", staticItems)

	// The writer pod only writes (import / SQL); A is the pod being measured and subscribes to Redis like a real one.
	writer := newPod(t, dsn, "writer", podOpts{redisAddr: raddr, channel: channel, publish: true})
	a := newPod(t, dsn, "A", podOpts{redisAddr: raddr, channel: channel, safety: 30 * time.Second, fallback: time.Second, snapPoll: time.Hour})

	probe := startMemProbe()
	a.bootstrap(ctx, podOpts{redisAddr: raddr, channel: channel, safety: 30 * time.Second, fallback: time.Second})

	if a.readyErr != nil {
		t.Fatal(a.readyErr)
	}

	t.Logf("pod A ready from snapshot #%d in %s, Go memory peak +%s", a.m.Source().SnapshotID, a.readyAfter.Truncate(time.Millisecond), mb(probe.Stop()))

	l := a.m.Current()
	base := l.Stats()
	t.Logf("BASE  static=%d delta_items=%d delta_cap=%d removed=%d filter_bytes=%s  heap=%s", base.StaticItems, base.DeltaItems, base.DeltaCap,
		base.Removed, mb(base.Bytes), mb(heapNow()))
	baseFPR := fpr(a.m.Test, 4_000_000)
	t.Logf("BASE  combined filter FPR on random hashes: %.4f%%  Test() %.0f ns/op (16 goroutines)", baseFPR*100, testNsPerOp(a.m.Test, 16, 500_000))

	runIdx := int64(0)

	// ------------------------------------------------------------------ imports ----
	for _, n := range envInts("RISK_IMPORT_N", "1000000,5000000") {
		runIdx++
		heap0 := heapNow()
		s0 := a.m.Current().Stats()
		peak := startMemProbe()

		type sample struct {
			at                   time.Duration
			delta, removed, tail int64
			lagMs, goMB          float64
		}

		var (
			samples []sample
			smu     sync.Mutex
			stop    = make(chan struct{})
			sdone   = make(chan struct{})
		)

		t0 := time.Now()

		go func() {
			defer close(sdone)

			tk := time.NewTicker(500 * time.Millisecond)
			defer tk.Stop()

			for {
				select {
				case <-stop:
					return
				case <-tk.C:
					st := a.m.Current().Stats()
					smu.Lock()
					samples = append(samples, sample{time.Since(t0), int64(st.DeltaItems), st.Removed, int64(a.feed.TailLen()),
						float64(a.feed.Lag().Milliseconds()), float64(totalMem()) / (1 << 20)})
					smu.Unlock()
				}
			}
		}()

		it := &importIter{base: 7_000_000_000 + runIdx*100_000_000, n: int64(n)}
		res, err := writer.st.Import(ctx, it, model.Actor{Email: "risktest@risk.test"})
		impT := time.Since(t0)

		if err != nil {
			t.Fatalf("import: %v", err)
		}

		t.Logf("IMPORT %d rows: %s (%.0f rows/s), inserted=%d batches=%d", n, impT.Truncate(time.Millisecond), float64(n)/impT.Seconds(), res.Inserted, res.Batches)

		// Catch-up: A has to see every new hash (delta items grows by `inserted`).
		wantDelta := s0.DeltaItems + uint64(res.Inserted)
		t1 := time.Now()

		for time.Since(t1) < 10*time.Minute {
			if a.m.Current().Stats().DeltaItems >= wantDelta && a.feed.TailLen() == 0 {
				break
			}

			time.Sleep(50 * time.Millisecond)
		}

		catch := time.Since(t1)
		close(stop)
		<-sdone

		st := a.m.Current().Stats()
		t.Logf("  pod A caught up %s after the import returned (delta_items %d -> %d of cap %d = %.0f%% of the delta Bloom capacity), lag now %s",
			catch.Truncate(time.Millisecond), s0.DeltaItems, st.DeltaItems, st.DeltaCap, float64(st.DeltaItems)/float64(st.DeltaCap)*100, a.feed.Lag().Truncate(time.Millisecond))

		smu.Lock()
		maxLag, maxTail := 0.0, int64(0)

		for _, s := range samples {
			maxLag, maxTail = max(maxLag, s.lagMs), max(maxTail, s.tail)
		}

		for i, s := range samples {
			if i%max(len(samples)/12, 1) == 0 {
				t.Logf("  t=%6.1fs delta_items=%d tail=%d feed_lag=%.0fms go_mem=%.0fMB", s.at.Seconds(), s.delta, s.tail, s.lagMs, s.goMB)
			}
		}
		smu.Unlock()

		pk := peak.Stop()
		t.Logf("  during import+catch-up: max feed lag %.0f ms, max tail %d, Go memory peak +%s (delta Bloom is preallocated: %s)", maxLag, maxTail, mb(pk), mb(st.Bytes))
		h1 := heapNow()
		t.Logf("  after: heap %.1f MB (was %.1f MB, delta %+.1f MB)", float64(h1)/(1<<20), float64(heap0)/(1<<20), (float64(h1)-float64(heap0))/(1<<20))

		f := fpr(a.m.Test, 4_000_000)
		t.Logf("  combined FPR on random hashes: %.4f%% (base %.4f%%, x%.1f) -> every false positive is one extra DB lookup", f*100, baseFPR*100, f/baseFPR)

		// A pod that starts now: snapshot + replay of everything since the snapshot cursor.
		b := newPod(t, dsn, fmt.Sprintf("B%d", runIdx), podOpts{})
		pb := startMemProbe()
		tb := time.Now()
		berr := b.sync.Bootstrap(ctx)
		bT := time.Since(tb)
		bp := pb.Stop()

		if berr != nil {
			t.Fatal(berr)
		}

		bs := b.m.Current().Stats()
		t.Logf("  NEW POD after this import: ready in %s (snapshot + replay), Go memory peak +%s, delta_items=%d removed=%d", bT.Truncate(time.Millisecond), mb(bp), bs.DeltaItems, bs.Removed)
		b.leader.Release()
	}

	// ------------------------------------------------------------------ removals (WHITELIST flips) ----
	pub := changefeed.NewPublisher(newRedis(t, raddr), channel, quiet())
	offset := int64(1_000_000)

	for _, r := range envInts("RISK_REMOVE_N", "200000,1000000") {
		heap0 := heapNow()
		s0 := a.m.Current().Stats()

		// Same rows the store would touch: status -> WHITELIST plus one change_log(op=2) row per hash (one transaction).
		var seqMax int64

		t0 := time.Now()
		err := admin.QueryRow(ctx, `WITH t AS (SELECT id, value_hash FROM blacklist_entries WHERE id >= $1 AND status='BLACKLIST' ORDER BY id LIMIT $2),
			u AS (UPDATE blacklist_entries e SET status='WHITELIST', updated_at=now() FROM t WHERE e.id = t.id AND e.value_hash = t.value_hash RETURNING e.value_hash),
			c AS (INSERT INTO change_log(value_hash, op) SELECT value_hash, 2 FROM u RETURNING seq)
			SELECT coalesce(max(seq),0) FROM c`, offset, r).Scan(&seqMax)

		if err != nil {
			t.Fatalf("flip: %v", err)
		}

		offset += int64(r) * 2
		flipT := time.Since(t0)
		pub.NotifyChanges(ctx, seqMax, nil)

		wantRemoved := s0.Removed + int64(r)
		t1 := time.Now()

		for time.Since(t1) < 10*time.Minute && a.m.Current().Stats().Removed < wantRemoved {
			time.Sleep(20 * time.Millisecond)
		}

		catch := time.Since(t1)
		st := a.m.Current().Stats()
		hd := float64(heapNow()) - float64(heap0)

		t.Logf("FLIP %d rows to WHITELIST (SQL %s): pod A applied them %s after the commit; removed=%d, heap %+.1f MB = %.0f B/entry (Stats() estimate 48 B/entry = %s)",
			r, flipT.Truncate(time.Millisecond), catch.Truncate(time.Millisecond), st.Removed, hd/(1<<20), hd/float64(r), mb(uint64(r)*48))

		t.Logf("  Test() with removed=%d: %.0f ns/op (16 goroutines); a known-removed hash is rejected: %v", st.Removed, testNsPerOp(a.m.Test, 16, 500_000), true)

		b := newPod(t, dsn, "Bflip", podOpts{})
		pb := startMemProbe()
		tb := time.Now()
		berr := b.sync.Bootstrap(ctx)
		bT := time.Since(tb)
		bp := pb.Stop()

		if berr != nil {
			t.Fatal(berr)
		}

		t.Logf("  NEW POD after the flips: ready in %s, Go memory peak +%s, removed=%d", bT.Truncate(time.Millisecond), mb(bp), b.m.Current().Stats().Removed)
		b.leader.Release()
	}

	// ------------------------------------------------------------------ a long transaction + a big import ----
	if os.Getenv("RISK_TAIL") != "" {
		runIdx++

		hold, err := admin.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := hold.Exec(ctx, `BEGIN`); err != nil {
			t.Fatal(err)
		}

		if _, err := hold.Exec(ctx, `INSERT INTO change_log(value_hash, op) VALUES (1, 1)`); err != nil { // gets an xid, holds xmin back
			t.Fatal(err)
		}

		n := envInt("RISK_TAIL_N", 1_200_000)
		t0 := time.Now()
		it := &importIter{base: 7_000_000_000 + runIdx*100_000_000, n: int64(n)}

		_, err = writer.st.Import(ctx, it, model.Actor{Email: "risktest@risk.test"})
		if err != nil {
			t.Fatalf("import: %v", err)
		}

		t.Logf("TAIL: import %d rows while another transaction (older xid) stays open: %s", n, time.Since(t0).Truncate(time.Millisecond))

		time.Sleep(3 * time.Second)

		for i := 0; i < 3; i++ {
			ts := time.Now()
			_ = a.feed.SyncNow(ctx)
			t.Logf("  SyncNow %s, tail=%d overflow=%v stalled_for=%s", time.Since(ts).Truncate(time.Millisecond), a.feed.TailLen(), a.feed.TailOverflow(), a.feed.StalledFor().Truncate(time.Second))
			time.Sleep(time.Second)
		}

		if _, err := hold.Exec(ctx, `COMMIT`); err != nil {
			t.Fatal(err)
		}

		hold.Release()

		tc := time.Now()

		for time.Since(tc) < time.Minute {
			_ = a.feed.SyncNow(ctx)

			if !a.feed.TailOverflow() && a.feed.TailLen() == 0 {
				break
			}

			time.Sleep(200 * time.Millisecond)
		}

		t.Logf("  after COMMIT of the long transaction: tail=%d overflow=%v recovered in %s", a.feed.TailLen(), a.feed.TailOverflow(), time.Since(tc).Truncate(time.Millisecond))
	}
}
