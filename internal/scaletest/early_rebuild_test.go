//go:build scale

package scaletest

import (
	"context"
	"strconv"
	"testing"
	"time"

	"vsf/internal/model"
)

// TestRiskImportEarlyRebuild is scenario (c) after the F10 fix, scaled down: one import larger than the delta layer
// between two scheduled snapshots. Pod L is the leader with the early rebuild on (ratio 0.7); pod A is a control that
// never refreshes (the behaviour before the fix). Both follow the change feed over Redis.
//
//	RISK_DATABASE_URL, RISK_REDIS_ADDR as for the other risk tests; RISK_EARLY_N rows to import (default 1500000).
func TestRiskImportEarlyRebuild(t *testing.T) {
	dsn, raddr := riskEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	if err := openStore(t, dsn).Migrate(ctx); err != nil { // a fresh database needs the schema
		t.Fatal(err)
	}

	channel := "risk-f10-" + strconv.FormatInt(time.Now().Unix(), 10)
	n := envInts("RISK_EARLY_N", "1500000")[0]

	writer := newPod(t, dsn, "writer", podOpts{redisAddr: raddr, channel: channel, publish: true})

	lo := podOpts{redisAddr: raddr, channel: channel, safety: 30 * time.Second, fallback: time.Second,
		snapPoll: 500 * time.Millisecond, snapEvery: 24 * time.Hour, rebuildRatio: 0.7, rebuildGap: 20 * time.Second}
	l := newPod(t, dsn, "L", lo)
	l.bootstrap(ctx, lo)
	if l.readyErr != nil {
		t.Fatal(l.readyErr)
	}

	ao := podOpts{redisAddr: raddr, channel: channel, safety: 30 * time.Second, fallback: time.Second,
		snapPoll: time.Hour, snapEvery: 24 * time.Hour, rebuildRatio: -1}
	a := newPod(t, dsn, "A", ao)
	a.bootstrap(ctx, ao)
	if a.readyErr != nil {
		t.Fatal(a.readyErr)
	}

	if !l.sync.Status().Leader {
		t.Fatal("pod L must be the snapshot leader (another leader holds the lock?)")
	}

	s0 := l.m.Current().Stats()
	t.Logf("BASE static=%d delta_cap=%d  FPR L=%.4f%% A=%.4f%%", s0.StaticItems, s0.DeltaCap, fpr(l.m.Test, 2_000_000)*100, fpr(a.m.Test, 2_000_000)*100)

	snap0 := l.m.Source().SnapshotID
	t0 := time.Now()
	it := &importIter{base: 8_000_000_000 + time.Now().Unix()%1000*1_000_000, n: int64(n)}
	res, err := writer.st.Import(ctx, it, model.Actor{Email: "risktest@risk.test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("IMPORT %d rows in %s, inserted=%d", n, time.Since(t0).Truncate(time.Millisecond), res.Inserted)

	// A (control) catches up on every new hash; L may have rebuilt meanwhile, so wait for its pressure to settle.
	for deadline := time.Now().Add(5 * time.Minute); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if a.m.Current().Stats().DeltaItems >= s0.DeltaItems+uint64(res.Inserted) && a.feed.TailLen() == 0 {
			break
		}
	}
	// Let the leader finish a last early rebuild if the tail of the import pushed it past the ratio again.
	for deadline := time.Now().Add(lo.rebuildGap + 30*time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		if r, _ := l.m.DeltaPressure(); r < 0.7 {
			break
		}
	}

	ra, _ := a.m.DeltaPressure()
	rl, _ := l.m.DeltaPressure()
	st := l.sync.Status()
	t.Logf("AFTER control A: delta fill %.0f%%, FPR %.4f%% (snapshot #%d)", ra*100, fpr(a.m.Test, 2_000_000)*100, a.m.Source().SnapshotID)
	t.Logf("AFTER leader  L: delta fill %.0f%%, FPR %.4f%% (snapshot #%d -> #%d, pressure builds %d)", rl*100, fpr(l.m.Test, 2_000_000)*100,
		snap0, l.m.Source().SnapshotID, st.PressureBuilds)

	if st.PressureBuilds == 0 || rl >= 0.7 {
		t.Fatalf("leader did not rebuild early: pressure builds %d, fill %.2f", st.PressureBuilds, rl)
	}
}
