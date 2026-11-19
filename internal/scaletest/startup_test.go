//go:build scale

package scaletest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"vsf/internal/model"
	"vsf/internal/normalize"
)

func rowsDefault() int { return envInt("SCALE_ROWS", 10_000_000) }

// verifySample checks a spread of real rows against the pod's filter: every sampled BLACKLIST hash must be present
// (no false negative, ever); sampled WHITELIST hashes must be absent apart from the static layer's ~0.4% FPR.
func verifySample(t *testing.T, p *pod, dsn string) {
	t.Helper()

	ctx := context.Background()
	pool := rawPool(t, dsn)

	check := func(status string, wantHit bool) (bad, total int) {
		rows, err := pool.Query(ctx, `SELECT value_hash FROM blacklist_entries WHERE status=$1 AND id % 997 = 0`, status)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()

		for rows.Next() {
			var h int64
			if err := rows.Scan(&h); err != nil {
				t.Fatal(err)
			}

			total++

			if p.m.Test(uint64(h)) != wantHit { // #nosec G115 -- bit pattern
				bad++
			}
		}

		return bad, total
	}

	bad, total := check(model.StatusBlacklist, true)
	if bad != 0 {
		t.Fatalf("%s: %d/%d sampled BLACKLIST hashes missing from the filter (false negatives!)", p.name, bad, total)
	}

	fp, wtotal := check(model.StatusWhitelist, false)
	if wtotal > 0 && float64(fp)/float64(wtotal) > 0.03 {
		t.Fatalf("%s: %d/%d sampled WHITELIST hashes present (>3%%)", p.name, fp, wtotal)
	}

	t.Logf("%s: verified %d BLACKLIST (0 missing) and %d WHITELIST rows (%d false positives)", p.name, total, wtotal, fp)
}

// TestScaleStartup compares a full rebuild from blacklist_entries with a start from a snapshot (+ replay).
//
//	go test -tags scale -run TestScaleStartup -v -timeout 60m ./internal/scaletest
func TestScaleStartup(t *testing.T) {
	dsn := scaleDSN(t)
	blacklist := ensureSeed(t, dsn, rowsDefault())
	admin := rawPool(t, dsn)
	ctx := context.Background()
	expected := uint64(blacklist)

	t.Logf("table: %d BLACKLIST rows (+ whitelist) in blacklist_entries", blacklist)

	// ---- A. full rebuild straight from the table (what every pod did before snapshots) ----
	resetSnapshots(t, admin)

	a := newPod(t, dsn, "full-rebuild", podOpts{expected: expected})
	s0, r0 := tableReads(t, admin)
	probe := startMemProbe()
	t0 := time.Now()

	if err := a.feed.Init(ctx, expected); err != nil {
		t.Fatal(err)
	}

	fullT := time.Since(t0)
	peak := probe.Stop()
	s1, r1 := tableReads(t, admin)

	t.Logf("FULL REBUILD : ready in %s  items=%d  filter=%s  Go peak above baseline=%s  blacklist_entries: %d queries, %d rows read",
		fullT.Truncate(time.Millisecond), a.m.Items(), mb(a.m.SizeBytes()), mb(peak), s1-s0, r1-r0)
	verifySample(t, a, dsn)

	// ---- B. leader builds + publishes a snapshot ----
	lead := newPod(t, dsn, "leader", podOpts{expected: expected})
	s0, r0 = tableReads(t, admin)
	probe = startMemProbe()
	lead.bootstrap(ctx, podOpts{})
	leadPeak := probe.Stop()

	if lead.readyErr != nil {
		t.Fatal(lead.readyErr)
	}

	s1, r1 = tableReads(t, admin)

	var snapID, snapSize int64

	if err := admin.QueryRow(ctx, `SELECT id, size_bytes FROM filter_snapshots WHERE complete ORDER BY id DESC LIMIT 1`).Scan(&snapID, &snapSize); err != nil {
		t.Fatal(err)
	}

	t.Logf("LEADER BUILD : ready in %s (scan+build+save)  snapshot #%d = %s  Go peak above baseline=%s  blacklist_entries: %d queries, %d rows read",
		lead.readyAfter.Truncate(time.Millisecond), snapID, mb(uint64(snapSize)), mb(leadPeak), s1-s0, r1-r0)

	// ---- C. a new pod starts from the snapshot: expect ZERO reads of blacklist_entries ----
	c := newPod(t, dsn, "from-snapshot", podOpts{expected: expected})
	s0, r0 = tableReads(t, admin)
	probe = startMemProbe()
	c.bootstrap(ctx, podOpts{})
	cPeak := probe.Stop()

	if c.readyErr != nil {
		t.Fatal(c.readyErr)
	}

	s1, r1 = tableReads(t, admin)

	t.Logf("FROM SNAPSHOT: ready in %s  items=%d  snapshot id=%d  Go peak above baseline=%s  blacklist_entries: %d queries, %d rows read",
		c.readyAfter.Truncate(time.Millisecond), c.m.Items(), c.m.Source().SnapshotID, mb(cPeak), s1-s0, r1-r0)

	if r1-r0 != 0 || s1-s0 != 0 {
		t.Errorf("starting from a valid snapshot must not touch blacklist_entries; saw %d queries / %d rows", s1-s0, r1-r0)
	}

	verifySample(t, c, dsn)

	// ---- D. snapshot + replay of 1000 changes made after the snapshot ----
	writer := openStore(t, dsn)
	keys := make([]normalize.Key, 0, 500)

	// Rows left by earlier runs would make the creates below fail with ErrDuplicate.
	_, _ = admin.Exec(ctx, `DELETE FROM blacklist_entries WHERE created_by IN ('t', 'scale-test')`)
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DELETE FROM blacklist_entries WHERE created_by IN ('t', 'scale-test')`)
	})

	for i := range 500 {
		k, err := normalize.NormalizeEntry(normalize.TypePhone, normalize.MatchExact, fmt.Sprintf("0933%06d", i), "VN")
		if err != nil {
			t.Fatal(err)
		}

		e, err := writer.CreateEntry(ctx, k, model.EntryInput{Status: model.StatusBlacklist, Category: "spam", RiskScore: 1, Note: "n"}, model.Actor{Email: "scale-test"})
		if err != nil {
			t.Fatal(err)
		}

		if _, err := writer.UpdateEntry(ctx, e.ID, model.EntryInput{Status: model.StatusWhitelist, Category: "spam", RiskScore: 1, Note: "n"}, model.Actor{Email: "scale-test"}); err != nil {
			t.Fatal(err)
		}

		if i%2 == 0 { // flip half of them back so the replay covers add/remove/add
			if _, err := writer.UpdateEntry(ctx, e.ID, model.EntryInput{Status: model.StatusBlacklist, Category: "spam", RiskScore: 1, Note: "n"}, model.Actor{Email: "scale-test"}); err != nil {
				t.Fatal(err)
			}
		}

		keys = append(keys, k)
	}

	d := newPod(t, dsn, "snapshot+replay", podOpts{expected: expected})
	s0, r0 = tableReads(t, admin)
	d.bootstrap(ctx, podOpts{})

	if d.readyErr != nil {
		t.Fatal(d.readyErr)
	}

	s1, r1 = tableReads(t, admin)

	var logRows int64
	_ = admin.QueryRow(ctx, `SELECT count(*) FROM change_log WHERE seq > $1`, c.m.Source().CursorSeq).Scan(&logRows)

	t.Logf("SNAPSHOT+REPLAY: ready in %s after %d change_log rows written since the snapshot cursor; blacklist_entries: %d queries, %d rows read",
		d.readyAfter.Truncate(time.Millisecond), logRows, s1-s0, r1-r0)

	for i, k := range keys {
		want := i%2 == 0 // even index ended BLACKLIST, odd ended WHITELIST

		if got := d.m.Test(uint64(k.Hash)); want && !got { // #nosec G115 -- bit pattern
			t.Fatalf("replayed BLACKLIST hash %d missing after start", i)
		}
	}

	t.Logf("replay verified on %d keys", len(keys))
}

// TestScaleRollingDeploy starts 3 pods at (almost) the same time, first with no snapshot, then with one.
//
//	go test -tags scale -run TestScaleRollingDeploy -v -timeout 60m ./internal/scaletest
func TestScaleRollingDeploy(t *testing.T) {
	dsn := scaleDSN(t)
	blacklist := ensureSeed(t, dsn, rowsDefault())
	admin := rawPool(t, dsn)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	run := func(label string) (pods []*pod, scans, rows int64) {
		resetPods := make([]*pod, 3)
		for i := range resetPods {
			resetPods[i] = newPod(t, dsn, fmt.Sprintf("pod-%d", i+1), podOpts{expected: uint64(blacklist)})
		}

		s0, r0 := tableReads(t, admin)

		var wg sync.WaitGroup

		start := time.Now()

		for i, p := range resetPods {
			wg.Add(1)

			go func() {
				defer wg.Done()
				time.Sleep(time.Duration(i) * 50 * time.Millisecond) // "almost" at the same time
				p.bootstrap(ctx, podOpts{})
			}()
		}

		wg.Wait()

		total := time.Since(start)
		s1, r1 := tableReads(t, admin)

		for _, p := range resetPods {
			if p.readyErr != nil {
				t.Fatalf("%s: %v", p.name, p.readyErr)
			}

			isLeader, _ := p.leader.TryAcquire(ctx)
			t.Logf("  %s: ready after %s  leader=%v  snapshot id=%d items=%d", p.name,
				p.readyAfter.Truncate(time.Millisecond), isLeader, p.m.Source().SnapshotID, p.m.Items())
		}

		t.Logf("%s: all 3 ready in %s; blacklist_entries: %d queries, %d rows read (table has %d BLACKLIST rows)",
			label, total.Truncate(time.Millisecond), s1-s0, r1-r0, blacklist)

		return resetPods, s1 - s0, r1 - r0
	}

	resetSnapshots(t, admin)

	_, _, rows1 := run("NO SNAPSHOT (cold deploy)")

	var nSnap int
	_ = admin.QueryRow(ctx, `SELECT count(*) FROM filter_snapshots WHERE complete`).Scan(&nSnap)

	// Ideal = 1 scan = every row once (~table size incl. whitelist). 3 scans would mean >= 3x.
	tableRows := int64(rowsDefault())
	if rows1 > tableRows*3/2 {
		t.Errorf("cold deploy read %d rows (table %d): more than one pod scanned", rows1, tableRows)
	}

	if nSnap != 1 {
		t.Errorf("expected exactly 1 snapshot after cold deploy, got %d", nSnap)
	}

	_, scans2, rows2 := run("WITH SNAPSHOT (rolling restart)")
	if rows2 != 0 || scans2 != 0 {
		t.Errorf("rolling restart with a valid snapshot must not read blacklist_entries; saw %d queries / %d rows", scans2, rows2)
	}
}
