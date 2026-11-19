//go:build scale

package scaletest

import (
	"context"
	"io"
	"math/rand/v2"
	"os"
	"testing"
	"time"

	"vsf/internal/snapshot"
)

// TestScaleBig measures the largest table this machine can take, one N per invocation (SCALE_BIG_N, seeded
// incrementally so raising N reuses the rows already there). Use a dedicated database (SCALE_DATABASE_URL ending in
// _test) and SCALE_LEAN=1: rows keep the real column types and the id index the scan walks, but the sealed columns are
// 1 byte and the unique index is not created, so 100M rows fit in ~11 GB of disk instead of ~36 GB.
//
//	SCALE_LEAN=1 SCALE_BIG_N=30000000 go test -tags scale -run TestScaleBig -v -timeout 3h ./internal/scaletest
func TestScaleBig(t *testing.T) {
	n := envInt("SCALE_BIG_N", 0)
	if n == 0 {
		t.Skip("SCALE_BIG_N is not set")
	}

	dsn := scaleDSN(t)
	admin := rawPool(t, dsn)
	ctx := context.Background()

	t0 := time.Now()
	blacklist := ensureSeed(t, dsn, n)
	seedT := time.Since(t0)

	var tableBytes int64
	_ = admin.QueryRow(ctx, `SELECT pg_total_relation_size('blacklist_entries')`).Scan(&tableBytes)

	var rows int64
	_ = admin.QueryRow(ctx, `SELECT count(*) FROM blacklist_entries`).Scan(&rows)

	t.Logf("TABLE: %d rows (%d BLACKLIST), %s on disk (%.0f B/row incl. indexes); seed/check step took %s (0 if already seeded)",
		rows, blacklist, mb(uint64(tableBytes)), float64(tableBytes)/float64(rows), seedT.Truncate(time.Second))

	resetSnapshots(t, admin)

	// ---- leader: scan + sort + build, then encode + save (timed separately) ----
	l := newPod(t, dsn, "leader", podOpts{expected: uint64(blacklist)})

	s0, r0 := tableReads(t, admin)
	probe := startMemProbe()
	t0 = time.Now()

	static, xid, seq, err := l.feed.BuildStatic(ctx, uint64(blacklist))
	if err != nil {
		t.Fatal(err)
	}

	buildT := time.Since(t0)
	peak := probe.Stop()
	s1, r1 := tableReads(t, admin)

	t.Logf("LEADER BUILD: scan+sort+build %s; Go peak above baseline %s (%.1f B/key); filter %s (%.2f B/key); items=%d; blacklist_entries: %d queries, %d rows read",
		buildT.Truncate(time.Millisecond), mb(peak), float64(peak)/float64(static.Items), mb(static.SizeBytes()),
		float64(static.SizeBytes())/float64(static.Items), static.Items, s1-s0, r1-r0)

	pr, pw := io.Pipe()

	go func() {
		_, _, e := snapshot.Encode(pw, static, l.st.Snapshots().Domain(), xid, seq)
		_ = pw.CloseWithError(e)
	}()

	t0 = time.Now()

	id, err := l.st.Snapshots().Save(ctx, snapshot.Meta{Kind: snapshot.KindBinaryFuse8, Items: static.Items, CursorXID: xid, CursorSeq: seq}, pr)
	if err != nil {
		t.Fatal(err)
	}

	saveT := time.Since(t0)

	var size, chunks int64
	_ = admin.QueryRow(ctx, `SELECT size_bytes, chunks FROM filter_snapshots WHERE id=$1`, id).Scan(&size, &chunks)
	t.Logf("SNAPSHOT SAVE: #%d %s in %d chunks, encode+save %s", id, mb(uint64(size)), chunks, saveT.Truncate(time.Millisecond))

	// ---- FPR of the built static layer (the same bytes a pod will load) ----
	neg := rand.New(rand.NewPCG(0xfeed, uint64(n)))
	fp := 0

	for range fprProbes {
		if static.Contains(neg.Uint64()) {
			fp++
		}
	}

	t.Logf("FPR: %.4f%% (%d / %d probes)", float64(fp)/fprProbes*100, fp, fprProbes)

	static = nil // the leader's copy is not needed any more: measure the pod's own footprint below

	// ---- a new pod starts from the snapshot ----
	pod := newPod(t, dsn, "from-snapshot", podOpts{expected: uint64(blacklist)})
	s0, r0 = tableReads(t, admin)
	probe = startMemProbe()
	pod.bootstrap(ctx, podOpts{})

	if pod.readyErr != nil {
		t.Fatal(pod.readyErr)
	}

	loadPeak := probe.Stop()
	s1, r1 = tableReads(t, admin)

	t.Logf("POD FROM SNAPSHOT: ready in %s; Go peak above baseline %s; resident filter %s; items=%d; blacklist_entries: %d queries, %d rows read",
		pod.readyAfter.Truncate(time.Millisecond), mb(loadPeak), mb(pod.m.SizeBytes()), pod.m.Items(), s1-s0, r1-r0)

	if r1-r0 != 0 {
		t.Errorf("pod from snapshot read %d rows", r1-r0)
	}

	t.Logf("resident Go heap after load (GC'd): %s", mb(heapNow()))

	verifySample(t, pod, dsn)
}

// TestScaleBigScanOnly times the leader's table scan (store.ScanBlacklistHashes) over the whole table WITHOUT keeping the
// hashes, so it needs almost no RAM. It is how the scan cost is measured at an N whose build does not fit in memory.
func TestScaleBigScanOnly(t *testing.T) {
	if os.Getenv("SCALE_BIG_SCAN") == "" {
		t.Skip("SCALE_BIG_SCAN is not set")
	}

	dsn := scaleDSN(t)
	admin := rawPool(t, dsn)
	st := openStore(t, dsn)

	s0, r0 := tableReads(t, admin)
	probe := startMemProbe()
	t0 := time.Now()

	var n uint64

	var xor uint64

	if err := st.ScanBlacklistHashes(context.Background(), func(h uint64) { n++; xor ^= h }); err != nil {
		t.Fatal(err)
	}

	d := time.Since(t0)
	peak := probe.Stop()
	s1, r1 := tableReads(t, admin)

	t.Logf("SCAN ONLY: %d BLACKLIST hashes (xor %x) in %s = %.2f M rows/s; Go peak above baseline %s; blacklist_entries: %d queries, %d rows read",
		n, xor, d.Truncate(time.Second), float64(r1-r0)/d.Seconds()/1e6, mb(peak), s1-s0, r1-r0)
}
