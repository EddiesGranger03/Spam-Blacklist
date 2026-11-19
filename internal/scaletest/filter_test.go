//go:build scale

package scaletest

import (
	"bytes"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
	"time"

	"vsf/internal/bloom"
	"vsf/internal/filter"
	"vsf/internal/snapshot"
)

// TestScaleFilter measures the static layer (binary fuse 8) against the old Bloom filter at the same N:
// build time, transient peak memory, resident size, measured false-positive rate, lookup cost, and the
// snapshot encode/decode(+checksum) cost. Nothing here needs a database.
//
//	go test -tags scale -run TestScaleFilter -v -timeout 30m ./internal/scaletest
func TestScaleFilter(t *testing.T) {
	for _, s := range strings.Split(envOr("SCALE_FILTER_N", "1000000,10000000"), ",") {
		n, err := strconv.Atoi(strings.TrimSpace(strings.ReplaceAll(s, "_", "")))
		if err != nil || n <= 0 {
			t.Fatalf("bad SCALE_FILTER_N entry %q", s)
		}

		t.Run("N="+s, func(t *testing.T) { runFilterBench(t, n) })
	}
}

const fprProbes = 50_000_000

func runFilterBench(t *testing.T, n int) {
	rng := rand.New(rand.NewPCG(uint64(n), 42))

	keys := make([]uint64, n)
	for i := range keys {
		keys[i] = rng.Uint64()
	}

	base := heapNow()

	// ---- static: sort+dedupe, then build ----
	probe := startMemProbe()
	t0 := time.Now()
	keys = filter.DedupeSorted(keys)
	sortT := time.Since(t0)

	t0 = time.Now()

	f, err := filter.BuildBinaryFuse8(keys)
	if err != nil {
		t.Fatal(err)
	}

	buildT := time.Since(t0)
	peakTransient := probe.Stop() // peak above "keys already in memory"

	// ---- correctness: zero false negatives on every key ----
	for _, k := range keys {
		if !f.Contains(k) {
			t.Fatalf("false negative for key %x", k)
		}
	}

	// ---- measured FPR: probes drawn from a different stream (collision with a member ~ n/2^64, i.e. none) ----
	neg := rand.New(rand.NewPCG(0xdeadbeef, uint64(n)))
	fp := 0

	t0 = time.Now()

	for range fprProbes {
		if f.Contains(neg.Uint64()) {
			fp++
		}
	}

	negNs := float64(time.Since(t0).Nanoseconds()) / fprProbes // includes the RNG, so an upper bound
	fprStatic := float64(fp) / fprProbes

	t0 = time.Now()
	hit := 0

	for i := 0; i < 5_000_000; i++ {
		if f.Contains(keys[(i*7919)%len(keys)]) {
			hit++
		}
	}

	posNs := float64(time.Since(t0).Nanoseconds()) / 5_000_000
	_ = hit

	l := filter.NewLayered(f, filter.DefaultDeltaCapacity(f.Items))
	t0 = time.Now()

	for range 5_000_000 {
		l.Test(neg.Uint64())
	}

	layeredNs := float64(time.Since(t0).Nanoseconds()) / 5_000_000

	// ---- snapshot encode / decode (checksum verified inside Decode) ----
	var buf bytes.Buffer

	t0 = time.Now()

	if _, _, err := snapshot.Encode(&buf, f, snapshot.PlainDomain, "123", 456); err != nil {
		t.Fatal(err)
	}

	encT := time.Since(t0)
	size := buf.Len()

	t0 = time.Now()

	if _, err := snapshot.Decode(bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatal(err)
	}

	decT := time.Since(t0)

	buf = bytes.Buffer{}

	t.Logf("STATIC N=%d  sort+dedupe=%s  build=%s  transient_peak=%s (%.1f B/key)  resident=%s (%.2f B/key)  FPR=%.4f%% (%d/%d probes)",
		n, sortT.Truncate(time.Millisecond), buildT.Truncate(time.Millisecond), mb(peakTransient), float64(peakTransient)/float64(n),
		mb(f.SizeBytes()), float64(f.SizeBytes())/float64(n), fprStatic*100, fp, fprProbes)
	t.Logf("STATIC lookups: negative=%.0f ns/op  positive=%.0f ns/op  layered(neg, empty layers)=%.0f ns/op",
		negNs, posNs, layeredNs)
	t.Logf("SNAPSHOT file=%s  encode=%s  decode+crc=%s  (keys slice itself = %s)",
		mb(uint64(size)), encT.Truncate(time.Millisecond), decT.Truncate(time.Millisecond), mb(uint64(n)*8))

	// ---- old Bloom at the same N (10 bits/item, 7 hashes) ----
	keys = nil
	_ = base

	heapNow()

	bprobe := startMemProbe()
	t0 = time.Now()
	bf := bloom.New(uint64(n))
	rng2 := rand.New(rand.NewPCG(uint64(n), 42))

	for range n {
		bf.Add(rng2.Uint64())
	}

	bBuild := time.Since(t0)
	bPeak := bprobe.Stop()

	neg2 := rand.New(rand.NewPCG(0xdeadbeef, uint64(n)))
	bfp := 0

	t0 = time.Now()

	for range fprProbes {
		if bf.Test(neg2.Uint64()) {
			bfp++
		}
	}

	bNs := float64(time.Since(t0).Nanoseconds()) / fprProbes

	t.Logf("BLOOM  N=%d  build=%s  peak_delta=%s  resident=%s (%.2f B/key)  FPR=%.4f%% (%d/%d probes)  negative lookup=%.0f ns/op",
		n, bBuild.Truncate(time.Millisecond), mb(bPeak), mb(bf.SizeBytes()), float64(bf.SizeBytes())/float64(n),
		float64(bfp)/fprProbes*100, bfp, fprProbes, bNs)

	if fprStatic > 0.01 {
		t.Errorf("static FPR %.4f%% is above 1%% (binary fuse 8 should be ~0.39%%)", fprStatic*100)
	}
}
