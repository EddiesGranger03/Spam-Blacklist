package filter

import (
	"bytes"
	"math/rand/v2"
	"runtime"
	"testing"
)

func randomKeys(n int, seed uint64) []uint64 {
	rng := rand.New(rand.NewPCG(seed, seed^0x5555))
	keys := make([]uint64, n)
	for i := range keys {
		keys[i] = rng.Uint64()
	}

	return DedupeSorted(keys)
}

func TestBinaryFuseOneMillionNoFalseNegativesAndFPR(t *testing.T) {
	keys := randomKeys(1_000_000, 1)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	f, err := BuildBinaryFuse8(keys)
	if err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	runtime.ReadMemStats(&after)

	for _, k := range keys {
		if !f.Contains(k) {
			t.Fatalf("false negative for %d", k)
		}
	}

	in := make(map[uint64]struct{}, len(keys))
	for _, k := range keys {
		in[k] = struct{}{}
	}

	rng := rand.New(rand.NewPCG(99, 98))
	const probes = 1_000_000
	fp := 0

	for n := 0; n < probes; {
		k := rng.Uint64()
		if _, ok := in[k]; ok {
			continue
		}

		n++
		if f.Contains(k) {
			fp++
		}
	}

	rate := float64(fp) / probes
	t.Logf("items=%d bytes=%d (%.2f bit/item) heap-retained≈%d FPR=%.4f%% (theory ≈0.39%%)",
		len(keys), f.SizeBytes(), float64(f.SizeBytes())*8/float64(len(keys)),
		int64(after.HeapAlloc)-int64(before.HeapAlloc), rate*100)

	if rate > 0.006 {
		t.Fatalf("FPR %.4f%% too high", rate*100)
	}
}

func TestBinaryFuseSmallSizes(t *testing.T) {
	for _, n := range []int{0, 1, 2, 3, 10, 100, 1000, 12345} {
		keys := randomKeys(n, uint64(n)+7)
		f, err := BuildBinaryFuse8(keys)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}

		for _, k := range keys {
			if !f.Contains(k) {
				t.Fatalf("n=%d: false negative", n)
			}
		}
	}

	if (&BinaryFuse8{}).Contains(1) {
		t.Fatal("empty filter must contain nothing")
	}
}

func TestBinaryFuseDuplicatesFailWithoutDedupe(t *testing.T) {
	if _, err := BuildBinaryFuse8([]uint64{1, 2, 3, 3}); err == nil {
		t.Fatal("expected failure with duplicate keys")
	}

	if f, err := BuildBinaryFuse8(DedupeSorted([]uint64{3, 1, 2, 3, 1})); err != nil || f.Items != 3 {
		t.Fatalf("dedupe: f=%v err=%v", f, err)
	}
}

func TestBinaryFuseSerializeRoundTrip(t *testing.T) {
	keys := randomKeys(50_000, 3)
	f, _ := BuildBinaryFuse8(keys)

	var buf bytes.Buffer
	if _, err := f.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}

	g, err := ReadBinaryFuse8(bytes.NewReader(buf.Bytes()), 1<<30)
	if err != nil {
		t.Fatal(err)
	}

	for _, k := range keys {
		if !g.Contains(k) {
			t.Fatal("false negative after round trip")
		}
	}

	raw := buf.Bytes()
	raw[8] ^= 1 // corrupt the segment length
	if _, err := ReadBinaryFuse8(bytes.NewReader(raw), 1<<30); err == nil {
		t.Fatal("corrupt geometry must be rejected")
	}
}

func TestLayeredSemantics(t *testing.T) {
	keys := randomKeys(100_000, 4)
	f, _ := BuildBinaryFuse8(keys)
	l := NewLayered(f, 0)

	removed := keys[0]
	l.Remove(removed)
	if l.Test(removed) {
		t.Fatal("removed hash must test false")
	}

	for _, k := range keys[1:] {
		if !l.Test(k) {
			t.Fatal("false negative in static layer")
		}
	}

	l.Add(removed) // re-added after removal
	if !l.Test(removed) {
		t.Fatal("re-added hash must test true")
	}

	added := uint64(0xdeadbeefcafe)
	l.Add(added)
	if !l.Test(added) {
		t.Fatal("delta add lost")
	}

	l.Remove(added)
	if l.Test(added) {
		t.Fatal("removed after add must test false")
	}

	if s := l.Stats(); s.Removed != 1 || s.StaticItems != uint64(len(keys)) {
		t.Fatalf("stats %+v", s)
	}
}

// One million random keys through all three layers: half in static, half added to delta, a slice removed and some
// of those re-added. Every key whose final state is "present" must test true.
func TestLayeredOneMillionNoFalseNegatives(t *testing.T) {
	keys := randomKeys(1_000_000, 5)
	half := len(keys) / 2
	f, err := BuildBinaryFuse8(keys[:half])
	if err != nil {
		t.Fatal(err)
	}

	l := NewLayered(f, DefaultDeltaCapacity(uint64(half)))
	for _, k := range keys[half:] {
		l.Add(k)
	}

	present := map[uint64]bool{}
	for _, k := range keys {
		present[k] = true
	}

	for i := 0; i < len(keys); i += 10 {
		l.Remove(keys[i])
		present[keys[i]] = false
	}

	for i := 0; i < len(keys); i += 20 {
		l.Add(keys[i])
		present[keys[i]] = true
	}

	for k, want := range present {
		if want && !l.Test(k) {
			t.Fatalf("false negative for %d", k)
		}

		if !want && l.Test(k) {
			t.Fatalf("removed key %d still present", k)
		}
	}

	rng := rand.New(rand.NewPCG(11, 12))
	fp := 0
	for n := 0; n < 1_000_000; {
		k := rng.Uint64()
		if _, ok := present[k]; ok {
			continue
		}
		n++
		if l.Test(k) {
			fp++
		}
	}

	t.Logf("layered FPR=%.4f%% stats=%+v", float64(fp)/1e4, l.Stats())
}

func TestManagerNotReady(t *testing.T) {
	m := NewManager()
	if m.Ready() || !m.Test(1) {
		t.Fatal("not-ready manager must be conservative and report not ready")
	}

	m.Swap(NewLayered(nil, 0), Source{SnapshotID: 7})
	if !m.Ready() || m.Test(1) || m.Source().SnapshotID != 7 {
		t.Fatal("after swap: ready, empty filter, source recorded")
	}
}
