package filter

import (
	"math/rand/v2"
	"testing"
)

// F10 reproduction: adding far more hashes to the delta Bloom than it was sized for keeps answers correct (no false
// negatives) but drives its false-positive rate up until almost every check falls through to the database. The
// filter must report how full the delta is so the leader can rebuild early.
func TestDeltaOverfillRaisesFPRAndIsReported(t *testing.T) {
	l := NewLayered(&BinaryFuse8{}, MinDeltaCapacity)
	rng := rand.New(rand.NewPCG(10, 10))

	fpr := func() float64 {
		probe := rand.New(rand.NewPCG(99, 99)) // random 64-bit probes: practically never real members
		hits := 0
		const n = 50_000
		for range n {
			if l.Test(probe.Uint64()) {
				hits++
			}
		}
		return float64(hits) / n
	}

	add := func(n int) {
		for range n {
			l.Add(rng.Uint64())
		}
	}

	add(MinDeltaCapacity / 2)
	half := fpr()
	if r := l.DeltaFillRatio(); r < 0.49 || r > 0.51 {
		t.Fatalf("fill ratio at half capacity = %.3f", r)
	}

	add(MinDeltaCapacity*4 - MinDeltaCapacity/2) // 4x the design capacity in total
	over := fpr()
	if r := l.DeltaFillRatio(); r < 3.9 || r > 4.1 {
		t.Fatalf("fill ratio at 4x = %.3f", r)
	}

	t.Logf("delta FPR at 0.5x capacity = %.4f, at 4x = %.4f", half, over)
	if half > 0.02 || over < 0.3 {
		t.Fatalf("expected low FPR at half capacity and a sharp rise when overfilled: %.4f -> %.4f", half, over)
	}

	l.Remove(1)
	l.Remove(2)
	if l.Stats().Removed != 2 {
		t.Fatal("removed-set size not reported")
	}
}

func TestDefaultDeltaCapacityScalesWithStatic(t *testing.T) {
	if DefaultDeltaCapacity(0) != MinDeltaCapacity {
		t.Fatal("small static must get the minimum delta")
	}
	if got := DefaultDeltaCapacity(100_000_000); got != 5_000_000 {
		t.Fatalf("100M static -> delta %d, want 5%% = 5M", got)
	}
}

func TestManagerDeltaPressure(t *testing.T) {
	m := NewManager()
	if r, n := m.DeltaPressure(); r != 0 || n != 0 {
		t.Fatal("not ready must report no pressure")
	}

	l := NewLayered(&BinaryFuse8{}, MinDeltaCapacity)
	m.Swap(l, Source{})
	for i := range uint64(MinDeltaCapacity / 4) {
		l.Add(i)
	}
	l.Remove(7)

	r, n := m.DeltaPressure()
	if r < 0.24 || r > 0.26 || n != 1 {
		t.Fatalf("pressure = %.3f, %d", r, n)
	}
}
