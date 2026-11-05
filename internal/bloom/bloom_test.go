package bloom

import (
	"context"
	"errors"
	"math/rand"
	"sync"
	"testing"
)

func TestNoFalseNegativesAndLowFalsePositives(t *testing.T) {
	const n = 100_000
	f := New(n)
	rng := rand.New(rand.NewSource(1))
	added := make([]uint64, n)
	for i := range added {
		added[i] = rng.Uint64()
		f.Add(added[i])
	}

	for _, h := range added {
		if !f.Test(h) {
			t.Fatal("false negative: Bloom filter must never lose an added hash")
		}
	}

	fp := 0

	for i := 0; i < n; i++ {
		if f.Test(rng.Uint64()) {
			fp++
		}
	}

	if rate := float64(fp) / n; rate > 0.02 {
		t.Fatalf("false positive rate %.4f too high (want <= 0.02)", rate)
	}
}

func TestConcurrentAddTest(t *testing.T) {
	f := New(10_000)
	var wg sync.WaitGroup

	for g := 0; g < 8; g++ {
		wg.Add(1)

		go func(g int) {
			defer wg.Done()
			for i := 0; i < 5000; i++ {
				h := uint64(g)<<32 | uint64(i)*2654435761
				f.Add(h)

				if !f.Test(h) {
					t.Error("false negative under concurrency")
					return
				}
			}
		}(g)
	}

	wg.Wait()
}

func TestManagerNotReadyIsConservative(t *testing.T) {
	m := NewManager()
	if m.Ready() {
		t.Fatal("new manager must not be ready")
	}

	if !m.Test(12345) {
		t.Fatal("not-ready manager must answer 'maybe' (true) so requests fall through to the DB")
	}
}

func TestRebuildKeepsHashesAddedDuringScan(t *testing.T) {
	m := NewManager()
	err := m.Rebuild(context.Background(), 1000, func(ctx context.Context, emit func(uint64)) error {
		emit(1)
		emit(2)
		m.Add(999)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, h := range []uint64{1, 2, 999} {
		if !m.Test(h) {
			t.Fatalf("hash %d lost after rebuild", h)
		}
	}

	if !m.Ready() {
		t.Fatal("should be ready after rebuild")
	}
}

func TestRebuildFailureKeepsOldFilter(t *testing.T) {
	m := NewManager()
	_ = m.Rebuild(context.Background(), 1000, func(ctx context.Context, emit func(uint64)) error {
		emit(42)
		return nil
	})

	boom := errors.New("boom")
	err := m.Rebuild(context.Background(), 1000, func(ctx context.Context, emit func(uint64)) error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}

	if !m.Test(42) {
		t.Fatal("old filter must be kept when rebuild fails")
	}
}

func TestConcurrentRebuildRejected(t *testing.T) {
	m := NewManager()
	started, release := make(chan struct{}), make(chan struct{})
	go func() {
		_ = m.Rebuild(context.Background(), 100, func(ctx context.Context, emit func(uint64)) error {
			close(started)
			<-release
			return nil
		})
	}()

	<-started
	err := m.Rebuild(context.Background(), 100, func(ctx context.Context, emit func(uint64)) error { return nil })
	if !errors.Is(err, ErrRebuilding) {
		t.Fatalf("want ErrRebuilding, got %v", err)
	}

	close(release)
}
