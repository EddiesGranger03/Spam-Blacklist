package changefeed

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"vsf/internal/bloom"
	"vsf/internal/model"
)

type fakeSource struct {
	mu      sync.Mutex
	all     []int64
	changes []model.Change
}

func (f *fakeSource) Head(ctx context.Context) (string, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n := len(f.changes); n > 0 {
		return f.changes[n-1].XID, f.changes[n-1].Seq, nil
	}

	return "0", 0, nil
}

func (f *fakeSource) ChangesSince(ctx context.Context, xid string, seq int64, limit int) ([]model.Change, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []model.Change
	after := xid == "0" && seq == 0

	for _, c := range f.changes {
		if !after {
			if c.XID == xid && c.Seq == seq {
				after = true
			}

			continue
		}

		out = append(out, c)
		if len(out) >= limit {
			break
		}
	}

	return out, nil
}

func (f *fakeSource) AllHashes(ctx context.Context, emit func(uint64)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, h := range f.all {
		emit(uint64(h))
	}

	return nil
}
func (f *fakeSource) EstimatedCount(ctx context.Context) (int64, error)          { return 0, nil }
func (f *fakeSource) PurgeChanges(context.Context, time.Duration) (int64, error) { return 0, nil }
func quiet() *slog.Logger                                                        { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestInitThenSync(t *testing.T) {
	src := &fakeSource{all: []int64{10, 20}}
	b := bloom.NewManager()
	f := New(src, b, quiet())
	ctx := context.Background()

	if err := f.Init(ctx, 1000); err != nil {
		t.Fatal(err)
	}

	if !b.Ready() || !b.Test(10) || !b.Test(20) {
		t.Fatal("bloom must contain hashes present at startup")
	}

	e0 := f.Epoch()

	src.mu.Lock()
	src.changes = append(src.changes, model.Change{Seq: 1, XID: "5", Hash: 777}, model.Change{Seq: 2, XID: "6", Hash: 888})
	src.mu.Unlock()

	if err := f.SyncNow(ctx); err != nil {
		t.Fatal(err)
	}

	if !b.Test(777) || !b.Test(888) {
		t.Fatal("changes must be applied to bloom")
	}

	if f.Epoch() == e0 {
		t.Fatal("epoch must change when changes are applied")
	}

	if f.Epoch() != "6.2" {
		t.Fatalf("epoch = %q, want 6.2", f.Epoch())
	}

	e1 := f.Epoch()
	_ = f.SyncNow(ctx)

	if f.Epoch() != e1 {
		t.Fatal("epoch must not change without new changes")
	}

	if f.Lag() > time.Second {
		t.Fatalf("lag too large: %v", f.Lag())
	}
}

func TestLagIsHugeBeforeFirstPoll(t *testing.T) {
	f := New(&fakeSource{}, bloom.NewManager(), quiet())
	if f.Lag() < time.Hour {
		t.Fatal("lag before first successful poll must be huge so /readyz fails")
	}
}
