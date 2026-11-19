package verify

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeWorld: DB (rows: hash -> version) và filter (set) tách rời, SyncNow chép trạng thái DB "đã commit" vào filter.
type fakeWorld struct {
	mu       sync.Mutex
	db       map[int64]string    // dòng BLACKLIST hiệu lực
	filter   map[uint64]struct{} // filter đang phục vụ
	unsynced map[uint64]struct{} // hash đã ghi DB nhưng feed chưa áp (SyncNow sẽ áp)
	lost     map[uint64]struct{} // hash filter "đánh mất" mà SyncNow không khôi phục (lỗi thật)
	onSync   func(n int)         // hook chạy sau mỗi SyncNow (giả lập ghi đồng thời)
	syncs    int
}

func newWorld() *fakeWorld {
	return &fakeWorld{db: map[int64]string{}, filter: map[uint64]struct{}{}, unsynced: map[uint64]struct{}{}, lost: map[uint64]struct{}{}}
}

func (w *fakeWorld) Ready() bool { return true }
func (w *fakeWorld) Test(h uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, ok := w.filter[h]
	return ok
}

func (w *fakeWorld) SyncNow(context.Context) error {
	w.mu.Lock()
	for h := range w.unsynced {
		if _, lost := w.lost[h]; !lost {
			w.filter[h] = struct{}{}
		}
	}
	clear(w.unsynced)
	w.syncs++
	n, hook := w.syncs, w.onSync
	w.mu.Unlock()

	if hook != nil {
		hook(n)
	}

	return nil
}

func (w *fakeWorld) SampleActiveBlacklistHashes(_ context.Context, _ int) ([]int64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]int64, 0, len(w.db))
	for h := range w.db {
		out = append(out, h)
	}
	return out, nil
}

func (w *fakeWorld) ActiveBlacklistVersions(_ context.Context, hs []int64) (map[int64]string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := map[int64]string{}
	for _, h := range hs {
		if v, ok := w.db[h]; ok {
			out[h] = v
		}
	}
	return out, nil
}

func (w *fakeWorld) add(h int64, synced bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.db[h] = "1:1"
	if synced {
		w.filter[uint64(h)] = struct{}{}
	} else {
		w.unsynced[uint64(h)] = struct{}{}
	}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newV(w *fakeWorld, heal func(uint64)) *Verifier {
	return New(w, w, w, Config{Sample: 1000, Heal: heal}, quiet())
}

func TestCorrectFilterHasNoFalseNegatives(t *testing.T) {
	w := newWorld()
	for i := int64(1); i <= 500; i++ {
		w.add(i, true)
	}

	fns, err := newV(w, nil).RunOnce(context.Background())
	if err != nil || len(fns) != 0 {
		t.Fatalf("fns=%v err=%v", fns, err)
	}

	if w.syncs != 0 {
		t.Fatalf("no suspects should mean no SyncNow, got %d", w.syncs)
	}
}

func TestMissingHashIsCaughtAndHealed(t *testing.T) {
	w := newWorld()
	for i := int64(1); i <= 100; i++ {
		w.add(i, true)
	}

	delete(w.filter, 42) // tiêm lỗi: filter mất hash 42
	w.lost[42] = struct{}{}

	var healed []uint64
	v := newV(w, func(h uint64) { healed = append(healed, h); w.filter[h] = struct{}{} })

	fns, err := v.RunOnce(context.Background())
	if err != nil || len(fns) != 1 || fns[0] != 42 {
		t.Fatalf("fns=%v err=%v", fns, err)
	}

	if len(healed) != 1 || !w.Test(42) {
		t.Fatalf("hash not healed: %v", healed)
	}

	if s := v.Warning(time.Now()); !strings.Contains(s, "false negative") || !strings.Contains(s, "000000000000002a") {
		t.Fatalf("warning = %q", s)
	}

	if v.Warning(time.Now().Add(2*time.Hour)) != "" {
		t.Fatal("warning should expire after WarnFor")
	}
}

func TestUnsyncedWriteIsNotAFalseAlarm(t *testing.T) {
	w := newWorld()
	w.add(1, true)
	w.add(7, false) // đã commit nhưng feed chưa áp

	fns, err := newV(w, nil).RunOnce(context.Background())
	if err != nil || len(fns) != 0 {
		t.Fatalf("fns=%v err=%v", fns, err)
	}
}

func TestRowRemovedDuringCheckIsNotAFalseAlarm(t *testing.T) {
	w := newWorld()
	w.add(5, true)
	delete(w.filter, 5)                                                  // filter đã áp lần gỡ...
	w.onSync = func(int) { w.mu.Lock(); delete(w.db, 5); w.mu.Unlock() } // ...mà DB commit sau lúc lấy mẫu

	fns, err := newV(w, nil).RunOnce(context.Background())
	if err != nil || len(fns) != 0 {
		t.Fatalf("fns=%v err=%v", fns, err)
	}
}

func TestRowRewrittenBetweenRechecksIsDiscarded(t *testing.T) {
	w := newWorld()
	w.add(9, true)
	delete(w.filter, 9)
	w.lost[9] = struct{}{}
	// Sau S2, dòng bị ghi lại (xmin đổi): không chứng minh được thứ tự -> bỏ, chu kỳ sau xét lại.
	w.onSync = func(n int) {
		if n == 2 {
			w.mu.Lock()
			w.db[9] = "1:2"
			w.mu.Unlock()
		}
	}

	fns, err := newV(w, nil).RunOnce(context.Background())
	if err != nil || len(fns) != 0 {
		t.Fatalf("fns=%v err=%v", fns, err)
	}
}

func TestDedupeSampleCapsAndDedupes(t *testing.T) {
	raw := []int64{1, 1, 2, 3, 3, 4, 5, 6}
	out := dedupeSample(raw, 3)
	if len(out) != 3 {
		t.Fatalf("len=%d", len(out))
	}

	seen := map[int64]bool{}
	for _, h := range out {
		if seen[h] {
			t.Fatalf("dup %d", h)
		}
		seen[h] = true
	}

	if got := dedupeSample([]int64{2, 2}, 10); len(got) != 1 {
		t.Fatalf("got %v", got)
	}
}
