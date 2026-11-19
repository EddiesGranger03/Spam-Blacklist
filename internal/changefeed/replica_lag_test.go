package changefeed

import (
	"context"
	"testing"
	"time"

	"vsf/internal/model"
)

// F6: message Pub/Sub (seq_max=1) tới TRƯỚC khi nguồn đọc (replica) có dòng change_log. Lần catch-up đầu không thấy gì;
// feed phải tự thử lại (backoff ms) thay vì ngủ tới safety poll. Safety đặt 1 giờ: trước khi sửa test này hết hạn.
func TestLaggingReplicaCatchUpRetriesUntilSeqMax(t *testing.T) {
	src := &fakeSource{}
	f, m := newFeed(t, src)
	f.live.Store(true) // đang subscribe: chu kỳ = safety

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go f.RunSync(ctx, time.Hour, time.Hour)

	epoch0 := f.Epoch()
	hint(t, f, 1, model.Change{Seq: 1, Hash: 55, Op: OpAdd})

	if !f.Pending() {
		t.Fatal("feed must report Pending while seq_max is not yet readable")
	}

	time.Sleep(60 * time.Millisecond) // replica trễ: vài lần thử lại đã chạy và không thấy gì
	push(src, model.Change{Seq: 1, XID: "5", Hash: 55, Op: OpAdd})

	deadline := time.Now().Add(2 * time.Second)
	for f.Pending() || f.Epoch() == epoch0 {
		if time.Now().After(deadline) {
			t.Fatalf("feed did not catch up within 2s after replica got the row (pending=%v epoch=%s)", f.Pending(), f.Epoch())
		}

		time.Sleep(2 * time.Millisecond)
	}

	if !m.Test(55) {
		t.Fatal("hash must be in filter after catch-up")
	}
}

// seq_max không bao giờ xuất hiện: sau catchUpTimeout feed bỏ cuộc (Pending=false) để checker cache lại bình thường.
func TestCatchUpGivesUp(t *testing.T) {
	f, _ := newFeed(t, &fakeSource{})
	hint(t, f, 99)

	b, r := f.trackCatchUp(time.Time{}, 0)
	if b.IsZero() || r != catchUpMin {
		t.Fatalf("start: behind=%v retry=%v", b, r)
	}

	if _, r = f.trackCatchUp(b, r); r != 2*catchUpMin {
		t.Fatalf("backoff not doubled: %v", r)
	}

	if b, _ = f.trackCatchUp(time.Now().Add(-catchUpTimeout), r); !b.IsZero() || f.Pending() {
		t.Fatalf("must give up after timeout: behind=%v pending=%v", b, f.Pending())
	}

	hint(t, f, 100) // message mới sau khi bỏ cuộc vẫn được chờ
	if !f.Pending() {
		t.Fatal("new seq_max after give-up must be pending again")
	}
}
