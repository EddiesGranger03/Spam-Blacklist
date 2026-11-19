package checker

import (
	"context"
	"sync/atomic"
	"testing"

	"vsf/internal/model"
	"vsf/internal/normalize"
)

// pendingEpoch giả lập *changefeed.Feed: epoch cố định (replica chưa thấy thay đổi nên catch-up chưa đổi epoch)
// và Pending bật/tắt được.
type pendingEpoch struct{ pending atomic.Bool }

func (p *pendingEpoch) Epoch() string { return "7.7" }
func (p *pendingEpoch) Pending() bool { return p.pending.Load() }

// primaryFinder: FindMatches (replica) trả replica; FindMatchesPrimary trả primary.
type primaryFinder struct {
	fakeFinder
	primary      []model.Entry
	primaryCalls atomic.Int32
}

func (f *primaryFinder) FindMatchesPrimary(context.Context, []normalize.Key) ([]model.Entry, error) {
	f.primaryCalls.Add(1)
	return f.primary, nil
}

var lagEntry = model.Entry{ID: 9, Type: "url", MatchType: "domain", Value: "example.com", Category: "scam", RiskScore: 90,
	Status: model.StatusBlacklist}

// F6: replica chưa có entry vừa ghi ở pod khác, feed đang Pending. Kết quả âm KHÔNG được cache theo epoch hiện tại,
// nên khi replica bắt kịp (cùng epoch, chưa kịp đổi) lần check sau phải thấy entry. Trước khi sửa: lần hai vẫn "an toàn".
func TestPendingNegativeIsNotCached(t *testing.T) {
	ep := &pendingEpoch{}
	ep.pending.Store(true)

	fd := &fakeFinder{}
	c := newMemCache()
	ck := New("VN", fakeFilter{true}, c, fd, ep)
	ctx := context.Background()

	if res, err := ck.Check(ctx, normalize.TypeURL, "http://example.com"); err != nil || res.Blacklisted {
		t.Fatalf("first check: res=%+v err=%v", res, err)
	}

	if n := len(c.data); n != 0 {
		t.Fatalf("negative result cached while feed pending (%d keys)", n)
	}

	fd.entries = []model.Entry{lagEntry} // replica bắt kịp

	res, err := ck.Check(ctx, normalize.TypeURL, "http://example.com")
	if err != nil || !res.Blacklisted {
		t.Fatalf("after replica caught up: res=%+v err=%v (stale negative served from cache)", res, err)
	}
}

// Có primary: kết quả âm từ replica khi Pending được xác nhận lại trên primary và trả đúng ngay; kết quả dương được cache.
func TestPendingNegativeRecheckedOnPrimary(t *testing.T) {
	ep := &pendingEpoch{}
	ep.pending.Store(true)

	fd := &primaryFinder{primary: []model.Entry{lagEntry}}
	c := newMemCache()
	ck := New("VN", fakeFilter{true}, c, fd, ep)

	res, err := ck.Check(context.Background(), normalize.TypeURL, "http://example.com")
	if err != nil || !res.Blacklisted {
		t.Fatalf("res=%+v err=%v", res, err)
	}

	if fd.primaryCalls.Load() != 1 || len(c.data) != 1 {
		t.Fatalf("primary calls=%d cached=%d, want 1/1", fd.primaryCalls.Load(), len(c.data))
	}
}

// Không Pending: hành vi cũ (kết quả âm được cache, không hỏi primary).
func TestNotPendingNegativeCachedNoPrimary(t *testing.T) {
	fd := &primaryFinder{primary: []model.Entry{lagEntry}}
	c := newMemCache()
	ck := New("VN", fakeFilter{true}, c, fd, &pendingEpoch{})

	if res, err := ck.Check(context.Background(), normalize.TypeURL, "http://example.com"); err != nil || res.Blacklisted {
		t.Fatalf("res=%+v err=%v", res, err)
	}

	if fd.primaryCalls.Load() != 0 || len(c.data) != 1 {
		t.Fatalf("primary calls=%d cached=%d, want 0/1", fd.primaryCalls.Load(), len(c.data))
	}
}
