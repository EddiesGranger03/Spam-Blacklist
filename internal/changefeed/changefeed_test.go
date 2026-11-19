package changefeed

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"vsf/internal/filter"
	"vsf/internal/model"
)

type fakeSource struct {
	mu      sync.Mutex
	all     []int64
	changes []model.Change
}

// Head của fakeSource trả về con trỏ hiện tại (giả lập).
func (f *fakeSource) Head(ctx context.Context) (string, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n := len(f.changes); n > 0 {
		return f.changes[n-1].XID, f.changes[n-1].Seq, nil
	}

	return "0", 0, nil
}

// ChangesSince của fakeSource trả về các thay đổi giả sau con trỏ đã cho.
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

// ScanBlacklistHashes của fakeSource gọi emit với các hash giả.
func (f *fakeSource) ScanBlacklistHashes(ctx context.Context, emit func(uint64)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, h := range f.all {
		emit(uint64(h))
	}

	return nil
}
// EstimatedCount của fakeSource luôn trả về 0.
func (f *fakeSource) EstimatedCount(ctx context.Context) (int64, error)          { return 0, nil }
// PurgeChanges của fakeSource không làm gì và trả về 0.
func (f *fakeSource) PurgeChanges(context.Context, time.Duration) (int64, error) { return 0, nil }
// quiet tạo logger im lặng để test không in log.
func quiet() *slog.Logger                                                        { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestInitThenSync kiểm tra khởi tạo feed rồi đồng bộ đưa hash vào Bloom.
func TestInitThenSync(t *testing.T) {
	src := &fakeSource{all: []int64{10, 20}}
	b := filter.NewManager()
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

// TestLagIsHugeBeforeFirstPoll kiểm tra lag rất lớn trước lần poll đầu tiên.
func TestLagIsHugeBeforeFirstPoll(t *testing.T) {
	f := New(&fakeSource{}, filter.NewManager(), quiet())
	if f.Lag() < time.Hour {
		t.Fatal("lag before first successful poll must be huge so /readyz fails")
	}
}

// --- C1: phần đuôi "Pending" (đã commit nhưng xid >= xmin vì một transaction cũ còn mở) ---

// newFeed tạo Feed và Bloom manager dùng cho test, nối với nguồn giả.
func newFeed(t *testing.T, src *fakeSource) (*Feed, *filter.Manager) {
	t.Helper()

	b := filter.NewManager()
	f := New(src, b, quiet())

	if err := f.Init(context.Background(), 1000); err != nil {
		t.Fatal(err)
	}

	return f, b
}

// cursorOf đọc con trỏ hiện tại (xid, seq) của Feed để kiểm tra.
func cursorOf(f *Feed) (string, int64) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.xid, f.seq
}

// Entry mới nằm sau một transaction đang mở phải vào Bloom NGAY (nếu không, /v1/check trả "an toàn" cho
// số đã bị chặn), nhưng con trỏ không được đi qua nó.
func TestPendingChangesReachBloomButDoNotAdvanceCursor(t *testing.T) {
	src := &fakeSource{}
	f, b := newFeed(t, src)

	src.mu.Lock()
	src.changes = []model.Change{
		{Seq: 1, XID: "5", Hash: 111},
		{Seq: 2, XID: "7", Hash: 222, Pending: true},
	}
	src.mu.Unlock()

	if err := f.SyncNow(context.Background()); err != nil {
		t.Fatal(err)
	}

	if !b.Test(111) || !b.Test(222) {
		t.Fatal("cả hash an toàn lẫn hash Pending phải có trong Bloom ngay")
	}

	if x, s := cursorOf(f); x != "5" || s != 1 {
		t.Fatalf("con trỏ không được đi qua dòng Pending: got (%s,%d), want (5,1)", x, s)
	}

	if f.TailLen() != 1 {
		t.Fatalf("TailLen = %d, want 1", f.TailLen())
	}

	if !strings.HasPrefix(f.Epoch(), "5.1.t1-") {
		t.Fatalf("epoch = %q, want tiền tố 5.1.t1- (đuôi nhận dòng mới phải đổi epoch để vô hiệu cache âm)", f.Epoch())
	}
}

// Đọc lại cùng một đuôi mỗi giây không được đếm trùng (Items) và không được đổi epoch.
func TestPendingTailIsNotReAddedOrRecounted(t *testing.T) {
	src := &fakeSource{}
	f, b := newFeed(t, src)

	src.mu.Lock()
	src.changes = []model.Change{{Seq: 1, XID: "7", Hash: 222, Pending: true}}
	src.mu.Unlock()

	if err := f.SyncNow(context.Background()); err != nil {
		t.Fatal(err)
	}

	items, epoch := b.Items(), f.Epoch()

	for i := 0; i < 5; i++ {
		if err := f.SyncNow(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	if b.Items() != items {
		t.Fatalf("Items tăng từ %d lên %d khi chỉ đọc lại cùng một đuôi", items, b.Items())
	}

	if f.Epoch() != epoch {
		t.Fatalf("epoch đổi từ %q sang %q dù không có dòng mới", epoch, f.Epoch())
	}
}

// Khi transaction cũ kết thúc, dòng Pending thành an toàn: con trỏ đi qua, đuôi sạch, không đếm trùng.
func TestPendingBecomesSafeAdvancesCursor(t *testing.T) {
	src := &fakeSource{}
	f, b := newFeed(t, src)

	src.mu.Lock()
	src.changes = []model.Change{
		{Seq: 1, XID: "5", Hash: 111},
		{Seq: 2, XID: "7", Hash: 222, Pending: true},
	}
	src.mu.Unlock()

	_ = f.SyncNow(context.Background())
	items, epoch := b.Items(), f.Epoch()

	src.mu.Lock()
	src.changes[1].Pending = false // xmin đã tiến lên
	src.mu.Unlock()

	if err := f.SyncNow(context.Background()); err != nil {
		t.Fatal(err)
	}

	if x, s := cursorOf(f); x != "7" || s != 2 {
		t.Fatalf("con trỏ phải đi qua dòng đã an toàn: got (%s,%d), want (7,2)", x, s)
	}

	if f.TailLen() != 0 || f.StalledFor() != 0 {
		t.Fatalf("đuôi phải sạch: TailLen=%d StalledFor=%v", f.TailLen(), f.StalledFor())
	}

	if b.Items() != items {
		t.Fatalf("dòng đã nạp lúc còn Pending không được đếm lại: %d -> %d", items, b.Items())
	}

	if f.Epoch() == epoch {
		t.Fatal("con trỏ đã dời nên epoch phải đổi")
	}
}

// Một transaction commit TRỄ có thể sinh dòng thứ tự TRƯỚC các dòng Pending đã thấy (đây là lý do cần xmin).
// Vì đuôi được đọc lại mỗi lần poll nên dòng đó vẫn phải được nạp.
func TestLateCommitInsideTailIsStillLoaded(t *testing.T) {
	src := &fakeSource{}
	f, b := newFeed(t, src)

	src.mu.Lock()
	src.changes = []model.Change{
		{Seq: 1, XID: "5", Hash: 111},
		{Seq: 3, XID: "7", Hash: 333, Pending: true},
	}
	src.mu.Unlock()

	_ = f.SyncNow(context.Background())
	items := b.Items()

	src.mu.Lock()
	src.changes = []model.Change{
		{Seq: 1, XID: "5", Hash: 111},
		{Seq: 2, XID: "7", Hash: 222, Pending: true}, // commit trễ, seq nhỏ hơn dòng đã thấy
		{Seq: 3, XID: "7", Hash: 333, Pending: true},
	}
	src.mu.Unlock()

	if err := f.SyncNow(context.Background()); err != nil {
		t.Fatal(err)
	}

	if !b.Test(222) {
		t.Fatal("dòng commit trễ nằm trong đuôi phải được nạp vào Bloom")
	}

	if b.Items() != items+1 {
		t.Fatalf("chỉ dòng mới được đếm: Items %d -> %d, want +1", items, b.Items())
	}

	if f.TailLen() != 2 {
		t.Fatalf("TailLen = %d, want 2", f.TailLen())
	}
}

// Đuôi lớn hơn trần mỗi lần poll nghĩa là còn dòng chưa nạp (nguy cơ sai thật): phải bật cờ để /readyz báo lỗi.
func TestTailOverflowIsFlagged(t *testing.T) {
	src := &fakeSource{}
	f, _ := newFeed(t, src)
	f.maxTail = 5000

	many := make([]model.Change, 0, batchSize+500)
	for i := 1; i <= batchSize+500; i++ {
		many = append(many, model.Change{Seq: int64(i), XID: "7", Hash: int64(1000 + i), Pending: true})
	}

	src.mu.Lock()
	src.changes = many
	src.mu.Unlock()

	if err := f.SyncNow(context.Background()); err != nil {
		t.Fatal(err)
	}

	if !f.TailOverflow() {
		t.Fatal("đuôi vượt trần và còn dòng chưa đọc: phải bật cờ TailOverflow")
	}

	src.mu.Lock()
	src.changes = many[:100]
	src.mu.Unlock()

	if err := f.SyncNow(context.Background()); err != nil {
		t.Fatal(err)
	}

	if f.TailOverflow() {
		t.Fatal("đuôi đã nhỏ lại và đọc hết: cờ phải tắt")
	}
}

// Epoch phải là hàm của TRẠNG THÁI đã thấy (con trỏ + tập dòng trong đuôi), không phụ thuộc lịch sử poll của
// instance. Hai instance dùng chung Redis, một cái thấy từng dòng một, cái kia thấy cả cụm trong một lần poll,
// phải có cùng epoch khi đã thấy cùng một tập; nếu không, chuỗi epoch trùng cho hai trạng thái khác nhau và
// instance này phục vụ câu trả lời "không bị chặn" đã cũ của instance kia.
func TestEpochDependsOnStateNotOnPollHistory(t *testing.T) {
	ctx := context.Background()
	rows := []model.Change{
		{Seq: 1, XID: "7", Hash: 101, Pending: true},
		{Seq: 2, XID: "7", Hash: 102, Pending: true},
		{Seq: 3, XID: "7", Hash: 103, Pending: true},
	}

	oneByOne := &fakeSource{}
	fa, _ := newFeed(t, oneByOne)

	var intermediate []string

	for i := range rows {
		oneByOne.mu.Lock()
		oneByOne.changes = append([]model.Change(nil), rows[:i+1]...)
		oneByOne.mu.Unlock()

		if err := fa.SyncNow(ctx); err != nil {
			t.Fatal(err)
		}

		intermediate = append(intermediate, fa.Epoch())
	}

	allAtOnce := &fakeSource{}
	fb, _ := newFeed(t, allAtOnce)

	allAtOnce.mu.Lock()
	allAtOnce.changes = append([]model.Change(nil), rows...)
	allAtOnce.mu.Unlock()

	if err := fb.SyncNow(ctx); err != nil {
		t.Fatal(err)
	}

	if fa.Epoch() != fb.Epoch() {
		t.Fatalf("cùng cursor và cùng tập dòng phải cho cùng epoch: %q vs %q", fa.Epoch(), fb.Epoch())
	}

	// Mỗi trạng thái trung gian khác nhau, và không trạng thái nào trùng epoch cuối (kịch bản lỗi: .t3 trùng .t3).
	seen := map[string]bool{}
	for _, e := range intermediate {
		if seen[e] {
			t.Fatalf("hai trạng thái khác nhau có cùng epoch %q: %v", e, intermediate)
		}

		seen[e] = true
	}
}

// Cùng số dòng trong đuôi nhưng là các dòng khác nhau thì epoch phải khác.
func TestEpochDiffersForDifferentTailSets(t *testing.T) {
	ctx := context.Background()
	mk := func(seqs ...int64) string {
		src := &fakeSource{}
		f, _ := newFeed(t, src)

		for _, q := range seqs {
			src.changes = append(src.changes, model.Change{Seq: q, XID: "7", Hash: 1000 + q, Pending: true})
		}

		if err := f.SyncNow(ctx); err != nil {
			t.Fatal(err)
		}

		return f.Epoch()
	}

	if mk(1, 2) == mk(1, 3) {
		t.Fatal("hai đuôi cùng cỡ nhưng khác dòng phải có epoch khác nhau")
	}

	if mk(1, 2) != mk(1, 2) {
		t.Fatal("cùng một đuôi phải cho cùng epoch")
	}
}

// Đúng bằng trần (trang cuối đầy vừa khít) mà không còn dòng nào chưa đọc thì KHÔNG phải tràn.
func TestTailExactlyAtCapIsNotOverflow(t *testing.T) {
	src := &fakeSource{}
	f, _ := newFeed(t, src)
	f.maxTail = batchSize

	exact := make([]model.Change, 0, batchSize)
	for i := 1; i <= batchSize; i++ {
		exact = append(exact, model.Change{Seq: int64(i), XID: "7", Hash: int64(5000 + i), Pending: true})
	}

	src.mu.Lock()
	src.changes = exact
	src.mu.Unlock()

	if err := f.SyncNow(context.Background()); err != nil {
		t.Fatal(err)
	}

	if f.TailOverflow() {
		t.Fatal("đuôi đúng bằng trần và đã đọc hết: không được báo tràn")
	}

	if f.TailLen() != batchSize {
		t.Fatalf("TailLen = %d, want %d", f.TailLen(), batchSize)
	}

	// Thêm một dòng nữa thì mới là tràn thật.
	src.mu.Lock()
	src.changes = append(src.changes, model.Change{Seq: int64(batchSize + 1), XID: "7", Hash: 9, Pending: true})
	src.mu.Unlock()

	if err := f.SyncNow(context.Background()); err != nil {
		t.Fatal(err)
	}

	if !f.TailOverflow() {
		t.Fatal("còn dòng chưa đọc sau khi chạm trần: phải báo tràn")
	}
}
