package changefeed

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"vsf/internal/filter"
	"vsf/internal/model"
)

// Source: Interface định nghĩa các thao tác đọc dữ liệu thay đổi từ tầng lưu trữ database.
type Source interface {
	Head(ctx context.Context) (xid string, seq int64, err error)
	// ChangesSince trả về các thay đổi đã commit sau vị trí con trỏ, sắp xếp theo thứ tự (xid, seq).
	// Các hàng có Pending=true là thấy được nhưng chưa chốt; các hàng không Pending sẽ nằm trước.
	ChangesSince(ctx context.Context, afterXID string, afterSeq int64, limit int) ([]model.Change, error)
}

// HashScanner quét toàn bộ hash đang BLACKLIST (chỉ dùng cho full build: leader dựng snapshot, hoặc test/dev).
type HashScanner interface {
	ScanBlacklistHashes(ctx context.Context, emit func(uint64)) error
}

// Mã thao tác trong change_log.op (model.Change.Op). 0 = dòng cũ trước khi có cột op, coi như thêm.
const (
	OpAdd    = model.OpAdd
	OpRemove = model.OpRemove
)

const (
	batchSize = 10000

	// defaultMaxTail giới hạn số lượng hàng Pending tối đa được đọc trong một lần thăm dò.
	// Nếu vượt quá giới hạn này mà vẫn còn hàng chưa đọc, một số bản ghi có thể chưa vào filter,
	// gây rủi ro sai sót dữ liệu, do đó sẽ kích hoạt TailOverflow (làm /readyz báo lỗi).
	defaultMaxTail = 1_000_000
)

// ErrRebuilding: đang có một lần full build khác chạy.
var ErrRebuilding = errors.New("filter rebuild already in progress")

// Feed: Cấu trúc quản lý luồng bắt sự kiện thay đổi dữ liệu (CDC) để đồng bộ vào filter 3 lớp.
type Feed struct {
	src    Source
	filter *filter.Manager
	log    *slog.Logger

	buildMu sync.Mutex // chỉ một full build cùng lúc

	mu  sync.Mutex
	xid string // Con trỏ bền vững: chỉ di chuyển qua các hàng đã chốt hoàn toàn (dưới xmin)
	seq int64

	// tail lưu seq của các hàng Pending đã thấy nhưng vẫn vượt quá con trỏ an toàn (dùng cho epoch và cảnh báo).
	tail    map[int64]struct{}
	maxTail int

	epoch        atomic.Value
	lastPoll     atomic.Int64
	tailLen      atomic.Int64
	stalledSince atomic.Int64 // Thời điểm unix nanos từ lúc tail liên tục có dữ liệu; 0 = không có tail
	tailOverflow atomic.Bool

	// Đồng bộ qua Redis Pub/Sub (notify.go).
	wake      chan struct{} // cap 1: nhiều tín hiệu dồn lại chỉ gây MỘT lần SyncNow (coalesce)
	live      atomic.Bool   // đang subscribe Redis thành công: dùng safety poll thưa; false = poll nhanh (fallback)
	lastLive  atomic.Int64  // unix nanos lần cuối kết nối Pub/Sub được xác nhận còn sống (message/pong/subscribe)
	cursorSeq atomic.Int64  // bản sao f.seq đọc không cần khóa (bỏ qua gợi ý đã cũ)
	hintTS    atomic.Int64  // thời điểm publish (unix nanos) sớm nhất chưa được đo độ trễ; 0 = không có

	// F6 (replica trễ): wantSeq = seq_max lớn nhất nhận qua Pub/Sub; seenSeq = seq lớn nhất catch-up đã đọc được
	// từ change_log (kể cả dòng Pending); giveUpSeq = wantSeq tại lần bỏ cuộc chờ gần nhất. wantSeq > max(seen, giveUp)
	// nghĩa là nguồn đọc (replica) chưa thấy một thay đổi đã commit: xem Pending.
	wantSeq   atomic.Int64
	seenSeq   atomic.Int64
	giveUpSeq atomic.Int64
}

// New: Khởi tạo Feed đồng bộ change_log vào filter do m quản lý.
func New(src Source, m *filter.Manager, log *slog.Logger) *Feed {
	f := &Feed{src: src, filter: m, log: log, xid: "0", tail: map[int64]struct{}{}, maxTail: defaultMaxTail,
		wake: make(chan struct{}, 1)}
	f.epoch.Store("0.0")
	return f
}

// Epoch: Trả về chuỗi định danh phiên bản trạng thái hiện tại của cache và Bloom filter.
func (f *Feed) Epoch() string { return f.epoch.Load().(string) }

// Lag: Đo khoảng thời gian từ lần cuối cùng thăm dò (poll) database thành công đến thời điểm hiện tại.
// Khi đang subscribe Redis, safety poll chỉ chạy thưa (mặc định 30s) nhưng mọi thay đổi đều đánh thức feed ngay,
// nên "đồng bộ" còn được xác nhận bởi kết nối Pub/Sub còn sống (ping định kỳ): Lag lấy mốc gần hơn trong hai mốc.
func (f *Feed) Lag() time.Duration {
	t := f.lastPoll.Load()
	if t == 0 {
		return time.Duration(1<<62 - 1)
	}

	if l := f.lastLive.Load(); f.live.Load() && l > t {
		t = l
	}

	return time.Since(time.Unix(0, t))
}

// TailLen: Trả về số lượng bản ghi thay đổi đang tạm chờ sau các transaction database chưa đóng.
// Hash của chúng đã được thêm vào Bloom filter, chỉ là con trỏ chưa thể vượt qua chúng.
func (f *Feed) TailLen() int { return int(f.tailLen.Load()) }

// StalledFor: Trả về thời gian mà danh sách đuôi (tail) liên tục bị ứ đọng do transaction dài.
// Bằng 0 nếu không có bản ghi nào bị kẹt ở tail.
func (f *Feed) StalledFor() time.Duration {
	t := f.stalledSince.Load()
	if t == 0 {
		return 0
	}

	return time.Since(time.Unix(0, t))
}

// TailOverflow: Báo hiệu việc danh sách chờ vượt quá ngưỡng an toàn, cảnh báo nguy cơ thiếu sót dữ liệu.
// Khác với ứ đọng thông thường, đây là lỗi ảnh hưởng đến tính đúng đắn của dữ liệu.
func (f *Feed) TailOverflow() bool { return f.tailOverflow.Load() }

// mixSeq: Hàm băm số thứ tự seq để tạo dấu vân tay (fingerprint) không phụ thuộc vào thứ tự hàng.
func mixSeq(seq int64) uint64 {
	z := uint64(seq) + 0x9e3779b97f4a7c15  // #nosec G115 -- seq là BIGSERIAL luôn dương; phép trộn bit cho dấu vân tay tail
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb

	return z ^ (z >> 31)
}

// publishEpoch: Cập nhật và lưu trữ giá trị epoch mới phản ánh đúng trạng thái dữ liệu hiện tại.
// Phải được gọi khi đang giữ f.mu. Epoch thay đổi sẽ làm vô hiệu hóa cache cũ ở Redis.
func (f *Feed) publishEpoch() {
	e := fmt.Sprintf("%s.%d", f.xid, f.seq)

	if n := len(f.tail); n > 0 {
		var fp uint64
		for seq := range f.tail {
			fp += mixSeq(seq)
		}

		e += fmt.Sprintf(".t%d-%016x", n, fp)
	}

	f.epoch.Store(e)
}


// Filter trả về Manager của filter đang phục vụ.
func (f *Feed) Filter() *filter.Manager { return f.filter }

// Init: full build cục bộ (quét bảng) rồi cài đặt. Chỉ dùng cho test/dev hoặc khi được gọi tường minh;
// production khởi động từ snapshot (package snapshot) để N pod không cùng quét bảng.
func (f *Feed) Init(ctx context.Context, expectedItems uint64) error {
	return f.Rebuild(ctx, expectedItems)
}

// BuildStatic đọc con trỏ an toàn (Head) rồi quét mọi hash BLACKLIST và dựng lớp cố định.
// Đọc Head TRƯỚC khi quét: mọi thay đổi <= con trỏ đã commit trước lúc quét nên đã phản ánh trong kết quả quét;
// các thay đổi sau con trỏ được replay khi cài đặt (replay theo đúng thứ tự nên thêm/gỡ lặp lại là vô hại).
func (f *Feed) BuildStatic(ctx context.Context, expectedItems uint64) (*filter.BinaryFuse8, string, int64, error) {
	sc, ok := f.src.(HashScanner)
	if !ok {
		return nil, "", 0, errors.New("changefeed: source cannot scan hashes")
	}

	xid, seq, err := f.src.Head(ctx)
	if err != nil {
		return nil, "", 0, fmt.Errorf("head: %w", err)
	}

	keys := make([]uint64, 0, min(expectedItems, 1<<28))
	if err := sc.ScanBlacklistHashes(ctx, func(h uint64) { keys = append(keys, h) }); err != nil {
		return nil, "", 0, err
	}

	keys = filter.DedupeSorted(keys)

	static, err := filter.BuildBinaryFuse8(keys)
	if err != nil {
		return nil, "", 0, err
	}

	return static, xid, seq, nil
}

// Rebuild: full build cục bộ, rồi cài đặt (replay change_log sau con trỏ). Lỗi thì giữ filter cũ.
func (f *Feed) Rebuild(ctx context.Context, expectedItems uint64) error {
	if !f.buildMu.TryLock() {
		return ErrRebuilding
	}
	defer f.buildMu.Unlock()

	start := time.Now()

	static, xid, seq, err := f.BuildStatic(ctx, expectedItems)
	if err != nil {
		return err
	}

	l := filter.NewLayered(static, filter.DefaultDeltaCapacity(static.Items))
	if err := f.Install(ctx, l, filter.Source{CursorXID: xid, CursorSeq: seq}); err != nil {
		return err
	}

	f.log.Info("filter rebuilt", "items", static.Items, "bytes", f.filter.SizeBytes(), "took", time.Since(start).String())
	return nil
}

// Install replay change_log sau con trỏ của src vào l (khi l CHƯA phục vụ), rồi swap atomic và đặt con trỏ của feed.
// Vì replay xong mới swap, không có lúc nào filter đang phục vụ thiếu thay đổi (không âm tính giả).
// delta/removed của filter cũ bị bỏ: chúng chỉ chứa thay đổi mà snapshot mới đã gộp (<= con trỏ) hoặc được replay lại (> con trỏ).
func (f *Feed) Install(ctx context.Context, l *filter.Layered, src filter.Source) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	x, s, tail, overflow, err := f.replay(ctx, l, src.CursorXID, src.CursorSeq, nil)
	if err != nil {
		return fmt.Errorf("replay after snapshot cursor: %w", err)
	}

	f.filter.Swap(l, src)
	f.xid, f.seq = x, s
	f.cursorSeq.Store(s)
	f.noteSeen(s)
	f.finishPoll(tail, overflow)

	return nil
}

// apply áp một thay đổi vào filter.
// Gỡ (op=2) đang Pending thì HOÃN: một transaction cũ hơn còn mở có thể commit một lần thêm đứng TRƯỚC nó,
// áp gỡ sớm có thể gây âm tính giả; dòng Pending được đọc lại mỗi lần poll nên sẽ được áp khi đã chốt.
// Thêm thì áp ngay (dương tính giả là vô hại), và áp lại mỗi lần đọc lại để giữ đúng thứ tự với các lần gỡ.
// seen: dòng này đã được áp ở lần poll trước (nằm trong tail cũ) — áp lại nhưng không đếm lại.
func apply(l *filter.Layered, c model.Change, seen bool) {
	h := uint64(c.Hash) // #nosec G115 -- chủ ý: cùng bit pattern với hash đã lưu trong BIGINT

	if c.Op == OpRemove {
		if !c.Pending {
			l.Remove(h)
		}

		return
	}

	if seen {
		l.Readd(h)
		return
	}

	l.Add(h)
}

// replay đọc mọi thay đổi sau (x, s) và áp vào l. Trả về con trỏ an toàn mới, tập tail (seq Pending) và cờ tràn.
// Khi lỗi giữa chừng, các thay đổi đã áp vẫn nằm trong l; con trỏ trả về là điểm an toàn cuối cùng đã áp.
func (f *Feed) replay(ctx context.Context, l *filter.Layered, x string, s int64, prevTail map[int64]struct{}) (string, int64, map[int64]struct{}, bool, error) {
	var (
		curX, curS = x, s // Con trỏ phân trang cho lần thăm dò này
		tail       = map[int64]struct{}{}
	)

	for {
		changes, err := f.src.ChangesSince(ctx, curX, curS, batchSize)
		if err != nil {
			return x, s, tail, false, err
		}

		for _, c := range changes {
			f.noteSeen(c.Seq)
			_, seen := prevTail[c.Seq]
			apply(l, c, seen)

			if c.Pending {
				tail[c.Seq] = struct{}{}
				continue
			}

			clear(tail)
			x, s = c.XID, c.Seq
		}

		if len(changes) < batchSize {
			return x, s, tail, false, nil
		}

		last := changes[len(changes)-1]
		curX, curS = last.XID, last.Seq

		if len(tail) >= f.maxTail {
			more, err := f.src.ChangesSince(ctx, curX, curS, 1)
			if err != nil {
				return x, s, tail, false, err
			}

			if len(more) > 0 {
				return x, s, tail, true, nil
			}
		}
	}
}

// finishPoll cập nhật tail, epoch và các chỉ số sau một lần đồng bộ thành công. Gọi khi giữ f.mu.
func (f *Feed) finishPoll(tail map[int64]struct{}, overflow bool) {
	f.tail = tail
	f.publishEpoch()
	f.lastPoll.Store(time.Now().UnixNano())
	f.tailLen.Store(int64(len(tail)))

	switch {
	case len(tail) == 0:
		f.stalledSince.Store(0)

	case f.stalledSince.Load() == 0:
		f.stalledSince.Store(time.Now().UnixNano())
	}

	if was := f.tailOverflow.Swap(overflow); overflow && !was {
		f.log.Error("changefeed: quá nhiều thay đổi đang chờ transaction mở; "+
			"filter có thể chưa đầy đủ cho đến khi transaction kết thúc", "tail", len(tail), "max", f.maxTail)
	}
}

// SyncNow: Quét và nạp các thay đổi mới nhất từ bảng change_log vào filter đang phục vụ.
// Thêm được nạp ngay, kể cả dòng Pending; gỡ chỉ áp khi dòng đã chốt. Con trỏ an toàn chỉ dịch chuyển
// qua các dòng đã hoàn tất hoàn toàn để tránh bỏ sót các transaction commit muộn hơn.
// Chưa có filter (chưa ready) thì không làm gì: con trỏ chỉ được đặt bởi Install.
func (f *Feed) SyncNow(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	l := f.filter.Current()
	if l == nil {
		return nil
	}

	x, s, tail, overflow, err := f.replay(ctx, l, f.xid, f.seq, f.tail)
	f.xid, f.seq = x, s
	f.cursorSeq.Store(s)
	f.noteSeen(s)

	if err != nil {
		f.publishEpoch() // filter có thể đã thay đổi: không để lại epoch cũ
		return err
	}

	f.finishPoll(tail, overflow)

	return nil
}

// Run: Vòng lặp chạy nền định kỳ gọi SyncNow theo chu kỳ cố định (không dùng Pub/Sub).
func (f *Feed) Run(ctx context.Context, interval time.Duration) {
	f.RunSync(ctx, interval, interval)
}

// RunSync: vòng lặp catch-up từ change_log. Chạy SyncNow khi (1) được đánh thức (Wake: có message Pub/Sub,
// vừa (re)subscribe, hoặc trạng thái Redis đổi) hoặc (2) hết chu kỳ: safety khi đang subscribe Redis (thưa, chỉ để
// phòng message bị mất), fallback khi không có Redis (poll nhanh như trước). Chu kỳ được chọn lại sau mỗi vòng,
// và mỗi lần đổi trạng thái đều Wake nên chuyển sang fallback không phải chờ hết chu kỳ safety đang chạy.
// Chỉ goroutine này gọi SyncNow cho tín hiệu Pub/Sub: tín hiệu dồn lại trong kênh cap 1 nên không spawn goroutine.
func (f *Feed) RunSync(ctx context.Context, safety, fallback time.Duration) {
	t := time.NewTimer(fallback)
	defer t.Stop()

	var (
		behindSince time.Time     // != zero: đang chờ nguồn đọc (replica) bắt kịp seq_max đã nhận (F6)
		retry       time.Duration // chu kỳ thử lại hiện tại khi đang chờ
	)

	for {
		d := fallback
		if f.live.Load() {
			d = safety
		}

		if !behindSince.IsZero() {
			d = min(d, retry)
		}

		t.Reset(d)

		select {
		case <-ctx.Done():
			return

		case <-t.C:
		case <-f.wake:
			t.Stop()
		}

		if err := f.SyncNow(ctx); err != nil {
			if ctx.Err() == nil {
				f.log.Error("changefeed poll failed", "err", err)
			}

			continue
		}

		behindSince, retry = f.trackCatchUp(behindSince, retry)

		if behindSince.IsZero() {
			f.observeHintLatency()
		}
	}
}
