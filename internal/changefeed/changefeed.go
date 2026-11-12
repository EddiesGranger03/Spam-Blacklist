package changefeed

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"vsf/internal/bloom"
	"vsf/internal/model"
)

// Source: Interface định nghĩa các thao tác đọc dữ liệu thay đổi từ tầng lưu trữ database.
type Source interface {
	Head(ctx context.Context) (xid string, seq int64, err error)
	// ChangesSince trả về các thay đổi đã commit sau vị trí con trỏ, sắp xếp theo thứ tự (xid, seq).
	// Các hàng có Pending=true là thấy được nhưng chưa chốt; các hàng không Pending sẽ nằm trước.
	ChangesSince(ctx context.Context, afterXID string, afterSeq int64, limit int) ([]model.Change, error)
	AllHashes(ctx context.Context, emit func(uint64)) error
	EstimatedCount(ctx context.Context) (int64, error)
	PurgeChanges(ctx context.Context, olderThan time.Duration) (int64, error)
}

const (
	batchSize = 10000

	// defaultMaxTail giới hạn số lượng hàng Pending tối đa được đọc trong một lần thăm dò.
	// Nếu vượt quá giới hạn này mà vẫn còn hàng chưa đọc, một số bản ghi có thể chưa vào Bloom filter,
	// gây rủi ro sai sót dữ liệu, do đó sẽ kích hoạt TailOverflow (làm /readyz báo lỗi).
	defaultMaxTail = 1_000_000
)

// Feed: Cấu trúc quản lý luồng bắt sự kiện thay đổi dữ liệu (CDC) để đồng bộ vào Bloom filter.
type Feed struct {
	src   Source
	bloom *bloom.Manager
	log   *slog.Logger

	mu  sync.Mutex
	xid string // Con trỏ bền vững: chỉ di chuyển qua các hàng đã chốt hoàn toàn (dưới xmin)
	seq int64

	// tail lưu seq của các hàng Pending đã nạp vào Bloom filter nhưng vẫn vượt quá con trỏ an toàn.
	// Các hàng Pending được đọc lại mỗi lần poll nên tập hợp này giúp tránh nạp trùng lặp.
	tail    map[int64]struct{}
	maxTail int

	epoch        atomic.Value
	lastPoll     atomic.Int64
	tailLen      atomic.Int64
	stalledSince atomic.Int64 // Thời điểm unix nanos từ lúc tail liên tục có dữ liệu; 0 = không có tail
	tailOverflow atomic.Bool
}

// New: Khởi tạo đối tượng Feed quản lý luồng đồng bộ dữ liệu vào Bloom filter.
func New(src Source, b *bloom.Manager, log *slog.Logger) *Feed {
	f := &Feed{src: src, bloom: b, log: log, xid: "0", tail: map[int64]struct{}{}, maxTail: defaultMaxTail}
	f.epoch.Store("0.0")
	return f
}

// Epoch: Trả về chuỗi định danh phiên bản trạng thái hiện tại của cache và Bloom filter.
func (f *Feed) Epoch() string { return f.epoch.Load().(string) }

// Lag: Đo khoảng thời gian từ lần cuối cùng thăm dò (poll) database thành công đến thời điểm hiện tại.
func (f *Feed) Lag() time.Duration {
	t := f.lastPoll.Load()
	if t == 0 {
		return time.Duration(1<<62 - 1)
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

// setCursor: Cập nhật vị trí con trỏ đã đọc an toàn và công bố epoch tương ứng.
func (f *Feed) setCursor(xid string, seq int64) {
	f.xid, f.seq = xid, seq
	f.publishEpoch()
}

// Init: Khởi tạo con trỏ ban đầu từ vị trí mới nhất của database và xây dựng Bloom filter.
func (f *Feed) Init(ctx context.Context, expectedItems uint64) error {
	xid, seq, err := f.src.Head(ctx)
	if err != nil {
		return fmt.Errorf("head: %w", err)
	}

	f.mu.Lock()
	f.setCursor(xid, seq)
	f.mu.Unlock()

	if err := f.Rebuild(ctx, expectedItems); err != nil {
		return err
	}

	f.lastPoll.Store(time.Now().UnixNano())
	return nil
}

// Rebuild: Quét toàn bộ hash từ database và xây dựng lại toàn bộ mảng bit của Bloom filter.
func (f *Feed) Rebuild(ctx context.Context, expectedItems uint64) error {
	start := time.Now()
	size := expectedItems

	if est, err := f.src.EstimatedCount(ctx); err == nil && est > 0 {
		if want := uint64(est) * 13 / 10; want > size {
			size = want
		}
	}

	err := f.bloom.Rebuild(ctx, size, func(ctx context.Context, emit func(uint64)) error {
		return f.src.AllHashes(ctx, emit)
	})
	if err != nil {
		return err
	}

	f.log.Info("bloom rebuilt", "items", f.bloom.Items(), "bytes", f.bloom.SizeBytes(), "took", time.Since(start).String())
	return nil
}

// SyncNow: Quét và nạp các thay đổi mới nhất từ bảng change_log vào Bloom filter.
// Mọi dòng đã commit được nạp ngay lập tức, kể cả các dòng Pending. Con trỏ an toàn chỉ dịch chuyển
// qua các dòng đã hoàn tất hoàn toàn để tránh bỏ sót các transaction commit muộn hơn.
func (f *Feed) SyncNow(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	var (
		curX, curS = f.xid, f.seq // Con trỏ phân trang cho lần thăm dò này
		tail       = map[int64]struct{}{}
		overflow   bool
	)

	for {
		changes, err := f.src.ChangesSince(ctx, curX, curS, batchSize)
		if err != nil {
			f.publishEpoch() // Bloom filter có thể đã thay đổi: không để lại epoch cũ

			return err
		}

		safeX, safeS, advanced := "", int64(0), false

		for _, c := range changes {
			if _, seen := f.tail[c.Seq]; !seen {
				f.bloom.Add(uint64(c.Hash))  // #nosec G115 -- chủ ý: cùng bit pattern với hash đã lưu trong BIGINT
			}

			if c.Pending {
				tail[c.Seq] = struct{}{}
				continue
			}

			// Một dòng đã chốt đồng nghĩa với việc các dòng Pending thu thập trước đó đều nằm trước nó,
			// con trỏ an toàn có thể đi qua chúng.
			clear(tail)

			safeX, safeS, advanced = c.XID, c.Seq, true
		}

		if advanced {
			f.xid, f.seq = safeX, safeS // Epoch được công bố 1 lần sau toàn bộ lần thăm dò
		}

		f.lastPoll.Store(time.Now().UnixNano())

		if len(changes) < batchSize {
			break
		}

		last := changes[len(changes)-1]
		curX, curS = last.XID, last.Seq

		if len(tail) >= f.maxTail {
			// Ngưỡng trần chỉ là vấn đề nếu vẫn còn các dòng chưa đọc
			more, err := f.src.ChangesSince(ctx, curX, curS, 1)
			if err != nil {
				f.publishEpoch()

				return err
			}

			if len(more) > 0 {
				overflow = true
				break
			}
		}
	}

	f.tail = tail
	f.publishEpoch()

	f.tailLen.Store(int64(len(tail)))

	switch {
	case len(tail) == 0:
		f.stalledSince.Store(0)

	case f.stalledSince.Load() == 0:
		f.stalledSince.Store(time.Now().UnixNano())
	}

	if was := f.tailOverflow.Swap(overflow); overflow && !was {
		f.log.Error("changefeed: quá nhiều thay đổi đang chờ transaction mở; "+
			"Bloom filter có thể chưa đầy đủ cho đến khi transaction kết thúc", "tail", len(tail), "max", f.maxTail)
	}

	return nil
}

// Run: Vòng lặp chạy nền định kỳ gọi SyncNow theo chu kỳ thời gian định sẵn.
func (f *Feed) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return

		case <-t.C:
			if err := f.SyncNow(ctx); err != nil && ctx.Err() == nil {
				f.log.Error("changefeed poll failed", "err", err)
			}
		}
	}
}
