package changefeed

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/redis/go-redis/v9"

	"vsf/internal/metrics"
	"vsf/internal/model"
)

// Đồng bộ filter giữa các pod bằng Redis Pub/Sub.
//
// change_log vẫn là NGUỒN SỰ THẬT; message Pub/Sub chỉ là tín hiệu tăng tốc:
//   - Pod ghi entry: sau khi transaction commit, publish {seq_max, [hash, op]...} (import lớn: chỉ seq_max).
//   - Pod nhận: (1) áp NGAY các hash op=add vào filter (độ trễ ms), (2) đánh thức vòng catch-up để SyncNow đọc
//     change_log từ con trỏ và áp mọi thay đổi (cả add lẫn remove) đúng thứ tự (xid, seq).
//   - Op remove KHÔNG bao giờ áp từ message: message có thể đến trễ / lệch thứ tự so với change_log
//     (ví dụ remove seq 6 rồi add seq 7 cho cùng hash: nếu message remove đến sau khi catch-up đã áp add seq 7,
//     áp remove sẽ gây ÂM TÍNH GIẢ — bỏ lọt số rác). Add từ message thì an toàn: tệ nhất là DƯƠNG TÍNH GIẢ,
//     checker sẽ hỏi DB và trả đúng.
//   - Mất message (Redis drop, pod đang reconnect) không làm sai: safety poll thưa (mặc định 30s) và resync ngay khi
//     (re)subscribe sẽ đọc lại change_log. Không có Redis thì quay về poll nhanh (mặc định 1s).

// DefaultChannel là kênh Redis mặc định cho tín hiệu thay đổi.
const DefaultChannel = "vsf:changes"

// MaxHintHashes: transaction ghi nhiều hơn số hash này thì message chỉ là tín hiệu (không kèm hash), giữ message nhỏ.
const MaxHintHashes = 256

const (
	publishTimeout  = 250 * time.Millisecond
	pingEvery       = 5 * time.Second // kiểm tra kết nối Pub/Sub còn sống khi không có message
	reconnectBackof = time.Second
	maxBackoff      = 15 * time.Second
)

// Message là payload trên kênh Pub/Sub. Giữ ngắn: C = [[hash, op], ...]; thiếu C = chỉ đánh thức.
type Message struct {
	SeqMax int64      `json:"s"`
	TS     int64      `json:"t"` // unix nanos lúc publish (đo độ trễ publish -> apply)
	C      [][2]int64 `json:"c,omitempty"`
}

// Publisher cài đặt store.ChangeNotifier: publish thay đổi đã commit lên Redis. Lỗi chỉ log + metric.
type Publisher struct {
	rdb     redis.UniversalClient
	channel string
	log     *slog.Logger
}

// NewPublisher tạo Publisher trên kênh channel (rỗng = DefaultChannel).
func NewPublisher(rdb redis.UniversalClient, channel string, log *slog.Logger) *Publisher {
	if channel == "" {
		channel = DefaultChannel
	}

	return &Publisher{rdb: rdb, channel: channel, log: log}
}

// EncodeMessage dựng payload; quá MaxHintHashes thì bỏ danh sách hash.
func EncodeMessage(seqMax int64, changes []model.Change, now time.Time) []byte {
	m := Message{SeqMax: seqMax, TS: now.UnixNano()}

	if len(changes) <= MaxHintHashes {
		for _, c := range changes {
			m.C = append(m.C, [2]int64{c.Hash, int64(c.Op)})
		}
	}

	b, _ := json.Marshal(m) // chỉ số nguyên: không thể lỗi
	return b
}

// NotifyChanges publish (đồng bộ, timeout ngắn để không giữ request lâu). Không bao giờ trả lỗi.
func (p *Publisher) NotifyChanges(ctx context.Context, seqMax int64, changes []model.Change) {
	ctx, cancel := context.WithTimeout(ctx, publishTimeout)
	defer cancel()

	if err := p.rdb.Publish(ctx, p.channel, EncodeMessage(seqMax, changes, time.Now())).Err(); err != nil {
		metrics.SyncPublished.WithLabelValues("error").Inc()
		p.log.Warn("change notification publish failed; other pods will catch up via safety poll",
			"err", err, "seq_max", seqMax)

		return
	}

	metrics.SyncPublished.WithLabelValues("ok").Inc()
}

// Wake đánh thức vòng RunSync (không chặn; nhiều lần gọi dồn thành một lần SyncNow).
func (f *Feed) Wake() {
	select {
	case f.wake <- struct{}{}:
	default:
	}
}

// Live: đang nhận tín hiệu Pub/Sub (safety poll thưa). false = poll nhanh (fallback) hoặc không cấu hình Redis.
func (f *Feed) Live() bool { return f.live.Load() }

// setLive đổi trạng thái và đánh thức vòng lặp để nó chọn lại chu kỳ poll (và resync ngay khi vừa subscribe lại).
func (f *Feed) setLive(v bool) {
	if v {
		f.lastLive.Store(time.Now().UnixNano())
	}

	if was := f.live.Swap(v); was != v {
		metrics.SyncSubscribed.Set(map[bool]float64{true: 1, false: 0}[v])

		if !v {
			metrics.SyncFallback.Inc()
			f.log.Warn("redis pub/sub unavailable; changefeed falling back to fast polling")
		} else {
			f.log.Info("redis pub/sub subscribed; changefeed using safety poll")
		}
	}

	f.Wake()
}

// HandleMessage áp gợi ý từ một message: add được áp ngay (an toàn), remove bỏ qua (chờ catch-up theo thứ tự seq),
// rồi đánh thức catch-up. Gợi ý đã cũ (con trỏ đã vượt seq_max, tức catch-up đã áp mọi dòng của message, có thể cả
// một remove sau đó) bị bỏ để không thêm lại một hash vừa bị gỡ.
func (f *Feed) HandleMessage(payload string) {
	var m Message
	if err := json.Unmarshal([]byte(payload), &m); err != nil {
		metrics.SyncReceived.WithLabelValues("invalid").Inc()
		f.Wake() // vẫn có thể là thay đổi thật: đọc change_log cho chắc
		return
	}

	kind := "signal"
	if len(m.C) > 0 {
		kind = "hashes"
	}
	metrics.SyncReceived.WithLabelValues(kind).Inc()

	if m.SeqMax > 0 {
		f.noteWant(m.SeqMax)
	}

	if m.TS > 0 {
		f.hintTS.CompareAndSwap(0, m.TS)
	}

	if l := f.filter.Current(); l != nil && (m.SeqMax == 0 || m.SeqMax > f.cursorSeq.Load()) {
		for _, c := range m.C {
			if int16(c[1]) != OpRemove { // #nosec G115 -- op là 1 hoặc 2
				l.Readd(uint64(c[0])) // #nosec G115 -- cùng bit pattern với hash BIGINT; Readd: không đếm, catch-up sẽ đếm
			}
		}
	}

	f.Wake()
}

// observeHintLatency ghi độ trễ publish -> catch-up xong cho message sớm nhất đang chờ.
func (f *Feed) observeHintLatency() {
	if ts := f.hintTS.Swap(0); ts > 0 {
		metrics.SyncApplyLatency.Observe(max(time.Since(time.Unix(0, ts)).Seconds(), 0))
	}
}

// Subscribe chạy đến khi ctx hủy: giữ subscription Redis trên channel, đẩy message vào HandleMessage.
// (Re)subscribe thành công -> live + resync ngay. Lỗi/mất kết nối -> fallback poll nhanh, thử lại với backoff.
func (f *Feed) Subscribe(ctx context.Context, rdb redis.UniversalClient, channel string) {
	if channel == "" {
		channel = DefaultChannel
	}

	backoff := reconnectBackof

	for ctx.Err() == nil {
		err := f.subscribeOnce(ctx, rdb, channel, func() { backoff = reconnectBackof })
		f.setLive(false)

		if ctx.Err() != nil {
			return
		}

		f.log.Warn("redis pub/sub subscription lost", "err", err, "retry_in", backoff.String())

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff = min(backoff*2, maxBackoff)
	}
}

// subscribeOnce giữ một subscription cho tới khi có lỗi. ReceiveTimeout + Ping phát hiện kết nối chết cả khi kênh im lặng.
func (f *Feed) subscribeOnce(ctx context.Context, rdb redis.UniversalClient, channel string, onOK func()) error {
	ps := rdb.Subscribe(ctx, channel)
	defer ps.Close()

	pinged := false

	for {
		msg, err := ps.ReceiveTimeout(ctx, pingEvery)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() && !pinged {
				// Im lặng quá lâu: ping; nếu pong không về trong chu kỳ sau thì coi là mất kết nối.
				if perr := ps.Ping(ctx); perr != nil {
					return perr
				}

				pinged = true
				continue
			}

			return err
		}

		pinged = false

		switch m := msg.(type) {
		case *redis.Subscription:
			if m.Kind == "subscribe" {
				onOK()
				f.setLive(true) // (re)subscribe: resync ngay vì có thể đã lỡ message trong lúc mất kết nối
			}

		case *redis.Pong:
			f.lastLive.Store(time.Now().UnixNano())

		case *redis.Message:
			f.lastLive.Store(time.Now().UnixNano())
			f.HandleMessage(m.Payload)
		}
	}
}

// Chờ nguồn đọc bắt kịp (F6). Với READ_DATABASE_URL, message Pub/Sub có thể tới TRƯỚC khi replica nhận dòng change_log
// tương ứng: một lần catch-up không thấy gì, con trỏ và epoch không đổi. Thay vì ngủ tới safety poll (30 s), RunSync
// thử lại với backoff lũy thừa catchUpMin -> catchUpMax cho tới khi đọc được seq_max hoặc hết catchUpTimeout.
const (
	catchUpMin     = 5 * time.Millisecond
	catchUpMax     = time.Second
	catchUpTimeout = 10 * time.Second
)

// noteSeen ghi nhận seq lớn nhất đã đọc được từ change_log (CAS max, an toàn đồng thời).
func (f *Feed) noteSeen(seq int64) {
	for {
		cur := f.seenSeq.Load()
		if seq <= cur || f.seenSeq.CompareAndSwap(cur, seq) {
			return
		}
	}
}

// noteWant ghi nhận seq_max lớn nhất đã được báo qua Pub/Sub.
func (f *Feed) noteWant(seq int64) {
	for {
		cur := f.wantSeq.Load()
		if seq <= cur || f.wantSeq.CompareAndSwap(cur, seq) {
			return
		}
	}
}

// Pending: feed biết có thay đổi đã commit (qua Pub/Sub) mà catch-up chưa đọc được (nguồn đọc đang trễ).
// Khi true, filter có thể chứa hash vừa được gợi ý mà DB đọc (replica) chưa có dòng: checker không được cache kết quả âm.
func (f *Feed) Pending() bool {
	want := f.wantSeq.Load()
	return want > f.seenSeq.Load() && want > f.giveUpSeq.Load()
}

// trackCatchUp cập nhật trạng thái chờ sau một lần SyncNow thành công. Trả (behindSince, retry) cho vòng tiếp theo:
// behindSince zero = không chờ (dùng chu kỳ poll thường).
func (f *Feed) trackCatchUp(behindSince time.Time, retry time.Duration) (time.Time, time.Duration) {
	if !f.Pending() {
		if !behindSince.IsZero() {
			metrics.SyncCatchUpWait.Observe(time.Since(behindSince).Seconds())
			metrics.SyncCatchUp.WithLabelValues("caught_up").Inc()
		}

		return time.Time{}, 0
	}

	if behindSince.IsZero() {
		metrics.SyncReplicaBehind.Inc()
		return time.Now(), catchUpMin
	}

	if waited := time.Since(behindSince); waited >= catchUpTimeout {
		// Có thể seq_max không bao giờ xuất hiện (dòng đã bị dọn, message hỏng). Bỏ cuộc để không chặn cache mãi;
		// safety poll vẫn chạy như trước.
		want := f.wantSeq.Load()
		f.giveUpSeq.Store(want)
		metrics.SyncCatchUpWait.Observe(waited.Seconds())
		metrics.SyncCatchUp.WithLabelValues("timeout").Inc()
		f.log.Warn("changefeed: read source did not reach notified seq in time; relying on safety poll",
			"want_seq", want, "seen_seq", f.seenSeq.Load(), "waited", waited.String())

		return time.Time{}, 0
	}

	return behindSince, min(retry*2, catchUpMax)
}
