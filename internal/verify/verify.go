// Package verify chạy nền trên mỗi pod, lấy mẫu ngẫu nhiên hash BLACKLIST còn hiệu lực từ database và kiểm tra filter
// trong RAM có chứa chúng không. Filter chỉ được phép dương tính giả; một âm tính giả nghĩa là spam lọt qua, và trước
// đây không có gì phát hiện được điều đó khi đang chạy.
//
// Loại race (báo động giả): một hash có thể vắng mặt trong filter một cách HỢP LỆ khi dòng vừa được ghi mà changefeed
// chưa áp. Thay vì so xid với con trỏ (con trỏ chỉ bao các dòng đã chốt dưới xmin; dòng Pending đã áp nhưng nằm sau con
// trỏ, nên so xid vừa phức tạp vừa dễ sai), một nghi vấn chỉ được xác nhận sau chuỗi:
//
//	T0  Test(h) = false                       (nghi vấn)
//	S1  SyncNow; Test(h) = false              (mọi thay đổi đã commit và nhìn thấy trước S1 đã được áp, kể cả Pending)
//	R1  DB: h còn dòng BLACKLIST hiệu lực, phiên bản v1 (id:xmin)
//	S2  SyncNow; Test(h) = false              (S2 bắt đầu SAU R1)
//	R2  DB: phiên bản v2 == v1
//
// v1 == v2 nghĩa là không có ghi nào lên các dòng của h trong [R1, R2], nên lần ghi cuối (cùng transaction với dòng
// change_log thêm h) đã commit trước R1, tức trước S2; S2 đọc change_log từ cùng read pool nên đã thấy và áp nó
// (thêm được áp ngay cả khi Pending). Vậy h vắng mặt sau S2 là âm tính giả thật, không phải độ trễ đồng bộ. Ngược lại,
// dòng vừa ghi chưa sync sẽ có mặt sau S1 (bị loại "synced"); dòng bị xóa/WHITELIST giữa chừng bị loại "gone";
// dòng bị ghi giữa chừng bị loại "changed" (sẽ được lấy mẫu lại ở chu kỳ sau nếu thật sự thiếu).
// Giới hạn còn lại: nếu read pool trỏ tới NHIỀU replica khác độ trễ, S2 có thể đọc replica chậm hơn R1; changefeed
// tự chờ replica (F6), và cửa sổ này cần một replica trễ hơn khoảng R1→S2 — hiếm, và chỉ gây cảnh báo chứ không hỏng dữ liệu.
package verify

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"vsf/internal/metrics"
)

// Filter là phần filter cần kiểm tra: *filter.Manager.
type Filter interface {
	Ready() bool
	Test(h uint64) bool
}

// Syncer đưa filter bắt kịp change_log: *changefeed.Feed.
type Syncer interface {
	SyncNow(ctx context.Context) error
}

// Source là nguồn dữ liệu đối chiếu: *store.Store (read pool).
type Source interface {
	SampleActiveBlacklistHashes(ctx context.Context, n int) ([]int64, error)
	ActiveBlacklistVersions(ctx context.Context, hashes []int64) (map[int64]string, error)
}

// Config của bộ kiểm tra.
type Config struct {
	Interval time.Duration // FILTER_VERIFY_INTERVAL (mặc định 1m); <= 0 = tắt
	Sample   int           // FILTER_VERIFY_SAMPLE (mặc định 1000)
	// WarnFor: /readyz giữ cảnh báo trong khoảng này sau âm tính giả gần nhất (mặc định 1h).
	WarnFor time.Duration
	// Heal: thêm lại hash bị thiếu vào filter ngay khi xác nhận (chặn spam lọt qua cho hash đó). Mặc định bật ở main.
	Heal func(h uint64)
	// OnFalseNegative được gọi một lần mỗi chu kỳ có âm tính giả (ví dụ: yêu cầu leader dựng lại snapshot).
	OnFalseNegative func(ctx context.Context, n int)
}

// Status là trạng thái để /readyz báo cáo (chỉ cảnh báo, không làm pod not-ready).
type Status struct {
	LastRun        time.Time
	LastErr        string
	Checked        uint64
	FalseNegatives uint64
	LastFN         time.Time
	LastFNHash     string
}

// Verifier: bộ lấy mẫu chạy nền.
type Verifier struct {
	f   Filter
	s   Syncer
	src Source
	cfg Config
	log *slog.Logger

	mu sync.Mutex
	st Status
}

// New tạo Verifier.
func New(f Filter, s Syncer, src Source, cfg Config, log *slog.Logger) *Verifier {
	if cfg.Sample <= 0 {
		cfg.Sample = 1000
	}

	if cfg.WarnFor <= 0 {
		cfg.WarnFor = time.Hour
	}

	return &Verifier{f: f, s: s, src: src, cfg: cfg, log: log}
}

// Status trả bản sao trạng thái hiện tại.
func (v *Verifier) Status() Status {
	v.mu.Lock()
	defer v.mu.Unlock()

	return v.st
}

// Warning trả chuỗi cảnh báo cho /readyz ("" = không có).
func (v *Verifier) Warning(now time.Time) string {
	st := v.Status()
	if !st.LastFN.IsZero() && now.Sub(st.LastFN) < v.cfg.WarnFor {
		return fmt.Sprintf("filter false negatives detected (%d total, last %s ago, hash %s): spam may be passing; "+
			"see RUNBOOK 'filter false negative'", st.FalseNegatives, now.Sub(st.LastFN).Truncate(time.Second), st.LastFNHash)
	}

	if st.LastErr != "" {
		return "filter verification failing: " + st.LastErr
	}

	return ""
}

// Run chạy RunOnce mỗi Interval cho tới khi ctx hủy.
func (v *Verifier) Run(ctx context.Context) {
	if v.cfg.Interval <= 0 {
		return
	}

	t := time.NewTicker(v.cfg.Interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		if _, err := v.RunOnce(ctx); err != nil && ctx.Err() == nil {
			v.log.Warn("filter verify round failed", "err", err)
		}
	}
}

// RunOnce chạy một chu kỳ và trả các hash âm tính giả đã xác nhận.
func (v *Verifier) RunOnce(ctx context.Context) ([]uint64, error) {
	if !v.f.Ready() {
		return nil, nil
	}

	start := time.Now()
	fns, checked, err := v.round(ctx)
	metrics.FilterVerifyDuration.Observe(time.Since(start).Seconds())
	metrics.FilterVerifyChecked.Add(float64(checked))

	v.mu.Lock()
	v.st.LastRun = start
	v.st.Checked += uint64(checked) // #nosec G115 -- checked >= 0

	if err != nil {
		v.st.LastErr = err.Error()
	} else {
		v.st.LastErr = ""
	}

	if len(fns) > 0 {
		v.st.FalseNegatives += uint64(len(fns))
		v.st.LastFN = time.Now()
		v.st.LastFNHash = hashStr(fns[0])
	}
	v.mu.Unlock()

	if err != nil {
		metrics.FilterVerifyErrors.Inc()
		return nil, err
	}

	if len(fns) > 0 {
		metrics.FilterVerifyFalseNegative.Add(float64(len(fns)))

		for _, h := range fns {
			// Chỉ log hash (đã băm có pepper), không bao giờ log số điện thoại/URL.
			v.log.Error("filter FALSE NEGATIVE: active BLACKLIST hash missing from filter after catch-up",
				"hash", hashStr(h), "healed", v.cfg.Heal != nil)

			if v.cfg.Heal != nil {
				v.cfg.Heal(h)
			}
		}

		if v.cfg.OnFalseNegative != nil {
			v.cfg.OnFalseNegative(ctx, len(fns))
		}
	}

	return fns, nil
}

// round: lấy mẫu -> Test -> chuỗi loại race (xem doc package). Độ phức tạp O(n) phép Test + 2 truy vấn mẫu/đối chiếu;
// SyncNow và truy vấn đối chiếu chỉ chạy khi có nghi vấn.
func (v *Verifier) round(ctx context.Context) ([]uint64, int, error) {
	raw, err := v.src.SampleActiveBlacklistHashes(ctx, v.cfg.Sample)
	if err != nil {
		return nil, 0, fmt.Errorf("sample: %w", err)
	}

	hashes := dedupeSample(raw, v.cfg.Sample)

	var suspects []int64

	for _, h := range hashes {
		if !v.f.Test(uint64(h)) { // #nosec G115 -- cùng bit pattern với hash lưu trong BIGINT
			suspects = append(suspects, h)
		}
	}

	if len(suspects) == 0 {
		return nil, len(hashes), nil
	}

	// S1
	if suspects, err = v.syncAndRetest(ctx, suspects); err != nil || len(suspects) == 0 {
		return nil, len(hashes), err
	}

	// R1
	v1, err := v.src.ActiveBlacklistVersions(ctx, suspects)
	if err != nil {
		return nil, len(hashes), fmt.Errorf("recheck: %w", err)
	}

	suspects = keepIf(suspects, func(h int64) bool { _, ok := v1[h]; return ok }, "gone")
	if len(suspects) == 0 {
		return nil, len(hashes), nil
	}

	// S2
	if suspects, err = v.syncAndRetest(ctx, suspects); err != nil || len(suspects) == 0 {
		return nil, len(hashes), err
	}

	// R2
	v2, err := v.src.ActiveBlacklistVersions(ctx, suspects)
	if err != nil {
		return nil, len(hashes), fmt.Errorf("recheck: %w", err)
	}

	suspects = keepIf(suspects, func(h int64) bool { return v2[h] != "" && v2[h] == v1[h] }, "changed")

	out := make([]uint64, len(suspects))
	for i, h := range suspects {
		out[i] = uint64(h) // #nosec G115
	}

	return out, len(hashes), nil
}

func (v *Verifier) syncAndRetest(ctx context.Context, suspects []int64) ([]int64, error) {
	if err := v.s.SyncNow(ctx); err != nil {
		return nil, fmt.Errorf("sync: %w", err)
	}

	return keepIf(suspects, func(h int64) bool { return !v.f.Test(uint64(h)) }, "synced"), nil // #nosec G115
}

// keepIf giữ phần tử thỏa keep, đếm phần bị loại vào metric theo lý do.
func keepIf(in []int64, keep func(int64) bool, reason string) []int64 {
	out := in[:0]

	for _, h := range in {
		if keep(h) {
			out = append(out, h)
		}
	}

	if d := len(in) - len(out); d > 0 {
		metrics.FilterVerifyDiscarded.WithLabelValues(reason).Add(float64(d))
	}

	return out
}

// dedupeSample khử trùng rồi giữ ngẫu nhiên tối đa n phần tử (Fisher–Yates một phần, O(len)).
func dedupeSample(raw []int64, n int) []int64 {
	seen := make(map[int64]struct{}, len(raw))
	out := make([]int64, 0, len(raw))

	for _, h := range raw {
		if _, ok := seen[h]; !ok {
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}

	if len(out) <= n {
		return out
	}

	for i := 0; i < n; i++ {
		j := i + rand.IntN(len(out)-i) // #nosec G404 -- lấy mẫu, không phải bảo mật
		out[i], out[j] = out[j], out[i]
	}

	return out[:n]
}

func hashStr(h uint64) string { return fmt.Sprintf("%016x", h) }
