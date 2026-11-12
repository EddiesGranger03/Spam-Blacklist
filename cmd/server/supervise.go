package main

import (
	"context"
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"

	"vsf/internal/metrics"
)

// loopRestartDelay là thời gian một vòng nền bị crash chờ trước khi được khởi động lại.
const loopRestartDelay = 5 * time.Second

// supervise chạy một vòng nền sống lâu và khởi động lại nó sau khi panic.
//
// Vì sao khởi động lại thay vì chỉ recover: các vòng này (poll changefeed, các job định kỳ) là thứ giữ Bloom filter và
// bộ đếm API key luôn cập nhật. Nếu một vòng panic và panic chỉ bị nuốt, hoặc để nó làm sập process, thì hoặc vòng biến mất
// trong khi server vẫn trông khỏe (đúng kiểu đình trệ im lặng như C1), hoặc mọi client mất server. Ghi log kèm stack, đếm lại
// (vsf_background_panics_total) và khởi động lại vòng giúp server vẫn đúng, còn /readyz vẫn báo changefeed không khỏe qua Lag()
// nếu nó không hồi phục được.
//
// Vòng trả về bình thường (context của nó đã bị hủy) thì kết thúc giám sát. Lúc khởi động lại có chờ delay, nhưng dừng ngay
// nếu ctx bị hủy.
func supervise(ctx context.Context, log *slog.Logger, name string, delay time.Duration, fn func(context.Context)) {
	for {
		if runGuarded(ctx, log, name, delay, fn) {
			return
		}

		select {
		case <-ctx.Done():
			return

		case <-time.After(delay):
		}
	}
}

// runGuarded chạy fn đúng một lần và báo cho biết nó có trả về bình thường không (false nghĩa là đã panic).
func runGuarded(ctx context.Context, log *slog.Logger, name string, delay time.Duration, fn func(context.Context)) (clean bool) {
	defer func() {
		if r := recover(); r != nil {
			metrics.BackgroundPanics.WithLabelValues(name).Inc()
			log.Error("background loop panicked; restarting it", "loop", name, "panic", fmt.Sprint(r),
				"stack", string(debug.Stack()), "restart_in", delay.String())

			clean = false
		}
	}()

	fn(ctx)

	return true
}
