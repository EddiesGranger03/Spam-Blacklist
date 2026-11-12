package main

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// quietLog tạo logger im lặng cho test.
func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// panicsFor đọc số lần panic đã ghi nhận cho một vòng nền trong metric.
func panicsFor(t *testing.T, loop string) float64 {
	t.Helper()

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}

	for _, mf := range families {
		if mf.GetName() != "vsf_background_panics_total" {
			continue
		}

		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "loop" && l.GetValue() == loop {
					return m.GetCounter().GetValue()
				}
			}
		}
	}

	return 0
}

// waitFor chờ đến khi điều kiện đúng (có giới hạn thời gian), báo lỗi test nếu quá hạn.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
		if cond() {
			return
		}
	}

	t.Fatalf("hết thời gian chờ: %s", what)
}

// Vòng lặp panic hai lần phải được khởi động lại, rồi chạy bình thường, đếm đúng 2 lần panic, và dừng khi ctx hủy.
func TestSuperviseRestartsLoopAfterPanic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var runs atomic.Int32

	done := make(chan struct{})
	before := panicsFor(t, "t-restart")

	go func() {
		defer close(done)
		supervise(ctx, quietLog(), "t-restart", 5*time.Millisecond, func(c context.Context) {
			if runs.Add(1) <= 2 {
				panic("mô phỏng: vòng nền panic")
			}

			<-c.Done()
		})
	}()

	waitFor(t, "vòng lặp chạy lần thứ 3 (sau 2 lần panic)", func() bool { return runs.Load() == 3 })

	if d := panicsFor(t, "t-restart") - before; d != 2 {
		t.Fatalf("vsf_background_panics_total phải tăng đúng 2, tăng %v", d)
	}

	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("supervise phải dừng khi ctx hủy")
	}

	if runs.Load() != 3 {
		t.Fatalf("sau khi ctx hủy không được chạy lại, runs=%d", runs.Load())
	}
}

// Đang chờ khởi động lại mà ctx bị hủy (tắt server) thì phải thoát ngay, không chờ hết thời gian chờ.
func TestSuperviseStopsDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var runs atomic.Int32

	done := make(chan struct{})

	go func() {
		defer close(done)
		supervise(ctx, quietLog(), "t-backoff", time.Hour, func(context.Context) {
			runs.Add(1)
			panic("boom")
		})
	}()

	waitFor(t, "lần chạy đầu tiên", func() bool { return runs.Load() == 1 })
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("phải thoát ngay khi ctx hủy dù đang chờ 1 giờ")
	}
}
