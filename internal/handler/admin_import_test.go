package handler

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// importPanics đọc số lần panic import đã ghi nhận trong metric.
func importPanics(t *testing.T) float64 {
	t.Helper()

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}

	for _, mf := range families {
		if mf.GetName() == "vsf_import_panics_total" {
			if ms := mf.GetMetric(); len(ms) > 0 {
				return ms[0].GetCounter().GetValue()
			}
		}
	}

	return 0
}

// quietHandler tạo Handler với logger im lặng cho test.
func quietHandler() *Handler {
	return &Handler{Deps: Deps{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}}
}

// Một panic trong goroutine import trước đây làm sập cả process (chimw.Recoverer không thấy goroutine này).
// Giờ job phải được đánh dấu failed, kèm lý do, và process vẫn sống để chạy tiếp test.
func TestGuardImportTurnsPanicIntoFailedJob(t *testing.T) {
	h := quietHandler()
	job := &importJob{ID: "j1", State: "running"}
	before := importPanics(t)

	h.guardImport(job, func() { panic("mô phỏng: file CSV làm thư viện panic") })

	v := job.view()
	if v.State != "failed" || v.Running {
		t.Fatalf("job phải failed và không còn chạy: %+v", v)
	}

	if !strings.Contains(v.Err, "panic") || v.Finished.IsZero() {
		t.Fatalf("job phải có lý do và thời điểm kết thúc: %+v", v)
	}

	if strings.Contains(v.Err, "mô phỏng") {
		t.Fatalf("lý do hiển thị cho người dùng không được lộ nội dung panic: %q", v.Err)
	}

	if d := importPanics(t) - before; d != 1 {
		t.Fatalf("vsf_import_panics_total phải tăng đúng 1, tăng %v", d)
	}
}

// Số đã commit trước khi panic phải được giữ (progress đã ghi vào job), và đường không-panic không bị đổi gì.
func TestGuardImportKeepsProgressAndLeavesNormalRunAlone(t *testing.T) {
	h := quietHandler()

	job := &importJob{ID: "j2", State: "running"}
	h.guardImport(job, func() {
		job.mu.Lock()
		job.Inserted, job.Updated = 300_000, 5
		job.mu.Unlock()
		panic("boom")
	})

	if v := job.view(); v.Inserted != 300_000 || v.Updated != 5 {
		t.Fatalf("phần đã commit phải được giữ: %+v", v)
	}

	ok := &importJob{ID: "j3", State: "running"}
	h.guardImport(ok, func() {})

	if v := ok.view(); v.State != "running" {
		t.Fatalf("không panic thì guard không được đụng vào trạng thái job: %+v", v)
	}
}
