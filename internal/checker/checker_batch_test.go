package checker

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"vsf/internal/normalize"
)

// poisonFilter mô phỏng một thư viện bên thứ ba bị panic trên một đầu vào lạ: Test() panic khi gặp
// đúng hash "độc", còn lại trả về false (Bloom nói "chắc chắn không có").
type poisonFilter struct{ poison uint64 }

// Test của poisonFilter panic với một hash cụ thể, để kiểm tra việc cô lập lỗi trong batch.
func (p poisonFilter) Test(h uint64) bool {
	if h == p.poison {
		panic("mô phỏng: thư viện panic trên đầu vào lạ")
	}

	return false
}

// TestCheckBatchSurvivesPanicInOneItem tái hiện lỗi M8 (docs/BAO_CAO_TONG_HOP.md): CheckBatch tự sinh
// goroutine cho từng mục, mà chimw.Recoverer chỉ bắt panic ở goroutine của request. Một panic ở MỘT mục
// vì vậy làm sập cả process (Go kết thúc chương trình khi bất kỳ goroutine nào panic mà không ai bắt).
// Sau khi vá, mục đó chỉ trả "internal error", các mục còn lại vẫn có kết quả đúng.
func TestCheckBatchSurvivesPanicInOneItem(t *testing.T) {
	_, poisonKeys, err := normalize.Candidates(normalize.TypePhone, "0900000001", "VN")
	if err != nil {
		t.Fatal(err)
	}

	ck := newChecker(poisonFilter{poison: uint64(poisonKeys[0].Hash)}, newMemCache(), &fakeFinder{})

	items := []Item{
		{Type: "phone", Value: "0900000000"},
		{Type: "phone", Value: "0900000001"}, // mục gây panic
		{Type: "phone", Value: "0900000002"},
		{Type: "url", Value: "http://example.com"},
		{Type: "phone", Value: "không phải số"}, // lỗi đầu vào thông thường, không liên quan panic
	}

	panicsBefore := counterValue(t, "vsf_check_panics_total")

	got := ck.CheckBatch(context.Background(), items)
	if len(got) != len(items) {
		t.Fatalf("muốn %d kết quả, được %d", len(items), len(got))
	}

	if d := counterValue(t, "vsf_check_panics_total") - panicsBefore; d != 1 {
		t.Errorf("vsf_check_panics_total phải tăng đúng 1 để vận hành biết có panic, tăng %v", d)
	}

	if got[1].Error != "internal error" || got[1].Blacklisted {
		t.Errorf("mục gây panic phải là internal error và không blacklisted: %+v", got[1])
	}

	if got[1].Input != "0900000001" || got[1].Type != "phone" {
		t.Errorf("mục gây panic vẫn phải giữ type/input để người gọi đối chiếu được: %+v", got[1])
	}

	for _, i := range []int{0, 2, 3} {
		if got[i].Error != "" || got[i].Normalized == "" {
			t.Errorf("mục %d không liên quan panic phải có kết quả bình thường: %+v", i, got[i])
		}
	}

	if got[4].Error == "" || got[4].Error == "internal error" {
		t.Errorf("lỗi đầu vào thông thường phải giữ thông báo cụ thể, không bị gộp thành internal error: %+v", got[4])
	}
}

// counterValue đọc giá trị hiện tại của một bộ đếm Prometheus theo tên, bằng DefaultGatherer (không
// cần thêm thư viện testutil vào go.mod). Bộ đếm chưa xuất hiện được coi là 0.
func counterValue(t *testing.T, name string) float64 {
	t.Helper()

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}

	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}

		if ms := mf.GetMetric(); len(ms) > 0 {
			return ms[0].GetCounter().GetValue()
		}
	}

	return 0
}
