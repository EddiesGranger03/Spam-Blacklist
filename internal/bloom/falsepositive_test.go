package bloom

import (
	"math/rand/v2"
	"testing"
)

// TestMeasuredFalsePositiveRate đo thực tế tỉ lệ dương tính giả (Bước 13) và kiểm tra không có âm tính giả.
// Hash thật là xxhash 64 bit nên phân bố đều; ở đây dùng uint64 ngẫu nhiên (seed cố định để test tất định).
// Cấu hình 10 bit/phần tử, 7 hàm băm có lý thuyết ≈ 0,82%; ngưỡng cho phép 1,5% để chừa sai số thống kê.
func TestMeasuredFalsePositiveRate(t *testing.T) {
	const (
		items  = 1_000_000
		probes = 1_000_000
	)

	rng := rand.New(rand.NewPCG(1, 2))
	f := New(items)
	added := make(map[uint64]struct{}, items)

	for len(added) < items {
		h := rng.Uint64()
		if _, dup := added[h]; dup {
			continue
		}

		added[h] = struct{}{}
		f.Add(h)
	}

	for h := range added {
		if !f.Test(h) {
			t.Fatalf("âm tính giả: hash %d đã thêm nhưng Test trả false", h)
		}
	}

	var fp int

	for n := 0; n < probes; {
		h := rng.Uint64()
		if _, in := added[h]; in {
			continue
		}

		n++

		if f.Test(h) {
			fp++
		}
	}

	rate := float64(fp) / probes
	t.Logf("items=%d, bộ nhớ=%d byte (%.1f bit/mục), dương tính giả: %d/%d = %.3f%% (lý thuyết ≈ 0,82%%)",
		items, f.SizeBytes(), float64(f.SizeBytes())*8/items, fp, probes, rate*100)

	if rate > 0.015 {
		t.Fatalf("tỉ lệ dương tính giả %.3f%% vượt ngưỡng 1,5%%", rate*100)
	}
}

// TestFalsePositiveRateWhenOverfilled đo khi dữ liệu vượt dung lượng dự kiến (BLOOM_EXPECTED_ITEMS đặt thấp):
// tỉ lệ tăng nhưng không bao giờ có âm tính giả. Chỉ ghi nhận số đo, không ép ngưỡng chặt.
func TestFalsePositiveRateWhenOverfilled(t *testing.T) {
	const (
		capacity = 200_000
		items    = 2 * capacity
		probes   = 200_000
	)

	rng := rand.New(rand.NewPCG(3, 4))
	f := New(capacity)
	added := make(map[uint64]struct{}, items)

	for len(added) < items {
		h := rng.Uint64()
		if _, dup := added[h]; dup {
			continue
		}

		added[h] = struct{}{}
		f.Add(h)
	}

	for h := range added {
		if !f.Test(h) {
			t.Fatalf("âm tính giả khi filter quá tải: hash %d", h)
		}
	}

	var fp int

	for n := 0; n < probes; {
		h := rng.Uint64()
		if _, in := added[h]; in {
			continue
		}

		n++

		if f.Test(h) {
			fp++
		}
	}

	t.Logf("quá tải 2x (%d mục trên dung lượng %d): dương tính giả %.2f%%", items, capacity, float64(fp)/probes*100)
}
