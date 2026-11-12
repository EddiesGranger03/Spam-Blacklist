package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// value đọc giá trị hiện tại của một counter.
func value(c prometheus.Counter) float64 {
	var m dto.Metric
	_ = c.Write(&m)

	return m.GetCounter().GetValue()
}

func TestCountersRegisterAndCount(t *testing.T) {
	before := value(CheckPanics)
	CheckPanics.Inc()

	if got := value(CheckPanics) - before; got != 1 {
		t.Fatalf("CheckPanics rose by %v, want 1", got)
	}

	CheckLayer.WithLabelValues("bloom").Add(2)
	CheckResult.WithLabelValues("safe").Inc()
	APIKeyRequests.WithLabelValues("1", "ok").Inc()
	BackgroundPanics.WithLabelValues("loop").Inc()
	HTTPDuration.WithLabelValues("GET", "/x", "200").Observe(0.01)
	BloomFalsePositive.Inc()
	QuotaBackendErrors.Inc()
	CacheErrors.Inc()
	RateLimitBackendErrors.Inc()
	LoginFailures.WithLabelValues("bad_credentials").Inc()
	LoginAttackSuspected.Inc()
	ImportPanics.Inc()

	if got := value(BloomFalseNegative); got != 0 {
		t.Fatalf("BloomFalseNegative must stay 0, got %v", got)
	}
}

// RegisterGauges phải đăng ký đủ các gauge, mỗi gauge đọc đúng hàm được truyền vào tại thời điểm scrape.
func TestRegisterGaugesReportsLiveValues(t *testing.T) {
	n := 1.0
	f := func(v float64) func() float64 { return func() float64 { return v } }

	RegisterGauges(func() float64 { return n }, f(2), f(3), f(4), f(5), f(6))

	n = 7 // đổi sau khi đăng ký: gauge phải thấy giá trị mới

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]float64{"vsf_bloom_items": 7, "vsf_bloom_bytes": 2, "vsf_changefeed_lag_seconds": 3, "vsf_db_pool_in_use": 4,
		"vsf_changefeed_tail_changes": 5, "vsf_changefeed_stalled_seconds": 6}
	seen := 0

	for _, mf := range families {
		if v, ok := want[mf.GetName()]; ok {
			seen++

			if got := mf.GetMetric()[0].GetGauge().GetValue(); got != v {
				t.Errorf("%s = %v, want %v", mf.GetName(), got, v)
			}

			if !strings.HasPrefix(mf.GetName(), "vsf_") {
				t.Errorf("unexpected name %s", mf.GetName())
			}
		}
	}

	if seen != len(want) {
		t.Fatalf("registered %d of %d gauges", seen, len(want))
	}
}

// Gọi lại RegisterGauges (server khởi động lần hai trong cùng process) phải thay gauge cũ, không panic.
func TestRegisterGaugesCanBeCalledAgain(t *testing.T) {
	f := func(v float64) func() float64 { return func() float64 { return v } }

	RegisterGauges(f(1), f(1), f(1), f(1), f(1), f(1))
	RegisterGauges(f(9), f(9), f(9), f(9), f(9), f(9))

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}

	for _, mf := range families {
		if mf.GetName() == "vsf_bloom_items" {
			if got := mf.GetMetric()[0].GetGauge().GetValue(); got != 9 {
				t.Fatalf("the latest registration must win, got %v", got)
			}

			return
		}
	}

	t.Fatal("vsf_bloom_items is not registered")
}
