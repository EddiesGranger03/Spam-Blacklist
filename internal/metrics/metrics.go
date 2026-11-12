package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	CheckLayer = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsf_check_layer_total", Help: "Check requests resolved per layer."}, []string{"layer"})

	CheckResult = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsf_check_result_total", Help: "Check results."}, []string{"result"})

	BloomFalsePositive = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsf_bloom_false_positive_total", Help: "Bloom said maybe but DB had no match."})

	BloomFalseNegative = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsf_bloom_false_negative_total", Help: "Bloom missed a hash that exists in DB. MUST stay 0."})

	HTTPDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name: "vsf_http_request_duration_seconds", Help: "HTTP request latency.",
		Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 30}},
		[]string{"method", "route", "status"})

	APIKeyRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsf_apikey_requests_total", Help: "Requests per API key and status."}, []string{"key_id", "status"})

	QuotaBackendErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsf_quota_backend_errors_total", Help: "Redis errors while checking quota (request allowed)."})

	RateLimitBackendErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsf_ratelimit_backend_errors_total", Help: "Redis errors in the rate limiter (request allowed, fail-open)."})

	LoginFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsf_login_failures_total", Help: "Admin login attempts that did not succeed, by reason."}, []string{"reason"})

	LoginAttackSuspected = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsf_login_attack_suspected_total",
		Help: "Times one email crossed the failed-login alert threshold (password guessing, possibly from many IPs)."})

	CacheErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsf_cache_errors_total", Help: "Redis cache errors."})

	BackgroundPanics = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsf_background_panics_total",
		Help: "Panics recovered in a long-running background loop (which is then restarted). Should stay 0."},
		[]string{"loop"})

	ImportPanics = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsf_import_panics_total",
		Help: "Import jobs that panicked and were marked failed. Each one is a bug to investigate; should stay 0."})

	CheckPanics = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsf_check_panics_total",
		Help: "Panics recovered while checking one batch item. Each one is a bug to investigate; should stay 0."})
)

// RegisterGauges đăng ký các gauge Prometheus (Bloom, changefeed, pool DB) với các hàm đo lấy giá trị.
var (
	gaugesMu sync.Mutex
	gauges   = map[string]prometheus.Collector{}
)

// RegisterGauges đăng ký các gauge đọc giá trị sống qua hàm. Gọi lại được: lần gọi sau thay thế lần trước (cần khi một
// process khởi động server nhiều lần, như trong test), thay vì panic vì đăng ký trùng.
func RegisterGauges(bloomItems, bloomBytes, feedLagSeconds, dbInUse, feedTail, feedStalledSeconds func() float64) {
	gaugesMu.Lock()
	defer gaugesMu.Unlock()

	register := func(name, help string, f func() float64) {
		if old, ok := gauges[name]; ok {
			prometheus.Unregister(old)
		}

		g := prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: help}, f)
		prometheus.MustRegister(g)
		gauges[name] = g
	}
	register("vsf_bloom_items", "Items added to the in-memory Bloom filter.", bloomItems)
	register("vsf_bloom_bytes", "Memory used by the Bloom filter.", bloomBytes)
	register("vsf_changefeed_lag_seconds", "Seconds since the last successful change_log poll.", feedLagSeconds)
	register("vsf_db_pool_in_use", "Postgres connections currently in use.", dbInUse)
	register("vsf_changefeed_tail_changes",
		"Committed changes waiting behind an open database transaction (already in the Bloom filter).", feedTail)
	register("vsf_changefeed_stalled_seconds",
		"Seconds the changefeed has continuously had changes waiting behind an open transaction; 0 = none.", feedStalledSeconds)
}
