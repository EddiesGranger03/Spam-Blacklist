package metrics

import (
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

	CacheErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsf_cache_errors_total", Help: "Redis cache errors."})
)

func RegisterGauges(bloomItems, bloomBytes, feedLagSeconds, dbInUse func() float64) {
	register := func(name, help string, f func() float64) {
		promauto.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: help}, f)
	}
	register("vsf_bloom_items", "Items added to the in-memory Bloom filter.", bloomItems)
	register("vsf_bloom_bytes", "Memory used by the Bloom filter.", bloomBytes)
	register("vsf_changefeed_lag_seconds", "Seconds since the last successful change_log poll.", feedLagSeconds)
	register("vsf_db_pool_in_use", "Postgres connections currently in use.", dbInUse)
}
