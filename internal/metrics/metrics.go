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

	// Redis Pub/Sub đồng bộ filter giữa các pod (package changefeed).
	SyncPublished = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsf_sync_published_total", Help: "Change notifications published to Redis, by result (ok, error)."},
		[]string{"result"})

	SyncReceived = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsf_sync_messages_total", Help: "Change notifications received from Redis, by kind (hashes, signal, invalid)."},
		[]string{"kind"})

	SyncApplyLatency = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "vsf_sync_publish_to_apply_seconds",
		Help:    "Time from publish on one pod to catch-up from change_log finished on this pod (includes clock skew).",
		Buckets: []float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5}})

	SyncFallback = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsf_sync_fallback_total",
		Help: "Times the changefeed fell back to fast polling because Redis Pub/Sub was unavailable."})

	SyncReplicaBehind = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsf_sync_replica_behind_total",
		Help: "Catch-ups that could not yet see a seq_max announced over Pub/Sub (read replica lagging); retried with backoff."})

	SyncCatchUp = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsf_sync_catchup_total", Help: "Outcome of waiting for a lagging read source (caught_up, timeout)."},
		[]string{"result"})

	SyncCatchUpWait = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "vsf_sync_catchup_wait_seconds",
		Help:    "Time spent retrying catch-up until the read source reached the announced seq_max (or gave up).",
		Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}})

	CheckNegativeNotCached = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsf_check_negative_uncached_total",
		Help: "Check lookups whose 'no match' result was not cached because the changefeed knew of unapplied changes."})

	SyncSubscribed = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vsf_sync_subscribed", Help: "1 while subscribed to Redis change notifications, 0 while polling fast (fallback)."})

	// Bộ kiểm tra âm tính giả của filter (package verify).
	FilterVerifyChecked = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsf_filter_verify_checked_total",
		Help: "Sampled active BLACKLIST hashes tested against this pod's filter."})

	FilterVerifyFalseNegative = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsf_filter_verify_false_negative_total",
		Help: "Confirmed false negatives: an active BLACKLIST hash missing from the filter after a full catch-up. Must stay 0."})

	FilterVerifyDiscarded = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsf_filter_verify_suspect_discarded_total",
		Help: "Suspects dropped as races, by reason (synced = present after catch-up, gone = no longer active, changed = row written during the check)."},
		[]string{"reason"})

	FilterVerifyErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsf_filter_verify_errors_total", Help: "Verification rounds that failed (database or sync error)."})

	FilterVerifyDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "vsf_filter_verify_duration_seconds",
		Help:    "Duration of one verification round (sample query + filter tests + race re-checks).",
		Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10}})
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

// FuncMetric is a metric whose value is read from a function at scrape time. Counter selects CounterFunc (monotonic
// totals) instead of GaugeFunc.
type FuncMetric struct {
	Name    string
	Help    string
	Counter bool
	F       func() float64
}

// RegisterFuncs registers function-backed metrics. Like RegisterGauges it can be called again (a later call replaces
// the earlier registration of the same name).
func RegisterFuncs(items []FuncMetric) {
	gaugesMu.Lock()
	defer gaugesMu.Unlock()

	for _, it := range items {
		if old, ok := gauges[it.Name]; ok {
			prometheus.Unregister(old)
		}

		var c prometheus.Collector
		if it.Counter {
			c = prometheus.NewCounterFunc(prometheus.CounterOpts{Name: it.Name, Help: it.Help}, it.F)
		} else {
			c = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: it.Name, Help: it.Help}, it.F)
		}

		prometheus.MustRegister(c)
		gauges[it.Name] = c
	}
}
