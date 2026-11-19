package main

// F9: Redis treo (docker pause, mạng đen) từng làm MỌI /v1/check mất đúng 5 s. Nguyên nhân gốc: go-redis v9 mặc định
// ContextTimeoutEnabled=false, nên deadline của ctx (50 ms trong cache/apikey) KHÔNG được áp vào socket; TCP dial vẫn
// thành công tức thì (kernel còn nhận kết nối), và lệnh treo ở bước đọc handshake/reply cho tới timeout nội bộ (~5 s).
//
// Nguyên tắc ở đây: Redis chỉ là lớp tăng tốc/phụ trợ. Client cho đường request (cache, rate limit, publish) có
// timeout ngắn, tôn trọng ctx, và một circuit breaker nhẹ: sau N lỗi mạng liên tiếp thì bỏ qua Redis trong một khoảng
// ngắn (lỗi trả về ngay, caller đã fail-open), rồi cho MỘT lệnh thăm dò đi qua để thử lại. Pub/Sub dùng client riêng
// (timeout dài hơn, không breaker) để kết nối subscribe không chiếm pool và không bị breaker cắt.

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/redis/go-redis/v9"
)

// Mặc định cho client đường request; đổi được qua env (đọc ở đây để không đụng internal/config).
const (
	defRedisOpTimeout      = 100 * time.Millisecond // REDIS_OP_TIMEOUT: Dial/Read/Write/Pool timeout
	defRedisBreakerFails   = 3                      // REDIS_BREAKER_FAILURES: số lỗi liên tiếp để mở breaker
	defRedisBreakerCooloff = 2 * time.Second        // REDIS_BREAKER_COOLOFF: thời gian bỏ qua Redis khi breaker mở
)

// ErrRedisBreakerOpen được trả ngay (không chạm mạng) khi breaker đang mở.
var ErrRedisBreakerOpen = errors.New("redis: circuit breaker open")

var (
	redisBreakerOpen = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vsf_redis_breaker_open", Help: "1 while the Redis circuit breaker is open (Redis bypassed), else 0."})
	redisBreakerShortCircuits = promauto.NewCounter(prometheus.CounterOpts{
		Name: "vsf_redis_breaker_short_circuits_total", Help: "Redis commands skipped because the circuit breaker was open."})
)

// redisTuning là cấu hình client Redis đường request.
type redisTuning struct {
	OpTimeout      time.Duration
	BreakerFails   int
	BreakerCooloff time.Duration
}

// redisTuningFromEnv đọc REDIS_OP_TIMEOUT, REDIS_BREAKER_FAILURES, REDIS_BREAKER_COOLOFF (giá trị sai -> mặc định).
func redisTuningFromEnv() redisTuning {
	t := redisTuning{OpTimeout: defRedisOpTimeout, BreakerFails: defRedisBreakerFails, BreakerCooloff: defRedisBreakerCooloff}
	if d, err := time.ParseDuration(os.Getenv("REDIS_OP_TIMEOUT")); err == nil && d > 0 {
		t.OpTimeout = d
	}

	if n, err := strconv.Atoi(os.Getenv("REDIS_BREAKER_FAILURES")); err == nil && n > 0 {
		t.BreakerFails = n
	}

	if d, err := time.ParseDuration(os.Getenv("REDIS_BREAKER_COOLOFF")); err == nil && d > 0 {
		t.BreakerCooloff = d
	}

	return t
}

// newRequestRedis tạo client cho đường request: mọi thao tác bị chặn bởi min(ctx, OpTimeout), có circuit breaker.
func newRequestRedis(addr, password string, t redisTuning) *redis.Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:                  addr,
		Password:              password,
		ContextTimeoutEnabled: true, // gốc của F9: thiếu cờ này thì deadline ctx bị bỏ qua
		DialTimeout:           t.OpTimeout,
		ReadTimeout:           t.OpTimeout,
		WriteTimeout:          t.OpTimeout,
		PoolTimeout:           t.OpTimeout,
		MaxRetries:            -1, // không retry: retry nhân đôi thời gian chờ khi Redis treo; caller đã fail-open
	})
	rdb.AddHook(newRedisBreaker(t.BreakerFails, t.BreakerCooloff))

	return rdb
}

// newPubSubRedis tạo client riêng cho Subscribe: kết nối dài hạn, không breaker; ReceiveTimeout/Ping trong
// changefeed tự phát hiện mất kết nối. PoolSize nhỏ vì chỉ có một subscription.
func newPubSubRedis(addr, password string) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:                  addr,
		Password:              password,
		ContextTimeoutEnabled: true,
		DialTimeout:           2 * time.Second,
		PoolSize:              2,
	})
}

// probeCtxKey đánh dấu ctx của lệnh thăm dò: go-redis chạy handshake (HELLO/AUTH) của kết nối mới qua CÙNG các hook,
// nên lệnh lồng bên trong lệnh thăm dò phải được đi qua, nếu không breaker tự chặn chính nó và không bao giờ đóng lại.
type probeCtxKey struct{}

// redisBreaker là circuit breaker 3 trạng thái (closed -> open -> half-open) cài như hook của go-redis.
type redisBreaker struct {
	threshold int
	cooloff   time.Duration
	now       func() time.Time

	mu        sync.Mutex
	fails     int
	openUntil time.Time
	probing   bool // half-open: đã có một lệnh thăm dò đang chạy
}

func newRedisBreaker(threshold int, cooloff time.Duration) *redisBreaker {
	return &redisBreaker{threshold: threshold, cooloff: cooloff, now: time.Now}
}

// allow trả (được chạy, là lệnh thăm dò).
func (b *redisBreaker) allow() (bool, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.fails < b.threshold {
		return true, false
	}

	if b.now().Before(b.openUntil) || b.probing {
		return false, false
	}

	b.probing = true

	return true, true
}

// done ghi nhận kết quả. Chỉ lỗi hạ tầng (mạng, timeout, pool) mới tính; redis.Nil và lỗi reply của server thì không.
func (b *redisBreaker) done(err error, probe bool) {
	failed := isRedisInfraErr(err)

	b.mu.Lock()
	defer b.mu.Unlock()

	if probe {
		b.probing = false
	}

	if !failed {
		if b.fails >= b.threshold {
			redisBreakerOpen.Set(0)
		}

		b.fails = 0

		return
	}

	b.fails++
	if b.fails >= b.threshold {
		b.openUntil = b.now().Add(b.cooloff)
		redisBreakerOpen.Set(1)
	}
}

func isRedisInfraErr(err error) bool {
	if err == nil || errors.Is(err, redis.Nil) {
		return false
	}

	// Caller tự hủy ctx (client ngắt) không phải lỗi của Redis.
	if errors.Is(err, context.Canceled) {
		return false
	}

	var re redis.Error
	if errors.As(err, &re) && !errors.Is(err, redis.ErrPoolTimeout) {
		return false // reply lỗi từ server (WRONGTYPE, NOSCRIPT...): Redis vẫn sống
	}

	return true
}

func (b *redisBreaker) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) { return next(ctx, network, addr) }
}

func (b *redisBreaker) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if ctx.Value(probeCtxKey{}) != nil {
			return next(ctx, cmd)
		}

		ok, probe := b.allow()
		if !ok {
			redisBreakerShortCircuits.Inc()
			cmd.SetErr(ErrRedisBreakerOpen)

			return ErrRedisBreakerOpen
		}

		if probe {
			ctx = context.WithValue(ctx, probeCtxKey{}, true)
		}

		err := next(ctx, cmd)
		b.done(err, probe)

		return err
	}
}

func (b *redisBreaker) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		if ctx.Value(probeCtxKey{}) != nil {
			return next(ctx, cmds)
		}

		ok, probe := b.allow()
		if !ok {
			redisBreakerShortCircuits.Inc()
			for _, c := range cmds {
				c.SetErr(ErrRedisBreakerOpen)
			}

			return ErrRedisBreakerOpen
		}

		if probe {
			ctx = context.WithValue(ctx, probeCtxKey{}, true)
		}

		err := next(ctx, cmds)
		b.done(err, probe)

		return err
	}
}
