package cache

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"

	"vsf/internal/metrics"
)

type Cache interface {
	Get(ctx context.Context, key string) ([]byte, bool)
	Set(ctx context.Context, key string, val []byte)
}

type Noop struct{}

// Get của Noop luôn báo không có, dùng khi không bật Redis.
func (Noop) Get(context.Context, string) ([]byte, bool) { return nil, false }
// Set của Noop không làm gì, dùng khi không bật Redis.
func (Noop) Set(context.Context, string, []byte)        {}

const opTimeout = 50 * time.Millisecond

type Redis struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewRedis tạo cache Redis với TTL cho trước.
func NewRedis(rdb *redis.Client, ttl time.Duration) *Redis { return &Redis{rdb: rdb, ttl: ttl} }

// Get của Redis đọc giá trị theo khóa; trả false nếu không có hoặc lỗi (lỗi được đếm trong metric).
func (r *Redis) Get(ctx context.Context, key string) ([]byte, bool) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	b, err := r.rdb.Get(ctx, key).Bytes()
	if err != nil {
		if err != redis.Nil {
			metrics.CacheErrors.Inc()
		}

		return nil, false
	}

	return b, true
}

// Set của Redis ghi giá trị vào Redis với TTL đã cấu hình; lỗi chỉ được đếm, không làm hỏng request.
func (r *Redis) Set(ctx context.Context, key string, val []byte) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	if err := r.rdb.Set(ctx, key, val, r.ttl).Err(); err != nil {
		metrics.CacheErrors.Inc()
	}
}
