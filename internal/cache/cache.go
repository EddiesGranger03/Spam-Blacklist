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

func (Noop) Get(context.Context, string) ([]byte, bool) { return nil, false }
func (Noop) Set(context.Context, string, []byte)        {}

const opTimeout = 50 * time.Millisecond

type Redis struct {
	rdb *redis.Client
	ttl time.Duration
}

func NewRedis(rdb *redis.Client, ttl time.Duration) *Redis { return &Redis{rdb: rdb, ttl: ttl} }

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

func (r *Redis) Set(ctx context.Context, key string, val []byte) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	if err := r.rdb.Set(ctx, key, val, r.ttl).Err(); err != nil {
		metrics.CacheErrors.Inc()
	}
}
