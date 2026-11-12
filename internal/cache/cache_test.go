package cache

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestNoopNeverStoresAnything(t *testing.T) {
	var c Cache = Noop{}

	c.Set(context.Background(), "k", []byte("v"))

	if v, ok := c.Get(context.Background(), "k"); ok || v != nil {
		t.Fatalf("Noop must always miss, got %q %v", v, ok)
	}
}

func redisClient(t *testing.T) *redis.Client {
	t.Helper()

	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR is not set; skipping Redis integration test")
	}

	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("TEST_REDIS_PASSWORD")})
	t.Cleanup(func() { _ = rdb.Close() })

	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Fatal(err)
	}

	return rdb
}

func TestRedisGetSetAndExpiry(t *testing.T) {
	c := NewRedis(redisClient(t), 300*time.Millisecond)
	ctx := context.Background()
	key := "cachetest:" + time.Now().Format("150405.000000000")

	if _, ok := c.Get(ctx, key); ok {
		t.Fatal("a missing key must miss")
	}

	c.Set(ctx, key, []byte("hello"))

	if v, ok := c.Get(ctx, key); !ok || string(v) != "hello" {
		t.Fatalf("got %q %v", v, ok)
	}

	time.Sleep(450 * time.Millisecond)

	if _, ok := c.Get(ctx, key); ok {
		t.Fatal("the key must expire after the TTL")
	}
}

// Redis không tới được: Get báo miss và Set không panic; request không bị hỏng.
func TestRedisErrorsAreSwallowed(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 30 * time.Millisecond, MaxRetries: -1})
	defer rdb.Close()

	c := NewRedis(rdb, time.Minute)

	c.Set(context.Background(), "k", []byte("v"))

	if v, ok := c.Get(context.Background(), "k"); ok || v != nil {
		t.Fatalf("an unreachable Redis must read as a miss, got %q %v", v, ok)
	}
}
