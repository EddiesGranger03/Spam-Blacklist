package apikey

import (
	"context"
	"errors"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"vsf/internal/model"
)

// testRedis trả client tới Redis thật (TEST_REDIS_ADDR, TEST_REDIS_PASSWORD); bỏ qua nếu chưa cấu hình.
// Mỗi test dùng ID key ngẫu nhiên nên không cần dọn dẹp và không đụng dữ liệu thật (khóa rl:* tự hết hạn).
func testRedis(t *testing.T) *redis.Client {
	t.Helper()

	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR is not set; skipping Redis integration test")
	}

	rdb := redis.NewClient(&redis.Options{Addr: addr, Password: os.Getenv("TEST_REDIS_PASSWORD")})
	t.Cleanup(func() { _ = rdb.Close() })

	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("redis: %v", err)
	}

	return rdb
}

// randKey tạo API key ngẫu nhiên với RPS cho trước, dùng trong test Redis.
func randKey(rps int) *model.APIKey {
	return &model.APIKey{ID: 1_000_000_000 + rand.Int63n(1_000_000_000), RPSLimit: rps}
}

// burstKey tạo key có bucket chứa đúng burst token nhưng nạp lại chỉ 1 token/giây (rps_limit=1, max_batch=burst), để thời
// gian trôi qua trên máy chậm gần như không làm đầy lại bucket. Các assert vẫn tính thêm số token đã nạp theo thời gian thật.
func burstKey(burst int) *model.APIKey {
	return &model.APIKey{ID: 1_000_000_000 + rand.Int63n(1_000_000_000), RPSLimit: 1, MaxBatch: burst}
}

// TestRedisRateLimitBlocksAfterBurst kiểm tra giới hạn Redis chặn sau khi hết burst.
func TestRedisRateLimitBlocksAfterBurst(t *testing.T) {
	s := NewService(&fakeStore{keys: map[string]model.APIKey{}}, testRedis(t), 100)
	k, ctx := burstKey(5), context.Background()
	start := time.Now()

	for i := 0; i < 5; i++ {
		if err := s.Allow(ctx, k, 1); err != nil {
			t.Fatalf("request %d within burst: %v", i+1, err)
		}
	}

	if time.Since(start) > 900*time.Millisecond {
		t.Skip("máy quá chậm: bucket đã nạp lại ít nhất một token trong lúc xả, không đo được")
	}

	if err := s.Allow(ctx, k, 1); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("6th request: want ErrRateLimited, got %v", err)
	}

	if err := s.Allow(ctx, burstKey(5), 1); err != nil {
		t.Fatalf("another key is independent: %v", err)
	}
}

// Đây là điều hybrid (bộ đếm trong bộ nhớ từng instance) không làm được: hai instance dùng chung MỘT giới hạn.
func TestRedisRateLimitIsSharedBetweenInstances(t *testing.T) {
	rdb := testRedis(t)
	a := NewService(&fakeStore{keys: map[string]model.APIKey{}}, rdb, 100)
	b := NewService(&fakeStore{keys: map[string]model.APIKey{}}, rdb, 100)
	k, ctx := burstKey(10), context.Background()

	allowed := 0
	start := time.Now()

	for i := 0; i < 30; i++ {
		svc := a
		if i%2 == 1 {
			svc = b
		}

		if svc.Allow(ctx, k, 1) == nil {
			allowed++
		}
	}

	// burst 10 + token nạp lại trong thời gian đã trôi qua (1/giây). Hai bộ đếm riêng trong bộ nhớ sẽ cho khoảng 20.
	max := 10 + int(time.Since(start).Seconds()) + 1
	if allowed < 10 || allowed > max {
		t.Fatalf("2 instances, burst 10: %d requests allowed, want between 10 and %d (in-memory limiters would allow ~20)", allowed, max)
	}
}

// TestRedisRateLimitRefillsOverTime kiểm tra giới hạn Redis nạp lại token theo thời gian.
func TestRedisRateLimitRefillsOverTime(t *testing.T) {
	s := NewService(&fakeStore{keys: map[string]model.APIKey{}}, testRedis(t), 100)
	k, ctx := randKey(5), context.Background() // tốc độ nạp thấp để máy chậm không làm bucket đầy lại trong lúc xả

	for i := 0; i < 5; i++ {
		_ = s.Allow(ctx, k, 1)
	}

	if err := s.Allow(ctx, k, 1); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("bucket should be empty, got %v", err)
	}

	time.Sleep(600 * time.Millisecond) // 5 token/s * 0.6s = 3 token

	ok := 0
	for i := 0; i < 10; i++ {
		if s.Allow(ctx, k, 1) == nil {
			ok++
		}
	}

	if ok < 2 || ok > 5 {
		t.Fatalf("after 0.6s at 5 rps expected about 3 tokens back, got %d", ok)
	}
}

func TestRedisRateLimitBatchCostsProportionally(t *testing.T) {
	s := NewService(&fakeStore{keys: map[string]model.APIKey{}}, testRedis(t), 100)
	k, ctx := randKey(100), context.Background()

	if err := s.Allow(ctx, k, 60); err != nil {
		t.Fatal(err)
	}

	if err := s.Allow(ctx, k, 60); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("second batch of 60 exceeds the 100 burst: got %v", err)
	}

	if err := s.Allow(ctx, k, 40); err != nil {
		t.Fatalf("a rejected batch must not consume tokens, 40 should still fit: %v", err)
	}

	// max_batch cho phép MỘT batch lớn hơn rps_limit
	big := &model.APIKey{ID: k.ID + 1, RPSLimit: 10, MaxBatch: 50}
	if err := s.Allow(ctx, big, 50); err != nil {
		t.Fatalf("batch within max_batch: %v", err)
	}

	if err := s.Allow(ctx, &model.APIKey{ID: k.ID + 2, RPSLimit: 10}, 50); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("batch above burst without max_batch: got %v", err)
	}
}

// Redis không tới được: cho qua (fail-open) thay vì làm API ngừng phục vụ.
func TestRedisRateLimitFailsOpenWhenRedisIsDown(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 50 * time.Millisecond, MaxRetries: -1})
	defer rdb.Close()

	s := NewService(&fakeStore{keys: map[string]model.APIKey{}}, rdb, 100)

	for i := 0; i < 5; i++ {
		if err := s.Allow(context.Background(), randKey(1), 1); err != nil {
			t.Fatalf("redis down must fail open, got %v", err)
		}
	}
}

// TestRedisIPLookupLimitIsShared kiểm tra giới hạn tra cứu theo IP được dùng chung giữa các instance.
func TestRedisIPLookupLimitIsShared(t *testing.T) {
	rdb := testRedis(t)
	a := NewService(&fakeStore{keys: map[string]model.APIKey{}}, rdb, 100)
	b := NewService(&fakeStore{keys: map[string]model.APIKey{}}, rdb, 100)
	ip := "203.0.113." + string(rune('0'+rand.Intn(9))) + "/" + time.Now().Format("150405.000000")
	ctx := context.Background()

	allowed := 0
	start := time.Now()

	for i := 0; i < 60; i++ {
		svc := a
		if i%2 == 1 {
			svc = b
		}

		if svc.allowLookup(ctx, ip) {
			allowed++
		}
	}

	// Giới hạn dùng chung: burst + tốc độ nạp * thời gian đã trôi qua (máy chậm thì nạp thêm được nhiều hơn).
	max := ipLookupBurst + int(ipLookupRPS*time.Since(start).Seconds()) + 2
	if allowed < ipLookupBurst || allowed > max {
		t.Fatalf("cache-miss lookups from one IP across 2 instances: %d allowed, want between %d and %d", allowed, ipLookupBurst, max)
	}
}
