package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"vsf/internal/apikey"
	"vsf/internal/cache"
	"vsf/internal/model"
)

// hangProxy là proxy TCP mô phỏng `docker pause` Redis: khi hang=true, kết nối vẫn được nhận (kernel còn sống) và
// byte gửi tới bị nuốt, nhưng không có phản hồi nào. target rỗng = luôn treo (không cần Redis thật).
type hangProxy struct {
	ln     net.Listener
	target string
	hang   atomic.Bool
	mu     sync.Mutex
	conns  []net.Conn
}

func startHangProxy(t *testing.T, target string) *hangProxy {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	p := &hangProxy{ln: ln, target: target}
	p.hang.Store(target == "")

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}

			p.mu.Lock()
			p.conns = append(p.conns, c)
			p.mu.Unlock()

			go p.serve(c)
		}
	}()

	t.Cleanup(func() {
		_ = ln.Close()
		p.mu.Lock()
		for _, c := range p.conns {
			_ = c.Close()
		}
		p.mu.Unlock()
	})

	return p
}

func (p *hangProxy) Addr() string { return p.ln.Addr().String() }

func (p *hangProxy) serve(c net.Conn) {
	if p.target == "" {
		_, _ = io.Copy(io.Discard, c)
		return
	}

	up, err := net.Dial("tcp", p.target)
	if err != nil {
		_ = c.Close()
		return
	}

	p.mu.Lock()
	p.conns = append(p.conns, up)
	p.mu.Unlock()

	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if err != nil {
				_ = dst.Close()
				return
			}

			for p.hang.Load() { // "pause": giữ dữ liệu lại, không chuyển tiếp
				time.Sleep(5 * time.Millisecond)
			}

			if _, err := dst.Write(buf[:n]); err != nil {
				return
			}
		}
	}

	go pipe(up, c)
	pipe(c, up)
}

// checkPathRedisOps làm đúng các thao tác Redis mà một /v1/check có API key gặp: rate limit (Lua), quota (INCRBY),
// cache Get, rồi cache Set khi miss.
func checkPathRedisOps(ctx context.Context, rc cache.Cache, keys *apikey.Service, k *model.APIKey) error {
	if err := keys.Allow(ctx, k, 1); err != nil {
		return err
	}

	if _, ok := rc.Get(ctx, "chk:test"); !ok {
		rc.Set(ctx, "chk:test", []byte("v"))
	}

	return nil
}

// measure chạy n request song song (conc goroutine) và trả các độ trễ đã sắp xếp.
func measure(t *testing.T, n, conc int, rdb *redis.Client) []time.Duration {
	t.Helper()

	rc := cache.NewRedis(rdb, time.Minute)
	keys := apikey.NewService(nil, rdb, 1000)
	k := &model.APIKey{ID: 1, RPSLimit: 1000, DailyQuota: 1 << 40}

	lat := make([]time.Duration, n)

	var next atomic.Int64

	var wg sync.WaitGroup

	for range conc {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for {
				i := int(next.Add(1)) - 1
				if i >= n {
					return
				}

				s := time.Now()
				if err := checkPathRedisOps(context.Background(), rc, keys, k); err != nil {
					t.Errorf("request %d: Redis down must fail open, got %v", i, err)
				}

				lat[i] = time.Since(s)
			}
		}()
	}

	wg.Wait()
	sort.Slice(lat, func(a, b int) bool { return lat[a] < lat[b] })

	return lat
}

func pct(lat []time.Duration, p float64) time.Duration { return lat[int(float64(len(lat)-1)*p)] }

// TestF9LegacyClientHangsOnPausedRedis tái hiện F9 với client cũ (option mặc định): mỗi request treo ~5 s dù code
// đặt timeout 50 ms. Chỉ chạy khi VSF_F9_LEGACY=1 vì tốn ~5 s; giữ lại làm bằng chứng "trước khi sửa".
func TestF9LegacyClientHangsOnPausedRedis(t *testing.T) {
	if os.Getenv("VSF_F9_LEGACY") != "1" {
		t.Skip("set VSF_F9_LEGACY=1 to reproduce the pre-fix 5 s hang")
	}

	p := startHangProxy(t, "")
	rdb := redis.NewClient(&redis.Options{Addr: p.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	lat := measure(t, 8, 8, rdb)
	t.Logf("legacy client, Redis hung: p50=%v p99=%v", pct(lat, .5), pct(lat, .99))

	if pct(lat, .5) < time.Second {
		t.Fatalf("expected legacy client to hang >= 1s, p50=%v", pct(lat, .5))
	}
}

// TestF9RequestRedisBoundedWhenHung: Redis treo hoàn toàn -> mọi request vẫn xong, fail-open, p99 <= 150 ms; breaker
// mở nên phần lớn request không chạm mạng.
func TestF9RequestRedisBoundedWhenHung(t *testing.T) {
	p := startHangProxy(t, "")
	rdb := newRequestRedis(p.Addr(), "", redisTuning{OpTimeout: 100 * time.Millisecond, BreakerFails: 3, BreakerCooloff: 2 * time.Second})
	t.Cleanup(func() { _ = rdb.Close() })

	lat := measure(t, 2000, 32, rdb)
	t.Logf("fixed client, Redis hung: p50=%v p99=%v max=%v", pct(lat, .5), pct(lat, .99), lat[len(lat)-1])

	if got := pct(lat, .99); got > 150*time.Millisecond {
		t.Fatalf("p99 with hung Redis = %v, want <= 150ms", got)
	}

	if got := lat[len(lat)-1]; got > 500*time.Millisecond {
		t.Fatalf("max with hung Redis = %v, want <= 500ms", got)
	}
}

// TestF9BreakerRecoversAfterPause dùng Redis thật (TEST_REDIS_ADDR): chạy bình thường -> "pause" -> nhanh, fail-open
// -> "unpause" -> sau cooloff Redis được dùng lại (cache Set/Get đúng giá trị).
func TestF9BreakerRecoversAfterPause(t *testing.T) {
	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR is not set; skipping Redis integration test")
	}

	p := startHangProxy(t, addr)
	cool := 300 * time.Millisecond
	rdb := newRequestRedis(p.Addr(), os.Getenv("TEST_REDIS_PASSWORD"), redisTuning{OpTimeout: 100 * time.Millisecond, BreakerFails: 3, BreakerCooloff: cool})
	t.Cleanup(func() { _ = rdb.Close() })

	ctx := context.Background()
	rc := cache.NewRedis(rdb, time.Minute)
	key := "f9:test:" + time.Now().Format("150405.000000000")

	rc.Set(ctx, key, []byte("before"))
	if v, ok := rc.Get(ctx, key); !ok || string(v) != "before" {
		t.Fatalf("healthy Redis: got %q %v", v, ok)
	}

	p.hang.Store(true)

	lat := measure(t, 500, 16, rdb)
	t.Logf("real Redis paused: p50=%v p99=%v", pct(lat, .5), pct(lat, .99))

	if got := pct(lat, .99); got > 150*time.Millisecond {
		t.Fatalf("p99 while paused = %v, want <= 150ms", got)
	}

	if err := rdb.Ping(ctx).Err(); !errors.Is(err, ErrRedisBreakerOpen) && err == nil {
		t.Fatalf("expected an error while paused, got nil")
	}

	p.hang.Store(false)

	deadline := time.Now().Add(5 * time.Second)
	for {
		rc.Set(ctx, key, []byte("after"))
		if v, ok := rc.Get(ctx, key); ok && string(v) == "after" {
			break
		}

		if time.Now().After(deadline) {
			t.Fatal("Redis not used again within 5s after unpause")
		}

		time.Sleep(cool / 3)
	}

	_ = rdb.Del(ctx, key).Err()
}

func TestRedisBreakerStates(t *testing.T) {
	now := time.Unix(0, 0)
	b := newRedisBreaker(2, time.Second)
	b.now = func() time.Time { return now }
	netErr := &net.OpError{Op: "read", Err: errors.New("i/o timeout")}

	for range 2 {
		ok, probe := b.allow()
		if !ok || probe {
			t.Fatal("closed breaker must allow without probe")
		}

		b.done(netErr, false)
	}

	if ok, _ := b.allow(); ok {
		t.Fatal("breaker must be open after threshold failures")
	}

	now = now.Add(time.Second)

	ok, probe := b.allow()
	if !ok || !probe {
		t.Fatal("after cooloff exactly one probe must pass")
	}

	if ok, _ := b.allow(); ok {
		t.Fatal("second caller must wait while probe in flight")
	}

	b.done(nil, true)

	if ok, probe := b.allow(); !ok || probe {
		t.Fatal("successful probe must close the breaker")
	}

	// redis.Nil và lỗi reply của server không làm mở breaker.
	for range 5 {
		b.done(redis.Nil, false)
	}

	if ok, _ := b.allow(); !ok {
		t.Fatal("redis.Nil must not count as failure")
	}
}
