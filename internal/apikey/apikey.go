package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"

	"vsf/internal/metrics"
	"vsf/internal/model"
	"vsf/internal/store"
)

var (
	ErrMissing             = errors.New("missing api key")
	ErrInvalid             = errors.New("invalid api key")
	ErrRevoked             = errors.New("api key revoked")
	ErrExpired             = errors.New("api key expired")
	ErrRateLimited         = errors.New("rate limit exceeded")
	ErrQuotaExceeded       = errors.New("daily quota exceeded")
	ErrTooManyAuthAttempts = errors.New("too many authentication attempts, try again shortly")
)

const (
	alphabet    = "abcdefghijklmnopqrstuvwxyz0123456789"
	prefixLen   = 8
	secretLen   = 32
	cacheTTL    = 30 * time.Second
	negativeTTL = 10 * time.Second

	// ipLookupRPS/ipLookupBurst giới hạn, theo IP client, tần suất một prefix chưa được nhận ra (trượt cache)
	// có thể kích hoạt một lần tra cứu Postgres thật. Caller dùng lại một key thật gần như không bao giờ chạm giới hạn này:
	// lần tra cứu đầu làm đầy cache và mọi lần lặp lại trong cacheTTL/negativeTTL được phục vụ từ bộ nhớ.
	// Chỉ caller liên tục gửi prefix MỚI (ví dụ ngẫu nhiên hóa header X-API-Key để vượt cache âm) mới làm cạn giới hạn này
	// và nhận 429 trước khi có truy vấn DB nào. Xem docs/ATTACK_PUBLIC_API.md, phát hiện A1.
	ipLookupRPS   = 10
	ipLookupBurst = 20
	// ipLookupLimiters giới hạn số lượng để một bên tấn công đổi cả IP không làm phình bộ nhớ vô hạn.
	maxIPLookupLimiters = 50_000
)

// randString tạo chuỗi ngẫu nhiên n ký tự dùng cho phần bí mật của API key.
func randString(n int) (string, error) {
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)

	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}

		for _, b := range buf {
			if b < 252 && len(out) < n {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
	}

	return string(out), nil
}

// Generate tạo API key mới: trả về key đầy đủ (chỉ hiện một lần), tiền tố hiển thị và hash của phần bí mật.
func Generate() (full, prefix string, hash []byte, err error) {
	prefix, err = randString(prefixLen)
	if err != nil {
		return
	}

	secret, err := randString(secretLen)
	if err != nil {
		return
	}

	return "vsf_" + prefix + "_" + secret, prefix, HashSecret(secret), nil
}

// HashSecret băm phần bí mật của API key bằng SHA-256 để lưu.
func HashSecret(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

// Parse tách API key đầy đủ thành tiền tố và phần bí mật; ok là false nếu sai định dạng.
func Parse(full string) (prefix, secret string, ok bool) {
	parts := strings.Split(full, "_")
	if len(parts) != 3 || parts[0] != "vsf" || len(parts[1]) != prefixLen || len(parts[2]) != secretLen {
		return "", "", false
	}

	return parts[1], parts[2], true
}

type Store interface {
	GetAPIKeyByPrefix(ctx context.Context, prefix string) (model.APIKey, error)
	TouchAPIKeys(ctx context.Context, ids []int64) error
}

type cacheEntry struct {
	key    *model.APIKey
	loaded time.Time
	// ttl có jitter 80–100% TTL danh nghĩa để các key nạp cùng lúc không hết hạn cùng một thời điểm.
	ttl time.Duration
}

type limiterEntry struct {
	l     *rate.Limiter
	rps   int
	burst int
}

type Service struct {
	store      Store
	rdb        *redis.Client
	defaultRPS int
	now        func() time.Time

	mu         sync.Mutex
	cache      map[string]cacheEntry
	limiters   map[int64]limiterEntry
	used       map[int64]struct{}
	ipLimiters map[string]*rate.Limiter

	// flights gộp các lần tra DB đồng thời của cùng một prefix thành một (F8).
	flights singleflight.Group
}

// NewService tạo dịch vụ API key với store, Redis (có thể nil) và RPS mặc định.
func NewService(st Store, rdb *redis.Client, defaultRPS int) *Service {
	return &Service{store: st, rdb: rdb, defaultRPS: defaultRPS, now: time.Now,
		cache: map[string]cacheEntry{}, limiters: map[int64]limiterEntry{}, used: map[int64]struct{}{},
		ipLimiters: map[string]*rate.Limiter{}}
}

// Authenticate xác thực API key. ip là địa chỉ của caller (chỉ dùng để giới hạn tốc độ tra DB
// cho các prefix chưa có trong cache, xem allowLookup); nó không ảnh hưởng tới kết quả xác thực.
func (s *Service) Authenticate(ctx context.Context, full, ip string) (*model.APIKey, error) {
	if full == "" {
		return nil, ErrMissing
	}

	prefix, secret, ok := Parse(full)
	if !ok {
		return nil, ErrInvalid
	}

	k, err := s.lookup(ctx, prefix, ip)
	if err != nil {
		return nil, err
	}

	if k == nil || subtle.ConstantTimeCompare(k.KeyHash, HashSecret(secret)) != 1 {
		return nil, ErrInvalid
	}

	if k.Status != "active" {
		return nil, ErrRevoked
	}

	if k.ExpiresAt != nil && !s.now().Before(*k.ExpiresAt) {
		return nil, ErrExpired
	}

	s.mu.Lock()
	s.used[k.ID] = struct{}{}
	s.mu.Unlock()
	return k, nil
}

// lookup tìm API key theo tiền tố: đọc cache trước, nếu trượt thì tra DB (có giới hạn theo IP).
func (s *Service) lookup(ctx context.Context, prefix, ip string) (*model.APIKey, error) {
	s.mu.Lock()

	if e, ok := s.cache[prefix]; ok {
		if s.now().Sub(e.loaded) < e.ttl {
			s.mu.Unlock()
			return e.key, nil
		}
	}

	s.mu.Unlock()

	// Chỉ tới đây mới thật sự cần tra Postgres (cache-miss). Các request đồng thời cùng prefix được gộp thành một
	// lần tra (single-flight, F8): chỉ người dẫn đầu bị tính vào giới hạn IP, nên một key thật khi cache hết hạn
	// không còn bị 429 oan. Kết quả chia sẻ chỉ là bản ghi key theo prefix; so khớp hash đầy đủ vẫn làm riêng
	// cho từng request ở Authenticate, nên key sai không thể ăn theo key đúng. Prefix khác nhau là flight khác nhau,
	// mỗi flight vẫn bị tính giới hạn IP như cũ.
	v, err, shared := s.flights.Do(prefix, func() (any, error) {
		if !s.allowLookup(ctx, ip) {
			return nil, ErrTooManyAuthAttempts
		}

		return s.load(ctx, prefix)
	})
	if err != nil && shared && errors.Is(err, ErrTooManyAuthAttempts) {
		// Người dẫn đầu (có thể là IP khác) bị giới hạn: không để người đi theo chịu thay, tự kiểm tra theo IP của mình.
		if !s.allowLookup(ctx, ip) {
			return nil, ErrTooManyAuthAttempts
		}

		return s.load(ctx, prefix)
	}

	if err != nil {
		return nil, err
	}

	return v.(*model.APIKey), nil
}

// load tra Postgres theo prefix và ghi cache (kể cả cache âm). Tách khỏi ctx của người gọi để người dẫn đầu bị hủy
// không làm hỏng những người đi theo.
func (s *Service) load(ctx context.Context, prefix string) (*model.APIKey, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()

	k, err := s.store.GetAPIKeyByPrefix(ctx, prefix)
	var ptr *model.APIKey

	switch {
	case err == nil:
		ptr = &k

	case errors.Is(err, store.ErrNotFound):
		ptr = nil

	default:
		return nil, err
	}

	ttl := cacheTTL
	if ptr == nil {
		ttl = negativeTTL
	}

	// Jitter chỉ RÚT NGẮN TTL (80–100%): key bị thu hồi phải hết hiệu lực trong tối đa cacheTTL như đã cam kết,
	// nên không được kéo dài quá TTL danh nghĩa.
	ttl = time.Duration(float64(ttl) * (0.8 + 0.2*mrand.Float64()))

	s.mu.Lock()

	if len(s.cache) > 100_000 {
		s.cache = map[string]cacheEntry{}
	}

	s.cache[prefix] = cacheEntry{key: ptr, loaded: s.now(), ttl: ttl}
	s.mu.Unlock()
	return ptr, nil
}

// allowLookup trả false khi ip đã vượt ipLookupRPS/ipLookupBurst lượt tra DB (cache-miss) trong
// giây hiện tại. ip rỗng (ví dụ test không quan tâm tới IP) luôn được coi là một caller chung,
// giới hạn như một IP duy nhất.
func (s *Service) allowLookup(ctx context.Context, ip string) bool {
	if s.rdb != nil {
		if ok, err := s.redisAllow(ctx, "rl:ip:"+ip, ipLookupRPS, ipLookupBurst, 1); err == nil {
			return ok
		}
		// Redis lỗi: cho qua (fail-open), đã đếm vào metrics.RateLimitBackendErrors. Không quay về bộ đếm cục bộ,
		// vì khi đó mỗi instance sẽ có một giới hạn riêng và hành vi phụ thuộc vào việc Redis sống hay chết.
		return true
	}

	s.mu.Lock()

	if len(s.ipLimiters) > maxIPLookupLimiters {
		s.ipLimiters = map[string]*rate.Limiter{}
	}

	l, ok := s.ipLimiters[ip]
	if !ok {
		l = rate.NewLimiter(rate.Limit(ipLookupRPS), ipLookupBurst)
		s.ipLimiters[ip] = l
	}

	s.mu.Unlock()
	return l.Allow()
}

// Allow tiêu units token khỏi bộ đếm tốc độ của k, trong đó units là số mục THẬT SẼ được xử lý
// (1 cho /v1/check, len(items) cho /v1/check/batch — xem apiCheckBatch). rps_limit vì vậy luôn có
// nghĩa là "số mục mỗi giây", không phải "số lần gọi mỗi giây": một batch 100 mục và 100 lần gọi
// riêng lẻ tốn đúng số token như nhau. burst mặc định = rps_limit, nên một batch đơn lẻ lớn hơn rps_limit
// luôn bị chặn (bucket không bao giờ giữ đủ token). Muốn cho phép batch lớn hơn rps_limit, đặt
// max_batch của key (tối đa checker.MaxBatch): burst khi đó là max(rps_limit, max_batch), còn thông
// lượng duy trì vẫn đúng rps_limit. Xem M1 trong docs/ATTACK_PUBLIC_API.md.
func (s *Service) Allow(ctx context.Context, k *model.APIKey, units int) error {
	rps := k.RPSLimit
	if rps <= 0 {
		rps = s.defaultRPS
	}

	if rps > 0 {
		// burst = rps_limit, trừ khi key được cấp max_batch lớn hơn: khi đó xô chứa được tới max_batch
		// token để MỘT lần gọi batch cỡ đó lọt qua. Tốc độ nạp lại vẫn là rps token/giây, nên thông
		// lượng duy trì vẫn đúng rps_limit; max_batch chỉ cho phép dội một lần rồi phải chờ bù.
		burst := max(rps, k.MaxBatch)

		if s.rdb != nil {
			// Có Redis: bộ đếm nằm ở Redis và dùng chung cho mọi instance (chạy nhiều instance không làm giới hạn nhân lên).
			if ok, err := s.redisAllow(ctx, fmt.Sprintf("rl:key:%d", k.ID), float64(rps), burst, units); err == nil && !ok {
				return ErrRateLimited
			}

			return s.checkDailyQuota(ctx, k, units)
		}

		s.mu.Lock()
		le, ok := s.limiters[k.ID]
		if !ok || le.rps != rps || le.burst != burst {
			le = limiterEntry{l: rate.NewLimiter(rate.Limit(rps), burst), rps: rps, burst: burst}
			s.limiters[k.ID] = le
		}

		s.mu.Unlock()

		if !le.l.AllowN(time.Now(), units) {
			return ErrRateLimited
		}
	}

	return s.checkDailyQuota(ctx, k, units)
}

// checkDailyQuota kiểm tra và trừ hạn mức theo ngày của key (dùng Redis; lỗi Redis thì cho qua và đếm metric).
func (s *Service) checkDailyQuota(ctx context.Context, k *model.APIKey, units int) error {
	if k.DailyQuota > 0 && s.rdb != nil {
		rkey := fmt.Sprintf("quota:%d:%s", k.ID, s.now().UTC().Format("20060102"))
		cctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		used, err := s.rdb.IncrBy(cctx, rkey, int64(units)).Result()
		if err != nil {
			metrics.QuotaBackendErrors.Inc()
			return nil
		}

		if used == int64(units) {
			s.rdb.Expire(cctx, rkey, 48*time.Hour)
		}

		if used > k.DailyQuota {
			return ErrQuotaExceeded
		}
	}

	return nil
}

// FlushLastUsed ghi thời điểm dùng gần nhất đã đệm xuống database theo lô.
func (s *Service) FlushLastUsed(ctx context.Context) error {
	s.mu.Lock()
	ids := make([]int64, 0, len(s.used))

	for id := range s.used {
		ids = append(ids, id)
	}

	s.used = map[int64]struct{}{}
	s.mu.Unlock()
	return s.store.TouchAPIKeys(ctx, ids)
}

// Invalidate xóa key khỏi cache theo tiền tố để thu hồi hoặc đổi có hiệu lực ngay.
func (s *Service) Invalidate(prefix string) {
	s.mu.Lock()
	delete(s.cache, prefix)
	s.mu.Unlock()
}

// tokenBucketLua là token bucket nguyên tử trên Redis. Thời gian lấy từ chính Redis (TIME) nên các instance có đồng hồ
// lệch nhau cũng không làm sai bộ đếm. Trả 1 nếu cho phép (đã trừ units token), 0 nếu từ chối (không trừ gì).
var tokenBucketLua = redis.NewScript(`
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local units = tonumber(ARGV[3])
local t = redis.call('TIME')
local now = t[1] * 1000000 + t[2]
local d = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(d[1])
local ts = tonumber(d[2])
if tokens == nil then
  tokens = burst
  ts = now
end
local elapsed = math.max(0, now - ts) / 1000000
tokens = math.min(burst, tokens + elapsed * rate)
local ok = 0
if tokens >= units then
  tokens = tokens - units
  ok = 1
end
redis.call('HSET', KEYS[1], 'tokens', tostring(tokens), 'ts', now)
redis.call('PEXPIRE', KEYS[1], math.ceil(burst / rate * 1000) + 1000)
return ok
`)

// redisAllow trừ units token khỏi bucket key. Lỗi Redis (hoặc quá hạn 50ms) trả err để caller quyết định; mỗi lỗi
// được đếm vào vsf_ratelimit_backend_errors_total.
func (s *Service) redisAllow(ctx context.Context, key string, rps float64, burst, units int) (bool, error) {
	cctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()

	v, err := tokenBucketLua.Run(cctx, s.rdb, []string{key}, rps, burst, units).Int()
	if err != nil {
		metrics.RateLimitBackendErrors.Inc()
		return true, err
	}

	return v == 1, nil
}
