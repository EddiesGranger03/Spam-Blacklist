package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"

	"vsf/internal/metrics"
	"vsf/internal/model"
	"vsf/internal/store"
)

var (
	ErrMissing       = errors.New("missing api key")
	ErrInvalid       = errors.New("invalid api key")
	ErrRevoked       = errors.New("api key revoked")
	ErrExpired       = errors.New("api key expired")
	ErrRateLimited   = errors.New("rate limit exceeded")
	ErrQuotaExceeded = errors.New("daily quota exceeded")
)

const (
	alphabet    = "abcdefghijklmnopqrstuvwxyz0123456789"
	prefixLen   = 8
	secretLen   = 32
	cacheTTL    = 30 * time.Second
	negativeTTL = 10 * time.Second
)

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

func HashSecret(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

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
}

type limiterEntry struct {
	l   *rate.Limiter
	rps int
}

type Service struct {
	store      Store
	rdb        *redis.Client
	defaultRPS int
	now        func() time.Time

	mu       sync.Mutex
	cache    map[string]cacheEntry
	limiters map[int64]limiterEntry
	used     map[int64]struct{}
}

func NewService(st Store, rdb *redis.Client, defaultRPS int) *Service {
	return &Service{store: st, rdb: rdb, defaultRPS: defaultRPS, now: time.Now,
		cache: map[string]cacheEntry{}, limiters: map[int64]limiterEntry{}, used: map[int64]struct{}{}}
}

func (s *Service) Authenticate(ctx context.Context, full string) (*model.APIKey, error) {
	if full == "" {
		return nil, ErrMissing
	}

	prefix, secret, ok := Parse(full)
	if !ok {
		return nil, ErrInvalid
	}

	k, err := s.lookup(ctx, prefix)
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

func (s *Service) lookup(ctx context.Context, prefix string) (*model.APIKey, error) {
	s.mu.Lock()

	if e, ok := s.cache[prefix]; ok {
		ttl := cacheTTL

		if e.key == nil {
			ttl = negativeTTL
		}

		if s.now().Sub(e.loaded) < ttl {
			s.mu.Unlock()
			return e.key, nil
		}
	}

	s.mu.Unlock()

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

	s.mu.Lock()

	if len(s.cache) > 100_000 {
		s.cache = map[string]cacheEntry{}
	}

	s.cache[prefix] = cacheEntry{key: ptr, loaded: s.now()}
	s.mu.Unlock()
	return ptr, nil
}

func (s *Service) Allow(ctx context.Context, k *model.APIKey, units int) error {
	rps := k.RPSLimit
	if rps <= 0 {
		rps = s.defaultRPS
	}

	if rps > 0 {
		s.mu.Lock()
		le, ok := s.limiters[k.ID]
		if !ok || le.rps != rps {
			le = limiterEntry{l: rate.NewLimiter(rate.Limit(rps), rps), rps: rps}
			s.limiters[k.ID] = le
		}

		s.mu.Unlock()

		if !le.l.Allow() {
			return ErrRateLimited
		}
	}

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

func (s *Service) Invalidate(prefix string) {
	s.mu.Lock()
	delete(s.cache, prefix)
	s.mu.Unlock()
}
