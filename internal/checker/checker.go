package checker

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"vsf/internal/cache"
	"vsf/internal/metrics"
	"vsf/internal/model"
	"vsf/internal/normalize"
)

type EntryFinder interface {
	FindMatches(ctx context.Context, keys []normalize.Key) ([]model.Entry, error)
}

type Filter interface{ Test(h uint64) bool }

type Epocher interface{ Epoch() string }

var ErrInvalidInput = normalize.ErrInvalid

type Match struct {
	EntryID      int64  `json:"entry_id"`
	MatchType    string `json:"match_type"`
	MatchedValue string `json:"matched_value"`
	Category     string `json:"category"`
	RiskScore    int    `json:"risk_score"`
}

type Result struct {
	Type        string `json:"type"`
	Input       string `json:"input"`
	Normalized  string `json:"normalized"`
	Blacklisted bool   `json:"blacklisted"`
	Match       *Match `json:"match,omitempty"`
}

type Item struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type BatchResult struct {
	Result
	Error string `json:"error,omitempty"`
}

const MaxBatch = 100

type Checker struct {
	region string
	filter Filter
	cache  cache.Cache
	sealer CacheSealer
	finder EntryFinder
	epoch  Epocher
	sf     singleflight.Group
}

func New(region string, f Filter, c cache.Cache, finder EntryFinder, e Epocher) *Checker {
	return &Checker{region: region, filter: f, cache: c, finder: finder, epoch: e}
}

// CacheSealer encrypts cache values so Redis never holds a matched value in clear.
// *seal.Sealer satisfies it.
type CacheSealer interface {
	Seal(plaintext, aad string) ([]byte, error)
	Open(blob []byte, aad string) (string, error)
}

const cacheAAD = "check-cache"

// SetCacheSealer makes the checker encrypt what it writes to the cache and use
// the keyed blind index (not the raw phone/URL) in cache keys.
func (c *Checker) SetCacheSealer(cs CacheSealer) { c.sealer = cs }

type cached struct {
	Match *Match `json:"m"`
}

func (c *Checker) Check(ctx context.Context, typ normalize.Type, raw string) (Result, error) {
	res := Result{Type: string(typ), Input: raw}

	normalized, keys, err := normalize.Candidates(typ, raw, c.region)
	if err != nil {
		metrics.CheckResult.WithLabelValues("invalid").Inc()
		return res, err
	}

	res.Normalized = normalized

	maybe := make([]normalize.Key, 0, len(keys))

	for _, k := range keys {
		if c.filter.Test(uint64(k.Hash)) {
			maybe = append(maybe, k)
		}
	}

	if len(maybe) == 0 {
		metrics.CheckLayer.WithLabelValues("bloom").Inc()
		metrics.CheckResult.WithLabelValues("safe").Inc()
		return res, nil
	}

	cacheID := normalized
	if len(keys[0].Blind) > 0 { // keys[0] is the exact candidate; its blind index hides the raw value
		cacheID = hex.EncodeToString(keys[0].Blind)
	}

	cacheKey := fmt.Sprintf("chk:%s:%s:%s", c.epoch.Epoch(), typ, cacheID)

	if b, ok := c.cache.Get(ctx, cacheKey); ok {
		var cv cached
		if c.openCache(b, &cv) == nil {
			metrics.CheckLayer.WithLabelValues("cache").Inc()
			return c.finish(res, cv.Match), nil
		}
	}

	v, err, _ := c.sf.Do(cacheKey, func() (any, error) {
		dbctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		entries, err := c.finder.FindMatches(dbctx, maybe)
		if err != nil {
			return nil, err
		}

		m := best(entries)
		if b, err := c.sealCache(cached{Match: m}); err == nil {
			c.cache.Set(dbctx, cacheKey, b)
		}

		return m, nil
	})
	if err != nil {
		metrics.CheckResult.WithLabelValues("error").Inc()
		return res, fmt.Errorf("lookup: %w", err)
	}

	m, _ := v.(*Match)
	metrics.CheckLayer.WithLabelValues("db").Inc()

	if m == nil {
		metrics.BloomFalsePositive.Inc()
	}

	return c.finish(res, m), nil
}

func (c *Checker) finish(res Result, m *Match) Result {
	if m != nil {
		res.Blacklisted, res.Match = true, m
		metrics.CheckResult.WithLabelValues("blacklisted").Inc()
	} else {
		metrics.CheckResult.WithLabelValues("safe").Inc()
	}

	return res
}

func best(entries []model.Entry) *Match {
	var top *model.Entry

	for i := range entries {
		e := &entries[i]
		if top == nil || e.RiskScore > top.RiskScore || (e.RiskScore == top.RiskScore && e.ID < top.ID) {
			top = e
		}
	}

	if top == nil {
		return nil
	}

	return &Match{EntryID: top.ID, MatchType: top.MatchType, MatchedValue: top.Value,
		Category: top.Category, RiskScore: top.RiskScore}
}

func (c *Checker) CheckBatch(ctx context.Context, items []Item) []BatchResult {
	out := make([]BatchResult, len(items))
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup

	for i, it := range items {
		wg.Add(1)
		sem <- struct{}{}

		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			res, err := c.Check(ctx, normalize.Type(it.Type), it.Value)
			out[i] = BatchResult{Result: res}

			if err != nil {
				if errors.Is(err, ErrInvalidInput) {
					out[i].Error = err.Error()
				} else {
					out[i].Error = "internal error"
				}
			}
		}()
	}

	wg.Wait()
	return out
}

func (c *Checker) sealCache(v cached) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil || c.sealer == nil {
		return b, err
	}

	return c.sealer.Seal(string(b), cacheAAD)
}

func (c *Checker) openCache(b []byte, v *cached) error {
	if c.sealer != nil {
		plain, err := c.sealer.Open(b, cacheAAD)
		if err != nil {
			return err
		}

		b = []byte(plain)
	}

	return json.Unmarshal(b, v)
}
