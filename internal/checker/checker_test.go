package checker

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/seal"
)

type fakeFilter struct{ answer bool }

func (f fakeFilter) Test(uint64) bool { return f.answer }

type fakeEpoch struct{ v string }

func (f fakeEpoch) Epoch() string { return f.v }

type fakeFinder struct {
	calls   atomic.Int32
	entries []model.Entry
	err     error
	delay   time.Duration
}

func (f *fakeFinder) FindMatches(ctx context.Context, keys []normalize.Key) ([]model.Entry, error) {
	f.calls.Add(1)
	time.Sleep(f.delay)
	return f.entries, f.err
}

type memCache struct {
	mu   sync.Mutex
	data map[string][]byte
	gets atomic.Int32
}

func newMemCache() *memCache { return &memCache{data: map[string][]byte{}} }
func (m *memCache) Get(_ context.Context, k string) ([]byte, bool) {
	m.gets.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.data[k]
	return b, ok
}
func (m *memCache) Set(_ context.Context, k string, v []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[k] = v
}

func newChecker(f Filter, c *memCache, fd *fakeFinder) *Checker {
	return New("VN", f, c, fd, fakeEpoch{"1.1"})
}

func TestBloomNegativeSkipsEverything(t *testing.T) {
	fd := &fakeFinder{}
	c := newMemCache()
	ck := newChecker(fakeFilter{false}, c, fd)
	res, err := ck.Check(context.Background(), normalize.TypeURL, "http://example.com")
	if err != nil || res.Blacklisted {
		t.Fatalf("res=%+v err=%v", res, err)
	}

	if fd.calls.Load() != 0 || c.gets.Load() != 0 {
		t.Fatal("Bloom negative must not touch cache or DB")
	}
}

func TestDBHitThenCacheHit(t *testing.T) {
	fd := &fakeFinder{entries: []model.Entry{
		{ID: 7, MatchType: "domain", Value: "evil.com", Category: "scam", RiskScore: 60},
		{ID: 9, MatchType: "prefix", Value: "evil.com/shop", Category: "phishing", RiskScore: 95},
	}}

	c := newMemCache()
	ck := newChecker(fakeFilter{true}, c, fd)

	res, err := ck.Check(context.Background(), normalize.TypeURL, "https://www.evil.com/shop/x?utm_source=a")
	if err != nil || !res.Blacklisted || res.Match.EntryID != 9 || res.Match.Category != "phishing" {
		t.Fatalf("want highest risk entry 9, got %+v err=%v", res, err)
	}

	if res.Normalized != "evil.com/shop/x" {
		t.Fatalf("normalized = %q", res.Normalized)
	}

	res2, _ := ck.Check(context.Background(), normalize.TypeURL, "HTTP://evil.com/shop/x/")
	if !res2.Blacklisted || fd.calls.Load() != 1 {
		t.Fatalf("second call should hit cache; dbCalls=%d res=%+v", fd.calls.Load(), res2)
	}
}

func TestNegativeResultIsCached(t *testing.T) {
	fd := &fakeFinder{}
	ck := newChecker(fakeFilter{true}, newMemCache(), fd)

	for i := 0; i < 3; i++ {
		res, err := ck.Check(context.Background(), normalize.TypePhone, "0901234567")
		if err != nil || res.Blacklisted {
			t.Fatalf("res=%+v err=%v", res, err)
		}
	}

	if fd.calls.Load() != 1 {
		t.Fatalf("negative result must be cached; dbCalls=%d", fd.calls.Load())
	}
}

func TestEpochChangeInvalidatesCache(t *testing.T) {
	fd := &fakeFinder{}
	c := newMemCache()
	ep := &fakeEpochMut{}
	ep.set("1.1")
	ck := New("VN", fakeFilter{true}, c, fd, ep)
	_, _ = ck.Check(context.Background(), normalize.TypePhone, "0901234567")
	ep.set("1.2")
	_, _ = ck.Check(context.Background(), normalize.TypePhone, "0901234567")

	if fd.calls.Load() != 2 {
		t.Fatalf("new epoch must bypass old cache entries; dbCalls=%d", fd.calls.Load())
	}
}

type fakeEpochMut struct{ v atomic.Value }

func (f *fakeEpochMut) set(s string)  { f.v.Store(s) }
func (f *fakeEpochMut) Epoch() string { return f.v.Load().(string) }

func TestSingleflightCollapsesConcurrentRequests(t *testing.T) {
	fd := &fakeFinder{delay: 100 * time.Millisecond, entries: []model.Entry{{ID: 1, MatchType: "exact", Value: "+84901234567", RiskScore: 50}}}
	ck := newChecker(fakeFilter{true}, newMemCache(), fd)
	var wg sync.WaitGroup

	for i := 0; i < 50; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()
			res, err := ck.Check(context.Background(), normalize.TypePhone, "0901234567")
			if err != nil || !res.Blacklisted {
				t.Errorf("res=%+v err=%v", res, err)
			}
		}()
	}

	wg.Wait()

	if n := fd.calls.Load(); n > 3 {
		t.Fatalf("expected requests to be collapsed, DB calls = %d", n)
	}
}

func TestInvalidInputAndDBError(t *testing.T) {
	ck := newChecker(fakeFilter{true}, newMemCache(), &fakeFinder{})
	if _, err := ck.Check(context.Background(), normalize.TypePhone, "abc"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("want ErrInvalidInput, got %v", err)
	}

	ck = newChecker(fakeFilter{true}, newMemCache(), &fakeFinder{err: errors.New("db down")})
	if _, err := ck.Check(context.Background(), normalize.TypePhone, "0901234567"); err == nil || errors.Is(err, ErrInvalidInput) {
		t.Fatalf("DB failure must surface as non-invalid error, got %v", err)
	}
}

func TestBatchKeepsOrderAndIsolatesErrors(t *testing.T) {
	fd := &fakeFinder{entries: []model.Entry{{ID: 1, MatchType: "exact", Value: "x", RiskScore: 1}}}
	ck := newChecker(fakeFilter{true}, newMemCache(), fd)
	out := ck.CheckBatch(context.Background(), []Item{
		{Type: "phone", Value: "0901234567"},
		{Type: "phone", Value: "not a phone"},
		{Type: "url", Value: "http://a.com/x"},
	})
	if len(out) != 3 || !out[0].Blacklisted || out[1].Error == "" || !out[2].Blacklisted {
		t.Fatalf("batch = %+v", out)
	}

	if out[0].Input != "0901234567" || out[2].Input != "http://a.com/x" {
		t.Fatal("results must keep input order")
	}
}

func TestCacheIsSealedAndKeyHidesInput(t *testing.T) {
	sl, err := seal.New("0123456789abcdef0123456789abcdef-data", "fedcba9876543210fedcba9876543210-pepper", 1)
	if err != nil {
		t.Fatal(err)
	}

	normalize.SetHasher(sl.Hasher())

	cache := newMemCache()
	fd := &fakeFinder{entries: []model.Entry{{ID: 7, Type: "phone", MatchType: "exact", Value: "+84901234567", Category: "spam", RiskScore: 90}}}
	c := newChecker(fakeFilter{true}, cache, fd)
	c.SetCacheSealer(sl)

	for i := 0; i < 2; i++ { // second call must be served from the sealed cache
		res, err := c.Check(context.Background(), normalize.TypePhone, "0901234567")
		if err != nil || !res.Blacklisted || res.Match == nil || res.Match.MatchedValue != "+84901234567" {
			t.Fatalf("call %d: %+v, %v", i, res, err)
		}
	}

	if fd.calls.Load() != 1 {
		t.Fatalf("expected 1 DB call (second from cache), got %d", fd.calls.Load())
	}

	cache.mu.Lock()
	defer cache.mu.Unlock()

	for k, v := range cache.data {
		if strings.Contains(k, "901234567") || bytes.Contains(v, []byte("901234567")) || bytes.Contains(v, []byte("spam")) {
			t.Errorf("cache leaks plaintext: key=%q", k)
		}
	}
}
