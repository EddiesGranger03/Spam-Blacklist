package apikey

import (
	"context"
	"errors"
	"testing"
	"time"

	"vsf/internal/model"
	"vsf/internal/store"
)

type fakeStore struct {
	keys  map[string]model.APIKey
	calls int
}

func (f *fakeStore) GetAPIKeyByPrefix(_ context.Context, p string) (model.APIKey, error) {
	f.calls++
	k, ok := f.keys[p]
	if !ok {
		return model.APIKey{}, store.ErrNotFound
	}

	return k, nil
}
func (f *fakeStore) TouchAPIKeys(context.Context, []int64) error { return nil }

func newKey(t *testing.T, fs *fakeStore, mut func(*model.APIKey)) string {
	t.Helper()
	full, prefix, hash, err := Generate()
	if err != nil {
		t.Fatal(err)
	}

	k := model.APIKey{ID: int64(len(fs.keys) + 1), Prefix: prefix, KeyHash: hash, Status: "active", RPSLimit: 1000}

	if mut != nil {
		mut(&k)
	}

	fs.keys[prefix] = k
	return full
}

func TestGenerateParse(t *testing.T) {
	full, prefix, hash, err := Generate()
	if err != nil {
		t.Fatal(err)
	}

	p, secret, ok := Parse(full)
	if !ok || p != prefix || string(HashSecret(secret)) != string(hash) {
		t.Fatalf("parse mismatch: %q", full)
	}

	for _, bad := range []string{"", "abc", "vsf_short_x", "xxx_12345678_" + secret, full + "_extra"} {
		if _, _, ok := Parse(bad); ok {
			t.Fatalf("Parse(%q) should fail", bad)
		}
	}

	other, _, _, _ := Generate()
	if other == full {
		t.Fatal("keys must be random")
	}
}

func TestAuthenticate(t *testing.T) {
	fs := &fakeStore{keys: map[string]model.APIKey{}}
	s := NewService(fs, nil, 100)
	ctx := context.Background()

	good := newKey(t, fs, nil)
	if k, err := s.Authenticate(ctx, good); err != nil || k == nil {
		t.Fatalf("valid key rejected: %v", err)
	}

	if _, err := s.Authenticate(ctx, ""); !errors.Is(err, ErrMissing) {
		t.Fatalf("want ErrMissing, got %v", err)
	}

	if _, err := s.Authenticate(ctx, "garbage"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}

	prefix, _, _ := Parse(good)
	wrong := "vsf_" + prefix + "_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := s.Authenticate(ctx, wrong); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong secret: want ErrInvalid, got %v", err)
	}

	revoked := newKey(t, fs, func(k *model.APIKey) { k.Status = "revoked" })
	if _, err := s.Authenticate(ctx, revoked); !errors.Is(err, ErrRevoked) {
		t.Fatalf("want ErrRevoked, got %v", err)
	}

	past := time.Now().Add(-time.Minute)
	expired := newKey(t, fs, func(k *model.APIKey) { k.ExpiresAt = &past })
	if _, err := s.Authenticate(ctx, expired); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}

	future := time.Now().Add(time.Hour)
	rotating := newKey(t, fs, func(k *model.APIKey) { k.ExpiresAt = &future })
	if _, err := s.Authenticate(ctx, rotating); err != nil {
		t.Fatalf("key within grace period must work: %v", err)
	}
}

func TestLookupCachingAndRevocationLatency(t *testing.T) {
	fs := &fakeStore{keys: map[string]model.APIKey{}}
	s := NewService(fs, nil, 100)
	now := time.Now()
	s.now = func() time.Time { return now }
	ctx := context.Background()
	full := newKey(t, fs, nil)

	for i := 0; i < 5; i++ {
		if _, err := s.Authenticate(ctx, full); err != nil {
			t.Fatal(err)
		}
	}

	if fs.calls != 1 {
		t.Fatalf("key lookups should be cached; DB calls = %d", fs.calls)
	}

	prefix, _, _ := Parse(full)
	k := fs.keys[prefix]
	k.Status = "revoked"
	fs.keys[prefix] = k

	if _, err := s.Authenticate(ctx, full); err != nil {
		t.Fatal("revocation is expected to lag until the cache expires")
	}

	now = now.Add(cacheTTL + time.Second)

	if _, err := s.Authenticate(ctx, full); !errors.Is(err, ErrRevoked) {
		t.Fatalf("after TTL want ErrRevoked, got %v", err)
	}

	k.Status = "active"
	fs.keys[prefix] = k
	s.Invalidate(prefix)

	if _, err := s.Authenticate(ctx, full); err != nil {
		t.Fatalf("after Invalidate want ok, got %v", err)
	}

	before := fs.calls
	unknown := "vsf_zzzzzzzz_" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	for i := 0; i < 5; i++ {
		_, _ = s.Authenticate(ctx, unknown)
	}

	if fs.calls-before != 1 {
		t.Fatalf("unknown prefix should hit DB once; got %d", fs.calls-before)
	}
}

func TestRateLimit(t *testing.T) {
	s := NewService(&fakeStore{keys: map[string]model.APIKey{}}, nil, 100)
	k := &model.APIKey{ID: 1, RPSLimit: 3}
	ctx := context.Background()
	ok := 0

	for i := 0; i < 10; i++ {
		if s.Allow(ctx, k, 1) == nil {
			ok++
		}
	}

	if ok < 3 || ok > 4 {
		t.Fatalf("expected about 3 requests allowed in a burst, got %d", ok)
	}

	if err := s.Allow(ctx, k, 1); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("want ErrRateLimited, got %v", err)
	}

	if err := s.Allow(ctx, &model.APIKey{ID: 2, RPSLimit: 3}, 1); err != nil {
		t.Fatalf("other key must be independent: %v", err)
	}
}
