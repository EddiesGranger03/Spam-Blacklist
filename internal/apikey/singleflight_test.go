package apikey

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vsf/internal/model"
	"vsf/internal/store"
)

// slowStore là Store an toàn đồng thời, trả chậm để mọi goroutine cùng kẹt trong cache-miss (F8).
type slowStore struct {
	keys  map[string]model.APIKey
	calls atomic.Int64
	delay time.Duration
}

func (s *slowStore) GetAPIKeyByPrefix(_ context.Context, p string) (model.APIKey, error) {
	s.calls.Add(1)
	time.Sleep(s.delay)

	k, ok := s.keys[p]
	if !ok {
		return model.APIKey{}, store.ErrNotFound
	}

	return k, nil
}

func (s *slowStore) TouchAPIKeys(context.Context, []int64) error { return nil }

// hammer chạy n goroutine cùng xác thực full từ cùng một IP, trả số lỗi theo loại.
func hammer(s *Service, full string, n int) (rateLimited, other int) {
	var wg sync.WaitGroup
	var rl, ot atomic.Int64
	start := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()
			<-start

			if _, err := s.Authenticate(context.Background(), full, "10.0.0.1"); err != nil {
				if errors.Is(err, ErrTooManyAuthAttempts) {
					rl.Add(1)
				} else {
					ot.Add(1)
				}
			}
		}()
	}

	close(start)
	wg.Wait()
	return int(rl.Load()), int(ot.Load())
}

// TestConcurrentCacheExpiryNoSpurious429 tái hiện F8: 64 request đồng thời cùng một key hợp lệ đúng lúc cache hết hạn
// không được nhận 429, và chỉ tốn một lần tra DB.
func TestConcurrentCacheExpiryNoSpurious429(t *testing.T) {
	fs := &fakeStore{keys: map[string]model.APIKey{}}
	full := newKey(t, fs, nil)
	st := &slowStore{keys: fs.keys, delay: 20 * time.Millisecond}
	s := NewService(st, nil, 0)

	var mu sync.Mutex
	now := time.Now()
	s.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }

	if _, err := s.Authenticate(context.Background(), full, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	now = now.Add(cacheTTL * 2)
	mu.Unlock()
	st.calls.Store(0)

	rl, other := hammer(s, full, 64)
	if rl != 0 || other != 0 {
		t.Fatalf("valid key got %d x 429 and %d other errors out of 64", rl, other)
	}

	if c := st.calls.Load(); c != 1 {
		t.Fatalf("expected 1 DB lookup, got %d", c)
	}
}

// TestSingleflightDoesNotShareVerdictAcrossSecrets: key sai secret nhưng cùng prefix với key đúng đi chung lần tra DB
// nhưng vẫn phải bị ErrInvalid, còn key đúng vẫn qua.
func TestSingleflightDoesNotShareVerdictAcrossSecrets(t *testing.T) {
	fs := &fakeStore{keys: map[string]model.APIKey{}}
	full := newKey(t, fs, nil)
	prefix, _, _ := Parse(full)
	wrong := "vsf_" + prefix + "_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	s := NewService(&slowStore{keys: fs.keys, delay: 20 * time.Millisecond}, nil, 0)

	var wg sync.WaitGroup
	var badOK, goodFail atomic.Int64

	for i := 0; i < 32; i++ {
		wg.Add(2)

		go func() {
			defer wg.Done()
			if _, err := s.Authenticate(context.Background(), wrong, "1.1.1.1"); err == nil {
				badOK.Add(1)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := s.Authenticate(context.Background(), full, "1.1.1.1"); err != nil {
				goodFail.Add(1)
			}
		}()
	}

	wg.Wait()

	if badOK.Load() != 0 || goodFail.Load() != 0 {
		t.Fatalf("wrong key accepted %d, valid key rejected %d", badOK.Load(), goodFail.Load())
	}
}

// TestUnknownPrefixesStillRateLimited: dò nhiều prefix lạ từ một IP vẫn bị giới hạn như cũ.
func TestUnknownPrefixesStillRateLimited(t *testing.T) {
	s := NewService(&slowStore{keys: map[string]model.APIKey{}}, nil, 0)
	limited := 0

	for i := 0; i < 100; i++ {
		full, _, _, _ := Generate()
		if _, err := s.Authenticate(context.Background(), full, "9.9.9.9"); errors.Is(err, ErrTooManyAuthAttempts) {
			limited++
		}
	}

	if limited < 50 {
		t.Fatalf("expected probing to be limited, only %d/100 limited", limited)
	}
}
