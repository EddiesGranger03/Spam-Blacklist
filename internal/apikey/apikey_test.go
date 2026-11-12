package apikey

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"vsf/internal/model"
	"vsf/internal/store"
)

type fakeStore struct {
	keys  map[string]model.APIKey
	calls int
}

// GetAPIKeyByPrefix của fakeStore trả về key theo tiền tố (giả lập).
func (f *fakeStore) GetAPIKeyByPrefix(_ context.Context, p string) (model.APIKey, error) {
	f.calls++
	k, ok := f.keys[p]
	if !ok {
		return model.APIKey{}, store.ErrNotFound
	}

	return k, nil
}
// TouchAPIKeys của fakeStore không làm gì (giả lập).
func (f *fakeStore) TouchAPIKeys(context.Context, []int64) error { return nil }

// newKey tạo một API key hợp lệ trong fakeStore, cho phép sửa trước khi lưu.
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

// TestGenerateParse kiểm tra tạo và tách API key khớp nhau.
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

// TestAuthenticate kiểm tra xác thực key đúng, sai, hết hạn và bị thu hồi.
func TestAuthenticate(t *testing.T) {
	fs := &fakeStore{keys: map[string]model.APIKey{}}
	s := NewService(fs, nil, 100)
	ctx := context.Background()

	good := newKey(t, fs, nil)
	if k, err := s.Authenticate(ctx, good, "1.1.1.1"); err != nil || k == nil {
		t.Fatalf("valid key rejected: %v", err)
	}

	if _, err := s.Authenticate(ctx, "", "1.1.1.1"); !errors.Is(err, ErrMissing) {
		t.Fatalf("want ErrMissing, got %v", err)
	}

	if _, err := s.Authenticate(ctx, "garbage", "1.1.1.1"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}

	prefix, _, _ := Parse(good)
	wrong := "vsf_" + prefix + "_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if _, err := s.Authenticate(ctx, wrong, "1.1.1.1"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong secret: want ErrInvalid, got %v", err)
	}

	revoked := newKey(t, fs, func(k *model.APIKey) { k.Status = "revoked" })
	if _, err := s.Authenticate(ctx, revoked, "1.1.1.1"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("want ErrRevoked, got %v", err)
	}

	past := time.Now().Add(-time.Minute)
	expired := newKey(t, fs, func(k *model.APIKey) { k.ExpiresAt = &past })
	if _, err := s.Authenticate(ctx, expired, "1.1.1.1"); !errors.Is(err, ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}

	future := time.Now().Add(time.Hour)
	rotating := newKey(t, fs, func(k *model.APIKey) { k.ExpiresAt = &future })
	if _, err := s.Authenticate(ctx, rotating, "1.1.1.1"); err != nil {
		t.Fatalf("key within grace period must work: %v", err)
	}
}

// TestLookupCachingAndRevocationLatency kiểm tra cache tra cứu và độ trễ khi thu hồi key.
func TestLookupCachingAndRevocationLatency(t *testing.T) {
	fs := &fakeStore{keys: map[string]model.APIKey{}}
	s := NewService(fs, nil, 100)
	now := time.Now()
	s.now = func() time.Time { return now }
	ctx := context.Background()
	full := newKey(t, fs, nil)

	for i := 0; i < 5; i++ {
		if _, err := s.Authenticate(ctx, full, "1.1.1.1"); err != nil {
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

	if _, err := s.Authenticate(ctx, full, "1.1.1.1"); err != nil {
		t.Fatal("revocation is expected to lag until the cache expires")
	}

	now = now.Add(cacheTTL + time.Second)

	if _, err := s.Authenticate(ctx, full, "1.1.1.1"); !errors.Is(err, ErrRevoked) {
		t.Fatalf("after TTL want ErrRevoked, got %v", err)
	}

	k.Status = "active"
	fs.keys[prefix] = k
	s.Invalidate(prefix)

	if _, err := s.Authenticate(ctx, full, "1.1.1.1"); err != nil {
		t.Fatalf("after Invalidate want ok, got %v", err)
	}

	before := fs.calls
	unknown := "vsf_zzzzzzzz_" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	for i := 0; i < 5; i++ {
		_, _ = s.Authenticate(ctx, unknown, "1.1.1.1")
	}

	if fs.calls-before != 1 {
		t.Fatalf("unknown prefix should hit DB once; got %d", fs.calls-before)
	}
}

// TestIPLookupRateLimit_BlocksRotatingPrefixes tái hiện lỗi A1 (docs/ATTACK_PUBLIC_API.md): một
// caller đổi prefix liên tục (luôn cache-miss) từ MỘT IP bị chặn ở đúng ipLookupBurst lượt, không
// được chạm tới store thêm nữa, trong khi một IP khác hoàn toàn không bị ảnh hưởng.
func TestIPLookupRateLimit_BlocksRotatingPrefixes(t *testing.T) {
	fs := &fakeStore{keys: map[string]model.APIKey{}}
	s := NewService(fs, nil, 100)
	ctx := context.Background()

	randomKey := func(i int) string {
		return fmt.Sprintf("vsf_rand%04d_cccccccccccccccccccccccccccccccc", i)
	}

	attackerCalls := 0
	limited := 0

	for i := 0; i < 200; i++ {
		_, err := s.Authenticate(ctx, randomKey(i), "9.9.9.9")
		if errors.Is(err, ErrTooManyAuthAttempts) {
			limited++
			continue
		}

		attackerCalls++
	}

	if attackerCalls != ipLookupBurst {
		t.Fatalf("attacker (1 IP, prefix xoay liên tục): muốn %d lượt chạm store trước khi bị chặn, được %d",
			ipLookupBurst, attackerCalls)
	}

	if limited != 200-ipLookupBurst {
		t.Fatalf("muốn %d lượt bị ErrTooManyAuthAttempts, được %d", 200-ipLookupBurst, limited)
	}

	if fs.calls != ipLookupBurst {
		t.Fatalf("store không được gọi nhiều hơn %d lần (bị chặn trước khi tra DB); gọi %d lần", ipLookupBurst, fs.calls)
	}

	// Một key THẬT, hợp lệ, đã nằm trong cache: đổi IP khác không liên quan, lặp lại nhiều lần,
	// vẫn phải luôn thành công vì không hề chạm nhánh DB (cache hit, không gọi allowLookup).
	good := newKey(t, fs, nil)
	if _, err := s.Authenticate(ctx, good, "8.8.8.8"); err != nil {
		t.Fatalf("lượt nạp cache đầu tiên phải thành công: %v", err)
	}

	callsAfterWarm := fs.calls

	for i := 0; i < 500; i++ {
		if _, err := s.Authenticate(ctx, good, "8.8.8.8"); err != nil {
			t.Fatalf("khách hợp lệ dùng ĐÚNG 1 key, IP khác: không được bị ảnh hưởng bởi IP 9.9.9.9 đang bị chặn: %v", err)
		}
	}

	if fs.calls != callsAfterWarm {
		t.Fatalf("key đã cache không được gọi thêm store: trước=%d sau=%d", callsAfterWarm, fs.calls)
	}
}

// TestIPLookupRateLimit_IndependentPerIP: IP bị chặn không ảnh hưởng IP khác đang tra prefix mới.
func TestIPLookupRateLimit_IndependentPerIP(t *testing.T) {
	fs := &fakeStore{keys: map[string]model.APIKey{}}
	s := NewService(fs, nil, 100)
	ctx := context.Background()

	for i := 0; i < ipLookupBurst+5; i++ {
		_, _ = s.Authenticate(ctx, fmt.Sprintf("vsf_evil%04d_cccccccccccccccccccccccccccccccc", i), "10.0.0.1")
	}

	// IP khác, cũng toàn prefix mới, nhưng chỉ trong giới hạn burst: không được bị ảnh hưởng
	// bởi việc IP "10.0.0.1" đã bị chặn ở trên.
	for i := 0; i < ipLookupBurst; i++ {
		if _, err := s.Authenticate(ctx, fmt.Sprintf("vsf_safe%04d_cccccccccccccccccccccccccccccccc", i), "10.0.0.2"); errors.Is(err, ErrTooManyAuthAttempts) {
			t.Fatalf("lượt %d từ IP khác không được bị chặn, do IP 10.0.0.1 đang bị chặn riêng", i)
		}
	}
}

// TestRateLimit kiểm tra giới hạn tốc độ theo key.
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

// TestRateLimit_MaxBatchGrantsBurstOnly: max_batch cho phép MỘT lần gọi batch lớn hơn rps_limit,
// nhưng không nâng tốc độ duy trì, và không nới gì cho key không được cấp max_batch.
func TestRateLimit_MaxBatchGrantsBurstOnly(t *testing.T) {
	s := NewService(&fakeStore{keys: map[string]model.APIKey{}}, nil, 100)
	ctx := context.Background()

	// rps_limit=10, max_batch=100: 1 batch 100 mục lọt (bucket đầy 100 token)...
	k := &model.APIKey{ID: 20, RPSLimit: 10, MaxBatch: 100}
	if err := s.Allow(ctx, k, 100); err != nil {
		t.Fatalf("batch 100 mục phải lọt khi max_batch=100: %v", err)
	}

	// ...nhưng ngay sau đó phải bị chặn: thông lượng duy trì vẫn chỉ 10 mục/giây.
	if err := s.Allow(ctx, k, 100); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("batch thứ 2 liền sau phải bị chặn (phải chờ nạp lại), got %v", err)
	}

	if err := s.Allow(ctx, k, 1); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("1 mục lẻ ngay sau khi bucket cạn phải bị chặn, got %v", err)
	}

	// max_batch=0 (mặc định, key cũ): batch 100 với rps_limit=10 vẫn luôn bị chặn như trước.
	old := &model.APIKey{ID: 21, RPSLimit: 10}
	if err := s.Allow(ctx, old, 100); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("key không có max_batch: batch 100 phải bị chặn, got %v", err)
	}

	// max_batch nhỏ hơn rps_limit không được làm xô nhỏ đi: burst = max(rps, max_batch).
	small := &model.APIKey{ID: 22, RPSLimit: 50, MaxBatch: 5}
	if err := s.Allow(ctx, small, 50); err != nil {
		t.Fatalf("max_batch < rps_limit không được hạ burst xuống dưới rps_limit: %v", err)
	}

	// Đổi cấu hình key (admin tăng max_batch) phải có hiệu lực: limiter được tạo lại.
	grow := &model.APIKey{ID: 23, RPSLimit: 10}
	if err := s.Allow(ctx, grow, 100); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("trước khi cấp max_batch: phải bị chặn, got %v", err)
	}

	grow.MaxBatch = 100
	if err := s.Allow(ctx, grow, 100); err != nil {
		t.Fatalf("sau khi cấp max_batch=100 phải lọt: %v", err)
	}
}

// TestRateLimit_BatchCostsProportionally tái hiện lỗi M1 (docs/ATTACK_PUBLIC_API.md): trước khi
// vá, 100 lượt batch 10-mục liên tiếp đều lọt (mỗi lượt chỉ tốn 1 token bất kể bao nhiêu mục).
// Sau khi vá, một batch phải tốn đúng bằng số mục của nó.
func TestRateLimit_BatchCostsProportionally(t *testing.T) {
	s := NewService(&fakeStore{keys: map[string]model.APIKey{}}, nil, 100)
	ctx := context.Background()

	k := &model.APIKey{ID: 10, RPSLimit: 10}

	// Batch đầu đúng bằng burst (10 mục): bucket đầy ngay sau khi tạo, phải lọt.
	if err := s.Allow(ctx, k, 10); err != nil {
		t.Fatalf("batch 10 mục đầu tiên (đúng bằng burst) phải lọt: %v", err)
	}

	// Batch thứ hai NGAY SAU ĐÓ phải bị chặn (bucket vừa cạn). Trước khi vá, lượt này vẫn lọt
	// vì Allow() cũ chỉ trừ 1 token bất kể units — đây chính là điều lỗi M1 cho phép.
	if err := s.Allow(ctx, k, 10); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("batch thứ 2 liền sau phải bị chặn (bucket đã cạn), got %v", err)
	}

	// Một đơn vị lẻ (units=1) ngay sau đó cũng phải bị chặn, vì bucket đang ở 0, không phải âm vô hạn.
	if err := s.Allow(ctx, k, 1); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("1 mục lẻ ngay sau khi bucket cạn cũng phải bị chặn, got %v", err)
	}

	// Batch LỚN HƠN rps_limit (100 mục, rps_limit=10): không bao giờ lọt, vì burst=rps_limit=10
	// nên bucket không bao giờ giữ đủ 100 token, dù chờ bao lâu. Đây là đánh đổi thiết kế đã biết.
	big := &model.APIKey{ID: 11, RPSLimit: 10}
	if err := s.Allow(ctx, big, 100); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("batch 100 mục với rps_limit=10 phải luôn bị chặn, got %v", err)
	}

	// Đối chứng: gọi 1-mục-mỗi-lần (hành vi cũ, không batch) không bị ảnh hưởng bởi thay đổi này.
	single := &model.APIKey{ID: 12, RPSLimit: 5}
	ok := 0

	for i := 0; i < 10; i++ {
		if s.Allow(ctx, single, 1) == nil {
			ok++
		}
	}

	if ok < 5 || ok > 6 {
		t.Fatalf("gọi 1 mục/lần không được bị ảnh hưởng: muốn ~5 lượt lọt, được %d", ok)
	}
}
