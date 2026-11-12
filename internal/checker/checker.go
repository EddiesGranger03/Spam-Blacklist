package checker

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/nyaruka/phonenumbers"
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
	// Region (tùy chọn, mã ISO 3166-1 alpha-2 như "VN", "US") dùng để hiểu số điện thoại viết dạng nội địa.
	// Rỗng = dùng DEFAULT_REGION của server. Số có dấu "+" không phụ thuộc trường này.
	Region string `json:"region,omitempty"`
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

// New tạo Checker với vùng mặc định, bộ lọc Bloom, cache, nguồn tra cứu DB và epoch.
func New(region string, f Filter, c cache.Cache, finder EntryFinder, e Epocher) *Checker {
	return &Checker{region: region, filter: f, cache: c, finder: finder, epoch: e}
}

// CacheSealer mã hóa giá trị cache để Redis không bao giờ giữ giá trị khớp dưới dạng rõ.
// *seal.Sealer thỏa mãn interface này.
type CacheSealer interface {
	Seal(plaintext, aad string) ([]byte, error)
	Open(blob []byte, aad string) (string, error)
}

const cacheAAD = "check-cache"

// SetCacheSealer bật việc mã hóa những gì checker ghi vào cache, và dùng chỉ mục blind có khóa
// (không dùng số điện thoại/URL gốc) trong khóa cache.
func (c *Checker) SetCacheSealer(cs CacheSealer) { c.sealer = cs }

type cached struct {
	Match *Match `json:"m"`
	// Exp: lúc entry khớp hết hạn. Cache hit sau thời điểm này bị bỏ qua để không trả kết quả "bị chặn" cho
	// một entry đã hết hạn (M7). Khóa cache chỉ đổi theo epoch (khi có thay đổi dữ liệu), còn hết hạn theo
	// thời gian thì không tạo thay đổi nào nên trước đây sai lệch kéo dài tới CACHE_TTL.
	Exp *time.Time `json:"x,omitempty"`
}

// ValidRegion: kiểm tra mã vùng có được thư viện số điện thoại hỗ trợ hay không (phân biệt hoa thường: "VN").
func ValidRegion(region string) bool {
	_, ok := supportedRegions[region]
	return ok
}

var supportedRegions = func() map[string]struct{} {
	m := map[string]struct{}{}
	for r := range phonenumbers.GetSupportedRegions() {
		m[r] = struct{}{}
	}

	return m
}()

// Check kiểm tra một giá trị có trong blacklist hay không: chuẩn hóa, lọc Bloom, cache, rồi tra DB nếu cần.
func (c *Checker) Check(ctx context.Context, typ normalize.Type, raw string) (Result, error) {
	return c.CheckRegion(ctx, typ, raw, "")
}

// CheckRegion giống Check nhưng cho phép client chỉ định vùng để hiểu số nội địa (M10). region rỗng = mặc định.
// Khóa cache dựa trên giá trị đã chuẩn hóa (E.164) nên không bị lẫn giữa các vùng.
func (c *Checker) CheckRegion(ctx context.Context, typ normalize.Type, raw, region string) (Result, error) {
	res := Result{Type: string(typ), Input: raw}

	if region == "" {
		region = c.region
	} else if region = strings.ToUpper(region); !ValidRegion(region) {
		metrics.CheckResult.WithLabelValues("invalid").Inc()
		return res, fmt.Errorf("%w: unknown region %q", ErrInvalidInput, region)
	}

	normalized, keys, err := normalize.Candidates(typ, raw, region)
	if err != nil {
		metrics.CheckResult.WithLabelValues("invalid").Inc()
		return res, err
	}

	res.Normalized = normalized

	maybe := make([]normalize.Key, 0, len(keys))

	for _, k := range keys {
		if c.filter.Test(uint64(k.Hash)) {  // #nosec G115 -- chủ ý: cùng bit pattern với hash đã lưu trong BIGINT
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
		if c.openCache(b, &cv) == nil && (cv.Exp == nil || cv.Exp.After(time.Now())) {
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

		m, exp := bestWithExpiry(entries)
		if b, err := c.sealCache(cached{Match: m, Exp: exp}); err == nil {
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

// finish điền kết quả (blacklisted hoặc safe) và tăng metric tương ứng.
func (c *Checker) finish(res Result, m *Match) Result {
	if m != nil {
		res.Blacklisted, res.Match = true, m
		metrics.CheckResult.WithLabelValues("blacklisted").Inc()
	} else {
		metrics.CheckResult.WithLabelValues("safe").Inc()
	}

	return res
}

// best chọn entry có risk cao nhất (hòa thì id nhỏ nhất) và chuyển thành Match.
func best(entries []model.Entry) *Match {
	m, _ := bestWithExpiry(entries)
	return m
}

// bestWithExpiry như best, nhưng trả thêm thời điểm hết hạn của entry được chọn.
func bestWithExpiry(entries []model.Entry) (*Match, *time.Time) {
	var top *model.Entry

	for i := range entries {
		e := &entries[i]
		if top == nil || e.RiskScore > top.RiskScore || (e.RiskScore == top.RiskScore && e.ID < top.ID) {
			top = e
		}
	}

	if top == nil {
		return nil, nil
	}

	return &Match{EntryID: top.ID, MatchType: top.MatchType, MatchedValue: top.Value,
		Category: top.Category, RiskScore: top.RiskScore}, top.ExpiresAt
}

// CheckBatch kiểm tra nhiều mục song song (tối đa 16 goroutine) và giữ nguyên thứ tự kết quả.
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
			out[i] = c.checkItem(ctx, it)
		}()
	}

	wg.Wait()
	return out
}

// checkItem xử lý đúng một mục của batch và không bao giờ để panic thoát ra ngoài.
//
// Vì sao cần: CheckBatch chạy mỗi mục trong goroutine riêng, mà chimw.Recoverer chỉ bắt panic ở
// goroutine của request. Trong Go, một panic không ai bắt ở BẤT KỲ goroutine nào sẽ kết thúc cả
// process, nên một đầu vào lạ làm một thư viện (phonenumbers, idna, publicsuffix...) panic sẽ đủ để
// một request vô danh sập cả server. Các mục của batch độc lập nhau (mỗi mục chỉ ghi vào ô kết quả
// của nó), nên cô lập lỗi theo từng mục là an toàn: mục lỗi trả "internal error", các mục còn lại
// vẫn có kết quả đúng.
//
// Cố ý KHÔNG dùng chung một helper "an toàn" cho mọi goroutine của dự án: mỗi nơi cần chính sách
// khác nhau (job import phải đánh dấu failed, vòng lặp nền nên khởi động lại hoặc để sập), xem
// docs/BAO_CAO_TONG_HOP.md.
func (c *Checker) checkItem(ctx context.Context, it Item) (out BatchResult) {
	defer func() {
		if r := recover(); r != nil {
			metrics.CheckPanics.Inc()
			// Không log it.Value: đó là số điện thoại/URL của khách. Type và stack là đủ để điều tra.
			slog.Error("panic khi kiểm tra một mục của batch; mục này trả internal error",
				"panic", fmt.Sprint(r), "type", it.Type, "stack", string(debug.Stack()))

			out = BatchResult{Result: Result{Type: it.Type, Input: it.Value}, Error: "internal error"}
		}
	}()

	res, err := c.CheckRegion(ctx, normalize.Type(it.Type), it.Value, it.Region)
	out = BatchResult{Result: res}

	if err != nil {
		if errors.Is(err, ErrInvalidInput) {
			out.Error = err.Error()
		} else {
			out.Error = "internal error"
		}
	}

	return out
}

// sealCache mã hóa giá trị cache bằng sealer (nếu có) trước khi ghi vào Redis.
func (c *Checker) sealCache(v cached) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil || c.sealer == nil {
		return b, err
	}

	return c.sealer.Seal(string(b), cacheAAD)
}

// openCache giải mã và parse giá trị cache đọc từ Redis.
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
