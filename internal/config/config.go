package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config: Chứa toàn bộ cấu hình hệ thống được nạp từ biến môi trường.
type Config struct {
	AppEnv   string
	HTTPAddr string

	DatabaseURL     string
	ReadDatabaseURL string
	PGMaxConns      int

	RedisAddr     string
	RedisPassword string
	CacheTTL      time.Duration

	// TrustedProxies: các mạng (CIDR) của reverse proxy được phép khai báo IP client qua X-Forwarded-For.
	// Rỗng = không tin header nào, dùng RemoteAddr.
	TrustedProxies []*net.IPNet

	// NoProxy: xác nhận rõ ràng là chạy không qua reverse proxy (TRUSTED_PROXIES_NONE=true).
	// Ở production, phải đặt TRUSTED_PROXIES hoặc cờ này để tránh quên cấu hình.
	NoProxy bool

	// MetricsToken: bearer token cho /metrics. Rỗng = chỉ cho phép gọi từ loopback.
	MetricsToken string

	SessionSecret  string
	CookieSecure   bool
	BootstrapEmail string
	BootstrapPass  string

	AuthDisabled bool

	// AuditKey là khóa HMAC dùng để nối chuỗi hash cho bảng audit_logs.
	// Nếu để rỗng, store sẽ tự dẫn xuất từ SessionSecret (khi đổi SessionSecret sẽ làm hỏng
	// việc xác minh các bản ghi cũ, do đó nên đặt khóa riêng).
	AuditKey string

	// DataKey và DataPepper bảo vệ dữ liệu blacklist ở trạng thái lưu trữ (xem internal/seal).
	// Cả hai đều bắt buộc. Mất một trong hai sẽ khiến dữ liệu đã lưu không thể đọc được.
	DataKey        string
	DataPepper     string
	DataKeyVersion int

	// DataKeysRetired lưu trữ các khóa cũ theo phiên bản tương ứng từ các biến DATA_KEY_V<n>.
	// Chúng chỉ dùng để ĐỌC dữ liệu cũ chưa được re-encrypt; dữ liệu mới luôn mã hóa bằng DataKey ở DataKeyVersion.
	DataKeysRetired map[int16]string

	// InspectorShowSource cho phép Live Inspector hiển thị mã nguồn handler trong giao diện admin.
	// Mặc định bật ở development và tắt ở production.
	InspectorShowSource bool

	DefaultRegion string

	BloomExpectedItems   uint64
	BloomRebuildInterval time.Duration // Deprecated: không còn dùng; filter làm mới qua snapshot (FILTER_SNAPSHOT_INTERVAL)
	// PollInterval (POLL_INTERVAL, mặc định 1s): chu kỳ poll change_log khi KHÔNG có Redis Pub/Sub (không cấu hình
	// hoặc mất kết nối). Khi đang subscribe Redis, feed được đánh thức bởi message và chỉ poll an toàn mỗi
	// SafetyPollInterval (SAFETY_POLL_INTERVAL, mặc định 30s) để phòng message bị mất.
	PollInterval       time.Duration
	SafetyPollInterval time.Duration
	SyncChannel        string // SYNC_CHANNEL, mặc định "vsf:changes"

	// Filter snapshot (package snapshot): leader dựng định kỳ, các pod nạp snapshot thay vì quét bảng.
	FilterSnapshotInterval time.Duration // FILTER_SNAPSHOT_INTERVAL, mặc định 1h
	FilterSnapshotPoll     time.Duration // FILTER_SNAPSHOT_POLL, mặc định 30s: chu kỳ tìm snapshot mới / bầu leader
	FilterSnapshotKeep     int           // FILTER_SNAPSHOT_KEEP, mặc định 3
	FilterBootstrapTimeout time.Duration // FILTER_BOOTSTRAP_TIMEOUT, mặc định 10m: pod chờ leader quá lâu thì log lỗi
	FilterScanBatch        int           // FILTER_SCAN_BATCH, mặc định 5000 dòng/trang khi quét, tối đa 5000 (nhỏ để mỗi query nhẹ cho DB)
	FilterScanPause        time.Duration // FILTER_SCAN_PAUSE, mặc định 2ms nghỉ giữa các trang
	FilterRetryBase        time.Duration // FILTER_RETRY_BASE, mặc định 5s: chờ sau lần dựng/lưu snapshot lỗi đầu tiên (gấp đôi mỗi lần)
	FilterRetryMax         time.Duration // FILTER_RETRY_MAX, mặc định 10m: trần của thời gian chờ đó
	FilterVerifyInterval   time.Duration // FILTER_VERIFY_INTERVAL, mặc định 1m: chu kỳ kiểm tra âm tính giả (0 = tắt)
	FilterVerifySample     int           // FILTER_VERIFY_SAMPLE, mặc định 1000 hash mỗi chu kỳ
	// F10: leader dựng snapshot sớm khi lớp delta/removed phình (vd import lớn giữa hai lần snapshot).
	FilterDeltaRebuildRatio float64       // FILTER_DELTA_REBUILD_RATIO, mặc định 0.7 (số phần tử delta / sức chứa thiết kế; <0 = tắt)
	FilterRemovedRebuildMax int64         // FILTER_REMOVED_REBUILD_MAX, mặc định 1000000 hash trong removed-set (<0 = tắt)
	FilterMinRebuildGap     time.Duration // FILTER_MIN_REBUILD_GAP, mặc định 5m: khoảng cách tối thiểu giữa hai lần dựng sớm

	RateLimitRPS int
}

// Load: Đọc cấu hình từ các biến môi trường, gán giá trị mặc định và kiểm tra tính hợp lệ.
func Load() (Config, error) {
	bloomItems := getenvInt("BLOOM_EXPECTED_ITEMS", 10_000_000)
	if err := checkPositive("BLOOM_EXPECTED_ITEMS", bloomItems, math.MaxInt32); err != nil {
		return Config{}, err
	}

	c := Config{
		AppEnv:               getenv("APP_ENV", "development"),
		HTTPAddr:             getenv("HTTP_ADDR", "127.0.0.1:8080"),
		DatabaseURL:          getenv("DATABASE_URL", "postgres://vsf:vsf@localhost:5433/vsf?sslmode=disable"),
		ReadDatabaseURL:      getenv("READ_DATABASE_URL", ""),
		PGMaxConns:           getenvInt("PG_MAX_CONNS", 32),
		RedisAddr:            getenv("REDIS_ADDR", ""),
		CacheTTL:             getenvDuration("CACHE_TTL", 10*time.Minute),
		SessionSecret:        getenv("SESSION_SECRET", ""),
		CookieSecure:         getenvBool("COOKIE_SECURE", false),
		BootstrapEmail:       getenv("BOOTSTRAP_ADMIN_EMAIL", ""),
		BootstrapPass:        getenv("BOOTSTRAP_ADMIN_PASSWORD", ""),
		AuthDisabled:         getenvBool("AUTH_DISABLED", false),
		DefaultRegion:        strings.ToUpper(getenv("DEFAULT_REGION", "VN")),
		BloomExpectedItems:   uint64(bloomItems), // #nosec G115 -- bloomItems đã được kiểm tra 1..MaxInt32 ở trên
		BloomRebuildInterval: getenvDuration("BLOOM_REBUILD_INTERVAL", 24*time.Hour),
		PollInterval:         getenvDuration("POLL_INTERVAL", time.Second),
		SafetyPollInterval:   getenvDuration("SAFETY_POLL_INTERVAL", 30*time.Second),
		SyncChannel:          getenv("SYNC_CHANNEL", "vsf:changes"),

		FilterSnapshotInterval:  getenvDuration("FILTER_SNAPSHOT_INTERVAL", time.Hour),
		FilterSnapshotPoll:      getenvDuration("FILTER_SNAPSHOT_POLL", 30*time.Second),
		FilterSnapshotKeep:      getenvInt("FILTER_SNAPSHOT_KEEP", 3),
		FilterBootstrapTimeout:  getenvDuration("FILTER_BOOTSTRAP_TIMEOUT", 10*time.Minute),
		FilterScanBatch:         getenvInt("FILTER_SCAN_BATCH", 5000),
		FilterScanPause:         getenvDuration("FILTER_SCAN_PAUSE", 2*time.Millisecond),
		FilterRetryBase:         getenvDuration("FILTER_RETRY_BASE", 5*time.Second),
		FilterRetryMax:          getenvDuration("FILTER_RETRY_MAX", 10*time.Minute),
		FilterVerifyInterval:    getenvDuration("FILTER_VERIFY_INTERVAL", time.Minute),
		FilterVerifySample:      getenvInt("FILTER_VERIFY_SAMPLE", 1000),
		FilterDeltaRebuildRatio: getenvFloat("FILTER_DELTA_REBUILD_RATIO", 0.7),
		FilterRemovedRebuildMax: int64(getenvInt("FILTER_REMOVED_REBUILD_MAX", 1_000_000)),
		FilterMinRebuildGap:     getenvDuration("FILTER_MIN_REBUILD_GAP", 5*time.Minute),

		RateLimitRPS: getenvInt("RATE_LIMIT_RPS", 100),
	}
	c.RedisPassword = getenv("REDIS_PASSWORD", "")
	c.MetricsToken = getenv("METRICS_TOKEN", "")

	proxies, err := ParseCIDRs(getenv("TRUSTED_PROXIES", ""))
	if err != nil {
		return c, err
	}

	c.TrustedProxies = proxies
	c.NoProxy = getenvBool("TRUSTED_PROXIES_NONE", false)
	if err := checkPositive("PG_MAX_CONNS", c.PGMaxConns, 1000); err != nil {
		return c, err
	}
	if err := checkPositive("RATE_LIMIT_RPS", c.RateLimitRPS, math.MaxInt32); err != nil {
		return c, err
	}
	c.AuditKey = getenv("AUDIT_HMAC_KEY", "")
	c.DataKey = getenv("DATA_KEY", "")
	c.DataPepper = getenv("DATA_PEPPER", "")
	c.DataKeyVersion = getenvInt("DATA_KEY_VERSION", 1)
	c.InspectorShowSource = getenvBool("INSPECTOR_SHOW_SOURCE", c.AppEnv == "development")

	retired, err := retiredDataKeys(os.Environ())
	if err != nil {
		return c, err
	}

	c.DataKeysRetired = retired

	return c, c.validate()
}

// ParseCIDRs: đọc danh sách CIDR hoặc IP đơn, phân cách bằng dấu phẩy.
func ParseCIDRs(list string) ([]*net.IPNet, error) {
	var out []*net.IPNet

	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}

		if !strings.Contains(item, "/") {
			ip := net.ParseIP(item)
			if ip == nil {
				return nil, fmt.Errorf("TRUSTED_PROXIES: %q không phải IP hoặc CIDR hợp lệ", item)
			}

			if ip.To4() != nil {
				item += "/32"
			} else {
				item += "/128"
			}
		}

		_, n, err := net.ParseCIDR(item)
		if err != nil {
			return nil, fmt.Errorf("TRUSTED_PROXIES: %q không phải IP hoặc CIDR hợp lệ", item)
		}

		out = append(out, n)
	}

	return out, nil
}

var retiredKeyVar = regexp.MustCompile(`^DATA_KEY_V(\d+)$`)

// retiredDataKeys: Thu thập các biến môi trường dạng DATA_KEY_V<n> để nạp danh sách khóa cũ.
func retiredDataKeys(environ []string) (map[int16]string, error) {
	out := map[int16]string{}

	for _, kv := range environ {
		name, value, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}

		m := retiredKeyVar.FindStringSubmatch(strings.ToUpper(name))
		if m == nil {
			continue
		}

		n, err := strconv.Atoi(m[1])
		if err != nil || n < 1 || n > math.MaxInt16 {
			return nil, fmt.Errorf("%s: phiên bản khóa phải là số từ 1 đến %d", name, math.MaxInt16)
		}

		if value == "" {
			continue // Biến rỗng tương đương với chưa thiết lập
		}

		if _, dup := out[int16(n)]; dup { // #nosec G109 G115 -- n đã được kiểm tra 1..MaxInt16 ở đoạn trên
			return nil, fmt.Errorf("%s bị khai báo hai lần", name)
		}

		out[int16(n)] = value // #nosec G109 G115 -- n đã được kiểm tra 1..MaxInt16 ở đoạn trên
	}

	return out, nil
}

// validate: Kiểm tra tính hợp lệ và các ràng buộc bảo mật bắt buộc của toàn bộ cấu hình.
func (c Config) validate() error {
	if c.AppEnv != "development" && c.AppEnv != "production" {
		return fmt.Errorf("APP_ENV phải là development hoặc production, nhận được %q", c.AppEnv)
	}

	if c.SessionSecret == "" {
		return fmt.Errorf("SESSION_SECRET là bắt buộc")
	}

	if c.AppEnv == "production" {
		if len(c.SessionSecret) < 32 {
			return fmt.Errorf("SESSION_SECRET phải có ít nhất 32 ký tự ở môi trường production")
		}

		if !c.CookieSecure {
			return fmt.Errorf("COOKIE_SECURE phải là true ở môi trường production")
		}

		if c.AuthDisabled {
			return fmt.Errorf("AUTH_DISABLED không được phép bật ở môi trường production")
		}

		// Quên TRUSTED_PROXIES sau reverse proxy làm mọi client có chung IP của proxy
		// (throttle đăng nhập và rate limit gộp chung), nên bắt buộc khai báo rõ ràng.
		switch {
		case len(c.TrustedProxies) == 0 && !c.NoProxy:
			return fmt.Errorf("production yêu cầu đặt TRUSTED_PROXIES (CIDR của reverse proxy) hoặc TRUSTED_PROXIES_NONE=true nếu chạy không qua proxy")
		case len(c.TrustedProxies) > 0 && c.NoProxy:
			return fmt.Errorf("TRUSTED_PROXIES và TRUSTED_PROXIES_NONE=true mâu thuẫn nhau, chỉ đặt một trong hai")
		}

		for name, dsn := range map[string]string{"DATABASE_URL": c.DatabaseURL, "READ_DATABASE_URL": c.ReadDatabaseURL} {
			if dsn != "" && !dbTLSEnforced(dsn) {
				return fmt.Errorf("%s bắt buộc phải sử dụng sslmode=require, verify-ca hoặc verify-full ở production", name)
			}
		}
	}

	// Token metrics quá ngắn dễ bị dò; rỗng vẫn hợp lệ (khi đó /metrics chỉ nhận loopback).
	if c.MetricsToken != "" && len(c.MetricsToken) < 16 {
		return fmt.Errorf("METRICS_TOKEN phải có ít nhất 16 ký tự (hoặc để rỗng để chỉ cho phép loopback)")
	}

	if len(c.DataKey) < 32 || len(c.DataPepper) < 32 {
		return fmt.Errorf("DATA_KEY và DATA_PEPPER là bắt buộc và mỗi khóa phải có ít nhất 32 ký tự")
	}

	if c.DataKey == c.DataPepper {
		return fmt.Errorf("DATA_KEY và DATA_PEPPER phải là hai chuỗi khác nhau")
	}

	// Phiên bản khóa được lưu dưới dạng SMALLINT trong DB: nếu vượt quá MaxInt16 sẽ bị cắt ngắn gây lỗi dữ liệu.
	if c.DataKeyVersion < 1 || c.DataKeyVersion > math.MaxInt16 {
		return fmt.Errorf("DATA_KEY_VERSION phải là số từ 1 đến %d, nhận được %d", math.MaxInt16, c.DataKeyVersion)
	}

	if c.AuthDisabled && !isLoopbackAddr(c.HTTPAddr) {
		return fmt.Errorf("AUTH_DISABLED yêu cầu HTTP_ADDR phải gắn vào localhost, nhận được %q", c.HTTPAddr)
	}

	return nil
}

// dbTLSEnforced: Kiểm tra xem chuỗi kết nối Postgres (DSN) có bắt buộc dùng kết nối mã hóa TLS hay không.
func dbTLSEnforced(dsn string) bool {
	mode := ""

	if strings.Contains(dsn, "://") {
		if u, err := url.Parse(dsn); err == nil {
			mode = u.Query().Get("sslmode")
		}
	} else {
		for _, kv := range strings.Fields(dsn) {
			if v, ok := strings.CutPrefix(kv, "sslmode="); ok {
				mode = v
			}
		}
	}

	switch mode {
	case "require", "verify-ca", "verify-full":
		return true
	}

	return false
}

// isLoopbackAddr: Kiểm tra xem địa chỉ IP/host được cấu hình có phải là localhost/loopback hay không.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}

	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkPositive: Kiểm tra một cấu hình số nằm trong khoảng 1..max; báo lỗi nêu rõ tên biến khi sai.
func checkPositive(name string, v, max int) error {
	if v < 1 || v > max {
		return fmt.Errorf("%s phải nằm trong khoảng 1 đến %d, nhận được %d", name, max, v)
	}

	return nil
}

// getenv: Lấy giá trị biến môi trường kiểu chuỗi, trả về giá trị mặc định nếu biến rỗng.
func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return def
}

// getenvInt: Lấy giá trị biến môi trường kiểu số nguyên, trả về giá trị mặc định nếu không hợp lệ.
func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}

	return def
}

// getenvFloat: Lấy giá trị biến môi trường kiểu số thực, trả về giá trị mặc định nếu không hợp lệ.
func getenvFloat(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}

	return def
}

// getenvBool: Lấy giá trị biến môi trường kiểu boolean, trả về giá trị mặc định nếu không hợp lệ.
func getenvBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}

	return def
}

// getenvDuration: Lấy giá trị biến môi trường kiểu thời lượng (time.Duration), trả về giá trị mặc định nếu không hợp lệ.
func getenvDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}

	return def
}

// Warnings: các cảnh báo cấu hình không chặn khởi động nhưng nên được người vận hành biết.
func (c Config) Warnings() []string {
	var out []string

	if c.AppEnv == "production" && c.MetricsToken == "" {
		out = append(out, "METRICS_TOKEN chưa đặt: /metrics chỉ nhận request từ loopback, hệ thống giám sát bên ngoài sẽ không thu thập được")
	}

	return out
}

// KeyFingerprint: vân tay ngắn (8 byte đầu của SHA-256, dạng hex) của một khóa để đối chiếu với nơi lưu khóa
// mà không làm lộ khóa. Khóa rỗng trả về chuỗi rỗng.
func KeyFingerprint(key string) string {
	if key == "" {
		return ""
	}

	sum := sha256.Sum256([]byte(key))

	return hex.EncodeToString(sum[:8])
}
