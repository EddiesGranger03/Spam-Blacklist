package handler

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"
	"github.com/prometheus/client_golang/prometheus"

	"vsf/internal/auth"
	"vsf/internal/config"
	"vsf/internal/model"
	"vsf/internal/seal"
	"vsf/internal/store"
)

const loginPass = "Correct-Horse-9"

// newLoginHandler dựng Handler thật với Postgres thật (TEST_DATABASE_URL, tên DB phải kết thúc bằng "_test").
// Dùng một database tạm riêng của gói (xem sharedDB), nên không đụng tới dữ liệu của DB test chung.
func newLoginHandler(t *testing.T) (*Handler, string) {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping integration test")
	}

	ctx := context.Background()

	if !strings.HasSuffix(dsnDBName(dsn), "_test") {
		t.Fatalf("TỪ CHỐI chạy: TEST_DATABASE_URL phải trỏ vào database có tên kết thúc bằng _test")
	}

	// Cả gói dùng chung MỘT database tạm (tạo và migrate một lần, xem sharedDB) để không dẫm chân lên các gói khác
	// dùng chung vsf_test: test của gói store dọn sạch mọi bảng của DB đó, có thể xóa mất admin giữa chừng.
	// Mỗi test vẫn cô lập vì dùng admin có email ngẫu nhiên và một Handler (cùng bộ đếm throttle) riêng.
	dsn = sharedDB(t, dsn)

	st, err := store.New(ctx, dsn, "", 4)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(st.Close)

	st.SetSealer(testSealer(t))

	hash := sharedPasswordHash(t)

	email := fmt.Sprintf("thr-%d@example.com", time.Now().UnixNano())
	if _, err := st.CreateAdmin(ctx, email, hash, model.RoleAdmin, model.Actor{Email: "test"}); err != nil {
		t.Fatal(err)
	}

	old := loginBackoff
	loginBackoff = func(int) time.Duration { return 0 } // test không chờ; việc làm chậm được kiểm riêng bên dưới

	t.Cleanup(func() { loginBackoff = old })

	h, err := New(Deps{Cfg: config.Config{TrustedProxies: mustCIDRs(t, "127.0.0.1"), SessionSecret: "test-session-secret-0123456789abcdef"}, Store: st})
	if err != nil {
		t.Fatal(err)
	}

	return h, email
}

var (
	sharedMu   sync.Mutex
	sharedDSN  string
	sharedDrop func()

	hashOnce sync.Once
	hashVal  string
	hashErr  error
)

// TestMain dọn database tạm dùng chung (nếu có test đã tạo nó) sau khi cả gói chạy xong.
func TestMain(m *testing.M) {
	code := m.Run()

	sharedMu.Lock()
	drop := sharedDrop
	sharedMu.Unlock()

	if drop != nil {
		drop()
	}

	os.Exit(code)
}

// testSealer tạo Sealer với khóa test.
func testSealer(t *testing.T) *seal.Sealer {
	t.Helper()

	sl, err := seal.New("k-0123456789012345678901234567890123", "p-0123456789012345678901234567890123", 1)
	if err != nil {
		t.Fatal(err)
	}

	return sl
}

// cheapPasswordHash tạo hash argon2id đúng định dạng của auth.HashPassword nhưng với tham số rẻ (8 KB, 1 vòng).
// VerifyPassword đọc tham số từ chính chuỗi hash nên vẫn xác minh đúng; test throttle gửi hàng chục lần đăng nhập
// nên với tham số thật (64 MB, 2 vòng) chỉ riêng argon2 đã chiếm phần lớn thời gian gói. Tham số thật được
// kiểm riêng ở gói auth, nên đây không làm yếu sản phẩm.
func cheapPasswordHash(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(password), salt, 1, 8, 1, 32)

	return fmt.Sprintf("$argon2id$v=%d$m=8,t=1,p=1$%s$%s", argon2.Version,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// sharedPasswordHash băm mật khẩu test đúng một lần cho cả gói (argon2 cố ý chậm, vài chục đến vài trăm mili giây).
func sharedPasswordHash(t *testing.T) string {
	t.Helper()

	hashOnce.Do(func() { hashVal, hashErr = cheapPasswordHash(loginPass) })

	if hashErr != nil {
		t.Fatal(hashErr)
	}

	return hashVal
}

// sharedDB trả về DSN của database tạm vsf_login_<nanos>_test, tạo và migrate ở lần gọi đầu tiên; TestMain xóa nó khi
// cả gói xong. Cần quyền CREATE DATABASE (có sẵn với user vsf của docker-compose); thiếu quyền thì test bị Skip kèm
// lý do chứ không đỏ.
func sharedDB(t *testing.T, dsn string) string {
	t.Helper()

	sharedMu.Lock()
	defer sharedMu.Unlock()

	if sharedDSN != "" {
		return sharedDSN
	}

	ctx := context.Background()

	// Kết nối vào DB bảo trì "postgres" chứ không phải vsf_test: câu CREATE/DROP DATABASE là một transaction đang mở
	// trên DB nó chạy, và sẽ làm hỏng các test của gói store đếm "transaction đang mở" trong vsf_test.
	base, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}

	maint := *base
	maint.Path = "/postgres"

	admin, err := pgxpool.New(ctx, maint.String())
	if err != nil {
		t.Fatal(err)
	}

	name := fmt.Sprintf("vsf_login_%d_test", time.Now().UnixNano())

	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close()

		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "42501" { // insufficient_privilege
			t.Skipf("user của TEST_DATABASE_URL không có quyền CREATE DATABASE; bỏ qua test đăng nhập (%v)", err)
		}

		t.Fatalf("create temp database: %v", err)
	}

	drop := func() {
		defer admin.Close()

		if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			fmt.Fprintf(os.Stderr, "drop temp database %s: %v\n", name, err)
		}
	}

	u := *base
	u.Path = "/" + name
	tmp := u.String()

	st, err := store.New(ctx, tmp, "", 4)
	if err != nil {
		drop()
		t.Fatal(err)
	}

	st.SetSealer(testSealer(t))

	err = st.Migrate(ctx)
	st.Close()

	if err != nil {
		drop()
		t.Fatalf("migrate: %v", err)
	}

	sharedDSN, sharedDrop = tmp, drop

	return sharedDSN
}

// dsnDBName lấy tên database từ DSN.
func dsnDBName(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return ""
	}

	return strings.TrimPrefix(u.Path, "/")
}

// mustCIDRs phân tích CIDR cho test, báo lỗi test nếu sai.
func mustCIDRs(t *testing.T, s string) []*net.IPNet {
	t.Helper()

	n, err := config.ParseCIDRs(s)
	if err != nil {
		t.Fatal(err)
	}

	return n
}

// loginWith như login nhưng gửi kèm cookie và trả cả response để đọc Set-Cookie.
func loginWith(h *Handler, ip, email, password string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	form := url.Values{"email": {email}, "password": {password}}
	r := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Forwarded-For", ip)
	r.RemoteAddr = "127.0.0.1:5555"

	for _, c := range cookies {
		r.AddCookie(c)
	}

	w := httptest.NewRecorder()
	h.loginSubmit(w, r)

	return w
}

// login gửi một POST /admin/login như thể đi qua reverse proxy 127.0.0.1 với IP client là ip.
func login(h *Handler, ip, email, password string) int {
	form := url.Values{"email": {email}, "password": {password}}
	r := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Forwarded-For", ip)
	r.RemoteAddr = "127.0.0.1:5555"

	w := httptest.NewRecorder()
	h.loginSubmit(w, r)

	return w.Code
}

// Người ngoài sai mật khẩu nhiều lần từ IP của họ không được khóa admin khi admin đăng nhập từ IP khác.
func TestLoginThrottleAttackerCannotLockOutVictim(t *testing.T) {
	h, email := newLoginHandler(t)

	for i := 1; i <= 5; i++ {
		if c := login(h, "198.51.100.1", email, "bad"); c != http.StatusUnauthorized {
			t.Fatalf("attempt %d: got %d want 401", i, c)
		}
	}

	if c := login(h, "198.51.100.1", email, "bad"); c != http.StatusTooManyRequests {
		t.Fatalf("attacker 6th attempt: got %d want 429", c)
	}

	if c := login(h, "198.51.100.1", email, loginPass); c != http.StatusTooManyRequests {
		t.Fatalf("attacker IP stays locked even with the right password: got %d want 429", c)
	}

	if c := login(h, "198.51.100.2", email, loginPass); c != http.StatusSeeOther {
		t.Fatalf("victim from another IP must still log in: got %d want 303", c)
	}
}

// Dò mật khẩu phân tán từ nhiều IP vẫn bị giới hạn rộng theo email chặn lại.
func TestLoginThrottleDistributedGuessingHitsEmailCap(t *testing.T) {
	h, email := newLoginHandler(t)

	for i := 1; i <= 30; i++ {
		if c := login(h, fmt.Sprintf("203.0.113.%d", i), email, "bad"); c != http.StatusUnauthorized {
			t.Fatalf("attempt %d from its own IP: got %d want 401", i, c)
		}
	}

	if c := login(h, "203.0.113.200", email, "bad"); c != http.StatusTooManyRequests {
		t.Fatalf("31st attempt from a fresh IP: got %d want 429", c)
	}
}

// Đăng nhập đúng xóa bộ đếm của cặp email|IP đó.
func TestLoginSuccessResetsPairCounter(t *testing.T) {
	h, email := newLoginHandler(t)

	for i := 0; i < 4; i++ {
		login(h, "192.0.2.7", email, "bad")
	}

	if c := login(h, "192.0.2.7", email, loginPass); c != http.StatusSeeOther {
		t.Fatalf("right password after 4 failures: got %d want 303", c)
	}

	for i := 1; i <= 4; i++ {
		if c := login(h, "192.0.2.7", email, "bad"); c != http.StatusUnauthorized {
			t.Fatalf("after reset, failure %d: got %d want 401", i, c)
		}
	}
}

// Người dùng thật đã có thiết bị tin cậy vẫn vào được khi kẻ tấn công đã dò quá ngưỡng từ nhiều IP.
func TestTrustedDeviceSurvivesDistributedGuessing(t *testing.T) {
	h, email := newLoginHandler(t)

	first := loginWith(h, "198.51.100.10", email, loginPass)
	if first.Code != http.StatusSeeOther {
		t.Fatalf("first login: %d", first.Code)
	}

	var device *http.Cookie

	for _, c := range first.Result().Cookies() {
		if c.Name == "vsf_device" {
			device = c
		}
	}

	if device == nil || !device.HttpOnly {
		t.Fatalf("a successful login must set an HttpOnly device cookie, got %+v", device)
	}

	for i := 1; i <= 30; i++ {
		login(h, fmt.Sprintf("203.0.113.%d", i), email, "bad")
	}

	if c := login(h, "203.0.113.250", email, loginPass); c != http.StatusTooManyRequests {
		t.Fatalf("a device without the cookie must be locked by the email cap: got %d", c)
	}

	if c := loginWith(h, "198.51.100.77", email, loginPass, device).Code; c != http.StatusSeeOther {
		t.Fatalf("trusted device must still log in: got %d want 303", c)
	}

	// cookie của người khác / giả / hết hạn không có tác dụng
	forged := &http.Cookie{Name: "vsf_device", Value: "1.deadbeef"}
	if c := loginWith(h, "198.51.100.78", email, loginPass, forged).Code; c != http.StatusTooManyRequests {
		t.Fatalf("forged device cookie must not bypass the cap: got %d", c)
	}
}

// Sai mật khẩu vẫn bị từ chối dù thiết bị tin cậy: cookie chỉ miễn giới hạn, không thay mật khẩu.
func TestTrustedDeviceStillNeedsThePassword(t *testing.T) {
	h, email := newLoginHandler(t)

	device := &http.Cookie{Name: "vsf_device", Value: auth.SignDevice(h.Cfg.SessionSecret, email, time.Now())}
	if c := loginWith(h, "198.51.100.30", email, "wrong", device).Code; c != http.StatusUnauthorized {
		t.Fatalf("wrong password with a valid device cookie: got %d want 401", c)
	}
}

// TestLoginBackoffSlowsUnknownDevicesOnly kiểm tra backoff chỉ làm chậm các thiết bị lạ.
func TestLoginBackoffSlowsUnknownDevicesOnly(t *testing.T) {
	h, email := newLoginHandler(t)

	// Đếm số lần hàm làm chậm được gọi thay vì đo thời gian: băm mật khẩu argon2 lúc máy tải nặng tốn cả giây, nên
	// một ngưỡng thời gian tuyệt đối sẽ đỏ giả. Chiều "bị làm chậm" vẫn đo thời gian vì đó là cận dưới (luôn đúng).
	var calls atomic.Int32

	loginBackoff = func(failures int) time.Duration {
		calls.Add(1)

		if failures >= loginAlertAfter {
			return 200 * time.Millisecond
		}

		return 0
	}

	for i := 1; i <= loginAlertAfter; i++ {
		login(h, fmt.Sprintf("192.0.2.%d", i), email, "bad")
	}

	calls.Store(0)

	start := time.Now()
	login(h, "192.0.2.100", email, "bad")

	if d := time.Since(start); d < 200*time.Millisecond || calls.Load() != 1 {
		t.Fatalf("an unknown device must wait after %d failures: took %s, backoff consulted %d times", loginAlertAfter, d, calls.Load())
	}

	device := &http.Cookie{Name: "vsf_device", Value: auth.SignDevice(h.Cfg.SessionSecret, email, time.Now())}

	calls.Store(0)

	if code := loginWith(h, "192.0.2.101", email, loginPass, device).Code; code != http.StatusSeeOther {
		t.Fatalf("a trusted device with the right password must log in: %d", code)
	}

	if calls.Load() != 0 {
		t.Fatalf("a trusted device must skip the backoff entirely, but it was consulted %d times", calls.Load())
	}
}

// TestLoginAttackAlertFiresOnce kiểm tra cảnh báo tấn công đăng nhập chỉ báo một lần.
func TestLoginAttackAlertFiresOnce(t *testing.T) {
	h, email := newLoginHandler(t)
	before := counterValue(t, "vsf_login_attack_suspected_total")

	for i := 1; i <= loginAlertAfter+5; i++ {
		login(h, fmt.Sprintf("192.0.2.%d", i), email, "bad")
	}

	if got := counterValue(t, "vsf_login_attack_suspected_total") - before; got != 1 {
		t.Fatalf("alert counter must rise exactly once per email crossing the threshold, rose by %v", got)
	}
}

// counterValue đọc giá trị hiện tại của một metric counter theo tên.
func counterValue(t *testing.T, name string) float64 {
	t.Helper()

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}

	for _, mf := range families {
		if mf.GetName() == name {
			if ms := mf.GetMetric(); len(ms) > 0 {
				return ms[0].GetCounter().GetValue()
			}
		}
	}

	return 0
}
