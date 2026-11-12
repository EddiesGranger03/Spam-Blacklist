package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"vsf/internal/apikey"
	"vsf/internal/bloom"
	"vsf/internal/changefeed"
	"vsf/internal/config"
	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/seal"
	"vsf/internal/store"
)

var (
	tplOnce sync.Once
	tplName string
	tplErr  error
)

// migratedTemplate tạo (một lần cho cả process test) một database mẫu đã Migrate với đúng khóa mà các test dùng.
// TestMain xóa nó khi xong.
func migratedTemplate(ctx context.Context, base string) (string, error) {
	tplOnce.Do(func() {
		u, err := url.Parse(base)
		if err != nil {
			tplErr = err
			return
		}

		admin, err := pgxpool.New(ctx, base)
		if err != nil {
			tplErr = err
			return
		}

		defer admin.Close()

		name := fmt.Sprintf("vsf_srv_tpl_%d_test", time.Now().UnixNano())
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+name); err != nil {
			tplErr = err
			return
		}

		tplName = name
		u.Path = "/" + name

		st, err := store.New(ctx, u.String(), "", 2)
		if err != nil {
			tplErr = err
			return
		}

		defer st.Close() // phải đóng hết kết nối thì mới dùng làm TEMPLATE được

		sl, err := seal.New("0123456789abcdef0123456789abcdef-data", "fedcba9876543210fedcba9876543210-pepper", 1)
		if err != nil {
			tplErr = err
			return
		}

		st.SetSealer(sl)
		st.SetAuditKey(store.AuditKeyFrom("", "server-test-secret-0123456789"))
		tplErr = st.Migrate(ctx)
	})

	return tplName, tplErr
}

func TestMain(m *testing.M) {
	code := m.Run()

	if tplName != "" {
		if admin, err := pgxpool.New(context.Background(), os.Getenv("TEST_DATABASE_URL")); err == nil {
			_, _ = admin.Exec(context.Background(), `DROP DATABASE IF EXISTS `+tplName+` WITH (FORCE)`)
			admin.Close()
		}
	}

	os.Exit(code)
}

// testStore tạo một database RIÊNG (tên _test) và một Store đã Migrate; xóa database khi xong.
func testStore(t *testing.T) (*store.Store, string) {
	t.Helper()

	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping integration test")
	}

	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}

	name := fmt.Sprintf("vsf_srv_%d_test", time.Now().UnixNano())
	ctx := context.Background()

	admin, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatal(err)
	}

	tpl, err := migratedTemplate(ctx, base)
	if err != nil {
		admin.Close()
		t.Fatal(err)
	}

	// Sao chép từ bản mẫu đã Migrate (vài trăm ms) thay vì Migrate lại từ đầu (vài giây: tạo 2 lần 32 partition).
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+name+` TEMPLATE `+tpl); err != nil {
		admin.Close()
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`)
		admin.Close()
	})

	u.Path = "/" + name
	dsn := u.String()

	st, err := store.New(ctx, dsn, "", 4)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(st.Close)

	sl, err := seal.New("0123456789abcdef0123456789abcdef-data", "fedcba9876543210fedcba9876543210-pepper", 1)
	if err != nil {
		t.Fatal(err)
	}

	st.SetSealer(sl)
	st.SetAuditKey(store.AuditKeyFrom("", "server-test-secret-0123456789"))

	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	return st, dsn
}

func TestBootstrapAdmin(t *testing.T) {
	st, _ := testStore(t)
	ctx := context.Background()
	log := quietLog()

	// chưa cấu hình thông tin: chỉ cảnh báo, không tạo gì
	if err := bootstrapAdmin(ctx, st, config.Config{}, log); err != nil {
		t.Fatal(err)
	}

	if n, _ := st.CountAdmins(ctx); n != 0 {
		t.Fatalf("no credentials configured: %d admins created", n)
	}

	// mật khẩu quá ngắn: lỗi rõ ràng, không tạo
	if err := bootstrapAdmin(ctx, st, config.Config{BootstrapEmail: "a@b.c", BootstrapPass: "short"}, log); err == nil ||
		!strings.Contains(err.Error(), "quá ngắn") {
		t.Fatalf("short password: %v", err)
	}

	if n, _ := st.CountAdmins(ctx); n != 0 {
		t.Fatalf("a short password must not create an admin: %d", n)
	}

	cfg := config.Config{BootstrapEmail: "first@example.com", BootstrapPass: "ChangeMe-12345"}
	if err := bootstrapAdmin(ctx, st, cfg, log); err != nil {
		t.Fatal(err)
	}

	a, err := st.GetAdminByEmail(ctx, "first@example.com")
	if err != nil || a.Role != "admin" || a.PasswordHash == "" || strings.Contains(a.PasswordHash, "ChangeMe") {
		t.Fatalf("bootstrap admin: %+v %v", a, err)
	}

	// đã có admin: chạy lại không tạo thêm và không đổi gì, kể cả với thông tin khác
	if err := bootstrapAdmin(ctx, st, config.Config{BootstrapEmail: "second@example.com", BootstrapPass: "AnotherPass-123"}, log); err != nil {
		t.Fatal(err)
	}

	if n, _ := st.CountAdmins(ctx); n != 1 {
		t.Fatalf("must stay at one admin, got %d", n)
	}
}

// Các vòng nền chạy theo chu kỳ, dừng khi context bị hủy, và một lỗi ở một vòng không làm vòng khác dừng.
func TestBackgroundJobsRunAndStop(t *testing.T) {
	st, _ := testStore(t)

	oldFlush, oldPurge := flushEvery, purgeEvery
	flushEvery, purgeEvery = 30*time.Millisecond, 30*time.Millisecond

	t.Cleanup(func() { flushEvery, purgeEvery = oldFlush, oldPurge })

	log := quietLog()
	bm := bloom.NewManager()
	feed := changefeed.New(st, bm, log)

	if err := feed.Init(context.Background(), 1000); err != nil {
		t.Fatal(err)
	}

	keys := apikey.NewService(st, nil, 100)
	cfg := config.Config{BloomExpectedItems: 1000, BloomRebuildInterval: 40 * time.Millisecond}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		backgroundJobs(ctx, log, st, feed, keys, cfg)
		close(done)
	}()

	time.Sleep(300 * time.Millisecond) // vài chu kỳ flush, purge và rebuild

	if !bm.Ready() {
		t.Fatal("the Bloom filter must stay ready while it is rebuilt")
	}

	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("backgroundJobs must return when its context is cancelled")
	}
}

// run dừng sớm với lỗi rõ ràng khi cấu hình hoặc database sai, thay vì treo hay panic.
func TestRunFailsFastOnBadConfiguration(t *testing.T) {
	t.Setenv("SESSION_SECRET", "")

	if err := run(quietLog()); err == nil || !strings.Contains(err.Error(), "SESSION_SECRET") {
		t.Fatalf("missing SESSION_SECRET: %v", err)
	}

	t.Setenv("SESSION_SECRET", "server-test-secret-0123456789")
	t.Setenv("DATA_KEY", "0123456789abcdef0123456789abcdef-data")
	t.Setenv("DATA_PEPPER", "fedcba9876543210fedcba9876543210-pepper")
	t.Setenv("DATABASE_URL", "postgres://vsf:wrong@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")

	if err := run(quietLog()); err == nil {
		t.Fatal("an unreachable database must be an error")
	}
}

// serve khởi động thật (migrate, bootstrap admin, Bloom, changefeed, HTTP), phục vụ request, và tắt êm khi ctx bị hủy.
func TestServeStartsServesAndShutsDown(t *testing.T) {
	_, dsn := testStore(t) // database riêng đã Migrate

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	addr := l.Addr().String()
	_ = l.Close()

	for k, v := range map[string]string{
		"APP_ENV": "development", "HTTP_ADDR": addr, "DATABASE_URL": dsn, "SESSION_SECRET": "server-test-secret-0123456789",
		"DATA_KEY": "0123456789abcdef0123456789abcdef-data", "DATA_PEPPER": "fedcba9876543210fedcba9876543210-pepper",
		"BOOTSTRAP_ADMIN_EMAIL": "boot@example.com", "BOOTSTRAP_ADMIN_PASSWORD": "ChangeMe-12345", "POLL_INTERVAL": "50ms",
		"REDIS_ADDR": "", "AUTH_DISABLED": "false",
	} {
		t.Setenv(k, v)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errc := make(chan error, 1)

	go func() { errc <- serve(ctx, cancel, quietLog()) }()

	deadline := time.Now().Add(15 * time.Second)

	for {
		resp, err := http.Get("http://" + addr + "/readyz")
		if err == nil {
			ok := resp.StatusCode == 200
			_ = resp.Body.Close()

			if ok {
				break
			}
		}

		if time.Now().After(deadline) {
			t.Fatalf("server never became ready (last err %v)", err)
		}

		time.Sleep(100 * time.Millisecond)
	}

	// cổng đăng nhập có thật, và admin đầu tiên đã được tạo
	resp, err := http.Get("http://" + addr + "/admin/login")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("login page: %v %v", resp, err)
	}

	_ = resp.Body.Close()

	cancel()

	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("graceful shutdown returned %v", err)
		}

	case <-time.After(20 * time.Second):
		t.Fatal("the server did not shut down after its context was cancelled")
	}

	if _, err := http.Get("http://" + addr + "/healthz"); err == nil {
		t.Error("the listener must be closed after shutdown")
	}
}

// serveEnv đặt cấu hình tối thiểu hợp lệ cho serve, trỏ tới database dsn và địa chỉ addr; extra ghi đè.
func serveEnv(t *testing.T, dsn, addr string, extra map[string]string) {
	t.Helper()

	env := map[string]string{
		"APP_ENV": "development", "HTTP_ADDR": addr, "DATABASE_URL": dsn, "SESSION_SECRET": "server-test-secret-0123456789",
		"DATA_KEY": "0123456789abcdef0123456789abcdef-data", "DATA_PEPPER": "fedcba9876543210fedcba9876543210-pepper",
		"BOOTSTRAP_ADMIN_EMAIL": "", "BOOTSTRAP_ADMIN_PASSWORD": "", "POLL_INTERVAL": "50ms", "REDIS_ADDR": "",
		"READ_DATABASE_URL": "", "DATA_KEY_VERSION": "1", "DATA_KEY_V1": "", "AUTH_DISABLED": "false",
	}

	for k, v := range extra {
		env[k] = v
	}

	for k, v := range env {
		t.Setenv(k, v)
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	defer l.Close()

	return l.Addr().String()
}

// serveMustFail chạy serve và đòi nó trả lỗi (chứa want) trong thời gian ngắn, không treo.
func serveMustFail(t *testing.T, want string) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errc := make(chan error, 1)

	go func() { errc <- serve(ctx, cancel, quietLog()) }()

	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("want an error containing %q, got %v", want, err)
		}

	case <-time.After(20 * time.Second):
		t.Fatalf("serve did not fail with %q (still running)", want)
	}
}

// Khóa cấu hình không đọc được dữ liệu đã lưu thì server từ chối khởi động, không phục vụ và không sửa gì.
func TestServeRefusesWrongDataKey(t *testing.T) {
	st, dsn := testStore(t)

	if _, err := st.CreateEntry(context.Background(), mustKeyForServe(t), model.EntryInput{Category: "spam", RiskScore: 1}, model.Actor{Email: "t"}); err != nil {
		t.Fatal(err)
	}

	serveEnv(t, dsn, freeAddr(t), map[string]string{"DATA_KEY": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-other-key"})
	serveMustFail(t, "cannot read the stored data")
}

func mustKeyForServe(t *testing.T) normalize.Key {
	t.Helper()

	k, err := normalize.NormalizeEntry(normalize.TypePhone, normalize.MatchExact, "0901234567", "VN")
	if err != nil {
		t.Fatal(err)
	}

	return k
}

func TestServeFailsOnBadReplicaAndBadBootstrapAndBusyPort(t *testing.T) {
	_, dsn := testStore(t)

	dead := "postgres://vsf:vsf@127.0.0.1:1/x?sslmode=disable&connect_timeout=1"

	serveEnv(t, dsn, freeAddr(t), map[string]string{"READ_DATABASE_URL": dead})
	serveMustFail(t, "open replica")

	// mật khẩu bootstrap quá ngắn: dừng ngay, không tạo tài khoản
	serveEnv(t, dsn, freeAddr(t), map[string]string{"BOOTSTRAP_ADMIN_EMAIL": "a@b.c", "BOOTSTRAP_ADMIN_PASSWORD": "short"})
	serveMustFail(t, "quá ngắn")

	// cổng đã bị chiếm: lỗi nghe cổng được trả về (không nuốt)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	defer busy.Close()

	serveEnv(t, dsn, busy.Addr().String(), nil)
	serveMustFail(t, "address")
}

// Redis không tới được: server vẫn khởi động và trả lời (cache và giới hạn tốc độ cho qua), thay vì từ chối chạy.
func TestServeStartsEvenWhenRedisIsDown(t *testing.T) {
	_, dsn := testStore(t)
	addr := freeAddr(t)

	serveEnv(t, dsn, addr, map[string]string{"REDIS_ADDR": "127.0.0.1:1", "AUTH_DISABLED": "true"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errc := make(chan error, 1)

	go func() { errc <- serve(ctx, cancel, quietLog()) }()

	deadline := time.Now().Add(15 * time.Second)

	for {
		if resp, err := http.Get("http://" + addr + "/readyz"); err == nil {
			ok := resp.StatusCode == 200
			_ = resp.Body.Close()

			if ok {
				break
			}
		}

		if time.Now().After(deadline) {
			t.Fatal("server with a dead Redis never became ready")
		}

		time.Sleep(100 * time.Millisecond)
	}

	resp, err := http.Get("http://" + addr + "/v1/check?type=phone&value=0901234567")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("a check must still work without Redis: %v %v", resp, err)
	}

	_ = resp.Body.Close()

	cancel()

	if err := <-errc; err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

// Bloom filter không dựng được lúc khởi động (ở đây: change_log biến mất nên feed.Init lỗi ở bước Head) thì server phải
// dừng với lỗi, không được chạy tiếp với Bloom rỗng và báo mọi số là an toàn.
func TestServeStopsWhenTheBloomFilterCannotBeBuilt(t *testing.T) {
	st, dsn := testStore(t)

	if _, err := st.CreateEntry(context.Background(), mustKeyForServe(t), model.EntryInput{Category: "spam", RiskScore: 1}, model.Actor{Email: "t"}); err != nil {
		t.Fatal(err)
	}

	admin, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}

	defer admin.Close()

	if _, err := admin.Exec(context.Background(), `ALTER TABLE change_log RENAME TO change_log_hidden`); err != nil {
		t.Fatal(err)
	}

	serveEnv(t, dsn, freeAddr(t), nil)
	serveMustFail(t, "head")
}

// Một lỗi ở vòng nền (database biến mất) chỉ được ghi log, vòng nền vẫn chạy tiếp và vẫn dừng khi context bị hủy.
func TestBackgroundJobsSurviveDatabaseErrors(t *testing.T) {
	st, _ := testStore(t)

	oldFlush, oldPurge := flushEvery, purgeEvery
	flushEvery, purgeEvery = 20*time.Millisecond, 20*time.Millisecond

	t.Cleanup(func() { flushEvery, purgeEvery = oldFlush, oldPurge })

	log := quietLog()
	bm := bloom.NewManager()
	feed := changefeed.New(st, bm, log)

	if err := feed.Init(context.Background(), 1000); err != nil {
		t.Fatal(err)
	}

	keys := apikey.NewService(st, nil, 100)

	// một lượt dùng thật, để FlushLastUsed có việc phải ghi xuống database khi database đã mất
	full, prefix, hash, err := apikey.Generate()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := st.CreateAPIKey(context.Background(), store.NewAPIKey{Name: "bg", Prefix: prefix, KeyHash: hash, RPSLimit: 10}, model.Actor{Email: "t"}); err != nil {
		t.Fatal(err)
	}

	if _, err := keys.Authenticate(context.Background(), full, "203.0.113.1"); err != nil {
		t.Fatal(err)
	}

	st.Close() // mất database: flush, purge và rebuild đều lỗi

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		backgroundJobs(ctx, log, st, feed, keys, config.Config{BloomExpectedItems: 1000, BloomRebuildInterval: 20 * time.Millisecond})
		close(done)
	}()

	time.Sleep(200 * time.Millisecond) // nhiều chu kỳ, mỗi chu kỳ đều lỗi

	select {
	case <-done:
		t.Fatal("a database error must not stop the background loop")
	default:
	}

	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("backgroundJobs must still stop when its context is cancelled")
	}
}
