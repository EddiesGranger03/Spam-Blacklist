package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/seal"
	"vsf/internal/store"
)

// Khóa cũ (phiên bản 1), khóa mới (phiên bản 2) và pepper dùng chung cho các test của lệnh rekey.
const (
	testKeyOld = "0123456789abcdef0123456789abcdef-data"
	testKeyNew = "abcdefghijklmnopqrstuvwxyz012345-datb"
	testPepper = "fedcba9876543210fedcba9876543210-pepper"
)

// tempDB tạo một database trống tên vsf_rekey_<nanos>_test trên cùng server với TEST_DATABASE_URL và xóa khi test xong.
// Bỏ qua test nếu chưa đặt TEST_DATABASE_URL hoặc user không có quyền CREATE DATABASE.
func tempDB(t *testing.T) string {
	t.Helper()

	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping integration test")
	}

	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Kết nối vào DB bảo trì "postgres" để CREATE/DROP DATABASE không giữ transaction trên DB test chung.
	maint := *u
	maint.Path = "/postgres"

	admin, err := pgxpool.New(ctx, maint.String())
	if err != nil {
		t.Fatal(err)
	}

	name := fmt.Sprintf("vsf_rekey_%d_test", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		admin.Close()

		var pe *pgconn.PgError
		if errors.As(err, &pe) && pe.Code == "42501" {
			t.Skipf("user của TEST_DATABASE_URL không có quyền CREATE DATABASE (%v)", err)
		}

		t.Fatalf("create temp database: %v", err)
	}

	t.Cleanup(func() {
		defer admin.Close()

		if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Logf("drop temp database %s: %v", name, err)
		}
	})

	tmp := *u
	tmp.Path = "/" + name

	return tmp.String()
}

// seedOldKey tạo schema và 3 entry được mã hóa bằng khóa cũ (phiên bản 1), giống dữ liệu trước khi xoay khóa.
func seedOldKey(t *testing.T, dsn string) {
	t.Helper()

	ctx := context.Background()

	sl, err := seal.New(testKeyOld, testPepper, 1)
	if err != nil {
		t.Fatal(err)
	}

	st, err := store.New(ctx, dsn, "", 4)
	if err != nil {
		t.Fatal(err)
	}

	defer st.Close()

	st.SetSealer(sl)

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	for i, phone := range []string{"0901000001", "0901000002", "0901000003"} {
		key, err := normalize.NormalizeEntry(normalize.TypePhone, normalize.MatchExact, phone, "VN")
		if err != nil {
			t.Fatal(err)
		}

		if _, err := st.CreateEntry(ctx, key, model.EntryInput{Category: "scam", RiskScore: 50 + i, Source: "test", Note: "seed"},
			model.Actor{Email: "seed"}); err != nil {
			t.Fatal(err)
		}
	}
}

// setRekeyEnv đặt môi trường như server sau khi xoay DATA_KEY lên phiên bản 2.
// withOldKey=true thì giữ khóa cũ là DATA_KEY_V1; false thì mô phỏng việc quên khai báo khóa cũ.
func setRekeyEnv(t *testing.T, dsn string, withOldKey bool) {
	t.Helper()

	t.Setenv("DATABASE_URL", dsn)
	t.Setenv("SESSION_SECRET", "test-session-secret-0123456789abcdef")
	t.Setenv("DATA_KEY", testKeyNew)
	t.Setenv("DATA_PEPPER", testPepper)
	t.Setenv("DATA_KEY_VERSION", "2")

	if withOldKey {
		t.Setenv("DATA_KEY_V1", testKeyOld)
	}
}

// countVersion đếm số dòng đang được mã hóa bằng một phiên bản khóa.
func countVersion(t *testing.T, dsn string, version int) int64 {
	t.Helper()

	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	defer pool.Close()

	var n int64
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM blacklist_entries WHERE key_version = $1", version).Scan(&n); err != nil {
		t.Fatal(err)
	}

	return n
}

// Thiếu DATA_KEY_V1: lệnh phải dừng TRƯỚC khi ghi gì và nói rõ cần đặt biến nào.
func TestRekeyFailsWhenOldKeyIsMissingAndWritesNothing(t *testing.T) {
	dsn := tempDB(t)
	seedOldKey(t, dsn)
	setRekeyEnv(t, dsn, false)

	err := run(nil)
	if err == nil {
		t.Fatal("rekey phải báo lỗi khi thiếu khóa cũ")
	}

	if !strings.Contains(err.Error(), "DATA_KEY_V1") {
		t.Fatalf("thông báo lỗi phải nêu DATA_KEY_V1, nhận được: %v", err)
	}

	if n := countVersion(t, dsn, 1); n != 3 {
		t.Fatalf("không được ghi gì khi lỗi: còn %d dòng ở phiên bản 1, muốn 3", n)
	}
}

// Cờ không hợp lệ phải báo lỗi ngay, không đụng tới cấu hình hay database.
func TestRekeyRejectsUnknownFlag(t *testing.T) {
	if err := run([]string{"-khong-co-cờ"}); err == nil {
		t.Fatal("cờ không tồn tại phải báo lỗi")
	}
}

// -status và -dry-run chỉ đọc: không đổi số dòng theo phiên bản.
func TestRekeyStatusAndDryRunWriteNothing(t *testing.T) {
	dsn := tempDB(t)
	seedOldKey(t, dsn)
	setRekeyEnv(t, dsn, true)

	if err := run([]string{"-status"}); err != nil {
		t.Fatalf("-status: %v", err)
	}

	if err := run([]string{"-dry-run"}); err != nil {
		t.Fatalf("-dry-run: %v", err)
	}

	if n := countVersion(t, dsn, 1); n != 3 {
		t.Fatalf("sau -status và -dry-run còn %d dòng ở phiên bản 1, muốn 3", n)
	}

	if n := countVersion(t, dsn, 2); n != 0 {
		t.Fatalf("sau -status và -dry-run có %d dòng ở phiên bản 2, muốn 0", n)
	}
}

// Chạy thật: mọi dòng cũ được chuyển sang khóa hiện tại, và chạy lại không còn gì để làm.
func TestRekeyMovesRowsToCurrentKey(t *testing.T) {
	dsn := tempDB(t)
	seedOldKey(t, dsn)
	setRekeyEnv(t, dsn, true)

	if err := run(nil); err != nil {
		t.Fatalf("rekey: %v", err)
	}

	if n := countVersion(t, dsn, 1); n != 0 {
		t.Fatalf("sau rekey còn %d dòng ở phiên bản 1, muốn 0", n)
	}

	if n := countVersion(t, dsn, 2); n != 3 {
		t.Fatalf("sau rekey có %d dòng ở phiên bản 2, muốn 3", n)
	}

	if err := run(nil); err != nil {
		t.Fatalf("chạy lại sau khi xong phải không lỗi: %v", err)
	}
}
