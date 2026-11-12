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

// Pepper cũ (dữ liệu đang lưu dưới nó), pepper mới, và một pepper sai dùng để kiểm tra từ chối.
const (
	testKey       = "0123456789abcdef0123456789abcdef-data"
	testPepperOld = "fedcba9876543210fedcba9876543210-pepper"
	testPepperNew = "pepper-moi-0123456789abcdef0123456789-abc"
	testPepperBad = "pepper-sai-0123456789abcdef0123456789-xyz"
)

// tempDB tạo một database trống tên vsf_pepper_<nanos>_test trên cùng server với TEST_DATABASE_URL và xóa khi test xong.
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

	name := fmt.Sprintf("vsf_pepper_%d_test", time.Now().UnixNano())
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

// seedOldPepper tạo schema và 3 entry được băm bằng pepper cũ, giống dữ liệu trước khi xoay pepper.
func seedOldPepper(t *testing.T, dsn string) {
	t.Helper()

	ctx := context.Background()

	sl, err := seal.New(testKey, testPepperOld, 1)
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

// setPepperEnv đặt môi trường như lúc chạy lệnh xoay pepper: pepper mới trong DATA_PEPPER, pepper cũ trong DATA_PEPPER_OLD.
func setPepperEnv(t *testing.T, dsn, oldPepper string) {
	t.Helper()

	t.Setenv("DATABASE_URL", dsn)
	t.Setenv("SESSION_SECRET", "test-session-secret-0123456789abcdef")
	t.Setenv("DATA_KEY", testKey)
	t.Setenv("DATA_PEPPER", testPepperNew)
	t.Setenv("DATA_KEY_VERSION", "1")
	t.Setenv("DATA_PEPPER_OLD", oldPepper)
}

// findable cho biết số điện thoại có tra cứu được (khớp entry) khi dùng pepper đã cho hay không.
func findable(t *testing.T, dsn, pepper, phone string) bool {
	t.Helper()

	ctx := context.Background()

	sl, err := seal.New(testKey, pepper, 1)
	if err != nil {
		t.Fatal(err)
	}

	st, err := store.New(ctx, dsn, "", 4)
	if err != nil {
		t.Fatal(err)
	}

	defer st.Close()

	st.SetSealer(sl)

	_, keys, err := normalize.Candidates(normalize.TypePhone, phone, "VN")
	if err != nil {
		t.Fatal(err)
	}

	entries, err := st.FindMatches(ctx, keys)
	if err != nil {
		t.Fatal(err)
	}

	return len(entries) > 0
}

// Thiếu cờ xác nhận -servers-stopped: không chạy thật, không đụng database.
func TestRotatePepperRefusesRealRunWithoutConfirmation(t *testing.T) {
	setPepperEnv(t, "postgres://nobody@127.0.0.1:1/none?sslmode=disable", testPepperOld)

	err := run(nil)
	if err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("phải từ chối khi thiếu -servers-stopped, nhận được: %v", err)
	}
}

// Thiếu DATA_PEPPER_OLD: báo lỗi nêu rõ biến cần đặt.
func TestRotatePepperRequiresOldPepper(t *testing.T) {
	setPepperEnv(t, "postgres://nobody@127.0.0.1:1/none?sslmode=disable", "")

	err := run([]string{"-servers-stopped"})
	if err == nil || !strings.Contains(err.Error(), "DATA_PEPPER_OLD is required") {
		t.Fatalf("phải báo thiếu DATA_PEPPER_OLD, nhận được: %v", err)
	}
}

// Pepper cũ trùng pepper mới: không có gì để xoay, báo lỗi thay vì chạy vô ích.
func TestRotatePepperRejectsSamePepper(t *testing.T) {
	setPepperEnv(t, "postgres://nobody@127.0.0.1:1/none?sslmode=disable", testPepperNew)

	err := run([]string{"-servers-stopped"})
	if err == nil || !strings.Contains(err.Error(), "nothing to rotate") {
		t.Fatalf("phải báo không có gì để xoay, nhận được: %v", err)
	}
}

// -dry-run chỉ đọc: dữ liệu vẫn tra cứu được bằng pepper cũ, không bằng pepper mới.
func TestRotatePepperDryRunWritesNothing(t *testing.T) {
	dsn := tempDB(t)
	seedOldPepper(t, dsn)
	setPepperEnv(t, dsn, testPepperOld)

	if err := run([]string{"-dry-run"}); err != nil {
		t.Fatalf("-dry-run: %v", err)
	}

	if !findable(t, dsn, testPepperOld, "0901000001") {
		t.Fatal("sau -dry-run dữ liệu phải vẫn tra cứu được bằng pepper cũ")
	}

	if findable(t, dsn, testPepperNew, "0901000001") {
		t.Fatal("sau -dry-run không được tra cứu được bằng pepper mới")
	}
}

// Chạy thật với pepper cũ đúng: mọi dòng chuyển sang pepper mới; chạy lại là không làm gì thêm.
func TestRotatePepperMovesRowsToNewPepper(t *testing.T) {
	dsn := tempDB(t)
	seedOldPepper(t, dsn)
	setPepperEnv(t, dsn, testPepperOld)

	if err := run([]string{"-servers-stopped"}); err != nil {
		t.Fatalf("rotate-pepper: %v", err)
	}

	for _, phone := range []string{"0901000001", "0901000002", "0901000003"} {
		if !findable(t, dsn, testPepperNew, phone) {
			t.Fatalf("%s phải tra cứu được bằng pepper mới sau khi xoay", phone)
		}

		if findable(t, dsn, testPepperOld, phone) {
			t.Fatalf("%s không được còn tra cứu được bằng pepper cũ sau khi xoay", phone)
		}
	}

	if err := run([]string{"-servers-stopped"}); err != nil {
		t.Fatalf("chạy lại sau khi xong phải không lỗi: %v", err)
	}
}

// Pepper cũ sai: lệnh phải dừng và không ghi gì; dữ liệu vẫn tra cứu được bằng pepper cũ thật.
func TestRotatePepperWrongOldPepperChangesNothing(t *testing.T) {
	dsn := tempDB(t)
	seedOldPepper(t, dsn)
	setPepperEnv(t, dsn, testPepperBad)

	if err := run([]string{"-servers-stopped"}); err == nil {
		t.Fatal("pepper cũ sai phải làm lệnh báo lỗi")
	}

	if !findable(t, dsn, testPepperOld, "0901000001") {
		t.Fatal("sau khi lỗi, dữ liệu phải còn nguyên dưới pepper cũ thật")
	}
}
