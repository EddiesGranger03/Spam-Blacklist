package store

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"vsf/internal/model"
)

// freshDatabase tạo một database RỖNG riêng (tên kết thúc bằng _test) và xóa nó khi xong; trả DSN của nó.
// Cần cho các test Migrate trên database chưa có schema, mà database dùng chung của gói đã Migrate sẵn.
func freshDatabase(t *testing.T) string {
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

	admin, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatal(err)
	}

	name := fmt.Sprintf("vsf_store_fresh_%d_test", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+name); err != nil {
		admin.Close()
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`)
		admin.Close()
	})

	u.Path = "/" + name

	return u.String()
}

func freshStore(t *testing.T, dsn string) *Store {
	t.Helper()

	s, err := New(context.Background(), dsn, "", 4)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(s.Close)
	s.SetSealer(newTestSealer(t))

	return s
}

func appliedMigrations(t *testing.T, s *Store) []string {
	t.Helper()

	rows, err := s.write.Query(context.Background(), `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		t.Fatal(err)
	}

	defer rows.Close()

	var out []string

	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}

		out = append(out, v)
	}

	return out
}

// Trên database rỗng, Migrate dựng toàn bộ schema (kể cả chuyển bố cục sang dạng mã hóa), ghi lại các migration đã
// chạy, dùng được ngay, và chạy lại là no-op.
func TestMigrateBuildsAFreshDatabase(t *testing.T) {
	s := freshStore(t, freshDatabase(t))
	ctx := context.Background()

	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	applied := appliedMigrations(t, s)
	if len(applied) < 4 || !strings.HasPrefix(applied[0], "001") {
		t.Fatalf("every migration file must be recorded: %v", applied)
	}

	if _, err := s.CreateEntry(ctx, mustKey(t, "phone", "exact", "0905000111"), model.EntryInput{Category: "spam", RiskScore: 1}, actor); err != nil {
		t.Fatalf("the migrated schema must accept entries: %v", err)
	}

	before := len(applied)

	if err := s.Migrate(ctx); err != nil || len(appliedMigrations(t, s)) != before {
		t.Fatalf("a second migrate is a no-op: %v", err)
	}
}

// Một migration lỗi thì dừng với lỗi nêu tên file, và KHÔNG được ghi là đã chạy (để lần sau chạy lại được).
func TestMigrateStopsOnAFailingMigrationAndRecordsNothing(t *testing.T) {
	dsn := freshDatabase(t)
	s := freshStore(t, dsn)
	ctx := context.Background()

	// Bảng cùng tên nhưng khác cấu trúc: CREATE TABLE trong 001_init.sql sẽ lỗi
	if _, err := s.write.Exec(ctx, `CREATE TABLE admins (x int)`); err != nil {
		t.Fatal(err)
	}

	err := s.Migrate(ctx)
	if err == nil || !strings.Contains(err.Error(), "migration 001") {
		t.Fatalf("want an error naming the failing migration, got %v", err)
	}

	for _, v := range appliedMigrations(t, s) {
		if strings.HasPrefix(v, "001") {
			t.Fatalf("a failed migration must not be recorded as applied: %v", appliedMigrations(t, s))
		}
	}
}

// Hai instance khởi động cùng lúc trên database rỗng: khóa advisory buộc chúng chạy lần lượt và cả hai đều thành công.
func TestMigrateIsSafeWhenTwoInstancesStartTogether(t *testing.T) {
	dsn := freshDatabase(t)
	a, b := freshStore(t, dsn), freshStore(t, dsn)

	var wg sync.WaitGroup

	errs := make([]error, 2)

	for i, s := range []*Store{a, b} {
		wg.Add(1)

		go func() {
			defer wg.Done()

			errs[i] = s.Migrate(context.Background())
		}()
	}

	wg.Wait()

	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("both instances must migrate cleanly: %v / %v", errs[0], errs[1])
	}

	seen := map[string]int{}
	for _, v := range appliedMigrations(t, a) {
		seen[v]++
	}

	for v, n := range seen {
		if n != 1 {
			t.Fatalf("migration %s recorded %d times", v, n)
		}
	}
}

func TestMigrateHonoursACancelledContext(t *testing.T) {
	s := freshStore(t, freshDatabase(t))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := s.Migrate(ctx); err == nil {
		t.Fatal("a cancelled context must stop the migration with an error")
	}
}
