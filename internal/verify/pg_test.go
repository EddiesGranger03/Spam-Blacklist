package verify_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"vsf/internal/changefeed"
	"vsf/internal/filter"
	"vsf/internal/seal"
	"vsf/internal/store"
	"vsf/internal/verify"
)

// pgEnv: database riêng cho test (tạo trên TEST_DATABASE_URL, drop khi xong), store đã migrate, feed + filter thật.
type pgEnv struct {
	db   *pgxpool.Pool
	st   *store.Store
	feed *changefeed.Feed
	bm   *filter.Manager
}

func newPGEnv(t *testing.T) *pgEnv {
	t.Helper()

	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping integration test")
	}

	ctx := context.Background()

	admin, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatal(err)
	}

	name := fmt.Sprintf("vsf_verify_%d_test", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+name); err != nil {
		admin.Close()
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`)
		admin.Close()
	})

	u, _ := url.Parse(base)
	u.Path = "/" + name
	dsn := u.String()

	st, err := store.New(ctx, dsn, "", 8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	sl, err := seal.New("0123456789abcdef0123456789abcdef-data", "fedcba9876543210fedcba9876543210-pepper", 1)
	if err != nil {
		t.Fatal(err)
	}
	st.SetSealer(sl)

	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)

	bm := filter.NewManager()
	return &pgEnv{db: db, st: st, feed: changefeed.New(st, bm, slog.New(slog.NewTextHandler(io.Discard, nil))), bm: bm}
}

// insert ghi n dòng BLACKLIST (hash from..from+n-1) và change_log tương ứng trong MỘT transaction, như store thật.
func (e *pgEnv) insert(t *testing.T, from, n int64) {
	t.Helper()

	ctx := context.Background()

	_, err := e.db.Exec(ctx, `WITH r AS (
			INSERT INTO blacklist_entries (type, match_type, value_hash, value_blind, value_enc, note_enc, source_enc, key_version)
			SELECT 'phone', 'exact', g, int8send(g), decode('00', 'hex'), decode('00', 'hex'), decode('00', 'hex'), 1 FROM generate_series($1::bigint, $2::bigint) g
			RETURNING value_hash)
		INSERT INTO change_log (value_hash, op) SELECT value_hash, 1 FROM r`, from, from+n-1)
	if err != nil {
		t.Fatal(err)
	}
}

func (e *pgEnv) verifier() *verify.Verifier {
	return verify.New(e.bm, e.feed, e.st, verify.Config{Sample: 1000}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestPGVerify(t *testing.T) {
	e := newPGEnv(t)
	ctx := context.Background()

	e.insert(t, 1, 300)

	if err := e.feed.Init(ctx, 1000); err != nil {
		t.Fatal(err)
	}

	v := e.verifier()

	t.Run("correct filter has zero false negatives", func(t *testing.T) {
		fns, err := v.RunOnce(ctx)
		if err != nil || len(fns) != 0 {
			t.Fatalf("fns=%v err=%v", fns, err)
		}

		if v.Status().Checked != 300 {
			t.Fatalf("checked %d, want 300 (table is small: TABLESAMPLE at 100%%)", v.Status().Checked)
		}
	})

	t.Run("committed but not yet synced is not a false alarm", func(t *testing.T) {
		e.insert(t, 1001, 50) // không SyncNow: filter chưa có 1001..1050

		if e.bm.Test(1001) {
			t.Skip("hash 1001 is a filter false positive; precondition not met")
		}

		fns, err := v.RunOnce(ctx)
		if err != nil || len(fns) != 0 {
			t.Fatalf("fns=%v err=%v", fns, err)
		}

		if !e.bm.Test(1001) {
			t.Fatal("verifier's catch-up should have applied the new rows")
		}
	})

	t.Run("hash dropped from filter is caught in one round", func(t *testing.T) {
		// Tiêm lỗi: removed-set che hash 42. Xóa dòng change_log của nó trước: nếu dòng đó còn Pending (xmin toàn cluster
		// bị transaction ở DB khác giữ lại khi chạy song song), mỗi SyncNow sẽ áp lại và tự vá, che mất lỗi cần bắt.
		if _, err := e.db.Exec(ctx, `DELETE FROM change_log WHERE value_hash = 42`); err != nil {
			t.Fatal(err)
		}

		e.bm.Current().Remove(42)

		healed := false
		vh := verify.New(e.bm, e.feed, e.st, verify.Config{Sample: 1000, Heal: func(h uint64) {
			healed = h == 42
			e.bm.Current().Add(h)
		}}, slog.New(slog.NewTextHandler(io.Discard, nil)))

		fns, err := vh.RunOnce(ctx)
		if err != nil || len(fns) != 1 || fns[0] != 42 {
			t.Fatalf("fns=%v err=%v", fns, err)
		}

		if !healed || !e.bm.Test(42) {
			t.Fatal("hash 42 should be healed")
		}

		if fns, _ := vh.RunOnce(ctx); len(fns) != 0 {
			t.Fatalf("after heal fns=%v", fns)
		}
	})

	t.Run("whitelisted or expired rows are not sampled", func(t *testing.T) {
		if _, err := e.db.Exec(ctx, `UPDATE blacklist_entries SET status='WHITELIST' WHERE value_hash = 7;
			UPDATE blacklist_entries SET expires_at = now() - interval '1 day' WHERE value_hash = 8`); err != nil {
			t.Fatal(err)
		}

		e.bm.Current().Remove(7)
		e.bm.Current().Remove(8)

		fns, err := v.RunOnce(ctx)
		if err != nil || len(fns) != 0 {
			t.Fatalf("fns=%v err=%v", fns, err)
		}
	})
}

// Bảng lớn đã ANALYZE: TABLESAMPLE dùng tỉ lệ < 100% và chỉ trả khoảng 3n dòng, không quét cả bảng.
func TestPGSampleUsesTableSample(t *testing.T) {
	e := newPGEnv(t)
	ctx := context.Background()

	e.insert(t, 1, 200_000)

	if _, err := e.db.Exec(ctx, `ANALYZE blacklist_entries`); err != nil {
		t.Fatal(err)
	}

	got, err := e.st.SampleActiveBlacklistHashes(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}

	// Kỳ vọng ~3000; SYSTEM theo trang nên dao động, chỉ chặn hai đầu rộng.
	if len(got) < 500 || len(got) > 20_000 {
		t.Fatalf("sample size %d, want roughly 3000 (TABLESAMPLE not effective?)", len(got))
	}
}
