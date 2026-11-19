package changefeed

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"vsf/internal/filter"
	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/seal"
	"vsf/internal/store"
	"vsf/internal/testutil/pgfault"
)

// Mất kết nối giữa hai câu lệnh với changefeed thật trên PostgreSQL thật. Hai điều không được xảy ra:
//   - dựng lại Bloom filter thất bại mà filter cũ bị mất hoặc cụt (mọi số bị chặn sẽ bị báo an toàn);
//   - một lần thăm dò change_log thất bại mà thay đổi bị bỏ sót vĩnh viễn (con trỏ đi quá thay đổi chưa được nạp).

type netEnv struct {
	dsn    string
	direct *store.Store
	proxy  *pgfault.Proxy
	sealer *seal.Sealer
}

func newNetEnv(t *testing.T) *netEnv {
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

	name := fmt.Sprintf("vsf_feed_net_%d_test", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, `CREATE DATABASE `+name); err != nil {
		admin.Close()
		t.Fatal(err)
	}

	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`)
		admin.Close()
	})

	u.Path = "/" + name
	dsn := u.String()

	sl, err := seal.New("0123456789abcdef0123456789abcdef-data", "fedcba9876543210fedcba9876543210-pepper", 1)
	if err != nil {
		t.Fatal(err)
	}

	direct, err := store.New(ctx, dsn, "", 4)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(direct.Close)

	direct.SetSealer(sl)
	direct.SetAuditKey(store.AuditKeyFrom("", "feed-net-test-secret-0123456789"))

	if err := direct.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	return &netEnv{dsn: dsn, direct: direct, proxy: pgfault.Start(t, pgfault.TargetOf(t, dsn)), sealer: sl}
}

func (e *netEnv) proxied(t *testing.T) *store.Store {
	t.Helper()

	s, err := store.New(context.Background(), e.proxy.DSN(t, e.dsn), "", 4)
	if err != nil {
		t.Fatal(err)
	}

	s.SetSealer(e.sealer)
	t.Cleanup(s.Close)

	return s
}

func (e *netEnv) add(t *testing.T, phone string) normalize.Key {
	t.Helper()

	k, err := normalize.NormalizeEntry(normalize.TypePhone, normalize.MatchExact, phone, "VN")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := e.direct.CreateEntry(context.Background(), k, model.EntryInput{Category: "spam", RiskScore: 1, Note: "n"},
		model.Actor{Email: "t"}); err != nil {
		t.Fatal(err)
	}

	return k
}

// Dựng lại Bloom filter bị đứt kết nối GIỮA LÚC đọc danh sách hash: trả lỗi và filter cũ còn nguyên (vẫn chặn mọi số đã có).
func TestRebuildCutMidStreamKeepsTheOldFilter(t *testing.T) {
	e := newNetEnv(t)
	ctx := context.Background()

	var keys []normalize.Key
	for i := 0; i < 600; i++ {
		keys = append(keys, e.add(t, fmt.Sprintf("0907%06d", i)))
	}

	bm := filter.NewManager()
	st := e.proxied(t)
	feed := New(st, bm, quiet())

	if err := feed.Init(ctx, 1000); err != nil {
		t.Fatal(err)
	}

	for _, k := range keys {
		if !bm.Test(uint64(k.Hash)) {
			t.Fatal("the initial filter must contain every entry")
		}
	}

	// đo kích thước kết quả của lần dựng lại, rồi đứt ở giữa
	e.proxy.FailAfterServerBytes(1 << 40)

	if err := feed.Rebuild(ctx, 1000); err != nil {
		t.Fatalf("a healthy rebuild: %v", err)
	}

	total := e.proxy.ServerBytes()

	e.proxy.Heal()

	if total < 4000 {
		t.Fatalf("the rebuild transferred only %d bytes: too small to cut in the middle", total)
	}

	// kết nối cũ trong pool của store có thể đã bị bỏ: dùng store mới cho lần thử có lỗi
	st2 := e.proxied(t)
	feed2 := New(st2, bm, quiet())

	e.proxy.FailAfterServerBytes(total / 2)

	err := feed2.Rebuild(ctx, 1000)

	e.proxy.Heal()

	if err == nil {
		t.Fatal("a rebuild whose connection was cut mid-stream must report an error")
	}

	if !bm.Ready() {
		t.Fatal("a failed rebuild must not leave the filter not-ready")
	}

	for _, k := range keys {
		if !bm.Test(uint64(k.Hash)) {
			t.Fatalf("a failed rebuild lost hash %d: a blacklisted number would now be reported safe", k.Hash)
		}
	}

	// sau khi hết lỗi, dựng lại thành công (bộ quản lý không kẹt ở trạng thái "đang dựng lại")
	if err := feed2.Rebuild(ctx, 1000); err != nil {
		t.Fatalf("rebuild after the fault is gone: %v", err)
	}
}

// Thăm dò change_log bị đứt ở BẤT KỲ điểm nào: lần thăm dò đó báo lỗi, và lần sau (khỏe) vẫn nạp được thay đổi, không bỏ sót.
func TestSyncNowCutAtAnyPointNeverLosesAChange(t *testing.T) {
	e := newNetEnv(t)
	ctx := context.Background()

	for _, mode := range []string{"before", "after"} {
		completed := false

		for k := 1; k <= 20; k++ {
			bm := filter.NewManager()
			st := e.proxied(t)
			feed := New(st, bm, quiet())

			if err := feed.Init(ctx, 1000); err != nil {
				t.Fatal(err)
			}

			key := e.add(t, fmt.Sprintf("0908%06d", k+len(mode)*1000)) // thay đổi mới, chưa nằm trong filter

			if bm.Test(uint64(key.Hash)) {
				t.Fatalf("[%s k=%d] the new hash must not be in the filter yet", mode, k)
			}

			cutsBefore := e.proxy.Cuts()

			if mode == "before" {
				e.proxy.FailAtRoundTrip(k)
			} else {
				e.proxy.FailAfterRoundTrip(k)
			}

			err := feed.SyncNow(ctx)
			cut := e.proxy.Cuts() > cutsBefore

			e.proxy.Heal()

			if cut && err == nil {
				t.Errorf("[%s k=%d] SyncNow reported success although its connection was cut", mode, k)
			}

			if !cut && err != nil {
				t.Fatalf("[%s k=%d] SyncNow failed although nothing was cut: %v", mode, k, err)
			}

			// thăm dò kế tiếp bằng kết nối mới khỏe: thay đổi PHẢI được nạp
			healthy := New(e.proxied(t), bm, quiet())
			healthy.xid, healthy.seq = feed.xid, feed.seq // tiếp tục từ con trỏ mà lần thăm dò hỏng để lại

			if err := healthy.SyncNow(ctx); err != nil {
				t.Fatalf("[%s k=%d] the next healthy poll must succeed: %v", mode, k, err)
			}

			if !bm.Test(uint64(key.Hash)) {
				t.Fatalf("[%s k=%d] the change was LOST: its hash never reached the Bloom filter after a cut poll", mode, k)
			}

			if !cut {
				completed = true

				t.Logf("[%s] SyncNow needs %d round trips; every cut point 1..%d was exercised", mode, k-1, k-1)

				if k-1 < 1 {
					t.Fatalf("[%s] no cut point was exercised", mode)
				}

				break
			}
		}

		if !completed {
			t.Fatalf("[%s] still being cut after 20 round trips", mode)
		}
	}
}
