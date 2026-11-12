package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"vsf/internal/testutil/pgfault"
)

// emptyDatabase tạo một database RỖNG (chưa có bảng nào) và xóa nó khi test xong; trả DSN của nó.
func emptyDatabase(t *testing.T) string {
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

	name := fmt.Sprintf("vsf_srv_net_%d_test", time.Now().UnixNano())
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

// waitServe chờ cho tới khi serve trả về (startFailed) hoặc /readyz trả 200 (ready); báo lỗi nếu không có gì xảy ra
// trong thời hạn (tức là server treo).
func waitServe(t *testing.T, errc <-chan error, addr string) (err error, ready bool) {
	t.Helper()

	deadline := time.Now().Add(45 * time.Second)

	for {
		select {
		case e := <-errc:
			return e, false
		default:
		}

		if resp, herr := http.Get("http://" + addr + "/readyz"); herr == nil {
			ok := resp.StatusCode == 200
			_ = resp.Body.Close()

			if ok {
				return nil, true
			}
		}

		if time.Now().After(deadline) {
			t.Fatal("serve neither failed nor became ready within 45s: it hung")
		}

		time.Sleep(50 * time.Millisecond)
	}
}

// Mất kết nối database ở nhiều điểm khác nhau trong LÚC KHỞI ĐỘNG trên database rỗng (migration, kiểm tra khóa, tạo admin
// đầu tiên, dựng Bloom filter). Với mỗi điểm đứt: serve không treo; nếu nó đã khởi động xong thì phục vụ đúng; nếu nó thất
// bại thì trả lỗi, và lần khởi động kế tiếp trên CÙNG database (đã dở dang) hoàn tất: có đúng một admin đầu tiên, schema đủ.
// Chỉ lấy mẫu một số điểm đứt vì mỗi lần cần một database rỗng và một lần migration đầy đủ.
func TestServeStartupCutAtSampledPoints(t *testing.T) {
	if testing.Short() {
		t.Skip("chậm (mỗi điểm đứt cần một database rỗng); bỏ qua với -short")
	}

	boot := map[string]string{"BOOTSTRAP_ADMIN_EMAIL": "first@example.com", "BOOTSTRAP_ADMIN_PASSWORD": "ChangeMe-12345"}
	failedStarts := 0

	for _, mode := range []string{"before", "after"} {
		for _, k := range []int{1, 3, 6, 10, 20, 40} {
			dsn := emptyDatabase(t)
			proxy := pgfault.Start(t, pgfault.TargetOf(t, dsn))
			addr := freeAddr(t)

			serveEnv(t, proxy.DSN(t, dsn), addr, boot)

			if mode == "before" {
				proxy.FailAtRoundTrip(k)
			} else {
				proxy.FailAfterRoundTrip(k)
			}

			ctx, cancel := context.WithCancel(context.Background())
			errc := make(chan error, 1)

			go func() { errc <- serve(ctx, cancel, quietLog()) }()

			err, ready := waitServe(t, errc, addr)
			cut := proxy.Cuts() > 0

			proxy.Heal()

			if ready {
				// khởi động xong (điểm đứt nằm sau giai đoạn khởi động, hoặc chưa tới): phải phục vụ được
				cancel()

				if serr := <-errc; serr != nil {
					t.Errorf("[%s k=%d] shutdown after a successful start: %v", mode, k, serr)
				}

				continue
			}

			cancel()

			if !cut {
				t.Fatalf("[%s k=%d] serve failed although nothing was cut: %v", mode, k, err)
			}

			if err == nil {
				t.Fatalf("[%s k=%d] serve returned nil although its database connection was cut during start-up", mode, k)
			}

			failedStarts++

			// khởi động lại trên cùng database dở dang, KHÔNG qua proxy: phải hoàn tất
			addr2 := freeAddr(t)
			serveEnv(t, dsn, addr2, boot)

			ctx2, cancel2 := context.WithCancel(context.Background())
			errc2 := make(chan error, 1)

			go func() { errc2 <- serve(ctx2, cancel2, quietLog()) }()

			err2, ready2 := waitServe(t, errc2, addr2)
			if !ready2 {
				cancel2()
				t.Fatalf("[%s k=%d] the restart on the half-initialised database failed: %v", mode, k, err2)
			}

			admin, perr := pgxpool.New(context.Background(), dsn)
			if perr != nil {
				t.Fatal(perr)
			}

			var admins int
			if qerr := admin.QueryRow(context.Background(), `SELECT count(*) FROM admins WHERE email = 'first@example.com'`).Scan(&admins); qerr != nil || admins != 1 {
				t.Errorf("[%s k=%d] after the restart there must be exactly one first admin: %d %v", mode, k, admins, qerr)
			}

			admin.Close()

			cancel2()

			if serr := <-errc2; serr != nil {
				t.Errorf("[%s k=%d] shutdown of the restarted server: %v", mode, k, serr)
			}
		}
	}

	if failedStarts < 6 {
		t.Fatalf("only %d of the sampled cut points actually broke the start-up: the sample is not testing what it should", failedStarts)
	}
}
