package handler

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"vsf/internal/apikey"
	"vsf/internal/model"
	"vsf/internal/store"
	"vsf/internal/testutil/pgfault"
)

// Mất kết nối database giữa hai câu lệnh ở mức HTTP. Chỉ các lời gọi database của handler đi qua proxy làm đứt kết nối
// (xem newAppWith), nên cách đếm vòng đi về là tất định. Điều cần giữ: client không bao giờ nhận thành công giả, trạng
// thái luôn là toàn bộ hoặc không gì, và một sự cố database KHÔNG bị báo thành lỗi của client (401 "sai key").

const httpFaultApp = "vsf_httpfault"

type httpFaultEnv struct {
	*testApp
	proxy *pgfault.Proxy
}

func newHTTPFaultEnv(t *testing.T) *httpFaultEnv {
	t.Helper()

	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping integration test")
	}

	proxy := pgfault.Start(t, pgfault.TargetOf(t, base))

	return &httpFaultEnv{testApp: newAppWith(t, proxy.DSN(t, base)+"&application_name="+httpFaultApp), proxy: proxy}
}

func (e *httpFaultEnv) counts() (entries, changes, audits int) {
	e.t.Helper()

	for table, dst := range map[string]*int{"blacklist_entries": &entries, "change_log": &changes, "audit_logs": &audits} {
		if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM `+table).Scan(dst); err != nil {
			e.t.Fatal(err)
		}
	}

	return
}

// settle chờ tới khi server xử lý xong mọi giao dịch của các kết nối đi qua proxy (kể cả vòng COMMIT đã tới server mà
// client không nhận phản hồi), rồi đọc kết quả mới ổn định.
func (e *httpFaultEnv) settle() {
	e.t.Helper()

	deadline := time.Now().Add(10 * time.Second)

	for {
		var n int
		if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM pg_stat_activity
			WHERE application_name = $1 AND state IN ('active', 'idle in transaction')`, httpFaultApp).Scan(&n); err != nil {
			e.t.Fatal(err)
		}

		if n == 0 {
			return
		}

		if time.Now().After(deadline) {
			e.t.Fatalf("%d backends of the proxied connections are still busy after 10s", n)
		}

		time.Sleep(10 * time.Millisecond)
	}
}

// warm làm vài request khỏe để bỏ các kết nối chết còn sót trong pool của handler (pool chỉ phát hiện kết nối chết khi dùng).
func (e *httpFaultEnv) warm(s *session) {
	e.t.Helper()

	for i := 0; i < 6; i++ {
		if s.get("/admin/check").Code == 200 {
			return
		}
	}

	e.t.Fatal("the handler did not recover after the proxy was healed")
}

// Kết nối bị cắt đột ngột: request đang chạy nhận lỗi 500 hoặc thành công, KHÔNG treo, và handler tự phục hồi sau đó.
func TestAppSelfHealsAfterTheDatabaseConnectionIsCut(t *testing.T) {
	e := newHTTPFaultEnv(t)
	adm := e.login(e.user(model.RoleAdmin))

	if r := adm.get("/admin/entries"); r.Code != 200 {
		t.Fatalf("healthy request: %d", r.Code)
	}

	e.proxy.Cut()

	start := time.Now()
	r := adm.get("/admin/entries")

	if time.Since(start) > 15*time.Second {
		t.Fatalf("a request after the connection was cut took %s", time.Since(start))
	}

	if r.Code != 200 && r.Code != 500 {
		t.Fatalf("after a cut the request must succeed (new connection) or fail cleanly with 500, got %d", r.Code)
	}

	if strings.Contains(r.Body, "EOF") || strings.Contains(r.Body, "pgx") || strings.Contains(r.Body, "conn closed") {
		t.Fatalf("the error page must not leak driver details: %.200s", r.Body)
	}

	e.warm(adm)

	if r := adm.get("/admin/entries"); r.Code != 200 {
		t.Fatalf("the handler must be fully healthy again: %d", r.Code)
	}
}

// Tạo entry qua HTTP, quét mọi điểm đứt (trước / sau mỗi vòng đi về).
func TestAppCreateEntryUnderEveryNetworkCut(t *testing.T) {
	e := newHTTPFaultEnv(t)
	adm := e.login(e.user(model.RoleAdmin))
	ackLost := 0

	for _, mode := range []string{"before", "after"} {
		completed := false

		for k := 1; k <= 40; k++ {
			e.proxy.Heal()
			e.warm(adm)
			e.settle()

			phone := phone9()
			e0, c0, a0 := e.counts()
			cutsBefore := e.proxy.Cuts()

			if mode == "before" {
				e.proxy.FailAtRoundTrip(k)
			} else {
				e.proxy.FailAfterRoundTrip(k)
			}

			form := url.Values{"type": {"phone"}, "match_type": {"exact"}, "value": {phone}, "category": {"scam"}, "risk_score": {"80"}}
			start := time.Now()
			r := adm.do("POST", "/admin/entries", form, htmx)

			cut := e.proxy.Cuts() > cutsBefore

			e.proxy.Heal()
			e.settle()

			if time.Since(start) > 15*time.Second {
				t.Fatalf("[%s k=%d] the request hung for %s", mode, k, time.Since(start))
			}

			e1, c1, a1 := e.counts()
			de, dc, da := e1-e0, c1-c0, a1-a0

			if de != dc || dc != da || de > 1 {
				t.Errorf("[%s k=%d] partial state: entries %+d, change_log %+d, audit %+d (HTTP %d)", mode, k, de, dc, da, r.Code)
			}

			if r.Code == 204 && de != 1 {
				t.Errorf("[%s k=%d] the client was told SUCCESS (204) but the entry was not stored", mode, k)
			}

			if r.Code >= 500 && strings.Contains(r.Body, "EOF") {
				t.Errorf("[%s k=%d] driver error leaked to the client: %.120s", mode, k, r.Body)
			}

			if !cut {
				if r.Code != 204 || de != 1 {
					t.Fatalf("[%s k=%d] nothing was cut but the request did not complete: %d %.100s", mode, k, r.Code, r.Body)
				}

				completed = true

				t.Logf("[%s] the request needs %d database round trips; every cut point 1..%d was exercised", mode, k-1, k-1)

				if k-1 < 3 {
					t.Fatalf("[%s] only %d cut points: the sweep looks too short", mode, k-1)
				}

				break
			}

			if de == 1 {
				// dữ liệu đã được lưu (kể cả khi client nhận 5xx): Bloom filter phải biết, không được có số bị chặn mà báo an toàn
				e.waitBlacklisted("", "phone", phone, true)

				if r.Code != 204 {
					ackLost++
				}
			}
		}

		if !completed {
			t.Fatalf("[%s] still being cut after 40 round trips", mode)
		}
	}

	if ackLost == 0 {
		t.Fatal("no cut point lost only the acknowledgement: the \"after\" mode did not exercise the hardest case")
	}
}

// Sự cố database lúc xác thực API key phải là 503, không phải 401/403: client sẽ không vứt một key đúng chỉ vì database
// đang có sự cố, và hệ thống gọi lại được sau đó.
func TestAppAPIKeyLookupDuringANetworkCutIsServiceUnavailableNotUnauthorized(t *testing.T) {
	e := newHTTPFaultEnv(t)
	ctx := context.Background()

	for _, mode := range []string{"before", "after"} {
		completed := false

		for k := 1; k <= 20; k++ {
			// key mới mỗi lần để chắc chắn là cache miss (phải tra database)
			full, prefix, hash, err := apikey.Generate()
			if err != nil {
				t.Fatal(err)
			}

			if _, err := e.st.CreateAPIKey(ctx, store.NewAPIKey{Name: fmt.Sprintf("net-%s-%d", mode, k), Prefix: prefix, KeyHash: hash, RPSLimit: 100},
				model.Actor{Email: "t"}); err != nil {
				t.Fatal(err)
			}

			e.proxy.Heal()
			e.settle()

			anon := e.anon()
			cutsBefore := e.proxy.Cuts()

			if mode == "before" {
				e.proxy.FailAtRoundTrip(k)
			} else {
				e.proxy.FailAfterRoundTrip(k)
			}

			r := anon.do("GET", "/v1/check?type=phone&value=0901234567", nil, map[string]string{"X-API-Key": full})
			cut := e.proxy.Cuts() > cutsBefore

			e.proxy.Heal()
			e.settle()

			if r.Code == 401 || r.Code == 403 {
				t.Fatalf("[%s k=%d] a database fault was reported as %d (the client would discard a valid key)", mode, k, r.Code)
			}

			if cut && r.Code == 200 {
				t.Fatalf("[%s k=%d] the connection was cut but the key lookup reported success", mode, k)
			}

			if cut && r.Code != 503 {
				t.Errorf("[%s k=%d] a cut lookup must be 503, got %d", mode, k, r.Code)
			}

			if !cut {
				if r.Code != 200 {
					t.Fatalf("[%s k=%d] nothing was cut but the lookup failed: %d", mode, k, r.Code)
				}

				completed = true

				t.Logf("[%s] the key lookup needs %d database round trips; every cut point 1..%d was exercised", mode, k-1, k-1)

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
