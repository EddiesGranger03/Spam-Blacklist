package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"vsf/internal/bloom"
	"vsf/internal/config"
	"vsf/internal/model"
)

// Admin không được tự khóa hoặc tự hạ quyền chính mình (sẽ mất quyền quản trị mà không ai khôi phục được).
func TestAppUserUpdateRules(t *testing.T) {
	a := newApp(t)
	email := a.user(model.RoleAdmin)
	adm := a.login(email)

	me, err := a.st.GetAdminByEmail(context.Background(), email)
	if err != nil {
		t.Fatal(err)
	}

	self := "/admin/users/" + itoa(me.ID)

	for name, f := range map[string]url.Values{
		"disable self":   {"role": {"admin"}, "disabled": {"1"}},
		"downgrade self": {"role": {"viewer"}},
	} {
		if r := adm.do("POST", self, f, nil); r.Code != 200 || !strings.Contains(r.Body, "Không thể tự") {
			t.Errorf("%s must be refused with a message: %d", name, r.Code)
		}
	}

	if after, _ := a.st.GetAdminByEmail(context.Background(), email); after.Role != model.RoleAdmin || after.Disabled {
		t.Fatalf("a refused update must change nothing: %+v", after)
	}

	for name, path := range map[string]string{"unknown id": "/admin/users/999999999", "non-numeric id": "/admin/users/abc"} {
		if r := adm.do("POST", path, url.Values{"role": {"viewer"}}, nil); r.Code != 404 {
			t.Errorf("%s: %d, want 404", name, r.Code)
		}
	}

	if r := adm.do("POST", self, url.Values{"role": {"god"}}, nil); r.Code != 200 || !strings.Contains(r.Body, "không hợp lệ") {
		t.Errorf("an invalid role must be explained: %d", r.Code)
	}

	// Lưu lại chính mình không đổi gì là hợp lệ và KHÔNG được đăng xuất người đó (trước đây UpdateAdmin luôn xóa phiên).
	if r := adm.do("POST", self, url.Values{"role": {"admin"}}, nil); r.Code != 303 {
		t.Errorf("saving yourself unchanged is allowed: %d", r.Code)
	}

	if r := adm.get("/admin/entries"); r.Code != 200 {
		t.Errorf("saving your own account without changing anything must keep you signed in: %d", r.Code)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

var keyRe = regexp.MustCompile(`vsf_[A-Za-z0-9_-]{20,}`)

// Xoay key: key mới kế thừa cấu hình, key cũ hết hạn sau thời gian ân hạn (mặc định 7 ngày khi nhập ngoài 0..90),
// không xoay được key đã thu hồi.
func TestAppAPIKeyRotationRules(t *testing.T) {
	a := newApp(t)
	adm := a.login(a.user(model.RoleAdmin))
	ctx := context.Background()

	create := func() (key string, id int64) {
		r := adm.do("POST", "/admin/apikeys", url.Values{"name": {uniq("rot")}, "rps_limit": {"77"}, "daily_quota": {"123"}, "max_batch": {"30"}}, nil)

		key = keyRe.FindString(r.Body)
		if key == "" {
			t.Fatalf("no key created: %d", r.Code)
		}

		keys, err := a.st.ListAPIKeys(ctx)
		if err != nil {
			t.Fatal(err)
		}

		for _, k := range keys {
			if strings.HasPrefix(key, "vsf_"+k.Prefix) {
				return key, k.ID
			}
		}

		t.Fatal("created key not listed")

		return "", 0
	}

	// ân hạn 0 ngày: key cũ hết hạn ngay
	_, id := create()

	r := adm.do("POST", "/admin/apikeys/"+itoa(id)+"/rotate", url.Values{"grace_days": {"0"}}, nil)
	if r.Code != 200 || keyRe.FindString(r.Body) == "" {
		t.Fatalf("rotate: %d", r.Code)
	}

	old, _ := a.st.GetAPIKey(ctx, id)
	if old.ExpiresAt == nil || old.ExpiresAt.After(time.Now().Add(time.Minute)) {
		t.Fatalf("grace_days=0 must expire the old key now: %v", old.ExpiresAt)
	}

	// giá trị ngoài khoảng dùng mặc định 7 ngày
	_, id2 := create()

	adm.do("POST", "/admin/apikeys/"+itoa(id2)+"/rotate", url.Values{"grace_days": {"999"}}, nil)

	old2, _ := a.st.GetAPIKey(ctx, id2)
	if old2.ExpiresAt == nil || old2.ExpiresAt.Before(time.Now().Add(6*24*time.Hour)) || old2.ExpiresAt.After(time.Now().Add(8*24*time.Hour)) {
		t.Fatalf("an out-of-range grace falls back to 7 days: %v", old2.ExpiresAt)
	}

	// key mới kế thừa cấu hình và ghi nhận nguồn gốc
	keys, _ := a.st.ListAPIKeys(ctx)

	var child *model.APIKey

	for i := range keys {
		if keys[i].RotatedFrom != nil && *keys[i].RotatedFrom == id2 {
			child = &keys[i]
		}
	}

	if child == nil || child.RPSLimit != 77 || child.DailyQuota != 123 || child.MaxBatch != 30 || child.Status != "active" {
		t.Fatalf("the new key must inherit the settings: %+v", child)
	}

	// key đã thu hồi hoặc không tồn tại: không xoay được
	_, id3 := create()

	if r := adm.do("POST", "/admin/apikeys/"+itoa(id3)+"/revoke", url.Values{}, nil); r.Code != 303 {
		t.Fatalf("revoke: %d", r.Code)
	}

	if r := adm.do("POST", "/admin/apikeys/"+itoa(id3)+"/rotate", url.Values{}, nil); r.Code != 404 {
		t.Errorf("rotating a revoked key: %d, want 404", r.Code)
	}

	if r := adm.do("POST", "/admin/apikeys/"+itoa(id3)+"/revoke", url.Values{}, nil); r.Code != 404 {
		t.Errorf("revoking twice: %d, want 404", r.Code)
	}
}

// /readyz: Bloom chưa dựng xong thì báo chưa sẵn sàng; chi tiết lỗi chỉ lộ cho loopback.
func TestAppReadyzReportsProblems(t *testing.T) {
	a := newApp(t)

	h2 := *a.h
	h2.Bloom = bloom.NewManager() // chưa dựng

	call := func(remote string) (int, string) {
		r := httptest.NewRequest("GET", "/readyz", nil)
		r.RemoteAddr = remote

		w := httptest.NewRecorder()
		h2.readyz(w, r)

		return w.Code, w.Body.String()
	}

	code, body := call("127.0.0.1:1234")
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "bloom") {
		t.Errorf("loopback must see the problem: %d %s", code, body)
	}

	code, body = call("203.0.113.9:1234")
	if code != http.StatusServiceUnavailable || strings.Contains(body, "bloom") || strings.Contains(body, "problems") {
		t.Errorf("a remote caller must see only the status: %d %s", code, body)
	}
}

func TestPeerIPAndSameOriginAndDeviceCookieName(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)

	r.RemoteAddr = "203.0.113.5:4000"
	if got := peerIP(r); got != "203.0.113.5" {
		t.Errorf("peerIP = %q", got)
	}

	r.RemoteAddr = "[2001:db8::1]:4000"
	if got := peerIP(r); got != "2001:db8::1" {
		t.Errorf("peerIP ipv6 = %q", got)
	}

	r.RemoteAddr = "no-port"
	if got := peerIP(r); got != "no-port" {
		t.Errorf("peerIP without a port must return it unchanged: %q", got)
	}

	cases := []struct {
		name   string
		origin string
		fetch  string
		want   bool
	}{
		{"same origin header", "http://example.com", "", true},
		{"other origin", "http://evil.example", "", false},
		{"unparsable origin", "http://[::1", "", false},
		{"fetch same-origin", "", "same-origin", true},
		{"fetch none (typed URL)", "", "none", true},
		{"fetch cross-site", "", "cross-site", false},
		{"fetch same-site", "", "same-site", false},
		{"no headers (non-browser client)", "", "", true},
	}

	for _, c := range cases {
		req := httptest.NewRequest("POST", "http://example.com/x", nil)

		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}

		if c.fetch != "" {
			req.Header.Set("Sec-Fetch-Site", c.fetch)
		}

		if got := sameOrigin(req); got != c.want {
			t.Errorf("%s: sameOrigin = %v, want %v", c.name, got, c.want)
		}
	}

	insecure := &Handler{Deps: Deps{Cfg: config.Config{}}}
	secure := &Handler{Deps: Deps{Cfg: config.Config{CookieSecure: true}}}

	if insecure.deviceCookieName() != "vsf_device" || secure.deviceCookieName() != "__Host-vsf_device" {
		t.Errorf("cookie names: %q %q", insecure.deviceCookieName(), secure.deviceCookieName())
	}
}
