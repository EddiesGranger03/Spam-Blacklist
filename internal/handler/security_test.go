package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"vsf/internal/config"
)

// newSecHandler tạo Handler test với danh sách proxy và token metrics cho trước.
func newSecHandler(t *testing.T, proxies, token string) *Handler {
	t.Helper()

	nets, err := config.ParseCIDRs(proxies)
	if err != nil {
		t.Fatal(err)
	}

	return &Handler{Deps: Deps{Cfg: config.Config{TrustedProxies: nets, MetricsToken: token}}}
}

// TestClientIP kiểm tra clientIP với các trường hợp X-Forwarded-For.
func TestClientIP(t *testing.T) {
	cases := []struct {
		name, proxies, remote string
		xff                   []string
		want                  string
	}{
		{"no trusted config ignores XFF", "", "203.0.113.9:1234", []string{"1.1.1.1"}, "203.0.113.9"},
		{"untrusted peer cannot spoof", "10.0.0.0/8", "203.0.113.9:1234", []string{"1.1.1.1"}, "203.0.113.9"},
		{"trusted peer uses XFF", "10.0.0.0/8", "10.0.0.2:80", []string{"198.51.100.7"}, "198.51.100.7"},
		{"spoofed left hop ignored", "10.0.0.0/8", "10.0.0.2:80", []string{"6.6.6.6, 198.51.100.7"}, "198.51.100.7"},
		{"multi trusted hops", "10.0.0.0/8", "10.0.0.2:80", []string{"198.51.100.7, 10.0.0.5"}, "198.51.100.7"},
		{"multiple header lines", "10.0.0.0/8", "10.0.0.2:80", []string{"6.6.6.6", "198.51.100.7"}, "198.51.100.7"},
		{"garbage XFF falls back to peer", "10.0.0.0/8", "10.0.0.2:80", []string{"not-an-ip"}, "10.0.0.2"},
		{"trusted peer without XFF", "10.0.0.0/8", "10.0.0.2:80", nil, "10.0.0.2"},
		{"ipv6 client", "10.0.0.0/8", "10.0.0.2:80", []string{"2001:db8::1"}, "2001:db8::1"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newSecHandler(t, c.proxies, "")
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = c.remote

			for _, v := range c.xff {
				r.Header.Add("X-Forwarded-For", v)
			}

			if got := h.clientIP(r); got != c.want {
				t.Fatalf("got %s want %s", got, c.want)
			}
		})
	}
}

// TestMetricsAuth kiểm tra bảo vệ /metrics bằng token hoặc loopback.
func TestMetricsAuth(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })

	do := func(h *Handler, remote, auth string) int {
		r := httptest.NewRequest("GET", "/metrics", nil)
		r.RemoteAddr = remote

		if auth != "" {
			r.Header.Set("Authorization", auth)
		}

		w := httptest.NewRecorder()
		h.metricsAuth(ok).ServeHTTP(w, r)

		return w.Code
	}

	noTok := newSecHandler(t, "", "")
	if c := do(noTok, "127.0.0.1:1", ""); c != 200 {
		t.Fatalf("loopback without token: %d", c)
	}

	if c := do(noTok, "[::1]:1", ""); c != 200 {
		t.Fatalf("ipv6 loopback: %d", c)
	}

	if c := do(noTok, "203.0.113.9:1", ""); c != 403 {
		t.Fatalf("remote without token config: %d", c)
	}

	withTok := newSecHandler(t, "", "s3cret-token")
	for auth, want := range map[string]int{"": 401, "Bearer wrong": 401, "s3cret-token": 401, "Bearer s3cret-token": 200} {
		if c := do(withTok, "203.0.113.9:1", auth); c != want {
			t.Fatalf("auth %q: got %d want %d", auth, c, want)
		}
	}
}
