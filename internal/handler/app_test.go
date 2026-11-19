package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"vsf/internal/apikey"
	"vsf/internal/auth"
	"vsf/internal/filter"
	"vsf/internal/cache"
	"vsf/internal/changefeed"
	"vsf/internal/checker"
	"vsf/internal/config"
	"vsf/internal/inspector"
	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/seal"
	"vsf/internal/store"
)

// Bộ test này dựng MỘT ứng dụng đầy đủ (Postgres thật, Bloom, changefeed, checker, API key, Router thật) và gọi nó
// qua HTTP như trình duyệt/khách API. Nó chỉ THÊM dữ liệu có email/tên ngẫu nhiên, không xóa hay sửa dữ liệu có sẵn,
// và bỏ qua nếu không có TEST_DATABASE_URL (tên DB phải kết thúc bằng "_test").

const appPass = "Sup3r-Secret-Pass"

type testApp struct {
	t    *testing.T
	h    *Handler
	srv  *httptest.Server
	st   *store.Store
	feed *changefeed.Feed
	pool *pgxpool.Pool
	hash string
}

func newApp(t *testing.T) *testApp { return newAppWith(t, "") }

// newAppWith như newApp. Nếu handlerDSN khác rỗng thì CHỈ các lời gọi database của handler (phiên, entry, API key, audit)
// đi qua DSN đó (thường là proxy làm đứt kết nối); changefeed, Bloom và checker vẫn dùng kết nối thẳng, để các truy vấn
// nền không làm lệch cách đếm vòng đi về của proxy.
func newAppWith(t *testing.T, handlerDSN string) *testApp {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping integration test")
	}

	if !strings.HasSuffix(dsnDBName(dsn), "_test") {
		t.Fatal("TỪ CHỐI chạy: TEST_DATABASE_URL phải trỏ vào database có tên kết thúc bằng _test")
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

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
	st.SetAuditKey(store.AuditKeyFrom("", "app-test-session-secret-0123456789"))

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(pool.Close)

	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('admins') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}

	if !exists {
		if err := st.Migrate(ctx); err != nil {
			t.Fatalf("migrate: %v", err)
		}
	}

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	bm := filter.NewManager()
	feed := changefeed.New(st, bm, log)

	if err := feed.Init(ctx, 10_000); err != nil {
		t.Fatalf("feed init: %v", err)
	}

	go feed.Run(ctx, 50*time.Millisecond)

	chk := checker.New("VN", bm, cache.Noop{}, st, feed)
	chk.SetCacheSealer(sl)

	hst := st // store mà handler dùng

	if handlerDSN != "" {
		var herr error

		hst, herr = store.New(ctx, handlerDSN, "", 4)
		if herr != nil {
			t.Fatal(herr)
		}

		hst.SetSealer(sl)
		hst.SetAuditKey(store.AuditKeyFrom("", "app-test-session-secret-0123456789"))
		t.Cleanup(hst.Close)
	}

	keys := apikey.NewService(hst, nil, 1000)

	cfg := config.Config{SessionSecret: "app-test-session-secret-0123456789", DefaultRegion: "VN", AppEnv: "development"}

	h, err := New(Deps{Cfg: cfg, Log: log, Store: hst, Checker: chk, Feed: feed, Bloom: bm, APIKeys: keys, Inspector: inspector.New(50)})
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(h.Router())
	t.Cleanup(srv.Close)

	hash, err := auth.HashPassword(appPass)
	if err != nil {
		t.Fatal(err)
	}

	return &testApp{t: t, h: h, srv: srv, st: st, feed: feed, pool: pool, hash: hash}
}

// user tạo một tài khoản với vai trò role và trả về email.
func (a *testApp) user(role model.Role) string {
	a.t.Helper()

	email := fmt.Sprintf("app-%s-%d@example.com", role, time.Now().UnixNano())
	if _, err := a.st.CreateAdmin(context.Background(), email, a.hash, role, model.Actor{Email: "test"}); err != nil {
		a.t.Fatal(err)
	}

	return email
}

type session struct {
	a    *testApp
	c    *http.Client
	csrf string
}

type reply struct {
	Code   int
	Body   string
	Header http.Header
}

func (a *testApp) client() *http.Client {
	jar, _ := cookiejar.New(nil)

	return &http.Client{Jar: jar, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// anon là một khách chưa đăng nhập.
func (a *testApp) anon() *session { return &session{a: a, c: a.client()} }

var csrfRe = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// login đăng nhập bằng email và trả về phiên có CSRF token.
func (a *testApp) login(email string) *session {
	a.t.Helper()

	s := a.anon()

	r := s.do("POST", "/admin/login", url.Values{"email": {email}, "password": {appPass}}, nil)
	if r.Code != http.StatusSeeOther {
		a.t.Fatalf("login %s: %d %s", email, r.Code, r.Body)
	}

	page := s.do("GET", "/admin/check", nil, nil)
	if m := csrfRe.FindStringSubmatch(page.Body); m != nil {
		s.csrf = m[1]
	}

	if s.csrf == "" {
		a.t.Fatalf("no csrf token on page after login (status %d)", page.Code)
	}

	return s
}

func (s *session) do(method, path string, form url.Values, hdr map[string]string) reply {
	s.a.t.Helper()

	var body io.Reader

	if form != nil {
		if s.csrf != "" && form.Get("csrf_token") == "" {
			form.Set("csrf_token", s.csrf)
		}

		body = strings.NewReader(form.Encode())
	}

	req, err := http.NewRequest(method, s.a.srv.URL+path, body)
	if err != nil {
		s.a.t.Fatal(err)
	}

	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	if s.csrf != "" {
		req.Header.Set("X-CSRF-Token", s.csrf)
	}

	for k, v := range hdr {
		req.Header.Set(k, v)
	}

	return s.send(req)
}

func (s *session) send(req *http.Request) reply {
	s.a.t.Helper()

	resp, err := s.c.Do(req)
	if err != nil {
		s.a.t.Fatal(err)
	}

	defer resp.Body.Close()

	b, _ := io.ReadAll(resp.Body)

	return reply{Code: resp.StatusCode, Body: string(b), Header: resp.Header}
}

func (s *session) get(path string) reply { return s.do("GET", path, nil, nil) }

// upload gửi một file CSV tới /admin/import.
func (s *session) upload(csv, defaultType string) reply {
	s.a.t.Helper()

	var buf strings.Builder

	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("csrf_token", s.csrf)
	_ = mw.WriteField("default_type", defaultType)
	fw, _ := mw.CreateFormFile("file", "data.csv")
	_, _ = fw.Write([]byte(csv))
	_ = mw.Close()

	req, _ := http.NewRequest("POST", s.a.srv.URL+"/admin/import", strings.NewReader(buf.String()))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-CSRF-Token", s.csrf)

	return s.send(req)
}

var htmx = map[string]string{"HX-Request": "true"}

func uniq(prefix string) string { return fmt.Sprintf("%s%d", prefix, time.Now().UnixNano()) }

// phone9 trả một số điện thoại VN hợp lệ, khác nhau giữa các lần gọi.
func phone9() string { return fmt.Sprintf("09%08d", time.Now().UnixNano()%100_000_000) }

func (a *testApp) waitBlacklisted(key, typ, value string, want bool) {
	a.t.Helper()

	deadline := time.Now().Add(5 * time.Second)

	for {
		res, err := a.h.Checker.Check(context.Background(), normalize.Type(typ), value)
		if err == nil && res.Blacklisted == want {
			return
		}

		if time.Now().After(deadline) {
			a.t.Fatalf("%s %s: blacklisted=%v after 5s, want %v (err=%v)", typ, value, res.Blacklisted, want, err)
		}

		time.Sleep(50 * time.Millisecond)
	}
}

// ---- công khai và đăng nhập --------------------------------------------------------------------------------------

func TestAppPublicEndpointsAndLogin(t *testing.T) {
	a := newApp(t)
	s := a.anon()

	for path, want := range map[string]int{"/healthz": 200, "/readyz": 200, "/metrics": 200, "/static/style.css": 200,
		"/static/nope.css": 404, "/admin/login": 200} {
		if r := s.get(path); r.Code != want {
			t.Errorf("GET %s = %d, want %d", path, r.Code, want)
		}
	}

	if r := s.get("/readyz"); !strings.Contains(r.Body, "ready") {
		t.Errorf("readyz body: %s", r.Body)
	}

	if r := s.get("/metrics"); !strings.Contains(r.Body, "vsf_http_request_duration_seconds") {
		t.Error("metrics must expose the request histogram")
	}

	if r := s.get("/"); r.Code != 303 || r.Header.Get("Location") != "/admin/entries" {
		t.Errorf("root redirect: %d %s", r.Code, r.Header.Get("Location"))
	}

	// chưa đăng nhập: chuyển tới trang đăng nhập; HTMX nhận 401 + HX-Redirect
	if r := s.get("/admin/entries"); r.Code != 303 || r.Header.Get("Location") != "/admin/login" {
		t.Errorf("unauthenticated admin page: %d %s", r.Code, r.Header.Get("Location"))
	}

	if r := s.do("GET", "/admin/entries", nil, map[string]string{"HX-Request": "true"}); r.Code != 401 || r.Header.Get("HX-Redirect") == "" {
		t.Errorf("htmx unauthenticated: %d %v", r.Code, r.Header)
	}

	// cookie rác bị xóa
	bad := a.anon()
	if r := bad.do("GET", "/admin/entries", nil, map[string]string{"Cookie": "vsf_session=not-a-real-token"}); r.Code != 303 {
		t.Errorf("bogus session cookie: %d", r.Code)
	}

	email := a.user(model.RoleAdmin)

	if r := a.anon().do("POST", "/admin/login", url.Values{"email": {email}, "password": {"wrong"}}, nil); r.Code != 401 ||
		!strings.Contains(r.Body, "không đúng") {
		t.Errorf("bad password: %d", r.Code)
	}

	if r := a.anon().do("POST", "/admin/login", url.Values{"email": {"nobody@example.com"}, "password": {"x"}}, nil); r.Code != 401 {
		t.Errorf("unknown user: %d", r.Code)
	}

	// khác origin bị từ chối
	if r := a.anon().do("POST", "/admin/login", url.Values{"email": {email}, "password": {appPass}},
		map[string]string{"Origin": "http://evil.example"}); r.Code != 403 {
		t.Errorf("cross-origin login: %d", r.Code)
	}

	// đăng nhập đúng rồi đăng xuất: phiên không còn dùng được
	adm := a.login(email)
	if r := adm.get("/admin/entries"); r.Code != 200 {
		t.Fatalf("entries after login: %d", r.Code)
	}

	su, _ := url.Parse(a.srv.URL)
	stolen := adm.c.Jar.Cookies(su) // cookie phiên trước khi đăng xuất

	if r := adm.do("POST", "/admin/logout", url.Values{}, nil); r.Code != 303 {
		t.Errorf("logout: %d", r.Code)
	}

	// phiên phải bị hủy Ở PHÍA SERVER: dùng lại đúng cookie cũ cũng không vào được
	replay := a.anon()
	replay.c.Jar.SetCookies(su, stolen)

	if r := replay.get("/admin/entries"); r.Code != 303 {
		t.Errorf("a logged-out session cookie must not work again: %d", r.Code)
	}

	if r := adm.get("/admin/entries"); r.Code != 303 {
		t.Errorf("session must be gone after logout: %d", r.Code)
	}
}

func TestAppCSRFAndRoles(t *testing.T) {
	a := newApp(t)
	viewer := a.login(a.user(model.RoleViewer))
	editor := a.login(a.user(model.RoleEditor))

	// viewer xem được nhưng không ghi được
	for _, p := range []string{"/admin/entries", "/admin/check"} {
		if r := viewer.get(p); r.Code != 200 {
			t.Errorf("viewer GET %s = %d", p, r.Code)
		}
	}

	for _, p := range []string{"/admin/entries/new", "/admin/import", "/admin/export", "/admin/audit", "/admin/users", "/admin/apikeys",
		"/admin/inspector"} {
		if r := viewer.get(p); r.Code != 403 {
			t.Errorf("viewer GET %s = %d, want 403", p, r.Code)
		}
	}

	// editor ghi được entry nhưng không quản trị
	for _, p := range []string{"/admin/entries/new", "/admin/import", "/admin/audit"} {
		if r := editor.do("GET", p, nil, htmx); r.Code != 200 {
			t.Errorf("editor GET %s = %d", p, r.Code)
		}
	}

	for _, p := range []string{"/admin/users", "/admin/apikeys", "/admin/inspector", "/admin/audit/verify"} {
		if r := editor.get(p); r.Code != 403 {
			t.Errorf("editor GET %s = %d, want 403", p, r.Code)
		}
	}

	// thiếu CSRF token hoặc sai nguồn: 403
	noCSRF := &session{a: a, c: editor.c}
	if r := noCSRF.do("POST", "/admin/check", url.Values{"type": {"phone"}, "value": {"0901234567"}}, nil); r.Code != 403 {
		t.Errorf("POST without csrf token: %d", r.Code)
	}

	if r := editor.do("POST", "/admin/check", url.Values{"type": {"phone"}, "value": {"0901234567"}},
		map[string]string{"Origin": "http://evil.example"}); r.Code != 403 {
		t.Errorf("POST from another origin: %d", r.Code)
	}

	if r := editor.do("POST", "/admin/check", url.Values{"type": {"phone"}, "value": {"0901234567"}},
		map[string]string{"X-CSRF-Token": "wrong"}); r.Code != 403 {
		t.Errorf("POST with a wrong csrf token: %d", r.Code)
	}
}

// ---- entry ---------------------------------------------------------------------------------------------------

func TestAppEntriesLifecycle(t *testing.T) {
	a := newApp(t)
	adm := a.login(a.user(model.RoleAdmin))
	phone := phone9()

	if r := adm.do("GET", "/admin/entries/new", nil, htmx); r.Code != 200 || !strings.Contains(r.Body, "risk_score") {
		t.Fatalf("new form: %d", r.Code)
	}

	// không phải HTMX thì quay về danh sách
	if r := adm.get("/admin/entries/new"); r.Code != 303 {
		t.Errorf("new form without htmx: %d", r.Code)
	}

	create := func(f url.Values) reply { return adm.do("POST", "/admin/entries", f, htmx) }
	valid := url.Values{"type": {"phone"}, "match_type": {"exact"}, "value": {phone}, "category": {"scam"}, "risk_score": {"80"},
		"source": {"test"}, "note": {"note"}}

	if r := create(valid); r.Code != 204 || !strings.Contains(r.Header.Get("HX-Redirect"), "created") {
		t.Fatalf("create: %d %s", r.Code, r.Body)
	}

	a.waitBlacklisted("", "phone", phone, true)

	if r := create(valid); r.Code != 200 || !strings.Contains(r.Body, "đã có") {
		t.Errorf("duplicate must show an error: %d", r.Code)
	}

	for name, f := range map[string]url.Values{
		"bad type":  {"type": {"fax"}, "match_type": {"exact"}, "value": {"1"}, "category": {"scam"}, "risk_score": {"5"}},
		"bad score": {"type": {"phone"}, "match_type": {"exact"}, "value": {phone9()}, "category": {"scam"}, "risk_score": {"abc"}},
		"bad value": {"type": {"phone"}, "match_type": {"exact"}, "value": {"not-a-number"}, "category": {"scam"}, "risk_score": {"5"}},
	} {
		if r := create(f); r.Code != 200 {
			t.Errorf("%s: got %d, want the form re-rendered with an error", name, r.Code)
		}
	}

	// danh sách có bộ lọc, phân trang theo chiều, HTMX trả bảng
	list, _, err := a.st.ListEntries(context.Background(), store.ListFilter{Type: "phone", Limit: 5})
	if err != nil || len(list) == 0 {
		t.Fatalf("seeded entry not listed: %v", err)
	}

	id := list[0].ID

	for _, q := range []string{"", "?type=phone", "?type=url&category=scam", "?dir=asc", fmt.Sprintf("?after=%d&dir=desc", id+1), "?category=bogus"} {
		if r := adm.get("/admin/entries" + q); r.Code != 200 {
			t.Errorf("list %q: %d", q, r.Code)
		}
	}

	if r := adm.do("GET", "/admin/entries", nil, map[string]string{"HX-Request": "true"}); r.Code != 200 ||
		strings.Contains(r.Body, "<html") {
		t.Errorf("htmx list must return only the table: %d", r.Code)
	}

	// sửa / xóa
	editPath := fmt.Sprintf("/admin/entries/%d", id)
	if r := adm.do("GET", editPath+"/edit", nil, htmx); r.Code != 200 {
		t.Errorf("edit form: %d", r.Code)
	}

	if r := adm.do("GET", "/admin/entries/999999999/edit", nil, htmx); r.Code != 404 {
		t.Errorf("edit missing: %d", r.Code)
	}

	if r := adm.do("GET", "/admin/entries/abc/edit", nil, htmx); r.Code != 404 {
		t.Errorf("edit bad id: %d", r.Code)
	}

	upd := url.Values{"type": {"phone"}, "match_type": {"exact"}, "value": {phone}, "category": {"spam"}, "risk_score": {"42"},
		"source": {"s2"}, "note": {"n2"}, "status": {"WHITELIST"}}
	if r := adm.do("PUT", editPath, upd, htmx); r.Code != 204 {
		t.Errorf("update: %d %s", r.Code, r.Body)
	}

	// WHITELIST: không còn bị chặn.
	a.waitBlacklisted("", "phone", phone, false)

	// Đổi status không hợp lệ -> form lỗi (200); đổi value sang giá trị đã có ở entry khác -> 409.
	bad := url.Values{"type": {"phone"}, "match_type": {"exact"}, "value": {phone}, "category": {"spam"}, "risk_score": {"42"}, "status": {"MAYBE"}}
	if r := adm.do("PUT", editPath, bad, htmx); r.Code != 200 {
		t.Errorf("invalid status should re-render the form: %d", r.Code)
	}

	other := phone9()
	oth := url.Values{"type": {"phone"}, "match_type": {"exact"}, "value": {other}, "category": {"scam"}, "risk_score": {"10"}}

	if r := create(oth); r.Code != 204 {
		t.Fatalf("create other: %d %s", r.Code, r.Body)
	}

	clash := url.Values{"type": {"phone"}, "match_type": {"exact"}, "value": {other}, "category": {"spam"}, "risk_score": {"42"}}
	if r := adm.do("PUT", editPath, clash, htmx); r.Code != 409 || !strings.Contains(r.Body, "đã có") {
		t.Errorf("value clash must be 409: %d %s", r.Code, r.Body)
	}

	if r := adm.do("PUT", editPath, url.Values{"risk_score": {"zzz"}}, htmx); r.Code != 200 {
		t.Errorf("update with a bad score should re-render the form: %d", r.Code)
	}

	if r := adm.do("PUT", "/admin/entries/999999999", upd, htmx); r.Code != 404 {
		t.Errorf("update missing: %d", r.Code)
	}

	if r := adm.do("DELETE", editPath, nil, nil); r.Code != 200 {
		t.Errorf("delete: %d", r.Code)
	}

	a.waitBlacklisted("", "phone", phone, false)

	if r := adm.do("DELETE", editPath, nil, nil); r.Code != 200 { // xóa lại: idempotent
		t.Errorf("delete twice: %d", r.Code)
	}

	if r := adm.do("DELETE", "/admin/entries/abc", nil, nil); r.Code != 404 {
		t.Errorf("delete bad id: %d", r.Code)
	}
}

func TestAppCheckPage(t *testing.T) {
	a := newApp(t)
	adm := a.login(a.user(model.RoleViewer))

	if r := adm.get("/admin/check"); r.Code != 200 {
		t.Fatalf("check page: %d", r.Code)
	}

	phone := phone9()
	if _, err := a.st.CreateEntry(context.Background(), mustNormalize(t, "phone", "exact", phone),
		model.EntryInput{Category: "scam", RiskScore: 70}, model.Actor{Email: "t"}); err != nil {
		t.Fatal(err)
	}

	a.waitBlacklisted("", "phone", phone, true)

	if r := adm.do("POST", "/admin/check", url.Values{"type": {"phone"}, "value": {phone}}, htmx); r.Code != 200 ||
		!strings.Contains(r.Body, "BỊ BLACKLIST") || !strings.Contains(r.Body, "scam") {
		t.Errorf("check blacklisted: %d %.300s", r.Code, r.Body)
	}

	if r := adm.do("POST", "/admin/check", url.Values{"type": {"phone"}, "value": {phone}}, nil); r.Code != 200 {
		t.Errorf("check blacklisted (full page): %d", r.Code)
	}

	if r := adm.do("POST", "/admin/check", url.Values{"type": {"phone"}, "value": {phone9()}}, nil); r.Code != 200 {
		t.Errorf("check clean: %d", r.Code)
	}

	if r := adm.do("POST", "/admin/check", url.Values{"type": {"phone"}, "value": {"abc"}}, nil); r.Code != 200 ||
		!strings.Contains(r.Body, "abc") {
		t.Errorf("check invalid input: %d", r.Code)
	}

	if r := adm.do("POST", "/admin/check", url.Values{"type": {"url"}, "value": {"http://evil.example/x"}}, map[string]string{"HX-Request": "true"}); r.Code != 200 {
		t.Errorf("htmx check: %d", r.Code)
	}

	// Số WHITELIST không nằm trong filter nên đường check thật trả "an toàn"; trang admin phải ghi rõ là WHITELIST.
	white := phone9()
	if _, err := a.st.CreateEntry(context.Background(), mustNormalize(t, "phone", "exact", white),
		model.EntryInput{Status: model.StatusWhitelist, Category: "other", RiskScore: 10}, model.Actor{Email: "t"}); err != nil {
		t.Fatal(err)
	}

	if r := adm.do("POST", "/admin/check", url.Values{"type": {"phone"}, "value": {white}}, htmx); r.Code != 200 ||
		!strings.Contains(r.Body, "WHITELIST") || strings.Contains(r.Body, "BỊ BLACKLIST") {
		t.Errorf("check whitelisted: %d %.300s", r.Code, r.Body)
	}
}

func mustNormalize(t *testing.T, typ, mt, v string) normalize.Key {
	t.Helper()

	k, err := normalize.NormalizeEntry(normalize.Type(typ), normalize.MatchType(mt), v, "VN")
	if err != nil {
		t.Fatal(err)
	}

	return k
}

// ---- import / export -----------------------------------------------------------------------------------------

func TestAppImportAndExport(t *testing.T) {
	a := newApp(t)
	adm := a.login(a.user(model.RoleAdmin))

	if r := adm.get("/admin/import"); r.Code != 200 {
		t.Fatalf("import page: %d", r.Code)
	}

	good1, good2 := phone9(), "09"+fmt.Sprintf("%08d", (time.Now().UnixNano()/7)%100_000_000)
	csv := "value,category,risk_score,note\n" + good1 + ",scam,90,first\n" + good2 + ",spam,50,=cmd|' /C calc'!A0\nnot-a-phone,scam,10,bad\n"

	r := adm.upload(csv, "phone")
	if r.Code != 200 {
		t.Fatalf("upload: %d %s", r.Code, r.Body)
	}

	m := regexp.MustCompile(`/admin/import/([0-9a-f]+)`).FindStringSubmatch(r.Body)
	if m == nil {
		t.Fatalf("no job id in the response: %s", r.Body)
	}

	deadline := time.Now().Add(15 * time.Second)

	var status reply

	for {
		status = adm.get("/admin/import/" + m[1])
		if status.Code == 200 && (strings.Contains(status.Body, "done") || strings.Contains(status.Body, "Hoàn")) ||
			time.Now().After(deadline) {
			break
		}

		time.Sleep(100 * time.Millisecond)
	}

	if status.Code != 200 {
		t.Fatalf("job status: %d", status.Code)
	}

	a.waitBlacklisted("", "phone", good1, true)
	a.waitBlacklisted("", "phone", good2, true)

	if r := adm.get("/admin/import/doesnotexist"); r.Code != 404 {
		t.Errorf("unknown job: %d", r.Code)
	}

	// export: có tiêu đề, có dòng vừa nhập, ô bắt đầu bằng "=" bị vô hiệu hóa (CSV injection)
	exp := adm.get("/admin/export?type=phone")
	if exp.Code != 200 || !strings.HasPrefix(exp.Header.Get("Content-Type"), "text/csv") ||
		!strings.HasPrefix(exp.Body, "type,value,match_type") || !strings.Contains(exp.Body, good1[1:]) {
		t.Fatalf("export: %d %.200s", exp.Code, exp.Body)
	}

	if strings.Contains(exp.Body, ",=cmd") {
		t.Error("a note that starts with '=' must be neutralised in the export")
	}

	if r := adm.get("/admin/export?type=bogus"); r.Code != 200 {
		t.Errorf("export with an unknown type falls back to all: %d", r.Code)
	}

	// file không phải multipart
	if r := adm.do("POST", "/admin/import", url.Values{"x": {"y"}}, nil); r.Code != 400 {
		t.Errorf("non-multipart import: %d", r.Code)
	}

	// audit ghi cả bắt đầu lẫn kết thúc, và kết thúc báo đúng trạng thái và số dòng
	var endDetail string
	if err := a.pool.QueryRow(context.Background(), `SELECT detail::text FROM audit_logs WHERE action = 'entry.export.end'
		ORDER BY id DESC LIMIT 1`).Scan(&endDetail); err != nil || !strings.Contains(endDetail, `"complete"`) || strings.Contains(endDetail, `"rows": 0`) {
		t.Errorf("export end audit: %q %v", endDetail, err)
	}

	// audit có start và end của export
	audit := adm.get("/admin/audit")
	if audit.Code != 200 || !strings.Contains(audit.Body, "entry.export") {
		t.Errorf("audit page must list the export: %d", audit.Code)
	}
}

func TestCSVSafe(t *testing.T) {
	for in, want := range map[string]string{"": "", "abc": "abc", "=1+1": "'=1+1", "+84": "'+84", "-5": "'-5", "@x": "'@x",
		"\tx": "'\tx", "a=b": "a=b"} {
		if got := csvSafe(in); got != want {
			t.Errorf("csvSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

// ---- quản trị: người dùng, API key, audit, inspector -------------------------------------------------------

func TestAppUsersAndAudit(t *testing.T) {
	a := newApp(t)
	adm := a.login(a.user(model.RoleAdmin))

	if r := adm.get("/admin/users"); r.Code != 200 {
		t.Fatalf("users page: %d", r.Code)
	}

	email := uniq("new-") + "@example.com"
	create := func(f url.Values) reply { return adm.do("POST", "/admin/users", f, nil) }

	if r := create(url.Values{"email": {email}, "password": {"long-enough-pass"}, "role": {"editor"}}); r.Code != 303 {
		t.Fatalf("create user: %d %s", r.Code, r.Body)
	}

	for name, f := range map[string]url.Values{
		"duplicate":      {"email": {email}, "password": {"long-enough-pass"}, "role": {"editor"}},
		"bad email":      {"email": {"nope"}, "password": {"long-enough-pass"}, "role": {"editor"}},
		"short password": {"email": {uniq("x") + "@e.com"}, "password": {"short"}, "role": {"editor"}},
		"bad role":       {"email": {uniq("y") + "@e.com"}, "password": {"long-enough-pass"}, "role": {"god"}},
	} {
		if r := create(f); r.Code != 200 {
			t.Errorf("%s: %d, want the page re-rendered with a message", name, r.Code)
		}
	}

	admins, err := a.st.ListAdmins(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var id int64

	for _, u := range admins {
		if u.Email == email {
			id = u.ID
		}
	}

	if id == 0 {
		t.Fatal("created user not found")
	}

	upd := func(f url.Values) reply { return adm.do("POST", fmt.Sprintf("/admin/users/%d", id), f, nil) }

	if r := upd(url.Values{"role": {"viewer"}, "disabled": {"1"}}); r.Code != 303 {
		t.Errorf("update user: %d %s", r.Code, r.Body)
	}

	if r := upd(url.Values{"role": {"bogus"}}); r.Code == 303 {
		t.Errorf("an invalid role must be rejected, got %d", r.Code)
	}

	if r := adm.do("POST", "/admin/users/abc", url.Values{"role": {"viewer"}}, nil); r.Code != 404 && r.Code != 400 {
		t.Errorf("bad user id: %d", r.Code)
	}

	// người bị khóa không đăng nhập được
	if r := a.anon().do("POST", "/admin/login", url.Values{"email": {email}, "password": {"long-enough-pass"}}, nil); r.Code != 401 {
		t.Errorf("a disabled user must not log in: %d", r.Code)
	}

	// audit: trang, phân trang, HTMX, xác minh chuỗi hash
	for _, p := range []string{"/admin/audit", "/admin/audit?before=999999999", "/admin/audit?before=abc"} {
		if r := adm.get(p); r.Code != 200 {
			t.Errorf("audit %s: %d", p, r.Code)
		}
	}

	if r := adm.do("GET", "/admin/audit", nil, map[string]string{"HX-Request": "true"}); r.Code != 200 {
		t.Errorf("audit htmx: %d", r.Code)
	}

	if r := adm.get("/admin/audit/verify"); r.Code != 200 {
		t.Errorf("audit verify: %d %s", r.Code, r.Body)
	}
}

func TestAppAPIKeysAndCheckAPI(t *testing.T) {
	a := newApp(t)
	adm := a.login(a.user(model.RoleAdmin))

	if r := adm.get("/admin/apikeys"); r.Code != 200 {
		t.Fatalf("apikeys page: %d", r.Code)
	}

	newKey := func(f url.Values) (string, reply) {
		r := adm.do("POST", "/admin/apikeys", f, nil)
		return regexp.MustCompile(`vsf_[A-Za-z0-9_-]{20,}`).FindString(r.Body), r
	}

	key, r := newKey(url.Values{"name": {uniq("k")}, "rps_limit": {"1000"}, "daily_quota": {"0"}, "max_batch": {"50"}, "expires_days": {"30"}})
	if r.Code != 200 || key == "" {
		t.Fatalf("create key: %d %.200s", r.Code, r.Body)
	}

	for name, f := range map[string]url.Values{
		"no name":   {"name": {""}, "rps_limit": {"10"}, "daily_quota": {"0"}},
		"bad rps":   {"name": {"n"}, "rps_limit": {"zero"}, "daily_quota": {"0"}},
		"bad batch": {"name": {"n"}, "rps_limit": {"10"}, "daily_quota": {"0"}, "max_batch": {"100000"}},
	} {
		if k, r := newKey(f); k != "" || r.Code != 200 {
			t.Errorf("%s: key=%q code=%d, want an error page without a key", name, k, r.Code)
		}
	}

	// dữ liệu để gọi API
	phone, domain := phone9(), uniq("evil") + ".example"
	ctx := context.Background()

	for _, e := range []struct {
		k  normalize.Key
		in model.EntryInput
	}{
		{mustNormalize(t, "phone", "exact", phone), model.EntryInput{Category: "scam", RiskScore: 90}},
		{mustNormalize(t, "url", "domain", domain), model.EntryInput{Category: "phishing", RiskScore: 80}},
	} {
		if _, err := a.st.CreateEntry(ctx, e.k, e.in, model.Actor{Email: "t"}); err != nil {
			t.Fatal(err)
		}
	}

	a.waitBlacklisted("", "phone", phone, true)
	a.waitBlacklisted("", "url", "http://"+domain+"/a", true) // chờ cả entry URL: changefeed nạp từng thay đổi một

	apiGet := func(k, q string) reply {
		hdr := map[string]string{}
		if k != "" {
			hdr["X-API-Key"] = k
		}

		return a.anon().do("GET", "/v1/check?"+q, nil, hdr)
	}

	r = apiGet(key, "type=phone&value="+phone)
	if r.Code != 200 || !strings.Contains(r.Body, `"blacklisted":true`) {
		t.Fatalf("api check: %d %s", r.Code, r.Body)
	}

	if r := apiGet(key, "type=phone&value="+phone9()); r.Code != 200 || !strings.Contains(r.Body, `"blacklisted":false`) {
		t.Errorf("api check clean: %d %s", r.Code, r.Body)
	}

	if r := apiGet(key, "type=phone&value=2025550123&region=US"); r.Code != 200 || !strings.Contains(r.Body, "+12025550123") {
		t.Errorf("api region: %d %s", r.Code, r.Body)
	}

	for name, q := range map[string]string{"bad type": "type=fax&value=1", "bad region": "type=phone&value=0912345678&region=ZZ",
		"empty value": "type=phone&value="} {
		if r := apiGet(key, q); r.Code != 400 {
			t.Errorf("%s: %d, want 400", name, r.Code)
		}
	}

	for name, k := range map[string]string{"missing": "", "garbage": "nope", "unknown prefix": "vsf_abcdefgh_" + strings.Repeat("a", 40)} {
		if r := apiGet(k, "type=phone&value="+phone); r.Code != 401 {
			t.Errorf("%s key: %d, want 401", name, r.Code)
		}
	}

	if r := a.anon().do("GET", "/v1/check?type=phone&value="+phone, nil, map[string]string{"Authorization": "Bearer " + key}); r.Code != 200 {
		t.Errorf("bearer auth: %d", r.Code)
	}

	// batch
	batch := func(k, body string) reply {
		return a.anon().do("POST", "/v1/check/batch", nil, nil).withBody(a, "/v1/check/batch", k, body)
	}

	body, _ := json.Marshal(map[string]any{"region": "VN", "items": []map[string]string{{"type": "phone", "value": phone},
		{"type": "url", "value": "http://" + domain + "/a"}, {"type": "phone", "value": "bad"}}})

	r = batch(key, string(body))
	if r.Code != 200 || strings.Count(r.Body, `"blacklisted":true`) != 2 || !strings.Contains(r.Body, `"error"`) {
		t.Errorf("batch: %d %s", r.Code, r.Body)
	}

	// region mặc định của batch áp cho mục không tự khai báo, mục có region riêng thì giữ riêng
	reg, _ := json.Marshal(map[string]any{"region": "US", "items": []map[string]string{
		{"type": "phone", "value": "2025550123"}, {"type": "phone", "value": "0912345678", "region": "VN"}}})

	if r := batch(key, string(reg)); r.Code != 200 || !strings.Contains(r.Body, "+12025550123") || !strings.Contains(r.Body, "+84912345678") {
		t.Errorf("batch region default and override: %d %s", r.Code, r.Body)
	}

	for name, b := range map[string]string{"bad json": "{", "empty": `{"items":[]}`, "unknown field": `{"items":[{"type":"phone","value":"1"}],"x":1}`} {
		if r := batch(key, b); r.Code != 400 {
			t.Errorf("batch %s: %d, want 400", name, r.Code)
		}
	}

	// rate limit: key rps 2 -> request thứ ba trong cùng một giây bị chặn
	slow, _ := newKey(url.Values{"name": {uniq("slow")}, "rps_limit": {"2"}, "daily_quota": {"0"}})
	limited := 0

	for i := 0; i < 6; i++ {
		if apiGet(slow, "type=phone&value="+phone).Code == 429 {
			limited++
		}
	}

	if limited == 0 {
		t.Error("a key with rps_limit=2 must be rate limited after a burst")
	}

	// xoay key: key cũ còn dùng được trong thời gian ân hạn, key mới dùng được
	keys, err := a.st.ListAPIKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var keyID int64

	for _, k := range keys {
		if strings.HasPrefix(key, "vsf_"+k.Prefix) {
			keyID = k.ID
		}
	}

	if keyID == 0 {
		t.Fatal("created key not listed")
	}

	rot := adm.do("POST", fmt.Sprintf("/admin/apikeys/%d/rotate", keyID), url.Values{"grace_days": {"1"}}, nil)

	newSecret := regexp.MustCompile(`vsf_[A-Za-z0-9_-]{20,}`).FindString(rot.Body)
	if rot.Code != 200 || newSecret == "" || newSecret == key {
		t.Fatalf("rotate: %d", rot.Code)
	}

	if r := apiGet(newSecret, "type=phone&value="+phone); r.Code != 200 {
		t.Errorf("rotated key: %d", r.Code)
	}

	// thu hồi: bị từ chối ngay (sau khi cache khóa hết hiệu lực)
	if r := adm.do("POST", fmt.Sprintf("/admin/apikeys/%d/revoke", keyID), url.Values{}, nil); r.Code != 303 {
		t.Errorf("revoke: %d", r.Code)
	}

	a.h.APIKeys.Invalidate(strings.TrimPrefix(strings.SplitN(key, "_", 3)[1], ""))

	if r := apiGet(key, "type=phone&value="+phone); r.Code != 403 {
		t.Errorf("revoked key: %d, want 403", r.Code)
	}

	if r := adm.do("POST", "/admin/apikeys/abc/revoke", url.Values{}, nil); r.Code != 404 && r.Code != 400 {
		t.Errorf("revoke bad id: %d", r.Code)
	}

	if r := adm.do("POST", "/admin/apikeys/999999999/rotate", url.Values{}, nil); r.Code != 404 {
		t.Errorf("rotate unknown key: %d", r.Code)
	}
}

func (r reply) withBody(a *testApp, path, key, body string) reply {
	req, _ := http.NewRequest("POST", a.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", key)

	return a.anon().send(req)
}

func TestAppInspector(t *testing.T) {
	a := newApp(t)
	adm := a.login(a.user(model.RoleAdmin))

	// tạo vài request để inspector có gì đó để hiển thị
	adm.get("/admin/entries")
	a.anon().get("/healthz")
	a.anon().do("POST", "/admin/login", url.Values{"email": {"x@y.z"}, "password": {"secret-pass-1"}}, nil)

	if r := adm.get("/admin/inspector"); r.Code != 303 {
		t.Errorf("inspector page redirects to the overlay host page: %d", r.Code)
	}

	for _, p := range []string{"/admin/inspector/feed", "/admin/inspector/stats", "/admin/inspector/stats?inspector_screen=/admin/entries",
		"/admin/inspector/detail/close"} {
		if r := adm.get(p); r.Code != 200 {
			t.Errorf("GET %s = %d", p, r.Code)
		}
	}

	if r := adm.get("/admin/inspector/999999"); r.Code != 404 {
		t.Errorf("unknown inspector id: %d", r.Code)
	}

	if r := adm.get("/admin/inspector/abc"); r.Code != 404 && r.Code != 400 {
		t.Errorf("bad inspector id: %d", r.Code)
	}

	feed := adm.get("/admin/inspector/feed")

	if m := regexp.MustCompile(`/admin/inspector/(\d+)`).FindStringSubmatch(feed.Body); m != nil {
		d := adm.get("/admin/inspector/" + m[1])
		if d.Code != 200 || strings.Contains(d.Body, "secret-pass-1") {
			t.Errorf("inspector detail: %d (body must never contain the login password)", d.Code)
		}
	}

	if r := adm.do("POST", "/admin/inspector/clear", url.Values{}, nil); r.Code != 200 && r.Code != 204 {
		t.Errorf("clear: %d", r.Code)
	}
}
