package handler

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"vsf/internal/apikey"
	"vsf/internal/auth"
	"vsf/internal/changefeed"
	"vsf/internal/checker"
	"vsf/internal/config"
	"vsf/internal/inspector"
	"vsf/internal/model"
	"vsf/internal/snapshot"
	"vsf/internal/store"
	"vsf/web"
)

// FilterStatus là phần trạng thái của filter mà handler cần (/readyz, dashboard): *filter.Manager.
type FilterStatus interface {
	Ready() bool
	Items() uint64
}

// SnapshotStatus là phần trạng thái snapshot/leader mà /readyz hiển thị: *snapshot.Syncer. Chỉ để báo cáo, không bao giờ
// làm instance not-ready (filter đã sẵn sàng thì snapshot cũ hay lỗi dựng không ảnh hưởng việc phục vụ).
type SnapshotStatus interface {
	Status() snapshot.Status
}

// VerifyStatus: *verify.Verifier. Chỉ cảnh báo trên /readyz: pod có âm tính giả vẫn phục vụ (đã tự vá hash thiếu),
// gạt nó khỏi load balancer không làm filter các pod khác đúng hơn mà còn dồn tải.
type VerifyStatus interface {
	Warning(now time.Time) string
}

type Deps struct {
	Cfg       config.Config
	Log       *slog.Logger
	Store     *store.Store
	Checker   *checker.Checker
	Feed      *changefeed.Feed
	Bloom     FilterStatus
	Snapshots SnapshotStatus // tùy chọn (nil = không báo)
	Verify    VerifyStatus   // tùy chọn (nil = không báo): bộ kiểm tra âm tính giả của filter
	APIKeys   *apikey.Service
	Inspector *inspector.Inspector
}

type Handler struct {
	Deps
	tmpl         map[string]*template.Template
	throttleIP   *auth.Throttle
	throttleUser *auth.Throttle // khóa theo cặp email|IP: người ngoài không khóa được tài khoản của người khác
	throttleMail *auth.Throttle // giới hạn rộng theo email để chặn dò mật khẩu từ nhiều IP
	jobs         *importJobs
	cookieName   string
	routeIndex   map[string]routeInfo
}

var pageNames = []string{"login", "entries", "check", "import", "audit", "users", "apikeys"}

// New tạo Handler từ các phụ thuộc: nạp template, khởi tạo throttle và bộ quản lý job import.
func New(d Deps) (*Handler, error) {
	if d.Log == nil {
		d.Log = slog.Default()
	}

	if d.Inspector == nil {
		d.Inspector = inspector.New(200)
	}

	h := &Handler{
		Deps:         d,
		tmpl:         map[string]*template.Template{},
		throttleIP:   auth.NewThrottle(20, 15*time.Minute),
		throttleUser: auth.NewThrottle(5, 15*time.Minute),
		throttleMail: auth.NewThrottle(30, 15*time.Minute),
		jobs:         newImportJobs(),
		cookieName:   "vsf_session",
	}

	if d.Cfg.CookieSecure {
		h.cookieName = "__Host-vsf_session"
	}

	for _, p := range pageNames {
		t, err := template.New(p).Funcs(templateFuncs).ParseFS(web.FS,
			"templates/layout.html", "templates/"+p+".html", "templates/_*.html")
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", p, err)
		}

		h.tmpl[p] = t
	}

	inspectorTmpl, err := template.New("inspector").Funcs(templateFuncs).ParseFS(web.FS,
		"templates/layout.html", "templates/_*.html")
	if err != nil {
		return nil, fmt.Errorf("parse template inspector: %w", err)
	}
	h.tmpl["inspector"] = inspectorTmpl

	return h, nil
}

// Router dựng toàn bộ cây route (công khai, API, admin) cùng middleware tương ứng.
func (h *Handler) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.RequestID, chimw.Recoverer, h.securityHeaders, h.instrument)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	r.Get("/readyz", h.readyz)
	r.Handle("/metrics", h.metricsAuth(promhttp.Handler()))

	staticFS, _ := fs.Sub(web.FS, "static")
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServerFS(staticFS)))

	r.Route("/v1", func(r chi.Router) {
		r.Use(h.apiAuth)
		r.Get("/check", h.apiCheckOne)
		r.Post("/check/batch", h.apiCheckBatch)
	})

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/entries", http.StatusSeeOther)
	})

	r.Route("/admin", func(r chi.Router) {
		r.Get("/login", h.loginPage)
		r.Post("/login", h.loginSubmit)

		r.Group(func(r chi.Router) {
			r.Use(h.requireSession, h.csrfProtect)

			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/admin/entries", http.StatusSeeOther)
			})

			r.Post("/logout", h.logout)

			r.Group(func(r chi.Router) {
				r.Use(requireRole(model.RoleViewer))
				r.Get("/entries", h.listEntries)
				r.Get("/check", h.checkPage)
				r.Post("/check", h.checkSubmit)
			})

			r.Group(func(r chi.Router) {
				r.Use(requireRole(model.RoleEditor))
				r.Get("/entries/new", h.newEntryForm)
				r.Post("/entries", h.createEntry)
				r.Get("/entries/{id}/edit", h.editEntryForm)
				r.Put("/entries/{id}", h.updateEntry)
				r.Delete("/entries/{id}", h.deleteEntry)
				r.Get("/import", h.importPage)
				r.Post("/import", h.importStart)
				r.Get("/import/{job}", h.importStatus)
				r.Get("/export", h.exportCSV)
				r.Get("/audit", h.auditPage)
			})

			r.Group(func(r chi.Router) {
				r.Use(requireRole(model.RoleAdmin))
				r.Get("/inspector", h.inspectorPage)
				r.Get("/inspector/feed", h.inspectorFeed)
				r.Get("/inspector/stats", h.inspectorStats)
				r.Get("/inspector/detail/close", h.inspectorCloseDetail)
				r.Get("/inspector/{id}", h.inspectorDetail)
				r.Post("/inspector/clear", h.inspectorClear)
				r.Get("/audit/verify", h.auditVerify)
				r.Get("/users", h.usersPage)
				r.Post("/users", h.userCreate)
				r.Post("/users/{id}", h.userUpdate)
				r.Get("/apikeys", h.apiKeysPage)
				r.Post("/apikeys", h.apiKeyCreate)
				r.Post("/apikeys/{id}/revoke", h.apiKeyRevoke)
				r.Post("/apikeys/{id}/rotate", h.apiKeyRotate)
			})
		})
	})

	h.routeIndex = buildRouteIndex(r)

	return r
}

// readyz kiểm tra trạng thái sẵn sàng (Bloom, changefeed, DB) và trả 503 nếu chưa sẵn sàng.
func (h *Handler) readyz(w http.ResponseWriter, r *http.Request) {
	problems := map[string]string{}

	if !h.Bloom.Ready() {
		problems["bloom"] = "not built yet"
	}

	if lag := h.Feed.Lag(); lag > 30*time.Second {
		problems["changefeed"] = fmt.Sprintf("last successful poll %s ago", lag.Truncate(time.Second))
	}

	// Các thay đổi đang chờ sau một transaction mở lâu đã có trong Bloom filter, nên riêng điều này không làm instance sai,
	// và không được gạt nó khỏi load balancer: nó chỉ là cảnh báo. Chỉ khi đuôi bị tràn thì mới là vấn đề, vì khi đó entry có thể thật sự bị thiếu.
	if h.Feed.TailOverflow() {
		problems["changefeed_tail"] = "too many committed changes waiting behind an open database transaction; " +
			"the Bloom filter may be missing entries"
	}

	warnings := map[string]string{}

	if st := h.Feed.StalledFor(); st > stallWarnAfter {
		warnings["changefeed_stalled"] = fmt.Sprintf("%d changes have been waiting %s behind an open database "+
			"transaction (already applied to the Bloom filter); look for an idle-in-transaction session or a long import",
			h.Feed.TailLen(), st.Truncate(time.Second))
	}

	// Không có Redis Pub/Sub: instance vẫn đúng (poll change_log nhanh), chỉ tốn tài nguyên hơn -> cảnh báo, không 503.
	if !h.Feed.Live() {
		warnings["changefeed_pubsub"] = "not subscribed to redis change notifications; polling change_log every POLL_INTERVAL"
	}

	if h.Verify != nil {
		if w := h.Verify.Warning(time.Now()); w != "" {
			warnings["filter_verify"] = w
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := h.Store.Ping(ctx); err != nil {
		problems["database"] = "unreachable"
	}

	// Chi tiết lỗi nội bộ chỉ dành cho loopback; bên ngoài chỉ thấy trạng thái.
	detail := false
	if ip := net.ParseIP(peerIP(r)); ip != nil && ip.IsLoopback() {
		detail = true
	}

	var snap map[string]any
	if h.Snapshots != nil {
		var snapWarn map[string]string

		snap, snapWarn = snapshotReport(h.Snapshots.Status(), time.Now())
		maps.Copy(warnings, snapWarn)
	}

	if len(problems) > 0 {
		if !detail {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not ready"})
			return
		}

		body := map[string]any{"status": "not ready", "problems": problems}
		if snap != nil {
			body["snapshot"] = snap
		}

		writeJSON(w, http.StatusServiceUnavailable, body)

		return
	}

	if detail && (len(warnings) > 0 || snap != nil) {
		body := map[string]any{"status": "ready"}
		if len(warnings) > 0 {
			body["warnings"] = warnings
		}

		if snap != nil {
			body["snapshot"] = snap
		}

		writeJSON(w, 200, body)

		return
	}

	writeJSON(w, 200, map[string]string{"status": "ready"})
}

// snapshotReport dựng phần chi tiết snapshot cho /readyz (chỉ loopback thấy) và các cảnh báo kèm theo. Chỉ cảnh báo,
// không bao giờ là problem: pod đã có filter thì vẫn phục vụ đúng dù snapshot cũ hoặc leader đang gặp lỗi dựng.
func snapshotReport(st snapshot.Status, now time.Time) (map[string]any, map[string]string) {
	rep := map[string]any{
		"leader":               st.Leader,
		"snapshot_id":          st.SnapshotID,
		"cursor":               fmt.Sprintf("%s.%d", st.CursorXID, st.CursorSeq),
		"build_failures":       st.BuildFailures,
		"save_failures":        st.SaveFailures,
		"install_failures":     st.InstallFailures,
		"consecutive_failures": st.Consecutive,
		"pending_save":         st.PendingSave,
		"fallbacks":            st.Fallbacks,
		"corrupt_flagged":      st.CorruptMarked,
		"rebuild_requests":     st.RebuildRequests,
		"rebuild_served":       st.RebuildServed,
	}

	warn := map[string]string{}

	if !st.SnapshotAt.IsZero() {
		age := now.Sub(st.SnapshotAt).Truncate(time.Second)
		rep["snapshot_age"] = age.String()

		if st.Interval > 0 && age > 3*st.Interval {
			warn["filter_snapshot_old"] = fmt.Sprintf("serving a filter from a snapshot %s old (build interval %s); "+
				"new pods may have to wait for a rebuild", age, st.Interval)
		}
	}

	if !st.LastSaveOK.IsZero() {
		rep["last_save_ok"] = st.LastSaveOK.UTC().Format(time.RFC3339)
	}

	if st.Consecutive > 0 {
		rep["next_attempt"] = st.NextAttempt.UTC().Format(time.RFC3339)
		warn["filter_snapshot_failing"] = fmt.Sprintf("%d consecutive snapshot build/save failures; retrying with backoff "+
			"(next attempt %s)", st.Consecutive, st.NextAttempt.UTC().Format(time.RFC3339))
	}

	return rep, warn
}

// stallWarnAfter là thời gian thay đổi được phép chờ sau một transaction mở trước khi /readyz nhắc tới.
const stallWarnAfter = 30 * time.Second

// writeJSON ghi phản hồi JSON với mã trạng thái cho trước.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr ghi phản hồi lỗi dạng JSON {"error": ...}.
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// peerIP trả về IP của kết nối trực tiếp (bỏ phần cổng).
func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

// inNets cho biết IP có thuộc một trong các mạng đã cho hay không.
func inNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}

	return false
}

// clientIP trả về IP client thật. Chỉ khi kết nối đến từ một proxy tin cậy (TRUSTED_PROXIES) mới đọc
// X-Forwarded-For, duyệt từ phải sang trái và lấy hop đầu tiên không thuộc proxy tin cậy.
// Header do client tự gửi không bao giờ được tin khi peer không nằm trong danh sách.
func (h *Handler) clientIP(r *http.Request) string {
	peer := peerIP(r)

	trusted := h.Cfg.TrustedProxies
	if len(trusted) == 0 {
		return peer
	}

	pip := net.ParseIP(peer)
	if pip == nil || !inNets(pip, trusted) {
		return peer
	}

	var hops []string

	for _, v := range r.Header.Values("X-Forwarded-For") {
		for _, p := range strings.Split(v, ",") {
			hops = append(hops, strings.TrimSpace(p))
		}
	}

	for i := len(hops) - 1; i >= 0; i-- {
		ip := net.ParseIP(hops[i])
		if ip == nil {
			return peer // header lỗi: không đoán
		}

		if !inNets(ip, trusted) {
			return ip.String()
		}
	}

	return peer
}

// metricsAuth bảo vệ /metrics: có METRICS_TOKEN thì cần Bearer đúng; không có thì chỉ nhận loopback.
func (h *Handler) metricsAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if tok := h.Cfg.MetricsToken; tok != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if got == r.Header.Get("Authorization") || subtle.ConstantTimeCompare([]byte(got), []byte(tok)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
				writeErr(w, http.StatusUnauthorized, "unauthorized")

				return
			}
		} else if ip := net.ParseIP(peerIP(r)); ip == nil || !ip.IsLoopback() {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// actorFrom tạo model.Actor cho audit từ IP và phiên đăng nhập hiện tại.
func (h *Handler) actorFrom(r *http.Request) model.Actor {
	a := model.Actor{IP: h.clientIP(r)}

	if s := sessionFrom(r); s != nil {
		a.ID, a.Email = s.AdminID, s.Email
	}

	return a
}

type pageData struct {
	Title      string
	Active     string
	Screen     string
	ScreenName string
	CSRF       string
	Flash      string
	Error      string
	User       *model.Session
	CanEdit    bool
	IsAdmin    bool
	Categories []string
	Data       any
}

var flashMessages = map[string]string{
	"created": "Đã thêm.", "updated": "Đã cập nhật.", "deleted": "Đã xóa.",
	"user_created": "Đã tạo người dùng.", "user_updated": "Đã cập nhật người dùng.",
	"key_revoked": "Đã thu hồi API key.", "logged_out": "Bạn đã đăng xuất.",
}

// newPage dựng dữ liệu chung cho trang (tiêu đề, CSRF, quyền của người dùng).
func (h *Handler) newPage(r *http.Request, title, active string, data any) pageData {
	pd := pageData{Title: title, Active: active, Screen: r.URL.Path, ScreenName: title, Categories: model.Categories, Data: data,
		Flash: flashMessages[r.URL.Query().Get("flash")]}

	if s := sessionFrom(r); s != nil {
		pd.User, pd.CSRF = s, s.CSRFToken
		pd.CanEdit = s.Role.AtLeast(model.RoleEditor)
		pd.IsAdmin = s.Role == model.RoleAdmin
	}

	return pd
}

// render hiển thị template của trang với mã trạng thái cho trước.
func (h *Handler) render(w http.ResponseWriter, status int, page, name string, pd pageData) {
	t, ok := h.tmpl[page]
	if !ok {
		http.Error(w, "template not found", http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, pd); err != nil {
		h.Log.Error("render template", "page", page, "name", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// isHTMX cho biết request có phải từ HTMX hay không (dựa vào header HX-Request).
func isHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-History-Restore-Request") != "true"
}

// serverError ghi log lỗi và trả 500 cho client mà không lộ chi tiết.
func (h *Handler) serverError(w http.ResponseWriter, r *http.Request, err error) {
	// Client đã bỏ đi (đóng tab, rời trang): không phải lỗi hệ thống, không ghi ERROR. 499 theo quy ước của nginx.
	if errors.Is(err, context.Canceled) && r.Context().Err() != nil {
		h.Log.Info("request canceled by client", "path", r.URL.Path, "method", r.Method)
		w.WriteHeader(499)
		return
	}

	h.Log.Error("request failed", "path", r.URL.Path, "method", r.Method, "err", err)
	http.Error(w, "Lỗi hệ thống. Vui lòng thử lại.", http.StatusInternalServerError)
}
