package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"vsf/internal/apikey"
	"vsf/internal/auth"
	"vsf/internal/bloom"
	"vsf/internal/changefeed"
	"vsf/internal/checker"
	"vsf/internal/config"
	"vsf/internal/model"
	"vsf/internal/store"
	"vsf/web"
)

type Deps struct {
	Cfg     config.Config
	Log     *slog.Logger
	Store   *store.Store
	Checker *checker.Checker
	Feed    *changefeed.Feed
	Bloom   *bloom.Manager
	APIKeys *apikey.Service
}

type Handler struct {
	Deps
	tmpl         map[string]*template.Template
	throttleIP   *auth.Throttle
	throttleUser *auth.Throttle
	jobs         *importJobs
	cookieName   string
}

var pageNames = []string{"login", "entries", "check", "import", "audit", "users", "apikeys"}

func New(d Deps) (*Handler, error) {
	h := &Handler{
		Deps:         d,
		tmpl:         map[string]*template.Template{},
		throttleIP:   auth.NewThrottle(20, 15*time.Minute),
		throttleUser: auth.NewThrottle(5, 15*time.Minute),
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

	return h, nil
}

func (h *Handler) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.RequestID, chimw.Recoverer, h.securityHeaders, h.instrument)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	r.Get("/readyz", h.readyz)
	r.Handle("/metrics", promhttp.Handler())

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

	return r
}

func (h *Handler) readyz(w http.ResponseWriter, r *http.Request) {
	problems := map[string]string{}

	if !h.Bloom.Ready() {
		problems["bloom"] = "not built yet"
	}

	if lag := h.Feed.Lag(); lag > 30*time.Second {
		problems["changefeed"] = fmt.Sprintf("last successful poll %s ago", lag.Truncate(time.Second))
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := h.Store.Ping(ctx); err != nil {
		problems["database"] = "unreachable"
	}

	if len(problems) > 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not ready", "problems": problems})
		return
	}

	writeJSON(w, 200, map[string]string{"status": "ready"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return host
}

func actorFrom(r *http.Request) model.Actor {
	a := model.Actor{IP: clientIP(r)}

	if s := sessionFrom(r); s != nil {
		a.ID, a.Email = s.AdminID, s.Email
	}

	return a
}

type pageData struct {
	Title      string
	Active     string
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

func (h *Handler) newPage(r *http.Request, title, active string, data any) pageData {
	pd := pageData{Title: title, Active: active, Categories: model.Categories, Data: data,
		Flash: flashMessages[r.URL.Query().Get("flash")]}

	if s := sessionFrom(r); s != nil {
		pd.User, pd.CSRF = s, s.CSRFToken
		pd.CanEdit = s.Role.AtLeast(model.RoleEditor)
		pd.IsAdmin = s.Role == model.RoleAdmin
	}

	return pd
}

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

func isHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-History-Restore-Request") != "true"
}

func (h *Handler) serverError(w http.ResponseWriter, r *http.Request, err error) {
	h.Log.Error("request failed", "path", r.URL.Path, "method", r.Method, "err", err)
	http.Error(w, "Lỗi hệ thống. Vui lòng thử lại.", http.StatusInternalServerError)
}
