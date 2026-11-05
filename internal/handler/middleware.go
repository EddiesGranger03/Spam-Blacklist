package handler

import (
	"context"
	"crypto/subtle"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"vsf/internal/auth"
	"vsf/internal/metrics"
	"vsf/internal/model"
	"vsf/internal/store"
)

type ctxKey int

const (
	sessKey ctxKey = iota
	apiKeyKey
)

const (
	sessionIdle     = 30 * time.Minute
	sessionAbsolute = 12 * time.Hour
)

func (h *Handler) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "+
				"frame-ancestors 'none'; form-action 'self'; base-uri 'none'")

		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "same-origin")

		if h.Cfg.CookieSecure {
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}

		if strings.HasPrefix(r.URL.Path, "/admin") {
			hd.Set("Cache-Control", "no-store")
		}

		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}

	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}

	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (h *Handler) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)

		if sw.status == 0 {
			sw.status = http.StatusOK
		}

		route := chi.RouteContext(r.Context()).RoutePattern()
		if route == "" {
			route = "unmatched"
		}

		dur := time.Since(start)
		metrics.HTTPDuration.WithLabelValues(r.Method, route, strconv.Itoa(sw.status)).Observe(dur.Seconds())

		if route == "/healthz" || route == "/metrics" || (strings.HasPrefix(route, "/v1") && sw.status < 400) {
			return
		}

		h.Log.Info("http", "method", r.Method, "route", route, "status", sw.status,
			"ms", dur.Milliseconds(), "ip", clientIP(r), "req_id", r.Context().Value(requestIDKey()))
	})
}

func sessionFrom(r *http.Request) *model.Session {
	s, _ := r.Context().Value(sessKey).(*model.Session)
	return s
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/admin/login")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (h *Handler) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(h.cookieName)
		if err != nil || c.Value == "" {
			redirectToLogin(w, r)
			return
		}

		hash := auth.HashToken(c.Value)
		sess, err := h.Store.GetSession(r.Context(), hash)
		if err != nil {
			if !errors.Is(err, store.ErrNotFound) {
				h.serverError(w, r, err)
				return
			}

			h.clearCookie(w)
			redirectToLogin(w, r)
			return
		}

		now := time.Now()
		if sess.Disabled || now.After(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) > sessionIdle {
			_ = h.Store.DeleteSession(r.Context(), hash)
			h.clearCookie(w)
			redirectToLogin(w, r)
			return
		}

		if now.Sub(sess.LastSeenAt) > time.Minute {
			_ = h.Store.TouchSession(r.Context(), hash)
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessKey, &sess)))
	})
}

func requireRole(min model.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s := sessionFrom(r)
			if s == nil || !s.Role.AtLeast(min) {
				http.Error(w, "Bạn không có quyền thực hiện thao tác này.", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func sameOrigin(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		return err == nil && u.Host == r.Host
	}

	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" {
		return sfs == "same-origin" || sfs == "none"
	}

	return true
}

func (h *Handler) csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}

		s := sessionFrom(r)
		if s == nil || !sameOrigin(r) {
			http.Error(w, "Yêu cầu bị từ chối (origin).", http.StatusForbidden)
			return
		}

		tok := r.Header.Get("X-CSRF-Token")
		if tok == "" && strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			tok = r.PostFormValue("csrf_token")
		}

		if subtle.ConstantTimeCompare([]byte(tok), []byte(s.CSRFToken)) != 1 {
			http.Error(w, "Yêu cầu bị từ chối (CSRF token).", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (h *Handler) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: h.cookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: h.Cfg.CookieSecure, SameSite: http.SameSiteLaxMode})
}

var templateFuncs = template.FuncMap{
	"fmtTime": func(t time.Time) string { return t.Local().Format("2006-01-02 15:04") },
	"fmtTimePtr": func(t *time.Time) string {
		if t == nil {
			return "—"
		}

		return t.Local().Format("2006-01-02 15:04")
	},
	"expired": func(t *time.Time) bool { return t != nil && t.Before(time.Now()) },
	"shorten": func(s string, n int) string {
		r := []rune(s)
		if len(r) <= n {
			return s
		}

		return string(r[:n]) + "…"
	},
	"deref": func(p *int64) int64 {
		if p == nil {
			return 0
		}

		return *p
	},
}
