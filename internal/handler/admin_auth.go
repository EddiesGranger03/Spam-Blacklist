package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"vsf/internal/auth"
	"vsf/internal/store"
)

type loginData struct{ Email string }

func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	pd := h.newPage(r, "Đăng nhập", "", loginData{})
	h.render(w, http.StatusOK, "login", "layout", pd)
}

func (h *Handler) loginSubmit(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, msg, email string) {
		pd := h.newPage(r, "Đăng nhập", "", loginData{Email: email})
		pd.Error = msg
		h.render(w, status, "login", "layout", pd)
	}

	if !sameOrigin(r) {
		http.Error(w, "Yêu cầu bị từ chối (origin).", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)

	if err := r.ParseForm(); err != nil {
		fail(http.StatusBadRequest, "Dữ liệu không hợp lệ.", "")
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	password := r.PostFormValue("password")
	ip := clientIP(r)

	if !h.throttleIP.Allowed(ip) || !h.throttleUser.Allowed(email) {
		fail(http.StatusTooManyRequests, "Thử quá nhiều lần. Vui lòng đợi 15 phút.", email)
		return
	}

	admin, err := h.Store.GetAdminByEmail(r.Context(), email)

	switch {
	case errors.Is(err, store.ErrNotFound):
		auth.BurnTime(password)
		admin.PasswordHash = ""

	case err != nil:
		h.serverError(w, r, err)
		return
	}

	if admin.PasswordHash == "" || admin.Disabled || !auth.VerifyPassword(password, admin.PasswordHash) {
		h.throttleIP.Fail(ip)
		h.throttleUser.Fail(email)
		h.Log.Warn("login failed", "email", email, "ip", ip)
		fail(http.StatusUnauthorized, "Email hoặc mật khẩu không đúng.", email)
		return
	}

	token, hash, err := auth.NewToken()
	if err != nil {
		h.serverError(w, r, err)
		return
	}

	csrf, _, err := auth.NewToken()
	if err != nil {
		h.serverError(w, r, err)
		return
	}

	expires := time.Now().Add(sessionAbsolute)
	if err := h.Store.CreateSession(r.Context(), hash, admin.ID, csrf, ip, r.UserAgent(), expires); err != nil {
		h.serverError(w, r, err)
		return
	}

	h.throttleUser.Reset(email)
	_ = h.Store.WriteAudit(r.Context(), actorOf(admin.ID, admin.Email, ip), "login", map[string]any{"ok": true})

	http.SetCookie(w, &http.Cookie{Name: h.cookieName, Value: token, Path: "/", Expires: expires,
		HttpOnly: true, Secure: h.Cfg.CookieSecure, SameSite: http.SameSiteLaxMode})

	http.Redirect(w, r, "/admin/entries", http.StatusSeeOther)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if s := sessionFrom(r); s != nil {
		_ = h.Store.DeleteSession(r.Context(), s.IDHash)
	}

	h.clearCookie(w)
	http.Redirect(w, r, "/admin/login?flash=logged_out", http.StatusSeeOther)
}
