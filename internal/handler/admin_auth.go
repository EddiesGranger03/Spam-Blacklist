package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"vsf/internal/auth"
	"vsf/internal/metrics"
	"vsf/internal/store"
)

type loginData struct{ Email string }

const (
	deviceTrustFor = 30 * 24 * time.Hour
	loginAlertAfter = 10 // số lần sai trên một email thì cảnh báo và bắt đầu làm chậm
)

// loginBackoff: thời gian chờ thêm trước khi xử lý một lượt đăng nhập từ thiết bị lạ, theo số lần sai hiện có của email.
// Là biến để test đặt về 0.
var loginBackoff = func(failures int) time.Duration {
	if failures < loginAlertAfter {
		return 0
	}

	return min(time.Duration(failures-loginAlertAfter+1)*500*time.Millisecond, 5*time.Second)
}

// deviceCookieName trả về tên cookie của thiết bị tin cậy, theo cùng quy tắc với cookie phiên.
func (h *Handler) deviceCookieName() string {
	if h.Cfg.CookieSecure {
		return "__Host-vsf_device"
	}

	return "vsf_device"
}

// loginPage hiển thị trang đăng nhập admin.
func (h *Handler) loginPage(w http.ResponseWriter, r *http.Request) {
	pd := h.newPage(r, "Đăng nhập", "", loginData{})
	h.render(w, http.StatusOK, "login", "layout", pd)
}

// loginSubmit xử lý đăng nhập: kiểm tra giới hạn, xác minh mật khẩu, tạo phiên và cookie.
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
	ip := h.clientIP(r)

	pair := email + "|" + ip

	// Thiết bị tin cậy (cookie ký, cấp sau lần đăng nhập thành công) không bị giới hạn rộng theo email, nên kẻ dò
	// mật khẩu từ nhiều IP không khóa được người dùng thật. Mật khẩu vẫn phải đúng.
	trusted := false
	if c, err := r.Cookie(h.deviceCookieName()); err == nil {
		trusted = auth.VerifyDevice(h.Cfg.SessionSecret, email, c.Value, time.Now(), deviceTrustFor)
	}

	switch {
	case !h.throttleIP.Allowed(ip):
		metrics.LoginFailures.WithLabelValues("throttled_ip").Inc()
		fail(http.StatusTooManyRequests, "Thử quá nhiều lần. Vui lòng đợi 15 phút.", email)

		return

	case !h.throttleUser.Allowed(pair):
		metrics.LoginFailures.WithLabelValues("throttled_pair").Inc()
		fail(http.StatusTooManyRequests, "Thử quá nhiều lần. Vui lòng đợi 15 phút.", email)

		return

	case !trusted && !h.throttleMail.Allowed(email):
		metrics.LoginFailures.WithLabelValues("throttled_email").Inc()
		fail(http.StatusTooManyRequests, "Thử quá nhiều lần. Vui lòng đợi 15 phút.", email)

		return
	}

	// Làm chậm dần: email đã bị đoán sai nhiều lần thì mỗi lượt thử mới (từ thiết bị lạ) phải chờ lâu hơn, nên dò
	// phân tán từ nhiều IP tốn thời gian hơn nhiều mà người dùng thật (thiết bị tin cậy) không bị ảnh hưởng.
	if !trusted {
		if d := loginBackoff(h.throttleMail.Count(email)); d > 0 {
			select {
			case <-time.After(d):
			case <-r.Context().Done():
				return
			}
		}
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
		h.throttleUser.Fail(pair)
		h.throttleMail.Fail(email)
		metrics.LoginFailures.WithLabelValues("bad_credentials").Inc()

		// Cảnh báo đúng một lần khi email vượt ngưỡng: log mức Error và tăng metric để Prometheus/alert bắt được.
		if h.throttleMail.Count(email) == loginAlertAfter {
			metrics.LoginAttackSuspected.Inc()
			h.Log.Error("login attack suspected: repeated failed logins for one email from several sources",
				"email", email, "failures", loginAlertAfter, "last_ip", ip)
		}
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

	h.throttleUser.Reset(pair)

	http.SetCookie(w, &http.Cookie{Name: h.deviceCookieName(), Value: auth.SignDevice(h.Cfg.SessionSecret, email, time.Now()),  // #nosec G124 -- Secure theo COOKIE_SECURE; APP_ENV=production bắt buộc COOKIE_SECURE=true (config.validate)
		Path: "/", MaxAge: int(deviceTrustFor.Seconds()), HttpOnly: true, Secure: h.Cfg.CookieSecure,
		SameSite: http.SameSiteLaxMode})
	_ = h.Store.WriteAudit(r.Context(), actorOf(admin.ID, admin.Email, ip), "login", map[string]any{"ok": true})

	http.SetCookie(w, &http.Cookie{Name: h.cookieName, Value: token, Path: "/", Expires: expires,  // #nosec G124 -- Secure theo COOKIE_SECURE; APP_ENV=production bắt buộc COOKIE_SECURE=true (config.validate)
		HttpOnly: true, Secure: h.Cfg.CookieSecure, SameSite: http.SameSiteLaxMode})

	http.Redirect(w, r, "/admin/entries", http.StatusSeeOther)
}

// logout xóa phiên hiện tại và cookie, rồi chuyển về trang đăng nhập.
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if s := sessionFrom(r); s != nil {
		_ = h.Store.DeleteSession(r.Context(), s.IDHash)
	}

	h.clearCookie(w)
	http.Redirect(w, r, "/admin/login?flash=logged_out", http.StatusSeeOther)
}
