package handler

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"vsf/internal/apikey"
	"vsf/internal/auth"
	"vsf/internal/model"
	"vsf/internal/store"
)

type auditData struct {
	Logs    []model.AuditLog
	NextURL string
}

func (h *Handler) auditPage(w http.ResponseWriter, r *http.Request) {
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	logs, next, err := h.Store.ListAudit(r.Context(), before, 50)
	if err != nil {
		h.serverError(w, r, err)
		return
	}

	d := auditData{Logs: logs}

	if next > 0 {
		d.NextURL = "/admin/audit?" + url.Values{"before": {strconv.FormatInt(next, 10)}}.Encode()
	}

	pd := h.newPage(r, "Audit log", "audit", d)

	if isHTMX(r) {
		h.render(w, http.StatusOK, "audit", "audit_table", pd)
		return
	}

	h.render(w, http.StatusOK, "audit", "layout", pd)
}

type usersData struct {
	Users []model.Admin
	Roles []model.Role
}

var allRoles = []model.Role{model.RoleViewer, model.RoleEditor, model.RoleAdmin}

func (h *Handler) usersPage(w http.ResponseWriter, r *http.Request) {
	h.renderUsers(w, r, http.StatusOK, "")
}

func (h *Handler) renderUsers(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	users, err := h.Store.ListAdmins(r.Context())
	if err != nil {
		h.serverError(w, r, err)
		return
	}

	pd := h.newPage(r, "Người dùng", "users", usersData{Users: users, Roles: allRoles})
	pd.Error = errMsg
	h.render(w, status, "users", "layout", pd)
}

func (h *Handler) userCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	email := strings.ToLower(strings.TrimSpace(r.PostFormValue("email")))
	password := r.PostFormValue("password")
	role := model.Role(r.PostFormValue("role"))

	switch {
	case !strings.Contains(email, "@") || len(email) > 200:
		h.renderUsers(w, r, http.StatusOK, "Email không hợp lệ.")
		return

	case len(password) < auth.MinPasswordLen:
		h.renderUsers(w, r, http.StatusOK, "Mật khẩu tối thiểu "+strconv.Itoa(auth.MinPasswordLen)+" ký tự.")
		return

	case !model.ValidRole(role):
		h.renderUsers(w, r, http.StatusOK, "Vai trò không hợp lệ.")
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		h.serverError(w, r, err)
		return
	}

	if _, err := h.Store.CreateAdmin(r.Context(), email, hash, role, actorFrom(r)); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			h.renderUsers(w, r, http.StatusOK, "Email này đã tồn tại.")
			return
		}

		h.serverError(w, r, err)
		return
	}

	http.Redirect(w, r, "/admin/users?flash=user_created", http.StatusSeeOther)
}

func (h *Handler) userUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	role := model.Role(r.PostFormValue("role"))
	disabled := r.PostFormValue("disabled") == "1"

	if !model.ValidRole(role) {
		h.renderUsers(w, r, http.StatusOK, "Vai trò không hợp lệ.")
		return
	}

	if me := sessionFrom(r); me != nil && me.AdminID == id && (disabled || role != model.RoleAdmin) {
		h.renderUsers(w, r, http.StatusOK, "Không thể tự khóa hoặc tự hạ quyền chính mình.")
		return
	}

	if err := h.Store.UpdateAdmin(r.Context(), id, role, disabled, actorFrom(r)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}

		h.serverError(w, r, err)
		return
	}

	http.Redirect(w, r, "/admin/users?flash=user_updated", http.StatusSeeOther)
}

type apiKeysData struct {
	Keys   []model.APIKey
	NewKey string
	NewFor string
}

func (h *Handler) apiKeysPage(w http.ResponseWriter, r *http.Request) {
	h.renderAPIKeys(w, r, apiKeysData{}, "")
}

func (h *Handler) renderAPIKeys(w http.ResponseWriter, r *http.Request, d apiKeysData, errMsg string) {
	keys, err := h.Store.ListAPIKeys(r.Context())
	if err != nil {
		h.serverError(w, r, err)
		return
	}

	d.Keys = keys
	pd := h.newPage(r, "API keys", "apikeys", d)
	pd.Error = errMsg
	h.render(w, http.StatusOK, "apikeys", "layout", pd)
}

func (h *Handler) createKey(r *http.Request, name string, rps int, quota int64, exp *time.Time, rotatedFrom *int64) (string, error) {
	full, prefix, hash, err := apikey.Generate()
	if err != nil {
		return "", err
	}

	_, err = h.Store.CreateAPIKey(r.Context(), store.NewAPIKey{Name: name, Prefix: prefix, KeyHash: hash,
		RPSLimit: rps, DailyQuota: quota, ExpiresAt: exp, RotatedFrom: rotatedFrom}, actorFrom(r))
	return full, err
}

func (h *Handler) apiKeyCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	name := strings.TrimSpace(r.PostFormValue("name"))
	rps, err1 := strconv.Atoi(strings.TrimSpace(r.PostFormValue("rps_limit")))
	quota, err2 := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("daily_quota")), 10, 64)
	if name == "" || len(name) > 100 || err1 != nil || err2 != nil || rps < 1 || quota < 0 {
		h.renderAPIKeys(w, r, apiKeysData{}, "Nhập tên, RPS (≥1) và hạn mức/ngày (≥0, 0 = không giới hạn).")
		return
	}

	var exp *time.Time

	if days, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("expires_days"))); err == nil && days > 0 {
		t := time.Now().Add(time.Duration(days) * 24 * time.Hour)
		exp = &t
	}

	full, err := h.createKey(r, name, rps, quota, exp, nil)
	if err != nil {
		h.serverError(w, r, err)
		return
	}

	h.renderAPIKeys(w, r, apiKeysData{NewKey: full, NewFor: name}, "")
}

func (h *Handler) apiKeyRevoke(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	k, err := h.Store.GetAPIKey(r.Context(), id)
	if err == nil {
		err = h.Store.RevokeAPIKey(r.Context(), id, actorFrom(r))
	}

	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}

		h.serverError(w, r, err)
		return
	}

	h.APIKeys.Invalidate(k.Prefix)
	http.Redirect(w, r, "/admin/apikeys?flash=key_revoked", http.StatusSeeOther)
}

func (h *Handler) apiKeyRotate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	grace := 7

	if g, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("grace_days"))); err == nil && g >= 0 && g <= 90 {
		grace = g
	}

	old, err := h.Store.GetAPIKey(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) || (err == nil && old.Status != "active") {
		http.NotFound(w, r)
		return
	} else if err != nil {
		h.serverError(w, r, err)
		return
	}

	full, err := h.createKey(r, old.Name, old.RPSLimit, old.DailyQuota, old.ExpiresAt, &old.ID)
	if err != nil {
		h.serverError(w, r, err)
		return
	}

	cut := time.Now().Add(time.Duration(grace) * 24 * time.Hour)
	if old.ExpiresAt == nil || cut.Before(*old.ExpiresAt) {
		if err := h.Store.SetAPIKeyExpiry(r.Context(), old.ID, cut); err != nil {
			h.serverError(w, r, err)
			return
		}
	}

	h.APIKeys.Invalidate(old.Prefix)
	h.renderAPIKeys(w, r, apiKeysData{NewKey: full, NewFor: old.Name + " (xoay từ #" + strconv.FormatInt(old.ID, 10) + ")"}, "")
}
