package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	chimw "github.com/go-chi/chi/v5/middleware"

	"vsf/internal/apikey"
	"vsf/internal/checker"
	"vsf/internal/metrics"
	"vsf/internal/model"
	"vsf/internal/normalize"
)

func requestIDKey() any { return chimw.RequestIDKey }

func apiKeyFrom(r *http.Request) *model.APIKey {
	k, _ := r.Context().Value(apiKeyKey).(*model.APIKey)
	return k
}

func (h *Handler) apiAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.Cfg.AuthDisabled {
			anon := &model.APIKey{ID: 0, Name: "dev-anonymous", RPSLimit: 1_000_000}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), apiKeyKey, anon)))
			return
		}

		raw := r.Header.Get("X-API-Key")
		if raw == "" {
			if a := r.Header.Get("Authorization"); strings.HasPrefix(a, "Bearer ") {
				raw = strings.TrimPrefix(a, "Bearer ")
			}
		}

		k, err := h.APIKeys.Authenticate(r.Context(), raw)
		if err != nil {
			switch {
			case errors.Is(err, apikey.ErrMissing), errors.Is(err, apikey.ErrInvalid):
				metrics.APIKeyRequests.WithLabelValues("none", "unauthorized").Inc()
				w.Header().Set("WWW-Authenticate", `ApiKey realm="vsf"`)
				writeErr(w, http.StatusUnauthorized, err.Error())

			case errors.Is(err, apikey.ErrRevoked):
				metrics.APIKeyRequests.WithLabelValues("none", "revoked").Inc()
				writeErr(w, http.StatusForbidden, err.Error())

			case errors.Is(err, apikey.ErrExpired):
				metrics.APIKeyRequests.WithLabelValues("none", "expired").Inc()
				writeErr(w, http.StatusForbidden, err.Error())

			default:
				h.Log.Error("api key lookup", "err", err)
				writeErr(w, http.StatusServiceUnavailable, "authentication temporarily unavailable")
			}

			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), apiKeyKey, k)))
	})
}

func (h *Handler) limited(w http.ResponseWriter, r *http.Request, units int) bool {
	k := apiKeyFrom(r)
	id := strconv.FormatInt(k.ID, 10)

	if err := h.APIKeys.Allow(r.Context(), k, units); err != nil {
		switch {
		case errors.Is(err, apikey.ErrRateLimited):
			metrics.APIKeyRequests.WithLabelValues(id, "rate_limited").Inc()
			w.Header().Set("Retry-After", "1")
			writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")

		case errors.Is(err, apikey.ErrQuotaExceeded):
			metrics.APIKeyRequests.WithLabelValues(id, "quota_exceeded").Inc()
			w.Header().Set("Retry-After", "3600")
			writeErr(w, http.StatusTooManyRequests, "daily quota exceeded")

		default:
			h.Log.Error("rate limit", "err", err)
			writeErr(w, http.StatusInternalServerError, "internal error")
		}

		return false
	}

	metrics.APIKeyRequests.WithLabelValues(id, "ok").Inc()
	return true
}

func (h *Handler) apiCheckOne(w http.ResponseWriter, r *http.Request) {
	if !h.limited(w, r, 1) {
		return
	}

	q := r.URL.Query()
	res, err := h.Checker.Check(r.Context(), normalize.Type(q.Get("type")), q.Get("value"))
	if err != nil {
		if errors.Is(err, checker.ErrInvalidInput) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}

		h.Log.Error("check failed", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, res)
}

func (h *Handler) apiCheckBatch(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req struct {
		Items []checker.Item `json:"items"`
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if len(req.Items) == 0 || len(req.Items) > checker.MaxBatch {
		writeErr(w, http.StatusBadRequest, "items must contain 1 to "+strconv.Itoa(checker.MaxBatch)+" entries")
		return
	}

	if !h.limited(w, r, len(req.Items)) {
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"results": h.Checker.CheckBatch(r.Context(), req.Items)})
}
