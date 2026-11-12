package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"vsf/internal/cache"
	"vsf/internal/checker"
	"vsf/internal/model"
	"vsf/internal/normalize"
)

type everyKeyFilter struct{}

func (everyKeyFilter) Test(uint64) bool { return true }

type brokenFinder struct{}

func (brokenFinder) FindMatches(context.Context, []normalize.Key) ([]model.Entry, error) {
	return nil, errors.New(`pq: relation "secret_internal_table" does not exist`)
}

type fixedEpoch struct{}

func (fixedEpoch) Epoch() string { return "1.1" }

// Lỗi bên trong khi check (ở đây: database lỗi): trả 500 với thông báo chung, không lộ chi tiết nội bộ cho người dùng.
func TestAppCheckSubmitHidesInternalErrors(t *testing.T) {
	a := newApp(t)

	h2 := *a.h
	h2.Checker = checker.New("VN", everyKeyFilter{}, cache.Noop{}, brokenFinder{}, fixedEpoch{})

	do := func(body string, htmx bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/admin/check", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		if htmx {
			r.Header.Set("HX-Request", "true")
		}

		w := httptest.NewRecorder()
		h2.checkSubmit(w, r)

		return w
	}

	w := do(url.Values{"type": {"phone"}, "value": {"0901234567"}}.Encode(), false)
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "secret_internal_table") ||
		strings.Contains(w.Body.String(), "pq:") {
		t.Errorf("an internal error must be a generic 500 without internals: %d %s", w.Code, w.Body.String())
	}

	// dữ liệu nhập sai vẫn là lỗi của người dùng (200 kèm thông báo), không phải 500
	w = do(url.Values{"type": {"phone"}, "value": {"not-a-number"}}.Encode(), true)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "not-a-number") {
		t.Errorf("an invalid value is the user's error: %d %s", w.Code, w.Body.String())
	}

	// body form hỏng (percent-encoding sai)
	w = do("type=phone&value=%zz", false)
	if w.Code != http.StatusBadRequest {
		t.Errorf("a malformed form body: %d", w.Code)
	}
}

// render: thiếu trang, hoặc trang thiếu template con, phải trả 500 chung thay vì panic hay ghi một nửa trang.
func TestAppRenderFailuresAreContained(t *testing.T) {
	a := newApp(t)

	render := func(page, name string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		a.h.render(w, http.StatusOK, page, name, pageData{Data: loginData{}})

		return w
	}

	if w := render("no-such-page", "layout"); w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "template not found") {
		t.Errorf("unknown page: %d %s", w.Code, w.Body.String())
	}

	w := render("check", "no-such-template")
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "internal error") || strings.Contains(w.Body.String(), "no-such-template") {
		t.Errorf("unknown template: %d %s", w.Code, w.Body.String())
	}

	// trang hợp lệ vẫn render bình thường
	if w := render("login", "layout"); w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Errorf("a valid page must still render: %d", w.Code)
	}
}
