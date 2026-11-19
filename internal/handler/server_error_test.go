package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
)

// Client rời trang giữa request: không được ghi ERROR "request failed" hay trả 500.
func TestServerErrorClientCanceled(t *testing.T) {
	var buf bytes.Buffer
	h := &Handler{Deps: Deps{Log: slog.New(slog.NewTextHandler(&buf, nil))}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	r := httptest.NewRequest("PUT", "/admin/entries/1", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	h.serverError(w, r, fmt.Errorf("update: %w", context.Canceled))

	if w.Code != 499 || strings.Contains(buf.String(), "level=ERROR") {
		t.Errorf("client-canceled: code %d, log %q", w.Code, buf.String())
	}

	// Lỗi thật vẫn là 500 + ERROR.
	buf.Reset()
	w = httptest.NewRecorder()
	h.serverError(w, httptest.NewRequest("PUT", "/admin/entries/1", nil), errors.New("boom"))

	if w.Code != 500 || !strings.Contains(buf.String(), "level=ERROR") {
		t.Errorf("real error: code %d, log %q", w.Code, buf.String())
	}
}
