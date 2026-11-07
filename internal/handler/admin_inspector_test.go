package handler

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"vsf/internal/config"
	"vsf/internal/inspector"
	"vsf/internal/model"
)

func TestInspector_Endpoints(t *testing.T) {
	ins := inspector.New(50)

	handlerInstance, err := New(Deps{
		Cfg:       config.Config{CookieSecure: false},
		Inspector: ins,
	})
	if err != nil {
		t.Fatalf("New handler failed: %v", err)
	}

	ins.Record(inspector.Record{
		Time:     time.Now(),
		Method:   "GET",
		Path:     "/v1/check",
		Query:    "type=phone&value=0901234567",
		FullPath: "/v1/check?type=phone&value=0901234567",
		Status:   200,
		Duration: 350 * time.Microsecond,
		ClientIP: "127.0.0.1",
	})

	records := ins.GetRecent(10, "", "", "", "")
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	recordID := records[0].ID

	router := handlerInstance.Router()

	reqHealth := httptest.NewRequest("GET", "/healthz", nil)
	recHealth := httptest.NewRecorder()
	router.ServeHTTP(recHealth, reqHealth)
	if recHealth.Code != 200 {
		t.Errorf("healthz failed with %d", recHealth.Code)
	}

	session := &model.Session{
		AdminID:   1,
		Email:     "admin@example.com",
		Role:      model.RoleAdmin,
		CSRFToken: "test-csrf",
	}

	reqStats := httptest.NewRequest("GET", "/admin/inspector/stats", nil)
	reqStats = reqStats.WithContext(context.WithValue(reqStats.Context(), sessKey, session))
	recStats := httptest.NewRecorder()
	router.ServeHTTP(recStats, reqStats)
	if recStats.Code != 200 {
		t.Fatalf("expected 200 for /admin/inspector/stats, got %d", recStats.Code)
	}
	if !strings.Contains(recStats.Body.String(), "reqs") {
		t.Errorf("expected stats text in response")
	}

	reqFeed := httptest.NewRequest("GET", "/admin/inspector/feed", nil)
	reqFeed = reqFeed.WithContext(context.WithValue(reqFeed.Context(), sessKey, session))
	recFeed := httptest.NewRecorder()
	router.ServeHTTP(recFeed, reqFeed)
	if recFeed.Code != 200 {
		t.Fatalf("expected 200 for /admin/inspector/feed, got %d", recFeed.Code)
	}

	reqDetail := httptest.NewRequest("GET", fmt.Sprintf("/admin/inspector/%d", recordID), nil)
	reqDetail = reqDetail.WithContext(context.WithValue(reqDetail.Context(), sessKey, session))
	recDetail := httptest.NewRecorder()
	router.ServeHTTP(recDetail, reqDetail)
	if recDetail.Code != 200 {
		t.Fatalf("expected 200 for /admin/inspector/{id}, got %d", recDetail.Code)
	}
	if !strings.Contains(recDetail.Body.String(), "/v1/check") {
		t.Errorf("expected request path in detail response")
	}

	reqClear := httptest.NewRequest("POST", "/admin/inspector/clear", nil)
	reqClear.Header.Set("X-CSRF-Token", session.CSRFToken)
	reqClear = reqClear.WithContext(context.WithValue(reqClear.Context(), sessKey, session))
	recClear := httptest.NewRecorder()
	router.ServeHTTP(recClear, reqClear)
	if recClear.Code != 200 {
		t.Fatalf("expected 200 for /admin/inspector/clear, got %d", recClear.Code)
	}
	if len(ins.GetRecent(10, "", "", "", "")) != 0 {
		t.Errorf("expected inspector buffer to be empty after clear")
	}

	viewerSession := &model.Session{
		AdminID:   2,
		Email:     "viewer@example.com",
		Role:      model.RoleViewer,
		CSRFToken: "test-csrf-2",
	}
	reqViewerFeed := httptest.NewRequest("GET", "/admin/inspector/feed", nil)
	reqViewerFeed = reqViewerFeed.WithContext(context.WithValue(reqViewerFeed.Context(), sessKey, viewerSession))
	recViewerFeed := httptest.NewRecorder()
	router.ServeHTTP(recViewerFeed, reqViewerFeed)
	if recViewerFeed.Code != 403 {
		t.Errorf("expected 403 for viewer accessing inspector feed, got %d", recViewerFeed.Code)
	}

	reqUnauth := httptest.NewRequest("GET", "/admin/inspector/feed", nil)
	recUnauth := httptest.NewRecorder()
	router.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != 303 {
		t.Errorf("expected 303 for unauthenticated user accessing inspector, got %d", recUnauth.Code)
	}
}

func TestInspector_DetailShowsHandlerSource(t *testing.T) {
	ins := inspector.New(10)
	h, err := New(Deps{Cfg: config.Config{InspectorShowSource: true}, Inspector: ins})
	if err != nil {
		t.Fatal(err)
	}
	router := h.Router()

	ins.Record(inspector.Record{
		Time: time.Now(), Method: "GET", Path: "/admin/entries", FullPath: "/admin/entries",
		Route: "/admin/entries", Screen: "/admin/entries", Status: 200,
	})
	id := ins.GetRecent(1, "", "", "", "")[0].ID

	session := &model.Session{AdminID: 1, Email: "a@x.io", Role: model.RoleAdmin, CSRFToken: "c"}
	req := httptest.NewRequest("GET", fmt.Sprintf("/admin/inspector/%d", id), nil)
	req = req.WithContext(context.WithValue(req.Context(), sessKey, session))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "listEntries") {
		t.Fatalf("expected handler name listEntries in detail, code=%d body=%s", rec.Code, body)
	}
	if !strings.Contains(body, "func (h *Handler) listEntries") {
		t.Errorf("expected handler source code in detail")
	}
}

func TestInspector_DetailMiddlewareAndSourceToggle(t *testing.T) {
	for _, show := range []bool{true, false} {
		ins := inspector.New(10)
		h, err := New(Deps{Cfg: config.Config{InspectorShowSource: show}, Inspector: ins})
		if err != nil {
			t.Fatal(err)
		}
		router := h.Router()

		ins.Record(inspector.Record{Time: time.Now(), Method: "GET", Path: "/admin/entries",
			Route: "/admin/entries", Screen: "/admin/entries", Status: 200})
		id := ins.GetRecent(1, "", "", "", "")[0].ID

		session := &model.Session{AdminID: 1, Email: "a@x.io", Role: model.RoleAdmin, CSRFToken: "c"}
		req := httptest.NewRequest("GET", fmt.Sprintf("/admin/inspector/%d", id), nil)
		req = req.WithContext(context.WithValue(req.Context(), sessKey, session))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		body := rec.Body.String()

		if !strings.Contains(body, "requireSession") {
			t.Errorf("show=%v: expected requireSession in middleware chain", show)
		}
		hasCode := strings.Contains(body, "func (h *Handler) listEntries")
		if hasCode != show {
			t.Errorf("show=%v: source visible=%v", show, hasCode)
		}
	}
}
