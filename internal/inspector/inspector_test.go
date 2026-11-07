package inspector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInspector_RecordAndGetRecent(t *testing.T) {
	ins := New(10)

	ins.Record(Record{
		Time:     time.Now(),
		Method:   "GET",
		Path:     "/v1/check",
		Query:    "type=phone&value=0901234567",
		Status:   200,
		Duration: 500 * time.Microsecond,
		ClientIP: "127.0.0.1",
	})

	ins.Record(Record{
		Time:     time.Now(),
		Method:   "POST",
		Path:     "/v1/check/batch",
		Status:   400,
		Duration: 1200 * time.Microsecond,
		ClientIP: "192.168.1.10",
	})

	stats := ins.GetStats("")
	if stats.TotalRequests != 2 {
		t.Fatalf("expected 2 requests, got %d", stats.TotalRequests)
	}
	if stats.Count2xx != 1 || stats.Count4xx != 1 {
		t.Fatalf("expected 1 2xx and 1 4xx, got %d, %d", stats.Count2xx, stats.Count4xx)
	}

	recent := ins.GetRecent(10, "", "", "", "")
	if len(recent) != 2 {
		t.Fatalf("expected 2 recent, got %d", len(recent))
	}
	if recent[0].Method != "POST" {
		t.Errorf("expected latest to be POST, got %s", recent[0].Method)
	}

	filtered := ins.GetRecent(10, "GET", "", "", "")
	if len(filtered) != 1 || filtered[0].Method != "GET" {
		t.Fatalf("expected 1 GET, got %v", filtered)
	}

	errFiltered := ins.GetRecent(10, "", "errors", "", "")
	if len(errFiltered) != 1 || errFiltered[0].Status != 400 {
		t.Fatalf("expected 1 error, got %v", errFiltered)
	}

	searchFiltered := ins.GetRecent(10, "", "", "batch", "")
	if len(searchFiltered) != 1 || searchFiltered[0].Path != "/v1/check/batch" {
		t.Fatalf("expected 1 match for batch, got %v", searchFiltered)
	}

	rec := ins.GetByID(recent[0].ID)
	if rec == nil || rec.Path != "/v1/check/batch" {
		t.Fatalf("GetByID failed for %d", recent[0].ID)
	}

	ins.Clear()
	if len(ins.GetRecent(10, "", "", "", "")) != 0 {
		t.Fatalf("expected 0 records after clear")
	}
}

func TestExtractHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-API-Key", "vsf_testkey_1234567890abcdef123456")
	h.Set("Random-Header", "value")

	res := ExtractHeaders(h)
	if res["Content-Type"] != "application/json" {
		t.Errorf("expected application/json, got %s", res["Content-Type"])
	}
	if res["X-API-Key"] == "" || len(res["X-API-Key"]) >= len("vsf_testkey_1234567890abcdef123456") {
		t.Errorf("expected masked X-API-Key, got %s", res["X-API-Key"])
	}
	if _, ok := res["Random-Header"]; ok {
		t.Errorf("did not expect Random-Header in extracted set")
	}
}

func TestInspector_ScreenScope(t *testing.T) {
	ins := New(10)
	ins.Record(Record{Time: time.Now(), Method: "GET", Path: "/admin/entries", Screen: "/admin/entries", Status: 200})
	ins.Record(Record{Time: time.Now(), Method: "GET", Path: "/admin/entries", Query: "q=1", Screen: "/admin/entries", Status: 500})
	ins.Record(Record{Time: time.Now(), Method: "POST", Path: "/admin/check", Screen: "/admin/check", Status: 200})

	if got := len(ins.GetRecent(10, "", "", "", "/admin/entries")); got != 2 {
		t.Fatalf("entries screen: want 2, got %d", got)
	}
	if got := len(ins.GetRecent(10, "", "", "", "/admin/check")); got != 1 {
		t.Fatalf("check screen: want 1, got %d", got)
	}
	if got := len(ins.GetRecent(10, "", "", "", "")); got != 3 {
		t.Fatalf("no scope: want 3, got %d", got)
	}

	st := ins.GetStats("/admin/entries")
	if st.TotalRequests != 2 || st.Count5xx != 1 {
		t.Fatalf("scoped stats wrong: %+v", st)
	}
	if st := ins.GetStats("/nope"); st.TotalRequests != 0 {
		t.Fatalf("unknown screen should be empty: %+v", st)
	}
}

func TestScreenOf(t *testing.T) {
	plain := httptest.NewRequest("GET", "/admin/check", nil)
	plain.Header.Set("Referer", "http://x/admin/entries")
	if got := ScreenOf(plain); got != "/admin/check" {
		t.Errorf("page load: got %q", got)
	}

	hx := httptest.NewRequest("GET", "/admin/entries?q=a", nil)
	hx.Header.Set("HX-Request", "true")
	hx.Header.Set("HX-Current-URL", "http://x/admin/entries?page=2")
	if got := ScreenOf(hx); got != "/admin/entries" {
		t.Errorf("htmx via HX-Current-URL: got %q", got)
	}

	hx2 := httptest.NewRequest("POST", "/admin/check", nil)
	hx2.Header.Set("HX-Request", "true")
	hx2.Header.Set("Referer", "http://x/admin/import")
	if got := ScreenOf(hx2); got != "/admin/import" {
		t.Errorf("htmx via Referer: got %q", got)
	}
}

func TestRedactBody(t *testing.T) {
	if got := RedactBody("/admin/login", "email=a@b.c&password=hunter2"); strings.Contains(got, "hunter2") {
		t.Errorf("login body leaked: %q", got)
	}
	got := RedactBody("/admin/users", "email=a@b.c&password=hunter2&csrf_token=abc123&role=admin")
	for _, leak := range []string{"hunter2", "abc123"} {
		if strings.Contains(got, leak) {
			t.Errorf("leaked %q in %q", leak, got)
		}
	}
	if !strings.Contains(got, "email=a@b.c") || !strings.Contains(got, "role=admin") {
		t.Errorf("non-sensitive fields lost: %q", got)
	}
	if got := RedactBody("/x", `{"api_key": "sekret99", "n": 1}`); strings.Contains(got, "sekret99") {
		t.Errorf("json key leaked: %q", got)
	}
}

func TestMaskSensitive(t *testing.T) {
	cases := map[string]string{
		"type=phone&value=0901234567":      "type=phone&value=090***",
		"value=https://evil.example/login": "value=htt***",
		"/lookup/0901234567":               "/lookup/090***67",
		"+84901234567":                     "+849***67",
		"page=2&dir=asc":                   "page=2&dir=asc",
	}
	for in, want := range cases {
		if got := MaskSensitive(in); got != want {
			t.Errorf("MaskSensitive(%q) = %q, want %q", in, got, want)
		}
	}

	ins := New(5)
	ins.Record(Record{Time: time.Now(), Method: "GET", Path: "/v1/check", Query: "value=0901234567", Status: 200})
	rec := ins.GetRecent(1, "", "", "", "")[0]
	if strings.Contains(rec.Query, "1234567") {
		t.Errorf("inspector stored full phone number: %q", rec.Query)
	}
}
