package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Tham số -mode và -batch sai phải bị từ chối trước khi gửi request nào.
func TestBenchRejectsBadModeAndBatch(t *testing.T) {
	if err := run([]string{"-mode", "khong-co"}, io.Discard); err == nil {
		t.Fatal("-mode sai phải báo lỗi")
	}

	if err := run([]string{"-batch", "0"}, io.Discard); err == nil {
		t.Fatal("-batch 0 phải báo lỗi")
	}

	if err := run([]string{"-batch", "101"}, io.Discard); err == nil {
		t.Fatal("-batch 101 phải báo lỗi")
	}
}

// Chế độ batch: mỗi request là POST /v1/check/batch đúng số mục, và kết quả có đếm mục/s.
func TestBenchBatchModeSendsRequestedItems(t *testing.T) {
	var posts, badItems atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/check/batch" {
			http.Error(w, "sai đường dẫn", http.StatusNotFound)

			return
		}

		posts.Add(1)

		var req struct {
			Items []json.RawMessage `json:"items"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Items) != 5 {
			badItems.Add(1)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	defer srv.Close()

	var out bytes.Buffer

	if err := run([]string{"-url", srv.URL, "-mode", "batch", "-batch", "5", "-c", "2", "-d", "300ms"}, &out); err != nil {
		t.Fatalf("run: %v", err)
	}

	if posts.Load() == 0 {
		t.Fatal("chưa có request batch nào tới server")
	}

	if badItems.Load() != 0 {
		t.Fatalf("%d request có số mục khác 5", badItems.Load())
	}

	s := out.String()
	if !strings.Contains(s, "mode=batch") || !strings.Contains(s, "items_per_s=") {
		t.Fatalf("kết quả thiếu thông tin chế độ batch:\n%s", s)
	}
}
