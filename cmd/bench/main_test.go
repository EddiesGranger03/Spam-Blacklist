package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// draw lấy mẫu từ bộ chọn (picker) đã cho, dùng cho test phân bố.
func draw(t *testing.T, dist string, s float64, n, count int, seed int64) []int {
	t.Helper()

	pick, err := newPicker(dist, s, n, rand.New(rand.NewSource(seed)))
	if err != nil {
		t.Fatal(err)
	}

	out := make([]int, count)
	for i := range out {
		out[i] = pick()
	}

	return out
}

// TestResolveSeed kiểm tra cách chọn seed (0 là theo thời gian, khác 0 là cố định).
func TestResolveSeed(t *testing.T) {
	if got := resolveSeed(7); got != 7 {
		t.Fatalf("seed cố định phải giữ nguyên, got %d", got)
	}

	if resolveSeed(0) == 0 {
		t.Fatal("seed 0 phải được đổi thành giá trị theo thời gian")
	}
}

// TestWorkerSeedsDifferAndAreStable kiểm tra seed mỗi worker khác nhau nhưng ổn định qua các lần chạy.
func TestWorkerSeedsDifferAndAreStable(t *testing.T) {
	if workerSeed(100, 0) == workerSeed(100, 1) {
		t.Fatal("hai luồng không được dùng chung seed")
	}

	if workerSeed(100, 3) != workerSeed(100, 3) {
		t.Fatal("cùng seed + luồng phải cho cùng kết quả")
	}
}

// Cùng seed thì dãy khóa giống hệt (để chạy lại được), khác seed thì khác.
func TestSameSeedReplaysDifferentSeedDiffers(t *testing.T) {
	a := draw(t, "uniform", 0, 1000, 200, 1)
	b := draw(t, "uniform", 0, 1000, 200, 1)
	c := draw(t, "uniform", 0, 1000, 200, 2)

	same, diff := true, false

	for i := range a {
		if a[i] != b[i] {
			same = false
		}

		if a[i] != c[i] {
			diff = true
		}
	}

	if !same {
		t.Fatal("cùng seed phải phát lại đúng dãy cũ")
	}

	if !diff {
		t.Fatal("khác seed phải cho dãy khác")
	}
}

// TestPickerRangeAndSkew kiểm tra bộ chọn khóa nằm trong khoảng và phân bố có lệch.
func TestPickerRangeAndSkew(t *testing.T) {
	const n, count = 10000, 100000

	for _, dist := range []string{"uniform", "zipf"} {
		for _, v := range draw(t, dist, 1.1, n, count, 5) {
			if v < 0 || v >= n {
				t.Fatalf("%s: chỉ số %d ngoài [0,%d)", dist, v, n)
			}
		}
	}

	top := func(xs []int) float64 {
		c := 0

		for _, x := range xs {
			if x < n/100 { // 1% khóa đầu tiên
				c++
			}
		}

		return float64(c) / float64(len(xs))
	}

	if u := top(draw(t, "uniform", 0, n, count, 5)); u > 0.03 {
		t.Errorf("uniform: 1%% khóa đầu chiếm %.1f%% lượt chọn, kỳ vọng ≈1%%", 100*u)
	}

	if z := top(draw(t, "zipf", 1.1, n, count, 5)); z < 0.4 {
		t.Errorf("zipf: 1%% khóa đầu chỉ chiếm %.1f%% lượt chọn, kỳ vọng >40%%", 100*z)
	}
}

// TestPickerValidation kiểm tra bộ chọn từ chối tham số không hợp lệ.
func TestPickerValidation(t *testing.T) {
	rng := rand.New(rand.NewSource(1))

	if _, err := newPicker("zipf", 1.0, 10, rng); err == nil {
		t.Error("zipf với s<=1 phải bị từ chối")
	}

	if _, err := newPicker("gauss", 1.5, 10, rng); err == nil {
		t.Error("dist lạ phải bị từ chối")
	}

	if _, err := newPicker("uniform", 0, 0, rng); err == nil {
		t.Error("không có khóa nào phải bị từ chối")
	}
}

// TestClassify kiểm tra hàm phân loại kết quả request.
func TestClassify(t *testing.T) {
	cases := map[string]error{
		"conn_forcibly_closed":      errors.New("read tcp: wsarecv: An existing connection was forcibly closed by the remote host."),
		"conn_refused":              errors.New("dial tcp 127.0.0.1:8099: connectex: No connection could be made because the target machine actively refused it."),
		"ephemeral_ports_exhausted": errors.New("dial tcp: connectex: Only one usage of each socket address is normally permitted."),
		"conn_aborted":              errors.New("wsasend: An established connection was aborted by the software in your host machine."),
		"timeout":                   context.DeadlineExceeded,
		"eof":                       io.EOF,
	}

	for want, err := range cases {
		if got := classify(err); got != want {
			t.Errorf("classify(%q) = %q, want %q", err, got, want)
		}
	}

	if got := classify(errors.New("something unexpected")); got != "other: something unexpected" {
		t.Errorf("lỗi lạ phải vào nhóm other, got %q", got)
	}
}

var sampleMetrics = string(rune(0xFEFF)) + "\r\n" +
	"vsf_cache_errors_total 0\r\n" +
	"vsf_check_layer_total{layer=\"bloom\"} 5.1204e+06\r\n" +
	"vsf_check_layer_total{layer=\"cache\"} 479962\r\n" +
	"vsf_check_layer_total{layer=\"db\"} 141088\r\n"

// TestParseLayersAndRatio kiểm tra đọc số liệu các lớp và tỉ lệ trúng.
func TestParseLayersAndRatio(t *testing.T) {
	after := parseLayers(sampleMetrics)

	if after["bloom"] != 5120400 || after["cache"] != 479962 || after["db"] != 141088 {
		t.Fatalf("parse sai: %v", after)
	}

	// bộ đếm chưa tồn tại ở lần chụp đầu được coi là 0
	d := layerDelta(map[string]float64{}, after)
	if d["cache"] != 479962 {
		t.Fatalf("delta với before rỗng phải bằng after, got %v", d)
	}

	r, ok := cacheHitRatio(d)
	if !ok || math.Abs(r-0.77283) > 0.0001 {
		t.Fatalf("cacheHitRatio = %v, %v; want ≈0.7728", r, ok)
	}

	// hiệu thật sự: before có sẵn một phần
	d2 := layerDelta(map[string]float64{"cache": 100, "db": 50, "bloom": 10}, map[string]float64{"cache": 160, "db": 90, "bloom": 30})
	if d2["cache"] != 60 || d2["db"] != 40 || d2["bloom"] != 20 {
		t.Fatalf("delta sai: %v", d2)
	}

	if r, _ := cacheHitRatio(d2); math.Abs(r-0.6) > 1e-9 {
		t.Fatalf("ratio = %v, want 0.6", r)
	}
}

// TestCacheHitRatioNoLookups kiểm tra tỉ lệ trúng cache khi không có lượt tra cứu (không chia cho 0).
func TestCacheHitRatioNoLookups(t *testing.T) {
	if _, ok := cacheHitRatio(map[string]float64{"bloom": 1000}); ok {
		t.Fatal("không có lượt xuống cache/DB thì ok phải là false")
	}
}

// fakeServer trả lời /v1/check như server thật (số bắt đầu bằng 0909 bị chặn) và có /metrics với các bộ đếm lớp.
func fakeServer(t *testing.T, hitsSeen *atomic.Int64) *httptest.Server {
	t.Helper()

	var layerCalls atomic.Int64

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/check", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if strings.HasPrefix(r.URL.Query().Get("value"), "0909") {
			hitsSeen.Add(1)
			fmt.Fprint(w, `{"blacklisted":true}`)

			return
		}

		fmt.Fprint(w, `{"blacklisted":false}`)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		n := layerCalls.Add(1) * 10
		fmt.Fprintf(w, "vsf_check_layer_total{layer=\"bloom\"} %d\nvsf_check_layer_total{layer=\"cache\"} %d\nvsf_check_layer_total{layer=\"db\"} %d\n", n*5, n*3, n)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv
}

func writeCSV(t *testing.T) string {
	t.Helper()

	p := filepath.Join(t.TempDir(), "data.csv")
	if err := os.WriteFile(p, []byte("phone,0909000001,spam\nphone,0909000002,spam\nurl,http://x.example,spam\nphone,0909000003,spam\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	return p
}

func TestRunAgainstAServer(t *testing.T) {
	var hits atomic.Int64

	srv := fakeServer(t, &hits)

	var out strings.Builder

	err := run([]string{"-url", srv.URL, "-key", "k", "-file", writeCSV(t), "-c", "4", "-d", "300ms", "-hit", "0.5", "-seed", "7",
		"-metrics-url", srv.URL + "/metrics"}, &out)
	if err != nil {
		t.Fatal(err)
	}

	got := out.String()

	for _, want := range []string{"requests=", "latency p50=", "status=map[200:", "seed=7 dist=uniform", "layers(delta) bloom=", "cache_hit_ratio="} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}

	if hits.Load() == 0 || !strings.Contains(got, "blacklisted_responses=") || strings.Contains(got, "blacklisted_responses=0") {
		t.Errorf("with hit=0.5 the server must have seen blacklisted keys (saw %d):\n%s", hits.Load(), got)
	}
}

func TestRunZipfAndSameSeedIsReproducible(t *testing.T) {
	var hits atomic.Int64

	srv := fakeServer(t, &hits)
	csv := writeCSV(t)

	var out strings.Builder
	if err := run([]string{"-url", srv.URL, "-key", "k", "-file", csv, "-c", "2", "-d", "200ms", "-dist", "zipf", "-zipf-s", "1.5", "-seed", "3"}, &out); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out.String(), "dist=zipf zipf_s=1.50") {
		t.Errorf("zipf parameters must be echoed:\n%s", out.String())
	}
}

func TestRunReportsErrorsAndBadInput(t *testing.T) {
	var out strings.Builder

	// không có server: mọi request lỗi, có nguyên nhân, không panic
	if err := run([]string{"-url", "http://127.0.0.1:1", "-c", "2", "-d", "200ms", "-seed", "1"}, &out); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(out.String(), "error_causes=") || !strings.Contains(out.String(), "status=map[0:") {
		t.Errorf("unreachable server must be reported with causes:\n%s", out.String())
	}

	// metrics không đọc được: bỏ qua phần tỉ lệ cache, vẫn chạy xong
	out.Reset()

	var hits atomic.Int64

	srv := fakeServer(t, &hits)
	if err := run([]string{"-url", srv.URL, "-key", "k", "-c", "1", "-d", "100ms", "-metrics-url", "http://127.0.0.1:1/metrics"}, &out); err != nil ||
		strings.Contains(out.String(), "layers(delta)") {
		t.Fatalf("an unreadable metrics endpoint must be skipped: %v\n%s", err, out.String())
	}

	for name, args := range map[string][]string{
		"unknown flag": {"-nope"},
		"bad dist":     {"-dist", "weird"},
		"missing file": {"-file", filepath.Join(t.TempDir(), "absent.csv")},
		"bad zipf":     {"-file", writeCSV(t), "-dist", "zipf", "-zipf-s", "0.5"},
		"no requests":  {"-url", srv.URL, "-d", "0s"},
	} {
		if err := run(args, io.Discard); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestFetchLayers(t *testing.T) {
	var hits atomic.Int64

	srv := fakeServer(t, &hits)

	d, err := fetchLayers(srv.URL + "/metrics")
	if err != nil || d["bloom"] != 50 || d["cache"] != 30 || d["db"] != 10 {
		t.Fatalf("fetchLayers: %v %v", d, err)
	}

	if _, err := fetchLayers("http://127.0.0.1:1/metrics"); err == nil {
		t.Error("an unreachable endpoint must be an error")
	}
}
