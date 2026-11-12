package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// resolveSeed trả về seed cơ sở của lượt chạy. 0 nghĩa là lấy theo thời gian, để mỗi lượt chạy
// sinh một dãy khóa khác nhau (seed cố định làm các lượt "phát lại" cùng một dãy khóa, khiến
// tỉ lệ trúng cache bị đẩy cao giả tạo). Truyền một số khác 0 để chạy lại đúng một dãy cũ.
func resolveSeed(seed int64) int64 {
	if seed != 0 {
		return seed
	}

	return time.Now().UnixNano()
}

// workerSeed cho mỗi luồng một seed riêng, suy ra từ seed cơ sở.
func workerSeed(base int64, worker int) int64 { return base + int64(worker) }

// newPicker trả về hàm chọn chỉ số khóa trong [0, n). "uniform" chọn đều; "zipf" lệch về các
// chỉ số đầu (khóa nóng), giống lưu lượng thật hơn. Zipf yêu cầu s > 1.
func newPicker(dist string, s float64, n int, rng *rand.Rand) (func() int, error) {
	if n <= 0 {
		return nil, errors.New("không có khóa nào để chọn")
	}

	switch dist {
	case "uniform":
		return func() int { return rng.Intn(n) }, nil

	case "zipf":
		if s <= 1 {
			return nil, fmt.Errorf("-zipf-s phải lớn hơn 1 (nhận %v)", s)
		}

		z := rand.NewZipf(rng, s, 1, uint64(n-1))

		return func() int { return int(z.Uint64()) }, nil  // #nosec G115 -- chỉ số khóa nằm trong [0, n) do bộ sinh Zipf tạo ra, n là số khóa đã đọc
	}

	return nil, fmt.Errorf("-dist phải là uniform hoặc zipf (nhận %q)", dist)
}

// classify gom lỗi kết nối vào vài nhóm dễ đọc, thay vì chỉ đếm chung là mã 0.
func classify(err error) string {
	s := err.Error()

	var ne net.Error

	switch {
	case strings.Contains(s, "forcibly closed"):
		return "conn_forcibly_closed"

	case strings.Contains(s, "actively refused") || strings.Contains(s, "connection refused"):
		return "conn_refused"

	case strings.Contains(s, "can't assign requested address") || strings.Contains(s, "Only one usage of each socket"):
		return "ephemeral_ports_exhausted"

	case strings.Contains(s, "aborted"):
		return "conn_aborted"

	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"

	case strings.Contains(s, "EOF"):
		return "eof"
	}

	if len(s) > 80 {
		s = s[:80]
	}

	return "other: " + s
}

var layerLine = regexp.MustCompile(`^vsf_check_layer_total\{layer="([^"]+)"\}\s+(\S+)`)

// parseLayers đọc bộ đếm vsf_check_layer_total từ văn bản /metrics.
func parseLayers(text string) map[string]float64 {
	out := map[string]float64{}

	for _, line := range strings.Split(text, "\n") {
		m := layerLine.FindStringSubmatch(strings.TrimSpace(strings.TrimPrefix(line, string(rune(0xFEFF)))))
		if m == nil {
			continue
		}

		if v, err := strconv.ParseFloat(m[2], 64); err == nil {
			out[m[1]] = v
		}
	}

	return out
}

// layerDelta là hiệu after - before. Một nhãn chưa xuất hiện ở before được coi là 0
// (Prometheus chỉ tạo bộ đếm có nhãn sau lần tăng đầu tiên).
func layerDelta(before, after map[string]float64) map[string]float64 {
	out := map[string]float64{}
	for k, v := range after {
		out[k] = v - before[k]
	}

	return out
}

// cacheHitRatio = cache / (cache + db): trong các request mà Bloom nói "có thể có", bao nhiêu
// phần được cache trả lời. ok=false khi chưa có lượt tra nào.
func cacheHitRatio(d map[string]float64) (ratio float64, ok bool) {
	lookups := d["cache"] + d["db"]
	if lookups <= 0 {
		return 0, false
	}

	return d["cache"] / lookups, true
}

// fetchLayers đọc số lượt tra cứu theo từng lớp (Bloom, cache, DB) từ endpoint metrics.
func fetchLayers(url string) (map[string]float64, error) {
	c := &http.Client{Timeout: 5 * time.Second}

	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return parseLayers(string(b)), nil
}

// main chạy benchmark: đọc tham số, sinh tải và in kết quả.
func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		log.Fatal(err)
	}
}

// run là phần thân của main, tách ra để test được: nhận tham số và nơi in kết quả.
func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)

	base := fs.String("url", "http://127.0.0.1:8090", "địa chỉ server")
	key := fs.String("key", "", "API key (bỏ trống nếu server chạy AUTH_DISABLED)")
	file := fs.String("file", "", "CSV chứa các SĐT đã import (để lấy khóa trúng)")
	conc := fs.Int("c", 64, "số kết nối đồng thời")
	dur := fs.Duration("d", 20*time.Second, "thời gian chạy")
	hit := fs.Float64("hit", 0.1, "tỉ lệ request dùng khóa TRÚNG blacklist (0..1)")
	seed := fs.Int64("seed", 0, "seed ngẫu nhiên; 0 = theo thời gian (mỗi lượt một dãy khóa khác nhau), số khác 0 = chạy lại đúng dãy cũ")
	dist := fs.String("dist", "uniform", "cách chọn khóa trúng: uniform (đều) hoặc zipf (có khóa nóng)")
	zipfS := fs.Float64("zipf-s", 1.1, "độ lệch của zipf (phải > 1, càng lớn càng có ít khóa rất nóng chiếm hết)")
	mode := fs.String("mode", "single", "single: GET /v1/check từng mục; batch: POST /v1/check/batch gồm -batch mục")
	batchN := fs.Int("batch", 100, "số mục mỗi request khi -mode batch (1..100)")
	metricsURL := fs.String("metrics-url", "", "địa chỉ /metrics của server; nếu đặt, in tỉ lệ rơi vào Bloom/cache/DB và tỉ lệ trúng cache của lượt chạy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *mode != "single" && *mode != "batch" {
		return fmt.Errorf("-mode phải là single hoặc batch, nhận được %q", *mode)
	}
	if *batchN < 1 || *batchN > 100 {
		return fmt.Errorf("-batch phải từ 1 đến 100, nhận được %d", *batchN)
	}

	var hits []string

	if *file != "" {
		f, err := os.Open(*file)
		if err != nil {
			return err
		}

		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if p := strings.Split(sc.Text(), ","); len(p) > 1 && p[0] == "phone" {
				hits = append(hits, p[1])
			}
		}

		_ = f.Close() // chỉ đọc: lỗi đóng không ảnh hưởng kết quả
		log.Printf("nạp %d SĐT trúng", len(hits))
	}

	baseSeed := resolveSeed(*seed)

	if len(hits) > 0 {
		// kiểm tra tham số sớm, trước khi tạo luồng
		if _, err := newPicker(*dist, *zipfS, len(hits), rand.New(rand.NewSource(baseSeed))); err != nil {  // #nosec G404 -- bộ sinh tải benchmark, cần tái lập được theo seed
			return err
		}
	} else if *dist != "uniform" && *dist != "zipf" {
		return fmt.Errorf("-dist phải là uniform hoặc zipf (nhận %q)", *dist)
	}

	log.Printf("seed=%d dist=%s", baseSeed, *dist)

	var layersBefore map[string]float64

	if *metricsURL != "" {
		var err error
		if layersBefore, err = fetchLayers(*metricsURL); err != nil {
			log.Printf("không đọc được metrics (bỏ qua phần tỉ lệ cache): %v", err)
			*metricsURL = ""
		}
	}

	tr := &http.Transport{MaxIdleConns: *conc * 2, MaxIdleConnsPerHost: *conc * 2, IdleConnTimeout: 30 * time.Second}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	var (
		mu       sync.Mutex
		lat      []time.Duration
		status   = map[int]int{}
		errCause = map[string]int{}
		blocked  atomic.Int64
		totalItems atomic.Int64
		total    atomic.Int64
		deadline = time.Now().Add(*dur)
		wg       sync.WaitGroup
	)

	start := time.Now()

	for w := 0; w < *conc; w++ {
		wg.Add(1)

		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))  // #nosec G404 -- bộ sinh tải benchmark, cần tái lập được theo seed
			local := make([]time.Duration, 0, 4096)
			localStatus := map[int]int{}
			localCause := map[string]int{}

			var pick func() int

			if len(hits) > 0 {
				pick, _ = newPicker(*dist, *zipfS, len(hits), rng) // tham số đã được kiểm tra ở trên
			}

			for time.Now().Before(deadline) {
				var phone string

				if *mode == "batch" {
					items := make([]string, 0, *batchN)
					for i := 0; i < *batchN; i++ {
						p := ""
						if pick != nil && rng.Float64() < *hit {
							p = hits[pick()]
						} else {
							p = fmt.Sprintf("09%08d", rng.Intn(100000000))
						}
						items = append(items, fmt.Sprintf(`{"type":"phone","value":"%s"}`, p))
					}
					body := `{"items":[` + strings.Join(items, ",") + `]}`
					req, _ := http.NewRequest("POST", *base+"/v1/check/batch", strings.NewReader(body))
					req.Header.Set("Content-Type", "application/json")
					if *key != "" {
						req.Header.Set("X-API-Key", *key)
					}
					t0 := time.Now()
					resp, err := client.Do(req)
					d := time.Since(t0)
					code := 0
					if err == nil {
						b, _ := io.ReadAll(resp.Body)
						_ = resp.Body.Close() // đã đọc hết body; lỗi đóng không ảnh hưởng kết quả
						code = resp.StatusCode
						if code == 200 {
							blocked.Add(int64(strings.Count(string(b), `"blacklisted":true`)))
							items := int64(*batchN)
							totalItems.Add(items)
						}
					} else {
						localCause[classify(err)]++
					}
					local = append(local, d)
					localStatus[code]++
					total.Add(1)
					continue
				}

				if pick != nil && rng.Float64() < *hit {
					phone = hits[pick()]
				} else {
					phone = fmt.Sprintf("09%08d", rng.Intn(100000000))
				}

				req, _ := http.NewRequest("GET", *base+"/v1/check?type=phone&value="+phone, nil)

				if *key != "" {
					req.Header.Set("X-API-Key", *key)
				}

				t0 := time.Now()
				resp, err := client.Do(req)
				d := time.Since(t0)
				code := 0

				if err == nil {
					b, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close() // đã đọc hết body; lỗi đóng không ảnh hưởng kết quả
					code = resp.StatusCode
					if code == 200 && strings.Contains(string(b), `"blacklisted":true`) {
						blocked.Add(1)
					}
				} else {
					localCause[classify(err)]++
				}

				local = append(local, d)
				localStatus[code]++
				total.Add(1)
			}

			mu.Lock()
			lat = append(lat, local...)

			for k, v := range localStatus {
				status[k] += v
			}

			for k, v := range localCause {
				errCause[k] += v
			}

			mu.Unlock()
		}(workerSeed(baseSeed, w))
	}

	wg.Wait()
	elapsed := time.Since(start)

	if len(lat) == 0 {
		return errors.New("không có request nào được gửi (thời gian chạy quá ngắn?)")
	}

	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) time.Duration { return lat[int(float64(len(lat)-1)*p)] }

	fmt.Fprintf(out, "requests=%d elapsed=%s rps=%.0f concurrency=%d hit_ratio=%.2f mode=%s\n",
		total.Load(), elapsed.Round(time.Millisecond), float64(total.Load())/elapsed.Seconds(), *conc, *hit, *mode)
	if *mode == "batch" {
		fmt.Fprintf(out, "items=%d items_per_s=%.0f batch=%d\n", totalItems.Load(),
			float64(totalItems.Load())/elapsed.Seconds(), *batchN)
	}

	fmt.Fprintf(out, "latency p50=%s p95=%s p99=%s max=%s\n", pct(.50), pct(.95), pct(.99), lat[len(lat)-1])
	fmt.Fprintf(out, "status=%v blacklisted_responses=%d\n", status, blocked.Load())
	fmt.Fprintf(out, "seed=%d dist=%s", baseSeed, *dist)

	if *dist == "zipf" {
		fmt.Fprintf(out, " zipf_s=%.2f", *zipfS)
	}

	fmt.Fprintln(out)

	if len(errCause) > 0 {
		fmt.Fprintf(out, "error_causes=%v\n", errCause)
	}

	if *metricsURL != "" {
		after, err := fetchLayers(*metricsURL)
		if err != nil {
			fmt.Fprintf(out, "metrics: không đọc được sau lượt chạy: %v\n", err)
			return nil
		}

		d := layerDelta(layersBefore, after)
		sum := d["bloom"] + d["cache"] + d["db"]
		fmt.Fprintf(out, "layers(delta) bloom=%.0f cache=%.0f db=%.0f", d["bloom"], d["cache"], d["db"])

		if sum > 0 {
			fmt.Fprintf(out, " | share bloom=%.1f%% cache=%.1f%% db=%.1f%%", 100*d["bloom"]/sum, 100*d["cache"]/sum, 100*d["db"]/sum)
		}

		if r, ok := cacheHitRatio(d); ok {
			fmt.Fprintf(out, " | cache_hit_ratio=%.1f%%", 100*r)
		} else {
			fmt.Fprintf(out, " | cache_hit_ratio=n/a (chưa có lượt tra nào xuống tầng cache/DB)")
		}

		fmt.Fprintln(out)
	}

	return nil
}
