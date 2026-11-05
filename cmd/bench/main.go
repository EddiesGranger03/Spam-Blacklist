package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	base := flag.String("url", "http://127.0.0.1:8090", "địa chỉ server")
	key := flag.String("key", "", "API key (bỏ trống nếu server chạy AUTH_DISABLED)")
	file := flag.String("file", "", "CSV chứa các SĐT đã import (để lấy khóa trúng)")
	conc := flag.Int("c", 64, "số kết nối đồng thời")
	dur := flag.Duration("d", 20*time.Second, "thời gian chạy")
	hit := flag.Float64("hit", 0.1, "tỉ lệ request dùng khóa TRÚNG blacklist (0..1)")
	flag.Parse()

	var hits []string

	if *file != "" {
		f, err := os.Open(*file)
		if err != nil {
			log.Fatal(err)
		}

		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if p := strings.Split(sc.Text(), ","); len(p) > 1 && p[0] == "phone" {
				hits = append(hits, p[1])
			}
		}

		f.Close()
		log.Printf("nạp %d SĐT trúng", len(hits))
	}

	tr := &http.Transport{MaxIdleConns: *conc * 2, MaxIdleConnsPerHost: *conc * 2, IdleConnTimeout: 30 * time.Second}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	var (
		mu       sync.Mutex
		lat      []time.Duration
		status   = map[int]int{}
		blocked  atomic.Int64
		total    atomic.Int64
		deadline = time.Now().Add(*dur)
		wg       sync.WaitGroup
	)

	start := time.Now()

	for w := 0; w < *conc; w++ {
		wg.Add(1)

		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(seed))
			local := make([]time.Duration, 0, 4096)
			localStatus := map[int]int{}

			for time.Now().Before(deadline) {
				var phone string

				if len(hits) > 0 && rng.Float64() < *hit {
					phone = hits[rng.Intn(len(hits))]
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
					resp.Body.Close()
					code = resp.StatusCode
					if code == 200 && strings.Contains(string(b), `"blacklisted":true`) {
						blocked.Add(1)
					}
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

			mu.Unlock()
		}(int64(w) + 1)
	}

	wg.Wait()
	elapsed := time.Since(start)

	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) time.Duration { return lat[int(float64(len(lat)-1)*p)] }

	fmt.Printf("requests=%d elapsed=%s rps=%.0f concurrency=%d hit_ratio=%.2f\n",
		total.Load(), elapsed.Round(time.Millisecond), float64(total.Load())/elapsed.Seconds(), *conc, *hit)

	fmt.Printf("latency p50=%s p95=%s p99=%s max=%s\n", pct(.50), pct(.95), pct(.99), lat[len(lat)-1])
	fmt.Printf("status=%v blacklisted_responses=%d\n", status, blocked.Load())
}
