package inspector

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Record struct {
	ID                uint64
	Time              time.Time
	TimeFormatted     string
	Method            string
	Path              string
	Query             string
	FullPath          string
	Status            int
	Duration          time.Duration
	DurationFormatted string
	ClientIP          string
	UserAgent         string
	RequestHeaders    map[string]string
	RequestBody       string
	Route             string
	Screen            string
	IsError           bool
}

type Stats struct {
	TotalRequests int
	RecentRPS     float64
	AvgLatency    string
	Count2xx      int
	Count4xx      int
	Count5xx      int
	ErrorRate     string
}

type Inspector struct {
	mu       sync.RWMutex
	records  []Record
	capacity int
	seq      uint64
}

func New(capacity int) *Inspector {
	if capacity <= 0 {
		capacity = 200
	}
	return &Inspector{
		records:  make([]Record, 0, capacity),
		capacity: capacity,
	}
}

func (ins *Inspector) Record(r Record) {
	ins.mu.Lock()
	defer ins.mu.Unlock()

	r.Path = MaskSensitive(r.Path)
	r.Query = MaskSensitive(r.Query)
	r.FullPath = MaskSensitive(r.FullPath)

	r.ID = atomic.AddUint64(&ins.seq, 1)
	r.TimeFormatted = r.Time.Format("15:04:05.000")
	r.DurationFormatted = formatDuration(r.Duration)
	r.IsError = r.Status >= 400

	if len(ins.records) >= ins.capacity {
		copy(ins.records, ins.records[1:])
		ins.records[len(ins.records)-1] = r
	} else {
		ins.records = append(ins.records, r)
	}
}

func (ins *Inspector) Clear() {
	ins.mu.Lock()
	defer ins.mu.Unlock()
	ins.records = ins.records[:0]
}

func (ins *Inspector) GetRecent(limit int, method, status, search, screen string) []Record {
	ins.mu.RLock()
	defer ins.mu.RUnlock()

	search = strings.ToLower(strings.TrimSpace(search))
	method = strings.ToUpper(strings.TrimSpace(method))
	status = strings.ToLower(strings.TrimSpace(status))

	var matches []Record
	for i := len(ins.records) - 1; i >= 0; i-- {
		rec := ins.records[i]

		if screen != "" && rec.Screen != screen {
			continue
		}

		if method != "" && method != "ALL" && rec.Method != method {
			continue
		}

		if status != "" && status != "all" {
			switch status {
			case "2xx":
				if rec.Status < 200 || rec.Status >= 300 {
					continue
				}
			case "3xx":
				if rec.Status < 300 || rec.Status >= 400 {
					continue
				}
			case "4xx":
				if rec.Status < 400 || rec.Status >= 500 {
					continue
				}
			case "5xx":
				if rec.Status < 500 {
					continue
				}
			case "errors":
				if rec.Status < 400 {
					continue
				}
			}
		}

		if search != "" {
			combined := strings.ToLower(rec.Path + " " + rec.Query + " " + rec.ClientIP + " " + rec.UserAgent)
			if !strings.Contains(combined, search) {
				continue
			}
		}

		matches = append(matches, rec)
		if limit > 0 && len(matches) >= limit {
			break
		}
	}

	return matches
}

func (ins *Inspector) GetByID(id uint64) *Record {
	ins.mu.RLock()
	defer ins.mu.RUnlock()

	for i := len(ins.records) - 1; i >= 0; i-- {
		if ins.records[i].ID == id {
			rec := ins.records[i]
			return &rec
		}
	}
	return nil
}

func (ins *Inspector) GetStats(screen string) Stats {
	ins.mu.RLock()
	defer ins.mu.RUnlock()

	recs := ins.records
	if screen != "" {
		recs = make([]Record, 0, len(ins.records))
		for _, r := range ins.records {
			if r.Screen == screen {
				recs = append(recs, r)
			}
		}
	}

	total := len(recs)
	if total == 0 {
		return Stats{
			AvgLatency: "0ms",
			ErrorRate:  "0%",
		}
	}

	var totalDur time.Duration
	var count2xx, count4xx, count5xx int
	now := time.Now()
	var inLast10s int

	for _, r := range recs {
		totalDur += r.Duration
		if r.Status >= 200 && r.Status < 300 {
			count2xx++
		} else if r.Status >= 400 && r.Status < 500 {
			count4xx++
		} else if r.Status >= 500 {
			count5xx++
		}
		if now.Sub(r.Time) <= 10*time.Second {
			inLast10s++
		}
	}

	avg := totalDur / time.Duration(total)
	errRate := float64(count4xx+count5xx) / float64(total) * 100

	return Stats{
		TotalRequests: total,
		RecentRPS:     float64(inLast10s) / 10.0,
		AvgLatency:    formatDuration(avg),
		Count2xx:      count2xx,
		Count4xx:      count4xx,
		Count5xx:      count5xx,
		ErrorRate:     fmt.Sprintf("%.1f%%", errRate),
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	if d < time.Second {
		return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000.0)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func ExtractHeaders(h http.Header) map[string]string {
	res := make(map[string]string)
	keys := []string{
		"Content-Type",
		"X-API-Key",
		"User-Agent",
		"Accept",
		"Origin",
		"Referer",
		"Authorization",
		"HX-Request",
		"HX-Target",
		"X-Forwarded-For",
	}
	for _, k := range keys {
		if v := h.Get(k); v != "" {
			if k == "X-API-Key" || k == "Authorization" {
				if len(v) > 16 {
					v = v[:6] + "..." + v[len(v)-4:]
				} else {
					v = "***"
				}
			}
			res[k] = v
		}
	}
	return res
}

var sensitiveField = regexp.MustCompile(`(?i)((?:password|passwd|pass|token|csrf[_-]?token|api[_-]?key|secret|key)["']?\s*[=:]\s*"?)([^&"\s,}]+)`)

// RedactBody hides credentials before a request body is stored.
// Login bodies are dropped entirely; other bodies have sensitive fields masked.
func RedactBody(path, body string) string {
	if body == "" {
		return ""
	}
	if strings.HasSuffix(path, "/login") {
		return "[đã ẩn: body đăng nhập]"
	}
	return MaskSensitive(sensitiveField.ReplaceAllString(body, "${1}***"))
}

var (
	// Query/form parameters that carry the data being checked (phone, URL).
	valueParam = regexp.MustCompile(`(?i)((?:^|[&?])(?:value|q|phone|url|number)=)([^&]{3})[^&]*`)
	// Digit runs long enough to be a phone number, with an optional leading +.
	phoneRun = regexp.MustCompile(`(\+?\d{3})\d{3,}(\d{2})`)
)

// MaskSensitive hides the data a request is about, so the inspector shows that
// a lookup happened without storing the phone number or URL itself.
func MaskSensitive(s string) string {
	if s == "" {
		return s
	}

	s = valueParam.ReplaceAllString(s, "${1}${2}***")

	return phoneRun.ReplaceAllString(s, "${1}***${2}")
}

// ScreenOf returns the page ("screen") a request belongs to.
// HTMX sub-requests belong to the page that triggered them (HX-Current-URL,
// falling back to Referer); every other request belongs to its own path.
func ScreenOf(r *http.Request) string {
	if r.Header.Get("HX-Request") == "true" {
		for _, h := range []string{"HX-Current-URL", "Referer"} {
			if v := r.Header.Get(h); v != "" {
				if u, err := url.Parse(v); err == nil && u.Path != "" {
					return u.Path
				}
			}
		}
	}
	return r.URL.Path
}
