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

// New tạo Inspector giữ tối đa capacity bản ghi gần nhất.
func New(capacity int) *Inspector {
	if capacity <= 0 {
		capacity = 200
	}
	return &Inspector{
		records:  make([]Record, 0, capacity),
		capacity: capacity,
	}
}

// Record thêm một request vào bộ đệm vòng gần nhất của Inspector.
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

// Clear xóa toàn bộ bản ghi trong Inspector.
func (ins *Inspector) Clear() {
	ins.mu.Lock()
	defer ins.mu.Unlock()
	ins.records = ins.records[:0]
}

// GetRecent trả về các bản ghi gần nhất, lọc theo method, status, từ khóa và màn hình.
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

// GetByID tìm một bản ghi theo ID; trả nil nếu không có.
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

// GetStats thống kê các bản ghi (số lượng, thời gian, trạng thái), có thể giới hạn theo màn hình.
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

// formatDuration định dạng thời lượng để hiển thị (µs, ms hoặc s).
func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	if d < time.Second {
		return fmt.Sprintf("%.2fms", float64(d.Microseconds())/1000.0)
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

// ExtractHeaders chọn một danh sách header cố định của request (Content-Type, User-Agent, ...) để hiển thị.
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

// RedactBody che thông tin nhạy cảm trước khi body request được lưu.
// Body đăng nhập bị bỏ hẳn; các body khác có trường nhạy cảm được che.
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
	// Tham số query/form mang dữ liệu đang được kiểm tra (số điện thoại, URL).
	valueParam = regexp.MustCompile(`(?i)((?:^|[&?])(?:value|q|phone|url|number)=)([^&]{3})[^&]*`)
	// Chuỗi chữ số đủ dài để là số điện thoại, với dấu + tùy chọn ở đầu.
	phoneRun = regexp.MustCompile(`(\+?\d{3})\d{3,}(\d{2})`)
	// Trường JSON mang dữ liệu đang kiểm tra: "value": "http://evil.example/x" (M5). Giữ 3 ký tự đầu như valueParam.
	jsonValue = regexp.MustCompile(`(?i)("(?:value|q|phone|url|number|domain|host)"\s*:\s*")([^"\\]{0,3})(?:[^"\\]|\\.)*"`)
)

// MaskSensitive che dữ liệu mà request đang nói tới, để Inspector cho thấy
// đã có một lượt tra cứu mà không lưu chính số điện thoại hoặc URL.
func MaskSensitive(s string) string {
	if s == "" {
		return s
	}

	s = valueParam.ReplaceAllString(s, "${1}${2}***")
	s = jsonValue.ReplaceAllString(s, `${1}${2}***"`)

	return phoneRun.ReplaceAllString(s, "${1}***${2}")
}

// ScreenOf trả về trang ("screen") mà một request thuộc về.
// Request HTMX thuộc về trang đã kích hoạt nó (HX-Current-URL, rồi tới Referer);
// mọi request khác thuộc về chính đường dẫn của nó.
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
