package handler

import (
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"

	"vsf/internal/metrics"
	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/store"
)

const maxUploadBytes = 2 << 30

type importJob struct {
	ID       string
	Actor    model.Actor
	Started  time.Time
	rows     atomic.Int64
	mu       sync.Mutex
	State    string
	Finished time.Time
	Inserted int64
	Updated  int64
	Rejected int64
	Errors   []string
	Err      string
}

type importView struct {
	ID                      string
	State                   string
	Rows, Inserted, Updated int64
	Rejected                int64
	Errors                  []string
	Err                     string
	Started, Finished       time.Time
	Running                 bool
}

// view tạo bản hiển thị (importView) của job import để trả về cho trang trạng thái.
func (j *importJob) view() importView {
	j.mu.Lock()
	defer j.mu.Unlock()
	return importView{ID: j.ID, State: j.State, Rows: j.rows.Load(), Inserted: j.Inserted, Updated: j.Updated,
		Rejected: j.Rejected, Errors: append([]string(nil), j.Errors...), Err: j.Err,
		Started: j.Started, Finished: j.Finished, Running: j.State == "running"}
}

type importJobs struct {
	mu    sync.Mutex
	byID  map[string]*importJob
	order []string
}

// newImportJobs tạo bộ quản lý các job import (lưu trong bộ nhớ).
func newImportJobs() *importJobs { return &importJobs{byID: map[string]*importJob{}} }

// add thêm một job import vào bộ quản lý.
func (s *importJobs) add(j *importJob) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byID[j.ID] = j
	s.order = append(s.order, j.ID)

	for len(s.order) > 20 {
		delete(s.byID, s.order[0])
		s.order = s.order[1:]
	}
}

// get tìm job import theo ID; trả nil nếu không có.
func (s *importJobs) get(id string) *importJob {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.byID[id]
}

type csvIterator struct {
	r           *csv.Reader
	cols        map[string]int
	defaultType string
	region      string
	job         *importJob
	line        int64
	err         error
}

// newCSVIterator tạo iterator đọc file CSV import, nhận diện các cột và kiểu dữ liệu mặc định.
func newCSVIterator(rd io.Reader, defaultType, region string, job *importJob) (*csvIterator, error) {
	cr := csv.NewReader(rd)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	cr.ReuseRecord = true
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("không đọc được dòng tiêu đề: %w", err)
	}

	cols := map[string]int{}

	for i, name := range header {
		cols[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(name, "\ufeff")))] = i
	}

	if _, ok := cols["value"]; !ok {
		return nil, fmt.Errorf("thiếu cột bắt buộc \"value\" (các cột: type,value,match_type,category,risk_score,source,note,expires_at)")
	}

	if _, ok := cols["type"]; !ok && defaultType == "" {
		return nil, fmt.Errorf("thiếu cột \"type\" và chưa chọn loại mặc định")
	}

	return &csvIterator{r: cr, cols: cols, defaultType: defaultType, region: region, job: job, line: 1}, nil
}

// field lấy giá trị một cột theo tên từ dòng CSV đã đọc.
func (it *csvIterator) field(rec []string, name string) string {
	i, ok := it.cols[name]
	if !ok || i >= len(rec) {
		return ""
	}

	s := strings.TrimSpace(rec[i])
	return strings.TrimPrefix(s, "'")
}

// reject ghi nhận một dòng CSV bị loại kèm lý do.
func (it *csvIterator) reject(msg string) {
	it.job.mu.Lock()
	it.job.Rejected++

	if len(it.job.Errors) < 20 {
		it.job.Errors = append(it.job.Errors, fmt.Sprintf("dòng %d: %s", it.line, msg))
	}

	it.job.mu.Unlock()
}

// Next trả về dòng CSV hợp lệ kế tiếp để nạp; bỏ qua và đếm các dòng lỗi.
func (it *csvIterator) Next() (store.ImportRow, bool) {
	for {
		rec, err := it.r.Read()
		if err == io.EOF {
			return store.ImportRow{}, false
		}

		it.line++
		it.job.rows.Add(1)

		if err != nil {
			it.reject("CSV sai định dạng")
			continue
		}

		typ := it.field(rec, "type")
		if typ == "" {
			typ = it.defaultType
		}

		key, err := normalize.NormalizeEntry(normalize.Type(typ), normalize.MatchType(it.field(rec, "match_type")),
			it.field(rec, "value"), it.region)
		if err != nil {
			it.reject(userMessage(err))
			continue
		}

		in := model.EntryInput{Category: it.field(rec, "category"), Source: it.field(rec, "source"), Note: it.field(rec, "note")}

		if s := it.field(rec, "risk_score"); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil {
				it.reject("risk_score không phải số")
				continue
			}

			in.RiskScore = n
		} else {
			in.RiskScore = 50
		}

		if in.ExpiresAt, err = store.ParseExpiry(it.field(rec, "expires_at")); err != nil {
			it.reject(userMessage(err))
			continue
		}

		if err := in.Validate(); err != nil {
			it.reject(userMessage(err))
			continue
		}

		return store.ImportRow{Key: key, Input: in}, true
	}
}

// Err trả về lỗi đọc file (nil nếu không có).
func (it *csvIterator) Err() error { return it.err }

// importPage hiển thị trang import.
func (h *Handler) importPage(w http.ResponseWriter, r *http.Request) {
	h.render(w, http.StatusOK, "import", "layout", h.newPage(r, "Import", "import", nil))
}

// importStart nhận file upload, lưu tạm và bắt đầu job import nền.
func (h *Handler) importStart(w http.ResponseWriter, r *http.Request) {
	// Upload lớn cần đọc lâu hơn ReadTimeout toàn cục (30s); nới riêng cho route này.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(importReadWindow))

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "Cần gửi form multipart/form-data.", http.StatusBadRequest)
		return
	}

	var defaultType, tmpPath string

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}

		if err != nil {
			h.cleanup(tmpPath)
			http.Error(w, "Upload lỗi hoặc file quá lớn.", http.StatusBadRequest)
			return
		}

		switch part.FormName() {
		case "default_type":
			b, _ := io.ReadAll(io.LimitReader(part, 16))
			defaultType = strings.TrimSpace(string(b))

		case "file":
			f, err := os.CreateTemp("", "vsf-import-*.csv")
			if err != nil {
				h.serverError(w, r, err)
				return
			}

			tmpPath = f.Name()
			_, cerr := io.Copy(f, part)
			if cerr == nil {
				// Lỗi khi đóng file ghi (ví dụ hết đĩa) cũng là lỗi upload: phải báo, không được bỏ qua.
				cerr = f.Close()
			}

			if cerr != nil {
				h.cleanup(tmpPath)
				http.Error(w, "Upload lỗi hoặc file quá lớn.", http.StatusBadRequest)
				return
			}
		}
	}

	if tmpPath == "" {
		http.Error(w, "Chưa chọn file CSV.", http.StatusBadRequest)
		return
	}

	if defaultType != "" && defaultType != "phone" && defaultType != "url" {
		h.cleanup(tmpPath)
		http.Error(w, "Loại mặc định không hợp lệ.", http.StatusBadRequest)
		return
	}

	idb := make([]byte, 8)
	_, _ = rand.Read(idb)
	job := &importJob{ID: hex.EncodeToString(idb), Actor: h.actorFrom(r), Started: time.Now(), State: "running"}
	h.jobs.add(job)
	go h.guardImport(job, func() { h.runImport(job, tmpPath, defaultType) })

	pd := h.newPage(r, "Import", "import", job.view())
	h.render(w, http.StatusOK, "import", "import_status", pd)
}

// guardImport chạy một job import và biến panic thành job failed thay vì để nó làm sập toàn bộ process.
//
// runImport chạy trong goroutine riêng nên chimw.Recoverer không thấy được panic của nó, mà trong Go một panic không được recover ở bất kỳ goroutine nào
// đều kết thúc chương trình: một file upload lỗi có thể làm sập server với mọi người. Chính sách đúng cho goroutine NÀY là đánh dấu job failed
// (các lô đã commit trước panic được giữ, và đã được phản ánh vào job.Inserted/Updated qua callback tiến độ), ghi log kèm stack, và đếm lại.
// Các goroutine khác cần chính sách khác (CheckBatch cô lập từng mục; các vòng nền không được chết âm thầm), vì vậy đây không phải
// một helper "safe go" dùng chung.
func (h *Handler) guardImport(job *importJob, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			metrics.ImportPanics.Inc()
			h.Log.Error("import job panicked; marked failed", "job", job.ID, "panic", fmt.Sprint(r), "stack", string(debug.Stack()))

			job.mu.Lock()
			job.Finished = time.Now()
			job.State = "failed"
			job.Err = "lỗi nội bộ khi import (panic). Các đợt đã ghi trước đó được giữ lại; tải lại đúng file này là an toàn. Xem log máy chủ."
			job.mu.Unlock()
		}
	}()

	fn()
}

// cleanup xóa file tạm của một job import sau khi xong.
func (h *Handler) cleanup(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}

// runImport chạy job import trong goroutine nền, cập nhật tiến độ và trạng thái.
func (h *Handler) runImport(job *importJob, path, defaultType string) {
	defer h.cleanup(path)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()

	// Import ghi theo lô, nên Inserted/Updated luôn là những gì thật sự có trong database: chúng được hiển thị
	// khi job đang chạy và được giữ lại khi job lỗi (các lô đã commit trước lỗi không bị rollback).
	finish := func(res store.ImportResult, err error) {
		job.mu.Lock()
		defer job.mu.Unlock()
		job.Finished = time.Now()
		job.Inserted, job.Updated = res.Inserted, res.Updated

		if err != nil {
			job.State, job.Err = "failed", err.Error()
			return
		}

		job.State = "done"
	}

	f, err := os.Open(path)  // #nosec G304 -- path do server tạo bằng os.CreateTemp, không lấy từ dữ liệu người dùng
	if err != nil {
		finish(store.ImportResult{}, err)
		return
	}

	defer f.Close()
	it, err := newCSVIterator(f, defaultType, h.Cfg.DefaultRegion, job)
	if err != nil {
		finish(store.ImportResult{}, err)
		return
	}

	res, err := h.Store.ImportWith(ctx, it, job.Actor, store.ImportOptions{Progress: func(r store.ImportResult) {
		job.mu.Lock()
		job.Inserted, job.Updated = r.Inserted, r.Updated
		job.mu.Unlock()
	}})
	if err == nil {
		err = it.Err()
	}

	if err == nil {
		err = h.Feed.SyncNow(ctx)
	}

	if err != nil {
		h.Log.Error("import failed", "job", job.ID, "err", err)
	}

	finish(res, err)
}

// importStatus trả về trạng thái và tiến độ của một job import.
func (h *Handler) importStatus(w http.ResponseWriter, r *http.Request) {
	job := h.jobs.get(chi.URLParam(r, "job"))
	if job == nil {
		http.Error(w, "Không tìm thấy job (có thể đã restart hoặc nằm trên instance khác). Xem Audit log.", http.StatusNotFound)
		return
	}

	h.render(w, http.StatusOK, "import", "import_status", h.newPage(r, "Import", "import", job.view()))
}

var phoneLike = regexp.MustCompile(`^\+\d{5,20}$`)

// csvSafe thêm dấu ' trước giá trị bắt đầu bằng ký tự công thức (= + - @) để chống CSV injection.
func csvSafe(s string) string {
	if s == "" || phoneLike.MatchString(s) {
		return s
	}

	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}

	return s
}

// importReadWindow là thời gian tối đa để nhận xong một file upload import.
const importReadWindow = 10 * time.Minute

// exportWriteWindow là hạn ghi cho MỖI batch export (được đặt lại sau từng batch).
const exportWriteWindow = 60 * time.Second

// exportCSV xuất danh sách entry ra file CSV theo từng lô, có ghi audit bắt đầu và kết thúc.
func (h *Handler) exportCSV(w http.ResponseWriter, r *http.Request) {
	typ := r.URL.Query().Get("type")
	if typ != "" && typ != "phone" && typ != "url" {
		typ = ""
	}

	// C3: ghi audit TRƯỚC khi dữ liệu rời khỏi hệ thống. Nếu không ghi được thì không export.
	actor := h.actorFrom(r)
	if err := h.Store.WriteAudit(r.Context(), actor, "entry.export.start", map[string]any{"type": typ}); err != nil {
		h.Log.Error("export audit", "err", err)
		http.Error(w, "Không ghi được audit log, export bị từ chối.", http.StatusInternalServerError)

		return
	}

	rc := http.NewResponseController(w)
	rows, status := 0, "aborted"

	defer func() {
		// Dùng context riêng: client ngắt kết nối thì r.Context() đã bị hủy nhưng audit vẫn phải được ghi.
		_ = h.Store.WriteAudit(context.WithoutCancel(r.Context()), actor, "entry.export.end",
			map[string]any{"type": typ, "rows": rows, "status": status})
	}()

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="blacklist-export.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"type", "value", "match_type", "category", "risk_score", "source", "note", "expires_at", "created_at"})

	var after int64

	for {
		_ = rc.SetWriteDeadline(time.Now().Add(exportWriteWindow))

		batch, err := h.Store.ExportBatch(r.Context(), typ, after, 10000)
		if err != nil {
			h.Log.Error("export", "err", err)
			if r.Context().Err() == nil {
				status = "failed" // lỗi thật; còn client ngắt kết nối thì giữ "aborted"
			}

			return
		}

		if len(batch) == 0 {
			break
		}

		for _, e := range batch {
			exp := ""

			if e.ExpiresAt != nil {
				exp = e.ExpiresAt.UTC().Format(time.RFC3339)
			}

			_ = cw.Write([]string{e.Type, csvSafe(e.Value), e.MatchType, e.Category, strconv.Itoa(e.RiskScore),
				csvSafe(e.Source), csvSafe(e.Note), exp, e.CreatedAt.UTC().Format(time.RFC3339)})

			after = e.ID
			rows++
		}

		cw.Flush()

		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}

	cw.Flush()

	if cw.Error() == nil {
		status = "complete"
	}
}
