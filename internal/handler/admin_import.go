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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"

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

func newImportJobs() *importJobs { return &importJobs{byID: map[string]*importJob{}} }

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

func (it *csvIterator) field(rec []string, name string) string {
	i, ok := it.cols[name]
	if !ok || i >= len(rec) {
		return ""
	}

	s := strings.TrimSpace(rec[i])
	return strings.TrimPrefix(s, "'")
}

func (it *csvIterator) reject(msg string) {
	it.job.mu.Lock()
	it.job.Rejected++

	if len(it.job.Errors) < 20 {
		it.job.Errors = append(it.job.Errors, fmt.Sprintf("dòng %d: %s", it.line, msg))
	}

	it.job.mu.Unlock()
}

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

func (it *csvIterator) Err() error { return it.err }

func (h *Handler) importPage(w http.ResponseWriter, r *http.Request) {
	h.render(w, http.StatusOK, "import", "layout", h.newPage(r, "Import", "import", nil))
}

func (h *Handler) importStart(w http.ResponseWriter, r *http.Request) {
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
			f.Close()

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
	job := &importJob{ID: hex.EncodeToString(idb), Actor: actorFrom(r), Started: time.Now(), State: "running"}
	h.jobs.add(job)
	go h.runImport(job, tmpPath, defaultType)

	pd := h.newPage(r, "Import", "import", job.view())
	h.render(w, http.StatusOK, "import", "import_status", pd)
}

func (h *Handler) cleanup(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}

func (h *Handler) runImport(job *importJob, path, defaultType string) {
	defer h.cleanup(path)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()

	finish := func(res store.ImportResult, err error) {
		job.mu.Lock()
		defer job.mu.Unlock()
		job.Finished = time.Now()

		if err != nil {
			job.State, job.Err = "failed", err.Error()
			return
		}

		job.State, job.Inserted, job.Updated = "done", res.Inserted, res.Updated
	}

	f, err := os.Open(path)
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

	res, err := h.Store.Import(ctx, it, job.Actor)
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

func (h *Handler) importStatus(w http.ResponseWriter, r *http.Request) {
	job := h.jobs.get(chi.URLParam(r, "job"))
	if job == nil {
		http.Error(w, "Không tìm thấy job (có thể đã restart hoặc nằm trên instance khác). Xem Audit log.", http.StatusNotFound)
		return
	}

	h.render(w, http.StatusOK, "import", "import_status", h.newPage(r, "Import", "import", job.view()))
}

var phoneLike = regexp.MustCompile(`^\+\d{5,20}$`)

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

func (h *Handler) exportCSV(w http.ResponseWriter, r *http.Request) {
	typ := r.URL.Query().Get("type")
	if typ != "" && typ != "phone" && typ != "url" {
		typ = ""
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="blacklist-export.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"type", "value", "match_type", "category", "risk_score", "source", "note", "expires_at", "created_at"})

	var after int64

	for {
		batch, err := h.Store.ExportBatch(r.Context(), typ, after, 10000)
		if err != nil {
			h.Log.Error("export", "err", err)
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
		}

		cw.Flush()

		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}

	cw.Flush()
	_ = h.Store.WriteAudit(r.Context(), actorFrom(r), "entry.export", map[string]any{"type": typ})
}
