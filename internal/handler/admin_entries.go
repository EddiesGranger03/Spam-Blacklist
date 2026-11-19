package handler

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"vsf/internal/checker"
	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/store"
)

// actorOf tạo model.Actor từ ID, email và IP của admin (dùng để ghi audit).
func actorOf(id int64, email, ip string) model.Actor {
	return model.Actor{ID: id, Email: email, IP: ip}
}

type entriesData struct {
	Entries   []model.Entry
	NextURL   string
	Type      string
	Category  string
	Status    string
	Cursor    int64
	Estimate  int64
	BloomN    uint64
	Ready     bool
	Asc       bool
	ToggleURL string
}

type entryForm struct {
	ID        int64
	Type      string
	MatchType string
	Value     string
	Status    string
	Category  string
	RiskScore int
	Source    string
	Note      string
	ExpiresAt string
	Error     string
}

// listEntries hiển thị danh sách entry theo bộ lọc và trang.
func (h *Handler) listEntries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := entriesData{
		Type:     q.Get("type"),
		Category: q.Get("category"),
		Status:   q.Get("status"),
		Asc:      q.Get("dir") == "asc",
	}
	if d.Type != "phone" && d.Type != "url" {
		d.Type = ""
	}

	if !slices.Contains(model.Categories, d.Category) {
		d.Category = ""
	}

	if d.Status != model.StatusBlacklist && d.Status != model.StatusWhitelist {
		d.Status = ""
	}

	d.Cursor, _ = strconv.ParseInt(q.Get("after"), 10, 64)

	link := func(dir string, after int64) string {
		v := url.Values{"dir": {dir}}

		if d.Type != "" {
			v.Set("type", d.Type)
		}

		if d.Category != "" {
			v.Set("category", d.Category)
		}

		if d.Status != "" {
			v.Set("status", d.Status)
		}

		if after > 0 {
			v.Set("after", strconv.FormatInt(after, 10))
		}

		return "/admin/entries?" + v.Encode()
	}

	thisDir, otherDir := "desc", "asc"

	if d.Asc {
		thisDir, otherDir = "asc", "desc"
	}

	d.ToggleURL = link(otherDir, 0)

	f := store.ListFilter{
		Type:     d.Type,
		Category: d.Category,
		Status:   d.Status,
		Cursor:   d.Cursor,
		Limit:    50,
		Asc:      d.Asc,
	}

	entries, next, err := h.Store.ListEntries(r.Context(), f)
	if err != nil {
		h.serverError(w, r, err)
		return
	}

	d.Entries = entries

	if next > 0 {
		d.NextURL = link(thisDir, next)
	}

	d.Estimate, _ = h.Store.EstimatedCount(r.Context())
	d.BloomN, d.Ready = h.Bloom.Items(), h.Bloom.Ready()
	pd := h.newPage(r, "Blacklist", "entries", d)

	if isHTMX(r) {
		h.render(w, http.StatusOK, "entries", "entries_table", pd)
		return
	}

	h.render(w, http.StatusOK, "entries", "layout", pd)
}

// renderForm hiển thị lại form entry kèm lỗi (dùng khi nhập sai).
func (h *Handler) renderForm(w http.ResponseWriter, r *http.Request, f entryForm) {
	h.renderFormStatus(w, r, http.StatusOK, f)
}

// renderFormStatus như renderForm nhưng với mã HTTP tùy chọn (409 khi giá trị trùng entry khác).
func (h *Handler) renderFormStatus(w http.ResponseWriter, r *http.Request, code int, f entryForm) {
	if !isHTMX(r) {
		http.Redirect(w, r, "/admin/entries", http.StatusSeeOther)
		return
	}

	pd := h.newPage(r, "Entry", "entries", f)
	h.render(w, code, "entries", "entry_form", pd)
}

// newEntryForm hiển thị form thêm entry mới.
func (h *Handler) newEntryForm(w http.ResponseWriter, r *http.Request) {
	h.renderForm(w, r, entryForm{Type: "phone", RiskScore: 50, Category: "spam", Status: model.StatusBlacklist})
}

// parseEntryForm đọc và kiểm tra dữ liệu form thành entry nhập liệu.
func parseEntryForm(r *http.Request) (entryForm, model.EntryInput, error) {
	if err := r.ParseForm(); err != nil {
		return entryForm{}, model.EntryInput{}, errors.New("dữ liệu form không hợp lệ")
	}

	score, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("risk_score")))
	f := entryForm{
		Type: r.PostFormValue("type"), MatchType: r.PostFormValue("match_type"),
		Value: strings.TrimSpace(r.PostFormValue("value")), Category: r.PostFormValue("category"),
		Status:    strings.ToUpper(strings.TrimSpace(r.PostFormValue("status"))),
		RiskScore: score, Source: strings.TrimSpace(r.PostFormValue("source")),
		Note: strings.TrimSpace(r.PostFormValue("note")), ExpiresAt: strings.TrimSpace(r.PostFormValue("expires_at")),
	}

	if err != nil {
		return f, model.EntryInput{}, errors.New("risk_score phải là số 0–100")
	}

	exp, err := store.ParseExpiry(f.ExpiresAt)
	if err != nil {
		return f, model.EntryInput{}, errors.New("ngày hết hạn không hợp lệ (dùng YYYY-MM-DD)")
	}

	in := model.EntryInput{Status: f.Status, Category: f.Category, RiskScore: f.RiskScore, Source: f.Source, Note: f.Note, ExpiresAt: exp}
	if err := in.Validate(); err != nil {
		return f, in, err
	}

	return f, in, nil
}

// createEntry tạo một entry mới từ form, ghi audit rồi chuyển hướng.
func (h *Handler) createEntry(w http.ResponseWriter, r *http.Request) {
	f, in, err := parseEntryForm(r)
	if err != nil {
		f.Error = userMessage(err)
		h.renderForm(w, r, f)
		return
	}

	key, err := normalize.NormalizeEntry(normalize.Type(f.Type), normalize.MatchType(f.MatchType), f.Value, h.Cfg.DefaultRegion)
	if err != nil {
		f.Error = userMessage(err)
		h.renderForm(w, r, f)
		return
	}

	wctx, wcancel := writeCtx(r)
	defer wcancel()

	if _, err := h.Store.CreateEntry(wctx, key, in, h.actorFrom(r)); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			f.Error = "Giá trị này đã có trong danh sách."
			h.renderForm(w, r, f)
			return
		}

		h.serverError(w, r, err)
		return
	}

	h.afterWrite(r)
	w.Header().Set("HX-Redirect", "/admin/entries?flash=created")
	w.WriteHeader(http.StatusNoContent)
}

// entryID lấy ID entry từ đường dẫn; trả false nếu không hợp lệ.
func entryID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	return id, err == nil && id > 0
}

// editEntryForm hiển thị form sửa một entry.
func (h *Handler) editEntryForm(w http.ResponseWriter, r *http.Request) {
	id, ok := entryID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}

	e, err := h.Store.GetEntry(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		h.serverError(w, r, err)
		return
	}

	f := entryForm{ID: e.ID, Type: e.Type, MatchType: e.MatchType, Value: e.Value, Status: e.Status, Category: e.Category,
		RiskScore: e.RiskScore, Source: e.Source, Note: e.Note}

	if e.ExpiresAt != nil {
		f.ExpiresAt = e.ExpiresAt.Format("2006-01-02")
	}

	h.renderForm(w, r, f)
}

// updateEntry cập nhật một entry từ form.
func (h *Handler) updateEntry(w http.ResponseWriter, r *http.Request) {
	id, ok := entryID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}

	f, in, err := parseEntryForm(r)
	f.ID = id

	if err != nil {
		f.Error = userMessage(err)
		h.renderForm(w, r, f)
		return
	}

	// Giá trị có thể được sửa: chuẩn hóa lại với type/match_type của entry hiện tại (form khóa hai trường này).
	key, err := normalize.NormalizeEntry(normalize.Type(f.Type), normalize.MatchType(f.MatchType), f.Value, h.Cfg.DefaultRegion)
	if err != nil {
		f.Error = userMessage(err)
		h.renderForm(w, r, f)
		return
	}

	wctx, wcancel := writeCtx(r)
	defer wcancel()

	if _, err := h.Store.UpdateEntryKey(wctx, id, in, &key, h.actorFrom(r)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}

		if errors.Is(err, store.ErrDuplicate) {
			f.Error = "Giá trị này đã có trong danh sách (entry khác)."
			h.renderFormStatus(w, r, http.StatusConflict, f)
			return
		}

		if errors.Is(err, normalize.ErrInvalid) {
			f.Error = userMessage(err)
			h.renderForm(w, r, f)
			return
		}

		h.serverError(w, r, err)
		return
	}

	h.afterWrite(r)
	w.Header().Set("HX-Redirect", "/admin/entries?flash=updated")
	w.WriteHeader(http.StatusNoContent)
}

// deleteEntry xóa một entry và ghi audit.
func (h *Handler) deleteEntry(w http.ResponseWriter, r *http.Request) {
	id, ok := entryID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}

	wctx, wcancel := writeCtx(r)
	defer wcancel()

	if err := h.Store.DeleteEntry(wctx, id, h.actorFrom(r)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			w.WriteHeader(http.StatusOK)
			return
		}

		h.serverError(w, r, err)
		return
	}

	h.afterWrite(r)
	w.WriteHeader(http.StatusOK)
}

// afterWrite đồng bộ changefeed ngay sau khi ghi entry để thay đổi có hiệu lực tức thì.
func (h *Handler) afterWrite(r *http.Request) {
	// Dữ liệu đã commit: đồng bộ filter của pod này cho trọn vẹn kể cả khi client đã rời trang (writeCtx).
	ctx, cancel := writeCtx(r)
	defer cancel()

	if err := h.Feed.SyncNow(ctx); err != nil {
		h.Log.Error("sync after write", "err", err)
	}
}

// userMessage đổi lỗi thành thông báo ngắn gọn để hiển thị cho người dùng.
func userMessage(err error) string {
	return strings.TrimPrefix(err.Error(), normalize.ErrInvalid.Error()+": ")
}

type checkData struct {
	Type   string
	Value  string
	Result any
	Err    string
}

// checkPage hiển thị trang kiểm tra một giá trị.
func (h *Handler) checkPage(w http.ResponseWriter, r *http.Request) {
	h.render(w, http.StatusOK, "check", "layout", h.newPage(r, "Check thử", "check", checkData{Type: "phone"}))
}

// checkSubmit xử lý form kiểm tra và hiển thị kết quả.
func (h *Handler) checkSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	d := checkData{Type: r.PostFormValue("type"), Value: r.PostFormValue("value")}
	res, err := h.Checker.Check(r.Context(), normalize.Type(d.Type), d.Value)

	switch {
	case errors.Is(err, normalize.ErrInvalid):
		d.Err = userMessage(err)

	case err != nil:
		h.serverError(w, r, err)
		return

	default:
		d.Result = h.annotateWhitelist(r.Context(), normalize.Type(d.Type), d.Value, res)
	}

	pd := h.newPage(r, "Check thử", "check", d)

	if isHTMX(r) {
		h.render(w, http.StatusOK, "check", "check_result", pd)
		return
	}

	h.render(w, http.StatusOK, "check", "layout", pd)
}

// writeCtx trả context cho thao tác GHI của portal: tách khỏi việc client hủy request (rời trang ngay sau khi bấm Lưu)
// nhưng vẫn có hạn chót. Nếu dùng r.Context(), client hủy giữa chừng có thể làm COMMIT đã chạy trên Postgres mà
// handler vẫn nhận "context canceled" và trả 500, dù dữ liệu đã lưu.
func writeCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(r.Context()), writeTimeout)
}

const writeTimeout = 10 * time.Second

// annotateWhitelist chỉ dùng cho trang "Check thử" của admin. Đường check thật trả "an toàn" ngay khi filter báo không có,
// mà số WHITELIST thì không nằm trong filter, nên kết quả không cho biết số đó có entry WHITELIST. Trang admin tra thêm DB
// (chỉ khi kết quả là an toàn) để người vận hành thấy rõ. API công khai không bị ảnh hưởng (không thêm truy vấn DB).
func (h *Handler) annotateWhitelist(ctx context.Context, typ normalize.Type, raw string, res checker.Result) checker.Result {
	if res.Blacklisted || res.Whitelisted {
		return res
	}

	_, keys, err := normalize.Candidates(typ, raw, h.Cfg.DefaultRegion)
	if err != nil || len(keys) == 0 {
		return res
	}

	entries, err := h.Store.FindMatches(ctx, keys)
	if err != nil {
		h.Log.Warn("check page: whitelist lookup failed", "err", err)
		return res
	}

	for _, e := range entries {
		if e.Status != model.StatusWhitelist {
			continue
		}

		if res.Match == nil || e.RiskScore > res.Match.RiskScore {
			res.Whitelisted = true
			res.Match = &checker.Match{EntryID: e.ID, MatchType: e.MatchType, MatchedValue: e.Value,
				Category: e.Category, RiskScore: e.RiskScore, Status: e.Status}
		}
	}

	return res
}
