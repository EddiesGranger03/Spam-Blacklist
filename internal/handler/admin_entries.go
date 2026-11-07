package handler

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"vsf/internal/model"
	"vsf/internal/normalize"
	"vsf/internal/store"
)

func actorOf(id int64, email, ip string) model.Actor {
	return model.Actor{ID: id, Email: email, IP: ip}
}

type entriesData struct {
	Entries   []model.Entry
	NextURL   string
	Type      string
	Category  string
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
	Category  string
	RiskScore int
	Source    string
	Note      string
	ExpiresAt string
	Error     string
}

func (h *Handler) listEntries(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := entriesData{
		Type:     q.Get("type"),
		Category: q.Get("category"),
		Asc:      q.Get("dir") == "asc",
	}
	if d.Type != "phone" && d.Type != "url" {
		d.Type = ""
	}

	if !slices.Contains(model.Categories, d.Category) {
		d.Category = ""
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

func (h *Handler) renderForm(w http.ResponseWriter, r *http.Request, f entryForm) {
	if !isHTMX(r) {
		http.Redirect(w, r, "/admin/entries", http.StatusSeeOther)
		return
	}

	pd := h.newPage(r, "Entry", "entries", f)
	h.render(w, http.StatusOK, "entries", "entry_form", pd)
}

func (h *Handler) newEntryForm(w http.ResponseWriter, r *http.Request) {
	h.renderForm(w, r, entryForm{Type: "phone", RiskScore: 50, Category: "spam"})
}

func parseEntryForm(r *http.Request) (entryForm, model.EntryInput, error) {
	if err := r.ParseForm(); err != nil {
		return entryForm{}, model.EntryInput{}, errors.New("dữ liệu form không hợp lệ")
	}

	score, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("risk_score")))
	f := entryForm{
		Type: r.PostFormValue("type"), MatchType: r.PostFormValue("match_type"),
		Value: strings.TrimSpace(r.PostFormValue("value")), Category: r.PostFormValue("category"),
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

	in := model.EntryInput{Category: f.Category, RiskScore: f.RiskScore, Source: f.Source, Note: f.Note, ExpiresAt: exp}
	if err := in.Validate(); err != nil {
		return f, in, err
	}

	return f, in, nil
}

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

	if _, err := h.Store.CreateEntry(r.Context(), key, in, actorFrom(r)); err != nil {
		if errors.Is(err, store.ErrDuplicate) {
			f.Error = "Giá trị này đã có trong blacklist."
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

func entryID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	return id, err == nil && id > 0
}

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

	f := entryForm{ID: e.ID, Type: e.Type, MatchType: e.MatchType, Value: e.Value, Category: e.Category,
		RiskScore: e.RiskScore, Source: e.Source, Note: e.Note}

	if e.ExpiresAt != nil {
		f.ExpiresAt = e.ExpiresAt.Format("2006-01-02")
	}

	h.renderForm(w, r, f)
}

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

	if _, err := h.Store.UpdateEntry(r.Context(), id, in, actorFrom(r)); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}

		h.serverError(w, r, err)
		return
	}

	h.afterWrite(r)
	w.Header().Set("HX-Redirect", "/admin/entries?flash=updated")
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) deleteEntry(w http.ResponseWriter, r *http.Request) {
	id, ok := entryID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}

	if err := h.Store.DeleteEntry(r.Context(), id, actorFrom(r)); err != nil {
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

func (h *Handler) afterWrite(r *http.Request) {
	if err := h.Feed.SyncNow(r.Context()); err != nil {
		h.Log.Error("sync after write", "err", err)
	}
}

func userMessage(err error) string {
	return strings.TrimPrefix(err.Error(), normalize.ErrInvalid.Error()+": ")
}

type checkData struct {
	Type   string
	Value  string
	Result any
	Err    string
}

func (h *Handler) checkPage(w http.ResponseWriter, r *http.Request) {
	h.render(w, http.StatusOK, "check", "layout", h.newPage(r, "Check thử", "check", checkData{Type: "phone"}))
}

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
		d.Result = res
	}

	pd := h.newPage(r, "Check thử", "check", d)

	if isHTMX(r) {
		h.render(w, http.StatusOK, "check", "check_result", pd)
		return
	}

	h.render(w, http.StatusOK, "check", "layout", pd)
}
