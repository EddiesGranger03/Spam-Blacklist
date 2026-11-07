package handler

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"vsf/internal/inspector"
)

type inspectorFeedData struct {
	Stats   inspector.Stats
	Records []inspector.Record
	Method  string
	Status  string
	Q       string
	Paused  bool
	Screen  string
}

type inspectorDetailData struct {
	Record    *inspector.Record
	QueryList []queryParam
	Source    *handlerSource
}

type queryParam struct {
	Key   string
	Value string
}

func (h *Handler) inspectorFeed(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	d := inspectorFeedData{
		Method: q.Get("inspector_method"),
		Status: q.Get("inspector_status"),
		Q:      strings.TrimSpace(q.Get("inspector_q")),
		Paused: q.Get("inspector_paused") == "true",
		Screen: q.Get("inspector_screen"),
	}

	d.Stats = h.Inspector.GetStats(d.Screen)
	d.Records = h.Inspector.GetRecent(50, d.Method, d.Status, d.Q, d.Screen)

	pd := h.newPage(r, "Live Inspector", "inspector", d)
	h.render(w, http.StatusOK, "inspector", "inspector_rows", pd)
}

func (h *Handler) inspectorStats(w http.ResponseWriter, r *http.Request) {
	stats := h.Inspector.GetStats(r.URL.Query().Get("inspector_screen"))
	pd := h.newPage(r, "Live Inspector Stats", "inspector", stats)
	h.render(w, http.StatusOK, "inspector", "inspector_stats", pd)
}

func (h *Handler) inspectorDetail(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	rec := h.Inspector.GetByID(id)
	if rec == nil {
		http.Error(w, "request not found or expired from buffer", http.StatusNotFound)
		return
	}

	var qList []queryParam
	if rec.Query != "" {
		if parsed, err := url.ParseQuery(rec.Query); err == nil {
			for k, vals := range parsed {
				for _, v := range vals {
					qList = append(qList, queryParam{Key: k, Value: v})
				}
			}
		}
	}

	detail := inspectorDetailData{
		Record:    rec,
		QueryList: qList,
	}

	info := h.routeIndex[rec.Method+" "+rec.Route]
	if src := lookupHandlerSource(info.Handler); src != nil {
		src.Middlewares = info.Middlewares
		if !h.Cfg.InspectorShowSource {
			src.ShowCode, src.Code, src.File, src.Line = false, "", "", 0
		}
		detail.Source = src
	}

	pd := h.newPage(r, "Chi tiết Request", "inspector", detail)
	h.render(w, http.StatusOK, "inspector", "inspector_detail", pd)
}

func (h *Handler) inspectorCloseDetail(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) inspectorClear(w http.ResponseWriter, r *http.Request) {
	h.Inspector.Clear()
	d := inspectorFeedData{
		Stats:   h.Inspector.GetStats(""),
		Records: nil,
	}
	pd := h.newPage(r, "Live Inspector", "inspector", d)
	h.render(w, http.StatusOK, "inspector", "inspector_rows", pd)
}

func (h *Handler) inspectorPage(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin/entries", http.StatusSeeOther)
}
