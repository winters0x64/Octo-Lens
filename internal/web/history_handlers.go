package web

import (
	"net/http"
	"strconv"
	"time"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/store"
)

// handlePATHistory returns the event log for a single PAT, newest first.
func (s *Server) handlePATHistory(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, `{"error":"persistence is not configured"}`, http.StatusServiceUnavailable)
		return
	}
	idStr := r.PathValue("id")
	if _, err := strconv.ParseInt(idStr, 10, 64); err != nil {
		http.Error(w, `{"error":"invalid PAT ID"}`, http.StatusBadRequest)
		return
	}
	limit := parseLimit(r, 100)

	events, err := store.ListEventsByEntity(r.Context(), s.store.DB(), store.EventEntityPAT, idStr, limit)
	if err != nil {
		http.Error(w, `{"error":"history query failed"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, events)
}

// handleEvents returns a paginated event feed across all entity types.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, `{"error":"persistence is not configured"}`, http.StatusServiceUnavailable)
		return
	}

	q := r.URL.Query()
	filter := store.EventFilter{
		EntityType: q.Get("entity_type"),
		Kind:       q.Get("kind"),
		Limit:      parseLimit(r, 100),
	}
	if since := q.Get("since"); since != "" {
		t, err := time.Parse(time.RFC3339, since)
		if err != nil {
			http.Error(w, `{"error":"invalid since (want RFC3339)"}`, http.StatusBadRequest)
			return
		}
		filter.Since = &t
	}

	events, err := store.ListEvents(r.Context(), s.store.DB(), filter)
	if err != nil {
		http.Error(w, `{"error":"events query failed"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, events)
}

// handlePATsHistorical lists PATs by persisted status (active|expired|removed).
// When ?status= is omitted, falls back to the in-memory report.
func (s *Server) handlePATsHistorical(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status == "" {
		s.handlePATs(w, r)
		return
	}
	if s.store == nil {
		http.Error(w, `{"error":"persistence is not configured; status filter unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	switch status {
	case store.PATStatusActive, store.PATStatusExpired, store.PATStatusRemoved:
	default:
		http.Error(w, `{"error":"invalid status (active|expired|removed)"}`, http.StatusBadRequest)
		return
	}
	rows, err := store.ListPATsByStatus(r.Context(), s.store.DB(), status)
	if err != nil {
		http.Error(w, `{"error":"pats query failed"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, rows)
}

func parseLimit(r *http.Request, def int) int {
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			return n
		}
	}
	return def
}
