package web

import (
	"fmt"
	"net/http"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/render"
)

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	report := s.report
	s.mu.RUnlock()

	if report == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}

	filename := fmt.Sprintf("pat-monitor-%s-%s.csv", report.Org, report.ScannedAt.Format("2006-01-02"))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	render.RenderCSV(w, report)
}
