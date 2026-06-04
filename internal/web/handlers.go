package web

import (
	"encoding/json"
	"net/http"
	"strconv"

	ghservice "github.com/th3-j0ik3r/github-pat-monitor/internal/github"
)

func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.report == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}

	writeJSON(w, s.report.Summary)
}

func (s *Server) handlePATs(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.report == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}

	writeJSON(w, s.report.PATs)
}

func (s *Server) handlePATRepos(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	patID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid PAT ID"}`, http.StatusBadRequest)
		return
	}

	repos, err := s.gh.ListPATRepositories(r.Context(), patID)
	if err != nil {
		http.Error(w, `{"error":"failed to fetch repositories"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, repos)
}

func (s *Server) handlePATRequests(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.report == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}

	writeJSON(w, s.report.PendingRequests)
}

func (s *Server) handleSSOCredentials(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.report == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}

	writeJSON(w, s.report.SSOCredentials)
}

func (s *Server) handleApps(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.report == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}

	writeJSON(w, s.report.Apps)
}

func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.report == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}

	writeJSON(w, s.report.Secrets)
}

func (s *Server) handleDeployKeys(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.report == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}

	writeJSON(w, s.report.DeployKeys)
}

func (s *Server) handleWorkflowPerms(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.report == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}

	writeJSON(w, s.report.WorkflowPerms)
}

func (s *Server) handleWorkflowFiles(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.report == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}

	writeJSON(w, s.report.WorkflowFiles)
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if !s.scanLimiter.Allow() {
		http.Error(w, `{"error":"rate limited: try again later"}`, http.StatusTooManyRequests)
		return
	}

	result, err := s.scanner.Scan(r.Context())
	if err != nil {
		http.Error(w, `{"error":"scan failed"}`, http.StatusInternalServerError)
		return
	}
	report := result.Report
	report.Org = s.org

	s.mu.Lock()
	s.prevReport = s.report
	s.report = report
	s.mu.Unlock()

	s.onScanComplete(report)

	writeJSON(w, report)
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.report == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}

	writeJSON(w, s.report)
}

func (s *Server) handleReviewPATRequest(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	patID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid PAT ID"}`, http.StatusBadRequest)
		return
	}

	var body struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if body.Action != "approve" && body.Action != "deny" {
		http.Error(w, `{"error":"action must be 'approve' or 'deny'"}`, http.StatusBadRequest)
		return
	}

	if err := s.gh.ReviewPATRequest(r.Context(), patID, body.Action, body.Reason); err != nil {
		http.Error(w, `{"error":"failed to review PAT request: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": body.Action + "d", "pat_id": idStr})
}

func (s *Server) handleRevokePAT(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	patID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid PAT ID"}`, http.StatusBadRequest)
		return
	}

	if err := s.gh.RevokePAT(r.Context(), patID); err != nil {
		http.Error(w, `{"error":"failed to revoke PAT: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "revoked", "pat_id": idStr})
}

func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	report := s.report
	s.mu.RUnlock()

	if report == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}

	checks := ghservice.RunComplianceChecks(s.org, report)
	writeJSON(w, checks)
}

func (s *Server) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	entries, err := s.gh.ListAuditLog(r.Context())
	if err != nil {
		// Non-fatal: Enterprise Cloud only
		writeJSON(w, map[string]any{
			"available": false,
			"error":     "Audit log API not available (requires GitHub Enterprise Cloud)",
			"entries":   []any{},
		})
		return
	}

	writeJSON(w, map[string]any{
		"available": true,
		"entries":   entries,
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
