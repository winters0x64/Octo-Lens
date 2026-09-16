package web

import (
	"context"
	"encoding/json"
	"log"
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
		log.Printf("ERROR: failed to fetch repos for PAT %d: %v", patID, err)
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

	// Return 202 immediately — the scan runs in the background with its own
	// context so the ALB idle timeout (60s) doesn't cancel a 3-4 minute scan.
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, map[string]string{"status": "scanning"})

	go s.runScan(context.Background())
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

func (s *Server) handleDeleteDeployKey(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	keyID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid key ID"}`, http.StatusBadRequest)
		return
	}

	repoName := r.URL.Query().Get("repo")
	if repoName == "" {
		http.Error(w, `{"error":"repo query parameter is required"}`, http.StatusBadRequest)
		return
	}

	if err := s.gh.DeleteDeployKey(r.Context(), repoName, keyID); err != nil {
		http.Error(w, `{"error":"failed to delete deploy key: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "deleted", "key_id": idStr})
}

func (s *Server) handleDeleteSecret(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Scope   string `json:"scope"`
		Name    string `json:"name"`
		RepoName string `json:"repo_name"`
		EnvName  string `json:"env_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if body.Scope == "" || body.Name == "" {
		http.Error(w, `{"error":"scope and name are required"}`, http.StatusBadRequest)
		return
	}

	if err := s.gh.DeleteSecret(r.Context(), body.Scope, body.Name, body.RepoName, body.EnvName); err != nil {
		http.Error(w, `{"error":"failed to delete secret: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "deleted", "name": body.Name})
}

func (s *Server) handleRevokeSSO(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	credID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid credential ID"}`, http.StatusBadRequest)
		return
	}

	if err := s.gh.RevokeSSO(r.Context(), credID); err != nil {
		http.Error(w, `{"error":"failed to revoke SSO credential: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "revoked", "credential_id": idStr})
}

func (s *Server) handleSuspendApp(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	appID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid app ID"}`, http.StatusBadRequest)
		return
	}

	if err := s.gh.SuspendApp(r.Context(), appID); err != nil {
		http.Error(w, `{"error":"failed to suspend app: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "suspended", "app_id": idStr})
}

func (s *Server) handleUnsuspendApp(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	appID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, `{"error":"invalid app ID"}`, http.StatusBadRequest)
		return
	}

	if err := s.gh.UnsuspendApp(r.Context(), appID); err != nil {
		http.Error(w, `{"error":"failed to unsuspend app: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{"status": "unsuspended", "app_id": idStr})
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
