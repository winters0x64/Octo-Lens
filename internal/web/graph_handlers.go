package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/graph"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/store"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/verify"
)

// findPrivateRepo returns the first repo among candidates that's actually
// private, for use as a verification vehicle for "all"/"private"-visibility
// org secrets — those need any repo, and reusing one already in the current
// sweep avoids touching anywhere new. Iteration order over candidates is
// Go's usual randomized map order, so which one gets picked isn't stable
// across runs, but any private repo is equally valid.
func (s *Server) findPrivateRepo(ctx context.Context, candidates map[string]bool) (string, error) {
	for repo := range candidates {
		info, _, err := s.gh.Client().Repositories.Get(ctx, s.org, repo)
		if err != nil {
			continue
		}
		if info.GetPrivate() {
			return repo, nil
		}
	}
	return "", fmt.Errorf("no private repo found among %d candidate(s)", len(candidates))
}

// persistVerifiedSecrets writes the current secrets snapshot — including
// whatever verification enrichment was just applied — to the cached_secrets
// table, so a verify result survives a process restart instead of only living
// in memory until overwritten by mergeVerifiedSecrets on the next scan.
// No-op when DB persistence isn't configured.
func (s *Server) persistVerifiedSecrets(secrets []models.OrgSecret) {
	if s.store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := store.UpsertCachedSecrets(ctx, s.store.DB(), secrets, time.Now()); err != nil {
		log.Printf("[verify] WARNING: failed to persist verification to DB: %v", err)
	}
}

// currentGraph returns the reachability graph for the latest scan, building and
// memoizing it on first use per scan. The report pointer is immutable once
// swapped in by runScan, so the graph is built without holding s.mu.
func (s *Server) currentGraph() (*graph.Graph, bool) {
	s.mu.RLock()
	report := s.report
	s.mu.RUnlock()
	if report == nil {
		return nil, false
	}

	s.graphMu.Lock()
	defer s.graphMu.Unlock()
	if s.graphCache != nil && s.graphCacheTS.Equal(report.ScannedAt) {
		return s.graphCache, true
	}
	g := graph.Build(report)
	s.graphCache = g
	s.graphCacheTS = report.ScannedAt
	return g, true
}

// handleAttackGraph returns the full reachability graph (nodes + edges) for the
// Explore view.
func (s *Server) handleAttackGraph(w http.ResponseWriter, r *http.Request) {
	g, ok := s.currentGraph()
	if !ok {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, g)
}

// handleAttackGraphNodes returns slim node descriptors for the search index,
// without the full edge set — keeps the focus-first UI from fetching the whole
// graph just to populate search.
func (s *Server) handleAttackGraphNodes(w http.ResponseWriter, r *http.Request) {
	g, ok := s.currentGraph()
	if !ok {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, g.NodeIndex())
}

// handleAttackAnalytics returns the ranked findings: largest blast radius,
// most-privileged workflows, risky third-party actions, and paths to prod.
func (s *Server) handleAttackAnalytics(w http.ResponseWriter, r *http.Request) {
	g, ok := s.currentGraph()
	if !ok {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, g.Analytics())
}

// handleAttackFindings returns the insight-first payload: ranked attack paths
// to production and prioritized remediation action items.
func (s *Server) handleAttackFindings(w http.ResponseWriter, r *http.Request) {
	g, ok := s.currentGraph()
	if !ok {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, g.Findings())
}

// handleActionsInventory returns the org-wide inventory of GitHub Actions and
// the versions in use.
func (s *Server) handleActionsInventory(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	report := s.report
	s.mu.RUnlock()
	if report == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, graph.InventoryActions(report))
}

// handleVerifySecrets triggers in-place secret verification for a specific repo.
// POST /api/verify-secrets with body {"repo": "repo-name"}
func (s *Server) handleVerifySecrets(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Repo string `json:"repo"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Repo == "" {
		http.Error(w, `{"error":"missing repo field"}`, http.StatusBadRequest)
		return
	}

	s.mu.RLock()
	report := s.report
	s.mu.RUnlock()
	if report == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}

	// Collect repo-scoped secret names, plus environment-scoped names grouped
	// by environment — GitHub only resolves ${{ secrets.NAME }} to an
	// environment secret when the job declares that environment, so each
	// environment needs its own job (see verify.GenerateWorkflow).
	var repoSecretNames []string
	envGroupsByName := map[string][]string{}
	for _, sec := range report.Secrets {
		if sec.RepoName != req.Repo {
			continue
		}
		switch sec.Scope {
		case "repo":
			repoSecretNames = append(repoSecretNames, sec.Name)
		case "environment":
			envGroupsByName[sec.EnvName] = append(envGroupsByName[sec.EnvName], sec.Name)
		}
	}
	if len(repoSecretNames) == 0 && len(envGroupsByName) == 0 {
		http.Error(w, `{"error":"no repo- or environment-scoped secrets found for this repo"}`, http.StatusNotFound)
		return
	}
	var envGroups []verify.EnvironmentSecrets
	for envName, names := range envGroupsByName {
		envGroups = append(envGroups, verify.EnvironmentSecrets{EnvName: envName, Names: names})
	}

	orch := verify.NewOrchestrator(s.org, s.gh.Client())
	result, err := orch.VerifyRepo(context.Background(), req.Repo, repoSecretNames, envGroups)
	if err != nil {
		log.Printf("[verify] failed for %s: %v", req.Repo, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Enrich the in-memory report with verification results.
	if result.Status == "success" {
		verifyMap := map[string]*verify.SecretVerification{}
		for i := range result.Secrets {
			sv := &result.Secrets[i]
			verifyMap[sv.Environment+"|"+sv.Name] = sv
		}

		now := time.Now()
		s.mu.Lock()
		for i := range s.report.Secrets {
			sec := &s.report.Secrets[i]
			if sec.RepoName != req.Repo {
				continue
			}
			sv, ok := verifyMap[sec.EnvName+"|"+sec.Name]
			if !ok {
				continue
			}
			sec.Verified = true
			sec.Valid = sv.Valid
			sec.VerifyProvider = sv.Provider
			sec.VerifyIdentity = sv.Identity
			sec.VerifyPerms = sv.Permissions
			sec.VerifyError = sv.Error
			sec.VerifiedAt = &now
			sec.VerifyRecognized = sv.Recognized
			if sv.Valid {
				sec.VerifyPermissionTier, sec.VerifyPermissionReasons = verify.ClassifyPermissionTier(sv.Provider, sv.Permissions, sv.PermissionNotes)
			}
		}
		secretsSnapshot := s.report.Secrets
		// Invalidate graph cache so next request rebuilds with verification data.
		s.graphCache = nil
		s.mu.Unlock()

		s.persistVerifiedSecrets(secretsSnapshot)
	}

	writeJSON(w, result)
}

// handleVerifyOrgSecrets runs the verify pipeline for org-level secrets,
// using a caller-chosen repo as the vehicle. Org secrets aren't tied to any
// single repo, so there's no automatic target — the caller picks one, and
// this figures out which org secrets that repo can actually see:
//   - visibility "all"      → every repo in the org can see it
//   - visibility "private"  → any private repo in the org can see it
//   - visibility "selected" → only repos on that secret's specific allowlist
//     (looked up per-secret via the GitHub API) can see it
//
// Only secrets the target repo is actually eligible for get pushed into the
// generated workflow — GitHub resolves ${{ secrets.NAME }} for these exactly
// like a repo secret, no `environment:` job scoping needed.
// POST /api/verify-org-secrets with body {"repo": "repo-name"}
func (s *Server) handleVerifyOrgSecrets(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Repo string `json:"repo"`
		// Secrets optionally narrows verification to just these org secret
		// names (still subject to the eligibility check below) — a repo
		// eligible for "private"-visibility secrets is eligible for ALL of
		// them at once, which can be a much wider sweep than intended, so
		// callers can use this to scope a run down deliberately.
		Secrets []string `json:"secrets,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Repo == "" {
		http.Error(w, `{"error":"missing repo field"}`, http.StatusBadRequest)
		return
	}
	wantedNames := map[string]bool{}
	for _, n := range req.Secrets {
		wantedNames[n] = true
	}

	s.mu.RLock()
	report := s.report
	s.mu.RUnlock()
	if report == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}

	var orgSecrets []models.OrgSecret
	for _, sec := range report.Secrets {
		if sec.Scope == "org" {
			orgSecrets = append(orgSecrets, sec)
		}
	}
	if len(orgSecrets) == 0 {
		http.Error(w, `{"error":"no org-level secrets found"}`, http.StatusNotFound)
		return
	}

	repoInfo, _, err := s.gh.Client().Repositories.Get(r.Context(), s.org, req.Repo)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("looking up repo %q: %v", req.Repo, err)})
		return
	}
	repoIsPrivate := repoInfo.GetPrivate()

	var eligible []string
	for _, sec := range orgSecrets {
		if len(wantedNames) > 0 && !wantedNames[sec.Name] {
			continue
		}
		switch sec.Visibility {
		case "all":
			eligible = append(eligible, sec.Name)
		case "private":
			if repoIsPrivate {
				eligible = append(eligible, sec.Name)
			}
		case "selected":
			repos, err := s.gh.ListOrgSecretRepos(r.Context(), sec.Name)
			if err != nil {
				log.Printf("[verify-org] WARNING: listing selected repos for %s: %v", sec.Name, err)
				continue
			}
			for _, rn := range repos {
				if rn == req.Repo {
					eligible = append(eligible, sec.Name)
					break
				}
			}
		}
	}
	if len(eligible) == 0 {
		http.Error(w, fmt.Sprintf(`{"error":"no org secrets are visible to repo %q"}`, req.Repo), http.StatusNotFound)
		return
	}
	log.Printf("[verify-org] %d org secret(s) visible to %s: %v", len(eligible), req.Repo, eligible)

	orch := verify.NewOrchestrator(s.org, s.gh.Client())
	result, err := orch.VerifyRepo(context.Background(), req.Repo, eligible, nil)
	if err != nil {
		log.Printf("[verify-org] failed via %s: %v", req.Repo, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	if result.Status == "success" {
		verifyMap := map[string]*verify.SecretVerification{}
		for i := range result.Secrets {
			sv := &result.Secrets[i]
			verifyMap[sv.Name] = sv
		}

		now := time.Now()
		s.mu.Lock()
		for i := range s.report.Secrets {
			sec := &s.report.Secrets[i]
			if sec.Scope != "org" {
				continue
			}
			sv, ok := verifyMap[sec.Name]
			if !ok {
				continue
			}
			sec.Verified = true
			sec.Valid = sv.Valid
			sec.VerifyProvider = sv.Provider
			sec.VerifyIdentity = sv.Identity
			sec.VerifyPerms = sv.Permissions
			sec.VerifyError = sv.Error
			sec.VerifiedAt = &now
			sec.VerifyRecognized = sv.Recognized
			if sv.Valid {
				sec.VerifyPermissionTier, sec.VerifyPermissionReasons = verify.ClassifyPermissionTier(sv.Provider, sv.Permissions, sv.PermissionNotes)
			}
		}
		secretsSnapshot := s.report.Secrets
		s.graphCache = nil
		s.mu.Unlock()

		s.persistVerifiedSecrets(secretsSnapshot)
	}

	writeJSON(w, result)
}

// handleVerifyAll runs secret verification across all repos with unverified
// repo-scoped secrets sequentially, returning the aggregated result.
// POST /api/verify-all
// verifyRepoResult is one repo's (or org-secret vehicle repo's) outcome from
// a verify-all sweep. Exported shape reused by both the HTTP handler and the
// scheduled background sweep.
type verifyRepoResult struct {
	Repo   string                   `json:"repo"`
	Status string                   `json:"status"`
	Error  string                   `json:"error,omitempty"`
	Result *verify.RepoVerifyResult `json:"result,omitempty"`
}

func (s *Server) handleVerifyAll(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	report := s.report
	s.mu.RUnlock()
	if report == nil {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}

	if !s.verifyRunning.CompareAndSwap(false, true) {
		http.Error(w, `{"error":"a verify-all sweep is already in progress"}`, http.StatusConflict)
		return
	}
	defer s.verifyRunning.Store(false)

	results, allDone := s.runVerifyAll(r.Context(), report)
	if allDone {
		writeJSON(w, map[string]interface{}{
			"status":  "done",
			"message": "all secrets already verified",
			"results": []interface{}{},
		})
		return
	}

	writeJSON(w, map[string]interface{}{
		"status":  "done",
		"results": results,
	})
}

// runVerifyAll sweeps every not-yet-verified secret in report: repo- and
// environment-scoped secrets grouped and verified per-repo, then org-level
// secrets verified via a picked vehicle repo per visibility class. Returns
// (nil, true) when there was nothing to verify.
//
// Shared by the manual "Verify All" HTTP handler and the background
// scheduled sweep (see scheduledVerify) — callers are responsible for
// verifyRunning overlap protection, since the HTTP handler needs to hold it
// across the JSON-response path too.
func (s *Server) runVerifyAll(ctx context.Context, report *models.OrgReport) (results []verifyRepoResult, allDone bool) {
	// Group unverified secrets by repo: repo-scoped names directly, and
	// environment-scoped names further grouped by environment.
	repoNamesByRepo := map[string][]string{}
	envGroupsByRepo := map[string]map[string][]string{} // repo -> env -> names
	for _, sec := range report.Secrets {
		if sec.RepoName == "" || sec.Verified {
			continue
		}
		switch sec.Scope {
		case "repo":
			repoNamesByRepo[sec.RepoName] = append(repoNamesByRepo[sec.RepoName], sec.Name)
		case "environment":
			if envGroupsByRepo[sec.RepoName] == nil {
				envGroupsByRepo[sec.RepoName] = map[string][]string{}
			}
			envGroupsByRepo[sec.RepoName][sec.EnvName] = append(envGroupsByRepo[sec.RepoName][sec.EnvName], sec.Name)
		}
	}

	repoSet := map[string]bool{}
	for repo := range repoNamesByRepo {
		repoSet[repo] = true
	}
	for repo := range envGroupsByRepo {
		repoSet[repo] = true
	}

	hasUnverifiedOrgSecrets := false
	for _, sec := range report.Secrets {
		if sec.Scope == "org" && !sec.Verified {
			hasUnverifiedOrgSecrets = true
			break
		}
	}

	if len(repoSet) == 0 && !hasUnverifiedOrgSecrets {
		return nil, true
	}

	orch := verify.NewOrchestrator(s.org, s.gh.Client())

	for repoName := range repoSet {
		var envGroups []verify.EnvironmentSecrets
		for envName, names := range envGroupsByRepo[repoName] {
			envGroups = append(envGroups, verify.EnvironmentSecrets{EnvName: envName, Names: names})
		}
		totalNames := len(repoNamesByRepo[repoName])
		for _, g := range envGroups {
			totalNames += len(g.Names)
		}
		log.Printf("[verify-all] verifying %s (%d secrets)", repoName, totalNames)

		result, err := orch.VerifyRepo(ctx, repoName, repoNamesByRepo[repoName], envGroups)
		if err != nil {
			log.Printf("[verify-all] %s failed: %v", repoName, err)
			results = append(results, verifyRepoResult{Repo: repoName, Status: "error", Error: err.Error()})
			continue
		}

		// Enrich in-memory report.
		if result.Status == "success" {
			verifyMap := map[string]*verify.SecretVerification{}
			for j := range result.Secrets {
				sv := &result.Secrets[j]
				verifyMap[sv.Environment+"|"+sv.Name] = sv
			}

			now := time.Now()
			s.mu.Lock()
			for j := range s.report.Secrets {
				sec := &s.report.Secrets[j]
				if sec.RepoName != repoName {
					continue
				}
				sv, ok := verifyMap[sec.EnvName+"|"+sec.Name]
				if !ok {
					continue
				}
				sec.Verified = true
				sec.Valid = sv.Valid
				sec.VerifyProvider = sv.Provider
				sec.VerifyIdentity = sv.Identity
				sec.VerifyPerms = sv.Permissions
				sec.VerifyError = sv.Error
				sec.VerifiedAt = &now
				sec.VerifyRecognized = sv.Recognized
				if sv.Valid {
					sec.VerifyPermissionTier, sec.VerifyPermissionReasons = verify.ClassifyPermissionTier(sv.Provider, sv.Permissions, sv.PermissionNotes)
				}
			}
			secretsSnapshot := s.report.Secrets
			s.graphCache = nil
			s.mu.Unlock()

			s.persistVerifiedSecrets(secretsSnapshot)
		}

		results = append(results, verifyRepoResult{Repo: repoName, Status: "ok", Result: result})
	}

	// Org-level secrets have no repo of their own, so pick a vehicle repo per
	// visibility class instead of introducing a new one:
	//   - "all"/"private" → any already-private repo already in this sweep
	//     (private covers both, and reusing a repo we're touching anyway
	//     doesn't expand the blast radius to anywhere new)
	//   - "selected" → only repos on that secret's own specific allowlist are
	//     eligible at all, looked up per-secret via the GitHub API
	var unverifiedOrgSecrets []models.OrgSecret
	for _, sec := range report.Secrets {
		if sec.Scope == "org" && !sec.Verified {
			unverifiedOrgSecrets = append(unverifiedOrgSecrets, sec)
		}
	}

	if len(unverifiedOrgSecrets) > 0 {
		orgNamesByRepo := map[string][]string{}

		vehicleRepo, verr := s.findPrivateRepo(ctx, repoSet)
		if verr != nil {
			log.Printf("[verify-all] WARNING: no private repo available as a vehicle for org secrets: %v", verr)
		}

		for _, sec := range unverifiedOrgSecrets {
			switch sec.Visibility {
			case "all":
				if vehicleRepo != "" {
					orgNamesByRepo[vehicleRepo] = append(orgNamesByRepo[vehicleRepo], sec.Name)
				}
			case "private":
				if vehicleRepo != "" {
					orgNamesByRepo[vehicleRepo] = append(orgNamesByRepo[vehicleRepo], sec.Name)
				}
			case "selected":
				repos, err := s.gh.ListOrgSecretRepos(ctx, sec.Name)
				if err != nil || len(repos) == 0 {
					log.Printf("[verify-all] WARNING: no eligible repo found for org secret %s: %v", sec.Name, err)
					continue
				}
				orgNamesByRepo[repos[0]] = append(orgNamesByRepo[repos[0]], sec.Name)
			}
		}

		for targetRepo, names := range orgNamesByRepo {
			log.Printf("[verify-all] verifying %d org secret(s) via %s: %v", len(names), targetRepo, names)

			result, err := orch.VerifyRepo(ctx, targetRepo, names, nil)
			label := "org secrets via " + targetRepo
			if err != nil {
				log.Printf("[verify-all] %s failed: %v", label, err)
				results = append(results, verifyRepoResult{Repo: label, Status: "error", Error: err.Error()})
				continue
			}

			if result.Status == "success" {
				verifyMap := map[string]*verify.SecretVerification{}
				for j := range result.Secrets {
					sv := &result.Secrets[j]
					verifyMap[sv.Name] = sv
				}

				now := time.Now()
				s.mu.Lock()
				for j := range s.report.Secrets {
					sec := &s.report.Secrets[j]
					if sec.Scope != "org" {
						continue
					}
					sv, ok := verifyMap[sec.Name]
					if !ok {
						continue
					}
					sec.Verified = true
					sec.Valid = sv.Valid
					sec.VerifyProvider = sv.Provider
					sec.VerifyIdentity = sv.Identity
					sec.VerifyPerms = sv.Permissions
					sec.VerifyError = sv.Error
					sec.VerifiedAt = &now
					sec.VerifyRecognized = sv.Recognized
					if sv.Valid {
						sec.VerifyPermissionTier, sec.VerifyPermissionReasons = verify.ClassifyPermissionTier(sv.Provider, sv.Permissions, sv.PermissionNotes)
					}
				}
				secretsSnapshot := s.report.Secrets
				s.graphCache = nil
				s.mu.Unlock()

				s.persistVerifiedSecrets(secretsSnapshot)
			}

			results = append(results, verifyRepoResult{Repo: label, Status: "ok", Result: result})
		}
	}

	return results, false
}

// handleBlastRadius answers "what does this node reach, and what reaches it?"
// for the node given by ?id=<nodeID>.
func (s *Server) handleBlastRadius(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, `{"error":"missing id query parameter"}`, http.StatusBadRequest)
		return
	}
	g, ok := s.currentGraph()
	if !ok {
		http.Error(w, `{"error":"no scan data available"}`, http.StatusServiceUnavailable)
		return
	}
	res, found := g.BlastRadius(id)
	if !found {
		http.Error(w, `{"error":"node not found"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, res)
}
