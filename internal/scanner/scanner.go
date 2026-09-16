package scanner

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	gh "github.com/google/go-github/v68/github"

	ghservice "github.com/th3-j0ik3r/github-pat-monitor/internal/github"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/verify"
)

type Scanner struct {
	gh     *ghservice.GitHubService
	org    string
	verify bool // run in-place secret verification
}

func New(gh *ghservice.GitHubService) *Scanner {
	return &Scanner{gh: gh}
}

// SetVerify enables the in-place secret verification pipeline.
func (s *Scanner) SetVerify(org string, enabled bool) {
	s.org = org
	s.verify = enabled
}

// Result is the structured outcome of one scan. Per-phase completion flags
// let downstream consumers (the persistence layer) safely diff entity types
// without false-removed signals from a partial fetch.
type Result struct {
	Report *models.OrgReport

	PATsComplete          bool
	PATRequestsComplete   bool
	AppsComplete          bool
	SSOComplete           bool
	ReposListed           bool
	ReposScanned          []string
	SecretsComplete       bool
	DeployKeysComplete    bool
	WorkflowPermsComplete bool
	WorkflowFilesComplete bool
	ZizmorComplete        bool
	VerifyComplete        bool

	// PhaseErrors collects per-phase failures without aborting the scan.
	PhaseErrors []error
}

// Scan fetches all credential data concurrently, tolerating per-phase failures.
// Returns an error only when no useful data could be produced.
func (s *Scanner) Scan(ctx context.Context) (*Result, error) {
	res := &Result{}

	var (
		pats     []models.PATInfo
		requests []models.PATRequest
		apps     []models.AppInstallation
		ssoCreds []models.SSOCredential
		repos    []*gh.Repository
		mu       sync.Mutex
		wg       sync.WaitGroup
	)

	addErr := func(phase string, err error) {
		mu.Lock()
		defer mu.Unlock()
		res.PhaseErrors = append(res.PhaseErrors, errPhase{phase: phase, err: err})
	}

	// Phase 1: parallel fetches with no repo dependency.
	wg.Add(5)

	go func() {
		defer wg.Done()
		var err error
		pats, err = s.gh.ListApprovedPATs(ctx)
		if err != nil {
			addErr("pats", err)
			return
		}
		res.PATsComplete = true
	}()

	go func() {
		defer wg.Done()
		var err error
		requests, err = s.gh.ListPendingPATRequests(ctx)
		if err != nil {
			addErr("pat_requests", err)
			return
		}
		res.PATRequestsComplete = true
	}()

	go func() {
		defer wg.Done()
		var err error
		apps, err = s.gh.ListInstalledApps(ctx)
		if err != nil {
			addErr("apps", err)
			return
		}
		res.AppsComplete = true
	}()

	go func() {
		defer wg.Done()
		var err error
		ssoCreds, err = s.gh.ListSSOCredentials(ctx)
		if err != nil {
			// SSO endpoint returns 404 on non-Enterprise orgs; that's not
			// a scan failure — flag the phase as not-complete and move on.
			ssoCreds = nil
			addErr("sso", err)
			return
		}
		res.SSOComplete = true
	}()

	go func() {
		defer wg.Done()
		var err error
		repos, err = s.gh.ListOrgRepos(ctx)
		if err != nil {
			log.Printf("WARNING: failed to list repos: %v (skipping repo-level scans)", err)
			repos = nil
			addErr("repos", err)
			return
		}
		res.ReposListed = true
		log.Printf("Found %d repositories", len(repos))
	}()

	wg.Wait()

	// Phase 2: per-repo scans, only attempted when repo listing succeeded.
	var (
		secrets       []models.OrgSecret
		deployKeys    []models.DeployKey
		workflowPerms []models.WorkflowPermission
		workflowFiles []models.WorkflowFile
	)

	if res.ReposListed {
		var wg2 sync.WaitGroup
		wg2.Add(4)

		go func() {
			defer wg2.Done()
			var err error
			secrets, err = s.gh.ListAllSecrets(ctx, repos)
			if err != nil {
				log.Printf("WARNING: secrets scan partial failure: %v", err)
				addErr("secrets", err)
				return
			}
			res.SecretsComplete = true
		}()

		go func() {
			defer wg2.Done()
			var err error
			deployKeys, err = s.gh.ListAllDeployKeys(ctx, repos)
			if err != nil {
				log.Printf("WARNING: deploy keys scan partial failure: %v", err)
				addErr("deploy_keys", err)
				return
			}
			res.DeployKeysComplete = true
		}()

		go func() {
			defer wg2.Done()
			var err error
			workflowPerms, err = s.gh.ListWorkflowPermissions(ctx, repos)
			if err != nil {
				log.Printf("WARNING: workflow permissions scan partial failure: %v", err)
				addErr("workflow_permissions", err)
				return
			}
			res.WorkflowPermsComplete = true
		}()

		go func() {
			defer wg2.Done()
			files, contents, err := s.gh.AuditWorkflowFiles(ctx, repos)
			workflowFiles = files
			if err != nil {
				log.Printf("WARNING: workflow audit partial failure: %v", err)
				addErr("workflow_files", err)
				return
			}
			res.WorkflowFilesComplete = true

			// Run zizmor (offline SAST) over the fetched YAMLs and attach
			// findings to each workflow file. Non-fatal: a zizmor failure or a
			// missing binary leaves the heuristic audit intact.
			findings, zerr := RunZizmor(ctx, contents)
			if zerr != nil {
				log.Printf("WARNING: zizmor scan failed: %v", zerr)
				addErr("zizmor", zerr)
				return
			}
			if len(findings) > 0 {
				for i := range workflowFiles {
					if fs := findings[workflowFiles[i].RepoName+"|"+workflowFiles[i].Path]; len(fs) > 0 {
						workflowFiles[i].ZizmorFindings = fs
					}
				}
			}
			res.ZizmorComplete = true
		}()

		wg2.Wait()

		res.ReposScanned = make([]string, 0, len(repos))
		for _, r := range repos {
			if r != nil && r.FullName != nil {
				res.ReposScanned = append(res.ReposScanned, *r.FullName)
			}
		}

		// Phase 3: In-place secret verification (optional, slow).
		if s.verify && res.SecretsComplete && len(secrets) > 0 {
			log.Printf("[verify] starting secret verification for %d secrets across repos", len(secrets))
			secrets = s.verifySecrets(ctx, secrets)
			res.VerifyComplete = true
			log.Printf("[verify] secret verification complete")
		}
	}

	// If absolutely nothing succeeded, surface a hard error so callers can
	// distinguish "scan ran with partial data" from "scan failed entirely".
	if !res.PATsComplete && !res.AppsComplete && !res.SSOComplete && !res.ReposListed {
		return nil, errors.New("scan: all phase 1 fetches failed; see phase errors")
	}

	res.Report = &models.OrgReport{
		ScannedAt:       time.Now(),
		PATs:            pats,
		PendingRequests: requests,
		Apps:            apps,
		SSOCredentials:  ssoCreds,
		Secrets:         secrets,
		DeployKeys:      deployKeys,
		WorkflowPerms:   workflowPerms,
		WorkflowFiles:   workflowFiles,
		Summary:         computeSummary(pats, requests, apps, ssoCreds, secrets, deployKeys, workflowPerms, workflowFiles, repos),
	}

	return res, nil
}

// PhaseErrorSummary returns a one-line description of which phases failed.
// Empty string if all phases ran cleanly.
func (r *Result) PhaseErrorSummary() string {
	if len(r.PhaseErrors) == 0 {
		return ""
	}
	parts := make([]string, 0, len(r.PhaseErrors))
	for _, e := range r.PhaseErrors {
		parts = append(parts, e.Error())
	}
	return strings.Join(parts, "; ")
}

type errPhase struct {
	phase string
	err   error
}

func (e errPhase) Error() string { return e.phase + ": " + e.err.Error() }
func (e errPhase) Unwrap() error { return e.err }

// verifySecrets runs the in-place verification pipeline: for each repo that has
// secrets, push a verification workflow, collect results, and enrich the secret
// list with actual validity/permissions data.
func (s *Scanner) verifySecrets(ctx context.Context, secrets []models.OrgSecret) []models.OrgSecret {
	orch := verify.NewOrchestrator(s.org, s.gh.Client())

	// Group by repo: repo-scoped secret names, and environment-scoped secret
	// names further grouped by environment (org-level secrets need a temp
	// repo and are skipped for now).
	repoNamesByRepo := map[string][]string{}
	envNamesByRepo := map[string]map[string][]string{} // repo -> env -> names
	for _, sec := range secrets {
		if sec.RepoName == "" {
			continue
		}
		switch sec.Scope {
		case "repo":
			repoNamesByRepo[sec.RepoName] = append(repoNamesByRepo[sec.RepoName], sec.Name)
		case "environment":
			if envNamesByRepo[sec.RepoName] == nil {
				envNamesByRepo[sec.RepoName] = map[string][]string{}
			}
			envNamesByRepo[sec.RepoName][sec.EnvName] = append(envNamesByRepo[sec.RepoName][sec.EnvName], sec.Name)
		}
	}

	repos := map[string]bool{}
	for repo := range repoNamesByRepo {
		repos[repo] = true
	}
	for repo := range envNamesByRepo {
		repos[repo] = true
	}

	// Run verification per repo (sequential — each pushes a branch).
	// Keyed by repo -> "scope|env|name" -> result (env is "" for repo scope).
	now := time.Now()
	verifyResults := map[string]map[string]*verify.SecretVerification{}

	for repo := range repos {
		var envGroups []verify.EnvironmentSecrets
		for envName, names := range envNamesByRepo[repo] {
			envGroups = append(envGroups, verify.EnvironmentSecrets{EnvName: envName, Names: names})
		}

		result, err := orch.VerifyRepo(ctx, repo, repoNamesByRepo[repo], envGroups)
		if err != nil {
			log.Printf("[verify] WARNING: %s failed: %v", repo, err)
			continue
		}
		if result.Status != "success" {
			continue
		}
		m := map[string]*verify.SecretVerification{}
		for i := range result.Secrets {
			sv := &result.Secrets[i]
			m[sv.Environment+"|"+sv.Name] = sv
		}
		verifyResults[repo] = m
	}

	// Enrich secrets with verification data.
	for i := range secrets {
		sec := &secrets[i]
		repo := sec.RepoName
		if repo == "" || (sec.Scope != "repo" && sec.Scope != "environment") {
			continue
		}
		rm, ok := verifyResults[repo]
		if !ok {
			continue
		}
		key := sec.EnvName + "|" + sec.Name
		sv, ok := rm[key]
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

		// Adjust risk based on actual verification — a real permission tier
		// (what the credential can actually DO, not just "has policies
		// attached") is ground truth and should override the name-based
		// heuristic that produced sec.Risk during the scan.
		switch {
		case !sv.Recognized:
			// The value didn't match any credential format we check — we
			// have no real answer either way, so leave the name-based
			// heuristic risk alone rather than misreading "unrecognized" as
			// "confirmed dead" (sv.Valid is false here by convention, but
			// that's not evidence of anything).
		case !sv.Valid:
			sec.Risk = models.RiskLow // confirmed-dead secret = no real threat
		default:
			tier, reasons := verify.ClassifyPermissionTier(sv.Provider, sv.Permissions, sv.PermissionNotes)
			sec.VerifyPermissionTier = tier
			sec.VerifyPermissionReasons = reasons
			switch tier {
			case verify.TierCritical, verify.TierHigh:
				sec.Risk = models.RiskHigh
			case verify.TierMedium:
				sec.Risk = models.RiskMedium
			case verify.TierLow:
				sec.Risk = models.RiskLow
				// TierUnknown: leave the existing name-based risk alone — we
				// genuinely don't know this credential's permission scope.
			}
		}
	}

	return secrets
}

func computeSummary(
	pats []models.PATInfo,
	requests []models.PATRequest,
	apps []models.AppInstallation,
	ssoCreds []models.SSOCredential,
	secrets []models.OrgSecret,
	deployKeys []models.DeployKey,
	workflowPerms []models.WorkflowPermission,
	workflowFiles []models.WorkflowFile,
	repos []*gh.Repository,
) models.OrgSummary {
	now := time.Now()
	thirtyDays := now.Add(30 * 24 * time.Hour)

	summary := models.OrgSummary{
		TotalPATs:         len(pats),
		PendingRequests:   len(requests),
		TotalApps:         len(apps),
		SSOCredentials:    len(ssoCreds),
		TotalSecrets:      len(secrets),
		TotalDeployKeys:   len(deployKeys),
		TotalReposScanned: len(repos),
	}

	for _, p := range pats {
		if p.TokenExpired {
			summary.ExpiredPATs++
		} else {
			summary.ActivePATs++
		}

		if p.TokenExpiresAt != nil && !p.TokenExpired && p.TokenExpiresAt.Before(thirtyDays) {
			summary.ExpiringSoon++
		}

		if p.RepositorySelection == "all" {
			summary.AllRepoAccessPATs++
		}
	}

	for _, a := range apps {
		if a.HighRiskCount > 0 {
			summary.HighRiskApps++
		}
		if a.RepositorySelection == "all" {
			summary.AllRepoAccessApps++
		}
	}

	for _, c := range ssoCreds {
		switch c.CredentialType {
		case "personal access token":
			summary.SSOClassicPATs++
		case "ssh key":
			summary.SSOSSHKeys++
		}
	}

	for _, sec := range secrets {
		if sec.Scope == "org" {
			summary.OrgSecrets++
			if sec.Visibility == "all" {
				summary.OrgWideSecrets++
			}
		}
	}

	for _, dk := range deployKeys {
		if !dk.ReadOnly {
			summary.WriteDeployKeys++
		}
	}

	for _, wp := range workflowPerms {
		if wp.DefaultPermission == "write" {
			summary.WriteAllWorkflows++
		}
	}

	unpinnedRepos := make(map[string]bool)
	for _, wf := range workflowFiles {
		if len(wf.UnpinnedActions) > 0 {
			unpinnedRepos[wf.RepoName] = true
		}
	}
	summary.UnpinnedActionRepos = len(unpinnedRepos)

	return summary
}
