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
)

type Scanner struct {
	gh *ghservice.GitHubService
}

func New(gh *ghservice.GitHubService) *Scanner {
	return &Scanner{gh: gh}
}

// Result is the structured outcome of one scan. Per-phase completion flags
// let downstream consumers (the persistence layer) safely diff entity types
// without false-removed signals from a partial fetch.
type Result struct {
	Report *models.OrgReport

	PATsComplete         bool
	PATRequestsComplete  bool
	AppsComplete         bool
	SSOComplete          bool
	ReposListed          bool
	ReposScanned         []string
	SecretsComplete      bool
	DeployKeysComplete   bool
	WorkflowPermsComplete bool
	WorkflowFilesComplete bool

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
			var err error
			workflowFiles, err = s.gh.AuditWorkflowFiles(ctx, repos)
			if err != nil {
				log.Printf("WARNING: workflow audit partial failure: %v", err)
				addErr("workflow_files", err)
				return
			}
			res.WorkflowFilesComplete = true
		}()

		wg2.Wait()

		res.ReposScanned = make([]string, 0, len(repos))
		for _, r := range repos {
			if r != nil && r.FullName != nil {
				res.ReposScanned = append(res.ReposScanned, *r.FullName)
			}
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
