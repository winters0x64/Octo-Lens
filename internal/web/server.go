package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/oauth2"

	ghservice "github.com/th3-j0ik3r/github-pat-monitor/internal/github"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/graph"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/notify"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/persist"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/policy"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/scanner"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/store"
)

type Server struct {
	gh            *ghservice.GitHubService
	scanner       *scanner.Scanner
	store         *store.Store
	org           string
	password      string
	oauthCfg      *oauth2.Config
	allowedDomain string // Google Workspace hosted-domain restriction; empty = unrestricted
	sessions      *sessionStore
	report        *models.OrgReport
	mu            sync.RWMutex
	scanLimiter   *RateLimiter

	// verifyRunning prevents a scheduled verify-all sweep from overlapping
	// with another one (manual or scheduled) — a sweep pushes a branch and
	// runs GitHub Actions per repo and can take 20+ minutes across a large
	// org, so a second sweep starting mid-run would race the first on the
	// same repos for no benefit.
	verifyRunning atomic.Bool

	// Policy and alerting
	policy        *policy.Policy
	slack         *notify.SlackNotifier
	webhookSecret string
	violations    []policy.Violation
	prevReport    *models.OrgReport
	scanDiff      ScanDiff

	// Tracks which entity phases were complete in the scan that produced prevReport.
	// Zero-value (false) on startup suppresses first-scan "all items are new" alerts.
	prevAppsComplete    bool
	prevSecretsComplete bool
	prevDKsComplete     bool

	// Reachability graph, memoized per scan (keyed by report.ScannedAt).
	graphMu      sync.Mutex
	graphCache   *graph.Graph
	graphCacheTS time.Time
}

type Config struct {
	Addr                string
	Port                int
	Password            string
	TLSCert             string
	TLSKey              string
	Org                 string
	ScanInterval        time.Duration
	VerifyInterval      time.Duration // 0 disables scheduled secret verification
	PolicyPath          string
	SlackWebhook        string
	WebhookSecret       string
	GoogleClientID      string
	GoogleClientSecret  string
	GoogleAllowedDomain string // restrict Google SSO to this Workspace domain; empty = unrestricted
	PublicURL           string // e.g. "https://your-octo-lens-host.example.com"
}

func NewServer(gh *ghservice.GitHubService, sc *scanner.Scanner, st *store.Store, org string, password string) *Server {
	return &Server{
		gh:          gh,
		scanner:     sc,
		store:       st,
		org:         org,
		password:    password,
		sessions:    newSessionStore(),
		scanLimiter: NewRateLimiter(60 * time.Second),
	}
}

// Configure sets up policy engine, Slack notifier, webhook secret, and Google OAuth.
func (s *Server) Configure(cfg Config) {
	if cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "" {
		publicURL := cfg.PublicURL
		if publicURL == "" {
			publicURL = fmt.Sprintf("http://%s:%d", cfg.Addr, cfg.Port)
		}
		s.oauthCfg = newOAuthConfig(cfg.GoogleClientID, cfg.GoogleClientSecret, publicURL)
		s.allowedDomain = cfg.GoogleAllowedDomain
		if s.allowedDomain != "" {
			log.Printf("Google SSO enabled (restricted to domain: %s)", s.allowedDomain)
		} else {
			log.Printf("Google SSO enabled (WARNING: no domain restriction configured — any Google account can sign in; set --google-allowed-domain)")
		}
	}

	if cfg.PolicyPath != "" {
		pol, err := policy.LoadFromFile(cfg.PolicyPath)
		if err != nil {
			log.Printf("WARNING: failed to load policy file: %v (using defaults)", err)
			pol = policy.Default()
		}
		s.policy = pol
		log.Printf("Policy loaded from %s", cfg.PolicyPath)
	}

	if cfg.SlackWebhook != "" {
		s.slack = notify.NewSlackNotifier(cfg.SlackWebhook)
		log.Printf("Slack notifications enabled")
	}

	if cfg.WebhookSecret != "" {
		s.webhookSecret = cfg.WebhookSecret
		log.Printf("GitHub webhook signature verification enabled")
	}
}

// ValidateConfig checks security constraints before starting.
func ValidateConfig(cfg Config) error {
	addr := cfg.Addr
	if addr == "" {
		addr = "127.0.0.1"
	}

	isLoopback := addr == "127.0.0.1" || addr == "localhost" || addr == "::1"

	hasAuth := cfg.Password != "" || (cfg.GoogleClientID != "" && cfg.GoogleClientSecret != "")
	if !isLoopback && !hasAuth {
		return fmt.Errorf(
			"refusing to start: binding to %s without auth is insecure; "+
				"set PAT_MONITOR_PASSWORD or GOOGLE_CLIENT_ID+GOOGLE_CLIENT_SECRET, or bind to 127.0.0.1",
			addr,
		)
	}

	if !isLoopback && cfg.TLSCert == "" {
		log.Printf("WARNING: serving on %s without TLS — PAT metadata will be transmitted in cleartext", addr)
	}

	return nil
}

// onScanComplete runs policy evaluation and sends alerts after each scan.
func (s *Server) onScanComplete(report *models.OrgReport) {
	if s.policy == nil {
		return
	}

	violations := s.policy.Evaluate(report)

	s.mu.Lock()
	s.violations = violations
	s.mu.Unlock()

	if len(violations) == 0 {
		log.Printf("Policy check passed: no violations")
		return
	}

	log.Printf("Policy check: %d violation(s) found", len(violations))

	// Only alert if there are new violations compared to previous scan
	if s.slack != nil {
		newViolations := s.diffViolations(violations)
		if len(newViolations) > 0 {
			log.Printf("Sending Slack alert for %d new violation(s)", len(newViolations))
			if err := s.slack.SendViolations(s.org, newViolations); err != nil {
				log.Printf("WARNING: Slack notification failed: %v", err)
			}
		}
	}
}

// diffViolations returns violations not present in the previous scan.
func (s *Server) diffViolations(current []policy.Violation) []policy.Violation {
	s.mu.RLock()
	prev := s.violations
	s.mu.RUnlock()

	if prev == nil {
		return current
	}

	prevSet := make(map[string]bool)
	for _, v := range prev {
		prevSet[v.Rule+"|"+v.Resource] = true
	}

	var newViolations []policy.Violation
	for _, v := range current {
		if !prevSet[v.Rule+"|"+v.Resource] {
			newViolations = append(newViolations, v)
		}
	}
	return newViolations
}

func (s *Server) runScan(ctx context.Context) {
	log.Printf("Starting scan for org %q...", s.org)
	start := time.Now()

	result, err := s.scanner.Scan(ctx)
	if err != nil {
		log.Printf("WARNING: scan failed: %v", err)
		return
	}
	report := result.Report
	report.Org = s.org

	// Atomically snapshot the previous completeness flags and rotate reports.
	// prevAppsComplete etc. reflect whether the scan that PRODUCED prevReport
	// was complete — used below to suppress first-boot "all items are new" alerts.
	s.mu.Lock()
	prevAppsWasComplete := s.prevAppsComplete
	prevSecretsWasComplete := s.prevSecretsComplete
	prevDKsWasComplete := s.prevDKsComplete
	if s.report != nil {
		// A fresh scan has no verification data of its own (verification only
		// ever runs via the manual /api/verify-secrets endpoints) — without this,
		// every rescan would silently reset all secrets back to unverified.
		report.Secrets = mergeVerifiedSecrets(s.report.Secrets, report.Secrets)
	}
	s.prevReport = s.report
	s.report = report
	s.prevAppsComplete = result.AppsComplete
	s.prevSecretsComplete = result.SecretsComplete
	s.prevDKsComplete = result.DeployKeysComplete
	s.mu.Unlock()

	log.Printf("Scan complete in %s: %d PATs, %d apps",
		time.Since(start).Round(time.Millisecond), len(report.PATs), len(report.Apps))

	if summary := result.PhaseErrorSummary(); summary != "" {
		log.Printf("WARNING: scan had partial failures: %s", summary)
	}

	if s.store != nil {
		if err := persist.Apply(ctx, s.store, result, s.policy, time.Now()); err != nil {
			log.Printf("WARNING: persistence failed: %v", err)
		}
	}

	diff := computeDiff(s.prevReport, report)
	s.mu.Lock()
	s.scanDiff = diff
	s.mu.Unlock()

	s.onScanComplete(report)
	s.sendSlackAlerts(diff, prevAppsWasComplete, prevSecretsWasComplete, prevDKsWasComplete)
}

// mergeVerifiedSecrets carries forward verification results from the previous
// report onto matching secrets in a freshly scanned report. Verification only
// ever happens via the manual /api/verify-secrets endpoints — a scan never
// produces verification data on its own — so without this, every background
// rescan would silently reset every secret back to unverified.
//
// A secret only keeps its prior verdict if its UpdatedAt is unchanged from
// when it was verified: if the secret's value was rotated since then, the old
// valid/invalid verdict no longer applies to whatever value is there now.
func mergeVerifiedSecrets(prev, fresh []models.OrgSecret) []models.OrgSecret {
	type secretKey struct{ scope, repo, env, name string }

	prevByKey := make(map[secretKey]models.OrgSecret, len(prev))
	for _, sec := range prev {
		if !sec.Verified {
			continue
		}
		prevByKey[secretKey{sec.Scope, sec.RepoName, sec.EnvName, sec.Name}] = sec
	}
	if len(prevByKey) == 0 {
		return fresh
	}

	for i := range fresh {
		f := &fresh[i]
		old, ok := prevByKey[secretKey{f.Scope, f.RepoName, f.EnvName, f.Name}]
		if !ok || !old.UpdatedAt.Equal(f.UpdatedAt) {
			continue
		}
		f.Verified = old.Verified
		f.Valid = old.Valid
		f.VerifyProvider = old.VerifyProvider
		f.VerifyIdentity = old.VerifyIdentity
		f.VerifyPerms = old.VerifyPerms
		f.VerifyError = old.VerifyError
		f.VerifiedAt = old.VerifiedAt
		f.VerifyPermissionTier = old.VerifyPermissionTier
		f.VerifyPermissionReasons = old.VerifyPermissionReasons
		f.VerifyRecognized = old.VerifyRecognized
	}
	return fresh
}

func (s *Server) sendSlackAlerts(diff ScanDiff, prevAppsComplete, prevSecretsComplete, prevDKsComplete bool) {
	if s.slack == nil || !diff.HasPrev {
		return
	}

	newApps := diff.NewApps
	if !prevAppsComplete {
		newApps = nil
	}
	newSecrets := diff.NewSecrets
	if !prevSecretsComplete {
		newSecrets = nil
	}
	newDKs := diff.NewDeployKeys
	if !prevDKsComplete {
		newDKs = nil
	}

	if len(diff.NewPATs) > 0 || len(newApps) > 0 {
		log.Printf("Sending Slack alert for %d new PAT(s), %d new app(s)", len(diff.NewPATs), len(newApps))
		if err := s.slack.SendNewCredentials(s.org, diff.NewPATs, newApps); err != nil {
			log.Printf("WARNING: Slack new credentials alert failed: %v", err)
		}
	}
	if len(newSecrets) > 0 || len(newDKs) > 0 {
		if err := s.slack.SendNewInfraCredentials(s.org, newSecrets, newDKs); err != nil {
			log.Printf("WARNING: Slack new infra credentials alert failed: %v", err)
		}
	}
	if len(diff.ChangedPATs) > 0 {
		pats := make([]models.PATInfo, len(diff.ChangedPATs))
		fields := make([][]string, len(diff.ChangedPATs))
		for i, c := range diff.ChangedPATs {
			pats[i] = c.PAT
			fields[i] = c.Fields
		}
		if err := s.slack.SendPermissionChanges(s.org, pats, fields); err != nil {
			log.Printf("WARNING: Slack permission changes alert failed: %v", err)
		}
	}
}

// loadCachedReport reconstructs a full OrgReport from the DB cache.
// Returns nil, nil when the DB is empty (first run — no scan has completed yet).
func (s *Server) loadCachedReport(ctx context.Context) (*models.OrgReport, error) {
	db := s.store.DB()

	pats, err := store.ListActivePATs(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("pats: %w", err)
	}
	requests, err := store.ListActivePATRequests(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("pat requests: %w", err)
	}
	ssoCreds, err := store.ListActiveSSOCredentials(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("sso creds: %w", err)
	}

	// Treat an empty DB as "first run" — trigger a blocking scan instead.
	if len(pats) == 0 && len(requests) == 0 && len(ssoCreds) == 0 {
		return nil, nil
	}

	apps, err := store.ListCachedApps(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("cached apps: %w", err)
	}
	secrets, err := store.ListCachedSecrets(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("cached secrets: %w", err)
	}
	deployKeys, err := store.ListCachedDeployKeys(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("cached deploy keys: %w", err)
	}
	workflowPerms, err := store.ListCachedWorkflowPerms(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("cached workflow perms: %w", err)
	}
	workflowFiles, err := store.ListCachedWorkflowFiles(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("cached workflow files: %w", err)
	}

	patInfos := make([]models.PATInfo, len(pats))
	for i, r := range pats {
		patInfos[i] = r.PATInfo
	}
	patReqs := make([]models.PATRequest, len(requests))
	for i, r := range requests {
		patReqs[i] = r.PATRequest
	}
	ssoCredentials := make([]models.SSOCredential, len(ssoCreds))
	for i, r := range ssoCreds {
		ssoCredentials[i] = r.SSOCredential
	}

	report := &models.OrgReport{
		Org:             s.org,
		ScannedAt:       time.Now(),
		PATs:            patInfos,
		PendingRequests: patReqs,
		SSOCredentials:  ssoCredentials,
		Apps:            apps,
		Secrets:         secrets,
		DeployKeys:      deployKeys,
		WorkflowPerms:   workflowPerms,
		WorkflowFiles:   workflowFiles,
	}
	report.Summary = buildBasicSummary(patInfos, patReqs, ssoCredentials)
	return report, nil
}

func buildBasicSummary(pats []models.PATInfo, requests []models.PATRequest, ssoCreds []models.SSOCredential) models.OrgSummary {
	s := models.OrgSummary{
		TotalPATs:       len(pats),
		PendingRequests: len(requests),
		SSOCredentials:  len(ssoCreds),
	}
	thirtyDays := time.Now().Add(30 * 24 * time.Hour)
	for _, p := range pats {
		if p.TokenExpired {
			s.ExpiredPATs++
		} else {
			s.ActivePATs++
		}
		if p.TokenExpiresAt != nil && !p.TokenExpired && p.TokenExpiresAt.Before(thirtyDays) {
			s.ExpiringSoon++
		}
		if p.RepositorySelection == "all" {
			s.AllRepoAccessPATs++
		}
	}
	for _, c := range ssoCreds {
		switch c.CredentialType {
		case "personal access token":
			s.SSOClassicPATs++
		case "ssh key":
			s.SSOSSHKeys++
		}
	}
	return s
}

func (s *Server) ListenAndServe(cfg Config) error {
	if err := ValidateConfig(cfg); err != nil {
		return err
	}

	s.Configure(cfg)

	staticFS, err := fs.Sub(StaticFS, "static")
	if err != nil {
		return fmt.Errorf("creating static sub-filesystem: %w", err)
	}

	mux := http.NewServeMux()

	// Public health check for ALB — no auth required
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Auth routes (no session required)
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		data, err := fs.ReadFile(staticFS, "login.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		page := string(data)
		if s.oauthCfg == nil {
			page = strings.Replace(page, `<!-- PASSWORD_FORM_START`, "", 1)
			page = strings.Replace(page, `PASSWORD_FORM_END -->`, "", 1)
			page = strings.Replace(page, `<!-- GOOGLE_SSO_START -->`, `<!-- GOOGLE_SSO_START`, 1)
			page = strings.Replace(page, `<!-- GOOGLE_SSO_END -->`, `GOOGLE_SSO_END -->`, 1)
		} else if s.allowedDomain == "" {
			// No domain restriction configured — the note would be false, so
			// drop it rather than show a hardcoded/stale domain.
			page = strings.Replace(page, `<!-- RESTRICTED_NOTE_START -->`, `<!-- RESTRICTED_NOTE_START`, 1)
			page = strings.Replace(page, `<!-- RESTRICTED_NOTE_END -->`, `RESTRICTED_NOTE_END -->`, 1)
		} else {
			page = strings.Replace(page, `__ALLOWED_DOMAIN__`, s.allowedDomain, 1)
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(page))
	})
	mux.HandleFunc("POST /auth/login", s.handleAuthLogin)
	mux.HandleFunc("POST /auth/logout", s.handleAuthLogout)
	// Google OAuth routes (public — no session required)
	if s.oauthCfg != nil {
		mux.HandleFunc("GET /auth/google", s.handleGoogleLogin)
		mux.HandleFunc("GET /auth/google/callback", s.handleGoogleCallback)
	}

	// API routes
	mux.HandleFunc("GET /api/summary", s.handleSummary)
	mux.HandleFunc("GET /api/pats", s.handlePATsHistorical)
	mux.HandleFunc("GET /api/pats/{id}/repos", s.handlePATRepos)
	mux.HandleFunc("GET /api/pats/{id}/history", s.handlePATHistory)
	mux.HandleFunc("GET /api/events", s.handleEvents)
	mux.HandleFunc("GET /api/pats/requests", s.handlePATRequests)
	mux.HandleFunc("GET /api/sso-credentials", s.handleSSOCredentials)
	mux.HandleFunc("DELETE /api/sso-credentials/{id}/revoke", s.handleRevokeSSO)
	mux.HandleFunc("GET /api/apps", s.handleApps)
	mux.HandleFunc("POST /api/scan", s.handleScan)
	mux.HandleFunc("GET /api/report", s.handleReport)
	mux.HandleFunc("GET /api/violations", s.handleViolations)
	mux.HandleFunc("GET /api/secrets", s.handleSecrets)
	mux.HandleFunc("DELETE /api/secrets", s.handleDeleteSecret)
	mux.HandleFunc("GET /api/deploy-keys", s.handleDeployKeys)
	mux.HandleFunc("DELETE /api/deploy-keys/{id}", s.handleDeleteDeployKey)
	mux.HandleFunc("GET /api/workflow-permissions", s.handleWorkflowPerms)
	mux.HandleFunc("GET /api/workflow-files", s.handleWorkflowFiles)
	mux.HandleFunc("GET /api/attack-graph", s.handleAttackGraph)
	mux.HandleFunc("GET /api/attack-graph/nodes", s.handleAttackGraphNodes)
	mux.HandleFunc("GET /api/attack-graph/analytics", s.handleAttackAnalytics)
	mux.HandleFunc("GET /api/attack-graph/findings", s.handleAttackFindings)
	mux.HandleFunc("GET /api/actions-inventory", s.handleActionsInventory)
	mux.HandleFunc("GET /api/blast-radius", s.handleBlastRadius)
	mux.HandleFunc("POST /api/verify-secrets", s.handleVerifySecrets)
	mux.HandleFunc("POST /api/verify-org-secrets", s.handleVerifyOrgSecrets)
	mux.HandleFunc("POST /api/verify-all", s.handleVerifyAll)
	mux.HandleFunc("POST /api/pats/requests/{id}/review", s.handleReviewPATRequest)
	mux.HandleFunc("POST /api/pats/{id}/revoke", s.handleRevokePAT)
	mux.HandleFunc("POST /api/apps/{id}/suspend", s.handleSuspendApp)
	mux.HandleFunc("POST /api/apps/{id}/unsuspend", s.handleUnsuspendApp)
	mux.HandleFunc("GET /api/compliance", s.handleCompliance)
	mux.HandleFunc("GET /api/audit-log", s.handleAuditLog)
	mux.HandleFunc("GET /api/diff", s.handleDiff)
	mux.HandleFunc("GET /api/export", s.handleExport)

	// Webhook endpoint (no bearer auth — uses its own signature verification)
	mux.HandleFunc("POST /webhooks/github", s.handleWebhook)

	// Static files (catch-all)
	mux.Handle("GET /", http.FileServer(http.FS(staticFS)))

	// Build middleware chain
	var handler http.Handler = mux
	handler = SecurityHeaders(handler)
	requireAuth := s.password != "" || s.oauthCfg != nil
	handler = SessionAuth(s.sessions, requireAuth)(handler)
	handler = RedactedLogger(handler)

	// Graceful shutdown context
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Periodic session cleanup
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.sessions.cleanup()
			}
		}
	}()

	if s.store != nil {
		if cached, err := s.loadCachedReport(context.Background()); err != nil {
			log.Printf("WARNING: failed to load cached report from DB: %v (will scan fresh)", err)
			s.runScan(context.Background())
		} else if cached != nil {
			// Full cache hit — serve immediately and refresh in background.
			s.mu.Lock()
			s.report = cached
			s.mu.Unlock()
			log.Printf("Loaded cached report from DB: %d PATs, %d apps, %d secrets, %d deploy keys",
				len(cached.PATs), len(cached.Apps), len(cached.Secrets), len(cached.DeployKeys))
			// Use context.Background() so a SIGTERM during rolling deployment
			// doesn't cancel the scan mid-way through 308 repos.
			go s.runScan(context.Background())
		} else {
			// First run (empty DB) — scan in the background so the dashboard is
			// reachable immediately; API endpoints return 503 until data lands.
			log.Printf("No cached data found, running initial scan in background...")
			go s.runScan(context.Background())
		}
	} else {
		// No MySQL — blocking scan.
		s.runScan(context.Background())
	}

	// Scheduled rescans — use context.Background() so SIGTERM (ECS rolling
	// deployment drain) doesn't cancel a scan that's mid-way through repos.
	if cfg.ScanInterval > 0 {
		go s.scheduledScan(ctx, cfg.ScanInterval)
		log.Printf("Scheduled scanning every %s", cfg.ScanInterval)
	}

	// Scheduled secret verification — deliberately a separate, independent
	// interval from ScanInterval: a verify-all sweep pushes a temp branch and
	// runs GitHub Actions per repo (20+ minutes across a large org), so it's
	// too invasive to run on the same cadence as a plain scan. Off by default.
	if cfg.VerifyInterval > 0 {
		go s.scheduledVerify(ctx, cfg.VerifyInterval)
		log.Printf("Scheduled secret verification every %s", cfg.VerifyInterval)
	}

	addr := cfg.Addr
	if addr == "" {
		addr = "127.0.0.1"
	}
	listenAddr := net.JoinHostPort(addr, fmt.Sprintf("%d", cfg.Port))

	log.Printf("Dashboard available at http://%s", listenAddr)

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown goroutine
	go func() {
		<-ctx.Done()
		log.Printf("Shutting down server...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		server.Shutdown(shutdownCtx)
	}()

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		log.Printf("TLS enabled")
		return server.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	}

	return server.ListenAndServe()
}

func (s *Server) scheduledScan(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// context.Background() — scan must not be canceled by SIGTERM/shutdown.
			// The ticker loop itself still respects ctx so we stop scheduling new
			// scans on shutdown, but any in-flight scan runs to completion.
			go s.runScan(context.Background())
		}
	}
}

// scheduledVerify periodically runs a verify-all sweep over every not-yet-
// verified secret. Ticks that land while a sweep (manual or scheduled) is
// already in progress are skipped rather than queued — see verifyRunning.
func (s *Server) scheduledVerify(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !s.verifyRunning.CompareAndSwap(false, true) {
				log.Printf("[verify-all] skipping scheduled sweep — one is already in progress")
				continue
			}
			// context.Background(): a sweep mid-way through pushing/cleaning up
			// branches across many repos must not be canceled by SIGTERM.
			go func() {
				defer s.verifyRunning.Store(false)
				s.mu.RLock()
				report := s.report
				s.mu.RUnlock()
				if report == nil {
					return
				}
				start := time.Now()
				results, allDone := s.runVerifyAll(context.Background(), report)
				if allDone {
					log.Printf("[verify-all] scheduled sweep: nothing to verify")
					return
				}
				log.Printf("[verify-all] scheduled sweep completed in %s across %d repo(s)",
					time.Since(start).Round(time.Second), len(results))
			}()
		}
	}
}

// handleWebhook receives GitHub webhook events and triggers a rescan.
func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB max
	if err != nil {
		http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
		return
	}

	// Verify webhook signature if secret is configured
	if s.webhookSecret != "" {
		sig := r.Header.Get("X-Hub-Signature-256")
		if sig == "" {
			http.Error(w, `{"error":"missing signature"}`, http.StatusUnauthorized)
			return
		}
		if !verifyWebhookSignature(body, sig, s.webhookSecret) {
			http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
			return
		}
	}

	event := r.Header.Get("X-GitHub-Event")
	log.Printf("Webhook received: event=%s", event)

	// Relevant events that should trigger a rescan
	switch event {
	case "personal_access_token_request",
		"installation",
		"installation_repositories",
		"organization",
		"membership",
		"member":
		// Trigger async rescan
		go s.runScan(context.Background())
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"status": "scan triggered"})
	case "ping":
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "pong"})
	default:
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ignored", "event": event})
	}
}

// handleViolations returns current policy violations.
func (s *Server) handleViolations(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	v := s.violations
	if v == nil {
		v = []policy.Violation{}
	}
	writeJSON(w, v)
}

// handleAuthLogin validates credentials and creates a session cookie.
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	validUser := subtle.ConstantTimeCompare([]byte(creds.Username), []byte("admin")) == 1
	validPass := subtle.ConstantTimeCompare([]byte(creds.Password), []byte(s.password)) == 1
	if !validUser || !validPass {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		return
	}

	sessionID, err := s.sessions.create()
	if err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionDuration.Seconds()),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// handleAuthLogout destroys the session and clears the cookie.
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.sessions.destroy(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func verifyWebhookSignature(payload []byte, signature, secret string) bool {
	sig := strings.TrimPrefix(signature, "sha256=")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(expected))
}
