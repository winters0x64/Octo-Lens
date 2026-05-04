package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
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
	"syscall"
	"time"

	ghservice "github.com/th3-j0ik3r/github-pat-monitor/internal/github"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/notify"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/persist"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/policy"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/scanner"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/store"
)

type Server struct {
	gh          *ghservice.GitHubService
	scanner     *scanner.Scanner
	store       *store.Store
	org         string
	authToken   string
	report      *models.OrgReport
	mu          sync.RWMutex
	scanLimiter *RateLimiter

	// Policy and alerting
	policy       *policy.Policy
	slack        *notify.SlackNotifier
	webhookSecret string
	violations   []policy.Violation
	prevReport   *models.OrgReport
}

type Config struct {
	Addr          string
	Port          int
	AuthToken     string
	TLSCert       string
	TLSKey        string
	Org           string
	ScanInterval  time.Duration
	PolicyPath    string
	SlackWebhook  string
	WebhookSecret string
}

func NewServer(gh *ghservice.GitHubService, sc *scanner.Scanner, st *store.Store, org string, authToken string) *Server {
	return &Server{
		gh:          gh,
		scanner:     sc,
		store:       st,
		org:         org,
		authToken:   authToken,
		scanLimiter: NewRateLimiter(60 * time.Second),
	}
}

// Configure sets up policy engine, Slack notifier, and webhook secret.
func (s *Server) Configure(cfg Config) {
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

	if !isLoopback && cfg.AuthToken == "" {
		return fmt.Errorf(
			"refusing to start: binding to %s without --auth-token is insecure; "+
				"set PAT_MONITOR_AUTH_TOKEN or use --auth-token, or bind to 127.0.0.1",
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

	s.mu.Lock()
	s.prevReport = s.report
	s.report = report
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

	s.onScanComplete(report)
}

func (s *Server) ListenAndServe(cfg Config) error {
	if err := ValidateConfig(cfg); err != nil {
		return err
	}

	s.Configure(cfg)

	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("GET /api/summary", s.handleSummary)
	mux.HandleFunc("GET /api/pats", s.handlePATsHistorical)
	mux.HandleFunc("GET /api/pats/{id}/repos", s.handlePATRepos)
	mux.HandleFunc("GET /api/pats/{id}/history", s.handlePATHistory)
	mux.HandleFunc("GET /api/events", s.handleEvents)
	mux.HandleFunc("GET /api/pats/requests", s.handlePATRequests)
	mux.HandleFunc("GET /api/sso-credentials", s.handleSSOCredentials)
	mux.HandleFunc("GET /api/apps", s.handleApps)
	mux.HandleFunc("POST /api/scan", s.handleScan)
	mux.HandleFunc("GET /api/report", s.handleReport)
	mux.HandleFunc("GET /api/violations", s.handleViolations)
	mux.HandleFunc("GET /api/secrets", s.handleSecrets)
	mux.HandleFunc("GET /api/deploy-keys", s.handleDeployKeys)
	mux.HandleFunc("GET /api/workflow-permissions", s.handleWorkflowPerms)
	mux.HandleFunc("GET /api/workflow-files", s.handleWorkflowFiles)
	mux.HandleFunc("POST /api/pats/requests/{id}/review", s.handleReviewPATRequest)
	mux.HandleFunc("POST /api/pats/{id}/revoke", s.handleRevokePAT)
	mux.HandleFunc("GET /api/compliance", s.handleCompliance)
	mux.HandleFunc("GET /api/audit-log", s.handleAuditLog)

	// Webhook endpoint (no bearer auth — uses its own signature verification)
	mux.HandleFunc("POST /webhooks/github", s.handleWebhook)

	// Static files
	staticFS, err := fs.Sub(StaticFS, "static")
	if err != nil {
		return fmt.Errorf("creating static sub-filesystem: %w", err)
	}
	mux.Handle("GET /", http.FileServer(http.FS(staticFS)))

	// Build middleware chain
	var handler http.Handler = mux
	handler = SecurityHeaders(handler)
	if s.authToken != "" {
		handler = BearerAuth(s.authToken)(handler)
	}
	handler = RedactedLogger(handler)

	// Initial scan
	s.runScan(context.Background())

	// Graceful shutdown context
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Start background scheduled scanner
	if cfg.ScanInterval > 0 {
		go s.scheduledScan(ctx, cfg.ScanInterval)
		log.Printf("Scheduled scanning every %s", cfg.ScanInterval)
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
			s.runScan(ctx)
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

func verifyWebhookSignature(payload []byte, signature, secret string) bool {
	sig := strings.TrimPrefix(signature, "sha256=")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(expected))
}
