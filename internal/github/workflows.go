package github

import (
	"context"
	"encoding/base64"
	"os"
	"regexp"
	"sort"
	"strings"

	gh "github.com/google/go-github/v68/github"
	"gopkg.in/yaml.v3"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// fakeWorkflowPermissions returns hardcoded fake workflow permissions for local UI development.
func fakeWorkflowPermissions() []models.WorkflowPermission {
	return []models.WorkflowPermission{
		// write + can approve PRs — worst case
		{RepoName: "scapia-backend",       DefaultPermission: "write", CanApprovePRs: true,  Risk: models.RiskHigh},
		{RepoName: "payments-service",     DefaultPermission: "write", CanApprovePRs: true,  Risk: models.RiskHigh},
		// write, no PR approval
		{RepoName: "infra-terraform",      DefaultPermission: "write", CanApprovePRs: false, Risk: models.RiskHigh},
		{RepoName: "card-service",         DefaultPermission: "write", CanApprovePRs: false, Risk: models.RiskHigh},
		{RepoName: "notification-service", DefaultPermission: "write", CanApprovePRs: false, Risk: models.RiskHigh},
		// read + can approve PRs — medium
		{RepoName: "scapia-frontend",      DefaultPermission: "read",  CanApprovePRs: true,  Risk: models.RiskMedium},
		{RepoName: "analytics-service",    DefaultPermission: "read",  CanApprovePRs: true,  Risk: models.RiskMedium},
		// read, no PR approval — clean
		{RepoName: "docs-internal",        DefaultPermission: "read",  CanApprovePRs: false, Risk: models.RiskLow},
		{RepoName: "mobile-app",           DefaultPermission: "read",  CanApprovePRs: false, Risk: models.RiskLow},
		{RepoName: "data-platform",        DefaultPermission: "read",  CanApprovePRs: false, Risk: models.RiskLow},
	}
}

// fakeWorkflowFiles returns hardcoded fake workflow files for local UI development.
func fakeWorkflowFiles() []models.WorkflowFile {
	return []models.WorkflowFile{
		// write-all + unpinned + OIDC to prod — critical, large blast radius
		{
			RepoName: "scapia-backend", FileName: "deploy.yml",
			Path: ".github/workflows/deploy.yml", Permissions: "write-all",
			HasPinnedActions: false,
			UnpinnedActions:  []string{"actions/checkout@v4", "actions/setup-node@v3", "aws-actions/amazon-ecr-login@v2"},
			Actions: []models.ActionRef{
				{Raw: "actions/checkout@v4", Owner: "actions", Name: "checkout", Ref: "v4", Kind: "marketplace"},
				{Raw: "actions/setup-node@v3", Owner: "actions", Name: "setup-node", Ref: "v3", Kind: "marketplace"},
				{Raw: "aws-actions/configure-aws-credentials@v4", Owner: "aws-actions", Name: "configure-aws-credentials", Ref: "v4", Kind: "marketplace"},
				{Raw: "aws-actions/amazon-ecr-login@v2", Owner: "aws-actions", Name: "amazon-ecr-login", Ref: "v2", Kind: "marketplace"},
			},
			SecretRefs:   []string{"AWS_PROD_KEY", "SLACK_WEBHOOK"},
			OIDCRoles:    []string{"arn:aws:iam::111122223333:role/ProdDeployRole"},
			Environments: []string{"production"},
			Triggers:     []string{"push", "workflow_dispatch"},
			IDTokenWrite: true,
			Risk:         models.RiskHigh,
		},
		// dangerous trigger + shared secret — pull_request_target with secret access
		{
			RepoName: "payments-service", FileName: "ci.yml",
			Path: ".github/workflows/ci.yml", Permissions: "write-all",
			HasPinnedActions: false,
			UnpinnedActions:  []string{"actions/checkout@v4", "gradle/gradle-build-action@v2"},
			Actions: []models.ActionRef{
				{Raw: "actions/checkout@v4", Owner: "actions", Name: "checkout", Ref: "v4", Kind: "marketplace"},
				{Raw: "gradle/gradle-build-action@v2", Owner: "gradle", Name: "gradle-build-action", Ref: "v2", Kind: "marketplace"},
			},
			SecretRefs: []string{"AWS_PROD_KEY", "NPM_TOKEN"},
			Triggers:   []string{"pull_request_target", "push"},
			Risk:       models.RiskHigh,
		},
		// write-all, all pinned
		{
			RepoName: "infra-terraform", FileName: "plan.yml",
			Path: ".github/workflows/plan.yml", Permissions: "write-all",
			HasPinnedActions: true,
			UnpinnedActions:  nil,
			Risk: models.RiskHigh,
		},
		// not set + unpinned
		{
			RepoName: "card-service", FileName: "release.yml",
			Path: ".github/workflows/release.yml", Permissions: "not set",
			HasPinnedActions: false,
			UnpinnedActions:  []string{"actions/checkout@v4", "docker/build-push-action@v5", "sigstore/cosign-installer@v3"},
			Risk: models.RiskHigh,
		},
		{
			RepoName: "notification-service", FileName: "test.yml",
			Path: ".github/workflows/test.yml", Permissions: "not set",
			HasPinnedActions: false,
			UnpinnedActions:  []string{"actions/checkout@v4", "actions/setup-go@v4"},
			Risk: models.RiskHigh,
		},
		// read-all + unpinned — medium
		{
			RepoName: "scapia-frontend", FileName: "lint.yml",
			Path: ".github/workflows/lint.yml", Permissions: "read-all",
			HasPinnedActions: false,
			UnpinnedActions:  []string{"actions/checkout@v4", "actions/setup-node@v3"},
			Risk: models.RiskMedium,
		},
		{
			RepoName: "analytics-service", FileName: "build.yml",
			Path: ".github/workflows/build.yml", Permissions: "read-all",
			HasPinnedActions: false,
			UnpinnedActions:  []string{"actions/checkout@v4"},
			Risk: models.RiskMedium,
		},
		// fully secure — read-all, all pinned
		{
			RepoName: "docs-internal", FileName: "publish.yml",
			Path: ".github/workflows/publish.yml", Permissions: "read-all",
			HasPinnedActions: true,
			UnpinnedActions:  nil,
			Risk: models.RiskLow,
		},
		{
			RepoName: "mobile-app", FileName: "test.yml",
			Path: ".github/workflows/test.yml", Permissions: "read-all",
			HasPinnedActions: true,
			UnpinnedActions:  nil,
			Risk: models.RiskLow,
		},
	}
}

// ListWorkflowPermissions fetches the default GITHUB_TOKEN permissions for each repo.
func (s *GitHubService) ListWorkflowPermissions(ctx context.Context, repos []*gh.Repository) ([]models.WorkflowPermission, error) {
	if os.Getenv("SEED_FAKE_SSO") == "true" {
		return fakeWorkflowPermissions(), nil
	}
	var all []models.WorkflowPermission

	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		name := repo.GetName()

		perms, _, err := s.client.Repositories.GetDefaultWorkflowPermissions(ctx, s.org, name)
		if err != nil {
			// Non-fatal: repo may not have Actions enabled
			continue
		}

		risk := models.RiskLow
		defaultPerm := perms.GetDefaultWorkflowPermissions()
		if defaultPerm == "write" {
			risk = models.RiskHigh
		}

		all = append(all, models.WorkflowPermission{
			RepoName:          name,
			DefaultPermission: defaultPerm,
			CanApprovePRs:     perms.GetCanApprovePullRequestReviews(),
			Risk:              risk,
		})

		if err := s.checkRateLimit(ctx); err != nil {
			return all, err
		}
	}

	return all, nil
}

// WorkflowContent is the raw, decoded YAML of one workflow file, captured so it
// can be handed to external analyzers (zizmor) without re-fetching.
type WorkflowContent struct {
	RepoName string
	Path     string
	Content  string
}

// AuditWorkflowFiles scans .github/workflows/ in each repo for permission and
// pinning issues, and returns the raw decoded YAML of each file alongside the
// findings so callers can run additional analysis (e.g. zizmor).
func (s *GitHubService) AuditWorkflowFiles(ctx context.Context, repos []*gh.Repository) ([]models.WorkflowFile, []WorkflowContent, error) {
	if os.Getenv("SEED_FAKE_SSO") == "true" {
		return fakeWorkflowFiles(), nil, nil
	}
	var all []models.WorkflowFile
	var contents []WorkflowContent

	for _, repo := range repos {
		if repo.GetArchived() {
			continue
		}
		name := repo.GetName()

		// List workflow directory contents
		_, dirContent, _, err := s.client.Repositories.GetContents(
			ctx, s.org, name, ".github/workflows", nil,
		)
		if err != nil {
			// No workflows directory — skip
			continue
		}

		for _, file := range dirContent {
			fname := file.GetName()
			if !strings.HasSuffix(fname, ".yml") && !strings.HasSuffix(fname, ".yaml") {
				continue
			}

			wf, content := s.auditSingleWorkflow(ctx, name, fname, file.GetPath())
			all = append(all, wf)
			if content != "" {
				contents = append(contents, WorkflowContent{RepoName: name, Path: file.GetPath(), Content: content})
			}
		}

		if err := s.checkRateLimit(ctx); err != nil {
			return all, contents, err
		}
	}

	return all, contents, nil
}

// auditSingleWorkflow returns the parsed findings and the raw decoded YAML
// (empty string when the content could not be fetched/decoded).
func (s *GitHubService) auditSingleWorkflow(ctx context.Context, repo, fileName, path string) (models.WorkflowFile, string) {
	wf := models.WorkflowFile{
		RepoName: repo,
		FileName: fileName,
		Path:     path,
		Risk:     models.RiskLow,
	}

	// Fetch file content
	fileContent, _, _, err := s.client.Repositories.GetContents(ctx, s.org, repo, path, nil)
	if err != nil || fileContent == nil {
		wf.Permissions = "unknown"
		return wf, ""
	}

	content, err := decodeContent(fileContent)
	if err != nil {
		wf.Permissions = "unknown"
		return wf, ""
	}

	// Top-level permission classification is kept as a string for back-compat
	// with the existing UI/compliance checks regardless of structured parse.
	wf.Permissions = analyzePermissions(content)

	// Structured parse for blast-radius inputs. Secret references are regex-based
	// (they appear in expressions anywhere), the rest come from the YAML tree.
	wf.SecretRefs = extractSecretRefs(content)
	parseWorkflowStructure(content, &wf)

	// Derive back-compat fields from the structured action list.
	for _, a := range wf.Actions {
		if !a.Pinned && (a.Kind == "marketplace" || a.Kind == "reusable_workflow") {
			wf.UnpinnedActions = append(wf.UnpinnedActions, a.Raw)
		}
	}
	wf.HasPinnedActions = len(wf.UnpinnedActions) == 0

	// Determine risk
	if wf.Permissions == "write-all" || wf.Permissions == "not set" {
		wf.Risk = models.RiskHigh
	} else if len(wf.UnpinnedActions) > 0 {
		wf.Risk = models.RiskMedium
	}

	return wf, content
}

// parseWorkflowStructure decodes the workflow YAML into a generic tree and
// extracts actions, triggers, environments, OIDC roles, id-token usage, and
// self-hosted runner usage. On parse failure it falls back to the legacy
// line-based action scan so a malformed file never loses all signal.
func parseWorkflowStructure(content string, wf *models.WorkflowFile) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil || doc == nil {
		// Fallback: at least recover action refs from raw text.
		for _, raw := range findUnpinnedActions(content) {
			wf.Actions = append(wf.Actions, parseActionRef(raw))
		}
		return
	}

	wf.Triggers = extractTriggers(doc["on"])

	// Top-level permissions can grant id-token.
	if idTokenWrite(doc["permissions"]) {
		wf.IDTokenWrite = true
	}

	envSet := map[string]bool{}
	oidcSet := map[string]bool{}

	jobs, _ := doc["jobs"].(map[string]any)
	for _, jv := range jobs {
		job, ok := jv.(map[string]any)
		if !ok {
			continue
		}

		if idTokenWrite(job["permissions"]) {
			wf.IDTokenWrite = true
		}
		if runsOnSelfHosted(job["runs-on"]) {
			wf.SelfHosted = true
		}
		for _, e := range extractEnvironments(job["environment"]) {
			envSet[e] = true
		}

		steps, _ := job["steps"].([]any)
		for _, sv := range steps {
			step, ok := sv.(map[string]any)
			if !ok {
				continue
			}
			uses, _ := step["uses"].(string)
			if uses == "" {
				continue
			}
			ref := parseActionRef(uses)
			wf.Actions = append(wf.Actions, ref)

			if with, ok := step["with"].(map[string]any); ok {
				for _, role := range oidcRolesFromStep(ref, with) {
					oidcSet[role] = true
				}
			}
		}
	}

	wf.Environments = sortedKeys(envSet)
	wf.OIDCRoles = sortedKeys(oidcSet)
}

var secretRefRe = regexp.MustCompile(`secrets\.([A-Za-z_][A-Za-z0-9_]*)`)

// extractSecretRefs returns the distinct secret names referenced via
// ${{ secrets.NAME }} expressions. Dynamic references (secrets.*, the whole
// secrets context via toJSON) collapse to "*".
func extractSecretRefs(content string) []string {
	set := map[string]bool{}
	if strings.Contains(content, "toJSON(secrets)") || strings.Contains(content, "secrets.*") {
		set["*"] = true
	}
	for _, m := range secretRefRe.FindAllStringSubmatch(content, -1) {
		name := m[1]
		// GITHUB_TOKEN is always present; it isn't a managed secret.
		if name == "GITHUB_TOKEN" {
			continue
		}
		set[name] = true
	}
	return sortedKeys(set)
}

// parseActionRef parses a `uses:` value into its components and classifies it.
func parseActionRef(raw string) models.ActionRef {
	raw = strings.TrimSpace(raw)
	ref := models.ActionRef{Raw: raw}

	switch {
	case strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "../"):
		ref.Kind = "local"
		return ref
	case strings.HasPrefix(raw, "docker://"):
		ref.Kind = "docker"
		ref.Name = strings.TrimPrefix(raw, "docker://")
		return ref
	}

	// owner/repo[/path]@ref  — a reusable workflow is owner/repo/path.yml@ref.
	path := raw
	if at := strings.LastIndex(raw, "@"); at != -1 {
		path = raw[:at]
		ref.Ref = raw[at+1:]
	}
	if strings.Contains(path, ".github/workflows/") ||
		strings.HasSuffix(path, ".yml") || strings.HasSuffix(path, ".yaml") {
		ref.Kind = "reusable_workflow"
	} else {
		ref.Kind = "marketplace"
	}

	parts := strings.SplitN(path, "/", 2)
	ref.Owner = parts[0]
	if len(parts) > 1 {
		ref.Name = parts[1]
	}

	if len(ref.Ref) == 40 && isHex(ref.Ref) {
		ref.SHA = ref.Ref
		ref.Pinned = true
	}
	return ref
}

// oidcRolesFromStep pulls the cloud identity a credential-configuring action
// requests, for the common AWS/Azure/GCP login actions.
func oidcRolesFromStep(ref models.ActionRef, with map[string]any) []string {
	id := ref.Owner + "/" + ref.Name
	var keys []string
	switch {
	case strings.HasPrefix(id, "aws-actions/configure-aws-credentials"):
		keys = []string{"role-to-assume"}
	case strings.HasPrefix(id, "azure/login"):
		keys = []string{"client-id"}
	case strings.HasPrefix(id, "google-github-actions/auth"):
		keys = []string{"workload_identity_provider"}
	default:
		return nil
	}
	var out []string
	for _, k := range keys {
		if v, ok := with[k].(string); ok {
			v = strings.TrimSpace(v)
			// Skip values that are pure expressions (e.g. ${{ secrets.ROLE }})
			// with no literal ARN — they carry no resolvable boundary.
			if v != "" && !strings.HasPrefix(v, "${{") {
				out = append(out, v)
			}
		}
	}
	return out
}

// idTokenWrite reports whether a permissions value grants OIDC id-token: write.
func idTokenWrite(perm any) bool {
	switch p := perm.(type) {
	case string:
		return p == "write-all"
	case map[string]any:
		if v, ok := p["id-token"].(string); ok {
			return v == "write"
		}
	}
	return false
}

// runsOnSelfHosted reports whether a runs-on value targets a self-hosted runner.
func runsOnSelfHosted(v any) bool {
	isSelf := func(s string) bool {
		s = strings.ToLower(s)
		return s == "self-hosted" || strings.Contains(s, "self-hosted")
	}
	switch r := v.(type) {
	case string:
		return isSelf(r)
	case []any:
		for _, item := range r {
			if s, ok := item.(string); ok && isSelf(s) {
				return true
			}
		}
	case map[string]any:
		// runs-on: { group: ..., labels: [...] } form
		if labels, ok := r["labels"].([]any); ok {
			for _, item := range labels {
				if s, ok := item.(string); ok && isSelf(s) {
					return true
				}
			}
		}
		if _, ok := r["group"]; ok {
			return true // runner groups are self-hosted by definition
		}
	}
	return false
}

// extractEnvironments returns environment names from a job's environment: key,
// which may be a bare string or a { name: ... } mapping.
func extractEnvironments(v any) []string {
	switch e := v.(type) {
	case string:
		if e != "" {
			return []string{e}
		}
	case map[string]any:
		if name, ok := e["name"].(string); ok && name != "" {
			return []string{name}
		}
	case []any:
		var out []string
		for _, item := range e {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// extractTriggers returns the event names from a workflow's on: key, which may
// be a string, a list, or a mapping of event -> config.
func extractTriggers(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case map[string]any:
		out := make([]string, 0, len(t))
		for k := range t {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	return nil
}

func sortedKeys(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func decodeContent(fc *gh.RepositoryContent) (string, error) {
	if fc.Content != nil {
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(*fc.Content, "\n", ""))
		if err != nil {
			return "", err
		}
		return string(decoded), nil
	}
	return "", nil
}

// analyzePermissions does simple text analysis of workflow YAML for top-level permissions.
func analyzePermissions(content string) string {
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip comments
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Top-level permissions block
		if strings.HasPrefix(trimmed, "permissions:") {
			value := strings.TrimSpace(strings.TrimPrefix(trimmed, "permissions:"))
			if value == "{}" || value == "read-all" {
				return "read-all"
			}
			if value == "write-all" {
				return "write-all"
			}
			if value == "" {
				// Multi-line permissions block — generally fine (explicit)
				return "explicit"
			}
			return value
		}
	}

	return "not set"
}

// findUnpinnedActions finds uses: directives that reference tags instead of SHA commits.
func findUnpinnedActions(content string) []string {
	var unpinned []string
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "- uses:") && !strings.HasPrefix(trimmed, "uses:") {
			continue
		}

		// Extract the action reference
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) < 2 {
			continue
		}
		ref := strings.TrimSpace(parts[1])

		// Skip local actions (./path)
		if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
			continue
		}

		// Check if pinned to SHA (40 hex chars after @)
		atIdx := strings.LastIndex(ref, "@")
		if atIdx == -1 {
			unpinned = append(unpinned, ref)
			continue
		}

		sha := ref[atIdx+1:]
		if len(sha) != 40 || !isHex(sha) {
			unpinned = append(unpinned, ref)
		}
	}

	return unpinned
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
