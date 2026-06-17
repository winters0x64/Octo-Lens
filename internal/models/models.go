package models

import "time"

type RiskLevel string

const (
	RiskHigh   RiskLevel = "high"
	RiskMedium RiskLevel = "medium"
	RiskLow    RiskLevel = "low"
)

type Permission struct {
	Name  string    `json:"name"`
	Level string    `json:"level"`
	Risk  RiskLevel `json:"risk"`
}

type PATInfo struct {
	ID                  int64        `json:"id"`
	TokenName           string       `json:"token_name"`
	OwnerLogin          string       `json:"owner_login"`
	OwnerAvatarURL      string       `json:"owner_avatar_url"`
	RepositorySelection string       `json:"repository_selection"`
	Permissions         []Permission `json:"permissions"`
	AccessGrantedAt     time.Time    `json:"access_granted_at"`
	TokenExpiresAt      *time.Time   `json:"token_expires_at"`
	TokenLastUsedAt     *time.Time   `json:"token_last_used_at"`
	TokenExpired        bool         `json:"token_expired"`
}

type RepoInfo struct {
	Name     string `json:"name"`
	FullName string `json:"full_name"`
	Private  bool   `json:"private"`
}

type PATRequest struct {
	ID                  int64        `json:"id"`
	TokenName           string       `json:"token_name"`
	OwnerLogin          string       `json:"owner_login"`
	RepositorySelection string       `json:"repository_selection"`
	Permissions         []Permission `json:"permissions"`
	CreatedAt           time.Time    `json:"created_at"`
	TokenExpiresAt      *time.Time   `json:"token_expires_at"`
}

type AppInstallation struct {
	ID                  int64        `json:"id"`
	AppName             string       `json:"app_name"`
	AppSlug             string       `json:"app_slug"`
	Permissions         []Permission `json:"permissions"`
	Events              []string     `json:"events"`
	RepositorySelection string       `json:"repository_selection"`
	CreatedAt           time.Time    `json:"created_at"`
	UpdatedAt           time.Time    `json:"updated_at"`
	Suspended           bool         `json:"suspended"`
	HighRiskCount       int          `json:"high_risk_count"`
	MediumRiskCount     int          `json:"medium_risk_count"`
	LowRiskCount        int          `json:"low_risk_count"`
}

type SSOCredential struct {
	CredentialID              int64      `json:"credential_id"`
	Login                     string     `json:"login"`
	CredentialType            string     `json:"credential_type"`
	TokenLastEight            string     `json:"token_last_eight"`
	CredentialAuthorizedAt    time.Time  `json:"credential_authorized_at"`
	CredentialAccessedAt      *time.Time `json:"credential_accessed_at"`
	AuthorizedCredentialTitle string     `json:"authorized_credential_title"`
	AuthorizedCredentialNote  string     `json:"authorized_credential_note"`
	AuthorizedCredentialExpAt *time.Time `json:"authorized_credential_expires_at"`
	Scopes                    []string   `json:"scopes"`
	Fingerprint               string     `json:"fingerprint"`
}

// OrgSecret represents an Actions secret at org, repo, or environment level.
type OrgSecret struct {
	Name       string     `json:"name"`
	Scope      string     `json:"scope"`       // "org", "repo", "environment"
	Visibility string     `json:"visibility"`   // "all", "private", "selected" (org-level only)
	RepoName   string     `json:"repo_name"`    // empty for org-level
	EnvName    string     `json:"env_name"`     // set for environment secrets
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	Risk       RiskLevel  `json:"risk"`
}

// DeployKey represents an SSH deploy key on a repository.
type DeployKey struct {
	ID        int64      `json:"id"`
	Title     string     `json:"title"`
	RepoName  string     `json:"repo_name"`
	ReadOnly  bool       `json:"read_only"`
	CreatedAt time.Time  `json:"created_at"`
	LastUsed  *time.Time `json:"last_used"`
	AddedBy   string     `json:"added_by"`
	Risk      RiskLevel  `json:"risk"`
}

// WorkflowPermission captures the default GITHUB_TOKEN permission for a repository.
type WorkflowPermission struct {
	RepoName                   string    `json:"repo_name"`
	DefaultPermission          string    `json:"default_permission"`          // "read" or "write"
	CanApprovePRs              bool      `json:"can_approve_pull_requests"`
	Risk                       RiskLevel `json:"risk"`
}

// ActionRef is a single `uses:` reference extracted from a workflow, with its
// pinning status. Kind distinguishes marketplace actions from reusable
// workflows, container actions, and local actions.
type ActionRef struct {
	Raw    string `json:"raw"`              // original ref, e.g. "actions/checkout@v4"
	Owner  string `json:"owner"`            // "actions" (empty for local/docker)
	Name   string `json:"name"`             // "checkout" (repo or repo/path for reusable)
	Ref    string `json:"ref"`              // tag/branch/SHA after @
	SHA    string `json:"sha,omitempty"`    // set when Ref is a 40-char commit SHA
	Pinned bool   `json:"pinned"`           // true when pinned to a full commit SHA
	Kind   string `json:"kind"`             // "marketplace" | "reusable_workflow" | "docker" | "local"
}

// WorkflowFile represents a parsed workflow YAML with permission findings and
// the structured supply-chain facts needed for blast-radius analysis.
type WorkflowFile struct {
	RepoName        string    `json:"repo_name"`
	FileName        string    `json:"file_name"`
	Path            string    `json:"path"`
	Permissions     string    `json:"permissions"`      // raw permissions string or "write-all", "read-all", "not set"
	HasPinnedActions bool     `json:"has_pinned_actions"`
	UnpinnedActions  []string `json:"unpinned_actions"` // retained for back-compat (derived from Actions)
	Risk            RiskLevel `json:"risk"`

	// Structured extraction (blast-radius graph inputs).
	Actions      []ActionRef `json:"actions,omitempty"`        // every uses: ref, pinned and unpinned
	SecretRefs   []string    `json:"secret_refs,omitempty"`    // ${{ secrets.NAME }} names; "*" = dynamic/all
	Environments []string    `json:"environments,omitempty"`   // job-level environment: values
	OIDCRoles    []string    `json:"oidc_roles,omitempty"`     // cloud role ARNs / WIF providers requested
	Triggers     []string    `json:"triggers,omitempty"`       // on: event keys
	IDTokenWrite bool        `json:"id_token_write"`           // OIDC: id-token: write present
	SelfHosted   bool        `json:"self_hosted"`              // any runs-on: self-hosted

	// External SAST findings from zizmor (offline audit).
	ZizmorFindings []ZizmorFinding `json:"zizmor_findings,omitempty"`
}

// ZizmorFinding is a single static-analysis finding from zizmor for a workflow.
type ZizmorFinding struct {
	RuleID     string `json:"rule_id"`    // zizmor "ident", e.g. "template-injection"
	Desc       string `json:"desc"`
	URL        string `json:"url"`        // link to the audit's documentation
	Severity   string `json:"severity"`   // informational | low | medium | high (lowercased)
	Confidence string `json:"confidence"` // low | medium | high (lowercased)
	Line       int    `json:"line"`       // 1-based line in the workflow (zizmor reports 0-based)
}

type OrgSummary struct {
	TotalPATs          int `json:"total_pats"`
	ActivePATs         int `json:"active_pats"`
	ExpiredPATs        int `json:"expired_pats"`
	ExpiringSoon       int `json:"expiring_soon"`
	PendingRequests    int `json:"pending_requests"`
	TotalApps          int `json:"total_apps"`
	HighRiskApps       int `json:"high_risk_apps"`
	AllRepoAccessPATs  int `json:"all_repo_access_pats"`
	AllRepoAccessApps  int `json:"all_repo_access_apps"`
	SSOCredentials     int `json:"sso_credentials"`
	SSOClassicPATs     int `json:"sso_classic_pats"`
	SSOSSHKeys         int `json:"sso_ssh_keys"`

	// New credential metrics
	TotalSecrets          int `json:"total_secrets"`
	OrgSecrets            int `json:"org_secrets"`
	OrgWideSecrets        int `json:"org_wide_secrets"`
	TotalDeployKeys       int `json:"total_deploy_keys"`
	WriteDeployKeys       int `json:"write_deploy_keys"`
	TotalReposScanned     int `json:"total_repos_scanned"`
	WriteAllWorkflows     int `json:"write_all_workflows"`
	UnpinnedActionRepos   int `json:"unpinned_action_repos"`
}

type OrgReport struct {
	Org             string              `json:"org"`
	ScannedAt       time.Time           `json:"scanned_at"`
	PATs            []PATInfo           `json:"pats"`
	PendingRequests []PATRequest        `json:"pending_requests"`
	Apps            []AppInstallation   `json:"apps"`
	SSOCredentials  []SSOCredential     `json:"sso_credentials"`
	Secrets         []OrgSecret         `json:"secrets"`
	DeployKeys      []DeployKey         `json:"deploy_keys"`
	WorkflowPerms   []WorkflowPermission `json:"workflow_permissions"`
	WorkflowFiles   []WorkflowFile      `json:"workflow_files"`
	Summary         OrgSummary          `json:"summary"`
}

// AuditLogEntry represents a PAT-related event from the org audit log.
type AuditLogEntry struct {
	Action    string     `json:"action"`
	Actor     string     `json:"actor"`
	CreatedAt time.Time  `json:"created_at"`
	TokenID   int64      `json:"token_id,omitempty"`
	TokenName string     `json:"token_name,omitempty"`
	User      string     `json:"user,omitempty"`
	Message   string     `json:"message,omitempty"`
}

// ComplianceCheck represents an org-level security posture check.
type ComplianceCheck struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Status      string    `json:"status"`  // "pass", "fail", "warn", "unknown"
	Detail      string    `json:"detail"`
	FixURL      string    `json:"fix_url"`
}

// CategorizePermission determines the risk level of a permission based on its name and access level.
func CategorizePermission(name, level string) RiskLevel {
	if level == "admin" {
		return RiskHigh
	}

	highRiskNames := map[string]bool{
		"administration":              true,
		"organization_administration": true,
		"members":                     true,
		"organization_secrets":        true,
		"secrets":                     true,
		"security_events":             true,
		"actions":                     true,
		"workflows":                   true,
		"environments":                true,
		"organization_hooks":          true,
		"organization_plan":           true,
	}

	if level == "write" {
		if highRiskNames[name] {
			return RiskHigh
		}
		return RiskMedium
	}

	if highRiskNames[name] && level == "read" {
		return RiskMedium
	}

	return RiskLow
}
