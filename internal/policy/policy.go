package policy

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// Policy defines security rules for all credential types.
type Policy struct {
	PAT      PATPolicy      `yaml:"pat"`
	App      AppPolicy      `yaml:"app"`
	SSO      SSOPolicy      `yaml:"sso"`
	Secrets  SecretsPolicy  `yaml:"secrets"`
	Deploy   DeployPolicy   `yaml:"deploy_keys"`
	Workflow WorkflowPolicy `yaml:"workflows"`
}

type PATPolicy struct {
	MaxExpiryDays        int  `yaml:"max_expiry_days"`
	DenyNoExpiry         bool `yaml:"deny_no_expiry"`
	DenyAllRepoAccess    bool `yaml:"deny_all_repo_access"`
	DenyAdminPermissions bool `yaml:"deny_admin_permissions"`
	MaxInactiveDays      int  `yaml:"max_inactive_days"`
}

type AppPolicy struct {
	DenyAllRepoAccess      bool `yaml:"deny_all_repo_access"`
	MaxHighRiskPermissions int  `yaml:"max_high_risk_permissions"`
}

type SSOPolicy struct {
	DenyClassicPATs bool `yaml:"deny_classic_pats"`
}

type SecretsPolicy struct {
	DenyOrgWideVisibility bool `yaml:"deny_org_wide_visibility"`
	MaxStaleDays          int  `yaml:"max_stale_days"`
}

type DeployPolicy struct {
	DenyWriteAccess bool `yaml:"deny_write_access"`
}

type WorkflowPolicy struct {
	DenyWriteAllDefault bool `yaml:"deny_write_all_default"`
	DenyUnpinnedActions bool `yaml:"deny_unpinned_actions"`
	DenyCanApprovePRs   bool `yaml:"deny_can_approve_prs"`
}

// Violation represents a single policy violation found during evaluation.
type Violation struct {
	Rule     string           `json:"rule"`
	Severity models.RiskLevel `json:"severity"`
	Resource string           `json:"resource"`
	Message  string           `json:"message"`
}

// LoadFromFile reads a YAML policy file from disk.
func LoadFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse policy file: %w", err)
	}
	return &p, nil
}

// Default returns a sensible-defaults policy.
func Default() *Policy {
	return &Policy{
		PAT: PATPolicy{
			MaxExpiryDays:        90,
			DenyNoExpiry:         true,
			DenyAllRepoAccess:    true,
			DenyAdminPermissions: true,
			MaxInactiveDays:      30,
		},
		App: AppPolicy{
			DenyAllRepoAccess:      true,
			MaxHighRiskPermissions: 0,
		},
		Secrets: SecretsPolicy{
			DenyOrgWideVisibility: true,
			MaxStaleDays:          365,
		},
		Deploy: DeployPolicy{
			DenyWriteAccess: true,
		},
		Workflow: WorkflowPolicy{
			DenyWriteAllDefault: true,
			DenyUnpinnedActions: true,
			DenyCanApprovePRs:   true,
		},
	}
}

// Evaluate checks all rules against an org report and returns violations.
func (p *Policy) Evaluate(report *models.OrgReport) []Violation {
	var violations []Violation

	violations = append(violations, p.evaluatePATs(report)...)
	violations = append(violations, p.evaluateApps(report)...)
	violations = append(violations, p.evaluateSSO(report)...)
	violations = append(violations, p.evaluateSecrets(report)...)
	violations = append(violations, p.evaluateDeployKeys(report)...)
	violations = append(violations, p.evaluateWorkflows(report)...)

	return violations
}

func (p *Policy) evaluatePATs(report *models.OrgReport) []Violation {
	var violations []Violation
	now := time.Now()

	for _, pat := range report.PATs {
		if pat.TokenExpired {
			continue
		}
		resource := fmt.Sprintf("PAT: %s (owner: %s)", pat.TokenName, pat.OwnerLogin)

		if p.PAT.DenyNoExpiry && pat.TokenExpiresAt == nil {
			violations = append(violations, Violation{
				Rule:     "pat.deny_no_expiry",
				Severity: models.RiskHigh,
				Resource: resource,
				Message:  "PAT has no expiration date set",
			})
		}

		if p.PAT.MaxExpiryDays > 0 && pat.TokenExpiresAt != nil {
			maxExpiry := now.Add(time.Duration(p.PAT.MaxExpiryDays) * 24 * time.Hour)
			if pat.TokenExpiresAt.After(maxExpiry) {
				violations = append(violations, Violation{
					Rule:     "pat.max_expiry_days",
					Severity: models.RiskMedium,
					Resource: resource,
					Message:  fmt.Sprintf("PAT expires in more than %d days", p.PAT.MaxExpiryDays),
				})
			}
		}

		if p.PAT.DenyAllRepoAccess && pat.RepositorySelection == "all" {
			violations = append(violations, Violation{
				Rule:     "pat.deny_all_repo_access",
				Severity: models.RiskHigh,
				Resource: resource,
				Message:  "PAT has access to all repositories",
			})
		}

		if p.PAT.DenyAdminPermissions {
			for _, perm := range pat.Permissions {
				if perm.Level == "admin" {
					violations = append(violations, Violation{
						Rule:     "pat.deny_admin_permissions",
						Severity: models.RiskHigh,
						Resource: resource,
						Message:  fmt.Sprintf("PAT has admin-level %q permission", perm.Name),
					})
				}
			}
		}

		if p.PAT.MaxInactiveDays > 0 && pat.TokenLastUsedAt != nil {
			threshold := now.Add(-time.Duration(p.PAT.MaxInactiveDays) * 24 * time.Hour)
			if pat.TokenLastUsedAt.Before(threshold) {
				violations = append(violations, Violation{
					Rule:     "pat.max_inactive_days",
					Severity: models.RiskLow,
					Resource: resource,
					Message:  fmt.Sprintf("PAT unused for over %d days", p.PAT.MaxInactiveDays),
				})
			}
		}
	}

	return violations
}

func (p *Policy) evaluateApps(report *models.OrgReport) []Violation {
	var violations []Violation

	for _, app := range report.Apps {
		if app.Suspended {
			continue
		}
		resource := fmt.Sprintf("App: %s", app.AppName)

		if p.App.DenyAllRepoAccess && app.RepositorySelection == "all" {
			violations = append(violations, Violation{
				Rule:     "app.deny_all_repo_access",
				Severity: models.RiskHigh,
				Resource: resource,
				Message:  "App has access to all repositories",
			})
		}

		if app.HighRiskCount > p.App.MaxHighRiskPermissions {
			violations = append(violations, Violation{
				Rule:     "app.max_high_risk_permissions",
				Severity: models.RiskHigh,
				Resource: resource,
				Message:  fmt.Sprintf("App has %d high-risk permissions (max: %d)", app.HighRiskCount, p.App.MaxHighRiskPermissions),
			})
		}
	}

	return violations
}

func (p *Policy) evaluateSSO(report *models.OrgReport) []Violation {
	var violations []Violation

	if p.SSO.DenyClassicPATs {
		for _, cred := range report.SSOCredentials {
			if cred.CredentialType == "personal access token" {
				violations = append(violations, Violation{
					Rule:     "sso.deny_classic_pats",
					Severity: models.RiskMedium,
					Resource: fmt.Sprintf("SSO credential: %s (user: %s)", cred.AuthorizedCredentialTitle, cred.Login),
					Message:  "Classic PAT authorized via SSO",
				})
			}
		}
	}

	return violations
}

func (p *Policy) evaluateSecrets(report *models.OrgReport) []Violation {
	var violations []Violation
	now := time.Now()

	for _, sec := range report.Secrets {
		resource := fmt.Sprintf("Secret: %s (%s", sec.Name, sec.Scope)
		if sec.RepoName != "" {
			resource += "/" + sec.RepoName
		}
		if sec.EnvName != "" {
			resource += "/" + sec.EnvName
		}
		resource += ")"

		if p.Secrets.DenyOrgWideVisibility && sec.Scope == "org" && sec.Visibility == "all" {
			violations = append(violations, Violation{
				Rule:     "secrets.deny_org_wide_visibility",
				Severity: models.RiskHigh,
				Resource: resource,
				Message:  "Org secret is visible to all repositories",
			})
		}

		if p.Secrets.MaxStaleDays > 0 {
			staleThreshold := now.Add(-time.Duration(p.Secrets.MaxStaleDays) * 24 * time.Hour)
			if sec.UpdatedAt.Before(staleThreshold) {
				violations = append(violations, Violation{
					Rule:     "secrets.max_stale_days",
					Severity: models.RiskMedium,
					Resource: resource,
					Message:  fmt.Sprintf("Secret not rotated in over %d days", p.Secrets.MaxStaleDays),
				})
			}
		}
	}

	return violations
}

func (p *Policy) evaluateDeployKeys(report *models.OrgReport) []Violation {
	var violations []Violation

	if p.Deploy.DenyWriteAccess {
		for _, dk := range report.DeployKeys {
			if !dk.ReadOnly {
				violations = append(violations, Violation{
					Rule:     "deploy_keys.deny_write_access",
					Severity: models.RiskHigh,
					Resource: fmt.Sprintf("Deploy key: %s (repo: %s)", dk.Title, dk.RepoName),
					Message:  "Deploy key has write (push) access",
				})
			}
		}
	}

	return violations
}

func (p *Policy) evaluateWorkflows(report *models.OrgReport) []Violation {
	var violations []Violation

	if p.Workflow.DenyWriteAllDefault {
		for _, wp := range report.WorkflowPerms {
			if wp.DefaultPermission == "write" {
				violations = append(violations, Violation{
					Rule:     "workflows.deny_write_all_default",
					Severity: models.RiskHigh,
					Resource: fmt.Sprintf("Repo: %s", wp.RepoName),
					Message:  "GITHUB_TOKEN default permission is write-all",
				})
			}
		}
	}

	if p.Workflow.DenyCanApprovePRs {
		for _, wp := range report.WorkflowPerms {
			if wp.CanApprovePRs {
				violations = append(violations, Violation{
					Rule:     "workflows.deny_can_approve_prs",
					Severity: models.RiskMedium,
					Resource: fmt.Sprintf("Repo: %s", wp.RepoName),
					Message:  "GITHUB_TOKEN can approve pull request reviews",
				})
			}
		}
	}

	if p.Workflow.DenyUnpinnedActions {
		for _, wf := range report.WorkflowFiles {
			if len(wf.UnpinnedActions) > 0 {
				violations = append(violations, Violation{
					Rule:     "workflows.deny_unpinned_actions",
					Severity: models.RiskMedium,
					Resource: fmt.Sprintf("Workflow: %s/%s", wf.RepoName, wf.FileName),
					Message:  fmt.Sprintf("%d unpinned action(s): %s", len(wf.UnpinnedActions), truncateList(wf.UnpinnedActions, 3)),
				})
			}
		}
	}

	return violations
}

// ViolationsForPAT returns the rule IDs a single PAT trips, in declaration order.
// Used by the event log to tag each event with the policy state at that moment.
func (p *Policy) ViolationsForPAT(pat models.PATInfo, now time.Time) []string {
	if pat.TokenExpired {
		return nil
	}
	var rules []string
	if p.PAT.DenyNoExpiry && pat.TokenExpiresAt == nil {
		rules = append(rules, "pat.deny_no_expiry")
	}
	if p.PAT.MaxExpiryDays > 0 && pat.TokenExpiresAt != nil {
		maxExpiry := now.Add(time.Duration(p.PAT.MaxExpiryDays) * 24 * time.Hour)
		if pat.TokenExpiresAt.After(maxExpiry) {
			rules = append(rules, "pat.max_expiry_days")
		}
	}
	if p.PAT.DenyAllRepoAccess && pat.RepositorySelection == "all" {
		rules = append(rules, "pat.deny_all_repo_access")
	}
	if p.PAT.DenyAdminPermissions {
		for _, perm := range pat.Permissions {
			if perm.Level == "admin" {
				rules = append(rules, "pat.deny_admin_permissions")
				break
			}
		}
	}
	if p.PAT.MaxInactiveDays > 0 && pat.TokenLastUsedAt != nil {
		threshold := now.Add(-time.Duration(p.PAT.MaxInactiveDays) * 24 * time.Hour)
		if pat.TokenLastUsedAt.Before(threshold) {
			rules = append(rules, "pat.max_inactive_days")
		}
	}
	return rules
}

// ViolationsForSSOCredential returns the rule IDs a single SSO credential trips.
func (p *Policy) ViolationsForSSOCredential(cred models.SSOCredential) []string {
	var rules []string
	if p.SSO.DenyClassicPATs && cred.CredentialType == "personal access token" {
		rules = append(rules, "sso.deny_classic_pats")
	}
	return rules
}

func truncateList(items []string, max int) string {
	if len(items) <= max {
		result := ""
		for i, item := range items {
			if i > 0 {
				result += ", "
			}
			result += item
		}
		return result
	}
	result := ""
	for i := 0; i < max; i++ {
		if i > 0 {
			result += ", "
		}
		result += items[i]
	}
	return fmt.Sprintf("%s (+%d more)", result, len(items)-max)
}
