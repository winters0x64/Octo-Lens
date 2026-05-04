package github

import (
	"fmt"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// RunComplianceChecks analyzes the scan report to infer org security posture.
func RunComplianceChecks(org string, report *models.OrgReport) []models.ComplianceCheck {
	baseURL := fmt.Sprintf("https://github.com/organizations/%s/settings", org)
	checks := []models.ComplianceCheck{}

	// Check 1: Are classic PATs blocked?
	classicPATCheck := models.ComplianceCheck{
		ID:          "classic_pats_blocked",
		Name:        "Classic PATs Restricted",
		Description: "Classic personal access tokens should be blocked to force fine-grained PATs with org approval.",
		FixURL:      baseURL + "/personal-access-tokens-onboarding",
	}

	if report.Summary.SSOClassicPATs > 0 {
		classicPATCheck.Status = "fail"
		classicPATCheck.Detail = fmt.Sprintf("%d classic PATs found authorized via SSO. Classic PATs may not be restricted.", report.Summary.SSOClassicPATs)
	} else if report.Summary.SSOCredentials > 0 {
		// SSO is active but no classic PATs — good sign
		classicPATCheck.Status = "pass"
		classicPATCheck.Detail = "No classic PATs detected via SSO. Policy may be enforced."
	} else {
		classicPATCheck.Status = "unknown"
		classicPATCheck.Detail = "Cannot verify — SSO not enabled or no credential data. Check org settings manually."
	}
	checks = append(checks, classicPATCheck)

	// Check 2: Fine-grained PAT approval required?
	approvalCheck := models.ComplianceCheck{
		ID:          "pat_approval_required",
		Name:        "Fine-Grained PAT Approval Required",
		Description: "Fine-grained PATs should require admin approval before accessing org resources.",
		FixURL:      baseURL + "/personal-access-tokens-onboarding",
	}

	if report.Summary.PendingRequests > 0 {
		// Pending requests exist — approval flow is active
		approvalCheck.Status = "pass"
		approvalCheck.Detail = fmt.Sprintf("%d pending requests awaiting approval. Approval flow is active.", report.Summary.PendingRequests)
	} else if report.Summary.TotalPATs > 0 {
		// PATs exist but no pending — could be auto-approve or all approved
		approvalCheck.Status = "unknown"
		approvalCheck.Detail = fmt.Sprintf("%d approved PATs, 0 pending. Approval may be required (all approved) or auto-approve may be enabled. Verify in settings.", report.Summary.TotalPATs)
	} else {
		approvalCheck.Status = "unknown"
		approvalCheck.Detail = "No PATs detected. Cannot determine if approval is required."
	}
	checks = append(checks, approvalCheck)

	// Check 3: SAML SSO enabled?
	ssoCheck := models.ComplianceCheck{
		ID:          "saml_sso_enabled",
		Name:        "SAML SSO Enabled",
		Description: "SAML SSO provides visibility into classic PATs and SSH keys authorized for your org.",
		FixURL:      baseURL + "/security",
	}

	if report.Summary.SSOCredentials > 0 {
		ssoCheck.Status = "pass"
		ssoCheck.Detail = fmt.Sprintf("SSO is active. %d authorized credentials visible (%d classic PATs, %d SSH keys).",
			report.Summary.SSOCredentials, report.Summary.SSOClassicPATs, report.Summary.SSOSSHKeys)
	} else {
		ssoCheck.Status = "warn"
		ssoCheck.Detail = "SSO not detected or no authorized credentials. Without SSO, classic PATs are invisible."
	}
	checks = append(checks, ssoCheck)

	// Check 4: GITHUB_TOKEN default permissions
	tokenPermCheck := models.ComplianceCheck{
		ID:          "github_token_least_privilege",
		Name:        "GITHUB_TOKEN Least Privilege",
		Description: "Repositories should use read-only as the default GITHUB_TOKEN permission.",
		FixURL:      baseURL + "/actions",
	}

	if report.Summary.WriteAllWorkflows > 0 {
		tokenPermCheck.Status = "fail"
		tokenPermCheck.Detail = fmt.Sprintf("%d repositories have GITHUB_TOKEN default set to write-all.", report.Summary.WriteAllWorkflows)
	} else if report.Summary.TotalReposScanned > 0 {
		tokenPermCheck.Status = "pass"
		tokenPermCheck.Detail = fmt.Sprintf("All %d scanned repositories use read-only default.", report.Summary.TotalReposScanned)
	} else {
		tokenPermCheck.Status = "unknown"
		tokenPermCheck.Detail = "No repositories scanned."
	}
	checks = append(checks, tokenPermCheck)

	// Check 5: Deploy keys with write access
	deployKeyCheck := models.ComplianceCheck{
		ID:          "deploy_keys_read_only",
		Name:        "Deploy Keys Read-Only",
		Description: "Deploy keys should be read-only unless write access is explicitly required.",
		FixURL:      baseURL,
	}

	if report.Summary.WriteDeployKeys > 0 {
		deployKeyCheck.Status = "fail"
		deployKeyCheck.Detail = fmt.Sprintf("%d deploy keys have write (push) access.", report.Summary.WriteDeployKeys)
	} else if report.Summary.TotalDeployKeys > 0 {
		deployKeyCheck.Status = "pass"
		deployKeyCheck.Detail = fmt.Sprintf("All %d deploy keys are read-only.", report.Summary.TotalDeployKeys)
	} else {
		deployKeyCheck.Status = "pass"
		deployKeyCheck.Detail = "No deploy keys found."
	}
	checks = append(checks, deployKeyCheck)

	// Check 6: Org-wide secrets
	secretCheck := models.ComplianceCheck{
		ID:          "secrets_scoped",
		Name:        "Secrets Properly Scoped",
		Description: "Organization secrets should not be visible to all repositories.",
		FixURL:      baseURL + "/secrets",
	}

	if report.Summary.OrgWideSecrets > 0 {
		secretCheck.Status = "fail"
		secretCheck.Detail = fmt.Sprintf("%d org secrets are visible to ALL repositories.", report.Summary.OrgWideSecrets)
	} else if report.Summary.OrgSecrets > 0 {
		secretCheck.Status = "pass"
		secretCheck.Detail = fmt.Sprintf("All %d org secrets are properly scoped.", report.Summary.OrgSecrets)
	} else {
		secretCheck.Status = "pass"
		secretCheck.Detail = "No org-level secrets found."
	}
	checks = append(checks, secretCheck)

	// Check 7: Actions pinning
	pinningCheck := models.ComplianceCheck{
		ID:          "actions_pinned",
		Name:        "GitHub Actions SHA-Pinned",
		Description: "Actions should reference commits by SHA, not mutable tags, to prevent supply chain attacks.",
		FixURL:      baseURL,
	}

	if report.Summary.UnpinnedActionRepos > 0 {
		pinningCheck.Status = "fail"
		pinningCheck.Detail = fmt.Sprintf("%d repositories have workflows using unpinned (tag-based) action references.", report.Summary.UnpinnedActionRepos)
	} else if len(report.WorkflowFiles) > 0 {
		pinningCheck.Status = "pass"
		pinningCheck.Detail = "All workflow action references are SHA-pinned."
	} else {
		pinningCheck.Status = "pass"
		pinningCheck.Detail = "No workflow files found."
	}
	checks = append(checks, pinningCheck)

	// Check 8: PAT expiry policy
	expiryCheck := models.ComplianceCheck{
		ID:          "pat_expiry_enforced",
		Name:        "PAT Expiry Enforced",
		Description: "All PATs should have an expiration date to limit credential lifetime.",
		FixURL:      baseURL + "/personal-access-tokens-onboarding",
	}

	noExpiryCount := 0
	for _, pat := range report.PATs {
		if pat.TokenExpiresAt == nil && !pat.TokenExpired {
			noExpiryCount++
		}
	}

	if noExpiryCount > 0 {
		expiryCheck.Status = "fail"
		expiryCheck.Detail = fmt.Sprintf("%d active PATs have no expiration date.", noExpiryCount)
	} else if report.Summary.TotalPATs > 0 {
		expiryCheck.Status = "pass"
		expiryCheck.Detail = fmt.Sprintf("All %d PATs have expiration dates set.", report.Summary.ActivePATs)
	} else {
		expiryCheck.Status = "pass"
		expiryCheck.Detail = "No PATs found."
	}
	checks = append(checks, expiryCheck)

	return checks
}
