package verify

import "strings"

// PermissionTier is a normalized risk tier for what a verified credential can
// actually do, derived from provider-specific permission data (IAM policies,
// OAuth scopes, ...). "unknown" means the credential's permission scope
// couldn't be determined at all — that's a distinct, honest state from
// "low", which means we checked and found nothing dangerous.
const (
	TierCritical = "critical"
	TierHigh     = "high"
	TierMedium   = "medium"
	TierLow      = "low"
	TierUnknown  = "unknown"
)

// ClassifyPermissionTier turns a verified credential's raw permissions/notes
// into a normalized tier + human-readable reasons, so the attack-surface
// graph has a real signal to rank risk by instead of guessing from the
// secret's name. Only called for credentials already confirmed Valid.
func ClassifyPermissionTier(provider string, permissions, notes []string) (tier string, reasons []string) {
	switch provider {
	case "aws":
		return classifyAWS(permissions, notes)
	case "github":
		return classifyGitHubScopes(permissions)
	case "slack":
		return classifySlackScopes(permissions)
	case "anthropic", "openai", "gemini", "stripe", "npm", "sonarcloud":
		// These providers don't expose a fine-grained permission model through
		// any endpoint we call — a valid key is simply "has API/account access
		// of some kind" (spend, data, or account-takeover risk depending on the
		// provider), which is a real but coarse signal. Default to medium
		// rather than unknown, since we DO know the credential is live and
		// usable, just not its exact scope.
		return TierMedium, []string{"live " + provider + " credential — provider doesn't expose scope detail via this check"}
	default:
		return TierUnknown, nil
	}
}

// classifyAWS: any note at all means the simulate/document/known-name checks
// (see workflow.go) found something genuinely dangerous — treat all of them
// as critical for now rather than trying to finely rank iam:PassRole vs.
// AdministratorAccess; a security tool should err toward over-flagging here.
func classifyAWS(permissions, notes []string) (string, []string) {
	if len(notes) > 0 {
		return TierCritical, notes
	}
	if len(permissions) > 0 {
		return TierLow, []string{"checked attached policies — no wildcard or dangerous grants found"}
	}
	return TierUnknown, []string{"could not determine attached policies (no IAM read access on this credential, or its ARN isn't a user)"}
}

var githubCriticalScopes = map[string]bool{
	"admin:org": true, "admin:org_hook": true, "admin:enterprise": true,
	"delete_repo": true, "admin:gpg_key": true, "admin:ssh_signing_key": true,
}

var githubHighScopes = map[string]bool{
	"repo": true, "workflow": true, "admin:repo_hook": true,
	"admin:public_key": true, "delete:packages": true, "write:packages": true,
}

func classifyGitHubScopes(scopes []string) (string, []string) {
	trimmed := make([]string, len(scopes))
	for i, s := range scopes {
		trimmed[i] = strings.TrimSpace(s)
	}
	for _, s := range trimmed {
		if githubCriticalScopes[s] {
			return TierCritical, []string{"scope:" + s}
		}
	}
	for _, s := range trimmed {
		if githubHighScopes[s] {
			return TierHigh, []string{"scope:" + s}
		}
	}
	if len(trimmed) > 0 {
		return TierMedium, []string{"has scopes, none in the known-dangerous list: " + strings.Join(trimmed, ", ")}
	}
	// Fine-grained PATs never report scopes via this check at all (there's no
	// simple API to introspect a fine-grained PAT's own permissions), so an
	// empty list here is expected, not evidence of a narrow token.
	return TierUnknown, []string{"no scopes reported — likely a fine-grained PAT, whose permissions aren't introspectable this way"}
}

func classifySlackScopes(scopes []string) (string, []string) {
	if len(scopes) == 0 {
		// Expected for most modern (granular-scope) bot tokens — Slack simply
		// doesn't expose scopes for these via any lightweight check.
		return TierUnknown, []string{"no scopes reported — expected for granular-scope bot tokens, Slack doesn't expose these via auth.test"}
	}
	critical := map[string]bool{"admin": true, "admin.users:write": true, "admin.conversations:write": true}
	high := map[string]bool{"chat:write": true, "files:write": true, "channels:manage": true, "users:read": true}
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if critical[s] {
			return TierCritical, []string{"scope:" + s}
		}
	}
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if high[s] {
			return TierHigh, []string{"scope:" + s}
		}
	}
	return TierMedium, []string{"has scopes, none in the known-dangerous list: " + strings.Join(scopes, ", ")}
}
