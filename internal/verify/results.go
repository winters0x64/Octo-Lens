package verify

// SecretVerification is the result of verifying one secret in-place.
type SecretVerification struct {
	Name        string `json:"name"`
	Repo        string `json:"repo"`
	Scope       string `json:"scope"`                 // repo | org | environment
	Environment string `json:"environment,omitempty"` // set when Scope == "environment"
	Provider    string `json:"provider"`              // aws | github | anthropic | openai | stripe | slack | gemini | npm | sonarcloud | unknown
	Valid       bool   `json:"valid"`
	Error       string `json:"error,omitempty"`

	// Recognized is true when the secret's live value matched a known
	// credential format (so Valid reflects an actual answer from the
	// provider — live or dead). It is false when the value didn't match any
	// pattern we check for at all: Valid is still reported as false in that
	// case for backward compatibility, but that's NOT the same thing as a
	// confirmed-dead credential — it just means we don't have a checker for
	// this format. Downstream code must not treat Recognized=false the same
	// as a confirmed-invalid secret (e.g. an SSH key or webhook URL we don't
	// pattern-match could easily still be live and dangerous).
	Recognized bool `json:"recognized"`

	// Provider-specific identity / attack surface (populated only when valid).
	Identity    string   `json:"identity,omitempty"`    // e.g. ARN, user login, bot name
	Permissions []string `json:"permissions,omitempty"` // attached policies, OAuth scopes, etc.
	ExpiresAt   string   `json:"expires_at,omitempty"`
	LastUsed    string   `json:"last_used,omitempty"`

	// PermissionNotes carries structured, provider-specific signals about what
	// the credential can actually DO, beyond just the raw policy/scope names in
	// Permissions — e.g. for AWS, "simulate:iam:CreateUser=allowed" or
	// "wildcard-policy:AdministratorAccess", produced by actually evaluating
	// the credential's effective permissions (IAM policy simulation, or a
	// fallback scan of the policy documents themselves), not just listing
	// policy names. Classify() in internal/verify turns these into a
	// PermissionTier. Empty when the credential's actual permission scope
	// couldn't be determined (e.g. the credential itself lacks IAM read
	// access on itself) — that's a real "unknown", not a "low".
	PermissionNotes []string `json:"permission_notes,omitempty"`
}

// RepoVerifyResult is the full verification output for one repo run.
type RepoVerifyResult struct {
	Repo    string               `json:"repo"`
	RunID   int64                `json:"run_id"`
	Status  string               `json:"status"` // success | failure | skipped
	Secrets []SecretVerification `json:"secrets"`
}
