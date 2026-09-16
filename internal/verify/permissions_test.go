package verify

import "testing"

func TestClassifyPermissionTier_AWS(t *testing.T) {
	tests := []struct {
		name        string
		permissions []string
		notes       []string
		wantTier    string
	}{
		{"admin managed policy", []string{"AdministratorAccess"}, []string{"managed-policy:AdministratorAccess"}, TierCritical},
		{"wildcard custom policy", []string{"custom-danger"}, []string{"wildcard-policy:custom-danger"}, TierCritical},
		{"simulate found dangerous action", []string{"ReadOnlyAccess"}, []string{"simulate:iam:CreateUser=allowed"}, TierCritical},
		{"clean, checked, nothing dangerous", []string{"ReadOnlyAccess"}, nil, TierLow},
		{"could not determine at all", nil, nil, TierUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tier, _ := ClassifyPermissionTier("aws", tt.permissions, tt.notes)
			if tier != tt.wantTier {
				t.Errorf("got tier %q, want %q", tier, tt.wantTier)
			}
		})
	}
}

func TestClassifyPermissionTier_GitHub(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		wantTier string
	}{
		{"admin:org is critical", []string{"admin:org"}, TierCritical},
		{"repo is high", []string{"repo"}, TierHigh},
		{"workflow is high", []string{"public_repo", "workflow"}, TierHigh},
		{"unrecognized scope is medium", []string{"read:user"}, TierMedium},
		{"no scopes reported is unknown (fine-grained PAT)", nil, TierUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tier, _ := ClassifyPermissionTier("github", tt.scopes, nil)
			if tier != tt.wantTier {
				t.Errorf("got tier %q, want %q", tier, tt.wantTier)
			}
		})
	}
}

func TestClassifyPermissionTier_Slack(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		wantTier string
	}{
		{"admin scope is critical", []string{"admin"}, TierCritical},
		{"chat:write is high", []string{"chat:write"}, TierHigh},
		{"unrecognized scope is medium", []string{"channels:read"}, TierMedium},
		{"no scopes is unknown (granular token)", nil, TierUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tier, _ := ClassifyPermissionTier("slack", tt.scopes, nil)
			if tier != tt.wantTier {
				t.Errorf("got tier %q, want %q", tier, tt.wantTier)
			}
		})
	}
}

func TestClassifyPermissionTier_UnscopedProviders(t *testing.T) {
	tier, reasons := ClassifyPermissionTier("openai", nil, nil)
	if tier != TierMedium {
		t.Errorf("got tier %q, want %q", tier, TierMedium)
	}
	if len(reasons) == 0 {
		t.Error("expected a reason explaining the coarse default")
	}
}

func TestClassifyPermissionTier_UnknownProvider(t *testing.T) {
	tier, _ := ClassifyPermissionTier("some-future-provider", []string{"whatever"}, nil)
	if tier != TierUnknown {
		t.Errorf("got tier %q, want %q", tier, TierUnknown)
	}
}
