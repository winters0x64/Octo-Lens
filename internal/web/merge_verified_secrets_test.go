package web

import (
	"testing"
	"time"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

func TestMergeVerifiedSecrets_CarriesForwardMatchingSecret(t *testing.T) {
	updatedAt := time.Date(2023, 6, 7, 12, 15, 5, 0, time.UTC)
	verifiedAt := time.Date(2026, 8, 31, 15, 25, 42, 0, time.UTC)

	prev := []models.OrgSecret{
		{
			Name: "AWS_ACCESS_KEY_ID_SANDBOX", Scope: "repo", RepoName: "flights",
			UpdatedAt: updatedAt, Verified: true, Valid: false, VerifyProvider: "aws",
			VerifiedAt: &verifiedAt,
		},
	}
	fresh := []models.OrgSecret{
		{
			Name: "AWS_ACCESS_KEY_ID_SANDBOX", Scope: "repo", RepoName: "flights",
			UpdatedAt: updatedAt, // unchanged since verification
		},
	}

	out := mergeVerifiedSecrets(prev, fresh)
	if !out[0].Verified || out[0].VerifyProvider != "aws" {
		t.Fatalf("expected verification carried forward, got %+v", out[0])
	}
	if out[0].VerifiedAt == nil || !out[0].VerifiedAt.Equal(verifiedAt) {
		t.Fatalf("expected VerifiedAt carried forward, got %+v", out[0].VerifiedAt)
	}
}

// TestMergeVerifiedSecrets_CarriesForwardPermissionTier guards against the
// exact bug found live: this function copies verification fields by name, so
// adding a new field to models.OrgSecret (VerifyPermissionTier /
// VerifyPermissionReasons) without also adding it here silently drops it on
// every rescan — reverting a confirmed-critical finding back to a
// name-heuristic guess with no error or warning anywhere.
func TestMergeVerifiedSecrets_CarriesForwardPermissionTier(t *testing.T) {
	updatedAt := time.Date(2024, 5, 30, 11, 52, 55, 0, time.UTC)
	prev := []models.OrgSecret{
		{
			Name: "AWS_ACCESS_KEY_ID", Scope: "org",
			UpdatedAt: updatedAt, Verified: true, Valid: true, VerifyProvider: "aws",
			VerifyPermissionTier:    "critical",
			VerifyPermissionReasons: []string{"managed-policy:AdministratorAccess"},
		},
	}
	fresh := []models.OrgSecret{
		{Name: "AWS_ACCESS_KEY_ID", Scope: "org", UpdatedAt: updatedAt},
	}

	out := mergeVerifiedSecrets(prev, fresh)
	if out[0].VerifyPermissionTier != "critical" {
		t.Fatalf("expected VerifyPermissionTier carried forward, got %+v", out[0])
	}
	if len(out[0].VerifyPermissionReasons) != 1 || out[0].VerifyPermissionReasons[0] != "managed-policy:AdministratorAccess" {
		t.Fatalf("expected VerifyPermissionReasons carried forward, got %+v", out[0].VerifyPermissionReasons)
	}
}

// TestMergeVerifiedSecrets_CarriesForwardRecognized guards the same
// silently-dropped-field bug for VerifyRecognized specifically: since it
// defaults to false, forgetting to carry it forward would make an already
// unrecognized-format secret STAY correctly unrecognized (masking the bug),
// but would silently turn a genuinely recognized+verified secret back into
// "unrecognized" on every rescan — undoing the confirmed-critical answer for
// no reason.
func TestMergeVerifiedSecrets_CarriesForwardRecognized(t *testing.T) {
	updatedAt := time.Date(2024, 5, 30, 11, 52, 55, 0, time.UTC)
	prev := []models.OrgSecret{
		{
			Name: "AWS_ACCESS_KEY_ID", Scope: "org",
			UpdatedAt: updatedAt, Verified: true, Valid: true, VerifyProvider: "aws",
			VerifyRecognized: true,
		},
	}
	fresh := []models.OrgSecret{
		{Name: "AWS_ACCESS_KEY_ID", Scope: "org", UpdatedAt: updatedAt},
	}

	out := mergeVerifiedSecrets(prev, fresh)
	if !out[0].VerifyRecognized {
		t.Fatalf("expected VerifyRecognized carried forward, got %+v", out[0])
	}
}

func TestMergeVerifiedSecrets_DropsVerificationOnRotation(t *testing.T) {
	prev := []models.OrgSecret{
		{
			Name: "OPENAI_API_KEY", Scope: "repo", RepoName: "api-connect",
			UpdatedAt: time.Date(2025, 2, 20, 9, 23, 44, 0, time.UTC),
			Verified:  true, Valid: true, VerifyProvider: "openai",
		},
	}
	fresh := []models.OrgSecret{
		{
			Name: "OPENAI_API_KEY", Scope: "repo", RepoName: "api-connect",
			// UpdatedAt has moved — the secret's value was rotated since it was verified.
			UpdatedAt: time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC),
		},
	}

	out := mergeVerifiedSecrets(prev, fresh)
	if out[0].Verified {
		t.Fatalf("expected verification NOT carried forward after rotation, got %+v", out[0])
	}
}

func TestMergeVerifiedSecrets_NoPreviousReport(t *testing.T) {
	fresh := []models.OrgSecret{
		{Name: "ARGUS_SLACK_BOT", Scope: "repo", RepoName: "argus"},
	}
	out := mergeVerifiedSecrets(nil, fresh)
	if len(out) != 1 || out[0].Verified {
		t.Fatalf("expected fresh secrets unchanged when there's no previous report, got %+v", out)
	}
}

func TestMergeVerifiedSecrets_IgnoresUnverifiedPreviousEntries(t *testing.T) {
	prev := []models.OrgSecret{
		{Name: "KNOWN_HOSTS", Scope: "repo", RepoName: "api-connect", Verified: false},
	}
	fresh := []models.OrgSecret{
		{Name: "KNOWN_HOSTS", Scope: "repo", RepoName: "api-connect"},
	}
	out := mergeVerifiedSecrets(prev, fresh)
	if out[0].Verified {
		t.Fatalf("expected no-op merge for a never-verified previous entry, got %+v", out[0])
	}
}
