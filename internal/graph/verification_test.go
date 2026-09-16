package graph

import (
	"testing"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/verify"
)

func findNode(g *Graph, id string) *Node {
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			return &g.Nodes[i]
		}
	}
	return nil
}

// TestVerifiedPermissionTierOverridesNameHeuristic guards the actual fix this
// pass made: a secret whose NAME looks unremarkable but whose VERIFIED
// permissions are confirmed critical (e.g. AdministratorAccess) must be
// classified as critical/high, not left at whatever the name-based heuristic
// alone would have guessed. This is the integration point between the
// secret-verification pipeline and the attack-surface graph.
func TestVerifiedPermissionTierOverridesNameHeuristic(t *testing.T) {
	report := &models.OrgReport{
		Secrets: []models.OrgSecret{
			{
				Name: "SOME_UNREMARKABLE_TOKEN", Scope: "repo", RepoName: "svc",
				Verified: true, Valid: true, VerifyProvider: "aws", VerifyRecognized: true,
				VerifyPermissionTier:    verify.TierCritical,
				VerifyPermissionReasons: []string{"managed-policy:AdministratorAccess"},
			},
		},
	}
	g := Build(report)
	n := findNode(g, "secret:repo:SOME_UNREMARKABLE_TOKEN:svc:")
	if n == nil {
		t.Fatal("secret node not found")
	}
	if n.Risk != "high" {
		t.Errorf("Risk = %q, want high (confirmed-critical tier must win over name heuristic)", n.Risk)
	}
	if got, _ := n.Meta["criticality"].(string); got != "critical" {
		t.Errorf("criticality = %q, want critical", got)
	}
	if got, _ := n.Meta["verify_permission_tier"].(string); got != verify.TierCritical {
		t.Errorf("verify_permission_tier = %q, want %q", got, verify.TierCritical)
	}
}

// TestVerifiedInvalidSecretIgnoresTier: an invalid (dead) credential is no
// threat regardless of what tier it would have classified as — Valid=false
// must win over everything else.
func TestVerifiedInvalidSecretIgnoresTier(t *testing.T) {
	report := &models.OrgReport{
		Secrets: []models.OrgSecret{
			{
				Name: "AWS_ACCESS_KEY_ID", Scope: "repo", RepoName: "svc",
				Verified: true, Valid: false, VerifyProvider: "aws", VerifyRecognized: true,
			},
		},
	}
	g := Build(report)
	n := findNode(g, "secret:repo:AWS_ACCESS_KEY_ID:svc:")
	if n == nil {
		t.Fatal("secret node not found")
	}
	if n.Risk != "low" {
		t.Errorf("Risk = %q, want low (dead credential = no threat, regardless of name heuristic)", n.Risk)
	}
	if boundary, _ := n.Meta["boundary"].(bool); boundary {
		t.Error("boundary should be false for a confirmed-dead secret")
	}
}

// TestVerifyPermissionTierUnknownLeavesHeuristicAlone: "unknown" means we
// couldn't determine the credential's real scope — that must NOT downgrade
// (or upgrade) whatever the name-based heuristic already decided.
func TestVerifyPermissionTierUnknownLeavesHeuristicAlone(t *testing.T) {
	report := &models.OrgReport{
		Secrets: []models.OrgSecret{
			{
				// Name matches the aws_static heuristic (critical by name).
				Name: "AWS_ACCESS_KEY_ID_PROD", Scope: "repo", RepoName: "svc",
				Verified: true, Valid: true, VerifyProvider: "aws", VerifyRecognized: true,
				VerifyPermissionTier: verify.TierUnknown,
			},
		},
	}
	g := Build(report)
	n := findNode(g, "secret:repo:AWS_ACCESS_KEY_ID_PROD:svc:")
	if n == nil {
		t.Fatal("secret node not found")
	}
	if got, _ := n.Meta["criticality"].(string); got != "critical" {
		t.Errorf("criticality = %q, want critical (unknown tier must leave the name heuristic's verdict alone)", got)
	}
}

// TestSecretActionsSurfacesUnusedConfirmedDangerousSecret: this is the fix for
// the "unused-but-dangerous secret is invisible" gap. A secret with a
// CONFIRMED critical permission tier must be surfaced even when no
// currently-scanned workflow references it — unlike the pure name-heuristic
// case (see the next test), real evidence justifies flagging it regardless of
// reachability.
func TestSecretActionsSurfacesUnusedConfirmedDangerousSecret(t *testing.T) {
	report := &models.OrgReport{
		Secrets: []models.OrgSecret{
			{
				Name: "ORPHANED_ADMIN_KEY", Scope: "org", Visibility: "private",
				Verified: true, Valid: true, VerifyProvider: "aws", VerifyRecognized: true,
				VerifyPermissionTier:    verify.TierCritical,
				VerifyPermissionReasons: []string{"managed-policy:AdministratorAccess"},
			},
		},
		// No WorkflowFiles reference this secret at all.
	}
	g := Build(report)
	f := g.Findings()

	var found *ActionItem
	for i := range f.Actions {
		if f.Actions[i].Kind == "rotate_secret" && f.Actions[i].FocusID == "secret:org:ORPHANED_ADMIN_KEY::" {
			found = &f.Actions[i]
		}
	}
	if found == nil {
		t.Fatal("expected a rotate_secret finding for an unused-but-confirmed-critical secret")
	}
	if found.Severity != "critical" && found.Severity != "high" {
		t.Errorf("severity = %q, want critical/high", found.Severity)
	}
}

// TestFindingsVerifiedFlag: rotate_secret action items and boundary-secret
// attack paths must report Verified=true only when the underlying secret was
// actually tested against its live provider — this is what backs the
// dashboard's verified/unverified findings filter.
func TestFindingsVerifiedFlag(t *testing.T) {
	report := &models.OrgReport{
		Secrets: []models.OrgSecret{
			{
				// org-wide visibility=all forces this into the surfaced set
				// regardless of workflow reach, same as orgWide handling above.
				Name: "VERIFIED_SECRET", Scope: "org", Visibility: "all",
				Verified: true, Valid: true, VerifyProvider: "aws", VerifyRecognized: true,
				VerifyPermissionTier: verify.TierCritical,
			},
			{Name: "UNVERIFIED_SECRET", Scope: "org", Visibility: "all"},
		},
	}
	g := Build(report)
	f := g.Findings()

	var verifiedItem, unverifiedItem *ActionItem
	for i := range f.Actions {
		if f.Actions[i].Kind != "rotate_secret" {
			continue
		}
		switch f.Actions[i].FocusID {
		case "secret:org:VERIFIED_SECRET::":
			verifiedItem = &f.Actions[i]
		case "secret:org:UNVERIFIED_SECRET::":
			unverifiedItem = &f.Actions[i]
		}
	}
	if verifiedItem == nil || !verifiedItem.Verified {
		t.Errorf("expected VERIFIED_SECRET's rotate_secret item to have Verified=true, got %+v", verifiedItem)
	}
	if unverifiedItem == nil || unverifiedItem.Verified {
		t.Errorf("expected UNVERIFIED_SECRET's rotate_secret item to have Verified=false, got %+v", unverifiedItem)
	}
}

// TestUnrecognizedSecretIsNotTreatedAsDead is the regression guard for the
// bug found live against a real production GitHub org: 275 of 329 "verified" secrets had a
// value that didn't match ANY known credential format (an SSH key, a webhook
// URL, a plain config value like AWS_REGION, etc.) — the verify pipeline
// still reports Valid=false for these by convention, but that is NOT the
// same as a confirmed-dead credential. Before this fix, such secrets were
// silently downgraded to risk=low/boundary=false and dropped from findings
// entirely, exactly as if we'd proven them harmless — when in fact we never
// checked them at all.
func TestUnrecognizedSecretIsNotTreatedAsDead(t *testing.T) {
	report := &models.OrgReport{
		Secrets: []models.OrgSecret{
			{
				// Verified=true (pipeline ran), Valid=false (placeholder),
				// VerifyRecognized=false (the honest "we don't know" state) —
				// e.g. CI_SSH_KEY, which the verify pipeline can't check.
				Name: "CI_SSH_KEY", Scope: "org", Visibility: "all",
				Verified: true, Valid: false, VerifyProvider: "unknown", VerifyRecognized: false,
			},
		},
		WorkflowFiles: []models.WorkflowFile{
			{RepoName: "svc", FileName: "a.yml", SecretRefs: []string{"CI_SSH_KEY"}, Triggers: []string{"push"}},
			{RepoName: "svc2", FileName: "b.yml", SecretRefs: []string{"CI_SSH_KEY"}, Triggers: []string{"push"}},
		},
	}
	g := Build(report)
	n := findNode(g, "secret:org:CI_SSH_KEY::")
	if n == nil {
		t.Fatal("secret node not found")
	}
	// org-wide visibility=all is a heuristic-critical classification; an
	// unrecognized verify result must leave that alone, not downgrade it.
	if n.Risk == "low" {
		t.Errorf("Risk = %q, want NOT low — an unrecognized-format secret must not be treated as confirmed-dead", n.Risk)
	}
	if recognized, _ := n.Meta["verify_recognized"].(bool); recognized {
		t.Error("verify_recognized should be false in Meta")
	}

	f := g.Findings()
	var found *ActionItem
	for i := range f.Actions {
		if f.Actions[i].FocusID == "secret:org:CI_SSH_KEY::" && f.Actions[i].Kind == "rotate_secret" {
			found = &f.Actions[i]
		}
	}
	if found == nil {
		t.Fatal("expected an unrecognized secret with real workflow reach to still surface as a rotate_secret finding")
	}
	if found.Verified {
		t.Error("Verified should be false for an unrecognized-format secret — we never got a real answer")
	}
	if !found.Unrecognized {
		t.Error("Unrecognized should be true — this is the 'we tried but don't know' state, distinct from both verified and never-checked")
	}
}

// TestSecretActionsSkipsUnusedSecretWithoutConfirmedTier: regression guard —
// an unused secret with ONLY a name-based heuristic (no verification data)
// must NOT be surfaced. A name heuristic alone is too noisy to justify
// flagging every unreferenced secret in the org; only confirmed evidence
// should unlock that.
func TestSecretActionsSkipsUnusedSecretWithoutConfirmedTier(t *testing.T) {
	report := &models.OrgReport{
		Secrets: []models.OrgSecret{
			{Name: "SOME_UNUSED_SECRET", Scope: "org", Visibility: "private"},
		},
	}
	g := Build(report)
	f := g.Findings()

	for i := range f.Actions {
		if f.Actions[i].FocusID == "secret:org:SOME_UNUSED_SECRET::" {
			t.Errorf("unused secret with no verification evidence should not be surfaced, got %+v", f.Actions[i])
		}
	}
}
