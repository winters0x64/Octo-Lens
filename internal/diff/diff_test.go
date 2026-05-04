package diff

import (
	"testing"
	"time"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/policy"
)

func ptrTime(t time.Time) *time.Time { return &t }

func TestPATs_NewPATEmitsCreatedEvent(t *testing.T) {
	now := time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC)
	scan := []models.PATInfo{{
		ID:                  100,
		TokenName:           "ci-deploy",
		OwnerLogin:          "alice",
		RepositorySelection: "selected",
		Permissions:         []models.Permission{{Name: "contents", Level: "read", Risk: models.RiskLow}},
		AccessGrantedAt:     now.Add(-24 * time.Hour),
	}}
	results := PATs(map[int64]ExistingPAT{}, scan, policy.Default(), now)

	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Op != OpInsert {
		t.Errorf("op = %v, want OpInsert", r.Op)
	}
	if r.NewStatus != PATStatusActive {
		t.Errorf("status = %q, want active", r.NewStatus)
	}
	if r.Event == nil || r.Event.Kind != EventKindCreated {
		t.Errorf("event = %+v, want kind=created", r.Event)
	}
}

func TestPATs_DisappearedPATIsRemoved(t *testing.T) {
	now := time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC)
	last := models.PATInfo{
		ID: 100, TokenName: "ci-deploy", OwnerLogin: "alice",
		RepositorySelection: "selected",
		Permissions:         []models.Permission{{Name: "contents", Level: "read"}},
	}
	existing := map[int64]ExistingPAT{
		100: {
			Status:              PATStatusActive,
			Permissions:         last.Permissions,
			RepositorySelection: last.RepositorySelection,
			LastKnown:           last,
		},
	}
	results := PATs(existing, nil, policy.Default(), now)

	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Op != OpMarkRemoved {
		t.Errorf("op = %v, want OpMarkRemoved", r.Op)
	}
	if r.Event == nil || r.Event.Kind != EventKindRemoved {
		t.Errorf("event = %+v, want kind=removed", r.Event)
	}
	if r.Event.OldStatus != PATStatusActive || r.Event.NewStatus != PATStatusRemoved {
		t.Errorf("status transition = %q→%q, want active→removed", r.Event.OldStatus, r.Event.NewStatus)
	}
}

func TestPATs_StatusFlipFromActiveToExpired(t *testing.T) {
	now := time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC)
	p := models.PATInfo{
		ID: 100, TokenName: "ci-deploy", OwnerLogin: "alice",
		RepositorySelection: "selected",
		Permissions:         []models.Permission{{Name: "contents", Level: "read"}},
		TokenExpired:        true,
	}
	existing := map[int64]ExistingPAT{
		100: {
			Status:              PATStatusActive,
			Permissions:         p.Permissions,
			RepositorySelection: p.RepositorySelection,
			LastKnown:           p,
		},
	}
	results := PATs(existing, []models.PATInfo{p}, policy.Default(), now)

	if len(results) != 1 || results[0].Op != OpUpdate {
		t.Fatalf("op = %v, want OpUpdate", results[0].Op)
	}
	ev := results[0].Event
	if ev == nil || ev.Kind != EventKindStatusChange {
		t.Fatalf("event kind = %+v, want status_change", ev)
	}
	if ev.OldStatus != PATStatusActive || ev.NewStatus != PATStatusExpired {
		t.Errorf("transition = %q→%q", ev.OldStatus, ev.NewStatus)
	}
}

func TestPATs_PermissionAdditionEmitsFieldChange(t *testing.T) {
	now := time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC)
	old := []models.Permission{{Name: "contents", Level: "read"}}
	updated := []models.Permission{
		{Name: "contents", Level: "read"},
		{Name: "actions", Level: "write"},
	}
	p := models.PATInfo{
		ID: 100, TokenName: "ci", OwnerLogin: "alice",
		RepositorySelection: "selected",
		Permissions:         updated,
	}
	existing := map[int64]ExistingPAT{
		100: {
			Status:              PATStatusActive,
			Permissions:         old,
			RepositorySelection: p.RepositorySelection,
			LastKnown:           p,
		},
	}
	results := PATs(existing, []models.PATInfo{p}, policy.Default(), now)

	if results[0].Op != OpUpdate {
		t.Fatalf("op = %v, want OpUpdate", results[0].Op)
	}
	ev := results[0].Event
	if ev.Kind != EventKindFieldChange {
		t.Errorf("event kind = %q, want field_change", ev.Kind)
	}
	if !sliceContains(ev.ChangedFields, "permissions") {
		t.Errorf("changed_fields = %v, want to contain permissions", ev.ChangedFields)
	}
}

func TestPATs_NoChangeProducesTouchOnly(t *testing.T) {
	now := time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC)
	perms := []models.Permission{{Name: "contents", Level: "read"}}
	p := models.PATInfo{
		ID: 100, TokenName: "ci", OwnerLogin: "alice",
		RepositorySelection: "selected",
		Permissions:         perms,
	}
	existing := map[int64]ExistingPAT{
		100: {
			Status:              PATStatusActive,
			Permissions:         perms,
			RepositorySelection: p.RepositorySelection,
			LastKnown:           p,
		},
	}
	results := PATs(existing, []models.PATInfo{p}, policy.Default(), now)

	if results[0].Op != OpTouch {
		t.Errorf("op = %v, want OpTouch", results[0].Op)
	}
	if results[0].Event != nil {
		t.Errorf("event = %+v, want nil", results[0].Event)
	}
}

func TestPATs_NewPATWithAdminPermissionTagsViolation(t *testing.T) {
	now := time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC)
	scan := []models.PATInfo{{
		ID: 100, TokenName: "admin-tool", OwnerLogin: "alice",
		RepositorySelection: "all",
		Permissions:         []models.Permission{{Name: "administration", Level: "admin"}},
		TokenExpiresAt:      ptrTime(now.Add(30 * 24 * time.Hour)),
	}}
	results := PATs(map[int64]ExistingPAT{}, scan, policy.Default(), now)
	ev := results[0].Event
	if !sliceContains(ev.PolicyViolations, "pat.deny_admin_permissions") {
		t.Errorf("expected pat.deny_admin_permissions in violations, got %v", ev.PolicyViolations)
	}
	if !sliceContains(ev.PolicyViolations, "pat.deny_all_repo_access") {
		t.Errorf("expected pat.deny_all_repo_access in violations, got %v", ev.PolicyViolations)
	}
}

func TestSSOCredentials_StatusFlipsOnExpiry(t *testing.T) {
	now := time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC)
	expired := now.Add(-1 * time.Hour)
	c := models.SSOCredential{
		CredentialID:              42,
		Login:                     "alice",
		CredentialType:            "personal access token",
		Scopes:                    []string{"repo"},
		AuthorizedCredentialExpAt: &expired,
	}
	existing := map[int64]ExistingSSOCredential{
		42: {
			Status:                    SSOStatusActive,
			Scopes:                    c.Scopes,
			AuthorizedCredentialExpAt: c.AuthorizedCredentialExpAt,
			LastKnown:                 c,
		},
	}
	results := SSOCredentials(existing, []models.SSOCredential{c}, policy.Default(), now)
	if results[0].Op != OpUpdate {
		t.Fatalf("op = %v, want OpUpdate", results[0].Op)
	}
	ev := results[0].Event
	if ev.NewStatus != SSOStatusExpired {
		t.Errorf("new_status = %q, want expired", ev.NewStatus)
	}
}

func TestPATRequests_RemovedFromPendingResolvesAndLooksUpPATID(t *testing.T) {
	now := time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC)
	last := models.PATRequest{
		ID:                  500,
		TokenName:           "ci-deploy",
		OwnerLogin:          "alice",
		RepositorySelection: "selected",
		Permissions:         []models.Permission{{Name: "contents", Level: "read"}},
	}
	existing := map[int64]ExistingPATRequest{
		500: {
			Status:              PATRequestStatusPending,
			Permissions:         last.Permissions,
			RepositorySelection: last.RepositorySelection,
			LastKnown:           last,
		},
	}
	lookup := func(owner, name string) int64 {
		if owner == "alice" && name == "ci-deploy" {
			return 999
		}
		return 0
	}
	results := PATRequests(existing, nil, lookup, now)
	if len(results) != 1 {
		t.Fatalf("want 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Op != OpMarkRemoved {
		t.Errorf("op = %v, want OpMarkRemoved", r.Op)
	}
	if r.NewStatus != PATRequestStatusResolved {
		t.Errorf("status = %q, want resolved", r.NewStatus)
	}
	if r.ResolvedPATID == nil || *r.ResolvedPATID != 999 {
		t.Errorf("resolved_pat_id = %v, want 999", r.ResolvedPATID)
	}
}

func sliceContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
