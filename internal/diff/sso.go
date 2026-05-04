package diff

import (
	"time"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/policy"
)

type ExistingSSOCredential struct {
	Status                    string
	Scopes                    []string
	AuthorizedCredentialExpAt *time.Time
	LastKnown                 models.SSOCredential
}

type SSOResult struct {
	Credential models.SSOCredential
	NewStatus  string
	Op         Op
	Event      *Event
}

// SSOCredentials diffs SSO credentials. Status flips:
//   - active → expired when authorized_credential_expires_at passes 'now'
//   - any → removed when missing from a successful scan
func SSOCredentials(
	existing map[int64]ExistingSSOCredential,
	scan []models.SSOCredential,
	pol *policy.Policy,
	now time.Time,
) []SSOResult {
	results := make([]SSOResult, 0, len(scan)+len(existing))
	seen := make(map[int64]bool, len(scan))

	for _, c := range scan {
		seen[c.CredentialID] = true
		newStatus := ssoStatus(c, now)
		ex, inDB := existing[c.CredentialID]

		if !inDB {
			results = append(results, SSOResult{
				Credential: c,
				NewStatus:  newStatus,
				Op:         OpInsert,
				Event: &Event{
					Kind:             EventKindCreated,
					NewStatus:        newStatus,
					Snapshot:         c,
					PolicyViolations: violationsForSSO(pol, c),
				},
			})
			continue
		}

		changed := changedFieldsSSO(ex, c)
		statusChanged := ex.Status != newStatus

		switch {
		case statusChanged:
			results = append(results, SSOResult{
				Credential: c,
				NewStatus:  newStatus,
				Op:         OpUpdate,
				Event: &Event{
					Kind:             EventKindStatusChange,
					OldStatus:        ex.Status,
					NewStatus:        newStatus,
					ChangedFields:    changed,
					Snapshot:         c,
					PolicyViolations: violationsForSSO(pol, c),
				},
			})
		case len(changed) > 0:
			results = append(results, SSOResult{
				Credential: c,
				NewStatus:  newStatus,
				Op:         OpUpdate,
				Event: &Event{
					Kind:             EventKindFieldChange,
					ChangedFields:    changed,
					Snapshot:         c,
					PolicyViolations: violationsForSSO(pol, c),
				},
			})
		default:
			results = append(results, SSOResult{
				Credential: c,
				NewStatus:  newStatus,
				Op:         OpTouch,
			})
		}
	}

	for id, ex := range existing {
		if seen[id] {
			continue
		}
		results = append(results, SSOResult{
			Credential: ex.LastKnown,
			NewStatus:  SSOStatusRemoved,
			Op:         OpMarkRemoved,
			Event: &Event{
				Kind:      EventKindRemoved,
				OldStatus: ex.Status,
				NewStatus: SSOStatusRemoved,
				Snapshot:  ex.LastKnown,
			},
		})
	}

	return results
}

func ssoStatus(c models.SSOCredential, now time.Time) string {
	if c.AuthorizedCredentialExpAt != nil && c.AuthorizedCredentialExpAt.Before(now) {
		return SSOStatusExpired
	}
	return SSOStatusActive
}

func changedFieldsSSO(ex ExistingSSOCredential, c models.SSOCredential) []string {
	var changed []string
	if !stringSliceEqual(ex.Scopes, c.Scopes) {
		changed = append(changed, "scopes")
	}
	if !timesEqual(ex.AuthorizedCredentialExpAt, c.AuthorizedCredentialExpAt) {
		changed = append(changed, "authorized_credential_expires_at")
	}
	return changed
}

func violationsForSSO(pol *policy.Policy, c models.SSOCredential) []string {
	if pol == nil {
		return nil
	}
	return pol.ViolationsForSSOCredential(c)
}

const (
	SSOStatusActive  = "active"
	SSOStatusExpired = "expired"
	SSOStatusRemoved = "removed"
)
