package diff

import (
	"time"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/policy"
)

// ExistingPAT is the minimal current-state info the PAT diff needs from DB.
// Other persisted fields (token_name, owner, etc.) ride along on the
// scanned PATInfo since the scan is authoritative for live entities.
type ExistingPAT struct {
	Status              string
	Permissions         []models.Permission
	RepositorySelection string
	TokenExpiresAt      *time.Time
	// LastKnown is the snapshot to emit on a 'removed' event when the
	// entity disappears from the scan — the scanned row is no longer available.
	LastKnown models.PATInfo
}

// PATResult is one outcome from PATs(): how to persist + whether to log.
type PATResult struct {
	PAT       models.PATInfo
	NewStatus string
	Op        Op
	Event     *Event // nil for OpTouch
}

// PATs runs the diff for fine-grained PATs. Caller must only invoke this
// when the PATs phase completed successfully — otherwise removed-detection
// would be a false positive.
func PATs(
	existing map[int64]ExistingPAT,
	scan []models.PATInfo,
	pol *policy.Policy,
	now time.Time,
) []PATResult {
	results := make([]PATResult, 0, len(scan)+len(existing))
	seen := make(map[int64]bool, len(scan))

	for _, p := range scan {
		seen[p.ID] = true
		newStatus := patStatus(p)
		ex, inDB := existing[p.ID]

		if !inDB {
			results = append(results, PATResult{
				PAT:       p,
				NewStatus: newStatus,
				Op:        OpInsert,
				Event: &Event{
					Kind:             EventKindCreated,
					NewStatus:        newStatus,
					Snapshot:         p,
					PolicyViolations: violationsForPAT(pol, p, now),
				},
			})
			continue
		}

		changed := changedFieldsPAT(ex, p)
		statusChanged := ex.Status != newStatus

		switch {
		case statusChanged:
			results = append(results, PATResult{
				PAT:       p,
				NewStatus: newStatus,
				Op:        OpUpdate,
				Event: &Event{
					Kind:             EventKindStatusChange,
					OldStatus:        ex.Status,
					NewStatus:        newStatus,
					ChangedFields:    changed,
					Snapshot:         p,
					PolicyViolations: violationsForPAT(pol, p, now),
				},
			})
		case len(changed) > 0:
			results = append(results, PATResult{
				PAT:       p,
				NewStatus: newStatus,
				Op:        OpUpdate,
				Event: &Event{
					Kind:             EventKindFieldChange,
					ChangedFields:    changed,
					Snapshot:         p,
					PolicyViolations: violationsForPAT(pol, p, now),
				},
			})
		default:
			results = append(results, PATResult{
				PAT:       p,
				NewStatus: newStatus,
				Op:        OpTouch,
			})
		}
	}

	// Anything in DB we did not see this scan is removed.
	for id, ex := range existing {
		if seen[id] {
			continue
		}
		results = append(results, PATResult{
			PAT:       ex.LastKnown,
			NewStatus: PATStatusRemoved,
			Op:        OpMarkRemoved,
			Event: &Event{
				Kind:      EventKindRemoved,
				OldStatus: ex.Status,
				NewStatus: PATStatusRemoved,
				Snapshot:  ex.LastKnown,
				// Removed entities do not violate live policy in any
				// meaningful sense; leave PolicyViolations empty.
			},
		})
	}

	return results
}

func patStatus(p models.PATInfo) string {
	if p.TokenExpired {
		return PATStatusExpired
	}
	return PATStatusActive
}

func changedFieldsPAT(ex ExistingPAT, p models.PATInfo) []string {
	var changed []string
	if !permsEqual(ex.Permissions, p.Permissions) {
		changed = append(changed, "permissions")
	}
	if ex.RepositorySelection != p.RepositorySelection {
		changed = append(changed, "repository_selection")
	}
	if !timesEqual(ex.TokenExpiresAt, p.TokenExpiresAt) {
		changed = append(changed, "token_expires_at")
	}
	return changed
}

func violationsForPAT(pol *policy.Policy, p models.PATInfo, now time.Time) []string {
	if pol == nil {
		return nil
	}
	return pol.ViolationsForPAT(p, now)
}

// Status enum mirrors store package values to avoid an import cycle.
const (
	PATStatusActive  = "active"
	PATStatusExpired = "expired"
	PATStatusRemoved = "removed"
)

// Event kinds (mirrors store package values).
const (
	EventKindCreated      = "created"
	EventKindStatusChange = "status_change"
	EventKindFieldChange  = "field_change"
	EventKindRemoved      = "removed"
)
