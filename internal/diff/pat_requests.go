package diff

import (
	"time"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// ExistingPATRequest mirrors ExistingPAT — minimum we need from DB to diff.
type ExistingPATRequest struct {
	Status              string
	Permissions         []models.Permission
	RepositorySelection string
	LastKnown           models.PATRequest
}

type PATRequestResult struct {
	Request   models.PATRequest
	NewStatus string
	Op        Op
	// ResolvedPATID is set on OpMarkResolved when we can identify the
	// approved PAT (matched by owner_login + token_name). nil otherwise.
	ResolvedPATID *int64
	Event         *Event
}

// PATRequests diffs pending request rows against the current pending list.
// resolvedLookup, if provided, returns the PAT ID that resolved a given
// (owner_login, token_name) — typically backed by FindPATByOwnerAndName.
// It may return 0 to indicate "not found".
func PATRequests(
	existing map[int64]ExistingPATRequest,
	scan []models.PATRequest,
	resolvedLookup func(owner, tokenName string) int64,
	now time.Time,
) []PATRequestResult {
	results := make([]PATRequestResult, 0, len(scan)+len(existing))
	seen := make(map[int64]bool, len(scan))

	for _, r := range scan {
		seen[r.ID] = true
		ex, inDB := existing[r.ID]

		if !inDB {
			results = append(results, PATRequestResult{
				Request:   r,
				NewStatus: PATRequestStatusPending,
				Op:        OpInsert,
				Event: &Event{
					Kind:      EventKindCreated,
					NewStatus: PATRequestStatusPending,
					Snapshot:  r,
				},
			})
			continue
		}

		changed := changedFieldsPATRequest(ex, r)
		// While a request is in the pending list its status stays 'pending'.
		if len(changed) > 0 {
			results = append(results, PATRequestResult{
				Request:   r,
				NewStatus: PATRequestStatusPending,
				Op:        OpUpdate,
				Event: &Event{
					Kind:          EventKindFieldChange,
					ChangedFields: changed,
					Snapshot:      r,
				},
			})
		} else {
			results = append(results, PATRequestResult{
				Request:   r,
				NewStatus: PATRequestStatusPending,
				Op:        OpTouch,
			})
		}
	}

	for id, ex := range existing {
		if seen[id] {
			continue
		}
		var resolvedID *int64
		if resolvedLookup != nil {
			if pid := resolvedLookup(ex.LastKnown.OwnerLogin, ex.LastKnown.TokenName); pid != 0 {
				resolvedID = &pid
			}
		}
		results = append(results, PATRequestResult{
			Request:       ex.LastKnown,
			NewStatus:     PATRequestStatusResolved,
			Op:            OpMarkRemoved, // store layer maps this to ResolvePATRequest
			ResolvedPATID: resolvedID,
			Event: &Event{
				// "removed" semantics here = "no longer pending"; the resolved_pat_id
				// linkage carries whether it was approved or denied/withdrawn.
				Kind:      EventKindRemoved,
				OldStatus: ex.Status,
				NewStatus: PATRequestStatusResolved,
				Snapshot:  ex.LastKnown,
			},
		})
	}

	return results
}

func changedFieldsPATRequest(ex ExistingPATRequest, r models.PATRequest) []string {
	var changed []string
	if !permsEqual(ex.Permissions, r.Permissions) {
		changed = append(changed, "permissions")
	}
	if ex.RepositorySelection != r.RepositorySelection {
		changed = append(changed, "repository_selection")
	}
	return changed
}

const (
	PATRequestStatusPending  = "pending"
	PATRequestStatusResolved = "resolved"
)
