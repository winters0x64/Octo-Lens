// Package persist orchestrates the per-scan write to MySQL: it consumes
// a scanner.Result, runs the diff against current DB rows, and applies the
// resulting ops + events transactionally.
package persist

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/diff"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/policy"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/scanner"
	"github.com/th3-j0ik3r/github-pat-monitor/internal/store"
)

// Apply persists the given scan result. All writes happen in one transaction.
// Phases that did not complete are skipped — their existing rows are left
// untouched to avoid false 'removed' events.
func Apply(ctx context.Context, st *store.Store, result *scanner.Result, pol *policy.Policy, now time.Time) error {
	if st == nil {
		return errors.New("persist.Apply: nil store")
	}
	if result == nil || result.Report == nil {
		return errors.New("persist.Apply: nil result/report")
	}

	return st.Tx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		flags := store.PhaseFlags{
			PATs:         result.PATsComplete,
			PATRequests:  result.PATRequestsComplete,
			SSO:          result.SSOComplete,
			Apps:         result.AppsComplete,
			Secrets:      result.SecretsComplete,
			DeployKeys:   result.DeployKeysComplete,
			Workflows:    result.WorkflowPermsComplete && result.WorkflowFilesComplete,
			ReposScanned: result.ReposScanned,
		}

		scanRunID, err := store.InsertScanRun(ctx, tx, now, flags)
		if err != nil {
			return fmt.Errorf("inserting scan_run: %w", err)
		}

		var events []store.EventWrite

		if result.PATsComplete {
			ev, err := applyPATs(ctx, tx, result, pol, now)
			if err != nil {
				return err
			}
			events = append(events, ev...)
		}

		if result.PATRequestsComplete {
			ev, err := applyPATRequests(ctx, tx, result, now)
			if err != nil {
				return err
			}
			events = append(events, ev...)
		}

		if result.SSOComplete {
			ev, err := applySSOCredentials(ctx, tx, result, pol, now)
			if err != nil {
				return err
			}
			events = append(events, ev...)
		}

		if err := store.BatchInsertEvents(ctx, tx, scanRunID, now, events); err != nil {
			return fmt.Errorf("inserting events: %w", err)
		}

		// Cache snapshot tables — replace atomically within the same transaction.
		if result.AppsComplete {
			if err := store.UpsertCachedApps(ctx, tx, result.Report.Apps, now); err != nil {
				return fmt.Errorf("upsert cached apps: %w", err)
			}
		}
		if result.SecretsComplete {
			if err := store.UpsertCachedSecrets(ctx, tx, result.Report.Secrets, now); err != nil {
				return fmt.Errorf("upsert cached secrets: %w", err)
			}
		}
		if result.DeployKeysComplete {
			if err := store.UpsertCachedDeployKeys(ctx, tx, result.Report.DeployKeys, now); err != nil {
				return fmt.Errorf("upsert cached deploy keys: %w", err)
			}
		}
		if result.WorkflowPermsComplete {
			if err := store.UpsertCachedWorkflowPerms(ctx, tx, result.Report.WorkflowPerms, now); err != nil {
				return fmt.Errorf("upsert cached workflow perms: %w", err)
			}
		}
		if result.WorkflowFilesComplete {
			if err := store.UpsertCachedWorkflowFiles(ctx, tx, result.Report.WorkflowFiles, now); err != nil {
				return fmt.Errorf("upsert cached workflow files: %w", err)
			}
		}

		errSummary := result.PhaseErrorSummary()
		if err := store.FinishScanRun(ctx, tx, scanRunID, time.Now(), errSummary); err != nil {
			return fmt.Errorf("finishing scan_run: %w", err)
		}
		return nil
	})
}

func applyPATs(ctx context.Context, q store.Querier, result *scanner.Result, pol *policy.Policy, now time.Time) ([]store.EventWrite, error) {
	rows, err := store.ListActivePATs(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listing existing pats: %w", err)
	}

	existing := make(map[int64]diff.ExistingPAT, len(rows))
	for _, r := range rows {
		existing[r.ID] = diff.ExistingPAT{
			Status:              r.Status,
			Permissions:         r.Permissions,
			RepositorySelection: r.RepositorySelection,
			TokenExpiresAt:      r.TokenExpiresAt,
			LastKnown:           r.PATInfo,
		}
	}

	results := diff.PATs(existing, result.Report.PATs, pol, now)
	events := make([]store.EventWrite, 0, len(results))

	for _, r := range results {
		switch r.Op {
		case diff.OpInsert:
			if err := store.InsertPAT(ctx, q, r.PAT, r.NewStatus, now); err != nil {
				return nil, fmt.Errorf("insert pat %d: %w", r.PAT.ID, err)
			}
		case diff.OpUpdate:
			if err := store.UpdatePAT(ctx, q, r.PAT, r.NewStatus, now); err != nil {
				return nil, fmt.Errorf("update pat %d: %w", r.PAT.ID, err)
			}
		case diff.OpTouch:
			if err := store.TouchPAT(ctx, q, r.PAT.ID, now); err != nil {
				return nil, fmt.Errorf("touch pat %d: %w", r.PAT.ID, err)
			}
		case diff.OpMarkRemoved:
			if err := store.MarkPATRemoved(ctx, q, r.PAT.ID, now); err != nil {
				return nil, fmt.Errorf("mark pat %d removed: %w", r.PAT.ID, err)
			}
		}
		if r.Event != nil {
			events = append(events, store.EventWrite{
				EntityType:       store.EventEntityPAT,
				EntityID:         itoa64(r.PAT.ID),
				Kind:             r.Event.Kind,
				OldStatus:        r.Event.OldStatus,
				NewStatus:        r.Event.NewStatus,
				ChangedFields:    r.Event.ChangedFields,
				Snapshot:         r.Event.Snapshot,
				PolicyViolations: r.Event.PolicyViolations,
			})
		}
	}
	return events, nil
}

func applyPATRequests(ctx context.Context, q store.Querier, result *scanner.Result, now time.Time) ([]store.EventWrite, error) {
	rows, err := store.ListActivePATRequests(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listing existing pat_requests: %w", err)
	}

	existing := make(map[int64]diff.ExistingPATRequest, len(rows))
	for _, r := range rows {
		existing[r.ID] = diff.ExistingPATRequest{
			Status:              r.Status,
			Permissions:         r.Permissions,
			RepositorySelection: r.RepositorySelection,
			LastKnown:           r.PATRequest,
		}
	}

	lookup := func(owner, name string) int64 {
		id, err := store.FindPATByOwnerAndName(ctx, q, owner, name)
		if err != nil {
			return 0
		}
		return id
	}

	results := diff.PATRequests(existing, result.Report.PendingRequests, lookup, now)
	events := make([]store.EventWrite, 0, len(results))

	for _, r := range results {
		switch r.Op {
		case diff.OpInsert:
			if err := store.InsertPATRequest(ctx, q, r.Request, r.NewStatus, now); err != nil {
				return nil, fmt.Errorf("insert pat_request %d: %w", r.Request.ID, err)
			}
		case diff.OpUpdate:
			if err := store.UpdatePATRequest(ctx, q, r.Request, r.NewStatus, now); err != nil {
				return nil, fmt.Errorf("update pat_request %d: %w", r.Request.ID, err)
			}
		case diff.OpTouch:
			if err := store.TouchPATRequest(ctx, q, r.Request.ID, now); err != nil {
				return nil, fmt.Errorf("touch pat_request %d: %w", r.Request.ID, err)
			}
		case diff.OpMarkRemoved:
			if err := store.ResolvePATRequest(ctx, q, r.Request.ID, r.ResolvedPATID, now); err != nil {
				return nil, fmt.Errorf("resolve pat_request %d: %w", r.Request.ID, err)
			}
		}
		if r.Event != nil {
			events = append(events, store.EventWrite{
				EntityType:    store.EventEntityPATRequest,
				EntityID:      itoa64(r.Request.ID),
				Kind:          r.Event.Kind,
				OldStatus:     r.Event.OldStatus,
				NewStatus:     r.Event.NewStatus,
				ChangedFields: r.Event.ChangedFields,
				Snapshot:      r.Event.Snapshot,
			})
		}
	}
	return events, nil
}

func applySSOCredentials(ctx context.Context, q store.Querier, result *scanner.Result, pol *policy.Policy, now time.Time) ([]store.EventWrite, error) {
	rows, err := store.ListActiveSSOCredentials(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("listing existing sso_credentials: %w", err)
	}

	existing := make(map[int64]diff.ExistingSSOCredential, len(rows))
	for _, r := range rows {
		existing[r.CredentialID] = diff.ExistingSSOCredential{
			Status:                    r.Status,
			Scopes:                    r.Scopes,
			AuthorizedCredentialExpAt: r.AuthorizedCredentialExpAt,
			LastKnown:                 r.SSOCredential,
		}
	}

	results := diff.SSOCredentials(existing, result.Report.SSOCredentials, pol, now)
	events := make([]store.EventWrite, 0, len(results))

	for _, r := range results {
		switch r.Op {
		case diff.OpInsert:
			if err := store.InsertSSOCredential(ctx, q, r.Credential, r.NewStatus, now); err != nil {
				return nil, fmt.Errorf("insert sso_credential %d: %w", r.Credential.CredentialID, err)
			}
		case diff.OpUpdate:
			if err := store.UpdateSSOCredential(ctx, q, r.Credential, r.NewStatus, now); err != nil {
				return nil, fmt.Errorf("update sso_credential %d: %w", r.Credential.CredentialID, err)
			}
		case diff.OpTouch:
			if err := store.TouchSSOCredential(ctx, q, r.Credential.CredentialID, now); err != nil {
				return nil, fmt.Errorf("touch sso_credential %d: %w", r.Credential.CredentialID, err)
			}
		case diff.OpMarkRemoved:
			if err := store.MarkSSOCredentialRemoved(ctx, q, r.Credential.CredentialID, now); err != nil {
				return nil, fmt.Errorf("mark sso_credential %d removed: %w", r.Credential.CredentialID, err)
			}
		}
		if r.Event != nil {
			events = append(events, store.EventWrite{
				EntityType:       store.EventEntitySSOCredential,
				EntityID:         itoa64(r.Credential.CredentialID),
				Kind:             r.Event.Kind,
				OldStatus:        r.Event.OldStatus,
				NewStatus:        r.Event.NewStatus,
				ChangedFields:    r.Event.ChangedFields,
				Snapshot:         r.Event.Snapshot,
				PolicyViolations: r.Event.PolicyViolations,
			})
		}
	}
	return events, nil
}

func itoa64(n int64) string {
	return strconv.FormatInt(n, 10)
}
