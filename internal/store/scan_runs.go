package store

import (
	"context"
	"database/sql"
	"time"
)

// PhaseFlags marks which scan phases completed cleanly. Only completed
// phases are eligible for diff/removal — a partial fetch must not flip
// surviving rows to 'removed'.
type PhaseFlags struct {
	PATs         bool
	PATRequests  bool
	SSO          bool
	Apps         bool
	Secrets      bool
	DeployKeys   bool
	Workflows    bool
	ReposScanned []string
}

// InsertScanRun records the start of a scan with phase completeness flags
// already known. Returns the new scan_runs.id.
func InsertScanRun(ctx context.Context, q Querier, startedAt time.Time, flags PhaseFlags) (int64, error) {
	reposJSON, err := marshalStringSlice(flags.ReposScanned)
	if err != nil {
		return 0, err
	}

	const sqlInsert = `
INSERT INTO scan_runs (
    started_at,
    pats_complete, pat_requests_complete, sso_complete,
    apps_complete, secrets_complete, deploy_keys_complete, workflows_complete,
    repos_scanned
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := q.ExecContext(ctx, sqlInsert,
		startedAt,
		flags.PATs, flags.PATRequests, flags.SSO,
		flags.Apps, flags.Secrets, flags.DeployKeys, flags.Workflows,
		reposJSON,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// FinishScanRun marks the scan as complete. errSummary is empty on success.
func FinishScanRun(ctx context.Context, q Querier, id int64, finishedAt time.Time, errSummary string) error {
	// Store NULL when errSummary is empty, non-null string otherwise.
	var summary sql.NullString
	if errSummary != "" {
		summary = sql.NullString{String: errSummary, Valid: true}
	}
	const sqlUpdate = `
UPDATE scan_runs
SET finished_at = ?, error_summary = ?
WHERE id = ?`
	_, err := q.ExecContext(ctx, sqlUpdate, finishedAt, summary, id)
	return err
}
