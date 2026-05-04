package store

import (
	"context"
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
	const sqlInsert = `
INSERT INTO scan_runs (
    started_at,
    pats_complete, pat_requests_complete, sso_complete,
    apps_complete, secrets_complete, deploy_keys_complete, workflows_complete,
    repos_scanned
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id`

	var id int64
	err := q.QueryRow(ctx, sqlInsert,
		startedAt,
		flags.PATs, flags.PATRequests, flags.SSO,
		flags.Apps, flags.Secrets, flags.DeployKeys, flags.Workflows,
		flags.ReposScanned,
	).Scan(&id)
	return id, err
}

// FinishScanRun marks the scan as complete. errSummary is empty on success.
func FinishScanRun(ctx context.Context, q Querier, id int64, finishedAt time.Time, errSummary string) error {
	const sqlUpdate = `
UPDATE scan_runs
SET finished_at = $2, error_summary = NULLIF($3, '')
WHERE id = $1`
	_, err := q.Exec(ctx, sqlUpdate, id, finishedAt, errSummary)
	return err
}
