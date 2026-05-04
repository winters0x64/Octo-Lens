package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

const (
	PATRequestStatusPending  = "pending"
	PATRequestStatusResolved = "resolved"
)

type PATRequestRow struct {
	models.PATRequest
	Status        string
	ResolvedPATID *int64
	FirstSeenAt   time.Time
	LastSeenAt    time.Time
	LastChangedAt time.Time
}

// ListActivePATRequests returns rows whose status is not 'resolved'.
func ListActivePATRequests(ctx context.Context, q Querier) ([]PATRequestRow, error) {
	const sqlSelect = `
SELECT request_id, token_name, owner_login, repository_selection,
       permissions, created_at, token_expires_at,
       status, resolved_pat_id, first_seen_at, last_seen_at, last_changed_at
FROM pat_requests
WHERE status <> 'resolved'`

	rows, err := q.Query(ctx, sqlSelect)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PATRequestRow
	for rows.Next() {
		var r PATRequestRow
		var permsJSON []byte
		if err := rows.Scan(
			&r.ID, &r.TokenName, &r.OwnerLogin, &r.RepositorySelection,
			&permsJSON, &r.CreatedAt, &r.TokenExpiresAt,
			&r.Status, &r.ResolvedPATID, &r.FirstSeenAt, &r.LastSeenAt, &r.LastChangedAt,
		); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(permsJSON, &r.Permissions); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func InsertPATRequest(ctx context.Context, q Querier, p models.PATRequest, status string, now time.Time) error {
	permsJSON, err := json.Marshal(p.Permissions)
	if err != nil {
		return err
	}
	const sqlInsert = `
INSERT INTO pat_requests (
    request_id, token_name, owner_login, repository_selection,
    permissions, created_at, token_expires_at,
    status, first_seen_at, last_seen_at, last_changed_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$9)`
	_, err = q.Exec(ctx, sqlInsert,
		p.ID, p.TokenName, p.OwnerLogin, p.RepositorySelection,
		permsJSON, p.CreatedAt, p.TokenExpiresAt,
		status, now,
	)
	return err
}

func UpdatePATRequest(ctx context.Context, q Querier, p models.PATRequest, status string, now time.Time) error {
	permsJSON, err := json.Marshal(p.Permissions)
	if err != nil {
		return err
	}
	const sqlUpdate = `
UPDATE pat_requests SET
    token_name = $2,
    owner_login = $3,
    repository_selection = $4,
    permissions = $5,
    created_at = $6,
    token_expires_at = $7,
    status = $8,
    last_seen_at = $9,
    last_changed_at = $9
WHERE request_id = $1`
	_, err = q.Exec(ctx, sqlUpdate,
		p.ID, p.TokenName, p.OwnerLogin, p.RepositorySelection,
		permsJSON, p.CreatedAt, p.TokenExpiresAt,
		status, now,
	)
	return err
}

func TouchPATRequest(ctx context.Context, q Querier, requestID int64, now time.Time) error {
	_, err := q.Exec(ctx, `UPDATE pat_requests SET last_seen_at = $2 WHERE request_id = $1`, requestID, now)
	return err
}

// ResolvePATRequest flips a request to 'resolved'. resolvedPATID is nullable —
// set when we can identify the issued PAT, NULL when the request was denied
// or withdrawn (we cannot tell which from the API).
func ResolvePATRequest(ctx context.Context, q Querier, requestID int64, resolvedPATID *int64, now time.Time) error {
	_, err := q.Exec(ctx,
		`UPDATE pat_requests SET status = 'resolved', resolved_pat_id = $2, last_changed_at = $3, last_seen_at = $3 WHERE request_id = $1`,
		requestID, resolvedPATID, now)
	return err
}
