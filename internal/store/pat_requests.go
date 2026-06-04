package store

import (
	"context"
	"database/sql"
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

	rows, err := q.QueryContext(ctx, sqlSelect)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PATRequestRow
	for rows.Next() {
		var r PATRequestRow
		var permsJSON []byte
		var tokenExpiresAt sql.NullTime
		var resolvedPATID sql.NullInt64
		if err := rows.Scan(
			&r.ID, &r.TokenName, &r.OwnerLogin, &r.RepositorySelection,
			&permsJSON, &r.CreatedAt, &tokenExpiresAt,
			&r.Status, &resolvedPATID, &r.FirstSeenAt, &r.LastSeenAt, &r.LastChangedAt,
		); err != nil {
			return nil, err
		}
		if tokenExpiresAt.Valid {
			t := tokenExpiresAt.Time
			r.TokenExpiresAt = &t
		}
		if resolvedPATID.Valid {
			v := resolvedPATID.Int64
			r.ResolvedPATID = &v
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
) VALUES (?,?,?,?,?,?,?,?,?,?,?)`
	_, err = q.ExecContext(ctx, sqlInsert,
		p.ID, p.TokenName, p.OwnerLogin, p.RepositorySelection,
		permsJSON, p.CreatedAt, p.TokenExpiresAt,
		status, now, now, now,
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
    token_name = ?,
    owner_login = ?,
    repository_selection = ?,
    permissions = ?,
    created_at = ?,
    token_expires_at = ?,
    status = ?,
    last_seen_at = ?,
    last_changed_at = ?
WHERE request_id = ?`
	_, err = q.ExecContext(ctx, sqlUpdate,
		p.TokenName, p.OwnerLogin, p.RepositorySelection,
		permsJSON, p.CreatedAt, p.TokenExpiresAt,
		status, now, now,
		p.ID,
	)
	return err
}

func TouchPATRequest(ctx context.Context, q Querier, requestID int64, now time.Time) error {
	_, err := q.ExecContext(ctx, `UPDATE pat_requests SET last_seen_at = ? WHERE request_id = ?`, now, requestID)
	return err
}

// ResolvePATRequest flips a request to 'resolved'. resolvedPATID is nullable —
// set when we can identify the issued PAT, NULL when the request was denied
// or withdrawn (we cannot tell which from the API).
func ResolvePATRequest(ctx context.Context, q Querier, requestID int64, resolvedPATID *int64, now time.Time) error {
	var nullableID sql.NullInt64
	if resolvedPATID != nil {
		nullableID = sql.NullInt64{Int64: *resolvedPATID, Valid: true}
	}
	_, err := q.ExecContext(ctx,
		`UPDATE pat_requests SET status = 'resolved', resolved_pat_id = ?, last_changed_at = ?, last_seen_at = ? WHERE request_id = ?`,
		nullableID, now, now, requestID)
	return err
}
