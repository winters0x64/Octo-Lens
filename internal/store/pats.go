package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

const (
	PATStatusActive  = "active"
	PATStatusExpired = "expired"
	PATStatusRemoved = "removed"
)

// PATRow is the persisted shape of a fine-grained PAT.
type PATRow struct {
	models.PATInfo
	Status        string
	FirstSeenAt   time.Time
	LastSeenAt    time.Time
	LastChangedAt time.Time
}

// ListActivePATs returns every PAT row whose status is not 'removed'.
// 'removed' rows are excluded so they don't bounce back to active on the
// next scan; if a removed PAT id reappears, it surfaces as a fresh insert.
func ListActivePATs(ctx context.Context, q Querier) ([]PATRow, error) {
	const sqlSelect = `
SELECT pat_id, token_name, owner_login, owner_avatar_url, repository_selection,
       permissions, access_granted_at, token_expires_at, token_last_used_at,
       status, first_seen_at, last_seen_at, last_changed_at
FROM pats
WHERE status <> 'removed'`

	rows, err := q.QueryContext(ctx, sqlSelect)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PATRow
	for rows.Next() {
		var r PATRow
		var permsJSON []byte
		var tokenExpiresAt, tokenLastUsedAt sql.NullTime
		if err := rows.Scan(
			&r.ID, &r.TokenName, &r.OwnerLogin, &r.OwnerAvatarURL, &r.RepositorySelection,
			&permsJSON, &r.AccessGrantedAt, &tokenExpiresAt, &tokenLastUsedAt,
			&r.Status, &r.FirstSeenAt, &r.LastSeenAt, &r.LastChangedAt,
		); err != nil {
			return nil, err
		}
		if tokenExpiresAt.Valid {
			t := tokenExpiresAt.Time
			r.TokenExpiresAt = &t
		}
		if tokenLastUsedAt.Valid {
			t := tokenLastUsedAt.Time
			r.TokenLastUsedAt = &t
		}
		if err := json.Unmarshal(permsJSON, &r.Permissions); err != nil {
			return nil, fmt.Errorf("decoding permissions for pat %d: %w", r.ID, err)
		}
		r.TokenExpired = r.Status == PATStatusExpired
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListPATsByStatus returns PAT rows matching the given status, latest first.
func ListPATsByStatus(ctx context.Context, q Querier, status string) ([]PATRow, error) {
	const sqlSelect = `
SELECT pat_id, token_name, owner_login, owner_avatar_url, repository_selection,
       permissions, access_granted_at, token_expires_at, token_last_used_at,
       status, first_seen_at, last_seen_at, last_changed_at
FROM pats
WHERE status = ?
ORDER BY last_changed_at DESC`

	rows, err := q.QueryContext(ctx, sqlSelect, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PATRow
	for rows.Next() {
		var r PATRow
		var permsJSON []byte
		var tokenExpiresAt, tokenLastUsedAt sql.NullTime
		if err := rows.Scan(
			&r.ID, &r.TokenName, &r.OwnerLogin, &r.OwnerAvatarURL, &r.RepositorySelection,
			&permsJSON, &r.AccessGrantedAt, &tokenExpiresAt, &tokenLastUsedAt,
			&r.Status, &r.FirstSeenAt, &r.LastSeenAt, &r.LastChangedAt,
		); err != nil {
			return nil, err
		}
		if tokenExpiresAt.Valid {
			t := tokenExpiresAt.Time
			r.TokenExpiresAt = &t
		}
		if tokenLastUsedAt.Valid {
			t := tokenLastUsedAt.Time
			r.TokenLastUsedAt = &t
		}
		if err := json.Unmarshal(permsJSON, &r.Permissions); err != nil {
			return nil, err
		}
		r.TokenExpired = r.Status == PATStatusExpired
		out = append(out, r)
	}
	return out, rows.Err()
}

// InsertPAT writes a brand-new PAT row.
func InsertPAT(ctx context.Context, q Querier, p models.PATInfo, status string, now time.Time) error {
	permsJSON, err := json.Marshal(p.Permissions)
	if err != nil {
		return err
	}
	const sqlInsert = `
INSERT INTO pats (
    pat_id, token_name, owner_login, owner_avatar_url, repository_selection,
    permissions, access_granted_at, token_expires_at, token_last_used_at,
    status, first_seen_at, last_seen_at, last_changed_at
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`
	_, err = q.ExecContext(ctx, sqlInsert,
		p.ID, p.TokenName, p.OwnerLogin, p.OwnerAvatarURL, p.RepositorySelection,
		permsJSON, p.AccessGrantedAt, p.TokenExpiresAt, p.TokenLastUsedAt,
		status, now, now, now,
	)
	return err
}

// UpdatePAT writes a status or watched-field change.
func UpdatePAT(ctx context.Context, q Querier, p models.PATInfo, status string, now time.Time) error {
	permsJSON, err := json.Marshal(p.Permissions)
	if err != nil {
		return err
	}
	const sqlUpdate = `
UPDATE pats SET
    token_name = ?,
    owner_login = ?,
    owner_avatar_url = ?,
    repository_selection = ?,
    permissions = ?,
    access_granted_at = ?,
    token_expires_at = ?,
    token_last_used_at = ?,
    status = ?,
    last_seen_at = ?,
    last_changed_at = ?
WHERE pat_id = ?`
	_, err = q.ExecContext(ctx, sqlUpdate,
		p.TokenName, p.OwnerLogin, p.OwnerAvatarURL, p.RepositorySelection,
		permsJSON, p.AccessGrantedAt, p.TokenExpiresAt, p.TokenLastUsedAt,
		status, now, now,
		p.ID,
	)
	return err
}

// TouchPAT bumps last_seen_at without recording a change.
func TouchPAT(ctx context.Context, q Querier, patID int64, now time.Time) error {
	_, err := q.ExecContext(ctx, `UPDATE pats SET last_seen_at = ? WHERE pat_id = ?`, now, patID)
	return err
}

// MarkPATRemoved flips a PAT to status='removed'. The row is preserved
// so historical events still join correctly.
func MarkPATRemoved(ctx context.Context, q Querier, patID int64, now time.Time) error {
	_, err := q.ExecContext(ctx,
		`UPDATE pats SET status = 'removed', last_changed_at = ?, last_seen_at = ? WHERE pat_id = ?`,
		now, now, patID)
	return err
}

// GetPATFirstSeen returns the first_seen_at for a PAT, used to preserve it on update.
// Returns sql.ErrNoRows if the row doesn't exist.
func GetPATFirstSeen(ctx context.Context, q Querier, patID int64) (time.Time, error) {
	var t time.Time
	err := q.QueryRowContext(ctx, `SELECT first_seen_at FROM pats WHERE pat_id = ?`, patID).Scan(&t)
	return t, err
}

// FindPATByOwnerAndName looks up a PAT by (owner_login, token_name). Used to
// resolve pending requests to the issued PAT after approval. Returns
// sql.ErrNoRows when no match exists.
func FindPATByOwnerAndName(ctx context.Context, q Querier, owner, name string) (int64, error) {
	var id int64
	err := q.QueryRowContext(ctx,
		`SELECT pat_id FROM pats WHERE owner_login = ? AND token_name = ? ORDER BY last_changed_at DESC LIMIT 1`,
		owner, name,
	).Scan(&id)
	return id, err
}
