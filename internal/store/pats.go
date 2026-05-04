package store

import (
	"context"
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

	rows, err := q.Query(ctx, sqlSelect)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PATRow
	for rows.Next() {
		var r PATRow
		var permsJSON []byte
		if err := rows.Scan(
			&r.ID, &r.TokenName, &r.OwnerLogin, &r.OwnerAvatarURL, &r.RepositorySelection,
			&permsJSON, &r.AccessGrantedAt, &r.TokenExpiresAt, &r.TokenLastUsedAt,
			&r.Status, &r.FirstSeenAt, &r.LastSeenAt, &r.LastChangedAt,
		); err != nil {
			return nil, err
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
WHERE status = $1
ORDER BY last_changed_at DESC`

	rows, err := q.Query(ctx, sqlSelect, status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PATRow
	for rows.Next() {
		var r PATRow
		var permsJSON []byte
		if err := rows.Scan(
			&r.ID, &r.TokenName, &r.OwnerLogin, &r.OwnerAvatarURL, &r.RepositorySelection,
			&permsJSON, &r.AccessGrantedAt, &r.TokenExpiresAt, &r.TokenLastUsedAt,
			&r.Status, &r.FirstSeenAt, &r.LastSeenAt, &r.LastChangedAt,
		); err != nil {
			return nil, err
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
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$11,$11)`
	_, err = q.Exec(ctx, sqlInsert,
		p.ID, p.TokenName, p.OwnerLogin, p.OwnerAvatarURL, p.RepositorySelection,
		permsJSON, p.AccessGrantedAt, p.TokenExpiresAt, p.TokenLastUsedAt,
		status, now,
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
    token_name = $2,
    owner_login = $3,
    owner_avatar_url = $4,
    repository_selection = $5,
    permissions = $6,
    access_granted_at = $7,
    token_expires_at = $8,
    token_last_used_at = $9,
    status = $10,
    last_seen_at = $11,
    last_changed_at = $11
WHERE pat_id = $1`
	_, err = q.Exec(ctx, sqlUpdate,
		p.ID, p.TokenName, p.OwnerLogin, p.OwnerAvatarURL, p.RepositorySelection,
		permsJSON, p.AccessGrantedAt, p.TokenExpiresAt, p.TokenLastUsedAt,
		status, now,
	)
	return err
}

// TouchPAT bumps last_seen_at without recording a change.
func TouchPAT(ctx context.Context, q Querier, patID int64, now time.Time) error {
	_, err := q.Exec(ctx, `UPDATE pats SET last_seen_at = $2 WHERE pat_id = $1`, patID, now)
	return err
}

// MarkPATRemoved flips a PAT to status='removed'. The row is preserved
// so historical events still join correctly.
func MarkPATRemoved(ctx context.Context, q Querier, patID int64, now time.Time) error {
	_, err := q.Exec(ctx,
		`UPDATE pats SET status = 'removed', last_changed_at = $2, last_seen_at = $2 WHERE pat_id = $1`,
		patID, now)
	return err
}

// GetPATFirstSeen returns the first_seen_at for a PAT, used to preserve it on update.
// Returns pgx.ErrNoRows if the row doesn't exist.
func GetPATFirstSeen(ctx context.Context, q Querier, patID int64) (time.Time, error) {
	var t time.Time
	err := q.QueryRow(ctx, `SELECT first_seen_at FROM pats WHERE pat_id = $1`, patID).Scan(&t)
	return t, err
}

// FindPATByOwnerAndName looks up a PAT by (owner_login, token_name). Used to
// resolve pending requests to the issued PAT after approval. Returns
// pgx.ErrNoRows when no match exists.
func FindPATByOwnerAndName(ctx context.Context, q Querier, owner, name string) (int64, error) {
	var id int64
	err := q.QueryRow(ctx,
		`SELECT pat_id FROM pats WHERE owner_login = $1 AND token_name = $2 ORDER BY last_changed_at DESC LIMIT 1`,
		owner, name,
	).Scan(&id)
	return id, err
}
