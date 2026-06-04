package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

const (
	SSOStatusActive  = "active"
	SSOStatusExpired = "expired"
	SSOStatusRemoved = "removed"
)

type SSOCredentialRow struct {
	models.SSOCredential
	Status        string
	FirstSeenAt   time.Time
	LastSeenAt    time.Time
	LastChangedAt time.Time
}

func ListActiveSSOCredentials(ctx context.Context, q Querier) ([]SSOCredentialRow, error) {
	const sqlSelect = `
SELECT credential_id, login, credential_type, token_last_eight,
       credential_authorized_at, credential_accessed_at,
       authorized_credential_title, authorized_credential_note,
       authorized_credential_expires_at, scopes, fingerprint,
       status, first_seen_at, last_seen_at, last_changed_at
FROM sso_credentials
WHERE status <> 'removed'`

	rows, err := q.QueryContext(ctx, sqlSelect)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SSOCredentialRow
	for rows.Next() {
		var r SSOCredentialRow
		var scopesJSON []byte
		var credentialAccessedAt sql.NullTime
		var authorizedCredentialExpAt sql.NullTime
		if err := rows.Scan(
			&r.CredentialID, &r.Login, &r.CredentialType, &r.TokenLastEight,
			&r.CredentialAuthorizedAt, &credentialAccessedAt,
			&r.AuthorizedCredentialTitle, &r.AuthorizedCredentialNote,
			&authorizedCredentialExpAt, &scopesJSON, &r.Fingerprint,
			&r.Status, &r.FirstSeenAt, &r.LastSeenAt, &r.LastChangedAt,
		); err != nil {
			return nil, err
		}
		if credentialAccessedAt.Valid {
			t := credentialAccessedAt.Time
			r.CredentialAccessedAt = &t
		}
		if authorizedCredentialExpAt.Valid {
			t := authorizedCredentialExpAt.Time
			r.AuthorizedCredentialExpAt = &t
		}
		if err := json.Unmarshal(scopesJSON, &r.Scopes); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func InsertSSOCredential(ctx context.Context, q Querier, c models.SSOCredential, status string, now time.Time) error {
	scopesJSON, err := json.Marshal(c.Scopes)
	if err != nil {
		return err
	}
	const sqlInsert = `
INSERT INTO sso_credentials (
    credential_id, login, credential_type, token_last_eight,
    credential_authorized_at, credential_accessed_at,
    authorized_credential_title, authorized_credential_note,
    authorized_credential_expires_at, scopes, fingerprint,
    status, first_seen_at, last_seen_at, last_changed_at
) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
	_, err = q.ExecContext(ctx, sqlInsert,
		c.CredentialID, c.Login, c.CredentialType, c.TokenLastEight,
		c.CredentialAuthorizedAt, c.CredentialAccessedAt,
		c.AuthorizedCredentialTitle, c.AuthorizedCredentialNote,
		c.AuthorizedCredentialExpAt, scopesJSON, c.Fingerprint,
		status, now, now, now,
	)
	return err
}

func UpdateSSOCredential(ctx context.Context, q Querier, c models.SSOCredential, status string, now time.Time) error {
	scopesJSON, err := json.Marshal(c.Scopes)
	if err != nil {
		return err
	}
	const sqlUpdate = `
UPDATE sso_credentials SET
    login = ?,
    credential_type = ?,
    token_last_eight = ?,
    credential_authorized_at = ?,
    credential_accessed_at = ?,
    authorized_credential_title = ?,
    authorized_credential_note = ?,
    authorized_credential_expires_at = ?,
    scopes = ?,
    fingerprint = ?,
    status = ?,
    last_seen_at = ?,
    last_changed_at = ?
WHERE credential_id = ?`
	_, err = q.ExecContext(ctx, sqlUpdate,
		c.Login, c.CredentialType, c.TokenLastEight,
		c.CredentialAuthorizedAt, c.CredentialAccessedAt,
		c.AuthorizedCredentialTitle, c.AuthorizedCredentialNote,
		c.AuthorizedCredentialExpAt, scopesJSON, c.Fingerprint,
		status, now, now,
		c.CredentialID,
	)
	return err
}

func TouchSSOCredential(ctx context.Context, q Querier, id int64, now time.Time) error {
	_, err := q.ExecContext(ctx, `UPDATE sso_credentials SET last_seen_at = ? WHERE credential_id = ?`, now, id)
	return err
}

func MarkSSOCredentialRemoved(ctx context.Context, q Querier, id int64, now time.Time) error {
	_, err := q.ExecContext(ctx,
		`UPDATE sso_credentials SET status = 'removed', last_changed_at = ?, last_seen_at = ? WHERE credential_id = ?`,
		now, now, id)
	return err
}
