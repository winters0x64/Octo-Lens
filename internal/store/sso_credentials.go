package store

import (
	"context"
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

	rows, err := q.Query(ctx, sqlSelect)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []SSOCredentialRow
	for rows.Next() {
		var r SSOCredentialRow
		var scopesJSON []byte
		if err := rows.Scan(
			&r.CredentialID, &r.Login, &r.CredentialType, &r.TokenLastEight,
			&r.CredentialAuthorizedAt, &r.CredentialAccessedAt,
			&r.AuthorizedCredentialTitle, &r.AuthorizedCredentialNote,
			&r.AuthorizedCredentialExpAt, &scopesJSON, &r.Fingerprint,
			&r.Status, &r.FirstSeenAt, &r.LastSeenAt, &r.LastChangedAt,
		); err != nil {
			return nil, err
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
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,$13)`
	_, err = q.Exec(ctx, sqlInsert,
		c.CredentialID, c.Login, c.CredentialType, c.TokenLastEight,
		c.CredentialAuthorizedAt, c.CredentialAccessedAt,
		c.AuthorizedCredentialTitle, c.AuthorizedCredentialNote,
		c.AuthorizedCredentialExpAt, scopesJSON, c.Fingerprint,
		status, now,
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
    login = $2,
    credential_type = $3,
    token_last_eight = $4,
    credential_authorized_at = $5,
    credential_accessed_at = $6,
    authorized_credential_title = $7,
    authorized_credential_note = $8,
    authorized_credential_expires_at = $9,
    scopes = $10,
    fingerprint = $11,
    status = $12,
    last_seen_at = $13,
    last_changed_at = $13
WHERE credential_id = $1`
	_, err = q.Exec(ctx, sqlUpdate,
		c.CredentialID, c.Login, c.CredentialType, c.TokenLastEight,
		c.CredentialAuthorizedAt, c.CredentialAccessedAt,
		c.AuthorizedCredentialTitle, c.AuthorizedCredentialNote,
		c.AuthorizedCredentialExpAt, scopesJSON, c.Fingerprint,
		status, now,
	)
	return err
}

func TouchSSOCredential(ctx context.Context, q Querier, id int64, now time.Time) error {
	_, err := q.Exec(ctx, `UPDATE sso_credentials SET last_seen_at = $2 WHERE credential_id = $1`, id, now)
	return err
}

func MarkSSOCredentialRemoved(ctx context.Context, q Querier, id int64, now time.Time) error {
	_, err := q.Exec(ctx,
		`UPDATE sso_credentials SET status = 'removed', last_changed_at = $2, last_seen_at = $2 WHERE credential_id = $1`,
		id, now)
	return err
}
