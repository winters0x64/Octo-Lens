package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/th3-j0ik3r/github-pat-monitor/internal/models"
)

// ─── Apps ──────────────────────────────────────────────────────────────────

// UpsertCachedApps atomically replaces all cached app rows.
// Must be called within a transaction so the delete+insert is atomic.
func UpsertCachedApps(ctx context.Context, q Querier, apps []models.AppInstallation, now time.Time) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM cached_apps`); err != nil {
		return err
	}
	for _, a := range apps {
		data, err := json.Marshal(a)
		if err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx,
			`INSERT INTO cached_apps (app_id, data, last_seen_at) VALUES (?, ?, ?)`,
			a.ID, string(data), now,
		); err != nil {
			return err
		}
	}
	return nil
}

// ListCachedApps returns all cached app installations.
func ListCachedApps(ctx context.Context, q Querier) ([]models.AppInstallation, error) {
	rows, err := q.QueryContext(ctx, `SELECT data FROM cached_apps ORDER BY app_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.AppInstallation
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var a models.AppInstallation
		if err := json.Unmarshal(raw, &a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ─── Secrets ───────────────────────────────────────────────────────────────

// UpsertCachedSecrets atomically replaces all cached secret rows.
func UpsertCachedSecrets(ctx context.Context, q Querier, secrets []models.OrgSecret, now time.Time) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM cached_secrets`); err != nil {
		return err
	}
	for _, s := range secrets {
		data, err := json.Marshal(s)
		if err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx,
			`INSERT INTO cached_secrets (name, scope, repo_name, env_name, data, last_seen_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			s.Name, s.Scope, s.RepoName, s.EnvName, string(data), now,
		); err != nil {
			return err
		}
	}
	return nil
}

// ListCachedSecrets returns all cached secrets.
func ListCachedSecrets(ctx context.Context, q Querier) ([]models.OrgSecret, error) {
	rows, err := q.QueryContext(ctx, `SELECT data FROM cached_secrets ORDER BY scope, repo_name, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.OrgSecret
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var s models.OrgSecret
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ─── Deploy Keys ───────────────────────────────────────────────────────────

// UpsertCachedDeployKeys atomically replaces all cached deploy key rows.
func UpsertCachedDeployKeys(ctx context.Context, q Querier, keys []models.DeployKey, now time.Time) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM cached_deploy_keys`); err != nil {
		return err
	}
	for _, k := range keys {
		data, err := json.Marshal(k)
		if err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx,
			`INSERT INTO cached_deploy_keys (deploy_key_id, data, last_seen_at) VALUES (?, ?, ?)`,
			k.ID, string(data), now,
		); err != nil {
			return err
		}
	}
	return nil
}

// ListCachedDeployKeys returns all cached deploy keys.
func ListCachedDeployKeys(ctx context.Context, q Querier) ([]models.DeployKey, error) {
	rows, err := q.QueryContext(ctx, `SELECT data FROM cached_deploy_keys ORDER BY deploy_key_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.DeployKey
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var k models.DeployKey
		if err := json.Unmarshal(raw, &k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// ─── Workflow Permissions ──────────────────────────────────────────────────

// UpsertCachedWorkflowPerms atomically replaces all cached workflow permission rows.
func UpsertCachedWorkflowPerms(ctx context.Context, q Querier, perms []models.WorkflowPermission, now time.Time) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM cached_workflow_permissions`); err != nil {
		return err
	}
	for _, p := range perms {
		data, err := json.Marshal(p)
		if err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx,
			`INSERT INTO cached_workflow_permissions (repo_name, data, last_seen_at) VALUES (?, ?, ?)`,
			p.RepoName, string(data), now,
		); err != nil {
			return err
		}
	}
	return nil
}

// ListCachedWorkflowPerms returns all cached workflow permissions.
func ListCachedWorkflowPerms(ctx context.Context, q Querier) ([]models.WorkflowPermission, error) {
	rows, err := q.QueryContext(ctx, `SELECT data FROM cached_workflow_permissions ORDER BY repo_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.WorkflowPermission
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var p models.WorkflowPermission
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ─── Workflow Files ────────────────────────────────────────────────────────

// UpsertCachedWorkflowFiles atomically replaces all cached workflow file rows.
func UpsertCachedWorkflowFiles(ctx context.Context, q Querier, files []models.WorkflowFile, now time.Time) error {
	if _, err := q.ExecContext(ctx, `DELETE FROM cached_workflow_files`); err != nil {
		return err
	}
	for _, f := range files {
		data, err := json.Marshal(f)
		if err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx,
			`INSERT INTO cached_workflow_files (repo_name, file_name, data, last_seen_at) VALUES (?, ?, ?, ?)`,
			f.RepoName, f.FileName, string(data), now,
		); err != nil {
			return err
		}
	}
	return nil
}

// ListCachedWorkflowFiles returns all cached workflow files.
func ListCachedWorkflowFiles(ctx context.Context, q Querier) ([]models.WorkflowFile, error) {
	rows, err := q.QueryContext(ctx, `SELECT data FROM cached_workflow_files ORDER BY repo_name, file_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.WorkflowFile
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var f models.WorkflowFile
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
