-- +goose Up

CREATE TABLE IF NOT EXISTS scan_runs (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    started_at DATETIME(3) NOT NULL,
    finished_at DATETIME(3),
    pats_complete TINYINT(1) NOT NULL DEFAULT 0,
    pat_requests_complete TINYINT(1) NOT NULL DEFAULT 0,
    sso_complete TINYINT(1) NOT NULL DEFAULT 0,
    apps_complete TINYINT(1) NOT NULL DEFAULT 0,
    secrets_complete TINYINT(1) NOT NULL DEFAULT 0,
    deploy_keys_complete TINYINT(1) NOT NULL DEFAULT 0,
    workflows_complete TINYINT(1) NOT NULL DEFAULT 0,
    repos_scanned TEXT NOT NULL,
    error_summary TEXT
);

CREATE TABLE IF NOT EXISTS pats (
    pat_id BIGINT PRIMARY KEY,
    token_name TEXT NOT NULL,
    owner_login VARCHAR(255) NOT NULL,
    owner_avatar_url TEXT NOT NULL,
    repository_selection TEXT NOT NULL,
    permissions TEXT NOT NULL,
    access_granted_at DATETIME(3) NOT NULL,
    token_expires_at DATETIME(3),
    token_last_used_at DATETIME(3),
    status ENUM('active','expired','removed') NOT NULL,
    first_seen_at DATETIME(3) NOT NULL,
    last_seen_at DATETIME(3) NOT NULL,
    last_changed_at DATETIME(3) NOT NULL
);

CREATE INDEX IF NOT EXISTS pats_status_idx ON pats(status);
CREATE INDEX IF NOT EXISTS pats_owner_idx  ON pats(owner_login(255));

CREATE TABLE IF NOT EXISTS pat_requests (
    request_id BIGINT PRIMARY KEY,
    token_name TEXT NOT NULL,
    owner_login TEXT NOT NULL,
    repository_selection TEXT NOT NULL,
    permissions TEXT NOT NULL,
    created_at DATETIME(3) NOT NULL,
    token_expires_at DATETIME(3),
    status ENUM('pending','resolved') NOT NULL,
    resolved_pat_id BIGINT,
    first_seen_at DATETIME(3) NOT NULL,
    last_seen_at DATETIME(3) NOT NULL,
    last_changed_at DATETIME(3) NOT NULL,
    CONSTRAINT fk_pat_requests_resolved_pat FOREIGN KEY (resolved_pat_id) REFERENCES pats(pat_id)
);

CREATE INDEX IF NOT EXISTS pat_requests_status_idx ON pat_requests(status);

CREATE TABLE IF NOT EXISTS sso_credentials (
    credential_id BIGINT PRIMARY KEY,
    login TEXT NOT NULL,
    credential_type TEXT NOT NULL,
    token_last_eight TEXT NOT NULL,
    credential_authorized_at DATETIME(3) NOT NULL,
    credential_accessed_at DATETIME(3),
    authorized_credential_title TEXT NOT NULL,
    authorized_credential_note TEXT NOT NULL,
    authorized_credential_expires_at DATETIME(3),
    scopes TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status ENUM('active','expired','removed') NOT NULL,
    first_seen_at DATETIME(3) NOT NULL,
    last_seen_at DATETIME(3) NOT NULL,
    last_changed_at DATETIME(3) NOT NULL
);

CREATE INDEX IF NOT EXISTS sso_credentials_status_idx ON sso_credentials(status);

CREATE TABLE IF NOT EXISTS events (
    id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    scan_run_id BIGINT NOT NULL,
    occurred_at DATETIME(3) NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_kind ENUM('created','status_change','field_change','removed') NOT NULL,
    old_status TEXT,
    new_status TEXT,
    changed_fields TEXT NOT NULL,
    snapshot TEXT NOT NULL,
    policy_violations TEXT NOT NULL,
    CONSTRAINT fk_events_scan_run FOREIGN KEY (scan_run_id) REFERENCES scan_runs(id)
);

CREATE INDEX IF NOT EXISTS events_entity_idx   ON events(entity_type(64), entity_id(64), occurred_at DESC);
CREATE INDEX IF NOT EXISTS events_occurred_idx ON events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS events_scan_run_idx ON events(scan_run_id);

-- +goose Down

DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS sso_credentials;
DROP TABLE IF EXISTS pat_requests;
DROP TABLE IF EXISTS pats;
DROP TABLE IF EXISTS scan_runs;
