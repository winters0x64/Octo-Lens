-- +goose Up

CREATE TABLE scan_runs (
    id BIGSERIAL PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    pats_complete BOOLEAN NOT NULL DEFAULT false,
    pat_requests_complete BOOLEAN NOT NULL DEFAULT false,
    sso_complete BOOLEAN NOT NULL DEFAULT false,
    apps_complete BOOLEAN NOT NULL DEFAULT false,
    secrets_complete BOOLEAN NOT NULL DEFAULT false,
    deploy_keys_complete BOOLEAN NOT NULL DEFAULT false,
    workflows_complete BOOLEAN NOT NULL DEFAULT false,
    repos_scanned TEXT[] NOT NULL DEFAULT '{}',
    error_summary TEXT
);

CREATE TABLE pats (
    pat_id BIGINT PRIMARY KEY,
    token_name TEXT NOT NULL,
    owner_login TEXT NOT NULL,
    owner_avatar_url TEXT NOT NULL,
    repository_selection TEXT NOT NULL,
    permissions JSONB NOT NULL,
    access_granted_at TIMESTAMPTZ NOT NULL,
    token_expires_at TIMESTAMPTZ,
    token_last_used_at TIMESTAMPTZ,
    status TEXT NOT NULL CHECK (status IN ('active','expired','removed')),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    last_changed_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX pats_status_idx ON pats(status);
CREATE INDEX pats_owner_idx  ON pats(owner_login);

CREATE TABLE pat_requests (
    request_id BIGINT PRIMARY KEY,
    token_name TEXT NOT NULL,
    owner_login TEXT NOT NULL,
    repository_selection TEXT NOT NULL,
    permissions JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    token_expires_at TIMESTAMPTZ,
    status TEXT NOT NULL CHECK (status IN ('pending','resolved')),
    resolved_pat_id BIGINT REFERENCES pats(pat_id),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    last_changed_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX pat_requests_status_idx ON pat_requests(status);

CREATE TABLE sso_credentials (
    credential_id BIGINT PRIMARY KEY,
    login TEXT NOT NULL,
    credential_type TEXT NOT NULL,
    token_last_eight TEXT NOT NULL,
    credential_authorized_at TIMESTAMPTZ NOT NULL,
    credential_accessed_at TIMESTAMPTZ,
    authorized_credential_title TEXT NOT NULL,
    authorized_credential_note TEXT NOT NULL,
    authorized_credential_expires_at TIMESTAMPTZ,
    scopes JSONB NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active','expired','removed')),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    last_changed_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX sso_credentials_status_idx ON sso_credentials(status);

CREATE TABLE events (
    id BIGSERIAL PRIMARY KEY,
    scan_run_id BIGINT NOT NULL REFERENCES scan_runs(id),
    occurred_at TIMESTAMPTZ NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_kind TEXT NOT NULL CHECK (event_kind IN ('created','status_change','field_change','removed')),
    old_status TEXT,
    new_status TEXT,
    changed_fields TEXT[] NOT NULL DEFAULT '{}',
    snapshot JSONB NOT NULL,
    policy_violations JSONB NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX events_entity_idx   ON events(entity_type, entity_id, occurred_at DESC);
CREATE INDEX events_occurred_idx ON events(occurred_at DESC);
CREATE INDEX events_scan_run_idx ON events(scan_run_id);

-- +goose Down

DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS sso_credentials;
DROP TABLE IF EXISTS pat_requests;
DROP TABLE IF EXISTS pats;
DROP TABLE IF EXISTS scan_runs;
