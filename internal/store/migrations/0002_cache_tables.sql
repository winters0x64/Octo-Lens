-- +goose Up

-- Simple snapshot cache for entity types that aren't event-sourced.
-- Each scan replaces all rows within the transaction, so the cache
-- always reflects the most recent completed scan for that phase.

CREATE TABLE IF NOT EXISTS cached_apps (
    app_id       BIGINT PRIMARY KEY,
    data         TEXT NOT NULL,
    last_seen_at DATETIME(3) NOT NULL
);

CREATE TABLE IF NOT EXISTS cached_secrets (
    name      VARCHAR(200) NOT NULL,
    scope     VARCHAR(64)  NOT NULL,
    repo_name VARCHAR(200) NOT NULL DEFAULT '',
    env_name  VARCHAR(200) NOT NULL DEFAULT '',
    data         TEXT NOT NULL,
    last_seen_at DATETIME(3) NOT NULL,
    PRIMARY KEY (name, scope, repo_name, env_name)
);

CREATE TABLE IF NOT EXISTS cached_deploy_keys (
    deploy_key_id BIGINT PRIMARY KEY,
    data         TEXT NOT NULL,
    last_seen_at DATETIME(3) NOT NULL
);

CREATE TABLE IF NOT EXISTS cached_workflow_permissions (
    repo_name    VARCHAR(255) PRIMARY KEY,
    data         TEXT NOT NULL,
    last_seen_at DATETIME(3) NOT NULL
);

CREATE TABLE IF NOT EXISTS cached_workflow_files (
    repo_name    VARCHAR(255) NOT NULL,
    file_name    VARCHAR(255) NOT NULL,
    data         TEXT NOT NULL,
    last_seen_at DATETIME(3) NOT NULL,
    PRIMARY KEY (repo_name, file_name)
);

-- +goose Down

DROP TABLE IF EXISTS cached_workflow_files;
DROP TABLE IF EXISTS cached_workflow_permissions;
DROP TABLE IF EXISTS cached_deploy_keys;
DROP TABLE IF EXISTS cached_secrets;
DROP TABLE IF EXISTS cached_apps;
