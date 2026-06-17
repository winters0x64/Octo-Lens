# Octo Lens

Centralized visibility into **fine-grained Personal Access Tokens (PATs)** and **installed GitHub Apps** across your GitHub organization. Provides both a CLI and a web dashboard.

## Features

- **Fine-grained PAT inventory**: List all approved PATs with owner, permissions, repo access, expiry, and last-used dates
- **Classic PAT visibility (SSO orgs)**: List all SAML SSO authorized credentials — classic PATs and SSH keys with scopes, owner, last accessed, expiry
- **Pending PAT requests**: View tokens awaiting approval
- **GitHub App audit**: List all installed apps with permission risk categorization (high/medium/low)
- **Web dashboard**: Interactive tables with sorting, filtering, and drill-down into per-PAT repository access
- **CLI output**: Table, JSON, and CSV formats for scripting and reporting
- **Security hardened**: Bearer token auth, TLS support, CSP headers, rate limiting, private key permission validation

## Prerequisites

### GitHub App Setup

This tool requires a **GitHub App** because GitHub's PAT listing APIs are exclusively available to GitHub Apps.

1. Go to your org's settings: `https://github.com/organizations/<YOUR_ORG>/settings/apps/new`
2. Set the following **Organization permissions**:
   - **Personal access tokens**: Read-only
   - **Administration**: Read-only
   - **Members**: Read-only
3. No webhook URL needed — uncheck "Active" under Webhooks
4. Under "Where can this GitHub App be installed?", select "Only on this account"
5. Create the app, then note the **App ID** from the app's General page
6. Generate a **private key** (.pem file) and download it
7. Install the app on your organization

### Private Key Security

Set the private key file permissions:

```bash
chmod 600 your-app.pem
```

The tool will **refuse to start** if the private key file is readable by group or others.

## Installation

```bash
go install github.com/th3-j0ik3r/github-pat-monitor@latest
```

Or build from source:

```bash
git clone https://github.com/th3-j0ik3r/github-pat-monitor.git
cd github-pat-monitor
go build -o github-pat-monitor .
```

## Usage

### Configuration

Set credentials via environment variables (recommended — avoids exposing secrets in process list):

```bash
export GITHUB_ORG=your-org
export GITHUB_APP_ID=123456
export GITHUB_APP_PRIVATE_KEY_PATH=./your-app.pem
# Optional: set if you don't want auto-discovery
# export GITHUB_INSTALLATION_ID=789
```

### CLI Scan

```bash
# Table output (default)
github-pat-monitor scan

# JSON output (for piping/scripting)
github-pat-monitor scan --output json

# CSV output (for spreadsheets)
github-pat-monitor scan --output csv
```

### Web Dashboard

```bash
# Local-only (default, no auth required)
github-pat-monitor serve

# With authentication (required for non-localhost)
export PAT_MONITOR_AUTH_TOKEN=your-secret-token
github-pat-monitor serve --addr 0.0.0.0 --port 8080

# With TLS
github-pat-monitor serve --addr 0.0.0.0 --port 8443 \
  --tls-cert cert.pem --tls-key key.pem \
  --auth-token your-secret-token
```

The dashboard will be available at `http://127.0.0.1:8080` (or your configured address).

## Security

- **Default bind**: `127.0.0.1` (localhost only)
- **Auth enforcement**: Server refuses to start on non-loopback addresses without `--auth-token`
- **Bearer token auth**: All `/api/*` endpoints require `Authorization: Bearer <token>`
- **TLS support**: `--tls-cert` and `--tls-key` flags
- **CSP headers**: `default-src 'self'` prevents XSS
- **Rate limiting**: `POST /api/scan` limited to 1 request per 60 seconds
- **Private key validation**: Refuses keys with permissions wider than 0600
- **No secrets in logs**: Custom logger redacts query parameters and auth headers

## API Endpoints

When running the dashboard, the following API endpoints are available:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/summary` | Organization summary statistics |
| GET | `/api/pats` | List all fine-grained PATs (in-memory, latest scan) |
| GET | `/api/pats?status=active\|expired\|removed` | List PATs by persisted status (requires Postgres) |
| GET | `/api/pats/{id}/repos` | Repositories accessible by a specific PAT |
| GET | `/api/pats/{id}/history` | Event log for a specific PAT (requires Postgres) |
| GET | `/api/pats/requests` | Pending PAT access requests |
| GET | `/api/events?since=&entity_type=&kind=&limit=` | Append-only event feed (requires Postgres) |
| GET | `/api/sso-credentials` | SSO authorized credentials (classic PATs, SSH keys) |
| GET | `/api/apps` | Installed GitHub Apps |
| GET | `/api/report` | Full organization report |
| POST | `/api/scan` | Trigger a fresh scan (rate limited) |

## Persistence (optional)

Setting `DATABASE_URL` enables Postgres persistence. The server keeps the
latest scan in memory for fast reads and writes a hybrid current+events
record to Postgres on every scan:

- **Current-state tables** (`pats`, `pat_requests`, `sso_credentials`) hold one row
  per entity with status: `active`, `expired`, `removed` — or `pending` /
  `resolved` for requests. Rows survive scans and persist when the process
  restarts.
- **Event log** (`events`) is append-only. Each row records a status flip or a
  watched-field change with a full JSONB snapshot of the entity at that moment
  and a list of policy rule IDs the new state trips. Point-in-time queries do
  not require replaying events.
- **Removed-entity safety:** the scanner reports per-phase completeness flags
  (`scan_runs.pats_complete`, etc.). Diff and removed-detection only run for
  phases that completed cleanly, so a rate-limit blip does not mass-remove
  surviving credentials.

Run `docker compose up -d` to start Postgres alongside the app; the embedded
goose migrations apply automatically on startup. Disable auto-apply with
`--auto-migrate=false` if you prefer to run migrations out-of-band.

### Useful queries

```sql
-- Has this PAT ever held admin permissions?
SELECT 1 FROM events
WHERE entity_type='pat' AND entity_id='123'
  AND policy_violations @> '["pat.deny_admin_permissions"]'::jsonb
LIMIT 1;

-- Which PATs gained permissions silently last week?
SELECT entity_id, occurred_at, changed_fields
FROM events
WHERE entity_type='pat' AND event_kind='field_change'
  AND 'permissions' = ANY(changed_fields)
  AND occurred_at > now() - interval '7 days';

-- What did this PAT look like on a given date?
SELECT snapshot FROM events
WHERE entity_type='pat' AND entity_id='123' AND occurred_at <= '2026-01-15'
ORDER BY occurred_at DESC LIMIT 1;
```

## Token Visibility Matrix

| Token Type | Requires | What's Visible |
|--|--|--|
| Fine-grained PATs | GitHub App | Full metadata: permissions, repos, expiry, last used |
| Classic PATs (SSO orgs) | SAML SSO enabled | Owner, last 8 chars, scopes, auth date, last accessed |
| Classic PATs (non-SSO orgs) | N/A | **Not visible** — no GitHub API exists for this |
| SSH Keys (SSO orgs) | SAML SSO enabled | Owner, fingerprint, auth date, last accessed |

## Limitations

- **Classic PATs without SSO**: If your org does not enforce SAML SSO, classic PATs cannot be enumerated by any tool (including StepSecurity). Consider [restricting classic PAT access](https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/setting-a-personal-access-token-policy-for-your-organization) at the org level.
- **SSO credential scopes**: The SSO endpoint shows OAuth scopes (e.g., `repo`, `admin:org`) but not which specific repos the classic PAT has accessed.
- **GitHub App required**: A personal access token (classic or fine-grained) cannot access the fine-grained PAT listing endpoints — only GitHub Apps can.
- **Rate limits**: GitHub App tokens get 5,000-15,000 requests/hour depending on org size. Large organizations with many PATs may need to be mindful of scan frequency.
