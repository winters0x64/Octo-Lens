# Deployment Guide

This guide covers deploying GitHub PAT Monitor as a self-hosted service with continuous monitoring, policy enforcement, and Slack alerting.

## Architecture Overview

```
┌──────────────────────────────────────────────────────┐
│  GitHub                                               │
│  ┌──────────────┐    ┌─────────────────────────────┐ │
│  │ GitHub App    │    │ Webhooks                    │ │
│  │ (your org)    │    │ PAT / Member / Org events   │ │
│  └──────┬───────┘    └──────────────┬──────────────┘ │
└─────────┼───────────────────────────┼────────────────┘
          │ API calls                 │ POST events
          ▼                           ▼
┌──────────────────────────────────────────────────────┐
│  Your Server (Docker / VM / K8s)                      │
│  ┌───────────┐  ┌───────────┐  ┌──────────────────┐ │
│  │ Scheduled  │  │ Webhook   │  │ Policy Engine    │ │
│  │ Scanner    │  │ Receiver  │  │ (policy.yaml)    │ │
│  └─────┬─────┘  └─────┬─────┘  └────────┬─────────┘ │
│        │               │                 │            │
│        ▼               ▼                 ▼            │
│  ┌───────────┐  ┌───────────┐  ┌──────────────────┐ │
│  │ Web       │  │ REST API  │  │ Slack Notifier   │ │
│  │ Dashboard │  │ /api/*    │  │ (diff-based)     │ │
│  └───────────┘  └───────────┘  └──────────────────┘ │
└──────────────────────────────────────────────────────┘
```

## Prerequisites

- A GitHub organization
- Access to create GitHub Apps (requires org owner role)
- A server, VM, or container runtime to host the service
- (Optional) A Slack workspace for alerts

---

## Step 1: Create a GitHub App

1. Go to `https://github.com/organizations/<YOUR_ORG>/settings/apps/new`

2. Fill in the basic info:

   | Field | Value |
   |-------|-------|
   | **App name** | `pat-monitor` (or any name you prefer) |
   | **Homepage URL** | `https://github.com/th3-j0k3r/github-pat-monitor` |

3. Configure the webhook (optional but recommended for real-time updates):

   | Field | Value |
   |-------|-------|
   | **Webhook URL** | `https://<YOUR_SERVER>:8080/webhooks/github` |
   | **Webhook secret** | Generate a random string and save it |
   | **Active** | Checked |

   If you don't want webhooks, uncheck **Active**. The server will still rescan on a schedule.

4. Set **Organization permissions**:

   | Permission | Access |
   |------------|--------|
   | Personal access tokens | **Read-only** |
   | Administration | **Read-only** |
   | Members | **Read-only** |
   | Secrets | **Read-only** |

   Set **Repository permissions**:

   | Permission | Access |
   |------------|--------|
   | Metadata | **Read-only** (auto-granted) |
   | Administration | **Read-only** (for deploy keys + workflow permissions) |
   | Contents | **Read-only** (for workflow file auditing) |
   | Secrets | **Read-only** (for repo/env secret metadata) |
   | Environments | **Read-only** (for environment secret metadata) |

5. Subscribe to events (only if webhook is enabled):

   - [x] Personal access token request
   - [x] Member
   - [x] Organization

6. Under **"Where can this GitHub App be installed?"**, select **Only on this account**

7. Click **Create GitHub App**

8. On the app's General page, note the **App ID**

## Step 2: Generate a Private Key

1. On the app's settings page, scroll to **Private keys**
2. Click **Generate a private key**
3. A `.pem` file will download — save it securely
4. Set file permissions:

```bash
chmod 600 your-app.pem
```

The tool refuses to start if the key file is readable by group or others.

## Step 3: Install the App on Your Org

1. Go to `https://github.com/organizations/<YOUR_ORG>/settings/installations`
2. Find your app and click **Install**
3. Choose **All repositories** (recommended) or select specific repositories
4. Click **Install**

The installation ID is auto-discovered. You don't need to note it.

---

## Deployment Options

### Option A: Docker Compose (Recommended)

This is the simplest production deployment.

**1. Clone and configure:**

```bash
git clone https://github.com/th3-j0k3r/github-pat-monitor.git
cd github-pat-monitor

cp .env.example .env
cp policy.yaml.example policy.yaml
```

**2. Edit `.env` with your credentials:**

```bash
# Required
GITHUB_ORG=your-org
GITHUB_APP_ID=123456
GITHUB_APP_PRIVATE_KEY_PATH=/app/private-key.pem
PAT_MONITOR_AUTH_TOKEN=your-secret-dashboard-token

# Optional: webhook signature verification
GITHUB_WEBHOOK_SECRET=your-webhook-secret

# Optional: Slack alerts
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../xxx
```

**3. Copy your private key into the project directory:**

```bash
cp /path/to/your-app.pem ./private-key.pem
chmod 600 private-key.pem
```

**4. Update `docker-compose.yml` to mount the key:**

```yaml
services:
  pat-monitor:
    build: .
    restart: unless-stopped
    ports:
      - "8080:8080"
    env_file:
      - .env
    volumes:
      - ./policy.yaml:/app/policy.yaml:ro
      - ./private-key.pem:/app/private-key.pem:ro
    command:
      - serve
      - --addr=0.0.0.0
      - --port=8080
      - --scan-interval=1h
      - --policy=/app/policy.yaml
```

**5. Start:**

```bash
docker compose up -d
```

**6. Verify:**

```bash
docker compose logs -f
# Should see: "Initial scan complete: X PATs, Y apps"
# Should see: "Dashboard available at http://0.0.0.0:8080"
```

Open `http://your-server:8080` in your browser.

### Option B: Docker Run (Quick Start)

```bash
docker build -t pat-monitor .

docker run -d \
  --name pat-monitor \
  --restart unless-stopped \
  -p 8080:8080 \
  -e GITHUB_ORG=your-org \
  -e GITHUB_APP_ID=123456 \
  -e GITHUB_APP_PRIVATE_KEY="$(cat your-app.pem)" \
  -e PAT_MONITOR_AUTH_TOKEN=your-secret-token \
  -e SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../xxx \
  -e GITHUB_WEBHOOK_SECRET=your-webhook-secret \
  -v $(pwd)/policy.yaml:/app/policy.yaml:ro \
  pat-monitor \
  serve --addr 0.0.0.0 --scan-interval 1h --policy /app/policy.yaml
```

Note: `GITHUB_APP_PRIVATE_KEY` accepts the raw PEM content (no file mount needed).

### Option C: Binary on a VM

```bash
# Install
curl -fsSL https://github.com/th3-j0k3r/github-pat-monitor/releases/latest/download/github-pat-monitor-linux-amd64.tar.gz | tar xz
sudo mv github-pat-monitor /usr/local/bin/

# Configure
export GITHUB_ORG=your-org
export GITHUB_APP_ID=123456
export GITHUB_APP_PRIVATE_KEY_PATH=/etc/pat-monitor/app.pem
export PAT_MONITOR_AUTH_TOKEN=your-secret-token
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../xxx
export GITHUB_WEBHOOK_SECRET=your-webhook-secret

# Run
github-pat-monitor serve \
  --addr 0.0.0.0 \
  --port 8080 \
  --scan-interval 1h \
  --policy /etc/pat-monitor/policy.yaml
```

For a systemd service, create `/etc/systemd/system/pat-monitor.service`:

```ini
[Unit]
Description=GitHub PAT Monitor
After=network.target

[Service]
Type=simple
User=patmonitor
EnvironmentFile=/etc/pat-monitor/env
ExecStart=/usr/local/bin/github-pat-monitor serve \
  --addr 0.0.0.0 --port 8080 \
  --scan-interval 1h \
  --policy /etc/pat-monitor/policy.yaml
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now pat-monitor
```

---

## Configuration Reference

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GITHUB_ORG` | Yes | GitHub organization name |
| `GITHUB_APP_ID` | Yes | GitHub App ID |
| `GITHUB_APP_PRIVATE_KEY_PATH` | Yes* | Path to `.pem` private key file |
| `GITHUB_APP_PRIVATE_KEY` | Yes* | Raw PEM content (alternative to path) |
| `GITHUB_INSTALLATION_ID` | No | Installation ID (auto-discovered if omitted) |
| `PAT_MONITOR_AUTH_TOKEN` | Yes** | Bearer token for dashboard/API auth |
| `SLACK_WEBHOOK_URL` | No | Slack incoming webhook URL for alerts |
| `GITHUB_WEBHOOK_SECRET` | No | Secret for verifying GitHub webhook signatures |
| `PAT_MONITOR_POLICY_PATH` | No | Path to policy YAML file |

\* One of `GITHUB_APP_PRIVATE_KEY_PATH` or `GITHUB_APP_PRIVATE_KEY` is required.
\** Required when binding to non-localhost addresses.

### Server Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `127.0.0.1` | Bind address |
| `--port` | `8080` | Listen port |
| `--auth-token` | | Bearer token for API auth |
| `--tls-cert` | | Path to TLS certificate |
| `--tls-key` | | Path to TLS private key |
| `--scan-interval` | `1h` | Auto-rescan interval (e.g., `5m`, `1h`, `0` to disable) |
| `--policy` | | Path to policy YAML file |
| `--slack-webhook` | | Slack webhook URL for alerts |
| `--webhook-secret` | | GitHub webhook secret |

### Policy File Format

See `policy.yaml.example` for a complete reference:

```yaml
pat:
  max_expiry_days: 90
  deny_no_expiry: true
  deny_all_repo_access: true
  deny_admin_permissions: true
  max_inactive_days: 30

app:
  deny_all_repo_access: true
  max_high_risk_permissions: 0

sso:
  deny_classic_pats: false

secrets:
  deny_org_wide_visibility: true   # Deny org secrets visible to all repos
  max_stale_days: 365              # Flag secrets not rotated in N days

deploy_keys:
  deny_write_access: true          # Deny deploy keys with push access

workflows:
  deny_write_all_default: true     # Deny repos with GITHUB_TOKEN write-all
  deny_unpinned_actions: true      # Require SHA-pinned action references
  deny_can_approve_prs: true       # Deny GITHUB_TOKEN PR approval
```

---

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/summary` | Bearer | Organization summary statistics |
| GET | `/api/pats` | Bearer | List all fine-grained PATs |
| GET | `/api/pats/{id}/repos` | Bearer | Repositories accessible by a PAT |
| GET | `/api/pats/requests` | Bearer | Pending PAT access requests |
| GET | `/api/sso-credentials` | Bearer | SSO authorized credentials |
| GET | `/api/apps` | Bearer | Installed GitHub Apps |
| GET | `/api/secrets` | Bearer | Actions secrets (org + repo + environment) |
| GET | `/api/deploy-keys` | Bearer | Deploy keys across all repos |
| GET | `/api/workflow-permissions` | Bearer | Default GITHUB_TOKEN permissions per repo |
| GET | `/api/workflow-files` | Bearer | Workflow security audit (permissions + pinning) |
| GET | `/api/violations` | Bearer | Current policy violations |
| GET | `/api/report` | Bearer | Full organization report |
| POST | `/api/scan` | Bearer | Trigger a fresh scan (rate limited: 1/60s) |
| POST | `/webhooks/github` | Signature | GitHub webhook receiver |

---

## Webhook Setup

If you want real-time updates (rescan immediately when PATs change), configure the webhook on your GitHub App:

1. Go to your App's settings → **General** → **Webhook**
2. Set **Webhook URL** to `https://<YOUR_SERVER>:8080/webhooks/github`
3. Set **Webhook secret** to the same value as `GITHUB_WEBHOOK_SECRET`
4. Ensure **Active** is checked

**Events that trigger a rescan:**
- `personal_access_token_request` — new PAT request created/approved/denied
- `installation` / `installation_repositories` — app install changes
- `member` / `membership` — org membership changes
- `organization` — org-level changes

**Verify delivery:**
Go to App settings → **Advanced** → **Recent Deliveries** to confirm GitHub can reach your server.

---

## CI/CD Integration

Use the scan command as a CI gate. It exits with code `1` when policy violations are found:

```bash
github-pat-monitor scan --policy policy.yaml --output table
# Exit 0 = clean
# Exit 1 = violations found
# Exit 2 = scan error
```

### GitHub Actions Example

```yaml
name: PAT Security Scan
on:
  schedule:
    - cron: '0 3 * * 1'  # Weekly Monday 3 AM
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Generate GitHub App Token
        id: app-token
        uses: actions/create-github-app-token@v3
        with:
          app-id: ${{ vars.PAT_MONITOR_APP_ID }}
          private-key: ${{ secrets.PAT_MONITOR_PRIVATE_KEY }}
          owner: ${{ github.repository_owner }}

      - name: Install PAT Monitor
        run: |
          curl -fsSL https://github.com/th3-j0k3r/github-pat-monitor/releases/latest/download/github-pat-monitor-linux-amd64.tar.gz | tar xz
          chmod +x github-pat-monitor

      - name: Run Scan
        env:
          GITHUB_ORG: ${{ github.repository_owner }}
          GITHUB_APP_ID: ${{ vars.PAT_MONITOR_APP_ID }}
          GITHUB_APP_PRIVATE_KEY: ${{ secrets.PAT_MONITOR_PRIVATE_KEY }}
        run: ./github-pat-monitor scan --policy policy.yaml --output table
```

---

## Security Recommendations

### TLS

Always use TLS when exposing the dashboard beyond localhost:

```bash
github-pat-monitor serve \
  --addr 0.0.0.0 \
  --tls-cert /etc/ssl/cert.pem \
  --tls-key /etc/ssl/key.pem \
  --auth-token your-secret-token
```

Or terminate TLS at a reverse proxy (nginx, Caddy, Traefik).

### Reverse Proxy (nginx)

```nginx
server {
    listen 443 ssl;
    server_name pat-monitor.example.com;

    ssl_certificate     /etc/ssl/cert.pem;
    ssl_certificate_key /etc/ssl/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Private Key Security

- Store the `.pem` file with `chmod 600` permissions
- In Docker, mount it read-only: `-v ./key.pem:/app/key.pem:ro`
- For Kubernetes, use a Secret mounted as a file
- Alternatively, pass the raw PEM content via `GITHUB_APP_PRIVATE_KEY` env var (useful for secret managers)

### Network

- The server binds to `127.0.0.1` by default (localhost only)
- It refuses to start on non-loopback addresses without `--auth-token`
- CSP headers (`default-src 'self'`) prevent XSS
- CORS is denied for all cross-origin requests
- The `/api/scan` endpoint is rate-limited to 1 request per 60 seconds

---

## Troubleshooting

### "refusing to start: binding to 0.0.0.0 without --auth-token is insecure"

Set `PAT_MONITOR_AUTH_TOKEN` or `--auth-token` when binding to non-localhost addresses.

### "private key file has permissions 0644, which are too open"

```bash
chmod 600 your-app.pem
```

### "finding installation for org: 404 Not Found"

The GitHub App is not installed on the org. Go to the app's **Install App** page and install it.

### Initial scan shows 0 PATs

- Verify the app has **Personal access tokens: Read-only** permission
- Verify the app is installed on the correct org
- Check if the org actually has fine-grained PATs (classic PATs require SSO to be visible)

### Webhook deliveries failing

- Ensure your server is reachable from the internet
- Check the webhook secret matches `GITHUB_WEBHOOK_SECRET`
- Go to App settings → **Advanced** → **Recent Deliveries** to see error details
- For local testing, use a tunnel like [smee.io](https://smee.io) or [ngrok](https://ngrok.com)

### Slack alerts not sending

- Verify `SLACK_WEBHOOK_URL` is set correctly
- Alerts are diff-based: they only fire when **new** violations appear, not on every scan
- Check server logs for `WARNING: Slack notification failed`
