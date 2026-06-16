# ── Secrets Manager ──────────────────────────────────────────────────────────
#
# Secrets are created here. Populate sensitive ones manually before deploying:
#
#   aws secretsmanager put-secret-value \
#     --secret-id github-pat-monitor/github-private-key \
#     --secret-string "$(cat private-key.pem)"
#
# DATABASE_URL uses MySQL DSN format for cspm-db:
#   patmonitor:<password>@tcp(cspm-db.cr8wiq2qgt6u.ap-south-1.rds.amazonaws.com:3306)/patmonitor?parseTime=true&loc=UTC&charset=utf8mb4
#
# Populate it after creating the patmonitor DB/user in cspm-db:
#   aws secretsmanager put-secret-value \
#     --secret-id github-pat-monitor/database-url \
#     --secret-string "patmonitor:<password>@tcp(cspm-db.cr8wiq2qgt6u.ap-south-1.rds.amazonaws.com:3306)/patmonitor?parseTime=true&loc=UTC&charset=utf8mb4"
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_secretsmanager_secret" "github_private_key" {
  name                    = "${local.service_name}/github-private-key"
  description             = "GitHub App private key PEM for ${local.service_name}"
  recovery_window_in_days = 7
  tags                    = merge(local.common_tags, { Name = "${local.service_name}/github-private-key" })
}

resource "aws_secretsmanager_secret" "slack_webhook_url" {
  name                    = "${local.service_name}/slack-webhook-url"
  description             = "Slack incoming webhook URL for ${local.service_name} alerts"
  recovery_window_in_days = 7
  tags                    = merge(local.common_tags, { Name = "${local.service_name}/slack-webhook-url" })
}

resource "aws_secretsmanager_secret" "auth_password" {
  name                    = "${local.service_name}/auth-password"
  description             = "Dashboard login password for ${local.service_name}"
  recovery_window_in_days = 7
  tags                    = merge(local.common_tags, { Name = "${local.service_name}/auth-password" })
}

resource "aws_secretsmanager_secret" "github_webhook_secret" {
  name                    = "${local.service_name}/github-webhook-secret"
  description             = "HMAC secret for verifying GitHub webhook payloads"
  recovery_window_in_days = 7
  tags                    = merge(local.common_tags, { Name = "${local.service_name}/github-webhook-secret" })
}

# MySQL DSN for cspm-db — populate manually after creating the patmonitor DB/user
resource "aws_secretsmanager_secret" "db_url" {
  name                    = "${local.service_name}/database-url"
  description             = "MySQL DSN for patmonitor database in cspm-db"
  recovery_window_in_days = 7
  tags                    = merge(local.common_tags, { Name = "${local.service_name}/database-url" })
}
