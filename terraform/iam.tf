data "aws_iam_policy_document" "ecs_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

# ── Task Execution Role ───────────────────────────────────────────────────────
# ECS uses this to pull images from ECR and fetch secrets from Secrets Manager.

resource "aws_iam_role" "task_execution" {
  name               = "${local.service_name}-task-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role.json
}

resource "aws_iam_role_policy_attachment" "task_execution_managed" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "secrets_read" {
  statement {
    sid    = "ReadSecrets"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
    ]
    resources = [
      aws_secretsmanager_secret.github_private_key.arn,
      aws_secretsmanager_secret.slack_webhook_url.arn,
      aws_secretsmanager_secret.auth_password.arn,
      aws_secretsmanager_secret.github_webhook_secret.arn,
      aws_secretsmanager_secret.db_url.arn,
    ]
    # db_url contains the full MySQL DSN for cspm-db (no separate db_password secret needed)
  }
}

resource "aws_iam_role_policy" "task_execution_secrets" {
  name   = "read-secrets"
  role   = aws_iam_role.task_execution.id
  policy = data.aws_iam_policy_document.secrets_read.json
}

# ── Task Role ─────────────────────────────────────────────────────────────────
# The running container's identity. No AWS API calls needed by the app,
# but the role is created so it can be extended later (e.g. for S3 exports).

resource "aws_iam_role" "task" {
  name               = "${local.service_name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role.json
}

data "aws_iam_policy_document" "task_cloudwatch" {
  statement {
    sid    = "WriteLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.app.arn}:*"]
  }
}

resource "aws_iam_role_policy" "task_cloudwatch" {
  name   = "write-logs"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.task_cloudwatch.json
}
