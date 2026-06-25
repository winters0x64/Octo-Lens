output "service_url" {
  description = "URL to access the PAT Monitor dashboard"
  value       = "https://octolens.security.scapia.in"
}

output "ecr_repository_url" {
  description = "ECR repository URL — use this to build and push the Docker image"
  value       = aws_ecr_repository.main.repository_url
}

output "ecr_push_commands" {
  description = "Commands to build and push the Docker image to ECR"
  value = <<-EOT
    # Authenticate Docker to ECR
    aws ecr get-login-password --region ${var.aws_region} | \
      docker login --username AWS --password-stdin ${aws_ecr_repository.main.repository_url}

    # Build and push
    docker build -t ${aws_ecr_repository.main.repository_url}:latest .
    docker push ${aws_ecr_repository.main.repository_url}:latest
  EOT
}

output "secrets_to_populate" {
  description = "Secrets Manager secrets that must be populated before the service can start"
  value = {
    github_private_key     = aws_secretsmanager_secret.github_private_key.name
    slack_webhook_url      = aws_secretsmanager_secret.slack_webhook_url.name
    auth_password          = aws_secretsmanager_secret.auth_password.name
    github_webhook_secret  = aws_secretsmanager_secret.github_webhook_secret.name
  }
}

output "secret_population_commands" {
  description = "AWS CLI commands to populate required secrets"
  sensitive   = false
  value = <<-EOT
    # GitHub App private key (run from project root)
    aws secretsmanager put-secret-value \
      --region ${var.aws_region} \
      --secret-id ${aws_secretsmanager_secret.github_private_key.name} \
      --secret-string "$(cat private-key.pem)"

    # Slack webhook URL
    aws secretsmanager put-secret-value \
      --region ${var.aws_region} \
      --secret-id ${aws_secretsmanager_secret.slack_webhook_url.name} \
      --secret-string "https://hooks.slack.com/services/..."

    # Dashboard password
    aws secretsmanager put-secret-value \
      --region ${var.aws_region} \
      --secret-id ${aws_secretsmanager_secret.auth_password.name} \
      --secret-string "Admin@patter2026!"

    # GitHub webhook secret (generate a random value)
    aws secretsmanager put-secret-value \
      --region ${var.aws_region} \
      --secret-id ${aws_secretsmanager_secret.github_webhook_secret.name} \
      --secret-string "$(openssl rand -hex 32)"
  EOT
}

output "cspm_db_endpoint" {
  description = "cspm-db MySQL endpoint — create patmonitor DB/user here"
  value       = "cspm-db.cr8wiq2qgt6u.ap-south-1.rds.amazonaws.com:3306"
}

output "mysql_setup_commands" {
  description = "SQL to run on cspm-db to create the patmonitor DB and user"
  value = <<-EOT
    -- Run these on cspm-db as the master user:
    CREATE DATABASE IF NOT EXISTS patmonitor CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    CREATE USER IF NOT EXISTS 'patmonitor'@'%' IDENTIFIED BY '<choose-a-strong-password>';
    GRANT ALL PRIVILEGES ON patmonitor.* TO 'patmonitor'@'%';
    FLUSH PRIVILEGES;

    -- Then populate the DATABASE_URL secret:
    aws secretsmanager put-secret-value \
      --region ap-south-1 \
      --secret-id github-pat-monitor/database-url \
      --secret-string "patmonitor:<password>@tcp(cspm-db.cr8wiq2qgt6u.ap-south-1.rds.amazonaws.com:3306)/patmonitor?parseTime=true&loc=UTC&charset=utf8mb4"
  EOT
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.main.name
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for container logs"
  value       = aws_cloudwatch_log_group.app.name
}
