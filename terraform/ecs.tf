resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${local.service_name}"
  retention_in_days = 30
}

resource "aws_ecs_cluster" "main" {
  name = local.service_name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

resource "aws_ecs_cluster_capacity_providers" "main" {
  cluster_name       = aws_ecs_cluster.main.name
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}

resource "aws_ecs_task_definition" "app" {
  family                   = local.service_name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = aws_iam_role.task.arn

  # The private key PEM is stored in Secrets Manager and injected as an env
  # variable. The entrypoint writes it to /app/private-key.pem before starting.
  container_definitions = jsonencode([
    {
      name  = local.service_name
      image = var.container_image != "" ? var.container_image : "${aws_ecr_repository.main.repository_url}:latest"

      essential = true

      portMappings = [
        {
          containerPort = 8080
          protocol      = "tcp"
        }
      ]

      # Override entrypoint to materialise the private key PEM file before
      # handing off to the actual binary.
      entryPoint = ["/bin/sh", "-c"]
      command = [
        join(" && ", [
          "printf '%s' \"$GITHUB_APP_PRIVATE_KEY_CONTENT\" > /app/private-key.pem",
          "chmod 600 /app/private-key.pem",
          "exec github-pat-monitor serve --addr=0.0.0.0 --port=8080 --auto-migrate=true --policy=/app/policy.yaml --scan-interval=${var.scan_interval}"
        ])
      ]

      environment = [
        { name = "GITHUB_ORG",                   value = var.github_org },
        { name = "GITHUB_APP_ID",                value = var.github_app_id },
        { name = "GITHUB_APP_PRIVATE_KEY_PATH",  value = "/app/private-key.pem" },
      ]

      secrets = [
        {
          name      = "GITHUB_APP_PRIVATE_KEY_CONTENT"
          valueFrom = aws_secretsmanager_secret.github_private_key.arn
        },
        {
          name      = "PAT_MONITOR_PASSWORD"
          valueFrom = aws_secretsmanager_secret.auth_password.arn
        },
        {
          name      = "SLACK_WEBHOOK_URL"
          valueFrom = aws_secretsmanager_secret.slack_webhook_url.arn
        },
        {
          name      = "GITHUB_WEBHOOK_SECRET"
          valueFrom = aws_secretsmanager_secret.github_webhook_secret.arn
        },
        {
          name      = "DATABASE_URL"
          valueFrom = aws_secretsmanager_secret.db_url.arn
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.app.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "wget -qO- http://localhost:8080/health > /dev/null 2>&1 || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 120  # allow time for the initial scan to complete
      }
    }
  ])

  tags = merge(local.common_tags, { Name = local.service_name })
}

resource "aws_ecs_service" "app" {
  name            = local.service_name
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = var.service_desired_count
  launch_type     = "FARGATE"

  # Allow Terraform to update the service without forcing a new deployment
  # when only the task definition revision changes.
  force_new_deployment = true

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = local.service_name
    container_port   = 8080
  }

  # Ensure the listener exists before the service starts
  depends_on = [aws_lb_listener.app]

  lifecycle {
    ignore_changes = [
      # Allow external deployments (e.g. CI/CD) to update task definition
      task_definition,
      desired_count,
    ]
  }

  tags = merge(local.common_tags, { Name = local.service_name })
}
