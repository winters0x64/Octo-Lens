# ── ECS tasks ────────────────────────────────────────────────────────────────

resource "aws_security_group" "ecs_tasks" {
  name        = "${local.service_name}-ecs-tasks"
  description = "Allow ALB to ECS tasks on port 8080"
  vpc_id      = var.vpc_id

  ingress {
    description     = "HTTP from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = tolist(data.aws_lb.existing.security_groups)
  }

  egress {
    description = "All outbound (GitHub API, AWS APIs, MySQL)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "${local.service_name}-ecs-tasks" })
}

# ── Allow ECS tasks into cspm-db on port 3306 ─────────────────────────────────
# Adds an ingress rule to the existing cspm-db security group so our ECS tasks
# can connect to MySQL. Uses a separate rule resource to avoid owning the SG.

data "aws_db_instance" "cspm_db" {
  db_instance_identifier = "cspm-db"
}

resource "aws_security_group_rule" "cspm_db_from_ecs" {
  type                     = "ingress"
  description              = "MySQL from github-pat-monitor ECS tasks"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  security_group_id        = data.aws_db_instance.cspm_db.vpc_security_groups[0]
  source_security_group_id = aws_security_group.ecs_tasks.id
}
