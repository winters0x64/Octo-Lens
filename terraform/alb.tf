# ─── Shared ALB HTTPS listener (managed by security-metabase CDK stack) ──────
data "aws_lb_listener" "https" {
  load_balancer_arn = data.aws_lb.existing.arn
  port              = 443
}

# ─── Target group ─────────────────────────────────────────────────────────────
resource "aws_lb_target_group" "app" {
  name        = local.service_name
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  health_check {
    enabled             = true
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    matcher             = "200"
    interval            = 30
    timeout             = 10
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }

  deregistration_delay = 30

  stickiness {
    type            = "lb_cookie"
    cookie_duration = 28800
    enabled         = true
  }

  tags = merge(local.common_tags, { Name = local.service_name })
}

# ─── Host-based listener rule ──────────────────────────────────────────────────
resource "aws_lb_listener_rule" "app" {
  listener_arn = data.aws_lb_listener.https.arn
  priority     = 50

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }

  condition {
    host_header {
      values = ["github-monitor.security.scapia.in"]
    }
  }

  tags = merge(local.common_tags, { Name = local.service_name })
}
