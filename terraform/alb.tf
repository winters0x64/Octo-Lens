resource "aws_lb_target_group" "app" {
  name        = local.service_name
  port        = 8080
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"  # required for Fargate awsvpc networking

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
    cookie_duration = 28800  # 8 hours — matches session lifetime
    enabled         = true
  }

  tags = merge(local.common_tags, { Name = local.service_name })
}

resource "aws_lb_listener" "app" {
  load_balancer_arn = data.aws_lb.existing.arn
  port              = var.alb_listener_port
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }

  tags = merge(local.common_tags, { Name = local.service_name })
}
