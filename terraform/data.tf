data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_lb" "existing" {
  name = var.alb_name
}
