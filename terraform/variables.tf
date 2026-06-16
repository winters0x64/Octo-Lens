variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-south-1"
}

variable "vpc_id" {
  description = "VPC ID where the ALB and ECS tasks are deployed"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for ECS tasks and RDS (minimum 2 for RDS multi-AZ)"
  type        = list(string)
}

variable "alb_name" {
  description = "Name of the existing internal ALB (e.g. Securi-Secur-Iom0UrbXs87b)"
  type        = string
  default     = "Securi-Secur-Iom0UrbXs87b"
}

variable "github_org" {
  description = "GitHub organisation to monitor"
  type        = string
  default     = "scapia"
}

variable "github_app_id" {
  description = "GitHub App ID"
  type        = string
  default     = "3865240"
}

variable "scan_interval" {
  description = "How often to rescan (e.g. 30m, 1h)"
  type        = string
  default     = "30m"
}

# ── ECS ──────────────────────────────────────────────────────────────────────

variable "container_image" {
  description = "Full ECR image URI including tag (e.g. 123456789.dkr.ecr.ap-south-1.amazonaws.com/github-pat-monitor:latest)"
  type        = string
  default     = ""  # Populated after first ECR push; see outputs.tf for the repo URL
}

variable "task_cpu" {
  description = "ECS task CPU units (256 = 0.25 vCPU)"
  type        = number
  default     = 512
}

variable "task_memory" {
  description = "ECS task memory in MB"
  type        = number
  default     = 1024
}

variable "service_desired_count" {
  description = "Number of ECS task replicas"
  type        = number
  default     = 1
}

# ── RDS ──────────────────────────────────────────────────────────────────────

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t4g.micro"
}

variable "db_allocated_storage" {
  description = "RDS allocated storage in GB"
  type        = number
  default     = 20
}

variable "db_multi_az" {
  description = "Enable RDS Multi-AZ for high availability"
  type        = bool
  default     = true
}

variable "db_deletion_protection" {
  description = "Prevent accidental RDS deletion"
  type        = bool
  default     = true
}
