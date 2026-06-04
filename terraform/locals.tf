locals {
  service_name = "github-pat-monitor"

  common_tags = {
    CostCenter  = "security"
    Group       = "security"
    Pod         = "security"
    Environment = "prod"
    ServiceName = local.service_name
  }
}
