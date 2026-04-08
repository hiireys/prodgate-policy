package prodgate.authz

default allow = false
valid_environment {
  input.resource.environment == "dev"
}

valid_environment {
  input.resource.environment == "test"
}

valid_environment {
  input.resource.environment == "uat"
}

valid_environment {
  input.resource.environment == "prod"
}

valid_action {
  input.action == "deploy"
}

valid_action {
  input.action == "edit_config"
}

valid_action {
  input.action == "restart_service"
}

valid_action {
  input.action == "read_secret"
}

valid_action {
  input.action == "approve_release"
}

valid_action {
  input.action == "qa_approve"
}

service_exists {
  data.services[input.resource.service]
}

service_owner_team = owner {
  svc := data.services[input.resource.service]
  owner := svc.owner_team
}

service_owner_team = "unknown" {
  not service_exists
}

user_is_release_manager {
  input.user.team == "release-managers"
}

user_is_devops {
  input.user.team == "devops"
}

user_is_sre {
  input.user.team == "sre"
}

user_is_qa {
  input.user.team == "qa"
}

user_is_owner_dev_team {
  input.user.team == "application-dev"
  input.user.team == service_owner_team
}

user_is_owner_dev_team {
  input.user.team == "data-science-dev"
  input.user.team == service_owner_team
}

prod_change_action {
  input.resource.environment == "prod"
  input.action == "deploy"
}

prod_change_action {
  input.resource.environment == "prod"
  input.action == "edit_config"
}

prod_change_action {
  input.resource.environment == "prod"
  input.action == "restart_service"
}

approved_for_action {
  input.approval.approved == true
  input.approval.approved_by != ""
  input.approval.approval_type == input.action
}

same_user_approved_and_executes {
  prod_change_action
  approved_for_action
  input.approval.approved_by == input.user.id
}

deny[msg] {
  not valid_environment
  msg := "unknown_environment"
}

deny[msg] {
  not valid_action
  msg := "unsupported_action"
}

deny[msg] {
  not service_exists
  msg := "service_not_found"
}

deny[msg] {
  prod_change_action
  not approved_for_action
  msg := "prod_action_requires_release_manager_approval"
}

deny[msg] {
  same_user_approved_and_executes
  msg := "same_user_cannot_approve_and_execute_prod_action"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  input.resource.environment == "dev"
  input.action == "deploy"
  user_is_owner_dev_team
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  input.resource.environment == "dev"
  input.action == "edit_config"
  user_is_owner_dev_team
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  input.resource.environment == "test"
  user_is_qa
  input.action == "deploy"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  input.resource.environment == "test"
  user_is_qa
  input.action == "edit_config"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  input.resource.environment == "test"
  user_is_qa
  input.action == "restart_service"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  input.resource.environment == "uat"
  user_is_sre
  input.action == "deploy"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  input.resource.environment == "uat"
  user_is_sre
  input.action == "edit_config"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  input.resource.environment == "uat"
  user_is_sre
  input.action == "restart_service"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  input.resource.environment == "uat"
  user_is_sre
  input.action == "read_secret"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  input.resource.environment == "prod"
  user_is_sre
  input.action == "deploy"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  input.resource.environment == "prod"
  user_is_sre
  input.action == "edit_config"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  input.resource.environment == "prod"
  user_is_sre
  input.action == "restart_service"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  input.resource.environment == "prod"
  user_is_sre
  input.action == "read_secret"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  user_is_devops
  input.action == "deploy"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  user_is_devops
  input.action == "edit_config"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  user_is_devops
  input.action == "restart_service"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  user_is_devops
  input.action == "read_secret"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  input.resource.environment == "uat"
  user_is_qa
  input.action == "qa_approve"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  input.resource.environment == "prod"
  user_is_qa
  input.action == "qa_approve"
}

allow {
  valid_environment
  valid_action
  service_exists
  count(deny) == 0
  user_is_release_manager
  input.resource.environment == "prod"
  input.action == "approve_release"
}

reasons = [msg] {
  deny[msg]
}

reasons = ["allowed_by_policy"] {
  allow
}

reasons = ["no_matching_policy"] {
  not allow
  count(deny) == 0
}

decision = {
  "allow": allow,
  "reasons": reasons,
  "service_owner_team": service_owner_team
}
