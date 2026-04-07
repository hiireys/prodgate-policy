package prodgate.authz

default permit = false

allow_decision {
  permit
  count(deny) == 0
}

decision := {
  "allow": allow_decision,
  "reasons": reasons,
  "service_owner_team": service_owner_team,
}

service_owner_team := object.get(object.get(data.services, input.resource.service, {}), "owner_team", "unknown")

reasons := ["allowed_by_policy"] {
  permit
  count(deny) == 0
}

reasons := [msg | deny[msg]] {
  count(deny) > 0
}

reasons := ["no_matching_policy"] {
  not permit
  count(deny) == 0
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

approval_required {
  prod_change_action
}

approved_for_action {
  input.approval.approved
  input.approval.approved_by != ""
  input.approval.approval_type == input.action
}

same_user_approved_and_executes {
  approved_for_action
  input.approval.approved_by == input.user.id
  prod_change_action
}

owned_dev_service {
  input.resource.environment == "dev"
  input.user.team == service_owner_team
  input.user.team == "application-dev"
}

owned_dev_service {
  input.resource.environment == "dev"
  input.user.team == service_owner_team
  input.user.team == "data-science-dev"
}

permit {
  input.action == "deploy"
  owned_dev_service
}

permit {
  input.action == "edit_config"
  owned_dev_service
}

permit {
  input.user.team == "qa"
  input.resource.environment == "test"
  input.action == "deploy"
}

permit {
  input.user.team == "qa"
  input.resource.environment == "test"
  input.action == "edit_config"
}

permit {
  input.user.team == "qa"
  input.resource.environment == "test"
  input.action == "restart_service"
}

permit {
  input.user.team == "sre"
  input.resource.environment == "uat"
  input.action == "deploy"
}

permit {
  input.user.team == "sre"
  input.resource.environment == "uat"
  input.action == "edit_config"
}

permit {
  input.user.team == "sre"
  input.resource.environment == "uat"
  input.action == "restart_service"
}

permit {
  input.user.team == "sre"
  input.resource.environment == "uat"
  input.action == "read_secret"
}

permit {
  input.user.team == "sre"
  input.resource.environment == "prod"
  input.action == "read_secret"
}

permit {
  input.user.team == "sre"
  input.resource.environment == "prod"
  input.action == "deploy"
}

permit {
  input.user.team == "sre"
  input.resource.environment == "prod"
  input.action == "edit_config"
}

permit {
  input.user.team == "sre"
  input.resource.environment == "prod"
  input.action == "restart_service"
}

permit {
  input.user.team == "devops"
  input.action == "deploy"
}

permit {
  input.user.team == "devops"
  input.action == "edit_config"
}

permit {
  input.user.team == "devops"
  input.action == "restart_service"
}

permit {
  input.user.team == "devops"
  input.action == "read_secret"
}

permit {
  input.user.team == "release-managers"
  input.action == "approve_release"
  input.resource.environment == "prod"
}

deny["service_not_found"] {
  not data.services[input.resource.service]
}

deny["unknown_environment"] {
  not valid_environment
}

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

deny["unsupported_action"] {
  not valid_action
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

deny["prod_action_requires_release_manager_approval"] {
  approval_required
  not approved_for_action
}

deny["same_user_cannot_approve_and_execute_prod_action"] {
  same_user_approved_and_executes
}
