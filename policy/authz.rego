package prodgate.authz

default allow = false

service_owner_team = owner {
  svc := data.services[input.resource.service]
  owner := svc.owner_team
}

service_owner_team = "unknown" {
  not data.services[input.resource.service]
}

allow {
  input.user.team == "sre"
  input.action == "deploy"
  input.resource.environment == "prod"
  input.approval.approved == true
  input.approval.approved_by == "rm-frank"
  input.approval.approval_type == "deploy"
}

reasons = ["allowed_by_policy"] {
  allow
}

reasons = ["no_matching_policy"] {
  not allow
}

decision = {
  "allow": allow,
  "reasons": reasons,
  "service_owner_team": service_owner_team
}
