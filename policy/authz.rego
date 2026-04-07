package prodgate.authz

default permit = false

allow_decision if {
  permit
  count(deny) == 0
}

service_owner_team := object.get(object.get(data, "services", {}), input.resource.service, {}).owner_team if {
  object.get(object.get(data, "services", {}), input.resource.service, null) != null
}

service_owner_team := "unknown" if {
  object.get(object.get(data, "services", {}), input.resource.service, null) == null
}

reasons := ["allowed_by_policy"] if {
  allow_decision
}

reasons := [msg | deny[msg]] if {
  count(deny) > 0
}

reasons := ["no_matching_policy"] if {
  not allow_decision
  count(deny) == 0
}

decision := {
  "allow": allow_decision,
  "reasons": reasons,
  "service_owner_team": service_owner_team,
}
