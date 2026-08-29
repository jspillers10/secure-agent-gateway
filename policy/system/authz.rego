# OPA's own API authorization policy: makes the running OPA server
# read-only from the outside: only the gateway's decision query and a
# liveness check are allowed. Everything else (policy upload/deletion via
# PUT/DELETE /v1/policies, data mutation via PUT/PATCH /v1/data, and
# introspection via GET /v1/data or /v1/policies) is denied, so a network
# attacker who reaches OPA's HTTP port cannot replace or inspect the
# loaded policy.
#
# Takes effect only when OPA is started with --authorization=basic (see
# docker-compose.yml). Verified empirically (not just by inspection) via
# scripts/verify_opa_hardening.py and policy/system/authz_test.rego; see
# docs/threat-model.md for how this was confirmed to actually reject
# mutation attempts before being relied upon.
#
# Input shape (as sent by OPA itself for every incoming API request):
#   {"method": "GET"|"POST"|..., "path": [string, ...], ...}
package system.authz

import rego.v1

default allow := false

gateway_identity if {
	uri := input.client_certificates[0].URIs[0]
	uri.Scheme == "spiffe"
	uri.Host == "secure-agent-gateway"
	uri.Path == "/gateway"
}

# Liveness check used by the Docker healthcheck / operators.
allow if {
	gateway_identity
	input.method == "GET"
	input.path == ["health"]
}

# The one thing the gateway is allowed to do: ask for an authz decision.
# The gateway queries the narrow `result` rule specifically (see
# src/gateway/policy/opa_client.py); the bare package path is also
# allowed for manual debugging (e.g. scripts/verify_opa_hardening.py),
# since it is still read-only and reveals nothing an operator couldn't
# already see in the policy source.
allow if {
	gateway_identity
	input.method == "POST"
	input.path == ["v1", "data", "gateway", "authz"]
}

allow if {
	gateway_identity
	input.method == "POST"
	input.path == ["v1", "data", "gateway", "authz", "result"]
}
