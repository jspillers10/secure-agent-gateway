# Secure Agent Gateway authorization policy.
#
# OPA, not the gateway, owns the mapping from tool name to required
# scope, risk level, and approval requirement (the `tools` object below).
# The gateway sends only the requested tool name, never a pre-resolved
# required_scope or risk; if a compromised or buggy gateway sent those
# fields anyway, this policy would never read them, because the decision
# and metadata rules below are computed entirely from `tools[input.tool]`.
# See authz_test.rego::test_ignores_spoofed_required_scope_and_risk.
#
# The gateway is the only caller of this package. It never trusts its own
# judgment about whether a request is allowed: every invocation asks this
# policy, and any failure to reach OPA, or any mismatch between this
# policy's metadata and the gateway's own fixed tool registry, is treated
# by the caller as a deny (see src/gateway/policy/opa_client.py and
# src/gateway/api/routes.py).
#
# Input contract (assembled server-side from verified identity only; nothing
# here is a raw, unverified value from the client):
#   {
#     "agent_id": string,             verified JWT subject / agent identity
#     "delegated_user_id": string,    verified delegated-user identity
#     "scopes": [string],             delegated-identity scopes from the verified JWT
#     "tool": string,                 the requested registry tool name
#     "approval_state": "none" | "valid" | "invalid"
#   }
#
# Queried at data.gateway.authz.result (not the bare package path): this
# package has several helper rules (tools, tool_known, has_required_scope,
# ...) that exist only to make `decision` and the metadata rules below
# readable. `result` is the one rule meant to be queried: a closed object
# with exactly five keys, so the gateway's closed Pydantic response
# schema (`extra="forbid"`, see src/gateway/policy/client.py) can reject
# any unexpected field without also having to enumerate every internal
# helper this policy happens to define today.
#
# Output (data.gateway.authz.result): {
#   "decision": "allow" | "deny" | "approval-required",
#   "policy_version": string,
#   "required_scope": string,   resolved from `tools`, "" if tool unknown
#   "risk": string,              resolved from `tools`, "" if tool unknown
#   "approval_required": boolean resolved from `tools`, false if tool unknown
# }
#
# Field names here match src/gateway/policy/client.py's PolicyDecision
# exactly (including "policy_version", not just "version") on purpose:
# the gateway does `PolicyDecision.model_validate(result)` with no manual
# key remapping in between, so a name that drifts out of sync between
# this file and that Pydantic model fails loudly (PolicyError, fail
# closed) rather than silently; see opa_client.py.
#
# The gateway cross-checks required_scope/risk/approval_required against
# its own fixed registry entry for the same tool and fails closed on any
# mismatch, regardless of what `decision` says; this is what makes the
# two independent sources of truth (this file, and
# src/gateway/registry/tools.py) meaningfully redundant rather than just
# duplicated.
package gateway.authz

import rego.v1

policy_version := "2.0.0"

# This is OPA's own source of truth for tool -> (scope, risk, approval).
# It must be kept in sync with src/gateway/registry/tools.py; the gateway
# enforces that at request time via the metadata cross-check described
# above, and CI enforces it via the Docker Compose integration smoke test.
tools := {
	"documents.read": {
		"required_scope": "documents.read",
		"risk": "low",
		"approval_required": false,
	},
	"tickets.create": {
		"required_scope": "tickets.write",
		"risk": "medium",
		"approval_required": false,
	},
	"admin.rotate_key": {
		"required_scope": "admin.rotate_key",
		"risk": "high",
		"approval_required": true,
	},
}

known_risk_levels := {"low", "medium", "high"}

known_approval_states := {"none", "valid", "invalid"}

# --- Input validity -----------------------------------------------------

valid_identity if {
	is_string(input.agent_id)
	input.agent_id != ""
	is_string(input.delegated_user_id)
	input.delegated_user_id != ""
}

valid_scopes if {
	is_array(input.scopes)
}

valid_approval_state if {
	input.approval_state in known_approval_states
}

tool_known if {
	tools[input.tool]
}

tool_spec := tools[input.tool]

valid_risk if {
	tool_known
	tool_spec.risk in known_risk_levels
}

has_required_scope if {
	tool_known
	tool_spec.required_scope in input.scopes
}

# --- Decision -------------------------------------------------------------
# Every branch below fails closed: any gap (missing identity, missing/
# malformed scopes, unknown tool, unknown risk level, missing scope,
# invalid approval state) resolves to "deny", never a default allow.

default decision := "deny"

decision := "deny" if {
	not valid_identity
} else := "deny" if {
	not valid_scopes
} else := "deny" if {
	not tool_known
} else := "deny" if {
	not valid_risk
} else := "deny" if {
	not has_required_scope
} else := "deny" if {
	not valid_approval_state
} else := "allow" if {
	not tool_spec.approval_required
} else := "allow" if {
	input.approval_state == "valid"
} else := "approval-required" if {
	input.approval_state == "none"
} else := "deny" if {
	input.approval_state == "invalid"
}

# --- Metadata (always present, defaulted safely for an unknown tool) -----

default required_scope := ""

required_scope := tool_spec.required_scope if tool_known

default risk := ""

risk := tool_spec.risk if tool_known

default approval_required := false

approval_required := tool_spec.approval_required if tool_known

# The only rule the gateway actually queries; see the note above.
result := {
	"decision": decision,
	"policy_version": policy_version,
	"required_scope": required_scope,
	"risk": risk,
	"approval_required": approval_required,
}
