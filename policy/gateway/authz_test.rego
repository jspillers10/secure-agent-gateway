# Run with: opa test policy/ -v
package gateway.authz_test

import rego.v1
import data.gateway.authz

base_input := {
	"agent_id": "agent-001",
	"delegated_user_id": "user-001",
	"scopes": ["documents.read"],
	"tool": "documents.read",
	"approval_state": "none",
}

test_deny_when_scope_missing if {
	authz.decision == "deny" with input as object.union(base_input, {"scopes": []})
}

test_allow_when_scope_present_no_approval_needed if {
	authz.decision == "allow" with input as base_input
}

test_web_fetch_requires_its_exact_scope if {
	authz.decision == "allow" with input as object.union(base_input, {
		"tool": "web.fetch_text",
		"scopes": ["web.fetch_text"],
	})
	authz.decision == "deny" with input as object.union(base_input, {
		"tool": "web.fetch_text",
		"scopes": ["documents.read"],
	})
}

test_deny_on_scope_escalation_attempt if {
	# Agent has only documents.read but requests tickets.create, which
	# OPA's own `tools` mapping resolves to requiring tickets.write.
	authz.decision == "deny" with input as object.union(base_input, {"tool": "tickets.create"})
}

test_approval_required_when_missing if {
	authz.decision == "approval-required" with input as {
		"agent_id": "agent-001",
		"delegated_user_id": "user-001",
		"scopes": ["admin.rotate_key"],
		"tool": "admin.rotate_key",
		"approval_state": "none",
	}
}

test_allow_when_approval_valid if {
	authz.decision == "allow" with input as {
		"agent_id": "agent-001",
		"delegated_user_id": "user-001",
		"scopes": ["admin.rotate_key"],
		"tool": "admin.rotate_key",
		"approval_state": "valid",
	}
}

test_deny_when_approval_invalid if {
	# Covers replay, argument mismatch, identity mismatch, and expiry:
	# the gateway collapses all of these into approval_state == "invalid".
	authz.decision == "deny" with input as {
		"agent_id": "agent-001",
		"delegated_user_id": "user-001",
		"scopes": ["admin.rotate_key"],
		"tool": "admin.rotate_key",
		"approval_state": "invalid",
	}
}

test_deny_when_scope_missing_even_with_valid_approval if {
	# Scope is checked before approval state, independently of it.
	authz.decision == "deny" with input as {
		"agent_id": "agent-001",
		"delegated_user_id": "user-001",
		"scopes": [],
		"tool": "admin.rotate_key",
		"approval_state": "valid",
	}
}

test_deny_unknown_tool if {
	authz.decision == "deny" with input as object.union(base_input, {"tool": "os.system"})
}

test_deny_missing_identity if {
	authz.decision == "deny" with input as object.union(base_input, {"agent_id": ""})
	authz.decision == "deny" with input as object.remove(base_input, ["delegated_user_id"])
}

test_deny_malformed_scopes if {
	authz.decision == "deny" with input as object.union(base_input, {"scopes": "documents.read"})
}

test_deny_inconsistent_approval_state if {
	authz.decision == "deny" with input as object.union(base_input, {"approval_state": "yes-please"})
}

test_deny_unknown_risk_state if {
	# Simulate a policy-data bug: a tool whose declared risk isn't one of
	# the known levels. Must fail closed, never fall through to allow.
	authz.decision == "deny" with input as {
		"agent_id": "agent-001",
		"delegated_user_id": "user-001",
		"scopes": ["broken.tool"],
		"tool": "broken.tool",
		"approval_state": "none",
	}
		with authz.tools as {"broken.tool": {
			"required_scope": "broken.tool",
			"risk": "catastrophic",
			"approval_required": false,
		}}
}

test_ignores_spoofed_required_scope_and_risk if {
	# A compromised or buggy gateway includes extra, incorrect fields that
	# used to be part of the input contract (a weaker required_scope the
	# agent actually has, and a lower risk). This policy never reads
	# input.required_scope or input.risk at all: the decision must still
	# come out as if those fields were never sent: admin.rotate_key
	# genuinely requires the admin.rotate_key scope, which this agent
	# does not have, so the correct decision is deny.
	authz.decision == "deny" with input as {
		"agent_id": "agent-001",
		"delegated_user_id": "user-001",
		"scopes": ["documents.read"],
		"tool": "admin.rotate_key",
		"approval_state": "none",
		"required_scope": "documents.read",
		"risk": "low",
	}
}

test_metadata_reflects_registry_for_known_tool if {
	authz.required_scope == "admin.rotate_key" with input as {"tool": "admin.rotate_key"}
	authz.risk == "high" with input as {"tool": "admin.rotate_key"}
	authz.approval_required == true with input as {"tool": "admin.rotate_key"}
}

test_metadata_is_safe_default_for_unknown_tool if {
	authz.required_scope == "" with input as {"tool": "os.system"}
	authz.risk == "" with input as {"tool": "os.system"}
	authz.approval_required == false with input as {"tool": "os.system"}
}

test_version_is_exposed if {
	authz.policy_version == "2.0.0"
	authz.result.policy_version == "2.0.0"
}

test_result_has_exactly_the_gateway_contract_keys if {
	# Regression test: src/gateway/policy/client.py's PolicyDecision does
	# `model_validate(result)` with extra="forbid" and no manual key
	# remapping. A field renamed on only one side (as genuinely happened
	# once during development: Rego said "version", Pydantic expected
	# "policy_version") fails closed at runtime (PolicyError), but this
	# test catches it here instead, at `opa test` time.
	object.keys(authz.result) == {
		"decision",
		"policy_version",
		"required_scope",
		"risk",
		"approval_required",
	} with input as {"tool": "documents.read", "scopes": ["documents.read"], "approval_state": "none"}
}
