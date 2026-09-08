"""A test double for the policy client used by hermetic unit tests.

Its `tools` mapping and decision logic are deliberately kept structurally
identical to policy/gateway/authz.rego so the two stay in sync by
inspection. Critically, `evaluate()` derives required_scope/risk/
approval_required from `policy_input["tool"]` via this mapping, exactly
like the real Rego policy, and never reads a `required_scope` or `risk`
key from the input even if one is present. This is what makes
test_fake_policy_client_ignores_spoofed_scope_metadata in
tests/test_approvals.py a real regression test of the *contract*, not
just of this fake: a caller (a compromised or buggy gateway) cannot
influence the decision by adding those fields to the input dict, because
nothing on the policy-client side of the interface ever looks at them.

The real Rego policy is exercised directly via `opa test policy/` (see
CI), via scripts/verify_opa_hardening.py against a live OPA, and
end-to-end against the real gateway via the Docker Compose integration
smoke test; this fake is never the only thing validating authorization
behavior.
"""

from __future__ import annotations

from typing import Any

from gateway.policy.client import PolicyDecision, PolicyError

TOOLS: dict[str, dict[str, Any]] = {
    "documents.read": {"required_scope": "documents.read", "risk": "low", "approval_required": False},
    "tickets.create": {"required_scope": "tickets.write", "risk": "medium", "approval_required": False},
    "admin.rotate_key": {"required_scope": "admin.rotate_key", "risk": "high", "approval_required": True},
    "web.fetch_text": {"required_scope": "web.fetch_text", "risk": "low", "approval_required": False},
}


class FakePolicyClient:
    def __init__(self, *, fail: bool = False, version: str = "2.0.0-fake") -> None:
        self.fail = fail
        self.version = version
        self.calls: list[dict[str, Any]] = []

    async def evaluate(self, policy_input: dict[str, Any]) -> PolicyDecision:
        self.calls.append(policy_input)
        if self.fail:
            raise PolicyError("simulated policy engine outage")

        tool_spec = TOOLS.get(policy_input["tool"])
        if tool_spec is None:
            return PolicyDecision(
                decision="deny",
                policy_version=self.version,
                required_scope="",
                risk="",
                approval_required=False,
            )

        required_scope = tool_spec["required_scope"]
        risk = tool_spec["risk"]
        approval_required = tool_spec["approval_required"]
        has_scope = required_scope in policy_input["scopes"]
        approval_state = policy_input["approval_state"]

        decision: str
        if not has_scope:
            decision = "deny"
        elif not approval_required or approval_state == "valid":
            decision = "allow"
        elif approval_state == "none":
            decision = "approval-required"
        else:
            decision = "deny"

        return PolicyDecision(
            decision=decision,  # type: ignore[arg-type]
            policy_version=self.version,
            required_scope=required_scope,
            risk=risk,
            approval_required=approval_required,
        )
