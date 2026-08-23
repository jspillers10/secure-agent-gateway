"""Tests for the high-risk approval-required path (admin.rotate_key).

Approval records are single-use and bound to (tool, argument hash, agent
identity, delegated-user identity). Each mismatch dimension is tested
independently, plus the two-phase validate-then-consume sequence that
prevents premature consumption (see src/gateway/approvals/store.py).
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.api.deps import get_policy_client
from gateway.approvals.store import ApprovalOutcome, ApprovalRecord, ApprovalStore
from gateway.hashing import sha256_hex
from gateway.policy.client import PolicyDecision
from gateway.registry.schemas import AdminRotateKeyArgs
from tests.helpers.fake_policy import FakePolicyClient


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _grant_approval(
    approval_store: ApprovalStore,
    *,
    agent_id: str = "agent-001",
    delegated_user_id: str = "user-001",
    key_id: str = "key-1",
    reason: str = "rotate",
    ttl_seconds: int = 300,
) -> ApprovalRecord:
    args = AdminRotateKeyArgs(key_id=key_id, reason=reason)
    argument_hash = sha256_hex(args.model_dump(mode="json"))
    return approval_store.create(
        tool_name="admin.rotate_key",
        argument_hash=argument_hash,
        agent_id=agent_id,
        delegated_user_id=delegated_user_id,
        granted_by="test-approver",
        ttl_seconds=ttl_seconds,
    )


def test_approval_required_when_none_supplied(
    client: TestClient, make_token: Callable[..., str]
) -> None:
    token = make_token(scopes=["admin.rotate_key"])
    resp = client.post(
        "/v1/tool-invocations",
        json={"tool": "admin.rotate_key", "arguments": {"key_id": "key-1", "reason": "rotate"}},
        headers=_auth(token),
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "approval-required"
    assert resp.json()["result"] is None


def test_valid_approval_allows_execution(
    client: TestClient, make_token: Callable[..., str], approval_store: ApprovalStore
) -> None:
    record = _grant_approval(approval_store)
    token = make_token(scopes=["admin.rotate_key"])
    resp = client.post(
        "/v1/tool-invocations",
        json={
            "tool": "admin.rotate_key",
            "arguments": {"key_id": "key-1", "reason": "rotate"},
            "approval_id": record.approval_id,
        },
        headers=_auth(token),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"
    assert body["result"]["status"] == "simulated_rotation_recorded"


def test_approval_replay_denied(
    client: TestClient, make_token: Callable[..., str], approval_store: ApprovalStore
) -> None:
    record = _grant_approval(approval_store)
    token = make_token(scopes=["admin.rotate_key"])
    body = {
        "tool": "admin.rotate_key",
        "arguments": {"key_id": "key-1", "reason": "rotate"},
        "approval_id": record.approval_id,
    }

    first = client.post("/v1/tool-invocations", json=body, headers=_auth(token))
    assert first.json()["decision"] == "allow"

    second = client.post("/v1/tool-invocations", json=body, headers=_auth(token))
    assert second.status_code == 200
    assert second.json()["decision"] == "deny"


def test_approval_for_different_arguments_denied(
    client: TestClient, make_token: Callable[..., str], approval_store: ApprovalStore
) -> None:
    record = _grant_approval(approval_store, key_id="key-1", reason="rotate")
    token = make_token(scopes=["admin.rotate_key"])
    resp = client.post(
        "/v1/tool-invocations",
        json={
            "tool": "admin.rotate_key",
            "arguments": {"key_id": "key-2", "reason": "rotate"},  # different from approval
            "approval_id": record.approval_id,
        },
        headers=_auth(token),
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "deny"


def test_approval_for_different_identity_denied(
    client: TestClient, make_token: Callable[..., str], approval_store: ApprovalStore
) -> None:
    record = _grant_approval(approval_store, agent_id="agent-001", delegated_user_id="user-001")
    # Token belongs to a different agent than the approval was granted to.
    token = make_token(scopes=["admin.rotate_key"], agent_id="agent-999")
    resp = client.post(
        "/v1/tool-invocations",
        json={
            "tool": "admin.rotate_key",
            "arguments": {"key_id": "key-1", "reason": "rotate"},
            "approval_id": record.approval_id,
        },
        headers=_auth(token),
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "deny"


# --- Premature-consumption regression tests --------------------------------


def test_approval_survives_policy_outage(
    app: FastAPI, client: TestClient, make_token: Callable[..., str], approval_store: ApprovalStore
) -> None:
    """A policy-engine outage must not burn the approval: validation
    happens before OPA is asked, and consumption happens only after OPA
    says allow. See src/gateway/approvals/store.py."""
    record = _grant_approval(approval_store)
    token = make_token(scopes=["admin.rotate_key"])
    body = {
        "tool": "admin.rotate_key",
        "arguments": {"key_id": "key-1", "reason": "rotate"},
        "approval_id": record.approval_id,
    }

    app.dependency_overrides[get_policy_client] = lambda: FakePolicyClient(fail=True)
    try:
        outage_resp = client.post("/v1/tool-invocations", json=body, headers=_auth(token))
    finally:
        app.dependency_overrides.pop(get_policy_client, None)
    assert outage_resp.status_code == 503

    # The approval must still be valid: a normal, working policy client
    # lets the very same approval succeed afterwards.
    recovered_resp = client.post("/v1/tool-invocations", json=body, headers=_auth(token))
    assert recovered_resp.status_code == 200
    assert recovered_resp.json()["decision"] == "allow"


def test_approval_survives_policy_denial(
    client: TestClient, make_token: Callable[..., str], approval_store: ApprovalStore
) -> None:
    """A denial for an unrelated reason (missing scope) must not consume
    an otherwise-valid approval presented alongside it."""
    record = _grant_approval(approval_store)
    body = {
        "tool": "admin.rotate_key",
        "arguments": {"key_id": "key-1", "reason": "rotate"},
        "approval_id": record.approval_id,
    }

    # This token lacks the admin.rotate_key scope entirely, so OPA denies
    # regardless of the approval's validity.
    scopeless_token = make_token(scopes=[])
    denied_resp = client.post("/v1/tool-invocations", json=body, headers=_auth(scopeless_token))
    assert denied_resp.status_code == 200
    assert denied_resp.json()["decision"] == "deny"

    # The same approval is still usable by a properly-scoped request.
    scoped_token = make_token(scopes=["admin.rotate_key"])
    allowed_resp = client.post("/v1/tool-invocations", json=body, headers=_auth(scoped_token))
    assert allowed_resp.status_code == 200
    assert allowed_resp.json()["decision"] == "allow"


def test_approval_expiring_between_validate_and_consume_fails_closed() -> None:
    """Simulates an approval that was valid at validate()-time but expired
    by the time consume() runs immediately before execution. consume()
    must fail closed (EXPIRED), never execute on a stale approval."""
    store = ApprovalStore()
    args = AdminRotateKeyArgs(key_id="key-1", reason="rotate")
    argument_hash = sha256_hex(args.model_dump(mode="json"))
    record = store.create(
        tool_name="admin.rotate_key",
        argument_hash=argument_hash,
        agent_id="agent-001",
        delegated_user_id="user-001",
        granted_by="test-approver",
        ttl_seconds=300,
    )

    pre_check = store.validate(
        record.approval_id,
        tool_name="admin.rotate_key",
        argument_hash=argument_hash,
        agent_id="agent-001",
        delegated_user_id="user-001",
    )
    assert pre_check.ok

    # Simulate time passing between validation and the final consume,
    # e.g. a slow policy-engine round trip.
    store._records[record.approval_id].expires_at = datetime.now(tz=UTC) - timedelta(seconds=1)  # noqa: SLF001

    post_check = store.consume(
        record.approval_id,
        tool_name="admin.rotate_key",
        argument_hash=argument_hash,
        agent_id="agent-001",
        delegated_user_id="user-001",
    )
    assert not post_check.ok
    assert post_check.outcome is ApprovalOutcome.EXPIRED


def test_approval_race_only_one_consumer_wins() -> None:
    """Simulates two (or more) concurrent requests racing to consume the
    same approval after both already saw it as valid during their
    non-consuming validate() phase: exactly the scenario the two-phase
    design (validate, decide, consume-immediately-before-execution) is
    meant to make safe. Only one concurrent consume() may ever succeed."""
    store = ApprovalStore()
    args = AdminRotateKeyArgs(key_id="key-1", reason="rotate")
    argument_hash = sha256_hex(args.model_dump(mode="json"))
    record = store.create(
        tool_name="admin.rotate_key",
        argument_hash=argument_hash,
        agent_id="agent-001",
        delegated_user_id="user-001",
        granted_by="test-approver",
        ttl_seconds=300,
    )

    # Both "requests" independently validate first, exactly like the real
    # route does, and both see the approval as valid.
    for _ in range(2):
        result = store.validate(
            record.approval_id,
            tool_name="admin.rotate_key",
            argument_hash=argument_hash,
            agent_id="agent-001",
            delegated_user_id="user-001",
        )
        assert result.ok

    outcomes: list[bool] = []
    outcomes_lock = threading.Lock()

    def _race_consume() -> None:
        result = store.consume(
            record.approval_id,
            tool_name="admin.rotate_key",
            argument_hash=argument_hash,
            agent_id="agent-001",
            delegated_user_id="user-001",
        )
        with outcomes_lock:
            outcomes.append(result.ok)

    threads = [threading.Thread(target=_race_consume) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert outcomes.count(True) == 1
    assert outcomes.count(False) == 19


class _AllowApprovalGatedToolWithoutApprovalIdPolicyClient:
    """Simulates a buggy or compromised policy answering "allow" with
    metadata that matches the registry (approval_required=True) even
    though the caller never supplied an approval id at all. The route's
    defensive guard must refuse to execute rather than trust this."""

    async def evaluate(self, policy_input: dict[str, object]) -> PolicyDecision:
        return PolicyDecision(
            decision="allow",
            policy_version="1.0.0-inconsistent",
            required_scope="admin.rotate_key",
            risk="high",
            approval_required=True,
        )


def test_policy_inconsistent_guard_when_allow_without_approval_id(
    app: FastAPI, client: TestClient, make_token: Callable[..., str]
) -> None:
    app.dependency_overrides[get_policy_client] = (
        lambda: _AllowApprovalGatedToolWithoutApprovalIdPolicyClient()
    )
    try:
        token = make_token(scopes=["admin.rotate_key"])
        resp = client.post(
            "/v1/tool-invocations",
            json={"tool": "admin.rotate_key", "arguments": {"key_id": "key-1", "reason": "rotate"}},
            headers=_auth(token),
        )
    finally:
        app.dependency_overrides.pop(get_policy_client, None)

    assert resp.status_code == 503
    assert resp.json()["error"] == "policy_inconsistent"


class _RaceInducingPolicyClient:
    """Wraps a normal FakePolicyClient but, as a side effect of
    evaluate(), consumes the approval itself first, simulating a second
    request that raced in and won during *this* request's OPA round trip.
    Proves the route's final atomic consume (not just ApprovalStore in
    isolation; see test_approval_race_only_one_consumer_wins) fails
    closed when it loses that race, rather than executing anyway."""

    def __init__(
        self,
        approval_store: ApprovalStore,
        approval_id: str,
        *,
        tool_name: str,
        argument_hash: str,
        agent_id: str,
        delegated_user_id: str,
    ) -> None:
        self._inner = FakePolicyClient()
        self._store = approval_store
        self._approval_id = approval_id
        self._tool_name = tool_name
        self._argument_hash = argument_hash
        self._agent_id = agent_id
        self._delegated_user_id = delegated_user_id

    async def evaluate(self, policy_input: dict[str, object]) -> PolicyDecision:
        self._store.consume(
            self._approval_id,
            tool_name=self._tool_name,
            argument_hash=self._argument_hash,
            agent_id=self._agent_id,
            delegated_user_id=self._delegated_user_id,
        )
        return await self._inner.evaluate(policy_input)


def test_consume_race_lost_denies_at_api_level(
    app: FastAPI, client: TestClient, make_token: Callable[..., str], approval_store: ApprovalStore
) -> None:
    record = _grant_approval(approval_store)
    racer = _RaceInducingPolicyClient(
        approval_store,
        record.approval_id,
        tool_name="admin.rotate_key",
        argument_hash=record.argument_hash,
        agent_id="agent-001",
        delegated_user_id="user-001",
    )
    app.dependency_overrides[get_policy_client] = lambda: racer
    try:
        token = make_token(scopes=["admin.rotate_key"])
        resp = client.post(
            "/v1/tool-invocations",
            json={
                "tool": "admin.rotate_key",
                "arguments": {"key_id": "key-1", "reason": "rotate"},
                "approval_id": record.approval_id,
            },
            headers=_auth(token),
        )
    finally:
        app.dependency_overrides.pop(get_policy_client, None)

    assert resp.status_code == 200
    assert resp.json()["decision"] == "deny"
    assert "finalized" in (resp.json()["message"] or "")


# --- Approval provenance / audit -------------------------------------------


def test_create_approval_requires_approver_key(client: TestClient) -> None:
    resp = client.post(
        "/v1/approvals",
        json={
            "tool": "admin.rotate_key",
            "arguments": {"key_id": "key-1", "reason": "rotate"},
            "agent_id": "agent-001",
            "delegated_user_id": "user-001",
        },
    )
    assert resp.status_code == 401


def test_create_approval_rejects_wrong_approver_key(client: TestClient) -> None:
    resp = client.post(
        "/v1/approvals",
        json={
            "tool": "admin.rotate_key",
            "arguments": {"key_id": "key-1", "reason": "rotate"},
            "agent_id": "agent-001",
            "delegated_user_id": "user-001",
        },
        headers={"X-Approver-Key": "not-the-right-key"},
    )
    assert resp.status_code == 401


def test_create_approval_ignores_client_supplied_granted_by(client: TestClient) -> None:
    """The request schema has no `granted_by` field at all; sending one
    must be rejected outright (extra="forbid"), not silently accepted and
    ignored, and never trusted as the approver identity."""
    resp = client.post(
        "/v1/approvals",
        json={
            "tool": "admin.rotate_key",
            "arguments": {"key_id": "key-1", "reason": "rotate"},
            "agent_id": "agent-001",
            "delegated_user_id": "user-001",
            "granted_by": "attacker-controlled-value",
        },
        headers={"X-Approver-Key": "test-approver-key"},
    )
    assert resp.status_code == 422


def test_create_approval_then_use_it_end_to_end(
    client: TestClient, make_token: Callable[..., str]
) -> None:
    create_resp = client.post(
        "/v1/approvals",
        json={
            "tool": "admin.rotate_key",
            "arguments": {"key_id": "key-1", "reason": "rotate"},
            "agent_id": "agent-001",
            "delegated_user_id": "user-001",
        },
        headers={"X-Approver-Key": "test-approver-key"},
    )
    assert create_resp.status_code == 200
    approval_id = create_resp.json()["approval_id"]

    token = make_token(scopes=["admin.rotate_key"])
    invoke_resp = client.post(
        "/v1/tool-invocations",
        json={
            "tool": "admin.rotate_key",
            "arguments": {"key_id": "key-1", "reason": "rotate"},
            "approval_id": approval_id,
        },
        headers=_auth(token),
    )
    assert invoke_resp.status_code == 200
    assert invoke_resp.json()["decision"] == "allow"


def test_create_approval_rejects_unknown_tool(client: TestClient) -> None:
    resp = client.post(
        "/v1/approvals",
        json={
            "tool": "os.system",
            "arguments": {},
            "agent_id": "agent-001",
            "delegated_user_id": "user-001",
        },
        headers={"X-Approver-Key": "test-approver-key"},
    )
    assert resp.status_code == 404


def test_create_approval_rejects_invalid_arguments(client: TestClient) -> None:
    resp = client.post(
        "/v1/approvals",
        json={
            "tool": "admin.rotate_key",
            "arguments": {"key_id": "key-1"},  # missing required "reason"
            "agent_id": "agent-001",
            "delegated_user_id": "user-001",
        },
        headers={"X-Approver-Key": "test-approver-key"},
    )
    assert resp.status_code == 422


# --- "OPA owns the policy" regression --------------------------------------


async def test_fake_policy_client_ignores_spoofed_scope_metadata() -> None:
    """A compromised or buggy gateway includes stale required_scope/risk
    fields in the policy input (fields the real contract never asks the
    gateway to send at all). Proves the policy-client contract itself
    (mirrored here by FakePolicyClient exactly as the real Rego policy
    does; see policy/gateway/authz.rego and
    policy/gateway/authz_test.rego::test_ignores_spoofed_required_scope_and_risk)
    never reads them: admin.rotate_key genuinely requires the
    admin.rotate_key scope, which this input's scopes list lacks, so the
    decision must be "deny" even though the spoofed required_scope
    ("documents.read") is one the caller does hold.
    """
    policy_client = FakePolicyClient()
    decision = await policy_client.evaluate(
        {
            "agent_id": "agent-001",
            "delegated_user_id": "user-001",
            "scopes": ["documents.read"],
            "tool": "admin.rotate_key",
            "approval_state": "none",
            "required_scope": "documents.read",  # spoofed, must be ignored
            "risk": "low",  # spoofed, must be ignored
        }
    )
    assert decision.decision == "deny"
    assert decision.required_scope == "admin.rotate_key"
    assert decision.risk == "high"
