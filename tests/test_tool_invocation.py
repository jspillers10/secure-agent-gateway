"""API-level tests for POST /v1/tool-invocations.

Token-error precision is tested separately in test_token_verification.py;
here the API is only expected to return a generic 401 for any bad token,
by design (see src/gateway/api/deps.py).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from gateway.api.deps import get_policy_client
from gateway.policy.client import PolicyDecision
from gateway.registry.tools import TOOL_REGISTRY
from tests.helpers.fake_policy import FakePolicyClient


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_valid_read_request_allowed(client: TestClient, make_token: Callable[..., str]) -> None:
    token = make_token(scopes=["documents.read"])
    resp = client.post(
        "/v1/tool-invocations",
        json={"tool": "documents.read", "arguments": {"document_id": "doc-001"}},
        headers=_auth(token),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "allow"
    assert body["risk_level"] == "low"
    assert body["result"]["document_id"] == "doc-001"


def test_missing_token_rejected(client: TestClient) -> None:
    resp = client.post(
        "/v1/tool-invocations",
        json={"tool": "documents.read", "arguments": {"document_id": "doc-001"}},
    )
    assert resp.status_code == 401


def test_unknown_tool_rejected(client: TestClient, make_token: Callable[..., str]) -> None:
    token = make_token(scopes=["documents.read"])
    resp = client.post(
        "/v1/tool-invocations",
        json={"tool": "os.system", "arguments": {"cmd": "rm -rf /"}},
        headers=_auth(token),
    )
    assert resp.status_code == 404
    assert resp.json()["error"] == "unknown_tool"


def test_unexpected_argument_rejected(client: TestClient, make_token: Callable[..., str]) -> None:
    token = make_token(scopes=["documents.read"])
    resp = client.post(
        "/v1/tool-invocations",
        json={
            "tool": "documents.read",
            "arguments": {"document_id": "doc-001", "unexpected_field": "x"},
        },
        headers=_auth(token),
    )
    assert resp.status_code == 422


def test_client_supplied_risk_override_rejected(
    client: TestClient, make_token: Callable[..., str]
) -> None:
    token = make_token(scopes=["documents.read"])
    resp = client.post(
        "/v1/tool-invocations",
        json={
            "tool": "documents.read",
            "arguments": {"document_id": "doc-001"},
            "risk": "low",  # not a field on the request schema; must be rejected, not ignored
        },
        headers=_auth(token),
    )
    assert resp.status_code == 422


def test_missing_delegated_scope_denied(client: TestClient, make_token: Callable[..., str]) -> None:
    token = make_token(scopes=[])
    resp = client.post(
        "/v1/tool-invocations",
        json={"tool": "documents.read", "arguments": {"document_id": "doc-001"}},
        headers=_auth(token),
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "deny"


def test_scope_escalation_attempt_denied(client: TestClient, make_token: Callable[..., str]) -> None:
    # Agent is only delegated documents.read but asks for a write-scoped tool.
    token = make_token(scopes=["documents.read"])
    resp = client.post(
        "/v1/tool-invocations",
        json={
            "tool": "tickets.create",
            "arguments": {"title": "t", "description": "d"},
        },
        headers=_auth(token),
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "deny"


def test_policy_service_failure_fails_closed(
    app: FastAPI, client: TestClient, make_token: Callable[..., str]
) -> None:
    app.dependency_overrides[get_policy_client] = lambda: FakePolicyClient(fail=True)
    try:
        token = make_token(scopes=["documents.read"])
        resp = client.post(
            "/v1/tool-invocations",
            json={"tool": "documents.read", "arguments": {"document_id": "doc-001"}},
            headers=_auth(token),
        )
    finally:
        app.dependency_overrides.pop(get_policy_client, None)

    assert resp.status_code == 503
    assert resp.json()["error"] == "policy_unavailable"


def test_mock_tool_exception_fails_safely(client: TestClient, make_token: Callable[..., str]) -> None:
    token = make_token(scopes=["documents.read"])
    resp = client.post(
        "/v1/tool-invocations",
        json={"tool": "documents.read", "arguments": {"document_id": "does-not-exist"}},
        headers=_auth(token),
    )
    assert resp.status_code == 502
    body = resp.json()
    assert body["error"] == "tool_execution_failed"
    # The internal exception message must never reach the client.
    assert "does-not-exist" not in resp.text


def test_unexpected_tool_exception_fails_safely(
    client: TestClient, make_token: Callable[..., str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A handler bug that raises something other than ToolExecutionError
    (e.g. a plain RuntimeError) must still be caught and converted to a
    safe, generic response rather than crashing the request or leaking a
    stack trace to the client."""

    def _boom(_args: object) -> dict[str, object]:
        raise RuntimeError("unexpected internal failure with sensitive details")

    broken_spec = dataclasses.replace(TOOL_REGISTRY["documents.read"], handler=_boom)
    monkeypatch.setitem(TOOL_REGISTRY, "documents.read", broken_spec)  # type: ignore[index]

    token = make_token(scopes=["documents.read"])
    resp = client.post(
        "/v1/tool-invocations",
        json={"tool": "documents.read", "arguments": {"document_id": "doc-001"}},
        headers=_auth(token),
    )
    assert resp.status_code == 502
    assert resp.json()["error"] == "tool_execution_failed"
    assert "sensitive details" not in resp.text


class _MismatchedMetadataPolicyClient:
    """Always answers "allow" but with metadata that disagrees with the
    fixed tool registry (documents.read is "low" risk, this claims
    "high"). Proves the gateway's registry-policy cross-check actually
    runs and actually fails closed, rather than just existing in code but
    never being exercised."""

    async def evaluate(self, policy_input: dict[str, object]) -> PolicyDecision:
        return PolicyDecision(
            decision="allow",
            policy_version="1.0.0-mismatch",
            required_scope="documents.read",
            risk="high",  # registry says "low": deliberate mismatch
            approval_required=False,
        )


def test_registry_policy_mismatch_fails_closed(
    app: FastAPI, client: TestClient, make_token: Callable[..., str]
) -> None:
    app.dependency_overrides[get_policy_client] = lambda: _MismatchedMetadataPolicyClient()
    try:
        token = make_token(scopes=["documents.read"])
        resp = client.post(
            "/v1/tool-invocations",
            json={"tool": "documents.read", "arguments": {"document_id": "doc-001"}},
            headers=_auth(token),
        )
    finally:
        app.dependency_overrides.pop(get_policy_client, None)

    assert resp.status_code == 503
    assert resp.json()["error"] == "policy_registry_mismatch"
