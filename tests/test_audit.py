"""Audit-trail tests: redaction and allow/deny distinguishability."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient

from gateway.approvals.store import ApprovalStore
from gateway.audit.log import AUDIT_LOGGER_NAME
from gateway.hashing import sha256_hex
from gateway.registry.schemas import AdminRotateKeyArgs


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _audit_events(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [
        json.loads(record.message) for record in caplog.records if record.name == AUDIT_LOGGER_NAME
    ]


def _approval_events(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [event for event in _audit_events(caplog) if "event" in event]


def test_audit_redacts_raw_arguments(
    client: TestClient, make_token: Callable[..., str], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger=AUDIT_LOGGER_NAME)

    sensitive_marker = "super-secret-title-should-never-appear-raw"
    token = make_token(scopes=["tickets.write"])
    resp = client.post(
        "/v1/tool-invocations",
        json={"tool": "tickets.create", "arguments": {"title": sensitive_marker, "description": "d"}},
        headers=_auth(token),
    )
    assert resp.status_code == 200

    # The raw sensitive value must not appear anywhere in the audit log text.
    assert sensitive_marker not in caplog.text

    events = _audit_events(caplog)
    assert len(events) == 1
    event = events[0]
    assert "arguments" not in event
    assert "title" not in event
    assert event["argument_hash"] is not None
    assert event["argument_hash"].startswith("sha256:")


def test_audit_entry_for_denial_is_distinguishable_from_allow(
    client: TestClient, make_token: Callable[..., str], caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger=AUDIT_LOGGER_NAME)

    allowed_token = make_token(scopes=["documents.read"])
    allow_resp = client.post(
        "/v1/tool-invocations",
        json={"tool": "documents.read", "arguments": {"document_id": "doc-001"}},
        headers=_auth(allowed_token),
    )
    assert allow_resp.json()["decision"] == "allow"

    denied_token = make_token(scopes=[])
    deny_resp = client.post(
        "/v1/tool-invocations",
        json={"tool": "documents.read", "arguments": {"document_id": "doc-001"}},
        headers=_auth(denied_token),
    )
    assert deny_resp.json()["decision"] == "deny"

    events = _audit_events(caplog)
    assert len(events) == 2
    allowed_event, denied_event = events

    assert allowed_event["outcome"] == "executed"
    assert allowed_event["policy_decision"] == "allow"
    assert allowed_event["scope_decision"] == "granted"

    assert denied_event["outcome"] == "denied"
    assert denied_event["policy_decision"] == "deny"
    assert denied_event["scope_decision"] == "denied"


def test_approval_creation_audited_and_redacted(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger=AUDIT_LOGGER_NAME)

    resp = client.post(
        "/v1/approvals",
        json={
            "tool": "admin.rotate_key",
            "arguments": {"key_id": "key-1", "reason": "a very specific rotation reason"},
            "agent_id": "agent-001",
            "delegated_user_id": "user-001",
        },
        headers={"X-Approver-Key": "test-approver-key"},
    )
    assert resp.status_code == 200
    approval_id = resp.json()["approval_id"]

    # Neither the approval id nor the raw argument text may appear
    # anywhere in the audit log text.
    assert approval_id not in caplog.text
    assert "test-approver-key" not in caplog.text
    assert "a very specific rotation reason" not in caplog.text

    events = _approval_events(caplog)
    assert len(events) == 1
    event = events[0]
    assert event["event"] == "created"
    assert event["tool_name"] == "admin.rotate_key"
    assert "approval_id" not in event
    assert "arguments" not in event
    assert event["argument_hash"] is not None and event["argument_hash"].startswith("sha256:")


def test_approval_rejection_audited(client: TestClient, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger=AUDIT_LOGGER_NAME)

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

    events = _approval_events(caplog)
    assert len(events) == 1
    assert events[0]["event"] == "rejected"
    assert events[0]["reason"] == "unknown_tool"


def test_approval_consumption_audited(
    client: TestClient,
    make_token: Callable[..., str],
    approval_store: ApprovalStore,
    caplog: pytest.LogCaptureFixture,
) -> None:
    args = AdminRotateKeyArgs(key_id="key-1", reason="rotate")
    argument_hash = sha256_hex(args.model_dump(mode="json"))
    record = approval_store.create(
        tool_name="admin.rotate_key",
        argument_hash=argument_hash,
        agent_id="agent-001",
        delegated_user_id="user-001",
        granted_by="test-approver",
        ttl_seconds=300,
    )

    caplog.set_level(logging.INFO, logger=AUDIT_LOGGER_NAME)
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
    assert resp.json()["decision"] == "allow"

    events = _approval_events(caplog)
    consumed_events = [e for e in events if e["event"] == "consumed"]
    assert len(consumed_events) == 1
    assert "approval_id" not in consumed_events[0]
    assert record.approval_id not in caplog.text


def test_approval_replay_binding_failure_audited(
    client: TestClient,
    make_token: Callable[..., str],
    approval_store: ApprovalStore,
    caplog: pytest.LogCaptureFixture,
) -> None:
    args = AdminRotateKeyArgs(key_id="key-1", reason="rotate")
    argument_hash = sha256_hex(args.model_dump(mode="json"))
    record = approval_store.create(
        tool_name="admin.rotate_key",
        argument_hash=argument_hash,
        agent_id="agent-001",
        delegated_user_id="user-001",
        granted_by="test-approver",
        ttl_seconds=300,
    )
    token = make_token(scopes=["admin.rotate_key"])
    body = {
        "tool": "admin.rotate_key",
        "arguments": {"key_id": "key-1", "reason": "rotate"},
        "approval_id": record.approval_id,
    }
    first = client.post("/v1/tool-invocations", json=body, headers=_auth(token))
    assert first.json()["decision"] == "allow"

    caplog.set_level(logging.INFO, logger=AUDIT_LOGGER_NAME)
    caplog.clear()
    second = client.post("/v1/tool-invocations", json=body, headers=_auth(token))
    assert second.json()["decision"] == "deny"

    events = _approval_events(caplog)
    binding_failures = [e for e in events if e["event"] == "binding_failed"]
    assert len(binding_failures) == 1
    assert binding_failures[0]["reason"] == "already_used"
    assert "approval_id" not in binding_failures[0]
    assert record.approval_id not in caplog.text
