from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from gateway.execution.client import LauncherError, LauncherRequest
from gateway.execution.local_launcher import InProcessLauncher
from gateway.execution.protocol import ActionEnvelope, ApprovalBinding, ToolIdentity
from gateway.execution.signing import (
    ExecutionGrantSigner,
    GrantVerificationError,
    ResultVerificationError,
    generate_result_keypair,
    parse_execution_grant,
    sign_tool_result,
    verify_execution_grant,
    verify_tool_result,
)
from gateway.hashing import canonical_json_bytes, sha256_hex
from gateway.registry.tools import WORKER_ARTIFACT_DIGEST
from tests.helpers.keys import generate_rsa_keypair

ISSUER = "secure-agent-gateway"
AUDIENCE = "secure-agent-worker-launcher"


def _action(
    *,
    arguments: dict[str, object] | None = None,
    artifact_digest: str = WORKER_ARTIFACT_DIGEST,
) -> ActionEnvelope:
    resolved_arguments = arguments or {"document_id": "doc-001"}
    return ActionEnvelope(
        invocation_id="invocation-001",
        request_id="request-001",
        correlation_id="correlation-001",
        agent_id="agent-001",
        delegated_user_id="user-001",
        tool=ToolIdentity(name="documents.read", artifact_digest=artifact_digest),
        arguments=resolved_arguments,
        argument_digest=sha256_hex(resolved_arguments),
        approval=ApprovalBinding(required=False, state="not_required"),
        policy_version="test-v1",
        risk="low",
        created_at=datetime.now(tz=UTC),
    )


def _verify(grant: object, public_key: str, **overrides: object) -> None:
    expected = {
        "issuer": ISSUER,
        "audience": AUDIENCE,
        "expected_tool_name": "documents.read",
        "expected_artifact_digest": WORKER_ARTIFACT_DIGEST,
        "expected_argument_digest": sha256_hex({"document_id": "doc-001"}),
        "expected_approval_digest": None,
    }
    expected.update(overrides)
    verify_execution_grant(grant, public_key_pem=public_key, **expected)  # type: ignore[arg-type]


def test_canonicalization_is_deterministic_and_rejects_non_json_numbers() -> None:
    first = {"z": "é", "a": [3, {"b": True, "a": None}]}
    second = {"a": [3, {"a": None, "b": True}], "z": "é"}
    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert sha256_hex(first) == sha256_hex(second)
    with pytest.raises(ValueError):
        canonical_json_bytes({"value": float("nan")})


@pytest.mark.parametrize("model_name", ["action", "grant", "result", "launcher"])
def test_cross_boundary_schemas_forbid_unknown_fields(model_name: str) -> None:
    private_key, _public_key = generate_rsa_keypair()
    grant = ExecutionGrantSigner(
        private_key, issuer=ISSUER, audience=AUDIENCE
    ).issue(_action())
    if model_name == "action":
        payload = grant.action.model_dump(mode="json") | {"command": ["sh"]}
        validator = ActionEnvelope.model_validate
    elif model_name == "grant":
        payload = grant.model_dump(mode="json") | {"mounts": ["/:/host"]}
        validator = type(grant).model_validate
    elif model_name == "result":
        result_key, _ = generate_result_keypair()
        payload = {
            "protocol_version": "1.0",
            "invocation_id": "invocation-001",
            "grant_nonce": grant.nonce,
            "worker_id": "worker-001",
            "tool": grant.action.tool.model_dump(mode="json"),
            "status": "succeeded",
            "result": {"ok": True},
            "result_digest": sha256_hex({"ok": True}),
            "error_code": None,
            "started_at": datetime.now(tz=UTC).isoformat(),
            "completed_at": datetime.now(tz=UTC).isoformat(),
        }
        payload = sign_tool_result(payload, result_key).model_dump(mode="json") | {
            "network": "host"
        }
        from gateway.execution.protocol import ToolResultEnvelope

        validator = ToolResultEnvelope.model_validate
    else:
        payload = {"grant": grant.model_dump(mode="json"), "image": "attacker/image"}
        validator = LauncherRequest.model_validate
    with pytest.raises(ValidationError):
        validator(payload)


def test_grant_verification_rejects_forgery_expiry_audience_and_version() -> None:
    trusted_private, trusted_public = generate_rsa_keypair()
    attacker_private, _ = generate_rsa_keypair()
    action = _action()

    forged = ExecutionGrantSigner(attacker_private, issuer=ISSUER, audience=AUDIENCE).issue(action)
    with pytest.raises(GrantVerificationError, match="signature_invalid"):
        _verify(forged, trusted_public)

    expired = ExecutionGrantSigner(
        trusted_private, issuer=ISSUER, audience=AUDIENCE, ttl_seconds=5
    ).issue(action, now=datetime.now(tz=UTC) - timedelta(seconds=10))
    with pytest.raises(GrantVerificationError, match="grant_expired"):
        _verify(expired, trusted_public)

    wrong_audience = ExecutionGrantSigner(
        trusted_private, issuer=ISSUER, audience="other-launcher"
    ).issue(action)
    with pytest.raises(GrantVerificationError, match="audience_invalid"):
        _verify(wrong_audience, trusted_public)

    wrong_issuer = ExecutionGrantSigner(
        trusted_private, issuer="other-gateway", audience=AUDIENCE
    ).issue(action)
    with pytest.raises(GrantVerificationError, match="issuer_invalid"):
        _verify(wrong_issuer, trusted_public)

    valid = ExecutionGrantSigner(trusted_private, issuer=ISSUER, audience=AUDIENCE).issue(action)
    unknown_version = valid.model_dump(mode="json") | {"protocol_version": "2.0"}
    with pytest.raises(GrantVerificationError, match="grant_schema_invalid"):
        parse_execution_grant(unknown_version)


def test_grant_verification_rejects_changed_arguments_and_artifact() -> None:
    private_key, public_key = generate_rsa_keypair()
    signer = ExecutionGrantSigner(private_key, issuer=ISSUER, audience=AUDIENCE)

    changed_arguments = signer.issue(_action(arguments={"document_id": "doc-002"}))
    with pytest.raises(GrantVerificationError, match="argument_digest_mismatch"):
        _verify(changed_arguments, public_key)

    wrong_digest = "sha256:" + "0" * 64
    changed_artifact = signer.issue(_action(artifact_digest=wrong_digest))
    with pytest.raises(GrantVerificationError, match="artifact_digest_mismatch"):
        _verify(changed_artifact, public_key)

    valid = signer.issue(_action())
    with pytest.raises(GrantVerificationError, match="approval_binding_mismatch"):
        _verify(valid, public_key, expected_approval_digest="sha256:" + "1" * 64)


@pytest.mark.asyncio
async def test_one_grant_has_exactly_one_concurrent_winner() -> None:
    private_key, public_key = generate_rsa_keypair()
    grant = ExecutionGrantSigner(private_key, issuer=ISSUER, audience=AUDIENCE).issue(_action())
    launcher = InProcessLauncher(
        grant_public_key_pem=public_key, issuer=ISSUER, audience=AUDIENCE
    )
    outcomes = await asyncio.gather(
        launcher.execute(grant), launcher.execute(grant), return_exceptions=True
    )
    assert sum(not isinstance(value, BaseException) for value in outcomes) == 1
    errors = [value for value in outcomes if isinstance(value, LauncherError)]
    assert len(errors) == 1 and errors[0].code == "grant_replayed"


def test_result_is_bound_to_specific_worker_invocation() -> None:
    result_private, result_public = generate_result_keypair()
    now = datetime.now(tz=UTC)
    result = sign_tool_result(
        {
            "protocol_version": "1.0",
            "invocation_id": "invocation-001",
            "grant_nonce": "n" * 32,
            "worker_id": "worker-001",
            "tool": {
                "name": "documents.read",
                "artifact_digest": WORKER_ARTIFACT_DIGEST,
            },
            "status": "succeeded",
            "result": {"ok": True},
            "result_digest": sha256_hex({"ok": True}),
            "error_code": None,
            "started_at": now.isoformat(),
            "completed_at": now.isoformat(),
        },
        result_private,
    )
    with pytest.raises(ResultVerificationError, match="result_binding_mismatch"):
        verify_tool_result(
            result,
            public_key_pem=result_public,
            expected_invocation_id="invocation-OTHER",
            expected_grant_nonce="n" * 32,
            expected_worker_id="worker-001",
            expected_tool_name="documents.read",
            expected_artifact_digest=WORKER_ARTIFACT_DIGEST,
        )
