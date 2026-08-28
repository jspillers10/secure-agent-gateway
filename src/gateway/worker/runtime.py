"""One-shot Worker protocol implementation.

The Worker accepts one closed request over stdin, re-verifies the signed grant,
executes one fixed-registry inert handler, signs one result, and exits.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, ValidationError

from gateway.execution.protocol import ExecutionGrant, ToolResultEnvelope
from gateway.execution.signing import (
    GrantVerificationError,
    sign_tool_result,
    verify_execution_grant,
)
from gateway.hashing import sha256_hex
from gateway.registry.tools import UnknownToolError, resolve_tool


class WorkerProtocolError(Exception):
    pass


class WorkerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    grant: ExecutionGrant
    worker_id: str
    grant_public_key_pem: str
    result_private_key_pem: str
    expected_issuer: str
    expected_audience: str


def execute_worker_request(request: WorkerRequest) -> ToolResultEnvelope:
    action = request.grant.action
    try:
        tool_spec = resolve_tool(action.tool.name)
    except UnknownToolError as exc:
        raise WorkerProtocolError("unknown_tool") from exc

    try:
        validated_args = tool_spec.args_model.model_validate(action.arguments)
    except ValidationError as exc:
        raise WorkerProtocolError("invalid_arguments") from exc

    arguments = validated_args.model_dump(mode="json")
    if arguments != action.arguments:
        raise WorkerProtocolError("arguments_not_canonical")

    try:
        verify_execution_grant(
            request.grant,
            public_key_pem=request.grant_public_key_pem,
            issuer=request.expected_issuer,
            audience=request.expected_audience,
            expected_tool_name=tool_spec.name,
            expected_artifact_digest=tool_spec.artifact_digest,
            expected_argument_digest=sha256_hex(arguments),
            expected_approval_digest=action.approval.digest,
        )
    except GrantVerificationError as exc:
        raise WorkerProtocolError(exc.code) from exc

    started_at = datetime.now(tz=UTC)
    result: dict[str, object] | None
    error_code: str | None
    status: str
    try:
        result = tool_spec.handler(validated_args)
        status = "succeeded"
        error_code = None
        committed = result
    except Exception:  # noqa: BLE001 - no exception detail crosses boundary
        result = None
        status = "failed"
        error_code = "tool_execution_failed"
        committed = {"error": error_code}
    completed_at = datetime.now(tz=UTC)

    unsigned = {
        "protocol_version": "1.0",
        "invocation_id": action.invocation_id,
        "grant_nonce": request.grant.nonce,
        "worker_id": request.worker_id,
        "tool": action.tool.model_dump(mode="json"),
        "status": status,
        "result": result,
        "result_digest": sha256_hex(committed),
        "error_code": error_code,
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
    }
    return sign_tool_result(unsigned, request.result_private_key_pem)
