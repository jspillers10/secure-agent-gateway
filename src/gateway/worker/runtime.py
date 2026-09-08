"""One-shot Worker protocol implementation.

The Worker accepts one closed request over stdin, re-verifies the signed grant,
executes one fixed-registry inert handler, signs one result, and exits.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from gateway.egress.client import UnixTlsEgressClient
from gateway.egress.protocol import BrokerFetchRequest
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
    egress_socket_path: str | None = None
    egress_server_hostname: str | None = None
    egress_server_ca_pem: str | None = None
    egress_client_certificate_pem: str | None = None
    egress_client_private_key_pem: str | None = None

    @model_validator(mode="after")
    def validate_egress_material(self) -> WorkerRequest:
        values = (
            self.egress_socket_path,
            self.egress_server_hostname,
            self.egress_server_ca_pem,
            self.egress_client_certificate_pem,
            self.egress_client_private_key_pem,
        )
        if any(value is not None for value in values) and not all(value for value in values):
            raise ValueError("egress connection material must be complete")
        if self.grant.action.tool.name != "web.fetch_text" and any(
            value is not None for value in values
        ):
            raise ValueError("non-egress tools cannot receive broker credentials")
        return self


def execute_worker_request(
    request: WorkerRequest,
    *,
    egress_client: object | None = None,
) -> ToolResultEnvelope:
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
        if tool_spec.requires_egress:
            client = egress_client or _create_egress_client(request)
            fetch = getattr(client, "fetch", None)
            if fetch is None:
                raise WorkerProtocolError("egress_client_invalid")
            broker_result = fetch(
                BrokerFetchRequest(
                    worker_id=request.worker_id,
                    grant=request.grant,
                )
            )
            result = {
                "url": broker_result.final_url,
                "content_type": broker_result.content_type,
                "byte_count": broker_result.byte_count,
                "text": broker_result.text,
                "redirect_hops": sum(
                    1 for decision in broker_result.decisions if decision.reason == "redirect"
                ),
                "egress_latency_ms": {
                    "dns": sum(decision.dns_duration_ms for decision in broker_result.decisions),
                    "broker": sum(
                        decision.broker_duration_ms for decision in broker_result.decisions
                    ),
                },
            }
        else:
            if tool_spec.handler is None:
                raise WorkerProtocolError("tool_handler_missing")
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


def _create_egress_client(request: WorkerRequest) -> UnixTlsEgressClient:
    if not all(
        (
            request.egress_socket_path,
            request.egress_server_hostname,
            request.egress_server_ca_pem,
            request.egress_client_certificate_pem,
            request.egress_client_private_key_pem,
        )
    ):
        raise WorkerProtocolError("egress_connection_material_missing")
    socket_path = cast(str, request.egress_socket_path)
    server_hostname = cast(str, request.egress_server_hostname)
    server_ca_pem = cast(str, request.egress_server_ca_pem)
    client_certificate_pem = cast(str, request.egress_client_certificate_pem)
    client_private_key_pem = cast(str, request.egress_client_private_key_pem)
    timeout = request.grant.egress.timeout_seconds if request.grant.egress is not None else 1.0
    return UnixTlsEgressClient(
        socket_path=socket_path,
        server_hostname=server_hostname,
        server_ca_pem=server_ca_pem,
        client_certificate_pem=client_certificate_pem,
        client_private_key_pem=client_private_key_pem,
        timeout_seconds=timeout,
    )
