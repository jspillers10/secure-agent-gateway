"""Protocol-faithful in-process Launcher used only by hermetic unit tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from gateway.execution.audit import (
    LauncherAuditEvent,
    WorkerAuditEvent,
    emit_launcher_audit_event,
    emit_worker_audit_event,
)
from gateway.execution.client import LauncherError
from gateway.execution.protocol import ExecutionGrant, ToolResultEnvelope
from gateway.execution.signing import (
    GrantVerificationError,
    ResultVerificationError,
    generate_result_keypair,
    verify_execution_grant,
    verify_tool_result,
)
from gateway.hashing import sha256_hex
from gateway.launcher.replay import GrantReplayGuard
from gateway.registry.tools import UnknownToolError, resolve_tool
from gateway.worker.runtime import WorkerProtocolError, WorkerRequest, execute_worker_request


class InProcessLauncher:
    """Executes the Worker function locally while preserving every protocol check.

    Production/Compose configuration never uses this class. It lets the existing
    API tests remain hermetic while proving that the Gateway no longer dispatches
    handlers itself.
    """

    def __init__(self, *, grant_public_key_pem: str, issuer: str, audience: str) -> None:
        self._grant_public_key_pem = grant_public_key_pem
        self._issuer = issuer
        self._audience = audience
        self._replay_guard = GrantReplayGuard()

    async def execute(self, grant: ExecutionGrant) -> ToolResultEnvelope:
        action = grant.action
        try:
            spec = resolve_tool(action.tool.name)
            verify_execution_grant(
                grant,
                public_key_pem=self._grant_public_key_pem,
                issuer=self._issuer,
                audience=self._audience,
                expected_tool_name=spec.name,
                expected_artifact_digest=spec.artifact_digest,
                expected_argument_digest=action.argument_digest,
                expected_approval_digest=action.approval.digest,
            )
        except (UnknownToolError, GrantVerificationError) as exc:
            raise LauncherError("grant_rejected") from exc
        if not self._replay_guard.claim(grant.nonce):
            raise LauncherError("grant_replayed")

        worker_id = str(uuid4())
        nonce_hash = sha256_hex({"nonce": grant.nonce})
        emit_launcher_audit_event(
            LauncherAuditEvent(
                timestamp=datetime.now(tz=UTC),
                event="accepted",
                invocation_id=action.invocation_id,
                request_id=action.request_id,
                correlation_id=action.correlation_id,
                grant_nonce_hash=nonce_hash,
                tool_name=spec.name,
                artifact_digest=spec.artifact_digest,
                worker_id=None,
                image_id="in-process-test-double",
                outcome="accepted",
            )
        )
        terminal_emitted = False
        try:
            emit_launcher_audit_event(
                LauncherAuditEvent(
                    timestamp=datetime.now(tz=UTC),
                    event="worker_started",
                    invocation_id=action.invocation_id,
                    request_id=action.request_id,
                    correlation_id=action.correlation_id,
                    grant_nonce_hash=nonce_hash,
                    tool_name=spec.name,
                    artifact_digest=spec.artifact_digest,
                    worker_id=worker_id,
                    image_id="in-process-test-double",
                    outcome="started",
                )
            )
            result_private_key, result_public_key = generate_result_keypair()
            result = execute_worker_request(
                WorkerRequest(
                    grant=grant,
                    worker_id=worker_id,
                    grant_public_key_pem=self._grant_public_key_pem,
                    result_private_key_pem=result_private_key,
                    expected_issuer=self._issuer,
                    expected_audience=self._audience,
                )
            )
            verify_tool_result(
                result,
                public_key_pem=result_public_key,
                expected_invocation_id=action.invocation_id,
                expected_grant_nonce=grant.nonce,
                expected_worker_id=worker_id,
                expected_tool_name=spec.name,
                expected_artifact_digest=spec.artifact_digest,
            )
            emit_worker_audit_event(
                WorkerAuditEvent(
                    timestamp=datetime.now(tz=UTC),
                    invocation_id=action.invocation_id,
                    request_id=action.request_id,
                    correlation_id=action.correlation_id,
                    worker_id=worker_id,
                    tool_name=spec.name,
                    artifact_digest=spec.artifact_digest,
                    result_digest=result.result_digest,
                    outcome=result.status,
                    error_code=result.error_code,
                )
            )
            emit_launcher_audit_event(
                LauncherAuditEvent(
                    timestamp=datetime.now(tz=UTC),
                    event="terminal",
                    invocation_id=action.invocation_id,
                    request_id=action.request_id,
                    correlation_id=action.correlation_id,
                    grant_nonce_hash=nonce_hash,
                    tool_name=spec.name,
                    artifact_digest=spec.artifact_digest,
                    worker_id=worker_id,
                    image_id="in-process-test-double",
                    outcome=result.status,
                    error_code=result.error_code,
                )
            )
            terminal_emitted = True
            return result
        except (WorkerProtocolError, ResultVerificationError) as exc:
            raise LauncherError("worker_failed") from exc
        finally:
            if not terminal_emitted:
                emit_launcher_audit_event(
                    LauncherAuditEvent(
                        timestamp=datetime.now(tz=UTC),
                        event="terminal",
                        invocation_id=action.invocation_id,
                        request_id=action.request_id,
                        correlation_id=action.correlation_id,
                        grant_nonce_hash=nonce_hash,
                        tool_name=spec.name,
                        artifact_digest=spec.artifact_digest,
                        worker_id=worker_id,
                        image_id="in-process-test-double",
                        outcome="failed",
                        error_code="worker_failed",
                    )
                )
