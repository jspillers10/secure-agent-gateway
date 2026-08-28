"""Docker-backed narrow Worker Launcher.

Only this component imports the Docker client and receives the Docker socket.
Every runtime option below is server-owned and fixed; the public request schema
contains only a signed execution grant.
"""

from __future__ import annotations

import json
import logging
import socket
import threading
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

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
from gateway.launcher.config import LauncherSettings
from gateway.launcher.registry import LauncherToolSpec, build_launcher_registry
from gateway.launcher.replay import GrantReplayGuard

logger = logging.getLogger(__name__)


class DockerExecutionLauncher:
    def __init__(self, settings: LauncherSettings, *, docker_client: Any) -> None:
        self._settings = settings
        self._docker = docker_client
        self._registry = build_launcher_registry(settings.worker_image_reference)
        self._replay_guard = GrantReplayGuard()
        self._image_lock = threading.Lock()
        self._pinned_image_ids: dict[str, str] = {}

    def _resolve_pinned_image_id(self, spec: LauncherToolSpec) -> str:
        """Resolve a configured reference once, then use only its immutable image ID."""
        with self._image_lock:
            existing = self._pinned_image_ids.get(spec.artifact_digest)
            if existing is not None:
                return existing
            image = self._docker.images.get(spec.image_reference)
            labels = image.attrs.get("Config", {}).get("Labels", {}) or {}
            if labels.get("org.secure-agent.artifact-digest") != spec.artifact_digest:
                raise LauncherError("worker_artifact_mismatch")
            image_id = str(image.id)
            if not image_id.startswith("sha256:"):
                raise LauncherError("worker_image_not_content_addressed")
            self._pinned_image_ids[spec.artifact_digest] = image_id
            return image_id

    def execute(self, grant: ExecutionGrant) -> ToolResultEnvelope:
        action = grant.action
        spec = self._registry.get(action.tool.name)
        if spec is None:
            raise LauncherError("unknown_tool")
        try:
            verify_execution_grant(
                grant,
                public_key_pem=self._settings.grant_public_key_pem,
                issuer=self._settings.grant_issuer,
                audience=self._settings.grant_audience,
                expected_tool_name=spec.tool_name,
                expected_artifact_digest=spec.artifact_digest,
                expected_argument_digest=action.argument_digest,
                expected_approval_digest=action.approval.digest,
            )
        except GrantVerificationError as exc:
            raise LauncherError("grant_rejected") from exc
        if not self._replay_guard.claim(grant.nonce):
            raise LauncherError("grant_replayed")

        worker_id = str(uuid4())
        nonce_hash = sha256_hex({"nonce": grant.nonce})
        container: Any | None = None
        attached: Any | None = None
        image_id: str | None = None
        terminal_outcome = "failed"
        terminal_error: str | None = "launcher_failed"
        emit_launcher_audit_event(
            self._launcher_event(
                grant,
                spec,
                nonce_hash=nonce_hash,
                event="accepted",
                worker_id=None,
                image_id=None,
                outcome="accepted",
            )
        )
        try:
            image_id = self._resolve_pinned_image_id(spec)
            result_private_key, result_public_key = generate_result_keypair()
            worker_request = {
                "grant": grant.model_dump(mode="json"),
                "worker_id": worker_id,
                "grant_public_key_pem": self._settings.grant_public_key_pem,
                "result_private_key_pem": result_private_key,
                "expected_issuer": self._settings.grant_issuer,
                "expected_audience": self._settings.grant_audience,
            }
            encoded_request = json.dumps(worker_request, separators=(",", ":")).encode("utf-8")
            if len(encoded_request) > 64 * 1024:
                raise LauncherError("grant_too_large")

            container = self._docker.containers.create(
                image=image_id,
                entrypoint=list(spec.entrypoint),
                name=f"secure-agent-worker-{worker_id}",
                detach=True,
                stdin_open=True,
                tty=False,
                network_disabled=True,
                user="10001:10001",
                working_dir="/app",
                read_only=True,
                cap_drop=["ALL"],
                # Docker's built-in default-deny seccomp profile remains active.
                security_opt=["no-new-privileges:true"],
                mem_limit=self._settings.memory_limit,
                nano_cpus=self._settings.nano_cpus,
                pids_limit=self._settings.pids_limit,
                # This is a new container-local bounded tmpfs, never a host temp path.
                tmpfs={"/tmp": "rw,noexec,nosuid,nodev,size=16m"},  # noqa: S108  # nosec B108
                log_config={
                    "type": "local",
                    "config": {"max-size": "128k", "max-file": "1", "compress": "false"},
                },
                labels={
                    "secure-agent.role": "disposable-worker",
                    "secure-agent.invocation": action.invocation_id,
                    "secure-agent.artifact": spec.artifact_digest,
                },
            )
            container.start()
            attached = container.attach_socket(params={"stdin": 1, "stream": 1})
            emit_launcher_audit_event(
                self._launcher_event(
                    grant,
                    spec,
                    nonce_hash=nonce_hash,
                    event="worker_started",
                    worker_id=worker_id,
                    image_id=image_id,
                    outcome="started",
                )
            )
            attached._sock.sendall(encoded_request + b"\n")  # noqa: SLF001
            attached._sock.shutdown(socket.SHUT_WR)  # noqa: SLF001
            wait_result = container.wait(timeout=self._settings.execution_timeout_seconds)
            if wait_result.get("StatusCode") != 0:
                raise LauncherError("worker_failed")
            raw_output: bytes = container.logs(stdout=True, stderr=False)
            if len(raw_output) > self._settings.output_limit_bytes:
                raise LauncherError("worker_output_exceeded")
            result = ToolResultEnvelope.model_validate_json(raw_output.strip())
            verify_tool_result(
                result,
                public_key_pem=result_public_key,
                expected_invocation_id=action.invocation_id,
                expected_grant_nonce=grant.nonce,
                expected_worker_id=worker_id,
                expected_tool_name=spec.tool_name,
                expected_artifact_digest=spec.artifact_digest,
            )
            emit_worker_audit_event(
                WorkerAuditEvent(
                    timestamp=datetime.now(tz=UTC),
                    invocation_id=action.invocation_id,
                    request_id=action.request_id,
                    correlation_id=action.correlation_id,
                    worker_id=worker_id,
                    tool_name=spec.tool_name,
                    artifact_digest=spec.artifact_digest,
                    result_digest=result.result_digest,
                    outcome=result.status,
                    error_code=result.error_code,
                )
            )
            terminal_outcome = result.status
            terminal_error = result.error_code
            return result
        except (LauncherError, ValidationError, ResultVerificationError) as exc:
            if isinstance(exc, LauncherError):
                raise
            raise LauncherError("worker_protocol_error") from exc
        except Exception as exc:  # noqa: BLE001 - Docker/runtime details never cross the boundary
            if container is not None:
                with suppress(Exception):
                    container.reload()
                    logger.warning(
                        "failed Worker state=%s error=%s",
                        container.attrs.get("State", {}).get("Status"),
                        container.attrs.get("State", {}).get("Error"),
                    )
            logger.exception("Launcher runtime failure")
            raise LauncherError("launcher_failed") from exc
        finally:
            cleanup_failed = False
            if attached is not None:
                with suppress(Exception):
                    attached.close()
            if container is not None:
                try:
                    container.remove(force=True, v=True)
                except Exception:  # noqa: BLE001
                    terminal_outcome = "failed"
                    terminal_error = "worker_cleanup_failed"
                    cleanup_failed = True
            emit_launcher_audit_event(
                self._launcher_event(
                    grant,
                    spec,
                    nonce_hash=nonce_hash,
                    event="terminal",
                    worker_id=worker_id,
                    image_id=image_id,
                    outcome=terminal_outcome,
                    error_code=terminal_error,
                )
            )
            if cleanup_failed:
                raise LauncherError("worker_cleanup_failed")

    @staticmethod
    def _launcher_event(
        grant: ExecutionGrant,
        spec: LauncherToolSpec,
        *,
        nonce_hash: str,
        event: str,
        worker_id: str | None,
        image_id: str | None,
        outcome: str,
        error_code: str | None = None,
    ) -> LauncherAuditEvent:
        action = grant.action
        return LauncherAuditEvent.model_validate(
            {
                "timestamp": datetime.now(tz=UTC),
                "event": event,
                "invocation_id": action.invocation_id,
                "request_id": action.request_id,
                "correlation_id": action.correlation_id,
                "grant_nonce_hash": nonce_hash,
                "tool_name": spec.tool_name,
                "artifact_digest": spec.artifact_digest,
                "worker_id": worker_id,
                "image_id": image_id,
                "outcome": outcome,
                "error_code": error_code,
            }
        )
