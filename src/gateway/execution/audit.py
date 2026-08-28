"""Redacted audit events for Launcher and disposable Worker lifecycles."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

LAUNCHER_AUDIT_LOGGER_NAME = "gateway.launcher.audit"
WORKER_AUDIT_LOGGER_NAME = "gateway.worker.audit"

_launcher_logger = logging.getLogger(LAUNCHER_AUDIT_LOGGER_NAME)
_worker_logger = logging.getLogger(WORKER_AUDIT_LOGGER_NAME)


class LauncherAuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    event: Literal["accepted", "worker_started", "terminal"]
    invocation_id: str
    request_id: str
    correlation_id: str
    grant_nonce_hash: str
    tool_name: str
    artifact_digest: str
    worker_id: str | None
    image_id: str | None
    outcome: Literal["accepted", "started", "succeeded", "failed"]
    error_code: str | None = None


class WorkerAuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    event: Literal["terminal"] = "terminal"
    invocation_id: str
    request_id: str
    correlation_id: str
    worker_id: str
    tool_name: str
    artifact_digest: str
    result_digest: str
    outcome: Literal["succeeded", "failed"]
    error_code: str | None = None


def emit_launcher_audit_event(event: LauncherAuditEvent) -> None:
    _launcher_logger.info(json.dumps(event.model_dump(mode="json"), sort_keys=True))


def emit_worker_audit_event(event: WorkerAuditEvent) -> None:
    _worker_logger.info(json.dumps(event.model_dump(mode="json"), sort_keys=True))
