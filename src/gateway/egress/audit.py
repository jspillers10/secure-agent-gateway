"""Redacted per-hop egress audit events."""

from __future__ import annotations

import logging
from collections.abc import Callable

from gateway.egress.protocol import HopDecision

logger = logging.getLogger("gateway.egress.audit")

EgressAuditSink = Callable[[HopDecision], None]


def emit_egress_audit_event(event: HopDecision) -> None:
    logger.info("egress_audit %s", event.model_dump_json())
