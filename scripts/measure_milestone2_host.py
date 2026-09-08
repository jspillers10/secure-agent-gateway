#!/usr/bin/env python
"""Measure the real broker core against example.com when Docker is unavailable.

This fallback deliberately does not claim Worker/Unix-socket/end-to-end
coverage. The Compose measurement remains scripts/measure_milestone2.py.
"""

from __future__ import annotations

import json
import statistics
import time
from datetime import UTC, datetime

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from generate_dev_keys import _create_ca

from gateway.egress.broker import EgressBroker, EgressBrokerSettings
from gateway.egress.protocol import BrokerFetchRequest
from gateway.execution.protocol import (
    ActionEnvelope,
    ApprovalBinding,
    EgressGrant,
    ToolIdentity,
)
from gateway.execution.signing import ExecutionGrantSigner
from gateway.hashing import sha256_hex
from gateway.registry.tools import WORKER_ARTIFACT_DIGEST
from gateway.workload.certificates import issue_invocation_worker_certificate

SAMPLES = 20
ORIGIN = "https://example.com"


def _summary(values: list[float]) -> dict[str, float]:
    ordered = sorted(values)
    return {
        "p50_ms": round(statistics.median(ordered), 3),
        "p95_ms": round(ordered[round((len(ordered) - 1) * 0.95)], 3),
    }


def main() -> int:
    grant_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    grant_private = grant_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    grant_public = grant_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    worker_ca_key, worker_ca = _create_ca("host-measurement-worker-ca")
    worker_ca_private = worker_ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    worker_ca_pem = worker_ca.public_bytes(serialization.Encoding.PEM).decode()
    signer = ExecutionGrantSigner(
        grant_private,
        issuer="secure-agent-gateway",
        audience="secure-agent-worker-launcher",
    )
    broker = EgressBroker(
        EgressBrokerSettings(
            grant_public_key_pem=grant_public,
            grant_issuer="secure-agent-gateway",
            grant_audience="secure-agent-worker-launcher",
            worker_ca_certificate_pem=worker_ca_pem,
            allowed_origins=frozenset({ORIGIN}),
        )
    )
    dns: list[float] = []
    broker_latency: list[float] = []
    total: list[float] = []
    for index in range(SAMPLES):
        invocation_id = f"host-measurement-{index}"
        worker_id = f"worker-{index}"
        arguments = {"url": f"{ORIGIN}/"}
        action = ActionEnvelope(
            invocation_id=invocation_id,
            request_id=f"request-{index}",
            correlation_id="host-measurement",
            agent_id="measurement-agent",
            delegated_user_id="measurement-user",
            tool=ToolIdentity(name="web.fetch_text", artifact_digest=WORKER_ARTIFACT_DIGEST),
            arguments=arguments,
            argument_digest=sha256_hex(arguments),
            approval=ApprovalBinding(required=False, state="not_required"),
            policy_version="measurement",
            risk="low",
            destination=arguments["url"],
            created_at=datetime.now(tz=UTC),
        )
        grant = signer.issue(
            action,
            egress=EgressGrant(initial_url=arguments["url"], allowed_origins=(ORIGIN,)),
        )
        _key, certificate = issue_invocation_worker_certificate(
            ca_private_key_pem=worker_ca_private,
            ca_certificate_pem=worker_ca_pem,
            invocation_id=invocation_id,
            worker_id=worker_id,
        )
        started = time.perf_counter()
        result = broker.fetch(
            BrokerFetchRequest(worker_id=worker_id, grant=grant),
            peer_certificate_pem=certificate,
        )
        total.append((time.perf_counter() - started) * 1000)
        if result.status != "succeeded":
            raise RuntimeError(f"measurement failed: {result.error_code}")
        dns.append(sum(item.dns_duration_ms for item in result.decisions))
        broker_latency.append(sum(item.broker_duration_ms for item in result.decisions))
    print(
        json.dumps(
            {
                "scope": "host broker core only; excludes Gateway, Launcher, Worker, and UDS",
                "samples": SAMPLES,
                "dns": _summary(dns),
                "broker": _summary(broker_latency),
                "total_fetch": _summary(total),
                "raw_ms": {"dns": dns, "broker": broker_latency, "total_fetch": total},
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
