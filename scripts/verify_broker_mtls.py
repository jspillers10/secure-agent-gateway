#!/usr/bin/env python
"""Verify live Worker authentication and invocation binding at the broker socket."""

from __future__ import annotations

import json
import socket
import ssl
import sys
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from generate_dev_keys import _create_ca, _create_leaf

from gateway.egress.protocol import BrokerFetchRequest, BrokerFetchResult
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

KEYS_DIR = Path("/keys")
SOCKET_PATH = "/run/secure-agent-egress/broker.sock"
SERVER_HOSTNAME = "egress-broker"
PROTECTED_URL = "https://blocked.secure-agent.test/protected"
OBSERVED_URL = "https://fixture.secure-agent.test/observed"
ALLOWED_URL = "https://fixture.secure-agent.test/text"
ALLOWED_ORIGINS = (
    "https://fixture.secure-agent.test",
    "https://redirect.secure-agent.test",
    "https://blocked.secure-agent.test",
)


class LiveCheckError(RuntimeError):
    pass


class TlsAuthenticationRejected(LiveCheckError):
    """A missing client certificate was rejected with a corroborating TLS alert."""


def _is_certificate_required_alert(exc: ssl.SSLError) -> bool:
    reason = str(getattr(exc, "reason", "") or "").lower()
    detail = str(exc).lower()
    return "certificate_required" in reason or "certificate required" in detail


def _send_broker_request(
    tls: ssl.SSLSocket,
    payload: bytes,
    *,
    corroborate_missing_certificate: bool = False,
) -> None:
    try:
        tls.sendall(payload)
    except BrokenPipeError as broken_pipe:
        if not corroborate_missing_certificate:
            raise
        try:
            tls.recv(1)
        except ssl.SSLError as alert:
            if _is_certificate_required_alert(alert):
                raise TlsAuthenticationRejected("client_certificate_required") from broken_pipe
            raise LiveCheckError("missing_certificate_rejection_not_corroborated") from alert
        except OSError as transport_error:
            raise LiveCheckError(
                "missing_certificate_rejection_not_corroborated"
            ) from transport_error
        raise LiveCheckError("missing_certificate_rejection_not_corroborated") from broken_pipe


def _private_pem(key: rsa.RSAPrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")


def _certificate_pem(certificate: x509.Certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")


def _request(
    *,
    execution_private_key: str,
    worker_id: str,
    invocation_id: str,
    url: str,
) -> BrokerFetchRequest:
    arguments = {"url": url}
    action = ActionEnvelope(
        invocation_id=invocation_id,
        request_id=f"live-broker-{uuid.uuid4()}",
        correlation_id=f"live-broker-{uuid.uuid4()}",
        agent_id="live-broker-verifier",
        delegated_user_id="live-broker-verifier",
        tool=ToolIdentity(name="web.fetch_text", artifact_digest=WORKER_ARTIFACT_DIGEST),
        arguments=arguments,
        argument_digest=sha256_hex(arguments),
        approval=ApprovalBinding(required=False, state="not_required"),
        policy_version="2.0.0",
        risk="low",
        destination=url,
        created_at=datetime.now(tz=UTC),
    )
    authority = EgressGrant(initial_url=url, allowed_origins=ALLOWED_ORIGINS)
    grant = ExecutionGrantSigner(
        execution_private_key,
        issuer="secure-agent-gateway",
        audience="secure-agent-worker-launcher",
        ttl_seconds=30,
    ).issue(action, egress=authority)
    return BrokerFetchRequest(worker_id=worker_id, grant=grant)


def _worker_credential(
    *,
    ca_private_key: str,
    ca_certificate: str,
    invocation_id: str,
    worker_id: str,
) -> tuple[str, str]:
    return issue_invocation_worker_certificate(
        ca_private_key_pem=ca_private_key,
        ca_certificate_pem=ca_certificate,
        invocation_id=invocation_id,
        worker_id=worker_id,
        ttl_seconds=60,
    )


def _exchange(
    request: BrokerFetchRequest,
    *,
    client_key_pem: str | None,
    client_certificate_pem: str | None,
    corroborate_missing_certificate: bool = False,
) -> BrokerFetchResult:
    context = ssl.create_default_context(
        cadata=(KEYS_DIR / "internal-server-ca-cert.pem").read_text(encoding="utf-8")
    )
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    with tempfile.TemporaryDirectory() as directory:
        if client_key_pem is not None and client_certificate_pem is not None:
            cert_path = Path(directory) / "client-cert.pem"
            key_path = Path(directory) / "client-key.pem"
            cert_path.write_text(client_certificate_pem, encoding="utf-8")
            key_path.write_text(client_key_pem, encoding="utf-8")
            cert_path.chmod(0o600)
            key_path.chmod(0o600)
            context.load_cert_chain(certfile=cert_path, keyfile=key_path)

        unix_family = getattr(socket, "AF_UNIX", 1)
        raw = socket.socket(unix_family, socket.SOCK_STREAM)
        tls: ssl.SSLSocket | None = None
        try:
            raw.settimeout(5.0)
            raw.connect(SOCKET_PATH)
            tls = context.wrap_socket(raw, server_hostname=SERVER_HOSTNAME)
            _send_broker_request(
                tls,
                request.model_dump_json().encode("utf-8") + b"\n",
                corroborate_missing_certificate=corroborate_missing_certificate,
            )
            response = bytearray()
            while not response.endswith(b"\n") and len(response) <= 1024 * 1024:
                chunk = tls.recv(16_384)
                if not chunk:
                    break
                response.extend(chunk)
            if not response.endswith(b"\n") or len(response) > 1024 * 1024:
                raise LiveCheckError("broker_response_invalid")
            return BrokerFetchResult.model_validate_json(bytes(response[:-1]))
        finally:
            if tls is not None:
                tls.close()
            else:
                raw.close()


def _observe_protected_connections(
    *,
    execution_private_key: str,
    worker_ca_private_key: str,
    worker_ca_certificate: str,
) -> int:
    invocation_id = str(uuid.uuid4())
    worker_id = str(uuid.uuid4())
    request = _request(
        execution_private_key=execution_private_key,
        worker_id=worker_id,
        invocation_id=invocation_id,
        url=OBSERVED_URL,
    )
    worker_key, worker_certificate = _worker_credential(
        ca_private_key=worker_ca_private_key,
        ca_certificate=worker_ca_certificate,
        invocation_id=invocation_id,
        worker_id=worker_id,
    )
    result = _exchange(
        request,
        client_key_pem=worker_key,
        client_certificate_pem=worker_certificate,
    )
    if result.status != "succeeded" or result.text is None:
        raise LiveCheckError("fixture_observation_failed")
    value = json.loads(result.text).get("protected_accepted_tcp_connections")
    if not isinstance(value, int):
        raise LiveCheckError("fixture_observation_invalid")
    return value


def _check_unknown_ca(
    *,
    execution_private_key: str,
    worker_ca_private_key: str,
    worker_ca_certificate: str,
) -> None:
    baseline = _observe_protected_connections(
        execution_private_key=execution_private_key,
        worker_ca_private_key=worker_ca_private_key,
        worker_ca_certificate=worker_ca_certificate,
    )
    untrusted_ca_key, untrusted_ca_certificate = _create_ca("live-untrusted-worker-ca")
    invocation_id = str(uuid.uuid4())
    worker_id = str(uuid.uuid4())
    request = _request(
        execution_private_key=execution_private_key,
        worker_id=worker_id,
        invocation_id=invocation_id,
        url=PROTECTED_URL,
    )
    worker_key, worker_certificate = _worker_credential(
        ca_private_key=_private_pem(untrusted_ca_key),
        ca_certificate=_certificate_pem(untrusted_ca_certificate),
        invocation_id=invocation_id,
        worker_id=worker_id,
    )
    try:
        _exchange(
            request,
            client_key_pem=worker_key,
            client_certificate_pem=worker_certificate,
        )
    except ssl.SSLError as exc:
        reason = str(exc).lower()
        if not any(
            marker in reason
            for marker in ("unknown ca", "certificate unknown", "bad certificate")
        ):
            raise LiveCheckError(f"unexpected_tls_failure:{type(exc).__name__}") from exc
    else:
        raise LiveCheckError("untrusted_ca_was_accepted")
    observed = _observe_protected_connections(
        execution_private_key=execution_private_key,
        worker_ca_private_key=worker_ca_private_key,
        worker_ca_certificate=worker_ca_certificate,
    )
    if observed != baseline:
        raise LiveCheckError("untrusted_ca_caused_outbound_connection")
    print("[PASS] untrusted Worker CA rejected during mutual-TLS authentication")
    print("[PASS] untrusted Worker CA caused zero protected-target connections")


def _expect_tls_credential_rejection(
    *,
    name: str,
    execution_private_key: str,
    worker_ca_private_key: str,
    worker_ca_certificate: str,
    client_key_pem: str | None,
    client_certificate_pem: str | None,
    invocation_id: str | None = None,
    worker_id: str | None = None,
) -> None:
    baseline = _observe_protected_connections(
        execution_private_key=execution_private_key,
        worker_ca_private_key=worker_ca_private_key,
        worker_ca_certificate=worker_ca_certificate,
    )
    invocation_id = invocation_id or str(uuid.uuid4())
    worker_id = worker_id or str(uuid.uuid4())
    request = _request(
        execution_private_key=execution_private_key,
        worker_id=worker_id,
        invocation_id=invocation_id,
        url=PROTECTED_URL,
    )
    try:
        _exchange(
            request,
            client_key_pem=client_key_pem,
            client_certificate_pem=client_certificate_pem,
            corroborate_missing_certificate=name == "missing",
        )
    except TlsAuthenticationRejected:
        if name != "missing":
            raise
    except ssl.SSLError as exc:
        detail = f"{getattr(exc, 'reason', '')} {exc}".lower()
        expected_markers = {
            "missing": ("certificate_required", "certificate required"),
            "expired": ("certificate_expired", "certificate expired"),
            "wrong-purpose": ("unsupported_certificate", "unsupported certificate"),
        }
        if not any(marker in detail for marker in expected_markers[name]):
            raise LiveCheckError(f"{name}_tls_rejection_not_specific") from exc
    else:
        raise LiveCheckError(f"{name}_credential_was_accepted")
    observed = _observe_protected_connections(
        execution_private_key=execution_private_key,
        worker_ca_private_key=worker_ca_private_key,
        worker_ca_certificate=worker_ca_certificate,
    )
    if observed != baseline:
        raise LiveCheckError(f"{name}_credential_caused_outbound_connection")
    print(f"[PASS] {name} Worker credential rejected during mutual-TLS authentication")
    print(f"[PASS] {name} Worker credential caused zero protected-target connections")


def _check_missing_expired_and_wrong_purpose(
    *,
    execution_private_key: str,
    worker_ca_private_key: str,
    worker_ca_certificate: str,
) -> None:
    _expect_tls_credential_rejection(
        name="missing",
        execution_private_key=execution_private_key,
        worker_ca_private_key=worker_ca_private_key,
        worker_ca_certificate=worker_ca_certificate,
        client_key_pem=None,
        client_certificate_pem=None,
    )

    expired_invocation = str(uuid.uuid4())
    expired_worker = str(uuid.uuid4())
    # Issue through the production path with a clock far enough in the past
    # that both its backdated notBefore tolerance and short lifetime elapsed.
    expired_key, expired_certificate = issue_invocation_worker_certificate(
        ca_private_key_pem=worker_ca_private_key,
        ca_certificate_pem=worker_ca_certificate,
        invocation_id=expired_invocation,
        worker_id=expired_worker,
        now=datetime.now(tz=UTC) - timedelta(minutes=5),
        ttl_seconds=60,
    )
    _expect_tls_credential_rejection(
        name="expired",
        execution_private_key=execution_private_key,
        worker_ca_private_key=worker_ca_private_key,
        worker_ca_certificate=worker_ca_certificate,
        client_key_pem=expired_key,
        client_certificate_pem=expired_certificate,
        invocation_id=expired_invocation,
        worker_id=expired_worker,
    )

    ca_key = serialization.load_pem_private_key(
        worker_ca_private_key.encode("utf-8"), password=None
    )
    ca_certificate = x509.load_pem_x509_certificate(worker_ca_certificate.encode("utf-8"))
    if not isinstance(ca_key, rsa.RSAPrivateKey):
        raise LiveCheckError("worker_ca_key_type_invalid")
    wrong_invocation = str(uuid.uuid4())
    wrong_worker = str(uuid.uuid4())
    wrong_key, wrong_certificate = _create_leaf(
        ca_key=ca_key,
        ca_certificate=ca_certificate,
        common_name="wrong-purpose-worker",
        uri=(
            "spiffe://secure-agent-gateway/worker/"
            f"{wrong_invocation}/{wrong_worker}"
        ),
        usage=ExtendedKeyUsageOID.SERVER_AUTH,
    )
    _expect_tls_credential_rejection(
        name="wrong-purpose",
        execution_private_key=execution_private_key,
        worker_ca_private_key=worker_ca_private_key,
        worker_ca_certificate=worker_ca_certificate,
        client_key_pem=_private_pem(wrong_key),
        client_certificate_pem=_certificate_pem(wrong_certificate),
        invocation_id=wrong_invocation,
        worker_id=wrong_worker,
    )


def _check_invocation_binding(
    *,
    execution_private_key: str,
    worker_ca_private_key: str,
    worker_ca_certificate: str,
) -> None:
    baseline = _observe_protected_connections(
        execution_private_key=execution_private_key,
        worker_ca_private_key=worker_ca_private_key,
        worker_ca_certificate=worker_ca_certificate,
    )
    certificate_invocation = str(uuid.uuid4())
    grant_invocation = str(uuid.uuid4())
    worker_id = str(uuid.uuid4())
    request = _request(
        execution_private_key=execution_private_key,
        worker_id=worker_id,
        invocation_id=grant_invocation,
        url=PROTECTED_URL,
    )
    worker_key, worker_certificate = _worker_credential(
        ca_private_key=worker_ca_private_key,
        ca_certificate=worker_ca_certificate,
        invocation_id=certificate_invocation,
        worker_id=worker_id,
    )
    result = _exchange(
        request,
        client_key_pem=worker_key,
        client_certificate_pem=worker_certificate,
    )
    if (
        result.status != "denied"
        or result.error_code != "broker_authentication_failed"
        or len(result.decisions) != 1
        or result.decisions[0].decision != "deny"
        or result.decisions[0].dns_duration_ms != 0
        or result.decisions[0].resolved_address_hashes
    ):
        raise LiveCheckError("invocation_mismatch_not_cleanly_denied")
    observed = _observe_protected_connections(
        execution_private_key=execution_private_key,
        worker_ca_private_key=worker_ca_private_key,
        worker_ca_certificate=worker_ca_certificate,
    )
    if observed != baseline:
        raise LiveCheckError("invocation_mismatch_caused_outbound_connection")
    print("[PASS] trusted TLS client reached broker authorization")
    print("[PASS] cross-invocation Worker identity rejected before DNS or egress")
    print("[PASS] cross-invocation rejection caused zero protected-target connections")


def _check_positive_control(
    *,
    execution_private_key: str,
    worker_ca_private_key: str,
    worker_ca_certificate: str,
) -> None:
    invocation_id = str(uuid.uuid4())
    worker_id = str(uuid.uuid4())
    request = _request(
        execution_private_key=execution_private_key,
        worker_id=worker_id,
        invocation_id=invocation_id,
        url=ALLOWED_URL,
    )
    worker_key, worker_certificate = _worker_credential(
        ca_private_key=worker_ca_private_key,
        ca_certificate=worker_ca_certificate,
        invocation_id=invocation_id,
        worker_id=worker_id,
    )
    result = _exchange(
        request,
        client_key_pem=worker_key,
        client_certificate_pem=worker_certificate,
    )
    if (
        result.status != "succeeded"
        or result.text != "milestone-2 controlled egress fixture\n"
    ):
        raise LiveCheckError("matching_positive_control_failed")
    print("[PASS] matching Worker identity and authorization succeeded")
    print("[PASS] positive control reached the allowed HTTPS fixture")


def main() -> int:
    try:
        execution_private_key = (KEYS_DIR / "execution-grant-private.pem").read_text(
            encoding="utf-8"
        )
        worker_ca_private_key = (KEYS_DIR / "worker-client-ca-private.pem").read_text(
            encoding="utf-8"
        )
        worker_ca_certificate = (KEYS_DIR / "worker-client-ca-cert.pem").read_text(
            encoding="utf-8"
        )
        _check_positive_control(
            execution_private_key=execution_private_key,
            worker_ca_private_key=worker_ca_private_key,
            worker_ca_certificate=worker_ca_certificate,
        )
        _check_unknown_ca(
            execution_private_key=execution_private_key,
            worker_ca_private_key=worker_ca_private_key,
            worker_ca_certificate=worker_ca_certificate,
        )
        _check_missing_expired_and_wrong_purpose(
            execution_private_key=execution_private_key,
            worker_ca_private_key=worker_ca_private_key,
            worker_ca_certificate=worker_ca_certificate,
        )
        _check_invocation_binding(
            execution_private_key=execution_private_key,
            worker_ca_private_key=worker_ca_private_key,
            worker_ca_certificate=worker_ca_certificate,
        )
    except (LiveCheckError, OSError, ssl.SSLError, ValueError) as exc:
        print(f"[FAIL] live broker authentication verification: {exc}")
        return 1
    print("\nAll live broker authentication and invocation-binding checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
