from __future__ import annotations

import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID
from scripts.generate_dev_keys import _create_ca, _create_leaf

from gateway.workload.certificates import (
    WorkloadCertificateError,
    issue_invocation_worker_certificate,
    verify_workload_certificate,
)


def _pem(certificate: object) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")  # type: ignore[attr-defined]


def _write_private_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def test_invocation_worker_certificate_passes_strict_mutual_tls(tmp_path: Path) -> None:
    worker_ca_key, worker_ca = _create_ca("worker-client-ca")
    server_ca_key, server_ca = _create_ca("broker-server-ca")
    server_key, server_certificate = _create_leaf(
        ca_key=server_ca_key,
        ca_certificate=server_ca,
        common_name="broker.test",
        uri="spiffe://secure-agent-gateway/egress-broker",
        usage=ExtendedKeyUsageOID.SERVER_AUTH,
        dns_names=("broker.test",),
    )
    worker_key_pem, worker_certificate_pem = issue_invocation_worker_certificate(
        ca_private_key_pem=worker_ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8"),
        ca_certificate_pem=_pem(worker_ca),
        invocation_id="invocation-1",
        worker_id="worker-1",
    )

    server_key_path = tmp_path / "server-key.pem"
    server_certificate_path = tmp_path / "server-cert.pem"
    worker_key_path = tmp_path / "worker-key.pem"
    worker_certificate_path = tmp_path / "worker-cert.pem"
    _write_private_key(server_key_path, server_key)
    server_certificate_path.write_text(_pem(server_certificate), encoding="utf-8")
    worker_key_path.write_text(worker_key_pem, encoding="utf-8")
    worker_certificate_path.write_text(worker_certificate_pem, encoding="utf-8")

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.verify_mode = ssl.CERT_REQUIRED
    server_context.verify_flags |= ssl.VERIFY_X509_STRICT
    server_context.load_cert_chain(server_certificate_path, server_key_path)
    server_context.load_verify_locations(cadata=_pem(worker_ca))

    client_context = ssl.create_default_context(cadata=_pem(server_ca))
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2
    client_context.load_cert_chain(worker_certificate_path, worker_key_path)

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    errors: list[BaseException] = []
    peer_certificates: list[bool] = []

    def serve() -> None:
        try:
            connection, _address = listener.accept()
            with connection, server_context.wrap_socket(connection, server_side=True) as tls:
                peer_certificates.append(tls.getpeercert(binary_form=True) is not None)
                assert tls.recv(1) == b"x"
                tls.sendall(b"x")
        except BaseException as exc:  # pragma: no cover - assertion reports the exception
            errors.append(exc)

    server_thread = threading.Thread(target=serve, daemon=True)
    server_thread.start()
    try:
        with (
            socket.create_connection(listener.getsockname(), timeout=5) as connection,
            client_context.wrap_socket(connection, server_hostname="broker.test") as tls,
        ):
            tls.sendall(b"x")
            assert tls.recv(1) == b"x"
    finally:
        listener.close()
        server_thread.join(timeout=5)

    assert not server_thread.is_alive()
    assert errors == []
    assert peer_certificates == [True]


def test_gateway_development_certificate_has_exact_role_and_usage() -> None:
    ca_key, ca = _create_ca("test-client-ca")
    _key, certificate = _create_leaf(
        ca_key=ca_key,
        ca_certificate=ca,
        common_name="gateway",
        uri="spiffe://secure-agent-gateway/gateway",
        usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    verify_workload_certificate(
        _pem(certificate),
        ca_certificate_pem=_pem(ca),
        expected_uri="spiffe://secure-agent-gateway/gateway",
        usage="client",
    )


def test_missing_expired_unknown_ca_and_wrong_service_credentials_are_rejected() -> None:
    ca_key, ca = _create_ca("expected-ca")
    _other_key, other_ca = _create_ca("other-ca")
    _key, gateway = _create_leaf(
        ca_key=ca_key,
        ca_certificate=ca,
        common_name="gateway",
        uri="spiffe://secure-agent-gateway/gateway",
        usage=ExtendedKeyUsageOID.CLIENT_AUTH,
    )
    _launcher_key, launcher = _create_leaf(
        ca_key=ca_key,
        ca_certificate=ca,
        common_name="launcher",
        uri="spiffe://secure-agent-gateway/launcher",
        usage=ExtendedKeyUsageOID.SERVER_AUTH,
    )

    with pytest.raises(WorkloadCertificateError, match="credential_missing_or_malformed"):
        verify_workload_certificate(
            "",
            ca_certificate_pem=_pem(ca),
            expected_uri="spiffe://secure-agent-gateway/gateway",
            usage="client",
        )
    with pytest.raises(WorkloadCertificateError, match="credential_expired"):
        verify_workload_certificate(
            _pem(gateway),
            ca_certificate_pem=_pem(ca),
            expected_uri="spiffe://secure-agent-gateway/gateway",
            usage="client",
            now=datetime.now(tz=UTC) + timedelta(days=8),
        )
    with pytest.raises(WorkloadCertificateError, match="unknown_ca"):
        verify_workload_certificate(
            _pem(gateway),
            ca_certificate_pem=_pem(other_ca),
            expected_uri="spiffe://secure-agent-gateway/gateway",
            usage="client",
        )
    with pytest.raises(WorkloadCertificateError, match="wrong_service_identity"):
        verify_workload_certificate(
            _pem(launcher),
            ca_certificate_pem=_pem(ca),
            expected_uri="spiffe://secure-agent-gateway/gateway",
            usage="client",
        )
