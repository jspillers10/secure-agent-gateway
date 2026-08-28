from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID
from scripts.generate_dev_keys import _create_ca, _create_leaf

from gateway.workload.certificates import WorkloadCertificateError, verify_workload_certificate


def _pem(certificate: object) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")  # type: ignore[attr-defined]


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
