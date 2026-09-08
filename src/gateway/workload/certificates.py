"""Strict certificate validation used by tests and credential generation checks.

TLS libraries perform the live handshake. This helper makes role, expiry, and
CA expectations independently testable with the same development certificate
profiles.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Literal

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class WorkloadCertificateError(Exception):
    pass


def verify_workload_certificate(
    certificate_pem: str,
    *,
    ca_certificate_pem: str,
    expected_uri: str,
    usage: Literal["client", "server"],
    now: datetime | None = None,
) -> None:
    try:
        certificate = x509.load_pem_x509_certificate(certificate_pem.encode("utf-8"))
        ca_certificate = x509.load_pem_x509_certificate(ca_certificate_pem.encode("utf-8"))
    except ValueError as exc:
        raise WorkloadCertificateError("credential_missing_or_malformed") from exc

    current = now or datetime.now(tz=UTC)
    if current < certificate.not_valid_before_utc or current >= certificate.not_valid_after_utc:
        raise WorkloadCertificateError("credential_expired_or_not_yet_valid")
    if certificate.issuer != ca_certificate.subject:
        raise WorkloadCertificateError("unknown_ca")

    ca_public_key = ca_certificate.public_key()
    signature_hash = certificate.signature_hash_algorithm
    if signature_hash is None:
        raise WorkloadCertificateError("unsupported_signature_algorithm")
    try:
        if isinstance(ca_public_key, rsa.RSAPublicKey):
            ca_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                signature_hash,
            )
        elif isinstance(ca_public_key, ec.EllipticCurvePublicKey):
            ca_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(signature_hash),
            )
        else:
            raise WorkloadCertificateError("unsupported_ca_key")
    except InvalidSignature as exc:
        raise WorkloadCertificateError("unknown_ca") from exc

    try:
        uris = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.UniformResourceIdentifier)
        eku = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound as exc:
        raise WorkloadCertificateError("credential_profile_invalid") from exc
    expected_usage = (
        ExtendedKeyUsageOID.CLIENT_AUTH if usage == "client" else ExtendedKeyUsageOID.SERVER_AUTH
    )
    if uris != [expected_uri] or expected_usage not in eku:
        raise WorkloadCertificateError("wrong_service_identity")


def issue_invocation_worker_certificate(
    *,
    ca_private_key_pem: str,
    ca_certificate_pem: str,
    invocation_id: str,
    worker_id: str,
    now: datetime | None = None,
    ttl_seconds: int = 60,
) -> tuple[str, str]:
    """Issue a short-lived client identity bound to one Worker invocation."""
    if (
        not invocation_id
        or not worker_id
        or any("/" in value for value in (invocation_id, worker_id))
    ):
        raise WorkloadCertificateError("invocation_identity_invalid")
    if not 1 <= ttl_seconds <= 300:
        raise WorkloadCertificateError("credential_ttl_invalid")
    try:
        ca_key = serialization.load_pem_private_key(
            ca_private_key_pem.encode("utf-8"), password=None
        )
        ca_certificate = x509.load_pem_x509_certificate(ca_certificate_pem.encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise WorkloadCertificateError("issuer_credential_invalid") from exc
    if not isinstance(ca_key, rsa.RSAPrivateKey):
        raise WorkloadCertificateError("issuer_key_invalid")
    current = now or datetime.now(tz=UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    uri = f"spiffe://secure-agent-gateway/worker/{invocation_id}/{worker_id}"
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "invocation-worker")]))
        .issuer_name(ca_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(current - timedelta(seconds=5))
        .not_valid_after(current + timedelta(seconds=ttl_seconds))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=True
        )
        .sign(ca_key, hashes.SHA256())
    )
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return private_pem, certificate_pem
