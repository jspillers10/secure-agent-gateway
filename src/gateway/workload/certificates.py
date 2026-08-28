"""Strict certificate validation used by tests and credential generation checks.

TLS libraries perform the live handshake. This helper makes role, expiry, and
CA expectations independently testable with the same development certificate
profiles.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID


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
