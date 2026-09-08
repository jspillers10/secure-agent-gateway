#!/usr/bin/env python
"""Generate local, ephemeral identity and workload credentials for Compose.

Writes the delegated-token keypair, execution-grant keypair, development CAs,
and the Gateway, Launcher, OPA, broker, and separate fixture identities under
./devkeys. Compose mounts only the files required by each service. This
directory and every PEM file are gitignored. These credentials are local
fixtures, not production workload identity.

This is local development tooling, not part of the gateway service itself.
"""

from __future__ import annotations

import ipaddress
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "devkeys"


def _private_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _public_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _write(name: str, value: bytes, *, private: bool = False) -> None:
    path = OUTPUT_DIR / name
    path.write_bytes(value)
    if private:
        path.chmod(0o600)
    print(f"Wrote {path}")


def _create_ca(common_name: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(tz=UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _create_leaf(
    *,
    ca_key: rsa.RSAPrivateKey,
    ca_certificate: x509.Certificate,
    common_name: str,
    uri: str,
    usage: ObjectIdentifier,
    dns_names: tuple[str, ...] = (),
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(tz=UTC)
    san_values: list[x509.GeneralName] = [x509.UniformResourceIdentifier(uri)]
    san_values.extend(x509.DNSName(name) for name in dns_names)
    san_values.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .add_extension(x509.SubjectAlternativeName(san_values), critical=False)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return key, certificate


def main() -> int:
    OUTPUT_DIR.mkdir(exist_ok=True)

    token_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _write("private.pem", _private_pem(token_key), private=True)
    _write("public.pem", _public_pem(token_key))

    grant_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    _write("execution-grant-private.pem", _private_pem(grant_key), private=True)
    _write("execution-grant-public.pem", _public_pem(grant_key))

    client_ca_key, client_ca_cert = _create_ca("secure-agent-development-client-ca")
    worker_ca_key, worker_ca_cert = _create_ca("secure-agent-development-worker-client-ca")
    server_ca_key, server_ca_cert = _create_ca("secure-agent-development-server-ca")
    _write("gateway-client-ca-private.pem", _private_pem(client_ca_key), private=True)
    _write("gateway-client-ca-cert.pem", client_ca_cert.public_bytes(serialization.Encoding.PEM))
    _write("worker-client-ca-private.pem", _private_pem(worker_ca_key), private=True)
    _write(
        "worker-client-ca-cert.pem", worker_ca_cert.public_bytes(serialization.Encoding.PEM)
    )
    _write("internal-server-ca-private.pem", _private_pem(server_ca_key), private=True)
    _write("internal-server-ca-cert.pem", server_ca_cert.public_bytes(serialization.Encoding.PEM))

    gateway_key, gateway_cert = _create_leaf(
        ca_key=client_ca_key,
        ca_certificate=client_ca_cert,
        common_name="gateway",
        uri="spiffe://secure-agent-gateway/gateway",
        usage=ExtendedKeyUsageOID.CLIENT_AUTH,
        dns_names=("gateway",),
    )
    launcher_key, launcher_cert = _create_leaf(
        ca_key=server_ca_key,
        ca_certificate=server_ca_cert,
        common_name="launcher",
        uri="spiffe://secure-agent-gateway/launcher",
        usage=ExtendedKeyUsageOID.SERVER_AUTH,
        dns_names=("launcher",),
    )
    opa_key, opa_cert = _create_leaf(
        ca_key=server_ca_key,
        ca_certificate=server_ca_cert,
        common_name="opa",
        uri="spiffe://secure-agent-gateway/opa",
        usage=ExtendedKeyUsageOID.SERVER_AUTH,
        dns_names=("opa",),
    )
    egress_key, egress_cert = _create_leaf(
        ca_key=server_ca_key,
        ca_certificate=server_ca_cert,
        common_name="egress-broker",
        uri="spiffe://secure-agent-gateway/egress-broker",
        usage=ExtendedKeyUsageOID.SERVER_AUTH,
        dns_names=("egress-broker",),
    )
    fixture_key, fixture_cert = _create_leaf(
        ca_key=server_ca_key,
        ca_certificate=server_ca_cert,
        common_name="milestone2-web-fixture",
        uri="spiffe://secure-agent-gateway/milestone2-web-fixture",
        usage=ExtendedKeyUsageOID.SERVER_AUTH,
        dns_names=(
            "fixture.secure-agent.test",
            "redirect.secure-agent.test",
            "blocked.secure-agent.test",
        ),
    )
    protected_fixture_key, protected_fixture_cert = _create_leaf(
        ca_key=server_ca_key,
        ca_certificate=server_ca_cert,
        common_name="milestone2-protected-fixture",
        uri="spiffe://secure-agent-gateway/milestone2-protected-fixture",
        usage=ExtendedKeyUsageOID.SERVER_AUTH,
        dns_names=("blocked.secure-agent.test", "rebinding.secure-agent.test"),
    )
    _write("gateway-client-key.pem", _private_pem(gateway_key), private=True)
    _write("gateway-client-cert.pem", gateway_cert.public_bytes(serialization.Encoding.PEM))
    _write("launcher-key.pem", _private_pem(launcher_key), private=True)
    _write("launcher-cert.pem", launcher_cert.public_bytes(serialization.Encoding.PEM))
    _write("opa-key.pem", _private_pem(opa_key), private=True)
    _write("opa-cert.pem", opa_cert.public_bytes(serialization.Encoding.PEM))
    _write("egress-broker-key.pem", _private_pem(egress_key), private=True)
    _write("egress-broker-cert.pem", egress_cert.public_bytes(serialization.Encoding.PEM))
    _write("web-fixture-key.pem", _private_pem(fixture_key), private=True)
    _write("web-fixture-cert.pem", fixture_cert.public_bytes(serialization.Encoding.PEM))
    _write(
        "protected-fixture-key.pem", _private_pem(protected_fixture_key), private=True
    )
    _write(
        "protected-fixture-cert.pem",
        protected_fixture_cert.public_bytes(serialization.Encoding.PEM),
    )

    print("All files are gitignored and development-only. Do not use them in production.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
