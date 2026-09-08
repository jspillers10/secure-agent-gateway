"""Milestone 2 destination, redirect, binding, and zero-connection matrix."""

from __future__ import annotations

import importlib
import ipaddress
import json
import logging
import multiprocessing
import socket
import ssl
import time
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from multiprocessing.connection import Connection
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from pydantic import ValidationError

from gateway.egress.broker import (
    BrokerPolicyError,
    EgressBroker,
    EgressBrokerSettings,
    PinnedTlsHttpConnector,
    ProcessDnsResolver,
    ResolvedAddress,
    Resolver,
    UpstreamResponse,
)
from gateway.egress.config import EgressConfigurationError, load_egress_settings
from gateway.egress.protocol import BrokerFetchRequest, BrokerFetchResult
from gateway.egress.service import UnixTlsEgressServer
from gateway.egress.url_policy import (
    DestinationPolicyError,
    canonicalize_https_url,
    classify_forbidden_address,
)
from gateway.execution.local_launcher import InProcessLauncher
from gateway.execution.protocol import (
    ActionEnvelope,
    ApprovalBinding,
    EgressGrant,
    ToolIdentity,
)
from gateway.execution.signing import ExecutionGrantSigner
from gateway.hashing import sha256_hex
from gateway.registry.tools import WORKER_ARTIFACT_DIGEST
from gateway.worker.main import CALCULATED_MAX_WEB_RESULT_BYTES, MAX_OUTPUT_BYTES
from gateway.worker.runtime import WorkerRequest, execute_worker_request
from gateway.workload.certificates import issue_invocation_worker_certificate
from tests.helpers.keys import generate_rsa_keypair

ALLOWED = "https://allowed.example"
REDIRECT = "https://redirect.example"
PUBLIC_V4 = "93.184.216.34"


def _blocking_resolution_worker(connection: Connection, _host: str, _port: int) -> None:
    try:
        time.sleep(30)
    finally:
        connection.close()


def _ca(common_name: str = "worker-ca") -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(tz=UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    cert = certificate.public_bytes(serialization.Encoding.PEM).decode()
    return private, cert


def _leaf(
    ca_private: str,
    ca_certificate: str,
    *,
    uri: str,
    usage: ExtendedKeyUsageOID,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
) -> str:
    ca_key = serialization.load_pem_private_key(ca_private.encode(), password=None)
    assert isinstance(ca_key, rsa.RSAPrivateKey)
    ca_cert = x509.load_pem_x509_certificate(ca_certificate.encode())
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(tz=UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test")]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(minutes=1))
        .not_valid_after(not_after or now + timedelta(minutes=5))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(uri)]), False)
        .add_extension(x509.ExtendedKeyUsage([usage]), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode()


def _grant(
    private_key: str,
    *,
    url: str = f"{ALLOWED}/text",
    allowed_origins: tuple[str, ...] = (ALLOWED, REDIRECT),
    invocation_id: str = "invocation-1",
    now: datetime | None = None,
    max_redirects: int = 3,
    max_bytes: int = 65_536,
    timeout: float = 5.0,
    ttl_seconds: int = 30,
    canonicalize: bool = True,
) -> Any:
    canonical = canonicalize_https_url(url).value if canonicalize else url
    arguments = {"url": canonical}
    action = ActionEnvelope(
        invocation_id=invocation_id,
        request_id="request-1",
        correlation_id="correlation-1",
        agent_id="agent-1",
        delegated_user_id="user-1",
        tool=ToolIdentity(name="web.fetch_text", artifact_digest=WORKER_ARTIFACT_DIGEST),
        arguments=arguments,
        argument_digest=sha256_hex(arguments),
        approval=ApprovalBinding(required=False, state="not_required"),
        policy_version="2.0.0",
        risk="low",
        destination=canonical,
        created_at=now or datetime.now(tz=UTC),
    )
    authority = EgressGrant(
        initial_url=canonical,
        allowed_origins=allowed_origins,
        max_redirects=max_redirects,
        max_response_bytes=max_bytes,
        timeout_seconds=timeout,
    )
    return ExecutionGrantSigner(
        private_key,
        issuer="secure-agent-gateway",
        audience="secure-agent-worker-launcher",
        ttl_seconds=ttl_seconds,
    ).issue(action, egress=authority, now=now)


class StaticResolver:
    def __init__(self, answers: dict[str, Sequence[str]]) -> None:
        self.answers = answers
        self.calls: list[str] = []

    def __call__(
        self, host: str, port: int, *, deadline: float
    ) -> tuple[ResolvedAddress, ...]:
        if time.monotonic() >= deadline:
            raise TimeoutError
        self.calls.append(host)
        return tuple(
            ResolvedAddress(ip=ip, family=2, sockaddr=(ip, port))
            for ip in self.answers.get(host, ())
        )


class ScriptedConnector:
    def __init__(self, responses: Sequence[UpstreamResponse | Exception]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str]] = []

    def request(self, url: Any, address: Any, **_kwargs: Any) -> UpstreamResponse:
        self.calls.append((url.value, address.ip))
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def _broker_fixture(
    *,
    resolver: Resolver,
    connector: ScriptedConnector,
    origins: frozenset[str] = frozenset({ALLOWED, REDIRECT}),
    denied_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (),
) -> tuple[EgressBroker, str, str, str]:
    grant_private, grant_public = generate_rsa_keypair()
    ca_private, ca_certificate = _ca()
    broker = EgressBroker(
        EgressBrokerSettings(
            grant_public_key_pem=grant_public,
            grant_issuer="secure-agent-gateway",
            grant_audience="secure-agent-worker-launcher",
            worker_ca_certificate_pem=ca_certificate,
            allowed_origins=origins,
            denied_networks=denied_networks,
        ),
        resolver=resolver,
        connector=connector,
    )
    return broker, grant_private, ca_private, ca_certificate


class _ConnectorRawSocket:
    def __init__(self, events: list[str], timeouts: list[float]) -> None:
        self.events = events
        self.timeouts = timeouts

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def connect(self, _address: object) -> None:
        self.events.append("connect")

    def close(self) -> None:
        self.events.append("raw_close")


class _ConnectorTlsSocket:
    def __init__(self, events: list[str], timeouts: list[float]) -> None:
        self.events = events
        self.timeouts = timeouts

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def do_handshake(self) -> None:
        self.events.append("handshake")

    def sendall(self, _request: bytes) -> None:
        self.events.append("send")

    def close(self) -> None:
        self.events.append("tls_close")


class _ConnectorTlsContext:
    def __init__(self, tls: _ConnectorTlsSocket, events: list[str]) -> None:
        self.tls = tls
        self.events = events

    def wrap_socket(
        self,
        _raw: object,
        *,
        server_hostname: str,
        do_handshake_on_connect: bool,
    ) -> _ConnectorTlsSocket:
        assert server_hostname == "allowed.example"
        assert not do_handshake_on_connect
        self.events.append("wrap")
        return self.tls


class _ConnectorHttpResponse:
    status = 200

    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.headers = SimpleNamespace(raw_items=lambda: ())

    def begin(self) -> None:
        self.events.append("response_begin")

    def getheader(self, name: str, default: str | None = None) -> str | None:
        if name == "Content-Length":
            return "0"
        return default

    def read(self, _limit: int) -> bytes:
        self.events.append("read")
        return b""

    def close(self) -> None:
        self.events.append("response_close")


def _request_and_certificate(
    grant: Any,
    ca_private: str,
    ca_certificate: str,
    *,
    worker_id: str = "worker-1",
    certificate_invocation: str | None = None,
    certificate_now: datetime | None = None,
) -> tuple[BrokerFetchRequest, str]:
    _key, certificate = issue_invocation_worker_certificate(
        ca_private_key_pem=ca_private,
        ca_certificate_pem=ca_certificate,
        invocation_id=certificate_invocation or grant.action.invocation_id,
        worker_id=worker_id,
        now=certificate_now,
    )
    return BrokerFetchRequest(worker_id=worker_id, grant=grant), certificate


def _egress_config_env(tmp_path: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for name in ("server-cert.pem", "server-key.pem", "worker-ca.pem", "grant-public.pem"):
        path = tmp_path / name
        path.write_text(f"fixture-{name}", encoding="utf-8")
        files[name] = str(path)
    return {
        "EGRESS_SOCKET_PATH": "/tmp/broker.sock",  # noqa: S108 - isolated test path
        "EGRESS_SERVER_CERT_FILE": files["server-cert.pem"],
        "EGRESS_SERVER_KEY_FILE": files["server-key.pem"],
        "WORKER_CLIENT_CA_CERT_FILE": files["worker-ca.pem"],
        "GRANT_PUBLIC_KEY_FILE": files["grant-public.pem"],
        "EGRESS_ALLOWED_ORIGINS": "https://allowed.example",
        "EGRESS_DENIED_CIDRS": "11.78.0.0/24,2606:4700:feed::/48",
    }


def test_egress_config_parses_server_owned_ipv4_and_ipv6_denied_cidrs(
    tmp_path: Path,
) -> None:
    settings = load_egress_settings(_egress_config_env(tmp_path))

    assert settings.broker.denied_networks == (
        ipaddress.ip_network("11.78.0.0/24"),
        ipaddress.ip_network("2606:4700:feed::/48"),
    )


@pytest.mark.parametrize(
    "value",
    ["", "not-a-network", "11.78.0.1/24", "11.78.0.0/24,", "::1/129"],
)
def test_invalid_deployment_denied_cidr_configuration_fails_closed(
    tmp_path: Path, value: str
) -> None:
    env = _egress_config_env(tmp_path)
    env["EGRESS_DENIED_CIDRS"] = value

    with pytest.raises(EgressConfigurationError):
        load_egress_settings(env)


@pytest.mark.parametrize(
    "value",
    [
        "http://allowed.example/",
        "ftp://allowed.example/",
        "https://user@allowed.example/",
        "https://allowed.example:444/",
        "https://allowed.example/path#fragment",
        "https://allowed.example\\@127.0.0.1/",
        "https://allowed.example/%zz",
        "https://127.0.0.1/",
        "https://2130706433/",
        "https://0177.0.0.1/",
        "https://0x7f.0.0.1/",
        " https://allowed.example/",
    ],
)
def test_url_confusion_is_rejected(value: str) -> None:
    with pytest.raises(DestinationPolicyError):
        canonicalize_https_url(value)


def test_case_trailing_dot_idna_and_percent_are_canonicalized() -> None:
    assert (
        canonicalize_https_url("HTTPS://ALLOWED.EXAMPLE./a%2f?q=%aa").value
        == "https://allowed.example/a%2F?q=%AA"
    )
    assert canonicalize_https_url("https://BÜCHER.example/").host == "xn--bcher-kva.example"


@pytest.mark.parametrize(
    "value",
    ["https://allowed.example/café", "https://allowed.example/?q=café"],
)
def test_raw_unicode_request_target_is_rejected_but_existing_escapes_are_preserved(
    value: str,
) -> None:
    with pytest.raises(DestinationPolicyError, match="url_request_target_non_ascii"):
        canonicalize_https_url(value)
    assert (
        canonicalize_https_url("https://allowed.example/caf%C3%A9?q=caf%C3%A9").request_target
        == "/caf%C3%A9?q=caf%C3%A9"
    )


def test_upstream_request_is_get_only_and_has_no_cookie_or_authentication() -> None:
    request = PinnedTlsHttpConnector._request_bytes(  # noqa: SLF001
        canonicalize_https_url("https://allowed.example/path?q=1")
    ).decode("ascii")
    assert request.startswith("GET /path?q=1 HTTP/1.1\r\n")
    assert "Authorization:" not in request
    assert "Cookie:" not in request
    assert "Proxy-Authorization:" not in request


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "169.254.169.254",
        "0.0.0.0",  # noqa: S104 - destination-policy attack fixture
        "::1",
        "fd00::1",
        "fe80::1",
        "ff02::1",
        "fd00:ec2::254",
        "::ffff:127.0.0.1",
    ],
)
def test_ipv4_and_ipv6_non_public_ranges_are_blocked(address: str) -> None:
    assert classify_forbidden_address(address) is not None


def test_allowed_direct_fetch_returns_exact_utf8_bytes_and_audit() -> None:
    resolver = StaticResolver({"allowed.example": [PUBLIC_V4]})
    connector = ScriptedConnector(
        [UpstreamResponse(200, {"content-type": "text/plain; charset=utf-8"}, b"hello")]
    )
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver, connector=connector
    )
    grant = _grant(grant_private)
    request, certificate = _request_and_certificate(grant, ca_private, ca_certificate)

    result = broker.fetch(request, peer_certificate_pem=certificate)

    assert result.status == "succeeded"
    assert result.text == "hello"
    assert result.byte_count == 5
    assert [(item.decision, item.reason) for item in result.decisions] == [
        ("allow", "response_accepted")
    ]
    assert connector.calls == [(f"{ALLOWED}/text", PUBLIC_V4)]


def test_redirect_destination_is_independently_resolved_and_allowed() -> None:
    resolver = StaticResolver(
        {"allowed.example": [PUBLIC_V4], "redirect.example": ["104.16.1.1"]}
    )
    connector = ScriptedConnector(
        [
            UpstreamResponse(302, {"location": f"{REDIRECT}/final"}, b""),
            UpstreamResponse(200, {"content-type": "text/plain"}, b"redirected"),
        ]
    )
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver, connector=connector
    )
    request, certificate = _request_and_certificate(
        _grant(grant_private), ca_private, ca_certificate
    )

    result = broker.fetch(request, peer_certificate_pem=certificate)

    assert result.status == "succeeded"
    assert resolver.calls == ["allowed.example", "redirect.example"]
    assert [item.reason for item in result.decisions] == ["redirect", "response_accepted"]


@pytest.mark.parametrize(
    "blocked_ip",
    ["127.0.0.1", "10.0.0.2", "169.254.169.254", "::1", "fd00::2", "ff02::1"],
)
def test_blocked_dns_answers_observe_zero_connections(blocked_ip: str) -> None:
    resolver = StaticResolver({"allowed.example": [blocked_ip]})
    connector = ScriptedConnector([])
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver, connector=connector
    )
    request, certificate = _request_and_certificate(
        _grant(grant_private), ca_private, ca_certificate
    )

    result = broker.fetch(request, peer_certificate_pem=certificate)

    assert result.status == "denied"
    assert connector.calls == []
    assert result.decisions[0].decision == "deny"


def test_mixed_public_and_blocked_dns_answer_fails_before_any_connection() -> None:
    resolver = StaticResolver({"allowed.example": [PUBLIC_V4, "127.0.0.1"]})
    connector = ScriptedConnector([])
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver, connector=connector
    )
    request, certificate = _request_and_certificate(
        _grant(grant_private), ca_private, ca_certificate
    )
    result = broker.fetch(request, peer_certificate_pem=certificate)
    assert result.status == "denied"
    assert connector.calls == []


@pytest.mark.parametrize(
    ("network", "address"),
    [("11.78.0.0/24", "11.78.0.11"), ("2606:4700:feed::/48", "2606:4700:feed::11")],
)
def test_deployment_denied_cidr_rejects_allowlisted_destination_before_connection(
    network: str, address: str
) -> None:
    resolver = StaticResolver({"allowed.example": [address]})
    connector = ScriptedConnector([])
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver,
        connector=connector,
        denied_networks=(ipaddress.ip_network(network),),
    )
    request, certificate = _request_and_certificate(
        _grant(grant_private), ca_private, ca_certificate
    )

    result = broker.fetch(request, peer_certificate_pem=certificate)

    assert result.status == "denied"
    assert result.error_code == "address_deployment_denied"
    assert resolver.calls == ["allowed.example"]
    assert connector.calls == []


def test_any_deployment_denied_answer_rejects_the_complete_answer_set() -> None:
    resolver = StaticResolver({"allowed.example": [PUBLIC_V4, "11.78.0.11"]})
    connector = ScriptedConnector([])
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver,
        connector=connector,
        denied_networks=(ipaddress.ip_network("11.78.0.0/24"),),
    )
    request, certificate = _request_and_certificate(
        _grant(grant_private), ca_private, ca_certificate
    )

    result = broker.fetch(request, peer_certificate_pem=certificate)

    assert result.error_code == "address_deployment_denied"
    assert resolver.calls == ["allowed.example"]
    assert connector.calls == []


def test_raw_unicode_target_is_denied_before_dns_or_connection() -> None:
    resolver = StaticResolver({"allowed.example": [PUBLIC_V4]})
    connector = ScriptedConnector([])
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver, connector=connector
    )
    grant = _grant(
        grant_private,
        url="https://allowed.example/café?q=café",
        canonicalize=False,
    )
    request, certificate = _request_and_certificate(grant, ca_private, ca_certificate)

    result = broker.fetch(request, peer_certificate_pem=certificate)

    assert result.status == "denied"
    assert result.error_code == "url_request_target_non_ascii"
    assert resolver.calls == []
    assert connector.calls == []
    assert result.decisions[0].reason == "url_request_target_non_ascii"


def test_excessive_dns_answer_set_is_denied_whole_before_connection() -> None:
    answers = [f"93.184.216.{index}" for index in range(1, 34)]
    resolver = StaticResolver({"allowed.example": answers})
    connector = ScriptedConnector([])
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver, connector=connector
    )
    request, certificate = _request_and_certificate(
        _grant(grant_private), ca_private, ca_certificate
    )

    result = broker.fetch(request, peer_certificate_pem=certificate)

    assert result.status == "denied"
    assert result.error_code == "dns_answer_limit_exceeded"
    assert connector.calls == []
    assert result.decisions[0].resolved_address_count == 33
    assert result.decisions[0].resolved_address_hashes == ()


def test_dns_is_resolved_once_and_connector_receives_the_validated_address() -> None:
    class ChangingResolver(StaticResolver):
        def __call__(
            self, host: str, port: int, *, deadline: float
        ) -> tuple[ResolvedAddress, ...]:
            if time.monotonic() >= deadline:
                raise TimeoutError
            self.calls.append(host)
            ip = PUBLIC_V4 if len(self.calls) == 1 else "127.0.0.1"
            return (ResolvedAddress(ip=ip, family=2, sockaddr=(ip, port)),)

    resolver = ChangingResolver({})
    connector = ScriptedConnector(
        [UpstreamResponse(200, {"content-type": "text/plain"}, b"pinned")]
    )
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver, connector=connector
    )
    request, certificate = _request_and_certificate(
        _grant(grant_private), ca_private, ca_certificate
    )
    result = broker.fetch(request, peer_certificate_pem=certificate)
    assert result.status == "succeeded"
    assert resolver.calls == ["allowed.example"]
    assert connector.calls == [(f"{ALLOWED}/text", PUBLIC_V4)]


def test_allowed_to_blocked_redirect_never_connects_to_protected_target() -> None:
    resolver = StaticResolver(
        {"allowed.example": [PUBLIC_V4], "redirect.example": ["127.0.0.1"]}
    )
    connector = ScriptedConnector(
        [UpstreamResponse(302, {"location": f"{REDIRECT}/private"}, b"")]
    )
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver, connector=connector
    )
    request, certificate = _request_and_certificate(
        _grant(grant_private), ca_private, ca_certificate
    )
    result = broker.fetch(request, peer_certificate_pem=certificate)
    assert result.status == "denied"
    assert connector.calls == [(f"{ALLOWED}/text", PUBLIC_V4)]
    assert [item.decision for item in result.decisions] == ["allow", "deny"]


@pytest.mark.parametrize(
    ("responses", "expected"),
    [
        (
            [UpstreamResponse(302, {"location": f"{ALLOWED}/text"}, b"")],
            "redirect_loop",
        ),
        ([BrokerPolicyError("response_too_large")], "response_too_large"),
        ([TimeoutError()], "fetch_timeout"),
        ([ssl.SSLCertVerificationError()], "tls_verification_failed"),
    ],
)
def test_redirect_loop_size_slow_and_tls_fail_closed(
    responses: Sequence[UpstreamResponse | Exception], expected: str
) -> None:
    resolver = StaticResolver({"allowed.example": [PUBLIC_V4]})
    connector = ScriptedConnector(responses)
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver, connector=connector
    )
    request, certificate = _request_and_certificate(
        _grant(grant_private), ca_private, ca_certificate
    )
    result = broker.fetch(request, peer_certificate_pem=certificate)
    assert result.status == "denied"
    assert result.error_code == expected
    assert result.decisions[-1].decision == "deny"


def test_process_dns_timeout_reaps_the_blocked_resolver() -> None:
    before = {process.pid for process in multiprocessing.active_children()}
    resolver = ProcessDnsResolver(worker=_blocking_resolution_worker)
    started = time.monotonic()

    with pytest.raises(TimeoutError):
        resolver("delayed.example", 443, deadline=started + 0.2)

    elapsed = time.monotonic() - started
    after = {process.pid for process in multiprocessing.active_children()}
    assert elapsed < 1.0
    assert after <= before


def test_process_dns_resolver_returns_system_answers_and_reaps_child() -> None:
    before = {process.pid for process in multiprocessing.active_children()}

    addresses = ProcessDnsResolver()("localhost", 443, deadline=time.monotonic() + 3.0)

    after = {process.pid for process in multiprocessing.active_children()}
    assert addresses
    assert all(address.ip in {"127.0.0.1", "::1"} for address in addresses)
    assert after <= before


def test_configured_deadline_stops_delayed_dns_before_connection() -> None:
    connector = ScriptedConnector([])
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=ProcessDnsResolver(worker=_blocking_resolution_worker),
        connector=connector,
    )
    request, certificate = _request_and_certificate(
        _grant(grant_private, timeout=0.2), ca_private, ca_certificate
    )
    started = time.monotonic()

    result = broker.fetch(request, peer_certificate_pem=certificate)

    assert result.status == "denied"
    assert result.error_code == "fetch_timeout"
    assert connector.calls == []
    assert time.monotonic() - started < 1.0


def test_grant_expiry_caps_dns_and_prevents_post_expiry_connection() -> None:
    connector = ScriptedConnector([])
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=ProcessDnsResolver(worker=_blocking_resolution_worker),
        connector=connector,
    )
    _key, certificate = issue_invocation_worker_certificate(
        ca_private_key_pem=ca_private,
        ca_certificate_pem=ca_certificate,
        invocation_id="invocation-1",
        worker_id="worker-1",
    )
    grant = _grant(grant_private, timeout=5.0, ttl_seconds=1)
    request = BrokerFetchRequest(worker_id="worker-1", grant=grant)
    started = time.monotonic()

    result = broker.fetch(request, peer_certificate_pem=certificate)

    assert result.status == "denied"
    assert result.error_code == "fetch_timeout"
    assert connector.calls == []
    assert time.monotonic() - started < 2.0


@pytest.mark.parametrize(
    ("headers", "body", "expected"),
    [
        ({"content-type": "application/json"}, b"{}", "content_type_forbidden"),
        (
            {"content-type": "text/plain; charset=iso-8859-1"},
            b"text",
            "content_charset_forbidden",
        ),
        ({"content-type": "text/plain"}, b"x" * 1025, "response_too_large"),
        ({"content-type": "text/plain"}, b"\xff", "content_not_utf8"),
    ],
)
def test_content_type_size_and_utf8_limits_are_enforced(
    headers: dict[str, str], body: bytes, expected: str
) -> None:
    resolver = StaticResolver({"allowed.example": [PUBLIC_V4]})
    connector = ScriptedConnector([UpstreamResponse(200, headers, body)])
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver, connector=connector
    )
    request, certificate = _request_and_certificate(
        _grant(grant_private, max_bytes=1024), ca_private, ca_certificate
    )
    result = broker.fetch(request, peer_certificate_pem=certificate)
    assert result.status == "denied"
    assert result.error_code == expected


def test_documented_64_kib_body_boundary_succeeds_and_one_byte_more_is_denied() -> None:
    at_limit = b"x" * 65_536
    resolver = StaticResolver({"allowed.example": [PUBLIC_V4]})
    connector = ScriptedConnector(
        [UpstreamResponse(200, {"content-type": "text/plain"}, at_limit)]
    )
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver, connector=connector
    )
    request, certificate = _request_and_certificate(
        _grant(grant_private, max_bytes=65_536), ca_private, ca_certificate
    )
    succeeded = broker.fetch(request, peer_certificate_pem=certificate)
    assert succeeded.status == "succeeded"
    assert succeeded.byte_count == 65_536

    resolver = StaticResolver({"allowed.example": [PUBLIC_V4]})
    connector = ScriptedConnector(
        [UpstreamResponse(200, {"content-type": "text/plain"}, at_limit + b"x")]
    )
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver, connector=connector
    )
    request, certificate = _request_and_certificate(
        _grant(grant_private, max_bytes=65_536), ca_private, ca_certificate
    )
    denied = broker.fetch(request, peer_certificate_pem=certificate)
    assert denied.status == "denied"
    assert denied.error_code == "response_too_large"


def test_disallowed_redirect_origin_is_denied_before_dns_or_connection() -> None:
    resolver = StaticResolver({"allowed.example": [PUBLIC_V4]})
    connector = ScriptedConnector(
        [UpstreamResponse(302, {"location": "https://not-allowed.example/"}, b"")]
    )
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver, connector=connector
    )
    request, certificate = _request_and_certificate(
        _grant(grant_private), ca_private, ca_certificate
    )
    result = broker.fetch(request, peer_certificate_pem=certificate)
    assert result.error_code == "destination_not_allowed"
    assert resolver.calls == ["allowed.example"]
    assert len(connector.calls) == 1


def test_redirect_hop_limit_is_small_and_enforced() -> None:
    resolver = StaticResolver(
        {"allowed.example": [PUBLIC_V4], "redirect.example": ["104.16.1.1"]}
    )
    connector = ScriptedConnector(
        [UpstreamResponse(302, {"location": f"{REDIRECT}/one"}, b"")]
    )
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver, connector=connector
    )
    request, certificate = _request_and_certificate(
        _grant(grant_private, max_redirects=0), ca_private, ca_certificate
    )
    result = broker.fetch(request, peer_certificate_pem=certificate)
    assert result.status == "denied"
    assert result.error_code == "redirect_limit_exceeded"
    assert len(connector.calls) == 1


def test_broker_protocol_has_no_method_destination_or_credential_escape_hatches() -> None:
    grant_private, _grant_public = generate_rsa_keypair()
    payload = {
        "worker_id": "worker-1",
        "grant": _grant(grant_private).model_dump(mode="json"),
        "method": "POST",
        "url": "https://attacker.example/",
        "headers": {"Authorization": "secret"},
    }
    with pytest.raises(ValidationError):
        BrokerFetchRequest.model_validate(payload)


@pytest.mark.parametrize(
    ("protocol_case", "expected_reason"),
    [
        ("schema", "schema_invalid"),
        ("framing", "framing_invalid"),
        ("encoding", "encoding_invalid"),
        ("nested", "json_invalid"),
    ],
)
def test_protocol_validation_rejection_redacts_logs_and_response(
    protocol_case: str,
    expected_reason: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret_marker = "broker-secret-marker-must-not-appear"
    grant_private, _grant_public = generate_rsa_keypair()
    ca_private, ca_certificate = _ca()
    grant = _grant(grant_private)
    _key, certificate_pem = issue_invocation_worker_certificate(
        ca_private_key_pem=ca_private,
        ca_certificate_pem=ca_certificate,
        invocation_id=grant.action.invocation_id,
        worker_id="worker-1",
    )
    certificate_der = x509.load_pem_x509_certificate(
        certificate_pem.encode("utf-8")
    ).public_bytes(serialization.Encoding.DER)
    if protocol_case == "schema":
        payload = json.dumps(
            {
                "worker_id": "worker-1",
                "grant": grant.model_dump(mode="json"),
                "headers": {"Authorization": secret_marker},
            }
        ).encode("utf-8") + b"\n"
    elif protocol_case == "framing":
        payload = json.dumps({"marker": secret_marker}).encode("utf-8")
    elif protocol_case == "encoding":
        payload = b'{"marker":"' + secret_marker.encode("ascii") + b'\xff"}\n'
    else:
        payload = b"[" * 5000 + b"0" + b"]" * 5000 + b"\n"

    class FakeRawSocket:
        def settimeout(self, _timeout: float) -> None:
            pass

        def close(self) -> None:
            pass

    class FakeTlsSocket:
        def __init__(self) -> None:
            self.remaining = payload
            self.sent: list[bytes] = []

        def getpeercert(self, *, binary_form: bool) -> bytes:
            assert binary_form
            return certificate_der

        def recv(self, _limit: int) -> bytes:
            chunk, self.remaining = self.remaining, b""
            return chunk

        def sendall(self, value: bytes) -> None:
            self.sent.append(value)

        def close(self) -> None:
            pass

    tls = FakeTlsSocket()
    server = object.__new__(UnixTlsEgressServer)
    server._settings = SimpleNamespace(  # type: ignore[attr-defined]
        broker=SimpleNamespace(max_timeout_seconds=5.0)
    )
    server._context = SimpleNamespace(  # type: ignore[attr-defined]
        wrap_socket=lambda _raw, server_side: tls
    )
    server._broker = SimpleNamespace()  # type: ignore[attr-defined]
    caplog.set_level(logging.WARNING, logger="gateway.egress.service")

    server._handle_connection(FakeRawSocket())  # type: ignore[arg-type]

    assert secret_marker not in caplog.text
    assert "Traceback" not in caplog.text
    assert "input_value" not in caplog.text
    assert f"reason={expected_reason}" in caplog.text
    assert len(tls.sent) == 1
    encoded_response = tls.sent[0]
    assert secret_marker.encode("utf-8") not in encoded_response
    response = BrokerFetchResult.model_validate_json(encoded_response)
    assert response.status == "denied"
    assert response.error_code == "broker_protocol_invalid"


def test_worst_case_valid_web_result_fits_finite_worker_and_launcher_limit() -> None:
    grant_private, grant_public = generate_rsa_keypair()
    result_private, _result_public = generate_rsa_keypair()
    prefix = "https://allowed.example/"
    long_url = prefix + "x" * (2048 - len(prefix))
    grant = _grant(grant_private, url=long_url, max_bytes=65_536)

    class WorstCaseEgressClient:
        def fetch(self, _request: BrokerFetchRequest) -> BrokerFetchResult:
            return BrokerFetchResult(
                status="succeeded",
                text="\x00" * 65_536,
                final_url=long_url,
                content_type="text/plain",
                byte_count=65_536,
                decisions=(),
            )

    result = execute_worker_request(
        WorkerRequest(
            grant=grant,
            worker_id="w" * 128,
            grant_public_key_pem=grant_public,
            result_private_key_pem=result_private,
            expected_issuer="secure-agent-gateway",
            expected_audience="secure-agent-worker-launcher",
        ),
        egress_client=WorstCaseEgressClient(),
    )
    encoded = result.model_dump_json().encode("utf-8")

    assert CALCULATED_MAX_WEB_RESULT_BYTES == 417_418
    assert len(encoded) <= CALCULATED_MAX_WEB_RESULT_BYTES
    assert len(encoded) <= MAX_OUTPUT_BYTES == 524_288


def _load_live_broker_harness(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parent.parent / "scripts"))
    return importlib.import_module("verify_broker_mtls")


class _BrokenPipeTls:
    def __init__(self, receive_error: BaseException) -> None:
        self.receive_error = receive_error
        self.receive_calls = 0

    def sendall(self, _payload: bytes) -> None:
        raise BrokenPipeError(32, "broken pipe")

    def recv(self, _limit: int) -> bytes:
        self.receive_calls += 1
        raise self.receive_error


def test_missing_certificate_broken_pipe_requires_certificate_required_tls_alert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _load_live_broker_harness(monkeypatch)
    tls = _BrokenPipeTls(
        ssl.SSLError(
            1,
            "[SSL: TLSV13_ALERT_CERTIFICATE_REQUIRED] tlsv13 alert certificate required",
        )
    )

    with pytest.raises(harness.TlsAuthenticationRejected):
        harness._send_broker_request(  # noqa: SLF001
            tls,
            b"request\n",
            corroborate_missing_certificate=True,
        )
    assert tls.receive_calls == 1


def test_bare_broken_pipe_is_not_treated_as_authentication_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _load_live_broker_harness(monkeypatch)
    tls = _BrokenPipeTls(ssl.SSLError(1, "certificate required"))

    with pytest.raises(BrokenPipeError):
        harness._send_broker_request(tls, b"request\n")  # noqa: SLF001
    assert tls.receive_calls == 0


@pytest.mark.parametrize(
    "receive_error",
    [TimeoutError("fixture unavailable"), ssl.SSLError(1, "unrelated TLS failure")],
)
def test_missing_certificate_corroboration_rejects_infrastructure_failures(
    monkeypatch: pytest.MonkeyPatch,
    receive_error: BaseException,
) -> None:
    harness = _load_live_broker_harness(monkeypatch)
    tls = _BrokenPipeTls(receive_error)

    with pytest.raises(
        harness.LiveCheckError,
        match="missing_certificate_rejection_not_corroborated",
    ):
        harness._send_broker_request(  # noqa: SLF001
            tls,
            b"request\n",
            corroborate_missing_certificate=True,
        )


def test_connector_recalculates_one_deadline_before_every_blocking_phase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    raw_timeouts: list[float] = []
    tls_timeouts: list[float] = []
    raw = _ConnectorRawSocket(events, raw_timeouts)
    tls = _ConnectorTlsSocket(events, tls_timeouts)
    response = _ConnectorHttpResponse(events)
    connector = object.__new__(PinnedTlsHttpConnector)
    connector._context = _ConnectorTlsContext(tls, events)  # type: ignore[attr-defined]
    samples = iter((0.0, 1.0, 2.0, 3.0, 4.0))
    monkeypatch.setattr(time, "monotonic", lambda: next(samples))
    monkeypatch.setattr("gateway.egress.broker.socket.socket", lambda *_args: raw)
    monkeypatch.setattr("gateway.egress.broker.http.client.HTTPResponse", lambda _sock: response)

    result = connector.request(
        canonicalize_https_url(f"{ALLOWED}/text"),
        ResolvedAddress(ip=PUBLIC_V4, family=socket.AF_INET, sockaddr=(PUBLIC_V4, 443)),
        deadline=10.0,
        max_bytes=1024,
    )

    assert result.status == 200
    assert raw_timeouts == [10.0]
    assert tls_timeouts == [9.0, 8.0, 7.0, 6.0]
    assert events[:6] == ["connect", "wrap", "handshake", "send", "response_begin", "read"]


@pytest.mark.parametrize(
    ("samples", "last_started_phase"),
    [
        ((0.0, 2.0), "wrap"),
        ((0.0, 0.1, 2.0), "handshake"),
        ((0.0, 0.1, 0.2, 2.0), "send"),
    ],
)
def test_connector_starts_no_later_phase_after_deadline(
    monkeypatch: pytest.MonkeyPatch,
    samples: tuple[float, ...],
    last_started_phase: str,
) -> None:
    events: list[str] = []
    raw = _ConnectorRawSocket(events, [])
    tls = _ConnectorTlsSocket(events, [])
    response = _ConnectorHttpResponse(events)
    connector = object.__new__(PinnedTlsHttpConnector)
    connector._context = _ConnectorTlsContext(tls, events)  # type: ignore[attr-defined]
    monotonic_samples = iter(samples)
    monkeypatch.setattr(time, "monotonic", lambda: next(monotonic_samples))
    monkeypatch.setattr("gateway.egress.broker.socket.socket", lambda *_args: raw)
    monkeypatch.setattr("gateway.egress.broker.http.client.HTTPResponse", lambda _sock: response)

    with pytest.raises(TimeoutError, match="fetch deadline exceeded"):
        connector.request(
            canonicalize_https_url(f"{ALLOWED}/text"),
            ResolvedAddress(ip=PUBLIC_V4, family=socket.AF_INET, sockaddr=(PUBLIC_V4, 443)),
            deadline=1.0,
            max_bytes=1024,
        )

    assert last_started_phase in events
    forbidden_after = {
        "wrap": {"handshake", "send", "response_begin", "read"},
        "handshake": {"send", "response_begin", "read"},
        "send": {"response_begin", "read"},
    }[last_started_phase]
    assert forbidden_after.isdisjoint(events)


def test_denied_origin_is_hashed_and_never_returned_or_logged(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret_origin = "https://private-marker.not-allowed.example"
    resolver = StaticResolver({})
    connector = ScriptedConnector([])
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver,
        connector=connector,
        origins=frozenset({ALLOWED}),
    )
    request, certificate = _request_and_certificate(
        _grant(
            grant_private,
            url=f"{secret_origin}/path",
            allowed_origins=(ALLOWED,),
        ),
        ca_private,
        ca_certificate,
    )
    caplog.set_level(logging.INFO, logger="gateway.egress.audit")

    result = broker.fetch(request, peer_certificate_pem=certificate)

    serialized = result.model_dump_json()
    assert result.error_code == "destination_not_allowed"
    assert result.decisions[-1].origin is None
    assert secret_origin not in serialized
    assert "private-marker" not in caplog.text
    assert resolver.calls == []
    assert connector.calls == []


def _load_internal_mtls_harness(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parent.parent / "scripts"))
    return importlib.import_module("verify_internal_mtls")


@pytest.mark.parametrize(
    "error",
    [
        httpx.ConnectError("connection refused"),
        httpx.ReadTimeout("read timed out"),
        httpx.ConnectError("malformed response"),
    ],
)
def test_internal_mtls_harness_rejects_generic_infrastructure_errors(
    monkeypatch: pytest.MonkeyPatch,
    error: httpx.HTTPError,
) -> None:
    harness = _load_internal_mtls_harness(monkeypatch)

    assert not harness._is_expected_tls_rejection(error)  # noqa: SLF001


@pytest.mark.parametrize(
    "detail",
    [
        "[SSL: TLSV13_ALERT_CERTIFICATE_REQUIRED] tlsv13 alert certificate required",
        "[SSL: TLSV1_ALERT_UNKNOWN_CA] tlsv1 alert unknown ca",
    ],
)
def test_internal_mtls_harness_accepts_only_certificate_tls_alerts(
    monkeypatch: pytest.MonkeyPatch,
    detail: str,
) -> None:
    harness = _load_internal_mtls_harness(monkeypatch)
    error = httpx.ConnectError(detail)

    assert harness._is_expected_tls_rejection(error)  # noqa: SLF001


@pytest.mark.parametrize("transport_error", [BrokenPipeError(), ConnectionResetError()])
def test_internal_mtls_harness_accepts_post_handshake_certificate_disconnects(
    monkeypatch: pytest.MonkeyPatch,
    transport_error: OSError,
) -> None:
    harness = _load_internal_mtls_harness(monkeypatch)
    try:
        raise transport_error
    except OSError as cause:
        try:
            raise httpx.ReadError("TLS application-data exchange failed") from cause
        except httpx.ReadError as error:
            assert harness._is_expected_tls_rejection(error)  # noqa: SLF001


def test_readme_full_validation_matches_ci_security_checks() -> None:
    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")

    for required in (
        "opa:0.70.0 check --strict /policy",
        "docker compose --profile worker-build build worker-image",
        "python scripts/verify_worker_hardening.py",
        "/scripts/verify_internal_mtls.py",
        "docker compose down -v",
    ):
        assert required in readme


@pytest.mark.parametrize(
    "credential_case",
    ["missing", "unknown_ca", "expired", "wrong_role", "wrong_invocation"],
)
def test_invalid_broker_credentials_fail_before_dns_and_egress(credential_case: str) -> None:
    resolver = StaticResolver({"allowed.example": [PUBLIC_V4]})
    connector = ScriptedConnector([])
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver, connector=connector
    )
    grant = _grant(grant_private)
    request, certificate = _request_and_certificate(grant, ca_private, ca_certificate)
    if credential_case == "missing":
        certificate = ""
    elif credential_case == "unknown_ca":
        other_private, other_ca = _ca("other-ca")
        request, certificate = _request_and_certificate(grant, other_private, other_ca)
    elif credential_case == "expired":
        certificate = _leaf(
            ca_private,
            ca_certificate,
            uri="spiffe://secure-agent-gateway/worker/invocation-1/worker-1",
            usage=ExtendedKeyUsageOID.CLIENT_AUTH,
            not_before=datetime.now(tz=UTC) - timedelta(days=2),
            not_after=datetime.now(tz=UTC) - timedelta(days=1),
        )
    elif credential_case == "wrong_role":
        certificate = _leaf(
            ca_private,
            ca_certificate,
            uri="spiffe://secure-agent-gateway/egress-broker",
            usage=ExtendedKeyUsageOID.SERVER_AUTH,
        )
    else:
        request, certificate = _request_and_certificate(
            grant,
            ca_private,
            ca_certificate,
            certificate_invocation="another-invocation",
        )

    result = broker.fetch(request, peer_certificate_pem=certificate)

    assert result.status == "denied"
    assert resolver.calls == []
    assert connector.calls == []


def test_expired_grant_and_broker_replay_fail_before_egress() -> None:
    resolver = StaticResolver({"allowed.example": [PUBLIC_V4]})
    connector = ScriptedConnector(
        [UpstreamResponse(200, {"content-type": "text/plain"}, b"once")]
    )
    broker, grant_private, ca_private, ca_certificate = _broker_fixture(
        resolver=resolver, connector=connector
    )
    request, certificate = _request_and_certificate(
        _grant(grant_private), ca_private, ca_certificate
    )
    assert broker.fetch(request, peer_certificate_pem=certificate).status == "succeeded"
    replay = broker.fetch(request, peer_certificate_pem=certificate)
    assert replay.error_code == "egress_grant_replayed"
    assert len(connector.calls) == 1

    old = datetime.now(tz=UTC) - timedelta(minutes=2)
    expired = _grant(grant_private, invocation_id="expired-invocation", now=old)
    expired_request, expired_certificate = _request_and_certificate(
        expired, ca_private, ca_certificate
    )
    denied = broker.fetch(expired_request, peer_certificate_pem=expired_certificate)
    assert denied.status == "denied"
    assert len(connector.calls) == 1


def test_real_web_tool_traverses_signed_worker_broker_contract(
    app: Any,
    client: Any,
    settings: Any,
    make_token: Any,
) -> None:
    class CapturingEgressClient:
        def __init__(self) -> None:
            self.requests: list[BrokerFetchRequest] = []

        def fetch(self, request: BrokerFetchRequest) -> BrokerFetchResult:
            self.requests.append(request)
            return BrokerFetchResult(
                status="succeeded",
                text="controlled body",
                final_url="https://example.com/path",
                content_type="text/plain",
                byte_count=15,
                decisions=(),
            )

    egress = CapturingEgressClient()
    app.state.launcher_client = InProcessLauncher(
        grant_public_key_pem=settings.execution_grant_public_key,
        issuer=settings.execution_grant_issuer,
        audience=settings.execution_grant_audience,
        egress_client=egress,
    )
    response = client.post(
        "/v1/tool-invocations",
        json={"tool": "web.fetch_text", "arguments": {"url": "HTTPS://EXAMPLE.COM./path"}},
        headers={"Authorization": f"Bearer {make_token(scopes=['web.fetch_text'])}"},
    )
    assert response.status_code == 200
    assert response.json()["result"] == {
        "url": "https://example.com/path",
        "content_type": "text/plain",
        "byte_count": 15,
        "text": "controlled body",
        "redirect_hops": 0,
        "egress_latency_ms": {"dns": 0, "broker": 0},
    }
    assert len(egress.requests) == 1
    assert egress.requests[0].grant.egress is not None
    assert egress.requests[0].grant.egress.initial_url == "https://example.com/path"


@pytest.mark.parametrize(
    "url",
    ["http://example.com/", "https://user@example.com/", "https://2130706433/"],
)
def test_web_tool_rejects_noncanonical_destinations_before_launcher(
    client: Any, make_token: Any, url: str
) -> None:
    response = client.post(
        "/v1/tool-invocations",
        json={"tool": "web.fetch_text", "arguments": {"url": url}},
        headers={"Authorization": f"Bearer {make_token(scopes=['web.fetch_text'])}"},
    )
    assert response.status_code == 422
