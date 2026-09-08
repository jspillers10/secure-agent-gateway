"""Destination-validating HTTPS GET broker with independent redirect checks."""

from __future__ import annotations

import http.client
import ipaddress
import multiprocessing
import socket
import ssl
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from multiprocessing.connection import Connection
from multiprocessing.process import BaseProcess
from typing import Protocol, cast

from gateway.egress.audit import EgressAuditSink, emit_egress_audit_event
from gateway.egress.protocol import (
    MAX_RESOLVED_ADDRESSES,
    BrokerFetchRequest,
    BrokerFetchResult,
    HopDecision,
)
from gateway.egress.url_policy import (
    CanonicalUrl,
    DestinationPolicyError,
    canonicalize_https_url,
    classify_forbidden_address,
)
from gateway.execution.signing import GrantVerificationError, verify_execution_grant
from gateway.hashing import sha256_hex
from gateway.registry.tools import WORKER_ARTIFACT_DIGEST
from gateway.workload.certificates import WorkloadCertificateError, verify_workload_certificate


class BrokerPolicyError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class ResolvedAddress:
    ip: str
    family: int
    sockaddr: tuple[str, int] | tuple[str, int, int, int]


@dataclass(frozen=True, slots=True)
class UpstreamResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class Resolver(Protocol):
    def __call__(
        self, host: str, port: int, *, deadline: float
    ) -> Sequence[ResolvedAddress]: ...


class Connector(Protocol):
    def request(
        self,
        url: CanonicalUrl,
        address: ResolvedAddress,
        *,
        deadline: float,
        max_bytes: int,
    ) -> UpstreamResponse: ...


def _resolve_addresses_unbounded(host: str, port: int) -> tuple[ResolvedAddress, ...]:
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise BrokerPolicyError("dns_resolution_failed") from exc
    unique: dict[tuple[int, str], ResolvedAddress] = {}
    for family, socktype, _protocol, _canonical, sockaddr in answers:
        if socktype != socket.SOCK_STREAM or family not in (socket.AF_INET, socket.AF_INET6):
            continue
        ip = str(sockaddr[0])
        typed_sockaddr = cast(tuple[str, int] | tuple[str, int, int, int], sockaddr)
        unique[(family, ip)] = ResolvedAddress(
            ip=ip, family=family, sockaddr=typed_sockaddr
        )
    if not unique:
        raise BrokerPolicyError("dns_no_usable_answers")
    # Prefer IPv4 in dual-stack environments that advertise IPv6 without a
    # usable IPv6 route. Every returned answer is still validated before this
    # selected address is connected.
    return tuple(sorted(unique.values(), key=lambda item: (item.family != socket.AF_INET, item.ip)))


ResolutionWorker = Callable[[Connection, str, int], None]


def _resolution_worker(connection: Connection, host: str, port: int) -> None:
    """Resolve in a disposable process so a stuck system resolver can be killed."""
    try:
        try:
            addresses = _resolve_addresses_unbounded(host, port)
        except BrokerPolicyError as exc:
            message: tuple[str, object] = ("error", exc.code)
        except Exception:  # noqa: BLE001 - no resolver detail crosses the process boundary
            message = ("error", "dns_resolution_failed")
        else:
            message = ("ok", addresses)
        connection.send(message)
    finally:
        connection.close()


class ProcessDnsResolver:
    """Run each system lookup in one deadline-bound, fully reaped child process."""

    def __init__(
        self,
        *,
        worker: ResolutionWorker = _resolution_worker,
    ) -> None:
        # ``spawn`` avoids forking the broker's multi-threaded TLS service.
        self._context = multiprocessing.get_context("spawn")
        self._worker = worker

    def __call__(self, host: str, port: int, *, deadline: float) -> tuple[ResolvedAddress, ...]:
        if deadline <= time.monotonic():
            raise TimeoutError("fetch deadline exceeded")
        receiver, sender = self._context.Pipe(duplex=False)
        process = self._context.Process(target=self._worker, args=(sender, host, port))
        started = False
        try:
            process.start()
            started = True
            sender.close()
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not receiver.poll(remaining):
                raise TimeoutError("fetch deadline exceeded")
            try:
                message: object = receiver.recv()
            except EOFError as exc:
                raise BrokerPolicyError("dns_resolution_failed") from exc
            return self._validate_message(message)
        finally:
            sender.close()
            receiver.close()
            if started:
                self._reap(process)
            else:
                process.close()

    @staticmethod
    def _validate_message(message: object) -> tuple[ResolvedAddress, ...]:
        if not isinstance(message, tuple) or len(message) != 2:
            raise BrokerPolicyError("dns_resolution_failed")
        kind, payload = message
        if kind == "error" and isinstance(payload, str):
            raise BrokerPolicyError(payload)
        if kind != "ok" or not isinstance(payload, tuple):
            raise BrokerPolicyError("dns_resolution_failed")
        if not payload or any(not isinstance(item, ResolvedAddress) for item in payload):
            raise BrokerPolicyError("dns_resolution_failed")
        return cast(tuple[ResolvedAddress, ...], payload)

    @staticmethod
    def _reap(process: BaseProcess) -> None:
        process.join(timeout=0.05)
        if process.is_alive():
            process.terminate()
            process.join(timeout=0.25)
        if process.is_alive():
            process.kill()
            process.join(timeout=0.25)
        if process.is_alive():
            raise BrokerPolicyError("dns_resolver_cleanup_failed")
        process.close()


def resolve_addresses(
    host: str, port: int, *, deadline: float
) -> tuple[ResolvedAddress, ...]:
    return ProcessDnsResolver()(host, port, deadline=deadline)


class PinnedTlsHttpConnector:
    """Connect to the validated IP while verifying TLS for the original hostname."""

    def __init__(self, *, upstream_ca_file: str | None = None) -> None:
        self._context = ssl.create_default_context(cafile=upstream_ca_file)
        self._context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._context.check_hostname = True
        self._context.verify_mode = ssl.CERT_REQUIRED

    def request(
        self,
        url: CanonicalUrl,
        address: ResolvedAddress,
        *,
        deadline: float,
        max_bytes: int,
    ) -> UpstreamResponse:
        remaining = self._remaining(deadline)
        raw = socket.socket(address.family, socket.SOCK_STREAM)
        tls_socket: ssl.SSLSocket | None = None
        response: http.client.HTTPResponse | None = None
        try:
            raw.settimeout(remaining)
            raw.connect(address.sockaddr)
            tls_socket = self._context.wrap_socket(
                raw,
                server_hostname=url.host,
                do_handshake_on_connect=False,
            )
            tls_socket.settimeout(self._remaining(deadline))
            tls_socket.do_handshake()
            request = self._request_bytes(url)
            tls_socket.settimeout(self._remaining(deadline))
            tls_socket.sendall(request)
            response = http.client.HTTPResponse(tls_socket)
            tls_socket.settimeout(self._remaining(deadline))
            response.begin()
            content_length = response.getheader("Content-Length")
            if content_length is not None:
                try:
                    declared = int(content_length)
                except ValueError as exc:
                    raise BrokerPolicyError("content_length_invalid") from exc
                if declared < 0 or declared > max_bytes:
                    raise BrokerPolicyError("response_too_large")
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise BrokerPolicyError("content_encoding_forbidden")
            body = bytearray()
            while True:
                tls_socket.settimeout(self._remaining(deadline))
                chunk = response.read(min(16_384, max_bytes + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise BrokerPolicyError("response_too_large")
            headers: dict[str, str] = {}
            for name, value in response.headers.raw_items():
                lowered = name.lower()
                if lowered in headers and lowered in {"location", "content-type", "content-length"}:
                    raise BrokerPolicyError("duplicate_security_header")
                headers[lowered] = value
            return UpstreamResponse(status=response.status, headers=headers, body=bytes(body))
        finally:
            if response is not None:
                response.close()
            if tls_socket is not None:
                tls_socket.close()
            else:
                raw.close()

    @staticmethod
    def _remaining(deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("fetch deadline exceeded")
        return remaining

    @staticmethod
    def _request_bytes(url: CanonicalUrl) -> bytes:
        return (
            f"GET {url.request_target} HTTP/1.1\r\n"
            f"Host: {url.host}\r\n"
            "Accept: text/plain, text/html\r\n"
            "Accept-Encoding: identity\r\n"
            "User-Agent: secure-agent-egress-broker/1.0\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")


@dataclass(frozen=True, slots=True)
class EgressBrokerSettings:
    grant_public_key_pem: str
    grant_issuer: str
    grant_audience: str
    worker_ca_certificate_pem: str
    allowed_origins: frozenset[str]
    denied_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    max_redirects: int = 3
    max_response_bytes: int = 65_536
    max_timeout_seconds: float = 5.0


class EgressBroker:
    def __init__(
        self,
        settings: EgressBrokerSettings,
        *,
        resolver: Resolver | None = None,
        connector: Connector | None = None,
        audit_sink: EgressAuditSink = emit_egress_audit_event,
    ) -> None:
        self._settings = settings
        self._resolver = resolver or ProcessDnsResolver()
        self._connector = connector or PinnedTlsHttpConnector()
        self._audit_sink = audit_sink
        self._replay_lock = threading.Lock()
        self._used_grants: set[str] = set()

    def fetch(self, request: BrokerFetchRequest, *, peer_certificate_pem: str) -> BrokerFetchResult:
        started = time.monotonic()
        decisions: list[HopDecision] = []
        try:
            self._authenticate(request, peer_certificate_pem)
        except (BrokerPolicyError, GrantVerificationError, WorkloadCertificateError) as exc:
            code = getattr(exc, "code", "broker_authentication_failed")
            self._record(
                decisions,
                request,
                hop=0,
                url=request.grant.action.destination or "",
                origin=None,
                decision="deny",
                reason=code,
                addresses=(),
                dns_ms=0.0,
                started=started,
            )
            return self._denied(code, decisions)

        grant = request.grant.egress
        if grant is None:  # guarded by the closed ExecutionGrant model and authentication
            return self._denied("egress_authority_missing", decisions)
        configured_deadline = started + grant.timeout_seconds
        remaining_grant_lifetime = (
            request.grant.expires_at - datetime.now(tz=UTC)
        ).total_seconds()
        deadline = min(
            configured_deadline,
            time.monotonic() + max(0.0, remaining_grant_lifetime),
        )
        current = grant.initial_url
        visited: set[str] = set()
        redirect_statuses = {301, 302, 303, 307, 308}

        for hop in range(grant.max_redirects + 1):
            hop_started = time.monotonic()
            dns_ms = 0.0
            addresses: Sequence[ResolvedAddress] = ()
            resolved_address_count = 0
            origin: str | None = None
            try:
                self._require_time_remaining(deadline)
                url = canonicalize_https_url(current)
                if url.value in visited:
                    raise BrokerPolicyError("redirect_loop")
                visited.add(url.value)
                if (
                    url.origin not in grant.allowed_origins
                    or url.origin not in self._settings.allowed_origins
                ):
                    raise BrokerPolicyError("destination_not_allowed")
                # A plaintext origin is audit-safe only after both independent
                # allowlists accept it. Denied attacker-controlled origins are
                # represented solely by the destination hash.
                origin = url.origin

                dns_started = time.monotonic()
                addresses = self._resolver(url.host, url.port, deadline=deadline)
                dns_ms = (time.monotonic() - dns_started) * 1000
                if not addresses:
                    raise BrokerPolicyError("dns_no_usable_answers")
                resolved_address_count = len(addresses)
                if resolved_address_count > MAX_RESOLVED_ADDRESSES:
                    # Deny the entire answer set. Do not select or silently
                    # truncate a subset that the audit schema cannot represent.
                    addresses = ()
                    raise BrokerPolicyError("dns_answer_limit_exceeded")
                for address in addresses:
                    blocked = classify_forbidden_address(address.ip)
                    if blocked is not None:
                        raise BrokerPolicyError(blocked)
                    parsed_address = ipaddress.ip_address(address.ip)
                    if (
                        isinstance(parsed_address, ipaddress.IPv6Address)
                        and parsed_address.ipv4_mapped is not None
                    ):
                        parsed_address = parsed_address.ipv4_mapped
                    if any(
                        parsed_address.version == network.version
                        and parsed_address in network
                        for network in self._settings.denied_networks
                    ):
                        raise BrokerPolicyError("address_deployment_denied")
                self._require_time_remaining(deadline)

                response = self._connector.request(
                    url,
                    addresses[0],
                    deadline=deadline,
                    max_bytes=grant.max_response_bytes,
                )
                self._require_time_remaining(deadline)
                if len(response.body) > grant.max_response_bytes:
                    raise BrokerPolicyError("response_too_large")
                if response.status in redirect_statuses:
                    location = response.headers.get("location")
                    if location is None:
                        raise BrokerPolicyError("redirect_location_missing")
                    next_url = canonicalize_https_url(location, base=url.value)
                    self._record(
                        decisions,
                        request,
                        hop=hop,
                        url=url.value,
                        origin=origin,
                        decision="allow",
                        reason="redirect",
                        addresses=addresses,
                        resolved_address_count=resolved_address_count,
                        dns_ms=dns_ms,
                        started=hop_started,
                    )
                    if hop >= grant.max_redirects:
                        raise BrokerPolicyError("redirect_limit_exceeded")
                    current = next_url.value
                    continue
                if response.status < 200 or response.status >= 300:
                    raise BrokerPolicyError("upstream_status_forbidden")
                media_type, charset = self._parse_content_type(response.headers.get("content-type"))
                if media_type not in grant.approved_content_types:
                    raise BrokerPolicyError("content_type_forbidden")
                if charset not in (None, "utf-8", "utf8"):
                    raise BrokerPolicyError("content_charset_forbidden")
                try:
                    text = response.body.decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    raise BrokerPolicyError("content_not_utf8") from exc
                self._record(
                    decisions,
                    request,
                    hop=hop,
                    url=url.value,
                    origin=origin,
                    decision="allow",
                    reason="response_accepted",
                    addresses=addresses,
                    resolved_address_count=resolved_address_count,
                    dns_ms=dns_ms,
                    started=hop_started,
                )
                return BrokerFetchResult(
                    status="succeeded",
                    text=text,
                    final_url=url.value,
                    content_type=media_type,
                    byte_count=len(response.body),
                    decisions=tuple(decisions),
                )
            except (DestinationPolicyError, BrokerPolicyError) as exc:
                code = exc.code
            except TimeoutError:
                code = "fetch_timeout"
            except ssl.SSLCertVerificationError:
                code = "tls_verification_failed"
            except ssl.SSLError:
                code = "tls_failed"
            except (OSError, http.client.HTTPException):
                code = "upstream_connection_failed"
            self._record(
                decisions,
                request,
                hop=hop,
                url=current,
                origin=origin,
                decision="deny",
                reason=code,
                addresses=addresses,
                resolved_address_count=resolved_address_count,
                dns_ms=dns_ms,
                started=hop_started,
            )
            return self._denied(code, decisions)
        return self._denied("redirect_limit_exceeded", decisions)

    @staticmethod
    def _require_time_remaining(deadline: float) -> None:
        if time.monotonic() >= deadline:
            raise BrokerPolicyError("fetch_timeout")

    def _authenticate(self, request: BrokerFetchRequest, peer_certificate_pem: str) -> None:
        action = request.grant.action
        expected_uri = (
            f"spiffe://secure-agent-gateway/worker/{action.invocation_id}/{request.worker_id}"
        )
        verify_workload_certificate(
            peer_certificate_pem,
            ca_certificate_pem=self._settings.worker_ca_certificate_pem,
            expected_uri=expected_uri,
            usage="client",
        )
        verify_execution_grant(
            request.grant,
            public_key_pem=self._settings.grant_public_key_pem,
            issuer=self._settings.grant_issuer,
            audience=self._settings.grant_audience,
            expected_tool_name="web.fetch_text",
            expected_artifact_digest=WORKER_ARTIFACT_DIGEST,
            expected_argument_digest=action.argument_digest,
            expected_approval_digest=action.approval.digest,
        )
        authority = request.grant.egress
        if authority is None or authority.operation != request.operation:
            raise BrokerPolicyError("egress_authority_missing")
        if not set(authority.allowed_origins).issubset(self._settings.allowed_origins):
            raise BrokerPolicyError("egress_policy_mismatch")
        if (
            authority.max_redirects > self._settings.max_redirects
            or authority.max_response_bytes > self._settings.max_response_bytes
            or authority.timeout_seconds > self._settings.max_timeout_seconds
        ):
            raise BrokerPolicyError("egress_limit_mismatch")
        with self._replay_lock:
            if request.grant.nonce in self._used_grants:
                raise BrokerPolicyError("egress_grant_replayed")
            self._used_grants.add(request.grant.nonce)

    @staticmethod
    def _parse_content_type(value: str | None) -> tuple[str, str | None]:
        if value is None:
            raise BrokerPolicyError("content_type_missing")
        parts = [part.strip().lower() for part in value.split(";")]
        media_type = parts[0]
        charset: str | None = None
        for parameter in parts[1:]:
            if parameter.startswith("charset="):
                if charset is not None:
                    raise BrokerPolicyError("content_type_invalid")
                charset = parameter[8:].strip('"')
            elif parameter:
                raise BrokerPolicyError("content_type_parameter_forbidden")
        return media_type, charset

    def _record(
        self,
        decisions: list[HopDecision],
        request: BrokerFetchRequest,
        *,
        hop: int,
        url: str,
        origin: str | None,
        decision: str,
        reason: str,
        addresses: Sequence[ResolvedAddress],
        resolved_address_count: int | None = None,
        dns_ms: float,
        started: float,
    ) -> None:
        event = HopDecision.model_validate(
            {
                "timestamp": datetime.now(tz=UTC),
                "invocation_id": request.grant.action.invocation_id,
                "worker_id": request.worker_id,
                "hop": hop,
                "destination_hash": sha256_hex({"url": url}),
                "origin": origin,
                "decision": decision,
                "reason": reason,
                "resolved_address_hashes": tuple(
                    sha256_hex({"address": address.ip}) for address in addresses
                ),
                "resolved_address_count": (
                    len(addresses)
                    if resolved_address_count is None
                    else resolved_address_count
                ),
                "dns_duration_ms": dns_ms,
                "broker_duration_ms": (time.monotonic() - started) * 1000,
            }
        )
        decisions.append(event)
        self._audit_sink(event)

    @staticmethod
    def _denied(code: str, decisions: Sequence[HopDecision]) -> BrokerFetchResult:
        return BrokerFetchResult(
            status="denied",
            byte_count=0,
            error_code=code,
            decisions=tuple(decisions),
        )
