"""Canonical HTTPS URL parsing and connect-time address classification."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import SplitResult, urljoin, urlsplit, urlunsplit


class DestinationPolicyError(ValueError):
    """A destination cannot be represented by the broker's closed policy."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


_CONTROL_OR_SPACE = re.compile(r"[\x00-\x20\x7f]")
_BAD_PERCENT = re.compile(r"%(?![0-9A-Fa-f]{2})")
_PERCENT = re.compile(r"%([0-9A-Fa-f]{2})")
_ALTERNATE_NUMERIC = re.compile(
    r"^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class CanonicalUrl:
    value: str
    scheme: str
    host: str
    port: int
    origin: str
    request_target: str


def _normalize_percent(value: str) -> str:
    if _BAD_PERCENT.search(value):
        raise DestinationPolicyError("url_percent_encoding_invalid")
    return _PERCENT.sub(lambda match: f"%{match.group(1).upper()}", value)


def _canonical_host(parsed: SplitResult) -> str:
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise DestinationPolicyError("url_userinfo_forbidden")
    try:
        raw_host = parsed.hostname
    except ValueError as exc:
        raise DestinationPolicyError("url_host_invalid") from exc
    if raw_host is None or not raw_host:
        raise DestinationPolicyError("url_host_missing")
    if "%" in raw_host:
        raise DestinationPolicyError("url_ipv6_zone_forbidden")
    raw_host = raw_host.rstrip(".")
    if not raw_host:
        raise DestinationPolicyError("url_host_invalid")
    try:
        host = raw_host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise DestinationPolicyError("url_idna_invalid") from exc
    if len(host) > 253 or any(not label or len(label) > 63 for label in host.split(".")):
        raise DestinationPolicyError("url_host_invalid")
    if _ALTERNATE_NUMERIC.fullmatch(host):
        raise DestinationPolicyError("url_numeric_host_forbidden")
    return host


def canonicalize_https_url(value: str, *, base: str | None = None) -> CanonicalUrl:
    """Return one unambiguous HTTPS representation or reject the URL."""
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise DestinationPolicyError("url_length_invalid")
    if _CONTROL_OR_SPACE.search(value) or "\\" in value:
        raise DestinationPolicyError("url_characters_forbidden")
    candidate = urljoin(base, value) if base is not None else value
    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise DestinationPolicyError("url_parse_failed") from exc
    scheme = parsed.scheme.lower()
    if scheme != "https":
        raise DestinationPolicyError("url_scheme_forbidden")
    if parsed.fragment:
        raise DestinationPolicyError("url_fragment_forbidden")
    host = _canonical_host(parsed)
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise DestinationPolicyError("url_port_invalid") from exc
    if port != 443:
        raise DestinationPolicyError("url_port_forbidden")

    # Raw non-ASCII request-target characters have no single HTTP/1.1 wire
    # representation. Require the caller to supply their UTF-8 percent-encoded
    # form so validation and the bytes sent upstream cannot diverge.
    try:
        parsed.path.encode("ascii")
        parsed.query.encode("ascii")
    except UnicodeEncodeError as exc:
        raise DestinationPolicyError("url_request_target_non_ascii") from exc

    # Brackets are required only for a canonical IPv6 literal. IP literals are
    # later denied by policy, but parsing them correctly prevents ambiguity.
    try:
        parsed_ip = ipaddress.ip_address(host)
    except ValueError:
        netloc = host
    else:
        netloc = f"[{parsed_ip.compressed}]" if parsed_ip.version == 6 else parsed_ip.compressed
        host = parsed_ip.compressed
    path = _normalize_percent(parsed.path or "/")
    query = _normalize_percent(parsed.query)
    request_target = path + (f"?{query}" if query else "")
    canonical = urlunsplit((scheme, netloc, path, query, ""))
    return CanonicalUrl(
        value=canonical,
        scheme=scheme,
        host=host,
        port=port,
        origin=f"https://{netloc}",
        request_target=request_target,
    )


def classify_forbidden_address(value: str) -> str | None:
    """Classify an IP that must never receive a broker connection."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise DestinationPolicyError("dns_answer_invalid") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    metadata = {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
    if address in metadata:
        return "address_metadata"
    checks = (
        (address.is_loopback, "address_loopback"),
        (address.is_private, "address_private"),
        (address.is_link_local, "address_link_local"),
        (address.is_multicast, "address_multicast"),
        (address.is_unspecified, "address_unspecified"),
        (address.is_reserved, "address_reserved"),
    )
    for blocked, reason in checks:
        if blocked:
            return reason
    if not address.is_global:
        return "address_not_global"
    return None
