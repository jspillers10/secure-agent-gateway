#!/usr/bin/env python
"""Live negative and control checks for internal development mTLS."""

from __future__ import annotations

import ssl
import sys

import httpx

CA_FILE = "/keys/internal-server-ca-cert.pem"
TARGETS = ("https://opa:8181/health", "https://launcher:8443/healthz")
EXPECTED_TLS_REJECTION_MARKERS = (
    "certificate required",
    "certificate_required",
    "unknown ca",
    "unknown_ca",
    "bad certificate",
    "bad_certificate",
    "unsupported certificate",
    "unsupported_certificate",
    "certificate unknown",
    "certificate_unknown",
)


def _context(*, cert: str | None = None, key: str | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=CA_FILE)
    if cert is not None and key is not None:
        context.load_cert_chain(certfile=cert, keyfile=key)
    return context


def _is_expected_tls_rejection(exc: httpx.HTTPError) -> bool:
    """Recognize explicit TLS alerts and TLS 1.3 post-handshake disconnects.

    Some OpenSSL combinations complete ``wrap_socket`` before processing the
    server's client-certificate rejection, then expose that rejection as a
    broken pipe or connection reset on the first application-data exchange.
    The caller has already established the fixed target with a successful
    positive control, so these two low-level signals are acceptable here;
    DNS failures, refused connections, timeouts, and generic HTTP errors are not.
    """
    seen: set[int] = set()
    current: BaseException | None = exc
    messages: list[str] = []
    post_handshake_rejection = False
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        messages.append(str(current).lower())
        post_handshake_rejection = post_handshake_rejection or isinstance(
            current, (BrokenPipeError, ConnectionResetError)
        )
        current = current.__cause__ or current.__context__
    detail = " ".join(messages)
    return post_handshake_rejection or any(
        marker in detail for marker in EXPECTED_TLS_REJECTION_MARKERS
    )


def main() -> int:
    failures: list[str] = []

    def check(name: str, condition: bool) -> None:
        print(f"[{'PASS' if condition else 'FAIL'}] {name}")
        if not condition:
            failures.append(name)

    valid = _context(
        cert="/keys/gateway-client-cert.pem", key="/keys/gateway-client-key.pem"
    )
    missing = _context()
    wrong_role = _context(cert="/keys/launcher-cert.pem", key="/keys/launcher-key.pem")

    for target in TARGETS:
        with httpx.Client(verify=valid, timeout=5.0) as client:
            response = client.get(target)
        check(f"valid Gateway credential accepted by {target}", response.status_code == 200)

        for label, context in (("missing", missing), ("wrong-role", wrong_role)):
            try:
                with httpx.Client(verify=context, timeout=5.0) as client:
                    client.get(target)
            except httpx.HTTPError as exc:
                rejected = _is_expected_tls_rejection(exc)
            else:
                rejected = False
            check(f"{label} credential rejected by {target}", rejected)

    if failures:
        print(f"\n{len(failures)} check(s) failed: {', '.join(failures)}")
        return 1
    print("\nAll internal mTLS checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
