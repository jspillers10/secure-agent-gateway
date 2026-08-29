#!/usr/bin/env python
"""Live negative and control checks for internal development mTLS."""

from __future__ import annotations

import ssl
import sys

import httpx

CA_FILE = "/keys/internal-server-ca-cert.pem"
TARGETS = ("https://opa:8181/health", "https://launcher:8443/healthz")


def _context(*, cert: str | None = None, key: str | None = None) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=CA_FILE)
    if cert is not None and key is not None:
        context.load_cert_chain(certfile=cert, keyfile=key)
    return context


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
            rejected = False
            try:
                with httpx.Client(verify=context, timeout=5.0) as client:
                    response = client.get(target)
                rejected = response.status_code in {401, 403}
            except httpx.HTTPError:
                rejected = True
            check(f"{label} credential rejected by {target}", rejected)

    if failures:
        print(f"\n{len(failures)} check(s) failed: {', '.join(failures)}")
        return 1
    print("\nAll internal mTLS checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
