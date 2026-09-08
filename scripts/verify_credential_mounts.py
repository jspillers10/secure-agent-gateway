#!/usr/bin/env python
"""Verify least-privilege credential distribution in the live Compose stack."""

from __future__ import annotations

import json
import sys
from typing import Any

import docker

EXPECTED: dict[str, set[str]] = {
    "opa": {
        "/keys/opa-cert.pem",
        "/keys/opa-key.pem",
        "/keys/gateway-client-ca-cert.pem",
    },
    "launcher": {
        "/keys/launcher-cert.pem",
        "/keys/launcher-key.pem",
        "/keys/gateway-client-ca-cert.pem",
        "/keys/execution-grant-public.pem",
        "/keys/internal-server-ca-cert.pem",
        "/keys/worker-client-ca-cert.pem",
        "/keys/worker-client-ca-private.pem",
    },
    "gateway": {
        "/keys/public.pem",
        "/keys/internal-server-ca-cert.pem",
        "/keys/gateway-client-cert.pem",
        "/keys/gateway-client-key.pem",
        "/keys/execution-grant-private.pem",
        "/keys/execution-grant-public.pem",
    },
    "egress-broker": {
        "/keys/egress-broker-cert.pem",
        "/keys/egress-broker-key.pem",
        "/keys/worker-client-ca-cert.pem",
        "/keys/execution-grant-public.pem",
        "/keys/internal-server-ca-cert.pem",
    },
    "web-fixture": {
        "/keys/web-fixture-cert.pem",
        "/keys/web-fixture-key.pem",
    },
    "protected-fixture": {
        "/keys/protected-fixture-cert.pem",
        "/keys/protected-fixture-key.pem",
    },
    "ingress": set(),
}

FORBIDDEN: dict[str, set[str]] = {
    "opa": {
        "/keys/gateway-client-key.pem",
        "/keys/launcher-key.pem",
        "/keys/egress-broker-key.pem",
        "/keys/web-fixture-key.pem",
        "/keys/protected-fixture-key.pem",
        "/keys/gateway-client-ca-private.pem",
        "/keys/worker-client-ca-private.pem",
        "/keys/internal-server-ca-private.pem",
    },
    "launcher": {"/keys/execution-grant-private.pem"},
    "gateway": {"/keys/worker-client-ca-private.pem", "/keys/web-fixture-key.pem"},
    "egress-broker": {
        "/keys/execution-grant-private.pem",
        "/keys/gateway-client-ca-private.pem",
        "/keys/worker-client-ca-private.pem",
        "/keys/internal-server-ca-private.pem",
    },
    "web-fixture": {
        "/keys/execution-grant-private.pem",
        "/keys/worker-client-ca-private.pem",
    },
    "protected-fixture": {
        "/keys/execution-grant-private.pem",
        "/keys/worker-client-ca-private.pem",
    },
    "ingress": {"/keys/execution-grant-private.pem", "/keys/gateway-client-key.pem"},
}


def _python_probe(container: Any, required: set[str], forbidden: set[str]) -> bool:
    code = (
        "import json; from pathlib import Path; "
        f"required={json.dumps(sorted(required))}; forbidden={json.dumps(sorted(forbidden))}; "
        "print(json.dumps({'readable': [p for p in required if Path(p).is_file() and "
        "Path(p).read_bytes()], 'foreign_present': [p for p in forbidden if Path(p).exists()]}))"
    )
    result = container.exec_run(["python", "-c", code])
    if result.exit_code != 0:
        return False
    observed = json.loads(result.output.decode("utf-8"))
    return set(observed["readable"]) == required and observed["foreign_present"] == []


def main() -> int:
    client = docker.from_env()
    failures: list[str] = []

    def check(name: str, condition: bool) -> None:
        print(f"[{'PASS' if condition else 'FAIL'}] {name}")
        if not condition:
            failures.append(name)

    services: dict[str, Any] = {}
    for container in client.containers.list():
        service = container.labels.get("com.docker.compose.service")
        if service in EXPECTED:
            services[service] = container
    check("all credential-bound services discovered", set(services) == set(EXPECTED))

    for service, required in EXPECTED.items():
        container = services.get(service)
        if container is None:
            continue
        key_mounts = {
            mount["Destination"]: mount
            for mount in container.attrs["Mounts"]
            if mount["Destination"] == "/keys" or mount["Destination"].startswith("/keys/")
        }
        check(f"{service} has no broad key-directory mount", "/keys" not in key_mounts)
        check(f"{service} receives exactly its required key paths", set(key_mounts) == required)
        check(
            f"{service} credential mounts are read-only",
            all(not mount["RW"] for mount in key_mounts.values()),
        )
        if service == "opa":
            health = container.attrs.get("State", {}).get("Health", {}).get("Status")
            check("OPA loaded its mounted TLS credentials", health == "healthy")
        else:
            check(
                f"{service} reads required credentials and cannot see foreign keys",
                _python_probe(container, required, FORBIDDEN[service]),
            )

    if failures:
        print(f"\n{len(failures)} credential-mount check(s) failed: {', '.join(failures)}")
        return 1
    print("\nAll credential-mount checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
