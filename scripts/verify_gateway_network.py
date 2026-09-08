#!/usr/bin/env python
"""Verify host ingress and Gateway network confinement in the live stack."""

from __future__ import annotations

import json
import sys
from typing import Any

import docker
import httpx

BASE_URL = "http://127.0.0.1:8088"

CONTAINER_PROBE = r"""
import json
import socket
import ssl
import httpx

def connects(host, port):
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except OSError:
        return False

def resolves(host):
    try:
        socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        return True
    except OSError:
        return False

context = ssl.create_default_context(cafile='/keys/internal-server-ca-cert.pem')
context.load_cert_chain('/keys/gateway-client-cert.pem', '/keys/gateway-client-key.pem')
with httpx.Client(verify=context, timeout=3.0) as client:
    opa = client.get('https://opa:8181/health').status_code
    launcher = client.get('https://launcher:8443/healthz').status_code

print(json.dumps({
    'opa': opa,
    'launcher': launcher,
    'public_ip': connects('1.1.1.1', 443),
    'external_dns': resolves('example.com'),
    'external_name_connection': connects('example.com', 443),
    'host_gateway': connects('host.docker.internal', 8088),
    'allowed_fixture_name': connects('fixture.secure-agent.test', 443),
    'protected_fixture_name': connects('blocked.secure-agent.test', 443),
    'allowed_fixture_ip': connects('11.77.0.10', 443),
    'protected_fixture_ip': connects('11.78.0.11', 443),
}))
"""


def _service_containers(client: Any) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for container in client.containers.list():
        service = container.labels.get("com.docker.compose.service")
        if service in {"gateway", "ingress", "web-fixture"}:
            result[service] = container
    return result


def _protected_count(web_fixture: Any) -> int:
    result = web_fixture.exec_run(
        [
            "python",
            "-c",
            (
                "from pathlib import Path; p=Path('/observations/protected-connections.log'); "
                "print(p.read_text(encoding='ascii').count('accepted') if p.exists() else 0)"
            ),
        ]
    )
    if result.exit_code != 0:
        raise RuntimeError("could not read protected connection observations")
    return int(result.output.decode("ascii").strip())


def main() -> int:
    client = docker.from_env()
    failures: list[str] = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        print(f"[{'PASS' if condition else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
        if not condition:
            failures.append(name)

    services = _service_containers(client)
    check("Gateway, ingress, and observation fixture discovered", len(services) == 3)
    if len(services) != 3:
        return 1
    gateway = services["gateway"]
    ingress = services["ingress"]
    web_fixture = services["web-fixture"]

    with httpx.Client(base_url=BASE_URL, timeout=5.0) as host_client:
        health = host_client.get("/healthz")
    check("host reaches Gateway through credential-free ingress", health.status_code == 200)

    gateway_networks = set(gateway.attrs["NetworkSettings"]["Networks"])
    check(
        "Gateway attaches only control and ingress networks",
        len(gateway_networks) == 2
        and any(name.endswith("_internal_net") for name in gateway_networks)
        and any(name.endswith("_ingress_net") for name in gateway_networks),
        detail=",".join(sorted(gateway_networks)),
    )
    check(
        "Gateway has no edge, fixture, or protected network",
        all(
            not name.endswith(("_edge_net", "_fixture_net", "_protected_net"))
            for name in gateway_networks
        ),
    )
    ingress_mounts = {mount["Destination"] for mount in ingress.attrs["Mounts"]}
    check(
        "ingress receives no credentials or Docker socket",
        not any(
            path == "/var/run/docker.sock" or path == "/keys" or path.startswith("/keys/")
            for path in ingress_mounts
        ),
    )
    ingress_networks = set(ingress.attrs["NetworkSettings"]["Networks"])
    check(
        "ingress reaches only the Gateway-side segment among private networks",
        len(ingress_networks) == 2
        and any(name.endswith("_ingress_net") for name in ingress_networks)
        and any(name.endswith("_edge_net") for name in ingress_networks),
    )

    baseline = _protected_count(web_fixture)
    probe = gateway.exec_run(["python", "-c", CONTAINER_PROBE])
    check("Gateway confinement probe executed", probe.exit_code == 0)
    if probe.exit_code != 0:
        print(probe.output.decode("utf-8", errors="replace"))
        return 1
    observed = json.loads(probe.output.decode("utf-8"))
    check("Gateway reaches OPA over authenticated control plane", observed["opa"] == 200)
    check("Gateway reaches Launcher over authenticated control plane", observed["launcher"] == 200)
    check("Gateway public-IP connection fails", not observed["public_ip"])
    check("Gateway external DNS resolution fails", not observed["external_dns"])
    check("Gateway external-name connection fails", not observed["external_name_connection"])
    check("Gateway host-gateway connection fails", not observed["host_gateway"])
    check(
        "Gateway cannot resolve or connect to either fixture network",
        not any(
            observed[name]
            for name in (
                "allowed_fixture_name",
                "protected_fixture_name",
                "allowed_fixture_ip",
                "protected_fixture_ip",
            )
        ),
    )
    after = _protected_count(web_fixture)
    check(
        "Gateway probes caused zero protected accepted connections",
        after == baseline,
        detail=f"before={baseline} after={after}",
    )

    if failures:
        print(f"\n{len(failures)} Gateway-network check(s) failed: {', '.join(failures)}")
        return 1
    print("\nAll Gateway-network confinement checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
