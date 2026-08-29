#!/usr/bin/env python
"""Live Docker checks for the Milestone-1 isolation boundary.

This is an operator-side evaluation harness. It intentionally has Docker
authority; that authority is not present in Gateway or Worker containers.
"""

from __future__ import annotations

import sys
import time
from typing import Any

import docker

WORKER_IMAGE = "secure-agent-gateway-worker:milestone1"
WORKER_LABEL = "secure-agent.role=disposable-worker"
SOCKET_DESTINATION = "/var/run/docker.sock"


def main() -> int:
    client = docker.from_env()
    failures: list[str] = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        print(f"[{'PASS' if condition else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
        if not condition:
            failures.append(name)

    services: dict[str, Any] = {}
    for container in client.containers.list():
        service = container.labels.get("com.docker.compose.service")
        if service in {"gateway", "launcher", "opa"}:
            services[service] = container
    check("compose services discovered", set(services) == {"gateway", "launcher", "opa"})

    socket_holders = []
    for service, container in services.items():
        destinations = {mount["Destination"] for mount in container.attrs["Mounts"]}
        if SOCKET_DESTINATION in destinations:
            socket_holders.append(service)
    check("only Launcher has orchestration socket", set(socket_holders) == {"launcher"})

    worker_image = client.images.get(WORKER_IMAGE)
    labels = worker_image.labels
    check(
        "Worker image carries registry artifact digest",
        labels.get("org.secure-agent.artifact-digest", "").startswith("sha256:"),
    )

    common = {
        "image": worker_image.id,
        "user": "10001:10001",
        "network_disabled": True,
        "read_only": True,
        "cap_drop": ["ALL"],
        "security_opt": ["no-new-privileges:true"],
        "mem_limit": "128m",
        "nano_cpus": 500_000_000,
        "pids_limit": 64,
        "tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=16m"},  # noqa: S108
        "remove": True,
    }
    network_probe = client.containers.run(
        entrypoint=["python", "-c"],
        command=[
            "import socket;\n"
            "try: socket.create_connection(('1.1.1.1', 53), 0.5); print('reachable')\n"
            "except OSError: print('blocked')"
        ],
        **common,
    )
    check("Worker network access blocked", network_probe.strip() == b"blocked")

    client.containers.run(
        entrypoint=["python", "-c"],
        command=["from pathlib import Path; Path('/tmp/cross-run-sentinel').write_text('x')"],
        **common,
    )
    state_probe = client.containers.run(
        entrypoint=["python", "-c"],
        command=[
            "from pathlib import Path; "
            "print('present' if Path('/tmp/cross-run-sentinel').exists() else 'absent')"
        ],
        **common,
    )
    check("cross-invocation ephemeral state absent", state_probe.strip() == b"absent")

    remaining = client.containers.list(all=True, filters={"label": WORKER_LABEL})
    check("Launcher left no invocation Workers", remaining == [])

    now = int(time.time())
    events = list(
        client.events(
            since=now - 300,
            until=now,
            filters={"type": "container", "label": WORKER_LABEL},
            decode=True,
        )
    )
    created = {event["Actor"]["ID"] for event in events if event.get("Action") == "create"}
    destroyed = {event["Actor"]["ID"] for event in events if event.get("Action") == "destroy"}
    check("live invocations created fresh Workers", len(created) >= 2)
    check("every observed Worker was destroyed", created <= destroyed)

    if failures:
        print(f"\n{len(failures)} check(s) failed: {', '.join(failures)}")
        return 1
    print("\nAll live Worker hardening checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
