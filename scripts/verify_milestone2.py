#!/usr/bin/env python
"""Exercise the real Gateway -> Worker -> Unix-mTLS broker -> HTTPS path."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx
import jwt

DEVKEYS_DIR = Path(__file__).resolve().parent.parent / "devkeys"
BASE_URL = "http://localhost:8088"
ISSUER = "https://issuer.secure-agent-gateway.local"
AUDIENCE = "secure-agent-gateway"


def docker_cli() -> str:
    executable = shutil.which("docker")
    if executable is None:
        raise RuntimeError("Docker CLI is unavailable")
    return executable


def mint_token(private_key: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "agent-milestone2",
            "agent_id": "agent-milestone2",
            "delegated_user": {"id": "user-milestone2"},
            "scopes": ["web.fetch_text"],
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + 300,
        },
        private_key,
        algorithm="RS256",
    )


def main() -> int:
    private_key = (DEVKEYS_DIR / "private.pem").read_text(encoding="utf-8")
    token = mint_token(private_key)
    headers = {"Authorization": f"Bearer {token}"}
    failures: list[str] = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        print(f"[{'PASS' if condition else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))
        if not condition:
            failures.append(name)

    def invoke(client: httpx.Client, url: str) -> httpx.Response:
        return client.post(
            "/v1/tool-invocations",
            json={"tool": "web.fetch_text", "arguments": {"url": url}},
            headers=headers,
        )

    def observed_connections(client: httpx.Client) -> int:
        response = invoke(client, "https://fixture.secure-agent.test/observed")
        if response.status_code != 200:
            raise RuntimeError("protected connection observation failed")
        text = response.json().get("result", {}).get("text", "{}")
        value = json.loads(text).get("protected_accepted_tcp_connections")
        if not isinstance(value, int):
            raise RuntimeError("protected connection observation was invalid")
        return value

    def broker_denied_cidr_events() -> int:
        completed = subprocess.run(  # noqa: S603 - resolved CLI and fixed arguments
            [docker_cli(), "compose", "logs", "--no-color", "egress-broker"],
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.count('"reason":"address_deployment_denied"')

    with httpx.Client(base_url=BASE_URL, timeout=15.0) as client:
        direct = invoke(client, "https://fixture.secure-agent.test/text")
        check(
            "allowed HTTPS GET traverses the real broker",
            direct.status_code == 200
            and direct.json().get("result", {}).get("text")
            == "milestone-2 controlled egress fixture\n",
            direct.text,
        )

        redirect = invoke(client, "https://fixture.secure-agent.test/redirect")
        check(
            "independently allowed redirect succeeds",
            redirect.status_code == 200
            and redirect.json().get("result", {}).get("redirect_hops") == 1
            and redirect.json().get("result", {}).get("text")
            == "independently allowed redirect\n",
            redirect.text,
        )

        baseline = observed_connections(client)
        subprocess.run(  # noqa: S603 - resolved CLI and fixed arguments
            [
                docker_cli(),
                "compose",
                "exec",
                "-T",
                "egress-broker",
                "python",
                "-c",
                (
                    "import socket; "
                    "s=socket.create_connection(('blocked.secure-agent.test',443),2); "
                    "s.close()"
                ),
            ],
            check=True,
        )
        after_positive_control = observed_connections(client)
        check(
            "raw TCP positive control increments the protected listener",
            after_positive_control == baseline + 1,
            f"before={baseline} after={after_positive_control}",
        )

        blocked = invoke(client, "https://fixture.secure-agent.test/redirect-blocked")
        check(
            "redirect to an origin absent from the signed allowlist is denied",
            blocked.status_code == 502,
            blocked.text,
        )

        after_blocked_redirect = observed_connections(client)
        check(
            "blocked redirect caused zero additional accepted TCP connections",
            after_blocked_redirect == after_positive_control,
            f"before={after_positive_control} after={after_blocked_redirect}",
        )

        cidr_events_before = broker_denied_cidr_events()
        rebinding = invoke(client, "https://rebinding.secure-agent.test/protected")
        check(
            "allowlisted route-local destination is denied by deployment CIDR policy",
            rebinding.status_code == 502,
            rebinding.text,
        )
        cidr_events_after = broker_denied_cidr_events()
        check(
            "route-local denial occurred after DNS and before connector activity",
            cidr_events_after == cidr_events_before + 1,
            f"before={cidr_events_before} after={cidr_events_after}",
        )
        after_route_local = observed_connections(client)
        check(
            "route-local CIDR denial caused zero accepted TCP connections",
            after_route_local == after_blocked_redirect,
            f"before={after_blocked_redirect} after={after_route_local}",
        )

        numeric = invoke(client, "https://2130706433/")
        check("alternate numeric host rejected before execution", numeric.status_code == 422)

    if failures:
        print(f"\n{len(failures)} Milestone 2 check(s) failed: {', '.join(failures)}")
        return 1
    print("\nAll live Milestone 2 checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
