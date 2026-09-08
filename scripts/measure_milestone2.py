#!/usr/bin/env python
"""Measure live DNS, broker, and total controlled-fetch latency."""

from __future__ import annotations

import json
import statistics
import time
from pathlib import Path

import httpx
from verify_milestone2 import BASE_URL, DEVKEYS_DIR, mint_token

SAMPLES = 20


def percentile(values: list[float], percentile_value: float) -> float:
    ordered = sorted(values)
    rank = max(0, min(len(ordered) - 1, int(round((len(ordered) - 1) * percentile_value))))
    return ordered[rank]


def summary(values: list[float]) -> dict[str, float]:
    return {
        "p50_ms": round(statistics.median(values), 3),
        "p95_ms": round(percentile(values, 0.95), 3),
        "min_ms": round(min(values), 3),
        "max_ms": round(max(values), 3),
    }


def main() -> int:
    private_key = (Path(DEVKEYS_DIR) / "private.pem").read_text(encoding="utf-8")
    token = mint_token(private_key)
    headers = {"Authorization": f"Bearer {token}"}
    dns_samples: list[float] = []
    broker_samples: list[float] = []
    total_samples: list[float] = []
    with httpx.Client(base_url=BASE_URL, timeout=15.0) as client:
        for _index in range(SAMPLES):
            started = time.perf_counter()
            response = client.post(
                "/v1/tool-invocations",
                json={
                    "tool": "web.fetch_text",
                    "arguments": {"url": "https://fixture.secure-agent.test/text"},
                },
                headers=headers,
            )
            total_samples.append((time.perf_counter() - started) * 1000)
            response.raise_for_status()
            latency = response.json()["result"]["egress_latency_ms"]
            dns_samples.append(float(latency["dns"]))
            broker_samples.append(float(latency["broker"]))
    report = {
        "case": "web.fetch_text via Gateway-OPA-Launcher-Worker-UDS-mTLS-broker-HTTPS",
        "samples": SAMPLES,
        "dns": summary(dns_samples),
        "broker": summary(broker_samples),
        "total_fetch": summary(total_samples),
        "raw_ms": {
            "dns": dns_samples,
            "broker": broker_samples,
            "total_fetch": total_samples,
        },
    }
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
