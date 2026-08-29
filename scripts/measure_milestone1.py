#!/usr/bin/env python
"""Measure end-to-end latency for the Milestone-1 legitimate control."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

import httpx
from smoke_test import BASE_URL, mint_token

DEVKEYS_DIR = Path(__file__).resolve().parent.parent / "devkeys"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", type=int, default=20)
    args = parser.parse_args()
    if not 2 <= args.runs <= 1000:
        parser.error("--runs must be between 2 and 1000")

    private_key = (DEVKEYS_DIR / "private.pem").read_text(encoding="utf-8")
    token = mint_token(
        private_key,
        scopes=["documents.read"],
        agent_id="agent-measurement",
    )
    samples_ms: list[float] = []
    with httpx.Client(base_url=BASE_URL, timeout=15.0) as client:
        for _index in range(args.runs):
            started = time.perf_counter()
            response = client.post(
                "/v1/tool-invocations",
                json={"tool": "documents.read", "arguments": {"document_id": "doc-001"}},
                headers={"Authorization": f"Bearer {token}"},
            )
            elapsed_ms = (time.perf_counter() - started) * 1000
            if response.status_code != 200 or response.json().get("decision") != "allow":
                raise RuntimeError("legitimate control failed during measurement")
            samples_ms.append(round(elapsed_ms, 3))

    quantiles = statistics.quantiles(samples_ms, n=100, method="inclusive")
    print(
        json.dumps(
            {
                "case": "documents.read via Gateway-OPA-Launcher-fresh-Worker",
                "runs": args.runs,
                "p50_ms": round(statistics.median(samples_ms), 3),
                "p95_ms": round(quantiles[94], 3),
                "min_ms": min(samples_ms),
                "max_ms": max(samples_ms),
                "raw_ms": samples_ms,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
