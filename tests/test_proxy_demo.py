"""The README demo must keep telling the truth: exfiltration succeeds
without the gateway and is blocked with it."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

AGENT = Path(__file__).resolve().parent.parent / "examples" / "injection-demo" / "agent.py"


def _run(*extra: str) -> str:
    proc = subprocess.run(  # noqa: S603
        [sys.executable, str(AGENT), *extra],
        capture_output=True, timeout=60, check=True,
    )
    return proc.stdout.decode()


def test_demo_unprotected_exfiltrates() -> None:
    out = _run()
    assert "run_shell" in out.splitlines()[1]
    assert "RESULT: AWS credentials sent" in out


def test_demo_protected_blocks_every_step() -> None:
    out = _run("--protected")
    assert "agent> tools offered: read_file, http_post" in out.splitlines()
    assert out.count("BLOCKED") == 3
    assert "matches deny pattern '*.env'" in out
    assert "aws_access_key_id" in out
    assert "RESULT: blocked" in out
