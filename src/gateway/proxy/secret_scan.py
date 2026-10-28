"""Credential detection for tool-call arguments.

The proxy scans every string inside a call's arguments (keys and values)
before forwarding it. A match is the signature of a model being steered
into exfiltrating a credential it saw earlier in the session, so the
default policy action is deny.

Only the detector name is ever reported. The matched text is never
returned, logged, or written to the audit trail.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

# Patterns are deliberately specific: a false positive blocks a legitimate
# call, so generic "high entropy string" heuristics are out of scope here.
DETECTORS: dict[str, re.Pattern[str]] = {
    "aws_access_key_id": re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"),
    "aws_secret_access_key": re.compile(
        r"(?i)aws_?secret_?access_?key\s*[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+]{40}"
    ),
    "private_key": re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
    "github_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
    "gitlab_token": re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"),
    "slack_token": re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    "anthropic_api_key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    "openai_api_key": re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}"),
    "stripe_secret_key": re.compile(r"\b[rs]k_live_[0-9A-Za-z]{24,}"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
}


def iter_strings(value: Any) -> Iterator[str]:
    """Yield every string leaf (and every object key) inside a JSON value."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from iter_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from iter_strings(item)


def find_secrets(value: Any) -> list[str]:
    """Return the sorted names of every detector that matches inside `value`."""
    found: set[str] = set()
    for text in iter_strings(value):
        for name, pattern in DETECTORS.items():
            if name not in found and pattern.search(text):
                found.add(name)
    return sorted(found)


def redact(value: Any, *, max_len: int = 200) -> Any:
    """Copy a JSON value with secrets masked and long strings truncated.

    Used only for the human-facing approval preview shown by `sag pending`,
    never for the audit trail (which records hashes only).
    """
    if isinstance(value, str):
        for name, pattern in DETECTORS.items():
            value = pattern.sub(f"[REDACTED:{name}]", value)
        if len(value) > max_len:
            value = value[:max_len] + f"...[{len(value) - max_len} more chars]"
        return value
    if isinstance(value, dict):
        return {str(k): redact(v, max_len=max_len) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, max_len=max_len) for v in value]
    return value
