"""Deterministic canonicalization and hashing for security-bound values.

The execution protocol commits to validated arguments, actions, grants, and
results using the same JSON representation everywhere.  JSON is UTF-8 encoded,
object keys are sorted, insignificant whitespace is removed, and non-JSON
objects are rejected rather than stringified implicitly.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256_hex(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()
