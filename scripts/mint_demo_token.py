#!/usr/bin/env python
"""Mint a delegated-identity token for manual curl testing against the
Docker Compose stack. Requires ./devkeys/private.pem (run
generate_dev_keys.py first). Prints only the token to stdout.

This is local development tooling, not part of the gateway service.
"""

from __future__ import annotations

import argparse
import sys
import time
import uuid
from pathlib import Path

import jwt

DEVKEYS_DIR = Path(__file__).resolve().parent.parent / "devkeys"
ISSUER = "https://issuer.secure-agent-gateway.local"
AUDIENCE = "secure-agent-gateway"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-id", default="agent-demo-001")
    parser.add_argument("--delegated-user-id", default="user-demo-001")
    parser.add_argument(
        "--scope",
        action="append",
        dest="scopes",
        default=None,
        help="Repeatable. Defaults to all three demo scopes.",
    )
    parser.add_argument("--expires-in", type=int, default=600)
    args = parser.parse_args()

    private_key_path = DEVKEYS_DIR / "private.pem"
    if not private_key_path.exists():
        print(
            f"error: {private_key_path} not found. Run scripts/generate_dev_keys.py first.",
            file=sys.stderr,
        )
        return 1

    private_key = private_key_path.read_text(encoding="utf-8")
    scopes = args.scopes or [
        "documents.read",
        "tickets.write",
        "admin.rotate_key",
        "web.fetch_text",
    ]
    now = int(time.time())

    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": args.agent_id,
        "agent_id": args.agent_id,
        "delegated_user": {"id": args.delegated_user_id},
        "scopes": scopes,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + args.expires_in,
    }

    token = jwt.encode(payload, private_key, algorithm="RS256")
    print(token)
    return 0


if __name__ == "__main__":
    sys.exit(main())
