#!/usr/bin/env python
"""Generate a local, ephemeral RSA keypair for the Docker Compose demo.

Writes ./devkeys/private.pem and ./devkeys/public.pem. This directory is
gitignored; nothing this script produces is ever committed. Re-run it any
time to rotate the local demo key; existing tokens signed with the old key
will simply stop verifying.

This is local development tooling, not part of the gateway service itself.
"""

from __future__ import annotations

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

OUTPUT_DIR = Path(__file__).resolve().parent.parent / "devkeys"


def main() -> int:
    OUTPUT_DIR.mkdir(exist_ok=True)
    private_path = OUTPUT_DIR / "private.pem"
    public_path = OUTPUT_DIR / "public.pem"

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    print(f"Wrote {private_path}")
    print(f"Wrote {public_path}")
    print("These files are gitignored and dev-only. Do not use them beyond this local demo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
