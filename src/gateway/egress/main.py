"""Egress broker process entry point."""

from __future__ import annotations

import logging

from gateway.egress.config import load_egress_settings
from gateway.egress.service import UnixTlsEgressServer


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    UnixTlsEgressServer(load_egress_settings()).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
