"""Shared fixtures.

The reference gateway fixtures need FastAPI and the rest of the [gateway]
extra. A proxy-only install (`pip install -e ".[dev]"`) skips loading them
so the proxy suites still run, which is how CI proves the light install works.
"""

from __future__ import annotations

import importlib.util

if importlib.util.find_spec("fastapi") is not None:
    from tests.helpers.gateway_fixtures import *  # noqa: F403
