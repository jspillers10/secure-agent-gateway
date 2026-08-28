"""Read one Worker request from stdin and write one signed result to stdout."""

from __future__ import annotations

import json
import sys

from pydantic import ValidationError

from gateway.worker.runtime import WorkerProtocolError, WorkerRequest, execute_worker_request

MAX_INPUT_BYTES = 64 * 1024


def main() -> int:
    raw = sys.stdin.buffer.readline(MAX_INPUT_BYTES + 1)
    # The disposable process handles exactly its first newline-delimited request
    # and exits. Do not wait for EOF: Docker's hijacked stdin stream can remain
    # half-open even after the Launcher has finished its one permitted write.
    if not raw or len(raw) > MAX_INPUT_BYTES or not raw.endswith(b"\n"):
        print("worker protocol rejected", file=sys.stderr)
        return 2
    try:
        request = WorkerRequest.model_validate(json.loads(raw))
        result = execute_worker_request(request)
    except (json.JSONDecodeError, ValidationError, WorkerProtocolError):
        print("worker protocol rejected", file=sys.stderr)
        return 2
    encoded = result.model_dump_json().encode("utf-8")
    if len(encoded) > 64 * 1024:
        print("worker output limit exceeded", file=sys.stderr)
        return 3
    sys.stdout.buffer.write(encoded + b"\n")
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
