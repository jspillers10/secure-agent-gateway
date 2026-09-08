#!/usr/bin/env python
"""Deterministic HTTPS fixture for the live Milestone 2 evaluation."""

from __future__ import annotations

import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

OBSERVATION_FILE = Path("/observations/protected-connections.log")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path == "/text":
            self._send(200, b"milestone-2 controlled egress fixture\n")
        elif self.path == "/redirect":
            self._redirect("https://redirect.secure-agent.test/final")
        elif self.path == "/redirect-blocked":
            self._redirect("https://blocked.secure-agent.test/protected")
        elif self.path == "/final":
            self._send(200, b"independently allowed redirect\n")
        elif self.path == "/observed":
            try:
                protected_connections = len(OBSERVATION_FILE.read_bytes().splitlines())
            except FileNotFoundError:
                protected_connections = 0
            self._send(
                200,
                json.dumps(
                    {"protected_accepted_tcp_connections": protected_connections}
                ).encode(),
                content_type="text/plain; charset=utf-8",
            )
        else:
            self._send(404, b"not found\n")

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def _send(self, status: int, body: bytes, *, content_type: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print(format % args, flush=True)


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 443), Handler)  # noqa: S104
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain("/keys/web-fixture-cert.pem", "/keys/web-fixture-key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
