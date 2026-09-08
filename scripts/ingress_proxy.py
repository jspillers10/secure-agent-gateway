#!/usr/bin/env python
"""Credential-free fixed-target TCP ingress for the local Compose gateway."""

from __future__ import annotations

import selectors
import socket
import socketserver

UPSTREAM = ("gateway", 8000)
MAX_IDLE_SECONDS = 30.0


class FixedGatewayProxy(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client = self.request
        assert isinstance(client, socket.socket)
        with socket.create_connection(UPSTREAM, timeout=5.0) as upstream:
            client.setblocking(False)
            upstream.setblocking(False)
            selector = selectors.DefaultSelector()
            try:
                selector.register(client, selectors.EVENT_READ, upstream)
                selector.register(upstream, selectors.EVENT_READ, client)
                while True:
                    events = selector.select(MAX_IDLE_SECONDS)
                    if not events:
                        return
                    for key, _mask in events:
                        source = key.fileobj
                        destination = key.data
                        assert isinstance(source, socket.socket)
                        assert isinstance(destination, socket.socket)
                        data = source.recv(16_384)
                        if not data:
                            return
                        destination.sendall(data)
            finally:
                selector.close()


class ThreadedFixedGatewayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    with ThreadedFixedGatewayServer(("0.0.0.0", 8080), FixedGatewayProxy) as server:  # noqa: S104
        server.serve_forever()


if __name__ == "__main__":
    main()
