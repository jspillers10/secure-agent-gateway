#!/usr/bin/env python
"""Record accepted protected-target TCP connections before protocol parsing."""

from __future__ import annotations

import socket
import ssl
from pathlib import Path

OBSERVATION_FILE = Path("/observations/protected-connections.log")


def main() -> None:
    # This dedicated listener owns the observation file. The separate HTTPS
    # control fixture can read it but cannot write or increment it.
    OBSERVATION_FILE.write_bytes(b"")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(
        "/keys/protected-fixture-cert.pem", "/keys/protected-fixture-key.pem"
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", 443))  # noqa: S104
        listener.listen(32)
        while True:
            connection, _address = listener.accept()
            with connection, OBSERVATION_FILE.open("ab", buffering=0) as observations:
                # Count immediately after accept and before reading TLS or HTTP.
                observations.write(b"accepted\n")
                try:
                    with context.wrap_socket(connection, server_side=True) as tls:
                        request = tls.recv(16_384)
                        if request.startswith(b"GET /protected HTTP/1.1\r\n"):
                            body = b"protected target reached\n"
                            tls.sendall(
                                b"HTTP/1.1 200 OK\r\n"
                                b"Content-Type: text/plain; charset=utf-8\r\n"
                                + f"Content-Length: {len(body)}\r\n".encode("ascii")
                                + b"Connection: close\r\n\r\n"
                                + body
                            )
                except (OSError, ssl.SSLError):
                    # The accepted-connection observation intentionally occurs
                    # before a client completes TLS or sends valid HTTP.
                    pass


if __name__ == "__main__":
    main()
