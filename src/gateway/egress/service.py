"""Mutually authenticated TLS server carried over a Unix-domain socket."""

from __future__ import annotations

import json
import logging
import os
import socket
import ssl
import threading
from contextlib import suppress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pydantic import ValidationError

from gateway.egress.broker import EgressBroker, PinnedTlsHttpConnector
from gateway.egress.config import EgressServiceSettings
from gateway.egress.protocol import BrokerFetchRequest, BrokerFetchResult

logger = logging.getLogger("gateway.egress.service")


class UnixTlsEgressServer:
    def __init__(self, settings: EgressServiceSettings) -> None:
        self._settings = settings
        self._broker = EgressBroker(
            settings.broker,
            connector=PinnedTlsHttpConnector(upstream_ca_file=settings.upstream_ca_file),
        )
        self._context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self._context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._context.verify_mode = ssl.CERT_REQUIRED
        self._context.load_cert_chain(
            certfile=settings.server_certificate_file,
            keyfile=settings.server_key_file,
        )
        self._context.load_verify_locations(cafile=settings.worker_ca_certificate_file)

    def serve_forever(self) -> None:
        path = Path(self._settings.socket_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if not path.is_socket():
                raise RuntimeError("egress socket path exists and is not a socket")
            path.unlink()
        unix_family = getattr(socket, "AF_UNIX", 1)
        listener = socket.socket(unix_family, socket.SOCK_STREAM)
        listener.bind(str(path))
        # The socket is group-connectable only by the Worker's fixed supplemental
        # group; mTLS and exact invocation binding still gate every request.
        os.chmod(path, 0o660)  # nosec B103
        listener.listen(32)
        try:
            while True:
                connection, _ = listener.accept()
                threading.Thread(
                    target=self._handle_connection,
                    args=(connection,),
                    daemon=True,
                ).start()
        finally:
            listener.close()
            path.unlink(missing_ok=True)

    def _handle_connection(self, raw: socket.socket) -> None:
        tls: ssl.SSLSocket | None = None
        try:
            raw.settimeout(self._settings.broker.max_timeout_seconds)
            tls = self._context.wrap_socket(raw, server_side=True)
            peer_der = tls.getpeercert(binary_form=True)
            if not peer_der:
                return
            peer_pem = x509.load_der_x509_certificate(peer_der).public_bytes(
                serialization.Encoding.PEM
            ).decode("utf-8")
            payload = self._readline(tls, 128 * 1024)
            request = BrokerFetchRequest.model_validate(json.loads(payload))
            result = self._broker.fetch(request, peer_certificate_pem=peer_pem)
            tls.sendall(result.model_dump_json().encode("utf-8") + b"\n")
        except (OSError, ssl.SSLError):
            self._reject_protocol(tls, reason="transport_invalid")
        except (json.JSONDecodeError, RecursionError):
            self._reject_protocol(tls, reason="json_invalid")
        except UnicodeError:
            self._reject_protocol(tls, reason="encoding_invalid")
        except ValidationError:
            self._reject_protocol(tls, reason="schema_invalid")
        except ValueError:
            self._reject_protocol(tls, reason="framing_invalid")
        finally:
            if tls is not None:
                tls.close()
            else:
                raw.close()

    @staticmethod
    def _reject_protocol(tls: ssl.SSLSocket | None, *, reason: str) -> None:
        # Only fixed codes and TLS state are safe to log. Validation exceptions
        # can contain the attacker's rejected input values.
        logger.warning(
            "egress_protocol_rejected reason=%s tls_established=%s",
            reason,
            tls is not None,
        )
        if tls is not None:
            result = BrokerFetchResult(
                status="denied",
                byte_count=0,
                error_code="broker_protocol_invalid",
                decisions=(),
            )
            with suppress(OSError):
                tls.sendall(result.model_dump_json().encode("utf-8") + b"\n")

    @staticmethod
    def _readline(sock: ssl.SSLSocket, limit: int) -> bytes:
        output = bytearray()
        while len(output) <= limit:
            chunk = sock.recv(min(16_384, limit + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if b"\n" in chunk:
                break
        if len(output) > limit or not output.endswith(b"\n") or output.count(b"\n") != 1:
            raise ValueError("invalid broker request framing")
        return bytes(output[:-1])
