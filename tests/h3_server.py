"""Pytest fixture: in-process aioquic H3 server for integration tests.

Skipped automatically if aioquic is not installed (pytest.importorskip).
The fixture yields (host, port, knobs) where `knobs` is a dict the test can
mutate to control server behavior:

    knobs["response_status"] = 425        # default 200
    knobs["max_early_data_size"] = 16384  # default 0 (no 0-RTT)
    knobs["response_headers"] = {...}     # default {"server": "test/1.0"}
"""

import asyncio
import datetime
import socket
import ssl
import tempfile
from typing import Iterator

import pytest

aioquic = pytest.importorskip("aioquic")

from aioquic.asyncio import serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, H3_ALPN
from aioquic.h3.events import H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _generate_self_signed_cert() -> tuple[str, str]:
    """Return (cert_path, key_path) for a freshly generated self-signed cert."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tempfile.NamedTemporaryFile(suffix=".pem", delete=False).name
    key_path = tempfile.NamedTemporaryFile(suffix=".pem", delete=False).name
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    return cert_path, key_path


class _ConfigurableH3Protocol(QuicConnectionProtocol):
    """H3 server protocol that responds based on a shared knobs dict."""

    knobs: dict = {}  # set by the fixture

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3: H3Connection | None = None

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._h3 is None:
            self._h3 = H3Connection(self._quic)
        for h3_event in self._h3.handle_event(event):
            self._handle_h3_event(h3_event)

    def _handle_h3_event(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived) and event.stream_ended:
            knobs = type(self).knobs
            status = str(knobs.get("response_status", 200)).encode()
            extra = knobs.get("response_headers", {"server": "test/1.0"})
            headers = [(b":status", status)]
            for k, v in extra.items():
                headers.append((k.encode(), v.encode()))
            self._h3.send_headers(stream_id=event.stream_id, headers=headers, end_stream=True)
            self.transmit()


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def h3_server(request) -> Iterator[tuple[str, int, dict]]:
    """Spawn an in-process aioquic H3 server. Yields (host, port, knobs).

    Indirect-parametrize friendly: pass a dict with `max_early_data_size`
    (truthy = 0-RTT enabled) via @pytest.mark.parametrize("h3_server",
    [{...}], indirect=True). The integer value itself is unused — aioquic
    1.3.0 hardcodes the advertised value to MAX_EARLY_DATA (0xFFFFFFFF) on
    the server side regardless of QuicConfiguration content (see
    aioquic/quic/connection.py:1452). What matters is whether
    session_ticket_handler is wired into serve(), which is what enables
    NEW_SESSION_TICKET emission. We use the parametrize value as a boolean
    toggle for that wiring.

    The knobs dict (mutated post-yield) only controls response
    status/headers per request.
    """
    params = getattr(request, "param", {}) if hasattr(request, "param") else {}
    early_data_size = params.get("max_early_data_size", 0)
    cert_path, key_path = _generate_self_signed_cert()
    port = _free_udp_port()
    knobs: dict = {}
    _ConfigurableH3Protocol.knobs = knobs

    config = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    config.load_cert_chain(cert_path, key_path)

    loop = asyncio.new_event_loop()
    server = None

    # aioquic only emits NEW_SESSION_TICKET when serve() receives a
    # session_ticket_handler kwarg (the handler is the storage callback;
    # passing a no-op lambda is enough to enable ticket emission).
    serve_kwargs = {}
    if early_data_size > 0:
        serve_kwargs["session_ticket_handler"] = lambda ticket: None

    async def _start():
        nonlocal server
        server = await serve(
            host="127.0.0.1",
            port=port,
            configuration=config,
            create_protocol=_ConfigurableH3Protocol,
            **serve_kwargs,
        )

    loop.run_until_complete(_start())

    # Run the loop in a daemon thread so tests can drive the client synchronously.
    import threading

    def _run_loop():
        loop.run_forever()

    t = threading.Thread(target=_run_loop, daemon=True)
    t.start()

    try:
        yield ("127.0.0.1", port, knobs)
    finally:
        # aioquic.asyncio.serve() returns a single QuicServer (not iterable).
        if server is not None:
            server.close()
        loop.call_soon_threadsafe(loop.stop)
        t.join(timeout=2)
