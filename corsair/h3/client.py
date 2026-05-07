"""aioquic-backed HTTP/3 scanner.

This module's import succeeds only when the [h3] extra is installed.
Public surface:
    H3ScanResult — frozen dataclass with status, headers, error, etc.
    scan_h3(url, timeout, user_agent, verify_tls) — async coroutine.
"""

import asyncio
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

# The aioquic imports below raise ImportError when [h3] extra is absent.
# corsair/h3/__init__.py catches that to set H3_AVAILABLE=False.
from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection, H3_ALPN
from aioquic.h3.events import H3Event, HeadersReceived, DataReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent


@dataclass(frozen=True)
class H3ScanResult:
    url: str
    status: Optional[int] = None
    headers: dict = field(default_factory=dict)
    quic_version: Optional[int] = None
    early_data_capability: int = 0
    error: Optional[str] = None
    duration_ms: float = 0.0


class _CorsairH3Protocol(QuicConnectionProtocol):
    """Captures HEAD response headers. Session-ticket capture is owned by
    a QuicConfiguration.session_ticket_handler callback installed in
    scan_h3() — aioquic invokes the *config*-level handler when a NEW_
    SESSION_TICKET arrives, not a method on the protocol subclass."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._h3: Optional[H3Connection] = None
        self._response_headers: dict = {}
        self._response_status: Optional[int] = None
        self._done = asyncio.Event()

    def quic_event_received(self, event: QuicEvent) -> None:
        if self._h3 is None:
            self._h3 = H3Connection(self._quic)
        for h3_event in self._h3.handle_event(event):
            self._handle_h3_event(h3_event)

    def _handle_h3_event(self, event: H3Event) -> None:
        if isinstance(event, HeadersReceived):
            for name, value in event.headers:
                key = name.decode().lower()
                val = value.decode(errors="replace")
                if key == ":status":
                    self._response_status = int(val)
                else:
                    self._response_headers[key] = val
            if event.stream_ended:
                self._done.set()
        elif isinstance(event, DataReceived):
            if event.stream_ended:
                self._done.set()

    async def head_request(
        self, parsed, user_agent: str, timeout: float
    ) -> tuple[Optional[int], dict]:
        stream_id = self._quic.get_next_available_stream_id()
        self._h3.send_headers(
            stream_id=stream_id,
            headers=[
                (b":method", b"HEAD"),
                (b":scheme", b"https"),
                (b":authority", parsed.netloc.encode()),
                (b":path", (parsed.path or "/").encode()),
                (b"user-agent", user_agent.encode()),
                # RFC 8470 hint: ask the origin to act as if this came via 0-RTT.
                (b"early-data", b"1"),
            ],
            end_stream=True,
        )
        self.transmit()
        try:
            await asyncio.wait_for(self._done.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass
        return self._response_status, self._response_headers


async def scan_h3(
    url: str,
    timeout: float = 10.0,
    user_agent: str = "Corsair/0.6.0 (HTTP Security Scanner)",
    verify_tls: bool = True,
) -> H3ScanResult:
    """Connect to (host, port) over QUIC + H3, send HEAD with Early-Data: 1,
    return H3ScanResult. Never raises; errors are returned in result.error.
    """
    started = time.time()
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or 443

    if host is None:
        return H3ScanResult(url=url, error="invalid url: no host")

    # Mutable holder for session-ticket capability — populated by the
    # session_ticket_handler kwarg passed to connect() (aioquic invokes it
    # when NEW_SESSION_TICKET arrives from the server).
    capability = [0]

    def _on_session_ticket(ticket) -> None:
        capability[0] = getattr(ticket, "max_early_data_size", 0) or 0

    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    if not verify_tls:
        config.verify_mode = ssl.CERT_NONE

    try:
        async with connect(
            host=host,
            port=port,
            configuration=config,
            create_protocol=_CorsairH3Protocol,
            session_ticket_handler=_on_session_ticket,
            wait_connected=True,
        ) as protocol:
            try:
                await asyncio.wait_for(
                    protocol.head_request(parsed, user_agent, timeout=timeout),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                return H3ScanResult(
                    url=url,
                    error=f"timeout after {timeout}s",
                    duration_ms=(time.time() - started) * 1000,
                )

            # NEW_SESSION_TICKET typically arrives shortly AFTER the first
            # response on a one-shot request — closing the connection right
            # after the HEAD response can race past the ticket. Poll briefly
            # so the config's session_ticket_handler can populate `capability`
            # before we return. Bounded at ~500ms, exits early when seen.
            for _ in range(10):
                if capability[0] > 0:
                    break
                await asyncio.sleep(0.05)

            return H3ScanResult(
                url=url,
                status=protocol._response_status,
                headers=dict(protocol._response_headers),
                quic_version=getattr(protocol._quic, "version", None),
                early_data_capability=capability[0],
                error=None,
                duration_ms=(time.time() - started) * 1000,
            )
    except asyncio.TimeoutError:
        return H3ScanResult(
            url=url,
            error=f"timeout after {timeout}s",
            duration_ms=(time.time() - started) * 1000,
        )
    except (ConnectionRefusedError, OSError) as e:
        return H3ScanResult(
            url=url,
            error=f"connection refused: {e}",
            duration_ms=(time.time() - started) * 1000,
        )
    except ssl.SSLError as e:
        return H3ScanResult(
            url=url,
            error=f"tls: {e}",
            duration_ms=(time.time() - started) * 1000,
        )
    except Exception as e:
        return H3ScanResult(
            url=url,
            error=f"unexpected: {type(e).__name__}: {e}",
            duration_ms=(time.time() - started) * 1000,
        )
