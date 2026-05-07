"""Integration tests for corsair.h3.client against a local aioquic server.

Skipped when aioquic is not installed.
"""

import asyncio
import pytest

aioquic = pytest.importorskip("aioquic")

from corsair.h3.client import scan_h3
from tests.h3_server import h3_server  # fixture import


def test_h3_client_handshake_and_head_request(h3_server):
    host, port, knobs = h3_server
    knobs["response_status"] = 200
    knobs["response_headers"] = {"strict-transport-security": "max-age=31536000"}

    result = asyncio.run(scan_h3(
        url=f"https://{host}:{port}/",
        timeout=5.0,
        verify_tls=False,  # self-signed cert
    ))

    assert result.error is None, result.error
    assert result.status == 200
    assert "strict-transport-security" in result.headers
    assert result.headers["strict-transport-security"] == "max-age=31536000"


@pytest.mark.parametrize(
    "h3_server", [{"max_early_data_size": 16384}], indirect=True
)
def test_h3_client_captures_session_ticket_capability(h3_server):
    """Verify the client wires session_ticket_handler correctly: when the
    server enables 0-RTT, scan_h3 should observe a non-zero capability.

    Note: aioquic hardcodes the advertised max_early_data_size to 0xFFFFFFFF
    on the server side (see aioquic/quic/connection.py:1452), so the actual
    integer the client receives is the unbounded sentinel, not the value we
    requested. The auditor's H3-001 logic only checks `> 0`, so this is the
    semantically correct assertion to lock in.
    """
    host, port, _ = h3_server

    result = asyncio.run(scan_h3(
        url=f"https://{host}:{port}/",
        timeout=5.0,
        verify_tls=False,
    ))
    assert result.error is None, result.error
    assert result.early_data_capability > 0


def test_h3_client_no_session_ticket_capability_when_disabled(h3_server):
    """Sanity check the inverse: when the server does NOT enable 0-RTT,
    early_data_capability remains 0 (no false positive)."""
    host, port, _ = h3_server  # default: max_early_data_size=0

    result = asyncio.run(scan_h3(
        url=f"https://{host}:{port}/",
        timeout=5.0,
        verify_tls=False,
    ))
    assert result.error is None, result.error
    assert result.early_data_capability == 0


def test_h3_client_handles_425_too_early(h3_server):
    host, port, knobs = h3_server
    knobs["response_status"] = 425

    result = asyncio.run(scan_h3(
        url=f"https://{host}:{port}/",
        timeout=5.0,
        verify_tls=False,
    ))
    assert result.status == 425
