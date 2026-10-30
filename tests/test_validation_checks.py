"""Tests for restricted, non-destructive validation checks."""

from __future__ import annotations

import asyncio
import contextlib

import pytest

from riskproof.errors import AuthorizationDenied
from riskproof.validation.checks import (
    CHECK_METHODS,
    run_authorized_check,
    run_check,
)
from riskproof.validation.targets import TargetAuthorizer


@pytest.fixture()
async def local_server():
    """A real TCP server on an ephemeral localhost port that greets clients."""

    async def handle(reader, writer):
        try:
            data = await reader.read(256)
            if data.startswith(b"HEAD"):
                writer.write(b"HTTP/1.0 200 OK\r\nServer: RiskProofTest\r\n\r\n")
                await writer.drain()
        finally:
            with contextlib.suppress(OSError):
                writer.close()
                await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield "127.0.0.1", port
    server.close()
    await server.wait_closed()


async def test_tcp_connect_verified(local_server):
    host, port = local_server
    target = TargetAuthorizer(["127.0.0.1"]).authorize(host)
    result = await run_check("tcp_connect", target, port, timeout=3.0)
    assert result.status == "verified"
    assert result.observed["tcp_reachable"] is True


async def test_http_banner_captures_response_lines(local_server):
    host, port = local_server
    target = TargetAuthorizer(["127.0.0.1"]).authorize(host)
    result = await run_check("http_banner", target, port, timeout=3.0)
    assert result.status == "verified"
    assert any("200 OK" in line for line in result.observed["response_lines"])


async def test_closed_port_is_inconclusive_not_verified():
    # Ephemeral port that almost certainly has no listener.
    sock = asyncio.get_running_loop()  # noqa: F841
    server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    server.close()
    await server.wait_closed()
    target = TargetAuthorizer(["127.0.0.1"]).authorize("127.0.0.1")
    result = await run_check("tcp_connect", target, port, timeout=2.0)
    assert result.status == "inconclusive"
    # Disclaimer must be present: negative result != safe.
    assert "does NOT" in result.disclaimer


async def test_unknown_method_refused():
    target = TargetAuthorizer(["127.0.0.1"]).authorize("127.0.0.1")
    with pytest.raises(AuthorizationDenied):
        await run_check("nmap_version_scan", target, 22)


async def test_unapproved_method_refused_by_pipeline(local_server):
    host, port = local_server
    with pytest.raises(AuthorizationDenied):
        await run_authorized_check(
            method="tcp_connect",
            host=host,
            port=port,
            authorizer=TargetAuthorizer(["127.0.0.1"]),
            approved_methods=[],  # policy approves nothing
        )


async def test_pipeline_refuses_unlisted_target():
    with pytest.raises(AuthorizationDenied):
        await run_authorized_check(
            method="tcp_connect",
            host="203.0.113.10",
            port=443,
            authorizer=TargetAuthorizer(["127.0.0.1"]),
            approved_methods=list(CHECK_METHODS),
        )


def test_check_registry_is_locked_down():
    """The registry must only contain the three non-destructive methods."""
    assert set(CHECK_METHODS) == {"tcp_connect", "http_banner", "tls_cert_dates"}
