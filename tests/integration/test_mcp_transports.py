import asyncio
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from prompt_sentry.integrations.mcp import StdioMCPUpstream, StreamableHTTPMCPUpstream

FIXTURE = Path(__file__).parents[1] / "fixtures" / "mcp_echo_server.py"


@pytest.mark.skipif(not FIXTURE.exists(), reason="MCP fixture unavailable")
def test_stdio_upstream_transport_round_trip():
    pytest.importorskip("mcp")

    async def run():
        async with StdioMCPUpstream(sys.executable, [str(FIXTURE)]) as upstream:
            tools = await upstream.list_tools()
            assert [tool.name for tool in tools.tools] == ["echo"]
            result = await upstream.call_tool("echo", {"text": "stdio-ok"})
            assert result.content[0].text == "stdio-ok"

    asyncio.run(run())


@pytest.mark.skipif(not FIXTURE.exists(), reason="MCP fixture unavailable")
def test_streamable_http_upstream_transport_round_trip():
    pytest.importorskip("mcp")
    port = _free_port()
    env = {**os.environ, "MCP_TRANSPORT": "streamable-http", "MCP_PORT": str(port)}
    process = subprocess.Popen(
        [sys.executable, str(FIXTURE)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        _wait_for_port(port, process)

        async def run():
            async with StreamableHTTPMCPUpstream(f"http://127.0.0.1:{port}/mcp") as upstream:
                tools = await upstream.list_tools()
                assert [tool.name for tool in tools.tools] == ["echo"]
                result = await upstream.call_tool("echo", {"text": "http-ok"})
                assert result.content[0].text == "http-ok"

        asyncio.run(run())
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_port(port: int, process: subprocess.Popen, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = process.stderr.read().decode() if process.stderr else ""
            raise AssertionError(f"MCP server exited early: {stderr}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError("MCP server did not start")
