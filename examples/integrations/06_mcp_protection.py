"""Owned FastMCP protection and an optional stdio-to-stdio upstream gateway."""

import asyncio
import os

from mcp.server.fastmcp import FastMCP

from prompt_sentry import AsyncPromptSentryClient, PromptSentryClient, SecurityContext
from prompt_sentry.integrations.mcp import (
    PromptSentryMCPGateway,
    ProtectedFastMCP,
    StdioMCPUpstream,
    create_gateway_server,
)


def owned_server() -> FastMCP:
    raw_server = FastMCP("Protected tools", json_response=True)
    server = ProtectedFastMCP(
        raw_server,
        PromptSentryClient(),
        SecurityContext(allowed_tools=("lookup",)),
    )

    @server.tool()
    def lookup(query: str) -> str:
        """Look up demonstration data."""
        return f"Result for {query}"

    return raw_server


async def gateway() -> None:
    from mcp.server.lowlevel import NotificationOptions
    from mcp.server.models import InitializationOptions
    from mcp.server.stdio import stdio_server

    command = os.environ["MCP_UPSTREAM_COMMAND"]
    args = os.getenv("MCP_UPSTREAM_ARGS", "").split()
    async with StdioMCPUpstream(command, args) as upstream, AsyncPromptSentryClient() as sentry:
        policy = PromptSentryMCPGateway(upstream, sentry, SecurityContext())
        server = create_gateway_server(policy)
        async with stdio_server() as (read, write):
            await server.run(
                read,
                write,
                InitializationOptions(
                    server_name="promptsentry-gateway",
                    server_version="0.1.0",
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )


if __name__ == "__main__":
    if os.getenv("MCP_UPSTREAM_COMMAND"):
        asyncio.run(gateway())
    else:
        owned_server().run(transport="streamable-http")
