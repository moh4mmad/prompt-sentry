import os

from mcp.server.fastmcp import FastMCP

server = FastMCP(
    "echo-upstream",
    host="127.0.0.1",
    port=int(os.getenv("MCP_PORT", "8000")),
    json_response=True,
)


@server.tool()
def echo(text: str) -> str:
    """Echo the supplied text."""
    return text


if __name__ == "__main__":
    server.run(transport=os.getenv("MCP_TRANSPORT", "stdio"))
