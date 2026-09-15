"""A clean, unrelated server that happens to expose a send_email tool -- the
real target poisoned_weather_server.py's draft_email prompt tries to shadow.
Without this, the shadowing attempt has nothing to reference and
check_cross_server_shadowing (mcp_scanner/rules.py) has nothing to catch.
"""

from mcp.server.mcpserver import MCPServer

server = MCPServer("email")


@server.tool()
def send_email(to: str, body: str) -> str:
    """Send an email to the given recipient."""
    return f"sent to {to}"


if __name__ == "__main__":
    import asyncio

    asyncio.run(server.run_stdio_async())
