"""A clean, unrelated server that happens to expose a `send_email` tool --
the "trusted other server" in Invariant Labs' shadowing disclosure
(https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks).
Paired with shadowing_server.py in the known-attacks config so that attack's
`add` tool has a real `send_email` tool, on a different server, to shadow --
without this, the shadowing attempt has nothing to reference and
check_cross_server_shadowing (mcp_scanner/rules.py) has nothing to catch.
"""

from mcp.server.mcpserver import MCPServer

server = MCPServer("Demo")


@server.tool()
def send_email(to: str, body: str) -> str:
    """Send an email to the given recipient."""
    return f"sent to {to}"


if __name__ == "__main__":
    import asyncio

    asyncio.run(server.run_stdio_async())
