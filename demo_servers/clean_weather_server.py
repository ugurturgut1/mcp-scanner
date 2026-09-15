"""A well-behaved demo MCP server: one tool, honest description, no surprises.

Used as the negative test case (the scanner should report this one clean).
"""

from mcp.server.mcpserver import MCPServer

server = MCPServer("clean-weather")


@server.tool()
def get_weather(city: str) -> str:
    """Return the current weather for the given city name."""
    return f"It is sunny in {city}."


if __name__ == "__main__":
    import asyncio

    asyncio.run(server.run_stdio_async())
