"""A well-behaved demo MCP server: one tool, one resource, one prompt, all
with honest descriptions, no surprises.

Used as the negative test case (the scanner should report this one clean).
"""

from mcp.server.mcpserver import MCPServer

server = MCPServer("clean-weather")


@server.tool()
def get_weather(city: str) -> str:
    """Return the current weather for the given city name."""
    return f"It is sunny in {city}."


@server.resource("weather://help", description="Explains how to use this server's weather tool.")
def help_text() -> str:
    return "Call get_weather with a city name to get its current weather."


@server.prompt(description="Drafts a one-line weather summary for a city.")
def summarize_weather(city: str) -> str:
    return f"Summarize the current weather in {city} in one sentence."


if __name__ == "__main__":
    import asyncio

    asyncio.run(server.run_stdio_async())
