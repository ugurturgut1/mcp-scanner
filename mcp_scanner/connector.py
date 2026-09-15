"""Connects to an MCP server over stdio and pulls its full manifest
(tools, resources, prompts) as plain dicts, ready for the rules engine.
"""

from __future__ import annotations

import dataclasses
from datetime import timezone, datetime

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


@dataclasses.dataclass
class ToolInfo:
    name: str
    description: str
    input_schema: dict


@dataclasses.dataclass
class ServerManifest:
    server_name: str
    command: str
    args: list[str]
    tools: list[ToolInfo]
    scanned_at: str


async def fetch_manifest(server_name: str, command: str, args: list[str], env: dict | None = None) -> ServerManifest:
    """Launch the given stdio MCP server, enumerate its tools, and shut it down.

    Resources/prompts enumeration is left for a later pass -- tools are the
    highest-value target since they're what the model actually calls.
    """
    params = StdioServerParameters(command=command, args=args, env=env)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_result = await session.list_tools()

    tools = [
        ToolInfo(
            name=t.name,
            description=t.description or "",
            input_schema=t.input_schema or {},
        )
        for t in tools_result.tools
    ]

    return ServerManifest(
        server_name=server_name,
        command=command,
        args=args,
        tools=tools,
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )
