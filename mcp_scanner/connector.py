"""Connects to an MCP server over stdio and pulls its full manifest
(tools, resources, prompts) as plain dicts, ready for the rules engine.
"""

from __future__ import annotations

import dataclasses
from datetime import timezone, datetime

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.exceptions import MCPError


@dataclasses.dataclass
class ToolInfo:
    name: str
    description: str
    input_schema: dict


@dataclasses.dataclass
class ResourceInfo:
    name: str
    uri: str
    description: str

    def as_tool_info(self) -> ToolInfo:
        # Resources have no argument schema, so reuse the same description-only
        # checks (imperative language, sensitive keywords, hidden characters,
        # cross-server shadowing) tools get, by wrapping in the same shape.
        return ToolInfo(name=self.name, description=self.description, input_schema={})


@dataclasses.dataclass
class PromptInfo:
    name: str
    description: str
    argument_names: list[str]

    def as_tool_info(self) -> ToolInfo:
        # A prompt's arguments are the closest thing it has to a tool's input
        # schema -- wrap them the same shape so check_schema_description_mismatch
        # (an unexplained "token"/"path"/... argument) applies here too.
        properties = {name: {} for name in self.argument_names}
        return ToolInfo(name=self.name, description=self.description, input_schema={"properties": properties})


@dataclasses.dataclass
class ServerManifest:
    server_name: str
    command: str
    args: list[str]
    tools: list[ToolInfo]
    scanned_at: str
    resources: list[ResourceInfo] = dataclasses.field(default_factory=list)
    prompts: list[PromptInfo] = dataclasses.field(default_factory=list)


async def _list_resources(session: ClientSession) -> list[ResourceInfo]:
    try:
        result = await session.list_resources()
    except MCPError:
        return []  # not every server implements resources
    return [
        ResourceInfo(name=r.name, uri=str(r.uri), description=r.description or "")
        for r in result.resources
    ]


async def _list_prompts(session: ClientSession) -> list[PromptInfo]:
    try:
        result = await session.list_prompts()
    except MCPError:
        return []  # not every server implements prompts
    return [
        PromptInfo(
            name=p.name,
            description=p.description or "",
            argument_names=[a.name for a in (p.arguments or [])],
        )
        for p in result.prompts
    ]


async def fetch_manifest(server_name: str, command: str, args: list[str], env: dict | None = None) -> ServerManifest:
    """Launch the given stdio MCP server, enumerate its tools/resources/prompts,
    and shut it down.
    """
    params = StdioServerParameters(command=command, args=args, env=env)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_result = await session.list_tools()
            resources = await _list_resources(session)
            prompts = await _list_prompts(session)

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
        resources=resources,
        prompts=prompts,
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )
