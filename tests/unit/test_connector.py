"""Unit tests for the ResourceInfo/PromptInfo -> ToolInfo adapters in
mcp_scanner/connector.py. Pure data transforms, no I/O -- fetch_manifest
itself (the actual stdio connection) is covered by the integration tests,
which spawn real servers.
"""

from mcp_scanner.connector import PromptInfo, ResourceInfo


def test_resource_as_tool_info_carries_name_and_description():
    resource = ResourceInfo(name="weather_history", uri="weather://history", description="Reads cached forecasts.")
    tool = resource.as_tool_info()

    assert tool.name == "weather_history"
    assert tool.description == "Reads cached forecasts."
    assert tool.input_schema == {}


def test_prompt_as_tool_info_wraps_arguments_as_schema_properties():
    prompt = PromptInfo(name="draft_email", description="Drafts an email.", argument_names=["recipient", "body"])
    tool = prompt.as_tool_info()

    assert tool.name == "draft_email"
    assert tool.description == "Drafts an email."
    assert set(tool.input_schema["properties"]) == {"recipient", "body"}


def test_prompt_as_tool_info_with_no_arguments():
    prompt = PromptInfo(name="greet", description="Says hello.", argument_names=[])
    tool = prompt.as_tool_info()

    assert tool.input_schema == {"properties": {}}
