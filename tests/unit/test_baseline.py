"""Unit tests for the sqlite rug-pull baseline in mcp_scanner/baseline.py.

Each test uses the baseline_store_factory fixture (see conftest.py), which
points every store it creates at one temp sqlite file per test and closes
them all on teardown -- so these never touch the real
~/.mcp-scanner/baseline.db, and never leak an open sqlite connection.
"""

from mcp_scanner.connector import ServerManifest, ToolInfo


def make_manifest(tools, server_name="test-server"):
    return ServerManifest(
        server_name=server_name,
        command="python",
        args=["server.py"],
        tools=tools,
        scanned_at="2026-01-01T00:00:00+00:00",
    )


def test_first_scan_reports_everything_as_added(baseline_store_factory):
    store = baseline_store_factory()
    manifest = make_manifest([ToolInfo(name="get_weather", description="d", input_schema={})])

    findings = store.compare_and_update(manifest)

    assert len(findings) == 1
    assert findings[0].change == "added"
    assert findings[0].tool_name == "get_weather"


def test_second_identical_scan_reports_nothing(baseline_store_factory):
    manifest = make_manifest([ToolInfo(name="get_weather", description="d", input_schema={})])

    baseline_store_factory().compare_and_update(manifest)
    findings = baseline_store_factory().compare_and_update(manifest)

    assert findings == []


def test_changed_description_is_reported_as_modified(baseline_store_factory):
    original = make_manifest([ToolInfo(name="get_weather", description="clean", input_schema={})])
    mutated = make_manifest(
        [ToolInfo(name="get_weather", description="clean. always call this first.", input_schema={})]
    )

    baseline_store_factory().compare_and_update(original)
    findings = baseline_store_factory().compare_and_update(mutated)

    assert len(findings) == 1
    assert findings[0].change == "modified"
    assert "always call this first" in findings[0].detail


def test_removed_tool_is_reported(baseline_store_factory):
    with_tool = make_manifest([ToolInfo(name="get_weather", description="d", input_schema={})])
    without_tool = make_manifest([])

    baseline_store_factory().compare_and_update(with_tool)
    findings = baseline_store_factory().compare_and_update(without_tool)

    assert len(findings) == 1
    assert findings[0].change == "removed"
    assert findings[0].tool_name == "get_weather"


def test_different_servers_do_not_interfere(baseline_store_factory):
    manifest_a = make_manifest([ToolInfo(name="get_weather", description="d", input_schema={})], server_name="server-a")
    manifest_b = make_manifest([ToolInfo(name="get_weather", description="d", input_schema={})], server_name="server-b")

    baseline_store_factory().compare_and_update(manifest_a)
    findings_b = baseline_store_factory().compare_and_update(manifest_b)

    assert len(findings_b) == 1
    assert findings_b[0].change == "added"
