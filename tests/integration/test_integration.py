"""Integration test for the full scan pipeline (cli.scan_config): spawns the
two real demo servers as subprocesses and speaks actual MCP over stdio, end
to end -- unlike the unit tests, this exercises connector.py, cli.py, and
report.py too, not just rules.py/baseline.py in isolation.
"""

import json
import sys
from pathlib import Path

import pytest

from mcp_scanner.cli import scan_config

# Anchor on this file's own location, not on whatever directory pytest
# happened to be launched from -- __file__ is always correct, cwd isn't.
REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_SERVERS = REPO_ROOT / "demo_servers"


@pytest.fixture
def demo_config(tmp_path):
    """Build the mcpServers config the test needs, in-memory, with absolute
    paths -- rather than reusing configs/demo_config.json, which bakes in
    relative paths meant for manual runs from the repo root.
    """
    config = {
        "mcpServers": {
            "clean-weather": {
                "command": sys.executable,
                "args": [str(DEMO_SERVERS / "clean_weather_server.py")],
            },
            "poisoned-weather": {
                "command": sys.executable,
                "args": [str(DEMO_SERVERS / "poisoned_weather_server.py")],
            },
            # A real send_email tool on a different server, so
            # poisoned-weather's draft_email prompt has an actual
            # cross-server target to shadow.
            "email": {
                "command": sys.executable,
                "args": [str(DEMO_SERVERS / "email_server.py")],
            },
        }
    }
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))
    return config_path


async def test_scan_flags_poisoned_server_and_clears_clean_one(demo_config, tmp_path):
    report = await scan_config(demo_config, tmp_path / "baseline.db")

    assert "clean-weather" in report
    assert "poisoned-weather" in report

    # every issue planted in poisoned_weather_server.py should surface here,
    # across its tool, its resource, and its prompt
    assert "imperative_language" in report
    assert "sensitive_keyword" in report
    assert "hidden_characters" in report
    assert "cross_server_shadowing" in report
    assert "resources found: 1" in report
    assert "prompts found: 1" in report


async def test_second_identical_scan_reports_no_new_baseline_changes(demo_config, tmp_path):
    db_path = tmp_path / "baseline.db"

    await scan_config(demo_config, db_path)  # first scan: baseline is empty, everything is "ADDED"
    report = await scan_config(demo_config, db_path)  # second scan: nothing should have changed

    assert "ADDED" not in report
    assert "MODIFIED" not in report
