"""Regression tests against real, disclosed MCP attacks (see known_attacks/README.md
for sources and the full writeup). These are "characterization tests": they encode
not just what the scanner currently catches, but what it currently *misses*, as a
measured baseline -- so that when the LLM-judge pass is added, these tests should
start failing on the documented misses, on purpose, forcing a deliberate update
rather than a silent regression either way.
"""

import json
import sys
from pathlib import Path

import pytest

from mcp_scanner.cli import scan_config

REPO_ROOT = Path(__file__).resolve().parents[2]
KNOWN_ATTACKS = REPO_ROOT / "known_attacks"
WHATSAPP_MARKER = KNOWN_ATTACKS / ".whatsapp_takeover_triggered"


@pytest.fixture
def known_attacks_config(tmp_path):
    config = {
        "mcpServers": {
            "direct-poisoning": {
                "command": sys.executable,
                "args": [str(KNOWN_ATTACKS / "direct_poisoning_server.py")],
            },
            "shadowing": {
                "command": sys.executable,
                "args": [str(KNOWN_ATTACKS / "shadowing_server.py")],
            },
            "whatsapp-takeover": {
                "command": sys.executable,
                "args": [str(KNOWN_ATTACKS / "whatsapp_takeover_server.py")],
            },
        }
    }
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))
    return config_path


@pytest.fixture(autouse=True)
def reset_whatsapp_marker():
    WHATSAPP_MARKER.unlink(missing_ok=True)
    yield
    WHATSAPP_MARKER.unlink(missing_ok=True)


async def test_direct_poisoning_caught_via_sensitive_keyword_only(known_attacks_config, tmp_path):
    report = await scan_config(known_attacks_config, tmp_path / "baseline.db")

    assert "sensitive_keyword" in report
    # Known gap (see known_attacks/README.md): "before using this tool" and the
    # wide "do not mention ... user" gap both dodge the current regex. Update
    # this assertion, on purpose, once the LLM-judge pass closes it.
    assert "imperative_language" not in report.split("## shadowing")[0]


async def test_shadowing_caught_via_imperative_language(known_attacks_config, tmp_path):
    report = await scan_config(known_attacks_config, tmp_path / "baseline.db")

    shadowing_section = report.split("## shadowing")[1].split("## whatsapp-takeover")[0]
    assert "imperative_language" in shadowing_section


async def test_whatsapp_rug_pull_caught_only_by_baseline_diff_not_static_rules(
    known_attacks_config, tmp_path
):
    db_path = tmp_path / "baseline.db"

    first = await scan_config(known_attacks_config, db_path)
    second = await scan_config(known_attacks_config, db_path)

    first_section = first.split("## whatsapp-takeover")[1]
    assert "No issues found" in first_section or "Static findings" not in first_section

    second_section = second.split("## whatsapp-takeover")[1]
    assert "MODIFIED" in second_section
    assert "+13241234123" in second_section  # the actual attacker proxy number, as evidence
    # Known gap: none of the four static checks fire on the poisoned text itself
    # (no literal "do not", no recognized urgency/coercion pattern) -- the rug-pull
    # diff is doing all the work here. Update this once that changes.
    assert "### Static findings" not in second_section
