"""CLI entrypoint: `python -m mcp_scanner.cli scan <config.json>`

Config format matches the `mcpServers` block used by Claude Desktop / Claude
Code, e.g.:

{
  "mcpServers": {
    "my-server": {
      "command": "python",
      "args": ["server.py"],
      "env": {}
    }
  }
}
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from mcp_scanner.baseline import BaselineStore
from mcp_scanner.connector import fetch_manifest
from mcp_scanner.report import render_report, render_server_section
from mcp_scanner.rules import run_all_checks


async def scan_config(config_path: Path, db_path: Path | None) -> str:
    config = json.loads(config_path.read_text())
    servers = config.get("mcpServers", {})
    if not servers:
        print(f"No 'mcpServers' entries found in {config_path}", file=sys.stderr)
        sys.exit(1)

    sections = []

    with (BaselineStore(db_path) if db_path else BaselineStore()) as store:
        for name, spec in servers.items():
            command = spec["command"]
            args = spec.get("args", [])
            env = spec.get("env")

            print(f"Scanning '{name}'...", file=sys.stderr)
            try:
                manifest = await fetch_manifest(name, command, args, env)
            except Exception as exc:  # noqa: BLE001 -- surface any connection failure in the report
                sections.append(f"## {name}\n\n**Failed to connect:** `{exc}`\n")
                continue

            findings = []
            for tool in manifest.tools:
                findings.extend(run_all_checks(tool))

            rug_pull_findings = store.compare_and_update(manifest)

            sections.append(render_server_section(manifest, findings, rug_pull_findings))

    return render_report(sections)


def main():
    parser = argparse.ArgumentParser(prog="mcp-scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan servers listed in an mcpServers config file")
    scan_parser.add_argument("config", type=Path, help="Path to a JSON file with an mcpServers block")
    scan_parser.add_argument("--db", type=Path, default=None, help="Path to the baseline sqlite db (default: ~/.mcp-scanner/baseline.db)")
    scan_parser.add_argument("--out", type=Path, default=None, help="Write the markdown report here instead of stdout")

    args = parser.parse_args()

    if args.command == "scan":
        report = asyncio.run(scan_config(args.config, args.db))
        if args.out:
            args.out.write_text(report)
            print(f"Report written to {args.out}", file=sys.stderr)
        else:
            print(report)


if __name__ == "__main__":
    main()
