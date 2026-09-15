"""Renders scan results (rule findings + baseline diffs) as a markdown report."""

from __future__ import annotations

from mcp_scanner.baseline import RugPullFinding
from mcp_scanner.connector import ServerManifest
from mcp_scanner.rules import Finding

_SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}


def render_server_section(
    manifest: ServerManifest,
    findings: list[Finding],
    rug_pull_findings: list[RugPullFinding],
) -> str:
    lines = [f"## {manifest.server_name}", ""]
    lines.append(f"- command: `{manifest.command} {' '.join(manifest.args)}`")
    lines.append(f"- scanned at: {manifest.scanned_at}")
    lines.append(f"- tools found: {len(manifest.tools)}")
    lines.append("")

    if not findings and not rug_pull_findings:
        lines.append("**No issues found.** ✅")
        lines.append("")
        return "\n".join(lines)

    if rug_pull_findings:
        lines.append("### Baseline changes")
        lines.append("")
        for rp in rug_pull_findings:
            lines.append(f"- **{rp.change.upper()}** `{rp.tool_name}`")
            for detail_line in rp.detail.splitlines():
                lines.append(f"  {detail_line}")
        lines.append("")

    if findings:
        lines.append("### Static findings")
        lines.append("")
        for f in findings:
            emoji = _SEVERITY_EMOJI.get(f.severity, "")
            lines.append(f"- {emoji} **[{f.severity.upper()}] {f.check}** on `{f.tool_name}`")
            lines.append(f"  {f.message}")
            lines.append(f"  > {f.evidence}")
        lines.append("")

    return "\n".join(lines)


def render_report(sections: list[str]) -> str:
    header = [
        "# MCP Scanner Report",
        "",
        "Static analysis of connected MCP servers' tool manifests: "
        "tool-poisoning language, hidden characters, schema/description "
        "mismatches, and rug-pull diffs against the last scan.",
        "",
    ]
    return "\n".join(header + sections)
