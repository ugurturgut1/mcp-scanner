"""Local baseline store for rug-pull detection.

The first time a server is scanned, its tool manifest is hashed and stored.
On every later scan, the current manifest is hashed again and compared --
any change (a tool added, removed, or its description/schema edited) is a
finding, since most MCP clients never re-confirm a server after first
approval.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sqlite3
from pathlib import Path

from mcp_scanner.connector import ServerManifest

DEFAULT_DB_PATH = Path.home() / ".mcp-scanner" / "baseline.db"


def _tool_hash(tool_dict: dict) -> str:
    canonical = json.dumps(tool_dict, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclasses.dataclass
class RugPullFinding:
    tool_name: str
    change: str  # "added" | "removed" | "modified"
    detail: str


class BaselineStore:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tool_baseline (
                server_name TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                tool_hash TEXT NOT NULL,
                description TEXT NOT NULL,
                input_schema TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                PRIMARY KEY (server_name, tool_name)
            )
            """
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "BaselineStore":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def compare_and_update(self, manifest: ServerManifest) -> list[RugPullFinding]:
        """Diff manifest against the stored baseline, then update the baseline
        to the current state (so the next scan diffs against *this* one).
        """
        findings: list[RugPullFinding] = []

        cur = self.conn.execute(
            "SELECT tool_name, tool_hash, description, input_schema FROM tool_baseline WHERE server_name = ?",
            (manifest.server_name,),
        )
        previous = {row[0]: {"hash": row[1], "description": row[2], "input_schema": row[3]} for row in cur.fetchall()}

        current_names = set()
        for tool in manifest.tools:
            current_names.add(tool.name)
            tool_dict = {"description": tool.description, "input_schema": tool.input_schema}
            new_hash = _tool_hash(tool_dict)

            if tool.name not in previous:
                findings.append(
                    RugPullFinding(
                        tool_name=tool.name,
                        change="added",
                        detail="New tool not present in the last approved baseline.",
                    )
                )
            elif previous[tool.name]["hash"] != new_hash:
                findings.append(
                    RugPullFinding(
                        tool_name=tool.name,
                        change="modified",
                        detail=(
                            "Description or schema changed since last scan.\n"
                            f"  was: {previous[tool.name]['description']!r}\n"
                            f"  now: {tool.description!r}"
                        ),
                    )
                )

            self.conn.execute(
                """
                INSERT INTO tool_baseline (server_name, tool_name, tool_hash, description, input_schema, first_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(server_name, tool_name) DO UPDATE SET
                    tool_hash = excluded.tool_hash,
                    description = excluded.description,
                    input_schema = excluded.input_schema
                """,
                (
                    manifest.server_name,
                    tool.name,
                    new_hash,
                    tool.description,
                    json.dumps(tool.input_schema),
                    manifest.scanned_at,
                ),
            )

        for old_name in previous:
            if old_name not in current_names:
                findings.append(
                    RugPullFinding(
                        tool_name=old_name,
                        change="removed",
                        detail="Tool present in the last baseline is now gone.",
                    )
                )
                self.conn.execute(
                    "DELETE FROM tool_baseline WHERE server_name = ? AND tool_name = ?",
                    (manifest.server_name, old_name),
                )

        self.conn.commit()
        return findings
