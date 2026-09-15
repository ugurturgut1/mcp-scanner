"""Local baseline store for rug-pull detection.

The first time a server is scanned, its manifest (tools, resources, prompts)
is hashed and stored. On every later scan, the current manifest is hashed
again and compared -- any change (an item added, removed, or its
description/schema edited) is a finding, since most MCP clients never
re-confirm a server after first approval.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sqlite3
from pathlib import Path

from mcp_scanner.connector import ServerManifest

DEFAULT_DB_PATH = Path.home() / ".mcp-scanner" / "baseline.db"


def _item_hash(item_dict: dict) -> str:
    canonical = json.dumps(item_dict, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _manifest_items(manifest: ServerManifest) -> list[tuple[str, str, str, dict]]:
    """Flatten a manifest's tools/resources/prompts into
    (item_kind, item_name, description, extra) tuples, all diffed the same way.
    """
    items = []
    for tool in manifest.tools:
        items.append(("tool", tool.name, tool.description, {"input_schema": tool.input_schema}))
    for resource in manifest.resources:
        items.append(("resource", resource.name, resource.description, {"uri": resource.uri}))
    for prompt in manifest.prompts:
        items.append(("prompt", prompt.name, prompt.description, {"argument_names": prompt.argument_names}))
    return items


@dataclasses.dataclass
class RugPullFinding:
    item_name: str
    item_kind: str  # "tool" | "resource" | "prompt"
    change: str  # "added" | "removed" | "modified"
    detail: str


class BaselineStore:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS item_baseline (
                server_name TEXT NOT NULL,
                item_kind TEXT NOT NULL,
                item_name TEXT NOT NULL,
                item_hash TEXT NOT NULL,
                description TEXT NOT NULL,
                extra TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                PRIMARY KEY (server_name, item_kind, item_name)
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
            "SELECT item_kind, item_name, item_hash, description FROM item_baseline WHERE server_name = ?",
            (manifest.server_name,),
        )
        previous = {
            (row[0], row[1]): {"hash": row[2], "description": row[3]} for row in cur.fetchall()
        }

        current_keys = set()
        for item_kind, item_name, description, extra in _manifest_items(manifest):
            current_keys.add((item_kind, item_name))
            item_dict = {"description": description, **extra}
            new_hash = _item_hash(item_dict)
            key = (item_kind, item_name)

            if key not in previous:
                findings.append(
                    RugPullFinding(
                        item_name=item_name,
                        item_kind=item_kind,
                        change="added",
                        detail=f"New {item_kind} not present in the last approved baseline.",
                    )
                )
            elif previous[key]["hash"] != new_hash:
                findings.append(
                    RugPullFinding(
                        item_name=item_name,
                        item_kind=item_kind,
                        change="modified",
                        detail=(
                            "Description or schema changed since last scan.\n"
                            f"  was: {previous[key]['description']!r}\n"
                            f"  now: {description!r}"
                        ),
                    )
                )

            self.conn.execute(
                """
                INSERT INTO item_baseline (server_name, item_kind, item_name, item_hash, description, extra, first_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(server_name, item_kind, item_name) DO UPDATE SET
                    item_hash = excluded.item_hash,
                    description = excluded.description,
                    extra = excluded.extra
                """,
                (
                    manifest.server_name,
                    item_kind,
                    item_name,
                    new_hash,
                    description,
                    json.dumps(extra),
                    manifest.scanned_at,
                ),
            )

        for old_kind, old_name in previous:
            if (old_kind, old_name) not in current_keys:
                findings.append(
                    RugPullFinding(
                        item_name=old_name,
                        item_kind=old_kind,
                        change="removed",
                        detail=f"{old_kind.capitalize()} present in the last baseline is now gone.",
                    )
                )
                self.conn.execute(
                    "DELETE FROM item_baseline WHERE server_name = ? AND item_kind = ? AND item_name = ?",
                    (manifest.server_name, old_kind, old_name),
                )

        self.conn.commit()
        return findings
