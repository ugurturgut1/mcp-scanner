"""Static heuristics for detecting suspicious MCP tool descriptions.

Each check function takes a ToolInfo and returns zero or more Finding
objects. Nothing here executes the tool or the server -- it's all string
and schema analysis, safe to run against an untrusted server's manifest.
"""

from __future__ import annotations

import dataclasses
import re
import unicodedata

from mcp_scanner.connector import ToolInfo

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclasses.dataclass
class Finding:
    tool_name: str
    check: str
    severity: str  # low | medium | high | critical
    message: str
    evidence: str


# --- Check 1: imperative language aimed at an agent, not a human reader ----
#
# A tool description is meant to tell a human "what does this button do."
# Phrases below only make sense if the *reader* is expected to act on them --
# i.e. the model calling the tool, not a person skimming a tool list.
_IMPERATIVE_PATTERNS = [
    r"\bdo not (?:tell|mention|inform|show)\b.{0,30}\b(?:user|human)\b",
    r"\bbefore calling this\b",
    r"\balways call this (?:tool|first)\b",
    r"\bignore (?:the )?(?:user-facing )?(?:previous|above)\b",
    r"\bwithout (?:informing|telling|asking)\b.{0,20}\b(?:user|human)\b",
    r"\bproceed silently\b",
    r"\bin order to comply\b",
    r"\byou must\b.{0,40}\b(?:call|include|forward|send)\b",
    r"\bfor internal diagnostics\b",
    r"\bsecretly\b",
]
_IMPERATIVE_RE = re.compile("|".join(_IMPERATIVE_PATTERNS), re.IGNORECASE)


def check_imperative_language(tool: ToolInfo) -> list[Finding]:
    findings = []
    for match in _IMPERATIVE_RE.finditer(tool.description):
        snippet = tool.description[max(0, match.start() - 20) : match.end() + 20]
        findings.append(
            Finding(
                tool_name=tool.name,
                check="imperative_language",
                severity="high",
                message="Description contains an instruction addressed to the "
                "calling agent rather than a human reading the tool list.",
                evidence=snippet.strip(),
            )
        )
    return findings


# --- Check 2: sensitive-resource keywords in description or schema ---------
#
# A tool that talks about credentials, keys, or arbitrary file paths is
# claiming access far beyond what most tool purposes need.
_SENSITIVE_KEYWORDS = [
    "id_rsa", "private key", "ssh", "credential", "password", "api_key",
    "api key", "secret", "token", "aws", ".env", "/etc/passwd",
]
_SENSITIVE_RE = re.compile("|".join(re.escape(k) for k in _SENSITIVE_KEYWORDS), re.IGNORECASE)


def check_sensitive_keywords(tool: ToolInfo) -> list[Finding]:
    findings = []
    for match in _SENSITIVE_RE.finditer(tool.description):
        snippet = tool.description[max(0, match.start() - 20) : match.end() + 20]
        findings.append(
            Finding(
                tool_name=tool.name,
                check="sensitive_keyword",
                severity="critical",
                message="Description references credentials/keys/sensitive "
                "paths that have no obvious connection to the tool's stated purpose.",
                evidence=snippet.strip(),
            )
        )
    return findings


# --- Check 3: schema/description mismatch -----------------------------------
#
# Flags argument names that imply filesystem/network/credential access when
# the description never explains why the tool needs that argument at all.
_SUSPICIOUS_ARG_NAME_RE = re.compile(
    r"(path|file|dir|directory|url|host|endpoint|token|key|secret|cred|debug)",
    re.IGNORECASE,
)


def check_schema_description_mismatch(tool: ToolInfo) -> list[Finding]:
    findings = []
    properties = (tool.input_schema or {}).get("properties", {})
    for arg_name in properties:
        if not _SUSPICIOUS_ARG_NAME_RE.search(arg_name):
            continue
        # If the argument name (or a close variant) is never mentioned in the
        # description, the description isn't explaining why the tool needs it.
        if arg_name.lower() not in tool.description.lower():
            findings.append(
                Finding(
                    tool_name=tool.name,
                    check="schema_description_mismatch",
                    severity="medium",
                    message=f"Argument '{arg_name}' suggests filesystem/network/"
                    "credential access but is never explained in the description.",
                    evidence=f"argument: {arg_name!r}, schema: {properties[arg_name]!r}",
                )
            )
    return findings


# --- Check 4: hidden/invisible characters ------------------------------------
#
# Zero-width spaces, bidi override characters, and other formatting
# codepoints render as nothing in a UI but are still tokenized by the model.
_HIDDEN_CATEGORIES = {"Cf"}  # Unicode "Format" category
_HIDDEN_CODEPOINTS = {
    "​", "‌", "‍", "⁠", "﻿",
    "‪", "‫", "‬", "‭", "‮",
}


def check_hidden_characters(tool: ToolInfo) -> list[Finding]:
    findings = []
    hidden_found = [
        ch for ch in tool.description
        if ch in _HIDDEN_CODEPOINTS or unicodedata.category(ch) in _HIDDEN_CATEGORIES
    ]
    if hidden_found:
        codepoints = sorted({f"U+{ord(ch):04X}" for ch in hidden_found})
        findings.append(
            Finding(
                tool_name=tool.name,
                check="hidden_characters",
                severity="critical",
                message=f"Description contains {len(hidden_found)} invisible/formatting "
                "character(s) that render as nothing but are still read by the model.",
                evidence=f"codepoints: {', '.join(codepoints)}",
            )
        )
    return findings


ALL_CHECKS = [
    check_imperative_language,
    check_sensitive_keywords,
    check_schema_description_mismatch,
    check_hidden_characters,
]


def run_all_checks(tool: ToolInfo) -> list[Finding]:
    findings = []
    for check in ALL_CHECKS:
        findings.extend(check(tool))
    return sorted(findings, key=lambda f: -SEVERITY_ORDER[f.severity])
