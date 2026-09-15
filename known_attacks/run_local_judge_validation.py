"""Validates the mcp_scanner.judge prompt/approach for free, using a local
Ollama model (qwen2.5:1.5b) instead of the real Anthropic API -- so this can
run with zero cost and no API key, before ever spending anything on the real
`--llm-judge` CLI flag.

This is deliberately NOT part of the mcp_scanner package: judge.py stays
Anthropic-only (per the project's own provider story), and this script just
proves the same reasoning task/prompt works by handing judge_tool/judge_tools
a duck-typed stand-in for the Anthropic client, backed by Ollama's grammar-
constrained JSON output instead. `ollama` (the pip package) is only needed to
run this one script -- it is not a project dependency.

Runs against a small LABELED set (both malicious and benign tools) and
reports a real confusion matrix -- an earlier version of this script only
ran malicious examples and reported "3/3 flagged" as if that were accuracy,
which it isn't: a judge that flags everything would score the same on a
malicious-only set. n is tiny here (7 tools) -- this is a sanity check on
the approach, not a statistically meaningful evaluation.

Usage: python known_attacks/run_local_judge_validation.py
Requires: ollama serve running locally, and `ollama pull qwen2.5:1.5b` done.
"""

import asyncio
import dataclasses
import sys
from pathlib import Path
from types import SimpleNamespace

import ollama

from mcp_scanner.connector import fetch_manifest
from mcp_scanner.judge import judge_tools

REPO_ROOT = Path(__file__).resolve().parent.parent
DEMO_SERVERS = REPO_ROOT / "demo_servers"
KNOWN_ATTACKS = REPO_ROOT / "known_attacks"
WHATSAPP_MARKER = KNOWN_ATTACKS / ".whatsapp_takeover_triggered"
LOCAL_MODEL = "qwen2.5:1.5b"


class _OllamaJudgeClient:
    """Duck-types the one method judge_tool actually calls
    (`client.messages.parse(...) -> response.parsed_output`), backed by a
    local Ollama model instead of the Anthropic API. judge_tool/judge_tools
    themselves run completely unmodified against this.
    """

    def __init__(self, model: str = LOCAL_MODEL):
        self._ollama = ollama.AsyncClient()
        self._model = model
        self.messages = self  # client.messages.parse(...) resolves here

    async def parse(self, *, model, max_tokens, system, messages, output_format):
        del model, max_tokens  # ignored -- always uses the local model instead
        schema = output_format.model_json_schema()
        response = await self._ollama.chat(
            model=self._model,
            messages=[{"role": "system", "content": system}, *messages],
            format=schema,
        )
        parsed = output_format.model_validate_json(response.message.content)
        return SimpleNamespace(parsed_output=parsed)


@dataclasses.dataclass
class LabeledTool:
    server_name: str
    tool_name: str
    is_malicious: bool  # ground truth
    tool_info: object = None  # filled in after connecting


async def build_labeled_dataset() -> list[LabeledTool]:
    WHATSAPP_MARKER.unlink(missing_ok=True)
    dataset = [
        LabeledTool("clean-weather", "get_weather", is_malicious=False),
        LabeledTool("poisoned-weather", "get_weather", is_malicious=True),
        LabeledTool("poisoned-weather", "list_recent_cities", is_malicious=True),
        LabeledTool("direct-poisoning", "add", is_malicious=True),
        LabeledTool("shadowing", "add", is_malicious=True),
        LabeledTool("whatsapp-takeover-clean", "get_fact_of_the_day", is_malicious=False),
        LabeledTool("whatsapp-takeover-poisoned", "get_fact_of_the_day", is_malicious=True),
    ]

    clean_manifest = await fetch_manifest(
        "clean-weather", sys.executable, [str(DEMO_SERVERS / "clean_weather_server.py")]
    )
    poisoned_manifest = await fetch_manifest(
        "poisoned-weather", sys.executable, [str(DEMO_SERVERS / "poisoned_weather_server.py")]
    )
    direct_manifest = await fetch_manifest(
        "direct-poisoning", sys.executable, [str(KNOWN_ATTACKS / "direct_poisoning_server.py")]
    )
    shadowing_manifest = await fetch_manifest(
        "shadowing", sys.executable, [str(KNOWN_ATTACKS / "shadowing_server.py")]
    )
    whatsapp_script = str(KNOWN_ATTACKS / "whatsapp_takeover_server.py")
    whatsapp_clean = await fetch_manifest("whatsapp-clean", sys.executable, [whatsapp_script])
    whatsapp_poisoned = await fetch_manifest("whatsapp-poisoned", sys.executable, [whatsapp_script])
    WHATSAPP_MARKER.unlink(missing_ok=True)

    by_key = {}
    for m in (clean_manifest, poisoned_manifest, direct_manifest, shadowing_manifest):
        for tool in m.tools:
            by_key[(m.server_name, tool.name)] = tool
    by_key[("whatsapp-takeover-clean", "get_fact_of_the_day")] = whatsapp_clean.tools[0]
    by_key[("whatsapp-takeover-poisoned", "get_fact_of_the_day")] = whatsapp_poisoned.tools[0]

    for item in dataset:
        item.tool_info = by_key[(item.server_name, item.tool_name)]
    return dataset


async def main():
    dataset = await build_labeled_dataset()

    print(f"Judging {len(dataset)} labeled tools with local model {LOCAL_MODEL} (free, no API key)...\n")

    client = _OllamaJudgeClient()
    results = await asyncio.gather(*(judge_tools([item.tool_info], client) for item in dataset))

    tp = fp = tn = fn = 0
    for item, findings in zip(dataset, results):
        predicted_malicious = len(findings) > 0
        label = "MALICIOUS" if item.is_malicious else "benign"
        prediction = "flagged" if predicted_malicious else "not flagged"
        correct = predicted_malicious == item.is_malicious
        print(f"=== {item.server_name} / {item.tool_name} (ground truth: {label}) ===")
        print(f"  prediction: {prediction} -- {'correct' if correct else 'WRONG'}")
        for f in findings:
            print(f"  confidence={f.confidence:.2f} reasoning={f.reasoning}")
        print()

        if item.is_malicious and predicted_malicious:
            tp += 1
        elif item.is_malicious and not predicted_malicious:
            fn += 1
        elif not item.is_malicious and predicted_malicious:
            fp += 1
        else:
            tn += 1

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total
    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    specificity = tn / (tn + fp) if (tn + fp) else float("nan")
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else float("nan")

    print("=== Confusion matrix ===")
    print(f"  TP={tp}  FP={fp}  TN={tn}  FN={fn}  (n={total})")
    print()
    print("=== Metrics (n is tiny -- 7 examples, not statistically meaningful) ===")
    print(f"  accuracy:    {accuracy:.2f}")
    print(f"  precision:   {precision:.2f}")
    print(f"  recall:      {recall:.2f}")
    print(f"  specificity: {specificity:.2f}")
    print(f"  f1:          {f1:.2f}")


if __name__ == "__main__":
    asyncio.run(main())
