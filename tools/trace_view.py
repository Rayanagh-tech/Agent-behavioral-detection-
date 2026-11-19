"""Affiche en arbre les traces exportées (logs/spans/*.jsonl), tous services confondus.

Usage : python tools/trace_view.py [DOSSIER_SPANS] [--trace TRACE_ID] [--last N]
"""
import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def load(directory):
    spans = []
    for path in sorted(Path(directory).glob("spans-*.jsonl")):
        with path.open(encoding="utf-8") as handle:
            spans.extend(json.loads(line) for line in handle if line.strip())
    return spans


def render(spans, trace_id):
    items = [s for s in spans if s["trace_id"] == trace_id]
    ids = {s["span_id"] for s in items}
    children = defaultdict(list)
    for s in sorted(items, key=lambda s: s["start_ns"]):
        children[s["parent_span_id"] if s["parent_span_id"] in ids else None].append(s)
    lines = [f"trace {trace_id}  ({len(items)} spans, services : {', '.join(sorted({s['service'] for s in items}))})"]

    def walk(parent, depth):
        for s in children[parent]:
            marks = {k: s["attributes"][k] for k in ("secres.decision", "agent.id", "event.type") if k in s["attributes"]}
            flag = " ERREUR" if s["status"] == "ERROR" else ""
            lines.append(f"{'  ' * (depth + 1)}- {s['name']} [{s['service']}] {s['duration_ms']} ms{flag} {marks or ''}")
            walk(s["span_id"], depth + 1)

    walk(None, 0)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", nargs="?", default="logs/spans")
    parser.add_argument("--trace")
    parser.add_argument("--last", type=int, default=3)
    args = parser.parse_args()
    spans = load(args.directory)
    if not spans:
        sys.exit(f"Aucun span dans {args.directory}")
    order = list(dict.fromkeys(s["trace_id"] for s in sorted(spans, key=lambda s: s["start_ns"])))
    for trace_id in ([args.trace] if args.trace else order[-args.last:]):
        print(render(spans, trace_id) + "\n")


if __name__ == "__main__":
    main()
