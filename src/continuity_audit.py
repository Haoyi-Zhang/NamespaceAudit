#!/usr/bin/env python3
"""Audit one bounded recovery-ordered namespace model from JSON.

The output is a deterministic JSON object containing the global classification
and every incompatible valid-view pair.  The command creates a new output file
and refuses to overwrite existing evidence.
"""
from __future__ import annotations

import argparse
import json
import resource
from pathlib import Path

from continuity import audit

MAX_BYTES = 1024 * 1024


def load_model(path: Path) -> dict:
    data = path.read_bytes()
    if len(data) > MAX_BYTES:
        raise ValueError("model exceeds 1 MiB input bound")
    try:
        raw = json.loads(data)
    except (UnicodeError, ValueError) as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError("model root must be an object")
    return raw


def main() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (3 * 1024**3, 3 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="omit per-view-pair details from the JSON output",
    )
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("refusing to overwrite existing output")
    try:
        result = audit(load_model(args.model), include_pairs=not args.summary_only)
    except (OSError, ValueError, KeyError, TypeError, IndexError) as exc:
        raise SystemExit(str(exc)) from exc
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"id": result["id"], "result": result["result"], "output": str(args.output)}))


if __name__ == "__main__":
    main()
