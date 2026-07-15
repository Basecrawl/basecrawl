"""CLI entry for schema validate + offline rescore.

Usage (from repo root or tools/benchmark)::

    python -m benchmark rescore --artifacts fixtures/artifacts
    python -m benchmark validate --path fixtures/artifacts/soft-basecrawl-example.json
    python -m benchmark score --path fixtures/artifacts/soft-basecrawl-example.json

Live scrape adapters are separate features; this CLI never dials network
vendors for rescore mode.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from .formats import CORE_FORMATS, EXCLUDED_CORE_FORMATS, request_core_formats
from .rescore import digests_equal, rescore_artifacts, rescore_directory, write_scoreboard
from .schema import (
    CORE_DIMENSIONS,
    SCHEMA_VERSION,
    SECONDARY_DIMENSIONS,
    load_many,
    validate_normalized_result,
)
from .scorer import CORE_WEIGHTS, score_results


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="benchmark",
        description=(
            "basecrawl competitive scrape benchmark — common schema + scorer. "
            "Rescore is offline and never calls Firecrawl or Oxylabs."
        ),
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    v = sub.add_parser("validate", help="Validate normalized result JSON against common schema")
    v.add_argument("--path", required=True, help="JSON or JSONL file (object, list, or envelope)")
    v.add_argument(
        "--require-body",
        action="store_true",
        help="Require markdown/links payload when content_success is true",
    )

    s = sub.add_parser("score", help="Score one or more normalized result artifacts")
    s.add_argument("--path", required=True, help="Normalized artifact JSON/JSONL")
    s.add_argument(
        "--base-dir",
        default=None,
        help="Base directory for relative markdown_path / links_path refs",
    )
    s.add_argument(
        "--out",
        default=None,
        help="Optional directory to write scoreboard JSON+md (usually .docs-evidence/benchmark)",
    )
    s.add_argument("--basename", default="scoreboard", help="Scoreboard filename stem")

    r = sub.add_parser(
        "rescore",
        help="Re-score saved artifacts without re-scrape (offline, deterministic)",
    )
    r.add_argument(
        "--artifacts",
        required=True,
        help="Directory of saved normalized artifacts (or single file via --path instead)",
    )
    r.add_argument(
        "--path",
        default=None,
        help="Optional single file instead of directory scan",
    )
    r.add_argument(
        "--out",
        default=None,
        help="Write scoreboard under this dir (default: print JSON to stdout)",
    )
    r.add_argument("--basename", default="scoreboard-rescore")
    r.add_argument(
        "--include-ceiling",
        action="store_true",
        help="Include ceiling/research rows in aggregate means (default: scoring only)",
    )
    r.add_argument(
        "--check-stable",
        action="store_true",
        help="Run rescore twice and exit non-zero if digests differ",
    )

    info = sub.add_parser("info", help="Print core formats, dimensions, and weights")
    # info has no required args; keep signature simple
    _ = info

    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "info":
        payload = {
            "schema_version": SCHEMA_VERSION,
            "core_formats": sorted(CORE_FORMATS),
            "default_request_formats": request_core_formats(),
            "excluded_from_core": sorted(EXCLUDED_CORE_FORMATS),
            "core_dimensions": list(CORE_DIMENSIONS),
            "secondary_dimensions": list(SECONDARY_DIMENSIONS),
            "core_weights": dict(CORE_WEIGHTS),
            "honesty": {
                "not_undetectable": True,
                "not_unlocker_parity": True,
                "proof_secondary_only": True,
            },
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    if args.command == "validate":
        path = Path(args.path)
        results = load_many(path, strict=False)
        raw_items = _raw_items(path)
        errors_all: List[str] = []
        for i, raw in enumerate(raw_items):
            errs = validate_normalized_result(raw, require_body_payload=args.require_body)
            for e in errs:
                errors_all.append(f"[{i}] {e}")
        if errors_all:
            print(json.dumps({"ok": False, "errors": errors_all}, indent=2))
            return 1
        print(
            json.dumps(
                {
                    "ok": True,
                    "n": len(results),
                    "schema_version": SCHEMA_VERSION,
                    "paths": [str(path)],
                },
                indent=2,
            )
        )
        return 0

    if args.command == "score":
        path = Path(args.path)
        base = Path(args.base_dir) if args.base_dir else path.parent
        results = load_many(path, strict=True)
        rows = score_results(results, base_dir=base)
        board = rescore_artifacts(results, base_dir=base)
        if args.out:
            write_scoreboard(board, args.out, basename=args.basename)
            print(
                json.dumps(
                    {
                        "ok": True,
                        "n": len(rows),
                        "digest": board["digest"],
                        "out": args.out,
                    },
                    indent=2,
                )
            )
        else:
            print(json.dumps(board, indent=2, sort_keys=True))
        return 0

    if args.command == "rescore":
        if args.path:
            path = Path(args.path)
            base = path.parent
            results = load_many(path, strict=True)
            board = rescore_artifacts(
                results,
                base_dir=base,
                include_ceiling=args.include_ceiling,
            )
            board["source_files"] = [str(path)]
        else:
            board = rescore_directory(
                args.artifacts,
                include_ceiling=args.include_ceiling,
            )

        if args.check_stable:
            board2 = (
                rescore_artifacts(
                    load_many(args.path, strict=True),
                    base_dir=Path(args.path).parent,
                    include_ceiling=args.include_ceiling,
                )
                if args.path
                else rescore_directory(
                    args.artifacts,
                    include_ceiling=args.include_ceiling,
                )
            )
            if not digests_equal(board, board2):
                print(
                    json.dumps(
                        {
                            "ok": False,
                            "error": "rescore digests differ (non-deterministic)",
                            "digest_a": board.get("digest"),
                            "digest_b": board2.get("digest"),
                        },
                        indent=2,
                    ),
                    file=sys.stderr,
                )
                return 2

        if args.out:
            paths = write_scoreboard(board, args.out, basename=args.basename)
            print(
                json.dumps(
                    {
                        "ok": True,
                        "digest": board["digest"],
                        "live_network": False,
                        "json": str(paths["json"]),
                        "markdown": str(paths["markdown"]),
                        "n_rows": (board.get("aggregate") or {}).get("n_rows"),
                    },
                    indent=2,
                )
            )
        else:
            print(json.dumps(board, indent=2, sort_keys=True))
        return 0

    parser.error(f"unknown command {args.command}")
    return 2


def _raw_items(path: Path) -> List[dict]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    data = json.loads(text)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "results" in data and isinstance(data["results"], list):
            return data["results"]
        return [data]
    raise ValueError("unsupported JSON shape")


if __name__ == "__main__":
    raise SystemExit(main())
