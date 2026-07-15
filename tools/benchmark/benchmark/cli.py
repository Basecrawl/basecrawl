"""CLI entry for schema validate + offline rescore + engine adapters.

Usage (from repo root or tools/benchmark)::

    python -m benchmark rescore --artifacts fixtures/artifacts
    python -m benchmark validate --path fixtures/artifacts/soft-basecrawl-example.json
    python -m benchmark score --path fixtures/artifacts/soft-basecrawl-example.json
    python -m benchmark basecrawl --url https://example.com/ --path-mode soft
    python -m benchmark basecrawl --url https://example.com/ --dry-run
    python -m benchmark firecrawl --url https://example.com/ --proxy basic --dry-run
    python -m benchmark firecrawl --url https://example.com/ --proxy basic

Rescore is offline and never calls Firecrawl or Oxylabs. Live residential
basecrawl path is max 1 concurrent. Firecrawl cloud concurrency ≤ 2.
Secrets stay in mode-600 ``.env`` and are never printed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__
from .basecrawl_adapter import (
    PROFILE_HARD,
    PROFILE_SOFT,
    BasecrawlAdapter,
    BasecrawlAdapterConfig,
)
from .firecrawl_adapter import (
    PROFILE_BASIC as FC_PROFILE_BASIC,
    PROFILE_ENHANCED as FC_PROFILE_ENHANCED,
    FirecrawlAdapter,
    FirecrawlAdapterConfig,
)
from .formats import CORE_FORMATS, EXCLUDED_CORE_FORMATS, request_core_formats
from .redact import looks_like_secret_leak, redact_text
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
            "basecrawl competitive scrape benchmark — common schema + scorer + "
            "basecrawl adapter. Rescore is offline and never calls Firecrawl or Oxylabs."
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

    bc = sub.add_parser(
        "basecrawl",
        help="Run basecrawl adapter into common schema (soft/hard/residential)",
    )
    bc.add_argument("--url", required=True, help="Target URL to scrape")
    bc.add_argument(
        "--path-mode",
        choices=("soft", "hard", "residential"),
        default="soft",
        help="soft=direct/--no-js; hard=--force-browser; residential=Oxylabs max1",
    )
    bc.add_argument(
        "--profile-id",
        default=None,
        help="Matrix profile id (default: P1 soft or P3 hard/residential)",
    )
    bc.add_argument(
        "--dry-run",
        action="store_true",
        help="Hermetic dry-run: no network; soft path does not require live proxy",
    )
    bc.add_argument("--binary", default=None, help="Path to basecrawl binary")
    bc.add_argument("--timeout", type=float, default=45.0, help="Scrape timeout seconds")
    bc.add_argument(
        "--proxy",
        default=None,
        help="Optional proxy URL (prefer env/.env; never commit secrets)",
    )
    bc.add_argument(
        "--proxy-class",
        default=None,
        choices=("direct", "datacenter", "residential", "mobile"),
    )
    bc.add_argument("--proxy-session", default=None)
    bc.add_argument("--proxy-country", default=None)
    bc.add_argument("--force-browser", action="store_true")
    bc.add_argument("--out", default=None, help="Write normalized JSON to this path")
    bc.add_argument(
        "--js-target",
        action="store_true",
        help="Mark result as JS-render target for scoring dimension",
    )

    fc = sub.add_parser(
        "firecrawl",
        help=(
            "Run Firecrawl adapter into common schema "
            "(proxy basic|auto|enhanced; skip if no key)"
        ),
    )
    fc.add_argument("--url", required=True, help="Target URL to scrape")
    fc.add_argument(
        "--proxy",
        choices=("basic", "auto", "enhanced"),
        default="basic",
        help="Firecrawl --proxy mode (enhanced = non-scoring ceiling)",
    )
    fc.add_argument(
        "--profile-id",
        default=None,
        help="Matrix profile id (default: P2 basic or P4 enhanced)",
    )
    fc.add_argument(
        "--dry-run",
        action="store_true",
        help="Hermetic dry-run: no network; emits normalized artifact when key present",
    )
    fc.add_argument("--binary", default=None, help="Path to firecrawl CLI binary")
    fc.add_argument("--timeout", type=float, default=60.0, help="Scrape timeout seconds")
    fc.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Max concurrent Firecrawl scrapes for multi-URL (hard cap 2)",
    )
    fc.add_argument("--out", default=None, help="Write normalized JSON to this path")
    fc.add_argument(
        "--js-target",
        action="store_true",
        help="Mark result as JS-render target for scoring dimension",
    )
    fc.add_argument(
        "--no-stored-credentials",
        action="store_true",
        help="Ignore Firecrawl CLI stored credentials; require FIRECRAWL_API_KEY",
    )
    fc.add_argument(
        "--no-dotenv",
        action="store_true",
        help="Do not load basecrawl/.env for the key lookup",
    )
    fc.add_argument(
        "--optional-tier",
        choices=("medium", "hard"),
        default=None,
        help="Emit typed optional skip for medium/hard without dialing",
    )
    fc.add_argument(
        "--api-url",
        default=None,
        help="Optional Firecrawl API URL override (self-host label when set)",
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

    if args.command == "basecrawl":
        path_mode = args.path_mode
        profile_id = args.profile_id
        if not profile_id:
            profile_id = PROFILE_SOFT if path_mode == "soft" else PROFILE_HARD
        cfg = BasecrawlAdapterConfig(
            binary=args.binary,
            profile_id=profile_id,
            timeout_s=float(args.timeout),
            path_mode=path_mode,
            force_browser=bool(args.force_browser) or path_mode in {"hard", "residential"},
            proxy_url=args.proxy,
            proxy_class=args.proxy_class
            or ("residential" if path_mode == "residential" else None),
            proxy_session=args.proxy_session,
            proxy_country=args.proxy_country,
            dry_run=bool(args.dry_run),
            js_target=bool(args.js_target),
            no_js=(path_mode == "soft" and not args.force_browser),
        )
        adapter = BasecrawlAdapter(cfg)
        result = adapter.scrape(args.url)
        payload = result.to_dict()
        # Secret hygiene on dump
        serialized = redact_text(json.dumps(payload, indent=2, sort_keys=True))
        if looks_like_secret_leak(serialized):
            # Fail closed: do not print leaked material
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": "refusing to emit adapter payload: secret leak detected after redaction",
                        "url": args.url,
                        "error_class": "policy_skip",
                    },
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 3
        payload = json.loads(serialized)
        if args.out:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(serialized + "\n", encoding="utf-8")
        print(serialized)
        # Non-zero when credential_error and credentials were expected (residential/hard with proxy).
        if result.error_class == "credential_error" and path_mode in {"residential"}:
            return 1
        if result.error_class == "engine_unavailable":
            return 1
        return 0

    if args.command == "firecrawl":
        proxy_mode = args.proxy
        profile_id = args.profile_id
        if not profile_id:
            profile_id = (
                FC_PROFILE_ENHANCED if proxy_mode == "enhanced" else FC_PROFILE_BASIC
            )
        # Concurrency hard-capped at 2 (account limit).
        concurrency = max(1, min(int(args.concurrency or 1), 2))
        env_overlay = {}
        # Strip keys for hermetic skip proof when --no-dotenv and no ambient key desired.
        load_dotenv = not bool(args.no_dotenv)
        allow_stored = not bool(args.no_stored_credentials)
        if args.no_dotenv and "FIRECRAWL_API_KEY" in os.environ and allow_stored is False:
            # Keep ambient process key if present unless user cleared it externally.
            # Child path monpatches use --no-dotenv + env strip via process env.
            pass
        surface = "self-host" if args.api_url else "cloud"
        cfg = FirecrawlAdapterConfig(
            binary=args.binary,
            profile_id=profile_id,
            timeout_s=float(args.timeout),
            proxy_mode=proxy_mode,
            dry_run=bool(args.dry_run),
            js_target=bool(args.js_target),
            concurrency=concurrency,
            load_dotenv=load_dotenv,
            allow_stored_credentials=allow_stored,
            optional_tier=args.optional_tier,
            api_url=args.api_url,
            surface=surface,
            env=env_overlay or None,
        )
        adapter = FirecrawlAdapter(cfg)
        result = adapter.scrape(args.url)
        payload = result.to_dict()
        serialized = redact_text(json.dumps(payload, indent=2, sort_keys=True))
        if looks_like_secret_leak(serialized):
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": "refusing to emit adapter payload: secret leak detected after redaction",
                        "url": args.url,
                        "error_class": "policy_skip",
                    },
                    indent=2,
                ),
                file=sys.stderr,
            )
            return 3
        payload = json.loads(serialized)
        if args.out:
            out_path = Path(args.out)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(serialized + "\n", encoding="utf-8")
        print(serialized)
        # Fair skip without key is pipeline-friendly (exit 0).
        if result.error_class == "engine_unavailable":
            return 0
        # Credential errors when a key path was attempted → non-zero fail closed.
        if result.error_class == "credential_error":
            return 1
        if result.error_class == "budget_exhausted":
            return 1
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
