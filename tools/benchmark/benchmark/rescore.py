"""Offline re-score pipeline over saved normalized artifacts (VAL-BENCH-030/031).

Never dials Firecrawl or Oxylabs. Produces stable scores within float tolerance
for unchanged inputs.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Union

from .schema import NormalizedResult, load_many
from .scorer import (
    FLOAT_TOLERANCE,
    AggregateScores,
    ScoredRow,
    aggregate_scores,
    score_results,
)

PathLike = Union[str, Path]


def rescore_artifacts(
    results: Sequence[NormalizedResult],
    *,
    base_dir: Optional[Path] = None,
    include_ceiling: bool = False,
) -> Dict[str, Any]:
    """Score in-memory normalized results; return a serializable scoreboard object."""
    rows = score_results(results, base_dir=base_dir)
    agg = aggregate_scores(rows, include_ceiling=include_ceiling)
    payload = {
        "mode": "rescore",
        "live_network": False,
        "n_inputs": len(results),
        "rows": [r.to_dict() for r in rows],
        "aggregate": agg.to_dict(),
        "honesty": {
            "model": "cryptographically-anchored trust-but-audit",
            "not_undetectable": True,
            "not_unlocker_parity": True,
            "enhanced_is_ceiling": True,
            "hard_optional_typed_skip": True,
            "core_formats": ["markdown", "html|rawHtml", "links"],
            "excluded_from_core": ["extract", "json-llm", "interact", "agent"],
            "proof_is_secondary_basecrawl_only": True,
            "secrets": "never commit; mode-600 gitignored .env only",
        },
        "float_tolerance": FLOAT_TOLERANCE,
    }
    payload["digest"] = scoreboard_digest(payload)
    return payload


def rescore_directory(
    artifact_dir: PathLike,
    *,
    pattern: str = "*.json",
    include_jsonl: bool = True,
    include_ceiling: bool = False,
) -> Dict[str, Any]:
    """Load saved normalized artifacts from a directory and re-score offline."""
    root = Path(artifact_dir)
    if not root.exists():
        raise FileNotFoundError(f"artifact directory not found: {root}")

    files: List[Path] = sorted(root.glob(pattern))
    if include_jsonl:
        files.extend(sorted(root.glob("*.jsonl")))
    # Prefer nested artifacts/ if present and root only has subdirs.
    if not files and (root / "artifacts").is_dir():
        return rescore_directory(
            root / "artifacts",
            pattern=pattern,
            include_jsonl=include_jsonl,
            include_ceiling=include_ceiling,
        )

    results: List[NormalizedResult] = []
    loaded_files: List[str] = []
    for path in files:
        # Skip scoreboard outputs if mixed in.
        name = path.name.lower()
        if "scoreboard" in name:
            continue
        try:
            batch = load_many(path, strict=True)
        except (ValueError, json.JSONDecodeError):
            # Allow a wrapper envelope without results.
            continue
        results.extend(batch)
        loaded_files.append(str(path))

    board = rescore_artifacts(
        results,
        base_dir=root,
        include_ceiling=include_ceiling,
    )
    board["artifact_dir"] = str(root)
    board["source_files"] = loaded_files
    return board


def write_scoreboard(
    board: MappingLike,
    output_dir: PathLike,
    *,
    basename: str = "scoreboard-rescore",
) -> Dict[str, Path]:
    """Write JSON + markdown under *output_dir* (typically gitignored evidence)."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / f"{basename}.json"
    md_path = out / f"{basename}.md"
    # Normalize board to plain dict for dump.
    data = dict(board)
    json_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_path.write_text(render_scoreboard_markdown(data), encoding="utf-8")
    return {"json": json_path, "markdown": md_path}


MappingLike = Mapping[str, Any]


def render_scoreboard_markdown(board: Mapping[str, Any]) -> str:
    """Human-readable scoreboard with required honesty language."""
    honesty = board.get("honesty") or {}
    agg = board.get("aggregate") or {}
    lines: List[str] = [
        "# Benchmark scoreboard (re-score)",
        "",
        "## Honesty",
        "",
        "- Results are **not** undetectable and **not** anonymous; residual risk remains (forbidden claim markers: absolute certainty means must never be claimed).",
        "- Firecrawl `enhanced` / auto-fallback to enhanced is a **non-scoring ceiling**, not parity.",
        "- Hard / residential profiles may typed-skip when not gated; skips are not soft content wins.",
        "- No commercial Web Unlocker parity claim is made from these rows.",
        "- Core formats only: markdown, html/rawHtml, links (LLM extract and interact excluded).",
        f"- Trust model: {honesty.get('model', 'cryptographically-anchored trust-but-audit')}.",
        "- Secrets stay in mode-600 gitignored `.env`; never in this report.",
        "",
        "## Aggregate (scoring rows)",
        "",
        f"- rows (all): {agg.get('n_rows')}",
        f"- rows (scoring): {agg.get('n_scoring_rows')}",
        f"- mean core_total: {agg.get('mean_core_total')}",
        f"- median core_total: {agg.get('median_core_total')}",
        f"- mean secondary proof (basecrawl only): {agg.get('mean_secondary_proof')}",
        "",
        "## Per-URL scores",
        "",
        "| url | engine | profile | core_total | content | interstitial | md | links | js | latency | cost | proof |",
        "| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in board.get("rows") or []:
        d = row.get("dimensions") or {}
        proof = d.get("proof_identity")
        proof_s = "" if proof is None else f"{proof:.3f}"
        lines.append(
            "| {url} | {engine} | {profile} | {core:.3f} | {cs:.3f} | {inter:.3f} | "
            "{md:.3f} | {links:.3f} | {js:.3f} | {lat:.3f} | {cost:.3f} | {proof} |".format(
                url=_cell(row.get("url")),
                engine=_cell(row.get("engine")),
                profile=_cell(row.get("profile_id")),
                core=float(row.get("core_total") or 0.0),
                cs=float(d.get("content_success") or 0.0),
                inter=float(d.get("interstitial_false_success") or 0.0),
                md=float(d.get("markdown_quality") or 0.0),
                links=float(d.get("links_quality") or 0.0),
                js=float(d.get("js_render") or 0.0),
                lat=float(d.get("latency") or 0.0),
                cost=float(d.get("cost_estimate") or 0.0),
                proof=proof_s,
            )
        )
    lines.extend(
        [
            "",
            f"digest: `{board.get('digest', '')}`",
            f"live_network: {board.get('live_network', False)}",
            "",
        ]
    )
    return "\n".join(lines)


def scoreboard_digest(board: Mapping[str, Any]) -> str:
    """Stable digest over row scores (ignores timing of write)."""
    material = {
        "rows": [
            {
                "url": r.get("url"),
                "engine": r.get("engine"),
                "profile_id": r.get("profile_id"),
                "core_total": r.get("core_total"),
                "dimensions": r.get("dimensions"),
                "secondary_total": r.get("secondary_total"),
            }
            for r in (board.get("rows") or [])
        ],
        "aggregate": {
            "mean_core_total": (board.get("aggregate") or {}).get("mean_core_total"),
            "median_core_total": (board.get("aggregate") or {}).get("median_core_total"),
            "mean_by_dimension": (board.get("aggregate") or {}).get("mean_by_dimension"),
            "n_scoring_rows": (board.get("aggregate") or {}).get("n_scoring_rows"),
        },
    }
    blob = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def digests_equal(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    da = a.get("digest") or scoreboard_digest(a)
    db = b.get("digest") or scoreboard_digest(b)
    return da == db


def _cell(value: Any) -> str:
    s = str(value or "")
    return s.replace("|", "\\|")
