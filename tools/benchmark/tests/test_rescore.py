"""Deterministic offline re-score tests (VAL-BENCH-030, 031)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark.rescore import (  # noqa: E402
    digests_equal,
    rescore_artifacts,
    rescore_directory,
    scoreboard_digest,
    write_scoreboard,
)
from benchmark.schema import load_many  # noqa: E402

FIXTURES = ROOT / "fixtures" / "artifacts"


def test_rescore_directory_has_no_live_network_flag():
    board = rescore_directory(FIXTURES)
    assert board["live_network"] is False
    assert board["mode"] == "rescore"
    assert board["n_inputs"] >= 4
    assert "aggregate" in board
    assert "rows" in board
    assert board["digest"]


def test_rescore_is_deterministic_for_unchanged_artifacts():
    a = rescore_directory(FIXTURES)
    b = rescore_directory(FIXTURES)
    assert digests_equal(a, b)
    assert a["digest"] == b["digest"]
    assert scoreboard_digest(a) == a["digest"]


def test_rescore_from_in_memory_matches_directory():
    results = []
    for path in sorted(FIXTURES.glob("*.json")):
        results.extend(load_many(path))
    board = rescore_artifacts(results, base_dir=FIXTURES)
    board2 = rescore_directory(FIXTURES)
    # Same inputs / order may differ by glob order; compare after sorting rows.
    def norm(b):
        rows = sorted(
            b["rows"],
            key=lambda r: (r["url"], r["engine"], r["profile_id"], r["core_total"]),
        )
        return json.dumps(
            {
                "rows": [
                    {
                        "url": r["url"],
                        "engine": r["engine"],
                        "profile_id": r["profile_id"],
                        "core_total": r["core_total"],
                        "dimensions": r["dimensions"],
                    }
                    for r in rows
                ]
            },
            sort_keys=True,
        )

    assert norm(board) == norm(board2)


def test_write_scoreboard_json_and_markdown(tmp_path: Path):
    board = rescore_directory(FIXTURES)
    paths = write_scoreboard(board, tmp_path, basename="scoreboard-test")
    assert paths["json"].is_file()
    assert paths["markdown"].is_file()
    data = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert data["digest"] == board["digest"]
    md = paths["markdown"].read_text(encoding="utf-8")
    assert "Honesty" in md
    assert "not" in md.lower() and "undetectable" in md.lower()
    assert "unlocker" in md.lower()
    assert "extract" in md.lower() or "interact" in md.lower()
    # Forbidden absolute marketing claims must not appear as affirmative true wins.
    assert "beats Firecrawl stealth 100%" not in md
    assert "trustless" not in md.lower()


def test_path_refs_support_offline_rescore(tmp_path: Path):
    """Artifacts can store path refs instead of inline bodies (VAL-BENCH-031)."""
    md_path = tmp_path / "body.md"
    links_path = tmp_path / "links.json"
    md_path.write_text(
        "# Path Ref Article\n\nPrimary body with enough substance for scoring.\n\n"
        "## Section\n\n- item one\n- item two\n\nMore paragraph content about examples.\n",
        encoding="utf-8",
    )
    links_path.write_text(
        json.dumps(["https://example.com/a", "https://example.com/b"]),
        encoding="utf-8",
    )
    artifact = {
        "schema_version": "1.0.0",
        "url": "https://example.com/path-ref",
        "engine": "basecrawl",
        "profile_id": "P1-soft-basecrawl",
        "formats_requested": ["markdown", "html", "links"],
        "formats_produced": ["markdown", "links"],
        "http_status": 200,
        "status_class": "2xx",
        "challenge_class": "none",
        "content_success": True,
        "latency_ms": 500,
        "cost_estimate": {"notes": "path-ref fixture"},
        "error_class": "none",
        "scoring_role": "scoring",
        "markdown_path": str(md_path.name),
        "links_path": str(links_path.name),
        "fetch_path": "direct",
        "proxy_class": "direct",
        "expected_min_links": 2,
        "js_target": False,
        "proof_present": False,
        "attestation_present": False,
    }
    art_file = tmp_path / "artifact.json"
    art_file.write_text(json.dumps(artifact), encoding="utf-8")
    results = load_many(art_file)
    board = rescore_artifacts(results, base_dir=tmp_path)
    assert board["rows"][0]["dimensions"]["markdown_quality"] > 0.3
    assert board["rows"][0]["dimensions"]["links_quality"] > 0.5
    # Second rescore identical.
    board2 = rescore_artifacts(results, base_dir=tmp_path)
    assert digests_equal(board, board2)
