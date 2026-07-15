"""Hard-shield CF sandwich false-success scoring (VAL-HARD-004/005/006/011/014).

Hermetic fixtures derived from the 2026-07-15 taostats probe matrix. Offline
re-score must never dial Firecrawl or Oxylabs.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark.rescore import digests_equal, rescore_directory  # noqa: E402
from benchmark.schema import (  # noqa: E402
    CHALLENGE_CLASSES,
    load_normalized_result_file,
)
from benchmark.scorer import (  # noqa: E402
    CONTENT_SUCCESS_SANDWICH_MAX,
    score_result,
    score_results,
)

FIXTURES = ROOT / "fixtures" / "artifacts"

# Documented hard-shield float ceiling for challenge sandwich content_success.
SANDWICH_CONTENT_MAX = 0.05


def _score(name: str):
    return score_result(load_normalized_result_file(FIXTURES / name))


def test_challenge_class_includes_managed_and_turnstile():
    """VAL-HARD-010 vocabulary for hard rows (classification beyond bare HTTP)."""
    for label in ("managed_challenge", "turnstile", "challenge_blocked", "interstitial"):
        assert label in CHALLENGE_CLASSES


def test_val_hard_004_taostats_sandwich_content_success_approx_zero():
    """VAL-HARD-004: CF sandwich → content_success ≈ 0 despite HTTP 200 / API success flag."""
    row = _score("taostats-fc-basic-sandwich.json")
    assert row.result.http_status == 200
    # Adapter-side flag may still claim success; scorer must suppress content win.
    assert row.result.content_success is True
    assert row.dimensions.content_success <= SANDWICH_CONTENT_MAX
    assert row.dimensions.content_success <= CONTENT_SUCCESS_SANDWICH_MAX
    assert row.dimensions.content_success == 0.0
    assert row.result.challenge_class in {
        "managed_challenge",
        "turnstile",
        "interstitial",
        "challenge_blocked",
        "captcha_surface",
    }


def test_val_hard_005_firecrawl_enhanced_sandwich_ceiling_not_content_win():
    """VAL-HARD-005: enhanced sandwich still content_success≈0 + non-parity ceiling."""
    row = _score("taostats-fc-enhanced-sandwich.json")
    assert row.result.scoring_role == "ceiling"
    assert row.result.profile_id == "P4-firecrawl-enhanced-ceiling"
    assert row.result.proxy_class == "enhanced"
    assert row.dimensions.content_success <= SANDWICH_CONTENT_MAX
    assert row.dimensions.content_success == 0.0
    assert any(
        "ceiling" in n.lower() or "non-scoring" in n.lower() or "non-parity" in n.lower()
        for n in row.notes
    )
    # Enhanced row is ceiling; not a core parity unlock win.
    assert row.result.metadata.get("parity_claim") is False or "non_scoring_ceiling" in (
        row.result.metadata or {}
    ) or row.result.scoring_role == "ceiling"


def test_val_hard_006_firecrawl_basic_sandwich_not_content_unlock():
    """VAL-HARD-006: FC basic/auto sandwich residual + content_success≈0."""
    basic = _score("taostats-fc-basic-sandwich.json")
    legacy = _score("interstitial-false-success.json")
    for row in (basic, legacy):
        assert row.dimensions.content_success <= SANDWICH_CONTENT_MAX
        assert row.dimensions.interstitial_false_success == 0.0
        assert row.dimensions.content_success < 0.5


def test_val_hard_011_interstitial_dimension_distinct_on_hard_scoreboard():
    """VAL-HARD-011: interstitial_false_success is a distinct core dim on hard rows."""
    row = _score("taostats-fc-basic-sandwich.json")
    dims = row.to_dict()["dimensions"]
    assert "content_success" in dims
    assert "interstitial_false_success" in dims
    assert dims["interstitial_false_success"] == 0.0
    assert dims["content_success"] == 0.0
    # Hard detect-not-solve also keeps the dimension (not fused with HTTP alone).
    detect = _score("taostats-basecrawl-hard-detect.json")
    assert "interstitial_false_success" in detect.to_dict()["dimensions"]
    assert detect.dimensions.content_success == 0.0


def test_val_hard_014_offline_rescore_sandwich_fixtures_stable_no_network():
    """VAL-HARD-014: offline re-score of sandwich fixtures; no live re-scrape."""
    board = rescore_directory(FIXTURES)
    assert board["live_network"] is False
    assert board["mode"] == "rescore"
    by_key = {
        (r["url"], r["engine"], r["profile_id"]): r for r in board["rows"]
    }
    basic = by_key[("https://taostats.io/", "firecrawl", "P2-soft-firecrawl-basic")]
    enhanced = by_key[
        ("https://taostats.io/", "firecrawl", "P4-firecrawl-enhanced-ceiling")
    ]
    assert basic["dimensions"]["content_success"] <= SANDWICH_CONTENT_MAX
    assert enhanced["dimensions"]["content_success"] <= SANDWICH_CONTENT_MAX
    assert enhanced["scoring_role"] == "ceiling"
    # Deterministic second pass.
    board2 = rescore_directory(FIXTURES)
    assert digests_equal(board, board2)


def test_legacy_interstitial_fixture_also_zeros_under_hard_rules():
    """Existing interstitial-false-success fixture upgrades to ≈0 content_success."""
    row = _score("interstitial-false-success.json")
    assert row.dimensions.content_success <= SANDWICH_CONTENT_MAX
    assert row.dimensions.interstitial_false_success == 0.0
    assert row.core_total < 0.5


def test_healthy_soft_content_still_scores_high():
    """Regression: real soft content is not false-penalized by sandwich rules."""
    good = _score("soft-basecrawl-example.json")
    assert good.dimensions.content_success == 1.0
    assert good.dimensions.interstitial_false_success == 1.0


def test_score_results_covers_all_hard_sandwich_fixtures():
    names = [
        "taostats-fc-basic-sandwich.json",
        "taostats-fc-enhanced-sandwich.json",
        "taostats-basecrawl-hard-detect.json",
        "interstitial-false-success.json",
    ]
    rows = score_results(
        [load_normalized_result_file(FIXTURES / n) for n in names]
    )
    assert len(rows) == 4
    for row in rows:
        assert row.dimensions.content_success <= SANDWICH_CONTENT_MAX
