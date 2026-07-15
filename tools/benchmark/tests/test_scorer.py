"""Scorer dimension tests (VAL-BENCH-008, 022–025, 028)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark.schema import load_normalized_result_file  # noqa: E402
from benchmark.scorer import (  # noqa: E402
    CORE_WEIGHTS,
    aggregate_scores,
    score_result,
    score_results,
)

FIXTURES = ROOT / "fixtures" / "artifacts"


def _score(name: str):
    result = load_normalized_result_file(FIXTURES / name)
    return score_result(result)


def test_dimensions_are_in_closed_unit_interval():
    rows = score_results(
        [
            load_normalized_result_file(p)
            for p in sorted(FIXTURES.glob("*.json"))
        ]
    )
    assert rows
    for row in rows:
        dims = row.dimensions.core_as_dict()
        assert set(dims.keys()) == set(CORE_WEIGHTS.keys())
        for name, value in dims.items():
            assert 0.0 <= value <= 1.0, (row.result.url, name, value)
        if row.dimensions.proof_identity is not None:
            assert 0.0 <= row.dimensions.proof_identity <= 1.0
        assert 0.0 <= row.core_total <= 1.0


def test_aggregates_present_and_weighted():
    rows = score_results(
        [
            load_normalized_result_file(FIXTURES / "soft-basecrawl-example.json"),
            load_normalized_result_file(FIXTURES / "soft-firecrawl-example.json"),
        ]
    )
    agg = aggregate_scores(rows)
    d = agg.to_dict()
    assert d["n_scoring_rows"] == 2
    assert 0.0 <= d["mean_core_total"] <= 1.0
    assert 0.0 <= d["median_core_total"] <= 1.0
    assert set(d["mean_by_dimension"].keys()) == set(CORE_WEIGHTS.keys())
    assert abs(sum(CORE_WEIGHTS.values()) - 1.0) < 1e-9


def test_interstitial_false_success_penalized_separately():
    """VAL-BENCH-022."""
    good = _score("soft-basecrawl-example.json")
    bad = _score("interstitial-false-success.json")
    assert good.dimensions.interstitial_false_success == 1.0
    assert bad.dimensions.interstitial_false_success == 0.0
    # Content success also dampened for interstitial substance failure.
    assert bad.dimensions.content_success < good.dimensions.content_success
    # Distinct dimensions both present in output.
    assert "interstitial_false_success" in bad.to_dict()["dimensions"]
    assert "content_success" in bad.to_dict()["dimensions"]


def test_markdown_quality_not_max_for_empty_or_nav():
    """VAL-BENCH-023."""
    rich = _score("soft-basecrawl-example.json")
    poor = _score("empty-markdown-links.json")
    assert rich.dimensions.markdown_quality > poor.dimensions.markdown_quality
    assert poor.dimensions.markdown_quality < 0.5
    # Non-empty short trash must not max.
    assert poor.dimensions.markdown_quality != 1.0
    assert rich.dimensions.markdown_quality > 0.4


def test_links_quality_empty_on_link_rich_page_is_low():
    """VAL-BENCH-024."""
    empty = _score("empty-markdown-links.json")
    good = _score("js-target-rendered.json")
    assert empty.dimensions.links_quality < 0.5
    assert good.dimensions.links_quality > empty.dimensions.links_quality
    assert empty.dimensions.links_quality != 1.0


def test_latency_does_not_reward_credential_short_circuit():
    """VAL-BENCH-025."""
    failure = _score("credential-error-fast.json")
    success = _score("soft-basecrawl-example.json")
    # Instant credential errors must not beat successful scrapes solely on speed.
    assert failure.dimensions.latency <= 0.55
    assert success.dimensions.latency >= failure.dimensions.latency
    assert failure.dimensions.content_success == 0.0


def test_proof_identity_secondary_basecrawl_only():
    """VAL-BENCH-028."""
    bc = _score("soft-basecrawl-example.json")
    fc = _score("soft-firecrawl-example.json")
    inter = _score("interstitial-false-success.json")

    assert bc.dimensions.proof_identity is not None
    assert bc.dimensions.proof_identity >= 0.5
    assert fc.dimensions.proof_identity is None
    # Firecrawl not failed for lacking attestation.
    assert fc.dimensions.content_success == 1.0
    # basecrawl cannot win core solely via proof on interstitial failure.
    assert inter.dimensions.proof_identity is not None
    assert inter.dimensions.proof_identity >= 0.5
    assert inter.dimensions.content_success < 0.5
    assert inter.core_total < bc.core_total
    assert any("secondary" in n.lower() or "proof" in n.lower() for n in inter.notes)


def test_js_render_prefers_dynamic_content():
    shell = _score("js-target-empty-shell.json")
    rendered = _score("js-target-rendered.json")
    assert rendered.dimensions.js_render > shell.dimensions.js_render


def test_cost_null_not_forced_zero_success():
    rapid = _score("credential-error-fast.json")
    # Cost score lands neutral when null, not 0.0 forced as free win/lose alone.
    assert 0.4 <= rapid.dimensions.cost_estimate <= 0.7
