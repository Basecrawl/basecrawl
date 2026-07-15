"""Schema validation tests (VAL-BENCH-005, 006, 031)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark.formats import (  # noqa: E402
    CORE_FORMATS,
    EXCLUDED_CORE_FORMATS,
    filter_core_formats,
    is_core_format,
    request_core_formats,
)
from benchmark.schema import (  # noqa: E402
    SCHEMA_VERSION,
    load_many,
    load_normalized_result,
    validate_normalized_result,
)

FIXTURES = ROOT / "fixtures" / "artifacts"


def _load_raw(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_common_schema_validates_basecrawl_and_firecrawl_fixtures():
    for name in ("soft-basecrawl-example.json", "soft-firecrawl-example.json"):
        raw = _load_raw(name)
        errors = validate_normalized_result(raw, require_body_payload=True)
        assert errors == [], (name, errors)
        result = load_normalized_result(raw)
        assert result.schema_version == SCHEMA_VERSION
        assert result.url
        assert result.engine in {"basecrawl", "firecrawl"}
        assert result.profile_id
        assert "markdown" in result.formats_requested
        assert result.latency_ms is not None
        assert result.cost_estimate is not None
        assert result.markdown_body or result.markdown_path
        assert result.links is not None


def test_required_common_fields_missing_are_reported():
    raw = {"url": "https://example.com/"}
    errors = validate_normalized_result(raw)
    joined = " ".join(errors)
    for field in (
        "schema_version",
        "engine",
        "profile_id",
        "formats_requested",
        "formats_produced",
        "challenge_class",
        "content_success",
        "latency_ms",
        "cost_estimate",
        "error_class",
    ):
        assert field in joined


def test_artifacts_retain_payload_for_rescore():
    """VAL-BENCH-031: bodies or paths present for quality dims."""
    results = []
    for path in sorted(FIXTURES.glob("*.json")):
        results.extend(load_many(path))
    assert len(results) >= 4
    for r in results:
        # At least one of body/path/empty explicit is present for scorer inputs.
        md = r.resolve_markdown()
        links = r.resolve_links()
        assert isinstance(md, str)
        assert isinstance(links, list)


def test_fair_core_formats_exclude_extract_and_interact():
    """VAL-BENCH-006 / VAL-BENCH-029."""
    assert "markdown" in CORE_FORMATS
    assert "links" in CORE_FORMATS
    assert "html" in CORE_FORMATS or "rawHtml" in CORE_FORMATS
    for bad in ("json", "extract", "interact", "agent", "summary", "branding", "product"):
        assert bad in EXCLUDED_CORE_FORMATS or not is_core_format(bad)
        assert not is_core_format(bad)

    default = request_core_formats()
    assert set(default) <= CORE_FORMATS
    assert "json" not in default
    assert "interact" not in default

    filtered = filter_core_formats(
        ["markdown", "json", "interact", "links", "summary", "html"]
    )
    assert "json" not in filtered
    assert "interact" not in filtered
    assert "summary" not in filtered
    assert "markdown" in filtered
    assert "links" in filtered


def test_scoring_role_must_request_core_format():
    raw = _load_raw("soft-basecrawl-example.json")
    raw["formats_requested"] = ["json", "interact"]
    raw["scoring_role"] = "scoring"
    errors = validate_normalized_result(raw)
    assert any("core format" in e for e in errors)


def test_invalid_engine_rejected():
    raw = _load_raw("soft-basecrawl-example.json")
    raw["engine"] = "selenium"
    errors = validate_normalized_result(raw)
    assert any("engine" in e for e in errors)
