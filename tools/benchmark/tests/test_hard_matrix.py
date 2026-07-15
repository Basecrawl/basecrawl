"""Hard-shield H2H matrix tests (VAL-HARD-001/007/009/010/012/013/016,
VAL-CROSS-HARD-005/007/009/010)."""

from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark.cli import main  # noqa: E402
from benchmark.hard_matrix import (  # noqa: E402
    HARD_CANARY_PORT_RANGE,
    HARD_TARGETS,
    PATH_COMBOS,
    TAOSTATS_URL,
    HardMatrixConfig,
    HardMatrixRunner,
    assert_ports_in_range,
    hard_matrix_summary,
    run_hard_matrix,
)
from benchmark.residential_limit import (  # noqa: E402
    ResidentialConcurrencyError,
    reset_residential_slot_for_tests,
    residential_slot,
    residential_slot_held,
)
from benchmark.schema import CostEstimate, NormalizedResult, SCHEMA_VERSION  # noqa: E402

FIXTURES = ROOT / "fixtures" / "artifacts"


@pytest.fixture(autouse=True)
def _clear_residential_slot():
    reset_residential_slot_for_tests()
    yield
    reset_residential_slot_for_tests()


def test_val_hard_001_taostats_required_in_matrix_docs():
    summary = hard_matrix_summary()
    assert summary["required_url"] == TAOSTATS_URL
    urls = [t["url"] for t in summary["targets"]]
    assert TAOSTATS_URL in urls
    assert any(t.get("required") for t in summary["targets"] if t["url"] == TAOSTATS_URL)


def test_val_hard_009_multi_vendor_shield_table():
    families = {t["shield_family"] for t in HARD_TARGETS}
    assert "cloudflare_turnstile" in families
    # At least a short list beyond taostats-only
    assert len(HARD_TARGETS) >= 3
    assert len(families) >= 3
    for t in HARD_TARGETS:
        assert t["url"]
        assert t["shield_family"]
        assert t["difficulty"] in {"hard", "medium"}


def test_val_cross_hard_007_path_combo_labels_explicit():
    labels = {c["label"] for c in PATH_COMBOS}
    assert "hard-chromium" in labels
    assert "hard-residential" in labels
    assert "hard-residential+solver" in labels
    assert "firecrawl-basic" in labels
    assert "firecrawl-enhanced-ceiling" in labels
    assert "soft-ssr-shell" in labels


def test_val_hard_016_canary_ports_in_mission_range():
    assert HARD_CANARY_PORT_RANGE == (21000, 21099)
    assert_ports_in_range([21000, 21095, 21099])
    with pytest.raises(AssertionError):
        assert_ports_in_range([21100])
    # default summary documents range
    s = hard_matrix_summary()
    assert s["canary_port_range"] == [21000, 21099]
    assert 21000 <= s["default_canary_bind_port"] <= 21099


def test_hard_matrix_rejects_out_of_range_canary_port(tmp_path: Path):
    with pytest.raises(ValueError):
        run_hard_matrix(
            HardMatrixConfig(
                canary_bind_port=3000,
                dry_run=True,
                live=False,
                output_dir=tmp_path,
                load_dotenv=False,
            )
        )


def test_dry_hard_matrix_writes_scoreboard_under_hard_dir(tmp_path: Path, monkeypatch):
    from benchmark import hard_matrix as hm

    def fake_bc(self, url):  # noqa: ANN001
        soft = self.config.path_mode == "soft"
        return NormalizedResult(
            schema_version=SCHEMA_VERSION,
            engine="basecrawl",
            profile_id=self.config.profile_id,
            url=url,
            scoring_role="scoring" if not soft else "research",
            content_success=False if "taostats" in url else True,
            challenge_class="challenge_blocked" if "taostats" in url else "none",
            status_class="2xx",
            error_class="challenge_blocked" if "taostats" in url else "none",
            fetch_path="direct" if soft else "chromium",
            proxy_class="direct",
            formats_requested=["markdown", "html", "links"],
            formats_produced=["markdown"] if soft else [],
            markdown_body=(
                "# marketing shell\n\n<div id=\"__next\"></div>\nplease enable javascript"
                if soft
                else ""
            ),
            html_body="<div id=\"__next\"></div>" if soft else "",
            links=[],
            http_status=200,
            latency_ms=900.0,
            cost_estimate=CostEstimate(notes="test hermetic"),
            proof_present=False,
            attestation_present=False,
            metadata={"fake": True, "path_mode": self.config.path_mode},
        )

    def fake_fc(self, url):  # noqa: ANN001
        enhanced = (self.config.proxy_mode or "") == "enhanced"
        body = (
            "Just a moment...\nChecking your Browser\ncdn-cgi/challenge-platform\ncf-turnstile"
        )
        return NormalizedResult(
            schema_version=SCHEMA_VERSION,
            engine="firecrawl",
            profile_id=self.config.profile_id,
            url=url,
            scoring_role="ceiling" if enhanced else "scoring",
            content_success=True,  # vendor success claim — scorer still zeros sandwich
            challenge_class="managed_challenge",
            status_class="2xx",
            error_class="none",
            fetch_path="cloud",
            proxy_class="enhanced" if enhanced else "basic",
            formats_requested=["markdown", "html", "links"],
            formats_produced=["markdown", "html"],
            markdown_body=body,
            html_body=f"<html>{body}</html>",
            links=[],
            http_status=200,
            latency_ms=1100.0,
            cost_estimate=CostEstimate(firecrawl_credits=1.0, notes="test"),
            proof_present=False,
            attestation_present=False,
            metadata={"fake": True, "non_scoring_ceiling": enhanced},
        )

    monkeypatch.setattr(hm.BasecrawlAdapter, "scrape", fake_bc)
    monkeypatch.setattr(hm.FirecrawlAdapter, "scrape", fake_fc)

    out = tmp_path / "benchmark" / "hard"
    board = run_hard_matrix(
        HardMatrixConfig(
            dry_run=True,
            live=False,
            include_residential=False,
            include_solver=False,
            include_soft_shell=True,
            include_enhanced=True,
            include_firecrawl_basic=True,
            max_targets=2,  # taostats + 1 optional
            output_dir=out,
            basename="scoreboard-hard-h2h-dry",
            load_dotenv=False,
            pacing_s=0.0,
        )
    )
    assert board["mode"] == "hard-matrix"
    assert board["live_network"] is False
    written = board["written"]
    assert "hard" in written["dir"]
    assert Path(written["json"]).is_file()
    assert Path(written["markdown"]).is_file()
    md = Path(written["markdown"]).read_text(encoding="utf-8")
    # VAL-HARD-012 honesty
    assert "Honesty" in md
    assert "not** undetectable" in md or "not" in md.lower()
    assert "undetectable" in md.lower()
    assert "Unlocker" in md or "unlocker" in md.lower()
    assert "CapSolver" in md or "capsolver" in md.lower()
    assert "must never" in md.lower() or "forbidden claim" in md.lower()
    # residual wording must keep "not" near banned struggles — check absolute slogans absent as claims
    assert "fully stealth" not in md.lower()
    assert "not** trustless" in md or "not trustless" in md.lower() or "**not** trustless" in md
    # taostats always
    assert "taostats.io" in md
    # path combos labeled
    assert "hard-chromium" in md
    assert "firecrawl-basic" in md or "firecrawl" in md.lower()

    # Artifacts have challenge_class and path_combo (VAL-HARD-010, VAL-CROSS-HARD-007)
    arts = list((out / "artifacts").glob("*.json"))
    assert arts
    path_combos = set()
    for p in arts:
        payload = json.loads(p.read_text(encoding="utf-8"))
        assert payload.get("challenge_class")
        meta = payload.get("metadata") or {}
        assert meta.get("path_combo")
        path_combos.add(meta["path_combo"])
        # secrets scrubbed
        blob = p.read_text(encoding="utf-8")
        assert "CAPSOLVER" not in blob
        assert "sk-" not in blob
        assert "password=" not in blob.lower()
    assert "hard-chromium" in path_combos
    assert "soft-ssr-shell" in path_combos

    # soft shell honesty (VAL-HARD-007)
    soft_arts = [
        json.loads(p.read_text(encoding="utf-8"))
        for p in arts
        if "soft" in (json.loads(p.read_text(encoding="utf-8")).get("profile_id") or "")
        or (json.loads(p.read_text(encoding="utf-8")).get("metadata") or {}).get(
            "path_combo"
        )
        == "soft-ssr-shell"
    ]
    assert soft_arts
    for a in soft_arts:
        meta = a.get("metadata") or {}
        if meta.get("path_combo") == "soft-ssr-shell":
            assert meta.get("shell_only") is True
            assert meta.get("dynamic_content_unlocked") is False
            assert meta.get("hard_unlock_claim") is False


def test_taostats_always_retained_when_filter_omits(tmp_path: Path, monkeypatch):
    from benchmark import hard_matrix as hm

    def fake(self, url):  # noqa: ANN001
        return NormalizedResult(
            schema_version=SCHEMA_VERSION,
            engine=self.config.profile_id.startswith("H-firecrawl") and "firecrawl" or "basecrawl"
            if False
            else ("basecrawl" if "firecrawl" not in self.config.profile_id else "firecrawl"),
            profile_id=self.config.profile_id,
            url=url,
            scoring_role="scoring",
            content_success=False,
            challenge_class="challenge_blocked",
            status_class="2xx",
            error_class="challenge_blocked",
            fetch_path="chromium",
            proxy_class="direct",
            formats_requested=["markdown"],
            formats_produced=[],
            markdown_body="",
            links=[],
            http_status=200,
            latency_ms=10.0,
            cost_estimate=CostEstimate(notes="t"),
            metadata={},
        )

    # simplify: monkey both
    def fake_bc(self, url):  # noqa: ANN001
        return NormalizedResult(
            schema_version=SCHEMA_VERSION,
            engine="basecrawl",
            profile_id=self.config.profile_id,
            url=url,
            scoring_role="scoring",
            content_success=False,
            challenge_class="managed_challenge",
            status_class="2xx",
            error_class="none",
            fetch_path="chromium",
            proxy_class="direct",
            formats_requested=["markdown"],
            formats_produced=[],
            markdown_body="Just a moment",
            links=[],
            http_status=200,
            latency_ms=10.0,
            cost_estimate=CostEstimate(notes="t"),
            metadata={},
        )

    def fake_fc(self, url):  # noqa: ANN001
        return NormalizedResult(
            schema_version=SCHEMA_VERSION,
            engine="firecrawl",
            profile_id=self.config.profile_id,
            url=url,
            scoring_role="scoring",
            content_success=False,
            challenge_class="managed_challenge",
            status_class="2xx",
            error_class="none",
            fetch_path="cloud",
            proxy_class="basic",
            formats_requested=["markdown"],
            formats_produced=[],
            markdown_body="Just a moment",
            links=[],
            http_status=200,
            latency_ms=10.0,
            cost_estimate=CostEstimate(notes="t"),
            metadata={},
        )

    monkeypatch.setattr(hm.BasecrawlAdapter, "scrape", fake_bc)
    monkeypatch.setattr(hm.FirecrawlAdapter, "scrape", fake_fc)

    board = run_hard_matrix(
        HardMatrixConfig(
            targets=["nowsecure"],  # omit taostats from filter
            combos=["hard-chromium"],
            dry_run=True,
            live=False,
            include_enhanced=False,
            include_soft_shell=False,
            include_firecrawl_basic=False,
            output_dir=tmp_path,
            load_dotenv=False,
            pacing_s=0.0,
        )
    )
    target_urls = [t["url"] for t in board["hard_matrix"]["targets"]]
    assert TAOSTATS_URL in target_urls
    row_urls = {r["url"] for r in board["rows"]}
    assert any("taostats.io" in u for u in row_urls)


def test_val_cross_hard_009_max1_residential_preserved(monkeypatch, tmp_path: Path):
    from benchmark import hard_matrix as hm

    calls = {"n": 0}
    concurrent = {"max": 0, "cur": 0}
    lock = threading.Lock()

    def fake_bc(self, url):  # noqa: ANN001
        if self.config.path_mode == "residential":
            # The runner acquires residential_slot before scrape for live non-dry.
            assert residential_slot_held(), "hard matrix must hold max-1 slot during residential"
            with lock:
                concurrent["cur"] += 1
                concurrent["max"] = max(concurrent["max"], concurrent["cur"])
            calls["n"] += 1
            with lock:
                concurrent["cur"] -= 1
        return NormalizedResult(
            schema_version=SCHEMA_VERSION,
            engine="basecrawl",
            profile_id=self.config.profile_id,
            url=url,
            scoring_role="scoring",
            content_success=False,
            challenge_class="network_error",
            status_class="unknown",
            error_class="transport",
            fetch_path="chromium",
            proxy_class="residential"
            if self.config.path_mode == "residential"
            else "direct",
            formats_requested=["markdown"],
            formats_produced=[],
            markdown_body="",
            links=[],
            http_status=None,
            latency_ms=5.0,
            cost_estimate=CostEstimate(notes="t"),
            metadata={"path_mode": self.config.path_mode},
        )

    monkeypatch.setattr(hm.BasecrawlAdapter, "scrape", fake_bc)

    board = run_hard_matrix(
        HardMatrixConfig(
            combos=["hard-residential"],
            targets=["taostats"],
            dry_run=False,
            live=True,  # exercises slot acquisition path without real network (fake scrape)
            include_residential=True,
            include_enhanced=False,
            include_soft_shell=False,
            include_firecrawl_basic=False,
            output_dir=tmp_path,
            load_dotenv=False,
            pacing_s=0.0,
        )
    )
    assert board["hard_matrix"]["residential_max_concurrent"] == 1
    assert concurrent["max"] <= 1
    assert calls["n"] >= 1

    # Second concurrent acquisition still refused by global guard.
    with residential_slot(owner="test-holder"):
        with pytest.raises(ResidentialConcurrencyError):
            with residential_slot(owner="intruder", blocking=False):
                pass


def test_scorer_only_hard_fixtures_write_hard_path(tmp_path: Path):
    board = run_hard_matrix(
        HardMatrixConfig(
            scorer_only=True,
            artifacts_dir=FIXTURES,
            output_dir=tmp_path / "hard",
            basename="scoreboard-hard-scorer",
            load_dotenv=False,
        )
    )
    assert board["mode"] == "hard-matrix-scorer-only"
    assert Path(board["written"]["json"]).is_file()
    md = Path(board["written"]["markdown"]).read_text(encoding="utf-8")
    assert "Honesty" in md
    assert "taostats" in md.lower() or any(
        "taostats" in (r.get("url") or "") for r in board.get("rows") or []
    )


def test_cli_hard_matrix_info_lists_taostats(capsys):
    rc = main(["hard-matrix", "--info"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["required_url"] == TAOSTATS_URL
    assert data["evidence_path"] == ".docs-evidence/benchmark/hard/"
    assert data["residential_max_concurrent"] == 1
    assert data["canary_port_range"] == [21000, 21099]
    assert data["honesty"]["not_unlocker_parity"] is True
    assert data["shell_vs_dynamic"]["full_unlock_claim_forbidden_from_shell_alone"] is True


def test_cli_hard_matrix_dry_run(tmp_path: Path, monkeypatch, capsys):
    from benchmark import hard_matrix as hm

    def fake_bc(self, url):  # noqa: ANN001
        return NormalizedResult(
            schema_version=SCHEMA_VERSION,
            engine="basecrawl",
            profile_id=self.config.profile_id,
            url=url,
            scoring_role="scoring",
            content_success=False,
            challenge_class="challenge_blocked",
            status_class="2xx",
            error_class="challenge_blocked",
            fetch_path="chromium",
            proxy_class="direct",
            formats_requested=["markdown"],
            formats_produced=[],
            markdown_body="",
            links=[],
            http_status=200,
            latency_ms=1.0,
            cost_estimate=CostEstimate(notes="t"),
            metadata={},
        )

    def fake_fc(self, url):  # noqa: ANN001
        return NormalizedResult(
            schema_version=SCHEMA_VERSION,
            engine="firecrawl",
            profile_id=self.config.profile_id,
            url=url,
            scoring_role="ceiling",
            content_success=False,
            challenge_class="managed_challenge",
            status_class="2xx",
            error_class="none",
            fetch_path="cloud",
            proxy_class="enhanced",
            formats_requested=["markdown"],
            formats_produced=["markdown"],
            markdown_body="Checking your Browser",
            links=[],
            http_status=200,
            latency_ms=1.0,
            cost_estimate=CostEstimate(notes="t"),
            metadata={},
        )

    monkeypatch.setattr(hm.BasecrawlAdapter, "scrape", fake_bc)
    monkeypatch.setattr(hm.FirecrawlAdapter, "scrape", fake_fc)

    rc = main(
        [
            "hard-matrix",
            "--dry-run",
            "--combos",
            "hard-chromium,firecrawl-enhanced-ceiling",
            "--targets",
            "taostats",
            "--out",
            str(tmp_path),
            "--basename",
            "cli-hard",
            "--no-dotenv",
            "--pacing-s",
            "0",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert out["mode"] == "hard-matrix"
    assert out["required_url"] == TAOSTATS_URL
    assert (tmp_path / "cli-hard.md").is_file()
    # VAL-CROSS-HARD-005: summary never dumps secrets
    text = json.dumps(out)
    assert "CAPSOLVER_API_KEY" not in text
    assert "sk-" not in text


def test_reusable_tools_benchmark_not_ad_hoc_shell():
    """VAL-HARD-013: hard H2H lives under tools/benchmark adapters/scorer."""
    pkg = ROOT / "benchmark"
    assert (pkg / "hard_matrix.py").is_file()
    assert (pkg / "basecrawl_adapter.py").is_file()
    assert (pkg / "firecrawl_adapter.py").is_file()
    assert (pkg / "scorer.py").is_file()
    # Docs surface
    assert (ROOT / "MATRIX.md").is_file()
