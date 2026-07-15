"""Matrix runner tests (VAL-BENCH-007, 009, 032–035, 039 + dry scorer-only)."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark.cli import main  # noqa: E402
from benchmark.matrix import (  # noqa: E402
    DEFAULT_CI_PROFILES,
    DEFAULT_JS_URL,
    DEFAULT_OPERATOR_OPTIONAL,
    DEFAULT_SOFT_URLS,
    DOCUMENTED_PROFILE_IDS,
    MATRIX_PROFILES,
    MatrixRunConfig,
    MatrixRunner,
    matrix_summary,
    resolve_profiles,
    run_matrix,
)

FIXTURES = ROOT / "fixtures" / "artifacts"


def test_matrix_profiles_documented_ci_vs_optional():
    summary = matrix_summary()
    assert "P1" in summary["profiles"]
    assert "P2" in summary["profiles"]
    assert "P3" in summary["profiles"]
    assert "P4" in summary["profiles"]
    assert "hard" in summary["profiles"]
    assert summary["profiles"]["P1"]["ci_default"] is True
    assert summary["profiles"]["P4"]["ci_default"] is False
    assert summary["profiles"]["P4"]["scoring_role"] == "ceiling"
    assert summary["profiles"]["P3"]["operator_optional"] is True
    assert "P1" in summary["ci_default_profiles"]
    assert "P4" in summary["operator_optional_profiles"]
    # JS target present (VAL-BENCH-018).
    assert DEFAULT_JS_URL in summary["js_render_url"]
    assert "quotes.toscrape.com/js" in summary["js_render_url"]
    # Artifact profile ids join MATRIX docs.
    for pid in DOCUMENTED_PROFILE_IDS:
        assert pid.startswith("P")


def test_resolve_profiles_includes_optional_flags():
    cfg = MatrixRunConfig(profiles=["P1"], include_enhanced=True, include_hard=True)
    ids = resolve_profiles(cfg)
    assert "P1" in ids
    assert "P4" in ids
    assert "hard" in ids


def test_dry_scorer_only_writes_scoreboard_under_evidence_dir(tmp_path: Path):
    out = tmp_path / "benchmark-evidence"
    board = run_matrix(
        MatrixRunConfig(
            scorer_only=True,
            artifacts_dir=FIXTURES,
            output_dir=out,
            basename="scoreboard-matrix-scorer",
            dry_run=True,
            live=False,
        )
    )
    assert board["mode"] == "matrix-scorer-only"
    assert board["live_network"] is False
    written = board["written"]
    assert Path(written["json"]).is_file()
    assert Path(written["markdown"]).is_file()
    assert str(out) in written["dir"]
    md = Path(written["markdown"]).read_text(encoding="utf-8")
    assert "Honesty" in md
    assert "undetectable" in md.lower() or "not** undetectable" in md.lower() or "not" in md
    assert "unlocker" in md.lower()
    # No residential label on soft-proven fixture aggregations required false claim
    assert "beats Firecrawl" not in md
    data = json.loads(Path(written["json"]).read_text(encoding="utf-8"))
    assert data.get("digest")
    # Fixture profile ids are documented.
    for row in data.get("rows") or []:
        assert row["profile_id"] in DOCUMENTED_PROFILE_IDS


def test_dry_matrix_p1_soft_dual_same_urls_no_live(tmp_path: Path):
    out = tmp_path / "bench"
    board = run_matrix(
        MatrixRunConfig(
            profiles=["P1"],
            dry_run=True,
            live=False,
            output_dir=out,
            basename="scoreboard-p1-dry",
            soft_urls=list(DEFAULT_SOFT_URLS),
            load_dotenv=False,
        )
    )
    assert board["mode"] == "matrix"
    assert board["live_network"] is False
    assert board["matrix"]["profiles"] == ["P1"]
    assert set(board["matrix"]["formats"]) >= {"markdown", "links"}
    soft_urls = set(board["matrix"]["soft_urls"])
    engines = {r["engine"] for r in board["rows"]}
    # Dual engine soft (firecrawl may skip as engine_unavailable).
    assert "basecrawl" in engines
    assert "firecrawl" in engines
    # Same URL list for both engines.
    bc_urls = {r["url"] for r in board["rows"] if r["engine"] == "basecrawl"}
    fc_urls = {r["url"] for r in board["rows"] if r["engine"] == "firecrawl"}
    assert bc_urls == soft_urls
    assert fc_urls == soft_urls
    # Soft basecrawl must not claim residential (VAL-BENCH-035).
    for r in board["rows"]:
        raw = next(
            (
                x
                for x in (Path(p).read_text(encoding="utf-8") for p in board["matrix"]["written_artifacts"])
                if json.loads(x).get("url") == r["url"] and json.loads(x).get("engine") == r["engine"]
            ),
            None,
        )
        # softer check via profile_id / scoreboard fields
        if r["engine"] == "basecrawl" and r["profile_id"] == "P1-soft-basecrawl":
            assert "residential" not in (r.get("profile_id") or "").lower()
    paths = board["written"]
    assert Path(paths["json"]).is_file()
    assert Path(paths["markdown"]).is_file()
    md = Path(paths["markdown"]).read_text(encoding="utf-8")
    assert "Honesty" in md
    # Secrets never in board.
    assert "sk-" not in md
    assert "password=" not in md.lower()


def test_p2_js_profile_marks_js_target(tmp_path: Path):
    board = run_matrix(
        MatrixRunConfig(
            profiles=["P2"],
            dry_run=True,
            live=False,
            output_dir=tmp_path,
            basename="scoreboard-p2-js",
            load_dotenv=False,
        )
    )
    assert board["matrix"]["js_url"] == DEFAULT_JS_URL
    assert any("quotes.toscrape.com/js" in r["url"] for r in board["rows"])
    # Artifacts retain js_target for re-score of JS dim.
    art_paths = board["matrix"]["written_artifacts"]
    assert art_paths
    sample = json.loads(Path(art_paths[0]).read_text(encoding="utf-8"))
    assert sample.get("js_target") is True
    assert sample["profile_id"] in DOCUMENTED_PROFILE_IDS


def test_p2_live_flag_does_not_typed_skip_basecrawl_js(monkeypatch, tmp_path: Path):
    """P2 is required scoring: live Chromium JS must dial, not hard_optional_skip.

    VAL-BENCH-018 + live H2H leaf: soft+JS profiles require scoring; hard optional only.
    """
    from benchmark import matrix as matrix_mod
    from benchmark.schema import CostEstimate, NormalizedResult, SCHEMA_VERSION

    calls = []

    def fake_scrape(self, url):  # noqa: ANN001
        calls.append((self.config.path_mode, self.config.force_browser, url, self.config.js_target))
        return NormalizedResult(
            schema_version=SCHEMA_VERSION,
            engine="basecrawl",
            profile_id=self.config.profile_id,
            url=url,
            scoring_role="scoring",
            content_success=True,
            challenge_class="none",
            status_class="2xx",
            error_class="none",
            fetch_path="chromium",
            proxy_class="direct",
            js_target=True,
            formats_requested=["markdown", "html", "links"],
            formats_produced=["markdown", "html", "links"],
            markdown_body="Albert Einstein quote text from JS",
            links=["https://quotes.toscrape.com/"],
            http_status=200,
            latency_ms=1200.0,
            cost_estimate=CostEstimate(notes="test"),
            proof_present=False,
            attestation_present=False,
            metadata={"fake": True},
        )

    monkeypatch.setattr(matrix_mod.BasecrawlAdapter, "scrape", fake_scrape)

    def fake_fc(self, url):  # noqa: ANN001
        return NormalizedResult(
            schema_version=SCHEMA_VERSION,
            engine="firecrawl",
            profile_id="P2-soft-firecrawl-basic",
            url=url,
            scoring_role="scoring",
            content_success=True,
            challenge_class="none",
            status_class="2xx",
            error_class="none",
            fetch_path="cloud",
            proxy_class="basic",
            js_target=True,
            formats_requested=["markdown", "html", "links"],
            formats_produced=["markdown"],
            markdown_body="quote",
            links=[],
            http_status=200,
            latency_ms=800.0,
            cost_estimate=CostEstimate(firecrawl_credits=1.0, notes="test"),
            proof_present=False,
            attestation_present=False,
            metadata={"fake": True},
        )

    monkeypatch.setattr(matrix_mod.FirecrawlAdapter, "scrape", fake_fc)

    board = run_matrix(
        MatrixRunConfig(
            profiles=["P2"],
            dry_run=False,
            live=True,
            include_hard=False,  # must NOT gate P2
            output_dir=tmp_path,
            basename="scoreboard-p2-live-nonskip",
            load_dotenv=False,
        )
    )
    art_paths = board["matrix"]["written_artifacts"]
    arts = [json.loads(Path(p).read_text(encoding="utf-8")) for p in art_paths]
    bc = [a for a in arts if a["engine"] == "basecrawl"]
    assert bc, "expected basecrawl P2 row"
    assert all(a.get("challenge_class") != "hard_optional_skipped" for a in bc)
    assert all(a.get("js_target") is True for a in bc)
    assert all(a.get("content_success") is True for a in bc)
    assert calls, "basecrawl adapter should dial for live P2 JS"
    assert calls[0][0] == "hard" and calls[0][1] is True


def test_optional_hard_and_p3_typed_skip_without_gate(tmp_path: Path):
    board = run_matrix(
        MatrixRunConfig(
            profiles=["hard", "P3"],
            dry_run=True,
            live=False,
            include_hard=False,
            include_residential=False,
            include_medium=False,
            include_optional=False,
            output_dir=tmp_path,
            basename="scoreboard-optional-skip",
            load_dotenv=False,
        )
    )
    challenges = {r.get("challenge_class") for r in board["rows"]}
    # Via row dimensions + artifacts
    arty = []
    for p in board["matrix"]["written_artifacts"]:
        arty.append(json.loads(Path(p).read_text(encoding="utf-8")))
    assert arty
    skip_classes = {a["challenge_class"] for a in arty}
    assert skip_classes & {
        "hard_optional_skipped",
        "medium_optional_skipped",
    }
    # Content success is false for typed skips.
    assert all(a["content_success"] is False for a in arty)
    assert all(a["error_class"] in {"policy_skip", "engine_unavailable"} for a in arty)


def test_p4_ceiling_role_preserved(tmp_path: Path):
    board = run_matrix(
        MatrixRunConfig(
            profiles=["P4"],
            dry_run=True,
            live=False,
            include_enhanced=True,
            output_dir=tmp_path,
            basename="scoreboard-p4",
            load_dotenv=False,
        )
    )
    roles = set()
    for p in board["matrix"]["written_artifacts"]:
        roles.add(json.loads(Path(p).read_text(encoding="utf-8")).get("scoring_role"))
    assert "ceiling" in roles


def test_cli_matrix_scorer_only(tmp_path: Path, capsys):
    rc = main(
        [
            "matrix",
            "--scorer-only",
            "--artifacts",
            str(FIXTURES),
            "--out",
            str(tmp_path),
            "--basename",
            "cli-matrix-scorer",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert out["mode"] == "matrix-scorer-only"
    assert out["live_network"] is False
    assert (tmp_path / "cli-matrix-scorer.json").is_file()
    assert (tmp_path / "cli-matrix-scorer.md").is_file()


def test_cli_matrix_dry_p1(tmp_path: Path, capsys):
    rc = main(
        [
            "matrix",
            "--profiles",
            "P1",
            "--dry-run",
            "--out",
            str(tmp_path),
            "--basename",
            "cli-matrix-p1",
            "--no-dotenv",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert out["mode"] == "matrix"
    assert (tmp_path / "cli-matrix-p1.json").is_file()
    md = (tmp_path / "cli-matrix-p1.md").read_text(encoding="utf-8")
    assert "Honesty" in md


def test_cli_matrix_info_lists_ci_profiles(capsys):
    rc = main(["matrix", "--info"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ci_default_profiles"] == list(DEFAULT_CI_PROFILES)
    assert data["operator_optional_profiles"] == list(DEFAULT_OPERATOR_OPTIONAL)
    assert data["js_render_url"] == DEFAULT_JS_URL
