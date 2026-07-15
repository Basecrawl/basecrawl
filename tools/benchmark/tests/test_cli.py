"""CLI smoke for validate / score / rescore / info."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark.cli import main  # noqa: E402

FIXTURES = ROOT / "fixtures" / "artifacts"


def test_cli_info_lists_core_formats_not_extract(capsys):
    rc = main(["info"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert "markdown" in data["core_formats"]
    assert "links" in data["core_formats"]
    assert "json" in data["excluded_from_core"] or "interact" in data["excluded_from_core"]
    assert "interact" in data["excluded_from_core"]
    assert set(data["core_weights"].keys())


def test_cli_validate_ok(capsys):
    rc = main(
        [
            "validate",
            "--path",
            str(FIXTURES / "soft-basecrawl-example.json"),
            "--require-body",
        ]
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True


def test_cli_rescore_stable(capsys, tmp_path: Path):
    rc = main(
        [
            "rescore",
            "--artifacts",
            str(FIXTURES),
            "--check-stable",
            "--out",
            str(tmp_path),
            "--basename",
            "cli-rescore",
        ]
    )
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is True
    assert out["live_network"] is False
    assert (tmp_path / "cli-rescore.json").is_file()
    assert (tmp_path / "cli-rescore.md").is_file()
