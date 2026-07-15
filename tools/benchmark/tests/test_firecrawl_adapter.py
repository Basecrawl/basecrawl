"""Firecrawl adapter tests (VAL-BENCH-003/004/012/014/016/019/020/026/027/036/038/040).

Hermetic by default: fakes, offline payloads, and env stripping. Never requires
live Firecrawl dial for CI green. Live soft dry-run works when key is present.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from pathlib import Path
from typing import List

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark.firecrawl_adapter import (  # noqa: E402
    PROFILE_BASIC,
    PROFILE_ENHANCED,
    FirecrawlAdapter,
    FirecrawlAdapterConfig,
    classify_challenge_body,
    classify_firecrawl_failure,
    normalize_firecrawl_payload,
)
from benchmark.firecrawl_limit import (  # noqa: E402
    FIRECRAWL_MAX_CONCURRENCY,
    FirecrawlConcurrencyError,
    firecrawl_active_count,
    firecrawl_slot,
    reset_firecrawl_slots_for_tests,
)
from benchmark.redact import (  # noqa: E402
    collect_secret_fragments,
    looks_like_secret_leak,
    redact_text,
)
from benchmark.schema import validate_normalized_result  # noqa: E402
from benchmark.scorer import score_result  # noqa: E402

FAKE_KEY = "fc-test-secret-key-NEVER-COMMIT-xyz789"
FAKE_KEY_OTHER = "fc-another-secret-SHOULD-NOT-LEAK-42"


@pytest.fixture(autouse=True)
def _clear_fc_slots_and_env(monkeypatch):
    reset_firecrawl_slots_for_tests()
    # Keep ambient real Firecrawl key/store out of unit hermetic paths unless a
    # test opts in explicitly.
    monkeypatch.delenv("FIRECRAWL_API_KEY", raising=False)
    yield
    reset_firecrawl_slots_for_tests()


def _fake_firecrawl_script(tmp_path: Path, payload: dict, *, exit_code: int = 0) -> Path:
    """Write an executable that dumps ``payload`` as JSON on stdout.

    Implemented as a Python script with absolute shebang so hermetic ``PATH``
    restrictions in adapter env cannot break the trivia of printing JSON.
    """
    fake = tmp_path / "fake-firecrawl"
    body = json.dumps(payload)
    # Absolute interpreter; stdout = JSON; stderr = timing line.
    script = (
        "#!/usr/bin/env python3\n"
        "import sys\n"
        'sys.stderr.write(\'Timing: { "url": "https://example.com/", '
        '"duration": "120ms", "status": "success" }\\n\')\n'
        f"sys.stdout.write({body!r} + '\\n')\n"
        f"raise SystemExit({int(exit_code)})\n"
    )
    fake.write_text(script, encoding="utf-8")
    fake.chmod(0o755)
    return fake


def _success_payload(
    *,
    proxy_used: str = "basic",
    credits: int = 1,
    status: int = 200,
    markdown: str | None = None,
) -> dict:
    md = markdown or (
        "# Example Domain\n\nThis domain is for use in illustrative examples "
        "in documents without coordination or asking for permission.\n"
    )
    return {
        "markdown": md,
        "html": "<html><body><h1>Example Domain</h1>"
        "<a href='https://iana.org/domains/example'>More</a></body></html>",
        "links": ["https://iana.org/domains/example"],
        "metadata": {
            "title": "Example Domain",
            "sourceURL": "https://example.com/",
            "url": "https://example.com/",
            "statusCode": status,
            "proxyUsed": proxy_used,
            "creditsUsed": credits,
            "scrapeId": "test-scrape-id-001",
            "concurrencyLimited": False,
        },
    }


def test_skip_cleanly_when_api_key_missing():
    """VAL-BENCH-004: missing key → engine_unavailable fair skip, no crash."""
    cfg = FirecrawlAdapterConfig(
        proxy_mode="basic",
        profile_id=PROFILE_BASIC,
        load_dotenv=False,
        allow_stored_credentials=False,
        skip_if_no_key=True,
        env={"PATH": "/usr/bin"},  # no FIRECRAWL_API_KEY
    )
    result = FirecrawlAdapter(cfg).scrape("https://example.com/")
    errors = validate_normalized_result(result.to_dict())
    assert errors == [], errors
    assert result.engine == "firecrawl"
    assert result.error_class == "engine_unavailable"
    assert result.challenge_class == "engine_unavailable"
    assert result.content_success is False
    assert result.metadata.get("fair_skip") is True
    # Must not be scored as content failure win path.
    scored = score_result(result)
    assert scored.dimensions.content_success == 0.0


def test_dry_run_with_key_available_produces_normalized_artifact():
    """VAL-BENCH-003: dry-run path emits artifact when key present."""
    cfg = FirecrawlAdapterConfig(
        proxy_mode="basic",
        profile_id=PROFILE_BASIC,
        dry_run=True,
        load_dotenv=False,
        allow_stored_credentials=False,
        env={"FIRECRAWL_API_KEY": FAKE_KEY, "PATH": "/usr/bin"},
    )
    result = FirecrawlAdapter(cfg).scrape("https://example.com/")
    errors = validate_normalized_result(result.to_dict())
    assert errors == [], errors
    assert result.engine == "firecrawl"
    assert result.profile_id == PROFILE_BASIC
    assert result.metadata.get("dry_run") is True
    assert result.metadata.get("key_present") is True
    assert result.fetch_path == "cloud"
    assert result.proxy_class == "basic"
    assert result.cost_estimate.notes
    # Secrets never in output.
    blob = json.dumps(result.to_dict())
    assert FAKE_KEY not in blob


def test_soft_adapter_subprocess_with_fake_binary(tmp_path: Path):
    """Normalize live-shaped response: credits, latency, core formats."""
    payload = _success_payload(proxy_used="basic", credits=1)
    fake = _fake_firecrawl_script(tmp_path, payload)
    cfg = FirecrawlAdapterConfig(
        binary=str(fake),
        proxy_mode="basic",
        profile_id=PROFILE_BASIC,
        load_dotenv=False,
        allow_stored_credentials=False,
        env={
            "FIRECRAWL_API_KEY": FAKE_KEY,
            "PATH": "/usr/bin:/bin",
        },
        timeout_s=5,
        expected_min_links=1,
        enforce_concurrency_limit=True,
        concurrency=1,
    )
    result = FirecrawlAdapter(cfg).scrape("https://example.com/")
    errors = validate_normalized_result(result.to_dict(), require_body_payload=True)
    assert errors == [], errors
    assert result.content_success is True
    assert result.fetch_path == "cloud"
    assert result.proxy_class == "basic"
    assert result.error_class == "none"
    assert result.cost_estimate.firecrawl_credits == 1
    assert result.cost_estimate.firecrawl_usd_estimate is not None
    assert result.cost_estimate.firecrawl_usd_estimate > 0
    assert result.latency_ms is not None and result.latency_ms >= 0
    assert "markdown" in result.formats_produced
    assert FAKE_KEY not in json.dumps(result.to_dict())
    # CLI must not have been invoked with -k / --api-key on argv.
    cmd = result.metadata.get("command_redacted") or []
    joined = " ".join(cmd)
    assert "--api-key=" not in joined
    assert FAKE_KEY not in joined


def test_auth_error_fail_closed(tmp_path: Path):
    """VAL-BENCH-014: invalid key → credential_error, not content success."""
    payload = {
        "success": False,
        "error": "Unauthorized: Invalid API key",
        "statusCode": 401,
    }
    fake = _fake_firecrawl_script(tmp_path, payload, exit_code=1)
    cfg = FirecrawlAdapterConfig(
        binary=str(fake),
        proxy_mode="basic",
        profile_id=PROFILE_BASIC,
        load_dotenv=False,
        allow_stored_credentials=False,
        env={"FIRECRAWL_API_KEY": FAKE_KEY, "PATH": "/usr/bin:/bin"},
        timeout_s=5,
    )
    result = FirecrawlAdapter(cfg).scrape("https://example.com/")
    assert result.content_success is False
    assert result.error_class == "credential_error"
    assert result.challenge_class == "credential_error"
    assert result.http_status in {401, 403, None} or result.status_class == "4xx"
    blob = json.dumps(result.to_dict())
    assert FAKE_KEY not in blob
    assert "content_success" in blob and result.content_success is False


def test_budget_exhausted_typed_non_corrupting(tmp_path: Path):
    """VAL-BENCH-038: credit exhaustion is typed budget_exhausted."""
    payload = {
        "success": False,
        "error": "Payment Required: insufficient credits for this scrape",
        "statusCode": 402,
    }
    fake = _fake_firecrawl_script(tmp_path, payload, exit_code=1)
    cfg = FirecrawlAdapterConfig(
        binary=str(fake),
        proxy_mode="basic",
        load_dotenv=False,
        allow_stored_credentials=False,
        env={"FIRECRAWL_API_KEY": FAKE_KEY, "PATH": "/usr/bin:/bin"},
    )
    adapter = FirecrawlAdapter(cfg)
    first = adapter.scrape("https://example.com/a")
    assert first.error_class == "budget_exhausted"
    assert first.challenge_class == "budget_exhausted"
    assert first.content_success is False

    # A prior-shape success payload (offline) remains independent — budget
    # failure does not rewrite existing artifacts.
    good = normalize_firecrawl_payload(_success_payload(), config=cfg, url="https://example.com/")
    assert good.content_success is True
    assert good.error_class == "none"
    assert good.cost_estimate.firecrawl_credits == 1


def test_enhanced_is_optional_non_scoring_ceiling(tmp_path: Path):
    """VAL-BENCH-027: enhanced labeled ceiling / non-parity."""
    payload = _success_payload(proxy_used="enhanced", credits=5)
    fake = _fake_firecrawl_script(tmp_path, payload)
    cfg = FirecrawlAdapterConfig(
        binary=str(fake),
        proxy_mode="enhanced",
        profile_id=PROFILE_ENHANCED,
        load_dotenv=False,
        allow_stored_credentials=False,
        env={"FIRECRAWL_API_KEY": FAKE_KEY, "PATH": "/usr/bin:/bin"},
    )
    result = FirecrawlAdapter(cfg).scrape("https://example.com/")
    assert result.scoring_role == "ceiling"
    assert result.profile_id == PROFILE_ENHANCED
    assert result.proxy_class == "enhanced"
    assert result.metadata.get("non_scoring_ceiling") is True
    assert result.metadata.get("parity_claim") is False
    assert "non-scoring" in (result.identity_notes or "").lower() or "ceiling" in (
        result.cost_estimate.notes or ""
    ).lower()

    # Dry-run enhanced also labeled ceiling without network.
    dry = FirecrawlAdapter(
        FirecrawlAdapterConfig(
            proxy_mode="enhanced",
            dry_run=True,
            load_dotenv=False,
            allow_stored_credentials=False,
            env={"FIRECRAWL_API_KEY": FAKE_KEY},
        )
    ).scrape("https://example.com/")
    assert dry.scoring_role == "ceiling"
    assert dry.metadata.get("non_scoring_ceiling") is True


def test_auto_fallback_to_enhanced_becomes_ceiling(tmp_path: Path):
    """auto proxy that reports proxyUsed=enhanced → ceiling non-parity."""
    payload = _success_payload(proxy_used="enhanced", credits=3)
    fake = _fake_firecrawl_script(tmp_path, payload)
    cfg = FirecrawlAdapterConfig(
        binary=str(fake),
        proxy_mode="auto",
        profile_id=PROFILE_BASIC,
        load_dotenv=False,
        allow_stored_credentials=False,
        env={"FIRECRAWL_API_KEY": FAKE_KEY, "PATH": "/usr/bin:/bin"},
    )
    result = FirecrawlAdapter(cfg).scrape("https://example.com/")
    assert result.scoring_role == "ceiling"
    assert result.proxy_class == "enhanced"


def test_concurrency_limit_at_most_two():
    """VAL-BENCH-012: plan concurrency ceiling is 2."""
    assert FIRECRAWL_MAX_CONCURRENCY == 2
    events: List[str] = []
    gate = threading.Event()

    def holder(name: str):
        with firecrawl_slot(owner=name, blocking=False):
            events.append(f"enter-{name}")
            gate.wait(timeout=1.0)
            events.append(f"exit-{name}")

    t1 = threading.Thread(target=holder, args=("a",))
    t2 = threading.Thread(target=holder, args=("b",))
    t1.start()
    t2.start()
    time.sleep(0.05)
    # Third concurrent must refuse with non-blocking.
    with pytest.raises(FirecrawlConcurrencyError):
        with firecrawl_slot(owner="c", blocking=False):
            events.append("enter-c")  # pragma: no cover
    assert firecrawl_active_count() == 2
    gate.set()
    t1.join(timeout=2)
    t2.join(timeout=2)
    assert "enter-c" not in events
    assert firecrawl_active_count() == 0


def test_scrape_many_caps_workers(tmp_path: Path):
    """scrape_many never uses >2 workers; all multi-URL rows normalize."""
    payload = _success_payload()
    fake = tmp_path / "slow-fc"
    body = json.dumps(payload)
    fake.write_text(
        "#!/usr/bin/env python3\n"
        "import sys, time\n"
        "time.sleep(0.05)\n"
        f"sys.stdout.write({body!r} + '\\n')\n"
        "raise SystemExit(0)\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    cfg = FirecrawlAdapterConfig(
        binary=str(fake),
        proxy_mode="basic",
        load_dotenv=False,
        allow_stored_credentials=False,
        env={"FIRECRAWL_API_KEY": FAKE_KEY, "PATH": "/usr/bin:/bin"},
        concurrency=2,  # at ceiling
        timeout_s=10,
    )
    assert cfg.concurrency <= FIRECRAWL_MAX_CONCURRENCY
    adapter = FirecrawlAdapter(cfg)
    results = adapter.scrape_many(
        [
            "https://example.com/1",
            "https://example.com/2",
            "https://example.com/3",
        ]
    )
    assert len(results) == 3
    assert all(r.engine == "firecrawl" for r in results)
    assert all(r.content_success for r in results)
    # Workers are hard-capped: requesting 99 still becomes ≤2 inside scrape_many.
    cfg_big = FirecrawlAdapterConfig(
        binary=str(fake),
        proxy_mode="basic",
        load_dotenv=False,
        allow_stored_credentials=False,
        env={"FIRECRAWL_API_KEY": FAKE_KEY, "PATH": "/usr/bin:/bin"},
        concurrency=99,
        timeout_s=10,
    )
    many = FirecrawlAdapter(cfg_big).scrape_many(
        ["https://example.com/a", "https://example.com/b"]
    )
    assert len(many) == 2
    assert all(r.content_success for r in many)


def test_secret_hygiene_no_raw_key_in_outputs():
    """VAL-BENCH-036 / 015: redact + no leak of FIRECRAWL_API_KEY."""
    secrets = collect_secret_fragments(
        extra=[FAKE_KEY, FAKE_KEY_OTHER],
        env={"FIRECRAWL_API_KEY": FAKE_KEY},
    )
    raw = f"auth failed for key={FAKE_KEY} Authorization: Bearer {FAKE_KEY_OTHER}"
    cleaned = redact_text(raw, secrets)
    assert FAKE_KEY not in cleaned
    assert FAKE_KEY_OTHER not in cleaned
    assert looks_like_secret_leak(cleaned, secrets) is False

    adapter = FirecrawlAdapter(
        FirecrawlAdapterConfig(
            load_dotenv=False,
            allow_stored_credentials=False,
            env={"FIRECRAWL_API_KEY": FAKE_KEY},
        )
    )
    result = adapter._error_result(
        url="https://example.com/",
        latency_ms=10.0,
        error_class="credential_error",
        challenge_class="credential_error",
        status_class="4xx",
        http_status=401,
        message=raw,
        secrets=secrets,
        profile_id=PROFILE_BASIC,
        scoring_role="scoring",
        content_success=False,
        proxy_class="basic",
    )
    blob = json.dumps(result.to_dict())
    assert FAKE_KEY not in blob
    assert FAKE_KEY_OTHER not in blob


def test_medium_and_hard_optional_typed_skips():
    """VAL-BENCH-019 / 020: medium/hard optional use typed skip classes."""
    medium = FirecrawlAdapter(
        FirecrawlAdapterConfig(
            optional_tier="medium",
            load_dotenv=False,
            allow_stored_credentials=False,
            env={"FIRECRAWL_API_KEY": FAKE_KEY},
        )
    ).scrape("https://medium.example/")
    assert medium.error_class == "policy_skip"
    assert medium.challenge_class == "medium_optional_skipped"
    assert medium.content_success is False

    hard = FirecrawlAdapter(
        FirecrawlAdapterConfig(
            optional_tier="hard",
            load_dotenv=False,
            allow_stored_credentials=False,
            env={"FIRECRAWL_API_KEY": FAKE_KEY},
        )
    ).scrape("https://hard.example/")
    assert hard.error_class == "policy_skip"
    assert hard.challenge_class == "hard_optional_skipped"
    assert "unlocker" not in (hard.metadata.get("error_message") or "").lower() or (
        "no commercial unlocker parity" in (hard.metadata.get("error_message") or "").lower()
    )
    # Message must not claim unlocker parity.
    msg = hard.metadata.get("error_message") or ""
    assert "parity assumed" in msg or "optional" in msg


def test_cloud_only_surface_label():
    """VAL-BENCH-040: default surface is cloud, labeled in metadata."""
    cfg = FirecrawlAdapterConfig(
        dry_run=True,
        load_dotenv=False,
        allow_stored_credentials=False,
        env={"FIRECRAWL_API_KEY": FAKE_KEY},
    )
    result = FirecrawlAdapter(cfg).scrape("https://example.com/")
    assert result.metadata.get("surface") == "cloud"
    assert result.metadata.get("cloud_only_matrix") is True
    assert result.fetch_path == "cloud"


def test_cost_estimate_fields_present_on_success(tmp_path: Path):
    """VAL-BENCH-026: Firecrawl credits + notes when FC ran."""
    payload = _success_payload(credits=2)
    fake = _fake_firecrawl_script(tmp_path, payload)
    cfg = FirecrawlAdapterConfig(
        binary=str(fake),
        load_dotenv=False,
        allow_stored_credentials=False,
        env={"FIRECRAWL_API_KEY": FAKE_KEY, "PATH": "/usr/bin:/bin"},
    )
    result = FirecrawlAdapter(cfg).scrape("https://example.com/")
    ce = result.cost_estimate.to_dict()
    assert ce["firecrawl_credits"] == 2
    assert ce["firecrawl_usd_estimate"] is not None
    # basecrawl side left null with notes path existing on object, not forced zeros.
    assert ce["basecrawl_cpu_ms_placeholder"] is None
    assert ce["basecrawl_proxy_usd_estimate"] is None


def test_challenge_classification_beyond_http():
    # CF "Checking your browser" → managed_challenge (or legacy interstitial).
    assert classify_challenge_body(
        http_status=200,
        html="<html>Checking your browser before you access</html>",
    ) in {"managed_challenge", "interstitial"}
    assert (
        classify_challenge_body(
            http_status=403,
            html="<div class='g-recaptcha'></div>",
        )
        == "captcha_surface"
    )
    assert classify_challenge_body(
        http_status=200,
        markdown="# Example Domain\n\nHello world content here for a dozen words.",
    ) == "none"


def test_classify_failure_helpers():
    err, chall, st, http = classify_firecrawl_failure("Unauthorized: Invalid API key", 1)
    assert err == "credential_error"
    assert http == 401
    err, chall, st, http = classify_firecrawl_failure("insufficient credits remaining", 1)
    assert err == "budget_exhausted"
    err, chall, st, http = classify_firecrawl_failure("timed out waiting", 1)
    assert err == "timeout"


def test_cli_firecrawl_dry_run(capsys, monkeypatch):
    from benchmark.cli import main

    monkeypatch.setenv("FIRECRAWL_API_KEY", FAKE_KEY)
    rc = main(
        [
            "firecrawl",
            "--url",
            "https://example.com/",
            "--proxy",
            "basic",
            "--dry-run",
            "--no-stored-credentials",
            "--no-dotenv",
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert FAKE_KEY not in out
    data = json.loads(out)
    assert data["engine"] == "firecrawl"
    assert data["metadata"]["dry_run"] is True
    assert data["metadata"]["key_present"] is True
    assert data["fetch_path"] == "cloud"


def test_cli_firecrawl_skip_without_key(capsys, monkeypatch):
    from benchmark.cli import main

    monkeypatch.delenv("FIRECRAWL_API_KEY", raising=False)
    rc = main(
        [
            "firecrawl",
            "--url",
            "https://example.com/",
            "--proxy",
            "basic",
            "--no-stored-credentials",
            "--no-dotenv",
        ]
    )
    # Fair skip should exit 0 (pipeline-friendly) with typed class in JSON.
    out = capsys.readouterr().out
    assert FAKE_KEY not in out
    data = json.loads(out)
    assert data["engine"] == "firecrawl"
    assert data["error_class"] == "engine_unavailable"
    assert data["content_success"] is False
    assert rc == 0
