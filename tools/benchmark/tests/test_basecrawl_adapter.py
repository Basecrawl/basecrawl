"""basecrawl adapter tests (VAL-BENCH-014, 015, 021 soft surface, 028 secondary).

Hermetic by default: uses fakes and offline proof fixtures. Soft dry-run does
**not** require live Oxylabs. Residential concurrency is process-local max 1.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from benchmark.basecrawl_adapter import (  # noqa: E402
    PROFILE_HARD,
    PROFILE_SOFT,
    BasecrawlAdapter,
    BasecrawlAdapterConfig,
    classify_challenge,
    map_basecrawl_error_kind,
    normalize_proof_file,
)
from benchmark.redact import (  # noqa: E402
    collect_secret_fragments,
    looks_like_secret_leak,
    redact_text,
)
from benchmark.residential_limit import (  # noqa: E402
    ResidentialConcurrencyError,
    reset_residential_slot_for_tests,
    residential_slot,
    residential_slot_held,
)
from benchmark.schema import validate_normalized_result  # noqa: E402
from benchmark.scorer import score_result  # noqa: E402

FIXTURES = ROOT / "fixtures"
PROOF_DIR = FIXTURES / "proofs"
ARTIFACTS = FIXTURES / "artifacts"


@pytest.fixture(autouse=True)
def _clear_residential_slot():
    reset_residential_slot_for_tests()
    yield
    reset_residential_slot_for_tests()


def test_hermetic_soft_dry_run_no_live_proxy_required():
    """Soft dry-run completes without BASECRAWL_LIVE_PROXY / Oxylabs."""
    cfg = BasecrawlAdapterConfig(
        path_mode="soft",
        profile_id=PROFILE_SOFT,
        dry_run=True,
        # Force env strip so residual proxy keys cannot affect dry-run.
        env={"BASECRAWL_LIVE_PROXY": "0"},
        load_dotenv=False,
    )
    result = BasecrawlAdapter(cfg).scrape("https://example.com/")
    errors = validate_normalized_result(result.to_dict())
    assert errors == [], errors
    assert result.engine == "basecrawl"
    assert result.profile_id == PROFILE_SOFT
    assert result.fetch_path == "direct"
    assert result.proxy_class == "direct"
    assert result.metadata.get("requires_live_proxy") is False
    assert result.metadata.get("dry_run") is True
    # Soft dry-run must not claim residential identity.
    assert result.proxy_class != "residential"


def test_hard_path_adapter_sets_chromium_fetch_path_on_proof(tmp_path: Path):
    """Hard path normalization captures fetch_path=chromium + challenge/status fields."""
    proof = {
        "version": 1,
        "request": {
            "method": "GET",
            "url": "https://quotes.toscrape.com/js/",
            "headers_hash": "a" * 64,
            "body_hash": "b" * 64,
            "request_hash": "c" * 64,
            "formats": ["markdown", "html", "links"],
        },
        "response": {
            "status_code": 200,
            "content_length": 1200,
            "body_truncated": False,
        },
        "result": {
            "formats_produced": {
                "markdown": "# Quotes\n\nAlbert Einstein said something thoughtful about life and the world.\n",
                "html": "<html><body><div class=\"quote\"><span>To be or not to be</span></div></body></html>",
                "links": {"links": ["https://quotes.toscrape.com/"]},
            },
            "result_hash": "d" * 64,
        },
        "egress": {
            "proxy_class": "direct",
            "fetch_path": "chromium",
            "fingerprint_seed": "e" * 64,
        },
        "attestation": {},
        "tls": {},
        "sdk_signature": {},
    }
    path = tmp_path / "hard-proof.json"
    path.write_text(json.dumps(proof), encoding="utf-8")
    cfg = BasecrawlAdapterConfig(
        path_mode="hard",
        profile_id=PROFILE_HARD,
        force_browser=True,
        js_target=True,
        expected_min_links=1,
    )
    result = normalize_proof_file(path, config=cfg)
    assert result.fetch_path == "chromium"
    assert result.proxy_class == "direct"
    assert result.challenge_class == "none"
    assert result.status_class == "2xx"
    assert result.http_status == 200
    assert result.content_success is True
    assert result.proof_present is True
    assert result.attestation_present is False
    # Secondary bonus only: can score proof_identity without replacing failed content.
    scored = score_result(result)
    assert scored.dimensions.proof_identity is not None
    assert scored.secondary_total is not None
    assert scored.secondary_total > 0
    # Core total still driven by content dimensions, not proof.
    assert "proof_identity" not in scored.dimensions.core_as_dict()


def test_challenge_classification_beyond_http_status():
    # CF "Checking your browser" → managed_challenge (or legacy interstitial).
    assert classify_challenge(
        http_status=200,
        html="<html>Checking your browser before you access the site</html>",
    ) in {"managed_challenge", "interstitial"}
    assert (
        classify_challenge(
            http_status=403,
            html="<div class='g-recaptcha'>captcha</div>",
            markdown="",
        )
        == "captcha_surface"
        or classify_challenge(
            http_status=403,
            html="<div class='g-recaptcha'>captcha</div>",
        )
        in {"captcha_surface", "challenge_blocked"}
    )
    assert (
        classify_challenge(
            http_status=403,
            markdown="",
            html="Access denied — bot detection active",
        )
        == "challenge_blocked"
    )
    assert classify_challenge(http_status=200, markdown="# Example Domain\n\nHello world content here for dozen words.") == "none"


def test_credential_error_fail_closed_not_content_success():
    """VAL-BENCH-014: proxy auth / class unavailable is credential_error, not success."""
    err_class, chall, status_class, http = map_basecrawl_error_kind(
        "proxy_class_unavailable",
        "required proxy class 'residential' unavailable: proxy authentication required",
        {"kind": "proxy_class_unavailable", "status_code": 407},
    )
    assert err_class == "credential_error"
    assert chall == "credential_error"
    assert status_class == "4xx"
    assert err_class != "none"

    adapter = BasecrawlAdapter(
        BasecrawlAdapterConfig(
            path_mode="residential",
            profile_id=PROFILE_HARD,
            proxy_class="residential",
            dry_run=False,
            load_dotenv=False,
            binary="/nonexistent/basecrawl-binary-that-does-not-exist",
        )
    )

    # FileNotFound would be engine_unavailable; exercise structured credential_error path.
    result = adapter._from_structured_error(
        url="https://example.com/",
        latency_ms=18.0,
        error_obj={
            "kind": "proxy_class_unavailable",
            "message": "required proxy class 'residential' unavailable: authentication failed",
            "status_code": 407,
        },
        secrets=["super-secret-pass-VALUE-999"],
        cfg=adapter.config,
        exit_code=1,
    )
    assert result.content_success is False
    assert result.error_class == "credential_error"
    assert result.challenge_class == "credential_error"
    payload = result.to_dict()
    assert "super-secret-pass-VALUE-999" not in json.dumps(payload)
    assert payload["content_success"] is False


def test_credential_error_redacts_secret_material():
    """VAL-BENCH-015: auth failure text never retains residual secrets."""
    password = "Oxylabs-Pass-Should-Never-Leak-42"
    proxy = f"http://user:{password}@pr.oxylabs.io:7777"
    secrets = collect_secret_fragments(
        extra=[password, proxy],
        env={"OXYLABS_PROXY_PASS": password, "BASECRAWL_HTTPS_PROXY": proxy},
    )
    raw = f"proxy transport error connecting via {proxy} password={password}"
    cleaned = redact_text(raw, secrets)
    assert password not in cleaned
    assert "user:Oxylabs" not in cleaned
    assert looks_like_secret_leak(cleaned, secrets) is False

    adapter = BasecrawlAdapter(
        BasecrawlAdapterConfig(path_mode="residential", profile_id=PROFILE_HARD, load_dotenv=False)
    )
    result = adapter._error_result(
        url="https://example.com/",
        latency_ms=12.0,
        error_class="credential_error",
        challenge_class="credential_error",
        status_class="4xx",
        http_status=407,
        message=raw,
        secrets=secrets,
        fetch_path="chromium",
        proxy_class="residential",
        content_success=False,
    )
    blob = json.dumps(result.to_dict())
    assert password not in blob
    assert "pr.oxylabs.io" not in blob or "[REDACTED]" in blob


def test_residential_concurrent_limit_enforced():
    """VAL-BENCH-011 surface for adapter: max 1 concurrent residential dial."""
    assert residential_slot_held() is False
    events: List[str] = []
    errors: List[BaseException] = []

    def holder():
        try:
            with residential_slot(owner="t1", blocking=False):
                events.append("held")
                time.sleep(0.25)
                events.append("released")
        except BaseException as exc:  # pragma: no cover
            errors.append(exc)

    def contender():
        time.sleep(0.05)
        try:
            with residential_slot(owner="t2", blocking=False):
                events.append("contender-entered")  # must not happen
        except ResidentialConcurrencyError as exc:
            events.append("refused")
            errors.append(exc)

    t1 = threading.Thread(target=holder)
    t2 = threading.Thread(target=contender)
    t1.start()
    t2.start()
    t1.join(timeout=2)
    t2.join(timeout=2)
    assert "held" in events
    assert "refused" in events
    assert "contender-entered" not in events
    assert any(isinstance(e, ResidentialConcurrencyError) for e in errors)

    # Adapter-level: second residential scrape while slot held → policy_skip.
    cfg = BasecrawlAdapterConfig(
        path_mode="residential",
        profile_id=PROFILE_HARD,
        proxy_class="residential",
        proxy_url="http://user:pass@127.0.0.1:1",
        force_browser=True,
        load_dotenv=False,
        dry_run=False,
        binary="/usr/bin/true",  # will not emit scrape JSON; used only for slot path test
        timeout_s=1,
    )
    adapter = BasecrawlAdapter(cfg)
    with residential_slot(owner="external-hold", blocking=False):
        r = adapter.scrape("https://example.com/")
        assert r.error_class == "policy_skip"
        assert r.challenge_class == "hard_optional_skipped"
        assert r.content_success is False
        assert r.proxy_class == "residential"


def test_soft_adapter_subprocess_with_fake_binary(tmp_path: Path):
    """Soft adapter works against a fake basecrawl that prints a ScrapeProof."""
    proof = {
        "version": 1,
        "request": {
            "method": "GET",
            "url": "https://example.com/",
            "headers_hash": "a" * 64,
            "body_hash": "b" * 64,
            "request_hash": "c" * 64,
            "formats": ["markdown", "html", "links"],
        },
        "response": {"status_code": 200, "content_length": 400, "body_truncated": False},
        "result": {
            "formats_produced": {
                "markdown": (
                    "# Example Domain\n\nThis domain is for use in illustrative examples "
                    "in documents without coordination.\n"
                ),
                "html": "<html><body><h1>Example Domain</h1><a href='https://iana.org/domains/example'>x</a></body></html>",
                "links": {"links": ["https://iana.org/domains/example"]},
            },
            "result_hash": "f" * 64,
        },
        "egress": {"proxy_class": "direct", "fetch_path": "direct"},
        "attestation": {},
        "tls": {},
        "sdk_signature": {},
    }
    fake = tmp_path / "fake-basecrawl"
    # Shell script that ignores args and prints JSON proof.
    fake.write_text(
        "#!/bin/sh\n" + "cat <<'EOF'\n" + json.dumps(proof) + "\nEOF\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    cfg = BasecrawlAdapterConfig(
        binary=str(fake),
        path_mode="soft",
        profile_id=PROFILE_SOFT,
        no_js=True,
        load_dotenv=False,
        timeout_s=5,
        expected_min_links=1,
    )
    result = BasecrawlAdapter(cfg).scrape("https://example.com/")
    errors = validate_normalized_result(result.to_dict(), require_body_payload=True)
    assert errors == [], errors
    assert result.content_success is True
    assert result.fetch_path == "direct"
    assert result.proxy_class == "direct"
    assert result.challenge_class == "none"
    assert result.proof_present is True
    assert result.error_class == "none"
    assert "markdown" in result.formats_produced
    scored = score_result(result)
    assert scored.dimensions.content_success == 1.0
    # Secondary is basecrawl-only.
    assert scored.dimensions.proof_identity is not None
    assert scored.dimensions.proof_identity >= 0.5


def test_proof_identity_secondary_cannot_win_core_alone():
    """VAL-BENCH-028: proof present does not invent content success when body fails."""
    proof = {
        "version": 1,
        "request": {"url": "https://example.com/", "formats": ["markdown"]},
        "response": {"status_code": 403},
        "result": {
            "formats_produced": {
                "markdown": "",
                "html": "<html>Access denied — bot detection active</html>",
            },
            "result_hash": "1" * 64,
        },
        "egress": {"proxy_class": "direct", "fetch_path": "chromium"},
        "attestation": {"quote": "deadbeef"},
    }
    cfg = BasecrawlAdapterConfig(path_mode="hard", profile_id=PROFILE_HARD, force_browser=True)
    path = Path("/tmp")  # unused — call internal
    adapter = BasecrawlAdapter(cfg)
    result = adapter._from_scrapepoof(
        url="https://example.com/",
        latency_ms=500.0,
        proof=proof,
        secrets=[],
        cfg=cfg,
    )
    assert result.content_success is False
    assert result.challenge_class == "challenge_blocked"
    assert result.attestation_present is True
    scored = score_result(result)
    assert scored.dimensions.content_success == 0.0
    assert scored.dimensions.proof_identity is not None
    assert scored.dimensions.proof_identity >= 0.5
    # Core total must remain low — proof cannot rescue content failure.
    assert scored.core_total < 0.55


def test_cli_basecrawl_dry_run(capsys):
    from benchmark.cli import main

    rc = main(
        [
            "basecrawl",
            "--url",
            "https://example.com/",
            "--path-mode",
            "soft",
            "--dry-run",
        ]
    )
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["engine"] == "basecrawl"
    assert data["fetch_path"] == "direct"
    assert data["metadata"]["dry_run"] is True
    assert data["metadata"]["requires_live_proxy"] is False


def test_soft_child_env_strips_ambient_proxy_for_direct_path():
    """Soft/P1 and hard-without-residential must not inherit ambient Oxylabs env."""
    proxy = "http://user:pass@example-proxy.test:7777"
    soft = BasecrawlAdapter(
        BasecrawlAdapterConfig(
            path_mode="soft",
            profile_id=PROFILE_SOFT,
            load_dotenv=False,
            proxy_url=None,
            proxy_class=None,
            env={
                "BASECRAWL_HTTPS_PROXY": proxy,
                "HTTPS_PROXY": proxy,
                "PATH": "/usr/bin",
            },
        )
    )._child_env()
    assert "BASECRAWL_HTTPS_PROXY" not in soft
    assert "HTTPS_PROXY" not in soft

    hard = BasecrawlAdapter(
        BasecrawlAdapterConfig(
            path_mode="hard",
            profile_id=PROFILE_HARD,
            force_browser=True,
            load_dotenv=False,
            env={
                "BASECRAWL_HTTPS_PROXY": proxy,
                "PATH": "/usr/bin",
            },
        )
    )._child_env()
    assert "BASECRAWL_HTTPS_PROXY" not in hard

    # Residential keeps ambient commercial proxy material available.
    child_r = BasecrawlAdapter(
        BasecrawlAdapterConfig(
            path_mode="residential",
            profile_id=PROFILE_HARD,
            load_dotenv=False,
            proxy_class="residential",
            env={
                "BASECRAWL_HTTPS_PROXY": proxy,
                "PATH": "/usr/bin",
            },
        )
    )._child_env()
    assert child_r.get("BASECRAWL_HTTPS_PROXY", "").startswith("http://")
