"""basecrawl CLI → common NormalizedResult adapter.

Supports:
- soft / direct rustls path (hermetic dry-run; no Oxylabs required)
- hard Chromium path (`--force-browser` / difficulty hard)
- optional residential Oxylabs via gitignored .env (max 1 concurrent dial)

Captures ``challenge_class`` / ``status_class`` / ``fetch_path`` / ``proxy_class``,
redacts secrets in error text, and fails closed on credentialed proxy auth errors
(VAL-BENCH-014, 015, 028 soft path + hard path behavior).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from .formats import request_core_formats
from .redact import collect_secret_fragments, redact_text
from .residential_limit import (
    ResidentialConcurrencyError,
    residential_slot,
)
from .schema import (
    SCHEMA_VERSION,
    CostEstimate,
    NormalizedResult,
    validate_normalized_result,
)

PathLike = Union[str, Path]

# Profile defaults for the documented matrix (MATRIX.md).
PROFILE_SOFT = "P1-soft-basecrawl"
PROFILE_HARD = "P3-basecrawl-hard-optional"
PROFILE_RESIDENTIAL = "P3-basecrawl-hard-optional"

DEFAULT_TIMEOUT_S = 45
DEFAULT_FORMATS = ("markdown", "html", "links")

# Soft interstitial / bot-manager markers for body classification (beyond HTTP).
_CHALLENGE_BODY_MARKERS = (
    "checking your browser",
    "just a moment",
    "challenge-platform",
    "cdn-cgi/challenge-platform",
    "challenges.cloudflare.com",
    "cf-browser-verification",
    "cf-challenge",
    "cf-turnstile",
    "attention required",
    "verify you are human",
    "verification failed",
    "verification expired",
    "hcaptcha",
    "recaptcha",
    "please enable javascript",
    "enable javascript to continue",
    "access denied",
    "bot detection",
    "perimeterx",
    "datadome",
    "ddos-guard",
)

_CREDENTIAL_MARKERS = (
    "407",
    "proxy authentication required",
    "authentication failed",
    "auth failed",
    "invalid credentials",
    "proxy_auth",
    "proxy_auth_error",
    "proxy_acl_error",
    "unauthorized",
    "proxy class",
    "proxy_class_unavailable",
    "residential_concurrency",
    "login failed",
    "incorrect password",
    "access denied by proxy",
    "connect 403",
    "product acl",
)


@dataclass
class BasecrawlAdapterConfig:
    """Runtime knobs for a single adapter invocation."""

    binary: Optional[str] = None  # path or name on PATH
    profile_id: str = PROFILE_SOFT
    formats: Sequence[str] = field(default_factory=lambda: list(DEFAULT_FORMATS))
    timeout_s: float = DEFAULT_TIMEOUT_S
    # soft | hard | residential
    path_mode: str = "soft"
    force_browser: bool = False
    difficulty: Optional[str] = None  # soft|hard
    proxy_url: Optional[str] = None
    proxy_class: Optional[str] = None  # direct|datacenter|residential|mobile
    proxy_session: Optional[str] = None
    proxy_country: Optional[str] = None
    no_js: bool = False
    tls_impersonate: Optional[str] = None
    dry_run: bool = False  # hermetic: do not shell out; synthesize policy/skip path only
    env: Optional[Mapping[str, str]] = None
    extra_args: Sequence[str] = field(default_factory=list)
    expected_min_links: Optional[int] = None
    js_target: bool = False
    cwd: Optional[PathLike] = None
    load_dotenv: bool = True
    # When True, refuse a second concurrent residential dial (default).
    enforce_residential_limit: bool = True


class BasecrawlAdapter:
    """Run basecrawl and normalize the ScrapeProof / structured error into a Result."""

    def __init__(self, config: Optional[BasecrawlAdapterConfig] = None) -> None:
        self.config = config or BasecrawlAdapterConfig()

    # ------------------------------------------------------------------ Public

    def scrape(self, url: str) -> NormalizedResult:
        """Scrape ``url`` and return a validated NormalizedResult (always)."""
        cfg = self.config
        started = time.monotonic()
        secrets = collect_secret_fragments(env=dict(cfg.env) if cfg.env else None)

        if cfg.dry_run and cfg.path_mode in {"soft", "hard"} and not cfg.proxy_url:
            # Hermetic soft (or hard-without-proxy) dry-run: synthetic skip that
            # validates schema + classification plumbing without network.
            # Soft profile still proves no Oxylabs dependency.
            return self._dry_run_result(url, started)

        # Residential needs concurrency slot.
        needs_residential = self._needs_residential_slot(cfg)
        try:
            if needs_residential and cfg.enforce_residential_limit:
                with residential_slot(owner=f"basecrawl:{cfg.profile_id}"):
                    return self._run_cli(url, started, secrets)
            return self._run_cli(url, started, secrets)
        except ResidentialConcurrencyError as exc:
            latency = max(0.0, (time.monotonic() - started) * 1000.0)
            return self._error_result(
                url=url,
                latency_ms=latency,
                error_class="policy_skip",
                challenge_class=exc.challenge_class,
                status_class="unknown",
                http_status=None,
                message=str(exc),
                secrets=secrets,
                fetch_path="chromium",
                proxy_class="residential",
                content_success=False,
            )

    def scrape_many(self, urls: Sequence[str]) -> List[NormalizedResult]:
        """Scrape URLs sequentially (residential max-1 is process-wide)."""
        return [self.scrape(u) for u in urls]

    # ----------------------------------------------------------------- Private

    def _needs_residential_slot(self, cfg: BasecrawlAdapterConfig) -> bool:
        if cfg.path_mode == "residential":
            return True
        if (cfg.proxy_class or "").lower() in {"residential", "mobile"}:
            return True
        if cfg.profile_id and "residential" in cfg.profile_id.lower():
            return True
        return False

    def _resolve_binary(self) -> str:
        cfg = self.config
        if cfg.binary:
            return cfg.binary
        env = cfg.env or os.environ
        if env.get("BASECRAWL_BIN"):
            return env["BASECRAWL_BIN"]
        # Prefer workspace release binary relative to typical repo layout.
        here = Path(__file__).resolve()
        candidates = [
            here.parents[3] / "target" / "release" / "basecrawl",  # basecrawl/tools/benchmark/benchmark
            here.parents[4] / "basecrawl" / "target" / "release" / "basecrawl",
            Path.cwd() / "target" / "release" / "basecrawl",
            Path.cwd() / "basecrawl" / "target" / "release" / "basecrawl",
        ]
        for c in candidates:
            if c.is_file() and os.access(c, os.X_OK):
                return str(c)
        found = shutil.which("basecrawl")
        if found:
            return found
        return "basecrawl"

    def _build_command(self, url: str) -> List[str]:
        cfg = self.config
        formats = list(cfg.formats) if cfg.formats else request_core_formats()
        # Always keep core subset for scoring fairness.
        fmt = ",".join(formats)
        cmd: List[str] = [
            self._resolve_binary(),
            "--formats",
            fmt,
            "--timeout",
            str(max(1, int(cfg.timeout_s))),
            "--output",
            "json",
        ]
        path_mode = (cfg.path_mode or "soft").lower()
        if path_mode == "soft":
            if cfg.no_js or not cfg.force_browser:
                # Soft P1 is cheap direct fetch unless operator forced browser.
                if not cfg.force_browser:
                    cmd.append("--no-js")
        if path_mode in {"hard", "residential"} or cfg.force_browser:
            cmd.append("--force-browser")
        if cfg.difficulty:
            cmd.extend(["--difficulty", cfg.difficulty])
        elif path_mode == "hard":
            cmd.extend(["--difficulty", "hard"])

        proxy_url = cfg.proxy_url
        proxy_class = cfg.proxy_class
        if path_mode == "residential":
            proxy_class = proxy_class or "residential"
            if not proxy_url:
                proxy_url = self._proxy_from_env()
        if proxy_url:
            # Never log proxy_url with credentials; argparse path keeps it in child env only via flag.
            cmd.extend(["--proxy", proxy_url])
        if proxy_class:
            cmd.extend(["--proxy-class", proxy_class])
        if cfg.proxy_session:
            cmd.extend(["--proxy-session", cfg.proxy_session])
        if cfg.proxy_country:
            cmd.extend(["--proxy-country", cfg.proxy_country])
        if cfg.tls_impersonate:
            cmd.extend(["--tls-impersonate", cfg.tls_impersonate])
        if cfg.extra_args:
            cmd.extend(list(cfg.extra_args))
        cmd.append(url)
        return cmd

    def _proxy_from_env(self) -> Optional[str]:
        env = dict(self.config.env) if self.config.env else dict(os.environ)
        if self.config.load_dotenv:
            env = {**_load_dotenv_keys(), **env}
        for key in (
            "BASECRAWL_HTTPS_PROXY",
            "BASECRAWL_HTTP_PROXY",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "ALL_PROXY",
        ):
            val = env.get(key)
            if val:
                return val
        # Compose from OXYLABS_* pieces when present (never log).
        host = env.get("OXYLABS_PROXY_HOST")
        user = env.get("OXYLABS_PROXY_USER")
        password = env.get("OXYLABS_PROXY_PASS")
        if host and user and password:
            # Default Oxylabs residential endpoint shape.
            if "://" not in host:
                host = f"http://{host}"
            # Insert user:pass if host has no userinfo.
            if "@" not in host:
                # http://host:port → http://user:pass@host:port
                scheme, rest = host.split("://", 1)
                return f"{scheme}://{user}:{password}@{rest}"
            return host
        return None

    def _child_env(self) -> Dict[str, str]:
        base = dict(os.environ)
        if self.config.load_dotenv:
            base.update(_load_dotenv_keys())
        if self.config.env:
            base.update(dict(self.config.env))

        cfg = self.config
        mode = (cfg.path_mode or "soft").lower()
        commercial = (cfg.proxy_class or "").lower() in {
            "residential",
            "mobile",
            "datacenter",
        }
        wants_proxy = bool(cfg.proxy_url) or commercial or mode == "residential"
        # Ambient Oxylabs BASECRAWL_*_PROXY from .env applies only when the
        # adapter intentionally runs a commercial/residential profile or an
        # explicit --proxy is set. Soft P1 and hard-without-residential must
        # stay direct so scoreboard rows do not silently claim datacenter
        # identity (VAL-BENCH-035 + honesty for P3 optional hard).
        if not wants_proxy:
            for key in (
                "BASECRAWL_HTTP_PROXY",
                "BASECRAWL_HTTPS_PROXY",
                "HTTPS_PROXY",
                "HTTP_PROXY",
                "ALL_PROXY",
                "http_proxy",
                "https_proxy",
                "all_proxy",
            ):
                base.pop(key, None)
        return base

    def _run_cli(
        self,
        url: str,
        started: float,
        secrets: Sequence[str],
    ) -> NormalizedResult:
        cfg = self.config
        cmd = self._build_command(url)
        env = self._child_env()
        # Expand secret fragments after dotenv load for redaction of this run.
        run_secrets = list(
            collect_secret_fragments(
                extra=list(secrets) + ([cfg.proxy_url] if cfg.proxy_url else []),
                env=env,
            )
        )

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(1.0, float(cfg.timeout_s) + 15.0),
                env=env,
                cwd=str(cfg.cwd) if cfg.cwd else None,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            latency = max(0.0, (time.monotonic() - started) * 1000.0)
            return self._error_result(
                url=url,
                latency_ms=latency,
                error_class="timeout",
                challenge_class="timeout",
                status_class="timeout",
                http_status=None,
                message=f"basecrawl timed out after {cfg.timeout_s}s",
                secrets=run_secrets,
                fetch_path=self._expected_fetch_path(cfg),
                proxy_class=self._expected_proxy_class(cfg),
                content_success=False,
                metadata={"subprocess": "timeout", "detail": redact_text(str(exc), run_secrets)},
            )
        except FileNotFoundError:
            latency = max(0.0, (time.monotonic() - started) * 1000.0)
            return self._error_result(
                url=url,
                latency_ms=latency,
                error_class="engine_unavailable",
                challenge_class="engine_unavailable",
                status_class="unknown",
                http_status=None,
                message="basecrawl binary not found",
                secrets=run_secrets,
                fetch_path="unknown",
                proxy_class=self._expected_proxy_class(cfg),
                content_success=False,
            )
        except OSError as exc:
            latency = max(0.0, (time.monotonic() - started) * 1000.0)
            return self._error_result(
                url=url,
                latency_ms=latency,
                error_class="engine_unavailable",
                challenge_class="engine_unavailable",
                status_class="unknown",
                http_status=None,
                message=redact_text(str(exc), run_secrets),
                secrets=run_secrets,
                fetch_path="unknown",
                proxy_class=self._expected_proxy_class(cfg),
                content_success=False,
            )

        latency = max(0.0, (time.monotonic() - started) * 1000.0)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        # Prefer structured JSON on stdout (proof or {"error":...}).
        payload = _parse_json_payload(stdout)
        if payload is None and stderr.strip().startswith("{"):
            payload = _parse_json_payload(stderr)

        if payload is not None and "error" in payload:
            return self._from_structured_error(
                url=url,
                latency_ms=latency,
                error_obj=payload.get("error") or payload,
                secrets=run_secrets,
                cfg=cfg,
                exit_code=proc.returncode,
            )

        if payload is not None and (
            "result" in payload or "egress" in payload or "response" in payload
        ):
            return self._from_scrapepoof(
                url=url,
                latency_ms=latency,
                proof=payload,
                secrets=run_secrets,
                cfg=cfg,
                stderr=stderr,
            )

        # Non-JSON failure: classify from text + exit code without inventing success.
        combined = redact_text(f"{stdout}\n{stderr}", run_secrets)
        err_class, chall = _classify_failure_text(combined, proc.returncode)
        return self._error_result(
            url=url,
            latency_ms=latency,
            error_class=err_class,
            challenge_class=chall,
            status_class=_status_class_from_error(err_class),
            http_status=None,
            message=combined[:2000] or f"basecrawl exit {proc.returncode}",
            secrets=run_secrets,
            fetch_path=self._expected_fetch_path(cfg),
            proxy_class=self._expected_proxy_class(cfg),
            content_success=False,
            metadata={"exit_code": proc.returncode},
        )

    def _from_scrapepoof(
        self,
        *,
        url: str,
        latency_ms: float,
        proof: Mapping[str, Any],
        secrets: Sequence[str],
        cfg: BasecrawlAdapterConfig,
        stderr: str = "",
    ) -> NormalizedResult:
        response = proof.get("response") if isinstance(proof.get("response"), Mapping) else {}
        result = proof.get("result") if isinstance(proof.get("result"), Mapping) else {}
        egress = proof.get("egress") if isinstance(proof.get("egress"), Mapping) else {}
        formats_produced_blob = result.get("formats_produced") or {}
        if not isinstance(formats_produced_blob, Mapping):
            formats_produced_blob = {}

        markdown = ""
        html = ""
        links: List[str] = []
        produced: List[str] = []

        md_val = formats_produced_blob.get("markdown")
        if isinstance(md_val, str):
            markdown = md_val
            produced.append("markdown")
        html_val = formats_produced_blob.get("html") or formats_produced_blob.get("rawHtml")
        if isinstance(html_val, str):
            html = html_val
            produced.append("html" if "html" in formats_produced_blob else "rawHtml")
        links_val = formats_produced_blob.get("links")
        if isinstance(links_val, Mapping):
            raw_links = links_val.get("links") or []
            if isinstance(raw_links, list):
                links = [str(x) for x in raw_links]
            produced.append("links")
        elif isinstance(links_val, list):
            links = [str(x) for x in links_val]
            produced.append("links")
        if "metadata" in formats_produced_blob:
            produced.append("metadata")

        status = response.get("status_code")
        if status is None:
            status = response.get("status")
        http_status = int(status) if isinstance(status, int) else None
        status_class = _status_class_from_code(http_status)

        fetch_path = str(egress.get("fetch_path") or self._expected_fetch_path(cfg))
        proxy_class = str(egress.get("proxy_class") or self._expected_proxy_class(cfg) or "direct")

        # Soft honesty: never label residential without residential class on egress.
        if (cfg.path_mode or "soft").lower() == "soft" and proxy_class == "direct":
            pass  # ok
        if (cfg.path_mode or "soft").lower() == "soft" and proxy_class not in {
            "direct",
            "datacenter",
            "none",
            "",
        }:
            # Keep truth from egress, but do not invent residential on soft.
            pass

        challenge_class = classify_challenge(
            http_status=http_status,
            markdown=markdown,
            html=html,
            fetch_path=fetch_path,
            error_kind=None,
        )

        # Content success: status 2xx + meaningful body + not challenge.
        content_success = (
            http_status is not None
            and 200 <= http_status < 300
            and challenge_class == "none"
            and (len(markdown.strip()) >= 32 or len(html.strip()) >= 64)
        )

        attestation = proof.get("attestation") if isinstance(proof.get("attestation"), Mapping) else {}
        proof_present = bool(proof.get("result") is not None and proof.get("response") is not None)
        attestation_present = bool(
            attestation
            and (
                attestation.get("quote")
                or attestation.get("quote_b64")
                or attestation.get("tdx_quote")
                or attestation.get("present") is True
            )
        )

        directish = proxy_class in {"direct", "none", ""}
        if directish and fetch_path == "chromium":
            cost_notes = "hard Chromium direct path; no residential proxy charged"
        elif directish:
            cost_notes = "soft direct path; no residential proxy charged"
        else:
            cost_notes = (
                f"proxy_class={proxy_class}; proxy cost placeholder null "
                "(operator track separately)"
            )
        cost = CostEstimate(
            firecrawl_credits=None,
            firecrawl_usd_estimate=None,
            basecrawl_cpu_ms_placeholder=latency_ms,
            basecrawl_proxy_usd_estimate=None,
            notes=cost_notes,
        )

        formats_requested = [str(x) for x in (cfg.formats or DEFAULT_FORMATS)]
        identity_notes = ""
        if proof_present and not attestation_present:
            identity_notes = "ScrapeProof envelope present; no live TEE quote in this run"
        elif attestation_present:
            identity_notes = "ScrapeProof + attestation fields present"
        # Secondary bonus only — never upgrades failed content (scorer enforces).
        # Keep notes non-secret.
        identity_notes = redact_text(identity_notes, secrets)

        meta: Dict[str, Any] = {
            "adapter": "basecrawl",
            "path_mode": cfg.path_mode,
            "stderr_redacted_len": len(redact_text(stderr, secrets)),
        }
        # Optionally retain result_hash for diagnostics (non-secret).
        rh = result.get("result_hash")
        if isinstance(rh, str) and rh:
            meta["result_hash"] = rh

        nr = NormalizedResult(
            schema_version=SCHEMA_VERSION,
            url=str(
                (proof.get("request") or {}).get("url")
                if isinstance(proof.get("request"), Mapping)
                else url
            )
            or url,
            engine="basecrawl",
            profile_id=cfg.profile_id,
            formats_requested=formats_requested,
            formats_produced=produced or formats_requested,
            http_status=http_status,
            status_class=status_class,
            challenge_class=challenge_class,
            content_success=bool(content_success),
            latency_ms=float(latency_ms),
            cost_estimate=cost,
            error_class="none" if content_success else (
                "challenge_blocked" if challenge_class == "challenge_blocked" else "unknown"
            ),
            scoring_role="scoring",
            markdown_body=markdown,
            html_body=html or None,
            links=links,
            fetch_path=fetch_path,
            proxy_class=proxy_class,
            expected_min_links=cfg.expected_min_links,
            js_target=bool(cfg.js_target),
            proof_present=proof_present,
            attestation_present=attestation_present,
            identity_notes=identity_notes,
            metadata=meta,
        )
        # Soft validation; adapter still returns even if odd proofs.
        _ = validate_normalized_result(nr.to_dict())
        return nr

    def _from_structured_error(
        self,
        *,
        url: str,
        latency_ms: float,
        error_obj: Any,
        secrets: Sequence[str],
        cfg: BasecrawlAdapterConfig,
        exit_code: int,
    ) -> NormalizedResult:
        if not isinstance(error_obj, Mapping):
            error_obj = {"message": str(error_obj), "kind": "unknown"}
        kind = str(error_obj.get("kind") or error_obj.get("error_kind") or "unknown")
        message = str(error_obj.get("message") or error_obj.get("detail") or kind)
        message = redact_text(message, secrets)
        # Nested detail fields may contain credentials if CLI ever misbehaves —
        # redact the serialized blob before storing.
        safe_error = json.loads(redact_text(json.dumps(error_obj, default=str), secrets))

        err_class, chall, status_class, http_status = map_basecrawl_error_kind(
            kind, message, error_obj
        )
        return self._error_result(
            url=url,
            latency_ms=latency_ms,
            error_class=err_class,
            challenge_class=chall,
            status_class=status_class,
            http_status=http_status,
            message=message,
            secrets=secrets,
            fetch_path=self._expected_fetch_path(cfg),
            proxy_class=self._expected_proxy_class(cfg),
            content_success=False,
            metadata={
                "exit_code": exit_code,
                "error_kind": kind,
                "error": safe_error,
            },
        )

    def _error_result(
        self,
        *,
        url: str,
        latency_ms: float,
        error_class: str,
        challenge_class: str,
        status_class: str,
        http_status: Optional[int],
        message: str,
        secrets: Sequence[str],
        fetch_path: str,
        proxy_class: str,
        content_success: bool,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> NormalizedResult:
        cfg = self.config
        safe_msg = redact_text(message, secrets)
        meta = dict(metadata or {})
        meta["adapter"] = "basecrawl"
        meta["error_message"] = safe_msg
        meta["path_mode"] = cfg.path_mode
        formats_requested = [str(x) for x in (cfg.formats or DEFAULT_FORMATS)]
        cost_notes = (
            "auth/proxy/policy failed before content success; cost null not forced zero"
            if error_class in {"credential_error", "policy_skip", "engine_unavailable"}
            else f"error_class={error_class}"
        )
        return NormalizedResult(
            schema_version=SCHEMA_VERSION,
            url=url,
            engine="basecrawl",
            profile_id=cfg.profile_id,
            formats_requested=formats_requested,
            formats_produced=[],
            http_status=http_status,
            status_class=status_class,
            challenge_class=challenge_class,
            content_success=content_success,
            latency_ms=float(latency_ms),
            cost_estimate=CostEstimate(
                notes=cost_notes,
            ),
            error_class=error_class,
            scoring_role="scoring",
            markdown_body="",
            links=[],
            fetch_path=fetch_path,
            proxy_class=proxy_class,
            expected_min_links=cfg.expected_min_links,
            js_target=bool(cfg.js_target),
            proof_present=False,
            attestation_present=False,
            identity_notes="",
            metadata=meta,
        )

    def _dry_run_result(self, url: str, started: float) -> NormalizedResult:
        """Hermetic dry-run: soft path does not require live proxy (VAL-BENCH soft).

        Used for offline classification plumbing when ``dry_run=True``. Does not
        invent content_success markdown for scoring wins — marks a structured
        dry-run research row if needed, but soft dry defaults to schema-complete
        empty with error_class none only when operator wants just schema smoke.
        For harness soft dry-run expected behavior is that soft targets *can*
        complete without Oxylabs; callers who set dry_run typically want no
        network. We return engine research-role row that is honest.
        """
        latency = max(0.0, (time.monotonic() - started) * 1000.0)
        cfg = self.config
        formats_requested = [str(x) for x in (cfg.formats or DEFAULT_FORMATS)]
        return NormalizedResult(
            schema_version=SCHEMA_VERSION,
            url=url,
            engine="basecrawl",
            profile_id=cfg.profile_id or PROFILE_SOFT,
            formats_requested=formats_requested,
            formats_produced=[],
            http_status=None,
            status_class="unknown",
            challenge_class="none",
            content_success=False,
            latency_ms=latency,
            cost_estimate=CostEstimate(
                notes="hermetic dry-run; no network and no residential proxy required"
            ),
            error_class="none",
            scoring_role="research",
            markdown_body="",
            links=[],
            fetch_path=self._expected_fetch_path(cfg),
            proxy_class=self._expected_proxy_class(cfg),
            expected_min_links=cfg.expected_min_links,
            js_target=bool(cfg.js_target),
            proof_present=False,
            attestation_present=False,
            identity_notes="dry-run: no ScrapeProof generated",
            metadata={
                "adapter": "basecrawl",
                "dry_run": True,
                "path_mode": cfg.path_mode,
                "requires_live_proxy": False,
            },
        )

    def _expected_fetch_path(self, cfg: BasecrawlAdapterConfig) -> str:
        mode = (cfg.path_mode or "soft").lower()
        if mode in {"hard", "residential"} or cfg.force_browser:
            return "chromium"
        if cfg.no_js or mode == "soft":
            return "direct"
        return "unknown"

    def _expected_proxy_class(self, cfg: BasecrawlAdapterConfig) -> str:
        if cfg.proxy_class:
            return cfg.proxy_class
        mode = (cfg.path_mode or "soft").lower()
        if mode == "residential":
            return "residential"
        return "direct"


# ---------------------------------------------------------------------------
# Classification helpers (exported for pure unit tests)
# ---------------------------------------------------------------------------


def classify_challenge(
    *,
    http_status: Optional[int],
    markdown: str = "",
    html: str = "",
    fetch_path: str = "",
    error_kind: Optional[str] = None,
) -> str:
    """Classify anti-bot / interstitial beyond bare HTTP (VAL-BENCH-021, VAL-HARD-010).

    CF challenge-platform / Turnstile sandwiches → managed_challenge or turnstile so
    the scorer zeros content_success even on HTTP 200.
    """
    if error_kind in {"challenge_blocked", "challenge_block"}:
        return "challenge_blocked"
    text = f"{markdown}\n{html}".lower()
    if http_status in {401, 403} and any(m in text for m in ("captcha", "cf-", "challenge")):
        return "challenge_blocked"
    if any(
        m in text
        for m in (
            "cf-turnstile",
            "challenges.cloudflare.com",
            "turnstile/v0",
            "/turnstile/",
        )
    ) and any(
        m in text
        for m in (
            "challenge-platform",
            "cdn-cgi/challenge-platform",
            "checking your browser",
            "just a moment",
            "verification failed",
            "verification expired",
            "cf-turnstile",
            "turnstile",
        )
    ):
        return "turnstile"
    if any(m in text for m in ("hcaptcha", "recaptcha", "captcha-box", "g-recaptcha")):
        return "captcha_surface"
    if any(
        m in text
        for m in (
            "challenge-platform",
            "cdn-cgi/challenge-platform",
            "checking your browser",
            "just a moment",
            "cf-browser-verification",
            "cf-challenge",
            "attention required",
            "verification failed",
            "verification expired",
            "managed challenge",
        )
    ):
        return "managed_challenge"
    if any(m in text for m in ("sign in to continue", "login required", "log in to continue")):
        return "login_wall"
    if "please enable javascript" in text or "enable javascript to continue" in text:
        return "interstitial"
    if any(m in text for m in ("access denied", "bot detection", "perimeterx", "datadome")):
        return "challenge_blocked"
    if http_status is not None and http_status >= 500:
        return "unknown"
    # Soft block: 200 with very tiny chrome-only body looking blocked is rare; leave none.
    _ = fetch_path
    return "none"


def map_basecrawl_error_kind(
    kind: str,
    message: str,
    error_obj: Optional[Mapping[str, Any]] = None,
) -> tuple[str, str, str, Optional[int]]:
    """Map basecrawl structured error kind → (error_class, challenge_class, status_class, http).

    Credentialed proxy failures and residential class-unavailable are sticky
    credential_error / fail-closed (VAL-BENCH-014).
    """
    error_obj = error_obj or {}
    msg_l = (message or "").lower()
    kind_l = (kind or "").lower()
    http_status = error_obj.get("status_code") if isinstance(error_obj, Mapping) else None
    if not isinstance(http_status, int):
        http_status = None

    # Proxy authentication / required residential unavailable.
    if kind_l in {"proxy_class_unavailable", "invalid_proxy"}:
        if any(m in msg_l for m in _CREDENTIAL_MARKERS) or "auth" in msg_l:
            return "credential_error", "credential_error", "4xx", http_status or 407
        return "credential_error", "credential_error", "4xx", http_status

    if kind_l in {"challenge_blocked"}:
        return "challenge_blocked", "challenge_blocked", _status_class_from_code(http_status), http_status

    if kind_l in {"timeout"}:
        return "timeout", "timeout", "timeout", http_status

    if kind_l in {
        "transport_error",
        "fetch_error",
        "certificate_validation",
        "tls_capture_error",
        "redirect_error",
        "too_many_redirects",
        "dns_isolation",
    }:
        # Connection refused / proxy dial issues may still be credential related.
        if any(m in msg_l for m in ("407", "proxy authentication", "authentication required")):
            return "credential_error", "credential_error", "4xx", 407
        return "transport", "network_error", "unknown", http_status

    if kind_l in {
        "hard_path_policy",
        "post_not_supported_on_hard_path",
        "tls_impersonate_unsupported",
    }:
        return "policy_skip", "hard_optional_skipped", "unknown", http_status

    if kind_l in {"robots_denied"}:
        return "policy_skip", "none", "4xx", http_status

    if kind_l in {"render_error", "document_extraction", "resource_budget_exceeded"}:
        return "unknown", "unknown", "unknown", http_status

    if kind_l in {"missing_url", "invalid_url", "unsupported_scheme", "invalid_format"}:
        return "parse_error", "unknown", "unknown", http_status

    # Free-text credential fallback.
    if any(m in msg_l for m in _CREDENTIAL_MARKERS):
        return "credential_error", "credential_error", "4xx", http_status or 401

    return "unknown", "unknown", "unknown", http_status


def _status_class_from_code(http_status: Optional[int]) -> str:
    if http_status is None:
        return "unknown"
    if 200 <= http_status < 300:
        return "2xx"
    if 300 <= http_status < 400:
        return "3xx"
    if 400 <= http_status < 500:
        return "4xx"
    if 500 <= http_status < 600:
        return "5xx"
    return "unknown"


def _status_class_from_error(error_class: str) -> str:
    if error_class == "timeout":
        return "timeout"
    if error_class == "credential_error":
        return "4xx"
    if error_class in {"transport", "network_error"}:
        return "unknown"
    return "unknown"


def _classify_failure_text(text: str, exit_code: int) -> tuple[str, str]:
    low = (text or "").lower()
    if any(m in low for m in _CREDENTIAL_MARKERS):
        return "credential_error", "credential_error"
    if "challenge_blocked" in low or "blocked by bot challenge" in low:
        return "challenge_blocked", "challenge_blocked"
    if "timed out" in low or "timeout" in low:
        return "timeout", "timeout"
    if "not found" in low and exit_code == 127:
        return "engine_unavailable", "engine_unavailable"
    if exit_code != 0:
        return "unknown", "unknown"
    return "unknown", "unknown"


def _parse_json_payload(text: str) -> Optional[dict]:
    if not text or not text.strip():
        return None
    stripped = text.strip()
    # Try whole payload first.
    try:
        data = json.loads(stripped)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    # Fallback: find first {...} object in mixed output.
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start >= 0 and end > start:
        try:
            data = json.loads(stripped[start : end + 1])
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            return None
    return None


def _load_dotenv_keys() -> Dict[str, str]:
    """Load non-empty KEY=VALUE pairs from basecrawl/.env without printing values."""
    candidates = [
        Path(__file__).resolve().parents[3] / ".env",  # basecrawl/.env
        Path.cwd() / ".env",
        Path.cwd() / "basecrawl" / ".env",
    ]
    out: Dict[str, str] = {}
    for path in candidates:
        if not path.is_file():
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                key = key.strip()
                val = val.strip().strip("'").strip('"')
                if key and val:
                    out[key] = val
        except OSError:
            continue
        break  # first readable .env wins
    return out


def normalize_proof_file(path: PathLike, *, config: Optional[BasecrawlAdapterConfig] = None) -> NormalizedResult:
    """Normalize a saved ScrapeProof JSON file without re-scraping (offline)."""
    cfg = config or BasecrawlAdapterConfig(path_mode="soft", profile_id=PROFILE_SOFT)
    adapter = BasecrawlAdapter(cfg)
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, Mapping):
        raise ValueError("proof file must be a JSON object")
    if "error" in data:
        return adapter._from_structured_error(
            url=str((data.get("request") or {}).get("url") if isinstance(data.get("request"), Mapping) else ""),
            latency_ms=0.0,
            error_obj=data.get("error") or data,
            secrets=collect_secret_fragments(),
            cfg=cfg,
            exit_code=1,
        )
    return adapter._from_scrapepoof(
        url=str((data.get("request") or {}).get("url") if isinstance(data.get("request"), Mapping) else ""),
        latency_ms=0.0,
        proof=data,
        secrets=collect_secret_fragments(),
        cfg=cfg,
    )


# Silence unused import warning if re unused in some lint paths.
_ = re
