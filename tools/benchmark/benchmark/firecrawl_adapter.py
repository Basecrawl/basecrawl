"""Firecrawl CLI/API → common NormalizedResult adapter.

Supports:
- formats markdown / html (or rawHtml) / links
- proxy ``basic`` | ``auto`` (default scoring) and ``enhanced`` (non-scoring ceiling)
- skip typed ``engine_unavailable`` when no API key / unauthenticated
- fail-closed ``credential_error`` on 401/403 / invalid key
- credits + latency on cost_estimate, concurrency ≤ 2 (account limit)

Secrets: ``FIRECRAWL_API_KEY`` from gitignored ``.env`` / process env only;
never passed on argv (`-k`), never written into artifacts (VAL-BENCH-016, 036).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from .firecrawl_limit import (
    FIRECRAWL_MAX_CONCURRENCY,
    FirecrawlConcurrencyError,
    firecrawl_slot,
)
from .formats import request_core_formats
from .redact import collect_secret_fragments, redact_text
from .schema import (
    SCHEMA_VERSION,
    CostEstimate,
    NormalizedResult,
    validate_normalized_result,
)

PathLike = Union[str, Path]

PROFILE_BASIC = "P2-soft-firecrawl-basic"
PROFILE_ENHANCED = "P4-firecrawl-enhanced-ceiling"

DEFAULT_TIMEOUT_S = 60.0
DEFAULT_FORMATS = ("markdown", "html", "links")
# Rough list-price placeholder for cost_estimate when credits are known.
DEFAULT_USD_PER_CREDIT = 0.00099

# Cloud-only matrix note (VAL-BENCH-040): this adapter targets Firecrawl cloud.
SURFACE_LABEL = "cloud"

_CREDENTIAL_MARKERS = (
    "401",
    "403",
    "unauthorized",
    "invalid api key",
    "invalid key",
    "api key is invalid",
    "authentication failed",
    "not authenticated",
    "forbidden",
    "missing api key",
    "unauthenticated",
    "auth failed",
    "please login",
    "please log in",
)

_BUDGET_MARKERS = (
    "insufficient credits",
    "out of credits",
    "credit limit",
    "payment required",
    "402",
    "plan limit",
    "rate limit exceeded",
    "quota exceeded",
    "billing",
    "upgrade your plan",
    "not enough credits",
)

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
)


@dataclass
class FirecrawlAdapterConfig:
    """Runtime knobs for a single Firecrawl adapter invocation."""

    binary: Optional[str] = None  # path or name on PATH (default: firecrawl)
    profile_id: Optional[str] = None
    formats: Sequence[str] = field(default_factory=lambda: list(DEFAULT_FORMATS))
    timeout_s: float = DEFAULT_TIMEOUT_S
    # basic | auto | enhanced  (proxy flag for CLI --proxy)
    proxy_mode: str = "basic"
    dry_run: bool = False
    env: Optional[Mapping[str, str]] = None
    extra_args: Sequence[str] = field(default_factory=list)
    expected_min_links: Optional[int] = None
    js_target: bool = False
    cwd: Optional[PathLike] = None
    load_dotenv: bool = True
    # Prefer 1; hard ceiling is FIRECRAWL_MAX_CONCURRENCY (2).
    concurrency: int = 1
    # When True, acquire firecrawl_slot around each live scrape.
    enforce_concurrency_limit: bool = True
    # Treat missing key as typed engine_unavailable rather than crash.
    skip_if_no_key: bool = True
    # When False, ignore ~/.config/firecrawl-cli stored login for auth detection
    # and strip any residual store-based auth from child by clearing home.
    allow_stored_credentials: bool = True
    # Optional medium/hard optional skip labels (matrix policy).
    optional_tier: Optional[str] = None  # None | medium | hard
    usd_per_credit: float = DEFAULT_USD_PER_CREDIT
    api_url: Optional[str] = None  # override API base (never log with secrets)
    # Force self-host label only if explicitly set (default cloud matrix).
    surface: str = SURFACE_LABEL


class FirecrawlAdapter:
    """Run Firecrawl CLI/scrape and normalize into a common Result."""

    def __init__(self, config: Optional[FirecrawlAdapterConfig] = None) -> None:
        self.config = config or FirecrawlAdapterConfig()

    # ------------------------------------------------------------------ Public

    def scrape(self, url: str) -> NormalizedResult:
        """Scrape ``url`` and return a validated NormalizedResult (always)."""
        cfg = self.config
        started = time.monotonic()
        secrets = self._collect_run_secrets()

        profile_id = self._profile_id(cfg)
        scoring_role = self._scoring_role(cfg)

        # Optional medium / hard matrix policy skip without dialing.
        if cfg.optional_tier == "medium":
            return self._skip_result(
                url=url,
                started=started,
                error_class="policy_skip",
                challenge_class="medium_optional_skipped",
                message="medium target optional; typed skip (not CI-required)",
                secrets=secrets,
                profile_id=profile_id,
                scoring_role=scoring_role,
            )
        if cfg.optional_tier == "hard":
            return self._skip_result(
                url=url,
                started=started,
                error_class="policy_skip",
                challenge_class="hard_optional_skipped",
                message=(
                    "hard target optional; typed skip — no commercial unlocker "
                    "parity assumed"
                ),
                secrets=secrets,
                profile_id=profile_id,
                scoring_role=scoring_role,
            )

        has_key = self._has_api_key()
        if not has_key and cfg.skip_if_no_key:
            return self._skip_result(
                url=url,
                started=started,
                error_class="engine_unavailable",
                challenge_class="engine_unavailable",
                message=(
                    "FIRECRAWL_API_KEY missing and no usable Firecrawl auth; "
                    "fair skip (not content failure)"
                ),
                secrets=secrets,
                profile_id=profile_id,
                scoring_role=scoring_role,
            )

        if cfg.dry_run:
            return self._dry_run_result(
                url=url,
                started=started,
                secrets=secrets,
                has_key=has_key,
                profile_id=profile_id,
                scoring_role=scoring_role,
            )

        try:
            if cfg.enforce_concurrency_limit:
                with firecrawl_slot(
                    owner=f"firecrawl:{profile_id}:{id(self)}",
                    blocking=True,
                    timeout=max(1.0, float(cfg.timeout_s) + 30.0),
                ):
                    return self._run_cli(url, started, secrets, profile_id, scoring_role)
            return self._run_cli(url, started, secrets, profile_id, scoring_role)
        except FirecrawlConcurrencyError as exc:
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
                profile_id=profile_id,
                scoring_role=scoring_role,
                content_success=False,
                proxy_class=self._proxy_label(cfg),
            )

    def scrape_many(self, urls: Sequence[str]) -> List[NormalizedResult]:
        """Scrape multiple URLs with concurrency ≤ plan limit (≤2).

        Never opens a fire-all unbounded pool (VAL-BENCH-012).
        """
        cfg = self.config
        if not urls:
            return []
        # Cap worker pool at min(requested concurrency, 2).
        workers = max(1, min(int(cfg.concurrency or 1), FIRECRAWL_MAX_CONCURRENCY))
        if workers == 1 or len(urls) == 1:
            return [self.scrape(u) for u in urls]

        results: Dict[int, NormalizedResult] = {}
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self.scrape, u): i for i, u in enumerate(urls)}
            for fut in as_completed(futures):
                idx = futures[fut]
                try:
                    results[idx] = fut.result()
                except Exception as exc:  # pragma: no cover - defensive
                    secrets = self._collect_run_secrets()
                    results[idx] = self._error_result(
                        url=urls[idx],
                        latency_ms=0.0,
                        error_class="unknown",
                        challenge_class="unknown",
                        status_class="unknown",
                        http_status=None,
                        message=redact_text(str(exc), secrets),
                        secrets=secrets,
                        profile_id=self._profile_id(cfg),
                        scoring_role=self._scoring_role(cfg),
                        content_success=False,
                        proxy_class=self._proxy_label(cfg),
                    )
        return [results[i] for i in range(len(urls))]

    def has_credentials(self) -> bool:
        """Public helper: True when adapter expects Firecrawl to be runnable."""
        return self._has_api_key()

    # ----------------------------------------------------------------- Private

    def _profile_id(self, cfg: FirecrawlAdapterConfig) -> str:
        if cfg.profile_id:
            return cfg.profile_id
        mode = (cfg.proxy_mode or "basic").lower()
        if mode == "enhanced":
            return PROFILE_ENHANCED
        return PROFILE_BASIC

    def _scoring_role(self, cfg: FirecrawlAdapterConfig) -> str:
        mode = (cfg.proxy_mode or "basic").lower()
        if mode == "enhanced":
            return "ceiling"
        return "scoring"

    def _proxy_label(self, cfg: FirecrawlAdapterConfig) -> str:
        mode = (cfg.proxy_mode or "basic").lower()
        if mode in {"basic", "auto", "enhanced"}:
            return mode
        return "basic"

    def _collect_run_secrets(self) -> List[str]:
        cfg = self.config
        env = self._merged_env(include_key=True)
        extras: List[str] = []
        key = env.get("FIRECRAWL_API_KEY")
        if key:
            extras.append(key)
        return list(collect_secret_fragments(extra=extras, env=env))

    def _has_api_key(self) -> bool:
        env = self._merged_env(include_key=True)
        key = (env.get("FIRECRAWL_API_KEY") or "").strip()
        if key:
            return True
        if self.config.allow_stored_credentials and _stored_credentials_present():
            return True
        return False

    def _merged_env(self, *, include_key: bool = True) -> Dict[str, str]:
        base = dict(os.environ)
        if self.config.load_dotenv:
            base.update(_load_dotenv_keys())
        if self.config.env:
            base.update(dict(self.config.env))
        if not include_key:
            base.pop("FIRECRAWL_API_KEY", None)
        return base

    def _child_env(self, secrets: Sequence[str]) -> Dict[str, str]:
        """Child process env: key present when available, never logged."""
        env = self._merged_env(include_key=True)
        # Ensure HOME is set so CLI can read stored credentials when allowed.
        if not self.config.allow_stored_credentials:
            # Isolate stored credentials so skip/auth tests are deterministic.
            # Keep a writable temp-like fake home without firecrawl config.
            env["HOME"] = env.get("BENCHMARK_FAKE_HOME") or "/tmp/benchmark-no-firecrawl-home"
            Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
            # Drop key if intentionally testing missing-key path: already stripped
            # when secrets/env lack it.
        # Never leak proxy Oxylabs secrets into FC child unnecessarily.
        # Keep FIRECRAWL_API_KEY only via env (not argv).
        _ = secrets
        return env

    def _resolve_binary(self) -> str:
        cfg = self.config
        if cfg.binary:
            return cfg.binary
        env = cfg.env or os.environ
        if env.get("FIRECRAWL_BIN"):
            return env["FIRECRAWL_BIN"]
        found = shutil.which("firecrawl")
        if found:
            return found
        # common bun install path
        bun = Path.home() / ".bun" / "bin" / "firecrawl"
        if bun.is_file() and os.access(bun, os.X_OK):
            return str(bun)
        return "firecrawl"

    def _build_command(self, url: str) -> List[str]:
        cfg = self.config
        formats = list(cfg.formats) if cfg.formats else request_core_formats()
        # Fair core subset; do not attach extract/interact by default.
        fmt = ",".join(formats)
        proxy = self._proxy_label(cfg)
        cmd: List[str] = [
            self._resolve_binary(),
            "scrape",
            "-u",
            url,
            "-f",
            fmt,
            "--json",
            "--pretty",
            "--proxy",
            proxy,
            # Prefer --timing on stderr for latency diagnostics only.
            "--timing",
        ]
        if cfg.api_url:
            cmd.extend(["--api-url", cfg.api_url])
        # Intentionally do NOT add -k / --api-key on argv (VAL-BENCH-036).
        if cfg.extra_args:
            cmd.extend(list(cfg.extra_args))
        return cmd

    def _run_cli(
        self,
        url: str,
        started: float,
        secrets: Sequence[str],
        profile_id: str,
        scoring_role: str,
    ) -> NormalizedResult:
        cfg = self.config
        cmd = self._build_command(url)
        env = self._child_env(secrets)
        run_secrets = list(
            collect_secret_fragments(
                extra=list(secrets),
                env=env,
            )
        )
        # Double-check argv never contains the raw key.
        safe_cmd = [redact_text(c, run_secrets) for c in cmd]
        if any(looks_like_key_arg(c) for c in cmd):
            # Fail closed if someone wired --api-key into extra_args with a secret.
            return self._error_result(
                url=url,
                latency_ms=max(0.0, (time.monotonic() - started) * 1000.0),
                error_class="policy_skip",
                challenge_class="credential_error",
                status_class="unknown",
                http_status=None,
                message="refusing firecrawl invocation that embeds API key on argv",
                secrets=run_secrets,
                profile_id=profile_id,
                scoring_role=scoring_role,
                content_success=False,
                proxy_class=self._proxy_label(cfg),
                metadata={"command_redacted": safe_cmd},
            )

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(1.0, float(cfg.timeout_s) + 20.0),
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
                message=f"firecrawl timed out after {cfg.timeout_s}s",
                secrets=run_secrets,
                profile_id=profile_id,
                scoring_role=scoring_role,
                content_success=False,
                proxy_class=self._proxy_label(cfg),
                metadata={
                    "subprocess": "timeout",
                    "detail": redact_text(str(exc), run_secrets),
                    "command_redacted": safe_cmd,
                },
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
                message="firecrawl binary not found",
                secrets=run_secrets,
                profile_id=profile_id,
                scoring_role=scoring_role,
                content_success=False,
                proxy_class=self._proxy_label(cfg),
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
                profile_id=profile_id,
                scoring_role=scoring_role,
                content_success=False,
                proxy_class=self._proxy_label(cfg),
            )

        latency = max(0.0, (time.monotonic() - started) * 1000.0)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        # Prefer duration from CLI timing if present.
        timing_ms = _parse_timing_ms(stderr) or _parse_timing_ms(stdout)
        if timing_ms is not None:
            latency = float(timing_ms)

        payload = _parse_json_payload(stdout)
        if payload is None and stderr.strip().startswith("{"):
            payload = _parse_json_payload(stderr)

        combined = redact_text(f"{stdout}\n{stderr}", run_secrets)
        if payload is not None:
            # API error shapes or success documents.
            return self._from_payload(
                url=url,
                latency_ms=latency,
                payload=payload,
                secrets=run_secrets,
                profile_id=profile_id,
                scoring_role=scoring_role,
                cfg=cfg,
                exit_code=proc.returncode,
                stderr_redacted=redact_text(stderr, run_secrets),
                command_redacted=safe_cmd,
            )

        # Non-JSON failure path.
        err_class, chall, status_class, http_status = classify_firecrawl_failure(
            combined, proc.returncode
        )
        return self._error_result(
            url=url,
            latency_ms=latency,
            error_class=err_class,
            challenge_class=chall,
            status_class=status_class,
            http_status=http_status,
            message=combined[:2000] or f"firecrawl exit {proc.returncode}",
            secrets=run_secrets,
            profile_id=profile_id,
            scoring_role=scoring_role,
            content_success=False,
            proxy_class=self._proxy_label(cfg),
            metadata={"exit_code": proc.returncode, "command_redacted": safe_cmd},
        )

    def _from_payload(
        self,
        *,
        url: str,
        latency_ms: float,
        payload: Mapping[str, Any],
        secrets: Sequence[str],
        profile_id: str,
        scoring_role: str,
        cfg: FirecrawlAdapterConfig,
        exit_code: int,
        stderr_redacted: str = "",
        command_redacted: Optional[List[str]] = None,
    ) -> NormalizedResult:
        # Error shapes: {"error": "..."} / {"success": false, ...}
        err_text, err_code = _extract_error_fields(payload)
        if err_text or err_code:
            err_class, chall, status_class, http_status = classify_firecrawl_failure(
                f"{err_text}\ncode={err_code}", exit_code
            )
            if err_code in {401, 403} or (
                isinstance(err_code, int) and err_code in {401, 403}
            ):
                err_class, chall, status_class, http_status = (
                    "credential_error",
                    "credential_error",
                    "4xx",
                    int(err_code),
                )
            return self._error_result(
                url=url,
                latency_ms=latency_ms,
                error_class=err_class,
                challenge_class=chall,
                status_class=status_class,
                http_status=http_status,
                message=redact_text(err_text or f"firecrawl error code={err_code}", secrets),
                secrets=secrets,
                profile_id=profile_id,
                scoring_role=scoring_role,
                content_success=False,
                proxy_class=self._proxy_label(cfg),
                metadata={
                    "exit_code": exit_code,
                    "error_code": err_code,
                    "command_redacted": command_redacted or [],
                },
            )

        # Success document (CLI --json): top-level markdown/html/links + metadata.
        data = payload
        # Some SDK envelopes wrap under data/result.
        if "data" in payload and isinstance(payload["data"], Mapping):
            data = payload["data"]  # type: ignore[assignment]
        elif "result" in payload and isinstance(payload["result"], Mapping):
            data = payload["result"]  # type: ignore[assignment]

        markdown = ""
        html = ""
        links: List[str] = []
        produced: List[str] = []

        md_val = data.get("markdown")
        if isinstance(md_val, str):
            markdown = md_val
            produced.append("markdown")
        html_val = data.get("html") or data.get("rawHtml")
        if isinstance(html_val, str):
            html = html_val
            produced.append("html" if "html" in data else "rawHtml")
        links_val = data.get("links")
        if isinstance(links_val, list):
            links = [str(x) for x in links_val]
            produced.append("links")
        elif isinstance(links_val, Mapping):
            raw = links_val.get("links") or []
            if isinstance(raw, list):
                links = [str(x) for x in raw]
            produced.append("links")

        meta = data.get("metadata") if isinstance(data.get("metadata"), Mapping) else {}
        status = meta.get("statusCode") if meta else None
        if status is None:
            status = data.get("statusCode") or data.get("status_code") or data.get("status")
        http_status = int(status) if isinstance(status, int) else None
        status_class = _status_class_from_code(http_status)

        proxy_used = str(meta.get("proxyUsed") or self._proxy_label(cfg)).lower()
        credits = meta.get("creditsUsed")
        if credits is None:
            credits = data.get("creditsUsed") or data.get("credits_used")
        credits_f = float(credits) if isinstance(credits, (int, float)) else None

        # Enhanced / auto-fallback-to-enhanced is non-scoring ceiling.
        role = scoring_role
        mode = self._proxy_label(cfg)
        if proxy_used == "enhanced" or mode == "enhanced":
            role = "ceiling"
            if not profile_id or profile_id == PROFILE_BASIC:
                profile_id = PROFILE_ENHANCED
        identity_notes = ""
        if role == "ceiling":
            identity_notes = (
                "Firecrawl enhanced (or auto→enhanced) is a non-scoring parity "
                "ceiling; not blended into core soft/basic leaderboard"
            )

        challenge_class = classify_challenge_body(
            http_status=http_status,
            markdown=markdown,
            html=html,
        )

        content_success = (
            http_status is not None
            and 200 <= http_status < 300
            and challenge_class == "none"
            and (len(markdown.strip()) >= 32 or len(html.strip()) >= 64)
        )

        # Surface labeling: cloud vs self-host (VAL-BENCH-040).
        surface = (cfg.surface or SURFACE_LABEL).lower()
        if surface != "cloud" and surface != "self-host":
            surface = SURFACE_LABEL

        usd = None
        notes = f"proxy={proxy_used}; surface={surface}"
        if credits_f is not None:
            usd = float(credits_f) * float(cfg.usd_per_credit)
            notes = (
                f"proxy={proxy_used}; surface={surface}; "
                f"{credits_f:g} credit(s) × {cfg.usd_per_credit} USD/credit estimate"
            )
        else:
            notes = (
                f"proxy={proxy_used}; surface={surface}; "
                "credits not reported; firecrawl_credits null (not forced zero)"
            )
        if role == "ceiling":
            notes += "; scoring_role=ceiling non-parity"

        cost = CostEstimate(
            firecrawl_credits=credits_f,
            firecrawl_usd_estimate=usd,
            basecrawl_cpu_ms_placeholder=None,
            basecrawl_proxy_usd_estimate=None,
            notes=notes,
        )

        formats_requested = [str(x) for x in (cfg.formats or DEFAULT_FORMATS)]
        source_url = (
            str(meta.get("sourceURL") or meta.get("url") or url) if meta else url
        )

        meta_out: Dict[str, Any] = {
            "adapter": "firecrawl",
            "proxy_mode_requested": mode,
            "proxy_used": proxy_used,
            "surface": surface,
            "cloud_only_matrix": surface == "cloud",
            "stderr_redacted_len": len(stderr_redacted or ""),
            "command_redacted": command_redacted or [],
            "exit_code": exit_code,
        }
        scrape_id = meta.get("scrapeId") if meta else None
        if isinstance(scrape_id, str) and scrape_id:
            meta_out["scrape_id"] = scrape_id
        concurrency_limited = meta.get("concurrencyLimited") if meta else None
        if concurrency_limited is not None:
            meta_out["concurrency_limited"] = bool(concurrency_limited)
        if role == "ceiling":
            meta_out["non_scoring_ceiling"] = True
            meta_out["parity_claim"] = False

        error_class = (
            "none"
            if content_success
            else (
                "challenge_blocked"
                if challenge_class == "challenge_blocked"
                else "unknown"
            )
        )

        nr = NormalizedResult(
            schema_version=SCHEMA_VERSION,
            url=source_url or url,
            engine="firecrawl",
            profile_id=profile_id,
            formats_requested=formats_requested,
            formats_produced=produced or [],
            http_status=http_status,
            status_class=status_class,
            challenge_class=challenge_class,
            content_success=bool(content_success),
            latency_ms=float(latency_ms),
            cost_estimate=cost,
            error_class=error_class,
            scoring_role=role,
            markdown_body=markdown,
            html_body=html or None,
            links=links,
            fetch_path="cloud" if surface == "cloud" else "self-host",
            proxy_class=proxy_used if proxy_used in {"basic", "auto", "enhanced"} else mode,
            expected_min_links=cfg.expected_min_links,
            js_target=bool(cfg.js_target),
            proof_present=False,
            attestation_present=False,
            identity_notes=redact_text(identity_notes, secrets),
            metadata=meta_out,
        )
        _ = validate_normalized_result(nr.to_dict())
        return nr

    def _dry_run_result(
        self,
        *,
        url: str,
        started: float,
        secrets: Sequence[str],
        has_key: bool,
        profile_id: str,
        scoring_role: str,
    ) -> NormalizedResult:
        """Hermetic dry-run: schema-complete FC row without network dial.

        When key is available (or stored login allowed) this still does not
        dial; it proves the soft adapter entry is runnable offline and labels
        cloud surface correctly (VAL-BENCH-003).
        """
        latency = max(0.0, (time.monotonic() - started) * 1000.0)
        cfg = self.config
        formats_requested = [str(x) for x in (cfg.formats or DEFAULT_FORMATS)]
        mode = self._proxy_label(cfg)
        role = scoring_role
        if mode == "enhanced":
            role = "ceiling"
        notes = (
            f"hermetic dry-run; key_present={bool(has_key)}; "
            f"proxy={mode}; surface={cfg.surface or SURFACE_LABEL}; "
            "no network and no Firecrawl credits charged"
        )
        meta = {
            "adapter": "firecrawl",
            "dry_run": True,
            "key_present": bool(has_key),
            "proxy_mode_requested": mode,
            "surface": cfg.surface or SURFACE_LABEL,
            "cloud_only_matrix": (cfg.surface or SURFACE_LABEL) == "cloud",
            "requires_live_fc": False,
        }
        if role == "ceiling":
            meta["non_scoring_ceiling"] = True
            meta["parity_claim"] = False
        return NormalizedResult(
            schema_version=SCHEMA_VERSION,
            url=url,
            engine="firecrawl",
            profile_id=profile_id,
            formats_requested=formats_requested,
            formats_produced=[],
            http_status=None,
            status_class="unknown",
            challenge_class="none",
            content_success=False,
            latency_ms=latency,
            cost_estimate=CostEstimate(
                firecrawl_credits=None,
                firecrawl_usd_estimate=None,
                notes=notes,
            ),
            error_class="none",
            scoring_role=role,
            markdown_body="",
            links=[],
            fetch_path="cloud",
            proxy_class=mode,
            expected_min_links=cfg.expected_min_links,
            js_target=bool(cfg.js_target),
            proof_present=False,
            attestation_present=False,
            identity_notes=(
                "dry-run: no Firecrawl scrape; enhanced rows are non-scoring ceiling"
                if role == "ceiling"
                else "dry-run: no Firecrawl scrape"
            ),
            metadata=meta,
        )

    def _skip_result(
        self,
        *,
        url: str,
        started: float,
        error_class: str,
        challenge_class: str,
        message: str,
        secrets: Sequence[str],
        profile_id: str,
        scoring_role: str,
    ) -> NormalizedResult:
        latency = max(0.0, (time.monotonic() - started) * 1000.0)
        return self._error_result(
            url=url,
            latency_ms=latency,
            error_class=error_class,
            challenge_class=challenge_class,
            status_class="unknown",
            http_status=None,
            message=message,
            secrets=secrets,
            profile_id=profile_id,
            scoring_role=scoring_role,
            content_success=False,
            proxy_class=self._proxy_label(self.config),
            metadata={
                "adapter": "firecrawl",
                "fair_skip": True,
                "key_present": self._has_api_key(),
                "surface": self.config.surface or SURFACE_LABEL,
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
        profile_id: str,
        scoring_role: str,
        content_success: bool,
        proxy_class: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> NormalizedResult:
        cfg = self.config
        safe_msg = redact_text(message, secrets)
        meta = dict(metadata or {})
        meta.setdefault("adapter", "firecrawl")
        meta["error_message"] = safe_msg
        meta.setdefault("surface", cfg.surface or SURFACE_LABEL)
        meta.setdefault("cloud_only_matrix", (cfg.surface or SURFACE_LABEL) == "cloud")
        # Refuse secret leakage in metadata recursively via text redaction.
        meta = json.loads(redact_text(json.dumps(meta, default=str), secrets))
        formats_requested = [str(x) for x in (cfg.formats or DEFAULT_FORMATS)]
        cost_notes = (
            "auth/budget/policy failed before scrape; cost null not forced zero"
            if error_class
            in {"credential_error", "budget_exhausted", "engine_unavailable", "policy_skip"}
            else f"error_class={error_class}"
        )
        return NormalizedResult(
            schema_version=SCHEMA_VERSION,
            url=url,
            engine="firecrawl",
            profile_id=profile_id,
            formats_requested=formats_requested,
            formats_produced=[],
            http_status=http_status,
            status_class=status_class,
            challenge_class=challenge_class,
            content_success=content_success,
            latency_ms=float(latency_ms),
            cost_estimate=CostEstimate(notes=cost_notes),
            error_class=error_class,
            scoring_role=scoring_role if scoring_role in {"scoring", "ceiling", "research"} else "scoring",
            markdown_body="",
            links=[],
            fetch_path="cloud",
            proxy_class=proxy_class,
            expected_min_links=cfg.expected_min_links,
            js_target=bool(cfg.js_target),
            proof_present=False,
            attestation_present=False,
            identity_notes=(
                "non-scoring ceiling profile"
                if scoring_role == "ceiling"
                else ""
            ),
            metadata=meta,
        )


# ---------------------------------------------------------------------------
# Classification helpers (exported for pure unit tests)
# ---------------------------------------------------------------------------


def classify_challenge_body(
    *,
    http_status: Optional[int],
    markdown: str = "",
    html: str = "",
) -> str:
    """Classify anti-bot / interstitial beyond bare HTTP.

    CF challenge-platform / Turnstile sandwiches are labeled managed_challenge
    or turnstile so hard scoring can zero content_success (VAL-HARD-002/004/006).
    """
    text = f"{markdown}\n{html}".lower()
    # Turnstile residual before generic captcha (taostats probe often embeds both).
    if any(
        m in text
        for m in (
            "cf-turnstile",
            "challenges.cloudflare.com",
            "turnstile/v0",
            "/turnstile/",
            "data-sitekey",
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
    if http_status in {401, 403} and any(m in text for m in ("captcha", "cf-", "challenge")):
        return "challenge_blocked"
    if http_status is not None and http_status >= 500:
        return "unknown"
    return "none"


def classify_firecrawl_failure(
    text: str,
    exit_code: int = 1,
) -> tuple[str, str, str, Optional[int]]:
    """Map CLI/API failure text → (error_class, challenge_class, status_class, http)."""
    low = (text or "").lower()
    if any(m in low for m in _BUDGET_MARKERS):
        return "budget_exhausted", "budget_exhausted", "4xx", 402
    if any(m in low for m in _CREDENTIAL_MARKERS):
        http = 401
        if "403" in low or "forbidden" in low:
            http = 403
        return "credential_error", "credential_error", "4xx", http
    if "timed out" in low or "timeout" in low:
        return "timeout", "timeout", "timeout", None
    if "not found" in low and exit_code == 127:
        return "engine_unavailable", "engine_unavailable", "unknown", None
    if "enoent" in low or "no such file" in low:
        return "engine_unavailable", "engine_unavailable", "unknown", None
    if exit_code != 0:
        return "unknown", "unknown", "unknown", None
    return "unknown", "unknown", "unknown", None


def looks_like_key_arg(arg: str) -> bool:
    """True if an argv token itself looks like an embedded API key assignment."""
    if not arg:
        return False
    low = arg.lower()
    if low.startswith("--api-key=") or low.startswith("-k="):
        return True
    # Bare fc-... tokens are suspicious when used as standalone args after -k,
    # but we cannot know position here; the adapter refuses --api-key= forms.
    return False


def normalize_firecrawl_payload(
    payload: Mapping[str, Any],
    *,
    config: Optional[FirecrawlAdapterConfig] = None,
    url: str = "",
    latency_ms: float = 0.0,
) -> NormalizedResult:
    """Normalize a saved Firecrawl JSON payload without re-scraping (offline)."""
    cfg = config or FirecrawlAdapterConfig(proxy_mode="basic", profile_id=PROFILE_BASIC)
    adapter = FirecrawlAdapter(cfg)
    secrets = adapter._collect_run_secrets()
    return adapter._from_payload(
        url=url
        or str(
            ((payload.get("metadata") or {}) if isinstance(payload.get("metadata"), Mapping) else {}).get(
                "sourceURL"
            )
            or ""
        ),
        latency_ms=latency_ms,
        payload=payload,
        secrets=secrets,
        profile_id=adapter._profile_id(cfg),
        scoring_role=adapter._scoring_role(cfg),
        cfg=cfg,
        exit_code=0,
    )


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


def _extract_error_fields(payload: Mapping[str, Any]) -> tuple[str, Optional[int]]:
    if payload.get("success") is False:
        err = payload.get("error") or payload.get("message") or "success=false"
        code = payload.get("statusCode") or payload.get("code") or payload.get("status")
        return str(err), int(code) if isinstance(code, int) else None
    if "error" in payload and not any(
        k in payload for k in ("markdown", "html", "links", "metadata", "data")
    ):
        err = payload.get("error")
        if isinstance(err, Mapping):
            msg = str(err.get("message") or err.get("error") or err)
            code = err.get("statusCode") or err.get("code") or err.get("status")
            return msg, int(code) if isinstance(code, int) else None
        code = payload.get("statusCode") or payload.get("code")
        return str(err), int(code) if isinstance(code, int) else None
    return "", None


def _parse_timing_ms(text: str) -> Optional[float]:
    if not text:
        return None
    # Timing: { "duration": "37560ms", ... } or duration ms number.
    m = re.search(r'"duration"\s*:\s*"?(\d+(?:\.\d+)?)(ms)?"?', text)
    if m:
        return float(m.group(1))
    m = re.search(r"duration[=: ]+(\d+(?:\.\d+)?)\s*ms", text, flags=re.I)
    if m:
        return float(m.group(1))
    return None


def _parse_json_payload(text: str) -> Optional[dict]:
    if not text or not text.strip():
        return None
    stripped = text.strip()
    try:
        data = json.loads(stripped)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
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


def _stored_credentials_present() -> bool:
    """True if the Firecrawl CLI stored-credentials file exists and is non-empty.

    Does not read or return secret material — only path presence for skip logic.
    """
    candidates = [
        Path.home() / ".config" / "firecrawl-cli" / "credentials.json",
        Path.home() / ".firecrawl" / "credentials.json",
    ]
    for path in candidates:
        try:
            if path.is_file() and path.stat().st_size > 2:
                return True
        except OSError:
            continue
    return False


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
        break
    return out


# Silence unused re if tree-shakers complain elsewhere.
_ = re
