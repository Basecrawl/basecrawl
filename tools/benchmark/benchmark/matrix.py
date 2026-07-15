"""Matrix runner for competitive H2H profiles (VAL-BENCH-007, 009, 032–035, 039).

Profiles (execution scenarios):
  - P1 soft dual: same soft URL list through basecrawl soft + Firecrawl basic
  - P2 JS render: quotes.toscrape.com/js/ for JS dimension
  - P3 medium/residential optional: typed skip when not gated
  - P4 firecrawl auto/enhanced optional non-parity ceiling
  - hard optional: typed skip without unlocker claims

Default CI path: P1 (basecrawl soft always; Firecrawl skip-if-no-key) + scorer-only
dry matrix. Live dials require explicit gates / keys. Scoreboards write under
gitignored ``.docs-evidence/benchmark/`` only.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Union

from .basecrawl_adapter import (
    PROFILE_HARD,
    PROFILE_SOFT,
    BasecrawlAdapter,
    BasecrawlAdapterConfig,
)
from .firecrawl_adapter import (
    PROFILE_BASIC as FC_PROFILE_BASIC,
    PROFILE_ENHANCED as FC_PROFILE_ENHANCED,
    FirecrawlAdapter,
    FirecrawlAdapterConfig,
)
from .formats import request_core_formats
from .redact import looks_like_secret_leak, redact_text
from .rescore import rescore_artifacts, write_scoreboard
from .schema import NormalizedResult

PathLike = Union[str, Path]

# Documented artifact profile_ids (MATRIX.md). Must join scoreboard/matrix docs.
DOCUMENTED_PROFILE_IDS: frozenset[str] = frozenset(
    {
        "P1-soft-basecrawl",
        "P2-soft-firecrawl-basic",
        "P3-basecrawl-hard-optional",
        "P4-firecrawl-enhanced-ceiling",
        # Medium optional rows reuse P3 / error classes; JS soft rows stay P1 or P2.
    }
)

# Soft public educational targets for dual soft fair H2H (VAL-BENCH-017, 034).
DEFAULT_SOFT_URLS: tuple[str, ...] = (
    "https://example.com/",
    "https://books.toscrape.com/",
)

# JS-render probe (VAL-BENCH-018).
DEFAULT_JS_URL = "https://quotes.toscrape.com/js/"

# Core fair formats (VAL-BENCH-006, 029).
DEFAULT_FORMATS: tuple[str, ...] = tuple(request_core_formats())


@dataclass(frozen=True)
class MatrixProfileSpec:
    """One execution scenario in the operator matrix."""

    id: str
    description: str
    ci_default: bool
    operator_optional: bool
    engines: tuple[str, ...]  # basecrawl | firecrawl
    # soft | hard | residential | medium | js | enhanced | auto
    path_kind: str
    scoring_role: str  # scoring | ceiling
    dry_support: bool = True
    requires_live_proxy: bool = False
    requires_firecrawl_key: bool = False
    urls: tuple[str, ...] = ()
    concurrency_note: str = ""
    proxy_tier: str = "direct"
    formats: tuple[str, ...] = DEFAULT_FORMATS
    typed_skip_class: Optional[str] = None  # when forced skip without dial


# Finite labeled matrix (VAL-BENCH-007 + feature profile list).
MATRIX_PROFILES: Dict[str, MatrixProfileSpec] = {
    "P1": MatrixProfileSpec(
        id="P1",
        description=(
            "Soft dual-engine fair H2H: same soft URL list + fair formats through "
            "basecrawl soft (direct --no-js) and Firecrawl basic (skip if no key)."
        ),
        ci_default=True,
        operator_optional=False,
        engines=("basecrawl", "firecrawl"),
        path_kind="soft",
        scoring_role="scoring",
        dry_support=True,
        requires_live_proxy=False,
        requires_firecrawl_key=False,  # fair skip when missing
        urls=DEFAULT_SOFT_URLS,
        concurrency_note="soft unlimited; FC prefer 1 max 2",
        proxy_tier="direct|basic",
        formats=DEFAULT_FORMATS,
    ),
    "P2": MatrixProfileSpec(
        id="P2",
        description=(
            "JS render probe: https://quotes.toscrape.com/js/ with js_target flag; "
            "basecrawl hard Chromium optional with soft fallback labeling; Firecrawl basic."
        ),
        ci_default=True,  # dry/typed path is CI-safe; live optional
        operator_optional=False,
        engines=("basecrawl", "firecrawl"),
        path_kind="js",
        scoring_role="scoring",
        dry_support=True,
        requires_live_proxy=False,
        requires_firecrawl_key=False,
        urls=(DEFAULT_JS_URL,),
        concurrency_note="prefer sequential",
        proxy_tier="direct|basic",
        formats=DEFAULT_FORMATS,
    ),
    "P3": MatrixProfileSpec(
        id="P3",
        description=(
            "Medium / residential optional doors: typed skip by default "
            "(medium_optional_skipped / hard_optional_skipped / residential gate); "
            "live residential max 1 concurrent Oxylabs dial when gated."
        ),
        ci_default=False,
        operator_optional=True,
        engines=("basecrawl", "firecrawl"),
        path_kind="medium-residential",
        scoring_role="scoring",
        dry_support=True,
        requires_live_proxy=True,  # live residential only
        requires_firecrawl_key=False,
        urls=DEFAULT_SOFT_URLS[:1],
        concurrency_note="residential max 1",
        proxy_tier="residential optional",
        formats=DEFAULT_FORMATS,
        typed_skip_class="medium_optional_skipped",
    ),
    "P4": MatrixProfileSpec(
        id="P4",
        description=(
            "Firecrawl auto/enhanced optional non-parity ceiling: never rewrites "
            "core soft/basic leaderboard aggregates."
        ),
        ci_default=False,
        operator_optional=True,
        engines=("firecrawl",),
        path_kind="enhanced",
        scoring_role="ceiling",
        dry_support=True,
        requires_live_proxy=False,
        requires_firecrawl_key=True,
        urls=DEFAULT_SOFT_URLS[:1],
        concurrency_note="FC ≤2",
        proxy_tier="enhanced|auto→enhanced",
        formats=DEFAULT_FORMATS,
    ),
    "hard": MatrixProfileSpec(
        id="hard",
        description=(
            "Hard optional typed skip without unlocking claims; optional live hard "
            "Chromium path when --include-hard / --live is set."
        ),
        ci_default=False,
        operator_optional=True,
        engines=("basecrawl",),
        path_kind="hard",
        scoring_role="scoring",
        dry_support=True,
        requires_live_proxy=False,
        requires_firecrawl_key=False,
        urls=DEFAULT_SOFT_URLS[:1],
        concurrency_note="n/a",
        proxy_tier="direct optional",
        formats=DEFAULT_FORMATS,
        typed_skip_class="hard_optional_skipped",
    ),
}

DEFAULT_CI_PROFILES: tuple[str, ...] = ("P1", "P2")
DEFAULT_OPERATOR_OPTIONAL: tuple[str, ...] = ("P3", "P4", "hard")


@dataclass
class MatrixRunConfig:
    """Runtime knobs for a matrix orchestration pass."""

    profiles: Sequence[str] = field(default_factory=lambda: list(DEFAULT_CI_PROFILES))
    # scorer-only: load artifacts, score, write board — no adapter dials.
    scorer_only: bool = False
    dry_run: bool = True
    # When True with dry_run=False, operators accept live network (gate own keys).
    live: bool = False
    # Operator gates for optional profiles.
    include_optional: bool = False
    include_hard: bool = False
    include_enhanced: bool = False
    include_residential: bool = False
    include_medium: bool = False
    artifacts_dir: Optional[PathLike] = None
    output_dir: Optional[PathLike] = None
    basename: str = "scoreboard-matrix"
    soft_urls: Sequence[str] = field(default_factory=lambda: list(DEFAULT_SOFT_URLS))
    js_url: str = DEFAULT_JS_URL
    formats: Sequence[str] = field(default_factory=lambda: list(DEFAULT_FORMATS))
    basecrawl_timeout_s: float = 45.0
    firecrawl_timeout_s: float = 60.0
    firecrawl_concurrency: int = 1
    load_dotenv: bool = True
    # Prefer writing under package-relative evidence when not set.
    prefer_docs_evidence: bool = True
    verbose: bool = False


def documented_profile_ids() -> List[str]:
    return sorted(DOCUMENTED_PROFILE_IDS)


def matrix_summary() -> Dict[str, Any]:
    """Machine-readable matrix for docs / CLI info."""
    return {
        "profiles": {
            pid: {
                "id": spec.id,
                "description": spec.description,
                "ci_default": spec.ci_default,
                "operator_optional": spec.operator_optional,
                "engines": list(spec.engines),
                "path_kind": spec.path_kind,
                "scoring_role": spec.scoring_role,
                "proxy_tier": spec.proxy_tier,
                "formats": list(spec.formats),
                "urls": list(spec.urls),
                "concurrency_note": spec.concurrency_note,
                "requires_live_proxy": spec.requires_live_proxy,
                "typed_skip_class": spec.typed_skip_class,
            }
            for pid, spec in MATRIX_PROFILES.items()
        },
        "artifact_profile_ids": documented_profile_ids(),
        "ci_default_profiles": list(DEFAULT_CI_PROFILES),
        "operator_optional_profiles": list(DEFAULT_OPERATOR_OPTIONAL),
        "default_soft_urls": list(DEFAULT_SOFT_URLS),
        "js_render_url": DEFAULT_JS_URL,
        "core_formats": list(DEFAULT_FORMATS),
        "evidence_path": ".docs-evidence/benchmark/",
        "honesty": {
            "not_undetectable": True,
            "not_unlocker_parity": True,
            "enhanced_is_ceiling": True,
            "hard_optional_typed_skip": True,
            "soft_not_residential": True,
        },
    }


def default_evidence_dir() -> Path:
    """Resolve preferred gitignored scoreboard path under basecrawl/.docs-evidence/benchmark/."""
    here = Path(__file__).resolve()
    # .../basecrawl/tools/benchmark/benchmark/matrix.py → basecrawl/
    basecrawl_root = here.parents[3]
    return basecrawl_root / ".docs-evidence" / "benchmark"


def resolve_profiles(cfg: MatrixRunConfig) -> List[str]:
    """Select matrix scenario ids from config flags."""
    requested = list(cfg.profiles) if cfg.profiles else list(DEFAULT_CI_PROFILES)
    if cfg.include_optional:
        for pid in DEFAULT_OPERATOR_OPTIONAL:
            if pid not in requested:
                requested.append(pid)
    if cfg.include_hard and "hard" not in requested:
        requested.append("hard")
    if cfg.include_enhanced and "P4" not in requested:
        requested.append("P4")
    if (cfg.include_residential or cfg.include_medium) and "P3" not in requested:
        requested.append("P3")

    resolved: List[str] = []
    for pid in requested:
        key = pid if pid in MATRIX_PROFILES else pid.upper()
        # accept "P1-soft-dual" style aliases prefix
        if key not in MATRIX_PROFILES:
            for mid, spec in MATRIX_PROFILES.items():
                if pid.lower().startswith(mid.lower()) or mid.lower() in pid.lower():
                    key = mid
                    break
        if key not in MATRIX_PROFILES:
            raise ValueError(
                f"unknown matrix profile {pid!r}; known: {sorted(MATRIX_PROFILES)}"
            )
        if key not in resolved:
            resolved.append(key)
    return resolved


class MatrixRunner:
    """Orchestrate adapters + scoreboard for selected matrix profiles."""

    def __init__(self, config: Optional[MatrixRunConfig] = None) -> None:
        self.config = config or MatrixRunConfig()

    def run(self) -> Dict[str, Any]:
        cfg = self.config
        if cfg.scorer_only:
            return self._run_scorer_only()

        profile_ids = resolve_profiles(cfg)
        results: List[NormalizedResult] = []
        notes: List[str] = []
        for pid in profile_ids:
            spec = MATRIX_PROFILES[pid]
            batch, batch_notes = self._run_profile(spec)
            results.extend(batch)
            notes.extend(batch_notes)

        return self._finish(results, notes=notes, live_network=bool(cfg.live and not cfg.dry_run))

    def _run_scorer_only(self) -> Dict[str, Any]:
        cfg = self.config
        art = Path(cfg.artifacts_dir) if cfg.artifacts_dir else self._default_fixtures()
        from .rescore import rescore_directory

        board = rescore_directory(art, include_ceiling=False)
        board["mode"] = "matrix-scorer-only"
        board["matrix"] = {
            "profiles": [],
            "scorer_only": True,
            "artifact_dir": str(art),
            "live_network": False,
        }
        # Reinforce honesty for generated boards.
        honesty = dict(board.get("honesty") or {})
        honesty.setdefault("soft_not_residential", True)
        honesty.setdefault("matrix_scorer_only", True)
        board["honesty"] = honesty
        board = self._attach_and_write(board)
        return board

    def _default_fixtures(self) -> Path:
        return Path(__file__).resolve().parents[1] / "fixtures" / "artifacts"

    def _run_profile(
        self, spec: MatrixProfileSpec
    ) -> tuple[List[NormalizedResult], List[str]]:
        cfg = self.config
        notes: List[str] = []
        results: List[NormalizedResult] = []
        urls = self._urls_for(spec)

        # Optional profiles without enable flags → typed skip rows only.
        if spec.operator_optional and not self._optional_enabled(spec):
            notes.append(f"{spec.id}: operator-optional → typed skip (no dial)")
            for engine in spec.engines:
                for url in urls:
                    results.append(self._typed_skip_result(spec, engine, url))
            return results, notes

        dry = bool(cfg.dry_run) or not cfg.live
        for engine in spec.engines:
            for url in urls:
                if engine == "basecrawl":
                    results.append(self._scrape_basecrawl(spec, url, dry=dry))
                elif engine == "firecrawl":
                    results.append(self._scrape_firecrawl(spec, url, dry=dry))
                else:
                    notes.append(f"unknown engine {engine}")
        return results, notes

    def _optional_enabled(self, spec: MatrixProfileSpec) -> bool:
        """Operator-optional profiles dial only when their gate flag is set.

        Explicit listing of P3/P4/hard without include_* still yields typed skips
        so CIconsent stays fail-safe (VAL-BENCH-019, 020, 027).
        """
        cfg = self.config
        if not spec.operator_optional:
            return True
        if cfg.include_optional:
            return True
        if spec.id == "P3" and (cfg.include_residential or cfg.include_medium):
            return True
        if spec.id == "P4" and cfg.include_enhanced:
            return True
        if spec.id == "hard" and cfg.include_hard:
            return True
        return False

    def _urls_for(self, spec: MatrixProfileSpec) -> List[str]:
        cfg = self.config
        if spec.path_kind == "js":
            return [cfg.js_url or DEFAULT_JS_URL]
        if spec.path_kind == "soft":
            return list(cfg.soft_urls) if cfg.soft_urls else list(DEFAULT_SOFT_URLS)
        if spec.urls:
            return list(spec.urls)
        return list(cfg.soft_urls[:1]) if cfg.soft_urls else [DEFAULT_SOFT_URLS[0]]

    def _scrape_basecrawl(
        self, spec: MatrixProfileSpec, url: str, *, dry: bool
    ) -> NormalizedResult:
        path_mode, force_browser, js_target, profile_id = self._basecrawl_path(spec)
        # Soft never residential (VAL-BENCH-035).
        if path_mode == "soft":
            proxy_class = "direct"
        elif path_mode == "residential":
            proxy_class = "residential"
        else:
            proxy_class = None

        formats = list(self.config.formats) if self.config.formats else list(DEFAULT_FORMATS)
        adapter_cfg = BasecrawlAdapterConfig(
            profile_id=profile_id,
            path_mode=path_mode,
            force_browser=force_browser,
            no_js=(path_mode == "soft" and not force_browser),
            dry_run=dry,
            proxy_class=proxy_class,
            js_target=js_target,
            formats=formats,
            timeout_s=self.config.basecrawl_timeout_s,
            load_dotenv=self.config.load_dotenv,
            enforce_residential_limit=True,
        )
        # Optional residential without include → typed skip (soft/JS never use this).
        if (
            path_mode == "residential"
            and not self.config.include_residential
            and not dry
        ):
            return self._typed_skip_result(
                spec, "basecrawl", url, challenge="hard_optional_skipped"
            )
        # Operator-optional hard profiles require --include-hard / --include-optional.
        # P2 JS (ci_default, path_kind=js) is *required scoring*: Chromium hard path
        # is the intentional live JS probe, not an optional hard-skip door.
        if (
            path_mode == "hard"
            and not dry
            and not (self.config.include_hard or self.config.include_optional)
            and spec.path_kind != "js"
            and (spec.operator_optional or spec.path_kind == "hard")
        ):
            return self._typed_skip_result(
                spec, "basecrawl", url, challenge="hard_optional_skipped"
            )

        result = BasecrawlAdapter(adapter_cfg).scrape(url)
        # Enforce soft not labeled residential on success rows.
        if path_mode == "soft" and (result.proxy_class or "").lower() in {
            "residential",
            "mobile",
        }:
            result.proxy_class = "direct"
            result.metadata = dict(result.metadata or {})
            result.metadata["soft_proxy_relabel"] = "forced_non_residential"
        return result

    def _basecrawl_path(
        self, spec: MatrixProfileSpec
    ) -> tuple[str, bool, bool, str]:
        kind = spec.path_kind
        if kind == "soft":
            return "soft", False, False, PROFILE_SOFT
        if kind == "js":
            # JS probe: hard Chromium when live; dry uses hard dry synthetic.
            return "hard", True, True, PROFILE_HARD
        if kind == "hard":
            return "hard", True, False, PROFILE_HARD
        if kind == "medium-residential":
            if self.config.include_residential:
                return "residential", True, False, PROFILE_HARD
            return "hard", True, False, PROFILE_HARD
        if kind == "enhanced":
            # Enhanced is Firecrawl-only; basecrawl not applied.
            return "soft", False, False, PROFILE_SOFT
        return "soft", False, False, PROFILE_SOFT

    def _scrape_firecrawl(
        self, spec: MatrixProfileSpec, url: str, *, dry: bool
    ) -> NormalizedResult:
        proxy_mode, profile_id, scoring_role, optional_tier, js_target = self._firecrawl_path(
            spec
        )
        formats = list(self.config.formats) if self.config.formats else list(DEFAULT_FORMATS)
        adapter_cfg = FirecrawlAdapterConfig(
            profile_id=profile_id,
            proxy_mode=proxy_mode,
            dry_run=dry,
            js_target=js_target,
            formats=formats,
            timeout_s=self.config.firecrawl_timeout_s,
            concurrency=max(1, min(int(self.config.firecrawl_concurrency or 1), 2)),
            load_dotenv=self.config.load_dotenv,
            optional_tier=optional_tier,
            surface="cloud",
        )
        result = FirecrawlAdapter(adapter_cfg).scrape(url)
        # Ensure ceiling role for enhanced profile when auto-enhanced not already set.
        if scoring_role == "ceiling" and result.scoring_role != "ceiling":
            result.scoring_role = "ceiling"
            result.metadata = dict(result.metadata or {})
            result.metadata["matrix_scoring_role"] = "ceiling"
        return result

    def _firecrawl_path(
        self, spec: MatrixProfileSpec
    ) -> tuple[str, str, str, Optional[str], bool]:
        kind = spec.path_kind
        if kind == "soft":
            return "basic", FC_PROFILE_BASIC, "scoring", None, False
        if kind == "js":
            return "basic", FC_PROFILE_BASIC, "scoring", None, True
        if kind == "enhanced":
            return "enhanced", FC_PROFILE_ENHANCED, "ceiling", None, False
        if kind == "medium-residential":
            # Firecrawl medium optional skip door (typed) unless operator enables medium.
            if self.config.include_medium or self.config.include_optional:
                return "auto", FC_PROFILE_BASIC, "scoring", "medium", False
            return "basic", FC_PROFILE_BASIC, "scoring", "medium", False
        if kind == "hard":
            return "basic", FC_PROFILE_BASIC, "scoring", "hard", False
        return "basic", FC_PROFILE_BASIC, "scoring", None, False

    def _typed_skip_result(
        self,
        spec: MatrixProfileSpec,
        engine: str,
        url: str,
        *,
        challenge: Optional[str] = None,
    ) -> NormalizedResult:
        from .schema import CostEstimate, SCHEMA_VERSION

        ch = challenge or spec.typed_skip_class or "hard_optional_skipped"
        if engine == "basecrawl":
            profile_id = PROFILE_HARD if "hard" in (spec.path_kind + ch) else PROFILE_SOFT
            if spec.path_kind in {"hard", "medium-residential", "js"}:
                profile_id = PROFILE_HARD
                fetch_path = "chromium" if spec.path_kind != "soft" else "direct"
                proxy_class = (
                    "residential"
                    if self.config.include_residential and spec.path_kind == "medium-residential"
                    else "direct"
                )
            else:
                fetch_path = "direct"
                proxy_class = "direct"
        else:
            profile_id = (
                FC_PROFILE_ENHANCED if spec.path_kind == "enhanced" else FC_PROFILE_BASIC
            )
            fetch_path = "cloud"
            proxy_class = "enhanced" if spec.path_kind == "enhanced" else "basic"

        scoring_role = "ceiling" if spec.scoring_role == "ceiling" else "scoring"
        formats = list(self.config.formats) if self.config.formats else list(DEFAULT_FORMATS)
        return NormalizedResult(
            schema_version=SCHEMA_VERSION,
            url=url,
            engine=engine,
            profile_id=profile_id,
            formats_requested=list(formats),
            formats_produced=[],
            http_status=None,
            status_class="unknown",
            challenge_class=ch,
            content_success=False,
            latency_ms=0.0,
            cost_estimate=CostEstimate(
                notes=f"typed optional skip ({ch}); matrix profile {spec.id}"
            ),
            error_class="policy_skip",
            scoring_role=scoring_role,
            fetch_path=fetch_path,
            proxy_class=proxy_class,
            js_target=(spec.path_kind == "js"),
            identity_notes="typed optional skip — not a soft content win; not unlocker parity",
            metadata={
                "matrix_profile": spec.id,
                "typed_optional_skip": True,
                "ci_default": spec.ci_default,
                "operator_optional": spec.operator_optional,
            },
        )

    def _finish(
        self,
        results: List[NormalizedResult],
        *,
        notes: Sequence[str],
        live_network: bool,
    ) -> Dict[str, Any]:
        board = rescore_artifacts(results, include_ceiling=self.config.include_enhanced)
        board["mode"] = "matrix"
        board["live_network"] = bool(live_network)
        board["matrix"] = {
            "profiles": resolve_profiles(self.config),
            "scorer_only": False,
            "dry_run": bool(self.config.dry_run),
            "notes": list(notes),
            "artifact_profile_ids_seen": sorted(
                {r.profile_id for r in results if r.profile_id}
            ),
            "soft_urls": list(self.config.soft_urls),
            "js_url": self.config.js_url,
            "formats": list(self.config.formats) if self.config.formats else list(DEFAULT_FORMATS),
        }
        honesty = dict(board.get("honesty") or {})
        honesty.update(
            {
                "model": "cryptographically-anchored trust-but-audit",
                "not_undetectable": True,
                "not_unlocker_parity": True,
                "enhanced_is_ceiling": True,
                "hard_optional_typed_skip": True,
                "soft_not_residential": True,
                "js_probe": DEFAULT_JS_URL,
            }
        )
        board["honesty"] = honesty

        # Save raw normalized results next to scoreboard for offline re-score.
        out_dir = self._resolve_output_dir()
        art_dir = out_dir / "artifacts"
        art_dir.mkdir(parents=True, exist_ok=True)
        manifest_paths: List[str] = []
        for i, result in enumerate(results):
            path = art_dir / f"matrix-{i:04d}-{result.engine}-{result.profile_id}.json"
            payload = result.to_dict()
            text = redact_text(json.dumps(payload, indent=2, sort_keys=True))
            if looks_like_secret_leak(text):
                text = json.dumps(
                    {
                        "schema_version": payload.get("schema_version"),
                        "url": payload.get("url"),
                        "engine": payload.get("engine"),
                        "profile_id": payload.get("profile_id"),
                        "error_class": "policy_skip",
                        "challenge_class": "unknown",
                        "content_success": False,
                        "status_class": "unknown",
                        "latency_ms": payload.get("latency_ms"),
                        "formats_requested": payload.get("formats_requested") or [],
                        "formats_produced": [],
                        "cost_estimate": {"notes": "redacted: secret leak refused"},
                        "scoring_role": payload.get("scoring_role") or "scoring",
                        "metadata": {"redacted_secret_leak": True},
                    },
                    indent=2,
                    sort_keys=True,
                )
            path.write_text(text + "\n", encoding="utf-8")
            manifest_paths.append(str(path))

        board["matrix"]["written_artifacts"] = manifest_paths
        board = self._attach_and_write(board)
        return board

    def _resolve_output_dir(self) -> Path:
        cfg = self.config
        if cfg.output_dir:
            out = Path(cfg.output_dir)
        elif cfg.prefer_docs_evidence:
            out = default_evidence_dir()
        else:
            out = Path.cwd() / ".docs-evidence" / "benchmark"
        out.mkdir(parents=True, exist_ok=True)
        return out

    def _attach_and_write(self, board: Dict[str, Any]) -> Dict[str, Any]:
        out = self._resolve_output_dir()
        basename = self.config.basename or "scoreboard-matrix"
        # Redact board dump
        raw = redact_text(json.dumps(board, indent=2, sort_keys=True))
        if looks_like_secret_leak(raw):
            board = dict(board)
            board["rows"] = []
            board["error"] = "refused to write scoreboard: secret material detected after redaction"
        paths = write_scoreboard(board, out, basename=basename)
        board["written"] = {
            "json": str(paths["json"]),
            "markdown": str(paths["markdown"]),
            "dir": str(out),
        }
        # Also re-render honesty-enhanced markdown (write_scoreboard already includes honesty).
        return board


def run_matrix(config: Optional[MatrixRunConfig] = None) -> Dict[str, Any]:
    """Convenience entry used by CLI and tests."""
    return MatrixRunner(config).run()
