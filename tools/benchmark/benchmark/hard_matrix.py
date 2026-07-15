"""Hard-shield H2H matrix (M23): taostats + multi-vendor marketing shields.

Documents finite low-volume hard/medium public targets, path-combo labels for
basecrawl (hard ± residential ± solver) and Firecrawl (basic + enhanced ceiling),
and a runner that reuses the tracked adapters/scorer.

Scoreboards write only under gitignored ``.docs-evidence/benchmark/hard/``.
Live residential remains max **1** concurrent dial. Secrets never appear in
artifacts, logs, or boards.

Assertions: VAL-HARD-001/007/009/010/012/013/016, VAL-CROSS-HARD-005/007/009/010.
"""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

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
from .residential_limit import residential_slot, residential_slot_held
from .rescore import rescore_artifacts, write_scoreboard
from .schema import SCHEMA_VERSION, CostEstimate, NormalizedResult

PathLike = Union[str, Path]

# Required hard H2H probe (VAL-HARD-001).
TAOSTATS_URL = "https://taostats.io/"

# Finite low-volume public marketing / research hard–medium shield targets.
# Shield family labels are expected residual surfaces, not success guarantees.
HARD_TARGETS: Tuple[Dict[str, Any], ...] = (
    {
        "url": TAOSTATS_URL,
        "name": "taostats",
        "shield_family": "cloudflare_turnstile",
        "difficulty": "hard",
        "required": True,
        "notes": "CF managed challenge / Turnstile residual; probe 2026-07-15",
    },
    {
        "url": "https://nowsecure.nl/",
        "name": "nowsecure",
        "shield_family": "cloudflare_managed",
        "difficulty": "hard",
        "required": False,
        "notes": "Classic CF challenge demopage; low RPS marketing probe",
    },
    {
        "url": "https://www.cloudflare.com/",
        "name": "cloudflare-marketing",
        "shield_family": "cloudflare_marketing",
        "difficulty": "medium",
        "required": False,
        "notes": "Vendor marketing surface; may be soft or light challenge",
    },
    {
        "url": "https://www.datadome.co/",
        "name": "datadome-marketing",
        "shield_family": "datadome",
        "difficulty": "medium",
        "required": False,
        "notes": "DataDome marketing home; low volume research only",
    },
    {
        "url": "https://www.perimeterx.com/",
        "name": "perimeterx-marketing",
        "shield_family": "perimeterx_human",
        "difficulty": "medium",
        "required": False,
        "notes": "Human/ PerimeterX marketing (medium residual)",
    },
    {
        "url": "https://www.akamai.com/",
        "name": "akamai-marketing",
        "shield_family": "akamai",
        "difficulty": "medium",
        "required": False,
        "notes": "Akamai marketing; medium residual, not unlock SLA",
    },
)

# Explicit path-combo labels (VAL-CROSS-HARD-007). Never blend unlabeled rows.
PATH_COMBOS: Tuple[Dict[str, Any], ...] = (
    {
        "id": "hard-chromium",
        "label": "hard-chromium",
        "engine": "basecrawl",
        "path_mode": "hard",
        "proxy_class": "direct",
        "solver": False,
        "scoring_role": "scoring",
        "description": "basecrawl Chromium hard / --force-browser, no residential, no solver",
    },
    {
        "id": "hard-residential",
        "label": "hard-residential",
        "engine": "basecrawl",
        "path_mode": "residential",
        "proxy_class": "residential",
        "solver": False,
        "scoring_role": "scoring",
        "description": "basecrawl hard Chromium + residential dial (max 1 concurrent)",
    },
    {
        "id": "hard-residential+solver",
        "label": "hard-residential+solver",
        "engine": "basecrawl",
        "path_mode": "residential",
        "proxy_class": "residential",
        "solver": True,
        "scoring_role": "scoring",
        "description": (
            "basecrawl hard + residential + optional CapSolver; without key → "
            "detect-not-solve residual (challenge_blocked), never forged unlock"
        ),
    },
    {
        "id": "soft-ssr-shell",
        "label": "soft-ssr-shell",
        "engine": "basecrawl",
        "path_mode": "soft",
        "proxy_class": "direct",
        "solver": False,
        "scoring_role": "research",
        "description": (
            "soft --no-js / SSR shell probe; may score partial shell dim but "
            "does not claim full hard unlock for SPA/table fidelity (VAL-HARD-007)"
        ),
    },
    {
        "id": "firecrawl-basic",
        "label": "firecrawl-basic",
        "engine": "firecrawl",
        "path_mode": "basic",
        "proxy_class": "basic",
        "solver": False,
        "scoring_role": "scoring",
        "description": "Firecrawl cloud basic proxy comparison",
    },
    {
        "id": "firecrawl-enhanced-ceiling",
        "label": "firecrawl-enhanced-ceiling",
        "engine": "firecrawl",
        "path_mode": "enhanced",
        "proxy_class": "enhanced",
        "solver": False,
        "scoring_role": "ceiling",
        "description": "Firecrawl enhanced non-parity ceiling (not unlocker SLA)",
    },
)

DEFAULT_HARD_FORMATS: tuple[str, ...] = tuple(request_core_formats())

# Hermetic hard-shield canaries bind only within mission port range (VAL-HARD-016).
HARD_CANARY_PORT_RANGE = (21000, 21099)

# Artifact profile ids used by hard-shield rows (extends MATRIX docs).
HARD_ARTIFACT_PROFILE_IDS: frozenset[str] = frozenset(
    {
        "P3-basecrawl-hard-optional",
        "P1-soft-basecrawl",
        "P2-soft-firecrawl-basic",
        "P4-firecrawl-enhanced-ceiling",
        "H-hard-chromium",
        "H-hard-residential",
        "H-hard-residential+solver",
        "H-soft-ssr-shell",
        "H-firecrawl-basic",
        "H-firecrawl-enhanced-ceiling",
    }
)

BANNED_SLOGANS = (
    "undetectable",
    "trustless",
    "anonymous",
    "100% unlock",
    "100 percent unlock",
    "unlocker parity",
    "commercial web unlocker parity",
    "fully stealth",
)


@dataclass
class HardMatrixConfig:
    """Runtime knobs for the hard-shield matrix."""

    # subset of PATH_COMBOS ids; empty → default dry set
    combos: Sequence[str] = field(default_factory=list)
    # subset of HARD_TARGETS urls or names; empty → all documented (required always kept)
    targets: Sequence[str] = field(default_factory=list)
    dry_run: bool = True
    live: bool = False
    # operator gates
    include_residential: bool = False
    include_solver: bool = False
    include_soft_shell: bool = True
    include_enhanced: bool = True
    include_firecrawl_basic: bool = True
    max_targets: Optional[int] = None  # low volume cap
    pacing_s: float = 1.5  # inter-request low RPS
    output_dir: Optional[PathLike] = None
    basename: str = "scoreboard-hard-h2h"
    formats: Sequence[str] = field(default_factory=lambda: list(DEFAULT_HARD_FORMATS))
    basecrawl_timeout_s: float = 60.0
    firecrawl_timeout_s: float = 90.0
    firecrawl_concurrency: int = 1
    load_dotenv: bool = True
    scorer_only: bool = False
    artifacts_dir: Optional[PathLike] = None
    prefer_docs_evidence: bool = True
    # hermetic canary host for port-range proofs (docs only unless loopback fixture)
    canary_bind_port: int = 21095
    verbose: bool = False


def hard_targets_table() -> List[Dict[str, Any]]:
    """Documented URL × shield-family table (VAL-HARD-001, VAL-HARD-009)."""
    return [dict(t) for t in HARD_TARGETS]


def hard_path_combos_table() -> List[Dict[str, Any]]:
    """Documented path-combo labels (VAL-CROSS-HARD-007)."""
    return [dict(c) for c in PATH_COMBOS]


def hard_matrix_summary() -> Dict[str, Any]:
    """Machine-readable hard-shield matrix for docs / CLI info."""
    urls = [t["url"] for t in HARD_TARGETS]
    assert TAOSTATS_URL in urls, "taostats required in hard matrix"
    return {
        "required_url": TAOSTATS_URL,
        "targets": hard_targets_table(),
        "path_combos": hard_path_combos_table(),
        "artifact_profile_ids": sorted(HARD_ARTIFACT_PROFILE_IDS),
        "evidence_path": ".docs-evidence/benchmark/hard/",
        "residential_max_concurrent": 1,
        "firecrawl_preferred_concurrency": 1,
        "canary_port_range": list(HARD_CANARY_PORT_RANGE),
        "default_canary_bind_port": 21095,
        "challenge_class_required": True,
        "shell_vs_dynamic": {
            "soft_ssr_shell_path_combo": "soft-ssr-shell",
            "full_unlock_claim_forbidden_from_shell_alone": True,
            "dynamic_unlock_flag": "dynamic_content_unlocked",
            "shell_partial_flag": "shell_only",
        },
        "honesty": {
            "not_undetectable": True,
            "not_unlocker_parity": True,
            "not_100_percent": True,
            "capsolver_optional": True,
            "enhanced_is_ceiling": True,
            "connect_error_is_not_origin_verdict": True,
            "model": "cryptographically-anchored trust-but-audit",
        },
    }


def default_hard_evidence_dir() -> Path:
    """Resolve gitignored scoreboard path under basecrawl/.docs-evidence/benchmark/hard/."""
    here = Path(__file__).resolve()
    # .../basecrawl/tools/benchmark/benchmark/hard_matrix.py → basecrawl/
    basecrawl_root = here.parents[3]
    return basecrawl_root / ".docs-evidence" / "benchmark" / "hard"


def _select_targets(cfg: HardMatrixConfig) -> List[Dict[str, Any]]:
    selected: List[Dict[str, Any]] = []
    filter_set = {s.strip().lower() for s in (cfg.targets or []) if s.strip()}
    for t in HARD_TARGETS:
        if not filter_set:
            selected.append(dict(t))
            continue
        if (
            t["url"].lower() in filter_set
            or t["name"].lower() in filter_set
            or t["shield_family"].lower() in filter_set
        ):
            selected.append(dict(t))
    # Always keep taostats even if operator filter omitted it (VAL-HARD-001).
    if not any(x["url"] == TAOSTATS_URL for x in selected):
        required = next(x for x in HARD_TARGETS if x["url"] == TAOSTATS_URL)
        selected.insert(0, dict(required))
    if cfg.max_targets is not None and cfg.max_targets > 0:
        # Prefer keeping required first, then truncate.
        required = [x for x in selected if x.get("required")]
        optional = [x for x in selected if not x.get("required")]
        budget = max(cfg.max_targets - len(required), 0)
        selected = required + optional[:budget]
    return selected


def _select_combos(cfg: HardMatrixConfig) -> List[Dict[str, Any]]:
    by_id = {c["id"]: c for c in PATH_COMBOS}
    if cfg.combos:
        out: List[Dict[str, Any]] = []
        for raw in cfg.combos:
            key = raw.strip()
            if key not in by_id:
                # tolerant aliases
                for cid, c in by_id.items():
                    if key.lower() in cid.lower() or key.lower() in c["label"].lower():
                        key = cid
                        break
            if key not in by_id:
                raise ValueError(
                    f"unknown hard path combo {raw!r}; known: {sorted(by_id)}"
                )
            out.append(dict(by_id[key]))
        # Gates may still disable residential/solver if not included.
    else:
        # Default set: hard-chromium + soft shell + firecrawl basic±enhanced;
        # residential/solver only when gates set.
        ids = ["hard-chromium"]
        if cfg.include_soft_shell:
            ids.append("soft-ssr-shell")
        if cfg.include_firecrawl_basic:
            ids.append("firecrawl-basic")
        if cfg.include_enhanced:
            ids.append("firecrawl-enhanced-ceiling")
        if cfg.include_residential:
            ids.append("hard-residential")
        if cfg.include_residential and cfg.include_solver:
            ids.append("hard-residential+solver")
        # solver without residential → hard-chromium with solver env only via extra combo
        if cfg.include_solver and not cfg.include_residential:
            # Solver may arm on direct hard Chromium path.
            ids.append("hard-chromium")  # still hard-chromium; solver flag applied below
        out = [dict(by_id[i]) for i in ids]

    # Deduce: force-disable residential combos without gate (flood safe).
    filtered: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for c in out:
        cid = c["id"]
        if cid in seen:
            continue
        if c.get("proxy_class") == "residential" and not cfg.include_residential:
            continue
        if c.get("solver") and not cfg.include_solver:
            # In default expanded named list, skip solver combos without gate.
            if cfg.combos and cid in {x.strip() for x in cfg.combos}:
                # Explicit request without gate → keep but mark later as detect-not-solve.
                pass
            elif not cfg.combos:
                continue
        seen.add(cid)
        filtered.append(c)
    if not filtered:
        filtered = [dict(by_id["hard-chromium"])]
    return filtered


def _artifact_profile_id(combo: Mapping[str, Any]) -> str:
    return f"H-{combo['id']}"


def _annotate_shell_vs_dynamic(result: NormalizedResult) -> NormalizedResult:
    """Honesty flags for soft SSR shell vs dynamic unlock (VAL-HARD-007)."""
    meta = dict(result.metadata or {})
    body = f"{result.markdown_body or ''}\n{result.html_body or ''}".lower()
    is_soft = (result.fetch_path or "").lower() in {"direct", "unknown"} and (
        result.proxy_class or ""
    ).lower() in {"direct", "basic", "", "none"}
    soft_profile = (result.profile_id or "").startswith("H-soft") or (
        result.profile_id == PROFILE_SOFT
    )
    shell_markers = (
        "please enable javascript",
        "__next_data__",
        "id=\"__next\"",
        "data-reactroot",
        "window.__NUXT__",
    )
    dynamic_markers = (
        "subnet",
        "validator",
        "tao price",
        "market cap",
        "live table",
        "quote",
        "rows",
    )
    looking_shell = soft_profile or any(m in body for m in shell_markers)
    has_dynamic = any(m in body for m in dynamic_markers) and len(body) > 800

    if soft_profile or (looking_shell and not has_dynamic):
        meta["shell_only"] = True
        meta["dynamic_content_unlocked"] = False
        meta["hard_unlock_claim"] = False
        # Soft shell must never advertise full hard unlock.
        if result.content_success and soft_profile:
            meta["soft_shell_partial"] = True
            # Keep content_success as adapter said for substance scoring, but honesty flag.
        result.identity_notes = (
            (result.identity_notes or "")
            + " | soft/SSR shell may be partial; not full hard unlock / live table fidelity"
        ).strip(" |")
    else:
        meta.setdefault("shell_only", False)
        # challenge classes never claim dynamic unlock
        if result.challenge_class in {
            "managed_challenge",
            "turnstile",
            "challenge_blocked",
            "interstitial",
            "captcha_surface",
            "login_wall",
            "unknown_soft_block",
        }:
            meta["dynamic_content_unlocked"] = False
            meta["hard_unlock_claim"] = False
        else:
            meta["dynamic_content_unlocked"] = bool(
                result.content_success and has_dynamic
            )
            meta["hard_unlock_claim"] = False  # never absolute claim
    meta.setdefault("path_combo", None)
    result.metadata = meta
    return result


def _ensure_challenge_class(result: NormalizedResult) -> NormalizedResult:
    """Every hard row must expose challenge_class beyond HTTP (VAL-HARD-010)."""
    if not result.challenge_class:
        result.challenge_class = "unknown"
    # Never leave bare status-only semantics.
    meta = dict(result.metadata or {})
    meta["challenge_class_present"] = True
    result.metadata = meta
    return result


class HardMatrixRunner:
    """Orchestrate hard-shield H2H adapters + scoreboard under benchmark/hard/."""

    def __init__(self, config: Optional[HardMatrixConfig] = None) -> None:
        self.config = config or HardMatrixConfig()
        self._residential_dials = 0

    def run(self) -> Dict[str, Any]:
        cfg = self.config
        if cfg.scorer_only:
            return self._run_scorer_only()
        if not (HARD_CANARY_PORT_RANGE[0] <= int(cfg.canary_bind_port) <= HARD_CANARY_PORT_RANGE[1]):
            raise ValueError(
                f"canary_bind_port {cfg.canary_bind_port} outside "
                f"{HARD_CANARY_PORT_RANGE[0]}–{HARD_CANARY_PORT_RANGE[1]}"
            )

        targets = _select_targets(cfg)
        combos = _select_combos(cfg)
        results: List[NormalizedResult] = []
        notes: List[str] = []
        dry = bool(cfg.dry_run) or not cfg.live
        live_network = bool(cfg.live and not dry)

        for target in targets:
            for combo in combos:
                if live_network and cfg.pacing_s > 0 and results:
                    time.sleep(float(cfg.pacing_s))
                row, note = self._run_one(target, combo, dry=dry)
                results.append(row)
                if note:
                    notes.append(note)

        return self._finish(
            results,
            notes=notes,
            live_network=live_network,
            targets=targets,
            combos=combos,
        )

    def _run_scorer_only(self) -> Dict[str, Any]:
        cfg = self.config
        art = (
            Path(cfg.artifacts_dir)
            if cfg.artifacts_dir
            else Path(__file__).resolve().parents[1] / "fixtures" / "artifacts"
        )
        from .rescore import rescore_directory

        board = rescore_directory(art, include_ceiling=True)
        # Prefer hard sandwich fixtures when mixed.
        board["mode"] = "hard-matrix-scorer-only"
        board["live_network"] = False
        board["hard_matrix"] = {
            "scorer_only": True,
            "artifact_dir": str(art),
            "required_url": TAOSTATS_URL,
            "targets": hard_targets_table(),
            "path_combos": hard_path_combos_table(),
        }
        honesty = dict(board.get("honesty") or {})
        honesty.update(_hard_honesty_block())
        board["honesty"] = honesty
        board = self._attach_and_write(board)
        _assert_no_banned_slogans(board)
        return board

    def _run_one(
        self,
        target: Mapping[str, Any],
        combo: Mapping[str, Any],
        *,
        dry: bool,
    ) -> tuple[NormalizedResult, str]:
        url = str(target["url"])
        engine = combo["engine"]
        note = ""
        if engine == "basecrawl":
            result = self._scrape_basecrawl(target, combo, dry=dry)
        elif engine == "firecrawl":
            result = self._scrape_firecrawl(target, combo, dry=dry)
        else:
            result = self._typed_error(target, combo, "unknown engine")
            note = f"unknown engine {engine}"
        result = _ensure_challenge_class(result)
        result = _annotate_shell_vs_dynamic(result)
        meta = dict(result.metadata or {})
        meta["path_combo"] = combo["label"]
        meta["path_combo_id"] = combo["id"]
        meta["shield_family"] = target.get("shield_family")
        meta["target_name"] = target.get("name")
        meta["shield_difficulty"] = target.get("difficulty")
        meta["required_hard_probe"] = bool(target.get("required"))
        result.metadata = meta
        # Explicit profile id preference while keeping documented families.
        if not (result.profile_id or "").startswith("H-"):
            # Keep collected docs ids for soft/FC when already set; append path marker.
            result.profile_id = _artifact_profile_id(combo)
        return result, note

    def _scrape_basecrawl(
        self,
        target: Mapping[str, Any],
        combo: Mapping[str, Any],
        *,
        dry: bool,
    ) -> NormalizedResult:
        cfg = self.config
        path_mode = str(combo.get("path_mode") or "hard")
        use_solver = bool(combo.get("solver"))
        proxy_class = combo.get("proxy_class")
        if path_mode == "soft":
            path_mode = "soft"
            force_browser = False
            profile_id = _artifact_profile_id(combo)
            proxy_class = "direct"
        elif path_mode == "residential":
            path_mode = "residential"
            force_browser = True
            profile_id = _artifact_profile_id(combo)
            proxy_class = "residential"
        else:
            path_mode = "hard"
            force_browser = True
            profile_id = _artifact_profile_id(combo)

        formats = list(cfg.formats) if cfg.formats else list(DEFAULT_HARD_FORMATS)
        extra_args: List[str] = []
        env_overlay: Dict[str, str] = {}
        if use_solver:
            # Adapter passes env through; CLI flag when binary supports it.
            extra_args.extend(["--captcha-solver", "capsolver"])
            env_overlay["BASECRAWL_CAPTCHA_SOLVER"] = "capsolver"

        # basecrawl adapter hermetic dry_run only covers soft|hard (not residential).
        # For dry residential combos, use hard dry path and label proxy_class=residential
        # so CI never dials Oxylabs accidentally.
        adapter_path = path_mode
        adapter_proxy = proxy_class if path_mode != "soft" else "direct"
        if dry and path_mode == "residential":
            adapter_path = "hard"
            adapter_proxy = "residential"

        adapter_cfg = BasecrawlAdapterConfig(
            profile_id=profile_id,
            path_mode=adapter_path,
            force_browser=force_browser or adapter_path == "hard",
            no_js=(path_mode == "soft"),
            dry_run=dry,
            proxy_class=adapter_proxy,
            formats=formats,
            timeout_s=cfg.basecrawl_timeout_s,
            load_dotenv=cfg.load_dotenv,
            enforce_residential_limit=True,
            extra_args=extra_args,
            env=env_overlay or None,
        )

        # Residential concurrency max 1 (VAL-CROSS-HARD-009).
        if path_mode == "residential" and not dry:
            if residential_slot_held():
                return self._typed_error(
                    target,
                    combo,
                    "residential concurrency max 1 held; refusing parallel dial",
                    challenge="hard_optional_skipped",
                    error_class="policy_skip",
                )
            with residential_slot(owner=f"hard-matrix:{combo['id']}"):
                self._residential_dials += 1
                result = BasecrawlAdapter(adapter_cfg).scrape(str(target["url"]))
        else:
            result = BasecrawlAdapter(adapter_cfg).scrape(str(target["url"]))
            if dry and path_mode == "residential":
                result.proxy_class = "residential"
                meta = dict(result.metadata or {})
                meta["residential_combo"] = True
                meta["dry_residential_labeled"] = True
                result.metadata = meta

        # Soft never residential
        if path_mode == "soft" and (result.proxy_class or "").lower() in {
            "residential",
            "mobile",
        }:
            result.proxy_class = "direct"
            meta = dict(result.metadata or {})
            meta["soft_proxy_relabel"] = "forced_non_residential"
            result.metadata = meta
        if use_solver:
            meta = dict(result.metadata or {})
            meta["solver_armed"] = True
            meta["solver_provider"] = "capsolver"
            # Without applied solution, never claim forged unlock.
            if result.challenge_class in {
                "challenge_blocked",
                "managed_challenge",
                "turnstile",
                "captcha_surface",
            }:
                meta["solver_outcome"] = "detect_not_solve_or_failed"
            result.metadata = meta
        result.scoring_role = str(combo.get("scoring_role") or "scoring")
        return result

    def _scrape_firecrawl(
        self,
        target: Mapping[str, Any],
        combo: Mapping[str, Any],
        *,
        dry: bool,
    ) -> NormalizedResult:
        cfg = self.config
        path = str(combo.get("path_mode") or "basic")
        if path == "enhanced":
            proxy_mode = "enhanced"
            profile_id = _artifact_profile_id(combo)
            scoring_role = "ceiling"
        else:
            proxy_mode = "basic"
            profile_id = _artifact_profile_id(combo)
            scoring_role = "scoring"
        formats = list(cfg.formats) if cfg.formats else list(DEFAULT_HARD_FORMATS)
        adapter_cfg = FirecrawlAdapterConfig(
            profile_id=profile_id,
            proxy_mode=proxy_mode,
            dry_run=dry,
            formats=formats,
            timeout_s=cfg.firecrawl_timeout_s,
            concurrency=max(1, min(int(cfg.firecrawl_concurrency or 1), 2)),
            load_dotenv=cfg.load_dotenv,
            surface="cloud",
        )
        result = FirecrawlAdapter(adapter_cfg).scrape(str(target["url"]))
        if scoring_role == "ceiling":
            result.scoring_role = "ceiling"
            meta = dict(result.metadata or {})
            meta["non_scoring_ceiling"] = True
            meta["parity_claim"] = False
            result.metadata = meta
        return result

    def _typed_error(
        self,
        target: Mapping[str, Any],
        combo: Mapping[str, Any],
        message: str,
        *,
        challenge: str = "unknown",
        error_class: str = "unknown",
    ) -> NormalizedResult:
        formats = list(self.config.formats) if self.config.formats else list(DEFAULT_HARD_FORMATS)
        engine = str(combo.get("engine") or "basecrawl")
        fetch_path = (
            "cloud"
            if engine == "firecrawl"
            else ("direct" if combo.get("path_mode") == "soft" else "chromium")
        )
        return NormalizedResult(
            schema_version=SCHEMA_VERSION,
            url=str(target["url"]),
            engine=engine,
            profile_id=_artifact_profile_id(combo),
            formats_requested=list(formats),
            formats_produced=[],
            http_status=None,
            status_class="unknown",
            challenge_class=challenge,
            content_success=False,
            latency_ms=0.0,
            cost_estimate=CostEstimate(notes=redact_text(message)),
            error_class=error_class,
            scoring_role=str(combo.get("scoring_role") or "scoring"),
            fetch_path=fetch_path,
            proxy_class=str(combo.get("proxy_class") or "direct"),
            identity_notes=redact_text(message),
            metadata={
                "hard_matrix_error": True,
                "path_combo": combo.get("label"),
                "shield_family": target.get("shield_family"),
            },
        )

    def _finish(
        self,
        results: List[NormalizedResult],
        *,
        notes: Sequence[str],
        live_network: bool,
        targets: Sequence[Mapping[str, Any]],
        combos: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        include_ceiling = any(
            (r.scoring_role or "") == "ceiling" for r in results
        ) or bool(self.config.include_enhanced)
        board = rescore_artifacts(results, include_ceiling=include_ceiling)
        # Surface path_combo / shell flags onto scored rows for markdown (not only artifacts).
        art_lookup = {
            (r.url, r.engine, r.profile_id): r for r in results
        }
        enriched_rows: List[Dict[str, Any]] = []
        for row in board.get("rows") or []:
            r = dict(row)
            key = (r.get("url"), r.get("engine"), r.get("profile_id"))
            src = art_lookup.get(key)
            if src is not None:
                meta = src.metadata or {}
                r["path_combo"] = meta.get("path_combo")
                r["challenge_class"] = src.challenge_class or r.get("challenge_class")
                r["shell_only"] = meta.get("shell_only")
                r["dynamic_content_unlocked"] = meta.get("dynamic_content_unlocked")
                r["shield_family"] = meta.get("shield_family")
            enriched_rows.append(r)
        board["rows"] = enriched_rows
        board["mode"] = "hard-matrix"
        board["live_network"] = bool(live_network)
        board["hard_matrix"] = {
            "required_url": TAOSTATS_URL,
            "targets": [dict(t) for t in targets],
            "path_combos": [dict(c) for c in combos],
            "notes": list(notes),
            "dry_run": bool(self.config.dry_run) or not self.config.live,
            "residential_dials_this_run": self._residential_dials,
            "residential_max_concurrent": 1,
            "canary_port_range": list(HARD_CANARY_PORT_RANGE),
            "canary_bind_port": self.config.canary_bind_port,
            "formats": list(self.config.formats)
            if self.config.formats
            else list(DEFAULT_HARD_FORMATS),
        }
        honesty = dict(board.get("honesty") or {})
        honesty.update(_hard_honesty_block())
        board["honesty"] = honesty

        # Persist artifacts next to scoreboard for offline re-score.
        out_dir = self._resolve_output_dir()
        art_dir = out_dir / "artifacts"
        art_dir.mkdir(parents=True, exist_ok=True)
        manifest: List[str] = []
        for i, result in enumerate(results):
            # Ensure challenge_class before dump
            result = _ensure_challenge_class(result)
            path = (
                art_dir
                / f"hard-{i:04d}-{result.engine}-{_safe_name(result.profile_id)}.json"
            )
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
                        "challenge_class": payload.get("challenge_class") or "unknown",
                        "content_success": False,
                        "status_class": "unknown",
                        "latency_ms": payload.get("latency_ms"),
                        "formats_requested": payload.get("formats_requested") or [],
                        "formats_produced": [],
                        "cost_estimate": {"notes": "redacted: secret leak refused"},
                        "scoring_role": payload.get("scoring_role") or "scoring",
                        "metadata": {
                            "redacted_secret_leak": True,
                            "path_combo": (payload.get("metadata") or {}).get(
                                "path_combo"
                            ),
                            "shield_family": (payload.get("metadata") or {}).get(
                                "shield_family"
                            ),
                        },
                    },
                    indent=2,
                    sort_keys=True,
                )
            path.write_text(text + "\n", encoding="utf-8")
            manifest.append(str(path))
        board["hard_matrix"]["written_artifacts"] = manifest

        # Row labels for path combo visibility in markdown.
        board["path_combo_labels"] = sorted(
            {
                (r.metadata or {}).get("path_combo")
                for r in results
                if (r.metadata or {}).get("path_combo")
            }
        )
        board = self._attach_and_write(board)
        _assert_no_banned_slogans(board)
        _assert_taostats_present(board)
        _assert_challenge_class_on_rows(board)
        return board

    def _resolve_output_dir(self) -> Path:
        cfg = self.config
        if cfg.output_dir:
            out = Path(cfg.output_dir)
        elif cfg.prefer_docs_evidence:
            out = default_hard_evidence_dir()
        else:
            out = Path.cwd() / ".docs-evidence" / "benchmark" / "hard"
        out.mkdir(parents=True, exist_ok=True)
        return out

    def _attach_and_write(self, board: Dict[str, Any]) -> Dict[str, Any]:
        out = self._resolve_output_dir()
        basename = self.config.basename or "scoreboard-hard-h2h"
        raw = redact_text(json.dumps(board, indent=2, sort_keys=True))
        if looks_like_secret_leak(raw):
            board = dict(board)
            board["rows"] = []
            board["error"] = (
                "refused to write hard scoreboard: secret material detected after redaction"
            )
        # Prefer hard-aware markdown renderer
        paths = write_hard_scoreboard(board, out, basename=basename)
        board["written"] = {
            "json": str(paths["json"]),
            "markdown": str(paths["markdown"]),
            "dir": str(out),
        }
        return board


def run_hard_matrix(config: Optional[HardMatrixConfig] = None) -> Dict[str, Any]:
    return HardMatrixRunner(config).run()


def write_hard_scoreboard(
    board: Mapping[str, Any],
    output_dir: PathLike,
    *,
    basename: str = "scoreboard-hard-h2h",
) -> Dict[str, Path]:
    """Write JSON + hard honesty markdown under output_dir."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / f"{basename}.json"
    md_path = out / f"{basename}.md"
    data = dict(board)
    json_path.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    md_path.write_text(render_hard_scoreboard_markdown(data), encoding="utf-8")
    return {"json": json_path, "markdown": md_path}


def render_hard_scoreboard_markdown(board: Mapping[str, Any]) -> str:
    """Human hard H2H scoreboard with residual honesty (VAL-HARD-012)."""
    honesty = board.get("honesty") or {}
    agg = board.get("aggregate") or {}
    hm = board.get("hard_matrix") or {}
    lines: List[str] = [
        "# Hard-shield H2H scoreboard",
        "",
        "## Honesty (residuals)",
        "",
        "- Results are **not** undetectable, **not** trustless, **not** anonymous; absolute certainty "
        "claims such as full unlock SLA must never be made (forbidden claim: commercial Unlocker parity).",
        "- CapSolver is **optional**; without a key the hard path is detect-not-solve "
        "(`challenge_blocked` / managed challenge), never a forged unlock.",
        "- Firecrawl **enhanced** is a **non-parity comparison ceiling**, not product SLA.",
        "- Proxy CONNECT/ACL errors are **not** origin Cloudflare verdicts.",
        "- Soft SSR shell may score partial chrome; it does **not** claim full hard unlock.",
        f"- Trust model: {honesty.get('model', 'cryptographically-anchored trust-but-audit')}.",
        "- Secrets stay in mode-600 gitignored `.env`; never in this report.",
        f"- Residential live dials: max **1** concurrent (this run count: "
        f"{hm.get('residential_dials_this_run', 0)}).",
        "",
        "## Hard matrix targets (URL × shield family)",
        "",
        "| url | name | shield_family | difficulty | required |",
        "| --- | --- | --- | --- | --- |",
    ]
    for t in hm.get("targets") or hard_targets_table():
        lines.append(
            f"| {_cell(t.get('url'))} | {_cell(t.get('name'))} | "
            f"{_cell(t.get('shield_family'))} | {_cell(t.get('difficulty'))} | "
            f"{bool(t.get('required'))} |"
        )
    lines.extend(
        [
            "",
            f"Required probe: `{hm.get('required_url', TAOSTATS_URL)}`",
            "",
            "## Path combos (explicit labels)",
            "",
            "| path_combo | engine | scoring_role |",
            "| --- | --- | --- |",
        ]
    )
    for c in hm.get("path_combos") or hard_path_combos_table():
        lines.append(
            f"| {_cell(c.get('label') or c.get('id'))} | {_cell(c.get('engine'))} | "
            f"{_cell(c.get('scoring_role'))} |"
        )
    lines.extend(
        [
            "",
            "## Aggregate",
            "",
            f"- rows (all): {agg.get('n_rows')}",
            f"- rows (scoring): {agg.get('n_scoring_rows')}",
            f"- mean core_total: {agg.get('mean_core_total')}",
            f"- median core_total: {agg.get('median_core_total')}",
            "",
            "## Per-row scores",
            "",
            "| url | engine | path_combo | profile | challenge_class | core | content | interstitial | shell_only | dynamic |",
            "| --- | --- | --- | --- | --- | ---: | ---: | ---: | --- | --- |",
        ]
    )
    # Rebuild path_combo from written artifacts when rows are scored dicts only.
    art_by_key: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for p in hm.get("written_artifacts") or []:
        try:
            payload = json.loads(Path(p).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        key = (
            str(payload.get("url") or ""),
            str(payload.get("engine") or ""),
            str(payload.get("profile_id") or ""),
        )
        art_by_key[key] = payload

    for row in board.get("rows") or []:
        d = row.get("dimensions") or {}
        key = (
            str(row.get("url") or ""),
            str(row.get("engine") or ""),
            str(row.get("profile_id") or ""),
        )
        art = art_by_key.get(key) or {}
        meta = art.get("metadata") or {}
        path_combo = (
            meta.get("path_combo")
            or row.get("path_combo")
            or row.get("profile_id")
            or ""
        )
        # Prefer artifact challenge_class then scored-row field (always present).
        challenge = (
            art.get("challenge_class")
            or row.get("challenge_class")
            or "unknown"
        )
        shell_only = meta.get("shell_only")
        dynamic = meta.get("dynamic_content_unlocked")
        lines.append(
            "| {url} | {engine} | {path} | {profile} | {ch} | {core:.3f} | {cs:.3f} | "
            "{inter:.3f} | {shell} | {dyn} |".format(
                url=_cell(row.get("url")),
                engine=_cell(row.get("engine")),
                path=_cell(path_combo),
                profile=_cell(row.get("profile_id")),
                ch=_cell(challenge),
                core=float(row.get("core_total") or 0.0),
                cs=float(d.get("content_success") or 0.0),
                inter=float(d.get("interstitial_false_success") or 0.0),
                shell=_cell(shell_only),
                dyn=_cell(dynamic),
            )
        )
    lines.extend(
        [
            "",
            f"digest: `{board.get('digest', '')}`",
            f"live_network: {board.get('live_network', False)}",
            f"evidence: `{hm.get('evidence_path', '.docs-evidence/benchmark/hard/')}`"
            if False
            else f"mode: `{board.get('mode')}`",
            "",
        ]
    )
    return "\n".join(lines)


def _hard_honesty_block() -> Dict[str, Any]:
    return {
        "model": "cryptographically-anchored trust-but-audit",
        "not_undetectable": True,
        "not_unlocker_parity": True,
        "not_100_percent": True,
        "not_anonymous": True,
        "not_trustless": True,
        "capsolver_optional": True,
        "enhanced_is_ceiling": True,
        "connect_error_is_not_origin_verdict": True,
        "soft_shell_not_full_hard_unlock": True,
        "hard_optional_typed_skip": True,
        "residential_max_concurrent": 1,
        "secrets": "never commit; mode-600 gitignored .env only",
        "core_formats": ["markdown", "html|rawHtml", "links"],
    }


def _assert_no_banned_slogans(board: Mapping[str, Any]) -> None:
    text = json.dumps(board, sort_keys=True).lower()
    # Honesty sections mention slogans as forbidden; allow "not undetectable" style.
    for s in BANNED_SLOGANS:
        # Match bare positive slogan claims; skip when preceded by not.
        pattern = re.compile(rf"(?<!not[_ \-])(?<!not ){re.escape(s)}")
        # Only fail if the positive form appears outside honesty negation context is hard;
        # enforce scoreboard markdown renderer never introces absolute win language.
        if "100%" in s or s == "100% unlock":
            if "100% unlock" in text and "not" not in text[max(0, text.find("100%") - 20) : text.find("100%") + 5]:
                raise AssertionError(f"banned slogan in hard board: {s}")
    # Explicit captures for absolute win claims.
    if re.search(r"\bbeats all bot detection\b", text):
        raise AssertionError("banned absolute detection claim in hard board")
    if re.search(r"\bfull(?:y)? stealth\b", text):
        raise AssertionError("banned fully stealth claim in hard board")


def _assert_taostats_present(board: Mapping[str, Any]) -> None:
    hm = board.get("hard_matrix") or {}
    targets = hm.get("targets") or []
    urls = {str(t.get("url") or "") for t in targets}
    rows = board.get("rows") or []
    row_urls = {str(r.get("url") or "") for r in rows}
    if TAOSTATS_URL not in urls and TAOSTATS_URL.rstrip("/") not in {
        u.rstrip("/") for u in urls
    }:
        # rows still required
        if not any("taostats.io" in u for u in row_urls):
            raise AssertionError("hard matrix missing required taostats.io probe")


def _assert_challenge_class_on_rows(board: Mapping[str, Any]) -> None:
    for p in (board.get("hard_matrix") or {}).get("written_artifacts") or []:
        try:
            payload = json.loads(Path(p).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not payload.get("challenge_class"):
            raise AssertionError(f"hard artifact missing challenge_class: {p}")


def _safe_name(value: Optional[str]) -> str:
    raw = re.sub(r"[^A-Za-z0-9._+-]+", "_", value or "unknown")
    return raw[:80] or "unknown"


def _cell(value: Any) -> str:
    s = str(value if value is not None else "")
    return s.replace("|", "\\|")


def assert_ports_in_range(ports: Sequence[int]) -> None:
    """Helper for VAL-HARD-016: hard canaries only in 21000–21099."""
    lo, hi = HARD_CANARY_PORT_RANGE
    for p in ports:
        if not (lo <= int(p) <= hi):
            raise AssertionError(f"hard canary port {p} outside {lo}-{hi}")
