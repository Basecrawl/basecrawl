"""Deterministic multi-dimension scorer for normalized scrape results.

All primary dimensions are reals in the closed interval [0, 1]. Aggregates
use explicit weights documented below. basecrawl proof/identity is a
secondary bonus only (VAL-BENCH-008, 022–025, 028). Scoring never re-fetches.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from statistics import mean, median
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from .formats import CORE_FORMATS
from .schema import CORE_DIMENSIONS, SECONDARY_DIMENSIONS, NormalizedResult

# Explicit core weights (sum to 1.0). Proof is secondary and not in core_total.
CORE_WEIGHTS: Dict[str, float] = {
    "content_success": 0.30,
    "interstitial_false_success": 0.15,
    "markdown_quality": 0.20,
    "links_quality": 0.15,
    "js_render": 0.10,
    "latency": 0.05,
    "cost_estimate": 0.05,
}

# Secondary weight for reporting own total (not mixed into core_total gates).
SECONDARY_WEIGHTS: Dict[str, float] = {
    "proof_identity": 1.0,
}

# Latency: midpoint of useful range for successful scrapes (ms).
LATENCY_GOOD_MS = 2_000.0
LATENCY_BAD_MS = 60_000.0
FLOAT_TOLERANCE = 1e-9

# VAL-HARD-004: documented float ceiling for CF challenge sandwich content_success.
# Sandwich bodies must score ≤ this bound (≈0) even when HTTP 200 / vendor API success.
CONTENT_SUCCESS_SANDWICH_MAX = 0.05

# Challenge classes that never unlock primary content under hard/soft scoring.
_CHALLENGE_FALSE_SUCCESS_CLASSES = frozenset(
    {
        "interstitial",
        "managed_challenge",
        "turnstile",
        "captcha_surface",
        "login_wall",
        "challenge_blocked",
        "unknown_soft_block",
    }
)

# Strong CF challenge-platform / Turnstile sandwich markers (hard penalty → 0 content).
_CF_SANDWICH_MARKERS = (
    "checking your browser",
    "just a moment",
    "challenge-platform",
    "cdn-cgi/challenge-platform",
    "cf-browser-verification",
    "cf-challenge",
    "cf-turnstile",
    "cf-turnstile-response",
    "challenges.cloudflare.com",
    "turnstile/v0",
    "verification failed",
    "verification expired",
    "attention required",
    "verify you are human",
    "managed challenge",
)

# Heuristic markers for interstitial / false-success bodies.
_INTERSTITIAL_MARKERS = (
    "please enable javascript",
    "please enable js",
    "enable javascript to continue",
    "checking your browser",
    "just a moment",
    "challenge-platform",
    "cdn-cgi/challenge-platform",
    "cf-browser-verification",
    "cf-challenge",
    "cf-turnstile",
    "challenges.cloudflare.com",
    "attention required",
    "access denied",
    "captcha",
    "hcaptcha",
    "recaptcha",
    "verify you are human",
    "verification failed",
    "verification expired",
    "bot detection",
    "cloudflare",
    "ddos-guard",
    "perimeterx",
    "datadome",
    "sign in to continue",
    "log in to continue",
    "login required",
)

_QUOTE_JS_MARKERS = (
    "albert einstein",
    "to be or not to be",
    "life is what happens",
    "the world as we have created",
    "class=\"quote\"",
    "div.quote",
)


@dataclass
class DimensionScores:
    """Per-URL dimension scores, all in [0, 1] when present."""

    content_success: float
    interstitial_false_success: float
    markdown_quality: float
    links_quality: float
    js_render: float
    latency: float
    cost_estimate: float
    proof_identity: Optional[float] = None  # secondary; None for non-basecrawl

    def core_as_dict(self) -> Dict[str, float]:
        return {
            "content_success": self.content_success,
            "interstitial_false_success": self.interstitial_false_success,
            "markdown_quality": self.markdown_quality,
            "links_quality": self.links_quality,
            "js_render": self.js_render,
            "latency": self.latency,
            "cost_estimate": self.cost_estimate,
        }

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = self.core_as_dict()
        d["proof_identity"] = self.proof_identity
        return d

    def validate_range(self) -> List[str]:
        errors: List[str] = []
        for name, value in self.core_as_dict().items():
            if not isinstance(value, (int, float)) or not (0.0 <= float(value) <= 1.0):
                errors.append(f"{name} out of [0,1]: {value!r}")
        if self.proof_identity is not None:
            if not (0.0 <= float(self.proof_identity) <= 1.0):
                errors.append(f"proof_identity out of [0,1]: {self.proof_identity!r}")
        return errors


@dataclass
class AggregateScores:
    """Rollups over a set of scored rows (VAL-BENCH-008)."""

    mean_core_total: float
    median_core_total: float
    mean_by_dimension: Dict[str, float]
    median_by_dimension: Dict[str, float]
    weighted_core_total_mean: float
    mean_secondary_proof: Optional[float]
    n_rows: int
    n_scoring_rows: int
    weights: Dict[str, float] = field(default_factory=lambda: dict(CORE_WEIGHTS))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mean_core_total": self.mean_core_total,
            "median_core_total": self.median_core_total,
            "mean_by_dimension": self.mean_by_dimension,
            "median_by_dimension": self.median_by_dimension,
            "weighted_core_total_mean": self.weighted_core_total_mean,
            "mean_secondary_proof": self.mean_secondary_proof,
            "n_rows": self.n_rows,
            "n_scoring_rows": self.n_scoring_rows,
            "weights": self.weights,
            "secondary_dimensions": list(SECONDARY_DIMENSIONS),
            "core_dimensions": list(CORE_DIMENSIONS),
        }


@dataclass
class ScoredRow:
    result: NormalizedResult
    dimensions: DimensionScores
    core_total: float
    secondary_total: Optional[float]
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.result.url,
            "engine": self.result.engine,
            "profile_id": self.result.profile_id,
            "scoring_role": self.result.scoring_role,
            "dimensions": self.dimensions.to_dict(),
            "core_total": self.core_total,
            "secondary_total": self.secondary_total,
            "notes": list(self.notes),
            "content_success_flag": self.result.content_success,
            "challenge_class": self.result.challenge_class,
            "error_class": self.result.error_class,
            "latency_ms": self.result.latency_ms,
            "cost_estimate": self.result.cost_estimate.to_dict(),
            "fetch_path": self.result.fetch_path,
            "proxy_class": self.result.proxy_class,
        }


def clamp01(x: float) -> float:
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)


def score_content_success(result: NormalizedResult, markdown: str, html: str = "") -> float:
    """Binary-ish content success with substance guardrails.

    VAL-HARD-004/005/006: CF challenge-platform / Turnstile / "Checking your
    Browser" sandwiches score ≈0 even when HTTP 200 or vendor API success set
    ``content_success=true`` on the adapter flag.
    """
    if result.error_class in {
        "credential_error",
        "budget_exhausted",
        "engine_unavailable",
        "policy_skip",
        "timeout",
        "transport",
        "challenge_blocked",
    }:
        return 0.0
    if result.challenge_class in {
        "engine_unavailable",
        "credential_error",
        "budget_exhausted",
        "medium_optional_skipped",
        "hard_optional_skipped",
    }:
        return 0.0
    # Challenge residual classes never count as content unlock (hard or soft).
    if result.challenge_class in _CHALLENGE_FALSE_SUCCESS_CLASSES:
        return 0.0
    body = f"{markdown}\n{html}".strip()
    body_only = markdown.strip()
    # Always zero CF sandwich markers, even when adapter flag claims success.
    if _looks_cf_sandwich(body) or _looks_cf_sandwich(body_only):
        return 0.0
    if _looks_interstitial(body) or _looks_interstitial(body_only):
        return 0.0
    if not result.content_success:
        return 0.0
    if len(body_only) < 32:
        return 0.25 if body_only else 0.0
    return 1.0


def score_interstitial_false_success(result: NormalizedResult, markdown: str, html: str) -> float:
    """High score = not an interstitial false success (VAL-BENCH-022, VAL-HARD-011)."""
    if result.challenge_class in _CHALLENGE_FALSE_SUCCESS_CLASSES:
        return 0.0
    text = f"{markdown}\n{html}".lower()
    if not text.strip():
        # Empty stream: default to mid-low only when content_success claimed.
        return 0.2 if result.content_success else 0.8
    if _looks_cf_sandwich(text) or _looks_interstitial(text):
        return 0.0
    if result.content_success and len(markdown.strip()) < 32:
        return 0.35
    return 1.0


def score_markdown_quality(result: NormalizedResult, markdown: str) -> float:
    """Structure + substance (VAL-BENCH-023). Non-empty alone is not 1.0."""
    if result.error_class not in {"none"} and not markdown.strip():
        return 0.0
    md = markdown.strip()
    if not md:
        return 0.0
    if _looks_interstitial(md):
        return 0.1

    length = len(md)
    # Length component: 0..0.45
    if length < 40:
        length_score = 0.05
    elif length < 200:
        length_score = 0.20
    elif length < 800:
        length_score = 0.35
    else:
        length_score = 0.45

    # Structure component: headings / lists / paragraphs
    headings = len(re.findall(r"(?m)^#{1,6}\s+\S+", md))
    lists = len(re.findall(r"(?m)^(?:[-*+]|\d+\.)\s+\S+", md))
    paras = len([p for p in re.split(r"\n\s*\n", md) if len(p.strip()) > 40])
    structure_hits = min(3, headings) + min(2, lists // 2) + min(2, paras)
    structure_score = min(0.40, structure_hits * 0.08)

    # Substance: words that are not pure chrome/nav tokens
    words = re.findall(r"[A-Za-z]{3,}", md)
    nav_like = {"home", "login", "menu", "nav", "cookie", "privacy", "terms", "subscribe"}
    content_words = [w for w in words if w.lower() not in nav_like]
    substance_score = 0.0
    if len(content_words) >= 20:
        substance_score = 0.15
    elif len(content_words) >= 8:
        substance_score = 0.10
    elif len(content_words) >= 3:
        substance_score = 0.05

    raw = length_score + structure_score + substance_score
    # Cap pure nav chrome: few content words even if long.
    if len(content_words) < 5 and length > 100:
        raw = min(raw, 0.45)
    return clamp01(raw)


def score_links_quality(result: NormalizedResult, links: Sequence[str]) -> float:
    """Link extraction fidelity (VAL-BENCH-024). Empty on link-rich pages is not 1.0."""
    requested_links = any(
        f in CORE_FORMATS and f == "links" for f in result.formats_requested
    ) or "links" in result.formats_requested
    if not requested_links and not links:
        # Links not requested: neutral high-ish score so it does not dominate core.
        return 0.75

    n = len([x for x in links if str(x).strip()])
    expected = result.expected_min_links
    if expected is None:
        # Soft default: multi-link educational pages expect at least 1 useful link when success.
        expected = 1 if result.content_success else 0

    if expected <= 0:
        return 1.0 if n == 0 else clamp01(0.8 + min(0.2, n * 0.02))

    if n == 0:
        return 0.0 if result.content_success else 0.25

    ratio = n / float(expected)
    # Absolute vs relative diversity bonus (abs handling documented).
    abs_count = sum(1 for u in links if str(u).startswith(("http://", "https://", "//")))
    rel_count = n - abs_count
    diversity = 0.05 if abs_count and rel_count else 0.0
    if abs_count == n and n >= expected:
        diversity = 0.05  # all absolute is still fine

    base = min(1.0, 0.55 + 0.45 * min(1.0, ratio))
    return clamp01(base + diversity - (0.0 if n >= expected else 0.15 * (1.0 - min(1.0, ratio))))


def score_js_render(result: NormalizedResult, markdown: str, html: str) -> float:
    """JS render dimension; neutral when not a JS target."""
    if not result.js_target:
        return 0.75  # neutral / not applicable

    text = f"{markdown}\n{html}".lower()
    if not text.strip():
        return 0.0
    if _looks_interstitial(text):
        return 0.05
    hits = sum(1 for m in _QUOTE_JS_MARKERS if m in text)
    # Generic dynamic indicators
    if "quote" in text and ("author" in text or "tags" in text):
        hits += 1
    if hits >= 2:
        return 1.0
    if hits == 1:
        return 0.7
    # Falling back: non-empty body without static shell markers still partial credit
    if len(markdown.strip()) >= 80:
        return 0.4
    return 0.1


def score_latency(result: NormalizedResult) -> float:
    """Normalize wall time; do not reward error short-circuits (VAL-BENCH-025)."""
    if result.error_class in {
        "credential_error",
        "budget_exhausted",
        "engine_unavailable",
        "policy_skip",
    }:
        # Failed/skipped trains: neutral, not a "fast win".
        return 0.5
    if result.challenge_class in {
        "medium_optional_skipped",
        "hard_optional_skipped",
        "engine_unavailable",
        "credential_error",
        "budget_exhausted",
    }:
        return 0.5

    lat = result.latency_ms
    if lat is None:
        return 0.5
    if lat < 0:
        return 0.0

    # Unsuccessful content with tiny latency: do not treat as better than slow success.
    if not result.content_success and lat < 250:
        return 0.45

    if lat <= LATENCY_GOOD_MS:
        return 1.0
    if lat >= LATENCY_BAD_MS:
        return 0.0
    # Smooth log falloff between good and bad.
    span = math.log(LATENCY_BAD_MS) - math.log(LATENCY_GOOD_MS)
    pos = math.log(lat) - math.log(LATENCY_GOOD_MS)
    return clamp01(1.0 - (pos / span))


def score_cost_estimate(result: NormalizedResult) -> float:
    """Better (higher) when cost is lower or rn null with honest notes.

    Never invent zeros as "free". Nulls → 0.55 neutral.
    """
    ce = result.cost_estimate
    if result.engine == "firecrawl":
        credits = ce.firecrawl_credits
        if credits is None:
            return 0.55
        # 1 credit soft page → high; 5 enhanced → lower for ceiling rows honesty.
        if credits <= 1.0:
            return 1.0
        if credits <= 2.0:
            return 0.85
        if credits <= 5.0:
            return 0.55
        return clamp01(0.55 - 0.05 * (credits - 5.0))

    # basecrawl: prefer lower reported proxy cost; null proxy with notes is ok.
    proxy = ce.basecrawl_proxy_usd_estimate
    cpu = ce.basecrawl_cpu_ms_placeholder
    if proxy is None and cpu is None:
        return 0.55
    score = 0.55
    if cpu is not None:
        if cpu <= 1_000:
            score = 0.85
        elif cpu <= 10_000:
            score = 0.70
        else:
            score = 0.50
    if proxy is not None:
        if proxy <= 0.0:
            score = min(score + 0.10, 1.0)
        elif proxy < 0.01:
            score = min(score + 0.05, 1.0)
        else:
            score = clamp01(score - min(0.3, proxy * 5.0))
    return clamp01(score)


def score_proof_identity(result: NormalizedResult) -> Optional[float]:
    """Secondary basecrawl-only bonus (VAL-BENCH-028). None for Firecrawl."""
    if result.engine != "basecrawl":
        return None
    score = 0.0
    if result.proof_present:
        score += 0.5
    if result.attestation_present:
        score += 0.5
    # Soft non-residential rows without proof stay low when proof absent; that is fine.
    return clamp01(score)


def weighted_core_total(dims: DimensionScores, weights: Mapping[str, float] = CORE_WEIGHTS) -> float:
    total = 0.0
    wsum = 0.0
    values = dims.core_as_dict()
    for name, w in weights.items():
        total += w * float(values[name])
        wsum += w
    if wsum <= 0:
        return 0.0
    return clamp01(total / wsum)


def score_result(
    result: NormalizedResult,
    *,
    base_dir: Optional[Path] = None,
    weights: Mapping[str, float] = CORE_WEIGHTS,
) -> ScoredRow:
    """Score a single normalized result without network I/O."""
    markdown = result.resolve_markdown(base_dir)
    html = result.resolve_html(base_dir)
    links = result.resolve_links(base_dir)

    dims = DimensionScores(
        content_success=score_content_success(result, markdown, html),
        interstitial_false_success=score_interstitial_false_success(result, markdown, html),
        markdown_quality=score_markdown_quality(result, markdown),
        links_quality=score_links_quality(result, links),
        js_render=score_js_render(result, markdown, html),
        latency=score_latency(result),
        cost_estimate=score_cost_estimate(result),
        proof_identity=score_proof_identity(result),
    )
    notes: List[str] = []
    # Proof cannot salvage failed content for "core win" narrative.
    if dims.content_success < 0.5 and (dims.proof_identity or 0.0) >= 0.5:
        notes.append(
            "proof_identity is secondary only; core residual note: proof cannot replace failed content wins"
        )
    if result.scoring_role == "ceiling":
        notes.append("non-scoring ceiling / non-parity row; separate from core leaderboard")
    if dims.content_success <= CONTENT_SUCCESS_SANDWICH_MAX and (
        result.challenge_class in _CHALLENGE_FALSE_SUCCESS_CLASSES
        or _looks_cf_sandwich(f"{markdown}\n{html}")
        or _looks_interstitial(f"{markdown}\n{html}")
    ):
        notes.append(
            "challenge sandwich residual: content_success≈0 despite HTTP/API success; "
            "not a content unlock win"
        )
    for err in dims.validate_range():
        notes.append(f"dimension range error: {err}")

    core = weighted_core_total(dims, weights)
    secondary = dims.proof_identity
    return ScoredRow(
        result=result,
        dimensions=dims,
        core_total=core,
        secondary_total=secondary,
        notes=notes,
    )


def score_results(
    results: Iterable[NormalizedResult],
    *,
    base_dir: Optional[Path] = None,
    weights: Mapping[str, float] = CORE_WEIGHTS,
) -> List[ScoredRow]:
    return [score_result(r, base_dir=base_dir, weights=weights) for r in results]


def aggregate_scores(
    rows: Sequence[ScoredRow],
    *,
    include_ceiling: bool = False,
    weights: Mapping[str, float] = CORE_WEIGHTS,
) -> AggregateScores:
    """Aggregate scored rows. Ceiling/research rows excluded by default from core means."""
    scoring = [
        r
        for r in rows
        if include_ceiling or r.result.scoring_role == "scoring"
    ]
    cores = [r.core_total for r in scoring] or [0.0]
    mean_by: Dict[str, float] = {}
    median_by: Dict[str, float] = {}
    for dim in CORE_DIMENSIONS:
        vals = [float(r.dimensions.core_as_dict()[dim]) for r in scoring] or [0.0]
        mean_by[dim] = float(mean(vals))
        median_by[dim] = float(median(vals))
    proof_vals = [
        float(r.dimensions.proof_identity)
        for r in scoring
        if r.dimensions.proof_identity is not None
    ]
    return AggregateScores(
        mean_core_total=float(mean(cores)),
        median_core_total=float(median(cores)),
        mean_by_dimension=mean_by,
        median_by_dimension=median_by,
        weighted_core_total_mean=float(mean(cores)),
        mean_secondary_proof=float(mean(proof_vals)) if proof_vals else None,
        n_rows=len(rows),
        n_scoring_rows=len(scoring),
        weights=dict(weights),
    )


def _looks_interstitial(text: str) -> bool:
    low = text.lower()
    return any(m in low for m in _INTERSTITIAL_MARKERS)


def _looks_cf_sandwich(text: str) -> bool:
    """True for Cloudflare challenge-platform / Turnstile residual sandwiches."""
    low = text.lower()
    return any(m in low for m in _CF_SANDWICH_MARKERS)
