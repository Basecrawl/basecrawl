"""Fair H2H format policy for the competitive scrape benchmark.

Core WIN/LOSS scoring uses only FETCH-fidelity formats that both engines
can produce without a vendor-side LLM agent runtime:

  - markdown
  - html (or rawHtml as alias)
  - links

Excluded from core score gates (may be collected for research only):

  - LLM-backed extract / json / summary / branding / product
  - Firecrawl interact sessions and agent runs
  - map/search as primary content success criteria

Optional screenshot is secondary and non-blocking for core content.
"""

from __future__ import annotations

from typing import Iterable, List, Sequence, Set

# Tokens that participate in core H2H scoring (VAL-BENCH-006, VAL-BENCH-029).
CORE_FORMATS: frozenset[str] = frozenset({"markdown", "html", "rawHtml", "links"})

# Tokens that must never drive core WIN/LOSS.
EXCLUDED_CORE_FORMATS: frozenset[str] = frozenset(
    {
        "json",
        "extract",
        "summary",
        "branding",
        "product",
        "audio",
        "interact",
        "agent",
        "changeTracking",
        "attributes",
    }
)

# Alias map for format tokens arriving from vendor APIs.
FAIR_FORMAT_ALIASES: dict[str, str] = {
    "rawhtml": "rawHtml",
    "rawh": "rawHtml",
    "md": "markdown",
    "link": "links",
}


def normalize_format_token(token: str) -> str:
    """Normalize a format token spelling while preserving Firecrawl rawHtml casing."""
    t = (token or "").strip()
    if not t:
        return t
    key = t.lower()
    if key in FAIR_FORMAT_ALIASES:
        return FAIR_FORMAT_ALIASES[key]
    if key == "rawhtml":
        return "rawHtml"
    # markdown, html, links keep lower-case product spelling
    if key in {"markdown", "html", "links", "metadata", "screenshot", "json"}:
        return key if key != "rawhtml" else "rawHtml"
    return t


def is_core_format(token: str) -> bool:
    """Return True when *token* is part of the fairness core set."""
    norm = normalize_format_token(token)
    return norm in CORE_FORMATS


def request_core_formats(
    include_html: bool = True,
    prefer_raw_html: bool = False,
) -> List[str]:
    """Default format list for fair dual-engine H2H profiles."""
    formats = ["markdown", "links"]
    if include_html:
        formats.insert(1, "rawHtml" if prefer_raw_html else "html")
    return formats


def filter_core_formats(requested: Sequence[str] | None) -> List[str]:
    """Keep only core formats from a vendor format list (preserves order, de-dupes)."""
    if not requested:
        return request_core_formats()
    out: List[str] = []
    seen: Set[str] = set()
    for raw in requested:
        norm = normalize_format_token(raw)
        if norm in EXCLUDED_CORE_FORMATS:
            continue
        if norm not in CORE_FORMATS:
            continue
        if norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
    return out or request_core_formats()


def assert_no_core_excluded(formats: Iterable[str]) -> None:
    """Raise ValueError if any excluded (LLM/interact) format appears as a core requirement."""
    bad = [normalize_format_token(f) for f in formats if normalize_format_token(f) in EXCLUDED_CORE_FORMATS]
    if bad:
        raise ValueError(
            "core scoring profiles must not require LLM extract/interact formats: "
            + ", ".join(sorted(set(bad)))
        )
