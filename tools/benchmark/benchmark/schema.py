"""Common normalized Result schema shared by basecrawl and Firecrawl adapters.

Adapters emit JSON objects validated by :func:`validate_normalized_result`.
Saved artifacts retain bodies/paths needed for offline re-score
(VAL-BENCH-005, VAL-BENCH-031). No secrets belong in these objects.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

from .formats import CORE_FORMATS, filter_core_formats, normalize_format_token

SCHEMA_VERSION = "1.0.0"

ENGINES = frozenset({"basecrawl", "firecrawl"})
SCORING_ROLES = frozenset({"scoring", "ceiling", "research"})

# Beyond bare HTTP status (VAL-BENCH-021).
CHALLENGE_CLASSES = frozenset(
    {
        "none",
        "challenge_blocked",
        "interstitial",
        "captcha_surface",
        "login_wall",
        "unknown_soft_block",
        "engine_unavailable",
        "credential_error",
        "budget_exhausted",
        "medium_optional_skipped",
        "hard_optional_skipped",
        "network_error",
        "timeout",
        "unknown",
    }
)

ERROR_CLASSES = frozenset(
    {
        "none",
        "transport",
        "timeout",
        "credential_error",
        "budget_exhausted",
        "engine_unavailable",
        "challenge_blocked",
        "policy_skip",
        "parse_error",
        "unknown",
    }
)

# Primary (core) dimensions every scored row may carry.
CORE_DIMENSIONS = (
    "content_success",
    "interstitial_false_success",
    "markdown_quality",
    "links_quality",
    "js_render",
    "latency",
    "cost_estimate",
)

# basecrawl-only secondary bonuses (VAL-BENCH-028). Never required of Firecrawl.
SECONDARY_DIMENSIONS = (
    "proof_identity",
)

PathLike = Union[str, Path]


@dataclass
class CostEstimate:
    """Honest dual-engine cost placeholders (VAL-BENCH-026).

    Missing sides use null + notes rather than forced zero.
    """

    firecrawl_credits: Optional[float] = None
    firecrawl_usd_estimate: Optional[float] = None
    basecrawl_cpu_ms_placeholder: Optional[float] = None
    basecrawl_proxy_usd_estimate: Optional[float] = None
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "firecrawl_credits": self.firecrawl_credits,
            "firecrawl_usd_estimate": self.firecrawl_usd_estimate,
            "basecrawl_cpu_ms_placeholder": self.basecrawl_cpu_ms_placeholder,
            "basecrawl_proxy_usd_estimate": self.basecrawl_proxy_usd_estimate,
            "notes": self.notes,
        }

    @classmethod
    def from_mapping(cls, data: Optional[Mapping[str, Any]]) -> "CostEstimate":
        if not data:
            return cls(notes="cost not reported")
        return cls(
            firecrawl_credits=_optional_float(data.get("firecrawl_credits")),
            firecrawl_usd_estimate=_optional_float(data.get("firecrawl_usd_estimate")),
            basecrawl_cpu_ms_placeholder=_optional_float(
                data.get("basecrawl_cpu_ms_placeholder")
            ),
            basecrawl_proxy_usd_estimate=_optional_float(
                data.get("basecrawl_proxy_usd_estimate")
            ),
            notes=str(data.get("notes") or ""),
        )


@dataclass
class NormalizedResult:
    """Engine-agnostic scrape outcome used by the scorer and re-score path."""

    schema_version: str
    url: str
    engine: str
    profile_id: str
    formats_requested: List[str]
    formats_produced: List[str]
    http_status: Optional[int]
    status_class: str
    challenge_class: str
    content_success: bool
    latency_ms: Optional[float]
    cost_estimate: CostEstimate
    error_class: str = "none"
    scoring_role: str = "scoring"  # scoring | ceiling | research
    # Bodies retained for offline quality re-score (inline or path refs).
    markdown_body: Optional[str] = None
    markdown_path: Optional[str] = None
    html_body: Optional[str] = None
    html_path: Optional[str] = None
    links: Optional[List[str]] = None
    links_path: Optional[str] = None
    # Path/labels for honesty in scoreboard rows.
    fetch_path: Optional[str] = None  # direct | chromium | cloud | unknown
    proxy_class: Optional[str] = None  # direct | datacenter | residential | mobile | basic | enhanced | auto
    expected_min_links: Optional[int] = None
    js_target: bool = False
    # Secondary basecrawl proof/identity surface (never required of Firecrawl).
    proof_present: bool = False
    attestation_present: bool = False
    identity_notes: str = ""
    # Free-form non-secret metadata (adapter diagnostics).
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["cost_estimate"] = self.cost_estimate.to_dict()
        return d

    def resolve_markdown(self, base_dir: Optional[Path] = None) -> str:
        if self.markdown_body is not None:
            return self.markdown_body
        if self.markdown_path:
            return _read_text_ref(self.markdown_path, base_dir)
        return ""

    def resolve_html(self, base_dir: Optional[Path] = None) -> str:
        if self.html_body is not None:
            return self.html_body
        if self.html_path:
            return _read_text_ref(self.html_path, base_dir)
        return ""

    def resolve_links(self, base_dir: Optional[Path] = None) -> List[str]:
        if self.links is not None:
            return list(self.links)
        if self.links_path:
            raw = _read_text_ref(self.links_path, base_dir)
            if not raw.strip():
                return []
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                return [line.strip() for line in raw.splitlines() if line.strip()]
            if isinstance(data, list):
                return [str(x) for x in data]
            if isinstance(data, dict) and "links" in data:
                return [str(x) for x in data["links"]]
            return []
        return []


REQUIRED_FIELDS = (
    "schema_version",
    "url",
    "engine",
    "profile_id",
    "formats_requested",
    "formats_produced",
    "status_class",
    "challenge_class",
    "content_success",
    "latency_ms",
    "cost_estimate",
    "error_class",
)


def validate_normalized_result(
    data: Mapping[str, Any],
    *,
    require_body_payload: bool = False,
) -> List[str]:
    """Return a list of validation errors (empty list => valid).

    Does not raise; callers may treat non-empty errors as hard failures.
    """
    errors: List[str] = []
    if not isinstance(data, Mapping):
        return ["result must be a JSON object"]

    for key in REQUIRED_FIELDS:
        if key not in data:
            errors.append(f"missing required field: {key}")

    engine = data.get("engine")
    if engine is not None and engine not in ENGINES:
        errors.append(f"engine must be one of {sorted(ENGINES)}; got {engine!r}")

    profile_id = data.get("profile_id")
    if profile_id is not None and (not isinstance(profile_id, str) or not profile_id.strip()):
        errors.append("profile_id must be a non-empty string")

    url = data.get("url")
    if url is not None and (not isinstance(url, str) or not url.strip()):
        errors.append("url must be a non-empty string")

    for list_field in ("formats_requested", "formats_produced"):
        val = data.get(list_field)
        if list_field in data and not isinstance(val, list):
            errors.append(f"{list_field} must be a list of format tokens")
        elif isinstance(val, list):
            for item in val:
                if not isinstance(item, str):
                    errors.append(f"{list_field} items must be strings")
                    break

    fr = data.get("formats_requested")
    if isinstance(fr, list):
        core = filter_core_formats(fr)
        # Core scoring role must not *require* excluded formats only.
        role = data.get("scoring_role", "scoring")
        if role == "scoring":
            requested_norm = [normalize_format_token(x) for x in fr if isinstance(x, str)]
            if requested_norm and not any(t in CORE_FORMATS for t in requested_norm):
                errors.append(
                    "scoring_role=scoring must request at least one core format "
                    f"({sorted(CORE_FORMATS)}); got {requested_norm}"
                )
            excluded_req = [
                t
                for t in requested_norm
                if t
                in {
                    "json",
                    "extract",
                    "summary",
                    "branding",
                    "product",
                    "interact",
                    "agent",
                }
            ]
            # Allowed to list excluded formats optionally, but core must also be present when scoring.
            # If only excluded present, flag (above). No further error if mix.
            _ = core, excluded_req

    status = data.get("http_status")
    if status is not None and not isinstance(status, int):
        errors.append("http_status must be an int or null")

    chall = data.get("challenge_class")
    if chall is not None and chall not in CHALLENGE_CLASSES:
        errors.append(
            f"challenge_class must be one of {sorted(CHALLENGE_CLASSES)}; got {chall!r}"
        )

    err_c = data.get("error_class")
    if err_c is not None and err_c not in ERROR_CLASSES:
        errors.append(f"error_class must be one of {sorted(ERROR_CLASSES)}; got {err_c!r}")

    cs = data.get("content_success")
    if cs is not None and not isinstance(cs, bool):
        errors.append("content_success must be a boolean")

    lat = data.get("latency_ms")
    if lat is not None and not isinstance(lat, (int, float)):
        errors.append("latency_ms must be a number or null")
    if isinstance(lat, (int, float)) and lat < 0:
        errors.append("latency_ms must be >= 0 when present")

    ce = data.get("cost_estimate")
    if ce is not None and not isinstance(ce, Mapping):
        errors.append("cost_estimate must be an object")

    role = data.get("scoring_role")
    if role is not None and role not in SCORING_ROLES:
        errors.append(f"scoring_role must be one of {sorted(SCORING_ROLES)}")

    links = data.get("links")
    if links is not None and not isinstance(links, list):
        errors.append("links must be a list of strings or null")

    if require_body_payload:
        has_md = bool(data.get("markdown_body") or data.get("markdown_path"))
        has_links = data.get("links") is not None or bool(data.get("links_path"))
        # Soft requirement: either inline body/path for markdown OR structural empty allowed when error.
        if data.get("content_success") is True and not has_md:
            errors.append(
                "content_success=true requires markdown_body or markdown_path for re-score"
            )
        if data.get("content_success") is True and "links" in (
            data.get("formats_requested") or []
        ):
            if not has_links and data.get("error_class") == "none":
                # still allow empty list via links=[]
                if data.get("links") is None and not data.get("links_path"):
                    errors.append(
                        "links format requested with content_success requires links or links_path"
                    )

    # Secret hygiene helpers (soft): reject obviously embedded credential URLs in free text keys.
    for key in ("metadata",):
        blob = data.get(key)
        if isinstance(blob, Mapping):
            serialized = json.dumps(blob, sort_keys=True)
            if "FIRECRAWL_API_KEY=" in serialized or "oxylabs.io:" in serialized.lower():
                # allow hostnames; block user:pass patterns slightly
                if "://" in serialized and "@" in serialized:
                    errors.append("metadata must not embed credentialed proxy URLs")

    return errors


def load_normalized_result(
    data: Mapping[str, Any],
    *,
    strict: bool = True,
) -> NormalizedResult:
    """Parse a mapping into :class:`NormalizedResult`, raising on strict validation errors."""
    errors = validate_normalized_result(data)
    if errors and strict:
        raise ValueError("invalid NormalizedResult: " + "; ".join(errors))

    formats_requested = [
        normalize_format_token(x) for x in (data.get("formats_requested") or []) if isinstance(x, str)
    ]
    formats_produced = [
        normalize_format_token(x) for x in (data.get("formats_produced") or []) if isinstance(x, str)
    ]
    links_raw = data.get("links")
    links: Optional[List[str]]
    if links_raw is None:
        links = None
    else:
        links = [str(x) for x in links_raw]

    return NormalizedResult(
        schema_version=str(data.get("schema_version") or SCHEMA_VERSION),
        url=str(data.get("url") or ""),
        engine=str(data.get("engine") or ""),
        profile_id=str(data.get("profile_id") or ""),
        formats_requested=formats_requested,
        formats_produced=formats_produced,
        http_status=_optional_int(data.get("http_status")),
        status_class=str(data.get("status_class") or "unknown"),
        challenge_class=str(data.get("challenge_class") or "unknown"),
        content_success=bool(data.get("content_success")),
        latency_ms=_optional_float(data.get("latency_ms")),
        cost_estimate=CostEstimate.from_mapping(
            data.get("cost_estimate") if isinstance(data.get("cost_estimate"), Mapping) else None
        ),
        error_class=str(data.get("error_class") or "none"),
        scoring_role=str(data.get("scoring_role") or "scoring"),
        markdown_body=_optional_str(data.get("markdown_body")),
        markdown_path=_optional_str(data.get("markdown_path")),
        html_body=_optional_str(data.get("html_body")),
        html_path=_optional_str(data.get("html_path")),
        links=links,
        links_path=_optional_str(data.get("links_path")),
        fetch_path=_optional_str(data.get("fetch_path")),
        proxy_class=_optional_str(data.get("proxy_class")),
        expected_min_links=_optional_int(data.get("expected_min_links")),
        js_target=bool(data.get("js_target", False)),
        proof_present=bool(data.get("proof_present", False)),
        attestation_present=bool(data.get("attestation_present", False)),
        identity_notes=str(data.get("identity_notes") or ""),
        metadata=dict(data.get("metadata") or {}) if isinstance(data.get("metadata"), Mapping) else {},
    )


def load_normalized_result_file(path: PathLike, *, strict: bool = True) -> NormalizedResult:
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, list):
        raise ValueError(f"{p}: expected single result object, got list (use load_many)")
    return load_normalized_result(data, strict=strict)


def load_many(path: PathLike, *, strict: bool = True) -> List[NormalizedResult]:
    """Load a single result, a list of results, or a JSONL file."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix == ".jsonl":
        rows: List[NormalizedResult] = []
        for i, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            rows.append(load_normalized_result(json.loads(line), strict=strict))
        return rows
    data = json.loads(text)
    if isinstance(data, list):
        return [load_normalized_result(item, strict=strict) for item in data]
    if isinstance(data, Mapping) and "results" in data and isinstance(data["results"], list):
        return [load_normalized_result(item, strict=strict) for item in data["results"]]
    return [load_normalized_result(data, strict=strict)]


def _optional_float(value: Any) -> Optional[float]:
    if value is None:
        return None
    return float(value)


def _optional_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    return int(value)


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value)


def _read_text_ref(ref: str, base_dir: Optional[Path]) -> str:
    path = Path(ref)
    if not path.is_absolute() and base_dir is not None:
        path = base_dir / path
    return path.read_text(encoding="utf-8", errors="replace")


# Keep dataclass field inventory discoverable for docs/tests.
NORMALIZED_RESULT_FIELD_NAMES = tuple(f.name for f in fields(NormalizedResult))
