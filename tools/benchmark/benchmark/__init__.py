"""basecrawl competitive scrape benchmark harness (schema + scorer + adapters).

Tracked under ``tools/benchmark/``. Live scoreboards land only under
gitignored ``.docs-evidence/benchmark/``. Core fairness formats are
``markdown``, ``html``/``rawHtml``, and ``links`` only; LLM extract and
Firecrawl interact are excluded from core scoring.
"""

from .basecrawl_adapter import (
    PROFILE_HARD,
    PROFILE_RESIDENTIAL,
    PROFILE_SOFT,
    BasecrawlAdapter,
    BasecrawlAdapterConfig,
    classify_challenge,
    map_basecrawl_error_kind,
    normalize_proof_file,
)
from .firecrawl_adapter import (
    PROFILE_BASIC as FIRECRAWL_PROFILE_BASIC,
    PROFILE_ENHANCED as FIRECRAWL_PROFILE_ENHANCED,
    FirecrawlAdapter,
    FirecrawlAdapterConfig,
    classify_challenge_body as firecrawl_classify_challenge_body,
    classify_firecrawl_failure,
    normalize_firecrawl_payload,
)
from .firecrawl_limit import (
    FIRECRAWL_MAX_CONCURRENCY,
    FirecrawlConcurrencyError,
    firecrawl_slot,
)
from .formats import (
    CORE_FORMATS,
    EXCLUDED_CORE_FORMATS,
    FAIR_FORMAT_ALIASES,
    is_core_format,
    normalize_format_token,
    request_core_formats,
)
from .redact import collect_secret_fragments, redact_text
from .rescore import rescore_artifacts, rescore_directory
from .residential_limit import ResidentialConcurrencyError, residential_slot
from .schema import (
    CHALLENGE_CLASSES,
    CORE_DIMENSIONS,
    ERROR_CLASSES,
    SECONDARY_DIMENSIONS,
    CostEstimate,
    NormalizedResult,
    SCHEMA_VERSION,
    load_normalized_result,
    validate_normalized_result,
)
from .scorer import (
    AggregateScores,
    DimensionScores,
    ScoredRow,
    score_result,
    score_results,
)

__all__ = [
    "CORE_FORMATS",
    "EXCLUDED_CORE_FORMATS",
    "FAIR_FORMAT_ALIASES",
    "is_core_format",
    "normalize_format_token",
    "request_core_formats",
    "CHALLENGE_CLASSES",
    "CORE_DIMENSIONS",
    "ERROR_CLASSES",
    "SECONDARY_DIMENSIONS",
    "CostEstimate",
    "NormalizedResult",
    "SCHEMA_VERSION",
    "load_normalized_result",
    "validate_normalized_result",
    "AggregateScores",
    "DimensionScores",
    "ScoredRow",
    "score_result",
    "score_results",
    "rescore_artifacts",
    "rescore_directory",
    "BasecrawlAdapter",
    "BasecrawlAdapterConfig",
    "PROFILE_SOFT",
    "PROFILE_HARD",
    "PROFILE_RESIDENTIAL",
    "classify_challenge",
    "map_basecrawl_error_kind",
    "normalize_proof_file",
    "FirecrawlAdapter",
    "FirecrawlAdapterConfig",
    "FIRECRAWL_PROFILE_BASIC",
    "FIRECRAWL_PROFILE_ENHANCED",
    "FIRECRAWL_MAX_CONCURRENCY",
    "FirecrawlConcurrencyError",
    "firecrawl_slot",
    "firecrawl_classify_challenge_body",
    "classify_firecrawl_failure",
    "normalize_firecrawl_payload",
    "collect_secret_fragments",
    "redact_text",
    "ResidentialConcurrencyError",
    "residential_slot",
]

__version__ = "0.1.0"
