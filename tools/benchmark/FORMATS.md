# Format fairness policy

## Core H2H formats (scored)

| Format | Rationale |
| --- | --- |
| `markdown` | Shared primary content surface |
| `html` or `rawHtml` | Structural DOM/source fidelity |
| `links` | Extraction fidelity, non-LLM |

Default request list:

```text
markdown, html, links
```

(`rawHtml` may replace `html` when comparing served source rather than cleaned HTML.)

## Excluded from core WIN/LOSS

| Surface | Why excluded |
| --- | --- |
| Firecrawl LLM `json` / extract | Vendor AI value-add, not fetch parity |
| `summary`, `branding`, `product` | LLM product features |
| Firecrawl **interact** / agent | Session runtime + optional AI prompt minutes |
| map / search as content success | Discovery products, not page fidelity |
| Optional screenshot | Secondary; absence must not fail core content |

Operators may still collect excluded formats for research (`scoring_role=research`), but published core scorecards ignore them for winner logic.

## Implementation

```python
from benchmark.formats import CORE_FORMATS, EXCLUDED_CORE_FORMATS, request_core_formats

assert "interact" in EXCLUDED_CORE_FORMATS
assert "markdown" in CORE_FORMATS
assert request_core_formats() == ["markdown", "html", "links"]
```

CLI:

```bash
python -m benchmark info
```
