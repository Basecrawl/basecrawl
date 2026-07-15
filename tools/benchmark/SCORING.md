# Scorer rubric

Deterministic offline scorer over [SCHEMA.md](SCHEMA.md) artifacts. Re-score never re-scrapes (VAL-BENCH-008, 022–025, 028, 030).

## Dimensions (all in \[0, 1\])

| Dimension | Core? | Description |
| --- | --- | --- |
| `content_success` | yes | Adapter success + substance; failures/skips → 0; interstitial dampened |
| `interstitial_false_success` | yes | High when **not** an empty/JS-enable/CF/login false success (separate from content) |
| `markdown_quality` | yes | Structure (headings/lists/paragraphs) + substance; non-empty alone ≠ 1.0 |
| `links_quality` | yes | Link list vs `expected_min_links`; empty on link-rich pages is low |
| `js_render` | yes | Active when `js_target=true`; neutral (~0.75) otherwise |
| `latency` | yes | Faster successful scrapes score higher; credential/skip short-circuits **neutral** (0.5), not "free wins" |
| `cost_estimate` | yes | Lower documented cost → higher score; nulls neutral (0.55), not forced 0 |
| `proof_identity` | **secondary** | basecrawl-only ScrapeProof / attestation bonus; `null` for Firecrawl |

## Core weights (sum = 1.0)

```text
content_success              0.30
interstitial_false_success   0.15
markdown_quality             0.20
links_quality                0.15
js_render                    0.10
latency                      0.05
cost_estimate                0.05
```

`core_total` = weighted sum of the seven core dims only. `proof_identity` is reported as `secondary_total` and **cannot** replace failed content wins.

## Aggregates

Per run:

- `mean_core_total`, `median_core_total`
- `mean_by_dimension`, `median_by_dimension`
- `mean_secondary_proof` (basecrawl rows only)
- `n_rows`, `n_scoring_rows`

Default aggregates **exclude** `scoring_role=ceiling|research` so Firecrawl enhanced ceilings do not rewrite core soft/basic standing.

## Latency rules

| Case | Score |
| --- | --- |
| Success, ≤ 2000 ms | 1.0 |
| Success, log falloff to 60000 ms | 1.0 → 0.0 |
| `credential_error`, `budget_exhausted`, engine skip | 0.5 (neutral) |
| Unsuccessful content with tiny latency (<250 ms) | ≤ 0.45 |

## Markdown quality notes

Rich article/example pages with headings and multi-word body score higher. Random short blobs, pure nav chrome, and interstitial bodies stay well below 1.0.

## Links quality notes

Absolute and relative links are both accepted. When `expected_min_links` is set (multi-link educational pages), empty lists under claimed content success score ~0.

## Re-score

```bash
cd tools/benchmark
python -m benchmark rescore --artifacts fixtures/artifacts --check-stable
python -m benchmark rescore --artifacts /path/to/.docs-evidence/benchmark/run-xyz/artifacts \
  --out ../../.docs-evidence/benchmark --basename scoreboard-rescore
```

Two passes over identical artifacts yield the same SHA-256 `digest` (float-stable path; tolerance documented as `float_tolerance` in board JSON).

## Fair formats

Core H2H formats only: markdown, html/rawHtml, links. LLM extract and interact are out of core gates — see [FORMATS.md](FORMATS.md).

## Honesty

Scores measure fetch/render quality under labeled profiles. They do **not** prove undetectable browsing, commercial unlocker parity, anonymity, or absolute authenticity of non-attested runs.
