# Profile matrix labels

Finite labeled profiles for the competitive benchmark. Profile ids written on
normalized artifacts must join this table (VAL-BENCH-007, VAL-BENCH-032, VAL-BENCH-039).

## Artifact profile_id rows

| profile_id | Engine | Difficulty / path | Proxy tier | Formats | Concurrency | Scoring role | CI default? |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `P1-soft-basecrawl` | basecrawl | soft / direct rustls (`--no-js`) | direct (non-residential) | markdown, html, links | unlimited soft | **scoring** | **yes** |
| `P2-soft-firecrawl-basic` | firecrawl | soft / cloud | `basic` (or auto that stayed basic) | markdown, html, links | ≤ plan / prefer 1–2 | **scoring** | yes if key present; else typed skip |
| `P3-basecrawl-hard-optional` | basecrawl | hard / Chromium (`--force-browser`) or residential when gated | optional; residential if dialed (max **1**) | markdown, html, links | **1** if residential | scoring or typed skip | **optional** |
| `P4-firecrawl-enhanced-ceiling` | firecrawl | cloud enhanced (or auto→enhanced) | `enhanced` | markdown, html, links | ≤2 | **ceiling** (non-parity) | **optional** |

## Execution scenarios (matrix runner)

The matrix CLI orchestrates multi-engine **scenarios**. Each scenario produces one or more
artifact rows with the `profile_id` values above.

| Scenario | What it runs | URLs | CI default? | Operator optional |
| --- | --- | --- | --- | --- |
| **P1** soft dual | basecrawl soft + firecrawl basic, **same** soft URL list + fair formats | `https://example.com/`, `https://books.toscrape.com/` (overrideable) | **yes** | no |
| **P2** JS render | both engines against JS probe; `js_target=true`; live basecrawl uses Chromium hard path (not hard-optional skip) | `https://quotes.toscrape.com/js/` | **yes** (required scoring; dry-safe + live when keys available) | hard *profile* remains optional separately |
| **P3** medium/residential | basecrawl hard/residential + firecrawl medium optional | soft probes or operator URLs | **no** | **yes** (`--include-medium` / `--include-residential`) |
| **P4** FC enhanced | firecrawl `--proxy enhanced` | soft probes | **no** | **yes** (`--include-enhanced`) |
| **hard** | basecrawl hard optional | soft probe | **no** | **yes** (`--include-hard`) |

CI-default behavior:

- Always run basecrawl **P1** dry/soft (no Oxylabs required).
- Firecrawl soft rows: dry when key present; **typed skip** (`engine_unavailable`) when key missing
  (pipeline continues).
- **P2** dry marks JS target for scorer; live JS is operator choice.
- Enhanced, residential (max 1 Oxylabs dial), medium, and hard are **operator-optional**.
  Without the corresponding include flag they emit **typed optional skips**
  (`hard_optional_skipped` / `medium_optional_skipped`) — not soft content wins.

## Fair dual soft H2H (P1)

- Same URL list for basecrawl and Firecrawl.
- Formats: **markdown, html, links only** (LLM extract / interact excluded from core).
- Soft basecrawl rows must **never** be labeled residential unlock success.

## Notes

- Soft basecrawl rows must **not** be labeled residential unlock success.
- Enhanced / auto-fallback-to-enhanced never rewrites core soft/basic leaderboard aggregates.
- Medium/hard optional skips use typed `challenge_class` / `error_class` values (e.g. `hard_optional_skipped`).
- Firecrawl surface for this matrix is **cloud** unless a future profile is explicitly labeled self-host.
- Scoreboard JSON+markdown land under gitignored `basecrawl/.docs-evidence/benchmark/`.
- Dry matrix scorer-only via `python -m benchmark matrix --scorer-only`.

## Core scores ignore

LLM extract / interact / agent formats and any enhanced ceiling row unless `--include-ceiling`
is explicitly set for research digests.
