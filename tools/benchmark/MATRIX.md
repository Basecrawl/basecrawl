# Profile matrix labels

Finite labeled profiles for the competitive benchmark. Profile ids written on
normalized artifacts must join this table (VAL-BENCH-007, VAL-BENCH-032, VAL-BENCH-039).

| profile_id | Engine | Difficulty / path | Proxy tier | Formats | Concurrency | Scoring role | CI default? |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `P1-soft-basecrawl` | basecrawl | soft / direct rustls | direct (non-residential) | markdown, html, links | unlimited soft | **scoring** | **yes** |
| `P2-soft-firecrawl-basic` | firecrawl | soft / cloud | `basic` (or auto that stayed basic) | markdown, html, links | ≤ plan / prefer 1–2 | **scoring** | yes if key present; else typed skip |
| `P3-basecrawl-hard-optional` | basecrawl | hard / Chromium (`--force-browser` or hard) | optional; residential if dialed | markdown, html, links | **1** if residential | scoring or typed skip | **optional** |
| `P4-firecrawl-enhanced-ceiling` | firecrawl | cloud enhanced (or auto→enhanced) | `enhanced` | markdown, html, links | ≤2 | **ceiling** (non-parity) | **optional** |

## Notes

- Soft basecrawl rows must **not** be labeled residential unlock success.
- Enhanced / auto-fallback-to-enhanced never rewrites core soft/basic leaderboard aggregates.
- Medium/hard optional skips use typed `challenge_class` / `error_class` values (e.g. `hard_optional_skipped`).
- Fair dual soft H2H uses the **same URL list** and fair format subset for P1 and P2.
- Firecrawl surface for this matrix is **cloud** unless a future profile is explicitly labeled self-host.

## Core scores ignore

LLM extract / interact / agent formats and any enhanced ceiling row unless `--include-ceiling` is explicitly set for research digests.
