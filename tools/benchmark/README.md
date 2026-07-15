# Competitive scrape benchmark harness

Tracked tools under `basecrawl/tools/benchmark/` for fair **basecrawl** vs **Firecrawl** head-to-head (**H2H**) scoring.

Delivers the common **NormalizedResult** schema, multi-dimension **scorer** (0–1 dims + aggregates), **offline re-score**, the **basecrawl adapter** (soft direct, hard Chromium, optional residential Oxylabs with max 1 concurrent dial), the **Firecrawl cloud adapter** (formats markdown/html/links, proxy basic|auto|enhanced, skip-if-no-key, concurrency ≤2), and the **matrix runner** that produces scoreboard JSON+markdown under gitignored `.docs-evidence/benchmark/`.

## Honesty (read first)

- Results are **not** “undetectable,” “trustless,” “anonymous,” or “100%.”
- Trust model for proofs is **cryptographically-anchored trust-but-audit**.
- Firecrawl `enhanced` / auto-fallback to enhanced is an optional **non-scoring ceiling**, not parity.
- Hard / residential / challenge class rows may **typed-skip** when not gated; skips are not soft wins.
- No claim of commercial Web Unlocker parity.
- Soft basecrawl success is **never** labeled residential unlock.
- Soft SSR shell may score partial chrome; it is **not** a full hard unlock of SPA/live tables.
- CapSolver is **optional** (detect-not-solve without a key; never forged unlock).
- CONNECT/proxy ACL errors are not origin Cloudflare verdicts.
- Secrets (`FIRECRAWL_API_KEY`, Oxylabs, CapSolver) live only in mode-**600** gitignored `.env`. Never print them; never commit them. Scoreboards redaction is mandatory.

## Layout

```text
tools/benchmark/
  README.md           # this file
  SCHEMA.md           # common NormalizedResult contract
  SCORING.md          # dimension rubric + weights
  FORMATS.md          # fair formats (markdown/html/links only)
  MATRIX.md           # profile matrix labels (CI vs optional)
  benchmark/          # Python package (schema, scorer, rescore, adapters, matrix, CLI)
  fixtures/artifacts/ # hermetic sample normalized rows (no secrets)
  tests/              # focused pytest suite
```

Evidence outputs (live or operator re-score boards) belong under gitignored:

```text
basecrawl/.docs-evidence/benchmark/
basecrawl/.docs-evidence/benchmark/hard/   # M23 hard-shield H2H scoreboards
```

Also ignored: `basecrawl/.firecrawl/` (CLI cache) and `.env`.

## Fair core formats

Scored formats are **only**:

- `markdown`
- `html` or `rawHtml`
- `links`

LLM extract/json/summary and Firecrawl **interact**/agent are **excluded** from core score gates. See [FORMATS.md](FORMATS.md).

## Dimensions (0–1)

Core: content success, interstitial/false-success, markdown quality, links quality, JS render, latency, cost estimate.

Secondary (basecrawl only): proof / identity. Firecrawl is never failed for missing attestation; proof cannot replace failed content. Details in [SCORING.md](SCORING.md).

## Matrix profiles (summary)

| Scenario | CI default? | Engines | Notes |
| --- | --- | --- | --- |
| **P1** soft dual | **yes** | basecrawl soft + Firecrawl basic | same soft URL list + fair formats; FC skip if no key |
| **P2** JS render | **yes** (dry) | both vs `quotes.toscrape.com/js/` | JS dimension target |
| **P3** medium / residential | optional | basecrawl hard/res + FC medium | typed skip unless `--include-medium` / `--include-residential` (res max **1**) |
| **P4** FC enhanced ceiling | optional | Firecrawl enhanced | non-parity ceiling; not core board rewrite |
| **hard** optional | optional | basecrawl Chromium hard | typed skip unless `--include-hard` |

Full table in [MATRIX.md](MATRIX.md).

## Usage

From `basecrawl/tools/benchmark`:

```bash
# Schema + dimension registry + matrix summary
python -m benchmark info

# Matrix documentation as JSON
python -m benchmark matrix --info

# Dry matrix: scorer-only re-score of fixtures (no network, no adapters)
python -m benchmark matrix --scorer-only \
  --artifacts fixtures/artifacts \
  --out ../../.docs-evidence/benchmark \
  --basename scoreboard-fixture-rescore

# Dry hermetic matrix P1+P2 (adapter dry-run, no live dials)
python -m benchmark matrix --profiles P1,P2 --dry-run \
  --out ../../.docs-evidence/benchmark --basename scoreboard-matrix-dry

# Soft dual + JS live H2H (keys in mode-600 .env; Firecrawl skip if key missing;
# hard optional profile typed-skips unless --include-hard)
# python -m benchmark matrix --profiles P1,P2,hard --live \
#   --out ../../.docs-evidence/benchmark --basename scoreboard-live-h2h

# Optional hard + enhanced ceiling (operator)
# python -m benchmark matrix --profiles P1,hard,P4 --live \
#   --include-hard --include-enhanced --out ../../.docs-evidence/benchmark

# Optional residential (max 1 Oxylabs dial; never parallel residential storm)
# python -m benchmark matrix --profiles P3 --live --include-residential

# Validate / score single artifacts
python -m benchmark validate --path fixtures/artifacts/soft-basecrawl-example.json --require-body
python -m benchmark score --path fixtures/artifacts/soft-basecrawl-example.json

# Offline re-score an artifact directory (no network)
python -m benchmark rescore --artifacts fixtures/artifacts --check-stable
mkdir -p ../../.docs-evidence/benchmark
python -m benchmark rescore --artifacts fixtures/artifacts \
  --out ../../.docs-evidence/benchmark --basename scoreboard-fixture-rescore

# basecrawl adapter — hermetic soft dry-run (no Oxylabs required)
python -m benchmark basecrawl --url https://example.com/ --path-mode soft --dry-run

# basecrawl adapter — soft live scrape (direct/--no-js)
python -m benchmark basecrawl --url https://example.com/ --path-mode soft --out /tmp/soft.json

# basecrawl adapter — hard Chromium path
python -m benchmark basecrawl --url https://quotes.toscrape.com/js/ --path-mode hard --js-target

# residential optional (max 1 concurrent; secrets from mode-600 .env only)
# python -m benchmark basecrawl --url https://example.com/ --path-mode residential

# Firecrawl adapter — hermetic dry-run (requires FIRECRAWL_API_KEY in env/.env for non-skip)
python -m benchmark firecrawl --url https://example.com/ --proxy basic --dry-run

# Firecrawl adapter — soft live cloud scrape (key from mode-600 .env; never printed)
# python -m benchmark firecrawl --url https://example.com/ --proxy basic --out /tmp/fc.json

# Firecrawl enhanced ceiling (optional non-scoring; not core parity)
# python -m benchmark firecrawl --url https://example.com/ --proxy enhanced

# Fair skip proof when key missing (CI path)
# env -u FIRECRAWL_API_KEY python -m benchmark firecrawl --url https://example.com/ \
#   --no-stored-credentials --no-dotenv

# Hard-shield H2H (M23): taostats required + multi-vendor shields; modules under tools/benchmark
python -m benchmark hard-matrix --info
python -m benchmark hard-matrix --dry-run \
  --out ../../.docs-evidence/benchmark/hard --basename scoreboard-hard-h2h-dry
python -m benchmark hard-matrix --scorer-only --artifacts fixtures/artifacts \
  --out ../../.docs-evidence/benchmark/hard --basename scoreboard-hard-scorer
# Live operator: low RPS; residential max 1; CapSolver optional; secrets never printed
# python -m benchmark hard-matrix --live --include-residential --include-solver \
#   --pacing-s 2 --out ../../.docs-evidence/benchmark/hard
```

Focused tests:

```bash
cd tools/benchmark
python -m pytest tests/ -q
```

## basecrawl adapter notes

| path_mode | CLI flags | Concurrent residential | Live `.env` |
| --- | --- | --- | --- |
| `soft` | `--no-js` (default) | n/a | not required |
| `hard` | `--force-browser` | n/a unless residential class | not required |
| `residential` | `--force-browser` + `--proxy-class residential` | **1** | Oxylabs via `.env` |

Normalized fields always include `challenge_class`, `status_class`, `fetch_path`, `proxy_class`, and redacted error text. Credential/proxy-auth failures are typed `credential_error` and never content success. ScrapeProof / attestation are **secondary** dimensions only.

## Firecrawl adapter notes

| proxy_mode | scoring_role | Concurrency | Auth |
| --- | --- | --- | --- |
| `basic` | scoring | ≤ plan / **max 2** in-process (prefer 1) | `FIRECRAWL_API_KEY` or CLI stored login |
| `auto` | scoring until response shows enhanced | same | same |
| `enhanced` | **ceiling** (non-parity) | ≤2 | same |

Behavior:

- **Missing key / unauthenticated** → typed `engine_unavailable` fair skip (exit 0); not a content-failure score for basecrawl-only boards.
- **401/403 / invalid key** → fail-closed `credential_error` (non-zero).
- **Insufficient credits / plan limit** → typed `budget_exhausted` without inventing scores.
- **API key never on argv** (`-k` avoided); injected only via env; secrets redacted from JSON dumps.
- **Cloud-only** for this matrix by default (self-host needs explicit `--api-url` + surface label). Auto-fallback that lands on `proxyUsed=enhanced` is labeled ceiling, not core parity.
- Medium/hard optional tiers: `--optional-tier medium|hard` → typed skip classes without dialing.

## Scoreboard outputs

A completed matrix / rescore write lands as:

```text
basecrawl/.docs-evidence/benchmark/scoreboard-*.json
basecrawl/.docs-evidence/benchmark/scoreboard-*.md
basecrawl/.docs-evidence/benchmark/artifacts/   # normalized rows for re-score
```

Both formats include an **Honesty** section. Digests are stable for offline re-score of frozen artifacts.

## Secrets

- Operator: `basecrawl/.env` mode 600 with optional Oxylabs + `FIRECRAWL_API_KEY`.
- CI: Firecrawl rows skip cleanly when key is absent (adapter + matrix leaf).
- Never put keys in fixtures, README examples, or scoreboards.
- Verbose matrix summaries are redacted; leaks refuse to print.

## What this is not

- Not a full SaaS crawl product comparison.
- Not a guarantee against every bot manager or WAF.
- Not a substitute for relay L0–L5 authenticity verification on production tasks.
- Not commercial Web Unlocker parity and not “undetectable.”
