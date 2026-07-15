# Competitive scrape benchmark harness

Tracked tools under `basecrawl/tools/benchmark/` for fair **basecrawl** vs **Firecrawl** head-to-head (**H2H**) scoring.

Delivers the common **NormalizedResult** schema, multi-dimension **scorer** (0–1 dims + aggregates), **offline re-score**, the **basecrawl adapter** (soft direct, hard Chromium, optional residential Oxylabs with max 1 concurrent dial), and the **Firecrawl cloud adapter** (formats markdown/html/links, proxy basic|auto|enhanced, skip-if-no-key, concurrency ≤2). Matrix runner arrives in a follow-on feature.

## Honesty (read first)

- Results are **not** “undetectable,” “trustless,” “anonymous,” or “100%.”
- Trust model for proofs is **cryptographically-anchored trust-but-audit**.
- Firecrawl `enhanced` / auto-fallback to enhanced is an optional **non-scoring ceiling**, not parity.
- Hard / residential / challenge class rows may **typed-skip** when not gated; skips are not soft wins.
- No claim of commercial Web Unlocker parity.
- Secrets (`FIRECRAWL_API_KEY`, Oxylabs credentials) live only in mode-**600** gitignored `.env`. Never print them; never commit them. Scoreboards redaction is mandatory.

## Layout

```text
tools/benchmark/
  README.md           # this file
  SCHEMA.md           # common NormalizedResult contract
  SCORING.md          # dimension rubric + weights
  FORMATS.md          # fair formats (markdown/html/links only)
  MATRIX.md           # profile matrix labels (CI vs optional)
  benchmark/          # Python package (schema, scorer, rescore, CLI)
  fixtures/artifacts/ # hermetic sample normalized rows (no secrets)
  tests/              # focused pytest suite
```

Evidence outputs (live or operator re-score boards) belong under gitignored:

```text
basecrawl/.docs-evidence/benchmark/
```

## Fair core formats

Scored formats are **only**:

- `markdown`
- `html` or `rawHtml`
- `links`

LLM extract/json/summary and Firecrawl **interact**/agent are **excluded** from core score gates. See [FORMATS.md](FORMATS.md).

## Dimensions (0–1)

Core: content success, interstitial/false-success, markdown quality, links quality, JS render, latency, cost estimate.

Secondary (basecrawl only): proof / identity. Firecrawl is never failed for missing attestation; proof cannot replace failed content. Details in [SCORING.md](SCORING.md).

## Usage

From `basecrawl/tools/benchmark`:

```bash
# Schema + dimension registry
python -m benchmark info

# Validate a normalized artifact
python -m benchmark validate --path fixtures/artifacts/soft-basecrawl-example.json --require-body

# Score a single artifact
python -m benchmark score --path fixtures/artifacts/soft-basecrawl-example.json

# Offline re-score an artifact directory (no network)
python -m benchmark rescore --artifacts fixtures/artifacts --check-stable

# Write scoreboard under gitignored evidence dir
mkdir -p ../../.docs-evidence/benchmark
python -m benchmark rescore --artifacts fixtures/artifacts \
  --out ../../.docs-evidence/benchmark --basename scoreboard-fixture-rescore

# basecrawl adapter — hermetic soft dry-run (no Oxylabs required)
python -m benchmark basecrawl --url https://example.com/ --path-mode soft --dry-run

# basecrawl adapter — soft live scrape (direct/--no-js; uses release binary if present)
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

## Matrix profiles (summary)

See [MATRIX.md](MATRIX.md) for engine × path × proxy labels, scoring vs ceiling flags, and CI-default vs operator-optional profiles. Profile ids on artifacts (`profile_id`) must join these labels.

## Secrets

- Operator: `basecrawl/.env` mode 600 with optional Oxylabs + `FIRECRAWL_API_KEY`.
- CI: Firecrawl rows skip cleanly when key is absent (adapter leaf).
- Never put keys in fixtures, README examples, or scoreboards.

## What this is not

- Not a full SaaS crawl product comparison.
- Not a guarantee against every bot manager or WAF.
- Not a substitute for relay L0–L5 authenticity verification on production tasks.
