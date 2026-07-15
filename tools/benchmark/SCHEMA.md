# Common Normalized Result Schema

Version: **1.0.0**

Adapters for **basecrawl** and **Firecrawl** normalize vendor-native payloads into this schema before scoring. Live scoreboards are written only under gitignored `.docs-evidence/benchmark/`. This document is the tracked contract for VAL-BENCH-005 / VAL-BENCH-031.

## Required fields

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | string | Currently `"1.0.0"` |
| `url` | string | Target URL |
| `engine` | string | `basecrawl` \| `firecrawl` |
| `profile_id` | string | Matrix profile id (e.g. `P1-soft-basecrawl`) |
| `formats_requested` | string[] | Formats asked of the engine |
| `formats_produced` | string[] | Formats actually emitted |
| `http_status` | int \| null | Raw HTTP status when known |
| `status_class` | string | e.g. `2xx`, `4xx`, `timeout`, `unknown` |
| `challenge_class` | string | See enum below (beyond bare HTTP) |
| `content_success` | bool | Adapter claim; scorer still applies substance heuristics |
| `latency_ms` | number \| null | Wall time for the scrape attempt |
| `cost_estimate` | object | Dual-engine cost placeholders (nulls allowed with notes) |
| `error_class` | string | `none` or typed failure class |

## Optional / recommended fields for re-score

| Field | Type | Notes |
| --- | --- | --- |
| `scoring_role` | string | `scoring` (default), `ceiling`, `research` |
| `markdown_body` \| `markdown_path` | string | Retained for markdown quality re-score |
| `html_body` \| `html_path` | string | Optional HTML/rawHtml body |
| `links` \| `links_path` | string[] / path | Retained for links quality re-score |
| `fetch_path` | string | `direct` \| `chromium` \| `cloud` \| `unknown` |
| `proxy_class` | string | Engine/path class label (never claim residential without dial) |
| `expected_min_links` | int | Target expectation for links scorer |
| `js_target` | bool | When true, JS-render dimension is active |
| `proof_present` | bool | basecrawl ScrapeProof envelope present |
| `attestation_present` | bool | Live TEE quote present |
| `identity_notes` | string | Non-secret commentary |
| `metadata` | object | Non-secret adapter diagnostics only |

### `cost_estimate` object

```json
{
  "firecrawl_credits": null,
  "firecrawl_usd_estimate": null,
  "basecrawl_cpu_ms_placeholder": null,
  "basecrawl_proxy_usd_estimate": null,
  "notes": "reason when null"
}
```

Both engines should leave the other side null with notes rather than invent forced zeros.

## `challenge_class` values

`none`, `challenge_blocked`, `managed_challenge`, `turnstile`, `interstitial`, `captcha_surface`, `login_wall`, `unknown_soft_block`, `engine_unavailable`, `credential_error`, `budget_exhausted`, `medium_optional_skipped`, `hard_optional_skipped`, `network_error`, `timeout`, `unknown`

**Hard-shield note (M23):** Cloudflare challenge-platform / Turnstile sandwiches
(`Checking your Browser…`, `cdn-cgi/challenge-platform`, `cf-turnstile`) classify as
`managed_challenge` or `turnstile`. Adapters may still emit HTTP 200 / vendor API success;
the scorer forces `content_success ≈ 0` and penalizes `interstitial_false_success` for these
classes. Firecrawl `enhanced` rows keep `scoring_role=ceiling` (non-parity).

## `error_class` values

`none`, `transport`, `timeout`, `credential_error`, `budget_exhausted`, `engine_unavailable`, `challenge_blocked`, `policy_skip`, `parse_error`, `unknown`

## Fair core formats

Scoring profiles request only:

- `markdown`
- `html` **or** `rawHtml`
- `links`

**Excluded from core WIN/LOSS:** LLM `json`/`extract`/`summary`/`branding`/`product`, Firecrawl **interact**, agent runs, map/search-as-success. Optional screenshot is secondary and non-blocking.

See also [FORMATS.md](FORMATS.md) and [SCORING.md](SCORING.md).

## Sample (basecrawl soft)

See `fixtures/artifacts/soft-basecrawl-example.json`.

## Sample (Firecrawl basic)

See `fixtures/artifacts/soft-firecrawl-example.json`.

## Validation

```bash
cd tools/benchmark
python -m benchmark validate --path fixtures/artifacts/soft-basecrawl-example.json --require-body
```

No secrets belong in normalized artifacts, logs, or scoreboards.
