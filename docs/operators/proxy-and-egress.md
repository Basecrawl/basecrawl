# Operator guide: universal proxy, composer, and stealth

How to configure commercial egress, understand the Chromium proxy composer, and use the hard-path stealth baseline. This is **configuration and residual risk**, not a claim of anonymity or automated defeat of every bot vendor.

Companions: [Architecture](../architecture.md), [Security](../SECURITY.md), [Trust model](../TRUST_MODEL.md).

## What this path is for

| Goal | Supported approach |
| --- | --- |
| Soft targets, no JS | Direct rustls fetch; optional HTTP CONNECT / SOCKS5 proxy |
| Hard / residential / JS | Chromium path with optional loopback proxy **composer** (sealed DoH, then upstream) |
| Sticky exit hop | Provider-agnostic username session tokens (`sessid`) |
| Country preference | Provider-agnostic username country tokens (`cc`) |

Proxy and stealth improve success on difficult origins. They are **not** anonymity and **not** a warranty against commercial bot detection.

## Universal proxy flags

Provider-agnostic. Any `http(s)://user:pass@host:port` CONNECT or `socks5://user:pass@host:port` URL works. Residential vendors such as Oxylabs are a live fixture, not a hard product dependency.

| Flag | Purpose |
| --- | --- |
| `--proxy <URL>` | Explicit proxy URL (overrides ambient env when set) |
| `--proxy-session <ID>` | Sticky session id embedded in the username template |
| `--proxy-country <CC>` | Country token (e.g. `US`) for supported providers |
| `--proxy-username-template <T>` | Full dial-time username template (`{user}`, `{country}`/`{cc}`, `{session}`/`{sessid}`) |
| `--proxy-class <CLASS>` | Declared class: `direct` \| `datacenter` \| `residential` \| `mobile` |

Ambient env (when `--proxy` is omitted), first match wins in product resolution order:

- `BASECRAWL_HTTP_PROXY` / `BASECRAWL_HTTPS_PROXY`
- `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`

### Username template defaults

When country/session are set without a full template, dial identity appends:

```text
{user}-cc-{country}-sessid-{session}
```

Supported placeholders for `--proxy-username-template`: `{user}` / `{username}`, `{country}` / `{cc}`, `{session}` / `{sessid}`.

Prebuilt env usernames already carrying `-cc-US` (or `-sessid-…`) are **stripped to the customer base** before re-applying country/session tokens, so operators do not accidentally double-decorate to `…-cc-US-cc-US`.

Example embedding (provider-specific host, product syntax stays generic; secrets stay env-only):

```bash
# Use a real http://user:pass@host:port URL only in a mode-600 gitignored .env; never paste passwords into shells or docs.
export BASECRAWL_HTTPS_PROXY   # load from .env with set -a; . ./.env; set +a
basecrawl \
  --proxy-session my-session-1 \
  --proxy-country US \
  --proxy-class residential \
  --formats markdown,metadata \
  https://example.com/
```

`BASECRAWL_HTTP_PROXY` / `BASECRAWL_HTTPS_PROXY` construction accepts standard
`http(s)://user:pass@host:port` userinfo. Live residential max concurrency is **1**
when `BASECRAWL_LIVE_PROXY=1` arms commercial dials.

### Class honesty

- Emitted ScrapeProof `egress.proxy_class` reflects the **actual dial path**, not a wish list.
- Commercial classes (`residential`, `mobile`) without a contactable upstream **fail closed**. The engine never emits a success proof that claims residential while dialing direct.
- Credentials never appear in ScrapeProof, attestation material, or host-safe error payloads. Keep secrets in a **gitignored** `.env` or OS secret store (mode `600` recommended).

## Chrome proxy composer (hard path)

```mermaid
flowchart LR
  CHR[Chromium document path]
  SOCKS[Loopback SOCKS accept]
  DoH[Sealed DoH pin]
  UP[Upstream CONNECT or SOCKS]
  Origin[Origin site]

  CHR --> SOCKS
  SOCKS --> DoH
  DoH --> UP
  UP --> Origin
```

On the hard Chromium path, the in-process **composer**:

1. Accepts SOCKS from Chromium on a loopback port (not your commercial proxy host).
2. Resolves the target with sealed DoH so the **host** DNS path does not see confidential origin QNAMEs.
3. Dials the configured upstream proxy with CONNECT/SOCKS after PIN-style IP connect.

Bind or start failure under a **required** residential/mobile class fails closed (`dns_isolation` / proxy class unavailable) rather than falling back to un-proxied success.

## Stealth identity (hard path)

| Knob | Effect |
| --- | --- |
| `--proxy-class residential\|mobile` | Forces Chromium hard identity |
| `--difficulty hard` | Forces Chromium even if class is soft |
| `--force-browser` | Explicit hard path regardless of soft class |
| `--keep-browser-profile` | Keep sticky profile on disk (default: wipe at end of task) |
| `--no-js` | Soft path only; refused when hard class requires Chromium |

Baseline launch hardening (not a universal cloak):

- Prefer `--headless=new` on the product pin (Chrome 112+; pin is Chromium **145**)
- Drop automation-oriented flags; early inject forces `navigator.webdriver` false before content probes
- Align UA / CH-UA / CDP `userAgentMetadata` with the **single pinned Chromium major** in the CVM image (no neighbor-major drift)
- Sticky profile keyed by task/session; wipe across tasks by default
- Challenge / block interstitials surface as structured `challenge_blocked` rather than silent success

Do not market this as "undetectable" or "defeats all bot vendors." It is an identity baseline under TDX with residual headless, CDP/Runtime, and vendor-heuristic risk. Soft rustls ClientHello chrome-impersonate (`--tls-impersonate chrome`) is **not** the hard Chromium wire; it never upgrades soft scrapes to `fetch_path=chromium` or residential without a real dial.

## Soft impersonate vs hard Chromium (operator identity split)

| Identity | Flags / trigger | Wire reality | ScrapeProof honesty |
| --- | --- | --- | --- |
| Soft path | Default soft targets, `--no-js`, optional `--tls-impersonate chrome` | In-process **rustls** only. Chrome-like ClientHello suite/group offer is **not** native Chromium wire/packet capture | Soft success keeps `fetch_path=direct`; digests labeled soft_synthetic_impersonate; never claims residential without dialed residential |
| Hard path | `--proxy-class residential\|mobile`, `--difficulty hard`, `--force-browser` | **Real Chromium** TLS/H2 + DOM + loopback composer | `fetch_path=chromium` only when Chromium actually ran |

Soft JA3-family alignment is for bootstrap/success-rate on soft targets. Residential seize and hard-site identity still require real Chromium. Soft race + hard bash never invent a hybrid residential soft prove.

### Challenge stance (not commercial Web Unlocker)

Default challenges and captcha pages are **detect-not-solve** (`challenge_blocked`). Soft CI and soft open-web profiles **never** require a captcha marketplace key. There is **no** commercial Web Unlocker feature-parity claim (not Bright Data Web Unlocker / Oxylabs captcha-manage style "unlock any site"). Treat residual blocks as operational signal, not a defect in silence.

Hard-path examples such as Cloudflare managed / Turnstile on public marketing or research targets (for example `https://taostats.io/`) should classify as **managed challenge / turnstile residual** (or a sibling `challenge_blocked` class), not as maxed content success on interstitial HTML alone.

### Optional CapSolver (operator and miner key; fail-closed)

Operators and miners may optionally inject a CapSolver client key for supported Turnstile/CF classes. Soft dual-engine paths and default CI stay green **without** any solver key.

| Surface | Value |
| --- | --- |
| Env (preferred) | `CAPSOLVER_API_KEY` or `BASECRAWL_CAPSOLVER_API_KEY` in gitignored `basecrawl/.env`, mode `600` |
| Provider select | `BASECRAWL_CAPTCHA_SOLVER=capsolver` and/or CLI `--captcha-solver capsolver` |
| Timeout | `--captcha-solve-timeout SECONDS` (default 90) |
| Supported classes | Turnstile → CapSolver `AntiTurnstileTaskProxyLess` (`createTask` + `getTaskResult`) |
| Unsupported classes | Typed residual; fail closed; never invent content success |

#### How-to: miner / operator CapSolver key

1. Create a CapSolver client key in your CapSolver dashboard (never paste it into chat, tickets, or ScrapeProof).
2. Write it only into a **gitignored** env file on the miner host (example path `basecrawl/.env`), then lock down permissions:

```bash
# miner host: secrets only; never commit this file
umask 077
cat >> basecrawl/.env <<'EOF'
CAPSOLVER_API_KEY=YOUR_CAPSOLVER_CLIENT_KEY
BASECRAWL_CAPTCHA_SOLVER=capsolver
EOF
chmod 600 basecrawl/.env
```

3. Load the env into the miner process (dotnet-style process supervisor, systemd `EnvironmentFile`, or `set -a; . ./basecrawl/.env; set +a` for one-off shells). Prefer env injection over CLI argv so the key never lands in shell history or process listings with long argv.
4. Arm the hard path for challenge pages (residential or forced browser). Example:

```bash
set -a; . ./basecrawl/.env; set +a
basecrawl \
  --captcha-solver capsolver \
  --force-browser \
  --formats markdown,html,metadata \
  --timeout 90 \
  https://example.com/
```

5. Optional residential stickiness (provider URL stays env-only; class is honest):

```bash
export BASECRAWL_HTTPS_PROXY='http://USER:PASS@proxy.example:7777'
basecrawl \
  --captcha-solver capsolver \
  --proxy-class residential \
  --proxy-country US \
  --proxy-session miner-sess-1 \
  --formats markdown,metadata \
  https://example.com/
```

**Without a key:** product stays detect-not-solve (`challenge_blocked`); no CapSolver network calls; soft CI green.

**With a key:** createTask/getTaskResult may run for supported classes. HTTP 401 / invalid key / unpaid / timeout / empty token → typed fail-closed (`solver_auth_error` / `solver_timeout` / `solver_error`); **never** forge `content_success`. A returned token must still be applied through the hard-path challenge completion flow before any content_success claim.

**Never** log, print, or commit the CapSolver API key (not in ScrapeProof, scoreboards, or host-visible stderr). Readiness `getBalance` probes that return HTTP 401 indicate key/account problems: remain fail-closed and fix the key format/account offline; never unlock content from a failed balance probe.

**Honesty residual:** optional CapSolver does **not** equal commercial Web Unlocker parity, not a complete unlock SLA, and not "undetectable" browsing. Multi-vendor marketplaces (2captcha / Anti-Captcha / CapMonster) are **not** integrated. Soft dual-engine / default CI remain free of solver keys.

### Oxylabs residential (live fixture, not hard dependency)

Oxylabs residential is the **live** residential fixture for sticky upper-bound smoke, not an Oxylabs-only product.

| Topic | Operator rule |
| --- | --- |
| Endpoint fixture | `pr.oxylabs.io:7777` (or any standards-compliant CONNECT/SOCKS URL of the same shape) |
| Auth | user:pass only in mode-`600` gitignored `.env` (`BASECRAWL_HTTP_PROXY` / `BASECRAWL_HTTPS_PROXY`) |
| Country + sticky | `--proxy-country US` + `--proxy-session <id>` or supply provider username tokens (`-cc-US`, `-sessid-…`) |
| Class | `--proxy-class residential` (forces Chromium hard identity) |
| Live gate | `BASECRAWL_LIVE_PROXY=1` for provider costs; **max 1 concurrent** residential dial family |
| Fail closed | Required residential without dialable upstream → typed dial residual, never residential success on direct outbound |

Template construction is provider-agnostic. Prebuilt env userinfo that already includes `-cc-US` is stripped to the customer base before re-applying country/session tokens so operators do not double-decorate.

### CF / Turnstile / Akamai residual (hard-shield honesty)

| Shield family | What basecrawl does | Residual |
| --- | --- | --- |
| Cloudflare managed / Turnstile | Detect interstitial markers; optional CapSolver Turnstile path when configured | Default **detect-not-solve**. Challenge sandwich HTML is not content unlock. Public targets under this family (for example taostats) must not score maxed content on pure "Just a moment…" / Turnstile glue. |
| Cloudflare marketing pages | Low-volume probe only | Marketing HTML may look soft while product bots remain proprietary residual. |
| Akamai Bot Manager family | Classify residual; marketing pages only as medium research probes | No Akamai-solve marketplace; no claim of hide-from-Akamai success; residual risk remains on hard commercial endpoints. |
| DataDome / PerimeterX families | Documented medium research probes only | Same honesty ceiling: identity + egress only, not commercial unlocker parity. |

Hard-path scenarios are identity, dial honesty, and classification honesty. They are **not** a warranty that every bot manager is defeated.

### Gated live residual smoke (identity/egress only)

Optional live residential residual smoke (`BASECRAWL_LIVE_PROXY=1`, max **1** concurrent dial family) exercises modern hard-path identity and truthful egress labels only. Secrets load from gitignored `.env` / process env (mode `600`). With the gate **off**, live residual cases **skip cleanly**; hermetic residual honesty stays primary. Live residual outcomes **never** claim commercial unlocker parity and **never** require a CapSolver key for the default residual gate.

### CONNECT residual vs origin challenge

Upstream HTTP CONNECT failures are **dial residuals**, not origin bot-challenge classification:

| CONNECT status | Product kind / failure_class | Not |
| --- | --- | --- |
| 407 / 401 | `proxy_auth_error` | `challenge_blocked` |
| 403 | `transport_error` / `proxy_acl_error` (destination or product ACL) | Cloudflare / origin challenge |
| other non-200 | `transport_error` / `proxy_connect_error` | content_success with residential claim |

A residential CONNECT 403 on a hard target while geo endpoints return CONNECT 200 is a **product/destination ACL residual**, not evidence that origin Cloudflare alone defeated residential scrapes. Origin challenge markers apply only after CONNECT establishes and an origin body is in hand. Mission diary (untracked): `.docs-evidence/hard-shield/`.

## Residual risks (operator)

| Residual | Operator stance |
| --- | --- |
| Proxy ≠ anonymity | Exit IP, SNI (without ECH), and traffic shape remain visible to the upstream proxy and networks. Proxy is not anonymity. |
| Headless residual | Headless is default (`--headless=new`). Such traits remain detectable; sticky profiles and residential egress only raise the bar. Do not advertise perfect headless cloaking. |
| CDP Runtime residual | CDP/Runtime protocol use (including possible Runtime.enable side effects) is a residual channel even when trivial automation flags are patched. Documented in [SECURITY.md](../SECURITY.md). |
| Challenge detect residual | Default detect + fail-closed. Optional CapSolver may createTask/poll Turnstile with a miner key but is not commercial unlocker parity and never forges unlocked content on auth/timeout. |
| CF / Turnstile residual | Managed challenge / Turnstile interstitials stay residual without a solved+applied token; also residual after some solved tokens if vendor re-challenges. |
| Akamai residual | Akamai Bot Manager heuristics, bot lists, and edge captchas remain residual. Product documents medium marketing probes only; no Akamai unlock SLA. |
| Soft TLS residual | Soft impersonate is not Chromium wire; residual GREASE/ALPS/H2 setting fingerprints remain. Hard path only for residential. |
| Chromium major residual | Pin is major **145** (`145.0.7632.46`). Detectors can track lag vs newer public Chrome; keep hard-path majors coherent when the pin moves. |
| Plugins / mimeTypes | Multipass PDF plugin names + non-empty `mimeTypes` improve trivial bot ranks only. Not full plugin/PDF API fidelity. |
| Canvas | Canvas seed noise diversifies render digests; it is not anonymity and never claims un-fingerprintability. See [SECURITY.md](../SECURITY.md). |
| Fonts | No complete OS font inventory spoof; font residual remains. Do not market full font anonymity. |
| Permissions | `permissions.query({name:'notifications'})` is aligned with `Notification.permission` when both exist; other PermissionName values are residual. |
| TEE.fail (self-hosted) | Physical DDR5 interposer residual; prefer managed-cloud TDX for high-stakes confidential work. See [SECURITY.md](../SECURITY.md). |
| Network metadata | Sealed DNS / content confidentiality do not erase all host-owned network observables. |
| Dual-fetch timing residual | Hard Chromium runs still start with a soft rustls document preflight (challenge triage / redirects) before the browser identity capture. Residual multi-handshake timing may be detector-visible. Soft preflight content is never labeled as residential Chromium success; see [SECURITY.md](../SECURITY.md). |
| Provider spend | Live residential sessions cost money; use sticky short sessions and rate limits. Max **1** concurrent live residential dial under the live gate. |

## Quick examples

```bash
# Soft path + datacenter-class CONNECT (load secrets from mode-600 .env; never CLI history)
set -a; . ./basecrawl/.env; set +a   # provides BASECRAWL_HTTPS_PROXY when needed
basecrawl --proxy-class datacenter --no-js \
  --formats markdown,metadata https://example.com/

# Hard path identity forced for a soft class site
basecrawl --force-browser --formats html,markdown https://example.com/

# Residential class fails closed if proxy cannot dial (honest error on stderr)
basecrawl --proxy-class residential --formats markdown https://example.com/

# Optional CapSolver (miner .env already loaded; still detect-not-solve without key)
basecrawl --captcha-solver capsolver --force-browser \
  --formats markdown,html https://example.com/
```

For structured JSON extract gating, product breadth (`--mode crawl|map|batch`, POST/body), and residual extract honesty, see [product-breadth-and-extract.md](product-breadth-and-extract.md).
