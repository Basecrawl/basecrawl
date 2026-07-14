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

Example embedding (provider-specific host, product syntax stays generic):

```bash
export BASECRAWL_HTTPS_PROXY='http://customer-USER:PASS@proxy.example:7777'
basecrawl \
  --proxy-session my-session-1 \
  --proxy-country US \
  --proxy-class residential \
  --formats markdown,metadata \
  https://example.com/
```

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

Challenges and captcha pages are **detect-not-solve** (`challenge_blocked`). There is **no captcha marketplace** integration and **no** commercial Web Unlocker feature-parity claim (not Bright Data Web Unlocker / Oxylabs captcha-manage style "unlock any site"). Treat residual blocks as operational signal, not a defect in silence.

## Residual risks (operator)

| Residual | Operator stance |
| --- | --- |
| Proxy ≠ anonymity | Exit IP, SNI (without ECH), and traffic shape remain visible to the upstream proxy and networks. Proxy is not anonymity. |
| Headless residual | Headless is default (`--headless=new`). Such traits remain detectable; sticky profiles and residential egress only raise the bar. Do not advertise perfect headless cloaking. |
| CDP Runtime residual | CDP/Runtime protocol use (including possible Runtime.enable side effects) is a residual channel even when trivial automation flags are patched. Documented in [SECURITY.md](../SECURITY.md). |
| Challenge detect residual | Detect + fail-closed. Not a captcha solve and not commercial unlocker parity. |
| Soft TLS residual | Soft impersonate is not Chromium wire; residual GREASE/ALPS/H2 setting fingerprints remain. Hard path only for residential. |
| Chromium major residual | Pin is major **145** (`145.0.7632.46`). Detectors can track lag vs newer public Chrome; keep hard-path majors coherent when the pin moves. |
| Plugins / mimeTypes | Multipass PDF plugin names + non-empty `mimeTypes` improve trivial bot ranks only. Not full plugin/PDF API fidelity. |
| Canvas | Canvas seed noise diversifies render digests; it is not anonymity and never claims un-fingerprintability. See [SECURITY.md](../SECURITY.md). |
| Fonts | No complete OS font inventory spoof; font residual remains. Do not market full font anonymity. |
| Permissions | `permissions.query({name:'notifications'})` is aligned with `Notification.permission` when both exist; other PermissionName values are residual. |
| TEE.fail (self-hosted) | Physical DDR5 interposer residual; prefer managed-cloud TDX for high-stakes confidential work. See [SECURITY.md](../SECURITY.md). |
| Network metadata | Sealed DNS / content confidentiality do not erase all host-owned network observables. |
| Dual-fetch timing residual | Hard Chromium runs still start with a soft rustls document preflight (challenge triage / redirects) before the browser identity capture. Residual multi-handshake timing may be detector-visible. Soft preflight content is never labeled as residential Chromium success; see [SECURITY.md](../SECURITY.md). |
| Provider spend | Live residential sessions cost money; use sticky short sessions and rate limits. |

## Quick examples

```bash
# Soft path + datacenter-class CONNECT (no secrets in CLI history: use env)
export BASECRAWL_HTTPS_PROXY='http://user:pass@proxy.example:3128'
basecrawl --proxy-class datacenter --no-js \
  --formats markdown,metadata https://example.com/

# Hard path identity forced for a soft class site
basecrawl --force-browser --formats html,markdown https://example.com/

# Residential class fails closed if proxy cannot dial (honest error on stderr)
basecrawl --proxy-class residential --formats markdown https://example.com/
```

For structured JSON extract gating, product breadth (`--mode crawl|map|batch`, POST/body), and residual extract honesty, see [product-breadth-and-extract.md](product-breadth-and-extract.md).
