# Security and residual risks

Threat model for the basecrawl crawler image and SDK. States the honesty model and the **TEE.fail** residual with managed-cloud mitigation. Companions: [tcb-inventory.md](tcb-inventory.md), [image-rotation-on-cve.md](image-rotation-on-cve.md), [TRUST_MODEL.md](TRUST_MODEL.md), [architecture.md](architecture.md).

## Trust model

Authenticity is **cryptographically-anchored trust-but-audit**. A scrape is authentic under:

- TEE vendor honest **and** host not physically compromised; **or**
- honest witness + clean network path; **or**
- honest-majority audit + slashing.

Do not claim absolute authenticity for this engine. Security enforcement is the verifier (L1 measurement allowlist + L2 report_data binding), not merely shipping the binary. A bare SDK outside an allowlisted TEE proves nothing.

## Absolute TEE claims are forbidden

Do not claim absolute TEE security for basecrawl or companion platforms. Prefer precise residual wording over absolute-trust vocabulary.

## TEE.fail residual (explicit)

**Residual:** a self-hosted DDR5 bus interposer can forge quotes and read enclave memory. There is no vendor fix. When operators self-host the CVM, a physical interposer adversary can undermine both quote authenticity and content-confidentiality.

**Managed-cloud mitigation:** run high-reward and confidential workloads on a managed-cloud TEE (for example Phala TDX) where the operator does not control bus access. Consumer scoring may weight managed-cloud higher and audit self-hosted harder. This does not make the TEE absolute; it is the operational answer to the residual while authenticity remains cryptographically-anchored trust-but-audit.

## Measured TCB and Chromium 0-day residual

The measured TCB is minimized and enumerated in [tcb-inventory.md](tcb-inventory.md). Measurement matching proves image identity, not that Chromium/OS code is free of unknown vulnerabilities. A measured-but-exploited residual is acknowledged; the backstop is replay-audit sampling plus the image rotation runbook in [image-rotation-on-cve.md](image-rotation-on-cve.md).

## Content-confidentiality only

On the sealed/TEE path, basecrawl aims for **content-confidentiality** (host does not see path/query/headers/cookies/body/result plaintext), not target-anonymity. Destination IP, SNI (absent ECH), DoH resolver destination, and traffic metadata remain expected residual leakage to a proxy-operating host.

## Proxy, composer, and stealth residual

Universal proxy support (HTTP CONNECT / SOCKS5, sticky/session and country username tokens) and the Chromium hard-path composer improve operational success. They do **not** make scrapes anonymous, and they do not defeat every commercial bot system. Proxy is **not anonymity**: exit operators and networks still see destination and traffic shape.

### Challenge detect, not captcha solve

Unlocker-depth improves hard-path identity baseline (CDP injects, fingerprint depth, soft TLS vibe for soft targets only). Default challenge posture remains **detect + fail-closed** (`challenge_blocked`) without a solver key. Operators and miners may **optionally** enable CapSolver (`CAPSOLVER_API_KEY` or `BASECRAWL_CAPSOLVER_API_KEY` + `--captcha-solver capsolver` / `BASECRAWL_CAPTCHA_SOLVER=capsolver`) for supported Turnstile classes via `createTask`/`getTaskResult`; soft CI never requires that key. Multi-vendor marketplaces (2captcha / Anti-Captcha / CapMonster) are **not** integrated. Optional CapSolver **does not** equal commercial Web Unlocker feature-parity (Bright Data Web Unlocker / Oxylabs captcha-manage style "unlock any site" products), never forges content_success without an applied solution token, and never logs the API key. Success remains scrape identity and egress honesty only.

Optional live residual smoke (gated by `BASECRAWL_LIVE_PROXY=1`, max one concurrent residential dial, secrets only from gitignored `.env`) is **identity/egress residual only**. With the gate off, live residual cases skip cleanly and hermetic residual honesty remains primary. Live residual never requires captcha marketplace keys and never claims unlocker parity.

### Hard-shield residual (CF / Turnstile / Akamai families)

Hard-site classification must stay richer than bare HTTP 200. Cloudflare managed / Turnstile residual (including public probes such as `https://taostats.io/`) surfaces as managed challenge / turnstile / `challenge_blocked` classes when only the interstitial is present; sandwich text is not maxed content success. Akamai Bot Manager vibes, DataDome / PerimeterX marketing surfaces, and similar shield families remain **residual**: the engine documents them for research probes and does **not** claim commercial unlocker parity, hide-from-bot-manager guarantees, or complete defeat of every WAF. Proxy CONNECT/ACL failures remain dial residuals, not origin classification.

### Soft impersonate vs hard Chromium (identity split)

| Path | What it is | What it is not |
| --- | --- | --- |
| Soft (`--no-js`, optional `--tls-impersonate chrome`) | In-process rustls fetch; optional Chrome-like ClientHello suite/group offer; complete cert + handshake transcript capture for ScrapeProof | **Not** native Chromium wire/packet identity; soft successes emit `fetch_path=direct` and soft digests label `soft_synthetic_impersonate` |
| Hard (residential/mobile, `--difficulty hard`, `--force-browser`) | Real headless Chromium TLS/H2 + DOM + composer; required when residential/mobile is claimed | Soft preflight triage may still run first (dual-fetch timing residual); soft never satisfies residential seize |

Never conflate soft JA3-family alignment with hard Chromium wire identity.

| Residual | Notes |
| --- | --- |
| Upstream proxy operator | Sees exit traffic to origins; credentials must stay env-only, never in proofs or logs. |
| Network metadata | Even with sealed DoH on the hard path, traffic shape and destination residual exist outside content confidentiality. |
| Headless detection residual | Hard path launches Chromium with `--headless=new` (when the pin supports it) and baseline stealth (drop automation flags, early inject). Headless remains the default; residual headless heuristics, GPU-less surfaces, and automation detectors may still classify the client. Absolute cross-detector headless cloaking is out of scope. |
| CDP / Runtime protocol residual | The Chrome DevTools Protocol path can still call into Runtime APIs for automation work. Even when classic automation flags and early-document injects are mitigated, a **Runtime.enable** (or equivalent CDP Runtime) side channel may remain observable to sophisticated detectors. This residual is documented rather than claimed eliminated. |
| Challenge / captcha residual | Detect-not-solve default. Optional CapSolver for Turnstile only when a miner/operator key is present; unsupported classes and missing keys stay fail-closed. No multi-vendor marketplace set; no commercial unlocker parity claim. |
| CF / Turnstile residual | Managed challenge and Turnstile interstitials classify beyond HTTP 200; sandwich HTML is not content unlock without an applied solution token. Public CF residual examples (including taostats) stay residual without forged unlock. |
| Akamai / Bot Manager residual | Akamai Bot Manager and sibling families remain residual on hard commercial endpoints. Marketing-page probes do not equal unlock SLA; residual risk is expected. |
| Chromium major pin residual | Measured image pins **Chromium major 145** (`CHROMIUM_VERSION=145.0.7632.46`). Detectors and vendor rules can track lag vs the current public Chrome major. Hard-path UA / Sec-CH-UA / CDP overrides stay major-coherent to this single pin (no 145-vs-148 product drift). A pin bump must update image pin + residual note together. |
| Plugin / mimeTypes residual | Hard-path inject exposes a multipass Chromium-style PDF plugin inventory and matching `mimeTypes` (not a single-PDF-only stub). This is a **name surface** only; it does not emulate full NPAPI/PDF internals and detectors can still score plugin quirks. |
| Canvas diversity residual | Seeded canvas pixel noise is **best-effort diversity**, not cryptographic anonymity and not un-fingerprintability. Same seed stays finite/non-crashing; different seeds may diverge. Do not market canvas spoof as anonymity. |
| Font inventory residual | Product does **not** implement a complete OS font inventory spoof or full font anonymity. Font enumerations, `document.fonts`, and related detectors remain residual; do not advertise complete font spoofing. |
| Screen / memory residual | Injected `screen` geometry is coherent with the seed viewport (positive, non-zero, screen ≥ viewport) and `deviceMemory` is finite positive from an allowlist when exposed. GPU-less or virtualized hosts can still fail secondary screen heuristics. |
| WebGL depth residual | Hard-path inject returns a seeded UNMASKED vendor/renderer pair and a coherent `WEBGL_debug_renderer_info` extension surface (getParameter + getExtension + supported list). This is **GPU-plausible name diversity**, not hardware anonymity; GPU-less/SwiftShader host residual and extension quirks remain detector-visible. |
| OfflineAudio / audio residual | OfflineAudioContext may still fingerprint. Product applies at most best-effort seed-bounded channel diversity when APIs exist; it does **not** claim audio anonymity or a complete Offline-audio defeat. Residual detector risk is expected. |
| WebRTC residual | Hard path forces WebRTC IP handling policy (`disable_non_proxied_udp`) and inject redacts host/LAN ICE candidates so private addresses do not enter page capture/ScrapeProof. Constructor presence, SDP shape, and non-host candidate classes may still residual-leak. |
| iframe surface residual | `Page.addScriptToEvaluateOnNewDocument` re-applies the stealth inject per new document (including same-origin iframes) so `chrome` / `webdriver` stay parent-coherent. Cross-origin frames, closed shadow roots, and timing races remain residual. |
| Class forgery | Product fails closed when residential/mobile is required but upstream is unavailable; never advertise a forged class on success. |
| Soft TLS chrome-impersonate residual | Soft path may align rustls ClientHello suite/group offer toward a documented Chrome-like profile (`--tls-impersonate chrome`). This is stronger than pure seed suite reorder for JA3-family bootstrap, still **in-process** (cert/transcript capture stays complete). Soft digests are labeled `soft_synthetic_impersonate` (**not** native Chromium wire/packet capture). Soft succeeds keep `fetch_path=direct` and never claim residential without a dialed residential proxy. Hard/residential seize still requires real Chromium. Invalid profiles fail closed. Residual GREASE/ALPS/HTTP2 settings fingerprints and modern edge detectors remain. Not undetectable. |
| Dual-fetch / soft-preflight timing residual | On hard Chromium targets the engine still performs a **soft rustls document preflight** (redirect/robots/challenge triage, seq=1) before launching Chromium for identity capture (seq=2). That dual-stack timing residual is intentional and documented: soft preflight content is **never** sold as a hard residential Chromium success (`fetch_path` remains `chromium` only when Chromium actually ran; challenge interstitials on soft preflight terminate as `challenge_blocked`). Do not claim single-handshake-only Chromium while this soft preflight remains. Batch soft+hard mixes keep per-item `fetch_path` / class honesty. |

Operator flag reference: [operators/proxy-and-egress.md](operators/proxy-and-egress.md).

## Structured extract residual

`--formats json` is request syntax only when no live extractor/provider is configured. The engine reports structured `structured_extraction_unsupported` / `invalid_json_schema` rather than inventing schema fields. Optional provider keys (`BASECRAWL_EXTRACT_API_KEY`, `OPENAI_API_KEY`) do not authorize empty fake success. See [operators/product-breadth-and-extract.md](operators/product-breadth-and-extract.md).

## Operator checklist

1. Prefer managed-cloud placement for confidential scrapes.
2. Keep image builds reproducible and digest-pinned; rotate on CVE per [image-rotation-on-cve.md](image-rotation-on-cve.md).
3. Never advertise absolute-trust language in tooling or docs (no "undetectable", trustless scrape claims, complete unlock SLA language, or anonymity guarantees).
4. Keep proxy, CapSolver, and LLM/extract keys in gitignored env files (mode `600`); never in ScrapeProof, scoreboards, or CI logs. CapSolver how-to: [operators/proxy-and-egress.md](operators/proxy-and-egress.md).
5. Treat residential success as topology improvement, not anonymity. Live Oxylabs-style residential: max **1** concurrent dial under `BASECRAWL_LIVE_PROXY=1`.
6. Default challenge posture is detect-not-solve; enable CapSolver only when you accept account cost and residual re-challenge risk.
