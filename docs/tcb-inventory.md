# Minimized basecrawl CVM TCB inventory

This document enumerates the **measured trusted computing base (TCB)** of the
digest-pinned `basecrawl` CVM image. The TCB is kept deliberately small so a
Chromium/OS CVE can be remediated by a reproducible image rebuild and an atomic
measurement rotation rather than by re-auditing an unbounded dependency tree.

Authenticity remains **cryptographically-anchored trust-but-audit**. A
measurement match proves the quoted registers equal a pinned repro image; it
does not by itself prove that Chromium/OS code is free of unpatched 0-days.

## Minimized TCB surfaces (in-measurement)

| Surface | Pinning mechanism | Notes |
| --- | --- | --- |
| Application binary (`basecrawl`) | Built from this repository with `Cargo.lock` and `cargo build --release --locked` | Source + lockfile are part of the image build context |
| Rust build toolchain | `rust:1.96.0-bookworm@sha256:…` (Dockerfile digest pin); `RUST_VERSION=1.96.0` checked at build | No floating `rust:latest`, no runtime `rustup` |
| Chromium browser builds | Puppeteer runtime image `ghcr.io/puppeteer/puppeteer:24.37.2@sha256:…` plus fixed `CHROMIUM_VERSION=145.0.7632.46` (**major 145**) and fixed `CHROME=…/linux-145.0.7632.46/…` path | Chromium + complete OS dependency set come from this **one** digest-pinned image. Residual: public Chrome majors move faster; detectors can track lag vs major 145 until the image pin rotates (see SECURITY residual table). Hard-path product UA/CH-UA stay major-coherent with this pin. |
| Runtime OS deps for Chromium | Supplied by the same digest-pinned Puppeteer image | Dockerfile never runs `apt`/`apk` install or `playwright install --with-deps` |
| Guest OS / hypervisor measurement inputs | Phala `dstack-0.5.9-bd369a8c` / `os_image_hash` pinned in `image/allowlist.json` and catalog metadata | Measured via `dstack-mr` MRTD/RTMR0-2 |
| App compose identity | Digest-pinned Compose image ref + Phala `app-compose.json` hash (`compose_hash`) | RTMR3 is runtime; validators replay the signed event log for `compose-hash` |
| VM shape | RTMR0 includes vCPU/memory for the fixed `tdx.small` shape | Changing shape requires a new allowlist entry |

## Explicitly excluded / forbidden in the measured image

- Floating base tags (`:latest` without digest, unpinned `FROM` stages).
- Unpinned toolchains (`rustup` at build, unpinned node/cargo channels).
- Build-time `playwright install --with-deps` or any host package-manager install of browsers.
- Runtime package installs that would change OS cookies after the image is digest-pinned.

## Files that encode the pins

- `image/Dockerfile` — digest-pinned builder + runtime, fixed Chromium version, locked cargo build.
- `image/docker-compose.yml` — digest-pinned `docker.io/mathiiss/basecrawl-cvm@sha256:…`.
- `image/allowlist.json` — validator-facing exact six-field measurement tuple.
- `image/phala-app-compose.json` — Phala app-compose whose hash is the allowlisted `compose_hash`.
- `image/measurement_allowlist.py` / `image/reproducibility.py` — fail-closed reproduction checks.

## Out of TCB (intentionally)

- The **miner host** (untrusted). Host sees sealed ciphertext only under the confidentiality path.
- Optional **LLM/extract** gateways used outside the quorum-critical authenticity path.
- The open-web **origin** and its certificate lifecycle (checked at L2, not part of the enclave TCB).

## Acknowledged residual: measured-but-exploited Chromium/OS 0-day

A Chromium or OS **0-day** that is still present in a currently allowlisted measurement can
attest **cleanly** (L1 pass) while the enclave process is exploited. Measurement allowlisting
detects *image identity drift*, not unknown vulnerabilities inside an already-pinned image.

**Backstop:** tier-driven **replay-audit sampling** on the validator administration plane
(`relay.scoring.replay_audit`) re-runs sampled attempts on the validator broker and flags
over-tolerance mismatches for adjudication. High-trust attested submissions are sampled at the
configured attested rate (~2% by default); low-trust / unverified submissions at a strictly
higher rate (~10% by default). Replay-audit does not claim to catch every 0-day; it is the
documented residual backstop until the CVE is patched and the image measurement is rotated
(see `docs/image-rotation-on-cve.md`).

The residual is never hidden: authenticity is cryptographically-anchored trust-but-audit, not
an absolute TEE claim.

## TEE.fail residual (self-hosted) + managed-cloud mitigation

Separately from Chromium/OS 0-days, **TEE.fail** residual remains on **self-hosted**
hardware: a **DDR5 bus interposer can forge quotes and read enclave memory**, and
there is **no vendor fix**. That residual degrades both quote authenticity and
content-confidentiality for self-hosted deployments. The operational mitigation is
**managed-cloud** placement (e.g. Phala TDX) where the miner has no bus access;
relay further weights and audits accordingly. Full wording lives in `docs/SECURITY.md`.
