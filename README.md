# basecrawl

Verifiable web scraping for platforms that need cryptographic scrape evidence.
Apache-2.0 Rust workspace that fetches content, captures TLS and render artifacts, and emits a canonical `ScrapeProof` with optional Phala TDX attestation binding.

## Workspace layout

| Crate / path | Role |
| --- | --- |
| `crates/basecrawl-core` | Crawler engine, CLI (`basecrawl`), fetch, formats, RTT echo, proof assembly |
| `crates/basecrawl-proof` | Canonical `ScrapeProof` wire types and serialization |
| `crates/basecrawl-render` | Headless Chromium render (patched `headless_chrome`) |
| `crates/basecrawl-seal` | Confidentiality: RA-TLS key-release, DoH/DoT DNS, sealed task decrypt, result seal, host-safe redaction |
| `crates/basecrawl-fp` | Seeded browser/TLS fingerprints (JA3/JA4, headers, UA/viewport/locale, canvas/WebGL) |
| `crates/basecrawl-ffi` | Stable C ABI for language bindings |
| `bindings/{python,node}` | Thin Python / Node SDK wrappers |
| `image/` | Digest-pinned CVM Dockerfile, compose, measurement tooling, mission evidence under `image/evidence/` |
| `docs/` | Trust model, security residuals, TCB inventory, CVE image-rotation runbook |

Workspace deps and edition are centralized in the root `Cargo.toml` (`edition = "2021"`, `rust-version = "1.96"`). `vendor/headless_chrome` is excluded from the workspace and patched via `[patch.crates-io]`.

## Build / run / test

Toolchain is pinned in `rust-toolchain.toml` (`1.96.0`, with `rustfmt` + `clippy`).

```bash
# full workspace check (incremental local builds keep CARGO_INCREMENTAL on by default)
cargo build

# release binary used by the CVM image
cargo build --release --locked --package basecrawl-core --bin basecrawl

# package-focused tests (prefer these over a full workspace test on small machines)
cargo test --package basecrawl-core
cargo test --package basecrawl-proof
cargo test --package basecrawl-seal
cargo test --package basecrawl-fp
cargo test --package basecrawl-render
cargo test --package basecrawl-ffi
```

Docker image builds force `CARGO_INCREMENTAL=0` for determinism; local incremental builds are fine outside the image.

## ScrapeProof and CLI

`basecrawl` scrapes a single URL and writes **exactly one** canonical `ScrapeProof` JSON object to stdout. On failure it writes a structured `{"error": ...}` object to stderr and exits non-zero (no partial proof on stdout).

```bash
# basic scrape (default formats: markdown,metadata)
basecrawl https://example.com/

# formats, budgets, task identity
basecrawl \
  --formats markdown,metadata,rawHtml \
  --task-id JOB-1 \
  --nonce once-abc \
  --timeout 60 \
  --max-body-bytes 10485760 \
  https://example.com/

# headless render controls
basecrawl --wait-for "#ready" --render-timeout 30 --viewport 1280x800 \
  --screenshot-full-page --screenshot-out /tmp/page.png \
  https://example.com/

# TEE path: request TDX quote + enclave signature via /var/run/dstack.sock
# Outside a CVM this fails closed; it never fabricates attestation fields.
basecrawl --attest --task-id JOB-1 --nonce once-abc \
  --formats markdown,metadata,rawHtml --timeout 60 --no-js \
  https://example.com/
```

Useful flags: `--header`, `--cookie`, `--auth-header`, `--basic-auth`, `--no-js`, `--actions` (JSON action array), `--follow-pagination` / `--max-pages`, `--robots`, `--fingerprint-seed`, `--sign-proof`, `--insecure` (diagnostic only), `--verbose` (redacted stderr summary).

Proof surface (schema version 1) includes `request`, `tls`, `response`, `result`, `egress`, `attestation`, and `sdk_signature`. With `--attest` / `--sign-proof` the proof binds request/cert/transcript/response/result hashes and the Ed25519 public key into TDX `report_data`, then signs the envelope with the enclave key.

Supporting properties delivered under M0–M10: seeded fingerprints, in-enclave DoH privacy for DNS, landmark RTT attestation echo, content-confidential sealed task path, and digest-pinned CVM image evidence.

## CVM image

Published image (digest-pinned; do not float on `:latest`):

```
docker.io/mathiiss/basecrawl-cvm@sha256:ba24465efe709c3f071696d807076eb5517d671c1e6f17ca0fe7143178d51e1a
```

- TDX CVM on Phala (`kms_type: phala`)
- dstack guest OS: `dstack-0.5.9` / slug `dstack-0.5.9-bd369a8c` (`os_image_hash` `bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033`)
- Spoke socket: `/var/run/dstack.sock` (`Info`, `GetQuote`, and related endpoints)
- Compose and measurement machinery live under `image/`
- Live mission evidence (quotes, decoded report_data, allowlist, proof A/B, PCK, assertions) is retained under `image/evidence/m10/` (earlier mission artifacts under `image/evidence/m2/` and related paths)

Validators authenticate a run by L1 measurement allowlist match plus L2 `report_data` binding, not by shipping the binary alone.

## Environment and dependencies

- Rust **1.96.0** (see `rust-toolchain.toml`)
- Linux/amd64 (CVM image is linux/amd64 only)
- System Chromium for the render path is supplied by the puppeteer root image inside the CVM Dockerfile; host CLI runs need a compatible Chrome/Chromium if JS render is enabled
- TLS stack: `rustls` + WebPKI roots; HTTPS only for normal authenticity-capable proofs
- Docker BuildKit for image builds after `image/Dockerfile` (no OS package installs in the image)
- Optional: Phala / dstack socket for `--attest` live TDX quotes
- Language bindings: optional Python 3 + PyO3 path, Node N-API path under `bindings/`

Root `.env` is local operator config and is not required to build the library crates.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).

## Trust model

Authenticity is **cryptographically-anchored trust-but-audit**. A verifying quote whose measurement is on the allowlist is evidence that the scrape ran inside software matching a pinned CVM image, with scrape hashes bound into `report_data`. Combined with certificate checks and (on the relay side) quorum, audit, and scoring, that is a cryptographic anchor for auditable authenticity claims, not absolute certainty.

A scrape is authentic under:

- TEE vendor honest **and** host not physically compromised; **or**
- honest witness + clean network path; **or**
- honest-majority audit + slashing.

Explicit residual: **TEE.fail** (self-hosted DDR5 interposer can forge quotes / read enclave memory; no vendor fix). Managed-cloud Phala TDX placement is the operational mitigation for high-reward or confidential workloads; it does not remove the residual. See `docs/TRUST_MODEL.md` and `docs/SECURITY.md`. Do not describe this system as trustless, absolute, or guaranteed.
