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

## Operator checklist

1. Prefer managed-cloud placement for confidential scrapes.
2. Keep image builds reproducible and digest-pinned; rotate on CVE per [image-rotation-on-cve.md](image-rotation-on-cve.md).
3. Never advertise absolute-trust language in tooling or docs.
