# Trust model

Authenticity is **cryptographically-anchored trust-but-audit**.

Companion residual write-up: [SECURITY.md](SECURITY.md). Architecture flow: [architecture.md](architecture.md).

## What a ScrapeProof means

A ScrapeProof whose quote verifies and whose measurement is on the verifier allowlist is evidence that the scrape ran inside software matching a pinned CVM image, with request/cert/transcript/response/result hashes bound into `report_data`. Combined with L2 certificate checks and consumer-side quorum, audit, and scoring, that is a cryptographic anchor, not absolute certainty.

A scrape is authentic under:

- TEE vendor honest **and** host not physically compromised; **or**
- honest witness + clean network path; **or**
- honest-majority audit + slashing.

## Forbidden language

Do not write absolute-trust or absolute-TEE wording about basecrawl or its TEE path. Prefer cryptographically-anchored trust-but-audit only. Avoid "trustless", "100%", "guaranteed", and "anonymous" as product claims.

## Residuals called out elsewhere

| Residual | Where |
| --- | --- |
| TEE.fail (self-hosted DDR5 interposer can forge quotes / read enclave memory; no vendor fix) + managed-cloud mitigation | [SECURITY.md](SECURITY.md) |
| Measured-but-exploited Chromium/OS 0-day + rotation runbook | [tcb-inventory.md](tcb-inventory.md), [image-rotation-on-cve.md](image-rotation-on-cve.md) |
