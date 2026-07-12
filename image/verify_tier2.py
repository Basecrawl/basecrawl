"""Verify a live TDX quote and emit self-contained Tier-2 attestation evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import attest


def _verify_quote(quote_path: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["dcap-qvl", "verify", "--hex", str(quote_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=90,
    )
    if result.returncode != 0:
        raise attest.AttestationError(
            f"dcap-qvl rejected quote {quote_path}: {result.stderr.strip()}"
        )
    try:
        verdict = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise attest.AttestationError(
            "dcap-qvl returned invalid verify JSON"
        ) from error
    statuses = [
        verdict.get("status"),
        verdict.get("qe_status", {}).get("status"),
        verdict.get("platform_status", {}).get("status"),
    ]
    advisories = [
        verdict.get("advisory_ids"),
        verdict.get("qe_status", {}).get("advisory_ids"),
        verdict.get("platform_status", {}).get("advisory_ids"),
    ]
    if statuses != ["UpToDate"] * 3 or advisories != [[], [], []]:
        raise attest.AttestationError(
            "quote, QE, and platform must all be UpToDate with no advisories"
        )
    if "Quote verified" not in result.stderr:
        raise attest.AttestationError("dcap-qvl did not report 'Quote verified'")
    return {
        "status": statuses[0],
        "advisory_ids": advisories[0],
        "qe_status": statuses[1],
        "qe_advisory_ids": advisories[1],
        "platform_status": statuses[2],
        "platform_advisory_ids": advisories[2],
        "quote_verified": True,
    }


def _execution_proof_roundtrip(
    attestation: dict[str, Any], platform_src: Path
) -> dict[str, Any]:
    sys.path.insert(0, str(platform_src))
    try:
        from base.schemas.worker import ExecutionProof
    finally:
        sys.path.pop(0)
    envelope = {
        "version": 1,
        "tier": 2,
        "manifest_sha256": "00" * 32,
        "image_digest": (
            "sha256:57a2ecdc9257846ca69dce38c53a464b68e9a08575fb45d8d18aed5b6b28f366"
        ),
        "provider": {"name": "phala"},
        "worker_signature": {
            "worker_pubkey": "tier2-evidence",
            "sig": "tier2-evidence",
        },
        "attestation": attestation,
    }
    parsed = ExecutionProof.model_validate(envelope)
    serialized = parsed.model_dump(mode="json")
    reparsed = ExecutionProof.model_validate_json(json.dumps(serialized))
    roundtripped = reparsed.model_dump(mode="json")
    if roundtripped["tier"] != 2 or roundtripped["attestation"] != attestation:
        raise attest.AttestationError(
            "ExecutionProof Tier-2 attestation round-trip was lossy"
        )
    return {
        "schema": "platform/src/base/schemas/worker.py::ExecutionProof",
        "version": roundtripped["version"],
        "tier": roundtripped["tier"],
        "lossless": True,
    }


def verify_tier2(
    quote_path: Path, platform_src: Path, source_evidence: Path
) -> dict[str, Any]:
    quote = quote_path.read_text(encoding="utf-8").strip().lower()
    decoded = attest.decode_quote(quote_path)
    pckinfo = attest.inspect_pckinfo(quote_path)
    verification = _verify_quote(quote_path)
    attestation = attest.build_tier2_attestation(quote, decoded)
    execution_proof = _execution_proof_roundtrip(attestation, platform_src)
    report = decoded["report"]["TD10"]
    attributes = report["td_attributes"]
    chain = pckinfo["certificate_chain"]
    source = json.loads(source_evidence.read_text(encoding="utf-8"))

    return {
        "feature": "quote-verification-tcb-tier2",
        "source": {
            "kind": "genuine-production-phala-cvm-quote",
            "cvm_name": source["reconciliation_deployments"]["second"]["cvm_name"],
            "automatic_placement": True,
            "os_image": source["reconciliation_deployments"]["second"]["image"],
            "instance_type": source["reconciliation_deployments"]["second"][
                "instance_type"
            ],
            "mission_cvm_deleted": source["cleanup"]["temporary_cvms_deleted"],
        },
        "quote_sha256": hashlib.sha256(bytes.fromhex(quote)).hexdigest(),
        "dcap_qvl": verification,
        "platform_identity": {
            "tee_type": pckinfo["tee_type"],
            "fmspc": pckinfo["fmspc"],
            "pce_svn": pckinfo["pce_svn"],
            "certificate_chain": [
                {
                    "role": certificate["role"],
                    "subject": certificate["subject"],
                    "issuer": certificate["issuer"],
                }
                for certificate in chain
            ],
            "intel_rooted": True,
        },
        "decoded_quote": {
            "quote_version": decoded["header"]["version"],
            "tee_type": "tdx",
            "td_attributes": attributes,
            "debug": bool(int.from_bytes(bytes.fromhex(attributes), "little") & 1),
            "measurement": attestation["measurement"],
            "report_data": report["report_data"],
        },
        "scrapeproof_attestation": attestation,
        "execution_proof_roundtrip": execution_proof,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quote", type=Path, required=True)
    parser.add_argument(
        "--platform-src",
        type=Path,
        default=Path("/projects/platform-network/platform/src"),
    )
    parser.add_argument(
        "--source-evidence",
        type=Path,
        default=Path(__file__).with_name("measurement-reconciliation.json"),
    )
    parser.add_argument("--output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        evidence = verify_tier2(args.quote, args.platform_src, args.source_evidence)
        args.output.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (OSError, KeyError, attest.AttestationError) as error:
        print(json.dumps({"verified": False, "error": str(error)}, sort_keys=True))
        return 1
    print(
        json.dumps(
            {
                "verified": True,
                "status": evidence["dcap_qvl"]["status"],
                "tee_type": evidence["decoded_quote"]["tee_type"],
                "tier2_roundtrip": evidence["execution_proof_roundtrip"]["lossless"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
