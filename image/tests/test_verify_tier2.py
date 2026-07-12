from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

# ruff: noqa: E402

IMAGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(IMAGE_DIR))

import attest
import verify_tier2


class Tier2VerificationTests(unittest.TestCase):
    def test_verifier_rejects_any_advisory_or_non_uptodate_component(self) -> None:
        verdict = {
            "status": "UpToDate",
            "advisory_ids": [],
            "qe_status": {"status": "UpToDate", "advisory_ids": []},
            "platform_status": {"status": "UpToDate", "advisory_ids": ["INTEL-SA"]},
        }
        completed = mock.Mock(
            returncode=0,
            stdout=json.dumps(verdict),
            stderr="Getting collateral...\nQuote verified\n",
        )
        with (
            mock.patch("verify_tier2.subprocess.run", return_value=completed),
            self.assertRaisesRegex(attest.AttestationError, "no advisories"),
        ):
            verify_tier2._verify_quote(Path("/tmp/quote.hex"))

    def test_durable_evidence_is_self_consistent_with_embedded_quote(self) -> None:
        evidence = json.loads(
            (IMAGE_DIR / "tier2-attestation-evidence.json").read_text(encoding="utf-8")
        )
        attestation = evidence["scrapeproof_attestation"]
        quote = bytes.fromhex(attestation["quote"])
        report = quote[48:]
        measurement = attestation["measurement"]

        self.assertEqual(attestation["tee_type"], "tdx")
        self.assertEqual(measurement["mrtd"], report[136:184].hex())
        self.assertEqual(measurement["rtmr0"], report[328:376].hex())
        self.assertEqual(measurement["rtmr1"], report[376:424].hex())
        self.assertEqual(measurement["rtmr2"], report[424:472].hex())
        self.assertEqual(measurement["rtmr3"], report[472:520].hex())
        self.assertEqual(attestation["report_data"], report[520:584].hex())
        self.assertEqual(evidence["quote_sha256"], hashlib.sha256(quote).hexdigest())
        self.assertFalse(evidence["decoded_quote"]["debug"])
        self.assertTrue(evidence["platform_identity"]["intel_rooted"])
        self.assertTrue(evidence["execution_proof_roundtrip"]["lossless"])


if __name__ == "__main__":
    unittest.main()
