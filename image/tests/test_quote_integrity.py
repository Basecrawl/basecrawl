from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# ruff: noqa: E402

IMAGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(IMAGE_DIR))

import attest


EVIDENCE_PATH = IMAGE_DIR / "tier2-attestation-evidence.json"
QUOTE_BODY_OFFSET = 48
SIGNATURE_DATA_LENGTH_OFFSET = 48 + 584
SIGNATURE_DATA_OFFSET = SIGNATURE_DATA_LENGTH_OFFSET + 4


def retained_quote() -> bytes:
    evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
    return bytes.fromhex(evidence["scrapeproof_attestation"]["quote"])


def dcap_qvl(operation: str, quote: bytes | bytearray | str) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile(mode="w", encoding="ascii", suffix=".hex") as quote_file:
        quote_file.write(quote if isinstance(quote, str) else quote.hex())
        quote_file.flush()
        return subprocess.run(
            ["dcap-qvl", operation, "--hex", quote_file.name],
            capture_output=True,
            text=True,
            check=False,
            timeout=90,
        )


def certification_data_offset(quote: bytes) -> int:
    outer = SIGNATURE_DATA_OFFSET + 64 + 64
    if int.from_bytes(quote[outer : outer + 2], "little") != 6:
        raise AssertionError("retained quote has no QE report certification data")
    qe_report = outer + 6
    auth_size_offset = qe_report + 384 + 64
    auth_size = int.from_bytes(quote[auth_size_offset : auth_size_offset + 2], "little")
    inner = auth_size_offset + 2 + auth_size
    if int.from_bytes(quote[inner : inner + 2], "little") != 5:
        raise AssertionError("retained quote has no PCK certificate-chain data")
    cert_size = int.from_bytes(quote[inner + 2 : inner + 6], "little")
    if cert_size == 0:
        raise AssertionError("retained quote has empty PCK certification data")
    return inner + 6


class QuoteIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.quote = retained_quote()
        baseline = dcap_qvl("verify", cls.quote)
        if baseline.returncode != 0 or "Quote verified" not in baseline.stderr:
            raise AssertionError(
                "retained genuine quote must verify before negative testing: "
                f"stdout={baseline.stdout!r}, stderr={baseline.stderr!r}"
            )

    def assert_mutation_rejected(self, label: str, offset: int) -> None:
        mutated = bytearray(self.quote)
        mutated[offset] ^= 0x01
        result = dcap_qvl("verify", mutated)
        self.assertNotEqual(
            result.returncode,
            0,
            f"{label} mutation unexpectedly verified: {result.stdout} {result.stderr}",
        )
        self.assertNotIn("Quote verified", result.stderr)

    def test_signed_td_report_mutations_break_verification(self) -> None:
        offsets = {
            "mrtd": QUOTE_BODY_OFFSET + 136,
            "rtmr0": QUOTE_BODY_OFFSET + 328,
            "rtmr1": QUOTE_BODY_OFFSET + 376,
            "rtmr2": QUOTE_BODY_OFFSET + 424,
            "rtmr3": QUOTE_BODY_OFFSET + 472,
            "report_data": QUOTE_BODY_OFFSET + 520,
        }
        for label, offset in offsets.items():
            with self.subTest(field=label):
                self.assert_mutation_rejected(label, offset)

    def test_signature_and_certification_mutations_break_verification(self) -> None:
        offsets = {
            "ecdsa_quote_signature": SIGNATURE_DATA_OFFSET,
            "qe_pck_certification_data": certification_data_offset(self.quote),
        }
        for label, offset in offsets.items():
            with self.subTest(field=label):
                self.assert_mutation_rejected(label, offset)

    def test_malformed_and_truncated_quotes_fail_decode_and_verify(self) -> None:
        malformed_quotes = {
            "below_minimum": self.quote[: attest.MIN_QUOTE_LEN - 1],
            "inside_signature": self.quote[: SIGNATURE_DATA_OFFSET + 32],
            "inside_certification": self.quote[: certification_data_offset(self.quote)],
            "non_hexadecimal": "zz",
        }
        for label, quote in malformed_quotes.items():
            with self.subTest(shape=label):
                for operation in ("decode", "verify"):
                    result = dcap_qvl(operation, quote)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("Quote verified", result.stderr)
                    self.assertTrue(
                        result.stdout.strip() or result.stderr.strip(),
                        f"{operation} returned no structural error",
                    )

    def test_scrapeproof_emitter_rejects_truncated_quote(self) -> None:
        evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        decoded = {
            "header": {"version": 4, "tee_type": 129},
            "report": {
                "TD10": {
                    "mr_td": evidence["decoded_quote"]["measurement"]["mrtd"],
                    "rt_mr0": evidence["decoded_quote"]["measurement"]["rtmr0"],
                    "rt_mr1": evidence["decoded_quote"]["measurement"]["rtmr1"],
                    "rt_mr2": evidence["decoded_quote"]["measurement"]["rtmr2"],
                    "rt_mr3": evidence["decoded_quote"]["measurement"]["rtmr3"],
                    "report_data": evidence["decoded_quote"]["report_data"],
                }
            },
        }
        truncated = self.quote[: certification_data_offset(self.quote)]
        with self.assertRaisesRegex(attest.AttestationError, "truncated|structure"):
            attest.build_tier2_attestation(truncated.hex(), decoded)
        with self.assertRaisesRegex(attest.AttestationError, "malformed|truncated"):
            attest.build_tier2_attestation("zz", decoded)

    def test_retained_quote_accepts_only_zero_transport_padding(self) -> None:
        signature_data_length = int.from_bytes(
            self.quote[SIGNATURE_DATA_LENGTH_OFFSET : SIGNATURE_DATA_LENGTH_OFFSET + 4],
            "little",
        )
        declared_end = SIGNATURE_DATA_OFFSET + signature_data_length
        self.assertLess(declared_end, len(self.quote))
        self.assertFalse(any(self.quote[declared_end:]))
        evidence = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        attest._quote_shape(self.quote.hex(), evidence["scrapeproof_attestation"]["report_data"])


if __name__ == "__main__":
    unittest.main()
