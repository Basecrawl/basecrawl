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


REPORT_DATA = bytes(range(64)).hex()


def valid_quote() -> str:
    quote = bytearray(48 + 584 + 4)
    quote[0:2] = (4).to_bytes(2, "little")
    quote[4:8] = (0x81).to_bytes(4, "little")
    quote[48 + 520 : 48 + 584] = bytes.fromhex(REPORT_DATA)
    return quote.hex()


def valid_decode() -> dict[str, object]:
    return {
        "header": {"version": 4, "tee_type": 129},
        "report": {
            "TD10": {
                "mr_td": "11" * 48,
                "rt_mr0": "22" * 48,
                "rt_mr1": "33" * 48,
                "rt_mr2": "44" * 48,
                "rt_mr3": "55" * 48,
                "report_data": REPORT_DATA,
                "td_attributes": "0000001000000000",
            }
        },
    }


def valid_pckinfo() -> dict[str, object]:
    return {
        "quote_version": 4,
        "tee_type": "TDX",
        "fmspc": "20a06f000000",
        "pce_svn": 13,
        "certificate_chain": [
            {
                "role": "Leaf PCK",
                "subject": "CN=Intel SGX PCK Certificate",
                "issuer": "CN=Intel SGX PCK Platform CA",
            },
            {
                "role": "PCK CA",
                "subject": "CN=Intel SGX PCK Platform CA",
                "issuer": "CN=Intel SGX Root CA",
            },
            {
                "role": "Root CA",
                "subject": "CN=Intel SGX Root CA",
                "issuer": "CN=Intel SGX Root CA",
            },
        ],
    }


class AttestationClientTests(unittest.TestCase):
    def test_parse_get_quote_requires_all_fields_and_full_report_data(self) -> None:
        response = attest.parse_get_quote(
            json.dumps(
                {
                    "quote": valid_quote(),
                    "event_log": [{"event": "fixture"}],
                    "report_data": REPORT_DATA,
                    "vm_config": {"cpu": 1},
                }
            ),
            REPORT_DATA,
        )
        self.assertEqual(response["report_data"], REPORT_DATA)
        self.assertGreaterEqual(len(response["quote"]), attest.MIN_QUOTE_HEX_LEN)

    def test_parse_get_quote_rejects_report_data_mismatch(self) -> None:
        with self.assertRaisesRegex(attest.AttestationError, "report_data"):
            attest.parse_get_quote(
                json.dumps(
                    {
                        "quote": valid_quote(),
                        "event_log": [{"event": "fixture"}],
                        "report_data": "ff" * 64,
                        "vm_config": {"cpu": 1},
                    }
                ),
                REPORT_DATA,
            )

    def test_forged_quote_has_enough_bytes_but_no_signature(self) -> None:
        forged = attest.hand_assembled_quote(REPORT_DATA)
        self.assertGreaterEqual(len(forged), attest.MIN_QUOTE_HEX_LEN)
        self.assertEqual(forged[(48 + 520) * 2 : (48 + 584) * 2], REPORT_DATA)

    def test_overlong_report_data_is_sha512_reduced_and_short_data_is_padded(
        self,
    ) -> None:
        overlong = "ab" * 65
        reduced = attest.normalize_report_data(overlong)
        self.assertEqual(
            reduced,
            hashlib.sha256(bytes.fromhex(overlong)).hexdigest() + "00" * 32,
        )
        short = attest.normalize_report_data("0102")
        self.assertEqual(short, "0102" + "00" * 62)

    def test_decode_quote_requires_every_tdx_register_and_production_attributes(
        self,
    ) -> None:
        completed = mock.Mock(
            returncode=0, stdout=json.dumps(valid_decode()), stderr=""
        )
        with mock.patch("attest.subprocess.run", return_value=completed):
            decoded = attest.decode_quote(Path("/tmp/quote.hex"))
        self.assertEqual(decoded["report"]["TD10"]["rt_mr3"], "55" * 48)

        missing = valid_decode()
        del missing["report"]["TD10"]["rt_mr2"]
        completed.stdout = json.dumps(missing)
        with (
            mock.patch("attest.subprocess.run", return_value=completed),
            self.assertRaisesRegex(attest.AttestationError, "rt_mr2"),
        ):
            attest.decode_quote(Path("/tmp/quote.hex"))

    def test_decode_quote_rejects_a_debug_td(self) -> None:
        decoded = valid_decode()
        decoded["report"]["TD10"]["td_attributes"] = "0100000000000000"
        completed = mock.Mock(returncode=0, stdout=json.dumps(decoded), stderr="")
        with (
            mock.patch("attest.subprocess.run", return_value=completed),
            self.assertRaisesRegex(attest.AttestationError, "DEBUG"),
        ):
            attest.decode_quote(Path("/tmp/quote.hex"))

    def test_pckinfo_requires_tdx_identity_and_intel_rooted_chain(self) -> None:
        completed = mock.Mock(
            returncode=0, stdout=json.dumps(valid_pckinfo()), stderr=""
        )
        with mock.patch("attest.subprocess.run", return_value=completed):
            pckinfo = attest.inspect_pckinfo(Path("/tmp/quote.hex"))
        self.assertEqual(pckinfo["fmspc"], "20a06f000000")

        wrong_root = valid_pckinfo()
        wrong_root["certificate_chain"][-1]["subject"] = "CN=Untrusted Root"
        completed.stdout = json.dumps(wrong_root)
        with (
            mock.patch("attest.subprocess.run", return_value=completed),
            self.assertRaisesRegex(attest.AttestationError, "Intel SGX Root CA"),
        ):
            attest.inspect_pckinfo(Path("/tmp/quote.hex"))

    def test_tier2_attestation_matches_decode_and_roundtrips_losslessly(self) -> None:
        decoded = valid_decode()
        attestation = attest.build_tier2_attestation(valid_quote(), decoded)
        self.assertEqual(attestation["tee_type"], "tdx")
        self.assertEqual(attestation["measurement"]["mrtd"], "11" * 48)
        self.assertEqual(attestation["measurement"]["rtmr3"], "55" * 48)
        self.assertEqual(attestation["report_data"], REPORT_DATA)
        self.assertEqual(json.loads(json.dumps(attestation)), attestation)


if __name__ == "__main__":
    unittest.main()
