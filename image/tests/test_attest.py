from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# ruff: noqa: E402

IMAGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(IMAGE_DIR))

import attest


REPORT_DATA = bytes(range(64)).hex()


def valid_quote(report_data: str = REPORT_DATA) -> str:
    quote = bytearray(48 + 584)
    quote[0:2] = (4).to_bytes(2, "little")
    quote[4:8] = (0x81).to_bytes(4, "little")
    quote[48 + 520 : 48 + 584] = bytes.fromhex(report_data)
    qe_certification = bytearray(384 + 64)
    qe_certification += (32).to_bytes(2, "little")
    qe_certification += bytes(range(32))
    qe_certification += (5).to_bytes(2, "little")
    qe_certification += (1).to_bytes(4, "little")
    qe_certification += b"\x42"
    signature_data = bytearray(b"\x11" * 64 + b"\x22" * 64)
    signature_data += (6).to_bytes(2, "little")
    signature_data += len(qe_certification).to_bytes(4, "little")
    signature_data += qe_certification
    quote += len(signature_data).to_bytes(4, "little")
    quote += signature_data
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

    def test_parse_get_quote_preserves_json_encoded_wire_strings(self) -> None:
        event_log = '[{"event":"fixture"}]'
        vm_config = '{"cpu":1}'
        response = attest.parse_get_quote(
            json.dumps(
                {
                    "quote": valid_quote(),
                    "event_log": event_log,
                    "report_data": REPORT_DATA,
                    "vm_config": vm_config,
                }
            ),
            REPORT_DATA,
        )
        self.assertEqual(response["event_log"], event_log)
        self.assertEqual(response["vm_config"], vm_config)

    def test_parse_get_quote_rejects_noncanonical_returned_report_data(self) -> None:
        for returned in ("0102", "ab" * 65):
            with self.subTest(returned_length=len(returned)):
                expected = attest.normalize_report_data(returned)
                with self.assertRaisesRegex(attest.AttestationError, "report_data"):
                    attest.parse_get_quote(
                        json.dumps(
                            {
                                "quote": valid_quote(expected),
                                "event_log": [{"event": "fixture"}],
                                "report_data": returned,
                                "vm_config": {"cpu": 1},
                            }
                        ),
                        returned,
                    )

    def test_request_quote_posts_sha256_reduced_overlong_report_data(
        self,
    ) -> None:
        overlong = "ab" * 65
        expected = hashlib.sha256(bytes.fromhex(overlong)).hexdigest() + "00" * 32

        def respond(_path: Path, body: bytes, _timeout: float) -> bytes:
            self.assertEqual(json.loads(body), {"report_data": expected})
            return json.dumps(
                {
                    "quote": valid_quote(expected),
                    "event_log": [{"event": "fixture"}],
                    "report_data": expected,
                    "vm_config": {"cpu": 1},
                }
            ).encode()

        with mock.patch("attest._http_post_unix", side_effect=respond):
            response = attest.request_quote(overlong)
        self.assertEqual(response["report_data"], expected)
        self.assertNotEqual(response["report_data"], overlong[: 64 * 2])

    def test_request_quote_left_aligns_and_zero_pads_short_report_data(self) -> None:
        short = "ab" * 32
        expected = short + "00" * 32

        def respond(_path: Path, body: bytes, _timeout: float) -> bytes:
            self.assertEqual(json.loads(body), {"report_data": expected})
            return json.dumps(
                {
                    "quote": valid_quote(expected),
                    "event_log": [{"event": "fixture"}],
                    "report_data": expected,
                    "vm_config": {"cpu": 1},
                }
            ).encode()

        with mock.patch("attest._http_post_unix", side_effect=respond):
            response = attest.request_quote(short)
        self.assertEqual(response["report_data"], expected)

    def test_request_quote_rejects_malformed_hex_before_socket_access(self) -> None:
        with mock.patch("attest._http_post_unix") as post:
            for malformed in ("", "0", "gg", "01xz"):
                with self.subTest(report_data=malformed):
                    with self.assertRaisesRegex(attest.AttestationError, "hexadecimal"):
                        attest.request_quote(malformed)
        post.assert_not_called()

    def test_request_quote_fails_closed_when_socket_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            missing = Path(temp_dir) / "missing.sock"
            with self.assertRaisesRegex(attest.AttestationError, "socket unavailable"):
                attest.request_quote(REPORT_DATA, socket_path=missing)

    def test_cli_socket_failure_writes_no_quote_response_or_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            quote_out = root / "quote.hex"
            response_out = root / "response.json"
            attestation_out = root / "attestation.json"
            args = [
                "attest.py",
                "--report-data",
                REPORT_DATA,
                "--socket",
                str(root / "missing.sock"),
                "--quote-out",
                str(quote_out),
                "--response-out",
                str(response_out),
                "--attestation-out",
                str(attestation_out),
            ]
            stdout = io.StringIO()
            with (
                mock.patch.object(sys, "argv", args),
                contextlib.redirect_stdout(stdout),
            ):
                self.assertEqual(attest.main(), 1)
            self.assertFalse(quote_out.exists())
            self.assertFalse(response_out.exists())
            self.assertFalse(attestation_out.exists())
            result = json.loads(stdout.getvalue())
            self.assertFalse(result["attestation"])
            self.assertIn("socket unavailable", result["error"])

    def test_forged_quote_has_enough_bytes_but_no_signature(self) -> None:
        forged = attest.hand_assembled_quote(REPORT_DATA)
        self.assertLess(len(forged), attest.MIN_QUOTE_HEX_LEN)
        self.assertEqual(forged[(48 + 520) * 2 : (48 + 584) * 2], REPORT_DATA)

    def test_decode_quote_requires_every_tdx_register_and_production_attributes(
        self,
    ) -> None:
        completed = mock.Mock(returncode=0, stdout=json.dumps(valid_decode()), stderr="")
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
        completed = mock.Mock(returncode=0, stdout=json.dumps(valid_pckinfo()), stderr="")
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

    def test_parser_and_emitter_reject_truncated_certification_data(self) -> None:
        truncated = valid_quote()[:-2]
        payload = json.dumps(
            {
                "quote": truncated,
                "event_log": [{"event": "fixture"}],
                "report_data": REPORT_DATA,
                "vm_config": {"cpu": 1},
            }
        )
        with self.assertRaisesRegex(attest.AttestationError, "truncated|structure"):
            attest.parse_get_quote(payload, REPORT_DATA)
        with self.assertRaisesRegex(attest.AttestationError, "truncated|structure"):
            attest.build_tier2_attestation(truncated, valid_decode())

    def test_parser_rejects_nonzero_bytes_after_declared_quote(self) -> None:
        payload = json.dumps(
            {
                "quote": valid_quote() + "01",
                "event_log": [{"event": "fixture"}],
                "report_data": REPORT_DATA,
                "vm_config": {"cpu": 1},
            }
        )
        with self.assertRaisesRegex(attest.AttestationError, "structure"):
            attest.parse_get_quote(payload, REPORT_DATA)


if __name__ == "__main__":
    unittest.main()
