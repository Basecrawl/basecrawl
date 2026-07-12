"""Fail-closed dstack GetQuote client and real-CVM attestation harness.

The quote signing key never exists in this process.  ``request_quote`` talks to the Unix socket
mounted inside a CVM; ``hand_assembled_quote`` exists only to exercise the negative verifier path
and deliberately contains no signature or certification data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import subprocess
from pathlib import Path
from typing import Any

SOCKET_PATH = Path("/var/run/dstack.sock")
REPORT_DATA_BYTES = 64
QUOTE_HEADER_BYTES = 48
TD_REPORT_BYTES = 584
TD_REPORT_DATA_OFFSET = 520
TD_REPORT_DATA_BYTES = 64
SIGNATURE_DATA_LENGTH_BYTES = 4
ECDSA_SIGNATURE_BYTES = 64
ECDSA_ATTESTATION_KEY_BYTES = 64
CERTIFICATION_HEADER_BYTES = 6
QE_REPORT_BYTES = 384
QE_REPORT_SIGNATURE_BYTES = 64
AUTHENTICATION_DATA_LENGTH_BYTES = 2
MIN_CERTIFICATION_DATA_BYTES = 1
SIGNATURE_DATA_LENGTH_OFFSET = QUOTE_HEADER_BYTES + TD_REPORT_BYTES
SIGNATURE_DATA_OFFSET = SIGNATURE_DATA_LENGTH_OFFSET + SIGNATURE_DATA_LENGTH_BYTES
MIN_SIGNATURE_DATA_BYTES = (
    ECDSA_SIGNATURE_BYTES
    + ECDSA_ATTESTATION_KEY_BYTES
    + CERTIFICATION_HEADER_BYTES
    + QE_REPORT_BYTES
    + QE_REPORT_SIGNATURE_BYTES
    + AUTHENTICATION_DATA_LENGTH_BYTES
    + CERTIFICATION_HEADER_BYTES
    + MIN_CERTIFICATION_DATA_BYTES
)
MIN_QUOTE_LEN = SIGNATURE_DATA_OFFSET + MIN_SIGNATURE_DATA_BYTES
MIN_QUOTE_HEX_LEN = MIN_QUOTE_LEN * 2
QE_REPORT_CERTIFICATION_DATA_TYPE = 6
PCK_CERTIFICATE_CHAIN_DATA_TYPE = 5
TD_MEASUREMENT_HEX_LEN = 48 * 2
TD_ATTRIBUTES_HEX_LEN = 8 * 2


class AttestationError(RuntimeError):
    """A quote response failed closed validation."""


def normalize_report_data(report_data: str) -> str:
    value = report_data.strip().lower()
    if not value or len(value) % 2 or any(char not in "0123456789abcdef" for char in value):
        raise AttestationError("report_data must be non-empty, even-length hexadecimal")
    payload = bytes.fromhex(value)
    if len(payload) > REPORT_DATA_BYTES:
        payload = hashlib.sha256(payload).digest()
    return payload.ljust(REPORT_DATA_BYTES, b"\0").hex()


def _quote_shape(quote_hex: str, report_data: str) -> None:
    if (
        len(quote_hex) < MIN_QUOTE_HEX_LEN
        or len(quote_hex) % 2
        or any(char not in "0123456789abcdef" for char in quote_hex)
    ):
        raise AttestationError("quote is missing, malformed, or truncated")
    quote = bytes.fromhex(quote_hex)
    if int.from_bytes(quote[0:2], "little") != 4 or int.from_bytes(quote[4:8], "little") != 0x81:
        raise AttestationError("quote is not an Intel TDX v4 quote")
    signature_data_length = int.from_bytes(
        quote[
            SIGNATURE_DATA_LENGTH_OFFSET : SIGNATURE_DATA_LENGTH_OFFSET
            + SIGNATURE_DATA_LENGTH_BYTES
        ],
        "little",
    )
    if signature_data_length < MIN_SIGNATURE_DATA_BYTES:
        raise AttestationError(
            "quote structure is malformed or truncated: signature data is too short"
        )
    declared_end = SIGNATURE_DATA_OFFSET + signature_data_length
    if declared_end > len(quote):
        raise AttestationError(
            "quote structure is malformed or truncated: declared signature data is truncated"
        )
    if any(quote[declared_end:]):
        raise AttestationError(
            "quote structure is malformed: non-zero bytes follow declared signature data"
        )
    signature_data = quote[SIGNATURE_DATA_OFFSET:declared_end]
    cursor = ECDSA_SIGNATURE_BYTES + ECDSA_ATTESTATION_KEY_BYTES
    outer_type = _read_uint(signature_data, cursor, 2)
    outer_length = _read_uint(signature_data, cursor + 2, 4)
    if outer_type != QE_REPORT_CERTIFICATION_DATA_TYPE:
        raise AttestationError("quote structure is malformed: no QE report certification envelope")
    cursor += CERTIFICATION_HEADER_BYTES
    outer_end = cursor + outer_length
    if outer_end != len(signature_data):
        raise AttestationError(
            "quote structure is malformed or truncated: "
            "QE certification length does not match signature data"
        )
    minimum_qe_certification = (
        QE_REPORT_BYTES
        + QE_REPORT_SIGNATURE_BYTES
        + AUTHENTICATION_DATA_LENGTH_BYTES
        + CERTIFICATION_HEADER_BYTES
        + MIN_CERTIFICATION_DATA_BYTES
    )
    if outer_length < minimum_qe_certification:
        raise AttestationError(
            "quote structure is malformed or truncated: QE report certification data is truncated"
        )
    cursor += QE_REPORT_BYTES + QE_REPORT_SIGNATURE_BYTES
    authentication_data_length = _read_uint(signature_data, cursor, 2)
    cursor += AUTHENTICATION_DATA_LENGTH_BYTES + authentication_data_length
    if cursor + CERTIFICATION_HEADER_BYTES > outer_end:
        raise AttestationError(
            "quote structure is malformed or truncated: authentication data is truncated"
        )
    certification_type = _read_uint(signature_data, cursor, 2)
    certification_data_length = _read_uint(signature_data, cursor + 2, 4)
    if certification_type != PCK_CERTIFICATE_CHAIN_DATA_TYPE:
        raise AttestationError("quote structure is malformed: no PCK certificate-chain data")
    if certification_data_length < MIN_CERTIFICATION_DATA_BYTES:
        raise AttestationError("quote structure is malformed: PCK certification data is empty")
    cursor += CERTIFICATION_HEADER_BYTES
    if cursor + certification_data_length != outer_end:
        raise AttestationError(
            "quote structure is malformed or truncated: "
            "PCK certification data length does not match quote"
        )
    embedded = quote[
        QUOTE_HEADER_BYTES + TD_REPORT_DATA_OFFSET : QUOTE_HEADER_BYTES
        + TD_REPORT_DATA_OFFSET
        + TD_REPORT_DATA_BYTES
    ].hex()
    if embedded != report_data:
        raise AttestationError("quote report_data does not match submitted report_data")


def _read_uint(value: bytes, offset: int, size: int) -> int:
    end = offset + size
    if end > len(value):
        raise AttestationError(
            "quote structure is malformed or truncated: missing length or type field"
        )
    return int.from_bytes(value[offset:end], "little")


def parse_get_quote(payload: str | bytes, submitted_report_data: str) -> dict[str, Any]:
    expected = normalize_report_data(submitted_report_data)
    try:
        response = json.loads(payload)
    except (TypeError, json.JSONDecodeError) as error:
        raise AttestationError(f"GetQuote returned invalid JSON: {error}") from error
    if not isinstance(response, dict):
        raise AttestationError("GetQuote response must be a JSON object")
    for field in ("quote", "event_log", "report_data", "vm_config"):
        if field not in response or response[field] in (None, "", [], {}):
            raise AttestationError(f"GetQuote response is missing {field}")
    returned = response["report_data"]
    if not isinstance(returned, str) or normalize_report_data(returned) != expected:
        raise AttestationError("GetQuote response report_data does not match submitted value")
    quote = response["quote"]
    if not isinstance(quote, str):
        raise AttestationError("GetQuote quote must be hexadecimal text")
    quote = quote.lower()
    _quote_shape(quote, expected)
    response["quote"] = quote
    response["report_data"] = expected
    return response


def _http_post_unix(path: Path, body: bytes, timeout: float) -> bytes:
    request = (
        b"POST /GetQuote HTTP/1.1\r\n"
        b"Host: dstack\r\n"
        b"Content-Type: application/json\r\n"
        + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
        + body
    )
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(str(path))
            client.sendall(request)
            chunks: list[bytes] = []
            while chunk := client.recv(64 * 1024):
                chunks.append(chunk)
    except OSError as error:
        raise AttestationError(f"dstack guest-agent socket unavailable: {error}") from error
    response = b"".join(chunks)
    separator = response.find(b"\r\n\r\n")
    if separator < 0:
        raise AttestationError("GetQuote returned an incomplete HTTP response")
    status_line = response.split(b"\r\n", 1)[0].split()
    if len(status_line) < 2:
        raise AttestationError("GetQuote returned an invalid HTTP status")
    try:
        status = int(status_line[1])
    except ValueError as error:
        raise AttestationError("GetQuote returned an invalid HTTP status") from error
    if status != 200:
        raise AttestationError(f"GetQuote returned HTTP {status}")
    return response[separator + 4 :]


def request_quote(
    report_data: str,
    *,
    socket_path: Path = SOCKET_PATH,
    timeout: float = 10.0,
) -> dict[str, Any]:
    expected = normalize_report_data(report_data)
    payload = json.dumps({"report_data": expected}, separators=(",", ":")).encode()
    return parse_get_quote(_http_post_unix(socket_path, payload, timeout), expected)


def hand_assembled_quote(report_data: str) -> str:
    """Build an intentionally unsigned v4-shaped value for negative testing only."""

    expected = normalize_report_data(report_data)
    quote = bytearray(QUOTE_HEADER_BYTES + 584 + 64)
    quote[0:2] = (4).to_bytes(2, "little")
    quote[4:8] = (0x81).to_bytes(4, "little")
    quote[
        QUOTE_HEADER_BYTES + TD_REPORT_DATA_OFFSET : QUOTE_HEADER_BYTES
        + TD_REPORT_DATA_OFFSET
        + TD_REPORT_DATA_BYTES
    ] = bytes.fromhex(expected)
    return quote.hex()


def assert_forged_quote_rejected(quote_hex: str, *, output: Path) -> None:
    """Run the host-side negative and require dcap-qvl to reject the unsigned value."""

    output.write_text(quote_hex + "\n", encoding="utf-8")
    result = subprocess.run(
        ["dcap-qvl", "verify", "--hex", str(output)],
        capture_output=True,
        text=True,
        check=False,
        timeout=90,
    )
    if result.returncode == 0:
        raise AttestationError("dcap-qvl accepted a locally hand-assembled quote")


def verify_quote(quote_path: Path) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["dcap-qvl", "verify", "--hex", str(quote_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=90,
    )
    if result.returncode != 0:
        raise AttestationError(f"dcap-qvl rejected quote {quote_path}: {result.stderr.strip()}")
    try:
        verdict = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AttestationError("dcap-qvl returned invalid JSON") from error
    if (
        verdict.get("status") != "UpToDate"
        or verdict.get("advisory_ids") != []
        or verdict.get("qe_status", {}).get("status") != "UpToDate"
        or verdict.get("platform_status", {}).get("status") != "UpToDate"
    ):
        raise AttestationError("quote TCB posture is not fully UpToDate")
    return result


def decode_quote(quote_path: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["dcap-qvl", "decode", "--hex", str(quote_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise AttestationError(f"dcap-qvl could not decode quote: {result.stderr.strip()}")
    try:
        decoded = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AttestationError("dcap-qvl returned invalid decode JSON") from error
    header = decoded.get("header", {})
    if header.get("version") != 4 or header.get("tee_type") != 129:
        raise AttestationError("decoded quote is not TDX v4")
    report = decoded.get("report", {}).get("TD10", {})
    if not isinstance(report, dict):
        raise AttestationError("decoded quote has no TD10 report")
    for field in ("mr_td", "rt_mr0", "rt_mr1", "rt_mr2", "rt_mr3"):
        value = report.get(field)
        if (
            not isinstance(value, str)
            or len(value) != TD_MEASUREMENT_HEX_LEN
            or any(char not in "0123456789abcdef" for char in value)
        ):
            raise AttestationError(f"decoded quote has no valid TD10 {field}")
    report_data = report.get("report_data")
    if (
        not isinstance(report_data, str)
        or len(report_data) != REPORT_DATA_BYTES * 2
        or any(char not in "0123456789abcdef" for char in report_data)
    ):
        raise AttestationError("decoded quote has no valid TD10 report_data")
    attributes = report.get("td_attributes")
    if (
        not isinstance(attributes, str)
        or len(attributes) != TD_ATTRIBUTES_HEX_LEN
        or any(char not in "0123456789abcdef" for char in attributes)
    ):
        raise AttestationError("decoded quote has no valid TD10 td_attributes")
    if int.from_bytes(bytes.fromhex(attributes), "little") & 1:
        raise AttestationError("decoded quote has the TD DEBUG attribute set")
    return decoded


def inspect_pckinfo(quote_path: Path) -> dict[str, Any]:
    result = subprocess.run(
        ["dcap-qvl", "pckinfo", "--hex", str(quote_path)],
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise AttestationError(
            f"dcap-qvl could not inspect PCK information: {result.stderr.strip()}"
        )
    try:
        pckinfo = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AttestationError("dcap-qvl returned invalid pckinfo JSON") from error
    if pckinfo.get("tee_type") != "TDX":
        raise AttestationError("PCK information is not for a TDX quote")
    if not isinstance(pckinfo.get("fmspc"), str) or not pckinfo["fmspc"]:
        raise AttestationError("PCK information has no fmspc")
    if not isinstance(pckinfo.get("pce_svn"), int):
        raise AttestationError("PCK information has no pce_svn")
    chain = pckinfo.get("certificate_chain")
    expected = [
        ("Leaf PCK", "Intel SGX PCK Certificate", "Intel SGX PCK Platform CA"),
        ("PCK CA", "Intel SGX PCK Platform CA", "Intel SGX Root CA"),
        ("Root CA", "Intel SGX Root CA", "Intel SGX Root CA"),
    ]
    if not isinstance(chain, list) or len(chain) != len(expected):
        raise AttestationError("PCK certificate chain is incomplete")
    for certificate, (role, subject, issuer) in zip(chain, expected, strict=True):
        if (
            not isinstance(certificate, dict)
            or certificate.get("role") != role
            or subject not in certificate.get("subject", "")
            or issuer not in certificate.get("issuer", "")
        ):
            raise AttestationError(
                "PCK certificate chain must be Leaf PCK -> PCK Platform CA -> Intel SGX Root CA"
            )
    return pckinfo


def build_tier2_attestation(quote_hex: str, decoded: dict[str, Any]) -> dict[str, Any]:
    header = decoded.get("header", {})
    report = decoded.get("report", {}).get("TD10", {})
    if header.get("version") != 4 or header.get("tee_type") != 129:
        raise AttestationError("decoded quote is not TDX v4")
    report_data = report.get("report_data")
    if not isinstance(report_data, str):
        raise AttestationError("decoded quote has no TD10 report_data")
    normalized_quote = quote_hex.strip().lower()
    _quote_shape(normalized_quote, report_data)
    measurement = {
        "mrtd": report["mr_td"],
        "rtmr0": report["rt_mr0"],
        "rtmr1": report["rt_mr1"],
        "rtmr2": report["rt_mr2"],
        "rtmr3": report["rt_mr3"],
    }
    attestation = {
        "tee_type": "tdx",
        "quote": normalized_quote,
        "measurement": measurement,
        "report_data": report_data,
    }
    if json.loads(json.dumps(attestation, separators=(",", ":"))) != attestation:
        raise AttestationError("Tier-2 attestation JSON round-trip was lossy")
    return attestation


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-data", required=True, help="hex report_data payload")
    parser.add_argument("--socket", type=Path, default=SOCKET_PATH)
    parser.add_argument("--quote-out", type=Path, required=True)
    parser.add_argument("--response-out", type=Path, required=True)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--decode-out", type=Path)
    parser.add_argument("--pckinfo-out", type=Path)
    parser.add_argument("--attestation-out", type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        response = request_quote(args.report_data, socket_path=args.socket)
        args.quote_out.write_text(response["quote"] + "\n", encoding="utf-8")
        args.response_out.write_text(
            json.dumps(response, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        if args.verify:
            verify_quote(args.quote_out)
        decoded = None
        if args.decode_out is not None or args.attestation_out is not None:
            decoded = decode_quote(args.quote_out)
            if args.decode_out is not None:
                args.decode_out.write_text(
                    json.dumps(decoded, sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )
        if args.pckinfo_out is not None:
            pckinfo = inspect_pckinfo(args.quote_out)
            args.pckinfo_out.write_text(
                json.dumps(pckinfo, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
        if args.attestation_out is not None:
            if decoded is None:
                decoded = decode_quote(args.quote_out)
            attestation = build_tier2_attestation(response["quote"], decoded)
            args.attestation_out.write_text(
                json.dumps(attestation, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
    except AttestationError as error:
        print(json.dumps({"attestation": False, "error": str(error)}, sort_keys=True))
        return 1
    print(
        json.dumps(
            {
                "attestation": True,
                "quote_hex_length": len(response["quote"]),
                "report_data": response["report_data"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
