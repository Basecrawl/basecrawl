import json
import multiprocessing
import subprocess
from contextlib import contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import basecrawl
import pytest


ROOT = Path(__file__).resolve().parents[3]
LOCAL_OPTIONS = {"formats": ["markdown", "links", "metadata"], "render_enabled": False}


class StaticHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    body = b"<!doctype html><html><title>Parity</title><body>same bytes</body></html>"

    def do_GET(self) -> None:  # noqa: N802
        self.send_response_only(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


@contextmanager
def static_server() -> object:
    port_queue = multiprocessing.Queue()
    process = multiprocessing.Process(target=serve_static_fixture, args=(port_queue,), daemon=True)
    process.start()
    try:
        yield f"http://127.0.0.1:{port_queue.get(timeout=5)}/"
    finally:
        process.terminate()
        process.join(timeout=5)


def serve_static_fixture(port_queue) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 21091), StaticHandler)
    port_queue.put(server.server_port)
    server.serve_forever()


def cli_run(url: str, formats: list[str] | None = None) -> subprocess.CompletedProcess[str]:
    command = [
        "cargo",
        "run",
        "--quiet",
        "--manifest-path",
        str(ROOT / "Cargo.toml"),
        "--package",
        "basecrawl-core",
        "--bin",
        "basecrawl",
        "--",
        url,
        "--no-js",
        "--output",
        "json",
    ]
    if formats is not None:
        command.extend(["--formats", ",".join(formats)])

    return subprocess.run(command, check=False, capture_output=True, text=True)


def cli_proof(url: str, formats: list[str]) -> dict[str, object]:
    output = cli_run(url, formats)
    output.check_returncode()
    return json.loads(output.stdout)


def canonical_wire(proof: dict[str, object]) -> str:
    return json.dumps(proof, ensure_ascii=False, separators=(",", ":"))


def without_volatile_fields(proof: dict[str, object]) -> dict[str, object]:
    normalized = deepcopy(proof)
    normalized["egress"].pop("timestamp")
    normalized["egress"].pop("egress_ip")
    normalized["tls"].pop("handshake_transcript_hash")
    normalized["tls"].pop("server_ephemeral_pubkey")
    normalized["response"].pop("headers_hash")
    return normalized


def error_kind(stderr_or_exception: str) -> str:
    return json.loads(stderr_or_exception)["error"]["kind"]


def test_python_and_cli_emit_byte_identical_canonical_json_after_normalization() -> None:
    with static_server() as url:
        python_proof = basecrawl.scrape(url, formats=["rawHtml"], render_enabled=False)
        cli_output = cli_run(url, ["rawHtml"])

    cli_output.check_returncode()
    assert canonical_wire(without_volatile_fields(python_proof)) == canonical_wire(
        without_volatile_fields(json.loads(cli_output.stdout))
    )


@pytest.mark.parametrize(
    "formats",
    [
        None,
        ["metadata", "rawHtml", "metadata"],
        ["rawHtml"],
    ],
)
def test_python_and_cli_normalize_format_selection_identically(
    formats: list[str] | None,
) -> None:
    python_options = {"render_enabled": False}
    if formats is not None:
        python_options["formats"] = formats

    with static_server() as url:
        python_proof = basecrawl.scrape(url, python_options)
        cli_output = cli_run(url, formats)

    cli_output.check_returncode()
    cli_proof = json.loads(cli_output.stdout)
    assert python_proof["request"]["formats"] == cli_proof["request"]["formats"]
    assert list(python_proof["result"]["formats_produced"]) == list(
        cli_proof["result"]["formats_produced"]
    )


@pytest.mark.parametrize(
    ("url", "options", "expected_kind"),
    [
        ("not a url", {"formats": ["rawHtml"]}, "invalid_url"),
        ("https://example.com", {"formats": ["bogusfmt"]}, "invalid_format"),
    ],
)
def test_python_and_cli_fail_without_partial_scrapeproof(
    url: str, options: dict[str, object], expected_kind: str
) -> None:
    cli_output = cli_run(url, options["formats"])

    assert cli_output.returncode != 0
    assert cli_output.stdout == ""
    assert error_kind(cli_output.stderr) == expected_kind

    with pytest.raises(ValueError) as error:
        basecrawl.scrape(url, options)

    assert error_kind(str(error.value)) == expected_kind


def test_python_version_matches_cli_version() -> None:
    output = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "--manifest-path",
            str(ROOT / "Cargo.toml"),
            "--package",
            "basecrawl-core",
            "--bin",
            "basecrawl",
            "--",
            "--version",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert output.stdout.strip() == f"basecrawl {basecrawl.__version__}"


def test_python_matches_cli_content_digests_and_outputs_on_deterministic_content() -> None:
    with static_server() as url:
        python_proof = basecrawl.scrape(url, LOCAL_OPTIONS)
        cli = cli_proof(url, LOCAL_OPTIONS["formats"])

    assert python_proof["result"]["result_hash"] == cli["result"]["result_hash"]
    assert python_proof["tls"]["cert_chain_hash"] == cli["tls"]["cert_chain_hash"]
    assert python_proof["result"]["formats_produced"]["markdown"] == cli["result"][
        "formats_produced"
    ]["markdown"]
    assert python_proof["result"]["formats_produced"]["links"] == cli["result"][
        "formats_produced"
    ]["links"]
