import json
import subprocess
from pathlib import Path

import basecrawl


ROOT = Path(__file__).resolve().parents[3]
EXAMPLE_OPTIONS = {"formats": ["markdown", "links", "metadata"], "render_enabled": False}
QUOTE_OPTIONS = {"formats": ["markdown", "links"], "render_enabled": False}


def cli_proof(url: str, formats: list[str]) -> dict[str, object]:
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
            url,
            "--formats",
            ",".join(formats),
            "--no-js",
            "--output",
            "json",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(output.stdout)


def test_python_matches_cli_content_digests_and_outputs() -> None:
    python_example = basecrawl.scrape("https://example.com", EXAMPLE_OPTIONS)
    cli_example = cli_proof("https://example.com", EXAMPLE_OPTIONS["formats"])

    assert python_example["result"]["result_hash"] == cli_example["result"]["result_hash"]
    assert python_example["tls"]["cert_chain_hash"] == cli_example["tls"]["cert_chain_hash"]

    python_quotes = basecrawl.scrape("https://quotes.toscrape.com", QUOTE_OPTIONS)
    cli_quotes = cli_proof("https://quotes.toscrape.com", QUOTE_OPTIONS["formats"])

    assert python_quotes["result"]["formats_produced"]["markdown"] == cli_quotes["result"][
        "formats_produced"
    ]["markdown"]
    assert python_quotes["result"]["formats_produced"]["links"] == cli_quotes["result"][
        "formats_produced"
    ]["links"]
