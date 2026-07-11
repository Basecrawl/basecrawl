from __future__ import annotations

import copy
import re
import sys
import unittest
from pathlib import Path

# ruff: noqa: E402

IMAGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(IMAGE_DIR))

import reproducibility as repro


SHA256 = "sha256:57a2ecdc9257846ca69dce38c53a464b68e9a08575fb45d8d18aed5b6b28f366"
IMAGE_REF = f"docker.io/mathiiss/basecrawl-cvm@{SHA256}"
SHA384_HEX = "b" * 96


def matching_evidence() -> list[dict[str, str]]:
    entry = {
        "build_digest": SHA256,
        "image_ref": IMAGE_REF,
        "image_identity": "c" * 64,
        "mrtd": SHA384_HEX,
        "rtmr0": SHA384_HEX,
        "rtmr1": SHA384_HEX,
        "rtmr2": SHA384_HEX,
        "compose_hash": "d" * 64,
        "app_id": "a" * 40,
        "cvm_name": "basecrawl-repro-a",
    }
    second = copy.deepcopy(entry)
    second["app_id"] = "b" * 40
    second["cvm_name"] = "basecrawl-repro-b"
    return [entry, second]


class StaticDefinitionTests(unittest.TestCase):
    def test_dockerfile_pins_every_external_stage_by_digest(self) -> None:
        report = repro.validate_dockerfile((IMAGE_DIR / "Dockerfile").read_text())
        self.assertGreaterEqual(len(report.external_images), 2)
        self.assertEqual(report.unpinned_images, ())
        self.assertTrue(
            all(
                re.search(r"@sha256:[0-9a-f]{64}$", image)
                for image in report.external_images
            )
        )

    def test_dockerfile_uses_locked_toolchain_without_os_package_installers(
        self,
    ) -> None:
        text = (IMAGE_DIR / "Dockerfile").read_text()
        self.assertRegex(text.splitlines()[0], r"^# syntax=.+@sha256:[0-9a-f]{64}$")
        self.assertIn("cargo build --release --locked", text)
        self.assertIn("RUST_VERSION=1.96.0", text)
        self.assertNotIn("ARG BUILD_IMAGE", text)
        self.assertNotIn("ARG RUNTIME_IMAGE", text)
        self.assertNotIn("rustup", text.lower())
        self.assertNotRegex(
            text, r"(?im)^\s*RUN\s+.*\b(?:apt|apt-get|apk|dnf|yum)\s+install\b"
        )
        self.assertNotIn("playwright install --with-deps", text.lower())

    def test_chromium_and_runtime_os_are_supplied_by_one_pinned_image(self) -> None:
        text = (IMAGE_DIR / "Dockerfile").read_text()
        self.assertRegex(
            text,
            r"ghcr\.io/puppeteer/puppeteer:24\.37\.2@sha256:[0-9a-f]{64}",
        )
        self.assertIn("CHROMIUM_VERSION=145.0.7632.46", text)
        self.assertIn(
            "CHROME=/home/pptruser/.cache/puppeteer/chrome/"
            "linux-145.0.7632.46/chrome-linux64/chrome",
            text,
        )

    def test_compose_pins_every_service_and_mounts_guest_agent_socket(self) -> None:
        report = repro.validate_compose((IMAGE_DIR / "docker-compose.yml").read_text())
        self.assertGreaterEqual(len(report.services), 1)
        self.assertEqual(report.unpinned_services, ())
        self.assertEqual(report.missing_image_services, ())
        self.assertTrue(report.mounts_dstack_socket)

    def test_socket_markers_outside_volumes_are_not_accepted(self) -> None:
        text = f"""
services:
  basecrawl:
    image: "{IMAGE_REF}"
    labels:
      source: "/var/run/dstack.sock"
      target: "/var/run/dstack.sock"
"""
        self.assertFalse(repro.validate_compose(text).mounts_dstack_socket)

    def test_build_command_normalizes_reproducibility_inputs(self) -> None:
        command = repro.build_command(
            output=Path("/tmp/basecrawl-image.tar"),
            metadata=Path("/tmp/basecrawl-metadata.json"),
        )
        joined = " ".join(command)
        self.assertIn("--no-cache", command)
        self.assertIn("--provenance=false", command)
        self.assertIn("--sbom=false", command)
        self.assertIn("SOURCE_DATE_EPOCH=1700000000", joined)
        self.assertIn(
            "type=oci,dest=/tmp/basecrawl-image.tar,rewrite-timestamp=true", joined
        )
        self.assertIn("--platform linux/amd64", joined)


class ReproducibilityEvidenceTests(unittest.TestCase):
    def test_two_matching_builds_and_deployments_pass(self) -> None:
        baseline = repro.assert_reproducible_evidence(matching_evidence())
        self.assertEqual(baseline["compose_hash"], "d" * 64)

    def test_every_measurement_or_compose_drift_fails_closed(self) -> None:
        for field in (
            "build_digest",
            "image_ref",
            "image_identity",
            "mrtd",
            "rtmr0",
            "rtmr1",
            "rtmr2",
            "compose_hash",
        ):
            with self.subTest(field=field):
                evidence = matching_evidence()
                evidence[1][field] = (
                    "sha256:" + ("e" * 64)
                    if field == "build_digest"
                    else (
                        f"ghcr.io/baseintelligence/basecrawl-cvm@sha256:{'e' * 64}"
                        if field == "image_ref"
                        else "e" * len(evidence[1][field])
                    )
                )
                with self.assertRaisesRegex(repro.ReproducibilityError, field):
                    repro.assert_reproducible_evidence(evidence)

    def test_mutable_image_identity_is_never_accepted(self) -> None:
        evidence = matching_evidence()
        evidence[1]["image_ref"] = "ghcr.io/baseintelligence/basecrawl-cvm:latest"
        with self.assertRaisesRegex(repro.ReproducibilityError, "image_ref"):
            repro.assert_reproducible_evidence(evidence)

    def test_image_ref_digest_must_equal_build_and_compose_digest(self) -> None:
        evidence = matching_evidence()
        evidence[1]["image_ref"] = "docker.io/mathiiss/basecrawl-cvm@sha256:" + (
            "e" * 64
        )
        with self.assertRaisesRegex(repro.ReproducibilityError, "build_digest"):
            repro.assert_reproducible_evidence(evidence)

    def test_incomplete_or_malformed_evidence_fails_closed(self) -> None:
        for mutation in ("missing", "malformed"):
            with self.subTest(mutation=mutation):
                evidence = matching_evidence()
                if mutation == "missing":
                    del evidence[1]["rtmr2"]
                else:
                    evidence[1]["mrtd"] = "not-a-register"
                with self.assertRaises(repro.ReproducibilityError):
                    repro.assert_reproducible_evidence(evidence)

    def test_independent_deployments_require_unique_identities(self) -> None:
        evidence = matching_evidence()
        evidence[1]["app_id"] = evidence[0]["app_id"]
        with self.assertRaisesRegex(repro.ReproducibilityError, "app_id is not unique"):
            repro.assert_reproducible_evidence(evidence)


if __name__ == "__main__":
    unittest.main()
