from __future__ import annotations

import copy
import json
import re
import sys
import unittest
from unittest import mock
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

    def test_malformed_volume_containers_fail_with_structured_errors(self) -> None:
        for value in (None, "not-a-list", {"source": "/x"}):
            with self.subTest(value=value):
                document = {
                    "services": {
                        "basecrawl": {
                            "image": IMAGE_REF,
                            "volumes": value,
                        }
                    }
                }
                with mock.patch.object(
                    repro, "_normalized_compose", return_value=document
                ):
                    with self.assertRaisesRegex(
                        repro.ReproducibilityError,
                        r"services\.basecrawl\.volumes",
                    ) as raised:
                        repro.validate_compose("ignored")
                self.assertEqual(raised.exception.code, "invalid_compose_volume")

    def test_malformed_volume_entries_fail_with_structured_errors(self) -> None:
        for value in (None, "not-a-mapping", {"type": "bind", "source": "/x"}):
            with self.subTest(value=value):
                document = {
                    "services": {
                        "basecrawl": {
                            "image": IMAGE_REF,
                            "volumes": [value],
                        }
                    }
                }
                with mock.patch.object(
                    repro, "_normalized_compose", return_value=document
                ):
                    with self.assertRaisesRegex(
                        repro.ReproducibilityError,
                        r"services\.basecrawl\.volumes\[0\]",
                    ) as raised:
                        repro.validate_compose("ignored")
                self.assertEqual(raised.exception.code, "invalid_compose_volume")

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

    def test_buildkit_metadata_requires_verifiable_invocation_and_output_identity(
        self,
    ) -> None:
        metadata = json.loads(
            (IMAGE_DIR / "evidence/m2/build/build-1.metadata.json").read_text()
        )
        history = json.loads(
            (IMAGE_DIR / "evidence/m2/build/build-1.history.json").read_text()
        )
        repro.validate_buildkit_metadata(metadata, SHA256, 0, history=history)
        for mutation in ("empty_ref", "bad_ref", "missing_provenance", "bad_output"):
            with self.subTest(mutation=mutation):
                candidate = copy.deepcopy(metadata)
                if mutation == "empty_ref":
                    candidate["buildx.build.ref"] = " "
                elif mutation == "bad_ref":
                    candidate["buildx.build.ref"] = "not-a-buildkit-reference"
                elif mutation == "missing_provenance":
                    del candidate["buildx.build.provenance"]
                else:
                    candidate["containerimage.descriptor"]["digest"] = (
                        "sha256:" + "0" * 64
                    )
                with self.assertRaisesRegex(
                    repro.ReproducibilityError,
                    "BuildKit",
                ):
                    repro.validate_buildkit_metadata(
                        candidate,
                        SHA256,
                        0,
                        history=history,
                    )

    def test_buildkit_reference_resolves_to_recorded_invocation_and_output(self) -> None:
        metadata = json.loads(
            (IMAGE_DIR / "evidence/m2/build/build-1.metadata.json").read_text()
        )
        history = json.loads(
            (IMAGE_DIR / "evidence/m2/build/build-1.history.json").read_text()
        )
        resolved = repro.validate_buildkit_metadata(
            metadata,
            SHA256,
            0,
            history=history,
        )
        self.assertEqual(resolved, SHA256)

    def test_unresolved_buildkit_reference_is_structured_and_fail_closed(self) -> None:
        metadata = json.loads(
            (IMAGE_DIR / "evidence/m2/build/build-1.metadata.json").read_text()
        )
        with mock.patch.object(
            repro,
            "_inspect_buildkit_reference",
            return_value=(1, "", "no record found"),
        ):
            with self.assertRaisesRegex(
                repro.ReproducibilityError,
                "cannot resolve BuildKit reference",
            ) as raised:
                repro.validate_buildkit_metadata(metadata, SHA256, 0)
        self.assertEqual(raised.exception.code, "unresolved_buildkit_reference")

    def test_buildkit_reference_output_mismatch_is_fail_closed(self) -> None:
        metadata = json.loads(
            (IMAGE_DIR / "evidence/m2/build/build-1.metadata.json").read_text()
        )
        history = json.loads(
            (IMAGE_DIR / "evidence/m2/build/build-1.history.json").read_text()
        )
        history["Attachments"][0]["Digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(
            repro.ReproducibilityError,
            "output identity",
        ) as raised:
            repro.validate_buildkit_metadata(
                metadata,
                SHA256,
                0,
                history=history,
            )
        self.assertEqual(raised.exception.code, "buildkit_output_mismatch")

    def test_buildkit_reference_invocation_mismatch_is_fail_closed(self) -> None:
        metadata = json.loads(
            (IMAGE_DIR / "evidence/m2/build/build-1.metadata.json").read_text()
        )
        history = json.loads(
            (IMAGE_DIR / "evidence/m2/build/build-1.history.json").read_text()
        )
        history["Config"]["SourceDateEpoch"] = "0"
        with self.assertRaisesRegex(
            repro.ReproducibilityError,
            "invocation",
        ) as raised:
            repro.validate_buildkit_metadata(
                metadata,
                SHA256,
                0,
                history=history,
            )
        self.assertEqual(raised.exception.code, "buildkit_invocation_mismatch")

    def test_validate_definitions_includes_durable_measurement_evidence(self) -> None:
        report = repro.validate_definitions()
        self.assertEqual(report["measurement_evidence"], "reconciled")


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

    def test_absolute_tmp_provenance_is_rejected(self) -> None:
        entry = matching_evidence()[0]
        for field in repro.PROVENANCE_FIELDS:
            entry[field] = f"/tmp/{field}.json"
        with self.assertRaisesRegex(
            repro.ReproducibilityError,
            "repository-relative",
        ):
            repro._require_live_provenance(entry, 0)


if __name__ == "__main__":
    unittest.main()
