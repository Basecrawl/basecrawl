from __future__ import annotations

import copy
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# ruff: noqa: E402

IMAGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(IMAGE_DIR))

import measurement_allowlist as measurements


ALLOWLIST_PATH = IMAGE_DIR / "allowlist.json"
APP_COMPOSE_PATH = IMAGE_DIR / "phala-app-compose.json"
RECONCILIATION_PATH = IMAGE_DIR / "measurement-reconciliation.json"


class MeasurementAllowlistTests(unittest.TestCase):
    def test_allowlist_is_the_exact_six_field_live_tuple(self) -> None:
        entries = measurements.load_allowlist(ALLOWLIST_PATH)
        self.assertEqual(len(entries), 1)
        self.assertEqual(
            set(entries[0]),
            {"mrtd", "rtmr0", "rtmr1", "rtmr2", "compose_hash", "os_image_hash"},
        )
        self.assertTrue(measurements.allowlist_contains(entries[0], entries))

    def test_every_pinned_field_drift_denies(self) -> None:
        entry = measurements.load_allowlist(ALLOWLIST_PATH)[0]
        for field in entry:
            with self.subTest(field=field):
                candidate = copy.deepcopy(entry)
                candidate[field] = "0" * len(candidate[field])
                self.assertFalse(measurements.allowlist_contains(candidate, [entry]))

    def test_phala_app_compose_hash_is_the_allowlisted_compose_hash(self) -> None:
        entry = measurements.load_allowlist(ALLOWLIST_PATH)[0]
        self.assertEqual(
            measurements.phala_app_compose_hash(APP_COMPOSE_PATH),
            entry["compose_hash"],
        )

    def test_phala_normalization_ignores_nulls_and_order_but_not_content(self) -> None:
        source = {"z": {"b": 2, "a": 1}, "null_value": None, "list": [3, 2, 1]}
        reordered = json.dumps(
            {"list": [3, 2, 1], "z": {"a": 1, "b": 2}, "null_value": None},
            indent=2,
        )
        self.assertEqual(
            measurements.phala_app_compose_hash(source),
            measurements.phala_app_compose_hash(reordered),
        )
        changed = copy.deepcopy(source)
        changed["z"]["a"] = 9
        self.assertNotEqual(
            measurements.phala_app_compose_hash(source),
            measurements.phala_app_compose_hash(changed),
        )

    def test_current_compose_and_image_tuple_is_unchanged(self) -> None:
        record = json.loads(RECONCILIATION_PATH.read_text())
        self.assertEqual(
            record["image"]["build_digest"],
            "sha256:57a2ecdc9257846ca69dce38c53a464b68e9a08575fb45d8d18aed5b6b28f366",
        )
        self.assertEqual(
            record["canonical_measurement"]["compose_hash"],
            "5f87b1082fdb39e7345db64bb5d5b5b62fff01b0afc624ad4da861ede4361a42",
        )
        self.assertEqual(
            (IMAGE_DIR / "docker-compose.yml").read_bytes(),
            (IMAGE_DIR / "evidence/m2/compose/docker-compose.yml").read_bytes(),
        )

    def test_reconciliation_record_is_complete_and_reconciled(self) -> None:
        result = measurements.validate_reconciliation(
            RECONCILIATION_PATH,
            allowlist_path=ALLOWLIST_PATH,
            app_compose_path=APP_COMPOSE_PATH,
        )
        self.assertEqual(result["status"], "reconciled")
        self.assertEqual(
            result["canonical_measurement"]["compose_hash"],
            "5f87b1082fdb39e7345db64bb5d5b5b62fff01b0afc624ad4da861ede4361a42",
        )
        manifest = result["evidence_bundle"]["manifest_path"]
        self.assertFalse(Path(manifest).is_absolute())
        self.assertEqual(
            result["image"]["build_digest"],
            "sha256:57a2ecdc9257846ca69dce38c53a464b68e9a08575fb45d8d18aed5b6b28f366",
        )

    def test_bundle_is_repository_local_and_hash_manifested(self) -> None:
        record = json.loads(RECONCILIATION_PATH.read_text())
        bundle = record["evidence_bundle"]
        manifest_path = IMAGE_DIR / bundle["manifest_path"]
        manifest = json.loads(manifest_path.read_text())
        self.assertGreaterEqual(len(manifest["files"]), 20)
        for relative_path in manifest["files"]:
            with self.subTest(path=relative_path):
                self.assertFalse(Path(relative_path).is_absolute())
                self.assertNotIn("..", Path(relative_path).parts)

    def test_absolute_tmp_only_provenance_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(IMAGE_DIR / "evidence", root / "evidence")
            record = json.loads(RECONCILIATION_PATH.read_text())
            record["live_evidence"][0]["quote_path"] = (
                "/tmp/basecrawl-first-cert-quote.hex"
            )
            path = root / "measurement-reconciliation.json"
            path.write_text(json.dumps(record))
            with self.assertRaisesRegex(
                measurements.MeasurementAllowlistError,
                "repository-relative",
            ):
                measurements.validate_reconciliation(
                    path,
                    allowlist_path=ALLOWLIST_PATH,
                    app_compose_path=APP_COMPOSE_PATH,
                )

    def test_missing_or_tampered_manifested_evidence_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(IMAGE_DIR / "evidence", root / "evidence")
            record = json.loads(RECONCILIATION_PATH.read_text())
            record_path = root / "measurement-reconciliation.json"
            record_path.write_text(json.dumps(record))
            metadata = root / record["catalog"]["metadata_source"]
            metadata.write_bytes(metadata.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                measurements.MeasurementAllowlistError,
                "manifest",
            ):
                measurements.validate_reconciliation(
                    record_path,
                    allowlist_path=ALLOWLIST_PATH,
                    app_compose_path=APP_COMPOSE_PATH,
                )

    def test_symlinked_evidence_cannot_escape_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(IMAGE_DIR / "evidence", root / "evidence")
            record = json.loads(RECONCILIATION_PATH.read_text())
            record_path = root / "measurement-reconciliation.json"
            record_path.write_text(json.dumps(record))
            metadata = root / record["catalog"]["metadata_source"]
            outside = root / "outside-metadata.json"
            outside.write_bytes(metadata.read_bytes())
            metadata.unlink()
            metadata.symlink_to(outside)
            measurements.write_evidence_manifest(
                root / record["evidence_bundle"]["manifest_path"]
            )
            with self.assertRaisesRegex(
                measurements.MeasurementAllowlistError,
                "inside",
            ):
                measurements.validate_reconciliation(
                    record_path,
                    allowlist_path=ALLOWLIST_PATH,
                    app_compose_path=APP_COMPOSE_PATH,
                )

    def test_catalog_release_digest_binds_sha256sum_contents(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(IMAGE_DIR / "evidence", root / "evidence")
            record = json.loads(RECONCILIATION_PATH.read_text())
            record_path = root / "measurement-reconciliation.json"
            record_path.write_text(json.dumps(record))
            checksum_path = root / record["catalog"]["sha256sum_path"]
            checksum_path.write_text(
                checksum_path.read_text().replace(
                    record["catalog"]["release_files_sha256"]["ovmf.fd"],
                    "0" * 64,
                )
            )
            measurements.write_evidence_manifest(
                root / record["evidence_bundle"]["manifest_path"]
            )
            with self.assertRaisesRegex(
                measurements.MeasurementAllowlistError,
                "catalog",
            ):
                measurements.validate_reconciliation(
                    record_path,
                    allowlist_path=ALLOWLIST_PATH,
                    app_compose_path=APP_COMPOSE_PATH,
                )

    def test_live_evidence_requires_two_independent_deployments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(IMAGE_DIR / "evidence", root / "evidence")
            record = json.loads(RECONCILIATION_PATH.read_text())
            record["live_evidence"][1] = copy.deepcopy(record["live_evidence"][0])
            record_path = root / "measurement-reconciliation.json"
            record_path.write_text(json.dumps(record))
            with self.assertRaisesRegex(
                measurements.MeasurementAllowlistError,
                "independent",
            ):
                measurements.validate_reconciliation(
                    record_path,
                    allowlist_path=ALLOWLIST_PATH,
                    app_compose_path=APP_COMPOSE_PATH,
                )

    def test_catalog_contents_are_parsed_independently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(IMAGE_DIR / "evidence", root / "evidence")
            record = json.loads(RECONCILIATION_PATH.read_text())
            record_path = root / "measurement-reconciliation.json"
            record_path.write_text(json.dumps(record))
            metadata = root / record["catalog"]["metadata_source"]
            contents = json.loads(metadata.read_text())
            contents["git_revision"] = "0" * 40
            metadata.write_text(json.dumps(contents))
            manifest_path = root / record["evidence_bundle"]["manifest_path"]
            measurements.write_evidence_manifest(manifest_path)
            with self.assertRaisesRegex(
                measurements.MeasurementAllowlistError,
                "catalog",
            ):
                measurements.validate_reconciliation(
                    record_path,
                    allowlist_path=ALLOWLIST_PATH,
                    app_compose_path=APP_COMPOSE_PATH,
                )

    def test_dstack_measurement_input_hash_is_bound_to_catalog_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            shutil.copytree(IMAGE_DIR / "evidence", root / "evidence")
            record = json.loads(RECONCILIATION_PATH.read_text())
            record["dstack_mr"]["metadata_sha256"] = "0" * 64
            invocation_path = root / record["dstack_mr"]["invocation_path"]
            invocation = json.loads(invocation_path.read_text())
            invocation["metadata_sha256"] = "0" * 64
            invocation_path.write_text(json.dumps(invocation))
            record_path = root / "measurement-reconciliation.json"
            record_path.write_text(json.dumps(record))
            measurements.write_evidence_manifest(
                root / record["evidence_bundle"]["manifest_path"]
            )
            with self.assertRaisesRegex(
                measurements.MeasurementAllowlistError,
                "dstack-mr",
            ):
                measurements.validate_reconciliation(
                    record_path,
                    allowlist_path=ALLOWLIST_PATH,
                    app_compose_path=APP_COMPOSE_PATH,
                )

    def test_each_complete_event_log_replays_against_signed_quote_rtmr3(
        self,
    ) -> None:
        record = measurements.validate_reconciliation(
            RECONCILIATION_PATH,
            allowlist_path=ALLOWLIST_PATH,
            app_compose_path=APP_COMPOSE_PATH,
        )
        for evidence in record["live_evidence"]:
            with self.subTest(cvm=evidence["cvm_name"]):
                event_path = IMAGE_DIR / evidence["event_log_path"]
                event_log = json.loads(event_path.read_text())
                self.assertGreater(len(event_log), 0)
                self.assertEqual(
                    measurements.replay_rtmr3(event_log)["rtmr3"],
                    evidence["rtmr3"],
                )

    def test_event_payload_or_digest_tampering_fails_replay(self) -> None:
        record = json.loads(RECONCILIATION_PATH.read_text())
        event_path = IMAGE_DIR / record["live_evidence"][0]["event_log_path"]
        events = json.loads(event_path.read_text())
        runtime_event = next(event for event in events if event.get("imr") == 3)
        runtime_event["event_payload"] = "00"
        with self.assertRaisesRegex(
            measurements.MeasurementAllowlistError,
            "digest mismatch",
        ):
            measurements.replay_rtmr3(events)

    def test_missing_reconciliation_artifact_fails_closed(self) -> None:
        with self.assertRaises(measurements.MeasurementAllowlistError):
            measurements.validate_reconciliation(
                RECONCILIATION_PATH.with_name("does-not-exist.json"),
                allowlist_path=ALLOWLIST_PATH,
                app_compose_path=APP_COMPOSE_PATH,
            )


if __name__ == "__main__":
    unittest.main()
