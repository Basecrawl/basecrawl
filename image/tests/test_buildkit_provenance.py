from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

# ruff: noqa: E402

IMAGE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(IMAGE_DIR))

import buildkit_provenance as provenance
import measurement_allowlist


BUILD_DIGEST = "sha256:57a2ecdc9257846ca69dce38c53a464b68e9a08575fb45d8d18aed5b6b28f366"
MANIFEST_PATH = IMAGE_DIR / "evidence/m2/manifest.json"


def build_record(index: int) -> tuple[dict[str, object], dict[str, object]]:
    metadata = json.loads(
        (IMAGE_DIR / f"evidence/m2/build/build-{index}.metadata.json").read_text()
    )
    history = json.loads(
        (IMAGE_DIR / f"evidence/m2/build/build-{index}.history.json").read_text()
    )
    return metadata, history


class BuildKitProvenanceTests(unittest.TestCase):
    def test_retained_records_pass_and_return_canonical_distinct_refs(self) -> None:
        manifest = measurement_allowlist.verify_evidence_manifest(MANIFEST_PATH)
        records = []
        for index in (1, 2):
            metadata, history = build_record(index)
            records.append(
                provenance.validate_buildkit_record(
                    metadata,
                    history,
                    expected_digest=BUILD_DIGEST,
                    index=index - 1,
                    metadata_path=IMAGE_DIR
                    / f"evidence/m2/build/build-{index}.metadata.json",
                    history_path=IMAGE_DIR
                    / f"evidence/m2/build/build-{index}.history.json",
                    manifest_files=manifest,
                )
            )
        provenance.validate_independent_records(records)
        self.assertEqual(
            [record.canonical_ref for record in records],
            [
                "default/default/aq0sgf81zazlsf122lupacz8h",
                "default/default/2cdtugm4vbavu7y8tlmikkbc3",
            ],
        )

    def test_materials_require_exact_normalized_set_equality(self) -> None:
        metadata, history = build_record(1)
        for mutation in ("metadata_extra", "metadata_missing", "history_extra"):
            with self.subTest(mutation=mutation):
                candidate_metadata = copy.deepcopy(metadata)
                candidate_history = copy.deepcopy(history)
                if mutation == "metadata_extra":
                    candidate_metadata["buildx.build.provenance"]["materials"].append(
                        {
                            "uri": "pkg:docker/example@1?digest=sha256:" + "0" * 64,
                            "digest": {"sha256": "0" * 64},
                        }
                    )
                elif mutation == "metadata_missing":
                    candidate_metadata["buildx.build.provenance"]["materials"].pop()
                else:
                    candidate_history["Materials"].append(
                        {
                            "URI": "pkg:docker/example@1?digest=sha256:" + "0" * 64,
                            "Digests": ["sha256:" + "0" * 64],
                        }
                    )
                with self.assertRaises(provenance.BuildKitProvenanceError):
                    provenance.validate_buildkit_record(
                        candidate_metadata,
                        candidate_history,
                        expected_digest=BUILD_DIGEST,
                        index=0,
                    )

    def test_reference_and_manifest_bindings_fail_closed(self) -> None:
        metadata, history = build_record(1)
        manifest = measurement_allowlist.verify_evidence_manifest(MANIFEST_PATH)
        cases = (
            ("bad_reference", lambda value: value.update({"buildx.build.ref": ""})),
            ("wrong_history_ref", lambda value: value.update({"Ref": "other-ref"})),
            (
                "descriptor_digest",
                lambda value: value["containerimage.descriptor"].update(
                    {"digest": "sha256:" + "0" * 64}
                ),
            ),
            (
                "history_output",
                lambda value: value["Attachments"][0].update(
                    {"Digest": "sha256:" + "0" * 64}
                ),
            ),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                candidate_metadata = copy.deepcopy(metadata)
                candidate_history = copy.deepcopy(history)
                if name in {"bad_reference", "descriptor_digest"}:
                    mutate(candidate_metadata)
                else:
                    mutate(candidate_history)
                with self.assertRaises(provenance.BuildKitProvenanceError):
                    provenance.validate_buildkit_record(
                        candidate_metadata,
                        candidate_history,
                        expected_digest=BUILD_DIGEST,
                        index=0,
                        metadata_path=IMAGE_DIR
                        / "evidence/m2/build/build-1.metadata.json",
                        history_path=IMAGE_DIR
                        / "evidence/m2/build/build-1.history.json",
                        manifest_files=manifest,
                    )

    def test_manifest_must_cover_both_immutable_records(self) -> None:
        metadata, history = build_record(1)
        manifest = measurement_allowlist.verify_evidence_manifest(MANIFEST_PATH)
        del manifest["build/build-1.history.json"]
        with self.assertRaisesRegex(
            provenance.BuildKitProvenanceError,
            "manifest",
        ):
            provenance.validate_buildkit_record(
                metadata,
                history,
                expected_digest=BUILD_DIGEST,
                index=0,
                metadata_path=IMAGE_DIR / "evidence/m2/build/build-1.metadata.json",
                history_path=IMAGE_DIR / "evidence/m2/build/build-1.history.json",
                manifest_files=manifest,
            )

    def test_independent_records_reject_reused_reference_even_with_equal_digest(
        self,
    ) -> None:
        metadata, history = build_record(1)
        second_metadata, second_history = build_record(2)
        second_metadata["buildx.build.ref"] = metadata["buildx.build.ref"]
        second_history["Ref"] = history["Ref"]
        first = provenance.validate_buildkit_record(
            metadata,
            history,
            expected_digest=BUILD_DIGEST,
            index=0,
        )
        second = provenance.validate_buildkit_record(
            second_metadata,
            second_history,
            expected_digest=BUILD_DIGEST,
            index=1,
        )
        with self.assertRaisesRegex(
            provenance.BuildKitProvenanceError,
            "distinct",
        ):
            provenance.validate_independent_records([first, second])

    def test_wrappers_share_rejection_semantics_for_extra_material(self) -> None:
        metadata, history = build_record(1)
        metadata["buildx.build.provenance"]["materials"].append(
            {
                "uri": "pkg:docker/example@1?digest=sha256:" + "0" * 64,
                "digest": {"sha256": "0" * 64},
            }
        )
        with self.assertRaises(provenance.BuildKitProvenanceError) as shared:
            provenance.validate_buildkit_record(
                metadata,
                history,
                expected_digest=BUILD_DIGEST,
                index=0,
            )
        with self.assertRaises(
            measurement_allowlist.MeasurementAllowlistError
        ) as durable:
            measurement_allowlist._validate_buildkit_history(
                metadata,
                history,
                build_digest=BUILD_DIGEST,
                index=0,
            )
        self.assertEqual(shared.exception.code, "buildkit_material_mismatch")
        self.assertIn("exactly match", str(durable.exception))


if __name__ == "__main__":
    unittest.main()
