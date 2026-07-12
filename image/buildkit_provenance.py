"""Authoritative validation of retained BuildKit provenance records.

Both durable measurement reconciliation and reproducibility checks call this
module.  A BuildKit output is accepted only when its canonical reference
resolves to the retained immutable history, its invocation and materials
match exactly, and its output attachment is bound to the expected digest.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


SOURCE_DATE_EPOCH = "1700000000"
EXPECTED_PLATFORM = "linux/amd64"
EXPECTED_BUILD_NAME = "basecrawl/image"
EXPECTED_CONTEXT = "basecrawl"
EXPECTED_DOCKERFILE = "image/Dockerfile"
_REFERENCE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_-]{8,}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ALGORITHM = re.compile(r"^[A-Za-z][A-Za-z0-9+._-]*$")
_HEX = re.compile(r"^[0-9a-fA-F]{64}$")
_OUTPUT_TYPES = frozenset(
    {
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    }
)


class BuildKitProvenanceError(ValueError):
    """A BuildKit record is malformed, unresolved, or internally inconsistent."""

    def __init__(self, message: str, *, code: str = "invalid_buildkit_provenance"):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class BuildKitRecord:
    """The normalized identity returned by the authoritative validator."""

    digest: str
    canonical_ref: str
    materials: frozenset[tuple[str, str, str]]


def _fail(message: str, *, code: str = "invalid_buildkit_provenance") -> None:
    raise BuildKitProvenanceError(message, code=code)


def canonical_reference(value: Any, *, index: int) -> str:
    """Validate and return a canonical full BuildKit history reference."""

    if not isinstance(value, str) or _REFERENCE.fullmatch(value) is None:
        _fail(
            f"BuildKit metadata[{index}] has an unverifiable build reference: {value!r}",
            code="invalid_buildkit_reference",
        )
    return value


def _normalize_uri(value: Any, *, index: int, source: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or any(character.isspace() for character in value)
    ):
        _fail(
            f"BuildKit history[{index}] {source} material URI is malformed",
            code="unverifiable_buildkit_reference",
        )
    parts = value.split("&")
    retained = [part for part in parts if not part.lower().startswith("platform=")]
    normalized = "&".join(retained)
    if not normalized:
        _fail(
            f"BuildKit history[{index}] {source} material URI is empty",
            code="unverifiable_buildkit_reference",
        )
    return normalized


def _normalize_digest(
    algorithm: Any,
    value: Any,
    *,
    index: int,
    source: str,
) -> tuple[str, str]:
    if not isinstance(algorithm, str) or _ALGORITHM.fullmatch(algorithm) is None:
        _fail(
            f"BuildKit history[{index}] {source} material digest algorithm is malformed",
            code="unverifiable_buildkit_reference",
        )
    if not isinstance(value, str):
        _fail(
            f"BuildKit history[{index}] {source} material digest is malformed",
            code="unverifiable_buildkit_reference",
        )
    algorithm = algorithm.lower()
    if algorithm != "sha256":
        _fail(
            f"BuildKit history[{index}] {source} material digest algorithm is unsupported",
            code="unverifiable_buildkit_reference",
        )
    value_algorithm, separator, digest = value.partition(":")
    if separator:
        if value_algorithm.lower() != algorithm:
            _fail(
                f"BuildKit history[{index}] {source} material digest algorithm mismatch",
                code="buildkit_material_mismatch",
            )
    else:
        digest = value
    if _HEX.fullmatch(digest) is None:
        _fail(
            f"BuildKit history[{index}] {source} material digest is malformed",
            code="unverifiable_buildkit_reference",
        )
    return algorithm, digest.lower()


def _metadata_materials(
    materials: Any,
    *,
    index: int,
) -> frozenset[tuple[str, str, str]]:
    if not isinstance(materials, list) or not materials:
        _fail(
            f"BuildKit history[{index}] metadata has no verifiable materials",
            code="unverifiable_buildkit_reference",
        )
    normalized: set[tuple[str, str, str]] = set()
    for material in materials:
        if (
            not isinstance(material, Mapping)
            or "uri" not in material
            or not isinstance(material.get("digest"), Mapping)
            or not material["digest"]
        ):
            _fail(
                f"BuildKit history[{index}] metadata materials are malformed",
                code="unverifiable_buildkit_reference",
            )
        uri = _normalize_uri(material["uri"], index=index, source="metadata")
        for algorithm, digest in material["digest"].items():
            normalized.add(
                (
                    uri,
                    *_normalize_digest(
                        algorithm,
                        digest,
                        index=index,
                        source="metadata",
                    ),
                )
            )
    return frozenset(normalized)


def _history_materials(
    materials: Any,
    *,
    index: int,
) -> frozenset[tuple[str, str, str]]:
    if not isinstance(materials, list) or not materials:
        _fail(
            f"BuildKit history[{index}] has no verifiable materials",
            code="unverifiable_buildkit_reference",
        )
    normalized: set[tuple[str, str, str]] = set()
    for material in materials:
        if (
            not isinstance(material, Mapping)
            or not isinstance(material.get("URI"), str)
            or not isinstance(material.get("Digests"), list)
            or not material["Digests"]
        ):
            _fail(
                f"BuildKit history[{index}] materials are malformed",
                code="unverifiable_buildkit_reference",
            )
        uri = _normalize_uri(material["URI"], index=index, source="history")
        for digest_value in material["Digests"]:
            if not isinstance(digest_value, str):
                _fail(
                    f"BuildKit history[{index}] material digest is malformed",
                    code="unverifiable_buildkit_reference",
                )
            algorithm = digest_value.partition(":")[0]
            normalized.add(
                (
                    uri,
                    *_normalize_digest(
                        algorithm,
                        digest_value,
                        index=index,
                        source="history",
                    ),
                )
            )
    return frozenset(normalized)


def _manifest_key(path: Path) -> str:
    path_text = path.as_posix()
    marker = "/evidence/m2/"
    if marker in path_text:
        return path_text.split(marker, 1)[1]
    if path_text.startswith("evidence/m2/"):
        return path_text.removeprefix("evidence/m2/")
    return path.name


def _validate_manifest_binding(
    path: Path,
    *,
    manifest_files: Mapping[str, str],
    label: str,
    index: int,
) -> None:
    key = _manifest_key(path)
    expected = manifest_files.get(key)
    if not isinstance(expected, str):
        _fail(
            f"BuildKit {label}[{index}] is not covered by the evidence manifest: {key}",
            code="unmanifested_buildkit_reference",
        )
    try:
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as error:
        _fail(
            f"BuildKit {label}[{index}] cannot be read: {error}",
            code="unresolved_buildkit_reference",
        )
    if actual != expected:
        _fail(
            f"BuildKit {label}[{index}] does not match its evidence manifest",
            code="unmanifested_buildkit_reference",
        )


def _validate_history(
    metadata: Mapping[str, Any],
    history: Mapping[str, Any],
    *,
    digest: str,
    canonical_ref: str,
    invocation: Mapping[str, Any],
    metadata_materials: frozenset[tuple[str, str, str]],
    index: int,
) -> frozenset[tuple[str, str, str]]:
    reference_id = canonical_ref.rsplit("/", 1)[-1]
    if (
        history.get("Ref") not in {canonical_ref, reference_id}
        or history.get("Name") != EXPECTED_BUILD_NAME
        or history.get("Context") != EXPECTED_CONTEXT
        or history.get("Dockerfile") != EXPECTED_DOCKERFILE
        or history.get("Status") != "completed"
        or not isinstance(history.get("VCSRevision"), str)
        or not history["VCSRevision"].strip()
    ):
        _fail(
            f"BuildKit history[{index}] reference is not bound to metadata",
            code="buildkit_reference_mismatch",
        )
    environment = invocation["environment"]
    if history.get("Platform") != [environment["platform"]]:
        _fail(
            f"BuildKit history[{index}] invocation platform does not match metadata",
            code="buildkit_invocation_mismatch",
        )
    parameters = invocation["parameters"]
    args = parameters["args"]
    build_args = history.get("BuildArgs")
    build_arg_values = (
        {
            item.get("Name"): item.get("Value")
            for item in build_args
            if isinstance(item, Mapping)
        }
        if isinstance(build_args, list)
        else {}
    )
    config = history.get("Config")
    if (
        build_arg_values.get("SOURCE_DATE_EPOCH") != SOURCE_DATE_EPOCH
        or not isinstance(config, Mapping)
        or config.get("NoCache") is not True
        or config.get("SourceDateEpoch") != SOURCE_DATE_EPOCH
        or args.get("build-arg:SOURCE_DATE_EPOCH") != SOURCE_DATE_EPOCH
    ):
        _fail(
            f"BuildKit history[{index}] invocation configuration does not match metadata",
            code="buildkit_invocation_mismatch",
        )
    history_materials = _history_materials(
        history.get("Materials"),
        index=index,
    )
    if metadata_materials != history_materials:
        _fail(
            f"BuildKit history[{index}] materials do not exactly match metadata",
            code="buildkit_material_mismatch",
        )
    attachments = history.get("Attachments")
    if not isinstance(attachments, list) or not any(
        isinstance(attachment, Mapping)
        and attachment.get("Digest") == digest
        and attachment.get("Type") in _OUTPUT_TYPES
        for attachment in attachments
    ):
        _fail(
            f"BuildKit history[{index}] output identity does not match metadata",
            code="buildkit_output_mismatch",
        )
    return history_materials


def validate_buildkit_record(
    metadata: Mapping[str, Any],
    history: Mapping[str, Any],
    *,
    expected_digest: str,
    index: int,
    metadata_path: Path | None = None,
    history_path: Path | None = None,
    manifest_files: Mapping[str, str] | None = None,
) -> BuildKitRecord:
    """Validate one metadata/history pair and return normalized immutable identity."""

    if not isinstance(metadata, Mapping) or not isinstance(history, Mapping):
        _fail(f"BuildKit record[{index}] must contain metadata and history objects")
    if (
        not isinstance(expected_digest, str)
        or _DIGEST.fullmatch(expected_digest) is None
    ):
        _fail(f"BuildKit expected digest[{index}] is malformed")
    if (metadata_path is None) != (history_path is None) or (
        metadata_path is not None and manifest_files is None
    ):
        _fail(
            f"BuildKit record[{index}] manifest coverage is incomplete",
            code="unmanifested_buildkit_reference",
        )
    if metadata_path is not None and history_path is not None:
        _validate_manifest_binding(
            metadata_path,
            manifest_files=manifest_files or {},
            label="metadata",
            index=index,
        )
        _validate_manifest_binding(
            history_path,
            manifest_files=manifest_files or {},
            label="history",
            index=index,
        )

    digest = metadata.get("containerimage.digest")
    if (
        not isinstance(digest, str)
        or _DIGEST.fullmatch(digest) is None
        or digest != expected_digest
    ):
        _fail(
            f"BuildKit metadata[{index}] has an invalid or unexpected output digest: {digest!r}"
        )
    canonical_ref = canonical_reference(
        metadata.get("buildx.build.ref"),
        index=index,
    )
    provenance = metadata.get("buildx.build.provenance")
    if not isinstance(provenance, Mapping):
        _fail(f"BuildKit metadata[{index}] has no provenance invocation")
    invocation = provenance.get("invocation")
    if not isinstance(invocation, Mapping):
        _fail(f"BuildKit metadata[{index}] has no provenance invocation")
    parameters = invocation.get("parameters")
    environment = invocation.get("environment")
    if not isinstance(parameters, Mapping) or not isinstance(environment, Mapping):
        _fail(f"BuildKit metadata[{index}] has no verifiable invocation identity")
    args = parameters.get("args")
    locals_ = parameters.get("locals")
    if (
        not isinstance(args, Mapping)
        or not args.get("cmdline")
        or not args.get("source")
        or not isinstance(locals_, list)
        or {item.get("name") for item in locals_ if isinstance(item, Mapping)}
        != {"context", "dockerfile"}
    ):
        _fail(f"BuildKit metadata[{index}] invocation is missing source identity")
    if environment.get("platform") != EXPECTED_PLATFORM:
        _fail(
            f"BuildKit metadata[{index}] invocation platform is not {EXPECTED_PLATFORM}"
        )
    descriptor = metadata.get("containerimage.descriptor")
    if (
        not isinstance(descriptor, Mapping)
        or descriptor.get("digest") != digest
        or descriptor.get("mediaType") not in _OUTPUT_TYPES
        or not isinstance(descriptor.get("size"), int)
        or descriptor["size"] <= 0
    ):
        _fail(
            f"BuildKit metadata[{index}] output descriptor is not bound to the digest",
            code="buildkit_output_mismatch",
        )
    materials = _metadata_materials(provenance.get("materials"), index=index)
    _validate_history(
        metadata,
        history,
        digest=digest,
        canonical_ref=canonical_ref,
        invocation=invocation,
        metadata_materials=materials,
        index=index,
    )
    return BuildKitRecord(
        digest=digest,
        canonical_ref=canonical_ref,
        materials=materials,
    )


def validate_independent_records(
    records: Sequence[BuildKitRecord],
    *,
    expected_count: int = 2,
) -> None:
    """Require independent canonical BuildKit references, regardless of digest."""

    if len(records) < expected_count:
        _fail(
            f"at least {expected_count} independent BuildKit records are required",
            code="insufficient_buildkit_records",
        )
    references = [record.canonical_ref for record in records]
    if len(set(references)) != len(references):
        _fail(
            f"BuildKit build references are not distinct: {references!r}",
            code="reused_buildkit_reference",
        )
