"""Fail-closed canonical Phala measurement allowlist.

The allowlist is deliberately small and validator-owned.  It contains the six
static values needed to identify the deployed basecrawl image and its fixed VM
shape.  RTMR3 is runtime state, so it is validated by replaying the signed
event log rather than by adding it to the static tuple.

The Phala ``app-compose.json`` hash is calculated with the dstack rules:
recursively remove JSON ``null`` fields, sort object keys, serialize compactly
as UTF-8, and hash those exact bytes with SHA-256.  This is not the hash of
the source YAML alone or of the provider's ``/Info`` response envelope.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import buildkit_provenance

CANONICAL_FIELDS = (
    "mrtd",
    "rtmr0",
    "rtmr1",
    "rtmr2",
    "compose_hash",
    "os_image_hash",
)
REGISTER_FIELDS = frozenset({"mrtd", "rtmr0", "rtmr1", "rtmr2"})
HEX96 = re.compile(r"^[0-9a-f]{96}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

DSTACK_COMMIT = "282eeb27d22d8f091ad0fa5a90e638f85cf68751"
META_DSTACK_COMMIT = "e3655d1390feee3736476f4bda35c4354b4a12fc"
CATALOG_VERSION = "0.5.9"
CATALOG_RELEASE_NAME = "dstack-0.5.9"
CATALOG_SLUG = "dstack-0.5.9-bd369a8c"
CATALOG_OS_IMAGE_HASH = (
    "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033"
)
APPLICATION_IMAGE_REF = (
    "docker.io/mathiiss/basecrawl-cvm@sha256:"
    "57a2ecdc9257846ca69dce38c53a464b68e9a08575fb45d8d18aed5b6b28f366"
)
MEASUREMENT_QEMU_VERSION = "8.0.0"
BUILD_SOURCE_DATE_EPOCH = "1700000000"
PROTECTED_CVM_ID = "cvm_MeD2Y9wQ"
PROTECTED_CVM_NAME = "dstack-app-nlv7j"

DSTACK_RUNTIME_EVENT_TYPE = 0x08000001
RTMR3_INDEX = 3
REGISTER_BYTES = 48
QUOTE_HEADER_BYTES = 48
TD_REPORT_BYTES = 584
QUOTE_VERSION = 4
TDX_TEE_TYPE = 0x81
INTEL_QE_VENDOR_ID = bytes.fromhex("939a7233f79c4ca9940a0db3957f0607")
EXPECTED_RUNTIME_EVENTS = (
    "system-preparing",
    "app-id",
    "compose-hash",
    "instance-id",
    "boot-mr-done",
    "mr-kms",
    "os-image-hash",
    "key-provider",
    "storage-fs",
    "system-ready",
)
EVIDENCE_MANIFEST_VERSION = 1
EXECUTION_RECORD_VERSION = 2
EXECUTION_RECORD_ID = "m2-tee-integration/production-reconciliation"
EXECUTION_ARTIFACT_PREFIX = "evidence/m2/"
EXECUTION_EVENT_PREFIX = "m2-tee-audit-"
EXECUTION_OPERATION_PREFIX = "m2-tee-integration/"
EXECUTION_VALIDATION_KINDS = (
    "dcap-qvl verify",
    "dcap-qvl decode",
    "direct RTMR3 replay",
    "reproducibility validation",
)
DEPLOYMENT_FIELDS = frozenset(
    {
        "app_id",
        "automatic_placement",
        "compose_hash",
        "cvm_id",
        "cvm_name",
        "image_ref",
        "instance_type",
        "os_image",
        "requested_node_id",
        "requested_region",
        "vm_uuid",
        "created",
        "deleted",
    }
)
DEPLOYMENT_SUMMARY_FIELDS = frozenset(
    {
        "app_id",
        "automatic_placement",
        "compose_hash",
        "cvm_id",
        "cvm_name",
        "image",
        "image_ref",
        "instance_type",
        "requested_node_id",
        "requested_region",
        "vm_uuid",
    }
)


class MeasurementAllowlistError(ValueError):
    """The validator measurement configuration is malformed or inconsistent."""


def _validate_identity_value(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MeasurementAllowlistError(f"{label} must be a non-empty string")
    return value


def _reject_protected_identity(value: str, *, label: str) -> None:
    if value in {PROTECTED_CVM_ID, PROTECTED_CVM_NAME}:
        raise MeasurementAllowlistError(
            f"{label} contains protected CVM identity {value}"
        )


def _validate_deployment_identity(
    value: Mapping[str, Any],
    *,
    label: str,
    fields: tuple[str, ...] = ("app_id", "cvm_id", "cvm_name"),
) -> dict[str, str]:
    identity: dict[str, str] = {}
    for field in fields:
        item = _validate_identity_value(value.get(field), label=f"{label}.{field}")
        _reject_protected_identity(item, label=f"{label}.{field}")
        identity[field] = item
    return identity


def _validate_mission_protected_disjoint(
    deployments: Iterable[Mapping[str, Any]],
) -> None:
    mission_ids: set[str] = set()
    mission_names: set[str] = set()
    for index, deployment in enumerate(deployments):
        mission_ids.add(
            _validate_identity_value(
                deployment.get("cvm_id"),
                label=f"mission_owned_cvms[{index}].cvm_id",
            )
        )
        mission_names.add(
            _validate_identity_value(
                deployment.get("cvm_name"),
                label=f"mission_owned_cvms[{index}].cvm_name",
            )
        )
    if PROTECTED_CVM_ID in mission_ids or PROTECTED_CVM_NAME in mission_names:
        raise MeasurementAllowlistError(
            "mission-owned and protected CVM inventories overlap"
        )


def _canonical_json_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _canonical_json_value(item)
            for key, item in sorted(value.items())
            if item is not None
        }
    if isinstance(value, list):
        return [_canonical_json_value(item) for item in value]
    return value


def normalize_app_compose(compose: Mapping[str, Any] | str) -> str:
    """Return the exact dstack-normalized JSON representation."""

    if isinstance(compose, str):
        try:
            value = json.loads(compose)
        except json.JSONDecodeError as exc:
            raise MeasurementAllowlistError(f"app-compose is not JSON: {exc}") from exc
    elif isinstance(compose, Mapping):
        value = compose
    else:
        raise MeasurementAllowlistError("app-compose must be a mapping or JSON string")
    return json.dumps(
        _canonical_json_value(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def phala_app_compose_hash(compose: Mapping[str, Any] | str | Path) -> str:
    """Hash a normalized app-compose mapping, JSON string, or JSON file."""

    if isinstance(compose, Path):
        try:
            compose = compose.read_text(encoding="utf-8")
        except OSError as exc:
            raise MeasurementAllowlistError(f"cannot read app-compose: {exc}") from exc
    return hashlib.sha256(normalize_app_compose(compose).encode("utf-8")).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MeasurementAllowlistError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, json.JSONDecodeError, MeasurementAllowlistError) as exc:
        raise MeasurementAllowlistError(f"cannot load {label} {path}: {exc}") from exc


def _repository_relative_path(root: Path, value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise MeasurementAllowlistError(f"{label} must be a repository-relative path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise MeasurementAllowlistError(f"{label} must be a repository-relative path")
    resolved_root = root.resolve()
    path = root / relative
    if not path.is_file():
        raise MeasurementAllowlistError(f"{label} does not exist: {value}")
    try:
        path.resolve().relative_to(resolved_root)
    except ValueError as exc:
        raise MeasurementAllowlistError(
            f"{label} must remain inside the repository evidence root"
        ) from exc
    return path


def write_evidence_manifest(path: Path | str) -> dict[str, Any]:
    """Write deterministic hashes for every file below the manifest directory."""

    target = Path(path)
    root = target.parent
    files = {
        item.relative_to(root).as_posix(): hashlib.sha256(item.read_bytes()).hexdigest()
        for item in sorted(root.rglob("*"))
        if item.is_file() and item != target
    }
    manifest = {"version": EVIDENCE_MANIFEST_VERSION, "files": files}
    target.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def verify_evidence_manifest(path: Path | str) -> dict[str, str]:
    """Fail closed unless the manifest exactly covers all repository-local files."""

    target = Path(path)
    manifest = _load_json(target, "evidence manifest")
    files = manifest.get("files") if isinstance(manifest, Mapping) else None
    if manifest.get("version") != EVIDENCE_MANIFEST_VERSION or not isinstance(
        files, Mapping
    ):
        raise MeasurementAllowlistError("evidence manifest is malformed")
    expected: dict[str, str] = {}
    for name, digest in files.items():
        if (
            not isinstance(name, str)
            or not isinstance(digest, str)
            or HEX64.fullmatch(digest) is None
        ):
            raise MeasurementAllowlistError("evidence manifest entry is malformed")
        artifact = _repository_relative_path(target.parent, name, "manifest path")
        actual = hashlib.sha256(artifact.read_bytes()).hexdigest()
        if actual != digest:
            raise MeasurementAllowlistError(
                f"evidence manifest digest mismatch: {name}"
            )
        expected[name] = digest
    actual_files = {
        item.relative_to(target.parent).as_posix()
        for item in target.parent.rglob("*")
        if item.is_file() and item != target
    }
    if set(expected) != actual_files:
        raise MeasurementAllowlistError("evidence manifest coverage mismatch")
    return expected


def _validate_entry(value: Mapping[str, Any], *, label: str) -> dict[str, str]:
    if set(value) != set(CANONICAL_FIELDS):
        raise MeasurementAllowlistError(
            f"{label} must contain exactly {', '.join(CANONICAL_FIELDS)}"
        )
    result: dict[str, str] = {}
    for field in CANONICAL_FIELDS:
        item = value.get(field)
        if not isinstance(item, str):
            raise MeasurementAllowlistError(f"{label}.{field} must be a string")
        item = item.strip().lower()
        pattern = HEX96 if field in REGISTER_FIELDS else HEX64
        if pattern.fullmatch(item) is None:
            raise MeasurementAllowlistError(
                f"{label}.{field} has the wrong digest width"
            )
        result[field] = item
    return result


def load_allowlist(path: Path | str) -> list[dict[str, str]]:
    """Load one or more exact six-field entries, rejecting malformed input."""

    source = Path(path)
    data = _load_json(source, "measurement allowlist")
    if isinstance(data, Mapping):
        data = data.get("entries")
    if not isinstance(data, list):
        raise MeasurementAllowlistError("measurement allowlist must be a JSON list")
    return (
        [
            _validate_entry(entry, label=f"allowlist[{index}]")
            for index, entry in enumerate(data)
            if isinstance(entry, Mapping)
        ]
        if all(isinstance(entry, Mapping) for entry in data)
        else _raise_entries()
    )


def _raise_entries() -> list[dict[str, str]]:
    raise MeasurementAllowlistError("every allowlist entry must be an object")


def _validate_buildkit_history(
    metadata: Mapping[str, Any],
    history: Mapping[str, Any],
    *,
    build_digest: Any,
    index: int,
    metadata_path: Path | None = None,
    history_path: Path | None = None,
    manifest_files: Mapping[str, str] | None = None,
) -> str:
    """Compatibility adapter for the authoritative BuildKit validator."""

    try:
        record = buildkit_provenance.validate_buildkit_record(
            metadata,
            history,
            expected_digest=build_digest,
            index=index,
            metadata_path=metadata_path,
            history_path=history_path,
            manifest_files=manifest_files,
        )
    except buildkit_provenance.BuildKitProvenanceError as error:
        raise MeasurementAllowlistError(str(error)) from error
    return record.canonical_ref


def allowlist_contains(
    candidate: Mapping[str, Any], entries: Iterable[Mapping[str, Any]]
) -> bool:
    """Return true only for an exact match across all six canonical fields."""

    try:
        normalized = _validate_entry(candidate, label="candidate")
    except MeasurementAllowlistError:
        return False
    return any(
        normalized == _validate_entry(entry, label="allowlist entry")
        for entry in entries
    )


def _runtime_event_digest(name: str, payload: bytes) -> bytes:
    return hashlib.sha384(
        DSTACK_RUNTIME_EVENT_TYPE.to_bytes(4, "little")
        + b":"
        + name.encode("utf-8")
        + b":"
        + payload
    ).digest()


def _key_provider_payload_is_valid(payload_hex: str) -> bool:
    try:
        payload = bytes.fromhex(payload_hex)
        value = json.loads(payload)
    except (ValueError, json.JSONDecodeError):
        return False
    return (
        isinstance(value, Mapping)
        and value.get("name") == "kms"
        and isinstance(value.get("id"), str)
        and bool(value["id"])
    )


def replay_rtmr3(event_log: Iterable[Mapping[str, Any]]) -> dict[str, str | None]:
    """Replay IMR3 and verify every runtime-event digest before folding it."""

    register = bytes(REGISTER_BYTES)
    compose_hash: str | None = None
    key_provider: str | None = None
    runtime_events: list[str] = []
    for index, event in enumerate(event_log):
        if not isinstance(event, Mapping) or event.get("imr") != RTMR3_INDEX:
            continue
        name = event.get("event", "")
        payload_hex = event.get("event_payload", "")
        logged_hex = event.get("digest")
        if (
            not isinstance(name, str)
            or not isinstance(payload_hex, str)
            or not isinstance(logged_hex, str)
        ):
            raise MeasurementAllowlistError(f"RTMR3 event {index} is malformed")
        try:
            payload = bytes.fromhex(payload_hex)
            logged = bytes.fromhex(logged_hex)
        except ValueError as exc:
            raise MeasurementAllowlistError(f"RTMR3 event {index} is not hex") from exc
        if len(logged) != REGISTER_BYTES:
            raise MeasurementAllowlistError(
                f"RTMR3 event {index} digest is not SHA-384"
            )
        event_type = event.get("event_type")
        if event_type != DSTACK_RUNTIME_EVENT_TYPE:
            raise MeasurementAllowlistError(
                f"RTMR3 event {index} has an unsupported event type"
            )
        digest = (
            _runtime_event_digest(name, payload)
            if event_type == DSTACK_RUNTIME_EVENT_TYPE
            else logged
        )
        if event_type == DSTACK_RUNTIME_EVENT_TYPE and digest != logged:
            raise MeasurementAllowlistError(f"RTMR3 event {index} digest mismatch")
        register = hashlib.sha384(register + digest).digest()
        runtime_events.append(name)
        if name == "compose-hash":
            compose_hash = payload.hex()
        elif name == "key-provider":
            key_provider = payload.hex()
    if runtime_events and runtime_events != list(EXPECTED_RUNTIME_EVENTS):
        raise MeasurementAllowlistError(
            "RTMR3 event sequence is not the expected boot sequence"
        )
    if compose_hash is not None and not HEX64.fullmatch(compose_hash):
        raise MeasurementAllowlistError("compose-hash event is not a SHA-256 digest")
    if key_provider is None or not _key_provider_payload_is_valid(key_provider):
        raise MeasurementAllowlistError("key-provider event is missing")
    return {
        "rtmr3": register.hex(),
        "compose_hash": compose_hash,
        "key_provider": key_provider,
    }


def validate_reconciliation(
    path: Path | str,
    *,
    allowlist_path: Path | str,
    app_compose_path: Path | str,
) -> dict[str, Any]:
    """Validate the durable evidence record before a caller trusts the tuple."""

    record = _load_json(Path(path), "measurement reconciliation")
    if not isinstance(record, Mapping) or record.get("status") != "reconciled":
        raise MeasurementAllowlistError("measurement reconciliation is not reconciled")
    record_root = Path(path).resolve().parent
    bundle = record.get("evidence_bundle")
    if not isinstance(bundle, Mapping):
        raise MeasurementAllowlistError("repository-local evidence bundle is missing")
    manifest_path = _repository_relative_path(
        record_root,
        bundle.get("manifest_path"),
        "evidence_bundle.manifest_path",
    )
    manifest_files = verify_evidence_manifest(manifest_path)
    execution_path = _repository_relative_path(
        record_root,
        bundle.get("execution_record_path"),
        "evidence_bundle.execution_record_path",
    )
    execution_record = _load_json(execution_path, "execution record")
    canonical = _validate_entry(
        record.get("canonical_measurement", {}),
        label="canonical_measurement",
    )
    allowlist = load_allowlist(allowlist_path)
    if len(allowlist) != 1 or allowlist[0] != canonical:
        raise MeasurementAllowlistError("allowlist does not pin the reconciled tuple")
    app_compose = Path(app_compose_path)
    if phala_app_compose_hash(app_compose) != canonical["compose_hash"]:
        raise MeasurementAllowlistError(
            "normalized app-compose hash does not match tuple"
        )
    image = record.get("image")
    if (
        not isinstance(image, Mapping)
        or image.get("image_ref") != APPLICATION_IMAGE_REF
        or image.get("build_digest")
        != "sha256:57a2ecdc9257846ca69dce38c53a464b68e9a08575fb45d8d18aed5b6b28f366"
        or image.get("all_service_images_digest_pinned") is not True
    ):
        raise MeasurementAllowlistError("application image identity is not pinned")
    retained_compose = _repository_relative_path(
        record_root,
        image.get("compose_file"),
        "image.compose_file",
    )
    retained_app_compose = _repository_relative_path(
        record_root,
        image.get("phala_app_compose"),
        "image.phala_app_compose",
    )
    current_compose = Path(__file__).resolve().with_name("docker-compose.yml")
    if (
        not current_compose.is_file()
        or retained_compose.read_bytes() != current_compose.read_bytes()
        or retained_app_compose.read_bytes() != app_compose.read_bytes()
    ):
        raise MeasurementAllowlistError(
            "retained Compose artifacts do not match current source"
        )

    catalog = record.get("catalog")
    if (
        not isinstance(catalog, Mapping)
        or catalog.get("version") != CATALOG_VERSION
        or catalog.get("name") != CATALOG_RELEASE_NAME
        or catalog.get("slug") != CATALOG_SLUG
        or catalog.get("os_image_hash") != CATALOG_OS_IMAGE_HASH
        or catalog.get("is_dev") is not False
        or not _catalog_artifacts_match(catalog, root=record_root)
    ):
        raise MeasurementAllowlistError(
            "catalog identity is not the pinned Phala image"
        )
    if record.get("source_pins") != {
        "dstack": DSTACK_COMMIT,
        "meta_dstack": META_DSTACK_COMMIT,
    }:
        raise MeasurementAllowlistError(
            "source pins do not match the required v0.5.9 pins"
        )
    measurement = record.get("dstack_mr")
    if (
        not isinstance(measurement, Mapping)
        or measurement.get("qemu_version") != MEASUREMENT_QEMU_VERSION
        or measurement.get("cpu") != 1
        or measurement.get("memory") != "2G"
        or measurement.get("registers")
        != {field: canonical[field] for field in ("mrtd", "rtmr0", "rtmr1", "rtmr2")}
    ):
        raise MeasurementAllowlistError(
            "dstack-mr output is not the reconciled live tuple"
        )
    invocation = _load_json(
        _repository_relative_path(
            record_root,
            measurement.get("invocation_path"),
            "dstack_mr.invocation_path",
        ),
        "dstack-mr invocation",
    )
    measured_output = _load_json(
        _repository_relative_path(
            record_root,
            measurement.get("output_path"),
            "dstack_mr.output_path",
        ),
        "dstack-mr output",
    )
    if (
        invocation.get("source_revision") != DSTACK_COMMIT
        or invocation.get("cpu") != measurement.get("cpu")
        or invocation.get("memory") != measurement.get("memory")
        or invocation.get("qemu_version") != measurement.get("qemu_version")
        or invocation.get("metadata_sha256") != measurement.get("metadata_sha256")
        or invocation.get("metadata_sha256")
        != hashlib.sha256(
            _repository_relative_path(
                record_root,
                measurement.get("metadata_path"),
                "dstack_mr.metadata_path",
            ).read_bytes()
        ).hexdigest()
        or measured_output != measurement.get("registers")
    ):
        raise MeasurementAllowlistError("dstack-mr retained input/output drift")

    build_paths = image.get("build_metadata_paths")
    history_paths = image.get("build_history_paths")
    if (
        not isinstance(build_paths, list)
        or len(build_paths) != 2
        or not isinstance(history_paths, list)
        or len(history_paths) != len(build_paths)
    ):
        raise MeasurementAllowlistError(
            "two BuildKit metadata and history records are required"
        )
    build_records: list[buildkit_provenance.BuildKitRecord] = []
    for index, metadata_value in enumerate(build_paths):
        metadata = _load_json(
            _repository_relative_path(
                record_root,
                metadata_value,
                f"image.build_metadata_paths[{index}]",
            ),
            "BuildKit metadata",
        )
        history = _load_json(
            _repository_relative_path(
                record_root,
                history_paths[index],
                f"image.build_history_paths[{index}]",
            ),
            "BuildKit history",
        )
        if metadata.get("containerimage.digest") != image.get("build_digest"):
            raise MeasurementAllowlistError("BuildKit metadata identity drift")
        try:
            build_records.append(
                buildkit_provenance.validate_buildkit_record(
                    metadata,
                    history,
                    expected_digest=image.get("build_digest"),
                    index=index,
                    metadata_path=record_root / metadata_value,
                    history_path=record_root / history_paths[index],
                    manifest_files=manifest_files,
                )
            )
        except buildkit_provenance.BuildKitProvenanceError as error:
            raise MeasurementAllowlistError(str(error)) from error
    try:
        buildkit_provenance.validate_independent_records(build_records)
    except buildkit_provenance.BuildKitProvenanceError as error:
        raise MeasurementAllowlistError(str(error)) from error
    publish_metadata = _load_json(
        _repository_relative_path(
            record_root,
            image.get("publish_metadata_path"),
            "image.publish_metadata_path",
        ),
        "publish metadata",
    )
    registry_manifest_path = _repository_relative_path(
        record_root,
        image.get("registry_manifest_path"),
        "image.registry_manifest_path",
    )
    if publish_metadata.get("containerimage.digest") != image.get(
        "build_digest"
    ) or "sha256:" + hashlib.sha256(
        registry_manifest_path.read_bytes()
    ).hexdigest() != image.get("build_digest"):
        raise MeasurementAllowlistError("published image identity drift")

    live_evidence = record.get("live_evidence")
    if not isinstance(live_evidence, list) or len(live_evidence) != 2:
        raise MeasurementAllowlistError(
            "exactly two live evidence records are required"
        )
    live_identities: list[dict[str, str]] = []
    for index, evidence in enumerate(live_evidence):
        if not isinstance(evidence, Mapping):
            raise MeasurementAllowlistError(f"live_evidence[{index}] must be an object")
        live_identities.append(
            _validate_deployment_identity(
                evidence,
                label=f"live_evidence[{index}]",
                fields=("app_id", "cvm_name"),
            )
        )
    app_ids = [identity["app_id"] for identity in live_identities]
    cvm_names = [identity["cvm_name"] for identity in live_identities]
    if len(set(app_ids)) != 2 or len(set(cvm_names)) != 2:
        raise MeasurementAllowlistError("live evidence deployments are not independent")
    deployment_summaries = _validate_deployment_summaries(
        record.get("reconciliation_deployments"),
        live_evidence=live_evidence,
        canonical=canonical,
    )
    deployment_records: list[dict[str, Any]] = []
    for index, evidence in enumerate(live_evidence):
        deployment_records.append(
            _validate_live_evidence(
                evidence,
                index=index,
                canonical=canonical,
                allowlisted_compose_hash=canonical["compose_hash"],
                root=record_root,
                deployment_summary=deployment_summaries[index],
            )
        )
    for field in ("app_id", "cvm_name", "cvm_id", "vm_uuid"):
        if len({deployment[field] for deployment in deployment_records}) != 2:
            raise MeasurementAllowlistError(
                f"deployment {field} values are not independent"
            )
    _validate_mission_protected_disjoint(deployment_records)
    replay_record = record.get("live_event_replay")
    if not isinstance(replay_record, Mapping) or not isinstance(
        replay_record.get("evidence"), list
    ):
        raise MeasurementAllowlistError("per-CVM RTMR3 replay evidence is missing")
    replay_by_name: dict[str, Mapping[str, Any]] = {}
    for index, item in enumerate(replay_record["evidence"]):
        if not isinstance(item, Mapping):
            raise MeasurementAllowlistError(
                f"RTMR3 replay record {index} must be an object"
            )
        cvm_name = _validate_deployment_identity(
            item,
            label=f"live_event_replay.evidence[{index}]",
            fields=("cvm_name",),
        )["cvm_name"]
        if cvm_name in replay_by_name:
            raise MeasurementAllowlistError("RTMR3 replay records are not independent")
        replay_by_name[cvm_name] = item
    if len(replay_by_name) != 2:
        raise MeasurementAllowlistError("RTMR3 replay records are not independent")
    for evidence in live_evidence:
        replay = replay_by_name.get(evidence.get("cvm_name"))
        if (
            not isinstance(replay, Mapping)
            or replay.get("rtmr3") != evidence.get("rtmr3")
            or replay.get("replayed_rtmr3") != evidence.get("rtmr3")
            or replay.get("event_names") != list(EXPECTED_RUNTIME_EVENTS)
        ):
            raise MeasurementAllowlistError(
                "recorded RTMR3 replay evidence does not match"
            )
    live_info = record.get("live_info")
    if (
        not isinstance(live_info, Mapping)
        or live_info.get("catalog_identity_confirmed") is not True
        or live_info.get("os_image_hash") != canonical["os_image_hash"]
        or live_info.get("compose_hash") != canonical["compose_hash"]
        or live_info.get("app_compose_sha256") != canonical["compose_hash"]
    ):
        raise MeasurementAllowlistError("live /Info identity does not match the tuple")
    cleanup = record.get("cleanup")
    cleanup_inventory = _load_json(
        _repository_relative_path(
            record_root,
            cleanup.get("inventory_path") if isinstance(cleanup, Mapping) else None,
            "cleanup.inventory_path",
        ),
        "cleanup inventory",
    )
    if not isinstance(cleanup, Mapping):
        raise MeasurementAllowlistError(
            "cleanup inventory does not prove ownership cleanup"
        )
    expected_deleted = {deployment["cvm_name"] for deployment in deployment_records}
    protected = (
        cleanup_inventory.get("protected_user_cvm")
        if isinstance(cleanup_inventory, Mapping)
        else None
    )
    deleted = (
        cleanup_inventory.get("deleted_mission_cvms")
        if isinstance(cleanup_inventory, Mapping)
        else None
    )
    if isinstance(deleted, list):
        for index, cvm_name in enumerate(deleted):
            name = _validate_identity_value(
                cvm_name,
                label=f"cleanup.deleted_mission_cvms[{index}]",
            )
            _reject_protected_identity(
                name,
                label=f"cleanup.deleted_mission_cvms[{index}]",
            )
    if isinstance(protected, Mapping):
        _validate_identity_value(
            protected.get("cvm_id"),
            label="cleanup.protected_user_cvm.cvm_id",
        )
        _validate_identity_value(
            protected.get("cvm_name"),
            label="cleanup.protected_user_cvm.cvm_name",
        )
    if (
        cleanup.get("mission_owned_cvm_total_after_cleanup") != 0
        or cleanup.get("account_cvm_total_after_cleanup") != 1
        or cleanup.get("protected_user_cvm_preserved") is not True
        or cleanup.get("temporary_cvms_deleted") is not True
        or cleanup_inventory.get("mission_owned_cvm_total") != 0
        or cleanup_inventory.get("account_cvm_total") != 1
        or not isinstance(deleted, list)
        or len(deleted) != 2
        or set(deleted) != expected_deleted
        or not isinstance(protected, Mapping)
        or protected.get("cvm_id") != PROTECTED_CVM_ID
        or protected.get("cvm_name") != PROTECTED_CVM_NAME
        or protected.get("status") != "running"
        or protected.get("preserved") is not True
    ):
        raise MeasurementAllowlistError(
            "cleanup inventory does not prove ownership cleanup"
        )
    _validate_execution_record(
        execution_record,
        deployment_records=deployment_records,
        root=record_root,
        manifest_files=manifest_files,
    )
    quote_verification = record.get("live_quote_verification")
    if (
        not isinstance(quote_verification, Mapping)
        or quote_verification.get("status") != "UpToDate"
        or quote_verification.get("advisory_ids") != []
        or quote_verification.get("qe_status") != "UpToDate"
        or quote_verification.get("platform_status") != "UpToDate"
    ):
        raise MeasurementAllowlistError("live quote TCB posture is not fully UpToDate")
    return dict(record)


def _validate_deployment_summaries(
    value: Any,
    *,
    live_evidence: list[Any],
    canonical: Mapping[str, str],
) -> list[Mapping[str, Any]]:
    if not isinstance(value, Mapping) or set(value) != {"first", "second"}:
        raise MeasurementAllowlistError(
            "exactly two reconciliation deployment summaries are required"
        )
    summaries: list[Mapping[str, Any]] = []
    for index, name in enumerate(("first", "second")):
        summary = value.get(name)
        evidence = live_evidence[index]
        if not isinstance(summary, Mapping):
            raise MeasurementAllowlistError(
                f"reconciliation deployment summary {name} drift"
            )
        _validate_deployment_identity(
            summary,
            label=f"reconciliation_deployments.{name}",
        )
        if (
            set(summary) != DEPLOYMENT_SUMMARY_FIELDS
            or not isinstance(evidence, Mapping)
            or summary.get("app_id") != evidence.get("app_id")
            or summary.get("cvm_name") != evidence.get("cvm_name")
            or summary.get("automatic_placement") is not True
            or summary.get("instance_type") != "tdx.small"
            or summary.get("image") != CATALOG_SLUG
            or summary.get("requested_region") is not None
            or summary.get("requested_node_id") is not None
            or summary.get("image_ref") != APPLICATION_IMAGE_REF
            or summary.get("compose_hash") != canonical["compose_hash"]
            or not isinstance(summary.get("vm_uuid"), str)
            or not summary.get("vm_uuid")
        ):
            raise MeasurementAllowlistError(
                f"reconciliation deployment summary {name} drift"
            )
        summaries.append(summary)
    for field in ("app_id", "cvm_name", "cvm_id", "vm_uuid"):
        if len({summary[field] for summary in summaries}) != 2:
            raise MeasurementAllowlistError(
                f"reconciliation deployment {field} values are not independent"
            )
    return summaries


def _validate_execution_record(
    value: Any,
    *,
    deployment_records: list[dict[str, Any]],
    root: Path,
    manifest_files: Mapping[str, str],
) -> None:
    if (
        not isinstance(value, Mapping)
        or set(value)
        != {
            "artifacts",
            "events",
            "immutable",
            "record_id",
            "redacted",
            "redaction",
            "version",
        }
        or value.get("version") != EXECUTION_RECORD_VERSION
        or value.get("record_id") != EXECUTION_RECORD_ID
        or value.get("immutable") is not True
        or value.get("redacted") is not True
        or not isinstance(value.get("redaction"), str)
        or not value["redaction"]
        or len(deployment_records) != 2
        or any(
            deployment.get("created") is not True
            or deployment.get("deleted") is not True
            for deployment in deployment_records
        )
    ):
        raise MeasurementAllowlistError(
            "immutable redacted execution record is incomplete"
        )
    record_artifacts = _validate_execution_artifacts(
        value.get("artifacts"),
        root=root,
        manifest_files=manifest_files,
    )
    expected_record_artifacts = {
        f"{EXECUTION_ARTIFACT_PREFIX}{name}": digest
        for name, digest in manifest_files.items()
        if name != "execution/reconciliation.json"
    }
    if {
        artifact["path"]: artifact["sha256"] for artifact in record_artifacts
    } != expected_record_artifacts:
        raise MeasurementAllowlistError(
            "execution record does not bind the complete evidence manifest"
        )
    _reject_sensitive_execution_values(value)
    events = value.get("events")
    if not isinstance(events, list) or len(events) != 18:
        raise MeasurementAllowlistError(
            "immutable redacted execution record has an incomplete event sequence"
        )
    deployment_by_name = {
        name: deployment
        for name, deployment in zip(("first", "second"), deployment_records)
    }
    expected_stages = (
        ("first", "deployment_request", "submitted"),
        ("first", "deployment_result", "created"),
        ("first", "evidence_capture", "complete"),
        ("first", "validation", "passed"),
        ("first", "validation", "passed"),
        ("first", "validation", "passed"),
        ("first", "validation", "passed"),
        ("first", "deletion", "deleted"),
        ("second", "deployment_request", "submitted"),
        ("second", "deployment_result", "created"),
        ("second", "evidence_capture", "complete"),
        ("second", "validation", "passed"),
        ("second", "validation", "passed"),
        ("second", "validation", "passed"),
        ("second", "validation", "passed"),
        ("second", "deletion", "deleted"),
        (None, "final_inventory", "ownership_clean"),
        (None, "reconciliation", "passed"),
    )
    deployment_validation_index = {"first": 0, "second": 0}
    for index, (event, expected) in enumerate(zip(events, expected_stages)):
        if not isinstance(event, Mapping):
            raise MeasurementAllowlistError(
                f"execution record event {index} is malformed"
            )
        deployment_name, stage, status = expected
        required_event_fields = {
            "artifacts",
            "deployment",
            "event_id",
            "identities",
            "immutable",
            "operation_id",
            "sequence",
            "stage",
            "status",
        }
        if stage in {"deployment_request", "deletion"}:
            required_event_fields.add("request")
        if stage in {
            "deployment_result",
            "deletion",
            "evidence_capture",
            "final_inventory",
        }:
            required_event_fields.add("response")
        if stage in {"validation", "reconciliation"}:
            required_event_fields.add("validation")
        if set(event) != required_event_fields:
            raise MeasurementAllowlistError(
                f"execution record event {index} fields are incomplete"
            )
        operation_scope = deployment_name or "mission"
        sequence = index + 1
        expected_operation_id = (
            f"{EXECUTION_OPERATION_PREFIX}{operation_scope}/{stage}/{sequence:04d}"
        )
        if (
            event.get("event_id") != f"{EXECUTION_EVENT_PREFIX}{sequence:04d}"
            or type(event.get("sequence")) is not int
            or event.get("sequence") != sequence
            or event.get("deployment") != deployment_name
            or event.get("stage") != stage
            or event.get("status") != status
            or event.get("immutable") is not True
            or not isinstance(event.get("identities"), Mapping)
        ):
            raise MeasurementAllowlistError(
                "immutable redacted execution record event order or identity drift"
            )
        if event.get("operation_id") != expected_operation_id:
            raise MeasurementAllowlistError(
                "immutable redacted execution record operation ID drift"
            )
        _validate_execution_artifacts(
            event.get("artifacts"),
            root=root,
            manifest_files=manifest_files,
        )
        identities = event["identities"]
        if deployment_name is not None:
            deployment = deployment_by_name[deployment_name]
            _validate_deployment_identity(
                identities,
                label=f"execution.events[{index}].identities",
            )
            for field in ("app_id", "cvm_id", "cvm_name", "vm_uuid"):
                if identities.get(field) != deployment[field]:
                    raise MeasurementAllowlistError(
                        f"execution record {stage} identity drift for {deployment_name}"
                    )
        if stage == "deployment_request":
            _validate_deployment_request(
                event, deployment=deployment_by_name[deployment_name]
            )
        elif stage == "deployment_result":
            _validate_deployment_result(
                event, deployment=deployment_by_name[deployment_name]
            )
        elif stage == "evidence_capture":
            _validate_capture_event(
                event,
                deployment_name=deployment_name,
                deployment=deployment_by_name[deployment_name],
                manifest_files=manifest_files,
            )
        elif stage == "validation":
            validation_index = deployment_validation_index[deployment_name]
            _validate_validation_event(
                event,
                deployment_name=deployment_name,
                expected_kind=EXECUTION_VALIDATION_KINDS[validation_index],
            )
            deployment_validation_index[deployment_name] = validation_index + 1
        elif stage == "deletion":
            _validate_deletion_event(
                event,
                deployment=deployment_by_name[deployment_name],
            )
        elif stage == "final_inventory":
            _validate_final_inventory_event(event)
        elif stage == "reconciliation":
            _validate_reconciliation_event(event)
        _reject_sensitive_execution_values(event)


def _validate_execution_artifacts(
    value: Any,
    *,
    root: Path,
    manifest_files: Mapping[str, str],
) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise MeasurementAllowlistError(
            "execution record artifact references are incomplete"
        )
    normalized: list[dict[str, str]] = []
    for index, artifact in enumerate(value):
        if (
            not isinstance(artifact, Mapping)
            or set(artifact) != {"path", "sha256"}
            or not isinstance(artifact.get("path"), str)
            or not isinstance(artifact.get("sha256"), str)
            or HEX64.fullmatch(artifact["sha256"]) is None
        ):
            raise MeasurementAllowlistError(
                f"execution record artifact {index} is malformed"
            )
        path = artifact["path"]
        if not path.startswith(EXECUTION_ARTIFACT_PREFIX):
            raise MeasurementAllowlistError(
                f"execution record artifact path escapes evidence bundle: {path}"
            )
        relative = path[len(EXECUTION_ARTIFACT_PREFIX) :]
        if not relative or relative not in manifest_files:
            raise MeasurementAllowlistError(
                f"execution record artifact is not manifest-covered: {path}"
            )
        artifact_path = _repository_relative_path(
            root, path, f"execution artifact[{index}].path"
        )
        digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
        if digest != artifact["sha256"] or digest != manifest_files[relative]:
            raise MeasurementAllowlistError(
                f"execution record artifact digest mismatch: {path}"
            )
        normalized.append({"path": path, "sha256": digest})
    if len({item["path"] for item in normalized}) != len(normalized):
        raise MeasurementAllowlistError(
            "execution record contains duplicate artifact references"
        )
    return normalized


def _validate_deployment_request(
    event: Mapping[str, Any],
    *,
    deployment: Mapping[str, Any],
) -> None:
    request = event.get("request")
    if (
        not isinstance(request, Mapping)
        or set(request)
        != {
            "automatic_placement",
            "compose_path",
            "compose_sha256",
            "image_ref",
            "instance_type",
            "name",
            "node_id",
            "os_image",
            "region",
        }
        or request.get("automatic_placement") is not True
        or request.get("compose_path") != "evidence/m2/compose/docker-compose.yml"
        or request.get("compose_sha256")
        != "4778611a0654dab542e1a2149d3b16275e81c0293dba652ad1424a54b0338740"
        or request.get("image_ref") != APPLICATION_IMAGE_REF
        or request.get("instance_type") != "tdx.small"
        or request.get("name") != deployment["cvm_name"]
        or request.get("node_id") is not None
        or request.get("os_image") != CATALOG_SLUG
        or request.get("region") is not None
    ):
        raise MeasurementAllowlistError("execution record deployment request drift")


def _validate_deployment_result(
    event: Mapping[str, Any],
    *,
    deployment: Mapping[str, Any],
) -> None:
    response = event.get("response")
    if isinstance(response, Mapping):
        _validate_deployment_identity(
            response,
            label="execution.deployment_result.response",
        )
    if (
        not isinstance(response, Mapping)
        or set(response) != {"app_id", "created", "cvm_id", "cvm_name", "vm_uuid"}
        or response.get("app_id") != deployment["app_id"]
        or response.get("created") is not True
        or response.get("cvm_id") != deployment["cvm_id"]
        or response.get("cvm_name") != deployment["cvm_name"]
        or response.get("vm_uuid") != deployment["vm_uuid"]
    ):
        raise MeasurementAllowlistError("execution record deployment result drift")


def _validate_capture_event(
    event: Mapping[str, Any],
    *,
    deployment_name: str,
    deployment: Mapping[str, Any],
    manifest_files: Mapping[str, str],
) -> None:
    response = event.get("response")
    if (
        not isinstance(response, Mapping)
        or set(response) != {"artifact_count", "captured", "status"}
        or response.get("captured") is not True
        or response.get("status") != "retained"
        or response.get("artifact_count") != 5
    ):
        raise MeasurementAllowlistError("execution record evidence capture drift")
    prefix = "evidence/m2/deployments/" + (deployment_name)
    expected = {
        f"{prefix}/attestation.json",
        f"{prefix}/deployment.json",
        f"{prefix}/event-log.json",
        f"{prefix}/info.json",
        f"{prefix}/quote.hex",
    }
    actual = {
        artifact["path"]
        for artifact in event["artifacts"]
        if isinstance(artifact, Mapping)
    }
    if actual != expected or any(
        path[len(EXECUTION_ARTIFACT_PREFIX) :] not in manifest_files for path in actual
    ):
        raise MeasurementAllowlistError("execution record evidence artifact drift")


def _validate_validation_event(
    event: Mapping[str, Any],
    *,
    deployment_name: str,
    expected_kind: str,
) -> None:
    validation = event.get("validation")
    if (
        not isinstance(validation, Mapping)
        or set(validation) != {"command", "exit_code", "kind", "result", "status"}
        or validation.get("exit_code") != 0
        or validation.get("status") != "passed"
        or not isinstance(validation.get("result"), Mapping)
    ):
        raise MeasurementAllowlistError("execution record validation result drift")

    deployment_prefix = f"evidence/m2/deployments/{deployment_name}"
    canonical_specs = {
        "dcap-qvl verify": {
            "command": f"dcap-qvl verify --hex {deployment_prefix}/quote.hex",
            "result": {"advisories": 0, "status": "UpToDate"},
            "artifacts": (
                f"{deployment_prefix}/quote.hex",
                f"{deployment_prefix}/attestation.json",
            ),
        },
        "dcap-qvl decode": {
            "command": f"dcap-qvl decode --hex {deployment_prefix}/quote.hex",
            "result": {"measurement": "allowlisted", "status": "decoded"},
            "artifacts": (f"{deployment_prefix}/quote.hex",),
        },
        "direct RTMR3 replay": {
            "command": (f"python3 -c replay_rtmr3 {deployment_prefix}/event-log.json"),
            "result": {
                "compose_hash": (
                    "5f87b1082fdb39e7345db64bb5d5b5b62fff01b0afc624ad4da861ede4361a42"
                ),
                "status": "matched",
            },
            "artifacts": (f"{deployment_prefix}/event-log.json",),
        },
        "reproducibility validation": {
            "command": "python3 image/reproducibility.py validate",
            "result": {"image": "current_digest", "status": "reconciled"},
            "artifacts": ("evidence/m2/measurement/dstack-mr-output.json",),
        },
    }
    if expected_kind not in canonical_specs or validation.get("kind") != expected_kind:
        raise MeasurementAllowlistError(
            "execution record validation kind or order drift"
        )
    expected = canonical_specs[expected_kind]
    if validation.get("command") != expected["command"]:
        raise MeasurementAllowlistError("execution record validation command drift")
    if dict(validation["result"]) != expected["result"]:
        raise MeasurementAllowlistError("execution record validation result drift")
    actual_artifacts = tuple(
        artifact["path"]
        for artifact in event["artifacts"]
        if isinstance(artifact, Mapping) and isinstance(artifact.get("path"), str)
    )
    if actual_artifacts != expected["artifacts"]:
        raise MeasurementAllowlistError("execution record validation artifacts drift")


def _validate_deletion_event(
    event: Mapping[str, Any],
    *,
    deployment: Mapping[str, Any],
) -> None:
    request = event.get("request")
    response = event.get("response")
    if isinstance(request, Mapping):
        _validate_deployment_identity(
            request,
            label="execution.deletion.request",
            fields=("cvm_id", "cvm_name"),
        )
    if isinstance(response, Mapping):
        _validate_deployment_identity(
            response,
            label="execution.deletion.response",
            fields=("cvm_id",),
        )
    if (
        not isinstance(request, Mapping)
        or set(request) != {"cvm_id", "cvm_name", "operation"}
        or request.get("cvm_id") != deployment["cvm_id"]
        or request.get("cvm_name") != deployment["cvm_name"]
        or request.get("operation") != "phala cvms delete"
        or not isinstance(response, Mapping)
        or set(response) != {"cvm_id", "deleted", "status"}
        or response.get("cvm_id") != deployment["cvm_id"]
        or response.get("deleted") is not True
        or response.get("status") != "deleted"
    ):
        raise MeasurementAllowlistError("execution record deletion result drift")


def _validate_final_inventory_event(event: Mapping[str, Any]) -> None:
    response = event.get("response")
    if isinstance(response, Mapping):
        mission_owned_cvm_ids = response.get("mission_owned_cvm_ids")
        if isinstance(mission_owned_cvm_ids, list):
            for index, value in enumerate(mission_owned_cvm_ids):
                cvm_id = _validate_identity_value(
                    value,
                    label=f"execution.final_inventory.mission_owned_cvm_ids[{index}]",
                )
                _reject_protected_identity(
                    cvm_id,
                    label=f"execution.final_inventory.mission_owned_cvm_ids[{index}]",
                )
        protected_cvm = response.get("protected_cvm")
        if isinstance(protected_cvm, Mapping):
            _validate_identity_value(
                protected_cvm.get("cvm_id"),
                label="execution.final_inventory.protected_cvm.cvm_id",
            )
            _validate_identity_value(
                protected_cvm.get("cvm_name"),
                label="execution.final_inventory.protected_cvm.cvm_name",
            )
    if (
        not isinstance(response, Mapping)
        or set(response)
        != {
            "account_cvm_total",
            "mission_owned_cvm_ids",
            "mission_owned_cvm_total",
            "protected_cvm",
        }
        or response.get("account_cvm_total") != 1
        or response.get("mission_owned_cvm_ids") != []
        or response.get("mission_owned_cvm_total") != 0
        or response.get("protected_cvm")
        != {
            "cvm_id": PROTECTED_CVM_ID,
            "cvm_name": PROTECTED_CVM_NAME,
            "preserved": True,
            "status": "running",
        }
    ):
        raise MeasurementAllowlistError("execution record final inventory drift")


def _validate_reconciliation_event(event: Mapping[str, Any]) -> None:
    validation = event.get("validation")
    if (
        not isinstance(validation, Mapping)
        or set(validation) != {"command", "exit_code", "result", "status"}
        or validation.get("command") != "python3 image/reproducibility.py validate"
        or validation.get("exit_code") != 0
        or validation.get("status") != "passed"
        or validation.get("result")
        != {"evidence": "retained", "additional_deployment": False}
    ):
        raise MeasurementAllowlistError("execution record reconciliation result drift")


def _reject_sensitive_execution_values(value: Any) -> None:
    serialized = json.dumps(value, sort_keys=True, ensure_ascii=True).lower()
    if any(
        marker in serialized
        for marker in (
            "-----begin",
            "private key",
            "api_key",
            "access_token",
            "authorization:",
            "password",
            "report_data",
        )
    ):
        raise MeasurementAllowlistError(
            "immutable redacted execution record contains sensitive material"
        )


def _catalog_artifacts_match(catalog: Mapping[str, Any], *, root: Path) -> bool:
    metadata_path = catalog.get("metadata_source")
    metadata_sha256 = catalog.get("metadata_sha256")
    release_hashes = catalog.get("release_files_sha256")
    if (
        not isinstance(metadata_path, str)
        or not isinstance(metadata_sha256, str)
        or HEX64.fullmatch(metadata_sha256) is None
        or not isinstance(release_hashes, Mapping)
    ):
        return False
    try:
        path = _repository_relative_path(root, metadata_path, "catalog.metadata_source")
        if hashlib.sha256(path.read_bytes()).hexdigest() != metadata_sha256:
            return False
        metadata = _load_json(path, "catalog metadata")
        release = _load_json(
            _repository_relative_path(
                root, catalog.get("release_identity_path"), "catalog release identity"
            ),
            "catalog release identity",
        )
        digest_path = _repository_relative_path(
            root, catalog.get("digest_path"), "catalog digest"
        )
        checksum_path = _repository_relative_path(
            root, catalog.get("sha256sum_path"), "catalog sha256sum"
        )
        files_path = _repository_relative_path(
            root, catalog.get("release_files_path"), "catalog release files"
        )
        release_files = _load_json(files_path, "catalog release files")
        checksums: dict[str, str] = {}
        for line in checksum_path.read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) != 2 or HEX64.fullmatch(parts[0]) is None:
                return False
            checksums[parts[1].lstrip("*")] = parts[0]
        digest = digest_path.read_text(encoding="utf-8").strip()
        release_digest = hashlib.sha256(checksum_path.read_bytes()).hexdigest()
        rootfs_match = re.search(
            r"\bdstack\.rootfs_hash=([0-9a-f]{64})\b", metadata["cmdline"]
        )
        if (
            metadata.get("version") != CATALOG_VERSION
            or metadata.get("git_revision") != META_DSTACK_COMMIT
            or metadata.get("is_dev") is not False
            or release.get("name") != CATALOG_RELEASE_NAME
            or release.get("slug") != CATALOG_SLUG
            or release.get("version") != CATALOG_VERSION
            or release.get("source_revision") != META_DSTACK_COMMIT
            or release.get("dstack_revision") != DSTACK_COMMIT
            or release.get("is_dev") is not False
            or release.get("os_image_hash") != CATALOG_OS_IMAGE_HASH
            or metadata_sha256 != release_hashes.get("metadata.json")
            or digest != catalog.get("digest_txt")
            or digest != CATALOG_OS_IMAGE_HASH
            or release_digest != digest
            or not rootfs_match
            or release.get("release_files_sha256") != release_hashes
            or checksums
            != {
                name: expected
                for name, expected in release_hashes.items()
                if name != "rootfs.img.verity"
            }
            or set(release_files) != set(release_hashes)
            or any(
                not isinstance(release_files[name], Mapping)
                or release_files[name].get("sha256") != expected
                or not isinstance(release_files[name].get("size"), int)
                or release_files[name]["size"] <= 0
                for name, expected in release_hashes.items()
            )
        ):
            return False
    except (KeyError, OSError, MeasurementAllowlistError):
        return False
    return True


def _validate_live_evidence(
    evidence: Any,
    *,
    index: int,
    canonical: Mapping[str, str],
    allowlisted_compose_hash: str,
    root: Path,
    deployment_summary: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(evidence, Mapping):
        raise MeasurementAllowlistError(f"live_evidence[{index}] must be an object")
    quote_path = evidence.get("quote_path")
    attestation_path = evidence.get("attestation_path")
    if not isinstance(quote_path, str) or not isinstance(attestation_path, str):
        raise MeasurementAllowlistError(f"live_evidence[{index}] paths are missing")
    info_path = evidence.get("info_path")
    if not isinstance(info_path, str):
        raise MeasurementAllowlistError(f"live_evidence[{index}] info_path is missing")
    quote_file = _repository_relative_path(
        root, quote_path, f"live_evidence[{index}].quote_path"
    )
    attestation_file = _repository_relative_path(
        root, attestation_path, f"live_evidence[{index}].attestation_path"
    )
    info_file = _repository_relative_path(
        root, info_path, f"live_evidence[{index}].info_path"
    )
    event_file = _repository_relative_path(
        root,
        evidence.get("event_log_path"),
        f"live_evidence[{index}].event_log_path",
    )
    deployment_file = _repository_relative_path(
        root,
        evidence.get("deployment_path"),
        f"live_evidence[{index}].deployment_path",
    )
    quote_hex = quote_file.read_text(encoding="utf-8").strip()
    try:
        quote = bytes.fromhex(quote_hex)
    except ValueError as exc:
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] quote is not hex"
        ) from exc
    if len(quote) < 584:
        raise MeasurementAllowlistError(f"live_evidence[{index}] quote is truncated")
    _verify_quote(quote, quote_path=quote_file, index=index)
    signed = {
        "mrtd": quote[48 + 136 : 48 + 136 + REGISTER_BYTES].hex(),
        "rtmr0": quote[48 + 328 : 48 + 328 + REGISTER_BYTES].hex(),
        "rtmr1": quote[48 + 376 : 48 + 376 + REGISTER_BYTES].hex(),
        "rtmr2": quote[48 + 424 : 48 + 424 + REGISTER_BYTES].hex(),
        "rtmr3": quote[48 + 472 : 48 + 472 + REGISTER_BYTES].hex(),
    }
    if any(
        signed[field] != canonical[field]
        for field in CANONICAL_FIELDS
        if field in REGISTER_FIELDS
    ):
        raise MeasurementAllowlistError(f"live_evidence[{index}] quote registers drift")
    mr_config_id = quote[48 + 184 : 48 + 184 + REGISTER_BYTES]
    if len(mr_config_id) != REGISTER_BYTES or mr_config_id[0] != 1:
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] mr_config_id is malformed"
        )
    if mr_config_id[1:33].hex() != allowlisted_compose_hash:
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] mr_config_id compose drift"
        )
    attestation = _load_json(attestation_file, "live attestation")
    certificates = (
        attestation.get("app_certificates")
        if isinstance(attestation, Mapping)
        else None
    )
    app_id = evidence.get("app_id")
    if not isinstance(certificates, list):
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] certificate binding is missing"
        )
    app_certificate = next(
        (
            certificate
            for certificate in certificates
            if isinstance(certificate, Mapping)
            and certificate.get("quote") == quote_hex
        ),
        None,
    )
    if (
        not isinstance(app_certificate, Mapping)
        or app_certificate.get("app_id") != app_id
        or not any(
            isinstance(certificate, Mapping) and certificate.get("app_id") == app_id
            for certificate in certificates
        )
    ):
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] quote is not bound to the recorded app certificate"
        )
    tcb_info = attestation.get("tcb_info") if isinstance(attestation, Mapping) else None
    if not isinstance(tcb_info, Mapping):
        raise MeasurementAllowlistError(f"live_evidence[{index}] has no tcb_info")
    for field in (*REGISTER_FIELDS, "rtmr3"):
        if tcb_info.get(field) != signed[field]:
            raise MeasurementAllowlistError(
                f"live_evidence[{index}] tcb_info.{field} does not match quote"
            )
    event_log = tcb_info.get("event_log")
    if not isinstance(event_log, list):
        raise MeasurementAllowlistError(f"live_evidence[{index}] has no event_log")
    retained_event_log = _load_json(event_file, "retained RTMR3 event log")
    if not isinstance(retained_event_log, list) or not retained_event_log:
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] retained event log is empty"
        )
    if retained_event_log != event_log:
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] retained event log differs from attestation"
        )
    replay = replay_rtmr3(retained_event_log)
    if replay["rtmr3"] != signed["rtmr3"]:
        raise MeasurementAllowlistError(f"live_evidence[{index}] RTMR3 replay mismatch")
    if replay["compose_hash"] != allowlisted_compose_hash:
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] compose-hash event mismatch"
        )
    if not replay["key_provider"]:
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] key-provider event missing"
        )
    event_names = [
        event.get("event")
        for event in event_log
        if isinstance(event, Mapping) and event.get("imr") == RTMR3_INDEX
    ]
    if event_names != list(EXPECTED_RUNTIME_EVENTS):
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] RTMR3 event sequence is not the expected boot sequence"
        )
    app_id_events = [
        event
        for event in event_log
        if isinstance(event, Mapping)
        and event.get("imr") == RTMR3_INDEX
        and event.get("event") == "app-id"
    ]
    if len(app_id_events) != 1 or app_id_events[0].get("event_payload") != app_id:
        raise MeasurementAllowlistError(f"live_evidence[{index}] app-id event drift")
    os_image_events = [
        event
        for event in event_log
        if isinstance(event, Mapping)
        and event.get("imr") == RTMR3_INDEX
        and event.get("event") == "os-image-hash"
    ]
    if (
        len(os_image_events) != 1
        or os_image_events[0].get("event_payload") != canonical["os_image_hash"]
    ):
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] os-image-hash event drift"
        )
    info = _load_json(info_file, "live /Info")
    deployment = _load_json(deployment_file, "deployment record")
    if not isinstance(info, Mapping):
        raise MeasurementAllowlistError(f"live_evidence[{index}] /Info identity drift")
    _validate_deployment_identity(
        {
            "app_id": info.get("app_id"),
            "cvm_id": info.get("id"),
            "cvm_name": info.get("name"),
        },
        label=f"live_evidence[{index}].info",
    )
    if not isinstance(deployment, Mapping):
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] deployment record drift"
        )
    _validate_deployment_identity(
        deployment,
        label=f"live_evidence[{index}].deployment",
    )
    os_info = info.get("os") if isinstance(info, Mapping) else None
    resource = info.get("resource") if isinstance(info, Mapping) else None
    if (
        info.get("status") != "running"
        or info.get("app_id") != app_id
        or info.get("name") != evidence.get("cvm_name")
        or info.get("id") != deployment_summary.get("cvm_id")
        or info.get("vm_uuid") != deployment_summary.get("vm_uuid")
        or not isinstance(resource, Mapping)
        or resource.get("instance_type") != "tdx.small"
        or resource.get("vcpu") != 1
        or resource.get("memory_in_gb") != 2
        or resource.get("gpus") != 0
        or not isinstance(os_info, Mapping)
        or os_info.get("name") != "dstack-0.5.9"
        or os_info.get("version") != "0.5.9"
        or os_info.get("is_dev") is not False
        or os_info.get("os_image_hash") != canonical["os_image_hash"]
        or info.get("compose_hash") != allowlisted_compose_hash
    ):
        raise MeasurementAllowlistError(f"live_evidence[{index}] /Info identity drift")
    if (
        set(deployment) != DEPLOYMENT_FIELDS
        or deployment.get("app_id") != app_id
        or deployment.get("cvm_name") != evidence.get("cvm_name")
        or deployment.get("cvm_id") != info.get("id")
        or deployment.get("vm_uuid") != info.get("vm_uuid")
        or deployment.get("cvm_id") != deployment_summary.get("cvm_id")
        or deployment.get("vm_uuid") != deployment_summary.get("vm_uuid")
        or deployment.get("instance_type") != "tdx.small"
        or deployment.get("os_image") != CATALOG_SLUG
        or deployment.get("automatic_placement") is not True
        or deployment.get("requested_region") is not None
        or deployment.get("requested_node_id") is not None
        or deployment.get("image_ref") != APPLICATION_IMAGE_REF
        or deployment.get("compose_hash") != allowlisted_compose_hash
        or deployment.get("created") is not True
        or deployment.get("deleted") is not True
    ):
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] deployment record drift"
        )
    compose_file = info.get("compose_file")
    if not isinstance(compose_file, Mapping):
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] /Info has no compose_file"
        )
    if (
        phala_app_compose_hash(
            {key: value for key, value in compose_file.items() if value is not None}
        )
        != allowlisted_compose_hash
    ):
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] /Info app-compose hash drift"
        )
    if evidence.get("rtmr3") != signed["rtmr3"]:
        raise MeasurementAllowlistError(f"live_evidence[{index}] recorded RTMR3 drift")
    return dict(deployment)


def _verify_quote(quote: bytes, *, quote_path: Path, index: int) -> None:
    """Require dcap-qvl to validate the signed quote and its production TDX report."""

    if (
        len(quote) < QUOTE_HEADER_BYTES + TD_REPORT_BYTES + 4
        or int.from_bytes(quote[0:2], "little") != QUOTE_VERSION
        or int.from_bytes(quote[4:8], "little") != TDX_TEE_TYPE
        or quote[8:12] != bytes(4)
        or quote[12:28] != INTEL_QE_VENDOR_ID
    ):
        raise MeasurementAllowlistError(f"live_evidence[{index}] is not a TDX quote v4")
    signed_prefix = QUOTE_HEADER_BYTES + TD_REPORT_BYTES
    signature_length = int.from_bytes(
        quote[signed_prefix : signed_prefix + 4], "little"
    )
    if signature_length < 584 or signed_prefix + 4 + signature_length > len(quote):
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] quote length is malformed"
        )
    try:
        result = subprocess.run(
            ["dcap-qvl", "verify", "--hex", str(quote_path)],
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] dcap-qvl could not run"
        ) from exc
    if result.returncode != 0:
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] quote verification failed"
        )
    try:
        verdict = json.loads(result.stdout.splitlines()[0])
    except (IndexError, json.JSONDecodeError) as exc:
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] dcap-qvl returned invalid JSON"
        ) from exc
    if (
        verdict.get("status") != "UpToDate"
        or verdict.get("advisory_ids") != []
        or not isinstance(verdict.get("qe_status"), Mapping)
        or verdict["qe_status"].get("status") != "UpToDate"
        or not isinstance(verdict.get("platform_status"), Mapping)
        or verdict["platform_status"].get("status") != "UpToDate"
        or verdict.get("report", {}).get("TD10", {}).get("td_attributes")
        != "0000001000000000"
    ):
        raise MeasurementAllowlistError(
            f"live_evidence[{index}] quote TCB or production posture is not acceptable"
        )


__all__ = [
    "CANONICAL_FIELDS",
    "CATALOG_OS_IMAGE_HASH",
    "CATALOG_RELEASE_NAME",
    "CATALOG_SLUG",
    "CATALOG_VERSION",
    "DSTACK_COMMIT",
    "MEASUREMENT_QEMU_VERSION",
    "META_DSTACK_COMMIT",
    "MeasurementAllowlistError",
    "allowlist_contains",
    "load_allowlist",
    "normalize_app_compose",
    "phala_app_compose_hash",
    "replay_rtmr3",
    "validate_reconciliation",
    "verify_evidence_manifest",
    "write_evidence_manifest",
]
