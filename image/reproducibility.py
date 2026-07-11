#!/usr/bin/env python3
"""Fail-closed reproducibility checks for the basecrawl CVM image."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence


IMAGE_DIR = Path(__file__).resolve().parent
REPO_ROOT = IMAGE_DIR.parent
DOCKERFILE = IMAGE_DIR / "Dockerfile"
COMPOSE_FILE = IMAGE_DIR / "docker-compose.yml"
SOURCE_DATE_EPOCH = 1_700_000_000

_DIGEST_PIN = re.compile(r"@sha256:[0-9a-f]{64}$")
_LATEST_TAG = re.compile(r":latest@sha256:[0-9a-f]{64}$")
_BUILD_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_HEX_96 = re.compile(r"^[0-9a-f]{96}$")
_ARG = re.compile(r"^\s*ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(\S+))?\s*$")
_FROM = re.compile(
    r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+[Aa][Ss]\s+([A-Za-z0-9_.-]+))?\s*$"
)
_SUBSTITUTION = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")

EVIDENCE_FIELDS = (
    "build_digest",
    "image_ref",
    "image_identity",
    "mrtd",
    "rtmr0",
    "rtmr1",
    "rtmr2",
    "compose_hash",
)
PROVENANCE_FIELDS = (
    "build_metadata_path",
    "quote_path",
    "attestation_path",
    "info_path",
)
DEPLOYMENT_FIELDS = ("app_id", "cvm_name")


class ReproducibilityError(RuntimeError):
    """A build definition or independent build/deployment comparison drifted."""


@dataclass(frozen=True)
class DockerfileReport:
    external_images: tuple[str, ...]
    unpinned_images: tuple[str, ...]


@dataclass(frozen=True)
class ComposeReport:
    services: tuple[str, ...]
    unpinned_services: tuple[str, ...]
    missing_image_services: tuple[str, ...]
    mounts_dstack_socket: bool


def _resolve_args(value: str, args: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        return args.get(name, match.group(0))

    return _SUBSTITUTION.sub(replace, value)


def validate_dockerfile(text: str) -> DockerfileReport:
    """Require every external Dockerfile stage to use an immutable digest."""

    args: dict[str, str] = {}
    stage_aliases: set[str] = set()
    external: list[str] = []

    for line in text.splitlines():
        if match := _ARG.match(line):
            if match.group(2) is not None:
                args[match.group(1)] = match.group(2)
            continue
        if not (match := _FROM.match(line)):
            continue
        image = _resolve_args(match.group(1), args)
        alias = match.group(2)
        if image not in stage_aliases and image != "scratch":
            external.append(image)
        if alias:
            stage_aliases.add(alias)

    unpinned = tuple(
        image
        for image in external
        if not _DIGEST_PIN.search(image) or _LATEST_TAG.search(image)
    )
    if not external:
        raise ReproducibilityError("Dockerfile contains no external base images")
    return DockerfileReport(tuple(external), unpinned)


def _normalized_compose(text: str) -> dict[str, Any]:
    proc = subprocess.run(
        ["docker", "compose", "-f", "-", "config", "--format", "json"],
        input=text,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise ReproducibilityError(f"invalid Compose definition: {proc.stderr.strip()}")
    try:
        document = json.loads(proc.stdout)
    except json.JSONDecodeError as error:
        raise ReproducibilityError(f"docker compose returned invalid JSON: {error}") from error
    if not isinstance(document, dict):
        raise ReproducibilityError("normalized Compose document is not an object")
    return document


def validate_compose(text: str) -> ComposeReport:
    """Validate normalized Compose services, image pins, and the socket bind."""

    document = _normalized_compose(text)
    service_specs = document.get("services")
    if not isinstance(service_specs, dict) or not service_specs:
        raise ReproducibilityError("Compose contains no services")

    services = tuple(sorted(service_specs))
    images = {
        service: spec.get("image")
        for service, spec in service_specs.items()
        if isinstance(spec, dict) and isinstance(spec.get("image"), str)
    }
    missing = tuple(service for service in services if service not in images)
    unpinned = tuple(
        service
        for service, image in images.items()
        if not _DIGEST_PIN.search(image) or _LATEST_TAG.search(image)
    )
    mounts_dstack_socket = any(
        isinstance(volume, dict)
        and volume.get("type") == "bind"
        and volume.get("source") == "/var/run/dstack.sock"
        and volume.get("target") == "/var/run/dstack.sock"
        for spec in service_specs.values()
        if isinstance(spec, dict)
        for volume in spec.get("volumes", [])
    )
    return ComposeReport(
        services=services,
        unpinned_services=unpinned,
        missing_image_services=missing,
        mounts_dstack_socket=mounts_dstack_socket,
    )


def compose_image_ref(text: str, service: str = "basecrawl") -> str:
    document = _normalized_compose(text)
    services = document.get("services")
    spec = services.get(service) if isinstance(services, dict) else None
    image = spec.get("image") if isinstance(spec, dict) else None
    if not isinstance(image, str) or not _DIGEST_PIN.search(image):
        raise ReproducibilityError(f"Compose service {service!r} is not digest-pinned")
    return image


def validate_definitions() -> dict[str, Any]:
    dockerfile = validate_dockerfile(DOCKERFILE.read_text(encoding="utf-8"))
    compose = validate_compose(COMPOSE_FILE.read_text(encoding="utf-8"))
    problems: list[str] = []
    if dockerfile.unpinned_images:
        problems.append(f"unpinned Dockerfile images: {dockerfile.unpinned_images!r}")
    if compose.unpinned_services:
        problems.append(f"unpinned Compose services: {compose.unpinned_services!r}")
    if compose.missing_image_services:
        problems.append(f"Compose services without images: {compose.missing_image_services!r}")
    if not compose.mounts_dstack_socket:
        problems.append("Compose does not mount /var/run/dstack.sock")
    dockerfile_text = DOCKERFILE.read_text(encoding="utf-8").lower()
    if "playwright install --with-deps" in dockerfile_text:
        problems.append("forbidden build-time playwright dependency installer found")
    if problems:
        raise ReproducibilityError("; ".join(problems))
    return {
        "dockerfile_images": list(dockerfile.external_images),
        "compose_services": list(compose.services),
        "dstack_socket_mounted": compose.mounts_dstack_socket,
    }


def build_command(
    *,
    output: Path,
    metadata: Path,
    dockerfile: Path = DOCKERFILE,
    context: Path = REPO_ROOT,
) -> list[str]:
    """Construct the normalized BuildKit command used for every independent build."""

    return [
        "docker",
        "buildx",
        "build",
        "--progress=plain",
        "--platform",
        "linux/amd64",
        "--no-cache",
        "--provenance=false",
        "--sbom=false",
        "--build-arg",
        f"SOURCE_DATE_EPOCH={SOURCE_DATE_EPOCH}",
        "--metadata-file",
        str(metadata),
        "--output",
        f"type=oci,dest={output},rewrite-timestamp=true",
        "-f",
        str(dockerfile),
        str(context),
    ]


def build_once(*, output: Path, metadata: Path) -> str:
    proc = subprocess.run(build_command(output=output, metadata=metadata), check=False)
    if proc.returncode != 0:
        raise ReproducibilityError(f"image build failed with exit code {proc.returncode}")
    try:
        build_metadata = json.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReproducibilityError(f"invalid BuildKit metadata: {error}") from error
    digest = build_metadata.get("containerimage.digest")
    if not isinstance(digest, str) or not _BUILD_DIGEST.fullmatch(digest):
        raise ReproducibilityError(f"BuildKit returned an invalid image digest: {digest!r}")
    return digest


def check_builds(*, count: int = 2, output_dir: Path | None = None) -> list[str]:
    """Build independently and reject any OCI image digest drift."""

    if count < 2:
        raise ReproducibilityError("at least two independent builds are required")
    if output_dir is None:
        with tempfile.TemporaryDirectory(prefix="basecrawl-repro-") as temporary:
            return check_builds(count=count, output_dir=Path(temporary))
    output_dir.mkdir(parents=True, exist_ok=True)
    digests = [
        build_once(
            output=output_dir / f"basecrawl-{index}.oci.tar",
            metadata=output_dir / f"basecrawl-{index}.metadata.json",
        )
        for index in range(1, count + 1)
    ]
    if len(set(digests)) != 1:
        raise ReproducibilityError(f"build_digest drift across independent builds: {digests!r}")
    return digests


def _validate_evidence(entry: dict[str, Any], index: int) -> None:
    missing = [
        field for field in (*EVIDENCE_FIELDS, *DEPLOYMENT_FIELDS) if field not in entry
    ]
    if missing:
        raise ReproducibilityError(f"evidence[{index}] missing fields: {missing!r}")
    validators = {
        "build_digest": _BUILD_DIGEST,
        "image_ref": re.compile(r"^.+@sha256:[0-9a-f]{64}$"),
        "image_identity": _HEX_64,
        "mrtd": _HEX_96,
        "rtmr0": _HEX_96,
        "rtmr1": _HEX_96,
        "rtmr2": _HEX_96,
        "compose_hash": _HEX_64,
    }
    for field, pattern in validators.items():
        value = entry[field]
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise ReproducibilityError(
                f"evidence[{index}] {field} is not an immutable canonical value: {value!r}"
            )
    image_digest = entry["image_ref"].rsplit("@", 1)[1]
    if image_digest != entry["build_digest"]:
        raise ReproducibilityError(
            f"evidence[{index}] image_ref digest does not equal build_digest"
        )
    expected_image_ref = compose_image_ref(COMPOSE_FILE.read_text(encoding="utf-8"))
    if entry["image_ref"] != expected_image_ref:
        raise ReproducibilityError(
            f"evidence[{index}] image_ref does not equal the current Compose image"
        )
    if not isinstance(entry["app_id"], str) or not re.fullmatch(
        r"[0-9a-f]{40}", entry["app_id"]
    ):
        raise ReproducibilityError(f"evidence[{index}] app_id is malformed")
    if not isinstance(entry["cvm_name"], str) or not entry["cvm_name"].strip():
        raise ReproducibilityError(f"evidence[{index}] cvm_name is malformed")


def _load_json(path: Path, what: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReproducibilityError(f"cannot load {what} {path}: {error}") from error
    if not isinstance(data, dict):
        raise ReproducibilityError(f"{what} {path} must contain one JSON object")
    return data


def _require_live_provenance(entry: dict[str, Any], index: int) -> str:
    missing = [field for field in PROVENANCE_FIELDS if field not in entry]
    if missing:
        raise ReproducibilityError(
            f"evidence[{index}] missing provenance fields: {missing!r}"
        )
    paths: dict[str, Path] = {}
    for field in PROVENANCE_FIELDS:
        value = entry[field]
        if not isinstance(value, str):
            raise ReproducibilityError(f"evidence[{index}] {field} must be a path")
        path = Path(value)
        if not path.is_absolute() or not path.is_file():
            raise ReproducibilityError(
                f"evidence[{index}] {field} is not an existing absolute file: {value!r}"
            )
        paths[field] = path

    metadata = _load_json(paths["build_metadata_path"], "BuildKit metadata")
    if metadata.get("containerimage.digest") != entry["build_digest"]:
        raise ReproducibilityError(
            f"evidence[{index}] build_digest does not match BuildKit metadata"
        )
    build_ref = metadata.get("buildx.build.ref")
    if not isinstance(build_ref, str) or not build_ref:
        raise ReproducibilityError(
            f"evidence[{index}] BuildKit metadata has no independent build reference"
        )
    registry = subprocess.run(
        ["docker", "buildx", "imagetools", "inspect", "--raw", entry["image_ref"]],
        capture_output=True,
        check=False,
    )
    if registry.returncode != 0:
        raise ReproducibilityError(
            f"evidence[{index}] published image cannot be inspected"
        )
    published_digest = "sha256:" + hashlib.sha256(registry.stdout).hexdigest()
    if published_digest != entry["build_digest"]:
        raise ReproducibilityError(
            f"evidence[{index}] published image digest does not match build_digest"
        )

    quote_hex = paths["quote_path"].read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]+", quote_hex) or len(quote_hex) < 1264:
        raise ReproducibilityError(f"evidence[{index}] quote is malformed")
    verify = subprocess.run(
        ["dcap-qvl", "verify", "--hex", str(paths["quote_path"])],
        capture_output=True,
        text=True,
        check=False,
    )
    if verify.returncode != 0:
        raise ReproducibilityError(
            f"evidence[{index}] quote verification failed: {verify.stderr.strip()}"
        )
    try:
        verdict = json.loads(verify.stdout)
    except json.JSONDecodeError as error:
        raise ReproducibilityError(
            f"evidence[{index}] quote verifier returned invalid JSON: {error}"
        ) from error
    qe_status = verdict.get("qe_status")
    platform_status = verdict.get("platform_status")
    if (
        verdict.get("status") != "UpToDate"
        or verdict.get("advisory_ids") != []
        or not isinstance(qe_status, dict)
        or qe_status.get("status") != "UpToDate"
        or not isinstance(platform_status, dict)
        or platform_status.get("status") != "UpToDate"
    ):
        raise ReproducibilityError(
            f"evidence[{index}] quote TCB posture is not fully UpToDate"
        )
    signed = verdict.get("report", {}).get("TD10")
    if not isinstance(signed, dict):
        raise ReproducibilityError(f"evidence[{index}] quote has no TD10 report")
    signed_fields = {
        "mrtd": "mr_td",
        "rtmr0": "rt_mr0",
        "rtmr1": "rt_mr1",
        "rtmr2": "rt_mr2",
    }
    for evidence_field, quote_field in signed_fields.items():
        if signed.get(quote_field) != entry[evidence_field]:
            raise ReproducibilityError(
                f"evidence[{index}] {evidence_field} does not match the signed quote"
            )
    mr_config_id = signed.get("mr_config_id")
    if (
        not isinstance(mr_config_id, str)
        or len(mr_config_id) < 66
        or mr_config_id[2:66] != entry["compose_hash"]
    ):
        raise ReproducibilityError(
            f"evidence[{index}] compose_hash does not match signed mr_config_id"
        )

    attestation = _load_json(paths["attestation_path"], "Phala attestation")
    certificates = attestation.get("app_certificates")
    if not isinstance(certificates, list) or not any(
        isinstance(certificate, dict) and certificate.get("quote") == quote_hex
        for certificate in certificates
    ):
        raise ReproducibilityError(
            f"evidence[{index}] quote is not the live app-certificate quote"
        )
    tcb_info = attestation.get("tcb_info")
    if not isinstance(tcb_info, dict):
        raise ReproducibilityError(f"evidence[{index}] attestation has no tcb_info")
    for evidence_field in ("mrtd", "rtmr0", "rtmr1", "rtmr2"):
        if tcb_info.get(evidence_field) != entry[evidence_field]:
            raise ReproducibilityError(
                f"evidence[{index}] {evidence_field} does not match live tcb_info"
            )
    if tcb_info.get("rtmr3") != signed.get("rt_mr3"):
        raise ReproducibilityError(
            f"evidence[{index}] live event log is not tied to the signed RTMR3"
        )

    info = _load_json(paths["info_path"], "Phala CVM info")
    os_info = info.get("os")
    compose_info = info.get("compose_file")
    if (
        info.get("status") != "running"
        or info.get("app_id") != entry["app_id"]
        or info.get("name") != entry["cvm_name"]
        or not isinstance(os_info, dict)
        or os_info.get("os_image_hash") != entry["image_identity"]
        or info.get("compose_hash") != entry["compose_hash"]
        or not isinstance(compose_info, dict)
    ):
        raise ReproducibilityError(
            f"evidence[{index}] image identity or compose_hash does not match live CVM info"
        )
    live_compose = compose_info.get("docker_compose_file")
    if not isinstance(live_compose, str):
        raise ReproducibilityError(f"evidence[{index}] live CVM has no Compose definition")
    live_report = validate_compose(live_compose)
    if live_report.unpinned_services or not live_report.mounts_dstack_socket:
        raise ReproducibilityError(
            f"evidence[{index}] live CVM Compose violates the immutable socket contract"
        )
    if compose_image_ref(live_compose) != entry["image_ref"]:
        raise ReproducibilityError(
            f"evidence[{index}] image_ref does not match the live CVM Compose image"
        )

    event_log = tcb_info.get("event_log")
    if not isinstance(event_log, list):
        raise ReproducibilityError(f"evidence[{index}] attestation has no event log")
    expected_events = {
        "compose-hash": entry["compose_hash"],
        "os-image-hash": entry["image_identity"],
    }
    for name, payload in expected_events.items():
        if not any(
            isinstance(event, dict)
            and event.get("event") == name
            and event.get("event_payload") == payload
            and event.get("imr") == 3
            for event in event_log
        ):
            raise ReproducibilityError(
                f"evidence[{index}] live event log does not bind {name}"
            )
    return build_ref


def assert_reproducible_evidence(entries: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Reject any image, register, image-identity, or compose-hash drift."""

    if len(entries) < 2:
        raise ReproducibilityError("at least two independent deployment records are required")
    for index, entry in enumerate(entries):
        _validate_evidence(entry, index)
    baseline = entries[0]
    for index, entry in enumerate(entries[1:], start=1):
        for field in EVIDENCE_FIELDS:
            if entry[field] != baseline[field]:
                raise ReproducibilityError(
                    f"{field} drift: evidence[0]={baseline[field]!r}, "
                    f"evidence[{index}]={entry[field]!r}"
                )
    for field in DEPLOYMENT_FIELDS:
        values = [entry[field] for entry in entries]
        if len(set(values)) != len(values):
            raise ReproducibilityError(
                f"{field} is not unique across independent deployments: {values!r}"
            )
    return dict(baseline)


def _load_evidence(paths: Sequence[Path]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ReproducibilityError(f"cannot load {path}: {error}") from error
        if not isinstance(data, dict):
            raise ReproducibilityError(f"{path} must contain one JSON object")
        entries.append(data)
    return entries


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate", help="validate immutable image and Compose definitions")
    build_parser = subparsers.add_parser("check-builds", help="build independently and compare")
    build_parser.add_argument("--builds", type=int, default=2)
    build_parser.add_argument("--output-dir", type=Path)
    evidence_parser = subparsers.add_parser(
        "compare-evidence", help="compare independent live deployment evidence"
    )
    evidence_parser.add_argument("evidence", nargs="+", type=Path)
    args = parser.parse_args(argv)

    try:
        if args.command == "validate":
            result: Any = validate_definitions()
        elif args.command == "check-builds":
            result = {"digests": check_builds(count=args.builds, output_dir=args.output_dir)}
        else:
            evidence = _load_evidence(args.evidence)
            build_refs = [
                _require_live_provenance(entry, index)
                for index, entry in enumerate(evidence)
            ]
            if len(set(build_refs)) != len(build_refs):
                raise ReproducibilityError(
                    f"build references are not independent: {build_refs!r}"
                )
            result = {"reproducible": True, "baseline": assert_reproducible_evidence(evidence)}
    except ReproducibilityError as error:
        print(json.dumps({"reproducible": False, "error": str(error)}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
