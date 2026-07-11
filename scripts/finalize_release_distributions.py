from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.metadata
import io
import json
import os
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any


CANONICAL_TOOLCHAIN = {
    "python": "3.13.5",
    "pip": "25.1.1",
    "setuptools": "80.9.0",
    "wheel": "0.45.1",
    "build": "1.2.2.post1",
    "twine": "6.1.0",
}
PROVENANCE_NAME = "RELEASE_PROVENANCE.json"
PACKAGE_PROVENANCE_NAME = "src/continuum/assets/RELEASE_PROVENANCE.json"
WHEEL_PROVENANCE_NAME = "continuum/assets/RELEASE_PROVENANCE.json"
EXPECTED_DISTRIBUTION_NAME = "epic-continuum-memory"
EXPECTED_NORMALIZED_NAME = "epic_continuum_memory"
RECEIPT_NAME = "RELEASE_DISTRIBUTIONS.json"
CHECKSUMS_NAME = "SHA256SUMS"
EXPECTED_WHEEL_GENERATOR = f"setuptools ({CANONICAL_TOOLCHAIN['setuptools']})"
RECEIPT_SCHEMA = "epic_continuum.release_distribution_receipt.v2"
CONTENT_MANIFEST_SCHEMA = "epic_continuum.package_content_manifest.v1"
CONTENT_BINDING_SCHEMA = "epic_continuum.package_content_bindings.v1"
SOURCE_BUILD_VERIFICATION_SCHEMA = "epic_continuum.source_build_verification.v1"
# This is the only package file synthesized by the canonical source builder. It
# is not permitted to vary: all three artifacts must contain the exact root
# release-provenance bytes from the canonical source ZIP.
GENERATED_PACKAGE_FILE_ALLOWANCE = frozenset({WHEEL_PROVENANCE_NAME})


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _stable_json_bytes(payload: Any) -> bytes:
    return (
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def _assert_unique(names: list[str], *, artifact: Path) -> None:
    if len(names) != len(set(names)):
        raise RuntimeError(f"{artifact.name} contains duplicate member names")


def _validate_archive_member_name(name: str, *, artifact: Path) -> None:
    candidate = name[:-1] if name.endswith("/") else name
    if (
        not candidate
        or name.startswith("/")
        or "\\" in name
        or any(part in {"", ".", ".."} for part in candidate.split("/"))
    ):
        raise RuntimeError(f"{artifact.name} contains an invalid archive member name")


def _package_manifest_rows(package_files: dict[str, bytes]) -> list[dict[str, Any]]:
    return [
        {
            "path": path,
            "sha256": _sha256(payload),
            "size_bytes": len(payload),
        }
        for path, payload in sorted(package_files.items())
    ]


def _package_manifest_descriptor(package_files: dict[str, bytes]) -> dict[str, Any]:
    rows = _package_manifest_rows(package_files)
    return {
        "schema": CONTENT_MANIFEST_SCHEMA,
        "file_count": len(rows),
        "sha256": _sha256(_stable_json_bytes(rows)),
    }


def _assert_package_correspondence(
    canonical: dict[str, bytes],
    candidate: dict[str, bytes],
    *,
    artifact_label: str,
) -> None:
    canonical_paths = set(canonical)
    candidate_paths = set(candidate)
    missing = sorted(canonical_paths - candidate_paths)
    extra = sorted(candidate_paths - canonical_paths)
    changed = sorted(
        path
        for path in canonical_paths & candidate_paths
        if candidate[path] != canonical[path]
    )
    if missing or extra or changed:
        raise RuntimeError(
            f"{artifact_label} package content does not match canonical source: "
            f"missing={missing}, extra={extra}, changed={changed}"
        )


def _content_bindings(
    *,
    canonical_package: dict[str, bytes],
    wheel_package: dict[str, bytes],
    sdist_package: dict[str, bytes],
    wheel_record: dict[str, Any],
    source_provenance: bytes,
) -> dict[str, Any]:
    generated_rows = [
        {
            "path": path,
            "rule": "must_equal_canonical_source_and_release_provenance",
            "sha256": _sha256(canonical_package[path]),
        }
        for path in sorted(GENERATED_PACKAGE_FILE_ALLOWANCE)
    ]
    for path in GENERATED_PACKAGE_FILE_ALLOWANCE:
        if canonical_package.get(path) != source_provenance:
            raise RuntimeError(
                "canonical source generated package provenance does not match root provenance"
            )
    return {
        "schema": CONTENT_BINDING_SCHEMA,
        "canonical_package_source": _package_manifest_descriptor(canonical_package),
        "wheel_package": _package_manifest_descriptor(wheel_package),
        "sdist_package_source": _package_manifest_descriptor(sdist_package),
        "wheel_record": dict(wheel_record),
        "generated_package_file_allowance": generated_rows,
    }


def installed_toolchain() -> dict[str, str]:
    versions = {
        "python": ".".join(str(part) for part in sys.version_info[:3]),
    }
    for distribution in ("pip", "setuptools", "wheel", "build", "twine"):
        try:
            versions[distribution] = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError as exc:
            raise RuntimeError(
                f"canonical build dependency is not installed: {distribution}"
            ) from exc
    return versions


def require_canonical_toolchain(actual: dict[str, str] | None = None) -> dict[str, str]:
    resolved = installed_toolchain() if actual is None else dict(actual)
    mismatches = {
        name: {"expected": expected, "actual": resolved.get(name)}
        for name, expected in CANONICAL_TOOLCHAIN.items()
        if resolved.get(name) != expected
    }
    if mismatches:
        rendered = ", ".join(
            f"{name}={values['actual']!r} (expected {values['expected']!r})"
            for name, values in sorted(mismatches.items())
        )
        raise RuntimeError(f"non-canonical distribution build toolchain: {rendered}")
    return resolved


def require_canonical_wheel_generator(generator: str) -> str:
    if generator != EXPECTED_WHEEL_GENERATOR:
        raise RuntimeError(
            f"wheel generator {generator!r} does not match canonical "
            f"{EXPECTED_WHEEL_GENERATOR!r}"
        )
    return generator


def _read_source_provenance(
    source_zip: Path,
) -> tuple[bytes, dict[str, Any], dict[str, bytes]]:
    with zipfile.ZipFile(source_zip) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        _assert_unique(names, artifact=source_zip)
        for info in infos:
            _validate_archive_member_name(info.filename, artifact=source_zip)
        candidates = [
            name
            for name in names
            if name.count("/") == 1 and name.endswith(f"/{PROVENANCE_NAME}")
        ]
        if len(candidates) != 1:
            raise RuntimeError(
                f"{source_zip.name} must contain exactly one root release provenance file"
            )
        root_name = candidates[0]
        prefix = root_name[: -len(PROVENANCE_NAME)]
        root_bytes = archive.read(root_name)
        package_bytes = archive.read(f"{prefix}{PACKAGE_PROVENANCE_NAME}")
        if package_bytes != root_bytes:
            raise RuntimeError("source ZIP root and package provenance differ")
    payload = json.loads(root_bytes)
    if not isinstance(payload, dict):
        raise RuntimeError("release provenance must be a JSON object")
    version = str(payload.get("version") or "")
    expected_root = f"epic-continuum-{version}/"
    if not version or source_zip.name != f"epic-continuum-{version}.zip":
        raise RuntimeError("source ZIP filename does not match provenance version")
    if root_name != f"{expected_root}{PROVENANCE_NAME}":
        raise RuntimeError("source ZIP root does not match provenance version")
    if expected_root not in names:
        raise RuntimeError("source ZIP is missing its canonical root directory entry")
    if str(payload.get("package") or "") != expected_root.rstrip("/"):
        raise RuntimeError("source provenance package does not match its archive root")
    if any(not name.startswith(expected_root) for name in names):
        raise RuntimeError(
            "source ZIP contains a member outside its canonical version root"
        )
    package_provenance_name = f"{expected_root}{PACKAGE_PROVENANCE_NAME}"
    excluded = {root_name, package_provenance_name}
    manifest_rows: list[dict[str, object]] = []
    package_files: dict[str, bytes] = {}
    with zipfile.ZipFile(source_zip) as manifest_archive:
        if not manifest_archive.getinfo(expected_root).is_dir():
            raise RuntimeError("source ZIP root entry is not a directory")
        for info in manifest_archive.infolist():
            mode = (info.external_attr >> 16) & 0xFFFF
            file_type = stat.S_IFMT(mode)
            if file_type not in {stat.S_IFREG, stat.S_IFDIR}:
                raise RuntimeError(
                    "source ZIP contains a non-file, non-directory member"
                )
            is_directory = info.is_dir()
            if is_directory != (file_type == stat.S_IFDIR):
                raise RuntimeError(
                    "source ZIP member mode and directory marker disagree"
                )
            if info.filename == expected_root:
                continue
            member_bytes = b"" if is_directory else manifest_archive.read(info.filename)
            package_prefix = f"{expected_root}src/continuum/"
            if info.filename.startswith(package_prefix) and not is_directory:
                normalized = f"continuum/{info.filename.removeprefix(package_prefix)}"
                package_files[normalized] = member_bytes
            if info.filename in excluded:
                continue
            row: dict[str, object] = {
                "path": info.filename,
                "mode": f"{mode:o}",
                "kind": "directory" if is_directory else "file",
            }
            if not is_directory:
                row["size"] = len(member_bytes)
                row["sha256"] = _sha256(member_bytes)
            manifest_rows.append(row)
    manifest_bytes = (
        json.dumps(manifest_rows, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    expected_count = len(manifest_rows)
    required_provenance = {
        "schema": "epic-continuum.release_provenance.v1",
        "builder": "scripts/build_release_package.py",
        "source": "git",
        "allow_dirty": False,
        "git_dirty": False,
        "git_status_short_count": 0,
        "git_status_short_sha256": None,
        "member_manifest_sha256": _sha256(manifest_bytes),
        "member_count_without_root_or_provenance": expected_count,
        "member_count_with_root_and_provenance": expected_count + 3,
    }
    mismatches = {
        key: {"expected": expected, "actual": payload.get(key)}
        for key, expected in required_provenance.items()
        if payload.get(key) != expected
    }
    commit = str(payload.get("git_commit") or "")
    epoch = payload.get("source_date_epoch")
    if len(commit) != 40 or any(
        character not in "0123456789abcdef" for character in commit
    ):
        mismatches["git_commit"] = {
            "expected": "40 lowercase hexadecimal characters",
            "actual": commit,
        }
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        mismatches["source_date_epoch"] = {
            "expected": "non-negative integer",
            "actual": epoch,
        }
    if len(names) != expected_count + 3:
        mismatches["archive_member_count"] = {
            "expected": expected_count + 3,
            "actual": len(names),
        }
    if mismatches:
        raise RuntimeError(
            f"source ZIP provenance does not match its members: {mismatches}"
        )
    if package_files.get(WHEEL_PROVENANCE_NAME) != root_bytes:
        raise RuntimeError(
            "source ZIP package provenance does not match root provenance"
        )
    return root_bytes, payload, package_files


def _validate_wheel_record(
    *,
    wheel_path: Path,
    wheel_files: dict[str, bytes],
    record_name: str,
) -> dict[str, Any]:
    record_bytes = wheel_files[record_name]
    try:
        reader = csv.reader(io.StringIO(record_bytes.decode("utf-8"), newline=""))
        rows = list(reader)
    except (UnicodeDecodeError, csv.Error) as exc:
        raise RuntimeError(f"{wheel_path.name} has an invalid RECORD") from exc
    parsed: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3:
            raise RuntimeError(f"{wheel_path.name} has an invalid RECORD row")
        path, digest, size = row
        _validate_archive_member_name(path, artifact=wheel_path)
        if path in parsed:
            raise RuntimeError(f"{wheel_path.name} RECORD contains duplicate paths")
        parsed[path] = (digest, size)
    if set(parsed) != set(wheel_files):
        missing = sorted(set(wheel_files) - set(parsed))
        extra = sorted(set(parsed) - set(wheel_files))
        raise RuntimeError(
            f"{wheel_path.name} RECORD does not exactly cover wheel members: "
            f"missing={missing}, extra={extra}"
        )
    for path, payload in wheel_files.items():
        digest, size = parsed[path]
        if path == record_name:
            if digest or size:
                raise RuntimeError(
                    f"{wheel_path.name} RECORD must leave its own hash and size empty"
                )
            continue
        encoded_digest = (
            base64.urlsafe_b64encode(hashlib.sha256(payload).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        if digest != f"sha256={encoded_digest}" or size != str(len(payload)):
            raise RuntimeError(
                f"{wheel_path.name} RECORD does not match member bytes: {path}"
            )
    return {
        "schema": "epic_continuum.wheel_record_binding.v1",
        "entry_count": len(rows),
        "sha256": _sha256(record_bytes),
    }


def _read_wheel_provenance(
    wheel_path: Path,
    *,
    version: str,
) -> tuple[bytes, str, dict[str, bytes], dict[str, Any]]:
    expected_filename = f"{EXPECTED_NORMALIZED_NAME}-{version}-py3-none-any.whl"
    if wheel_path.name != expected_filename:
        raise RuntimeError(
            "wheel filename does not match the canonical distribution identity"
        )
    metadata_root = f"{EXPECTED_NORMALIZED_NAME}-{version}.dist-info"
    with zipfile.ZipFile(wheel_path) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        _assert_unique(names, artifact=wheel_path)
        wheel_files: dict[str, bytes] = {}
        for info in infos:
            _validate_archive_member_name(info.filename, artifact=wheel_path)
            mode = (info.external_attr >> 16) & 0xFFFF
            if info.is_dir() or stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
                raise RuntimeError(f"{wheel_path.name} contains a non-file member")
            if not (
                info.filename.startswith("continuum/")
                or info.filename.startswith(f"{metadata_root}/")
            ):
                raise RuntimeError(
                    f"{wheel_path.name} contains a non-canonical top-level file"
                )
            wheel_files[info.filename] = archive.read(info.filename)
        wheel_metadata_name = f"{metadata_root}/WHEEL"
        package_metadata_name = f"{metadata_root}/METADATA"
        record_name = f"{metadata_root}/RECORD"
        if (
            WHEEL_PROVENANCE_NAME not in names
            or wheel_metadata_name not in names
            or package_metadata_name not in names
        ):
            raise RuntimeError(
                f"{wheel_path.name} is missing canonical provenance, WHEEL, or METADATA"
            )
        provenance = wheel_files[WHEEL_PROVENANCE_NAME]
        if record_name not in names:
            raise RuntimeError(f"{wheel_path.name} is missing canonical RECORD")
        if sum(name.endswith(".dist-info/WHEEL") for name in names) != 1:
            raise RuntimeError(
                f"{wheel_path.name} must contain exactly one WHEEL metadata file"
            )
        if sum(name.endswith(".dist-info/RECORD") for name in names) != 1:
            raise RuntimeError(
                f"{wheel_path.name} must contain exactly one RECORD file"
            )
        wheel_metadata = wheel_files[wheel_metadata_name].decode("utf-8")
        package_metadata = BytesParser(policy=policy.default).parsebytes(
            wheel_files[package_metadata_name]
        )
    wheel_record = _validate_wheel_record(
        wheel_path=wheel_path,
        wheel_files=wheel_files,
        record_name=record_name,
    )
    generator_lines = [
        line for line in wheel_metadata.splitlines() if line.startswith("Generator: ")
    ]
    if len(generator_lines) != 1:
        raise RuntimeError(f"{wheel_path.name} must record exactly one wheel generator")
    if str(package_metadata.get("Name") or "") != EXPECTED_DISTRIBUTION_NAME:
        raise RuntimeError(
            "wheel METADATA Name does not match the canonical distribution"
        )
    if str(package_metadata.get("Version") or "") != version:
        raise RuntimeError("wheel METADATA Version does not match source provenance")
    package_files = {
        path: payload
        for path, payload in wheel_files.items()
        if path.startswith("continuum/")
    }
    return (
        provenance,
        generator_lines[0].removeprefix("Generator: "),
        package_files,
        wheel_record,
    )


def _read_sdist_provenance(
    sdist_path: Path,
    *,
    version: str,
) -> tuple[bytes, dict[str, bytes]]:
    expected_root = f"{EXPECTED_NORMALIZED_NAME}-{version}"
    if sdist_path.name != f"{expected_root}.tar.gz":
        raise RuntimeError(
            "sdist filename does not match the canonical distribution identity"
        )
    with tarfile.open(sdist_path, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        _assert_unique(names, artifact=sdist_path)
        for member in members:
            _validate_archive_member_name(member.name, artifact=sdist_path)
            if not (member.isfile() or member.isdir()):
                raise RuntimeError(
                    f"{sdist_path.name} contains a non-file, non-directory member"
                )
        if any(
            name != expected_root and not name.startswith(f"{expected_root}/")
            for name in names
        ):
            raise RuntimeError(
                "sdist contains a member outside its canonical version root"
            )
        provenance_name = f"{expected_root}/{PACKAGE_PROVENANCE_NAME}"
        package_metadata_name = f"{expected_root}/PKG-INFO"
        if provenance_name not in names or package_metadata_name not in names:
            raise RuntimeError(
                f"{sdist_path.name} is missing canonical provenance or PKG-INFO"
            )
        extracted = archive.extractfile(provenance_name)
        if extracted is None:
            raise RuntimeError(f"could not read provenance from {sdist_path.name}")
        provenance = extracted.read()
        metadata_file = archive.extractfile(package_metadata_name)
        if metadata_file is None:
            raise RuntimeError(f"could not read PKG-INFO from {sdist_path.name}")
        package_metadata = BytesParser(policy=policy.default).parsebytes(
            metadata_file.read()
        )
        package_prefix = f"{expected_root}/src/continuum/"
        package_files: dict[str, bytes] = {}
        for member in members:
            if not member.isfile() or not member.name.startswith(package_prefix):
                continue
            extracted_member = archive.extractfile(member)
            if extracted_member is None:
                raise RuntimeError(
                    f"could not read package file from {sdist_path.name}"
                )
            normalized = f"continuum/{member.name.removeprefix(package_prefix)}"
            package_files[normalized] = extracted_member.read()
    if str(package_metadata.get("Name") or "") != EXPECTED_DISTRIBUTION_NAME:
        raise RuntimeError(
            "sdist PKG-INFO Name does not match the canonical distribution"
        )
    if str(package_metadata.get("Version") or "") != version:
        raise RuntimeError("sdist PKG-INFO Version does not match source provenance")
    return provenance, package_files


def _artifact_row(kind: str, path: Path) -> dict[str, Any]:
    payload = path.read_bytes()
    return {
        "kind": kind,
        "filename": path.name,
        "sha256": _sha256(payload),
        "size_bytes": len(payload),
    }


def _assert_reproducible(primary: Path, comparison_dir: Path) -> None:
    comparison = comparison_dir / primary.name
    if not comparison.is_file():
        raise RuntimeError(f"independent build is missing {primary.name}")
    if primary.samefile(comparison):
        raise RuntimeError(
            f"independent build aliases the primary artifact for {primary.name}"
        )
    if comparison.read_bytes() != primary.read_bytes():
        raise RuntimeError(f"independent canonical builds differ for {primary.name}")


def _source_build_verification_descriptor(
    *,
    source_zip: Path,
    wheel_path: Path,
    sdist_path: Path,
) -> dict[str, Any]:
    return {
        "schema": SOURCE_BUILD_VERIFICATION_SCHEMA,
        "method": "two_separate_source_zip_extractions_rebuilt_by_finalizer",
        "source_zip_sha256": _sha256(source_zip.read_bytes()),
        "separately_extracted_source_tree_count": 2,
        "byte_identical": True,
        "build_command": [
            "python",
            "-m",
            "build",
            "--no-isolation",
            "--wheel",
            "--sdist",
        ],
        "artifacts": [
            _artifact_row("wheel", wheel_path),
            _artifact_row("sdist", sdist_path),
        ],
    }


def _extract_canonical_source_tree(
    *,
    source_zip: Path,
    destination: Path,
    version: str,
) -> Path:
    expected_root = f"epic-continuum-{version}/"
    destination.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(source_zip) as archive:
        for info in archive.infolist():
            if info.filename == expected_root:
                continue
            if not info.filename.startswith(expected_root):
                raise RuntimeError("source ZIP member escaped its canonical root")
            relative = info.filename.removeprefix(expected_root)
            target = destination.joinpath(*relative.rstrip("/").split("/"))
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as handle:
                handle.write(archive.read(info.filename))
            mode = (info.external_attr >> 16) & 0xFFFF
            target.chmod(stat.S_IMODE(mode))
    return destination


def _rebuild_and_verify_from_source(
    *,
    source_zip: Path,
    wheel_path: Path,
    sdist_path: Path,
    version: str,
    source_date_epoch: int,
) -> dict[str, Any]:
    expected_names = {wheel_path.name, sdist_path.name}
    rebuilt: list[dict[str, bytes]] = []
    with tempfile.TemporaryDirectory(prefix="continuum-release-rebuild-") as raw_temp:
        temp_root = Path(raw_temp)
        for build_number in (1, 2):
            source_tree = _extract_canonical_source_tree(
                source_zip=source_zip,
                destination=temp_root / f"source-{build_number}",
                version=version,
            )
            output_dir = temp_root / f"dist-{build_number}"
            output_dir.mkdir()
            environment = os.environ.copy()
            environment.pop("PYTHONHOME", None)
            environment.pop("PYTHONPATH", None)
            environment["PYTHONHASHSEED"] = "0"
            environment["SOURCE_DATE_EPOCH"] = str(source_date_epoch)
            command = [
                sys.executable,
                "-m",
                "build",
                "--no-isolation",
                "--wheel",
                "--sdist",
                "--outdir",
                str(output_dir),
            ]
            completed = subprocess.run(
                command,
                cwd=source_tree,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=300,
            )
            if completed.returncode != 0:
                detail = (completed.stderr or completed.stdout)[-4000:]
                raise RuntimeError(
                    f"canonical source rebuild {build_number} failed: {detail}"
                )
            produced_names = {entry.name for entry in output_dir.iterdir()}
            if produced_names != expected_names:
                raise RuntimeError(
                    "canonical source rebuild produced an unexpected artifact set: "
                    f"expected={sorted(expected_names)}, actual={sorted(produced_names)}"
                )
            rebuilt.append(
                {
                    name: (output_dir / name).read_bytes()
                    for name in sorted(expected_names)
                }
            )
    for artifact_path in (wheel_path, sdist_path):
        artifact_name = artifact_path.name
        if rebuilt[0][artifact_name] != rebuilt[1][artifact_name]:
            raise RuntimeError(
                f"separate canonical source rebuilds differ for {artifact_name}"
            )
        if rebuilt[0][artifact_name] != artifact_path.read_bytes():
            raise RuntimeError(
                f"supplied artifact does not match canonical source rebuild: {artifact_name}"
            )
    return _source_build_verification_descriptor(
        source_zip=source_zip,
        wheel_path=wheel_path,
        sdist_path=sdist_path,
    )


def _resolved(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _assert_distinct_release_paths(
    *,
    source_zip: Path,
    wheel_path: Path,
    sdist_path: Path,
    comparison_dir: Path,
    receipt_out: Path,
    checksums_out: Path,
) -> None:
    paths = {
        "source_zip": _resolved(source_zip),
        "wheel": _resolved(wheel_path),
        "sdist": _resolved(sdist_path),
        "comparison_wheel": _resolved(comparison_dir / wheel_path.name),
        "comparison_sdist": _resolved(comparison_dir / sdist_path.name),
        "receipt_out": _resolved(receipt_out),
        "checksums_out": _resolved(checksums_out),
    }
    by_path: dict[Path, list[str]] = {}
    for label, path in paths.items():
        by_path.setdefault(path, []).append(label)
    collisions = [labels for labels in by_path.values() if len(labels) > 1]
    if collisions:
        rendered = ", ".join("/".join(labels) for labels in collisions)
        raise RuntimeError(
            f"release input/output paths must be pairwise distinct: {rendered}"
        )
    bound_labels = (
        "source_zip",
        "wheel",
        "sdist",
        "receipt_out",
        "checksums_out",
    )
    release_parent = paths["source_zip"].parent
    misplaced = [
        label for label in bound_labels if paths[label].parent != release_parent
    ]
    if misplaced:
        raise RuntimeError(
            "source ZIP, wheel, sdist, receipt, and checksums must share one "
            f"release directory: misplaced={misplaced}"
        )


def _require_canonical_output_names(*, receipt_out: Path, checksums_out: Path) -> None:
    mismatches: list[str] = []
    if receipt_out.name != RECEIPT_NAME:
        mismatches.append(
            f"receipt_out={receipt_out.name!r} (expected {RECEIPT_NAME!r})"
        )
    if checksums_out.name != CHECKSUMS_NAME:
        mismatches.append(
            f"checksums_out={checksums_out.name!r} (expected {CHECKSUMS_NAME!r})"
        )
    if mismatches:
        raise RuntimeError(
            "release outputs must use canonical filenames: " + ", ".join(mismatches)
        )


def _require_closed_release_directory(
    *,
    source_zip: Path,
    wheel_path: Path,
    sdist_path: Path,
    receipt_out: Path,
    checksums_out: Path,
) -> None:
    release_dir = source_zip.parent
    if not release_dir.is_dir():
        raise RuntimeError(f"release directory does not exist: {release_dir}")
    allowed_names = {
        source_zip.name,
        wheel_path.name,
        sdist_path.name,
        receipt_out.name,
        checksums_out.name,
    }
    extras = sorted(
        entry.name for entry in release_dir.iterdir() if entry.name not in allowed_names
    )
    if extras:
        raise RuntimeError(
            "release directory must contain only the canonical five-file set: "
            f"extras={extras}"
        )
    invalid_outputs = sorted(
        path.name
        for path in (receipt_out, checksums_out)
        if path.exists() and not path.is_file()
    )
    if invalid_outputs:
        raise RuntimeError(
            f"existing release outputs must be regular files: invalid={invalid_outputs}"
        )


def _atomic_write_outputs(outputs: list[tuple[Path, bytes]]) -> None:
    temporary: list[tuple[Path, Path]] = []
    try:
        for destination, payload in outputs:
            destination.parent.mkdir(parents=True, exist_ok=True)
            descriptor, raw_temp = tempfile.mkstemp(
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
            )
            temp_path = Path(raw_temp)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.append((temp_path, destination))
        for temp_path, destination in temporary:
            temp_path.replace(destination)
    finally:
        for temp_path, _destination in temporary:
            try:
                temp_path.unlink()
            except FileNotFoundError:
                pass


def _parse_checksum_manifest(payload: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in payload.splitlines():
        digest, separator, filename = line.partition("  ")
        if (
            separator != "  "
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not filename
            or Path(filename).name != filename
            or "\\" in filename
            or filename in parsed
        ):
            raise RuntimeError("SHA256SUMS contains an invalid or duplicate row")
        parsed[filename] = digest
    return parsed


def verify_bound_release(
    release_dir: Path,
    *,
    actual_toolchain: dict[str, str] | None = None,
) -> dict[str, Any]:
    release_dir = _resolved(release_dir)
    receipt_path = release_dir / RECEIPT_NAME
    checksums_path = release_dir / CHECKSUMS_NAME
    if not receipt_path.is_file() or not checksums_path.is_file():
        raise RuntimeError("release directory is missing its receipt or SHA256SUMS")
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    if not isinstance(receipt, dict) or receipt.get("schema") != RECEIPT_SCHEMA:
        raise RuntimeError("release distribution receipt has an unsupported schema")
    # Download verification is intentionally independent of the local build
    # environment. Supplying an explicit toolchain remains useful to callers
    # that want an additional environment assertion, but the CLI verify path
    # never imports or requires the build, wheel, or twine distributions.
    if actual_toolchain is not None:
        require_canonical_toolchain(actual_toolchain)
    if receipt.get("distribution_build_toolchain") != CANONICAL_TOOLCHAIN:
        raise RuntimeError(
            "release receipt does not name the canonical build toolchain"
        )
    reproducibility = receipt.get("reproducibility")
    if reproducibility != {"independent_build_count": 2, "byte_identical": True}:
        raise RuntimeError(
            "release receipt does not attest two byte-identical canonical builds"
        )

    artifact_rows = receipt.get("artifacts")
    if not isinstance(artifact_rows, list) or len(artifact_rows) != 3:
        raise RuntimeError("release receipt must bind exactly three artifacts")
    by_kind: dict[str, Path] = {}
    expected_checksums: dict[str, str] = {}
    for row in artifact_rows:
        if not isinstance(row, dict):
            raise RuntimeError("release receipt artifact row must be an object")
        kind = str(row.get("kind") or "")
        filename = str(row.get("filename") or "")
        if (
            kind not in {"source_zip", "wheel", "sdist"}
            or kind in by_kind
            or Path(filename).name != filename
            or "\\" in filename
        ):
            raise RuntimeError("release receipt contains an invalid artifact identity")
        path = release_dir / filename
        if not path.is_file():
            raise RuntimeError(f"release receipt artifact is missing: {filename}")
        payload = path.read_bytes()
        digest = _sha256(payload)
        if digest != row.get("sha256") or len(payload) != row.get("size_bytes"):
            raise RuntimeError(
                f"release receipt artifact bytes do not match: {filename}"
            )
        by_kind[kind] = path
        expected_checksums[filename] = digest

    receipt_digest = _sha256(receipt_path.read_bytes())
    expected_checksums[receipt_path.name] = receipt_digest
    manifest = _parse_checksum_manifest(checksums_path.read_text(encoding="utf-8"))
    if manifest != expected_checksums:
        raise RuntimeError(
            "SHA256SUMS does not exactly bind the receipt and release artifacts"
        )
    expected_directory_entries = {*expected_checksums, checksums_path.name}
    actual_directory_entries = {entry.name for entry in release_dir.iterdir()}
    if actual_directory_entries != expected_directory_entries:
        extras = sorted(actual_directory_entries - expected_directory_entries)
        missing = sorted(expected_directory_entries - actual_directory_entries)
        raise RuntimeError(
            "release directory contains unbound or missing entries: "
            f"extras={extras}, missing={missing}"
        )

    source_provenance, provenance, canonical_package = _read_source_provenance(
        by_kind["source_zip"]
    )
    version = str(provenance.get("version") or "")
    wheel_provenance, wheel_generator, wheel_package, wheel_record = (
        _read_wheel_provenance(by_kind["wheel"], version=version)
    )
    require_canonical_wheel_generator(wheel_generator)
    sdist_provenance, sdist_package = _read_sdist_provenance(
        by_kind["sdist"], version=version
    )
    if wheel_provenance != source_provenance or sdist_provenance != source_provenance:
        raise RuntimeError("downloaded distributions do not match source provenance")
    _assert_package_correspondence(
        canonical_package,
        wheel_package,
        artifact_label="wheel",
    )
    _assert_package_correspondence(
        canonical_package,
        sdist_package,
        artifact_label="sdist",
    )
    expected_content_bindings = _content_bindings(
        canonical_package=canonical_package,
        wheel_package=wheel_package,
        sdist_package=sdist_package,
        wheel_record=wheel_record,
        source_provenance=source_provenance,
    )
    if receipt.get("content_manifests") != expected_content_bindings:
        raise RuntimeError(
            "release receipt content manifests do not match release artifacts"
        )
    expected_source_build_verification = _source_build_verification_descriptor(
        source_zip=by_kind["source_zip"],
        wheel_path=by_kind["wheel"],
        sdist_path=by_kind["sdist"],
    )
    if receipt.get("source_build_verification") != expected_source_build_verification:
        raise RuntimeError(
            "release receipt does not bind canonical source rebuild verification"
        )
    if receipt.get("source_provenance_sha256") != _sha256(source_provenance):
        raise RuntimeError("release receipt source provenance hash does not match")
    if receipt.get("wheel_generator") != wheel_generator:
        raise RuntimeError("release receipt wheel generator does not match the wheel")
    if (
        provenance.get("distribution_build_toolchain") != CANONICAL_TOOLCHAIN
        or receipt.get("package") != EXPECTED_DISTRIBUTION_NAME
        or receipt.get("source_package") != provenance.get("package")
        or receipt.get("version") != version
        or receipt.get("git_commit") != provenance.get("git_commit")
        or receipt.get("source_date_epoch") != provenance.get("source_date_epoch")
    ):
        raise RuntimeError("release receipt identity does not match source provenance")
    return receipt


def finalize_distributions(
    *,
    source_zip: Path,
    wheel_path: Path,
    sdist_path: Path,
    comparison_dir: Path,
    receipt_out: Path,
    checksums_out: Path,
    actual_toolchain: dict[str, str] | None = None,
) -> dict[str, Any]:
    source_zip = _resolved(source_zip)
    wheel_path = _resolved(wheel_path)
    sdist_path = _resolved(sdist_path)
    comparison_dir = _resolved(comparison_dir)
    receipt_out = _resolved(receipt_out)
    checksums_out = _resolved(checksums_out)
    _assert_distinct_release_paths(
        source_zip=source_zip,
        wheel_path=wheel_path,
        sdist_path=sdist_path,
        comparison_dir=comparison_dir,
        receipt_out=receipt_out,
        checksums_out=checksums_out,
    )
    _require_canonical_output_names(
        receipt_out=receipt_out,
        checksums_out=checksums_out,
    )
    _require_closed_release_directory(
        source_zip=source_zip,
        wheel_path=wheel_path,
        sdist_path=sdist_path,
        receipt_out=receipt_out,
        checksums_out=checksums_out,
    )
    for artifact in (source_zip, wheel_path, sdist_path):
        if not artifact.is_file():
            raise RuntimeError(f"release artifact does not exist: {artifact}")
    if not comparison_dir.is_dir():
        raise RuntimeError(
            f"independent build directory does not exist: {comparison_dir}"
        )

    toolchain = require_canonical_toolchain(actual_toolchain)
    source_provenance, provenance, canonical_package = _read_source_provenance(
        source_zip
    )
    version = str(provenance.get("version") or "")
    wheel_provenance, wheel_generator, wheel_package, wheel_record = (
        _read_wheel_provenance(wheel_path, version=version)
    )
    sdist_provenance, sdist_package = _read_sdist_provenance(
        sdist_path, version=version
    )
    if wheel_provenance != source_provenance or sdist_provenance != source_provenance:
        raise RuntimeError(
            "wheel or sdist provenance does not match the canonical source ZIP"
        )
    if provenance.get("distribution_build_toolchain") != CANONICAL_TOOLCHAIN:
        raise RuntimeError(
            "source provenance does not name the canonical distribution toolchain"
        )
    require_canonical_wheel_generator(wheel_generator)
    _assert_package_correspondence(
        canonical_package,
        wheel_package,
        artifact_label="wheel",
    )
    _assert_package_correspondence(
        canonical_package,
        sdist_package,
        artifact_label="sdist",
    )
    content_manifests = _content_bindings(
        canonical_package=canonical_package,
        wheel_package=wheel_package,
        sdist_package=sdist_package,
        wheel_record=wheel_record,
        source_provenance=source_provenance,
    )

    _assert_reproducible(wheel_path, comparison_dir)
    _assert_reproducible(sdist_path, comparison_dir)
    source_build_verification = _rebuild_and_verify_from_source(
        source_zip=source_zip,
        wheel_path=wheel_path,
        sdist_path=sdist_path,
        version=version,
        source_date_epoch=int(provenance["source_date_epoch"]),
    )
    artifacts = [
        _artifact_row("source_zip", source_zip),
        _artifact_row("wheel", wheel_path),
        _artifact_row("sdist", sdist_path),
    ]
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "package": EXPECTED_DISTRIBUTION_NAME,
        "source_package": provenance.get("package"),
        "version": version,
        "git_commit": provenance.get("git_commit"),
        "source_date_epoch": provenance.get("source_date_epoch"),
        "source_provenance_sha256": _sha256(source_provenance),
        "distribution_build_toolchain": toolchain,
        "wheel_generator": wheel_generator,
        "content_manifests": content_manifests,
        "source_build_verification": source_build_verification,
        "reproducibility": {
            "independent_build_count": 2,
            "byte_identical": True,
        },
        "artifacts": artifacts,
    }

    receipt_bytes = _stable_json_bytes(receipt)
    checksum_rows = [f"{row['sha256']}  {row['filename']}" for row in artifacts]
    checksum_rows.append(f"{_sha256(receipt_bytes)}  {receipt_out.name}")
    checksums_bytes = ("\n".join(checksum_rows) + "\n").encode("utf-8")
    _atomic_write_outputs(
        [(receipt_out, receipt_bytes), (checksums_out, checksums_bytes)]
    )
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify and bind canonical Epic Continuum wheel/sdist release artifacts."
    )
    parser.add_argument("--verify-directory", type=Path)
    parser.add_argument("--source-zip", type=Path)
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--sdist", type=Path)
    parser.add_argument("--comparison-dir", type=Path)
    parser.add_argument("--receipt-out", type=Path)
    parser.add_argument("--checksums-out", type=Path)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    finalization_values = {
        "source_zip": args.source_zip,
        "wheel": args.wheel,
        "sdist": args.sdist,
        "comparison_dir": args.comparison_dir,
        "receipt_out": args.receipt_out,
        "checksums_out": args.checksums_out,
    }
    if args.verify_directory is not None:
        if any(value is not None for value in finalization_values.values()):
            parser.error(
                "--verify-directory cannot be combined with finalization arguments"
            )
        receipt = verify_bound_release(args.verify_directory)
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    missing = [name for name, value in finalization_values.items() if value is None]
    if missing:
        parser.error(
            "finalization requires: "
            + ", ".join(f"--{name.replace('_', '-')}" for name in missing)
        )
    assert args.source_zip is not None
    assert args.wheel is not None
    assert args.sdist is not None
    assert args.comparison_dir is not None
    assert args.receipt_out is not None
    assert args.checksums_out is not None
    receipt = finalize_distributions(
        source_zip=args.source_zip.resolve(),
        wheel_path=args.wheel.resolve(),
        sdist_path=args.sdist.resolve(),
        comparison_dir=args.comparison_dir.resolve(),
        receipt_out=args.receipt_out.resolve(),
        checksums_out=args.checksums_out.resolve(),
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
