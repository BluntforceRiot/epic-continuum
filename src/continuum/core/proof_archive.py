from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
import sys
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

from .operations import (
    OPERATION_SCHEMA,
    PROOF_ARTIFACT_MUTATION_LOCK_OPERATION_ID,
    PROOF_PACK_SCHEMA,
    operation_event_paths,
    operation_lock,
    operation_paths,
    verify_operation_event_log,
)
from .permissions import fsync_parent, secure_append_text, secure_file, secure_mkdir, secure_write_text
from .store import connect_existing, utc_now
from .writer_claim import ensure_writer_claim


ARCHIVE_MANIFEST_SCHEMA = "epic_continuum.proof_archive.v1"
ARCHIVE_PLAN_SCHEMA = "epic_continuum.proof_archive_plan.v1"
RELOCATION_SCHEMA = "epic_continuum.proof_artifact_relocation.v1"
ARCHIVE_LOCATOR_SCHEMA = "epic_continuum.proof_archive_locator.v1"
ARCHIVE_MANIFEST_NAME = "archive.manifest.json"
RELOCATION_LEDGER_NAME = "relocations.jsonl"
ARCHIVE_LOCATOR_RELATIVE_PATH = Path("config/proof-archive.json")
ARCHIVE_OBJECT_PREFIX = PurePosixPath("objects/sha256")
_ARCHIVE_LOCK_OPERATION_ID = PROOF_ARTIFACT_MUTATION_LOCK_OPERATION_ID
_DARWIN_SYSTEM_SYMLINK_ALIASES = {
    "/tmp": "private/tmp",
    "/var": "private/var",
}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_OPERATION_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_CATALOG_SNAPSHOT_NAME = "catalog.snapshot.sqlite3"
_SOURCE_QUARANTINE_PREFIX = f".{_CATALOG_SNAPSHOT_NAME}.archive-quarantine-"
_UUID_HEX_RE = re.compile(r"^[0-9a-f]{32}$")
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
_RELOCATION_KEYS = {
    "schema",
    "sequence",
    "action",
    "recorded_at",
    "root_binding",
    "source_uri",
    "archive_uri",
    "sha256",
    "size_bytes",
    "previous_record_hash",
    "record_hash",
}
_MANIFEST_KEYS = {"schema", "created_at", "root_binding", "object_layout"}
_LOCATOR_KEYS = {
    "schema",
    "created_at",
    "root_binding",
    "archive_root",
    "archive_manifest_sha256",
}


class ProofArchiveError(ValueError):
    """Base class for fail-closed proof archive errors."""


class RelocationLedgerError(ProofArchiveError):
    """The relocation ledger or archive binding is malformed or tampered."""


class RelocatedArtifactIntegrityError(ProofArchiveError):
    """A source or external archive object does not match its recorded identity."""


def _link_like_reason(path: Path) -> str | None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ProofArchiveError(f"unable to inspect path component: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        return "symlink"
    is_junction = getattr(path, "is_junction", None)
    try:
        if callable(is_junction) and is_junction():
            return "junction"
    except OSError as exc:
        raise ProofArchiveError(f"unable to inspect junction state: {path}") from exc
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    if reparse_flag and attributes & reparse_flag:
        return "reparse_point"
    return None


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _allowed_platform_symlink(path: Path, reason: str) -> bool:
    """Allow only the two fixed macOS compatibility aliases."""
    if reason != "symlink" or sys.platform != "darwin":
        return False
    expected_link = _DARWIN_SYSTEM_SYMLINK_ALIASES.get(path.as_posix())
    if expected_link is None:
        return False
    try:
        if os.readlink(path) != expected_link:
            return False
        for physical_directory in (Path("/private"), Path("/") / expected_link):
            if not stat.S_ISDIR(os.lstat(physical_directory).st_mode):
                return False
        return True
    except OSError:
        return False


def _assert_no_link_components(path: Path) -> Path:
    """Reject every existing symlink, junction, or reparse point in a path."""
    absolute = _lexical_absolute(path)
    current = Path(absolute.anchor)
    parts = absolute.parts[1:] if absolute.anchor else absolute.parts
    for part in parts:
        current /= part
        reason = _link_like_reason(current)
        if reason and not _allowed_platform_symlink(current, reason):
            raise ProofArchiveError(f"refusing {reason} traversal: {current}")
    return absolute


def _canonical_root(root: Path) -> Path:
    absolute = _assert_no_link_components(root)
    if not absolute.exists() or not absolute.is_dir():
        raise ProofArchiveError(f"Continuum root must be an existing directory: {absolute}")
    return absolute.resolve(strict=True)


def _paths_overlap(left: Path, right: Path) -> bool:
    try:
        common = os.path.commonpath((os.path.normcase(str(left)), os.path.normcase(str(right))))
    except ValueError:
        return False
    left_text = os.path.normcase(str(left))
    right_text = os.path.normcase(str(right))
    return common in {left_text, right_text}


def _validated_roots(root: Path, archive_root: Path) -> tuple[Path, Path]:
    canonical_root = _canonical_root(root)
    absolute_archive = _assert_no_link_components(archive_root).resolve(strict=False)
    if _paths_overlap(canonical_root, absolute_archive):
        raise ProofArchiveError("external proof archive must not overlap the Continuum root")
    if absolute_archive.exists() and not absolute_archive.is_dir():
        raise ProofArchiveError(f"external proof archive must be a directory: {absolute_archive}")
    return canonical_root, absolute_archive


def _root_binding(root: Path) -> str:
    canonical = os.path.normcase(str(root.resolve(strict=True)))
    return hashlib.sha256(canonical.encode("utf-8", errors="strict")).hexdigest()


def _require_sha256(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ProofArchiveError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _require_positive_size(value: object, *, field: str = "size_bytes") -> int:
    if type(value) is not int or value <= 0:
        raise ProofArchiveError(f"{field} must be a positive integer")
    return value


def _portable_operation_component(value: str) -> bool:
    stem = value.split(".", 1)[0].upper()
    return bool(
        _OPERATION_COMPONENT_RE.fullmatch(value)
        and value not in {".", ".."}
        and not value.endswith(".")
        and stem not in _WINDOWS_RESERVED_NAMES
    )


def _source_uri(value: object) -> str:
    if not isinstance(value, (str, Path)):
        raise ProofArchiveError("source_uri must be a root-relative proof path")
    text = str(value)
    if "\\" in text or Path(text).is_absolute():
        raise ProofArchiveError("source_uri must use root-relative POSIX separators")
    path = PurePosixPath(text)
    if (
        len(path.parts) != 4
        or path.parts[:2] != ("exports", "proof_artifacts")
        or not _portable_operation_component(path.parts[2])
        or path.parts[3] != "catalog.snapshot.sqlite3"
    ):
        raise ProofArchiveError("source_uri must identify one legacy catalog proof snapshot")
    return path.as_posix()


def _object_uri(sha256: str) -> str:
    digest = _require_sha256(sha256, field="sha256")
    return (ARCHIVE_OBJECT_PREFIX / digest[:2] / f"{digest}.sqlite3").as_posix()


def _archive_object_path(archive_root: Path, archive_uri: str) -> Path:
    uri = PurePosixPath(archive_uri)
    if uri.is_absolute() or ".." in uri.parts:
        raise RelocationLedgerError("archive_uri must be a safe relative path")
    path = _assert_no_link_components(archive_root.joinpath(*uri.parts))
    try:
        path.relative_to(archive_root)
    except ValueError as exc:
        raise RelocationLedgerError("archive_uri escapes the external archive") from exc
    return path


def _canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _record_hash(payload: dict[str, Any]) -> str:
    material = {key: value for key, value in payload.items() if key != "record_hash"}
    return hashlib.sha256(_canonical_json(material).encode("utf-8")).hexdigest()


def _manifest_path(archive_root: Path) -> Path:
    return archive_root / ARCHIVE_MANIFEST_NAME


def _ledger_path(archive_root: Path) -> Path:
    return archive_root / RELOCATION_LEDGER_NAME


def _validate_manifest(payload: object, *, expected_root_binding: str) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != _MANIFEST_KEYS:
        raise RelocationLedgerError("proof archive manifest has an invalid shape")
    if payload.get("schema") != ARCHIVE_MANIFEST_SCHEMA:
        raise RelocationLedgerError("proof archive manifest schema mismatch")
    if payload.get("object_layout") != "content_addressed_sha256_v1":
        raise RelocationLedgerError("proof archive object layout mismatch")
    binding = payload.get("root_binding")
    try:
        _require_sha256(binding, field="root_binding")
    except ProofArchiveError as exc:
        raise RelocationLedgerError(str(exc)) from exc
    if binding != expected_root_binding:
        raise RelocationLedgerError("proof archive belongs to a different Continuum root")
    if not isinstance(payload.get("created_at"), str) or not payload["created_at"]:
        raise RelocationLedgerError("proof archive manifest created_at is invalid")
    return payload


def _load_manifest(archive_root: Path, *, expected_root_binding: str) -> dict[str, Any] | None:
    path = _manifest_path(archive_root)
    if not path.exists():
        return None
    if _link_like_reason(path):
        raise RelocationLedgerError("proof archive manifest must not be link-like")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RelocationLedgerError("proof archive manifest is unreadable or malformed") from exc
    return _validate_manifest(payload, expected_root_binding=expected_root_binding)


def _ensure_archive(archive_root: Path, *, root_binding: str) -> dict[str, Any]:
    secure_mkdir(archive_root)
    _assert_no_link_components(archive_root)
    existing = _load_manifest(archive_root, expected_root_binding=root_binding)
    if existing is not None:
        return existing
    unexpected = [path for path in archive_root.iterdir() if path.name != ARCHIVE_MANIFEST_NAME]
    if unexpected:
        raise RelocationLedgerError("refusing to initialize a non-empty unbound proof archive")
    payload = {
        "schema": ARCHIVE_MANIFEST_SCHEMA,
        "created_at": utc_now(),
        "root_binding": root_binding,
        "object_layout": "content_addressed_sha256_v1",
    }
    secure_write_text(_manifest_path(archive_root), json.dumps(payload, indent=2, sort_keys=True) + "\n")
    loaded = _load_manifest(archive_root, expected_root_binding=root_binding)
    if loaded is None:
        raise RelocationLedgerError("proof archive manifest creation was not durable")
    return loaded


def _locator_path(root: Path) -> Path:
    return root / ARCHIVE_LOCATOR_RELATIVE_PATH


def _archive_manifest_identity(archive_root: Path) -> tuple[str, int]:
    manifest_path = _manifest_path(archive_root)
    digest, size_bytes, _ = _hash_regular_file(manifest_path)
    if size_bytes <= 0:
        raise RelocationLedgerError("proof archive manifest must not be empty")
    return digest, size_bytes


def _validate_locator(root: Path, payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != _LOCATOR_KEYS:
        raise RelocationLedgerError("proof archive locator has an invalid shape")
    if payload.get("schema") != ARCHIVE_LOCATOR_SCHEMA:
        raise RelocationLedgerError("proof archive locator schema mismatch")
    if not isinstance(payload.get("created_at"), str) or not payload["created_at"]:
        raise RelocationLedgerError("proof archive locator created_at is invalid")
    expected_binding = _root_binding(root)
    if payload.get("root_binding") != expected_binding:
        raise RelocationLedgerError("proof archive locator root binding mismatch")
    try:
        _require_sha256(payload.get("root_binding"), field="root_binding")
        expected_manifest_hash = _require_sha256(
            payload.get("archive_manifest_sha256"),
            field="archive_manifest_sha256",
        )
    except ProofArchiveError as exc:
        raise RelocationLedgerError(str(exc)) from exc
    archive_value = payload.get("archive_root")
    if not isinstance(archive_value, str) or not archive_value or not Path(archive_value).is_absolute():
        raise RelocationLedgerError("proof archive locator archive_root must be an absolute path")
    _, archive_root = _validated_roots(root, Path(archive_value))
    if archive_value != str(archive_root):
        raise RelocationLedgerError("proof archive locator archive_root must be canonical")
    if not archive_root.exists():
        raise RelocationLedgerError("configured external proof archive is missing")
    manifest = _load_manifest(archive_root, expected_root_binding=expected_binding)
    if manifest is None:
        raise RelocationLedgerError("configured external proof archive has no manifest")
    actual_manifest_hash, _ = _archive_manifest_identity(archive_root)
    if actual_manifest_hash != expected_manifest_hash:
        raise RelocationLedgerError("proof archive locator manifest hash mismatch")
    return payload


def _load_locator(root: Path) -> dict[str, Any] | None:
    path = _assert_no_link_components(_locator_path(root))
    if not path.exists():
        return None
    try:
        payload = _strict_json(path)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, ProofArchiveError) as exc:
        raise RelocationLedgerError("proof archive locator is unreadable or malformed") from exc
    return _validate_locator(root, payload)


def _requested_archive_matches_locator(root: Path, archive_root: Path) -> None:
    locator = _load_locator(root)
    if locator is not None and locator["archive_root"] != str(archive_root):
        raise RelocationLedgerError("requested proof archive conflicts with the configured archive locator")


def _ensure_locator(root: Path, archive_root: Path, *, root_binding: str) -> dict[str, Any]:
    existing = _load_locator(root)
    if existing is not None:
        if existing["archive_root"] != str(archive_root):
            raise RelocationLedgerError("requested proof archive conflicts with the configured archive locator")
        return existing
    manifest_hash, _ = _archive_manifest_identity(archive_root)
    payload = {
        "schema": ARCHIVE_LOCATOR_SCHEMA,
        "created_at": utc_now(),
        "root_binding": root_binding,
        "archive_root": str(archive_root),
        "archive_manifest_sha256": manifest_hash,
    }
    locator_path = _assert_no_link_components(_locator_path(root))
    secure_write_text(locator_path, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    loaded = _load_locator(root)
    if loaded is None or loaded != payload:
        raise RelocationLedgerError("proof archive locator creation was not durable")
    return loaded


def configured_archive_root(root: Path) -> Path | None:
    """Return the strictly validated external archive configured for a root."""
    canonical_root = _canonical_root(root)
    locator = _load_locator(canonical_root)
    return None if locator is None else Path(str(locator["archive_root"]))


def _validate_relocation_record(
    payload: object,
    *,
    line_number: int,
    expected_sequence: int,
    expected_previous: str | None,
    expected_root_binding: str,
) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != _RELOCATION_KEYS:
        raise RelocationLedgerError(f"relocation ledger line {line_number} has an invalid shape")
    if payload.get("schema") != RELOCATION_SCHEMA:
        raise RelocationLedgerError(f"relocation ledger line {line_number} has the wrong schema")
    if type(payload.get("sequence")) is not int or payload["sequence"] != expected_sequence:
        raise RelocationLedgerError(f"relocation ledger line {line_number} breaks sequence ordering")
    if payload.get("action") not in {"archived", "restored"}:
        raise RelocationLedgerError(f"relocation ledger line {line_number} has an invalid action")
    if not isinstance(payload.get("recorded_at"), str) or not payload["recorded_at"]:
        raise RelocationLedgerError(f"relocation ledger line {line_number} has an invalid timestamp")
    if payload.get("root_binding") != expected_root_binding:
        raise RelocationLedgerError(f"relocation ledger line {line_number} has the wrong root binding")
    try:
        _require_sha256(payload.get("root_binding"), field="root_binding")
        _require_sha256(payload.get("sha256"), field="sha256")
        _require_positive_size(payload.get("size_bytes"))
        source_uri = _source_uri(payload.get("source_uri"))
    except ProofArchiveError as exc:
        raise RelocationLedgerError(f"relocation ledger line {line_number}: {exc}") from exc
    if payload.get("source_uri") != source_uri:
        raise RelocationLedgerError(f"relocation ledger line {line_number} has a non-canonical source_uri")
    if payload.get("archive_uri") != _object_uri(payload["sha256"]):
        raise RelocationLedgerError(f"relocation ledger line {line_number} has a non-canonical archive_uri")
    if payload.get("previous_record_hash") != expected_previous:
        raise RelocationLedgerError(f"relocation ledger line {line_number} breaks the hash chain")
    try:
        _require_sha256(payload.get("record_hash"), field="record_hash")
    except ProofArchiveError as exc:
        raise RelocationLedgerError(f"relocation ledger line {line_number}: {exc}") from exc
    if payload["record_hash"] != _record_hash(payload):
        raise RelocationLedgerError(f"relocation ledger line {line_number} has a record hash mismatch")
    return payload


def _load_verified_ledger(archive_root: Path, *, root_binding: str) -> dict[str, Any]:
    path = _ledger_path(archive_root)
    if not path.exists():
        return {"records": [], "mappings": {}, "last_record_hash": None}
    if _link_like_reason(path):
        raise RelocationLedgerError("relocation ledger must not be link-like")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise RelocationLedgerError("relocation ledger is unreadable") from exc
    records: list[dict[str, Any]] = []
    mappings: dict[str, dict[str, Any]] = {}
    previous: str | None = None
    for line_number, line in enumerate(lines, start=1):
        if not line:
            raise RelocationLedgerError(f"relocation ledger line {line_number} is blank")
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RelocationLedgerError(f"relocation ledger line {line_number} is malformed JSON") from exc
        record = _validate_relocation_record(
            decoded,
            line_number=line_number,
            expected_sequence=line_number,
            expected_previous=previous,
            expected_root_binding=root_binding,
        )
        records.append(record)
        previous = str(record["record_hash"])
        if record["action"] == "archived":
            prior = mappings.get(str(record["source_uri"]))
            if prior is not None and any(
                record[field] != prior[field] for field in ("archive_uri", "sha256", "size_bytes")
            ):
                raise RelocationLedgerError("one source_uri has conflicting archive identities")
            mappings[str(record["source_uri"])] = record
        else:
            prior = mappings.get(str(record["source_uri"]))
            if prior is None or any(
                record[field] != prior[field] for field in ("archive_uri", "sha256", "size_bytes")
            ):
                raise RelocationLedgerError("restore record has no matching archived identity")
    return {"records": records, "mappings": mappings, "last_record_hash": previous}


def verify_relocation_ledger(root: Path, archive_root: Path) -> dict[str, Any]:
    """Verify the archive binding and complete hash-chained relocation ledger.

    Malformed manifests and ledgers raise :class:`RelocationLedgerError`; callers
    must not treat a damaged ledger as an empty archive.
    """
    canonical_root, canonical_archive = _validated_roots(root, archive_root)
    _requested_archive_matches_locator(canonical_root, canonical_archive)
    binding = _root_binding(canonical_root)
    if not canonical_archive.exists():
        return {
            "ok": True,
            "initialized": False,
            "record_count": 0,
            "mapping_count": 0,
            "last_record_hash": None,
        }
    manifest = _load_manifest(canonical_archive, expected_root_binding=binding)
    if manifest is None:
        if any(canonical_archive.iterdir()):
            raise RelocationLedgerError("external archive is non-empty but has no binding manifest")
        return {
            "ok": True,
            "initialized": False,
            "record_count": 0,
            "mapping_count": 0,
            "last_record_hash": None,
        }
    state = _load_verified_ledger(canonical_archive, root_binding=binding)
    return {
        "ok": True,
        "initialized": True,
        "record_count": len(state["records"]),
        "mapping_count": len(state["mappings"]),
        "last_record_hash": state["last_record_hash"],
    }


def _strict_path_absent(path: Path) -> bool:
    """Return true only when ``lstat`` proves that the pathname is absent."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    return False


def _bounded_exception_detail(exc: BaseException, *, limit: int = 400) -> str:
    text = " ".join(str(exc).split())
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return f"{type(exc).__name__}: {text}"


def _note_cleanup_failure(
    primary: BaseException,
    *,
    action: str,
    secondary: BaseException,
) -> None:
    primary.add_note(f"{action} also failed: {_bounded_exception_detail(secondary)}")


def _close_fd_after_error(fd: int, primary: BaseException, *, action: str) -> None:
    try:
        os.close(fd)
    except BaseException as secondary:
        _note_cleanup_failure(primary, action=action, secondary=secondary)


def _descriptor_path_identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        stat.S_IFMT(metadata.st_mode),
        int(metadata.st_size),
    )


def _stable_descriptor_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        *_descriptor_path_identity(metadata),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _hash_open_regular_fd(fd: int, path: Path) -> tuple[str, int, os.stat_result]:
    try:
        initial_metadata = os.fstat(fd)
        if not stat.S_ISREG(initial_metadata.st_mode):
            raise RelocatedArtifactIntegrityError(f"proof artifact is not a regular file: {path}")
        digest = hashlib.sha256()
        read_bytes = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            read_bytes += len(chunk)
        final_metadata = os.fstat(fd)
        if _stable_descriptor_identity(initial_metadata) != _stable_descriptor_identity(final_metadata):
            raise RelocatedArtifactIntegrityError(f"proof artifact changed while it was hashed: {path}")
        if read_bytes != int(final_metadata.st_size):
            raise RelocatedArtifactIntegrityError(f"proof artifact size changed while it was hashed: {path}")
        try:
            path_metadata = os.lstat(path)
        except OSError as exc:
            raise RelocatedArtifactIntegrityError(
                f"proof artifact path changed while it was hashed: {path}"
            ) from exc
        if _descriptor_path_identity(path_metadata) != _descriptor_path_identity(final_metadata):
            raise RelocatedArtifactIntegrityError(
                f"proof artifact path identity changed while it was hashed: {path}"
            )
        return digest.hexdigest(), read_bytes, final_metadata
    except OSError as exc:
        raise RelocatedArtifactIntegrityError(f"unable to hash proof artifact: {path}") from exc


def _open_hashed_regular_file(path: Path) -> tuple[int, str, int, os.stat_result]:
    reason = _link_like_reason(path)
    if reason:
        raise RelocatedArtifactIntegrityError(f"refusing {reason} artifact: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as exc:
        raise RelocatedArtifactIntegrityError(f"unable to open proof artifact: {path}") from exc
    try:
        digest, size_bytes, metadata = _hash_open_regular_fd(fd, path)
        return fd, digest, size_bytes, metadata
    except BaseException as original:
        _close_fd_after_error(fd, original, action="Closing the proof artifact descriptor")
        raise


def _hash_regular_file(path: Path) -> tuple[str, int, os.stat_result]:
    fd, digest, size_bytes, metadata = _open_hashed_regular_file(path)
    try:
        return digest, size_bytes, metadata
    finally:
        os.close(fd)


def _verify_file(path: Path, *, sha256: str, size_bytes: int) -> os.stat_result:
    actual_hash, actual_size, metadata = _hash_regular_file(path)
    if actual_hash != sha256 or actual_size != size_bytes:
        raise RelocatedArtifactIntegrityError(
            f"artifact identity mismatch for {path}: expected {sha256}/{size_bytes}, "
            f"found {actual_hash}/{actual_size}"
        )
    return metadata


def _normalize_catalog_uri(root: Path, value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    candidate = Path(value)
    if candidate.is_absolute():
        try:
            relative = _lexical_absolute(candidate).relative_to(root)
        except ValueError:
            return None
        text = relative.as_posix()
    else:
        text = value.replace("\\", "/")
    try:
        return _source_uri(text)
    except ProofArchiveError:
        return None


def _artifact_references(root: Path) -> dict[str, list[dict[str, Any]]]:
    _assert_no_link_components(root / "catalog" / "catalog.sqlite3")
    conn = connect_existing(root)
    try:
        rows = conn.execute(
            """
            SELECT id, uri, sha256, size_bytes, immutable
            FROM artifacts
            WHERE immutable = 1
            ORDER BY created_at, id
            """
        ).fetchall()
    finally:
        conn.close()
    references: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        uri = _normalize_catalog_uri(root, row["uri"])
        if uri is None:
            continue
        references.setdefault(uri, []).append(
            {
                "id": str(row["id"]),
                "reference_kind": "artifact_ledger",
                "sha256": str(row["sha256"]),
                "size_bytes": int(row["size_bytes"]),
            }
        )
    return references


def _strict_json(path: Path) -> object:
    if _link_like_reason(path):
        raise ProofArchiveError(f"refusing link-like JSON evidence: {path}")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_nonfinite(value: str) -> Any:
        raise ValueError(f"non-finite JSON number: {value}")

    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicates,
        parse_constant=reject_nonfinite,
    )


def _legacy_payload_hash(payload: dict[str, Any], *, hash_field: str) -> str:
    material = {key: value for key, value in payload.items() if key != hash_field}
    encoded = json.dumps(material, ensure_ascii=True, sort_keys=True, default=str)
    return hashlib.sha256(encoded.encode("utf-8", errors="replace")).hexdigest()


def _proof_pack_receipt_binding_valid(root: Path, proof_path: Path, proof: dict[str, Any]) -> bool:
    operation_id = proof.get("operation_id")
    if not isinstance(operation_id, str) or not _portable_operation_component(operation_id):
        return False
    if proof_path.name != f"{operation_id}.json":
        return False
    expected_proof_uri = f"exports/proof_packs/{operation_id}.json"
    if str(proof.get("proof_pack_uri") or "").replace("\\", "/") != expected_proof_uri:
        return False
    expected_receipt_hash = proof.get("operation_receipt_hash")
    if not isinstance(expected_receipt_hash, str) or not _SHA256_RE.fullmatch(expected_receipt_hash):
        return False
    proof_uris = {
        str(item.get("uri") or item.get("path") or "").replace("\\", "/")
        for item in proof.get("paths") or []
        if isinstance(item, dict)
    }
    receipts: list[dict[str, Any]] = []
    receipt_paths = operation_paths(root, operation_id)
    for label, receipt_path in receipt_paths.items():
        expected_uri = (
            f"run/operations/{operation_id}.json"
            if label == "run"
            else f"exports/operation_receipts/{operation_id}.json"
        )
        if expected_uri not in proof_uris:
            return False
        try:
            decoded = _strict_json(receipt_path)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError, ProofArchiveError):
            return False
        if not isinstance(decoded, dict):
            return False
        receipt_hash = decoded.get("receipt_hash")
        if (
            decoded.get("schema") != OPERATION_SCHEMA
            or decoded.get("operation_id") != operation_id
            or receipt_hash != expected_receipt_hash
            or receipt_hash != _legacy_payload_hash(decoded, hash_field="receipt_hash")
            or str(decoded.get("proof_pack_uri") or "").replace("\\", "/") != expected_proof_uri
        ):
            return False
        receipts.append(decoded)
    if receipts[0] != receipts[1]:
        return False

    event_results: list[dict[str, Any]] = []
    for label, event_path in operation_event_paths(root, operation_id).items():
        expected_uri = (
            f"run/operation_events/{operation_id}.jsonl"
            if label == "run"
            else f"exports/operation_events/{operation_id}.jsonl"
        )
        if expected_uri not in proof_uris:
            return False
        try:
            _assert_no_link_components(event_path)
            result = verify_operation_event_log(event_path, operation_id=operation_id)
        except (OSError, ValueError, ProofArchiveError):
            return False
        if not result.get("ok"):
            return False
        event_results.append(result)
    return (
        event_results[0].get("event_count") == event_results[1].get("event_count")
        and event_results[0].get("last_event_hash") == event_results[1].get("last_event_hash")
    )


def _proof_metadata_references(root: Path) -> dict[str, list[dict[str, Any]]]:
    """Return exact legacy bindings corroborated by proof pack, receipts, and event logs."""
    proof_dir = _assert_no_link_components(root / "exports" / "proof_packs")
    references: dict[str, list[dict[str, Any]]] = {}
    if not proof_dir.exists():
        return references
    for proof_path in sorted(proof_dir.glob("*.json"), key=lambda item: item.name):
        try:
            decoded = _strict_json(proof_path)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError, ProofArchiveError):
            continue
        if not isinstance(decoded, dict) or decoded.get("schema") != PROOF_PACK_SCHEMA:
            continue
        stored_proof_hash = decoded.get("proof_pack_hash")
        if (
            not isinstance(stored_proof_hash, str)
            or not _SHA256_RE.fullmatch(stored_proof_hash)
            or stored_proof_hash != _legacy_payload_hash(decoded, hash_field="proof_pack_hash")
            or not _proof_pack_receipt_binding_valid(root, proof_path, decoded)
        ):
            continue
        operation_id = str(decoded["operation_id"])
        try:
            proof_file_sha256, proof_file_size, _ = _hash_regular_file(proof_path)
        except RelocatedArtifactIntegrityError:
            continue
        for item in decoded.get("paths") or []:
            if not isinstance(item, dict) or item.get("uri_base") != "continuum_root":
                continue
            raw_uri = item.get("uri")
            raw_path = item.get("path")
            try:
                uri = _source_uri(raw_uri)
                digest = _require_sha256(item.get("sha256"), field="sha256")
                size_bytes = _require_positive_size(item.get("size_bytes"))
            except ProofArchiveError:
                continue
            if (
                uri.split("/")[2] != operation_id
                or item.get("exists") is not True
                or item.get("kind") != "file"
                or (raw_path is not None and str(raw_path).replace("\\", "/") != uri)
            ):
                continue
            references.setdefault(uri, []).append(
                {
                    "id": f"proof_pack:{proof_path.name}",
                    "reference_kind": "proof_pack",
                    "reference_uri": f"exports/proof_packs/{proof_path.name}",
                    "reference_file_sha256": proof_file_sha256,
                    "reference_file_size_bytes": proof_file_size,
                    "proof_pack_hash": stored_proof_hash,
                    "sha256": digest,
                    "size_bytes": size_bytes,
                }
            )
    return references


def _plan_skip(source_uri: str, reason: str, **details: Any) -> dict[str, Any]:
    return {"source_uri": source_uri, "reason": reason, **details}


def _retained_source_quarantines(
    root: Path,
    proof_root: Path,
    archive_root: Path,
    *,
    mappings: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Describe leftover source quarantines without mutating them.

    The relocation ledger binds a source URI and content identity, but it does
    not durably bind the exact filesystem object moved into a quarantine. A
    later retry therefore reports every leftover quarantine and keeps it for
    explicit resolution instead of deleting a same-content replacement.
    """
    retained: list[dict[str, Any]] = []
    try:
        proof_root_metadata = os.lstat(proof_root)
        proof_root_link_reason = _link_like_reason(proof_root)
    except FileNotFoundError:
        return retained
    except (OSError, ProofArchiveError) as exc:
        return [
            {
                "item_kind": "retained_quarantine_scan_failure",
                "source_uri": "exports/proof_artifacts",
                "quarantine_uri": None,
                "status": "proof_root_inspection_failed",
                "entry_count": 0,
                "entry_bytes": 0,
                "entries": [],
                "error": _bounded_exception_detail(exc),
            }
        ]
    if proof_root_link_reason or not stat.S_ISDIR(proof_root_metadata.st_mode):
        return [
            {
                "item_kind": "retained_quarantine_scan_failure",
                "source_uri": "exports/proof_artifacts",
                "quarantine_uri": None,
                "status": "proof_root_not_physical_directory",
                "entry_count": 0,
                "entry_bytes": 0,
                "entries": [],
            }
        ]
    for operation_dir in sorted(proof_root.iterdir(), key=lambda item: item.name):
        if not _portable_operation_component(operation_dir.name):
            continue
        try:
            operation_metadata = os.lstat(operation_dir)
            operation_link_reason = _link_like_reason(operation_dir)
        except FileNotFoundError:
            continue
        except (OSError, ProofArchiveError) as exc:
            source_uri = _source_uri(
                f"exports/proof_artifacts/{operation_dir.name}/{_CATALOG_SNAPSHOT_NAME}"
            )
            retained.append(
                {
                    "item_kind": "retained_quarantine_scan_failure",
                    "source_uri": source_uri,
                    "quarantine_uri": None,
                    "status": "operation_directory_inspection_failed",
                    "entry_count": 0,
                    "entry_bytes": 0,
                    "entries": [],
                    "error": _bounded_exception_detail(exc),
                }
            )
            continue
        if operation_link_reason:
            source_uri = _source_uri(
                f"exports/proof_artifacts/{operation_dir.name}/{_CATALOG_SNAPSHOT_NAME}"
            )
            retained.append(
                {
                    "item_kind": "retained_quarantine_scan_failure",
                    "source_uri": source_uri,
                    "quarantine_uri": None,
                    "status": f"operation_directory_{operation_link_reason}",
                    "entry_count": 0,
                    "entry_bytes": 0,
                    "entries": [],
                }
            )
            continue
        if not stat.S_ISDIR(operation_metadata.st_mode):
            continue
        source_uri = _source_uri(
            f"exports/proof_artifacts/{operation_dir.name}/{_CATALOG_SNAPSHOT_NAME}"
        )
        try:
            operation_children = sorted(operation_dir.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            retained.append(
                {
                    "item_kind": "retained_quarantine_scan_failure",
                    "source_uri": source_uri,
                    "quarantine_uri": None,
                    "status": "operation_directory_scan_failed",
                    "entry_count": 0,
                    "entry_bytes": 0,
                    "entries": [],
                    "error": _bounded_exception_detail(exc),
                }
            )
            continue
        for quarantine_root in operation_children:
            if not quarantine_root.name.startswith(_SOURCE_QUARANTINE_PREFIX):
                continue
            quarantine_uri = quarantine_root.relative_to(root).as_posix()
            suffix = quarantine_root.name.removeprefix(_SOURCE_QUARANTINE_PREFIX)
            item: dict[str, Any] = {
                "item_kind": "retained_quarantine",
                "source_uri": source_uri,
                "quarantine_uri": quarantine_uri,
                "quarantine_name_status": (
                    "canonical" if _UUID_HEX_RE.fullmatch(suffix) else "noncanonical"
                ),
                "status": "retained_quarantine_requires_exact_object_resolution",
                "entry_count": 0,
                "entry_bytes": 0,
                "entries": [],
            }
            mapping = mappings.get(source_uri)
            if mapping is None:
                item["archive_identity_status"] = "missing_relocation_record"
            else:
                item.update(
                    archive_uri=str(mapping["archive_uri"]),
                    sha256=str(mapping["sha256"]),
                    size_bytes=int(mapping["size_bytes"]),
                )
                try:
                    _verify_file(
                        _archive_object_path(archive_root, str(mapping["archive_uri"])),
                        sha256=str(mapping["sha256"]),
                        size_bytes=int(mapping["size_bytes"]),
                    )
                    item["archive_identity_status"] = "verified_relocation_object"
                except (OSError, ProofArchiveError) as exc:
                    item["archive_identity_status"] = "archive_object_unverified"
                    item["archive_error"] = _bounded_exception_detail(exc)
            try:
                quarantine_metadata = os.lstat(quarantine_root)
                quarantine_link_reason = _link_like_reason(quarantine_root)
            except FileNotFoundError:
                continue
            except (OSError, ProofArchiveError) as exc:
                item["quarantine_path_status"] = "inspection_failed"
                item["error"] = _bounded_exception_detail(exc)
                retained.append(item)
                continue
            if quarantine_link_reason:
                item["quarantine_path_status"] = f"{quarantine_link_reason}_retained"
                retained.append(item)
                continue
            if not stat.S_ISDIR(quarantine_metadata.st_mode):
                item["quarantine_path_status"] = "non_directory_retained"
                retained.append(item)
                continue
            item.update(
                quarantine_path_status="physical_directory_retained",
                quarantine_device=int(quarantine_metadata.st_dev),
                quarantine_inode=int(quarantine_metadata.st_ino),
                quarantine_ctime_ns=int(quarantine_metadata.st_ctime_ns),
            )
            try:
                quarantine_children = sorted(quarantine_root.iterdir(), key=lambda child: child.name)
            except OSError as exc:
                item["quarantine_path_status"] = "directory_read_failed"
                item["error"] = _bounded_exception_detail(exc)
                retained.append(item)
                continue
            entries: list[dict[str, Any]] = []
            entry_bytes = 0
            for child in quarantine_children:
                child_item: dict[str, Any] = {"name": child.name}
                try:
                    child_metadata = os.lstat(child)
                    child_link_reason = _link_like_reason(child)
                except FileNotFoundError:
                    child_item["identity_status"] = "vanished_during_scan"
                    entries.append(child_item)
                    continue
                except (OSError, ProofArchiveError) as exc:
                    child_item["identity_status"] = "inspection_failed"
                    child_item["error"] = _bounded_exception_detail(exc)
                    entries.append(child_item)
                    continue
                if child_link_reason:
                    child_item["identity_status"] = f"{child_link_reason}_retained"
                    entries.append(child_item)
                    continue
                if not stat.S_ISREG(child_metadata.st_mode):
                    child_item["identity_status"] = "non_regular_retained"
                    entries.append(child_item)
                    continue
                try:
                    actual_hash, actual_size, verified_metadata = _hash_regular_file(child)
                except (OSError, ProofArchiveError) as exc:
                    child_item["identity_status"] = "hash_failed"
                    child_item["error"] = _bounded_exception_detail(exc)
                    entries.append(child_item)
                    continue
                entry_bytes += actual_size
                child_item.update(
                    sha256=actual_hash,
                    size_bytes=actual_size,
                    source_device=int(verified_metadata.st_dev),
                    source_inode=int(verified_metadata.st_ino),
                    source_mtime_ns=int(verified_metadata.st_mtime_ns),
                    source_ctime_ns=int(verified_metadata.st_ctime_ns),
                    identity_status=(
                        "matches_relocation_content"
                        if mapping is not None
                        and actual_hash == mapping["sha256"]
                        and actual_size == mapping["size_bytes"]
                        else "does_not_match_relocation_content"
                    ),
                )
                entries.append(child_item)
            item["entries"] = entries
            item["entry_count"] = len(entries)
            item["entry_bytes"] = entry_bytes
            retained.append(item)
    retained.sort(key=lambda item: (str(item["source_uri"]), str(item.get("quarantine_uri") or "")))
    return retained


def plan_legacy_catalog_archive(
    root: Path,
    archive_root: Path,
    *,
    keep_latest: int = 0,
) -> dict[str, Any]:
    """Build a read-only relocation plan for legacy full-catalog proof copies."""
    if type(keep_latest) is not int or keep_latest < 0:
        raise ProofArchiveError("keep_latest must be a non-negative integer")
    canonical_root, canonical_archive = _validated_roots(root, archive_root)
    binding = _root_binding(canonical_root)
    _requested_archive_matches_locator(canonical_root, canonical_archive)
    archive_initialized = False
    ledger_state: dict[str, Any] = {"records": [], "mappings": {}, "last_record_hash": None}
    if canonical_archive.exists():
        manifest = _load_manifest(canonical_archive, expected_root_binding=binding)
        if manifest is None and any(canonical_archive.iterdir()):
            raise RelocationLedgerError("external archive is non-empty but has no binding manifest")
        archive_initialized = manifest is not None
        if archive_initialized:
            ledger_state = _load_verified_ledger(canonical_archive, root_binding=binding)

    references = _artifact_references(canonical_root)
    for uri, proof_references in _proof_metadata_references(canonical_root).items():
        references.setdefault(uri, []).extend(proof_references)
    proof_root = _assert_no_link_components(canonical_root / "exports" / "proof_artifacts")
    items: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    if proof_root.exists():
        for operation_dir in sorted(proof_root.iterdir(), key=lambda item: item.name):
            operation_uri = f"exports/proof_artifacts/{operation_dir.name}/{_CATALOG_SNAPSHOT_NAME}"
            reason = _link_like_reason(operation_dir)
            if reason:
                skipped.append(_plan_skip(operation_uri, f"operation_directory_{reason}"))
                continue
            if not operation_dir.is_dir() or not _portable_operation_component(operation_dir.name):
                continue
            source = operation_dir / _CATALOG_SNAPSHOT_NAME
            try:
                metadata = os.lstat(source)
            except FileNotFoundError:
                continue
            except OSError as exc:
                skipped.append(_plan_skip(operation_uri, "source_stat_failed", error=str(exc)))
                continue
            link_reason = _link_like_reason(source)
            if link_reason:
                skipped.append(_plan_skip(operation_uri, f"source_{link_reason}"))
                continue
            if not stat.S_ISREG(metadata.st_mode):
                skipped.append(_plan_skip(operation_uri, "source_not_regular_file"))
                continue
            if metadata.st_size <= 0:
                skipped.append(_plan_skip(operation_uri, "zero_byte_source"))
                continue
            source_uri = _source_uri(operation_uri)
            source_references = references.get(source_uri, [])
            if not source_references:
                skipped.append(_plan_skip(source_uri, "unreferenced_source"))
                continue
            try:
                actual_hash, actual_size, verified_metadata = _hash_regular_file(source)
            except RelocatedArtifactIntegrityError as exc:
                skipped.append(_plan_skip(source_uri, "source_unreadable", error=str(exc)))
                continue
            identities = {(item["sha256"], item["size_bytes"]) for item in source_references}
            if (actual_hash, actual_size) not in identities:
                skipped.append(
                    _plan_skip(
                        source_uri,
                        "artifact_ledger_mismatch",
                        actual_sha256=actual_hash,
                        actual_size_bytes=actual_size,
                    )
                )
                continue
            if len(identities) != 1:
                skipped.append(_plan_skip(source_uri, "conflicting_artifact_ledger_references"))
                continue
            items.append(
                {
                    "source_uri": source_uri,
                    "archive_uri": _object_uri(actual_hash),
                    "sha256": actual_hash,
                    "size_bytes": actual_size,
                    "source_mtime_ns": int(verified_metadata.st_mtime_ns),
                    "source_ctime_ns": int(verified_metadata.st_ctime_ns),
                    "source_device": int(verified_metadata.st_dev),
                    "source_inode": int(verified_metadata.st_ino),
                    "reference_ids": sorted(
                        item["id"]
                        for item in source_references
                        if item["sha256"] == actual_hash and item["size_bytes"] == actual_size
                    ),
                    "reference_kinds": sorted(
                        {
                            str(item["reference_kind"])
                            for item in source_references
                            if item["sha256"] == actual_hash and item["size_bytes"] == actual_size
                        }
                    ),
                }
            )

    items.sort(key=lambda item: (item["source_mtime_ns"], item["source_uri"]), reverse=True)
    if keep_latest:
        retained, items = items[:keep_latest], items[keep_latest:]
        skipped.extend(
            _plan_skip(item["source_uri"], "keep_latest", sha256=item["sha256"], size_bytes=item["size_bytes"])
            for item in retained
        )
    retained_quarantines = _retained_source_quarantines(
        canonical_root,
        proof_root,
        canonical_archive,
        mappings=ledger_state["mappings"],
    )
    return {
        "schema": ARCHIVE_PLAN_SCHEMA,
        "created_at": utc_now(),
        "root": str(canonical_root),
        "archive_root": str(canonical_archive),
        "archive_initialized": archive_initialized,
        "root_binding": binding,
        "keep_latest": keep_latest,
        "candidate_count": len(items),
        "candidate_bytes": sum(int(item["size_bytes"]) for item in items),
        "retained_quarantine_count": len(retained_quarantines),
        "retained_quarantine_bytes": sum(
            int(item["entry_bytes"]) for item in retained_quarantines
        ),
        "skipped_count": len(skipped),
        "items": items,
        "retained_quarantines": retained_quarantines,
        "skipped": skipped,
    }


def _cleanup_copy_resources(
    *,
    source_fd: int,
    destination_fd: int,
    temporary: Path,
    primary: BaseException | None,
) -> None:
    cleanup_errors: list[tuple[str, BaseException]] = []
    for fd, action in (
        (source_fd, "Closing the proof copy source descriptor"),
        (destination_fd, "Closing the proof copy destination descriptor"),
    ):
        if fd < 0:
            continue
        try:
            os.close(fd)
        except BaseException as secondary:
            if primary is not None:
                _note_cleanup_failure(primary, action=action, secondary=secondary)
            else:
                cleanup_errors.append((action, secondary))
    try:
        temporary.unlink(missing_ok=True)
    except BaseException as secondary:
        if primary is not None:
            _note_cleanup_failure(
                primary,
                action="Removing the temporary proof copy",
                secondary=secondary,
            )
        else:
            cleanup_errors.append(("Removing the temporary proof copy", secondary))
    if primary is None and cleanup_errors:
        first_action, first_error = cleanup_errors[0]
        for action, cleanup_error in cleanup_errors[1:]:
            _note_cleanup_failure(first_error, action=action, secondary=cleanup_error)
        first_error.add_note(f"Cleanup action failed: {first_action}")
        raise first_error


def _copy_verified_file(
    source: Path,
    destination: Path,
    *,
    sha256: str,
    size_bytes: int,
) -> str:
    if not _strict_path_absent(destination):
        _verify_file(destination, sha256=sha256, size_bytes=size_bytes)
        return "reused_verified_destination"
    secure_mkdir(destination.parent)
    _assert_no_link_components(destination)
    temporary = destination.parent / f".{destination.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    flags |= getattr(os, "O_NOFOLLOW", 0)
    destination_fd = os.open(str(temporary), flags, 0o600)
    source_flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        source_flags |= os.O_BINARY
    source_flags |= getattr(os, "O_NOFOLLOW", 0)
    source_flags |= getattr(os, "O_NONBLOCK", 0)
    source_fd = -1
    digest = hashlib.sha256()
    copied = 0
    try:
        source_fd = os.open(str(source), source_flags)
        initial_source_metadata = os.fstat(source_fd)
        if not stat.S_ISREG(initial_source_metadata.st_mode):
            raise RelocatedArtifactIntegrityError(f"copy source is not a regular file: {source}")
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(destination_fd, remaining)
                if written <= 0:
                    raise OSError("proof archive copy made no forward write progress")
                remaining = remaining[written:]
            digest.update(chunk)
            copied += len(chunk)
        final_source_metadata = os.fstat(source_fd)
        if _stable_descriptor_identity(initial_source_metadata) != _stable_descriptor_identity(
            final_source_metadata
        ):
            raise RelocatedArtifactIntegrityError(
                "source changed while it was copied to the proof archive"
            )
        current_source_metadata = os.lstat(source)
        if _descriptor_path_identity(current_source_metadata) != _descriptor_path_identity(
            final_source_metadata
        ):
            raise RelocatedArtifactIntegrityError(
                "source path changed while it was copied to the proof archive"
            )
        os.fsync(destination_fd)
        destination_metadata = os.fstat(destination_fd)
        if not stat.S_ISREG(destination_metadata.st_mode) or int(destination_metadata.st_size) != copied:
            raise RelocatedArtifactIntegrityError(
                "temporary destination changed while copying the proof archive object"
            )
        if digest.hexdigest() != sha256 or copied != size_bytes:
            raise RelocatedArtifactIntegrityError("source changed while it was copied to the proof archive")
        fd_to_close = source_fd
        source_fd = -1
        os.close(fd_to_close)
        fd_to_close = destination_fd
        destination_fd = -1
        os.close(fd_to_close)
        try:
            os.link(temporary, destination)
        except FileExistsError:
            pass
        except OSError as exc:
            if exc.errno not in {errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EXDEV}:
                raise
            reserve_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            reserve_flags |= getattr(os, "O_NOFOLLOW", 0)
            try:
                reserve_fd = os.open(str(destination), reserve_flags, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(reserve_fd)
                os.replace(temporary, destination)
        secure_file(destination)
        fsync_parent(destination)
        _verify_file(destination, sha256=sha256, size_bytes=size_bytes)
    except BaseException as original:
        _cleanup_copy_resources(
            source_fd=source_fd,
            destination_fd=destination_fd,
            temporary=temporary,
            primary=original,
        )
        raise
    _cleanup_copy_resources(
        source_fd=source_fd,
        destination_fd=destination_fd,
        temporary=temporary,
        primary=None,
    )
    return "copied_verified_destination"


def _append_relocation_record(
    archive_root: Path,
    *,
    root_binding: str,
    action: str,
    source_uri: str,
    archive_uri: str,
    sha256: str,
    size_bytes: int,
    state: dict[str, Any],
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "schema": RELOCATION_SCHEMA,
        "sequence": len(state["records"]) + 1,
        "action": action,
        "recorded_at": utc_now(),
        "root_binding": root_binding,
        "source_uri": source_uri,
        "archive_uri": archive_uri,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "previous_record_hash": state["last_record_hash"],
    }
    record["record_hash"] = _record_hash(record)
    secure_append_text(_ledger_path(archive_root), _canonical_json(record) + "\n")
    verified = _load_verified_ledger(archive_root, root_binding=root_binding)
    if verified["last_record_hash"] != record["record_hash"]:
        raise RelocationLedgerError("new relocation record was not durably committed")
    return verified


def _planned_source_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
        stat.S_IFMT(metadata.st_mode),
    )


def _expected_source_identity(expected_identity: dict[str, Any]) -> tuple[int, int, int, int, int, int]:
    return (
        int(expected_identity["source_device"]),
        int(expected_identity["source_inode"]),
        int(expected_identity["size_bytes"]),
        int(expected_identity["source_mtime_ns"]),
        int(expected_identity["source_ctime_ns"]),
        stat.S_IFREG,
    )


def _create_source_quarantine(source: Path) -> tuple[Path, Path]:
    _assert_no_link_components(source.parent)
    for _ in range(32):
        quarantine_root = source.parent / f".{source.name}.archive-quarantine-{uuid.uuid4().hex}"
        try:
            os.mkdir(quarantine_root, 0o700)
        except FileExistsError:
            continue
        except OSError as exc:
            raise RelocatedArtifactIntegrityError(
                f"unable to create source quarantine beside proof artifact: {source}"
            ) from exc
        try:
            quarantine_metadata = os.lstat(quarantine_root)
            if not stat.S_ISDIR(quarantine_metadata.st_mode) or _link_like_reason(quarantine_root):
                raise RelocatedArtifactIntegrityError(
                    f"source quarantine is not a physical directory: {quarantine_root}"
                )
            return quarantine_root, quarantine_root / source.name
        except BaseException:
            try:
                os.rmdir(quarantine_root)
            except OSError:
                pass
            raise
    raise RelocatedArtifactIntegrityError("unable to reserve a unique source quarantine")


def _open_windows_deletable_file(path: Path) -> tuple[int, int]:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    generic_read = 0x80000000
    delete_access = 0x00010000
    # Readers and delete/rename participants may coexist. Writers may not: the
    # verified bytes must remain immutable through the handle disposition.
    share_read_delete = 0x00000001 | 0x00000004
    open_existing = 3
    open_reparse_point = 0x00200000
    handle = kernel32.CreateFileW(
        str(path),
        generic_read | delete_access,
        share_read_delete,
        None,
        open_existing,
        open_reparse_point,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    handle_value = int(handle) if handle is not None else 0
    if handle_value in {0, invalid_handle}:
        raise RelocatedArtifactIntegrityError(
            f"unable to open quarantined proof artifact for identity-bound deletion: {path}"
        ) from ctypes.WinError(ctypes.get_last_error())
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    try:
        fd = msvcrt.open_osfhandle(handle_value, flags)
    except BaseException as original:
        try:
            if not kernel32.CloseHandle(handle):
                raise ctypes.WinError(ctypes.get_last_error())
        except BaseException as secondary:
            _note_cleanup_failure(
                original,
                action="Closing the unconverted Windows proof handle",
                secondary=secondary,
            )
        raise
    return fd, handle_value


def _set_windows_delete_disposition(handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    class FileDispositionInfo(ctypes.Structure):
        _fields_ = [("delete_file", wintypes.BOOLEAN)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
    disposition = FileDispositionInfo(True)
    if not kernel32.SetFileInformationByHandle(
        wintypes.HANDLE(handle),
        4,
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        raise RelocatedArtifactIntegrityError(
            "unable to mark quarantined proof artifact for identity-bound deletion"
        ) from ctypes.WinError(ctypes.get_last_error())


def _open_windows_directory_flush_handle(directory: Path) -> tuple[Any, int]:
    import ctypes
    from ctypes import wintypes

    _assert_no_link_components(directory)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    kernel32.FlushFileBuffers.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    generic_write = 0x40000000
    share_read_write_delete = 0x00000001 | 0x00000002 | 0x00000004
    open_existing = 3
    backup_semantics = 0x02000000
    handle = kernel32.CreateFileW(
        str(directory),
        generic_write,
        share_read_write_delete,
        None,
        open_existing,
        backup_semantics,
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    handle_value = int(getattr(handle, "value", handle) or 0)
    if handle_value in {0, invalid_handle}:
        raise RelocatedArtifactIntegrityError(
            f"unable to open proof source parent for a strict durability flush: {directory}"
        ) from ctypes.WinError(ctypes.get_last_error())
    return kernel32, handle_value


def _flush_windows_directory_handle(kernel32: Any, handle: int, directory: Path) -> None:
    import ctypes
    from ctypes import wintypes

    if not kernel32.FlushFileBuffers(wintypes.HANDLE(handle)):
        raise RelocatedArtifactIntegrityError(
            f"unable to durably flush proof source parent directory: {directory}"
        ) from ctypes.WinError(ctypes.get_last_error())


def _close_windows_directory_flush_handle(kernel32: Any, handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    if not kernel32.CloseHandle(wintypes.HANDLE(handle)):
        raise RelocatedArtifactIntegrityError(
            "unable to close proof source parent durability handle"
        ) from ctypes.WinError(ctypes.get_last_error())


def _flush_windows_directory_strict(directory: Path) -> None:
    kernel32, handle = _open_windows_directory_flush_handle(directory)
    try:
        _flush_windows_directory_handle(kernel32, handle, directory)
    except BaseException as original:
        try:
            _close_windows_directory_flush_handle(kernel32, handle)
        except BaseException as secondary:
            _note_cleanup_failure(
                original,
                action="Closing the proof source parent durability handle",
                secondary=secondary,
            )
        raise
    _close_windows_directory_flush_handle(kernel32, handle)


def _unlink_verified_quarantine(
    quarantine: Path,
    *,
    sha256: str,
    size_bytes: int,
    expected_metadata: os.stat_result,
) -> dict[str, Any]:
    if os.name != "nt":
        raise RelocatedArtifactIntegrityError(
            "identity-bound proof source deletion is unavailable on this platform; "
            f"retained {quarantine}"
        )
    fd, windows_handle = _open_windows_deletable_file(quarantine)
    try:
        actual_hash, actual_size, final_metadata = _hash_open_regular_fd(fd, quarantine)
        if actual_hash != sha256 or actual_size != size_bytes:
            raise RelocatedArtifactIntegrityError(
                "quarantined source content does not match the archived proof artifact"
            )
        if _descriptor_path_identity(final_metadata) != _descriptor_path_identity(expected_metadata):
            raise RelocatedArtifactIntegrityError("quarantined source identity changed before deletion")
        current = os.lstat(quarantine)
        if _descriptor_path_identity(current) != _descriptor_path_identity(final_metadata):
            raise RelocatedArtifactIntegrityError(
                "quarantined source pathname changed immediately before deletion"
            )
        # The disposition applies to the verified file handle itself. A final
        # pathname replacement is retained rather than unlinked.
        _set_windows_delete_disposition(windows_handle)
    except BaseException as original:
        _close_fd_after_error(
            fd,
            original,
            action="Closing the quarantined proof artifact descriptor",
        )
        raise
    try:
        os.close(fd)
    except BaseException:
        # A failed close leaves the handle/disposition completion uncertain.
        # Do not retry the possibly consumed CRT descriptor or report removal.
        raise
    try:
        quarantine_absent = _strict_path_absent(quarantine)
    except Exception as exc:
        return {
            "source_removed": True,
            "quarantine_path_absent": False,
            "error": (
                "unable to verify quarantined pathname after identity-bound deletion: "
                f"{_bounded_exception_detail(exc)}"
            ),
        }
    return {
        "source_removed": True,
        "quarantine_path_absent": quarantine_absent,
        "error": (
            None
            if quarantine_absent
            else "quarantined source pathname was repopulated during identity-bound deletion"
        ),
    }


def _remove_verified_source(
    source: Path,
    *,
    sha256: str,
    size_bytes: int,
    expected_identity: dict[str, Any] | None = None,
) -> dict[str, Any]:
    actual_hash, actual_size, verified_metadata = _hash_regular_file(source)
    if actual_hash != sha256 or actual_size != size_bytes:
        raise RelocatedArtifactIntegrityError(
            "source content changed immediately before removal"
        )
    if expected_identity is not None and _planned_source_identity(
        verified_metadata
    ) != _expected_source_identity(expected_identity):
        raise RelocatedArtifactIntegrityError("source identity changed immediately before removal")
    if os.name != "nt":
        raise RelocatedArtifactIntegrityError(
            "identity-bound proof source deletion is unavailable on this platform; "
            f"source retained: {source}"
        )

    quarantine_root, quarantine = _create_source_quarantine(source)
    moved = False
    try:
        os.rename(source, quarantine)
        moved = True
        _flush_windows_directory_strict(source.parent)
        if not _strict_path_absent(source):
            raise RelocatedArtifactIntegrityError(
                "source pathname remained populated after quarantine rename"
            )
        try:
            disposition = _unlink_verified_quarantine(
                quarantine,
                sha256=sha256,
                size_bytes=size_bytes,
                expected_metadata=verified_metadata,
            )
        except Exception as exc:
            raise RelocatedArtifactIntegrityError(
                f"source retained in quarantine after final verification failed: "
                f"{type(exc).__name__}: {exc}; quarantine={quarantine}"
            ) from exc
        cleanup_errors: list[str] = []
        durability_errors: list[str] = []
        disposition_error = disposition.get("error")
        if disposition_error:
            cleanup_errors.append(str(disposition_error))
        try:
            if not _strict_path_absent(source):
                cleanup_errors.append(
                    "source pathname was repopulated during quarantine deletion"
                )
        except Exception as exc:
            cleanup_errors.append(
                "unable to verify source pathname after disposition: "
                + _bounded_exception_detail(exc)
            )
        try:
            os.rmdir(quarantine_root)
        except Exception as exc:
            cleanup_errors.append(
                "unable to remove empty source quarantine: "
                + _bounded_exception_detail(exc)
            )
        try:
            _flush_windows_directory_strict(source.parent)
        except Exception as exc:
            durability_errors.append(
                "unable to durably commit proof source disposition: "
                + _bounded_exception_detail(exc)
            )
        try:
            if not _strict_path_absent(source):
                cleanup_errors.append(
                    "source pathname was repopulated before archive removal completed"
                )
        except Exception as exc:
            cleanup_errors.append(
                "unable to verify final source pathname state: "
                + _bounded_exception_detail(exc)
            )
        errors = [*cleanup_errors, *durability_errors]
        return {
            "source_removed": bool(disposition["source_removed"]),
            "source_disposition_status": "removed_exact_handle",
            "quarantine_cleanup_status": (
                "cleaned" if not cleanup_errors else "cleanup_failed_or_incomplete"
            ),
            "source_durability_status": (
                "durable" if not durability_errors else "durability_failed_or_incomplete"
            ),
            "ok": bool(disposition["source_removed"])
            and not cleanup_errors
            and not durability_errors,
            "errors": errors,
        }
    finally:
        if not moved:
            try:
                os.rmdir(quarantine_root)
            except OSError:
                pass


def _archive_one(
    root: Path,
    archive_root: Path,
    *,
    root_binding: str,
    item: dict[str, Any],
    state: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    source_uri = _source_uri(item["source_uri"])
    sha256 = _require_sha256(item["sha256"], field="sha256")
    size_bytes = _require_positive_size(item["size_bytes"])
    archive_uri = _object_uri(sha256)
    if item.get("archive_uri") != archive_uri:
        raise ProofArchiveError("archive plan contains a non-canonical archive_uri")
    source = _assert_no_link_components(root.joinpath(*PurePosixPath(source_uri).parts))
    destination = _archive_object_path(archive_root, archive_uri)
    existing = state["mappings"].get(source_uri)
    if existing is not None:
        if any(existing[field] != value for field, value in (("sha256", sha256), ("size_bytes", size_bytes), ("archive_uri", archive_uri))):
            raise RelocationLedgerError(f"existing relocation conflicts with current artifact: {source_uri}")
        copy_status = "reused_recorded_destination"
        record_status = "existing_relocation_record"
    else:
        copy_status = _copy_verified_file(source, destination, sha256=sha256, size_bytes=size_bytes)
        state = _append_relocation_record(
            archive_root,
            root_binding=root_binding,
            action="archived",
            source_uri=source_uri,
            archive_uri=archive_uri,
            sha256=sha256,
            size_bytes=size_bytes,
            state=state,
        )
        record_status = "relocation_record_appended"

    removal: dict[str, Any] = {
        "source_removed": False,
        "source_disposition_status": "retained",
        "quarantine_cleanup_status": "not_started",
        "source_durability_status": "not_started",
        "ok": False,
        "errors": [],
    }
    removal_error: str | None = None
    try:
        _verify_file(destination, sha256=sha256, size_bytes=size_bytes)
    except (OSError, ProofArchiveError) as exc:
        removal_error = (
            "archived destination verification failed before source disposition: "
            + _bounded_exception_detail(exc)
        )
    try:
        source_absent = _strict_path_absent(source)
    except OSError as exc:
        source_absent = False
        source_state_error = (
            "unable to determine proof source disposition: "
            + _bounded_exception_detail(exc)
        )
        removal_error = (
            source_state_error
            if removal_error is None
            else f"{removal_error}; {source_state_error}"
        )
    if source_absent:
        removal = {
            "source_removed": True,
            "source_disposition_status": "already_absent",
            "quarantine_cleanup_status": "not_required",
            "source_durability_status": "not_required",
            "ok": removal_error is None,
            "errors": [],
        }
    elif removal_error is None:
        try:
            removal = _remove_verified_source(
                source,
                sha256=sha256,
                size_bytes=size_bytes,
                expected_identity=item,
            )
        except (OSError, ProofArchiveError) as exc:
            removal_error = str(exc)
    result = {
        "source_uri": source_uri,
        "archive_uri": archive_uri,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "copy_status": copy_status,
        "record_status": record_status,
        "source_removed": bool(removal["source_removed"]),
        "source_disposition_status": removal["source_disposition_status"],
        "quarantine_cleanup_status": removal["quarantine_cleanup_status"],
        "source_durability_status": removal["source_durability_status"],
        "ok": bool(removal["ok"]),
    }
    reported_errors = [str(error) for error in removal.get("errors") or []]
    if removal_error is not None:
        reported_errors.insert(0, removal_error)
    if reported_errors:
        result["error"] = "; ".join(reported_errors)
    return result, state


def _retained_quarantine_result(item: dict[str, Any]) -> dict[str, Any]:
    quarantine_uri = item.get("quarantine_uri")
    location = str(quarantine_uri) if quarantine_uri else str(item["source_uri"])
    result: dict[str, Any] = {
        "result_kind": "retained_quarantine",
        "source_uri": str(item["source_uri"]),
        "quarantine_uri": quarantine_uri,
        "source_removed": False,
        "source_disposition_status": "retained_quarantine_requires_exact_object_resolution",
        "quarantine_cleanup_status": "retained_for_exact_object_resolution",
        "source_durability_status": "not_applicable",
        "entry_count": int(item.get("entry_count", 0)),
        "entry_bytes": int(item.get("entry_bytes", 0)),
        "ok": False,
        "error": (
            "retained source quarantine requires exact-object resolution; retry will not delete "
            f"by pathname or matching content alone: {location}"
        ),
        "quarantine_evidence": item,
    }
    for field in ("archive_uri", "sha256", "size_bytes"):
        if field in item:
            result[field] = item[field]
    return result


def apply_legacy_catalog_archive(
    root: Path,
    archive_root: Path,
    *,
    keep_latest: int = 0,
) -> dict[str, Any]:
    """Relocate eligible catalog proof copies with record-before-remove ordering."""
    canonical_root, canonical_archive = _validated_roots(root, archive_root)
    ensure_writer_claim(canonical_root)
    _assert_no_link_components(canonical_root / "run" / "locks" / "operations")
    with operation_lock(canonical_root, _ARCHIVE_LOCK_OPERATION_ID):
        binding = _root_binding(canonical_root)
        _ensure_archive(canonical_archive, root_binding=binding)
        _ensure_locator(canonical_root, canonical_archive, root_binding=binding)
        state = _load_verified_ledger(canonical_archive, root_binding=binding)
        plan = plan_legacy_catalog_archive(canonical_root, canonical_archive, keep_latest=keep_latest)
        results: list[dict[str, Any]] = []
        for item in plan["items"]:
            result, state = _archive_one(
                canonical_root,
                canonical_archive,
                root_binding=binding,
                item=item,
                state=state,
            )
            results.append(result)
        retained_quarantine_results = [
            _retained_quarantine_result(item) for item in plan["retained_quarantines"]
        ]
        results.extend(retained_quarantine_results)
        return {
            "ok": all(item["ok"] for item in results),
            "dry_run": False,
            "plan": plan,
            "archived_count": sum(1 for item in results if item["source_removed"]),
            "archived_bytes": sum(int(item["size_bytes"]) for item in results if item["source_removed"]),
            "retained_source_count": sum(1 for item in results if not item["source_removed"]),
            "incomplete_cleanup_count": sum(
                1
                for item in results
                if item["source_removed"] and not item["ok"]
            ),
            "unresolved_quarantine_count": len(retained_quarantine_results),
            "results": results,
            "ledger": verify_relocation_ledger(canonical_root, canonical_archive),
        }


def archive_legacy_catalog_snapshots(
    root: Path,
    archive_root: Path,
    *,
    keep_latest: int = 0,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Plan by default, or safely apply, relocation of legacy catalog snapshots."""
    if not isinstance(dry_run, bool):
        raise ProofArchiveError("dry_run must be true or false")
    if dry_run:
        plan = plan_legacy_catalog_archive(root, archive_root, keep_latest=keep_latest)
        return {
            "ok": plan["retained_quarantine_count"] == 0,
            "dry_run": True,
            "plan": plan,
        }
    return apply_legacy_catalog_archive(root, archive_root, keep_latest=keep_latest)


def resolve_relocated_proof(
    root: Path,
    archive_root: Path,
    source_uri: str | Path,
    *,
    expected_sha256: str,
    expected_size_bytes: int,
) -> Path | None:
    """Resolve a missing root-relative proof path to a verified external object."""
    canonical_root, canonical_archive = _validated_roots(root, archive_root)
    _requested_archive_matches_locator(canonical_root, canonical_archive)
    source = _source_uri(source_uri)
    digest = _require_sha256(expected_sha256, field="expected_sha256")
    size = _require_positive_size(expected_size_bytes, field="expected_size_bytes")
    if not canonical_archive.exists():
        return None
    binding = _root_binding(canonical_root)
    manifest = _load_manifest(canonical_archive, expected_root_binding=binding)
    if manifest is None:
        if any(canonical_archive.iterdir()):
            raise RelocationLedgerError("external archive is non-empty but has no binding manifest")
        return None
    state = _load_verified_ledger(canonical_archive, root_binding=binding)
    record = state["mappings"].get(source)
    if record is None:
        return None
    if record["sha256"] != digest or record["size_bytes"] != size:
        return None
    path = _archive_object_path(canonical_archive, str(record["archive_uri"]))
    _verify_file(path, sha256=digest, size_bytes=size)
    return path


def resolve_configured_relocated_proof(
    root: Path,
    source_uri: str | Path,
    *,
    expected_sha256: str,
    expected_size_bytes: int,
) -> Path | None:
    """Resolve relocated proof evidence using the root-internal archive locator."""
    archive_root = configured_archive_root(root)
    if archive_root is None:
        return None
    return resolve_relocated_proof(
        root,
        archive_root,
        source_uri,
        expected_sha256=expected_sha256,
        expected_size_bytes=expected_size_bytes,
    )


def restore_relocated_proof(
    root: Path,
    archive_root: Path,
    source_uri: str | Path,
    *,
    expected_sha256: str,
    expected_size_bytes: int,
) -> dict[str, Any]:
    """Restore one relocated proof file without deleting its external object."""
    canonical_root, canonical_archive = _validated_roots(root, archive_root)
    source = _source_uri(source_uri)
    digest = _require_sha256(expected_sha256, field="expected_sha256")
    size = _require_positive_size(expected_size_bytes, field="expected_size_bytes")
    ensure_writer_claim(canonical_root)
    _assert_no_link_components(canonical_root / "run" / "locks" / "operations")
    with operation_lock(canonical_root, _ARCHIVE_LOCK_OPERATION_ID):
        archive_path = resolve_relocated_proof(
            canonical_root,
            canonical_archive,
            source,
            expected_sha256=digest,
            expected_size_bytes=size,
        )
        if archive_path is None:
            raise RelocatedArtifactIntegrityError("no matching verified external proof artifact was found")
        destination = _assert_no_link_components(canonical_root.joinpath(*PurePosixPath(source).parts))
        if not _strict_path_absent(destination):
            _verify_file(destination, sha256=digest, size_bytes=size)
            return {
                "ok": True,
                "status": "verified_existing_source",
                "source_uri": source,
                "archive_uri": _object_uri(digest),
                "external_retained": True,
            }
        copy_status = _copy_verified_file(archive_path, destination, sha256=digest, size_bytes=size)
        binding = _root_binding(canonical_root)
        state = _load_verified_ledger(canonical_archive, root_binding=binding)
        _append_relocation_record(
            canonical_archive,
            root_binding=binding,
            action="restored",
            source_uri=source,
            archive_uri=_object_uri(digest),
            sha256=digest,
            size_bytes=size,
            state=state,
        )
        _verify_file(archive_path, sha256=digest, size_bytes=size)
        return {
            "ok": True,
            "status": "restored",
            "copy_status": copy_status,
            "source_uri": source,
            "archive_uri": _object_uri(digest),
            "external_retained": True,
        }
