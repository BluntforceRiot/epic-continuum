from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
import zipfile
import zlib
from collections import Counter
from contextlib import nullcontext
from dataclasses import dataclass
from itertools import chain
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, TypeVar

from .config import load_config
from .operations import _verify_artifact_ledger, _verify_recent_proof_packs, verify_root
from .permissions import secure_copy_file, secure_mkdir, secure_sqlite_files
from .safety import redact_text_secrets, redact_value_secrets, scan_text_for_secrets, scan_value_for_secrets
from .store import (
    atomic_write_text_file,
    audit_secrets,
    connect_existing,
    content_hash,
    file_sha256,
    is_initialized,
    sqlite_readonly_uri,
    unique_id,
    utc_now,
)
from .writer_claim import claim_writer, writer_claim_path


BUNDLE_MANIFEST_SCHEMA = "epic_continuum.root_bundle_manifest.v1"
BUNDLE_ROOT_NAME = "epic-continuum-root"
BUNDLE_MANIFEST_NAME = "bundle.manifest.json"
SUPPORTED_BUNDLE_PROFILES = {"portable", "shareable"}
SUPPORTED_SYMLINK_POLICIES = {"fail", "skip"}

# Bundle verification is intentionally stricter than the ZIP format's technical
# maxima.  Continuum's default root-size budget is 50 GB; 64 GiB leaves useful
# headroom without turning a verification request into an unbounded extraction.
# Operators can raise the byte limits deliberately, but never beyond the
# historical 1 TiB hard ceiling.
BUNDLE_ABSOLUTE_MAX_EXPANDED_BYTES = 1024**4
BUNDLE_DEFAULT_MAX_EXPANDED_BYTES = 64 * 1024**3
BUNDLE_DEFAULT_MAX_ENTRIES = 100_000
BUNDLE_ABSOLUTE_MAX_ENTRIES = 1_000_000
BUNDLE_DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES = 256 * 1024**2
BUNDLE_ABSOLUTE_MAX_CENTRAL_DIRECTORY_BYTES = 4 * 1024**3
BUNDLE_DEFAULT_MAX_COMPRESSION_RATIO = 1_000
BUNDLE_ABSOLUTE_MAX_COMPRESSION_RATIO = 1_000_000
BUNDLE_DEFAULT_VERIFY_TIMEOUT_SECONDS = 3_600
BUNDLE_MAX_VERIFY_TIMEOUT_SECONDS = 86_400
BUNDLE_SEMANTIC_TEMP_RESERVE_BYTES = 1024**3
_BUNDLE_IO_CHUNK_BYTES = 1024 * 1024
_BUNDLE_RESERVE_CHECK_BYTES = 64 * 1024**2
_BUNDLE_SEMANTIC_RESULT_MAX_BYTES = 1024 * 1024
_BUNDLE_MANIFEST_MAX_BYTES = 16 * 1024**2
_PORTABLE_METADATA_MAX_FILE_BYTES = 20 * 1024**2
_PORTABLE_METADATA_MAX_STREAM_BYTES = 512 * 1024**2
_PORTABLE_METADATA_MAX_STREAM_RECORDS = 1_000_000
_PORTABLE_METADATA_MAX_ERRORS = 100
_SQLITE_METADATA_MAX_VALUE_BYTES = 20 * 1024**2
_SQLITE_METADATA_MAX_ROW_BYTES = 2 * _SQLITE_METADATA_MAX_VALUE_BYTES + 1024**2
_SQLITE_METADATA_MAX_TABLES = 10_000
_SQLITE_METADATA_MAX_SCHEMA_NAME_BYTES = 1024
_SQLITE_METADATA_MAX_SCHEMA_COLUMNS = 512
_SQLITE_METADATA_MAX_SCAN_GROUPS = 1024
_SQLITE_METADATA_MAX_VALUES_SCANNED = 5_000_000
_SQLITE_METADATA_MAX_ERRORS = 100
_BUNDLE_MAX_RETAINED_ERRORS = 100
_BUNDLE_DIAGNOSTIC_SAMPLE_LIMIT = 20


class _BundleLimitError(RuntimeError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


class _BoundedBundleErrors(list[dict[str, Any]]):
    """Retain first diagnostics plus one counter-bearing truncation marker."""

    def __init__(self, maximum: int = _BUNDLE_MAX_RETAINED_ERRORS) -> None:
        if maximum < 2:
            raise ValueError("maximum retained bundle errors must be at least 2")
        super().__init__()
        self.maximum = maximum
        self.total_count = 0
        self.omitted_count = 0

    @property
    def truncated(self) -> bool:
        return self.omitted_count > 0

    @property
    def retained_original_count(self) -> int:
        return len(self) - (1 if self.truncated else 0)

    def _record_unavailable(self, count: int) -> None:
        if count <= 0:
            return
        had_marker = self.truncated
        self.total_count += count
        self.omitted_count += count
        if not had_marker:
            super().append(
                {
                    "error": "bundle_error_limit_reached",
                    "maximum_retained_errors": self.maximum,
                    "omitted_error_count": self.omitted_count,
                }
            )
            return
        self[-1]["omitted_error_count"] = self.omitted_count

    def append(self, error: dict[str, Any]) -> None:
        if self.retained_original_count < self.maximum - 1:
            self.total_count += 1
            if self.truncated:
                super().insert(len(self) - 1, error)
            else:
                super().append(error)
            return
        self._record_unavailable(1)

    def extend(self, errors: Iterable[dict[str, Any]]) -> None:
        if errors is self:
            raise ValueError("cannot extend bounded bundle errors with itself")
        if isinstance(errors, _BoundedBundleErrors):
            retained = errors[:-1] if errors.truncated else errors[:]
            for error in retained:
                self.append(error)
            self._record_unavailable(errors.total_count - len(retained))
            return
        for error in errors:
            self.append(error)


class _PortableMetadataTooLarge(ValueError):
    pass


class _PortableMetadataStreamLimit(_PortableMetadataTooLarge):
    def __init__(self, code: str, detail: str, *, maximum: int) -> None:
        super().__init__(detail)
        self.code = code
        self.maximum = maximum


@dataclass
class _PortableMetadataLineBudget:
    max_bytes: int
    max_records: int
    bytes_scanned: int = 0
    records_scanned: int = 0

    def consume(self, payload_bytes: int) -> None:
        if self.records_scanned >= self.max_records:
            raise _PortableMetadataStreamLimit(
                "metadata_stream_record_limit_reached",
                f"metadata stream exceeds {self.max_records} records",
                maximum=self.max_records,
            )
        next_bytes = self.bytes_scanned + max(0, int(payload_bytes))
        if next_bytes > self.max_bytes:
            raise _PortableMetadataStreamLimit(
                "metadata_stream_byte_limit_reached",
                f"metadata stream exceeds {self.max_bytes} scanned bytes",
                maximum=self.max_bytes,
            )
        self.records_scanned += 1
        self.bytes_scanned = next_bytes


@dataclass
class _BundleVerificationBudget:
    """One monotonic deadline and byte-work account for a verification pass."""

    deadline: float
    max_work_bytes: int
    work_bytes: int = 0

    def check_deadline(self, phase: str) -> None:
        if time.monotonic() > self.deadline:
            raise _BundleLimitError(
                "bundle_verification_timeout",
                f"bundle verification exceeded its deadline while {phase}",
            )

    def consume(self, count: int, phase: str) -> None:
        self.check_deadline(phase)
        next_total = self.work_bytes + max(0, int(count))
        if next_total > self.max_work_bytes:
            raise _BundleLimitError(
                "bundle_verification_work_limit_exceeded",
                f"bundle verification exceeded its byte-work budget while {phase}",
            )
        self.work_bytes = next_total


@dataclass
class _BundleVerifierResources:
    raw_archive: Any | None = None
    archive: zipfile.ZipFile | None = None

    def close(self) -> None:
        """Best-effort close without masking the verifier's primary outcome."""
        for handle in (self.archive, self.raw_archive):
            if handle is None:
                continue
            try:
                handle.close()
            except Exception:
                pass


def _open_bundle_read_handle(path: Path) -> Any:
    """Open a bundle read-only and deny later write/delete opens on Windows."""
    if os.name != "nt":
        return path.open("rb")

    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        os.path.abspath(path),
        0x80000000,  # GENERIC_READ
        0x00000001,  # FILE_SHARE_READ: deny new write/delete handles
        None,
        3,  # OPEN_EXISTING
        0x08000080,  # FILE_FLAG_SEQUENTIAL_SCAN | FILE_ATTRIBUTE_NORMAL
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if handle == invalid_handle:
        raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    try:
        descriptor = msvcrt.open_osfhandle(int(handle), flags)  # type: ignore[attr-defined]
    except Exception:
        kernel32.CloseHandle(handle)
        raise
    try:
        return os.fdopen(descriptor, "rb", closefd=True)
    except Exception:
        os.close(descriptor)
        raise

# These are process/build leftovers outside the immutable ``archive`` evidence
# namespace. Generic names such as ``build`` or ``*.egg-info`` may legitimately
# occur inside archived source evidence, where filename-based filtering would
# silently corrupt completeness. The live SQLite database is handled separately
# with SQLite's backup API.
_TRANSIENT_PROCESS_PARTS = {".git", ".venv", "__pycache__", ".pytest_cache", "build"}
_TRANSIENT_PREFIXES = (
    PurePosixPath("run/locks"),
    PurePosixPath("run/recovery_drills"),
    PurePosixPath("run/restore_drills"),
)
_TRANSIENT_NAMES = {
    "catalog/catalog.sqlite3-wal",
    "catalog/catalog.sqlite3-shm",
    # A writer claim describes one live host/runtime, not portable root data.
    # Extracted bundles intentionally require an explicit claim before writing.
    "config/writer-claim.json",
    BUNDLE_MANIFEST_NAME,
}


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), default=str)


def _manifest_hash(manifest: dict[str, Any]) -> str:
    material = {key: value for key, value in manifest.items() if key != "manifest_hash"}
    return content_hash(_canonical_json(material))


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except (OSError, ValueError):
        return False


def _is_link_like(path: Path) -> bool:
    """Treat POSIX symlinks and Windows reparse-point links as references."""
    try:
        if path.is_symlink():
            return True
    except OSError:
        pass
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction):
        try:
            if is_junction():
                return True
        except OSError:
            pass
    try:
        stat_result = path.stat(follow_symlinks=False)
    except OSError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(stat_result, "st_file_attributes", 0)
    return bool(reparse_flag and (file_attributes & reparse_flag))


def _safe_rel_text(rel: Path) -> dict[str, Any]:
    raw = rel.as_posix()
    findings = scan_text_for_secrets(raw, max_findings=1)
    safe = redact_text_secrets(raw) if findings else raw
    result: dict[str, Any] = {"path": safe, "path_redacted": safe != raw}
    if safe != raw:
        result["path_hash"] = content_hash(raw)
    return result


def _is_transient(rel: Path) -> bool:
    rel_posix = PurePosixPath(rel.as_posix())
    if rel_posix.as_posix() in _TRANSIENT_NAMES:
        return True
    first_part = rel.parts[0] if rel.parts else ""
    # ``archive`` is the immutable evidence namespace. Names that resemble
    # process debris (``build``, ``*.db-wal``, ``*.pyc``, ``.name.tmp``) can be
    # the exact source evidence a user intentionally retained, so never discard
    # them by filename convention alone.
    if first_part == "archive":
        return False
    if any(part in _TRANSIENT_PROCESS_PARTS or part.endswith(".egg-info") for part in rel.parts):
        return True
    lower_name = rel.name.casefold()
    # SQLite creates process-local sidecars beside any opened database, not only
    # the live catalog. Verification and restore drills may therefore leave
    # WAL/SHM/journal files beside snapshots and frozen proof databases. They
    # are transient recovery state, not portable evidence.
    for sidecar_suffix in ("-wal", "-shm", "-journal"):
        if lower_name.endswith(sidecar_suffix):
            database_name = lower_name[: -len(sidecar_suffix)]
            if database_name.endswith((".sqlite", ".sqlite3", ".db")):
                return True
    if rel.suffix == ".pyc":
        return True
    if rel.name.startswith(".") and rel.name.endswith(".tmp"):
        return True
    return any(rel_posix == prefix or prefix in rel_posix.parents for prefix in _TRANSIENT_PREFIXES)


def _sqlite_backup(source: Path, destination: Path) -> None:
    if _is_link_like(source):
        raise ValueError(
            "refusing to back up a symlink, junction, or reparse-point "
            f"database: {source}"
        )
    source_stat = source.stat(follow_symlinks=False)
    if not stat.S_ISREG(source_stat.st_mode):
        raise ValueError(f"refusing to back up a non-regular database: {source}")
    secure_mkdir(destination.parent)
    source_conn = sqlite3.connect(sqlite_readonly_uri(source, immutable=False), uri=True)
    destination_conn = sqlite3.connect(str(destination))
    try:
        source_conn.backup(destination_conn)
        destination_conn.commit()
    finally:
        destination_conn.close()
        source_conn.close()
    secure_sqlite_files(destination)


def _catalog_database_for_bundle(root: Path) -> Path:
    """Return the live catalog only when its in-root path is a regular file."""
    catalog_dir = root / "catalog"
    source_db = catalog_dir / "catalog.sqlite3"
    if _is_link_like(catalog_dir) or _is_link_like(source_db):
        raise ValueError(
            "bundle catalog/catalog.sqlite3 must be a regular in-root file; "
            "symlinks, junctions, and reparse points are not supported"
        )
    try:
        source_stat = source_db.stat(follow_symlinks=False)
    except FileNotFoundError:
        raise FileNotFoundError(str(source_db)) from None
    if not stat.S_ISREG(source_stat.st_mode):
        raise ValueError(f"bundle catalog database is not a regular file: {source_db}")
    return source_db


def _artifact_row_count(root: Path) -> int:
    conn = connect_existing(root)
    try:
        table = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'artifacts'").fetchone()
        if not table:
            return 0
        return int(conn.execute("SELECT count(*) FROM artifacts WHERE immutable = 1").fetchone()[0])
    finally:
        conn.close()


def _proof_pack_count(root: Path) -> int:
    proof_dir = root / "exports" / "proof_packs"
    return sum(1 for _path in proof_dir.glob("*.json")) if proof_dir.exists() else 0


_WINDOWS_ABSOLUTE_RE = re.compile(r"^[A-Za-z]:|^\\\\")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_METADATA_PATHS = (
    PurePosixPath("config"),
    PurePosixPath("run"),
    PurePosixPath("exports"),
    PurePosixPath("snapshots"),
)
_PATH_KEY_TOKENS = {
    "path",
    "uri",
    "url",
    "root",
    "file",
    "filename",
    "directory",
    "dir",
    "folder",
    "source",
    "target",
    "location",
    "cwd",
    "workspace",
    "repository",
    "repo",
    "home",
    "base",
    "working",
}
_PATH_KEY_COMPOUNDS = {
    "filepath",
    "filename",
    "sourcepath",
    "sourcefile",
    "sourceuri",
    "sourceurl",
    "targetpath",
    "targetfile",
    "targeturi",
    "locationpath",
    "locationuri",
    "rootpath",
    "rootdir",
    "basedir",
    "basepath",
    "homedir",
    "homepath",
    "workdir",
    "workingdir",
    "workingdirectory",
    "workspacepath",
    "workspaceroot",
    "repositorypath",
    "repositoryroot",
    "repopath",
    "reporoot",
    "cwd",
}
_JSON_LIKE_COLUMN_NAMES = {
    "json",
    "metadata",
    "properties",
    "payload",
    "config",
    "details",
    "context",
    "state",
    "data",
    "source_refs",
    "source_metadata",
}
_SQLITE_KEY_COLUMNS = {"key", "name", "field", "property", "attribute", "metadata_key"}
_SQLITE_VALUE_COLUMNS = {
    "value",
    "string_value",
    "text_value",
    "metadata_value",
    "path_value",
    "uri_value",
}
_SQLITE_SUFFIXES = {".sqlite", ".sqlite3", ".db"}
_EMBEDDED_TRACEBACK_PATH_RE = re.compile(
    r"(?i)\bFile\s+[\"\'](?P<path>(?:[A-Z]:[\\\\/]|/|~[/\\\\])[^\"\'\r\n]+)[\"\']"
)
_EMBEDDED_QUOTED_PATH_RE = re.compile(
    r"(?P<quote>[\"\'])(?P<path>(?:file:(?://)?|[A-Za-z]:[\\\\/]|~[/\\\\]|/(?:Users|home|root|tmp|private|var|opt|mnt|Volumes|srv|data|workspace|workspaces|app)(?:/|$))[^\"\'\r\n]*)(?P=quote)",
    re.IGNORECASE,
)
_EMBEDDED_WINDOWS_PATH_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?P<path>[A-Z]:[\\\\/][^\s\"\'<>|\r\n]+)"
)
_PORTABLE_METADATA_MAX_FINDING_FIELD_BYTES = 1024
_PORTABLE_METADATA_MAX_PATH_FIELD_BYTES = 2048
_PORTABLE_METADATA_MAX_REFERENCE_BYTES = 512


def _normalized_key_text(value: str) -> str:
    split = _CAMEL_BOUNDARY_RE.sub("_", str(value))
    return re.sub(r"[^A-Za-z0-9]+", "_", split).strip("_").casefold()


def _is_path_like_key(value: str) -> bool:
    normalized = _normalized_key_text(value)
    if not normalized:
        return False
    tokens = {token for token in normalized.split("_") if token}
    compact = normalized.replace("_", "")
    return bool(tokens & _PATH_KEY_TOKENS) or compact in _PATH_KEY_COMPOUNDS


def _is_json_like_column(value: str) -> bool:
    normalized = _normalized_key_text(value)
    tokens = {token for token in normalized.split("_") if token}
    return normalized.endswith("_json") or "json" in tokens or normalized in _JSON_LIKE_COLUMN_NAMES


def _is_metadata_file(rel: Path) -> bool:
    pure = PurePosixPath(rel.as_posix())
    suffix = rel.suffix.casefold()
    if suffix == ".log":
        integration_logs = PurePosixPath("run/integrations")
        return pure == integration_logs or integration_logs in pure.parents
    if suffix not in {".json", ".jsonl"}:
        return False
    return any(pure == prefix or prefix in pure.parents for prefix in _METADATA_PATHS)


def _looks_nonportable_local_path(value: str) -> bool:
    text = value.strip()
    if not text or "\n" in text or "\r" in text:
        return False
    lowered = text.casefold()
    if lowered.startswith(("http://", "https://", "mempalace://", "external:", "redacted:")):
        return False
    if lowered.startswith(("/proc/", "/sys/", "/dev/")):
        return False
    if lowered.startswith("file:"):
        return True
    normalized = text.replace("\\", "/")
    normalized_lower = normalized.casefold()
    if normalized_lower.startswith(
        (
            "~/", "${home}/", "$home/", "${userprofile}/", "$userprofile/",
            "%userprofile%/", "%homepath%/", "%appdata%/", "%localappdata%/",
        )
    ) or re.match(r"^~[^/]+/", normalized):
        return True
    if normalized.startswith("/") or any(part == ".." for part in PurePosixPath(normalized).parts):
        return True
    return Path(text).is_absolute() or bool(_WINDOWS_ABSOLUTE_RE.match(text))


def _bounded_portable_text(value: object, *, maximum_bytes: int) -> str:
    text = redact_text_secrets(str(value))
    encoded = text.encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return text
    digest = hashlib.sha256(encoded).hexdigest()
    marker = f"...<truncated sha256={digest} bytes={len(encoded)}>"
    marker_bytes = marker.encode("ascii")
    prefix_budget = max(0, maximum_bytes - len(marker_bytes))
    prefix = encoded[:prefix_budget].decode("utf-8", errors="ignore")
    return prefix + marker


def _bounded_metadata_path(value: object) -> str:
    return _bounded_portable_text(
        value,
        maximum_bytes=_PORTABLE_METADATA_MAX_PATH_FIELD_BYTES,
    )


def _bounded_portable_finding(finding: dict[str, Any]) -> dict[str, Any]:
    bounded: dict[str, Any] = {}
    for key, value in finding.items():
        if not isinstance(value, str) or key == "value_hash":
            bounded[key] = value
            continue
        maximum = (
            _PORTABLE_METADATA_MAX_PATH_FIELD_BYTES
            if key == "metadata_path"
            else _PORTABLE_METADATA_MAX_FINDING_FIELD_BYTES
        )
        bounded[key] = _bounded_portable_text(value, maximum_bytes=maximum)
    return bounded


def _embedded_nonportable_paths(
    value: str,
    *,
    max_paths: int,
) -> tuple[list[str], bool]:
    """Extract embedded local paths without expanding beyond ``max_paths``."""

    found: list[str] = []
    seen: set[str] = set()
    for pattern in (
        _EMBEDDED_TRACEBACK_PATH_RE,
        _EMBEDDED_QUOTED_PATH_RE,
        _EMBEDDED_WINDOWS_PATH_RE,
    ):
        for match in pattern.finditer(value):
            if len(found) >= max_paths:
                return found, True
            candidate = match.group("path").strip().rstrip(".,;:)")
            candidate_hash = content_hash(candidate)
            if candidate and _looks_nonportable_local_path(candidate) and candidate_hash not in seen:
                found.append(candidate)
                seen.add(candidate_hash)
    return found, False


def _external_path_reference(value: str) -> str:
    text = value.strip().rstrip("/\\")
    lowered = text.casefold()
    if lowered.startswith("file:"):
        without_query = text.split("?", 1)[0].split("#", 1)[0]
        name = re.split(r"[/\\]", without_query.rstrip("/\\"))[-1]
    elif _WINDOWS_ABSOLUTE_RE.match(text):
        name = re.split(r"[\\/]", text)[-1]
    else:
        name = PurePosixPath(text.replace("\\", "/")).name
    safe_name = redact_text_secrets(name or "path") or "path"
    return _bounded_portable_text(
        f"external:{safe_name}",
        maximum_bytes=_PORTABLE_METADATA_MAX_REFERENCE_BYTES,
    )


def _portable_metadata_findings(
    value: Any,
    *,
    path: str = "$",
    key_hint: str | None = None,
    scan_embedded_paths: bool = False,
    max_findings: int,
) -> tuple[list[dict[str, Any]], bool]:
    """Walk structured metadata without expanding beyond ``max_findings``."""

    findings: list[dict[str, Any]] = []
    if max_findings <= 0:
        return findings, True
    stack: list[tuple[str, Any, str, str | None]] = [
        ("visit", value, _bounded_metadata_path(path), key_hint)
    ]
    while stack:
        if len(findings) >= max_findings:
            return findings, True
        kind, current, current_path, current_hint = stack.pop()
        if kind == "dict_iter":
            try:
                key, nested = next(current)
            except StopIteration:
                continue
            stack.append(("dict_iter", current, current_path, current_hint))
            key_text = str(key)
            if isinstance(key, str) and _looks_nonportable_local_path(key_text):
                findings.append(
                    _bounded_portable_finding(
                        {
                            "metadata_path": f"{current_path}.[path_key]",
                            "value": _external_path_reference(key_text),
                            "value_hash": content_hash(key_text),
                        }
                    )
                )
                nested_path = _bounded_metadata_path(f"{current_path}.[path_key]")
            else:
                safe_key_text = _bounded_portable_text(
                    key_text,
                    maximum_bytes=_PORTABLE_METADATA_MAX_FINDING_FIELD_BYTES,
                )
                nested_path = _bounded_metadata_path(f"{current_path}.{safe_key_text}")
            stack.append(("visit", nested, nested_path, key_text))
            continue
        if kind == "list_iter":
            try:
                index, nested = next(current)
            except StopIteration:
                continue
            stack.append(("list_iter", current, current_path, current_hint))
            stack.append(
                (
                    "visit",
                    nested,
                    _bounded_metadata_path(f"{current_path}[{index}]"),
                    current_hint,
                )
            )
            continue
        if isinstance(current, dict):
            stack.append(("dict_iter", iter(current.items()), current_path, current_hint))
            continue
        if isinstance(current, list):
            stack.append(("list_iter", iter(enumerate(current)), current_path, current_hint))
            continue
        if not isinstance(current, str):
            continue
        seen_hashes: set[str] = set()
        if (
            current_hint
            and _is_path_like_key(current_hint)
            and _looks_nonportable_local_path(current)
        ):
            direct_hash = content_hash(current)
            findings.append(
                _bounded_portable_finding(
                    {
                        "metadata_path": current_path,
                        "value": _external_path_reference(current),
                        "value_hash": direct_hash,
                    }
                )
            )
            seen_hashes.add(direct_hash)
        if scan_embedded_paths and len(findings) < max_findings:
            embedded_paths, embedded_truncated = _embedded_nonportable_paths(
                current,
                max_paths=max_findings - len(findings),
            )
            for embedded in embedded_paths:
                embedded_hash = content_hash(embedded)
                if embedded_hash in seen_hashes:
                    continue
                findings.append(
                    _bounded_portable_finding(
                        {
                            "metadata_path": current_path,
                            "value": _external_path_reference(embedded),
                            "value_hash": embedded_hash,
                            "embedded": True,
                        }
                    )
                )
                seen_hashes.add(embedded_hash)
            if embedded_truncated:
                return findings, True
    return findings, False


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _append_bounded_audit_error(
    errors: list[dict[str, Any]],
    error: dict[str, Any],
    *,
    maximum: int,
    source: str,
) -> bool:
    """Append one error or a single terminal truncation marker."""

    if maximum <= 0 or len(errors) >= maximum:
        return False
    if len(errors) < maximum - 1:
        errors.append(
            {
                key: (
                    _bounded_portable_text(
                        value,
                        maximum_bytes=(
                            _PORTABLE_METADATA_MAX_PATH_FIELD_BYTES
                            if key in {"detail", "file", "metadata_path"}
                            else _PORTABLE_METADATA_MAX_FINDING_FIELD_BYTES
                        ),
                    )
                    if isinstance(value, str)
                    else value
                )
                for key, value in error.items()
            }
        )
        return True
    errors.append(
        {
            "source": source,
            "error": "audit_error_limit_reached",
            "maximum_errors": maximum,
        }
    )
    return False


def _sqlite_rows_for_columns(
    conn: Any,
    table: str,
    columns: list[str],
) -> Any:
    selected = ", ".join(_quote_identifier(column) for column in columns)
    table_name = _quote_identifier(table)
    try:
        return conn.execute(
            f"SELECT rowid AS __continuum_rowid__, {selected} FROM {table_name}"
        )
    except sqlite3.OperationalError:
        return conn.execute(f"SELECT {selected} FROM {table_name}")


def _sqlite_database_paths(root: Path) -> list[Path]:
    """Return durable files that are actually SQLite databases.

    A filename suffix alone is not enough: archived user evidence may legitimately
    end in ``.db`` without being SQLite. Checking the file signature avoids making
    a shareable bundle fail merely because an arbitrary evidence file uses that
    extension.
    """
    databases: list[Path] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if _is_link_like(path) or not path.is_file() or path.suffix.casefold() not in _SQLITE_SUFFIXES:
            continue
        try:
            rel = path.relative_to(root)
            if _is_transient(rel):
                continue
            with path.open("rb") as handle:
                signature = handle.read(16)
        except (OSError, ValueError):
            continue
        if signature == b"SQLite format 3\x00":
            databases.append(path)
    return databases


def _audit_sqlite_portable_metadata(
    root: Path,
    *,
    max_findings: int,
) -> tuple[list[dict[str, Any]], int, list[dict[str, Any]], int]:
    """Scan path-bearing metadata in every durable SQLite database.

    This intentionally avoids scanning arbitrary prose columns. It inspects
    path-like columns, structured JSON columns, and common key/value metadata
    schemas such as Chroma's ``key`` + ``string_value`` layout.
    """
    if max_findings <= 0:
        return [], 0, [], 0

    findings: list[dict[str, Any]] = []
    values_scanned = 0
    errors: list[dict[str, Any]] = []
    databases_scanned = 0

    databases = _sqlite_database_paths(root)
    for database_index, database in enumerate(databases):
        if len(findings) >= max_findings or len(errors) >= _SQLITE_METADATA_MAX_ERRORS:
            break
        if values_scanned >= _SQLITE_METADATA_MAX_VALUES_SCANNED:
            if not any(
                item.get("error") == "sqlite_value_scan_limit_reached"
                for item in errors
            ):
                _append_bounded_audit_error(
                    errors,
                    {
                        "source": "sqlite",
                        "error": "sqlite_value_scan_limit_reached",
                        "maximum_values": _SQLITE_METADATA_MAX_VALUES_SCANNED,
                        "pending_databases": len(databases) - database_index,
                    },
                    maximum=_SQLITE_METADATA_MAX_ERRORS,
                    source="sqlite",
                )
            break
        rel_raw = database.relative_to(root)
        rel = str(_safe_rel_text(rel_raw)["path"])
        try:
            conn = sqlite3.connect(sqlite_readonly_uri(database), uri=True, timeout=2)
        except sqlite3.Error as exc:
            _append_bounded_audit_error(
                errors,
                {
                    "source": "sqlite",
                    "file": rel,
                    "error": "sqlite_open_failed",
                    "detail": redact_text_secrets(str(exc)),
                },
                maximum=_SQLITE_METADATA_MAX_ERRORS,
                source="sqlite",
            )
            continue

        set_limit = getattr(conn, "setlimit", None)
        get_limit = getattr(conn, "getlimit", None)
        length_category = getattr(sqlite3, "SQLITE_LIMIT_LENGTH", None)
        if (
            not callable(set_limit)
            or not callable(get_limit)
            or not isinstance(length_category, int)
        ):
            _append_bounded_audit_error(
                errors,
                {
                    "source": "sqlite",
                    "file": rel,
                    "error": "sqlite_length_limit_unavailable",
                },
                maximum=_SQLITE_METADATA_MAX_ERRORS,
                source="sqlite",
            )
            conn.close()
            continue
        try:
            set_limit(length_category, _SQLITE_METADATA_MAX_ROW_BYTES)
            observed_limit = int(get_limit(length_category))
            if observed_limit > _SQLITE_METADATA_MAX_ROW_BYTES:
                raise ValueError("SQLite length limit was not lowered")
            conn.row_factory = sqlite3.Row
        except Exception as exc:
            _append_bounded_audit_error(
                errors,
                {
                    "source": "sqlite",
                    "file": rel,
                    "error": "sqlite_length_limit_failed",
                    "detail": redact_text_secrets(str(exc)),
                },
                maximum=_SQLITE_METADATA_MAX_ERRORS,
                source="sqlite",
            )
            conn.close()
            continue

        databases_scanned += 1
        try:
            try:
                oversized_name = conn.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
                    "AND length(CAST(name AS BLOB)) > ? LIMIT 1",
                    (_SQLITE_METADATA_MAX_SCHEMA_NAME_BYTES,),
                ).fetchone()
                if oversized_name is not None:
                    _append_bounded_audit_error(
                        errors,
                        {
                            "source": "sqlite",
                            "file": rel,
                            "error": "sqlite_schema_name_too_large",
                            "maximum_bytes": _SQLITE_METADATA_MAX_SCHEMA_NAME_BYTES,
                        },
                        maximum=_SQLITE_METADATA_MAX_ERRORS,
                        source="sqlite",
                    )
                    continue
                table_rows = list(
                    conn.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' "
                        "ORDER BY name LIMIT ?",
                        (_SQLITE_METADATA_MAX_TABLES + 1,),
                    )
                )
                if len(table_rows) > _SQLITE_METADATA_MAX_TABLES:
                    _append_bounded_audit_error(
                        errors,
                        {
                            "source": "sqlite",
                            "file": rel,
                            "error": "sqlite_table_count_too_large",
                            "maximum_tables": _SQLITE_METADATA_MAX_TABLES,
                        },
                        maximum=_SQLITE_METADATA_MAX_ERRORS,
                        source="sqlite",
                    )
                    continue
                tables = [str(row[0]) for row in table_rows]
            except sqlite3.Error as exc:
                _append_bounded_audit_error(
                    errors,
                    {
                        "source": "sqlite",
                        "file": rel,
                        "error": "sqlite_schema_list_failed",
                        "detail": redact_text_secrets(str(exc)),
                    },
                    maximum=_SQLITE_METADATA_MAX_ERRORS,
                    source="sqlite",
                )
                continue

            for table_index, table in enumerate(tables):
                if len(findings) >= max_findings or len(errors) >= _SQLITE_METADATA_MAX_ERRORS:
                    break
                if values_scanned >= _SQLITE_METADATA_MAX_VALUES_SCANNED:
                    if not any(
                        item.get("error") == "sqlite_value_scan_limit_reached"
                        for item in errors
                    ):
                        _append_bounded_audit_error(
                            errors,
                            {
                                "source": "sqlite",
                                "file": rel,
                                "error": "sqlite_value_scan_limit_reached",
                                "maximum_values": _SQLITE_METADATA_MAX_VALUES_SCANNED,
                                "pending_tables": len(tables) - table_index,
                            },
                            maximum=_SQLITE_METADATA_MAX_ERRORS,
                            source="sqlite",
                        )
                    break
                safe_table = _bounded_portable_text(
                    table,
                    maximum_bytes=_PORTABLE_METADATA_MAX_FINDING_FIELD_BYTES,
                )
                try:
                    schema_cursor = conn.execute(f"PRAGMA table_info({_quote_identifier(table)})")
                    schema_rows = schema_cursor.fetchmany(_SQLITE_METADATA_MAX_SCHEMA_COLUMNS + 1)
                except sqlite3.Error as exc:
                    _append_bounded_audit_error(
                        errors,
                        {
                            "source": "sqlite",
                            "file": rel,
                            "sqlite_table": safe_table,
                            "error": "sqlite_schema_read_failed",
                            "detail": redact_text_secrets(str(exc)),
                        },
                        maximum=_SQLITE_METADATA_MAX_ERRORS,
                        source="sqlite",
                    )
                    continue

                if len(schema_rows) > _SQLITE_METADATA_MAX_SCHEMA_COLUMNS:
                    _append_bounded_audit_error(
                        errors,
                        {
                            "source": "sqlite",
                            "file": rel,
                            "sqlite_table": safe_table,
                            "error": "sqlite_schema_column_count_too_large",
                            "maximum_columns": _SQLITE_METADATA_MAX_SCHEMA_COLUMNS,
                        },
                        maximum=_SQLITE_METADATA_MAX_ERRORS,
                        source="sqlite",
                    )
                    continue

                columns = [str(row[1]) for row in schema_rows]
                direct_columns = [column for column in columns if _is_path_like_key(column)]
                json_columns = [column for column in columns if _is_json_like_column(column)]
                key_columns = [
                    column
                    for column in columns
                    if _normalized_key_text(column) in _SQLITE_KEY_COLUMNS
                ]
                value_columns = [
                    column
                    for column in columns
                    if _normalized_key_text(column) in _SQLITE_VALUE_COLUMNS
                ]
                selected = list(
                    dict.fromkeys(
                        [
                            *direct_columns,
                            *json_columns,
                            *key_columns,
                            *(value_columns if key_columns else []),
                        ]
                    )
                )
                if not selected:
                    continue

                single_scan_columns = list(dict.fromkeys([*direct_columns, *json_columns]))
                key_value_pairs = [
                    (key_column, value_column)
                    for key_column in key_columns
                    for value_column in value_columns
                ]
                if (
                    len(single_scan_columns) + len(key_value_pairs)
                    > _SQLITE_METADATA_MAX_SCAN_GROUPS
                ):
                    _append_bounded_audit_error(
                        errors,
                        {
                            "source": "sqlite",
                            "file": rel,
                            "sqlite_table": safe_table,
                            "error": "sqlite_scan_group_count_too_large",
                            "maximum_scan_groups": _SQLITE_METADATA_MAX_SCAN_GROUPS,
                        },
                        maximum=_SQLITE_METADATA_MAX_ERRORS,
                        source="sqlite",
                    )
                    continue

                oversized_value = False
                for column in selected:
                    quoted_column = _quote_identifier(column)
                    oversized_condition = (
                        f"typeof({quoted_column}) IN ('text', 'blob') "
                        f"AND length(CAST({quoted_column} AS BLOB)) > ?"
                    )
                    try:
                        try:
                            oversized_row = conn.execute(
                                f"SELECT rowid FROM {_quote_identifier(table)} "
                                f"WHERE {oversized_condition} LIMIT 1",
                                (_SQLITE_METADATA_MAX_VALUE_BYTES,),
                            ).fetchone()
                        except sqlite3.DataError:
                            raise
                        except sqlite3.Error:
                            oversized_row = conn.execute(
                                f"SELECT 1 FROM {_quote_identifier(table)} "
                                f"WHERE {oversized_condition} LIMIT 1",
                                (_SQLITE_METADATA_MAX_VALUE_BYTES,),
                            ).fetchone()
                    except sqlite3.DataError as exc:
                        _append_bounded_audit_error(
                            errors,
                            {
                                "source": "sqlite",
                                "file": rel,
                                "sqlite_table": safe_table,
                                "sqlite_column": redact_text_secrets(column),
                                "error": "sqlite_value_too_large",
                                "maximum_bytes": _SQLITE_METADATA_MAX_VALUE_BYTES,
                                "detail": redact_text_secrets(str(exc)),
                            },
                            maximum=_SQLITE_METADATA_MAX_ERRORS,
                            source="sqlite",
                        )
                        oversized_value = True
                        break
                    except sqlite3.Error as exc:
                        _append_bounded_audit_error(
                            errors,
                            {
                                "source": "sqlite",
                                "file": rel,
                                "sqlite_table": safe_table,
                                "sqlite_column": redact_text_secrets(column),
                                "error": "sqlite_value_size_probe_failed",
                                "detail": redact_text_secrets(str(exc)),
                            },
                            maximum=_SQLITE_METADATA_MAX_ERRORS,
                            source="sqlite",
                        )
                        oversized_value = True
                        break
                    if oversized_row is not None:
                        _append_bounded_audit_error(
                            errors,
                            {
                                "source": "sqlite",
                                "file": rel,
                                "sqlite_table": safe_table,
                                "sqlite_column": redact_text_secrets(column),
                                "sqlite_rowid": oversized_row[0],
                                "error": "sqlite_value_too_large",
                                "maximum_bytes": _SQLITE_METADATA_MAX_VALUE_BYTES,
                            },
                            maximum=_SQLITE_METADATA_MAX_ERRORS,
                            source="sqlite",
                        )
                        oversized_value = True
                        break
                if oversized_value:
                    continue

                direct_set = set(direct_columns)
                json_set = set(json_columns)
                scan_stopped = False
                for column in single_scan_columns:
                    if len(findings) >= max_findings:
                        break
                    try:
                        rows = _sqlite_rows_for_columns(conn, table, [column])
                        for row_number, row in enumerate(rows, start=1):
                            if len(findings) >= max_findings:
                                break
                            value = row[column]
                            if value is None:
                                continue
                            if values_scanned >= _SQLITE_METADATA_MAX_VALUES_SCANNED:
                                _append_bounded_audit_error(
                                    errors,
                                    {
                                        "source": "sqlite",
                                        "file": rel,
                                        "error": "sqlite_value_scan_limit_reached",
                                        "maximum_values": _SQLITE_METADATA_MAX_VALUES_SCANNED,
                                    },
                                    maximum=_SQLITE_METADATA_MAX_ERRORS,
                                    source="sqlite",
                                )
                                scan_stopped = True
                                break
                            values_scanned += 1
                            row_keys = set(row.keys())
                            row_id = (
                                row["__continuum_rowid__"]
                                if "__continuum_rowid__" in row_keys
                                else row_number
                            )
                            text_value = (
                                value.decode("utf-8", errors="replace")
                                if isinstance(value, bytes)
                                else str(value)
                            )
                            if column in direct_set and _looks_nonportable_local_path(text_value):
                                findings.append(
                                    _bounded_portable_finding(
                                        {
                                            "source": "sqlite",
                                            "file": rel,
                                            "sqlite_table": safe_table,
                                            "sqlite_column": column,
                                            "sqlite_rowid": row_id,
                                            "metadata_path": f"$.{safe_table}[{row_id}].{column}",
                                            "value": _external_path_reference(text_value),
                                            "value_hash": content_hash(text_value),
                                        }
                                    )
                                )
                            if column not in json_set or len(findings) >= max_findings:
                                continue
                            json_text = text_value.strip()
                            if not json_text or json_text[0] not in "[{":
                                continue
                            try:
                                parsed = _strict_json_loads(json_text)
                            except ValueError as exc:
                                if not _append_bounded_audit_error(
                                    errors,
                                    {
                                        "source": "sqlite_json",
                                        "file": rel,
                                        "sqlite_table": safe_table,
                                        "sqlite_column": column,
                                        "sqlite_rowid": row_id,
                                        "error": "sqlite_json_decode_failed",
                                        "detail": redact_text_secrets(str(exc)),
                                    },
                                    maximum=_SQLITE_METADATA_MAX_ERRORS,
                                    source="sqlite",
                                ):
                                    scan_stopped = True
                                    break
                                continue
                            remaining = max_findings - len(findings)
                            nested_findings, nested_truncated = _portable_metadata_findings(
                                parsed,
                                max_findings=remaining,
                            )
                            for item in nested_findings:
                                item.update(
                                    {
                                        "source": "sqlite_json",
                                        "file": rel,
                                        "sqlite_table": safe_table,
                                        "sqlite_column": column,
                                        "sqlite_rowid": row_id,
                                    }
                                )
                                findings.append(_bounded_portable_finding(item))
                            if nested_truncated:
                                _append_bounded_audit_error(
                                    errors,
                                    {
                                        "source": "sqlite_json",
                                        "file": rel,
                                        "sqlite_table": safe_table,
                                        "error": "metadata_finding_limit_reached",
                                        "maximum_findings": max_findings,
                                    },
                                    maximum=_SQLITE_METADATA_MAX_ERRORS,
                                    source="sqlite",
                                )
                                scan_stopped = True
                                break
                    except sqlite3.DataError as exc:
                        _append_bounded_audit_error(
                            errors,
                            {
                                "source": "sqlite",
                                "file": rel,
                                "sqlite_table": safe_table,
                                "sqlite_column": column,
                                "error": "sqlite_value_too_large",
                                "maximum_bytes": _SQLITE_METADATA_MAX_VALUE_BYTES,
                                "detail": redact_text_secrets(str(exc)),
                            },
                            maximum=_SQLITE_METADATA_MAX_ERRORS,
                            source="sqlite",
                        )
                    except sqlite3.Error as exc:
                        _append_bounded_audit_error(
                            errors,
                            {
                                "source": "sqlite",
                                "file": rel,
                                "sqlite_table": safe_table,
                                "sqlite_column": column,
                                "error": "sqlite_iteration_failed",
                                "detail": redact_text_secrets(str(exc)),
                            },
                            maximum=_SQLITE_METADATA_MAX_ERRORS,
                            source="sqlite",
                        )
                    if scan_stopped or len(errors) >= _SQLITE_METADATA_MAX_ERRORS:
                        break
                if scan_stopped or len(findings) >= max_findings:
                    continue

                for key_column, value_column in key_value_pairs:
                    if len(findings) >= max_findings:
                        break
                    try:
                        rows = _sqlite_rows_for_columns(
                            conn,
                            table,
                            [key_column, value_column],
                        )
                        for row_number, row in enumerate(rows, start=1):
                            row_keys = set(row.keys())
                            row_id = (
                                row["__continuum_rowid__"]
                                if "__continuum_rowid__" in row_keys
                                else row_number
                            )
                            texts: dict[str, str] = {}
                            for column in (key_column, value_column):
                                value = row[column]
                                if value is None:
                                    continue
                                if values_scanned >= _SQLITE_METADATA_MAX_VALUES_SCANNED:
                                    _append_bounded_audit_error(
                                        errors,
                                        {
                                            "source": "sqlite",
                                            "file": rel,
                                            "error": "sqlite_value_scan_limit_reached",
                                            "maximum_values": _SQLITE_METADATA_MAX_VALUES_SCANNED,
                                        },
                                        maximum=_SQLITE_METADATA_MAX_ERRORS,
                                        source="sqlite",
                                    )
                                    scan_stopped = True
                                    break
                                values_scanned += 1
                                texts[column] = (
                                    value.decode("utf-8", errors="replace")
                                    if isinstance(value, bytes)
                                    else str(value)
                                )
                            if scan_stopped:
                                break
                            key_text = texts.get(key_column)
                            value_text = texts.get(value_column)
                            if (
                                key_text
                                and value_text is not None
                                and _is_path_like_key(key_text)
                                and _looks_nonportable_local_path(value_text)
                            ):
                                findings.append(
                                    _bounded_portable_finding(
                                        {
                                            "source": "sqlite_key_value",
                                            "file": rel,
                                            "sqlite_table": safe_table,
                                            "sqlite_key_column": key_column,
                                            "sqlite_value_column": value_column,
                                            "sqlite_rowid": row_id,
                                            "metadata_path": f"$.{safe_table}[{row_id}].{key_text}",
                                            "value": _external_path_reference(value_text),
                                            "value_hash": content_hash(value_text),
                                        }
                                    )
                                )
                                if len(findings) >= max_findings:
                                    break
                    except sqlite3.DataError as exc:
                        _append_bounded_audit_error(
                            errors,
                            {
                                "source": "sqlite",
                                "file": rel,
                                "sqlite_table": safe_table,
                                "error": "sqlite_value_too_large",
                                "maximum_bytes": _SQLITE_METADATA_MAX_VALUE_BYTES,
                                "detail": redact_text_secrets(str(exc)),
                            },
                            maximum=_SQLITE_METADATA_MAX_ERRORS,
                            source="sqlite",
                        )
                    except sqlite3.Error as exc:
                        _append_bounded_audit_error(
                            errors,
                            {
                                "source": "sqlite",
                                "file": rel,
                                "sqlite_table": safe_table,
                                "error": "sqlite_iteration_failed",
                                "detail": redact_text_secrets(str(exc)),
                            },
                            maximum=_SQLITE_METADATA_MAX_ERRORS,
                            source="sqlite",
                        )
                    if scan_stopped or len(errors) >= _SQLITE_METADATA_MAX_ERRORS:
                        break
        finally:
            conn.close()

    return findings, values_scanned, errors, databases_scanned


_YAML_KEY_VALUE_RE = re.compile(
    r'^(?P<indent>\s*)(?:-\s+)?(?P<key>"(?:\\.|[^"\\])*"|[A-Za-z_][A-Za-z0-9_.-]*):(?:\s*(?P<value>.*))?$'
)


def _yaml_scalar_text(raw: str) -> str:
    text = raw.strip()
    if not text:
        return ""
    if text.startswith('"'):
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            return text.strip('"')
        return str(value)
    if text.startswith("'") and text.endswith("'") and len(text) >= 2:
        return text[1:-1].replace("''", "'")
    return text


def _read_portable_metadata_text(path: Path) -> str:
    """Read one metadata file without allowing whole-file memory growth."""
    with path.open("rb") as handle:
        payload = handle.read(_PORTABLE_METADATA_MAX_FILE_BYTES + 1)
    if len(payload) > _PORTABLE_METADATA_MAX_FILE_BYTES:
        raise _PortableMetadataTooLarge(
            f"metadata file exceeds {_PORTABLE_METADATA_MAX_FILE_BYTES} bytes"
        )
    return payload.decode("utf-8")


def _iter_portable_metadata_lines(
    path: Path,
    *,
    budget: _PortableMetadataLineBudget,
) -> Iterable[tuple[int, str]]:
    """Stream UTF-8 metadata while bounding every individual record."""
    with path.open("rb") as handle:
        line_number = 0
        while True:
            payload = handle.readline(_PORTABLE_METADATA_MAX_FILE_BYTES + 1)
            if not payload:
                return
            line_number += 1
            if len(payload) > _PORTABLE_METADATA_MAX_FILE_BYTES:
                raise _PortableMetadataTooLarge(
                    "metadata line exceeds "
                    f"{_PORTABLE_METADATA_MAX_FILE_BYTES} bytes"
                )
            budget.consume(len(payload))
            yield line_number, payload.decode("utf-8").rstrip("\r\n")


def _audit_yaml_portable_metadata(
    root: Path,
    *,
    max_findings: int,
    line_budget: _PortableMetadataLineBudget,
) -> tuple[list[dict[str, Any]], int, list[dict[str, Any]]]:
    """Inspect generated card YAML path fields without adding a YAML dependency."""
    findings: list[dict[str, Any]] = []
    files_scanned = 0
    errors: list[dict[str, Any]] = []
    cards_dir = root / "catalog" / "cards"
    if not cards_dir.exists() or max_findings <= 0:
        return findings, files_scanned, errors
    for file_path in sorted(
        (item for item in cards_dir.rglob("*") if item.suffix.casefold() in {".yaml", ".yml"}),
        key=lambda item: item.as_posix(),
    ):
        if len(findings) >= max_findings:
            break
        if _is_link_like(file_path) or not file_path.is_file():
            continue
        rel = file_path.relative_to(root).as_posix()
        try:
            files_scanned += 1
            for line_number, line in _iter_portable_metadata_lines(
                file_path,
                budget=line_budget,
            ):
                if len(findings) >= max_findings:
                    break
                match = _YAML_KEY_VALUE_RE.match(line)
                if not match:
                    continue
                raw_key = match.group("key")
                try:
                    key = str(json.loads(raw_key)) if raw_key.startswith('"') else raw_key
                except json.JSONDecodeError:
                    key = raw_key.strip('"')
                raw_value = match.group("value") or ""
                value = _yaml_scalar_text(raw_value)
                if _is_path_like_key(key) and _looks_nonportable_local_path(value):
                    findings.append(
                        _bounded_portable_finding(
                            {
                            "source": "yaml",
                            "file": rel,
                            "line": line_number,
                            "metadata_path": f"$.{key}",
                            "value": _external_path_reference(value),
                            "value_hash": content_hash(value),
                            }
                        )
                    )
        except _PortableMetadataStreamLimit as exc:
            _append_bounded_audit_error(
                errors,
                {
                    "source": "yaml",
                    "file": rel,
                    "error": exc.code,
                    "maximum": exc.maximum,
                    "detail": str(exc),
                },
                maximum=_PORTABLE_METADATA_MAX_ERRORS,
                source="yaml",
            )
            break
        except _PortableMetadataTooLarge as exc:
            _append_bounded_audit_error(
                errors,
                {
                    "source": "yaml",
                    "file": rel,
                    "error": "yaml_too_large",
                    "detail": str(exc),
                },
                maximum=_PORTABLE_METADATA_MAX_ERRORS,
                source="yaml",
            )
            continue
        except (OSError, UnicodeDecodeError) as exc:
            _append_bounded_audit_error(
                errors,
                {"source": "yaml", "file": rel, "error": "yaml_read_failed", "detail": str(exc)},
                maximum=_PORTABLE_METADATA_MAX_ERRORS,
                source="yaml",
            )
            continue
    return findings, files_scanned, errors


def audit_portable_metadata(root: Path, *, max_findings: int = 200) -> dict[str, Any]:
    """Detect raw absolute local paths in durable JSON, JSONL, YAML, and SQLite metadata."""
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    json_files_scanned = 0
    max_findings = max(1, int(max_findings))
    line_budget = _PortableMetadataLineBudget(
        max_bytes=_PORTABLE_METADATA_MAX_STREAM_BYTES,
        max_records=_PORTABLE_METADATA_MAX_STREAM_RECORDS,
    )
    for file_path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if len(findings) >= max_findings or len(errors) >= _PORTABLE_METADATA_MAX_ERRORS:
            break
        if _is_link_like(file_path) or not file_path.is_file():
            continue
        rel = file_path.relative_to(root)
        if _is_transient(rel):
            continue
        if not _is_metadata_file(rel):
            continue
        json_files_scanned += 1
        line_oriented = rel.suffix.casefold() in {".jsonl", ".log"}
        if line_oriented:
            try:
                streamed_values = _iter_portable_metadata_lines(file_path, budget=line_budget)
                for line_number, line in streamed_values:
                    if len(findings) >= max_findings:
                        break
                    if not line.strip():
                        continue
                    try:
                        parsed = _strict_json_loads(line)
                    except ValueError as exc:
                        if not _append_bounded_audit_error(
                            errors,
                            {
                                "source": "jsonl",
                                "file": rel.as_posix(),
                                "line": line_number,
                                "error": "metadata_decode_failed",
                                "detail": redact_text_secrets(str(exc)),
                            },
                            maximum=_PORTABLE_METADATA_MAX_ERRORS,
                            source="jsonl",
                        ):
                            break
                        continue
                    remaining = max_findings - len(findings)
                    record_findings, record_truncated = _portable_metadata_findings(
                        parsed,
                        scan_embedded_paths=rel.suffix.casefold() == ".log",
                        max_findings=remaining,
                    )
                    for item in record_findings:
                        item["source"] = "jsonl"
                        item["file"] = rel.as_posix()
                        item["line"] = line_number
                        findings.append(_bounded_portable_finding(item))
                    if record_truncated:
                        _append_bounded_audit_error(
                            errors,
                            {
                                "source": "jsonl",
                                "file": rel.as_posix(),
                                "line": line_number,
                                "error": "metadata_finding_limit_reached",
                                "maximum_findings": max_findings,
                            },
                            maximum=_PORTABLE_METADATA_MAX_ERRORS,
                            source="jsonl",
                        )
                        break
            except _PortableMetadataStreamLimit as exc:
                _append_bounded_audit_error(
                    errors,
                    {
                        "source": "jsonl",
                        "file": rel.as_posix(),
                        "error": exc.code,
                        "maximum": exc.maximum,
                        "detail": str(exc),
                    },
                    maximum=_PORTABLE_METADATA_MAX_ERRORS,
                    source="jsonl",
                )
            except _PortableMetadataTooLarge as exc:
                _append_bounded_audit_error(
                    errors,
                    {
                        "source": "jsonl",
                        "file": rel.as_posix(),
                        "error": "metadata_line_too_large",
                        "detail": str(exc),
                    },
                    maximum=_PORTABLE_METADATA_MAX_ERRORS,
                    source="jsonl",
                )
            except (OSError, UnicodeDecodeError) as exc:
                _append_bounded_audit_error(
                    errors,
                    {
                        "source": "jsonl",
                        "file": rel.as_posix(),
                        "error": "metadata_read_failed",
                        "detail": str(exc),
                    },
                    maximum=_PORTABLE_METADATA_MAX_ERRORS,
                    source="jsonl",
                )
            continue

        try:
            text = _read_portable_metadata_text(file_path)
        except _PortableMetadataTooLarge as exc:
            _append_bounded_audit_error(
                errors,
                {
                    "source": "json",
                    "file": rel.as_posix(),
                    "error": "metadata_too_large",
                    "detail": str(exc),
                },
                maximum=_PORTABLE_METADATA_MAX_ERRORS,
                source="json",
            )
            continue
        except (OSError, UnicodeDecodeError) as exc:
            _append_bounded_audit_error(
                errors,
                {"source": "json", "file": rel.as_posix(), "error": "metadata_read_failed", "detail": str(exc)},
                maximum=_PORTABLE_METADATA_MAX_ERRORS,
                source="json",
            )
            continue
        try:
            parsed = _strict_json_loads(text)
        except ValueError as exc:
            _append_bounded_audit_error(
                errors,
                {
                    "source": "json",
                    "file": rel.as_posix(),
                    "error": "metadata_decode_failed",
                    "detail": redact_text_secrets(str(exc)),
                },
                maximum=_PORTABLE_METADATA_MAX_ERRORS,
                source="json",
            )
            continue
        remaining = max_findings - len(findings)
        record_findings, record_truncated = _portable_metadata_findings(
            parsed,
            max_findings=remaining,
        )
        for item in record_findings:
            item["source"] = "json"
            item["file"] = rel.as_posix()
            findings.append(_bounded_portable_finding(item))
        if record_truncated:
            _append_bounded_audit_error(
                errors,
                {
                    "source": "json",
                    "file": rel.as_posix(),
                    "error": "metadata_finding_limit_reached",
                    "maximum_findings": max_findings,
                },
                maximum=_PORTABLE_METADATA_MAX_ERRORS,
                source="json",
            )
            break

    remaining = max_findings - len(findings)
    sqlite_findings, sqlite_values_scanned, sqlite_errors, sqlite_databases_scanned = _audit_sqlite_portable_metadata(
        root,
        max_findings=max(0, remaining),
    )
    findings.extend(sqlite_findings)
    errors.extend(sqlite_errors)

    remaining = max_findings - len(findings)
    yaml_findings, yaml_files_scanned, yaml_errors = _audit_yaml_portable_metadata(
        root,
        max_findings=max(0, remaining),
        line_budget=line_budget,
    )
    findings.extend(yaml_findings)
    errors.extend(yaml_errors)

    truncated = len(findings) >= max_findings
    complete = not truncated and not errors
    return {
        "ok": not findings,
        "complete": complete,
        "files_scanned": json_files_scanned + yaml_files_scanned,
        "json_files_scanned": json_files_scanned,
        "yaml_files_scanned": yaml_files_scanned,
        "sqlite_databases_scanned": sqlite_databases_scanned,
        "sqlite_values_scanned": sqlite_values_scanned,
        "finding_count": len(findings),
        "findings": findings,
        "error_count": len(errors),
        "errors": errors[:100],
        "truncated": truncated,
    }

def _symlink_inventory(root: Path) -> list[dict[str, Any]]:
    inventory: list[dict[str, Any]] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if not _is_link_like(path):
            continue
        rel = path.relative_to(root)
        item = _safe_rel_text(rel)
        try:
            target = os.readlink(path)
        except OSError as exc:
            item["error"] = str(exc)
        else:
            target_findings = scan_text_for_secrets(target, max_findings=1)
            if Path(target).is_absolute() or _looks_nonportable_local_path(target):
                safe_target = _external_path_reference(target)
            else:
                safe_target = redact_text_secrets(target) if target_findings else target
            item.update(
                {
                    "link_target": safe_target,
                    "link_target_redacted": safe_target != target,
                    "link_target_hash": content_hash(target),
                    "link_target_absolute": Path(target).is_absolute(),
                }
            )
        inventory.append(item)
    return inventory


def _copy_root_to_stage(
    root: Path,
    stage_root: Path,
    *,
    symlink_policy: str,
) -> dict[str, Any]:
    skipped: list[dict[str, Any]] = []
    copied_files = 0
    copied_bytes = 0
    source_db = _catalog_database_for_bundle(root)

    symlinks = _symlink_inventory(root)
    if symlinks and symlink_policy == "fail":
        raise ValueError(
            f"bundle symlink policy is 'fail', but the root contains {len(symlinks)} symlink(s)"
        )

    secure_mkdir(stage_root)
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        rel = path.relative_to(root)
        if _is_transient(rel):
            skipped.append({**_safe_rel_text(rel), "reason": "transient_excluded"})
            continue
        if _is_link_like(path):
            skipped.append({**_safe_rel_text(rel), "reason": "symlink_skipped"})
            continue
        if path.is_dir():
            continue
        if not path.is_file():
            skipped.append({**_safe_rel_text(rel), "reason": "unsupported_file_type"})
            continue
        if rel.as_posix() == "catalog/catalog.sqlite3":
            continue
        target = stage_root / rel
        secure_copy_file(path, target)
        copied_files += 1
        copied_bytes += target.stat().st_size

    staged_db = stage_root / "catalog" / "catalog.sqlite3"
    _sqlite_backup(source_db, staged_db)
    copied_files += 1
    copied_bytes += staged_db.stat().st_size
    return {
        "copied_files": copied_files,
        "copied_bytes": copied_bytes,
        "skipped": skipped,
        "symlinks": symlinks,
    }


def _claim_disposable_bundle_root(root: Path) -> dict[str, Any]:
    """Give an isolated staging/extraction root temporary verification authority."""
    marker = writer_claim_path(root)
    if os.path.lexists(marker):
        raise ValueError(
            "disposable bundle root unexpectedly contains a writer claim"
        )
    result = claim_writer(root)
    if (
        not result.get("ok")
        or not result.get("claimed")
        or not result.get("compatible")
        or result.get("changed") is not True
    ):
        raise ValueError(
            "disposable bundle root could not acquire exclusive verification authority"
        )
    return result


def _file_entries(root: Path) -> tuple[list[dict[str, Any]], int]:
    entries: list[dict[str, Any]] = []
    total_bytes = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if _is_link_like(path):
            raise ValueError(f"staged bundle unexpectedly contains symlink or junction: {path}")
        if not path.is_file() or path.name == BUNDLE_MANIFEST_NAME:
            continue
        rel_path = path.relative_to(root)
        if _is_transient(rel_path):
            continue
        rel = rel_path.as_posix()
        size = path.stat().st_size
        total_bytes += size
        entries.append(
            {
                "path": rel,
                "sha256": file_sha256(path),
                "size_bytes": size,
                "mode": stat.S_IMODE(path.stat().st_mode),
            }
        )
    unsafe = _bounded_diagnostic_sample(
        (
            str(entry["path"])
            for entry in entries
            if not _zip_member_is_safe(str(entry["path"]))
        ),
        maximum=5,
    )
    if unsafe:
        raise ValueError(f"root contains bundle-incompatible path(s): {unsafe}")
    collisions = _portable_name_collisions(
        (str(entry["path"]) for entry in entries),
        maximum=5,
        members_per_collision=5,
    )
    if collisions:
        raise ValueError(f"root contains case/Unicode-colliding path(s): {collisions}")
    return entries, total_bytes


_WINDOWS_RESERVED_COMPONENTS = {
    "con", "prn", "aux", "nul", "clock$", "conin$", "conout$",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
    "com¹", "com²", "com³", "lpt¹", "lpt²", "lpt³",
}
_WINDOWS_FORBIDDEN_COMPONENT_CHARACTERS = frozenset('<>:"\\|?*')


def _zip_member_is_safe(name: str) -> bool:
    if not name or "\\" in name or any(ord(char) < 32 or ord(char) == 127 for char in name):
        return False
    pure = PurePosixPath(name)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        return False
    if name != pure.as_posix():
        return False
    for component in pure.parts:
        if any(char in _WINDOWS_FORBIDDEN_COMPONENT_CHARACTERS for char in component):
            return False
        if component.endswith((" ", ".")):
            return False
        try:
            windows_code_units = len(component.encode("utf-16-le")) // 2
        except UnicodeEncodeError:
            return False
        if windows_code_units > 255:
            return False
        stem = component.split(".", 1)[0].casefold()
        if stem in _WINDOWS_RESERVED_COMPONENTS:
            return False
    return True


_DiagnosticItem = TypeVar("_DiagnosticItem")


def _bounded_diagnostic_sample(
    values: Iterable[_DiagnosticItem],
    *,
    maximum: int = _BUNDLE_DIAGNOSTIC_SAMPLE_LIMIT,
) -> list[_DiagnosticItem]:
    """Retain at most ``maximum`` already-matched diagnostic values."""

    if maximum < 1:
        raise ValueError("diagnostic sample maximum must be positive")
    sample: list[_DiagnosticItem] = []
    for value in values:
        sample.append(value)
        if len(sample) == maximum:
            break
    return sample


def _bounded_absent_text_sample(
    candidates: Iterable[str],
    present: set[str],
    *,
    maximum: int = _BUNDLE_DIAGNOSTIC_SAMPLE_LIMIT,
) -> list[str]:
    """Sample unique candidates absent from ``present`` without a full difference."""

    if maximum < 1:
        raise ValueError("diagnostic sample maximum must be positive")
    sample: list[str] = []
    sampled: set[str] = set()
    for candidate in candidates:
        if candidate in present or candidate in sampled:
            continue
        sampled.add(candidate)
        sample.append(candidate)
        if len(sample) == maximum:
            break
    return sample


def _is_nondecreasing_text(values: Iterable[str]) -> bool:
    iterator = iter(values)
    try:
        previous = next(iterator)
    except StopIteration:
        return True
    for value in iterator:
        if previous > value:
            return False
        previous = value
    return True


def _portable_name_collisions(
    names: Iterable[str],
    *,
    maximum: int = _BUNDLE_DIAGNOSTIC_SAMPLE_LIMIT,
    members_per_collision: int = _BUNDLE_DIAGNOSTIC_SAMPLE_LIMIT,
) -> list[list[str]]:
    """Return bounded collision groups while preserving exact collision detection."""

    if maximum < 1 or members_per_collision < 2:
        raise ValueError("collision sample limits are invalid")
    first_by_key: dict[str, str] = {}
    sampled_by_key: dict[str, list[str]] = {}
    samples: list[list[str]] = []
    for name in names:
        key = unicodedata.normalize("NFC", name).casefold()
        if key not in first_by_key:
            first_by_key[key] = name
            continue
        group = sampled_by_key.get(key)
        if group is None:
            group = [first_by_key[key], name]
            sampled_by_key[key] = group
            samples.append(group)
            if len(samples) == maximum:
                return [sorted(values) for values in samples]
            continue
        if len(group) < members_per_collision:
            group.append(name)
    return [sorted(values) for values in samples]


def _zip_member_type(info: zipfile.ZipInfo) -> str:
    if info.is_dir():
        return "directory"
    if info.create_system != 3:
        return "regular_or_unspecified"
    raw_mode = info.external_attr >> 16
    file_type = stat.S_IFMT(raw_mode)
    if file_type in {0, stat.S_IFREG}:
        return "regular_or_unspecified"
    if file_type == stat.S_IFLNK:
        return "symlink"
    return f"non_regular:{oct(file_type)}"


def _is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _manifest_structure_errors(
    manifest: dict[str, Any],
    *,
    _errors: _BoundedBundleErrors | None = None,
) -> list[dict[str, Any]]:
    errors = _errors if _errors is not None else _BoundedBundleErrors()
    allowed_keys = {
        "schema", "bundle_id", "created_at", "profile", "symlink_policy",
        "redaction_profile", "root_identity_hash", "file_count", "total_size_bytes",
        "files", "copy", "preflight", "alias_key_policy", "manifest_hash",
    }
    unexpected = _bounded_diagnostic_sample(
        (key for key in manifest if key not in allowed_keys)
    )
    if unexpected:
        errors.append({"error": "manifest_unexpected_fields", "fields": unexpected})
    required_strings = ("bundle_id", "created_at", "manifest_hash")
    for key in required_strings:
        if not isinstance(manifest.get(key), str) or not str(manifest.get(key)).strip():
            errors.append({"error": "manifest_required_string", "field": key})
    if manifest.get("profile") not in SUPPORTED_BUNDLE_PROFILES:
        errors.append({"error": "manifest_profile_invalid", "actual": manifest.get("profile")})
    if manifest.get("symlink_policy") not in SUPPORTED_SYMLINK_POLICIES:
        errors.append({"error": "manifest_symlink_policy_invalid", "actual": manifest.get("symlink_policy")})
    redaction_profile = manifest.get("redaction_profile")
    if redaction_profile not in {"private", "portable", "shareable"}:
        errors.append({"error": "manifest_redaction_profile_invalid", "actual": redaction_profile})
    root_identity_hash = manifest.get("root_identity_hash")
    if root_identity_hash is not None and (
        not isinstance(root_identity_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", root_identity_hash)
    ):
        errors.append({"error": "manifest_root_identity_hash_invalid"})
    for key in ("file_count", "total_size_bytes"):
        value = manifest.get(key)
        if not _is_nonnegative_int(value):
            errors.append({"error": "manifest_nonnegative_integer_required", "field": key, "actual": value})
    if not isinstance(manifest.get("preflight"), dict):
        errors.append({"error": "manifest_preflight_not_object"})
    if not isinstance(manifest.get("copy"), dict):
        errors.append({"error": "manifest_copy_not_object"})
    files = manifest.get("files")
    if not isinstance(files, list):
        return errors
    previous_path: str | None = None
    file_order_noncanonical = False
    alias_key_paths: list[str] = []
    shareable = manifest.get("profile") == "shareable"
    for entry in files:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            continue
        path = str(entry["path"])
        if previous_path is not None and previous_path > path:
            file_order_noncanonical = True
        previous_path = path
        if (
            shareable
            and len(alias_key_paths) < _BUNDLE_DIAGNOSTIC_SAMPLE_LIMIT
            and (
                path == "catalog/partition_alias.key"
                or (
                    path.startswith("snapshots/continuum_partition_alias_")
                    and path.endswith(".key")
                )
            )
        ):
            alias_key_paths.append(path)
    if file_order_noncanonical:
        errors.append({"error": "manifest_file_order_noncanonical"})
    if alias_key_paths:
        errors.append(
            {
                "error": "manifest_shareable_alias_key_included",
                "paths": alias_key_paths,
            }
        )
    allowed_entry_keys = {"path", "sha256", "size_bytes", "mode"}
    for index, entry in enumerate(files):
        if not isinstance(entry, dict):
            continue
        unexpected_entry = _bounded_diagnostic_sample(
            (key for key in entry if key not in allowed_entry_keys)
        )
        if unexpected_entry:
            errors.append({"error": "manifest_file_entry_unexpected_fields", "index": index, "fields": unexpected_entry})
        if not isinstance(entry.get("path"), str) or not entry.get("path"):
            errors.append({"error": "manifest_file_path_invalid", "index": index})
        digest = entry.get("sha256")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            errors.append({"error": "manifest_file_sha256_invalid", "index": index})
        for key in ("size_bytes", "mode"):
            value = entry.get(key)
            if not _is_nonnegative_int(value):
                errors.append({"error": "manifest_file_integer_invalid", "index": index, "field": key})
    return errors


def _manifest_semantic_errors(
    manifest: dict[str, Any],
    *,
    _errors: _BoundedBundleErrors | None = None,
) -> list[dict[str, Any]]:
    """Validate claims that distinguish a policy-checked handoff from a hash list."""
    errors = _errors if _errors is not None else _BoundedBundleErrors()
    profile = manifest.get("profile")
    symlink_policy = manifest.get("symlink_policy")
    redaction_profile = manifest.get("redaction_profile")

    if profile == "shareable":
        if symlink_policy != "fail":
            errors.append(
                {
                    "error": "manifest_shareable_symlink_policy_invalid",
                    "expected": "fail",
                    "actual": symlink_policy,
                }
            )
        if redaction_profile not in {"portable", "shareable"}:
            errors.append(
                {
                    "error": "manifest_shareable_redaction_profile_invalid",
                    "actual": redaction_profile,
                }
            )

    copy_payload = manifest.get("copy")
    if isinstance(copy_payload, dict):
        allowed_copy_keys = {
            "copied_files", "copied_bytes", "skipped_count", "skipped",
            "symlink_count", "symlinks",
        }
        unexpected = _bounded_diagnostic_sample(
            (key for key in copy_payload if key not in allowed_copy_keys)
        )
        if unexpected:
            errors.append({"error": "manifest_copy_unexpected_fields", "fields": unexpected})
        for key in ("copied_files", "copied_bytes", "skipped_count", "symlink_count"):
            if not _is_nonnegative_int(copy_payload.get(key)):
                errors.append({"error": "manifest_copy_nonnegative_integer_required", "field": key})
        skipped = copy_payload.get("skipped")
        symlinks = copy_payload.get("symlinks")
        if not isinstance(skipped, list):
            errors.append({"error": "manifest_copy_skipped_not_list"})
            skipped = []
        if not isinstance(symlinks, list):
            errors.append({"error": "manifest_copy_symlinks_not_list"})
            symlinks = []
        if _is_nonnegative_int(copy_payload.get("skipped_count")) and copy_payload.get("skipped_count") != len(skipped):
            errors.append({"error": "manifest_copy_skipped_count_mismatch"})
        if _is_nonnegative_int(copy_payload.get("symlink_count")) and copy_payload.get("symlink_count") != len(symlinks):
            errors.append({"error": "manifest_copy_symlink_count_mismatch"})
        if _is_nonnegative_int(copy_payload.get("copied_files")) and _is_nonnegative_int(manifest.get("file_count")):
            if copy_payload.get("copied_files") != manifest.get("file_count"):
                errors.append({"error": "manifest_copy_file_count_mismatch"})
        if _is_nonnegative_int(copy_payload.get("copied_bytes")) and _is_nonnegative_int(manifest.get("total_size_bytes")):
            if copy_payload.get("copied_bytes") != manifest.get("total_size_bytes"):
                errors.append({"error": "manifest_copy_size_mismatch"})
        valid_skip_reasons = {"transient_excluded", "symlink_skipped", "unsupported_file_type", "shareable_alias_key_omitted"}
        invalid_skipped = _bounded_diagnostic_sample(
            (
                index
                for index, item in enumerate(skipped)
                if not isinstance(item, dict)
                or not isinstance(item.get("reason"), str)
                or item.get("reason") not in valid_skip_reasons
            )
        )
        if invalid_skipped:
            errors.append(
                {
                    "error": "manifest_copy_skip_entry_invalid",
                    "indexes": invalid_skipped,
                }
            )
        symlink_count = copy_payload.get("symlink_count")
        if symlink_policy == "fail" and (symlinks or (symlink_count is not None and symlink_count != 0)):
            errors.append({"error": "manifest_fail_policy_contains_symlinks"})
        if profile == "shareable":
            prohibited = _bounded_diagnostic_sample(
                (
                    index
                    for index, item in enumerate(skipped)
                    if isinstance(item, dict)
                    and isinstance(item.get("reason"), str)
                    and item.get("reason")
                    in {"symlink_skipped", "unsupported_file_type"}
                )
            )
            if prohibited:
                errors.append(
                    {
                        "error": "manifest_shareable_omitted_evidence",
                        "indexes": prohibited,
                    }
                )

    preflight = manifest.get("preflight")
    if isinstance(preflight, dict):
        allowed_preflight_keys = {
            "root_verification_ok", "staged_root_verification_ok", "secret_audit_complete",
            "secret_finding_count", "secret_allowlisted_finding_count", "proof_pack_count",
            "proof_packs_ok", "artifact_count", "artifact_ledger_ok",
            "portable_metadata_files_scanned", "portable_metadata_sqlite_values_scanned",
            "portable_metadata_complete", "portable_metadata_ok", "restore_drill_ran",
            "alias_key_included", "alias_key_policy", "alias_key_files_omitted",
            "snapshot_manifests_rewritten_for_shareable",
        }
        unexpected = _bounded_diagnostic_sample(
            (key for key in preflight if key not in allowed_preflight_keys)
        )
        if unexpected:
            errors.append({"error": "manifest_preflight_unexpected_fields", "fields": unexpected})
        healthy_bool_fields = (
            "root_verification_ok", "staged_root_verification_ok", "secret_audit_complete",
            "proof_packs_ok", "artifact_ledger_ok", "portable_metadata_complete",
            "portable_metadata_ok",
        )
        for key in (*healthy_bool_fields, "restore_drill_ran"):
            if not isinstance(preflight.get(key), bool):
                errors.append({"error": "manifest_preflight_boolean_required", "field": key})
        for key in (
            "secret_finding_count", "secret_allowlisted_finding_count", "proof_pack_count",
            "artifact_count", "portable_metadata_files_scanned",
            "portable_metadata_sqlite_values_scanned", "alias_key_files_omitted",
            "snapshot_manifests_rewritten_for_shareable",
        ):
            if not _is_nonnegative_int(preflight.get(key)):
                errors.append({"error": "manifest_preflight_nonnegative_integer_required", "field": key})
        unhealthy = [key for key in healthy_bool_fields if preflight.get(key) is not True]
        if unhealthy:
            errors.append({"error": "manifest_preflight_unhealthy", "fields": unhealthy})
        if preflight.get("secret_finding_count") != 0:
            errors.append(
                {
                    "error": "manifest_preflight_secret_findings_present",
                    "actual": preflight.get("secret_finding_count"),
                }
            )
        if profile == "shareable" and preflight.get("secret_allowlisted_finding_count") != 0:
            errors.append(
                {
                    "error": "manifest_shareable_allowlisted_findings_present",
                    "actual": preflight.get("secret_allowlisted_finding_count"),
                }
            )
        files = manifest.get("files")
        if isinstance(files, list) and _is_nonnegative_int(preflight.get("proof_pack_count")):
            actual_proof_count = sum(
                1
                for item in files
                if isinstance(item, dict)
                and isinstance(item.get("path"), str)
                and PurePosixPath(item["path"]).parent == PurePosixPath("exports/proof_packs")
                and PurePosixPath(item["path"]).suffix.casefold() == ".json"
            )
            if preflight.get("proof_pack_count") != actual_proof_count:
                errors.append(
                    {
                        "error": "manifest_preflight_proof_count_mismatch",
                        "expected": preflight.get("proof_pack_count"),
                        "actual": actual_proof_count,
                    }
                )
    return errors


class _DuplicateJSONKeyError(ValueError):
    pass


def _strict_json_loads(text: str) -> Any:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise _DuplicateJSONKeyError("duplicate JSON object key")
            result[key] = value
        return result

    def reject_nonfinite(value: str) -> Any:
        raise ValueError(f"non-finite JSON number is not allowed: {value}")

    return json.loads(text, object_pairs_hook=reject_duplicate_keys, parse_constant=reject_nonfinite)


def _write_zip_member(
    archive: zipfile.ZipFile,
    path: Path,
    *,
    arcname: str,
    mode_override: int | None = None,
) -> None:
    """Write one regular file with normalized timestamp and explicit POSIX mode."""
    stat_result = path.stat()
    mode = stat.S_IMODE(stat_result.st_mode) if mode_override is None else stat.S_IMODE(mode_override)
    info = zipfile.ZipInfo(arcname, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.file_size = stat_result.st_size
    force_zip64 = _zip64_local_layout_required(stat_result.st_size, 0)
    with path.open("rb") as source, archive.open(info, "w", force_zip64=force_zip64) as destination:
        shutil.copyfileobj(source, destination, length=1024 * 1024)


def _read_zip_member_exact(
    handle: Any,
    info: zipfile.ZipInfo,
    *,
    collect: bool = False,
    budget: _BundleVerificationBudget | None = None,
) -> tuple[bytes | None, str | None, int, str | None]:
    """Read a member and require DEFLATE EOF at the declared byte boundary.

    ``zipfile`` verifies the decompressed CRC, but it accepts bytes appended after
    a valid DEFLATE end marker inside the member's declared compressed region.
    Those bytes are invisible to an uncompressed manifest hash.  This reader
    therefore binds both the logical file and its physical compressed envelope.
    """
    try:
        header = _read_exact_at(handle, int(info.header_offset), 30)
        if struct.unpack_from("<I", header)[0] != _ZIP_LOCAL_SIGNATURE:
            return None, None, 0, "local_header_invalid"
        name_length, extra_length = struct.unpack_from("<HH", header, 26)
        data_offset = int(info.header_offset) + 30 + name_length + extra_length
        handle.seek(data_offset)
    except (OSError, EOFError, struct.error) as exc:
        return None, None, 0, f"member_seek_failed:{type(exc).__name__}"

    digest = hashlib.sha256()
    crc = 0
    output_size = 0
    declared_output_size = int(info.file_size)
    collected: list[bytes] | None = [] if collect else None

    class _OutputSizeExceeded(Exception):
        pass

    def consume(output: bytes) -> None:
        nonlocal crc, output_size
        if not output:
            return
        if output_size + len(output) > declared_output_size:
            raise _OutputSizeExceeded
        if budget is not None:
            budget.consume(len(output), f"hashing ZIP member {info.filename}")
        digest.update(output)
        crc = zlib.crc32(output, crc)
        output_size += len(output)
        if collected is not None:
            collected.append(output)

    remaining = int(info.compress_size)
    try:
        if info.compress_type == zipfile.ZIP_STORED:
            while remaining:
                if budget is not None:
                    budget.check_deadline(f"reading ZIP member {info.filename}")
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    return None, None, output_size, "compressed_data_truncated"
                remaining -= len(chunk)
                consume(chunk)
        elif info.compress_type == zipfile.ZIP_DEFLATED:
            inflater = zlib.decompressobj(-15)
            while remaining:
                if budget is not None:
                    budget.check_deadline(f"reading ZIP member {info.filename}")
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    return None, None, output_size, "compressed_data_truncated"
                remaining -= len(chunk)
                if inflater.eof:
                    return None, None, output_size, "compressed_stream_trailing_data"
                pending = chunk
                while pending:
                    before = len(pending)
                    output = inflater.decompress(pending, 1024 * 1024)
                    consume(output)
                    if inflater.unused_data:
                        return None, None, output_size, "compressed_stream_trailing_data"
                    pending = inflater.unconsumed_tail
                    if pending and len(pending) == before and not output:
                        return None, None, output_size, "decompressor_stalled"
                if inflater.eof and remaining:
                    return None, None, output_size, "compressed_stream_trailing_data"
            if not inflater.eof:
                return None, None, output_size, "compressed_stream_not_terminated"
            if inflater.unused_data or inflater.unconsumed_tail:
                return None, None, output_size, "compressed_stream_trailing_data"
            consume(inflater.flush())
        else:
            return None, None, output_size, "compression_method_not_supported"
    except _OutputSizeExceeded:
        return None, None, output_size, "uncompressed_size_exceeded"
    except (OSError, zlib.error) as exc:
        return None, None, output_size, f"decompression_failed:{type(exc).__name__}"

    actual_hash = digest.hexdigest()
    if output_size != int(info.file_size):
        return None, actual_hash, output_size, "uncompressed_size_mismatch"
    if (crc & 0xFFFFFFFF) != int(info.CRC):
        return None, actual_hash, output_size, "crc_mismatch"
    return (b"".join(collected) if collected is not None else None), actual_hash, output_size, None


_ZIP_LOCAL_SIGNATURE = 0x04034B50
_ZIP_CENTRAL_SIGNATURE = 0x02014B50
_ZIP_EOCD_SIGNATURE = 0x06054B50
_ZIP64_EOCD_SIGNATURE = 0x06064B50
_ZIP64_LOCATOR_SIGNATURE = 0x07064B50
_ZIP64_EXTRA_ID = 0x0001
_ZIP_UINT16_MAX = 0xFFFF
_ZIP_UINT32_MAX = 0xFFFFFFFF


def _zip64_local_layout_required(uncompressed_size: int, compressed_size: int) -> bool:
    """Return the layout decision used by Python's seekable ZIP writer."""
    return (
        int(uncompressed_size) * 1.05 > zipfile.ZIP64_LIMIT
        or int(compressed_size) > zipfile.ZIP64_LIMIT
    )


def _zip64_central_value_required(value: int) -> bool:
    """Return whether Python's central-directory writer emits a Zip64 value."""
    return int(value) > zipfile.ZIP64_LIMIT


def _zip_extra_fields(extra: bytes) -> tuple[list[tuple[int, bytes]], str | None]:
    fields: list[tuple[int, bytes]] = []
    cursor = 0
    while cursor < len(extra):
        if len(extra) - cursor < 4:
            return fields, "truncated_extra_header"
        field_id, field_size = struct.unpack_from("<HH", extra, cursor)
        cursor += 4
        end = cursor + field_size
        if end > len(extra):
            return fields, "truncated_extra_payload"
        fields.append((field_id, extra[cursor:end]))
        cursor = end
    return fields, None


def _zip64_extra_error(
    extra: bytes,
    *,
    raw_uncompressed: int,
    raw_compressed: int,
    actual_uncompressed: int,
    actual_compressed: int,
    raw_offset: int | None = None,
    actual_offset: int | None = None,
    raw_disk: int | None = None,
) -> str | None:
    fields, parse_error = _zip_extra_fields(extra)
    if parse_error:
        return parse_error
    if any(field_id != _ZIP64_EXTRA_ID for field_id, _data in fields):
        return "unapproved_extra_field"
    if len(fields) > 1:
        return "duplicate_zip64_extra"

    required: list[tuple[str, int, int]] = []
    if raw_uncompressed == _ZIP_UINT32_MAX:
        required.append(("uncompressed_size", 8, actual_uncompressed))
    if raw_compressed == _ZIP_UINT32_MAX:
        required.append(("compressed_size", 8, actual_compressed))
    if raw_offset == _ZIP_UINT32_MAX and actual_offset is not None:
        required.append(("local_header_offset", 8, actual_offset))
    if raw_disk == _ZIP_UINT16_MAX:
        required.append(("disk_number", 4, 0))

    if not required:
        return "unnecessary_extra_field" if fields else None
    if len(fields) != 1:
        return "missing_zip64_extra"
    data = fields[0][1]
    cursor = 0
    for _name, width, expected in required:
        if cursor + width > len(data):
            return "truncated_zip64_extra"
        fmt = "<Q" if width == 8 else "<I"
        actual = struct.unpack_from(fmt, data, cursor)[0]
        if actual != expected:
            return "zip64_value_mismatch"
        cursor += width
    if cursor != len(data):
        return "zip64_extra_trailing_data"
    return None


def _decode_zip_filename(raw: bytes, flags: int) -> str:
    encoding = "utf-8" if flags & 0x800 else "cp437"
    return raw.decode(encoding)


def _find_eocd(data: bytes) -> tuple[int, tuple[int, ...]] | None:
    minimum = max(0, len(data) - (22 + _ZIP_UINT16_MAX + 4096))
    signature = struct.pack("<I", _ZIP_EOCD_SIGNATURE)
    cursor = len(data)
    while True:
        offset = data.rfind(signature, minimum, cursor)
        if offset < 0:
            return None
        if offset + 22 <= len(data):
            values = struct.unpack_from("<IHHHHIIH", data, offset)
            comment_length = values[-1]
            if offset + 22 + comment_length <= len(data):
                return offset, values
        cursor = offset


@dataclass(frozen=True)
class _BundleZipPreflight:
    file_size: int
    declared_entry_count: int
    observed_entry_count: int
    central_directory_size: int
    central_directory_offset: int

    @property
    def entry_count(self) -> int:
        return self.observed_entry_count


def _validated_bundle_limit(name: str, value: Any, *, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if value < 1 or value > maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}")
    return value


def _deflate_compressed_size_bound(expanded_bytes: int, entry_count: int) -> int:
    """Conservative sum of zlib ``compressBound`` over canonical members."""
    expanded = max(0, int(expanded_bytes))
    entries = max(0, int(entry_count))
    return (
        expanded
        + (expanded >> 12)
        + (expanded >> 14)
        + (expanded >> 25)
        + 13 * entries
    )


def _read_bundle_zip_preflight(
    path: Path,
    *,
    budget: _BundleVerificationBudget | None = None,
    raw_handle: Any | None = None,
    max_entries: int | None = None,
    max_central_directory_bytes: int | None = None,
) -> _BundleZipPreflight:
    """Walk bounded EOCD and central records before ``ZipFile`` allocates them."""
    file_size = (
        os.fstat(raw_handle.fileno()).st_size
        if raw_handle is not None
        else path.stat().st_size
    )
    if file_size < 22:
        raise ValueError("ZIP end-of-central-directory record is missing")
    handle_context = nullcontext(raw_handle) if raw_handle is not None else path.open("rb")
    with handle_context as handle:
        if budget is not None:
            budget.check_deadline("preflighting the ZIP end record")
        tail_size = min(file_size, 22 + _ZIP_UINT16_MAX + 4096)
        tail = _read_exact_at(handle, file_size - tail_size, tail_size)
        located = _find_eocd(tail)
        if located is None:
            raise ValueError("ZIP end-of-central-directory record is missing")
        relative_eocd, eocd = located
        eocd_offset = file_size - tail_size + relative_eocd
        (
            _signature,
            _disk_number,
            _central_disk,
            _entries_on_disk,
            declared_entries,
            central_size,
            central_offset,
            _comment_length,
        ) = eocd
        legacy_central_size = int(central_size)
        legacy_central_offset = int(central_offset)
        if _disk_number != 0 or _central_disk != 0 or _entries_on_disk != declared_entries:
            raise ValueError("multi-disk ZIP metadata is not supported")

        locator_offset = eocd_offset - 20
        locator = _read_exact_at(handle, locator_offset, 20) if locator_offset >= 0 else b""
        central_boundary = eocd_offset
        has_zip64_locator = (
            len(locator) == 20
            and struct.unpack_from("<I", locator)[0] == _ZIP64_LOCATOR_SIGNATURE
        )
        if has_zip64_locator:
            _locator_signature, zip64_disk, zip64_offset, zip64_disks = struct.unpack(
                "<IIQI", locator
            )
            if zip64_disk != 0 or zip64_disks != 1:
                raise ValueError("multi-disk ZIP64 metadata is not supported")
            zip64_header = _read_exact_at(handle, int(zip64_offset), 56)
            if struct.unpack_from("<I", zip64_header)[0] != _ZIP64_EOCD_SIGNATURE:
                raise ValueError("ZIP64 end-of-central-directory record is missing")
            record_size = struct.unpack_from("<Q", zip64_header, 4)[0]
            if record_size != 44 or int(zip64_offset) + 56 != locator_offset:
                raise ValueError("ZIP64 end record is not the fixed adjacent canonical record")
            (
                made,
                needed,
                disk_number,
                directory_disk,
                entries_on_disk,
                total_entries,
                central_size,
                central_offset,
            ) = struct.unpack_from("<HHIIQQQQ", zip64_header, 12)
            if made != 45 or needed != 45:
                raise ValueError("ZIP64 version metadata is not canonical")
            if (
                disk_number != 0
                or directory_disk != 0
                or entries_on_disk != total_entries
            ):
                raise ValueError("multi-disk or inconsistent ZIP64 entry metadata")
            if not (
                int(total_entries) > zipfile.ZIP_FILECOUNT_LIMIT
                or int(central_size) > zipfile.ZIP64_LIMIT
                or int(central_offset) > zipfile.ZIP64_LIMIT
            ):
                raise _BundleLimitError(
                    "zip64_not_required",
                    "ZIP64 end records are present below every writer threshold",
                )
            expected_legacy_entries = min(int(total_entries), _ZIP_UINT16_MAX)
            expected_legacy_size = min(int(central_size), _ZIP_UINT32_MAX)
            expected_legacy_offset = min(int(central_offset), _ZIP_UINT32_MAX)
            if (
                _entries_on_disk != expected_legacy_entries
                or declared_entries != expected_legacy_entries
                or legacy_central_size != expected_legacy_size
                or legacy_central_offset != expected_legacy_offset
            ):
                raise ValueError("ZIP64 legacy end-record fields are inconsistent")
            declared_entries = int(total_entries)
            central_boundary = int(zip64_offset)
        elif (
            legacy_central_size > zipfile.ZIP64_LIMIT
            or legacy_central_offset > zipfile.ZIP64_LIMIT
        ):
            raise _BundleLimitError(
                "zip64_required",
                "ZIP central size or offset exceeds the writer threshold without ZIP64 end records",
            )

        central_size = int(central_size)
        central_offset = int(central_offset)
        central_end = central_offset + central_size
        if central_offset >= 0 and central_size >= 0 and central_end < central_boundary:
            raise _BundleLimitError(
                "zip_local_member_gap_or_preamble",
                "ZIP local/central regions leave an unbound prefix or gap",
            )
        if (
            central_offset < 0
            or central_size < 0
            or central_end != central_boundary
            or central_boundary > file_size
        ):
            raise ValueError("ZIP central directory geometry is invalid")
        if (
            max_central_directory_bytes is not None
            and central_size > max_central_directory_bytes
        ):
            raise _BundleLimitError(
                "bundle_central_directory_too_large",
                "ZIP central directory exceeds the configured byte limit",
            )

        cursor = central_offset
        observed_entries = 0
        while cursor < central_end:
            if budget is not None:
                budget.check_deadline("counting ZIP central-directory records")
            if max_entries is not None and observed_entries >= max_entries:
                raise _BundleLimitError(
                    "bundle_entry_count_too_large",
                    "ZIP central directory exceeds the configured entry limit",
                )
            header = _read_exact_at(handle, cursor, 46)
            if struct.unpack_from("<I", header)[0] != _ZIP_CENTRAL_SIGNATURE:
                raise ValueError("ZIP central directory contains a non-record gap")
            name_length, extra_length, comment_length = struct.unpack_from(
                "<HHH", header, 28
            )
            record_size = 46 + name_length + extra_length + comment_length
            if record_size < 46 or cursor + record_size > central_end:
                raise ValueError("ZIP central-directory record exceeds its boundary")
            cursor += record_size
            observed_entries += 1
        if cursor != central_end:
            raise ValueError("ZIP central directory is not exactly contiguous")
        if observed_entries != int(declared_entries):
            raise ValueError(
                "ZIP declared entry count does not match observed central records"
            )
    return _BundleZipPreflight(
        file_size=int(file_size),
        declared_entry_count=int(declared_entries),
        observed_entry_count=observed_entries,
        central_directory_size=int(central_size),
        central_directory_offset=int(central_offset),
    )


def _bounded_bundle_sha256(handle: Any, budget: _BundleVerificationBudget) -> str:
    digest = hashlib.sha256()
    handle.seek(0)
    while True:
        budget.check_deadline("hashing the ZIP envelope")
        chunk = handle.read(_BUNDLE_IO_CHUNK_BYTES)
        if not chunk:
            break
        budget.consume(len(chunk), "hashing the ZIP envelope")
        digest.update(chunk)
    return digest.hexdigest()


def _read_exact_at(handle: Any, offset: int, size: int) -> bytes:
    handle.seek(offset)
    data = handle.read(size)
    if len(data) != size:
        raise EOFError(f"expected {size} bytes at offset {offset}, got {len(data)}")
    return data


def _zip_envelope_errors(
    path: Path,
    infos: list[zipfile.ZipInfo],
    *,
    budget: _BundleVerificationBudget | None = None,
    raw_handle: Any | None = None,
    _errors: _BoundedBundleErrors | None = None,
) -> list[dict[str, Any]]:
    """Reject bytes and metadata that are not bound by the bundle manifest.

    The normal ``zipfile`` API exposes logical members but intentionally tolerates
    self-extracting preambles, comments, extra fields, and trailing bytes.  A
    handoff bundle treats those channels as unmanifested storage, so this parser
    requires one contiguous, single-disk ZIP envelope and permits only the
    structurally required Zip64 size fields emitted by the packer.  It uses
    bounded random-access reads rather than loading the entire archive into RAM.
    """
    errors = _errors if _errors is not None else _BoundedBundleErrors()
    if budget is not None:
        budget.check_deadline("validating the ZIP envelope")
    try:
        file_size = (
            os.fstat(raw_handle.fileno()).st_size
            if raw_handle is not None
            else path.stat().st_size
        )
        handle_context = (
            nullcontext(raw_handle) if raw_handle is not None else path.open("rb")
        )
    except OSError as exc:
        errors.append({"error": "zip_envelope_read_failed", "detail": str(exc)})
        return errors

    with handle_context as handle:
        tail_size = min(file_size, 22 + _ZIP_UINT16_MAX + 4096)
        try:
            tail = _read_exact_at(handle, file_size - tail_size, tail_size)
        except (OSError, EOFError) as exc:
            errors.append({"error": "zip_envelope_read_failed", "detail": str(exc)})
            return errors
        located = _find_eocd(tail)
        if located is None:
            errors.append({"error": "zip_eocd_missing"})
            return errors
        relative_eocd, eocd = located
        eocd_offset = file_size - tail_size + relative_eocd
        (
            _sig,
            disk_number,
            central_disk,
            entries_on_disk,
            total_entries,
            central_size_32,
            central_offset_32,
            comment_length,
        ) = eocd
        expected_end = eocd_offset + 22 + comment_length
        if expected_end != file_size:
            errors.append(
                {
                    "error": "zip_trailing_bytes",
                    "trailing_size_bytes": max(0, file_size - expected_end),
                }
            )
        if comment_length:
            errors.append({"error": "archive_comment_not_allowed", "size_bytes": comment_length})
        if disk_number != 0 or central_disk != 0 or entries_on_disk != total_entries:
            errors.append({"error": "multi_disk_zip_not_allowed"})

        central_size = central_size_32
        central_offset = central_offset_32
        central_boundary = eocd_offset
        locator_offset = eocd_offset - 20
        try:
            locator = _read_exact_at(handle, locator_offset, 20) if locator_offset >= 0 else b""
        except (OSError, EOFError):
            locator = b""
        locator_present = (
            len(locator) == 20
            and struct.unpack_from("<I", locator)[0] == _ZIP64_LOCATOR_SIGNATURE
        )

        # Python's writer begins using Zip64 end records at zipfile.ZIP64_LIMIT,
        # while legacy EOCD fields can still contain literal values below the
        # raw 0xffffffff boundary. Locator presence is therefore modeled
        # against Python's writer contract, not only saturated legacy fields.
        if locator_present:
            _locator_sig, zip64_disk, zip64_offset, zip64_disks = struct.unpack("<IIQI", locator)
            if zip64_disk != 0 or zip64_disks != 1:
                errors.append({"error": "multi_disk_zip64_not_allowed"})
            try:
                zip64_header = _read_exact_at(handle, zip64_offset, 56)
            except (OSError, EOFError):
                zip64_header = b""
            if len(zip64_header) != 56 or struct.unpack_from("<I", zip64_header)[0] != _ZIP64_EOCD_SIGNATURE:
                errors.append({"error": "zip64_eocd_missing"})
                return errors
            record_size = struct.unpack_from("<Q", zip64_header, 4)[0]
            if record_size != 44:
                errors.append(
                    {
                        "error": "zip64_extensible_data_not_allowed",
                        "record_size": record_size,
                    }
                )
            zip64_end = zip64_offset + 12 + record_size
            if zip64_end != locator_offset:
                errors.append({"error": "zip64_structure_gap_or_overlap"})
            values = struct.unpack_from("<HHIIQQQQ", zip64_header, 12)
            (
                zip64_made,
                zip64_needed,
                zip64_disk_no,
                zip64_central_disk,
                zip64_entries_disk,
                zip64_entries_total,
                central_size,
                central_offset,
            ) = values
            if zip64_made != 45 or zip64_needed != 45:
                errors.append(
                    {
                        "error": "zip64_version_noncanonical",
                        "made_by": zip64_made,
                        "needed": zip64_needed,
                    }
                )
            if (
                zip64_disk_no != 0
                or zip64_central_disk != 0
                or zip64_entries_disk != zip64_entries_total
            ):
                errors.append({"error": "multi_disk_zip64_not_allowed"})
            zip64_required = (
                zip64_entries_total > zipfile.ZIP_FILECOUNT_LIMIT
                or central_size > zipfile.ZIP64_LIMIT
                or central_offset > zipfile.ZIP64_LIMIT
            )
            if not zip64_required:
                errors.append({"error": "zip64_not_required"})
            expected_legacy_entries = min(zip64_entries_total, _ZIP_UINT16_MAX)
            expected_legacy_size = min(central_size, _ZIP_UINT32_MAX)
            expected_legacy_offset = min(central_offset, _ZIP_UINT32_MAX)
            if entries_on_disk != expected_legacy_entries or total_entries != expected_legacy_entries:
                errors.append({"error": "zip64_legacy_entry_count_noncanonical"})
            if central_size_32 != expected_legacy_size or central_offset_32 != expected_legacy_offset:
                errors.append({"error": "zip64_legacy_directory_fields_noncanonical"})
            total_entries = zip64_entries_total
            central_boundary = zip64_offset
        elif (
            total_entries > zipfile.ZIP_FILECOUNT_LIMIT
            or central_size > zipfile.ZIP64_LIMIT
            or central_offset > zipfile.ZIP64_LIMIT
        ):
            errors.append({"error": "zip64_eocd_required"})

        if total_entries != len(infos):
            errors.append(
                {"error": "zip_entry_count_mismatch", "expected": total_entries, "actual": len(infos)}
            )
        central_end = central_offset + central_size
        if central_end != central_boundary or central_offset < 0 or central_end > file_size:
            errors.append(
                {
                    "error": "zip_central_directory_bounds_invalid",
                    "offset": central_offset,
                    "size": central_size,
                }
            )

        cursor = central_offset
        central_index = 0
        central_zip64_by_offset: dict[int, bool] = {}
        while cursor < min(central_end, file_size):
            if budget is not None:
                budget.check_deadline("validating the ZIP central directory")
            try:
                header = _read_exact_at(handle, cursor, 46)
            except (OSError, EOFError):
                errors.append({"error": "zip_central_record_truncated", "offset": cursor})
                break
            if struct.unpack_from("<I", header)[0] != _ZIP_CENTRAL_SIGNATURE:
                errors.append({"error": "zip_central_directory_gap", "offset": cursor})
                break
            values = struct.unpack("<IHHHHHHIIIHHHHHII", header)
            (
                _signature,
                _made,
                _needed,
                flags,
                compression,
                _mtime,
                _mdate,
                _crc,
                compressed_32,
                uncompressed_32,
                name_length,
                extra_length,
                member_comment_length,
                disk_start,
                _internal_attr,
                _external_attr,
                local_offset_32,
            ) = values
            variable_size = name_length + extra_length + member_comment_length
            try:
                variable = _read_exact_at(handle, cursor + 46, variable_size)
            except (OSError, EOFError):
                errors.append({"error": "zip_central_record_truncated", "offset": cursor})
                break
            raw_name = variable[:name_length]
            extra = variable[name_length : name_length + extra_length]
            try:
                name = _decode_zip_filename(raw_name, flags)
            except UnicodeDecodeError:
                name = "<invalid>"
                errors.append({"error": "zip_member_name_decode_failed", "offset": cursor})
            if member_comment_length:
                errors.append({"error": "member_comments_not_allowed", "member": name})
            if flags & 0x8:
                errors.append({"error": "zip_data_descriptors_not_allowed", "member": name})
            if flags & ~0x800:
                errors.append({"error": "zip_member_flags_not_allowed", "member": name, "flags": flags})
            if compression not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                errors.append({"error": "zip_compression_not_allowed", "member": name, "method": compression})
            info = infos[central_index] if central_index < len(infos) else None
            actual_uncompressed = int(info.file_size) if info is not None else uncompressed_32
            actual_compressed = int(info.compress_size) if info is not None else compressed_32
            actual_offset = int(info.header_offset) if info is not None else local_offset_32
            expected_flags = 0x800 if any(ord(char) > 127 for char in name) else 0
            if flags != expected_flags:
                errors.append(
                    {
                        "error": "zip_member_flags_noncanonical",
                        "member": name,
                        "expected": expected_flags,
                        "actual": flags,
                    }
                )
            if compression != zipfile.ZIP_DEFLATED:
                errors.append(
                    {
                        "error": "zip_member_compression_noncanonical",
                        "member": name,
                        "actual": compression,
                    }
                )
            if _mtime != 0 or _mdate != 33:
                errors.append(
                    {
                        "error": "zip_member_timestamp_noncanonical",
                        "member": name,
                    }
                )
            if disk_start != 0:
                errors.append(
                    {
                        "error": "zip_member_disk_start_invalid",
                        "member": name,
                        "actual": disk_start,
                    }
                )
            expected_sizes_zip64 = (
                _zip64_central_value_required(actual_uncompressed)
                or _zip64_central_value_required(actual_compressed)
            )
            expected_offset_zip64 = _zip64_central_value_required(actual_offset)
            central_uses_zip64 = expected_sizes_zip64 or expected_offset_zip64
            central_zip64_by_offset[actual_offset] = central_uses_zip64
            expected_uncompressed_32 = _ZIP_UINT32_MAX if expected_sizes_zip64 else actual_uncompressed
            expected_compressed_32 = _ZIP_UINT32_MAX if expected_sizes_zip64 else actual_compressed
            expected_offset_32 = _ZIP_UINT32_MAX if expected_offset_zip64 else actual_offset
            if (
                uncompressed_32 != expected_uncompressed_32
                or compressed_32 != expected_compressed_32
                or local_offset_32 != expected_offset_32
                or disk_start != 0
            ):
                errors.append({"error": "zip_central_zip64_layout_noncanonical", "member": name})
            extra_error = _zip64_extra_error(
                extra,
                raw_uncompressed=uncompressed_32,
                raw_compressed=compressed_32,
                actual_uncompressed=actual_uncompressed,
                actual_compressed=actual_compressed,
                raw_offset=local_offset_32,
                actual_offset=actual_offset,
                raw_disk=disk_start,
            )
            if extra_error:
                errors.append(
                    {"error": "zip_unapproved_extra_fields", "member": name, "detail": extra_error}
                )
            if info is not None:
                if name != info.filename:
                    errors.append(
                        {
                            "error": "zip_central_directory_order_mismatch",
                            "expected": info.filename,
                            "actual": name,
                        }
                    )
                expected_made = (int(info.create_system) << 8) | int(info.create_version)
                if (
                    flags != info.flag_bits
                    or compression != info.compress_type
                    or _made != expected_made
                    or _needed != info.extract_version
                    or _crc != info.CRC
                    or _internal_attr != info.internal_attr
                    or _external_attr != info.external_attr
                ):
                    errors.append({"error": "zip_central_metadata_mismatch", "member": name})
                if (
                    info.create_system != 3
                    or info.date_time != (1980, 1, 1, 0, 0, 0)
                    or info.volume != 0
                    or info.internal_attr != 0
                    or (info.external_attr & 0xFFFF) != 0
                ):
                    errors.append({"error": "zip_member_metadata_noncanonical", "member": name})
            cursor += 46 + variable_size
            central_index += 1
        if cursor != central_end:
            errors.append({"error": "zip_central_directory_not_contiguous"})

        ordered_infos = sorted(infos, key=lambda item: item.header_offset)
        expected_local_offset = 0
        for info in ordered_infos:
            if budget is not None:
                budget.check_deadline("validating ZIP local records")
            offset = int(info.header_offset)
            if offset != expected_local_offset:
                errors.append(
                    {
                        "error": "zip_local_member_gap_or_preamble",
                        "member": info.filename,
                        "expected_offset": expected_local_offset,
                        "actual_offset": offset,
                    }
                )
            try:
                header = _read_exact_at(handle, offset, 30)
            except (OSError, EOFError):
                errors.append({"error": "zip_local_header_invalid", "member": info.filename})
                continue
            if struct.unpack_from("<I", header)[0] != _ZIP_LOCAL_SIGNATURE:
                errors.append({"error": "zip_local_header_invalid", "member": info.filename})
                continue
            values = struct.unpack("<IHHHHHIIIHH", header)
            (
                _signature,
                needed,
                flags,
                compression,
                mtime,
                mdate,
                crc,
                compressed_32,
                uncompressed_32,
                name_length,
                extra_length,
            ) = values
            try:
                variable = _read_exact_at(handle, offset + 30, name_length + extra_length)
            except (OSError, EOFError):
                errors.append({"error": "zip_local_header_truncated", "member": info.filename})
                continue
            raw_name = variable[:name_length]
            extra = variable[name_length:]
            try:
                local_name = _decode_zip_filename(raw_name, flags)
            except UnicodeDecodeError:
                local_name = "<invalid>"
                errors.append({"error": "zip_local_name_decode_failed", "member": info.filename})
            if local_name != info.filename:
                errors.append(
                    {
                        "error": "zip_local_central_name_mismatch",
                        "member": info.filename,
                        "local_name": local_name,
                    }
                )
            if (
                flags != info.flag_bits
                or compression != info.compress_type
                or crc != info.CRC
            ):
                errors.append({"error": "zip_local_central_metadata_mismatch", "member": info.filename})
            local_uses_zip64 = compressed_32 == _ZIP_UINT32_MAX or uncompressed_32 == _ZIP_UINT32_MAX
            expected_local_zip64 = _zip64_local_layout_required(int(info.file_size), int(info.compress_size))
            expected_local_version = 45 if expected_local_zip64 else 20
            expected_member_version = 45 if (
                expected_local_zip64 or central_zip64_by_offset.get(offset, False)
            ) else 20
            if needed != expected_local_version or mtime != 0 or mdate != 33:
                errors.append({"error": "zip_local_metadata_noncanonical", "member": info.filename})
            if local_uses_zip64 != expected_local_zip64:
                errors.append({"error": "zip_local_zip64_layout_noncanonical", "member": info.filename})
            elif expected_local_zip64:
                if compressed_32 != _ZIP_UINT32_MAX or uncompressed_32 != _ZIP_UINT32_MAX:
                    errors.append({"error": "zip_local_zip64_layout_noncanonical", "member": info.filename})
            elif compressed_32 != int(info.compress_size) or uncompressed_32 != int(info.file_size):
                errors.append({"error": "zip_local_size_mismatch", "member": info.filename})
            if info.create_version != expected_member_version or info.extract_version != expected_member_version:
                errors.append({"error": "zip_member_metadata_noncanonical", "member": info.filename})
            if flags & 0x8:
                errors.append({"error": "zip_data_descriptors_not_allowed", "member": info.filename})
            extra_error = _zip64_extra_error(
                extra,
                raw_uncompressed=uncompressed_32,
                raw_compressed=compressed_32,
                actual_uncompressed=int(info.file_size),
                actual_compressed=int(info.compress_size),
            )
            if extra_error:
                errors.append(
                    {
                        "error": "zip_unapproved_extra_fields",
                        "member": info.filename,
                        "detail": extra_error,
                    }
                )
            data_offset = offset + 30 + name_length + extra_length
            expected_local_offset = data_offset + int(info.compress_size)
        if expected_local_offset != central_offset:
            errors.append(
                {
                    "error": "zip_local_region_not_contiguous",
                    "expected_central_offset": expected_local_offset,
                    "actual_central_offset": central_offset,
                }
            )
    return errors



def _require_semantic_temp_reserve(
    temp_parent: Path,
    phase: str,
    *,
    additional_bytes: int = 0,
) -> None:
    try:
        free_bytes = int(shutil.disk_usage(temp_parent).free)
    except OSError as exc:
        raise _BundleLimitError(
            "semantic_temp_space_probe_failed",
            f"temporary free-space probe failed while {phase}: {type(exc).__name__}",
        ) from exc
    required_bytes = BUNDLE_SEMANTIC_TEMP_RESERVE_BYTES + max(
        0, int(additional_bytes)
    )
    if free_bytes < required_bytes:
        raise _BundleLimitError(
            "semantic_temp_reserve_eroded",
            f"temporary free space fell below the reserve while {phase}",
        )


def _extract_manifested_root(
    archive: zipfile.ZipFile,
    manifest: dict[str, Any],
    destination: Path,
    *,
    budget: _BundleVerificationBudget,
    temp_parent: Path,
) -> None:
    """Extract only already-validated manifest members into a fresh root.

    This intentionally avoids ``extractall``.  Member names have already passed
    the portable-name and exact-stream checks, but rebuilding paths from
    ``PurePosixPath.parts`` keeps the extraction boundary explicit on every host.
    """
    secure_mkdir(destination)
    file_entries = manifest.get("files")
    if not isinstance(file_entries, list):
        raise ValueError("manifest files are unavailable for semantic verification")
    bytes_since_reserve_check = 0
    for entry in file_entries:
        if not isinstance(entry, dict):
            raise ValueError("manifest file entry is not an object")
        rel = str(entry.get("path") or "")
        if not _zip_member_is_safe(rel):
            raise ValueError(f"unsafe manifest path during semantic extraction: {rel}")
        member = f"{BUNDLE_ROOT_NAME}/{rel}"
        target = destination.joinpath(*PurePosixPath(rel).parts)
        secure_mkdir(target.parent)
        expected_size = entry.get("size_bytes")
        if not isinstance(expected_size, int):
            raise ValueError(f"semantic extraction size is invalid: {rel}")
        written = 0
        _require_semantic_temp_reserve(temp_parent, f"starting extraction of {member}")
        with archive.open(member, "r") as source, target.open("xb") as output:
            while True:
                budget.check_deadline(f"extracting ZIP member {member}")
                chunk = source.read(_BUNDLE_IO_CHUNK_BYTES)
                if not chunk:
                    break
                written += len(chunk)
                if written > expected_size:
                    raise ValueError(f"semantic extraction size exceeded: {rel}")
                budget.consume(len(chunk), f"extracting ZIP member {member}")
                _require_semantic_temp_reserve(
                    temp_parent,
                    f"writing ZIP member {member}",
                    additional_bytes=len(chunk),
                )
                output.write(chunk)
                bytes_since_reserve_check += len(chunk)
                if bytes_since_reserve_check >= _BUNDLE_RESERVE_CHECK_BYTES:
                    output.flush()
                    _require_semantic_temp_reserve(
                        temp_parent, f"extracting ZIP member {member}"
                    )
                    bytes_since_reserve_check = 0
            output.flush()
        _require_semantic_temp_reserve(temp_parent, f"finishing extraction of {member}")
        if written != expected_size or target.stat().st_size != expected_size:
            raise ValueError(f"semantic extraction size mismatch: {rel}")
        mode = entry.get("mode")
        if isinstance(mode, int):
            try:
                os.chmod(target, stat.S_IMODE(mode), follow_symlinks=False)
            except (NotImplementedError, OSError):
                # Windows exposes a narrower chmod model.  Archive mode binding
                # was already verified against the manifest before extraction.
                pass


def _audit_extracted_root(
    embedded_root: Path,
    manifest: dict[str, Any],
) -> list[dict[str, Any]]:
    """Run semantic checks in the disposable worker process."""
    errors: list[dict[str, Any]] = []
    try:
        # Portability is checked first so later verifiers never follow an
        # absolute URI or config path outside the temporary extraction root.
        try:
            portability = audit_portable_metadata(embedded_root)
        except (OSError, ValueError, RuntimeError, sqlite3.Error, json.JSONDecodeError) as exc:
            return [
                {
                    "error": "embedded_root_portability_audit_failed",
                    "detail": redact_text_secrets(str(exc)),
                }
            ]
        if not portability.get("ok") or not portability.get("complete", True):
            return [
                {
                    "error": "embedded_root_portability_audit_unhealthy",
                    "finding_count": portability.get("finding_count"),
                    "complete": portability.get("complete", True),
                }
            ]

        try:
            config = load_config(embedded_root)
            actual_redaction_profile = str(
                config.get("security", {}).get("redaction_profile") or "portable"
            )
        except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
            return [
                {
                    "error": "embedded_root_config_invalid",
                    "detail": redact_text_secrets(str(exc)),
                }
            ]
        if actual_redaction_profile != manifest.get("redaction_profile"):
            errors.append(
                {
                    "error": "embedded_root_redaction_profile_mismatch",
                    "expected": manifest.get("redaction_profile"),
                    "actual": actual_redaction_profile,
                }
            )

        try:
            _claim_disposable_bundle_root(embedded_root)
        except (OSError, ValueError, RuntimeError) as exc:
            return [
                {
                    "error": "embedded_root_disposable_writer_claim_failed",
                    "detail": redact_text_secrets(str(exc)),
                }
            ]

        proof_count = _proof_pack_count(embedded_root)
        try:
            # Secret scanning is performed exactly once below. The root verifier
            # still checks doctor/search/proofs/stale operations and the normal
            # artifact sample, while the full immutable ledger is checked after.
            root_verification = verify_root(
                embedded_root,
                strict=True,
                verify_recent_proof_packs=proof_count,
                run_restore_drill=False,
                scan_secrets=False,
                allowed_roots=[embedded_root],
                allow_missing_alias_key=str(manifest.get("profile") or "") == "shareable",
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error, json.JSONDecodeError) as exc:
            return [
                {
                    "error": "embedded_root_verification_failed",
                    "detail": redact_text_secrets(str(exc)),
                }
            ]
        if not root_verification.get("ok"):
            failed_checks = _bounded_diagnostic_sample(
                (
                    str(item.get("name"))
                    for item in root_verification.get("checks") or []
                    if not item.get("ok")
                )
            )
            errors.append(
                {
                    "error": "embedded_root_verification_unhealthy",
                    "failed_checks": failed_checks,
                }
            )

        try:
            secret_audit = audit_secrets(embedded_root, create=False)
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            return errors + [
                {
                    "error": "embedded_root_secret_audit_failed",
                    "detail": redact_text_secrets(str(exc)),
                }
            ]
        if not secret_audit.get("ok") or not secret_audit.get("complete", True):
            errors.append(
                {
                    "error": "embedded_root_secret_audit_unhealthy",
                    "finding_count": secret_audit.get("finding_count"),
                    "allowlisted_findings": secret_audit.get("allowlisted_findings"),
                    "complete": secret_audit.get("complete", True),
                }
            )
        actual_findings = int(secret_audit.get("finding_count") or 0)
        actual_allowlisted = int(secret_audit.get("allowlisted_findings") or 0)
        if manifest.get("profile") == "shareable" and actual_allowlisted:
            errors.append(
                {
                    "error": "embedded_shareable_root_contains_allowlisted_findings",
                    "actual": actual_allowlisted,
                }
            )

        try:
            artifact_count = _artifact_row_count(embedded_root)
            artifact_verification = _verify_artifact_ledger(
                embedded_root,
                limit=max(1, artifact_count),
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error) as exc:
            return errors + [
                {
                    "error": "embedded_root_artifact_verification_failed",
                    "detail": redact_text_secrets(str(exc)),
                }
            ]
        if not artifact_verification.get("ok"):
            errors.append(
                {
                    "error": "embedded_root_artifact_ledger_unhealthy",
                    "missing": artifact_verification.get("missing"),
                    "mismatch_count": artifact_verification.get("mismatch_count"),
                    "absolute_internal_uri_count": artifact_verification.get(
                        "absolute_internal_uri_count"
                    ),
                }
            )

        preflight = manifest.get("preflight")
        if isinstance(preflight, dict):
            for field, actual in (
                ("proof_pack_count", proof_count),
                ("artifact_count", artifact_count),
                ("secret_finding_count", actual_findings),
                ("secret_allowlisted_finding_count", actual_allowlisted),
            ):
                if preflight.get(field) != actual:
                    errors.append(
                        {
                            "error": "embedded_root_preflight_count_mismatch",
                            "field": field,
                            "expected": preflight.get(field),
                            "actual": actual,
                        }
                    )
    except Exception as exc:
        return errors + [
            {
                "error": "embedded_root_audit_failed",
                "detail": redact_text_secrets(str(exc)),
            }
        ]
    return errors


def _semantic_worker_cli(
    embedded_root_text: str,
    manifest_path_text: str,
    result_path_text: str,
) -> int:
    """Private subprocess entrypoint for hard-bounded semantic verification."""
    try:
        with Path(manifest_path_text).open("rb") as manifest_file:
            manifest_bytes = manifest_file.read(_BUNDLE_MANIFEST_MAX_BYTES + 1)
        if len(manifest_bytes) > _BUNDLE_MANIFEST_MAX_BYTES:
            raise ValueError("semantic worker manifest exceeds its byte limit")
        manifest = _strict_json_loads(manifest_bytes.decode("utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("semantic worker manifest must be an object")
        errors = _audit_extracted_root(Path(embedded_root_text), manifest)
    except Exception as exc:
        errors = [
            {
                "error": "embedded_root_audit_worker_failed",
                "detail": redact_text_secrets(f"{type(exc).__name__}: {exc}"),
            }
        ]
    payload = json.dumps(
        errors,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(payload) > _BUNDLE_SEMANTIC_RESULT_MAX_BYTES:
        payload = b'[{"error":"embedded_root_audit_result_too_large"}]'
    try:
        result_path = Path(result_path_text)
        _require_semantic_temp_reserve(
            result_path.parent,
            "writing embedded-root semantic result",
            additional_bytes=len(payload),
        )
        with result_path.open("xb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
    except (OSError, _BundleLimitError):
        return 1
    return 0


def _stop_semantic_worker(process: subprocess.Popen[bytes]) -> None:
    """Reap one semantic child; never return while it remains live."""
    if process.poll() is not None:
        process.wait(timeout=0)
        return
    try:
        process.terminate()
    except OSError:
        if process.poll() is None:
            raise
    try:
        process.wait(timeout=2)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        process.kill()
    except OSError:
        if process.poll() is None:
            raise
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("semantic verification child could not be reaped") from exc


def _run_extracted_root_audit(
    embedded_root: Path,
    manifest: dict[str, Any],
    *,
    budget: _BundleVerificationBudget,
    temp_parent: Path,
    worker_command: list[str] | None = None,
) -> list[dict[str, Any]]:
    control_dir = embedded_root.parent
    manifest_path = control_dir / "semantic-worker-manifest.json"
    result_path = control_dir / "semantic-worker-result.json"
    manifest_payload = json.dumps(
        manifest,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(manifest_payload) > _BUNDLE_MANIFEST_MAX_BYTES:
        return [{"error": "embedded_root_audit_worker_manifest_too_large"}]
    try:
        budget.check_deadline("preparing embedded-root semantic worker")
        manifest_path.unlink(missing_ok=True)
        result_path.unlink(missing_ok=True)
        _require_semantic_temp_reserve(
            temp_parent,
            "writing embedded-root semantic controls",
            additional_bytes=(
                len(manifest_payload) + _BUNDLE_SEMANTIC_RESULT_MAX_BYTES
            ),
        )
        with manifest_path.open("xb") as manifest_file:
            manifest_file.write(manifest_payload)
            manifest_file.flush()
            os.fsync(manifest_file.fileno())
        _require_semantic_temp_reserve(
            temp_parent,
            "starting embedded-root semantic worker",
            additional_bytes=_BUNDLE_SEMANTIC_RESULT_MAX_BYTES,
        )
    except _BundleLimitError:
        raise
    except OSError as exc:
        return [
            {
                "error": "embedded_root_audit_worker_setup_failed",
                "detail": redact_text_secrets(str(exc)),
            }
        ]
    source_root = str(Path(__file__).resolve().parents[2])
    if worker_command is None:
        worker_code = (
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "from continuum.core.bundle import _semantic_worker_cli; "
            "raise SystemExit(_semantic_worker_cli(sys.argv[2], sys.argv[3], sys.argv[4]))"
        )
        worker_command = [
            sys.executable,
            "-I",
            "-S",
            "-c",
            worker_code,
            source_root,
            str(embedded_root),
            str(manifest_path),
            str(result_path),
        ]
    worker_env = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("PYTHON")
    }
    try:
        process = subprocess.Popen(
            worker_command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            env=worker_env,
            cwd=source_root,
        )
    except OSError as exc:
        return [
            {
                "error": "embedded_root_audit_worker_start_failed",
                "detail": redact_text_secrets(str(exc)),
            }
        ]
    try:
        while process.poll() is None:
            budget.check_deadline("running embedded-root semantic checks")
            _require_semantic_temp_reserve(
                temp_parent, "running embedded-root semantic checks"
            )
            remaining = budget.deadline - time.monotonic()
            if remaining <= 0:
                raise _BundleLimitError(
                    "bundle_verification_timeout",
                    "bundle verification exceeded its semantic-audit deadline",
                )
            try:
                process.wait(timeout=min(0.1, remaining))
            except subprocess.TimeoutExpired:
                continue
    except BaseException as exc:
        try:
            _stop_semantic_worker(process)
        except Exception as cleanup_exc:
            if hasattr(exc, "add_note"):
                exc.add_note(f"semantic worker cleanup failed: {cleanup_exc}")
        raise
    _stop_semantic_worker(process)
    _require_semantic_temp_reserve(temp_parent, "finishing embedded-root semantic checks")
    if process.returncode != 0:
        return [{"error": "embedded_root_audit_worker_failed"}]
    try:
        with result_path.open("rb") as result_file:
            result_bytes = result_file.read(_BUNDLE_SEMANTIC_RESULT_MAX_BYTES + 1)
    except OSError as exc:
        return [
            {
                "error": "embedded_root_audit_result_missing",
                "detail": redact_text_secrets(str(exc)),
            }
        ]
    if len(result_bytes) > _BUNDLE_SEMANTIC_RESULT_MAX_BYTES:
        return [{"error": "embedded_root_audit_result_too_large"}]
    try:
        result = _strict_json_loads(result_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        return [
            {
                "error": "embedded_root_audit_result_invalid",
                "detail": redact_text_secrets(str(exc)),
            }
        ]
    if not isinstance(result, list) or any(not isinstance(item, dict) for item in result):
        return [{"error": "embedded_root_audit_result_invalid"}]
    return result


def _embedded_root_semantic_errors(
    archive: zipfile.ZipFile,
    manifest: dict[str, Any],
    *,
    budget: _BundleVerificationBudget,
    temp_parent: Path,
) -> list[dict[str, Any]]:
    """Extract in-process, then hard-bound every semantic check in one child."""
    budget.check_deadline("starting embedded-root verification")
    with tempfile.TemporaryDirectory(
        prefix="continuum-bundle-verify-",
        dir=temp_parent,
    ) as tmp:
        embedded_root = Path(tmp) / BUNDLE_ROOT_NAME
        try:
            _extract_manifested_root(
                archive,
                manifest,
                embedded_root,
                budget=budget,
                temp_parent=temp_parent,
            )
        except _BundleLimitError:
            raise
        except (
            OSError,
            ValueError,
            RuntimeError,
            KeyError,
            zipfile.BadZipFile,
            NotImplementedError,
            zlib.error,
        ) as exc:
            return [
                {
                    "error": "embedded_root_extraction_failed",
                    "detail": redact_text_secrets(str(exc)),
                }
            ]
        _require_semantic_temp_reserve(temp_parent, "starting semantic audit")
        errors = _run_extracted_root_audit(
            embedded_root,
            manifest,
            budget=budget,
            temp_parent=temp_parent,
        )
    budget.check_deadline("finishing embedded-root verification")
    return errors


def _verify_root_bundle_impl(
    bundle_path: Path,
    *,
    _resources: _BundleVerifierResources,
    verify_embedded_root: bool = True,
    max_entries: int = BUNDLE_DEFAULT_MAX_ENTRIES,
    max_expanded_bytes: int = BUNDLE_DEFAULT_MAX_EXPANDED_BYTES,
    max_member_bytes: int | None = None,
    max_compression_ratio: int = BUNDLE_DEFAULT_MAX_COMPRESSION_RATIO,
    max_central_directory_bytes: int = BUNDLE_DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES,
    timeout_seconds: int = BUNDLE_DEFAULT_VERIFY_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Verify one bounded ZIP envelope and, by default, its embedded root."""
    path = Path(bundle_path)
    max_entries = _validated_bundle_limit(
        "max_entries", max_entries, maximum=BUNDLE_ABSOLUTE_MAX_ENTRIES
    )
    max_expanded_bytes = _validated_bundle_limit(
        "max_expanded_bytes",
        max_expanded_bytes,
        maximum=BUNDLE_ABSOLUTE_MAX_EXPANDED_BYTES,
    )
    effective_max_member_bytes = _validated_bundle_limit(
        "max_member_bytes",
        max_expanded_bytes if max_member_bytes is None else max_member_bytes,
        maximum=BUNDLE_ABSOLUTE_MAX_EXPANDED_BYTES,
    )
    max_compression_ratio = _validated_bundle_limit(
        "max_compression_ratio",
        max_compression_ratio,
        maximum=BUNDLE_ABSOLUTE_MAX_COMPRESSION_RATIO,
    )
    max_central_directory_bytes = _validated_bundle_limit(
        "max_central_directory_bytes",
        max_central_directory_bytes,
        maximum=BUNDLE_ABSOLUTE_MAX_CENTRAL_DIRECTORY_BYTES,
    )
    timeout_seconds = _validated_bundle_limit(
        "timeout_seconds",
        timeout_seconds,
        maximum=BUNDLE_MAX_VERIFY_TIMEOUT_SECONDS,
    )
    limits = {
        "max_entries": max_entries,
        "max_expanded_bytes": max_expanded_bytes,
        "max_member_bytes": effective_max_member_bytes,
        "max_compression_ratio": max_compression_ratio,
        "max_central_directory_bytes": max_central_directory_bytes,
        "timeout_seconds": timeout_seconds,
        "semantic_temp_reserve_bytes": BUNDLE_SEMANTIC_TEMP_RESERVE_BYTES,
    }
    errors = _BoundedBundleErrors()
    manifest: dict[str, Any] | None = None
    bundle_sha256: str | None = None
    bundle_size_bytes: int | None = None
    archive: zipfile.ZipFile | None = None
    raw_archive: Any | None = None
    initial_handle_stat: os.stat_result | None = None
    identity_checked = False
    content_checked = False
    budget: _BundleVerificationBudget | None = None

    def result() -> dict[str, Any]:
        nonlocal content_checked, identity_checked
        if (
            not content_checked
            and bundle_sha256 is not None
            and budget is not None
            and raw_archive is not None
            and not raw_archive.closed
        ):
            content_checked = True
            try:
                current_sha256 = _bounded_bundle_sha256(raw_archive, budget)
                if current_sha256 != bundle_sha256:
                    errors.append({"error": "bundle_file_identity_changed"})
            except _BundleLimitError as exc:
                errors.append({"error": exc.code, "detail": exc.detail})
            except OSError as exc:
                errors.append(
                    {
                        "error": "bundle_file_content_check_failed",
                        "detail": redact_text_secrets(str(exc)),
                    }
                )
        if (
            not identity_checked
            and raw_archive is not None
            and not raw_archive.closed
            and initial_handle_stat is not None
        ):
            identity_checked = True
            try:
                final_handle_stat = os.fstat(raw_archive.fileno())
                current_path_stat = path.stat(follow_symlinks=False)
                stable_handle = (
                    os.path.samestat(initial_handle_stat, final_handle_stat)
                    and initial_handle_stat.st_size == final_handle_stat.st_size
                    and initial_handle_stat.st_mtime_ns == final_handle_stat.st_mtime_ns
                    and initial_handle_stat.st_ctime_ns == final_handle_stat.st_ctime_ns
                )
                stable_path = (
                    stat.S_ISREG(current_path_stat.st_mode)
                    and not _is_link_like(path)
                    and os.path.samestat(final_handle_stat, current_path_stat)
                )
                if not stable_handle or not stable_path:
                    errors.append({"error": "bundle_file_identity_changed"})
            except OSError as exc:
                errors.append(
                    {
                        "error": "bundle_file_identity_check_failed",
                        "detail": redact_text_secrets(str(exc)),
                    }
                )
        output = {
            "schema": "epic_continuum.root_bundle_verification.v1",
            "ok": not errors,
            "bundle_uri": str(path),
            "bundle_sha256": bundle_sha256,
            "bundle_size_bytes": bundle_size_bytes,
            "bundle_id": manifest.get("bundle_id") if isinstance(manifest, dict) else None,
            "profile": manifest.get("profile") if isinstance(manifest, dict) else None,
            "file_count": manifest.get("file_count") if isinstance(manifest, dict) else None,
            "verify_embedded_root": bool(verify_embedded_root),
            "verification_limits": limits,
            "error_count": errors.total_count,
            "errors": redact_value_secrets(errors),
        }
        return output

    try:
        initial_path_stat = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        errors.append({"error": "bundle_missing"})
        return result()
    except OSError as exc:
        errors.append({"error": "bundle_stat_failed", "detail": redact_text_secrets(str(exc))})
        return result()
    if not stat.S_ISREG(initial_path_stat.st_mode) or _is_link_like(path):
        errors.append({"error": "bundle_not_regular_file"})
        return result()
    try:
        raw_archive = _open_bundle_read_handle(path)
        _resources.raw_archive = raw_archive
        initial_handle_stat = os.fstat(raw_archive.fileno())
    except OSError as exc:
        errors.append({"error": "bundle_raw_open_failed", "detail": redact_text_secrets(str(exc))})
        return result()
    if (
        not stat.S_ISREG(initial_handle_stat.st_mode)
        or not os.path.samestat(initial_path_stat, initial_handle_stat)
    ):
        errors.append({"error": "bundle_file_identity_changed"})
        return result()
    bundle_size_bytes = int(initial_handle_stat.st_size)

    budget = _BundleVerificationBudget(
        deadline=time.monotonic() + timeout_seconds,
        max_work_bytes=(
            bundle_size_bytes * 2
            + max_expanded_bytes * (2 if verify_embedded_root else 1)
            + _BUNDLE_IO_CHUNK_BYTES
        ),
    )
    try:
        budget.check_deadline("probing the ZIP archive")
        is_zip = zipfile.is_zipfile(raw_archive)
    except _BundleLimitError as exc:
        errors.append({"error": exc.code, "detail": exc.detail})
        return result()
    except (OSError, ValueError, RuntimeError, UnicodeError, OverflowError, struct.error) as exc:
        errors.append({"error": "bundle_probe_failed", "detail": redact_text_secrets(str(exc))})
        return result()
    if not is_zip:
        errors.append({"error": "not_a_zip_archive"})
        return result()

    try:
        preflight = _read_bundle_zip_preflight(
            path,
            budget=budget,
            raw_handle=raw_archive,
            max_entries=max_entries,
            max_central_directory_bytes=max_central_directory_bytes,
        )
    except _BundleLimitError as exc:
        errors.append({"error": exc.code, "detail": exc.detail})
        return result()
    except (OSError, EOFError, ValueError, OverflowError, struct.error) as exc:
        errors.append(
            {"error": "zip_preflight_failed", "detail": redact_text_secrets(str(exc))}
        )
        return result()

    if preflight.entry_count > max_entries:
        errors.append(
            {
                "error": "bundle_entry_count_too_large",
                "count": preflight.entry_count,
                "maximum": max_entries,
            }
        )
    if preflight.central_directory_size > max_central_directory_bytes:
        errors.append(
            {
                "error": "bundle_central_directory_too_large",
                "size_bytes": preflight.central_directory_size,
                "maximum": max_central_directory_bytes,
            }
        )
    # A canonical archive duplicates central-directory names in local headers.
    # This derived physical bound prevents a huge invalid/trailing file from
    # reaching the whole-file hash even when its declared expanded size is tiny.
    max_archive_bytes = (
        _deflate_compressed_size_bound(max_expanded_bytes, max_entries)
        + 2 * max_central_directory_bytes
        + max_entries * 128
        + _BUNDLE_IO_CHUNK_BYTES
    )
    if preflight.file_size > max_archive_bytes:
        errors.append(
            {
                "error": "bundle_archive_size_too_large",
                "size_bytes": preflight.file_size,
                "maximum": max_archive_bytes,
            }
        )
    if errors:
        return result()

    try:
        bundle_sha256 = _bounded_bundle_sha256(raw_archive, budget)
    except _BundleLimitError as exc:
        errors.append({"error": exc.code, "detail": exc.detail})
        return result()
    except OSError as exc:
        errors.append({"error": "bundle_hash_failed", "detail": redact_text_secrets(str(exc))})
        return result()

    try:
        archive = zipfile.ZipFile(raw_archive, "r")
        _resources.archive = archive
    except (
        OSError,
        ValueError,
        RuntimeError,
        UnicodeError,
        OverflowError,
        struct.error,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
    ) as exc:
        errors.append({"error": "bundle_open_failed", "detail": redact_text_secrets(str(exc))})
        return result()

    with archive:
        try:
            budget.check_deadline("reading ZIP metadata")
            infos = archive.infolist()
            _zip_envelope_errors(
                path,
                infos,
                budget=budget,
                raw_handle=raw_archive,
                _errors=errors,
            )
        except _BundleLimitError as exc:
            errors.append({"error": exc.code, "detail": exc.detail})
            return result()
        except (OSError, EOFError, ValueError, OverflowError, struct.error) as exc:
            errors.append(
                {
                    "error": "zip_envelope_validation_failed",
                    "detail": redact_text_secrets(str(exc)),
                }
            )
            return result()
        if len(infos) != preflight.entry_count:
            errors.append(
                {
                    "error": "zip_preflight_entry_count_mismatch",
                    "preflight": preflight.entry_count,
                    "actual": len(infos),
                }
            )
        if not _is_nondecreasing_text(info.filename for info in infos):
            errors.append({"error": "zip_member_order_noncanonical"})
        name_counts = Counter(info.filename for info in infos)
        duplicate_names = _bounded_diagnostic_sample(
            (name for name, count in name_counts.items() if count > 1)
        )
        if duplicate_names:
            errors.append(
                {"error": "duplicate_member_names", "members": duplicate_names}
            )
        unsafe_names = _bounded_diagnostic_sample(
            (
                info.filename
                for info in infos
                if not _zip_member_is_safe(info.filename)
            )
        )
        if unsafe_names:
            errors.append({"error": "unsafe_member_names", "members": unsafe_names})
        portable_collisions = _portable_name_collisions(
            info.filename for info in infos
        )
        if portable_collisions:
            errors.append(
                {
                    "error": "portable_member_name_collisions",
                    "collisions": portable_collisions,
                }
            )

        directory_members = _bounded_diagnostic_sample(
            (info.filename for info in infos if info.is_dir())
        )
        if directory_members:
            errors.append(
                {"error": "directory_members_not_allowed", "members": directory_members}
            )
        encrypted_members = _bounded_diagnostic_sample(
            (info.filename for info in infos if info.flag_bits & 0x1)
        )
        if encrypted_members:
            errors.append(
                {"error": "encrypted_members_not_allowed", "members": encrypted_members}
            )
        non_unix_members = _bounded_diagnostic_sample(
            (info.filename for info in infos if info.create_system != 3)
        )
        if non_unix_members:
            errors.append(
                {"error": "zip_member_platform_invalid", "members": non_unix_members}
            )
        non_regular = _bounded_diagnostic_sample(
            (
                {"member": info.filename, "kind": kind}
                for info in infos
                if (kind := _zip_member_type(info))
                not in {"regular_or_unspecified", "directory"}
            )
        )
        if non_regular:
            errors.append({"error": "non_regular_bundle_members", "members": non_regular})

        declared_expanded_size = sum(max(0, int(info.file_size)) for info in infos)
        declared_compressed_size = sum(max(0, int(info.compress_size)) for info in infos)
        if declared_expanded_size > max_expanded_bytes:
            errors.append(
                {
                    "error": "bundle_expanded_size_too_large",
                    "size_bytes": declared_expanded_size,
                    "maximum": max_expanded_bytes,
                }
            )
        oversized_members: list[dict[str, Any]] = []
        for info in infos:
            if int(info.file_size) <= effective_max_member_bytes:
                continue
            oversized_members.append(
                {"member": info.filename, "size_bytes": int(info.file_size)}
            )
            if len(oversized_members) == 20:
                break
        if oversized_members:
            errors.append(
                {
                    "error": "bundle_member_too_large",
                    "maximum": effective_max_member_bytes,
                    "members": oversized_members,
                }
            )
        excessive_ratio_members: list[dict[str, Any]] = []
        for info in infos:
            if int(info.file_size) <= max_compression_ratio * max(
                1, int(info.compress_size)
            ):
                continue
            excessive_ratio_members.append(
                {
                    "member": info.filename,
                    "expanded_bytes": int(info.file_size),
                    "compressed_bytes": int(info.compress_size),
                }
            )
            if len(excessive_ratio_members) == 20:
                break
        if excessive_ratio_members:
            errors.append(
                {
                    "error": "bundle_compression_ratio_too_large",
                    "maximum": max_compression_ratio,
                    "members": excessive_ratio_members,
                }
            )
        if declared_expanded_size > max_compression_ratio * max(1, declared_compressed_size):
            errors.append(
                {
                    "error": "bundle_total_compression_ratio_too_large",
                    "maximum": max_compression_ratio,
                    "expanded_bytes": declared_expanded_size,
                    "compressed_bytes": declared_compressed_size,
                }
            )

        # Do not decode a manifest or inflate a single member after any cheap
        # envelope/resource rejection.
        if errors:
            return result()

        manifest_member = f"{BUNDLE_ROOT_NAME}/{BUNDLE_MANIFEST_NAME}"
        if name_counts.get(manifest_member, 0) != 1:
            errors.append(
                {
                    "error": "manifest_member_count",
                    "member": manifest_member,
                    "count": name_counts.get(manifest_member, 0),
                }
            )
        else:
            info = archive.getinfo(manifest_member)
            if info.create_system == 3:
                manifest_mode = stat.S_IMODE(info.external_attr >> 16)
                if manifest_mode != 0o644:
                    errors.append(
                        {
                            "error": "manifest_member_mode_noncanonical",
                            "expected": 0o644,
                            "actual": manifest_mode,
                        }
                    )
            if info.file_size > _BUNDLE_MANIFEST_MAX_BYTES:
                errors.append({"error": "manifest_too_large", "size_bytes": info.file_size})
            else:
                try:
                    manifest_bytes, _manifest_hash_value, _manifest_size, stream_error = (
                        _read_zip_member_exact(
                            raw_archive,
                            info,
                            collect=True,
                            budget=budget,
                        )
                    )
                    if stream_error:
                        errors.append(
                            {
                                "error": "bundle_member_stream_invalid",
                                "path": BUNDLE_MANIFEST_NAME,
                                "detail": stream_error,
                            }
                        )
                    elif manifest_bytes is not None:
                        manifest = _strict_json_loads(manifest_bytes.decode("utf-8"))
                        decoded_files = (
                            manifest.get("files") if isinstance(manifest, dict) else None
                        )
                        if isinstance(decoded_files, list) and len(decoded_files) > max_entries:
                            errors.append(
                                {
                                    "error": "manifest_file_count_too_large",
                                    "count": len(decoded_files),
                                    "maximum": max_entries,
                                }
                            )
                            # Drop the hostile object before canonicalization,
                            # secret scanning, portability walking, or hashing.
                            manifest = None
                        else:
                            canonical_manifest_bytes = (
                                json.dumps(
                                    manifest,
                                    ensure_ascii=True,
                                    indent=2,
                                    sort_keys=True,
                                )
                                + "\n"
                            ).encode("utf-8")
                            if manifest_bytes != canonical_manifest_bytes:
                                errors.append({"error": "manifest_serialization_noncanonical"})
                except _BundleLimitError as exc:
                    errors.append({"error": exc.code, "detail": exc.detail})
                except (
                    UnicodeDecodeError, ValueError, RuntimeError, OSError, EOFError,
                    zipfile.BadZipFile, NotImplementedError, zlib.error,
                ) as exc:
                    errors.append(
                        {
                            "error": "manifest_decode_failed",
                            "detail": redact_text_secrets(str(exc)),
                        }
                    )

        if isinstance(manifest, dict):
            _manifest_structure_errors(manifest, _errors=errors)
            _manifest_semantic_errors(manifest, _errors=errors)
            manifest_secret_findings = scan_value_for_secrets(
                manifest, scope="bundle_manifest", max_findings=20
            )
            if manifest_secret_findings:
                errors.append(
                    {
                        "error": "manifest_secret_policy_violation",
                        "finding_count": len(manifest_secret_findings),
                        "finding_types": sorted(
                            {str(item.get("type") or "unknown") for item in manifest_secret_findings}
                        ),
                        "metadata_paths": [
                            str(item.get("metadata_path"))
                            for item in manifest_secret_findings[:20]
                            if item.get("metadata_path")
                        ],
                    }
                )
            (
                manifest_portability_findings,
                manifest_portability_truncated,
            ) = _portable_metadata_findings(manifest, max_findings=20)
            if manifest_portability_findings:
                errors.append(
                    {
                        "error": "manifest_nonportable_metadata",
                        "finding_count": len(manifest_portability_findings),
                        "findings": manifest_portability_findings,
                        "truncated": manifest_portability_truncated,
                    }
                )
            if manifest.get("schema") != BUNDLE_MANIFEST_SCHEMA:
                errors.append(
                    {
                        "error": "manifest_schema_mismatch",
                        "actual": manifest.get("schema"),
                        "expected": BUNDLE_MANIFEST_SCHEMA,
                    }
                )
            stored_manifest_hash = manifest.get("manifest_hash")
            actual_manifest_hash = _manifest_hash(manifest)
            if stored_manifest_hash != actual_manifest_hash:
                errors.append(
                    {
                        "error": "manifest_hash_mismatch",
                        "expected": stored_manifest_hash,
                        "actual": actual_manifest_hash,
                    }
                )
            file_entries = manifest.get("files")
            if not isinstance(file_entries, list):
                errors.append({"error": "manifest_files_not_list"})
                file_entries = []
            if len(file_entries) > max_entries:
                errors.append(
                    {
                        "error": "manifest_file_count_too_large",
                        "count": len(file_entries),
                        "maximum": max_entries,
                    }
                )
                file_entries = []

            listed_paths: list[str] = []
            computed_total = 0
            for index, entry in enumerate(file_entries if not errors else []):
                if not isinstance(entry, dict):
                    errors.append({"error": "manifest_file_entry_not_object", "index": index})
                    continue
                rel = str(entry.get("path") or "")
                if not _zip_member_is_safe(rel) or rel.startswith(f"{BUNDLE_ROOT_NAME}/"):
                    errors.append({"error": "unsafe_manifest_path", "index": index, "path": rel})
                    continue
                listed_paths.append(rel)
                member = f"{BUNDLE_ROOT_NAME}/{rel}"
                if name_counts.get(member, 0) != 1:
                    errors.append(
                        {
                            "error": "bundle_member_count",
                            "path": rel,
                            "count": name_counts.get(member, 0),
                        }
                    )
                    continue
                info = archive.getinfo(member)
                try:
                    _member_data, actual_hash, actual_size, stream_error = _read_zip_member_exact(
                        raw_archive,
                        info,
                        collect=False,
                        budget=budget,
                    )
                except _BundleLimitError as exc:
                    errors.append({"error": exc.code, "detail": exc.detail})
                    return result()
                except OSError as exc:
                    errors.append(
                        {
                            "error": "bundle_member_read_failed",
                            "path": rel,
                            "detail": redact_text_secrets(str(exc)),
                        }
                    )
                    continue
                if stream_error or actual_hash is None:
                    errors.append(
                        {
                            "error": "bundle_member_stream_invalid",
                            "path": rel,
                            "detail": stream_error or "hash_unavailable",
                        }
                    )
                    continue
                computed_total += actual_size
                if actual_hash != entry.get("sha256"):
                    errors.append(
                        {
                            "error": "bundle_member_hash_mismatch",
                            "path": rel,
                            "expected": entry.get("sha256"),
                            "actual": actual_hash,
                        }
                    )
                if actual_size != entry.get("size_bytes"):
                    errors.append(
                        {
                            "error": "bundle_member_size_mismatch",
                            "path": rel,
                            "expected": entry.get("size_bytes"),
                            "actual": actual_size,
                        }
                    )
                if info.create_system == 3 and isinstance(entry.get("mode"), int):
                    actual_mode = stat.S_IMODE(info.external_attr >> 16)
                    if actual_mode != entry.get("mode"):
                        errors.append(
                            {
                                "error": "bundle_member_mode_mismatch",
                                "path": rel,
                                "expected": entry.get("mode"),
                                "actual": actual_mode,
                            }
                        )

            listed_counts = Counter(listed_paths)
            duplicate_listed = _bounded_diagnostic_sample(
                (item for item, count in listed_counts.items() if count > 1)
            )
            if duplicate_listed:
                errors.append(
                    {"error": "duplicate_manifest_paths", "paths": duplicate_listed}
                )
            listed_collisions = _portable_name_collisions(listed_paths)
            if listed_collisions:
                errors.append(
                    {
                        "error": "portable_manifest_path_collisions",
                        "collisions": listed_collisions,
                    }
                )
            required_paths = {"catalog/catalog.sqlite3", "config/continuum.config.json"}
            missing_required = sorted(required_paths - set(listed_paths))
            if missing_required:
                errors.append({"error": "required_root_members_missing", "members": missing_required})
            expected_members = {f"{BUNDLE_ROOT_NAME}/{rel}" for rel in listed_paths}
            expected_members.add(manifest_member)
            actual_file_members = {info.filename for info in infos if not info.is_dir()}
            unexpected = _bounded_absent_text_sample(
                (info.filename for info in infos if not info.is_dir()),
                expected_members,
            )
            missing = _bounded_absent_text_sample(
                chain(
                    (manifest_member,),
                    (f"{BUNDLE_ROOT_NAME}/{rel}" for rel in listed_paths),
                ),
                actual_file_members,
            )
            if unexpected:
                errors.append({"error": "unlisted_bundle_members", "members": unexpected})
            if missing:
                errors.append({"error": "missing_bundle_members", "members": missing})
            if manifest.get("file_count") != len(file_entries):
                errors.append(
                    {
                        "error": "manifest_file_count_mismatch",
                        "expected": manifest.get("file_count"),
                        "actual": len(file_entries),
                    }
                )
            if manifest.get("total_size_bytes") != computed_total:
                errors.append(
                    {
                        "error": "manifest_total_size_mismatch",
                        "expected": manifest.get("total_size_bytes"),
                        "actual": computed_total,
                    }
                )
        elif manifest is not None:
            errors.append({"error": "manifest_not_object"})

        if isinstance(manifest, dict) and not errors and verify_embedded_root:
            temp_parent = Path(tempfile.gettempdir())
            semantic_control_bytes = len(
                json.dumps(
                    manifest,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            semantic_output_bytes = _BUNDLE_SEMANTIC_RESULT_MAX_BYTES
            required_temp_bytes = (
                computed_total
                + BUNDLE_SEMANTIC_TEMP_RESERVE_BYTES
                + semantic_control_bytes
                + semantic_output_bytes
            )
            try:
                budget.check_deadline("checking semantic-verification free space")
                free_temp_bytes = int(shutil.disk_usage(temp_parent).free)
            except _BundleLimitError as exc:
                errors.append({"error": exc.code, "detail": exc.detail})
            except OSError as exc:
                errors.append(
                    {
                        "error": "semantic_temp_space_probe_failed",
                        "detail": redact_text_secrets(str(exc)),
                    }
                )
            else:
                if free_temp_bytes < required_temp_bytes:
                    errors.append(
                        {
                            "error": "semantic_temp_space_insufficient",
                            "free_bytes": free_temp_bytes,
                            "required_bytes": required_temp_bytes,
                            "payload_bytes": computed_total,
                            "reserve_bytes": BUNDLE_SEMANTIC_TEMP_RESERVE_BYTES,
                            "control_bytes": semantic_control_bytes,
                            "result_bytes": semantic_output_bytes,
                        }
                    )
            if not errors:
                try:
                    errors.extend(
                        _embedded_root_semantic_errors(
                            archive,
                            manifest,
                            budget=budget,
                            temp_parent=temp_parent,
                        )
                    )
                except _BundleLimitError as exc:
                    errors.append({"error": exc.code, "detail": exc.detail})
                except Exception as exc:
                    errors.append(
                        {
                            "error": "embedded_root_semantic_verification_failed",
                            "detail": redact_text_secrets(
                                f"{type(exc).__name__}: {exc}"
                            ),
                        }
                    )

    return result()


def verify_root_bundle(
    bundle_path: Path,
    *,
    verify_embedded_root: bool = True,
    max_entries: int = BUNDLE_DEFAULT_MAX_ENTRIES,
    max_expanded_bytes: int = BUNDLE_DEFAULT_MAX_EXPANDED_BYTES,
    max_member_bytes: int | None = None,
    max_compression_ratio: int = BUNDLE_DEFAULT_MAX_COMPRESSION_RATIO,
    max_central_directory_bytes: int = BUNDLE_DEFAULT_MAX_CENTRAL_DIRECTORY_BYTES,
    timeout_seconds: int = BUNDLE_DEFAULT_VERIFY_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Verify a bundle while guaranteeing every owned descriptor is closed."""
    resources = _BundleVerifierResources()
    try:
        return _verify_root_bundle_impl(
            bundle_path,
            _resources=resources,
            verify_embedded_root=verify_embedded_root,
            max_entries=max_entries,
            max_expanded_bytes=max_expanded_bytes,
            max_member_bytes=max_member_bytes,
            max_compression_ratio=max_compression_ratio,
            max_central_directory_bytes=max_central_directory_bytes,
            timeout_seconds=timeout_seconds,
        )
    finally:
        resources.close()

def _verification_failure_message(result: dict[str, Any]) -> str:
    failed = _bounded_diagnostic_sample(
        (
            str(item.get("name"))
            for item in result.get("checks") or []
            if not item.get("ok")
        )
    )
    return ", ".join(failed) or str(result.get("reason") or "verification_failed")


def _trusted_bundle_verification_limits(path: Path) -> dict[str, int]:
    """Derive exact public verifier ceilings for a packer-created archive."""
    preflight = _read_bundle_zip_preflight(path)
    with zipfile.ZipFile(path, "r") as archive:
        infos = archive.infolist()
    expanded = sum(max(0, int(info.file_size)) for info in infos)
    compressed = sum(max(0, int(info.compress_size)) for info in infos)
    member_size = max((max(0, int(info.file_size)) for info in infos), default=0)
    maximum_ratio = max(
        (
            (max(0, int(info.file_size)) + max(1, int(info.compress_size)) - 1)
            // max(1, int(info.compress_size))
            for info in infos
        ),
        default=1,
    )
    maximum_ratio = max(
        maximum_ratio,
        (expanded + max(1, compressed) - 1) // max(1, compressed),
    )
    derived = {
        "max_entries": max(1, len(infos)),
        "max_expanded_bytes": max(1, expanded),
        "max_member_bytes": max(1, member_size),
        "max_compression_ratio": max(1, maximum_ratio),
        "max_central_directory_bytes": max(1, preflight.central_directory_size),
        "timeout_seconds": BUNDLE_DEFAULT_VERIFY_TIMEOUT_SECONDS,
    }
    absolute_limits = {
        "max_entries": BUNDLE_ABSOLUTE_MAX_ENTRIES,
        "max_expanded_bytes": BUNDLE_ABSOLUTE_MAX_EXPANDED_BYTES,
        "max_member_bytes": BUNDLE_ABSOLUTE_MAX_EXPANDED_BYTES,
        "max_compression_ratio": BUNDLE_ABSOLUTE_MAX_COMPRESSION_RATIO,
        "max_central_directory_bytes": BUNDLE_ABSOLUTE_MAX_CENTRAL_DIRECTORY_BYTES,
        "timeout_seconds": BUNDLE_MAX_VERIFY_TIMEOUT_SECONDS,
    }
    exceeded = [
        name for name, value in derived.items() if value > absolute_limits[name]
    ]
    if exceeded:
        raise ValueError(
            "new bundle exceeds absolute verification limit(s): "
            + ", ".join(sorted(exceeded))
        )
    return derived


def _path_lexists(path: Path) -> bool:
    return os.path.lexists(path)


def _backup_existing_regular_file(path: Path) -> Path | None:
    """Create a same-directory rollback copy/link without disturbing the published path."""
    if not _path_lexists(path):
        return None
    if _is_link_like(path) or not path.is_file():
        raise ValueError(f"refusing to replace non-regular output path: {path}")
    fd, backup_name = tempfile.mkstemp(prefix=f".{path.name}.rollback.", suffix=".bak", dir=path.parent)
    os.close(fd)
    backup = Path(backup_name)
    backup.unlink(missing_ok=True)
    try:
        os.link(path, backup)
    except OSError:
        shutil.copy2(path, backup, follow_symlinks=False)
    return backup


def _restore_or_remove(path: Path, backup: Path | None) -> None:
    if backup is not None and backup.exists():
        os.replace(backup, path)
    else:
        path.unlink(missing_ok=True)


def _relative_stage_path(stage_root: Path, path: Path) -> str:
    return path.relative_to(stage_root).as_posix()


def _remove_staged_file(stage_root: Path, path: Path, copy_result: dict[str, Any], *, reason: str) -> bool:
    if not path.exists():
        return False
    rel = _relative_stage_path(stage_root, path)
    try:
        size = path.stat().st_size
    except OSError:
        size = 0
    path.unlink()
    copy_result["copied_files"] = max(0, int(copy_result.get("copied_files") or 0) - 1)
    copy_result["copied_bytes"] = max(0, int(copy_result.get("copied_bytes") or 0) - int(size))
    copy_result.setdefault("skipped", []).append({"path": rel, "reason": reason})
    return True


def _rewrite_shareable_snapshot_manifests(stage_root: Path, copy_result: dict[str, Any]) -> int:
    snapshots_dir = stage_root / "snapshots"
    if not snapshots_dir.exists():
        return 0
    rewritten = 0
    conn: sqlite3.Connection | None = None
    db_path = stage_root / "catalog" / "catalog.sqlite3"
    if db_path.exists():
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
    try:
        for manifest_path in sorted(snapshots_dir.glob("continuum_snapshot_*.manifest.json")):
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not manifest.get("partition_alias_key"):
                continue
            old_size = manifest_path.stat().st_size
            manifest["partition_alias_key"] = None
            manifest["partition_alias_key_fingerprint"] = None
            manifest["partition_alias_key_policy"] = "shareable_omitted_hmac_key"
            atomic_write_text_file(
                manifest_path,
                json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            )
            new_size = manifest_path.stat().st_size
            copy_result["copied_bytes"] = max(
                0,
                int(copy_result.get("copied_bytes") or 0) + int(new_size) - int(old_size),
            )
            rewritten += 1
            if conn is not None:
                rel = _relative_stage_path(stage_root, manifest_path)
                conn.execute(
                    """
                    UPDATE snapshots
                    SET manifest_hash = ?, partition_alias_key_hash = NULL
                    WHERE manifest_uri = ?
                    """,
                    (file_sha256(manifest_path), rel),
                )
        if conn is not None:
            conn.commit()
    finally:
        if conn is not None:
            conn.close()
    return rewritten


def _strip_shareable_alias_keys(stage_root: Path, copy_result: dict[str, Any]) -> dict[str, Any]:
    removed = 0
    if _remove_staged_file(
        stage_root,
        stage_root / "catalog" / "partition_alias.key",
        copy_result,
        reason="shareable_alias_key_omitted",
    ):
        removed += 1
    snapshots_dir = stage_root / "snapshots"
    if snapshots_dir.exists():
        for path in sorted(snapshots_dir.glob("continuum_partition_alias_*.key")):
            if _remove_staged_file(stage_root, path, copy_result, reason="shareable_alias_key_omitted"):
                removed += 1
    rewritten_manifests = _rewrite_shareable_snapshot_manifests(stage_root, copy_result)
    return {"removed_alias_key_files": removed, "rewritten_snapshot_manifests": rewritten_manifests}


def _publish_without_overwrite(source: Path, destination: Path) -> None:
    """Publish one complete file without replacing a concurrently created path.

    A same-directory hard link is the cleanest atomic no-clobber primitive.  Some
    portable/network filesystems do not support hard links, so fall back to an
    exclusive placeholder reservation followed by atomic replacement of that
    placeholder.  Both paths leave the caller's source intact on failure.
    """
    try:
        os.link(source, destination)
    except FileExistsError:
        raise
    except OSError:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        fd = os.open(destination, flags, 0o600)
        os.close(fd)
        try:
            os.replace(source, destination)
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        return

    try:
        source.unlink()
    except Exception:
        destination.unlink(missing_ok=True)
        raise


def pack_root(
    root: Path,
    *,
    out_path: Path,
    profile: str = "shareable",
    symlink_policy: str = "fail",
    run_restore_drill: bool = True,
    force: bool = False,
) -> dict[str, Any]:
    """Create and self-verify a portable ZIP handoff bundle for one Continuum root."""
    root = Path(root)
    out_path = Path(out_path)
    if profile not in SUPPORTED_BUNDLE_PROFILES:
        raise ValueError(f"profile must be one of {sorted(SUPPORTED_BUNDLE_PROFILES)}")
    if symlink_policy not in SUPPORTED_SYMLINK_POLICIES:
        raise ValueError(f"symlink_policy must be one of {sorted(SUPPORTED_SYMLINK_POLICIES)}")
    if profile == "shareable" and symlink_policy != "fail":
        raise ValueError("shareable bundles require symlink_policy='fail' so no evidence is silently omitted")
    if not is_initialized(root):
        raise ValueError(f"Continuum root is not initialized: {root}")
    _catalog_database_for_bundle(root)
    if out_path.suffix.casefold() != ".zip":
        raise ValueError("root bundles currently use .zip output; choose an output path ending in .zip")
    if _is_relative_to(out_path, root):
        raise ValueError("bundle output must be outside the Continuum root")
    sha_path = Path(str(out_path) + ".sha256")
    existing_outputs = [path for path in (out_path, sha_path) if _path_lexists(path)]
    if existing_outputs and not force:
        raise FileExistsError(str(existing_outputs[0]))
    for existing in existing_outputs:
        if _is_link_like(existing) or not existing.is_file():
            raise ValueError(f"refusing to replace non-regular output path: {existing}")

    symlinks = _symlink_inventory(root)
    if symlinks and symlink_policy == "fail":
        raise ValueError(f"bundle refused because the root contains {len(symlinks)} symlink(s)")

    config = load_config(root)
    redaction_profile = str(config.get("security", {}).get("redaction_profile") or "portable")
    if profile == "shareable" and redaction_profile == "private":
        raise ValueError(
            "shareable bundle refused because security.redaction_profile is 'private'; "
            "use portable/shareable metadata or create a redacted copy first"
        )

    preflight_portability_audit = audit_portable_metadata(root)
    if not preflight_portability_audit.get("ok"):
        raise ValueError(
            f"portable metadata audit found {preflight_portability_audit.get('finding_count', 0)} raw absolute local path(s)"
        )
    if not preflight_portability_audit.get("complete", True):
        raise ValueError("portable metadata audit was incomplete")

    # The root preflight verifies every currently present proof pack, not only a
    # small recent sample. Restore-drill writes happen before the final audit and
    # stage copy so the bundle captures the tested state.
    proof_count = _proof_pack_count(root)
    root_verification = verify_root(
        root,
        strict=True,
        verify_recent_proof_packs=proof_count,
        run_restore_drill=run_restore_drill,
        scan_secrets=True,
        allow_symlinks=symlink_policy == "skip",
    )
    if not root_verification.get("ok"):
        raise ValueError(f"root verification failed: {_verification_failure_message(root_verification)}")

    secret_audit = audit_secrets(root, create=False)
    if not secret_audit.get("ok"):
        raise ValueError(f"secret audit found {secret_audit.get('finding_count', 0)} active finding(s)")
    if not secret_audit.get("complete", True):
        raise ValueError(
            "secret audit was incomplete; raise secret_audit_max_file_bytes or fix unreadable files before packing"
        )
    if profile == "shareable" and int(secret_audit.get("allowlisted_findings") or 0) > 0:
        raise ValueError(
            "shareable bundle refused because the root contains allowlisted secret-like findings; "
            "use the portable profile or create a redacted copy"
        )

    portability_audit = audit_portable_metadata(root)
    if not portability_audit.get("ok"):
        raise ValueError(
            f"portable metadata audit found {portability_audit.get('finding_count', 0)} raw absolute local path(s)"
        )
    if not portability_audit.get("complete", True):
        raise ValueError("portable metadata audit was incomplete")

    artifact_count = _artifact_row_count(root)
    artifact_verification = _verify_artifact_ledger(root, limit=max(1, artifact_count))
    if not artifact_verification.get("ok"):
        raise ValueError("full artifact-ledger verification failed")
    proof_count = _proof_pack_count(root)
    proof_verification = _verify_recent_proof_packs(root, limit=proof_count)
    if not proof_verification.get("ok"):
        raise ValueError("full proof-pack verification failed")

    secure_mkdir(out_path.parent)
    temp_zip: Path | None = None
    with tempfile.TemporaryDirectory(prefix="continuum-bundle-") as tmp:
        stage_root = Path(tmp) / BUNDLE_ROOT_NAME
        copy_result = _copy_root_to_stage(root, stage_root, symlink_policy=symlink_policy)
        staged_alias_key = stage_root / "catalog" / "partition_alias.key"
        alias_key_was_present = staged_alias_key.exists()
        alias_key_policy = "portable_included_for_disaster_recovery" if profile == "portable" else "shareable_omitted_hmac_key"
        alias_key_stage_policy: dict[str, Any] = {"removed_alias_key_files": 0, "rewritten_snapshot_manifests": 0}
        if profile == "shareable":
            alias_key_stage_policy = _strip_shareable_alias_keys(stage_root, copy_result)
        unsupported_count = sum(
            1
            for item in copy_result["skipped"]
            if item.get("reason") == "unsupported_file_type"
        )
        if profile == "shareable" and unsupported_count:
            raise ValueError(
                "shareable bundle refused because the root contains "
                f"{unsupported_count} unsupported file type(s)"
            )

        _claim_disposable_bundle_root(stage_root)
        staged_proof_count = _proof_pack_count(stage_root)
        staged_verification = verify_root(
            stage_root,
            strict=True,
            verify_recent_proof_packs=staged_proof_count,
            run_restore_drill=False,
            scan_secrets=True,
            allow_symlinks=False,
            allow_missing_alias_key=profile == "shareable",
        )
        if not staged_verification.get("ok"):
            raise ValueError(f"staged root verification failed: {_verification_failure_message(staged_verification)}")
        staged_secret_audit = audit_secrets(stage_root, create=False)
        if not staged_secret_audit.get("ok") or not staged_secret_audit.get("complete", True):
            raise ValueError("staged root secret audit failed or was incomplete")
        if profile == "shareable" and int(staged_secret_audit.get("allowlisted_findings") or 0) > 0:
            raise ValueError("staged shareable root contains allowlisted secret-like findings")
        staged_portability_audit = audit_portable_metadata(stage_root)
        if not staged_portability_audit.get("ok") or not staged_portability_audit.get("complete", True):
            raise ValueError("staged root portable metadata audit failed or was incomplete")
        staged_artifact_count = _artifact_row_count(stage_root)
        staged_artifact_verification = _verify_artifact_ledger(
            stage_root,
            limit=max(1, staged_artifact_count),
        )
        if not staged_artifact_verification.get("ok"):
            raise ValueError("staged root artifact-ledger verification failed")

        file_entries, total_size = _file_entries(stage_root)
        manifest: dict[str, Any] = {
            "schema": BUNDLE_MANIFEST_SCHEMA,
            "bundle_id": unique_id("bundle"),
            "created_at": utc_now(),
            "profile": profile,
            "symlink_policy": symlink_policy,
            "redaction_profile": redaction_profile,
            "alias_key_policy": alias_key_policy,
            "file_count": len(file_entries),
            "total_size_bytes": total_size,
            "files": file_entries,
            "copy": {
                "copied_files": copy_result["copied_files"],
                "copied_bytes": copy_result["copied_bytes"],
                "skipped_count": len(copy_result["skipped"]),
                "skipped": copy_result["skipped"],
                "symlink_count": len(copy_result["symlinks"]),
                "symlinks": copy_result["symlinks"],
            },
            "preflight": {
                "root_verification_ok": bool(root_verification.get("ok")),
                "staged_root_verification_ok": bool(staged_verification.get("ok")),
                "secret_audit_complete": bool(secret_audit.get("complete", True)),
                "secret_finding_count": int(secret_audit.get("finding_count") or 0),
                "secret_allowlisted_finding_count": int(secret_audit.get("allowlisted_findings") or 0),
                "proof_pack_count": proof_count,
                "proof_packs_ok": bool(proof_verification.get("ok")),
                "artifact_count": artifact_count,
                "artifact_ledger_ok": bool(artifact_verification.get("ok")),
                "portable_metadata_files_scanned": portability_audit.get("files_scanned", 0),
                "portable_metadata_sqlite_values_scanned": portability_audit.get("sqlite_values_scanned", 0),
                "portable_metadata_complete": bool(portability_audit.get("complete", True)),
                "portable_metadata_ok": bool(portability_audit.get("ok")),
                "restore_drill_ran": bool(run_restore_drill),
                "alias_key_included": bool(profile == "portable" and alias_key_was_present),
                "alias_key_policy": alias_key_policy,
                "alias_key_files_omitted": int(alias_key_stage_policy.get("removed_alias_key_files") or 0),
                "snapshot_manifests_rewritten_for_shareable": int(
                    alias_key_stage_policy.get("rewritten_snapshot_manifests") or 0
                ),
            },
        }
        manifest["manifest_hash"] = _manifest_hash(manifest)
        manifest_path = stage_root / BUNDLE_MANIFEST_NAME
        manifest_path.write_bytes(
            (json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")
        )

        fd, tmp_name = tempfile.mkstemp(prefix=f".{out_path.name}.", suffix=".tmp", dir=out_path.parent)
        os.close(fd)
        temp_zip = Path(tmp_name)
        try:
            with zipfile.ZipFile(
                temp_zip,
                "w",
                compression=zipfile.ZIP_DEFLATED,
                compresslevel=6,
                allowZip64=True,
                strict_timestamps=False,
            ) as archive:
                # Write only manifest-listed evidence plus the manifest itself.
                # Staged verification may create SQLite WAL/SHM sidecars; those
                # are process artifacts and must never hitch a ride in a bundle.
                archive_paths = [stage_root / str(entry["path"]) for entry in file_entries]
                archive_paths.append(manifest_path)
                for path in sorted(archive_paths, key=lambda item: item.relative_to(stage_root).as_posix()):
                    rel = path.relative_to(stage_root).as_posix()
                    _write_zip_member(
                        archive,
                        path,
                        arcname=f"{BUNDLE_ROOT_NAME}/{rel}",
                        mode_override=0o644 if path == manifest_path else None,
                    )

            # The packer has just measured and written this immutable temporary
            # archive.  Derive tight limits from those trusted bytes so a root
            # above the public 64 GiB default can still self-check deliberately,
            # while every absolute verifier ceiling remains in force.
            trusted_verification_limits = _trusted_bundle_verification_limits(temp_zip)
            bundle_verification = verify_root_bundle(
                temp_zip,
                verify_embedded_root=False,
                **trusted_verification_limits,
            )
            if not bundle_verification.get("ok"):
                raise ValueError(f"new bundle failed self-verification: {bundle_verification.get('errors')}")

            # Preserve the previously published pair until the replacement ZIP
            # and checksum both pass. Hard links make rollback cheap on normal
            # filesystems; copy2 is the cross-platform fallback.
            bundle_backup: Path | None = None
            checksum_backup: Path | None = None
            publication_started = False
            try:
                if force:
                    bundle_backup = _backup_existing_regular_file(out_path)
                    try:
                        checksum_backup = _backup_existing_regular_file(sha_path)
                    except Exception:
                        if bundle_backup is not None:
                            bundle_backup.unlink(missing_ok=True)
                            bundle_backup = None
                        raise
                if not force and (_path_lexists(out_path) or _path_lexists(sha_path)):
                    raise FileExistsError(str(out_path if _path_lexists(out_path) else sha_path))
                if force:
                    os.replace(temp_zip, out_path)
                    temp_zip = None
                    publication_started = True
                else:
                    # ``os.replace`` would overwrite a file created by another
                    # publisher after the existence check.  Publish with an
                    # atomic no-clobber primitive instead.
                    _publish_without_overwrite(temp_zip, out_path)
                    publication_started = True
                    temp_zip = None

                # The staged root has already passed the full semantic audit.
                # Re-verify the published archive envelope and member binding
                # without extracting and re-auditing the same root a third time.
                final_verification = verify_root_bundle(
                    out_path,
                    verify_embedded_root=False,
                    **trusted_verification_limits,
                )
                if not final_verification.get("ok"):
                    raise ValueError(f"final bundle verification failed: {final_verification.get('errors')}")
                bundle_sha256 = final_verification.get("bundle_sha256")
                if not isinstance(bundle_sha256, str) or not re.fullmatch(
                    r"[0-9a-f]{64}", bundle_sha256
                ):
                    raise ValueError("final bundle verification did not return a valid SHA-256")
                atomic_write_text_file(sha_path, f"{bundle_sha256}  {out_path.name}\n")
            except Exception:
                if publication_started:
                    _restore_or_remove(out_path, bundle_backup)
                    _restore_or_remove(sha_path, checksum_backup)
                    bundle_backup = None
                    checksum_backup = None
                raise
            finally:
                if bundle_backup is not None:
                    bundle_backup.unlink(missing_ok=True)
                if checksum_backup is not None:
                    checksum_backup.unlink(missing_ok=True)
        finally:
            if temp_zip is not None:
                temp_zip.unlink(missing_ok=True)

    return {
        "schema": "epic_continuum.pack_root_result.v1",
        "ok": bool(final_verification.get("ok")),
        "profile": profile,
        "source_root": str(root),
        "bundle_uri": str(out_path),
        "bundle_sha256": bundle_sha256,
        "bundle_size_bytes": out_path.stat().st_size,
        "sha256_receipt_uri": str(sha_path),
        "file_count": final_verification.get("file_count"),
        "verification": final_verification,
    }
