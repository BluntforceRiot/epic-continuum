from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import struct
import tempfile
import unicodedata
import zipfile
import zlib
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

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


BUNDLE_MANIFEST_SCHEMA = "epic_continuum.root_bundle_manifest.v1"
BUNDLE_ROOT_NAME = "epic-continuum-root"
BUNDLE_MANIFEST_NAME = "bundle.manifest.json"
SUPPORTED_BUNDLE_PROFILES = {"portable", "shareable"}
SUPPORTED_SYMLINK_POLICIES = {"fail", "skip"}

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
    source_conn = sqlite3.connect(sqlite_readonly_uri(source), uri=True)
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


def _embedded_nonportable_paths(value: str) -> list[str]:
    """Extract clear local filesystem references embedded in diagnostic text."""
    found: list[str] = []
    for pattern in (
        _EMBEDDED_TRACEBACK_PATH_RE,
        _EMBEDDED_QUOTED_PATH_RE,
        _EMBEDDED_WINDOWS_PATH_RE,
    ):
        for match in pattern.finditer(value):
            candidate = match.group("path").strip().rstrip(".,;:)")
            if candidate and _looks_nonportable_local_path(candidate) and candidate not in found:
                found.append(candidate)
    return found


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
    return f"external:{safe_name}"


def _portable_metadata_findings(
    value: Any,
    *,
    path: str = "$",
    key_hint: str | None = None,
    scan_embedded_paths: bool = False,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            key_text = str(key)
            key_is_path = isinstance(key, str) and _looks_nonportable_local_path(key_text)
            if key_is_path:
                findings.append(
                    {
                        "metadata_path": f"{path}.[path_key]",
                        "value": _external_path_reference(key_text),
                        "value_hash": content_hash(key_text),
                    }
                )
                nested_path = f"{path}.[path_key]"
            else:
                safe_key_text = redact_text_secrets(key_text)
                nested_path = f"{path}.{safe_key_text}"
            findings.extend(
                _portable_metadata_findings(
                    nested,
                    path=nested_path,
                    key_hint=key_text,
                    scan_embedded_paths=scan_embedded_paths,
                )
            )
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            findings.extend(
                _portable_metadata_findings(
                    nested,
                    path=f"{path}[{index}]",
                    key_hint=key_hint,
                    scan_embedded_paths=scan_embedded_paths,
                )
            )
    elif isinstance(value, str):
        if key_hint and _is_path_like_key(key_hint) and _looks_nonportable_local_path(value):
            findings.append(
                {
                    "metadata_path": path,
                    "value": _external_path_reference(value),
                    "value_hash": content_hash(value),
                }
            )
        if scan_embedded_paths:
            seen_hashes = {str(item.get("value_hash")) for item in findings}
            for embedded in _embedded_nonportable_paths(value):
                embedded_hash = content_hash(embedded)
                if embedded_hash in seen_hashes:
                    continue
                findings.append(
                    {
                        "metadata_path": path,
                        "value": _external_path_reference(embedded),
                        "value_hash": embedded_hash,
                        "embedded": True,
                    }
                )
                seen_hashes.add(embedded_hash)
    return findings


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


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

    for database in _sqlite_database_paths(root):
        if len(findings) >= max_findings:
            break
        rel_raw = database.relative_to(root)
        rel = str(_safe_rel_text(rel_raw)["path"])
        try:
            conn = sqlite3.connect(sqlite_readonly_uri(database), uri=True, timeout=2)
            conn.row_factory = sqlite3.Row
        except sqlite3.Error as exc:
            errors.append(
                {
                    "source": "sqlite",
                    "file": rel,
                    "error": "sqlite_open_failed",
                    "detail": redact_text_secrets(str(exc)),
                }
            )
            continue

        databases_scanned += 1
        try:
            try:
                tables = [
                    str(row[0])
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
                    )
                ]
            except sqlite3.Error as exc:
                errors.append(
                    {
                        "source": "sqlite",
                        "file": rel,
                        "error": "sqlite_schema_list_failed",
                        "detail": redact_text_secrets(str(exc)),
                    }
                )
                continue

            for table in tables:
                if len(findings) >= max_findings:
                    break
                safe_table = redact_text_secrets(table)
                try:
                    schema_rows = list(conn.execute(f"PRAGMA table_info({_quote_identifier(table)})"))
                except sqlite3.Error as exc:
                    errors.append(
                        {
                            "source": "sqlite",
                            "file": rel,
                            "sqlite_table": safe_table,
                            "error": "sqlite_schema_read_failed",
                            "detail": redact_text_secrets(str(exc)),
                        }
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

                select_columns = ", ".join(_quote_identifier(column) for column in selected)
                try:
                    rows = conn.execute(
                        f"SELECT rowid AS __continuum_rowid__, {select_columns} "
                        f"FROM {_quote_identifier(table)}"
                    )
                except sqlite3.Error:
                    try:
                        rows = conn.execute(
                            f"SELECT {select_columns} FROM {_quote_identifier(table)}"
                        )
                    except sqlite3.Error as exc:
                        errors.append(
                            {
                                "source": "sqlite",
                                "file": rel,
                                "sqlite_table": safe_table,
                                "error": "sqlite_query_failed",
                                "detail": redact_text_secrets(str(exc)),
                            }
                        )
                        continue

                try:
                    for row_number, row in enumerate(rows, start=1):
                        if len(findings) >= max_findings:
                            break
                        row_keys = set(row.keys())
                        row_id = (
                            row["__continuum_rowid__"]
                            if "__continuum_rowid__" in row_keys
                            else row_number
                        )
                        texts: dict[str, str] = {}
                        for column in selected:
                            value = row[column]
                            if value is None:
                                continue
                            values_scanned += 1
                            texts[column] = (
                                value.decode("utf-8", errors="replace")
                                if isinstance(value, bytes)
                                else str(value)
                            )

                        for column in direct_columns:
                            text_value = texts.get(column)
                            if text_value is None or not _looks_nonportable_local_path(text_value):
                                continue
                            findings.append(
                                {
                                    "source": "sqlite",
                                    "file": rel,
                                    "sqlite_table": safe_table,
                                    "sqlite_column": redact_text_secrets(column),
                                    "sqlite_rowid": row_id,
                                    "metadata_path": (
                                        f"$.{safe_table}[{row_id}].{redact_text_secrets(column)}"
                                    ),
                                    "value": _external_path_reference(text_value),
                                    "value_hash": content_hash(text_value),
                                }
                            )
                            if len(findings) >= max_findings:
                                break
                        if len(findings) >= max_findings:
                            break

                        for column in json_columns:
                            text_value = texts.get(column, "").strip()
                            if not text_value or text_value[0] not in "[{":
                                continue
                            try:
                                parsed = _strict_json_loads(text_value)
                            except ValueError as exc:
                                errors.append(
                                    {
                                        "source": "sqlite_json",
                                        "file": rel,
                                        "sqlite_table": safe_table,
                                        "sqlite_column": redact_text_secrets(column),
                                        "sqlite_rowid": row_id,
                                        "error": "sqlite_json_decode_failed",
                                        "detail": redact_text_secrets(str(exc)),
                                    }
                                )
                                continue
                            remaining = max_findings - len(findings)
                            for item in _portable_metadata_findings(parsed)[:remaining]:
                                item.update(
                                    {
                                        "source": "sqlite_json",
                                        "file": rel,
                                        "sqlite_table": safe_table,
                                        "sqlite_column": redact_text_secrets(column),
                                        "sqlite_rowid": row_id,
                                    }
                                )
                                findings.append(item)
                        if len(findings) >= max_findings:
                            break

                        for key_column in key_columns:
                            key_text = texts.get(key_column)
                            if not key_text or not _is_path_like_key(key_text):
                                continue
                            for value_column in value_columns:
                                value_text = texts.get(value_column)
                                if value_text is None or not _looks_nonportable_local_path(value_text):
                                    continue
                                findings.append(
                                    {
                                        "source": "sqlite_key_value",
                                        "file": rel,
                                        "sqlite_table": safe_table,
                                        "sqlite_key_column": redact_text_secrets(key_column),
                                        "sqlite_value_column": redact_text_secrets(value_column),
                                        "sqlite_rowid": row_id,
                                        "metadata_path": (
                                            f"$.{safe_table}[{row_id}].{redact_text_secrets(key_text)}"
                                        ),
                                        "value": _external_path_reference(value_text),
                                        "value_hash": content_hash(value_text),
                                    }
                                )
                                if len(findings) >= max_findings:
                                    break
                            if len(findings) >= max_findings:
                                break
                except sqlite3.Error as exc:
                    errors.append(
                        {
                            "source": "sqlite",
                            "file": rel,
                            "sqlite_table": safe_table,
                            "error": "sqlite_iteration_failed",
                            "detail": redact_text_secrets(str(exc)),
                        }
                    )
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


def _audit_yaml_portable_metadata(
    root: Path,
    *,
    max_findings: int,
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
            text = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append({"source": "yaml", "file": rel, "error": "yaml_read_failed", "detail": str(exc)})
            continue
        files_scanned += 1
        for line_number, line in enumerate(text.splitlines(), start=1):
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
                    {
                        "source": "yaml",
                        "file": rel,
                        "line": line_number,
                        "metadata_path": f"$.{key}",
                        "value": _external_path_reference(value),
                        "value_hash": content_hash(value),
                    }
                )
    return findings, files_scanned, errors


def audit_portable_metadata(root: Path, *, max_findings: int = 200) -> dict[str, Any]:
    """Detect raw absolute local paths in durable JSON, JSONL, YAML, and SQLite metadata."""
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    json_files_scanned = 0
    max_findings = max(1, int(max_findings))
    for file_path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if len(findings) >= max_findings:
            break
        if _is_link_like(file_path) or not file_path.is_file():
            continue
        rel = file_path.relative_to(root)
        if _is_transient(rel):
            continue
        if not _is_metadata_file(rel):
            continue
        json_files_scanned += 1
        try:
            text = file_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errors.append({"source": "json", "file": rel.as_posix(), "error": "metadata_read_failed", "detail": str(exc)})
            continue
        values: list[tuple[int | None, Any]] = []
        line_oriented = rel.suffix.casefold() in {".jsonl", ".log"}
        if line_oriented:
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    parsed = _strict_json_loads(line)
                except ValueError as exc:
                    errors.append(
                        {
                            "source": "jsonl",
                            "file": rel.as_posix(),
                            "line": line_number,
                            "error": "metadata_decode_failed",
                            "detail": redact_text_secrets(str(exc)),
                        }
                    )
                    continue
                values.append((line_number, parsed))
        else:
            try:
                values.append((None, _strict_json_loads(text)))
            except ValueError as exc:
                errors.append(
                    {
                        "source": "json",
                        "file": rel.as_posix(),
                        "error": "metadata_decode_failed",
                        "detail": redact_text_secrets(str(exc)),
                    }
                )
                continue
        for line_number, parsed in values:
            remaining = max_findings - len(findings)
            if remaining <= 0:
                break
            for item in _portable_metadata_findings(
                parsed,
                scan_embedded_paths=rel.suffix.casefold() == ".log",
            )[:remaining]:
                item["source"] = "jsonl" if line_number is not None else "json"
                item["file"] = rel.as_posix()
                if line_number is not None:
                    item["line"] = line_number
                findings.append(item)

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
    unsafe = [entry["path"] for entry in entries if not _zip_member_is_safe(str(entry["path"]))]
    if unsafe:
        raise ValueError(f"root contains bundle-incompatible path(s): {unsafe[:5]}")
    collisions = _portable_name_collisions(str(entry["path"]) for entry in entries)
    if collisions:
        raise ValueError(f"root contains case/Unicode-colliding path(s): {collisions[:5]}")
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


def _portable_name_collisions(names: Iterable[str]) -> list[list[str]]:
    groups: dict[str, list[str]] = {}
    for name in names:
        key = unicodedata.normalize("NFC", name).casefold()
        groups.setdefault(key, []).append(name)
    return [sorted(values) for values in groups.values() if len(values) > 1]


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


def _manifest_structure_errors(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    allowed_keys = {
        "schema", "bundle_id", "created_at", "profile", "symlink_policy",
        "redaction_profile", "root_identity_hash", "file_count", "total_size_bytes",
        "files", "copy", "preflight", "manifest_hash",
    }
    unexpected = sorted(set(manifest) - allowed_keys)
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
    ordered_paths = [
        str(entry.get("path"))
        for entry in files
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    ]
    if ordered_paths != sorted(ordered_paths):
        errors.append({"error": "manifest_file_order_noncanonical"})
    allowed_entry_keys = {"path", "sha256", "size_bytes", "mode"}
    for index, entry in enumerate(files):
        if not isinstance(entry, dict):
            continue
        unexpected_entry = sorted(set(entry) - allowed_entry_keys)
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


def _manifest_semantic_errors(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate claims that distinguish a policy-checked handoff from a hash list."""
    errors: list[dict[str, Any]] = []
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
        unexpected = sorted(set(copy_payload) - allowed_copy_keys)
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
        valid_skip_reasons = {"transient_excluded", "symlink_skipped", "unsupported_file_type"}
        invalid_skipped = [
            index for index, item in enumerate(skipped)
            if not isinstance(item, dict)
            or not isinstance(item.get("reason"), str)
            or item.get("reason") not in valid_skip_reasons
        ]
        if invalid_skipped:
            errors.append({"error": "manifest_copy_skip_entry_invalid", "indexes": invalid_skipped[:20]})
        symlink_count = copy_payload.get("symlink_count")
        if symlink_policy == "fail" and (symlinks or (symlink_count is not None and symlink_count != 0)):
            errors.append({"error": "manifest_fail_policy_contains_symlinks"})
        if profile == "shareable":
            prohibited = [
                index for index, item in enumerate(skipped)
                if isinstance(item, dict)
                and isinstance(item.get("reason"), str)
                and item.get("reason") in {"symlink_skipped", "unsupported_file_type"}
            ]
            if prohibited:
                errors.append({"error": "manifest_shareable_omitted_evidence", "indexes": prohibited[:20]})

    preflight = manifest.get("preflight")
    if isinstance(preflight, dict):
        allowed_preflight_keys = {
            "root_verification_ok", "staged_root_verification_ok", "secret_audit_complete",
            "secret_finding_count", "secret_allowlisted_finding_count", "proof_pack_count",
            "proof_packs_ok", "artifact_count", "artifact_ledger_ok",
            "portable_metadata_files_scanned", "portable_metadata_sqlite_values_scanned",
            "portable_metadata_complete", "portable_metadata_ok", "restore_drill_ran",
        }
        unexpected = sorted(set(preflight) - allowed_preflight_keys)
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
            "portable_metadata_sqlite_values_scanned",
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
        digest.update(output)
        crc = zlib.crc32(output, crc)
        output_size += len(output)
        if collected is not None:
            collected.append(output)

    remaining = int(info.compress_size)
    try:
        if info.compress_type == zipfile.ZIP_STORED:
            while remaining:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    return None, None, output_size, "compressed_data_truncated"
                remaining -= len(chunk)
                consume(chunk)
        elif info.compress_type == zipfile.ZIP_DEFLATED:
            inflater = zlib.decompressobj(-15)
            while remaining:
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


def _read_exact_at(handle: Any, offset: int, size: int) -> bytes:
    handle.seek(offset)
    data = handle.read(size)
    if len(data) != size:
        raise EOFError(f"expected {size} bytes at offset {offset}, got {len(data)}")
    return data


def _zip_envelope_errors(path: Path, infos: list[zipfile.ZipInfo]) -> list[dict[str, Any]]:
    """Reject bytes and metadata that are not bound by the bundle manifest.

    The normal ``zipfile`` API exposes logical members but intentionally tolerates
    self-extracting preambles, comments, extra fields, and trailing bytes.  A
    handoff bundle treats those channels as unmanifested storage, so this parser
    requires one contiguous, single-disk ZIP envelope and permits only the
    structurally required Zip64 size fields emitted by the packer.  It uses
    bounded random-access reads rather than loading the entire archive into RAM.
    """
    errors: list[dict[str, Any]] = []
    try:
        file_size = path.stat().st_size
        handle = path.open("rb")
    except OSError as exc:
        return [{"error": "zip_envelope_read_failed", "detail": str(exc)}]

    with handle:
        tail_size = min(file_size, 22 + _ZIP_UINT16_MAX + 4096)
        try:
            tail = _read_exact_at(handle, file_size - tail_size, tail_size)
        except (OSError, EOFError) as exc:
            return [{"error": "zip_envelope_read_failed", "detail": str(exc)}]
        located = _find_eocd(tail)
        if located is None:
            return [{"error": "zip_eocd_missing"}]
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



def _extract_manifested_root(
    archive: zipfile.ZipFile,
    manifest: dict[str, Any],
    destination: Path,
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
    for entry in file_entries:
        if not isinstance(entry, dict):
            raise ValueError("manifest file entry is not an object")
        rel = str(entry.get("path") or "")
        if not _zip_member_is_safe(rel):
            raise ValueError(f"unsafe manifest path during semantic extraction: {rel}")
        member = f"{BUNDLE_ROOT_NAME}/{rel}"
        target = destination.joinpath(*PurePosixPath(rel).parts)
        secure_mkdir(target.parent)
        with archive.open(member, "r") as source, target.open("xb") as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)
        expected_size = entry.get("size_bytes")
        if not isinstance(expected_size, int) or target.stat().st_size != expected_size:
            raise ValueError(f"semantic extraction size mismatch: {rel}")
        mode = entry.get("mode")
        if isinstance(mode, int):
            try:
                os.chmod(target, stat.S_IMODE(mode), follow_symlinks=False)
            except (NotImplementedError, OSError):
                # Windows exposes a narrower chmod model.  Archive mode binding
                # was already verified against the manifest before extraction.
                pass


def _embedded_root_semantic_errors(
    archive: zipfile.ZipFile,
    manifest: dict[str, Any],
) -> list[dict[str, Any]]:
    """Independently verify the Continuum root carried by a valid ZIP envelope.

    Manifest hashes prove byte consistency, not that the catalog opens, proof
    packs remain meaningful, or a claimed shareable root is actually free of
    secrets and machine-local paths. Reconstructing the root in a temporary
    directory closes that trust gap without touching the caller's filesystem.
    """
    errors: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="continuum-bundle-verify-") as tmp:
        embedded_root = Path(tmp) / BUNDLE_ROOT_NAME
        try:
            _extract_manifested_root(archive, manifest, embedded_root)
        except (
            OSError, ValueError, RuntimeError, KeyError, zipfile.BadZipFile,
            NotImplementedError, zlib.error,
        ) as exc:
            return [
                {
                    "error": "embedded_root_extraction_failed",
                    "detail": redact_text_secrets(str(exc)),
                }
            ]

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
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error, json.JSONDecodeError) as exc:
            return [
                {
                    "error": "embedded_root_verification_failed",
                    "detail": redact_text_secrets(str(exc)),
                }
            ]
        if not root_verification.get("ok"):
            failed_checks = [
                str(item.get("name"))
                for item in root_verification.get("checks") or []
                if not item.get("ok")
            ]
            errors.append(
                {
                    "error": "embedded_root_verification_unhealthy",
                    "failed_checks": failed_checks[:20],
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
    return errors

def verify_root_bundle(
    bundle_path: Path,
    *,
    verify_embedded_root: bool = True,
) -> dict[str, Any]:
    """Verify the ZIP envelope and, by default, the embedded Continuum root."""
    path = Path(bundle_path)
    errors: list[dict[str, Any]] = []
    manifest: dict[str, Any] | None = None
    if not path.exists():
        return {
            "schema": "epic_continuum.root_bundle_verification.v1",
            "ok": False,
            "bundle_uri": str(path),
            "error_count": 1,
            "errors": [{"error": "bundle_missing"}],
        }
    try:
        is_zip = zipfile.is_zipfile(path)
    except (OSError, ValueError, RuntimeError, UnicodeError, OverflowError, struct.error) as exc:
        return {
            "schema": "epic_continuum.root_bundle_verification.v1",
            "ok": False,
            "bundle_uri": str(path),
            "error_count": 1,
            "errors": [{"error": "bundle_probe_failed", "detail": redact_text_secrets(str(exc))}],
        }
    if not is_zip:
        return {
            "schema": "epic_continuum.root_bundle_verification.v1",
            "ok": False,
            "bundle_uri": str(path),
            "error_count": 1,
            "errors": [{"error": "not_a_zip_archive"}],
        }

    try:
        archive = zipfile.ZipFile(path, "r")
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
        return {
            "schema": "epic_continuum.root_bundle_verification.v1",
            "ok": False,
            "bundle_uri": str(path),
            "error_count": 1,
            "errors": [{"error": "bundle_open_failed", "detail": redact_text_secrets(str(exc))}],
        }

    try:
        raw_archive = path.open("rb")
    except OSError as exc:
        archive.close()
        return {
            "schema": "epic_continuum.root_bundle_verification.v1",
            "ok": False,
            "bundle_uri": str(path),
            "error_count": 1,
            "errors": [{"error": "bundle_raw_open_failed", "detail": redact_text_secrets(str(exc))}],
        }

    with archive, raw_archive:
        infos = archive.infolist()
        try:
            errors.extend(_zip_envelope_errors(path, infos))
        except (OSError, EOFError, ValueError, OverflowError, struct.error) as exc:
            errors.append(
                {
                    "error": "zip_envelope_validation_failed",
                    "detail": redact_text_secrets(str(exc)),
                }
            )
        names = [item.filename for item in infos]
        if names != sorted(names):
            errors.append({"error": "zip_member_order_noncanonical"})
        name_counts = Counter(names)
        duplicate_names = sorted(name for name, count in name_counts.items() if count > 1)
        if duplicate_names:
            errors.append({"error": "duplicate_member_names", "members": duplicate_names[:20]})
        unsafe_names = [name for name in names if not _zip_member_is_safe(name)]
        if unsafe_names:
            errors.append({"error": "unsafe_member_names", "members": unsafe_names[:20]})
        portable_collisions = _portable_name_collisions(names)
        if portable_collisions:
            errors.append({"error": "portable_member_name_collisions", "collisions": portable_collisions[:20]})

        directory_members = [info.filename for info in infos if info.is_dir()]
        if directory_members:
            errors.append({"error": "directory_members_not_allowed", "members": directory_members[:20]})
        encrypted_members = [info.filename for info in infos if info.flag_bits & 0x1]
        if encrypted_members:
            errors.append({"error": "encrypted_members_not_allowed", "members": encrypted_members[:20]})
        non_unix_members = [info.filename for info in infos if info.create_system != 3]
        if non_unix_members:
            errors.append({"error": "zip_member_platform_invalid", "members": non_unix_members[:20]})
        non_regular = [
            {"member": info.filename, "kind": _zip_member_type(info)}
            for info in infos
            if _zip_member_type(info) not in {"regular_or_unspecified", "directory"}
        ]
        if non_regular:
            errors.append({"error": "non_regular_bundle_members", "members": non_regular[:20]})

        declared_expanded_size = sum(max(0, int(info.file_size)) for info in infos)
        expanded_size_allowed = declared_expanded_size <= 1024**4
        if not expanded_size_allowed:
            errors.append({"error": "bundle_expanded_size_too_large", "size_bytes": declared_expanded_size})

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
            if info.file_size > 16 * 1024 * 1024:
                errors.append({"error": "manifest_too_large", "size_bytes": info.file_size})
            else:
                try:
                    manifest_bytes, _manifest_hash_value, _manifest_size, stream_error = (
                        _read_zip_member_exact(raw_archive, info, collect=True)
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
                        canonical_manifest_bytes = (
                            json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
                        ).encode("utf-8")
                        if manifest_bytes != canonical_manifest_bytes:
                            errors.append({"error": "manifest_serialization_noncanonical"})
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
            errors.extend(_manifest_structure_errors(manifest))
            errors.extend(_manifest_semantic_errors(manifest))
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
            manifest_portability_findings = _portable_metadata_findings(manifest)
            if manifest_portability_findings:
                errors.append(
                    {
                        "error": "manifest_nonportable_metadata",
                        "finding_count": len(manifest_portability_findings),
                        "findings": manifest_portability_findings[:20],
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
            if len(file_entries) > 1_000_000:
                errors.append({"error": "manifest_file_count_too_large", "count": len(file_entries)})
                file_entries = []

            listed_paths: list[str] = []
            computed_total = 0
            for index, entry in enumerate(file_entries):
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
                if not expanded_size_allowed:
                    continue
                try:
                    _member_data, actual_hash, actual_size, stream_error = _read_zip_member_exact(
                        raw_archive, info, collect=False
                    )
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
            duplicate_listed = sorted(item for item, count in listed_counts.items() if count > 1)
            if duplicate_listed:
                errors.append({"error": "duplicate_manifest_paths", "paths": duplicate_listed[:20]})
            listed_collisions = _portable_name_collisions(listed_paths)
            if listed_collisions:
                errors.append({"error": "portable_manifest_path_collisions", "collisions": listed_collisions[:20]})
            required_paths = {"catalog/catalog.sqlite3", "config/continuum.config.json"}
            missing_required = sorted(required_paths - set(listed_paths))
            if missing_required:
                errors.append({"error": "required_root_members_missing", "members": missing_required})
            expected_members = {f"{BUNDLE_ROOT_NAME}/{rel}" for rel in listed_paths}
            expected_members.add(manifest_member)
            actual_file_members = {info.filename for info in infos if not info.is_dir()}
            unexpected = sorted(actual_file_members - expected_members)
            missing = sorted(expected_members - actual_file_members)
            if unexpected:
                errors.append({"error": "unlisted_bundle_members", "members": unexpected[:20]})
            if missing:
                errors.append({"error": "missing_bundle_members", "members": missing[:20]})
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
            errors.extend(_embedded_root_semantic_errors(archive, manifest))

    return {
        "schema": "epic_continuum.root_bundle_verification.v1",
        "ok": not errors,
        "bundle_uri": str(path),
        "bundle_sha256": file_sha256(path),
        "bundle_size_bytes": path.stat().st_size,
        "bundle_id": manifest.get("bundle_id") if isinstance(manifest, dict) else None,
        "profile": manifest.get("profile") if isinstance(manifest, dict) else None,
        "file_count": manifest.get("file_count") if isinstance(manifest, dict) else None,
        "error_count": len(errors),
        "errors": redact_value_secrets(errors[:100]),
    }

def _verification_failure_message(result: dict[str, Any]) -> str:
    failed = [str(item.get("name")) for item in result.get("checks") or [] if not item.get("ok")]
    return ", ".join(failed) or str(result.get("reason") or "verification_failed")


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
        unsupported = [
            item for item in copy_result["skipped"]
            if item.get("reason") == "unsupported_file_type"
        ]
        if profile == "shareable" and unsupported:
            raise ValueError(
                f"shareable bundle refused because the root contains {len(unsupported)} unsupported file type(s)"
            )

        staged_proof_count = _proof_pack_count(stage_root)
        staged_verification = verify_root(
            stage_root,
            strict=True,
            verify_recent_proof_packs=staged_proof_count,
            run_restore_drill=False,
            scan_secrets=True,
            allow_symlinks=False,
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

            bundle_verification = verify_root_bundle(temp_zip, verify_embedded_root=False)
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
                    out_path, verify_embedded_root=False
                )
                if not final_verification.get("ok"):
                    raise ValueError(f"final bundle verification failed: {final_verification.get('errors')}")
                bundle_sha256 = file_sha256(out_path)
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
