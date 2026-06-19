from __future__ import annotations

import json
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from .config import load_config
from .operations import (
    atomic_write_json,
    atomic_write_text,
    create_preflight_snapshot,
    create_proof_pack,
    describe_path,
    finish_operation,
    proof_pack_path,
    record_operation_progress,
    start_operation,
    update_operation_cursor,
)
from .permissions import secure_copy_file, secure_copytree, secure_mkdir, secure_sqlite_files
from .safety import redact_text_secrets, redact_value_secrets, scan_text_for_secrets
from .store import (
    add_graph_edge,
    audit_event,
    chunk_text,
    connect,
    content_hash,
    continuum_uri,
    create_card,
    delete_book_fts,
    enqueue_job,
    estimate_tokens,
    extract_terms,
    file_sha256,
    index_chunk_fts,
    init_db,
    json_dumps,
    json_loads,
    record_artifact,
    stable_id,
    unique_id,
    summarize_text,
    upsert_graph_node,
    utc_now,
)


ProgressCallback = Callable[[dict[str, Any]], None]


@contextmanager
def mempalace_import_lock(root: Path, import_id: str, *, timeout_seconds: float = 60.0) -> Iterator[Path]:
    lock_dir = root / "run" / "locks"
    secure_mkdir(lock_dir)
    lock_path = lock_dir / "mempalace-import.lock"
    started = time.monotonic()
    stale_after_seconds = max(timeout_seconds * 3, 300.0)
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            try:
                age = time.time() - lock_path.stat().st_mtime
            except OSError:
                age = 0
            if age > stale_after_seconds:
                try:
                    lock_path.unlink()
                except OSError:
                    pass
                continue
            if time.monotonic() - started > timeout_seconds:
                raise TimeoutError(f"timed out waiting for MemPalace import lock: {lock_path}")
            time.sleep(0.15)
            continue
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                json.dump({"import_id": import_id, "pid": os.getpid(), "created_at": utc_now()}, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            yield lock_path
        finally:
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass
        return


def import_state_path(root: Path, import_id: str) -> Path:
    return root / "run" / "import_state" / f"{safe_filename(import_id)}.json"


IMPORT_RECEIPT_URI_KEYS = (
    "receipt_uri",
    "manifest_uri",
    "catalog_backup_uri",
    "resume_state_uri",
    "operation_receipt_uri",
    "proof_pack_uri",
)
IMPORT_SNAPSHOT_URI_KEYS = ("snapshot_dir", "chroma_db", "kg_db")


def _root_relative_uri_or_none(root: Path, path: Path) -> str | None:
    try:
        return path.resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()
    except (OSError, ValueError):
        return None


def safe_public_identifier(value: str, *, prefix: str, limit: int = 96) -> str:
    if scan_text_for_secrets(value, max_findings=1):
        return safe_filename(f"redacted_{prefix}_{content_hash(value)[:16]}", limit=limit)
    return safe_filename(value or prefix, limit=limit)


def source_path_reference(root: Path, path: Path) -> dict[str, Any]:
    rel = _root_relative_uri_or_none(root, path)
    safe_name = safe_public_identifier(path.name or "source", prefix="source", limit=80)
    name_redacted = safe_name != safe_filename(path.name or "source", limit=80)
    if rel is not None:
        if scan_text_for_secrets(rel, max_findings=1):
            return {
                "uri_base": "redacted_source",
                "uri": f"redacted:{content_hash(rel)[:16]}",
                "name": safe_name,
                "name_redacted": True,
                "path_hash": content_hash(rel),
            }
        return {"uri_base": "continuum_root", "uri": rel, "name": safe_name, "name_redacted": name_redacted}
    return {
        "uri_base": "external_source",
        "uri": f"external:{safe_name}",
        "name": safe_name,
        "name_redacted": name_redacted,
        "path_hash": content_hash(str(path.resolve(strict=False))),
    }


def _root_relative_any(root: Path, value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _root_relative_any(root, nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [_root_relative_any(root, nested) for nested in value]
    if isinstance(value, tuple):
        return [_root_relative_any(root, nested) for nested in value]
    if isinstance(value, str):
        candidate = Path(value)
        if candidate.is_absolute():
            rel = _root_relative_uri_or_none(root, candidate)
            if rel is not None:
                return rel
    return value


def _root_relative_snapshot(root: Path, snapshot: dict[str, Any]) -> dict[str, Any]:
    stored = dict(snapshot)
    for key in IMPORT_SNAPSHOT_URI_KEYS:
        value = stored.get(key)
        if value:
            stored[key] = continuum_uri(root, Path(str(value)))
    return stored


def _display_snapshot(root: Path, snapshot: dict[str, Any]) -> dict[str, Any]:
    displayed = dict(snapshot)
    for key in IMPORT_SNAPSHOT_URI_KEYS:
        value = displayed.get(key)
        if value:
            candidate = Path(str(value))
            displayed[key] = str(candidate if candidate.is_absolute() else root / candidate)
    return displayed


def root_relative_import_payload(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    stored = _root_relative_any(root, payload)
    if stored.get("palace_path") and not stored.get("palace_source"):
        palace_ref = source_path_reference(root, Path(str(stored["palace_path"])))
        stored["palace_path"] = palace_ref["uri"]
        stored["palace_source"] = palace_ref
    if isinstance(stored.get("snapshot"), dict):
        stored["snapshot"] = _root_relative_snapshot(root, stored["snapshot"])
    for key in IMPORT_RECEIPT_URI_KEYS:
        value = stored.get(key)
        if value:
            stored[key] = continuum_uri(root, Path(str(value)))
    return stored


def display_import_payload(root: Path, payload: dict[str, Any]) -> dict[str, Any]:
    displayed = dict(payload)
    if isinstance(displayed.get("snapshot"), dict):
        displayed["snapshot"] = _display_snapshot(root, displayed["snapshot"])
    for key in IMPORT_RECEIPT_URI_KEYS:
        value = displayed.get(key)
        if value:
            candidate = Path(str(value))
            displayed[key] = str(candidate if candidate.is_absolute() else root / candidate)
    return displayed


def write_import_state(
    root: Path,
    *,
    import_id: str,
    operation_id: str,
    phase: str,
    palace_path: Path,
    counts: dict[str, int],
    errors: list[dict[str, Any]],
    snapshot: dict[str, Any] | None = None,
    current: int | None = None,
    total: int | None = None,
    last_embedding_row_id: int | None = None,
    last_embedding_id: str | None = None,
    receipt_uri: str | None = None,
    proof_pack_uri: str | None = None,
) -> dict[str, Any]:
    state_uri = import_state_path(root, import_id)
    state = {
        "schema": "epic_continuum.mempalace_import_state.v1",
        "import_id": import_id,
        "operation_id": operation_id,
        "phase": phase,
        "palace_path": str(palace_path),
        "updated_at": utc_now(),
        "resume_token": f"mempalace:{import_id}",
        "resume_state_uri": str(state_uri),
        "current": current,
        "total": total,
        "last_embedding_row_id": last_embedding_row_id,
        "last_embedding_id": last_embedding_id,
        "snapshot": snapshot or {},
        "counts": dict(counts),
        "error_count": len(errors),
        "recent_errors": errors[-25:],
        "receipt_uri": receipt_uri,
        "proof_pack_uri": proof_pack_uri,
        "resume_instruction": (
            "Use this state as a durable cursor. A future resumable importer can continue from "
            "last_embedding_row_id against the preserved snapshot; current safe fallback is to rerun the import."
        ),
    }
    state_for_disk = root_relative_import_payload(root, state)
    atomic_write_json(state_uri, state_for_disk)
    return display_import_payload(root, state_for_disk)


def default_mempalace_path() -> Path:
    configured = os.environ.get("MEMPALACE_PATH") or os.environ.get("MEMPALACE_PALACE")
    candidates = []
    if configured:
        candidates.append(Path(configured))
    candidates.append(Path.home() / ".mempalace" / "palace")
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[-1]


def safe_filename(value: str, limit: int = 160) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return (cleaned or "mempalace_item")[:limit]


def metadata_value(row: sqlite3.Row) -> Any:
    for key in ("string_value", "int_value", "float_value", "bool_value"):
        value = row[key]
        if value is not None:
            if key == "bool_value":
                return bool(value)
            return value
    return None


def emit_progress(callback: ProgressCallback | None, payload: dict[str, Any]) -> None:
    if callback is not None:
        callback(payload)


def sqlite_backup(source: Path, dest: Path) -> None:
    secure_mkdir(dest.parent)
    source_uri = f"{source.resolve(strict=False).as_uri()}?mode=ro"
    src = sqlite3.connect(source_uri, uri=True, timeout=2)
    try:
        dst = sqlite3.connect(str(dest))
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    secure_sqlite_files(dest)


def stop_mempalace_processes() -> dict[str, Any]:
    stopped: list[dict[str, Any]] = []
    errors: list[str] = []
    system = platform.system().lower()
    if system == "windows":
        command = (
            "Get-CimInstance Win32_Process | "
            "Where-Object { $_.CommandLine -match 'mempalace-readonly-mcp' } | "
            "ForEach-Object { \"$($_.ProcessId)`t$($_.Name)`t$($_.CommandLine)\" }"
        )
        try:
            proc = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", command],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in proc.stdout.splitlines():
                if not line.strip():
                    continue
                pid_text, name, _matched_args = (line.split("\t", 2) + ["", ""])[:3]
                try:
                    pid = int(pid_text)
                except ValueError:
                    continue
                kill = subprocess.run(
                    ["taskkill.exe", "/PID", str(pid), "/T", "/F"],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                stopped.append(
                    {
                        "pid": pid,
                        "name": name,
                        "matched": "mempalace-readonly-mcp",
                        "returncode": kill.returncode,
                        "stdout": kill.stdout.strip(),
                        "stderr": kill.stderr.strip(),
                    }
                )
        except Exception as exc:
            errors.append(str(exc))
    else:
        try:
            proc = subprocess.run(
                ["pgrep", "-af", "mempalace-readonly-mcp"],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            current_pid = os.getpid()
            for line in proc.stdout.splitlines():
                parts = line.split(maxsplit=1)
                if not parts:
                    continue
                try:
                    pid = int(parts[0])
                except ValueError:
                    continue
                if pid == current_pid:
                    continue
                try:
                    os.kill(pid, 15)
                    stopped.append({"pid": pid, "matched": "mempalace-readonly-mcp", "signal": "TERM"})
                except ProcessLookupError:
                    continue
                except Exception as exc:
                    errors.append(f"{pid}: {exc}")
            time.sleep(0.8)
        except FileNotFoundError:
            errors.append("pgrep is not available")
        except Exception as exc:
            errors.append(str(exc))
    return {"stopped": stopped, "errors": errors}


def snapshot_mempalace(
    *,
    root: Path,
    palace_path: Path,
    import_id: str,
    allow_stop: bool,
    snapshot_dir: Path | None = None,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    snapshot_dir = snapshot_dir or root / "run" / "mempalace_import_snapshots" / safe_filename(import_id)
    source_chroma = palace_path / "chroma.sqlite3"
    source_kg = palace_path / "knowledge_graph.sqlite3"
    if not source_chroma.exists():
        raise FileNotFoundError(str(source_chroma))

    stopped: dict[str, Any] | None = None
    emit_progress(progress, {"phase": "snapshot", "message": "snapshotting chroma.sqlite3"})
    try:
        sqlite_backup(source_chroma, snapshot_dir / "chroma.sqlite3")
    except sqlite3.OperationalError as exc:
        if not allow_stop:
            raise RuntimeError(
                "MemPalace Chroma database is locked. Re-run with allow_stop=True to stop "
                "mempalace-readonly-mcp before snapshotting."
            ) from exc
        emit_progress(progress, {"phase": "stop", "message": "stopping MemPalace MCP processes"})
        stopped = stop_mempalace_processes()
        sqlite_backup(source_chroma, snapshot_dir / "chroma.sqlite3")

    if source_kg.exists():
        emit_progress(progress, {"phase": "snapshot", "message": "snapshotting knowledge_graph.sqlite3"})
        try:
            sqlite_backup(source_kg, snapshot_dir / "knowledge_graph.sqlite3")
        except sqlite3.OperationalError:
            secure_copy_file(source_kg, snapshot_dir / "knowledge_graph.sqlite3")
            secure_sqlite_files(snapshot_dir / "knowledge_graph.sqlite3")

    return {
        "snapshot_dir": str(snapshot_dir),
        "chroma_db": str(snapshot_dir / "chroma.sqlite3"),
        "kg_db": str(snapshot_dir / "knowledge_graph.sqlite3") if (snapshot_dir / "knowledge_graph.sqlite3").exists() else None,
        "stopped_processes": stopped,
    }


def quarantine_snapshot_reference(snapshot: dict[str, Any], *, policy: str = "quarantined_pending_secret_scan") -> dict[str, Any]:
    return {
        "snapshot_policy": policy,
        "source_snapshot_retained": False,
        "stopped_processes": snapshot.get("stopped_processes"),
    }


def promote_mempalace_snapshot(root: Path, import_id: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    source_dir = Path(str(snapshot["snapshot_dir"]))
    target_dir = root / "run" / "mempalace_import_snapshots" / safe_filename(import_id)
    if target_dir.exists():
        shutil.rmtree(target_dir)
    secure_copytree(source_dir, target_dir)
    promoted = dict(snapshot)
    promoted.update(
        {
            "snapshot_dir": str(target_dir),
            "chroma_db": str(target_dir / "chroma.sqlite3"),
            "kg_db": str(target_dir / "knowledge_graph.sqlite3") if (target_dir / "knowledge_graph.sqlite3").exists() else None,
            "snapshot_policy": "retained_after_secret_scan",
            "source_snapshot_retained": True,
        }
    )
    return promoted


def write_blocked_source_snapshot_manifest(
    root: Path,
    *,
    import_id: str,
    snapshot: dict[str, Any],
    counts: dict[str, int],
    errors: list[dict[str, Any]],
) -> tuple[Path, dict[str, Any]]:
    import_dir = root / "exports" / "imports" / safe_filename(import_id)
    manifest_path = import_dir / "blocked-source-snapshot.manifest.json"
    source_files: dict[str, dict[str, Any] | None] = {}
    for key in ("chroma_db", "kg_db"):
        value = snapshot.get(key)
        if not value:
            source_files[key] = None
            continue
        path = Path(str(value))
        source_files[key] = {
            "name": path.name,
            "sha256": file_sha256(path) if path.exists() else None,
            "size_bytes": path.stat().st_size if path.exists() else None,
        }
    payload = {
        "schema": "epic_continuum.mempalace_blocked_source_snapshot.v1",
        "import_id": import_id,
        "created_at": utc_now(),
        "snapshot_policy": "blocked_by_secret_policy",
        "source_snapshot_retained": False,
        "reason": "security.secret_scan_action=block found one or more secrets before raw source snapshot promotion",
        "counts": dict(counts),
        "source_files": source_files,
        "blocked_items": [
            {
                "embedding_id": item.get("embedding_id"),
                "blocked": bool(item.get("blocked")),
                "secret_finding_count": item.get("secret_finding_count"),
                "secret_finding_scopes": item.get("secret_finding_scopes"),
                "error": item.get("error"),
            }
            for item in errors
            if item.get("blocked")
        ],
    }
    atomic_write_json(manifest_path, payload)
    snapshot_ref = {
        "snapshot_policy": "blocked_by_secret_policy",
        "source_snapshot_retained": False,
        "blocked_source_manifest_uri": continuum_uri(root, manifest_path),
        "source_files": source_files,
        "stopped_processes": snapshot.get("stopped_processes"),
    }
    return manifest_path, snapshot_ref


def scan_mempalace_item_for_secrets(
    content: str,
    metadata: dict[str, Any],
    *,
    embedding_id: str | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for finding in scan_text_for_secrets(content, max_findings=10):
        scoped = dict(finding)
        scoped["scope"] = "content"
        findings.append(scoped)
    if embedding_id:
        for finding in scan_text_for_secrets(embedding_id, max_findings=5):
            scoped = dict(finding)
            scoped["scope"] = "embedding_id"
            findings.append(scoped)
    metadata_for_scan = {key: value for key, value in metadata.items() if key != "chroma:document"}
    metadata_text = json.dumps(metadata_for_scan, ensure_ascii=True, sort_keys=True, default=str)
    for finding in scan_text_for_secrets(metadata_text, max_findings=10):
        scoped = dict(finding)
        scoped["scope"] = "metadata"
        findings.append(scoped)
    return findings[:20]


def safe_metadata_key(key: Any) -> Any:
    if not isinstance(key, str):
        return key
    if scan_text_for_secrets(key, max_findings=1):
        return f"redacted_key_{content_hash(key)[:16]}"
    return key


def sanitize_mempalace_metadata(root: Path, metadata: dict[str, Any]) -> dict[str, Any]:
    sanitized: dict[str, Any] = {}
    for key, value in metadata.items():
        safe_key = safe_metadata_key(key)
        if key == "chroma:document":
            sanitized["chroma_document_present"] = isinstance(value, str) and bool(value.strip())
            continue
        if isinstance(value, str):
            redacted = redact_text_secrets(value)
            lowered = str(safe_key).lower()
            if not scan_text_for_secrets(value) and (
                lowered.endswith("source_file")
                or lowered.endswith("_path")
                or lowered in {"path", "file", "filename", "source_path"}
            ):
                ref = source_path_reference(root, Path(value))
                sanitized[safe_key] = ref["uri"]
                sanitized[f"{safe_key}_ref"] = ref
            else:
                sanitized[safe_key] = redacted
        else:
            sanitized[safe_key] = redact_value_secrets(value)
    return sanitized


def sanitize_kg_value(root: Path, key: str, value: Any) -> Any:
    if isinstance(value, dict):
        return {safe_metadata_key(nested_key): sanitize_kg_value(root, str(nested_key), nested_value) for nested_key, nested_value in value.items()}
    if isinstance(value, list):
        return [sanitize_kg_value(root, key, nested) for nested in value]
    if isinstance(value, str):
        if key.casefold() in {"api_key", "apikey", "secret", "token", "password"}:
            return "[REDACTED]"
        redacted = redact_text_secrets(value)
        lowered = key.lower()
        if redacted == value and (
            lowered.endswith("source_file")
            or lowered.endswith("_path")
            or lowered in {"path", "file", "filename", "source_path"}
        ):
            ref = source_path_reference(root, Path(value))
            return {"uri": ref["uri"], "source_ref": ref}
        return redacted
    return value


def secret_scan_material(value: Any, *, prefix: str = "") -> list[str]:
    lines: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            nested_prefix = f"{prefix}.{key}" if prefix else str(key)
            lines.extend(secret_scan_material(nested, prefix=nested_prefix))
        return lines
    if isinstance(value, list):
        for index, nested in enumerate(value):
            nested_prefix = f"{prefix}[{index}]" if prefix else str(index)
            lines.extend(secret_scan_material(nested, prefix=nested_prefix))
        return lines
    if prefix:
        lines.append(f"{prefix}={value}")
    else:
        lines.append(str(value))
    return lines


def kg_source_file_reference(root: Path, value: Any) -> dict[str, Any] | None:
    if not value:
        return None
    text = str(value)
    if scan_text_for_secrets(text):
        return {
            "uri_base": "external_source_redacted",
            "uri": "external:redacted",
            "name": "redacted",
            "path_hash": content_hash(redact_text_secrets(text)),
        }
    return source_path_reference(root, Path(text))


def load_metadata(conn: sqlite3.Connection, embedding_row_id: int) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    rows = conn.execute(
        """
        SELECT key, string_value, int_value, float_value, bool_value
        FROM embedding_metadata
        WHERE id = ?
        """,
        (embedding_row_id,),
    ).fetchall()
    for row in rows:
        metadata[row["key"]] = metadata_value(row)
    return metadata


def load_document(conn: sqlite3.Connection, embedding_row_id: int, metadata: dict[str, Any]) -> str:
    document = metadata.get("chroma:document")
    if isinstance(document, str):
        return document
    try:
        row = conn.execute(
            "SELECT string_value FROM embedding_fulltext_search WHERE rowid = ?",
            (embedding_row_id,),
        ).fetchone()
    except sqlite3.OperationalError:
        row = None
    if row and row["string_value"]:
        return str(row["string_value"])
    return ""


def classify_embedding(embedding_id: str) -> str:
    if embedding_id.startswith("drawer_"):
        return "drawer"
    if embedding_id.startswith("closet_"):
        return "closet"
    return "embedding"


def write_import_text(
    *,
    root: Path,
    import_id: str,
    embedding_id: str,
    content: str,
    digest: str,
    metadata: dict[str, Any],
    kind: str,
) -> dict[str, Path]:
    wing = str(metadata.get("wing") or "unknown_wing")
    room = str(metadata.get("room") or "unknown_room")
    safe_import = safe_filename(import_id)
    safe_embedding = safe_filename(embedding_id)
    safe_digest = safe_filename(digest, limit=96)
    rel_dir = (
        Path("archive")
        / "originals"
        / "hot"
        / "mempalace"
        / "by-import"
        / safe_import
        / safe_filename(wing)
        / safe_filename(room)
        / safe_embedding
    )
    original_path = root / rel_dir / f"{safe_digest}.md"
    payload = {
        "schema": "epic_continuum.mempalace_import.v1",
        "import_id": import_id,
        "mempalace_embedding_id": embedding_id,
        "mempalace_kind": kind,
        "content_hash": digest,
        "metadata": metadata,
    }
    text = "---continuum-import-json\n" + json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n---\n\n" + content
    atomic_write_text(original_path, text)

    reader_dir = (
        root
        / "archive"
        / "reader_editions"
        / "hot"
        / "mempalace"
        / "by-import"
        / safe_import
        / safe_filename(wing)
        / safe_filename(room)
        / safe_embedding
    )
    reader_path = reader_dir / f"{safe_digest}.txt"
    atomic_write_text(reader_path, content)

    hash_path = root / "archive" / "originals" / "hot" / "mempalace" / "by-hash" / digest[:2] / f"{digest}.txt"
    if not hash_path.exists():
        atomic_write_text(hash_path, content)
    return {"original_path": original_path, "reader_path": reader_path, "content_hash_path": hash_path}


def collect_import_artifact_paths(root: Path, import_id: str) -> list[Path]:
    safe_import = safe_filename(import_id)
    candidates = [
        root / "archive" / "originals" / "hot" / "mempalace" / "by-import" / safe_import,
        root / "archive" / "reader_editions" / "hot" / "mempalace" / "by-import" / safe_import,
    ]
    paths: list[Path] = []
    for candidate in candidates:
        if candidate.exists():
            paths.extend(path for path in candidate.rglob("*") if path.is_file())
    return sorted(paths)


def import_embedding(
    *,
    root: Path,
    target_conn: sqlite3.Connection,
    embedding: sqlite3.Row,
    metadata: dict[str, Any],
    content: str,
    import_id: str,
    operation_id: str,
    secret_findings: list[dict[str, Any]] | None = None,
    artifact_sink: list[Path] | None = None,
) -> dict[str, Any]:
    raw_embedding_id = str(embedding["embedding_id"])
    embedding_id = safe_public_identifier(raw_embedding_id, prefix="embedding", limit=120)
    kind = classify_embedding(raw_embedding_id)
    wing = str(metadata.get("wing") or "unknown_wing")
    room = str(metadata.get("room") or "unknown_room")
    source_file = metadata.get("source_file")
    title = f"MemPalace {kind}: {wing}/{room}/{embedding_id}"
    digest = content_hash(content)
    secret_findings = list(secret_findings) if secret_findings is not None else scan_text_for_secrets(content, max_findings=10)
    artifact_paths = write_import_text(
        root=root,
        import_id=import_id,
        embedding_id=embedding_id,
        content=content,
        digest=digest,
        metadata=metadata,
        kind=kind,
    )
    original_path = artifact_paths["original_path"]
    reader_path = artifact_paths["reader_path"]
    hash_path = artifact_paths["content_hash_path"]
    if artifact_sink is not None:
        artifact_sink.extend([original_path, reader_path, hash_path])
    artifact_ids: dict[str, str] = {}
    for artifact_kind, artifact_path in (
        ("mempalace_original", original_path),
        ("mempalace_reader", reader_path),
        ("mempalace_content_hash", hash_path),
    ):
        artifact_ids[artifact_kind] = record_artifact(
            target_conn,
            kind=artifact_kind,
            uri=continuum_uri(root, artifact_path),
            sha256=file_sha256(artifact_path),
            size_bytes=artifact_path.stat().st_size,
            operation_id=operation_id,
            immutable=True,
            source_type="imported_mempalace",
            trust_level="local_archive",
            metadata={
                "import_id": import_id,
                "mempalace_embedding_id": embedding_id,
                "mempalace_kind": kind,
                "content_hash": digest,
            },
        )
    now = utc_now()
    book_id = stable_id("book", "mempalace", embedding_id, digest)
    source_uri = f"mempalace://{wing}/{room}/{embedding_id}"
    embedding_id_hash = content_hash(raw_embedding_id) if raw_embedding_id != embedding_id else None
    original_uri = continuum_uri(root, original_path)
    reader_uri = continuum_uri(root, reader_path)
    hash_uri = continuum_uri(root, hash_path)
    current_source = {
        "import_id": import_id,
        "imported_at": now,
        "mempalace_embedding_id": embedding_id,
        "mempalace_embedding_id_hash": embedding_id_hash,
        "source_uri": source_uri,
        "original_uri": original_uri,
        "reader_uri": reader_uri,
        "location_uri": original_uri,
        "content_hash_uri": hash_uri,
        "artifact_ids": artifact_ids,
    }
    book_original_uri = original_uri
    book_reader_uri = reader_uri
    book_location_uri = original_uri
    existing_book = target_conn.execute(
        "SELECT original_uri, reader_uri, location_uri, metadata_json FROM books WHERE id = ?",
        (book_id,),
    ).fetchone()
    source_history = [current_source]
    first_import_id = import_id
    if existing_book:
        existing_metadata = json_loads(existing_book["metadata_json"], {})
        book_original_uri = str(existing_book["original_uri"])
        book_reader_uri = str(existing_book["reader_uri"])
        book_location_uri = str(existing_book["location_uri"])
        first_import_id = str(existing_metadata.get("first_import_id") or existing_metadata.get("import_id") or import_id)
        prior_history = existing_metadata.get("source_history")
        source_history = prior_history if isinstance(prior_history, list) else []
        if not source_history:
            source_history.append(
                {
                    "import_id": existing_metadata.get("import_id"),
                    "imported_at": existing_metadata.get("imported_at") or existing_metadata.get("created_at"),
                    "mempalace_embedding_id": existing_metadata.get("mempalace_embedding_id"),
                    "source_uri": source_uri,
                    "original_uri": existing_book["original_uri"],
                    "reader_uri": existing_book["reader_uri"],
                    "location_uri": existing_book["location_uri"],
                    "content_hash_uri": existing_metadata.get("content_hash_uri"),
                    "artifact_ids": existing_metadata.get("artifact_ids") or {},
                }
            )
        if not any(
            entry.get("import_id") == import_id and entry.get("original_uri") == original_uri
            for entry in source_history
            if isinstance(entry, dict)
        ):
            source_history.append(current_source)
    metadata_json = {
        "mempalace_import": True,
        "import_id": first_import_id,
        "first_import_id": first_import_id,
        "latest_import_id": import_id,
        "mempalace_embedding_id": embedding_id,
        "mempalace_embedding_id_hash": embedding_id_hash,
        "mempalace_kind": kind,
        "mempalace_metadata": metadata,
        "source_file": source_file,
        "created_at": embedding["created_at"],
        "content_hash_uri": hash_uri,
        "artifact_ids": artifact_ids,
        "canonical_original_uri": book_original_uri,
        "canonical_reader_uri": book_reader_uri,
        "canonical_location_uri": book_location_uri,
        "source_history": source_history,
        "source_history_count": len(source_history),
        "source_type": "imported_mempalace",
        "trust_level": "local_archive",
        "instruction_authority": False,
        "can_override_user": False,
        "contains_untrusted_text": True,
        "secret_findings": secret_findings,
    }
    target_conn.execute(
        """
        INSERT INTO books(
            id, title, source_uri, original_uri, reader_uri, content_hash,
            storage_tier, location_uri, status, metadata_json, created_at, updated_at
        )
        VALUES(?, ?, ?, ?, ?, ?, 'hot', ?, 'active', ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            title = excluded.title,
            metadata_json = excluded.metadata_json,
            updated_at = excluded.updated_at
        """,
        (
            book_id,
            title,
            source_uri,
            book_original_uri,
            book_reader_uri,
            digest,
            book_location_uri,
            json_dumps(metadata_json),
            now,
            now,
        ),
    )
    target_conn.execute("DELETE FROM chunks WHERE book_id = ?", (book_id,))
    fts_enabled = delete_book_fts(target_conn, book_id)
    for ordinal, chunk in enumerate(chunk_text(content)):
        chunk_id = stable_id("chunk", book_id, str(ordinal), content_hash(chunk))
        target_conn.execute(
            """
            INSERT INTO chunks(id, book_id, ordinal, text, content_hash, token_estimate, created_at)
            VALUES(?, ?, ?, ?, ?, ?, ?)
            """,
            (
                chunk_id,
                book_id,
                ordinal,
                chunk,
                content_hash(chunk),
                estimate_tokens(chunk),
                now,
            ),
        )
        if fts_enabled:
            index_chunk_fts(target_conn, chunk_id=chunk_id, book_id=book_id, title=title, text=chunk)
    card_id = create_card(
        target_conn,
        root=root,
        card_type=f"mempalace_{kind}",
        title=title,
        summary=summarize_text(content),
        source_refs=[
            {
                "book_id": book_id,
                "mempalace_embedding_id": embedding_id,
                "mempalace_wing": wing,
                "mempalace_room": room,
                "source_file": source_file,
                "content_hash": digest,
                "source_type": "imported_mempalace",
                "trust_level": "local_archive",
                "instruction_authority": False,
                "can_override_user": False,
                "contains_untrusted_text": True,
                "secret_findings": secret_findings,
            }
        ],
        entities=extract_terms(content),
        topics=[term for term in [wing, room, *extract_terms(content, limit=6)] if term],
        metadata={
            "import_id": import_id,
            "book_id": book_id,
            "mempalace_embedding_id": embedding_id,
            "mempalace_kind": kind,
            "mempalace_wing": wing,
            "mempalace_room": room,
            "source_type": "imported_mempalace",
            "trust_level": "local_archive",
            "instruction_authority": False,
            "can_override_user": False,
            "contains_untrusted_text": True,
            "secret_finding_count": len(secret_findings),
        },
        salience=0.7 if kind == "drawer" else 0.45,
        confidence=0.85,
    )
    card_node = upsert_graph_node(target_conn, kind="card", label=title, card_id=card_id)
    room_node = upsert_graph_node(target_conn, kind="mempalace_room", label=f"{wing}/{room}")
    wing_node = upsert_graph_node(target_conn, kind="mempalace_wing", label=wing)
    add_graph_edge(
        target_conn,
        source_node_id=card_node,
        relation="imported_from",
        target_node_id=room_node,
        weight=0.85,
        confidence=0.95,
        source_refs=[{"import_id": import_id, "mempalace_embedding_id": embedding_id}],
    )
    add_graph_edge(
        target_conn,
        source_node_id=room_node,
        relation="within_wing",
        target_node_id=wing_node,
        weight=0.9,
        confidence=0.95,
        source_refs=[{"import_id": import_id}],
    )
    return {
        "book_id": book_id,
        "card_id": card_id,
        "kind": kind,
        "wing": wing,
        "room": room,
        "content_hash": digest,
        "original_uri": str(original_path),
        "reader_uri": str(reader_path),
        "content_hash_uri": str(hash_path),
        "artifact_ids": artifact_ids,
        "secret_findings": secret_findings,
    }


def import_kg(root: Path, target_conn: sqlite3.Connection, kg_db: Path, import_id: str) -> dict[str, int]:
    if not kg_db.exists():
        return {"entities": 0, "triples": 0}
    source = sqlite3.connect(str(kg_db))
    source.row_factory = sqlite3.Row
    try:
        entity_rows = source.execute("SELECT * FROM entities").fetchall()
        entity_nodes: dict[str, str] = {}
        for row in entity_rows:
            properties = sanitize_kg_value(root, "properties", json_loads(row["properties"], {}))
            entity_type = redact_text_secrets(str(row["type"] or "unknown"))
            entity_label = redact_text_secrets(str(row["name"]))
            node_id = upsert_graph_node(
                target_conn,
                kind=f"mempalace_entity:{entity_type}",
                label=entity_label,
                metadata={
                    "import_id": import_id,
                    "mempalace_entity_id": safe_public_identifier(str(row["id"]), prefix="kg_entity", limit=120),
                    "mempalace_entity_id_hash": content_hash(str(row["id"]))
                    if safe_public_identifier(str(row["id"]), prefix="kg_entity", limit=120) != str(row["id"])
                    else None,
                    "properties": properties,
                },
            )
            entity_nodes[row["id"]] = node_id
        triple_rows = source.execute("SELECT * FROM triples").fetchall()
        for row in triple_rows:
            source_node = entity_nodes.get(row["subject"])
            target_node = entity_nodes.get(row["object"])
            if not source_node or not target_node:
                continue
            source_file_ref = kg_source_file_reference(root, row["source_file"])
            predicate = redact_text_secrets(str(row["predicate"]))
            source_drawer_id = redact_text_secrets(str(row["source_drawer_id"])) if row["source_drawer_id"] else None
            add_graph_edge(
                target_conn,
                source_node_id=source_node,
                relation=predicate,
                target_node_id=target_node,
                weight=max(0.05, min(1.0, float(row["confidence"] or 1.0))),
                confidence=max(0.05, min(1.0, float(row["confidence"] or 1.0))),
                source_refs=[
                    {
                        "import_id": import_id,
                        "mempalace_triple_id": safe_public_identifier(str(row["id"]), prefix="kg_triple", limit=120),
                        "mempalace_triple_id_hash": content_hash(str(row["id"]))
                        if safe_public_identifier(str(row["id"]), prefix="kg_triple", limit=120) != str(row["id"])
                        else None,
                        "source_file": source_file_ref["uri"] if source_file_ref else None,
                        "source_file_ref": source_file_ref,
                        "source_drawer_id": source_drawer_id,
                    }
                ],
            )
        return {"entities": len(entity_rows), "triples": len(triple_rows)}
    finally:
        source.close()


def scan_kg_for_secrets(kg_db: Path) -> list[dict[str, Any]]:
    if not kg_db.exists():
        return []
    findings: list[dict[str, Any]] = []
    source = sqlite3.connect(str(kg_db))
    source.row_factory = sqlite3.Row
    try:
        try:
            entity_rows = source.execute("SELECT id, name, type, properties FROM entities").fetchall()
            triple_rows = source.execute("SELECT id, predicate, source_file, source_drawer_id FROM triples").fetchall()
        except sqlite3.OperationalError:
            return []
        for row in entity_rows:
            properties = json_loads(row["properties"], {})
            payload = {
                "entity_id": row["id"],
                "name": row["name"],
                "type": row["type"],
                "properties": properties,
                "properties_raw": row["properties"],
            }
            payload_text = "\n".join(
                [
                    json.dumps(payload, ensure_ascii=True, sort_keys=True, default=str),
                    *secret_scan_material(properties, prefix="properties"),
                ]
            )
            for finding in scan_text_for_secrets(payload_text, max_findings=10):
                scoped = dict(finding)
                scoped["scope"] = "knowledge_graph_entity"
                scoped["entity_id"] = row["id"]
                findings.append(scoped)
                if len(findings) >= 20:
                    return findings
        for row in triple_rows:
            payload = {
                "triple_id": row["id"],
                "predicate": row["predicate"],
                "source_file": row["source_file"],
                "source_drawer_id": row["source_drawer_id"],
            }
            payload_text = json.dumps(payload, ensure_ascii=True, sort_keys=True, default=str)
            for finding in scan_text_for_secrets(payload_text, max_findings=10):
                scoped = dict(finding)
                scoped["scope"] = "knowledge_graph_metadata"
                scoped["triple_id"] = row["id"]
                findings.append(scoped)
                if len(findings) >= 20:
                    return findings
        return findings
    finally:
        source.close()


def import_mempalace(
    root: Path,
    *,
    palace_path: Path | None = None,
    include_closets: bool = True,
    include_kg: bool = True,
    allow_stop: bool = False,
    progress: ProgressCallback | None = None,
) -> dict[str, Any]:
    palace = palace_path or default_mempalace_path()
    import_id = unique_id("import")
    with mempalace_import_lock(root, import_id):
        return _import_mempalace_locked(
            root,
            palace=palace,
            import_id=import_id,
            include_closets=include_closets,
            include_kg=include_kg,
            allow_stop=allow_stop,
            progress=progress,
        )


def _import_mempalace_locked(
    root: Path,
    *,
    palace: Path,
    import_id: str,
    include_closets: bool,
    include_kg: bool,
    allow_stop: bool,
    progress: ProgressCallback | None,
) -> dict[str, Any]:
    init_db(root)
    palace_source = source_path_reference(root, palace)
    operation = start_operation(
        root,
        operation_type="mempalace_import",
        title="Import MemPalace into Epic Continuum",
        intent={
            "import_id": import_id,
            "palace_path": palace_source["uri"],
            "palace_source": palace_source,
            "include_closets": include_closets,
            "include_kg": include_kg,
            "allow_stop": allow_stop,
            "preflight_snapshot_policy": "auto",
            "preflight_snapshot_reason": "MemPalace import mutates Library/catalog",
        },
    )
    operation_id = operation["operation_id"]

    def import_progress(payload: dict[str, Any]) -> None:
        emit_progress(progress, payload)
        record_operation_progress(
            root,
            operation_id,
            phase=str(payload.get("phase", "work")),
            message=str(payload.get("message", "")),
            current=payload.get("current") if isinstance(payload.get("current"), int) else None,
            total=payload.get("total") if isinstance(payload.get("total"), int) else None,
            detail={"counts": payload.get("counts")} if payload.get("counts") else None,
        )

    snapshot: dict[str, Any] = {}
    working_snapshot: dict[str, Any] = {}
    blocked_snapshot_manifest_path: Path | None = None
    quarantine_tmp = tempfile.TemporaryDirectory(prefix=f"continuum-mempalace-{safe_filename(import_id, limit=48)}-")
    source: sqlite3.Connection | None = None
    target: sqlite3.Connection | None = None
    counts = {
        "embeddings_seen": 0,
        "drawers_imported": 0,
        "closets_imported": 0,
        "other_embeddings_imported": 0,
        "skipped": 0,
        "books": 0,
        "cards": 0,
        "chunks": 0,
        "kg_entities": 0,
        "kg_triples": 0,
        "secret_findings": 0,
    }
    errors: list[dict[str, Any]] = []
    imported_items: list[dict[str, Any]] = []
    imported_artifact_paths: list[Path] = []
    resume_state = write_import_state(
        root,
        import_id=import_id,
        operation_id=operation_id,
        phase="started",
        palace_path=palace,
        counts=counts,
        errors=errors,
    )
    try:
        try:
            catalog_snapshot = create_preflight_snapshot(
                root,
                operation_id,
                reason="mempalace_import mutates Library/catalog",
            )
            record_operation_progress(
                root,
                operation_id,
                phase="preflight_snapshot",
                message="catalog snapshot created",
                detail=catalog_snapshot,
            )
        except Exception as exc:
            record_operation_progress(
                root,
                operation_id,
                phase="preflight_snapshot",
                message=f"catalog snapshot skipped: {exc}",
                detail={"error_type": type(exc).__name__},
            )
        working_snapshot = snapshot_mempalace(
            root=root,
            palace_path=palace,
            import_id=import_id,
            allow_stop=allow_stop,
            snapshot_dir=Path(quarantine_tmp.name) / safe_filename(import_id),
            progress=import_progress,
        )
        snapshot = quarantine_snapshot_reference(working_snapshot)
        update_operation_cursor(
            root,
            operation_id,
            {
                "phase": "snapshot",
                "snapshot_policy": snapshot["snapshot_policy"],
                "source_snapshot_retained": False,
                "import_id": import_id,
            },
        )
        resume_state = write_import_state(
            root,
            import_id=import_id,
            operation_id=operation_id,
            phase="snapshot",
            palace_path=palace,
            counts=counts,
            errors=errors,
            snapshot=snapshot,
        )
        chroma_db = Path(working_snapshot["chroma_db"])
        kg_db = Path(working_snapshot["kg_db"]) if working_snapshot.get("kg_db") else None
        source = sqlite3.connect(str(chroma_db))
        source.row_factory = sqlite3.Row
        target = connect(root)
        security_config = load_config(root).get("security", {})
        secret_scan_enabled = bool(security_config.get("secret_scan_enabled", True))
        secret_action = str(security_config.get("secret_scan_action") or "warn")
        rows = source.execute(
            """
            SELECT id, embedding_id, created_at
            FROM embeddings
            ORDER BY id
            """
        ).fetchall()
        total = len(rows)
        import_progress({"phase": "import", "current": 0, "total": total, "message": "starting embeddings"})
        for index, row in enumerate(rows, start=1):
            embedding_id = str(row["embedding_id"])
            display_embedding_id = safe_public_identifier(embedding_id, prefix="embedding", limit=120)
            kind = classify_embedding(embedding_id)
            counts["embeddings_seen"] += 1
            if kind == "closet" and not include_closets:
                counts["skipped"] += 1
                continue
            metadata = load_metadata(source, int(row["id"]))
            content = load_document(source, int(row["id"]), metadata)
            if not content.strip():
                counts["skipped"] += 1
                continue
            secret_findings: list[dict[str, Any]] = []
            if secret_scan_enabled and secret_action != "off":
                secret_findings = scan_mempalace_item_for_secrets(content, metadata, embedding_id=embedding_id)
                if secret_findings and secret_action == "block":
                    counts["secret_findings"] += len(secret_findings)
                    counts["skipped"] += 1
                    errors.append(
                        {
                            "embedding_id": display_embedding_id,
                            "embedding_id_hash": content_hash(embedding_id) if display_embedding_id != embedding_id else None,
                            "error": "secret scan blocked MemPalace import item before archiving",
                            "blocked": True,
                            "secret_finding_count": len(secret_findings),
                            "secret_finding_scopes": sorted(
                                {str(finding.get("scope") or "unknown") for finding in secret_findings}
                            ),
                        }
                    )
                    continue
            sanitized_metadata = sanitize_mempalace_metadata(root, metadata)
            try:
                result = import_embedding(
                    root=root,
                    target_conn=target,
                    embedding=row,
                    metadata=sanitized_metadata,
                    content=content,
                    import_id=import_id,
                    operation_id=operation_id,
                    secret_findings=secret_findings,
                    artifact_sink=imported_artifact_paths,
                )
                imported_items.append(result)
                for key in ("original_uri", "reader_uri", "content_hash_uri"):
                    if result.get(key):
                        imported_artifact_paths.append(Path(str(result[key])))
                if result["kind"] == "drawer":
                    counts["drawers_imported"] += 1
                elif result["kind"] == "closet":
                    counts["closets_imported"] += 1
                else:
                    counts["other_embeddings_imported"] += 1
                counts["books"] += 1
                counts["cards"] += 1
                counts["chunks"] += len(chunk_text(content))
                counts["secret_findings"] += len(result.get("secret_findings") or [])
            except Exception as exc:
                errors.append(
                    {
                        "embedding_id": display_embedding_id,
                        "embedding_id_hash": content_hash(embedding_id) if display_embedding_id != embedding_id else None,
                        "error": str(exc),
                    }
                )
            if index == total or index % 10 == 0:
                update_operation_cursor(
                    root,
                    operation_id,
                    {
                        "phase": "import",
                        "current": index,
                        "total": total,
                        "last_embedding_id": display_embedding_id,
                        "last_embedding_id_hash": content_hash(embedding_id) if display_embedding_id != embedding_id else None,
                        "counts": dict(counts),
                    },
                )
                resume_state = write_import_state(
                    root,
                    import_id=import_id,
                    operation_id=operation_id,
                    phase="import",
                    palace_path=palace,
                    counts=counts,
                    errors=errors,
                    snapshot=snapshot,
                    current=index,
                    total=total,
                    last_embedding_row_id=int(row["id"]),
                    last_embedding_id=display_embedding_id,
                )
                import_progress(
                    {
                        "phase": "import",
                        "current": index,
                        "total": total,
                        "message": display_embedding_id,
                        "counts": dict(counts),
                    },
                )
        if include_kg and kg_db is not None:
            update_operation_cursor(
                root,
                operation_id,
                {
                    "phase": "kg",
                    "snapshot_policy": snapshot.get("snapshot_policy"),
                    "source_snapshot_retained": bool(snapshot.get("source_snapshot_retained")),
                    "counts": dict(counts),
                },
            )
            import_progress({"phase": "kg", "message": "importing knowledge graph"})
            kg_secret_findings: list[dict[str, Any]] = []
            if secret_scan_enabled and secret_action != "off":
                kg_secret_findings = scan_kg_for_secrets(kg_db)
            if kg_secret_findings and secret_action == "block":
                counts["secret_findings"] += len(kg_secret_findings)
                counts["skipped"] += 1
                errors.append(
                    {
                        "embedding_id": "knowledge_graph",
                        "error": "secret scan blocked MemPalace knowledge graph before archiving",
                        "blocked": True,
                        "secret_finding_count": len(kg_secret_findings),
                        "secret_finding_scopes": sorted(
                            {str(finding.get("scope") or "unknown") for finding in kg_secret_findings}
                        ),
                    }
                )
            else:
                kg_counts = import_kg(root, target, kg_db, import_id)
                counts["kg_entities"] = kg_counts["entities"]
                counts["kg_triples"] = kg_counts["triples"]
            resume_state = write_import_state(
                root,
                import_id=import_id,
                operation_id=operation_id,
                phase="kg",
                palace_path=palace,
                counts=counts,
                errors=errors,
                snapshot=snapshot,
                current=total,
                total=total,
            )
        if secret_scan_enabled and secret_action == "block" and counts["secret_findings"] > 0:
            blocked_snapshot_manifest_path, snapshot = write_blocked_source_snapshot_manifest(
                root,
                import_id=import_id,
                snapshot=working_snapshot,
                counts=counts,
                errors=errors,
            )
            imported_artifact_paths.append(blocked_snapshot_manifest_path)
        else:
            snapshot = promote_mempalace_snapshot(root, import_id, working_snapshot)
        resume_state = write_import_state(
            root,
            import_id=import_id,
            operation_id=operation_id,
            phase="snapshot_retained" if snapshot.get("source_snapshot_retained") else "snapshot_blocked",
            palace_path=palace,
            counts=counts,
            errors=errors,
            snapshot=snapshot,
            current=total,
            total=total,
        )
        enqueue_job(
            target,
            role="librarian",
            job_type="review_mempalace_import",
            priority=65,
            payload={"import_id": import_id, "counts": counts, "snapshot": _root_relative_snapshot(root, snapshot)},
            preemptible=True,
        )
        audit_event(
            target,
            action="import_mempalace",
            target_type="mempalace",
            target_id=import_id,
            payload={
                "palace_path": palace_source["uri"],
                "palace_source": palace_source,
                "snapshot": _root_relative_snapshot(root, snapshot),
                "counts": counts,
                "errors": errors[:25],
            },
        )
        target.commit()

        import_dir = root / "exports" / "imports" / safe_filename(import_id)
        receipt_path = import_dir / "receipt.final.json"
        manifest_path = import_dir / "originals.manifest.json"
        catalog_backup_path = import_dir / "catalog.snapshot.sqlite3"
        proof_uri = str(proof_pack_path(root, operation_id))
        unique_artifact_paths = sorted({str(path) for path in imported_artifact_paths})
        manifest_items: list[dict[str, Any]] = []
        for item in imported_items:
            manifest_item = dict(item)
            for uri_key in ("original_uri", "reader_uri", "content_hash_uri"):
                if manifest_item.get(uri_key):
                    manifest_item[uri_key] = continuum_uri(root, Path(str(manifest_item[uri_key])))
            manifest_items.append(manifest_item)
        manifest = {
            "schema": "epic_continuum.mempalace_originals_manifest.v1",
            "import_id": import_id,
            "operation_id": operation_id,
            "created_at": utc_now(),
            "palace_path": palace_source["uri"],
            "palace_source": palace_source,
            "resume_token": resume_state["resume_token"],
            "resume_state_uri": continuum_uri(root, Path(str(resume_state["resume_state_uri"]))),
            "artifact_count": len(unique_artifact_paths),
            "artifacts": [describe_path(Path(path), root=root) for path in unique_artifact_paths],
            "items": manifest_items,
            "source_snapshot": {
                "snapshot_policy": snapshot.get("snapshot_policy"),
                "source_snapshot_retained": bool(snapshot.get("source_snapshot_retained")),
                "blocked_source_manifest_uri": snapshot.get("blocked_source_manifest_uri"),
                "snapshot_dir": continuum_uri(root, Path(snapshot["snapshot_dir"])) if snapshot.get("snapshot_dir") else None,
                "chroma_db": describe_path(Path(snapshot["chroma_db"]), root=root) if snapshot.get("chroma_db") else None,
                "kg_db": describe_path(Path(snapshot["kg_db"]), root=root) if snapshot.get("kg_db") else None,
            },
        }
        atomic_write_json(manifest_path, manifest)
        update_operation_cursor(
            root,
            operation_id,
            {
                "phase": "finalizing",
                "import_id": import_id,
                "receipt_uri": continuum_uri(root, receipt_path),
                "manifest_uri": continuum_uri(root, manifest_path),
                "catalog_backup_uri": continuum_uri(root, catalog_backup_path),
                "counts": dict(counts),
            },
        )
        update_operation_cursor(
            root,
            operation_id,
            {
                "phase": "done",
                "import_id": import_id,
                "receipt_uri": continuum_uri(root, receipt_path),
                "manifest_uri": continuum_uri(root, manifest_path),
                "catalog_backup_uri": continuum_uri(root, catalog_backup_path),
                "proof_pack_uri": continuum_uri(root, Path(proof_uri)),
                "counts": dict(counts),
            },
        )
        import_progress(
            {
                "phase": "done",
                "current": counts["embeddings_seen"],
                "total": counts["embeddings_seen"],
                "message": str(receipt_path),
            }
        )
        finished = finish_operation(
            root,
            operation_id,
            status="succeeded",
            result={
                "import_id": import_id,
                "palace_path": palace_source["uri"],
                "palace_source": palace_source,
                "snapshot": _root_relative_snapshot(root, snapshot),
                "counts": counts,
                "error_count": len(errors),
                "receipt_uri": continuum_uri(root, receipt_path),
                "manifest_uri": continuum_uri(root, manifest_path),
                "catalog_backup_uri": continuum_uri(root, catalog_backup_path),
                "proof_pack_uri": continuum_uri(root, Path(proof_uri)),
                "resume_token": resume_state["resume_token"],
                "resume_state_uri": continuum_uri(root, Path(str(resume_state["resume_state_uri"]))),
            },
        )
        receipt = {
            "schema": "epic_continuum.mempalace_import_receipt.v1",
            "import_id": import_id,
            "operation_id": operation_id,
            "created_at": utc_now(),
            "palace_path": palace_source["uri"],
            "palace_source": palace_source,
            "snapshot": snapshot,
            "counts": counts,
            "error_count": len(errors),
            "errors": errors[:100],
            "receipt_uri": str(receipt_path),
            "manifest_uri": str(manifest_path),
            "catalog_backup_uri": str(catalog_backup_path),
            "resume_token": resume_state["resume_token"],
            "resume_state_uri": resume_state["resume_state_uri"],
            "operation_receipt_uri": finished["export_receipt_uri"],
            "proof_pack_uri": proof_uri,
            "artifact_count": len(unique_artifact_paths),
        }
        receipt_for_disk = root_relative_import_payload(root, receipt)
        atomic_write_json(receipt_path, receipt_for_disk)
        resume_state = write_import_state(
            root,
            import_id=import_id,
            operation_id=operation_id,
            phase="done",
            palace_path=palace,
            counts=counts,
            errors=errors,
            snapshot=snapshot,
            current=counts["embeddings_seen"],
            total=counts["embeddings_seen"],
            receipt_uri=str(receipt_path),
            proof_pack_uri=proof_uri,
        )
        for artifact_kind, artifact_path in (
            ("mempalace_import_manifest", manifest_path),
            ("mempalace_import_receipt", receipt_path),
            ("mempalace_import_state", Path(str(resume_state["resume_state_uri"]))),
        ):
            record_artifact(
                target,
                kind=artifact_kind,
                uri=continuum_uri(root, artifact_path),
                sha256=file_sha256(artifact_path),
                size_bytes=artifact_path.stat().st_size,
                operation_id=operation_id,
                immutable=True,
                source_type="imported_mempalace",
                trust_level="local_archive",
                metadata={"import_id": import_id},
            )
        target.commit()
        target.close()
        target = None
        if source is not None:
            source.close()
            source = None
        sqlite_backup(root / "catalog" / "catalog.sqlite3", catalog_backup_path)
        proof_touched_paths = [
            receipt_path,
            manifest_path,
            Path(str(resume_state["resume_state_uri"])),
            catalog_backup_path,
        ]
        if snapshot.get("chroma_db"):
            proof_touched_paths.append(Path(snapshot["chroma_db"]))
        if snapshot.get("kg_db"):
            proof_touched_paths.append(Path(snapshot["kg_db"]))
        if blocked_snapshot_manifest_path is not None:
            proof_touched_paths.append(blocked_snapshot_manifest_path)
        proof = create_proof_pack(
            root,
            operation_id,
            touched_paths=proof_touched_paths,
            extra={
                "import_id": import_id,
                "finished_receipt_hash": finished.get("receipt_hash"),
                "catalog_hash_scope": "catalog.snapshot.sqlite3 backup, not live catalog/catalog.sqlite3",
                "manifest_uri": continuum_uri(root, manifest_path),
                "artifact_count": len(unique_artifact_paths),
            },
        )
        if str(proof["proof_pack_uri"]) != proof_uri:
            raise RuntimeError("predicted proof pack URI did not match created proof pack URI")
        return display_import_payload(root, receipt_for_disk)
    except Exception as exc:
        if source is not None:
            source.close()
            source = None
        if target is not None:
            try:
                target.rollback()
            except sqlite3.Error:
                pass
            target.close()
            target = None
        failure_dir = root / "exports" / "imports" / safe_filename(import_id)
        failure_receipt_path = failure_dir / "receipt.failed.json"
        failure_catalog_backup_path = failure_dir / "catalog.failure.sqlite3"
        touched_paths: list[Path] = []
        if (root / "catalog" / "catalog.sqlite3").exists():
            try:
                sqlite_backup(root / "catalog" / "catalog.sqlite3", failure_catalog_backup_path)
                touched_paths.append(failure_catalog_backup_path)
            except sqlite3.Error:
                pass
        proof_uri = str(proof_pack_path(root, operation_id))
        failure_message = str(exc).replace(str(palace), palace_source["uri"])
        failure_state = write_import_state(
            root,
            import_id=import_id,
            operation_id=operation_id,
            phase="failed",
            palace_path=palace,
            counts=counts,
            errors=errors,
            snapshot=snapshot,
            receipt_uri=str(failure_receipt_path),
            proof_pack_uri=proof_uri,
        )
        finished = finish_operation(
            root,
            operation_id,
            status="failed",
            error={"type": type(exc).__name__, "message": failure_message, "counts": counts, "error_count": len(errors)},
        )
        failure_receipt = {
            "schema": "epic_continuum.mempalace_import_receipt.v1",
            "status": "failed",
            "import_id": import_id,
            "operation_id": operation_id,
            "created_at": utc_now(),
            "palace_path": palace_source["uri"],
            "palace_source": palace_source,
            "snapshot": snapshot,
            "counts": counts,
            "error_count": len(errors),
            "errors": errors[:100],
            "failure": {"type": type(exc).__name__, "message": failure_message},
            "receipt_uri": str(failure_receipt_path),
            "catalog_backup_uri": str(failure_catalog_backup_path) if failure_catalog_backup_path.exists() else None,
            "resume_token": failure_state["resume_token"],
            "resume_state_uri": failure_state["resume_state_uri"],
            "operation_receipt_uri": finished["export_receipt_uri"],
            "proof_pack_uri": proof_uri,
        }
        failure_receipt_for_disk = root_relative_import_payload(root, failure_receipt)
        atomic_write_json(failure_receipt_path, failure_receipt_for_disk)
        touched_paths.append(failure_receipt_path)
        touched_paths.append(Path(str(failure_state["resume_state_uri"])))
        touched_paths.extend(imported_artifact_paths)
        touched_paths.extend(collect_import_artifact_paths(root, import_id))
        touched_paths = sorted({path for path in touched_paths if path.exists()}, key=lambda item: str(item))
        create_proof_pack(
            root,
            operation_id,
            touched_paths=touched_paths,
            extra={
                "failure_type": type(exc).__name__,
                "import_id": import_id,
                "partial_artifact_count": len(touched_paths),
            },
        )
        raise
    finally:
        if source is not None:
            source.close()
        if target is not None:
            target.close()
        quarantine_tmp.cleanup()


def progress_bar(payload: dict[str, Any]) -> None:
    phase = str(payload.get("phase", "work"))
    current = int(payload.get("current") or 0)
    total = int(payload.get("total") or 0)
    message = str(payload.get("message") or "")
    if total > 0:
        width = 28
        filled = int(width * min(current, total) / total)
        bar = "#" * filled + "-" * (width - filled)
        sys.stderr.write(f"\r[{bar}] {current}/{total} {phase}: {message[:80]}")
        if current >= total or phase == "done":
            sys.stderr.write("\n")
    else:
        sys.stderr.write(f"{phase}: {message}\n")
    sys.stderr.flush()
