from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import tempfile
import traceback
from pathlib import Path
from typing import Any

from .config import config_path, load_config, write_default_config
from .permissions import (
    audit_private_permissions,
    repair_private_permissions,
    secure_copy_file,
    secure_copytree,
    secure_file,
    secure_mkdir,
    secure_sqlite_files,
    secure_write_text,
)
from .safety import redact_text_secrets, redact_value_secrets, scan_text_for_secrets, scan_value_for_secrets
from .store import (
    SCHEMA_PATH,
    SCHEMA_VERSION,
    audit,
    audit_search_index,
    audit_secrets,
    connect,
    connect_existing,
    content_hash,
    file_sha256,
    init_db,
    init_layout,
    is_internal_absolute_uri,
    is_initialized,
    record_artifact,
    resolve_stored_uri,
    snapshot,
    status,
    unique_id,
    utc_now,
)


EPIC_PRINCIPLE = "No one said we could not back it up while building it."
OPERATION_SCHEMA = "epic_continuum.operation_receipt.v1"
OPERATION_EVENT_SCHEMA = "epic_continuum.operation_event.v1"
PROOF_PACK_SCHEMA = "epic_continuum.proof_pack.v1"
OPERATION_RECOVERY_SCHEMA = "epic_continuum.operation_recovery.v1"
RECOVERY_DRILL_SCHEMA = "epic_continuum.recovery_drill.v1"
RESTORE_DRILL_SCHEMA = "epic_continuum.restore_drill.v1"
TERMINAL_STATUSES = {"succeeded", "failed", "interrupted"}
ACTIVE_STATUSES = {"running"}


def safe_slug(value: str, limit: int = 96) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return (cleaned or "operation")[:limit]


def secret_safe_slug(value: str, *, prefix: str = "path", limit: int = 96) -> str:
    if scan_text_for_secrets(value, max_findings=1):
        return safe_slug(f"redacted_{prefix}_{content_hash(value)[:16]}", limit=limit)
    return safe_slug(value, limit=limit)


def atomic_write_text(path: Path, text: str) -> None:
    secure_write_text(path, text)


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    atomic_write_text(path, json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n")


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    secure_mkdir(path.parent)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    secure_file(path)


def operation_paths(root: Path, operation_id: str) -> dict[str, Path]:
    return {
        "run": root / "run" / "operations" / f"{operation_id}.json",
        "export": root / "exports" / "operation_receipts" / f"{operation_id}.json",
    }


def operation_event_paths(root: Path, operation_id: str) -> dict[str, Path]:
    return {
        "run": root / "run" / "operation_events" / f"{operation_id}.jsonl",
        "export": root / "exports" / "operation_events" / f"{operation_id}.jsonl",
    }


def proof_pack_path(root: Path, operation_id: str) -> Path:
    return root / "exports" / "proof_packs" / f"{operation_id}.json"


def proof_artifact_dir(root: Path, operation_id: str) -> Path:
    return root / "exports" / "proof_artifacts" / operation_id


def operation_recovery_path(root: Path, operation_id: str) -> Path:
    return root / "exports" / "operation_recovery" / f"{operation_id}.md"


def operation_recovery_json_path(root: Path, operation_id: str) -> Path:
    return root / "exports" / "operation_recovery" / f"{operation_id}.recovery.json"


def _stable_json_hash(payload: dict[str, Any]) -> str:
    material = {key: value for key, value in payload.items() if key != "receipt_hash"}
    return content_hash(json.dumps(material, ensure_ascii=True, sort_keys=True, default=str))


def _operation_event_hash(payload: dict[str, Any]) -> str:
    material = {key: value for key, value in payload.items() if key != "event_hash"}
    return content_hash(json.dumps(material, ensure_ascii=True, sort_keys=True, default=str))


def verify_operation_event_log(path: Path, *, operation_id: str | None = None) -> dict[str, Any]:
    """Verify a hash-chained operation JSONL log."""
    errors: list[dict[str, Any]] = []
    event_count = 0
    expected_previous: str | None = None
    last_event_hash: str | None = None
    if not path.exists():
        return {"ok": False, "path": str(path), "event_count": 0, "last_event_hash": None, "errors": [{"line": 0, "error": "missing"}]}
    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append({"line": line_number, "error": f"json_decode: {exc}"})
            continue
        event_count += 1
        stored_hash = event.get("event_hash")
        actual_hash = _operation_event_hash(event)
        if event.get("schema") != OPERATION_EVENT_SCHEMA:
            errors.append({"line": line_number, "error": "schema_mismatch", "actual": event.get("schema")})
        if operation_id is not None and event.get("operation_id") != operation_id:
            errors.append({"line": line_number, "error": "operation_id_mismatch", "actual": event.get("operation_id"), "expected": operation_id})
        if stored_hash != actual_hash:
            errors.append({"line": line_number, "error": "event_hash_mismatch", "expected": stored_hash, "actual": actual_hash})
        if event.get("previous_event_hash") != expected_previous:
            errors.append({"line": line_number, "error": "previous_event_hash_mismatch", "expected": expected_previous, "actual": event.get("previous_event_hash")})
        expected_previous = stored_hash if isinstance(stored_hash, str) else actual_hash
        last_event_hash = expected_previous
    if event_count == 0:
        errors.append({"line": 0, "error": "empty_operation_event_log"})
    return {
        "ok": not errors,
        "path": str(path),
        "event_count": event_count,
        "last_event_hash": last_event_hash,
        "errors": errors[:20],
    }


def replay_operation_event_log(path: Path, *, operation_id: str | None = None) -> dict[str, Any]:
    """Replay an operation JSONL log into a compact reconstructed state."""
    verification = verify_operation_event_log(path, operation_id=operation_id)
    events: list[dict[str, Any]] = []
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip():
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    progress_events: list[dict[str, Any]] = []
    cursor: dict[str, Any] | None = None
    status = "unknown"
    reconstructed_operation_id = operation_id
    for event in events:
        reconstructed_operation_id = reconstructed_operation_id or event.get("operation_id")
        event_type = str(event.get("event_type") or "")
        payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
        if event_type == "started":
            status = "running"
        elif event_type == "progress":
            progress_events.append(payload)
        elif event_type == "cursor":
            cursor = payload.get("cursor") if isinstance(payload.get("cursor"), dict) else payload
        elif event_type in {"succeeded", "failed", "interrupted"}:
            status = event_type
    return {
        "ok": bool(verification.get("ok")),
        "path": str(path),
        "operation_id": reconstructed_operation_id,
        "status": status,
        "event_count": verification.get("event_count", len(events)),
        "last_event_hash": verification.get("last_event_hash"),
        "event_types": [str(event.get("event_type")) for event in events],
        "progress_event_count": len(progress_events),
        "last_progress": progress_events[-1] if progress_events else None,
        "cursor": cursor,
        "verification": verification,
    }


def _last_operation_event_hash(path: Path) -> str | None:
    if not path.exists():
        return None
    last = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            last = line
    if not last:
        return None
    try:
        payload = json.loads(last)
    except json.JSONDecodeError:
        return None
    return payload.get("event_hash")


def append_operation_event(
    root: Path,
    operation_id: str,
    *,
    event_type: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    paths = operation_event_paths(root, operation_id)
    previous_hash = _last_operation_event_hash(paths["run"])
    event = {
        "schema": OPERATION_EVENT_SCHEMA,
        "event_id": unique_id("opevt"),
        "operation_id": operation_id,
        "event_type": event_type,
        "created_at": utc_now(),
        "previous_event_hash": previous_hash,
        "payload": payload or {},
    }
    event = _root_relative_payload(root, event)
    event = _apply_persistent_secret_policy(root, event, scope="operation_event")
    event["event_hash"] = _operation_event_hash(event)
    for path in paths.values():
        append_jsonl(path, event)
    return event


def _apply_persistent_secret_policy(root: Path, payload: dict[str, Any], *, scope: str) -> dict[str, Any]:
    """Scrub secret-bearing receipt/proof metadata before durable writes."""
    try:
        security = load_config(root).get("security", {})
    except Exception:
        return payload
    if not bool(security.get("secret_scan_enabled", True)):
        return payload
    action = str(security.get("secret_scan_action") or "block")
    if action == "off":
        return payload
    scan_payload = {key: value for key, value in payload.items() if key not in {"receipt_hash", "proof_pack_hash"}}
    findings = scan_value_for_secrets(scan_payload, scope=scope, max_findings=20)
    if not findings:
        return payload
    sanitized = redact_value_secrets(payload)
    sanitized["secret_scan_action"] = action
    sanitized["secret_findings"] = findings
    sanitized["secret_policy_note"] = (
        "Secret-like material was redacted from operation/proof metadata before durable persistence."
    )
    return sanitized


def _stored_root_uri(root: Path, path: Path | str) -> str:
    candidate = Path(path)
    try:
        return candidate.resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()
    except (OSError, ValueError):
        return str(path)


def _root_relative_payload(root: Path, value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _root_relative_payload(root, nested) for key, nested in value.items()}
    if isinstance(value, list):
        return [_root_relative_payload(root, nested) for nested in value]
    if isinstance(value, tuple):
        return [_root_relative_payload(root, nested) for nested in value]
    if isinstance(value, str):
        candidate = Path(value)
        if candidate.is_absolute():
            relative = _root_relative_uri(root, candidate)
            if relative is not None:
                return relative
    return value


def _resolve_root_uri(root: Path, value: str | Path | None) -> str | None:
    if value is None:
        return None
    candidate = Path(str(value))
    if candidate.is_absolute():
        return str(candidate)
    return str(root / candidate)


def _normalize_receipt_uris(root: Path, receipt: dict[str, Any]) -> None:
    for key in (
        "run_receipt_uri",
        "export_receipt_uri",
        "operation_event_log_uri",
        "operation_event_export_uri",
        "proof_pack_uri",
        "recovery_packet_uri",
        "recovery_packet_json_uri",
    ):
        value = receipt.get(key)
        if value:
            receipt[key] = _stored_root_uri(root, Path(str(value)))


def _display_receipt_uris(root: Path, receipt: dict[str, Any]) -> dict[str, Any]:
    displayed = dict(receipt)
    for key in (
        "run_receipt_uri",
        "export_receipt_uri",
        "operation_event_log_uri",
        "operation_event_export_uri",
        "proof_pack_uri",
        "recovery_packet_uri",
        "recovery_packet_json_uri",
    ):
        displayed[key] = _resolve_root_uri(root, displayed.get(key))
    return displayed


def write_operation(root: Path, receipt: dict[str, Any]) -> dict[str, Any]:
    init_layout(root)
    operation_id = str(receipt["operation_id"])
    paths = operation_paths(root, operation_id)
    event_paths = operation_event_paths(root, operation_id)
    receipt["run_receipt_uri"] = _stored_root_uri(root, paths["run"])
    receipt["export_receipt_uri"] = _stored_root_uri(root, paths["export"])
    receipt["operation_event_log_uri"] = _stored_root_uri(root, event_paths["run"])
    receipt["operation_event_export_uri"] = _stored_root_uri(root, event_paths["export"])
    _normalize_receipt_uris(root, receipt)
    receipt = _root_relative_payload(root, receipt)
    receipt = _apply_persistent_secret_policy(root, receipt, scope="operation_receipt")
    receipt["updated_at"] = utc_now()
    receipt["receipt_hash"] = _stable_json_hash(receipt)
    for path in paths.values():
        atomic_write_json(path, receipt)
    return _display_receipt_uris(root, receipt)


def _load_receipt(path: Path) -> dict[str, Any]:
    receipt = json.loads(path.read_text(encoding="utf-8"))
    stored_hash = receipt.get("receipt_hash")
    if stored_hash and stored_hash != _stable_json_hash(receipt):
        raise ValueError(f"receipt hash mismatch for {path}")
    return receipt


def start_operation(
    root: Path,
    *,
    operation_type: str,
    title: str,
    intent: dict[str, Any] | None = None,
    actor: str = "system",
) -> dict[str, Any]:
    now = utc_now()
    operation_id = unique_id("op")
    receipt = {
        "schema": OPERATION_SCHEMA,
        "operation_id": operation_id,
        "operation_type": operation_type,
        "title": title,
        "actor": actor,
        "status": "running",
        "principle": EPIC_PRINCIPLE,
        "intent": intent or {},
        "cursor": None,
        "preflight_snapshots": [],
        "created_at": now,
        "updated_at": now,
        "progress": [],
        "result": None,
        "error": None,
    }
    written = write_operation(root, receipt)
    append_operation_event(
        root,
        operation_id,
        event_type="started",
        payload={"operation_type": operation_type, "title": title, "actor": actor, "intent": intent or {}},
    )
    return written


def read_operation(root: Path, operation_id: str) -> dict[str, Any]:
    path = operation_paths(root, operation_id)["run"]
    return _load_receipt(path)


def record_operation_progress(
    root: Path,
    operation_id: str,
    *,
    phase: str,
    message: str,
    current: int | None = None,
    total: int | None = None,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    receipt = read_operation(root, operation_id)
    event: dict[str, Any] = {
        "at": utc_now(),
        "phase": phase,
        "message": message,
    }
    if current is not None:
        event["current"] = current
    if total is not None:
        event["total"] = total
    if detail:
        event["detail"] = detail
    receipt.setdefault("progress", []).append(event)
    written = write_operation(root, receipt)
    append_operation_event(root, operation_id, event_type="progress", payload=event)
    return written


def update_operation_cursor(root: Path, operation_id: str, cursor: dict[str, Any] | None) -> dict[str, Any]:
    receipt = read_operation(root, operation_id)
    receipt["cursor"] = cursor
    written = write_operation(root, receipt)
    append_operation_event(root, operation_id, event_type="cursor", payload={"cursor": cursor})
    return written


def attach_preflight_snapshot(root: Path, operation_id: str, snapshot_result: dict[str, Any]) -> dict[str, Any]:
    receipt = read_operation(root, operation_id)
    receipt.setdefault("preflight_snapshots", []).append(snapshot_result)
    written = write_operation(root, receipt)
    append_operation_event(root, operation_id, event_type="preflight_snapshot", payload=snapshot_result)
    return written


def create_preflight_snapshot(root: Path, operation_id: str, *, reason: str) -> dict[str, Any]:
    snap = snapshot(root, reason=f"preflight:{operation_id}:{reason}")
    attach_preflight_snapshot(root, operation_id, snap)
    return snap


def finish_operation(
    root: Path,
    operation_id: str,
    *,
    status: str,
    result: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if status not in TERMINAL_STATUSES:
        raise ValueError("status must be succeeded, failed, or interrupted")
    receipt = read_operation(root, operation_id)
    receipt["status"] = status
    receipt["finished_at"] = utc_now()
    receipt["result"] = result
    receipt["error"] = error
    written = write_operation(root, receipt)
    append_operation_event(root, operation_id, event_type=status, payload={"result": result, "error": error})
    return written


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _root_relative_uri(root: Path, path: Path) -> str | None:
    try:
        resolved_root = root.resolve(strict=False)
        resolved_path = path.resolve(strict=False)
        return resolved_path.relative_to(resolved_root).as_posix()
    except (OSError, ValueError):
        return None


def _lexical_root_relative_uri(root: Path, path: Path) -> str | None:
    """Return a root-relative path without following a final symlink.

    Most proof inputs should resolve symlinks so that external sources are
    treated as external evidence. A symlink itself is different: the durable
    fact is the link record, not the target bytes. For that case we need the
    link's lexical location inside the root so verification can re-read the
    link metadata without wandering outside the Continuum root.
    """
    try:
        return path.absolute().relative_to(root.absolute()).as_posix()
    except (OSError, ValueError):
        return None


def _proof_path_identity(path: Path, root: Path | None = None) -> dict[str, str]:
    if root is not None:
        if path.is_symlink():
            lexical_relative = _lexical_root_relative_uri(root, path)
            if lexical_relative is not None:
                return {"path": lexical_relative, "uri": lexical_relative, "uri_base": "continuum_root"}
        relative = _root_relative_uri(root, path)
        if relative is not None:
            return {"path": relative, "uri": relative, "uri_base": "continuum_root"}
        if path.is_absolute():
            safe_name = secret_safe_slug(path.name or "external_path", prefix="external_path", limit=80)
            return {
                "path": f"external:{safe_name}",
                "uri": f"external:{safe_name}",
                "uri_base": "external_original",
                "path_hash": content_hash(str(path.resolve(strict=False))),
            }
    return {"path": str(path), "uri": str(path), "uri_base": "absolute"}


def _describe_symlink(path: Path) -> dict[str, Any]:
    try:
        target = os.readlink(path)
    except OSError as exc:
        return {"kind": "symlink", "link_target": None, "link_error": str(exc)}
    target_findings = scan_text_for_secrets(target, max_findings=1)
    target_path = Path(target)
    if target_path.is_absolute():
        safe_target = f"external:{secret_safe_slug(target_path.name or 'symlink_target', prefix='symlink_target', limit=80)}"
    else:
        safe_target = redact_text_secrets(target) if target_findings else target
    payload: dict[str, Any] = {
        "kind": "symlink",
        "link_target": safe_target,
        "link_target_redacted": safe_target != target,
        "link_target_hash": content_hash(target),
        "link_target_absolute": target_path.is_absolute(),
    }
    try:
        payload["size_bytes"] = path.lstat().st_size
    except OSError:
        pass
    return payload


def _describe_directory_tree(path: Path, *, limit: int = 10000) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    truncated = False
    try:
        children = sorted(path.rglob("*"), key=lambda child: child.relative_to(path).as_posix())
    except OSError:
        return {"entry_count": 0, "tree_sha256": None, "entries": [], "tree_truncated": False}
    for child in children:
        if len(entries) >= limit:
            truncated = True
            break
        try:
            rel = child.relative_to(path).as_posix()
        except ValueError:
            rel = child.name
        rel_findings = scan_text_for_secrets(rel, max_findings=1)
        if rel_findings:
            entry: dict[str, Any] = {
                "path": redact_text_secrets(rel),
                "path_redacted": True,
                "path_hash": content_hash(rel),
            }
        else:
            entry = {"path": rel, "path_redacted": False}
        try:
            if child.is_symlink():
                entry.update(_describe_symlink(child))
            elif child.is_file():
                stat = child.stat()
                entry.update({"kind": "file", "size_bytes": stat.st_size, "sha256": _sha256_file(child)})
            elif child.is_dir():
                entry["kind"] = "directory"
            else:
                entry["kind"] = "other"
        except OSError as exc:
            entry.update({"kind": "unreadable", "error": str(exc)})
        entries.append(entry)
    tree_material = json.dumps(entries, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return {
        "entry_count": len(entries),
        "tree_sha256": content_hash(tree_material),
        "entries": entries,
        "tree_truncated": truncated,
    }


def describe_path(path: Path, *, root: Path | None = None) -> dict[str, Any]:
    resolved = path
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        pass
    exists = path.exists() or path.is_symlink()
    payload: dict[str, Any] = {**_proof_path_identity(path, root), "exists": exists}
    if payload["uri_base"] == "absolute":
        payload["resolved_path"] = str(resolved)
    if not exists:
        payload["kind"] = "missing"
        return payload
    if path.is_symlink():
        payload.update(_describe_symlink(path))
    elif path.is_file():
        stat = path.stat()
        payload.update(
            {
                "kind": "file",
                "size_bytes": stat.st_size,
                "mtime_utc": dt.datetime.fromtimestamp(stat.st_mtime, dt.UTC).replace(microsecond=0).isoformat(),
                "sha256": _sha256_file(path),
            }
        )
    elif path.is_dir():
        try:
            child_count = sum(1 for _child in path.iterdir())
        except OSError:
            child_count = None
        payload.update({"kind": "directory", "child_count": child_count, **_describe_directory_tree(path)})
    else:
        payload["kind"] = "other"
    return payload


def resolve_proof_path(item: dict[str, Any], *, root: Path | None = None) -> Path:
    raw_uri = str(item.get("uri") or item.get("path") or "")
    uri_base = item.get("uri_base")
    if uri_base == "continuum_root":
        if root is None:
            raise ValueError(f"proof path requires a continuum root: {raw_uri}")
        return root / raw_uri
    item_path = Path(str(item.get("path") or raw_uri))
    if item_path.is_absolute() or root is None:
        return item_path
    return root / item_path


def _same_path(left: Path, right: Path) -> bool:
    try:
        return left.resolve(strict=False) == right.resolve(strict=False)
    except OSError:
        return str(left) == str(right)


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except (OSError, ValueError):
        return False


def _is_lexically_within(path: Path, parent: Path) -> bool:
    """Containment check that does not dereference symlink targets."""
    try:
        path.absolute().relative_to(parent.absolute())
        return True
    except (OSError, ValueError):
        return False


def _proof_item_within_allowed_root(item_path: Path, item: dict[str, Any], allowed: Path) -> bool:
    """Return whether a proof item is safe to verify under an allowed root.

    Symlink proof entries are evidence about the link itself, not the target
    bytes. For those entries, use lexical containment so an in-root symlink to
    an external file can still be verified without following or hashing the
    target. All non-symlink proof entries continue to use resolved containment.
    """
    if item.get("kind") == "symlink" or item_path.is_symlink():
        return _is_lexically_within(item_path, allowed)
    return _is_within(item_path, allowed)


def _backup_sqlite(source: Path, dest: Path) -> None:
    secure_mkdir(dest.parent)
    src = sqlite3.connect(f"file:{source}?mode=ro", uri=True, timeout=5)
    try:
        dst = sqlite3.connect(str(dest))
        try:
            src.backup(dst)
        finally:
            dst.close()
    finally:
        src.close()
    secure_sqlite_files(dest)


def _freeze_mutable_proof_path(root: Path, operation_id: str, path: Path) -> tuple[Path, dict[str, Any] | None]:
    live_catalog = root / "catalog" / "catalog.sqlite3"
    if not _same_path(path, live_catalog):
        return path, None
    if not live_catalog.exists():
        return path, None
    frozen = proof_artifact_dir(root, operation_id) / "catalog.snapshot.sqlite3"
    _backup_sqlite(live_catalog, frozen)
    return frozen, {
        "source": _proof_path_identity(path, root),
        "frozen": _proof_path_identity(frozen, root),
        "reason": "live SQLite catalog is backed up before proof hashing",
        "kind": "sqlite_backup",
    }


def _copy_file_for_proof(source: Path, dest: Path) -> Path:
    secure_copy_file(source, dest)
    return dest


def _freeze_config_for_proof(root: Path, operation_id: str, path: Path) -> tuple[Path, dict[str, Any] | None]:
    config_file = config_path(root)
    if not _same_path(path, config_file) or not path.exists() or not path.is_file():
        return path, None
    frozen = proof_artifact_dir(root, operation_id) / "config" / "continuum.config.json"
    _copy_file_for_proof(path, frozen)
    return frozen, {
        "source": _proof_path_identity(path, root),
        "frozen": _proof_path_identity(frozen, root),
        "reason": "live config is copied before proof hashing",
        "kind": "config_snapshot",
    }


def _freeze_external_file_for_proof(root: Path, operation_id: str, path: Path) -> tuple[Path, dict[str, Any] | None]:
    if path.is_symlink() or _is_within(path, root) or not path.exists() or not path.is_file():
        return path, None
    digest = _sha256_file(path)
    safe_name = secret_safe_slug(path.name, prefix="external_file", limit=80)
    frozen = proof_artifact_dir(root, operation_id) / "external" / f"{digest[:16]}_{safe_name}"
    _copy_file_for_proof(path, frozen)
    return frozen, {
        "source": {"uri": f"external:{safe_name}", "uri_base": "external_original", "sha256": digest},
        "frozen": _proof_path_identity(frozen, root),
        "sha256": digest,
        "reason": "external source file is copied into proof artifacts before hashing",
        "kind": "external_file_snapshot",
    }


def _redacted_internal_source_identity(root: Path, path: Path, *, rel: str | None = None) -> dict[str, str]:
    relative = rel if rel is not None else _root_relative_uri(root, path)
    material = relative if relative is not None else str(path)
    return {
        "uri": f"redacted:internal:{content_hash(material)[:16]}",
        "uri_base": "redacted_source",
        "path_hash": content_hash(material),
    }


def _freeze_secret_internal_file_for_proof(root: Path, operation_id: str, path: Path) -> tuple[Path, dict[str, Any] | None]:
    if path.is_symlink() or not _is_within(path, root) or not path.exists() or not path.is_file():
        return path, None
    rel = _root_relative_uri(root, path)
    if rel is None or not scan_text_for_secrets(rel, max_findings=1):
        return path, None
    digest = _sha256_file(path)
    safe_name = secret_safe_slug(path.name or "file", prefix="internal_file", limit=80)
    frozen = proof_artifact_dir(root, operation_id) / "redacted_internal" / f"{digest[:16]}_{safe_name}"
    _copy_file_for_proof(path, frozen)
    return frozen, {
        "source": {**_redacted_internal_source_identity(root, path, rel=rel), "sha256": digest},
        "frozen": _proof_path_identity(frozen, root),
        "sha256": digest,
        "reason": "internal source file path contained secret-like material and was copied into a secret-safe proof artifact",
        "kind": "internal_file_snapshot_redacted_path",
    }


def _freeze_secret_internal_symlink_for_proof(root: Path, operation_id: str, path: Path) -> tuple[Path, dict[str, Any] | None]:
    if not path.is_symlink() or not _is_lexically_within(path, root):
        return path, None
    rel = _lexical_root_relative_uri(root, path)
    if rel is None or not scan_text_for_secrets(rel, max_findings=1):
        return path, None
    safe_name = secret_safe_slug(path.name or "symlink", prefix="internal_symlink", limit=80)
    manifest_path = (
        proof_artifact_dir(root, operation_id)
        / "redacted_internal_symlinks"
        / f"{content_hash(rel)[:16]}_{safe_name}.symlink.json"
    )
    manifest = {
        "schema": "epic_continuum.proof_symlink_manifest.v1",
        "created_at": utc_now(),
        "source": _redacted_internal_source_identity(root, path, rel=rel),
        "link": _describe_symlink(path),
    }
    atomic_write_json(manifest_path, manifest)
    return manifest_path, {
        "source": _redacted_internal_source_identity(root, path, rel=rel),
        "frozen": _proof_path_identity(manifest_path, root),
        "reason": "internal symlink path contained secret-like material and was recorded in a secret-safe proof manifest",
        "kind": "internal_symlink_manifest_redacted_path",
    }


def _freeze_directory_manifest_for_proof(root: Path, operation_id: str, path: Path) -> tuple[Path, dict[str, Any] | None]:
    if path.is_symlink() or not path.exists() or not path.is_dir():
        return path, None
    if _is_within(path, proof_artifact_dir(root, operation_id)):
        return path, None
    rel = _root_relative_uri(root, path)
    if rel is not None and scan_text_for_secrets(rel, max_findings=1):
        source_identity = _redacted_internal_source_identity(root, path, rel=rel)
    else:
        source_identity = _proof_path_identity(path, root) if rel is not None else {
            "uri": f"external:{secret_safe_slug(path.name or 'directory', prefix='directory', limit=80)}",
            "uri_base": "external_original",
        }
    label = secret_safe_slug(rel or str(path), prefix="directory", limit=120)
    manifest_path = proof_artifact_dir(root, operation_id) / "directory_manifests" / f"{label}.tree.json"
    manifest = {
        "schema": "epic_continuum.proof_directory_manifest.v1",
        "created_at": utc_now(),
        "source": source_identity,
        "tree": _describe_directory_tree(path),
    }
    atomic_write_json(manifest_path, manifest)
    return manifest_path, {
        "source": source_identity,
        "frozen": _proof_path_identity(manifest_path, root),
        "reason": "directory tree is recorded as an immutable proof manifest instead of hashing a live directory",
        "kind": "directory_manifest_snapshot",
    }


def normalize_proof_input(root: Path, operation_id: str, path: Path) -> tuple[Path, dict[str, Any] | None]:
    for freezer in (
        _freeze_mutable_proof_path,
        _freeze_config_for_proof,
        _freeze_external_file_for_proof,
        _freeze_secret_internal_file_for_proof,
        _freeze_secret_internal_symlink_for_proof,
        _freeze_directory_manifest_for_proof,
    ):
        frozen, substitution = freezer(root, operation_id, path)
        if substitution:
            return frozen, substitution
    return path, None


def _record_proof_artifacts(
    root: Path,
    operation_id: str,
    proof_path: Path,
    described_paths: list[dict[str, Any]],
) -> None:
    if not is_initialized(root):
        return
    conn = connect(root)
    try:
        for item in described_paths:
            if item.get("kind") != "file" or not item.get("exists") or not item.get("sha256"):
                continue
            record_artifact(
                conn,
                kind="proof_input",
                uri=str(item.get("uri") or item["path"]),
                sha256=str(item["sha256"]),
                size_bytes=int(item.get("size_bytes") or 0),
                operation_id=operation_id,
                immutable=True,
                source_type="proof_pack",
                trust_level="local_artifact",
                metadata={
                    "proof_pack_uri": _proof_path_identity(proof_path, root)["uri"],
                    "path_kind": item.get("kind"),
                    "uri_base": item.get("uri_base"),
                },
            )
        if proof_path.exists():
            record_artifact(
                conn,
                kind="proof_pack",
                uri=_proof_path_identity(proof_path, root)["uri"],
                sha256=file_sha256(proof_path),
                size_bytes=proof_path.stat().st_size,
                operation_id=operation_id,
                immutable=True,
                source_type="proof_pack",
                trust_level="local_artifact",
                metadata={"schema": PROOF_PACK_SCHEMA},
            )
        conn.commit()
    except sqlite3.Error:
        conn.rollback()
    finally:
        conn.close()


def create_proof_pack(
    root: Path,
    operation_id: str,
    *,
    touched_paths: list[Path | str] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    write_default_config(root)
    init_db(root)
    receipt = read_operation(root, operation_id)
    paths = operation_paths(root, operation_id)
    proof_path = proof_pack_path(root, operation_id)
    receipt["proof_pack_uri"] = str(proof_path)
    receipt.pop("proof_pack_hash", None)
    write_operation(root, receipt)
    append_operation_event(root, operation_id, event_type="proof_pack_started", payload={"proof_pack_uri": str(proof_path)})
    receipt = read_operation(root, operation_id)
    event_paths = operation_event_paths(root, operation_id)
    proof_paths: list[Path] = [
        paths["run"],
        paths["export"],
        event_paths["run"],
        event_paths["export"],
        root / "config" / "continuum.config.json",
    ]
    for item in touched_paths or []:
        candidate = Path(item)
        proof_paths.append(candidate if candidate.is_absolute() else root / candidate)
    input_seen: set[str] = set()
    seen: set[str] = set()
    described: list[dict[str, Any]] = []
    substitutions: list[dict[str, Any]] = []
    for described_path in proof_paths:
        try:
            input_key = str(described_path.resolve(strict=False))
        except OSError:
            input_key = str(described_path)
        if input_key in input_seen:
            continue
        input_seen.add(input_key)
        frozen_path, substitution = normalize_proof_input(root, operation_id, described_path)
        key = str(frozen_path)
        if key in seen:
            continue
        seen.add(key)
        if substitution:
            substitutions.append(substitution)
        described.append(describe_path(frozen_path, root=root))
    proof = {
        "schema": PROOF_PACK_SCHEMA,
        "operation_id": operation_id,
        "operation_type": receipt.get("operation_type"),
        "title": receipt.get("title"),
        "status": receipt.get("status"),
        "created_at": utc_now(),
        "root": "continuum_root",
        "operation_receipt_hash": receipt.get("receipt_hash"),
        "run_receipt_uri": receipt.get("run_receipt_uri"),
        "export_receipt_uri": receipt.get("export_receipt_uri"),
        "preflight_snapshots": receipt.get("preflight_snapshots") or [],
        "cursor": receipt.get("cursor"),
        "intent": receipt.get("intent") or {},
        "result": receipt.get("result"),
        "error": receipt.get("error"),
        "paths": described,
        "path_substitutions": substitutions,
        "extra": extra or {},
        "hash_scope": (
            "Proof pack hashes describe the receipt files after proof_pack_uri is written. "
            "Live mutable SQLite databases are represented by immutable SQLite backup artifacts. "
            "The proof_pack_hash is stored inside this proof pack, not written back into the receipts it hashes."
        ),
    }
    proof["proof_pack_uri"] = _stored_root_uri(root, proof_path)
    proof = _root_relative_payload(root, proof)
    proof = _apply_persistent_secret_policy(root, proof, scope="proof_pack")
    proof["proof_pack_hash"] = content_hash(json.dumps(proof, ensure_ascii=True, sort_keys=True, default=str))
    atomic_write_json(proof_path, proof)
    _record_proof_artifacts(root, operation_id, proof_path, described)
    display_proof = dict(proof)
    display_proof["root"] = str(root)
    display_proof["proof_pack_uri"] = str(proof_path)
    return display_proof


def _proof_pack_hash(payload: dict[str, Any]) -> str:
    material = {key: value for key, value in payload.items() if key != "proof_pack_hash"}
    return content_hash(json.dumps(material, ensure_ascii=True, sort_keys=True, default=str))


def infer_root_from_proof_path(path: Path) -> Path | None:
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        resolved = path
    if resolved.parent.name == "proof_packs" and resolved.parent.parent.name == "exports":
        return resolved.parent.parent.parent
    return None


def _add_check(
    checks: list[dict[str, Any]],
    errors: list[dict[str, Any]],
    check: str,
    ok: bool,
    **detail: Any,
) -> None:
    payload = {"check": check, "ok": ok, **detail}
    checks.append(payload)
    if not ok:
        errors.append(payload)


def _proof_path_uris(proof: dict[str, Any]) -> set[str]:
    uris: set[str] = set()
    for item in proof.get("paths") or []:
        if not isinstance(item, dict):
            continue
        raw = str(item.get("uri") or item.get("path") or "")
        if raw:
            uris.add(raw.replace("\\", "/"))
    return uris


def _semantic_receipt_checks(
    *,
    proof_path: Path,
    proof: dict[str, Any],
    root: Path | None,
    checks: list[dict[str, Any]],
    errors: list[dict[str, Any]],
) -> None:
    operation_id = proof.get("operation_id")
    if not operation_id:
        return
    if root is None:
        _add_check(checks, errors, "semantic_root_available", False, error="strict proof verification requires a root")
        return

    paths = operation_paths(root, str(operation_id))
    proof_uris = _proof_path_uris(proof)
    loaded: dict[str, dict[str, Any]] = {}
    for label, receipt_path in (("run", paths["run"]), ("export", paths["export"])):
        rel_uri = _stored_root_uri(root, receipt_path).replace("\\", "/")
        _add_check(
            checks,
            errors,
            f"{label}_receipt_path_bound",
            rel_uri in proof_uris,
            uri=rel_uri,
        )
        try:
            receipt = _load_receipt(receipt_path)
        except Exception as exc:
            _add_check(
                checks,
                errors,
                f"{label}_receipt_loads",
                False,
                uri=rel_uri,
                error=f"{type(exc).__name__}: {exc}",
            )
            continue
        loaded[label] = receipt
        _add_check(checks, errors, f"{label}_receipt_loads", True, uri=rel_uri)
        _add_check(
            checks,
            errors,
            f"{label}_receipt_operation_id_matches",
            receipt.get("operation_id") == operation_id,
            expected=operation_id,
            actual=receipt.get("operation_id"),
        )
        _add_check(
            checks,
            errors,
            f"{label}_receipt_schema_matches",
            receipt.get("schema") == OPERATION_SCHEMA,
            expected=OPERATION_SCHEMA,
            actual=receipt.get("schema"),
        )

    event_log_results: dict[str, dict[str, Any]] = {}
    for label, event_path in (("run", operation_event_paths(root, str(operation_id))["run"]), ("export", operation_event_paths(root, str(operation_id))["export"])):
        rel_uri = _stored_root_uri(root, event_path).replace("\\", "/")
        _add_check(
            checks,
            errors,
            f"{label}_operation_event_log_path_bound",
            rel_uri in proof_uris,
            uri=rel_uri,
        )
        result = verify_operation_event_log(event_path, operation_id=str(operation_id))
        event_log_results[label] = result
        _add_check(
            checks,
            errors,
            f"{label}_operation_event_log_chain_valid",
            bool(result.get("ok")),
            uri=rel_uri,
            event_count=result.get("event_count"),
            last_event_hash=result.get("last_event_hash"),
            event_log_errors=result.get("errors"),
        )
    if event_log_results.get("run") and event_log_results.get("export"):
        _add_check(
            checks,
            errors,
            "run_export_operation_event_logs_match",
            event_log_results["run"].get("event_count") == event_log_results["export"].get("event_count")
            and event_log_results["run"].get("last_event_hash") == event_log_results["export"].get("last_event_hash"),
            run_event_count=event_log_results["run"].get("event_count"),
            export_event_count=event_log_results["export"].get("event_count"),
            run_last_event_hash=event_log_results["run"].get("last_event_hash"),
            export_last_event_hash=event_log_results["export"].get("last_event_hash"),
        )

    run_receipt = loaded.get("run")
    export_receipt = loaded.get("export")
    final_receipt = export_receipt or run_receipt
    if run_receipt and export_receipt:
        _add_check(
            checks,
            errors,
            "run_export_receipt_hashes_match",
            run_receipt.get("receipt_hash") == export_receipt.get("receipt_hash"),
            run_receipt_hash=run_receipt.get("receipt_hash"),
            export_receipt_hash=export_receipt.get("receipt_hash"),
        )
    if not final_receipt:
        return

    _add_check(
        checks,
        errors,
        "operation_receipt_hash_matches_receipt",
        proof.get("operation_receipt_hash") == final_receipt.get("receipt_hash"),
        proof_operation_receipt_hash=proof.get("operation_receipt_hash"),
        receipt_hash=final_receipt.get("receipt_hash"),
    )
    receipt_proof_uri = final_receipt.get("proof_pack_uri")
    if receipt_proof_uri:
        _add_check(
            checks,
            errors,
            "receipt_points_to_this_proof_pack",
            _same_path(resolve_stored_uri(root, str(receipt_proof_uri)), proof_path),
            receipt_proof_pack_uri=receipt_proof_uri,
            proof_pack_uri=str(proof_path),
        )
    else:
        _add_check(checks, errors, "receipt_points_to_this_proof_pack", False, error="receipt has no proof_pack_uri")

    for key in ("operation_type", "title", "status", "intent", "cursor", "result", "error"):
        _add_check(
            checks,
            errors,
            f"proof_{key}_matches_receipt",
            proof.get(key) == final_receipt.get(key),
            expected=final_receipt.get(key),
            actual=proof.get(key),
        )

    if not is_initialized(root):
        _add_check(
            checks,
            errors,
            "artifact_ledger_proof_pack_bound",
            False,
            error="strict proof verification requires the generated artifact ledger",
        )
        return
    try:
        conn = connect_existing(root)
        try:
            rel_uri = _stored_root_uri(root, proof_path)
            candidates = {rel_uri, str(proof_path)}
            rows = conn.execute(
                """
                SELECT uri, sha256, size_bytes, operation_id
                FROM artifacts
                WHERE kind = 'proof_pack' AND operation_id = ?
                ORDER BY created_at DESC
                """,
                (str(operation_id),),
            ).fetchall()
        finally:
            conn.close()
    except Exception as exc:
        _add_check(
            checks,
            errors,
            "artifact_ledger_proof_pack_bound",
            False,
            error=f"{type(exc).__name__}: {exc}",
        )
        return
    matching_rows = [row for row in rows if str(row["uri"]) in candidates]
    _add_check(
        checks,
        errors,
        "artifact_ledger_proof_pack_bound",
        bool(matching_rows),
        operation_id=operation_id,
        expected_uris=sorted(candidates),
        candidate_count=len(rows),
    )
    if not matching_rows:
        return
    row = matching_rows[0]
    actual_hash = _sha256_file(proof_path) if proof_path.exists() else None
    actual_size = proof_path.stat().st_size if proof_path.exists() else None
    _add_check(
        checks,
        errors,
        "artifact_ledger_proof_pack_hash_matches",
        row["sha256"] == actual_hash and int(row["size_bytes"]) == actual_size,
        uri=row["uri"],
        expected_sha256=row["sha256"],
        actual_sha256=actual_hash,
        expected_size_bytes=int(row["size_bytes"]),
        actual_size_bytes=actual_size,
    )


def verify_proof_pack(
    path: Path,
    *,
    root: Path | None = None,
    strict: bool = True,
    allowed_roots: list[Path] | None = None,
) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    try:
        proof = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "proof_pack_uri": str(path), "errors": [{"check": "load", "error": str(exc)}], "checks": []}

    expected_hash = proof.get("proof_pack_hash")
    if expected_hash:
        actual_hash = _proof_pack_hash(proof)
        ok = expected_hash == actual_hash
        checks.append({"check": "proof_pack_hash", "ok": ok, "expected": expected_hash, "actual": actual_hash})
        if not ok:
            errors.append({"check": "proof_pack_hash", "expected": expected_hash, "actual": actual_hash})
    elif strict:
        _add_check(checks, errors, "proof_pack_hash_present", False, error="proof_pack_hash is required")

    if proof.get("schema") != PROOF_PACK_SCHEMA:
        errors.append({"check": "schema", "expected": PROOF_PACK_SCHEMA, "actual": proof.get("schema")})
    checks.append({"check": "schema", "ok": proof.get("schema") == PROOF_PACK_SCHEMA})
    if strict:
        _add_check(checks, errors, "operation_id_present", bool(proof.get("operation_id")))
        paths_value = proof.get("paths")
        paths_is_list = isinstance(paths_value, list)
        _add_check(checks, errors, "paths_present", paths_is_list and bool(paths_value))
        if paths_is_list:
            proof_uris = {str(item.get("uri") or item.get("path") or "") for item in paths_value if isinstance(item, dict)}
            has_receipt_path = any(
                uri.startswith("run/operations/")
                or uri.startswith("exports/operation_receipts/")
                or "/run/operations/" in uri.replace("\\", "/")
                or "/exports/operation_receipts/" in uri.replace("\\", "/")
                for uri in proof_uris
            )
            _add_check(checks, errors, "operation_receipt_path_present", has_receipt_path)
        else:
            paths_value = []

    verification_root = root or infer_root_from_proof_path(path)
    inferred_root = verification_root is not None and root is None
    proof_root = proof.get("root")
    if verification_root is None and proof_root and str(proof_root) not in {"continuum_root", "<continuum-root>"}:
        candidate_root = Path(str(proof["root"]))
        if allowed_roots is not None and not any(_is_within(candidate_root, allowed) for allowed in allowed_roots):
            _add_check(
                checks,
                errors,
                "verification_root_allowed",
                False,
                root=str(candidate_root),
                error="proof root is outside this verifier's allowed roots",
            )
        else:
            verification_root = candidate_root

    semantic_root_allowed = True
    if allowed_roots is not None and verification_root is not None:
        semantic_root_allowed = any(_is_within(verification_root, allowed) for allowed in allowed_roots)
        _add_check(
            checks,
            errors,
            "verification_root_allowed",
            semantic_root_allowed,
            root=str(verification_root),
        )

    if strict and semantic_root_allowed:
        _semantic_receipt_checks(
            proof_path=path,
            proof=proof,
            root=verification_root,
            checks=checks,
            errors=errors,
        )

    for item in proof.get("paths") or []:
        if strict:
            item_uri = str(item.get("uri") or item.get("path") or "")
            _add_check(checks, errors, "path_entry_shape", bool(item_uri) and "exists" in item and "kind" in item, uri=item_uri)
            if item.get("exists") and item.get("kind") == "file":
                _add_check(
                    checks,
                    errors,
                    "file_entry_hash_shape",
                    bool(item.get("sha256")) and "size_bytes" in item,
                    uri=item_uri,
                )
        try:
            item_path = resolve_proof_path(item, root=verification_root)
        except ValueError as exc:
            path_check = {
                "check": "path",
                "path": str(item.get("path") or item.get("uri") or ""),
                "ok": False,
                "error": str(exc),
            }
            checks.append(path_check)
            errors.append(path_check)
            continue
        if allowed_roots is not None and not any(_proof_item_within_allowed_root(item_path, item, allowed) for allowed in allowed_roots):
            path_check = {
                "check": "path_allowed",
                "path": str(item.get("uri") or item.get("path") or ""),
                "ok": False,
                "error": "proof path is outside this verifier's allowed roots",
            }
            checks.append(path_check)
            errors.append(path_check)
            continue
        expected_exists = bool(item.get("exists"))
        actual_exists = item_path.exists() or item_path.is_symlink()
        path_check: dict[str, Any] = {
            "check": "path",
            "path": str(item_path),
            "ok": expected_exists == actual_exists,
            "expected_exists": expected_exists,
            "actual_exists": actual_exists,
        }
        if expected_exists and actual_exists and item.get("kind") == "file":
            actual_sha = _sha256_file(item_path)
            path_check["expected_sha256"] = item.get("sha256")
            path_check["actual_sha256"] = actual_sha
            path_check["ok"] = path_check["ok"] and item.get("sha256") == actual_sha
            if "size_bytes" in item:
                path_check["expected_size_bytes"] = item.get("size_bytes")
                path_check["actual_size_bytes"] = item_path.stat().st_size
                path_check["ok"] = path_check["ok"] and item.get("size_bytes") == item_path.stat().st_size
        if expected_exists and actual_exists and item.get("kind") == "directory":
            actual_tree = _describe_directory_tree(item_path)
            path_check["expected_tree_sha256"] = item.get("tree_sha256")
            path_check["actual_tree_sha256"] = actual_tree.get("tree_sha256")
            path_check["expected_entry_count"] = item.get("entry_count")
            path_check["actual_entry_count"] = actual_tree.get("entry_count")
            path_check["ok"] = (
                path_check["ok"]
                and item.get("tree_sha256") == actual_tree.get("tree_sha256")
                and item.get("entry_count") == actual_tree.get("entry_count")
            )
        if expected_exists and actual_exists and item.get("kind") == "symlink":
            actual_link = _describe_symlink(item_path)
            path_check["expected_link_target_hash"] = item.get("link_target_hash")
            path_check["actual_link_target_hash"] = actual_link.get("link_target_hash")
            path_check["ok"] = path_check["ok"] and item.get("link_target_hash") == actual_link.get("link_target_hash")
        checks.append(path_check)
        if not path_check["ok"]:
            errors.append(path_check)

    return {
        "ok": not errors,
        "proof_pack_uri": str(path),
        "operation_id": proof.get("operation_id"),
        "verification_root": str(verification_root) if verification_root else None,
        "verification_root_inferred": inferred_root,
        "strict": strict,
        "check_count": len(checks),
        "error_count": len(errors),
        "errors": errors,
        "checks": checks,
    }


def doctor(
    root: Path,
    *,
    verify_recent_proof_packs: int = 1,
    scan_secrets: bool = False,
    allowed_roots: list[Path] | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(name: str, ok: bool, **detail: Any) -> None:
        checks.append({"name": name, "ok": ok, **detail})

    add("package_config_default", (SCHEMA_PATH.parents[1] / "config.default.json").exists())
    add("package_schema_sql", SCHEMA_PATH.exists(), path=str(SCHEMA_PATH))
    try:
        permissions = audit_private_permissions(root)
        add(
            "private_permissions",
            bool(permissions.get("ok")),
            supported=permissions.get("supported"),
            checked=permissions.get("checked"),
            unsafe_count=permissions.get("unsafe_count"),
            reason=permissions.get("reason"),
            repair_hint=permissions.get("repair_hint"),
            findings=permissions.get("findings", [])[:10],
        )
    except Exception as exc:
        add("private_permissions", False, error=str(exc))
    proof_dir = root / "exports" / "proof_packs"
    proof_results: list[dict[str, Any]] = []
    if proof_dir.exists() and verify_recent_proof_packs > 0:
        proof_paths = sorted(proof_dir.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)[
            :verify_recent_proof_packs
        ]
        for proof_path in proof_paths:
            result = verify_proof_pack(proof_path, root=root, allowed_roots=allowed_roots)
            proof_results.append(result)
            add("verify_proof_pack", bool(result["ok"]), path=str(proof_path), error_count=result["error_count"])

    try:
        root_status = status(root, create=False)
        add("status", True, scroll_events=root_status.get("scroll_events"), cards=root_status.get("cards"))
    except Exception as exc:
        root_status = None
        add("status", False, error=str(exc))
    add("config_exists", config_path(root).exists(), path=str(config_path(root)))

    if root_status and root_status.get("initialized"):
        try:
            conn = connect_existing(root)
            try:
                journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
                add("sqlite_open", True)
                add("sqlite_wal", str(journal_mode).lower() == "wal", journal_mode=journal_mode)
            finally:
                conn.close()
        except Exception as exc:
            add("sqlite_open", False, error=str(exc))
        try:
            search_audit = audit_search_index(root, create=False)
            add(
                "search_index_consistent",
                bool(search_audit.get("ok")),
                chunks=search_audit.get("chunks"),
                fts_rows=search_audit.get("fts_rows"),
                missing_chunks=search_audit.get("missing_chunks"),
                orphan_fts_rows=search_audit.get("orphan_fts_rows"),
                fts_available=search_audit.get("fts_available"),
                reason=search_audit.get("reason"),
            )
        except Exception as exc:
            add("search_index_consistent", False, error=str(exc))
        try:
            artifact_ledger = _verify_artifact_ledger(root)
            add(
                "artifact_ledger_portable_and_hashes_match",
                bool(artifact_ledger.get("ok")),
                checked=artifact_ledger.get("checked"),
                missing=artifact_ledger.get("missing"),
                mismatch_count=artifact_ledger.get("mismatch_count", 0),
                absolute_internal_uri_count=artifact_ledger.get("absolute_internal_uri_count", 0),
            )
        except Exception as exc:
            add("artifact_ledger_portable_and_hashes_match", False, error=str(exc))
        if scan_secrets:
            try:
                secret_audit = audit_secrets(root, create=False)
                add(
                    "secret_audit_clean",
                    bool(secret_audit.get("ok")) and bool(secret_audit.get("complete", True)),
                    files_scanned=secret_audit.get("files_scanned"),
                    files_skipped=secret_audit.get("files_skipped"),
                    incomplete_skip_count=secret_audit.get("incomplete_skip_count", 0),
                    finding_count=secret_audit.get("finding_count"),
                    truncated=secret_audit.get("truncated"),
                    complete=secret_audit.get("complete", True),
                )
            except Exception as exc:
                add("secret_audit_clean", False, error=str(exc))
    else:
        add("sqlite_open", False, error="root is not initialized")

    for rel in ("run/operations", "run/operation_events", "exports/operation_receipts", "exports/operation_events", "exports/proof_packs", "snapshots"):
        target = root / rel
        try:
            secure_mkdir(target)
            probe = target / f".doctor_{unique_id('probe')}.tmp"
            atomic_write_text(probe, "ok\n")
            probe.unlink(missing_ok=True)
            add(f"writable:{rel}", True, path=str(target))
        except Exception as exc:
            add(f"writable:{rel}", False, path=str(target), error=str(exc))

    return {
        "ok": all(check["ok"] for check in checks),
        "root": str(root),
        "check_count": len(checks),
        "checks": checks,
        "status": root_status,
        "verified_proof_packs": proof_results,
    }


def repair_permissions(root: Path) -> dict[str, Any]:
    before = audit_private_permissions(root)
    repair = repair_private_permissions(root)
    after = audit_private_permissions(root)
    return {
        "ok": bool(repair.get("ok")) and bool(after.get("ok")),
        "before": before,
        "repair": repair,
        "after": after,
    }


def list_operations(root: Path, *, status: str | None = None, limit: int = 20) -> dict[str, Any]:
    operations_dir = root / "run" / "operations"
    if not operations_dir.exists():
        return {"root": str(root), "operations": [], "skipped_corrupt": 0, "skipped": []}
    receipts: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for path in operations_dir.glob("*.json"):
        try:
            receipt = _load_receipt(path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            skipped.append({"path": str(path), "error": str(exc)})
            continue
        if status and receipt.get("status") != status:
            continue
        receipts.append(receipt)
    operations: list[dict[str, Any]] = []
    for receipt in sorted(receipts, key=lambda item: _safe_timestamp(item.get("updated_at")), reverse=True):
        operations.append(
            {
                "operation_id": receipt.get("operation_id"),
                "operation_type": receipt.get("operation_type"),
                "title": receipt.get("title"),
                "status": receipt.get("status"),
                "created_at": receipt.get("created_at"),
                "updated_at": receipt.get("updated_at"),
                "finished_at": receipt.get("finished_at"),
                "progress_events": len(receipt.get("progress") or []),
                "cursor": receipt.get("cursor"),
                "export_receipt_uri": _resolve_root_uri(root, receipt.get("export_receipt_uri")),
                "operation_event_log_uri": _resolve_root_uri(root, receipt.get("operation_event_log_uri")),
                "operation_event_export_uri": _resolve_root_uri(root, receipt.get("operation_event_export_uri")),
                "proof_pack_uri": _resolve_root_uri(root, receipt.get("proof_pack_uri")),
                "recovery_packet_uri": _resolve_root_uri(root, receipt.get("recovery_packet_uri")),
                "recovery_packet_json_uri": _resolve_root_uri(root, receipt.get("recovery_packet_json_uri")),
            }
        )
        if len(operations) >= limit:
            break
    return {"root": str(root), "operations": operations, "skipped_corrupt": len(skipped), "skipped": skipped[:10]}


def operation_summary(root: Path, operation_id: str) -> dict[str, Any]:
    receipt = read_operation(root, operation_id)
    return {
        "operation_id": receipt.get("operation_id"),
        "operation_type": receipt.get("operation_type"),
        "title": receipt.get("title"),
        "status": receipt.get("status"),
        "created_at": receipt.get("created_at"),
        "updated_at": receipt.get("updated_at"),
        "finished_at": receipt.get("finished_at"),
        "principle": receipt.get("principle"),
        "cursor": receipt.get("cursor"),
        "preflight_snapshots": receipt.get("preflight_snapshots") or [],
        "progress_events": len(receipt.get("progress") or []),
        "last_progress": (receipt.get("progress") or [None])[-1],
        "run_receipt_uri": _resolve_root_uri(root, receipt.get("run_receipt_uri")),
        "export_receipt_uri": _resolve_root_uri(root, receipt.get("export_receipt_uri")),
        "operation_event_log_uri": _resolve_root_uri(root, receipt.get("operation_event_log_uri")),
        "operation_event_export_uri": _resolve_root_uri(root, receipt.get("operation_event_export_uri")),
        "proof_pack_uri": _resolve_root_uri(root, receipt.get("proof_pack_uri")),
        "proof_pack_hash": receipt.get("proof_pack_hash"),
        "recovery_packet_uri": _resolve_root_uri(root, receipt.get("recovery_packet_uri")),
        "recovery_packet_json_uri": _resolve_root_uri(root, receipt.get("recovery_packet_json_uri")),
        "result": receipt.get("result"),
        "error": receipt.get("error"),
    }


def _parse_timestamp(value: str | None) -> dt.datetime:
    if not value:
        return dt.datetime.fromtimestamp(0, dt.UTC)
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.UTC)
    return parsed.astimezone(dt.UTC)


def _safe_timestamp(value: str | None) -> dt.datetime:
    try:
        return _parse_timestamp(value)
    except (TypeError, ValueError):
        return dt.datetime.fromtimestamp(0, dt.UTC)


def _write_operation_recovery_packet(
    root: Path,
    receipt: dict[str, Any],
    *,
    reason: str,
) -> dict[str, Any]:
    operation_id = str(receipt["operation_id"])
    last_progress = (receipt.get("progress") or [None])[-1]
    generated_at = utc_now()
    packet_path = operation_recovery_path(root, operation_id)
    packet_json_path = operation_recovery_json_path(root, operation_id)
    machine_packet = {
        "schema": OPERATION_RECOVERY_SCHEMA,
        "operation_id": operation_id,
        "generated_at": generated_at,
        "reason": reason,
        "status": receipt.get("status"),
        "operation_type": receipt.get("operation_type"),
        "title": receipt.get("title"),
        "root": str(root),
        "run_receipt_uri": receipt.get("run_receipt_uri"),
        "export_receipt_uri": receipt.get("export_receipt_uri"),
        "proof_pack_uri": receipt.get("proof_pack_uri"),
        "cursor": receipt.get("cursor"),
        "last_progress": last_progress,
        "intent": receipt.get("intent") or {},
        "progress": receipt.get("progress") or [],
        "resume_instruction": (
            "Inspect cursor and last_progress first. Resume from the last durable cursor when "
            "the tool supports resume; otherwise rerun against preserved receipts and proof pack."
        ),
        "packet_uri": str(packet_path),
        "packet_json_uri": str(packet_json_path),
    }
    lines = [
        f"# Epic Continuum Operation Recovery: {operation_id}",
        "",
        f"- Schema: `{OPERATION_RECOVERY_SCHEMA}`",
        f"- Generated: `{generated_at}`",
        f"- Reason: `{reason}`",
        f"- Status: `{receipt.get('status')}`",
        f"- Operation type: `{receipt.get('operation_type')}`",
        f"- Title: {receipt.get('title')}",
        f"- Root: `{root}`",
        f"- Run receipt: `{receipt.get('run_receipt_uri')}`",
        f"- Export receipt: `{receipt.get('export_receipt_uri')}`",
        f"- Proof pack: `{receipt.get('proof_pack_uri')}`",
        "",
        "## Resume Cursor",
        "",
        "```json",
        json.dumps(receipt.get("cursor"), ensure_ascii=True, indent=2, sort_keys=True),
        "```",
        "",
        "## Last Progress",
        "",
        "```json",
        json.dumps(last_progress, ensure_ascii=True, indent=2, sort_keys=True),
        "```",
        "",
        "## Intent",
        "",
        "```json",
        json.dumps(receipt.get("intent") or {}, ensure_ascii=True, indent=2, sort_keys=True),
        "```",
        "",
        "## Recovery Instruction",
        "",
        "Inspect the cursor and last progress first. Resume from the last durable cursor when the tool supports resume; otherwise rerun the operation against the preserved receipts and proof pack.",
    ]
    packet_text = "\n".join(lines).rstrip() + "\n"
    atomic_write_text(packet_path, packet_text)
    machine_packet["packet_hash"] = content_hash(packet_text)
    atomic_write_json(packet_json_path, machine_packet)

    receipt = read_operation(root, operation_id)
    receipt["recovery_packet_uri"] = str(packet_path)
    receipt["recovery_packet_json_uri"] = str(packet_json_path)
    write_operation(root, receipt)
    return {
        "operation_id": operation_id,
        "packet_uri": str(packet_path),
        "packet_json_uri": str(packet_json_path),
        "packet_hash": content_hash(packet_text),
        "reason": reason,
    }


def recover_stale_operations(
    root: Path,
    *,
    older_than_seconds: int = 300,
    mark: bool = True,
    limit: int = 20,
) -> dict[str, Any]:
    operations_dir = root / "run" / "operations"
    if not operations_dir.exists():
        return {"root": str(root), "older_than_seconds": older_than_seconds, "recovered": [], "skipped_corrupt": 0, "skipped": []}
    cutoff = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=older_than_seconds)
    recovered: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    for path in operations_dir.glob("*.json"):
        try:
            receipts.append(_load_receipt(path))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            skipped.append({"path": str(path), "error": str(exc)})
            continue
    for receipt in sorted(receipts, key=lambda item: _safe_timestamp(item.get("updated_at"))):
        if receipt.get("status") not in ACTIVE_STATUSES:
            continue
        updated = _parse_timestamp(receipt.get("updated_at"))
        if updated > cutoff:
            continue
        operation_id = str(receipt["operation_id"])
        if older_than_seconds <= 0:
            reason = "operation selected for immediate recovery"
        else:
            reason = f"operation remained running for at least {older_than_seconds} seconds"
        if mark:
            receipt = finish_operation(
                root,
                operation_id,
                status="interrupted",
                error={
                    "type": "InterruptedOperation",
                    "message": reason,
                    "updated_at": receipt.get("updated_at"),
                },
            )
            receipt["proof_pack_uri"] = str(proof_pack_path(root, operation_id))
            receipt = write_operation(root, receipt)
            packet = _write_operation_recovery_packet(root, receipt, reason=reason)
            proof = create_proof_pack(
                root,
                operation_id,
                touched_paths=[packet["packet_uri"], packet["packet_json_uri"]],
                extra={"recovery_reason": reason, "recovery_packet_hash": packet["packet_hash"]},
            )
            receipt = read_operation(root, operation_id)
        else:
            packet = {
                "packet_uri": None,
                "packet_json_uri": None,
                "packet_hash": None,
                "reason": reason,
            }
            proof = {"proof_pack_uri": receipt.get("proof_pack_uri")}
        recovered.append(
            {
                "operation_id": operation_id,
                "status": "interrupted" if mark else receipt.get("status"),
                "updated_at": receipt.get("updated_at"),
                "cursor": receipt.get("cursor"),
                "last_progress": (receipt.get("progress") or [None])[-1],
                "proof_pack_uri": proof.get("proof_pack_uri"),
                "recovery_packet_uri": packet["packet_uri"],
                "recovery_packet_json_uri": packet["packet_json_uri"],
                "would_recover": not mark,
                "reason": reason,
            }
        )
        if len(recovered) >= limit:
            break
    return {
        "root": str(root),
        "older_than_seconds": older_than_seconds,
        "marked": mark,
        "recovered": recovered,
        "skipped_corrupt": len(skipped),
        "skipped": skipped[:10],
    }


class OperationGuard:
    def __init__(
        self,
        root: Path,
        *,
        operation_type: str,
        title: str,
        intent: dict[str, Any] | None = None,
        actor: str = "system",
        snapshot_policy: str = "none",
        snapshot_reason: str | None = None,
        proof: bool = True,
        touched_paths: list[Path | str] | None = None,
    ) -> None:
        if snapshot_policy not in {"none", "auto", "always"}:
            raise ValueError("snapshot_policy must be none, auto, or always")
        self.root = root
        self.operation_type = operation_type
        self.title = title
        self.intent = dict(intent or {})
        self.intent.setdefault("preflight_snapshot_policy", snapshot_policy)
        self.intent.setdefault("preflight_snapshot_reason", snapshot_reason or "not required")
        self.actor = actor
        self.snapshot_policy = snapshot_policy
        self.snapshot_reason = snapshot_reason or operation_type
        self.proof = proof
        self.touched_paths = list(touched_paths or [])
        self.operation_id = ""
        self.finished = False
        self.final_receipt: dict[str, Any] | None = None

    def __enter__(self) -> OperationGuard:
        receipt = start_operation(
            self.root,
            operation_type=self.operation_type,
            title=self.title,
            intent=self.intent,
            actor=self.actor,
        )
        self.operation_id = str(receipt["operation_id"])
        if self.snapshot_policy == "none":
            self.progress(
                "preflight_snapshot",
                f"snapshot skipped: {self.snapshot_reason}",
            )
        else:
            try:
                snap = create_preflight_snapshot(self.root, self.operation_id, reason=self.snapshot_reason)
                self.progress("preflight_snapshot", "catalog snapshot created", detail=snap)
            except Exception as exc:
                self.progress(
                    "preflight_snapshot",
                    f"snapshot failed: {exc}",
                    detail={"error_type": type(exc).__name__},
                )
                if self.snapshot_policy == "always":
                    raise
        return self

    def __exit__(self, exc_type: Any, exc: BaseException | None, tb: Any) -> bool:
        if self.finished:
            return False
        if exc is not None:
            error = {
                "type": type(exc).__name__,
                "message": str(exc),
                "traceback": "".join(traceback.format_exception(exc_type, exc, tb))[-4000:],
            }
            self.final_receipt = finish_operation(self.root, self.operation_id, status="failed", error=error)
            if self.proof:
                create_proof_pack(self.root, self.operation_id, touched_paths=self.touched_paths)
            self.finished = True
            return False
        self.succeed({})
        return False

    def progress(
        self,
        phase: str,
        message: str,
        *,
        current: int | None = None,
        total: int | None = None,
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return record_operation_progress(
            self.root,
            self.operation_id,
            phase=phase,
            message=message,
            current=current,
            total=total,
            detail=detail,
        )

    def cursor(self, cursor: dict[str, Any] | None) -> dict[str, Any]:
        return update_operation_cursor(self.root, self.operation_id, cursor)

    def succeed(
        self,
        result: dict[str, Any] | None,
        *,
        touched_paths: list[Path | str] | None = None,
        proof_extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self.finished:
            return self.final_receipt or read_operation(self.root, self.operation_id)
        self.final_receipt = finish_operation(self.root, self.operation_id, status="succeeded", result=result)
        if self.proof:
            proof_paths = [*self.touched_paths, *(touched_paths or [])]
            create_proof_pack(self.root, self.operation_id, touched_paths=proof_paths, extra=proof_extra)
            self.final_receipt = read_operation(self.root, self.operation_id)
        self.finished = True
        return self.final_receipt

    def wrap_result(self, result: Any) -> Any:
        receipt = self.final_receipt or read_operation(self.root, self.operation_id)
        operation_payload = {
            "operation_id": self.operation_id,
            "status": receipt.get("status"),
            "operation_receipt_uri": _resolve_root_uri(self.root, receipt.get("export_receipt_uri")),
            "proof_pack_uri": _resolve_root_uri(self.root, receipt.get("proof_pack_uri")),
            "recovery_packet_uri": _resolve_root_uri(self.root, receipt.get("recovery_packet_uri")),
            "recovery_packet_json_uri": _resolve_root_uri(self.root, receipt.get("recovery_packet_json_uri")),
        }
        if isinstance(result, dict):
            wrapped = dict(result)
            wrapped["_operation"] = operation_payload
            return wrapped
        return {"result": result, "_operation": operation_payload}


def recovery_drill(root: Path, *, drill_name: str = "epic-continuum-recovery-drill") -> dict[str, Any]:
    drill_id = unique_id("drill")
    drill_root = root / "run" / "recovery_drills" / drill_id
    operation = start_operation(
        drill_root,
        operation_type="drill_interrupted_job",
        title="Recovery drill interrupted operation",
        intent={"drill_id": drill_id, "parent_root": str(root)},
        actor="recovery_drill",
    )
    operation_id = str(operation["operation_id"])
    record_operation_progress(
        drill_root,
        operation_id,
        phase="simulate",
        message="created a deliberately unfinished operation",
        current=1,
        total=2,
    )
    update_operation_cursor(
        drill_root,
        operation_id,
        {"phase": "simulate", "step": 1, "resume_hint": "continue with step 2 after recovery"},
    )
    recovered = recover_stale_operations(drill_root, older_than_seconds=0, mark=True, limit=5)
    summary = operation_summary(drill_root, operation_id)
    proof_verification = (
        verify_proof_pack(Path(str(summary["proof_pack_uri"]))) if summary.get("proof_pack_uri") else {"ok": False}
    )
    ok = (
        summary["status"] == "interrupted"
        and bool(summary.get("proof_pack_uri"))
        and bool(summary.get("recovery_packet_uri"))
        and Path(str(summary["recovery_packet_uri"])).exists()
        and bool(proof_verification.get("ok"))
    )
    result = {
        "schema": RECOVERY_DRILL_SCHEMA,
        "ok": ok,
        "drill_id": drill_id,
        "drill_root": str(drill_root),
        "operation_id": operation_id,
        "summary": summary,
        "proof_verification": proof_verification,
        "recovered": recovered["recovered"],
    }
    out_path = root / "exports" / "recovery_drills" / f"{drill_id}.json"
    result["receipt_uri"] = str(out_path)
    stored_result = _root_relative_payload(root, result)
    stored_result["receipt_uri"] = _stored_root_uri(root, out_path)
    atomic_write_json(out_path, stored_result)
    return result


def _latest_snapshot_path(root: Path) -> Path | None:
    snapshot_dir = root / "snapshots"
    if not snapshot_dir.exists():
        return None
    snapshots = sorted(
        snapshot_dir.glob("continuum_catalog_*.sqlite3"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    return snapshots[0] if snapshots else None


def _snapshot_sidecars_path(snapshot_path: Path) -> Path | None:
    name = snapshot_path.name
    prefix = "continuum_catalog_"
    suffix = ".sqlite3"
    if not name.startswith(prefix) or not name.endswith(suffix):
        return None
    snapshot_id = name[len(prefix) : -len(suffix)]
    sidecars = snapshot_path.parent / f"continuum_cards_{snapshot_id}"
    return sidecars if sidecars.exists() else None


def _schema_version_for_root(root: Path) -> str | None:
    conn = connect_existing(root)
    try:
        row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
        return str(row["value"]) if row else None
    finally:
        conn.close()


SNAPSHOT_COUNT_TABLES = (
    "scroll_events",
    "scroll_segments",
    "books",
    "chunks",
    "cards",
    "queue_jobs",
    "graph_nodes",
    "graph_edges",
    "audit_events",
    "snapshots",
    "artifacts",
)


def _catalog_counts_from_db(db_path: Path) -> dict[str, int]:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        existing_tables = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            if row["name"]
        }
        counts: dict[str, int] = {}
        for table in SNAPSHOT_COUNT_TABLES:
            counts[table] = conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] if table in existing_tables else 0
        return counts
    finally:
        conn.close()


def _snapshot_manifest(snapshot_path: Path) -> dict[str, Any]:
    sidecars = _snapshot_sidecars_path(snapshot_path)
    return {
        "schema": "epic_continuum.snapshot_manifest.v1",
        "snapshot_uri": str(snapshot_path),
        "counts": _catalog_counts_from_db(snapshot_path),
        "card_sidecars_uri": str(sidecars) if sidecars else None,
        "card_sidecar_count": sum(1 for item in sidecars.glob("*.yaml")) if sidecars else 0,
    }


def _verify_artifact_ledger(root: Path, *, limit: int = 500) -> dict[str, Any]:
    if not is_initialized(root):
        return {
            "ok": False,
            "table_exists": False,
            "checked": 0,
            "missing": 0,
            "mismatches": [],
            "absolute_internal_uri_count": 0,
            "absolute_internal_uris": [],
        }
    conn = connect_existing(root)
    mismatches: list[dict[str, Any]] = []
    absolute_internal_uris: list[str] = []
    checked = 0
    missing = 0
    try:
        table = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'artifacts'").fetchone()
        if not table:
            return {
                "ok": True,
                "table_exists": False,
                "checked": 0,
                "missing": 0,
                "mismatches": [],
                "absolute_internal_uri_count": 0,
                "absolute_internal_uris": [],
            }
        rows = conn.execute(
            """
            SELECT id, kind, uri, sha256, size_bytes
            FROM artifacts
            WHERE immutable = 1
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (max(1, int(limit)),),
        ).fetchall()
        for row in rows:
            if is_internal_absolute_uri(root, str(row["uri"])):
                absolute_internal_uris.append(str(row["uri"]))
            artifact_path = resolve_stored_uri(root, str(row["uri"]))
            if not artifact_path.exists():
                missing += 1
                continue
            checked += 1
            actual_hash = file_sha256(artifact_path)
            actual_size = artifact_path.stat().st_size
            expected_hash = str(row["sha256"])
            expected_size = int(row["size_bytes"])
            if actual_hash != expected_hash or actual_size != expected_size:
                mismatches.append(
                    {
                        "id": row["id"],
                        "kind": row["kind"],
                        "uri": row["uri"],
                        "expected_sha256": expected_hash,
                        "actual_sha256": actual_hash,
                        "expected_size_bytes": expected_size,
                        "actual_size_bytes": actual_size,
                    }
                )
        return {
            "ok": not mismatches and missing == 0 and not absolute_internal_uris,
            "table_exists": True,
            "row_count": len(rows),
            "checked": checked,
            "missing": missing,
            "mismatch_count": len(mismatches),
            "mismatches": mismatches[:20],
            "absolute_internal_uri_count": len(absolute_internal_uris),
            "absolute_internal_uris": absolute_internal_uris[:20],
        }
    finally:
        conn.close()


def _verify_recent_proof_packs(
    root: Path,
    *,
    limit: int,
    allowed_roots: list[Path] | None = None,
) -> dict[str, Any]:
    proof_dir = root / "exports" / "proof_packs"
    if limit <= 0 or not proof_dir.exists():
        return {"ok": True, "checked": 0, "results": []}
    proof_paths = sorted(proof_dir.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)[:limit]
    results = [verify_proof_pack(path, root=root, allowed_roots=allowed_roots) for path in proof_paths]
    return {"ok": all(result["ok"] for result in results), "checked": len(results), "results": results}


def verify_root(
    root: Path,
    *,
    strict: bool = True,
    verify_recent_proof_packs: int = 5,
    run_restore_drill: bool = True,
    scan_secrets: bool = True,
    allowed_roots: list[Path] | None = None,
) -> dict[str, Any]:
    """Run the high-level root invariant suite for reviewer and recovery handoffs."""
    checks: list[dict[str, Any]] = []
    sections: dict[str, Any] = {}

    def add(name: str, ok: bool, **detail: Any) -> None:
        checks.append({"name": name, "ok": ok, **detail})

    doctor_result = doctor(
        root,
        verify_recent_proof_packs=verify_recent_proof_packs,
        scan_secrets=scan_secrets,
        allowed_roots=allowed_roots,
    )
    sections["doctor"] = doctor_result
    add("doctor", bool(doctor_result.get("ok")), check_count=doctor_result.get("check_count"))

    search_result = audit_search_index(root, create=False)
    sections["search_index"] = search_result
    add(
        "search_index_audit",
        bool(search_result.get("ok")),
        chunks=search_result.get("chunks"),
        fts_rows=search_result.get("fts_rows"),
        missing_chunks=search_result.get("missing_chunks"),
        orphan_fts_rows=search_result.get("orphan_fts_rows"),
    )

    permissions_result = audit_private_permissions(root)
    sections["private_permissions"] = permissions_result
    add(
        "private_permissions",
        bool(permissions_result.get("ok")),
        supported=permissions_result.get("supported"),
        checked=permissions_result.get("checked"),
        unsafe_count=permissions_result.get("unsafe_count"),
        reason=permissions_result.get("reason"),
    )

    if scan_secrets:
        secret_result = audit_secrets(root, create=False)
        sections["secret_audit"] = secret_result
        secret_audit_ok = bool(secret_result.get("ok")) and (
            not strict or bool(secret_result.get("complete", True))
        )
        add(
            "secret_audit",
            secret_audit_ok,
            finding_count=secret_result.get("finding_count"),
            files_scanned=secret_result.get("files_scanned"),
            files_skipped=secret_result.get("files_skipped"),
            incomplete_skip_count=secret_result.get("incomplete_skip_count", 0),
            truncated=secret_result.get("truncated"),
            complete=secret_result.get("complete", True),
        )
    else:
        sections["secret_audit"] = {"ok": True, "skipped": True, "reason": "scan_secrets_disabled"}
        add("secret_audit_skipped", True, reason="scan_secrets_disabled")

    artifact_result = _verify_artifact_ledger(root)
    sections["artifact_ledger"] = artifact_result
    add(
        "artifact_ledger",
        bool(artifact_result.get("ok")),
        checked=artifact_result.get("checked"),
        missing=artifact_result.get("missing"),
        mismatch_count=artifact_result.get("mismatch_count", 0),
        absolute_internal_uri_count=artifact_result.get("absolute_internal_uri_count", 0),
    )

    proof_result = _verify_recent_proof_packs(root, limit=verify_recent_proof_packs, allowed_roots=allowed_roots)
    sections["proof_packs"] = proof_result
    add("recent_proof_packs", bool(proof_result.get("ok")), checked=proof_result.get("checked"))

    stale_operations = recover_stale_operations(root, older_than_seconds=0, mark=False, limit=50)
    sections["stale_operations"] = stale_operations
    add("no_stale_running_operations", not bool(stale_operations.get("recovered")), stale_count=len(stale_operations.get("recovered") or []))

    if strict and run_restore_drill:
        if is_initialized(root):
            restore_result = restore_drill(
                root,
                drill_name="verify-root-strict",
                verify_recent_proof_packs=max(0, min(verify_recent_proof_packs, 3)),
                allowed_roots=allowed_roots,
            )
            sections["restore_drill"] = restore_result
            add("restore_drill", bool(restore_result.get("ok")), drill_id=restore_result.get("drill_id"))
        else:
            sections["restore_drill"] = {"ok": False, "reason": "root_not_initialized"}
            add("restore_drill", False, reason="root_not_initialized")

    return {
        "schema": "epic_continuum.verify_root.v1",
        "ok": all(check["ok"] for check in checks),
        "root": str(root),
        "strict": strict,
        "verify_recent_proof_packs": verify_recent_proof_packs,
        "run_restore_drill": bool(strict and run_restore_drill),
        "scan_secrets": scan_secrets,
        "check_count": len(checks),
        "checks": checks,
        "sections": sections,
    }


def restore_drill(
    root: Path,
    *,
    snapshot_uri: str | None = None,
    drill_name: str = "epic-continuum-restore-drill",
    verify_recent_proof_packs: int = 1,
    allowed_roots: list[Path] | None = None,
) -> dict[str, Any]:
    created_seed_snapshot: dict[str, Any] | None = None
    if snapshot_uri:
        selected_snapshot = resolve_stored_uri(root, snapshot_uri)
    else:
        created_seed_snapshot = snapshot(root, reason="restore_drill_seed_snapshot")
        selected_snapshot = Path(str(created_seed_snapshot["snapshot_uri"]))
    if not selected_snapshot.exists():
        raise FileNotFoundError(str(selected_snapshot))
    selected_manifest = _snapshot_manifest(selected_snapshot)

    drill_id = unique_id("restore")
    drill_root = root / "run" / "restore_drills" / drill_id
    restored_db = drill_root / "catalog" / "catalog.sqlite3"
    secure_copy_file(selected_snapshot, restored_db)
    secure_sqlite_files(restored_db)

    sidecars = _snapshot_sidecars_path(selected_snapshot)
    restored_sidecars = drill_root / "catalog" / "cards"
    sidecar_count = 0
    if sidecars is not None:
        secure_copytree(sidecars, restored_sidecars, dirs_exist_ok=True, symlinks=True)
        sidecar_count = sum(1 for item in restored_sidecars.glob("*.yaml"))

    durable_rel_paths = (
        Path("archive"),
        Path("run/import_state"),
        Path("run/mempalace_import_snapshots"),
        Path("run/operation_events"),
        Path("run/operations"),
        Path("snapshots"),
        Path("exports/proof_artifacts"),
        Path("exports/proof_packs"),
        Path("exports/imports"),
        Path("exports/operation_events"),
        Path("exports/operation_receipts"),
        Path("exports/operation_recovery"),
        Path("exports/recovery_drills"),
        Path("exports/restore_drills"),
        Path("exports/thread_recovery"),
    )
    copied_durable_paths: list[str] = []
    for rel_path in durable_rel_paths:
        source_path = root / rel_path
        if not source_path.exists():
            continue
        target_path = drill_root / rel_path
        secure_copytree(source_path, target_path, dirs_exist_ok=True, symlinks=True)
        copied_durable_paths.append(rel_path.as_posix())

    status_result = status(drill_root, create=False)
    audit_result = audit(drill_root, create=False)
    restored_schema_version = _schema_version_for_root(drill_root)
    restored_counts = {table: int(status_result.get(table, 0)) for table in SNAPSHOT_COUNT_TABLES}
    expected_counts = dict(selected_manifest["counts"])
    search_index = audit_search_index(drill_root, create=False)
    recent_proofs = _verify_recent_proof_packs(drill_root, limit=verify_recent_proof_packs, allowed_roots=allowed_roots)
    artifact_ledger = _verify_artifact_ledger(drill_root)
    recovery_probe = recovery_drill(drill_root, drill_name=f"{drill_name}-recovery-probe")
    checks = [
        {"name": "snapshot_exists", "ok": selected_snapshot.exists(), "path": str(selected_snapshot)},
        {"name": "restored_db_exists", "ok": restored_db.exists(), "path": str(restored_db)},
        {"name": "status_initialized", "ok": bool(status_result.get("initialized"))},
        {"name": "audit_opened", "ok": bool(audit_result.get("initialized"))},
        {
            "name": "schema_version_matches",
            "ok": restored_schema_version == SCHEMA_VERSION,
            "restored_schema_version": restored_schema_version,
            "expected_schema_version": SCHEMA_VERSION,
        },
        {
            "name": "restored_counts_match_snapshot_manifest",
            "ok": restored_counts == expected_counts,
            "expected_counts": expected_counts,
            "restored_counts": restored_counts,
        },
        {
            "name": "search_index_consistent",
            "ok": bool(search_index.get("ok")),
            "missing_chunks": search_index.get("missing_chunks"),
            "orphan_fts_rows": search_index.get("orphan_fts_rows"),
            "fts_rows": search_index.get("fts_rows"),
        },
        {"name": "recent_proof_packs_verify", "ok": bool(recent_proofs["ok"]), "checked": recent_proofs["checked"]},
        {
            "name": "artifact_ledger_hashes_match",
            "ok": bool(artifact_ledger["ok"]),
            "checked": artifact_ledger["checked"],
            "missing": artifact_ledger["missing"],
            "absolute_internal_uri_count": artifact_ledger.get("absolute_internal_uri_count", 0),
        },
        {
            "name": "recovery_packet_generated",
            "ok": bool(recovery_probe.get("ok")) and bool(recovery_probe.get("summary", {}).get("recovery_packet_uri")),
            "operation_id": recovery_probe.get("operation_id"),
        },
    ]
    result = {
        "schema": RESTORE_DRILL_SCHEMA,
        "ok": all(check["ok"] for check in checks),
        "drill_id": drill_id,
        "drill_name": drill_name,
        "root": str(root),
        "drill_root": str(drill_root),
        "snapshot_uri": str(selected_snapshot),
        "seed_snapshot": created_seed_snapshot,
        "snapshot_manifest": selected_manifest,
        "restored_db_uri": str(restored_db),
        "restored_card_sidecars_uri": str(restored_sidecars) if restored_sidecars.exists() else None,
        "restored_card_sidecar_count": sidecar_count,
        "copied_durable_paths": copied_durable_paths,
        "restored_schema_version": restored_schema_version,
        "recent_proof_packs": recent_proofs,
        "artifact_ledger": artifact_ledger,
        "search_index": search_index,
        "recovery_probe": recovery_probe,
        "checks": checks,
        "status": status_result,
        "audit": audit_result,
    }
    out_path = root / "exports" / "restore_drills" / f"{drill_id}.json"
    result["receipt_uri"] = str(out_path)
    stored_result = _root_relative_payload(root, result)
    stored_result["receipt_uri"] = _stored_root_uri(root, out_path)
    atomic_write_json(out_path, stored_result)
    return result
