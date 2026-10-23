"""Explicit portable evidence and hash-bound, no-provider memory experiments.

Imports are inert shared evidence, not activated facts, handoffs, instructions or
claims of independent verification. Snapshot hashes are integrity anchors supplied
by the caller, not signatures or a new remote trust/authentication mechanism.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Any

from .config import config_path, default_config, write_config
from .knowledge_records import KINDS, SCHEMA, append_record, read_records, require_text, require_timestamp
from .recall import recall_memory
from .safety import scan_text_for_secrets, scan_value_for_secrets
from .store import canonical_partition_identifier, connect_existing, init_db, validate_partition_identifier

_CAPSULE = "continuum.workspace.v1"
_EXPERIMENT = "continuum.memory-experiment.v1"
_REPLAY = "continuum.memory-replay.v1"
_MAX_CAPSULE = 512 * 1024
_MAX_SOURCE = 49152
_MAX_SNAPSHOT = 64 * 1024 * 1024
_MAX_PROJECT_RECORDS = 10000
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


def _identifier(value: Any, field: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(f"{field} must be a portable identifier of at most 128 characters")
    return value


def _hash(value: Any) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ValueError("a lowercase SHA-256 hash is required")
    return value


def _project(root: Path, value: Any) -> str:
    require_text(value, "project_id", 256)
    result = canonical_partition_identifier(root, "project_id", value, lookup=True)
    if not result:
        raise ValueError("project_id is required")
    return result


def _plain(value: Any, depth: int = 0, counter: list[int] | None = None) -> None:
    counter = [0] if counter is None else counter
    counter[0] += 1
    if depth > 24 or counter[0] > 100000:
        raise ValueError("workspace structure exceeds its bounds")
    if value is None or type(value) is bool:
        return
    if type(value) is int and abs(value) <= 2**63 - 1:
        return
    if type(value) is float:
        import math
        if math.isfinite(value):
            return
    if type(value) is str:
        if len(value) > _MAX_CAPSULE:
            raise ValueError("workspace text exceeds its bound")
        try:
            value.encode("utf-8")
        except UnicodeError:
            raise ValueError("workspace text must be valid UTF-8") from None
        return
    if type(value) is list and len(value) <= 16384:
        for item in value:
            _plain(item, depth + 1, counter)
        return
    if type(value) is dict and len(value) <= 16384 and all(type(key) is str for key in value):
        for key, item in value.items():
            _plain(key, depth + 1, counter)
            _plain(item, depth + 1, counter)
        return
    raise ValueError("workspace values must be bounded plain JSON")


def _json(value: Any, maximum: int = _MAX_CAPSULE) -> bytes:
    _plain(value)
    try:
        raw = json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        raise ValueError("workspace JSON is malformed") from None
    if len(raw) > maximum:
        raise ValueError("workspace JSON exceeds the byte limit")
    return raw


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object key")
        value[key] = item
    return value


def _load(raw: bytes, maximum: int = _MAX_CAPSULE) -> Any:
    if len(raw) > maximum:
        raise ValueError("workspace JSON exceeds the byte limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        _json(value, maximum)
        return value
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise ValueError("workspace JSON is malformed or exceeds limits") from None


def _digest(value: Any) -> str:
    return hashlib.sha256(_json(value)).hexdigest()


def _origin(value: Any) -> dict[str, str]:
    if type(value) is not dict or set(value) != {"workspace_id", "project_id", "record_id"}:
        raise ValueError("origin requires workspace, project and record identity")
    _identifier(value["workspace_id"], "workspace_id")
    require_text(value["project_id"], "source project_id", 256)
    _identifier(value["record_id"], "source record_id")
    return dict(value)


def _key(origin: dict[str, str]) -> tuple[str, str, str]:
    return origin["workspace_id"], origin["project_id"], origin["record_id"]


def _source(item: Any, source_project: str) -> dict[str, Any]:
    if type(item) is not dict or set(item) != {"id", "kind", "recorded_at", "content_hash", "content"}:
        raise ValueError("workspace records require exact source envelopes")
    _identifier(item["id"], "source record_id")
    if type(item["kind"]) is not str or item["kind"] not in KINDS:
        raise ValueError("unsupported source knowledge kind")
    require_timestamp(item["recorded_at"], "source recorded_at")
    content = require_text(item["content"], "source content", _MAX_SOURCE)
    raw = content.encode("utf-8")
    if len(raw) > _MAX_SOURCE or hashlib.sha256(raw).hexdigest() != _hash(item["content_hash"]):
        raise ValueError("source content hash or size mismatch")
    envelope = _load(raw, _MAX_SOURCE)
    if (type(envelope) is not dict or set(envelope) != {"schema", "kind", "project_id", "nonce", "payload"}
            or envelope["schema"] != SCHEMA or envelope["project_id"] != source_project
            or envelope["kind"] != item["kind"] or type(envelope["payload"]) is not dict
            or type(envelope["nonce"]) is not str or re.fullmatch(r"[0-9a-f]{32}", envelope["nonce"]) is None):
        raise ValueError("source envelope does not match declared authority")
    if (scan_value_for_secrets(envelope, scope="workspace source", max_findings=1)
            or scan_text_for_secrets(content, max_findings=1)):
        raise ValueError("workspace source contains credential-like material")
    return item


def _capsule(value: Any, expected_snapshot_hash: str) -> dict[str, Any]:
    # Canonical roundtrip provides a bounded defensive copy before any writes.
    capsule = _load(_json(value))
    if type(capsule) is not dict or set(capsule) != {"schema", "workspace_id", "source_project", "records", "snapshot_hash"}:
        raise ValueError("invalid workspace capsule")
    if capsule["schema"] != _CAPSULE:
        raise ValueError("unsupported workspace schema")
    _identifier(capsule["workspace_id"], "workspace_id")
    require_text(capsule["source_project"], "source_project", 256)
    records = capsule["records"]
    if type(records) is not list or not 1 <= len(records) <= 32:
        raise ValueError("workspace must contain 1 to 32 explicit records")
    if _hash(expected_snapshot_hash) != _hash(capsule["snapshot_hash"]) or _digest({
        key: item for key, item in capsule.items() if key != "snapshot_hash"
    }) != expected_snapshot_hash:
        raise ValueError("workspace snapshot hash mismatch")
    ids = []
    for record in records:
        _source(record, capsule["source_project"])
        ids.append(record["id"])
        _json(_shared_payload(capsule, record), 60000)
    if ids != sorted(set(ids)):
        raise ValueError("workspace source IDs must be unique and sorted")
    if scan_value_for_secrets(capsule, scope="workspace", max_findings=1):
        raise ValueError("workspace contains credential-like material")
    return capsule


def _shared_payload(capsule: dict[str, Any], item: dict[str, Any]) -> dict[str, Any]:
    return {"schema": 1, "origin": {"workspace_id": capsule["workspace_id"], "project_id": capsule["source_project"], "record_id": item["id"]},
            "source_kind": item["kind"], "source_hash": item["content_hash"], "source_recorded_at": item["recorded_at"],
            "source_content": item["content"], "trust": "accepted_evidence_not_verified_or_active"}


def export_workspace(root: Path, *, project_id: str, record_ids: list[str], workspace_id: str) -> dict[str, Any]:
    """Export exactly selected project-visible typed rows; never follow references."""
    project_id = _project(root, project_id)
    _identifier(workspace_id, "workspace_id")
    if type(record_ids) is not list or not 1 <= len(record_ids) <= 32:
        raise ValueError("record_ids must select 1 to 32 records")
    ids = [_identifier(item, "record_id") for item in record_ids]
    if len(ids) != len(set(ids)):
        raise ValueError("record_ids must be unique")
    if not (root / "catalog" / "catalog.sqlite3").is_file():
        raise ValueError("selected records are unavailable")
    with closing(connect_existing(root)) as conn:
        conn.execute("BEGIN")
        records = {row["id"]: row for row in read_records(root, project_id=project_id, connection=conn)}
        if any(item not in records for item in ids):
            raise ValueError("selected record is not visible in the requested project")
        selected = []
        for record_id in sorted(ids):
            row = records[record_id]
            content = conn.execute("SELECT content FROM scroll_events WHERE id=?", (record_id,)).fetchone()[0]
            selected.append({"id": record_id, "kind": row["kind"], "recorded_at": row["recorded_at"],
                             "content_hash": row["content_hash"], "content": content})
    capsule: dict[str, Any] = {"schema": _CAPSULE, "workspace_id": workspace_id, "source_project": project_id, "records": selected}
    capsule["snapshot_hash"] = _digest(capsule)
    return _capsule(capsule, capsule["snapshot_hash"])


def _state(root: Path, project_id: str, connection: sqlite3.Connection | None = None,
           exclude_id: str | None = None) -> tuple[dict, dict, int]:
    variants: dict[tuple[str, str, str], dict[str, dict[str, Any]]] = {}
    decisions: dict[tuple[str, str, str], dict[str, Any]] = {}
    # The existing typed-record read bound applies to the whole project, not
    # just imported evidence. Keep that same bound for planning and validation.
    records = read_records(root, project_id=project_id, connection=connection, max_records=_MAX_PROJECT_RECORDS)
    for row in records:
        if row["id"] == exclude_id or row["kind"] not in {"shared_knowledge", "workspace_decision"}:
            continue
        payload = row["payload"]
        if type(payload.get("schema")) is not int or payload["schema"] != 1:
            raise ValueError("invalid shared knowledge schema")
        origin = _origin(payload.get("origin"))
        identity = _key(origin)
        if row["kind"] == "shared_knowledge":
            if set(payload) != {"schema", "origin", "source_kind", "source_hash", "source_recorded_at", "source_content", "trust"}:
                raise ValueError("invalid shared knowledge fields")
            if payload["trust"] != "accepted_evidence_not_verified_or_active":
                raise ValueError("shared evidence cannot confer active authority")
            _source({"id": origin["record_id"], "kind": payload["source_kind"], "recorded_at": payload["source_recorded_at"],
                     "content_hash": payload["source_hash"], "content": payload["source_content"]}, origin["project_id"])
            versions = variants.setdefault(identity, {})
            if payload["source_hash"] in versions:
                raise ValueError("duplicate imported origin version")
            versions[payload["source_hash"]] = row
        else:
            if set(payload) != {"schema", "origin", "variant_hashes", "selected_hash", "reviewer", "reason", "previous_decision_id"}:
                raise ValueError("invalid workspace decision fields")
            hashes = payload["variant_hashes"]
            if type(hashes) is not list or not 2 <= len(hashes) <= 32 or hashes != sorted({_hash(item) for item in hashes}):
                raise ValueError("decision requires a unique bounded variant set")
            if set(hashes) != set(variants.get(identity, {})) or _hash(payload["selected_hash"]) not in hashes:
                raise ValueError("decision variant set was not current at recording")
            current = decisions.get(identity)
            expected = None if current is None else current["id"]
            if payload["previous_decision_id"] != expected:
                raise ValueError("workspace decision head changed")
            require_text(payload["reviewer"], "reviewer", 128)
            require_text(payload["reason"], "reason", 2000)
            decisions[identity] = row
    return variants, decisions, len(records)


def plan_workspace_import(
    root: Path, *, project_id: str, capsule: dict[str, Any], expected_snapshot_hash: str,
    allow_fork: bool = False,
) -> dict[str, Any]:
    """Validate the complete input and report conflicts without creating a root."""
    project_id = _project(root, project_id)
    if type(allow_fork) is not bool:
        raise ValueError("allow_fork must be a boolean")
    capsule = _capsule(capsule, expected_snapshot_hash)
    variants, decisions, record_count = _state(root, project_id)
    results = []
    for source in capsule["records"]:
        payload = _shared_payload(capsule, source)
        identity = _key(payload["origin"])
        existing = variants.get(identity, {})
        status = "unchanged" if source["content_hash"] in existing else ("fork" if allow_fork else "conflict") if existing else "import"
        if status == "fork" and len(existing) >= 32:
            status = "capacity_exceeded"
        decision = decisions.get(identity)
        results.append({"origin": payload["origin"], "source_hash": source["content_hash"], "status": status,
                        "variants": sorted(existing), "existing_id": existing[source["content_hash"]]["id"] if status == "unchanged" else None,
                        "decision_id": None if decision is None else decision["id"],
                        "decision_current": bool(decision and set(decision["payload"]["variant_hashes"]) == set(existing))})
    new_records = sum(row["status"] in {"import", "fork"} for row in results)
    capacity_exceeded = record_count + new_records > _MAX_PROJECT_RECORDS
    return {"schema_version": 1, "project_id": project_id, "snapshot_hash": expected_snapshot_hash,
            "can_import": not capacity_exceeded and not any(row["status"] in {"conflict", "capacity_exceeded"} for row in results),
            "record_capacity": {"limit": _MAX_PROJECT_RECORDS, "current_records": record_count,
                                "new_records": new_records, "exceeded": capacity_exceeded}, "results": results,
            "activated": False, "instruction_authority": "none"}


class _AlreadyImported(Exception):
    def __init__(self, row: dict[str, Any]) -> None:
        self.row = row


def import_workspace(
    root: Path, *, project_id: str, session_id: str, capsule: dict[str, Any], expected_snapshot_hash: str,
    allow_fork: bool = False,
) -> dict[str, Any]:
    """Append inert evidence with per-origin idempotency; never overwrite a variant.

    All input/conflicts are preflighted. A later concurrent conflict can stop a
    multi-record import after earlier records committed; retry is idempotent.
    """
    project_id = _project(root, project_id)
    require_text(session_id, "session_id", 256)
    capsule = _capsule(capsule, expected_snapshot_hash)
    plan = plan_workspace_import(root, project_id=project_id, capsule=capsule,
                                 expected_snapshot_hash=expected_snapshot_hash, allow_fork=allow_fork)
    if not plan["can_import"]:
        if plan["record_capacity"]["exceeded"]:
            raise ValueError("workspace project record capacity exceeded; no records imported")
        if any(item["status"] == "capacity_exceeded" for item in plan["results"]):
            raise ValueError("workspace origin has reached the 32-variant bound; no records imported")
        raise ValueError("workspace origin conflict; explicitly review or allow a preserved fork")
    results = []
    for item in capsule["records"]:
        payload = _shared_payload(capsule, item)
        identity = _key(payload["origin"])
        current, _, _ = _state(root, project_id)
        existing = current.get(identity, {})
        same = existing.get(item["content_hash"])
        if same is not None:
            results.append({"id": same["id"], "content_hash": same["content_hash"], "origin": payload["origin"],
                            "source_hash": item["content_hash"], "status": "unchanged"})
            continue

        def validate(conn: sqlite3.Connection, inserted: dict[str, Any]) -> None:
            # Inspect pre-insert history so duplicate attempts can roll back and
            # return the committed existing row, not poison the strict history.
            previous_variants, _, _ = _state(root, project_id, conn, exclude_id=inserted["id"])
            previous = previous_variants.get(identity, {})
            identical = previous.get(item["content_hash"])
            if identical is not None:
                raise _AlreadyImported(identical)
            if previous and not allow_fork:
                raise ValueError("workspace origin changed concurrently; import stopped without overwrite")
            if len(previous) >= 32:
                raise ValueError("workspace origin has reached the 32-variant bound")
            _state(root, project_id, conn)

        try:
            record = append_record(root, project_id=project_id, session_id=session_id, kind="shared_knowledge", payload=payload, validate=validate)
            status = "forked" if existing else "imported"
        except _AlreadyImported as same_import:
            record, status = same_import.row, "unchanged"
        results.append({"id": record["id"], "content_hash": record["content_hash"], "origin": payload["origin"],
                        "source_hash": item["content_hash"], "status": status})
    return {"schema_version": 1, "project_id": project_id, "snapshot_hash": expected_snapshot_hash,
            "results": results, "imported": sum(item["status"] != "unchanged" for item in results),
            "unchanged": sum(item["status"] == "unchanged" for item in results), "activated": False,
            "instruction_authority": "none"}


def resolve_workspace_conflict(
    root: Path, *, project_id: str, session_id: str, origin: dict[str, str], variant_hashes: list[str],
    selected_hash: str, reviewer: str, reason: str, expected_decision_id: str | None = None,
) -> dict[str, Any]:
    """Record a selection against the exact variant set/head, retaining all data."""
    project_id = _project(root, project_id)
    origin = _origin(origin)
    if type(variant_hashes) is not list or not 2 <= len(variant_hashes) <= 32:
        raise ValueError("variant_hashes must name 2 to 32 exact variants")
    hashes = sorted(_hash(item) for item in variant_hashes)
    if len(hashes) != len(set(hashes)) or _hash(selected_hash) not in hashes:
        raise ValueError("variant hashes must be unique and contain selected_hash")
    require_text(reviewer, "reviewer", 128)
    require_text(reason, "reason", 2000)
    if expected_decision_id is not None:
        _identifier(expected_decision_id, "expected_decision_id")
    payload = {"schema": 1, "origin": origin, "variant_hashes": hashes, "selected_hash": selected_hash,
               "reviewer": reviewer, "reason": reason, "previous_decision_id": expected_decision_id}
    variants, decisions, _ = _state(root, project_id)
    current = decisions.get(_key(origin))
    if set(variants.get(_key(origin), {})) != set(hashes):
        raise ValueError("workspace decision requires the exact current variant set")
    if expected_decision_id != (None if current is None else current["id"]):
        raise ValueError("workspace decision head changed")

    def validate(conn: sqlite3.Connection, inserted: dict[str, Any]) -> None:
        _state(root, project_id, conn)

    return append_record(root, project_id=project_id, session_id=session_id, kind="workspace_decision", payload=payload, validate=validate)


def _link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024))


def _directory(value: Path | str) -> Path:
    if not isinstance(value, (str, Path)) or not Path(value).is_absolute():
        raise ValueError("an explicit absolute directory is required")
    path = Path(value)
    try:
        for entry in (path, *path.parents):
            info = entry.lstat()
            if _link(info) or not stat.S_ISDIR(info.st_mode):
                raise ValueError("directory must not traverse links or reparse points")
        return path.resolve(strict=True)
    except OSError:
        raise ValueError("directory is not available") from None


def _read_file(path: Path, maximum: int) -> bytes:
    _directory(path.parent)
    try:
        before = path.lstat()
        if _link(before) or not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError("experiment file must be a bounded regular non-link file")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError("experiment file changed while opening")
            raw = stream.read(maximum + 1)
            after = os.fstat(stream.fileno())
        final = path.lstat()
        _directory(path.parent)
        if (len(raw) > maximum or _link(final) or (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino)
                or (after.st_size, after.st_mtime_ns) != (opened.st_size, opened.st_mtime_ns)
                or (final.st_size, final.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
            raise ValueError("experiment file changed while reading")
        return raw
    except OSError:
        raise ValueError("experiment file is unavailable") from None


def create_memory_experiment(
    root: Path, *, project_id: str, record_ids: list[str], workspace_id: str, destination: Path | str,
) -> dict[str, Any]:
    """Create a new isolated working root and immutable hash-bound seed snapshot."""
    source = _directory(root)
    if not isinstance(destination, (Path, str)) or not Path(destination).is_absolute():
        raise ValueError("destination must be an explicit absolute new directory")
    requested = Path(destination)
    parent = _directory(requested.parent)
    target = parent / requested.name
    if target.exists() or target.is_symlink() or target.is_relative_to(source) or source.is_relative_to(target):
        raise ValueError("experiment destination must be new and disjoint from its source")
    capsule = export_workspace(source, project_id=project_id, record_ids=record_ids, workspace_id=workspace_id)
    # Internal aliases are valid only in their owning catalog. Select a stable,
    # ordinary destination partition without copying the source alias table/key
    # or persisting the caller's possibly credential-bearing external spelling.
    seed_project = capsule["source_project"]
    try:
        validate_partition_identifier("project_id", seed_project)
    except ValueError:
        seed_project = "workspace-" + hashlib.sha256(seed_project.encode("utf-8")).hexdigest()[:24]
    plan_workspace_import(target, project_id=seed_project, capsule=capsule, expected_snapshot_hash=capsule["snapshot_hash"])
    target.mkdir(exist_ok=False)
    config = default_config()
    config["capture"]["mode"] = "manual"
    config["capture"]["dedup_window_seconds"] = 0
    config["local_inference"]["enabled"] = False
    write_config(target, config)
    init_db(target)
    imported = import_workspace(target, project_id=seed_project, session_id="workspace-seed", capsule=capsule,
                                expected_snapshot_hash=capsule["snapshot_hash"])
    evidence = target / ".experiment"
    evidence.mkdir(exist_ok=False)
    snapshot = evidence / "snapshot.sqlite3"
    with closing(connect_existing(target)) as src, closing(sqlite3.connect(snapshot)) as dst:
        src.backup(dst)
    raw = _read_file(snapshot, _MAX_SNAPSHOT)
    config_raw = _read_file(config_path(target), _MAX_CAPSULE)
    mapping = []
    sources = {item["id"]: item for item in capsule["records"]}
    for item in imported["results"]:
        original = sources[item["origin"]["record_id"]]
        mapping.append({"id": item["id"], "content_hash": item["content_hash"],
                        "source": {"project_id": capsule["source_project"], "kind": "scroll_event",
                                   "id": original["id"], "content_hash": original["content_hash"]}})
    manifest = {"schema": _EXPERIMENT, "workspace_id": workspace_id, "project_id": imported["project_id"],
                "source_project": capsule["source_project"],
                "capsule_hash": capsule["snapshot_hash"], "snapshot_sha256": hashlib.sha256(raw).hexdigest(),
                "snapshot_bytes": len(raw), "config_sha256": hashlib.sha256(config_raw).hexdigest(), "mapping": mapping}
    for name, content in (("capsule.json", _json(capsule)), ("config.json", config_raw), ("manifest.json", _json(manifest))):
        with (evidence / name).open("xb") as stream:
            stream.write(content)
    return {"schema_version": 1, "experiment_root": str(target), "manifest_sha256": _digest(manifest),
            "project_id": imported["project_id"], "source_project": capsule["source_project"],
            "snapshot_sha256": manifest["snapshot_sha256"], "capsule_hash": capsule["snapshot_hash"],
            "seeded": len(mapping), "mapping": mapping, "provider_used": False, "source_mutated": False}


def _experiment(experiment_root: Path | str, expected_manifest_hash: str) -> tuple[dict, dict, bytes, bytes]:
    root = _directory(experiment_root)
    evidence = _directory(root / ".experiment")
    manifest = _load(_read_file(evidence / "manifest.json", _MAX_CAPSULE))
    if _digest(manifest) != _hash(expected_manifest_hash):
        raise ValueError("experiment manifest hash mismatch")
    if type(manifest) is not dict or set(manifest) != {"schema", "workspace_id", "project_id", "source_project", "capsule_hash", "snapshot_sha256", "snapshot_bytes", "config_sha256", "mapping"}:
        raise ValueError("invalid experiment manifest")
    if manifest["schema"] != _EXPERIMENT:
        raise ValueError("unsupported experiment manifest")
    _identifier(manifest["workspace_id"], "workspace_id")
    require_text(manifest["project_id"], "project_id", 256)
    require_text(manifest["source_project"], "source_project", 256)
    capsule = _capsule(_load(_read_file(evidence / "capsule.json", _MAX_CAPSULE)), manifest["capsule_hash"])
    # The source's persisted alias and the isolated destination partition are
    # distinct authorities. Never interpret a source-local alias in a new root.
    if capsule["workspace_id"] != manifest["workspace_id"] or capsule["source_project"] != manifest["source_project"]:
        raise ValueError("experiment capsule authority mismatch")
    snapshot = _read_file(evidence / "snapshot.sqlite3", _MAX_SNAPSHOT)
    config = _read_file(evidence / "config.json", _MAX_CAPSULE)
    if (type(manifest["snapshot_bytes"]) is not int or manifest["snapshot_bytes"] != len(snapshot)
            or hashlib.sha256(snapshot).hexdigest() != _hash(manifest["snapshot_sha256"])
            or hashlib.sha256(config).hexdigest() != _hash(manifest["config_sha256"])):
        raise ValueError("experiment frozen artifact hash mismatch")
    mapping = manifest["mapping"]
    if type(mapping) is not list or len(mapping) != len(capsule["records"]):
        raise ValueError("experiment mapping does not cover its seed")
    original = {item["id"]: item["content_hash"] for item in capsule["records"]}
    ids, sources = set(), set()
    for row in mapping:
        if type(row) is not dict or set(row) != {"id", "content_hash", "source"}:
            raise ValueError("invalid experiment mapping")
        _identifier(row["id"], "experiment record_id")
        _hash(row["content_hash"])
        reference = row["source"]
        if (type(reference) is not dict or set(reference) != {"project_id", "kind", "id", "content_hash"}
                or reference["project_id"] != capsule["source_project"] or reference["kind"] != "scroll_event"
                or type(reference["id"]) is not str or original.get(reference["id"]) != reference["content_hash"]
                or row["id"] in ids or reference["id"] in sources):
            raise ValueError("invalid original source mapping")
        ids.add(row["id"])
        sources.add(reference["id"])
    return manifest, capsule, snapshot, config


def replay_memory_experiment(
    experiment_root: Path | str, *, queries: list[str], expected_manifest_hash: str,
    limit: int = 8, token_budget: int = 2400,
) -> dict[str, Any]:
    """Replay actual recall over a disposable frozen copy, never the mutable root."""
    if type(queries) is not list or not 1 <= len(queries) <= 16:
        raise ValueError("queries must contain 1 to 16 explicit queries")
    queries = [require_text(query, "query", 1024) for query in queries]
    if len(set(queries)) != len(queries):
        raise ValueError("queries must be unique")
    if type(limit) is not int or not 1 <= limit <= 32 or type(token_budget) is not int or not 512 <= token_budget <= 32768:
        raise ValueError("invalid replay limit or token budget")
    manifest, capsule, snapshot, config = _experiment(experiment_root, expected_manifest_hash)
    mapping = {item["id"]: item for item in manifest["mapping"]}
    outputs = []
    with tempfile.TemporaryDirectory(prefix="continuum-memory-replay-") as temporary:
        root = Path(temporary)
        (root / "catalog").mkdir()
        (root / "config").mkdir()
        (root / "catalog" / "catalog.sqlite3").write_bytes(snapshot)
        config_path(root).write_bytes(config)
        actual = read_records(root, project_id=manifest["project_id"])
        if {row["id"]: row["content_hash"] for row in actual} != {key: value["content_hash"] for key, value in mapping.items()}:
            raise ValueError("frozen catalog does not match its seed mapping")
        for row in actual:
            reference = mapping[row["id"]]["source"]
            expected_origin = {"workspace_id": capsule["workspace_id"], "project_id": reference["project_id"], "record_id": reference["id"]}
            if (row["kind"] != "shared_knowledge" or row["payload"].get("origin") != expected_origin
                    or row["payload"].get("source_hash") != reference["content_hash"]):
                raise ValueError("frozen catalog original provenance does not match its mapping")
        # Strict shared-history validation also rechecks the nested exact hashes.
        variants, _, _ = _state(root, manifest["project_id"])
        if sum(len(items) for items in variants.values()) != len(mapping):
            raise ValueError("frozen catalog contains unexpected imported variants")
        for query in queries:
            packet = recall_memory(root, project_id=manifest["project_id"], query=query, limit=limit, token_budget=token_budget)
            selected = []
            for rank, result in enumerate(packet["results"], 1):
                item = mapping.get(result["id"])
                if result["kind"] != "scroll_event" or item is None or item["content_hash"] != result["content_hash"]:
                    raise ValueError("replay produced an unattributed source")
                selected.append({"rank": rank, "source": item["source"], "score": result["score"]})
            outputs.append({"query_hash": packet["query_hash"], "packet_hash": _digest(packet),
                            "result_hash": _digest(selected), "results": selected, "abstained": packet["abstained"]})
    result = {"schema": _REPLAY, "manifest_hash": expected_manifest_hash, "snapshot_hash": manifest["snapshot_sha256"],
              "capsule_hash": capsule["snapshot_hash"], "options": {"limit": limit, "token_budget": token_budget},
              "queries": outputs, "provider_used": False, "instruction_authority": "none"}
    result["replay_hash"] = _digest(result)
    return result


def _replay(value: Any) -> dict[str, Any]:
    result = _load(_json(value))
    if (type(result) is not dict or set(result) != {"schema", "manifest_hash", "snapshot_hash", "capsule_hash", "options", "queries", "provider_used", "instruction_authority", "replay_hash"}
            or result["schema"] != _REPLAY or result["provider_used"] is not False or result["instruction_authority"] != "none"
            or _digest({key: item for key, item in result.items() if key != "replay_hash"}) != _hash(result["replay_hash"])):
        raise ValueError("invalid replay evidence")
    for field in ("manifest_hash", "snapshot_hash", "capsule_hash"):
        _hash(result[field])
    options = result["options"]
    if (type(options) is not dict or set(options) != {"limit", "token_budget"}
            or type(options["limit"]) is not int or not 1 <= options["limit"] <= 32
            or type(options["token_budget"]) is not int or not 512 <= options["token_budget"] <= 32768):
        raise ValueError("invalid replay options")
    queries = result["queries"]
    if type(queries) is not list or not 1 <= len(queries) <= 16:
        raise ValueError("invalid replay query set")
    seen = set()
    for query in queries:
        if type(query) is not dict or set(query) != {"query_hash", "packet_hash", "result_hash", "results", "abstained"}:
            raise ValueError("invalid replay query")
        key = _hash(query["query_hash"])
        if key in seen:
            raise ValueError("duplicate replay query")
        seen.add(key)
        _hash(query["packet_hash"])
        if (type(query["results"]) is not list or len(query["results"]) > options["limit"]
                or type(query["abstained"]) is not bool or query["abstained"] != (not query["results"])
                or _digest(query["results"]) != _hash(query["result_hash"])):
            raise ValueError("invalid replay result set")
        found = set()
        for rank, row in enumerate(query["results"], 1):
            if (type(row) is not dict or set(row) != {"rank", "source", "score"}
                    or type(row["rank"]) is not int or row["rank"] != rank
                    or type(row["score"]) not in (float, int) or not 0 <= row["score"] <= 1):
                raise ValueError("invalid replay rank")
            source = row["source"]
            if type(source) is not dict or set(source) != {"project_id", "kind", "id", "content_hash"} or source["kind"] != "scroll_event":
                raise ValueError("invalid replay source")
            require_text(source["project_id"], "source project", 256)
            _identifier(source["id"], "source id")
            _hash(source["content_hash"])
            identity = (source["project_id"], source["id"], source["content_hash"])
            if identity in found:
                raise ValueError("duplicate replay source")
            found.add(identity)
    return result


def compare_experiment_replays(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Compare fixed evidence; score/rank differences are not quality judgements."""
    before, after = _replay(before), _replay(after)
    old, new = {row["query_hash"]: row for row in before["queries"]}, {row["query_hash"]: row for row in after["queries"]}
    if set(old) != set(new) or before["options"] != after["options"]:
        raise ValueError("comparisons require identical query hashes and retrieval options")
    outputs = []
    for query_hash in sorted(old):
        prior = {(row["source"]["project_id"], row["source"]["id"], row["source"]["content_hash"]): row for row in old[query_hash]["results"]}
        current = {(row["source"]["project_id"], row["source"]["id"], row["source"]["content_hash"]): row for row in new[query_hash]["results"]}
        changes = [{"source": (prior.get(key) or current[key])["source"],
                    "before_rank": None if key not in prior else prior[key]["rank"],
                    "after_rank": None if key not in current else current[key]["rank"]}
                   for key in sorted(set(prior) | set(current))
                   if key not in prior or key not in current or prior[key]["rank"] != current[key]["rank"]]
        outputs.append({"query_hash": query_hash, "rank_changes": changes,
                        "packet_changed": old[query_hash]["packet_hash"] != new[query_hash]["packet_hash"],
                        "results_changed": old[query_hash]["result_hash"] != new[query_hash]["result_hash"]})
    return {"schema_version": 1, "before_hash": before["replay_hash"], "after_hash": after["replay_hash"],
            "queries": outputs, "quality_judgement": "not_evaluated", "instruction_authority": "none"}


def adopt_experiment_records(
    experiment_root: Path | str, *, record_ids: list[str], target_root: Path, project_id: str,
    session_id: str, workspace_id: str, expected_manifest_hash: str, allow_fork: bool = False,
) -> dict[str, Any]:
    """Adopt explicitly selected working-root records as inert evidence only."""
    manifest, _, _, _ = _experiment(experiment_root, expected_manifest_hash)
    source = _directory(experiment_root)
    capsule = export_workspace(source, project_id=manifest["project_id"], record_ids=record_ids, workspace_id=workspace_id)
    return import_workspace(target_root, project_id=project_id, session_id=session_id, capsule=capsule,
                            expected_snapshot_hash=capsule["snapshot_hash"], allow_fork=allow_fork)
