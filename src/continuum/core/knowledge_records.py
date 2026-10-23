"""Bounded project knowledge on the existing append-only Scroll authority.

This is a typed evidence codec, not another catalog or an inference authority.
Mutations use the normal capture transaction, writer claim and secret policy.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .recall import read_memory_source
from .safety import scan_text_for_secrets, scan_value_for_secrets
from .store import (
    _metadata_scope_visible,
    append_scroll_event,
    canonical_partition_identifier,
    connect_existing,
    is_initialized,
)

SCHEMA = "continuum.knowledge.v1"
EVENT_TYPE = "knowledge_record"
KINDS = frozenset({
    "temporal_fact", "project_file", "project_knowledge",
    "analysis_asset", "analysis_finding", "media_annotation", "notebook_entry",
    "experience", "procedure", "procedure_review",
    "handoff", "handoff_transition", "collection", "collection_revision",
    "shared_knowledge", "workspace_decision",
})
MAX_RECORD_BYTES = 65536
Record = dict[str, Any]
Validator = Callable[[sqlite3.Connection, Record], None]


def require_text(value: object, name: str, max_chars: int = 1024) -> str:
    if type(value) is not str or not value.strip() or len(value) > max_chars:
        raise ValueError(f"{name} must contain nonempty bounded text")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{name} must be valid UTF-8 text") from None
    if "\x00" in value:
        raise ValueError(f"{name} must not contain NUL")
    return value


def require_timestamp(value: object, name: str) -> str:
    text = require_text(value, name, 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError):
        raise ValueError(f"{name} must be an ISO-8601 timestamp with UTC offset") from None


def _plain(value: object, *, depth: int = 0, count: list[int] | None = None) -> None:
    if count is None:
        count = [0]
    count[0] += 1
    if depth > 16 or count[0] > 16384:
        raise ValueError("knowledge structure exceeds its bounds")
    if value is None or type(value) is bool:
        return
    if type(value) is str:
        if len(value) > MAX_RECORD_BYTES:
            raise ValueError("knowledge text exceeds its bounds")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("knowledge text must be valid UTF-8") from None
        return
    if type(value) is int:
        if abs(value) > 2**63 - 1:
            raise ValueError("knowledge integer exceeds its bounds")
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is dict:
        if len(value) > 4096 or any(type(key) is not str for key in value):
            raise ValueError("knowledge object must have bounded string keys")
        for key, item in value.items():
            _plain(key, depth=depth + 1, count=count)
            _plain(item, depth=depth + 1, count=count)
        return
    if type(value) is list and len(value) <= 4096:
        for item in value:
            _plain(item, depth=depth + 1, count=count)
        return
    raise ValueError("knowledge must contain only bounded plain JSON values")


def _encode(value: dict[str, Any]) -> str:
    _plain(value)
    text = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    if len(text.encode("utf-8")) > MAX_RECORD_BYTES:
        raise ValueError("knowledge record exceeds 65536 UTF-8 bytes")
    return text


def _scope(root: Path, project_id: str) -> str:
    require_text(project_id, "project_id", 256)
    canonical = canonical_partition_identifier(root, "project_id", project_id, lookup=True)
    if not canonical:
        raise ValueError("project_id is required")
    return canonical


def _decode(row: sqlite3.Row, project_id: str) -> Record:
    text = row["content"]
    if type(text) is not str or len(text.encode("utf-8")) > MAX_RECORD_BYTES:
        raise ValueError("stored knowledge record is malformed")
    try:
        value, metadata = json.loads(text), json.loads(row["metadata_json"])
        valid = (
            type(value) is dict
            and set(value) == {"schema", "kind", "project_id", "nonce", "payload"}
            and value["schema"] == SCHEMA
            and type(value["kind"]) is str and value["kind"] in KINDS
            and value["project_id"] == project_id
            and type(value["nonce"]) is str and re.fullmatch(r"[0-9a-f]{32}", value["nonce"]) is not None
            and type(value["payload"]) is dict
            and type(metadata) is dict
            and metadata.get("knowledge_schema") == SCHEMA
            and _metadata_scope_visible(metadata, candidate_session_id=row["session_id"], project_id=project_id)
            and row["content_hash"] == hashlib.sha256(text.encode("utf-8")).hexdigest()
        )
        if not valid:
            raise ValueError
        _encode(value)
        recorded_at = require_timestamp(row["created_at"], "stored recorded_at")
    except (KeyError, TypeError, ValueError, RecursionError, OverflowError):
        raise ValueError("stored knowledge record is malformed") from None
    return {
        "id": row["id"], "session_id": row["session_id"], "project_id": project_id,
        "recorded_at": recorded_at, "kind": value["kind"], "payload": value["payload"],
        "content_hash": row["content_hash"], "order": int(row["knowledge_order"]),
    }


def read_records(
    root: Path, *, project_id: str, kinds: tuple[str, ...] | list[str] | None = None,
    connection: sqlite3.Connection | None = None, max_records: int = 10000,
) -> list[Record]:
    """Read complete visible typed evidence, or fail instead of hiding history.

    The count limit applies to all typed records in the project. Kind selection
    happens only after envelope validation, so corruption cannot hide a revision.
    Existing Scroll timestamps have seconds precision; ``order`` breaks ties.
    """
    project = _scope(root, project_id)
    if type(max_records) is not int or not 1 <= max_records <= 100000:
        raise ValueError("max_records must be an integer from 1 to 100000")
    if kinds is not None and (type(kinds) not in (tuple, list) or any(type(kind) is not str or kind not in KINDS for kind in kinds)):
        raise ValueError("unsupported knowledge kind")
    if connection is None and not is_initialized(root):
        return []
    conn = connection if connection is not None else connect_existing(root)
    try:
        rows = conn.execute(
            """SELECT rowid AS knowledge_order, * FROM scroll_events
               WHERE event_type=? AND visibility_scope='project' AND project_id=?
               ORDER BY created_at, rowid LIMIT ?""", (EVENT_TYPE, project, max_records + 1),
        ).fetchall()
        if len(rows) > max_records:
            raise ValueError("project knowledge exceeds the requested read bound")
        records = [_decode(row, project) for row in rows]
        return [record for record in records if kinds is None or record["kind"] in kinds]
    finally:
        if connection is None:
            conn.close()


def append_record(
    root: Path, *, project_id: str, session_id: str, kind: str,
    payload: dict[str, Any], validate: Validator | None = None,
) -> Record:
    project = _scope(root, project_id)
    require_text(session_id, "session_id", 256)
    if type(kind) is not str or kind not in KINDS or type(payload) is not dict:
        raise ValueError("unsupported knowledge record")
    envelope = {"schema": SCHEMA, "kind": kind, "project_id": project,
                "nonce": uuid.uuid4().hex, "payload": payload}
    text = _encode(envelope)
    # Typed records cannot safely accept text-only redaction that invalidates
    # their embedded hashes/links. Reject before capture even on a redacting root.
    if scan_value_for_secrets(envelope, scope="knowledge", max_findings=1) or scan_text_for_secrets(text, max_findings=1):
        raise ValueError("credential-like material is not permitted in knowledge records")
    result: Record = {}

    def effect(conn: sqlite3.Connection, event: dict[str, Any]) -> None:
        row = conn.execute("SELECT rowid AS knowledge_order, * FROM scroll_events WHERE id=?", (event["event_id"],)).fetchone()
        if row is None:
            raise ValueError("knowledge capture is missing")
        record = _decode(row, project)
        if record["payload"] != payload or record["kind"] != kind:
            raise ValueError("knowledge capture changed the structured evidence")
        if validate is not None:
            validate(conn, record)
        result.update(record)

    append_scroll_event(
        root, session_id=session_id, event_type=EVENT_TYPE, role="agent", content=text,
        metadata={"project_id": project, "visibility_scope": "project", "knowledge_schema": SCHEMA,
                  "instruction_authority": "none", "trust_level": "recorded_claim_not_verified_truth"},
        transaction_effect=effect,
    )
    return result


def validate_evidence(root: Path, project_id: str, evidence: object) -> list[dict[str, str]]:
    project = _scope(root, project_id)
    if evidence is None:
        return []
    if type(evidence) is not list or len(evidence) > 16:
        raise ValueError("evidence must be an array of at most 16 exact source citations")
    result: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for item in evidence:
        if type(item) is not dict or set(item) != {"kind", "id", "content_hash"} or any(type(v) is not str for v in item.values()):
            raise ValueError("evidence must contain exact source citations")
        identity = (item["kind"], item["id"])
        if identity in seen:
            raise ValueError("evidence citations must be unique")
        found = read_memory_source(root, kind=item["kind"], source_id=item["id"],
                                   content_hash=item["content_hash"], project_id=project, limit=1)
        if not found["found"]:
            raise ValueError("evidence source is unavailable or changed")
        seen.add(identity)
        result.append(dict(item))
    return result


def bounded_results(
    records: list[Record], *, token_budget: int = 2400, extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if type(token_budget) is not int or not 512 <= token_budget <= 32768:
        raise ValueError("token_budget must be an integer from 512 to 32768")
    packet = dict(extra or {})
    packet.update(schema_version=1, instruction_authority="none", results=list(records),
                  matched_count=len(records), result_count=len(records), excluded_by_budget=0,
                  budget={"requested_tokens": token_budget, "estimated_tokens": 0,
                          "method": "compact_ascii_json_chars_div_4"})
    while True:
        for _ in range(8):
            size = len(json.dumps(packet, ensure_ascii=True, allow_nan=False, separators=(",", ":")))
            estimate = (size + 3) // 4
            if packet["budget"]["estimated_tokens"] == estimate:
                break
            packet["budget"]["estimated_tokens"] = estimate
        if size <= token_budget * 4:
            return packet
        if not packet["results"]:
            raise ValueError("token_budget cannot hold the knowledge envelope")
        packet["results"].pop()
        packet["result_count"] = len(packet["results"])
        packet["excluded_by_budget"] += 1
