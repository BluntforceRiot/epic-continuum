"""Project-scoped asserted facts with valid-time and as-known correction history.

These are recorded claims, not automatically inferred truth. A correction replaces
an entire earlier assertion from its recording time onward; no interval splitting
is inferred. Independent differing assertions remain disagreements. Recorded time
uses the Scroll's seconds precision, with insertion order breaking internal ties:
an as-known timestamp at that second necessarily includes every recorded tie.
"""
from __future__ import annotations

import re
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .knowledge_records import (
    append_record,
    bounded_results,
    read_records,
    require_text,
    require_timestamp,
    validate_evidence,
)
from .safety import scan_value_for_secrets

FACT_KIND = "temporal_fact"
_PAYLOAD_KEYS = {
    "schema", "subject", "predicate", "value", "valid_from", "valid_to", "corrects", "evidence",
}
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _instant(value: Any, name: str) -> tuple[str, datetime]:
    canonical = require_timestamp(value, name)
    return canonical, datetime.fromisoformat(canonical.replace("Z", "+00:00"))


def _identifier(value: Any, name: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} must be a portable identifier of at most 128 characters")
    return value


def _evidence_shape(value: Any) -> None:
    if type(value) is not list or len(value) > 16:
        raise ValueError("fact evidence must be a list of at most 16 exact source references")
    seen: set[tuple[str, str]] = set()
    for reference in value:
        if type(reference) is not dict or set(reference) != {"kind", "id", "content_hash"}:
            raise ValueError("fact evidence must contain exact source references")
        kind = reference["kind"]
        if type(kind) is not str or kind not in {"card", "scroll_event", "chunk"}:
            raise ValueError("fact evidence has an invalid source kind")
        source_id = _identifier(reference["id"], "fact evidence id")
        digest = reference["content_hash"]
        if type(digest) is not str or _SHA256.fullmatch(digest) is None:
            raise ValueError("fact evidence has an invalid content hash")
        if (kind, source_id) in seen:
            raise ValueError("fact evidence contains a duplicate source")
        seen.add((kind, source_id))


def _payload(value: Any) -> dict[str, Any]:
    """Validate stored records too; a filter must not conceal malformed history."""
    if type(value) is not dict or set(value) != _PAYLOAD_KEYS:
        raise ValueError("invalid temporal fact payload")
    if type(value["schema"]) is not int or value["schema"] != 1:
        raise ValueError("unsupported temporal fact schema")
    for field, limit in (("subject", 256), ("predicate", 128), ("value", 2048)):
        if require_text(value[field], field, max_chars=limit) != value[field]:
            raise ValueError(f"stored fact {field} is not canonical")
    if (scan_value_for_secrets(value, scope="fact")
            or scan_value_for_secrets({value["predicate"]: value["value"]}, scope="fact")):
        raise ValueError("temporal facts must not contain credentials")
    start, start_at = _instant(value["valid_from"], "valid_from")
    if start != value["valid_from"]:
        raise ValueError("stored fact valid_from is not canonical")
    if value["valid_to"] is not None:
        end, end_at = _instant(value["valid_to"], "valid_to")
        if end != value["valid_to"] or end_at <= start_at:
            raise ValueError("valid_to must be canonical and later than valid_from")
    if value["corrects"] is not None:
        _identifier(value["corrects"], "corrects")
    _evidence_shape(value["evidence"])
    return value


def _validated(records: list[dict[str, Any]]) -> dict[str, str]:
    """Check complete visible shape/topology, including facts outside query filters."""
    earlier: dict[str, dict[str, Any]] = {}
    corrected_by: dict[str, str] = {}
    previous_order: tuple[datetime, int] | None = None
    for record in records:
        payload = _payload(record["payload"])
        source_id = _identifier(record["id"], "fact id")
        _, recorded_at = _instant(record["recorded_at"], "recorded_at")
        order = record["order"]
        if type(order) is not int or order < 1:
            raise ValueError("invalid temporal fact insertion order")
        current_order = (recorded_at, order)
        if source_id in earlier or (previous_order is not None and current_order <= previous_order):
            raise ValueError("invalid temporal fact recording order")
        previous_order = current_order
        target_id = payload["corrects"]
        if target_id is not None:
            target = earlier.get(target_id)
            if target is None or target_id in corrected_by:
                raise ValueError("correction target must be an earlier uncorrected fact in this project")
            target_payload = target["payload"]
            if (target["project_id"] != record["project_id"]
                    or target_payload["subject"] != payload["subject"]
                    or target_payload["predicate"] != payload["predicate"]):
                raise ValueError("correction target must have the same project, subject, and predicate")
            # The read order is recorded time followed by rowid; require actual
            # earlier insertion as well, so a corrupt/backdated row cannot win.
            if target["order"] >= order:
                raise ValueError("correction target must be an earlier insertion")
            corrected_by[target_id] = source_id
        earlier[source_id] = record
    return corrected_by


def record_temporal_fact(
    root: Path, *, project_id: str, session_id: str, subject: str, predicate: str,
    value: str, valid_from: str, valid_to: str | None = None,
    corrects: str | None = None, evidence: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Append one explicit claim, atomically validating corrections before commit.

    Concurrent corrections of the same target serialize in the existing Scroll
    writer transaction: exactly one may replace a current leaf. Independent
    assertions are never silently overwritten or assigned a winner.
    """
    start, start_at = _instant(valid_from, "valid_from")
    end = None
    if valid_to is not None:
        end, end_at = _instant(valid_to, "valid_to")
        if end_at <= start_at:
            raise ValueError("valid_to must be later than valid_from")
    if corrects is not None:
        corrects = _identifier(corrects, "corrects")
    payload = {
        "schema": 1,
        "subject": require_text(subject, "subject", max_chars=256),
        "predicate": require_text(predicate, "predicate", max_chars=128),
        "value": require_text(value, "value", max_chars=2048),
        "valid_from": start,
        "valid_to": end,
        "corrects": corrects,
        "evidence": validate_evidence(root, project_id, evidence),
    }
    _payload(payload)

    def validate(conn: sqlite3.Connection, record: dict[str, Any]) -> None:
        records = read_records(root, project_id=project_id, kinds=[FACT_KIND], connection=conn)
        _validated(records)
        if not any(item["id"] == record["id"] for item in records):
            raise ValueError("new temporal fact is not visible in its project transaction")

    return append_record(
        root, project_id=project_id, session_id=session_id,
        kind=FACT_KIND, payload=payload, validate=validate,
    )


def query_temporal_facts(
    root: Path, *, project_id: str, subject: str | None = None,
    predicate: str | None = None, valid_at: str | None = None,
    known_at: str | None = None, include_history: bool = False, token_budget: int = 2400,
) -> dict[str, Any]:
    """Return bounded claims, with no model calls, writes, or inferred truth.

    Current results are uncorrected as of known_at and valid at valid_at, using
    half-open validity intervals. History includes all claims known at known_at
    for the selectors, even corrected/expired claims, and labels both states.
    Both forms are newest-recorded first. Disagreement flags refer to current,
    applicable assertions with the same subject/predicate but differing values.
    """
    if type(include_history) is not bool:
        raise ValueError("include_history must be a boolean")
    if subject is not None:
        subject = require_text(subject, "subject", max_chars=256)
    if predicate is not None:
        predicate = require_text(predicate, "predicate", max_chars=128)
    now = datetime.now(timezone.utc).isoformat()
    valid_text, valid_instant = _instant(now if valid_at is None else valid_at, "valid_at")
    known_text, known_instant = _instant(now if known_at is None else known_at, "known_at")
    records = read_records(root, project_id=project_id, kinds=[FACT_KIND])
    _validated(records)
    known = [item for item in records if _instant(item["recorded_at"], "recorded_at")[1] <= known_instant]
    corrected = {item["payload"]["corrects"]: item["id"] for item in known
                 if item["payload"]["corrects"] is not None}

    def valid(payload: dict[str, Any]) -> bool:
        return (_instant(payload["valid_from"], "valid_from")[1] <= valid_instant
                and (payload["valid_to"] is None
                     or valid_instant < _instant(payload["valid_to"], "valid_to")[1]))

    values: dict[tuple[str, str], set[str]] = defaultdict(set)
    for item in known:
        payload = item["payload"]
        if item["id"] not in corrected and valid(payload):
            values[(payload["subject"], payload["predicate"])].add(payload["value"])
    results: list[dict[str, Any]] = []
    for item in reversed(known):
        payload = item["payload"]
        if ((subject is not None and payload["subject"] != subject)
                or (predicate is not None and payload["predicate"] != predicate)):
            continue
        applicable = valid(payload)
        replacement = corrected.get(item["id"])
        if not include_history and (replacement is not None or not applicable):
            continue
        results.append({
            "id": item["id"], "project_id": item["project_id"],
            "recorded_at": item["recorded_at"], **payload,
            "correction_state": "corrected" if replacement is not None else "current",
            "corrected_by": replacement, "valid_at_matches": applicable,
            "disagreement": replacement is None and applicable
            and len(values[(payload["subject"], payload["predicate"])]) > 1,
            "citation": {"kind": "scroll_event", "id": item["id"], "content_hash": item["content_hash"]},
        })
    return bounded_results(results, token_budget=token_budget, extra={
        "valid_at": valid_text, "known_at": known_text, "include_history": include_history,
        "semantics": "recorded_claims; half_open_valid_time; whole_assertion_corrections",
    })
