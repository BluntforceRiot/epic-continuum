"""Local claimable handoffs and exact-source collections on typed Scroll.

Actor names record caller attribution; they are not authentication or remote
agent control. Leases use the local UTC wall clock and exact append-head CAS.
"""
from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timedelta, timezone
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
from .recall import read_memory_source
from .safety import scan_value_for_secrets

_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_HANDOFF_KINDS = ["handoff", "handoff_transition"]
_COLLECTION_KINDS = ["collection", "collection_revision"]
_ACTIONS = {"claim", "renew", "release", "complete"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _identifier(value: object, name: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} must be a portable identifier of at most 128 characters")
    return value


def _integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _texts(value: object, name: str, count: int) -> list[str]:
    if type(value) is not list or len(value) > count:
        raise ValueError(f"{name} must be a list of at most {count} text entries")
    return [require_text(item, name, 2048) for item in value]


def _citations(value: object) -> list[dict[str, str]]:
    if type(value) is not list or len(value) > 16:
        raise ValueError("members/evidence must contain at most 16 exact source citations")
    seen: set[tuple[str, str]] = set()
    for item in value:
        if type(item) is not dict or set(item) != {"kind", "id", "content_hash"}:
            raise ValueError("members/evidence require exact source citations")
        if type(item["kind"]) is not str or item["kind"] not in {"scroll_event", "card", "chunk"}:
            raise ValueError("invalid source kind")
        _identifier(item["id"], "source id")
        if type(item["content_hash"]) is not str or not _HASH.fullmatch(item["content_hash"]):
            raise ValueError("source content_hash must be lowercase SHA-256")
        key = (item["kind"], item["id"])
        if key in seen:
            raise ValueError("source citations must be unique")
        seen.add(key)
    return value


def _shape(value: object, keys: set[str]) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys or type(value.get("schema")) is not int or value["schema"] != 1:
        raise ValueError("invalid coordination record schema")
    if scan_value_for_secrets(value, scope="coordination"):
        raise ValueError("coordination records must not contain credentials")
    return value


def _instant(value: object, name: str) -> datetime:
    normalized = require_timestamp(value, name)
    if value != normalized:
        raise ValueError(f"{name} must be canonical UTC")
    return datetime.fromisoformat(normalized)


def _citation(record: dict[str, Any]) -> dict[str, str]:
    return {"kind": "scroll_event", "id": record["id"], "content_hash": record["content_hash"]}


def _ordered(records: list[dict[str, Any]]) -> None:
    prior = 0
    seen: set[str] = set()
    for record in records:
        _identifier(record["id"], "record id")
        order = record["order"]
        if type(order) is not int or order <= prior or record["id"] in seen:
            raise ValueError("coordination history has invalid append order")
        prior = order
        seen.add(record["id"])


def _handoff_payload(value: object) -> dict[str, Any]:
    p = _shape(value, {"schema", "objective", "actor", "accepted_decisions", "unfinished_work", "evidence"})
    require_text(p["objective"], "objective", 4096)
    require_text(p["actor"], "actor", 128)
    _texts(p["accepted_decisions"], "accepted_decisions", 16)
    _texts(p["unfinished_work"], "unfinished_work", 32)
    _citations(p["evidence"])
    return p


def _transition_payload(value: object) -> dict[str, Any]:
    p = _shape(value, {"schema", "handoff_id", "expected_head", "action", "actor", "occurred_at", "lease_seconds", "lease_until"})
    _identifier(p["handoff_id"], "handoff_id")
    _identifier(p["expected_head"], "expected_head")
    if type(p["action"]) is not str or p["action"] not in _ACTIONS:
        raise ValueError("unsupported handoff action")
    require_text(p["actor"], "actor", 128)
    moment = _instant(p["occurred_at"], "occurred_at")
    if p["action"] in {"claim", "renew"}:
        seconds = _integer(p["lease_seconds"], "lease_seconds", 1, 86400)
        expiry = _instant(p["lease_until"], "lease_until")
        if expiry != moment + timedelta(seconds=seconds):
            raise ValueError("handoff lease must match its bounded duration")
    elif p["lease_seconds"] is not None or p["lease_until"] is not None:
        raise ValueError("release and complete do not accept lease fields")
    return p


def _apply_transition(state: dict[str, Any], record: dict[str, Any]) -> None:
    p = _transition_payload(record["payload"])
    moment = _instant(p["occurred_at"], "occurred_at")
    if state["head"] != p["expected_head"]:
        raise ValueError("handoff head changed; read the current head before retrying")
    if state["status"] == "completed":
        raise ValueError("completed handoffs cannot be changed or reclaimed")
    if state["last_transition_at"] is not None and moment < state["last_transition_at"]:
        raise ValueError("handoff clock moved backwards")
    active = state["status"] == "claimed" and moment < state["lease_until"]
    if p["action"] == "claim":
        if active:
            raise ValueError("handoff already has an active owner")
    elif not active or state["owner"] != p["actor"]:
        raise ValueError("handoff transition requires its active lease owner")
    if p["action"] in {"claim", "renew"}:
        state.update(status="claimed", owner=p["actor"], lease_until=_instant(p["lease_until"], "lease_until"))
    else:
        state.update(status="completed" if p["action"] == "complete" else "open", owner=None, lease_until=None)
    state.update(head=record["id"], last_transition_at=moment)
    state["history"].append(record)


def _handoffs(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    _ordered(records)
    states: dict[str, dict[str, Any]] = {}
    for record in records:
        if record["kind"] == "handoff":
            _handoff_payload(record["payload"])
            states[record["id"]] = {
                "record": record, "head": record["id"], "status": "open", "owner": None,
                "lease_until": None, "last_transition_at": None, "history": [],
            }
        else:
            p = _transition_payload(record["payload"])
            state = states.get(p["handoff_id"])
            if state is None:
                raise ValueError("handoff transition has no earlier project-visible handoff")
            _apply_transition(state, record)
    return states


def create_handoff(
    root: Path, *, project_id: str, session_id: str, objective: str, actor: str,
    accepted_decisions: list[str] | None = None, unfinished_work: list[str] | None = None,
    evidence: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Capture resumable work, never send messages or execute the work itself."""
    payload = _handoff_payload({
        "schema": 1, "objective": objective, "actor": actor,
        "accepted_decisions": [] if accepted_decisions is None else accepted_decisions,
        "unfinished_work": [] if unfinished_work is None else unfinished_work,
        "evidence": validate_evidence(root, project_id, evidence),
    })

    def validate(conn: sqlite3.Connection, record: dict[str, Any]) -> None:
        states = _handoffs(read_records(root, project_id=project_id, kinds=_HANDOFF_KINDS, connection=conn))
        if record["id"] not in states:
            raise ValueError("new handoff is not visible in its project transaction")
        validate_evidence(root, project_id, payload["evidence"])

    return append_record(root, project_id=project_id, session_id=session_id, kind="handoff", payload=payload, validate=validate)


def transition_handoff(
    root: Path, *, project_id: str, session_id: str, handoff_id: str,
    expected_head: str, action: str, actor: str, lease_seconds: int | None = None,
) -> dict[str, Any]:
    """Append an exact-head CAS claim/renew/release/complete in one transaction.

    Expiry is half-open: at lease_until a different actor may claim the current
    head. A late old owner cannot renew, release or complete that expired lease.
    """
    moment = _now()
    if moment.tzinfo is None or moment.utcoffset() != timedelta(0):
        raise ValueError("handoff clock must be aware UTC")
    if type(action) is not str or action not in _ACTIONS:
        raise ValueError("unsupported handoff action")
    seconds = None
    expiry = None
    if action in {"claim", "renew"}:
        seconds = _integer(300 if lease_seconds is None else lease_seconds, "lease_seconds", 1, 86400)
        expiry = (moment + timedelta(seconds=seconds)).isoformat()
    elif lease_seconds is not None:
        raise ValueError("release and complete do not accept lease_seconds")
    payload = _transition_payload({
        "schema": 1, "handoff_id": handoff_id, "expected_head": expected_head,
        "action": action, "actor": actor, "occurred_at": moment.isoformat(),
        "lease_seconds": seconds, "lease_until": expiry,
    })

    def validate(conn: sqlite3.Connection, record: dict[str, Any]) -> None:
        records = read_records(root, project_id=project_id, kinds=_HANDOFF_KINDS, connection=conn)
        states = _handoffs(records)
        state = states.get(handoff_id)
        if state is None or state["head"] != record["id"]:
            raise ValueError("new transition is not the current project-visible head")
        current = _now()
        if current < moment:
            raise ValueError("handoff clock moved backwards while acquiring the writer")
        if action in {"claim", "renew"} and current >= state["lease_until"]:
            raise ValueError("lease expired before the transition could commit")
        if action != "claim":
            before = _handoffs([item for item in records if item["id"] != record["id"]])[handoff_id]
            if current >= before["lease_until"]:
                raise ValueError("owner lease expired before the transition could commit")

    return append_record(root, project_id=project_id, session_id=session_id,
                         kind="handoff_transition", payload=payload, validate=validate)


def query_handoffs(
    root: Path, *, project_id: str, handoff_id: str | None = None,
    include_history: bool = False, token_budget: int = 2400,
) -> dict[str, Any]:
    """Read lease state and current evidence availability, without mutations.

    Original references remain historical evidence. Their indexed state is
    checked against current scope/hash authority; lease ownership is independent
    of whether that historical support still exists or is accessible.
    """
    if handoff_id is not None:
        _identifier(handoff_id, "handoff_id")
    if type(include_history) is not bool:
        raise ValueError("include_history must be a boolean")
    states = _handoffs(read_records(root, project_id=project_id, kinds=_HANDOFF_KINDS))
    now = _now()
    results = []
    for identity, state in reversed(list(states.items())):
        if handoff_id is not None and identity != handoff_id:
            continue
        expired = state["status"] == "claimed" and now >= state["lease_until"]
        record = state["record"]
        evidence_states = []
        for index, reference in enumerate(record["payload"]["evidence"]):
            source = read_memory_source(
                root, project_id=project_id, kind=reference["kind"], source_id=reference["id"],
                content_hash=reference["content_hash"], limit=1,
            )
            evidence_states.append({
                "index": index, "source_state": "current" if source["found"] else "stale_or_unavailable",
            })
        unavailable = sum(row["source_state"] != "current" for row in evidence_states)
        item = {
            "id": identity, "project_id": record["project_id"], "head": state["head"],
            "status": "expired" if expired else state["status"],
            "owner": None if expired else state["owner"],
            "lease_until": state["lease_until"].isoformat() if state["lease_until"] else None,
            "recorded_at": record["recorded_at"], **record["payload"], "citation": _citation(record),
            "evidence_states": evidence_states, "unavailable_count": unavailable,
            "needs_review": bool(unavailable),
            "review_reasons": ["evidence_unavailable_or_changed"] if unavailable else [],
        }
        if include_history:
            item["history"] = [{"id": row["id"], **row["payload"], "citation": _citation(row)} for row in state["history"]]
        results.append(item)
    return bounded_results(results, token_budget=token_budget, extra={
        "observed_at": now.isoformat(), "actor_authority": "caller_attribution_not_authentication",
        "include_history": include_history,
        "source_validation": "current_project_scope_and_exact_content_hash",
    })


def _collection_payload(value: object, *, revision: bool) -> dict[str, Any]:
    keys = {"schema", "title", "summary", "overview", "members", "version"}
    if revision:
        keys |= {"collection_id", "expected_head"}
    p = _shape(value, keys)
    require_text(p["title"], "title", 256)
    require_text(p["summary"], "summary", 1024)
    require_text(p["overview"], "overview", 8192)
    _citations(p["members"])
    _integer(p["version"], "version", 1, 10000)
    if revision:
        _identifier(p["collection_id"], "collection_id")
        _identifier(p["expected_head"], "expected_head")
    elif p["version"] != 1:
        raise ValueError("new collections start at version one")
    return p


def _collections(records: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    _ordered(records)
    histories: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        revision = record["kind"] == "collection_revision"
        p = _collection_payload(record["payload"], revision=revision)
        if not revision:
            histories[record["id"]] = [record]
            continue
        history = histories.get(p["collection_id"])
        if not history or p["expected_head"] != history[-1]["id"]:
            raise ValueError("collection head changed or is not project-visible")
        if p["version"] != history[-1]["payload"]["version"] + 1:
            raise ValueError("collection revision must increment exactly one version")
        history.append(record)
    return histories


def create_collection(
    root: Path, *, project_id: str, session_id: str, title: str, summary: str,
    overview: str, members: list[dict[str, str]],
) -> dict[str, Any]:
    """Create a scoped explicit collection; no search or inferred membership."""
    _citations(members)
    payload = _collection_payload({"schema": 1, "title": title, "summary": summary,
        "overview": overview, "members": validate_evidence(root, project_id, members), "version": 1}, revision=False)

    def validate(conn: sqlite3.Connection, record: dict[str, Any]) -> None:
        histories = _collections(read_records(root, project_id=project_id, kinds=_COLLECTION_KINDS, connection=conn))
        if record["id"] not in histories:
            raise ValueError("new collection is not visible in its project transaction")
        validate_evidence(root, project_id, payload["members"])

    return append_record(root, project_id=project_id, session_id=session_id, kind="collection", payload=payload, validate=validate)


def revise_collection(
    root: Path, *, project_id: str, session_id: str, collection_id: str,
    expected_head: str, title: str, summary: str, overview: str, members: list[dict[str, str]],
) -> dict[str, Any]:
    """Replace the complete collection view with a retained, exact-head revision."""
    _identifier(collection_id, "collection_id")
    _identifier(expected_head, "expected_head")
    _citations(members)
    histories = _collections(read_records(root, project_id=project_id, kinds=_COLLECTION_KINDS))
    history = histories.get(collection_id)
    if not history or history[-1]["id"] != expected_head:
        raise ValueError("collection head changed or is not project-visible")
    payload = _collection_payload({"schema": 1, "title": title, "summary": summary, "overview": overview,
        "members": validate_evidence(root, project_id, members), "version": history[-1]["payload"]["version"] + 1,
        "collection_id": collection_id, "expected_head": expected_head}, revision=True)

    def validate(conn: sqlite3.Connection, record: dict[str, Any]) -> None:
        current = _collections(read_records(root, project_id=project_id, kinds=_COLLECTION_KINDS, connection=conn))
        if current[collection_id][-1]["id"] != record["id"]:
            raise ValueError("new collection revision is not its current project-visible head")
        validate_evidence(root, project_id, payload["members"])

    return append_record(root, project_id=project_id, session_id=session_id,
                         kind="collection_revision", payload=payload, validate=validate)


def query_collections(
    root: Path, *, project_id: str, collection_id: str | None = None, detail: str = "summary",
    include_history: bool = False, member_index: int | None = None, member_offset: int = 0,
    member_limit: int = 4000, token_budget: int = 2400,
) -> dict[str, Any]:
    """Browse summary/overview, then explicitly reveal current exact source text.

    Full text is paged with member_index/offset/limit, retaining source hashes.
    Missing, private, obsolete and changed citations are intentionally reported
    together; no unverified replacement text is returned.
    """
    if collection_id is not None:
        _identifier(collection_id, "collection_id")
    if type(detail) is not str or detail not in {"summary", "overview", "full"}:
        raise ValueError("detail must be summary, overview or full")
    if type(include_history) is not bool:
        raise ValueError("include_history must be a boolean")
    _integer(member_offset, "member_offset", 0, 2**63 - 1)
    _integer(member_limit, "member_limit", 1, 8000)
    if member_index is not None:
        _integer(member_index, "member_index", 0, 15)
        if collection_id is None or detail != "full" or include_history:
            raise ValueError("member_index requires one current collection and full detail")
    elif member_offset:
        raise ValueError("member_offset requires an exact member_index")
    if detail != "full" and member_limit != 4000:
        raise ValueError("member_limit applies only to full source detail")
    histories = _collections(read_records(root, project_id=project_id, kinds=_COLLECTION_KINDS))
    results = []
    for identity, history in reversed(list(histories.items())):
        if collection_id is not None and identity != collection_id:
            continue
        for record in reversed(history if include_history else history[-1:]):
            p = record["payload"]
            if member_index is not None and member_index >= len(p["members"]):
                raise ValueError("member_index exceeds this collection's membership")
            members = []
            for index, reference in enumerate(p["members"]):
                reveal = detail == "full" and (member_index is None or member_index == index)
                source = read_memory_source(root, project_id=project_id, kind=reference["kind"],
                    source_id=reference["id"], content_hash=reference["content_hash"],
                    offset=member_offset if reveal else 0, limit=member_limit if reveal else 1)
                item = {"index": index, "citation": dict(reference),
                        "source_state": "current" if source["found"] else "stale_or_unavailable"}
                if reveal and source["found"]:
                    item["source"] = source
                members.append(item)
            item = {"id": identity, "head": history[-1]["id"], "revision_id": record["id"],
                    "project_id": record["project_id"], "version": p["version"],
                    "title": p["title"], "summary": p["summary"], "members": members,
                    "member_count": len(members), "unavailable_count": sum(row["source_state"] != "current" for row in members),
                    "citation": _citation(record), "is_current_revision": record["id"] == history[-1]["id"]}
            if detail != "summary":
                item["overview"] = p["overview"]
            results.append(item)
    return bounded_results(results, token_budget=token_budget, extra={
        "detail": detail, "include_history": include_history,
        "source_validation": "current_project_scope_and_exact_content_hash",
    })
