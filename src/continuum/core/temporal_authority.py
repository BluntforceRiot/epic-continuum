from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections import defaultdict
from typing import Any, Mapping, Sequence


NON_CURRENT_CARD_STATUSES = frozenset(
    {"archived", "summary_only", "historical", "superseded", "pruned"}
)
VALID_VISIBILITY_SCOPES = frozenset({"global", "session", "project", "private"})
CONFLICT_DISMISSAL_METADATA_KEY = "dismissed_conflict_components"
CONFLICT_RESOLUTION_RECEIPTS_TABLE = "conflict_resolution_receipts"
CONFLICT_RESOLUTION_MEMBERS_TABLE = "conflict_resolution_members"
INTEGRITY_SAMPLE_LIMIT = 20
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )


def _content_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _value(row: Any, key: str, default: Any = None) -> Any:
    try:
        return row[key]
    except (IndexError, KeyError, TypeError):
        if isinstance(row, Mapping):
            return row.get(key, default)
        return default


def conflict_boundary(card: Any) -> tuple[str, str, str]:
    """Return the durable visibility boundary used by conflict authority."""

    scope = str(_value(card, "visibility_scope") or "session")
    project_id = str(_value(card, "project_id") or "")
    session_id = str(_value(card, "session_id") or "")
    if scope == "project" and project_id:
        return ("project", project_id, "")
    if scope == "global":
        return ("global", "", "")
    return (scope, project_id, session_id)


def _conflict_member_material(card: Any) -> dict[str, Any]:
    return {
        "id": str(_value(card, "id") or ""),
        "card_type": str(_value(card, "card_type") or ""),
        "title": str(_value(card, "title") or ""),
        "summary": str(_value(card, "summary") or ""),
        "boundary": list(conflict_boundary(card)),
    }


def conflict_component_fingerprint(
    by_id: Mapping[str, Any],
    member_ids: Sequence[str],
) -> str:
    material = [
        _conflict_member_material(by_id[member_id])
        for member_id in sorted({str(value) for value in member_ids})
    ]
    return _content_hash(
        {
            "schema": "continuum.conflict_resolution_component.v1",
            "members": material,
        }
    )


def conflict_member_binding_hash(card: Any) -> str:
    return _content_hash(
        {
            "schema": "continuum.conflict_resolution_member.v1",
            "member": _conflict_member_material(card),
        }
    )


def _table_names(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
    }


def _json_object(value: Any) -> dict[str, Any] | None:
    try:
        loaded = json.loads(str(value or "{}"))
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError):
        return None
    return loaded if isinstance(loaded, dict) else None


def _stored_integer(value: Any) -> int | None:
    return value if type(value) is int else None


def _receipt_members(
    conn: sqlite3.Connection,
    receipt_id: str,
) -> list[sqlite3.Row]:
    return conn.execute(
        f"""
        SELECT receipt_id, card_id, member_ordinal, member_binding_hash
        FROM {CONFLICT_RESOLUTION_MEMBERS_TABLE}
        WHERE receipt_id = ?
        ORDER BY member_ordinal, card_id
        """,
        (receipt_id,),
    ).fetchall()


def _conflict_resolution_receipt_error(
    conn: sqlite3.Connection,
    receipt: Any,
    *,
    by_id: Mapping[str, Any],
    expected_action: str | None = None,
    expected_fingerprint: str | None = None,
    expected_member_ids: Sequence[str] | None = None,
    allowed_divergent_member_ids: frozenset[str] = frozenset(),
    allow_supersession_topology_divergence: bool = False,
) -> str | None:
    receipt_id = str(_value(receipt, "id") or "")
    action = str(_value(receipt, "action") or "")
    fingerprint = str(_value(receipt, "component_fingerprint") or "")
    conflict_group = str(_value(receipt, "conflict_group") or "")
    selected_card_id = str(_value(receipt, "selected_card_id") or "")
    audit_event_id = str(_value(receipt, "audit_event_id") or "")
    actor = str(_value(receipt, "actor") or "")
    if not receipt_id:
        return "resolution receipt id is missing"
    if action not in {"dismiss", "supersede"}:
        return "resolution receipt action is invalid"
    if expected_action is not None and action != expected_action:
        return "resolution receipt action does not match"
    if _SHA256_RE.fullmatch(fingerprint) is None:
        return "resolution receipt component fingerprint is invalid"
    if expected_fingerprint is not None and fingerprint != expected_fingerprint:
        return "resolution receipt component fingerprint does not match"
    if not conflict_group:
        return "resolution receipt conflict group is missing"
    if actor != "system":
        return "resolution receipt actor is invalid"

    member_rows = _receipt_members(conn, receipt_id)
    member_ids = [str(row["card_id"] or "") for row in member_rows]
    member_ordinals = [_stored_integer(row["member_ordinal"]) for row in member_rows]
    stored_member_count = _stored_integer(_value(receipt, "member_count"))
    if (
        len(member_rows) < 2
        or len(member_ids) != len(set(member_ids))
        or any(not card_id for card_id in member_ids)
        or member_ordinals != list(range(len(member_rows)))
        or stored_member_count != len(member_rows)
    ):
        return "resolution receipt member closure is invalid"
    sorted_member_ids = sorted(member_ids)
    if expected_member_ids is not None and sorted_member_ids != sorted(
        {str(value) for value in expected_member_ids}
    ):
        return "resolution receipt members do not match"
    if selected_card_id not in set(member_ids):
        return "resolution receipt selected Card is not a member"
    if any(card_id not in by_id for card_id in member_ids):
        return "resolution receipt references a missing Card"
    if not allowed_divergent_member_ids.issubset(set(member_ids)):
        return "resolution receipt retirement members do not match"

    stored_boundary = (
        str(_value(receipt, "visibility_scope") or ""),
        str(_value(receipt, "project_id") or ""),
        str(_value(receipt, "session_id") or ""),
    )
    if stored_boundary[0] not in VALID_VISIBILITY_SCOPES:
        return "resolution receipt boundary binding is invalid"
    if any(
        card_id not in allowed_divergent_member_ids
        and conflict_boundary(by_id[card_id]) != stored_boundary
        for card_id in member_ids
    ):
        return "resolution receipt members cross authority boundaries"
    if not allowed_divergent_member_ids and any(
        conflict_boundary(by_id[card_id]) != stored_boundary
        for card_id in member_ids
    ):
        return "resolution receipt boundary binding is invalid"
    boundary = stored_boundary

    actual_fingerprint = conflict_component_fingerprint(by_id, member_ids)
    if fingerprint != actual_fingerprint and not allowed_divergent_member_ids:
        return "resolution receipt component binding is invalid"
    for member_row in member_rows:
        card_id = str(member_row["card_id"])
        if card_id in allowed_divergent_member_ids:
            continue
        if str(member_row["member_binding_hash"] or "") != conflict_member_binding_hash(
            by_id[card_id]
        ):
            return "resolution receipt member binding is invalid"
    if action == "supersede" and not allow_supersession_topology_divergence:
        for card_id in member_ids:
            if card_id == selected_card_id:
                continue
            if (
                str(_value(by_id[card_id], "superseded_by_card_id") or "").strip()
                != selected_card_id
            ):
                return "resolution receipt supersession topology is invalid"

    audit_row = conn.execute(
        """
        SELECT actor, action, target_type, target_id, payload_json
        FROM audit_events
        WHERE id = ?
        """,
        (audit_event_id,),
    ).fetchone()
    if (
        audit_row is None
        or str(audit_row["actor"] or "") != "system"
        or str(audit_row["action"] or "") != "librarian_resolve_conflict"
        or str(audit_row["target_type"] or "") != "card"
        or str(audit_row["target_id"] or "") != selected_card_id
    ):
        return "resolution receipt audit binding is invalid"
    payload = _json_object(audit_row["payload_json"])
    expected_boundary = {
        "visibility_scope": boundary[0],
        "project_id": boundary[1],
        "session_id": boundary[2],
    }
    expected_peers = sorted(card_id for card_id in member_ids if card_id != selected_card_id)
    if (
        payload is None
        or payload.get("schema") != "continuum.conflict_resolution.v1"
        or str(payload.get("resolution_id") or "") != receipt_id
        or str(payload.get("resolution") or "") != action
        or str(payload.get("conflict_group") or "") != conflict_group
        or str(payload.get("component_fingerprint") or "") != fingerprint
        or str(payload.get("selected_card_id") or "") != selected_card_id
        or payload.get("member_card_ids") != sorted_member_ids
        or payload.get("resolved_peer_ids") != expected_peers
        or payload.get("member_count") != len(member_ids)
        or payload.get("boundary") != expected_boundary
        or payload.get("whole_group") is not True
    ):
        return "resolution receipt audit payload is invalid"
    return None


def valid_conflict_resolution_receipt(
    conn: sqlite3.Connection,
    *,
    action: str,
    component_fingerprint: str,
    by_id: Mapping[str, Any],
    member_ids: Sequence[str],
) -> sqlite3.Row | None:
    """Return the exact valid Continuum resolution receipt, if one exists."""

    tables = _table_names(conn)
    if not {
        CONFLICT_RESOLUTION_RECEIPTS_TABLE,
        CONFLICT_RESOLUTION_MEMBERS_TABLE,
        "audit_events",
    }.issubset(tables):
        return None
    receipts = conn.execute(
        f"""
        SELECT *
        FROM {CONFLICT_RESOLUTION_RECEIPTS_TABLE}
        WHERE action = ? AND component_fingerprint = ?
        ORDER BY created_at DESC, id DESC
        """,
        (action, component_fingerprint),
    ).fetchall()
    for receipt in receipts:
        if (
            _conflict_resolution_receipt_error(
                conn,
                receipt,
                by_id=by_id,
                expected_action=action,
                expected_fingerprint=component_fingerprint,
                expected_member_ids=member_ids,
            )
            is None
        ):
            return receipt
    return None


def _resolution_receipt_report(
    conn: sqlite3.Connection,
    *,
    by_id: Mapping[str, Any],
    valid_project_state_quarantines: Mapping[str, str | None],
    sample_limit: int,
) -> dict[str, Any]:
    tables = _table_names(conn)
    receipt_tables = {
        CONFLICT_RESOLUTION_RECEIPTS_TABLE,
        CONFLICT_RESOLUTION_MEMBERS_TABLE,
    }
    present = receipt_tables & tables
    invalid: list[dict[str, str]] = []
    invalid_count = 0
    valid: list[sqlite3.Row] = []
    valid_members: dict[str, list[str]] = {}
    retired_receipt_ids: list[str] = []
    if present and present != receipt_tables:
        invalid_count += 1
        invalid.append(
            {
                "receipt_id": "",
                "reason": "conflict resolution receipt schema is incomplete",
            }
        )
    elif present == receipt_tables:
        receipts = conn.execute(
            f"SELECT * FROM {CONFLICT_RESOLUTION_RECEIPTS_TABLE} ORDER BY created_at, id"
        ).fetchall()
        for receipt in receipts:
            receipt_id = str(receipt["id"] or "")
            member_ids = [
                str(row["card_id"])
                for row in _receipt_members(conn, receipt_id)
            ]
            quarantined_member_ids = frozenset(member_ids).intersection(
                valid_project_state_quarantines
            )
            if quarantined_member_ids:
                retirement_error = _conflict_resolution_receipt_error(
                    conn,
                    receipt,
                    by_id=by_id,
                    allowed_divergent_member_ids=quarantined_member_ids,
                    allow_supersession_topology_divergence=True,
                )
                if retirement_error is None:
                    action = str(receipt["action"] or "")
                    if action == "supersede":
                        permitted_current_ids = {
                            predecessor_id
                            for quarantined_id in quarantined_member_ids
                            if (
                                predecessor_id
                                := valid_project_state_quarantines.get(
                                    quarantined_id
                                )
                            )
                        }
                        retirement_error = next(
                            (
                                "retired supersession member topology is invalid"
                                for member_id in member_ids
                                if member_id not in quarantined_member_ids
                                and (
                                    str(
                                        _value(
                                            by_id[member_id],
                                            "superseded_by_card_id",
                                        )
                                        or ""
                                    ).strip()
                                    or str(
                                        _value(
                                            by_id[member_id],
                                            "conflict_group",
                                        )
                                        or ""
                                    ).strip()
                                    or (
                                        member_id not in permitted_current_ids
                                        and str(
                                            _value(
                                                by_id[member_id],
                                                "status",
                                            )
                                            or ""
                                        ).casefold()
                                        not in NON_CURRENT_CARD_STATUSES
                                    )
                                )
                            ),
                            None,
                        )
                if retirement_error is None:
                    retired_receipt_ids.append(receipt_id)
                    continue
                invalid_count += 1
                invalid.append(
                    {"receipt_id": receipt_id, "reason": retirement_error}
                )
                continue
            error = _conflict_resolution_receipt_error(
                conn,
                receipt,
                by_id=by_id,
            )
            if error is not None:
                invalid_count += 1
                invalid.append({"receipt_id": receipt_id, "reason": error})
                continue
            valid.append(receipt)
            valid_members[receipt_id] = member_ids
        orphan_count = int(
            conn.execute(
                f"""
                SELECT count(*)
                FROM {CONFLICT_RESOLUTION_MEMBERS_TABLE} AS member
                LEFT JOIN {CONFLICT_RESOLUTION_RECEIPTS_TABLE} AS receipt
                  ON receipt.id = member.receipt_id
                WHERE receipt.id IS NULL
                """
            ).fetchone()[0]
        )
        invalid_count += orphan_count
        for _ in range(min(orphan_count, sample_limit)):
            invalid.append(
                {
                    "receipt_id": "",
                    "reason": "orphan conflict resolution member row",
                }
            )

    valid_supersede_fan_in: set[tuple[str, str]] = set()
    valid_dismissal_members: dict[str, set[str]] = defaultdict(set)
    valid_receipt_ids: list[str] = []
    for receipt in valid:
        receipt_id = str(receipt["id"])
        action = str(receipt["action"])
        selected_card_id = str(receipt["selected_card_id"])
        fingerprint = str(receipt["component_fingerprint"])
        member_ids = valid_members[receipt_id]
        valid_receipt_ids.append(receipt_id)
        if action == "supersede":
            valid_supersede_fan_in.update(
                (card_id, selected_card_id)
                for card_id in member_ids
                if card_id != selected_card_id
            )
        elif action == "dismiss":
            valid_dismissal_members[fingerprint].update(member_ids)

    unproven_dismissals: list[dict[str, str]] = []
    if "cards" in tables:
        rows = conn.execute(
            """
            SELECT id, metadata_json
            FROM cards
            WHERE instr(metadata_json, ?) > 0
            ORDER BY id
            """,
            (CONFLICT_DISMISSAL_METADATA_KEY,),
        ).fetchall()
        for row in rows:
            card_id = str(row["id"])
            metadata = _json_object(row["metadata_json"])
            entries = (
                metadata.get(CONFLICT_DISMISSAL_METADATA_KEY)
                if isinstance(metadata, dict)
                else None
            )
            if not isinstance(entries, list):
                unproven_dismissals.append(
                    {"card_id": card_id, "fingerprint": "", "reason": "malformed"}
                )
                continue
            for entry in entries:
                fingerprint = (
                    str(entry.get("fingerprint") or "")
                    if isinstance(entry, dict)
                    else ""
                )
                if (
                    _SHA256_RE.fullmatch(fingerprint) is None
                    or card_id not in valid_dismissal_members.get(fingerprint, set())
                ):
                    unproven_dismissals.append(
                        {
                            "card_id": card_id,
                            "fingerprint": fingerprint,
                            "reason": "no valid exact-component dismissal receipt",
                        }
                    )

    return {
        "invalid_conflict_resolution_receipts": invalid_count,
        "unproven_conflict_dismissals": len(unproven_dismissals),
        "valid_supersede_fan_in": valid_supersede_fan_in,
        "valid_receipt_ids": valid_receipt_ids,
        "retired_receipt_ids": retired_receipt_ids,
        "samples": {
            "invalid_conflict_resolution_receipts": invalid[:sample_limit],
            "unproven_conflict_dismissals": unproven_dismissals[:sample_limit],
        },
    }


def _valid_project_state_fan_in_edges(
    conn: sqlite3.Connection,
    *,
    by_id: Mapping[str, Any],
    valid_project_state_agents: Mapping[str, str],
) -> set[tuple[str, str]]:
    """Recover intentional legacy-fork repair edges from exact system audits."""

    fan_in: set[tuple[str, str]] = set()
    rows = conn.execute(
        """
        SELECT actor, target_id, payload_json
        FROM audit_events
        WHERE action = 'project_state_superseded' AND target_type = 'card'
        ORDER BY created_at, id
        """
    ).fetchall()
    for row in rows:
        successor_id = str(row["target_id"] or "")
        successor = by_id.get(successor_id)
        payload = _json_object(row["payload_json"])
        if successor is None or payload is None:
            continue
        authority = payload.get("authority")
        predecessor_ids = payload.get("superseded_card_ids")
        direct_predecessor = str(payload.get("direct_predecessor_card_id") or "")
        if (
            not isinstance(authority, dict)
            or not isinstance(predecessor_ids, list)
            or not predecessor_ids
            or not all(isinstance(value, str) and value for value in predecessor_ids)
            or len(predecessor_ids) != len(set(predecessor_ids))
            or direct_predecessor not in predecessor_ids
            or any(predecessor_id not in by_id for predecessor_id in predecessor_ids)
            or str(_value(successor, "card_type") or "") != "project_state"
        ):
            continue
        boundary = conflict_boundary(successor)
        agent_id = valid_project_state_agents.get(successor_id)
        stored_boundary = (
            str(authority.get("visibility_scope") or ""),
            str(authority.get("project_id") or ""),
            str(authority.get("session_id") or ""),
        )
        if (
            not agent_id
            or str(row["actor"] or "") != agent_id
            or str(authority.get("agent_id") or "") != agent_id
            or stored_boundary != boundary
            or str(successor["supersedes_card_id"] or "") != direct_predecessor
        ):
            continue
        if any(
            str(by_id[predecessor_id]["card_type"] or "") != "project_state"
            or conflict_boundary(by_id[predecessor_id]) != boundary
            or valid_project_state_agents.get(predecessor_id) != agent_id
            or str(by_id[predecessor_id]["superseded_by_card_id"] or "")
            != successor_id
            for predecessor_id in predecessor_ids
        ):
            continue
        fan_in.update(
            (predecessor_id, successor_id)
            for predecessor_id in predecessor_ids
            if predecessor_id != direct_predecessor
        )
    return fan_in


def _supersession_cycle_components(
    edges: Mapping[str, set[str]],
) -> list[list[str]]:
    visited: set[str] = set()
    finish_order: list[str] = []
    for start in sorted(edges):
        if start in visited:
            continue
        stack: list[tuple[str, bool]] = [(start, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                finish_order.append(node)
                continue
            if node in visited:
                continue
            visited.add(node)
            stack.append((node, True))
            for target in sorted(edges.get(node, ()), reverse=True):
                if target not in visited:
                    stack.append((target, False))

    reverse_edges: dict[str, set[str]] = {card_id: set() for card_id in edges}
    for source, targets in edges.items():
        for target in targets:
            reverse_edges[target].add(source)
    assigned: set[str] = set()
    cyclic: list[list[str]] = []
    for start in reversed(finish_order):
        if start in assigned:
            continue
        component: list[str] = []
        pending = [start]
        assigned.add(start)
        while pending:
            node = pending.pop()
            component.append(node)
            for target in reverse_edges.get(node, ()):
                if target not in assigned:
                    assigned.add(target)
                    pending.append(target)
        component.sort()
        if len(component) > 1 or (
            len(component) == 1 and component[0] in edges.get(component[0], set())
        ):
            cyclic.append(component)
    cyclic.sort()
    return cyclic


def temporal_authority_integrity_report(
    conn: sqlite3.Connection,
    *,
    valid_project_state_agents: Mapping[str, str] | None = None,
    valid_project_state_quarantines: Mapping[str, str | None] | None = None,
    sample_limit: int = INTEGRITY_SAMPLE_LIMIT,
) -> dict[str, Any]:
    """Validate the complete temporal/conflict authority model in one snapshot."""

    rows = conn.execute(
        """
        SELECT id, card_type, title, summary, status, visibility_scope,
               session_id, project_id, conflict_group, supersedes_card_id,
               superseded_by_card_id
        FROM cards
        ORDER BY id
        """
    ).fetchall()
    by_id = {str(row["id"]): row for row in rows}
    receipt_report = _resolution_receipt_report(
        conn,
        by_id=by_id,
        valid_project_state_quarantines=(
            valid_project_state_quarantines or {}
        ),
        sample_limit=sample_limit,
    )
    valid_fan_in = set(receipt_report["valid_supersede_fan_in"])
    valid_fan_in.update(
        _valid_project_state_fan_in_edges(
            conn,
            by_id=by_id,
            valid_project_state_agents=valid_project_state_agents or {},
        )
    )

    missing: set[tuple[str, str, str]] = set()
    asymmetric: set[tuple[str, str, str]] = set()
    cross_boundary: set[tuple[str, str]] = set()
    edges: dict[str, set[str]] = {card_id: set() for card_id in by_id}
    referenced_predecessors: set[str] = set()
    for card_id, row in by_id.items():
        predecessor = str(row["supersedes_card_id"] or "").strip()
        successor = str(row["superseded_by_card_id"] or "").strip()
        if predecessor:
            referenced_predecessors.add(predecessor)
            if predecessor not in by_id:
                missing.add((card_id, "supersedes_card_id", predecessor))
            else:
                edges[predecessor].add(card_id)
                if conflict_boundary(by_id[predecessor]) != conflict_boundary(row):
                    cross_boundary.add((predecessor, card_id))
                if str(by_id[predecessor]["superseded_by_card_id"] or "").strip() != card_id:
                    asymmetric.add((predecessor, card_id, "direct predecessor backlink"))
        if successor:
            if successor not in by_id:
                missing.add((card_id, "superseded_by_card_id", successor))
            else:
                edges[card_id].add(successor)
                if conflict_boundary(row) != conflict_boundary(by_id[successor]):
                    cross_boundary.add((card_id, successor))
                direct = str(by_id[successor]["supersedes_card_id"] or "").strip()
                if direct != card_id and (card_id, successor) not in valid_fan_in:
                    asymmetric.add((card_id, successor, "successor forward link"))

    cyclic_components = _supersession_cycle_components(edges)
    mixed_project_state_edges: set[tuple[str, str]] = set()
    unproven_cross_agent_project_state_edges: set[tuple[str, str]] = set()
    project_state_agents = valid_project_state_agents or {}
    for predecessor_id, successor_ids in edges.items():
        if predecessor_id not in by_id:
            continue
        predecessor_is_project_state = (
            str(by_id[predecessor_id]["card_type"] or "").casefold().strip()
            == "project_state"
        )
        for successor_id in successor_ids:
            if successor_id not in by_id:
                continue
            successor_is_project_state = (
                str(by_id[successor_id]["card_type"] or "").casefold().strip()
                == "project_state"
            )
            if predecessor_is_project_state != successor_is_project_state:
                mixed_project_state_edges.add((predecessor_id, successor_id))
                continue
            if not predecessor_is_project_state:
                continue
            predecessor_agent = project_state_agents.get(predecessor_id)
            successor_agent = project_state_agents.get(successor_id)
            if (
                predecessor_agent
                and successor_agent
                and predecessor_agent != successor_agent
                and (predecessor_id, successor_id) not in valid_fan_in
            ):
                unproven_cross_agent_project_state_edges.add(
                    (predecessor_id, successor_id)
                )
    unsuperseded_ids = {
        card_id
        for card_id, row in by_id.items()
        if str(row["status"] or "").casefold() not in NON_CURRENT_CARD_STATUSES
        and not str(row["superseded_by_card_id"] or "").strip()
        and card_id not in referenced_predecessors
    }
    duplicate_heads: list[dict[str, Any]] = []
    heads_by_authority: dict[tuple[tuple[str, str, str], str], list[str]] = defaultdict(list)
    for card_id, agent_id in sorted((valid_project_state_agents or {}).items()):
        if card_id not in unsuperseded_ids or card_id not in by_id:
            continue
        heads_by_authority[(conflict_boundary(by_id[card_id]), agent_id)].append(card_id)
    for (boundary, agent_id), card_ids in sorted(heads_by_authority.items()):
        if len(card_ids) > 1:
            duplicate_heads.append(
                {
                    "boundary": list(boundary),
                    "agent_id": agent_id,
                    "card_ids": sorted(card_ids),
                }
            )

    grouped: dict[str, list[str]] = defaultdict(list)
    blank_group_cards: list[str] = []
    for card_id, row in by_id.items():
        raw_group = row["conflict_group"]
        group = str(raw_group or "").strip()
        if raw_group is not None and not group:
            blank_group_cards.append(card_id)
        elif group:
            grouped[group].append(card_id)
    invalid_groups: list[dict[str, Any]] = [
        {"conflict_group": "", "card_ids": [card_id], "reasons": ["blank group id"]}
        for card_id in sorted(blank_group_cards)
    ]
    for group, card_ids in sorted(grouped.items()):
        boundaries = {conflict_boundary(by_id[card_id]) for card_id in card_ids}
        card_types = {
            str(by_id[card_id]["card_type"] or "").casefold().strip()
            for card_id in card_ids
        }
        reasons: list[str] = []
        if len(card_ids) < 2:
            reasons.append("group has fewer than two members")
        if any(card_id not in unsuperseded_ids for card_id in card_ids):
            reasons.append("group contains a historical or superseded Card")
        if len(boundaries) != 1:
            reasons.append("group crosses authority boundaries")
        if "project_state" in card_types and len(card_types) > 1:
            reasons.append("project-state group contains another Card type")
        if reasons:
            invalid_groups.append(
                {
                    "conflict_group": group,
                    "card_ids": sorted(card_ids),
                    "reasons": reasons,
                }
            )

    checks = {
        "supersession_missing_references": len(missing),
        "supersession_asymmetric_links": len(asymmetric),
        "supersession_cross_boundary_links": len(cross_boundary),
        "supersession_cycle_count": len(cyclic_components),
        "mixed_project_state_supersession_edges": len(
            mixed_project_state_edges
        ),
        "unproven_cross_agent_project_state_edges": len(
            unproven_cross_agent_project_state_edges
        ),
        "multiple_same_agent_project_state_heads": len(duplicate_heads),
        "invalid_conflict_groups": len(invalid_groups),
        "invalid_conflict_resolution_receipts": int(
            receipt_report["invalid_conflict_resolution_receipts"]
        ),
        "unproven_conflict_dismissals": int(
            receipt_report["unproven_conflict_dismissals"]
        ),
    }
    samples = {
        "supersession_missing_references": [
            {"card_id": card_id, "field": field, "target_id": target_id}
            for card_id, field, target_id in sorted(missing)[:sample_limit]
        ],
        "supersession_asymmetric_links": [
            {"predecessor_id": predecessor, "successor_id": successor, "reason": reason}
            for predecessor, successor, reason in sorted(asymmetric)[:sample_limit]
        ],
        "supersession_cross_boundary_links": [
            {"predecessor_id": predecessor, "successor_id": successor}
            for predecessor, successor in sorted(cross_boundary)[:sample_limit]
        ],
        "supersession_cycles": cyclic_components[:sample_limit],
        "mixed_project_state_supersession_edges": [
            {"predecessor_id": predecessor, "successor_id": successor}
            for predecessor, successor in sorted(mixed_project_state_edges)[
                :sample_limit
            ]
        ],
        "unproven_cross_agent_project_state_edges": [
            {"predecessor_id": predecessor, "successor_id": successor}
            for predecessor, successor in sorted(
                unproven_cross_agent_project_state_edges
            )[:sample_limit]
        ],
        "multiple_same_agent_project_state_heads": duplicate_heads[:sample_limit],
        "invalid_conflict_groups": invalid_groups[:sample_limit],
        **receipt_report["samples"],
    }
    return {
        "ok": not any(checks.values()),
        "checks": checks,
        "samples": samples,
        "valid_conflict_resolution_receipt_ids": receipt_report[
            "valid_receipt_ids"
        ],
        "retired_conflict_resolution_receipt_ids": receipt_report[
            "retired_receipt_ids"
        ],
    }
