from __future__ import annotations

import datetime as dt
import os
import time
from pathlib import Path
from typing import Any

from .config import config_path, default_config, load_config, retention_policy
from .permissions import secure_move_file
from .store import (
    add_graph_edge,
    audit_event,
    canonical_partition_identifier,
    connect,
    connect_existing,
    content_hash,
    continuum_uri,
    estimate_tokens,
    extract_terms,
    file_sha256,
    init_db,
    is_initialized,
    json_dumps,
    json_loads,
    mark_card_sidecar_outbox,
    refresh_graph_edge_aggregate,
    resolve_stored_uri,
    roll_scroll_segment,
    segment_hash_material,
    snapshot,
    sync_card_sidecar,
    sync_card_sidecars_after_commit,
    unique_id,
    upsert_graph_node,
    utc_now,
)
from .units import parse_size


TERMINAL_JOB_STATUSES = {"succeeded", "failed", "skipped"}
ACTIVE_JOB_STATUS = "running"
PENDING_JOB_STATUS = "pending"


def _lease_expiry(seconds: int) -> str:
    return (dt.datetime.now(dt.UTC).replace(microsecond=0) + dt.timedelta(seconds=max(1, int(seconds)))).isoformat()


def _root_size_bytes(root: Path) -> int:
    total = 0
    if not root.exists():
        return 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total


def _parse_utc_timestamp(value: str) -> dt.datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    parsed = dt.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.UTC)
    return parsed.astimezone(dt.UTC)


def _reclaim_expired_leases(conn, roles: set[str] | None = None) -> int:
    now = utc_now()
    params: list[Any] = [now]
    role_clause = ""
    if roles:
        placeholders = ",".join("?" for _ in roles)
        role_clause = f" AND role IN ({placeholders})"
        params.extend(sorted(roles))
    cursor = conn.execute(
        f"""
        UPDATE queue_jobs
        SET status = ?, lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = NULL, updated_at = ?,
            error_json = ?
        WHERE status = ?
          AND preemptible = 1
          AND lease_expires_at IS NOT NULL
          AND lease_expires_at <= ?{role_clause}
        """,
        [PENDING_JOB_STATUS, now, json_dumps({"reclaimed": True, "reason": "worker_lease_expired"}), ACTIVE_JOB_STATUS, *params],
    )
    reclaimed = int(cursor.rowcount or 0)
    failed_cursor = conn.execute(
        f"""
        UPDATE queue_jobs
        SET status = 'failed', finished_at = ?, lease_owner = NULL, lease_expires_at = NULL,
            heartbeat_at = NULL, updated_at = ?, error_json = ?
        WHERE status = ?
          AND preemptible = 0
          AND lease_expires_at IS NOT NULL
          AND lease_expires_at <= ?{role_clause}
        """,
        [
            now,
            now,
            json_dumps({"error": "non_preemptible_worker_lease_expired", "reclaimed": False}),
            ACTIVE_JOB_STATUS,
            *params,
        ],
    )
    return reclaimed + int(failed_cursor.rowcount or 0)


def _claim_job(conn, roles: set[str] | None = None, *, lease_owner: str, lease_seconds: int) -> dict[str, Any] | None:
    params: list[Any] = [PENDING_JOB_STATUS]
    role_clause = ""
    if roles:
        placeholders = ",".join("?" for _ in roles)
        role_clause = f" AND role IN ({placeholders})"
        params.extend(sorted(roles))
    row = conn.execute(
        f"""
        SELECT *
        FROM queue_jobs
        WHERE status = ?{role_clause}
        ORDER BY priority ASC, created_at ASC
        LIMIT 1
        """,
        params,
    ).fetchone()
    if row is None:
        return None
    now = utc_now()
    expires_at = _lease_expiry(lease_seconds)
    cursor = conn.execute(
        """
        UPDATE queue_jobs
        SET status = ?, started_at = coalesce(started_at, ?),
            attempt_count = attempt_count + 1, lease_owner = ?, lease_expires_at = ?,
            heartbeat_at = ?, updated_at = ?
        WHERE id = ? AND status = ?
        """,
        (ACTIVE_JOB_STATUS, now, lease_owner, expires_at, now, now, row["id"], PENDING_JOB_STATUS),
    )
    if int(cursor.rowcount or 0) != 1:
        return None
    job = dict(row)
    job["lease_owner"] = lease_owner
    job["lease_expires_at"] = expires_at
    job["heartbeat_at"] = now
    return job


def _heartbeat_job(conn, job_id: str, *, lease_owner: str, lease_seconds: int) -> bool:
    now = utc_now()
    expires_at = _lease_expiry(lease_seconds)
    cursor = conn.execute(
        """
        UPDATE queue_jobs
        SET heartbeat_at = ?, lease_expires_at = ?, updated_at = ?
        WHERE id = ? AND status = ? AND lease_owner = ?
        """,
        (now, expires_at, now, job_id, ACTIVE_JOB_STATUS, lease_owner),
    )
    return int(cursor.rowcount or 0) == 1


def _finish_job(
    conn,
    job_id: str,
    *,
    status: str,
    result: dict[str, Any] | None = None,
    error: str | None = None,
    lease_owner: str | None = None,
) -> bool:
    now = utc_now()
    where_clause = "WHERE id = ?"
    params: list[Any] = [
        status,
        now,
        now,
        json_dumps({"error": error, "result": result or {}}) if error or result else None,
        now,
        job_id,
    ]
    if lease_owner is not None:
        where_clause = "WHERE id = ? AND status = ? AND lease_owner = ?"
        params.extend([ACTIVE_JOB_STATUS, lease_owner])
    cursor = conn.execute(
        f"""
        UPDATE queue_jobs
        SET status = ?, finished_at = ?, updated_at = ?, error_json = ?,
            lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = ?
        {where_clause}
        """,
        params,
    )
    return int(cursor.rowcount or 0) == 1


def _finish_owned_job(
    conn,
    job_id: str,
    *,
    lease_owner: str,
    lease_seconds: int,
    status: str,
    result: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    if not _heartbeat_job(conn, job_id, lease_owner=lease_owner, lease_seconds=lease_seconds):
        raise RuntimeError("worker lease lost before job finish")
    if not _finish_job(conn, job_id, status=status, result=result, error=error, lease_owner=lease_owner):
        raise RuntimeError("worker lease lost before job finish")


def _last_segment_end(conn, session_id: str) -> int:
    row = conn.execute(
        "SELECT coalesce(max(end_seq), 0) AS end_seq FROM scroll_segments WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    return int(row["end_seq"] or 0)


def _scroll_security_runs(conn, *, session_id: str, start_seq: int, end_seq: int) -> list[tuple[int, int]]:
    rows = conn.execute(
        """
        SELECT seq, visibility_scope, project_id
        FROM scroll_events
        WHERE session_id = ? AND seq BETWEEN ? AND ?
        ORDER BY seq
        """,
        (session_id, start_seq, end_seq),
    ).fetchall()
    runs: list[tuple[int, int]] = []
    run_start: int | None = None
    run_end: int | None = None
    run_boundary: tuple[str, str, str] | None = None
    for row in rows:
        seq = int(row["seq"])
        boundary = (str(row["visibility_scope"] or "session"), str(row["project_id"] or ""), session_id)
        if run_start is None:
            run_start = seq
            run_end = seq
            run_boundary = boundary
            continue
        if seq != int(run_end) + 1 or boundary != run_boundary:
            runs.append((int(run_start), int(run_end)))
            run_start = seq
            run_boundary = boundary
        run_end = seq
    if run_start is not None and run_end is not None:
        runs.append((int(run_start), int(run_end)))
    return runs


def roll_due_scroll_segments(root: Path, *, session_id: str | None = None, force: bool = False) -> dict[str, Any]:
    init_db(root)
    config = load_config(root)
    threshold = int(config.get("capture", {}).get("roll_segments_every_events", 200))
    if session_id:
        session_id = canonical_partition_identifier(root, "session_id", session_id, lookup=True)
    rolled: list[dict[str, Any]] = []
    conn = connect(root)
    try:
        if session_id:
            sessions = [session_id]
        else:
            sessions = [row["session_id"] for row in conn.execute("SELECT DISTINCT session_id FROM scroll_events")]
        for current_session in sessions:
            max_row = conn.execute(
                "SELECT coalesce(max(seq), 0) AS max_seq FROM scroll_events WHERE session_id = ?",
                (current_session,),
            ).fetchone()
            max_seq = int(max_row["max_seq"] or 0)
            start = _last_segment_end(conn, current_session) + 1
            pending = max_seq - start + 1
            while pending > 0 and (force or pending >= threshold):
                end = max_seq if force else min(max_seq, start + threshold - 1)
                if end < start:
                    break
                runs = _scroll_security_runs(conn, session_id=current_session, start_seq=start, end_seq=end)
                if not runs:
                    break
                conn.close()
                for run_start, run_end in runs:
                    result = roll_scroll_segment(root, session_id=current_session, start_seq=run_start, end_seq=run_end)
                    rolled.append(result)
                conn = connect(root)
                start = runs[-1][1] + 1
                pending = max_seq - start + 1
                if not force:
                    break
    finally:
        conn.close()
    return {"ok": True, "rolled_count": len(rolled), "rolled": rolled}


def review_card_placement(root: Path, *, card_id: str) -> dict[str, Any]:
    conn = connect(root)
    try:
        row = conn.execute("SELECT * FROM cards WHERE id = ?", (card_id,)).fetchone()
        if row is None:
            return {"ok": False, "reason": "card_missing", "card_id": card_id}
        topics = json_loads(row["topics_json"], [])
        entities = json_loads(row["entities_json"], [])
        terms = [str(term) for term in [*topics, *entities] if str(term).strip()]
        shelf = str(terms[0] if terms else row["card_type"]).casefold()[:96]
        now = utc_now()
        card_node = upsert_graph_node(conn, kind="card", label=row["title"], card_id=card_id)
        for term in terms[:16]:
            term_node = upsert_graph_node(conn, kind="term", label=term)
            add_graph_edge(
                conn,
                source_node_id=card_node,
                relation="mentions",
                target_node_id=term_node,
                weight=0.5,
                confidence=max(0.5, float(row["confidence"] or 0.7)),
                source_refs=[{"card_id": card_id, "worker": "librarian"}],
            )
        conn.execute(
            """
            UPDATE cards
            SET status = CASE WHEN status = 'pending_librarian_review' THEN 'active' ELSE status END,
                placement_collection = coalesce(placement_collection, ?),
                shelf = coalesce(shelf, ?),
                storage_tier = coalesce(storage_tier, 'hot'),
                updated_at = ?
            WHERE id = ?
            """,
            ("library", shelf, now, card_id),
        )
        audit_event(conn, action="librarian_review_card", target_type="card", target_id=card_id, payload={"shelf": shelf})
        mark_card_sidecar_outbox(conn, [card_id], reason="librarian_review_card")
        conn.commit()
        sync_card_sidecars_after_commit(root, [card_id])
        conflict = detect_conflicts(root, card_id=card_id, limit=10)
        return {"ok": True, "card_id": card_id, "shelf": shelf, "term_edges": len(terms[:16]), "conflicts": conflict}
    finally:
        conn.close()


def verify_book_integrity(root: Path, *, book_id: str, content_hash_value: str | None = None) -> dict[str, Any]:
    conn = connect(root)
    try:
        row = conn.execute("SELECT * FROM books WHERE id = ?", (book_id,)).fetchone()
        if row is None:
            return {"ok": False, "reason": "book_missing", "book_id": book_id}
        expected = content_hash_value or row["content_hash"]
        original_uri = row["original_uri"]
        reader_uri = row["reader_uri"]
        original_path = resolve_stored_uri(root, original_uri) if original_uri else None
        reader_path = resolve_stored_uri(root, reader_uri) if reader_uri else None
        ok = False
        reason = "original_missing"
        actual_original_hash: str | None = None
        actual_reader_hash: str | None = None
        if original_path and original_path.exists():
            actual_original_hash = file_sha256(original_path)
            ok = actual_original_hash == expected
            reason = "ok" if ok else "original_hash_mismatch"
        elif reader_path and reader_path.exists():
            # Legacy roots may have a reader edition but no original archive. Reader
            # hashes are text-normalized and are only authoritative as a fallback.
            actual_reader_hash = content_hash(reader_path.read_text(encoding="utf-8", errors="replace"))
            ok = actual_reader_hash == expected
            reason = "ok" if ok else "reader_hash_mismatch"
        else:
            reason = "original_and_reader_missing"
        now = utc_now()
        metadata = json_loads(row["metadata_json"], {})
        metadata["last_verified_at"] = now
        metadata["verification_reason"] = reason
        if actual_original_hash:
            metadata["last_original_sha256"] = actual_original_hash
        if actual_reader_hash:
            metadata["last_reader_text_hash"] = actual_reader_hash
        conn.execute(
            """
            UPDATE books
            SET verification_status = ?, last_verified_at = ?, metadata_json = ?, updated_at = ?
            WHERE id = ?
            """,
            ("verified" if ok else "failed", now, json_dumps(metadata), now, book_id),
        )
        audit_event(
            conn,
            action="archivist_verify_book",
            target_type="book",
            target_id=book_id,
            payload={"ok": ok, "reason": reason, "checked_original": bool(original_path and original_path.exists())},
        )
        conn.commit()
        return {
            "ok": ok,
            "book_id": book_id,
            "reason": reason,
            "checked_original": bool(original_path and original_path.exists()),
            "checked_reader": bool((not original_path or not original_path.exists()) and reader_path and reader_path.exists()),
        }
    finally:
        conn.close()


def verify_segment_integrity(root: Path, *, segment_id: str, segment_hash: str | None = None) -> dict[str, Any]:
    conn = connect(root)
    try:
        row = conn.execute("SELECT * FROM scroll_segments WHERE id = ?", (segment_id,)).fetchone()
        if row is None:
            return {"ok": False, "reason": "segment_missing", "segment_id": segment_id}
        expected = segment_hash or row["segment_hash"]
        events = conn.execute(
            """
            SELECT seq, role, event_type, content, content_hash
            FROM scroll_events
            WHERE session_id = ? AND seq BETWEEN ? AND ?
            ORDER BY seq
            """,
            (row["session_id"], row["start_seq"], row["end_seq"]),
        ).fetchall()
        event_hash_mismatches = [
            {"seq": event["seq"], "expected_content_hash": event["content_hash"], "actual_content_hash": content_hash(event["content"])}
            for event in events
            if content_hash(event["content"]) != event["content_hash"]
        ]
        actual = content_hash(segment_hash_material(events))
        legacy_actual = content_hash(segment_hash_material(events, legacy=True))
        segment_hash_ok = actual == expected or legacy_actual == expected
        ok = segment_hash_ok and not event_hash_mismatches
        reason = "ok" if ok else ("scroll_event_hash_mismatch" if event_hash_mismatches else "segment_hash_mismatch")
        audit_event(
            conn,
            action="archivist_verify_segment",
            target_type="scroll_segment",
            target_id=segment_id,
            payload={"ok": ok, "event_count": len(events), "reason": reason, "event_hash_mismatch_count": len(event_hash_mismatches)},
        )
        conn.commit()
        return {
            "ok": ok,
            "segment_id": segment_id,
            "reason": reason,
            "event_hash_mismatch_count": len(event_hash_mismatches),
            "event_hash_mismatches": event_hash_mismatches[:10],
        }
    finally:
        conn.close()


def _graph_source_security_domain(conn, source_ref_json: str | None) -> str:
    ref = json_loads(source_ref_json or "{}", {})
    if not isinstance(ref, dict):
        return "global"
    project_id = str(ref.get("project_id") or "")
    if project_id:
        return f"project:{project_id}"
    if card_id := ref.get("card_id"):
        row = conn.execute(
            "SELECT visibility_scope, session_id, project_id FROM cards WHERE id = ?",
            (str(card_id),),
        ).fetchone()
        if row is not None:
            if row["project_id"]:
                return f"project:{row['project_id']}"
            if row["session_id"]:
                return f"session:{row['session_id']}"
            if row["visibility_scope"]:
                return f"scope:{row['visibility_scope']}"
    if event_id := ref.get("event_id"):
        row = conn.execute(
            "SELECT visibility_scope, session_id, project_id FROM scroll_events WHERE id = ?",
            (str(event_id),),
        ).fetchone()
        if row is not None:
            if row["project_id"]:
                return f"project:{row['project_id']}"
            if row["session_id"]:
                return f"session:{row['session_id']}"
            if row["visibility_scope"]:
                return f"scope:{row['visibility_scope']}"
    session_id = str(ref.get("session_id") or "")
    if session_id:
        return f"session:{session_id}"
    visibility_scope = str(ref.get("visibility_scope") or "")
    if visibility_scope:
        return f"scope:{visibility_scope}"
    return "global"


def decay_graph_routes(root: Path, *, limit: int = 200, prune_threshold: int = 3) -> dict[str, Any]:
    init_db(root)
    learning = load_config(root).get("learning", {})
    min_interval = int(learning.get("route_decay_min_interval_seconds", 3600))
    weight_factor = float(learning.get("route_decay_weight_factor", 0.92))
    weight_floor = float(learning.get("route_decay_floor", 0.01))
    prune_weight_threshold = float(learning.get("route_prune_weight_threshold", 0.12))
    cutoff = (dt.datetime.now(dt.UTC) - dt.timedelta(seconds=min_interval)).replace(microsecond=0).isoformat()
    conn = connect(root)
    try:
        due_rows = conn.execute(
            """
            SELECT ges.edge_id, ges.source_ref_key, ges.source_ref_json, ges.weight, ges.decay_count
            FROM graph_edge_sources ges
            JOIN graph_edges ge ON ge.id = ges.edge_id
            WHERE ges.status = 'active'
              AND ge.pinned = 0
              AND (? <= 0 OR ges.last_decay_at IS NULL OR ges.last_decay_at <= ?)
            ORDER BY coalesce(ges.last_used_at, ges.created_at) ASC, ges.edge_id, ges.source_ref_key
            """,
            (min_interval, cutoff),
        ).fetchall()
        grouped: dict[str, list[Any]] = {}
        for row in due_rows:
            grouped.setdefault(_graph_source_security_domain(conn, row["source_ref_json"]), []).append(row)
        total_limit = max(0, int(limit))
        rows: list[Any] = []
        positions = {domain: 0 for domain in grouped}
        domains = sorted(grouped)
        while len(rows) < total_limit and any(positions[domain] < len(grouped[domain]) for domain in domains):
            for domain in domains:
                position = positions[domain]
                if position >= len(grouped[domain]):
                    continue
                rows.append(grouped[domain][position])
                positions[domain] = position + 1
                if len(rows) >= total_limit:
                    break
        decayed = 0
        pruned = 0
        now = utc_now()
        touched_edges: set[str] = set()
        for row in rows:
            new_decay = int(row["decay_count"] or 0) + 1
            new_weight = max(weight_floor, float(row["weight"] or 0.25) * weight_factor)
            status = "pruned" if new_decay >= prune_threshold and new_weight < prune_weight_threshold else "active"
            conn.execute(
                """
                UPDATE graph_edge_sources
                SET weight = ?,
                    decay_count = ?,
                    status = ?,
                    last_decay_at = ?,
                    updated_at = ?
                WHERE edge_id = ? AND source_ref_key = ? AND status = 'active'
                """,
                (new_weight, new_decay, status, now, now, row["edge_id"], row["source_ref_key"]),
            )
            if status == "pruned":
                pruned += 1
            else:
                decayed += 1
            touched_edges.add(str(row["edge_id"]))
        for edge_id in touched_edges:
            refresh_graph_edge_aggregate(conn, edge_id, now=now)
        audit_event(
            conn,
            action="librarian_decay_routes",
            target_type="graph",
            target_id=None,
            payload={
                "decayed": decayed,
                "pruned": pruned,
                "min_interval_seconds": min_interval,
                "due_sources": len(due_rows),
                "domains": len(grouped),
                "global_limit": total_limit,
            },
        )
        conn.commit()
        return {
            "ok": True,
            "decayed": decayed,
            "pruned": pruned,
            "processed": len(rows),
            "due_sources": len(due_rows),
            "domains": len(grouped),
            "global_limit": total_limit,
            "skipped_recent": 0 if min_interval <= 0 else max(0, len(due_rows) - len(rows)),
            "min_interval_seconds": min_interval,
        }
    finally:
        conn.close()


def detect_conflicts(root: Path, *, card_id: str | None = None, limit: int = 50) -> dict[str, Any]:
    init_db(root)
    conn = connect(root)
    try:
        if card_id:
            candidates = conn.execute("SELECT * FROM cards WHERE id = ?", (card_id,)).fetchall()
        else:
            candidates = conn.execute(
                "SELECT * FROM cards WHERE status != 'pruned' ORDER BY updated_at DESC LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
        conflicts: list[dict[str, Any]] = []
        touched_cards: set[str] = set()
        now = utc_now()
        for card in candidates:
            terms = extract_terms(f"{card['title']} {card['summary']}", limit=6)
            if not terms:
                continue
            pattern = f"%{terms[0]}%"
            scope = str(card["visibility_scope"] or "session")
            project_id = str(card["project_id"] or "")
            session_id = str(card["session_id"] or "")
            if scope == "project" and project_id:
                scope_clause = "visibility_scope = 'project' AND coalesce(project_id, '') = ?"
                scope_params: list[Any] = [project_id]
            elif scope == "global":
                scope_clause = "visibility_scope = 'global' AND coalesce(project_id, '') = ''"
                scope_params = []
            else:
                scope_clause = (
                    "visibility_scope = ? AND coalesce(project_id, '') = ? "
                    "AND coalesce(session_id, '') = ?"
                )
                scope_params = [scope, project_id, session_id]
            others = conn.execute(
                f"""
                SELECT id, title, summary
                FROM cards
                WHERE id != ? AND status != 'pruned'
                  AND {scope_clause}
                  AND (title LIKE ? OR summary LIKE ?)
                LIMIT 5
                """,
                (card["id"], *scope_params, pattern, pattern),
            ).fetchall()
            negative = any(word in card["summary"].casefold() for word in (" not ", " no ", "never", "disable", "removed"))
            for other in others:
                other_negative = any(word in other["summary"].casefold() for word in (" not ", " no ", "never", "disable", "removed"))
                if negative == other_negative and card["title"].casefold() != other["title"].casefold():
                    continue
                group = content_hash("|".join(sorted([card["id"], other["id"]]))[:512])[:16]
                conn.execute("UPDATE cards SET conflict_group = ?, updated_at = ? WHERE id IN (?, ?)", (group, now, card["id"], other["id"]))
                touched_cards.update([str(card["id"]), str(other["id"])])
                conflicts.append({"conflict_group": group, "card_ids": [card["id"], other["id"]]})
                audit_event(conn, action="librarian_detect_conflict", target_type="card", target_id=card["id"], payload={"other_card_id": other["id"], "conflict_group": group})
        mark_card_sidecar_outbox(conn, list(touched_cards), reason="conflict_group_updated")
        conn.commit()
        sync_card_sidecars_after_commit(root, list(touched_cards))
        return {"ok": True, "conflict_count": len(conflicts), "conflicts": conflicts}
    finally:
        conn.close()


def apply_storage_tiering(root: Path, *, dry_run: bool = False, limit: int = 100) -> dict[str, Any]:
    init_db(root)
    policy = retention_policy(root)
    hot_days = int(policy.get("raw_scroll_hot_days", 30))
    warm_days = int(policy.get("raw_scroll_warm_days", 180))
    actions: list[dict[str, Any]] = []
    conn = connect(root)
    try:
        rows = conn.execute(
            """
            SELECT id, title, storage_tier, original_uri, reader_uri, location_uri, updated_at, metadata_json
            FROM books
            WHERE status = 'active'
            ORDER BY updated_at ASC
            LIMIT ?
            """,
            (max(1, int(limit)),),
        ).fetchall()
        now = utc_now()
        now_dt = dt.datetime.now(dt.UTC).replace(microsecond=0)
        for row in rows:
            age_days = 9999
            try:
                updated = _parse_utc_timestamp(row["updated_at"])
                age_days = max(0, int((now_dt - updated).total_seconds() // 86400))
            except Exception:
                pass
            tier = row["storage_tier"]
            target = tier
            if tier == "hot" and age_days >= hot_days:
                target = "warm"
            elif tier == "warm" and age_days >= warm_days:
                target = "cold"
            if target == tier:
                continue
            action = {"book_id": row["id"], "from": tier, "to": target, "age_days": age_days}
            original_uri = row["original_uri"]
            reader_uri = row["reader_uri"]
            moved_files: list[dict[str, Any]] = []
            for field, base, uri, target_tier in (
                ("original_uri", root / "archive" / "originals", original_uri, target),
                ("reader_uri", root / "archive" / "reader_editions", reader_uri, "cold" if target == "vault" else target),
            ):
                if not uri:
                    continue
                source_path = resolve_stored_uri(root, uri)
                destination = base / target_tier / source_path.name
                target_uri = continuum_uri(root, destination)
                move_detail = {
                    "field": field,
                    "from_uri": str(uri),
                    "to_uri": target_uri,
                    "moved": False,
                }
                try:
                    same_path = source_path.resolve(strict=False) == destination.resolve(strict=False)
                    inside_root = source_path.resolve(strict=False).is_relative_to(root.resolve(strict=False))
                except OSError:
                    same_path = False
                    inside_root = False
                if same_path:
                    move_detail["reason"] = "already_in_target_tier"
                elif not inside_root:
                    move_detail["reason"] = "external_uri_not_moved"
                elif not source_path.exists():
                    move_detail["reason"] = "source_missing"
                else:
                    if not dry_run:
                        secure_move_file(source_path, destination)
                    move_detail["moved"] = True
                if field == "original_uri" and (move_detail["moved"] or same_path):
                    original_uri = target_uri
                if field == "reader_uri" and (move_detail["moved"] or same_path):
                    reader_uri = target_uri
                moved_files.append(move_detail)
            action["files"] = moved_files
            actions.append(action)
            if dry_run:
                continue
            metadata = json_loads(row["metadata_json"], {})
            metadata.setdefault("tier_history", []).append(
                {"from": tier, "to": target, "at": now, "reason": "retention_age", "files": moved_files}
            )
            location_uri = original_uri if row["location_uri"] == row["original_uri"] else row["location_uri"]
            conn.execute(
                """
                UPDATE books
                SET storage_tier = ?, original_uri = ?, reader_uri = ?, location_uri = ?,
                    last_tiered_at = ?, metadata_json = ?, updated_at = ?
                WHERE id = ?
                """,
                (target, original_uri, reader_uri, location_uri, now, json_dumps(metadata), now, row["id"]),
            )
        if not dry_run:
            audit_event(conn, action="archivist_apply_storage_tiering", target_type="books", target_id=None, payload={"actions": actions})
            conn.commit()
        return {"ok": True, "dry_run": dry_run, "action_count": len(actions), "actions": actions}
    finally:
        conn.close()


def prune_memory(
    root: Path,
    *,
    topic: str | None = None,
    action: str = "archive",
    dry_run: bool = False,
    limit: int = 100,
    allow_global: bool = False,
) -> dict[str, Any]:
    if action not in {"archive", "summarize_only", "forget"}:
        raise ValueError("action must be archive, summarize_only, or forget")
    if not topic and not allow_global:
        raise ValueError("prune_memory requires a topic unless allow_global=True")
    init_db(root)
    conn = connect(root)
    try:
        pattern = f"%{topic}%" if topic else "%"
        rows = conn.execute(
            """
            SELECT id, title, summary, topics_json, metadata_json
            FROM cards
            WHERE status != 'pruned'
              AND (title LIKE ? OR summary LIKE ? OR topics_json LIKE ?)
            ORDER BY salience ASC, updated_at ASC
            LIMIT ?
            """,
            (pattern, pattern, pattern, max(1, int(limit))),
        ).fetchall()
        target_status = {"archive": "archived", "summarize_only": "summary_only", "forget": "pruned"}[action]
        now = utc_now()
        touched: list[str] = []
        for row in rows:
            touched.append(row["id"])
            if dry_run:
                continue
            metadata = json_loads(row["metadata_json"], {})
            metadata.setdefault("prune_history", []).append({"action": action, "topic": topic, "at": now})
            conn.execute(
                "UPDATE cards SET status = ?, metadata_json = ?, updated_at = ? WHERE id = ?",
                (target_status, json_dumps(metadata), now, row["id"]),
            )
        if not dry_run:
            audit_event(conn, action="librarian_prune_memory", target_type="cards", target_id=None, payload={"action": action, "topic": topic, "card_ids": touched})
            mark_card_sidecar_outbox(conn, touched, reason="memory_pruned")
            conn.commit()
            sync_card_sidecars_after_commit(root, touched)
        return {"ok": True, "dry_run": dry_run, "action": action, "topic": topic, "card_count": len(touched), "card_ids": touched}
    finally:
        conn.close()


def sync_card_sidecar_job(root: Path, *, card_id: str) -> dict[str, Any]:
    conn = connect(root)
    try:
        location_uri = sync_card_sidecar(root, conn, card_id)
        if location_uri is None:
            audit_event(
                conn,
                action="card_sidecar_sync_skipped",
                target_type="card",
                target_id=card_id,
                payload={"reason": "card_missing_or_sidecars_disabled"},
            )
            conn.execute("DELETE FROM card_sidecar_outbox WHERE card_id = ?", (card_id,))
            conn.commit()
            return {"ok": False, "reason": "card_missing_or_sidecars_disabled", "card_id": card_id}
        audit_event(
            conn,
            action="card_sidecar_synced",
            target_type="card",
            target_id=card_id,
            payload={"location_uri": location_uri, "worker": "archivist"},
        )
        conn.execute("DELETE FROM card_sidecar_outbox WHERE card_id = ?", (card_id,))
        conn.commit()
        return {"ok": True, "card_id": card_id, "location_uri": location_uri}
    finally:
        conn.close()


def drain_card_sidecar_outbox(root: Path, *, limit: int = 50) -> dict[str, Any]:
    init_db(root)
    conn = connect(root)
    try:
        rows = conn.execute(
            """
            SELECT card_id
            FROM card_sidecar_outbox
            ORDER BY updated_at ASC
            LIMIT ?
            """,
            (max(1, int(limit)),),
        ).fetchall()
    finally:
        conn.close()
    card_ids = [str(row["card_id"]) for row in rows]
    if not card_ids:
        return {"ok": True, "pending": 0, "synced": 0, "failed": 0, "failures": []}
    result = sync_card_sidecars_after_commit(root, card_ids)
    return {
        "ok": bool(result.get("ok")),
        "pending": len(card_ids),
        "synced": int(result.get("synced", 0)),
        "failed": int(result.get("failed", 0)),
        "failures": result.get("failures", []),
    }


def _process_job(root: Path, job: dict[str, Any]) -> dict[str, Any]:
    payload = json_loads(job.get("payload_json"), {})
    job_type = job["job_type"]
    if job_type == "scroll_event_ingested":
        return roll_due_scroll_segments(root, session_id=payload.get("session_id"))
    if job_type == "review_card_placement":
        return review_card_placement(root, card_id=str(payload["card_id"]))
    if job_type == "verify_book_integrity":
        return verify_book_integrity(root, book_id=str(payload["book_id"]), content_hash_value=payload.get("content_hash"))
    if job_type == "verify_segment_integrity":
        return verify_segment_integrity(root, segment_id=str(payload["segment_id"]), segment_hash=payload.get("segment_hash"))
    if job_type == "sync_card_sidecar":
        return sync_card_sidecar_job(root, card_id=str(payload["card_id"]))
    if job_type == "review_mempalace_import":
        return {"ok": True, "reviewed_import": payload.get("import_id")}
    return {"ok": True, "skipped": True, "reason": "unknown_job_type", "job_type": job_type}


def run_worker_pass(
    root: Path,
    *,
    roles: list[str] | None = None,
    limit: int = 50,
    maintenance: bool = True,
) -> dict[str, Any]:
    init_db(root)
    config = load_config(root)
    lease_seconds = max(30, int(config.get("queues", {}).get("worker_lease_seconds", 3600)))
    worker_id = unique_id("worker")
    role_set = set(roles or []) or None
    processed: list[dict[str, Any]] = []
    reclaimed_expired_jobs = 0
    for _ in range(max(1, int(limit))):
        conn = connect(root)
        try:
            conn.execute("BEGIN IMMEDIATE")
            reclaimed_expired_jobs += _reclaim_expired_leases(conn, role_set)
            job = _claim_job(conn, role_set, lease_owner=worker_id, lease_seconds=lease_seconds)
            conn.commit()
        finally:
            conn.close()
        if job is None:
            break
        try:
            result = _process_job(root, job)
            job_ok = bool(result.get("ok", True))
            job_status = "skipped" if result.get("skipped") else ("succeeded" if job_ok else "failed")
            conn = connect(root)
            try:
                _finish_owned_job(
                    conn,
                    job["id"],
                    lease_owner=worker_id,
                    lease_seconds=lease_seconds,
                    status=job_status,
                    result=result,
                    error=None if job_ok else str(result.get("reason") or result.get("error") or "worker result reported ok=false"),
                )
                conn.commit()
            finally:
                conn.close()
            processed.append({"job_id": job["id"], "role": job["role"], "job_type": job["job_type"], "status": job_status, "ok": job_ok, "result": result})
        except Exception as exc:
            conn = connect(root)
            try:
                _finish_job(conn, job["id"], status="failed", error=str(exc), lease_owner=worker_id)
                conn.commit()
            finally:
                conn.close()
            processed.append({"job_id": job["id"], "role": job["role"], "job_type": job["job_type"], "ok": False, "error": str(exc)})
    maintenance_result: dict[str, Any] = {}
    if maintenance:
        maintenance_result["sidecars"] = drain_card_sidecar_outbox(root, limit=50)
        maintenance_result["decay"] = decay_graph_routes(root, limit=50)
        maintenance_result["tiering"] = apply_storage_tiering(root, dry_run=False, limit=50)
        maintenance_result["conflicts"] = detect_conflicts(root, limit=25)
    return {
        "ok": all(item.get("ok", False) for item in processed) if processed else True,
        "worker_id": worker_id,
        "lease_seconds": lease_seconds,
        "reclaimed_expired_jobs": reclaimed_expired_jobs,
        "processed_count": len(processed),
        "processed": processed,
        "maintenance": maintenance_result,
    }


def serve_workers(
    root: Path,
    *,
    roles: list[str] | None = None,
    limit: int = 0,
    interval_seconds: float = 5.0,
) -> dict[str, Any]:
    passes = 0
    processed = 0
    while True:
        result = run_worker_pass(root, roles=roles, limit=50, maintenance=True)
        passes += 1
        processed += int(result.get("processed_count", 0))
        if limit and passes >= limit:
            return {"ok": True, "passes": passes, "processed_count": processed}
        time.sleep(max(0.1, float(interval_seconds)))


def memory_health(root: Path) -> dict[str, Any]:
    if not is_initialized(root):
        return {"ok": False, "initialized": False, "root": str(root), "reason": "catalog_missing"}
    config = load_config(root) if config_path(root).exists() else default_config()
    conn = connect_existing(root)
    try:
        pending_jobs = conn.execute("SELECT count(*) AS n FROM queue_jobs WHERE status = 'pending'").fetchone()["n"]
        failed_jobs = conn.execute("SELECT count(*) AS n FROM queue_jobs WHERE status = 'failed'").fetchone()["n"]
        pending_cards = conn.execute("SELECT count(*) AS n FROM cards WHERE status = 'pending_librarian_review'").fetchone()["n"]
        pruned_edges = conn.execute("SELECT count(*) AS n FROM graph_edges WHERE status = 'pruned'").fetchone()["n"]
        last_event = conn.execute("SELECT max(created_at) AS ts FROM scroll_events").fetchone()["ts"]
        root_size = _root_size_bytes(root)
        max_root_size = parse_size(config.get("retention", {}).get("max_root_size", "50GB"))
        checks = [
            {"name": "capture_configured", "ok": bool(config.get("capture", {}).get("mode"))},
            {"name": "queue_backlog_reasonable", "ok": pending_jobs < 1000, "pending_jobs": pending_jobs},
            {"name": "no_failed_jobs", "ok": failed_jobs == 0, "failed_jobs": failed_jobs},
            {"name": "librarian_backlog_reasonable", "ok": pending_cards < 1000, "pending_librarian_cards": pending_cards},
            {"name": "root_size_within_budget", "ok": root_size <= max_root_size, "root_size_bytes": root_size, "max_root_size": max_root_size},
        ]
        return {
            "ok": all(check["ok"] for check in checks),
            "initialized": True,
            "root": str(root),
            "last_scroll_event_at": last_event,
            "pending_jobs": pending_jobs,
            "failed_jobs": failed_jobs,
            "pending_librarian_cards": pending_cards,
            "pruned_graph_edges": pruned_edges,
            "root_size_bytes": root_size,
            "checks": checks,
        }
    finally:
        conn.close()


def maybe_maintain_after_capture(root: Path, *, session_id: str) -> dict[str, Any]:
    config = load_config(root)
    capture = config.get("capture", {})
    if str(capture.get("mode", "automatic")) not in {"automatic", "paranoid"}:
        return {"ok": True, "skipped": True, "reason": "capture_mode_not_automatic"}
    rolled = roll_due_scroll_segments(root, session_id=session_id, force=False)
    maintenance = {}
    if str(capture.get("mode")) == "paranoid":
        maintenance = run_worker_pass(root, roles=["librarian", "archivist"], limit=10, maintenance=True)
        snapshot(root, reason="paranoid_capture_maintenance")
    return {"ok": True, "rolled": rolled, "maintenance": maintenance}
