from __future__ import annotations

import datetime as dt
import time
from pathlib import Path
from typing import Any

from .config import load_config, retention_policy
from .store import (
    add_graph_edge,
    audit_event,
    connect,
    connect_existing,
    content_hash,
    estimate_tokens,
    extract_terms,
    file_sha256,
    init_db,
    is_initialized,
    json_dumps,
    json_loads,
    resolve_stored_uri,
    roll_scroll_segment,
    segment_hash_material,
    snapshot,
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
    for path in root.rglob("*"):
        if path.is_symlink():
            continue
        if path.is_file():
            try:
                total += path.stat().st_size
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
    params: list[Any] = [utc_now()]
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
        [PENDING_JOB_STATUS, utc_now(), json_dumps({"reclaimed": True, "reason": "worker_lease_expired"}), ACTIVE_JOB_STATUS, *params],
    )
    return int(cursor.rowcount or 0)


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


def roll_due_scroll_segments(root: Path, *, session_id: str | None = None, force: bool = False) -> dict[str, Any]:
    init_db(root)
    config = load_config(root)
    threshold = int(config.get("capture", {}).get("roll_segments_every_events", 200))
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
                conn.close()
                result = roll_scroll_segment(root, session_id=current_session, start_seq=start, end_seq=end)
                rolled.append(result)
                conn = connect(root)
                start = end + 1
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
        conn.commit()
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
        rows = conn.execute(
            """
            SELECT id, weight, decay_count, pinned
            FROM graph_edges
            WHERE status = 'active' AND pinned = 0
              AND (? <= 0 OR last_decay_at IS NULL OR last_decay_at <= ?)
            ORDER BY coalesce(last_used_at, created_at) ASC
            LIMIT ?
            """,
            (min_interval, cutoff, max(1, int(limit))),
        ).fetchall()
        decayed = 0
        pruned = 0
        now = utc_now()
        for row in rows:
            new_decay = int(row["decay_count"] or 0) + 1
            new_weight = max(weight_floor, float(row["weight"] or 0.25) * weight_factor)
            status = "pruned" if new_decay >= prune_threshold and new_weight < prune_weight_threshold else "active"
            if status == "pruned":
                pruned += 1
            else:
                decayed += 1
            conn.execute(
                "UPDATE graph_edges SET weight = ?, decay_count = ?, status = ?, last_decay_at = ?, updated_at = ? WHERE id = ?",
                (new_weight, new_decay, status, now, now, row["id"]),
            )
        audit_event(
            conn,
            action="librarian_decay_routes",
            target_type="graph",
            target_id=None,
            payload={"decayed": decayed, "pruned": pruned, "min_interval_seconds": min_interval},
        )
        conn.commit()
        return {"ok": True, "decayed": decayed, "pruned": pruned, "skipped_recent": max(0, int(limit) - len(rows)) if min_interval > 0 else 0, "min_interval_seconds": min_interval}
    finally:
        conn.close()


def detect_conflicts(root: Path, *, card_id: str | None = None, limit: int = 50) -> dict[str, Any]:
    init_db(root)
    conn = connect(root)
    try:
        if card_id:
            candidates = conn.execute("SELECT id, title, summary FROM cards WHERE id = ?", (card_id,)).fetchall()
        else:
            candidates = conn.execute(
                "SELECT id, title, summary FROM cards WHERE status != 'pruned' ORDER BY updated_at DESC LIMIT ?",
                (max(1, int(limit)),),
            ).fetchall()
        conflicts: list[dict[str, Any]] = []
        now = utc_now()
        for card in candidates:
            terms = extract_terms(f"{card['title']} {card['summary']}", limit=6)
            if not terms:
                continue
            pattern = f"%{terms[0]}%"
            others = conn.execute(
                """
                SELECT id, title, summary
                FROM cards
                WHERE id != ? AND status != 'pruned'
                  AND (title LIKE ? OR summary LIKE ?)
                LIMIT 5
                """,
                (card["id"], pattern, pattern),
            ).fetchall()
            negative = any(word in card["summary"].casefold() for word in (" not ", " no ", "never", "disable", "removed"))
            for other in others:
                other_negative = any(word in other["summary"].casefold() for word in (" not ", " no ", "never", "disable", "removed"))
                if negative == other_negative and card["title"].casefold() != other["title"].casefold():
                    continue
                group = content_hash("|".join(sorted([card["id"], other["id"]]))[:512])[:16]
                conn.execute("UPDATE cards SET conflict_group = ?, updated_at = ? WHERE id IN (?, ?)", (group, now, card["id"], other["id"]))
                conflicts.append({"conflict_group": group, "card_ids": [card["id"], other["id"]]})
                audit_event(conn, action="librarian_detect_conflict", target_type="card", target_id=card["id"], payload={"other_card_id": other["id"], "conflict_group": group})
        conn.commit()
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
            SELECT id, title, storage_tier, original_uri, reader_uri, updated_at, metadata_json
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
            actions.append(action)
            if dry_run:
                continue
            metadata = json_loads(row["metadata_json"], {})
            metadata.setdefault("tier_history", []).append({"from": tier, "to": target, "at": now, "reason": "retention_age"})
            conn.execute(
                """
                UPDATE books
                SET storage_tier = ?, last_tiered_at = ?, metadata_json = ?, updated_at = ?
                WHERE id = ?
                """,
                (target, now, json_dumps(metadata), now, row["id"]),
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
            conn.commit()
        return {"ok": True, "dry_run": dry_run, "action": action, "topic": topic, "card_count": len(touched), "card_ids": touched}
    finally:
        conn.close()


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
    config = load_config(root)
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
