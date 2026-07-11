from __future__ import annotations

import datetime as dt
import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from .config import config_path, default_config, load_config, retention_policy
from .operations import operation_lock
from .permissions import secure_move_file
from .store import (
    add_graph_edge,
    audit_event,
    canonical_partition_identifier,
    connect,
    connect_existing,
    content_hash,
    continuum_uri,
    enqueue_job,
    extract_terms,
    file_sha256,
    init_db,
    is_initialized,
    json_dumps,
    json_loads,
    mark_card_sidecar_outbox,
    NON_CURRENT_CARD_STATUSES,
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
DEFAULT_BACKLOG_RECONCILE_LIMIT = 5000
MAX_BACKLOG_RECONCILE_LIMIT = 10000
DEFAULT_WORKER_MAINTENANCE_INTERVAL_SECONDS = 300.0
# A single notification may represent an arbitrarily large per-session backlog
# because Scroll appends deliberately deduplicate pending Scribe jobs. Drain more
# than one window, but yield after a bounded amount of work and leave a durable
# continuation for the same session.
MAX_SCRIBE_SEGMENT_BATCHES_PER_RUN = 64
_WORKER_SERVICE_ROOTS: set[str] = set()
_WORKER_SERVICE_ROOTS_GUARD = threading.Lock()


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
        role_clause = f" AND queue_jobs.role IN ({placeholders})"
        params.extend(sorted(roles))
    superseded_cursor = conn.execute(
        f"""
        UPDATE queue_jobs
        SET status = 'skipped', finished_at = ?, lease_owner = NULL,
            lease_expires_at = NULL, heartbeat_at = NULL, updated_at = ?,
            error_json = ?
        WHERE status = ?
          AND preemptible = 1
          AND lease_expires_at IS NOT NULL
          AND lease_expires_at <= ?
          AND dedupe_key IS NOT NULL
          AND EXISTS (
              SELECT 1
              FROM queue_jobs AS pending
              WHERE pending.status = ?
                AND pending.dedupe_key = queue_jobs.dedupe_key
                AND pending.id != queue_jobs.id
          ){role_clause}
        """,
        [
            now,
            now,
            json_dumps(
                {
                    "error": None,
                    "result": {
                        "skipped": True,
                        "reason": "expired_lease_superseded_by_pending_dedupe_job",
                    },
                }
            ),
            ACTIVE_JOB_STATUS,
            now,
            PENDING_JOB_STATUS,
            *params[1:],
        ],
    )
    superseded = int(superseded_cursor.rowcount or 0)
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
    return superseded + reclaimed + int(failed_cursor.rowcount or 0)


def _claim_job(conn, roles: set[str] | None = None, *, lease_owner: str, lease_seconds: int) -> dict[str, Any] | None:
    params: list[Any] = [PENDING_JOB_STATUS]
    role_clause = ""
    if roles:
        placeholders = ",".join("?" for _ in roles)
        role_clause = f" AND pending_job.role IN ({placeholders})"
        params.extend(sorted(roles))
    row = conn.execute(
        f"""
        SELECT pending_job.*
        FROM queue_jobs AS pending_job
        WHERE pending_job.status = ?{role_clause}
          AND (
              pending_job.dedupe_key IS NULL
              OR NOT EXISTS (
                  SELECT 1
                  FROM queue_jobs AS active_job
                  WHERE active_job.status = '{ACTIVE_JOB_STATUS}'
                    AND active_job.dedupe_key = pending_job.dedupe_key
              )
          )
        ORDER BY pending_job.priority ASC, pending_job.created_at ASC
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


def _bounded_reconcile_limit(value: int, *, field: str) -> int:
    limit = int(value)
    if limit <= 0:
        raise ValueError(f"{field} must be positive")
    if limit > MAX_BACKLOG_RECONCILE_LIMIT:
        raise ValueError(f"{field} must be at most {MAX_BACKLOG_RECONCILE_LIMIT}")
    return limit


_REDUNDANT_SCRIBE_CTE = """
WITH base AS (
    SELECT id, created_at,
           CASE WHEN json_valid(payload_json)
                THEN json_extract(payload_json, '$.session_id')
                ELSE NULL
           END AS session_id
    FROM queue_jobs
    WHERE status = 'pending' AND job_type = 'scroll_event_ingested'
), ranked AS (
    SELECT id, created_at, session_id,
           first_value(id) OVER (
               PARTITION BY session_id
               ORDER BY created_at DESC, id DESC
               ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
           ) AS keeper_job_id,
           row_number() OVER (
               PARTITION BY session_id
               ORDER BY created_at DESC, id DESC
           ) AS session_ordinal
    FROM base
    WHERE typeof(session_id) = 'text' AND trim(session_id) != ''
)
"""


def _redundant_scribe_notifications(conn, *, limit: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        _REDUNDANT_SCRIBE_CTE
        + """
        SELECT id, session_id, keeper_job_id, created_at
        FROM ranked
        WHERE session_ordinal > 1
        ORDER BY session_id, created_at, id
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def _count_redundant_scribe_notifications(conn) -> int:
    row = conn.execute(
        _REDUNDANT_SCRIBE_CTE
        + """
        SELECT count(*) AS n
        FROM ranked
        WHERE session_ordinal > 1
        """
    ).fetchone()
    return int(row["n"] or 0)


def _legacy_card_where(*, import_id: str | None = None) -> tuple[str, list[Any]]:
    type_clause = "(c.card_type = 'project_state' OR c.card_type LIKE 'mempalace_%')"
    params: list[Any] = []
    if import_id is not None:
        type_clause = "c.card_type LIKE 'mempalace_%'"
        import_clause = """
          AND CASE WHEN json_valid(c.metadata_json)
                   THEN json_extract(c.metadata_json, '$.import_id')
                   ELSE NULL
              END = ?
        """
        params.append(import_id)
    else:
        import_clause = ""
    return (
        f"""
        c.status = 'pending_librarian_review'
        AND {type_clause}
        {import_clause}
        AND EXISTS (
            SELECT 1
            FROM graph_nodes n
            WHERE n.card_id = c.id
              AND (
                  EXISTS (
                      SELECT 1
                      FROM graph_edges e
                      WHERE e.source_node_id = n.id AND e.status = 'active'
                  )
                  OR EXISTS (
                      SELECT 1
                      FROM graph_edges e
                      WHERE e.target_node_id = n.id AND e.status = 'active'
                  )
              )
        )
        AND NOT EXISTS (
            SELECT 1
            FROM queue_jobs q
            WHERE q.status IN ('pending', 'running')
              AND q.job_type = 'review_card_placement'
              AND (
                  CASE WHEN json_valid(q.payload_json)
                       THEN json_extract(q.payload_json, '$.card_id')
                       ELSE NULL
                  END = c.id
                  OR EXISTS (
                      SELECT 1
                      FROM json_each(
                          CASE WHEN json_valid(q.related_card_ids_json)
                               THEN q.related_card_ids_json
                               ELSE '[]'
                          END
                      ) related
                      WHERE related.value = c.id
                  )
              )
        )
        """,
        params,
    )


def _legacy_card_candidates(conn, *, limit: int, import_id: str | None = None) -> list[dict[str, Any]]:
    where_clause, params = _legacy_card_where(import_id=import_id)
    rows = conn.execute(
        f"""
        SELECT c.id, c.card_type, c.project_id, c.metadata_json, c.created_at
        FROM cards c
        WHERE {where_clause}
        ORDER BY c.created_at, c.id
        LIMIT ?
        """,
        (*params, limit),
    ).fetchall()
    return [dict(row) for row in rows]


def _count_legacy_card_candidates(conn, *, import_id: str | None = None) -> int:
    where_clause, params = _legacy_card_where(import_id=import_id)
    row = conn.execute(f"SELECT count(*) AS n FROM cards c WHERE {where_clause}", params).fetchone()
    return int(row["n"] or 0)


def _count_genuine_pending_card_reviews(conn) -> int:
    row = conn.execute(
        """
        SELECT count(DISTINCT c.id) AS n
        FROM cards c
        WHERE c.status = 'pending_librarian_review'
          AND EXISTS (
              SELECT 1
              FROM queue_jobs q
              WHERE q.status IN ('pending', 'running')
                AND q.job_type = 'review_card_placement'
                AND (
                    CASE WHEN json_valid(q.payload_json)
                         THEN json_extract(q.payload_json, '$.card_id')
                         ELSE NULL
                    END = c.id
                    OR EXISTS (
                        SELECT 1
                        FROM json_each(
                            CASE WHEN json_valid(q.related_card_ids_json)
                                 THEN q.related_card_ids_json
                                 ELSE '[]'
                            END
                        ) related
                        WHERE related.value = c.id
                    )
                )
          )
        """
    ).fetchone()
    return int(row["n"] or 0)


def _legacy_unqueued_card_reviews(conn, *, limit: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT c.id, c.card_type, c.project_id, c.metadata_json, c.created_at
        FROM cards c
        WHERE c.status = 'pending_librarian_review'
          AND (c.card_type = 'project_state' OR c.card_type LIKE 'mempalace_%')
          AND NOT EXISTS (
              SELECT 1
              FROM graph_nodes n
              WHERE n.card_id = c.id
                AND (
                    EXISTS (
                        SELECT 1 FROM graph_edges e
                        WHERE e.source_node_id = n.id AND e.status = 'active'
                    )
                    OR EXISTS (
                        SELECT 1 FROM graph_edges e
                        WHERE e.target_node_id = n.id AND e.status = 'active'
                    )
                )
          )
          AND NOT EXISTS (
              SELECT 1
              FROM queue_jobs q
              WHERE q.status IN ('pending', 'running')
                AND q.job_type = 'review_card_placement'
                AND (
                    CASE WHEN json_valid(q.payload_json)
                         THEN json_extract(q.payload_json, '$.card_id')
                         ELSE NULL
                    END = c.id
                    OR EXISTS (
                        SELECT 1
                        FROM json_each(
                            CASE WHEN json_valid(q.related_card_ids_json)
                                 THEN q.related_card_ids_json
                                 ELSE '[]'
                            END
                        ) related
                        WHERE related.value = c.id
                    )
                )
          )
        ORDER BY c.created_at, c.id
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def _count_legacy_unqueued_card_reviews(conn) -> int:
    return len(_legacy_unqueued_card_reviews(conn, limit=MAX_BACKLOG_RECONCILE_LIMIT))


def _enqueue_legacy_card_reviews(conn, cards: list[dict[str, Any]]) -> list[str]:
    job_ids: list[str] = []
    for card in cards:
        card_id = str(card["id"])
        job_id = enqueue_job(
            conn,
            role="librarian",
            job_type="review_card_placement",
            priority=70,
            payload={"card_id": card_id, "reason": "legacy_missing_librarian_job"},
            related_card_ids=[card_id],
            dedupe_key=f"card:{card_id}",
        )
        job_ids.append(job_id)
        audit_event(
            conn,
            action="enqueue_legacy_card_review",
            target_type="card",
            target_id=card_id,
            payload={"job_id": job_id, "card_type": card["card_type"]},
            actor="worker",
        )
    return job_ids


def _legacy_card_placement(card: dict[str, Any]) -> tuple[str, str]:
    metadata = json_loads(card.get("metadata_json"), {})
    card_type = str(card.get("card_type") or "")
    if card_type == "project_state":
        project_id = str(card.get("project_id") or metadata.get("project_id") or "project_state").strip()
        return "projects", project_id.casefold()[:96] or "project_state"
    wing = str(metadata.get("mempalace_wing") or "mempalace").strip()
    room = str(metadata.get("mempalace_room") or "unshelved").strip()
    shelf = "/".join(part for part in (wing, room) if part).casefold()
    return "mempalace", shelf[:96] or "mempalace"


def _apply_graph_placed_card_reconciliation(
    conn,
    cards: list[dict[str, Any]],
    *,
    reason: str,
) -> list[str]:
    changed: list[str] = []
    now = utc_now()
    for card in cards:
        collection, shelf = _legacy_card_placement(card)
        cursor = conn.execute(
            """
            UPDATE cards
            SET status = 'active',
                placement_collection = coalesce(placement_collection, ?),
                shelf = coalesce(shelf, ?),
                storage_tier = coalesce(storage_tier, 'hot'),
                updated_at = ?
            WHERE id = ? AND status = 'pending_librarian_review'
            """,
            (collection, shelf, now, card["id"]),
        )
        if int(cursor.rowcount or 0) != 1:
            continue
        changed.append(str(card["id"]))
        audit_event(
            conn,
            action="reconcile_graph_placed_card",
            target_type="card",
            target_id=str(card["id"]),
            payload={
                "reason": reason,
                "card_type": card["card_type"],
                "previous_status": "pending_librarian_review",
                "status": "active",
                "placement_collection": collection,
                "shelf": shelf,
            },
            actor="worker",
        )
    if changed:
        mark_card_sidecar_outbox(conn, changed, reason=reason)
    return changed


def _apply_redundant_scribe_reconciliation(conn, jobs: list[dict[str, Any]]) -> list[str]:
    changed: list[str] = []
    now = utc_now()
    for job in jobs:
        result = {
            "skipped": True,
            "reason": "superseded_pending_scroll_notification",
            "session_id": job["session_id"],
            "keeper_job_id": job["keeper_job_id"],
        }
        cursor = conn.execute(
            """
            UPDATE queue_jobs
            SET status = 'skipped', finished_at = ?, updated_at = ?,
                error_json = ?, lease_owner = NULL, lease_expires_at = NULL,
                heartbeat_at = ?
            WHERE id = ? AND status = 'pending'
            """,
            (now, now, json_dumps({"error": None, "result": result}), now, job["id"]),
        )
        if int(cursor.rowcount or 0) != 1:
            continue
        changed.append(str(job["id"]))
        audit_event(
            conn,
            action="supersede_redundant_scribe_notification",
            target_type="queue_job",
            target_id=str(job["id"]),
            payload=result,
            actor="worker",
        )
    return changed


def reconcile_worker_backlog(
    root: Path,
    *,
    dry_run: bool = True,
    queue_limit: int = DEFAULT_BACKLOG_RECONCILE_LIMIT,
    card_limit: int = DEFAULT_BACKLOG_RECONCILE_LIMIT,
) -> dict[str, Any]:
    """Reconcile legacy worker backlog without deleting queue or card evidence."""
    queue_limit = _bounded_reconcile_limit(queue_limit, field="queue_limit")
    card_limit = _bounded_reconcile_limit(card_limit, field="card_limit")
    if not is_initialized(root):
        return {"ok": False, "initialized": False, "root": str(root), "reason": "catalog_missing", "dry_run": dry_run}

    if not dry_run:
        init_db(root)
    conn = connect_existing(root) if dry_run else connect(root)
    changed_jobs: list[str] = []
    changed_cards: list[str] = []
    enqueued_card_review_jobs: list[str] = []
    try:
        if not dry_run:
            conn.execute("BEGIN IMMEDIATE")
        redundant_before = _count_redundant_scribe_notifications(conn)
        card_candidates_before = _count_legacy_card_candidates(conn)
        unqueued_card_reviews_before = _count_legacy_unqueued_card_reviews(conn)
        genuine_reviews_before = _count_genuine_pending_card_reviews(conn)
        jobs = _redundant_scribe_notifications(conn, limit=queue_limit)
        cards = _legacy_card_candidates(conn, limit=card_limit)
        unqueued_cards = _legacy_unqueued_card_reviews(conn, limit=max(0, card_limit - len(cards)))
        if not dry_run:
            changed_jobs = _apply_redundant_scribe_reconciliation(conn, jobs)
            changed_cards = _apply_graph_placed_card_reconciliation(
                conn,
                cards,
                reason="legacy_graph_placed_card_reconciliation",
            )
            enqueued_card_review_jobs = _enqueue_legacy_card_reviews(conn, unqueued_cards)
            conn.commit()
        redundant_remaining = _count_redundant_scribe_notifications(conn) if not dry_run else redundant_before
        card_candidates_remaining = _count_legacy_card_candidates(conn) if not dry_run else card_candidates_before
        unqueued_card_reviews_remaining = (
            _count_legacy_unqueued_card_reviews(conn) if not dry_run else unqueued_card_reviews_before
        )
        genuine_reviews_after = _count_genuine_pending_card_reviews(conn)
    except Exception:
        if not dry_run:
            conn.rollback()
        raise
    finally:
        conn.close()

    sidecars: dict[str, Any] = {"ok": True, "synced": 0, "failed": 0, "skipped": dry_run}
    if changed_cards:
        sidecars = sync_card_sidecars_after_commit(root, changed_cards)
    return {
        "ok": bool(sidecars.get("ok", True)),
        "initialized": True,
        "root": str(root),
        "dry_run": dry_run,
        "limits": {"queue_limit": queue_limit, "card_limit": card_limit},
        "queue": {
            "redundant_before": redundant_before,
            "selected": len(jobs),
            "changed": len(changed_jobs),
            "remaining_redundant": redundant_remaining,
            "complete": redundant_remaining == 0,
            "keeper_strategy": "newest_pending_notification_per_session",
            "sample_job_ids": [str(item["id"]) for item in jobs[:25]],
        },
        "cards": {
            "eligible_before": card_candidates_before,
            "selected": len(cards),
            "changed": len(changed_cards),
            "remaining_eligible": card_candidates_remaining,
            "complete": card_candidates_remaining == 0 and unqueued_card_reviews_remaining == 0,
            "genuine_pending_reviews_before": genuine_reviews_before,
            "genuine_pending_reviews_after": genuine_reviews_after,
            "unqueued_reviews_before": unqueued_card_reviews_before,
            "unqueued_reviews_selected": len(unqueued_cards),
            "review_jobs_enqueued": len(enqueued_card_review_jobs),
            "unqueued_reviews_remaining": unqueued_card_reviews_remaining,
            "sample_review_job_ids": enqueued_card_review_jobs[:25],
            "sample_card_ids": [str(item["id"]) for item in cards[:25]],
        },
        "sidecars": sidecars,
    }


def review_mempalace_import(
    root: Path,
    *,
    import_id: str,
    limit: int = MAX_BACKLOG_RECONCILE_LIMIT,
) -> dict[str, Any]:
    """Complete Librarian placement for graph-linked cards from one MemPalace import."""
    import_id = str(import_id or "").strip()
    if not import_id:
        return {"ok": False, "reason": "import_id_missing", "reviewed_import": import_id}
    limit = _bounded_reconcile_limit(limit, field="limit")
    init_db(root)
    conn = connect(root)
    changed_cards: list[str] = []
    try:
        conn.execute("BEGIN IMMEDIATE")
        eligible_before = _count_legacy_card_candidates(conn, import_id=import_id)
        cards = _legacy_card_candidates(conn, limit=limit, import_id=import_id)
        changed_cards = _apply_graph_placed_card_reconciliation(
            conn,
            cards,
            reason="reviewed_mempalace_import",
        )
        remaining = _count_legacy_card_candidates(conn, import_id=import_id)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    sidecars: dict[str, Any] = {"ok": True, "synced": 0, "failed": 0}
    if changed_cards:
        sidecars = sync_card_sidecars_after_commit(root, changed_cards)
    return {
        "ok": remaining == 0 and bool(sidecars.get("ok", True)),
        "reviewed_import": import_id,
        "eligible_before": eligible_before,
        "reviewed_cards": len(changed_cards),
        "remaining_eligible": remaining,
        "limit": limit,
        "sidecars": sidecars,
    }


def _last_segment_end(conn, session_id: str) -> int:
    row = conn.execute(
        "SELECT coalesce(max(end_seq), 0) AS end_seq FROM scroll_segments WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    return int(row["end_seq"] or 0)


def _scroll_segment_backlog(conn, session_id: str, *, max_seq_limit: int | None = None) -> dict[str, int]:
    row = conn.execute(
        "SELECT coalesce(max(seq), 0) AS max_seq FROM scroll_events WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    max_seq = int(row["max_seq"] or 0)
    if max_seq_limit is not None:
        max_seq = min(max_seq, max(0, int(max_seq_limit)))
    frontier = _last_segment_end(conn, session_id)
    start_seq = frontier + 1
    return {
        "frontier": frontier,
        "start_seq": start_seq,
        "max_seq": max_seq,
        "pending_events": max(0, max_seq - start_seq + 1),
    }


def _ensure_scribe_continuation(root: Path, *, session_id: str, threshold: int) -> dict[str, Any]:
    """Atomically inspect the live frontier and retain one notification if due.

    The transaction closes the only dangerous gap: work arriving before this
    check is represented by the continuation created here, while work arriving
    after the commit sees either that pending dedupe row or the currently running
    job and creates/reuses a pending notification itself.
    """

    conn = connect(root)
    try:
        conn.execute("BEGIN IMMEDIATE")
        backlog = _scroll_segment_backlog(conn, session_id)
        continuation_job_id: str | None = None
        if backlog["pending_events"] >= threshold:
            continuation_job_id = enqueue_job(
                conn,
                role="scribe",
                job_type="scroll_event_ingested",
                priority=100,
                payload={
                    "session_id": session_id,
                    "seq": backlog["max_seq"],
                    "reason": "scroll_segment_backlog_continuation",
                },
                dedupe_key=f"session:{session_id}",
            )
        conn.commit()
        return {**backlog, "continuation_job_id": continuation_job_id}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


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
        assert run_end is not None
        if seq != run_end + 1 or boundary != run_boundary:
            runs.append((run_start, run_end))
            run_start = seq
            run_boundary = boundary
        run_end = seq
    if run_start is not None and run_end is not None:
        runs.append((int(run_start), int(run_end)))
    return runs


def roll_due_scroll_segments(
    root: Path,
    *,
    session_id: str | None = None,
    force: bool = False,
    heartbeat: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Roll eligible Scroll windows, renewing an owning worker lease as needed."""
    init_db(root)
    config = load_config(root)
    threshold = int(config.get("capture", {}).get("roll_segments_every_events", 200))
    if session_id:
        session_id = canonical_partition_identifier(root, "session_id", session_id, lookup=True)
    rolled: list[dict[str, Any]] = []
    batches_processed = 0
    concurrent_progress = 0
    continuations: list[dict[str, Any]] = []
    conn = connect(root)
    try:
        if session_id:
            sessions = [session_id]
        else:
            sessions = [
                row["session_id"]
                for row in conn.execute("SELECT DISTINCT session_id FROM scroll_events ORDER BY session_id")
            ]
    finally:
        conn.close()

    # Preserve explicit force semantics by fixing each session's upper bound at
    # invocation time. Non-forced work observes newly committed events but yields
    # after MAX_SCRIBE_SEGMENT_BATCHES_PER_RUN threshold windows.
    force_targets: dict[str, int] = {}
    if force:
        conn = connect(root)
        try:
            for current_session in sessions:
                force_targets[current_session] = _scroll_segment_backlog(conn, current_session)["max_seq"]
        finally:
            conn.close()

    for current_session in sessions:
        while force or batches_processed < MAX_SCRIBE_SEGMENT_BATCHES_PER_RUN:
            if heartbeat is not None and not heartbeat():
                raise RuntimeError("worker lease lost during Scribe segmentation")
            conn = connect(root)
            try:
                backlog = _scroll_segment_backlog(
                    conn,
                    current_session,
                    max_seq_limit=force_targets.get(current_session) if force else None,
                )
                pending = backlog["pending_events"]
                if pending <= 0 or (not force and pending < threshold):
                    break
                start = backlog["start_seq"]
                end = backlog["max_seq"] if force else min(backlog["max_seq"], start + threshold - 1)
                runs = _scroll_security_runs(
                    conn,
                    session_id=current_session,
                    start_seq=start,
                    end_seq=end,
                )
            finally:
                conn.close()
            if not runs:
                break

            batches_processed += 1
            retry_from_fresh_frontier = False
            for run_start, run_end in runs:
                try:
                    result = roll_scroll_segment(
                        root,
                        session_id=current_session,
                        start_seq=run_start,
                        end_seq=run_end,
                    )
                    if heartbeat is not None and not heartbeat():
                        raise RuntimeError("worker lease lost during Scribe segmentation")
                except ValueError:
                    # Another valid Scribe can win between the backlog read and
                    # the idempotent segment write. Only absorb the error when the
                    # authoritative frontier proves that concurrent progress
                    # covered at least the start of this exact run.
                    conn = connect(root)
                    try:
                        latest_frontier = _last_segment_end(conn, current_session)
                    finally:
                        conn.close()
                    if latest_frontier < run_start:
                        raise
                    concurrent_progress += 1
                    retry_from_fresh_frontier = True
                    break
                else:
                    rolled.append(result)
            if retry_from_fresh_frontier:
                continue

        if not force:
            continuation = _ensure_scribe_continuation(
                root,
                session_id=current_session,
                threshold=threshold,
            )
            if continuation["continuation_job_id"] is not None:
                continuations.append({"session_id": current_session, **continuation})

    return {
        "ok": True,
        "rolled_count": len(rolled),
        "rolled": rolled,
        "batches_processed": batches_processed,
        "batch_limit": None if force else MAX_SCRIBE_SEGMENT_BATCHES_PER_RUN,
        "drain_limited": bool(continuations),
        "continuations": continuations,
        "concurrent_progress": concurrent_progress,
    }


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


_CONFLICT_NEGATION_MARKERS = (" not ", " no ", "never", "disable", "removed")
_CONFLICT_DISMISSAL_METADATA_KEY = "dismissed_conflict_components"
_MAX_CONFLICT_DISMISSALS_PER_CARD = 8


def _load_temporal_card_state(conn) -> tuple[list[Any], dict[str, Any], set[str]]:
    rows = conn.execute("SELECT rowid AS card_rowid, * FROM cards ORDER BY rowid").fetchall()
    by_id = {str(row["id"]): row for row in rows}
    referenced_predecessors = {
        str(row["supersedes_card_id"])
        for row in rows
        if str(row["supersedes_card_id"] or "").strip()
    }
    current_ids = {
        card_id
        for card_id, row in by_id.items()
        if str(row["status"] or "").casefold() not in NON_CURRENT_CARD_STATUSES
        and not str(row["superseded_by_card_id"] or "").strip()
        and card_id not in referenced_predecessors
    }
    return rows, by_id, current_ids


def _supersession_graph(conn) -> dict[str, set[str]]:
    rows = conn.execute(
        "SELECT id, supersedes_card_id, superseded_by_card_id FROM cards ORDER BY id"
    ).fetchall()
    card_ids = {str(row["id"]) for row in rows}
    edges: dict[str, set[str]] = {card_id: set() for card_id in card_ids}
    for row in rows:
        card_id = str(row["id"])
        superseded_by = str(row["superseded_by_card_id"] or "").strip()
        supersedes = str(row["supersedes_card_id"] or "").strip()
        if superseded_by:
            if superseded_by not in card_ids:
                raise ValueError(
                    f"supersession graph references missing card: {card_id} -> {superseded_by}"
                )
            edges[card_id].add(superseded_by)
        if supersedes:
            if supersedes not in card_ids:
                raise ValueError(
                    f"supersession graph references missing card: {supersedes} -> {card_id}"
                )
            edges[supersedes].add(card_id)
    return edges


def _assert_supersession_dag(conn) -> dict[str, set[str]]:
    edges = _supersession_graph(conn)
    incoming = {card_id: 0 for card_id in edges}
    for targets in edges.values():
        for target in targets:
            incoming[target] += 1
    ready = sorted(card_id for card_id, count in incoming.items() if count == 0)
    visited = 0
    while ready:
        card_id = ready.pop()
        visited += 1
        for target in sorted(edges[card_id]):
            incoming[target] -= 1
            if incoming[target] == 0:
                ready.append(target)
    if visited != len(edges):
        cyclic = sorted(card_id for card_id, count in incoming.items() if count > 0)
        raise ValueError(f"supersession graph must be acyclic; cycle involves: {', '.join(cyclic)}")
    return edges


def _supersession_reaches(edges: dict[str, set[str]], start: str, target: str) -> bool:
    pending = [start]
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        if current == target:
            return True
        pending.extend(edges.get(current, ()))
    return False


def _conflict_boundary(card: Any) -> tuple[str, str, str]:
    scope = str(card["visibility_scope"] or "session")
    project_id = str(card["project_id"] or "")
    session_id = str(card["session_id"] or "")
    if scope == "project" and project_id:
        return ("project", project_id, "")
    if scope == "global":
        return ("global", "", "")
    return (scope, project_id, session_id)


def _conflict_signature(card: Any) -> dict[str, Any]:
    title = str(card["title"] or "").casefold().strip()
    summary = " ".join(str(card["summary"] or "").casefold().split())
    metadata = json_loads(card["metadata_json"], {})
    if not isinstance(metadata, dict):
        metadata = {}
    terms = tuple(dict.fromkeys(extract_terms(f"{title} {summary}", limit=12)))
    negative = summary.startswith(("no ", "not ")) or any(
        marker in f" {summary} " for marker in _CONFLICT_NEGATION_MARKERS
    )
    return {
        "card_type": str(card["card_type"] or "").casefold().strip(),
        "agent_id": str(metadata.get("agent_id") or "").casefold().strip(),
        "title": title,
        "summary": summary,
        "terms": terms,
        "term_set": set(terms),
        "anchor": terms[0] if terms else "",
        "negative": negative,
    }


def _conflict_card_types_compatible(left_type: str, right_type: str) -> bool:
    card_types = {str(left_type).casefold().strip(), str(right_type).casefold().strip()}
    return "project_state" not in card_types or len(card_types) == 1


def _conflict_component_fingerprint(by_id: dict[str, Any], member_ids: list[str]) -> str:
    material = [
        {
            "id": member_id,
            "card_type": str(by_id[member_id]["card_type"] or ""),
            "title": str(by_id[member_id]["title"] or ""),
            "summary": str(by_id[member_id]["summary"] or ""),
            "boundary": list(_conflict_boundary(by_id[member_id])),
        }
        for member_id in sorted(member_ids)
    ]
    return content_hash(json_dumps({"schema": "continuum.conflict_dismissal.v1", "members": material}))


def _conflict_component_is_suppressed(
    by_id: dict[str, Any],
    member_ids: list[str],
    fingerprint: str,
) -> bool:
    for member_id in member_ids:
        metadata = json_loads(by_id[member_id]["metadata_json"], {})
        entries = metadata.get(_CONFLICT_DISMISSAL_METADATA_KEY, []) if isinstance(metadata, dict) else []
        if not isinstance(entries, list):
            continue
        if any(
            isinstance(entry, dict) and str(entry.get("fingerprint") or "") == fingerprint
            for entry in entries[-_MAX_CONFLICT_DISMISSALS_PER_CARD:]
        ):
            return True
    return False


def _append_conflict_dismissal(
    metadata_json: str | None,
    *,
    fingerprint: str,
    member_count: int,
    dismissed_at: str,
) -> str:
    metadata = json_loads(metadata_json, {})
    if not isinstance(metadata, dict):
        metadata = {}
    raw_entries = metadata.get(_CONFLICT_DISMISSAL_METADATA_KEY, [])
    entries = [entry for entry in raw_entries if isinstance(entry, dict)] if isinstance(raw_entries, list) else []
    entries = [entry for entry in entries if str(entry.get("fingerprint") or "") != fingerprint]
    entries.append(
        {
            "fingerprint": fingerprint,
            "member_count": int(member_count),
            "dismissed_at": dismissed_at,
        }
    )
    metadata[_CONFLICT_DISMISSAL_METADATA_KEY] = entries[-_MAX_CONFLICT_DISMISSALS_PER_CARD:]
    return json_dumps(metadata)


def _conflict_adjacency(cards: list[Any]) -> dict[str, set[str]]:
    by_id = {str(card["id"]): card for card in cards}
    signatures = {card_id: _conflict_signature(card) for card_id, card in by_id.items()}
    term_members: dict[str, set[str]] = {}
    anchor_members: dict[str, set[str]] = {}
    title_members: dict[str, set[str]] = {}
    existing_group_members: dict[str, set[str]] = {}
    for card_id, signature in signatures.items():
        for term in signature["term_set"]:
            term_members.setdefault(term, set()).add(card_id)
        if signature["anchor"]:
            anchor_members.setdefault(signature["anchor"], set()).add(card_id)
        if signature["title"]:
            title_members.setdefault(signature["title"], set()).add(card_id)
        existing_group = str(by_id[card_id]["conflict_group"] or "").strip()
        if existing_group:
            existing_group_members.setdefault(existing_group, set()).add(card_id)

    potential_pairs: set[tuple[str, str]] = set()
    for card_id, signature in signatures.items():
        peers: set[str] = set(title_members.get(signature["title"], set()))
        if signature["anchor"]:
            peers.update(term_members.get(signature["anchor"], set()))
        for term in signature["term_set"]:
            peers.update(anchor_members.get(term, set()))
        for peer_id in peers:
            if peer_id != card_id:
                potential_pairs.add(
                    (card_id, peer_id) if card_id < peer_id else (peer_id, card_id)
                )

    adjacency: dict[str, set[str]] = {card_id: set() for card_id in by_id}
    # Existing group membership is durable review state. Treat it as an edge so
    # a later heuristic scan cannot fragment a valid connected group merely
    # because only some of its text pairs are rediscovered.
    for members in existing_group_members.values():
        if len(members) < 2:
            continue
        anchor_id = min(members)
        for member_id in members - {anchor_id}:
            adjacency[anchor_id].add(member_id)
            adjacency[member_id].add(anchor_id)
    for left_id, right_id in sorted(potential_pairs):
        left = signatures[left_id]
        right = signatures[right_id]
        if not _conflict_card_types_compatible(left["card_type"], right["card_type"]):
            continue
        # Sequential project-state Cards from one agent are ordered checkpoints,
        # not competing claims. Cross-agent checkpoints may still disagree and
        # must remain eligible for conflict detection. Any durable group
        # explicitly assigned by a reviewer is still preserved above.
        if (
            left["card_type"] == right["card_type"] == "project_state"
            and left["agent_id"]
            and left["agent_id"] == right["agent_id"]
        ):
            continue
        if left["title"] == right["title"] and left["summary"] == right["summary"]:
            continue
        concept_match = (
            left["anchor"] in right["term_set"]
            or right["anchor"] in left["term_set"]
            or left["title"] == right["title"]
        )
        if not concept_match:
            continue
        if left["negative"] == right["negative"] and left["title"] != right["title"]:
            continue
        adjacency[left_id].add(right_id)
        adjacency[right_id].add(left_id)
    return adjacency


def _clear_orphan_conflict_groups(
    conn,
    *,
    rows: list[Any],
    current_ids: set[str],
    now: str,
) -> tuple[set[str], set[str]]:
    grouped: dict[str, list[str]] = {}
    by_id = {str(row["id"]): row for row in rows}
    touched: set[str] = set()
    cleared_groups: set[str] = set()
    for row in rows:
        card_id = str(row["id"])
        group = str(row["conflict_group"] or "").strip()
        if row["conflict_group"] is not None and not group:
            conn.execute(
                "UPDATE cards SET conflict_group = NULL, updated_at = ? WHERE id = ?",
                (now, card_id),
            )
            touched.add(card_id)
            continue
        if group:
            grouped.setdefault(group, []).append(card_id)

    for group, member_ids in grouped.items():
        current_members = [card_id for card_id in member_ids if card_id in current_ids]
        invalid_members = [card_id for card_id in member_ids if card_id not in current_ids]
        clear_ids = list(invalid_members)
        current_boundaries = {
            _conflict_boundary(by_id[card_id])
            for card_id in current_members
        }
        current_card_types = {
            str(by_id[card_id]["card_type"] or "").casefold().strip()
            for card_id in current_members
        }
        incompatible_project_state_group = (
            "project_state" in current_card_types and len(current_card_types) > 1
        )
        if (
            len(current_members) < 2
            or len(current_boundaries) > 1
            or incompatible_project_state_group
        ):
            clear_ids.extend(current_members)
            cleared_groups.add(group)
        for card_id in dict.fromkeys(clear_ids):
            conn.execute(
                "UPDATE cards SET conflict_group = NULL, updated_at = ? WHERE id = ? AND conflict_group = ?",
                (now, card_id, group),
            )
            touched.add(card_id)
    return touched, cleared_groups


def detect_conflicts(root: Path, *, card_id: str | None = None, limit: int = 50) -> dict[str, Any]:
    init_db(root)
    conn = connect(root)
    touched_cards: set[str] = set()
    try:
        conn.execute("BEGIN IMMEDIATE")
        _assert_supersession_dag(conn)
        rows, by_id, current_ids = _load_temporal_card_state(conn)
        now = utc_now()
        orphan_cards, orphan_groups = _clear_orphan_conflict_groups(
            conn,
            rows=rows,
            current_ids=current_ids,
            now=now,
        )
        touched_cards.update(orphan_cards)

        # Cleanup changes authority and grouping state. Reload before deriving
        # components so results, audit rows, and the committed catalog all refer
        # to the same post-cleanup snapshot.
        rows, by_id, current_ids = _load_temporal_card_state(conn)

        boundary_rows: dict[tuple[str, str, str], list[Any]] = {}
        for row in rows:
            if str(row["id"]) in current_ids:
                boundary_rows.setdefault(_conflict_boundary(row), []).append(row)

        all_components: list[dict[str, Any]] = []
        for boundary, cards in sorted(boundary_rows.items()):
            adjacency = _conflict_adjacency(cards)
            unseen = set(adjacency)
            ordered_ids = sorted(
                unseen,
                key=lambda member_id: int(by_id[member_id]["card_rowid"]),
            )
            for seed_id in ordered_ids:
                if seed_id not in unseen:
                    continue
                pending = [seed_id]
                component_ids: set[str] = set()
                while pending:
                    current = pending.pop()
                    if current in component_ids:
                        continue
                    component_ids.add(current)
                    pending.extend(adjacency.get(current, ()))
                unseen.difference_update(component_ids)
                if len(component_ids) < 2:
                    continue
                member_ids = sorted(component_ids)
                fingerprint = _conflict_component_fingerprint(by_id, member_ids)
                component_existing_groups = {
                    str(by_id[member_id]["conflict_group"] or "").strip()
                    for member_id in member_ids
                    if str(by_id[member_id]["conflict_group"] or "").strip()
                }
                all_components.append(
                    {
                        "boundary": boundary,
                        "member_ids": member_ids,
                        "fingerprint": fingerprint,
                        "suppressed": _conflict_component_is_suppressed(
                            by_id,
                            member_ids,
                            fingerprint,
                        ),
                        "needs_assignment": (
                            len(component_existing_groups) != 1
                            or any(
                                not str(by_id[member_id]["conflict_group"] or "").strip()
                                for member_id in member_ids
                            )
                        ),
                        "first_rowid": min(int(by_id[member_id]["card_rowid"]) for member_id in member_ids),
                    }
                )

        suppressed_components = [record for record in all_components if record["suppressed"]]
        for component_record in suppressed_components:
            grouped_member_ids = [
                member_id
                for member_id in component_record["member_ids"]
                if str(by_id[member_id]["conflict_group"] or "").strip()
            ]
            for member_id in grouped_member_ids:
                conn.execute(
                    "UPDATE cards SET conflict_group = NULL, updated_at = ? WHERE id = ?",
                    (now, member_id),
                )
            if grouped_member_ids:
                touched_cards.update(grouped_member_ids)
                audit_event(
                    conn,
                    action="librarian_apply_conflict_dismissal",
                    target_type="conflict_component",
                    target_id=str(component_record["fingerprint"]),
                    payload={
                        "card_ids": component_record["member_ids"],
                        "fingerprint": component_record["fingerprint"],
                    },
                )

        eligible_components = [record for record in all_components if not record["suppressed"]]
        if card_id:
            requested_card_id = str(card_id)
            selected_components = [
                record
                for record in eligible_components
                if requested_card_id in record["member_ids"]
            ][:1]
        else:
            # Limit components, not mutable Card rows. Ungrouped/newly expanded
            # components sort first by immutable insertion order, so repeated
            # limit=1 passes make progress instead of revisiting a group whose
            # updated_at was just changed by the previous pass.
            selected_components = sorted(
                eligible_components,
                key=lambda record: (
                    0 if record["needs_assignment"] else 1,
                    int(record["first_rowid"]),
                    tuple(record["member_ids"]),
                ),
            )[: max(1, int(limit))]

        detected_components: list[dict[str, Any]] = []
        claimed_groups: set[str] = set()
        for component_record in selected_components:
            member_ids = list(component_record["member_ids"])
            anchor_id = min(
                member_ids,
                key=lambda member_id: int(by_id[member_id]["card_rowid"]),
            )
            ordered_existing_groups = sorted(
                (
                    int(by_id[member_id]["card_rowid"]),
                    str(by_id[member_id]["conflict_group"] or "").strip(),
                )
                for member_id in member_ids
                if str(by_id[member_id]["conflict_group"] or "").strip()
            )
            group = ordered_existing_groups[0][1] if ordered_existing_groups else ""
            if not group or group in claimed_groups:
                group = content_hash(f"continuum_conflict_v2|{anchor_id}")[:16]
            claimed_groups.add(group)
            changed_ids = [
                member_id
                for member_id in member_ids
                if str(by_id[member_id]["conflict_group"] or "") != group
            ]
            for member_id in changed_ids:
                conn.execute(
                    "UPDATE cards SET conflict_group = ?, updated_at = ? WHERE id = ?",
                    (group, now, member_id),
                )
            if changed_ids:
                touched_cards.update(changed_ids)
                audit_event(
                    conn,
                    action="librarian_detect_conflict",
                    target_type="conflict_group",
                    target_id=group,
                    payload={"card_ids": member_ids, "conflict_group": group},
                )
            detected_components.append({"conflict_group": group, "card_ids": member_ids})

        # Assigning a repaired connected component can leave behind the final
        # member of an older fragmented group. Clear that orphan in the same
        # transaction so a contested marker always means at least two current Cards.
        refreshed_rows, _refreshed_by_id, refreshed_current_ids = _load_temporal_card_state(conn)
        trailing_orphans, trailing_orphan_groups = _clear_orphan_conflict_groups(
            conn,
            rows=refreshed_rows,
            current_ids=refreshed_current_ids,
            now=now,
        )
        touched_cards.update(trailing_orphans)
        _final_rows, final_by_id, final_current_ids = _load_temporal_card_state(conn)
        conflicts: list[dict[str, Any]] = []
        for detected_record in detected_components:
            member_ids = list(detected_record["card_ids"])
            groups = {
                str(final_by_id[member_id]["conflict_group"] or "").strip()
                for member_id in member_ids
                if member_id in final_current_ids
            }
            groups.discard("")
            if len(groups) == 1 and all(
                member_id in final_current_ids
                and str(final_by_id[member_id]["conflict_group"] or "").strip() in groups
                for member_id in member_ids
            ):
                conflicts.append({"conflict_group": next(iter(groups)), "card_ids": member_ids})
        if orphan_cards or trailing_orphans:
            audit_event(
                conn,
                action="librarian_clear_orphan_conflicts",
                target_type="cards",
                target_id=None,
                payload={"card_ids": sorted(orphan_cards | trailing_orphans)},
            )
        if touched_cards:
            mark_card_sidecar_outbox(conn, sorted(touched_cards), reason="conflict_group_updated")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    if touched_cards:
        sync_card_sidecars_after_commit(root, sorted(touched_cards))
    return {
        "ok": True,
        "conflict_count": len(conflicts),
        "conflicts": conflicts,
        "changed_card_count": len(touched_cards),
        "orphan_groups_cleared": len(orphan_groups | trailing_orphan_groups),
        "suppressed_component_count": len(suppressed_components),
        "supersession_dag": True,
    }


def resolve_conflict(
    root: Path,
    *,
    card_id: str,
    action: str = "supersede",
    superseded_card_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Resolve an entire contested Card group without deleting its evidence.

    ``supersede`` promotes ``card_id`` as the current Card and links every peer
    back to it. ``dismiss`` clears a false-positive annotation. Partial group
    resolution is rejected because it can fragment temporal authority.
    """
    if action not in {"supersede", "dismiss"}:
        raise ValueError("action must be supersede or dismiss")
    init_db(root)
    conn = connect(root)
    touched_cards: list[str] = []
    try:
        conn.execute("BEGIN IMMEDIATE")
        edges = _assert_supersession_dag(conn)
        _rows, by_id, current_ids = _load_temporal_card_state(conn)
        winner = conn.execute("SELECT * FROM cards WHERE id = ?", (card_id,)).fetchone()
        if winner is None:
            raise ValueError(f"card not found: {card_id}")
        if card_id not in current_ids:
            raise ValueError(f"historical or superseded card cannot win a conflict: {card_id}")
        conflict_group = str(winner["conflict_group"] or "").strip()
        if not conflict_group:
            raise ValueError(f"card is not contested: {card_id}")
        peers = conn.execute(
            "SELECT * FROM cards WHERE conflict_group = ? AND id != ? ORDER BY id",
            (conflict_group, card_id),
        ).fetchall()
        peer_ids = [str(row["id"]) for row in peers]
        historical_peers = sorted(set(peer_ids) - current_ids)
        if historical_peers:
            raise ValueError(
                "conflict group contains historical or superseded cards: "
                + ", ".join(historical_peers)
            )
        winner_boundary = _conflict_boundary(winner)
        cross_boundary_peers = sorted(
            str(peer["id"])
            for peer in peers
            if _conflict_boundary(peer) != winner_boundary
        )
        if cross_boundary_peers:
            raise ValueError(
                "conflict group crosses visibility boundaries: "
                + ", ".join(cross_boundary_peers)
            )
        requested = list(dict.fromkeys(str(value).strip() for value in (superseded_card_ids or []) if str(value).strip()))
        if requested:
            unknown = sorted(set(requested) - set(peer_ids))
            if unknown:
                raise ValueError(f"cards are not peers in conflict group {conflict_group}: {', '.join(unknown)}")
            omitted = sorted(set(peer_ids) - set(requested))
            if omitted:
                raise ValueError(
                    "partial conflict resolution is not allowed; whole group also requires: "
                    + ", ".join(omitted)
                )
        resolved_peer_ids = peer_ids
        if not peer_ids:
            raise ValueError(f"conflict group has no peers: {conflict_group}")
        member_card_types = {
            str(row["card_type"] or "").casefold().strip()
            for row in [winner, *peers]
        }
        if (
            action == "supersede"
            and "project_state" in member_card_types
            and len(member_card_types) > 1
        ):
            raise ValueError(
                "project_state conflict groups cannot include non-project_state cards"
            )

        now = utc_now()
        dismissal_fingerprint: str | None = None
        if action == "supersede":
            reversing = [
                peer_id
                for peer_id in resolved_peer_ids
                if _supersession_reaches(edges, card_id, peer_id)
            ]
            if reversing:
                raise ValueError(
                    "conflict resolution would reverse existing supersession: "
                    + ", ".join(sorted(reversing))
                )
            placeholders = ",".join("?" for _ in resolved_peer_ids)
            conn.execute(
                f"""
                UPDATE cards
                SET superseded_by_card_id = ?, conflict_group = NULL, updated_at = ?
                WHERE id IN ({placeholders})
                """,
                (card_id, now, *resolved_peer_ids),
            )
            direct_predecessor = max(
                resolved_peer_ids,
                key=lambda peer_id: (
                    str(by_id[peer_id]["created_at"] or ""),
                    int(by_id[peer_id]["card_rowid"]),
                ),
            )
            conn.execute(
                """
                UPDATE cards
                SET supersedes_card_id = coalesce(supersedes_card_id, ?), conflict_group = NULL,
                    status = CASE WHEN status = 'pending_librarian_review' THEN 'active' ELSE status END,
                    updated_at = ?
                WHERE id = ?
                """,
                (direct_predecessor, now, card_id),
            )
        else:
            all_ids = sorted({card_id, *peer_ids})
            dismissal_fingerprint = _conflict_component_fingerprint(by_id, all_ids)
            for member_id in all_ids:
                metadata_json = _append_conflict_dismissal(
                    by_id[member_id]["metadata_json"],
                    fingerprint=dismissal_fingerprint,
                    member_count=len(all_ids),
                    dismissed_at=now,
                )
                conn.execute(
                    """
                    UPDATE cards
                    SET conflict_group = NULL, metadata_json = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (metadata_json, now, member_id),
                )
            resolved_peer_ids = peer_ids

        touched_cards = sorted({card_id, *resolved_peer_ids})
        _assert_supersession_dag(conn)
        mark_card_sidecar_outbox(conn, touched_cards, reason=f"conflict_{action}_resolved")
        audit_event(
            conn,
            action="librarian_resolve_conflict",
            target_type="card",
            target_id=card_id,
            payload={
                "resolution": action,
                "conflict_group": conflict_group,
                "resolved_peer_ids": resolved_peer_ids,
                "whole_group": True,
                **({"dismissal_fingerprint": dismissal_fingerprint} if dismissal_fingerprint else {}),
            },
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    sync_card_sidecars_after_commit(root, touched_cards)
    return {
        "ok": True,
        "action": action,
        "card_id": card_id,
        "conflict_group": conflict_group,
        "resolved_peer_ids": resolved_peer_ids,
        "card_count": len(touched_cards),
        "whole_group": True,
        "supersession_dag": True,
        **({"dismissal_fingerprint": dismissal_fingerprint} if dismissal_fingerprint else {}),
    }


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


def _process_job(
    root: Path,
    job: dict[str, Any],
    *,
    heartbeat: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    payload = json_loads(job.get("payload_json"), {})
    job_type = job["job_type"]
    if job_type == "scroll_event_ingested":
        return roll_due_scroll_segments(root, session_id=payload.get("session_id"), heartbeat=heartbeat)
    if job_type == "review_card_placement":
        return review_card_placement(root, card_id=str(payload["card_id"]))
    if job_type == "verify_book_integrity":
        return verify_book_integrity(root, book_id=str(payload["book_id"]), content_hash_value=payload.get("content_hash"))
    if job_type == "verify_segment_integrity":
        return verify_segment_integrity(root, segment_id=str(payload["segment_id"]), segment_hash=payload.get("segment_hash"))
    if job_type == "sync_card_sidecar":
        return sync_card_sidecar_job(root, card_id=str(payload["card_id"]))
    if job_type == "review_mempalace_import":
        return review_mempalace_import(root, import_id=str(payload.get("import_id") or ""))
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
            def renew_lease() -> bool:
                lease_conn = connect(root)
                try:
                    renewed = _heartbeat_job(
                        lease_conn,
                        job["id"],
                        lease_owner=worker_id,
                        lease_seconds=lease_seconds,
                    )
                    lease_conn.commit()
                    return renewed
                finally:
                    lease_conn.close()

            if job["job_type"] == "scroll_event_ingested":
                result = _process_job(root, job, heartbeat=renew_lease)
            else:
                # Preserve the small internal hook surface used by integrations
                # and tests that replace non-Scribe job processors.
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


@contextmanager
def _worker_service_lock(root: Path) -> Iterator[None]:
    key = os.path.normcase(str(root.resolve(strict=False)))
    with _WORKER_SERVICE_ROOTS_GUARD:
        if key in _WORKER_SERVICE_ROOTS:
            raise RuntimeError(f"worker service already running for root: {root}")
        _WORKER_SERVICE_ROOTS.add(key)
    try:
        try:
            with operation_lock(root, "worker-service", timeout_seconds=0.0):
                yield
        except TimeoutError as exc:
            raise RuntimeError(f"worker service already running for root: {root}") from exc
    finally:
        with _WORKER_SERVICE_ROOTS_GUARD:
            _WORKER_SERVICE_ROOTS.discard(key)


def serve_workers(
    root: Path,
    *,
    roles: list[str] | None = None,
    limit: int = 0,
    interval_seconds: float = 5.0,
    maintenance_interval_seconds: float = DEFAULT_WORKER_MAINTENANCE_INTERVAL_SECONDS,
    maintenance_on_start: bool = True,
) -> dict[str, Any]:
    passes = 0
    processed = 0
    maintenance_passes = 0
    maintenance_interval = max(1.0, float(maintenance_interval_seconds))
    next_maintenance_at = time.monotonic() if maintenance_on_start else time.monotonic() + maintenance_interval
    with _worker_service_lock(root):
        while True:
            now = time.monotonic()
            maintenance_due = now >= next_maintenance_at
            result = run_worker_pass(root, roles=roles, limit=50, maintenance=maintenance_due)
            passes += 1
            processed += int(result.get("processed_count", 0))
            if maintenance_due:
                maintenance_passes += 1
                next_maintenance_at = time.monotonic() + maintenance_interval
            if limit and passes >= limit:
                return {
                    "ok": True,
                    "passes": passes,
                    "processed_count": processed,
                    "maintenance_passes": maintenance_passes,
                    "maintenance_interval_seconds": maintenance_interval,
                }
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
        oldest_pending_job = conn.execute(
            "SELECT min(created_at) AS ts FROM queue_jobs WHERE status = 'pending'"
        ).fetchone()["ts"]
        invalid_pending_job_timestamps = 0
        for timestamp_row in conn.execute(
            "SELECT created_at FROM queue_jobs WHERE status = 'pending'"
        ):
            try:
                _parse_utc_timestamp(timestamp_row["created_at"])
            except (TypeError, ValueError, OverflowError):
                invalid_pending_job_timestamps += 1
        latest_running_job_heartbeat = conn.execute(
            "SELECT max(heartbeat_at) AS ts FROM queue_jobs WHERE status = 'running'"
        ).fetchone()["ts"]
        health_checked_at = utc_now()
        running_jobs = conn.execute(
            "SELECT count(*) AS n FROM queue_jobs WHERE status = 'running'"
        ).fetchone()["n"]
        stale_running_jobs = conn.execute(
            """
            SELECT count(*) AS n
            FROM queue_jobs
            WHERE status = 'running'
              AND (
                    lease_owner IS NULL
                 OR trim(lease_owner) = ''
                 OR lease_expires_at IS NULL
                 OR julianday(lease_expires_at) IS NULL
                 OR julianday(lease_expires_at) <= julianday(?)
                 OR heartbeat_at IS NULL
                 OR julianday(heartbeat_at) IS NULL
              )
            """,
            (health_checked_at,),
        ).fetchone()["n"]
        unsegmented_events = conn.execute(
            """
            SELECT count(*) AS n
            FROM scroll_events e
            WHERE NOT EXISTS (
                SELECT 1
                FROM scroll_segments s
                WHERE s.session_id = e.session_id
                  AND e.seq BETWEEN s.start_seq AND s.end_seq
            )
            """
        ).fetchone()["n"]
        sidecar_backlog = conn.execute("SELECT count(*) AS n FROM card_sidecar_outbox").fetchone()["n"]
        latest_snapshot = conn.execute("SELECT max(created_at) AS ts FROM snapshots").fetchone()["ts"]
        root_size = _root_size_bytes(root)
        max_root_size = parse_size(config.get("retention", {}).get("max_root_size", "50GB"))
        wal_path = root / "catalog" / "catalog.sqlite3-wal"
        try:
            wal_size = wal_path.stat().st_size if wal_path.exists() else 0
        except OSError:
            wal_size = 0
        now = dt.datetime.now(dt.UTC)

        def age_seconds(timestamp: str | None) -> float | None:
            if not timestamp:
                return None
            try:
                return max(0.0, (now - _parse_utc_timestamp(timestamp)).total_seconds())
            except (TypeError, ValueError, OverflowError):
                return None

        queue_age = age_seconds(oldest_pending_job)
        queue_timestamp_valid = (
            invalid_pending_job_timestamps == 0
            and (pending_jobs == 0 or queue_age is not None)
        )
        checks = [
            {"name": "capture_configured", "ok": bool(config.get("capture", {}).get("mode"))},
            {"name": "queue_backlog_reasonable", "ok": pending_jobs < 1000, "pending_jobs": pending_jobs},
            {
                "name": "queue_age_reasonable",
                "ok": queue_timestamp_valid and (queue_age is None or queue_age < 86400),
                "oldest_pending_job_age_seconds": queue_age,
                "timestamp_valid": queue_timestamp_valid,
                "invalid_pending_job_timestamps": invalid_pending_job_timestamps,
            },
            {"name": "no_failed_jobs", "ok": failed_jobs == 0, "failed_jobs": failed_jobs},
            {
                "name": "running_jobs_current",
                "ok": stale_running_jobs == 0,
                "running_jobs": running_jobs,
                "stale_running_jobs": stale_running_jobs,
            },
            {"name": "librarian_backlog_reasonable", "ok": pending_cards < 1000, "pending_librarian_cards": pending_cards},
            {"name": "scroll_segmentation_lag_reasonable", "ok": unsegmented_events < 1000, "unsegmented_events": unsegmented_events},
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
            "oldest_pending_job_at": oldest_pending_job,
            "oldest_pending_job_age_seconds": queue_age,
            "oldest_pending_job_timestamp_valid": queue_timestamp_valid,
            "invalid_pending_job_timestamps": invalid_pending_job_timestamps,
            "latest_running_job_heartbeat_at": latest_running_job_heartbeat,
            "running_jobs": running_jobs,
            "stale_running_jobs": stale_running_jobs,
            "unsegmented_scroll_events": unsegmented_events,
            "sidecar_outbox_backlog": sidecar_backlog,
            "latest_snapshot_at": latest_snapshot,
            "catalog_wal_size_bytes": wal_size,
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
