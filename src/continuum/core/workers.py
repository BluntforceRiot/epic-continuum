from __future__ import annotations

import datetime as dt
import contextvars
import math
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

from .config import config_path, default_config, load_config, retention_policy
from .operations import operation_lock
from .permissions import secure_move_file
from .temporal_authority import (
    conflict_boundary as _conflict_boundary,
    conflict_component_fingerprint as _conflict_component_fingerprint,
    conflict_member_binding_hash as _conflict_member_binding_hash,
    valid_conflict_resolution_receipt,
)
from .store import (
    _card_sidecar_intent_reconciliation_budget,
    _card_sidecar_intent_reconciliation_limit,
    _current_card_sidecar_intent_reconciliation_budget,
    _project_state_card_integrity_error,
    _queue_retry_authority_triggers_ready,
    _queue_retry_order_counter_ready,
    add_graph_edge,
    audit_event,
    canonical_partition_identifier,
    connect,
    connect_existing,
    content_hash,
    continuum_uri,
    current_card_sidecar_path,
    enqueue_job,
    extract_terms,
    file_sha256,
    init_db,
    is_initialized,
    json_dumps,
    json_loads,
    mark_card_sidecar_outbox,
    MAX_QUEUE_RETRY_ORDER,
    NON_CURRENT_CARD_STATUSES,
    QUEUE_RETRY_ORDER_META_KEY,
    QUEUE_RETRY_ORDER_BACKFILL_META_KEY,
    QUEUE_RETRY_ORDER_BACKFILL_META_VALUE,
    QUEUE_RETRY_PENDING_BACKFILL_META_KEY,
    QUEUE_RETRY_PENDING_BACKFILL_META_VALUE,
    QUEUE_ROLE_LEASE_INDEX_NAME,
    QUEUE_STATUS_LEASE_INDEX_NAME,
    reconcile_card_sidecar_write_intents,
    register_card_sidecar_compensation_intents,
    refresh_graph_edge_aggregate,
    resolve_stored_uri,
    roll_scroll_segment,
    segment_hash_material,
    semantic_integrity_report,
    snapshot,
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
DEFAULT_PRUNE_MEMORY_LIMIT = 100
MAX_PRUNE_MEMORY_LIMIT = 1000
PRUNE_MEMORY_LITERAL_MATCHING_MODE = "literal_substring"
PRUNE_MEMORY_GLOBAL_MATCHING_MODE = "explicit_global"
DEFAULT_WORKER_MAINTENANCE_INTERVAL_SECONDS = 300.0
WORKER_SIDECAR_INTENT_LIMIT = 50
WORKER_MAINTENANCE_FAILURE_LIMIT = 10
WORKER_FAILED_SIDECAR_RECOVERY_LIMIT = 50
WORKER_FAILED_SCRIBE_STEP_VALIDATION_LIMIT = 64
WORKER_EXPIRED_LEASE_RECLAIM_LIMIT = 50
POST_COMMIT_SIDECAR_RETRY_REASON = "post_commit_sidecar_retry_pending"
POST_COMMIT_EXCEPTION_RETRY_REASON = "post_commit_exception_retry_pending"
MAX_CONSECUTIVE_PRIORITY_BYPASSES = 8
MAX_CONSECUTIVE_RETRY_BYPASSES = 8
_QUEUE_FAIRNESS_META_PREFIX = "worker_queue_priority_burst_v1:"
_QUEUE_RETRY_FAIRNESS_META_PREFIX = "worker_queue_retry_burst_v1:"
# A single notification may represent an arbitrarily large per-session backlog
# because Scroll appends deliberately deduplicate pending Scribe jobs. Drain more
# than one window, but yield after a bounded amount of work and leave a durable
# continuation for the same session.
MAX_SCRIBE_SEGMENT_BATCHES_PER_RUN = 64
_WORKER_SERVICE_ROOTS: set[str] = set()
_WORKER_SERVICE_ROOTS_GUARD = threading.Lock()
_WORKER_EFFECT_ACTION = "worker_job_effect_committed"
_WORKER_EFFECT_SCHEMA = "continuum.worker_job_effect.v1"
_WORKER_POST_PHASE_COMPLETE_KEY = "_worker_post_phase_complete"
_WORKER_PHASE_ACTION = "worker_job_phase_committed"
_WORKER_PHASE_SCHEMA = "continuum.worker_job_phase.v1"
_SIDECAR_WORKER_PHASE_ACTION = "worker_card_sidecar_phase_committed"
_SIDECAR_WORKER_PHASE_SCHEMA = "continuum.worker_card_sidecar_phase.v1"
_SCRIBE_STEP_ACTION = "worker_scribe_segment_step_intent"
_SCRIBE_STEP_COMMITTED_ACTION = "worker_scribe_segment_step_committed"
_SCRIBE_STEP_COMPLETED_ACTION = "worker_scribe_segment_step_completed"
_FAILED_SIDECAR_RECOVERY_ACTION = (
    "worker_failed_post_phase_sidecar_recovery"
)
_FAILED_SIDECAR_RECOVERY_SCHEMA = (
    "continuum.worker_failed_post_phase_sidecar_recovery.v1"
)
_FAILED_SIDECAR_RECOVERY_JOB_ROLES = {
    "review_card_placement": "librarian",
    "review_mempalace_import": "librarian",
    "scroll_event_ingested": "scribe",
    "sync_card_sidecar": "archivist",
}
_FAILED_SIDECAR_EFFECTLESS_KEY = "effectless"


class _JobLease:
    """Durable ownership token for one claimed queue row."""

    def __init__(self, root: Path, job_id: str, lease_owner: str, lease_seconds: int) -> None:
        self.root = root
        self.job_id = str(job_id)
        self.lease_owner = str(lease_owner)
        self.lease_seconds = max(1, int(lease_seconds))

    def renew(self) -> bool:
        conn = connect(self.root)
        try:
            renewed = _heartbeat_job(
                conn,
                self.job_id,
                lease_owner=self.lease_owner,
                lease_seconds=self.lease_seconds,
            )
            conn.commit()
            return renewed
        finally:
            conn.close()

    def renew_in_transaction(self, conn) -> bool:
        """Renew using a processor's writer connection without committing it."""
        return _heartbeat_job(
            conn,
            self.job_id,
            lease_owner=self.lease_owner,
            lease_seconds=self.lease_seconds,
        )

    def assert_owned(self, conn) -> None:
        if not _job_lease_is_owned(conn, self.job_id, lease_owner=self.lease_owner):
            raise RuntimeError("worker lease lost before committing job effects")


_CURRENT_JOB_LEASE: contextvars.ContextVar[_JobLease | None] = contextvars.ContextVar(
    "continuum_current_job_lease",
    default=None,
)


def _worker_sidecar_intent_budget_snapshot(
    budget: dict[str, int],
) -> dict[str, int]:
    return {
        "limit": int(budget["limit"]),
        "used": int(budget["used"]),
        "remaining": int(budget["remaining"]),
    }


def _worker_sidecar_intent_budget_allowance(
    requested_limit: int = WORKER_SIDECAR_INTENT_LIMIT,
) -> tuple[dict[str, int], int, bool]:
    bounded_request = max(
        1,
        min(int(requested_limit), WORKER_SIDECAR_INTENT_LIMIT),
    )
    shared_budget = (
        _current_card_sidecar_intent_reconciliation_budget()
    )
    if shared_budget is None:
        standalone_budget = {
            "limit": bounded_request,
            "used": 0,
            "remaining": bounded_request,
        }
        return standalone_budget, bounded_request, False
    return (
        shared_budget,
        min(bounded_request, max(0, int(shared_budget["remaining"]))),
        True,
    )


def _charge_worker_sidecar_intent_budget(
    budget: dict[str, int],
    *,
    allowance: int,
    result: dict[str, Any] | None,
) -> int:
    if allowance <= 0:
        return 0
    if result is None or result.get("remaining") is None:
        charge = allowance
    else:
        charge = max(
            max(0, int(result.get("enumerated", 0))),
            max(0, int(result.get("inspected", 0))),
            max(0, int(result.get("selected", 0))),
            max(0, int(result.get("processed", 0))),
        )
        if not result.get("ok") and not result.get("complete"):
            charge = allowance
    charge = min(allowance, charge)
    budget["used"] = min(
        int(budget["limit"]),
        int(budget["used"]) + charge,
    )
    budget["remaining"] = max(
        0,
        int(budget["limit"]) - int(budget["used"]),
    )
    return charge


def _worker_sidecar_intent_budget_exhausted_result(
    budget: dict[str, int],
    *,
    card_id: str | None,
    ok: bool,
) -> dict[str, Any]:
    return {
        "ok": ok,
        "processed": 0,
        "pending": 0 if ok else 1,
        "failures": (
            []
            if ok
            else [
                {
                    "card_id": card_id,
                    "error": (
                        "Worker Card sidecar intent reconciliation budget "
                        "was exhausted"
                    ),
                }
            ]
        ),
        "results": [],
        "limit": 0,
        "selected": 0,
        "inspected": 0,
        "enumerated": 0,
        "remaining": None,
        "remaining_is_lower_bound": True,
        "complete": False,
        "has_more": True,
        "remaining_lower_bound": 0,
        "batch_truncated": True,
        "overflow": False,
        "scope_filtered": False,
        "scope_complete": False,
        "deferred": True,
        "budget_exhausted": True,
        "worker_intent_budget": _worker_sidecar_intent_budget_snapshot(
            budget
        ),
    }


def _reconcile_worker_sidecar_intents_with_budget(
    root: Path,
    *,
    card_id: str | None = None,
    requested_limit: int = WORKER_SIDECAR_INTENT_LIMIT,
    exhausted_ok: bool = False,
) -> dict[str, Any]:
    budget, allowance, shared = (
        _worker_sidecar_intent_budget_allowance(requested_limit)
    )
    if allowance <= 0:
        return _worker_sidecar_intent_budget_exhausted_result(
            budget,
            card_id=card_id,
            ok=exhausted_ok,
        )
    try:
        raw_result = reconcile_card_sidecar_write_intents(
            root,
            limit=allowance,
        )
    except Exception as exc:
        if not shared:
            _charge_worker_sidecar_intent_budget(
                budget,
                allowance=allowance,
                result=None,
            )
        error = f"{type(exc).__name__}: {str(exc)[:512]}"
        return {
            "ok": False,
            "processed": 0,
            "pending": 1 if card_id else 0,
            "failures": [{"card_id": card_id, "error": error}],
            "results": [],
            "limit": allowance,
            "selected": 0,
            "inspected": 0,
            "enumerated": 0,
            "remaining": None,
            "remaining_is_lower_bound": True,
            "complete": False,
            "has_more": True,
            "remaining_lower_bound": 0,
            "batch_truncated": True,
            "overflow": False,
            "raised": True,
            "error": error,
            "scope_filtered": False,
            "scope_complete": False,
            "budget_exhausted": budget["remaining"] == 0,
            "worker_intent_budget": (
                _worker_sidecar_intent_budget_snapshot(budget)
            ),
        }
    result = dict(raw_result)
    if not shared:
        result["budget_charged"] = (
            _charge_worker_sidecar_intent_budget(
                budget,
                allowance=allowance,
                result=result,
            )
        )
    result["budget_exhausted"] = bool(
        budget["remaining"] == 0 and not result.get("complete")
    )
    result["worker_intent_budget"] = (
        _worker_sidecar_intent_budget_snapshot(budget)
    )
    return result


def _lease_renewal_interval(lease_seconds: int) -> float:
    return max(0.05, min(5.0, max(1, int(lease_seconds)) / 3.0))


class _JobLeaseRenewer:
    """Renew a claimed row while arbitrary worker code is executing."""

    def __init__(self, lease: _JobLease) -> None:
        self.lease = lease
        self._stop = threading.Event()
        self._lost = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"continuum-lease-{lease.job_id}",
            daemon=True,
        )

    @property
    def lost(self) -> bool:
        return self._lost.is_set()

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=max(1.0, _lease_renewal_interval(self.lease.lease_seconds) * 2.0))

    def _run(self) -> None:
        interval = _lease_renewal_interval(self.lease.lease_seconds)
        while not self._stop.wait(interval):
            try:
                if not self.lease.renew():
                    self._lost.set()
                    return
            except Exception:
                # A transient SQLite busy/error is not proof of lost ownership.
                # The owning processor and final fenced commit re-check the row.
                continue


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


def _expired_lease_candidates(
    conn,
    *,
    roles: set[str] | None,
    now: str,
) -> list[Any]:
    columns = """
        id, preemptible, retry_pending, dedupe_key, lease_expires_at
    """
    if not roles:
        return conn.execute(
            f"""
            SELECT {columns}
            FROM queue_jobs INDEXED BY {QUEUE_STATUS_LEASE_INDEX_NAME}
            WHERE status = ?
              AND lease_expires_at IS NOT NULL
              AND lease_expires_at <= ?
            ORDER BY lease_expires_at ASC, id ASC
            LIMIT ?
            """,
            (
                ACTIVE_JOB_STATUS,
                now,
                WORKER_EXPIRED_LEASE_RECLAIM_LIMIT,
            ),
        ).fetchall()

    candidates: list[Any] = []
    for role in sorted(roles):
        candidates.extend(
            conn.execute(
                f"""
                SELECT {columns}
                FROM queue_jobs INDEXED BY {QUEUE_ROLE_LEASE_INDEX_NAME}
                WHERE role = ?
                  AND status = ?
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= ?
                ORDER BY lease_expires_at ASC, id ASC
                LIMIT ?
                """,
                (
                    role,
                    ACTIVE_JOB_STATUS,
                    now,
                    WORKER_EXPIRED_LEASE_RECLAIM_LIMIT,
                ),
            ).fetchall()
        )
    candidates.sort(
        key=lambda row: (
            str(row["lease_expires_at"]),
            str(row["id"]),
        )
    )
    return candidates[:WORKER_EXPIRED_LEASE_RECLAIM_LIMIT]


def _reclaim_expired_leases(conn, roles: set[str] | None = None) -> int:
    now = utc_now()
    candidates = _expired_lease_candidates(
        conn,
        roles=roles,
        now=now,
    )
    retry_candidates = [
        row
        for row in candidates
        if int(row["preemptible"]) == 1
        and int(row["retry_pending"]) == 1
        and not (
            row["dedupe_key"] is not None
            and conn.execute(
                """
                SELECT 1
                FROM queue_jobs
                WHERE status = ?
                  AND dedupe_key = ?
                  AND id != ?
                LIMIT 1
                """,
                (
                    PENDING_JOB_STATUS,
                    row["dedupe_key"],
                    row["id"],
                ),
            ).fetchone()
            is not None
        )
    ]
    retry_order_start = (
        _reserve_queue_retry_orders(conn, len(retry_candidates))
        if retry_candidates
        else 0
    )
    retry_orders = {
        str(row["id"]): retry_order_start + offset
        for offset, row in enumerate(retry_candidates)
    }
    reclaimed = 0
    for row in candidates:
        job_id = str(row["id"])
        preemptible = int(row["preemptible"])
        retry_pending = int(row["retry_pending"])
        dedupe_key = row["dedupe_key"]
        superseded = bool(
            preemptible == 1
            and dedupe_key is not None
            and conn.execute(
                """
                SELECT 1
                FROM queue_jobs
                WHERE status = ?
                  AND dedupe_key = ?
                  AND id != ?
                LIMIT 1
                """,
                (
                    PENDING_JOB_STATUS,
                    dedupe_key,
                    job_id,
                ),
            ).fetchone()
            is not None
        )
        if superseded:
            cursor = conn.execute(
                """
                UPDATE queue_jobs
                SET status = 'skipped', finished_at = ?,
                    lease_owner = NULL, lease_expires_at = NULL,
                    heartbeat_at = NULL, updated_at = ?, error_json = ?,
                    retry_pending = 0, retry_order = 0
                WHERE id = ? AND status = ?
                  AND preemptible = 1
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= ?
                  AND dedupe_key = ?
                  AND EXISTS (
                      SELECT 1
                      FROM queue_jobs AS pending
                      WHERE pending.status = ?
                        AND pending.dedupe_key = queue_jobs.dedupe_key
                        AND pending.id != queue_jobs.id
                  )
                """,
                (
                    now,
                    now,
                    json_dumps(
                        {
                            "error": None,
                            "result": {
                                "skipped": True,
                                "reason": (
                                    "expired_lease_superseded_by_"
                                    "pending_dedupe_job"
                                ),
                            },
                        }
                    ),
                    job_id,
                    ACTIVE_JOB_STATUS,
                    now,
                    dedupe_key,
                    PENDING_JOB_STATUS,
                ),
            )
        elif preemptible == 1 and retry_pending == 1:
            cursor = conn.execute(
                """
                UPDATE queue_jobs
                SET status = ?, lease_owner = NULL,
                    lease_expires_at = NULL, heartbeat_at = NULL,
                    updated_at = ?, error_json = ?, retry_order = ?
                WHERE id = ? AND status = ?
                  AND preemptible = 1
                  AND retry_pending = 1
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= ?
                """,
                (
                    PENDING_JOB_STATUS,
                    now,
                    json_dumps(
                        {
                            "reclaimed": True,
                            "reason": "worker_lease_expired",
                        }
                    ),
                    retry_orders[job_id],
                    job_id,
                    ACTIVE_JOB_STATUS,
                    now,
                ),
            )
        elif preemptible == 1 and retry_pending == 0:
            cursor = conn.execute(
                """
                UPDATE queue_jobs
                SET status = ?, lease_owner = NULL,
                    lease_expires_at = NULL, heartbeat_at = NULL,
                    updated_at = ?, error_json = ?, retry_order = 0
                WHERE id = ? AND status = ?
                  AND preemptible = 1
                  AND retry_pending = 0
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= ?
                """,
                (
                    PENDING_JOB_STATUS,
                    now,
                    json_dumps(
                        {
                            "reclaimed": True,
                            "reason": "worker_lease_expired",
                        }
                    ),
                    job_id,
                    ACTIVE_JOB_STATUS,
                    now,
                ),
            )
        elif preemptible == 0:
            cursor = conn.execute(
                """
                UPDATE queue_jobs
                SET status = 'failed', finished_at = ?,
                    lease_owner = NULL, lease_expires_at = NULL,
                    heartbeat_at = NULL, updated_at = ?, error_json = ?,
                    retry_pending = 0, retry_order = 0
                WHERE id = ? AND status = ?
                  AND preemptible = 0
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= ?
                """,
                (
                    now,
                    now,
                    json_dumps(
                        {
                            "error": "non_preemptible_worker_lease_expired",
                            "reclaimed": False,
                        }
                    ),
                    job_id,
                    ACTIVE_JOB_STATUS,
                    now,
                ),
            )
        else:
            continue
        reclaimed += int(cursor.rowcount or 0)
    return reclaimed


def _queue_fairness_meta_key(roles: set[str] | None) -> str:
    lane = ["*"] if not roles else sorted(roles)
    return _QUEUE_FAIRNESS_META_PREFIX + content_hash(json_dumps(lane))[:32]


def _queue_retry_fairness_meta_key(roles: set[str] | None) -> str:
    lane = ["*"] if not roles else sorted(roles)
    return (
        _QUEUE_RETRY_FAIRNESS_META_PREFIX
        + content_hash(json_dumps(lane))[:32]
    )


def _reserve_queue_retry_orders(conn, count: int) -> int:
    if isinstance(count, bool) or not isinstance(count, int) or count <= 0:
        raise ValueError("queue retry-order reservation count must be positive")
    row = conn.execute(
        "SELECT value FROM meta WHERE key = ?",
        (QUEUE_RETRY_ORDER_META_KEY,),
    ).fetchone()
    if row is None:
        raise RuntimeError("queue retry-order authority is unavailable")
    try:
        current = int(row["value"])
    except (TypeError, ValueError) as exc:
        raise RuntimeError(
            "queue retry-order authority is invalid"
        ) from exc
    if current < 0 or count > MAX_QUEUE_RETRY_ORDER - current:
        raise RuntimeError("queue retry-order authority is exhausted")
    next_order = current + count
    cursor = conn.execute(
        "UPDATE meta SET value = ? WHERE key = ? AND value = ?",
        (
            str(next_order),
            QUEUE_RETRY_ORDER_META_KEY,
            str(row["value"]),
        ),
    )
    if int(cursor.rowcount or 0) != 1:
        raise RuntimeError("queue retry-order authority changed")
    return current + 1


def _next_queue_retry_order(conn) -> int:
    return _reserve_queue_retry_orders(conn, 1)


def _queue_bypass_count(conn, key: str) -> int:
    row = conn.execute(
        "SELECT value FROM meta WHERE key = ?",
        (key,),
    ).fetchone()
    if row is None:
        return 0
    try:
        return max(0, int(row["value"]))
    except (TypeError, ValueError):
        return 0


def _set_queue_bypass_count(
    conn,
    key: str,
    value: int,
    *,
    maximum: int,
) -> None:
    bounded_value = max(
        0,
        min(int(value), int(maximum)),
    )
    if bounded_value == 0:
        conn.execute("DELETE FROM meta WHERE key = ?", (key,))
        return
    conn.execute(
        """
        INSERT INTO meta(key, value)
        VALUES(?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (key, str(bounded_value)),
    )


def _queue_priority_bypass_count(conn, roles: set[str] | None) -> int:
    return _queue_bypass_count(conn, _queue_fairness_meta_key(roles))


def _set_queue_priority_bypass_count(
    conn,
    roles: set[str] | None,
    value: int,
) -> None:
    _set_queue_bypass_count(
        conn,
        _queue_fairness_meta_key(roles),
        value,
        maximum=MAX_CONSECUTIVE_PRIORITY_BYPASSES,
    )


def _queue_retry_bypass_count(conn, roles: set[str] | None) -> int:
    return _queue_bypass_count(
        conn,
        _queue_retry_fairness_meta_key(roles),
    )


def _set_queue_retry_bypass_count(
    conn,
    roles: set[str] | None,
    value: int,
) -> None:
    _set_queue_bypass_count(
        conn,
        _queue_retry_fairness_meta_key(roles),
        value,
        maximum=MAX_CONSECUTIVE_RETRY_BYPASSES,
    )


def _role_filtered_candidate_sql(
    *,
    oldest: bool,
    exclude_deferred: bool = False,
    retry_pending: bool | None = None,
    retry_rotation: bool = False,
) -> str:
    if retry_rotation:
        if oldest or retry_pending is not True:
            raise ValueError(
                "retry rotation requires the retry-pending lane"
            )
        index_name = "idx_queue_role_retry"
        order_by = (
            "pending_job.retry_order ASC, "
            "pending_job.priority ASC, "
            "pending_job.created_at ASC, pending_job.rowid ASC"
        )
    elif oldest:
        index_name = "idx_queue_role_created"
        order_by = (
            "pending_job.created_at ASC, pending_job.rowid ASC"
        )
    else:
        index_name = "idx_queue_role_priority"
        order_by = (
            "pending_job.priority ASC, pending_job.created_at ASC, "
            "pending_job.rowid ASC"
        )
    deferred_clause = (
        """
          AND pending_job.id NOT IN (
              SELECT value FROM json_each(?)
          )"""
        if exclude_deferred
        else ""
    )
    retry_clause = (
        "AND pending_job.retry_pending = ?"
        if retry_pending is not None
        else ""
    )
    return f"""
        SELECT pending_job.*, pending_job.rowid AS queue_rowid
        FROM queue_jobs AS pending_job INDEXED BY {index_name}
        WHERE pending_job.role = ? AND pending_job.status = ?
          {retry_clause}
          {deferred_clause}
          AND (
              pending_job.dedupe_key IS NULL
              OR NOT EXISTS (
                  SELECT 1
                  FROM queue_jobs AS active_job
                  WHERE active_job.status = '{ACTIVE_JOB_STATUS}'
                    AND active_job.dedupe_key = pending_job.dedupe_key
              )
          )
        ORDER BY {order_by}
        LIMIT 1
    """


def _eligible_job_candidate(
    conn,
    roles: set[str] | None,
    *,
    oldest: bool,
    deferred_job_ids: set[str] | None = None,
    retry_pending: bool | None = None,
    retry_rotation: bool = False,
) -> sqlite3.Row | None:
    if retry_rotation and (oldest or retry_pending is not True):
        raise ValueError(
            "retry rotation requires the retry-pending lane"
        )
    deferred_ids = sorted(
        {str(job_id) for job_id in (deferred_job_ids or set())}
    )
    deferred_json = json_dumps(deferred_ids) if deferred_ids else None
    if roles:
        candidates: list[sqlite3.Row] = []
        query = _role_filtered_candidate_sql(
            oldest=oldest,
            exclude_deferred=bool(deferred_ids),
            retry_pending=retry_pending,
            retry_rotation=retry_rotation,
        )
        for role in sorted(roles):
            params: list[Any] = [role, PENDING_JOB_STATUS]
            if retry_pending is not None:
                params.append(1 if retry_pending else 0)
            if deferred_json is not None:
                params.append(deferred_json)
            row = conn.execute(
                query,
                params,
            ).fetchone()
            if row is not None:
                candidates.append(row)
        if not candidates:
            return None
        if retry_rotation:
            return min(
                candidates,
                key=lambda row: (
                    int(row["retry_order"]),
                    int(row["priority"]),
                    str(row["created_at"]),
                    int(row["queue_rowid"]),
                ),
            )
        if oldest:
            return min(
                candidates,
                key=lambda row: (
                    str(row["created_at"]),
                    int(row["queue_rowid"]),
                ),
            )
        return min(
            candidates,
            key=lambda row: (
                int(row["priority"]),
                str(row["created_at"]),
                int(row["queue_rowid"]),
            ),
        )
    if retry_rotation:
        index_name = "idx_queue_status_retry"
        order_by = (
            "pending_job.retry_order ASC, "
            "pending_job.priority ASC, "
            "pending_job.created_at ASC, pending_job.rowid ASC"
        )
    elif oldest:
        index_name = "idx_queue_status_created"
        order_by = "pending_job.created_at ASC, pending_job.rowid ASC"
    else:
        index_name = "idx_queue_status_priority"
        order_by = (
            "pending_job.priority ASC, pending_job.created_at ASC, "
            "pending_job.rowid ASC"
        )
    deferred_clause = (
        """
          AND pending_job.id NOT IN (
              SELECT value FROM json_each(?)
          )"""
        if deferred_json is not None
        else ""
    )
    retry_clause = (
        "AND pending_job.retry_pending = ?"
        if retry_pending is not None
        else ""
    )
    params = [PENDING_JOB_STATUS]
    if retry_pending is not None:
        params.append(1 if retry_pending else 0)
    if deferred_json is not None:
        params.append(deferred_json)
    return conn.execute(
        f"""
        SELECT pending_job.*, pending_job.rowid AS queue_rowid
        FROM queue_jobs AS pending_job INDEXED BY {index_name}
        WHERE pending_job.status = ?
          {retry_clause}
          {deferred_clause}
          AND (
              pending_job.dedupe_key IS NULL
              OR NOT EXISTS (
                  SELECT 1
                  FROM queue_jobs AS active_job
                  WHERE active_job.status = '{ACTIVE_JOB_STATUS}'
                    AND active_job.dedupe_key = pending_job.dedupe_key
              )
          )
        ORDER BY {order_by}
        LIMIT 1
        """,
        params,
    ).fetchone()


def _claim_job(
    conn,
    roles: set[str] | None = None,
    *,
    lease_owner: str,
    lease_seconds: int,
    deferred_job_ids: set[str] | None = None,
) -> dict[str, Any] | None:
    fresh_priority_row = _eligible_job_candidate(
        conn,
        roles,
        oldest=False,
        deferred_job_ids=deferred_job_ids,
        retry_pending=False,
    )
    retry_row = _eligible_job_candidate(
        conn,
        roles,
        oldest=False,
        deferred_job_ids=deferred_job_ids,
        retry_pending=True,
        retry_rotation=True,
    )
    if fresh_priority_row is None and retry_row is None:
        _set_queue_priority_bypass_count(conn, roles, 0)
        _set_queue_retry_bypass_count(conn, roles, 0)
        return None

    priority_bypass_count = 0
    next_priority_bypass_count = 0
    fresh_row = fresh_priority_row
    if fresh_priority_row is not None:
        oldest_fresh_row = _eligible_job_candidate(
            conn,
            roles,
            oldest=True,
            deferred_job_ids=deferred_job_ids,
            retry_pending=False,
        )
        if oldest_fresh_row is not None:
            priority_bypass_count = _queue_priority_bypass_count(
                conn,
                roles,
            )
            real_priority_bypass = (
                str(fresh_priority_row["id"])
                != str(oldest_fresh_row["id"])
            )
            if (
                real_priority_bypass
                and priority_bypass_count
                >= MAX_CONSECUTIVE_PRIORITY_BYPASSES
            ):
                fresh_row = oldest_fresh_row
            else:
                next_priority_bypass_count = (
                    priority_bypass_count + 1
                    if real_priority_bypass
                    else 0
                )

    if fresh_row is not None and retry_row is not None:
        retry_bypass_count = _queue_retry_bypass_count(conn, roles)
        if (
            retry_bypass_count
            >= MAX_CONSECUTIVE_RETRY_BYPASSES
        ):
            row = retry_row
            next_retry_bypass_count = 0
            next_priority_bypass_count = priority_bypass_count
        else:
            row = fresh_row
            next_retry_bypass_count = retry_bypass_count + 1
    elif fresh_row is not None:
        row = fresh_row
        next_retry_bypass_count = 0
    else:
        if retry_row is None:
            raise RuntimeError(
                "queue candidate selection invariant violated"
            )
        row = retry_row
        next_retry_bypass_count = 0
        next_priority_bypass_count = 0
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
    _set_queue_priority_bypass_count(
        conn,
        roles,
        next_priority_bypass_count,
    )
    _set_queue_retry_bypass_count(
        conn,
        roles,
        next_retry_bypass_count,
    )
    job = dict(row)
    job.pop("queue_rowid", None)
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
          AND lease_expires_at IS NOT NULL
          AND lease_expires_at > ?
        """,
        (now, expires_at, now, job_id, ACTIVE_JOB_STATUS, lease_owner, now),
    )
    return int(cursor.rowcount or 0) == 1


def _job_lease_is_owned(conn, job_id: str, *, lease_owner: str) -> bool:
    now = utc_now()
    row = conn.execute(
        """
        SELECT 1
        FROM queue_jobs
        WHERE id = ?
          AND status = ?
          AND lease_owner = ?
          AND lease_expires_at IS NOT NULL
          AND lease_expires_at > ?
        """,
        (job_id, ACTIVE_JOB_STATUS, lease_owner, now),
    ).fetchone()
    return row is not None


def _prior_worker_effect(conn, lease: _JobLease | None) -> dict[str, Any] | None:
    if lease is None:
        return None
    row = conn.execute(
        """
        SELECT payload_json
        FROM audit_events
        WHERE action = ? AND target_type = 'queue_job' AND target_id = ?
        ORDER BY rowid DESC
        LIMIT 1
        """,
        (_WORKER_EFFECT_ACTION, lease.job_id),
    ).fetchone()
    if row is None:
        return None
    payload = json_loads(row["payload_json"], {})
    result = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(result, dict):
        return None
    replayed = {**result, "idempotent_replay": True}
    if payload.get("post_phase_complete") is True:
        replayed[_WORKER_POST_PHASE_COMPLETE_KEY] = True
    return replayed


def _prior_non_post_phase_worker_effect(
    conn,
    lease: _JobLease | None,
    *,
    job_type: str,
) -> dict[str, Any] | None:
    """Read an exact legacy core receipt without treating terminal output as core."""

    if lease is None:
        return None
    row = conn.execute(
        """
        SELECT payload_json
        FROM audit_events
        WHERE action = ? AND target_type = 'queue_job' AND target_id = ?
          AND json_valid(payload_json)
          AND json_extract(payload_json, '$.schema') = ?
          AND json_extract(payload_json, '$.job_type') = ?
          AND (
              json_type(payload_json, '$.post_phase_complete') = 'false'
              OR json_type(payload_json, '$.post_phase_complete') IS NULL
          )
        ORDER BY rowid DESC
        LIMIT 1
        """,
        (
            _WORKER_EFFECT_ACTION,
            lease.job_id,
            _WORKER_EFFECT_SCHEMA,
            job_type,
        ),
    ).fetchone()
    if row is None:
        return None
    payload = json_loads(row["payload_json"], {})
    if not isinstance(payload, dict):
        return None
    required_keys = {"schema", "job_type", "result"}
    if (
        not required_keys.issubset(payload)
        or set(payload) - required_keys - {"post_phase_complete"}
        or (
            "post_phase_complete" in payload
            and payload["post_phase_complete"] is not False
        )
    ):
        return None
    result = payload.get("result")
    if not isinstance(result, dict):
        return None
    return dict(result)


def _record_worker_effect(
    conn,
    lease: _JobLease | None,
    *,
    job_type: str,
    result: dict[str, Any],
    post_phase_complete: bool = False,
) -> None:
    if lease is None:
        return
    lease.assert_owned(conn)
    audit_event(
        conn,
        action=_WORKER_EFFECT_ACTION,
        target_type="queue_job",
        target_id=lease.job_id,
        payload={
            "schema": _WORKER_EFFECT_SCHEMA,
            "job_type": job_type,
            "post_phase_complete": bool(post_phase_complete),
            "result": result,
        },
    )


def _begin_worker_effect(conn, lease: _JobLease | None) -> dict[str, Any] | None:
    if lease is None:
        return None
    lease.assert_owned(conn)
    return _prior_worker_effect(conn, lease)


def _prior_worker_phase(
    conn,
    lease: _JobLease | None,
    *,
    job_type: str,
    phase: str,
) -> dict[str, Any] | None:
    if lease is None:
        return None
    lease.assert_owned(conn)
    row = conn.execute(
        """
        SELECT payload_json
        FROM audit_events
        WHERE action = ? AND target_type = 'queue_job' AND target_id = ?
          AND json_valid(payload_json)
          AND json_extract(payload_json, '$.job_type') = ?
          AND json_extract(payload_json, '$.phase') = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (_WORKER_PHASE_ACTION, lease.job_id, job_type, phase),
    ).fetchone()
    if row is None:
        return None
    payload = json_loads(row["payload_json"], {})
    result = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(result, dict):
        raise RuntimeError(
            f"Committed {job_type} worker phase has an invalid result"
        )
    return result


def _record_worker_phase(
    conn,
    lease: _JobLease | None,
    *,
    job_type: str,
    phase: str,
    result: dict[str, Any],
) -> None:
    if lease is None:
        return
    lease.assert_owned(conn)
    audit_event(
        conn,
        action=_WORKER_PHASE_ACTION,
        target_type="queue_job",
        target_id=lease.job_id,
        payload={
            "schema": _WORKER_PHASE_SCHEMA,
            "job_type": job_type,
            "phase": phase,
            "result": result,
        },
    )


def _commit_worker_effect_result(
    root: Path,
    lease: _JobLease | None,
    *,
    job_type: str,
    result: dict[str, Any],
) -> None:
    if lease is None:
        return
    receipt_conn = connect(root)
    try:
        receipt_conn.execute("BEGIN IMMEDIATE")
        _record_worker_effect(
            receipt_conn,
            lease,
            job_type=job_type,
            result=result,
            post_phase_complete=True,
        )
        receipt_conn.commit()
    except Exception:
        receipt_conn.rollback()
        raise
    finally:
        receipt_conn.close()


def _commit_sidecar_worker_phase(
    conn,
    lease: _JobLease | None,
    *,
    result: dict[str, Any],
    phase: str,
    terminal: bool,
) -> None:
    """Fence and durably bind each sidecar-worker database commit."""

    if lease is not None:
        if not lease.renew_in_transaction(conn):
            raise RuntimeError("worker lease lost before committing job effects")
        if terminal:
            _record_worker_effect(
                conn,
                lease,
                job_type="sync_card_sidecar",
                result=result,
            )
        else:
            lease.assert_owned(conn)
            audit_event(
                conn,
                action=_SIDECAR_WORKER_PHASE_ACTION,
                target_type="queue_job",
                target_id=lease.job_id,
                payload={
                    "schema": _SIDECAR_WORKER_PHASE_SCHEMA,
                    "job_type": "sync_card_sidecar",
                    "phase": phase,
                    "result": result,
                },
            )
    conn.commit()


def _reconcile_sidecar_worker_intents(root: Path, card_id: str) -> dict[str, Any]:
    """Convert transient reconciliation exceptions into durable retry state."""

    return _reconcile_worker_sidecar_intents_with_budget(
        root,
        card_id=card_id,
    )


def _defer_worker_card_sidecars_for_intent_budget(
    root: Path,
    card_ids: list[str],
    budget: dict[str, int],
) -> dict[str, Any]:
    unique_card_ids = [
        card_id for card_id in dict.fromkeys(card_ids) if card_id
    ]
    if not unique_card_ids:
        return {
            "ok": True,
            "synced": 0,
            "deferred": 0,
            "failed": 0,
            "failures": [],
            "compensation_cas_complete": True,
            "compensation_cas_rows": [],
            "worker_intent_budget": (
                _worker_sidecar_intent_budget_snapshot(budget)
            ),
        }
    conn = connect(root)
    try:
        conn.execute("BEGIN IMMEDIATE")
        mark_card_sidecar_outbox(
            conn,
            unique_card_ids,
            reason="worker_intent_budget_exhausted",
        )
        audit_event(
            conn,
            action="worker_card_sidecar_intent_budget_exhausted",
            target_type="cards",
            target_id=None,
            payload={"card_ids": unique_card_ids},
        )
        compensation_rows: list[dict[str, Any]] = []
        for card_id in unique_card_ids:
            row = conn.execute(
                """
                SELECT card.location_uri,
                       outbox.generation AS sidecar_generation
                FROM cards AS card
                LEFT JOIN card_sidecar_outbox AS outbox
                  ON outbox.card_id = card.id
                WHERE card.id = ?
                """,
                (card_id,),
            ).fetchone()
            if row is None:
                continue
            compensation_rows.append(
                {
                    "card_id": card_id,
                    "location_uri": (
                        str(row["location_uri"])
                        if row["location_uri"] is not None
                        else None
                    ),
                    "sidecar_generation": (
                        str(row["sidecar_generation"])
                        if row["sidecar_generation"] is not None
                        else None
                    ),
                }
            )
        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()
    reconciliation = _worker_sidecar_intent_budget_exhausted_result(
        budget,
        card_id=None,
        ok=False,
    )
    failure = {
        "card_id": None,
        "error": "Worker Card sidecar intent budget exhausted; retry deferred",
        "intent_reconciliation": reconciliation,
    }
    return {
        "ok": False,
        "synced": 0,
        "deferred": len(unique_card_ids),
        "failed": len(unique_card_ids),
        "failures": [failure],
        "generated_sidecar_candidates": [],
        "intent_reconciliation_results": [],
        "intent_reconciliation": reconciliation,
        "compensation_cas_complete": (
            len(compensation_rows) == len(unique_card_ids)
        ),
        "compensation_cas_rows": compensation_rows,
        "worker_intent_budget": (
            _worker_sidecar_intent_budget_snapshot(budget)
        ),
    }


def _sync_worker_card_sidecars(
    root: Path,
    card_ids: list[str],
    *,
    reconcile_intents: bool = True,
) -> dict[str, Any]:
    """Materialize worker-owned sidecars under the shared intent budget."""

    if not reconcile_intents:
        shared_budget = _current_card_sidecar_intent_reconciliation_budget()
        budget = shared_budget or {
            "limit": WORKER_SIDECAR_INTENT_LIMIT,
            "used": 0,
            "remaining": WORKER_SIDECAR_INTENT_LIMIT,
        }
        result = dict(
            sync_card_sidecars_after_commit(
                root,
                card_ids,
                reconcile_intents=False,
            )
        )
        result["worker_intent_budget"] = (
            _worker_sidecar_intent_budget_snapshot(budget)
        )
        return result

    budget, allowance, shared = (
        _worker_sidecar_intent_budget_allowance()
    )
    if allowance <= 0:
        return _defer_worker_card_sidecars_for_intent_budget(
            root,
            card_ids,
            budget,
        )
    try:
        with _card_sidecar_intent_reconciliation_limit(allowance):
            raw_result = sync_card_sidecars_after_commit(
                root,
                card_ids,
            )
    except Exception:
        if not shared:
            _charge_worker_sidecar_intent_budget(
                budget,
                allowance=allowance,
                result=None,
            )
        raise
    result = dict(raw_result)
    raw_reconciliation = result.get("intent_reconciliation")
    reconciliation = (
        raw_reconciliation
        if isinstance(raw_reconciliation, dict)
        else None
    )
    if not shared:
        _charge_worker_sidecar_intent_budget(
            budget,
            allowance=allowance,
            result=reconciliation,
        )
    result["worker_intent_budget"] = (
        _worker_sidecar_intent_budget_snapshot(budget)
    )
    return result


def _sidecar_result_requires_queue_retry(
    sidecars: dict[str, Any] | None,
) -> bool:
    """Identify incomplete post-commit sidecar authority that remains durable."""

    if not isinstance(sidecars, dict) or sidecars.get("ok", True):
        return False
    if sidecars.get("completion_receipt_missing"):
        return bool(sidecars.get("pending_outbox"))
    return True


def _result_has_failed_sidecar_phase(result: dict[str, Any] | None) -> bool:
    """Recognize only the sidecar result locations owned by worker protocols."""

    if not isinstance(result, dict) or result.get("ok") is not False:
        return False
    known_sidecars: list[Any] = [result.get("sidecars")]
    conflicts = result.get("conflicts")
    if isinstance(conflicts, dict):
        known_sidecars.append(conflicts.get("sidecars"))
    rolled = result.get("rolled")
    if isinstance(rolled, list):
        known_sidecars.extend(
            item.get("sidecars")
            for item in rolled
            if isinstance(item, dict)
        )
    return any(
        isinstance(sidecars, dict) and sidecars.get("ok") is False
        for sidecars in known_sidecars
    )


def _result_has_explicit_non_sidecar_failure(
    result: dict[str, Any] | None,
) -> bool:
    """Keep explicit business failures outside sidecar retry/recovery paths."""

    if not isinstance(result, dict):
        return True
    for key in ("reason", "error"):
        value = result.get(key)
        if value not in (None, "", POST_COMMIT_SIDECAR_RETRY_REASON):
            return True
    rolled = result.get("rolled")
    if not isinstance(rolled, list):
        return False
    for item in rolled:
        if not isinstance(item, dict):
            return True
        if item.get("ok") is not False:
            continue
        sidecars = item.get("sidecars")
        if not (
            isinstance(sidecars, dict)
            and sidecars.get("ok") is False
        ):
            return True
        if any(item.get(key) not in (None, "") for key in ("reason", "error")):
            return True
    return False


def _result_is_replayable_sidecar_failure(
    result: dict[str, Any] | None,
) -> bool:
    return bool(
        _result_has_failed_sidecar_phase(result)
        and not _result_has_explicit_non_sidecar_failure(result)
    )


def _mark_post_commit_sidecar_retry(
    result: dict[str, Any],
    *sidecar_results: dict[str, Any] | None,
) -> bool:
    retry_pending = any(
        _sidecar_result_requires_queue_retry(sidecars)
        for sidecars in sidecar_results
    )
    if retry_pending:
        result["ok"] = False
        result["reason"] = POST_COMMIT_SIDECAR_RETRY_REASON
        result["retry_pending"] = True
    return retry_pending


def _record_scribe_step_intent(
    root: Path,
    lease: _JobLease | None,
    *,
    session_id: str,
    start_seq: int,
    end_seq: int,
) -> None:
    """Bind one deterministic Scribe range to its queue job before store commit."""
    if lease is None:
        return
    step_key = f"{session_id}:{int(start_seq)}:{int(end_seq)}"
    conn = connect(root)
    try:
        conn.execute("BEGIN IMMEDIATE")
        lease.assert_owned(conn)
        already_recorded = conn.execute(
            """
            SELECT 1
            FROM audit_events
            WHERE action = ? AND target_type = 'queue_job' AND target_id = ?
              AND json_valid(payload_json)
              AND json_extract(payload_json, '$.step_key') = ?
            LIMIT 1
            """,
            (_SCRIBE_STEP_ACTION, lease.job_id, step_key),
        ).fetchone()
        if already_recorded is None:
            audit_event(
                conn,
                action=_SCRIBE_STEP_ACTION,
                target_type="queue_job",
                target_id=lease.job_id,
                payload={
                    "schema": "continuum.worker_scribe_segment_step.v1",
                    "step_key": step_key,
                    "session_id": session_id,
                    "start_seq": int(start_seq),
                    "end_seq": int(end_seq),
                },
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _record_scribe_step_committed(
    conn,
    lease: _JobLease | None,
    *,
    session_id: str,
    start_seq: int,
    end_seq: int,
    batch_number: int,
    result: dict[str, Any],
) -> None:
    """Commit one Scribe step receipt atomically with its segment effects."""

    if lease is None:
        return
    lease.assert_owned(conn)
    step_key = f"{session_id}:{int(start_seq)}:{int(end_seq)}"
    already_recorded = conn.execute(
        """
        SELECT 1
        FROM audit_events
        WHERE action = ? AND target_type = 'queue_job' AND target_id = ?
          AND json_valid(payload_json)
          AND json_extract(payload_json, '$.step_key') = ?
        LIMIT 1
        """,
        (_SCRIBE_STEP_COMMITTED_ACTION, lease.job_id, step_key),
    ).fetchone()
    if already_recorded is None:
        audit_event(
            conn,
            action=_SCRIBE_STEP_COMMITTED_ACTION,
            target_type="queue_job",
            target_id=lease.job_id,
            payload={
                "schema": "continuum.worker_scribe_segment_step_committed.v1",
                "step_key": step_key,
                "session_id": session_id,
                "start_seq": int(start_seq),
                "end_seq": int(end_seq),
                "batch_number": int(batch_number),
                "result": result,
            },
        )


def _record_scribe_step_completed(
    root: Path,
    lease: _JobLease | None,
    *,
    session_id: str,
    start_seq: int,
    end_seq: int,
    batch_number: int,
    result: dict[str, Any],
) -> None:
    """Bind the post-sidecar Scribe result to its already committed step."""

    if lease is None:
        return
    step_key = f"{session_id}:{int(start_seq)}:{int(end_seq)}"
    conn = connect(root)
    try:
        conn.execute("BEGIN IMMEDIATE")
        lease.assert_owned(conn)
        already_recorded = conn.execute(
            """
            SELECT 1
            FROM audit_events
            WHERE action = ? AND target_type = 'queue_job' AND target_id = ?
              AND json_valid(payload_json)
              AND json_extract(payload_json, '$.step_key') = ?
            LIMIT 1
            """,
            (_SCRIBE_STEP_COMPLETED_ACTION, lease.job_id, step_key),
        ).fetchone()
        if already_recorded is None:
            audit_event(
                conn,
                action=_SCRIBE_STEP_COMPLETED_ACTION,
                target_type="queue_job",
                target_id=lease.job_id,
                payload={
                    "schema": "continuum.worker_scribe_segment_step_completed.v1",
                    "step_key": step_key,
                    "session_id": session_id,
                    "start_seq": int(start_seq),
                    "end_seq": int(end_seq),
                    "batch_number": int(batch_number),
                    "result": result,
                },
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _committed_scribe_steps(
    root: Path,
    lease: _JobLease | None,
) -> tuple[list[dict[str, Any]], int]:
    if lease is None:
        return [], 0
    conn = connect(root)
    try:
        rows = conn.execute(
            """
            SELECT action, payload_json
            FROM audit_events
            WHERE action IN (?, ?)
              AND target_type = 'queue_job' AND target_id = ?
            ORDER BY rowid
            """,
            (
                _SCRIBE_STEP_COMMITTED_ACTION,
                _SCRIBE_STEP_COMPLETED_ACTION,
                lease.job_id,
            ),
        ).fetchall()
    finally:
        conn.close()
    committed_payloads: list[dict[str, Any]] = []
    completed_by_step: dict[str, dict[str, Any]] = {}
    for row in rows:
        payload = json_loads(row["payload_json"], {})
        if not isinstance(payload, dict):
            continue
        step_key = str(payload.get("step_key") or "")
        step_result = payload.get("result")
        if not step_key or not isinstance(step_result, dict):
            continue
        if str(row["action"]) == _SCRIBE_STEP_COMPLETED_ACTION:
            completed_by_step[step_key] = step_result
        else:
            committed_payloads.append(payload)
    committed: list[dict[str, Any]] = []
    seen_segments: set[str] = set()
    max_batch_number = 0
    missing_expected_sidecars: set[str] = set()
    location_conn = connect_existing(root)
    try:
        for payload in committed_payloads:
            step_result = payload.get("result")
            if not isinstance(step_result, dict):
                continue
            segment_id = str(step_result.get("segment_id") or "")
            if not segment_id or segment_id in seen_segments:
                continue
            seen_segments.add(segment_id)
            step_key = str(payload.get("step_key") or "")
            completed_result = completed_by_step.get(step_key)
            materialized = dict(completed_result or step_result)
            committed_card_id = str(step_result.get("card_id") or "")
            committed_segment_id = str(step_result.get("segment_id") or "")
            completed_identity_matches = bool(
                isinstance(completed_result, dict)
                and str(completed_result.get("card_id") or "")
                == committed_card_id
                and str(completed_result.get("segment_id") or "")
                == committed_segment_id
            )
            revalidate_sidecars = bool(
                completed_result is None
                or (
                    completed_identity_matches
                    and _result_is_replayable_sidecar_failure(
                        completed_result
                    )
                )
            )
            card_id = (
                committed_card_id
                if revalidate_sidecars
                else str(materialized.get("card_id") or "")
            )
            card_state = (
                location_conn.execute(
                    """
                    SELECT c.location_uri, c.status,
                           EXISTS(
                               SELECT 1
                               FROM card_sidecar_outbox AS outbox
                               WHERE outbox.card_id = c.id
                           ) AS sidecar_pending
                    FROM cards AS c
                    WHERE c.id = ?
                    """,
                    (card_id,),
                ).fetchone()
                if card_id
                else None
            )
            sidecar_path = (
                current_card_sidecar_path(root, location_conn, card_id)
                if card_state is not None
                else None
            )
            sidecar_exists = bool(
                sidecar_path is not None and sidecar_path.exists()
            )
            materialized["card_uri"] = (
                str(sidecar_path)
                if sidecar_exists
                else None
            )
            if revalidate_sidecars:
                sidecar_pending = bool(
                    card_state is not None and card_state["sidecar_pending"]
                )
                card_is_current = bool(
                    card_state is not None
                    and str(card_state["status"] or "").casefold()
                    not in NON_CURRENT_CARD_STATUSES
                )
                sidecar_expected = bool(
                    card_state is not None and card_state["location_uri"]
                )
                if (
                    card_is_current
                    and sidecar_expected
                    and not sidecar_pending
                    and not sidecar_exists
                ):
                    missing_expected_sidecars.add(card_id)
                    sidecar_pending = True
                sidecar_ok = bool(
                    card_is_current
                    and not sidecar_pending
                    and (not sidecar_expected or sidecar_exists)
                )
                sidecar_result: dict[str, Any] = {
                    "ok": sidecar_ok,
                    "synced": int(sidecar_ok and sidecar_expected),
                    "failed": int(not sidecar_ok),
                    "pending_outbox": sidecar_pending,
                    "completion_receipt_missing": completed_result is None,
                    "replayed_from_committed_step": True,
                    "stale_failed_completion_revalidated": (
                        completed_result is not None
                    ),
                }
                if not sidecar_ok:
                    sidecar_result["failures"] = [
                        {
                            "card_id": card_id or None,
                            "error": (
                                "Committed Scribe step still has no durable "
                                "post-sidecar success evidence"
                            ),
                        }
                    ]
                materialized["segment_id"] = committed_segment_id
                materialized["card_id"] = committed_card_id
                materialized["ok"] = sidecar_ok
                materialized["sidecars"] = sidecar_result
                if sidecar_ok:
                    materialized.pop("reason", None)
                    materialized.pop("error", None)
                    materialized.pop("retry_pending", None)
            committed.append(materialized)
            try:
                max_batch_number = max(
                    max_batch_number,
                    int(payload.get("batch_number") or 0),
                )
            except (TypeError, ValueError):
                pass
    finally:
        location_conn.close()
    if missing_expected_sidecars:
        rearm_conn = connect(root)
        try:
            rearm_conn.execute("BEGIN IMMEDIATE")
            live_card_ids: list[str] = []
            for card_id in sorted(missing_expected_sidecars):
                row = rearm_conn.execute(
                    """
                    SELECT status, location_uri
                    FROM cards
                    WHERE id = ?
                    """,
                    (card_id,),
                ).fetchone()
                if (
                    row is not None
                    and str(row["status"] or "").casefold()
                    not in NON_CURRENT_CARD_STATUSES
                    and row["location_uri"]
                ):
                    live_card_ids.append(card_id)
            if live_card_ids:
                mark_card_sidecar_outbox(
                    rearm_conn,
                    live_card_ids,
                    reason="scribe_committed_step_sidecar_authority_missing",
                )
                audit_event(
                    rearm_conn,
                    action="worker_scribe_sidecar_authority_rearmed",
                    target_type="queue_job",
                    target_id=lease.job_id,
                    payload={
                        "schema": (
                            "continuum."
                            "worker_scribe_sidecar_authority_rearmed.v1"
                        ),
                        "card_ids": live_card_ids,
                    },
                    actor="worker",
                )
            rearm_conn.commit()
        except Exception:
            if rearm_conn.in_transaction:
                rearm_conn.rollback()
            raise
        finally:
            rearm_conn.close()
    return committed, max_batch_number


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
        where_clause = (
            "WHERE id = ? AND status = ? AND lease_owner = ? "
            "AND lease_expires_at IS NOT NULL AND lease_expires_at > ?"
        )
        params.extend([ACTIVE_JOB_STATUS, lease_owner, now])
    cursor = conn.execute(
        f"""
        UPDATE queue_jobs
        SET status = ?, finished_at = ?, updated_at = ?, error_json = ?,
            lease_owner = NULL, lease_expires_at = NULL, heartbeat_at = ?,
            retry_pending = 0, retry_order = 0
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


def _retry_owned_job(
    conn,
    job_id: str,
    *,
    lease_owner: str,
    lease_seconds: int,
    result: dict[str, Any],
) -> None:
    """Release an owned lease back to pending without recording a failure."""

    if not _heartbeat_job(conn, job_id, lease_owner=lease_owner, lease_seconds=lease_seconds):
        raise RuntimeError("worker lease lost before job retry")
    now = utc_now()
    retry_order = _next_queue_retry_order(conn)
    cursor = conn.execute(
        """
        UPDATE queue_jobs
        SET status = ?, finished_at = NULL, updated_at = ?, error_json = ?,
            lease_owner = NULL, lease_expires_at = NULL,
            heartbeat_at = NULL, retry_pending = 1, retry_order = ?
        WHERE id = ? AND status = ? AND lease_owner = ?
          AND lease_expires_at IS NOT NULL AND lease_expires_at > ?
        """,
        (
            PENDING_JOB_STATUS,
            now,
            json_dumps({"error": None, "result": result, "retry_pending": True}),
            retry_order,
            job_id,
            ACTIVE_JOB_STATUS,
            lease_owner,
            now,
        ),
    )
    if int(cursor.rowcount or 0) != 1:
        raise RuntimeError("worker lease lost before job retry")


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
    heartbeat: Callable[[], bool] | None = None,
) -> list[str]:
    changed: list[str] = []
    now = utc_now()
    for index, card in enumerate(cards):
        if heartbeat is not None and index % 64 == 0 and not heartbeat():
            raise RuntimeError("worker lease lost during MemPalace reconciliation")
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
    if heartbeat is not None and changed and not heartbeat():
        raise RuntimeError("worker lease lost during MemPalace reconciliation")
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
                heartbeat_at = ?, retry_pending = 0, retry_order = 0
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
        sidecars = _sync_worker_card_sidecars(root, changed_cards)
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
    recover_pending_card_sidecars: bool = True,
) -> dict[str, Any]:
    """Complete Librarian placement for graph-linked cards from one MemPalace import."""
    import_id = str(import_id or "").strip()
    if not import_id:
        return {"ok": False, "reason": "import_id_missing", "reviewed_import": import_id}
    limit = _bounded_reconcile_limit(limit, field="limit")
    init_db(
        root,
        recover_pending_card_sidecars=recover_pending_card_sidecars,
    )
    conn = connect(root)
    changed_cards: list[str] = []
    core_result: dict[str, Any]
    lease = _CURRENT_JOB_LEASE.get()
    try:
        conn.execute("BEGIN IMMEDIATE")
        prior = _begin_worker_effect(conn, lease)
        legacy_core_result: dict[str, Any] | None = None
        failed_terminal_replay: dict[str, Any] | None = None
        if prior is not None:
            post_phase_complete = bool(
                prior.pop(_WORKER_POST_PHASE_COMPLETE_KEY, False)
            )
            if post_phase_complete:
                if not _result_is_replayable_sidecar_failure(prior):
                    conn.commit()
                    return prior
                failed_terminal_replay = dict(prior)
                legacy_core_result = _prior_non_post_phase_worker_effect(
                    conn,
                    lease,
                    job_type="review_mempalace_import",
                )
            else:
                legacy_core_result = dict(prior)
            if legacy_core_result is not None:
                legacy_core_result.pop("idempotent_replay", None)
        committed_phase = _prior_worker_phase(
            conn,
            lease,
            job_type="review_mempalace_import",
            phase="core",
        )
        if committed_phase is not None:
            phase_core_result = committed_phase.get("core_result")
            phase_changed_cards = committed_phase.get("changed_cards")
            if (
                not isinstance(phase_core_result, dict)
                or str(phase_core_result.get("reviewed_import") or "")
                != import_id
                or phase_core_result.get("ok") is not True
                or not isinstance(phase_changed_cards, list)
                or any(
                    not isinstance(card_id, str) or not card_id
                    for card_id in phase_changed_cards
                )
            ):
                raise RuntimeError(
                    "Committed review_mempalace_import core phase is invalid"
                )
            core_result = dict(phase_core_result)
            changed_cards = list(dict.fromkeys(phase_changed_cards))
            conn.commit()
        elif legacy_core_result is not None:
            if (
                str(legacy_core_result.get("reviewed_import") or "")
                != import_id
                or legacy_core_result.get("ok") is not True
                or _result_has_failed_sidecar_phase(legacy_core_result)
            ):
                raise RuntimeError(
                    "Legacy review_mempalace_import receipt is invalid"
                )
            pending_outbox = (
                conn.execute(
                    """
                    SELECT 1
                    FROM cards AS card
                    JOIN card_sidecar_outbox AS outbox
                      ON outbox.card_id = card.id
                    WHERE card.card_type LIKE 'mempalace_%'
                      AND json_valid(card.metadata_json)
                      AND json_extract(
                          card.metadata_json,
                          '$.import_id'
                      ) = ?
                    LIMIT 1
                    """,
                    (import_id,),
                ).fetchone()
                is not None
            )
            conn.commit()
            legacy_sidecars: dict[str, Any] = {
                "ok": not pending_outbox,
                "synced": 0,
                "failed": int(pending_outbox),
                "pending_outbox": pending_outbox,
                "legacy_core_receipt_revalidated": True,
            }
            if pending_outbox:
                legacy_sidecars["failures"] = [
                    {
                        "error": (
                            "Legacy MemPalace core receipt has pending "
                            "sidecar authority"
                        )
                    }
                ]
            result = {
                **legacy_core_result,
                "ok": bool(legacy_core_result.get("ok"))
                and not pending_outbox,
                "sidecars": legacy_sidecars,
            }
            retry_pending = _mark_post_commit_sidecar_retry(
                result,
                legacy_sidecars,
            )
            if not retry_pending:
                _commit_worker_effect_result(
                    root,
                    lease,
                    job_type="review_mempalace_import",
                    result=result,
                )
            return result
        elif failed_terminal_replay is not None:
            conn.commit()
            return failed_terminal_replay
        else:
            candidate_window = _legacy_card_candidates(
                conn,
                limit=limit + 1,
                import_id=import_id,
            )
            cards = candidate_window[:limit]
            has_more = len(candidate_window) > limit
            eligible_before = len(candidate_window)
            changed_cards = _apply_graph_placed_card_reconciliation(
                conn,
                cards,
                reason="reviewed_mempalace_import",
                heartbeat=(
                    lambda: lease.renew_in_transaction(conn)
                )
                if lease is not None
                else None,
            )
            remaining = max(0, len(candidate_window) - len(cards))
            complete = not has_more
            continuation_job_id: str | None = None
            if not complete:
                continuation_role = "librarian"
                continuation_priority = 65
                if lease is not None:
                    current_job = conn.execute(
                        "SELECT role, priority FROM queue_jobs WHERE id = ?",
                        (lease.job_id,),
                    ).fetchone()
                    if current_job is not None:
                        continuation_role = str(
                            current_job["role"] or continuation_role
                        )
                        continuation_priority = int(
                            current_job["priority"]
                            if current_job["priority"] is not None
                            else continuation_priority
                        )
                continuation_job_id = enqueue_job(
                    conn,
                    role=continuation_role,
                    job_type="review_mempalace_import",
                    priority=continuation_priority,
                    payload={
                        "import_id": import_id,
                        "limit": limit,
                        "reason": "bounded_mempalace_import_continuation",
                    },
                    dedupe_key=f"import:{import_id}",
                    replace_pending=True,
                )
            core_result = {
                "ok": True,
                "complete": complete,
                "resumable": not complete,
                "reviewed_import": import_id,
                "eligible_before": eligible_before,
                "eligible_before_is_lower_bound": has_more,
                "reviewed_cards": len(changed_cards),
                "remaining_eligible": remaining,
                "remaining_eligible_is_lower_bound": has_more,
                "limit": limit,
                "continuation_job_id": continuation_job_id,
            }
            _record_worker_phase(
                conn,
                lease,
                job_type="review_mempalace_import",
                phase="core",
                result={
                    "core_result": core_result,
                    "changed_cards": changed_cards,
                },
            )
            conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()
    sidecars: dict[str, Any] = {"ok": True, "synced": 0, "failed": 0}
    if changed_cards:
        sidecars = _sync_worker_card_sidecars(root, changed_cards)
    result = {
        **core_result,
        "ok": bool(core_result["ok"]) and bool(sidecars.get("ok", True)),
        "sidecars": sidecars,
    }
    retry_pending = _mark_post_commit_sidecar_retry(result, sidecars)
    if not retry_pending:
        _commit_worker_effect_result(
            root,
            lease,
            job_type="review_mempalace_import",
            result=result,
        )
    return result


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
            continuation_priority = 100
            lease = _CURRENT_JOB_LEASE.get()
            if lease is not None:
                current_job = conn.execute(
                    "SELECT priority FROM queue_jobs WHERE id = ?",
                    (lease.job_id,),
                ).fetchone()
                if (
                    current_job is not None
                    and current_job["priority"] is not None
                ):
                    continuation_priority = int(current_job["priority"])
            continuation_job_id = enqueue_job(
                conn,
                role="scribe",
                job_type="scroll_event_ingested",
                priority=continuation_priority,
                payload={
                    "session_id": session_id,
                    "seq": backlog["max_seq"],
                    "reason": "scroll_segment_backlog_continuation",
                },
                dedupe_key=f"session:{session_id}",
                replace_pending=True,
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
    recover_pending_card_sidecars: bool = True,
) -> dict[str, Any]:
    """Roll eligible Scroll windows, renewing an owning worker lease as needed."""
    init_db(
        root,
        recover_pending_card_sidecars=recover_pending_card_sidecars,
    )
    lease = _CURRENT_JOB_LEASE.get()
    if lease is not None:
        receipt_conn = connect(root)
        try:
            receipt_conn.execute("BEGIN IMMEDIATE")
            prior = _begin_worker_effect(receipt_conn, lease)
            receipt_conn.commit()
        except Exception:
            receipt_conn.rollback()
            raise
        finally:
            receipt_conn.close()
        if prior is not None and prior.pop(
            _WORKER_POST_PHASE_COMPLETE_KEY,
            False,
        ):
            if not _result_is_replayable_sidecar_failure(prior):
                return prior
    config = load_config(root)
    threshold = int(config.get("capture", {}).get("roll_segments_every_events", 200))
    if session_id:
        session_id = canonical_partition_identifier(root, "session_id", session_id, lookup=True)
    rolled: list[dict[str, Any]] = []
    batches_processed = 0
    concurrent_progress = 0
    continuations: list[dict[str, Any]] = []
    runtime_roll_ok = True
    sidecar_failures: list[dict[str, Any]] = []
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
                    _record_scribe_step_intent(
                        root,
                        lease,
                        session_id=current_session,
                        start_seq=run_start,
                        end_seq=run_end,
                    )
                    transaction_effect = None
                    if lease is not None:
                        current_lease = lease

                        def transaction_effect(
                            transaction_conn,
                            step_result: dict[str, Any],
                            *,
                            current_session_id: str = current_session,
                            current_start_seq: int = run_start,
                            current_end_seq: int = run_end,
                            current_batch_number: int = batches_processed,
                        ) -> None:
                            _record_scribe_step_committed(
                                transaction_conn,
                                current_lease,
                                session_id=current_session_id,
                                start_seq=current_start_seq,
                                end_seq=current_end_seq,
                                batch_number=current_batch_number,
                                result=step_result,
                            )

                    result = roll_scroll_segment(
                        root,
                        session_id=current_session,
                        start_seq=run_start,
                        end_seq=run_end,
                        recover_pending_card_sidecars=recover_pending_card_sidecars,
                        transaction_guard=(lease.assert_owned if lease is not None else None),
                        transaction_effect=transaction_effect,
                    )
                    if heartbeat is not None and not heartbeat():
                        raise RuntimeError("worker lease lost during Scribe segmentation")
                    if result.get("ok", True):
                        _record_scribe_step_completed(
                            root,
                            lease,
                            session_id=current_session,
                            start_seq=run_start,
                            end_seq=run_end,
                            batch_number=batches_processed,
                            result=result,
                        )
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
                    if not result.get("ok", True):
                        runtime_roll_ok = False
                        sidecar_failures.append(
                            {
                                "segment_id": result.get("segment_id"),
                                "card_id": result.get("card_id"),
                                "sidecars": result.get("sidecars"),
                            }
                        )
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

    if lease is not None:
        committed_rolled, committed_batch_number = _committed_scribe_steps(
            root,
            lease,
        )
        rolled = committed_rolled
        batches_processed = max(batches_processed, committed_batch_number)

    sidecar_failures = [
        {
            "segment_id": item.get("segment_id"),
            "card_id": item.get("card_id"),
            "sidecars": item.get("sidecars"),
        }
        for item in rolled
        if not item.get("ok", True)
    ]
    result = {
        "ok": bool(
            runtime_roll_ok
            and all(item.get("ok", True) for item in rolled)
        ),
        "rolled_count": len(rolled),
        "rolled": rolled,
        "batches_processed": batches_processed,
        "batch_limit": None if force else MAX_SCRIBE_SEGMENT_BATCHES_PER_RUN,
        "drain_limited": bool(continuations),
        "continuations": continuations,
        "concurrent_progress": concurrent_progress,
        "sidecar_failures": sidecar_failures,
    }
    retry_pending = _mark_post_commit_sidecar_retry(
        result,
        *[
            item.get("sidecars")
            if isinstance(item.get("sidecars"), dict)
            else None
            for item in rolled
        ],
    )
    if lease is not None and not retry_pending:
        receipt_conn = connect(root)
        try:
            receipt_conn.execute("BEGIN IMMEDIATE")
            _record_worker_effect(
                receipt_conn,
                lease,
                job_type="scroll_event_ingested",
                result=result,
                post_phase_complete=True,
            )
            receipt_conn.commit()
        except Exception:
            receipt_conn.rollback()
            raise
        finally:
            receipt_conn.close()
    return result


def review_card_placement(
    root: Path,
    *,
    card_id: str,
    recover_pending_card_sidecars: bool = True,
) -> dict[str, Any]:
    conn = connect(root)
    lease = _CURRENT_JOB_LEASE.get()
    try:
        conn.execute("BEGIN IMMEDIATE")
        prior = _begin_worker_effect(conn, lease)
        legacy_core_result: dict[str, Any] | None = None
        failed_terminal_replay: dict[str, Any] | None = None
        if prior is not None:
            post_phase_complete = bool(
                prior.pop(_WORKER_POST_PHASE_COMPLETE_KEY, False)
            )
            if post_phase_complete:
                if not _result_is_replayable_sidecar_failure(prior):
                    conn.commit()
                    return prior
                failed_terminal_replay = dict(prior)
                legacy_core_result = _prior_non_post_phase_worker_effect(
                    conn,
                    lease,
                    job_type="review_card_placement",
                )
            else:
                legacy_core_result = dict(prior)
            if legacy_core_result is not None:
                legacy_core_result.pop("idempotent_replay", None)
        committed_phase = _prior_worker_phase(
            conn,
            lease,
            job_type="review_card_placement",
            phase="core",
        )
        if committed_phase is not None:
            phase_core_result = committed_phase.get("core_result")
            if (
                not isinstance(phase_core_result, dict)
                or str(phase_core_result.get("card_id") or "") != card_id
                or phase_core_result.get("ok") is not True
            ):
                raise RuntimeError(
                    "Committed review_card_placement core phase is invalid"
                )
            core_result = dict(phase_core_result)
            conn.commit()
        elif legacy_core_result is not None:
            if (
                str(legacy_core_result.get("card_id") or "") != card_id
                or legacy_core_result.get("ok") is not True
                or _result_has_failed_sidecar_phase(legacy_core_result)
            ):
                raise RuntimeError(
                    "Legacy review_card_placement receipt is invalid"
                )
            core_result = legacy_core_result
            _record_worker_phase(
                conn,
                lease,
                job_type="review_card_placement",
                phase="core",
                result={"core_result": core_result},
            )
            conn.commit()
        elif failed_terminal_replay is not None:
            conn.commit()
            return failed_terminal_replay
        else:
            row = conn.execute(
                "SELECT * FROM cards WHERE id = ?",
                (card_id,),
            ).fetchone()
            if row is None:
                conn.commit()
                return {
                    "ok": False,
                    "reason": "card_missing",
                    "card_id": card_id,
                }
            topics = json_loads(row["topics_json"], [])
            entities = json_loads(row["entities_json"], [])
            terms = [
                str(term)
                for term in [*topics, *entities]
                if str(term).strip()
            ]
            shelf = str(
                terms[0] if terms else row["card_type"]
            ).casefold()[:96]
            now = utc_now()
            card_node = upsert_graph_node(
                conn,
                kind="card",
                label=row["title"],
                card_id=card_id,
            )
            for term in terms[:16]:
                term_node = upsert_graph_node(conn, kind="term", label=term)
                add_graph_edge(
                    conn,
                    source_node_id=card_node,
                    relation="mentions",
                    target_node_id=term_node,
                    weight=0.5,
                    confidence=max(0.5, float(row["confidence"] or 0.7)),
                    source_refs=[
                        {"card_id": card_id, "worker": "librarian"}
                    ],
                )
            conn.execute(
                """
                UPDATE cards
                SET status = CASE
                        WHEN status = 'pending_librarian_review'
                        THEN 'active'
                        ELSE status
                    END,
                    placement_collection = coalesce(
                        placement_collection,
                        ?
                    ),
                    shelf = coalesce(shelf, ?),
                    storage_tier = coalesce(storage_tier, 'hot'),
                    updated_at = ?
                WHERE id = ?
                """,
                ("library", shelf, now, card_id),
            )
            audit_event(
                conn,
                action="librarian_review_card",
                target_type="card",
                target_id=card_id,
                payload={"shelf": shelf},
            )
            mark_card_sidecar_outbox(
                conn,
                [card_id],
                reason="librarian_review_card",
            )
            core_result = {
                "ok": True,
                "card_id": card_id,
                "shelf": shelf,
                "term_edges": len(terms[:16]),
            }
            _record_worker_phase(
                conn,
                lease,
                job_type="review_card_placement",
                phase="core",
                result={"core_result": core_result},
            )
            conn.commit()
        sidecars = _sync_worker_card_sidecars(root, [card_id])
        conflict = detect_conflicts(
            root,
            card_id=card_id,
            limit=10,
            recover_pending_card_sidecars=recover_pending_card_sidecars,
        )
        result = {
            **core_result,
            "ok": bool(
                core_result["ok"]
                and sidecars.get("ok")
                and conflict.get("ok")
            ),
            "sidecars": sidecars,
            "conflicts": conflict,
        }
        retry_pending = _mark_post_commit_sidecar_retry(
            result,
            sidecars,
            (
                conflict.get("sidecars")
                if isinstance(conflict.get("sidecars"), dict)
                else None
            ),
        )
        if not retry_pending:
            _commit_worker_effect_result(
                root,
                lease,
                job_type="review_card_placement",
                result=result,
            )
        return result
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()


def verify_book_integrity(root: Path, *, book_id: str, content_hash_value: str | None = None) -> dict[str, Any]:
    conn = connect(root)
    lease = _CURRENT_JOB_LEASE.get()
    try:
        prior = _begin_worker_effect(conn, lease)
        if prior is not None:
            return prior
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
        # Hashing can be arbitrarily slow for large archives. Do it without a
        # SQLite writer lock so the generic lease-renewal thread can keep this
        # job alive, then fence the small durable-effect transaction again.
        conn.execute("BEGIN IMMEDIATE")
        prior = _begin_worker_effect(conn, lease)
        if prior is not None:
            conn.commit()
            return prior
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
        result = {
            "ok": ok,
            "book_id": book_id,
            "reason": reason,
            "checked_original": bool(original_path and original_path.exists()),
            "checked_reader": bool((not original_path or not original_path.exists()) and reader_path and reader_path.exists()),
        }
        _record_worker_effect(
            conn,
            lease,
            job_type="verify_book_integrity",
            result=result,
        )
        conn.commit()
        return result
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()


def verify_segment_integrity(root: Path, *, segment_id: str, segment_hash: str | None = None) -> dict[str, Any]:
    conn = connect(root)
    lease = _CURRENT_JOB_LEASE.get()
    try:
        prior = _begin_worker_effect(conn, lease)
        if prior is not None:
            return prior
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
        # Keep event hashing out of the writer transaction for the same reason
        # as book hashing above; ownership is re-checked under the write lock.
        conn.execute("BEGIN IMMEDIATE")
        prior = _begin_worker_effect(conn, lease)
        if prior is not None:
            conn.commit()
            return prior
        audit_event(
            conn,
            action="archivist_verify_segment",
            target_type="scroll_segment",
            target_id=segment_id,
            payload={"ok": ok, "event_count": len(events), "reason": reason, "event_hash_mismatch_count": len(event_hash_mismatches)},
        )
        result = {
            "ok": ok,
            "segment_id": segment_id,
            "reason": reason,
            "event_hash_mismatch_count": len(event_hash_mismatches),
            "event_hash_mismatches": event_hash_mismatches[:10],
        }
        _record_worker_effect(
            conn,
            lease,
            job_type="verify_segment_integrity",
            result=result,
        )
        conn.commit()
        return result
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
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


def decay_graph_routes(
    root: Path,
    *,
    limit: int = 200,
    prune_threshold: int = 3,
    recover_pending_card_sidecars: bool = True,
) -> dict[str, Any]:
    init_db(
        root,
        recover_pending_card_sidecars=recover_pending_card_sidecars,
    )
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
_CONFLICT_RESOLUTION_AUDIT_SCHEMA = "continuum.conflict_resolution.v1"
_CONFLICT_SCAN_CURSOR_ACTION = "librarian_conflict_scan_cursor"
_CONFLICT_REVIEW_REQUIRED_ACTION = "librarian_conflict_review_required"
MAX_CONFLICT_CANDIDATE_CARDS = 512
MAX_CONFLICT_COMPARISONS = 130816  # 512 choose 2
MAX_CONFLICT_CARD_MUTATIONS = 512
MAX_CONFLICT_COMPONENT_MEMBERS = 512
MAX_CONFLICT_TRANSACTION_SECONDS = 5.0


def _ensure_conflict_indexes(root: Path) -> None:
    """Install additive indexes before opening the bounded writer transaction."""
    conn = connect(root)
    try:
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_cards_conflict_group
            ON cards(conflict_group)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_cards_conflict_title_boundary
            ON cards(lower(trim(title)), visibility_scope, project_id, session_id)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_cards_conflict_title_boundary_normalized
            ON cards(
                lower(trim(title)),
                coalesce(visibility_scope, 'session'),
                coalesce(project_id, ''),
                coalesce(session_id, '')
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_cards_conflict_boundary
            ON cards(
                coalesce(visibility_scope, 'session'),
                coalesce(project_id, ''),
                coalesce(session_id, '')
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_cards_conflict_boundary_direct
            ON cards(visibility_scope, project_id, session_id)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_cards_supersedes_card_id
            ON cards(supersedes_card_id)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_audit_events_action_target
            ON audit_events(action, target_type, target_id, created_at)
            """
        )
        conn.commit()
    finally:
        conn.close()


class _ConflictWorkBudget:
    def __init__(
        self,
        *,
        candidate_cards: int,
        comparisons: int,
        component_members: int,
        card_mutations: int,
        transaction_seconds: float,
    ) -> None:
        self.candidate_card_limit = max(1, min(int(candidate_cards), MAX_CONFLICT_CANDIDATE_CARDS))
        self.comparison_limit = max(1, min(int(comparisons), MAX_CONFLICT_COMPARISONS))
        self.component_member_limit = max(
            1,
            min(int(component_members), MAX_CONFLICT_COMPONENT_MEMBERS),
        )
        self.card_mutation_limit = max(1, min(int(card_mutations), MAX_CONFLICT_CARD_MUTATIONS))
        self.transaction_seconds = max(
            0.01,
            min(float(transaction_seconds), MAX_CONFLICT_TRANSACTION_SECONDS),
        )
        self.started = time.monotonic()
        self.deadline = self.started + self.transaction_seconds
        self.finished: float | None = None
        self.candidate_cards = 0
        self.comparisons = 0
        self.component_members = 0
        self.card_mutations = 0
        self.candidate_exhausted = False
        self.comparison_exhausted = False
        self.component_member_exhausted = False
        self.card_mutation_exhausted = False
        self.time_exhausted = False

    def start_transaction(self) -> None:
        self.started = time.monotonic()
        self.deadline = self.started + self.transaction_seconds
        self.finished = None

    def finish_transaction(self) -> None:
        self.finished = time.monotonic()
        if self.finished > self.deadline:
            self.time_exhausted = True

    def has_time(self) -> bool:
        if time.monotonic() <= self.deadline:
            return True
        self.time_exhausted = True
        return False

    def consume_comparison(self) -> bool:
        if self.comparisons >= self.comparison_limit:
            self.comparison_exhausted = True
            return False
        if not self.has_time():
            return False
        self.comparisons += 1
        return True

    def consume_component_member(self) -> bool:
        if self.component_members >= self.component_member_limit:
            self.component_member_exhausted = True
            return False
        if not self.has_time():
            return False
        self.component_members += 1
        return True

    def can_mutate(self, count: int) -> bool:
        if count < 0:
            return False
        if self.card_mutations + count > self.card_mutation_limit:
            self.card_mutation_exhausted = True
            return False
        return self.has_time()

    def record_mutations(self, count: int) -> None:
        self.card_mutations += max(0, int(count))

    def result(self) -> dict[str, Any]:
        elapsed = max(
            0.0,
            (self.finished if self.finished is not None else time.monotonic())
            - self.started,
        )
        return {
            "limits": {
                "candidate_cards": self.candidate_card_limit,
                "comparisons": self.comparison_limit,
                "component_members": self.component_member_limit,
                "card_mutations": self.card_mutation_limit,
                "transaction_seconds": self.transaction_seconds,
            },
            "used": {
                "candidate_cards": self.candidate_cards,
                "comparisons": self.comparisons,
                "component_members": self.component_members,
                "card_mutations": self.card_mutations,
                # A deadline abort may be observed just after the configured
                # instant.  Work-budget consumption is capped at the declared
                # allowance; the observed duration remains available below.
                "transaction_seconds": round(min(elapsed, self.transaction_seconds), 6),
            },
            "observed_transaction_seconds": round(elapsed, 6),
            "time_exhausted": self.time_exhausted,
            "exhausted": {
                "candidate_cards": self.candidate_exhausted,
                "comparisons": self.comparison_exhausted,
                "component_members": self.component_member_exhausted,
                "card_mutations": self.card_mutation_exhausted,
                "transaction_seconds": self.time_exhausted,
            },
        }


class _ConflictDeadlineExceeded(RuntimeError):
    """Internal signal used to roll back an over-deadline conflict pass."""


def _require_conflict_time(budget: _ConflictWorkBudget) -> None:
    if not budget.has_time():
        raise _ConflictDeadlineExceeded("conflict work deadline exceeded")


def _install_conflict_deadline_progress(conn, budget: _ConflictWorkBudget) -> None:
    """Interrupt one long SQLite statement when the conflict deadline expires."""

    def cancel_after_deadline() -> int:
        return 0 if budget.has_time() else 1

    conn.set_progress_handler(cancel_after_deadline, 100)


def _conflict_work_budget(
    component_limit: int,
    *,
    candidate_card_limit: int | None,
    comparison_limit: int | None,
    component_member_limit: int | None,
    mutation_limit: int | None,
    transaction_seconds: float | None,
) -> _ConflictWorkBudget:
    components = max(1, int(component_limit))
    requested_candidates = candidate_card_limit or max(32, min(MAX_CONFLICT_CANDIDATE_CARDS, components * 8))
    requested_comparisons = comparison_limit or min(
        MAX_CONFLICT_COMPARISONS,
        requested_candidates * (requested_candidates - 1) // 2,
    )
    # Always make the selected set small enough that a complete worst-case pair
    # pass fits the comparison budget. This prevents partial adjacency from being
    # mistaken for a complete conflict component.
    max_candidates_for_comparisons = max(
        2,
        int((1 + math.isqrt(1 + (8 * max(1, int(requested_comparisons))))) // 2),
    )
    effective_candidates = min(int(requested_candidates), max_candidates_for_comparisons)
    return _ConflictWorkBudget(
        candidate_cards=effective_candidates,
        comparisons=requested_comparisons,
        component_members=component_member_limit or effective_candidates,
        card_mutations=mutation_limit or effective_candidates,
        transaction_seconds=(
            MAX_CONFLICT_TRANSACTION_SECONDS
            if transaction_seconds is None
            else transaction_seconds
        ),
    )


def _latest_conflict_scan_cursor(conn, *, card_id: str | None) -> int:
    target_id = str(card_id) if card_id else "global"
    row = conn.execute(
        """
        SELECT payload_json
        FROM audit_events
        WHERE action = ? AND target_type = 'conflict_scan' AND target_id = ?
        ORDER BY created_at DESC, rowid DESC
        LIMIT 1
        """,
        (_CONFLICT_SCAN_CURSOR_ACTION, target_id),
    ).fetchone()
    payload = json_loads(row["payload_json"], {}) if row is not None else {}
    try:
        return max(0, int(payload.get("next_rowid", 0))) if isinstance(payload, dict) else 0
    except (TypeError, ValueError):
        return 0


def _rows_by_ids(conn, card_ids: list[str]) -> list[Any]:
    if not card_ids:
        return []
    placeholders = ",".join("?" for _ in card_ids)
    return conn.execute(
        f"SELECT rowid AS card_rowid, * FROM cards WHERE id IN ({placeholders}) ORDER BY rowid",
        card_ids,
    ).fetchall()


def _current_ids_for_rows(
    conn,
    rows: list[Any],
    *,
    budget: _ConflictWorkBudget,
) -> set[str]:
    card_ids = [str(row["id"]) for row in rows]
    if not card_ids:
        return set()
    # One indexed existence probe per selected Card is enough.  Returning every
    # successor row allowed one selected predecessor with an arbitrarily large
    # fan-out to escape the candidate budget.
    referenced: set[str] = set()
    for card_id in card_ids:
        _require_conflict_time(budget)
        if conn.execute(
            """
            SELECT 1
            FROM cards
            WHERE supersedes_card_id = ?
            LIMIT 1
            """,
            (card_id,),
        ).fetchone() is not None:
            referenced.add(card_id)
    return {
        str(row["id"])
        for row in rows
        if str(row["status"] or "").casefold() not in NON_CURRENT_CARD_STATUSES
        and not str(row["superseded_by_card_id"] or "").strip()
        and str(row["id"]) not in referenced
    }


def _bounded_card_count(
    conn,
    *,
    where_clause: str,
    params: tuple[Any, ...],
    selected_count: int,
    budget: _ConflictWorkBudget,
) -> int:
    """Count only far enough to prove selected rows are or are not closed."""

    _require_conflict_time(budget)
    probe_limit = max(1, int(selected_count) + 1)
    row = conn.execute(
        f"""
        SELECT count(*) AS n
        FROM (
            SELECT 1
            FROM cards
            WHERE {where_clause}
            LIMIT ?
        ) AS bounded_conflict_closure
        """,
        (*params, probe_limit),
    ).fetchone()
    return int(row["n"] or 0)


def _complete_conflict_groups(
    conn,
    rows: list[Any],
    *,
    budget: _ConflictWorkBudget,
) -> set[str]:
    selected_counts: dict[str, int] = {}
    for row in rows:
        group = str(row["conflict_group"] or "").strip()
        if group:
            selected_counts[group] = selected_counts.get(group, 0) + 1
    if not selected_counts:
        return set()
    return {
        group
        for group, count in selected_counts.items()
        if _bounded_card_count(
            conn,
            where_clause="conflict_group = ?",
            params=(group,),
            selected_count=count,
            budget=budget,
        )
        == count
    }


def _conflict_boundary_clause(
    boundary: tuple[str, str, str],
) -> tuple[str, tuple[Any, ...]]:
    if boundary[0] == "project":
        return "visibility_scope = 'project' AND project_id = ?", (boundary[1],)
    if boundary[0] == "global":
        return "visibility_scope = 'global'", ()
    return (
        "coalesce(visibility_scope, 'session') = ? "
        "AND coalesce(project_id, '') = ? AND coalesce(session_id, '') = ?",
        boundary,
    )


def _conflict_index_boundary_clause(
    boundary: tuple[str, str, str],
) -> tuple[str, tuple[Any, ...], str]:
    """Return an expression-index-compatible boundary and stable row order."""

    scope, project_id, session_id = boundary
    base = (
        "coalesce(visibility_scope, 'session') = ? "
        "AND coalesce(project_id, '') = ?"
    )
    if scope in {"project", "global"}:
        return (
            base,
            (scope, project_id),
            "coalesce(session_id, ''), rowid",
        )
    return (
        f"{base} AND coalesce(session_id, '') = ?",
        (scope, project_id, session_id),
        "rowid",
    )


def _complete_conflict_boundaries(
    conn,
    rows: list[Any],
    *,
    budget: _ConflictWorkBudget,
) -> set[tuple[str, str, str]]:
    selected_counts: dict[tuple[str, str, str], int] = {}
    for row in rows:
        boundary = _conflict_boundary(row)
        selected_counts[boundary] = selected_counts.get(boundary, 0) + 1
    complete: set[tuple[str, str, str]] = set()
    for boundary, selected_count in selected_counts.items():
        clause, params = _conflict_boundary_clause(boundary)
        actual_count = _bounded_card_count(
            conn,
            where_clause=clause,
            params=params,
            selected_count=selected_count,
            budget=budget,
        )
        if actual_count == selected_count:
            complete.add(boundary)
    return complete


def _complete_conflict_titles(
    conn,
    rows: list[Any],
    *,
    budget: _ConflictWorkBudget,
) -> set[tuple[tuple[str, str, str], str]]:
    selected_counts: dict[tuple[tuple[str, str, str], str], int] = {}
    for row in rows:
        title = _conflict_title_key(row["title"])
        if not title:
            continue
        key = (_conflict_boundary(row), title)
        selected_counts[key] = selected_counts.get(key, 0) + 1
    complete: set[tuple[tuple[str, str, str], str]] = set()
    for (boundary, title), selected_count in selected_counts.items():
        clause, params, _order_by = _conflict_index_boundary_clause(boundary)
        actual_count = _bounded_card_count(
            conn,
            where_clause=f"lower(trim(title)) = ? AND {clause}",
            params=(title, *params),
            selected_count=selected_count,
            budget=budget,
        )
        if actual_count == selected_count:
            complete.add((boundary, title))
    return complete


def _bounded_conflict_rows(
    conn,
    *,
    card_id: str | None,
    cursor: int,
    budget: _ConflictWorkBudget,
) -> tuple[list[Any], dict[str, Any]]:
    """Load one fair anchor plus its whole bounded durable/text closure.

    Optional cursor noise must never occupy slots needed by the anchor's exact
    title or durable conflict group.  Otherwise a component whose size equals
    the candidate ceiling can be fragmented forever by unrelated rows.
    """

    candidate_limit = budget.candidate_card_limit
    requested_cursor = 0 if card_id else max(0, int(cursor))

    def transitive_closure(seed_rows: list[Any]) -> list[Any]:
        closure: dict[str, Any] = {
            str(row["id"]): row for row in seed_rows
        }
        pending = sorted(
            closure.values(), key=lambda row: int(row["card_rowid"])
        )
        expanded_groups: set[str] = set()
        expanded_titles: set[tuple[tuple[str, str, str], str]] = set()
        while pending and len(closure) <= candidate_limit:
            current = pending.pop(0)
            related_sets: list[list[Any]] = []
            group = str(current["conflict_group"] or "").strip()
            if group and group not in expanded_groups:
                expanded_groups.add(group)
                related_sets.append(
                    conn.execute(
                        """
                        SELECT rowid AS card_rowid, *
                        FROM cards
                        WHERE conflict_group = ?
                        ORDER BY rowid
                        LIMIT ?
                        """,
                        (group, candidate_limit + 1),
                    ).fetchall()
                )
            title = _conflict_title_key(current["title"])
            title_key = (_conflict_boundary(current), title)
            if title and title_key not in expanded_titles:
                expanded_titles.add(title_key)
                boundary_clause, boundary_params, boundary_order = (
                    _conflict_index_boundary_clause(title_key[0])
                )
                related_sets.append(
                    conn.execute(
                        f"""
                        SELECT rowid AS card_rowid, *
                        FROM cards
                        WHERE lower(trim(title)) = ? AND {boundary_clause}
                        ORDER BY {boundary_order}
                        LIMIT ?
                        """,
                        (title, *boundary_params, candidate_limit + 1),
                    ).fetchall()
                )
            for related_rows in related_sets:
                for row in related_rows:
                    row_id = str(row["id"])
                    if row_id in closure:
                        continue
                    closure[row_id] = row
                    pending.append(row)
                    if len(closure) > candidate_limit:
                        break
                if len(closure) > candidate_limit:
                    break
        return sorted(
            closure.values(), key=lambda item: int(item["card_rowid"])
        )

    anchor_wrapped = False
    if card_id:
        anchor = conn.execute(
            "SELECT rowid AS card_rowid, * FROM cards WHERE id = ?",
            (str(card_id),),
        ).fetchone()
    else:
        anchor = conn.execute(
            """
            SELECT rowid AS card_rowid, *
            FROM cards
            WHERE rowid > ?
            ORDER BY rowid
            LIMIT 1
            """,
            (requested_cursor,),
        ).fetchone()
        if anchor is None and requested_cursor > 0:
            anchor = conn.execute(
                """
                SELECT rowid AS card_rowid, *
                FROM cards
                WHERE rowid <= ?
                ORDER BY rowid
                LIMIT 1
                """,
                (requested_cursor,),
            ).fetchone()
            anchor_wrapped = anchor is not None
    if anchor is None:
        return [], {
            "cursor": requested_cursor,
            "next_cursor": 0,
            "has_more": False,
            "wrapped": False,
            "base_candidate_count": 0,
            "required_candidate_cards_lower_bound": 0,
            "manual_review_required": False,
            "manual_review_reason": None,
            "optional_boundary_overflow": False,
            "anchor_card_id": None,
            "anchor_identity_hash": None,
        }

    closure_rows = transitive_closure([anchor])
    required_candidate_cards_lower_bound = (
        len(closure_rows) if len(closure_rows) > candidate_limit else 0
    )
    selected: dict[str, Any] = {
        str(row["id"]): row for row in closure_rows[:candidate_limit]
    }
    remaining = max(0, candidate_limit - len(selected))
    optional_rows: list[Any] = []
    wrapped = anchor_wrapped
    has_more = required_candidate_cards_lower_bound > candidate_limit
    optional_boundary_overflow = False

    if not has_more:
        if card_id:
            scope_clause, scope_params, optional_order = (
                _conflict_index_boundary_clause(_conflict_boundary(anchor))
            )
            # Targeted optional pages are single-pass only; legacy cursor state
            # cannot accumulate fuzzy evidence and would defeat the index order.
            optional_cursor = 0
        else:
            scope_clause, scope_params, optional_order = "1 = 1", (), "rowid"
            optional_cursor = int(anchor["card_rowid"])
        excluded_ids = sorted(selected)
        placeholders = ",".join("?" for _ in excluded_ids)
        exclusion_clause = (
            f" AND id NOT IN ({placeholders})" if excluded_ids else ""
        )

        after_rows = conn.execute(
            f"""
            SELECT rowid AS card_rowid, *
            FROM cards
            WHERE {scope_clause} AND rowid > ?{exclusion_clause}
            ORDER BY {optional_order}
            LIMIT ?
            """,
            (*scope_params, optional_cursor, *excluded_ids, remaining + 1),
        ).fetchall()
        optional_rows.extend(after_rows[:remaining])
        has_more = len(after_rows) > remaining
        wrap_capacity = max(0, remaining - len(optional_rows))
        if not has_more and optional_cursor > 0:
            wrap_rows = conn.execute(
                f"""
                SELECT rowid AS card_rowid, *
                FROM cards
                WHERE {scope_clause} AND rowid <= ?{exclusion_clause}
                ORDER BY {optional_order}
                LIMIT ?
                """,
                (*scope_params, optional_cursor, *excluded_ids, wrap_capacity + 1),
            ).fetchall()
            wrapped = wrapped or bool(wrap_rows)
            optional_rows.extend(wrap_rows[:wrap_capacity])
            has_more = len(wrap_rows) > wrap_capacity
        for row in optional_rows:
            selected[str(row["id"])] = row

        if card_id and not has_more and optional_rows:
            expanded_rows = transitive_closure(list(selected.values()))
            if len(expanded_rows) > candidate_limit:
                required_candidate_cards_lower_bound = max(
                    required_candidate_cards_lower_bound,
                    len(expanded_rows),
                )
                selected = {
                    str(row["id"]): row
                    for row in expanded_rows[:candidate_limit]
                }
                has_more = True
            else:
                selected = {str(row["id"]): row for row in expanded_rows}

    if (
        card_id
        and required_candidate_cards_lower_bound <= candidate_limit
        and has_more
    ):
        # Targeted optional pages are not accumulated across calls, so cycling
        # them cannot prove a fuzzy cross-title component. Keep optional rows
        # only when the entire boundary fits this pass. The writer phase below
        # defers the whole targeted result when these rows do not fit.
        selected = {
            str(row["id"]): row for row in closure_rows[:candidate_limit]
        }
        optional_rows = []
        optional_boundary_overflow = True
        has_more = False
        wrapped = False

    if card_id:
        if required_candidate_cards_lower_bound > candidate_limit:
            next_cursor = requested_cursor
        else:
            # Targeted evidence is either complete in this pass or explicitly
            # escalated below; non-accumulating optional pages have no cursor.
            next_cursor = 0
    else:
        # Advance one fair anchor at a time. Optional rows are evidence for this
        # pass, not permission to skip their future closure turn.
        next_cursor = int(anchor["card_rowid"]) if has_more else 0

    rows = sorted(selected.values(), key=lambda row: int(row["card_rowid"]))
    budget.candidate_cards = len(rows)
    budget.candidate_exhausted = has_more
    manual_review_required = (
        required_candidate_cards_lower_bound > MAX_CONFLICT_CANDIDATE_CARDS
    )
    anchor_group = str(anchor["conflict_group"] or "").strip()
    anchor_identity = (
        {
            "schema": "continuum.conflict_anchor.v1",
            "durable_group": anchor_group,
        }
        if anchor_group
        else {
            "schema": "continuum.conflict_anchor.v1",
            "boundary": list(_conflict_boundary(anchor)),
            "title_key": _conflict_title_key(anchor["title"]),
        }
    )
    anchor_identity_hash = content_hash(
        json_dumps(anchor_identity)
    )
    return rows, {
        "cursor": requested_cursor,
        "next_cursor": next_cursor,
        "has_more": has_more,
        "wrapped": wrapped,
        "base_candidate_count": 1,
        "required_candidate_cards_lower_bound": required_candidate_cards_lower_bound,
        "manual_review_required": manual_review_required,
        "manual_review_reason": (
            "component_exceeds_automatic_candidate_limit"
            if manual_review_required
            else None
        ),
        "optional_boundary_overflow": optional_boundary_overflow,
        "anchor_card_id": str(anchor["id"]),
        "anchor_identity_hash": anchor_identity_hash,
    }


def _assert_bounded_supersession_dag(rows: list[Any]) -> None:
    card_ids = {str(row["id"]) for row in rows}
    edges: dict[str, set[str]] = {card_id: set() for card_id in card_ids}
    for row in rows:
        card_id = str(row["id"])
        superseded_by = str(row["superseded_by_card_id"] or "").strip()
        supersedes = str(row["supersedes_card_id"] or "").strip()
        if superseded_by in card_ids:
            edges[card_id].add(superseded_by)
        if supersedes in card_ids:
            edges[supersedes].add(card_id)
    incoming = {card_id: 0 for card_id in edges}
    for targets in edges.values():
        for target in targets:
            incoming[target] += 1
    ready = [card_id for card_id, count in incoming.items() if count == 0]
    visited = 0
    while ready:
        card_id = ready.pop()
        visited += 1
        for target in edges[card_id]:
            incoming[target] -= 1
            if incoming[target] == 0:
                ready.append(target)
    if visited != len(edges):
        cyclic = sorted(card_id for card_id, count in incoming.items() if count > 0)
        raise ValueError(f"supersession graph must be acyclic; cycle involves: {', '.join(cyclic)}")


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


_ASCII_TITLE_LOWER = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "abcdefghijklmnopqrstuvwxyz",
)


def _conflict_title_key(value: Any) -> str:
    """Match SQLite's indexed ``lower(trim(title))`` normalization exactly."""

    return str(value or "").strip(" ").translate(_ASCII_TITLE_LOWER)


def _conflict_signature(card: Any) -> dict[str, Any]:
    title = _conflict_title_key(card["title"])
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


def _conflict_component_is_suppressed(
    conn: sqlite3.Connection,
    by_id: dict[str, Any],
    member_ids: list[str],
    fingerprint: str,
) -> bool:
    return (
        valid_conflict_resolution_receipt(
            conn,
            action="dismiss",
            component_fingerprint=fingerprint,
            by_id=by_id,
            member_ids=member_ids,
        )
        is not None
    )


def _record_conflict_resolution_receipt(
    conn: sqlite3.Connection,
    *,
    action: str,
    conflict_group: str,
    selected_card_id: str,
    member_ids: list[str],
    by_id: dict[str, Any],
    component_fingerprint: str,
) -> str:
    ordered_ids = sorted(member_ids)
    boundary = _conflict_boundary(by_id[ordered_ids[0]])
    resolution_id = unique_id("conflict_resolution")
    resolved_peer_ids = [
        member_id for member_id in ordered_ids if member_id != selected_card_id
    ]
    audit_payload = {
        "schema": _CONFLICT_RESOLUTION_AUDIT_SCHEMA,
        "resolution_id": resolution_id,
        "resolution": action,
        "conflict_group": conflict_group,
        "component_fingerprint": component_fingerprint,
        "selected_card_id": selected_card_id,
        "member_card_ids": ordered_ids,
        "member_count": len(ordered_ids),
        "resolved_peer_ids": resolved_peer_ids,
        "boundary": {
            "visibility_scope": boundary[0],
            "project_id": boundary[1],
            "session_id": boundary[2],
        },
        "whole_group": True,
    }
    audit_event_id = audit_event(
        conn,
        action="librarian_resolve_conflict",
        target_type="card",
        target_id=selected_card_id,
        actor="system",
        payload=audit_payload,
    )
    audit_row = conn.execute(
        "SELECT created_at FROM audit_events WHERE id = ?",
        (audit_event_id,),
    ).fetchone()
    if audit_row is None:
        raise RuntimeError("conflict resolution audit event was not recorded")
    audit_created_at = str(audit_row["created_at"] or "")
    conn.execute(
        """
        INSERT INTO conflict_resolution_receipts(
            id, action, component_fingerprint, conflict_group,
            visibility_scope, project_id, session_id, selected_card_id,
            member_count, actor, audit_event_id, created_at
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'system', ?, ?)
        """,
        (
            resolution_id,
            action,
            component_fingerprint,
            conflict_group,
            boundary[0],
            boundary[1],
            boundary[2],
            selected_card_id,
            len(ordered_ids),
            audit_event_id,
            audit_created_at,
        ),
    )
    for ordinal, member_id in enumerate(ordered_ids):
        conn.execute(
            """
            INSERT INTO conflict_resolution_members(
                receipt_id, card_id, member_ordinal, member_binding_hash
            )
            VALUES(?, ?, ?, ?)
            """,
            (
                resolution_id,
                member_id,
                ordinal,
                _conflict_member_binding_hash(by_id[member_id]),
            ),
        )
    return resolution_id


def _conflict_adjacency(
    cards: list[Any],
    *,
    budget: _ConflictWorkBudget,
    complete_groups: set[str],
    boundary_complete: bool,
) -> tuple[dict[str, set[str]], bool]:
    by_id = {str(card["id"]): card for card in cards}
    signatures = {card_id: _conflict_signature(card) for card_id, card in by_id.items()}
    existing_group_members: dict[str, set[str]] = {}
    for card_id in signatures:
        existing_group = str(by_id[card_id]["conflict_group"] or "").strip()
        if existing_group and existing_group in complete_groups:
            existing_group_members.setdefault(existing_group, set()).add(card_id)

    adjacency: dict[str, set[str]] = {card_id: set() for card_id in by_id}
    # Existing group membership is durable review state. Treat it as an edge so
    # a later heuristic scan cannot fragment a valid connected group merely
    # because only some of its text pairs are rediscovered.
    for members in existing_group_members.values():
        if len(members) < 2:
            continue
        anchor_id = min(members)
        for member_id in sorted(members - {anchor_id}):
            adjacency[anchor_id].add(member_id)
            adjacency[member_id].add(anchor_id)

    ordered_ids = sorted(by_id, key=lambda card_id: int(by_id[card_id]["card_rowid"]))
    for left_index, left_id in enumerate(ordered_ids):
        for right_id in ordered_ids[left_index + 1 :]:
            if not budget.consume_comparison():
                return adjacency, False
            left = signatures[left_id]
            right = signatures[right_id]
            # The indexed candidate loader supplies exact-title peers globally;
            # other comparisons stay bounded to this fair cursor window.
            potential_pair = (
                left["title"] == right["title"]
                or (
                    boundary_complete
                    and (
                        left["anchor"] in right["term_set"]
                        or right["anchor"] in left["term_set"]
                    )
                )
            )
            if not potential_pair:
                continue
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
    return adjacency, True


def _clear_orphan_conflict_groups(
    conn,
    *,
    rows: list[Any],
    current_ids: set[str],
    now: str,
    budget: _ConflictWorkBudget,
    complete_groups: set[str],
) -> tuple[set[str], set[str], int]:
    grouped: dict[str, list[str]] = {}
    by_id = {str(row["id"]): row for row in rows}
    touched: set[str] = set()
    cleared_groups: set[str] = set()
    deferred_groups = 0
    for row in rows:
        if not budget.has_time():
            break
        card_id = str(row["id"])
        group = str(row["conflict_group"] or "").strip()
        if row["conflict_group"] is not None and not group:
            if not budget.can_mutate(1):
                deferred_groups += 1
                continue
            conn.execute(
                "UPDATE cards SET conflict_group = NULL, updated_at = ? WHERE id = ?",
                (now, card_id),
            )
            touched.add(card_id)
            budget.record_mutations(1)
            continue
        if group:
            grouped.setdefault(group, []).append(card_id)

    for group, member_ids in grouped.items():
        if not budget.has_time():
            deferred_groups += 1
            continue
        if group not in complete_groups:
            deferred_groups += 1
            continue
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
        unique_clear_ids = list(dict.fromkeys(clear_ids))
        if not budget.can_mutate(len(unique_clear_ids)):
            deferred_groups += 1
            cleared_groups.discard(group)
            continue
        for card_id in unique_clear_ids:
            conn.execute(
                "UPDATE cards SET conflict_group = NULL, updated_at = ? WHERE id = ? AND conflict_group = ?",
                (now, card_id, group),
            )
            touched.add(card_id)
        budget.record_mutations(len(unique_clear_ids))
    return touched, cleared_groups, deferred_groups


def detect_conflicts(
    root: Path,
    *,
    card_id: str | None = None,
    limit: int = 50,
    candidate_card_limit: int | None = None,
    comparison_limit: int | None = None,
    component_member_limit: int | None = None,
    mutation_limit: int | None = None,
    transaction_seconds: float | None = None,
    recover_pending_card_sidecars: bool = True,
) -> dict[str, Any]:
    """Detect conflict components under one explicit, global work budget."""

    if card_id and candidate_card_limit is not None and int(candidate_card_limit) < 2:
        raise ValueError("targeted conflict scans require candidate_card_limit >= 2")
    component_limit = max(1, int(limit))
    budget = _conflict_work_budget(
        component_limit,
        candidate_card_limit=candidate_card_limit,
        comparison_limit=comparison_limit,
        component_member_limit=component_member_limit,
        mutation_limit=mutation_limit,
        transaction_seconds=transaction_seconds,
    )
    init_db(
        root,
        recover_pending_card_sidecars=recover_pending_card_sidecars,
    )
    index_setup_started = time.monotonic()
    _ensure_conflict_indexes(root)
    index_setup_seconds = round(time.monotonic() - index_setup_started, 6)
    budget.start_transaction()
    candidate_conn = connect(root)
    try:
        cursor = (
            0
            if card_id
            else _latest_conflict_scan_cursor(candidate_conn, card_id=None)
        )
        candidate_rows, scan_state = _bounded_conflict_rows(
            candidate_conn,
            card_id=card_id,
            cursor=cursor,
            budget=budget,
        )
        selected_ids = [str(row["id"]) for row in candidate_rows]
        targeted_candidate_incomplete = bool(
            card_id
            and (
                scan_state.get("optional_boundary_overflow")
                or int(
                    scan_state.get("required_candidate_cards_lower_bound") or 0
                )
                > budget.candidate_card_limit
            )
        )
        if targeted_candidate_incomplete:
            # Omitted rows may be exact, durable, fuzzy, or transitive members
            # of the anchor component. Do not perform even cleanup mutations
            # from an incomplete targeted candidate set.
            selected_ids = []
    finally:
        candidate_conn.close()
    conn = connect(root)
    touched_cards: set[str] = set()
    conflicts: list[dict[str, Any]] = []
    orphan_groups: set[str] = set()
    trailing_orphan_groups: set[str] = set()
    suppressed_components: list[dict[str, Any]] = []
    selected_components: list[dict[str, Any]] = []
    eligible_components: list[dict[str, Any]] = []
    deferred_components = int(targeted_candidate_incomplete)
    deferred_orphan_groups = 0
    scan_complete = True
    deadline_aborted = False
    rows: list[Any] = []
    try:
        _install_conflict_deadline_progress(conn, budget)
        _require_conflict_time(budget)
        conn.execute("BEGIN IMMEDIATE")
        rows = _rows_by_ids(conn, selected_ids)
        _assert_bounded_supersession_dag(rows)
        by_id = {str(row["id"]): row for row in rows}
        current_ids = _current_ids_for_rows(conn, rows, budget=budget)
        complete_groups = _complete_conflict_groups(conn, rows, budget=budget)
        complete_boundaries = _complete_conflict_boundaries(conn, rows, budget=budget)
        complete_titles = _complete_conflict_titles(conn, rows, budget=budget)
        now = utc_now()

        orphan_cards, orphan_groups, first_deferred_orphans = _clear_orphan_conflict_groups(
            conn,
            rows=rows,
            current_ids=current_ids,
            now=now,
            budget=budget,
            complete_groups=complete_groups,
        )
        deferred_orphan_groups += first_deferred_orphans
        touched_cards.update(orphan_cards)

        # Cleanup changes grouping state. Reload only this bounded candidate set.
        rows = _rows_by_ids(conn, selected_ids)
        by_id = {str(row["id"]): row for row in rows}
        current_ids = _current_ids_for_rows(conn, rows, budget=budget)
        complete_groups = _complete_conflict_groups(conn, rows, budget=budget)
        complete_boundaries = _complete_conflict_boundaries(conn, rows, budget=budget)
        complete_titles = _complete_conflict_titles(conn, rows, budget=budget)

        boundary_rows: dict[tuple[str, str, str], list[Any]] = {}
        for row in rows:
            if str(row["id"]) in current_ids:
                boundary_rows.setdefault(_conflict_boundary(row), []).append(row)

        all_components: list[dict[str, Any]] = []
        for boundary, cards in sorted(boundary_rows.items()):
            adjacency, adjacency_complete = _conflict_adjacency(
                cards,
                budget=budget,
                complete_groups=complete_groups,
                boundary_complete=boundary in complete_boundaries,
            )
            if not adjacency_complete:
                scan_complete = False
                break
            unseen = {member_id for member_id, peers in adjacency.items() if peers}
            ordered_ids = sorted(
                unseen,
                key=lambda member_id: int(by_id[member_id]["card_rowid"]),
            )
            for seed_id in ordered_ids:
                if seed_id not in unseen:
                    continue
                pending = [seed_id]
                component_ids: set[str] = set()
                component_complete = True
                while pending:
                    current = pending.pop()
                    if current in component_ids:
                        continue
                    if not budget.consume_component_member():
                        component_complete = False
                        scan_complete = False
                        break
                    component_ids.add(current)
                    pending.extend(adjacency.get(current, ()))
                if not component_complete:
                    break
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
                member_groups = [
                    str(by_id[member_id]["conflict_group"] or "").strip()
                    for member_id in member_ids
                ]
                has_incomplete_existing_group = any(
                    group and group not in complete_groups
                    for group in member_groups
                )
                component_titles = {
                    _conflict_title_key(by_id[member_id]["title"])
                    for member_id in member_ids
                    if str(by_id[member_id]["title"] or "").strip()
                }
                all_titles_closed = bool(component_titles) and all(
                    (boundary, title) in complete_titles
                    for title in component_titles
                )
                all_members_in_closed_groups = bool(member_groups) and all(
                    group and group in complete_groups
                    for group in member_groups
                )
                closure_proven = (
                    not has_incomplete_existing_group
                    and (
                        boundary in complete_boundaries
                        or all_titles_closed
                        or all_members_in_closed_groups
                    )
                )
                if not closure_proven:
                    deferred_components += 1
                    continue
                all_components.append(
                    {
                        "boundary": boundary,
                        "member_ids": member_ids,
                        "fingerprint": fingerprint,
                        "suppressed": _conflict_component_is_suppressed(
                            conn,
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
                        "first_rowid": min(
                            int(by_id[member_id]["card_rowid"])
                            for member_id in member_ids
                        ),
                    }
                )
            if not scan_complete:
                break

        suppressed_components = [record for record in all_components if record["suppressed"]]
        for component_record in suppressed_components:
            grouped_member_ids = [
                member_id
                for member_id in component_record["member_ids"]
                if str(by_id[member_id]["conflict_group"] or "").strip()
            ]
            if not budget.can_mutate(len(grouped_member_ids)):
                deferred_components += 1
                continue
            for member_id in grouped_member_ids:
                conn.execute(
                    "UPDATE cards SET conflict_group = NULL, updated_at = ? WHERE id = ?",
                    (now, member_id),
                )
            budget.record_mutations(len(grouped_member_ids))
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
            selected_components = sorted(
                eligible_components,
                key=lambda record: (
                    0 if record["needs_assignment"] else 1,
                    int(record["first_rowid"]),
                    tuple(record["member_ids"]),
                ),
            )[:component_limit]

        detected_components: list[dict[str, Any]] = []
        claimed_groups: set[str] = set()
        for component_record in selected_components:
            if not budget.has_time():
                deferred_components += 1
                break
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
            if not budget.can_mutate(len(changed_ids)):
                deferred_components += 1
                continue
            for member_id in changed_ids:
                conn.execute(
                    "UPDATE cards SET conflict_group = ?, updated_at = ? WHERE id = ?",
                    (group, now, member_id),
                )
            budget.record_mutations(len(changed_ids))
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

        refreshed_rows = _rows_by_ids(conn, selected_ids)
        refreshed_current_ids = _current_ids_for_rows(conn, refreshed_rows, budget=budget)
        refreshed_complete_groups = _complete_conflict_groups(
            conn,
            refreshed_rows,
            budget=budget,
        )
        trailing_orphans, trailing_orphan_groups, trailing_deferred_orphans = (
            _clear_orphan_conflict_groups(
                conn,
                rows=refreshed_rows,
                current_ids=refreshed_current_ids,
                now=now,
                budget=budget,
                complete_groups=refreshed_complete_groups,
            )
        )
        deferred_orphan_groups += trailing_deferred_orphans
        touched_cards.update(trailing_orphans)

        final_rows = _rows_by_ids(conn, selected_ids)
        final_by_id = {str(row["id"]): row for row in final_rows}
        final_current_ids = _current_ids_for_rows(conn, final_rows, budget=budget)
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
        _require_conflict_time(budget)
        if touched_cards:
            mark_card_sidecar_outbox(conn, sorted(touched_cards), reason="conflict_group_updated")

        _require_conflict_time(budget)
        if (
            not targeted_candidate_incomplete
            and (scan_state["has_more"] or cursor > 0)
        ):
            audit_event(
                conn,
                action=_CONFLICT_SCAN_CURSOR_ACTION,
                target_type="conflict_scan",
                target_id=str(card_id) if card_id else "global",
                payload={
                    "schema": "continuum.conflict_scan_cursor.v1",
                    "next_rowid": int(scan_state["next_cursor"]),
                    "candidate_count": len(rows),
                    "wrapped": bool(scan_state["wrapped"]),
                },
            )
        _require_conflict_time(budget)
        conn.commit()
        budget.finish_transaction()
    except (_ConflictDeadlineExceeded, sqlite3.OperationalError) as exc:
        is_deadline_interrupt = (
            isinstance(exc, _ConflictDeadlineExceeded)
            or (
                budget.time_exhausted
                and "interrupted" in str(exc).casefold()
            )
        )
        if conn.in_transaction:
            conn.rollback()
        if not is_deadline_interrupt:
            raise
        deadline_aborted = True
        scan_complete = False
        deferred_components += 1
        touched_cards.clear()
        conflicts.clear()
        orphan_groups.clear()
        trailing_orphan_groups.clear()
        suppressed_components = []
        selected_components = []
        eligible_components = []
        budget.card_mutations = 0
        scan_state = {
            **scan_state,
            "next_cursor": int(cursor),
            "has_more": True,
        }
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.set_progress_handler(None, 0)
        if budget.finished is None:
            budget.finish_transaction()
        conn.close()

    sidecars: dict[str, Any] = {
        "ok": True,
        "synced": 0,
        "failed": 0,
    }
    if touched_cards:
        sidecars = _sync_worker_card_sidecars(
            root,
            sorted(touched_cards),
        )
    selected_fingerprints = {
        str(record["fingerprint"])
        for record in selected_components
    }
    deferred_components += sum(
        1
        for record in eligible_components
        if record["needs_assignment"]
        and str(record["fingerprint"]) not in selected_fingerprints
    )
    optional_fuzzy_evidence_deferred = bool(
        card_id and scan_state.get("optional_boundary_overflow")
    )
    optional_fuzzy_requires_larger = optional_fuzzy_evidence_deferred
    reported_candidate_lower_bound = int(
        scan_state.get("required_candidate_cards_lower_bound") or 0
    )
    if optional_fuzzy_requires_larger:
        reported_candidate_lower_bound = max(
            reported_candidate_lower_bound,
            budget.candidate_card_limit + 1,
        )
    targeted_nonadvancing_structural_deferral = bool(
        card_id
        and int(scan_state.get("next_cursor") or 0) == 0
        and (deferred_components or deferred_orphan_groups or not scan_complete)
        and not scan_state.get("has_more")
        and not optional_fuzzy_requires_larger
        and not budget.comparison_exhausted
        and not budget.component_member_exhausted
        and not budget.card_mutation_exhausted
        and not budget.time_exhausted
    )
    if targeted_nonadvancing_structural_deferral:
        reported_candidate_lower_bound = max(
            reported_candidate_lower_bound,
            budget.candidate_card_limit + 1,
        )
    manual_review_required = bool(
        scan_state.get("manual_review_required")
        or reported_candidate_lower_bound > MAX_CONFLICT_CANDIDATE_CARDS
    )
    manual_review_reason = scan_state.get("manual_review_reason")
    if manual_review_required and manual_review_reason is None:
        manual_review_reason = "targeted_fuzzy_boundary_exceeds_automatic_candidate_limit"
    partial = bool(
        scan_state["has_more"]
        or not scan_complete
        or deferred_components
        or deferred_orphan_groups
        or budget.time_exhausted
        or optional_fuzzy_requires_larger
    )
    budget_result = budget.result()
    exhausted_dimensions = sorted(
        name
        for name, exhausted in budget_result["exhausted"].items()
        if exhausted
    )
    return {
        "ok": bool(sidecars.get("ok")),
        "conflict_count": len(conflicts),
        "conflicts": conflicts,
        "changed_card_count": len(touched_cards),
        "orphan_groups_cleared": len(orphan_groups | trailing_orphan_groups),
        "suppressed_component_count": len(suppressed_components),
        "supersession_dag": True,
        "supersession_dag_scope": "candidate_window",
        "partial": partial,
        "has_more": partial,
        "deadline_aborted": deadline_aborted,
        "deferred_components": deferred_components,
        "deferred_orphan_groups": deferred_orphan_groups,
        "scan": scan_state,
        "continuation": {
            "required": partial,
            "strategy": "targeted_rowid_cursor" if card_id else "circular_rowid_cursor",
            "next_cursor": int(scan_state["next_cursor"]),
            "card_id": str(card_id) if card_id else None,
            "budget_exhausted": exhausted_dimensions,
            "required_candidate_cards_lower_bound": reported_candidate_lower_bound,
            "optional_fuzzy_evidence_deferred": optional_fuzzy_evidence_deferred,
            "manual_review_required": manual_review_required,
            "manual_review_reason": manual_review_reason,
            "requires_larger_budget": bool(
                reported_candidate_lower_bound > budget.candidate_card_limit
                or budget.component_member_exhausted
                or budget.card_mutation_exhausted
                or budget.time_exhausted
            ),
        },
        "work_budget": budget_result,
        "index_setup": {
            "outside_scan_budget": True,
            "seconds": index_setup_seconds,
        },
        "sidecars": sidecars,
    }


def _conflict_result_requires_larger_budget(result: dict[str, Any]) -> bool:
    continuation = result.get("continuation")
    return bool(
        isinstance(continuation, dict)
        and continuation.get("required")
        and continuation.get("requires_larger_budget")
    )


def _conflict_review_signal_key(result: dict[str, Any]) -> str:
    raw_scan = result.get("scan")
    scan: dict[str, Any] = raw_scan if isinstance(raw_scan, dict) else {}
    identity_hash = str(scan.get("anchor_identity_hash") or "global")
    return "conflict_review_v1_" + content_hash(identity_hash)[:32]


def _record_conflict_review_signal(
    root: Path,
    *,
    result: dict[str, Any],
) -> dict[str, Any]:
    signal_key = _conflict_review_signal_key(result)
    raw_continuation = result.get("continuation")
    continuation: dict[str, Any] = (
        raw_continuation if isinstance(raw_continuation, dict) else {}
    )
    raw_scan = result.get("scan")
    scan: dict[str, Any] = raw_scan if isinstance(raw_scan, dict) else {}
    anchor_card_id = str(scan.get("anchor_card_id") or "")
    payload = {
        "schema": "continuum.conflict_review_required.v1",
        "signal_key": signal_key,
        "anchor_card_id": anchor_card_id[:128] or None,
        "anchor_card_id_hash": content_hash(anchor_card_id),
        "anchor_identity_hash": scan.get("anchor_identity_hash"),
        "required_candidate_cards_lower_bound": int(
            continuation.get("required_candidate_cards_lower_bound") or 0
        ),
        "manual_review_required": bool(
            continuation.get("manual_review_required")
        ),
        "manual_review_reason": continuation.get("manual_review_reason")
        or "automatic_conflict_escalation_incomplete",
    }
    conn = connect(root)
    try:
        conn.execute("BEGIN IMMEDIATE")
        existing = conn.execute(
            """
            SELECT payload_json, created_at
            FROM audit_events
            WHERE action = ? AND target_type = 'conflict_review'
              AND target_id = ?
            ORDER BY rowid DESC
            LIMIT 1
            """,
            (_CONFLICT_REVIEW_REQUIRED_ACTION, signal_key),
        ).fetchone()
        if existing is None:
            audit_event(
                conn,
                action=_CONFLICT_REVIEW_REQUIRED_ACTION,
                target_type="conflict_review",
                target_id=signal_key,
                payload=payload,
            )
            created = True
            created_at = utc_now()
        else:
            created = False
            created_at = existing["created_at"]
            existing_payload = json_loads(existing["payload_json"], {})
            if isinstance(existing_payload, dict):
                payload = existing_payload
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return {
        "created": created,
        "signal_key": signal_key,
        "created_at": created_at,
        **payload,
    }


def _run_conflict_maintenance(
    root: Path,
    *,
    recover_pending_card_sidecars: bool = True,
) -> dict[str, Any]:
    """Run one base pass, at most one hard-cap escalation, then quarantine."""

    base = detect_conflicts(
        root,
        limit=25,
        recover_pending_card_sidecars=recover_pending_card_sidecars,
    )
    result: dict[str, Any] = {"conflicts": base}
    if not _conflict_result_requires_larger_budget(base):
        return result
    raw_scan = base.get("scan")
    scan: dict[str, Any] = raw_scan if isinstance(raw_scan, dict) else {}
    anchor_card_id = str(scan.get("anchor_card_id") or "")
    final_result = base
    if anchor_card_id:
        escalated = detect_conflicts(
            root,
            card_id=anchor_card_id,
            limit=25,
            candidate_card_limit=MAX_CONFLICT_CANDIDATE_CARDS,
            comparison_limit=MAX_CONFLICT_COMPARISONS,
            component_member_limit=MAX_CONFLICT_COMPONENT_MEMBERS,
            mutation_limit=MAX_CONFLICT_CARD_MUTATIONS,
            transaction_seconds=MAX_CONFLICT_TRANSACTION_SECONDS,
            recover_pending_card_sidecars=recover_pending_card_sidecars,
        )
        result["conflict_escalation"] = escalated
        final_result = escalated
    if _conflict_result_requires_larger_budget(final_result):
        result["conflict_review_required"] = _record_conflict_review_signal(
            root,
            result=final_result,
        )
    return result


def resolve_conflict(
    root: Path,
    *,
    card_id: str,
    action: str = "supersede",
    superseded_card_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Resolve an entire contested Card group or authority boundary.

    ``supersede`` promotes ``card_id`` as the current Card and links every peer
    back to it. Compatible independent project-state heads may not form a
    heuristic conflict group, so callers can explicitly confirm every other
    current head in that authority boundary. ``dismiss`` remains limited to a
    detected false-positive group. Partial group or boundary resolution is
    rejected because it can fragment temporal authority.
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
        winner = by_id.get(card_id)
        if winner is None:
            raise ValueError(f"card not found: {card_id}")
        if card_id not in current_ids:
            raise ValueError(f"historical or superseded card cannot win a conflict: {card_id}")
        requested = list(
            dict.fromkeys(
                str(value).strip()
                for value in (superseded_card_ids or [])
                if str(value).strip()
            )
        )
        conflict_group = str(winner["conflict_group"] or "").strip()
        resolution_scope = "conflict_group"
        peers = (
            conn.execute(
                "SELECT rowid AS card_rowid, * FROM cards "
                "WHERE conflict_group = ? AND id != ? ORDER BY id",
                (conflict_group, card_id),
            ).fetchall()
            if conflict_group
            else []
        )
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

        winner_card_type = str(winner["card_type"] or "").casefold().strip()
        if action == "supersede" and winner_card_type == "project_state":
            authority_peer_ids = sorted(
                candidate_id
                for candidate_id in current_ids
                if candidate_id != card_id
                and str(by_id[candidate_id]["card_type"] or "").casefold().strip()
                == "project_state"
                and _conflict_boundary(by_id[candidate_id]) == winner_boundary
            )
            if not conflict_group or set(authority_peer_ids) != set(peer_ids):
                resolution_scope = "project_state_authority_boundary"
                if not authority_peer_ids:
                    raise ValueError(
                        "project-state authority boundary has no other current "
                        f"heads: {card_id}"
                    )
                if not requested:
                    raise ValueError(
                        "project-state authority resolution requires explicit "
                        "confirmation of every other current head: "
                        + ", ".join(authority_peer_ids)
                    )
                unknown = sorted(set(requested) - set(authority_peer_ids))
                if unknown:
                    raise ValueError(
                        "cards are not current project-state authority peers in "
                        "the selected boundary: "
                        + ", ".join(unknown)
                    )
                omitted = sorted(set(authority_peer_ids) - set(requested))
                if omitted:
                    raise ValueError(
                        "partial authority resolution is not allowed; the whole "
                        "project-state boundary also requires: "
                        + ", ".join(omitted)
                    )
                peer_ids = authority_peer_ids
                peers = [by_id[peer_id] for peer_id in peer_ids]
                all_authority_ids = sorted({card_id, *peer_ids})
                authority_id_set = set(all_authority_ids)
                authority_groups = sorted(
                    {
                        str(by_id[member_id]["conflict_group"] or "").strip()
                        for member_id in all_authority_ids
                        if str(by_id[member_id]["conflict_group"] or "").strip()
                    }
                )
                for authority_group in authority_groups:
                    group_member_ids = sorted(
                        member_id
                        for member_id, member in by_id.items()
                        if str(member["conflict_group"] or "").strip()
                        == authority_group
                    )
                    outside_ids = sorted(
                        set(group_member_ids) - authority_id_set
                    )
                    if len(group_member_ids) < 2 or outside_ids:
                        details = outside_ids or group_member_ids
                        raise ValueError(
                            "project-state authority boundary intersects an "
                            f"incomplete conflict group {authority_group}; "
                            "resolve or repair the group first: "
                            + ", ".join(details)
                        )
                conflict_group = content_hash(
                    "continuum_project_state_authority_resolution_v1|"
                    + "|".join(all_authority_ids)
                )[:16]
            elif requested:
                unknown = sorted(set(requested) - set(peer_ids))
                if unknown:
                    raise ValueError(
                        f"cards are not peers in conflict group {conflict_group}: "
                        + ", ".join(unknown)
                    )
                omitted = sorted(set(peer_ids) - set(requested))
                if omitted:
                    raise ValueError(
                        "partial conflict resolution is not allowed; whole group "
                        "also requires: "
                        + ", ".join(omitted)
                    )
        else:
            if not conflict_group:
                raise ValueError(f"card is not contested: {card_id}")
            if requested:
                unknown = sorted(set(requested) - set(peer_ids))
                if unknown:
                    raise ValueError(
                        f"cards are not peers in conflict group {conflict_group}: "
                        + ", ".join(unknown)
                    )
                omitted = sorted(set(peer_ids) - set(requested))
                if omitted:
                    raise ValueError(
                        "partial conflict resolution is not allowed; whole group "
                        "also requires: "
                        + ", ".join(omitted)
                    )

        resolved_peer_ids = peer_ids
        if not peer_ids:
            raise ValueError(f"conflict group has no peers: {conflict_group}")

        all_ids = sorted({card_id, *peer_ids})
        if winner_card_type == "project_state":
            for member_id in all_ids:
                integrity_error = _project_state_card_integrity_error(
                    conn,
                    member_id,
                )
                if integrity_error is not None:
                    raise ValueError(
                        "project-state authority member failed integrity "
                        f"validation: {member_id}: {integrity_error}"
                    )
        component_fingerprint = _conflict_component_fingerprint(by_id, all_ids)
        now = utc_now()
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
            for member_id in all_ids:
                conn.execute(
                    """
                    UPDATE cards
                    SET conflict_group = NULL, updated_at = ?
                    WHERE id = ?
                    """,
                    (now, member_id),
                )
            resolved_peer_ids = peer_ids

        touched_cards = sorted({card_id, *resolved_peer_ids})
        resolution_id = _record_conflict_resolution_receipt(
            conn,
            action=action,
            conflict_group=conflict_group,
            selected_card_id=card_id,
            member_ids=all_ids,
            by_id=by_id,
            component_fingerprint=component_fingerprint,
        )
        _assert_supersession_dag(conn)
        mark_card_sidecar_outbox(conn, touched_cards, reason=f"conflict_{action}_resolved")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    sidecars = _sync_worker_card_sidecars(root, touched_cards)
    return {
        "ok": bool(sidecars.get("ok")),
        "action": action,
        "card_id": card_id,
        "conflict_group": conflict_group,
        "resolved_peer_ids": resolved_peer_ids,
        "card_count": len(touched_cards),
        "whole_group": True,
        "resolution_scope": resolution_scope,
        "supersession_dag": True,
        "resolution_id": resolution_id,
        "component_fingerprint": component_fingerprint,
        "sidecars": sidecars,
        **(
            {"dismissal_fingerprint": component_fingerprint}
            if action == "dismiss"
            else {}
        ),
    }


def apply_storage_tiering(
    root: Path,
    *,
    dry_run: bool = False,
    limit: int = 100,
    recover_pending_card_sidecars: bool = True,
) -> dict[str, Any]:
    init_db(
        root,
        recover_pending_card_sidecars=recover_pending_card_sidecars,
    )
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


_PRUNE_MEMORY_PROTECTED_CARD_SQL = """
(
    lower(trim(coalesce(candidate.card_type, ''))) = 'project_state'
    OR trim(coalesce(candidate.conflict_group, '')) != ''
    OR trim(coalesce(candidate.supersedes_card_id, '')) != ''
    OR trim(coalesce(candidate.superseded_by_card_id, '')) != ''
    OR candidate.id IN (
        SELECT trim(authority_peer.supersedes_card_id)
        FROM cards AS authority_peer
        WHERE trim(coalesce(authority_peer.supersedes_card_id, '')) != ''
        UNION
        SELECT trim(authority_peer.superseded_by_card_id)
        FROM cards AS authority_peer
        WHERE trim(coalesce(authority_peer.superseded_by_card_id, '')) != ''
    )
)
"""


def validate_prune_memory_limit(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("prune-memory limit must be an integer")
    if value < 1 or value > MAX_PRUNE_MEMORY_LIMIT:
        raise ValueError(f"prune-memory limit must be between 1 and {MAX_PRUNE_MEMORY_LIMIT}")
    return value


def validate_prune_memory_scope(
    topic: str | None,
    *,
    allow_global: bool,
) -> tuple[str | None, str]:
    if not isinstance(allow_global, bool):
        raise ValueError("allow_global must be a boolean")
    if topic is None:
        if not allow_global:
            raise ValueError("prune_memory requires a topic unless allow_global=True")
        return None, PRUNE_MEMORY_GLOBAL_MATCHING_MODE
    if not isinstance(topic, str):
        raise ValueError("prune-memory topic must be a string")
    normalized_topic = topic.strip()
    if not normalized_topic:
        raise ValueError("prune-memory topic must not be empty or whitespace-only")
    if "\x00" in normalized_topic:
        raise ValueError("prune-memory topic must not contain NUL characters")
    return normalized_topic, PRUNE_MEMORY_LITERAL_MATCHING_MODE


def _prune_memory_match_sql(topic: str | None) -> tuple[str, tuple[str, ...]]:
    if topic is None:
        return "1 = 1", ()
    return (
        """
        (
            instr(lower(coalesce(candidate.title, '')), lower(?)) > 0
            OR instr(lower(coalesce(candidate.summary, '')), lower(?)) > 0
            OR EXISTS (
                SELECT 1
                FROM json_each(
                    CASE
                        WHEN json_valid(candidate.topics_json)
                        THEN candidate.topics_json
                        ELSE '[]'
                    END
                ) AS topic_item
                WHERE topic_item.type = 'text'
                  AND instr(lower(CAST(topic_item.value AS TEXT)), lower(?)) > 0
            )
        )
        """,
        (topic, topic, topic),
    )


def _validated_sidecar_compensation_cas_rows(
    result: dict[str, Any],
    *,
    card_ids: list[str],
) -> dict[str, dict[str, Any]] | None:
    """Validate transaction-bound sidecar fields returned by the sync layer."""

    if result.get("compensation_cas_complete") is not True:
        return None
    raw_rows = result.get("compensation_cas_rows")
    if not isinstance(raw_rows, list) or len(raw_rows) != len(card_ids):
        return None
    expected_ids = set(card_ids)
    rows_by_id: dict[str, dict[str, Any]] = {}
    for raw_row in raw_rows:
        if not isinstance(raw_row, dict):
            return None
        card_id = raw_row.get("card_id")
        location_uri = raw_row.get("location_uri")
        sidecar_generation = raw_row.get("sidecar_generation")
        if (
            not isinstance(card_id, str)
            or card_id not in expected_ids
            or card_id in rows_by_id
            or (location_uri is not None and not isinstance(location_uri, str))
            or (
                sidecar_generation is not None
                and (
                    not isinstance(sidecar_generation, str)
                    or not sidecar_generation
                )
            )
        ):
            return None
        rows_by_id[card_id] = {
            "location_uri": location_uri,
            "sidecar_generation": sidecar_generation,
        }
    if set(rows_by_id) != expected_ids:
        return None
    return rows_by_id


def _restore_prune_memory_rows(
    root: Path,
    original_rows: list[dict[str, Any]],
    *,
    expected_rows: list[dict[str, Any]],
    failure_reason: str,
    cleanup_candidates: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    card_ids = [str(row["id"]) for row in original_rows]
    original_by_id = {str(row["id"]): row for row in original_rows}
    conn = connect(root)
    try:
        conn.execute("BEGIN IMMEDIATE")
        cas_mismatches: list[str] = []
        for expected in expected_rows:
            current = conn.execute(
                """
                SELECT card.status, card.metadata_json, card.updated_at,
                       card.location_uri, outbox.generation AS sidecar_generation
                FROM cards AS card
                LEFT JOIN card_sidecar_outbox AS outbox ON outbox.card_id = card.id
                WHERE card.id = ?
                """,
                (expected["id"],),
            ).fetchone()
            if current is None or any(
                current[field] != expected[field]
                for field in (
                    "status",
                    "metadata_json",
                    "updated_at",
                    "location_uri",
                    "sidecar_generation",
                )
            ):
                cas_mismatches.append(str(expected["id"]))
        if cas_mismatches:
            conn.rollback()
            return {
                "ok": False,
                "restored": False,
                "cas_mismatch_card_ids": sorted(cas_mismatches),
                "reason": "Card state changed after prune commit",
            }

        registered_cleanup_intents = register_card_sidecar_compensation_intents(
            root,
            cleanup_candidates or [],
            conn=conn,
        )

        for card_id in card_ids:
            row = original_by_id[card_id]
            restored = conn.execute(
                """
                UPDATE cards
                SET status = ?, metadata_json = ?, updated_at = ?, location_uri = ?
                WHERE id = ?
                """,
                (
                    row["status"],
                    row["metadata_json"],
                    row["updated_at"],
                    row["location_uri"],
                    row["id"],
                ),
            )
            if restored.rowcount != 1:
                raise RuntimeError(f"unable to restore pruned Card row: {row['id']}")
        audit_event(
            conn,
            action="librarian_prune_memory_rolled_back",
            target_type="cards",
            target_id=None,
            payload={"card_ids": card_ids, "failure_reason": failure_reason},
        )
        mark_card_sidecar_outbox(conn, card_ids, reason="memory_prune_rolled_back")
        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()

    sidecar_sync = _sync_worker_card_sidecars(root, card_ids)
    cleanup_reconciliation = _reconcile_worker_sidecar_intents_with_budget(
        root,
    )
    semantic_integrity = semantic_integrity_report(root, create=False)
    return {
        "ok": (
            bool(sidecar_sync.get("ok"))
            and bool(cleanup_reconciliation.get("ok"))
            and not cleanup_reconciliation.get("pending")
            and bool(semantic_integrity.get("ok"))
        ),
        "restored": True,
        "cas_mismatch_card_ids": [],
        "sidecar_sync": sidecar_sync,
        "registered_cleanup_intents": registered_cleanup_intents,
        "cleanup_reconciliation": cleanup_reconciliation,
        "semantic_integrity": semantic_integrity,
    }


def prune_memory(
    root: Path,
    *,
    topic: str | None = None,
    action: str = "archive",
    dry_run: bool = False,
    limit: int = DEFAULT_PRUNE_MEMORY_LIMIT,
    allow_global: bool = False,
) -> dict[str, Any]:
    if action not in {"archive", "summarize_only", "forget"}:
        raise ValueError("action must be archive, summarize_only, or forget")
    normalized_topic, matching_mode = validate_prune_memory_scope(topic, allow_global=allow_global)
    validated_limit = validate_prune_memory_limit(limit)
    match_sql, match_params = _prune_memory_match_sql(normalized_topic)
    init_db(root, recover_pending_card_sidecars=False)
    conn = connect(root)
    transaction_started = False
    original_rows: list[dict[str, Any]] = []
    applied_rows: list[dict[str, Any]] = []
    try:
        if not dry_run:
            conn.execute("BEGIN IMMEDIATE")
            transaction_started = True
            preflight_integrity = semantic_integrity_report(root, create=False, conn=conn)
            if not preflight_integrity.get("ok"):
                raise ValueError(
                    "prune-memory preflight failed: semantic integrity is not clean: "
                    f"{preflight_integrity.get('failing')}"
                )

        rows = conn.execute(
            f"""
            SELECT candidate.id, candidate.status, candidate.metadata_json,
                   candidate.updated_at, candidate.location_uri
            FROM cards AS candidate
            WHERE candidate.status != 'pruned'
              AND {match_sql}
              AND NOT {_PRUNE_MEMORY_PROTECTED_CARD_SQL}
            ORDER BY candidate.salience ASC, candidate.updated_at ASC
            LIMIT ?
            """,
            (*match_params, validated_limit),
        ).fetchall()
        protected_scan = conn.execute(
            f"""
            SELECT candidate.id
            FROM cards AS candidate
            WHERE candidate.status != 'pruned'
              AND {match_sql}
              AND {_PRUNE_MEMORY_PROTECTED_CARD_SQL}
            ORDER BY candidate.id
            LIMIT ?
            """,
            (*match_params, MAX_PRUNE_MEMORY_LIMIT + 1),
        ).fetchall()
        protected_count_is_lower_bound = len(protected_scan) > MAX_PRUNE_MEMORY_LIMIT
        protected_count = len(protected_scan)
        protected_ids = [str(row["id"]) for row in protected_scan[:20]]
        eligible_ids = [str(row["id"]) for row in rows]
        targeted_protected_cards = normalized_topic is not None and protected_count > 0
        base_result = {
            "ok": True,
            "dry_run": dry_run,
            "action": action,
            "topic": normalized_topic,
            "normalized_topic": normalized_topic,
            "matching_mode": matching_mode,
            "limit": validated_limit,
            "global_scope": normalized_topic is None,
            "protected_card_count": protected_count,
            "protected_card_count_is_lower_bound": protected_count_is_lower_bound,
            "protected_card_count_at_least": (
                MAX_PRUNE_MEMORY_LIMIT + 1 if protected_count_is_lower_bound else protected_count
            ),
            "protected_card_ids": protected_ids,
        }
        if targeted_protected_cards:
            if dry_run:
                return {
                    **base_result,
                    "blocked": True,
                    "block_reason": "topic matches authority-protected Cards",
                    "eligible_card_count": len(eligible_ids),
                    "eligible_card_ids": eligible_ids,
                    "card_count": 0,
                    "card_ids": [],
                }
            raise ValueError(
                "prune-memory topic matches authority-protected Cards; use the dedicated "
                "project-state or conflict operation instead"
            )

        if dry_run:
            return {
                **base_result,
                "blocked": False,
                "card_count": len(eligible_ids),
                "card_ids": eligible_ids,
            }

        if not rows:
            conn.rollback()
            transaction_started = False
            return {
                **base_result,
                "blocked": False,
                "card_count": 0,
                "card_ids": [],
                "semantic_integrity_ok": True,
            }

        original_rows = [dict(row) for row in rows]
        target_status = {"archive": "archived", "summarize_only": "summary_only", "forget": "pruned"}[action]
        now = utc_now()
        for row in rows:
            metadata = json_loads(row["metadata_json"], {})
            metadata.setdefault("prune_history", []).append(
                {"action": action, "topic": normalized_topic, "matching_mode": matching_mode, "at": now}
            )
            conn.execute(
                "UPDATE cards SET status = ?, metadata_json = ?, updated_at = ? WHERE id = ?",
                (target_status, json_dumps(metadata), now, row["id"]),
            )
        audit_event(
            conn,
            action="librarian_prune_memory",
            target_type="cards",
            target_id=None,
            payload={
                "action": action,
                "topic": normalized_topic,
                "matching_mode": matching_mode,
                "card_ids": eligible_ids,
                "protected_card_count": protected_count,
            },
        )
        mark_card_sidecar_outbox(conn, eligible_ids, reason="memory_pruned")
        applied_rows = [
            dict(row)
            for row in conn.execute(
                f"""
                SELECT card.id, card.status, card.metadata_json, card.updated_at,
                       card.location_uri, outbox.generation AS sidecar_generation
                FROM cards AS card
                LEFT JOIN card_sidecar_outbox AS outbox ON outbox.card_id = card.id
                WHERE card.id IN ({','.join('?' for _ in eligible_ids)})
                ORDER BY card.id
                """,
                eligible_ids,
            ).fetchall()
        ]
        catalog_postcondition = semantic_integrity_report(
            root,
            create=False,
            conn=conn,
            check_card_sidecars=False,
        )
        if not catalog_postcondition.get("ok"):
            raise RuntimeError(
                "prune-memory postcondition failed before commit: "
                f"{catalog_postcondition.get('failing')}"
            )
        conn.commit()
        transaction_started = False
    except Exception:
        if transaction_started and conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()

    try:
        sidecar_sync = _sync_worker_card_sidecars(root, eligible_ids)
    except Exception as exc:
        sidecar_sync = {
            "ok": False,
            "synced": 0,
            "deferred": len(eligible_ids),
            "failed": len(eligible_ids),
            "failures": [
                {
                    "card_id": None,
                    "error": f"{type(exc).__name__}: {str(exc)[:512]}",
                }
            ],
            "raised": True,
        }
    post_sync_sidecar_rows = _validated_sidecar_compensation_cas_rows(
        sidecar_sync,
        card_ids=eligible_ids,
    )
    try:
        postflight_integrity = semantic_integrity_report(root, create=False)
    except Exception as exc:
        postflight_integrity = {
            "ok": False,
            "failing": {"postflight_exception": 1},
            "error": f"{type(exc).__name__}: {str(exc)[:512]}",
            "raised": True,
        }
    if not sidecar_sync.get("ok") or not postflight_integrity.get("ok"):
        failure_reasons: list[str] = []
        if not sidecar_sync.get("ok"):
            failure_reasons.append("sidecar synchronization failed")
        if not postflight_integrity.get("ok"):
            failure_reasons.append(
                "semantic integrity is not clean: "
                f"{postflight_integrity.get('failing')}"
            )
        failure_reason = "; ".join(failure_reasons)
        if post_sync_sidecar_rows is None:
            rollback_result = {
                "ok": False,
                "restored": False,
                "cas_mismatch_card_ids": [],
                "reason": "sidecar compensation CAS evidence unavailable",
            }
        else:
            expected_rows: list[dict[str, Any]] = []
            for applied in applied_rows:
                expected = dict(applied)
                card_id = str(expected["id"])
                post_sync = post_sync_sidecar_rows[card_id]
                expected["location_uri"] = post_sync["location_uri"]
                expected["sidecar_generation"] = post_sync["sidecar_generation"]
                expected_rows.append(expected)
            rollback_result = _restore_prune_memory_rows(
                root,
                original_rows,
                expected_rows=expected_rows,
                failure_reason=failure_reason,
                cleanup_candidates=list(
                    sidecar_sync.get("generated_sidecar_candidates", [])
                ),
            )
        if rollback_result.get("ok"):
            rollback_message = "Card mutations were rolled back"
        elif rollback_result.get("restored"):
            rollback_message = (
                "Card mutations were restored, but rollback verification did not complete"
            )
        elif rollback_result.get("reason") == "sidecar compensation CAS evidence unavailable":
            rollback_message = (
                "Card mutations were not rolled back because transaction-bound "
                "sidecar compensation evidence was unavailable"
            )
        else:
            rollback_message = (
                "Card mutations were not rolled back because their committed state changed"
            )
        raise RuntimeError(
            f"prune-memory postcondition failed; {rollback_message}: "
            f"{failure_reason}; rollback_ok={rollback_result.get('ok')}"
        )
    return {
        **base_result,
        "blocked": False,
        "card_count": len(eligible_ids),
        "card_ids": eligible_ids,
        "semantic_integrity_ok": True,
    }


def sync_card_sidecar_job(root: Path, *, card_id: str) -> dict[str, Any]:
    lease = _CURRENT_JOB_LEASE.get()
    conn = connect(root)
    try:
        conn.execute("BEGIN IMMEDIATE")
        prior = _begin_worker_effect(conn, lease)
        card_row = conn.execute(
            "SELECT location_uri FROM cards WHERE id = ?",
            (card_id,),
        ).fetchone()
        conn.commit()
    except Exception:
        if conn.in_transaction:
            conn.rollback()
        raise
    finally:
        conn.close()

    if prior is not None:
        reconciliation = _reconcile_sidecar_worker_intents(root, card_id)
        prior["intent_reconciliation"] = reconciliation
        reconciliation_clean = bool(
            reconciliation.get("ok")
            and int(reconciliation.get("pending", 0)) == 0
            and reconciliation.get(
                "scope_complete",
                reconciliation.get("complete"),
            )
        )
        if not reconciliation_clean:
            prior["ok"] = False
            prior["reason"] = "intent_reconciliation_incomplete"
            prior["retry_pending"] = True
            phase_conn = connect(root)
            try:
                phase_conn.execute("BEGIN IMMEDIATE")
                mark_card_sidecar_outbox(
                    phase_conn,
                    [card_id],
                    reason="intent_reconciliation_incomplete",
                )
                _commit_sidecar_worker_phase(
                    phase_conn,
                    lease,
                    result=prior,
                    phase="reconciliation_deferred",
                    terminal=False,
                )
            except Exception:
                if phase_conn.in_transaction:
                    phase_conn.rollback()
                raise
            finally:
                phase_conn.close()
        return prior

    writes_enabled = bool(
        load_config(root)
        .get("atomic_memory", {})
        .get("write_card_sidecars", True)
    )
    card_exists = card_row is not None
    promised_location = bool(
        card_row is not None and card_row["location_uri"]
    )
    if not card_exists or not writes_enabled:
        unmaterialized = bool(card_exists and not promised_location)
        reason = "sidecars_disabled" if card_exists else "card_missing"
        if unmaterialized:
            reason = "sidecars_disabled_unmaterialized"
        result = {
            "ok": bool(unmaterialized),
            "reason": reason,
            "card_id": card_id,
        }
        terminal = not card_exists or unmaterialized
        if not terminal:
            result["retry_pending"] = True
        phase_conn = connect(root)
        try:
            phase_conn.execute("BEGIN IMMEDIATE")
            audit_event(
                phase_conn,
                action="card_sidecar_sync_skipped",
                target_type="card",
                target_id=card_id,
                payload={"reason": reason},
            )
            if card_exists and not unmaterialized:
                if phase_conn.execute(
                    "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                ).fetchone() is None:
                    mark_card_sidecar_outbox(
                        phase_conn,
                        [card_id],
                        reason="sidecars_disabled",
                    )
                else:
                    phase_conn.execute(
                        """
                        UPDATE card_sidecar_outbox
                        SET attempt_count = attempt_count + 1,
                            last_error = ?,
                            updated_at = ?
                        WHERE card_id = ?
                        """,
                        (
                            "Card sidecar materialization is disabled",
                            utc_now(),
                            card_id,
                        ),
                    )
            else:
                phase_conn.execute(
                    "DELETE FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                )
            _commit_sidecar_worker_phase(
                phase_conn,
                lease,
                result=result,
                phase=(
                    "sidecar_not_required"
                    if terminal
                    else "sidecars_disabled_retry_pending"
                ),
                terminal=terminal,
            )
        except Exception:
            if phase_conn.in_transaction:
                phase_conn.rollback()
            raise
        finally:
            phase_conn.close()
        return result

    sidecar_sync = _sync_worker_card_sidecars(
        root,
        [card_id],
        reconcile_intents=False,
    )
    state_conn = connect_existing(root)
    try:
        current_row = state_conn.execute(
            """
            SELECT card.location_uri,
                   EXISTS(
                       SELECT 1
                       FROM card_sidecar_outbox AS outbox
                       WHERE outbox.card_id = card.id
                   ) AS sidecar_pending
            FROM cards AS card
            WHERE card.id = ?
            """,
            (card_id,),
        ).fetchone()
    finally:
        state_conn.close()
    current_card_exists = current_row is not None
    location_uri = (
        str(current_row["location_uri"])
        if current_row is not None and current_row["location_uri"]
        else None
    )
    sidecar_pending = bool(
        current_row is not None and current_row["sidecar_pending"]
    )
    materialized = bool(
        sidecar_sync.get("ok")
        and not int(sidecar_sync.get("deferred", 0))
        and current_card_exists
        and location_uri
        and not sidecar_pending
    )
    if not materialized:
        if not current_card_exists:
            result = {
                "ok": False,
                "reason": "card_missing",
                "card_id": card_id,
                "sidecars": sidecar_sync,
            }
            terminal = True
        else:
            result = {
                "ok": False,
                "reason": "sidecar_sync_incomplete",
                "retry_pending": True,
                "card_id": card_id,
                "location_uri": location_uri,
                "sidecars": sidecar_sync,
            }
            terminal = False
        phase_conn = connect(root)
        try:
            phase_conn.execute("BEGIN IMMEDIATE")
            if not terminal:
                mark_card_sidecar_outbox(
                    phase_conn,
                    [card_id],
                    reason="sidecar_sync_incomplete",
                )
            audit_event(
                phase_conn,
                action=(
                    "card_sidecar_sync_deferred"
                    if not terminal
                    else "card_sidecar_sync_skipped"
                ),
                target_type="card",
                target_id=card_id,
                payload={"reason": result["reason"]},
            )
            _commit_sidecar_worker_phase(
                phase_conn,
                lease,
                result=result,
                phase=(
                    "sidecar_sync_deferred"
                    if not terminal
                    else "sidecar_not_required"
                ),
                terminal=terminal,
            )
        except Exception:
            if phase_conn.in_transaction:
                phase_conn.rollback()
            raise
        finally:
            phase_conn.close()
        return result

    result = {
        "ok": True,
        "card_id": card_id,
        "location_uri": location_uri,
    }
    phase_conn = connect(root)
    try:
        phase_conn.execute("BEGIN IMMEDIATE")
        _commit_sidecar_worker_phase(
            phase_conn,
            lease,
            result=result,
            phase="materialized_pending_reconciliation",
            terminal=False,
        )
    except Exception:
        if phase_conn.in_transaction:
            phase_conn.rollback()
        raise
    finally:
        phase_conn.close()

    reconciliation = _reconcile_sidecar_worker_intents(root, card_id)
    result["intent_reconciliation"] = reconciliation
    reconciliation_clean = bool(
        reconciliation.get("ok")
        and int(reconciliation.get("pending", 0)) == 0
        and reconciliation.get(
            "scope_complete",
            reconciliation.get("complete"),
        )
    )
    terminal_conn = connect(root)
    try:
        terminal_conn.execute("BEGIN IMMEDIATE")
        newer_sidecar_pending = (
            terminal_conn.execute(
                "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                (card_id,),
            ).fetchone()
            is not None
        )
        if not reconciliation_clean or newer_sidecar_pending:
            result["ok"] = False
            result["reason"] = "intent_reconciliation_incomplete"
            result["retry_pending"] = True
            mark_card_sidecar_outbox(
                terminal_conn,
                [card_id],
                reason="intent_reconciliation_incomplete",
            )
            audit_event(
                terminal_conn,
                action="card_sidecar_intent_reconciliation_incomplete",
                target_type="card",
                target_id=card_id,
                payload={
                    "pending": int(reconciliation.get("pending", 0)),
                    "failure_count": len(reconciliation.get("failures", [])),
                    "newer_sidecar_pending": newer_sidecar_pending,
                },
            )
            _commit_sidecar_worker_phase(
                terminal_conn,
                lease,
                result=result,
                phase="reconciliation_deferred",
                terminal=False,
            )
        else:
            _commit_sidecar_worker_phase(
                terminal_conn,
                lease,
                result=result,
                phase="complete",
                terminal=True,
            )
    except Exception:
        if terminal_conn.in_transaction:
            terminal_conn.rollback()
        raise
    finally:
        terminal_conn.close()
    return result


def drain_card_sidecar_outbox(
    root: Path,
    *,
    limit: int = 50,
    reconcile_intents: bool = True,
) -> dict[str, Any]:
    init_db(root, recover_pending_card_sidecars=False)
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
    result = sync_card_sidecars_after_commit(
        root,
        card_ids,
        reconcile_intents=reconcile_intents,
    )
    return {
        "ok": bool(result.get("ok")),
        "pending": len(card_ids),
        "synced": int(result.get("synced", 0)),
        "failed": int(result.get("failed", 0)),
        "failures": result.get("failures", []),
    }


def _reconcile_card_sidecar_intent_maintenance(
    root: Path,
    *,
    limit: int = WORKER_SIDECAR_INTENT_LIMIT,
) -> dict[str, Any]:
    """Resolve a bounded active-intent window without claiming outbox work."""

    init_db(root, recover_pending_card_sidecars=False)
    try:
        result = _reconcile_worker_sidecar_intents_with_budget(
            root,
            requested_limit=limit,
            exhausted_ok=True,
        )
    except Exception as exc:
        return {
            "ok": False,
            "processed": 0,
            "pending": 0,
            "limit": limit,
            "selected": 0,
            "inspected": 0,
            "enumerated": 0,
            "remaining": None,
            "remaining_is_lower_bound": True,
            "complete": False,
            "has_more": True,
            "remaining_lower_bound": 0,
            "batch_truncated": False,
            "overflow": False,
            "progress_blocked": False,
            "failure_count": 1,
            "failures": [
                {
                    "error": f"{type(exc).__name__}: {str(exc)[:512]}",
                }
            ],
            "status_counts": {},
        }
    raw_results = result.get("results")
    reconciliation_results = (
        raw_results
        if isinstance(raw_results, list)
        else []
    )
    status_counts: dict[str, int] = {}
    for reconciliation_result in reconciliation_results:
        if not isinstance(reconciliation_result, dict):
            continue
        status = str(reconciliation_result.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    raw_failures = result.get("failures")
    failures = raw_failures if isinstance(raw_failures, list) else []
    pending = max(0, int(result.get("pending", 0)))
    raw_remaining = result.get("remaining")
    remaining = (
        max(0, int(raw_remaining))
        if raw_remaining is not None
        else None
    )
    return {
        "ok": bool(result.get("ok")),
        "processed": max(0, int(result.get("processed", 0))),
        "pending": pending,
        "limit": max(1, int(result.get("limit", limit))),
        "selected": max(0, int(result.get("selected", 0))),
        "inspected": max(0, int(result.get("inspected", 0))),
        "enumerated": max(0, int(result.get("enumerated", 0))),
        "remaining": remaining,
        "remaining_is_lower_bound": bool(
            result.get("remaining_is_lower_bound")
        ),
        "complete": bool(result.get("complete")),
        "has_more": bool(result.get("has_more")),
        "remaining_lower_bound": max(
            0,
            int(result.get("remaining_lower_bound", 0)),
        ),
        "batch_truncated": bool(result.get("batch_truncated")),
        "overflow": bool(result.get("overflow")),
        "progress_blocked": bool(result.get("progress_blocked")),
        "budget_exhausted": bool(result.get("budget_exhausted")),
        "worker_intent_budget": result.get("worker_intent_budget"),
        "failure_count": len(failures),
        "failures": failures[:WORKER_MAINTENANCE_FAILURE_LIMIT],
        "status_counts": status_counts,
    }


def _json_values_match(left: Any, right: Any) -> bool:
    """Compare JSON values without Python's bool/int equality coercion."""

    return json_dumps(left) == json_dumps(right)


def _opaque_queue_dedupe_key(
    role: Any,
    job_type: Any,
    raw_dedupe_key: Any,
) -> str:
    return "queue_v1_" + content_hash(
        json_dumps(
            [
                str(role),
                str(job_type),
                str(raw_dedupe_key),
            ]
        )
    )


def _failed_sidecar_recovery_candidates(
    conn,
    *,
    limit: int,
    job_id: str | None = None,
) -> list[dict[str, Any]]:
    job_clause = ""
    if job_id is not None:
        job_clause = " AND q.id = ?"
    job_placeholders = ",".join(
        "?" for _ in _FAILED_SIDECAR_RECOVERY_JOB_ROLES
    )
    rows = conn.execute(
        f"""
        WITH latest_effect AS (
            SELECT q.rowid AS queue_rowid, q.*,
                   effect.rowid AS effect_rowid,
                   effect.id AS effect_event_id,
                   effect.payload_json AS effect_payload_json
            FROM queue_jobs AS q
            JOIN audit_events AS effect
              ON effect.rowid = (
                  SELECT candidate_effect.rowid
                  FROM audit_events AS candidate_effect
                  WHERE candidate_effect.action = ?
                    AND candidate_effect.target_type = 'queue_job'
                    AND candidate_effect.target_id = q.id
                  ORDER BY candidate_effect.rowid DESC
                  LIMIT 1
            )
            WHERE q.status = 'failed'
              AND q.job_type IN ({job_placeholders}){job_clause}
        )
        SELECT q.*
        FROM latest_effect AS q
        WHERE NOT EXISTS (
            SELECT 1
            FROM audit_events AS disposition
            WHERE disposition.action = ?
              AND disposition.target_type = 'queue_job'
              AND disposition.target_id = q.id
              AND json_valid(disposition.payload_json)
              AND json_extract(disposition.payload_json, '$.schema') = ?
              AND json_extract(
                  disposition.payload_json,
                  '$.effect_event_id'
               ) = q.effect_event_id
              AND json_extract(
                  disposition.payload_json,
                  '$.decision'
              ) IN ('requeued', 'rejected')
        )
        ORDER BY q.effect_rowid, q.queue_rowid
        LIMIT ?
        """,
        [
            _WORKER_EFFECT_ACTION,
            *_FAILED_SIDECAR_RECOVERY_JOB_ROLES,
            *([job_id] if job_id is not None else []),
            _FAILED_SIDECAR_RECOVERY_ACTION,
            _FAILED_SIDECAR_RECOVERY_SCHEMA,
            max(1, int(limit)),
        ],
    ).fetchall()
    return [
        {
            **dict(row),
            "recovery_effect_key": str(row["effect_event_id"]),
            "recovery_mode": "effect",
        }
        for row in rows
    ]


def _failed_effectless_recovery_candidates(
    conn,
    *,
    limit: int,
    job_id: str | None = None,
) -> list[dict[str, Any]]:
    job_clause = ""
    if job_id is not None:
        job_clause = " AND q.id = ?"
    job_placeholders = ",".join(
        "?" for _ in _FAILED_SIDECAR_RECOVERY_JOB_ROLES
    )
    rows = conn.execute(
        f"""
        SELECT q.rowid AS queue_rowid, q.*,
               NULL AS effect_rowid,
               NULL AS effect_event_id,
               NULL AS effect_payload_json
        FROM queue_jobs AS q
        WHERE q.status = 'failed'
          AND q.job_type IN ({job_placeholders}){job_clause}
          AND NOT EXISTS (
              SELECT 1
              FROM audit_events AS effect
              WHERE effect.action = ?
                AND effect.target_type = 'queue_job'
                AND effect.target_id = q.id
          )
          AND NOT EXISTS (
              SELECT 1
              FROM audit_events AS disposition
              WHERE disposition.action = ?
                AND disposition.target_type = 'queue_job'
                AND disposition.target_id = q.id
                AND json_valid(disposition.payload_json)
                AND json_extract(disposition.payload_json, '$.schema') = ?
                AND json_extract(
                    disposition.payload_json,
                    '$.effect_event_id'
                ) = ?
                AND json_extract(
                    disposition.payload_json,
                    '$.decision'
                ) IN ('requeued', 'rejected')
          )
        ORDER BY q.rowid
        LIMIT ?
        """,
        [
            *_FAILED_SIDECAR_RECOVERY_JOB_ROLES,
            *([job_id] if job_id is not None else []),
            _WORKER_EFFECT_ACTION,
            _FAILED_SIDECAR_RECOVERY_ACTION,
            _FAILED_SIDECAR_RECOVERY_SCHEMA,
            _FAILED_SIDECAR_EFFECTLESS_KEY,
            max(1, int(limit)),
        ],
    ).fetchall()
    return [
        {
            **dict(row),
            "effect_event_id": None,
            "effect_rowid": None,
            "effect_payload_json": None,
            "recovery_effect_key": _FAILED_SIDECAR_EFFECTLESS_KEY,
            "recovery_mode": "effectless",
        }
        for row in rows
    ]


def _all_failed_sidecar_recovery_candidates(
    conn,
    *,
    limit: int,
    job_id: str | None = None,
) -> list[dict[str, Any]]:
    bounded = max(1, int(limit))
    candidates = [
        *_failed_sidecar_recovery_candidates(
            conn,
            limit=bounded,
            job_id=job_id,
        ),
        *_failed_effectless_recovery_candidates(
            conn,
            limit=bounded,
            job_id=job_id,
        ),
    ]
    candidates.sort(
        key=lambda item: (
            int(item.get("queue_rowid") or 0),
            0 if item.get("recovery_mode") == "effect" else 1,
        )
    )
    return candidates[:bounded]


_FAILED_RECOVERY_SNAPSHOT_FIELDS = (
    "queue_rowid",
    "id",
    "job_type",
    "role",
    "status",
    "priority",
    "attempt_count",
    "error_json",
    "payload_json",
    "related_card_ids_json",
    "dedupe_key",
    "created_at",
    "updated_at",
    "started_at",
    "finished_at",
    "lease_owner",
    "lease_expires_at",
    "heartbeat_at",
    "effect_event_id",
    "effect_rowid",
    "effect_payload_json",
    "recovery_effect_key",
    "recovery_mode",
)


def _failed_recovery_snapshot(
    candidate: dict[str, Any],
) -> dict[str, Any]:
    return {
        key: candidate.get(key)
        for key in _FAILED_RECOVERY_SNAPSHOT_FIELDS
    }


def _failed_recovery_snapshot_sha256(
    candidate: dict[str, Any],
) -> str:
    return content_hash(json_dumps(_failed_recovery_snapshot(candidate)))


def _exact_worker_phase_receipt(
    conn,
    *,
    job_id: str,
    job_type: str,
    before_rowid: int | None = None,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    rowid_clause = ""
    params: list[Any] = [
        _WORKER_PHASE_ACTION,
        job_id,
    ]
    if before_rowid is not None:
        rowid_clause = " AND rowid < ?"
        params.append(int(before_rowid))
    row = conn.execute(
        f"""
        SELECT id, rowid AS event_rowid, payload_json
        FROM audit_events
        WHERE action = ? AND target_type = 'queue_job' AND target_id = ?
          {rowid_clause}
        ORDER BY rowid DESC
        LIMIT 1
        """,
        params,
    ).fetchone()
    if row is None:
        return None
    payload = json_loads(row["payload_json"], None)
    if (
        not isinstance(payload, dict)
        or set(payload)
        != {"schema", "job_type", "phase", "result"}
        or payload.get("schema") != _WORKER_PHASE_SCHEMA
        or payload.get("job_type") != job_type
        or payload.get("phase") != "core"
        or not isinstance(payload.get("result"), dict)
    ):
        return None
    return dict(row), payload


def _exact_legacy_core_effect(
    conn,
    *,
    job_id: str,
    job_type: str,
    before_rowid: int,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    row = conn.execute(
        """
        SELECT id, rowid AS event_rowid, payload_json
        FROM audit_events
        WHERE action = ? AND target_type = 'queue_job' AND target_id = ?
          AND rowid < ?
        ORDER BY rowid DESC
        LIMIT 1
        """,
        (_WORKER_EFFECT_ACTION, job_id, int(before_rowid)),
    ).fetchone()
    if row is None:
        return None
    payload = json_loads(row["payload_json"], None)
    if not isinstance(payload, dict):
        return None
    required_keys = {"schema", "job_type", "result"}
    if (
        not required_keys.issubset(payload)
        or set(payload) - required_keys - {"post_phase_complete"}
        or payload.get("schema") != _WORKER_EFFECT_SCHEMA
        or payload.get("job_type") != job_type
        or (
            "post_phase_complete" in payload
            and payload["post_phase_complete"] is not False
        )
        or not isinstance(payload.get("result"), dict)
    ):
        return None
    return dict(row), payload


def _worker_core_fields(
    result: dict[str, Any],
    *,
    post_phase_keys: set[str],
) -> dict[str, Any]:
    return {
        key: value
        for key, value in result.items()
        if key not in post_phase_keys
        and key not in {"reason", "error", "retry_pending", "idempotent_replay"}
    }


def _validate_failed_queue_state(
    candidate: dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    expected_role = _FAILED_SIDECAR_RECOVERY_JOB_ROLES.get(
        str(candidate.get("job_type") or "")
    )
    if expected_role is None or candidate.get("role") != expected_role:
        return None, "queue_role_mismatch"
    if (
        candidate.get("status") != "failed"
        or candidate.get("finished_at") is None
        or any(
            candidate.get(field) is not None
            for field in ("lease_owner", "lease_expires_at")
        )
    ):
        return None, "queue_not_terminally_failed"
    queue_payload = json_loads(candidate.get("payload_json"), None)
    related_card_ids = json_loads(
        candidate.get("related_card_ids_json"),
        None,
    )
    error_payload = json_loads(candidate.get("error_json"), None)
    if not isinstance(queue_payload, dict):
        return None, "queue_payload_invalid"
    if (
        not isinstance(related_card_ids, list)
        or any(
            not isinstance(card_id, str) or not card_id
            for card_id in related_card_ids
        )
        or len(set(related_card_ids)) != len(related_card_ids)
    ):
        return None, "queue_related_cards_invalid"
    if (
        not isinstance(error_payload, dict)
        or set(error_payload) != {"error", "result"}
        or not isinstance(error_payload.get("result"), dict)
    ):
        return None, "queue_failure_envelope_invalid"
    return {
        "queue_payload": queue_payload,
        "related_card_ids": related_card_ids,
        "error_payload": error_payload,
    }, "eligible"


def _validate_failed_queue_effect(
    candidate: dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    parsed, reason = _validate_failed_queue_state(candidate)
    if parsed is None:
        return None, reason
    effect_payload = json_loads(candidate.get("effect_payload_json"), None)
    if (
        not isinstance(effect_payload, dict)
        or set(effect_payload)
        != {"schema", "job_type", "post_phase_complete", "result"}
        or effect_payload.get("schema") != _WORKER_EFFECT_SCHEMA
        or effect_payload.get("job_type") != candidate.get("job_type")
        or effect_payload.get("post_phase_complete") is not True
        or not isinstance(effect_payload.get("result"), dict)
    ):
        return None, "latest_worker_effect_invalid"
    result = effect_payload["result"]
    if (
        not _result_is_replayable_sidecar_failure(result)
        or result.get("retry_pending") is True
    ):
        return None, "not_exclusive_sidecar_failure"
    error_payload = parsed["error_payload"]
    queue_result = dict(error_payload["result"])
    if "idempotent_replay" in queue_result:
        if queue_result["idempotent_replay"] is not True:
            return None, "queue_failure_result_mismatch"
        queue_result.pop("idempotent_replay")
    if not _json_values_match(queue_result, result):
        return None, "queue_failure_result_mismatch"
    expected_error = str(
        result.get("reason")
        or result.get("error")
        or "worker result reported ok=false"
    )
    if error_payload.get("error") != expected_error:
        return None, "queue_failure_error_mismatch"
    parsed.update(
        {
            "effect_payload": effect_payload,
            "result": result,
            "effectless": False,
        }
    )
    return parsed, "eligible"


def _validate_failed_effectless_queue(
    candidate: dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    parsed, reason = _validate_failed_queue_state(candidate)
    if parsed is None:
        return None, reason
    error_payload = parsed["error_payload"]
    if (
        not isinstance(error_payload.get("error"), str)
        or not str(error_payload["error"]).strip()
        or error_payload["result"]
    ):
        return None, "effectless_queue_failure_envelope_invalid"
    parsed.update({"result": None, "effectless": True})
    return parsed, "eligible"


def _validate_failed_placement_authority(
    conn,
    candidate: dict[str, Any],
    parsed: dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    payload = parsed["queue_payload"]
    result = parsed["result"]
    card_id = payload.get("card_id")
    related_card_ids = parsed["related_card_ids"]
    if (
        not isinstance(card_id, str)
        or not card_id
        or card_id not in related_card_ids
    ):
        return None, "placement_identity_mismatch"
    if result is not None:
        if result.get("card_id") != card_id:
            return None, "placement_identity_mismatch"
        direct_sidecars = result.get("sidecars")
        conflicts = result.get("conflicts")
        conflict_sidecars = (
            conflicts.get("sidecars")
            if isinstance(conflicts, dict)
            else None
        )
        direct_failed = bool(
            isinstance(direct_sidecars, dict)
            and direct_sidecars.get("ok") is False
        )
        conflict_failed = bool(
            isinstance(conflict_sidecars, dict)
            and conflict_sidecars.get("ok") is False
        )
        if not (direct_failed or conflict_failed):
            return None, "placement_sidecar_shape_invalid"
        if (
            isinstance(conflicts, dict)
            and conflicts.get("ok") is False
            and not conflict_failed
        ):
            return None, "placement_non_sidecar_conflict_failure"
    before_rowid = (
        int(candidate["effect_rowid"])
        if candidate.get("effect_rowid") is not None
        else None
    )
    authority = _exact_worker_phase_receipt(
        conn,
        job_id=str(candidate["id"]),
        job_type="review_card_placement",
        before_rowid=before_rowid,
    )
    if authority is None:
        if before_rowid is None:
            return None, "placement_core_receipt_missing"
        authority = _exact_legacy_core_effect(
            conn,
            job_id=str(candidate["id"]),
            job_type="review_card_placement",
            before_rowid=before_rowid,
        )
        if authority is None:
            return None, "placement_core_receipt_missing"
        receipt_row, receipt_payload = authority
        core_result = receipt_payload["result"]
    else:
        receipt_row, receipt_payload = authority
        phase_result = receipt_payload["result"]
        if set(phase_result) != {"core_result"}:
            return None, "placement_core_receipt_invalid"
        core_result = phase_result["core_result"]
    if (
        not isinstance(core_result, dict)
        or core_result.get("ok") is not True
        or core_result.get("card_id") != card_id
    ):
        return None, "placement_core_receipt_invalid"
    if result is not None and not _json_values_match(
        _worker_core_fields(
            result,
            post_phase_keys={"ok", "sidecars", "conflicts"},
        ),
        _worker_core_fields(core_result, post_phase_keys={"ok"}),
    ):
        return None, "placement_core_receipt_invalid"
    card = conn.execute(
        "SELECT status FROM cards WHERE id = ?",
        (card_id,),
    ).fetchone()
    if (
        card is None
        or str(card["status"] or "") in NON_CURRENT_CARD_STATUSES
    ):
        return None, "placement_live_card_missing"
    return {
        "identity": {"card_id": card_id},
        "authority_event_ids": [str(receipt_row["id"])],
    }, "eligible"


def _validate_failed_mempalace_authority(
    conn,
    candidate: dict[str, Any],
    parsed: dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    payload = parsed["queue_payload"]
    result = parsed["result"]
    import_id = payload.get("import_id")
    if (
        not isinstance(import_id, str)
        or not import_id
    ):
        return None, "mempalace_identity_or_sidecar_mismatch"
    if result is not None:
        sidecars = result.get("sidecars")
        if (
            result.get("reviewed_import") != import_id
            or not isinstance(sidecars, dict)
            or sidecars.get("ok") is not False
        ):
            return None, "mempalace_identity_or_sidecar_mismatch"
    before_rowid = (
        int(candidate["effect_rowid"])
        if candidate.get("effect_rowid") is not None
        else None
    )
    authority = _exact_worker_phase_receipt(
        conn,
        job_id=str(candidate["id"]),
        job_type="review_mempalace_import",
        before_rowid=before_rowid,
    )
    changed_cards: list[str] | None = None
    if authority is None:
        if before_rowid is None:
            return None, "mempalace_core_receipt_missing"
        authority = _exact_legacy_core_effect(
            conn,
            job_id=str(candidate["id"]),
            job_type="review_mempalace_import",
            before_rowid=before_rowid,
        )
        if authority is None:
            return None, "mempalace_core_receipt_missing"
        receipt_row, receipt_payload = authority
        core_result = receipt_payload["result"]
    else:
        receipt_row, receipt_payload = authority
        phase_result = receipt_payload["result"]
        if (
            set(phase_result) != {"core_result", "changed_cards"}
            or not isinstance(phase_result.get("changed_cards"), list)
        ):
            return None, "mempalace_core_receipt_invalid"
        core_result = phase_result["core_result"]
        changed_cards = phase_result["changed_cards"]
    if (
        not isinstance(core_result, dict)
        or core_result.get("ok") is not True
        or core_result.get("reviewed_import") != import_id
    ):
        return None, "mempalace_core_receipt_invalid"
    if result is not None and not _json_values_match(
        _worker_core_fields(
            result,
            post_phase_keys={"ok", "sidecars"},
        ),
        _worker_core_fields(core_result, post_phase_keys={"ok"}),
    ):
        return None, "mempalace_core_receipt_invalid"
    if changed_cards is not None:
        if (
            not changed_cards
            or len(changed_cards) > MAX_BACKLOG_RECONCILE_LIMIT
            or any(
                not isinstance(card_id, str) or not card_id
                for card_id in changed_cards
            )
            or len(set(changed_cards)) != len(changed_cards)
        ):
            return None, "mempalace_changed_cards_invalid"
        non_current_statuses = sorted(NON_CURRENT_CARD_STATUSES)
        status_placeholders = ",".join(
            "?" for _ in non_current_statuses
        )
        matching = conn.execute(
            f"""
            SELECT count(*) AS n
            FROM json_each(?) AS changed
            JOIN cards AS card ON card.id = changed.value
            WHERE card.card_type LIKE 'mempalace_%'
              AND card.status NOT IN ({status_placeholders})
              AND json_valid(card.metadata_json)
              AND json_extract(card.metadata_json, '$.import_id') = ?
            """,
            (
                json_dumps(changed_cards),
                *non_current_statuses,
                import_id,
            ),
        ).fetchone()
        if matching is None or int(matching["n"] or 0) != len(changed_cards):
            return None, "mempalace_live_card_identity_mismatch"
        live_card_ids = list(changed_cards)
    else:
        non_current_statuses = sorted(NON_CURRENT_CARD_STATUSES)
        status_placeholders = ",".join(
            "?" for _ in non_current_statuses
        )
        live_card = conn.execute(
            f"""
            SELECT id
            FROM cards
            WHERE card_type LIKE 'mempalace_%'
              AND status NOT IN ({status_placeholders})
              AND json_valid(metadata_json)
              AND json_extract(metadata_json, '$.import_id') = ?
            ORDER BY rowid
            LIMIT 1
            """,
            (*non_current_statuses, import_id),
        ).fetchone()
        if live_card is None:
            return None, "mempalace_live_import_missing"
        live_card_ids = [str(live_card["id"])]
    return {
        "identity": {
            "import_id": import_id,
            "card_ids": live_card_ids,
        },
        "authority_event_ids": [str(receipt_row["id"])],
    }, "eligible"


def _exact_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


_SCRIBE_COMMITTED_CORE_KEYS = {
    "segment_id",
    "card_id",
    "event_count",
    "token_estimate",
    "librarian_job_id",
    "archivist_job_id",
}
_SCRIBE_RECEIPT_KEYS = {
    "schema",
    "step_key",
    "session_id",
    "start_seq",
    "end_seq",
    "batch_number",
    "result",
}
_SCRIBE_TERMINAL_RESULT_KEYS = {
    "ok",
    "rolled_count",
    "rolled",
    "batches_processed",
    "batch_limit",
    "drain_limited",
    "continuations",
    "concurrent_progress",
    "sidecar_failures",
}
_SCRIBE_VALIDATION_STATE_KEYS = {
    "validated_count",
    "completed_count",
    "last_committed_rowid",
    "first_start_seq",
    "last_end_seq",
    "last_batch_number",
    "batch_numbers",
    "authority_chain_sha256",
}


def _exact_scribe_committed_core(
    value: Any,
) -> dict[str, Any] | None:
    if (
        not isinstance(value, dict)
        or set(value) != _SCRIBE_COMMITTED_CORE_KEYS
        or any(
            not isinstance(value.get(key), str) or not value[key]
            for key in (
                "segment_id",
                "card_id",
                "librarian_job_id",
                "archivist_job_id",
            )
        )
        or value["librarian_job_id"] == value["archivist_job_id"]
        or not _exact_int(value.get("event_count"))
        or int(value["event_count"]) <= 0
        or not _exact_int(value.get("token_estimate"))
        or int(value["token_estimate"]) < 0
    ):
        return None
    return dict(value)


def _parse_exact_scribe_receipt(
    row: Any,
    *,
    action: str,
    session_id: str,
) -> tuple[dict[str, Any] | None, str]:
    receipt = json_loads(row["payload_json"], None)
    expected_schema = (
        "continuum.worker_scribe_segment_step_committed.v1"
        if action == _SCRIBE_STEP_COMMITTED_ACTION
        else "continuum.worker_scribe_segment_step_completed.v1"
    )
    if (
        not isinstance(receipt, dict)
        or set(receipt) != _SCRIBE_RECEIPT_KEYS
        or receipt.get("schema") != expected_schema
        or receipt.get("session_id") != session_id
        or not _exact_int(receipt.get("start_seq"))
        or int(receipt["start_seq"]) < 1
        or not _exact_int(receipt.get("end_seq"))
        or int(receipt["end_seq"]) < int(receipt["start_seq"])
        or not _exact_int(receipt.get("batch_number"))
        or not 1 <= int(receipt["batch_number"]) <= (
            MAX_SCRIBE_SEGMENT_BATCHES_PER_RUN
        )
        or receipt.get("step_key")
        != (
            f"{session_id}:{receipt['start_seq']}:"
            f"{receipt['end_seq']}"
        )
        or not isinstance(receipt.get("result"), dict)
    ):
        return None, "scribe_receipt_invalid"
    return receipt, "eligible"


def _scribe_post_sidecar_result_matches_core(
    value: Any,
    core: dict[str, Any],
) -> bool:
    if (
        not isinstance(value, dict)
        or set(value)
        != _SCRIBE_COMMITTED_CORE_KEYS | {"ok", "sidecars", "card_uri"}
        or not isinstance(value.get("ok"), bool)
        or not isinstance(value.get("sidecars"), dict)
        or not isinstance(value["sidecars"].get("ok"), bool)
        or value["sidecars"]["ok"] is not value["ok"]
        or value.get("card_uri") is not None
        and (
            not isinstance(value.get("card_uri"), str)
            or not value["card_uri"]
        )
    ):
        return False
    return _json_values_match(
        {key: value[key] for key in _SCRIBE_COMMITTED_CORE_KEYS},
        core,
    )


def _scribe_missing_completion_matches(
    value: Any,
    core: dict[str, Any],
) -> bool:
    if not _scribe_post_sidecar_result_matches_core(value, core):
        return False
    sidecars = value["sidecars"]
    required = {
        "ok",
        "synced",
        "failed",
        "pending_outbox",
        "completion_receipt_missing",
        "replayed_from_committed_step",
        "stale_failed_completion_revalidated",
    }
    if (
        not required.issubset(sidecars)
        or set(sidecars) - required - {"failures"}
        or sidecars.get("completion_receipt_missing") is not True
        or sidecars.get("replayed_from_committed_step") is not True
        or sidecars.get("stale_failed_completion_revalidated") is not False
        or not isinstance(sidecars.get("pending_outbox"), bool)
        or not _exact_int(sidecars.get("synced"))
        or not _exact_int(sidecars.get("failed"))
        or value["ok"] is not False
        or sidecars["ok"] is not False
        or sidecars["synced"] != 0
        or sidecars["failed"] != 1
        or sidecars["pending_outbox"] is not True
    ):
        return False
    failures = sidecars.get("failures")
    return bool(
        isinstance(failures, list)
        and len(failures) == 1
        and isinstance(failures[0], dict)
        and set(failures[0]) == {"card_id", "error"}
        and failures[0]["card_id"] == core["card_id"]
        and failures[0]["error"]
        in {
            (
                "Committed Scribe step has no durable "
                "post-sidecar success evidence"
            ),
            (
                "Committed Scribe step still has no durable "
                "post-sidecar success evidence"
            ),
        }
    )


def _validate_live_scribe_core(
    conn,
    *,
    session_id: str,
    start_seq: int,
    end_seq: int,
    core: dict[str, Any],
) -> str | None:
    live = conn.execute(
        """
        SELECT segment.session_id, segment.start_seq, segment.end_seq,
               segment.summary_card_id, segment.token_estimate,
               segment.segment_hash, card.status, card.visibility_scope,
               card.project_id
        FROM scroll_segments AS segment
        JOIN cards AS card ON card.id = segment.summary_card_id
        WHERE segment.id = ?
        """,
        (core["segment_id"],),
    ).fetchone()
    if (
        live is None
        or live["session_id"] != session_id
        or int(live["start_seq"]) != start_seq
        or int(live["end_seq"]) != end_seq
        or live["summary_card_id"] != core["card_id"]
        or int(live["token_estimate"]) != core["token_estimate"]
        or not isinstance(live["segment_hash"], str)
        or not live["segment_hash"]
        or str(live["status"] or "").casefold()
        in NON_CURRENT_CARD_STATUSES
    ):
        return "scribe_live_segment_identity_mismatch"
    event_state = conn.execute(
        """
        SELECT count(*) AS event_count, min(seq) AS first_seq,
               max(seq) AS last_seq,
               coalesce(sum(token_estimate), 0) AS token_estimate
        FROM scroll_events
        WHERE session_id = ? AND seq BETWEEN ? AND ?
        """,
        (session_id, start_seq, end_seq),
    ).fetchone()
    expected_event_count = end_seq - start_seq + 1
    if (
        event_state is None
        or int(event_state["event_count"]) != expected_event_count
        or int(event_state["event_count"]) != core["event_count"]
        or int(event_state["first_seq"]) != start_seq
        or int(event_state["last_seq"]) != end_seq
        or int(event_state["token_estimate"]) != core["token_estimate"]
    ):
        return "scribe_live_event_or_token_mismatch"
    boundary_state = conn.execute(
        """
        WITH boundaries AS (
            SELECT visibility_scope, coalesce(project_id, '') AS project_id
            FROM scroll_events
            WHERE session_id = ? AND seq BETWEEN ? AND ?
            GROUP BY visibility_scope, coalesce(project_id, '')
        )
        SELECT count(*) AS boundary_count,
               min(visibility_scope) AS visibility_scope,
               min(project_id) AS project_id
        FROM boundaries
        """,
        (session_id, start_seq, end_seq),
    ).fetchone()
    if (
        boundary_state is None
        or int(boundary_state["boundary_count"]) != 1
        or str(boundary_state["visibility_scope"] or "")
        != str(live["visibility_scope"] or "")
        or str(boundary_state["project_id"] or "")
        != str(live["project_id"] or "")
    ):
        return "scribe_live_security_boundary_mismatch"
    project_id = str(live["project_id"] or "")
    shared_payload = {
        "session_id": session_id,
        "visibility_scope": str(live["visibility_scope"]),
        **({"project_id": project_id} if project_id else {}),
    }
    expected_children = {
        core["librarian_job_id"]: {
            "role": "librarian",
            "job_type": "review_card_placement",
            "payload": {
                "card_id": core["card_id"],
                "segment_id": core["segment_id"],
                **shared_payload,
            },
            "dedupe_key": _opaque_queue_dedupe_key(
                "librarian",
                "review_card_placement",
                f"card:{core['card_id']}",
            ),
        },
        core["archivist_job_id"]: {
            "role": "archivist",
            "job_type": "verify_segment_integrity",
            "payload": {
                "segment_id": core["segment_id"],
                "segment_hash": str(live["segment_hash"]),
                **shared_payload,
            },
            "dedupe_key": _opaque_queue_dedupe_key(
                "archivist",
                "verify_segment_integrity",
                f"segment:{core['segment_id']}",
            ),
        },
    }
    child_rows = conn.execute(
        """
        SELECT id, role, job_type, payload_json, related_card_ids_json,
               dedupe_key
        FROM queue_jobs
        WHERE id IN (?, ?)
        """,
        (
            core["librarian_job_id"],
            core["archivist_job_id"],
        ),
    ).fetchall()
    if len(child_rows) != 2:
        return "scribe_live_child_job_missing"
    for child in child_rows:
        expected = expected_children.get(str(child["id"]))
        if (
            expected is None
            or child["role"] != expected["role"]
            or child["job_type"] != expected["job_type"]
            or child["dedupe_key"] != expected["dedupe_key"]
            or not _json_values_match(
                json_loads(child["payload_json"], None),
                expected["payload"],
            )
            or not _json_values_match(
                json_loads(child["related_card_ids_json"], None),
                [core["card_id"]],
            )
        ):
            return "scribe_live_child_job_identity_mismatch"
    return None


def _validate_scribe_terminal_result(
    result: Any,
) -> tuple[list[dict[str, Any]] | None, str]:
    if (
        not isinstance(result, dict)
        or set(result) != _SCRIBE_TERMINAL_RESULT_KEYS
        or result.get("ok") is not False
        or not isinstance(result.get("rolled"), list)
        or not result["rolled"]
        or not _exact_int(result.get("rolled_count"))
        or result["rolled_count"] != len(result["rolled"])
        or not _exact_int(result.get("batches_processed"))
        or not 1 <= result["batches_processed"] <= (
            MAX_SCRIBE_SEGMENT_BATCHES_PER_RUN
        )
        or result.get("batch_limit")
        != MAX_SCRIBE_SEGMENT_BATCHES_PER_RUN
        or not isinstance(result.get("drain_limited"), bool)
        or not isinstance(result.get("continuations"), list)
        or not _exact_int(result.get("concurrent_progress"))
        or result["concurrent_progress"] < 0
        or not isinstance(result.get("sidecar_failures"), list)
    ):
        return None, "scribe_result_identity_invalid"
    expected_failures: list[dict[str, Any]] = []
    for item in result["rolled"]:
        if not isinstance(item, dict) or not isinstance(item.get("ok"), bool):
            return None, "scribe_rolled_item_invalid"
        if item["ok"] is False:
            sidecars = item.get("sidecars")
            if (
                not isinstance(sidecars, dict)
                or sidecars.get("ok") is not False
                or any(
                    item.get(key) not in (None, "")
                    for key in ("reason", "error")
                )
            ):
                return None, "scribe_non_sidecar_failure"
            expected_failures.append(
                {
                    "segment_id": item.get("segment_id"),
                    "card_id": item.get("card_id"),
                    "sidecars": sidecars,
                }
            )
    if (
        not expected_failures
        or not _json_values_match(
            result["sidecar_failures"],
            expected_failures,
        )
    ):
        return None, "scribe_sidecar_failure_set_invalid"
    return result["rolled"], "eligible"


def _scribe_validation_progress_state(
    conn,
    candidate: dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    snapshot_sha256 = _failed_recovery_snapshot_sha256(candidate)
    row = conn.execute(
        """
        SELECT payload_json
        FROM audit_events
        WHERE action = ? AND target_type = 'queue_job' AND target_id = ?
          AND json_valid(payload_json)
          AND json_extract(payload_json, '$.schema') = ?
          AND json_extract(payload_json, '$.decision') = 'validating'
          AND json_extract(payload_json, '$.effect_event_id') = ?
          AND json_extract(
              payload_json,
              '$.queue_snapshot_sha256'
          ) = ?
        ORDER BY rowid DESC
        LIMIT 1
        """,
        (
            _FAILED_SIDECAR_RECOVERY_ACTION,
            candidate["id"],
            _FAILED_SIDECAR_RECOVERY_SCHEMA,
            candidate["recovery_effect_key"],
            snapshot_sha256,
        ),
    ).fetchone()
    if row is None:
        return None, "none"
    payload = json_loads(row["payload_json"], None)
    state = payload.get("validation_state") if isinstance(payload, dict) else None
    if (
        not isinstance(state, dict)
        or set(state) != _SCRIBE_VALIDATION_STATE_KEYS
        or not _exact_int(state.get("validated_count"))
        or state["validated_count"] < 1
        or not _exact_int(state.get("completed_count"))
        or not 0 <= state["completed_count"] <= state["validated_count"]
        or not _exact_int(state.get("last_committed_rowid"))
        or state["last_committed_rowid"] < 1
        or not _exact_int(state.get("first_start_seq"))
        or state["first_start_seq"] < 1
        or not _exact_int(state.get("last_end_seq"))
        or state["last_end_seq"] < state["first_start_seq"]
        or not _exact_int(state.get("last_batch_number"))
        or not 1 <= state["last_batch_number"] <= (
            MAX_SCRIBE_SEGMENT_BATCHES_PER_RUN
        )
        or not isinstance(state.get("batch_numbers"), list)
        or state["batch_numbers"]
        != sorted(set(state["batch_numbers"]))
        or any(
            not _exact_int(batch_number)
            or not 1 <= batch_number <= MAX_SCRIBE_SEGMENT_BATCHES_PER_RUN
            for batch_number in state["batch_numbers"]
        )
        or len(state["batch_numbers"])
        > MAX_SCRIBE_SEGMENT_BATCHES_PER_RUN
        or state["last_batch_number"] not in state["batch_numbers"]
        or not isinstance(state.get("authority_chain_sha256"), str)
        or not state["authority_chain_sha256"]
    ):
        return None, "scribe_validation_progress_invalid"
    return dict(state), "eligible"


def _scribe_receipt_count_state(
    conn,
    *,
    job_id: str,
    before_rowid: int | None,
) -> tuple[int, int]:
    before_clause = ""
    if before_rowid is not None:
        before_clause = " AND rowid < ?"
    row = conn.execute(
        f"""
        SELECT sum(action = ?) AS committed_count,
               sum(action = ?) AS completed_count
        FROM audit_events
        WHERE target_type = 'queue_job' AND target_id = ?
          AND action IN (?, ?){before_clause}
        """,
        [
            _SCRIBE_STEP_COMMITTED_ACTION,
            _SCRIBE_STEP_COMPLETED_ACTION,
            job_id,
            _SCRIBE_STEP_COMMITTED_ACTION,
            _SCRIBE_STEP_COMPLETED_ACTION,
            *([before_rowid] if before_rowid is not None else []),
        ],
    ).fetchone()
    return (
        int(row["committed_count"] or 0),
        int(row["completed_count"] or 0),
    )


def _scribe_final_authority_drift_reason(
    conn,
    *,
    job_id: str,
    session_id: str,
    before_rowid: int | None,
    terminal_result: dict[str, Any] | None,
) -> str | None:
    conn.create_function(
        "_continuum_queue_dedupe_v1",
        3,
        _opaque_queue_dedupe_key,
        deterministic=True,
    )
    upper_clause = ""
    upper_params: list[Any] = []
    if before_rowid is not None:
        upper_clause = " AND rowid < ?"
        upper_params.append(before_rowid)
    malformed = conn.execute(
        f"""
        SELECT 1
        FROM audit_events
        WHERE target_type = 'queue_job' AND target_id = ?
          AND action IN (?, ?){upper_clause}
          AND NOT json_valid(payload_json)
        LIMIT 1
        """,
        (
            job_id,
            _SCRIBE_STEP_COMMITTED_ACTION,
            _SCRIBE_STEP_COMPLETED_ACTION,
            *upper_params,
        ),
    ).fetchone()
    if malformed is not None:
        return "scribe_final_receipt_json_drift"
    malformed_child = conn.execute(
        f"""
        WITH committed AS (
            SELECT payload_json
            FROM audit_events
            WHERE action = ?
              AND target_type = 'queue_job' AND target_id = ?
              {upper_clause}
        )
        SELECT 1
        FROM committed
        LEFT JOIN queue_jobs AS librarian
          ON librarian.id = json_extract(
              committed.payload_json,
              '$.result.librarian_job_id'
          )
        LEFT JOIN queue_jobs AS archivist
          ON archivist.id = json_extract(
              committed.payload_json,
              '$.result.archivist_job_id'
          )
        WHERE librarian.id IS NULL
           OR archivist.id IS NULL
           OR NOT json_valid(librarian.payload_json)
           OR NOT json_valid(librarian.related_card_ids_json)
           OR NOT json_valid(archivist.payload_json)
           OR NOT json_valid(archivist.related_card_ids_json)
        LIMIT 1
        """,
        (
            _SCRIBE_STEP_COMMITTED_ACTION,
            job_id,
            *upper_params,
        ),
    ).fetchone()
    if malformed_child is not None:
        return "scribe_final_child_authority_drift"
    non_current_statuses = sorted(NON_CURRENT_CARD_STATUSES)
    status_placeholders = ",".join(
        "?" for _ in non_current_statuses
    )
    terminal_json = (
        json_dumps(terminal_result)
        if terminal_result is not None
        else None
    )
    committed_drift = conn.execute(
        f"""
        WITH committed AS (
            SELECT rowid AS committed_rowid, payload_json,
                   row_number() OVER (ORDER BY rowid) - 1 AS ordinal
            FROM audit_events
            WHERE action = ?
              AND target_type = 'queue_job' AND target_id = ?
              {upper_clause}
        ),
        rolled AS (
            SELECT CAST(key AS INTEGER) AS ordinal, value
            FROM json_each(?, '$.rolled')
        )
        SELECT 1
        FROM committed AS receipt
        LEFT JOIN rolled
          ON rolled.ordinal = receipt.ordinal
        LEFT JOIN scroll_segments AS segment
          ON segment.id = json_extract(
              receipt.payload_json,
              '$.result.segment_id'
          )
        LEFT JOIN cards AS card
          ON card.id = segment.summary_card_id
        LEFT JOIN queue_jobs AS librarian
          ON librarian.id = json_extract(
              receipt.payload_json,
              '$.result.librarian_job_id'
          )
        LEFT JOIN queue_jobs AS archivist
          ON archivist.id = json_extract(
              receipt.payload_json,
              '$.result.archivist_job_id'
          )
        WHERE
            (SELECT count(*) FROM json_each(receipt.payload_json)) != 7
            OR (
                SELECT count(*)
                FROM json_each(receipt.payload_json)
                WHERE key IN (
                    'schema', 'step_key', 'session_id', 'start_seq',
                    'end_seq', 'batch_number', 'result'
                )
            ) != 7
            OR json_extract(receipt.payload_json, '$.schema')
               IS NOT
               'continuum.worker_scribe_segment_step_committed.v1'
            OR json_extract(receipt.payload_json, '$.session_id')
               IS NOT ?
            OR json_type(receipt.payload_json, '$.start_seq')
               IS NOT 'integer'
            OR json_extract(receipt.payload_json, '$.start_seq') < 1
            OR json_type(receipt.payload_json, '$.end_seq')
               IS NOT 'integer'
            OR json_extract(receipt.payload_json, '$.end_seq')
               < json_extract(receipt.payload_json, '$.start_seq')
            OR json_type(receipt.payload_json, '$.batch_number')
               IS NOT 'integer'
            OR json_extract(receipt.payload_json, '$.batch_number')
               NOT BETWEEN 1 AND ?
            OR json_extract(receipt.payload_json, '$.step_key')
               IS NOT (
                   ? || ':' ||
                   json_extract(receipt.payload_json, '$.start_seq')
                   || ':' ||
                   json_extract(receipt.payload_json, '$.end_seq')
               )
            OR json_type(receipt.payload_json, '$.result')
               IS NOT 'object'
            OR (
                SELECT count(*)
                FROM json_each(receipt.payload_json, '$.result')
            ) != 6
            OR (
                SELECT count(*)
                FROM json_each(receipt.payload_json, '$.result')
                WHERE key IN (
                    'segment_id', 'card_id', 'event_count',
                    'token_estimate', 'librarian_job_id',
                    'archivist_job_id'
                )
            ) != 6
            OR json_type(
                receipt.payload_json,
                '$.result.segment_id'
            ) IS NOT 'text'
            OR json_type(
                receipt.payload_json,
                '$.result.card_id'
            ) IS NOT 'text'
            OR json_type(
                receipt.payload_json,
                '$.result.librarian_job_id'
            ) IS NOT 'text'
            OR json_type(
                receipt.payload_json,
                '$.result.archivist_job_id'
            ) IS NOT 'text'
            OR json_type(
                receipt.payload_json,
                '$.result.event_count'
            ) IS NOT 'integer'
            OR json_extract(
                receipt.payload_json,
                '$.result.event_count'
            ) <= 0
            OR json_type(
                receipt.payload_json,
                '$.result.token_estimate'
            ) IS NOT 'integer'
            OR json_extract(
                receipt.payload_json,
                '$.result.token_estimate'
            ) < 0
            OR segment.id IS NULL
            OR segment.session_id IS NOT ?
            OR segment.start_seq IS NOT json_extract(
                receipt.payload_json,
                '$.start_seq'
            )
            OR segment.end_seq IS NOT json_extract(
                receipt.payload_json,
                '$.end_seq'
            )
            OR segment.summary_card_id IS NOT json_extract(
                receipt.payload_json,
                '$.result.card_id'
            )
            OR segment.token_estimate IS NOT json_extract(
                receipt.payload_json,
                '$.result.token_estimate'
            )
            OR segment.segment_hash IS NULL
            OR segment.segment_hash = ''
            OR card.id IS NULL
            OR lower(card.status) IN ({status_placeholders})
            OR card.session_id IS NOT ?
            OR (
                SELECT count(*)
                FROM (
                    SELECT event.visibility_scope,
                           coalesce(event.project_id, '') AS project_id
                    FROM scroll_events AS event
                    WHERE event.session_id = ?
                      AND event.seq BETWEEN
                          json_extract(
                              receipt.payload_json,
                              '$.start_seq'
                          )
                          AND json_extract(
                              receipt.payload_json,
                              '$.end_seq'
                          )
                    GROUP BY event.visibility_scope,
                             coalesce(event.project_id, '')
                )
            ) != 1
            OR card.visibility_scope IS NOT (
                SELECT event.visibility_scope
                FROM scroll_events AS event
                WHERE event.session_id = ?
                  AND event.seq BETWEEN
                      json_extract(receipt.payload_json, '$.start_seq')
                      AND json_extract(receipt.payload_json, '$.end_seq')
                ORDER BY event.seq
                LIMIT 1
            )
            OR coalesce(card.project_id, '') IS NOT coalesce((
                SELECT event.project_id
                FROM scroll_events AS event
                WHERE event.session_id = ?
                  AND event.seq BETWEEN
                      json_extract(receipt.payload_json, '$.start_seq')
                      AND json_extract(receipt.payload_json, '$.end_seq')
                ORDER BY event.seq
                LIMIT 1
            ), '')
            OR (
                SELECT count(*)
                FROM scroll_events AS event
                WHERE event.session_id = ?
                  AND event.seq BETWEEN
                      json_extract(receipt.payload_json, '$.start_seq')
                      AND json_extract(receipt.payload_json, '$.end_seq')
            ) IS NOT json_extract(
                receipt.payload_json,
                '$.result.event_count'
            )
            OR (
                SELECT min(event.seq)
                FROM scroll_events AS event
                WHERE event.session_id = ?
                  AND event.seq BETWEEN
                      json_extract(receipt.payload_json, '$.start_seq')
                      AND json_extract(receipt.payload_json, '$.end_seq')
            ) IS NOT json_extract(receipt.payload_json, '$.start_seq')
            OR (
                SELECT max(event.seq)
                FROM scroll_events AS event
                WHERE event.session_id = ?
                  AND event.seq BETWEEN
                      json_extract(receipt.payload_json, '$.start_seq')
                      AND json_extract(receipt.payload_json, '$.end_seq')
            ) IS NOT json_extract(receipt.payload_json, '$.end_seq')
            OR (
                SELECT coalesce(sum(event.token_estimate), 0)
                FROM scroll_events AS event
                WHERE event.session_id = ?
                  AND event.seq BETWEEN
                      json_extract(receipt.payload_json, '$.start_seq')
                      AND json_extract(receipt.payload_json, '$.end_seq')
            ) IS NOT json_extract(
                receipt.payload_json,
                '$.result.token_estimate'
            )
            OR librarian.id IS NULL
            OR librarian.role IS NOT 'librarian'
            OR librarian.job_type IS NOT 'review_card_placement'
            OR json_type(librarian.payload_json) IS NOT 'object'
            OR (
                SELECT count(*)
                FROM json_each(librarian.payload_json)
            ) != 4 + (coalesce(card.project_id, '') != '')
            OR (
                SELECT count(*)
                FROM json_each(librarian.payload_json)
                WHERE key IN (
                    'card_id', 'segment_id', 'session_id',
                    'visibility_scope', 'project_id'
                )
            ) != 4 + (coalesce(card.project_id, '') != '')
            OR json_extract(librarian.payload_json, '$.card_id')
               IS NOT card.id
            OR json_extract(librarian.payload_json, '$.segment_id')
               IS NOT segment.id
            OR json_extract(librarian.payload_json, '$.session_id')
               IS NOT ?
            OR json_extract(
                librarian.payload_json,
                '$.visibility_scope'
            ) IS NOT card.visibility_scope
            OR coalesce(
                json_extract(librarian.payload_json, '$.project_id'),
                ''
            ) IS NOT coalesce(card.project_id, '')
            OR json_type(librarian.related_card_ids_json)
               IS NOT 'array'
            OR json_array_length(librarian.related_card_ids_json) != 1
            OR json_extract(
                librarian.related_card_ids_json,
                '$[0]'
            ) IS NOT card.id
            OR librarian.dedupe_key IS NOT
               _continuum_queue_dedupe_v1(
                   'librarian',
                   'review_card_placement',
                   'card:' || card.id
               )
            OR archivist.id IS NULL
            OR archivist.role IS NOT 'archivist'
            OR archivist.job_type IS NOT 'verify_segment_integrity'
            OR json_type(archivist.payload_json) IS NOT 'object'
            OR (
                SELECT count(*)
                FROM json_each(archivist.payload_json)
            ) != 4 + (coalesce(card.project_id, '') != '')
            OR (
                SELECT count(*)
                FROM json_each(archivist.payload_json)
                WHERE key IN (
                    'segment_id', 'segment_hash', 'session_id',
                    'visibility_scope', 'project_id'
                )
            ) != 4 + (coalesce(card.project_id, '') != '')
            OR json_extract(archivist.payload_json, '$.segment_id')
               IS NOT segment.id
            OR json_extract(archivist.payload_json, '$.segment_hash')
               IS NOT segment.segment_hash
            OR json_extract(archivist.payload_json, '$.session_id')
               IS NOT ?
            OR json_extract(
                archivist.payload_json,
                '$.visibility_scope'
            ) IS NOT card.visibility_scope
            OR coalesce(
                json_extract(archivist.payload_json, '$.project_id'),
                ''
            ) IS NOT coalesce(card.project_id, '')
            OR json_type(archivist.related_card_ids_json)
               IS NOT 'array'
            OR json_array_length(archivist.related_card_ids_json) != 1
            OR json_extract(
                archivist.related_card_ids_json,
                '$[0]'
            ) IS NOT card.id
            OR archivist.dedupe_key IS NOT
               _continuum_queue_dedupe_v1(
                   'archivist',
                   'verify_segment_integrity',
                   'segment:' || segment.id
               )
            OR (
                ? IS NOT NULL
                AND (
                    rolled.ordinal IS NULL
                    OR json_extract(rolled.value, '$.segment_id')
                       IS NOT segment.id
                    OR json_extract(rolled.value, '$.card_id')
                       IS NOT card.id
                    OR json_extract(rolled.value, '$.event_count')
                       IS NOT json_extract(
                           receipt.payload_json,
                           '$.result.event_count'
                       )
                    OR json_extract(rolled.value, '$.token_estimate')
                       IS NOT segment.token_estimate
                    OR json_extract(rolled.value, '$.librarian_job_id')
                       IS NOT librarian.id
                    OR json_extract(rolled.value, '$.archivist_job_id')
                       IS NOT archivist.id
                )
            )
        LIMIT 1
        """,
        (
            _SCRIBE_STEP_COMMITTED_ACTION,
            job_id,
            *upper_params,
            terminal_json,
            session_id,
            MAX_SCRIBE_SEGMENT_BATCHES_PER_RUN,
            session_id,
            session_id,
            *non_current_statuses,
            session_id,
            session_id,
            session_id,
            session_id,
            session_id,
            session_id,
            session_id,
            session_id,
            session_id,
            session_id,
            terminal_json,
        ),
    ).fetchone()
    if committed_drift is not None:
        return "scribe_final_committed_or_live_authority_drift"
    completed_drift = conn.execute(
        f"""
        WITH committed AS (
            SELECT rowid AS committed_rowid, payload_json,
                   row_number() OVER (ORDER BY rowid) - 1 AS ordinal
            FROM audit_events
            WHERE action = ?
              AND target_type = 'queue_job' AND target_id = ?
              {upper_clause}
        ),
        completed AS (
            SELECT rowid AS completed_rowid, payload_json
            FROM audit_events
            WHERE action = ?
              AND target_type = 'queue_job' AND target_id = ?
              {upper_clause}
        ),
        rolled AS (
            SELECT CAST(key AS INTEGER) AS ordinal, value
            FROM json_each(?, '$.rolled')
        )
        SELECT 1
        FROM completed
        LEFT JOIN committed
          ON json_extract(completed.payload_json, '$.step_key')
             = json_extract(committed.payload_json, '$.step_key')
        LEFT JOIN rolled ON rolled.ordinal = committed.ordinal
        WHERE committed.committed_rowid IS NULL
           OR completed.completed_rowid <= committed.committed_rowid
           OR (
               SELECT count(*)
               FROM json_each(completed.payload_json)
           ) != 7
           OR (
               SELECT count(*)
               FROM json_each(completed.payload_json)
               WHERE key IN (
                   'schema', 'step_key', 'session_id', 'start_seq',
                   'end_seq', 'batch_number', 'result'
               )
           ) != 7
           OR json_extract(completed.payload_json, '$.schema')
              IS NOT
              'continuum.worker_scribe_segment_step_completed.v1'
           OR json_extract(completed.payload_json, '$.session_id')
              IS NOT ?
           OR json_extract(completed.payload_json, '$.start_seq')
              IS NOT json_extract(
                  committed.payload_json,
                  '$.start_seq'
              )
           OR json_extract(completed.payload_json, '$.end_seq')
              IS NOT json_extract(committed.payload_json, '$.end_seq')
           OR json_extract(completed.payload_json, '$.batch_number')
              IS NOT json_extract(
                  committed.payload_json,
                  '$.batch_number'
              )
           OR (
               SELECT count(*)
               FROM json_each(completed.payload_json, '$.result')
           ) != 9
           OR (
               SELECT count(*)
               FROM json_each(completed.payload_json, '$.result')
               WHERE key IN (
                   'segment_id', 'card_id', 'event_count',
                   'token_estimate', 'librarian_job_id',
                   'archivist_job_id', 'ok', 'sidecars', 'card_uri'
               )
           ) != 9
           OR json_type(completed.payload_json, '$.result.ok')
              NOT IN ('true', 'false')
           OR json_type(completed.payload_json, '$.result.sidecars')
              IS NOT 'object'
           OR json_type(completed.payload_json, '$.result.card_uri')
              NOT IN ('null', 'text')
           OR json_extract(completed.payload_json, '$.result.segment_id')
              IS NOT json_extract(
                  committed.payload_json,
                  '$.result.segment_id'
              )
           OR json_extract(completed.payload_json, '$.result.card_id')
              IS NOT json_extract(
                  committed.payload_json,
                  '$.result.card_id'
              )
           OR json_extract(completed.payload_json, '$.result.event_count')
              IS NOT json_extract(
                  committed.payload_json,
                  '$.result.event_count'
              )
           OR json_extract(
               completed.payload_json,
               '$.result.token_estimate'
           ) IS NOT json_extract(
               committed.payload_json,
               '$.result.token_estimate'
           )
           OR json_extract(
               completed.payload_json,
               '$.result.librarian_job_id'
           ) IS NOT json_extract(
               committed.payload_json,
               '$.result.librarian_job_id'
           )
           OR json_extract(
               completed.payload_json,
               '$.result.archivist_job_id'
           ) IS NOT json_extract(
               committed.payload_json,
               '$.result.archivist_job_id'
           )
           OR (
               ? IS NOT NULL
               AND json(
                   json_remove(
                       json_extract(completed.payload_json, '$.result'),
                       '$.card_uri'
                   )
               ) IS NOT json(json_remove(rolled.value, '$.card_uri'))
           )
        LIMIT 1
        """,
        (
            _SCRIBE_STEP_COMMITTED_ACTION,
            job_id,
            *upper_params,
            _SCRIBE_STEP_COMPLETED_ACTION,
            job_id,
            *upper_params,
            terminal_json,
            session_id,
            terminal_json,
        ),
    ).fetchone()
    if completed_drift is not None:
        return "scribe_final_completed_authority_drift"
    return None


def _validate_failed_scribe_authority(
    conn,
    candidate: dict[str, Any],
    parsed: dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    payload = parsed["queue_payload"]
    session_id = payload.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        return None, "scribe_result_identity_invalid"
    rolled: list[dict[str, Any]] | None = None
    if not parsed["effectless"]:
        rolled, reason = _validate_scribe_terminal_result(parsed["result"])
        if rolled is None:
            return None, reason
    effect_rowid = (
        int(candidate["effect_rowid"])
        if candidate.get("effect_rowid") is not None
        else None
    )
    state, progress_reason = _scribe_validation_progress_state(
        conn,
        candidate,
    )
    if progress_reason == "scribe_validation_progress_invalid":
        return None, progress_reason
    snapshot_sha256 = _failed_recovery_snapshot_sha256(candidate)
    if state is None:
        validated_count = 0
        completed_count = 0
        last_committed_rowid = 0
        first_start_seq: int | None = None
        last_end_seq: int | None = None
        last_batch_number = 0
        batch_numbers: set[int] = set()
        authority_chain_sha256 = content_hash(
            f"scribe-recovery-v1:{snapshot_sha256}"
        )
    else:
        validated_count = int(state["validated_count"])
        completed_count = int(state["completed_count"])
        last_committed_rowid = int(state["last_committed_rowid"])
        first_start_seq = int(state["first_start_seq"])
        last_end_seq = int(state["last_end_seq"])
        last_batch_number = int(state["last_batch_number"])
        batch_numbers = set(state["batch_numbers"])
        authority_chain_sha256 = str(state["authority_chain_sha256"])
    rowid_clause = ""
    params: list[Any] = [
        _SCRIBE_STEP_COMMITTED_ACTION,
        candidate["id"],
        last_committed_rowid,
    ]
    if effect_rowid is not None:
        rowid_clause = " AND rowid < ?"
        params.append(effect_rowid)
    rows = conn.execute(
        f"""
        SELECT id, rowid AS event_rowid, payload_json
        FROM audit_events
        WHERE action = ?
          AND target_type = 'queue_job' AND target_id = ?
          AND rowid > ?{rowid_clause}
        ORDER BY rowid
        LIMIT ?
        """,
        [
            *params,
            WORKER_FAILED_SCRIBE_STEP_VALIDATION_LIMIT + 1,
        ],
    ).fetchall()
    for committed_row in rows[
        :WORKER_FAILED_SCRIBE_STEP_VALIDATION_LIMIT
    ]:
        committed_receipt, reason = _parse_exact_scribe_receipt(
            committed_row,
            action=_SCRIBE_STEP_COMMITTED_ACTION,
            session_id=session_id,
        )
        if committed_receipt is None:
            return None, reason
        core = _exact_scribe_committed_core(
            committed_receipt["result"]
        )
        if core is None:
            return None, "scribe_committed_core_invalid"
        start_seq = int(committed_receipt["start_seq"])
        end_seq = int(committed_receipt["end_seq"])
        batch_number = int(committed_receipt["batch_number"])
        if (
            last_end_seq is not None
            and start_seq != last_end_seq + 1
        ):
            return None, "scribe_committed_range_not_contiguous"
        if batch_number < last_batch_number:
            return None, "scribe_batch_chronology_invalid"
        batch_numbers.add(batch_number)
        if len(batch_numbers) > MAX_SCRIBE_SEGMENT_BATCHES_PER_RUN:
            return None, "scribe_batch_set_exceeded"
        live_reason = _validate_live_scribe_core(
            conn,
            session_id=session_id,
            start_seq=start_seq,
            end_seq=end_seq,
            core=core,
        )
        if live_reason is not None:
            return None, live_reason
        ordinal = validated_count
        terminal_item = (
            rolled[ordinal]
            if rolled is not None and ordinal < len(rolled)
            else None
        )
        if rolled is not None and terminal_item is None:
            return None, "scribe_terminal_result_missing_step"
        if terminal_item is not None and not (
            _scribe_post_sidecar_result_matches_core(
                terminal_item,
                core,
            )
        ):
            return None, "scribe_terminal_core_mismatch"
        completion_params: list[Any] = [
            _SCRIBE_STEP_COMPLETED_ACTION,
            candidate["id"],
            committed_receipt["step_key"],
        ]
        completion_upper = ""
        if effect_rowid is not None:
            completion_upper = " AND rowid < ?"
            completion_params.append(effect_rowid)
        completed_rows = conn.execute(
            f"""
            SELECT id, rowid AS event_rowid, payload_json
            FROM audit_events
            WHERE action = ?
              AND target_type = 'queue_job' AND target_id = ?
              AND json_valid(payload_json)
              AND json_extract(payload_json, '$.step_key') = ?
              {completion_upper}
            ORDER BY rowid
            LIMIT 2
            """,
            completion_params,
        ).fetchall()
        completed_event_id: str | None = None
        completed_payload_sha256: str | None = None
        if len(completed_rows) > 1:
            return None, "scribe_completed_step_duplicate"
        if completed_rows:
            completed_row = completed_rows[0]
            if int(completed_row["event_rowid"]) <= int(
                committed_row["event_rowid"]
            ):
                return None, "scribe_completed_chronology_invalid"
            completed_receipt, reason = _parse_exact_scribe_receipt(
                completed_row,
                action=_SCRIBE_STEP_COMPLETED_ACTION,
                session_id=session_id,
            )
            if completed_receipt is None:
                return None, reason
            if any(
                completed_receipt[key] != committed_receipt[key]
                for key in (
                    "step_key",
                    "session_id",
                    "start_seq",
                    "end_seq",
                    "batch_number",
                )
            ) or not _scribe_post_sidecar_result_matches_core(
                completed_receipt["result"],
                core,
            ):
                return None, "scribe_completed_identity_mismatch"
            if terminal_item is not None:
                comparable_item = dict(terminal_item)
                comparable_completed = dict(completed_receipt["result"])
                comparable_item.pop("card_uri", None)
                comparable_completed.pop("card_uri", None)
                if not _json_values_match(
                    comparable_item,
                    comparable_completed,
                ):
                    return None, "scribe_completed_result_mismatch"
            completed_count += 1
            completed_event_id = str(completed_row["id"])
            completed_payload_sha256 = content_hash(
                str(completed_row["payload_json"])
            )
        elif terminal_item is not None and not (
            _scribe_missing_completion_matches(terminal_item, core)
        ):
            return None, "scribe_completed_step_missing"
        authority_chain_sha256 = content_hash(
            json_dumps(
                {
                    "previous": authority_chain_sha256,
                    "committed_event_id": str(committed_row["id"]),
                    "committed_payload_sha256": content_hash(
                        str(committed_row["payload_json"])
                    ),
                    "completed_event_id": completed_event_id,
                    "completed_payload_sha256": completed_payload_sha256,
                    "terminal_result_sha256": (
                        content_hash(json_dumps(terminal_item))
                        if terminal_item is not None
                        else None
                    ),
                }
            )
        )
        validated_count += 1
        last_committed_rowid = int(committed_row["event_rowid"])
        if first_start_seq is None:
            first_start_seq = start_seq
        last_end_seq = end_seq
        last_batch_number = batch_number
    if len(rows) > WORKER_FAILED_SCRIBE_STEP_VALIDATION_LIMIT:
        if first_start_seq is None or last_end_seq is None:
            return None, "scribe_committed_range_missing"
        return {
            "validation_pending": True,
            "queue_snapshot_sha256": snapshot_sha256,
            "validation_state": {
                "validated_count": validated_count,
                "completed_count": completed_count,
                "last_committed_rowid": last_committed_rowid,
                "first_start_seq": first_start_seq,
                "last_end_seq": last_end_seq,
                "last_batch_number": last_batch_number,
                "batch_numbers": sorted(batch_numbers),
                "authority_chain_sha256": authority_chain_sha256,
            },
        }, "scribe_validation_pending"
    if validated_count < 1:
        return None, "scribe_committed_step_missing"
    if rolled is not None and len(rolled) != validated_count:
        return None, "scribe_terminal_result_step_count_mismatch"
    if (
        rolled is not None
        and parsed["result"]["batches_processed"]
        != max(batch_numbers)
    ):
        return None, "scribe_batch_count_mismatch"
    receipt_counts = _scribe_receipt_count_state(
        conn,
        job_id=str(candidate["id"]),
        before_rowid=effect_rowid,
    )
    if receipt_counts != (validated_count, completed_count):
        return None, "scribe_receipt_set_mismatch"
    if effect_rowid is not None:
        post_effect_receipt = conn.execute(
            """
            SELECT 1
            FROM audit_events
            WHERE target_type = 'queue_job' AND target_id = ?
              AND action IN (?, ?) AND rowid >= ?
            LIMIT 1
            """,
            (
                candidate["id"],
                _SCRIBE_STEP_COMMITTED_ACTION,
                _SCRIBE_STEP_COMPLETED_ACTION,
                effect_rowid,
            ),
        ).fetchone()
        if post_effect_receipt is not None:
            return None, "scribe_receipt_after_terminal_effect"
    duplicate = conn.execute(
        """
        WITH committed AS (
            SELECT payload_json
            FROM audit_events
            WHERE action = ?
              AND target_type = 'queue_job' AND target_id = ?
              AND (? IS NULL OR rowid < ?)
        ),
        identities(kind, value) AS (
            SELECT 'step', json_extract(payload_json, '$.step_key')
            FROM committed
            UNION ALL
            SELECT 'range',
                   json_extract(payload_json, '$.start_seq') || ':'
                   || json_extract(payload_json, '$.end_seq')
            FROM committed
            UNION ALL
            SELECT 'segment',
                   json_extract(payload_json, '$.result.segment_id')
            FROM committed
            UNION ALL
            SELECT 'card',
                   json_extract(payload_json, '$.result.card_id')
            FROM committed
        )
        SELECT 1
        FROM identities
        GROUP BY kind, value
        HAVING value IS NULL OR count(*) != 1
        LIMIT 1
        """,
        (
            _SCRIBE_STEP_COMMITTED_ACTION,
            candidate["id"],
            effect_rowid,
            effect_rowid,
        ),
    ).fetchone()
    if duplicate is not None:
        return None, "scribe_committed_identity_duplicate"
    final_batch_state = conn.execute(
        """
        SELECT count(DISTINCT json_extract(
                   payload_json,
                   '$.batch_number'
               )) AS batch_count,
               max(json_extract(
                   payload_json,
                   '$.batch_number'
               )) AS max_batch
        FROM audit_events
        WHERE action = ?
          AND target_type = 'queue_job' AND target_id = ?
          AND (? IS NULL OR rowid < ?)
        """,
        (
            _SCRIBE_STEP_COMMITTED_ACTION,
            candidate["id"],
            effect_rowid,
            effect_rowid,
        ),
    ).fetchone()
    if (
        final_batch_state is None
        or int(final_batch_state["batch_count"] or 0) != len(batch_numbers)
        or int(final_batch_state["max_batch"] or 0) != max(batch_numbers)
        or (
            rolled is not None
            and int(final_batch_state["max_batch"] or 0)
            != parsed["result"]["batches_processed"]
        )
    ):
        return None, "scribe_final_batch_authority_drift"
    drift_reason = _scribe_final_authority_drift_reason(
        conn,
        job_id=str(candidate["id"]),
        session_id=session_id,
        before_rowid=effect_rowid,
        terminal_result=(
            parsed["result"] if rolled is not None else None
        ),
    )
    if drift_reason is not None:
        return None, drift_reason
    if first_start_seq is None or last_end_seq is None:
        return None, "scribe_committed_range_missing"
    return {
        "identity": {
            "session_id": session_id,
            "step_count": validated_count,
            "first_start_seq": first_start_seq,
            "last_end_seq": last_end_seq,
        },
        "authority_chain_sha256": authority_chain_sha256,
        "completed_step_count": completed_count,
        "batch_numbers": sorted(batch_numbers),
        "queue_snapshot_sha256": snapshot_sha256,
    }, "eligible"


def _sidecar_reconciliation_is_clean(value: Any) -> bool:
    return bool(
        isinstance(value, dict)
        and value.get("ok") is True
        and _exact_int(value.get("pending"))
        and int(value["pending"]) == 0
        and value.get("scope_complete", value.get("complete")) is True
    )


def _validate_failed_sync_sidecar_authority(
    conn,
    candidate: dict[str, Any],
    parsed: dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    payload = parsed["queue_payload"]
    card_id = payload.get("card_id")
    if (
        not isinstance(card_id, str)
        or not card_id
        or card_id not in parsed["related_card_ids"]
    ):
        return None, "sidecar_job_identity_mismatch"
    live = conn.execute(
        "SELECT status, location_uri FROM cards WHERE id = ?",
        (card_id,),
    ).fetchone()
    if (
        live is None
        or str(live["status"] or "").casefold()
        in NON_CURRENT_CARD_STATUSES
    ):
        return None, "sidecar_job_live_card_missing"
    if parsed["effectless"]:
        phase_row = conn.execute(
            """
            SELECT id, rowid AS event_rowid, payload_json
            FROM audit_events
            WHERE action = ?
              AND target_type = 'queue_job' AND target_id = ?
            ORDER BY rowid DESC
            LIMIT 1
            """,
            (_SIDECAR_WORKER_PHASE_ACTION, candidate["id"]),
        ).fetchone()
        if phase_row is None:
            return None, "sidecar_job_phase_missing"
        phase_payload = json_loads(phase_row["payload_json"], None)
        allowed_phases = {
            "materialized_pending_reconciliation",
            "reconciliation_deferred",
            "sidecar_sync_deferred",
            "sidecars_disabled_retry_pending",
        }
        if (
            not isinstance(phase_payload, dict)
            or set(phase_payload)
            != {"schema", "job_type", "phase", "result"}
            or phase_payload.get("schema")
            != _SIDECAR_WORKER_PHASE_SCHEMA
            or phase_payload.get("job_type") != "sync_card_sidecar"
            or phase_payload.get("phase") not in allowed_phases
            or not isinstance(phase_payload.get("result"), dict)
            or phase_payload["result"].get("card_id") != card_id
        ):
            return None, "sidecar_job_phase_invalid"
        phase_location = phase_payload["result"].get("location_uri")
        if (
            phase_location is not None
            and phase_location != live["location_uri"]
        ):
            return None, "sidecar_job_phase_live_location_mismatch"
        return {
            "identity": {"card_id": card_id},
            "authority_event_ids": [str(phase_row["id"])],
        }, "eligible"
    effect_payload = json_loads(
        candidate.get("effect_payload_json"),
        None,
    )
    if (
        not isinstance(effect_payload, dict)
        or set(effect_payload)
        != {"schema", "job_type", "post_phase_complete", "result"}
        or effect_payload.get("schema") != _WORKER_EFFECT_SCHEMA
        or effect_payload.get("job_type") != "sync_card_sidecar"
        or effect_payload.get("post_phase_complete") is not False
        or not isinstance(effect_payload.get("result"), dict)
    ):
        return None, "sidecar_job_terminal_effect_invalid"
    effect_result = effect_payload["result"]
    if (
        set(effect_result)
        != {"ok", "card_id", "location_uri", "intent_reconciliation"}
        or effect_result.get("ok") is not True
        or effect_result.get("card_id") != card_id
        or not isinstance(effect_result.get("location_uri"), str)
        or not effect_result["location_uri"]
        or not _sidecar_reconciliation_is_clean(
            effect_result.get("intent_reconciliation")
        )
        or effect_result["location_uri"] != live["location_uri"]
    ):
        return None, "sidecar_job_terminal_effect_invalid"
    error_payload = parsed["error_payload"]
    queue_result = error_payload["result"]
    if (
        error_payload.get("error") != "worker result reported ok=false"
        or set(queue_result)
        != set(effect_result) | {"idempotent_replay"}
        or queue_result.get("idempotent_replay") is not True
        or queue_result.get("ok") is not False
        or queue_result.get("card_id") != card_id
        or queue_result.get("location_uri") != effect_result["location_uri"]
        or not isinstance(queue_result.get("intent_reconciliation"), dict)
        or _sidecar_reconciliation_is_clean(
            queue_result["intent_reconciliation"]
        )
    ):
        return None, "sidecar_job_failed_replay_envelope_invalid"
    phase_row = conn.execute(
        """
        SELECT id, rowid AS event_rowid, payload_json
        FROM audit_events
        WHERE action = ?
          AND target_type = 'queue_job' AND target_id = ?
          AND rowid > ?
        ORDER BY rowid DESC
        LIMIT 1
        """,
        (
            _SIDECAR_WORKER_PHASE_ACTION,
            candidate["id"],
            int(candidate["effect_rowid"]),
        ),
    ).fetchone()
    if phase_row is None:
        return None, "sidecar_job_failed_replay_phase_missing"
    phase_payload = json_loads(phase_row["payload_json"], None)
    if (
        not isinstance(phase_payload, dict)
        or set(phase_payload)
        != {"schema", "job_type", "phase", "result"}
        or phase_payload.get("schema") != _SIDECAR_WORKER_PHASE_SCHEMA
        or phase_payload.get("job_type") != "sync_card_sidecar"
        or phase_payload.get("phase") != "reconciliation_deferred"
        or not _json_values_match(
            phase_payload.get("result"),
            queue_result,
        )
    ):
        return None, "sidecar_job_failed_replay_phase_invalid"
    return {
        "identity": {"card_id": card_id},
        "authority_event_ids": [
            str(candidate["effect_event_id"]),
            str(phase_row["id"]),
        ],
    }, "eligible"


def _validate_failed_sidecar_recovery_candidate(
    conn,
    candidate: dict[str, Any],
) -> tuple[dict[str, Any] | None, str]:
    recovery_mode = str(candidate.get("recovery_mode") or "")
    job_type = str(candidate["job_type"])
    if recovery_mode == "effectless":
        parsed, reason = _validate_failed_effectless_queue(candidate)
    elif job_type == "sync_card_sidecar":
        parsed, reason = _validate_failed_queue_state(candidate)
        if parsed is not None:
            parsed.update({"result": None, "effectless": False})
    else:
        parsed, reason = _validate_failed_queue_effect(candidate)
    if parsed is None:
        return None, reason
    if job_type == "review_card_placement":
        return _validate_failed_placement_authority(
            conn,
            candidate,
            parsed,
        )
    if job_type == "review_mempalace_import":
        return _validate_failed_mempalace_authority(
            conn,
            candidate,
            parsed,
        )
    if job_type == "scroll_event_ingested":
        return _validate_failed_scribe_authority(
            conn,
            candidate,
            parsed,
        )
    if job_type == "sync_card_sidecar":
        return _validate_failed_sync_sidecar_authority(
            conn,
            candidate,
            parsed,
        )
    return None, "job_type_not_allowed"


def _record_failed_sidecar_recovery_disposition(
    conn,
    candidate: dict[str, Any],
    *,
    decision: str,
    reason: str,
    authority: dict[str, Any] | None = None,
) -> str:
    return audit_event(
        conn,
        action=_FAILED_SIDECAR_RECOVERY_ACTION,
        target_type="queue_job",
        target_id=str(candidate["id"]),
        payload={
            "schema": _FAILED_SIDECAR_RECOVERY_SCHEMA,
            "decision": decision,
            "reason": reason,
            "job_type": candidate["job_type"],
            "effect_event_id": candidate["recovery_effect_key"],
            "effect_event_rowid": (
                int(candidate["effect_rowid"])
                if candidate.get("effect_rowid") is not None
                else None
            ),
            "effect_payload_sha256": content_hash(
                str(candidate.get("effect_payload_json") or "")
            ),
            "queue_payload_sha256": content_hash(
                str(candidate["payload_json"])
            ),
            "previous_error_sha256": content_hash(
                str(candidate.get("error_json") or "")
            ),
            "attempt_count": int(candidate.get("attempt_count") or 0),
            "queue_snapshot_sha256": (
                _failed_recovery_snapshot_sha256(candidate)
            ),
            **(authority or {}),
        },
        actor="worker",
    )


def _recover_failed_post_phase_sidecar_jobs(
    root: Path,
    *,
    limit: int = WORKER_FAILED_SIDECAR_RECOVERY_LIMIT,
) -> dict[str, Any]:
    bounded_limit = max(
        1,
        min(int(limit), WORKER_FAILED_SIDECAR_RECOVERY_LIMIT),
    )
    read_conn = connect(root)
    try:
        window = _all_failed_sidecar_recovery_candidates(
            read_conn,
            limit=bounded_limit + 1,
        )
    finally:
        read_conn.close()
    selected = window[:bounded_limit]
    dispositions: list[dict[str, Any]] = []
    requeued = 0
    rejected = 0
    validating = 0
    changed = 0
    for snapshot_candidate in selected:
        conn = connect(root)
        try:
            conn.execute("BEGIN IMMEDIATE")
            current_window = _all_failed_sidecar_recovery_candidates(
                conn,
                limit=1,
                job_id=str(snapshot_candidate["id"]),
            )
            if not current_window:
                conn.rollback()
                changed += 1
                continue
            candidate = current_window[0]
            if not _json_values_match(
                _failed_recovery_snapshot(candidate),
                _failed_recovery_snapshot(snapshot_candidate),
            ):
                conn.rollback()
                changed += 1
                continue
            authority, reason = (
                _validate_failed_sidecar_recovery_candidate(
                    conn,
                    candidate,
                )
            )
            if (
                authority is not None
                and authority.get("validation_pending") is True
            ):
                progress_authority = dict(authority)
                progress_authority.pop("validation_pending", None)
                disposition_id = (
                    _record_failed_sidecar_recovery_disposition(
                        conn,
                        candidate,
                        decision="validating",
                        reason=reason,
                        authority=progress_authority,
                    )
                )
                conn.commit()
                validating += 1
                dispositions.append(
                    {
                        "job_id": candidate["id"],
                        "effect_event_id": candidate[
                            "recovery_effect_key"
                        ],
                        "disposition_id": disposition_id,
                        "decision": "validating",
                        "reason": reason,
                    }
                )
                continue
            if authority is not None and candidate.get("dedupe_key"):
                collision = conn.execute(
                    """
                    SELECT id, status
                    FROM queue_jobs
                    WHERE id != ? AND dedupe_key = ?
                      AND status IN ('pending', 'running')
                    ORDER BY rowid
                    LIMIT 1
                    """,
                    (candidate["id"], candidate["dedupe_key"]),
                ).fetchone()
                if collision is not None:
                    authority = None
                    reason = "live_dedupe_job_exists"
            if authority is None:
                disposition_id = (
                    _record_failed_sidecar_recovery_disposition(
                        conn,
                        candidate,
                        decision="rejected",
                        reason=reason,
                    )
                )
                conn.commit()
                rejected += 1
                dispositions.append(
                    {
                        "job_id": candidate["id"],
                        "effect_event_id": candidate[
                            "recovery_effect_key"
                        ],
                        "disposition_id": disposition_id,
                        "decision": "rejected",
                        "reason": reason,
                    }
                )
                continue
            now = utc_now()
            recovery_result = {
                "ok": False,
                "reason": POST_COMMIT_SIDECAR_RETRY_REASON,
                "retry_pending": True,
                "recovered_from_failed_status": True,
                "effect_event_id": candidate["recovery_effect_key"],
            }
            retry_order = _next_queue_retry_order(conn)
            cursor = conn.execute(
                """
                UPDATE queue_jobs
                SET status = 'pending', finished_at = NULL,
                    lease_owner = NULL, lease_expires_at = NULL,
                    heartbeat_at = NULL, updated_at = ?, error_json = ?,
                    retry_pending = 1, retry_order = ?
                WHERE rowid = ? AND id = ? AND status = 'failed'
                  AND job_type = ? AND role = ?
                  AND attempt_count = ? AND payload_json = ?
                  AND related_card_ids_json = ?
                  AND error_json IS ? AND updated_at = ?
                  AND finished_at IS ?
                   AND lease_owner IS ? AND lease_expires_at IS ?
                   AND heartbeat_at IS ?
                   AND (
                       (
                           ? = 'effect'
                           AND ? = (
                               SELECT effect.id
                               FROM audit_events AS effect
                               WHERE effect.action = ?
                                 AND effect.target_type = 'queue_job'
                                 AND effect.target_id = queue_jobs.id
                               ORDER BY effect.rowid DESC
                               LIMIT 1
                           )
                       )
                       OR (
                           ? = 'effectless'
                           AND NOT EXISTS (
                               SELECT 1
                               FROM audit_events AS effect
                               WHERE effect.action = ?
                                 AND effect.target_type = 'queue_job'
                                 AND effect.target_id = queue_jobs.id
                           )
                       )
                   )
                """,
                (
                    now,
                    json_dumps(
                        {
                            "error": None,
                            "result": recovery_result,
                            "retry_pending": True,
                        }
                    ),
                    retry_order,
                    int(candidate["queue_rowid"]),
                    candidate["id"],
                    candidate["job_type"],
                    candidate["role"],
                    int(candidate.get("attempt_count") or 0),
                    candidate["payload_json"],
                    candidate["related_card_ids_json"],
                    candidate.get("error_json"),
                    candidate["updated_at"],
                    candidate.get("finished_at"),
                    candidate.get("lease_owner"),
                    candidate.get("lease_expires_at"),
                    candidate.get("heartbeat_at"),
                    candidate["recovery_mode"],
                    candidate["effect_event_id"],
                    _WORKER_EFFECT_ACTION,
                    candidate["recovery_mode"],
                    _WORKER_EFFECT_ACTION,
                ),
            )
            if int(cursor.rowcount or 0) != 1:
                conn.rollback()
                changed += 1
                continue
            disposition_id = _record_failed_sidecar_recovery_disposition(
                conn,
                candidate,
                decision="requeued",
                reason=(
                    "exact_failed_sidecar_effect_recovered"
                    if candidate["recovery_mode"] == "effect"
                    else "exact_failed_post_commit_authority_recovered"
                ),
                authority=authority,
            )
            conn.commit()
            requeued += 1
            dispositions.append(
                {
                    "job_id": candidate["id"],
                    "effect_event_id": candidate[
                        "recovery_effect_key"
                    ],
                    "disposition_id": disposition_id,
                    "decision": "requeued",
                    "reason": (
                        "exact_failed_sidecar_effect_recovered"
                        if candidate["recovery_mode"] == "effect"
                        else (
                            "exact_failed_post_commit_authority_recovered"
                        )
                    ),
                }
            )
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()
    final_conn = connect(root)
    try:
        remaining = bool(
            _all_failed_sidecar_recovery_candidates(
                final_conn,
                limit=1,
            )
        )
    finally:
        final_conn.close()
    has_more = bool(validating or changed or remaining)
    return {
        "ok": True,
        "limit": bounded_limit,
        "selected": len(selected),
        "requeued": requeued,
        "rejected": rejected,
        "validating": validating,
        "changed_during_scan": changed,
        "has_more": has_more,
        "complete": not has_more,
        "dispositions": dispositions[:WORKER_MAINTENANCE_FAILURE_LIMIT],
    }


def _running_job_post_commit_authority(
    conn,
    job: dict[str, Any],
) -> dict[str, Any] | None:
    job_id = str(job["id"])
    job_type = str(job["job_type"])
    payload = json_loads(job.get("payload_json"), None)
    if not isinstance(payload, dict):
        return None
    effect_row = conn.execute(
        """
        SELECT id, payload_json
        FROM audit_events
        WHERE action = ?
          AND target_type = 'queue_job' AND target_id = ?
        ORDER BY rowid DESC
        LIMIT 1
        """,
        (_WORKER_EFFECT_ACTION, job_id),
    ).fetchone()
    if effect_row is not None:
        effect_payload = json_loads(effect_row["payload_json"], None)
        if (
            isinstance(effect_payload, dict)
            and set(effect_payload)
            == {"schema", "job_type", "post_phase_complete", "result"}
            and effect_payload.get("schema") == _WORKER_EFFECT_SCHEMA
            and effect_payload.get("job_type") == job_type
            and isinstance(effect_payload.get("post_phase_complete"), bool)
            and isinstance(effect_payload.get("result"), dict)
        ):
            return {
                "kind": "worker_effect",
                "event_id": str(effect_row["id"]),
            }
    if job_type == "review_card_placement":
        card_id = payload.get("card_id")
        phase = _exact_worker_phase_receipt(
            conn,
            job_id=job_id,
            job_type=job_type,
        )
        if (
            not isinstance(card_id, str)
            or not card_id
            or phase is None
        ):
            return None
        phase_row, phase_payload = phase
        phase_result = phase_payload["result"]
        core_result = phase_result.get("core_result")
        live = conn.execute(
            "SELECT status FROM cards WHERE id = ?",
            (card_id,),
        ).fetchone()
        if (
            set(phase_result) != {"core_result"}
            or not isinstance(core_result, dict)
            or core_result.get("ok") is not True
            or core_result.get("card_id") != card_id
            or live is None
            or str(live["status"] or "").casefold()
            in NON_CURRENT_CARD_STATUSES
        ):
            return None
        return {
            "kind": "placement_core_phase",
            "event_id": str(phase_row["id"]),
            "card_id": card_id,
        }
    if job_type == "review_mempalace_import":
        import_id = payload.get("import_id")
        phase = _exact_worker_phase_receipt(
            conn,
            job_id=job_id,
            job_type=job_type,
        )
        if (
            not isinstance(import_id, str)
            or not import_id
            or phase is None
        ):
            return None
        phase_row, phase_payload = phase
        phase_result = phase_payload["result"]
        core_result = phase_result.get("core_result")
        changed_cards = phase_result.get("changed_cards")
        if (
            set(phase_result) != {"core_result", "changed_cards"}
            or not isinstance(core_result, dict)
            or core_result.get("ok") is not True
            or core_result.get("reviewed_import") != import_id
            or not isinstance(changed_cards, list)
            or not changed_cards
            or len(changed_cards) > MAX_BACKLOG_RECONCILE_LIMIT
            or len(set(changed_cards)) != len(changed_cards)
        ):
            return None
        live_count = int(
            conn.execute(
                """
                SELECT count(*)
                FROM cards
                WHERE id IN (SELECT value FROM json_each(?))
                  AND status NOT IN (
                      'superseded', 'archived', 'pruned', 'deleted'
                  )
                """,
                (json_dumps(changed_cards),),
            ).fetchone()[0]
        )
        if live_count != len(changed_cards):
            return None
        return {
            "kind": "mempalace_core_phase",
            "event_id": str(phase_row["id"]),
            "import_id": import_id,
        }
    if job_type == "scroll_event_ingested":
        session_id = payload.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            return None
        committed_row = conn.execute(
            """
            SELECT id, rowid AS event_rowid, payload_json
            FROM audit_events
            WHERE action = ?
              AND target_type = 'queue_job' AND target_id = ?
            ORDER BY rowid DESC
            LIMIT 1
            """,
            (_SCRIBE_STEP_COMMITTED_ACTION, job_id),
        ).fetchone()
        if committed_row is None:
            return None
        committed_receipt, _reason = _parse_exact_scribe_receipt(
            committed_row,
            action=_SCRIBE_STEP_COMMITTED_ACTION,
            session_id=session_id,
        )
        if committed_receipt is None:
            return None
        core = _exact_scribe_committed_core(
            committed_receipt["result"]
        )
        if core is None:
            return None
        live_reason = _validate_live_scribe_core(
            conn,
            session_id=session_id,
            start_seq=int(committed_receipt["start_seq"]),
            end_seq=int(committed_receipt["end_seq"]),
            core=core,
        )
        if live_reason is not None:
            return None
        return {
            "kind": "scribe_committed_step",
            "event_id": str(committed_row["id"]),
            "step_key": committed_receipt["step_key"],
        }
    if job_type == "sync_card_sidecar":
        card_id = payload.get("card_id")
        if not isinstance(card_id, str) or not card_id:
            return None
        phase_row = conn.execute(
            """
            SELECT id, payload_json
            FROM audit_events
            WHERE action = ?
              AND target_type = 'queue_job' AND target_id = ?
            ORDER BY rowid DESC
            LIMIT 1
            """,
            (_SIDECAR_WORKER_PHASE_ACTION, job_id),
        ).fetchone()
        if phase_row is None:
            return None
        phase_payload = json_loads(phase_row["payload_json"], None)
        if (
            not isinstance(phase_payload, dict)
            or set(phase_payload)
            != {"schema", "job_type", "phase", "result"}
            or phase_payload.get("schema")
            != _SIDECAR_WORKER_PHASE_SCHEMA
            or phase_payload.get("job_type") != job_type
            or not isinstance(phase_payload.get("result"), dict)
            or phase_payload["result"].get("card_id") != card_id
        ):
            return None
        return {
            "kind": "sidecar_worker_phase",
            "event_id": str(phase_row["id"]),
            "card_id": card_id,
        }
    return None


def _process_job(
    root: Path,
    job: dict[str, Any],
    *,
    heartbeat: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    payload = json_loads(job.get("payload_json"), {})
    job_type = job["job_type"]
    if job_type == "scroll_event_ingested":
        return roll_due_scroll_segments(
            root,
            session_id=payload.get("session_id"),
            heartbeat=heartbeat,
            recover_pending_card_sidecars=False,
        )
    if job_type == "review_card_placement":
        return review_card_placement(
            root,
            card_id=str(payload["card_id"]),
            recover_pending_card_sidecars=False,
        )
    if job_type == "verify_book_integrity":
        return verify_book_integrity(root, book_id=str(payload["book_id"]), content_hash_value=payload.get("content_hash"))
    if job_type == "verify_segment_integrity":
        return verify_segment_integrity(root, segment_id=str(payload["segment_id"]), segment_hash=payload.get("segment_hash"))
    if job_type == "sync_card_sidecar":
        return sync_card_sidecar_job(root, card_id=str(payload["card_id"]))
    if job_type == "review_mempalace_import":
        raw_limit = payload.get("limit")
        return review_mempalace_import(
            root,
            import_id=str(payload.get("import_id") or ""),
            limit=(
                MAX_BACKLOG_RECONCILE_LIMIT
                if raw_limit is None
                else int(raw_limit)
            ),
            recover_pending_card_sidecars=False,
        )
    return {"ok": True, "skipped": True, "reason": "unknown_job_type", "job_type": job_type}


def run_worker_pass(
    root: Path,
    *,
    roles: list[str] | None = None,
    limit: int = 50,
    maintenance: bool = True,
) -> dict[str, Any]:
    budget = {
        "limit": WORKER_SIDECAR_INTENT_LIMIT,
        "used": 0,
        "remaining": WORKER_SIDECAR_INTENT_LIMIT,
    }
    with _card_sidecar_intent_reconciliation_budget(budget):
        result = _run_worker_pass_with_sidecar_intent_budget(
            root,
            roles=roles,
            limit=limit,
            maintenance=maintenance,
        )
        result["sidecar_intent_budget"] = (
            _worker_sidecar_intent_budget_snapshot(budget)
        )
        return result


def _run_worker_pass_with_sidecar_intent_budget(
    root: Path,
    *,
    roles: list[str] | None = None,
    limit: int = 50,
    maintenance: bool = True,
) -> dict[str, Any]:
    init_db(root, recover_pending_card_sidecars=False)
    config = load_config(root)
    lease_seconds = max(30, int(config.get("queues", {}).get("worker_lease_seconds", 3600)))
    worker_id = unique_id("worker")
    role_set = set(roles or []) or None
    processed: list[dict[str, Any]] = []
    deferred_job_ids: set[str] = set()
    reclaimed_expired_jobs = 0
    for pass_index in range(max(1, int(limit))):
        conn = connect(root)
        try:
            conn.execute("BEGIN IMMEDIATE")
            if pass_index == 0:
                reclaimed_expired_jobs += _reclaim_expired_leases(
                    conn,
                    role_set,
                )
            job = _claim_job(
                conn,
                role_set,
                lease_owner=worker_id,
                lease_seconds=lease_seconds,
                deferred_job_ids=deferred_job_ids,
            )
            conn.commit()
        finally:
            conn.close()
        if job is None:
            break
        lease = _JobLease(root, str(job["id"]), worker_id, lease_seconds)
        renewer = _JobLeaseRenewer(lease)
        lease_token = _CURRENT_JOB_LEASE.set(lease)
        renewer.start()
        try:
            if job["job_type"] == "scroll_event_ingested":
                result = _process_job(root, job, heartbeat=lease.renew)
            else:
                # Preserve the small internal hook surface used by integrations
                # and tests that replace non-Scribe job processors.
                result = _process_job(root, job)
            renewer.stop()
            job_ok = bool(result.get("ok", True))
            retry_pending = bool(result.get("retry_pending"))
            job_status = (
                "pending"
                if retry_pending
                else "skipped"
                if result.get("skipped")
                else "succeeded"
                if job_ok
                else "failed"
            )
            conn = connect(root)
            try:
                if retry_pending:
                    _retry_owned_job(
                        conn,
                        job["id"],
                        lease_owner=worker_id,
                        lease_seconds=lease_seconds,
                        result=result,
                    )
                else:
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
            if retry_pending:
                deferred_job_ids.add(str(job["id"]))
        except Exception as exc:
            renewer.stop()
            conn = connect(root)
            try:
                conn.execute("BEGIN IMMEDIATE")
                post_commit_authority = (
                    _running_job_post_commit_authority(conn, job)
                )
                retry_authority_is_owned = bool(
                    post_commit_authority is not None
                    and _job_lease_is_owned(
                        conn,
                        str(job["id"]),
                        lease_owner=worker_id,
                    )
                )
                if retry_authority_is_owned:
                    retry_result = {
                        "ok": False,
                        "reason": POST_COMMIT_EXCEPTION_RETRY_REASON,
                        "retry_pending": True,
                        "post_commit_authority": post_commit_authority,
                        "exception_sha256": content_hash(
                            f"{type(exc).__name__}:{exc}"
                        ),
                    }
                    _retry_owned_job(
                        conn,
                        job["id"],
                        lease_owner=worker_id,
                        lease_seconds=lease_seconds,
                        result=retry_result,
                    )
                else:
                    post_commit_authority = None
                    _finish_job(
                        conn,
                        job["id"],
                        status="failed",
                        error=str(exc),
                        lease_owner=worker_id,
                    )
                conn.commit()
            finally:
                conn.close()
            if post_commit_authority is not None:
                processed.append(
                    {
                        "job_id": job["id"],
                        "role": job["role"],
                        "job_type": job["job_type"],
                        "status": "pending",
                        "ok": False,
                        "result": retry_result,
                    }
                )
                deferred_job_ids.add(str(job["id"]))
            else:
                processed.append(
                    {
                        "job_id": job["id"],
                        "role": job["role"],
                        "job_type": job["job_type"],
                        "status": "failed",
                        "ok": False,
                        "error": str(exc),
                    }
                )
        finally:
            renewer.stop()
            _CURRENT_JOB_LEASE.reset(lease_token)
    maintenance_result: dict[str, Any] = {}
    if maintenance:
        maintenance_result["sidecars"] = drain_card_sidecar_outbox(
            root,
            limit=50,
            reconcile_intents=False,
        )
        maintenance_result["sidecar_intents"] = (
            _reconcile_card_sidecar_intent_maintenance(root)
        )
        maintenance_result["failed_sidecar_jobs"] = (
            _recover_failed_post_phase_sidecar_jobs(root)
        )
        maintenance_result["decay"] = decay_graph_routes(
            root,
            limit=50,
            recover_pending_card_sidecars=False,
        )
        maintenance_result["tiering"] = apply_storage_tiering(
            root,
            dry_run=False,
            limit=50,
            recover_pending_card_sidecars=False,
        )
        maintenance_result.update(
            _run_conflict_maintenance(
                root,
                recover_pending_card_sidecars=False,
            )
        )
    retry_pending_count = sum(
        1
        for item in processed
        if item.get("status") == PENDING_JOB_STATUS
        and isinstance(item.get("result"), dict)
        and item["result"].get("retry_pending") is True
    )
    processed_ok = all(
        item.get("ok", False)
        or (
            item.get("status") == PENDING_JOB_STATUS
            and isinstance(item.get("result"), dict)
            and item["result"].get("retry_pending") is True
        )
        for item in processed
    )
    maintenance_ok = all(
        bool(value["ok"])
        for value in maintenance_result.values()
        if isinstance(value, dict) and "ok" in value
    )
    return {
        "ok": processed_ok and maintenance_ok,
        "worker_id": worker_id,
        "lease_seconds": lease_seconds,
        "reclaimed_expired_jobs": reclaimed_expired_jobs,
        "retry_pending_count": retry_pending_count,
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
    retry_pending = 0
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
            retry_pending += int(result.get("retry_pending_count", 0))
            if maintenance_due:
                maintenance_passes += 1
                next_maintenance_at = time.monotonic() + maintenance_interval
            if result.get("ok") is False:
                return {
                    "ok": False,
                    "reason": "worker_pass_failed",
                    "passes": passes,
                    "processed_count": processed,
                    "retry_pending_count": retry_pending,
                    "maintenance_passes": maintenance_passes,
                    "maintenance_interval_seconds": maintenance_interval,
                    "failed_pass": result,
                }
            if limit and passes >= limit:
                return {
                    "ok": True,
                    "passes": passes,
                    "processed_count": processed,
                    "retry_pending_count": retry_pending,
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
        queue_columns = {
            str(row["name"])
            for row in conn.execute(
                "PRAGMA table_info(queue_jobs)"
            ).fetchall()
        }
        retry_markers = {
            key: conn.execute(
                "SELECT value FROM meta WHERE key = ?",
                (key,),
            ).fetchone()
            for key in (
                QUEUE_RETRY_PENDING_BACKFILL_META_KEY,
                QUEUE_RETRY_ORDER_BACKFILL_META_KEY,
            )
        }
        retry_authority_triggers_ready = (
            {"retry_pending", "retry_order"}.issubset(queue_columns)
            and _queue_retry_authority_triggers_ready(conn)
        )
        retry_order_counter_ready = (
            retry_authority_triggers_ready
            and _queue_retry_order_counter_ready(conn)
        )
        missing_retry_authority: list[str] = []
        for column in ("retry_pending", "retry_order"):
            if column not in queue_columns:
                missing_retry_authority.append(
                    f"queue_jobs.{column}"
                )
        for marker_key, marker_value in (
            (
                QUEUE_RETRY_PENDING_BACKFILL_META_KEY,
                QUEUE_RETRY_PENDING_BACKFILL_META_VALUE,
            ),
            (
                QUEUE_RETRY_ORDER_BACKFILL_META_KEY,
                QUEUE_RETRY_ORDER_BACKFILL_META_VALUE,
            ),
        ):
            marker = retry_markers[marker_key]
            if (
                marker is None
                or str(marker["value"]) != marker_value
            ):
                missing_retry_authority.append(marker_key)
        if not retry_order_counter_ready:
            missing_retry_authority.append(
                QUEUE_RETRY_ORDER_META_KEY
            )
        if (
            {"retry_pending", "retry_order"}.issubset(queue_columns)
            and not retry_authority_triggers_ready
        ):
            missing_retry_authority.append(
                "queue_jobs.retry_authority_triggers"
            )
        if missing_retry_authority:
            return {
                "ok": False,
                "initialized": True,
                "root": str(root),
                "reason": "schema_migration_required",
                "missing_schema_authority": missing_retry_authority,
                "checks": [
                    {
                        "name": "queue_retry_authority_ready",
                        "ok": False,
                        "missing": missing_retry_authority,
                    }
                ],
            }
        pending_jobs = conn.execute("SELECT count(*) AS n FROM queue_jobs WHERE status = 'pending'").fetchone()["n"]
        retry_pending_jobs = conn.execute(
            """
            SELECT count(*) AS n
            FROM queue_jobs
            WHERE status = 'pending' AND retry_pending = 1
            """
        ).fetchone()["n"]
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
            "retry_pending_jobs": retry_pending_jobs,
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
