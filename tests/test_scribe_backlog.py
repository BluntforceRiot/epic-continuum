from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import continuum.core.workers as worker_module
from continuum.core.config import default_config, write_config
from continuum.core.store import append_scroll_event, connect
from continuum.core.workers import run_worker_pass


def _root_with_threshold(base: str, *, threshold: int = 2) -> Path:
    root = Path(base) / "continuum"
    config = default_config()
    config["capture"]["roll_segments_every_events"] = threshold
    write_config(root, config)
    return root


def _append_events(root: Path, *, session_id: str, count: int) -> list[str]:
    return [
        append_scroll_event(
            root,
            session_id=session_id,
            event_type="message",
            role="user",
            content=f"Scribe backlog event {index}.",
        )["scribe_job_id"]
        for index in range(1, count + 1)
    ]


class ScribeBacklogTest(unittest.TestCase):
    def test_one_deduplicated_notification_drains_every_due_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _root_with_threshold(tmp, threshold=2)
            job_ids = _append_events(root, session_id="six-event-backlog", count=6)

            self.assertEqual(len(set(job_ids)), 1)
            result = run_worker_pass(root, roles=["scribe"], limit=1, maintenance=False)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["processed_count"], 1)
            scribe_result = result["processed"][0]["result"]
            self.assertEqual(scribe_result["batches_processed"], 3)
            self.assertEqual(scribe_result["rolled_count"], 3)
            self.assertFalse(scribe_result["drain_limited"])
            self.assertEqual(scribe_result["continuations"], [])

            conn = connect(root)
            try:
                segments = conn.execute(
                    """
                    SELECT start_seq, end_seq
                    FROM scroll_segments
                    WHERE session_id = 'six-event-backlog'
                    ORDER BY start_seq
                    """
                ).fetchall()
                scribe_jobs = conn.execute(
                    """
                    SELECT id, status
                    FROM queue_jobs
                    WHERE role = 'scribe' AND job_type = 'scroll_event_ingested'
                    ORDER BY created_at, id
                    """
                ).fetchall()
            finally:
                conn.close()

            self.assertEqual(
                [(row["start_seq"], row["end_seq"]) for row in segments],
                [(1, 2), (3, 4), (5, 6)],
            )
            self.assertEqual([(row["id"], row["status"]) for row in scribe_jobs], [(job_ids[0], "succeeded")])

            # A repeated pass is an idempotent no-op: it neither duplicates
            # segments nor manufactures a notification after the frontier.
            repeated = run_worker_pass(root, roles=["scribe"], limit=1, maintenance=False)
            self.assertTrue(repeated["ok"], repeated)
            self.assertEqual(repeated["processed_count"], 0)

    def test_bounded_drain_leaves_one_durable_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _root_with_threshold(tmp, threshold=2)
            original_job_ids = _append_events(root, session_id="bounded-backlog", count=6)
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE queue_jobs SET priority = 7 WHERE id = ?",
                    (original_job_ids[0],),
                )
                conn.commit()
            finally:
                conn.close()

            with patch("continuum.core.workers.MAX_SCRIBE_SEGMENT_BATCHES_PER_RUN", 2):
                first = run_worker_pass(root, roles=["scribe"], limit=1, maintenance=False)

                self.assertTrue(first["ok"], first)
                first_result = first["processed"][0]["result"]
                self.assertEqual(first_result["batches_processed"], 2)
                self.assertEqual(first_result["rolled_count"], 2)
                self.assertTrue(first_result["drain_limited"])
                self.assertEqual(len(first_result["continuations"]), 1)
                continuation_job_id = first_result["continuations"][0]["continuation_job_id"]
                self.assertNotEqual(continuation_job_id, original_job_ids[0])

                conn = connect(root)
                try:
                    mid_segments = conn.execute(
                        "SELECT start_seq, end_seq FROM scroll_segments ORDER BY start_seq"
                    ).fetchall()
                    mid_jobs = conn.execute(
                        """
                        SELECT id, status, priority
                        FROM queue_jobs
                        WHERE role = 'scribe' AND job_type = 'scroll_event_ingested'
                        ORDER BY created_at, id
                        """
                    ).fetchall()
                finally:
                    conn.close()

                self.assertEqual(
                    [(row["start_seq"], row["end_seq"]) for row in mid_segments],
                    [(1, 2), (3, 4)],
                )
                self.assertEqual(
                    {
                        row["id"]: (row["status"], row["priority"])
                        for row in mid_jobs
                    },
                    {
                        original_job_ids[0]: ("succeeded", 7),
                        continuation_job_id: ("pending", 7),
                    },
                )

                second = run_worker_pass(root, roles=["scribe"], limit=1, maintenance=False)

            self.assertTrue(second["ok"], second)
            self.assertEqual(second["processed_count"], 1)
            self.assertEqual(second["processed"][0]["job_id"], continuation_job_id)
            self.assertEqual(second["processed"][0]["result"]["rolled_count"], 1)

            conn = connect(root)
            try:
                final_segments = conn.execute(
                    "SELECT start_seq, end_seq FROM scroll_segments ORDER BY start_seq"
                ).fetchall()
                final_states = conn.execute(
                    """
                    SELECT status, count(*) AS n
                    FROM queue_jobs
                    WHERE role = 'scribe' AND job_type = 'scroll_event_ingested'
                    GROUP BY status
                    """
                ).fetchall()
            finally:
                conn.close()

            self.assertEqual(
                [(row["start_seq"], row["end_seq"]) for row in final_segments],
                [(1, 2), (3, 4), (5, 6)],
            )
            self.assertEqual({row["status"]: row["n"] for row in final_states}, {"succeeded": 2})

    def test_normal_65_event_drain_keeps_retry_beside_continuation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _root_with_threshold(tmp, threshold=1)
            source_job_id = _append_events(
                root,
                session_id="normal-65-event-retry-transfer",
                count=65,
            )[0]

            first = run_worker_pass(
                root,
                roles=["scribe"],
                limit=1,
                maintenance=False,
            )

            self.assertTrue(first["ok"], first)
            self.assertEqual(first["retry_pending_count"], 1)
            first_attempt = first["processed"][0]
            self.assertEqual(first_attempt["job_id"], source_job_id)
            self.assertEqual(first_attempt["status"], "skipped")
            self.assertTrue(first_attempt["result"]["retry_transferred"])
            continuation_job_id = first_attempt["result"]["retry_job_id"]
            self.assertNotEqual(continuation_job_id, source_job_id)

            conn = connect(root)
            try:
                mid_rows = {
                    str(row["id"]): dict(row)
                    for row in conn.execute(
                        """
                        SELECT id, status, retry_pending, retry_order,
                               dedupe_key
                        FROM queue_jobs
                        WHERE id IN (?, ?)
                        """,
                        (source_job_id, continuation_job_id),
                    ).fetchall()
                }
                segment_count = int(
                    conn.execute(
                        """
                        SELECT count(*) AS n
                        FROM scroll_segments
                        WHERE session_id = ?
                        """,
                        ("normal-65-event-retry-transfer",),
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(segment_count, 64)
            self.assertEqual(
                (
                    mid_rows[source_job_id]["status"],
                    mid_rows[source_job_id]["retry_pending"],
                    mid_rows[source_job_id]["dedupe_key"],
                ),
                (
                    "skipped",
                    0,
                    mid_rows[continuation_job_id]["dedupe_key"],
                ),
            )
            self.assertEqual(
                mid_rows[source_job_id]["retry_order"],
                0,
            )
            self.assertEqual(
                (
                    mid_rows[continuation_job_id]["status"],
                    mid_rows[continuation_job_id]["retry_pending"],
                ),
                ("pending", 1),
            )
            self.assertGreater(
                mid_rows[continuation_job_id]["retry_order"],
                0,
            )
            self.assertIsNotNone(
                mid_rows[continuation_job_id]["dedupe_key"]
            )

            preview = worker_module.reconcile_worker_backlog(
                root,
                dry_run=True,
            )
            reconciled = worker_module.reconcile_worker_backlog(
                root,
                dry_run=False,
            )
            self.assertEqual(preview["queue"]["redundant_before"], 0)
            self.assertEqual(reconciled["queue"]["changed"], 0)

            second = run_worker_pass(
                root,
                roles=["scribe"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(second["ok"], second)
            self.assertEqual(
                second["processed"][0]["job_id"],
                continuation_job_id,
            )
            self.assertEqual(
                second["processed"][0]["status"],
                "succeeded",
            )

            final_service = worker_module.serve_workers(
                root,
                roles=["scribe"],
                limit=1,
                interval_seconds=0.1,
                maintenance_interval_seconds=3600.0,
                maintenance_on_start=False,
            )
            self.assertTrue(final_service["ok"], final_service)

            conn = connect(root)
            try:
                final_rows = {
                    str(row["id"]): dict(row)
                    for row in conn.execute(
                        """
                        SELECT id, status, retry_pending, retry_order
                        FROM queue_jobs
                        WHERE id IN (?, ?)
                        """,
                        (source_job_id, continuation_job_id),
                    ).fetchall()
                }
                final_segment_count = int(
                    conn.execute(
                        """
                        SELECT count(*) AS n
                        FROM scroll_segments
                        WHERE session_id = ?
                        """,
                        ("normal-65-event-retry-transfer",),
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(final_segment_count, 65)
            self.assertEqual(final_rows[source_job_id]["status"], "skipped")
            self.assertEqual(
                final_rows[continuation_job_id]["status"],
                "succeeded",
            )
            for job_id in (source_job_id, continuation_job_id):
                self.assertEqual(final_rows[job_id]["retry_pending"], 0)
                self.assertEqual(final_rows[job_id]["retry_order"], 0)

    def test_continuation_refresh_preserves_transferred_retry_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _root_with_threshold(tmp, threshold=1)
            session_id = "scribe-transferred-refresh-authority"
            source_job_id = _append_events(
                root,
                session_id=session_id,
                count=65,
            )[0]

            first = run_worker_pass(
                root,
                roles=["scribe"],
                limit=1,
                maintenance=False,
            )

            self.assertTrue(first["ok"], first)
            self.assertEqual(first["processed_count"], 1)
            self.assertEqual(first["retry_pending_count"], 1)
            first_attempt = first["processed"][0]
            self.assertEqual(first_attempt["job_id"], source_job_id)
            self.assertEqual(first_attempt["status"], "skipped")
            self.assertTrue(first_attempt["result"]["retry_transferred"])
            continuation_job_id = first_attempt["result"]["retry_job_id"]

            conn = connect(root)
            try:
                before = dict(
                    conn.execute(
                        """
                        SELECT status, retry_pending, retry_order, error_json,
                               dedupe_key
                        FROM queue_jobs
                        WHERE id = ?
                        """,
                        (continuation_job_id,),
                    ).fetchone()
                )
            finally:
                conn.close()
            before_receipt = json.loads(before["error_json"])
            self.assertEqual(before["status"], "pending")
            self.assertEqual(before["retry_pending"], 1)
            self.assertGreater(before["retry_order"], 0)
            self.assertIsNotNone(before["dedupe_key"])
            self.assertTrue(
                before_receipt["result"]["retry_transferred"]
            )
            self.assertEqual(
                before_receipt["result"]["retry_source_job_id"],
                source_job_id,
            )
            self.assertEqual(
                before_receipt["result"]["retry_job_id"],
                continuation_job_id,
            )

            real_enqueue_job = worker_module.enqueue_job
            with patch.object(
                worker_module,
                "enqueue_job",
                wraps=real_enqueue_job,
            ) as enqueue_spy:
                refreshed = worker_module._ensure_scribe_continuation(
                    root,
                    session_id=session_id,
                    threshold=1,
                )

            self.assertEqual(
                refreshed["continuation_job_id"],
                continuation_job_id,
            )
            self.assertTrue(
                any(
                    call.kwargs.get("replace_pending") is True
                    for call in enqueue_spy.call_args_list
                ),
                enqueue_spy.call_args_list,
            )
            conn = connect(root)
            try:
                after = dict(
                    conn.execute(
                        """
                        SELECT status, retry_pending, retry_order, error_json,
                               dedupe_key
                        FROM queue_jobs
                        WHERE id = ?
                        """,
                        (continuation_job_id,),
                    ).fetchone()
                )
                pending_ids = [
                    str(row["id"])
                    for row in conn.execute(
                        """
                        SELECT id
                        FROM queue_jobs
                        WHERE status = 'pending' AND dedupe_key = ?
                        ORDER BY id
                        """,
                        (before["dedupe_key"],),
                    ).fetchall()
                ]
            finally:
                conn.close()
            self.assertEqual(after, before)
            self.assertEqual(pending_ids, [continuation_job_id])

            claimed = run_worker_pass(
                root,
                roles=["scribe"],
                limit=2,
                maintenance=False,
            )
            idle = run_worker_pass(
                root,
                roles=["scribe"],
                limit=2,
                maintenance=False,
            )

            self.assertTrue(claimed["ok"], claimed)
            self.assertEqual(claimed["processed_count"], 1, claimed)
            self.assertEqual(
                claimed["processed"][0]["job_id"],
                continuation_job_id,
            )
            self.assertEqual(
                claimed["processed"][0]["status"],
                "succeeded",
            )
            self.assertTrue(idle["ok"], idle)
            self.assertEqual(idle["processed_count"], 0, idle)

            conn = connect(root)
            try:
                final = dict(
                    conn.execute(
                        """
                        SELECT status, attempt_count, retry_pending, retry_order
                        FROM queue_jobs
                        WHERE id = ?
                        """,
                        (continuation_job_id,),
                    ).fetchone()
                )
                segment_count = int(
                    conn.execute(
                        """
                        SELECT count(*) AS n
                        FROM scroll_segments
                        WHERE session_id = ?
                        """,
                        (session_id,),
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(
                final,
                {
                    "status": "succeeded",
                    "attempt_count": 1,
                    "retry_pending": 0,
                    "retry_order": 0,
                },
            )
            self.assertEqual(segment_count, 65)

    def test_existing_pending_continuation_is_refreshed_to_parent_priority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _root_with_threshold(tmp, threshold=2)
            running_job = _append_events(root, session_id="priority-refresh", count=6)[0]
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE queue_jobs SET priority = 7 WHERE id = ?",
                    (running_job,),
                )
                conn.commit()
            finally:
                conn.close()

            original_ensure = worker_module._ensure_scribe_continuation
            concurrent_job_ids: list[str] = []

            def append_before_continuation(
                continuation_root: Path,
                *,
                session_id: str,
                threshold: int,
            ) -> dict[str, object]:
                concurrent_job_ids.append(
                    append_scroll_event(
                        continuation_root,
                        session_id=session_id,
                        event_type="message",
                        role="user",
                        content=(
                            "A concurrent append creates a default-priority "
                            "pending generation."
                        ),
                    )["scribe_job_id"]
                )
                return original_ensure(
                    continuation_root,
                    session_id=session_id,
                    threshold=threshold,
                )

            with (
                patch(
                    "continuum.core.workers.MAX_SCRIBE_SEGMENT_BATCHES_PER_RUN",
                    2,
                ),
                patch.object(
                    worker_module,
                    "_ensure_scribe_continuation",
                    side_effect=append_before_continuation,
                ),
            ):
                result = run_worker_pass(
                    root,
                    roles=["scribe"],
                    limit=1,
                    maintenance=False,
                )

            self.assertTrue(result["ok"], result)
            self.assertEqual(len(concurrent_job_ids), 1)
            pending_job = concurrent_job_ids[0]
            self.assertNotEqual(pending_job, running_job)
            self.assertEqual(
                result["processed"][0]["result"]["continuations"][0][
                    "continuation_job_id"
                ],
                pending_job,
            )
            conn = connect(root)
            try:
                refreshed = conn.execute(
                    """
                    SELECT id, status, priority
                    FROM queue_jobs
                    WHERE id IN (?, ?)
                    ORDER BY id
                    """,
                    (running_job, pending_job),
                ).fetchall()
            finally:
                conn.close()
            self.assertEqual(
                {
                    row["id"]: (row["status"], row["priority"])
                    for row in refreshed
                },
                {
                    running_job: ("succeeded", 7),
                    pending_job: ("pending", 7),
                },
            )

    def test_pending_generation_waits_for_same_dedupe_running_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _root_with_threshold(tmp, threshold=2)
            running_job = _append_events(root, session_id="concurrent-backlog", count=2)[0]

            conn = connect(root)
            try:
                conn.execute(
                    """
                    UPDATE queue_jobs
                    SET status = 'running', lease_owner = 'still-active',
                        lease_expires_at = '2999-01-01T00:00:00+00:00'
                    WHERE id = ?
                    """,
                    (running_job,),
                )
                conn.commit()
            finally:
                conn.close()

            pending_job = append_scroll_event(
                root,
                session_id="concurrent-backlog",
                event_type="message",
                role="user",
                content="A concurrent append creates the next Scribe generation.",
            )["scribe_job_id"]
            self.assertNotEqual(pending_job, running_job)

            deferred = run_worker_pass(root, roles=["scribe"], limit=1, maintenance=False)
            self.assertTrue(deferred["ok"], deferred)
            self.assertEqual(deferred["processed_count"], 0)

            conn = connect(root)
            try:
                states = conn.execute(
                    "SELECT id, status FROM queue_jobs WHERE id IN (?, ?)",
                    (running_job, pending_job),
                ).fetchall()
                conn.execute(
                    """
                    UPDATE queue_jobs
                    SET status = 'succeeded', finished_at = updated_at,
                        lease_owner = NULL, lease_expires_at = NULL
                    WHERE id = ?
                    """,
                    (running_job,),
                )
                conn.commit()
            finally:
                conn.close()

            self.assertEqual(
                {row["id"]: row["status"] for row in states},
                {running_job: "running", pending_job: "pending"},
            )
            resumed = run_worker_pass(root, roles=["scribe"], limit=1, maintenance=False)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["processed"][0]["job_id"], pending_job)

    def test_long_scribe_drain_renews_the_worker_lease_between_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = _root_with_threshold(tmp, threshold=2)
            _append_events(root, session_id="lease-renewal", count=6)

            with patch.object(worker_module, "_heartbeat_job", wraps=worker_module._heartbeat_job) as heartbeat:
                result = run_worker_pass(root, roles=["scribe"], limit=1, maintenance=False)

            self.assertTrue(result["ok"], result)
            # The Scribe processor renews before and after each segment window;
            # the final owned-job finish heartbeat is in addition to these calls.
            self.assertGreaterEqual(heartbeat.call_count, 4)


if __name__ == "__main__":
    unittest.main()
