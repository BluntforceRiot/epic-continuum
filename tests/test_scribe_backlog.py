from __future__ import annotations

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
