from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from continuum.core.config import default_config, write_config
from continuum.core.store import connect, enqueue_job, init_db
from continuum.core.workers import memory_health


class WorkerHealthContractTest(unittest.TestCase):
    def _segmentation_root(
        self,
        tmp: str,
        *,
        sessions: dict[str, int],
        threshold: int = 200,
        segments: tuple[tuple[str, int, int], ...] = (),
    ) -> Path:
        root = Path(tmp) / "continuum"
        config = default_config()
        config["capture"]["roll_segments_every_events"] = threshold
        write_config(root, config)
        init_db(root)
        conn = connect(root)
        try:
            # Direct catalog fixtures keep queue/capture work out of a read-only
            # health test; each session still has the production sequence shape.
            conn.executemany(
                """
                INSERT INTO scroll_events
                    (id, session_id, seq, event_type, role, content, content_hash, created_at)
                VALUES (?, ?, ?, 'message', 'user', 'test event', 'fixture', ?)
                """,
                (
                    (f"event-{session}-{seq}", session, seq, "2026-07-10T12:00:00+00:00")
                    for session, count in sessions.items()
                    for seq in range(1, count + 1)
                ),
            )
            conn.executemany(
                """
                INSERT INTO scroll_segments
                    (id, session_id, start_seq, end_seq, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    (
                        f"segment-{index}", session, start, end,
                        "2026-07-10T12:00:00+00:00", "2026-07-10T12:00:00+00:00",
                    )
                    for index, (session, start, end) in enumerate(segments)
                ),
            )
            conn.commit()
        finally:
            conn.close()
        return root

    def _segmentation_check(self, result: dict) -> dict:
        return next(check for check in result["checks"] if check["name"] == "scroll_segmentation_lag_reasonable")

    def test_many_short_sessions_are_normal_tails_not_segmentation_lag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._segmentation_root(tmp, sessions={f"short-{index}": 3 for index in range(500)})
            result = memory_health(root)

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["unsegmented_scroll_events"], 1500)
        self.assertEqual(result["segmentation_lag_events"], 0)
        self.assertEqual(result["segmentation_due_events"], 0)
        self.assertEqual(result["segmentation_due_sessions"], 0)
        self.assertEqual(result["below_threshold_tail_events"], 1500)
        self.assertEqual(result["unsegmented_before_frontier_events"], 0)
        self.assertEqual(result["segmentation_roll_threshold"], 200)
        check = self._segmentation_check(result)
        self.assertTrue(check["ok"])
        self.assertEqual(check["unsegmented_events"], 1500)
        for field in (
            "segmentation_lag_events", "segmentation_due_events", "segmentation_due_sessions",
            "below_threshold_tail_events", "unsegmented_before_frontier_events", "segmentation_roll_threshold",
        ):
            self.assertEqual(check[field], result[field])

    def test_due_classification_uses_configured_threshold_and_existing_frontier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._segmentation_root(
                tmp,
                threshold=4,
                sessions={"below": 3, "exact": 4, "above": 5, "rolled": 11},
                segments=(("rolled", 1, 4), ("rolled", 5, 8)),
            )
            result = memory_health(root)

        self.assertTrue(self._segmentation_check(result)["ok"])
        self.assertEqual(result["unsegmented_scroll_events"], 15)
        self.assertEqual(result["segmentation_due_sessions"], 2)
        self.assertEqual(result["segmentation_due_events"], 9)
        self.assertEqual(result["below_threshold_tail_events"], 6)
        self.assertEqual(result["segmentation_lag_events"], 9)
        self.assertEqual(result["unsegmented_before_frontier_events"], 0)
        self.assertEqual(result["segmentation_roll_threshold"], 4)

    def test_actionable_backlog_retains_exact_thousand_event_warning(self) -> None:
        for count, expected_ok in ((999, True), (1000, False)):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as tmp:
                root = self._segmentation_root(tmp, sessions={"due": count, "normal": 199})
                result = memory_health(root)
                self.assertEqual(self._segmentation_check(result)["ok"], expected_ok)
                self.assertEqual(result["segmentation_due_sessions"], 1)
                self.assertEqual(result["segmentation_due_events"], count)
                self.assertEqual(result["segmentation_lag_events"], count)
                self.assertEqual(result["below_threshold_tail_events"], 199)

    def test_uncovered_rows_behind_frontier_are_not_hidden_as_normal_tails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._segmentation_root(
                tmp,
                sessions={"gap": 1002},
                segments=(("gap", 1001, 1001),),
            )
            result = memory_health(root)

        self.assertFalse(self._segmentation_check(result)["ok"])
        self.assertEqual(result["unsegmented_scroll_events"], 1001)
        self.assertEqual(result["unsegmented_before_frontier_events"], 1000)
        self.assertEqual(result["segmentation_lag_events"], 1000)
        self.assertEqual(result["segmentation_due_events"], 0)
        self.assertEqual(result["below_threshold_tail_events"], 1)

    def test_empty_and_fully_segmented_catalog_have_zero_segmentation_lag(self) -> None:
        for sessions, segments in (({}, ()), ({"rolled": 4}, (("rolled", 1, 4),))):
            with self.subTest(sessions=sessions), tempfile.TemporaryDirectory() as tmp:
                root = self._segmentation_root(tmp, sessions=sessions, segments=segments)
                result = memory_health(root)
                self.assertTrue(self._segmentation_check(result)["ok"])
                for field in (
                    "unsegmented_scroll_events", "segmentation_lag_events", "segmentation_due_sessions",
                    "segmentation_due_events", "below_threshold_tail_events", "unsegmented_before_frontier_events",
                ):
                    self.assertEqual(result[field], 0)

    def test_sequence_gap_does_not_inflate_actual_due_event_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._segmentation_root(tmp, sessions={"gap": 200})
            conn = connect(root)
            try:
                conn.execute("DELETE FROM scroll_events WHERE seq < 200")
                conn.commit()
            finally:
                conn.close()
            result = memory_health(root)

        self.assertEqual(result["unsegmented_scroll_events"], 1)
        self.assertEqual(result["segmentation_due_sessions"], 1)
        self.assertEqual(result["segmentation_due_events"], 1)
        self.assertEqual(result["segmentation_lag_events"], 1)
        self.assertEqual(result["below_threshold_tail_events"], 0)

    def test_running_job_heartbeat_uses_precise_non_service_name(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                running_id = enqueue_job(
                    conn,
                    role="scribe",
                    job_type="health_running",
                    priority=100,
                    payload={},
                )
                terminal_id = enqueue_job(
                    conn,
                    role="scribe",
                    job_type="health_terminal",
                    priority=100,
                    payload={},
                )
                conn.execute(
                    """
                    UPDATE queue_jobs
                    SET status = 'running',
                        lease_owner = 'worker-health-contract',
                        heartbeat_at = '2026-07-10T12:34:56+00:00',
                        lease_expires_at = '2099-01-01T00:00:00+00:00'
                    WHERE id = ?
                    """,
                    (running_id,),
                )
                conn.execute(
                    """
                    UPDATE queue_jobs
                    SET status = 'succeeded', heartbeat_at = '2099-01-01T00:00:00+00:00'
                    WHERE id = ?
                    """,
                    (terminal_id,),
                )
                conn.commit()
            finally:
                conn.close()

            result = memory_health(root)

            expected = "2026-07-10T12:34:56+00:00"
            self.assertEqual(result["latest_running_job_heartbeat_at"], expected)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["running_jobs"], 1)
            self.assertEqual(result["stale_running_jobs"], 0)
            self.assertNotIn("latest_worker_heartbeat_at", result)

    def test_expired_running_job_makes_memory_health_unhealthy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                running_id = enqueue_job(
                    conn,
                    role="scribe",
                    job_type="expired_running_health",
                    priority=100,
                    payload={},
                )
                conn.execute(
                    """
                    UPDATE queue_jobs
                    SET status = 'running',
                        lease_owner = 'expired-worker',
                        heartbeat_at = '2000-01-01T00:00:00+00:00',
                        lease_expires_at = '2000-01-01T00:00:01+00:00'
                    WHERE id = ?
                    """,
                    (running_id,),
                )
                conn.commit()
            finally:
                conn.close()

            result = memory_health(root)

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["running_jobs"], 1)
            self.assertEqual(result["stale_running_jobs"], 1)
            running_check = next(
                check for check in result["checks"] if check["name"] == "running_jobs_current"
            )
            self.assertFalse(running_check["ok"])

    def test_unowned_running_job_makes_memory_health_unhealthy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                running_id = enqueue_job(
                    conn,
                    role="scribe",
                    job_type="unowned_running_health",
                    priority=100,
                    payload={},
                )
                conn.execute(
                    """
                    UPDATE queue_jobs
                    SET status = 'running',
                        lease_owner = NULL,
                        heartbeat_at = '2026-07-10T12:34:56+00:00',
                        lease_expires_at = '2099-01-01T00:00:00+00:00'
                    WHERE id = ?
                    """,
                    (running_id,),
                )
                conn.commit()
            finally:
                conn.close()

            result = memory_health(root)

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["running_jobs"], 1)
            self.assertEqual(result["stale_running_jobs"], 1)
            running_check = next(
                check for check in result["checks"] if check["name"] == "running_jobs_current"
            )
            self.assertFalse(running_check["ok"])

    def test_malformed_pending_job_timestamp_makes_memory_health_unhealthy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                pending_id = enqueue_job(
                    conn,
                    role="scribe",
                    job_type="malformed_pending_health",
                    priority=100,
                    payload={},
                )
                enqueue_job(
                    conn,
                    role="scribe",
                    job_type="valid_pending_health",
                    priority=100,
                    payload={},
                )
                conn.execute(
                    "UPDATE queue_jobs SET created_at = '2451545' WHERE id = ?",
                    (pending_id,),
                )
                conn.commit()
            finally:
                conn.close()

            result = memory_health(root)

            self.assertFalse(result["ok"], result)
            self.assertFalse(result["oldest_pending_job_timestamp_valid"])
            self.assertEqual(result["invalid_pending_job_timestamps"], 1)
            queue_check = next(
                check for check in result["checks"] if check["name"] == "queue_age_reasonable"
            )
            self.assertFalse(queue_check["ok"])
            self.assertFalse(queue_check["timestamp_valid"])
            self.assertEqual(queue_check["invalid_pending_job_timestamps"], 1)


if __name__ == "__main__":
    unittest.main()
