from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from continuum.core.store import connect, enqueue_job, init_db
from continuum.core.workers import memory_health


class WorkerHealthContractTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
