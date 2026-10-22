from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from continuum.core import workers
from continuum.core.store import connect, create_card, enqueue_job, init_db, mark_card_sidecar_outbox


class WorkerLockRecoveryTest(unittest.TestCase):
    def test_busy_retry_transfers_to_existing_public_dedupe_successor(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "memory"
            init_db(root)
            with closing(connect(root)) as conn:
                source_id = enqueue_job(
                    conn, role="archivist", job_type="busy-dedupe-fixture",
                    priority=1, payload={}, dedupe_key="busy-dedupe-fixture",
                )
                conn.commit()
            successors = []

            def process_then_busy(*args, **kwargs):
                with closing(connect(root)) as conn:
                    successors.append(enqueue_job(
                        conn, role="archivist", job_type="busy-dedupe-fixture",
                        priority=1, payload={}, dedupe_key="busy-dedupe-fixture",
                    ))
                    conn.commit()
                raise sqlite3.OperationalError("database is locked")

            with patch.object(workers, "_process_job", side_effect=process_then_busy):
                first = workers.run_worker_pass(root, limit=8, maintenance=False)
            self.assertTrue(first["ok"], first)
            self.assertEqual(first["processed_count"], 1)
            self.assertEqual(first["retry_pending_count"], 1)
            self.assertEqual(len(successors), 1)
            attempt = first["processed"][0]
            self.assertEqual(attempt["status"], "skipped")
            self.assertTrue(attempt["result"]["retry_transferred"])
            self.assertEqual(attempt["result"]["retry_job_id"], successors[0])
            self.assertEqual(self.read_job(root, source_id)["status"], "skipped")
            self.assertEqual(self.read_job(root, successors[0])["status"], "pending")
            self.assertTrue(workers.run_worker_pass(root, limit=8, maintenance=False)["ok"])
            self.assertEqual(self.read_job(root, successors[0])["status"], "skipped")

    def make_job(self, root: Path) -> str:
        init_db(root)
        conn = connect(root)
        try:
            job_id = enqueue_job(conn, role="scribe", job_type="lock-recovery-fixture", priority=100, payload={})
            conn.commit()
            return job_id
        finally:
            conn.close()

    def read_job(self, root: Path, job_id: str) -> dict:
        conn = connect(root)
        try:
            return dict(conn.execute("SELECT * FROM queue_jobs WHERE id = ?", (job_id,)).fetchone())
        finally:
            conn.close()

    def test_busy_classifier_uses_primary_code_and_rejects_other_errors(self):
        for code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED, 261, 517, 262):
            with self.subTest(code=code):
                exc = sqlite3.OperationalError("opaque")
                exc.sqlite_errorcode = code
                self.assertTrue(workers._is_worker_sqlite_busy(exc))
        exc = sqlite3.OperationalError("database is locked")
        exc.sqlite_errorcode = sqlite3.SQLITE_READONLY
        self.assertFalse(workers._is_worker_sqlite_busy(exc))
        for exc in (ValueError("database is locked"), sqlite3.OperationalError("no such table: database is locked")):
            self.assertFalse(workers._is_worker_sqlite_busy(exc))
        for message in ("database is locked", "database table is locked", "database table is locked: queue_jobs"):
            self.assertTrue(workers._is_worker_sqlite_busy(sqlite3.OperationalError(message)))

    def test_retry_backoff_is_capped_and_no_error_payload_is_logged(self):
        failures = [sqlite3.OperationalError("database is locked") for _ in range(7)]
        with (
            patch.object(workers.time, "sleep") as sleep,
            patch.object(workers.logging.getLogger(workers.__name__), "warning") as warning,
            patch.object(workers, "run_worker_pass", side_effect=[*failures, {"ok": True}]) as action,
        ):
            self.assertEqual(workers._retry_worker_sqlite_busy(action), {"ok": True})
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [5, 10, 20, 40, 60, 60, 60])
        self.assertEqual(warning.call_count, 7)
        self.assertTrue(all(len(call.args) == 2 for call in warning.call_args_list))

    def test_nonlock_errors_and_operator_interrupt_are_not_swallowed(self):
        for error in (sqlite3.OperationalError("disk I/O error"), ValueError("bad configuration"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__), patch.object(workers.time, "sleep") as sleep:
                def fail():
                    raise error
                with self.assertRaises(type(error)):
                    workers._retry_worker_sqlite_busy(fail)
                sleep.assert_not_called()

    def test_service_retries_lock_without_skipping_maintenance_or_counting_failure_as_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = []

            def run_pass(root, *, roles, limit, maintenance):
                calls.append(maintenance)
                if len(calls) == 1:
                    raise sqlite3.OperationalError("database is locked")
                return {"ok": True, "processed_count": 0}

            with patch.object(workers, "run_worker_pass", side_effect=run_pass), patch.object(workers.time, "sleep"):
                result = workers.serve_workers(Path(tmp), limit=2, maintenance_interval_seconds=3600)
            self.assertEqual(calls, [True, True, False])
            self.assertTrue(result["ok"])
            self.assertEqual(result["passes"], 2)
            self.assertEqual(result["maintenance_passes"], 1)

    def test_real_sqlite_writer_lock_releases_and_same_service_drains_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "memory"
            job_id = self.make_job(root)
            lock_seen = threading.Event()
            released = threading.Event()
            result = []
            failures = []
            blocker = connect(root)
            blocker.execute("BEGIN IMMEDIATE")

            def retry_sleep(seconds):
                lock_seen.set()
                if not released.wait(15):
                    raise TimeoutError("test writer was not released")

            def run_service():
                try:
                    result.append(workers.serve_workers(root, limit=1, maintenance_on_start=False))
                except BaseException as exc:
                    failures.append(exc)

            with patch.object(workers.time, "sleep", side_effect=retry_sleep):
                thread = threading.Thread(target=run_service, daemon=True)
                thread.start()
                try:
                    self.assertTrue(lock_seen.wait(15), "worker did not reach contention retry")
                    self.assertTrue(thread.is_alive())
                    with self.assertRaisesRegex(RuntimeError, "already running"):
                        workers.serve_workers(root, limit=1)
                finally:
                    blocker.rollback()
                    blocker.close()
                    released.set()
                    thread.join(20)
            self.assertFalse(thread.is_alive())
            self.assertEqual(failures, [])
            self.assertTrue(result[0]["ok"])
            job = self.read_job(root, job_id)
            self.assertEqual(job["status"], "skipped")
            self.assertEqual(job["attempt_count"], 1)

    def test_processing_lock_keeps_same_job_pending_then_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "memory"
            job_id = self.make_job(root)
            with patch.object(workers, "_process_job", side_effect=sqlite3.OperationalError("database is locked")):
                first = workers.run_worker_pass(root, limit=1, maintenance=False)
            job = self.read_job(root, job_id)
            self.assertTrue(first["ok"])
            self.assertEqual(job["status"], "pending")
            self.assertIsNone(job["lease_owner"])
            self.assertIsNone(job["finished_at"])
            self.assertIn("sqlite_busy", job["error_json"])
            second = workers.run_worker_pass(root, limit=1, maintenance=False)
            self.assertTrue(second["ok"])
            self.assertEqual(self.read_job(root, job_id)["attempt_count"], 2)
            self.assertEqual(self.read_job(root, job_id)["status"], "skipped")

    def test_finalization_lock_and_release_lock_do_not_fail_or_duplicate_job(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "memory"
            job_id = self.make_job(root)
            retry = workers._retry_owned_job
            retries = []

            def retry_once_locked(*args, **kwargs):
                retries.append(1)
                if len(retries) == 1:
                    raise sqlite3.OperationalError("database is locked")
                return retry(*args, **kwargs)

            with (
                patch.object(workers, "_finish_owned_job", side_effect=sqlite3.OperationalError("database is locked")),
                patch.object(workers, "_retry_owned_job", side_effect=retry_once_locked),
                patch.object(workers.time, "sleep") as sleep,
            ):
                first = workers.run_worker_pass(root, limit=1, maintenance=False)
            self.assertTrue(first["ok"])
            sleep.assert_called_once_with(5)
            self.assertEqual(self.read_job(root, job_id)["status"], "pending")
            second = workers.run_worker_pass(root, limit=1, maintenance=False)
            self.assertTrue(second["ok"])
            conn = connect(root)
            try:
                self.assertEqual(conn.execute("SELECT count(*) FROM queue_jobs").fetchone()[0], 1)
            finally:
                conn.close()

    def test_real_job_error_still_fails_and_stops_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "memory"
            job_id = self.make_job(root)
            with patch.object(workers, "_process_job", side_effect=sqlite3.OperationalError("disk I/O error")):
                result = workers.serve_workers(root, limit=1, maintenance_on_start=False)
            self.assertFalse(result["ok"])
            self.assertEqual(self.read_job(root, job_id)["status"], "failed")

    def test_real_card_effect_is_not_duplicated_after_finalization_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "memory"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(conn, root=root, card_type="note", title="Lock recovery",
                                      summary="Preserve this memory exactly.", source_refs=[])
                job_id = enqueue_job(conn, role="librarian", job_type="review_card_placement", priority=70,
                                     payload={"card_id": card_id})
                conn.commit()
            finally:
                conn.close()
            with patch.object(workers, "_finish_owned_job", side_effect=sqlite3.OperationalError("database is locked")):
                first = workers.run_worker_pass(root, limit=1, maintenance=False)
            self.assertTrue(first["ok"])
            self.assertEqual(self.read_job(root, job_id)["status"], "pending")
            second = workers.run_worker_pass(root, limit=1, maintenance=False)
            self.assertTrue(second["ok"])
            self.assertEqual(self.read_job(root, job_id)["status"], "succeeded")
            conn = connect(root)
            try:
                self.assertEqual(conn.execute("SELECT summary FROM cards WHERE id=?", (card_id,)).fetchone()[0],
                                 "Preserve this memory exactly.")
                self.assertEqual(conn.execute("SELECT count(*) FROM cards").fetchone()[0], 1)
                self.assertEqual(conn.execute(
                    "SELECT count(*) FROM audit_events WHERE action=? AND target_id=?",
                    (workers._WORKER_EFFECT_ACTION, job_id),
                ).fetchone()[0], 1)
            finally:
                conn.close()

    def test_reconciliation_lock_is_not_converted_to_permanent_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "memory"
            init_db(root)
            with patch.object(workers, "reconcile_card_sidecar_write_intents", side_effect=sqlite3.OperationalError("database is locked")):
                with self.assertRaises(sqlite3.OperationalError):
                    workers._reconcile_card_sidecar_intent_maintenance(root)

    def test_sidecar_lock_result_retries_but_mixed_or_permanent_failures_do_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            for errors, retryable in ((["database is locked"], True),
                                      (["database is locked", "disk I/O error"], False),
                                      (["disk I/O error"], False)):
                result = {"ok": False, "failed": len(errors), "failures": [{"error": e} for e in errors]}
                with self.subTest(errors=errors), patch.object(workers, "sync_card_sidecars_after_commit", return_value=result):
                    if retryable:
                        with self.assertRaises(sqlite3.OperationalError):
                            workers._sync_worker_card_sidecars(Path(tmp), ["card-fixture"])
                    else:
                        actual = workers._sync_worker_card_sidecars(Path(tmp), ["card-fixture"])
                        self.assertFalse(actual["ok"])
                        self.assertEqual(actual["failures"], result["failures"])

    def test_closed_nested_store_lock_wrappers_and_mixed_errors(self):
        def nested(errors):
            return {"ok": False, "failed": 1, "failures": [{
                "error": "Card sidecar intent reconciliation did not complete cleanly",
                "intent_reconciliation": {"failures": [{"error": e} for e in errors]},
            }]}

        lock_errors = ["Card sidecar intent postflight scan failed: OperationalError: database is locked"]
        self.assertTrue(workers._worker_sidecar_failures_are_busy(nested(lock_errors)))
        self.assertFalse(workers._worker_sidecar_failures_are_busy(nested(lock_errors + ["disk I/O error"])))
        self.assertFalse(workers._worker_sidecar_failures_are_busy(nested([])))
        self.assertFalse(workers._worker_sidecar_failures_are_busy({"failures": [{"error": "unknown wrapper: database is locked"}]}))
        self.assertFalse(workers._worker_sidecar_failures_are_busy({"failures": [{"error": "ValueError: database is locked"}]}))
        for prefix in ("OperationalError: ",
                       "Card sidecar intent postflight scan failed: OperationalError: ",
                       "Card sidecar reconciliation retry authority could not be recorded: OperationalError: "):
            self.assertTrue(workers._worker_sidecar_failures_are_busy({"failures": [{"error": prefix + "database is locked"}]}))
            self.assertFalse(workers._worker_sidecar_failures_are_busy({"failures": [{"error": prefix + "disk I/O error"}]}))
        cycle = {"failures": []}
        cycle["failures"].append({"error": "Card sidecar intent reconciliation did not complete cleanly", "intent_reconciliation": cycle})
        self.assertFalse(workers._worker_sidecar_failures_are_busy(cycle))
        result = {"failed": 1, "failures": [{"error": "database is locked"}, {"error": "database is locked"}]}
        self.assertTrue(workers._worker_sidecar_failures_are_busy(result))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            init_db(root)
            with patch.object(workers, "reconcile_card_sidecar_write_intents", return_value=nested(lock_errors)):
                with self.assertRaises(sqlite3.OperationalError):
                    workers._reconcile_card_sidecar_intent_maintenance(root)

    def test_maintenance_sidecar_lock_result_retries_in_same_service(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(conn, root=root, card_type="note", title="Maintenance retry",
                                      summary="Do not lose this note.", source_refs=[])
                mark_card_sidecar_outbox(conn, [card_id], reason="lock-test")
                conn.commit()
            finally:
                conn.close()
            original_sync = workers.sync_card_sidecars_after_commit
            calls = []

            def sync_once_busy(*args, **kwargs):
                calls.append(1)
                if len(calls) == 1:
                    return {"ok": False, "failed": 1, "failures": [{"error": "database is locked"}]}
                return original_sync(*args, **kwargs)

            with patch.object(workers, "sync_card_sidecars_after_commit", side_effect=sync_once_busy), patch.object(workers.time, "sleep") as sleep:
                result = workers.serve_workers(root, limit=1)
            self.assertTrue(result["ok"])
            self.assertGreaterEqual(len(calls), 2)
            sleep.assert_called_once_with(5)
            conn = connect(root)
            try:
                self.assertEqual(conn.execute("SELECT count(*) FROM card_sidecar_outbox").fetchone()[0], 0)
                self.assertEqual(conn.execute("SELECT summary FROM cards WHERE id=?", (card_id,)).fetchone()[0],
                                 "Do not lose this note.")
            finally:
                conn.close()

    def test_real_sidecar_write_lock_recovers_without_terminal_failed_effect(self):
        for hold_seconds in (7, 12):
            with self.subTest(hold_seconds=hold_seconds):
                self._check_real_sidecar_lock(hold_seconds)

    def _check_real_sidecar_lock(self, hold_seconds):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "memory"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(conn, root=root, card_type="note", title="Sidecar lock",
                                      summary="Keep this note unchanged.", source_refs=[])
                job_id = enqueue_job(conn, role="librarian", job_type="review_card_placement", priority=70,
                                     payload={"card_id": card_id})
                conn.commit()
            finally:
                conn.close()
            original_sync = workers._sync_worker_card_sidecars
            ready = threading.Event()
            failures = []

            def hold_writer():
                blocker = connect(root)
                try:
                    blocker.execute("BEGIN IMMEDIATE")
                    ready.set()
                    threading.Event().wait(hold_seconds)
                except BaseException as exc:
                    failures.append(exc)
                finally:
                    blocker.rollback()
                    blocker.close()

            def locked_sync(*args, **kwargs):
                blocker_thread = threading.Thread(target=hold_writer, daemon=True)
                blocker_thread.start()
                try:
                    self.assertTrue(ready.wait(10))
                    return original_sync(*args, **kwargs)
                finally:
                    blocker_thread.join(15)

            with patch.object(workers, "_sync_worker_card_sidecars", side_effect=locked_sync):
                first = workers.serve_workers(root, limit=1, maintenance_on_start=False)
            self.assertEqual(failures, [])
            self.assertTrue(first["ok"])
            self.assertEqual(self.read_job(root, job_id)["status"], "pending")
            second = workers.serve_workers(root, limit=1, maintenance_on_start=False)
            self.assertTrue(second["ok"])
            self.assertEqual(self.read_job(root, job_id)["status"], "succeeded")
            conn = connect(root)
            try:
                self.assertEqual(conn.execute("SELECT summary FROM cards WHERE id=?", (card_id,)).fetchone()[0],
                                 "Keep this note unchanged.")
                self.assertEqual(conn.execute(
                    "SELECT count(*) FROM audit_events WHERE action=? AND target_id=?",
                    (workers._WORKER_EFFECT_ACTION, job_id),
                ).fetchone()[0], 1)
            finally:
                conn.close()

    def test_lock_past_lease_expiry_yields_to_normal_reclaim_without_service_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "memory"
            job_id = self.make_job(root)
            retry = workers._retry_owned_job
            calls = []

            def expired_retry(conn, *args, **kwargs):
                calls.append(1)
                if len(calls) == 1:
                    raise sqlite3.OperationalError("database is locked")
                conn.execute("UPDATE queue_jobs SET lease_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?", (job_id,))
                conn.commit()
                return retry(conn, *args, **kwargs)

            with (
                patch.object(workers, "_process_job", side_effect=sqlite3.OperationalError("database is locked")),
                patch.object(workers, "_retry_owned_job", side_effect=expired_retry),
                patch.object(workers.time, "sleep"),
            ):
                first = workers.serve_workers(root, limit=1, maintenance_on_start=False)
            self.assertTrue(first["ok"])
            self.assertEqual(self.read_job(root, job_id)["status"], "running")
            second = workers.serve_workers(root, limit=1, maintenance_on_start=False)
            self.assertTrue(second["ok"])
            self.assertEqual(self.read_job(root, job_id)["status"], "skipped")
            self.assertEqual(self.read_job(root, job_id)["attempt_count"], 2)

    def test_lock_retry_does_not_overwrite_reassigned_lease(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "memory"
            job_id = self.make_job(root)
            retry = workers._retry_owned_job

            def reassigned_retry(conn, *args, **kwargs):
                conn.execute("UPDATE queue_jobs SET lease_owner='another-worker' WHERE id=?", (job_id,))
                conn.commit()
                return retry(conn, *args, **kwargs)

            with (
                patch.object(workers, "_process_job", side_effect=sqlite3.OperationalError("database is locked")),
                patch.object(workers, "_retry_owned_job", side_effect=reassigned_retry),
            ):
                result = workers.serve_workers(root, limit=1, maintenance_on_start=False)
            self.assertTrue(result["ok"])
            job = self.read_job(root, job_id)
            self.assertEqual(job["status"], "running")
            self.assertEqual(job["lease_owner"], "another-worker")
