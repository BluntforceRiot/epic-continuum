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
    def test_conflict_escalation_lock_preserves_committed_base_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "memory"
            init_db(root)
            with closing(connect(root)) as conn:
                for summary in ("Decision: use the blue route.", "Decision: do not use the blue route."):
                    create_card(conn, root=root, card_type="decision", title="Route choice",
                                summary=summary, source_refs=[], topics=["routes"])
                conn.execute("DELETE FROM queue_jobs")
                conn.commit()
            original_detect = workers.detect_conflicts
            original_finish = workers._ConflictWorkBudget.finish_transaction
            detected = []
            calls = []
            finishes = []

            def commit_crosses_deadline(budget):
                original_finish(budget)
                finishes.append(1)
                if len(finishes) == 1:
                    budget.finished = budget.deadline + 0.001
                    budget.time_exhausted = True

            def escalation_once_busy(*args, **kwargs):
                calls.append(kwargs.get("card_id"))
                if len(calls) == 2:
                    raise sqlite3.OperationalError("database is locked")
                result = original_detect(*args, **kwargs)
                detected.append(result)
                return result

            with (
                patch.object(workers._ConflictWorkBudget, "finish_transaction", commit_crosses_deadline),
                patch.object(workers, "detect_conflicts", side_effect=escalation_once_busy),
                patch.object(workers, "_sync_worker_card_sidecars", return_value={
                    "ok": False, "synced": 0, "failed": 2,
                    "failures": [{"error": "OperationalError: disk I/O error"}],
                }),
                patch.object(workers.time, "sleep") as sleep,
            ):
                result = workers.serve_workers(root, limit=1)
            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "worker_pass_failed")
            self.assertEqual(len(calls), 3)
            self.assertIsNone(calls[0])
            self.assertTrue(calls[1])
            self.assertEqual(calls[1], calls[2])
            self.assertFalse(detected[0]["ok"])
            self.assertEqual(result["failed_pass"]["maintenance"]["conflicts"], detected[0])
            sleep.assert_called_once_with(5)
            with closing(connect(root)) as conn:
                self.assertEqual(conn.execute("SELECT count(*) FROM card_sidecar_outbox").fetchone()[0], 2)

    def test_conflict_signal_lock_preserves_both_scan_results(self):
        base = {"ok": False, "scan": {"anchor_card_id": "card-fixture"},
                "continuation": {"required": True, "requires_larger_budget": True}}
        escalated = {**base, "reason": "permanent-sidecar-failure"}
        with (
            patch.object(workers, "detect_conflicts", side_effect=[base, escalated]) as detect,
            patch.object(workers, "_record_conflict_review_signal", side_effect=[
                sqlite3.OperationalError("database is locked"), {"ok": True},
            ]) as signal,
            patch.object(workers.time, "sleep") as sleep,
        ):
            result = workers._run_conflict_maintenance(Path("unused-root"))
        self.assertEqual(result["conflicts"], base)
        self.assertEqual(result["conflict_escalation"], escalated)
        self.assertEqual(detect.call_count, 2)
        self.assertEqual(signal.call_count, 2)
        sleep.assert_called_once_with(5)

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
            original_init = workers.init_db
            original_pass = workers.run_worker_pass
            init_calls = []

            def init_once_busy(*args, **kwargs):
                init_calls.append(1)
                if len(init_calls) == 1:
                    raise sqlite3.OperationalError("database is locked")
                return original_init(*args, **kwargs)

            def run_pass(root, *, roles, limit, maintenance):
                calls.append(maintenance)
                return original_pass(root, roles=roles, limit=limit, maintenance=maintenance)

            with (
                patch.object(workers, "init_db", side_effect=init_once_busy),
                patch.object(workers, "run_worker_pass", side_effect=run_pass),
                patch.object(workers.time, "sleep"),
            ):
                result = workers.serve_workers(Path(tmp), limit=2, maintenance_interval_seconds=3600)
            self.assertEqual(calls, [True, False])
            self.assertTrue(result["ok"])
            self.assertEqual(result["passes"], 2)
            self.assertEqual(result["maintenance_passes"], 1)

    def test_later_claim_lock_preserves_completed_job_results(self):
        for job_ok in (False, True):
            with self.subTest(job_ok=job_ok), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "memory"
                job_id = self.make_job(root)
                original_claim = workers._claim_job
                claims = []

                def claim_once_busy(*args, **kwargs):
                    claims.append(1)
                    if len(claims) == 2:
                        raise sqlite3.OperationalError("database is locked")
                    return original_claim(*args, **kwargs)

                with (
                    patch.object(workers, "_process_job", return_value={"ok": True},
                                 side_effect=None if job_ok else sqlite3.OperationalError("disk I/O error")) as process,
                    patch.object(workers, "_claim_job", side_effect=claim_once_busy),
                    patch.object(workers.time, "sleep") as sleep,
                ):
                    result = workers.serve_workers(root, limit=1, maintenance_on_start=False)
                self.assertEqual(result["ok"], job_ok, result)
                self.assertEqual(result["passes"], 1)
                self.assertEqual(result["processed_count"], 1)
                self.assertEqual(process.call_count, 1)
                sleep.assert_called_once_with(5)
                job = self.read_job(root, job_id)
                self.assertEqual(job["status"], "succeeded" if job_ok else "failed")
                self.assertEqual(job["attempt_count"], 1)
                if not job_ok:
                    self.assertEqual(result["reason"], "worker_pass_failed")
                    self.assertEqual(result["failed_pass"]["processed"][0]["error"], "disk I/O error")

    def test_each_maintenance_lock_preserves_completed_job_results(self):
        maintenance_units = (
            "drain_card_sidecar_outbox",
            "_reconcile_card_sidecar_intent_maintenance",
            "_recover_failed_post_phase_sidecar_jobs",
            "decay_graph_routes",
            "apply_storage_tiering",
            "detect_conflicts",
        )
        for unit in maintenance_units:
            for job_ok in (False, True):
                with self.subTest(unit=unit, job_ok=job_ok), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp) / "memory"
                    job_id = self.make_job(root)
                    with (
                        patch.object(workers, "_process_job", return_value={"ok": True},
                                     side_effect=None if job_ok else sqlite3.OperationalError("disk I/O error")) as process,
                        patch.object(workers, unit, side_effect=[
                            sqlite3.OperationalError("database is locked"), {"ok": True}
                        ]) as maintenance,
                        patch.object(workers.time, "sleep") as sleep,
                    ):
                        result = workers.serve_workers(root, limit=1)
                    self.assertEqual(result["ok"], job_ok, result)
                    self.assertEqual(result["processed_count"], 1)
                    self.assertEqual(result["passes"], 1)
                    self.assertEqual(result["maintenance_passes"], 1)
                    self.assertEqual(process.call_count, 1)
                    self.assertEqual(maintenance.call_count, 2)
                    sleep.assert_called_once_with(5)
                    job = self.read_job(root, job_id)
                    self.assertEqual(job["status"], "succeeded" if job_ok else "failed")
                    self.assertEqual(job["attempt_count"], 1)
                    if not job_ok:
                        self.assertEqual(result["reason"], "worker_pass_failed")
                        self.assertEqual(result["failed_pass"]["processed"][0]["error"], "disk I/O error")

    def test_later_maintenance_lock_preserves_prior_maintenance_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "memory"
            with (
                patch.object(workers, "drain_card_sidecar_outbox", return_value={"ok": False, "failed": 1}) as drain,
                patch.object(workers, "_reconcile_card_sidecar_intent_maintenance", side_effect=[
                    sqlite3.OperationalError("database is locked"), {"ok": True}
                ]),
                patch.object(workers.time, "sleep") as sleep,
            ):
                result = workers.serve_workers(root, limit=1)
            self.assertFalse(result["ok"], result)
            self.assertFalse(result["failed_pass"]["maintenance"]["sidecars"]["ok"])
            self.assertEqual(drain.call_count, 1)
            sleep.assert_called_once_with(5)

    def test_failure_persistence_lock_keeps_prior_failed_results_and_rolls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "memory"
            self.make_job(root)
            self.make_job(root)
            original_finish = workers._finish_job
            finishes = []

            def finish_once_busy(*args, **kwargs):
                finishes.append(1)
                result = original_finish(*args, **kwargs)
                if len(finishes) == 2:
                    raise sqlite3.OperationalError("database is locked")
                return result

            with (
                patch.object(workers, "_process_job", side_effect=sqlite3.OperationalError("disk I/O error")) as process,
                patch.object(workers, "_finish_job", side_effect=finish_once_busy),
                patch.object(workers.time, "sleep") as sleep,
            ):
                result = workers.serve_workers(root, limit=1, maintenance_on_start=False)
            self.assertFalse(result["ok"], result)
            self.assertEqual(result["processed_count"], 2)
            self.assertEqual(process.call_count, 2)
            self.assertEqual(len(finishes), 3)
            sleep.assert_called_once_with(5)
            for attempt in result["failed_pass"]["processed"]:
                self.assertEqual(attempt["status"], "failed")
                self.assertEqual(attempt["error"], "disk I/O error")
                job = self.read_job(root, attempt["job_id"])
                self.assertEqual(job["status"], "failed")
                self.assertEqual(job["attempt_count"], 1)

    def test_claim_retry_does_not_double_count_rolled_back_reclaims(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "memory"
            job_id = self.make_job(root)
            with closing(connect(root)) as conn:
                conn.execute(
                    "UPDATE queue_jobs SET status='running', preemptible=0, "
                    "lease_owner='expired-worker', lease_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?",
                    (job_id,),
                )
                conn.commit()
            with (
                patch.object(workers, "_claim_job", side_effect=[sqlite3.OperationalError("database is locked"), None]),
                patch.object(workers.time, "sleep") as sleep,
            ):
                result = workers.run_worker_pass(root, maintenance=False)
            self.assertFalse(result["ok"], result)
            self.assertEqual(result["processed_count"], 1)
            self.assertEqual(result["reclaimed_expired_jobs"], 1)
            self.assertEqual(result["expired_non_preemptible_failure_count"], 1)
            self.assertEqual(self.read_job(root, job_id)["status"], "failed")
            sleep.assert_called_once_with(5)

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

    def test_busy_lost_lease_uses_durable_authority(self):
        cases = (
            ("failed_reclaim", "terminal_failure", False),
            ("non_preemptible_expired", "running_non_preemptible_unrecoverable", False),
            ("missing", "missing", False),
            ("live_transferred", "running_live_owner", True),
            ("preemptible_expired", "running_preemptible_reclaimable", True),
            ("pending_reclaim", "pending_recoverable", True),
            ("completed", "terminal_success", True),
        )
        for transition, authority_state, authority_ok in cases:
            with self.subTest(transition=transition), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "memory"
                job_id = self.make_job(root)
                reclaimed = []

                def change_authority_then_busy(*args, **kwargs):
                    with closing(connect(root)) as conn:
                        if transition == "missing":
                            conn.execute("DELETE FROM queue_jobs WHERE id=?", (job_id,))
                        elif transition == "live_transferred":
                            conn.execute("UPDATE queue_jobs SET lease_owner='another-worker' WHERE id=?", (job_id,))
                        elif transition == "completed":
                            self.assertTrue(workers._finish_job(conn, job_id, status="succeeded", result={"ok": True}))
                        else:
                            conn.execute(
                                "UPDATE queue_jobs SET preemptible=?, lease_expires_at='2000-01-01T00:00:00+00:00' WHERE id=?",
                                (0 if transition in {"failed_reclaim", "non_preemptible_expired"} else 1, job_id),
                            )
                            if transition in {"failed_reclaim", "pending_reclaim"}:
                                workers._reclaim_expired_leases(conn, public_results=reclaimed)
                        conn.commit()
                    raise sqlite3.OperationalError("database is locked")

                with patch.object(workers, "_process_job", side_effect=change_authority_then_busy) as process:
                    result = workers.run_worker_pass(root, limit=8, maintenance=False)
                self.assertEqual(result["ok"], authority_ok, result)
                self.assertEqual(result["processed_count"], 1)
                self.assertEqual(result["incomplete_attempt_count"], 1)
                self.assertEqual(result["retry_pending_count"], 0)
                self.assertEqual(process.call_count, 1)
                attempt = result["processed"][0]
                self.assertEqual(attempt["status"], "incomplete")
                self.assertFalse(attempt["attempt_completed"])
                self.assertEqual(attempt["reason"], "worker_lease_lost")
                authority = attempt["authoritative_job"]
                self.assertEqual(authority["authority_state"], authority_state)
                self.assertEqual(authority["authority_ok"], authority_ok)
                if transition == "failed_reclaim":
                    self.assertEqual(len(reclaimed), 1)
                    self.assertEqual(reclaimed[0]["reason"], "non_preemptible_worker_lease_expired")
                    self.assertEqual(self.read_job(root, job_id)["status"], "failed")
                elif transition == "live_transferred":
                    self.assertEqual(self.read_job(root, job_id)["lease_owner"], "another-worker")
                elif transition == "missing":
                    self.assertFalse(authority["exists"])
