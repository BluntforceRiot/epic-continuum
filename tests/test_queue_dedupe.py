from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum.core.store import (
    append_scroll_event,
    connect,
    create_card,
    enqueue_job,
    ingest_file,
    init_db,
    record_project_state,
    roll_scroll_segment,
    sync_card_sidecars_after_commit,
)
from continuum.core.writer_claim import claim_writer
from continuum.core.workers import run_worker_pass


class QueueDedupeTest(unittest.TestCase):
    def test_expired_running_job_is_superseded_when_same_dedupe_is_pending(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                expired = enqueue_job(
                    conn,
                    role="scribe",
                    job_type="dedupe_lease_test",
                    priority=100,
                    payload={"generation": 1},
                    dedupe_key="session:lease-test",
                )
                conn.execute(
                    """
                    UPDATE queue_jobs
                    SET status = 'running', lease_owner = 'dead-worker',
                        lease_expires_at = '2000-01-01T00:00:00+00:00'
                    WHERE id = ?
                    """,
                    (expired,),
                )
                replacement = enqueue_job(
                    conn,
                    role="scribe",
                    job_type="dedupe_lease_test",
                    priority=100,
                    payload={"generation": 2},
                    dedupe_key="session:lease-test",
                )
                conn.commit()
            finally:
                conn.close()

            result = run_worker_pass(root, roles=["scribe"], limit=2, maintenance=False)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["reclaimed_expired_jobs"], 1)
            conn = connect(root)
            try:
                rows = conn.execute(
                    "SELECT id, status, error_json FROM queue_jobs WHERE id IN (?, ?)",
                    (expired, replacement),
                ).fetchall()
            finally:
                conn.close()
            by_id = {row["id"]: row for row in rows}
            self.assertEqual(by_id[expired]["status"], "skipped")
            self.assertIn("expired_lease_superseded_by_pending_dedupe_job", by_id[expired]["error_json"])
            self.assertEqual(by_id[replacement]["status"], "skipped")

    def test_pending_dedupe_reuses_row_but_terminal_history_allows_a_new_job(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                first = enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_card_placement",
                    priority=70,
                    payload={"card_id": "card-alpha", "version": 1},
                    related_card_ids=["card-alpha"],
                    dedupe_key="card:card-alpha",
                )
                reused = enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_card_placement",
                    priority=70,
                    payload={"card_id": "card-alpha", "version": 2},
                    related_card_ids=["card-alpha"],
                    dedupe_key="card:card-alpha",
                )
                other_protocol = enqueue_job(
                    conn,
                    role="archivist",
                    job_type="sync_card_sidecar",
                    priority=25,
                    payload={"card_id": "card-alpha"},
                    related_card_ids=["card-alpha"],
                    dedupe_key="card:card-alpha",
                )
                conn.commit()

                self.assertEqual(reused, first)
                self.assertNotEqual(other_protocol, first)
                rows = conn.execute(
                    "SELECT id, payload_json, dedupe_key FROM queue_jobs ORDER BY id"
                ).fetchall()
                self.assertEqual(len(rows), 2)
                first_row = next(row for row in rows if row["id"] == first)
                self.assertIn('"version":1', first_row["payload_json"])
                self.assertNotIn("card-alpha", first_row["dedupe_key"])
                self.assertTrue(str(first_row["dedupe_key"]).startswith("queue_v1_"))

                conn.execute(
                    "UPDATE queue_jobs SET status = 'succeeded', finished_at = updated_at WHERE id = ?",
                    (first,),
                )
                replacement = enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_card_placement",
                    priority=70,
                    payload={"card_id": "card-alpha", "version": 3},
                    related_card_ids=["card-alpha"],
                    dedupe_key="card:card-alpha",
                )
                conn.commit()

                self.assertNotEqual(replacement, first)
                history = conn.execute(
                    """
                    SELECT id, status, dedupe_key
                    FROM queue_jobs
                    WHERE job_type = 'review_card_placement'
                    ORDER BY created_at, id
                    """
                ).fetchall()
                self.assertEqual(len(history), 2)
                self.assertEqual({row["status"] for row in history}, {"pending", "succeeded"})
                self.assertEqual(len({row["dedupe_key"] for row in history}), 1)
            finally:
                conn.close()

    def test_legacy_queue_schema_is_migrated_without_losing_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            catalog = root / "catalog"
            catalog.mkdir(parents=True)
            conn = sqlite3.connect(catalog / "catalog.sqlite3")
            try:
                conn.execute(
                    """
                    CREATE TABLE queue_jobs (
                        id TEXT PRIMARY KEY,
                        role TEXT NOT NULL,
                        job_type TEXT NOT NULL,
                        priority INTEGER NOT NULL DEFAULT 500,
                        status TEXT NOT NULL DEFAULT 'pending',
                        preemptible INTEGER NOT NULL DEFAULT 1,
                        attempt_count INTEGER NOT NULL DEFAULT 0,
                        error_json TEXT,
                        lease_owner TEXT,
                        lease_expires_at TEXT,
                        heartbeat_at TEXT,
                        related_card_ids_json TEXT NOT NULL DEFAULT '[]',
                        payload_json TEXT NOT NULL DEFAULT '{}',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        started_at TEXT,
                        finished_at TEXT
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO queue_jobs(
                        id, role, job_type, priority, status, preemptible,
                        related_card_ids_json, payload_json, created_at, updated_at
                    ) VALUES('legacy-job', 'scribe', 'scroll_event_ingested', 100, 'pending', 1, '[]', '{}', ?, ?)
                    """,
                    ("2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
                )
                conn.commit()
            finally:
                conn.close()

            claim_writer(root)
            init_db(root)

            conn = sqlite3.connect(catalog / "catalog.sqlite3")
            try:
                columns = {row[1] for row in conn.execute("PRAGMA table_info(queue_jobs)")}
                index_row = conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_queue_pending_dedupe_key'"
                ).fetchone()
                legacy_row = conn.execute(
                    "SELECT status, dedupe_key FROM queue_jobs WHERE id = 'legacy-job'"
                ).fetchone()
            finally:
                conn.close()

            self.assertIn("dedupe_key", columns)
            self.assertIsNotNone(index_row)
            self.assertIn("WHERE status = 'pending'", str(index_row[0]))
            self.assertEqual(legacy_row, ("pending", None))

    def test_routine_producers_use_stable_scope_and_project_state_gets_reviewed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first_event = append_scroll_event(
                root,
                session_id="queue-session",
                event_type="message",
                role="user",
                content="First queue signal.",
            )
            second_event = append_scroll_event(
                root,
                session_id="queue-session",
                event_type="message",
                role="user",
                content="Second queue signal.",
            )
            other_session = append_scroll_event(
                root,
                session_id="other-session",
                event_type="message",
                role="user",
                content="A different session has its own signal.",
            )
            self.assertEqual(first_event["scribe_job_id"], second_event["scribe_job_id"])
            self.assertNotEqual(first_event["scribe_job_id"], other_session["scribe_job_id"])

            segment = roll_scroll_segment(root, session_id="queue-session", start_seq=1, end_seq=2)
            source = Path(tmp) / "evidence.txt"
            source.write_text("Durable queue evidence.", encoding="utf-8")
            first_book = ingest_file(root, path=source)
            second_book = ingest_file(root, path=source)
            self.assertEqual(first_book["librarian_job_id"], second_book["librarian_job_id"])
            self.assertEqual(first_book["archivist_job_id"], second_book["archivist_job_id"])

            project_state = record_project_state(
                root,
                session_id="queue-session",
                agent_id="codex",
                project_id="continuum",
                objective="Keep worker queues bounded.",
            )
            self.assertTrue(project_state["librarian_job_id"])

            conn = connect(root)
            try:
                routine_ids = [
                    first_event["scribe_job_id"],
                    segment["librarian_job_id"],
                    segment["archivist_job_id"],
                    first_book["librarian_job_id"],
                    first_book["archivist_job_id"],
                    project_state["librarian_job_id"],
                ]
                placeholders = ", ".join("?" for _ in routine_ids)
                rows = conn.execute(
                    f"SELECT id, dedupe_key FROM queue_jobs WHERE id IN ({placeholders})",
                    routine_ids,
                ).fetchall()
                project_review = conn.execute(
                    """
                    SELECT payload_json
                    FROM queue_jobs
                    WHERE id = ? AND role = 'librarian' AND job_type = 'review_card_placement'
                    """,
                    (project_state["librarian_job_id"],),
                ).fetchone()
            finally:
                conn.close()

            self.assertEqual({row["id"] for row in rows}, set(routine_ids))
            self.assertTrue(all(row["dedupe_key"] for row in rows))
            self.assertIsNotNone(project_review)
            self.assertIn(project_state["card_id"], project_review["payload_json"])

    def test_repeated_sidecar_failure_keeps_one_pending_retry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="Sidecar retry",
                    summary="The same failed sidecar should have one pending retry.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()

            with patch("continuum.core.store.sync_card_sidecar", side_effect=OSError("simulated failure")):
                first = sync_card_sidecars_after_commit(root, [card_id])
                second = sync_card_sidecars_after_commit(root, [card_id])
            self.assertFalse(first["ok"])
            self.assertFalse(second["ok"])

            conn = connect(root)
            try:
                retry_rows = conn.execute(
                    """
                    SELECT id, dedupe_key
                    FROM queue_jobs
                    WHERE status = 'pending' AND job_type = 'sync_card_sidecar'
                    """
                ).fetchall()
            finally:
                conn.close()
            self.assertEqual(len(retry_rows), 1)
            self.assertTrue(retry_rows[0]["dedupe_key"])


if __name__ == "__main__":
    unittest.main()
