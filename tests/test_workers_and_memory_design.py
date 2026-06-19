from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum.core.config import default_config, write_config
from continuum.core.evals import run_memory_quality_evals
from continuum.core.store import (
    append_scroll_event,
    compile_context,
    connect_existing,
    create_card,
    init_db,
    ingest_file,
    roll_scroll_segment,
)
from continuum.core.workers import (
    apply_storage_tiering,
    decay_graph_routes,
    detect_conflicts,
    memory_health,
    prune_memory,
    run_worker_pass,
    verify_book_integrity,
    verify_segment_integrity,
)


class EpicContinuumWorkerDesignTest(unittest.TestCase):
    def test_worker_pass_reviews_cards_and_verifies_segment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            append_scroll_event(root, session_id="worker-flow", event_type="message", role="user", content="Aurora worker notes.")
            append_scroll_event(root, session_id="worker-flow", event_type="message", role="assistant", content="Decision: keep Aurora worker notes hot.")
            segment = roll_scroll_segment(root, session_id="worker-flow", start_seq=1, end_seq=2)

            result = run_worker_pass(root, limit=20, maintenance=False)

            self.assertGreaterEqual(result["processed_count"], 3)
            conn = connect_existing(root)
            try:
                card = conn.execute("SELECT status, shelf FROM cards WHERE id = ?", (segment["card_id"],)).fetchone()
                jobs = conn.execute("SELECT status, count(*) AS n FROM queue_jobs GROUP BY status").fetchall()
            finally:
                conn.close()
            self.assertEqual(card["status"], "active")
            self.assertTrue(card["shelf"])
            self.assertTrue(any(row["status"] == "succeeded" for row in jobs))

    def test_scoped_recall_and_reinforcement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            append_scroll_event(root, session_id="alpha", event_type="message", role="user", content="Alpha needs copper gasket work.")
            roll_scroll_segment(root, session_id="alpha", start_seq=1, end_seq=1)

            alpha_context = compile_context(root, session_id="alpha", query="copper gasket", token_budget=1200, card_scope="session")
            beta_context = compile_context(root, session_id="beta", query="copper gasket", token_budget=1200, card_scope="session")

            self.assertIn("copper gasket", alpha_context["context_text"])
            self.assertNotIn("copper gasket", beta_context["context_text"])
            conn = connect_existing(root)
            try:
                recalled = conn.execute("SELECT recall_count FROM cards WHERE session_id = 'alpha'").fetchone()["recall_count"]
            finally:
                conn.close()
            self.assertGreaterEqual(recalled, 1)

    def test_archivist_book_integrity_uses_original_bytes_for_non_utf8_ingests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            source = Path(tmp) / "binary-ish.bin"
            source.write_bytes(b"hello\xffworld\x00raw-bytes")

            result = ingest_file(root, path=source, title="Binaryish evidence")
            verified = verify_book_integrity(root, book_id=result["book_id"])

            self.assertTrue(verified["ok"], verified)
            self.assertTrue(verified["checked_original"])
            self.assertFalse(verified["checked_reader"])

    def test_segment_integrity_detects_tamper_and_failed_worker_marks_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            append_scroll_event(root, session_id="integrity", event_type="message", role="user", content="Original evidence line.")
            append_scroll_event(root, session_id="integrity", event_type="message", role="assistant", content="Original reply line.")
            segment = roll_scroll_segment(root, session_id="integrity", start_seq=1, end_seq=2)

            good = verify_segment_integrity(root, segment_id=segment["segment_id"])
            self.assertTrue(good["ok"], good)

            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            try:
                conn.execute(
                    "UPDATE scroll_events SET content = ? WHERE session_id = ? AND seq = 1",
                    ("Tampered evidence line.", "integrity"),
                )
                conn.commit()
            finally:
                conn.close()

            bad = verify_segment_integrity(root, segment_id=segment["segment_id"])
            self.assertFalse(bad["ok"], bad)
            self.assertEqual(bad["reason"], "scroll_event_hash_mismatch")

            result = run_worker_pass(root, limit=20, maintenance=False)
            self.assertFalse(result["ok"], result)
            conn = connect_existing(root)
            try:
                verify_job = conn.execute(
                    "SELECT status, error_json FROM queue_jobs WHERE job_type = 'verify_segment_integrity' ORDER BY updated_at DESC LIMIT 1"
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(verify_job["status"], "failed")
            self.assertIn("scroll_event_hash_mismatch", verify_job["error_json"])

    def test_worker_pass_reclaims_expired_running_job_lease(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            try:
                now = "2026-01-01T00:00:00+00:00"
                conn.execute(
                    """
                    INSERT INTO queue_jobs(
                        id, role, job_type, priority, status, preemptible, attempt_count,
                        error_json, lease_owner, lease_expires_at, heartbeat_at,
                        related_card_ids_json, payload_json, created_at, updated_at, started_at
                    )
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "job_expired",
                        "archivist",
                        "review_mempalace_import",
                        1,
                        "running",
                        1,
                        0,
                        None,
                        "dead-worker",
                        "2000-01-01T00:00:00+00:00",
                        "2000-01-01T00:00:00+00:00",
                        "[]",
                        json.dumps({"import_id": "legacy"}),
                        now,
                        now,
                        now,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            result = run_worker_pass(root, roles=["archivist"], limit=1, maintenance=False)

            self.assertEqual(result["reclaimed_expired_jobs"], 1)
            self.assertEqual(result["processed_count"], 1)
            conn = connect_existing(root)
            try:
                row = conn.execute("SELECT status, lease_owner, lease_expires_at, heartbeat_at, attempt_count FROM queue_jobs WHERE id = 'job_expired'").fetchone()
            finally:
                conn.close()
            self.assertEqual(row["status"], "succeeded")
            self.assertIsNone(row["lease_owner"])
            self.assertIsNone(row["lease_expires_at"])
            self.assertIsNotNone(row["heartbeat_at"])
            self.assertEqual(row["attempt_count"], 1)

    def test_worker_pass_does_not_finish_job_after_lease_owner_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            try:
                now = "2026-01-01T00:00:00+00:00"
                conn.execute(
                    """
                    INSERT INTO queue_jobs(
                        id, role, job_type, priority, status, preemptible, attempt_count,
                        error_json, related_card_ids_json, payload_json, created_at, updated_at
                    )
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "job_lease_stolen",
                        "archivist",
                        "review_mempalace_import",
                        1,
                        "pending",
                        1,
                        0,
                        None,
                        "[]",
                        json.dumps({"import_id": "lease-stolen"}),
                        now,
                        now,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            def steal_lease(_root: Path, job: dict) -> dict:
                stolen = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
                try:
                    stolen.execute(
                        "UPDATE queue_jobs SET lease_owner = ?, lease_expires_at = ? WHERE id = ?",
                        ("new-worker", "2099-01-01T00:00:00+00:00", job["id"]),
                    )
                    stolen.commit()
                finally:
                    stolen.close()
                return {"ok": True, "reviewed_import": "lease-stolen"}

            with patch("continuum.core.workers._process_job", side_effect=steal_lease):
                result = run_worker_pass(root, roles=["archivist"], limit=1, maintenance=False)

            self.assertFalse(result["ok"])
            self.assertIn("worker lease lost", result["processed"][0]["error"])
            conn = connect_existing(root)
            try:
                row = conn.execute("SELECT status, lease_owner, finished_at FROM queue_jobs WHERE id = 'job_lease_stolen'").fetchone()
            finally:
                conn.close()
            self.assertEqual(row["status"], "running")
            self.assertEqual(row["lease_owner"], "new-worker")
            self.assertIsNone(row["finished_at"])

    def test_prune_memory_requires_topic_or_explicit_global_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            conn.row_factory = sqlite3.Row
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="Global Prune Candidate",
                    summary="A low salience global prune candidate.",
                    source_refs=[],
                    topics=["Global"],
                    salience=0.1,
                )
                conn.commit()
            finally:
                conn.close()

            with self.assertRaisesRegex(ValueError, "requires a topic"):
                prune_memory(root, action="archive")

            result = prune_memory(root, action="archive", allow_global=True)
            self.assertEqual(result["card_ids"], [card_id])

    def test_route_decay_respects_minimum_interval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            append_scroll_event(root, session_id="decay-interval", event_type="message", role="user", content="Aurora route decay interval evidence.")
            segment = roll_scroll_segment(root, session_id="decay-interval", start_seq=1, end_seq=1)
            run_worker_pass(root, limit=10, maintenance=False)

            first = decay_graph_routes(root, limit=20, prune_threshold=99)
            second = decay_graph_routes(root, limit=20, prune_threshold=99)

            self.assertGreaterEqual(first["decayed"], 1)
            self.assertEqual(second["decayed"], 0)
            conn = connect_existing(root)
            try:
                card = conn.execute("SELECT recall_count FROM cards WHERE id = ?", (segment["card_id"],)).fetchone()
                edge = conn.execute("SELECT last_decay_at FROM graph_edges WHERE last_decay_at IS NOT NULL LIMIT 1").fetchone()
            finally:
                conn.close()
            self.assertEqual(card["recall_count"], 0)
            self.assertIsNotNone(edge)

    def test_decay_and_prune_memory_controls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            conn.row_factory = sqlite3.Row
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Prune Target",
                    summary="A low-salience topic about Zephyr pruning.",
                    source_refs=[],
                    topics=["Zephyr"],
                    salience=0.1,
                )
                conn.commit()
            finally:
                conn.close()

            dry = prune_memory(root, topic="Zephyr", action="archive", dry_run=True)
            actual = prune_memory(root, topic="Zephyr", action="archive")
            decay = decay_graph_routes(root, limit=10, prune_threshold=1)

            self.assertEqual(dry["card_count"], 1)
            self.assertEqual(actual["card_ids"], [card_id])
            self.assertTrue(decay["ok"])
            conn = connect_existing(root)
            try:
                status = conn.execute("SELECT status FROM cards WHERE id = ?", (card_id,)).fetchone()["status"]
            finally:
                conn.close()
            self.assertEqual(status, "archived")

    def test_storage_tiering_health_and_evals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["retention"]["raw_scroll_hot_days"] = 0
            write_config(root, config)
            source = Path(tmp) / "tier-source.txt"
            source.write_text("Tiering source evidence for Archivist.\n", encoding="utf-8")
            from continuum.core.store import ingest_file

            book = ingest_file(root, path=source, storage_tier="hot")
            old_original = Path(book["original_uri"])
            old_reader = Path(book["reader_uri"])
            tiered = apply_storage_tiering(root)
            health = memory_health(root)
            evals = run_memory_quality_evals(root)

            self.assertTrue(tiered["ok"])
            self.assertGreaterEqual(tiered["action_count"], 1)
            self.assertTrue(health["initialized"])
            self.assertTrue(evals["ok"], evals["scores"])
            conn = connect_existing(root)
            try:
                row = conn.execute("SELECT storage_tier, original_uri, reader_uri FROM books WHERE id = ?", (book["book_id"],)).fetchone()
            finally:
                conn.close()
            self.assertEqual(row["storage_tier"], "warm")
            self.assertIn("archive/originals/warm/", row["original_uri"])
            self.assertIn("archive/reader_editions/warm/", row["reader_uri"])
            self.assertFalse(old_original.exists())
            self.assertFalse(old_reader.exists())
            self.assertTrue((root / row["original_uri"]).exists())
            self.assertTrue((root / row["reader_uri"]).exists())

    def test_memory_health_skips_inaccessible_reparse_like_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            exports = root / "exports"
            readable = exports / "readable"
            blocked = exports / "blocked-reparse-point"
            readable.mkdir(parents=True)
            blocked.mkdir(parents=True)
            (readable / "note.txt").write_text("healthy bytes\n", encoding="utf-8")
            real_scandir = os.scandir

            def guarded_scandir(path):
                if Path(path) == blocked:
                    raise OSError("simulated inaccessible Windows reparse point")
                return real_scandir(path)

            with patch("continuum.core.workers.os.scandir", side_effect=guarded_scandir):
                health = memory_health(root)

            self.assertTrue(health["initialized"])
            self.assertIn("root_size_bytes", health)

    def test_non_preemptible_expired_worker_lease_is_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            expired = (dt.datetime.now(dt.UTC) - dt.timedelta(seconds=30)).replace(microsecond=0).isoformat()
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            try:
                conn.execute(
                    """
                    INSERT INTO queue_jobs(
                        id, role, job_type, priority, status, preemptible, attempt_count,
                        lease_owner, lease_expires_at, heartbeat_at, related_card_ids_json,
                        payload_json, created_at, updated_at, started_at
                    )
                    VALUES(
                        'job_stale_nonpreemptible', 'archivist', 'verify_book_integrity', 10,
                        'running', 0, 1, 'dead-worker', ?, ?, '[]', '{}', ?, ?, ?
                    )
                    """,
                    (expired, expired, expired, expired, expired),
                )
                conn.commit()
            finally:
                conn.close()

            result = run_worker_pass(root, roles=["archivist"], limit=1, maintenance=False)

            self.assertEqual(result["reclaimed_expired_jobs"], 1)
            conn = connect_existing(root)
            try:
                row = conn.execute("SELECT status, error_json FROM queue_jobs WHERE id = 'job_stale_nonpreemptible'").fetchone()
            finally:
                conn.close()
            self.assertEqual(row["status"], "failed")
            self.assertIn("non_preemptible_worker_lease_expired", row["error_json"])

    def test_conflict_detection_marks_related_cards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            conn.row_factory = sqlite3.Row
            try:
                first = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Hermes Route",
                    summary="Decision: use Hermes route for local model.",
                    source_refs=[],
                    topics=["Hermes"],
                )
                second = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Hermes Route",
                    summary="Decision: do not use Hermes route for local model.",
                    source_refs=[],
                    topics=["Hermes"],
                )
                conn.commit()
            finally:
                conn.close()

            result = detect_conflicts(root)

            self.assertGreaterEqual(result["conflict_count"], 1)
            conn = connect_existing(root)
            try:
                rows = conn.execute("SELECT conflict_group FROM cards WHERE id IN (?, ?)", (first, second)).fetchall()
            finally:
                conn.close()
            self.assertTrue(all(row["conflict_group"] for row in rows))


if __name__ == "__main__":
    unittest.main()
