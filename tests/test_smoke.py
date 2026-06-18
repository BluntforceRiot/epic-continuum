from __future__ import annotations

import tempfile
import unittest
import sqlite3
from pathlib import Path

from continuum.core.store import append_scroll_event, init_db, status


class EpicContinuumSmokeTest(unittest.TestCase):
    def test_init_and_append_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            self.assertTrue((root / "catalog" / "catalog.sqlite3").exists())
            self.assertTrue((root / "archive" / "originals" / "hot").exists())

            result = append_scroll_event(
                root,
                session_id="smoke",
                event_type="message",
                role="user",
                content="The Scroll rolls into the Library.",
            )
            self.assertEqual(result["seq"], 1)

            state = status(root)
            self.assertEqual(state["scroll_events"], 1)
            self.assertEqual(state["queue_jobs"], 1)
            self.assertEqual(state["audit_events"], 1)

    def test_init_migrates_old_catalog_before_creating_new_indexes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            catalog = root / "catalog"
            catalog.mkdir(parents=True)
            conn = sqlite3.connect(catalog / "catalog.sqlite3")
            try:
                conn.execute(
                    """
                    CREATE TABLE cards (
                        id TEXT PRIMARY KEY,
                        card_type TEXT NOT NULL,
                        title TEXT NOT NULL,
                        summary TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'pending_librarian_review',
                        placement_collection TEXT,
                        shelf TEXT,
                        storage_tier TEXT,
                        location_uri TEXT,
                        source_refs_json TEXT NOT NULL DEFAULT '[]',
                        entities_json TEXT NOT NULL DEFAULT '[]',
                        topics_json TEXT NOT NULL DEFAULT '[]',
                        decisions_json TEXT NOT NULL DEFAULT '[]',
                        open_tasks_json TEXT NOT NULL DEFAULT '[]',
                        salience REAL NOT NULL DEFAULT 0.5,
                        confidence REAL NOT NULL DEFAULT 0.7,
                        metadata_json TEXT NOT NULL DEFAULT '{}',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    )
                    """
                )
                conn.commit()
            finally:
                conn.close()

            init_db(root)

            conn = sqlite3.connect(catalog / "catalog.sqlite3")
            try:
                columns = {row[1] for row in conn.execute("PRAGMA table_info(cards)")}
                indexes = {row[1] for row in conn.execute("PRAGMA index_list(cards)")}
            finally:
                conn.close()

            self.assertIn("visibility_scope", columns)
            self.assertIn("session_id", columns)
            self.assertIn("idx_cards_visibility", indexes)


if __name__ == "__main__":
    unittest.main()
