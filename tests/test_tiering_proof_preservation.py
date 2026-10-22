from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum.core import store, workers
from continuum.core.config import default_config, write_config


class StorageTierProofPreservationTest(unittest.TestCase):
    def _book(self, tmp: str) -> tuple[Path, dict, dict[str, Path]]:
        root = Path(tmp) / "continuum"
        config = default_config()
        config["retention"]["raw_scroll_hot_days"] = 0
        config["retention"]["raw_scroll_warm_days"] = 0
        write_config(root, config)
        source = Path(tmp) / "tier-proof.txt"
        source.write_text("Tiering preserves historical proof bytes.\n", encoding="utf-8")
        book = store.ingest_file(root, path=source, storage_tier="hot")
        paths = {
            field: Path(book[field])
            for field in ("original_uri", "reader_uri")
        }
        return root, book, paths

    def _bind(self, root: Path, path: Path) -> None:
        content = path.read_bytes()
        conn = store.connect(root)
        try:
            store.record_artifact(
                conn,
                kind="proof_input",
                uri=store.continuum_uri(root, path),
                sha256=hashlib.sha256(content).hexdigest(),
                size_bytes=len(content),
                immutable=True,
            )
            conn.commit()
        finally:
            conn.close()

    def _current(self, root: Path, book: dict) -> dict:
        conn = store.connect_existing(root)
        try:
            return dict(conn.execute(
                "SELECT * FROM books WHERE id = ?", (book["book_id"],),
            ).fetchone())
        finally:
            conn.close()

    def _artifacts(self, root: Path) -> list[tuple]:
        conn = store.connect_existing(root)
        try:
            return [tuple(row) for row in conn.execute("SELECT * FROM artifacts ORDER BY id")]
        finally:
            conn.close()

    def test_preserves_bound_sources_and_routes_current_copies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, book, paths = self._book(tmp)
            before = {field: path.read_bytes() for field, path in paths.items()}
            for path in paths.values():
                self._bind(root, path)
            artifacts = self._artifacts(root)

            preview = workers.apply_storage_tiering(root, dry_run=True)
            self.assertTrue(preview["ok"])
            self.assertTrue(all(
                item["copied"] and item["source_preserved"]
                for item in preview["actions"][0]["files"]
            ))
            for path in paths.values():
                self.assertFalse((path.parent.parent / "warm" / path.name).exists())
            for tier in ("warm", "cold"):
                result = workers.apply_storage_tiering(root)
                self.assertTrue(result["ok"])
                current = self._current(root, book)
                self.assertEqual(current["storage_tier"], tier)
                self.assertEqual(current["location_uri"], current["original_uri"])
                self.assertEqual(self._artifacts(root), artifacts)
                for field, path in paths.items():
                    self.assertEqual(path.read_bytes(), before[field])
                    target = store.resolve_stored_uri(root, current[field])
                    self.assertEqual(target.parent.name, tier)
                    self.assertEqual(target.read_bytes(), before[field])

    def test_preflights_both_files_before_staging(self) -> None:
        for damage in ("missing", "mismatched"):
            with self.subTest(damage=damage), tempfile.TemporaryDirectory() as tmp:
                root, book, paths = self._book(tmp)
                reader = paths["reader_uri"]
                self._bind(root, reader)
                artifacts = self._artifacts(root)
                if damage == "missing":
                    reader.unlink()
                else:
                    reader.write_bytes(b"Changed bytes do not redefine a historical proof.\n")
                with self.assertRaises((OSError, ValueError)):
                    workers.apply_storage_tiering(root)
                original = paths["original_uri"]
                self.assertTrue(original.exists())
                self.assertFalse((original.parent.parent / "warm" / original.name).exists())
                self.assertEqual(self._current(root, book)["storage_tier"], "hot")
                self.assertEqual(self._artifacts(root), artifacts)

    def test_preflights_later_books_before_staging(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, first, paths = self._book(tmp)
            source = Path(tmp) / "later.txt"
            source.write_text("Later book unavailable proof.\n", encoding="utf-8")
            second = store.ingest_file(root, path=source)
            reader = Path(second["reader_uri"])
            self._bind(root, reader)
            reader.unlink()
            conn = store.connect(root)
            try:
                for book, year in ((first, "2000"), (second, "2001")):
                    conn.execute(
                        "UPDATE books SET updated_at = ? WHERE id = ?",
                        (f"{year}-01-01T00:00:00+00:00", book["book_id"]),
                    )
                conn.commit()
            finally:
                conn.close()
            with self.assertRaises((OSError, ValueError)):
                workers.apply_storage_tiering(root)
            for path in paths.values():
                self.assertTrue(path.exists())
                self.assertFalse((path.parent.parent / "warm" / path.name).exists())

    def test_validates_bound_destinations_without_overwriting_them(self) -> None:
        for matching in (False, True):
            with self.subTest(matching=matching), tempfile.TemporaryDirectory() as tmp:
                root, book, paths = self._book(tmp)
                source = paths["reader_uri"]
                destination = source.parent.parent / "warm" / source.name
                destination.parent.mkdir(parents=True, exist_ok=True)
                expected = source.read_bytes() if matching else b"Unrelated immutable bytes.\n"
                destination.write_bytes(expected)
                self._bind(root, destination)
                artifacts = self._artifacts(root)
                if matching:
                    result = workers.apply_storage_tiering(root)
                    detail = next(
                        item for item in result["actions"][0]["files"]
                        if item["field"] == "reader_uri"
                    )
                    self.assertTrue(detail["source_preserved"])
                    self.assertEqual(detail["reason"], "reused_verified_destination")
                    self.assertTrue(source.exists())
                else:
                    with self.assertRaisesRegex(ValueError, "immutable destination conflict"):
                        workers.apply_storage_tiering(root)
                    self.assertEqual(self._current(root, book)["storage_tier"], "hot")
                    original = paths["original_uri"]
                    self.assertFalse((original.parent.parent / "warm" / original.name).exists())
                self.assertEqual(destination.read_bytes(), expected)
                self.assertEqual(self._artifacts(root), artifacts)

    def test_preserves_source_bound_through_hardlink_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, _book, paths = self._book(tmp)
            source = paths["original_uri"]
            alias = root / "exports" / "original-proof.txt"
            try:
                os.link(source, alias)
            except OSError as exc:
                self.skipTest(f"hardlink creation unavailable: {exc}")
            self._bind(root, alias)
            expected = source.read_bytes()
            result = workers.apply_storage_tiering(root)
            self.assertTrue(result["ok"])
            self.assertEqual(source.read_bytes(), expected)
            self.assertEqual(alias.read_bytes(), expected)

    def test_preserves_public_noclobber_policy_for_destination_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, book, paths = self._book(tmp)
            source = paths["original_uri"]
            self._bind(root, source)
            unrelated = Path(tmp) / "unrelated.txt"
            expected = b"Unrelated bytes survive destination conflict.\n"
            unrelated.write_bytes(expected)
            destination = source.parent.parent / "warm" / source.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(unrelated, destination)
            except OSError as exc:
                self.skipTest(f"hardlink creation unavailable: {exc}")
            with self.assertRaisesRegex(RuntimeError, "canonical destination exists"):
                workers.apply_storage_tiering(root)
            self.assertEqual(destination.read_bytes(), expected)
            self.assertEqual(unrelated.read_bytes(), expected)
            self.assertTrue(source.exists())
            self.assertEqual(self._current(root, book)["storage_tier"], "hot")

    def test_new_binding_during_staging_is_preserved_at_retirement(self) -> None:
        for bind_destination in (False, True):
            with self.subTest(destination=bind_destination), tempfile.TemporaryDirectory() as tmp:
                root, _book, paths = self._book(tmp)
                original = paths["original_uri"]
                expected = original.read_bytes()
                copy = workers._copy_verified_storage_tier_file

                def copy_and_bind(source: Path, destination: Path, **kwargs):
                    result = copy(source, destination, **kwargs)
                    if source == original:
                        # This independent writer also proves staging has no
                        # SQLite writer fence held across the copy.
                        self._bind(root, destination if bind_destination else source)
                    return result

                with patch.object(workers, "_copy_verified_storage_tier_file", side_effect=copy_and_bind):
                    result = workers.apply_storage_tiering(root)
                self.assertTrue(result["ok"])
                detail = result["actions"][0]["files"][0]
                self.assertEqual(detail["retirement_disposition"], "immutable_artifact_preserved")
                self.assertEqual(original.read_bytes(), expected)

    def test_retirement_fences_new_artifact_writers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, _book, _paths = self._book(tmp)
            finish = workers._finish_storage_tier_source_retirement

            def assert_fence(*args, **kwargs):
                writer = sqlite3.connect(root / "catalog" / "catalog.sqlite3", timeout=0.01)
                try:
                    with self.assertRaises(sqlite3.OperationalError):
                        writer.execute("BEGIN IMMEDIATE")
                finally:
                    writer.close()
                return finish(*args, **kwargs)

            with patch.object(workers, "_finish_storage_tier_source_retirement", side_effect=assert_fence):
                result = workers.apply_storage_tiering(root)
            self.assertTrue(result["ok"])

    def test_history_recovery_preserves_a_newly_bound_old_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root, book, paths = self._book(tmp)
            config = default_config()
            config["retention"]["raw_scroll_hot_days"] = 0
            write_config(root, config)
            with patch.object(
                workers, "_retire_storage_tier_source",
                side_effect=RuntimeError("stop after catalog commit"),
            ):
                with self.assertRaisesRegex(RuntimeError, "stop after catalog commit"):
                    workers.apply_storage_tiering(root)
            self.assertEqual(self._current(root, book)["storage_tier"], "warm")
            original = paths["original_uri"]
            expected = original.read_bytes()
            self._bind(root, original)

            recovered = workers.apply_storage_tiering(root)
            self.assertEqual(recovered["action_count"], 0)
            self.assertEqual(recovered["reconciled_cleanup_count"], 2)
            self.assertEqual(original.read_bytes(), expected)
            with patch.object(
                workers, "_retire_storage_tier_source",
                side_effect=AssertionError("completed preservation must not be retried"),
            ):
                repeated = workers.apply_storage_tiering(root)
            self.assertEqual(repeated["reconciled_cleanup_count"], 0)


if __name__ == "__main__":
    unittest.main()
