from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from continuum.core.store import connect, connect_existing, init_db, sqlite_readonly_uri


class LiveWalReadTests(unittest.TestCase):
    @staticmethod
    def _durable_files(root: Path) -> dict[str, bytes]:
        return {
            path.relative_to(root).as_posix(): path.read_bytes()
            for path in root.rglob("*")
            if path.is_file() and not path.name.endswith(("-wal", "-shm", "-journal"))
        }

    def test_default_existing_connection_observes_committed_live_wal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)

            writer = connect(root)
            try:
                writer.execute("PRAGMA wal_autocheckpoint = 0")
                writer.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('wal_probe', 'visible')")
                writer.commit()

                wal_path = Path(f"{root / 'catalog' / 'catalog.sqlite3'}-wal")
                self.assertTrue(wal_path.exists())
                self.assertGreater(wal_path.stat().st_size, 0)

                reader = connect_existing(root)
                try:
                    row = reader.execute("SELECT value FROM meta WHERE key = 'wal_probe'").fetchone()
                finally:
                    reader.close()
            finally:
                writer.close()

            self.assertIsNotNone(row)
            self.assertEqual(row["value"], "visible")

    def test_default_existing_connection_remains_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)

            reader = connect_existing(root)
            try:
                with self.assertRaisesRegex(sqlite3.OperationalError, "readonly"):
                    reader.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('forbidden', 'write')")
            finally:
                reader.close()

    def test_wal_aware_read_does_not_modify_durable_root_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            before = self._durable_files(root)

            reader = connect_existing(root)
            try:
                self.assertGreater(reader.execute("SELECT count(*) FROM meta").fetchone()[0], 0)
            finally:
                reader.close()

            self.assertEqual(before, self._durable_files(root))
            runtime_sidecars = {
                path.name
                for path in (root / "catalog").iterdir()
                if path.name.endswith(("-wal", "-shm", "-journal"))
            }
            self.assertLessEqual(runtime_sidecars, {"catalog.sqlite3-wal", "catalog.sqlite3-shm"})

    def test_immutable_mode_requires_explicit_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            database = Path(tmp) / "frozen.sqlite3"
            conn = sqlite3.connect(database)
            try:
                conn.execute("CREATE TABLE frozen(value TEXT NOT NULL)")
                conn.execute("INSERT INTO frozen(value) VALUES('snapshot')")
                conn.commit()
            finally:
                conn.close()

            ordinary_uri = sqlite_readonly_uri(database)
            immutable_uri = sqlite_readonly_uri(database, immutable=True)
            self.assertIn("mode=ro", ordinary_uri)
            self.assertNotIn("immutable=", ordinary_uri)
            self.assertIn("immutable=true", immutable_uri)

            frozen_reader = sqlite3.connect(immutable_uri, uri=True)
            try:
                self.assertEqual(frozen_reader.execute("SELECT value FROM frozen").fetchone()[0], "snapshot")
            finally:
                frozen_reader.close()


if __name__ == "__main__":
    unittest.main()
