from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from continuum.core.config import load_config, write_config
from continuum.core.mempalace_import import import_mempalace, sqlite_backup, stop_mempalace_processes
from continuum.core.operations import doctor, verify_proof_pack
from continuum.core.store import audit_search_index, init_db, rebuild_search_index, resolve_stored_uri, search_memory


def create_fake_chroma(
    path: Path,
    *,
    drawer_content: str = "Alpha drawer content with Epic Continuum migration notes.",
    source_file: str = "/portable/example.md",
    drawer_embedding_id: str = "drawer_operator_core_context_general_alpha",
    closet_embedding_id: str = "closet_operator_core_context_general_alpha",
) -> None:
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(
            """
            CREATE TABLE embeddings (
                id INTEGER PRIMARY KEY,
                segment_id TEXT NOT NULL,
                embedding_id TEXT NOT NULL,
                seq_id BLOB NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (segment_id, embedding_id)
            );
            CREATE TABLE embedding_metadata (
                id INTEGER REFERENCES embeddings(id),
                key TEXT NOT NULL,
                string_value TEXT,
                int_value INTEGER,
                float_value REAL,
                bool_value INTEGER,
                PRIMARY KEY (id, key)
            );
            CREATE VIRTUAL TABLE embedding_fulltext_search USING fts5(string_value);
            """
        )
        rows = [
            (
                1,
                "seg-a",
                drawer_embedding_id,
                "2026-06-01 00:00:00",
                {
                    "wing": "operator_core_context",
                    "room": "general",
                    "hall": "memory",
                    "source_file": source_file,
                    "chroma:document": drawer_content,
                },
            ),
            (
                2,
                "seg-a",
                closet_embedding_id,
                "2026-06-01 00:01:00",
                {
                    "wing": "operator_core_context",
                    "room": "general",
                    "chroma:document": "operator_core_context/general/alpha||->drawer_alpha",
                },
            ),
        ]
        for row_id, segment_id, embedding_id, created_at, metadata in rows:
            conn.execute(
                "INSERT INTO embeddings(id, segment_id, embedding_id, seq_id, created_at) VALUES(?, ?, ?, ?, ?)",
                (row_id, segment_id, embedding_id, row_id, created_at),
            )
            conn.execute(
                "INSERT INTO embedding_fulltext_search(rowid, string_value) VALUES(?, ?)",
                (row_id, metadata["chroma:document"]),
            )
            for key, value in metadata.items():
                conn.execute(
                    """
                    INSERT INTO embedding_metadata(id, key, string_value, int_value, float_value, bool_value)
                    VALUES(?, ?, ?, NULL, NULL, NULL)
                    """,
                    (row_id, key, value),
                )
        conn.commit()
    finally:
        conn.close()


class _FakeSqliteConnection:
    def backup(self, _destination: object) -> None:
        return None

    def close(self) -> None:
        return None


def create_fake_kg(
    path: Path,
    *,
    entity_name: str = "Epic Continuum",
    entity_properties: str = "{}",
    predicate: str = "imports",
    source_drawer_id: str = "drawer_operator_core_context_general_alpha",
) -> None:
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(
            """
            CREATE TABLE entities (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT DEFAULT 'unknown',
                properties TEXT DEFAULT '{}',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE triples (
                id TEXT PRIMARY KEY,
                subject TEXT NOT NULL,
                predicate TEXT NOT NULL,
                object TEXT NOT NULL,
                valid_from TEXT,
                valid_to TEXT,
                confidence REAL DEFAULT 1.0,
                source_closet TEXT,
                source_file TEXT,
                source_drawer_id TEXT,
                adapter_name TEXT,
                extracted_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            """
        )
        conn.execute(
            "INSERT INTO entities(id, name, type, properties) VALUES('e1', ?, 'project', ?)",
            (entity_name, entity_properties),
        )
        conn.execute(
            "INSERT INTO entities(id, name, type, properties) VALUES('e2', 'MemPalace', 'system', '{}')"
        )
        conn.execute(
            """
            INSERT INTO triples(id, subject, predicate, object, confidence, source_drawer_id)
            VALUES('t1', 'e1', ?, 'e2', 0.9, ?)
            """,
            (predicate, source_drawer_id),
        )
        conn.commit()
    finally:
        conn.close()


def connect_catalog(root: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(root / "catalog" / "catalog.sqlite3"))
    conn.row_factory = sqlite3.Row
    return conn


def root_uri(root: Path, path: str | Path) -> str:
    return Path(path).resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()


def root_contains_bytes(root: Path, needle: bytes) -> bool:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            if needle in path.read_bytes():
                return True
        except OSError:
            continue
    return False


class MemPalaceImportTest(unittest.TestCase):
    def test_sqlite_backup_opens_source_read_only_uri(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "source.sqlite3"
            dest = Path(tmp) / "dest.sqlite3"
            source.write_bytes(b"not used by fake connection")
            calls: list[tuple[object, dict[str, object]]] = []

            def fake_connect(target: object, *args: object, **kwargs: object) -> _FakeSqliteConnection:
                calls.append((target, dict(kwargs)))
                return _FakeSqliteConnection()

            with patch("continuum.core.mempalace_import.sqlite3.connect", side_effect=fake_connect):
                sqlite_backup(source, dest)

            self.assertIn("mode=ro", str(calls[0][0]))
            self.assertTrue(calls[0][1].get("uri"))

    def test_stop_mempalace_processes_does_not_record_command_lines(self) -> None:
        class Completed:
            def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0) -> None:
                self.stdout = stdout
                self.stderr = stderr
                self.returncode = returncode

        with patch("continuum.core.mempalace_import.platform.system", return_value="Windows"), patch(
            "continuum.core.mempalace_import.subprocess.run",
            side_effect=[
                Completed(stdout="1234\tpython.exe\tpython mempalace-readonly-mcp --token secret\n"),
                Completed(stdout="SUCCESS"),
            ],
        ):
            result = stop_mempalace_processes()

        self.assertEqual(result["errors"], [])
        self.assertEqual(result["stopped"][0]["pid"], 1234)
        self.assertNotIn("command_line", result["stopped"][0])
        self.assertEqual(result["stopped"][0]["matched"], "mempalace-readonly-mcp")

    def test_imports_chroma_drawers_closets_and_kg(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            palace = tmp_path / "palace"
            palace.mkdir()
            create_fake_chroma(
                palace / "chroma.sqlite3",
                drawer_content="Alpha drawer content with Epic Continuum migration notes.\napi_key=supersecretvalue123",
            )
            create_fake_kg(palace / "knowledge_graph.sqlite3")
            root = tmp_path / "continuum"
            init_db(root)
            config = load_config(root)
            config["security"]["secret_scan_action"] = "warn"
            write_config(root, config)
            progress_events: list[dict] = []

            result = import_mempalace(
                root,
                palace_path=palace,
                progress=progress_events.append,
            )

            self.assertTrue(Path(result["receipt_uri"]).exists())
            self.assertEqual(result["counts"]["drawers_imported"], 1)
            self.assertEqual(result["counts"]["closets_imported"], 1)
            self.assertEqual(result["counts"]["kg_entities"], 2)
            self.assertEqual(result["counts"]["kg_triples"], 1)
            self.assertGreaterEqual(len(progress_events), 2)

            with closing(connect_catalog(root)) as conn:
                self.assertEqual(conn.execute("SELECT count(*) FROM books").fetchone()[0], 2)
                self.assertEqual(conn.execute("SELECT count(*) FROM cards").fetchone()[0], 2)
                card_types = {row["card_type"] for row in conn.execute("SELECT card_type FROM cards")}
                self.assertIn("mempalace_drawer", card_types)
                self.assertIn("mempalace_closet", card_types)

                book = conn.execute("SELECT * FROM books WHERE title LIKE '%drawer%'").fetchone()
                self.assertFalse(Path(book["original_uri"]).is_absolute())
                self.assertTrue(resolve_stored_uri(root, book["original_uri"]).exists())
                self.assertIn("mempalace_import", book["metadata_json"])
                self.assertNotIn("/portable/example.md", book["metadata_json"])
                self.assertIn("external:example.md", book["metadata_json"])

                relations = {row["relation"] for row in conn.execute("SELECT relation FROM graph_edges")}
                self.assertIn("imported_from", relations)
                self.assertIn("imports", relations)

                audit_payload = conn.execute(
                    "SELECT payload_json FROM audit_events WHERE action = 'import_mempalace'"
                ).fetchone()
                self.assertIn("drawers_imported", audit_payload["payload_json"])

            receipt = json.loads(Path(result["receipt_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(receipt["schema"], "epic_continuum.mempalace_import_receipt.v1")
            for uri_key in (
                "receipt_uri",
                "manifest_uri",
                "catalog_backup_uri",
                "resume_state_uri",
                "operation_receipt_uri",
                "proof_pack_uri",
            ):
                self.assertFalse(Path(str(receipt[uri_key])).is_absolute(), uri_key)
            self.assertTrue((root / "exports" / "operation_receipts" / f"{receipt['operation_id']}.json").exists())
            self.assertTrue((root / receipt["proof_pack_uri"]).exists())
            self.assertTrue((root / receipt["manifest_uri"]).exists())
            self.assertTrue((root / receipt["catalog_backup_uri"]).exists())
            self.assertTrue((root / receipt["resume_state_uri"]).exists())
            self.assertEqual(receipt["resume_token"], f"mempalace:{receipt['import_id']}")
            state = json.loads((root / receipt["resume_state_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(state["phase"], "done")
            self.assertEqual(state["resume_token"], receipt["resume_token"])
            self.assertEqual(receipt["counts"]["secret_findings"], 1)
            self.assertTrue(str(receipt["palace_path"]).startswith("external:"))
            self.assertEqual(receipt["palace_source"]["uri_base"], "external_source")
            self.assertEqual(state["palace_path"], receipt["palace_path"])
            self.assertEqual(state["palace_source"]["uri_base"], "external_source")

            receipt_before_verify = Path(result["receipt_uri"]).read_bytes()
            verification = verify_proof_pack(root / receipt["proof_pack_uri"])
            self.assertTrue(verification["ok"], verification["errors"])
            self.assertEqual(receipt_before_verify, Path(result["receipt_uri"]).read_bytes())

            proof = json.loads((root / receipt["proof_pack_uri"]).read_text(encoding="utf-8"))
            proof_paths = {item.get("uri") or item["path"] for item in proof["paths"]}
            self.assertIn(receipt["catalog_backup_uri"].replace("\\", "/"), proof_paths)
            self.assertIn(receipt["resume_state_uri"].replace("\\", "/"), proof_paths)
            self.assertNotIn(str(root / "catalog" / "catalog.sqlite3"), proof_paths)

            manifest = json.loads((root / receipt["manifest_uri"]).read_text(encoding="utf-8"))

            def walk_strings(value: object) -> list[str]:
                if isinstance(value, str):
                    return [value]
                if isinstance(value, dict):
                    found: list[str] = []
                    for nested in value.values():
                        found.extend(walk_strings(nested))
                    return found
                if isinstance(value, list):
                    found = []
                    for nested in value:
                        found.extend(walk_strings(nested))
                    return found
                return []

            internal_absolute_paths = [
                value for value in walk_strings(manifest) if Path(value).is_absolute() and str(root) in value
            ]
            self.assertEqual(internal_absolute_paths, [])
            self.assertNotIn(str(palace), walk_strings(receipt))
            self.assertNotIn(str(palace), walk_strings(state))
            self.assertNotIn(str(palace), walk_strings(manifest))

            health = doctor(root, verify_recent_proof_packs=1)
            self.assertTrue(health["ok"], health["checks"])

    def test_can_skip_closets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            palace = tmp_path / "palace"
            palace.mkdir()
            create_fake_chroma(palace / "chroma.sqlite3")

            result = import_mempalace(
                tmp_path / "continuum",
                palace_path=palace,
                include_closets=False,
                include_kg=False,
            )

            self.assertEqual(result["counts"]["drawers_imported"], 1)
            self.assertEqual(result["counts"]["closets_imported"], 0)
            self.assertEqual(result["counts"]["skipped"], 1)

    def test_imported_drawers_are_searchable_through_fts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            palace = tmp_path / "palace"
            palace.mkdir()
            create_fake_chroma(
                palace / "chroma.sqlite3",
                drawer_content="Continuum migration note with ZephyrMoonBaseBeacon search token.",
            )
            root = tmp_path / "continuum"

            import_mempalace(root, palace_path=palace, include_closets=False, include_kg=False)

            audit_result = audit_search_index(root, create=False)
            self.assertTrue(audit_result["ok"], audit_result)
            result = search_memory(root, query="ZephyrMoonBaseBeacon", limit=5, create=False)
            self.assertEqual(result["backend"], "fts5")
            self.assertEqual(result["result_count"], 1)
            self.assertIn("fts5_match", result["results"][0]["reason"])

    def test_secret_block_skips_mempalace_item_before_archiving(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            palace = tmp_path / "palace"
            palace.mkdir()
            create_fake_chroma(
                palace / "chroma.sqlite3",
                drawer_content="Do not archive this line because api_key=supersecretvalue123.",
            )
            root = tmp_path / "continuum"
            init_db(root)
            config = load_config(root)
            config["security"]["secret_scan_action"] = "block"
            write_config(root, config)

            result = import_mempalace(root, palace_path=palace, include_closets=False, include_kg=False)

            self.assertEqual(result["counts"]["drawers_imported"], 0)
            self.assertEqual(result["counts"]["skipped"], 2)
            self.assertEqual(result["counts"]["secret_findings"], 1)
            self.assertEqual(result["error_count"], 1)
            import_archive = root / "archive" / "originals" / "hot" / "mempalace" / "by-import"
            self.assertFalse(import_archive.exists())
            self.assertFalse((root / "run" / "mempalace_import_snapshots").exists())
            self.assertFalse(root_contains_bytes(root, b"supersecretvalue123"))
            search = search_memory(root, query="supersecretvalue123", limit=5, create=False)
            self.assertEqual(search["result_count"], 0)

            receipt = json.loads(Path(result["receipt_uri"]).read_text(encoding="utf-8"))
            self.assertFalse(receipt["snapshot"]["source_snapshot_retained"])
            self.assertEqual(receipt["snapshot"]["snapshot_policy"], "blocked_by_secret_policy")
            blocked_manifest = root / receipt["snapshot"]["blocked_source_manifest_uri"]
            self.assertTrue(blocked_manifest.exists())
            proof = json.loads((root / receipt["proof_pack_uri"]).read_text(encoding="utf-8"))
            proof_uris = {item.get("uri") or item["path"] for item in proof["paths"]}
            self.assertIn(receipt["snapshot"]["blocked_source_manifest_uri"], proof_uris)
            self.assertFalse(any(str(uri).endswith("chroma.sqlite3") for uri in proof_uris))

    def test_metadata_secret_block_skips_item_before_snapshot_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            palace = tmp_path / "palace"
            palace.mkdir()
            create_fake_chroma(
                palace / "chroma.sqlite3",
                drawer_content="Safe content should still be blocked because metadata has the secret.",
                source_file="api_key=supersecretvalue123",
            )
            root = tmp_path / "continuum"
            init_db(root)
            config = load_config(root)
            config["security"]["secret_scan_action"] = "block"
            write_config(root, config)

            result = import_mempalace(root, palace_path=palace, include_closets=False, include_kg=False)

            self.assertEqual(result["counts"]["drawers_imported"], 0)
            self.assertEqual(result["counts"]["secret_findings"], 1)
            self.assertFalse((root / "run" / "mempalace_import_snapshots").exists())
            self.assertFalse(root_contains_bytes(root, b"supersecretvalue123"))

    def test_secret_block_scans_mempalace_embedding_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            palace = tmp_path / "palace"
            palace.mkdir()
            create_fake_chroma(
                palace / "chroma.sqlite3",
                drawer_content="Safe content with a dangerous identifier.",
                drawer_embedding_id="drawer_api_key=supersecretvalue123",
                closet_embedding_id="closet_safe_identifier",
            )
            root = tmp_path / "continuum"
            init_db(root)
            config = load_config(root)
            config["security"]["secret_scan_action"] = "block"
            write_config(root, config)

            result = import_mempalace(root, palace_path=palace, include_closets=False, include_kg=False)

            self.assertEqual(result["counts"]["drawers_imported"], 0)
            self.assertEqual(result["counts"]["secret_findings"], 1)
            self.assertFalse((root / "run" / "mempalace_import_snapshots").exists())
            self.assertFalse(root_contains_bytes(root, b"supersecretvalue123"))
            self.assertTrue(doctor(root, verify_recent_proof_packs=1, scan_secrets=True)["ok"])

    def test_kg_secret_block_prevents_raw_snapshot_promotion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            palace = tmp_path / "palace"
            palace.mkdir()
            create_fake_chroma(palace / "chroma.sqlite3", drawer_content="Safe drawer evidence.")
            create_fake_kg(
                palace / "knowledge_graph.sqlite3",
                entity_properties='{"token":"supersecretvalue123"}',
            )
            root = tmp_path / "continuum"
            init_db(root)
            config = load_config(root)
            config["security"]["secret_scan_action"] = "block"
            write_config(root, config)

            result = import_mempalace(root, palace_path=palace, include_closets=False, include_kg=True)

            self.assertEqual(result["counts"]["drawers_imported"], 1)
            self.assertEqual(result["counts"]["kg_entities"], 0)
            self.assertEqual(result["counts"]["kg_triples"], 0)
            self.assertGreaterEqual(result["counts"]["secret_findings"], 1)
            self.assertFalse((root / "run" / "mempalace_import_snapshots").exists())
            self.assertFalse(root_contains_bytes(root, b"supersecretvalue123"))

    def test_kg_warn_policy_redacts_secret_fields_before_graph_storage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            palace = tmp_path / "palace"
            palace.mkdir()
            create_fake_chroma(palace / "chroma.sqlite3", drawer_content="Safe drawer evidence.")
            create_fake_kg(
                palace / "knowledge_graph.sqlite3",
                entity_name="api_key=supersecretvalue123",
                predicate="token=supersecretvalue123",
                source_drawer_id="password=supersecretvalue123",
            )
            root = tmp_path / "continuum"
            init_db(root)
            config = load_config(root)
            config["security"]["secret_scan_action"] = "warn"
            write_config(root, config)

            result = import_mempalace(root, palace_path=palace, include_closets=False, include_kg=True)

            self.assertEqual(result["counts"]["kg_entities"], 2)
            self.assertEqual(result["counts"]["kg_triples"], 1)
            with closing(connect_catalog(root)) as conn:
                graph_blob = "\n".join(
                    [
                        "\n".join(row["label"] for row in conn.execute("SELECT label FROM graph_nodes")),
                        "\n".join(row["relation"] for row in conn.execute("SELECT relation FROM graph_edges")),
                        "\n".join(row["source_refs_json"] for row in conn.execute("SELECT source_refs_json FROM graph_edges")),
                    ]
                )
            self.assertIn("[REDACTED]", graph_blob)
            self.assertNotIn("supersecretvalue123", graph_blob)

    def test_doctor_fails_when_imported_chunks_are_missing_from_fts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            palace = tmp_path / "palace"
            palace.mkdir()
            create_fake_chroma(palace / "chroma.sqlite3")
            root = tmp_path / "continuum"

            import_mempalace(root, palace_path=palace, include_closets=False, include_kg=False)
            with closing(connect_catalog(root)) as conn:
                conn.execute("DELETE FROM chunks_fts")
                conn.commit()

            health = doctor(root, verify_recent_proof_packs=0)
            search_check = [check for check in health["checks"] if check["name"] == "search_index_consistent"][0]
            self.assertFalse(health["ok"], health["checks"])
            self.assertFalse(search_check["ok"], search_check)
            self.assertGreater(search_check["missing_chunks"], 0)

            rebuilt = rebuild_search_index(root)
            self.assertTrue(rebuilt["ok"], rebuilt)
            repaired = doctor(root, verify_recent_proof_packs=0)
            repaired_check = [check for check in repaired["checks"] if check["name"] == "search_index_consistent"][0]
            self.assertTrue(repaired_check["ok"], repaired_check)

    def test_failed_import_proof_includes_partial_import_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            palace = tmp_path / "palace"
            palace.mkdir()
            create_fake_chroma(palace / "chroma.sqlite3", drawer_content="Partial artifact proof evidence.")
            create_fake_kg(palace / "knowledge_graph.sqlite3")
            root = tmp_path / "continuum"

            with patch("continuum.core.mempalace_import.import_kg", side_effect=RuntimeError("kg failure")):
                with self.assertRaisesRegex(RuntimeError, "kg failure"):
                    import_mempalace(root, palace_path=palace, include_closets=False, include_kg=True)

            proof_paths = sorted((root / "exports" / "proof_packs").glob("*.json"))
            self.assertEqual(len(proof_paths), 1)
            proof = json.loads(proof_paths[0].read_text(encoding="utf-8"))
            proof_uris = {item.get("uri") or item["path"] for item in proof["paths"]}
            partial_artifacts = [uri for uri in proof_uris if "archive/originals/hot/mempalace/by-import" in uri]
            self.assertTrue(partial_artifacts, proof_uris)
            verification = verify_proof_pack(proof_paths[0], root=root)
            self.assertTrue(verification["ok"], verification["errors"])

    def test_identical_reimport_keeps_canonical_evidence_and_source_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            palace = tmp_path / "palace"
            palace.mkdir()
            create_fake_chroma(palace / "chroma.sqlite3", drawer_content="Stable drawer evidence.")
            root = tmp_path / "continuum"

            first = import_mempalace(root, palace_path=palace, include_closets=False, include_kg=False)
            second = import_mempalace(root, palace_path=palace, include_closets=False, include_kg=False)

            with closing(connect_catalog(root)) as conn:
                rows = conn.execute("SELECT * FROM books WHERE title LIKE '%drawer%'").fetchall()
                self.assertEqual(len(rows), 1)
                book = rows[0]
                metadata = json.loads(book["metadata_json"])

            self.assertIn(first["import_id"], book["original_uri"])
            self.assertIn(first["import_id"], book["reader_uri"])
            self.assertNotIn(second["import_id"], book["original_uri"])
            self.assertNotIn(second["import_id"], book["reader_uri"])
            self.assertEqual(metadata["first_import_id"], first["import_id"])
            self.assertEqual(metadata["latest_import_id"], second["import_id"])
            history_imports = [entry["import_id"] for entry in metadata["source_history"]]
            self.assertIn(first["import_id"], history_imports)
            self.assertIn(second["import_id"], history_imports)

    def test_reimport_changed_embedding_preserves_old_original_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            palace = tmp_path / "palace"
            palace.mkdir()
            chroma_path = palace / "chroma.sqlite3"
            root = tmp_path / "continuum"

            create_fake_chroma(chroma_path, drawer_content="Alpha drawer evidence.")
            first = import_mempalace(root, palace_path=palace, include_closets=False, include_kg=False)

            with closing(connect_catalog(root)) as conn:
                first_book = conn.execute("SELECT * FROM books WHERE title LIKE '%drawer%'").fetchone()
                first_original = resolve_stored_uri(root, first_book["original_uri"])
                first_hash = first_book["content_hash"]
            first_text = first_original.read_text(encoding="utf-8")
            self.assertIn(first["import_id"], str(first_original))

            chroma_path.unlink()
            create_fake_chroma(chroma_path, drawer_content="Beta drawer evidence.")
            second = import_mempalace(root, palace_path=palace, include_closets=False, include_kg=False)

            with closing(connect_catalog(root)) as conn:
                rows = conn.execute("SELECT * FROM books WHERE title LIKE '%drawer%' ORDER BY created_at").fetchall()
                self.assertEqual(len(rows), 2)
                second_book = [row for row in rows if row["content_hash"] != first_hash][0]
                second_original = resolve_stored_uri(root, second_book["original_uri"])

            self.assertEqual(first_text, first_original.read_text(encoding="utf-8"))
            self.assertIn("Alpha drawer evidence.", first_original.read_text(encoding="utf-8"))
            self.assertNotIn("Beta drawer evidence.", first_original.read_text(encoding="utf-8"))
            self.assertNotEqual(first_original, second_original)
            self.assertIn(second["import_id"], str(second_original))
            self.assertIn("Beta drawer evidence.", second_original.read_text(encoding="utf-8"))

    def test_concurrent_imports_get_unique_receipts_and_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            palace = tmp_path / "palace"
            palace.mkdir()
            create_fake_chroma(palace / "chroma.sqlite3")
            root = tmp_path / "continuum"

            def run_import() -> dict:
                return import_mempalace(root, palace_path=palace, include_closets=False, include_kg=False)

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(lambda _item: run_import(), range(2)))

            self.assertEqual(len({result["import_id"] for result in results}), 2)
            self.assertEqual(len({result["receipt_uri"] for result in results}), 2)
            self.assertEqual(len({result["snapshot"]["snapshot_dir"] for result in results}), 2)
            for result in results:
                verification = verify_proof_pack(Path(result["proof_pack_uri"]))
                self.assertTrue(verification["ok"], verification["errors"])


if __name__ == "__main__":
    unittest.main()
