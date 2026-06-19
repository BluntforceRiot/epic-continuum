from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from importlib.resources import files
from pathlib import Path

import continuum
from continuum.core.atomic import atomic_memory_card, dump_yaml, load_atomic_yaml
from continuum.core.config import load_config, write_config
from continuum.core.store import (
    append_scroll_event,
    audit,
    compile_context,
    ingest_file,
    init_db,
    recover_thread,
    resolve_stored_uri,
    roll_scroll_segment,
    search_memory,
    snapshot,
    status,
)


def connect_catalog(root: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(root / "catalog" / "catalog.sqlite3"))
    conn.row_factory = sqlite3.Row
    return conn


class EpicContinuumCoreFlowTest(unittest.TestCase):
    def test_package_data_is_addressable_for_wheel_installs(self) -> None:
        package_root = files(continuum)

        self.assertTrue(package_root.joinpath("config.default.json").is_file())
        self.assertTrue(package_root.joinpath("core", "schema.sql").is_file())
        schema_root = package_root.joinpath("assets", "schemas")
        for name in (
            "operation_receipt.schema.json",
            "operation_event.schema.json",
            "proof_pack.schema.json",
            "operation_recovery.schema.json",
            "atomic_memory_card.schema.json",
            "root_bundle_manifest.schema.json",
        ):
            payload = json.loads(schema_root.joinpath(name).read_text(encoding="utf-8"))
            self.assertEqual(payload["$schema"], "https://json-schema.org/draft/2020-12/schema")
            self.assertTrue(payload["$id"].startswith("https://epic-continuum.local/schemas/"))

    def test_atomic_memory_card_matches_required_schema_keys(self) -> None:
        package_root = files(continuum)
        schema = json.loads(
            package_root.joinpath("assets", "schemas", "atomic_memory_card.schema.json").read_text(encoding="utf-8")
        )
        card = atomic_memory_card(
            card_id="card_schema_test",
            card_type="note",
            title="Schema Test",
            summary="Schema required keys should match producer output.",
            source_refs=[],
            entities=[],
            topics=[],
            decisions=[],
            open_tasks=[],
            salience=0.5,
            confidence=0.8,
            metadata={},
            created_at="2026-06-17T00:00:00+00:00",
            updated_at="2026-06-17T00:00:00+00:00",
            summary_hash="abc123",
        )

        for key in schema["required"]:
            self.assertIn(key, card)
        self.assertEqual(card["card_id"], card["id"])
        self.assertIn("metadata: {}", dump_yaml(card))
        self.assertEqual(load_atomic_yaml(dump_yaml(card)), card)

    def test_atomic_yaml_rejects_non_finite_floats(self) -> None:
        with self.assertRaises(ValueError):
            dump_yaml({"salience": float("nan")})

    def test_status_can_read_missing_root_without_initializing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "missing-continuum"

            state = status(root, create=False)

            self.assertFalse(state["initialized"])
            self.assertFalse(root.exists())

    def test_compile_context_can_read_missing_root_without_initializing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "missing-continuum"

            context = compile_context(root, session_id="missing", create=False)

            self.assertFalse(context["initialized"])
            self.assertEqual(context["context_text"], "")
            self.assertFalse(root.exists())

    def test_search_can_read_missing_root_without_initializing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "missing-continuum"

            result = search_memory(root, query="anything", create=False)

            self.assertFalse(result["initialized"])
            self.assertEqual(result["result_count"], 0)
            self.assertFalse(root.exists())

    def test_scroll_segment_context_audit_and_snapshot_flow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            append_scroll_event(
                root,
                session_id="core-flow",
                event_type="message",
                role="user",
                content="We need to preserve Aurora engine decisions and follow-up tasks.",
            )
            append_scroll_event(
                root,
                session_id="core-flow",
                event_type="message",
                role="assistant",
                content="Decision: keep Aurora engine notes hot and create verification tasks.",
            )

            segment = roll_scroll_segment(root, session_id="core-flow", start_seq=1, end_seq=2)

            self.assertEqual(segment["event_count"], 2)
            self.assertTrue(segment["segment_id"].startswith("seg_"))
            self.assertTrue(segment["card_id"].startswith("card_"))
            self.assertTrue(Path(segment["card_uri"]).exists())
            self.assertGreater(segment["token_estimate"], 0)

            with closing(connect_catalog(root)) as conn:
                self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")
                segment_row = conn.execute("SELECT * FROM scroll_segments").fetchone()
                self.assertEqual(segment_row["session_id"], "core-flow")
                self.assertEqual(segment_row["start_seq"], 1)
                self.assertEqual(segment_row["end_seq"], 2)
                self.assertEqual(segment_row["status"], "carded")
                self.assertEqual(segment_row["summary_card_id"], segment["card_id"])

                card_row = conn.execute("SELECT * FROM cards WHERE id = ?", (segment["card_id"],)).fetchone()
                self.assertEqual(card_row["card_type"], "scroll_segment")
                self.assertIn("core-flow scroll 1-2", card_row["title"])
                self.assertEqual(json.loads(card_row["metadata_json"])["session_id"], "core-flow")
                self.assertEqual(len(json.loads(card_row["source_refs_json"])), 2)
                self.assertFalse(Path(card_row["location_uri"]).is_absolute())
                card_sidecar = resolve_stored_uri(root, card_row["location_uri"])
                self.assertTrue(card_sidecar.exists())
                self.assertIn(
                    'schema: "continuum.atomic_memory.v1"',
                    card_sidecar.read_text(encoding="utf-8"),
                )

                job_types = {
                    (row["role"], row["job_type"])
                    for row in conn.execute("SELECT role, job_type FROM queue_jobs")
                }
                self.assertIn(("scribe", "scroll_event_ingested"), job_types)
                self.assertIn(("librarian", "review_card_placement"), job_types)
                self.assertIn(("archivist", "verify_segment_integrity"), job_types)

                audit_actions = [
                    row["action"]
                    for row in conn.execute("SELECT action FROM audit_events ORDER BY created_at, action")
                ]
                self.assertEqual(audit_actions.count("append_scroll_event"), 2)
                self.assertIn("roll_scroll_segment", audit_actions)

            context = compile_context(
                root,
                session_id="core-flow",
                token_budget=2000,
                query="Aurora verification tasks",
            )
            self.assertEqual(context["session_id"], "core-flow")
            self.assertEqual(context["token_budget"], 2000)
            self.assertGreaterEqual(context["section_count"], 2)
            self.assertIn("## recent_scroll", context["context_text"])
            self.assertIn("## recalled_cards", context["context_text"])
            self.assertIn("Decision: keep Aurora engine notes hot", context["context_text"])
            self.assertIn(segment["card_id"], context["context_text"])

            recovery = recover_thread(
                root,
                session_id="core-flow",
                query="Aurora verification tasks",
                token_budget=2000,
            )
            self.assertTrue(Path(recovery["packet_uri"]).exists())
            self.assertIn("Epic Continuum Thread Recovery: core-flow", recovery["packet_text"])
            self.assertIn("Epic Continuum root: `<continuum-root>`", recovery["packet_text"])
            self.assertNotIn(str(root), recovery["packet_text"])
            self.assertIn("Decision: keep Aurora engine notes hot", recovery["packet_text"])
            self.assertGreaterEqual(recovery["recent_event_count"], 2)
            self.assertGreaterEqual(recovery["card_count"], 1)

            state = audit(root)
            self.assertEqual(state["scroll_events"], 2)
            self.assertEqual(state["scroll_segments"], 1)
            self.assertEqual(state["cards"], 1)
            self.assertEqual(state["pending_librarian_cards"], 1)
            self.assertEqual(state["orphan_chunks"], 0)
            self.assertEqual(state["orphan_card_sidecars"], 0)
            self.assertGreaterEqual(state["active_graph_edges"], 1)

            snap = snapshot(root, reason="core_flow_test")

            snapshot_path = Path(snap["snapshot_uri"])
            self.assertTrue(snapshot_path.exists())
            self.assertTrue(Path(snap["card_sidecars_uri"]).exists())
            self.assertEqual(snap["card_sidecar_count"], 1)
            self.assertEqual(Path(snap["source_db_uri"]), root / "catalog" / "catalog.sqlite3")

            with closing(sqlite3.connect(str(snapshot_path))) as snap_conn:
                self.assertEqual(snap_conn.execute("SELECT count(*) FROM scroll_events").fetchone()[0], 2)
                self.assertEqual(snap_conn.execute("SELECT count(*) FROM scroll_segments").fetchone()[0], 1)

            post_snapshot_state = audit(root)
            self.assertEqual(post_snapshot_state["snapshots"], 1)
            self.assertGreaterEqual(post_snapshot_state["audit_events"], 4)
            self.assertEqual(post_snapshot_state["orphan_card_sidecars"], 0)

    def test_ingest_file_archives_chunks_catalogs_and_audits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            source = Path(tmp) / "source-notes.md"
            source_text = (
                "# Helios Source Notes\n\n"
                + "Helios archive parser requires warm storage and an audit trace.\n" * 140
            )
            source.write_bytes(source_text.encode("utf-8"))

            result = ingest_file(root, path=source, title="Helios Source Notes", storage_tier="warm")

            self.assertTrue(result["book_id"].startswith("book_"))
            self.assertTrue(result["card_id"].startswith("card_"))
            self.assertTrue(Path(result["card_uri"]).exists())
            self.assertGreater(result["chunk_count"], 1)
            self.assertTrue(Path(result["original_uri"]).exists())
            self.assertTrue(Path(result["reader_uri"]).exists())
            self.assertIn(str(root / "archive" / "originals" / "warm"), result["original_uri"])
            self.assertIn(str(root / "archive" / "reader_editions" / "warm"), result["reader_uri"])
            self.assertEqual(Path(result["reader_uri"]).read_text(encoding="utf-8"), source_text)

            with closing(connect_catalog(root)) as conn:
                book_row = conn.execute("SELECT * FROM books WHERE id = ?", (result["book_id"],)).fetchone()
                self.assertEqual(book_row["title"], "Helios Source Notes")
                self.assertEqual(book_row["storage_tier"], "warm")
                self.assertEqual(book_row["source_uri"], "external:source-notes.md")
                book_metadata = json.loads(book_row["metadata_json"])
                self.assertEqual(book_metadata["source_ref"]["uri_base"], "external_source")
                self.assertEqual(book_metadata["source_history_count"], 1)
                self.assertNotIn(str(source), book_row["metadata_json"])

                chunk_count = conn.execute(
                    "SELECT count(*) FROM chunks WHERE book_id = ?",
                    (result["book_id"],),
                ).fetchone()[0]
                self.assertEqual(chunk_count, result["chunk_count"])

                card_row = conn.execute("SELECT * FROM cards WHERE id = ?", (result["card_id"],)).fetchone()
                self.assertEqual(card_row["card_type"], "book")
                self.assertEqual(card_row["title"], "Helios Source Notes")
                self.assertEqual(json.loads(card_row["metadata_json"])["chunk_count"], result["chunk_count"])
                self.assertFalse(Path(card_row["location_uri"]).is_absolute())
                self.assertTrue(resolve_stored_uri(root, card_row["location_uri"]).exists())

                graph_edges = {
                    row["relation"]
                    for row in conn.execute("SELECT relation FROM graph_edges WHERE status = 'active'")
                }
                self.assertIn("describes", graph_edges)

                job_types = {
                    (row["role"], row["job_type"])
                    for row in conn.execute("SELECT role, job_type FROM queue_jobs")
                }
                self.assertIn(("librarian", "review_card_placement"), job_types)
                self.assertIn(("archivist", "verify_book_integrity"), job_types)

                audit_actions = [row["action"] for row in conn.execute("SELECT action FROM audit_events")]
                self.assertIn("ingest_file", audit_actions)

            state = audit(root)
            self.assertEqual(state["books"], 1)
            self.assertEqual(state["chunks"], result["chunk_count"])
            self.assertEqual(state["cards"], 1)
            self.assertEqual(state["pending_librarian_cards"], 1)
            self.assertEqual(state["orphan_chunks"], 0)
            self.assertEqual(state["orphan_card_sidecars"], 0)
            self.assertGreaterEqual(state["active_graph_edges"], 1)

            search = search_memory(root, query="Helios parser", limit=5)
            self.assertIn(search["backend"], {"fts5", "like"})
            self.assertGreaterEqual(search["result_count"], 1)
            self.assertIn("Helios Source Notes", search["results"][0]["title"])

    def test_search_memory_quotes_structured_tokens_for_fts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            source = Path(tmp) / "structured-token.txt"
            source.write_text("Document DOW-UAP-D077 and file:C:/uap/drop-03 are indexed.\n", encoding="utf-8")
            ingest_file(root, path=source, title="Structured Token Source")

            result = search_memory(root, query="DOW-UAP-D077 file:C:/uap/drop-03")

            self.assertEqual(result["backend"], "fts5", result)
            self.assertGreaterEqual(result["result_count"], 1)

    def test_snapshots_do_not_collide_in_bursts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            append_scroll_event(
                root,
                session_id="snapshot-burst",
                event_type="message",
                role="user",
                content="Make two snapshots in the same burst.",
            )

            first = snapshot(root, reason="burst")
            second = snapshot(root, reason="burst")

            self.assertNotEqual(first["snapshot_id"], second["snapshot_id"])
            self.assertNotEqual(first["snapshot_uri"], second["snapshot_uri"])
            self.assertTrue(Path(first["snapshot_uri"]).exists())
            self.assertTrue(Path(second["snapshot_uri"]).exists())

    def test_ingest_file_respects_configured_max_size_before_reading(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            source = Path(tmp) / "oversized.txt"
            source.write_text("too large for this configured ingest limit", encoding="utf-8")
            config = load_config(root)
            config["storage"]["max_ingest_bytes"] = "4B"
            write_config(root, config)

            with self.assertRaisesRegex(ValueError, "file too large for ingest_file"):
                ingest_file(root, path=source)

    def test_ingest_file_blocks_ignored_secret_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            source = Path(tmp) / ".env"
            source.write_text("OPENAI_API_KEY=sk-testvalue12345678901234567890", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "Continuum ignore rule"):
                ingest_file(root, path=source)

    def test_ingest_file_reports_secret_findings_without_raw_secret(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            config = load_config(root)
            config["security"]["secret_scan_action"] = "warn"
            write_config(root, config)
            source = Path(tmp) / "notes.txt"
            secret = "sk-testvalue12345678901234567890"
            source.write_text(f"temporary key {secret}\nnormal notes", encoding="utf-8")

            result = ingest_file(root, path=source)

            self.assertEqual(len(result["secret_findings"]), 1)
            self.assertEqual(result["secret_findings"][0]["type"], "openai_key")
            self.assertNotIn(secret, result["secret_findings"][0]["snippet"])

    def test_ingest_file_blocks_secret_findings_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            source = Path(tmp) / "notes.txt"
            source.write_text("temporary key sk-testvalue12345678901234567890\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "secret scan blocked ingest_file"):
                ingest_file(root, path=source)

    def test_compile_context_uses_configured_scroll_event_fetch_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            for index in range(1, 13):
                append_scroll_event(
                    root,
                    session_id="limited-scroll",
                    event_type="message",
                    role="user",
                    content=f"event {index} marker limited-scroll",
                )
            config = load_config(root)
            config["context"]["scroll_event_fetch_limit"] = 5
            write_config(root, config)

            context = compile_context(root, session_id="limited-scroll", token_budget=2000)

            self.assertEqual(context["recent_scroll_fetch_limit"], 5)
            self.assertIn("event 12 marker", context["context_text"])
            self.assertIn("event 8 marker", context["context_text"])
            self.assertNotIn("event 7 marker", context["context_text"])
            self.assertNotIn("event 1 marker", context["context_text"])

    def test_compile_context_strictly_truncates_to_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = load_config(root)
            config["context"]["reserve_output_tokens"] = 0
            write_config(root, config)
            append_scroll_event(
                root,
                session_id="strict-budget",
                event_type="message",
                role="user",
                content="large-event " * 200,
            )

            context = compile_context(root, session_id="strict-budget", token_budget=20)

            self.assertLessEqual(context["estimated_tokens"], context["usable_context_budget"])
            self.assertTrue(context["truncated"])
            self.assertGreaterEqual(len(context["truncated_items"]), 1)
            self.assertGreaterEqual(context["remaining_budget"], 0)

    def test_audit_reports_orphan_card_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            append_scroll_event(
                root,
                session_id="orphan-flow",
                event_type="message",
                role="user",
                content="Create a normal sidecar first.",
            )
            roll_scroll_segment(root, session_id="orphan-flow", start_seq=1, end_seq=1)
            orphan = root / "catalog" / "cards" / "card_orphan.yaml"
            orphan.write_text("schema: test\n", encoding="utf-8")

            state = audit(root)

            self.assertEqual(state["orphan_card_sidecars"], 1)

    def test_recover_thread_bounds_user_controlled_filename_component(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)

            result = recover_thread(root, session_id="A" * 5000)

            packet = Path(result["packet_uri"])
            self.assertTrue(packet.exists())
            self.assertLessEqual(len(packet.name.encode("utf-8")), 255)
            self.assertIn("A" * 80, packet.name)



if __name__ == "__main__":
    unittest.main()
