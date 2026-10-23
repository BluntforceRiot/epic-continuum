from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import continuum
from continuum.core.config import default_config, write_config
from continuum.core.retrieval import query_excerpt, query_terms
from continuum.core.tool_outputs import record_indexed_tool_result
from continuum.core.workers import apply_storage_tiering, verify_book_integrity
from continuum.core.store import (
    append_scroll_event, compile_context, connect, connect_existing, cue_recall,
    ingest_file, read_memory_chunk, resolve_stored_uri, search_memory,
)
from continuum.integrations.common import record_tool_event
from continuum.mcp_server import tool_read_chunk, tool_annotations


class RetrievalOutputsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="continuum-output-test-")
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.root = self.directory / "memory"

    def config(self, **capture: object) -> None:
        config = default_config()
        config["capture"].update({"large_result_policy": "index_and_link", "max_tool_result_bytes": "128B", **capture})
        write_config(self.root, config)

    def capture(self, payload: object, **kwargs: object) -> dict | None:
        return record_tool_event(self.root, session_id="session-one", tool_name="test-output", payload=payload,
                                 source="test", result=True, **kwargs)

    def rows(self, table: str) -> list:
        conn = connect_existing(self.root)
        try:
            return conn.execute(f"SELECT * FROM {table}").fetchall()
        finally:
            conn.close()

    def test_fixed_retrieval_corpus(self) -> None:
        fixture = json.loads((Path(__file__).resolve().parents[1] / "benchmarks/fixtures/retrieval_v04_cases.json").read_text(encoding="utf-8"))
        ids = {}
        for doc in fixture["documents"]:
            source = self.directory / f"{doc['id']}.txt"
            source.write_text("Routine progress entry without the requested decision.\n" * doc.get("prefix_repeat", 0) + doc["text"], encoding="utf-8")
            ids[ingest_file(self.root, path=source, title=doc["title"])["book_id"]] = doc["id"]
        for case in fixture["cases"]:
            with self.subTest(query=case["query"]):
                result = search_memory(self.root, query=case["query"], limit=3)
                hits = result["results"]
                self.assertEqual(ids[hits[0]["book_id"]] if hits else None, case["expected"])
                if hits:
                    self.assertIn(case["excerpt_contains"], hits[0]["snippet"])
                    self.assertLessEqual(len(hits[0]["snippet"]), 360)
                    self.assertNotIn("text", hits[0])
                    self.assertEqual(hits[0]["ranking"]["method"], "rrf_60")

    def test_query_terms_short_unicode_and_structured(self) -> None:
        for query, expected in [("SQL 429", "429"), ("mémoire café", "mémoire"), ("R2-D7", "R2-D7"), ("東京 検索", "東京")]:
            self.assertIn(expected, query_terms(query))
        self.assertLessEqual(len(query_terms(" ".join(f"word{i}" for i in range(1000)))), 16)

    def test_unicode_case_expansion_preserves_exact_search_and_excerpt(self) -> None:
        text = "Routine progress. " * 180 + "Straße and İstanbul are the exact locations."
        source = self.directory / "unicode.txt"
        source.write_text(text, encoding="utf-8")
        ingest_file(self.root, path=source, title="Locations")
        for query in ("Straße", "İstanbul"):
            with self.subTest(query=query):
                self.assertIn(query, query_terms(query))
                excerpt = query_excerpt(text, query, limit=120)
                self.assertIn(query, excerpt["text"])
                self.assertIn(query, text[excerpt["start"]:excerpt["end"]])
                result = search_memory(self.root, query=query)
                self.assertEqual(result["backend"], "fts5")
                self.assertGreater(result["result_count"], 0)
                self.assertIn(query, result["results"][0]["snippet"])

    def test_excerpt_exact_unicode_offsets_and_bound(self) -> None:
        text = "前置き " * 500 + "The turquoise heron answer is forty two." + " 后续" * 500
        excerpt = query_excerpt(text, "turquoise heron", limit=120)
        self.assertIn("forty two", excerpt["text"])
        self.assertLessEqual(len(excerpt["text"]), 120)
        self.assertEqual(excerpt["text"], "..." + text[excerpt["start"]:excerpt["end"]] + "...")

    def test_excerpt_handles_long_query_token(self) -> None:
        text = "abc " + "x" * 1000 + " tail"
        excerpt = query_excerpt(text, "x" * 1000, limit=32)
        self.assertLessEqual(len(excerpt["text"]), 32)

    def test_scroll_cue_excerpt_is_not_head_clipping(self) -> None:
        text = "Ordinary filler. " * 200 + "turquoiseheron chose the green switch."
        append_scroll_event(self.root, session_id="session-one", role="user", event_type="message", content=text)
        result = cue_recall(self.root, cue="turquoiseheron", session_id="session-one")
        self.assertTrue(any("green switch" in hit["summary"] for hit in result["results"]))

    def test_preserves_exact_text_scope_archive_and_bounded_context(self) -> None:
        self.config()
        text = "  Start\r\n" + "é 中文 output\n" * 1200 + "needlequartz final detail.\n  "
        event = self.capture(text)
        self.assertTrue(event["output_preserved"])
        books = self.rows("books")
        self.assertEqual(len(books), 1)
        archived = resolve_stored_uri(self.root, books[0]["original_uri"])
        self.assertEqual(archived.read_bytes(), text.encode("utf-8"))
        self.assertEqual(books[0]["content_hash"], hashlib.sha256(text.encode("utf-8")).hexdigest())
        chunks = sorted(self.rows("chunks"), key=lambda row: row["ordinal"])
        self.assertEqual("".join(row["text"] for row in chunks), text)
        scroll = self.rows("scroll_events")[0]
        self.assertLessEqual(len(scroll["content"].encode("utf-8")), 128)
        self.assertNotIn("needlequartz", scroll["content"])
        self.assertEqual(json.loads(books[0]["metadata_json"])["visibility_scope"], "session")
        self.assertEqual(search_memory(self.root, query="needlequartz")["result_count"], 0)
        result = search_memory(self.root, query="needlequartz", session_id="session-one")
        hit = result["results"][0]
        self.assertIn("final detail", hit["snippet"])
        self.assertFalse(read_memory_chunk(self.root, chunk_id=hit["chunk_id"])["found"])
        self.assertFalse(read_memory_chunk(self.root, chunk_id=hit["chunk_id"], session_id="wrong")["found"])
        detail = read_memory_chunk(self.root, chunk_id=hit["chunk_id"], session_id="session-one", offset=hit["excerpt_start"])
        self.assertIn("final detail", detail["content"])
        context = compile_context(self.root, session_id="session-one", token_budget=1000)
        self.assertNotIn("needlequartz", context["context_text"])
        recalled = cue_recall(self.root, cue="needlequartz", session_id="session-one")
        self.assertTrue(any(hit["kind"] == "library" and "final detail" in hit["summary"] for hit in recalled["results"]))

    def test_searchable_term_at_chunk_boundary(self) -> None:
        self.config()
        self.capture("f " * 2045 + "boundaryquartz final detail")
        result = search_memory(self.root, query="boundaryquartz", session_id="session-one")
        self.assertEqual(result["result_count"], 1)

    def test_read_pagination_roundtrips_all_chunks(self) -> None:
        self.config()
        text = "hello αβ\n" * 1500
        self.capture(text)
        chunk_id = min(self.rows("chunks"), key=lambda row: row["ordinal"])["id"]
        offset, collected = 0, []
        for _ in range(100):
            detail = read_memory_chunk(self.root, chunk_id=chunk_id, session_id="session-one", offset=offset, limit=777)
            self.assertLessEqual(len(detail["content"]), 777)
            collected.append(detail["content"])
            if detail["next_offset"] is not None:
                offset = detail["next_offset"]
            elif detail["next_chunk_id"]:
                chunk_id, offset = detail["next_chunk_id"], 0
            else:
                break
        else:
            self.fail("pagination did not terminate")
        self.assertEqual("".join(collected), text)

    def test_structured_payload_is_exact_valid_json(self) -> None:
        self.config()
        payload = {"items": list(range(2000)), "message": "safe output"}
        self.capture(payload)
        chunks = sorted(self.rows("chunks"), key=lambda row: row["ordinal"])
        self.assertEqual(json.loads("".join(row["text"] for row in chunks)), payload)

    def test_small_results_are_not_indexed(self) -> None:
        self.config()
        self.capture("small text")
        self.assertEqual(self.rows("books"), [])
        self.assertEqual(self.rows("scroll_events")[0]["content"], "small text")

    def test_dedup_keeps_one_archive_book(self) -> None:
        self.config()
        first = self.capture("same output " * 300)
        second = self.capture("same output " * 300)
        self.assertEqual(first["book_id"], second["book_id"])
        self.assertEqual(len(self.rows("books")), 1)

    def test_project_selector_required_and_no_cross_partition_dedup(self) -> None:
        self.config()
        text = "scopedneedle " * 300
        self.capture(text, project_id="alpha")
        self.capture(text, project_id="beta")
        self.assertEqual(len(self.rows("books")), 2)
        self.assertEqual(search_memory(self.root, query="scopedneedle", session_id="session-one")["result_count"], 0)
        hits = search_memory(self.root, query="scopedneedle", project_id="alpha")["results"]
        self.assertEqual(len(hits), 1)
        self.assertFalse(read_memory_chunk(self.root, chunk_id=hits[0]["chunk_id"], project_id="beta")["found"])
        self.assertTrue(read_memory_chunk(self.root, chunk_id=hits[0]["chunk_id"], project_id="alpha")["found"])

    def test_blocked_secret_tail_never_archives(self) -> None:
        self.config()
        result = self.capture("safe " * 1000 + "\napi_key=supersecretvalue123")
        self.assertIsNone(result)
        self.assertFalse((self.root / "archive").exists())
        self.assertFalse((self.root / "catalog/catalog.sqlite3").exists())

    def test_direct_indexing_preserves_secret_blocking(self) -> None:
        self.config()
        with self.assertRaisesRegex(ValueError, "secret scan blocked"):
            record_indexed_tool_result(self.root, session_id="session-one", event_type="tool_result",
                                      text="safe " * 100 + "\napi_key=supersecretvalue123",
                                      metadata={}, max_reference_bytes=128)
        self.assertFalse((self.root / "archive").exists())

    def test_archive_verification_and_tiering_preserve_output(self) -> None:
        config = default_config()
        config["capture"].update({"large_result_policy": "index_and_link", "max_tool_result_bytes": "128B"})
        config["retention"].update({"raw_scroll_hot_days": 0, "raw_scroll_warm_days": 0})
        write_config(self.root, config)
        text = "safe archived output\r\n" * 500
        event = self.capture(text)
        self.assertTrue(verify_book_integrity(self.root, book_id=event["book_id"])["ok"])
        for tier in ("warm", "cold"):
            self.assertTrue(apply_storage_tiering(self.root)["ok"])
            book = self.rows("books")[0]
            self.assertEqual(book["storage_tier"], tier)
            for field in ("original_uri", "reader_uri"):
                self.assertEqual(resolve_stored_uri(self.root, book[field]).read_bytes(), text.encode("utf-8"))
            self.assertTrue(verify_book_integrity(self.root, book_id=event["book_id"])["ok"])

    def test_blocked_newline_metadata_never_archives(self) -> None:
        self.config()
        result = self.capture("safe " * 1000, metadata={"model": {"api_key": "\nsupersecretvalue123"}})
        self.assertIsNone(result)
        self.assertFalse((self.root / "archive").exists())

    def test_warn_archives_only_redacted_text(self) -> None:
        config = default_config()
        config["capture"].update({"large_result_policy": "index_and_link", "max_tool_result_bytes": "128B"})
        config["security"]["secret_scan_action"] = "warn"
        write_config(self.root, config)
        self.capture("safe " * 1000 + "\napi_key=supersecretvalue123")
        for row in self.rows("chunks"):
            self.assertNotIn("supersecretvalue123", row["text"])
        book = self.rows("books")[0]
        self.assertNotIn(b"supersecretvalue123", resolve_stored_uri(self.root, book["original_uri"]).read_bytes())

    def test_archive_ceiling_reports_truncation_without_false_preservation(self) -> None:
        config = default_config()
        config["capture"].update({"large_result_policy": "index_and_link", "max_tool_result_bytes": "128B"})
        config["storage"]["max_ingest_bytes"] = "256B"
        write_config(self.root, config)
        event = self.capture("safe " * 1000)
        self.assertNotIn("output_preserved", event)
        self.assertEqual(self.rows("books"), [])
        row = self.rows("scroll_events")[0]
        self.assertLessEqual(len(row["content"].encode("utf-8")), 128)
        self.assertIn("index_skipped_reason", json.loads(row["metadata_json"]))

    def test_tiny_reference_cap_remains_absolute(self) -> None:
        self.config(max_tool_result_bytes="1B")
        self.capture("safe output " * 100)
        self.assertLessEqual(len(self.rows("scroll_events")[0]["content"].encode("utf-8")), 1)
        self.assertEqual(len(self.rows("books")), 1)

    def test_tiny_reference_dedup_keeps_distinct_output_authority(self) -> None:
        self.config(max_tool_result_bytes="1B")
        first = self.capture("first output " * 100)
        second = self.capture("second output " * 100)
        repeated = self.capture("second output " * 100)
        self.assertNotEqual(first["event_id"], second["event_id"])
        self.assertEqual(second["event_id"], repeated["event_id"])
        self.assertEqual(len(self.rows("scroll_events")), 2)
        self.assertEqual(len(self.rows("books")), 2)
        for book in self.rows("books"):
            metadata = json.loads(book["metadata_json"])
            capture = metadata["source_metadata"]["capture"]
            self.assertEqual(capture["book_id"], book["id"])
            self.assertEqual(capture["original_sha256"], book["content_hash"])
            source_event = next(row for row in self.rows("scroll_events") if row["id"] == metadata["source_event_id"])
            self.assertEqual(json.loads(source_event["metadata_json"])["capture"], capture)

    def test_failed_index_cannot_commit_false_scroll_reference(self) -> None:
        self.config()
        with patch("continuum.core.tool_outputs.index_chunk_fts", side_effect=RuntimeError("index failed")):
            with self.assertRaisesRegex(RuntimeError, "index failed"):
                self.capture("safe output " * 100)
        self.assertEqual(self.rows("books"), [])
        self.assertEqual(self.rows("scroll_events"), [])

    def test_default_capture_behavior_is_unchanged(self) -> None:
        config = default_config()
        self.assertEqual(config["capture"]["large_result_policy"], "truncate_with_notice")
        config["capture"]["max_tool_result_bytes"] = "128B"
        write_config(self.root, config)
        self.capture("safe output " * 100)
        self.assertEqual(self.rows("books"), [])
        self.assertIn("truncated", self.rows("scroll_events")[0]["content"])

    def test_fallback_search_and_empty_query(self) -> None:
        self.config()
        self.capture("filler " * 500 + "quartzneedle is at the end")
        conn = connect(self.root)
        try:
            conn.execute("DROP TABLE chunks_fts")
            conn.commit()
        finally:
            conn.close()
        result = search_memory(self.root, query="quartzneedle", session_id="session-one")
        self.assertEqual(result["backend"], "like")
        self.assertIn("at the end", result["results"][0]["snippet"])
        self.assertEqual(search_memory(self.root, query="  ")["result_count"], 0)

    def test_reader_does_not_initialize_and_rejects_invalid_bounds(self) -> None:
        self.assertFalse(read_memory_chunk(self.root, chunk_id="unknown")["found"])
        self.assertFalse(self.root.exists())
        for bounds in [{"limit": 0}, {"limit": 8001}, {"offset": -1}, {"offset": True}, {"limit": 1.5}]:
            with self.subTest(bounds=bounds), self.assertRaises(ValueError):
                read_memory_chunk(self.root, chunk_id="unknown", **bounds)

    def test_mcp_handler_scope_and_readonly_annotation(self) -> None:
        self.config()
        self.capture("visible needle " * 100)
        chunk_id = self.rows("chunks")[0]["id"]
        with patch.dict(os.environ, {"CONTINUUM_ROOT": str(self.root), "CONTINUUM_ALLOWED_ROOTS": str(self.root)}):
            missing = tool_read_chunk({"root": str(self.root), "chunk_id": chunk_id})
            found = tool_read_chunk({"root": str(self.root), "chunk_id": chunk_id, "session_id": "session-one", "limit": 20})
        self.assertFalse(missing["found"])
        self.assertTrue(found["found"])
        self.assertEqual(len(found["content"]), 20)
        self.assertTrue(tool_annotations("continuum_read_chunk")["readOnlyHint"])

    def test_cli_fresh_process_read(self) -> None:
        self.config()
        self.capture("visible needle " * 100)
        chunk_id = self.rows("chunks")[0]["id"]
        env = {**os.environ, "PYTHONPATH": str(Path(continuum.__file__).parent.parent), "PYTHONDONTWRITEBYTECODE": "1"}
        completed = subprocess.run([sys.executable, "-m", "continuum", "read-chunk", "--root", str(self.root), "--chunk-id", chunk_id, "--session-id", "session-one", "--limit", "23"], env=env, cwd=self.directory, capture_output=True, text=True, timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        result = json.loads(completed.stdout)
        self.assertEqual(len(result["content"]), 23)
        self.assertEqual(result["next_offset"], 23)


if __name__ == "__main__":
    unittest.main()
