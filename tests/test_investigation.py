from __future__ import annotations

import hashlib
import json
import socket
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
from unittest.mock import patch

from continuum.core.config import default_config, write_config
from continuum.core.investigation import (
    MAX_ASSET_BYTES,
    export_investigation_notebook,
    query_investigation,
    record_analysis_finding,
    record_media_annotation,
    record_notebook_entry,
    register_analysis_asset,
)
from continuum.core.knowledge_records import append_record, read_records
from continuum.core.project_knowledge import index_project_files
from continuum.core.store import connect_existing, init_db


class InvestigationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="continuum-investigation-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / "memory"
        self.source = self.directory / "source"
        self.source.mkdir()
        config = default_config()
        config["capture"]["mode"] = "manual"
        config["local_inference"]["enabled"] = False
        write_config(self.root, config)
        init_db(self.root)
        for target in (
            "urllib.request.urlopen",
            "continuum.core.local_model._http_json",
        ):
            blocker = patch(
                target, side_effect=AssertionError("network/model forbidden")
            )
            blocker.start()
            self.addCleanup(blocker.stop)
        blocker = patch.object(
            socket, "create_connection", side_effect=AssertionError("network forbidden")
        )
        blocker.start()
        self.addCleanup(blocker.stop)

    def write(self, name: str, content: bytes | str) -> Path:
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode() if isinstance(content, str) else content)
        return path

    def asset(
        self, name: str = "sample.bin", project: str = "project-a", **kwargs
    ) -> dict:
        values = {"asset_kind": "binary", "build_id": "build-1"}
        values.update(kwargs)
        return register_analysis_asset(
            self.root,
            project_id=project,
            session_id="test-session",
            source_root=self.source,
            path=name,
            **values,
        )

    def finding(self, asset: dict, project: str = "project-a", **kwargs) -> dict:
        values = {
            "title": "Bounded parser",
            "text": "Candidate validates the length first.",
            "analyst": "operator",
            "function": "parse_header",
        }
        values.update(kwargs)
        return record_analysis_finding(
            self.root,
            project_id=project,
            session_id="test-session",
            asset_id=asset["id"],
            asset_hash=asset["payload"]["source_hash"],
            **values,
        )

    def note(self, **kwargs) -> dict:
        values = {
            "notebook_id": "parser-investigation",
            "entry_kind": "observation",
            "title": "Length check",
            "text": "Observe supplied evidence, then test.",
        }
        values.update(kwargs)
        return record_notebook_entry(
            self.root, project_id="project-a", session_id="test-session", **values
        )

    def annotation(self, asset: dict, **kwargs) -> dict:
        values = {
            "title": "Diagram region",
            "text": "A length check feeds the parser.",
            "anchor": {"page": 1, "region": [0.1, 0.2, 0.7, 0.8]},
        }
        values.update(kwargs)
        return record_media_annotation(
            self.root,
            project_id="project-a",
            session_id="test-session",
            asset_id=asset["id"],
            asset_hash=asset["payload"]["source_hash"],
            **values,
        )

    def query(self, **kwargs) -> dict:
        return query_investigation(self.root, project_id="project-a", **kwargs)

    def records(self) -> list[dict]:
        return read_records(self.root, project_id="project-a")

    def count(self) -> int:
        conn = connect_existing(self.root)
        try:
            return conn.execute("SELECT COUNT(*) FROM scroll_events").fetchone()[0]
        finally:
            conn.close()

    @staticmethod
    def citation(record: dict) -> dict:
        return {
            "kind": "scroll_event",
            "id": record["id"],
            "content_hash": record["content_hash"],
        }

    @staticmethod
    def link(record: dict, relation: str = "supports") -> dict:
        return {
            "relation": relation,
            "target_id": record["id"],
            "content_hash": record["content_hash"],
        }

    def test_binary_hash_build_and_relative_locator_without_bytes(self) -> None:
        raw = b"MZ\x00\xff\x01never-execute-me"
        self.write("bin/parser.bin", raw)
        result = self.asset("bin/parser.bin")
        self.assertEqual(
            result["payload"],
            {
                "schema": 1,
                "path": "bin/parser.bin",
                "source_hash": hashlib.sha256(raw).hexdigest(),
                "bytes": len(raw),
                "asset_kind": "binary",
                "build_id": "build-1",
                "version": 1,
            },
        )
        stored = json.dumps(self.records())
        self.assertNotIn("never-execute-me", stored)
        self.assertNotIn(str(self.source), stored)
        self.assertEqual(result["status"], "registered")

    def test_same_registration_is_idempotent_and_changed_build_retains_history(
        self,
    ) -> None:
        self.write("sample.bin", b"binary\x00one")
        first = self.asset()
        second = self.asset()
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(second["status"], "unchanged")
        third = self.asset(build_id="build-2")
        self.assertNotEqual(first["id"], third["id"])
        self.assertEqual(third["payload"]["version"], 2)
        self.assertEqual(self.count(), 2)
        self.assertEqual(self.query()["matched_count"], 1)
        history = self.query(include_history=True)["results"]
        self.assertEqual(len(history), 2)
        self.assertIn("newer_asset_version", history[1]["review_reasons"])

    def test_concurrent_same_registration_creates_one_version(self) -> None:
        self.write("sample.bin", b"binary\x00one")
        barrier = Barrier(4)

        def worker(_):
            barrier.wait(timeout=10)
            return self.asset()

        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(worker, range(4)))
        self.assertEqual(len({row["id"] for row in results}), 1)
        self.assertEqual(self.count(), 1)

    def test_same_file_case_alias_uses_one_history_where_supported(self) -> None:
        original = self.write("Sample.bin", b"one\x00")
        alias = self.source / "sample.bin"
        if not alias.exists() or not alias.samefile(original):
            self.skipTest("host filesystem does not provide this case alias")
        first = self.asset("Sample.bin")
        second = self.asset("sample.bin")
        self.assertEqual(first["id"], second["id"])
        self.write("sample.bin", b"two\x00")
        third = self.asset("sample.bin")
        self.assertEqual(third["payload"]["path"], first["payload"]["path"])
        self.assertEqual(third["payload"]["version"], 2)

    def test_unsafe_paths_and_missing_input_do_not_record(self) -> None:
        self.write("sample.bin", b"one\x00")
        for path in (
            "../sample.bin",
            "/sample.bin",
            "C:/sample.bin",
            "bin//sample.bin",
            "./sample.bin",
            "sample.bin:ads",
            "sample.bin ",
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.asset(path)
        with self.assertRaises(FileNotFoundError):
            self.asset("missing.bin")
        with self.assertRaises(ValueError):
            register_analysis_asset(
                self.root,
                project_id="project-a",
                session_id="test-session",
                source_root="relative",
                path="sample.bin",
                asset_kind="binary",
                build_id="one",
            )
        self.assertEqual(self.count(), 0)

    def test_oversized_asset_is_rejected_before_read(self) -> None:
        path = self.write("sample.bin", b"")
        with path.open("wb") as stream:
            stream.truncate(MAX_ASSET_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "32 MiB"):
            self.asset()
        self.assertEqual(self.count(), 0)

    def test_links_and_reparse_files_are_rejected(self) -> None:
        self.write("sample.bin", b"one\x00")
        original = Path.lstat

        def reparse(path, *args, **kwargs):
            if path.name == "sample.bin":
                return SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=1024)
            return original(path, *args, **kwargs)

        with (
            patch.object(Path, "lstat", reparse),
            self.assertRaisesRegex(ValueError, "non-link"),
        ):
            self.asset()
        self.assertEqual(self.count(), 0)

    def test_real_link_and_parent_link_rejected(self) -> None:
        outside = self.directory / "outside"
        outside.mkdir()
        (outside / "sample.bin").write_bytes(b"outside\x00")
        try:
            (self.source / "sample.bin").symlink_to(outside / "sample.bin")
            (self.source / "linked").symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation unavailable on this host")
        for name in ("sample.bin", "linked/sample.bin"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.asset(name)
        self.assertEqual(self.count(), 0)

    def test_raw_structured_and_duplicate_json_credentials_rejected(self) -> None:
        secret = "synthetic" + "-guard-test-value"
        for raw in (
            "api_" + "key=" + secret,
            json.dumps({"pass" + "word": "\n" + secret}),
            '{"notes":"one","notes":"two"}',
        ):
            self.write("sample.bin", raw)
            with (
                self.subTest(structured=raw.startswith("{")),
                self.assertRaises(ValueError),
            ):
                self.asset()
        self.assertEqual(self.count(), 0)
        self.write("sample.bin", "Safe note: use the approved local adapter.")
        self.assertEqual(self.asset()["status"], "registered")

    def test_invalid_asset_metadata_does_not_record(self) -> None:
        self.write("sample.bin", b"one\x00")
        for kwargs in (
            {"asset_kind": "executable"},
            {"asset_kind": []},
            {"build_id": ""},
            {"build_id": "api_" + "key=" + "synthetic" + "-test-value"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.asset(**kwargs)
        self.assertEqual(self.count(), 0)

    def test_finding_exact_binary_source_symbol_and_operator_evidence(self) -> None:
        self.write("sample.bin", b"MZ\x00one")
        self.write("parser.py", "def parse_header(data):\n    return len(data)\n")
        index_project_files(
            self.root,
            project_id="project-a",
            session_id="source-session",
            source_root=self.source,
            paths=["parser.py"],
        )
        source = self.records()[0]
        asset = self.asset()
        finding = self.finding(
            asset,
            address="0x401000",
            status="operator_confirmed",
            evidence=[self.citation(source)],
            source_symbol={
                "record_id": source["id"],
                "content_hash": source["content_hash"],
                "symbol": "parse_header",
            },
        )
        self.assertEqual(finding["payload"]["build_id"], "build-1")
        self.assertEqual(finding["payload"]["status"], "operator_confirmed")
        self.assertEqual(finding["payload"]["source_symbol"]["symbol"], "parse_header")
        self.assertFalse(
            next(row for row in self.query()["results"] if row["id"] == finding["id"])[
                "needs_review"
            ]
        )

    def test_finding_anchor_status_source_and_scope_fail_closed(self) -> None:
        self.write("sample.bin", b"one\x00")
        asset = self.asset()
        for kwargs in (
            {"function": None},
            {"address": "401000"},
            {"address": "0x" + "1" * 17},
            {"status": "verified"},
            {"status": "operator_confirmed"},
            {
                "source_symbol": {
                    "record_id": "missing",
                    "content_hash": "a" * 64,
                    "symbol": "x",
                }
            },
            {
                "evidence": [
                    {
                        "kind": "scroll_event",
                        "id": asset["id"],
                        "content_hash": "0" * 64,
                    }
                ]
            },
        ):
            before = self.count()
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.finding(asset, **kwargs)
            self.assertEqual(self.count(), before)
        with self.assertRaisesRegex(ValueError, "unavailable"):
            self.finding(asset, project="unrelated")
        altered = {**asset, "payload": {**asset["payload"], "source_hash": "0" * 64}}
        with self.assertRaises(ValueError):
            self.finding(altered)
        self.assertEqual(self.count(), 1)

    def test_nonbinary_finding_and_binary_annotation_rejected(self) -> None:
        self.write("sample.bin", b"one\x00")
        binary = self.asset()
        with self.assertRaises(ValueError):
            self.annotation(binary)
        image = self.asset(asset_kind="image")
        with self.assertRaises(ValueError):
            self.finding(image)
        self.assertEqual(self.count(), 2)

    def test_duplicate_source_symbol_requires_exact_line(self) -> None:
        self.write("sample.bin", b"one\x00")
        self.write(
            "parser.py",
            "def parse_header(data):\n    return 1\ndef parse_header(data):\n    return 2\n",
        )
        index_project_files(
            self.root,
            project_id="project-a",
            session_id="source-session",
            source_root=self.source,
            paths=["parser.py"],
        )
        source = self.records()[0]
        asset = self.asset()
        citation = {
            "record_id": source["id"],
            "content_hash": source["content_hash"],
            "symbol": "parse_header",
        }
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            self.finding(asset, source_symbol=citation)
        with self.assertRaises(ValueError):
            self.finding(asset, source_symbol={**citation, "line": True})
        exact = self.finding(asset, source_symbol={**citation, "line": 3})
        self.assertEqual(exact["payload"]["source_symbol"]["line"], 3)

    def test_media_page_region_table_and_time_anchors(self) -> None:
        self.write("sample.bin", b"media\x00")
        image = self.asset(asset_kind="image")
        for anchor in (
            {"page": 7},
            {"region": [0, 0.25, 1, 1]},
            {
                "table": {
                    "row_start": 1,
                    "row_end": 2,
                    "column_start": 3,
                    "column_end": 4,
                }
            },
            {"time": {"start_ms": 123, "end_ms": 456}},
        ):
            with self.subTest(anchor=anchor):
                result = self.annotation(image, anchor=anchor)
                self.assertEqual(result["payload"]["anchor"], anchor)
                self.assertEqual(
                    result["payload"]["asset_hash"], image["payload"]["source_hash"]
                )

    def test_invalid_media_anchors_are_atomic(self) -> None:
        self.write("sample.bin", b"media\x00")
        image = self.asset(asset_kind="pdf")
        for anchor in (
            {},
            {"page": True},
            {"page": 0},
            {"page": 1, "extra": "x"},
            {"region": [0, 0, 1]},
            {"region": [0, 1, 1, 0]},
            {"region": [0, 0, float("nan"), 1]},
            {"region": [0, 0, 10**1000, 1]},
            {"region": [False, 0, 1, 1]},
            {"table": {"row_start": 1}},
            {"time": {"start_ms": 10, "end_ms": 9}},
            {"time": {"start_ms": 0.5, "end_ms": 9}},
        ):
            with self.subTest(anchor=anchor), self.assertRaises(ValueError):
                self.annotation(image, anchor=anchor)
        self.assertEqual(self.count(), 1)

    def test_notebook_kinds_exact_links_and_credential_policy(self) -> None:
        first = self.note()
        for kind in ("experiment", "hypothesis", "competing_explanation", "conclusion"):
            entry = self.note(
                entry_kind=kind,
                links=[self.link(first, "contradicts")],
                evidence=[self.citation(first)],
            )
            self.assertEqual(entry["payload"]["entry_kind"], kind)
        before = self.count()
        for kwargs in (
            {"entry_kind": "truth"},
            {"notebook_id": "../bad"},
            {
                "links": [
                    {
                        "relation": "supports",
                        "target_id": first["id"],
                        "content_hash": "0" * 64,
                    }
                ]
            },
            {"links": [self.link(first), self.link(first)]},
            {"text": "api_" + "key=" + "synthetic" + "-test-value"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.note(**kwargs)
        self.assertEqual(self.count(), before)

    def test_foreign_notebook_link_is_rejected(self) -> None:
        foreign = record_notebook_entry(
            self.root,
            project_id="other",
            session_id="foreign-session",
            notebook_id="other",
            entry_kind="observation",
            title="Foreign",
            text="Foreign evidence",
        )
        with self.assertRaises(ValueError):
            self.note(links=[self.link(foreign)])
        self.assertEqual(self.query()["matched_count"], 0)

    def test_asset_versions_propagate_to_findings_and_linked_notebook(self) -> None:
        self.write("sample.bin", b"one\x00")
        first = self.asset()
        finding = self.finding(first)
        note = self.note(links=[self.link(finding)])
        self.write("sample.bin", b"two\x00")
        second = self.asset()
        by_id = {
            row["id"]: row
            for row in self.query(include_history=True, token_budget=6000)["results"]
        }
        self.assertFalse(by_id[second["id"]]["needs_review"])
        self.assertIn("newer_asset_version", by_id[first["id"]]["review_reasons"])
        self.assertIn(
            "linked_evidence_needs_review", by_id[finding["id"]]["review_reasons"]
        )
        self.assertIn(
            "linked_evidence_needs_review", by_id[note["id"]]["review_reasons"]
        )
        self.assertEqual(self.count(), 4)

    def test_explicit_disk_change_missing_and_unsafe_without_implicit_reads(
        self,
    ) -> None:
        self.write("sample.bin", b"one\x00")
        asset = self.asset()
        self.finding(asset)
        before = self.count()
        self.write("sample.bin", b"different\x00")
        with patch(
            "continuum.core.investigation._read_asset",
            side_effect=AssertionError("no implicit disk reads"),
        ):
            ordinary = self.query()
        self.assertTrue(all(not row["needs_review"] for row in ordinary["results"]))
        changed = self.query(source_root=self.source)
        self.assertTrue(all(row["needs_review"] for row in changed["results"]))
        (self.source / "sample.bin").unlink()
        missing = self.query(source_root=self.source)
        self.assertIn(
            "input_missing",
            next(row for row in missing["results"] if row["id"] == asset["id"])[
                "review_reasons"
            ],
        )
        with patch(
            "continuum.core.investigation._read_asset", side_effect=ValueError("unsafe")
        ):
            unsafe = self.query(source_root=self.source)
        self.assertIn(
            "input_unreadable_or_unsafe",
            next(row for row in unsafe["results"] if row["id"] == asset["id"])[
                "review_reasons"
            ],
        )
        self.assertEqual(self.count(), before)

    def test_changed_indexed_source_symbol_marks_finding_and_note(self) -> None:
        self.write("sample.bin", b"one\x00")
        self.write("parser.py", "def parse_header(data):\n    return len(data)\n")
        index_project_files(
            self.root,
            project_id="project-a",
            session_id="source-session",
            source_root=self.source,
            paths=["parser.py"],
        )
        source = self.records()[0]
        asset = self.asset()
        finding = self.finding(
            asset,
            source_symbol={
                "record_id": source["id"],
                "content_hash": source["content_hash"],
                "symbol": "parse_header",
            },
        )
        note = self.note(links=[self.link(finding)])
        self.write("parser.py", "def parse_header(data):\n    return 0\n")
        index_project_files(
            self.root,
            project_id="project-a",
            session_id="source-session",
            source_root=self.source,
            paths=["parser.py"],
        )
        by_id = {row["id"]: row for row in self.query(token_budget=5000)["results"]}
        self.assertTrue(by_id[finding["id"]]["needs_review"])
        self.assertTrue(by_id[note["id"]]["needs_review"])
        self.assertFalse(by_id[asset["id"]]["needs_review"])

    def test_combined_binary_media_notebook_and_stale_propagation(self) -> None:
        self.write("sample.bin", b"binary\x00")
        self.write("figure.png", b"image\x00")
        asset = self.asset()
        finding = self.finding(asset, address="0x00401000")
        media = self.asset("figure.png", asset_kind="image")
        annotation = self.annotation(media)
        note = self.note(
            entry_kind="competing_explanation",
            links=[self.link(finding), self.link(annotation, "contradicts")],
        )
        self.assertEqual(self.query(token_budget=8000)["matched_count"], 5)
        self.write("figure.png", b"updated\x00")
        current = {
            row["id"]: row
            for row in self.query(source_root=self.source, token_budget=8000)["results"]
        }
        self.assertTrue(current[annotation["id"]]["needs_review"])
        self.assertTrue(current[note["id"]]["needs_review"])
        self.assertFalse(current[finding["id"]]["needs_review"])

    def test_query_and_export_missing_roots_do_not_initialize(self) -> None:
        root = self.directory / "missing"
        self.assertEqual(
            query_investigation(root, project_id="project-a")["result_count"], 0
        )
        exported = export_investigation_notebook(
            root, project_id="project-a", notebook_id="empty"
        )
        self.assertEqual(exported["result_count"], 0)
        self.assertFalse(root.exists())

    def test_query_budget_preserves_whole_json_records_and_scope(self) -> None:
        for number in range(6):
            self.note(title=f"Observation {number}", text="evidence " * 100)
        packet = self.query(token_budget=512)
        wire = json.dumps(packet, ensure_ascii=True, separators=(",", ":"))
        self.assertLessEqual(len(wire), 512 * 4)
        self.assertEqual(packet["matched_count"], 6)
        self.assertEqual(packet["result_count"] + packet["excluded_by_budget"], 6)
        self.assertTrue(all("text" in row["payload"] for row in packet["results"]))
        self.assertEqual(
            query_investigation(self.root, project_id="other")["result_count"], 0
        )
        self.assertEqual(self.query(query="Observation 3")["matched_count"], 1)
        self.assertEqual(self.query(notebook_id="other")["matched_count"], 0)

    def test_readable_export_is_bounded_complete_and_escaped(self) -> None:
        first = self.note(
            title="Link [example](url)",
            text="<script>not code</script>\n![image](url)\n```payload``` continued",
        )
        self.note(text="x" * 7000, links=[self.link(first)])
        exported = export_investigation_notebook(
            self.root,
            project_id="project-a",
            notebook_id="parser-investigation",
            max_chars=1400,
        )
        self.assertLessEqual(len(exported["markdown"]), 1400)
        self.assertEqual(exported["result_count"], 1)
        self.assertEqual(exported["excluded_by_budget"], 1)
        self.assertIn(first["content_hash"], exported["markdown"])
        self.assertIn("&lt;script&gt;", exported["markdown"])
        self.assertNotIn("![image]", exported["markdown"])
        self.assertNotIn("```payload```", exported["markdown"])
        self.assertIn("Exported 1 of 2", exported["markdown"])

    def test_read_stored_payload_validation_fails_closed(self) -> None:
        append_record(
            self.root,
            project_id="project-a",
            session_id="test-session",
            kind="analysis_asset",
            payload={"schema": 1, "path": "../escape"},
        )
        with self.assertRaises(ValueError):
            self.query()

    def test_evidence_is_rechecked_during_query(self) -> None:
        first = self.note()
        second = self.note(evidence=[self.citation(first)])
        with patch(
            "continuum.core.investigation.validate_evidence",
            side_effect=ValueError("unavailable"),
        ):
            rows = self.query()["results"]
        self.assertIn(
            "evidence_unavailable",
            next(row for row in rows if row["id"] == second["id"])["review_reasons"],
        )

    def test_read_invalid_parameters_fail_without_writes(self) -> None:
        for kwargs in (
            {"include_history": 1},
            {"token_budget": True},
            {"token_budget": 511},
            {"query": ""},
            {"notebook_id": []},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.query(**kwargs)
        for limit in (True, 1023, 131073):
            with self.assertRaises(ValueError):
                export_investigation_notebook(
                    self.root,
                    project_id="project-a",
                    notebook_id="sample",
                    max_chars=limit,
                )
        self.assertEqual(self.count(), 0)

    def test_export_cannot_exceed_budget_with_large_header(self) -> None:
        with self.assertRaisesRegex(ValueError, "envelope"):
            export_investigation_notebook(
                self.root, project_id="&" * 250, notebook_id="a" * 128, max_chars=1024
            )


if __name__ == "__main__":
    unittest.main()
