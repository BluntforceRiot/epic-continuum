from __future__ import annotations

import hashlib
import json
import socket
import stat
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from continuum.core.config import default_config, write_config
from continuum.core.knowledge_records import append_record, read_records
from continuum.core.project_knowledge import (
    index_project_files,
    query_project_knowledge,
    record_project_knowledge,
)
from continuum.core.store import (
    _ensure_partition_alias,
    connect,
    connect_existing,
    init_db,
)


class ProjectKnowledgeTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="continuum-project-knowledge-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
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

    def write(self, name: str, text: str | bytes) -> Path:
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
        return path

    def index(self, *paths: str, project: str = "project-a") -> dict:
        return index_project_files(
            self.root,
            project_id=project,
            session_id="session-a",
            source_root=self.source,
            paths=list(paths),
        )

    def record(self, *, project: str = "project-a", **kwargs) -> dict:
        values = {
            "kind": "decision",
            "title": "Use bounded parser",
            "summary": "Keep exact source anchors.",
        }
        values.update(kwargs)
        return record_project_knowledge(
            self.root, project_id=project, session_id="session-a", **values
        )

    def query(self, **kwargs) -> dict:
        return query_project_knowledge(self.root, project_id="project-a", **kwargs)

    def records(self, project: str = "project-a") -> list[dict]:
        return read_records(self.root, project_id=project)

    def count(self) -> int:
        with closing(connect_existing(self.root)) as conn:
            return conn.execute("SELECT COUNT(*) FROM scroll_events").fetchone()[0]

    def test_python_symbols_imports_hash_and_lines_without_execution(self) -> None:
        text = "import os as operating\nfrom .utils import helper\n\nclass Example:\n    async def run(self):\n        return 3\n\nraise RuntimeError('never execute')\n"
        self.write("pkg/module.py", text)
        result = self.index("pkg/module.py")
        self.assertEqual(result["indexed"], 1)
        record = self.records()[0]
        payload = record["payload"]
        self.assertEqual(
            payload["source_hash"], hashlib.sha256(text.encode()).hexdigest()
        )
        self.assertEqual(payload["bytes"], len(text.encode()))
        self.assertEqual(payload["line_count"], 8)
        self.assertEqual(
            payload["symbols"],
            [
                {"name": "Example", "kind": "class", "line": 4, "end_line": 6},
                {
                    "name": "Example.run",
                    "kind": "async_function",
                    "line": 5,
                    "end_line": 6,
                },
            ],
        )
        self.assertEqual(payload["imports"][0]["module"], "os")
        self.assertEqual(payload["imports"][0]["alias"], "operating")
        self.assertEqual(payload["imports"][1]["module"], ".utils")
        encoded = json.dumps(record)
        self.assertNotIn(str(self.source), encoded)
        self.assertNotIn("never execute", encoded)
        self.assertFalse(result["source_text_stored"])

    def test_original_utf8_bom_and_crlf_hash_is_exact(self) -> None:
        raw = b"\xef\xbb\xbfdef hello():\r\n    return 1\r\n"
        self.write("module.py", raw)
        self.index("module.py")
        payload = self.records()[0]["payload"]
        self.assertEqual(payload["source_hash"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(payload["symbols"][0]["line"], 1)
        self.assertEqual(payload["symbols"][0]["end_line"], 2)

    def test_text_file_records_do_not_invent_symbols(self) -> None:
        self.write("notes.md", "Some ordinary project context.\n")
        self.index("notes.md")
        payload = self.records()[0]["payload"]
        self.assertEqual(payload["language"], "text")
        self.assertEqual(payload["symbols"], [])
        self.assertEqual(payload["imports"], [])

    def test_idempotence_versions_and_history(self) -> None:
        self.write("notes.md", "Original context")
        first = self.index("notes.md")
        count = self.count()
        second = self.index("notes.md")
        self.assertEqual(second["indexed"], 0)
        self.assertEqual(second["unchanged"], 1)
        self.assertEqual(first["files"][0]["id"], second["files"][0]["id"])
        self.assertEqual(self.count(), count)
        self.write("notes.md", "Revised context")
        third = self.index("notes.md")
        self.assertEqual(third["files"][0]["version"], 2)
        self.assertNotEqual(first["files"][0]["id"], third["files"][0]["id"])
        self.assertEqual(len(self.records()), 2)
        self.assertEqual(len(self.query()["results"]), 1)
        history = self.query(include_history=True)["results"]
        self.assertEqual(len(history), 2)
        old = next(
            record for record in history if record["id"] == first["files"][0]["id"]
        )
        self.assertTrue(old["needs_review"])
        self.assertIn("newer_file_version", old["review_reasons"])

    def test_case_alias_continues_history_and_stales_dependent(self) -> None:
        path = self.write("module.py", "def original():\n    pass\n")
        alias = self.source / "MODULE.PY"
        if not alias.exists() or not alias.samefile(path):
            self.skipTest("fixture filesystem treats the case variants as distinct")
        first = self.index("module.py")["files"][0]
        decision = self.record(
            links=[{"relation": "depends_on", "target_id": first["id"]}]
        )
        self.write("module.py", "def revised():\n    pass\n")
        second = self.index("MODULE.PY")["files"][0]
        self.assertEqual(second["version"], 2)
        self.assertEqual(second["path"], first["path"])
        packet = self.query(token_budget=32768)
        files = [row for row in packet["results"] if row["kind"] == "project_file"]
        self.assertEqual([row["id"] for row in files], [second["id"]])
        dependent = next(
            row for row in packet["results"] if row["id"] == decision["id"]
        )
        self.assertTrue(dependent["needs_review"])
        self.assertEqual(packet["freshness"], "recorded_versions_only")
        self.assertEqual(len(self.records()), 3)

    def test_duplicate_case_aliases_in_one_pass_capture_nothing(self) -> None:
        path = self.write("module.py", "def original():\n    pass\n")
        alias = self.source / "MODULE.PY"
        if not alias.exists() or not alias.samefile(path):
            self.skipTest("fixture filesystem treats the case variants as distinct")
        with self.assertRaisesRegex(ValueError, "aliases"):
            self.index("module.py", "MODULE.PY")
        self.assertEqual(self.count(), 0)

    def test_case_sensitive_distinct_files_have_distinct_histories(self) -> None:
        lower = self.write("module.py", "def lower():\n    pass\n")
        upper = self.source / "MODULE.PY"
        if upper.exists() and upper.samefile(lower):
            self.skipTest("fixture filesystem aliases case variants")
        self.write("MODULE.PY", "def upper():\n    pass\n")
        self.assertFalse(upper.samefile(lower))
        result = self.index("module.py", "MODULE.PY")
        self.assertEqual(result["indexed"], 2)
        self.assertEqual(
            {file["path"] for file in result["files"]}, {"module.py", "MODULE.PY"}
        )
        self.assertEqual([file["version"] for file in result["files"]], [1, 1])
        self.write("module.py", "def changed_lower():\n    pass\n")
        changed = self.index("module.py")["files"][0]
        current = self.query(token_budget=32768)["results"]
        self.assertEqual(len(current), 2)
        self.assertEqual(changed["version"], 2)
        self.assertEqual(
            next(
                row["payload"]["version"]
                for row in current
                if row["payload"]["path"] == "MODULE.PY"
            ),
            1,
        )

    def test_existing_alias_spelling_and_evidence_are_not_rewritten(self) -> None:
        path = self.write("module.py", "def original():\n    pass\n")
        alias = self.source / "MODULE.PY"
        if not alias.exists() or not alias.samefile(path):
            self.skipTest("fixture filesystem treats the case variants as distinct")
        self.index("module.py")
        legacy_payload = {**self.records()[0]["payload"], "path": "MODULE.PY"}
        legacy = append_record(
            self.root,
            project_id="legacy-project",
            session_id="session-a",
            kind="project_file",
            payload=legacy_payload,
        )
        self.write("module.py", "def revised():\n    pass\n")
        result = self.index("module.py", project="legacy-project")["files"][0]
        self.assertEqual(result["path"], "MODULE.PY")
        self.assertEqual(result["version"], 2)
        records = self.records("legacy-project")
        self.assertEqual(records[0], legacy)
        self.assertEqual(len(records), 2)

    def test_invalid_last_file_leaves_no_partial_first_capture(self) -> None:
        self.write("okay.py", "def good():\n    return 1\n")
        self.write("bad.py", "def broken(:")
        before = self.count()
        with self.assertRaisesRegex(ValueError, "parsed"):
            self.index("okay.py", "bad.py")
        self.assertEqual(self.count(), before)

    def test_explicit_files_only_no_directory_crawl(self) -> None:
        self.write("safe.txt", "Ordinary text")
        self.write("not-requested.txt", "api_" + "key=" + "x" * 30)
        self.index("safe.txt")
        self.assertEqual(
            [record["payload"]["path"] for record in self.records()], ["safe.txt"]
        )

    def test_paths_reject_escape_absolute_ads_and_nonregular_inputs(self) -> None:
        self.write("safe.txt", "Ordinary text")
        for path in (
            "../outside.txt",
            "/outside.txt",
            "C:/outside.txt",
            "C:outside.txt",
            "safe.txt:stream",
            "./safe.txt",
            "safe.txt/",
            "safe.txt.",
            "safe.txt ",
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.index(path)
        with self.assertRaises(ValueError):
            self.index("missing-directory")
        (self.source / "directory").mkdir()
        with self.assertRaises(ValueError):
            self.index("directory")
        self.assertEqual(self.count(), 0)

    def test_relative_source_root_and_duplicate_paths_rejected(self) -> None:
        self.write("safe.txt", "Ordinary text")
        with self.assertRaises(ValueError):
            index_project_files(
                self.root,
                project_id="project-a",
                session_id="session-a",
                source_root="relative",
                paths=["safe.txt"],
            )
        with self.assertRaises(ValueError):
            self.index("safe.txt", "safe.txt")
        for paths in ([], ["safe.txt"] * 33, "safe.txt"):
            with self.subTest(paths=type(paths)), self.assertRaises(ValueError):
                index_project_files(
                    self.root,
                    project_id="project-a",
                    session_id="session-a",
                    source_root=self.source,
                    paths=paths,
                )

    def test_link_files_and_link_parents_rejected(self) -> None:
        outside = self.directory / "outside"
        outside.mkdir()
        (outside / "input.txt").write_text("not in source", encoding="utf-8")
        try:
            (self.source / "linked.txt").symlink_to(outside / "input.txt")
            (self.source / "linked-dir").symlink_to(outside, target_is_directory=True)
        except OSError:
            self.skipTest("symlink creation is unavailable on this host")
        for name in ("linked.txt", "linked-dir/input.txt"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.index(name)
        with self.assertRaises(ValueError):
            index_project_files(
                self.root,
                project_id="project-a",
                session_id="session-a",
                source_root=self.source / "linked-dir",
                paths=["input.txt"],
            )
        self.assertEqual(self.count(), 0)

    def test_binary_oversized_and_non_utf8_files_rejected(self) -> None:
        for content in (b"binary\x00text", b"\xff", b"x" * (1024 * 1024 + 1)):
            self.write("input.txt", content)
            with self.subTest(size=len(content)), self.assertRaises(ValueError):
                self.index("input.txt")
        self.assertEqual(self.count(), 0)

    def test_windows_reparse_attribute_blocks_even_regular_file_mode(self) -> None:
        self.write("safe.txt", "context")
        original = Path.lstat

        def reparse(path, *args, **kwargs):
            if path.name == "safe.txt":
                return SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=1024)
            return original(path, *args, **kwargs)

        with (
            patch.object(Path, "lstat", reparse),
            self.assertRaisesRegex(ValueError, "non-link"),
        ):
            self.index("safe.txt")
        self.assertEqual(self.count(), 0)

    def test_credential_text_and_structured_newline_values_blocked(self) -> None:
        secret = "synthetic" + "-value-for-guard-regression"
        for text in (
            "api_" + "key=" + secret,
            json.dumps({"pass" + "word": "\n" + secret}),
        ):
            self.write("input.json", text)
            with (
                self.subTest(structured=text.startswith("{")),
                self.assertRaisesRegex(ValueError, "credential"),
            ):
                self.index("input.json")
        with self.assertRaisesRegex(ValueError, "credential"):
            self.record(summary="api_" + "key=" + secret)
        self.assertEqual(self.count(), 0)

    def test_duplicate_json_keys_cannot_hide_escaped_credentials(self) -> None:
        self.write("safe.txt", "Ordinary project note")
        hidden = json.dumps("\n" + "sk-" + "fixture" * 6)
        for nested in (False, True):
            duplicate = '{"notes":' + hidden + ',"notes":"ordinary"}'
            text = '{"outer":' + duplicate + "}" if nested else duplicate
            # The existing raw-text scan cannot inspect the discarded JSON
            # value after normal json.loads has collapsed duplicate keys.
            self.write("notes.json", text)
            with (
                self.subTest(nested=nested),
                self.assertRaisesRegex(ValueError, "duplicate"),
            ):
                self.index("safe.txt", "notes.json")
            self.assertEqual(self.count(), 0)
        self.write("notes.json", '{"notes":"one","notes":"two"}')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.index("notes.json")
        self.assertEqual(self.count(), 0)

    def test_json_integer_limit_cannot_bypass_credential_admission(self) -> None:
        previous_limit = sys.get_int_max_str_digits()
        sys.set_int_max_str_digits(4300)
        self.addCleanup(sys.set_int_max_str_digits, previous_limit)
        ordinary = "Safe project note: this is ordinary non-JSON prose."
        self.write("safe.txt", ordinary)
        wire = json.dumps({"notes": "heading\n" + "sk-" + "A" * 30})
        content = wire[:-1] + ', "number": ' + "9" * 5000 + "}"
        with self.assertRaises(ValueError) as failed_decoder:
            json.loads(content)
        self.assertNotIsInstance(failed_decoder.exception, json.JSONDecodeError)
        self.write("limited.json", content)
        with self.assertRaisesRegex(ValueError, "analysis limits"):
            self.index("safe.txt", "limited.json")
        self.assertEqual(self.count(), 0)
        result = self.index("safe.txt")
        self.assertEqual(result["indexed"], 1)
        self.assertEqual(
            self.records()[0]["payload"]["source_hash"],
            hashlib.sha256(ordinary.encode()).hexdigest(),
        )

    def test_analysis_cap_fails_not_silent_symbol_loss(self) -> None:
        self.write(
            "many.py", "\n".join(f"def function_{i}():\n    pass" for i in range(257))
        )
        with self.assertRaisesRegex(ValueError, "256-symbol"):
            self.index("many.py")
        self.write("many.py", "\n".join(f"import module_{i}" for i in range(257)))
        with self.assertRaisesRegex(ValueError, "256-import"):
            self.index("many.py")
        self.assertEqual(self.count(), 0)

    def test_links_are_typed_same_project_existing_and_transactional(self) -> None:
        self.write("file.txt", "file one")
        source = self.index("file.txt")["files"][0]["id"]
        decision = self.record(links=[{"relation": "depends_on", "target_id": source}])
        self.assertEqual(decision["payload"]["links"][0]["target_id"], source)
        for links in (
            [{"relation": "magic", "target_id": source}],
            [{"relation": "depends_on", "target_id": "missing"}],
            [{"relation": "depends_on", "target_id": source, "extra": 1}],
        ):
            before = self.count()
            with self.subTest(links=links), self.assertRaises(ValueError):
                self.record(links=links)
            self.assertEqual(self.count(), before)
        before = self.count()
        with self.assertRaisesRegex(ValueError, "unavailable"):
            self.record(
                project="project-b",
                links=[{"relation": "depends_on", "target_id": source}],
            )
        self.assertEqual(self.count(), before)
        self.assertEqual(self.records("project-b"), [])

    def test_all_knowledge_kinds_and_relations_are_retained(self) -> None:
        self.write("file.txt", "file context")
        source = self.index("file.txt")["files"][0]["id"]
        for kind in ("decision", "test", "error", "fix", "note"):
            result = self.record(
                kind=kind, links=[{"relation": "related_to", "target_id": source}]
            )
            self.assertEqual(result["payload"]["kind"], kind)
        for relation in ("depends_on", "supports", "contradicts", "fixes", "tests"):
            self.record(links=[{"relation": relation, "target_id": source}])
        self.assertEqual(len(self.records()), 11)

    def test_disk_change_and_missing_propagate_through_link_chain(self) -> None:
        path = self.write("file.txt", "file context")
        source = self.index("file.txt")["files"][0]["id"]
        decision = self.record(links=[{"relation": "depends_on", "target_id": source}])
        test = self.record(
            kind="test", links=[{"relation": "tests", "target_id": decision["id"]}]
        )
        original = self.query(source_root=self.source)
        self.assertTrue(all(not item["needs_review"] for item in original["results"]))
        before = self.count()
        path.write_text("modified", encoding="utf-8")
        changed = self.query(source_root=self.source)
        self.assertTrue(all(item["needs_review"] for item in changed["results"]))
        self.assertEqual(
            {item["id"] for item in changed["results"]},
            {source, decision["id"], test["id"]},
        )
        self.assertEqual(self.count(), before)
        without_disk = self.query()
        self.assertTrue(
            all(not item["needs_review"] for item in without_disk["results"])
        )
        path.unlink()
        missing = self.query(source_root=self.source)
        file_record = next(
            item for item in missing["results"] if item["kind"] == "project_file"
        )
        self.assertIn("file_missing", file_record["review_reasons"])

    def test_recorded_new_version_marks_old_dependents_without_disk_access(
        self,
    ) -> None:
        path = self.write("file.txt", "old")
        old = self.index("file.txt")["files"][0]["id"]
        decision = self.record(links=[{"relation": "depends_on", "target_id": old}])
        path.write_text("new", encoding="utf-8")
        new = self.index("file.txt")["files"][0]["id"]
        result = self.query()
        self.assertNotIn(old, {item["id"] for item in result["results"]})
        by_id = {item["id"]: item for item in result["results"]}
        self.assertTrue(by_id[decision["id"]]["needs_review"])
        self.assertFalse(by_id[new]["needs_review"])
        self.assertEqual(len(self.records()), 3)

    def test_hidden_link_target_is_not_returned_or_treated_fresh(self) -> None:
        self.write("file.txt", "context")
        source = self.index("file.txt")["files"][0]["id"]
        decision = self.record(links=[{"relation": "depends_on", "target_id": source}])
        with closing(connect(self.root)) as conn:
            conn.execute(
                "UPDATE scroll_events SET visibility_scope='private' WHERE id=?",
                (source,),
            )
            conn.commit()
        result = self.query()
        self.assertEqual([item["id"] for item in result["results"]], [decision["id"]])
        self.assertTrue(result["results"][0]["needs_review"])
        with self.assertRaises(ValueError):
            self.record(links=[{"relation": "depends_on", "target_id": source}])

    def test_exact_evidence_citation_and_stale_record_propagation(self) -> None:
        self.write("file.txt", "old")
        source = self.index("file.txt")["files"][0]["id"]
        file_record = self.records()[0]
        citation = {
            "kind": "scroll_event",
            "id": source,
            "content_hash": file_record["content_hash"],
        }
        note = self.record(evidence=[citation])
        self.assertEqual(note["payload"]["evidence"], [citation])
        bad = {**citation, "content_hash": "0" * 64}
        with self.assertRaises(ValueError):
            self.record(evidence=[bad])
        self.write("file.txt", "new")
        self.index("file.txt")
        result = self.query()
        returned = next(item for item in result["results"] if item["id"] == note["id"])
        self.assertTrue(returned["needs_review"])

    def test_query_budget_and_read_only_filter_are_truthful(self) -> None:
        for i in range(8):
            self.record(
                title=f"Decision {i}",
                summary=("Special datum " if i == 2 else "ordinary data ") * 80,
            )
        before = self.count()
        packet = self.query(token_budget=512)
        self.assertLessEqual(
            len(json.dumps(packet, ensure_ascii=True, separators=(",", ":"))), 2048
        )
        self.assertEqual(packet["matched_count"], 8)
        self.assertEqual(packet["result_count"] + packet["excluded_by_budget"], 8)
        filtered = self.query(query="Special datum", token_budget=4096)
        self.assertEqual(filtered["matched_count"], 1)
        self.assertEqual(filtered["results"][0]["payload"]["title"], "Decision 2")
        self.assertEqual(self.count(), before)

    def test_missing_memory_query_does_not_create_root(self) -> None:
        missing = self.directory / "missing-memory"
        packet = query_project_knowledge(missing, project_id="project-a")
        self.assertEqual(packet["results"], [])
        self.assertFalse(missing.exists())

    def test_existing_display_aliases_share_canonical_project_authority(self) -> None:
        project = "Project display name"
        session = "Session display name"
        canonical = _ensure_partition_alias(self.root, "project_id", project)
        canonical_session = _ensure_partition_alias(self.root, "session_id", session)
        self.write("file.txt", "context")
        indexed = index_project_files(
            self.root,
            project_id=project,
            session_id=session,
            source_root=self.source,
            paths=["file.txt"],
        )
        self.assertEqual(indexed["project_id"], canonical)
        note = record_project_knowledge(
            self.root,
            project_id=project,
            session_id=session,
            kind="note",
            title="Recorded scope",
            summary="The named scope resolves to its established alias.",
            links=[{"relation": "depends_on", "target_id": indexed["files"][0]["id"]}],
        )
        self.assertEqual(note["project_id"], canonical)
        self.assertEqual(note["session_id"], canonical_session)
        aliased = query_project_knowledge(self.root, project_id=project)
        opaque = query_project_knowledge(self.root, project_id=canonical)
        self.assertEqual(aliased, opaque)
        self.assertEqual(aliased["matched_count"], 2)

    def test_malformed_typed_payload_fails_closed(self) -> None:
        append_record(
            self.root,
            project_id="project-a",
            session_id="session-a",
            kind="project_file",
            payload={"schema": 1, "path": "../escape"},
        )
        with self.assertRaisesRegex(ValueError, "malformed"):
            self.query(source_root=self.source)

    def test_callback_duplicate_race_rolls_back_to_existing(self) -> None:
        self.write("file.txt", "same")
        first = self.index("file.txt")["files"][0]["id"]
        import continuum.core.project_knowledge as module

        original = module._records
        calls = 0

        def stale_read(*args, **kwargs):
            nonlocal calls
            calls += 1
            rows = original(*args, **kwargs)
            return [] if calls == 1 else rows

        before = self.count()
        with patch.object(module, "_records", side_effect=stale_read):
            result = self.index("file.txt")
        self.assertEqual(result["files"][0]["id"], first)
        self.assertEqual(result["unchanged"], 1)
        self.assertEqual(self.count(), before)

    def test_callback_conflicting_race_rolls_back_insert(self) -> None:
        self.write("file.txt", "old")
        self.index("file.txt")
        first = self.records()[0]
        self.write("file.txt", "concurrent")
        self.index("file.txt")
        self.write("file.txt", "requested")
        import continuum.core.project_knowledge as module

        original = module._records
        calls = 0

        def stale_read(*args, **kwargs):
            nonlocal calls
            calls += 1
            rows = original(*args, **kwargs)
            return [first] if calls == 1 else rows

        before = self.count()
        with (
            patch.object(module, "_records", side_effect=stale_read),
            self.assertRaisesRegex(ValueError, "concurrently"),
        ):
            self.index("file.txt")
        self.assertEqual(self.count(), before)

    def test_malformed_arguments_fail_without_record_mutation(self) -> None:
        for changes in (
            {"kind": "invented"},
            {"title": ""},
            {"summary": ""},
            {"links": "wrong"},
            {"evidence": "wrong"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.record(**changes)
        for values in ({"token_budget": True}, {"include_history": 1}, {"query": ""}):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.query(**values)
        self.assertEqual(self.count(), 0)


if __name__ == "__main__":
    unittest.main()
