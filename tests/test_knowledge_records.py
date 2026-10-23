from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from continuum.core.config import default_config, write_config
from continuum.core.knowledge_records import (
    append_record,
    bounded_results,
    read_records,
    require_text,
    require_timestamp,
    validate_evidence,
)
from continuum.core.recall import read_memory_source
from continuum.core.store import (
    append_scroll_event,
    connect,
    connect_existing,
    create_card,
    init_db,
)
from continuum.core.tool_outputs import record_indexed_tool_result


class KnowledgeRecordsTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="continuum-knowledge-records-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / "memory"
        config = default_config()
        config["capture"]["mode"] = "manual"
        config["capture"]["dedup_window_seconds"] = 0
        config["local_inference"]["enabled"] = False
        write_config(self.root, config)
        init_db(self.root)

    def record(self, **changes) -> dict:
        arguments = {"project_id": "project-a", "session_id": "session-a",
                     "kind": "project_knowledge", "payload": {"note": "safe explicit claim"}}
        arguments.update(changes)
        return append_record(self.root, **arguments)

    def records(self, **changes) -> list[dict]:
        arguments = {"project_id": "project-a"}
        arguments.update(changes)
        return read_records(self.root, **arguments)

    def snapshot(self) -> dict[str, list[tuple]]:
        with closing(connect_existing(self.root)) as conn:
            names = [row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )]
            return {name: sorted((tuple(row) for row in conn.execute(f'SELECT * FROM "{name}"')), key=repr)
                    for name in names}

    def source(self, kind: str, scope: str, project: str | None = None) -> dict[str, str]:
        text = "Review located the test fixture without credential material."
        metadata = {"visibility_scope": scope, "continuum_disable_exact_memory": True}
        if project is not None:
            metadata["project_id"] = project
        if kind == "scroll_event":
            event = append_scroll_event(self.root, session_id="source-session", event_type="message",
                                        role="user", content=text, metadata=metadata)
            source_id = event["event_id"]
        elif kind == "card":
            title = "Safe fixture"
            with closing(connect(self.root)) as conn:
                source_id = create_card(conn, root=self.root, card_type="decision", title=title,
                                        summary=text, source_refs=[], visibility_scope=scope,
                                        project_id=project, session_id="source-session")
                conn.commit()
            text = title + "\n" + text
        else:
            output = record_indexed_tool_result(
                self.root, session_id="source-session", event_type="tool_result", text=text,
                metadata=metadata, max_reference_bytes=128,
            )
            with closing(connect_existing(self.root)) as conn:
                row = conn.execute("SELECT id,text FROM chunks WHERE book_id=? ORDER BY ordinal", (output["book_id"],)).fetchone()
            source_id, text = row["id"], row["text"]
        return {"kind": kind, "id": source_id, "content_hash": hashlib.sha256(text.encode()).hexdigest()}

    def test_missing_root_reads_and_empty_citations_do_not_create_root(self) -> None:
        root = self.directory / "absent"
        self.assertEqual(read_records(root, project_id="project-a"), [])
        self.assertEqual(validate_evidence(root, "project-a", None), [])
        self.assertEqual(validate_evidence(root, "project-a", []), [])
        self.assertFalse(root.exists())

    def test_roundtrip_stable_order_and_kind_filter(self) -> None:
        with patch("continuum.core.store.utc_now", return_value="2025-01-01T00:00:00+00:00"):
            first = self.record(payload={"note": "first"})
            second = self.record(kind="temporal_fact", payload={"note": "second"})
        self.assertEqual(self.records(), [first, second])
        self.assertEqual(self.records(kinds=["temporal_fact"]), [second])
        self.assertLess(first["order"], second["order"])
        self.assertEqual(first["recorded_at"], second["recorded_at"])
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(self.records(project_id="project-b"), [])

    def test_callback_sees_inserted_row_in_same_transaction(self) -> None:
        observed = []

        def callback(conn, record) -> None:
            self.assertTrue(conn.in_transaction)
            rows = read_records(self.root, project_id="project-a", connection=conn)
            self.assertEqual(rows, [record])
            observed.append(copy.deepcopy(record))

        result = self.record(validate=callback)
        self.assertEqual(observed, [result])
        self.assertEqual(self.records(), [result])

    def test_callback_exception_rolls_back_new_record_and_callback_changes(self) -> None:
        first = self.record()
        # Drain existing graph-source backfill before taking the transaction
        # baseline. Capture's normal init_db preflight is outside its write unit.
        init_db(self.root)
        before = self.snapshot()
        attempted = []

        def callback(conn, record) -> None:
            self.assertTrue(conn.in_transaction)
            self.assertEqual(len(read_records(self.root, project_id="project-a", connection=conn)), 2)
            attempted.append(record["id"])
            conn.execute("UPDATE scroll_events SET role='assistant' WHERE id=?", (first["id"],))
            raise ValueError("fixture rejected transaction")

        with self.assertRaisesRegex(ValueError, "fixture rejected transaction"):
            self.record(payload={"note": "rejected"}, validate=callback)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.records(), [first])
        self.assertNotEqual(attempted, [])
        self.assertNotIn(attempted[0], repr(self.snapshot()))

    def test_actual_reader_enforces_project_citation_partition_for_all_kinds(self) -> None:
        for kind in ("card", "scroll_event", "chunk"):
            for scope, project, admitted in (("project", "project-a", True),
                                             ("project", "project-b", False),
                                             ("global", None, False), ("private", None, False),
                                             ("session", None, False)):
                with self.subTest(kind=kind, scope=scope, project=project):
                    citation = self.source(kind, scope, project)
                    direct = read_memory_source(self.root, kind=kind, source_id=citation["id"],
                                                content_hash=citation["content_hash"],
                                                project_id="project-a", limit=1)
                    self.assertIs(direct["found"], admitted)
                    with patch("continuum.core.knowledge_records.read_memory_source", wraps=read_memory_source) as reader:
                        if admitted:
                            self.assertEqual(validate_evidence(self.root, "project-a", [citation]), [citation])
                        else:
                            with self.assertRaises(ValueError):
                                validate_evidence(self.root, "project-a", [citation])
                        reader.assert_called_once()
                        self.assertEqual(reader.call_args.kwargs["project_id"], "project-a")
                        self.assertEqual(reader.call_args.kwargs["content_hash"], citation["content_hash"])

    def test_evidence_requires_hash_currentness_and_unique_exact_references(self) -> None:
        citation = self.source("card", "project", "project-a")
        self.assertEqual(validate_evidence(self.root, "project-a", [citation]), [citation])
        for items in ([{**citation, "content_hash": "0" * 64}], [citation, citation],
                      [{**citation, "extra": "unrecognized"}], [{**citation, "id": "absent"}],
                      [{**citation, "kind": "shell"}], [citation] * 17):
            with self.subTest(items=items), self.assertRaises(ValueError):
                validate_evidence(self.root, "project-a", items)
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE cards SET status='superseded' WHERE id=?", (citation["id"],))
            conn.commit()
        with self.assertRaises(ValueError):
            validate_evidence(self.root, "project-a", [citation])

    def test_malformed_visible_record_is_not_hidden_by_kind_filter(self) -> None:
        record = self.record()
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE scroll_events SET content=? WHERE id=?", ("{broken", record["id"]))
            conn.commit()
        with self.assertRaisesRegex(ValueError, "malformed"):
            self.records(kinds=["temporal_fact"])

    def test_hash_mismatch_fails_closed(self) -> None:
        record = self.record()
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE scroll_events SET content_hash=? WHERE id=?", ("0" * 64, record["id"]))
            conn.commit()
        with self.assertRaisesRegex(ValueError, "malformed"):
            self.records()

    def test_invalid_envelope_and_mismatched_metadata_fail_closed(self) -> None:
        record = self.record()
        with closing(connect(self.root)) as conn:
            original = conn.execute("SELECT content,metadata_json FROM scroll_events WHERE id=?", (record["id"],)).fetchone()
            envelope = json.loads(original["content"])
            for key, invalid in (("schema", "unknown"), ("nonce", "bad"), ("project_id", "project-b"),
                                 ("payload", []), ("kind", "unsupported")):
                with self.subTest(key=key):
                    changed = {**envelope, key: invalid}
                    text = json.dumps(changed, sort_keys=True, separators=(",", ":"))
                    conn.execute("UPDATE scroll_events SET content=?,content_hash=? WHERE id=?",
                                 (text, hashlib.sha256(text.encode()).hexdigest(), record["id"]))
                    conn.commit()
                    with self.assertRaisesRegex(ValueError, "malformed"):
                        self.records()
            conn.execute("UPDATE scroll_events SET content=?,content_hash=?,metadata_json=? WHERE id=?",
                         (original["content"], hashlib.sha256(original["content"].encode()).hexdigest(), "{}", record["id"]))
            conn.commit()
        with self.assertRaisesRegex(ValueError, "malformed"):
            self.records()

    def test_other_project_corruption_does_not_cross_partition(self) -> None:
        expected = self.record()
        other = self.record(project_id="project-b")
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE scroll_events SET content='bad' WHERE id=?", (other["id"],))
            conn.commit()
        self.assertEqual(self.records(), [expected])
        with self.assertRaises(ValueError):
            self.records(project_id="project-b")

    def test_count_bound_is_fail_closed_before_kind_filter(self) -> None:
        first = self.record(kind="temporal_fact")
        self.record(kind="project_file")
        self.record(kind="project_knowledge")
        self.assertEqual(len(self.records(max_records=3)), 3)
        self.assertEqual(self.records(max_records=3, kinds=["temporal_fact"]), [first])
        with self.assertRaisesRegex(ValueError, "read bound"):
            self.records(max_records=2)
        with self.assertRaisesRegex(ValueError, "read bound"):
            self.records(max_records=2, kinds=["temporal_fact"])
        for maximum in (0, -1, True, 100001, 1.0):
            with self.subTest(maximum=maximum), self.assertRaises(ValueError):
                self.records(max_records=maximum)

    def test_plaintext_and_newline_structured_credentials_block_before_capture(self) -> None:
        before = self.snapshot()
        secret = "synthetic" + "-not-a-real-binding"
        payloads = (
            {"note": "api_" + "key=" + secret},
            {"metadata": {"pass" + "word": "\n" + secret}},
            {"metadata": {"notes": "safe heading\n" + "access_" + "token=" + secret}},
            {"metadata": [{"notes": "heading\r\n" + "api_" + "key=" + secret}]},
        )
        for payload in payloads:
            with self.subTest(payload=payload), patch("continuum.core.knowledge_records.append_scroll_event") as capture:
                with self.assertRaisesRegex(ValueError, "credential"):
                    self.record(payload=payload)
                capture.assert_not_called()
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn(secret, repr(self.snapshot()))

    def test_credential_rejection_does_not_depend_on_redaction_policy(self) -> None:
        config = default_config()
        config["security"]["secret_scan_action"] = "warn"
        write_config(self.root, config)
        secret = "synthetic" + "-not-a-real-binding"
        with patch("continuum.core.knowledge_records.append_scroll_event") as capture:
            with self.assertRaisesRegex(ValueError, "credential"):
                self.record(payload={"password": "\n" + secret})
            capture.assert_not_called()
        self.assertEqual(self.records(), [])

    def test_structural_limits_reject_without_capture(self) -> None:
        nested = {}
        for _ in range(18):
            nested = {"nested": nested}
        payloads = ({"text": "界" * 30000}, {"text": "x" * 65537}, {"bad": float("nan")},
                    {"bad": object()}, {"bad": 2**64}, nested, {"bad": ("tuple",)},
                    {"bad": "\ud800"})
        for payload in payloads:
            with self.subTest(kind=type(payload)), patch("continuum.core.knowledge_records.append_scroll_event") as capture:
                with self.assertRaises(ValueError):
                    self.record(payload=payload)
                capture.assert_not_called()
        self.assertEqual(self.records(), [])

    def test_whole_packet_unicode_budget_preserves_complete_items_and_input(self) -> None:
        records = [{"id": str(index), "text": "🧠" * (100 + index * 100)} for index in range(8)]
        original = copy.deepcopy(records)
        for budget in (512, 1024, 2400):
            with self.subTest(budget=budget):
                packet = bounded_results(records, token_budget=budget, extra={"mode": "history"})
                text = json.dumps(packet, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
                self.assertLessEqual(len(text), budget * 4)
                self.assertEqual(json.loads(text), packet)
                self.assertEqual(packet["budget"]["estimated_tokens"], (len(text) + 3) // 4)
                self.assertEqual(packet["results"], records[:packet["result_count"]])
                self.assertEqual(packet["matched_count"], len(records))
                self.assertEqual(packet["excluded_by_budget"], len(records) - packet["result_count"])
                self.assertEqual(packet["instruction_authority"], "none")
        self.assertEqual(records, original)
        with self.assertRaises(ValueError):
            bounded_results([], token_budget=512, extra={"unbounded": "🧠" * 1000})

    def test_text_timestamp_and_packet_inputs_are_strict(self) -> None:
        self.assertEqual(require_text("hello", "fixture", 5), "hello")
        for value in ("", " ", 1, None, "a\x00b", "\ud800", "sixsix"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                require_text(value, "fixture", 5)
        self.assertEqual(require_timestamp("2025-01-01T05:00:00+05:00", "time"), "2025-01-01T00:00:00+00:00")
        for value in (None, "", "2025-01-01", "2025-01-01T00:00:00", "not-a-date"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                require_timestamp(value, "time")
        for budget in (0, 511, 32769, True, 512.0):
            with self.subTest(budget=budget), self.assertRaises(ValueError):
                bounded_results([], token_budget=budget)

    def test_read_only_operations_preserve_durable_tables(self) -> None:
        record = self.record()
        before = self.snapshot()
        self.assertEqual(self.records(), [record])
        self.assertEqual(self.records(kinds=["temporal_fact"]), [])
        bounded_results(self.records(), token_budget=512)
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
