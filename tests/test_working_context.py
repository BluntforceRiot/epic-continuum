from __future__ import annotations

import copy
import hashlib
import json
import socket
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from continuum.core.config import default_config, write_config
from continuum.core.coordination import create_collection
from continuum.core.knowledge_records import read_records
from continuum.core.project_knowledge import index_project_files, record_project_knowledge
from continuum.core.store import append_scroll_event, connect, connect_existing, init_db
from continuum.core.working_context import (
    change_impact,
    compile_task_pack,
    explain_memory,
    prepare_working_chat_request,
    select_working_context,
)


def tool_pair(identity="call-1", content=None):
    return [
        {"role": "assistant", "content": None, "tool_calls": [
            {"id": identity, "type": "function", "function": {"name": "session_search", "arguments": '{"limit":8}'}}]},
        {"role": "tool", "tool_call_id": identity, "content": content or json.dumps({"messages": ["a" * 9000]})},
    ]


class WorkingSelectionTests(unittest.TestCase):
    def messages(self, image_bytes=7_980_000):
        return [
            {"role": "system", "content": "Stable instructions"},
            {"role": "user", "content": "old " * 5000},
            {"role": "assistant", "content": "old answer " * 5000},
            {"role": "user", "content": [{"type": "text", "text": "What is this?"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64," + "A" * image_bytes}}]},
            {"role": "assistant", "content": "It is the parser node. " * 50},
            {"role": "user", "content": "Which node did you just identify?"},
            *tool_pair(),
        ]

    def test_large_image_never_consumes_base64_text_budget(self):
        large = self.messages()
        small = self.messages(32)
        # If whole-message JSON serialization returns, this regression fails.
        with patch("continuum.core.working_context.json.dumps", side_effect=AssertionError("serialized image")):
            actual = select_working_context(large, context_tokens=98304)
            comparison = select_working_context(small, context_tokens=98304)
        self.assertTrue(actual["fits"])
        self.assertEqual(actual["messages"], large)
        self.assertEqual(actual["input_estimated_tokens"], comparison["input_estimated_tokens"])
        self.assertLess(actual["input_estimated_tokens"], 30000)

    def test_prior_multimodal_boundary_and_active_json_group_survive_small_tail(self):
        messages = self.messages()
        original = copy.deepcopy(messages)
        result = select_working_context(messages, context_tokens=7000, reserve_tokens=512)
        self.assertTrue(result["fits"])
        self.assertEqual(result["dropped_groups"], 1)
        self.assertEqual(result["messages"], [messages[0], *messages[3:]])
        self.assertIs(result["messages"][-1], messages[-1])
        self.assertEqual(json.loads(result["messages"][-1]["content"])["messages"], ["a" * 9000])
        self.assertEqual(messages, original)

    def test_overflow_returns_intact_mandatory_boundary_not_silent_slice(self):
        messages = self.messages(40)
        result = select_working_context(messages, context_tokens=256, reserve_tokens=0)
        self.assertFalse(result["fits"])
        self.assertEqual(result["status"], "mandatory_boundary_exceeds_budget")
        self.assertEqual(result["messages"], [messages[0], *messages[3:]])
        with self.assertRaisesRegex(ValueError, "mandatory context"):
            prepare_working_chat_request({"model": "do-not-change", "messages": messages}, context_tokens=256, reserve_tokens=0)

    def test_pure_request_preserves_model_options_and_stable_prefix(self):
        request = {"model": "unchanged", "temperature": 0.2, "messages": self.messages(8), "tools": [{"x": 1}]}
        actual, metrics = prepare_working_chat_request(request, context_tokens=7000, reserve_tokens=512)
        self.assertEqual(actual["model"], request["model"])
        self.assertIs(actual["tools"], request["tools"])
        self.assertEqual(actual["messages"][0], request["messages"][0])
        self.assertNotIn("messages", metrics)
        self.assertFalse(metrics["sent"])
        self.assertFalse(metrics["mutated"])

    def test_parallel_calls_and_results_preserved_atomically(self):
        first = tool_pair("one", "{\"ok\":true}")
        second = tool_pair("two", "{\"ok\":false}")
        first[0]["tool_calls"] += second[0]["tool_calls"]
        messages = [{"role": "user", "content": "inspect"}, first[0], second[1], first[1]]
        self.assertEqual(select_working_context(messages, context_tokens=4096)["messages"], messages)

    def test_invalid_role_and_tool_boundaries_fail_closed(self):
        variants = [
            [{"role": "tool", "tool_call_id": "orphan", "content": "result"}],
            [{"role": "user", "content": "hi"}, {"role": "system", "content": "late"}],
            [{"role": "user", "content": "hi"}, tool_pair()[0]],
            [{"role": "user", "content": "hi"}, tool_pair()[0], {"role": "user", "content": "split"}],
            [{"role": "user", "content": "hi"}, *tool_pair(), tool_pair()[1]],
            [{"role": "user", "content": "hi"}, *tool_pair(), *tool_pair()],
            [{"role": "function", "content": "legacy ambiguous"}],
            [{"role": "system", "content": "no user"}],
        ]
        for messages in variants:
            with self.subTest(messages=str(messages)[:100]), self.assertRaises(ValueError):
                select_working_context(messages, context_tokens=32768)

    def test_plain_json_bounds_and_types(self):
        for value in (float("nan"), object(), b"binary", {"type": []}, "\ud800"):
            messages = [{"role": "user", "content": value}]
            if value == {"type": []}:
                self.assertTrue(select_working_context(messages, context_tokens=4096)["fits"])
            else:
                with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                    select_working_context(messages, context_tokens=4096)
        cycle = []
        cycle.append(cycle)
        with self.assertRaises(ValueError):
            select_working_context([{"role": "user", "content": cycle}], context_tokens=4096)

    def test_budget_parameters_strict(self):
        for kwargs in ({"context_tokens": True}, {"context_tokens": 100},
                       {"context_tokens": 4096, "reserve_tokens": 4096},
                       {"context_tokens": 4096, "image_tokens": 0}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                select_working_context([{"role": "user", "content": "hi"}], **kwargs)

    def test_latest_two_turns_are_mandatory_even_without_tools(self):
        messages = [{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"},
                    {"role": "user", "content": "c"}]
        self.assertEqual(select_working_context(messages, context_tokens=256, reserve_tokens=0)["messages"], messages)

    def test_audio_and_raw_data_url_costs_are_bounded(self):
        for content in ("data:image/png;base64," + "A" * 1000000,
                        [{"type": "input_audio", "input_audio": {"data": "A" * 1000000, "format": "wav"}}]):
            result = select_working_context([{"role": "user", "content": content}], context_tokens=4096)
            self.assertLess(result["output_estimated_tokens"], 1100)


class WorkingKnowledgeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="continuum-working-context-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve(strict=True)
        self.root = self.directory / "memory"
        self.source = self.directory / "source"
        self.source.mkdir()
        config = default_config()
        config["capture"]["mode"] = "manual"
        config["local_inference"]["enabled"] = False
        write_config(self.root, config)
        init_db(self.root)
        blocker = patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden"))
        blocker.start()
        self.addCleanup(blocker.stop)

    def note(self, text="Use the bounded parser", **kwargs):
        values = {"project_id": "project-a", "session_id": "session-a", "kind": "note",
                  "title": "Parser decision", "summary": text}
        values.update(kwargs)
        return record_project_knowledge(self.root, **values)

    def cite(self, record):
        return {"kind": "scroll_event", "id": record["id"], "content_hash": record["content_hash"]}

    def state(self):
        with closing(connect_existing(self.root)) as conn:
            return [tuple(row) for row in conn.execute("SELECT * FROM scroll_events ORDER BY rowid")]

    def test_task_packet_exact_stable_hash_and_no_writes(self):
        row = self.note()
        before = self.state()
        first = compile_task_pack(self.root, project_id="project-a", purpose="review", record_ids=[row["id"]])
        second = compile_task_pack(self.root, project_id="project-a", purpose="review", record_ids=[row["id"]])
        self.assertEqual(first, second)
        self.assertEqual(first["results"][0]["record"]["payload"], row["payload"])
        self.assertEqual(first["results"][0]["citation"], self.cite(row))
        self.assertNotIn("session_id", first["results"][0]["record"])
        self.assertEqual(self.state(), before)
        digest = hashlib.sha256(json.dumps({key: value for key, value in first.items() if key != "packet_sha256"},
                                           sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(digest, first["packet_sha256"])

    def test_task_packet_budget_omits_whole_record_with_count(self):
        row = self.note("x" * 8000)
        packet = compile_task_pack(self.root, project_id="project-a", record_ids=[row["id"]], token_budget=512)
        self.assertEqual(packet["results"], [])
        self.assertEqual(packet["excluded_by_budget"], 1)
        self.assertLessEqual(len(json.dumps(packet, separators=(",", ":"))), 2048)

    def test_task_packet_scope_and_selector_errors(self):
        row = self.note(project_id="other")
        for changes in ({"record_ids": [row["id"]]}, {"citations": [self.cite(row)]},
                        {"record_ids": []}, {"purpose": "execute", "record_ids": [row["id"]]},
                        {"record_ids": ["a", "a"]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                compile_task_pack(self.root, project_id="project-a", **changes)

    def test_exact_source_citation_keeps_pagination_metadata(self):
        row = self.note("z" * 8000)
        packet = compile_task_pack(self.root, project_id="project-a", citations=[self.cite(row)], token_budget=32768)
        source = packet["results"][0]["source"]
        self.assertEqual(source["next_offset"], 4000)
        self.assertEqual(source["content_hash"], row["content_hash"])
        self.assertEqual(len(source["content"]), 4000)

    def test_new_file_version_propagates_through_decision_collection_and_pack(self):
        path = self.source / "parser.py"
        path.write_text("def parse(): return 1\n", encoding="utf-8")
        index_project_files(self.root, project_id="project-a", session_id="s", source_root=self.source, paths=["parser.py"])
        file = read_records(self.root, project_id="project-a")[0]
        note = self.note(links=[{"relation": "depends_on", "target_id": file["id"]}])
        collection = create_collection(self.root, project_id="project-a", session_id="s", title="Parser",
                                       summary="Overview", overview="Detailed overview", members=[self.cite(note)])
        self.assertEqual(change_impact(self.root, project_id="project-a")["result_count"], 0)
        path.write_text("def parse(): return 2\n", encoding="utf-8")
        index_project_files(self.root, project_id="project-a", session_id="s", source_root=self.source, paths=["parser.py"])
        before = self.state()
        impact = change_impact(self.root, project_id="project-a", token_budget=32768)
        self.assertEqual({item["id"] for item in impact["results"]}, {file["id"], note["id"], collection["id"]})
        packet = compile_task_pack(self.root, project_id="project-a", record_ids=[note["id"]])
        self.assertTrue(packet["results"][0]["record"]["needs_review"])
        self.assertEqual(self.state(), before)

    def test_explicit_change_signal_bounded_scope(self):
        row = self.note()
        impact = change_impact(self.root, project_id="project-a", changed_record_ids=[row["id"]])
        self.assertEqual(impact["results"][0]["review_reasons"], ["explicit_change_signal"])
        with self.assertRaises(ValueError):
            change_impact(self.root, project_id="other", changed_record_ids=[row["id"]])

    def test_selected_collection_expands_only_exact_members(self):
        member = self.note()
        self.note("An unrelated record must not be expanded")
        collection = create_collection(self.root, project_id="project-a", session_id="s", title="Selected",
                                       summary="Summary", overview="Overview", members=[self.cite(member)])
        packet = compile_task_pack(self.root, project_id="project-a", record_ids=[collection["id"]], token_budget=32768)
        self.assertEqual([item["citation"]["id"] for item in packet["results"]], [collection["id"], member["id"]])
        compact = compile_task_pack(self.root, project_id="project-a", record_ids=[collection["id"]], expand_collections=False)
        self.assertEqual(compact["result_count"], 1)

    def test_debugger_labels_superseded_fact_without_staling_its_correction(self):
        from continuum.core.temporal_facts import record_temporal_fact
        first = record_temporal_fact(self.root, project_id="project-a", session_id="s", subject="parser",
                                     predicate="mode", value="legacy", valid_from="2026-01-01T00:00:00Z")
        current = record_temporal_fact(self.root, project_id="project-a", session_id="s", subject="parser",
                                       predicate="mode", value="bounded", valid_from="2026-01-01T00:00:00Z", corrects=first["id"])
        result = explain_memory(self.root, project_id="project-a", query="parser", source_id=first["id"])
        self.assertEqual(result["source_state"], "superseded_recorded_evidence")
        packet = compile_task_pack(self.root, project_id="project-a", record_ids=[current["id"]])
        self.assertFalse(packet["results"][0]["record"]["needs_review"])

    def test_revoked_evidence_marked_unavailable_and_not_expanded(self):
        source = self.note()
        note = self.note("Depends on evidence", evidence=[self.cite(source)])
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE scroll_events SET visibility_scope='private', metadata_json=? WHERE id=?",
                         (json.dumps({"visibility_scope": "private", "project_id": "project-a"}), source["id"]))
            conn.commit()
        impact = change_impact(self.root, project_id="project-a")
        self.assertEqual(impact["results"][0]["id"], note["id"])
        self.assertIn("evidence_unavailable", impact["results"][0]["review_reasons"])

    def test_debugger_included_and_other_project_indistinguishable(self):
        row = self.note("Bounded parser quasar relay")
        before = self.state()
        found = explain_memory(self.root, project_id="project-a", query="quasar", source_id=row["id"], token_budget=32768)
        self.assertEqual(found["reason"], "included")
        absent = explain_memory(self.root, project_id="other", query="quasar", source_id=row["id"])
        missing = explain_memory(self.root, project_id="other", query="quasar", source_id="nonexistent")
        self.assertEqual(absent, missing)
        self.assertEqual(absent["reason"], "not_available_in_scope")
        self.assertEqual(self.state(), before)

    def test_debugger_ranking_and_no_match_distinguished(self):
        rows = [self.note(f"quasar retrieval candidate {index}") for index in range(5)]
        all_results = explain_memory(self.root, project_id="project-a", query="quasar", token_budget=32768)
        lower = all_results["results"][-1]["id"]
        result = explain_memory(self.root, project_id="project-a", query="quasar", source_id=lower, limit=1)
        self.assertEqual(result["reason"], "ranked_below_limit")
        absent = explain_memory(self.root, project_id="project-a", query="nevermatchingword", source_id=rows[0]["id"])
        self.assertEqual(absent["reason"], "outside_diagnostic_window_or_no_match")

    def test_read_missing_root_does_not_initialize(self):
        missing = self.directory / "missing"
        self.assertEqual(change_impact(missing, project_id="project-a")["results"], [])
        result = explain_memory(missing, project_id="project-a", query="hello")
        self.assertEqual(result["results"], [])
        self.assertFalse(missing.exists())

    def test_raw_private_event_cannot_be_added_by_citation(self):
        text = "Private ordinary note"
        event = append_scroll_event(self.root, session_id="private-session", event_type="message", role="user",
                                    content=text, metadata={"visibility_scope": "private", "project_id": "project-a"})
        citation = {"kind": "scroll_event", "id": event["event_id"], "content_hash": hashlib.sha256(text.encode()).hexdigest()}
        with self.assertRaises(ValueError):
            compile_task_pack(self.root, project_id="project-a", citations=[citation])


if __name__ == "__main__":
    unittest.main()
