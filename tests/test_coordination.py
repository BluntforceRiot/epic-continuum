from __future__ import annotations

import hashlib
import json
import socket
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

from continuum.core.config import default_config, write_config
from continuum.core.coordination import (
    create_collection,
    create_handoff,
    query_collections,
    query_handoffs,
    revise_collection,
    transition_handoff,
)
from continuum.core.knowledge_records import append_record, read_records
from continuum.core.store import append_scroll_event, connect, connect_existing, init_db


class CoordinationTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory(prefix="continuum-coordination-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.root = self.directory / "memory"
        config = default_config()
        config["capture"]["mode"] = "manual"
        config["capture"]["dedup_window_seconds"] = 0
        config["local_inference"]["enabled"] = False
        write_config(self.root, config)
        init_db(self.root)
        self.now = datetime(2025, 1, 1, tzinfo=timezone.utc)
        clock = patch("continuum.core.coordination._now", side_effect=lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)
        blocker = patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden"))
        blocker.start()
        self.addCleanup(blocker.stop)

    def handoff(self, **changes) -> dict:
        args = {"project_id": "project-a", "session_id": "session-a", "actor": "author",
                "objective": "Finish the isolated parser change", "accepted_decisions": ["Keep byte anchors"],
                "unfinished_work": ["Run the focused check"]}
        args.update(changes)
        return create_handoff(self.root, **args)

    def transition(self, handoff: dict, **changes) -> dict:
        args = {"project_id": "project-a", "session_id": "session-a", "handoff_id": handoff["id"],
                "expected_head": handoff["id"], "action": "claim", "actor": "worker-a", "lease_seconds": 60}
        args.update(changes)
        return transition_handoff(self.root, **args)

    def handoffs(self, **changes) -> dict:
        return query_handoffs(self.root, **{"project_id": "project-a", **changes})

    def source(self, text: str = "Exact local test result.", scope: str = "project", project: str = "project-a") -> dict:
        row = append_scroll_event(self.root, session_id="source-session", event_type="message", role="user",
            content=text, metadata={"visibility_scope": scope, "project_id": project,
                                    "continuum_disable_exact_memory": True})
        return {"kind": "scroll_event", "id": row["event_id"], "content_hash": hashlib.sha256(text.encode()).hexdigest()}

    def collection(self, **changes) -> dict:
        args = {"project_id": "project-a", "session_id": "session-a", "title": "Parser evidence",
                "summary": "Recorded observations", "overview": "Follow exact citations for original evidence.", "members": []}
        args.update(changes)
        return create_collection(self.root, **args)

    def revise(self, collection: dict, **changes) -> dict:
        args = {"project_id": "project-a", "session_id": "session-a", "collection_id": collection["id"],
                "expected_head": collection["id"], "title": "Parser evidence", "summary": "Reviewed observations",
                "overview": "The collection was explicitly revised.", "members": []}
        args.update(changes)
        return revise_collection(self.root, **args)

    def collections(self, **changes) -> dict:
        return query_collections(self.root, **{"project_id": "project-a", **changes})

    def records(self, project: str = "project-a") -> list[dict]:
        return read_records(self.root, project_id=project)

    def snapshot(self) -> dict[str, list[tuple]]:
        with closing(connect_existing(self.root)) as conn:
            names = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            return {name: sorted((tuple(row) for row in conn.execute(f'SELECT * FROM "{name}"')), key=repr) for name in names}

    def test_handoff_preserves_context_without_remote_actions(self) -> None:
        citation = self.source()
        first = self.handoff(evidence=[citation])
        packet = self.handoffs()
        self.assertEqual(packet["actor_authority"], "caller_attribution_not_authentication")
        self.assertEqual(packet["instruction_authority"], "none")
        item = packet["results"][0]
        self.assertEqual(item["id"], first["id"])
        self.assertEqual(item["head"], first["id"])
        self.assertEqual(item["status"], "open")
        self.assertEqual(item["evidence"], [citation])
        self.assertEqual(item["accepted_decisions"], ["Keep byte anchors"])
        self.assertEqual(item["unfinished_work"], ["Run the focused check"])

    def test_handoff_claim_renew_release_and_new_owner(self) -> None:
        handoff = self.handoff()
        claim = self.transition(handoff)
        state = self.handoffs()["results"][0]
        self.assertEqual((state["status"], state["owner"], state["head"]), ("claimed", "worker-a", claim["id"]))
        self.now += timedelta(seconds=10)
        renewal = self.transition(handoff, action="renew", expected_head=claim["id"])
        self.assertEqual(renewal["payload"]["lease_until"], (self.now + timedelta(seconds=60)).isoformat())
        release = self.transition(handoff, action="release", expected_head=renewal["id"], lease_seconds=None)
        self.assertEqual(self.handoffs()["results"][0]["status"], "open")
        replacement = self.transition(handoff, expected_head=release["id"], actor="worker-b")
        item = self.handoffs(include_history=True)["results"][0]
        self.assertEqual(item["owner"], "worker-b")
        self.assertEqual(item["head"], replacement["id"])
        self.assertEqual([row["action"] for row in item["history"]], ["claim", "renew", "release", "claim"])

    def test_handoff_revoked_evidence_warns_without_changing_claim_head(self) -> None:
        reference = self.source()
        handoff = self.handoff(evidence=[reference])
        collection = self.collection(members=[reference])
        claim = self.transition(handoff)
        original = self.handoffs(handoff_id=handoff["id"], include_history=True)["results"][0]
        self.assertEqual(original["evidence_states"], [{"index": 0, "source_state": "current"}])
        self.assertFalse(original["needs_review"])
        with closing(connect(self.root)) as conn:
            metadata = json.loads(conn.execute("SELECT metadata_json FROM scroll_events WHERE id=?", (reference["id"],)).fetchone()[0])
            metadata["visibility_scope"] = "private"
            conn.execute("UPDATE scroll_events SET visibility_scope='private',metadata_json=? WHERE id=?",
                         (json.dumps(metadata), reference["id"]))
            conn.commit()
        before = self.snapshot()
        for include_history in (False, True):
            with self.subTest(include_history=include_history):
                item = self.handoffs(handoff_id=handoff["id"], include_history=include_history)["results"][0]
                self.assertEqual(item["evidence"], [reference])
                self.assertEqual(item["evidence_states"], [{"index": 0, "source_state": "stale_or_unavailable"}])
                self.assertEqual(item["unavailable_count"], 1)
                self.assertTrue(item["needs_review"])
                self.assertEqual(item["review_reasons"], ["evidence_unavailable_or_changed"])
                for field in ("id", "head", "owner", "status", "lease_until", "citation"):
                    self.assertEqual(item[field], original[field])
                self.assertEqual(item["head"], claim["id"])
                if include_history:
                    self.assertEqual(item["history"], original["history"])
                self.assertNotIn("Exact local test result.", json.dumps(item))
                self.assertNotIn("private", json.dumps(item))
        counterpart = self.collections(collection_id=collection["id"])["results"][0]
        self.assertEqual(counterpart["unavailable_count"], 1)
        self.assertEqual(counterpart["members"][0]["source_state"], "stale_or_unavailable")
        self.assertEqual(self.snapshot(), before)

    def test_handoff_changed_and_missing_references_are_identified_individually(self) -> None:
        changed = self.source("Original changed evidence.")
        missing = self.source("Original removed evidence.")
        current = self.source("Current retained evidence.")
        handoff = self.handoff(evidence=[changed, missing, current])
        claim = self.transition(handoff)
        complete = self.transition(handoff, expected_head=claim["id"], action="complete", lease_seconds=None)
        with closing(connect(self.root)) as conn:
            text = "Replacement is not original evidence."
            conn.execute("UPDATE scroll_events SET content=?,content_hash=? WHERE id=?",
                         (text, hashlib.sha256(text.encode()).hexdigest(), changed["id"]))
            conn.execute("DELETE FROM scroll_events WHERE id=?", (missing["id"],))
            conn.commit()
        before = self.snapshot()
        item = self.handoffs(handoff_id=handoff["id"], include_history=True, token_budget=32768)["results"][0]
        self.assertEqual(item["evidence"], [changed, missing, current])
        self.assertEqual(item["evidence_states"], [
            {"index": 0, "source_state": "stale_or_unavailable"},
            {"index": 1, "source_state": "stale_or_unavailable"},
            {"index": 2, "source_state": "current"},
        ])
        self.assertEqual(item["unavailable_count"], 2)
        self.assertTrue(item["needs_review"])
        self.assertEqual(item["status"], "completed")
        self.assertEqual(item["head"], complete["id"])
        self.assertIsNone(item["owner"])
        self.assertNotIn("Replacement is not original evidence.", json.dumps(item))
        self.assertEqual(self.snapshot(), before)

    def test_handoff_empty_evidence_has_no_unavailable_support_warning(self) -> None:
        self.handoff()
        item = self.handoffs()["results"][0]
        self.assertEqual(item["evidence_states"], [])
        self.assertEqual(item["unavailable_count"], 0)
        self.assertFalse(item["needs_review"])
        self.assertEqual(item["review_reasons"], [])

    def test_default_claim_lease_is_bounded(self) -> None:
        handoff = self.handoff()
        claim = self.transition(handoff, lease_seconds=None)
        self.assertEqual(claim["payload"]["lease_seconds"], 300)
        self.assertEqual(claim["payload"]["lease_until"], (self.now + timedelta(seconds=300)).isoformat())

    def test_expiry_is_recoverable_without_mutating_read(self) -> None:
        handoff = self.handoff()
        claim = self.transition(handoff)
        self.now += timedelta(seconds=60)
        before = self.snapshot()
        expired = self.handoffs()["results"][0]
        self.assertEqual(expired["status"], "expired")
        self.assertIsNone(expired["owner"])
        self.assertEqual(self.snapshot(), before)
        for action in ("renew", "release", "complete"):
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.transition(handoff, expected_head=claim["id"], action=action,
                                lease_seconds=60 if action == "renew" else None)
        successor = self.transition(handoff, expected_head=claim["id"], actor="worker-b")
        self.assertEqual(self.handoffs()["results"][0]["head"], successor["id"])
        self.assertEqual(len(self.records()), 3)

    def test_completed_handoff_cannot_be_reclaimed(self) -> None:
        handoff = self.handoff()
        claim = self.transition(handoff)
        complete = self.transition(handoff, expected_head=claim["id"], action="complete", lease_seconds=None)
        self.assertEqual(self.handoffs()["results"][0]["status"], "completed")
        self.now += timedelta(days=2)
        with self.assertRaisesRegex(ValueError, "completed"):
            self.transition(handoff, expected_head=complete["id"])
        self.assertEqual(len(self.records()), 3)

    def test_active_claim_and_wrong_owner_and_wrong_head_rollback(self) -> None:
        handoff = self.handoff()
        claim = self.transition(handoff)
        init_db(self.root)
        before = self.snapshot()
        for changes in ({"expected_head": claim["id"], "actor": "worker-b"},
                        {"expected_head": claim["id"], "actor": "worker-b", "action": "renew"},
                        {"expected_head": handoff["id"], "action": "renew"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.transition(handoff, **changes)
        self.assertEqual(self.snapshot(), before)

    def test_same_head_parallel_claim_has_exactly_one_winner(self) -> None:
        handoff = self.handoff()
        barrier = Barrier(2)

        def attempt(actor: str) -> str:
            barrier.wait(timeout=10)
            try:
                self.transition(handoff, actor=actor)
                return "accepted"
            except ValueError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(attempt, ["worker-a", "worker-b"])), ["accepted", "rejected"])
        self.assertEqual(len(self.records()), 2)

    def test_stale_owner_cannot_complete_recovered_lease(self) -> None:
        handoff = self.handoff()
        first = self.transition(handoff)
        self.now += timedelta(seconds=61)
        second = self.transition(handoff, actor="worker-b", expected_head=first["id"])
        with self.assertRaises(ValueError):
            self.transition(handoff, action="complete", expected_head=first["id"], lease_seconds=None)
        with self.assertRaises(ValueError):
            self.transition(handoff, action="complete", expected_head=second["id"], lease_seconds=None)
        self.assertEqual(self.handoffs()["results"][0]["owner"], "worker-b")

    def test_transition_duplicate_and_unknown_target_fail(self) -> None:
        handoff = self.handoff()
        claim = self.transition(handoff)
        for changes in ({}, {"handoff_id": "missing"}, {"handoff_id": claim["id"]}, {"project_id": "project-b"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.transition(handoff, **changes)
        self.assertEqual(len(self.records()), 2)
        self.assertEqual(self.records("project-b"), [])

    def test_transition_write_delay_cannot_commit_expired_lease(self) -> None:
        handoff = self.handoff()
        with patch("continuum.core.coordination._now", side_effect=[self.now, self.now + timedelta(seconds=61)]):
            with self.assertRaisesRegex(ValueError, "expired"):
                self.transition(handoff)
        self.assertEqual(len(self.records()), 1)

    def test_owner_expiry_while_waiting_for_writer_is_rechecked(self) -> None:
        handoff = self.handoff()
        claim = self.transition(handoff)
        with patch("continuum.core.coordination._now", side_effect=[self.now + timedelta(seconds=50), self.now + timedelta(seconds=61)]):
            with self.assertRaisesRegex(ValueError, "expired"):
                self.transition(handoff, action="renew", expected_head=claim["id"])
        self.assertEqual(len(self.records()), 2)

    def test_clock_backwards_and_naive_clock_fail_closed(self) -> None:
        handoff = self.handoff()
        claim = self.transition(handoff)
        self.now -= timedelta(seconds=1)
        with self.assertRaisesRegex(ValueError, "clock"):
            self.transition(handoff, action="renew", expected_head=claim["id"])
        with patch("continuum.core.coordination._now", return_value=datetime(2025, 1, 1)):
            with self.assertRaisesRegex(ValueError, "aware UTC"):
                self.transition(handoff)

    def test_strict_handoff_arguments(self) -> None:
        for changes in ({"objective": ""}, {"actor": 1}, {"accepted_decisions": "yes"},
                        {"unfinished_work": ["x"] * 33}, {"objective": "x" * 4097}, {"actor": "a\x00b"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.handoff(**changes)
        handoff = self.handoff()
        for changes in ({"lease_seconds": True}, {"lease_seconds": 0}, {"lease_seconds": 86401},
                        {"action": "steal"}, {"action": []}, {"expected_head": "../bad"},
                        {"action": "complete", "lease_seconds": 10}, {"actor": ""}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.transition(handoff, **changes)
        self.assertEqual(len(self.records()), 1)

    def test_stored_malformed_transition_is_not_hidden_by_selector(self) -> None:
        handoff = self.handoff()
        append_record(self.root, project_id="project-a", session_id="session-a", kind="handoff_transition",
                      payload={"schema": 1, "action": "claim"})
        with self.assertRaises(ValueError):
            self.handoffs(handoff_id="not-found")
        with self.assertRaises(ValueError):
            self.transition(handoff)

    def test_collection_progressive_disclosure_and_exact_pagination(self) -> None:
        text = "First exact line.\nSecond exact line."
        reference = self.source(text)
        collection = self.collection(members=[reference])
        summary = self.collections()["results"][0]
        self.assertNotIn("overview", summary)
        self.assertNotIn("source", summary["members"][0])
        self.assertEqual(summary["members"][0]["source_state"], "current")
        overview = self.collections(detail="overview")["results"][0]
        self.assertIn("overview", overview)
        self.assertNotIn("source", overview["members"][0])
        first = self.collections(collection_id=collection["id"], detail="full", member_index=0, member_limit=10)["results"][0]["members"][0]["source"]
        rest = self.collections(collection_id=collection["id"], detail="full", member_index=0,
                                member_offset=first["next_offset"])["results"][0]["members"][0]["source"]
        self.assertEqual(first["content"] + rest["content"], text)
        self.assertEqual(rest["content_hash"], reference["content_hash"])
        self.assertIsNone(rest["next_offset"])

    def test_collection_revision_retains_history_and_exact_head(self) -> None:
        first = self.collection()
        reference = self.source()
        second = self.revise(first, members=[reference])
        current = self.collections()["results"][0]
        self.assertEqual(current["version"], 2)
        self.assertEqual(current["head"], second["id"])
        self.assertEqual(current["id"], first["id"])
        history = self.collections(include_history=True)["results"]
        self.assertEqual([row["version"] for row in history], [2, 1])
        self.assertFalse(history[1]["is_current_revision"])
        with self.assertRaises(ValueError):
            self.revise(first)
        self.assertEqual(len(self.records()), 2)

    def test_parallel_collection_revision_has_one_winner(self) -> None:
        collection = self.collection()
        barrier = Barrier(2)

        def attempt(summary: str) -> str:
            barrier.wait(timeout=10)
            try:
                self.revise(collection, summary=summary)
                return "accepted"
            except ValueError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(attempt, ["one", "two"])), ["accepted", "rejected"])
        self.assertEqual(len(self.records()), 2)

    def test_collection_changed_source_never_returns_replacement_text(self) -> None:
        reference = self.source()
        self.collection(members=[reference])
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE scroll_events SET content=? WHERE id=?", ("Replacement is not admitted.", reference["id"]))
            conn.commit()
        for detail in ("summary", "overview", "full"):
            packet = self.collections(detail=detail)
            item = packet["results"][0]
            self.assertEqual(item["unavailable_count"], 1)
            self.assertEqual(item["members"][0]["source_state"], "stale_or_unavailable")
            self.assertNotIn("source", item["members"][0])
            self.assertNotIn("Replacement", json.dumps(packet))

    def test_collection_private_or_moved_scope_member_becomes_unavailable(self) -> None:
        reference = self.source()
        self.collection(members=[reference])
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE scroll_events SET visibility_scope='private' WHERE id=?", (reference["id"],))
            conn.commit()
        packet = self.collections(detail="full")
        self.assertEqual(packet["results"][0]["unavailable_count"], 1)
        self.assertNotIn("Exact local test result.", json.dumps(packet))

    def test_source_admission_rejects_private_wrong_project_hash_and_duplicate(self) -> None:
        valid = self.source()
        private = self.source(scope="private")
        other = self.source(project="project-b")
        invalid = [[private], [other], [{**valid, "content_hash": "0" * 64}], [valid, valid],
                   [{**valid, "kind": "path"}], [{**valid, "extra": "untrusted"}], [{**valid, "id": "../file"}]]
        for references in invalid:
            with self.subTest(references=references), self.assertRaises(ValueError):
                self.collection(members=references)
            with self.subTest(handoff=references), self.assertRaises(ValueError):
                self.handoff(evidence=references)
        self.assertEqual(self.records(), [])

    def test_collection_member_admission_rechecked_in_transaction(self) -> None:
        reference = self.source()
        from continuum.core.coordination import validate_evidence

        calls = []

        def check(*args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise ValueError("fixture source changed during admission")
            return validate_evidence(*args, **kwargs)

        with patch("continuum.core.coordination.validate_evidence", side_effect=check):
            with self.assertRaisesRegex(ValueError, "during admission"):
                self.collection(members=[reference])
        self.assertEqual(calls, [1, 1])
        self.assertEqual(self.records(), [])

    def test_collection_strict_arguments(self) -> None:
        for changes in ({"members": None}, {"members": {}}, {"members": [None]}, {"title": ""},
                        {"summary": "x" * 1025}, {"overview": "x" * 8193}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.collection(**changes)
        first = self.collection()
        for changes in ({"collection_id": "missing"}, {"expected_head": "missing"}, {"project_id": "project-b"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.revise(first, **changes)
        self.assertEqual(len(self.records()), 1)

    def test_query_selector_types_and_pagination_fail_closed(self) -> None:
        first = self.collection()
        for changes in ({"detail": []}, {"detail": "everything"}, {"include_history": 1},
                        {"member_index": True}, {"member_offset": True}, {"member_limit": 0},
                        {"member_offset": 1}, {"member_index": 0}, {"member_limit": 10},
                        {"collection_id": first["id"], "detail": "full", "member_index": 0},
                        {"collection_id": first["id"], "detail": "full", "member_index": 0, "include_history": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.collections(**changes)
        for changes in ({"handoff_id": 1}, {"include_history": 1}, {"token_budget": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.handoffs(**changes)

    def test_collection_unselected_member_is_checked_but_not_revealed(self) -> None:
        a = self.source("One selected result")
        b = self.source("Unselected content is hidden")
        first = self.collection(members=[a, b])
        item = self.collections(collection_id=first["id"], detail="full", member_index=0)["results"][0]
        self.assertIn("source", item["members"][0])
        self.assertNotIn("source", item["members"][1])
        self.assertEqual(item["members"][1]["source_state"], "current")

    def test_outputs_are_complete_json_with_whole_record_budget_omission(self) -> None:
        for index in range(4):
            self.handoff(objective=f"Work {index} " + "界" * 500)
            self.collection(title=f"Collection {index}", summary="界" * 400)
        for packet in (self.handoffs(token_budget=512), self.collections(token_budget=512)):
            serialized = json.dumps(packet, ensure_ascii=True, separators=(",", ":"))
            self.assertLessEqual(len(serialized), 512 * 4)
            self.assertEqual(json.loads(serialized), packet)
            self.assertGreater(packet["excluded_by_budget"], 0)
            self.assertEqual(packet["matched_count"], 4)
            self.assertEqual(packet["result_count"] + packet["excluded_by_budget"], 4)

    def test_missing_root_reads_and_project_filters_are_nonmutating(self) -> None:
        absent = self.directory / "missing"
        self.assertEqual(query_handoffs(absent, project_id="project-a")["result_count"], 0)
        self.assertEqual(query_collections(absent, project_id="project-a")["result_count"], 0)
        self.assertFalse(absent.exists())
        self.handoff()
        self.collection()
        before = self.snapshot()
        self.assertEqual(self.handoffs(project_id="project-b")["result_count"], 0)
        self.assertEqual(self.collections(project_id="project-b")["result_count"], 0)
        self.assertEqual(self.snapshot(), before)

    def test_credential_material_rejected_before_capture(self) -> None:
        material = "sk-" + "a" * 48
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.handoff(objective=material)
        with self.assertRaises(ValueError):
            self.collection(overview=material)
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn(material, repr(self.snapshot()))

    def test_invalid_collection_topology_not_hidden_by_filter(self) -> None:
        first = self.collection()
        append_record(self.root, project_id="project-a", session_id="session-a", kind="collection_revision",
            payload={**first["payload"], "collection_id": first["id"], "expected_head": "not-the-head", "version": 2})
        with self.assertRaisesRegex(ValueError, "head"):
            self.collections(collection_id="unrelated")


if __name__ == "__main__":
    unittest.main()
