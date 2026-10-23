from __future__ import annotations

import copy
import hashlib
import json
import socket
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

from continuum.core.config import default_config, write_config
from continuum.core.experience import (
    find_reusable_lessons,
    propose_procedure,
    query_experiences,
    record_experience,
    review_procedure,
)
from continuum.core.investigation import record_analysis_finding, register_analysis_asset
from continuum.core.knowledge_records import append_record, read_records
from continuum.core.project_knowledge import index_project_files
from continuum.core.store import append_scroll_event, connect, connect_existing, init_db


class ExperienceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="continuum-experience-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / "memory"
        config = default_config()
        config["capture"]["mode"] = "manual"
        config["capture"]["dedup_window_seconds"] = 0
        config["local_inference"]["enabled"] = False
        write_config(self.root, config)
        init_db(self.root)
        blocker = patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden"))
        blocker.start()
        self.addCleanup(blocker.stop)
        self.counter = 0

    def source(self, *, project: str = "project-a", scope: str = "project") -> dict:
        self.counter += 1
        text = f"Disposable test {self.counter} completed with the expected local fixture output."
        event = append_scroll_event(self.root, session_id="source-session", event_type="message", role="user",
                                    content=text, metadata={"visibility_scope": scope, "project_id": project})
        return {"kind": "scroll_event", "id": event["event_id"],
                "content_hash": hashlib.sha256(text.encode()).hexdigest()}

    def attempt(self, **changes) -> dict:
        args = {"project_id": "project-a", "session_id": "session-a", "goal": "Repair parser",
                "approach": "Change parser then replay fixture", "prerequisites": {"language": "Python", "format": "JSON"},
                "steps": ["Inspect exact input", "Apply a bounded parser change", "Replay the fixture"],
                "outcome": "success", "observed_result": "Fixture matched the expected output."}
        args.update(changes)
        if "verification" not in args:
            args["verification"] = [self.source(project=args["project_id"])]
        return record_experience(self.root, **args)

    def proposal(self, **changes) -> dict:
        project = changes.get("project_id", "project-a")
        ids = changes.pop("experience_ids", None)
        if ids is None:
            ids = [self.attempt(project_id=project)["id"], self.attempt(project_id=project)["id"]]
        args = {"project_id": project, "session_id": "session-a", "experience_ids": ids, "title": "Replay-based parser repair"}
        args.update(changes)
        return propose_procedure(self.root, **args)

    def review(self, procedure: dict, **changes) -> dict:
        args = {"project_id": procedure["project_id"], "session_id": "review-session", "procedure_id": procedure["id"],
                "decision": "accept", "reviewer": "local-operator", "reason": "Reviewed the exact supporting reports."}
        args.update(changes)
        return review_procedure(self.root, **args)

    def query(self, **changes) -> dict:
        args = {"project_id": "project-a", "token_budget": 32768}
        args.update(changes)
        return query_experiences(self.root, **args)

    def lessons(self, **changes) -> dict:
        args = {"source_projects": ["project-a"], "goal": "Repair parser",
                "prerequisites": {"language": "Python", "format": "JSON"}, "token_budget": 32768}
        args.update(changes)
        return find_reusable_lessons(self.root, **args)

    def snapshot(self) -> dict:
        with closing(connect_existing(self.root)) as conn:
            names = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            return {name: sorted((tuple(row) for row in conn.execute(f'SELECT * FROM "{name}"')), key=repr) for name in names}

    def test_repeated_success_proposal_acceptance_and_transfer_shortlist(self) -> None:
        proposal = self.proposal()
        self.assertEqual(self.lessons()["result_count"], 0)
        unreviewed = self.lessons(accepted_only=False)["results"][0]
        self.assertTrue(unreviewed["inference"])
        self.assertEqual(unreviewed["review_state"], "proposed")
        self.assertFalse(unreviewed["auto_apply"])
        review = self.review(proposal)
        packet = self.lessons()
        self.assertEqual(packet["instruction_authority"], "none")
        self.assertEqual(packet["scope"], "explicit_projects_only")
        self.assertEqual(packet["result_count"], 1)
        result = packet["results"][0]
        self.assertEqual(result["id"], proposal["id"])
        self.assertEqual(result["review_id"], review["id"])
        self.assertEqual(result["review_citation"]["content_hash"], review["content_hash"])
        self.assertEqual(result["review_state"], "accept")
        self.assertEqual(len(result["payload"]["support"]), 2)
        self.assertEqual(len(result["payload"]["verification"]), 2)
        self.assertTrue(result["applicability"]["prerequisites_match"])
        self.assertFalse(result["applicability"]["applied"])
        self.assertFalse(result["needs_review"])
        self.assertNotIn("session_id", json.dumps(result))
        self.assertEqual(result["truth_status"], "recorded_claim_not_independently_verified")

    def test_failed_attempt_is_retained_but_cannot_support_a_procedure(self) -> None:
        failure = self.attempt(outcome="failure", observed_result="Fixture still failed.", verification=[])
        success = self.attempt()
        with self.assertRaisesRegex(ValueError, "matching recorded successes"):
            self.proposal(experience_ids=[failure["id"], success["id"]])
        results = self.query()["results"]
        self.assertEqual({row["id"] for row in results}, {failure["id"], success["id"]})
        failed = next(row for row in results if row["id"] == failure["id"])
        self.assertEqual(failed["payload"]["observed_result"], "Fixture still failed.")

    def test_success_requires_actual_exact_verification_citations(self) -> None:
        for references in ([], None, [{"kind": "scroll_event", "id": "missing", "content_hash": "0" * 64}]):
            with self.subTest(references=references), self.assertRaises(ValueError):
                self.attempt(verification=references)
        self.assertEqual(self.query()["result_count"], 0)

    def test_duplicate_attempt_or_shared_single_source_is_not_repeated_proof(self) -> None:
        citation = self.source()
        first, second = self.attempt(verification=[citation]), self.attempt(verification=[citation])
        for ids in ([first["id"]], [first["id"], first["id"]], [first["id"], second["id"]]):
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                self.proposal(experience_ids=ids)

    def test_proposal_requires_exact_matching_goal_steps_approach_and_prerequisites(self) -> None:
        first = self.attempt()
        for changes in ({"goal": "Other goal"}, {"approach": "Skip tests"}, {"steps": ["Different step"]},
                        {"prerequisites": {"language": "Rust"}}):
            second = self.attempt(**changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.proposal(experience_ids=[first["id"], second["id"]])

    def test_prerequisite_matching_reports_missing_different_and_extra_values(self) -> None:
        proposal = self.proposal()
        self.review(proposal)
        result = self.lessons(prerequisites={"format": "YAML", "platform": "local"})["results"][0]
        self.assertEqual(result["applicability"], {"matched": [], "missing": ["language"],
                         "differences": {"format": {"required": "JSON", "provided": "YAML"}},
                         "additional": ["platform"], "prerequisites_match": False, "applied": False})

    def test_source_projects_are_explicit_and_other_project_corruption_is_not_read(self) -> None:
        accepted = self.proposal()
        self.review(accepted)
        other = self.proposal(project_id="project-b")
        self.review(other)
        self.assertEqual([row["id"] for row in self.lessons()["results"]], [accepted["id"]])
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE scroll_events SET content='malformed' WHERE id=?", (other["id"],))
            conn.commit()
        self.assertEqual(self.lessons()["result_count"], 1)
        with self.assertRaises(ValueError):
            self.lessons(source_projects=["project-a", "project-b"])

    def test_private_session_and_other_project_verification_are_rejected(self) -> None:
        for citation in (self.source(scope="private"), self.source(scope="session"), self.source(project="project-b")):
            with self.subTest(citation=citation), self.assertRaises(ValueError):
                self.attempt(verification=[citation])
        other = self.attempt(project_id="project-b")
        own = self.attempt()
        with self.assertRaises(ValueError):
            self.proposal(experience_ids=[own["id"], other["id"]])

    def test_corrected_attempt_history_stales_procedure_without_deleting_it(self) -> None:
        proposal = self.proposal()
        self.review(proposal)
        source_id = proposal["payload"]["support"][0]["id"]
        correction = self.attempt(outcome="failure", observed_result="Prior result was misreported.", corrects=source_id)
        history = self.query()["results"]
        original = next(row for row in history if row["id"] == source_id)
        self.assertEqual(original["corrected_by"], correction["id"])
        self.assertTrue(original["needs_review"])
        self.assertNotIn(source_id, [row["id"] for row in self.query(include_history=False)["results"]])
        lesson = self.lessons()["results"][0]
        self.assertTrue(lesson["needs_review"])
        self.assertIn("supporting_attempt_corrected", lesson["review_reasons"])
        self.assertEqual(lesson["review_state"], "accept")
        with self.assertRaises(ValueError):
            self.review(proposal, expected_review_id=lesson["review_id"])

    def test_correction_requires_current_same_project_goal_and_preserves_source(self) -> None:
        first = self.attempt()
        for changes in ({"corrects": "missing"}, {"corrects": first["id"], "goal": "Other"},
                        {"corrects": first["id"], "project_id": "project-b"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.attempt(**changes)
        self.attempt(corrects=first["id"])
        with self.assertRaises(ValueError):
            self.attempt(corrects=first["id"])
        self.assertEqual(self.query()["result_count"], 2)

    def test_exact_hash_or_scope_invalidation_is_visible_and_blocks_acceptance(self) -> None:
        proposal = self.proposal()
        source_id = proposal["payload"]["verification"][0]["id"]
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE scroll_events SET visibility_scope='session' WHERE id=?", (source_id,))
            conn.commit()
        result = self.lessons(accepted_only=False)["results"][0]
        self.assertTrue(result["needs_review"])
        with self.assertRaises(ValueError):
            self.review(proposal)
        rejection = self.review(proposal, decision="reject", reason="Supporting evidence became unavailable.")
        self.assertEqual(rejection["payload"]["decision"], "reject")

    def test_new_recorded_file_version_invalidates_readable_historical_evidence(self) -> None:
        directory = self.directory / "source"
        directory.mkdir()
        path = directory / "fixture.txt"
        path.write_text("Initial test fixture.", encoding="utf-8")
        index_project_files(self.root, project_id="project-a", session_id="session-a", source_root=directory, paths=["fixture.txt"])
        row = read_records(self.root, project_id="project-a", kinds=["project_file"])[0]
        citation = {"kind": "scroll_event", "id": row["id"], "content_hash": row["content_hash"]}
        first, second = self.attempt(verification=[citation]), self.attempt()
        proposal = self.proposal(experience_ids=[first["id"], second["id"]])
        self.review(proposal)
        path.write_text("Changed test fixture.", encoding="utf-8")
        index_project_files(self.root, project_id="project-a", session_id="session-a", source_root=directory, paths=["fixture.txt"])
        result = self.lessons()["results"][0]
        self.assertTrue(result["needs_review"])
        self.assertIn("verification_source_superseded", result["review_reasons"])

    def test_review_is_append_only_and_requires_exact_head(self) -> None:
        proposal = self.proposal()
        accepted = self.review(proposal)
        with self.assertRaisesRegex(ValueError, "head changed"):
            self.review(proposal, decision="reject")
        rejected = self.review(proposal, decision="reject", expected_review_id=accepted["id"], reason="Prerequisites changed.")
        self.assertEqual(self.lessons()["result_count"], 0)
        result = self.lessons(accepted_only=False)["results"][0]
        self.assertEqual(result["review_id"], rejected["id"])
        self.assertEqual(result["review_state"], "reject")
        self.assertEqual(len([row for row in self.query()["results"] if row["kind"] == "procedure_review"]), 2)

    def test_parallel_reviews_allow_only_one_cas_commit(self) -> None:
        proposal = self.proposal()
        barrier = Barrier(2)

        def attempt(decision: str) -> str:
            barrier.wait(timeout=10)
            try:
                self.review(proposal, decision=decision)
                return "accepted"
            except ValueError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt, ["accept", "reject"]))
        self.assertEqual(sorted(outcomes), ["accepted", "rejected"])
        self.assertEqual(len([row for row in self.query()["results"] if row["kind"] == "procedure_review"]), 1)

    def test_parallel_corrections_preserve_one_current_attempt(self) -> None:
        first = self.attempt()
        verification = [self.source()]
        barrier = Barrier(2)

        def attempt(result: str) -> str:
            barrier.wait(timeout=10)
            try:
                self.attempt(corrects=first["id"], observed_result=result, verification=verification)
                return "accepted"
            except ValueError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(attempt, ["First correction.", "Second correction."]))
        self.assertEqual(sorted(outcomes), ["accepted", "rejected"])
        self.assertEqual(self.query()["result_count"], 2)
        self.assertEqual(self.query(include_history=False)["result_count"], 1)

    def test_invalid_mutation_inputs_fail_before_any_capture(self) -> None:
        source = [self.source()]
        before = self.snapshot()
        for changes in ({"goal": ""}, {"goal": 1}, {"goal": "g" * 513}, {"approach": True},
                        {"prerequisites": []}, {"prerequisites": {"x": 1}}, {"prerequisites": {"x" * 65: "v"}},
                        {"prerequisites": {str(i): "v" for i in range(17)}}, {"steps": []}, {"steps": [1]},
                        {"steps": ["a"] * 33}, {"steps": ["a" * 1025]}, {"outcome": True},
                        {"outcome": "verified"}, {"observed_result": " "}, {"corrects": False},
                        {"verification": [source[0], source[0]]}, {"verification": [{**source[0], "content_hash": True}]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.attempt(verification=source, **changes) if "verification" not in changes else self.attempt(**changes)
        self.assertEqual(self.snapshot(), before)

    def test_credentials_rejected_in_text_and_prerequisite_mapping(self) -> None:
        source = [self.source()]
        before = self.snapshot()
        binding = "synthetic" + "-not-a-real-binding"
        for changes in ({"observed_result": "password=" + binding},
                        {"prerequisites": {"api_" + "key": "\n" + binding}},
                        {"steps": ["safe heading\naccess_" + "token=" + binding]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.attempt(verification=source, **changes)
        self.assertEqual(self.snapshot(), before)

    def test_invalid_query_and_transfer_inputs_are_strict(self) -> None:
        for changes in ({"include_history": 1}, {"query": ""}, {"query": False}, {"token_budget": True},
                        {"token_budget": 511}, {"token_budget": 32769}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.query(**changes)
        for changes in ({"source_projects": []}, {"source_projects": ["project-a"] * 2},
                        {"source_projects": "project-a"}, {"source_projects": [False]},
                        {"source_projects": [str(i) for i in range(17)]}, {"accepted_only": 1},
                        {"goal": ""}, {"prerequisites": {"x": None}}, {"token_budget": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.lessons(**changes)

    def test_missing_root_reads_never_create_it(self) -> None:
        absent = self.directory / "absent"
        self.assertEqual(query_experiences(absent, project_id="project-a")["result_count"], 0)
        self.assertEqual(find_reusable_lessons(absent, source_projects=["project-a"], goal="parser", prerequisites={})["result_count"], 0)
        self.assertFalse(absent.exists())

    def test_read_queries_are_nonmutating_and_omit_entire_records_under_budget(self) -> None:
        for _ in range(4):
            proposal = self.proposal()
            self.review(proposal)
        before = self.snapshot()
        for packet in (self.query(token_budget=512), self.lessons(token_budget=512), self.query(token_budget=2400)):
            encoded = json.dumps(packet, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
            self.assertLessEqual(len(encoded), 4 * packet["budget"]["requested_tokens"])
            self.assertEqual(json.loads(encoded), packet)
            self.assertEqual(packet["matched_count"], packet["result_count"] + packet["excluded_by_budget"])
            for result in packet["results"]:
                self.assertIn("payload", result)
                self.assertIn("citation", result)
        self.assertEqual(self.snapshot(), before)

    def test_malformed_stored_record_not_hidden_by_query(self) -> None:
        row = self.attempt()
        malformed = copy.deepcopy(row["payload"])
        malformed["schema"] = True
        malformed["goal"] = "Unmatched hidden goal"
        append_record(self.root, project_id="project-a", session_id="session-a", kind="experience", payload=malformed)
        with self.assertRaises(ValueError):
            self.query(query="Repair parser")

    def test_forged_proposal_or_review_topology_fails_closed(self) -> None:
        proposal = self.proposal()
        malformed = copy.deepcopy(proposal["payload"])
        malformed["steps"] = ["Unobserved replacement instruction"]
        append_record(self.root, project_id="project-a", session_id="session-a", kind="procedure", payload=malformed)
        with self.assertRaises(ValueError):
            self.lessons(accepted_only=False)

    def test_stale_support_blocks_proposal_and_review_cannot_target_attempt(self) -> None:
        first, second = self.attempt(), self.attempt()
        self.attempt(corrects=first["id"])
        with self.assertRaises(ValueError):
            self.proposal(experience_ids=[first["id"], second["id"]])
        with self.assertRaises(ValueError):
            self.review(second)

    def test_review_validates_decision_attribution_and_head_types(self) -> None:
        proposal = self.proposal()
        for changes in ({"decision": True}, {"decision": "approved"}, {"reviewer": ""},
                        {"reviewer": "x" * 129}, {"reason": None}, {"expected_review_id": True},
                        {"expected_review_id": "missing"}, {"project_id": "project-b"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.review(proposal, **changes)

    def test_correction_between_proposal_preflight_and_capture_is_rejected(self) -> None:
        first, second = self.attempt(), self.attempt()
        original_append = append_record

        correction = copy.deepcopy(first["payload"])
        correction.update(corrects=first["id"], outcome="failure", observed_result="Corrected report.")

        def interleave(*args, **kwargs):
            original_append(self.root, project_id="project-a", session_id="session-a", kind="experience", payload=correction)
            return original_append(*args, **kwargs)

        with patch("continuum.core.experience.append_record", side_effect=interleave):
            with self.assertRaises(ValueError):
                self.proposal(experience_ids=[first["id"], second["id"]])
        self.assertEqual(len(read_records(self.root, project_id="project-a", kinds=["procedure"])), 0)

    def test_acceptance_rechecks_evidence_after_preflight(self) -> None:
        proposal = self.proposal()
        original_append = append_record
        citation = proposal["payload"]["verification"][0]

        def interleave(*args, **kwargs):
            with closing(connect(self.root)) as conn:
                conn.execute("UPDATE scroll_events SET visibility_scope='session' WHERE id=?", (citation["id"],))
                conn.commit()
            return original_append(*args, **kwargs)

        with patch("continuum.core.experience.append_record", side_effect=interleave):
            with self.assertRaises(ValueError):
                self.review(proposal)
        self.assertEqual(len(read_records(self.root, project_id="project-a", kinds=["procedure_review"])), 0)

    def test_replaced_binary_asset_stales_support_and_blocks_propose_and_accept(self) -> None:
        directory = self.directory / "assets"
        directory.mkdir()
        (directory / "demo.bin").write_bytes(b"MZ\x00disposable-fixture")
        old = register_analysis_asset(self.root, project_id="project-a", session_id="asset-session",
            source_root=directory, path="demo.bin", asset_kind="binary", build_id="v1")
        first = self.attempt(verification=[{"kind": "scroll_event", "id": old["id"], "content_hash": old["content_hash"]}])
        second = self.attempt()
        proposal = self.proposal(experience_ids=[first["id"], second["id"]])
        review = self.review(proposal)
        self.assertFalse(self.lessons()["results"][0]["needs_review"])
        newer = register_analysis_asset(self.root, project_id="project-a", session_id="asset-session",
            source_root=directory, path="demo.bin", asset_kind="binary", build_id="v2")
        self.assertEqual(newer["payload"]["version"], 2)
        rows = {row["id"]: row for row in self.query()["results"]}
        self.assertTrue(rows[first["id"]]["needs_review"])
        self.assertIn("verification_source_needs_review", rows[first["id"]]["review_reasons"])
        self.assertTrue(rows[proposal["id"]]["needs_review"])
        lesson = self.lessons()["results"][0]
        self.assertTrue(lesson["needs_review"])
        self.assertEqual(lesson["review_state"], "accept")
        with self.assertRaisesRegex(ValueError, "stale"):
            self.proposal(experience_ids=[first["id"], second["id"]])
        with self.assertRaisesRegex(ValueError, "needs review"):
            self.review(proposal, expected_review_id=review["id"])
        self.assertEqual(len(read_records(self.root, project_id="project-a", kinds=["procedure"])), 1)
        self.assertEqual(len(read_records(self.root, project_id="project-a", kinds=["procedure_review"])), 1)

    def test_linked_investigation_finding_inherits_asset_currentness(self) -> None:
        directory = self.directory / "assets"
        directory.mkdir()
        (directory / "demo.bin").write_bytes(b"MZ\x00disposable-fixture")
        asset = register_analysis_asset(self.root, project_id="project-a", session_id="asset-session",
            source_root=directory, path="demo.bin", asset_kind="binary", build_id="v1")
        finding = record_analysis_finding(self.root, project_id="project-a", session_id="asset-session",
            asset_id=asset["id"], asset_hash=asset["payload"]["source_hash"], title="Parser observation",
            text="The parser entry is at this function.", analyst="fixture-analyst", function="parse")
        first = self.attempt(verification=[{"kind": "scroll_event", "id": finding["id"], "content_hash": finding["content_hash"]}])
        second = self.attempt()
        proposal = self.proposal(experience_ids=[first["id"], second["id"]])
        (directory / "demo.bin").write_bytes(b"MZ\x00changed-disposable-fixture")
        register_analysis_asset(self.root, project_id="project-a", session_id="asset-session",
            source_root=directory, path="demo.bin", asset_kind="binary", build_id="v2")
        with self.assertRaisesRegex(ValueError, "needs review"):
            self.review(proposal)
        self.assertTrue(self.lessons(accepted_only=False)["results"][0]["needs_review"])


if __name__ == "__main__":
    unittest.main()
