"""Cross-domain acceptance using disposable memory and synthetic local inputs."""

from __future__ import annotations

import hashlib
import json
import socket
import tempfile
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from continuum.core.config import default_config, write_config
from continuum.core.coordination import (
    create_collection,
    create_handoff,
    query_collections,
    query_handoffs,
    transition_handoff,
)
from continuum.core.experience import (
    find_reusable_lessons,
    propose_procedure,
    query_experiences,
    record_experience,
    review_procedure,
)
from continuum.core.investigation import (
    export_investigation_notebook,
    query_investigation,
    record_analysis_finding,
    record_media_annotation,
    record_notebook_entry,
    register_analysis_asset,
)
from continuum.core.knowledge_records import read_records
from continuum.core.project_knowledge import (
    index_project_files,
    record_project_knowledge,
)
from continuum.core.store import init_db
from continuum.core.working_context import (
    change_impact,
    compile_task_pack,
    select_working_context,
)
from continuum.core.workspaces import (
    adopt_experiment_records,
    compare_experiment_replays,
    create_memory_experiment,
    export_workspace,
    import_workspace,
    replay_memory_experiment,
)


class CapabilityIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(
            prefix="continuum-capability-integration-"
        )
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve(strict=True)
        self.root = self.directory / "source-memory"
        self.source = self.directory / "source-files"
        self.source.mkdir()
        self.project = "parser-investigation"
        self.session = "isolated-integration"
        self.initialize(self.root)
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

    @staticmethod
    def initialize(root: Path) -> None:
        config = default_config()
        config["capture"]["mode"] = "manual"
        config["local_inference"]["enabled"] = False
        write_config(root, config)
        init_db(root)

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

    def records(self) -> list[dict]:
        return read_records(self.root, project_id=self.project)

    def scoped(self) -> dict:
        return {"project_id": self.project, "session_id": self.session}

    def source_hashes(self) -> dict[str, str]:
        return {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(self.source.iterdir())
            if path.is_file()
        }

    def recorded_scenario(self) -> dict[str, dict]:
        # Only fixture bytes are created. The stored source is never imported.
        binary_bytes = b"MZ" + (5).to_bytes(4, "little") + b"hello"
        (self.source / "parser.bin").write_bytes(binary_bytes)
        (self.source / "parser.py").write_text(
            "def payload_length(data):\n    return int.from_bytes(data[2:6], 'little')\n",
            encoding="utf-8",
        )
        (self.source / "diagram.png").write_bytes(b"fixture-image\x00length-check")
        index_project_files(
            self.root, **self.scoped(), source_root=self.source, paths=["parser.py"]
        )
        source = self.records()[0]
        binary = register_analysis_asset(
            self.root,
            **self.scoped(),
            source_root=self.source,
            path="parser.bin",
            asset_kind="binary",
            build_id="synthetic-build-one",
        )
        finding = record_analysis_finding(
            self.root,
            **self.scoped(),
            asset_id=binary["id"],
            asset_hash=binary["payload"]["source_hash"],
            title="Payload length",
            text="The four-byte little-endian field begins at offset two.",
            analyst="fixture-operator",
            function="payload_length",
            address="0x2",
            source_symbol={
                "record_id": source["id"],
                "content_hash": source["content_hash"],
                "symbol": "payload_length",
            },
        )
        image = register_analysis_asset(
            self.root,
            **self.scoped(),
            source_root=self.source,
            path="diagram.png",
            asset_kind="image",
            build_id="synthetic-build-one",
        )
        annotation = record_media_annotation(
            self.root,
            **self.scoped(),
            asset_id=image["id"],
            asset_hash=image["payload"]["source_hash"],
            title="Diagram evidence",
            text="Supplied diagram label identifies a length check.",
            anchor={"region": [0.1, 0.2, 0.8, 0.9]},
        )

        failed = record_experience(
            self.root,
            **self.scoped(),
            goal="Read the payload length",
            approach="Use a big-endian field",
            prerequisites={"format": "synthetic-length-v1"},
            steps=["Read bytes two through five as big-endian."],
            outcome="failure",
            observed_result=f"Observed {int.from_bytes(binary_bytes[2:6], 'big')}, expected 5.",
            verification=[self.citation(binary)],
        )
        self.assertNotEqual(int.from_bytes(binary_bytes[2:6], "big"), 5)
        attempts, checks = [], []
        for expected in (5, 9):
            sample = b"MZ" + expected.to_bytes(4, "little") + b"x" * expected
            actual = int.from_bytes(sample[2:6], "little")
            self.assertEqual(actual, expected)
            check = record_project_knowledge(
                self.root,
                **self.scoped(),
                kind="test",
                title=f"Length fixture {expected}",
                summary=f"Synthetic header decoded to {actual}; expected {expected}.",
                links=[{"relation": "tests", "target_id": source["id"]}],
                evidence=[self.citation(source), self.citation(binary)],
            )
            checks.append(check)
            attempts.append(
                record_experience(
                    self.root,
                    **self.scoped(),
                    goal="Read the payload length",
                    approach="Use the little-endian header field",
                    prerequisites={"format": "synthetic-length-v1"},
                    steps=[
                        "Check the two-byte magic.",
                        "Read four bytes at offset two as little-endian.",
                    ],
                    outcome="success",
                    observed_result=f"Decoded {actual}; matched expected {expected}.",
                    verification=[self.citation(source), self.citation(check)],
                )
            )
        procedure = propose_procedure(
            self.root,
            **self.scoped(),
            experience_ids=[row["id"] for row in attempts],
            title="Read the bounded length header",
        )
        review = review_procedure(
            self.root,
            **self.scoped(),
            procedure_id=procedure["id"],
            decision="accept",
            reviewer="fixture-operator",
            reason="Two distinct cited synthetic checks matched.",
        )
        notebook = record_notebook_entry(
            self.root,
            **self.scoped(),
            notebook_id="length-notebook",
            entry_kind="conclusion",
            title="Retain the failed alternative",
            text="Little-endian fits both synthetic checks; keep the failed big-endian approach visible.",
            links=[
                self.link(finding),
                self.link(annotation),
                self.link(failed, "contradicts"),
                self.link(procedure),
            ],
            evidence=[self.citation(check) for check in checks],
        )
        collection = create_collection(
            self.root,
            **self.scoped(),
            title="Header investigation",
            summary="One binary mapping, failed alternative, and checked procedure.",
            overview="The procedure is an accepted local inference from recorded synthetic checks, not independently verified truth.",
            members=[
                self.citation(row)
                for row in (finding, failed, procedure, notebook, annotation)
            ],
        )
        handoff = create_handoff(
            self.root,
            **self.scoped(),
            objective="Continue the header investigation against any updated input.",
            actor="agent-one",
            accepted_decisions=["Use little-endian for the recorded build only."],
            unfinished_work=["Recheck exact source and binary hashes before reuse."],
            evidence=[
                self.citation(collection),
                self.citation(procedure),
                self.citation(notebook),
            ],
        )

        moment = datetime(2030, 1, 1, tzinfo=timezone.utc)
        with patch("continuum.core.coordination._now", return_value=moment):
            claimed = transition_handoff(
                self.root,
                **self.scoped(),
                handoff_id=handoff["id"],
                expected_head=handoff["id"],
                action="claim",
                actor="agent-one",
                lease_seconds=30,
            )
        with patch(
            "continuum.core.coordination._now",
            return_value=moment + timedelta(seconds=30),
        ):
            expired = query_handoffs(
                self.root, project_id=self.project, handoff_id=handoff["id"]
            )["results"][0]
            self.assertEqual(expired["status"], "expired")
            recovered = transition_handoff(
                self.root,
                **self.scoped(),
                handoff_id=handoff["id"],
                expected_head=claimed["id"],
                action="claim",
                actor="agent-two",
                lease_seconds=60,
            )
            with self.assertRaises(ValueError):
                transition_handoff(
                    self.root,
                    **self.scoped(),
                    handoff_id=handoff["id"],
                    expected_head=claimed["id"],
                    action="complete",
                    actor="agent-one",
                )
            state = query_handoffs(
                self.root,
                project_id=self.project,
                handoff_id=handoff["id"],
                include_history=True,
                token_budget=5000,
            )["results"][0]
        self.assertEqual(state["owner"], "agent-two")
        self.assertEqual(state["head"], recovered["id"])
        self.assertEqual(len(state["history"]), 2)
        return {
            "source": source,
            "binary": binary,
            "finding": finding,
            "image": image,
            "annotation": annotation,
            "failed": failed,
            "first_success": attempts[0],
            "second_success": attempts[1],
            "procedure": procedure,
            "review": review,
            "notebook": notebook,
            "collection": collection,
            "handoff": handoff,
            "recovered": recovered,
        }

    def assert_bounded(self, packet: dict, budget: int) -> None:
        wire = json.dumps(
            packet, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        )
        self.assertLessEqual(len(wire), budget * 4)
        self.assertEqual(json.loads(wire), packet)
        self.assertEqual(
            packet["matched_count"],
            packet["result_count"] + packet["excluded_by_budget"],
        )

    def test_investigation_to_recovered_handoff_and_changed_input(self) -> None:
        scenario = self.recorded_scenario()
        raw_before = self.records()
        files_before = self.source_hashes()
        experiences = query_experiences(
            self.root, project_id=self.project, token_budget=16000
        )
        experience_ids = {row["id"] for row in experiences["results"]}
        self.assertTrue(
            {
                scenario[name]["id"]
                for name in ("failed", "first_success", "second_success", "procedure")
            }
            <= experience_ids
        )
        proposal = next(
            row
            for row in experiences["results"]
            if row["id"] == scenario["procedure"]["id"]
        )
        self.assertEqual(proposal["review_state"], "accept")
        self.assertFalse(proposal["auto_apply"])
        lessons = find_reusable_lessons(
            self.root,
            source_projects=[self.project],
            goal="payload length",
            prerequisites={"format": "synthetic-length-v1"},
            token_budget=5000,
        )
        self.assertEqual(lessons["result_count"], 1)
        self.assertTrue(lessons["results"][0]["applicability"]["prerequisites_match"])
        self.assertFalse(lessons["results"][0]["applicability"]["applied"])
        summary = query_collections(
            self.root,
            project_id=self.project,
            collection_id=scenario["collection"]["id"],
        )
        self.assertTrue(
            all("source" not in row for row in summary["results"][0]["members"])
        )
        expanded = query_collections(
            self.root,
            project_id=self.project,
            collection_id=scenario["collection"]["id"],
            detail="full",
            member_index=0,
            member_limit=1000,
            token_budget=5000,
        )
        exact_member = expanded["results"][0]["members"][0]
        self.assertEqual(exact_member["citation"], self.citation(scenario["finding"]))
        self.assertEqual(exact_member["source_state"], "current")
        self.assertIn("source", exact_member)
        notebook = export_investigation_notebook(
            self.root, project_id=self.project, notebook_id="length-notebook"
        )
        self.assertEqual(notebook["result_count"], 1)
        self.assertIn(scenario["failed"]["id"], notebook["markdown"])

        selected = [
            scenario[name]["id"]
            for name in (
                "failed",
                "procedure",
                "notebook",
                "collection",
                "handoff",
                "recovered",
            )
        ]
        pack = compile_task_pack(
            self.root,
            project_id=self.project,
            purpose="resume",
            record_ids=selected,
            token_budget=16000,
        )
        self.assert_bounded(pack, 16000)
        self.assertTrue(
            set(selected) <= {row["citation"]["id"] for row in pack["results"]}
        )
        self.assertTrue(
            all(not row["record"]["needs_review"] for row in pack["results"] if "record" in row)
        )
        for row in pack["results"]:
            if "source" in row:
                self.assertTrue(row["source"]["found"])
                self.assertEqual(row["source"]["content_hash"], row["citation"]["content_hash"])
        tiny = compile_task_pack(
            self.root, project_id=self.project, record_ids=selected, token_budget=512
        )
        self.assert_bounded(tiny, 512)
        self.assertGreater(tiny["excluded_by_budget"], 0)
        with self.assertRaises(ValueError):
            compile_task_pack(
                self.root,
                project_id="unrelated-project",
                record_ids=selected,
                token_budget=512,
            )
        self.assertEqual(raw_before, self.records())
        self.assertEqual(files_before, self.source_hashes())

        # The only deliberate source modifications in this scenario.
        (self.source / "parser.py").write_text(
            "def payload_length(data):\n    return 0\n", encoding="utf-8"
        )
        (self.source / "parser.bin").write_bytes(b"MZ\x00changed-build")
        index_project_files(
            self.root, **self.scoped(), source_root=self.source, paths=["parser.py"]
        )
        newer_asset = register_analysis_asset(
            self.root,
            **self.scoped(),
            source_root=self.source,
            path="parser.bin",
            asset_kind="binary",
            build_id="synthetic-build-two",
        )
        self.assertEqual(newer_asset["payload"]["version"], 2)
        impact = change_impact(self.root, project_id=self.project, token_budget=16000)
        self.assert_bounded(impact, 16000)
        impact_by_id = {row["id"]: row for row in impact["results"]}
        for name in (
            "source",
            "binary",
            "finding",
            "first_success",
            "second_success",
            "procedure",
            "notebook",
            "collection",
            "handoff",
        ):
            self.assertIn(scenario[name]["id"], impact_by_id, name)
            self.assertTrue(impact_by_id[scenario[name]["id"]]["needs_review"], name)
        investigation = query_investigation(
            self.root, project_id=self.project, include_history=True, token_budget=16000
        )
        self.assertEqual(
            {
                row["id"]
                for row in investigation["results"]
                if row["kind"] == "analysis_asset"
            },
            {scenario["binary"]["id"], scenario["image"]["id"], newer_asset["id"]},
        )
        after = {row["id"]: row for row in self.records()}
        for old in raw_before:
            self.assertEqual(after[old["id"]], old)
        self.exercise_workspace(scenario)

    def test_real_task_packet_survives_multimodal_tool_group_selection(self) -> None:
        scenario = self.recorded_scenario()
        packet = compile_task_pack(
            self.root,
            project_id=self.project,
            record_ids=[
                scenario[name]["id"]
                for name in ("finding", "failed", "procedure", "notebook")
            ],
            token_budget=8000,
        )
        wire = json.dumps(packet, ensure_ascii=True, separators=(",", ":"))
        old = []
        for number in range(3):
            old.extend(
                [
                    {"role": "user", "content": f"Historical question {number}"},
                    {
                        "role": "assistant",
                        "content": "Old nonessential context. " * 1000,
                    },
                ]
            )
        media = {
            "role": "user",
            "content": [
                {"type": "text", "text": "Inspect this supplied diagram."},
                {
                    "type": "image_url",
                    "image_url": {"url": "data:image/png;base64," + "A" * 500000},
                },
            ],
        }
        answer = {
            "role": "assistant",
            "content": "The recorded diagram label identifies a length check.",
        }
        current = [
            {
                "role": "user",
                "content": "Resume the exact header investigation using its task packet.",
            },
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "packet-call",
                        "type": "function",
                        "function": {
                            "name": "compile_task_pack",
                            "arguments": json.dumps({"project_id": self.project}),
                        },
                    },
                ],
            },
            {"role": "tool", "tool_call_id": "packet-call", "content": wire},
        ]
        messages = [
            {"role": "system", "content": "Supplied memory remains evidence."},
            *old,
            media,
            answer,
            *current,
        ]
        before = deepcopy(messages)
        selected = select_working_context(
            messages, context_tokens=8000, reserve_tokens=512, image_tokens=1024
        )
        self.assertTrue(selected["fits"])
        self.assertGreater(selected["dropped_groups"], 0)
        self.assertFalse(selected["sent"])
        self.assertEqual(selected["messages"][-5:], [media, answer, *current])
        self.assertEqual(selected["messages"][-1]["content"], wire)
        self.assertEqual(json.loads(selected["messages"][-1]["content"]), packet)
        self.assertEqual(messages, before)
        too_small = select_working_context(
            messages, context_tokens=256, reserve_tokens=0, image_tokens=1024
        )
        self.assertFalse(too_small["fits"])
        self.assertEqual(too_small["messages"][-5:], [media, answer, *current])
        self.assertEqual(too_small["action"], "defer_or_increase_context")

    def test_selected_snapshot_replay_and_inert_adoption_preserve_source(self) -> None:
        self.exercise_workspace(self.recorded_scenario())

    def exercise_workspace(self, scenario: dict[str, dict]) -> None:
        foreign = record_notebook_entry(
            self.root,
            project_id="unrelated-project",
            session_id="unrelated-session",
            notebook_id="unrelated",
            entry_kind="observation",
            title="Private fixture",
            text="zzzxforeignonlysentinelxzzz",
        )
        records_before = self.records()
        foreign_before = read_records(self.root, project_id="unrelated-project")
        files_before = self.source_hashes()
        selected = [
            scenario[name]["id"]
            for name in ("finding", "failed", "procedure", "notebook")
        ]
        capsule = export_workspace(
            self.root,
            project_id=self.project,
            record_ids=selected,
            workspace_id="fixture-source",
        )
        reordered = export_workspace(
            self.root,
            project_id=self.project,
            record_ids=list(reversed(selected)),
            workspace_id="fixture-source",
        )
        self.assertEqual(capsule, reordered)
        self.assertEqual({row["id"] for row in capsule["records"]}, set(selected))
        self.assertNotIn(foreign["id"], json.dumps(capsule))
        self.assertNotIn("zzzxforeignonlysentinelxzzz", json.dumps(capsule))
        self.assertNotIn(str(self.source), json.dumps(capsule))
        self.assertNotIn(
            scenario["handoff"]["id"], {row["id"] for row in capsule["records"]}
        )
        with self.assertRaises(ValueError):
            export_workspace(
                self.root,
                project_id=self.project,
                record_ids=[foreign["id"]],
                workspace_id="fixture-source",
            )

        peer = self.directory / "portable-peer"
        self.initialize(peer)
        imported = import_workspace(
            peer,
            project_id="received-evidence",
            session_id="portable-import",
            capsule=capsule,
            expected_snapshot_hash=capsule["snapshot_hash"],
        )
        repeated = import_workspace(
            peer,
            project_id="received-evidence",
            session_id="portable-retry",
            capsule=capsule,
            expected_snapshot_hash=capsule["snapshot_hash"],
        )
        self.assertEqual(imported["imported"], 4)
        self.assertEqual(repeated["imported"], 0)
        self.assertEqual(repeated["unchanged"], 4)
        self.assertFalse(imported["activated"])
        peer_records = read_records(peer, project_id="received-evidence")
        self.assertEqual({row["kind"] for row in peer_records}, {"shared_knowledge"})
        self.assertEqual(
            {row["payload"]["origin"]["record_id"] for row in peer_records},
            set(selected),
        )
        self.assertTrue(
            all(
                row["payload"]["origin"]["project_id"] == self.project
                for row in peer_records
            )
        )
        self.assertTrue(
            all(
                row["payload"]["trust"] == "accepted_evidence_not_verified_or_active"
                for row in peer_records
            )
        )
        self.assertEqual(
            query_handoffs(peer, project_id="received-evidence")["result_count"], 0
        )
        self.assertEqual(
            query_experiences(peer, project_id="received-evidence")["result_count"], 0
        )

        experiment_root = self.directory / "memory-experiment"
        experiment = create_memory_experiment(
            self.root,
            project_id=self.project,
            record_ids=selected,
            workspace_id="fixture-experiment",
            destination=experiment_root,
        )
        self.assertEqual(experiment["seeded"], 4)
        self.assertFalse(experiment["provider_used"])
        self.assertFalse(experiment["source_mutated"])
        self.assertEqual(
            {row["source"]["id"] for row in experiment["mapping"]}, set(selected)
        )
        queries = ["little-endian header", "big-endian", "zzzxforeignonlysentinelxzzz"]
        replay_before = replay_memory_experiment(
            experiment_root,
            queries=queries,
            expected_manifest_hash=experiment["manifest_sha256"],
            token_budget=5000,
        )
        self.assertFalse(replay_before["provider_used"])
        self.assertTrue(any(query["results"] for query in replay_before["queries"][:2]))
        self.assertTrue(replay_before["queries"][-1]["abstained"])
        for query in replay_before["queries"]:
            self.assertTrue(
                all(row["source"]["id"] in selected for row in query["results"])
            )
            self.assertTrue(
                all(
                    row["source"]["project_id"] == self.project
                    for row in query["results"]
                )
            )

        working_observation = record_notebook_entry(
            experiment_root,
            project_id=self.project,
            session_id="experiment-only",
            notebook_id="experiment-notes",
            entry_kind="observation",
            title="Working-root-only observation",
            text="This new selected observation is not part of the frozen retrieval snapshot.",
        )
        replay_after = replay_memory_experiment(
            experiment_root,
            queries=queries,
            expected_manifest_hash=experiment["manifest_sha256"],
            token_budget=5000,
        )
        self.assertEqual(replay_before, replay_after)
        comparison = compare_experiment_replays(replay_before, replay_after)
        self.assertEqual(comparison["quality_judgement"], "not_evaluated")
        self.assertTrue(
            all(
                not row["rank_changes"]
                and not row["packet_changed"]
                and not row["results_changed"]
                for row in comparison["queries"]
            )
        )
        accepted_root = self.directory / "accepted-work"
        self.initialize(accepted_root)
        accepted = adopt_experiment_records(
            experiment_root,
            record_ids=[working_observation["id"]],
            target_root=accepted_root,
            project_id="accepted-project",
            session_id="accepted-observation",
            workspace_id="accepted-experiment",
            expected_manifest_hash=experiment["manifest_sha256"],
        )
        repeated_adoption = adopt_experiment_records(
            experiment_root,
            record_ids=[working_observation["id"]],
            target_root=accepted_root,
            project_id="accepted-project",
            session_id="accepted-retry",
            workspace_id="accepted-experiment",
            expected_manifest_hash=experiment["manifest_sha256"],
        )
        self.assertEqual(accepted["imported"], 1)
        self.assertFalse(accepted["activated"])
        self.assertEqual(repeated_adoption["unchanged"], 1)
        accepted_records = read_records(accepted_root, project_id="accepted-project")
        self.assertEqual(len(accepted_records), 1)
        self.assertEqual(accepted_records[0]["kind"], "shared_knowledge")
        self.assertEqual(
            accepted_records[0]["payload"]["origin"]["record_id"],
            working_observation["id"],
        )
        self.assertEqual(
            accepted_records[0]["payload"]["source_hash"],
            working_observation["content_hash"],
        )
        self.assertEqual(records_before, self.records())
        self.assertEqual(
            foreign_before, read_records(self.root, project_id="unrelated-project")
        )
        self.assertEqual(files_before, self.source_hashes())


if __name__ == "__main__":
    unittest.main()
