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

from continuum.core.config import default_config, load_config, write_config
from continuum.core.knowledge_records import append_record, read_records
from continuum.core.project_knowledge import record_project_knowledge
from continuum.core.store import (
    _ensure_partition_alias,
    append_scroll_event,
    canonical_partition_identifier,
    connect,
    connect_existing,
    init_db,
)
from continuum.core.workspaces import (
    adopt_experiment_records,
    compare_experiment_replays,
    create_memory_experiment,
    export_workspace,
    import_workspace,
    plan_workspace_import,
    replay_memory_experiment,
    resolve_workspace_conflict,
)


def encoded(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def seal(capsule: dict) -> dict:
    value = copy.deepcopy(capsule)
    value["snapshot_hash"] = hashlib.sha256(encoded({key: item for key, item in value.items() if key != "snapshot_hash"})).hexdigest()
    return value


class WorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="continuum-workspace-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / "memory"
        config = default_config()
        config["capture"]["mode"] = "manual"
        config["capture"]["dedup_window_seconds"] = 0
        config["local_inference"]["enabled"] = False
        write_config(self.root, config)
        init_db(self.root)
        self.target = self.directory / "target"
        blocker = patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden"))
        blocker.start()
        self.addCleanup(blocker.stop)

    def record(self, *, root=None, project="project-a", summary="Parser fixture reproduced the expected bounded output.", title="Parser finding") -> dict:
        return record_project_knowledge(self.root if root is None else root, project_id=project, session_id="fixture-session",
                                        kind="note", title=title, summary=summary)

    def capsule(self, rows=None, **changes) -> dict:
        rows = [self.record()] if rows is None else rows
        args = {"project_id": "project-a", "record_ids": [row["id"] for row in rows], "workspace_id": "fixture-workspace"}
        args.update(changes)
        return export_workspace(self.root, **args)

    def plan(self, capsule, **changes) -> dict:
        args = {"project_id": "target-project", "capsule": capsule, "expected_snapshot_hash": capsule["snapshot_hash"]}
        args.update(changes)
        return plan_workspace_import(self.target, **args)

    def ingest(self, capsule, **changes) -> dict:
        args = {"project_id": "target-project", "session_id": "target-session", "capsule": capsule,
                "expected_snapshot_hash": capsule["snapshot_hash"]}
        args.update(changes)
        return import_workspace(self.target, **args)

    def variant(self, capsule, value="Revised parser conclusion.") -> dict:
        result = copy.deepcopy(capsule)
        source = result["records"][0]
        envelope = json.loads(source["content"])
        envelope["payload"]["summary"] = value
        source["content"] = encoded(envelope).decode()
        source["content_hash"] = hashlib.sha256(source["content"].encode()).hexdigest()
        return seal(result)

    def snapshot(self, root=None) -> dict:
        with closing(connect_existing(self.root if root is None else root)) as conn:
            names = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            return {name: sorted((tuple(row) for row in conn.execute(f'SELECT * FROM "{name}"')), key=repr) for name in names}

    def fill_target_records(self, count: int) -> None:
        """Batch valid unrelated rows without thousands of capture transactions."""
        write_config(self.target, load_config(self.root))
        template_record = self.record(root=self.target, project="target-project", title="Capacity fixture")
        with closing(connect(self.target)) as conn:
            template = dict(conn.execute("SELECT * FROM scroll_events WHERE id=?", (template_record["id"],)).fetchone())
            columns = list(template)
            current = conn.execute("SELECT COUNT(*) FROM scroll_events WHERE event_type='knowledge_record' AND project_id='target-project'").fetchone()[0]
            next_sequence = conn.execute("SELECT MAX(seq) FROM scroll_events").fetchone()[0] + 1
            generated = []
            for index in range(current, count):
                row = dict(template)
                envelope = json.loads(row["content"])
                envelope["nonce"] = f"{index:032x}"
                row["content"] = encoded(envelope).decode()
                row["content_hash"] = hashlib.sha256(row["content"].encode()).hexdigest()
                row["id"] = f"capacity-fixture-{index}"
                row["seq"] = next_sequence + index - current
                generated.append(tuple(row[column] for column in columns))
            names = ",".join('"' + column + '"' for column in columns)
            conn.executemany(f"INSERT INTO scroll_events ({names}) VALUES ({','.join('?' for _ in columns)})", generated)
            conn.commit()
        self.assertEqual(len(read_records(self.target, project_id="target-project")), count)

    def experiment(self, rows=None) -> dict:
        rows = [self.record()] if rows is None else rows
        return create_memory_experiment(self.root, project_id="project-a", record_ids=[row["id"] for row in rows],
                                        workspace_id="fixture-experiment", destination=self.directory / "experiment")

    def replay(self, experiment, **changes) -> dict:
        args = {"queries": ["parser fixture", "missing-nebula-word"], "expected_manifest_hash": experiment["manifest_sha256"]}
        args.update(changes)
        return replay_memory_experiment(Path(experiment["experiment_root"]), **args)

    def test_export_is_exact_deterministic_selection_without_reference_traversal(self) -> None:
        first, second, omitted = self.record(), self.record(title="Second finding"), self.record(title="Not selected")
        before = self.snapshot()
        capsule = self.capsule([first, second])
        self.assertEqual(capsule, self.capsule([second, first]))
        self.assertEqual({row["id"] for row in capsule["records"]}, {first["id"], second["id"]})
        self.assertNotIn(omitted["id"], encoded(capsule).decode())
        for row in capsule["records"]:
            self.assertEqual(hashlib.sha256(row["content"].encode()).hexdigest(), row["content_hash"])
        self.assertEqual(capsule, seal(capsule))
        self.assertEqual(self.snapshot(), before)

    def test_export_rejects_private_session_other_project_and_missing_records(self) -> None:
        first = self.record()
        other = self.record(project="project-b")
        for ids in ([other["id"]], ["missing-record"], [first["id"], first["id"]], []):
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                self.capsule([first], record_ids=ids)
        for visibility in ("private", "session"):
            with closing(connect(self.root)) as conn:
                conn.execute("UPDATE scroll_events SET visibility_scope=? WHERE id=?", (visibility, first["id"]))
                conn.commit()
            with self.subTest(visibility=visibility), self.assertRaises(ValueError):
                self.capsule([first])

    def test_plan_missing_target_is_nonmutating_and_import_is_inert_idempotent(self) -> None:
        capsule = self.capsule()
        plan = self.plan(capsule)
        self.assertTrue(plan["can_import"])
        self.assertEqual(plan["results"][0]["status"], "import")
        self.assertFalse(self.target.exists())
        imported = self.ingest(capsule)
        self.assertEqual(imported["imported"], 1)
        self.assertFalse(imported["activated"])
        first = read_records(self.target, project_id="target-project")
        self.assertEqual([row["kind"] for row in first], ["shared_knowledge"])
        self.assertEqual(first[0]["payload"]["trust"], "accepted_evidence_not_verified_or_active")
        before = self.snapshot(self.target)
        again = self.ingest(capsule)
        self.assertEqual(again["unchanged"], 1)
        self.assertEqual(again["results"][0]["id"], imported["results"][0]["id"])
        self.assertEqual(self.snapshot(self.target), before)
        self.assertEqual(self.plan(capsule)["results"][0]["status"], "unchanged")

    def test_all_input_validated_before_first_write(self) -> None:
        capsule = self.capsule([self.record(), self.record(title="Second")])
        capsule["records"][1]["content_hash"] = "0" * 64
        capsule = seal(capsule)
        with self.assertRaises(ValueError):
            self.ingest(capsule)
        self.assertFalse(self.target.exists())

    def test_origin_conflict_preserves_both_only_after_explicit_fork(self) -> None:
        capsule = self.capsule()
        first = self.ingest(capsule)
        changed = self.variant(capsule)
        before = self.snapshot(self.target)
        self.assertFalse(self.plan(changed)["can_import"])
        with self.assertRaisesRegex(ValueError, "origin conflict"):
            self.ingest(changed)
        self.assertEqual(self.snapshot(self.target), before)
        fork = self.ingest(changed, allow_fork=True)
        self.assertEqual(fork["results"][0]["status"], "forked")
        self.assertNotEqual(first["results"][0]["id"], fork["results"][0]["id"])
        self.assertEqual(len(read_records(self.target, project_id="target-project")), 2)

    def test_conflict_decisions_are_exact_variant_set_and_head_cas(self) -> None:
        capsule = self.capsule()
        first = self.ingest(capsule)
        second = self.variant(capsule)
        self.ingest(second, allow_fork=True)
        origin = first["results"][0]["origin"]
        hashes = [capsule["records"][0]["content_hash"], second["records"][0]["content_hash"]]
        args = {"project_id": "target-project", "session_id": "review-session", "origin": origin,
                "variant_hashes": hashes, "selected_hash": hashes[1], "reviewer": "local-operator", "reason": "Reviewed exact variants."}
        decision = resolve_workspace_conflict(self.target, **args)
        with self.assertRaisesRegex(ValueError, "head changed"):
            resolve_workspace_conflict(self.target, **args)
        changed = {**args, "expected_decision_id": decision["id"], "selected_hash": hashes[0]}
        resolve_workspace_conflict(self.target, **changed)
        third = self.variant(capsule, "Third independent conclusion.")
        self.ingest(third, allow_fork=True)
        plan = self.plan(capsule)
        self.assertFalse(plan["results"][0]["decision_current"])
        with self.assertRaises(ValueError):
            resolve_workspace_conflict(self.target, **changed)
        self.assertEqual(len(read_records(self.target, project_id="target-project", kinds=["shared_knowledge"])), 3)

    def test_parallel_imports_are_idempotent_under_the_capture_transaction(self) -> None:
        capsule = self.capsule()
        config = default_config()
        config["capture"]["mode"] = "manual"
        write_config(self.target, config)
        init_db(self.target)
        barrier = Barrier(2)

        def import_one(_):
            barrier.wait(timeout=10)
            return self.ingest(capsule)

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(import_one, range(2)))
        self.assertEqual(sum(row["imported"] for row in results), 1)
        self.assertEqual({row["results"][0]["id"] for row in results}, {results[0]["results"][0]["id"]})
        self.assertEqual(len(read_records(self.target, project_id="target-project")), 1)

    def test_parallel_conflicting_imports_preserve_one_without_implicit_fork(self) -> None:
        capsule = self.capsule()
        variant = self.variant(capsule)
        config = default_config()
        config["capture"]["mode"] = "manual"
        write_config(self.target, config)
        init_db(self.target)
        barrier = Barrier(2)

        def import_one(value):
            barrier.wait(timeout=10)
            try:
                self.ingest(value)
                return "accepted"
            except ValueError:
                return "conflict"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(import_one, [capsule, variant]))
        self.assertEqual(sorted(results), ["accepted", "conflict"])
        self.assertEqual(len(read_records(self.target, project_id="target-project")), 1)

    def test_parallel_decisions_have_one_current_head(self) -> None:
        capsule = self.capsule()
        first = self.ingest(capsule)
        variant = self.variant(capsule)
        self.ingest(variant, allow_fork=True)
        hashes = [capsule["records"][0]["content_hash"], variant["records"][0]["content_hash"]]
        barrier = Barrier(2)

        def choose(selected):
            barrier.wait(timeout=10)
            try:
                resolve_workspace_conflict(self.target, project_id="target-project", session_id="review",
                    origin=first["results"][0]["origin"], variant_hashes=hashes, selected_hash=selected,
                    reviewer="operator", reason="Explicit review.")
                return "accepted"
            except ValueError:
                return "conflict"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(choose, hashes))
        self.assertEqual(sorted(results), ["accepted", "conflict"])

    def test_capsule_hash_shapes_bounds_and_source_scope_are_strict(self) -> None:
        original = self.capsule()
        mutations = []
        changed = copy.deepcopy(original)
        changed["schema"] = "unknown"
        mutations.append(seal(changed))
        changed = copy.deepcopy(original)
        changed["source_project"] = "different-project"
        mutations.append(seal(changed))
        changed = copy.deepcopy(original)
        changed["records"] *= 2
        mutations.append(seal(changed))
        changed = copy.deepcopy(original)
        changed["records"][0]["kind"] = "system_instruction"
        mutations.append(seal(changed))
        changed = copy.deepcopy(original)
        changed["records"][0]["content"] += " "
        mutations.append(seal(changed))
        for value in mutations:
            with self.subTest(value=value["schema"]), self.assertRaises(ValueError):
                self.ingest(value)
        for changes in ({"expected_snapshot_hash": "0" * 64}, {"allow_fork": 1}, {"expected_snapshot_hash": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.ingest(original, **changes)
        self.assertFalse(self.target.exists())

    def test_nested_escaped_credentials_and_duplicate_source_json_rejected(self) -> None:
        original = self.capsule()
        binding = "synthetic" + "-not-a-real-binding"
        for content in (
            original["records"][0]["content"].replace('"summary":', '"summary":"safe","summary":', 1),
            original["records"][0]["content"].replace('"summary":', '"api_\\u006bey":"' + binding + '","summary":', 1),
        ):
            changed = copy.deepcopy(original)
            changed["records"][0]["content"] = content
            changed["records"][0]["content_hash"] = hashlib.sha256(content.encode()).hexdigest()
            with self.assertRaises(ValueError):
                self.ingest(seal(changed))
        self.assertFalse(self.target.exists())

    def test_capsule_size_and_record_count_fail_before_writes(self) -> None:
        row = self.record()
        for ids in ([], [row["id"]] * 33, True):
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                export_workspace(self.root, project_id="project-a", workspace_id="workspace", record_ids=ids)
        oversized = append_record(self.root, project_id="project-a", session_id="s", kind="project_knowledge", payload={"note": "x" * 50000})
        with self.assertRaises(ValueError):
            self.capsule([oversized])
        with self.assertRaises(ValueError):
            self.ingest({"padding": "x" * (512 * 1024 + 1), "snapshot_hash": "0" * 64})
        self.assertFalse(self.target.exists())

    def test_experiment_seeds_only_selected_evidence_without_source_mutation(self) -> None:
        first, second = self.record(), self.record(title="Omitted source")
        before = self.snapshot()
        experiment = self.experiment([first])
        root = Path(experiment["experiment_root"])
        config = load_config(root)
        self.assertEqual(config["capture"]["mode"], "manual")
        self.assertFalse(config["local_inference"]["enabled"])
        rows = read_records(root, project_id="project-a")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["kind"], "shared_knowledge")
        self.assertNotIn(second["id"], repr(rows))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(experiment["seeded"], 1)
        self.assertFalse(experiment["provider_used"])

    def test_replay_is_actual_fixed_snapshot_and_deterministic_after_working_changes(self) -> None:
        source = self.record()
        experiment = self.experiment([source])
        first = self.replay(experiment)
        self.assertFalse(first["provider_used"])
        self.assertEqual(first["queries"][0]["results"][0]["source"]["id"], source["id"])
        self.assertTrue(first["queries"][1]["abstained"])
        self.record(root=Path(experiment["experiment_root"]), title="Working root mutation", summary="Missing-nebula-word now has a new working record.")
        before = self.snapshot(Path(experiment["experiment_root"]))
        with patch("continuum.core.workspaces.recall_memory", wraps=__import__("continuum.core.recall", fromlist=["recall_memory"]).recall_memory) as actual:
            second = self.replay(experiment)
        self.assertEqual(actual.call_count, 2)
        self.assertEqual(first, second)
        self.assertEqual(self.snapshot(Path(experiment["experiment_root"])), before)
        self.assertNotIn(str(self.directory), encoded(first).decode())
        comparison = compare_experiment_replays(first, second)
        self.assertTrue(all(not row["packet_changed"] and not row["results_changed"] and not row["rank_changes"] for row in comparison["queries"]))

    def test_experiment_destination_never_overwrites_or_nests_in_source(self) -> None:
        row = self.record()
        existing = self.directory / "existing"
        existing.mkdir()
        sentinel = existing / "keep.txt"
        sentinel.write_text("preserve", encoding="utf-8")
        for destination in (existing, self.root / "nested", self.root.parent, Path("relative")):
            with self.subTest(destination=destination), self.assertRaises(ValueError):
                create_memory_experiment(self.root, project_id="project-a", record_ids=[row["id"]], workspace_id="experiment", destination=destination)
        self.assertEqual(sentinel.read_text(), "preserve")
        self.assertFalse((self.root / "nested").exists())

    def test_experiment_rejects_linked_destination_parent(self) -> None:
        row = self.record()
        link = self.directory / "link"
        actual = self.directory / "actual"
        actual.mkdir()
        try:
            link.symlink_to(actual, target_is_directory=True)
        except OSError:
            self.skipTest("creating symlinks is unavailable on this host")
        with self.assertRaises(ValueError):
            create_memory_experiment(self.root, project_id="project-a", record_ids=[row["id"]], workspace_id="experiment", destination=link / "child")
        self.assertFalse((actual / "child").exists())

    def test_replay_rejects_changed_manifest_and_frozen_snapshot(self) -> None:
        experiment = self.experiment()
        with self.assertRaisesRegex(ValueError, "manifest hash"):
            self.replay(experiment, expected_manifest_hash="0" * 64)
        snapshot = Path(experiment["experiment_root"]) / ".experiment" / "snapshot.sqlite3"
        with snapshot.open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(ValueError, "artifact hash"):
            self.replay(experiment)

    def test_adoption_selects_only_working_records_and_keeps_import_inert(self) -> None:
        experiment = self.experiment()
        working = Path(experiment["experiment_root"])
        selected = self.record(root=working, title="Adopted experiment finding")
        omitted = self.record(root=working, title="Not adopted")
        result = adopt_experiment_records(working, record_ids=[selected["id"]], target_root=self.target,
            project_id="target-project", session_id="adoption", workspace_id="selected-adoption",
            expected_manifest_hash=experiment["manifest_sha256"])
        self.assertEqual(result["imported"], 1)
        records = read_records(self.target, project_id="target-project")
        self.assertEqual([row["kind"] for row in records], ["shared_knowledge"])
        self.assertIn(selected["id"], repr(records))
        self.assertNotIn(omitted["id"], repr(records))
        again = adopt_experiment_records(working, record_ids=[selected["id"]], target_root=self.target,
            project_id="target-project", session_id="adoption", workspace_id="selected-adoption",
            expected_manifest_hash=experiment["manifest_sha256"])
        self.assertEqual(again["unchanged"], 1)

    def test_replay_inputs_and_comparison_evidence_are_strict(self) -> None:
        experiment = self.experiment()
        for changes in ({"queries": []}, {"queries": ["same", "same"]}, {"queries": [False]},
                        {"queries": ["x" * 1025]}, {"limit": True}, {"limit": 33}, {"token_budget": False}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.replay(experiment, **changes)
        first = self.replay(experiment)
        changed = copy.deepcopy(first)
        changed["queries"][0]["results"] = []
        with self.assertRaises(ValueError):
            compare_experiment_replays(first, changed)
        different = self.replay(experiment, queries=["a different query"])
        with self.assertRaisesRegex(ValueError, "identical query"):
            compare_experiment_replays(first, different)

    def test_missing_source_export_and_target_plan_leave_paths_absent(self) -> None:
        absent = self.directory / "absent"
        with self.assertRaises(ValueError):
            export_workspace(absent, project_id="project-a", record_ids=["missing"], workspace_id="workspace")
        self.assertFalse(absent.exists())
        self.plan(self.capsule())
        self.assertFalse(self.target.exists())

    def test_inconsistent_original_provenance_mapping_is_rejected(self) -> None:
        first, second = self.record(), self.record(title="Distinct source")
        experiment = self.experiment([first, second])
        manifest_path = Path(experiment["experiment_root"]) / ".experiment" / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["mapping"][0]["source"], manifest["mapping"][1]["source"] = manifest["mapping"][1]["source"], manifest["mapping"][0]["source"]
        manifest_path.write_bytes(encoded(manifest))
        with self.assertRaisesRegex(ValueError, "original provenance"):
            self.replay(experiment, expected_manifest_hash=hashlib.sha256(encoded(manifest)).hexdigest())

    def test_invalid_resolution_does_not_initialize_missing_target(self) -> None:
        with self.assertRaises(ValueError):
            resolve_workspace_conflict(self.target, project_id="target-project", session_id="review",
                origin={"workspace_id": "example", "project_id": "project-a", "record_id": "record"},
                variant_hashes=["0" * 64, "1" * 64], selected_hash="0" * 64, reviewer="operator", reason="No variants exist.")
        self.assertFalse(self.target.exists())

    def test_full_origin_capacity_preflight_rejects_entire_mixed_import(self) -> None:
        capsule = self.capsule()
        capsule["records"][0]["id"] = "z-full-origin"
        capsule = seal(capsule)
        for index in range(32):
            self.ingest(self.variant(capsule, f"Recorded variant {index}."), allow_fork=True)
        candidate = self.variant(capsule, "Unadmitted variant 33.")
        fresh = copy.deepcopy(candidate["records"][0])
        fresh["id"] = "a-fresh-origin"
        candidate["records"].insert(0, fresh)
        candidate = seal(candidate)
        before = self.snapshot(self.target)
        plan = self.plan(candidate, allow_fork=True)
        self.assertFalse(plan["can_import"])
        self.assertEqual([row["status"] for row in plan["results"]], ["import", "capacity_exceeded"])
        with self.assertRaisesRegex(ValueError, "32-variant bound"):
            self.ingest(candidate, allow_fork=True)
        self.assertEqual(self.snapshot(self.target), before)
        records = read_records(self.target, project_id="target-project", kinds=["shared_knowledge"])
        self.assertEqual(len(records), 32)
        self.assertFalse(any(row["payload"]["origin"]["record_id"] == "a-fresh-origin" for row in records))
        unchanged = self.variant(capsule, "Recorded variant 31.")
        self.assertTrue(self.plan(unchanged, allow_fork=True)["can_import"])
        self.assertEqual(self.ingest(unchanged, allow_fork=True)["unchanged"], 1)

    def test_project_record_capacity_preflights_all_new_origins_before_any_write(self) -> None:
        self.fill_target_records(9999)
        capsule = self.capsule([self.record(), self.record(title="Second imported origin")])
        before = self.snapshot(self.target)
        plan = self.plan(capsule)
        self.assertFalse(plan["can_import"])
        self.assertEqual([row["status"] for row in plan["results"]], ["import", "import"])
        self.assertEqual(plan["record_capacity"], {"limit": 10000, "current_records": 9999, "new_records": 2, "exceeded": True})
        with self.assertRaisesRegex(ValueError, "project record capacity"):
            self.ingest(capsule)
        self.assertEqual(self.snapshot(self.target), before)
        self.assertEqual(len(read_records(self.target, project_id="target-project")), 9999)

    def test_project_record_capacity_counts_only_new_variants_and_allows_full_idempotency(self) -> None:
        capsule = self.capsule([self.record(), self.record(title="Second imported origin")])
        first = copy.deepcopy(capsule)
        first["records"] = first["records"][:1]
        self.ingest(seal(first))
        self.fill_target_records(9999)
        mixed_fork = self.variant(capsule, "Preserved fork at the capacity boundary.")
        before = self.snapshot(self.target)
        blocked = self.plan(mixed_fork, allow_fork=True)
        self.assertEqual([row["status"] for row in blocked["results"]], ["fork", "import"])
        self.assertEqual(blocked["record_capacity"]["new_records"], 2)
        self.assertFalse(blocked["can_import"])
        with self.assertRaisesRegex(ValueError, "project record capacity"):
            self.ingest(mixed_fork, allow_fork=True)
        self.assertEqual(self.snapshot(self.target), before)

        plan = self.plan(capsule)
        self.assertTrue(plan["can_import"])
        self.assertEqual(plan["record_capacity"], {"limit": 10000, "current_records": 9999, "new_records": 1, "exceeded": False})
        result = self.ingest(capsule)
        self.assertEqual((result["imported"], result["unchanged"]), (1, 1))
        full = self.snapshot(self.target)
        plan = self.plan(capsule)
        self.assertTrue(plan["can_import"])
        self.assertEqual(plan["record_capacity"], {"limit": 10000, "current_records": 10000, "new_records": 0, "exceeded": False})
        self.assertEqual(self.ingest(capsule)["unchanged"], 2)
        self.assertEqual(self.snapshot(self.target), full)
        self.assertFalse(self.plan(mixed_fork, allow_fork=True)["can_import"])
        with self.assertRaisesRegex(ValueError, "project record capacity"):
            self.ingest(mixed_fork, allow_fork=True)
        self.assertEqual(self.snapshot(self.target), full)

    def test_experiment_preserves_source_canonical_alias_and_destination_partition(self) -> None:
        external = "legacy-project"
        internal = _ensure_partition_alias(self.root, "project_id", external)
        source = self.record(project=external)
        self.assertEqual(source["project_id"], internal)
        before = self.snapshot()
        result = create_memory_experiment(self.root, project_id=external, record_ids=[source["id"]],
            workspace_id="alias-experiment", destination=self.directory / "alias-experiment")
        destination = Path(result["experiment_root"])
        manifest = json.loads((destination / ".experiment" / "manifest.json").read_text())
        self.assertEqual(manifest["source_project"], internal)
        self.assertEqual(manifest["project_id"], result["project_id"])
        self.assertTrue(manifest["project_id"].startswith("workspace-"))
        self.assertEqual(result["mapping"][0]["source"]["project_id"], internal)
        seeded = read_records(destination, project_id=manifest["project_id"])
        self.assertEqual(len(seeded), 1)
        self.assertEqual(seeded[0]["payload"]["origin"]["project_id"], internal)
        first = replay_memory_experiment(destination, queries=["parser"], expected_manifest_hash=result["manifest_sha256"])
        second = replay_memory_experiment(destination, queries=["parser"], expected_manifest_hash=result["manifest_sha256"])
        self.assertEqual(first, second)
        self.assertEqual(first["queries"][0]["results"][0]["source"]["project_id"], internal)
        self.assertEqual(self.snapshot(), before)

    def test_public_capture_alias_canonical_id_seeds_replays_and_adopts(self) -> None:
        config = default_config()
        config["capture"]["mode"] = "manual"
        config["local_inference"]["enabled"] = False
        config["security"]["secret_scan_action"] = "warn"
        write_config(self.root, config)
        binding = "synthetic" + "-review-fixture-only"
        external = "pass" + "word=" + binding
        append_scroll_event(self.root, session_id="alias-source", event_type="message", role="user",
            content="Alias migration fixture", metadata={"project_id": external, "visibility_scope": "project"})
        internal = canonical_partition_identifier(self.root, "project_id", external, lookup=True)
        self.assertNotEqual(internal, external)
        record = self.record(project=internal)
        before = self.snapshot()
        result = create_memory_experiment(self.root, project_id=internal, record_ids=[record["id"]],
            workspace_id="public-alias-experiment", destination=self.directory / "public-alias-experiment")
        destination = Path(result["experiment_root"])
        self.assertEqual(result["seeded"], 1)
        self.assertEqual(result["source_project"], internal)
        self.assertTrue(result["project_id"].startswith("workspace-"))
        replay = replay_memory_experiment(destination, queries=["parser"], expected_manifest_hash=result["manifest_sha256"])
        self.assertEqual(replay["queries"][0]["results"][0]["source"]["project_id"], internal)
        rows = read_records(destination, project_id=result["project_id"])
        adopted = adopt_experiment_records(destination, record_ids=[rows[0]["id"]], target_root=self.target,
            project_id="target-project", session_id="adoption", workspace_id="alias-adoption",
            expected_manifest_hash=result["manifest_sha256"])
        self.assertEqual(adopted["imported"], 1)
        capsule = (destination / ".experiment" / "capsule.json").read_text()
        self.assertNotIn(binding, capsule)
        self.assertNotIn(external, encoded(result).decode())
        self.assertEqual(self.snapshot(), before)


if __name__ == "__main__":
    unittest.main()
