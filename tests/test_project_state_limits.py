from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import continuum.core.store as store_module
from continuum.core.project_state import (
    MAX_PROJECT_STATE_BYTES,
    MAX_PROJECT_STATE_OPEN_TASKS,
    validate_project_state_input,
)
from continuum.core.store import (
    connect,
    create_card,
    cue_recall,
    record_project_state,
    repair_invalid_project_state_checkpoints,
    resume_latest,
    roll_scroll_segment,
    semantic_integrity_report,
    snapshot,
    sync_card_sidecar,
)
from continuum.core.workers import run_worker_pass


class ProjectStateLimitTests(unittest.TestCase):
    def test_core_partition_ids_fail_before_pristine_root_creation(self) -> None:
        for field in ("session_id", "agent_id", "project_id"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                arguments = {
                    "session_id": "valid-session",
                    "agent_id": "valid-agent",
                    "project_id": "valid-project",
                    field: "x" * 129,
                }
                with self.assertRaisesRegex(ValueError, "1-128"):
                    record_project_state(root, **arguments)
                self.assertFalse(root.exists())

    def test_metadata_64_property_boundary_records_and_65_rejects_pristine(
        self,
    ) -> None:
        metadata = {f"property_{index}": index for index in range(64)}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="metadata-boundary-session",
                agent_id="metadata-boundary-agent",
                project_id="metadata-boundary-project",
                metadata=metadata,
            )
            resumed = resume_latest(
                root,
                project_id="metadata-boundary-project",
                token_budget=8192,
                model_assist=False,
            )
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["discovery"]["checkpoint_id"], state["card_id"])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with self.assertRaisesRegex(ValueError, "maximum of 64 members"):
                record_project_state(
                    root,
                    session_id="metadata-overflow-session",
                    agent_id="metadata-overflow-agent",
                    project_id="metadata-overflow-project",
                    metadata={f"property_{index}": index for index in range(65)},
                )
            self.assertFalse(root.exists())

    def test_near_8k_caller_metadata_remains_valid_after_enrichment(self) -> None:
        metadata = {f"field_{index}": "m" * 1900 for index in range(4)}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="metadata-size-session",
                agent_id="metadata-size-agent",
                project_id="metadata-size-project",
                metadata=metadata,
            )
            resumed = resume_latest(
                root,
                project_id="metadata-size-project",
                token_budget=8192,
                model_assist=False,
            )
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["discovery"]["checkpoint_id"], state["card_id"])

    def test_core_rejects_oversized_checkpoint_before_root_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with self.assertRaisesRegex(ValueError, "open_tasks exceeds maximum"):
                record_project_state(
                    root,
                    session_id="bounded-session",
                    agent_id="bounded-agent",
                    project_id="bounded-project",
                    open_tasks=[
                        f"task-{index}" for index in range(MAX_PROJECT_STATE_OPEN_TASKS + 1)
                    ],
                )
            self.assertFalse(root.exists())

            with self.assertRaisesRegex(ValueError, "project state exceeds maximum"):
                record_project_state(
                    root,
                    session_id="bounded-session",
                    agent_id="bounded-agent",
                    project_id="bounded-project",
                    decisions=["d" * 1900 for _ in range(8)],
                    open_tasks=["t" * 1900 for _ in range(8)],
                )
            self.assertFalse(root.exists())

    def test_metadata_complexity_and_nonfinite_values_fail_without_recursion(self) -> None:
        nested: dict[str, object] = {}
        cursor = nested
        for _ in range(10):
            child: dict[str, object] = {}
            cursor["child"] = child
            cursor = child
        with self.assertRaisesRegex(ValueError, "maximum depth"):
            validate_project_state_input(
                session_id="s",
                agent_id="a",
                project_id="p",
                metadata=nested,
            )

        cyclic: dict[str, object] = {}
        cyclic["self"] = cyclic
        with self.assertRaisesRegex(ValueError, "cycles"):
            validate_project_state_input(
                session_id="s",
                agent_id="a",
                project_id="p",
                metadata=cyclic,
            )

        with self.assertRaisesRegex(ValueError, "finite"):
            validate_project_state_input(
                session_id="s",
                agent_id="a",
                project_id="p",
                metadata={"value": float("inf")},
            )

    def test_large_valid_checkpoint_remains_resumable_at_8192_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="large-valid-session",
                agent_id="large-valid-agent",
                project_id="large-valid-project",
                objective="Preserve the bounded complete checkpoint",
                decisions=[f"decision-{index}-" + "d" * 300 for index in range(12)],
                open_tasks=[f"task-{index}-" + "t" * 300 for index in range(12)],
            )

            resumed = resume_latest(
                root,
                project_id="large-valid-project",
                token_budget=8192,
                model_assist=False,
            )

            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["discovery"]["checkpoint_id"], state["card_id"])
            self.assertIn("task-11-", resumed["packet_text"])

    def test_escape_dense_checkpoint_near_input_cap_resumes_losslessly_at_8192(
        self,
    ) -> None:
        pattern = 'edge-"\\\n雪'
        decisions = [f"decision-{index}-" + pattern * 87 for index in range(4)]
        open_tasks = [f"task-{index}-" + pattern * 87 for index in range(4)]
        validated = validate_project_state_input(
            session_id="escape-session",
            agent_id="escape-agent",
            project_id="escape-project",
            decisions=decisions,
            open_tasks=open_tasks,
        )
        self.assertGreater(validated["serialized_bytes"], MAX_PROJECT_STATE_BYTES - 256)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="escape-session",
                agent_id="escape-agent",
                project_id="escape-project",
                decisions=decisions,
                open_tasks=open_tasks,
            )
            resumed = resume_latest(
                root,
                project_id="escape-project",
                token_budget=8192,
                model_assist=False,
            )
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["discovery"]["checkpoint_id"], state["card_id"])
            for value in (decisions[-1], open_tasks[-1]):
                encoded_value = json.dumps(value, ensure_ascii=True)[1:-1]
                self.assertIn(encoded_value, resumed["packet_text"])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            over_cap_decisions = [
                f"decision-{index}-" + pattern * 88 for index in range(4)
            ]
            over_cap_tasks = [
                f"task-{index}-" + pattern * 88 for index in range(4)
            ]
            with self.assertRaisesRegex(ValueError, "project state exceeds maximum"):
                record_project_state(
                    root,
                    session_id="escape-session",
                    agent_id="escape-agent",
                    project_id="escape-project",
                    decisions=over_cap_decisions,
                    open_tasks=over_cap_tasks,
                )
            self.assertFalse(root.exists())

    def test_legacy_oversized_head_is_explicitly_quarantined_and_predecessor_resumes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            predecessor = record_project_state(
                root,
                session_id="legacy-one",
                agent_id="legacy-agent",
                project_id="legacy-project",
                objective="VALID_PREDECESSOR_OBJECTIVE",
                open_tasks=["VALID_PREDECESSOR_TASK"],
            )
            invalid = record_project_state(
                root,
                session_id="legacy-two",
                agent_id="legacy-agent",
                project_id="legacy-project",
                objective="Legacy head later found invalid",
            )
            huge_tasks = [f"HUGE_TASK_{index}-" + "x" * 1990 for index in range(300)]
            conn = connect(root)
            try:
                conn.execute(
                    """
                    UPDATE cards
                    SET open_tasks_json = ?, location_uri = NULL
                    WHERE id = ?
                    """,
                    (json.dumps(huge_tasks), invalid["card_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            blocked = resume_latest(
                root,
                project_id="legacy-project",
                token_budget=8192,
                model_assist=False,
            )
            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "invalid_project_state_checkpoint")
            self.assertTrue(blocked["repair_required"])
            self.assertIsNone(blocked.get("packet_uri"))

            preview = repair_invalid_project_state_checkpoints(
                root,
                project_id="legacy-project",
                dry_run=True,
            )
            self.assertEqual(preview["quarantined_count"], 1)
            repaired = repair_invalid_project_state_checkpoints(
                root,
                project_id="legacy-project",
                dry_run=False,
            )
            self.assertEqual(repaired["quarantined_count"], 1)
            self.assertEqual(
                repaired["reactivated_card_ids"],
                [predecessor["card_id"]],
            )

            resumed = resume_latest(
                root,
                project_id="legacy-project",
                token_budget=8192,
                model_assist=False,
            )
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                predecessor["card_id"],
            )
            self.assertIn("VALID_PREDECESSOR_TASK", resumed["packet_text"])
            self.assertNotIn("HUGE_TASK_", resumed["packet_text"])

            conn = connect(root)
            try:
                rows = {
                    str(row["id"]): dict(row)
                    for row in conn.execute(
                        """
                        SELECT id, status, supersedes_card_id,
                               superseded_by_card_id
                        FROM cards WHERE id IN (?, ?)
                        """,
                        (predecessor["card_id"], invalid["card_id"]),
                    )
                }
            finally:
                conn.close()
            self.assertEqual(rows[invalid["card_id"]]["status"], "historical")
            self.assertIsNone(rows[invalid["card_id"]]["supersedes_card_id"])
            self.assertIsNone(rows[predecessor["card_id"]]["superseded_by_card_id"])
            semantic = semantic_integrity_report(root)
            self.assertTrue(semantic["ok"], semantic)
            self.assertEqual(
                semantic["checks"]["quarantined_project_state_cards"],
                1,
            )
            snap = snapshot(root, reason="quarantined_checkpoint_repair")
            self.assertTrue(Path(str(snap["snapshot_uri"])).exists())
            workers = run_worker_pass(
                root,
                roles=["librarian"],
                limit=10,
                maintenance=False,
            )
            self.assertTrue(workers["ok"], workers)
            maintained = semantic_integrity_report(root)
            self.assertTrue(maintained["ok"], maintained)
            self.assertEqual(
                maintained["checks"]["quarantined_project_state_cards"],
                1,
            )
            repeated = repair_invalid_project_state_checkpoints(
                root,
                project_id="legacy-project",
                dry_run=False,
            )
            self.assertEqual(repeated["quarantined_count"], 0)

            conn = connect(root)
            try:
                source_before = conn.execute(
                    """
                    SELECT content, content_hash, metadata_json
                    FROM scroll_events WHERE id = ?
                    """,
                    (invalid["event_id"],),
                ).fetchone()
                self.assertIsNotNone(source_before)
                assert source_before is not None
                changed_content = "changed quarantined source evidence"
                changed_metadata = json.loads(source_before["metadata_json"])
                changed_metadata["agent_id"] = "changed-quarantine-agent"
                conn.execute(
                    """
                    UPDATE scroll_events
                    SET content = ?, content_hash = ?, metadata_json = ?
                    WHERE id = ?
                    """,
                    (
                        changed_content,
                        store_module.content_hash(changed_content),
                        json.dumps(changed_metadata, sort_keys=True),
                        invalid["event_id"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()
            changed_source = semantic_integrity_report(root)
            self.assertFalse(changed_source["ok"], changed_source)
            self.assertEqual(
                changed_source["checks"]["invalid_project_state_cards"],
                1,
            )
            conn = connect(root)
            try:
                conn.execute(
                    """
                    UPDATE scroll_events
                    SET content = ?, content_hash = ?, metadata_json = ?
                    WHERE id = ?
                    """,
                    (
                        source_before["content"],
                        source_before["content_hash"],
                        source_before["metadata_json"],
                        invalid["event_id"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()
            restored_source = semantic_integrity_report(root)
            self.assertTrue(restored_source["ok"], restored_source)

            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET title = title || ' changed' WHERE id = ?",
                    (invalid["card_id"],),
                )
                sync_card_sidecar(root, conn, str(invalid["card_id"]))
                conn.commit()
            finally:
                conn.close()
            divergent = semantic_integrity_report(root)
            self.assertFalse(divergent["ok"], divergent)
            self.assertEqual(
                divergent["checks"]["invalid_project_state_cards"],
                1,
            )
            with self.assertRaisesRegex(ValueError, "semantic integrity"):
                snapshot(root, reason="mutated_quarantined_checkpoint")

    def test_malformed_metadata_head_uses_bound_scroll_authority_for_repair(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            predecessor = record_project_state(
                root,
                session_id="malformed-one",
                agent_id="malformed-agent",
                project_id="malformed-project",
                objective="VALID_MALFORMED_PREDECESSOR",
                open_tasks=["VALID_MALFORMED_TASK"],
            )
            invalid = record_project_state(
                root,
                session_id="malformed-two",
                agent_id="malformed-agent",
                project_id="malformed-project",
                objective="Malformed metadata head",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET metadata_json = '{' WHERE id = ?",
                    (invalid["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()

            blocked = resume_latest(
                root,
                project_id="malformed-project",
                token_budget=8192,
                model_assist=False,
            )
            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "invalid_project_state_checkpoint")

            conn = connect(root)
            try:
                before = [
                    dict(row)
                    for row in conn.execute(
                        """
                        SELECT id, status, supersedes_card_id,
                               superseded_by_card_id, metadata_json
                        FROM cards WHERE id IN (?, ?) ORDER BY rowid
                        """,
                        (predecessor["card_id"], invalid["card_id"]),
                    )
                ]
            finally:
                conn.close()
            preview = repair_invalid_project_state_checkpoints(
                root,
                project_id="malformed-project",
                dry_run=True,
            )
            self.assertEqual(preview["quarantined_count"], 1)
            self.assertEqual(
                preview["quarantined"][0]["predecessor_card_id"],
                predecessor["card_id"],
            )
            conn = connect(root)
            try:
                after_preview = [
                    dict(row)
                    for row in conn.execute(
                        """
                        SELECT id, status, supersedes_card_id,
                               superseded_by_card_id, metadata_json
                        FROM cards WHERE id IN (?, ?) ORDER BY rowid
                        """,
                        (predecessor["card_id"], invalid["card_id"]),
                    )
                ]
            finally:
                conn.close()
            self.assertEqual(after_preview, before)

            repaired = repair_invalid_project_state_checkpoints(
                root,
                project_id="malformed-project",
                dry_run=False,
            )
            self.assertEqual(repaired["quarantined_count"], 1)
            self.assertEqual(repaired["reactivated_card_ids"], [predecessor["card_id"]])
            resumed = resume_latest(
                root,
                project_id="malformed-project",
                token_budget=8192,
                model_assist=False,
            )
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                predecessor["card_id"],
            )
            repeated = repair_invalid_project_state_checkpoints(
                root,
                project_id="malformed-project",
                dry_run=False,
            )
            self.assertEqual(repeated["quarantined_count"], 0)

    def test_malformed_metadata_repair_does_not_cross_source_agent_boundary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            predecessor = record_project_state(
                root,
                session_id="boundary-one",
                agent_id="boundary-agent-a",
                project_id="boundary-project",
                objective="Boundary predecessor",
            )
            invalid = record_project_state(
                root,
                session_id="boundary-two",
                agent_id="boundary-agent-a",
                project_id="boundary-project",
                objective="Boundary malformed head",
            )
            conn = connect(root)
            try:
                event_row = conn.execute(
                    "SELECT metadata_json FROM scroll_events WHERE id = ?",
                    (invalid["event_id"],),
                ).fetchone()
                assert event_row is not None
                event_metadata = json.loads(event_row["metadata_json"])
                event_metadata["agent_id"] = "boundary-agent-b"
                conn.execute(
                    "UPDATE scroll_events SET metadata_json = ? WHERE id = ?",
                    (json.dumps(event_metadata), invalid["event_id"]),
                )
                conn.execute(
                    "UPDATE cards SET metadata_json = '{' WHERE id = ?",
                    (invalid["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()

            repaired = repair_invalid_project_state_checkpoints(
                root,
                project_id="boundary-project",
                dry_run=False,
            )

            self.assertEqual(repaired["quarantined_count"], 1)
            self.assertIsNone(repaired["quarantined"][0]["predecessor_card_id"])
            self.assertEqual(repaired["reactivated_card_ids"], [])
            conn = connect(root)
            try:
                predecessor_row = conn.execute(
                    "SELECT superseded_by_card_id FROM cards WHERE id = ?",
                    (predecessor["card_id"],),
                ).fetchone()
            finally:
                conn.close()
            assert predecessor_row is not None
            self.assertIsNone(predecessor_row["superseded_by_card_id"])
            conn = connect(root)
            try:
                predecessor_status = conn.execute(
                    "SELECT status FROM cards WHERE id = ?",
                    (predecessor["card_id"],),
                ).fetchone()["status"]
            finally:
                conn.close()
            self.assertEqual(predecessor_status, "historical")
            self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_deep_legacy_json_is_invalid_and_quarantines_without_recursion(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            predecessor = record_project_state(
                root,
                session_id="deep-one",
                agent_id="deep-agent",
                project_id="deep-project",
                objective="VALID_DEEP_PREDECESSOR",
            )
            invalid = record_project_state(
                root,
                session_id="deep-two",
                agent_id="deep-agent",
                project_id="deep-project",
                objective="Deep legacy JSON",
            )
            deeply_nested_json = "[" * 1500 + "0" + "]" * 1500
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET metadata_json = ? WHERE id = ?",
                    (deeply_nested_json, invalid["card_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            blocked = resume_latest(
                root,
                project_id="deep-project",
                token_budget=8192,
                model_assist=False,
            )
            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "invalid_project_state_checkpoint")
            preview = repair_invalid_project_state_checkpoints(
                root,
                project_id="deep-project",
                dry_run=True,
            )
            self.assertEqual(preview["quarantined_count"], 1)
            self.assertEqual(
                preview["quarantined"][0]["predecessor_card_id"],
                predecessor["card_id"],
            )
            repaired = repair_invalid_project_state_checkpoints(
                root,
                project_id="deep-project",
                dry_run=False,
            )
            self.assertEqual(repaired["quarantined_count"], 1)
            self.assertEqual(repaired["reactivated_card_ids"], [predecessor["card_id"]])
            resumed = resume_latest(
                root,
                project_id="deep-project",
                token_budget=8192,
                model_assist=False,
            )
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                predecessor["card_id"],
            )

    def test_quarantine_limit_signals_unvalidated_reactivated_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            valid = record_project_state(
                root,
                session_id="paged-valid",
                agent_id="paged-agent",
                project_id="paged-project",
                objective="VALID_PAGED_PREDECESSOR",
            )
            invalid_a = record_project_state(
                root,
                session_id="paged-a",
                agent_id="paged-agent",
                project_id="paged-project",
                objective="Invalid paged A",
            )
            invalid_b = record_project_state(
                root,
                session_id="paged-b",
                agent_id="paged-agent",
                project_id="paged-project",
                objective="Invalid paged B",
            )
            huge_tasks = json.dumps(["x" * 1990 for _ in range(300)])
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET open_tasks_json = ? WHERE id IN (?, ?)",
                    (huge_tasks, invalid_a["card_id"], invalid_b["card_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            preview = repair_invalid_project_state_checkpoints(
                root,
                project_id="paged-project",
                limit=1,
                dry_run=True,
            )
            self.assertEqual(preview["quarantined_count"], 1)
            self.assertTrue(preview["has_more"])
            first_pass = repair_invalid_project_state_checkpoints(
                root,
                project_id="paged-project",
                limit=1,
                dry_run=False,
            )
            self.assertEqual(first_pass["quarantined_count"], 1)
            self.assertEqual(first_pass["reactivated_card_ids"], [invalid_a["card_id"]])
            self.assertTrue(first_pass["has_more"])
            second_pass = repair_invalid_project_state_checkpoints(
                root,
                project_id="paged-project",
                limit=1,
                dry_run=False,
            )
            self.assertEqual(second_pass["quarantined_count"], 1)
            self.assertEqual(second_pass["reactivated_card_ids"], [valid["card_id"]])
            self.assertTrue(second_pass["has_more"])
            final_pass = repair_invalid_project_state_checkpoints(
                root,
                project_id="paged-project",
                limit=1,
                dry_run=False,
            )
            self.assertEqual(final_pass["quarantined_count"], 0)
            self.assertFalse(final_pass["has_more"])
            resumed = resume_latest(
                root,
                project_id="paged-project",
                token_budget=8192,
                model_assist=False,
            )
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["discovery"]["checkpoint_id"], valid["card_id"])

    def test_invalid_source_refs_shape_is_explicitly_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            predecessor = record_project_state(
                root,
                session_id="source-ref-one",
                agent_id="source-ref-agent",
                project_id="source-ref-project",
                objective="VALID_SOURCE_REF_PREDECESSOR",
            )
            invalid = record_project_state(
                root,
                session_id="source-ref-two",
                agent_id="source-ref-agent",
                project_id="source-ref-project",
                objective="Invalid source refs",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET source_refs_json = '{}' WHERE id = ?",
                    (invalid["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()

            blocked = resume_latest(
                root,
                project_id="source-ref-project",
                token_budget=8192,
                model_assist=False,
            )
            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "invalid_project_state_checkpoint")
            self.assertIn(
                "source_refs",
                blocked["invalid_checkpoint"]["reason"],
            )
            preview = repair_invalid_project_state_checkpoints(
                root,
                project_id="source-ref-project",
                dry_run=True,
            )
            self.assertEqual(preview["quarantined_count"], 1)
            self.assertEqual(
                preview["quarantined"][0]["predecessor_card_id"],
                predecessor["card_id"],
            )
            repaired = repair_invalid_project_state_checkpoints(
                root,
                project_id="source-ref-project",
                dry_run=False,
            )
            self.assertEqual(repaired["quarantined_count"], 1)
            self.assertEqual(repaired["reactivated_card_ids"], [predecessor["card_id"]])
            resumed = resume_latest(
                root,
                project_id="source-ref-project",
                token_budget=8192,
                model_assist=False,
            )
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                predecessor["card_id"],
            )

    def test_oversized_source_repair_does_not_load_source_for_agent_fallback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            predecessor = record_project_state(
                root,
                session_id="source-size-one",
                agent_id="source-size-agent",
                project_id="source-size-project",
                objective="VALID_SOURCE_SIZE_PREDECESSOR",
            )
            invalid = record_project_state(
                root,
                session_id="source-size-two",
                agent_id="source-size-agent",
                project_id="source-size-project",
                objective="Oversized source head",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE scroll_events SET content = ? WHERE id = ?",
                    ("x" * 100_000, invalid["event_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            blocked = resume_latest(
                root,
                project_id="source-size-project",
                token_budget=8192,
                model_assist=False,
            )
            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "invalid_project_state_checkpoint")
            source_event_resolver = store_module._project_state_source_event

            def bounded_source_event(*args: object, **kwargs: object) -> object:
                if kwargs.get("checkpoint_session_id") == "source-size-two":
                    raise AssertionError("oversized source must not be loaded")
                return source_event_resolver(*args, **kwargs)

            with patch.object(
                store_module,
                "_project_state_source_event",
                side_effect=bounded_source_event,
            ):
                preview = repair_invalid_project_state_checkpoints(
                    root,
                    project_id="source-size-project",
                    dry_run=True,
                )
                repaired = repair_invalid_project_state_checkpoints(
                    root,
                    project_id="source-size-project",
                    dry_run=False,
                )
            self.assertEqual(preview["quarantined_count"], 1)
            self.assertEqual(repaired["quarantined_count"], 1)
            self.assertEqual(repaired["reactivated_card_ids"], [predecessor["card_id"]])

    def test_invalid_secondary_cross_agent_state_is_absent_from_resume_and_cue(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            invalid = record_project_state(
                root,
                session_id="secondary-invalid",
                agent_id="secondary-agent-a",
                project_id="secondary-project",
                objective=(
                    "archive emberwhale obsidian plumecipher "
                    "SECONDARY_INVALID_OBJECTIVE_MARKER"
                ),
                decisions=["SECONDARY_INVALID_DECISION_MARKER"],
                open_tasks=["SECONDARY_INVALID_TASK_MARKER"],
            )
            valid = record_project_state(
                root,
                session_id="secondary-valid",
                agent_id="secondary-agent-b",
                project_id="secondary-project",
                objective="archive VALID_SECONDARY_SELECTED_CHECKPOINT",
                decisions=["VALID_SECONDARY_DECISION"],
                open_tasks=["VALID_SECONDARY_TASK"],
            )
            invalid_summary_marker = "SECONDARY_INVALID_SUMMARY_MARKER"
            invalid_scroll_marker = "SECONDARY_INVALID_SCROLL_MARKER"
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = ? WHERE id = ?",
                    (invalid_summary_marker + "x" * 9000, invalid["card_id"]),
                )
                conn.execute(
                    "UPDATE scroll_events SET content = ? WHERE id = ?",
                    (invalid_scroll_marker + "y" * 100_000, invalid["event_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            recalled = cue_recall(
                root,
                cue="archive",
                project_id="secondary-project",
                limit=50,
                max_associations=50,
                create=False,
            )
            resumed = resume_latest(
                root,
                project_id="secondary-project",
                query="SECONDARY INVALID MARKER",
                token_budget=8192,
                model_assist=False,
            )

            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["discovery"]["checkpoint_id"], valid["card_id"])
            recalled_text = json.dumps(recalled, sort_keys=True)
            for marker in (
                invalid_summary_marker,
                invalid_scroll_marker,
                "SECONDARY_INVALID_OBJECTIVE_MARKER",
                "SECONDARY_INVALID_DECISION_MARKER",
                "SECONDARY_INVALID_TASK_MARKER",
            ):
                self.assertNotIn(marker, recalled_text)
                self.assertNotIn(marker, resumed["packet_text"])
            self.assertNotIn(invalid["card_id"], recalled_text)
            self.assertNotIn(invalid["event_id"], recalled_text)
            related_text = json.dumps(
                recalled["related_terms"],
                sort_keys=True,
            ).casefold()
            self.assertNotIn("emberwhale", related_text)
            self.assertNotIn("obsidian", related_text)
            self.assertNotIn("plumecipher", related_text)
            self.assertIn("VALID_SECONDARY_SELECTED_CHECKPOINT", resumed["packet_text"])

    def test_new_checkpoint_refuses_corrupt_current_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            invalid = record_project_state(
                root,
                session_id="blocked-authority-one",
                agent_id="blocked-authority-agent",
                project_id="blocked-authority-project",
                objective="Corrupt current authority",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = ? WHERE id = ?",
                    ("x" * 9000, invalid["card_id"]),
                )
                conn.commit()
                before_counts = {
                    table: int(
                        conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                    )
                    for table in (
                        "scroll_events",
                        "cards",
                        "queue_jobs",
                        "graph_nodes",
                        "graph_edges",
                        "audit_events",
                    )
                }
            finally:
                conn.close()

            with self.assertRaisesRegex(ValueError, "repair required"):
                record_project_state(
                    root,
                    session_id="blocked-authority-two",
                    agent_id="blocked-authority-agent",
                    project_id="blocked-authority-project",
                    objective="Must not create a parallel head",
                )

            conn = connect(root)
            try:
                cards = list(
                    conn.execute(
                        "SELECT id FROM cards WHERE card_type = 'project_state'"
                    )
                )
                after_counts = {
                    table: int(
                        conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                    )
                    for table in before_counts
                }
            finally:
                conn.close()
            self.assertEqual([str(row["id"]) for row in cards], [invalid["card_id"]])
            self.assertEqual(after_counts, before_counts)

    def test_private_checkpoint_authority_supersedes_within_exact_boundary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="private-session",
                agent_id="private-agent",
                project_id="private-project",
                objective="PRIVATE_FIRST",
                metadata={"visibility_scope": "private"},
            )
            second = record_project_state(
                root,
                session_id="private-session",
                agent_id="private-agent",
                project_id="private-project",
                objective="PRIVATE_SECOND",
                metadata={"visibility_scope": "private"},
            )
            self.assertEqual(second["supersedes_card_id"], first["card_id"])
            conn = connect(root)
            try:
                rows = {
                    str(row["id"]): dict(row)
                    for row in conn.execute(
                        """
                        SELECT id, supersedes_card_id, superseded_by_card_id
                        FROM cards WHERE id IN (?, ?)
                        """,
                        (first["card_id"], second["card_id"]),
                    )
                }
            finally:
                conn.close()
            self.assertEqual(
                rows[first["card_id"]]["superseded_by_card_id"],
                second["card_id"],
            )
            self.assertEqual(
                rows[second["card_id"]]["supersedes_card_id"],
                first["card_id"],
            )

    def test_invalid_other_agent_head_does_not_block_independent_writer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            agent_a = record_project_state(
                root,
                session_id="agent-a-one",
                agent_id="agent-a",
                project_id="isolated-project",
                objective="Agent A head",
            )
            agent_b = record_project_state(
                root,
                session_id="agent-b-one",
                agent_id="agent-b",
                project_id="isolated-project",
                objective="Agent B head",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = ? WHERE id = ?",
                    ("small integrity tamper", agent_a["card_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            agent_b_next = record_project_state(
                root,
                session_id="agent-b-two",
                agent_id="agent-b",
                project_id="isolated-project",
                objective="Agent B advances independently",
            )
            self.assertEqual(agent_b_next["supersedes_card_id"], agent_b["card_id"])
            self.assertNotIn(agent_a["card_id"], agent_b_next["superseded_card_ids"])
            with self.assertRaisesRegex(ValueError, "repair required"):
                record_project_state(
                    root,
                    session_id="agent-a-two",
                    agent_id="agent-a",
                    project_id="isolated-project",
                    objective="Agent A must repair first",
                )

    def test_agent_metadata_mismatch_blocks_authority_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            agent_a = record_project_state(
                root,
                session_id="identity-a",
                agent_id="identity-agent-a",
                project_id="identity-project",
            )
            record_project_state(
                root,
                session_id="identity-b",
                agent_id="identity-agent-b",
                project_id="identity-project",
            )
            conn = connect(root)
            try:
                row = conn.execute(
                    "SELECT metadata_json FROM cards WHERE id = ?",
                    (agent_a["card_id"],),
                ).fetchone()
                assert row is not None
                metadata = json.loads(row["metadata_json"])
                metadata["agent_id"] = "identity-agent-b"
                conn.execute(
                    "UPDATE cards SET metadata_json = ? WHERE id = ?",
                    (json.dumps(metadata), agent_a["card_id"]),
                )
                before_events = int(
                    conn.execute("SELECT count(*) FROM scroll_events").fetchone()[0]
                )
                conn.commit()
            finally:
                conn.close()

            with self.assertRaisesRegex(ValueError, "repair required"):
                record_project_state(
                    root,
                    session_id="identity-b-next",
                    agent_id="identity-agent-b",
                    project_id="identity-project",
                )
            conn = connect(root)
            try:
                after_events = int(
                    conn.execute("SELECT count(*) FROM scroll_events").fetchone()[0]
                )
            finally:
                conn.close()
            self.assertEqual(after_events, before_events)

    def test_small_integrity_tamper_is_quarantined_and_predecessor_restored(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            predecessor = record_project_state(
                root,
                session_id="small-tamper-one",
                agent_id="small-tamper-agent",
                project_id="small-tamper-project",
                objective="SMALL_TAMPER_VALID_PREDECESSOR",
            )
            invalid = record_project_state(
                root,
                session_id="small-tamper-two",
                agent_id="small-tamper-agent",
                project_id="small-tamper-project",
                objective="Small tamper head",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = ? WHERE id = ?",
                    ("small tamper", invalid["card_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            blocked = resume_latest(
                root,
                project_id="small-tamper-project",
                token_budget=8192,
                model_assist=False,
            )
            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "invalid_project_state_checkpoint")
            repaired = repair_invalid_project_state_checkpoints(
                root,
                project_id="small-tamper-project",
                dry_run=False,
            )
            self.assertEqual(repaired["reactivated_card_ids"], [predecessor["card_id"]])
            next_state = record_project_state(
                root,
                session_id="small-tamper-three",
                agent_id="small-tamper-agent",
                project_id="small-tamper-project",
                objective="Writer resumes after repair",
            )
            self.assertEqual(next_state["supersedes_card_id"], predecessor["card_id"])

    def test_derived_card_chain_from_historical_state_is_not_operational(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            old = record_project_state(
                root,
                session_id="derived-session",
                agent_id="derived-agent",
                project_id="derived-project",
                objective="RETIRED_EMBERWHALE_OBJECTIVE",
                decisions=["RETIRED_OBSIDIAN_DECISION"],
                open_tasks=["RETIRED_PLUMECIPHER_TASK"],
            )
            record_project_state(
                root,
                session_id="derived-session",
                agent_id="derived-agent",
                project_id="derived-project",
                objective="CURRENT_AZURE_OBJECTIVE",
            )
            segment = roll_scroll_segment(
                root,
                session_id="derived-session",
                start_seq=1,
                end_seq=2,
            )
            conn = connect(root)
            try:
                deep_card_id = create_card(
                    conn,
                    root=root,
                    card_type="concept",
                    title="Deep derived stale marker",
                    summary="RETIRED_DEEP_SUMMARY",
                    decisions=["RETIRED_DEEP_DECISION"],
                    open_tasks=["RETIRED_DEEP_TASK"],
                    source_refs=[{"card_id": segment["card_id"]}],
                    visibility_scope="project",
                    session_id="derived-session",
                    project_id="derived-project",
                )
                conn.commit()
            finally:
                conn.close()

            resumed = resume_latest(
                root,
                project_id="derived-project",
                query="retired emberwhale obsidian plumecipher deep",
                token_budget=8192,
                model_assist=False,
            )
            recalled = cue_recall(
                root,
                cue="retired emberwhale obsidian plumecipher deep",
                project_id="derived-project",
                limit=50,
                max_associations=50,
                create=False,
            )
            self.assertTrue(resumed["ok"], resumed)
            combined = resumed["packet_text"] + json.dumps(recalled, sort_keys=True)
            for marker in (
                "RETIRED_EMBERWHALE_OBJECTIVE",
                "RETIRED_OBSIDIAN_DECISION",
                "RETIRED_PLUMECIPHER_TASK",
                "RETIRED_DEEP_SUMMARY",
                "RETIRED_DEEP_DECISION",
                "RETIRED_DEEP_TASK",
                old["card_id"],
                segment["card_id"],
                deep_card_id,
            ):
                self.assertNotIn(marker, combined)

    def test_superseded_project_state_graph_terms_do_not_influence_cue_recall(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="stale-term-old",
                agent_id="stale-term-agent",
                project_id="stale-term-project",
                objective="archive EMBERWHALE obsidian plumecipher",
            )
            record_project_state(
                root,
                session_id="stale-term-new",
                agent_id="stale-term-agent",
                project_id="stale-term-project",
                objective="archive CURRENT_VALID_TERM",
            )

            recalled = cue_recall(
                root,
                cue="archive",
                project_id="stale-term-project",
                limit=50,
                max_associations=50,
                create=False,
            )

            related_text = json.dumps(
                recalled["related_terms"],
                sort_keys=True,
            ).casefold()
            self.assertNotIn("emberwhale", related_text)
            self.assertNotIn("obsidian", related_text)
            self.assertNotIn("plumecipher", related_text)


if __name__ == "__main__":
    unittest.main()
