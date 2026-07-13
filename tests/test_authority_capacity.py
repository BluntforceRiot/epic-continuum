from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from continuum.core import store as store_module
from continuum.core.store import (
    record_project_state,
    repair_invalid_project_state_checkpoints,
    resume_latest,
    semantic_integrity_report,
    snapshot,
)


def _seed_independent_project_states(root: Path, *, count: int) -> list[str]:
    """Create canonical independent checkpoints in one fixture transaction."""

    store_module.init_db(root)
    conn = store_module.connect(root)
    card_ids: list[str] = []
    payload_hash = store_module._project_state_payload_hash([], [])
    assert payload_hash is not None
    try:
        conn.execute("BEGIN IMMEDIATE")
        for index in range(count):
            session_id = f"shared-session-{index:04d}"
            project_id = f"shared-project-{index:04d}"
            agent_id = "shared-agent"
            content = (
                f"Project state for {project_id}\n"
                f"Agent: {agent_id}\n"
                f"Objective: Checkpoint {index}\n"
                f"Continuum-State-Payload-SHA256: {payload_hash}"
            )
            event_metadata = {
                "agent_id": agent_id,
                "project_id": project_id,
                "session_id": session_id,
                "source_type": "project_state",
                "state_payload_hash": payload_hash,
                "trust_level": "agent_reported_local_evidence",
                "instruction_authority": "user_level_evidence",
                "visibility_scope": "project",
                "continuum_disable_exact_memory": True,
                "branch": None,
                "commit": None,
                "dirty": None,
                "changed_files": [],
            }
            digest = store_module.content_hash(content)
            event_id = store_module.stable_id(
                "evt",
                session_id,
                "1",
                digest,
            )
            now = store_module.utc_now()
            conn.execute(
                """
                INSERT INTO scroll_events(
                    id, session_id, seq, event_type, role, content,
                    token_estimate, content_hash, visibility_scope, project_id,
                    metadata_json, created_at
                )
                VALUES(?, ?, 1, 'project_state', 'agent', ?, ?, ?, 'project',
                       ?, ?, ?)
                """,
                (
                    event_id,
                    session_id,
                    content,
                    store_module.estimate_tokens(content),
                    digest,
                    project_id,
                    store_module.json_dumps(event_metadata),
                    now,
                ),
            )
            card_id = store_module.create_card(
                conn,
                root=root,
                card_type="project_state",
                title=f"{project_id} project state from {agent_id}",
                summary=store_module.summarize_text(content, limit=900),
                source_refs=[
                    {"event_id": event_id, "session_id": session_id, "seq": 1}
                ],
                entities=[],
                topics=[project_id, agent_id],
                decisions=[],
                open_tasks=[],
                metadata=event_metadata,
                visibility_scope="project",
                session_id=session_id,
                project_id=project_id,
                salience=0.9,
                confidence=0.8,
            )
            project_node = store_module.upsert_graph_node(
                conn,
                kind="project",
                label=project_id,
                metadata={"project_id": project_id},
            )
            card_node = store_module.upsert_graph_node(
                conn,
                kind="card",
                label=f"{project_id} state {agent_id}",
                card_id=card_id,
            )
            store_module.add_graph_edge(
                conn,
                source_node_id=project_node,
                relation="shared_state",
                target_node_id=card_node,
                weight=0.75,
                confidence=0.85,
                source_refs=[{"event_id": event_id, "card_id": card_id}],
            )
            card_ids.append(card_id)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    store_module.sync_card_sidecars_after_commit(root, card_ids)
    return card_ids


class ProjectStateAuthorityCapacityTests(unittest.TestCase):
    def test_unscoped_resume_does_not_skip_newest_orphan_on_timestamp_tie(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            store_module.init_db(root)
            conn = store_module.connect(root)
            try:
                for index in range(64):
                    store_module.create_card(
                        conn,
                        root=root,
                        card_type="note",
                        title=f"Rowid noise {index}",
                        summary=f"Ordinary Card {index}",
                        source_refs=[],
                        visibility_scope="project",
                        session_id=f"noise-session-{index}",
                        project_id="rowid-noise",
                    )
                conn.commit()
            finally:
                conn.close()
            healthy = record_project_state(
                root,
                session_id="orphan-order-healthy-session",
                agent_id="orphan-order-healthy-agent",
                project_id="orphan-order-healthy-project",
                objective="Healthy checkpoint before orphan",
            )
            orphaned = record_project_state(
                root,
                session_id="orphan-order-damaged-session",
                agent_id="orphan-order-damaged-agent",
                project_id="orphan-order-damaged-project",
                objective="Newest checkpoint becomes orphaned",
            )
            tied_at = "2026-07-12T12:00:00+00:00"
            conn = store_module.connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET created_at = ? WHERE id IN (?, ?)",
                    (
                        tied_at,
                        healthy["card_id"],
                        orphaned["card_id"],
                    ),
                )
                conn.execute(
                    "UPDATE scroll_events SET created_at = ? WHERE id IN (?, ?)",
                    (
                        tied_at,
                        healthy["event_id"],
                        orphaned["event_id"],
                    ),
                )
                conn.execute(
                    "DELETE FROM cards WHERE id = ?",
                    (orphaned["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()

            resumed = resume_latest(root, model_assist=False)

            self.assertFalse(resumed["ok"], resumed)
            self.assertEqual(resumed["reason"], "authority_corrupt")
            self.assertIn(
                "orphan_project_state_source_event",
                {
                    issue["type"]
                    for issue in resumed["authority_corruption"][
                        "topology_issues"
                    ]
                },
            )
            self.assertIn(
                orphaned["card_id"],
                str(resumed["authority_corruption"]),
            )

    def test_unscoped_resume_does_not_skip_newest_source_only_corruption(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="older-healthy-session",
                agent_id="older-healthy-agent",
                project_id="newest-damaged-project",
                objective="Older healthy head in damaged boundary",
            )
            record_project_state(
                root,
                session_id="middle-healthy-session",
                agent_id="middle-healthy-agent",
                project_id="middle-healthy-project",
                objective="Middle healthy checkpoint",
            )
            damaged = record_project_state(
                root,
                session_id="newest-damaged-session",
                agent_id="newest-damaged-agent",
                project_id="newest-damaged-project",
                objective="Newest damaged checkpoint",
            )
            conn = store_module.connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET card_type = 'note' WHERE id = ?",
                    (damaged["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            store_module.sync_card_sidecars_after_commit(
                root,
                [str(damaged["card_id"])],
            )

            resumed = resume_latest(root, model_assist=False)

            self.assertFalse(resumed["ok"], resumed)
            self.assertEqual(resumed["reason"], "authority_corrupt")
            self.assertIn(
                "source_bound_card_type_mismatch",
                {
                    issue["type"]
                    for issue in resumed["authority_corruption"][
                        "topology_issues"
                    ]
                },
            )
            self.assertIn(
                damaged["card_id"],
                {
                    item["checkpoint_id"]
                    for item in resumed["authority_corruption"][
                        "invalid_checkpoints"
                    ]
                },
            )

    def test_257_sequential_checkpoints_remain_consistently_usable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            latest = None
            for index in range(257):
                latest = record_project_state(
                    root,
                    session_id=f"long-session-{index:03d}",
                    agent_id="long-agent",
                    project_id="long-project",
                    objective=f"Checkpoint {index}",
                )

            resumed = resume_latest(
                root,
                project_id="long-project",
                model_assist=False,
            )
            repair_preview = repair_invalid_project_state_checkpoints(
                root,
                project_id="long-project",
                dry_run=True,
            )
            semantic = semantic_integrity_report(root)
            created_snapshot = snapshot(root, reason="authority capacity regression")

            self.assertIsNotNone(latest)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                latest["card_id"],
            )
            self.assertTrue(repair_preview["ok"], repair_preview)
            self.assertEqual(repair_preview["quarantined_count"], 0)
            self.assertTrue(semantic["ok"], semantic)
            self.assertTrue(
                (root / created_snapshot["snapshot_uri"]).is_file(),
                created_snapshot,
            )

    def test_1001_projects_remain_verifiable_resumable_and_snapshottable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            card_ids = _seed_independent_project_states(root, count=1001)

            semantic = semantic_integrity_report(root)
            resumed = resume_latest(root, model_assist=False)
            created_snapshot = snapshot(root, reason="shared root capacity regression")

            self.assertTrue(semantic["ok"], semantic)
            self.assertEqual(len(card_ids), 1001)
            self.assertEqual(
                semantic["checks"]["source_bound_project_state_scan_overflow"],
                0,
            )
            self.assertEqual(
                semantic["checks"]["orphan_project_state_source_scan_overflow"],
                0,
            )
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["project_id"], "shared-project-1000")
            self.assertTrue(
                (root / created_snapshot["snapshot_uri"]).is_file(),
                created_snapshot,
            )


if __name__ == "__main__":
    unittest.main()
