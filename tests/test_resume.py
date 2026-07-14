from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import continuum.core.store as store_module
from continuum.core.config import configure_personal_profile, default_config, write_config
from continuum.core.store import (
    NON_CURRENT_CARD_STATUSES,
    append_scroll_event,
    compile_context,
    connect,
    create_card,
    cue_recall,
    enqueue_job,
    estimate_tokens,
    ingest_file,
    init_db,
    record_project_state,
    recover_thread,
    reinforce_card_recall,
    resume_latest,
    roll_scroll_segment,
    sync_card_sidecars_after_commit,
)
from continuum.core.workers import (
    detect_conflicts,
    prune_memory,
    resolve_conflict,
    run_worker_pass,
)


class ResumeLatestTests(unittest.TestCase):
    def test_resume_discovers_latest_project_state_without_thread_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="resume-session",
                agent_id="codex-sol",
                project_id="resume-project",
                objective="Resume the project",
                open_tasks=["verify the handoff"],
            )

            result = resume_latest(root, token_budget=1200)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["resume_profile"], "latest")
            self.assertEqual(result["session_id"], "resume-session")
            self.assertEqual(result["project_id"], "resume-project")
            self.assertEqual(result["discovery"]["source"], "project_state_card")
            self.assertIn("verify the handoff", result["packet_text"])

    def test_resume_can_discover_latest_state_for_a_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="project-session",
                agent_id="codex-sol",
                project_id="target-project",
                objective="Targeted resume",
            )

            result = resume_latest(root, project_id="target-project", token_budget=800)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["session_id"], "project-session")
            self.assertEqual(result["discovery"]["requested_project_id"], "target-project")

    def test_resume_discovery_skips_private_project_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="visible-session",
                agent_id="codex-sol",
                project_id="visible-project",
                objective="VISIBLE-CHECKPOINT",
            )
            record_project_state(
                root,
                session_id="private-session",
                agent_id="codex-sol",
                project_id="private-project",
                objective="PRIVATE-CHECKPOINT",
                metadata={"visibility_scope": "private"},
            )

            result = resume_latest(root, token_budget=800, model_assist=False)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["session_id"], "visible-session")
            self.assertEqual(result["project_id"], "visible-project")
            self.assertIn("VISIBLE-CHECKPOINT", result["packet_text"])
            self.assertNotIn("PRIVATE-CHECKPOINT", result["packet_text"])

    def test_unscoped_resume_selects_global_scroll_without_deriving_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            append_scroll_event(
                root,
                session_id="visible-scroll-session",
                event_type="message",
                role="user",
                content="VISIBLE-SCROLL-EVENT",
                metadata={"visibility_scope": "session"},
            )
            append_scroll_event(
                root,
                session_id="global-scroll-session",
                event_type="message",
                role="user",
                content="GLOBAL-SCROLL-EVENT",
                metadata={"visibility_scope": "global"},
            )

            result = resume_latest(root, token_budget=800, model_assist=False)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["discovery"]["source"], "scroll_event")
            self.assertEqual(result["session_id"], "global-scroll-session")
            self.assertEqual(result["project_id"], None)
            self.assertEqual(
                result["visibility_capability"],
                {"session_id": None, "project_id": None},
            )
            self.assertEqual(result["recent_event_count"], 1)
            self.assertIn("GLOBAL-SCROLL-EVENT", result["packet_text"])
            self.assertNotIn("VISIBLE-SCROLL-EVENT", result["packet_text"])

    def test_unscoped_resume_skips_stale_partitions_without_poisoning_fresh_scroll(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            stale = record_project_state(
                root,
                session_id="stale-session",
                agent_id="codex-sol",
                project_id="stale-project",
                objective="Archived checkpoint",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET status = 'archived' WHERE id = ?",
                    (stale["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            append_scroll_event(
                root,
                session_id="fresh-session",
                event_type="message",
                role="user",
                content="FRESH-RECOVERABLE-SCROLL",
                metadata={"visibility_scope": "project", "project_id": "fresh-project"},
            )
            append_scroll_event(
                root,
                session_id="stale-session",
                event_type="message",
                role="user",
                content="NEWER-BUT-STALE-PARTITION",
                metadata={"visibility_scope": "project", "project_id": "stale-project"},
            )

            scoped = resume_latest(root, project_id="stale-project", model_assist=False)
            unscoped = resume_latest(root, model_assist=False)

            self.assertFalse(scoped["ok"], scoped)
            self.assertEqual(scoped["reason"], "authority_corrupt")
            self.assertTrue(unscoped["ok"], unscoped)
            self.assertEqual(unscoped["discovery"]["source"], "scroll_event")
            self.assertEqual(unscoped["session_id"], "fresh-session")
            self.assertEqual(unscoped["project_id"], "fresh-project")
            self.assertIn("FRESH-RECOVERABLE-SCROLL", unscoped["packet_text"])
            self.assertNotIn("NEWER-BUT-STALE-PARTITION", unscoped["packet_text"])
            repaired = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="stale-project",
                dry_run=False,
            )
            after_repair = resume_latest(
                root,
                project_id="stale-project",
                model_assist=False,
            )
            self.assertTrue(repaired["ok"], repaired)
            self.assertEqual(repaired["quarantined_count"], 1)
            self.assertFalse(after_repair["ok"], after_repair)
            self.assertEqual(
                after_repair["reason"],
                "no_current_project_state",
            )
            self.assertTrue(store_module.semantic_integrity_report(root)["ok"])

    def test_resume_reports_missing_state_without_writing_a_packet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)

            result = resume_latest(root)

            self.assertFalse(result["ok"])
            self.assertEqual(result["reason"], "no_resume_state")
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_source_bound_card_type_drift_blocks_and_quarantines_hidden_head(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            hidden = record_project_state(
                root,
                session_id="type-drift-hidden",
                agent_id="agent-hidden",
                project_id="type-drift-project",
                decisions=["Hidden independent authority"],
            )
            current = record_project_state(
                root,
                session_id="type-drift-current",
                agent_id="agent-current",
                project_id="type-drift-project",
                decisions=["Visible authority"],
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET card_type = 'decision' WHERE id = ?",
                    (hidden["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [str(hidden["card_id"])])

            semantic = store_module.semantic_integrity_report(root)
            blocked = resume_latest(
                root,
                project_id="type-drift-project",
                model_assist=False,
            )
            preview = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="type-drift-project",
                dry_run=True,
            )
            repaired = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="type-drift-project",
                dry_run=False,
            )
            resumed = resume_latest(
                root,
                project_id="type-drift-project",
                model_assist=False,
            )

            self.assertFalse(semantic["ok"], semantic)
            self.assertEqual(
                semantic["checks"]["source_bound_card_type_mismatches"],
                1,
            )
            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "authority_corrupt")
            self.assertIn(
                "source_bound_card_type_mismatch",
                {
                    issue["type"]
                    for issue in blocked["authority_corruption"][
                        "topology_issues"
                    ]
                },
            )
            self.assertEqual(preview["quarantined_count"], 1)
            self.assertEqual(repaired["quarantined_count"], 1)
            self.assertIn("decision", repaired["quarantined"][0]["reason"])
            self.assertTrue(
                all(
                    boundary["ok"]
                    for boundary in repaired[
                        "post_repair_authority_boundaries"
                    ]
                ),
                repaired,
            )
            self.assertTrue(store_module.semantic_integrity_report(root)["ok"])
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                current["card_id"],
            )

    def test_ordinary_card_referencing_project_state_source_is_not_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="ordinary-source-session",
                agent_id="ordinary-source-agent",
                project_id="ordinary-source-project",
            )
            conn = connect(root)
            try:
                event = conn.execute(
                    "SELECT session_id, seq FROM scroll_events WHERE id = ?",
                    (state["event_id"],),
                ).fetchone()
                ordinary_id = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Ordinary derived decision",
                    summary="This is evidence, not project-state authority.",
                    source_refs=[
                        {
                            "event_id": state["event_id"],
                            "session_id": event["session_id"],
                            "seq": event["seq"],
                        }
                    ],
                    visibility_scope="project",
                    session_id="ordinary-source-session",
                    project_id="ordinary-source-project",
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [ordinary_id])

            semantic = store_module.semantic_integrity_report(root)
            resumed = resume_latest(
                root,
                project_id="ordinary-source-project",
                model_assist=False,
            )
            preview = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="ordinary-source-project",
                dry_run=True,
            )

            self.assertTrue(semantic["ok"], semantic)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["discovery"]["checkpoint_id"], state["card_id"])
            self.assertEqual(preview["quarantined_count"], 0)
            self.assertNotIn(ordinary_id, preview["retired_peer_card_ids"])

    def test_source_bound_type_repair_reactivates_safe_predecessor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            predecessor = record_project_state(
                root,
                session_id="type-chain-session",
                agent_id="type-chain-agent",
                project_id="type-chain-project",
                decisions=["Predecessor state"],
            )
            damaged = record_project_state(
                root,
                session_id="type-chain-session",
                agent_id="type-chain-agent",
                project_id="type-chain-project",
                decisions=["Damaged state"],
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET card_type = 'note' WHERE id = ?",
                    (damaged["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [str(damaged["card_id"])])

            preview = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="type-chain-project",
                dry_run=True,
            )
            repaired = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="type-chain-project",
                dry_run=False,
            )
            resumed = resume_latest(
                root,
                project_id="type-chain-project",
                model_assist=False,
            )

            self.assertEqual(
                preview["quarantined"][0]["predecessor_card_id"],
                predecessor["card_id"],
            )
            self.assertEqual(preview["retired_peer_count"], 0)
            self.assertEqual(repaired["retired_peer_count"], 0)
            self.assertEqual(
                repaired["reactivated_card_ids"],
                [predecessor["card_id"]],
            )
            self.assertTrue(store_module.semantic_integrity_report(root)["ok"])
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                predecessor["card_id"],
            )

    def test_repair_detaches_unproven_peers_and_preserves_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            predecessor = record_project_state(
                root,
                session_id="peer-report-chain",
                agent_id="peer-report-agent",
                project_id="peer-report-project",
            )
            damaged = record_project_state(
                root,
                session_id="peer-report-chain",
                agent_id="peer-report-agent",
                project_id="peer-report-project",
            )
            peer_one = record_project_state(
                root,
                session_id="peer-report-one",
                agent_id="peer-report-one-agent",
                project_id="peer-report-project",
            )
            peer_two = record_project_state(
                root,
                session_id="peer-report-two",
                agent_id="peer-report-two-agent",
                project_id="peer-report-project",
            )
            peer_ids = sorted([str(peer_one["card_id"]), str(peer_two["card_id"])])
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = summary || ' damaged' WHERE id = ?",
                    (damaged["card_id"],),
                )
                conn.execute(
                    "UPDATE cards SET superseded_by_card_id = ? "
                    "WHERE id IN (?, ?)",
                    (damaged["card_id"], *peer_ids),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(
                root,
                [str(damaged["card_id"]), *peer_ids],
            )

            preview = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="peer-report-project",
                dry_run=True,
            )
            applied = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="peer-report-project",
                dry_run=False,
            )
            repeated = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="peer-report-project",
                dry_run=False,
            )

            self.assertTrue(preview["ok"], preview)
            self.assertEqual(preview["quarantined_count"], 1)
            self.assertEqual(preview["retired_peer_count"], 0)
            self.assertEqual(preview["detached_peer_count"], 2)
            self.assertEqual(preview["detached_peer_card_ids"], peer_ids)
            self.assertEqual(
                preview["detached_peer_card_ids"],
                applied["detached_peer_card_ids"],
            )
            self.assertEqual(preview["detached_peers"], applied["detached_peers"])
            self.assertEqual(
                applied["reactivated_card_ids"],
                [predecessor["card_id"]],
            )
            self.assertTrue(
                applied["post_repair_authority_boundaries"],
                applied,
            )
            self.assertTrue(
                all(
                    boundary["ok"]
                    for boundary in applied[
                        "post_repair_authority_boundaries"
                    ]
                ),
                applied,
            )
            self.assertEqual(repeated["quarantined_count"], 0)
            self.assertEqual(repeated["retired_peer_count"], 0)
            self.assertEqual(repeated["retired_peer_card_ids"], [])
            self.assertEqual(repeated["detached_peer_count"], 0)
            ambiguous = resume_latest(
                root,
                project_id="peer-report-project",
                model_assist=False,
            )
            self.assertFalse(ambiguous["ok"], ambiguous)
            self.assertEqual(ambiguous["reason"], "authority_ambiguous")
            self.assertTrue(store_module.semantic_integrity_report(root)["ok"])

    def test_orphan_project_state_source_blocks_and_repair_refuses_writes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            missing = record_project_state(
                root,
                session_id="orphan-source-old",
                agent_id="orphan-source-old-agent",
                project_id="orphan-source-project",
            )
            current = record_project_state(
                root,
                session_id="orphan-source-current",
                agent_id="orphan-source-current-agent",
                project_id="orphan-source-project",
            )
            conn = connect(root)
            try:
                conn.execute("DELETE FROM cards WHERE id = ?", (missing["card_id"],))
                conn.commit()
                before = [
                    tuple(row)
                    for row in conn.execute(
                        "SELECT id, card_type, status, supersedes_card_id, "
                        "superseded_by_card_id FROM cards ORDER BY id"
                    ).fetchall()
                ]
            finally:
                conn.close()

            semantic = store_module.semantic_integrity_report(root)
            blocked = resume_latest(
                root,
                project_id="orphan-source-project",
                model_assist=False,
            )
            preview = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="orphan-source-project",
                dry_run=True,
            )
            applied = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="orphan-source-project",
                dry_run=False,
            )
            conn = connect(root)
            try:
                after = [
                    tuple(row)
                    for row in conn.execute(
                        "SELECT id, card_type, status, supersedes_card_id, "
                        "superseded_by_card_id FROM cards ORDER BY id"
                    ).fetchall()
                ]
            finally:
                conn.close()

            self.assertFalse(semantic["ok"], semantic)
            self.assertEqual(
                semantic["checks"]["orphan_project_state_source_events"],
                1,
            )
            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "authority_corrupt")
            self.assertEqual(
                blocked["authority_corruption"][
                    "orphan_project_state_source_event_count"
                ],
                1,
            )
            self.assertFalse(preview["ok"], preview)
            self.assertFalse(applied["ok"], applied)
            self.assertIn(
                "orphan_project_state_source_event",
                {issue["type"] for issue in applied["authority_topology_issues"]},
            )
            self.assertEqual(before, after)
            self.assertEqual(applied["quarantined_count"], 0)
            self.assertEqual(applied["retired_peer_count"], 0)
            self.assertNotEqual(missing["card_id"], current["card_id"])

    def test_invalid_source_scope_has_structured_repair_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            repairable = record_project_state(
                root,
                session_id="invalid-source-scope",
                agent_id="invalid-source-agent",
                project_id="invalid-source-project",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE scroll_events SET visibility_scope = 'bogus' "
                    "WHERE id = ?",
                    (repairable["event_id"],),
                )
                conn.commit()
            finally:
                conn.close()

            preview = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="invalid-source-project",
                dry_run=True,
            )
            applied = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="invalid-source-project",
                dry_run=False,
            )
            self.assertTrue(preview["ok"], preview)
            self.assertEqual(preview["quarantined_count"], 1)
            self.assertTrue(applied["ok"], applied)
            self.assertEqual(applied["quarantined_count"], 1)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            unrepairable = record_project_state(
                root,
                session_id="invalid-hidden-source-scope",
                agent_id="invalid-hidden-source-agent",
                project_id="invalid-hidden-source-project",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET card_type = 'decision' WHERE id = ?",
                    (unrepairable["card_id"],),
                )
                conn.execute(
                    "UPDATE scroll_events SET visibility_scope = 'bogus' "
                    "WHERE id = ?",
                    (unrepairable["event_id"],),
                )
                conn.commit()
                before = conn.execute(
                    "SELECT card_type, status, supersedes_card_id, "
                    "superseded_by_card_id FROM cards WHERE id = ?",
                    (unrepairable["card_id"],),
                ).fetchone()
            finally:
                conn.close()
            preview = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="invalid-hidden-source-project",
                dry_run=True,
            )
            applied = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="invalid-hidden-source-project",
                dry_run=False,
            )
            conn = connect(root)
            try:
                after = conn.execute(
                    "SELECT card_type, status, supersedes_card_id, "
                    "superseded_by_card_id FROM cards WHERE id = ?",
                    (unrepairable["card_id"],),
                ).fetchone()
            finally:
                conn.close()
            self.assertFalse(preview["ok"], preview)
            self.assertFalse(applied["ok"], applied)
            self.assertIn(
                "invalid_source_authority_boundary",
                {issue["type"] for issue in applied["authority_topology_issues"]},
            )
            self.assertEqual(tuple(before), tuple(after))

    def test_graph_proven_expected_id_survives_combined_card_drift(self) -> None:
        mutations = {
            "title": "UPDATE cards SET title = title || ' drift' WHERE id = ?",
            "summary": (
                "UPDATE cards SET summary = summary || ' drift' WHERE id = ?"
            ),
            "project": (
                "UPDATE cards SET project_id = 'moved-project' WHERE id = ?"
            ),
            "source_refs": (
                "UPDATE cards SET source_refs_json = '[]' WHERE id = ?"
            ),
        }
        for field, mutation_sql in mutations.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                hidden = record_project_state(
                    root,
                    session_id=f"combined-hidden-{field}",
                    agent_id=f"combined-hidden-agent-{field}",
                    project_id="combined-drift-project",
                )
                current = record_project_state(
                    root,
                    session_id=f"combined-current-{field}",
                    agent_id=f"combined-current-agent-{field}",
                    project_id="combined-drift-project",
                )
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE cards SET card_type = 'decision' WHERE id = ?",
                        (hidden["card_id"],),
                    )
                    conn.execute(mutation_sql, (hidden["card_id"],))
                    conn.commit()
                finally:
                    conn.close()
                sync_card_sidecars_after_commit(root, [str(hidden["card_id"])])

                semantic = store_module.semantic_integrity_report(root)
                blocked = resume_latest(
                    root,
                    project_id="combined-drift-project",
                    model_assist=False,
                )
                preview = store_module.repair_invalid_project_state_checkpoints(
                    root,
                    project_id="combined-drift-project",
                    dry_run=True,
                )
                repaired = store_module.repair_invalid_project_state_checkpoints(
                    root,
                    project_id="combined-drift-project",
                    dry_run=False,
                )
                resumed = resume_latest(
                    root,
                    project_id="combined-drift-project",
                    model_assist=False,
                )

                self.assertFalse(semantic["ok"], semantic)
                self.assertEqual(
                    semantic["checks"]["source_bound_card_type_mismatches"],
                    1,
                )
                self.assertFalse(blocked["ok"], blocked)
                self.assertEqual(blocked["reason"], "authority_corrupt")
                self.assertEqual(preview["quarantined_count"], 1)
                self.assertEqual(repaired["quarantined_count"], 1)
                self.assertTrue(resumed["ok"], resumed)
                self.assertEqual(
                    resumed["discovery"]["checkpoint_id"],
                    current["card_id"],
                )

    def test_source_boundary_drift_reactivates_reciprocal_predecessor(self) -> None:
        cases = (
            (
                "project_project",
                "project",
                "UPDATE cards SET project_id = 'moved-project' WHERE id = ?",
            ),
            (
                "project_scope",
                "project",
                "UPDATE cards SET visibility_scope = 'private' WHERE id = ?",
            ),
            (
                "session_project",
                "session",
                "UPDATE cards SET project_id = 'moved-project' WHERE id = ?",
            ),
            (
                "session_session",
                "session",
                "UPDATE cards SET session_id = 'moved-session' WHERE id = ?",
            ),
            (
                "session_scope",
                "session",
                "UPDATE cards SET visibility_scope = 'private' WHERE id = ?",
            ),
        )
        for name, scope, mutation_sql in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                session_id = f"boundary-chain-{name}"
                metadata = {"visibility_scope": scope}
                predecessor = record_project_state(
                    root,
                    session_id=session_id,
                    agent_id="boundary-chain-agent",
                    project_id="boundary-chain-project",
                    metadata=metadata,
                )
                damaged = record_project_state(
                    root,
                    session_id=session_id,
                    agent_id="boundary-chain-agent",
                    project_id="boundary-chain-project",
                    metadata=metadata,
                )
                conn = connect(root)
                try:
                    conn.execute(mutation_sql, (damaged["card_id"],))
                    conn.commit()
                finally:
                    conn.close()
                sync_card_sidecars_after_commit(root, [str(damaged["card_id"])])

                repair_kwargs = {"project_id": "boundary-chain-project"}
                if scope == "session":
                    repair_kwargs["session_id"] = session_id
                preview = store_module.repair_invalid_project_state_checkpoints(
                    root,
                    dry_run=True,
                    **repair_kwargs,
                )
                applied = store_module.repair_invalid_project_state_checkpoints(
                    root,
                    dry_run=False,
                    **repair_kwargs,
                )
                resume_kwargs = {"project_id": "boundary-chain-project"}
                if scope == "session":
                    resume_kwargs["session_id"] = session_id
                resumed = resume_latest(
                    root,
                    model_assist=False,
                    **resume_kwargs,
                )

                self.assertEqual(
                    preview["quarantined"][0]["predecessor_card_id"],
                    predecessor["card_id"],
                )
                self.assertEqual(preview["retired_peer_count"], 0)
                self.assertEqual(preview["detached_peer_count"], 0)
                self.assertEqual(
                    applied["reactivated_card_ids"],
                    [predecessor["card_id"]],
                )
                self.assertEqual(applied["retired_peer_count"], 0)
                self.assertEqual(applied["detached_peer_count"], 0)
                self.assertTrue(store_module.semantic_integrity_report(root)["ok"])
                self.assertTrue(resumed["ok"], resumed)
                self.assertEqual(
                    resumed["discovery"]["checkpoint_id"],
                    predecessor["card_id"],
                )

    def test_proven_non_direct_peer_retirement_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="proven-peer-first",
                agent_id="proven-peer-agent-a",
                project_id="proven-peer-project",
            )
            direct = record_project_state(
                root,
                session_id="proven-peer-direct",
                agent_id="proven-peer-agent-b",
                project_id="proven-peer-project",
            )
            winner = record_project_state(
                root,
                session_id="proven-peer-winner",
                agent_id="proven-peer-agent-c",
                project_id="proven-peer-project",
            )
            resolve_conflict(
                root,
                card_id=winner["card_id"],
                superseded_card_ids=[first["card_id"], direct["card_id"]],
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = summary || ' damaged' WHERE id = ?",
                    (winner["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [str(winner["card_id"])])

            preview = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="proven-peer-project",
                dry_run=True,
            )
            applied = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="proven-peer-project",
                dry_run=False,
            )

            self.assertEqual(preview["quarantined_count"], 1)
            self.assertEqual(preview["retired_peer_count"], 2)
            self.assertEqual(
                preview["retired_peer_card_ids"],
                sorted([first["card_id"], direct["card_id"]]),
            )
            self.assertEqual(preview["detached_peer_count"], 0)
            self.assertEqual(
                preview["retired_peer_card_ids"],
                applied["retired_peer_card_ids"],
            )
            self.assertEqual(applied["reactivated_card_ids"], [])
            self.assertTrue(store_module.semantic_integrity_report(root)["ok"])

    def test_unproven_noncurrent_peer_refuses_repair_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="unknown-peer-chain",
                agent_id="unknown-peer-chain-agent",
                project_id="unknown-peer-project",
            )
            damaged = record_project_state(
                root,
                session_id="unknown-peer-chain",
                agent_id="unknown-peer-chain-agent",
                project_id="unknown-peer-project",
            )
            peer = record_project_state(
                root,
                session_id="unknown-peer",
                agent_id="unknown-peer-agent",
                project_id="unknown-peer-project",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = summary || ' damaged' WHERE id = ?",
                    (damaged["card_id"],),
                )
                conn.execute(
                    "UPDATE cards SET status = 'historical', "
                    "superseded_by_card_id = ? WHERE id = ?",
                    (damaged["card_id"], peer["card_id"]),
                )
                conn.commit()
                before = [
                    tuple(row)
                    for row in conn.execute(
                        "SELECT id, status, supersedes_card_id, "
                        "superseded_by_card_id FROM cards ORDER BY id"
                    ).fetchall()
                ]
            finally:
                conn.close()
            sync_card_sidecars_after_commit(
                root,
                [str(damaged["card_id"]), str(peer["card_id"])],
            )

            preview = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="unknown-peer-project",
                dry_run=True,
            )
            applied = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="unknown-peer-project",
                dry_run=False,
            )
            conn = connect(root)
            try:
                after = [
                    tuple(row)
                    for row in conn.execute(
                        "SELECT id, status, supersedes_card_id, "
                        "superseded_by_card_id FROM cards ORDER BY id"
                    ).fetchall()
                ]
            finally:
                conn.close()

            self.assertFalse(preview["ok"], preview)
            self.assertFalse(applied["ok"], applied)
            self.assertIn(
                "unproven_noncurrent_peer_restoration_unknown",
                {issue["type"] for issue in applied["authority_topology_issues"]},
            )
            self.assertEqual(applied["quarantined_count"], 0)
            self.assertEqual(applied["retired_peer_count"], 0)
            self.assertEqual(applied["detached_peer_count"], 0)
            self.assertEqual(before, after)

    def test_scroll_only_project_state_event_is_not_an_orphan_card(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            payload_hash = store_module._project_state_payload_hash([], [])
            content = (
                "Project state for scroll-only-project\n"
                "Agent: scroll-only-agent\n"
                f"{store_module._PROJECT_STATE_PAYLOAD_MARKER}{payload_hash}"
            )
            append_scroll_event(
                root,
                session_id="scroll-only-session",
                event_type="project_state",
                role="agent",
                content=content,
                metadata={
                    "agent_id": "scroll-only-agent",
                    "project_id": "scroll-only-project",
                    "source_type": "project_state",
                    "state_payload_hash": payload_hash,
                    "visibility_scope": "project",
                },
            )

            semantic = store_module.semantic_integrity_report(root)
            preview = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="scroll-only-project",
                dry_run=True,
            )
            resumed = resume_latest(
                root,
                project_id="scroll-only-project",
                model_assist=False,
            )

            self.assertTrue(semantic["ok"], semantic)
            self.assertEqual(
                semantic["checks"]["orphan_project_state_source_events"],
                0,
            )
            self.assertTrue(preview["ok"], preview)
            self.assertEqual(preview["quarantined_count"], 0)
            self.assertFalse(resumed["ok"], resumed)
            self.assertEqual(resumed["reason"], "no_resume_state")

    def test_duplicate_exact_graph_refs_cannot_hide_source_authority(self) -> None:
        for scenario in ("deleted", "combined_drift"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                hidden = record_project_state(
                    root,
                    session_id=f"graph-overflow-hidden-{scenario}",
                    agent_id=f"graph-overflow-agent-{scenario}",
                    project_id="graph-overflow-project",
                )
                current = record_project_state(
                    root,
                    session_id=f"graph-overflow-current-{scenario}",
                    agent_id=f"graph-overflow-current-agent-{scenario}",
                    project_id="graph-overflow-project",
                )
                conn = connect(root)
                try:
                    target_node_id = store_module.upsert_graph_node(
                        conn,
                        kind="topic",
                        label=f"graph-overflow-target-{scenario}",
                    )
                    for ordinal in range(20):
                        source_node_id = store_module.upsert_graph_node(
                            conn,
                            kind="topic",
                            label=(
                                f"graph-overflow-source-{scenario}-{ordinal}"
                            ),
                        )
                        store_module.add_graph_edge(
                            conn,
                            source_node_id=source_node_id,
                            relation="duplicates_exact_authority_source",
                            target_node_id=target_node_id,
                            weight=0.5,
                            confidence=0.9,
                            source_refs=[
                                {
                                    "event_id": hidden["event_id"],
                                    "card_id": hidden["card_id"],
                                }
                            ],
                        )
                    if scenario == "deleted":
                        conn.execute(
                            "DELETE FROM cards WHERE id = ?",
                            (hidden["card_id"],),
                        )
                    else:
                        conn.execute(
                            "UPDATE cards SET card_type = 'decision', "
                            "summary = summary || ' drift' WHERE id = ?",
                            (hidden["card_id"],),
                        )
                    conn.commit()
                finally:
                    conn.close()
                if scenario == "combined_drift":
                    sync_card_sidecars_after_commit(
                        root,
                        [str(hidden["card_id"])],
                    )

                semantic = store_module.semantic_integrity_report(root)
                blocked = resume_latest(
                    root,
                    project_id="graph-overflow-project",
                    model_assist=False,
                )
                preview = store_module.repair_invalid_project_state_checkpoints(
                    root,
                    project_id="graph-overflow-project",
                    dry_run=True,
                )

                self.assertFalse(semantic["ok"], semantic)
                self.assertFalse(blocked["ok"], blocked)
                self.assertEqual(blocked["reason"], "authority_corrupt")
                if scenario == "deleted":
                    self.assertEqual(
                        semantic["checks"][
                            "orphan_project_state_source_events"
                        ],
                        1,
                    )
                    self.assertFalse(preview["ok"], preview)
                    self.assertEqual(preview["quarantined_count"], 0)
                else:
                    self.assertEqual(
                        semantic["checks"][
                            "source_bound_card_type_mismatches"
                        ],
                        1,
                    )
                    self.assertEqual(preview["quarantined_count"], 1)
                    repaired = (
                        store_module.repair_invalid_project_state_checkpoints(
                            root,
                            project_id="graph-overflow-project",
                            dry_run=False,
                        )
                    )
                    resumed = resume_latest(
                        root,
                        project_id="graph-overflow-project",
                        model_assist=False,
                    )
                    self.assertEqual(repaired["quarantined_count"], 1)
                    self.assertTrue(resumed["ok"], resumed)
                    self.assertEqual(
                        resumed["discovery"]["checkpoint_id"],
                        current["card_id"],
                    )

    def test_ordinary_source_noise_does_not_truncate_authority_verification(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            hidden = record_project_state(
                root,
                session_id="source-noise-hidden",
                agent_id="source-noise-hidden-agent",
                project_id="source-noise-project",
            )
            record_project_state(
                root,
                session_id="source-noise-current",
                agent_id="source-noise-current-agent",
                project_id="source-noise-project",
            )
            conn = connect(root)
            try:
                source = conn.execute(
                    "SELECT session_id, seq FROM scroll_events WHERE id = ?",
                    (hidden["event_id"],),
                ).fetchone()
                template_id = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Ordinary source-derived noise",
                    summary="This Card is not project-state authority.",
                    source_refs=[
                        {
                            "event_id": hidden["event_id"],
                            "session_id": source["session_id"],
                            "seq": source["seq"],
                        }
                    ],
                    visibility_scope="project",
                    session_id="source-noise-hidden",
                    project_id="source-noise-project",
                )
                conn.execute(
                    "DELETE FROM graph_edge_sources "
                    "WHERE json_extract(source_ref_json, '$.event_id') = ? "
                    "AND json_extract(source_ref_json, '$.card_id') = ?",
                    (hidden["event_id"], hidden["card_id"]),
                )
                conn.execute(
                    "UPDATE cards SET project_id = 'source-noise-moved' "
                    "WHERE id = ?",
                    (hidden["card_id"],),
                )
                columns = [
                    str(row["name"])
                    for row in conn.execute("PRAGMA table_info(cards)").fetchall()
                ]
                select_columns = [
                    "?" if column == "id" else column for column in columns
                ]
                clone_sql = (
                    f"INSERT INTO cards ({', '.join(columns)}) "
                    f"SELECT {', '.join(select_columns)} FROM cards WHERE id = ?"
                )
                conn.executemany(
                    clone_sql,
                    [
                        (f"ordinary_source_noise_{ordinal:04d}", template_id)
                        for ordinal in range(1005)
                    ],
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [str(hidden["card_id"])])

            blocked = resume_latest(
                root,
                project_id="source-noise-project",
                model_assist=False,
            )
            preview = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="source-noise-project",
                dry_run=True,
            )
            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "authority_corrupt")
            authority = blocked["authority_corruption"]
            self.assertFalse(authority["boundary_scan_overflow"], authority)
            self.assertIn(
                "source_bound_authority_boundary_mismatch",
                {issue["type"] for issue in authority["topology_issues"]},
            )
            self.assertTrue(preview["ok"], preview)
            self.assertEqual(preview["quarantined_count"], 1)
            self.assertNotIn(
                "repair_scan_overflow",
                {issue["type"] for issue in preview["authority_topology_issues"]},
            )

    def test_source_coordinate_drift_cannot_hide_original_authority(self) -> None:
        cases = (
            (
                "P1_type_source_bogus",
                "project",
                (
                    "UPDATE cards SET card_type = 'decision' WHERE id = ?",
                    "UPDATE scroll_events SET visibility_scope = 'bogus' WHERE id = ?",
                ),
                False,
            ),
            (
                "P2_type_source_project_moved",
                "project",
                (
                    "UPDATE cards SET card_type = 'decision' WHERE id = ?",
                    "UPDATE scroll_events SET project_id = 'coordinate-other' WHERE id = ?",
                ),
                True,
            ),
            (
                "P3_card_and_source_project_moved",
                "project",
                (
                    "UPDATE cards SET project_id = 'coordinate-other' WHERE id = ?",
                    "UPDATE scroll_events SET project_id = 'coordinate-other' WHERE id = ?",
                ),
                True,
            ),
            (
                "P4_type_source_private",
                "project",
                (
                    "UPDATE cards SET card_type = 'decision' WHERE id = ?",
                    "UPDATE scroll_events SET visibility_scope = 'private' WHERE id = ?",
                ),
                True,
            ),
            (
                "P5_card_and_source_globalized",
                "project",
                (
                    "UPDATE cards SET visibility_scope = 'global', project_id = '' WHERE id = ?",
                    "UPDATE scroll_events SET visibility_scope = 'global', project_id = '' WHERE id = ?",
                ),
                True,
            ),
            (
                "S1_type_source_session_moved",
                "session",
                (
                    "UPDATE cards SET card_type = 'decision' WHERE id = ?",
                    "UPDATE scroll_events SET session_id = 'coordinate-session-other' WHERE id = ?",
                ),
                True,
            ),
            (
                "S2_card_and_source_session_moved",
                "session",
                (
                    "UPDATE cards SET session_id = 'coordinate-session-other' WHERE id = ?",
                    "UPDATE scroll_events SET session_id = 'coordinate-session-other' WHERE id = ?",
                ),
                True,
            ),
            (
                "S3_type_source_bogus",
                "session",
                (
                    "UPDATE cards SET card_type = 'decision' WHERE id = ?",
                    "UPDATE scroll_events SET visibility_scope = 'bogus' WHERE id = ?",
                ),
                False,
            ),
        )
        for name, scope, mutation_sql, repairable in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                session_id = f"coordinate-original-{name}"
                metadata = {"visibility_scope": scope}
                hidden = record_project_state(
                    root,
                    session_id=session_id,
                    agent_id=f"coordinate-hidden-{name}",
                    project_id="coordinate-project",
                    metadata=metadata,
                )
                current = record_project_state(
                    root,
                    session_id=session_id,
                    agent_id=f"coordinate-current-{name}",
                    project_id="coordinate-project",
                    metadata=metadata,
                )
                conn = connect(root)
                try:
                    conn.execute(mutation_sql[0], (hidden["card_id"],))
                    conn.execute(mutation_sql[1], (hidden["event_id"],))
                    conn.commit()
                finally:
                    conn.close()
                sync_card_sidecars_after_commit(root, [str(hidden["card_id"])])
                resume_kwargs = (
                    {"project_id": "coordinate-project"}
                    if scope == "project"
                    else {"session_id": session_id}
                )

                blocked = resume_latest(
                    root,
                    model_assist=False,
                    **resume_kwargs,
                )
                unscoped_blocked = resume_latest(
                    root,
                    model_assist=False,
                )
                preview = store_module.repair_invalid_project_state_checkpoints(
                    root,
                    project_id="coordinate-project",
                    session_id=(session_id if scope == "session" else None),
                    include_private=(name == "P4_type_source_private"),
                    dry_run=True,
                )

                self.assertFalse(blocked["ok"], blocked)
                self.assertEqual(blocked["reason"], "authority_corrupt")
                self.assertTrue(blocked["repair_required"])
                self.assertFalse(unscoped_blocked["ok"], unscoped_blocked)
                self.assertEqual(
                    unscoped_blocked["reason"],
                    "authority_corrupt",
                )
                self.assertFalse(
                    (root / "exports" / "thread_recovery").exists()
                )
                if repairable:
                    self.assertTrue(preview["ok"], preview)
                    self.assertEqual(preview["quarantined_count"], 1)
                    applied = (
                        store_module.repair_invalid_project_state_checkpoints(
                            root,
                            project_id="coordinate-project",
                            session_id=(session_id if scope == "session" else None),
                            include_private=(name == "P4_type_source_private"),
                            dry_run=False,
                        )
                    )
                    resumed = resume_latest(
                        root,
                        model_assist=False,
                        **resume_kwargs,
                    )
                    self.assertTrue(applied["ok"], applied)
                    self.assertEqual(applied["quarantined_count"], 1)
                    self.assertTrue(resumed["ok"], resumed)
                    self.assertEqual(
                        resumed["discovery"]["checkpoint_id"],
                        current["card_id"],
                    )
                else:
                    self.assertFalse(preview["ok"], preview)
                    self.assertIn(
                        "invalid_source_authority_boundary",
                        {
                            issue["type"]
                            for issue in preview["authority_topology_issues"]
                        },
                    )

    def test_graphless_deterministic_identity_preserves_original_boundary(
        self,
    ) -> None:
        cases = (
            (
                "project",
                "graphless-coordinate-project-session",
                {
                    "project_id": "graphless-coordinate-project",
                },
                (
                    "UPDATE cards SET card_type = 'decision', project_id = ? "
                    "WHERE id = ?",
                    "UPDATE scroll_events SET project_id = ? WHERE id = ?",
                    "graphless-coordinate-other-project",
                ),
            ),
            (
                "session",
                "graphless-coordinate-original-session",
                {
                    "session_id": "graphless-coordinate-original-session",
                },
                (
                    "UPDATE cards SET card_type = 'decision', session_id = ? "
                    "WHERE id = ?",
                    "UPDATE scroll_events SET session_id = ? WHERE id = ?",
                    "graphless-coordinate-other-session",
                ),
            ),
        )
        for scope, session_id, resume_kwargs, mutation in cases:
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                project_id = "graphless-coordinate-project"
                metadata = {"visibility_scope": scope}
                hidden = record_project_state(
                    root,
                    session_id=session_id,
                    agent_id=f"graphless-coordinate-hidden-{scope}",
                    project_id=project_id,
                    metadata=metadata,
                )
                current = record_project_state(
                    root,
                    session_id=session_id,
                    agent_id=f"graphless-coordinate-current-{scope}",
                    project_id=project_id,
                    metadata=metadata,
                )
                conn = connect(root)
                try:
                    conn.execute(
                        "DELETE FROM graph_edge_sources "
                        "WHERE json_extract(source_ref_json, '$.event_id') = ? "
                        "AND json_extract(source_ref_json, '$.card_id') = ?",
                        (hidden["event_id"], hidden["card_id"]),
                    )
                    conn.execute(
                        mutation[0],
                        (mutation[2], hidden["card_id"]),
                    )
                    conn.execute(
                        mutation[1],
                        (mutation[2], hidden["event_id"]),
                    )
                    conn.commit()
                finally:
                    conn.close()
                sync_card_sidecars_after_commit(
                    root,
                    [str(hidden["card_id"])],
                )

                blocked = resume_latest(
                    root,
                    model_assist=False,
                    **resume_kwargs,
                )
                unscoped_blocked = resume_latest(root, model_assist=False)
                preview = (
                    store_module.repair_invalid_project_state_checkpoints(
                        root,
                        project_id=project_id,
                        session_id=(session_id if scope == "session" else None),
                        dry_run=True,
                    )
                )

                self.assertFalse(blocked["ok"], blocked)
                self.assertEqual(blocked["reason"], "authority_corrupt")
                self.assertFalse(unscoped_blocked["ok"], unscoped_blocked)
                self.assertEqual(
                    unscoped_blocked["reason"],
                    "authority_corrupt",
                )
                self.assertEqual(preview["quarantined_count"], 1, preview)
                self.assertFalse(
                    (root / "exports" / "thread_recovery").exists()
                )

                applied = store_module.repair_invalid_project_state_checkpoints(
                    root,
                    project_id=project_id,
                    session_id=(session_id if scope == "session" else None),
                    dry_run=False,
                )
                resumed = resume_latest(
                    root,
                    model_assist=False,
                    **resume_kwargs,
                )

                self.assertTrue(applied["ok"], applied)
                self.assertEqual(applied["quarantined_count"], 1)
                self.assertTrue(resumed["ok"], resumed)
                self.assertEqual(
                    resumed["discovery"]["checkpoint_id"],
                    current["card_id"],
                )

    def test_graph_proven_legacy_reference_survives_source_session_drift(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            session_id = "legacy-graph-original-session"
            project_id = "legacy-graph-project"
            hidden = record_project_state(
                root,
                session_id=session_id,
                agent_id="legacy-graph-hidden-agent",
                project_id=project_id,
                metadata={"visibility_scope": "session"},
            )
            current = record_project_state(
                root,
                session_id=session_id,
                agent_id="legacy-graph-current-agent",
                project_id=project_id,
                metadata={"visibility_scope": "session"},
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET card_type = 'decision', "
                    "source_refs_json = json_remove(source_refs_json, "
                    "'$[0].event_id') WHERE id = ?",
                    (hidden["card_id"],),
                )
                conn.execute(
                    "UPDATE scroll_events SET session_id = ? WHERE id = ?",
                    ("legacy-graph-moved-session", hidden["event_id"]),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [str(hidden["card_id"])])

            semantic = store_module.semantic_integrity_report(root)
            blocked = resume_latest(
                root,
                session_id=session_id,
                model_assist=False,
            )
            unscoped_blocked = resume_latest(root, model_assist=False)
            preview = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id=project_id,
                session_id=session_id,
                dry_run=True,
            )

            self.assertFalse(semantic["ok"], semantic)
            self.assertEqual(
                semantic["checks"]["source_bound_card_type_mismatches"],
                1,
            )
            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "authority_corrupt")
            self.assertFalse(unscoped_blocked["ok"], unscoped_blocked)
            self.assertEqual(
                unscoped_blocked["reason"],
                "authority_corrupt",
            )
            self.assertEqual(preview["quarantined_count"], 1, preview)
            self.assertFalse((root / "exports" / "thread_recovery").exists())

            applied = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id=project_id,
                session_id=session_id,
                dry_run=False,
            )
            resumed = resume_latest(
                root,
                session_id=session_id,
                model_assist=False,
            )

            self.assertTrue(applied["ok"], applied)
            self.assertEqual(applied["quarantined_count"], 1)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                current["card_id"],
            )

    def test_deterministic_legacy_reference_survives_source_session_drift_without_graph(
        self,
    ) -> None:
        for mutation in ("card_type", "card_and_source_session"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                session_id = f"legacy-no-graph-original-{mutation}"
                project_id = "legacy-no-graph-project"
                hidden = record_project_state(
                    root,
                    session_id=session_id,
                    agent_id=f"legacy-no-graph-hidden-{mutation}",
                    project_id=project_id,
                    metadata={"visibility_scope": "session"},
                )
                current = record_project_state(
                    root,
                    session_id=session_id,
                    agent_id=f"legacy-no-graph-current-{mutation}",
                    project_id=project_id,
                    metadata={"visibility_scope": "session"},
                )
                moved_session = f"legacy-no-graph-moved-{mutation}"
                conn = connect(root)
                try:
                    # This test exercises authority drift, not host clock behavior.
                    conn.execute(
                        "UPDATE scroll_events SET created_at = ? WHERE id = ?",
                        ("2024-01-01T00:00:00+00:00", hidden["event_id"]),
                    )
                    conn.execute(
                        "UPDATE scroll_events SET created_at = ? WHERE id = ?",
                        ("2024-01-01T00:00:01+00:00", current["event_id"]),
                    )
                    conn.execute(
                        "UPDATE cards SET source_refs_json = "
                        "json_remove(source_refs_json, '$[0].event_id') "
                        "WHERE id = ?",
                        (hidden["card_id"],),
                    )
                    if mutation == "card_type":
                        conn.execute(
                            "UPDATE cards SET card_type = 'decision' WHERE id = ?",
                            (hidden["card_id"],),
                        )
                    else:
                        conn.execute(
                            "UPDATE cards SET session_id = ? WHERE id = ?",
                            (moved_session, hidden["card_id"]),
                        )
                    conn.execute(
                        "UPDATE scroll_events SET session_id = ? WHERE id = ?",
                        (moved_session, hidden["event_id"]),
                    )
                    conn.execute(
                        """
                        DELETE FROM graph_edge_sources
                        WHERE json_extract(source_ref_json, '$.event_id') = ?
                          AND json_extract(source_ref_json, '$.card_id') = ?
                        """,
                        (hidden["event_id"], hidden["card_id"]),
                    )
                    conn.commit()
                finally:
                    conn.close()
                sync_card_sidecars_after_commit(root, [str(hidden["card_id"])])

                semantic = store_module.semantic_integrity_report(root)
                blocked = resume_latest(
                    root,
                    session_id=session_id,
                    model_assist=False,
                )
                unscoped_blocked = resume_latest(root, model_assist=False)
                preview = store_module.repair_invalid_project_state_checkpoints(
                    root,
                    project_id=project_id,
                    session_id=session_id,
                    dry_run=True,
                )

                self.assertFalse(semantic["ok"], semantic)
                self.assertFalse(blocked["ok"], blocked)
                self.assertEqual(blocked["reason"], "authority_corrupt")
                self.assertFalse(unscoped_blocked["ok"], unscoped_blocked)
                self.assertEqual(unscoped_blocked["reason"], "authority_corrupt")
                self.assertEqual(preview["quarantined_count"], 1, preview)
                self.assertFalse((root / "exports" / "thread_recovery").exists())

                applied = store_module.repair_invalid_project_state_checkpoints(
                    root,
                    project_id=project_id,
                    session_id=session_id,
                    dry_run=False,
                )
                resumed = resume_latest(
                    root,
                    session_id=session_id,
                    model_assist=False,
                )

                self.assertTrue(applied["ok"], applied)
                self.assertEqual(applied["quarantined_count"], 1)
                self.assertTrue(resumed["ok"], resumed)
                self.assertEqual(
                    resumed["discovery"]["checkpoint_id"],
                    current["card_id"],
                )

    def test_many_valid_legacy_sessions_do_not_overflow_source_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            card_ids: list[str] = []
            for index in range(24):
                state = record_project_state(
                    root,
                    session_id=f"legacy-many-session-{index:02d}",
                    agent_id=f"legacy-many-agent-{index:02d}",
                    project_id="legacy-many-project",
                    metadata={"visibility_scope": "session"},
                )
                card_ids.append(str(state["card_id"]))
            conn = connect(root)
            try:
                placeholders = ", ".join("?" for _ in card_ids)
                conn.execute(
                    f"""
                    UPDATE cards
                    SET source_refs_json = json_remove(
                        source_refs_json,
                        '$[0].event_id'
                    )
                    WHERE id IN ({placeholders})
                    """,
                    tuple(card_ids),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, card_ids)

            semantic = store_module.semantic_integrity_report(root)
            resumed = resume_latest(root, model_assist=False)

            self.assertTrue(semantic["ok"], semantic)
            self.assertEqual(
                semantic["checks"]["source_bound_project_state_scan_overflow"],
                0,
            )
            self.assertNotEqual(
                resumed.get("reason"),
                "authority_corrupt",
                resumed,
            )

    def test_project_resume_ignores_valid_session_private_source_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            project_state = record_project_state(
                root,
                session_id="coordinate-project-current",
                agent_id="coordinate-project-agent",
                project_id="coordinate-isolation-project",
            )
            private_state = record_project_state(
                root,
                session_id="coordinate-private-session",
                agent_id="coordinate-private-agent",
                project_id="coordinate-isolation-project",
                metadata={"visibility_scope": "session"},
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET card_type = 'decision' WHERE id = ?",
                    (private_state["card_id"],),
                )
                conn.execute(
                    "UPDATE scroll_events SET visibility_scope = 'private' "
                    "WHERE id = ?",
                    (private_state["event_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(
                root,
                [str(private_state["card_id"])],
            )

            resumed = resume_latest(
                root,
                project_id="coordinate-isolation-project",
                model_assist=False,
            )

            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                project_state["card_id"],
            )

    def test_unscoped_resume_uses_durable_boundary_for_invalid_coordinates(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            hidden = record_project_state(
                root,
                session_id="coordinate-unscoped-hidden",
                agent_id="coordinate-unscoped-hidden-agent",
                project_id="coordinate-unscoped-project",
            )
            record_project_state(
                root,
                session_id="coordinate-unscoped-current",
                agent_id="coordinate-unscoped-current-agent",
                project_id="coordinate-unscoped-project",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET card_type = 'decision', "
                    "visibility_scope = 'bogus' WHERE id = ?",
                    (hidden["card_id"],),
                )
                conn.execute(
                    "UPDATE scroll_events SET visibility_scope = 'bogus' "
                    "WHERE id = ?",
                    (hidden["event_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [str(hidden["card_id"])])

            blocked = resume_latest(root, model_assist=False)

            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "authority_corrupt")

    def test_dual_capability_annotates_session_and_project_claims(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            session_id = "coordinate-dual-session"
            hidden = record_project_state(
                root,
                session_id=session_id,
                agent_id="coordinate-dual-hidden",
                project_id="coordinate-dual-project",
                metadata={"visibility_scope": "session"},
            )
            record_project_state(
                root,
                session_id=session_id,
                agent_id="coordinate-dual-current",
                project_id="coordinate-dual-project",
                metadata={"visibility_scope": "session"},
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET card_type = 'decision' WHERE id = ?",
                    (hidden["card_id"],),
                )
                conn.execute(
                    "UPDATE scroll_events SET visibility_scope = 'project', "
                    "project_id = ? WHERE id = ?",
                    ("coordinate-dual-project", hidden["event_id"]),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [str(hidden["card_id"])])

            authorized_results = (
                resume_latest(root, session_id=session_id, model_assist=False),
                resume_latest(
                    root,
                    session_id=session_id,
                    project_id="coordinate-dual-project",
                    model_assist=False,
                ),
                resume_latest(root, model_assist=False),
            )
            project_only = resume_latest(
                root,
                project_id="coordinate-dual-project",
                model_assist=False,
            )

            for result in authorized_results:
                self.assertFalse(result["ok"], result)
                self.assertEqual(result["reason"], "authority_corrupt")
            self.assertFalse(project_only["ok"], project_only)
            self.assertEqual(project_only["reason"], "no_resume_state")
            serialized = json.dumps(project_only, sort_keys=True)
            self.assertNotIn(str(hidden["card_id"]), serialized)
            self.assertNotIn(str(hidden["event_id"]), serialized)
            self.assertNotIn(session_id, serialized)
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_source_metadata_boundary_survives_corrupt_card_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            hidden = record_project_state(
                root,
                session_id="coordinate-source-metadata-hidden",
                agent_id="coordinate-source-metadata-agent",
                project_id="coordinate-source-metadata-project",
            )
            record_project_state(
                root,
                session_id="coordinate-source-metadata-current",
                agent_id="coordinate-source-metadata-current-agent",
                project_id="coordinate-source-metadata-project",
            )
            conn = connect(root)
            try:
                metadata_row = conn.execute(
                    "SELECT metadata_json FROM cards WHERE id = ?",
                    (hidden["card_id"],),
                ).fetchone()
                metadata = json.loads(metadata_row["metadata_json"])
                metadata["project_id"] = "coordinate-metadata-other"
                metadata["visibility_scope"] = "project"
                conn.execute(
                    "UPDATE cards SET card_type = 'decision', project_id = ?, "
                    "metadata_json = ? WHERE id = ?",
                    (
                        "coordinate-metadata-other",
                        json.dumps(metadata),
                        hidden["card_id"],
                    ),
                )
                conn.execute(
                    "UPDATE scroll_events SET project_id = ? WHERE id = ?",
                    ("coordinate-metadata-other", hidden["event_id"]),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [str(hidden["card_id"])])

            blocked = resume_latest(
                root,
                project_id="coordinate-source-metadata-project",
                model_assist=False,
            )

            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "authority_corrupt")

    def test_session_metadata_survives_coordinate_and_ref_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            session_id = "coordinate-metadata-session-original"
            hidden = record_project_state(
                root,
                session_id=session_id,
                agent_id="coordinate-metadata-session-hidden",
                project_id="coordinate-metadata-session-project",
                metadata={"visibility_scope": "session"},
            )
            current = record_project_state(
                root,
                session_id=session_id,
                agent_id="coordinate-metadata-session-current",
                project_id="coordinate-metadata-session-project",
                metadata={"visibility_scope": "session"},
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET card_type = 'decision', session_id = ?, "
                    "source_refs_json = json_set(source_refs_json, "
                    "'$[0].session_id', ?) WHERE id = ?",
                    (
                        "coordinate-metadata-session-moved",
                        "coordinate-metadata-session-moved",
                        hidden["card_id"],
                    ),
                )
                conn.execute(
                    "UPDATE scroll_events SET session_id = ? WHERE id = ?",
                    (
                        "coordinate-metadata-session-moved",
                        hidden["event_id"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [str(hidden["card_id"])])

            blocked = resume_latest(
                root,
                session_id=session_id,
                model_assist=False,
            )
            preview = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="coordinate-metadata-session-project",
                session_id=session_id,
                dry_run=True,
            )
            applied = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="coordinate-metadata-session-project",
                session_id=session_id,
                dry_run=False,
            )
            resumed = resume_latest(
                root,
                session_id=session_id,
                model_assist=False,
            )

            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "authority_corrupt")
            self.assertEqual(preview["quarantined_count"], 1)
            self.assertTrue(applied["ok"], applied)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                current["card_id"],
            )

    def test_repair_reports_committed_catalog_when_sidecar_sync_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            damaged = record_project_state(
                root,
                session_id="repair-sidecar-failure",
                agent_id="repair-sidecar-agent",
                project_id="repair-sidecar-project",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = summary || ' damaged' WHERE id = ?",
                    (damaged["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [str(damaged["card_id"])])
            failed_sync = {
                "ok": False,
                "synced": 0,
                "deferred": 1,
                "failed": 1,
                "failures": [
                    {
                        "card_id": damaged["card_id"],
                        "error": "injected sidecar failure",
                    }
                ],
            }

            with patch.object(
                store_module,
                "sync_card_sidecars_after_commit",
                return_value=failed_sync,
            ):
                repaired = (
                    store_module.repair_invalid_project_state_checkpoints(
                        root,
                        project_id="repair-sidecar-project",
                        dry_run=False,
                    )
                )

            self.assertFalse(repaired["ok"], repaired)
            self.assertTrue(repaired["catalog_repair_committed"])
            self.assertTrue(repaired["sidecar_sync_deferred"])
            self.assertEqual(repaired["sidecar_sync"], failed_sync)
            self.assertFalse(
                repaired["post_repair_semantic_integrity"]["ok"],
                repaired,
            )
            conn = connect(root)
            try:
                card = conn.execute(
                    "SELECT status FROM cards WHERE id = ?",
                    (damaged["card_id"],),
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(card["status"], "historical")

    def test_repair_fails_committed_result_for_semantic_postflight_failure(
        self,
    ) -> None:
        for failure_mode in ("false", "exception"):
            with self.subTest(failure_mode=failure_mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                damaged = record_project_state(
                    root,
                    session_id=f"repair-postflight-{failure_mode}",
                    agent_id="repair-postflight-agent",
                    project_id="repair-postflight-project",
                )
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE cards SET summary = summary || ' damaged' "
                        "WHERE id = ?",
                        (damaged["card_id"],),
                    )
                    conn.commit()
                finally:
                    conn.close()
                sync_card_sidecars_after_commit(root, [str(damaged["card_id"])])
                real_semantic_report = store_module.semantic_integrity_report
                call_count = 0

                def semantic_report(*args: object, **kwargs: object) -> dict[str, object]:
                    nonlocal call_count
                    call_count += 1
                    report = real_semantic_report(*args, **kwargs)
                    if call_count != 3:
                        return report
                    if failure_mode == "exception":
                        raise RuntimeError("injected semantic postflight failure")
                    return {
                        **report,
                        "ok": False,
                        "failing": {"injected_postflight_failure": 1},
                    }

                with patch.object(
                    store_module,
                    "semantic_integrity_report",
                    side_effect=semantic_report,
                ):
                    repaired = (
                        store_module.repair_invalid_project_state_checkpoints(
                            root,
                            project_id="repair-postflight-project",
                            dry_run=False,
                        )
                    )

                self.assertFalse(repaired["ok"], repaired)
                self.assertTrue(repaired["catalog_repair_committed"])
                self.assertTrue(repaired["sidecar_sync"]["ok"])
                self.assertFalse(repaired["post_repair_semantic_ok"])
                conn = connect(root)
                try:
                    status = conn.execute(
                        "SELECT status FROM cards WHERE id = ?",
                        (damaged["card_id"],),
                    ).fetchone()["status"]
                finally:
                    conn.close()
                self.assertEqual(status, "historical")

    def test_resume_fails_closed_when_discovered_checkpoint_becomes_contested(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="interleaved-session",
                agent_id="codex-sol",
                project_id="interleaved-project",
                objective="Do not return a mixed checkpoint",
            )
            original_recover = store_module.recover_thread

            def interleaved_recover(*args, **kwargs):
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE cards SET conflict_group = 'interleaved-conflict' WHERE id = ?",
                        (state["card_id"],),
                    )
                    conn.commit()
                finally:
                    conn.close()
                return original_recover(*args, **kwargs)

            with patch.object(
                store_module,
                "recover_thread",
                side_effect=interleaved_recover,
            ):
                result = resume_latest(root, model_assist=False)

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "checkpoint_changed_during_resume")
            self.assertEqual(result["discovery"]["checkpoint_id"], state["card_id"])
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_fails_closed_when_a_newer_project_state_arrives_after_discovery(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="old-session",
                agent_id="codex-sol",
                project_id="old-project",
                objective="Older selected checkpoint",
            )
            original_recover = store_module.recover_thread

            def interleaved_recover(*args, **kwargs):
                record_project_state(
                    root,
                    session_id="new-session",
                    agent_id="codex-sol",
                    project_id="new-project",
                    objective="Newer checkpoint inserted after discovery",
                )
                return original_recover(*args, **kwargs)

            with patch.object(
                store_module,
                "recover_thread",
                side_effect=interleaved_recover,
            ):
                result = resume_latest(root, model_assist=False)

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "checkpoint_changed_during_resume")
            self.assertEqual(result["session_id"], "old-session")
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_fails_closed_when_a_newer_scroll_event_arrives_after_discovery(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            old_event = append_scroll_event(
                root,
                session_id="old-scroll-session",
                event_type="message",
                role="user",
                content="Older Scroll fallback",
                metadata={"visibility_scope": "session"},
            )
            original_recover = store_module.recover_thread

            def interleaved_recover(*args, **kwargs):
                append_scroll_event(
                    root,
                    session_id="new-scroll-session",
                    event_type="message",
                    role="user",
                    content="Newer Scroll fallback inserted after discovery",
                    metadata={"visibility_scope": "session"},
                )
                return original_recover(*args, **kwargs)

            with patch.object(
                store_module,
                "recover_thread",
                side_effect=interleaved_recover,
            ):
                result = resume_latest(root, model_assist=False)

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "checkpoint_changed_during_resume")
            self.assertEqual(
                result["discovery"]["checkpoint_id"], old_event["event_id"]
            )
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_recovery_recent_event_limit_is_bounded_and_non_negative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with self.assertRaisesRegex(ValueError, "recent_event_limit"):
                recover_thread(root, session_id="bounded-session", recent_event_limit=-1)
            with self.assertRaisesRegex(ValueError, "recent_event_limit"):
                resume_latest(root, recent_event_limit=-1)
            self.assertFalse(root.exists())

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="bounded-session",
                agent_id="codex-sol",
                project_id="bounded-project",
                objective="Bound recovery scroll output",
            )
            for index in range(3):
                append_scroll_event(
                    root,
                    session_id="bounded-session",
                    event_type="message",
                    role="user",
                    content=f"recent bounded event {index}",
                    metadata={"project_id": "bounded-project", "visibility_scope": "project"},
                )

            none = recover_thread(
                root,
                session_id="bounded-session",
                project_id="bounded-project",
                recent_event_limit=0,
            )
            one = recover_thread(
                root,
                session_id="bounded-session",
                project_id="bounded-project",
                recent_event_limit=1,
            )

            self.assertEqual(none["recent_event_count"], 0)
            self.assertEqual(one["recent_event_count"], 1)

    def test_resume_packet_budget_bounds_complete_packet_without_raw_duplication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="bounded-packet-session",
                agent_id="codex-sol",
                project_id="bounded-packet-project",
                objective="Bound the complete recovery packet",
            )
            for index in range(24):
                append_scroll_event(
                    root,
                    session_id="bounded-packet-session",
                    event_type="message",
                    role="user",
                    content=f"LARGE-PACKET-EVENT-{index}:" + ("x" * 4096),
                    metadata={
                        "visibility_scope": "project",
                        "project_id": "bounded-packet-project",
                    },
                )
            configure_personal_profile(root, safe_context_ceiling=384)

            result = resume_latest(
                root,
                project_id="bounded-packet-project",
                recent_event_limit=24,
                model_assist=False,
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["packet_token_budget"], 384)
            self.assertEqual(result["recent_event_count"], 24)
            self.assertLessEqual(result["packet_estimated_tokens"], 384)
            self.assertEqual(
                result["packet_estimated_tokens"],
                estimate_tokens(result["packet_text"]),
            )
            self.assertTrue(result["packet_truncated"], result)
            self.assertIn('"session_id":"bounded-packet-session"', result["packet_text"])
            self.assertIn('"project_id":"bounded-packet-project"', result["packet_text"])
            self.assertIn("Bound the complete recovery packet", result["packet_text"])
            self.assertNotIn("## Recent Scroll", result["packet_text"])
            self.assertNotIn("## Recalled Cards", result["packet_text"])
            self.assertLessEqual(result["packet_text"].count("LARGE-PACKET-EVENT-23"), 1)

    def test_resume_packet_preserves_actionable_and_operational_details(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["context"]["scroll_event_fetch_limit"] = 2
            write_config(root, config)
            record_project_state(
                root,
                session_id="detail-session",
                agent_id="codex-sol",
                project_id="detail-project",
                objective="X" * 1200,
                decisions=["KEEP-RESTORE-PROOF"],
                open_tasks=["MUST-RUN-RESTORE-DRILL"],
            )
            source = Path(tmp) / "recovery-source.md"
            source.write_text("Recovery source evidence.\n", encoding="utf-8")
            ingested = ingest_file(
                root,
                path=source,
                title="RECOVERY-BOOK-MARKER",
            )
            conn = connect(root)
            try:
                create_card(
                    conn,
                    root=root,
                    card_type="reference",
                    title="Detail project recovery reference",
                    summary="Use the recovery book for the detail project.",
                    source_refs=[{"book_id": ingested["book_id"]}],
                    visibility_scope="project",
                    session_id="detail-session",
                    project_id="detail-project",
                )
                enqueue_job(
                    conn,
                    role="archivist",
                    job_type="RECOVERY-JOB-MARKER",
                    priority=5,
                    payload={
                        "visibility_scope": "project",
                        "session_id": "detail-session",
                        "project_id": "detail-project",
                        "next_step": "PRESERVE-JOB-PAYLOAD",
                    },
                )
                conn.commit()
            finally:
                conn.close()
            for index in range(3):
                append_scroll_event(
                    root,
                    session_id="detail-session",
                    event_type="message",
                    role="user",
                    content=f"newer detail event {index}",
                    metadata={
                        "visibility_scope": "project",
                        "project_id": "detail-project",
                    },
                )

            result = resume_latest(
                root,
                project_id="detail-project",
                token_budget=6000,
                model_assist=False,
            )

            self.assertTrue(result["ok"], result)
            self.assertIn("MUST-RUN-RESTORE-DRILL", result["packet_text"])
            self.assertIn("KEEP-RESTORE-PROOF", result["packet_text"])
            self.assertIn("RECOVERY-JOB-MARKER", result["packet_text"])
            self.assertIn("PRESERVE-JOB-PAYLOAD", result["packet_text"])
            self.assertIn("RECOVERY-BOOK-MARKER", result["packet_text"])
            self.assertIn("MUST-RUN-RESTORE-DRILL", result["context"]["context_text"])
            self.assertIn("KEEP-RESTORE-PROOF", result["context"]["context_text"])

    def test_resume_preserves_the_callers_visibility_capability_scope_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            session_state = record_project_state(
                root,
                session_id="matrix-session",
                agent_id="codex-sol",
                project_id="matrix-project",
                objective="SESSION-SCOPED-AUTHORIZED-CHECKPOINT",
                metadata={"visibility_scope": "session"},
            )
            project_state = record_project_state(
                root,
                session_id="matrix-session",
                agent_id="codex-sol",
                project_id="matrix-project",
                objective="NEWER-PROJECT-SCOPED-CHECKPOINT",
            )
            append_scroll_event(
                root,
                session_id="matrix-session",
                event_type="message",
                role="user",
                content="PROJECT-SCROLL-CAPABILITY-MARKER",
                metadata={
                    "visibility_scope": "project",
                    "project_id": "matrix-project",
                },
            )
            append_scroll_event(
                root,
                session_id="matrix-session",
                event_type="message",
                role="user",
                content="SESSION-SCROLL-CAPABILITY-MARKER",
                metadata={"visibility_scope": "session"},
            )
            conn = connect(root)
            try:
                create_card(
                    conn,
                    root=root,
                    card_type="reference",
                    title="PROJECT-CARD-CAPABILITY-MARKER",
                    summary="Evidence authorized only by the project capability.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="matrix-session",
                    project_id="matrix-project",
                )
                create_card(
                    conn,
                    root=root,
                    card_type="reference",
                    title="SESSION-CARD-CAPABILITY-MARKER",
                    summary="Evidence authorized only by the session capability.",
                    source_refs=[],
                    visibility_scope="session",
                    session_id="matrix-session",
                    project_id="matrix-project",
                )
                conn.commit()
            finally:
                conn.close()

            cases = [
                (
                    "session_only",
                    {"session_id": "matrix-session"},
                    {"session_id": "matrix-session", "project_id": None},
                    session_state["card_id"],
                    True,
                    False,
                ),
                (
                    "project_only",
                    {"project_id": "matrix-project"},
                    {"session_id": None, "project_id": "matrix-project"},
                    project_state["card_id"],
                    False,
                    True,
                ),
                (
                    "session_and_project",
                    {
                        "session_id": "matrix-session",
                        "project_id": "matrix-project",
                    },
                    {
                        "session_id": "matrix-session",
                        "project_id": "matrix-project",
                    },
                    project_state["card_id"],
                    True,
                    True,
                ),
                (
                    "unscoped_project_checkpoint",
                    {},
                    {"session_id": None, "project_id": "matrix-project"},
                    project_state["card_id"],
                    False,
                    True,
                ),
            ]
            for (
                name,
                kwargs,
                expected_capability,
                expected_checkpoint_id,
                sees_session,
                sees_project,
            ) in cases:
                with self.subTest(name=name):
                    result = resume_latest(
                        root,
                        token_budget=12000,
                        model_assist=False,
                        **kwargs,
                    )

                    self.assertTrue(result["ok"], result)
                    self.assertEqual(
                        result["visibility_capability"],
                        expected_capability,
                    )
                    self.assertEqual(
                        result["discovery"]["checkpoint_id"],
                        expected_checkpoint_id,
                    )
                    context_text = result["context"]["context_text"]
                    self.assertTrue(result["context"]["mandatory_checkpoint_fit"])
                    self.assertIn(expected_checkpoint_id, context_text)
                    for marker in (
                        session_state["card_id"],
                        "SESSION-SCOPED-AUTHORIZED-CHECKPOINT",
                        "SESSION-CARD-CAPABILITY-MARKER",
                        "SESSION-SCROLL-CAPABILITY-MARKER",
                    ):
                        if sees_session:
                            self.assertIn(marker, context_text)
                        else:
                            self.assertNotIn(marker, context_text)
                    for marker in (
                        project_state["card_id"],
                        "NEWER-PROJECT-SCOPED-CHECKPOINT",
                        "PROJECT-CARD-CAPABILITY-MARKER",
                        "PROJECT-SCROLL-CAPABILITY-MARKER",
                    ):
                        if sees_project:
                            self.assertIn(marker, context_text)
                        else:
                            self.assertNotIn(marker, context_text)

        unauthorized_cases = (
            (
                "session_cannot_select_project_checkpoint",
                {"session_id": "authority-session"},
                "project",
            ),
            (
                "project_cannot_select_session_checkpoint",
                {"project_id": "authority-project"},
                "session",
            ),
        )
        for name, kwargs, checkpoint_scope in unauthorized_cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                record_project_state(
                    root,
                    session_id="authority-session",
                    agent_id="codex-sol",
                    project_id="authority-project",
                    objective="UNAUTHORIZED-CHECKPOINT-MUST-NOT-RETURN",
                    metadata={"visibility_scope": checkpoint_scope},
                )

                result = resume_latest(root, model_assist=False, **kwargs)

                self.assertFalse(result["ok"], result)
                self.assertEqual(result["reason"], "no_resume_state")
                self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_dual_scope_resume_preserves_both_requested_capabilities_for_asymmetric_checkpoints(
        self,
    ) -> None:
        for winner in ("session", "project"):
            with self.subTest(winner=winner), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                if winner == "session":
                    project_state = record_project_state(
                        root,
                        session_id="project-checkpoint-session",
                        agent_id="codex-sol",
                        project_id="requested-project",
                        objective="REQUESTED-PROJECT-CARD-MARKER",
                    )
                    session_state = record_project_state(
                        root,
                        session_id="requested-session",
                        agent_id="codex-sol",
                        project_id="other-project",
                        objective="REQUESTED-SESSION-CARD-MARKER",
                        metadata={"visibility_scope": "session"},
                    )
                    selected_checkpoint_id = session_state["card_id"]
                else:
                    session_state = record_project_state(
                        root,
                        session_id="requested-session",
                        agent_id="codex-sol",
                        project_id="other-project",
                        objective="REQUESTED-SESSION-CARD-MARKER",
                        metadata={"visibility_scope": "session"},
                    )
                    project_state = record_project_state(
                        root,
                        session_id="project-checkpoint-session",
                        agent_id="codex-sol",
                        project_id="requested-project",
                        objective="REQUESTED-PROJECT-CARD-MARKER",
                    )
                    selected_checkpoint_id = project_state["card_id"]

                append_scroll_event(
                    root,
                    session_id="requested-session",
                    event_type="message",
                    role="user",
                    content="REQUESTED-SESSION-SCROLL-MARKER",
                    metadata={"visibility_scope": "session"},
                )
                append_scroll_event(
                    root,
                    session_id="project-evidence-session",
                    event_type="message",
                    role="user",
                    content="REQUESTED-PROJECT-SCROLL-MARKER",
                    metadata={
                        "visibility_scope": "project",
                        "project_id": "requested-project",
                    },
                )

                result = resume_latest(
                    root,
                    session_id="requested-session",
                    project_id="requested-project",
                    token_budget=12000,
                    model_assist=False,
                )

                self.assertTrue(result["ok"], result)
                self.assertEqual(
                    result["visibility_capability"],
                    {
                        "session_id": "requested-session",
                        "project_id": "requested-project",
                    },
                )
                self.assertEqual(
                    result["discovery"]["checkpoint_id"],
                    selected_checkpoint_id,
                )
                context_text = result["context"]["context_text"]
                for marker in (
                    "REQUESTED-SESSION-CARD-MARKER",
                    "REQUESTED-PROJECT-CARD-MARKER",
                    "REQUESTED-SESSION-SCROLL-MARKER",
                    "REQUESTED-PROJECT-SCROLL-MARKER",
                ):
                    self.assertIn(marker, context_text)

    def test_compile_context_rejects_unauthorized_mandatory_checkpoint_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="unauthorized-session",
                agent_id="codex-sol",
                project_id="unauthorized-project",
                objective="UNAUTHORIZED-MANDATORY-CARD-MARKER",
            )
            event = append_scroll_event(
                root,
                session_id="unauthorized-session",
                event_type="message",
                role="user",
                content="UNAUTHORIZED-MANDATORY-SCROLL-MARKER",
                metadata={
                    "visibility_scope": "project",
                    "project_id": "unauthorized-project",
                },
            )
            cases = (
                (
                    "card_with_explicit_capability",
                    {
                        "source": "project_state_card",
                        "checkpoint_id": state["card_id"],
                        "session_id": "unauthorized-session",
                        "project_id": "unauthorized-project",
                        "checkpoint_visibility_scope": "project",
                    },
                    {
                        "visibility_capability": {
                            "session_id": "allowed-session",
                            "project_id": None,
                        }
                    },
                    "UNAUTHORIZED-MANDATORY-CARD-MARKER",
                ),
                (
                    "scroll_with_implicit_session_capability",
                    {
                        "source": "scroll_event",
                        "checkpoint_id": event["event_id"],
                        "session_id": "unauthorized-session",
                        "project_id": "unauthorized-project",
                        "checkpoint_visibility_scope": "project",
                    },
                    {},
                    "UNAUTHORIZED-MANDATORY-SCROLL-MARKER",
                ),
            )
            for name, mandatory_checkpoint, extra_kwargs, marker in cases:
                with self.subTest(name=name):
                    result = compile_context(
                        root,
                        session_id="allowed-session",
                        token_budget=3000,
                        planner_profile="resume",
                        create=False,
                        mandatory_checkpoint=mandatory_checkpoint,
                        **extra_kwargs,
                    )

                    self.assertFalse(result["ok"], result)
                    self.assertFalse(result["mandatory_checkpoint_found"])
                    self.assertFalse(result["mandatory_checkpoint_fit"])
                    self.assertEqual(result["reason"], "checkpoint_missing")
                    self.assertNotIn(marker, result["context_text"])
                    self.assertNotIn(
                        mandatory_checkpoint["checkpoint_id"],
                        result["context_text"],
                    )

    def test_public_context_apis_reject_foreign_visibility_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="declared-session",
                agent_id="codex-sol",
                project_id="declared-project",
                objective="Declared recovery authority",
            )
            forged_capabilities = (
                (
                    "session_id",
                    {"session_id": "foreign-session", "project_id": None},
                ),
                (
                    "project_id",
                    {"session_id": None, "project_id": "foreign-project"},
                ),
            )
            for api_name in ("compile_context", "recover_thread"):
                for field, forged_capability in forged_capabilities:
                    with self.subTest(api=api_name, field=field):
                        with self.assertRaisesRegex(
                            ValueError,
                            rf"visibility_capability {field} must match",
                        ):
                            if api_name == "compile_context":
                                compile_context(
                                    root,
                                    session_id="declared-session",
                                    project_id="declared-project",
                                    token_budget=1000,
                                    planner_profile="resume",
                                    create=False,
                                    visibility_capability=forged_capability,
                                )
                            else:
                                recover_thread(
                                    root,
                                    session_id="declared-session",
                                    project_id="declared-project",
                                    token_budget=1000,
                                    planner_profile="resume",
                                    visibility_capability=forged_capability,
                                )
                with self.subTest(api=api_name, field="empty"):
                    with self.assertRaisesRegex(
                        ValueError,
                        "cannot remove all declared coordinates",
                    ):
                        if api_name == "compile_context":
                            compile_context(
                                root,
                                session_id="declared-session",
                                project_id="declared-project",
                                token_budget=1000,
                                planner_profile="resume",
                                create=False,
                                visibility_capability={
                                    "session_id": None,
                                    "project_id": None,
                                },
                            )
                        else:
                            recover_thread(
                                root,
                                session_id="declared-session",
                                project_id="declared-project",
                                token_budget=1000,
                                planner_profile="resume",
                                visibility_capability={
                                    "session_id": None,
                                    "project_id": None,
                                },
                            )
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_pins_lossless_checkpoint_ahead_of_crowded_windows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["context"]["scroll_event_fetch_limit"] = 2
            write_config(root, config)
            objective_tail = "PINNED-CHECKPOINT-OBJECTIVE-TAIL"
            state = record_project_state(
                root,
                session_id="crowded-session",
                agent_id="codex-sol",
                project_id="crowded-project",
                objective=(
                    "PINNED-CHECKPOINT-OBJECTIVE:"
                    + ("X" * 3200)
                    + objective_tail
                ),
                decisions=["PINNED-CHECKPOINT-DECISION"],
                open_tasks=["PINNED-CHECKPOINT-TASK"],
            )
            for index in range(3):
                append_scroll_event(
                    root,
                    session_id="crowded-session",
                    event_type="message",
                    role="user",
                    content=f"newer capped Scroll event {index}",
                    metadata={
                        "visibility_scope": "project",
                        "project_id": "crowded-project",
                    },
                )
            conn = connect(root)
            try:
                for index in range(90):
                    create_card(
                        conn,
                        root=root,
                        card_type="reference",
                        title=f"High-salience reference {index}",
                        summary=f"Crowded project reference {index}",
                        source_refs=[],
                        salience=1.0,
                        confidence=1.0,
                        visibility_scope="project",
                        session_id="crowded-session",
                        project_id="crowded-project",
                    )
                conn.commit()
            finally:
                conn.close()

            too_small = resume_latest(
                root,
                project_id="crowded-project",
                query="deliberately-unmatched-query",
                token_budget=700,
                model_assist=False,
            )

            self.assertFalse(too_small["ok"], too_small)
            self.assertEqual(too_small["reason"], "checkpoint_did_not_fit")
            self.assertGreater(too_small["minimum_checkpoint_tokens"], 700)
            self.assertFalse((root / "exports" / "thread_recovery").exists())

            result = resume_latest(
                root,
                project_id="crowded-project",
                query="deliberately-unmatched-query",
                token_budget=3000,
                model_assist=False,
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["discovery"]["checkpoint_id"], state["card_id"])
            self.assertTrue(result["context"]["mandatory_checkpoint_fit"])
            self.assertEqual(
                result["context"]["mandatory_checkpoint_id"],
                state["card_id"],
            )
            self.assertIn(state["card_id"], result["context"]["context_text"])
            self.assertIn(state["card_id"], result["packet_text"])
            self.assertIn(state["event_id"], result["context"]["context_text"])
            self.assertIn(objective_tail, result["context"]["context_text"])
            self.assertIn(objective_tail, result["packet_text"])
            self.assertIn("PINNED-CHECKPOINT-TASK", result["packet_text"])
            self.assertIn("PINNED-CHECKPOINT-DECISION", result["packet_text"])

    def test_resume_fails_closed_when_project_state_source_is_invalid(self) -> None:
        for mutation in (
            "missing",
            "session_mismatch",
            "project_mismatch",
            "scope_mismatch",
            "content_mismatch",
            "content_hash_mismatch",
            "non_project_large",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                state = record_project_state(
                    root,
                    session_id="source-check-session",
                    agent_id="codex-sol",
                    project_id="source-check-project",
                    objective="SOURCE-CHECKPOINT-MUST-FAIL-CLOSED",
                )
                conn = connect(root)
                try:
                    if mutation == "missing":
                        conn.execute(
                            "DELETE FROM scroll_events WHERE id = ?",
                            (state["event_id"],),
                        )
                    elif mutation == "session_mismatch":
                        conn.execute(
                            "UPDATE scroll_events SET session_id = ? WHERE id = ?",
                            ("other-source-session", state["event_id"]),
                        )
                    elif mutation == "project_mismatch":
                        conn.execute(
                            "UPDATE scroll_events SET project_id = ? WHERE id = ?",
                            ("other-source-project", state["event_id"]),
                        )
                    elif mutation == "scope_mismatch":
                        conn.execute(
                            """
                            UPDATE scroll_events
                            SET visibility_scope = 'session', project_id = NULL
                            WHERE id = ?
                            """,
                            (state["event_id"],),
                        )
                    elif mutation == "content_mismatch":
                        conn.execute(
                            "UPDATE scroll_events SET content = ? WHERE id = ?",
                            ("MUTATED-SOURCE-CONTENT", state["event_id"]),
                        )
                    elif mutation == "content_hash_mismatch":
                        conn.execute(
                            "UPDATE scroll_events SET content_hash = ? WHERE id = ?",
                            ("0" * 64, state["event_id"]),
                        )
                    else:
                        conn.execute(
                            """
                            UPDATE scroll_events
                            SET event_type = 'message', content = ?
                            WHERE id = ?
                            """,
                            ("x" * 100_000, state["event_id"]),
                        )
                    conn.commit()
                finally:
                    conn.close()

                result = resume_latest(
                    root,
                    project_id="source-check-project",
                    token_budget=3000,
                    model_assist=False,
                )

                self.assertFalse(result["ok"], result)
                expected_reason = (
                    "authority_corrupt"
                    if mutation in {"project_mismatch", "scope_mismatch"}
                    else (
                        "no_current_project_state"
                        if mutation in {"missing", "non_project_large"}
                        else "invalid_project_state_checkpoint"
                    )
                )
                self.assertEqual(result["reason"], expected_reason)
                if mutation in {"missing", "non_project_large"}:
                    serialized_result = json.dumps(result, sort_keys=True)
                    self.assertNotIn(state["card_id"], serialized_result)
                    self.assertNotIn(state["event_id"], serialized_result)
                    self.assertNotIn("invalid_checkpoint", result)
                    self.assertNotIn("repair_required", result)
                    self.assertNotIn("repair_command", result)
                self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_fails_closed_when_project_state_structured_payload_is_mutated(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            original_decisions = [
                f"ORIGINAL_DECISION_{index}" for index in range(25)
            ]
            original_tasks = [f"ORIGINAL_TASK_{index}" for index in range(25)]
            state = record_project_state(
                root,
                session_id="payload-binding-session",
                agent_id="codex-sol",
                project_id="payload-binding-project",
                objective="PROJECT-STATE-PAYLOAD-BINDING",
                decisions=original_decisions,
                open_tasks=original_tasks,
            )
            tampered_decisions = list(original_decisions)
            tampered_tasks = list(original_tasks)
            tampered_decisions[-1] = "TAMPERED_DECISION_OUTSIDE_RENDERED_WINDOW"
            tampered_tasks[-1] = "TAMPERED_TASK_OUTSIDE_RENDERED_WINDOW"
            conn = connect(root)
            try:
                conn.execute(
                    """
                    UPDATE cards
                    SET decisions_json = ?, open_tasks_json = ?
                    WHERE id = ?
                    """,
                    (
                        json.dumps(tampered_decisions),
                        json.dumps(tampered_tasks),
                        state["card_id"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            result = resume_latest(
                root,
                project_id="payload-binding-project",
                token_budget=3000,
                model_assist=False,
            )

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "invalid_project_state_checkpoint")
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_project_state_payload_marker_ignores_earlier_user_text_collision(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="payload-marker-session",
                agent_id="codex-sol",
                project_id="payload-marker-project",
                objective=(
                    "Normal objective\n"
                    "Continuum-State-Payload-SHA256: user-authored text"
                ),
                decisions=["KEEP_MARKER_COLLISION_DECISION"],
                open_tasks=["KEEP_MARKER_COLLISION_TASK"],
            )

            result = resume_latest(
                root,
                project_id="payload-marker-project",
                token_budget=3000,
                model_assist=False,
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["discovery"]["checkpoint_id"], state["card_id"])
            self.assertIn("KEEP_MARKER_COLLISION_DECISION", result["packet_text"])
            self.assertIn("KEEP_MARKER_COLLISION_TASK", result["packet_text"])

    def test_resume_fails_closed_when_checkpoint_source_is_rebound_within_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            old_state = record_project_state(
                root,
                session_id="rebound-source-session",
                agent_id="codex-sol",
                project_id="rebound-source-project",
                objective="OLD-SOURCE-EVENT-OBJECTIVE",
            )
            new_state = record_project_state(
                root,
                session_id="rebound-source-session",
                agent_id="codex-sol",
                project_id="rebound-source-project",
                objective="NEW-SELECTED-CARD-OBJECTIVE",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET source_refs_json = ? WHERE id = ?",
                    (
                        json.dumps(
                            [
                                {
                                    "event_id": old_state["event_id"],
                                    "session_id": "rebound-source-session",
                                    "seq": old_state["seq"],
                                }
                            ],
                            separators=(",", ":"),
                        ),
                        new_state["card_id"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            result = resume_latest(
                root,
                project_id="rebound-source-project",
                token_budget=3000,
                model_assist=False,
            )

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "invalid_project_state_checkpoint")
            self.assertEqual(
                result["invalid_checkpoint"]["checkpoint_id"],
                new_state["card_id"],
            )
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_resolves_legacy_project_state_source_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            objective_tail = "LEGACY-SOURCE-OBJECTIVE-TAIL"
            state = record_project_state(
                root,
                session_id="legacy-source-session",
                agent_id="codex-sol",
                project_id="legacy-source-project",
                objective=("X" * 1200) + objective_tail,
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET source_refs_json = ? WHERE id = ?",
                    (
                        json.dumps(
                            [
                                {
                                    "session_id": "legacy-source-session",
                                    "seq": state["seq"],
                                }
                            ],
                            separators=(",", ":"),
                        ),
                        state["card_id"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            result = resume_latest(
                root,
                project_id="legacy-source-project",
                token_budget=3000,
                model_assist=False,
            )

            self.assertTrue(result["ok"], result)
            self.assertIn(state["event_id"], result["context"]["context_text"])
            self.assertIn(objective_tail, result["packet_text"])

    def test_v021_official_source_orphan_is_detected_after_card_loss(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            session_id = "v021-orphan-session"
            project_id = "v021-orphan-project"
            agent_id = "v021-orphan-agent"
            content = "\n".join(
                [
                    f"Project state for {project_id}",
                    f"Agent: {agent_id}",
                    "Objective: V021 OFFICIAL SOURCE ORPHAN",
                ]
            )
            metadata = {
                "agent_id": agent_id,
                "project_id": project_id,
                "session_id": session_id,
                "source_type": "project_state",
                "trust_level": "agent_reported_local_evidence",
                "instruction_authority": "user_level_evidence",
                "visibility_scope": "project",
            }
            event = append_scroll_event(
                root,
                session_id=session_id,
                event_type="project_state",
                role="agent",
                content=content,
                metadata=metadata,
            )
            source_refs = [
                {
                    "event_id": event["event_id"],
                    "session_id": session_id,
                    "seq": event["seq"],
                }
            ]
            expected_card_id = store_module.stable_id(
                "card",
                "project",
                session_id,
                project_id,
                "project_state",
                f"{project_id} project state from {agent_id}",
                store_module.content_hash(
                    store_module.summarize_text(content, limit=900)
                ),
                store_module.json_dumps(source_refs),
            )
            conn = connect(root)
            try:
                conn.execute("BEGIN IMMEDIATE")
                enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_card_placement",
                    priority=70,
                    payload={
                        "card_id": expected_card_id,
                        "event_id": event["event_id"],
                        "session_id": session_id,
                        "project_id": project_id,
                        "visibility_scope": "project",
                    },
                    related_card_ids=[expected_card_id],
                    dedupe_key=f"card:{expected_card_id}",
                )
                conn.execute("DELETE FROM graph_edge_sources")
                conn.execute("DELETE FROM graph_edges")
                conn.execute("DELETE FROM graph_nodes")
                conn.commit()
            finally:
                conn.close()

            semantic = store_module.semantic_integrity_report(root)
            resumed = resume_latest(
                root,
                project_id=project_id,
                model_assist=False,
            )
            preview = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id=project_id,
                dry_run=True,
            )

            self.assertFalse(semantic["ok"], semantic)
            self.assertEqual(
                semantic["checks"]["orphan_project_state_source_events"],
                1,
            )
            self.assertFalse(resumed["ok"], resumed)
            self.assertEqual(resumed["reason"], "authority_corrupt")
            self.assertTrue(resumed["repair_required"])
            self.assertFalse(preview["ok"], preview)
            self.assertIn(
                "orphan_project_state_source_event",
                {
                    issue["type"]
                    for issue in preview["authority_topology_issues"]
                },
            )

    def test_v021_orphan_requires_exact_historical_placement_job_footprint(
        self,
    ) -> None:
        scenarios = (
            ("exact", True),
            ("wrong_role", False),
            ("raw_dedupe", False),
            ("extra_related_id", False),
            ("extra_payload_field", False),
            ("drifted_project", False),
        )
        for scenario, should_prove in scenarios:
            with self.subTest(
                scenario=scenario
            ), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                session_id = f"v021-footprint-{scenario}-session"
                project_id = "v021-footprint-project"
                agent_id = "v021-footprint-agent"
                content = "\n".join(
                    [
                        f"Project state for {project_id}",
                        f"Agent: {agent_id}",
                        f"Objective: V021 EXACT FOOTPRINT {scenario}",
                    ]
                )
                event = append_scroll_event(
                    root,
                    session_id=session_id,
                    event_type="project_state",
                    role="agent",
                    content=content,
                    metadata={
                        "agent_id": agent_id,
                        "project_id": project_id,
                        "session_id": session_id,
                        "source_type": "project_state",
                        "trust_level": "agent_reported_local_evidence",
                        "instruction_authority": "user_level_evidence",
                        "visibility_scope": "project",
                    },
                )
                source_refs = [
                    {
                        "event_id": event["event_id"],
                        "session_id": session_id,
                        "seq": event["seq"],
                    }
                ]
                expected_card_id = store_module.stable_id(
                    "card",
                    "project",
                    session_id,
                    project_id,
                    "project_state",
                    f"{project_id} project state from {agent_id}",
                    store_module.content_hash(
                        store_module.summarize_text(content, limit=900)
                    ),
                    store_module.json_dumps(source_refs),
                )
                conn = connect(root)
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    enqueue_job(
                        conn,
                        role="librarian",
                        job_type="review_card_placement",
                        priority=70,
                        payload={
                            "card_id": expected_card_id,
                            "event_id": event["event_id"],
                            "session_id": session_id,
                            "project_id": project_id,
                            "visibility_scope": "project",
                        },
                        related_card_ids=[expected_card_id],
                        dedupe_key=f"card:{expected_card_id}",
                    )
                    expected_dedupe = "queue_v1_" + store_module.content_hash(
                        store_module.json_dumps(
                            [
                                "librarian",
                                "review_card_placement",
                                f"card:{expected_card_id}",
                            ]
                        )
                    )
                    stored_dedupe = str(
                        conn.execute(
                            "SELECT dedupe_key FROM queue_jobs "
                            "WHERE job_type = 'review_card_placement'"
                        ).fetchone()[0]
                    )
                    self.assertEqual(stored_dedupe, expected_dedupe)
                    if scenario == "wrong_role":
                        conn.execute(
                            "UPDATE queue_jobs SET role = 'scribe' "
                            "WHERE job_type = 'review_card_placement'"
                        )
                    elif scenario == "raw_dedupe":
                        conn.execute(
                            "UPDATE queue_jobs SET dedupe_key = ? "
                            "WHERE job_type = 'review_card_placement'",
                            (f"card:{expected_card_id}",),
                        )
                    elif scenario == "extra_related_id":
                        conn.execute(
                            "UPDATE queue_jobs SET related_card_ids_json = ? "
                            "WHERE job_type = 'review_card_placement'",
                            (
                                store_module.json_dumps(
                                    [expected_card_id, "unexpected-card"]
                                ),
                            ),
                        )
                    elif scenario == "extra_payload_field":
                        conn.execute(
                            "UPDATE queue_jobs SET payload_json = "
                            "json_set(payload_json, '$.unexpected', 'extra') "
                            "WHERE job_type = 'review_card_placement'"
                        )
                    elif scenario == "drifted_project":
                        conn.execute(
                            "UPDATE queue_jobs SET payload_json = "
                            "json_set(payload_json, '$.project_id', 'other-project') "
                            "WHERE job_type = 'review_card_placement'"
                        )
                    conn.execute("DELETE FROM graph_edge_sources")
                    conn.execute("DELETE FROM graph_edges")
                    conn.execute("DELETE FROM graph_nodes")
                    conn.commit()
                finally:
                    conn.close()

                semantic = store_module.semantic_integrity_report(root)

                self.assertEqual(
                    semantic["checks"]["orphan_project_state_source_events"],
                    int(should_prove),
                    semantic,
                )
                self.assertEqual(semantic["ok"], not should_prove, semantic)

    def test_resume_pins_selected_scroll_checkpoint_beyond_the_fetch_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["context"]["scroll_event_fetch_limit"] = 2
            write_config(root, config)
            checkpoint = append_scroll_event(
                root,
                session_id="saturated-scroll-session",
                event_type="message",
                role="user",
                content="SATURATED-SCROLL-SELECTED-CHECKPOINT",
                metadata={"visibility_scope": "session"},
            )
            for index in range(3):
                append_scroll_event(
                    root,
                    session_id="saturated-scroll-session",
                    event_type="message",
                    role="user",
                    content=f"newer capped Scroll event {index}",
                    metadata={"visibility_scope": "session"},
                )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE scroll_events SET created_at = ? WHERE id = ?",
                    ("2099-01-01T00:00:00+00:00", checkpoint["event_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            result = resume_latest(
                root,
                session_id="saturated-scroll-session",
                query="deliberately-unmatched-query",
                token_budget=3000,
                model_assist=False,
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["discovery"]["source"], "scroll_event")
            self.assertEqual(
                result["discovery"]["checkpoint_id"],
                checkpoint["event_id"],
            )
            self.assertTrue(result["context"]["mandatory_checkpoint_fit"])
            self.assertIn(checkpoint["event_id"], result["context"]["context_text"])
            self.assertIn(
                "SATURATED-SCROLL-SELECTED-CHECKPOINT",
                result["context"]["context_text"],
            )
            self.assertIn(checkpoint["event_id"], result["packet_text"])

    def test_resume_fails_closed_when_selected_scroll_checkpoint_is_corrupted(
        self,
    ) -> None:
        for mutation in ("content", "content_hash", "sequence"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                checkpoint = append_scroll_event(
                    root,
                    session_id="corrupt-scroll-session",
                    event_type="message",
                    role="user",
                    content="IMMUTABLE-SELECTED-SCROLL-CHECKPOINT",
                    metadata={"visibility_scope": "session"},
                )
                conn = connect(root)
                try:
                    if mutation == "content":
                        conn.execute(
                            "UPDATE scroll_events SET content = ? WHERE id = ?",
                            ("MUTATED-SELECTED-SCROLL-CONTENT", checkpoint["event_id"]),
                        )
                    elif mutation == "content_hash":
                        conn.execute(
                            "UPDATE scroll_events SET content_hash = ? WHERE id = ?",
                            ("0" * 64, checkpoint["event_id"]),
                        )
                    else:
                        conn.execute(
                            "UPDATE scroll_events SET seq = ? WHERE id = ?",
                            ("not-a-sequence", checkpoint["event_id"]),
                        )
                    conn.commit()
                finally:
                    conn.close()

                result = resume_latest(
                    root,
                    session_id="corrupt-scroll-session",
                    token_budget=3000,
                    model_assist=False,
                )

                self.assertFalse(result["ok"], result)
                self.assertEqual(
                    result["reason"],
                    "checkpoint_changed_during_resume",
                )
                self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_does_not_succeed_with_an_id_only_checkpoint_stub(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["context"]["default_token_budget"] = 300
            config["context"]["max_token_budget"] = 300
            config["personal_profile"]["safe_context_ceiling"] = 300
            write_config(root, config)
            record_project_state(
                root,
                session_id="complete-minimum-session",
                agent_id="codex-sol",
                project_id="complete-minimum-project",
                objective="REQUIRED-CHECKPOINT-STATE:" + ("x" * 4000),
                decisions=["REQUIRED-CHECKPOINT-DECISION"],
                open_tasks=["REQUIRED-CHECKPOINT-TASK"],
            )

            result = resume_latest(
                root,
                project_id="complete-minimum-project",
                token_budget=300,
                model_assist=False,
            )

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "checkpoint_did_not_fit")
            self.assertEqual(result["packet_token_budget"], 300)
            self.assertGreater(result["minimum_checkpoint_tokens"], 300)
            self.assertGreater(result["minimum_packet_tokens"], 300)
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_reports_when_checkpoint_cannot_fit_a_supported_small_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["context"]["default_token_budget"] = 100
            config["context"]["max_token_budget"] = 100
            config["personal_profile"]["safe_context_ceiling"] = 100
            write_config(root, config)
            record_project_state(
                root,
                session_id="small-budget-session",
                agent_id="codex-sol",
                project_id="small-budget-project",
                objective="Keep the complete packet within the configured ceiling",
            )

            result = resume_latest(root, project_id="small-budget-project", token_budget=1000)

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "checkpoint_did_not_fit")
            self.assertEqual(result["packet_token_budget"], 100)
            self.assertGreater(result["minimum_checkpoint_tokens"], 0)
            self.assertGreater(result["minimum_packet_tokens"], 100)
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_reports_checkpoint_did_not_fit_at_one_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["context"]["default_token_budget"] = 1
            config["context"]["max_token_budget"] = 1
            config["personal_profile"]["safe_context_ceiling"] = 1
            write_config(root, config)
            record_project_state(
                root,
                session_id="tiny-session",
                agent_id="codex-sol",
                project_id="tiny-project",
                objective="Do not emit malformed recovery markup",
            )

            result = resume_latest(root, model_assist=False)

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "checkpoint_did_not_fit")
            self.assertEqual(result["packet_token_budget"], 1)
            self.assertGreater(result["minimum_checkpoint_tokens"], 1)
            self.assertGreater(result["minimum_packet_tokens"], 1)
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_planner_balances_sources_and_respects_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="planner-session",
                agent_id="codex-sol",
                project_id="planner-project",
                objective="Planner evidence",
                decisions=["Use source citations"],
            )

            packet = compile_context(
                root,
                session_id="planner-session",
                project_id="planner-project",
                query="source citations",
                token_budget=500,
                planner_profile="resume",
                create=False,
            )

            self.assertTrue(packet["ok"], packet)
            self.assertEqual(packet["planner_profile"], "resume")
            self.assertLessEqual(packet["estimated_tokens"], 500)
            self.assertTrue(packet["planner_trace"])
            self.assertTrue(packet["sections"])

    def test_resume_planner_ranks_query_score_before_card_candidate_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                target_card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="zirconium lattice target",
                    summary="The two-term target should outrank one-term noise.",
                    source_refs=[],
                    visibility_scope="session",
                    session_id="query-ranking-session",
                    salience=0.3,
                    confidence=0.3,
                )
                for index in range(90):
                    create_card(
                        conn,
                        root=root,
                        card_type="note",
                        title=f"zirconium noise {index}",
                        summary="A one-term candidate with slightly higher salience.",
                        source_refs=[],
                        visibility_scope="session",
                        session_id="query-ranking-session",
                        salience=0.4,
                        confidence=0.4,
                    )
                conn.commit()
            finally:
                conn.close()

            packet = compile_context(
                root,
                session_id="query-ranking-session",
                query="zirconium lattice",
                token_budget=2000,
                planner_profile="resume",
                create=False,
            )

            current_cards = next(
                section
                for section in packet["sections"]
                if section["kind"] == "current_cards"
            )
            self.assertEqual(current_cards["ids"][0], target_card_id)

    def test_resume_prioritizes_query_cue_under_tight_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            session_id = "query-budget-session"
            project_id = "query-budget-project"
            record_project_state(
                root,
                session_id=session_id,
                agent_id="codex-sol",
                project_id=project_id,
                objective="Initial release state",
            )
            append_scroll_event(
                root,
                session_id=session_id,
                event_type="message",
                role="user",
                content=(
                    "ZIRCONIUM-CUE-TARGET preserves the buried lattice evidence."
                ),
                metadata={
                    "visibility_scope": "project",
                    "project_id": project_id,
                },
            )
            for index in range(110):
                append_scroll_event(
                    root,
                    session_id=session_id,
                    event_type="message",
                    role="user",
                    content=f"ordinary unrelated scroll noise {index}",
                    metadata={
                        "visibility_scope": "project",
                        "project_id": project_id,
                    },
                )
            record_project_state(
                root,
                session_id=session_id,
                agent_id="codex-sol",
                project_id=project_id,
                objective="Continue local release verification",
                open_tasks=["finish deterministic gates"],
            )
            conn = connect(root)
            try:
                create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="High salience unrelated card",
                    summary="ordinary filler " * 1200,
                    source_refs=[],
                    visibility_scope="project",
                    session_id=session_id,
                    project_id=project_id,
                    salience=1.0,
                    confidence=1.0,
                )
                conn.commit()
            finally:
                conn.close()

            resumed = resume_latest(
                root,
                session_id=session_id,
                project_id=project_id,
                query="zirconium lattice evidence",
                token_budget=900,
                model_assist=False,
            )

            self.assertTrue(resumed["ok"], resumed)
            self.assertIn("ZIRCONIUM-CUE-TARGET", resumed["packet_text"])
            optional_inclusions = [
                item
                for item in resumed["context"]["planner_trace"]
                if item.get("included") and not item.get("mandatory")
            ]
            self.assertEqual(optional_inclusions[0]["source"], "cue_recall")

    def test_resume_planner_respects_configured_scroll_fetch_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["context"]["scroll_event_fetch_limit"] = 2
            write_config(root, config)
            for index in range(10):
                append_scroll_event(
                    root,
                    session_id="fetch-cap-session",
                    event_type="message",
                    role="user",
                    content=f"fetch-cap-event-{index}",
                    metadata={"visibility_scope": "session"},
                )

            packet = compile_context(
                root,
                session_id="fetch-cap-session",
                token_budget=6000,
                planner_profile="resume",
                create=False,
            )

            recent = next(
                section
                for section in packet["sections"]
                if section["kind"] == "recent_scroll"
            )
            self.assertEqual(
                recent["ids"],
                ["scroll:fetch-cap-session:10", "scroll:fetch-cap-session:9"],
            )

    def test_sequential_project_state_remains_resumable_but_cross_agent_disagreement_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="checkpoint-one",
                agent_id="codex-sol",
                project_id="checkpoint-project",
                objective="Continue the release",
                open_tasks=["run focused tests"],
            )
            record_project_state(
                root,
                session_id="checkpoint-two",
                agent_id="codex-sol",
                project_id="checkpoint-project",
                objective="Continue the release",
                open_tasks=["run the full suite"],
            )

            detected = detect_conflicts(root)
            resumed = resume_latest(
                root,
                project_id="checkpoint-project",
                model_assist=False,
            )

            self.assertEqual(detected["conflict_count"], 0, detected)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["session_id"], "checkpoint-two")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="agent-a-session",
                agent_id="agent-a",
                project_id="shared-project",
                objective="Use alpha routing for deployment",
            )
            record_project_state(
                root,
                session_id="agent-b-session",
                agent_id="agent-b",
                project_id="shared-project",
                objective="Do not use alpha routing for deployment",
            )

            detected = detect_conflicts(root)

            self.assertEqual(detected["conflict_count"], 1, detected)

    def test_immediate_cross_agent_project_heads_fail_closed_until_resolved(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="agent-a-session",
                agent_id="agent-a",
                project_id="shared-project",
                objective="Prepare deployment routing",
                decisions=["Use alpha routing for deployment"],
            )
            second = record_project_state(
                root,
                session_id="agent-b-session",
                agent_id="agent-b",
                project_id="shared-project",
                objective="Prepare deployment routing",
                decisions=["Do not use alpha routing for deployment"],
            )

            ambiguous = resume_latest(
                root,
                project_id="shared-project",
                model_assist=False,
            )

            self.assertFalse(ambiguous["ok"], ambiguous)
            self.assertEqual(ambiguous["reason"], "authority_ambiguous")
            self.assertTrue(ambiguous["resolution_required"])
            details = ambiguous["authority_ambiguity"]
            self.assertEqual(
                details["boundary"],
                {
                    "visibility_scope": "project",
                    "project_id": "shared-project",
                    "session_id": None,
                },
            )
            self.assertEqual(
                set(details["current_head_ids"]),
                {first["card_id"], second["card_id"]},
            )
            self.assertEqual(details["head_count_at_least"], 2)
            self.assertEqual(
                details["head_list_limit"],
                store_module.PROJECT_STATE_AUTHORITY_BOUNDARY_SCAN_LIMIT,
            )
            self.assertFalse((root / "exports" / "thread_recovery").exists())

            detected = detect_conflicts(root)
            self.assertEqual(detected["conflict_count"], 1, detected)
            grouped_ambiguous = resume_latest(
                root,
                project_id="shared-project",
                model_assist=False,
            )
            self.assertFalse(grouped_ambiguous["ok"], grouped_ambiguous)
            self.assertEqual(
                grouped_ambiguous["reason"],
                "authority_ambiguous",
            )
            self.assertEqual(
                set(
                    grouped_ambiguous["authority_ambiguity"][
                        "contested_head_ids"
                    ]
                ),
                {first["card_id"], second["card_id"]},
            )
            conn = connect(root)
            try:
                before_event_count = int(
                    conn.execute(
                        "SELECT count(*) FROM scroll_events"
                    ).fetchone()[0]
                )
            finally:
                conn.close()
            with self.assertRaisesRegex(ValueError, "unresolved conflict"):
                record_project_state(
                    root,
                    session_id="agent-a-follow-up",
                    agent_id="agent-a",
                    project_id="shared-project",
                    objective="Advance without resolving the disagreement",
                )
            conn = connect(root)
            try:
                self.assertEqual(
                    int(
                        conn.execute(
                            "SELECT count(*) FROM scroll_events"
                        ).fetchone()[0]
                    ),
                    before_event_count,
                )
            finally:
                conn.close()
            resolved = resolve_conflict(
                root,
                card_id=second["card_id"],
                action="supersede",
            )
            self.assertTrue(resolved["ok"], resolved)

            resumed = resume_latest(
                root,
                project_id="shared-project",
                model_assist=False,
            )

            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                second["card_id"],
            )

    def test_compatible_independent_heads_require_complete_explicit_resolution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="compatible-agent-a",
                agent_id="agent-a",
                project_id="compatible-project",
                objective="Prepare release notes",
            )
            second = record_project_state(
                root,
                session_id="compatible-agent-b",
                agent_id="agent-b",
                project_id="compatible-project",
                objective="Prepare package metadata",
            )
            winner = record_project_state(
                root,
                session_id="compatible-agent-c",
                agent_id="agent-c",
                project_id="compatible-project",
                objective="Prepare final review bundle",
            )
            outside = record_project_state(
                root,
                session_id="outside-agent",
                agent_id="outside-agent",
                project_id="outside-project",
                objective="Prepare an unrelated project",
            )

            detected = detect_conflicts(root, card_id=winner["card_id"])
            ambiguous = resume_latest(
                root,
                project_id="compatible-project",
                model_assist=False,
            )

            self.assertEqual(detected["conflict_count"], 0, detected)
            self.assertFalse(ambiguous["ok"], ambiguous)
            self.assertEqual(ambiguous["reason"], "authority_ambiguous")
            with self.assertRaisesRegex(ValueError, "card is not contested"):
                resolve_conflict(
                    root,
                    card_id=winner["card_id"],
                    action="dismiss",
                    superseded_card_ids=[first["card_id"], second["card_id"]],
                )
            with self.assertRaisesRegex(
                ValueError,
                "explicit confirmation",
            ) as missing_confirmation:
                resolve_conflict(root, card_id=winner["card_id"])
            self.assertIn(first["card_id"], str(missing_confirmation.exception))
            self.assertIn(second["card_id"], str(missing_confirmation.exception))
            with self.assertRaisesRegex(ValueError, "whole project-state boundary"):
                resolve_conflict(
                    root,
                    card_id=winner["card_id"],
                    superseded_card_ids=[first["card_id"]],
                )
            with self.assertRaisesRegex(ValueError, "selected boundary"):
                resolve_conflict(
                    root,
                    card_id=winner["card_id"],
                    superseded_card_ids=[
                        first["card_id"],
                        second["card_id"],
                        outside["card_id"],
                    ],
                )

            resolved = resolve_conflict(
                root,
                card_id=winner["card_id"],
                superseded_card_ids=[first["card_id"], second["card_id"]],
            )
            resumed = resume_latest(
                root,
                project_id="compatible-project",
                model_assist=False,
            )

            self.assertTrue(resolved["ok"], resolved)
            self.assertEqual(
                resolved["resolution_scope"],
                "project_state_authority_boundary",
            )
            self.assertEqual(
                set(resolved["resolved_peer_ids"]),
                {first["card_id"], second["card_id"]},
            )
            semantic = store_module.semantic_integrity_report(root)
            self.assertTrue(semantic["ok"], semantic)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                winner["card_id"],
            )

    def test_grouped_project_state_resolution_requires_every_boundary_head(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="grouped-agent-a",
                agent_id="agent-a",
                project_id="grouped-project",
                objective="Prepare deployment routing",
                decisions=["Use alpha routing"],
            )
            winner = record_project_state(
                root,
                session_id="grouped-agent-b",
                agent_id="agent-b",
                project_id="grouped-project",
                objective="Prepare deployment routing",
                decisions=["Do not use alpha routing"],
            )
            detected = detect_conflicts(root)
            self.assertEqual(detected["conflict_count"], 1, detected)
            independent = record_project_state(
                root,
                session_id="grouped-agent-c",
                agent_id="agent-c",
                project_id="grouped-project",
                objective="Prepare release documentation",
            )

            with self.assertRaisesRegex(ValueError, "explicit confirmation"):
                resolve_conflict(root, card_id=winner["card_id"])
            with self.assertRaisesRegex(ValueError, "whole project-state boundary"):
                resolve_conflict(
                    root,
                    card_id=winner["card_id"],
                    superseded_card_ids=[first["card_id"]],
                )

            resolved = resolve_conflict(
                root,
                card_id=winner["card_id"],
                superseded_card_ids=[first["card_id"], independent["card_id"]],
            )
            resumed = resume_latest(
                root,
                project_id="grouped-project",
                model_assist=False,
            )

            self.assertEqual(
                resolved["resolution_scope"],
                "project_state_authority_boundary",
            )
            self.assertTrue(store_module.semantic_integrity_report(root)["ok"])
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                winner["card_id"],
            )

    def test_explicit_authority_resolution_rejects_intersecting_group(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="intersecting-agent-a",
                agent_id="agent-a",
                project_id="intersecting-project",
                objective="Prepare release notes",
            )
            winner = record_project_state(
                root,
                session_id="intersecting-agent-b",
                agent_id="agent-b",
                project_id="intersecting-project",
                objective="Prepare final review bundle",
            )
            conn = connect(root)
            try:
                note_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="Unrelated project note",
                    summary="Evidence that is not project-state authority.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="intersecting-note",
                    project_id="intersecting-project",
                )
                conn.execute(
                    "UPDATE cards SET conflict_group = 'legacy-mixed-group' "
                    "WHERE id IN (?, ?)",
                    (first["card_id"], note_id),
                )
                conn.commit()
            finally:
                conn.close()

            with self.assertRaisesRegex(ValueError, "incomplete conflict group"):
                resolve_conflict(
                    root,
                    card_id=winner["card_id"],
                    superseded_card_ids=[first["card_id"]],
                )

            conn = connect(root)
            try:
                rows = {
                    str(row["id"]): row
                    for row in conn.execute(
                        "SELECT id, conflict_group, superseded_by_card_id "
                        "FROM cards WHERE id IN (?, ?, ?)",
                        (first["card_id"], winner["card_id"], note_id),
                    )
                }
            finally:
                conn.close()
            self.assertEqual(
                rows[first["card_id"]]["conflict_group"],
                "legacy-mixed-group",
            )
            self.assertEqual(rows[note_id]["conflict_group"], "legacy-mixed-group")
            self.assertIsNone(rows[first["card_id"]]["superseded_by_card_id"])
            self.assertIsNone(rows[winner["card_id"]]["superseded_by_card_id"])

    def test_explicit_authority_resolution_rejects_invalid_project_state(
        self,
    ) -> None:
        for tampered_member in ("peer", "winner"):
            with self.subTest(tampered_member=tampered_member):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp) / "continuum"
                    peer = record_project_state(
                        root,
                        session_id="invalid-agent-a",
                        agent_id="agent-a",
                        project_id="invalid-resolution-project",
                        objective="Prepare release notes",
                    )
                    winner = record_project_state(
                        root,
                        session_id="invalid-agent-b",
                        agent_id="agent-b",
                        project_id="invalid-resolution-project",
                        objective="Prepare final review bundle",
                    )
                    target_id = (
                        peer["card_id"]
                        if tampered_member == "peer"
                        else winner["card_id"]
                    )
                    conn = connect(root)
                    try:
                        conn.execute(
                            "UPDATE cards SET summary = 'tampered' WHERE id = ?",
                            (target_id,),
                        )
                        conn.commit()
                    finally:
                        conn.close()

                    with self.assertRaisesRegex(
                        ValueError,
                        "failed integrity validation",
                    ):
                        resolve_conflict(
                            root,
                            card_id=winner["card_id"],
                            superseded_card_ids=[peer["card_id"]],
                        )

                    conn = connect(root)
                    try:
                        rows = {
                            str(row["id"]): row
                            for row in conn.execute(
                                "SELECT id, supersedes_card_id, "
                                "superseded_by_card_id FROM cards "
                                "WHERE id IN (?, ?)",
                                (peer["card_id"], winner["card_id"]),
                            )
                        }
                    finally:
                        conn.close()
                    self.assertIsNone(
                        rows[peer["card_id"]]["superseded_by_card_id"]
                    )
                    self.assertIsNone(
                        rows[winner["card_id"]]["supersedes_card_id"]
                    )

    def test_explicit_session_authority_resolution_stays_in_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="shared-authority-session",
                agent_id="agent-a",
                project_id="session-authority-project",
                objective="Prepare release notes",
                metadata={"visibility_scope": "session"},
            )
            winner = record_project_state(
                root,
                session_id="shared-authority-session",
                agent_id="agent-b",
                project_id="session-authority-project",
                objective="Prepare final review bundle",
                metadata={"visibility_scope": "session"},
            )
            outside = record_project_state(
                root,
                session_id="outside-authority-session",
                agent_id="agent-c",
                project_id="session-authority-project",
                objective="Continue an independent session",
                metadata={"visibility_scope": "session"},
            )

            ambiguous = resume_latest(
                root,
                session_id="shared-authority-session",
                model_assist=False,
            )
            self.assertFalse(ambiguous["ok"], ambiguous)
            self.assertEqual(ambiguous["reason"], "authority_ambiguous")
            with self.assertRaisesRegex(ValueError, "selected boundary"):
                resolve_conflict(
                    root,
                    card_id=winner["card_id"],
                    superseded_card_ids=[first["card_id"], outside["card_id"]],
                )

            resolved = resolve_conflict(
                root,
                card_id=winner["card_id"],
                superseded_card_ids=[first["card_id"]],
            )
            shared = resume_latest(
                root,
                session_id="shared-authority-session",
                model_assist=False,
            )
            separate = resume_latest(
                root,
                session_id="outside-authority-session",
                model_assist=False,
            )

            self.assertTrue(resolved["ok"], resolved)
            self.assertTrue(shared["ok"], shared)
            self.assertEqual(
                shared["discovery"]["checkpoint_id"],
                winner["card_id"],
            )
            self.assertTrue(separate["ok"], separate)
            self.assertEqual(
                separate["discovery"]["checkpoint_id"],
                outside["card_id"],
            )

    def test_immediate_cross_agent_session_heads_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="shared-session",
                agent_id="agent-a",
                project_id="session-project",
                decisions=["Use alpha routing for deployment"],
                metadata={"visibility_scope": "session"},
            )
            second = record_project_state(
                root,
                session_id="shared-session",
                agent_id="agent-b",
                project_id="session-project",
                decisions=["Do not use alpha routing for deployment"],
                metadata={"visibility_scope": "session"},
            )

            ambiguous = resume_latest(
                root,
                session_id="shared-session",
                model_assist=False,
            )

            self.assertFalse(ambiguous["ok"], ambiguous)
            self.assertEqual(ambiguous["reason"], "authority_ambiguous")
            details = ambiguous["authority_ambiguity"]
            self.assertEqual(
                details["boundary"],
                {
                    "visibility_scope": "session",
                    "project_id": "session-project",
                    "session_id": "shared-session",
                },
            )
            self.assertEqual(
                set(details["current_head_ids"]),
                {first["card_id"], second["card_id"]},
            )
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_boundary_page_size_does_not_truncate_corruption_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            invalid_head_ids = []
            for index in range(64):
                state = record_project_state(
                    root,
                    session_id=f"overflow-session-{index}",
                    agent_id=f"overflow-agent-{index}",
                    project_id="overflow-project",
                    objective=f"Historical independent state {index}",
                )
                invalid_head_ids.append(state["card_id"])
            record_project_state(
                root,
                session_id="overflow-selected-session",
                agent_id="overflow-selected-agent",
                project_id="overflow-project",
                objective="VALID OVERFLOW SELECTED CHECKPOINT",
            )
            conn = connect(root)
            try:
                placeholders = ", ".join("?" for _ in invalid_head_ids)
                conn.execute(
                    f"UPDATE cards SET summary = 'invalid' "
                    f"WHERE id IN ({placeholders})",
                    tuple(invalid_head_ids),
                )
                conn.commit()
            finally:
                conn.close()

            with patch.object(
                store_module,
                "PROJECT_STATE_AUTHORITY_BOUNDARY_SCAN_LIMIT",
                64,
            ):
                ambiguous = resume_latest(
                    root,
                    project_id="overflow-project",
                    model_assist=False,
                )

            self.assertFalse(ambiguous["ok"], ambiguous)
            self.assertEqual(ambiguous["reason"], "authority_corrupt")
            details = ambiguous["authority_corruption"]
            self.assertIsNone(details["boundary_scan_limit"])
            self.assertEqual(details["boundary_scan_page_size"], 64)
            self.assertFalse(details["boundary_scan_overflow"])
            self.assertEqual(details["invalid_checkpoint_count"], 64)
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_invalid_selected_cross_agent_head_precedes_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="valid-older-session",
                agent_id="valid-older-agent",
                project_id="invalid-selected-project",
                objective="VALID OLDER CHECKPOINT",
            )
            invalid = record_project_state(
                root,
                session_id="invalid-newer-session",
                agent_id="invalid-newer-agent",
                project_id="invalid-selected-project",
                objective="INVALID NEWER CHECKPOINT",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = 'invalid' WHERE id = ?",
                    (invalid["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()

            resumed = resume_latest(
                root,
                project_id="invalid-selected-project",
                model_assist=False,
            )

            self.assertFalse(resumed["ok"], resumed)
            self.assertEqual(resumed["reason"], "invalid_project_state_checkpoint")
            self.assertEqual(
                resumed["invalid_checkpoint"]["checkpoint_id"],
                invalid["card_id"],
            )
            self.assertNotIn("authority_ambiguity", resumed)
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_invalid_older_independent_head_blocks_resume_and_repair_finds_it(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            invalid_older = record_project_state(
                root,
                session_id="invalid-older-session",
                agent_id="invalid-older-agent",
                project_id="complete-boundary-project",
                objective="INVALID OLDER AUTHORITY",
            )
            valid_newer = record_project_state(
                root,
                session_id="valid-newer-session",
                agent_id="valid-newer-agent",
                project_id="complete-boundary-project",
                objective="VALID NEWER AUTHORITY",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = summary || ' damaged' WHERE id = ?",
                    (invalid_older["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [invalid_older["card_id"]])

            blocked = resume_latest(
                root,
                project_id="complete-boundary-project",
                model_assist=False,
            )
            preview = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="complete-boundary-project",
                dry_run=True,
            )
            repaired = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="complete-boundary-project",
                dry_run=False,
            )
            resumed = resume_latest(
                root,
                project_id="complete-boundary-project",
                model_assist=False,
            )

            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "authority_corrupt")
            self.assertEqual(preview["quarantined_count"], 1)
            self.assertTrue(repaired["ok"], repaired)
            self.assertEqual(repaired["quarantined_count"], 1)
            self.assertTrue(store_module.semantic_integrity_report(root)["ok"])
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                valid_newer["card_id"],
            )

    def test_asymmetric_pointer_blocks_resume_and_repair_without_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="asymmetric-a",
                agent_id="agent-a",
                project_id="asymmetric-project",
                objective="FIRST INDEPENDENT AUTHORITY",
            )
            second = record_project_state(
                root,
                session_id="asymmetric-b",
                agent_id="agent-b",
                project_id="asymmetric-project",
                objective="SECOND INDEPENDENT AUTHORITY",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET superseded_by_card_id = ? WHERE id = ?",
                    (second["card_id"], first["card_id"]),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [first["card_id"]])
            conn = connect(root)
            try:
                before = [
                    tuple(row)
                    for row in conn.execute(
                        """
                        SELECT id, supersedes_card_id, superseded_by_card_id
                        FROM cards WHERE id IN (?, ?) ORDER BY id
                        """,
                        (first["card_id"], second["card_id"]),
                    ).fetchall()
                ]
            finally:
                conn.close()

            blocked = resume_latest(
                root,
                project_id="asymmetric-project",
                model_assist=False,
            )
            preview = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="asymmetric-project",
                dry_run=True,
            )
            applied = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="asymmetric-project",
                dry_run=False,
            )
            conn = connect(root)
            try:
                after = [
                    tuple(row)
                    for row in conn.execute(
                        """
                        SELECT id, supersedes_card_id, superseded_by_card_id
                        FROM cards WHERE id IN (?, ?) ORDER BY id
                        """,
                        (first["card_id"], second["card_id"]),
                    ).fetchall()
                ]
            finally:
                conn.close()

            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "authority_corrupt")
            self.assertIn(
                "supersession_asymmetric_link",
                {
                    issue["type"]
                    for issue in blocked["authority_corruption"][
                        "topology_issues"
                    ]
                },
            )
            self.assertFalse(preview["ok"], preview)
            self.assertFalse(applied["ok"], applied)
            self.assertEqual(applied["quarantined_count"], 0)
            self.assertEqual(before, after)

    def test_repair_detaches_a_valid_successor_from_an_invalid_older_predecessor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            invalid_older = record_project_state(
                root,
                session_id="chain-older-session",
                agent_id="chain-agent",
                project_id="invalid-predecessor-project",
                objective="OLDER CHAIN AUTHORITY",
            )
            valid_newer = record_project_state(
                root,
                session_id="chain-newer-session",
                agent_id="chain-agent",
                project_id="invalid-predecessor-project",
                objective="VALID NEWER CHAIN AUTHORITY",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = summary || ' damaged' WHERE id = ?",
                    (invalid_older["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [invalid_older["card_id"]])

            blocked = resume_latest(
                root,
                project_id="invalid-predecessor-project",
                model_assist=False,
            )
            repaired = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="invalid-predecessor-project",
                dry_run=False,
            )
            conn = connect(root)
            try:
                newer_row = conn.execute(
                    "SELECT supersedes_card_id FROM cards WHERE id = ?",
                    (valid_newer["card_id"],),
                ).fetchone()
            finally:
                conn.close()
            resumed = resume_latest(
                root,
                project_id="invalid-predecessor-project",
                model_assist=False,
            )

            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "authority_corrupt")
            self.assertTrue(repaired["ok"], repaired)
            self.assertEqual(repaired["quarantined_count"], 1)
            self.assertIsNone(newer_row["supersedes_card_id"])
            self.assertTrue(store_module.semantic_integrity_report(root)["ok"])
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                valid_newer["card_id"],
            )

    def test_resume_fails_closed_for_partial_resolution_receipt_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="partial-receipt-session",
                agent_id="partial-receipt-agent",
                project_id="partial-receipt-project",
                objective="VALID AUTHORITY WITH PARTIAL RECEIPT SCHEMA",
            )
            conn = connect(root)
            try:
                conn.execute("DROP TABLE conflict_resolution_members")
                conn.commit()
            finally:
                conn.close()

            resumed = resume_latest(
                root,
                project_id="partial-receipt-project",
                model_assist=False,
            )

            self.assertFalse(resumed["ok"], resumed)
            self.assertEqual(resumed["reason"], "authority_corrupt")
            self.assertIn(
                "incomplete_conflict_resolution_receipt_schema",
                {
                    issue["type"]
                    for issue in resumed["authority_corruption"][
                        "topology_issues"
                    ]
                },
            )
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_source_bound_project_membership_exposes_card_boundary_drift(
        self,
    ) -> None:
        mutations = (
            ("scope_private", "visibility_scope = 'private'"),
            ("project_moved", "project_id = 'moved-project'"),
            ("scope_invalid", "visibility_scope = 'bogus'"),
        )
        for mutation, assignment in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                displaced = record_project_state(
                    root,
                    session_id="source-bound-project-a",
                    agent_id="source-bound-agent-a",
                    project_id="source-bound-project",
                    objective="DISPLACED PROJECT AUTHORITY",
                )
                current = record_project_state(
                    root,
                    session_id="source-bound-project-b",
                    agent_id="source-bound-agent-b",
                    project_id="source-bound-project",
                    objective="CURRENT PROJECT AUTHORITY",
                )
                conn = connect(root)
                try:
                    conn.execute(
                        f"UPDATE cards SET {assignment} WHERE id = ?",
                        (displaced["card_id"],),
                    )
                    conn.commit()
                finally:
                    conn.close()
                sync_card_sidecars_after_commit(root, [displaced["card_id"]])

                blocked = resume_latest(
                    root,
                    project_id="source-bound-project",
                    model_assist=False,
                )
                repaired = store_module.repair_invalid_project_state_checkpoints(
                    root,
                    project_id="source-bound-project",
                    dry_run=False,
                )
                resumed = resume_latest(
                    root,
                    project_id="source-bound-project",
                    model_assist=False,
                )

                self.assertFalse(blocked["ok"], blocked)
                self.assertEqual(blocked["reason"], "authority_corrupt")
                self.assertIn(
                    "source_bound_authority_boundary_mismatch",
                    {
                        issue["type"]
                        for issue in blocked["authority_corruption"][
                            "topology_issues"
                        ]
                    },
                )
                self.assertTrue(repaired["ok"], repaired)
                self.assertEqual(repaired["quarantined_count"], 1)
                self.assertTrue(resumed["ok"], resumed)
                self.assertEqual(
                    resumed["discovery"]["checkpoint_id"],
                    current["card_id"],
                )

    def test_source_bound_session_membership_exposes_card_boundary_drift(
        self,
    ) -> None:
        mutations = (
            ("session_moved", "session_id = 'other-session'"),
            ("project_moved", "project_id = 'other-project'"),
        )
        for mutation, assignment in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                displaced = record_project_state(
                    root,
                    session_id="source-bound-session",
                    agent_id="source-bound-session-agent-a",
                    project_id="source-bound-session-project",
                    objective="DISPLACED SESSION AUTHORITY",
                    metadata={"visibility_scope": "session"},
                )
                current = record_project_state(
                    root,
                    session_id="source-bound-session",
                    agent_id="source-bound-session-agent-b",
                    project_id="source-bound-session-project",
                    objective="CURRENT SESSION AUTHORITY",
                    metadata={"visibility_scope": "session"},
                )
                conn = connect(root)
                try:
                    conn.execute(
                        f"UPDATE cards SET {assignment} WHERE id = ?",
                        (displaced["card_id"],),
                    )
                    conn.commit()
                finally:
                    conn.close()
                sync_card_sidecars_after_commit(root, [displaced["card_id"]])

                blocked = resume_latest(
                    root,
                    session_id="source-bound-session",
                    model_assist=False,
                )
                repaired = store_module.repair_invalid_project_state_checkpoints(
                    root,
                    session_id="source-bound-session",
                    dry_run=False,
                )
                resumed = resume_latest(
                    root,
                    session_id="source-bound-session",
                    model_assist=False,
                )

                self.assertFalse(blocked["ok"], blocked)
                self.assertEqual(blocked["reason"], "authority_corrupt")
                self.assertTrue(repaired["ok"], repaired)
                self.assertEqual(repaired["quarantined_count"], 1)
                self.assertTrue(resumed["ok"], resumed)
                self.assertEqual(
                    resumed["discovery"]["checkpoint_id"],
                    current["card_id"],
                )

    def test_source_bound_seed_supports_legacy_sequence_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            displaced = record_project_state(
                root,
                session_id="legacy-source-bound-a",
                agent_id="legacy-source-agent-a",
                project_id="legacy-source-bound-project",
                objective="LEGACY DISPLACED AUTHORITY",
            )
            current = record_project_state(
                root,
                session_id="legacy-source-bound-b",
                agent_id="legacy-source-agent-b",
                project_id="legacy-source-bound-project",
                objective="LEGACY CURRENT AUTHORITY",
            )
            conn = connect(root)
            try:
                conn.execute(
                    """
                    UPDATE cards
                    SET source_refs_json = ?, project_id = 'legacy-moved-project'
                    WHERE id = ?
                    """,
                    (
                        json.dumps(
                            [
                                {
                                    "session_id": "legacy-source-bound-a",
                                    "seq": displaced["seq"],
                                }
                            ],
                            separators=(",", ":"),
                        ),
                        displaced["card_id"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [displaced["card_id"]])

            blocked = resume_latest(
                root,
                project_id="legacy-source-bound-project",
                model_assist=False,
            )
            repaired = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="legacy-source-bound-project",
                dry_run=False,
            )
            resumed = resume_latest(
                root,
                project_id="legacy-source-bound-project",
                model_assist=False,
            )

            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "authority_corrupt")
            self.assertTrue(repaired["ok"], repaired)
            self.assertEqual(repaired["quarantined_count"], 1)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                current["card_id"],
            )

    def test_non_object_source_reference_fails_closed_without_sql_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="non-object-source-session",
                agent_id="non-object-source-agent",
                project_id="non-object-source-project",
                objective="NON OBJECT SOURCE REFERENCE",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET source_refs_json = ? WHERE id = ?",
                    (json.dumps(["not-an-object"]), state["card_id"]),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [state["card_id"]])

            resumed = resume_latest(
                root,
                project_id="non-object-source-project",
                model_assist=False,
            )

            self.assertFalse(resumed["ok"], resumed)
            self.assertEqual(
                resumed["reason"],
                "invalid_project_state_checkpoint",
            )
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_legacy_session_source_without_project_metadata_remains_resumable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="legacy-session-source",
                agent_id="legacy-session-agent",
                project_id="legacy-session-project",
                objective="LEGACY SESSION SOURCE METADATA",
                metadata={"visibility_scope": "session"},
            )
            conn = connect(root)
            try:
                source_row = conn.execute(
                    "SELECT metadata_json FROM scroll_events WHERE id = ?",
                    (state["event_id"],),
                ).fetchone()
                source_metadata = json.loads(source_row["metadata_json"])
                source_metadata.pop("project_id", None)
                conn.execute(
                    "UPDATE scroll_events SET metadata_json = ? WHERE id = ?",
                    (
                        json.dumps(source_metadata, separators=(",", ":")),
                        state["event_id"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            semantic = store_module.semantic_integrity_report(root)
            resumed = resume_latest(
                root,
                session_id="legacy-session-source",
                model_assist=False,
            )

            self.assertTrue(semantic["ok"], semantic)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                state["card_id"],
            )

    def test_dual_scope_uses_project_head_when_newer_session_boundary_is_quarantined(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            project_head = record_project_state(
                root,
                session_id="project-source-session",
                agent_id="project-agent",
                project_id="dual-live-project",
                objective="LIVE PROJECT AUTHORITY",
            )
            retired_session = record_project_state(
                root,
                session_id="dual-requested-session",
                agent_id="session-agent",
                project_id="separate-session-project",
                objective="NEWER SESSION AUTHORITY TO QUARANTINE",
                metadata={"visibility_scope": "session"},
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = summary || ' damaged' WHERE id = ?",
                    (retired_session["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [retired_session["card_id"]])
            repaired = store_module.repair_invalid_project_state_checkpoints(
                root,
                session_id="dual-requested-session",
                dry_run=False,
            )

            resumed = resume_latest(
                root,
                session_id="dual-requested-session",
                project_id="dual-live-project",
                model_assist=False,
            )

            self.assertTrue(repaired["ok"], repaired)
            self.assertEqual(repaired["quarantined_count"], 1)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                project_head["card_id"],
            )

    def test_unscoped_resume_ignores_a_newer_clean_boundary_without_a_head(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            live = record_project_state(
                root,
                session_id="unscoped-live-session",
                agent_id="unscoped-live-agent",
                project_id="unscoped-live-project",
                objective="LIVE UNSCOPED AUTHORITY",
            )
            stale_successor = record_project_state(
                root,
                session_id="unscoped-stale-b",
                agent_id="unscoped-stale-agent",
                project_id="unscoped-stale-project",
                objective="STALE SUCCESSOR",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET status = 'archived' WHERE id = ?",
                    (stale_successor["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [stale_successor["card_id"]])
            repaired = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="unscoped-stale-project",
                dry_run=False,
            )

            resumed = resume_latest(root, model_assist=False)

            self.assertTrue(repaired["ok"], repaired)
            self.assertEqual(repaired["quarantined_count"], 1)
            self.assertTrue(store_module.semantic_integrity_report(root)["ok"])
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["discovery"]["source"], "project_state_card")
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                live["card_id"],
            )

    def test_same_agent_project_state_supersession_keeps_one_operational_head_and_raw_history(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="checkpoint-one",
                agent_id="codex-sol",
                project_id="checkpoint-project",
                objective="OLD_OBJECTIVE_9QQ",
                decisions=["OLD_DECISION_9QQ"],
                open_tasks=["OLD_TASK_9QQ"],
            )
            second = record_project_state(
                root,
                session_id="checkpoint-two",
                agent_id="codex-sol",
                project_id="checkpoint-project",
                objective="MIDDLE_OBJECTIVE_4RR",
                decisions=["MIDDLE_DECISION_4RR"],
                open_tasks=["MIDDLE_TASK_4RR"],
            )
            third = record_project_state(
                root,
                session_id="checkpoint-three",
                agent_id="codex-sol",
                project_id="checkpoint-project",
                objective="NEW_OBJECTIVE_7VV",
                decisions=["NEW_DECISION_7VV"],
                open_tasks=["NEW_TASK_7VV"],
            )

            workers = run_worker_pass(
                root,
                roles=["librarian"],
                limit=10,
                maintenance=False,
            )
            resumed = resume_latest(
                root,
                project_id="checkpoint-project",
                token_budget=5000,
                model_assist=False,
            )

            self.assertTrue(workers["ok"], workers)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["discovery"]["checkpoint_id"], third["card_id"])
            self.assertEqual(second["supersedes_card_id"], first["card_id"])
            self.assertEqual(third["supersedes_card_id"], second["card_id"])
            for marker in (
                "OLD_OBJECTIVE_9QQ",
                "OLD_DECISION_9QQ",
                "OLD_TASK_9QQ",
                "MIDDLE_OBJECTIVE_4RR",
                "MIDDLE_DECISION_4RR",
                "MIDDLE_TASK_4RR",
            ):
                self.assertNotIn(marker, resumed["packet_text"])
            self.assertIn("NEW_OBJECTIVE_7VV", resumed["packet_text"])
            self.assertIn("NEW_DECISION_7VV", resumed["packet_text"])
            self.assertIn("NEW_TASK_7VV", resumed["packet_text"])

            conn = connect(root)
            try:
                rows = {
                    str(row["id"]): dict(row)
                    for row in conn.execute(
                        """
                        SELECT id, status, decisions_json, open_tasks_json,
                               supersedes_card_id, superseded_by_card_id,
                               conflict_group
                        FROM cards
                        WHERE id IN (?, ?, ?)
                        """,
                        (first["card_id"], second["card_id"], third["card_id"]),
                    )
                }
                current_ids = [
                    str(row["id"])
                    for row in conn.execute(
                        f"""
                        SELECT id
                        FROM cards
                        WHERE card_type = 'project_state'
                          AND {store_module._current_card_authority_clause('cards')}
                        """
                    )
                ]
            finally:
                conn.close()

            self.assertEqual(current_ids, [third["card_id"]])
            self.assertEqual(rows[first["card_id"]]["superseded_by_card_id"], second["card_id"])
            self.assertIsNone(rows[first["card_id"]]["supersedes_card_id"])
            self.assertEqual(rows[second["card_id"]]["supersedes_card_id"], first["card_id"])
            self.assertEqual(rows[second["card_id"]]["superseded_by_card_id"], third["card_id"])
            self.assertEqual(rows[third["card_id"]]["supersedes_card_id"], second["card_id"])
            self.assertIsNone(rows[third["card_id"]]["superseded_by_card_id"])
            self.assertEqual(
                json.loads(rows[first["card_id"]]["decisions_json"]),
                ["OLD_DECISION_9QQ"],
            )

            historical = compile_context(
                root,
                session_id="checkpoint-one",
                project_id="checkpoint-project",
                token_budget=5000,
                planner_profile="legacy",
                create=False,
            )
            self.assertIn("OLD_OBJECTIVE_9QQ", historical["context_text"])
            self.assertIn("OLD_DECISION_9QQ", historical["context_text"])
            self.assertIn("OLD_TASK_9QQ", historical["context_text"])

    def test_concurrent_same_agent_checkpoints_form_one_serialized_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            seed = record_project_state(
                root,
                session_id="concurrent-seed",
                agent_id="codex-sol",
                project_id="concurrent-project",
                objective="Seed checkpoint",
            )
            writer_count = 8
            barrier = threading.Barrier(writer_count)

            def write_checkpoint(index: int) -> dict[str, object]:
                barrier.wait()
                return record_project_state(
                    root,
                    session_id=f"concurrent-session-{index}",
                    agent_id="codex-sol",
                    project_id="concurrent-project",
                    objective=f"Concurrent checkpoint {index}",
                    decisions=[f"concurrent-decision-{index}"],
                    open_tasks=[f"concurrent-task-{index}"],
                )

            with ThreadPoolExecutor(max_workers=writer_count) as executor:
                results = list(executor.map(write_checkpoint, range(writer_count)))

            workers = run_worker_pass(
                root,
                roles=["librarian"],
                limit=20,
                maintenance=False,
            )
            self.assertTrue(workers["ok"], workers)
            self.assertEqual(len({str(result["card_id"]) for result in results}), writer_count)

            conn = connect(root)
            try:
                rows = [
                    dict(row)
                    for row in conn.execute(
                        """
                        SELECT rowid AS card_rowid, id, supersedes_card_id,
                               superseded_by_card_id, conflict_group
                        FROM cards
                        WHERE card_type = 'project_state'
                          AND project_id = 'concurrent-project'
                        ORDER BY card_rowid
                        """
                    )
                ]
                head_ids = [
                    str(row["id"])
                    for row in conn.execute(
                        f"""
                        SELECT id
                        FROM cards
                        WHERE card_type = 'project_state'
                          AND project_id = 'concurrent-project'
                          AND {store_module._current_card_authority_clause('cards')}
                        """
                    )
                ]
            finally:
                conn.close()

            self.assertEqual(len(rows), writer_count + 1)
            self.assertEqual(head_ids, [rows[-1]["id"]])
            by_id = {str(row["id"]): row for row in rows}
            self.assertIn(seed["card_id"], by_id)
            for row in rows[:-1]:
                successor_id = str(row["superseded_by_card_id"] or "")
                self.assertIn(successor_id, by_id)
                self.assertEqual(by_id[successor_id]["supersedes_card_id"], row["id"])
                self.assertIsNone(row["conflict_group"])
            self.assertIsNone(rows[-1]["superseded_by_card_id"])
            self.assertIsNone(rows[-1]["conflict_group"])

            detected = detect_conflicts(root)
            self.assertEqual(detected["conflict_count"], 0, detected)

    def test_identical_project_state_calls_create_distinct_acyclic_checkpoints(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            values = {
                "session_id": "identical-session",
                "agent_id": "identical-agent",
                "project_id": "identical-project",
                "objective": "IDENTICAL_CHECKPOINT_OBJECTIVE",
                "decisions": ["IDENTICAL_CHECKPOINT_DECISION"],
                "open_tasks": ["IDENTICAL_CHECKPOINT_TASK"],
            }
            first = record_project_state(root, **values)
            second = record_project_state(root, **values)

            self.assertNotEqual(first["event_id"], second["event_id"])
            self.assertNotEqual(first["card_id"], second["card_id"])
            self.assertEqual(second["supersedes_card_id"], first["card_id"])
            conn = connect(root)
            try:
                rows = [
                    dict(row)
                    for row in conn.execute(
                        """
                        SELECT id, supersedes_card_id, superseded_by_card_id
                        FROM cards WHERE card_type = 'project_state' ORDER BY rowid
                        """
                    )
                ]
                current_ids = [
                    str(row["id"])
                    for row in conn.execute(
                        f"""
                        SELECT id FROM cards
                        WHERE card_type = 'project_state'
                          AND {store_module._current_card_authority_clause('cards')}
                        """
                    )
                ]
            finally:
                conn.close()
            self.assertEqual(current_ids, [second["card_id"]])
            self.assertTrue(
                all(
                    row["id"] != row["supersedes_card_id"]
                    and row["id"] != row["superseded_by_card_id"]
                    for row in rows
                )
            )
            resumed = resume_latest(
                root,
                project_id="identical-project",
                token_budget=3000,
                model_assist=False,
            )
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                second["card_id"],
            )

    def test_repeated_older_payload_appends_new_head_without_reversing_chain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            repeated_values = {
                "session_id": "aba-session",
                "agent_id": "aba-agent",
                "project_id": "aba-project",
                "objective": "ABA_OBJECTIVE_A",
                "decisions": ["ABA_DECISION_A"],
                "open_tasks": ["ABA_TASK_A"],
            }
            first = record_project_state(root, **repeated_values)
            middle = record_project_state(
                root,
                session_id="aba-session",
                agent_id="aba-agent",
                project_id="aba-project",
                objective="ABA_OBJECTIVE_B",
                decisions=["ABA_DECISION_B"],
                open_tasks=["ABA_TASK_B"],
            )
            third = record_project_state(root, **repeated_values)

            self.assertNotEqual(first["event_id"], third["event_id"])
            self.assertNotEqual(first["card_id"], third["card_id"])
            self.assertEqual(middle["supersedes_card_id"], first["card_id"])
            self.assertEqual(third["supersedes_card_id"], middle["card_id"])
            conn = connect(root)
            try:
                rows = {
                    str(row["id"]): dict(row)
                    for row in conn.execute(
                        """
                        SELECT id, supersedes_card_id, superseded_by_card_id
                        FROM cards WHERE card_type = 'project_state'
                        """
                    )
                }
                current_ids = [
                    str(row["id"])
                    for row in conn.execute(
                        f"""
                        SELECT id FROM cards
                        WHERE card_type = 'project_state'
                          AND {store_module._current_card_authority_clause('cards')}
                        """
                    )
                ]
            finally:
                conn.close()
            self.assertEqual(current_ids, [third["card_id"]])
            cursor: str | None = third["card_id"]
            visited: list[str] = []
            while cursor:
                self.assertNotIn(cursor, visited)
                visited.append(cursor)
                cursor = rows[cursor]["supersedes_card_id"]
            self.assertEqual(
                visited,
                [third["card_id"], middle["card_id"], first["card_id"]],
            )
            resumed = resume_latest(
                root,
                project_id="aba-project",
                token_budget=3000,
                model_assist=False,
            )
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["discovery"]["checkpoint_id"], third["card_id"])
            self.assertNotIn("ABA_OBJECTIVE_B", resumed["packet_text"])
            self.assertNotIn("ABA_DECISION_B", resumed["packet_text"])
            self.assertNotIn("ABA_TASK_B", resumed["packet_text"])

    def test_librarian_does_not_contest_project_state_with_derived_scroll_segment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="normal-session",
                agent_id="codex-sol",
                project_id="alpha-project",
                objective="Use alpha routing",
            )
            append_scroll_event(
                root,
                session_id="normal-session",
                event_type="message",
                role="user",
                content="Do not use alpha routing",
                metadata={"visibility_scope": "project", "project_id": "alpha-project"},
            )
            segment = roll_scroll_segment(
                root,
                session_id="normal-session",
                start_seq=1,
                end_seq=2,
            )

            workers = run_worker_pass(
                root,
                roles=["librarian"],
                limit=10,
                maintenance=False,
            )
            resumed = resume_latest(
                root,
                project_id="alpha-project",
                model_assist=False,
            )

            self.assertTrue(workers["ok"], workers)
            conn = connect(root)
            try:
                groups = {
                    str(row["id"]): row["conflict_group"]
                    for row in conn.execute(
                        "SELECT id, conflict_group FROM cards WHERE id IN (?, ?)",
                        (state["card_id"], segment["card_id"]),
                    )
                }
            finally:
                conn.close()
            self.assertEqual(groups[state["card_id"]], None)
            self.assertEqual(groups[segment["card_id"]], None)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["session_id"], "normal-session")
            self.assertEqual(resumed["project_id"], "alpha-project")

    def test_resume_planner_preserves_descending_scroll_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            for seq in range(1, 16):
                append_scroll_event(
                    root,
                    session_id="ordered-session",
                    event_type="message",
                    role="user",
                    content=f"ordered evidence {seq}",
                    metadata={"project_id": "ordered-project", "visibility_scope": "project"},
                )

            packet = compile_context(
                root,
                session_id="ordered-session",
                project_id="ordered-project",
                token_budget=6000,
                planner_profile="resume",
                create=False,
            )

            recent = next(section for section in packet["sections"] if section["kind"] == "recent_scroll")
            self.assertEqual(
                recent["ids"],
                [f"scroll:ordered-session:{seq}" for seq in range(15, 0, -1)],
            )

    def test_resume_planner_excludes_superseded_and_contested_cue_cards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            superseded = record_project_state(
                root,
                session_id="superseded-session",
                agent_id="codex-sol",
                project_id="cue-project",
                objective="Retire the obsolete quasar protocol",
            )
            contested = record_project_state(
                root,
                session_id="contested-session",
                agent_id="codex-sol",
                project_id="cue-project",
                objective="Resolve the disputed nebula protocol",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET superseded_by_card_id = ? WHERE id = ?",
                    ("replacement-card", superseded["card_id"]),
                )
                conn.execute(
                    "UPDATE cards SET conflict_group = ? WHERE id = ?",
                    ("conflict-group", contested["card_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            packet = compile_context(
                root,
                session_id="superseded-session",
                project_id="cue-project",
                query="obsolete quasar disputed nebula",
                token_budget=6000,
                cue_recall_limit=20,
                planner_profile="resume",
                create=False,
            )

            selected_ids = {
                item_id
                for section in packet["sections"]
                for item_id in section["ids"]
            }
            excluded_cue_ids = {
                item["id"]
                for item in packet["planner_trace"]
                if item.get("source") == "cue_recall"
                and item.get("reason") == "superseded_or_contested"
            }
            expected_cue_ids = {
                f"cue:card:{superseded['card_id']}",
                f"cue:card:{contested['card_id']}",
            }
            self.assertTrue(expected_cue_ids.isdisjoint(selected_ids))
            self.assertTrue(excluded_cue_ids.issubset(expected_cue_ids))

    def test_one_way_lineage_excludes_predecessor_but_keeps_successor_everywhere(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                predecessor = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="One Way Quasar Lineage",
                    summary="ONE-WAY-PREDECESSOR: use the old quasar authority.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="one-way-session",
                    project_id="one-way-project",
                )
                successor = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="One Way Quasar Lineage",
                    summary="ONE-WAY-SUCCESSOR: use the current quasar authority.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="one-way-session",
                    project_id="one-way-project",
                )
                conn.execute(
                    "UPDATE cards SET supersedes_card_id = ? WHERE id = ?",
                    (predecessor, successor),
                )
                conn.commit()
            finally:
                conn.close()

            packet = compile_context(
                root,
                session_id="one-way-session",
                project_id="one-way-project",
                query="one way quasar lineage authority",
                token_budget=6000,
                planner_profile="resume",
                create=False,
            )
            selected_ids = {
                str(item_id)
                for section in packet["sections"]
                for item_id in section.get("ids", [])
            }
            self.assertNotIn(predecessor, selected_ids, packet)
            self.assertIn(successor, selected_ids, packet)
            self.assertNotIn("ONE-WAY-PREDECESSOR", packet["context_text"])
            self.assertIn("ONE-WAY-SUCCESSOR", packet["context_text"])

            recalled = cue_recall(
                root,
                cue="one way quasar lineage authority",
                project_id="one-way-project",
                limit=50,
                max_associations=50,
                create=False,
            )
            recalled_card_ids = {
                str(item["id"])
                for item in recalled["results"]
                if item.get("kind") == "card"
            }
            self.assertNotIn(predecessor, recalled_card_ids, recalled)
            self.assertIn(successor, recalled_card_ids, recalled)

            conn = connect(root)
            try:
                reinforced = reinforce_card_recall(
                    conn,
                    card_ids=[predecessor, successor],
                    root=root,
                )
                conn.commit()
                counts = {
                    str(row["id"]): int(row["recall_count"])
                    for row in conn.execute(
                        "SELECT id, recall_count FROM cards WHERE id IN (?, ?)",
                        (predecessor, successor),
                    )
                }
            finally:
                conn.close()
            self.assertEqual(reinforced, 1)
            self.assertEqual(counts[predecessor], 0)
            self.assertEqual(counts[successor], 1)

    def test_public_planners_and_cue_recall_exclude_every_noncurrent_card_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_ids: dict[str, str] = {}
                for status in sorted(NON_CURRENT_CARD_STATUSES):
                    card_id = create_card(
                        conn,
                        root=root,
                        card_type="decision",
                        title=f"Lifecycle Quasar {status}",
                        summary=f"LIFECYCLE-MARKER-{status}: retain this as non-current evidence.",
                        source_refs=[],
                        visibility_scope="project",
                        session_id="lifecycle-session",
                        project_id="lifecycle-project",
                    )
                    if status != "archived":
                        conn.execute("UPDATE cards SET status = ? WHERE id = ?", (status, card_id))
                    card_ids[status] = card_id
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, list(card_ids.values()))
            archived = prune_memory(
                root,
                topic="Lifecycle Quasar archived",
                action="archive",
            )
            self.assertEqual(archived["card_ids"], [card_ids["archived"]])

            for planner_profile in ("legacy", "resume"):
                packet = compile_context(
                    root,
                    session_id="lifecycle-session",
                    project_id="lifecycle-project",
                    query="lifecycle quasar marker",
                    token_budget=6000,
                    planner_profile=planner_profile,
                    include_cue_recall=True,
                    create=False,
                )
                selected_ids = {
                    str(item_id)
                    for section in packet.get("sections", [])
                    for item_id in (section.get("ids") or section.get("card_ids") or [])
                }
                self.assertTrue(set(card_ids.values()).isdisjoint(selected_ids), packet)
                self.assertNotIn("LIFECYCLE-MARKER", packet["context_text"])

            recalled = cue_recall(
                root,
                cue="lifecycle quasar marker",
                project_id="lifecycle-project",
                limit=50,
                max_associations=50,
                create=False,
            )
            recalled_card_ids = {
                str(item["id"])
                for item in recalled["results"]
                if item.get("kind") == "card"
            }
            self.assertTrue(set(card_ids.values()).isdisjoint(recalled_card_ids), recalled)

    def test_pointerless_historical_and_superseded_state_require_quarantine_receipt(
        self,
    ) -> None:
        for status in ("historical", "superseded"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                state = record_project_state(
                    root,
                    session_id=f"{status}-session",
                    agent_id="codex-sol",
                    project_id=f"{status}-project",
                    objective=f"Pointerless {status} checkpoint",
                )
                conn = connect(root)
                try:
                    conn.execute(
                        """
                        UPDATE cards
                        SET status = ?, supersedes_card_id = NULL,
                            superseded_by_card_id = NULL, conflict_group = NULL
                        WHERE id = ?
                        """,
                        (status, state["card_id"]),
                    )
                    conn.commit()
                finally:
                    conn.close()

                result = resume_latest(root, project_id=f"{status}-project")

                self.assertFalse(result["ok"], result)
                self.assertEqual(result["reason"], "authority_corrupt")
                self.assertFalse((root / "exports" / "thread_recovery").exists())
                repaired = store_module.repair_invalid_project_state_checkpoints(
                    root,
                    project_id=f"{status}-project",
                    dry_run=False,
                )
                after_repair = resume_latest(
                    root,
                    project_id=f"{status}-project",
                )
                self.assertTrue(repaired["ok"], repaired)
                self.assertEqual(repaired["quarantined_count"], 1)
                self.assertFalse(after_repair["ok"], after_repair)
                self.assertEqual(
                    after_repair["reason"],
                    "no_current_project_state",
                )

    def test_unproven_noncurrent_status_cannot_erase_an_independent_head(
        self,
    ) -> None:
        for status in sorted(NON_CURRENT_CARD_STATUSES):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                retired = record_project_state(
                    root,
                    session_id=f"retired-{status}",
                    agent_id="retired-agent",
                    project_id="retirement-boundary-project",
                    objective=f"RETIRE {status} WITHOUT RECEIPT",
                )
                current = record_project_state(
                    root,
                    session_id=f"current-{status}",
                    agent_id="current-agent",
                    project_id="retirement-boundary-project",
                    objective="CURRENT INDEPENDENT AUTHORITY",
                )
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE cards SET status = ? WHERE id = ?",
                        (status, retired["card_id"]),
                    )
                    conn.commit()
                finally:
                    conn.close()
                sync_card_sidecars_after_commit(root, [retired["card_id"]])

                semantic_before = store_module.semantic_integrity_report(root)
                blocked = resume_latest(
                    root,
                    project_id="retirement-boundary-project",
                    model_assist=False,
                )
                repaired = store_module.repair_invalid_project_state_checkpoints(
                    root,
                    project_id="retirement-boundary-project",
                    dry_run=False,
                )
                semantic_after = store_module.semantic_integrity_report(root)
                resumed = resume_latest(
                    root,
                    project_id="retirement-boundary-project",
                    model_assist=False,
                )

                self.assertFalse(semantic_before["ok"], semantic_before)
                self.assertEqual(
                    semantic_before["checks"][
                        "unproven_project_state_retirements"
                    ],
                    1,
                )
                self.assertFalse(blocked["ok"], blocked)
                self.assertEqual(blocked["reason"], "authority_corrupt")
                self.assertIn(
                    "unproven_project_state_retirement",
                    {
                        issue["type"]
                        for issue in blocked["authority_corruption"][
                            "topology_issues"
                        ]
                    },
                )
                self.assertTrue(repaired["ok"], repaired)
                self.assertEqual(repaired["quarantined_count"], 1)
                self.assertTrue(semantic_after["ok"], semantic_after)
                self.assertTrue(resumed["ok"], resumed)
                self.assertEqual(
                    resumed["discovery"]["checkpoint_id"],
                    current["card_id"],
                )

    def test_unproven_retired_chain_head_is_quarantined_and_reactivates_predecessor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            predecessor = record_project_state(
                root,
                session_id="retired-chain-predecessor",
                agent_id="chain-agent",
                project_id="retired-chain-project",
                objective="CHAIN PREDECESSOR",
            )
            retired_head = record_project_state(
                root,
                session_id="retired-chain-head",
                agent_id="chain-agent",
                project_id="retired-chain-project",
                objective="CHAIN HEAD RETIRED WITHOUT RECEIPT",
            )
            independent = record_project_state(
                root,
                session_id="retired-chain-independent",
                agent_id="independent-agent",
                project_id="retired-chain-project",
                objective="INDEPENDENT AUTHORITY",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET status = 'archived' WHERE id = ?",
                    (retired_head["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [retired_head["card_id"]])

            blocked = resume_latest(
                root,
                project_id="retired-chain-project",
                model_assist=False,
            )
            repaired = store_module.repair_invalid_project_state_checkpoints(
                root,
                project_id="retired-chain-project",
                dry_run=False,
            )
            ambiguous = resume_latest(
                root,
                project_id="retired-chain-project",
                model_assist=False,
            )

            self.assertFalse(blocked["ok"], blocked)
            self.assertEqual(blocked["reason"], "authority_corrupt")
            self.assertTrue(repaired["ok"], repaired)
            self.assertEqual(repaired["quarantined_count"], 1)
            self.assertEqual(
                repaired["reactivated_card_ids"],
                [predecessor["card_id"]],
            )
            self.assertTrue(store_module.semantic_integrity_report(root)["ok"])
            self.assertFalse(ambiguous["ok"], ambiguous)
            self.assertEqual(ambiguous["reason"], "authority_ambiguous")
            self.assertEqual(
                set(ambiguous["authority_ambiguity"]["current_head_ids"]),
                {predecessor["card_id"], independent["card_id"]},
            )

    def test_explicit_resume_mode_requires_and_honors_supplied_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="explicit-session",
                agent_id="codex-sol",
                project_id="explicit-project",
                objective="Explicit resume",
            )
            configure_personal_profile(root, resume_mode="explicit")

            missing_scope = resume_latest(root)

            self.assertFalse(missing_scope["ok"])
            self.assertEqual(missing_scope["reason"], "explicit_resume_requires_scope")
            self.assertFalse((root / "exports" / "thread_recovery").exists())

            scoped = resume_latest(root, project_id="explicit-project", token_budget=800)

            self.assertTrue(scoped["ok"], scoped)
            self.assertEqual(scoped["resume_profile"], "explicit")
            self.assertEqual(scoped["session_id"], "explicit-session")

    def test_latest_project_mode_requires_then_uses_default_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="target-session",
                agent_id="codex-sol",
                project_id="target-project",
                objective="Default project state",
            )
            record_project_state(
                root,
                session_id="other-session",
                agent_id="codex-sol",
                project_id="other-project",
                objective="Other project state",
            )
            configure_personal_profile(root, resume_mode="latest_project", clear_default_project=True)

            missing_default = resume_latest(root)

            self.assertFalse(missing_default["ok"])
            self.assertEqual(missing_default["reason"], "latest_project_requires_default_project")
            self.assertFalse((root / "exports" / "thread_recovery").exists())

            configure_personal_profile(root, default_project_id="target-project")
            resumed = resume_latest(root, token_budget=800)

            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["resume_profile"], "latest_project")
            self.assertEqual(resumed["project_id"], "target-project")
            self.assertEqual(resumed["session_id"], "target-session")

    def test_resume_canonicalizes_supplied_partition_aliases_before_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["security"]["secret_scan_action"] = "warn"
            write_config(root, config)
            secret_session = "sk-" + "S" * 40
            secret_project = "sk-" + "P" * 40
            state = record_project_state(
                root,
                session_id=secret_session,
                agent_id="codex-sol",
                project_id=secret_project,
                objective="Alias lookup checkpoint",
            )
            conn = connect(root)
            try:
                row = conn.execute(
                    "SELECT session_id, project_id FROM cards WHERE id = ?",
                    (state["card_id"],),
                ).fetchone()
            finally:
                conn.close()

            result = resume_latest(
                root,
                session_id=secret_session,
                project_id=secret_project,
                token_budget=800,
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["session_id"], row["session_id"])
            self.assertEqual(result["project_id"], row["project_id"])
            self.assertEqual(result["discovery"]["requested_session_id"], row["session_id"])
            self.assertEqual(result["discovery"]["requested_project_id"], row["project_id"])
            self.assertNotEqual(result["session_id"], secret_session)
            self.assertNotEqual(result["project_id"], secret_project)

    def test_resume_orders_current_checkpoints_by_immutable_creation_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            older = record_project_state(
                root,
                session_id="older-session",
                agent_id="codex-sol",
                project_id="checkpoint-project",
                objective="Older checkpoint",
            )
            newer = record_project_state(
                root,
                session_id="newer-session",
                agent_id="codex-sol",
                project_id="checkpoint-project",
                objective="Newer checkpoint",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET created_at = ?, updated_at = ? WHERE id = ?",
                    ("2026-01-01T00:00:00+00:00", "2099-01-01T00:00:00+00:00", older["card_id"]),
                )
                conn.execute(
                    "UPDATE cards SET created_at = ?, updated_at = ? WHERE id = ?",
                    ("2026-02-01T00:00:00+00:00", "2000-01-01T00:00:00+00:00", newer["card_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            result = resume_latest(root, project_id="checkpoint-project", token_budget=800)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["session_id"], "newer-session")
            self.assertEqual(result["discovery"]["checkpoint_at"], "2026-02-01T00:00:00+00:00")

    def test_resume_breaks_same_timestamp_ties_by_insertion_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            older = record_project_state(
                root,
                session_id="same-second-older",
                agent_id="codex-sol",
                project_id="same-second-project",
                objective="Earlier insertion",
            )
            newer = record_project_state(
                root,
                session_id="same-second-newer",
                agent_id="codex-sol",
                project_id="same-second-project",
                objective="Later insertion",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET created_at = ? WHERE id IN (?, ?)",
                    ("2026-02-01T00:00:00+00:00", older["card_id"], newer["card_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            result = resume_latest(root, project_id="same-second-project", token_budget=800)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["session_id"], "same-second-newer")

    def test_resume_does_not_fall_back_to_scroll_when_state_cards_are_not_current(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            superseded = record_project_state(
                root,
                session_id="stale-session",
                agent_id="codex-sol",
                project_id="stale-project",
                objective="Superseded state",
            )
            contested = record_project_state(
                root,
                session_id="contested-session",
                agent_id="codex-sol",
                project_id="stale-project",
                objective="Contested state",
            )
            append_scroll_event(
                root,
                session_id="scroll-fallback-session",
                event_type="message",
                role="user",
                content="This Scroll event must not override stale checkpoint safety.",
                metadata={"project_id": "stale-project", "visibility_scope": "project"},
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET superseded_by_card_id = ? WHERE id = ?",
                    ("replacement-card", superseded["card_id"]),
                )
                conn.execute(
                    "UPDATE cards SET conflict_group = ? WHERE id = ?",
                    ("conflict-group", contested["card_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            result = resume_latest(root, project_id="stale-project")

            self.assertFalse(result["ok"])
            self.assertEqual(result["reason"], "authority_corrupt")
            self.assertTrue(result["repair_required"])
            issue_types = {
                issue["type"]
                for issue in result["authority_corruption"]["topology_issues"]
            }
            self.assertIn("missing_or_cross_boundary_successor", issue_types)
            self.assertFalse((root / "exports" / "thread_recovery").exists())


if __name__ == "__main__":
    unittest.main()
