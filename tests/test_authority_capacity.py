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
from continuum.core.workers import resolve_conflict


def _seed_independent_project_states(
    root: Path,
    *,
    count: int,
    start_index: int = 0,
    historical: bool = False,
) -> list[str]:
    """Create canonical independent checkpoints in one fixture transaction."""

    store_module.init_db(root)
    conn = store_module.connect(root)
    card_ids: list[str] = []
    payload_hash = store_module._project_state_payload_hash([], [])
    assert payload_hash is not None
    try:
        conn.execute("BEGIN IMMEDIATE")
        for offset in range(count):
            index = start_index + offset
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
            store_module.audit_event(
                conn,
                action="append_scroll_event",
                target_type="scroll_event",
                target_id=event_id,
                actor="system",
                payload={
                    "session_id": session_id,
                    "seq": 1,
                    "project_id": project_id,
                    "visibility_scope": "project",
                },
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
            if historical:
                conn.execute(
                    """
                    UPDATE cards
                    SET status = 'historical', supersedes_card_id = NULL,
                        superseded_by_card_id = NULL, conflict_group = NULL
                    WHERE id = ?
                    """,
                    (card_id,),
                )
                store_module._record_project_state_quarantine(
                    conn,
                    card_id=card_id,
                    reason="authority capacity historical fixture",
                    predecessor_card_id=None,
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
    def test_pair_specific_authority_queries_are_bounded_linearly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            states = [
                record_project_state(
                    root,
                    session_id=f"cache-chain-{index}",
                    agent_id="cache-chain-agent",
                    project_id="cache-chain-project",
                    objective=f"Cache chain {index}",
                )
                for index in range(8)
            ]
            receipt_first = record_project_state(
                root,
                session_id="cache-receipt-first",
                agent_id="cache-receipt-agent-a",
                project_id="cache-receipt-project",
            )
            receipt_selected = record_project_state(
                root,
                session_id="cache-receipt-selected",
                agent_id="cache-receipt-agent-b",
                project_id="cache-receipt-project",
            )
            resolve_conflict(
                root,
                card_id=str(receipt_selected["card_id"]),
                action="supersede",
                superseded_card_ids=[str(receipt_first["card_id"])],
            )
            states.extend([receipt_first, receipt_selected])
            card_ids = [str(state["card_id"]) for state in states]
            conn = store_module.connect(root)
            statements: list[str] = []
            try:
                placeholders = ", ".join("?" for _ in card_ids)
                rows = conn.execute(
                    f"SELECT {store_module._PROJECT_STATE_AUTHORITY_SELECT_FIELDS} "
                    f"FROM cards WHERE id IN ({placeholders})",
                    tuple(card_ids),
                ).fetchall()
                source_rows = (
                    store_module._project_state_bound_source_rows_by_card_id(
                        conn,
                        card_ids,
                        page_size=256,
                    )
                )
                proof_cache: dict[str, dict[object, object]] = {}
                conn.set_trace_callback(statements.append)
                for row in rows:
                    store_module._project_state_durable_authority_signals(
                        root,
                        conn,
                        row,
                        source_rows=source_rows.get(str(row["id"]), []),
                        proof_cache=proof_cache,
                    )
                conn.set_trace_callback(None)
            finally:
                conn.close()

            normalized = [statement.casefold() for statement in statements]
            source_identity_queries = sum(
                "select session_id, seq, content, visibility_scope, project_id"
                in statement
                and "from scroll_events" in statement
                for statement in normalized
            )
            exact_placement_queries = sum(
                "select role, payload_json, related_card_ids_json, dedupe_key"
                in statement
                and "from queue_jobs" in statement
                for statement in normalized
            )
            self.assertLessEqual(source_identity_queries, len(card_ids))
            self.assertLessEqual(exact_placement_queries, len(card_ids))
            self.assertLessEqual(
                len(proof_cache.get("member_authorities", {})),
                len(card_ids),
            )

    def test_unscoped_resume_pages_past_511_512_and_513_noncurrent_rows(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="paged-ambiguous-a",
                agent_id="paged-ambiguous-agent-a",
                project_id="paged-ambiguous-project",
                objective="Use alpha",
            )
            second = record_project_state(
                root,
                session_id="paged-ambiguous-b",
                agent_id="paged-ambiguous-agent-b",
                project_id="paged-ambiguous-project",
                objective="Do not use alpha",
            )
            self.assertNotEqual(first["card_id"], second["card_id"])

            seeded = 0
            for expected_count, addition in ((511, 511), (512, 1), (513, 1)):
                _seed_independent_project_states(
                    root,
                    count=addition,
                    start_index=seeded,
                    historical=True,
                )
                seeded += addition

                resumed = resume_latest(root, model_assist=False)

                self.assertEqual(seeded, expected_count)
                self.assertFalse(resumed["ok"], resumed)
                self.assertEqual(resumed["reason"], "authority_ambiguous")
                self.assertEqual(
                    set(
                        resumed["authority_ambiguity"]["current_head_ids"]
                    ),
                    {first["card_id"], second["card_id"]},
                )

    def test_unscoped_resume_pages_past_513_rows_to_older_corruption(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            damaged = record_project_state(
                root,
                session_id="paged-corrupt-session",
                agent_id="paged-corrupt-agent",
                project_id="paged-corrupt-project",
            )
            conn = store_module.connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = summary || ' damaged' "
                    "WHERE id = ?",
                    (damaged["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            store_module.sync_card_sidecars_after_commit(
                root,
                [str(damaged["card_id"])],
            )
            _seed_independent_project_states(
                root,
                count=513,
                historical=True,
            )

            resumed = resume_latest(root, model_assist=False)

            self.assertFalse(resumed["ok"], resumed)
            self.assertEqual(
                resumed["reason"],
                "invalid_project_state_checkpoint",
            )
            self.assertEqual(
                resumed["invalid_checkpoint"]["checkpoint_id"],
                damaged["card_id"],
            )

    def test_modern_scroll_authority_survives_total_derived_state_loss(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="derived-loss-a",
                agent_id="derived-loss-agent-a",
                project_id="derived-loss-project",
                objective="Use alpha",
            )
            second = record_project_state(
                root,
                session_id="derived-loss-b",
                agent_id="derived-loss-agent-b",
                project_id="derived-loss-project",
                objective="Do not use alpha",
            )
            conn = store_module.connect(root)
            try:
                conn.execute("DELETE FROM graph_edge_sources")
                conn.execute("DELETE FROM graph_edges")
                conn.execute("DELETE FROM graph_nodes")
                conn.execute("DELETE FROM cards")
                conn.commit()
            finally:
                conn.close()
            sidecar_dir = root / "catalog" / "cards"
            if sidecar_dir.is_dir():
                for sidecar in sidecar_dir.glob("*.yaml"):
                    sidecar.unlink()

            semantic = semantic_integrity_report(root)
            scoped = resume_latest(
                root,
                project_id="derived-loss-project",
                model_assist=False,
            )
            unscoped = resume_latest(root, model_assist=False)

            self.assertFalse(semantic["ok"], semantic)
            self.assertEqual(
                semantic["checks"]["orphan_project_state_source_events"],
                2,
            )
            self.assertEqual(
                {
                    item["expected_card_id"]
                    for item in semantic["orphan_project_state_source_events"]
                },
                {first["card_id"], second["card_id"]},
            )
            for blocked in (scoped, unscoped):
                self.assertFalse(blocked["ok"], blocked)
                self.assertEqual(blocked["reason"], "authority_corrupt")
            with self.assertRaisesRegex(ValueError, "semantic integrity"):
                snapshot(root, reason="derived authority loss must fail")

    def test_graphless_modern_source_requires_exact_official_queue_binding(
        self,
    ) -> None:
        scenarios = (
            ("processed", None, True),
            (
                "wrong_role",
                "UPDATE queue_jobs SET role = 'scribe' "
                "WHERE job_type = 'review_card_placement'",
                False,
            ),
            (
                "wrong_dedupe",
                "UPDATE queue_jobs SET dedupe_key = 'queue_v1_wrong' "
                "WHERE job_type = 'review_card_placement'",
                False,
            ),
            (
                "mismatched_event",
                "UPDATE queue_jobs SET payload_json = "
                "json_set(payload_json, '$.event_id', 'evt_wrong') "
                "WHERE job_type = 'review_card_placement'",
                False,
            ),
            (
                "extra_payload_field",
                "UPDATE queue_jobs SET payload_json = "
                "json_set(payload_json, '$.unexpected', 'extra') "
                "WHERE job_type = 'review_card_placement'",
                False,
            ),
            (
                "missing_related_id",
                "UPDATE queue_jobs SET related_card_ids_json = '[]' "
                "WHERE job_type = 'review_card_placement'",
                False,
            ),
            ("extra_related_id", None, False),
            (
                "malformed_payload",
                "UPDATE queue_jobs SET payload_json = '{' "
                "WHERE job_type = 'review_card_placement'",
                False,
            ),
            ("oversized_payload", None, False),
        )
        for scenario, mutation_sql, should_prove in scenarios:
            with self.subTest(
                scenario=scenario
            ), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                state = record_project_state(
                    root,
                    session_id=f"queue-proof-{scenario}",
                    agent_id="queue-proof-agent",
                    project_id="queue-proof-project",
                )
                conn = store_module.connect(root)
                try:
                    conn.execute("DELETE FROM graph_edge_sources")
                    conn.execute("DELETE FROM graph_edges")
                    conn.execute("DELETE FROM graph_nodes")
                    conn.execute(
                        "DELETE FROM audit_events WHERE target_type = 'card' "
                        "AND target_id = ?",
                        (state["card_id"],),
                    )
                    if scenario == "processed":
                        conn.execute(
                            "UPDATE queue_jobs SET status = 'done' "
                            "WHERE job_type = 'review_card_placement'"
                        )
                        stored_dedupe = str(
                            conn.execute(
                                "SELECT dedupe_key FROM queue_jobs "
                                "WHERE job_type = 'review_card_placement'"
                            ).fetchone()[0]
                        )
                        expected_dedupe = "queue_v1_" + store_module.content_hash(
                            store_module.json_dumps(
                                [
                                    "librarian",
                                    "review_card_placement",
                                    f"card:{state['card_id']}",
                                ]
                            )
                        )
                        self.assertEqual(stored_dedupe, expected_dedupe)
                    elif scenario == "extra_related_id":
                        conn.execute(
                            "UPDATE queue_jobs SET related_card_ids_json = ? "
                            "WHERE job_type = 'review_card_placement'",
                            (
                                store_module.json_dumps(
                                    [state["card_id"], "unexpected-card"]
                                ),
                            ),
                        )
                    elif scenario == "oversized_payload":
                        conn.execute(
                            "UPDATE queue_jobs SET payload_json = ? "
                            "WHERE job_type = 'review_card_placement'",
                            (
                                store_module.json_dumps(
                                    {
                                        "card_id": state["card_id"],
                                        "event_id": state["event_id"],
                                        "session_id": f"queue-proof-{scenario}",
                                        "project_id": "queue-proof-project",
                                        "visibility_scope": "project",
                                        "padding": "x"
                                        * store_module.MAX_STORED_PROJECT_STATE_BYTES,
                                    }
                                ),
                            ),
                        )
                    elif mutation_sql is not None:
                        conn.execute(mutation_sql)
                    conn.execute("DELETE FROM cards")
                    conn.commit()
                finally:
                    conn.close()
                sidecar = (
                    root
                    / "catalog"
                    / "cards"
                    / f"{state['card_id']}.yaml"
                )
                sidecar.unlink(missing_ok=True)

                semantic = semantic_integrity_report(root)
                resumed = resume_latest(
                    root,
                    project_id="queue-proof-project",
                    model_assist=False,
                )

                self.assertEqual(
                    semantic["checks"]["orphan_project_state_source_events"],
                    int(should_prove),
                    semantic,
                )
                if should_prove:
                    self.assertFalse(semantic["ok"], semantic)
                    self.assertEqual(resumed["reason"], "authority_corrupt")
                else:
                    self.assertTrue(semantic["ok"], semantic)
                    self.assertEqual(resumed["reason"], "no_resume_state")

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
