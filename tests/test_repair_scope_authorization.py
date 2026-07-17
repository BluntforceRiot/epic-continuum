from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

from continuum.core import store as store_module
from continuum.core.config import load_config, write_config
from continuum.core.store import (
    append_scroll_event,
    connect,
    record_project_state,
    repair_invalid_project_state_checkpoints,
    resume_latest,
    sync_card_sidecars_after_commit,
)
from continuum.core.workers import resolve_conflict


class RepairScopeAuthorizationTests(unittest.TestCase):
    def _damaged_project_and_private_checkpoints(
        self,
        root: Path,
    ) -> dict[str, dict[str, Any]]:
        project_state = record_project_state(
            root,
            session_id="repair-visible-session",
            agent_id="repair-visible-agent",
            project_id="repair-scope-project",
            objective="DAMAGED PROJECT-VISIBLE CHECKPOINT",
        )
        private_state = record_project_state(
            root,
            session_id="repair-private-session",
            agent_id="repair-private-agent",
            project_id="repair-scope-project",
            objective="DAMAGED PRIVATE CHECKPOINT",
            metadata={"visibility_scope": "private"},
        )
        conn = connect(root)
        try:
            conn.execute(
                "UPDATE cards SET summary = summary || ' damaged' WHERE id IN (?, ?)",
                (project_state["card_id"], private_state["card_id"]),
            )
            conn.commit()
        finally:
            conn.close()
        sync_card_sidecars_after_commit(
            root,
            [str(project_state["card_id"]), str(private_state["card_id"])],
        )
        return {"project": project_state, "private": private_state}

    def _assert_private_checkpoint_not_disclosed(
        self,
        result: dict[str, Any],
        private_state: dict[str, Any],
    ) -> None:
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn(str(private_state["card_id"]), serialized)
        self.assertNotIn("repair-private-session", serialized)

    def _assert_checkpoint_markers_not_disclosed(
        self,
        result: dict[str, Any],
        state: dict[str, Any],
        *markers: str,
    ) -> None:
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn(str(state["card_id"]), serialized)
        self.assertNotIn(str(state["event_id"]), serialized)
        for marker in markers:
            self.assertNotIn(marker, serialized)

    def _assert_project_only_withholds_checkpoint(
        self,
        root: Path,
        state: dict[str, Any],
        *,
        project_id: str,
        markers: tuple[str, ...],
    ) -> dict[str, Any]:
        preview = repair_invalid_project_state_checkpoints(
            root,
            project_id=project_id,
            dry_run=True,
        )
        resumed = resume_latest(
            root,
            project_id=project_id,
            model_assist=False,
        )
        self.assertEqual(preview["quarantined_count"], 0, preview)
        self._assert_checkpoint_markers_not_disclosed(
            preview,
            state,
            *markers,
        )
        self._assert_checkpoint_markers_not_disclosed(
            resumed,
            state,
            *markers,
        )
        return preview

    def _remove_card_sidecar(
        self,
        root: Path,
        state: dict[str, Any],
    ) -> None:
        (
            root
            / "catalog"
            / "cards"
            / f"{state['card_id']}.yaml"
        ).unlink(missing_ok=True)

    def _record_v021_project_state(
        self,
        root: Path,
        *,
        session_id: str,
        agent_id: str,
        project_id: str,
        objective: str,
        visibility_scope: str,
    ) -> dict[str, Any]:
        content = "\n".join(
            [
                f"Project state for {project_id}",
                f"Agent: {agent_id}",
                f"Objective: {objective}",
            ]
        )
        source_metadata = {
            "agent_id": agent_id,
            "project_id": project_id,
            "session_id": session_id,
            "source_type": "project_state",
            "trust_level": "agent_reported_local_evidence",
            "instruction_authority": "user_level_evidence",
            "visibility_scope": visibility_scope,
        }
        event = append_scroll_event(
            root,
            session_id=session_id,
            event_type="project_state",
            role="agent",
            content=content,
            metadata=source_metadata,
        )
        source_refs = [
            {
                "event_id": event["event_id"],
                "session_id": session_id,
                "seq": event["seq"],
            }
        ]
        card_metadata = dict(source_metadata)
        card_metadata.pop("instruction_authority", None)
        conn = connect(root)
        try:
            conn.execute("BEGIN IMMEDIATE")
            card_id = store_module.create_card(
                conn,
                root=root,
                card_type="project_state",
                title=f"{project_id} project state from {agent_id}",
                summary=store_module.summarize_text(content, limit=900),
                source_refs=source_refs,
                metadata=card_metadata,
                visibility_scope=visibility_scope,
                session_id=session_id,
                project_id=project_id,
                salience=0.9,
                confidence=0.8,
            )
            librarian_job_id = store_module.enqueue_job(
                conn,
                role="librarian",
                job_type="review_card_placement",
                priority=70,
                payload={
                    "card_id": card_id,
                    "event_id": event["event_id"],
                    "session_id": session_id,
                    "project_id": project_id,
                    "visibility_scope": visibility_scope,
                },
                related_card_ids=[card_id],
                dedupe_key=f"card:{card_id}",
            )
            conn.commit()
        finally:
            conn.close()
        sync_card_sidecars_after_commit(root, [card_id])
        return {
            "ok": True,
            "event_id": event["event_id"],
            "seq": event["seq"],
            "card_id": card_id,
            "librarian_job_id": librarian_job_id,
            "project_id": project_id,
            "agent_id": agent_id,
        }

    def test_project_scope_preview_and_apply_do_not_cross_private_visibility(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            states = self._damaged_project_and_private_checkpoints(root)
            conn = connect(root)
            try:
                private_row_before = tuple(
                    conn.execute(
                        "SELECT * FROM cards WHERE id = ?",
                        (states["private"]["card_id"],),
                    ).fetchone()
                )
            finally:
                conn.close()

            preview = repair_invalid_project_state_checkpoints(
                root,
                project_id="repair-scope-project",
                dry_run=True,
            )

            self.assertTrue(preview["ok"], preview)
            self.assertEqual(preview["quarantined_count"], 1)
            self.assertEqual(
                [item["card_id"] for item in preview["quarantined"]],
                [states["project"]["card_id"]],
            )
            self.assertEqual(
                preview["repair_scope"]["authorized_visibility_scopes"],
                ["global", "project"],
            )
            self._assert_private_checkpoint_not_disclosed(
                preview,
                states["private"],
            )

            applied = repair_invalid_project_state_checkpoints(
                root,
                project_id="repair-scope-project",
                dry_run=False,
            )

            self.assertTrue(applied["ok"], applied)
            self.assertTrue(applied["catalog_repair_committed"], applied)
            self.assertEqual(applied["quarantined_count"], 1)
            self.assertEqual(
                [item["card_id"] for item in applied["quarantined"]],
                [states["project"]["card_id"]],
            )
            self._assert_private_checkpoint_not_disclosed(
                applied,
                states["private"],
            )
            conn = connect(root)
            try:
                private_row_after = tuple(
                    conn.execute(
                        "SELECT * FROM cards WHERE id = ?",
                        (states["private"]["card_id"],),
                    ).fetchone()
                )
                rows = {
                    str(row["id"]): str(row["status"])
                    for row in conn.execute(
                        "SELECT id, status FROM cards WHERE id IN (?, ?)",
                        (
                            states["project"]["card_id"],
                            states["private"]["card_id"],
                        ),
                    ).fetchall()
                }
            finally:
                conn.close()
            self.assertEqual(rows[str(states["project"]["card_id"])], "historical")
            self.assertEqual(private_row_after, private_row_before)

    def test_include_private_and_exact_session_authorize_private_checkpoint(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            states = self._damaged_project_and_private_checkpoints(root)

            inclusive = repair_invalid_project_state_checkpoints(
                root,
                project_id="repair-scope-project",
                include_private=True,
                dry_run=True,
            )
            exact_session = repair_invalid_project_state_checkpoints(
                root,
                session_id="repair-private-session",
                dry_run=True,
            )

            self.assertTrue(inclusive["ok"], inclusive)
            self.assertEqual(inclusive["quarantined_count"], 2)
            self.assertEqual(
                {item["card_id"] for item in inclusive["quarantined"]},
                {
                    states["project"]["card_id"],
                    states["private"]["card_id"],
                },
            )
            self.assertEqual(
                inclusive["repair_scope"]["authorized_visibility_scopes"],
                ["global", "project", "private"],
            )
            self.assertTrue(exact_session["ok"], exact_session)
            self.assertEqual(exact_session["quarantined_count"], 1)
            self.assertEqual(
                [item["card_id"] for item in exact_session["quarantined"]],
                [states["private"]["card_id"]],
            )
            self.assertEqual(
                exact_session["repair_scope"]["authorized_visibility_scopes"],
                ["global", "project", "session", "private"],
            )

    def test_project_scope_uses_durable_source_visibility_when_card_scope_drifts(
        self,
    ) -> None:
        for drifted_visibility in ("project", "unknown-scope"):
            with self.subTest(
                drifted_visibility=drifted_visibility
            ), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                private_state = record_project_state(
                    root,
                    session_id="durably-private-session",
                    agent_id="durably-private-agent",
                    project_id="repair-scope-project",
                    objective="DURABLY PRIVATE CHECKPOINT",
                    metadata={"visibility_scope": "private"},
                )
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE cards SET visibility_scope = ? WHERE id = ?",
                        (drifted_visibility, private_state["card_id"]),
                    )
                    conn.commit()
                finally:
                    conn.close()
                sync_card_sidecars_after_commit(
                    root,
                    [str(private_state["card_id"])],
                )

                preview = repair_invalid_project_state_checkpoints(
                    root,
                    project_id="repair-scope-project",
                    dry_run=True,
                )

                self.assertTrue(preview["ok"], preview)
                self.assertEqual(preview["quarantined_count"], 0, preview)
                self._assert_private_checkpoint_not_disclosed(
                    preview,
                    private_state,
                )

    def test_missing_source_does_not_erase_private_repair_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            private_state = record_project_state(
                root,
                session_id="missing-source-private-session",
                agent_id="missing-source-private-agent",
                project_id="repair-scope-project",
                objective="PRIVATE CHECKPOINT WITH LOST SOURCE",
                metadata={"visibility_scope": "private"},
            )
            conn = connect(root)
            try:
                conn.execute(
                    "DELETE FROM scroll_events WHERE id = ?",
                    (private_state["event_id"],),
                )
                conn.execute(
                    "UPDATE cards SET visibility_scope = 'project' WHERE id = ?",
                    (private_state["card_id"],),
                )
                conn.commit()
                drifted_row = tuple(
                    conn.execute(
                        "SELECT * FROM cards WHERE id = ?",
                        (private_state["card_id"],),
                    ).fetchone()
                )
            finally:
                conn.close()
            sync_card_sidecars_after_commit(
                root,
                [str(private_state["card_id"])],
            )

            preview = repair_invalid_project_state_checkpoints(
                root,
                project_id="repair-scope-project",
                dry_run=True,
            )
            applied = repair_invalid_project_state_checkpoints(
                root,
                project_id="repair-scope-project",
                dry_run=False,
            )
            exact_session = repair_invalid_project_state_checkpoints(
                root,
                session_id="missing-source-private-session",
                dry_run=True,
            )
            explicit_private = repair_invalid_project_state_checkpoints(
                root,
                project_id="repair-scope-project",
                include_private=True,
                dry_run=True,
            )

            for project_only in (preview, applied):
                self.assertTrue(project_only["ok"], project_only)
                self.assertEqual(project_only["quarantined_count"], 0)
                self._assert_private_checkpoint_not_disclosed(
                    project_only,
                    private_state,
                )
            self.assertEqual(exact_session["quarantined_count"], 1)
            self.assertEqual(explicit_private["quarantined_count"], 1)
            conn = connect(root)
            try:
                unchanged_row = tuple(
                    conn.execute(
                        "SELECT * FROM cards WHERE id = ?",
                        (private_state["card_id"],),
                    ).fetchone()
                )
            finally:
                conn.close()
            self.assertEqual(unchanged_row, drifted_row)

    def test_source_seeded_private_claims_veto_project_only_repair(self) -> None:
        for drift_card in (False, True):
            with self.subTest(
                drift_card=drift_card
            ), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                session_id = f"source-drift-private-{int(drift_card)}"
                objective = f"PRIVATE SOURCE DRIFT {int(drift_card)}"
                private_state = record_project_state(
                    root,
                    session_id=session_id,
                    agent_id="source-drift-private-agent",
                    project_id="source-drift-project",
                    objective=objective,
                    metadata={"visibility_scope": "private"},
                )
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE scroll_events SET visibility_scope = 'project' "
                        "WHERE id = ?",
                        (private_state["event_id"],),
                    )
                    if drift_card:
                        conn.execute(
                            "UPDATE cards SET visibility_scope = 'project' "
                            "WHERE id = ?",
                            (private_state["card_id"],),
                        )
                    conn.commit()
                    before = tuple(
                        conn.execute(
                            "SELECT * FROM cards WHERE id = ?",
                            (private_state["card_id"],),
                        ).fetchone()
                    )
                finally:
                    conn.close()
                sync_card_sidecars_after_commit(
                    root,
                    [str(private_state["card_id"])],
                )

                preview = repair_invalid_project_state_checkpoints(
                    root,
                    project_id="source-drift-project",
                    dry_run=True,
                )
                applied = repair_invalid_project_state_checkpoints(
                    root,
                    project_id="source-drift-project",
                    dry_run=False,
                )
                exact_session = repair_invalid_project_state_checkpoints(
                    root,
                    session_id=session_id,
                    dry_run=True,
                )
                explicit_private = repair_invalid_project_state_checkpoints(
                    root,
                    project_id="source-drift-project",
                    include_private=True,
                    dry_run=True,
                )

                for project_only in (preview, applied):
                    self.assertTrue(project_only["ok"], project_only)
                    self.assertEqual(project_only["quarantined_count"], 0)
                    self._assert_checkpoint_markers_not_disclosed(
                        project_only,
                        private_state,
                        session_id,
                        objective,
                    )
                self.assertEqual(exact_session["quarantined_count"], 1)
                self.assertEqual(explicit_private["quarantined_count"], 1)
                conn = connect(root)
                try:
                    after = tuple(
                        conn.execute(
                            "SELECT * FROM cards WHERE id = ?",
                            (private_state["card_id"],),
                        ).fetchone()
                    )
                finally:
                    conn.close()
                self.assertEqual(after, before)

    def test_scoped_resume_withholds_private_claims_after_coordinate_drift(
        self,
    ) -> None:
        for drift_source in (False, True):
            with self.subTest(
                drift_source=drift_source
            ), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                session_id = f"resume-private-drift-{int(drift_source)}"
                objective = f"PRIVATE RESUME DRIFT {int(drift_source)}"
                private_state = record_project_state(
                    root,
                    session_id=session_id,
                    agent_id="resume-private-drift-agent",
                    project_id="resume-private-drift-project",
                    objective=objective,
                    metadata={"visibility_scope": "private"},
                )
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE cards SET visibility_scope = 'project' "
                        "WHERE id = ?",
                        (private_state["card_id"],),
                    )
                    if drift_source:
                        conn.execute(
                            "UPDATE scroll_events SET visibility_scope = 'project' "
                            "WHERE id = ?",
                            (private_state["event_id"],),
                        )
                    conn.commit()
                finally:
                    conn.close()

                resumed = resume_latest(
                    root,
                    project_id="resume-private-drift-project",
                    model_assist=False,
                )

                self.assertFalse(resumed["ok"], resumed)
                self.assertEqual(
                    resumed["reason"],
                    "no_current_project_state",
                )
                self._assert_checkpoint_markers_not_disclosed(
                    resumed,
                    private_state,
                    session_id,
                    objective,
                )

    def test_missing_all_durable_scope_evidence_is_redacted_and_unrepairable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            uncertain = record_project_state(
                root,
                session_id="uncertain-repair-session",
                agent_id="uncertain-repair-agent",
                project_id="uncertain-repair-project",
                objective="CHECKPOINT WITH LOST AUTHORITY EVIDENCE",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "DELETE FROM scroll_events WHERE id = ?",
                    (uncertain["event_id"],),
                )
                conn.execute(
                    "DELETE FROM queue_jobs "
                    "WHERE job_type = 'review_card_placement' "
                    "AND json_extract(payload_json, '$.card_id') = ?",
                    (uncertain["card_id"],),
                )
                conn.execute(
                    "DELETE FROM audit_events WHERE target_id = ?",
                    (uncertain["card_id"],),
                )
                conn.execute(
                    "UPDATE cards SET metadata_json = '{}', "
                    "source_refs_json = '[]' WHERE id = ?",
                    (uncertain["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            sidecar = root / "catalog" / "cards" / f"{uncertain['card_id']}.yaml"
            sidecar.unlink(missing_ok=True)

            scoped = repair_invalid_project_state_checkpoints(
                root,
                project_id="uncertain-repair-project",
                dry_run=True,
            )
            resumed = resume_latest(
                root,
                project_id="uncertain-repair-project",
                model_assist=False,
            )
            administrative = repair_invalid_project_state_checkpoints(
                root,
                all_projects=True,
                include_session_scoped=True,
                include_private=True,
                dry_run=True,
            )

            self.assertFalse(scoped["ok"], scoped)
            self.assertEqual(scoped["quarantined_count"], 0)
            self.assertEqual(scoped["withheld_uncertain_candidate_count"], 1)
            self.assertIn(
                "repair_scope_authority_unproven",
                {
                    issue["type"]
                    for issue in scoped["authority_topology_issues"]
                },
            )
            serialized = json.dumps(scoped, sort_keys=True)
            self.assertNotIn(str(uncertain["card_id"]), serialized)
            self.assertNotIn("uncertain-repair-session", serialized)
            self.assertFalse(resumed["ok"], resumed)
            self.assertEqual(resumed["reason"], "no_current_project_state")
            self._assert_checkpoint_markers_not_disclosed(
                resumed,
                uncertain,
                "uncertain-repair-session",
                "CHECKPOINT WITH LOST AUTHORITY EVIDENCE",
            )
            self.assertTrue(administrative["ok"], administrative)
            self.assertEqual(administrative["quarantined_count"], 1)

    def test_boundary_expansion_does_not_reintroduce_private_checkpoint(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            public_state = record_project_state(
                root,
                session_id="expanded-public-session",
                agent_id="expanded-public-agent",
                project_id="expanded-boundary-project",
                objective="PUBLIC EXPANDED BOUNDARY",
            )
            private_state = record_project_state(
                root,
                session_id="expanded-private-session",
                agent_id="expanded-private-agent",
                project_id="expanded-boundary-project",
                objective="PRIVATE EXPANDED BOUNDARY",
                metadata={"visibility_scope": "private"},
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET visibility_scope = 'project' WHERE id = ?",
                    (private_state["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [str(private_state["card_id"])])
            private_sidecar = (
                root / "catalog" / "cards" / f"{private_state['card_id']}.yaml"
            )
            conn = connect(root)
            try:
                private_before = tuple(
                    conn.execute(
                        "SELECT * FROM cards WHERE id = ?",
                        (private_state["card_id"],),
                    ).fetchone()
                )
            finally:
                conn.close()
            sidecar_before = private_sidecar.read_bytes()

            preview = repair_invalid_project_state_checkpoints(
                root,
                project_id="expanded-boundary-project",
                dry_run=True,
            )
            applied = repair_invalid_project_state_checkpoints(
                root,
                project_id="expanded-boundary-project",
                dry_run=False,
            )
            resumed = resume_latest(
                root,
                project_id="expanded-boundary-project",
                model_assist=False,
            )

            for result in (preview, applied, resumed):
                self._assert_checkpoint_markers_not_disclosed(
                    result,
                    private_state,
                    "expanded-private-session",
                    "PRIVATE EXPANDED BOUNDARY",
                )
            self.assertEqual(preview["quarantined_count"], 0)
            self.assertEqual(applied["quarantined_count"], 0)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                public_state["card_id"],
            )
            conn = connect(root)
            try:
                private_after = tuple(
                    conn.execute(
                        "SELECT * FROM cards WHERE id = ?",
                        (private_state["card_id"],),
                    ).fetchone()
                )
            finally:
                conn.close()
            self.assertEqual(private_after, private_before)
            self.assertEqual(private_sidecar.read_bytes(), sidecar_before)

    def test_resume_rejects_cross_coordinate_and_unscoped_private_drift(
        self,
    ) -> None:
        cases: tuple[
            tuple[str, dict[str, str], str, dict[str, str]], ...
        ] = (
            (
                "project",
                {"project_id": "resume-drift-project-b"},
                "UPDATE cards SET project_id = 'resume-drift-project-b' WHERE id = ?",
                {},
            ),
            (
                "session",
                {"session_id": "resume-drift-session-b"},
                "UPDATE cards SET session_id = 'resume-drift-session-b' WHERE id = ?",
                {"visibility_scope": "session"},
            ),
            (
                "private",
                {},
                "UPDATE cards SET visibility_scope = 'project' WHERE id = ?",
                {"visibility_scope": "private"},
            ),
        )
        for scope, resume_kwargs, mutation, metadata in cases:
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                state = record_project_state(
                    root,
                    session_id=f"resume-drift-{scope}-a",
                    agent_id=f"resume-drift-{scope}-agent",
                    project_id=(
                        "resume-drift-project-a"
                        if scope == "project"
                        else f"resume-drift-{scope}-project"
                    ),
                    objective=f"RESUME DRIFT {scope.upper()} MARKER",
                    metadata=metadata,
                )
                conn = connect(root)
                try:
                    conn.execute(mutation, (state["card_id"],))
                    conn.commit()
                finally:
                    conn.close()
                sync_card_sidecars_after_commit(root, [str(state["card_id"])])

                if "project_id" in resume_kwargs:
                    result = resume_latest(
                        root,
                        project_id=resume_kwargs["project_id"],
                        model_assist=False,
                    )
                elif "session_id" in resume_kwargs:
                    result = resume_latest(
                        root,
                        session_id=resume_kwargs["session_id"],
                        model_assist=False,
                    )
                else:
                    result = resume_latest(root, model_assist=False)

                self.assertFalse(result["ok"], result)
                self.assertIn(
                    result["reason"],
                    {"no_current_project_state", "no_resume_state"},
                )
                self._assert_checkpoint_markers_not_disclosed(
                    result,
                    state,
                    f"resume-drift-{scope}-a",
                    f"RESUME DRIFT {scope.upper()} MARKER",
                )

    def test_private_backlinks_are_neither_disclosed_nor_mutated(self) -> None:
        for link_column in ("superseded_by_card_id", "supersedes_card_id"):
            with self.subTest(
                link_column=link_column
            ), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                public_state = record_project_state(
                    root,
                    session_id=f"backlink-public-{link_column}",
                    agent_id="backlink-public-agent",
                    project_id="backlink-public-project",
                )
                private_state = record_project_state(
                    root,
                    session_id=f"backlink-private-{link_column}",
                    agent_id="backlink-private-agent",
                    project_id="backlink-private-project",
                    objective=f"PRIVATE BACKLINK {link_column}",
                    metadata={"visibility_scope": "private"},
                )
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE cards SET summary = summary || ' damaged' "
                        "WHERE id = ?",
                        (public_state["card_id"],),
                    )
                    conn.execute(
                        f"UPDATE cards SET {link_column} = ? WHERE id = ?",
                        (public_state["card_id"], private_state["card_id"]),
                    )
                    conn.commit()
                finally:
                    conn.close()
                sync_card_sidecars_after_commit(
                    root,
                    [str(public_state["card_id"]), str(private_state["card_id"])],
                )
                private_sidecar = (
                    root
                    / "catalog"
                    / "cards"
                    / f"{private_state['card_id']}.yaml"
                )
                conn = connect(root)
                try:
                    private_before = tuple(
                        conn.execute(
                            "SELECT * FROM cards WHERE id = ?",
                            (private_state["card_id"],),
                        ).fetchone()
                    )
                finally:
                    conn.close()
                sidecar_before = private_sidecar.read_bytes()

                preview = repair_invalid_project_state_checkpoints(
                    root,
                    project_id="backlink-public-project",
                    dry_run=True,
                )
                applied = repair_invalid_project_state_checkpoints(
                    root,
                    project_id="backlink-public-project",
                    dry_run=False,
                )

                self.assertEqual(preview["quarantined_count"], 1, preview)
                self.assertEqual(applied["quarantined_count"], 1, applied)
                for result in (preview, applied):
                    self._assert_checkpoint_markers_not_disclosed(
                        result,
                        private_state,
                        f"backlink-private-{link_column}",
                        f"PRIVATE BACKLINK {link_column}",
                    )
                conn = connect(root)
                try:
                    private_after = tuple(
                        conn.execute(
                            "SELECT * FROM cards WHERE id = ?",
                            (private_state["card_id"],),
                        ).fetchone()
                    )
                finally:
                    conn.close()
                self.assertEqual(private_after, private_before)
                self.assertEqual(private_sidecar.read_bytes(), sidecar_before)

    def test_authorized_outbound_link_fails_closed_with_redacted_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            public_state = record_project_state(
                root,
                session_id="outbound-public-session",
                agent_id="outbound-public-agent",
                project_id="outbound-public-project",
            )
            private_state = record_project_state(
                root,
                session_id="outbound-private-session",
                agent_id="outbound-private-agent",
                project_id="outbound-private-project",
                objective="PRIVATE OUTBOUND TARGET",
                metadata={"visibility_scope": "private"},
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET supersedes_card_id = ? WHERE id = ?",
                    (private_state["card_id"], public_state["card_id"]),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [str(public_state["card_id"])])

            resumed = resume_latest(
                root,
                project_id="outbound-public-project",
                model_assist=False,
            )
            preview = repair_invalid_project_state_checkpoints(
                root,
                project_id="outbound-public-project",
                dry_run=True,
            )

            self.assertFalse(resumed["ok"], resumed)
            self.assertEqual(resumed["reason"], "authority_corrupt")
            self.assertFalse(preview["ok"], preview)
            for result in (resumed, preview):
                self._assert_checkpoint_markers_not_disclosed(
                    result,
                    private_state,
                    "outbound-private-session",
                    "PRIVATE OUTBOUND TARGET",
                )
                self.assertIn("redacted_cross_authority_link", json.dumps(result))

    def test_conflict_receipt_expansion_redacts_private_and_missing_members(
        self,
    ) -> None:
        for missing_member in (False, True):
            with self.subTest(
                missing_member=missing_member
            ), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                first = record_project_state(
                    root,
                    session_id=f"receipt-first-{missing_member}",
                    agent_id="receipt-first-agent",
                    project_id="receipt-public-project",
                )
                selected = record_project_state(
                    root,
                    session_id=f"receipt-selected-{missing_member}",
                    agent_id="receipt-selected-agent",
                    project_id="receipt-public-project",
                )
                resolve_conflict(
                    root,
                    card_id=str(selected["card_id"]),
                    action="supersede",
                    superseded_card_ids=[str(first["card_id"])],
                )
                private_state = record_project_state(
                    root,
                    session_id=f"receipt-private-{missing_member}",
                    agent_id="receipt-private-agent",
                    project_id="receipt-private-project",
                    objective=f"PRIVATE RECEIPT {missing_member}",
                    metadata={"visibility_scope": "private"},
                )
                replacement_id = (
                    "card_PRIVATE_DELETED_MARKER"
                    if missing_member
                    else str(private_state["card_id"])
                )
                conn = connect(root)
                try:
                    receipt_id = str(
                        conn.execute(
                            "SELECT id FROM conflict_resolution_receipts "
                            "ORDER BY created_at DESC, id DESC LIMIT 1"
                        ).fetchone()["id"]
                    )
                    conn.execute("PRAGMA foreign_keys = OFF")
                    conn.execute(
                        "UPDATE conflict_resolution_members SET card_id = ? "
                        "WHERE receipt_id = ? AND card_id = ?",
                        (replacement_id, receipt_id, first["card_id"]),
                    )
                    conn.commit()
                finally:
                    conn.close()

                resumed = resume_latest(
                    root,
                    project_id="receipt-public-project",
                    model_assist=False,
                )
                preview = repair_invalid_project_state_checkpoints(
                    root,
                    project_id="receipt-public-project",
                    dry_run=True,
                )

                self.assertFalse(resumed["ok"], resumed)
                self.assertFalse(preview["ok"], preview)
                for result in (resumed, preview):
                    serialized = json.dumps(result, sort_keys=True)
                    self.assertNotIn(replacement_id, serialized)
                    self.assertIn(
                        "redacted_cross_authority_conflict_receipt",
                        serialized,
                    )
                    self.assertIn("redacted_member_count", serialized)
                    if not missing_member:
                        self._assert_checkpoint_markers_not_disclosed(
                            result,
                            private_state,
                            f"receipt-private-{missing_member}",
                            f"PRIVATE RECEIPT {missing_member}",
                        )

    def test_zero_claim_source_and_private_identity_claim_fail_closed(self) -> None:
        for case in ("zero_claim", "private_identity"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                private_state = record_project_state(
                    root,
                    session_id=f"claim-{case}-session",
                    agent_id=f"claim-{case}-agent",
                    project_id="claim-scope-project",
                    objective=f"PRIVATE CLAIM {case}",
                    metadata={"visibility_scope": "private"},
                )
                conn = connect(root)
                try:
                    if case == "zero_claim":
                        conn.execute(
                            "UPDATE cards SET visibility_scope = 'project', "
                            "metadata_json = '{}' WHERE id = ?",
                            (private_state["card_id"],),
                        )
                        conn.execute(
                            "UPDATE scroll_events SET visibility_scope = 'bogus', "
                            "metadata_json = '{}' WHERE id = ?",
                            (private_state["event_id"],),
                        )
                        conn.execute(
                            "DELETE FROM audit_events WHERE target_id IN (?, ?)",
                            (private_state["card_id"], private_state["event_id"]),
                        )
                    else:
                        conn.execute(
                            "UPDATE cards SET visibility_scope = 'project', "
                            "metadata_json = json_set(metadata_json, "
                            "'$.visibility_scope', 'project') WHERE id = ?",
                            (private_state["card_id"],),
                        )
                        conn.execute(
                            "UPDATE scroll_events SET metadata_json = "
                            "json_set(metadata_json, '$.visibility_scope', 'project') "
                            "WHERE id = ?",
                            (private_state["event_id"],),
                        )
                    conn.execute(
                        "DELETE FROM queue_jobs WHERE job_type = "
                        "'review_card_placement' AND "
                        "json_extract(payload_json, '$.card_id') = ?",
                        (private_state["card_id"],),
                    )
                    conn.commit()
                finally:
                    conn.close()
                sidecar = (
                    root
                    / "catalog"
                    / "cards"
                    / f"{private_state['card_id']}.yaml"
                )
                if case == "zero_claim":
                    sidecar.unlink(missing_ok=True)
                else:
                    sync_card_sidecars_after_commit(
                        root,
                        [str(private_state["card_id"])],
                    )

                preview = repair_invalid_project_state_checkpoints(
                    root,
                    project_id="claim-scope-project",
                    dry_run=True,
                )

                self.assertEqual(preview["quarantined_count"], 0, preview)
                self._assert_checkpoint_markers_not_disclosed(
                    preview,
                    private_state,
                    f"claim-{case}-session",
                    f"PRIVATE CLAIM {case}",
                )

    def test_retained_queue_claim_requires_exact_official_placement_footprint(
        self,
    ) -> None:
        scenarios = (
            ("exact", True),
            ("wrong_role", False),
            ("raw_dedupe", False),
            ("extra_payload", False),
            ("extra_related", False),
            ("invalid_event_id", False),
            ("nonexistent_event", False),
            ("wrong_existing_event", False),
            ("lookalike_existing_event", False),
        )
        for scenario, recognized in scenarios:
            with self.subTest(
                scenario=scenario
            ), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                session_id = f"retained-queue-{scenario}-session"
                objective = f"PRIVATE RETAINED QUEUE {scenario}"
                project_id = "retained-queue-project"
                state = record_project_state(
                    root,
                    session_id=session_id,
                    agent_id="retained-queue-agent",
                    project_id=project_id,
                    objective=objective,
                    metadata={"visibility_scope": "private"},
                )
                replacement_event: dict[str, Any] | None = None
                if scenario == "wrong_existing_event":
                    replacement_event = append_scroll_event(
                        root,
                        session_id=f"{session_id}-ordinary",
                        event_type="project_state",
                        role="agent",
                        content="ordinary project-state lookalike",
                        metadata={
                            "project_id": project_id,
                            "visibility_scope": "project",
                            "source_type": "ordinary-note",
                        },
                    )
                elif scenario == "lookalike_existing_event":
                    payload_hash = "b" * 64
                    replacement_event = append_scroll_event(
                        root,
                        session_id=session_id,
                        event_type="project_state",
                        role="agent",
                        content="\n".join(
                            [
                                f"Project state for {project_id}",
                                "Agent: retained-queue-agent",
                                f"Objective: {objective}",
                                "Continuum-State-Payload-SHA256: "
                                + payload_hash,
                            ]
                        ),
                        metadata={
                            "agent_id": "retained-queue-agent",
                            "project_id": project_id,
                            "session_id": session_id,
                            "source_type": "project_state",
                            "trust_level": "agent_reported_local_evidence",
                            "instruction_authority": "user_level_evidence",
                            "continuum_disable_exact_memory": True,
                            "state_payload_hash": payload_hash,
                            "visibility_scope": "private",
                        },
                    )
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE cards SET visibility_scope = 'project', "
                        "metadata_json = '{}', source_refs_json = '[]' "
                        "WHERE id = ?",
                        (state["card_id"],),
                    )
                    conn.execute(
                        "DELETE FROM audit_events WHERE target_id = ?",
                        (state["card_id"],),
                    )
                    if scenario == "wrong_role":
                        conn.execute(
                            "UPDATE queue_jobs SET role = 'scribe' "
                            "WHERE job_type = 'review_card_placement' AND "
                            "json_extract(payload_json, '$.card_id') = ?",
                            (state["card_id"],),
                        )
                    elif scenario == "raw_dedupe":
                        conn.execute(
                            "UPDATE queue_jobs SET dedupe_key = ? "
                            "WHERE job_type = 'review_card_placement' AND "
                            "json_extract(payload_json, '$.card_id') = ?",
                            (f"card:{state['card_id']}", state["card_id"]),
                        )
                    elif scenario == "extra_payload":
                        conn.execute(
                            "UPDATE queue_jobs SET payload_json = "
                            "json_set(payload_json, '$.unexpected', 'value') "
                            "WHERE job_type = 'review_card_placement' AND "
                            "json_extract(payload_json, '$.card_id') = ?",
                            (state["card_id"],),
                        )
                    elif scenario == "extra_related":
                        conn.execute(
                            "UPDATE queue_jobs SET related_card_ids_json = ? "
                            "WHERE job_type = 'review_card_placement' AND "
                            "json_extract(payload_json, '$.card_id') = ?",
                            (
                                json.dumps(
                                    [state["card_id"], "card_unrelated"]
                                ),
                                state["card_id"],
                            ),
                        )
                    elif scenario == "invalid_event_id":
                        conn.execute(
                            "UPDATE queue_jobs SET payload_json = "
                            "json_set(payload_json, '$.event_id', 'ordinary-event') "
                            "WHERE job_type = 'review_card_placement' AND "
                            "json_extract(payload_json, '$.card_id') = ?",
                            (state["card_id"],),
                        )
                    elif scenario == "nonexistent_event":
                        conn.execute(
                            "UPDATE queue_jobs SET payload_json = "
                            "json_set(payload_json, '$.event_id', "
                            "'evt_000000000000000000000000') "
                            "WHERE job_type = 'review_card_placement' AND "
                            "json_extract(payload_json, '$.card_id') = ?",
                            (state["card_id"],),
                        )
                    elif scenario in {
                        "wrong_existing_event",
                        "lookalike_existing_event",
                    }:
                        assert replacement_event is not None
                        conn.execute(
                            "UPDATE queue_jobs SET payload_json = "
                            "json_set(payload_json, '$.event_id', ?) "
                            "WHERE job_type = 'review_card_placement' AND "
                            "json_extract(payload_json, '$.card_id') = ?",
                            (
                                replacement_event["event_id"],
                                state["card_id"],
                            ),
                        )
                    conn.commit()
                finally:
                    conn.close()
                self._remove_card_sidecar(root, state)

                preview = self._assert_project_only_withholds_checkpoint(
                    root,
                    state,
                    project_id=project_id,
                    markers=(session_id, objective),
                )

                self.assertEqual(
                    preview["withheld_uncertain_candidate_count"],
                    0 if recognized else 1,
                    preview,
                )

    def test_retained_card_metadata_requires_official_modern_or_legacy_shape(
        self,
    ) -> None:
        scenarios = (
            ("modern", True),
            ("modern_with_instruction", True),
            ("v021", True),
            ("matching_modern", False),
            ("matching_v021", False),
            ("legacy_empty_hash", False),
            ("legacy_false_disable", False),
            ("modern_null_instruction", False),
            ("v021_null_instruction", False),
            ("ordinary", False),
            ("wrong_source_type", False),
            ("missing_agent", False),
            ("wrong_instruction", False),
        )
        for scenario, recognized in scenarios:
            with self.subTest(
                scenario=scenario
            ), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                session_id = f"retained-metadata-{scenario}-session"
                objective = f"PRIVATE RETAINED METADATA {scenario}"
                project_id = "retained-metadata-project"
                state = record_project_state(
                    root,
                    session_id=session_id,
                    agent_id="retained-metadata-agent",
                    project_id=project_id,
                    objective=objective,
                    metadata={"visibility_scope": "private"},
                )
                conn = connect(root)
                try:
                    metadata = json.loads(
                        str(
                            conn.execute(
                                "SELECT metadata_json FROM cards WHERE id = ?",
                                (state["card_id"],),
                            ).fetchone()[0]
                        )
                    )
                    if scenario == "v021":
                        metadata.pop("state_payload_hash", None)
                        metadata.pop("continuum_disable_exact_memory", None)
                    elif scenario == "matching_modern":
                        metadata["visibility_scope"] = "project"
                    elif scenario == "matching_v021":
                        metadata.pop("state_payload_hash", None)
                        metadata.pop("continuum_disable_exact_memory", None)
                        metadata["visibility_scope"] = "project"
                    elif scenario == "legacy_empty_hash":
                        metadata["state_payload_hash"] = ""
                        metadata.pop("continuum_disable_exact_memory", None)
                    elif scenario == "legacy_false_disable":
                        metadata.pop("state_payload_hash", None)
                        metadata["continuum_disable_exact_memory"] = False
                    elif scenario == "modern_null_instruction":
                        metadata["instruction_authority"] = None
                    elif scenario == "v021_null_instruction":
                        metadata.pop("state_payload_hash", None)
                        metadata.pop("continuum_disable_exact_memory", None)
                        metadata["instruction_authority"] = None
                    elif scenario == "modern_with_instruction":
                        metadata["instruction_authority"] = (
                            "user_level_evidence"
                        )
                    elif scenario == "ordinary":
                        metadata = {
                            "visibility_scope": "private",
                            "project_id": project_id,
                            "session_id": session_id,
                            "source_type": "ordinary-note",
                        }
                    elif scenario == "wrong_source_type":
                        metadata["source_type"] = "ordinary-note"
                    elif scenario == "missing_agent":
                        metadata.pop("agent_id", None)
                    elif scenario == "wrong_instruction":
                        metadata["instruction_authority"] = "ordinary-note"
                    conn.execute(
                        "UPDATE cards SET visibility_scope = 'project', "
                        "metadata_json = ?, source_refs_json = '[]' WHERE id = ?",
                        (json.dumps(metadata, sort_keys=True), state["card_id"]),
                    )
                    conn.execute(
                        "DELETE FROM scroll_events WHERE id = ?",
                        (state["event_id"],),
                    )
                    conn.execute(
                        "DELETE FROM queue_jobs WHERE job_type = "
                        "'review_card_placement' AND "
                        "json_extract(payload_json, '$.card_id') = ?",
                        (state["card_id"],),
                    )
                    conn.execute(
                        "DELETE FROM audit_events WHERE target_id IN (?, ?)",
                        (state["card_id"], state["event_id"]),
                    )
                    conn.commit()
                finally:
                    conn.close()
                self._remove_card_sidecar(root, state)

                preview = self._assert_project_only_withholds_checkpoint(
                    root,
                    state,
                    project_id=project_id,
                    markers=(session_id, objective),
                )

                self.assertEqual(
                    preview["withheld_uncertain_candidate_count"],
                    0 if recognized else 1,
                    preview,
                )

    def test_retained_supersession_claim_requires_exact_official_audit(
        self,
    ) -> None:
        scenarios = (
            ("exact", True),
            ("wrong_actor", False),
            ("wrong_target_type", False),
            ("extra_payload", False),
            ("extra_authority", False),
            ("missing_member", False),
        )
        for scenario, recognized in scenarios:
            with self.subTest(
                scenario=scenario
            ), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                session_id = f"supersession-audit-{scenario}-session"
                project_id = "supersession-audit-project"
                agent_id = "supersession-audit-agent"
                objective = f"PRIVATE SUPERSESSION AUDIT {scenario}"
                first = record_project_state(
                    root,
                    session_id=session_id,
                    agent_id=agent_id,
                    project_id=project_id,
                    objective=objective,
                    metadata={"visibility_scope": "private"},
                )
                second = record_project_state(
                    root,
                    session_id=session_id,
                    agent_id=agent_id,
                    project_id=project_id,
                    objective=f"successor {scenario}",
                    metadata={"visibility_scope": "private"},
                )
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE cards SET visibility_scope = 'project', "
                        "metadata_json = '{}', source_refs_json = '[]' "
                        "WHERE id = ?",
                        (first["card_id"],),
                    )
                    conn.execute(
                        "DELETE FROM queue_jobs WHERE job_type = "
                        "'review_card_placement' AND "
                        "json_extract(payload_json, '$.card_id') = ?",
                        (first["card_id"],),
                    )
                    conn.execute(
                        "DELETE FROM audit_events WHERE target_id = ?",
                        (first["card_id"],),
                    )
                    if scenario == "wrong_actor":
                        conn.execute(
                            "UPDATE audit_events SET actor = 'ordinary-agent' "
                            "WHERE action = 'project_state_superseded' AND "
                            "target_id = ?",
                            (second["card_id"],),
                        )
                    elif scenario == "wrong_target_type":
                        conn.execute(
                            "UPDATE audit_events SET target_type = 'ordinary-note' "
                            "WHERE action = 'project_state_superseded' AND "
                            "target_id = ?",
                            (second["card_id"],),
                        )
                    elif scenario == "extra_payload":
                        conn.execute(
                            "UPDATE audit_events SET payload_json = "
                            "json_set(payload_json, '$.unexpected', 'value') "
                            "WHERE action = 'project_state_superseded' AND "
                            "target_id = ?",
                            (second["card_id"],),
                        )
                    elif scenario == "extra_authority":
                        conn.execute(
                            "UPDATE audit_events SET payload_json = "
                            "json_set(payload_json, '$.authority.unexpected', "
                            "'value') WHERE action = "
                            "'project_state_superseded' AND target_id = ?",
                            (second["card_id"],),
                        )
                    elif scenario == "missing_member":
                        conn.execute(
                            "UPDATE audit_events SET payload_json = "
                            "json_set(payload_json, '$.superseded_card_ids', "
                            "json_array('card_000000000000000000000000')) "
                            "WHERE action = 'project_state_superseded' AND "
                            "target_id = ?",
                            (second["card_id"],),
                        )
                    conn.commit()
                finally:
                    conn.close()
                self._remove_card_sidecar(root, first)

                preview = self._assert_project_only_withholds_checkpoint(
                    root,
                    first,
                    project_id=project_id,
                    markers=(session_id, objective),
                )

                self.assertEqual(
                    preview["withheld_uncertain_candidate_count"],
                    0 if recognized else 1,
                    preview,
                )

    def test_official_modern_and_v021_sources_retain_narrow_authority(self) -> None:
        for variant in ("modern", "v021"):
            with self.subTest(
                variant=variant
            ), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                session_id = f"official-source-{variant}-session"
                project_id = "official-source-project"
                objective = f"PRIVATE OFFICIAL SOURCE {variant}"
                if variant == "modern":
                    state = record_project_state(
                        root,
                        session_id=session_id,
                        agent_id="official-source-agent",
                        project_id=project_id,
                        objective=objective,
                        metadata={"visibility_scope": "private"},
                    )
                else:
                    state = self._record_v021_project_state(
                        root,
                        session_id=session_id,
                        agent_id="official-source-agent",
                        project_id=project_id,
                        objective=objective,
                        visibility_scope="private",
                    )
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE cards SET visibility_scope = 'project', "
                        "metadata_json = '{}', summary = summary || ' damaged' "
                        "WHERE id = ?",
                        (state["card_id"],),
                    )
                    if variant == "modern":
                        conn.execute(
                            "DELETE FROM queue_jobs WHERE job_type = "
                            "'review_card_placement' AND "
                            "json_extract(payload_json, '$.card_id') = ?",
                            (state["card_id"],),
                        )
                    conn.commit()
                finally:
                    conn.close()
                self._remove_card_sidecar(root, state)

                conn = connect(root)
                try:
                    card_row = conn.execute(
                        f"SELECT {store_module._PROJECT_STATE_AUTHORITY_SELECT_FIELDS} "
                        "FROM cards WHERE id = ?",
                        (state["card_id"],),
                    ).fetchone()
                    source_rows = (
                        store_module._project_state_bound_source_rows_by_card_id(
                            conn,
                            [str(state["card_id"])],
                            page_size=256,
                        )[str(state["card_id"])]
                    )
                    signals = store_module._project_state_durable_authority_signals(
                        root,
                        conn,
                        card_row,
                        source_rows=source_rows,
                    )
                finally:
                    conn.close()

                self.assertIn(
                    ("private", project_id, session_id),
                    signals["source_claims"],
                    signals,
                )
                preview = self._assert_project_only_withholds_checkpoint(
                    root,
                    state,
                    project_id=project_id,
                    markers=(session_id, objective),
                )
                self.assertEqual(
                    preview["withheld_uncertain_candidate_count"],
                    0,
                    preview,
                )

    def test_ordinary_rebound_source_ref_is_coordinate_only_and_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            session_id = "ordinary-rebound-private-session"
            project_id = "ordinary-rebound-project"
            objective = "PRIVATE ORDINARY REBOUND SOURCE"
            state = record_project_state(
                root,
                session_id=session_id,
                agent_id="ordinary-rebound-agent",
                project_id=project_id,
                objective=objective,
                metadata={"visibility_scope": "private"},
            )
            ordinary = append_scroll_event(
                root,
                session_id="ordinary-rebound-visible-session",
                event_type="project_state",
                role="agent",
                content="ordinary project-state lookalike",
                metadata={
                    "project_id": project_id,
                    "visibility_scope": "project",
                    "source_type": "ordinary-note",
                    "trust_level": "ordinary-local-note",
                },
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET visibility_scope = 'project', "
                    "metadata_json = '{}', summary = summary || ' damaged', "
                    "source_refs_json = ? WHERE id = ?",
                    (
                        json.dumps(
                            [
                                {
                                    "event_id": ordinary["event_id"],
                                    "session_id": ordinary["session_id"],
                                    "seq": ordinary["seq"],
                                }
                            ],
                            sort_keys=True,
                        ),
                        state["card_id"],
                    ),
                )
                conn.execute(
                    "DELETE FROM scroll_events WHERE id = ?",
                    (state["event_id"],),
                )
                conn.execute(
                    "DELETE FROM queue_jobs WHERE job_type = "
                    "'review_card_placement' AND "
                    "json_extract(payload_json, '$.card_id') = ?",
                    (state["card_id"],),
                )
                conn.execute(
                    "DELETE FROM audit_events WHERE target_id IN (?, ?, ?)",
                    (
                        state["card_id"],
                        state["event_id"],
                        ordinary["event_id"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()
            self._remove_card_sidecar(root, state)

            conn = connect(root)
            try:
                card_row = conn.execute(
                    f"SELECT {store_module._PROJECT_STATE_AUTHORITY_SELECT_FIELDS} "
                    "FROM cards WHERE id = ?",
                    (state["card_id"],),
                ).fetchone()
                source_rows = (
                    store_module._project_state_bound_source_rows_by_card_id(
                        conn,
                        [str(state["card_id"])],
                        page_size=256,
                    )[str(state["card_id"])]
                )
                signals = store_module._project_state_durable_authority_signals(
                    root,
                    conn,
                    card_row,
                    source_rows=source_rows,
                )
            finally:
                conn.close()

            self.assertEqual(signals["source_claims"], set(), signals)
            preview = self._assert_project_only_withholds_checkpoint(
                root,
                state,
                project_id=project_id,
                markers=(session_id, objective),
            )
            self.assertEqual(
                preview["withheld_uncertain_candidate_count"],
                1,
                preview,
            )

    def test_modern_source_impersonator_cannot_borrow_generic_card_audit(
        self,
    ) -> None:
        for retain_card_audits in (True, False):
            with self.subTest(
                retain_card_audits=retain_card_audits
            ), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                private_session = (
                    f"modern-impersonation-private-{int(retain_card_audits)}"
                )
                project_id = "modern-impersonation-project"
                objective = (
                    f"PRIVATE MODERN IMPERSONATION {int(retain_card_audits)}"
                )
                state = record_project_state(
                    root,
                    session_id=private_session,
                    agent_id="private-modern-agent",
                    project_id=project_id,
                    objective=objective,
                    metadata={"visibility_scope": "private"},
                )
                payload_hash = "c" * 64
                impersonator = append_scroll_event(
                    root,
                    session_id="modern-impersonation-public-session",
                    event_type="project_state",
                    role="agent",
                    content="\n".join(
                        [
                            f"Project state for {project_id}",
                            "Agent: public-modern-agent",
                            "Objective: ordinary public impersonator",
                            "Continuum-State-Payload-SHA256: " + payload_hash,
                        ]
                    ),
                    metadata={
                        "agent_id": "public-modern-agent",
                        "project_id": project_id,
                        "source_type": "project_state",
                        "trust_level": "agent_reported_local_evidence",
                        "instruction_authority": "user_level_evidence",
                        "continuum_disable_exact_memory": True,
                        "state_payload_hash": payload_hash,
                        "visibility_scope": "project",
                    },
                )
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE cards SET visibility_scope = 'project', "
                        "metadata_json = '{}', summary = summary || ' damaged', "
                        "source_refs_json = ? WHERE id = ?",
                        (
                            json.dumps(
                                [
                                    {
                                        "event_id": impersonator["event_id"],
                                        "session_id": impersonator["session_id"],
                                        "seq": impersonator["seq"],
                                    }
                                ],
                                sort_keys=True,
                            ),
                            state["card_id"],
                        ),
                    )
                    conn.execute(
                        "DELETE FROM scroll_events WHERE id = ?",
                        (state["event_id"],),
                    )
                    conn.execute(
                        "DELETE FROM queue_jobs WHERE job_type = "
                        "'review_card_placement' AND "
                        "json_extract(payload_json, '$.card_id') = ?",
                        (state["card_id"],),
                    )
                    conn.execute(
                        "DELETE FROM audit_events WHERE target_id = ?",
                        (state["event_id"],),
                    )
                    if not retain_card_audits:
                        conn.execute(
                            "DELETE FROM audit_events WHERE target_id = ?",
                            (state["card_id"],),
                        )
                    conn.commit()
                finally:
                    conn.close()
                self._remove_card_sidecar(root, state)

                preview = self._assert_project_only_withholds_checkpoint(
                    root,
                    state,
                    project_id=project_id,
                    markers=(private_session, objective),
                )
                self.assertEqual(
                    preview["withheld_uncertain_candidate_count"],
                    1,
                    preview,
                )

    def test_graph_pair_cannot_rewrite_append_audit_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            session_id = "graph-boundary-private-session"
            project_id = "graph-boundary-project"
            objective = "PRIVATE GRAPH APPEND BOUNDARY"
            state = record_project_state(
                root,
                session_id=session_id,
                agent_id="graph-boundary-agent",
                project_id=project_id,
                objective=objective,
                metadata={"visibility_scope": "private"},
            )
            conn = connect(root)
            try:
                source_metadata = json.loads(
                    str(
                        conn.execute(
                            "SELECT metadata_json FROM scroll_events WHERE id = ?",
                            (state["event_id"],),
                        ).fetchone()[0]
                    )
                )
                source_metadata["visibility_scope"] = "project"
                card_metadata = dict(source_metadata)
                card_metadata.pop("instruction_authority", None)
                conn.execute(
                    "UPDATE scroll_events SET visibility_scope = 'project', "
                    "project_id = ?, metadata_json = ? WHERE id = ?",
                    (
                        project_id,
                        json.dumps(source_metadata, sort_keys=True),
                        state["event_id"],
                    ),
                )
                conn.execute(
                    "UPDATE cards SET visibility_scope = 'project', "
                    "metadata_json = ?, summary = summary || ' damaged' "
                    "WHERE id = ?",
                    (
                        json.dumps(card_metadata, sort_keys=True),
                        state["card_id"],
                    ),
                )
                conn.execute(
                    "DELETE FROM queue_jobs WHERE job_type = "
                    "'review_card_placement' AND "
                    "json_extract(payload_json, '$.card_id') = ?",
                    (state["card_id"],),
                )
                conn.execute(
                    "DELETE FROM audit_events WHERE target_id = ?",
                    (state["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            self._remove_card_sidecar(root, state)

            preview = self._assert_project_only_withholds_checkpoint(
                root,
                state,
                project_id=project_id,
                markers=(session_id, objective),
            )
            self.assertEqual(
                preview["withheld_uncertain_candidate_count"],
                1,
                preview,
            )

    def test_matching_resynced_sidecar_cannot_become_primary_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            session_id = "matching-sidecar-private-session"
            project_id = "matching-sidecar-project"
            objective = "PRIVATE MATCHING RESYNCED SIDECAR"
            state = record_project_state(
                root,
                session_id=session_id,
                agent_id="matching-sidecar-agent",
                project_id=project_id,
                objective=objective,
                metadata={"visibility_scope": "private"},
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET visibility_scope = 'project', "
                    "metadata_json = '{}', source_refs_json = '[]', "
                    "summary = summary || ' damaged' WHERE id = ?",
                    (state["card_id"],),
                )
                conn.execute(
                    "DELETE FROM scroll_events WHERE id = ?",
                    (state["event_id"],),
                )
                conn.execute(
                    "DELETE FROM queue_jobs WHERE job_type = "
                    "'review_card_placement' AND "
                    "json_extract(payload_json, '$.card_id') = ?",
                    (state["card_id"],),
                )
                conn.execute(
                    "DELETE FROM audit_events WHERE target_id IN (?, ?)",
                    (state["card_id"], state["event_id"]),
                )
                conn.commit()
            finally:
                conn.close()
            self._remove_card_sidecar(root, state)
            sync_card_sidecars_after_commit(root, [str(state["card_id"])])
            conn = connect(root)
            try:
                before = tuple(
                    conn.execute(
                        "SELECT * FROM cards WHERE id = ?",
                        (state["card_id"],),
                    ).fetchone()
                )
            finally:
                conn.close()

            preview = self._assert_project_only_withholds_checkpoint(
                root,
                state,
                project_id=project_id,
                markers=(session_id, objective),
            )
            applied = repair_invalid_project_state_checkpoints(
                root,
                project_id=project_id,
                dry_run=False,
            )
            self.assertEqual(
                preview["withheld_uncertain_candidate_count"],
                1,
                preview,
            )
            self.assertEqual(applied["quarantined_count"], 0, applied)
            self._assert_checkpoint_markers_not_disclosed(
                applied,
                state,
                session_id,
                objective,
            )
            conn = connect(root)
            try:
                after = tuple(
                    conn.execute(
                        "SELECT * FROM cards WHERE id = ?",
                        (state["card_id"],),
                    ).fetchone()
                )
            finally:
                conn.close()
            self.assertEqual(after, before)

    def test_preserved_divergent_sidecar_remains_a_narrow_constraint(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            session_id = "divergent-sidecar-private-session"
            project_id = "divergent-sidecar-project"
            objective = "PRIVATE PRESERVED SIDECAR CONSTRAINT"
            state = record_project_state(
                root,
                session_id=session_id,
                agent_id="divergent-sidecar-agent",
                project_id=project_id,
                objective=objective,
                metadata={"visibility_scope": "private"},
            )
            conn = connect(root)
            try:
                location_uri = conn.execute(
                    "SELECT location_uri FROM cards WHERE id = ?",
                    (state["card_id"],),
                ).fetchone()["location_uri"]
                immutable_path = store_module.resolve_stored_uri(root, location_uri)
                immutable_bytes = immutable_path.read_bytes()
                store_module.record_artifact(
                    conn,
                    kind="proof_input",
                    uri=location_uri,
                    sha256=hashlib.sha256(immutable_bytes).hexdigest(),
                    size_bytes=len(immutable_bytes),
                    source_type="preserved_project_state_sidecar",
                    trust_level="local_generated",
                    immutable=True,
                )
                conn.execute(
                    "UPDATE cards SET visibility_scope = 'project', "
                    "metadata_json = '{}', source_refs_json = '[]', "
                    "summary = summary || ' damaged' WHERE id = ?",
                    (state["card_id"],),
                )
                conn.execute(
                    "DELETE FROM scroll_events WHERE id = ?",
                    (state["event_id"],),
                )
                conn.execute(
                    "DELETE FROM queue_jobs WHERE job_type = "
                    "'review_card_placement' AND "
                    "json_extract(payload_json, '$.card_id') = ?",
                    (state["card_id"],),
                )
                conn.execute(
                    "DELETE FROM audit_events WHERE target_id IN (?, ?)",
                    (state["card_id"], state["event_id"]),
                )
                store_module.mark_card_sidecar_outbox(
                    conn,
                    [str(state["card_id"])],
                    reason="preserved_project_state_sidecar_drift",
                )
                conn.commit()
            finally:
                conn.close()

            sync_result = sync_card_sidecars_after_commit(
                root,
                [str(state["card_id"])],
            )
            self.assertTrue(sync_result["ok"], sync_result)
            self.assertEqual(immutable_path.read_bytes(), immutable_bytes)
            conn = connect(root)
            try:
                live_uri = conn.execute(
                    "SELECT location_uri FROM cards WHERE id = ?",
                    (state["card_id"],),
                ).fetchone()["location_uri"]
            finally:
                conn.close()
            self.assertNotEqual(
                store_module.resolve_stored_uri(root, live_uri),
                immutable_path,
            )

            preview = self._assert_project_only_withholds_checkpoint(
                root,
                state,
                project_id=project_id,
                markers=(session_id, objective),
            )
            self.assertEqual(
                preview["withheld_uncertain_candidate_count"],
                0,
                preview,
            )

    def test_disabling_future_sidecar_writes_preserves_existing_read_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="sidecar-read-toggle-session",
                agent_id="sidecar-read-toggle-agent",
                project_id="sidecar-read-toggle-project",
                objective="EXISTING SIDECAR REMAINS READ AUTHORITY",
            )
            before = resume_latest(
                root,
                project_id="sidecar-read-toggle-project",
                model_assist=False,
            )
            self.assertTrue(before["ok"], before)

            config = load_config(root)
            config["atomic_memory"]["write_card_sidecars"] = False
            write_config(root, config)

            after = resume_latest(
                root,
                project_id="sidecar-read-toggle-project",
                model_assist=False,
            )
            semantic = store_module.semantic_integrity_report(root)
            self.assertTrue(after["ok"], after)
            self.assertEqual(after["discovery"]["checkpoint_id"], state["card_id"])
            self.assertTrue(semantic["ok"], semantic)

            conn = connect(root)
            try:
                sidecar_uri = conn.execute(
                    "SELECT location_uri FROM cards WHERE id = ?",
                    (state["card_id"],),
                ).fetchone()["location_uri"]
            finally:
                conn.close()
            store_module.resolve_stored_uri(root, sidecar_uri).write_text(
                "not: [valid atomic memory",
                encoding="utf-8",
            )
            damaged = store_module.semantic_integrity_report(root)
            self.assertFalse(damaged["ok"], damaged)
            self.assertGreater(
                damaged["checks"]["malformed_card_sidecars"],
                0,
                damaged,
            )

    def test_unrelated_immutable_artifact_with_card_basename_is_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="unrelated-artifact-session",
                agent_id="unrelated-artifact-agent",
                project_id="unrelated-artifact-project",
                objective="UNRELATED ARTIFACT MUST NOT ALTER CARD AUTHORITY",
            )
            proof_path = root / "proofs" / f"{state['card_id']}.yaml"
            proof_path.parent.mkdir(parents=True)
            proof_bytes = b"ordinary proof bytes\n"
            proof_path.write_bytes(proof_bytes)
            conn = connect(root)
            try:
                store_module.record_artifact(
                    conn,
                    kind="proof_input",
                    uri=store_module.continuum_uri(root, proof_path),
                    sha256=hashlib.sha256(proof_bytes).hexdigest(),
                    size_bytes=len(proof_bytes),
                    immutable=True,
                )
                cards_dir = store_module._configured_card_sidecar_dir(root)
                verified, uncertain = store_module._verified_immutable_card_sidecars(
                    root,
                    conn,
                    cards_dir,
                )
                conn.commit()
            finally:
                conn.close()

            resumed = resume_latest(
                root,
                project_id="unrelated-artifact-project",
                model_assist=False,
            )
            self.assertNotIn(state["card_id"], verified)
            self.assertNotIn(state["card_id"], uncertain)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["discovery"]["checkpoint_id"], state["card_id"])

    @unittest.skipUnless(os.name == "nt", "Windows path aliases are Windows-only")
    def test_windows_short_and_long_root_aliases_share_managed_sidecar_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="windows-sidecar-alias-session",
                agent_id="windows-sidecar-alias-agent",
                project_id="windows-sidecar-alias-project",
                objective="WINDOWS PATH ALIASES SHARE ONE SIDECAR",
            )
            conn = connect(root)
            try:
                location_uri = str(
                    conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (state["card_id"],),
                    ).fetchone()["location_uri"]
                )
                short_path = store_module.resolve_stored_uri(root, location_uri)
                long_path = short_path.resolve()
                if os.path.normcase(os.path.abspath(short_path)) == os.path.normcase(
                    os.path.abspath(long_path)
                ):
                    self.skipTest("temporary root has no distinct short/long spelling")
                sidecar_bytes = short_path.read_bytes()
                store_module.record_artifact(
                    conn,
                    kind="proof_input",
                    uri=str(long_path),
                    sha256=hashlib.sha256(sidecar_bytes).hexdigest(),
                    size_bytes=len(sidecar_bytes),
                    immutable=True,
                    source_type="preserved_project_state_sidecar",
                )
                conn.execute(
                    "UPDATE cards SET location_uri = ? WHERE id = ?",
                    (str(long_path), state["card_id"]),
                )
                cards_dir = short_path.parent
                verified, uncertain = store_module._verified_immutable_card_sidecars(
                    root,
                    conn,
                    cards_dir,
                )
                conn.commit()
            finally:
                conn.close()

            resumed = resume_latest(
                root,
                project_id="windows-sidecar-alias-project",
                model_assist=False,
            )
            semantic = store_module.semantic_integrity_report(root)
            self.assertIn(state["card_id"], verified)
            self.assertNotIn(state["card_id"], uncertain)
            self.assertTrue(resumed["ok"], resumed)
            self.assertTrue(semantic["ok"], semantic)

    @unittest.skipUnless(os.name == "posix", "real sidecar symlinks are POSIX-only")
    def test_immutable_sidecar_symlink_is_uncertain_and_not_orphan_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="immutable-sidecar-link-session",
                agent_id="immutable-sidecar-link-agent",
                project_id="immutable-sidecar-link-project",
                objective="LINKED IMMUTABLE ARTIFACT IS NOT CARD AUTHORITY",
            )
            conn = connect(root)
            try:
                location_uri = str(
                    conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (state["card_id"],),
                    ).fetchone()["location_uri"]
                )
                current_path = store_module.resolve_stored_uri(root, location_uri)
                backup_path = current_path.parent / "unrelated-backup.yaml"
                backup_path.write_bytes(current_path.read_bytes())
                linked_path = current_path.with_name(
                    f"{state['card_id']}.live-{'a' * 64}.yaml"
                )
                linked_path.symlink_to(backup_path.name)
                linked_bytes = linked_path.read_bytes()
                store_module.record_artifact(
                    conn,
                    kind="proof_input",
                    uri=store_module.lexical_continuum_uri(root, linked_path),
                    sha256=hashlib.sha256(linked_bytes).hexdigest(),
                    size_bytes=len(linked_bytes),
                    immutable=True,
                    source_type="preserved_project_state_sidecar",
                )
                verified, uncertain = store_module._verified_immutable_card_sidecars(
                    root,
                    conn,
                    current_path.parent,
                )
                sidecar_audit = store_module.audit_card_sidecars(root, conn)
                conn.commit()
            finally:
                conn.close()

            self.assertNotIn(
                linked_path,
                [path for path, _payload in verified.get(str(state["card_id"]), [])],
            )
            self.assertIn(state["card_id"], uncertain)
            self.assertEqual(sidecar_audit["orphan_card_sidecars"], 1, sidecar_audit)
            self.assertEqual(
                sidecar_audit["unsafe_card_sidecar_paths"],
                1,
                sidecar_audit,
            )

    def test_external_card_sidecar_uri_cannot_supply_repair_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            session_id = "external-sidecar-private-session"
            project_id = "external-sidecar-project"
            objective = "EXTERNAL SIDECAR MUST NOT BECOME AUTHORITY"
            state = record_project_state(
                root,
                session_id=session_id,
                agent_id="external-sidecar-agent",
                project_id=project_id,
                objective=objective,
                metadata={"visibility_scope": "private"},
            )
            conn = connect(root)
            try:
                location_uri = conn.execute(
                    "SELECT location_uri FROM cards WHERE id = ?",
                    (state["card_id"],),
                ).fetchone()["location_uri"]
                external_path = Path(tmp) / "attacker-controlled-card.yaml"
                external_path.write_bytes(
                    store_module.resolve_stored_uri(root, location_uri).read_bytes()
                )
                conn.execute(
                    "UPDATE cards SET visibility_scope = 'project', "
                    "metadata_json = '{}', source_refs_json = '[]', "
                    "summary = summary || ' damaged', location_uri = ? WHERE id = ?",
                    (str(external_path), state["card_id"]),
                )
                conn.execute(
                    "DELETE FROM scroll_events WHERE id = ?",
                    (state["event_id"],),
                )
                conn.execute(
                    "DELETE FROM queue_jobs WHERE job_type = "
                    "'review_card_placement' AND "
                    "json_extract(payload_json, '$.card_id') = ?",
                    (state["card_id"],),
                )
                conn.execute(
                    "DELETE FROM audit_events WHERE target_id IN (?, ?)",
                    (state["card_id"], state["event_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            sidecar_audit = store_module.audit(root)
            self.assertEqual(sidecar_audit["divergent_card_sidecars"], 1, sidecar_audit)
            self.assertEqual(sidecar_audit["orphan_card_sidecars"], 1, sidecar_audit)
            self.assertFalse(store_module.semantic_integrity_report(root)["ok"])
            preview = self._assert_project_only_withholds_checkpoint(
                root,
                state,
                project_id=project_id,
                markers=(session_id, objective),
            )
            self.assertEqual(
                preview["withheld_uncertain_candidate_count"],
                1,
                preview,
            )

    def test_matching_sidecar_does_not_block_independent_placement_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            project_id = "matching-sidecar-official-project"
            state = record_project_state(
                root,
                session_id="matching-sidecar-official-session",
                agent_id="matching-sidecar-official-agent",
                project_id=project_id,
                objective="PROJECT MATCHING SIDECAR WITH PLACEMENT",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET metadata_json = '{}', "
                    "source_refs_json = '[]', summary = summary || ' damaged' "
                    "WHERE id = ?",
                    (state["card_id"],),
                )
                conn.execute(
                    "DELETE FROM audit_events WHERE target_id = ?",
                    (state["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            self._remove_card_sidecar(root, state)
            sync_card_sidecars_after_commit(root, [str(state["card_id"])])

            preview = repair_invalid_project_state_checkpoints(
                root,
                project_id=project_id,
                dry_run=True,
            )

            self.assertEqual(preview["quarantined_count"], 1, preview)
            self.assertEqual(
                preview["quarantined"][0]["card_id"],
                state["card_id"],
                preview,
            )

    def test_cross_boundary_supersession_anchor_cannot_lend_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            project_id = "cross-boundary-supersession-project"
            private_session = "cross-boundary-private-session"
            objective = "PRIVATE CROSS BOUNDARY SUPERSESSION"
            candidate = record_project_state(
                root,
                session_id=private_session,
                agent_id="private-chain-agent",
                project_id=project_id,
                objective=objective,
                metadata={"visibility_scope": "private"},
            )
            anchor = record_project_state(
                root,
                session_id="cross-boundary-project-session",
                agent_id="project-chain-agent",
                project_id=project_id,
                objective="genuine project anchor",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET visibility_scope = 'project', "
                    "metadata_json = '{}', source_refs_json = '[]', "
                    "summary = summary || ' damaged', "
                    "superseded_by_card_id = ? WHERE id = ?",
                    (anchor["card_id"], candidate["card_id"]),
                )
                conn.execute(
                    "UPDATE cards SET supersedes_card_id = ? WHERE id = ?",
                    (candidate["card_id"], anchor["card_id"]),
                )
                conn.execute(
                    "DELETE FROM queue_jobs WHERE job_type = "
                    "'review_card_placement' AND "
                    "json_extract(payload_json, '$.card_id') = ?",
                    (candidate["card_id"],),
                )
                conn.execute(
                    "DELETE FROM audit_events WHERE target_id = ?",
                    (candidate["card_id"],),
                )
                store_module.audit_event(
                    conn,
                    action="project_state_superseded",
                    target_type="card",
                    target_id=str(anchor["card_id"]),
                    actor="project-chain-agent",
                    payload={
                        "authority": {
                            "visibility_scope": "project",
                            "session_id": None,
                            "project_id": project_id,
                            "agent_id": "project-chain-agent",
                        },
                        "direct_predecessor_card_id": candidate["card_id"],
                        "superseded_card_ids": [candidate["card_id"]],
                    },
                )
                conn.commit()
            finally:
                conn.close()
            self._remove_card_sidecar(root, candidate)

            preview = self._assert_project_only_withholds_checkpoint(
                root,
                candidate,
                project_id=project_id,
                markers=(private_session, objective),
            )
            self.assertEqual(
                preview["withheld_uncertain_candidate_count"],
                1,
                preview,
            )

    def test_project_mirrors_cannot_widen_current_private_or_session_card(
        self,
    ) -> None:
        for scope in ("private", "session"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                session_id = f"mirror-widen-{scope}-session"
                project_id = "mirror-widen-project"
                objective = f"NARROW MIRROR WIDEN {scope.upper()}"
                state = record_project_state(
                    root,
                    session_id=session_id,
                    agent_id="mirror-widen-agent",
                    project_id=project_id,
                    objective=objective,
                    metadata={"visibility_scope": scope},
                )
                ordinary = append_scroll_event(
                    root,
                    session_id=f"mirror-widen-public-{scope}",
                    event_type="project_state",
                    role="agent",
                    content="ordinary visible source",
                    metadata={
                        "project_id": project_id,
                        "visibility_scope": "project",
                        "source_type": "ordinary-note",
                    },
                )
                conn = connect(root)
                try:
                    original_metadata = json.loads(
                        str(
                            conn.execute(
                                "SELECT metadata_json FROM cards WHERE id = ?",
                                (state["card_id"],),
                            ).fetchone()[0]
                        )
                    )
                    original_metadata["visibility_scope"] = "project"
                    conn.execute(
                        "UPDATE cards SET visibility_scope = 'project', "
                        "metadata_json = ?, source_refs_json = ?, "
                        "summary = summary || ' damaged' WHERE id = ?",
                        (
                            json.dumps(original_metadata, sort_keys=True),
                            json.dumps(
                                [
                                    {
                                        "event_id": ordinary["event_id"],
                                        "session_id": ordinary["session_id"],
                                        "seq": ordinary["seq"],
                                    }
                                ],
                                sort_keys=True,
                            ),
                            state["card_id"],
                        ),
                    )
                    conn.execute(
                        "DELETE FROM scroll_events WHERE id = ?",
                        (state["event_id"],),
                    )
                    conn.execute(
                        "DELETE FROM queue_jobs WHERE job_type = "
                        "'review_card_placement' AND "
                        "json_extract(payload_json, '$.card_id') = ?",
                        (state["card_id"],),
                    )
                    conn.execute(
                        "DELETE FROM audit_events WHERE target_id IN (?, ?, ?)",
                        (
                            state["card_id"],
                            state["event_id"],
                            ordinary["event_id"],
                        ),
                    )
                    conn.commit()
                finally:
                    conn.close()
                self._remove_card_sidecar(root, state)
                sync_card_sidecars_after_commit(root, [str(state["card_id"])])
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE cards SET visibility_scope = ? WHERE id = ?",
                        (scope, state["card_id"]),
                    )
                    conn.commit()
                    before = tuple(
                        conn.execute(
                            "SELECT * FROM cards WHERE id = ?",
                            (state["card_id"],),
                        ).fetchone()
                    )
                finally:
                    conn.close()

                preview = self._assert_project_only_withholds_checkpoint(
                    root,
                    state,
                    project_id=project_id,
                    markers=(session_id, objective),
                )
                applied = repair_invalid_project_state_checkpoints(
                    root,
                    project_id=project_id,
                    dry_run=False,
                )
                self.assertEqual(preview["quarantined_count"], 0, preview)
                self.assertEqual(applied["quarantined_count"], 0, applied)
                self._assert_checkpoint_markers_not_disclosed(
                    applied,
                    state,
                    session_id,
                    objective,
                )
                conn = connect(root)
                try:
                    after = tuple(
                        conn.execute(
                            "SELECT * FROM cards WHERE id = ?",
                            (state["card_id"],),
                        ).fetchone()
                    )
                finally:
                    conn.close()
                self.assertEqual(after, before)

    def test_conflict_receipt_requires_pair_specific_authority_for_every_member(
        self,
    ) -> None:
        for erase_member_pair in (False, True):
            with self.subTest(
                erase_member_pair=erase_member_pair
            ), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                project_id = "receipt-member-proof-project"
                objective = f"RECEIPT MEMBER PROOF {erase_member_pair}"
                first = record_project_state(
                    root,
                    session_id=f"receipt-member-first-{erase_member_pair}",
                    agent_id="receipt-member-first-agent",
                    project_id=project_id,
                    objective=objective,
                )
                selected = record_project_state(
                    root,
                    session_id=f"receipt-member-selected-{erase_member_pair}",
                    agent_id="receipt-member-selected-agent",
                    project_id=project_id,
                    objective="selected receipt member",
                )
                resolve_conflict(
                    root,
                    card_id=str(selected["card_id"]),
                    action="supersede",
                    superseded_card_ids=[str(first["card_id"])],
                )
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE cards SET metadata_json = '{}', "
                        "source_refs_json = '[]' WHERE id = ?",
                        (first["card_id"],),
                    )
                    conn.execute(
                        "DELETE FROM queue_jobs WHERE job_type = "
                        "'review_card_placement' AND "
                        "json_extract(payload_json, '$.card_id') = ?",
                        (first["card_id"],),
                    )
                    conn.execute(
                        "DELETE FROM audit_events WHERE target_id = ?",
                        (first["card_id"],),
                    )
                    if erase_member_pair:
                        conn.execute(
                            "DELETE FROM graph_edge_sources WHERE "
                            "json_extract(CASE WHEN json_valid(source_ref_json) "
                            "THEN source_ref_json ELSE '{}' END, '$.card_id') = ?",
                            (first["card_id"],),
                        )
                        conn.execute(
                            "DELETE FROM audit_events WHERE target_id = ?",
                            (first["event_id"],),
                        )
                        conn.execute(
                            "DELETE FROM scroll_events WHERE id = ?",
                            (first["event_id"],),
                        )
                    conn.commit()
                finally:
                    conn.close()
                self._remove_card_sidecar(root, first)

                preview = repair_invalid_project_state_checkpoints(
                    root,
                    project_id=project_id,
                    dry_run=True,
                )

                if erase_member_pair:
                    self.assertEqual(preview["quarantined_count"], 0, preview)
                    self.assertEqual(
                        preview["withheld_uncertain_candidate_count"],
                        1,
                        preview,
                    )
                    self._assert_checkpoint_markers_not_disclosed(
                        preview,
                        first,
                        objective,
                    )
                else:
                    self.assertEqual(preview["quarantined_count"], 1, preview)
                    self.assertEqual(
                        preview["quarantined"][0]["card_id"],
                        first["card_id"],
                        preview,
                    )

    def test_all_projects_requires_opt_in_before_private_checkpoint_is_visible(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            states = self._damaged_project_and_private_checkpoints(root)

            default_scope = repair_invalid_project_state_checkpoints(
                root,
                all_projects=True,
                dry_run=True,
            )
            inclusive = repair_invalid_project_state_checkpoints(
                root,
                all_projects=True,
                include_private=True,
                dry_run=True,
            )

            self.assertTrue(default_scope["ok"], default_scope)
            self.assertEqual(default_scope["quarantined_count"], 1)
            self.assertEqual(
                [item["card_id"] for item in default_scope["quarantined"]],
                [states["project"]["card_id"]],
            )
            self._assert_private_checkpoint_not_disclosed(
                default_scope,
                states["private"],
            )
            self.assertTrue(inclusive["ok"], inclusive)
            self.assertEqual(inclusive["quarantined_count"], 2)
            self.assertEqual(
                {item["card_id"] for item in inclusive["quarantined"]},
                {
                    states["project"]["card_id"],
                    states["private"]["card_id"],
                },
            )

    def test_scope_and_limit_validation_happen_before_root_initialization(self) -> None:
        invalid_calls: tuple[dict[str, Any], ...] = (
            {},
            {"project_id": ""},
            {"project_id": "   "},
            {"session_id": ""},
            {"project_id": "project", "all_projects": True},
            {"all_projects": "yes"},
            {"project_id": "project", "limit": 0},
            {"project_id": "project", "limit": 1001},
            {"project_id": "project", "limit": True},
            {"project_id": "project", "limit": 1.5},
            {"project_id": "project", "include_session_scoped": "yes"},
            {"project_id": "project", "include_private": "yes"},
        )
        for index, kwargs in enumerate(invalid_calls):
            with self.subTest(kwargs=kwargs), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / f"continuum-{index}"
                with self.assertRaises(ValueError):
                    repair_invalid_project_state_checkpoints(root, **kwargs)
                self.assertFalse(root.exists())

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum-valid-uninitialized"
            result = repair_invalid_project_state_checkpoints(
                root,
                project_id="project",
                include_private=True,
                limit=7,
            )
            self.assertFalse(result["ok"], result)
            self.assertFalse(result["initialized"], result)
            self.assertEqual(
                result["repair_scope"],
                {
                    "project_id": "project",
                    "session_id": None,
                    "all_projects": False,
                    "include_session_scoped": False,
                    "include_private": True,
                    "authorized_visibility_scopes": [
                        "global",
                        "project",
                        "private",
                    ],
                    "limit": 7,
                },
            )
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
