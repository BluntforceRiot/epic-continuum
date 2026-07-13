from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from continuum.core.store import (
    connect,
    record_project_state,
    repair_invalid_project_state_checkpoints,
    sync_card_sidecars_after_commit,
)


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
