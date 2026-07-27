from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import continuum.core.store as store_module
import continuum.core.workers as worker_module
from continuum.cli import main as cli_main
from continuum.core.config import load_config, write_config
from continuum.core.operations import list_operations, verify_proof_pack
from continuum.core.store import (
    MAX_RECENT_EVENT_LIMIT,
    connect,
    create_card,
    init_db,
    recover_thread,
    record_project_state,
    resume_latest,
    sync_card_sidecars_after_commit,
    validate_recent_event_limit,
)


class ResumeCliTests(unittest.TestCase):
    def test_run_workers_cli_preserves_queue_ownership_and_failure_receipts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="cli-worker-ownership",
                    summary="CLI proof generation must leave this queued sidecar alone.",
                    source_refs=[],
                )
                conn.execute("DELETE FROM queue_jobs")
                conn.commit()
            finally:
                conn.close()

            deferred_output = io.StringIO()
            with (
                patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}),
                patch.object(
                    store_module,
                    "sync_pending_card_sidecars",
                    wraps=store_module.sync_pending_card_sidecars,
                ) as deferred_generic_recovery,
                redirect_stdout(deferred_output),
            ):
                deferred_code = cli_main(
                    [
                        "run-workers",
                        "--root",
                        str(root),
                        "--limit",
                        "1",
                        "--no-maintenance",
                    ]
                )

            deferred = json.loads(deferred_output.getvalue())
            self.assertEqual(deferred_code, 0, deferred)
            self.assertTrue(deferred["ok"], deferred)
            self.assertEqual(deferred["_operation"]["status"], "succeeded")
            deferred_generic_recovery.assert_not_called()
            conn = connect(root)
            try:
                pending_after_deferred = (
                    conn.execute(
                        "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                        (card_id,),
                    ).fetchone()
                    is not None
                )
            finally:
                conn.close()
            self.assertTrue(pending_after_deferred, deferred)
            deferred_proof = Path(deferred["_operation"]["proof_pack_uri"])
            self.assertTrue(
                verify_proof_pack(
                    deferred_proof,
                    root=root,
                    allowed_roots=[root],
                )["ok"]
            )

            failed_sync = {
                "ok": False,
                "synced": 0,
                "failed": 1,
                "failures": [{"error": "simulated CLI worker drain failure"}],
            }
            failed_output = io.StringIO()
            with (
                patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}),
                patch.object(
                    worker_module,
                    "sync_card_sidecars_after_commit",
                    return_value=failed_sync,
                ),
                patch.object(
                    store_module,
                    "sync_pending_card_sidecars",
                    wraps=store_module.sync_pending_card_sidecars,
                ) as failed_generic_recovery,
                redirect_stdout(failed_output),
            ):
                failed_code = cli_main(
                    [
                        "run-workers",
                        "--root",
                        str(root),
                        "--limit",
                        "1",
                    ]
                )

            failed = json.loads(failed_output.getvalue())
            self.assertEqual(failed_code, 1, failed)
            self.assertFalse(failed["ok"], failed)
            self.assertEqual(failed["_operation"]["status"], "failed")
            failed_generic_recovery.assert_not_called()
            conn = connect(root)
            try:
                pending_after_failure = (
                    conn.execute(
                        "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                        (card_id,),
                    ).fetchone()
                    is not None
                )
            finally:
                conn.close()
            self.assertTrue(pending_after_failure, failed)
            failed_proof = Path(failed["_operation"]["proof_pack_uri"])
            self.assertTrue(
                verify_proof_pack(
                    failed_proof,
                    root=root,
                    allowed_roots=[root],
                )["ok"]
            )

    def test_yarn_configure_rejects_path_model_before_operation_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            model_path = "models\\Private Models\\qwythos secret.gguf"
            output = io.StringIO()
            with (
                patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}),
                redirect_stdout(output),
            ):
                code = cli_main(
                    [
                        "yarn-configure",
                        "--root",
                        str(root),
                        "--model",
                        model_path,
                    ]
                )

            result = json.loads(output.getvalue())
            self.assertEqual(code, 1, result)
            self.assertFalse(result["ok"])
            self.assertNotIn("Private Models", json.dumps(result))
            self.assertFalse(root.exists())

    def test_yarn_configure_rejects_incoherent_token_budgets_before_operation_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            output = io.StringIO()
            with (
                patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}),
                redirect_stdout(output),
            ):
                code = cli_main(
                    [
                        "yarn-configure",
                        "--root",
                        str(root),
                        "--max-input-tokens",
                        "256",
                        "--max-output-tokens",
                        "768",
                    ]
                )

            result = json.loads(output.getvalue())
            self.assertEqual(code, 1, result)
            self.assertFalse(result["ok"])
            self.assertIn("usable context", result["error"])
            self.assertFalse(root.exists())

    def test_yarn_configure_rejects_invalid_timeout_before_operation_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            output = io.StringIO()
            with redirect_stdout(output):
                code = cli_main(
                    [
                        "yarn-configure",
                        "--root",
                        str(root),
                        "--timeout-seconds",
                        "0",
                    ]
                )

            result = json.loads(output.getvalue())
            self.assertEqual(code, 1, result)
            self.assertIn("timeout_seconds", result["error"])
            self.assertFalse(root.exists())

    def test_yarn_no_enable_preserves_omitted_custom_settings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first_output = io.StringIO()
            with redirect_stdout(first_output):
                first_code = cli_main(
                    [
                        "yarn-configure",
                        "--root",
                        str(root),
                        "--enable",
                        "--base-url",
                        "https://models.example.com/v1",
                        "--model",
                        "custom-yarn-alias",
                        "--max-input-tokens",
                        "32768",
                        "--max-output-tokens",
                        "1024",
                        "--timeout-seconds",
                        "120",
                        "--allow-remote-endpoint",
                    ]
                )
            self.assertEqual(first_code, 0, first_output.getvalue())
            before = load_config(root)
            before["personal_profile"]["safe_context_ceiling"] = 12000
            write_config(root, before)
            before = load_config(root)

            second_output = io.StringIO()
            with redirect_stdout(second_output):
                second_code = cli_main(
                    ["yarn-configure", "--root", str(root), "--no-enable"]
                )
            self.assertEqual(second_code, 0, second_output.getvalue())
            after = load_config(root)

            for key in (
                "base_url",
                "model",
                "max_input_tokens",
                "max_output_tokens",
                "timeout_seconds",
                "allow_remote_endpoint",
            ):
                self.assertEqual(after["local_inference"][key], before["local_inference"][key])
            self.assertEqual(
                after["personal_profile"]["safe_context_ceiling"],
                before["personal_profile"]["safe_context_ceiling"],
            )
            self.assertFalse(after["local_inference"]["enabled"])
            self.assertFalse(after["personal_profile"]["assist_on_resume"])

    def test_core_recovery_apis_reject_limits_above_maximum_before_artifacts(
        self,
    ) -> None:
        self.assertEqual(validate_recent_event_limit(0), 0)
        self.assertEqual(
            validate_recent_event_limit(MAX_RECENT_EVENT_LIMIT),
            MAX_RECENT_EVENT_LIMIT,
        )
        for function, kwargs in (
            (recover_thread, {"session_id": "bounded-session"}),
            (resume_latest, {}),
        ):
            with self.subTest(function=function.__name__), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                with self.assertRaisesRegex(ValueError, "recent_event_limit"):
                    function(
                        root,
                        recent_event_limit=MAX_RECENT_EVENT_LIMIT + 1,
                        **kwargs,
                    )
                self.assertFalse(root.exists())

    def test_recovery_commands_reject_out_of_range_recent_event_limits_before_artifacts(
        self,
    ) -> None:
        for command, extra_args in (
            ("recover-thread", ["--session-id", "bounded-session"]),
            ("resume", []),
        ):
            for invalid_limit in (-1, MAX_RECENT_EVENT_LIMIT + 1):
                with (
                    self.subTest(command=command, recent_event_limit=invalid_limit),
                    tempfile.TemporaryDirectory() as tmp,
                ):
                    root = Path(tmp) / "continuum"
                    output = io.StringIO()
                    with (
                        patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}),
                        redirect_stdout(output),
                    ):
                        code = cli_main(
                            [
                                command,
                                "--root",
                                str(root),
                                *extra_args,
                                "--recent-event-limit",
                                str(invalid_limit),
                            ]
                        )

                    result = json.loads(output.getvalue())
                    self.assertEqual(code, 1, result)
                    self.assertFalse(result["ok"])
                    self.assertEqual(result["error_type"], "ValueError")
                    self.assertIn("recent_event_limit", result["error"])
                    self.assertFalse(root.exists())

    def test_resume_is_operation_guarded_and_returns_proof_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                record_project_state(
                    root,
                    session_id="cli-resume-session",
                    agent_id="codex-sol",
                    project_id="cli-resume-project",
                    objective="Guard automatic resume",
                )
                output = io.StringIO()
                with redirect_stdout(output):
                    code = cli_main(
                        [
                            "resume",
                            "--root",
                            str(root),
                            "--project-id",
                            "cli-resume-project",
                            "--no-model-assist",
                        ]
                    )

            result = json.loads(output.getvalue())
            self.assertEqual(code, 0, result)
            self.assertTrue(result["ok"], result)
            self.assertEqual(result["_operation"]["status"], "succeeded")
            self.assertTrue(Path(result["_operation"]["proof_pack_uri"]).is_file())
            operations = list_operations(root)["operations"]
            self.assertTrue(
                any(
                    item["operation_type"] == "cli_resume_latest" for item in operations
                )
            )

    def test_cli_resume_migrates_authority_indexes_before_discovery(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="cli-upgrade-session",
                agent_id="codex-sol",
                project_id="cli-upgrade-project",
                objective="Migrate before CLI resume discovery.",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "DROP INDEX idx_graph_edge_sources_card_id_authority"
                )
                conn.execute(
                    "DROP INDEX "
                    "idx_graph_edge_sources_source_ref_key_authority"
                )
                conn.commit()
            finally:
                conn.close()
            store_module._INIT_DB_CACHE.discard(
                str(root.resolve(strict=False))
            )

            output = io.StringIO()
            with (
                patch.dict(
                    "os.environ",
                    {"CONTINUUM_ALLOWED_ROOTS": tmp},
                ),
                redirect_stdout(output),
            ):
                code = cli_main(
                    [
                        "resume",
                        "--root",
                        str(root),
                        "--project-id",
                        "cli-upgrade-project",
                        "--no-model-assist",
                    ]
                )

            result = json.loads(output.getvalue())
            self.assertEqual(code, 0, result)
            self.assertTrue(result["ok"], result)
            conn = connect(root)
            try:
                indexes = {
                    str(row["name"])
                    for row in conn.execute(
                        "PRAGMA index_list(graph_edge_sources)"
                    ).fetchall()
                }
            finally:
                conn.close()
            self.assertTrue(
                store_module.RESUME_AUTHORITY_INDEX_NAMES.issubset(
                    indexes
                ),
                indexes,
            )

    def test_checkpoint_repair_requires_explicit_scope_before_artifacts(self) -> None:
        cases = (
            ([], "requires --project-id, --session-id, or explicit --all"),
            (["--project-id", ""], "--project-id must be non-empty"),
            (["--session-id", "   "], "--session-id must be non-empty"),
            (
                ["--all", "--project-id", "ambiguous-project"],
                "--all cannot be combined",
            ),
            (
                ["--project-id", "bounded-project", "--limit", "1001"],
                "limit must be between 1 and 1000",
            ),
        )
        for extra_args, expected_error in cases:
            with self.subTest(extra_args=extra_args), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                output = io.StringIO()
                with redirect_stdout(output):
                    code = cli_main(
                        [
                            "repair-project-state-checkpoints",
                            "--root",
                            str(root),
                            *extra_args,
                            "--apply",
                        ]
                    )

                result = json.loads(output.getvalue())
                self.assertEqual(code, 1, result)
                self.assertIn(expected_error, result["error"])
                self.assertFalse(root.exists())

    def test_checkpoint_repair_preview_apply_share_scope_and_receipt_flags(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            store_module.init_db(root)
            preview_output = io.StringIO()
            apply_output = io.StringIO()
            mock_result = {
                "ok": True,
                "quarantined_count": 0,
                "quarantined": [],
            }
            common_args = [
                "repair-project-state-checkpoints",
                "--root",
                str(root),
                "--all",
                "--include-session-scoped",
                "--include-private",
                "--limit",
                "37",
            ]
            with patch(
                "continuum.cli.repair_invalid_project_state_checkpoints",
                return_value=mock_result,
            ) as repair:
                with redirect_stdout(preview_output):
                    preview_code = cli_main(common_args)
                with redirect_stdout(apply_output):
                    apply_code = cli_main([*common_args, "--apply"])

            preview = json.loads(preview_output.getvalue())
            applied = json.loads(apply_output.getvalue())
            self.assertEqual(preview_code, 0, preview)
            self.assertEqual(apply_code, 0, applied)
            self.assertNotIn("_operation", preview)
            self.assertEqual(applied["_operation"]["status"], "succeeded")
            self.assertEqual(repair.call_count, 2)
            preview_kwargs = repair.call_args_list[0].kwargs
            apply_kwargs = repair.call_args_list[1].kwargs
            self.assertTrue(preview_kwargs.pop("dry_run"))
            self.assertFalse(apply_kwargs.pop("dry_run"))
            self.assertEqual(preview_kwargs, apply_kwargs)
            self.assertEqual(
                preview_kwargs,
                {
                    "session_id": None,
                    "project_id": None,
                    "all_projects": True,
                    "include_session_scoped": True,
                    "include_private": True,
                    "limit": 37,
                },
            )
            operation = next(
                item
                for item in list_operations(root)["operations"]
                if item["operation_type"]
                == "cli_repair_project_state_checkpoints"
            )
            receipt = json.loads(
                Path(operation["export_receipt_uri"]).read_text(encoding="utf-8")
            )
            self.assertEqual(
                receipt["intent"],
                {
                    "session_id": None,
                    "project_id": None,
                    "all_projects": True,
                    "include_session_scoped": True,
                    "include_private": True,
                    "apply": True,
                    "limit": 37,
                    "preflight_snapshot_policy": "auto",
                    "preflight_snapshot_reason": (
                        "checkpoint quarantine changes Card authority pointers"
                    ),
                },
            )

    def test_applied_repair_fails_its_receipt_for_asymmetric_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                first = record_project_state(
                    root,
                    session_id="cli-asymmetric-a",
                    agent_id="agent-a",
                    project_id="cli-asymmetric-project",
                    objective="FIRST CLI AUTHORITY",
                )
                second = record_project_state(
                    root,
                    session_id="cli-asymmetric-b",
                    agent_id="agent-b",
                    project_id="cli-asymmetric-project",
                    objective="SECOND CLI AUTHORITY",
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
                output = io.StringIO()
                with redirect_stdout(output):
                    code = cli_main(
                        [
                            "repair-project-state-checkpoints",
                            "--root",
                            str(root),
                            "--project-id",
                            "cli-asymmetric-project",
                            "--apply",
                        ]
                    )

            result = json.loads(output.getvalue())
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
            repair_operations = [
                item
                for item in list_operations(root)["operations"]
                if item["operation_type"]
                == "cli_repair_project_state_checkpoints"
            ]
            self.assertEqual(code, 1, result)
            self.assertFalse(result["ok"])
            self.assertIn("repair refused", result["error"])
            self.assertEqual(before, after)
            self.assertTrue(repair_operations)
            self.assertEqual(repair_operations[0]["status"], "failed")

    def test_applied_repair_fails_receipt_after_committed_sidecar_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                damaged = record_project_state(
                    root,
                    session_id="cli-sidecar-failure",
                    agent_id="cli-sidecar-agent",
                    project_id="cli-sidecar-project",
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
                sync_card_sidecars_after_commit(root, [damaged["card_id"]])
                failed_sync = {
                    "ok": False,
                    "synced": 0,
                    "deferred": 1,
                    "failed": 1,
                    "failures": [
                        {
                            "card_id": damaged["card_id"],
                            "error": "injected CLI sidecar failure",
                        }
                    ],
                }
                output = io.StringIO()
                with (
                    patch(
                        "continuum.core.store.sync_card_sidecars_after_commit",
                        return_value=failed_sync,
                    ),
                    redirect_stdout(output),
                ):
                    code = cli_main(
                        [
                            "repair-project-state-checkpoints",
                            "--root",
                            str(root),
                            "--project-id",
                            "cli-sidecar-project",
                            "--apply",
                        ]
                    )

            result = json.loads(output.getvalue())
            operations = [
                item
                for item in list_operations(root)["operations"]
                if item["operation_type"]
                == "cli_repair_project_state_checkpoints"
            ]
            self.assertEqual(code, 1, result)
            self.assertFalse(result["ok"], result)
            self.assertIn("catalog repair committed", result["error"])
            self.assertTrue(operations)
            self.assertEqual(operations[0]["status"], "failed")
            self.assertEqual(
                operations[0]["cursor"]["phase"],
                "project_state_catalog_repair_committed_postflight_failed",
            )
            self.assertTrue(
                operations[0]["cursor"]["catalog_repair_committed"]
            )
            conn = connect(root)
            try:
                status = conn.execute(
                    "SELECT status FROM cards WHERE id = ?",
                    (damaged["card_id"],),
                ).fetchone()["status"]
            finally:
                conn.close()
            self.assertEqual(status, "historical")

    def test_applied_repair_fails_receipt_after_semantic_postflight_false(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                damaged = record_project_state(
                    root,
                    session_id="cli-postflight-false",
                    agent_id="cli-postflight-agent",
                    project_id="cli-postflight-project",
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
                sync_card_sidecars_after_commit(root, [damaged["card_id"]])
                real_semantic_report = store_module.semantic_integrity_report
                transaction_report_count = 0
                injected = False

                def semantic_report(*args: object, **kwargs: object) -> dict[str, object]:
                    nonlocal transaction_report_count, injected
                    report = real_semantic_report(*args, **kwargs)
                    if kwargs.get("conn") is not None:
                        transaction_report_count += 1
                    elif transaction_report_count >= 2 and not injected:
                        injected = True
                        return {
                            **report,
                            "ok": False,
                            "failing": {"injected_postflight_failure": 1},
                        }
                    return report

                output = io.StringIO()
                with (
                    patch.object(
                        store_module,
                        "semantic_integrity_report",
                        side_effect=semantic_report,
                    ),
                    redirect_stdout(output),
                ):
                    code = cli_main(
                        [
                            "repair-project-state-checkpoints",
                            "--root",
                            str(root),
                            "--project-id",
                            "cli-postflight-project",
                            "--apply",
                        ]
                    )

            result = json.loads(output.getvalue())
            operation = next(
                item
                for item in list_operations(root)["operations"]
                if item["operation_type"]
                == "cli_repair_project_state_checkpoints"
            )
            self.assertEqual(code, 1, result)
            self.assertIn("catalog repair committed", result["error"])
            self.assertEqual(operation["status"], "failed")
            self.assertEqual(
                operation["cursor"]["phase"],
                "project_state_catalog_repair_committed_postflight_failed",
            )
            self.assertTrue(operation["cursor"]["catalog_repair_committed"])
            self.assertFalse(operation["cursor"]["post_repair_semantic_ok"])

    def test_cli_resolves_complete_compatible_authority_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                first_peer = record_project_state(
                    root,
                    session_id="cli-authority-peer-a",
                    agent_id="agent-a",
                    project_id="cli-authority-project",
                    objective="Prepare release notes",
                )
                second_peer = record_project_state(
                    root,
                    session_id="cli-authority-peer-b",
                    agent_id="agent-b",
                    project_id="cli-authority-project",
                    objective="Prepare package metadata",
                )
                winner = record_project_state(
                    root,
                    session_id="cli-authority-winner",
                    agent_id="agent-c",
                    project_id="cli-authority-project",
                    objective="Prepare final review bundle",
                )
                missing_output = io.StringIO()
                with redirect_stdout(missing_output):
                    missing_code = cli_main(
                        [
                            "resolve-conflict",
                            "--root",
                            str(root),
                            "--card-id",
                            winner["card_id"],
                        ]
                    )
                output = io.StringIO()
                with redirect_stdout(output):
                    code = cli_main(
                        [
                            "resolve-conflict",
                            "--root",
                            str(root),
                            "--card-id",
                            winner["card_id"],
                            "--superseded-card-id",
                            first_peer["card_id"],
                            "--superseded-card-id",
                            second_peer["card_id"],
                        ]
                    )

            missing = json.loads(missing_output.getvalue())
            self.assertEqual(missing_code, 1, missing)
            self.assertIn(first_peer["card_id"], missing["error"])
            self.assertIn(second_peer["card_id"], missing["error"])
            result = json.loads(output.getvalue())
            self.assertEqual(code, 0, result)
            self.assertTrue(result["ok"], result)
            self.assertEqual(
                result["resolution_scope"],
                "project_state_authority_boundary",
            )
            resumed = resume_latest(
                root,
                project_id="cli-authority-project",
                model_assist=False,
            )
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                winner["card_id"],
            )


if __name__ == "__main__":
    unittest.main()
