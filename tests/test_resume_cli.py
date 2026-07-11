from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from continuum.cli import main as cli_main
from continuum.core.operations import list_operations
from continuum.core.store import (
    MAX_RECENT_EVENT_LIMIT,
    recover_thread,
    record_project_state,
    resume_latest,
    validate_recent_event_limit,
)


class ResumeCliTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
