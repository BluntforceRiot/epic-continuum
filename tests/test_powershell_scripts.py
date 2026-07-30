from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


@unittest.skipUnless(os.name == "nt", "PowerShell native-exit tests require Windows")
class PowerShellNativeExitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.powershell = shutil.which("powershell.exe") or shutil.which("powershell")
        if cls.powershell is None:
            raise unittest.SkipTest("Windows PowerShell is unavailable")

    def _run_script(
        self,
        script: Path,
        arguments: list[str],
        *,
        environment: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                str(self.powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(script),
                *arguments,
            ],
            cwd=self.repo_root,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_codex_installer_stops_at_each_failed_native_registration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp)
            log_path = temp_root / "calls.log"
            python_stub = temp_root / "python-stub.cmd"
            codex_stub = temp_root / "codex.cmd"
            python_stub.write_text(
                "@echo off\r\n"
                "echo python %*>>\"%STUB_LOG%\"\r\n"
                "if defined STUB_STAGE_OUTPUT echo %STUB_STAGE_OUTPUT%\r\n"
                "exit /b %STUB_PYTHON_EXIT%\r\n",
                encoding="utf-8",
            )
            codex_stub.write_text(
                "@echo off\r\n"
                "echo codex %*>>\"%STUB_LOG%\"\r\n"
                "if \"%1 %2 %3\"==\"plugin marketplace add\" exit /b %STUB_MARKETPLACE_EXIT%\r\n"
                "if \"%1 %2\"==\"plugin add\" exit /b %STUB_PLUGIN_EXIT%\r\n"
                "exit /b 0\r\n",
                encoding="utf-8",
            )
            base_env = os.environ.copy()
            base_env.update(
                {
                    "PATH": f"{temp_root}{os.pathsep}{base_env.get('PATH', '')}",
                    "STUB_LOG": str(log_path),
                    "STUB_PYTHON_EXIT": "0",
                    "STUB_STAGE_OUTPUT": str(temp_root / "stage"),
                }
            )
            allowed_roots = os.pathsep.join(
                (
                    str(temp_root / "workspace"),
                    str(temp_root / "evidence"),
                )
            )
            script = self.repo_root / "scripts" / "install_codex_plugin.ps1"
            arguments = [
                "-RepoRoot",
                str(self.repo_root),
                "-Root",
                str(temp_root / "root"),
                "-Python",
                str(python_stub),
                "-StageRoot",
                str(temp_root / "stage-base"),
                "-AllowedRoots",
                allowed_roots,
                "-Codex",
                str(codex_stub),
            ]

            for marketplace_exit, plugin_exit, expected_exit, expected_codex_calls in (
                ("23", "0", 23, 1),
                ("0", "24", 24, 2),
            ):
                with self.subTest(expected_exit=expected_exit):
                    log_path.unlink(missing_ok=True)
                    environment = dict(base_env)
                    environment["STUB_MARKETPLACE_EXIT"] = marketplace_exit
                    environment["STUB_PLUGIN_EXIT"] = plugin_exit
                    completed = self._run_script(
                        script,
                        arguments,
                        environment=environment,
                    )
                    calls = log_path.read_text(encoding="utf-8").splitlines()
                    codex_calls = [line for line in calls if line.startswith("codex ")]
                    python_calls = [
                        line for line in calls if line.startswith("python ")
                    ]
                    self.assertEqual(completed.returncode, expected_exit, completed)
                    self.assertEqual(len(python_calls), 1, calls)
                    self.assertIn("--allowed-roots", python_calls[0])
                    self.assertIn(allowed_roots, python_calls[0])
                    self.assertEqual(len(codex_calls), expected_codex_calls, calls)
                    self.assertNotIn("Epic Continuum Codex plugin installed", completed.stdout)

    def test_hermes_installer_propagates_python_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp)
            log_path = temp_root / "calls.log"
            python_stub = temp_root / "python-stub.cmd"
            python_stub.write_text(
                "@echo off\r\n"
                "echo python %*>>\"%STUB_LOG%\"\r\n"
                "exit /b %STUB_PYTHON_EXIT%\r\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "STUB_LOG": str(log_path),
                    "STUB_PYTHON_EXIT": "29",
                }
            )
            completed = self._run_script(
                self.repo_root / "scripts" / "install_hermes_adapter.ps1",
                [
                    "-Root",
                    str(temp_root / "root"),
                    "-HermesHome",
                    str(temp_root / "hermes"),
                    "-Python",
                    str(python_stub),
                ],
                environment=environment,
            )

            self.assertEqual(completed.returncode, 29, completed)
            self.assertEqual(len(log_path.read_text(encoding="utf-8").splitlines()), 1)

    def test_hermes_installer_propagates_requested_native_command_failures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp)
            log_path = temp_root / "hermes-calls.log"
            hermes_stub = temp_root / "hermes.cmd"
            hermes_stub.write_text(
                "@echo off\r\n"
                "echo hermes %*>>\"%STUB_LOG%\"\r\n"
                "if \"%1 %2 %3\"==\"plugins enable epic_continuum\" "
                "exit /b %STUB_ENABLE_EXIT%\r\n"
                "if \"%1 %2 %3\"==\"config set model.default\" "
                "exit /b %STUB_CONFIG_EXIT%\r\n"
                "exit /b 0\r\n",
                encoding="utf-8",
            )
            base_environment = os.environ.copy()
            base_environment.update(
                {
                    "PYTHONPATH": str(self.repo_root / "src"),
                    "STUB_LOG": str(log_path),
                }
            )
            script = self.repo_root / "scripts" / "install_hermes_adapter.ps1"
            arguments = [
                "-Root",
                str(temp_root / "root"),
                "-HermesHome",
                str(temp_root / "hermes-home"),
                "-Python",
                sys.executable,
                "-HermesExe",
                str(hermes_stub),
                "-ModelName",
                "local-model",
                "-BaseUrl",
                "http://127.0.0.1:9999/v1",
                "-SetDefaultModel",
            ]

            for enable_exit, config_exit, expected_calls in (
                ("19", "0", ["hermes plugins enable epic_continuum"]),
                (
                    "0",
                    "23",
                    [
                        "hermes plugins enable epic_continuum",
                        "hermes config set model.default local-model",
                    ],
                ),
            ):
                with self.subTest(
                    enable_exit=enable_exit,
                    config_exit=config_exit,
                ):
                    log_path.unlink(missing_ok=True)
                    environment = dict(base_environment)
                    environment["STUB_ENABLE_EXIT"] = enable_exit
                    environment["STUB_CONFIG_EXIT"] = config_exit
                    completed = self._run_script(
                        script,
                        arguments,
                        environment=environment,
                    )

                    self.assertNotEqual(completed.returncode, 0, completed)
                    self.assertEqual(
                        log_path.read_text(encoding="utf-8").splitlines(),
                        expected_calls,
                    )
                    result = json.loads(completed.stdout)
                    self.assertIs(result["ok"], False)
                    self.assertEqual(result["_operation"]["status"], "failed")
                    self.assertEqual(result["command_failure_count"], 1)
                    receipt = json.loads(
                        Path(
                            result["_operation"]["operation_receipt_uri"]
                        ).read_text(encoding="utf-8")
                    )
                    self.assertEqual(
                        receipt["cursor"]["phase"],
                        "hermes_adapter_install_failed",
                    )
                    self.assertEqual(receipt["status"], "failed")
                    self.assertEqual(
                        receipt["result"]["failed_commands"],
                        result["failed_commands"],
                    )

    def test_codex_stage_only_does_not_claim_installation_or_call_codex(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp)
            log_path = temp_root / "calls.log"
            python_stub = temp_root / "python-stub.cmd"
            codex_stub = temp_root / "codex.cmd"
            python_stub.write_text(
                "@echo off\r\n"
                "echo python %*>>\"%STUB_LOG%\"\r\n"
                "echo %STUB_STAGE_OUTPUT%\r\n"
                "exit /b 0\r\n",
                encoding="utf-8",
            )
            codex_stub.write_text(
                "@echo off\r\n"
                "echo codex %*>>\"%STUB_LOG%\"\r\n"
                "exit /b 0\r\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{temp_root}{os.pathsep}{environment.get('PATH', '')}",
                    "STUB_LOG": str(log_path),
                    "STUB_STAGE_OUTPUT": str(temp_root / "stage"),
                }
            )
            allowed_roots = os.pathsep.join(
                (
                    str(temp_root / "workspace"),
                    str(temp_root / "evidence"),
                )
            )
            completed = self._run_script(
                self.repo_root / "scripts" / "install_codex_plugin.ps1",
                [
                    "-RepoRoot",
                    str(self.repo_root),
                    "-Root",
                    str(temp_root / "root"),
                    "-Python",
                    str(python_stub),
                    "-StageRoot",
                    str(temp_root / "stage-base"),
                    "-AllowedRoots",
                    allowed_roots,
                    "-StageOnly",
                ],
                environment=environment,
            )

            calls = log_path.read_text(encoding="utf-8").splitlines()
            python_calls = [
                line for line in calls if line.startswith("python ")
            ]
            self.assertEqual(completed.returncode, 0, completed)
            self.assertEqual(len(python_calls), 1, calls)
            self.assertIn("--allowed-roots", python_calls[0])
            self.assertIn(allowed_roots, python_calls[0])
            self.assertFalse(any(line.startswith("codex ") for line in calls), calls)
            self.assertIn("staged without registration", completed.stdout)
            self.assertNotIn("plugin installed", completed.stdout)

    def test_quickstart_stops_after_first_python_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp)
            log_path = temp_root / "calls.log"
            python_stub = temp_root / "python.cmd"
            python_stub.write_text(
                "@echo off\r\n"
                "echo python %*>>\"%STUB_LOG%\"\r\n"
                "exit /b %STUB_PYTHON_EXIT%\r\n",
                encoding="utf-8",
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{temp_root}{os.pathsep}{environment.get('PATH', '')}",
                    "CONTINUUM_ROOT": str(temp_root / "root"),
                    "STUB_LOG": str(log_path),
                    "STUB_PYTHON_EXIT": "31",
                }
            )
            completed = self._run_script(
                self.repo_root / "examples" / "quickstart.ps1",
                [],
                environment=environment,
            )

            self.assertEqual(completed.returncode, 31, completed)
            self.assertEqual(len(log_path.read_text(encoding="utf-8").splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
