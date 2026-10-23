from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

import continuum
from continuum.core.inspection import inspect_runtime
from continuum.core.store import connect, init_db
from continuum.core.writer_claim import WriterClaimError


NOW = dt.datetime(2026, 10, 23, 12, tzinfo=dt.UTC)
PAST = "2026-10-23T11:00:00+00:00"
FUTURE = "2026-10-23T13:00:00+00:00"


class InspectionTests(unittest.TestCase):
    def _root(self, temporary: str) -> Path:
        root = Path(temporary) / "memory"
        init_db(root)
        return root

    def _job(self, conn: sqlite3.Connection, name: str, status: str, **overrides) -> None:
        values = {
            "id": name, "role": "scribe", "job_type": "inspection_fixture", "status": status,
            "retry_pending": 0, "retry_order": 0, "created_at": PAST, "updated_at": PAST,
            "lease_owner": "fixture-worker" if status == "running" else None,
            "lease_expires_at": FUTURE if status == "running" else None,
            "heartbeat_at": PAST if status == "running" else None,
            "finished_at": PAST if status in {"succeeded", "failed", "skipped"} else None,
        }
        values.update(overrides)
        conn.execute(
            f"INSERT INTO queue_jobs ({', '.join(values)}) VALUES ({', '.join('?' for _ in values)})",
            tuple(values.values()),
        )

    def _inspect(self, root: Path, **kwargs) -> dict:
        with patch("continuum.core.inspection._now", return_value=NOW):
            return inspect_runtime(root, **kwargs)

    def _codes(self, report: dict) -> set[str]:
        return {warning["code"] for warning in report["warnings"]}

    def test_missing_root_stays_missing_and_does_not_use_environment_default(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "absent"
            unrelated = Path(temporary) / "environment-default"
            with patch.dict("os.environ", {"CONTINUUM_ROOT": str(unrelated)}):
                report = self._inspect(root)
            self.assertFalse(root.exists())
            self.assertFalse(unrelated.exists())
            self.assertFalse(report["ok"])
            self.assertEqual(report["root"], str(root.resolve()))
            self.assertEqual(report["reason"], "catalog_missing")
            self.assertIsNone(report["queue"]["counts"])
            self.assertFalse(report["upgrade"]["installed_or_changed"])

    def test_no_root_argument_is_not_a_default_root_request(self) -> None:
        with self.assertRaises(TypeError):
            inspect_runtime()  # type: ignore[call-arg]

    def test_runtime_identifies_loaded_module_and_not_only_distribution_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = self._inspect(Path(temporary) / "missing")
        self.assertEqual(report["runtime"]["active_version"], continuum.__version__)
        self.assertEqual(report["runtime"]["module_path"], str(Path(continuum.__file__).resolve()))
        self.assertEqual(report["runtime"]["python_executable"], str(Path(sys.executable).resolve()))

    def test_distinct_counts_follow_retry_and_terminal_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            conn = connect(root)
            try:
                self._job(conn, "fresh", "pending")
                self._job(conn, "retry", "pending", retry_pending=1, retry_order=1)
                self._job(conn, "running", "running")
                self._job(conn, "running-retry", "running", retry_pending=1, retry_order=2)
                self._job(conn, "failure", "failed")
                self._job(conn, "success", "succeeded")
                self._job(conn, "skip", "skipped")
                self._job(conn, "other", "fixture-unknown")
                conn.commit()
            finally:
                conn.close()
            report = self._inspect(root)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["queue"]["counts"], {
            "pending": 1, "retrying": 1, "running": 2, "failed": 1,
            "completed": 1, "skipped": 1, "unknown": 1,
        })
        self.assertEqual(report["queue"]["total"], 8)
        self.assertEqual(report["queue"]["running_retry_jobs"], 1)
        self.assertIn("unclassified_jobs", self._codes(report))
        self.assertIn("failed_jobs", self._codes(report))

    def test_report_preserves_logical_catalog_config_operations_and_live_wal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            conn = connect(root)
            try:
                self._job(conn, "committed-wal-row", "pending", payload_json='{"private":"do-not-emit"}')
                conn.commit()
                before_dump = "\n".join(conn.iterdump())
                before_files = {
                    str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in root.rglob("*") if path.is_file() and "catalog" not in path.relative_to(root).parts
                }
                with patch("continuum.core.store.init_db", side_effect=AssertionError("no init")), patch(
                    "continuum.core.config.load_config", side_effect=AssertionError("no loader")
                ), patch("continuum.core.store.connect", side_effect=AssertionError("no writer")):
                    report = self._inspect(root)
                after_files = {
                    str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in root.rglob("*") if path.is_file() and "catalog" not in path.relative_to(root).parts
                }
                self.assertEqual(before_dump, "\n".join(conn.iterdump()))
                self.assertEqual(before_files, after_files)
                self.assertEqual(report["queue"]["counts"]["pending"], 1)
                self.assertNotIn("do-not-emit", json.dumps(report))
            finally:
                conn.close()

    def test_existing_catalog_without_config_does_not_write_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            config = root / "config" / "continuum.config.json"
            config.unlink()
            report = self._inspect(root)
            self.assertFalse(config.exists())
            self.assertTrue(report["ok"])
            self.assertEqual(report["config"]["state"], "missing")

    def test_stale_jobs_and_completion_are_not_service_liveness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            conn = connect(root)
            try:
                self._job(conn, "active", "running")
                self._job(conn, "expired", "running", lease_expires_at=PAST)
                self._job(conn, "unowned", "running", lease_owner=" ")
                self._job(conn, "missing-heartbeat", "running", heartbeat_at=None)
                self._job(conn, "future-heartbeat", "running", heartbeat_at=FUTURE)
                self._job(conn, "terminal", "succeeded", heartbeat_at=FUTURE)
                conn.commit()
            finally:
                conn.close()
            report = self._inspect(root)
        workers = report["workers"]
        self.assertEqual(workers["stale_running_jobs"], 4)
        self.assertEqual(workers["latest_running_job_heartbeat_at"], PAST)
        self.assertEqual(workers["latest_successful_completion_at"], PAST)
        self.assertEqual(workers["successful_completions_last_24h"], 1)
        self.assertEqual(workers["service_liveness"], "not_checked")
        self.assertEqual(workers["progress_since_previous_inspection"], "not_measured")
        self.assertIn("stale_running_jobs", self._codes(report))

    def test_empty_queue_does_not_assert_active_workers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = self._inspect(self._root(temporary))
        self.assertEqual(report["queue"]["total"], 0)
        self.assertIsNone(report["workers"]["latest_running_job_heartbeat_at"])
        self.assertIsNone(report["workers"]["latest_successful_completion_at"])
        self.assertEqual(report["workers"]["service_liveness"], "not_checked")

    def test_timestamp_offsets_invalid_and_future_values_are_not_fresh_progress(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            conn = connect(root)
            try:
                self._job(conn, "old", "pending", created_at="2026-10-22T14:00:00+03:00")
                self._job(conn, "bad", "pending", created_at="2451545")
                self._job(conn, "future", "pending", created_at=FUTURE)
                self._job(conn, "naive", "succeeded", finished_at="2026-10-23T11:00:00")
                self._job(conn, "future-done", "succeeded", finished_at=FUTURE)
                self._job(conn, "offset-done", "succeeded", finished_at="2026-10-23T13:00:00+03:00")
                conn.commit()
            finally:
                conn.close()
            report = self._inspect(root)
        self.assertEqual(report["queue"]["oldest_waiting_job_age_seconds"], 90000)
        self.assertEqual(report["queue"]["invalid_waiting_timestamps"], 1)
        self.assertEqual(report["queue"]["future_waiting_timestamps"], 1)
        self.assertEqual(report["workers"]["invalid_successful_completion_timestamps"], 2)
        self.assertEqual(report["workers"]["successful_completions_last_24h"], 1)
        self.assertEqual(report["workers"]["latest_successful_completion_at"], "2026-10-23T10:00:00+00:00")
        self.assertTrue({"old_waiting_jobs", "waiting_timestamp_invalid", "completion_timestamp_invalid", "backlog_without_running_jobs"}.issubset(self._codes(report)))

    def test_old_schema_is_unavailable_not_zero_and_is_not_migrated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "old"
            catalog = root / "catalog" / "catalog.sqlite3"
            catalog.parent.mkdir(parents=True)
            conn = sqlite3.connect(catalog)
            try:
                conn.execute("CREATE TABLE queue_jobs (status TEXT)")
                conn.execute("INSERT INTO queue_jobs VALUES ('pending')")
                conn.commit()
            finally:
                conn.close()
            before = catalog.read_bytes()
            report = self._inspect(root)
            self.assertEqual(before, catalog.read_bytes())
            self.assertFalse((root / "config").exists())
        self.assertFalse(report["ok"])
        self.assertIsNone(report["queue"]["counts"])
        self.assertIn("retry_pending", report["queue"]["missing_columns"])
        self.assertIn("queue_schema_incomplete", self._codes(report))
        self.assertFalse(report["upgrade"]["migration_certified"])

    def test_corrupt_catalog_and_writer_guard_errors_are_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "corrupt"
            catalog = root / "catalog" / "catalog.sqlite3"
            catalog.parent.mkdir(parents=True)
            catalog.write_bytes(b"not a database")
            report = self._inspect(root)
            self.assertFalse(report["ok"])
            self.assertEqual(report["reason"], "catalog_unreadable")
            with patch("continuum.core.inspection.connect_existing", side_effect=WriterClaimError("do-not-emit-secret")):
                guarded = self._inspect(root)
            self.assertEqual(guarded["reason"], "writer_claim_incompatible")
            self.assertNotIn("do-not-emit-secret", json.dumps(guarded))

    def test_explicit_hermes_and_codex_bindings_and_secrets_are_not_dumped(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            source = str(Path(continuum.__file__).resolve().parent.parent)
            hermes = Path(temporary) / "adapter.json"
            codex = Path(temporary) / "mcp.json"
            hermes.write_text(json.dumps({"continuum_root": str(root), "continuum_src": source, "api_key": "fixture-secret-hermes"}), encoding="utf-8")
            codex.write_text(json.dumps({"mcpServers": {"continuum": {
                "command": sys.executable, "args": ["-m", "continuum.mcp_server"],
                "env": {"CONTINUUM_ROOT": str(root), "PYTHONPATH": source, "API_KEY": "fixture-secret-codex"},
            }}}), encoding="utf-8")
            before = (hermes.read_bytes(), codex.read_bytes())
            with patch("subprocess.run", side_effect=AssertionError("no execution")):
                report = self._inspect(root, hermes_adapter_config=hermes, codex_mcp_config=codex)
            self.assertEqual(before, (hermes.read_bytes(), codex.read_bytes()))
        for connection in report["connections"]:
            self.assertTrue(connection["root_binding"]["matches"])
            self.assertTrue(connection["source_binding"]["matches"])
            self.assertFalse(connection["live_connection_verified"])
            self.assertFalse(connection["commands_executed"])
        self.assertEqual(report["connections"][1]["launch_shape"], "python_module")
        self.assertTrue(report["connections"][1]["python_binding"]["matches"])
        self.assertNotIn("fixture-secret", json.dumps(report))

    def test_codex_toml_mismatch_and_unresolved_host_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = self._root(temporary)
            config = Path(temporary) / "codex.toml"
            other = Path(temporary) / "other-root"
            config.write_text(
                '[mcp_servers.continuum]\ncommand = "python"\nargs = ["-m", "continuum.mcp_server"]\n'
                '[mcp_servers.continuum.env]\nCONTINUUM_ROOT = ' + json.dumps(str(other)) + '\nPYTHONPATH = "$HOST_SOURCE"\nAPI_KEY = "fixture-secret-toml"\n',
                encoding="utf-8",
            )
            report = self._inspect(root, codex_mcp_config=config)
        facts = report["connections"][0]
        self.assertFalse(facts["root_binding"]["matches"])
        self.assertIsNone(facts["source_binding"]["matches"])
        self.assertEqual(facts["python_binding"]["state"], "unresolved")
        self.assertTrue({"codex_root_mismatch", "codex_source_unverified", "codex_python_unverified"}.issubset(self._codes(report)))
        self.assertNotIn("fixture-secret-toml", json.dumps(report))

    def test_absolute_paths_with_literal_tilde_are_not_home_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "literal~1" / "memory"
            config = Path(temporary) / "adapter.json"
            config.write_text(json.dumps({"continuum_root": str(root)}), encoding="utf-8")
            report = self._inspect(root, hermes_adapter_config=config)
            self.assertFalse(root.exists())
        binding = report["connections"][0]["root_binding"]
        self.assertEqual(binding["state"], "absolute")
        self.assertTrue(binding["matches"])

    def test_multiple_pythonpath_entries_are_unresolved_not_a_single_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "mcp.json"
            paths = os.pathsep.join(str(Path(temporary) / name) for name in ("first", "second"))
            config.write_text(json.dumps({"mcpServers": {"continuum": {"env": {"PYTHONPATH": paths}}}}), encoding="utf-8")
            report = self._inspect(Path(temporary) / "missing", codex_mcp_config=config)
        self.assertEqual(report["connections"][0]["source_binding"]["state"], "unresolved")
        self.assertIsNone(report["connections"][0]["source_binding"]["normalized_path"])

    def test_invalid_retry_authority_is_unknown_not_successful_progress(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "legacy"
            catalog = root / "catalog" / "catalog.sqlite3"
            catalog.parent.mkdir(parents=True)
            conn = sqlite3.connect(catalog)
            try:
                conn.execute(
                    "CREATE TABLE queue_jobs (status TEXT, retry_pending INTEGER, retry_order INTEGER, "
                    "created_at TEXT, finished_at TEXT, lease_owner TEXT, lease_expires_at TEXT, heartbeat_at TEXT)"
                )
                conn.execute("INSERT INTO queue_jobs VALUES ('succeeded', 1, 0, ?, ?, NULL, NULL, NULL)", (PAST, PAST))
                conn.commit()
            finally:
                conn.close()
            report = self._inspect(root)
        self.assertEqual(report["queue"]["counts"]["unknown"], 1)
        self.assertEqual(report["queue"]["counts"]["completed"], 0)
        self.assertEqual(report["queue"]["invalid_retry_rows"], 1)
        self.assertIsNone(report["workers"]["latest_successful_completion_at"])
        self.assertEqual(report["workers"]["successful_completions_last_24h"], 0)

    def test_unrecognized_commands_are_not_echoed_or_executed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "mcp.json"
            config.write_text(json.dumps({"mcpServers": {"continuum": {
                "command": "https://user:fixture-secret@example.invalid/run", "args": ["fixture-secret-argument"],
                "env": {"CONTINUUM_ROOT": "https://fixture-secret@example.invalid/root"},
            }}}), encoding="utf-8")
            report = self._inspect(Path(temporary) / "missing", codex_mcp_config=config)
        self.assertNotIn("fixture-secret", json.dumps(report))
        self.assertEqual(report["connections"][0]["launch_shape"], "unrecognized")

    def test_mismatching_absolute_path_values_are_not_echoed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "mcp.json"
            untrusted = str(Path(temporary) / "fixture-secret-command --key fixture-secret")
            config.write_text(json.dumps({"mcpServers": {"continuum": {
                "command": untrusted, "args": ["-m", "continuum.mcp_server"],
                "env": {"CONTINUUM_ROOT": untrusted, "PYTHONPATH": untrusted},
            }}}), encoding="utf-8")
            report = self._inspect(Path(temporary) / "missing", codex_mcp_config=config)
        self.assertNotIn("fixture-secret", json.dumps(report))
        for name in ("root_binding", "source_binding", "python_binding"):
            self.assertFalse(report["connections"][0][name]["matches"])
            self.assertIsNone(report["connections"][0][name]["normalized_path"])

    def test_config_directory_is_not_opened_as_a_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "config.json"
            config.mkdir()
            report = self._inspect(Path(temporary) / "missing", hermes_adapter_config=config)
        self.assertEqual(report["connections"][0]["state"], "not_regular_file")

    def test_missing_invalid_and_oversize_configs_are_not_initialized_or_echoed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "missing"
            config = Path(temporary) / "adapter.json"
            absent = self._inspect(root, hermes_adapter_config=config)
            self.assertFalse(config.exists())
            self.assertEqual(absent["connections"][0]["state"], "missing")
            for text, expected in (("fixture-secret invalid json", "unreadable"), ("[]", "invalid_object"), (" " * (256 * 1024 + 1), "too_large")):
                with self.subTest(expected=expected):
                    config.write_text(text, encoding="utf-8")
                    report = self._inspect(root, hermes_adapter_config=config)
                    self.assertEqual(report["connections"][0]["state"], expected)
                    self.assertNotIn("fixture-secret", json.dumps(report))
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
