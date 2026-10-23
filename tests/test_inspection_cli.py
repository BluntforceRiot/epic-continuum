from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import continuum
from continuum.core.store import append_scroll_event, connect_existing


class InspectionCliTest(unittest.TestCase):
    def call(self, root: Path, *args: str) -> dict:
        env = {**os.environ, "PYTHONPATH": str(Path(continuum.__file__).parent.parent), "PYTHONDONTWRITEBYTECODE": "1"}
        run = subprocess.run([sys.executable, "-B", "-m", "continuum", "inspect", "--root", str(root), *args],
                             capture_output=True, text=True, env=env, cwd=root.parent, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def test_missing_root_report_never_initializes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "missing"
            report = self.call(root)
            self.assertFalse(root.exists())
            self.assertFalse(report["ok"])
            self.assertEqual(report["reason"], "catalog_missing")
            self.assertEqual(report["runtime"]["active_version"], continuum.__version__)
            self.assertEqual(report["workers"]["service_liveness"], "not_checked")

    def test_initialized_root_has_read_only_logical_state_and_true_pending_count(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "memory"
            append_scroll_event(root, session_id="cli-contract", event_type="message", role="user", content="A safe note.")
            def state():
                conn = connect_existing(root)
                try:
                    return list(conn.iterdump())
                finally:
                    conn.close()
            before = state()
            config = root / "config/continuum.config.json"
            config_before = config.read_bytes()
            report = self.call(root)
            self.assertTrue(report["ok"])
            self.assertEqual(report["queue"]["counts"]["pending"], 1)
            self.assertEqual(report["queue"]["counts"]["completed"], 0)
            self.assertEqual(before, state())
            self.assertEqual(config_before, config.read_bytes())
            self.assertFalse((root / "run/operations").exists())

    def test_explicit_connection_file_is_not_modified_or_executed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "missing"
            config = Path(tmp) / "codex.json"
            config.write_text(json.dumps({"mcpServers": {"continuum": {
                "command": str(Path(sys.executable)), "args": ["-m", "continuum.mcp_server"],
                "env": {"CONTINUUM_ROOT": str(root), "PYTHONPATH": str(Path(continuum.__file__).parent.parent)},
            }}}), encoding="utf-8")
            before = config.read_bytes()
            report = self.call(root, "--codex-config", str(config))
            connection = report["connections"][0]
            self.assertFalse(connection["commands_executed"])
            self.assertFalse(connection["live_connection_verified"])
            self.assertTrue(connection["root_binding"]["matches"])
            self.assertEqual(before, config.read_bytes())
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
