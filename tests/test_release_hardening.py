from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum.core.bundle import pack_root
from continuum.core.mempalace_import import import_mempalace
from continuum.core.operations import create_proof_pack, doctor, finish_operation, repair_permissions, start_operation
from continuum.core.permissions import PRIVATE_DIR_MODE, PRIVATE_FILE_MODE, audit_private_permissions, posix_permissions_supported
from continuum.core.store import audit_search_index, ingest_file, init_db, snapshot
from continuum.integrations.hermes_adapter import REDACTED_SECRET, install_hermes_adapter
from continuum.mcp_server import dispatch


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def _assert_private_root(testcase: unittest.TestCase, root: Path) -> None:
    audited = audit_private_permissions(root)
    testcase.assertTrue(audited["ok"], audited)


def _create_minimal_mempalace(palace: Path) -> None:
    palace.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(palace / "chroma.sqlite3")
    try:
        conn.executescript(
            """
            CREATE TABLE embeddings (
                id INTEGER PRIMARY KEY,
                segment_id TEXT NOT NULL,
                embedding_id TEXT NOT NULL,
                seq_id BLOB NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (segment_id, embedding_id)
            );
            CREATE TABLE embedding_metadata (
                id INTEGER REFERENCES embeddings(id),
                key TEXT NOT NULL,
                string_value TEXT,
                int_value INTEGER,
                float_value REAL,
                bool_value INTEGER,
                PRIMARY KEY (id, key)
            );
            CREATE VIRTUAL TABLE embedding_fulltext_search USING fts5(string_value);
            """
        )
        conn.execute(
            "INSERT INTO embeddings(id, segment_id, embedding_id, seq_id, created_at) VALUES(1, 'seg-a', 'drawer_operator_core_context_general_alpha', 1, '2026-06-01 00:00:00')"
        )
        metadata = {
            "wing": "operator_core_context",
            "room": "general",
            "source_file": "/portable/example.md",
            "chroma:document": "Alpha drawer content with Epic Continuum migration notes.",
        }
        conn.execute(
            "INSERT INTO embedding_fulltext_search(rowid, string_value) VALUES(1, ?)",
            (metadata["chroma:document"],),
        )
        for key, value in metadata.items():
            conn.execute(
                "INSERT INTO embedding_metadata(id, key, string_value, int_value, float_value, bool_value) VALUES(1, ?, ?, NULL, NULL, NULL)",
                (key, value),
            )
        conn.commit()
    finally:
        conn.close()


class ReleaseHardeningTest(unittest.TestCase):
    def test_pack_root_does_not_chmod_existing_external_export_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            if os.name != "posix" or not posix_permissions_supported(Path(tmp)):
                self.skipTest("POSIX mode checks require chmod-style permissions")
            base = Path(tmp)
            root = base / "epic-continuum"
            export_parent = base / "downloads"
            export_parent.mkdir()
            export_parent.chmod(0o755)

            init_db(root)
            result = pack_root(root, out_path=export_parent / "continuum.zip", run_restore_drill=False)

            self.assertTrue(result["ok"], result)
            self.assertEqual(_mode(export_parent), 0o755)

    def test_symlinked_memory_root_does_not_break_permission_handling(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            if os.name != "posix" or not posix_permissions_supported(Path(tmp)):
                self.skipTest("POSIX mode checks require chmod-style permissions")
            base = Path(tmp)
            target = base / "actual-root"
            link = base / "linked-root"
            target.mkdir()
            try:
                link.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")

            init_db(link)
            audited = audit_private_permissions(link)

            self.assertTrue((target / "catalog" / "catalog.sqlite3").exists())
            self.assertTrue(audited["ok"], audited)

    def test_release_builder_refuses_dirty_tracked_tree_unless_explicitly_allowed(self) -> None:
        if not shutil.which("git"):
            self.skipTest("git is required for dirty-tree release builder smoke")
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo = base / "repo"
            out = base / "dist"
            repo.mkdir()
            (repo / "pyproject.toml").write_text(
                """
[project]
name = "epic-continuum-memory"
version = "9.9.9"
""".lstrip(),
                encoding="utf-8",
            )
            (repo / "README.md").write_text("clean\n", encoding="utf-8")
            subprocess.run(["git", "init"], cwd=repo, check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "add", "pyproject.toml", "README.md"], cwd=repo, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.email=continuum@example.invalid",
                    "-c",
                    "user.name=Continuum Test",
                    "commit",
                    "-m",
                    "initial",
                ],
                cwd=repo,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            (repo / "README.md").write_text("dirty sentinel\n", encoding="utf-8")

            script = Path(__file__).resolve().parents[1] / "scripts" / "build_release_package.py"
            blocked = subprocess.run(
                [sys.executable, str(script), "--repo-root", str(repo), "--out-dir", str(out)],
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(blocked.returncode, 0, blocked.stdout + blocked.stderr)
            self.assertIn("tracked working-tree changes", blocked.stderr)

            allowed = subprocess.run(
                [sys.executable, str(script), "--repo-root", str(repo), "--out-dir", str(out), "--allow-dirty"],
                text=True,
                capture_output=True,
            )
            self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
            self.assertTrue((out / "epic-continuum-9.9.9.zip").exists())

    def test_codex_stage_helper_preserves_base_and_writes_bomless_cachebusted_plugin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(__file__).resolve().parents[1]
            stage_base = Path(tmp) / "stage-base"
            stage_base.mkdir()
            sentinel = stage_base / "keep.txt"
            sentinel.write_text("keep\n", encoding="utf-8")
            script = repo_root / "scripts" / "stage_codex_plugin.py"

            proc = subprocess.run(
                [
                    sys.executable,
                    str(script),
                    "--repo-root",
                    str(repo_root),
                    "--root",
                    str(Path(tmp) / "continuum-root"),
                    "--python",
                    sys.executable,
                    "--stage-base",
                    str(stage_base),
                ],
                text=True,
                capture_output=True,
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertTrue(sentinel.exists())
            stage_root = Path(proc.stdout.strip())
            self.assertEqual(stage_root.parent.resolve(), stage_base.resolve())
            self.assertTrue(stage_root.name.startswith("continuum-"))

            mcp_bytes = (stage_root / "plugins" / "continuum" / ".mcp.json").read_bytes()
            self.assertFalse(mcp_bytes.startswith(b"\xef\xbb\xbf"))
            json.loads(mcp_bytes.decode("utf-8"))

            manifest = json.loads((stage_root / "plugins" / "continuum" / ".codex-plugin" / "plugin.json").read_text())
            self.assertIn(".local.", manifest["version"])
            self.assertLessEqual(len(manifest["interface"]["defaultPrompt"]), 3)

    def test_private_root_files_are_created_private_and_repairable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            if os.name != "posix" or not posix_permissions_supported(Path(tmp)):
                self.skipTest("POSIX mode checks require chmod-style permissions")
            root = Path(tmp) / "epic-continuum"
            old_umask = os.umask(0o022)
            try:
                init_db(root)
            finally:
                os.umask(old_umask)

            self.assertEqual(_mode(root), PRIVATE_DIR_MODE)
            self.assertEqual(_mode(root / "config"), PRIVATE_DIR_MODE)
            self.assertEqual(_mode(root / "catalog"), PRIVATE_DIR_MODE)
            self.assertEqual(_mode(root / "config" / "continuum.config.json"), PRIVATE_FILE_MODE)
            self.assertEqual(_mode(root / "catalog" / "catalog.sqlite3"), PRIVATE_FILE_MODE)

            unsafe_file = root / "archive" / "unsafe.txt"
            unsafe_file.parent.mkdir(parents=True, exist_ok=True)
            unsafe_file.write_text("private memory\n", encoding="utf-8")
            unsafe_file.chmod(0o644)

            before = doctor(root, verify_recent_proof_packs=0)
            private_check = next(check for check in before["checks"] if check["name"] == "private_permissions")
            self.assertFalse(private_check["ok"], before)

            repaired = repair_permissions(root)
            self.assertTrue(repaired["ok"], repaired)
            self.assertEqual(_mode(unsafe_file), PRIVATE_FILE_MODE)

            after = doctor(root, verify_recent_proof_packs=0)
            private_check = next(check for check in after["checks"] if check["name"] == "private_permissions")
            self.assertTrue(private_check["ok"], after)

    def test_private_root_stays_private_after_normal_operations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            if os.name != "posix" or not posix_permissions_supported(Path(tmp)):
                self.skipTest("POSIX mode checks require chmod-style permissions")
            root = Path(tmp) / "epic-continuum"
            source = Path(tmp) / "source.txt"
            source.write_text("Private evidence for permission hardening.\n", encoding="utf-8")
            old_umask = os.umask(0o022)
            try:
                init_db(root)
                _assert_private_root(self, root)

                ingest_file(root, path=source, title="Permission hardening source")
                _assert_private_root(self, root)

                snapshot(root, reason="permission_hardening_snapshot")
                _assert_private_root(self, root)

                operation = start_operation(root, operation_type="permission_hardening", title="Permission hardening proof")
                finish_operation(root, operation["operation_id"], status="succeeded", result={"ok": True})
                create_proof_pack(
                    root,
                    operation["operation_id"],
                    touched_paths=[root / "catalog" / "catalog.sqlite3", root / "config" / "continuum.config.json"],
                )
                _assert_private_root(self, root)
            finally:
                os.umask(old_umask)

    def test_private_root_stays_private_after_mempalace_import(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            if os.name != "posix" or not posix_permissions_supported(Path(tmp)):
                self.skipTest("POSIX mode checks require chmod-style permissions")
            root = Path(tmp) / "epic-continuum"
            palace = Path(tmp) / "palace"
            _create_minimal_mempalace(palace)
            old_umask = os.umask(0o022)
            try:
                import_mempalace(root, palace_path=palace, include_closets=False, include_kg=False)
                _assert_private_root(self, root)
            finally:
                os.umask(old_umask)

    def test_fts_absence_is_healthy_degraded_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            with patch("continuum.core.store.ensure_fts", return_value=False):
                init_db(root)

            audit = audit_search_index(root, create=False)
            self.assertTrue(audit["ok"], audit)
            self.assertTrue(audit["degraded"], audit)
            self.assertFalse(audit["fts_available"], audit)

            checked = doctor(root, verify_recent_proof_packs=0)
            search_check = next(check for check in checked["checks"] if check["name"] == "search_index_consistent")
            self.assertTrue(search_check["ok"], checked)
            self.assertFalse(search_check["fts_available"], checked)

    def test_hermes_secret_api_key_is_never_placed_in_recorded_or_executed_argv(self) -> None:
        secret = "sk-secretvalue12345678901234567890"
        with tempfile.TemporaryDirectory() as tmp:
            hermes_home = Path(tmp) / "hermes"
            root = Path(tmp) / "continuum"
            continuum_src = Path(__file__).resolve().parents[1] / "src"
            hermes_exe = Path(tmp) / "hermes.exe"
            hermes_exe.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")

            with patch.dict(os.environ, {"HERMES_TEST_API_KEY": secret}), patch(
                "continuum.integrations.hermes_adapter.subprocess.run"
            ) as run:
                run.return_value.returncode = 0
                run.return_value.stdout = ""
                run.return_value.stderr = ""
                result = install_hermes_adapter(
                    hermes_home=hermes_home,
                    continuum_root=root,
                    continuum_src=continuum_src,
                    enable=True,
                    dry_run=False,
                    hermes_exe=hermes_exe,
                    model_alias="secret-model",
                    model_name="secret-model",
                    base_url="http://127.0.0.1:9999/v1",
                    api_key_env="HERMES_TEST_API_KEY",
                    set_default_model=True,
                )

            serialized = json.dumps(result, ensure_ascii=True)
            self.assertNotIn(secret, serialized)
            self.assertIn(REDACTED_SECRET, serialized)
            self.assertFalse(result["api_key_applied_to_default_model"])
            self.assertTrue(any(command.get("api_key_source") == "env:HERMES_TEST_API_KEY" for command in result["commands"]))
            executed_argv = json.dumps([call.args[0] for call in run.call_args_list], ensure_ascii=True)
            self.assertNotIn(secret, executed_argv)
            self.assertFalse(any("model.api_key" in call.args[0] for call in run.call_args_list))

    def test_mcp_annotations_are_explicit_for_local_and_destructive_tools(self) -> None:
        response = dispatch({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})

        self.assertIsNotNone(response)
        assert response is not None
        tools = {tool["name"]: tool for tool in response["result"]["tools"]}

        self.assertFalse(tools["continuum_status"]["annotations"]["openWorldHint"])
        self.assertFalse(tools["continuum_doctor"]["annotations"]["openWorldHint"])
        self.assertTrue(tools["continuum_rebuild_search_index"]["annotations"]["idempotentHint"])
        self.assertFalse(tools["continuum_rebuild_search_index"]["annotations"]["destructiveHint"])
        self.assertTrue(tools["continuum_repair_permissions"]["annotations"]["idempotentHint"])
        self.assertFalse(tools["continuum_repair_permissions"]["annotations"]["openWorldHint"])
        self.assertTrue(tools["continuum_import_mempalace"]["annotations"]["openWorldHint"])
        self.assertTrue(tools["continuum_prune_memory"]["annotations"]["destructiveHint"])


if __name__ == "__main__":
    unittest.main()
