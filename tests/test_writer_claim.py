from __future__ import annotations

import io
import hashlib
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from continuum.cli import main as cli_main
from continuum.core.bundle import _is_transient
from continuum.core.operations import doctor, start_operation, verify_root
from continuum.core.store import append_scroll_event, connect, connect_existing, init_db, status
from continuum.core.workers import run_worker_pass
from continuum.core.writer_claim import (
    WRITER_AUTHORITY_ENV,
    WRITER_CLAIM_AUTHORITY_SCHEMA,
    WRITER_CLAIM_SCHEMA,
    WriterClaimError,
    _is_wsl_windows_mount,
    claim_writer,
    detect_runtime_identity,
    ensure_writer_claim,
    writer_claim_path,
    writer_claim_status,
)


WINDOWS = {"runtime": "windows", "host": "continuum-host"}
WSL = {"runtime": "wsl", "host": "continuum-host"}
LINUX = {"runtime": "linux", "host": "linux-host"}
PROMOTION_AUTHORITY = "a" * 64
NORMAL_AUTHORITY = "b" * 64


class WriterClaimTests(unittest.TestCase):
    @staticmethod
    def _write_authority_claim(root: Path, authority_id: str = PROMOTION_AUTHORITY) -> None:
        marker = writer_claim_path(root)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(
            json.dumps(
                {
                    "schema": WRITER_CLAIM_AUTHORITY_SCHEMA,
                    "runtime": WINDOWS["runtime"],
                    "host": WINDOWS["host"],
                    "claimed_at": "2026-07-30T00:00:00+00:00",
                    "authority_id": authority_id,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def _tree_state(root: Path) -> str:
        rows: list[dict[str, object]] = []
        paths = [root, *sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix())]
        for path in paths:
            item_stat = path.lstat()
            row: dict[str, object] = {
                "path": "." if path == root else path.relative_to(root).as_posix(),
                "kind": "directory" if path.is_dir() else "file",
                "mode": item_stat.st_mode,
                "size": item_stat.st_size,
                "mtime_ns": item_stat.st_mtime_ns,
            }
            if path.is_file():
                row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            rows.append(row)
        return hashlib.sha256(
            json.dumps(rows, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).hexdigest()

    def test_runtime_detection_distinguishes_windows_wsl_linux_and_macos(self) -> None:
        self.assertEqual(
            detect_runtime_identity(system="Windows", environ={}, osrelease="", hostname="HOST-A"),
            {"runtime": "windows", "host": "host-a"},
        )
        self.assertEqual(
            detect_runtime_identity(
                system="Linux",
                environ={"WSL_DISTRO_NAME": "Ubuntu"},
                osrelease="6.6.0-linux",
                hostname="HOST-A",
            ),
            {"runtime": "wsl", "host": "host-a"},
        )
        self.assertEqual(
            detect_runtime_identity(system="Linux", environ={}, osrelease="6.8.0-generic", hostname="HOST-B"),
            {"runtime": "linux", "host": "host-b"},
        )
        self.assertEqual(
            detect_runtime_identity(system="Darwin", environ={}, osrelease="24.0", hostname="MacBook"),
            {"runtime": "macos", "host": "macbook"},
        )
        self.assertEqual(
            detect_runtime_identity(
                system="Linux",
                environ={},
                osrelease="5.15.153.1-microsoft-standard-WSL2",
                hostname="HOST-A",
            )["runtime"],
            "wsl",
        )

    def test_new_root_is_atomically_claimed_before_catalog_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch("continuum.core.writer_claim.detect_runtime_identity", return_value=WINDOWS):
                init_db(root)
                state = status(root, create=False)

            marker = writer_claim_path(root)
            claim = json.loads(marker.read_text(encoding="utf-8"))
            self.assertEqual(set(claim), {"schema", "runtime", "host", "claimed_at"})
            self.assertEqual(claim["schema"], WRITER_CLAIM_SCHEMA)
            self.assertEqual(claim["runtime"], "windows")
            self.assertEqual(claim["host"], "continuum-host")
            self.assertTrue(state["writer_claim"]["compatible"])
            self.assertTrue((root / "catalog" / "catalog.sqlite3").exists())

    def test_missing_root_status_is_read_only_and_does_not_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "missing"
            with patch("continuum.core.writer_claim.detect_runtime_identity", return_value=WINDOWS):
                state = status(root, create=False)

            self.assertFalse(state["initialized"])
            self.assertFalse(state["writer_claim"]["claimed"])
            self.assertFalse(root.exists())

    def test_bootstrap_config_and_lock_do_not_masquerade_as_legacy_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bootstrap"
            (root / "config").mkdir(parents=True)
            (root / "config" / "continuum.config.json").write_text("{}\n", encoding="utf-8")
            (root / "run" / "locks").mkdir(parents=True)

            claim = ensure_writer_claim(root, identity=WINDOWS)

            self.assertTrue(claim["claimed"])
            self.assertTrue(claim["compatible"])
            self.assertFalse(claim["root_has_existing_state"])

    def test_explicit_wal_aware_read_only_connection_observes_committed_wal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "wal-aware"
            with patch("continuum.core.writer_claim.detect_runtime_identity", return_value=WINDOWS):
                init_db(root)
                writer = connect(root)
                try:
                    writer.execute("PRAGMA wal_autocheckpoint = 0")
                    writer.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('wal_probe', 'visible')")
                    writer.commit()
                    reader = connect_existing(root, immutable=False)
                    try:
                        row = reader.execute("SELECT value FROM meta WHERE key = 'wal_probe'").fetchone()
                    finally:
                        reader.close()
                finally:
                    writer.close()

            self.assertIsNotNone(row)
            self.assertEqual(row["value"], "visible")

    def test_incompatible_runtime_refuses_live_wal_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "wal-runtime-boundary"
            with patch("continuum.core.writer_claim.detect_runtime_identity", return_value=WINDOWS):
                init_db(root)
                writer = connect(root)
                try:
                    writer.execute("PRAGMA wal_autocheckpoint = 0")
                    writer.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('wal_boundary', 'owned')")
                    writer.commit()
                    with patch("continuum.core.writer_claim.detect_runtime_identity", return_value=WSL):
                        with self.assertRaisesRegex(WriterClaimError, "live WAL read refused"):
                            connect_existing(root)
                finally:
                    writer.close()

    def test_existing_unclaimed_root_requires_explicit_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "legacy"
            (root / "catalog").mkdir(parents=True)
            (root / "catalog" / "catalog.sqlite3").write_bytes(b"legacy catalog placeholder")

            with self.assertRaisesRegex(WriterClaimError, "existing Continuum root has no writer claim"):
                ensure_writer_claim(root, identity=WINDOWS)

            claimed = claim_writer(root, identity=WINDOWS)
            self.assertTrue(claimed["changed"])
            self.assertTrue(claimed["compatible"])

    def test_windows_claim_blocks_wsl_catalog_and_operation_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch("continuum.core.writer_claim.detect_runtime_identity", return_value=WINDOWS):
                init_db(root)

            with patch("continuum.core.writer_claim.detect_runtime_identity", return_value=WSL):
                read_state = status(root, create=False)
                self.assertTrue(read_state["initialized"])
                self.assertFalse(read_state["writer_claim"]["compatible"])
                with self.assertRaisesRegex(WriterClaimError, "write-claimed by windows@continuum-host"):
                    connect(root)
                with self.assertRaises(WriterClaimError):
                    append_scroll_event(
                        root,
                        session_id="blocked",
                        event_type="message",
                        role="user",
                        content="must remain read only",
                    )
                before = list((root / "run" / "operations").glob("*.json")) if (root / "run" / "operations").exists() else []
                with self.assertRaises(WriterClaimError):
                    start_operation(root, operation_type="blocked", title="blocked")
                after = list((root / "run" / "operations").glob("*.json")) if (root / "run" / "operations").exists() else []
                self.assertEqual(after, before)

    def test_authority_claim_blocks_same_runtime_without_exact_capability(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch("continuum.core.writer_claim.detect_runtime_identity", return_value=WINDOWS):
                init_db(root)
                self._write_authority_claim(root)

                missing = writer_claim_status(root, environ={})
                self.assertTrue(missing["claimed"])
                self.assertTrue(missing["authority_required"])
                self.assertFalse(missing["authority_present"])
                self.assertFalse(missing["authority_compatible"])
                self.assertFalse(missing["compatible"])
                with patch.dict(os.environ, {WRITER_AUTHORITY_ENV: ""}):
                    with self.assertRaisesRegex(WriterClaimError, "recovery writer authority"):
                        connect(root)
                    with self.assertRaisesRegex(WriterClaimError, "recovery writer authority"):
                        append_scroll_event(
                            root,
                            session_id="fenced",
                            event_type="message",
                            role="user",
                            content="must remain fenced",
                        )
                    with self.assertRaisesRegex(WriterClaimError, "recovery writer authority"):
                        start_operation(root, operation_type="fenced", title="fenced")
                    with self.assertRaisesRegex(WriterClaimError, "recovery writer authority"):
                        run_worker_pass(root, limit=1, maintenance=False)

                with patch.dict(os.environ, {WRITER_AUTHORITY_ENV: NORMAL_AUTHORITY}):
                    wrong = writer_claim_status(root)
                    self.assertTrue(wrong["authority_present"])
                    self.assertFalse(wrong["authority_compatible"])
                    self.assertFalse(wrong["compatible"])
                    with self.assertRaisesRegex(WriterClaimError, "recovery writer authority"):
                        init_db(root)

    def test_authority_claim_allows_only_exact_case_sensitive_capability(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch("continuum.core.writer_claim.detect_runtime_identity", return_value=WINDOWS):
                init_db(root)
                self._write_authority_claim(root)

                with patch.dict(os.environ, {WRITER_AUTHORITY_ENV: PROMOTION_AUTHORITY}):
                    allowed = ensure_writer_claim(root)
                    connection = connect(root)
                    connection.close()
                    unchanged = claim_writer(root)

                self.assertTrue(allowed["compatible"])
                self.assertTrue(allowed["authority_required"])
                self.assertTrue(allowed["authority_compatible"])
                self.assertFalse(unchanged["changed"])
                self.assertEqual(unchanged["claim"]["schema"], WRITER_CLAIM_AUTHORITY_SCHEMA)

                with patch.dict(os.environ, {WRITER_AUTHORITY_ENV: PROMOTION_AUTHORITY.upper()}):
                    with self.assertRaisesRegex(WriterClaimError, "recovery writer authority"):
                        ensure_writer_claim(root)
                    with self.assertRaisesRegex(WriterClaimError, "recovery writer authority"):
                        connect(root)
                    with self.assertRaisesRegex(WriterClaimError, "recovery writer authority"):
                        start_operation(root, operation_type="wrong-authority", title="wrong-authority")
                    with self.assertRaisesRegex(WriterClaimError, "recovery writer authority"):
                        run_worker_pass(root, limit=1, maintenance=False)

                with patch.dict(os.environ, {WRITER_AUTHORITY_ENV: "malformed"}):
                    with self.assertRaisesRegex(WriterClaimError, "recovery writer authority"):
                        connect(root)

    def test_authority_claim_requires_valid_exact_marker_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            self._write_authority_claim(root, "ABC")

            state = writer_claim_status(root, identity=WINDOWS, environ={WRITER_AUTHORITY_ENV: "ABC"})

            self.assertFalse(state["ok"])
            self.assertFalse(state["compatible"])
            self.assertIn("64 lowercase hexadecimal", state["error"])

    def test_authority_claim_rejects_unbound_extra_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            self._write_authority_claim(root)
            marker = writer_claim_path(root)
            payload = json.loads(marker.read_text(encoding="utf-8"))
            payload["unexpected"] = "not-authority"
            marker.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            state = writer_claim_status(
                root,
                identity=WINDOWS,
                environ={WRITER_AUTHORITY_ENV: PROMOTION_AUTHORITY},
            )

            self.assertFalse(state["ok"])
            self.assertFalse(state["compatible"])
            self.assertIn("must contain exactly", state["error"])

    def test_v1_claim_remains_compatible_with_unrelated_authority_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            claim_writer(root, identity=WINDOWS, environ={WRITER_AUTHORITY_ENV: NORMAL_AUTHORITY})

            status_result = writer_claim_status(
                root,
                identity=WINDOWS,
                environ={WRITER_AUTHORITY_ENV: NORMAL_AUTHORITY},
            )

            self.assertEqual(status_result["claim"]["schema"], WRITER_CLAIM_SCHEMA)
            self.assertTrue(status_result["compatible"])
            self.assertFalse(status_result["authority_required"])
            self.assertTrue(status_result["authority_present"])
            self.assertTrue(status_result["authority_compatible"])

    def test_authority_claim_force_transfer_still_requires_stopped_writer_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            self._write_authority_claim(root)

            with self.assertRaisesRegex(WriterClaimError, "stop every Continuum writer"):
                claim_writer(root, identity=WINDOWS, force=True, environ={})
            transferred = claim_writer(
                root,
                identity=WINDOWS,
                force=True,
                acknowledge_writers_stopped=True,
                environ={},
            )

            self.assertTrue(transferred["changed"])
            self.assertEqual(transferred["claim"]["schema"], WRITER_CLAIM_SCHEMA)
            self.assertEqual(transferred["previous_claim"]["schema"], WRITER_CLAIM_AUTHORITY_SCHEMA)

    def test_fenced_doctor_and_verify_are_full_tree_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch("continuum.core.writer_claim.detect_runtime_identity", return_value=WINDOWS):
                init_db(root)
                self._write_authority_claim(root)

                before_doctor = self._tree_state(root)
                with patch.dict(os.environ, {WRITER_AUTHORITY_ENV: ""}):
                    doctor_result = doctor(
                        root,
                        verify_recent_proof_packs=0,
                        scan_secrets=False,
                    )
                after_doctor = self._tree_state(root)

                self.assertEqual(after_doctor, before_doctor)
                self.assertFalse(doctor_result["ok"])
                self.assertFalse(doctor_result["complete"])
                self.assertEqual(
                    doctor_result["diagnostic_mode"],
                    "read_only_writer_claim_fenced",
                )
                writable_checks = [
                    check
                    for check in doctor_result["checks"]
                    if str(check["name"]).startswith("writable:")
                ]
                self.assertEqual(writable_checks, [])
                self.assertFalse(doctor_result["writability_verified"])
                self.assertEqual(
                    doctor_result["write_probe_mode"],
                    "disabled_read_only_contract",
                )

                before_verify = self._tree_state(root)
                with patch.dict(os.environ, {WRITER_AUTHORITY_ENV: NORMAL_AUTHORITY}):
                    verify_result = verify_root(
                        root,
                        strict=True,
                        run_restore_drill=True,
                        verify_recent_proof_packs=0,
                        scan_secrets=False,
                    )
                after_verify = self._tree_state(root)

                self.assertEqual(after_verify, before_verify)
                self.assertFalse(verify_result["ok"])
                self.assertFalse(verify_result["complete"])
                self.assertFalse(verify_result["writability_verified"])
                self.assertFalse(verify_result["run_restore_drill"])
                self.assertTrue(verify_result["sections"]["restore_drill"]["skipped"])
                self.assertEqual(
                    verify_result["diagnostic_mode"],
                    "read_only_writer_claim_fenced",
                )

    def test_verify_honors_doctor_observed_fence_transition(self) -> None:
        compatible_claim = {
            "ok": True,
            "claimed": True,
            "compatible": True,
            "root_has_existing_state": True,
            "claim": {
                "schema": WRITER_CLAIM_SCHEMA,
                "runtime": "windows",
                "host": "continuum-host",
            },
        }
        fenced_claim = {
            "ok": True,
            "claimed": True,
            "compatible": False,
            "root_has_existing_state": True,
            "claim": {
                "schema": WRITER_CLAIM_AUTHORITY_SCHEMA,
                "runtime": "windows",
                "host": "continuum-host",
                "authority_id": PROMOTION_AUTHORITY,
            },
        }
        doctor_result = {
            "ok": False,
            "complete": False,
            "diagnostic_mode": "read_only_writer_claim_fenced",
            "reason": "writer_claim_incompatible_read_only_diagnostic",
            "check_count": 1,
            "checks": [],
            "writer_claim": fenced_claim,
            "status": {"writer_claim": fenced_claim},
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with (
                patch("continuum.core.operations.doctor", return_value=doctor_result),
                patch(
                    "continuum.core.operations.writer_claim_status",
                    return_value=compatible_claim,
                ),
                patch("continuum.core.operations.audit_search_index") as search_audit,
                patch("continuum.core.operations.restore_drill") as restore,
            ):
                result = verify_root(
                    root,
                    strict=True,
                    run_restore_drill=True,
                    verify_recent_proof_packs=0,
                    scan_secrets=False,
                )

            self.assertFalse(result["ok"])
            self.assertFalse(result["complete"])
            self.assertEqual(
                result["diagnostic_mode"],
                "read_only_writer_claim_fenced",
            )
            search_audit.assert_not_called()
            restore.assert_not_called()

    def test_strict_verify_degrades_to_read_only_on_runtime_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch("continuum.core.writer_claim.detect_runtime_identity", return_value=WINDOWS):
                init_db(root)

            with (
                patch("continuum.core.writer_claim.detect_runtime_identity", return_value=WSL),
                patch("continuum.core.operations.restore_drill", side_effect=AssertionError("must not mutate")),
            ):
                result = verify_root(
                    root,
                    strict=True,
                    run_restore_drill=True,
                    verify_recent_proof_packs=0,
                    scan_secrets=False,
                )

            self.assertTrue(result["restore_drill_requested"])
            self.assertFalse(result["run_restore_drill"])
            self.assertTrue(result["sections"]["restore_drill"]["skipped"])
            self.assertEqual(
                result["sections"]["restore_drill"]["reason"],
                "writer_claim_incompatible_read_only_verification",
            )

    def test_force_transfer_requires_stopped_writer_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            claim_writer(root, identity=WINDOWS)

            with self.assertRaisesRegex(WriterClaimError, "stop every Continuum writer"):
                claim_writer(root, identity=LINUX)
            with self.assertRaisesRegex(WriterClaimError, "stop every Continuum writer"):
                claim_writer(root, identity=LINUX, force=True)
            transferred = claim_writer(
                root,
                identity=LINUX,
                force=True,
                acknowledge_writers_stopped=True,
            )

            self.assertTrue(transferred["changed"])
            self.assertEqual(transferred["claim"]["runtime"], "linux")
            self.assertEqual(transferred["previous_claim"]["runtime"], "windows")

    def test_cli_exposes_read_only_status_and_explicit_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            output = io.StringIO()
            with (
                patch("continuum.core.writer_claim.detect_runtime_identity", return_value=WINDOWS),
                redirect_stdout(output),
            ):
                self.assertEqual(cli_main(["writer-status", "--root", str(root)]), 0)
                self.assertEqual(cli_main(["writer-claim", "--root", str(root)]), 0)

            lines = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertFalse(lines[0]["claimed"])
            self.assertTrue(lines[1]["claimed"])
            self.assertTrue(lines[1]["compatible"])

    def test_wsl_mounted_windows_drive_never_auto_claims(self) -> None:
        self.assertTrue(_is_wsl_windows_mount(Path("/mnt/c/continuum")))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with (
                patch("continuum.core.writer_claim._is_wsl_windows_mount", return_value=True),
                self.assertRaisesRegex(WriterClaimError, "WSL will not auto-claim"),
            ):
                ensure_writer_claim(root, identity=WSL)
            self.assertFalse(root.exists())

    def test_claim_refuses_linked_config_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            root.mkdir()
            target = base / "outside"
            target.mkdir()
            try:
                (root / "config").symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"directory symlinks unavailable: {exc}")
            with self.assertRaisesRegex(WriterClaimError, "unsafe writer-claim config directory"):
                claim_writer(root, identity=WINDOWS)
            self.assertFalse((target / "writer-claim.json").exists())

    def test_writer_claim_is_not_portable_bundle_state(self) -> None:
        self.assertTrue(_is_transient(Path("config/writer-claim.json")))

    def test_status_reports_malformed_marker_without_mutating_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            marker = root / "config" / "writer-claim.json"
            marker.parent.mkdir(parents=True)
            marker.write_text("{not json", encoding="utf-8")
            before = marker.read_bytes()

            state = writer_claim_status(root, identity=WINDOWS)

            self.assertFalse(state["ok"])
            self.assertFalse(state["compatible"])
            self.assertEqual(marker.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
