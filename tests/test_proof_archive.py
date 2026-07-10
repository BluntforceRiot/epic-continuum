from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import continuum.core.proof_archive as proof_archive_module
from continuum.core.proof_archive import (
    ProofArchiveError,
    RelocatedArtifactIntegrityError,
    RelocationLedgerError,
    apply_legacy_catalog_archive,
    configured_archive_root,
    plan_legacy_catalog_archive,
    resolve_configured_relocated_proof,
    resolve_relocated_proof,
    restore_relocated_proof,
    verify_relocation_ledger,
)
from continuum.core.operations import create_proof_pack, finish_operation, start_operation
from continuum.core.store import connect, init_db, record_artifact


def _identity(data: bytes) -> tuple[str, int]:
    return hashlib.sha256(data).hexdigest(), len(data)


def _make_directory_link(testcase: unittest.TestCase, link: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if completed.returncode != 0:
            testcase.skipTest(f"junction creation unavailable: {completed.stdout} {completed.stderr}")
        return
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        testcase.skipTest(f"symlink creation unavailable: {exc}")


def _remove_directory_link(link: Path) -> None:
    if os.name == "nt":
        os.rmdir(link)
    else:
        link.unlink()


class ProofArchiveTest(unittest.TestCase):
    def test_macos_system_alias_allowlist_requires_direct_physical_target(self) -> None:
        def directory_lstat(path: Path) -> SimpleNamespace:
            self.assertIn(Path(path).as_posix(), {"/private", "/private/tmp", "/private/var"})
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755)

        with (
            patch.object(proof_archive_module.sys, "platform", "darwin"),
            patch.object(
                proof_archive_module.os,
                "readlink",
                side_effect=lambda path: {"/tmp": "private/tmp", "/var": "private/var"}[Path(path).as_posix()],
            ),
            patch.object(proof_archive_module.os, "lstat", side_effect=directory_lstat),
        ):
            self.assertTrue(proof_archive_module._allowed_platform_symlink(Path("/var"), "symlink"))
            self.assertTrue(proof_archive_module._allowed_platform_symlink(Path("/tmp"), "symlink"))
            self.assertFalse(proof_archive_module._allowed_platform_symlink(Path("/etc"), "symlink"))
            self.assertFalse(proof_archive_module._allowed_platform_symlink(Path("/var"), "junction"))

        with (
            patch.object(proof_archive_module.sys, "platform", "darwin"),
            patch.object(proof_archive_module.os, "readlink", return_value="intermediate/var"),
        ):
            self.assertFalse(proof_archive_module._allowed_platform_symlink(Path("/var"), "symlink"))

        with (
            patch.object(proof_archive_module.sys, "platform", "darwin"),
            patch.object(proof_archive_module.os, "readlink", return_value="private/var"),
            patch.object(
                proof_archive_module.os,
                "lstat",
                return_value=SimpleNamespace(st_mode=stat.S_IFLNK | 0o777),
            ),
        ):
            self.assertFalse(proof_archive_module._allowed_platform_symlink(Path("/var"), "symlink"))

    @unittest.skipUnless(sys.platform == "darwin", "macOS system alias contract")
    def test_standard_macos_temp_alias_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"

            plan = plan_legacy_catalog_archive(root, archive)

            self.assertEqual(plan["candidate_count"], 0)
            self.assertTrue(proof_archive_module._allowed_platform_symlink(Path("/var"), "symlink"))
            self.assertTrue(proof_archive_module._allowed_platform_symlink(Path("/tmp"), "symlink"))
            self.assertFalse(
                proof_archive_module._allowed_platform_symlink(base / "arbitrary-link", "symlink")
            )
            with self.assertRaisesRegex(ProofArchiveError, "refusing symlink traversal"):
                proof_archive_module._assert_no_link_components(Path("/etc"))
            with self.assertRaisesRegex(ProofArchiveError, "must not overlap"):
                plan_legacy_catalog_archive(root, root.resolve(strict=True) / "nested-archive")

        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            base = Path(tmp)
            root = self._root(base)

            plan = plan_legacy_catalog_archive(root, base / "external-archive")

            self.assertEqual(plan["candidate_count"], 0)

    def _root(self, base: Path) -> Path:
        root = base / "continuum-root"
        init_db(root)
        return root

    def _proof(
        self,
        root: Path,
        operation_id: str,
        data: bytes,
        *,
        referenced: bool = True,
        ledger_sha256: str | None = None,
        ledger_size: int | None = None,
        modified_ns: int | None = None,
    ) -> tuple[Path, str, str, int]:
        source_uri = f"exports/proof_artifacts/{operation_id}/catalog.snapshot.sqlite3"
        source = root.joinpath(*source_uri.split("/"))
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_bytes(data)
        if modified_ns is not None:
            os.utime(source, ns=(modified_ns, modified_ns))
        sha256, size_bytes = _identity(data)
        if referenced:
            conn = connect(root)
            try:
                record_artifact(
                    conn,
                    kind="proof_input",
                    uri=source_uri,
                    sha256=ledger_sha256 or sha256,
                    size_bytes=size_bytes if ledger_size is None else ledger_size,
                    operation_id=operation_id,
                    immutable=True,
                    source_type="proof_pack",
                    trust_level="local_artifact",
                )
                conn.commit()
            finally:
                conn.close()
        return source, source_uri, sha256, size_bytes

    def test_dry_run_skips_unsafe_artifacts_and_keeps_latest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            old = self._proof(root, "op_old", b"old catalog", modified_ns=1_000_000_000)
            latest = self._proof(root, "op_latest", b"latest catalog", modified_ns=2_000_000_000)
            self._proof(root, "op_zero", b"")
            self._proof(root, "op_unreferenced", b"orphan", referenced=False)
            self._proof(root, "op_mismatch", b"changed", ledger_sha256="0" * 64)

            plan = plan_legacy_catalog_archive(root, archive, keep_latest=1)

            self.assertFalse(archive.exists(), "planning must not initialize or mutate the archive")
            self.assertEqual(plan["candidate_count"], 1)
            self.assertEqual(plan["items"][0]["source_uri"], old[1])
            reasons = {item["source_uri"]: item["reason"] for item in plan["skipped"]}
            self.assertEqual(reasons[latest[1]], "keep_latest")
            self.assertEqual(reasons["exports/proof_artifacts/op_zero/catalog.snapshot.sqlite3"], "zero_byte_source")
            self.assertEqual(reasons["exports/proof_artifacts/op_unreferenced/catalog.snapshot.sqlite3"], "unreferenced_source")
            self.assertEqual(reasons["exports/proof_artifacts/op_mismatch/catalog.snapshot.sqlite3"], "artifact_ledger_mismatch")

    def test_archive_records_verified_destination_before_removing_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            source, source_uri, sha256, size_bytes = self._proof(root, "op_order", b"catalog evidence")
            real_remove = proof_archive_module._remove_verified_source
            observed: dict[str, object] = {}

            def inspect_then_remove(
                path: Path,
                *,
                sha256: str,
                size_bytes: int,
                expected_identity: dict[str, object] | None = None,
            ) -> None:
                ledger = verify_relocation_ledger(root, archive)
                resolved = resolve_relocated_proof(
                    root,
                    archive,
                    source_uri,
                    expected_sha256=sha256,
                    expected_size_bytes=size_bytes,
                )
                observed.update(
                    ledger_count=ledger["record_count"],
                    resolved=resolved,
                    configured=configured_archive_root(root),
                )
                real_remove(
                    path,
                    sha256=sha256,
                    size_bytes=size_bytes,
                    expected_identity=expected_identity,
                )

            with patch.object(proof_archive_module, "_remove_verified_source", side_effect=inspect_then_remove):
                result = apply_legacy_catalog_archive(root, archive)

            self.assertTrue(result["ok"])
            self.assertFalse(source.exists())
            self.assertEqual(observed["ledger_count"], 1)
            self.assertEqual(observed["configured"], archive.resolve(strict=True))
            resolved = Path(str(observed["resolved"]))
            self.assertTrue(resolved.exists())
            self.assertEqual(_identity(resolved.read_bytes()), (sha256, size_bytes))

    def test_failed_source_removal_is_idempotently_completed_without_duplicate_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            source, source_uri, sha256, size_bytes = self._proof(root, "op_retry", b"retry evidence")
            with patch.object(proof_archive_module, "_remove_verified_source", side_effect=OSError("busy")):
                first = apply_legacy_catalog_archive(root, archive)

            self.assertFalse(first["ok"])
            self.assertTrue(source.exists())
            self.assertEqual(verify_relocation_ledger(root, archive)["record_count"], 1)

            second = apply_legacy_catalog_archive(root, archive)

            self.assertTrue(second["ok"])
            self.assertFalse(source.exists())
            self.assertEqual(verify_relocation_ledger(root, archive)["record_count"], 1)
            resolved = resolve_relocated_proof(
                root,
                archive,
                source_uri,
                expected_sha256=sha256,
                expected_size_bytes=size_bytes,
            )
            self.assertIsNotNone(resolved)

    def test_restore_preserves_external_object_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            source, source_uri, sha256, size_bytes = self._proof(root, "op_restore", b"restore evidence")
            self.assertTrue(apply_legacy_catalog_archive(root, archive)["ok"])
            external = resolve_relocated_proof(
                root,
                archive,
                source_uri,
                expected_sha256=sha256,
                expected_size_bytes=size_bytes,
            )
            self.assertIsNotNone(external)
            assert external is not None

            restored = restore_relocated_proof(
                root,
                archive,
                source_uri,
                expected_sha256=sha256,
                expected_size_bytes=size_bytes,
            )
            repeated = restore_relocated_proof(
                root,
                archive,
                source_uri,
                expected_sha256=sha256,
                expected_size_bytes=size_bytes,
            )

            self.assertEqual(restored["status"], "restored")
            self.assertEqual(repeated["status"], "verified_existing_source")
            self.assertEqual(source.read_bytes(), b"restore evidence")
            self.assertEqual(external.read_bytes(), b"restore evidence")
            self.assertEqual(verify_relocation_ledger(root, archive)["record_count"], 2)

    def test_tampered_ledger_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            _, source_uri, sha256, size_bytes = self._proof(root, "op_tamper_ledger", b"ledger evidence")
            self.assertTrue(apply_legacy_catalog_archive(root, archive)["ok"])
            ledger = archive / "relocations.jsonl"
            record = json.loads(ledger.read_text(encoding="utf-8"))
            record["size_bytes"] += 1
            ledger.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

            with self.assertRaisesRegex(RelocationLedgerError, "record hash mismatch"):
                resolve_relocated_proof(
                    root,
                    archive,
                    source_uri,
                    expected_sha256=sha256,
                    expected_size_bytes=size_bytes,
                )
            with self.assertRaises(RelocationLedgerError):
                verify_relocation_ledger(root, archive)

    def test_tampered_external_object_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            _, source_uri, sha256, size_bytes = self._proof(root, "op_tamper_object", b"object evidence")
            self.assertTrue(apply_legacy_catalog_archive(root, archive)["ok"])
            external = archive / "objects" / "sha256" / sha256[:2] / f"{sha256}.sqlite3"
            external.write_bytes(b"tampered")

            with self.assertRaises(RelocatedArtifactIntegrityError):
                resolve_relocated_proof(
                    root,
                    archive,
                    source_uri,
                    expected_sha256=sha256,
                    expected_size_bytes=size_bytes,
                )

    def test_archive_must_be_external_and_non_overlapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            self._proof(root, "op_overlap", b"overlap")

            with self.assertRaisesRegex(ProofArchiveError, "must not overlap"):
                plan_legacy_catalog_archive(root, root / "archive")
            with self.assertRaisesRegex(ProofArchiveError, "must not overlap"):
                plan_legacy_catalog_archive(root, root.parent)

    def test_wrong_expected_identity_never_resolves(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            _, source_uri, sha256, size_bytes = self._proof(root, "op_expectation", b"expected")
            self.assertTrue(apply_legacy_catalog_archive(root, archive)["ok"])

            self.assertIsNone(
                resolve_relocated_proof(
                    root,
                    archive,
                    source_uri,
                    expected_sha256="f" * 64,
                    expected_size_bytes=size_bytes,
                )
            )
            self.assertIsNone(
                resolve_relocated_proof(
                    root,
                    archive,
                    source_uri,
                    expected_sha256=sha256,
                    expected_size_bytes=size_bytes + 1,
                )
            )

    def test_existing_unbound_archive_is_rejected_without_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            archive.mkdir()
            marker = archive / "foreign.txt"
            marker.write_text("do not adopt", encoding="utf-8")
            self._proof(root, "op_foreign", b"foreign")

            with self.assertRaisesRegex(RelocationLedgerError, "no binding manifest"):
                plan_legacy_catalog_archive(root, archive)
            self.assertEqual(marker.read_text(encoding="utf-8"), "do not adopt")

    def test_link_like_paths_are_never_traversed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            proof_root = root / "exports" / "proof_artifacts"
            proof_root.mkdir(parents=True, exist_ok=True)
            linked_operation = proof_root / "op_link"
            operation_target = base / "operation-target"
            operation_target.mkdir()
            (operation_target / "catalog.snapshot.sqlite3").write_bytes(b"must not read")
            archive_link = base / "archive-link"
            archive_target = base / "archive-target"
            _make_directory_link(self, linked_operation, operation_target)
            _make_directory_link(self, archive_link, archive_target)
            try:
                plan = plan_legacy_catalog_archive(root, base / "safe-archive")
                reasons = {item["source_uri"]: item["reason"] for item in plan["skipped"]}
                self.assertIn(
                    reasons["exports/proof_artifacts/op_link/catalog.snapshot.sqlite3"],
                    {"operation_directory_symlink", "operation_directory_junction", "operation_directory_reparse_point"},
                )
                with self.assertRaisesRegex(ProofArchiveError, "refusing .* traversal"):
                    plan_legacy_catalog_archive(root, archive_link)
            finally:
                _remove_directory_link(linked_operation)
                _remove_directory_link(archive_link)

    def test_exact_proof_metadata_can_bind_one_legacy_unledgered_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            started = start_operation(root, operation_type="legacy_proof", title="Legacy proof metadata")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})
            proof = create_proof_pack(
                root,
                started["operation_id"],
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
                catalog_proof_mode="snapshot",
            )
            catalog_item = next(
                item
                for item in proof["paths"]
                if str(item.get("uri") or item.get("path")).endswith("catalog.snapshot.sqlite3")
            )
            source_uri = str(catalog_item["uri"])
            conn = connect(root)
            try:
                conn.execute("DELETE FROM artifacts WHERE operation_id = ?", (started["operation_id"],))
                conn.commit()
            finally:
                conn.close()

            plan = plan_legacy_catalog_archive(root, archive)

            self.assertEqual(plan["candidate_count"], 1)
            self.assertEqual(plan["items"][0]["source_uri"], source_uri)
            self.assertEqual(plan["items"][0]["reference_kinds"], ["proof_pack"])

            conn = connect(root)
            try:
                record_artifact(
                    conn,
                    kind="proof_input",
                    uri=source_uri,
                    sha256="0" * 64,
                    size_bytes=int(catalog_item["size_bytes"]),
                    operation_id=started["operation_id"],
                    immutable=True,
                )
                conn.commit()
            finally:
                conn.close()
            conflicted = plan_legacy_catalog_archive(root, archive)
            reasons = {item["source_uri"]: item["reason"] for item in conflicted["skipped"]}
            self.assertEqual(conflicted["candidate_count"], 0)
            self.assertEqual(reasons[source_uri], "conflicting_artifact_ledger_references")

    def test_configured_locator_resolves_and_refuses_conflicts_or_manifest_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            _, source_uri, sha256, size_bytes = self._proof(root, "op_locator", b"located evidence")
            self.assertTrue(apply_legacy_catalog_archive(root, archive)["ok"])

            self.assertEqual(configured_archive_root(root), archive.resolve(strict=True))
            self.assertIsNotNone(
                resolve_configured_relocated_proof(
                    root,
                    source_uri,
                    expected_sha256=sha256,
                    expected_size_bytes=size_bytes,
                )
            )
            with self.assertRaisesRegex(RelocationLedgerError, "conflicts with the configured"):
                plan_legacy_catalog_archive(root, base / "different-archive")

            manifest_path = archive / "archive.manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["created_at"] = "2099-01-01T00:00:00+00:00"
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(RelocationLedgerError, "manifest hash mismatch"):
                configured_archive_root(root)

    def test_writer_claim_failure_precedes_archive_initialization_and_lock(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            self._proof(root, "op_writer_guard", b"writer guard")
            with (
                patch.object(proof_archive_module, "ensure_writer_claim", side_effect=RuntimeError("wrong runtime")),
                patch.object(proof_archive_module, "operation_lock") as lock,
            ):
                with self.assertRaisesRegex(RuntimeError, "wrong runtime"):
                    apply_legacy_catalog_archive(root, archive)
                lock.assert_not_called()
            self.assertFalse(archive.exists())


if __name__ == "__main__":
    unittest.main()
