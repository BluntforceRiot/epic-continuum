from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from unittest.mock import patch

import continuum.core.operations as operations_module
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
            ) -> dict[str, object]:
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
                return real_remove(
                    path,
                    sha256=sha256,
                    size_bytes=size_bytes,
                    expected_identity=expected_identity,
                )

            with patch.object(proof_archive_module, "_remove_verified_source", side_effect=inspect_then_remove):
                result = apply_legacy_catalog_archive(root, archive)

            self.assertEqual(result["ok"], os.name == "nt")
            self.assertEqual(source.exists(), os.name != "nt")
            self.assertEqual(observed["ledger_count"], 1)
            self.assertEqual(observed["configured"], archive.resolve(strict=True))
            resolved = Path(str(observed["resolved"]))
            self.assertTrue(resolved.exists())
            self.assertEqual(_identity(resolved.read_bytes()), (sha256, size_bytes))

    def test_proof_creation_waits_for_archive_source_mutation_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            self._proof(root, "op_archive_lock", b"archive lock evidence")
            started = start_operation(
                root,
                operation_type="concurrent_proof",
                title="Concurrent proof creation",
            )
            finish_operation(
                root,
                started["operation_id"],
                status="succeeded",
                result={"ok": True},
            )
            copy_entered = Event()
            release_copy = Event()
            create_entered = Event()
            real_copy = proof_archive_module._copy_verified_file
            real_create = operations_module._create_proof_pack_unlocked

            def blocking_copy(*args: object, **kwargs: object) -> str:
                copy_entered.set()
                if not release_copy.wait(5):
                    raise TimeoutError("archive lock test did not release copy")
                return real_copy(*args, **kwargs)

            def observed_create(*args: object, **kwargs: object) -> dict[str, object]:
                create_entered.set()
                return real_create(*args, **kwargs)

            with (
                patch.object(
                    proof_archive_module,
                    "_copy_verified_file",
                    side_effect=blocking_copy,
                ),
                patch.object(
                    operations_module,
                    "_create_proof_pack_unlocked",
                    side_effect=observed_create,
                ),
                ThreadPoolExecutor(max_workers=2) as pool,
            ):
                archive_future = pool.submit(apply_legacy_catalog_archive, root, archive)
                self.assertTrue(copy_entered.wait(5))
                proof_future = pool.submit(
                    create_proof_pack,
                    root,
                    started["operation_id"],
                )
                self.assertFalse(create_entered.wait(0.2))
                release_copy.set()
                archived = archive_future.result(timeout=5)
                self.assertEqual(archived["ok"], os.name == "nt")
                proof = proof_future.result(timeout=5)

            self.assertTrue(create_entered.is_set())
            self.assertEqual(proof["operation_id"], started["operation_id"])

    @unittest.skipUnless(os.name == "nt", "identity-bound proof source deletion requires Windows")
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

    def test_reused_record_with_tampered_destination_retains_source_and_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            source, _, sha256, _ = self._proof(
                root,
                "op_reused_tamper",
                b"reused destination evidence",
            )
            with patch.object(
                proof_archive_module,
                "_remove_verified_source",
                side_effect=OSError("retain source for retry"),
            ):
                first = apply_legacy_catalog_archive(root, archive)
            self.assertFalse(first["ok"], first)
            self.assertTrue(source.exists())
            destination = archive / "objects" / "sha256" / sha256[:2] / f"{sha256}.sqlite3"
            destination.write_bytes(b"tampered destination")

            second = apply_legacy_catalog_archive(root, archive)

            item = second["results"][0]
            self.assertFalse(second["ok"], second)
            self.assertFalse(item["ok"])
            self.assertFalse(item["source_removed"])
            self.assertEqual(item["copy_status"], "reused_recorded_destination")
            self.assertIn("archived destination verification failed", item["error"])
            self.assertEqual(source.read_bytes(), b"reused destination evidence")
            self.assertEqual(verify_relocation_ledger(root, archive)["record_count"], 1)

    def test_already_absent_source_with_missing_destination_fails_item_and_aggregate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            source, _, sha256, _ = self._proof(
                root,
                "op_absent_missing_destination",
                b"destination must survive disposition",
            )
            destination = archive / "objects" / "sha256" / sha256[:2] / f"{sha256}.sqlite3"
            real_append = proof_archive_module._append_relocation_record

            def append_then_remove_bytes(*args: object, **kwargs: object) -> dict[str, object]:
                state = real_append(*args, **kwargs)
                source.unlink()
                destination.unlink()
                return state

            with patch.object(
                proof_archive_module,
                "_append_relocation_record",
                side_effect=append_then_remove_bytes,
            ):
                result = apply_legacy_catalog_archive(root, archive)

            item = result["results"][0]
            self.assertFalse(result["ok"], result)
            self.assertFalse(item["ok"])
            self.assertTrue(item["source_removed"])
            self.assertEqual(item["source_disposition_status"], "already_absent")
            self.assertIn("archived destination verification failed", item["error"])
            self.assertFalse(destination.exists())
            self.assertEqual(verify_relocation_ledger(root, archive)["record_count"], 1)

    def test_retained_quarantine_retry_is_reported_instead_of_empty_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            source, source_uri, sha256, size_bytes = self._proof(
                root,
                "op_retained_retry",
                b"retained retry evidence",
            )
            with patch.object(
                proof_archive_module,
                "_remove_verified_source",
                side_effect=OSError("first removal did not start"),
            ):
                first = apply_legacy_catalog_archive(root, archive)

            self.assertFalse(first["ok"])
            self.assertTrue(source.exists())
            self.assertEqual(verify_relocation_ledger(root, archive)["record_count"], 1)
            quarantine_root = source.parent / (
                f".{source.name}.archive-quarantine-{'a' * 32}"
            )
            quarantine_root.mkdir()
            quarantine = quarantine_root / source.name
            os.rename(source, quarantine)

            plan = plan_legacy_catalog_archive(root, archive)

            self.assertEqual(plan["candidate_count"], 0)
            self.assertEqual(plan["retained_quarantine_count"], 1)
            self.assertEqual(plan["retained_quarantine_bytes"], size_bytes)
            retained = plan["retained_quarantines"][0]
            self.assertEqual(retained["source_uri"], source_uri)
            self.assertEqual(retained["archive_identity_status"], "verified_relocation_object")
            self.assertEqual(retained["entries"][0]["sha256"], sha256)
            self.assertEqual(
                retained["entries"][0]["identity_status"],
                "matches_relocation_content",
            )

            second = apply_legacy_catalog_archive(root, archive)

            self.assertFalse(second["ok"], second)
            self.assertEqual(second["plan"]["candidate_count"], 0)
            self.assertEqual(second["unresolved_quarantine_count"], 1)
            self.assertEqual(len(second["results"]), 1)
            unresolved = second["results"][0]
            self.assertEqual(unresolved["result_kind"], "retained_quarantine")
            self.assertFalse(unresolved["source_removed"])
            self.assertEqual(
                unresolved["source_disposition_status"],
                "retained_quarantine_requires_exact_object_resolution",
            )
            self.assertIn("will not delete by pathname or matching content alone", unresolved["error"])
            self.assertEqual(quarantine.read_bytes(), b"retained retry evidence")
            self.assertEqual(verify_relocation_ledger(root, archive)["record_count"], 1)

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "mkfifo"), "POSIX FIFO contract")
    def test_copy_rejects_fifo_replacement_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source.sqlite3"
            destination = base / "objects" / "destination.sqlite3"
            payload = b"verified before FIFO replacement"
            source.write_bytes(payload)
            sha256, size_bytes = _identity(payload)
            proof_archive_module._verify_file(
                source,
                sha256=sha256,
                size_bytes=size_bytes,
            )
            parked = base / "source.sqlite3.parked"
            os.rename(source, parked)
            os.mkfifo(source)
            real_open = proof_archive_module.os.open
            observed_source_flags: list[int] = []

            def inspect_open(path: object, flags: int, *args: object) -> int:
                if Path(path) == source:
                    observed_source_flags.append(flags)
                return real_open(path, flags, *args)

            started = time.monotonic()
            with (
                patch.object(proof_archive_module.os, "open", side_effect=inspect_open),
                self.assertRaisesRegex(
                    RelocatedArtifactIntegrityError,
                    "copy source is not a regular file",
                ),
            ):
                proof_archive_module._copy_verified_file(
                    source,
                    destination,
                    sha256=sha256,
                    size_bytes=size_bytes,
                )

            self.assertLess(time.monotonic() - started, 2.0)
            self.assertEqual(len(observed_source_flags), 1)
            self.assertTrue(observed_source_flags[0] & os.O_NONBLOCK)
            self.assertFalse(destination.exists())

    def test_copy_integrity_error_remains_primary_when_temp_cleanup_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source.sqlite3"
            destination = base / "objects" / "destination.sqlite3"
            payload = b"copy integrity primary"
            source.write_bytes(payload)
            _, size_bytes = _identity(payload)
            real_unlink = Path.unlink

            def fail_temporary_cleanup(path: Path, *args: object, **kwargs: object) -> None:
                if path.parent == destination.parent and path.name.endswith(".tmp"):
                    raise OSError("temporary cleanup failed")
                real_unlink(path, *args, **kwargs)

            with (
                patch.object(Path, "unlink", new=fail_temporary_cleanup),
                self.assertRaisesRegex(
                    RelocatedArtifactIntegrityError,
                    "source changed while it was copied",
                ) as raised,
            ):
                proof_archive_module._copy_verified_file(
                    source,
                    destination,
                    sha256="0" * 64,
                    size_bytes=size_bytes,
                )

            notes = getattr(raised.exception, "__notes__", [])
            self.assertEqual(len(notes), 1)
            self.assertIn("temporary cleanup failed", notes[0])
            self.assertLessEqual(len(notes[0]), 500)
            self.assertFalse(destination.exists())
            temporary_files = list(destination.parent.glob(".*.tmp"))
            self.assertEqual(len(temporary_files), 1)
            temporary_files[0].unlink()

    def test_source_open_error_remains_primary_when_destination_close_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / "source.sqlite3"
            destination = base / "objects" / "destination.sqlite3"
            payload = b"source open primary"
            source.write_bytes(payload)
            sha256, size_bytes = _identity(payload)
            real_open = proof_archive_module.os.open
            real_close = proof_archive_module.os.close
            destination_fds: set[int] = set()

            def open_then_fail_source(
                path: object,
                flags: int,
                mode: int = 0o777,
                *args: object,
                **kwargs: object,
            ) -> int:
                if Path(path) == source:
                    raise OSError("primary source open failed")
                fd = real_open(path, flags, mode, *args, **kwargs)
                if Path(path).parent == destination.parent and Path(path).name.endswith(".tmp"):
                    destination_fds.add(fd)
                return fd

            def close_destination_then_fail(fd: int) -> None:
                if fd in destination_fds:
                    destination_fds.remove(fd)
                    real_close(fd)
                    raise OSError("destination close failed")
                real_close(fd)

            with (
                patch.object(proof_archive_module.os, "open", side_effect=open_then_fail_source),
                patch.object(proof_archive_module.os, "close", side_effect=close_destination_then_fail),
                self.assertRaisesRegex(OSError, "primary source open failed") as raised,
            ):
                proof_archive_module._copy_verified_file(
                    source,
                    destination,
                    sha256=sha256,
                    size_bytes=size_bytes,
                )

            notes = getattr(raised.exception, "__notes__", [])
            self.assertEqual(len(notes), 1)
            self.assertIn("destination close failed", notes[0])
            self.assertLessEqual(len(notes[0]), 500)
            self.assertEqual(destination_fds, set())
            self.assertFalse(destination.exists())
            self.assertEqual(list(destination.parent.glob(".*.tmp")), [])

    def test_same_size_source_mutation_with_restored_mtime_is_retained(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            original = b"original proof bytes"
            replacement = b"replaced proof bytes"
            self.assertEqual(len(original), len(replacement))
            source, _, sha256, size_bytes = self._proof(root, "op_mutated", original)
            planned_mtime_ns = int(os.lstat(source).st_mtime_ns)
            real_remove = proof_archive_module._remove_verified_source

            def mutate_then_remove(
                path: Path,
                *,
                sha256: str,
                size_bytes: int,
                expected_identity: dict[str, object] | None = None,
            ) -> None:
                path.write_bytes(replacement)
                os.utime(path, ns=(planned_mtime_ns, planned_mtime_ns))
                real_remove(
                    path,
                    sha256=sha256,
                    size_bytes=size_bytes,
                    expected_identity=expected_identity,
                )

            with patch.object(
                proof_archive_module,
                "_remove_verified_source",
                side_effect=mutate_then_remove,
            ):
                result = apply_legacy_catalog_archive(root, archive)

            self.assertFalse(result["ok"], result)
            self.assertFalse(result["results"][0]["source_removed"])
            self.assertEqual(source.read_bytes(), replacement)
            external = archive / "objects" / "sha256" / sha256[:2] / f"{sha256}.sqlite3"
            self.assertEqual(external.read_bytes(), original)
            self.assertEqual(external.stat().st_size, size_bytes)

    def test_unavailable_identity_bound_delete_retains_source_without_path_unlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "catalog.snapshot.sqlite3"
            payload = b"portable source retained"
            source.write_bytes(payload)
            sha256, size_bytes = _identity(payload)

            with (
                patch.object(proof_archive_module.os, "name", "posix"),
                patch.object(proof_archive_module.os, "unlink") as unlink,
                self.assertRaisesRegex(
                    RelocatedArtifactIntegrityError,
                    "identity-bound proof source deletion is unavailable",
                ),
            ):
                proof_archive_module._remove_verified_source(
                    source,
                    sha256=sha256,
                    size_bytes=size_bytes,
                )

            unlink.assert_not_called()
            self.assertEqual(source.read_bytes(), payload)
            self.assertEqual(
                list(source.parent.glob(f".{source.name}.archive-quarantine-*")),
                [],
            )

    def test_strict_absence_never_converts_lstat_failure_into_success(self) -> None:
        candidate = Path("proof-source.sqlite3")
        with (
            patch.object(
                proof_archive_module.os,
                "lstat",
                side_effect=PermissionError("lstat denied"),
            ),
            self.assertRaisesRegex(PermissionError, "lstat denied"),
        ):
            proof_archive_module._strict_path_absent(candidate)

    def test_hash_failure_remains_primary_when_descriptor_close_also_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "proof.sqlite3"
            source.write_bytes(b"proof")
            opened: list[int] = []
            real_open = proof_archive_module.os.open

            def track_open(*args: object, **kwargs: object) -> int:
                fd = real_open(*args, **kwargs)
                opened.append(fd)
                return fd

            with (
                patch.object(proof_archive_module.os, "open", side_effect=track_open),
                patch.object(
                    proof_archive_module,
                    "_hash_open_regular_fd",
                    side_effect=RuntimeError("primary hash failure"),
                ),
                patch.object(
                    proof_archive_module.os,
                    "close",
                    side_effect=OSError("secondary close failure"),
                ),
                self.assertRaisesRegex(RuntimeError, "primary hash failure") as raised,
            ):
                proof_archive_module._open_hashed_regular_file(source)

            notes = getattr(raised.exception, "__notes__", [])
            self.assertEqual(len(notes), 1)
            self.assertIn("secondary close failure", notes[0])
            self.assertLessEqual(len(notes[0]), 500)
            self.assertEqual(len(opened), 1)
            os.close(opened[0])

    def test_dangling_source_link_is_not_misreported_as_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            source, _, _, _ = self._proof(root, "op_dangling", b"dangling proof")
            real_remove = proof_archive_module._remove_verified_source
            target = base / "removed-link-target"

            def replace_with_dangling_link(path: Path, **kwargs: object) -> None:
                path.unlink()
                _make_directory_link(self, path, target)
                shutil.rmtree(target)
                real_remove(path, **kwargs)

            with patch.object(
                proof_archive_module,
                "_remove_verified_source",
                side_effect=replace_with_dangling_link,
            ):
                result = apply_legacy_catalog_archive(root, archive)

            self.assertFalse(result["ok"], result)
            self.assertFalse(result["results"][0]["source_removed"])
            self.assertTrue(os.path.lexists(source))
            self.assertFalse(source.exists())
            self.assertIsNotNone(proof_archive_module._link_like_reason(source))

    @unittest.skipUnless(os.name == "nt", "identity-bound proof source deletion requires Windows")
    def test_final_quarantine_path_swap_is_retained(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            original = b"final swap proof"
            source, _, _, _ = self._proof(root, "op_final_swap", original)
            real_unlink = proof_archive_module._unlink_verified_quarantine

            def swap_then_unlink(
                quarantine: Path,
                *,
                sha256: str,
                size_bytes: int,
                expected_metadata: os.stat_result,
            ) -> None:
                parked = quarantine.with_name(quarantine.name + ".parked")
                os.rename(quarantine, parked)
                quarantine.write_bytes(original)
                os.utime(
                    quarantine,
                    ns=(int(expected_metadata.st_mtime_ns), int(expected_metadata.st_mtime_ns)),
                )
                real_unlink(
                    quarantine,
                    sha256=sha256,
                    size_bytes=size_bytes,
                    expected_metadata=expected_metadata,
                )

            with patch.object(
                proof_archive_module,
                "_unlink_verified_quarantine",
                side_effect=swap_then_unlink,
            ):
                result = apply_legacy_catalog_archive(root, archive)

            self.assertFalse(result["ok"], result)
            self.assertFalse(result["results"][0]["source_removed"])
            self.assertIn(
                "source retained in quarantine after final verification failed",
                result["results"][0]["error"],
            )
            self.assertFalse(os.path.lexists(source))
            quarantines = list(
                source.parent.glob(f".{source.name}.archive-quarantine-*")
            )
            self.assertEqual(len(quarantines), 1)
            retained = sorted(item.read_bytes() for item in quarantines[0].iterdir())
            self.assertEqual(retained, [original, original])

            repeated = apply_legacy_catalog_archive(root, archive)

            self.assertFalse(repeated["ok"], repeated)
            self.assertEqual(repeated["plan"]["candidate_count"], 0)
            self.assertEqual(repeated["plan"]["retained_quarantine_count"], 1)
            self.assertEqual(repeated["unresolved_quarantine_count"], 1)
            self.assertEqual(len(repeated["results"]), 1)
            unresolved = repeated["results"][0]
            self.assertEqual(unresolved["result_kind"], "retained_quarantine")
            self.assertFalse(unresolved["source_removed"])
            self.assertEqual(
                [entry["identity_status"] for entry in unresolved["quarantine_evidence"]["entries"]],
                ["matches_relocation_content", "matches_relocation_content"],
            )
            self.assertEqual(
                sorted(item.read_bytes() for item in quarantines[0].iterdir()),
                [original, original],
            )
            self.assertEqual(verify_relocation_ledger(root, archive)["record_count"], 1)

    @unittest.skipUnless(os.name == "nt", "Windows handle-bound deletion contract")
    def test_final_delete_boundary_does_not_unlink_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            original = b"handle-bound original"
            replacement = b"final replacement retained"
            source, _, _, _ = self._proof(root, "op_delete_boundary", original)
            real_set_disposition = proof_archive_module._set_windows_delete_disposition

            def swap_at_delete_boundary(handle: int) -> None:
                quarantine_roots = list(
                    source.parent.glob(f".{source.name}.archive-quarantine-*")
                )
                self.assertEqual(len(quarantine_roots), 1)
                quarantine = quarantine_roots[0] / source.name
                parked = quarantine.with_name(quarantine.name + ".parked")
                os.rename(quarantine, parked)
                quarantine.write_bytes(replacement)
                real_set_disposition(handle)

            with patch.object(
                proof_archive_module,
                "_set_windows_delete_disposition",
                side_effect=swap_at_delete_boundary,
            ):
                result = apply_legacy_catalog_archive(root, archive)

            self.assertFalse(result["ok"], result)
            self.assertTrue(result["results"][0]["source_removed"])
            self.assertEqual(
                result["results"][0]["quarantine_cleanup_status"],
                "cleanup_failed_or_incomplete",
            )
            quarantine_roots = list(
                source.parent.glob(f".{source.name}.archive-quarantine-*")
            )
            self.assertEqual(len(quarantine_roots), 1)
            retained = list(quarantine_roots[0].iterdir())
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0].read_bytes(), replacement)

    @unittest.skipUnless(os.name == "nt", "Windows strict directory durability contract")
    def test_windows_strict_directory_flush_succeeds_for_physical_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proof_archive_module._flush_windows_directory_strict(Path(tmp))

    def test_directory_flush_failure_remains_primary_when_handle_close_fails(self) -> None:
        primary = OSError("primary directory flush failure")
        with (
            patch.object(
                proof_archive_module,
                "_open_windows_directory_flush_handle",
                return_value=(object(), 41),
            ),
            patch.object(
                proof_archive_module,
                "_flush_windows_directory_handle",
                side_effect=primary,
            ),
            patch.object(
                proof_archive_module,
                "_close_windows_directory_flush_handle",
                side_effect=OSError("secondary directory handle close failure"),
            ),
            self.assertRaisesRegex(OSError, "primary directory flush failure") as raised,
        ):
            proof_archive_module._flush_windows_directory_strict(Path("physical-parent"))

        notes = getattr(raised.exception, "__notes__", [])
        self.assertEqual(len(notes), 1)
        self.assertIn("secondary directory handle close failure", notes[0])
        self.assertLessEqual(len(notes[0]), 500)

    @unittest.skipUnless(os.name == "nt", "Windows strict directory durability contract")
    def test_post_disposition_directory_flush_failure_is_surfaced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            source, _, _, _ = self._proof(
                root,
                "op_final_flush_failure",
                b"disposed before strict parent flush failure",
            )
            real_flush = proof_archive_module._flush_windows_directory_strict
            flush_count = 0

            def fail_final_flush(directory: Path) -> None:
                nonlocal flush_count
                flush_count += 1
                if flush_count == 2:
                    raise OSError("final strict directory flush failed")
                real_flush(directory)

            with patch.object(
                proof_archive_module,
                "_flush_windows_directory_strict",
                side_effect=fail_final_flush,
            ):
                result = apply_legacy_catalog_archive(root, archive)

            item = result["results"][0]
            self.assertEqual(flush_count, 2)
            self.assertFalse(result["ok"], result)
            self.assertFalse(item["ok"])
            self.assertTrue(item["source_removed"])
            self.assertEqual(item["source_disposition_status"], "removed_exact_handle")
            self.assertEqual(
                item["source_durability_status"],
                "durability_failed_or_incomplete",
            )
            self.assertIn("final strict directory flush failed", item["error"])
            self.assertFalse(os.path.lexists(source))

    @unittest.skipUnless(os.name == "nt", "Windows share-mode proof contract")
    def test_writer_is_denied_between_final_hash_and_handle_disposition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            original = b"immutable disposition boundary"
            source, _, _, _ = self._proof(root, "op_write_denied", original)
            real_set_disposition = proof_archive_module._set_windows_delete_disposition
            attempted = Event()

            def attempt_write(path: Path) -> BaseException | None:
                attempted.set()
                try:
                    with path.open("r+b") as handle:
                        handle.seek(0)
                        handle.write(b"MUTATED")
                        handle.flush()
                except BaseException as exc:
                    return exc
                return None

            def inspect_share_boundary(handle: int) -> None:
                quarantine_roots = list(
                    source.parent.glob(f".{source.name}.archive-quarantine-*")
                )
                self.assertEqual(len(quarantine_roots), 1)
                quarantine = quarantine_roots[0] / source.name
                with ThreadPoolExecutor(max_workers=1) as pool:
                    write_error = pool.submit(attempt_write, quarantine).result(timeout=5)
                self.assertTrue(attempted.is_set())
                self.assertIsInstance(write_error, OSError)
                real_set_disposition(handle)

            with patch.object(
                proof_archive_module,
                "_set_windows_delete_disposition",
                side_effect=inspect_share_boundary,
            ):
                result = apply_legacy_catalog_archive(root, archive)

            self.assertTrue(result["ok"], result)
            self.assertTrue(result["results"][0]["source_removed"])
            archived = next((archive / "objects" / "sha256").glob("*/*.sqlite3"))
            self.assertEqual(archived.read_bytes(), original)

    @unittest.skipUnless(os.name == "nt", "Windows handle-bound deletion contract")
    def test_post_disposition_quarantine_cleanup_failure_preserves_removal_truth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            source, _, _, _ = self._proof(
                root,
                "op_cleanup_failure",
                b"disposed before cleanup failure",
            )

            with patch.object(
                proof_archive_module.os,
                "rmdir",
                side_effect=OSError("quarantine rmdir failed"),
            ):
                result = apply_legacy_catalog_archive(root, archive)

            item = result["results"][0]
            self.assertFalse(result["ok"], result)
            self.assertTrue(item["source_removed"])
            self.assertEqual(item["source_disposition_status"], "removed_exact_handle")
            self.assertEqual(
                item["quarantine_cleanup_status"],
                "cleanup_failed_or_incomplete",
            )
            self.assertEqual(item["source_durability_status"], "durable")
            self.assertIn("quarantine rmdir failed", item["error"])
            self.assertFalse(os.path.lexists(source))

    @unittest.skipUnless(os.name == "nt", "identity-bound proof source deletion requires Windows")
    def test_recreated_source_after_quarantine_delete_is_reported_retained(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = self._root(base)
            archive = base / "external-archive"
            source, _, _, _ = self._proof(root, "op_recreated", b"archived source")
            replacement = b"new source bytes"
            real_unlink = proof_archive_module._unlink_verified_quarantine

            def recreate_source(*args: object, **kwargs: object) -> dict[str, object]:
                disposition = real_unlink(*args, **kwargs)
                source.write_bytes(replacement)
                return disposition

            with patch.object(
                proof_archive_module,
                "_unlink_verified_quarantine",
                side_effect=recreate_source,
            ):
                result = apply_legacy_catalog_archive(root, archive)

            self.assertFalse(result["ok"], result)
            self.assertTrue(result["results"][0]["source_removed"])
            self.assertEqual(
                result["results"][0]["quarantine_cleanup_status"],
                "cleanup_failed_or_incomplete",
            )
            self.assertEqual(source.read_bytes(), replacement)

    @unittest.skipUnless(os.name == "nt", "identity-bound proof source deletion requires Windows")
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

    @unittest.skipUnless(os.name == "nt", "identity-bound proof source deletion requires Windows")
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

    @unittest.skipUnless(os.name == "nt", "identity-bound proof source deletion requires Windows")
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

    @unittest.skipUnless(os.name == "nt", "identity-bound proof source deletion requires Windows")
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

    @unittest.skipUnless(os.name == "nt", "identity-bound proof source deletion requires Windows")
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

    @unittest.skipUnless(os.name == "nt", "identity-bound proof source deletion requires Windows")
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
