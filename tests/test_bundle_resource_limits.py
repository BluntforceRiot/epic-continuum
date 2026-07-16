from __future__ import annotations

import io
import json
import os
import random
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from collections.abc import Iterator
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import continuum.core.bundle as bundle_module
import continuum.mcp_server as mcp_server
from continuum.cli import main as cli_main
from continuum.core.bundle import (
    BUNDLE_ABSOLUTE_MAX_EXPANDED_BYTES,
    BUNDLE_MANIFEST_NAME,
    BUNDLE_ROOT_NAME,
    BUNDLE_SEMANTIC_TEMP_RESERVE_BYTES,
    _BundleLimitError,
    _BundleVerificationBudget,
    _PORTABLE_METADATA_MAX_FILE_BYTES,
    _BUNDLE_SEMANTIC_RESULT_MAX_BYTES,
    _SQLITE_METADATA_MAX_VALUE_BYTES,
    audit_portable_metadata,
    _deflate_compressed_size_bound,
    _read_bundle_zip_preflight,
    _run_extracted_root_audit,
    _write_zip_member,
    pack_root,
    verify_root_bundle,
)
from continuum.core.config import load_config, write_config
from continuum.core.permissions import secure_file
from continuum.core.store import init_db


def _error_codes(result: dict[str, object]) -> set[str]:
    raw_errors = result.get("errors")
    if not isinstance(raw_errors, list):
        return set()
    return {
        str(item.get("error"))
        for item in raw_errors
        if isinstance(item, dict)
    }


class BundleResourceLimitsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._temp.cleanup)
        cls.base = Path(cls._temp.name)
        cls.root = cls.base / "continuum"
        cls.bundle = cls.base / "continuum.zip"
        init_db(cls.root)
        packed = pack_root(cls.root, out_path=cls.bundle, run_restore_drill=False)
        if not packed.get("ok"):
            raise AssertionError(packed)

    def test_ordinary_semantic_verification_still_passes(self) -> None:
        result = verify_root_bundle(self.bundle)
        self.assertTrue(result["ok"], result)

    def test_expanded_and_member_limits_reject_before_inflation(self) -> None:
        with zipfile.ZipFile(self.bundle) as archive:
            infos = archive.infolist()
        expanded = sum(info.file_size for info in infos)
        largest = max(info.file_size for info in infos)

        expanded_result = verify_root_bundle(
            self.bundle,
            verify_embedded_root=False,
            max_expanded_bytes=expanded - 1,
        )
        member_result = verify_root_bundle(
            self.bundle,
            verify_embedded_root=False,
            max_member_bytes=largest - 1,
        )

        self.assertIn("bundle_expanded_size_too_large", _error_codes(expanded_result))
        self.assertIn("bundle_member_too_large", _error_codes(member_result))

    def test_central_directory_limit_rejects_before_zipfile_materialization(self) -> None:
        central_size = _read_bundle_zip_preflight(self.bundle).central_directory_size
        with patch.object(
            bundle_module.zipfile,
            "ZipFile",
            side_effect=AssertionError("ZipFile must not be constructed"),
        ):
            result = verify_root_bundle(
                self.bundle,
                verify_embedded_root=False,
                max_central_directory_bytes=central_size - 1,
            )
        self.assertIn("bundle_central_directory_too_large", _error_codes(result))

    def test_declared_small_observed_large_directory_rejects_before_zipfile(self) -> None:
        archive_path = self.base / "declared-small.zip"
        sources: list[Path] = []
        for index in range(5):
            source = self.base / f"declared-small-{index}.txt"
            source.write_text(str(index), encoding="utf-8")
            sources.append(source)
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for source in sources:
                _write_zip_member(archive, source, arcname=source.name)
        data = bytearray(archive_path.read_bytes())
        eocd = data.rfind(b"PK\x05\x06")
        self.assertGreaterEqual(eocd, 0)
        struct.pack_into("<H", data, eocd + 8, 1)
        struct.pack_into("<H", data, eocd + 10, 1)
        archive_path.write_bytes(data)

        with patch.object(
            bundle_module.zipfile,
            "ZipFile",
            side_effect=AssertionError("ZipFile must not see forged counts"),
        ):
            result = verify_root_bundle(
                archive_path,
                verify_embedded_root=False,
                max_entries=3,
            )
        self.assertIn("bundle_entry_count_too_large", _error_codes(result))

    def test_nonadjacent_fake_zip64_record_rejects_before_zipfile(self) -> None:
        archive_path = self.base / "nonadjacent-zip64.zip"
        sources: list[Path] = []
        with patch.object(zipfile, "ZIP_FILECOUNT_LIMIT", 3):
            for index in range(5):
                source = self.base / f"zip64-{index}.txt"
                source.write_text(str(index), encoding="utf-8")
                sources.append(source)
            with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for source in sources:
                    _write_zip_member(archive, source, arcname=source.name)

        data = bytearray(archive_path.read_bytes())
        eocd = data.rfind(b"PK\x05\x06")
        locator = eocd - 20
        self.assertEqual(data[locator : locator + 4], b"PK\x06\x07")
        zip64_offset = struct.unpack_from("<Q", data, locator + 8)[0]
        record = bytes(data[zip64_offset:locator])
        self.assertEqual(len(record), 56)
        archive_path.write_bytes(data[:zip64_offset] + record + b"X" + data[locator:])

        with patch.object(
            bundle_module.zipfile,
            "is_zipfile",
            return_value=True,
        ), patch.object(
            bundle_module.zipfile,
            "ZipFile",
            side_effect=AssertionError("ZipFile must not see differential Zip64 metadata"),
        ):
            result = verify_root_bundle(archive_path, verify_embedded_root=False)
        self.assertIn("zip_preflight_failed", _error_codes(result))

    def test_required_zip64_size_without_locator_rejects_before_zipfile(self) -> None:
        archive_path = self.base / "missing-required-zip64.zip"
        shutil.copy2(self.bundle, archive_path)
        data = bytearray(archive_path.read_bytes())
        eocd = data.rfind(b"PK\x05\x06")
        self.assertGreaterEqual(eocd, 0)
        struct.pack_into("<I", data, eocd + 12, zipfile.ZIP64_LIMIT + 1)
        archive_path.write_bytes(data)

        with patch.object(
            bundle_module.zipfile,
            "ZipFile",
            side_effect=AssertionError("ZipFile must not see missing required ZIP64"),
        ):
            result = verify_root_bundle(archive_path, verify_embedded_root=False)
        self.assertIn("zip64_required", _error_codes(result))

    def test_compression_ratio_bomb_rejects_without_manifest_walk(self) -> None:
        source = self.base / "zeros.bin"
        source.write_bytes(b"\0" * (2 * 1024 * 1024))
        archive_path = self.base / "ratio-bomb.zip"
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            _write_zip_member(archive, source, arcname=source.name)

        result = verify_root_bundle(
            archive_path,
            verify_embedded_root=False,
            max_compression_ratio=10,
        )
        self.assertIn("bundle_compression_ratio_too_large", _error_codes(result))

    def test_phase_boundary_path_replacement_never_verifies_new_path(self) -> None:
        victim = self.base / "identity-victim.zip"
        replacement = self.base / "identity-replacement.zip"
        shutil.copy2(self.bundle, victim)
        shutil.copy2(self.bundle, replacement)
        original_preflight = bundle_module._read_bundle_zip_preflight
        swapped = False

        def swap_after_preflight(*args: object, **kwargs: object) -> object:
            nonlocal swapped
            value = original_preflight(*args, **kwargs)
            try:
                os.replace(replacement, victim)
                swapped = True
            except PermissionError:
                # A host that denies replacement while the pinned handle is open
                # already enforces the same boundary at the filesystem layer.
                pass
            return value

        with patch.object(
            bundle_module,
            "_read_bundle_zip_preflight",
            side_effect=swap_after_preflight,
        ):
            result = verify_root_bundle(victim, verify_embedded_root=False)

        if swapped:
            self.assertIn("bundle_file_identity_changed", _error_codes(result))
        else:
            self.assertTrue(result["ok"], result)

    @unittest.skipUnless(os.name == "nt", "Windows share-mode proof")
    def test_windows_handle_denies_same_size_in_place_rewrite(self) -> None:
        victim = self.base / "write-denied-victim.zip"
        shutil.copy2(self.bundle, victim)
        original_preflight = bundle_module._read_bundle_zip_preflight
        write_denied = False

        def attempt_rewrite(*args: object, **kwargs: object) -> object:
            nonlocal write_denied
            value = original_preflight(*args, **kwargs)
            original_stat = victim.stat()
            try:
                with victim.open("r+b") as handle:
                    first = handle.read(1)
                    handle.seek(0)
                    handle.write(bytes([first[0] ^ 0x01]))
                    handle.flush()
                    os.fsync(handle.fileno())
                os.utime(
                    victim,
                    ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
                )
            except OSError:
                write_denied = True
            return value

        with patch.object(
            bundle_module,
            "_read_bundle_zip_preflight",
            side_effect=attempt_rewrite,
        ):
            result = verify_root_bundle(victim, verify_embedded_root=False)
        self.assertTrue(write_denied, result)
        self.assertTrue(result["ok"], result)

    def test_semantic_temp_reserve_is_rechecked_during_extraction(self) -> None:
        calls = 0

        def diminishing_space(_path: object) -> SimpleNamespace:
            nonlocal calls
            calls += 1
            free = 10**15 if calls < 3 else 0
            return SimpleNamespace(free=free)

        with patch.object(bundle_module.shutil, "disk_usage", side_effect=diminishing_space):
            result = verify_root_bundle(self.bundle)
        self.assertIn("semantic_temp_reserve_eroded", _error_codes(result))

        with patch.object(
            bundle_module.shutil,
            "disk_usage",
            side_effect=AssertionError("envelope-only verification must not probe temp space"),
        ):
            envelope = verify_root_bundle(self.bundle, verify_embedded_root=False)
        self.assertTrue(envelope["ok"], envelope)

    def test_semantic_temp_preflight_requires_payload_plus_reserve(self) -> None:
        with patch.object(
            bundle_module.shutil,
            "disk_usage",
            return_value=SimpleNamespace(free=0),
        ):
            result = verify_root_bundle(self.bundle)
        self.assertIn("semantic_temp_space_insufficient", _error_codes(result))

    def test_monotonic_deadline_rejects_before_archive_work(self) -> None:
        with patch.object(bundle_module.time, "monotonic", side_effect=[0.0, 2.0]):
            result = verify_root_bundle(
                self.bundle,
                verify_embedded_root=False,
                timeout_seconds=1,
            )
        self.assertIn("bundle_verification_timeout", _error_codes(result))

    def test_manifest_entry_cap_precedes_full_manifest_traversals(self) -> None:
        archive_path = self.base / "oversized-manifest.zip"
        manifest_source = self.base / BUNDLE_MANIFEST_NAME
        manifest_source.write_text(
            json.dumps(
                {"files": [{} for _ in range(10)]},
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            _write_zip_member(
                archive,
                manifest_source,
                arcname=f"{BUNDLE_ROOT_NAME}/{BUNDLE_MANIFEST_NAME}",
                mode_override=0o644,
            )

        sentinels = (
            "_manifest_structure_errors",
            "_manifest_semantic_errors",
            "scan_value_for_secrets",
            "_portable_metadata_findings",
            "_manifest_hash",
        )
        patches = [
            patch.object(
                bundle_module,
                name,
                side_effect=AssertionError(f"{name} must not traverse the oversized manifest"),
            )
            for name in sentinels
        ]
        for active_patch in patches:
            active_patch.start()
            self.addCleanup(active_patch.stop)
        result = verify_root_bundle(
            archive_path,
            verify_embedded_root=False,
            max_entries=2,
        )
        self.assertIn("manifest_file_count_too_large", _error_codes(result))

    def test_repeated_stalled_semantic_workers_are_killed_and_reaped(self) -> None:
        embedded_root = self.base / "stall-root"
        embedded_root.mkdir(exist_ok=True)
        real_popen = subprocess.Popen
        children: list[subprocess.Popen[bytes]] = []

        def tracked_popen(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
            child = real_popen(*args, **kwargs)
            children.append(child)
            return child

        started = time.monotonic()
        with patch.object(bundle_module.subprocess, "Popen", side_effect=tracked_popen):
            for _index in range(2):
                budget = _BundleVerificationBudget(
                    deadline=time.monotonic() + 0.25,
                    max_work_bytes=1,
                )
                with self.assertRaises(_BundleLimitError) as raised:
                    _run_extracted_root_audit(
                        embedded_root,
                        {},
                        budget=budget,
                        temp_parent=self.base,
                        worker_command=[
                            sys.executable,
                            "-c",
                            "import time; time.sleep(60)",
                        ],
                    )
                self.assertEqual(raised.exception.code, "bundle_verification_timeout")
        self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(len(children), 2)
        self.assertTrue(all(child.poll() is not None for child in children))

    def test_semantic_worker_launch_failure_is_structured(self) -> None:
        embedded_root = self.base / "worker-start-failure-root"
        embedded_root.mkdir(exist_ok=True)
        budget = _BundleVerificationBudget(
            deadline=time.monotonic() + 5,
            max_work_bytes=1,
        )
        with patch.object(
            bundle_module.subprocess,
            "Popen",
            side_effect=OSError("simulated launch failure"),
        ):
            errors = _run_extracted_root_audit(
                embedded_root,
                {},
                budget=budget,
                temp_parent=self.base,
            )
        self.assertEqual(
            errors[0]["error"],
            "embedded_root_audit_worker_start_failed",
        )

    def test_semantic_worker_ignores_cwd_and_python_startup_shadowing(self) -> None:
        hostile = self.base / "hostile-worker-startup"
        hostile_package = hostile / "continuum"
        hostile_package.mkdir(parents=True, exist_ok=True)
        marker = hostile / "shadow-imported.txt"
        marker_literal = repr(str(marker))
        (hostile / "sitecustomize.py").write_text(
            f"from pathlib import Path\nPath({marker_literal}).write_text('sitecustomize')\n",
            encoding="utf-8",
        )
        (hostile_package / "__init__.py").write_text(
            f"from pathlib import Path\nPath({marker_literal}).write_text('continuum')\n",
            encoding="utf-8",
        )
        embedded_root = self.base / "isolated-worker-root"
        embedded_root.mkdir(exist_ok=True)
        budget = _BundleVerificationBudget(
            deadline=time.monotonic() + 10,
            max_work_bytes=1,
        )
        previous_cwd = Path.cwd()
        try:
            os.chdir(hostile)
            with patch.dict(os.environ, {"PYTHONPATH": str(hostile)}):
                errors = _run_extracted_root_audit(
                    embedded_root,
                    {},
                    budget=budget,
                    temp_parent=self.base,
                )
        finally:
            os.chdir(previous_cwd)
        self.assertTrue(errors)
        self.assertFalse(marker.exists(), errors)
        self.assertNotEqual(errors[0].get("error"), "embedded_root_audit_worker_failed")

    def test_semantic_control_and_result_writes_preserve_reserve(self) -> None:
        embedded_root = self.base / "control-reserve-root"
        embedded_root.mkdir(exist_ok=True)
        manifest: dict[str, object] = {}
        manifest_payload = json.dumps(
            manifest,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        insufficient = (
            BUNDLE_SEMANTIC_TEMP_RESERVE_BYTES
            + len(manifest_payload)
            + _BUNDLE_SEMANTIC_RESULT_MAX_BYTES
            - 1
        )
        budget = _BundleVerificationBudget(
            deadline=time.monotonic() + 5,
            max_work_bytes=1,
        )
        with patch.object(
            bundle_module.shutil,
            "disk_usage",
            return_value=SimpleNamespace(free=insufficient),
        ), patch.object(
            bundle_module.subprocess,
            "Popen",
            side_effect=AssertionError("worker must not start below control reserve"),
        ):
            with self.assertRaises(_BundleLimitError) as raised:
                _run_extracted_root_audit(
                    embedded_root,
                    manifest,
                    budget=budget,
                    temp_parent=self.base,
                )
        self.assertEqual(raised.exception.code, "semantic_temp_reserve_eroded")

        manifest_path = self.base / "result-reserve-manifest.json"
        result_path = self.base / "result-reserve.json"
        manifest_path.write_text("{}", encoding="utf-8")
        result_path.unlink(missing_ok=True)
        with patch.object(
            bundle_module,
            "_audit_extracted_root",
            return_value=[],
        ), patch.object(
            bundle_module.shutil,
            "disk_usage",
            return_value=SimpleNamespace(
                free=BUNDLE_SEMANTIC_TEMP_RESERVE_BYTES
            ),
        ):
            code = bundle_module._semantic_worker_cli(
                str(embedded_root),
                str(manifest_path),
                str(result_path),
            )
        self.assertNotEqual(code, 0)
        self.assertFalse(result_path.exists())

    def test_large_metadata_member_has_bounded_semantic_failure(self) -> None:
        embedded_root = self.base / "large-metadata-root"
        metadata = embedded_root / "config" / "oversized.json"
        metadata.parent.mkdir(parents=True, exist_ok=True)
        with metadata.open("wb") as handle:
            handle.seek(_PORTABLE_METADATA_MAX_FILE_BYTES)
            handle.write(b"x")
        budget = _BundleVerificationBudget(
            deadline=time.monotonic() + 10,
            max_work_bytes=1,
        )
        started = time.monotonic()
        errors = _run_extracted_root_audit(
            embedded_root,
            {},
            budget=budget,
            temp_parent=self.base,
        )
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(
            errors[0].get("error"),
            "embedded_root_portability_audit_unhealthy",
        )

    def test_large_sqlite_metadata_cell_fails_without_materializing_payload(self) -> None:
        embedded_root = self.base / "large-sqlite-metadata-root"
        database = embedded_root / "config" / "large-metadata.sqlite3"
        database.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(database)
        try:
            conn.execute("CREATE TABLE metadata(path BLOB)")
            conn.execute(
                "INSERT INTO metadata(path) VALUES (zeroblob(?))",
                (_SQLITE_METADATA_MAX_VALUE_BYTES + 1,),
            )
            conn.commit()
        finally:
            conn.close()

        started = time.monotonic()
        result = audit_portable_metadata(embedded_root)
        self.assertLess(time.monotonic() - started, 10)
        self.assertFalse(result["complete"], result)
        error_codes = {
            str(item.get("error"))
            for item in result["errors"]
            if isinstance(item, dict)
        }
        self.assertIn("sqlite_value_too_large", error_codes)
        rendered = json.dumps(result, ensure_ascii=True)
        self.assertLess(len(rendered), 10_000)
        self.assertNotIn("zeroblob", rendered)

    def test_line_metadata_caps_records_bytes_and_malformed_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            metadata = root / "exports" / "many.jsonl"
            metadata.parent.mkdir(parents=True)

            metadata.write_text("x\n" * 50, encoding="utf-8")
            with patch.object(bundle_module, "_PORTABLE_METADATA_MAX_ERRORS", 8):
                malformed = audit_portable_metadata(root)
            self.assertFalse(malformed["complete"], malformed)
            self.assertLessEqual(malformed["error_count"], 8)
            self.assertIn("audit_error_limit_reached", _error_codes(malformed))

            metadata.write_text('{"message":"ordinary"}\n' * 50, encoding="utf-8")
            with patch.object(
                bundle_module,
                "_PORTABLE_METADATA_MAX_STREAM_RECORDS",
                8,
            ):
                record_limited = audit_portable_metadata(root)
            self.assertIn(
                "metadata_stream_record_limit_reached",
                _error_codes(record_limited),
            )

            with patch.object(bundle_module, "_PORTABLE_METADATA_MAX_STREAM_BYTES", 40):
                byte_limited = audit_portable_metadata(root)
            self.assertIn(
                "metadata_stream_byte_limit_reached",
                _error_codes(byte_limited),
            )

    def test_single_record_finding_expansion_and_fields_are_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            metadata = root / "exports" / "many-paths.json"
            metadata.parent.mkdir(parents=True)
            huge_key = "k" * 5000 + "Path"
            huge_leaf = "x" * 5000
            payload = {
                huge_key: "/private/leaf",
                "target_path": f"/private/{huge_leaf}",
                **{f"source_path_{index}": f"C:\\private\\item-{index}" for index in range(50)},
            }
            metadata.write_text(json.dumps(payload), encoding="utf-8")

            result = audit_portable_metadata(root, max_findings=6)

        self.assertEqual(result["finding_count"], 6, result)
        self.assertFalse(result["complete"], result)
        self.assertIn("metadata_finding_limit_reached", _error_codes(result))
        for finding in result["findings"]:
            self.assertLessEqual(
                len(str(finding["metadata_path"]).encode("utf-8")),
                bundle_module._PORTABLE_METADATA_MAX_PATH_FIELD_BYTES,
            )
            self.assertLessEqual(
                len(str(finding["value"]).encode("utf-8")),
                bundle_module._PORTABLE_METADATA_MAX_REFERENCE_BYTES,
            )
        self.assertTrue(
            any("sha256=" in str(item["metadata_path"]) for item in result["findings"]),
            result,
        )
        self.assertTrue(
            any("sha256=" in str(item["value"]) for item in result["findings"]),
            result,
        )

    def test_sqlite_limit_is_lowered_before_first_query_and_unavailable_fails_closed(self) -> None:
        class RecordingConnection:
            def __init__(self, inner: sqlite3.Connection, *, expose_limit: bool) -> None:
                self.inner = inner
                self.expose_limit = expose_limit
                self.first_query_limit: int | None = None
                self.execute_calls = 0

            @property
            def row_factory(self) -> object:
                return self.inner.row_factory

            @row_factory.setter
            def row_factory(self, value: object) -> None:
                self.inner.row_factory = value

            def setlimit(self, category: int, limit: int) -> int:
                if not self.expose_limit:
                    raise AssertionError("setlimit must be treated as unavailable")
                return self.inner.setlimit(category, limit)

            def getlimit(self, category: int) -> int:
                return self.inner.getlimit(category)

            def execute(self, *args: object, **kwargs: object) -> sqlite3.Cursor:
                self.execute_calls += 1
                if self.first_query_limit is None:
                    self.first_query_limit = self.inner.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
                return self.inner.execute(*args, **kwargs)

            def close(self) -> None:
                self.inner.close()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            database = root / "config" / "metadata.sqlite3"
            database.parent.mkdir(parents=True)
            conn = sqlite3.connect(database)
            conn.execute("CREATE TABLE metadata(source_path TEXT)")
            conn.commit()
            conn.close()

            recording = RecordingConnection(sqlite3.connect(database), expose_limit=True)
            with patch.object(bundle_module.sqlite3, "connect", return_value=recording):
                result = audit_portable_metadata(root)
            self.assertTrue(result["complete"], result)
            self.assertEqual(
                recording.first_query_limit,
                bundle_module._SQLITE_METADATA_MAX_ROW_BYTES,
            )

            unavailable = RecordingConnection(sqlite3.connect(database), expose_limit=False)
            unavailable.setlimit = None  # type: ignore[method-assign]
            with patch.object(bundle_module.sqlite3, "connect", return_value=unavailable):
                result = audit_portable_metadata(root)
            self.assertIn("sqlite_length_limit_unavailable", _error_codes(result))
            self.assertEqual(unavailable.execute_calls, 0)

    def test_sqlite_text_and_blob_columns_fit_individual_cap_without_aggregate_false_reject(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            database = root / "config" / "metadata.sqlite3"
            database.parent.mkdir(parents=True)
            conn = sqlite3.connect(database)
            try:
                conn.execute("CREATE TABLE metadata(source_path TEXT, target_path BLOB)")
                conn.execute(
                    "INSERT INTO metadata(source_path, target_path) VALUES (?, ?)",
                    ("x" * 900, b"y" * 900),
                )
                conn.commit()
            finally:
                conn.close()
            with patch.object(
                bundle_module,
                "_SQLITE_METADATA_MAX_VALUE_BYTES",
                1024,
            ), patch.object(bundle_module, "_SQLITE_METADATA_MAX_ROW_BYTES", 4096):
                result = audit_portable_metadata(root)
        self.assertTrue(result["complete"], result)

    def test_sqlite_real_text_and_blob_payloads_over_small_limit_fail_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            database = root / "config" / "metadata.sqlite3"
            database.parent.mkdir(parents=True)
            conn = sqlite3.connect(database)
            try:
                conn.execute("CREATE TABLE metadata(source_path TEXT, target_path BLOB)")
                conn.execute(
                    "INSERT INTO metadata(source_path, target_path) VALUES (?, ?)",
                    ("x" * 1025, b"y" * 1025),
                )
                conn.commit()
            finally:
                conn.close()
            with patch.object(
                bundle_module,
                "_SQLITE_METADATA_MAX_VALUE_BYTES",
                1024,
            ), patch.object(bundle_module, "_SQLITE_METADATA_MAX_ROW_BYTES", 4096):
                result = audit_portable_metadata(root)

        self.assertFalse(result["complete"], result)
        self.assertIn("sqlite_value_too_large", _error_codes(result))
        self.assertLess(len(json.dumps(result, ensure_ascii=True)), 10_000)

    def test_sqlite_exact_value_cap_marks_pending_table_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            database = root / "config" / "metadata.sqlite3"
            database.parent.mkdir(parents=True)
            conn = sqlite3.connect(database)
            try:
                conn.execute("CREATE TABLE a_metadata(source_path TEXT)")
                conn.execute("CREATE TABLE b_metadata(source_path TEXT)")
                conn.execute("INSERT INTO a_metadata(source_path) VALUES ('ordinary')")
                conn.execute(
                    "INSERT INTO b_metadata(source_path) VALUES (?)",
                    (r"C:\Private Folder\secret.txt",),
                )
                conn.commit()
            finally:
                conn.close()
            with patch.object(bundle_module, "_SQLITE_METADATA_MAX_VALUES_SCANNED", 1):
                result = audit_portable_metadata(root)

        self.assertFalse(result["complete"], result)
        self.assertIn("sqlite_value_scan_limit_reached", _error_codes(result))
        self.assertEqual(result["finding_count"], 0, result)

    def test_packer_accepts_streamed_line_metadata_larger_than_whole_json_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            output = Path(tmp) / "large-lines.zip"
            init_db(root)
            config = load_config(root)
            config["security"]["secret_audit_max_file_bytes"] = "32MB"
            write_config(root, config)
            metadata = root / "exports" / "large.jsonl"
            metadata.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps({"message": "ordinary " * 100}) + "\n"
            target_bytes = _PORTABLE_METADATA_MAX_FILE_BYTES + 1024
            with metadata.open("w", encoding="utf-8", newline="\n") as handle:
                for _index in range(target_bytes // len(line.encode("utf-8")) + 1):
                    handle.write(line)
            secure_file(metadata)

            result = pack_root(root, out_path=output, run_restore_drill=False)

        self.assertTrue(result["ok"], result)

    def test_semantic_worker_serialized_result_is_bounded(self) -> None:
        embedded_root = self.base / "bounded-result-root"
        embedded_root.mkdir(exist_ok=True)
        manifest_path = self.base / "bounded-result-manifest.json"
        result_path = self.base / "bounded-result.json"
        manifest_path.write_text("{}", encoding="utf-8")
        result_path.unlink(missing_ok=True)
        oversized = [{"error": "simulated", "detail": "x" * (2 * 1024 * 1024)}]
        with patch.object(bundle_module, "_audit_extracted_root", return_value=oversized):
            code = bundle_module._semantic_worker_cli(
                str(embedded_root),
                str(manifest_path),
                str(result_path),
            )
        self.assertEqual(code, 0)
        payload = result_path.read_bytes()
        self.assertLessEqual(len(payload), bundle_module._BUNDLE_SEMANTIC_RESULT_MAX_BYTES)
        self.assertIn("embedded_root_audit_result_too_large", payload.decode("utf-8"))

    def test_limit_overrides_are_capped_at_absolute_boundary(self) -> None:
        with self.assertRaisesRegex(ValueError, "max_expanded_bytes"):
            verify_root_bundle(
                self.bundle,
                max_expanded_bytes=BUNDLE_ABSOLUTE_MAX_EXPANDED_BYTES + 1,
            )

    def test_deflate_physical_bound_scales_for_incompressible_data(self) -> None:
        simulated_expanded = 8 * 1024**3
        simulated_bound = _deflate_compressed_size_bound(simulated_expanded, 1)
        self.assertGreater(simulated_bound - simulated_expanded, 1024**2)

        source = self.base / "incompressible.bin"
        payload = random.Random(20260716).randbytes(4 * 1024**2)
        source.write_bytes(payload)
        archive_path = self.base / "incompressible.zip"
        with zipfile.ZipFile(
            archive_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=6,
        ) as archive:
            _write_zip_member(archive, source, arcname=source.name)
        preflight = _read_bundle_zip_preflight(archive_path)
        with zipfile.ZipFile(archive_path) as archive:
            info = archive.infolist()[0]
        self.assertGreater(info.compress_size, info.file_size)
        self.assertLessEqual(
            info.compress_size,
            _deflate_compressed_size_bound(info.file_size, 1),
        )
        result = verify_root_bundle(
            archive_path,
            verify_embedded_root=False,
            max_entries=1,
            max_expanded_bytes=info.file_size,
            max_member_bytes=info.file_size,
            max_compression_ratio=2,
            max_central_directory_bytes=preflight.central_directory_size,
        )
        self.assertNotIn("bundle_archive_size_too_large", _error_codes(result))

    def test_unexpected_semantic_failure_closes_handle_and_keeps_primary(self) -> None:
        tracked = self.bundle.open("rb")
        primary = RuntimeError("primary semantic worker failure")
        if hasattr(primary, "add_note"):
            primary.add_note("semantic worker cleanup failed: forced cleanup failure")
        with patch.object(
            bundle_module,
            "_open_bundle_read_handle",
            return_value=tracked,
        ), patch.object(
            bundle_module,
            "_embedded_root_semantic_errors",
            side_effect=primary,
        ):
            result = verify_root_bundle(self.bundle)
        self.assertTrue(tracked.closed)
        self.assertIn(
            "embedded_root_semantic_verification_failed",
            _error_codes(result),
        )
        rendered = json.dumps(result, ensure_ascii=True)
        self.assertIn("primary semantic worker failure", rendered)
        self.assertNotIn("forced cleanup failure", rendered)

    def test_member_limit_error_returns_result_and_closes_raw_handle(self) -> None:
        tracked = self.bundle.open("rb")
        original_reader = bundle_module._read_zip_member_exact
        reads = 0

        def fail_second_read(*args: object, **kwargs: object) -> object:
            nonlocal reads
            reads += 1
            if reads == 2:
                raise _BundleLimitError(
                    "forced_member_read_limit",
                    "forced member read limit",
                )
            return original_reader(*args, **kwargs)

        with patch.object(
            bundle_module,
            "_open_bundle_read_handle",
            return_value=tracked,
        ), patch.object(
            bundle_module,
            "_read_zip_member_exact",
            side_effect=fail_second_read,
        ):
            result = verify_root_bundle(self.bundle, verify_embedded_root=False)

        self.assertFalse(result["ok"], result)
        self.assertIn("forced_member_read_limit", _error_codes(result))
        self.assertTrue(tracked.closed)

    def test_many_malformed_zip_entries_retain_bounded_diagnostics(self) -> None:
        archive_path = self.base / "many-malformed-members.zip"
        with zipfile.ZipFile(
            archive_path,
            "w",
            compression=zipfile.ZIP_STORED,
        ) as archive:
            for index in range(48):
                info = zipfile.ZipInfo(f"member-{index:04d}.txt")
                info.date_time = (2026, 7, 16, 12, 0, 0)
                archive.writestr(info, b"ordinary")

        with zipfile.ZipFile(archive_path) as archive:
            internal_errors = bundle_module._zip_envelope_errors(
                archive_path,
                archive.infolist(),
            )

        maximum = bundle_module._BUNDLE_MAX_RETAINED_ERRORS
        self.assertLessEqual(len(internal_errors), maximum)
        internal_marker = next(
            item
            for item in internal_errors
            if item.get("error") == "bundle_error_limit_reached"
        )
        self.assertGreater(internal_marker["omitted_error_count"], 0)

        result = verify_root_bundle(archive_path, verify_embedded_root=False)
        self.assertFalse(result["ok"], result)
        self.assertLessEqual(len(result["errors"]), maximum)
        self.assertGreater(result["error_count"], len(result["errors"]))
        result_marker = next(
            item
            for item in result["errors"]
            if item.get("error") == "bundle_error_limit_reached"
        )
        self.assertGreater(result_marker["omitted_error_count"], 0)
        self.assertLess(len(json.dumps(result, ensure_ascii=True).encode("utf-8")), 256_000)

    def test_bounded_bundle_errors_append_tracks_true_total(self) -> None:
        errors = bundle_module._BoundedBundleErrors(maximum=4)
        for index in range(6):
            errors.append({"error": f"error-{index}"})

        self.assertEqual(errors.total_count, 6)
        self.assertEqual(errors.retained_original_count, 3)
        self.assertEqual(errors.omitted_count, 3)
        self.assertEqual(
            [item["error"] for item in errors],
            ["error-0", "error-1", "error-2", "bundle_error_limit_reached"],
        )
        self.assertEqual(errors[-1]["omitted_error_count"], 3)

    def test_bounded_bundle_errors_generator_extend_tracks_true_total(self) -> None:
        yielded: list[int] = []

        def generated_errors() -> Iterator[dict[str, str]]:
            for index in range(5):
                yielded.append(index)
                yield {"error": f"generated-{index}"}

        errors = bundle_module._BoundedBundleErrors(maximum=4)
        errors.extend(generated_errors())

        self.assertEqual(yielded, list(range(5)))
        self.assertEqual(errors.total_count, 5)
        self.assertEqual(errors.retained_original_count, 3)
        self.assertEqual(errors.omitted_count, 2)
        self.assertEqual(errors[-1]["omitted_error_count"], 2)

    def test_bounded_bundle_errors_merge_preserves_child_hidden_total(self) -> None:
        child = bundle_module._BoundedBundleErrors(maximum=4)
        for index in range(10):
            child.append({"error": f"child-{index}"})

        parent = bundle_module._BoundedBundleErrors(maximum=6)
        parent.extend(child)
        self.assertEqual(parent.total_count, 10)
        self.assertEqual(parent.retained_original_count, 3)
        self.assertEqual(parent.omitted_count, 7)
        parent.append({"error": "after"})

        self.assertEqual(child.total_count, 10)
        self.assertEqual(parent.total_count, 11)
        self.assertEqual(parent.retained_original_count, 4)
        self.assertEqual(parent.omitted_count, 7)
        self.assertEqual(
            [item["error"] for item in parent],
            [
                "child-0",
                "child-1",
                "child-2",
                "after",
                "bundle_error_limit_reached",
            ],
        )
        markers = [
            item
            for item in parent
            if item.get("error") == "bundle_error_limit_reached"
        ]
        self.assertEqual(len(markers), 1)
        self.assertEqual(markers[0]["omitted_error_count"], 7)

    def test_bounded_bundle_errors_rejects_self_extension_without_mutation(self) -> None:
        errors = bundle_module._BoundedBundleErrors(maximum=4)
        errors.append({"error": "original"})
        before = list(errors)

        with self.assertRaisesRegex(ValueError, "itself"):
            errors.extend(errors)

        self.assertEqual(errors, before)
        self.assertEqual(errors.total_count, 1)
        self.assertEqual(errors.omitted_count, 0)

    def test_diagnostic_sample_stops_before_iterator_sentinel(self) -> None:
        maximum = bundle_module._BUNDLE_DIAGNOSTIC_SAMPLE_LIMIT

        def values() -> Iterator[int]:
            for index in range(maximum):
                yield index
            raise AssertionError("bounded sample over-consumed its iterator")

        sample = bundle_module._bounded_diagnostic_sample(values())
        self.assertEqual(sample, list(range(maximum)))

    def test_manifest_diagnostics_bound_aliases_but_scan_full_order(self) -> None:
        maximum = bundle_module._BUNDLE_DIAGNOSTIC_SAMPLE_LIMIT
        files = [
            {
                "path": f"snapshots/continuum_partition_alias_{index:04d}.key",
                "sha256": "a" * 64,
                "size_bytes": 1,
                "mode": 0o600,
            }
            for index in range(maximum + 5)
        ]
        files.append(
            {
                "path": "aaa-last-but-noncanonical.txt",
                "sha256": "b" * 64,
                "size_bytes": 1,
                "mode": 0o600,
            }
        )
        errors = bundle_module._manifest_structure_errors(
            {
                "schema": bundle_module.BUNDLE_MANIFEST_SCHEMA,
                "bundle_id": "bounded-diagnostics",
                "created_at": "2026-07-16T00:00:00Z",
                "profile": "shareable",
                "symlink_policy": "fail",
                "redaction_profile": "shareable",
                "root_identity_hash": None,
                "file_count": len(files),
                "total_size_bytes": len(files),
                "files": files,
                "copy": {},
                "preflight": {},
                "alias_key_policy": "exclude",
                "manifest_hash": "c" * 64,
            }
        )

        alias_error = next(
            item
            for item in errors
            if item.get("error") == "manifest_shareable_alias_key_included"
        )
        self.assertEqual(len(alias_error["paths"]), maximum)
        self.assertIn(
            "manifest_file_order_noncanonical",
            {item.get("error") for item in errors},
        )

    def test_collision_samples_bound_groups_members_and_iterator_use(self) -> None:
        maximum = bundle_module._BUNDLE_DIAGNOSTIC_SAMPLE_LIMIT

        def collision_names() -> Iterator[str]:
            for index in range(maximum):
                yield f"Member-{index}"
            for index in range(maximum):
                yield f"member-{index}"
            raise AssertionError("collision sampler over-consumed its iterator")

        collisions = bundle_module._portable_name_collisions(collision_names())
        self.assertEqual(len(collisions), maximum)
        self.assertTrue(all(len(group) == 2 for group in collisions))

        one_group = bundle_module._portable_name_collisions(
            ("same" if index % 2 else "SAME" for index in range(200))
        )
        self.assertEqual(len(one_group), 1)
        self.assertEqual(len(one_group[0]), maximum)

    def test_cli_forwards_all_bundle_limits(self) -> None:
        output = io.StringIO()
        with patch(
            "continuum.cli.verify_root_bundle",
            return_value={"ok": True},
        ) as verifier, redirect_stdout(output):
            code = cli_main(
                [
                    "verify-bundle",
                    "--path",
                    str(self.bundle),
                    "--envelope-only",
                    "--max-entries",
                    "7",
                    "--max-expanded-bytes",
                    "8000",
                    "--max-member-bytes",
                    "7000",
                    "--max-compression-ratio",
                    "60",
                    "--max-central-directory-bytes",
                    "5000",
                    "--timeout-seconds",
                    "9",
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(
            verifier.call_args.kwargs,
            {
                "verify_embedded_root": False,
                "max_entries": 7,
                "max_expanded_bytes": 8000,
                "max_member_bytes": 7000,
                "max_compression_ratio": 60,
                "max_central_directory_bytes": 5000,
                "timeout_seconds": 9,
            },
        )

    def test_mcp_forwards_and_schemas_all_bundle_limits(self) -> None:
        arguments = {
            "path": str(self.bundle),
            "verify_embedded_root": False,
            "max_entries": 7,
            "max_expanded_bytes": 8000,
            "max_member_bytes": 7000,
            "max_compression_ratio": 60,
            "max_central_directory_bytes": 5000,
            "timeout_seconds": 9,
        }
        with patch.object(
            mcp_server,
            "validate_allowed_path",
            side_effect=lambda path, **_kwargs: path,
        ), patch.object(
            mcp_server,
            "verify_root_bundle",
            return_value={"ok": True},
        ) as verifier:
            result = mcp_server.tool_verify_bundle(arguments)
        self.assertTrue(result["ok"])
        self.assertEqual(verifier.call_args.kwargs, {key: value for key, value in arguments.items() if key != "path"})
        properties = mcp_server.TOOLS["continuum_verify_bundle"][1]["properties"]
        for name in arguments:
            self.assertIn(name, properties)

    def test_packer_passes_trusted_derived_limits_to_both_self_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            output = Path(tmp) / "bundle.zip"
            init_db(root)
            with patch.object(
                bundle_module,
                "verify_root_bundle",
                wraps=verify_root_bundle,
            ) as verifier:
                result = pack_root(root, out_path=output, run_restore_drill=False)
        self.assertTrue(result["ok"], result)
        self.assertEqual(verifier.call_count, 2)
        for call in verifier.call_args_list:
            self.assertFalse(call.kwargs["verify_embedded_root"])
            for name in (
                "max_entries",
                "max_expanded_bytes",
                "max_member_bytes",
                "max_compression_ratio",
                "max_central_directory_bytes",
                "timeout_seconds",
            ):
                self.assertIn(name, call.kwargs)


if __name__ == "__main__":
    unittest.main()
