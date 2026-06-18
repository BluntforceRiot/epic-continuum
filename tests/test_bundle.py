from __future__ import annotations

import io
import json
import os
import shutil
import sqlite3
import stat
import struct
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from typing import Callable
from unittest.mock import patch

from continuum.cli import main as cli_main
from continuum.core.bundle import (
    BUNDLE_MANIFEST_NAME,
    BUNDLE_ROOT_NAME,
    _is_transient,
    _manifest_hash,
    _write_zip_member,
    _zip_member_is_safe,
    audit_portable_metadata,
    pack_root,
    verify_root_bundle,
)
from continuum.core.config import load_config, write_config
from continuum.core.operations import verify_root
from continuum.core.permissions import secure_file, secure_mkdir, secure_sqlite_files, secure_tree, secure_write_text
from continuum.core.store import audit_secrets, file_sha256, init_db


def _write_private_bytes(path: Path, data: bytes) -> None:
    secure_mkdir(path.parent)
    path.write_bytes(data)
    secure_file(path)


def _write_private_json(path: Path, payload: object) -> None:
    secure_write_text(path, json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n")


def _rewrite_bundle_manifest(
    source: Path,
    destination: Path,
    transform: Callable[[bytes], bytes],
) -> None:
    manifest_member = f"{BUNDLE_ROOT_NAME}/{BUNDLE_MANIFEST_NAME}"
    with zipfile.ZipFile(source, "r") as source_archive, zipfile.ZipFile(destination, "w") as target_archive:
        for info in source_archive.infolist():
            data = source_archive.read(info.filename)
            if info.filename == manifest_member:
                data = transform(data)
            target_archive.writestr(info, data)


def _write_canonical_bundle_from_root(
    embedded_root: Path,
    destination: Path,
    *,
    reverse_member_order: bool = False,
) -> None:
    paths = sorted(
        (path for path in embedded_root.rglob("*") if path.is_file()),
        key=lambda item: item.relative_to(embedded_root).as_posix(),
        reverse=reverse_member_order,
    )
    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=6,
        allowZip64=True,
        strict_timestamps=False,
    ) as archive:
        for path in paths:
            rel = path.relative_to(embedded_root).as_posix()
            _write_zip_member(archive, path, arcname=f"{BUNDLE_ROOT_NAME}/{rel}")


class RootBundleTest(unittest.TestCase):
    def test_all_sqlite_sidecar_variants_are_transient(self) -> None:
        transient = (
            "catalog/catalog.sqlite3-wal",
            "snapshots/state.sqlite3-shm",
            "exports/proof_artifacts/op/catalog.snapshot.sqlite-journal",
            "run/index.db-wal",
        )
        for rel in transient:
            with self.subTest(rel=rel):
                self.assertTrue(_is_transient(Path(rel)))
        self.assertFalse(_is_transient(Path("archive/evidence-wal.txt")))
        self.assertTrue(_is_transient(Path("build/release.tmp")))
        self.assertTrue(_is_transient(Path("run/work/__pycache__/worker.pyc")))
        self.assertFalse(_is_transient(Path("archive/originals/hot/project/build/evidence.txt")))
        self.assertFalse(_is_transient(Path("archive/originals/hot/package.egg-info")))
        self.assertFalse(_is_transient(Path("archive/originals/hot/evidence.db-wal")))
        self.assertFalse(_is_transient(Path("archive/originals/hot/.evidence.tmp")))
        self.assertFalse(_is_transient(Path("archive/originals/hot/evidence.pyc")))

    def test_shareable_bundle_preserves_nested_generic_evidence_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            output = base / "continuum-shareable.zip"
            init_db(root)
            evidence_files = [
                root / "archive" / "originals" / "hot" / "project" / "build" / "evidence.txt",
                root / "archive" / "originals" / "hot" / "project" / "evidence.db-wal",
                root / "archive" / "originals" / "hot" / "project" / ".evidence.tmp",
                root / "archive" / "originals" / "hot" / "project" / "evidence.pyc",
            ]
            for evidence in evidence_files:
                _write_private_bytes(evidence, f"durable evidence: {evidence.name}".encode("utf-8"))

            result = pack_root(root, out_path=output, profile="shareable", run_restore_drill=False)
            self.assertTrue(result["ok"], result)
            with zipfile.ZipFile(output) as archive:
                members = set(archive.namelist())
                for evidence in evidence_files:
                    member = f"{BUNDLE_ROOT_NAME}/{evidence.relative_to(root).as_posix()}"
                    self.assertIn(member, members)
                    self.assertEqual(archive.read(member), evidence.read_bytes())

    def test_windows_portable_name_policy_rejects_forbidden_and_superscript_device_names(self) -> None:
        unsafe = (
            "archive/bad?.txt",
            "archive/bad*.txt",
            "archive/bad<name>.txt",
            "archive/bad>name.txt",
            'archive/bad"name.txt',
            "archive/bad|name.txt",
            "archive/COM¹.txt",
            "archive/com².log",
            "archive/LPT³.tar.gz",
        )
        for name in unsafe:
            with self.subTest(name=name):
                self.assertFalse(_zip_member_is_safe(name))
        self.assertFalse(_zip_member_is_safe("archive/" + ("a" * 256)))
        self.assertFalse(_zip_member_is_safe("archive/" + ("😀" * 128)))
        self.assertTrue(_zip_member_is_safe("archive/" + ("a" * 255)))

    def test_pack_root_manifest_bypasses_platform_text_newline_translation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            output = base / "continuum.zip"
            init_db(root)

            original_write_text = Path.write_text

            def windows_translating_write_text(path: Path, data: str, *args: object, **kwargs: object) -> int:
                if path.name == BUNDLE_MANIFEST_NAME:
                    encoding = str(kwargs.get("encoding") or "utf-8")
                    path.write_bytes(data.replace("\n", "\r\n").encode(encoding))
                    return len(data)
                return original_write_text(path, data, *args, **kwargs)

            with patch.object(Path, "write_text", new=windows_translating_write_text):
                result = pack_root(root, out_path=output, run_restore_drill=False)

            self.assertTrue(result["ok"], result)
            with zipfile.ZipFile(output, "r") as archive:
                manifest_bytes = archive.read(f"{BUNDLE_ROOT_NAME}/{BUNDLE_MANIFEST_NAME}")
            self.assertTrue(manifest_bytes.endswith(b"\n"))
            self.assertNotIn(b"\r\n", manifest_bytes)

    def test_bundle_verifier_rejects_noncanonical_member_and_manifest_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            clean = base / "clean.zip"
            reversed_members = base / "reversed-members.zip"
            reversed_manifest = base / "reversed-manifest.zip"
            stage = base / "stage"
            init_db(root)
            pack_root(root, out_path=clean, run_restore_drill=False)
            with zipfile.ZipFile(clean, "r") as archive:
                archive.extractall(stage)
            embedded_root = stage / BUNDLE_ROOT_NAME
            secure_tree(embedded_root)

            _write_canonical_bundle_from_root(
                embedded_root, reversed_members, reverse_member_order=True
            )
            member_result = verify_root_bundle(reversed_members)
            self.assertFalse(member_result["ok"], member_result)
            self.assertIn("zip_member_order_noncanonical", json.dumps(member_result["errors"]))

            manifest_path = embedded_root / BUNDLE_MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"] = list(reversed(manifest["files"]))
            manifest["manifest_hash"] = _manifest_hash(manifest)
            _write_private_json(manifest_path, manifest)
            _write_canonical_bundle_from_root(embedded_root, reversed_manifest)
            manifest_result = verify_root_bundle(reversed_manifest)
            self.assertFalse(manifest_result["ok"], manifest_result)
            self.assertIn("manifest_file_order_noncanonical", json.dumps(manifest_result["errors"]))

    def test_bundle_verifier_reaudits_embedded_root_instead_of_trusting_preflight_claims(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            clean = base / "clean.zip"
            forged = base / "forged.zip"
            stage = base / "stage"
            init_db(root)
            pack_root(root, out_path=clean, run_restore_drill=False)
            with zipfile.ZipFile(clean, "r") as archive:
                archive.extractall(stage)
            embedded_root = stage / BUNDLE_ROOT_NAME
            secure_tree(embedded_root)

            config_path = embedded_root / "config" / "continuum.config.json"
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["client_secret"] = "short"
            _write_private_json(config_path, config)

            manifest_path = embedded_root / BUNDLE_MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for entry in manifest["files"]:
                if entry["path"] == "config/continuum.config.json":
                    entry["sha256"] = file_sha256(config_path)
                    entry["size_bytes"] = config_path.stat().st_size
                    entry["mode"] = stat.S_IMODE(config_path.stat().st_mode)
            total_size = sum(int(entry["size_bytes"]) for entry in manifest["files"] )
            manifest["total_size_bytes"] = total_size
            manifest["copy"]["copied_bytes"] = total_size
            manifest["manifest_hash"] = _manifest_hash(manifest)
            _write_private_json(manifest_path, manifest)
            _write_canonical_bundle_from_root(embedded_root, forged)

            envelope_only = verify_root_bundle(forged, verify_embedded_root=False)
            self.assertTrue(envelope_only["ok"], envelope_only)
            result = verify_root_bundle(forged)
            self.assertFalse(result["ok"], result)
            rendered = json.dumps(result["errors"])
            self.assertIn("embedded_root_secret_audit_unhealthy", rendered)

    def test_bundle_verifier_rejects_rehashed_but_invalid_embedded_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            clean = base / "clean.zip"
            forged = base / "forged-invalid-catalog.zip"
            stage = base / "stage"
            init_db(root)
            pack_root(root, out_path=clean, run_restore_drill=False)
            with zipfile.ZipFile(clean, "r") as archive:
                archive.extractall(stage)
            embedded_root = stage / BUNDLE_ROOT_NAME
            secure_tree(embedded_root)

            catalog_path = embedded_root / "catalog" / "catalog.sqlite3"
            _write_private_bytes(catalog_path, b"NOT A SQLITE DATABASE\n")
            manifest_path = embedded_root / BUNDLE_MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for entry in manifest["files"]:
                if entry["path"] == "catalog/catalog.sqlite3":
                    entry["sha256"] = file_sha256(catalog_path)
                    entry["size_bytes"] = catalog_path.stat().st_size
                    entry["mode"] = stat.S_IMODE(catalog_path.stat().st_mode)
            total_size = sum(int(entry["size_bytes"]) for entry in manifest["files"])
            manifest["total_size_bytes"] = total_size
            manifest["copy"]["copied_bytes"] = total_size
            manifest["manifest_hash"] = _manifest_hash(manifest)
            _write_private_json(manifest_path, manifest)
            _write_canonical_bundle_from_root(embedded_root, forged)

            envelope_only = verify_root_bundle(forged, verify_embedded_root=False)
            self.assertTrue(envelope_only["ok"], envelope_only)
            result = verify_root_bundle(forged)
            self.assertFalse(result["ok"], result)
            rendered = json.dumps(result["errors"])
            self.assertTrue(
                "embedded_root_portability_audit_failed" in rendered
                or "embedded_root_verification_failed" in rendered,
                result,
            )

    def test_bundle_verifier_rejects_rehashed_preflight_count_lie(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            clean = base / "clean.zip"
            forged = base / "forged-preflight-count.zip"
            stage = base / "stage"
            init_db(root)
            pack_root(root, out_path=clean, run_restore_drill=False)
            with zipfile.ZipFile(clean, "r") as archive:
                archive.extractall(stage)
            embedded_root = stage / BUNDLE_ROOT_NAME
            secure_tree(embedded_root)

            manifest_path = embedded_root / BUNDLE_MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["preflight"]["artifact_count"] = int(
                manifest["preflight"]["artifact_count"]
            ) + 1
            manifest["manifest_hash"] = _manifest_hash(manifest)
            _write_private_json(manifest_path, manifest)
            _write_canonical_bundle_from_root(embedded_root, forged)

            envelope_only = verify_root_bundle(forged, verify_embedded_root=False)
            self.assertTrue(envelope_only["ok"], envelope_only)
            result = verify_root_bundle(forged)
            self.assertFalse(result["ok"], result)
            self.assertIn("embedded_root_preflight_count_mismatch", json.dumps(result["errors"]))

    @unittest.skipIf(os.name == "nt", "Windows cannot create the invalid source filename")
    def test_pack_root_rejects_windows_invalid_evidence_name_on_posix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            invalid = root / "archive" / "originals" / "hot" / "bad?.txt"
            secure_write_text(invalid, "evidence")
            with self.assertRaisesRegex(ValueError, "bundle-incompatible"):
                pack_root(
                    root,
                    out_path=Path(tmp) / "invalid-name.zip",
                    run_restore_drill=False,
                )

    def test_pack_root_creates_self_verifying_bundle_without_external_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            source = base / "private-source.txt"
            output = base / "continuum-shareable.zip"
            source.write_text("portable bundle evidence", encoding="utf-8")

            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli_main(["init", "--root", str(root)]), 0)
                self.assertEqual(
                    cli_main(["ingest-file", "--root", str(root), "--path", str(source)]),
                    0,
                )

            source_text = str(source)
            durable_metadata = [
                *sorted((root / "run" / "operations").glob("*.json")),
                *sorted((root / "run" / "operation_events").glob("*.jsonl")),
                *sorted((root / "exports" / "operation_receipts").glob("*.json")),
                *sorted((root / "exports" / "operation_events").glob("*.jsonl")),
                *sorted((root / "exports" / "proof_packs").glob("*.json")),
            ]
            self.assertTrue(durable_metadata)
            for path in durable_metadata:
                self.assertNotIn(source_text, path.read_text(encoding="utf-8"), path)

            result = pack_root(
                root,
                out_path=output,
                profile="shareable",
                symlink_policy="fail",
                run_restore_drill=False,
            )
            self.assertTrue(result["ok"], result)
            self.assertTrue(output.exists())
            self.assertTrue(Path(str(output) + ".sha256").exists())
            verification = verify_root_bundle(output)
            self.assertTrue(verification["ok"], verification)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli_main(["verify-bundle", "--path", str(output)]), 0)
            with zipfile.ZipFile(output) as archive:
                self.assertTrue(archive.infolist())
                self.assertTrue(all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in archive.infolist()))
                self.assertTrue(all(info.create_system == 3 for info in archive.infolist()))
                names = {info.filename for info in archive.infolist()}
                self.assertFalse(any(name.endswith((".sqlite3-wal", ".sqlite3-shm")) for name in names), names)
                manifest = json.loads(archive.read("epic-continuum-root/bundle.manifest.json"))
                self.assertNotIn("root_identity_hash", manifest)
                self.assertEqual(manifest["copy"]["copied_files"], manifest["file_count"])
                self.assertEqual(manifest["copy"]["copied_bytes"], manifest["total_size_bytes"])

            extract_parent = base / "unpacked"
            with zipfile.ZipFile(output) as archive:
                for info in archive.infolist():
                    if info.is_dir() or info.file_size > 4 * 1024 * 1024:
                        continue
                    self.assertNotIn(source_text.encode(), archive.read(info.filename), info.filename)
                archive.extractall(extract_parent)

            shutil.rmtree(root)
            source.unlink()
            extracted_root = extract_parent / "epic-continuum-root"
            secure_tree(extracted_root)
            extracted_verification = verify_root(
                extracted_root,
                strict=True,
                verify_recent_proof_packs=20,
                run_restore_drill=False,
                scan_secrets=True,
            )
            self.assertTrue(extracted_verification["ok"], extracted_verification)

    def test_pack_root_rejects_incomplete_secret_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            config = load_config(root)
            config["security"]["secret_audit_max_file_bytes"] = "16B"
            write_config(root, config)
            large = root / "archive" / "originals" / "hot" / "large-safe.txt"
            secure_write_text(large, "ordinary text that exceeds the deliberately tiny audit cap")

            audit = audit_secrets(root, create=False)
            self.assertTrue(audit["ok"], audit)
            self.assertFalse(audit["complete"], audit)
            self.assertGreaterEqual(audit["incomplete_skip_count"], 1)
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli_main(["audit-secrets", "--root", str(root)]), 1)
            with self.assertRaisesRegex(ValueError, "verification failed|incomplete"):
                pack_root(
                    root,
                    out_path=Path(tmp) / "should-not-exist.zip",
                    run_restore_drill=False,
                )

    def test_pack_root_rejects_symlink_for_shareable_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            target = Path(tmp) / "external.txt"
            target.write_text("external evidence", encoding="utf-8")
            init_db(root)
            link = root / "archive" / "external-link.txt"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")

            with self.assertRaisesRegex(ValueError, "symlink"):
                pack_root(
                    root,
                    out_path=Path(tmp) / "should-not-exist.zip",
                    profile="shareable",
                    run_restore_drill=False,
                )

    def test_verify_root_bundle_rejects_tampered_member(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            output = Path(tmp) / "clean.zip"
            tampered = Path(tmp) / "tampered.zip"
            init_db(root)
            result = pack_root(root, out_path=output, run_restore_drill=False)
            self.assertTrue(result["ok"], result)

            with zipfile.ZipFile(output, "r") as source_archive, zipfile.ZipFile(
                tampered, "w", compression=zipfile.ZIP_DEFLATED
            ) as target_archive:
                changed = False
                for info in source_archive.infolist():
                    data = source_archive.read(info.filename)
                    if not changed and not info.is_dir() and not info.filename.endswith("bundle.manifest.json"):
                        data += b"tamper"
                        changed = True
                    target_archive.writestr(info, data)
            self.assertTrue(changed)
            verification = verify_root_bundle(tampered)
            self.assertFalse(verification["ok"], verification)
            self.assertIn("bundle_member_hash_mismatch", json.dumps(verification["errors"]))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli_main(["verify-bundle", "--path", str(tampered)]), 1)

    def test_portable_metadata_audit_detects_absolute_local_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            metadata = root / "exports" / "imports" / "legacy.json"
            raw_path = str(Path(tmp) / "private" / "source.txt")
            secure_write_text(metadata, json.dumps({"source_path": raw_path}))

            audit = audit_portable_metadata(root)
            self.assertFalse(audit["ok"], audit)
            self.assertEqual(audit["finding_count"], 1)
            self.assertEqual(audit["findings"][0]["file"], "exports/imports/legacy.json")
            self.assertNotEqual(audit["findings"][0]["value"], raw_path)

    def test_portable_metadata_audit_scans_config_camelcase_and_file_uris(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            config = load_config(root)
            config["custom_integration"] = {
                "workspacePath": "file:///Users/alice/private-project",
                "homeDir": "~/private-cache",
                "windowsDriveRelativePath": r"C:private\workspace",
                "windowsRootRelativePath": r"\Users\alice\private-cache",
                "sourcePaths": {"/Users/alice/local-map-entry": True},
            }
            write_config(root, config)

            audit = audit_portable_metadata(root)
            self.assertFalse(audit["ok"], audit)
            self.assertTrue(audit["complete"], audit)
            self.assertGreaterEqual(audit["finding_count"], 5)
            self.assertTrue(
                all(item["file"] == "config/continuum.config.json" for item in audit["findings"]),
                audit,
            )
            serialized = json.dumps(audit)
            self.assertNotIn("/Users/alice/private-project", serialized)
            self.assertNotIn("~/private-cache", serialized)
            self.assertNotIn(r"C:private\workspace", serialized)
            self.assertNotIn(r"\Users\alice\private-cache", serialized)
            self.assertNotIn("/Users/alice/local-map-entry", serialized)
            with self.assertRaisesRegex(ValueError, "portable metadata"):
                pack_root(
                    root,
                    out_path=Path(tmp) / "should-not-exist.zip",
                    profile="shareable",
                    run_restore_drill=False,
                )

    def test_portable_metadata_audit_scans_nested_sqlite_key_value_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            nested = root / "run" / "mempalace_import_snapshots" / "import_x" / "chroma.sqlite3"
            secure_mkdir(nested.parent)
            conn = sqlite3.connect(nested)
            try:
                conn.execute("CREATE TABLE embedding_metadata(key TEXT, string_value TEXT)")
                conn.execute(
                    "INSERT INTO embedding_metadata(key, string_value) VALUES(?, ?)",
                    ("source_file", "/Users/alice/private-project/example.md"),
                )
                conn.commit()
            finally:
                conn.close()
            secure_sqlite_files(nested)
            non_sqlite = root / "archive" / "originals" / "hot" / "ordinary.db"
            secure_write_text(non_sqlite, "ordinary evidence with a .db suffix")

            audit = audit_portable_metadata(root)
            self.assertFalse(audit["ok"], audit)
            self.assertTrue(audit["complete"], audit)
            self.assertGreaterEqual(audit["sqlite_databases_scanned"], 2)
            finding = next(item for item in audit["findings"] if item["source"] == "sqlite_key_value")
            self.assertEqual(
                finding["file"],
                "run/mempalace_import_snapshots/import_x/chroma.sqlite3",
            )
            self.assertNotIn("/Users/alice/private-project/example.md", json.dumps(audit))
            with self.assertRaisesRegex(ValueError, "portable metadata"):
                pack_root(
                    root,
                    out_path=Path(tmp) / "should-not-exist.zip",
                    profile="shareable",
                    run_restore_drill=False,
                )

    def test_portable_metadata_audit_rejects_duplicate_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            ambiguous = root / "exports" / "imports" / "ambiguous.json"
            secure_write_text(
                ambiguous,
                '{"source_path":"/Users/alice/private.txt","source_path":"external:safe.txt"}\n',
            )

            audit = audit_portable_metadata(root)
            self.assertTrue(audit["ok"], audit)
            self.assertFalse(audit["complete"], audit)
            self.assertEqual(audit["error_count"], 1)
            self.assertIn("duplicate JSON object key", audit["errors"][0]["detail"])
            self.assertNotIn("/Users/alice/private.txt", json.dumps(audit))
            with self.assertRaisesRegex(ValueError, "portable metadata audit was incomplete"):
                pack_root(
                    root,
                    out_path=Path(tmp) / "should-not-exist.zip",
                    profile="shareable",
                    run_restore_drill=False,
                )


    def test_shareable_pack_rejects_allowlisted_secret_like_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            legacy = root / "archive" / "legacy.env"
            secure_write_text(legacy, "client_secret: short\n")
            first = audit_secrets(root, create=False)
            self.assertFalse(first["ok"], first)
            secret_hash = first["findings"][0]["secret_hash"]
            allowlist = root / "security" / "secret_allowlist.jsonl"
            secure_write_text(allowlist, json.dumps({"secret_hash": secret_hash}) + "\n")
            second = audit_secrets(root, create=False)
            self.assertTrue(second["ok"], second)
            self.assertGreater(second["allowlisted_findings"], 0)
            with self.assertRaisesRegex(ValueError, "allowlisted"):
                pack_root(
                    root,
                    out_path=Path(tmp) / "should-not-exist.zip",
                    profile="shareable",
                    run_restore_drill=False,
                )

    def test_portable_metadata_audit_scans_sqlite_and_card_yaml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            raw_db_path = str(Path(tmp) / "private" / "database-source.txt")
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            try:
                conn.execute(
                    "INSERT INTO audit_events(id, actor, action, target_type, target_id, payload_json, created_at) "
                    "VALUES(?, 'tester', 'legacy', 'file', NULL, ?, '2026-06-17T00:00:00Z')",
                    ("audit_legacy_path", json.dumps({"source_path": raw_db_path})),
                )
                conn.commit()
            finally:
                conn.close()
            raw_yaml_path = str(Path(tmp) / "private" / "yaml-source.txt")
            sidecar = root / "catalog" / "cards" / "legacy.yaml"
            secure_write_text(sidecar, f'source_uri: {json.dumps(raw_yaml_path)}\n')

            audit = audit_portable_metadata(root)
            self.assertFalse(audit["ok"], audit)
            self.assertTrue(audit["complete"], audit)
            sources = {item["source"] for item in audit["findings"]}
            self.assertIn("sqlite_json", sources)
            self.assertIn("yaml", sources)
            serialized = json.dumps(audit)
            self.assertNotIn(raw_db_path, serialized)
            self.assertNotIn(raw_yaml_path, serialized)
            with self.assertRaisesRegex(ValueError, "portable metadata"):
                pack_root(
                    root,
                    out_path=Path(tmp) / "should-not-exist.zip",
                    run_restore_drill=False,
                )

    def test_bundle_verifier_rejects_portable_name_collisions_and_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            collision = Path(tmp) / "collision.zip"
            with zipfile.ZipFile(collision, "w") as archive:
                for name in ("epic-continuum-root/A.txt", "epic-continuum-root/a.txt"):
                    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o644) << 16
                    archive.writestr(info, b"x")
            result = verify_root_bundle(collision)
            self.assertFalse(result["ok"], result)
            self.assertIn("portable_member_name_collisions", json.dumps(result["errors"]))

            symlink_bundle = Path(tmp) / "symlink.zip"
            with zipfile.ZipFile(symlink_bundle, "w") as archive:
                info = zipfile.ZipInfo("epic-continuum-root/link", date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, b"target")
            result = verify_root_bundle(symlink_bundle)
            self.assertFalse(result["ok"], result)
            self.assertIn("non_regular_bundle_members", json.dumps(result["errors"]))


    def test_bundle_verifier_rejects_forged_shareable_policy_claims(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            clean = Path(tmp) / "clean.zip"
            forged = Path(tmp) / "forged.zip"
            init_db(root)
            pack_root(root, out_path=clean, run_restore_drill=False)

            def forge(data: bytes) -> bytes:
                manifest = json.loads(data)
                manifest["profile"] = "shareable"
                manifest["symlink_policy"] = "skip"
                manifest["redaction_profile"] = "private"
                manifest["preflight"].update(
                    {
                        "root_verification_ok": False,
                        "staged_root_verification_ok": False,
                        "secret_audit_complete": False,
                        "secret_finding_count": 2,
                        "secret_allowlisted_finding_count": 1,
                        "proof_packs_ok": False,
                        "artifact_ledger_ok": False,
                        "portable_metadata_complete": False,
                        "portable_metadata_ok": False,
                    }
                )
                manifest["manifest_hash"] = _manifest_hash(manifest)
                return (json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()

            _rewrite_bundle_manifest(clean, forged, forge)
            result = verify_root_bundle(forged)
            self.assertFalse(result["ok"], result)
            serialized = json.dumps(result["errors"])
            self.assertIn("manifest_shareable_symlink_policy_invalid", serialized)
            self.assertIn("manifest_shareable_redaction_profile_invalid", serialized)
            self.assertIn("manifest_preflight_unhealthy", serialized)
            self.assertIn("manifest_preflight_secret_findings_present", serialized)

    def test_bundle_verifier_rejects_secret_and_local_path_manifest_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            clean = Path(tmp) / "clean.zip"
            forged = Path(tmp) / "forged-metadata.zip"
            init_db(root)
            pack_root(root, out_path=clean, run_restore_drill=False)

            def forge(data: bytes) -> bytes:
                manifest = json.loads(data)
                manifest["copy"]["skipped"].append(
                    {
                        "reason": "transient_excluded",
                        "path": "/Users/alice/private/source.txt",
                        "client_secret": "short",
                    }
                )
                manifest["copy"]["skipped_count"] += 1
                manifest["manifest_hash"] = _manifest_hash(manifest)
                return (json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()

            _rewrite_bundle_manifest(clean, forged, forge)
            result = verify_root_bundle(forged)
            self.assertFalse(result["ok"], result)
            rendered = json.dumps(result["errors"])
            self.assertIn("manifest_secret_policy_violation", rendered)
            self.assertIn("manifest_nonportable_metadata", rendered)
            self.assertNotIn("/Users/alice/private/source.txt", rendered)
            self.assertNotIn('"client_secret": "short"', rendered)

    def test_bundle_verifier_rejects_duplicate_manifest_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            clean = Path(tmp) / "clean.zip"
            ambiguous = Path(tmp) / "ambiguous.zip"
            init_db(root)
            pack_root(root, out_path=clean, run_restore_drill=False)

            def duplicate_profile_key(data: bytes) -> bytes:
                text = data.decode("utf-8")
                needle = '  "profile": "shareable",'
                replacement = '  "profile": "portable",\n  "profile": "shareable",'
                self.assertIn(needle, text)
                return text.replace(needle, replacement, 1).encode("utf-8")

            _rewrite_bundle_manifest(clean, ambiguous, duplicate_profile_key)
            result = verify_root_bundle(ambiguous)
            self.assertFalse(result["ok"], result)
            self.assertIn("manifest_decode_failed", json.dumps(result["errors"]))
            self.assertIn("duplicate JSON object key", json.dumps(result["errors"]))

    def test_bundle_verifier_rejects_unmanifested_zip_envelope_channels(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            clean = base / "clean.zip"
            init_db(root)
            pack_root(root, out_path=clean, run_restore_drill=False)

            archive_comment = base / "archive-comment.zip"
            shutil.copy2(clean, archive_comment)
            with zipfile.ZipFile(archive_comment, "a") as archive:
                archive.comment = b"client_secret=hidden-in-archive-comment"
            result = verify_root_bundle(archive_comment)
            self.assertFalse(result["ok"], result)
            self.assertIn("archive_comment_not_allowed", json.dumps(result["errors"]))

            trailing = base / "trailing.zip"
            shutil.copy2(clean, trailing)
            with trailing.open("ab") as handle:
                handle.write(b"client_secret=hidden-after-eocd")
            result = verify_root_bundle(trailing)
            self.assertFalse(result["ok"], result)
            self.assertIn("zip_trailing_bytes", json.dumps(result["errors"]))

            preamble = base / "preamble.zip"
            preamble.write_bytes(b"client_secret=hidden-before-local-header" + clean.read_bytes())
            result = verify_root_bundle(preamble)
            self.assertFalse(result["ok"], result)
            self.assertIn("zip_local_member_gap_or_preamble", json.dumps(result["errors"]))

            local_metadata = base / "local-metadata.zip"
            local_bytes = bytearray(clean.read_bytes())
            self.assertEqual(local_bytes[:4], b"PK\x03\x04")
            local_bytes[10:12] = (1).to_bytes(2, "little")  # noncanonical DOS mtime
            local_metadata.write_bytes(local_bytes)
            result = verify_root_bundle(local_metadata)
            self.assertFalse(result["ok"], result)
            self.assertIn("zip_local_metadata_noncanonical", json.dumps(result["errors"]))

            member_metadata = base / "member-metadata.zip"
            with zipfile.ZipFile(clean, "r") as source, zipfile.ZipFile(member_metadata, "w") as target:
                for index, info in enumerate(source.infolist()):
                    data = source.read(info.filename)
                    if index == 0:
                        info.comment = b"client_secret=hidden-in-member-comment"
                        info.extra = b"\x99\x99\x04\x00JUNK"
                    target.writestr(info, data)
            result = verify_root_bundle(member_metadata)
            self.assertFalse(result["ok"], result)
            rendered = json.dumps(result["errors"])
            self.assertIn("member_comments_not_allowed", rendered)
            self.assertIn("zip_unapproved_extra_fields", rendered)

    def test_bundle_verifier_rejects_unnecessary_zip64_end_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            clean = base / "clean.zip"
            mutated = base / "unnecessary-zip64.zip"
            init_db(root)
            pack_root(root, out_path=clean, run_restore_drill=False)

            data = bytearray(clean.read_bytes())
            eocd_offset = data.rfind(b"PK\x05\x06")
            self.assertGreaterEqual(eocd_offset, 0)
            (
                _signature,
                _disk,
                _central_disk,
                _entries_on_disk,
                entries_total,
                central_size,
                central_offset,
                _comment_length,
            ) = struct.unpack_from("<IHHHHIIH", data, eocd_offset)
            zip64_eocd = struct.pack(
                "<IQHHIIQQQQ",
                0x06064B50,
                44,
                45,
                45,
                0,
                0,
                entries_total,
                entries_total,
                central_size,
                central_offset,
            )
            zip64_locator = struct.pack("<IIQI", 0x07064B50, 0, eocd_offset, 1)
            legacy_eocd = struct.pack(
                "<IHHHHIIH",
                0x06054B50,
                0,
                0,
                0xFFFF,
                0xFFFF,
                central_size,
                central_offset,
                0,
            )
            mutated.write_bytes(data[:eocd_offset] + zip64_eocd + zip64_locator + legacy_eocd)

            result = verify_root_bundle(mutated)
            self.assertFalse(result["ok"], result)
            self.assertIn("zip64_not_required", json.dumps(result["errors"]))

    def test_bundle_verifier_fails_closed_on_unsupported_central_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            clean = base / "clean.zip"
            mutated = base / "unsupported-version.zip"
            init_db(root)
            pack_root(root, out_path=clean, run_restore_drill=False)

            data = bytearray(clean.read_bytes())
            eocd_offset = data.rfind(b"PK\x05\x06")
            self.assertGreaterEqual(eocd_offset, 0)
            central_offset = struct.unpack_from("<I", data, eocd_offset + 16)[0]
            self.assertEqual(data[central_offset : central_offset + 4], b"PK\x01\x02")
            data[central_offset + 6] = 164
            mutated.write_bytes(data)

            result = verify_root_bundle(mutated)
            self.assertFalse(result["ok"], result)
            self.assertEqual(result["errors"][0]["error"], "bundle_open_failed")

    def test_bundle_verifier_fails_closed_on_corrupt_member_stream(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            clean = base / "clean.zip"
            corrupted = base / "corrupted.zip"
            init_db(root)
            pack_root(root, out_path=clean, run_restore_drill=False)

            data = bytearray(clean.read_bytes())
            manifest_member = f"{BUNDLE_ROOT_NAME}/{BUNDLE_MANIFEST_NAME}"
            with zipfile.ZipFile(clean) as archive:
                info = archive.getinfo(manifest_member)
            offset = int(info.header_offset)
            name_length = int.from_bytes(data[offset + 26 : offset + 28], "little")
            extra_length = int.from_bytes(data[offset + 28 : offset + 30], "little")
            data_offset = offset + 30 + name_length + extra_length
            mutation_offset = data_offset + max(1, int(info.compress_size) // 2)
            data[mutation_offset] ^= 0xFF
            corrupted.write_bytes(data)

            result = verify_root_bundle(corrupted)
            self.assertFalse(result["ok"], result)
            self.assertTrue(
                any(
                    item.get("error") in {
                        "manifest_decode_failed",
                        "bundle_member_read_failed",
                        "bundle_member_stream_invalid",
                    }
                    for item in result["errors"]
                ),
                result,
            )

    def test_bundle_verifier_rejects_bytes_after_deflate_end_inside_member(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            clean = base / "clean.zip"
            hidden = base / "hidden-compressed-trailer.zip"
            init_db(root)
            pack_root(root, out_path=clean, run_restore_drill=False)

            data = bytearray(clean.read_bytes())
            trailer = b"client_secret=hidden-after-deflate-end"
            with zipfile.ZipFile(clean) as archive:
                target = sorted(archive.infolist(), key=lambda item: item.header_offset)[-1]

            local_offset = int(target.header_offset)
            name_length, extra_length = struct.unpack_from("<HH", data, local_offset + 26)
            extra_offset = local_offset + 30 + name_length
            compressed_32, uncompressed_32 = struct.unpack_from("<II", data, local_offset + 18)
            compressed_size = int(target.compress_size)
            data_offset = extra_offset + extra_length
            insertion_offset = data_offset + compressed_size
            data[insertion_offset:insertion_offset] = trailer
            if compressed_32 == 0xFFFFFFFF or uncompressed_32 == 0xFFFFFFFF:
                extra_id, extra_size = struct.unpack_from("<HH", data, extra_offset)
                self.assertEqual((extra_id, extra_size), (1, 16))
                struct.pack_into("<Q", data, extra_offset + 12, compressed_size + len(trailer))
            else:
                struct.pack_into("<I", data, local_offset + 18, compressed_size + len(trailer))

            eocd_offset = data.rfind(b"PK\x05\x06")
            central_size, old_central_offset = struct.unpack_from("<II", data, eocd_offset + 12)
            central_offset = old_central_offset + len(trailer)
            cursor = central_offset
            found = False
            while cursor < central_offset + central_size:
                self.assertEqual(data[cursor : cursor + 4], b"PK\x01\x02")
                values = struct.unpack_from("<IHHHHHHIIIHHHHHII", data, cursor)
                central_name_length = values[10]
                central_extra_length = values[11]
                central_comment_length = values[12]
                name = bytes(data[cursor + 46 : cursor + 46 + central_name_length]).decode("utf-8")
                if name == target.filename:
                    struct.pack_into("<I", data, cursor + 20, int(target.compress_size) + len(trailer))
                    found = True
                cursor += 46 + central_name_length + central_extra_length + central_comment_length
            self.assertTrue(found)
            struct.pack_into("<I", data, eocd_offset + 16, central_offset)
            hidden.write_bytes(data)

            with zipfile.ZipFile(hidden) as archive:
                self.assertGreater(len(archive.read(target.filename)), 0)
            result = verify_root_bundle(hidden)
            self.assertFalse(result["ok"], result)
            self.assertIn("compressed_stream_trailing_data", json.dumps(result["errors"]))

    def test_non_force_publication_race_does_not_overwrite_competing_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            output = base / "continuum.zip"
            checksum = Path(str(output) + ".sha256")
            init_db(root)

            calls = 0

            def raced_lexists(path: Path) -> bool:
                nonlocal calls
                calls += 1
                if calls == 3:
                    output.write_bytes(b"competing publisher")
                    return False
                return os.path.lexists(path)

            with patch("continuum.core.bundle._path_lexists", side_effect=raced_lexists):
                with self.assertRaises(FileExistsError):
                    pack_root(root, out_path=output, run_restore_drill=False)

            self.assertEqual(output.read_bytes(), b"competing publisher")
            self.assertFalse(checksum.exists())

    def test_non_force_publication_falls_back_when_hard_links_are_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            output = base / "continuum.zip"
            init_db(root)

            with patch("continuum.core.bundle.os.link", side_effect=OSError("hard links unavailable")):
                result = pack_root(root, out_path=output, run_restore_drill=False)

            self.assertTrue(result["ok"], result)
            self.assertTrue(verify_root_bundle(output)["ok"])
            self.assertTrue(Path(str(output) + ".sha256").is_file())

    def test_force_publication_failure_restores_previous_bundle_and_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            output = base / "continuum.zip"
            checksum = Path(str(output) + ".sha256")
            init_db(root)
            pack_root(root, out_path=output, run_restore_drill=False)
            original_bundle = output.read_bytes()
            original_checksum = checksum.read_bytes()

            with patch(
                "continuum.core.bundle.verify_root_bundle",
                side_effect=[
                    {"ok": True, "errors": []},
                    {"ok": False, "errors": [{"error": "simulated_final_failure"}]},
                ],
            ):
                with self.assertRaisesRegex(ValueError, "final bundle verification failed"):
                    pack_root(
                        root,
                        out_path=output,
                        run_restore_drill=False,
                        force=True,
                    )

            self.assertEqual(output.read_bytes(), original_bundle)
            self.assertEqual(checksum.read_bytes(), original_checksum)
            self.assertTrue(verify_root_bundle(output)["ok"])

    def test_force_checksum_write_failure_restores_previous_output_pair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            output = base / "continuum.zip"
            checksum = Path(str(output) + ".sha256")
            init_db(root)
            pack_root(root, out_path=output, run_restore_drill=False)
            original_bundle = output.read_bytes()
            original_checksum = checksum.read_bytes()

            with patch(
                "continuum.core.bundle.atomic_write_text_file",
                side_effect=OSError("simulated checksum publication failure"),
            ):
                with self.assertRaisesRegex(OSError, "checksum publication failure"):
                    pack_root(
                        root,
                        out_path=output,
                        run_restore_drill=False,
                        force=True,
                    )

            self.assertEqual(output.read_bytes(), original_bundle)
            self.assertEqual(checksum.read_bytes(), original_checksum)
            self.assertTrue(verify_root_bundle(output)["ok"])

    def test_pack_root_treats_checksum_receipt_as_output_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            output = Path(tmp) / "continuum.zip"
            checksum = Path(str(output) + ".sha256")
            init_db(root)
            checksum.write_text("stale\n", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                pack_root(root, out_path=output, run_restore_drill=False)
            self.assertFalse(output.exists())
            self.assertEqual(checksum.read_text(encoding="utf-8"), "stale\n")

    def test_pack_root_cli_returns_failure_when_result_is_unhealthy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            output = Path(tmp) / "bundle.zip"
            with patch("continuum.cli.pack_root", return_value={"ok": False, "error": "simulated"}):
                with redirect_stdout(io.StringIO()):
                    status = cli_main(
                        [
                            "pack-root",
                            "--root",
                            str(root),
                            "--out",
                            str(output),
                            "--no-restore-drill",
                        ]
                    )
            self.assertEqual(status, 1)

    def test_pack_root_removes_output_when_final_verification_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            output = Path(tmp) / "bundle.zip"
            init_db(root)
            with patch(
                "continuum.core.bundle.verify_root_bundle",
                side_effect=[
                    {"ok": True},
                    {"ok": False, "errors": [{"error": "simulated_final_failure"}]},
                ],
            ):
                with self.assertRaisesRegex(ValueError, "final bundle verification failed"):
                    pack_root(root, out_path=output, run_restore_drill=False)
            self.assertFalse(output.exists())
            self.assertFalse(Path(str(output) + ".sha256").exists())



if __name__ == "__main__":
    unittest.main()
