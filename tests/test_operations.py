from __future__ import annotations

import hashlib
import io
import os
import json
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import continuum.core.store as store_module
from continuum.cli import main as cli_main
from continuum.core.config import load_config, write_config
from continuum.core.permissions import secure_write_text
from continuum.core.proof_archive import apply_legacy_catalog_archive, configured_archive_root
from continuum.core.writer_claim import claim_writer
from continuum.core.store import (
    audit_secrets,
    append_scroll_event,
    compile_context,
    connect,
    connect_existing,
    enforce_snapshot_retention,
    ingest_file,
    init_db,
    record_artifact,
    roll_scroll_segment,
    snapshot,
    snapshot_manifest_path,
)
from continuum.core.operations import (
    OperationGuard,
    SNAPSHOT_COUNT_TABLES,
    _proof_pack_hash,
    _stable_json_hash,
    append_operation_event,
    create_proof_pack,
    doctor,
    enforce_proof_pack_retention,
    finish_operation,
    list_operations,
    operation_summary,
    read_operation,
    record_operation_progress,
    recover_stale_operations,
    recovery_drill,
    replay_operation_event_log,
    restore_drill,
    start_operation,
    update_operation_cursor,
    verify_operation_event_log,
    verify_root,
    verify_proof_pack,
    write_operation,
)


def proof_item_path(root: Path, item: dict) -> Path:
    if item.get("uri_base") == "continuum_root":
        return root / str(item.get("uri") or item["path"])
    return Path(str(item["path"]))


def root_uri(root: Path, path: str | Path) -> str:
    return Path(path).resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()


def make_link_like_dir(testcase: unittest.TestCase, link: Path, target: Path) -> None:
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
        testcase.skipTest(f"symlinks unavailable: {exc}")


class OperationLedgerTest(unittest.TestCase):
    def test_operation_id_cannot_escape_receipt_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "epic-continuum"
            start_operation(root, operation_type="seed", title="Create operation directories")
            outside = base / "outside.json"
            outside.write_text(json.dumps({"operation_id": "outside", "title": "loot"}), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "safe portable filename component"):
                operation_summary(root, "../../../outside")
            for reserved in ("CON", "nul", "LPT1.backup"):
                with self.subTest(reserved=reserved):
                    with self.assertRaisesRegex(ValueError, "safe portable filename component"):
                        operation_summary(root, reserved)

    def test_concurrent_progress_updates_are_lossless_and_hash_chained(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            started = start_operation(root, operation_type="concurrency", title="Concurrent progress")
            operation_id = started["operation_id"]

            def record(index: int) -> None:
                record_operation_progress(
                    root,
                    operation_id,
                    phase="parallel",
                    message=f"progress-{index}",
                    current=index,
                    total=40,
                )

            with ThreadPoolExecutor(max_workers=16) as executor:
                list(executor.map(record, range(40)))

            summary = operation_summary(root, operation_id)
            self.assertEqual(summary["progress_events"], 40)
            for path in (
                root / "run" / "operation_events" / f"{operation_id}.jsonl",
                root / "exports" / "operation_events" / f"{operation_id}.jsonl",
            ):
                verification = verify_operation_event_log(path, operation_id=operation_id)
                self.assertTrue(verification["ok"], verification["errors"])
                self.assertEqual(verification["event_count"], 41)

    def test_cross_process_progress_updates_are_lossless_and_hash_chained(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            started = start_operation(root, operation_type="multiprocess", title="Cross-process progress")
            operation_id = started["operation_id"]
            code = (
                "from pathlib import Path; import sys; "
                "from continuum.core.operations import record_operation_progress; "
                "record_operation_progress(Path(sys.argv[1]), sys.argv[2], "
                "phase='parallel-process', message='progress-' + sys.argv[3], "
                "current=int(sys.argv[3]), total=8)"
            )
            environment = dict(os.environ)
            processes = [
                subprocess.Popen(
                    [sys.executable, "-c", code, str(root), operation_id, str(index)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=environment,
                )
                for index in range(8)
            ]
            failures: list[str] = []
            for process in processes:
                stdout, stderr = process.communicate(timeout=60)
                if process.returncode != 0:
                    failures.append(f"returncode={process.returncode} stdout={stdout!r} stderr={stderr!r}")
            self.assertEqual(failures, [])

            summary = operation_summary(root, operation_id)
            self.assertEqual(summary["progress_events"], 8)
            for path in (
                root / "run" / "operation_events" / f"{operation_id}.jsonl",
                root / "exports" / "operation_events" / f"{operation_id}.jsonl",
            ):
                verification = verify_operation_event_log(path, operation_id=operation_id)
                self.assertTrue(verification["ok"], verification["errors"])
                self.assertEqual(verification["event_count"], 9)

    def test_operation_ids_do_not_collide_in_bursts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"

            first = start_operation(root, operation_type="burst_test", title="Same title")
            second = start_operation(root, operation_type="burst_test", title="Same title")

            self.assertNotEqual(first["operation_id"], second["operation_id"])
            self.assertTrue(Path(first["run_receipt_uri"]).exists())
            self.assertTrue(Path(second["run_receipt_uri"]).exists())

    def test_operation_receipts_are_written_while_work_runs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"

            started = start_operation(
                root,
                operation_type="test_build",
                title="Back up while building",
                intent={"target": "unit-test"},
            )

            run_receipt = Path(started["run_receipt_uri"])
            export_receipt = Path(started["export_receipt_uri"])
            event_log = Path(started["operation_event_log_uri"])
            self.assertTrue(run_receipt.exists())
            self.assertTrue(export_receipt.exists())
            self.assertTrue(event_log.exists())
            self.assertEqual(json.loads(run_receipt.read_text(encoding="utf-8"))["status"], "running")

            record_operation_progress(root, started["operation_id"], phase="build", message="halfway", current=1, total=2)
            mid = operation_summary(root, started["operation_id"])
            self.assertEqual(mid["progress_events"], 1)
            self.assertEqual(mid["last_progress"]["message"], "halfway")

            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})
            done = operation_summary(root, started["operation_id"])
            self.assertEqual(done["status"], "succeeded")
            self.assertEqual(done["result"], {"ok": True})
            self.assertTrue(Path(done["operation_event_log_uri"]).exists())
            events = [json.loads(line) for line in event_log.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual([event["event_type"] for event in events], ["started", "progress", "succeeded"])
            self.assertIsNone(events[0]["previous_event_hash"])
            self.assertEqual(events[1]["previous_event_hash"], events[0]["event_hash"])
            self.assertEqual(events[2]["previous_event_hash"], events[1]["event_hash"])

            listed = list_operations(root)
            self.assertEqual(len(listed["operations"]), 1)
            self.assertEqual(listed["operations"][0]["operation_id"], started["operation_id"])
            self.assertTrue(Path(listed["operations"][0]["operation_event_log_uri"]).exists())
            self.assertEqual(listed["skipped_corrupt"], 0)

    def test_operation_event_log_verifier_rejects_tampered_hash_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            started = start_operation(root, operation_type="event_chain", title="Event chain")
            record_operation_progress(root, started["operation_id"], phase="work", message="middle")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})
            event_log = Path(started["operation_event_log_uri"])

            self.assertTrue(verify_operation_event_log(event_log, operation_id=started["operation_id"])["ok"])
            events = [json.loads(line) for line in event_log.read_text(encoding="utf-8").splitlines() if line.strip()]
            events[1]["previous_event_hash"] = "tampered"
            event_log.write_text("\n".join(json.dumps(event, ensure_ascii=True, sort_keys=True) for event in events) + "\n", encoding="utf-8")

            verification = verify_operation_event_log(event_log, operation_id=started["operation_id"])
            self.assertFalse(verification["ok"])
            serialized = json.dumps(verification["errors"], ensure_ascii=True)
            self.assertIn("previous_event_hash_mismatch", serialized)

    def test_operation_event_log_replay_reconstructs_status_and_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            started = start_operation(root, operation_type="event_replay", title="Event replay")
            record_operation_progress(root, started["operation_id"], phase="work", message="middle")
            update_operation_cursor(root, started["operation_id"], {"phase": "cursor"})
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})

            replayed = replay_operation_event_log(Path(started["operation_event_log_uri"]), operation_id=started["operation_id"])

            self.assertTrue(replayed["ok"], replayed)
            self.assertEqual(replayed["operation_id"], started["operation_id"])
            self.assertEqual(replayed["status"], "succeeded")
            self.assertEqual(replayed["progress_event_count"], 1)
            self.assertEqual(replayed["cursor"], {"phase": "cursor"})

    def test_operation_guard_writes_cursor_and_proof_pack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            source = Path(tmp) / "source.txt"
            source.write_text("guarded proof material", encoding="utf-8")

            with OperationGuard(
                root,
                operation_type="guarded_test",
                title="Guarded test operation",
                intent={"target": "unit-test"},
                actor="test",
                snapshot_policy="none",
                snapshot_reason="unit test append-only operation",
                touched_paths=[source],
            ) as operation:
                operation.cursor({"phase": "writing", "source": str(source)})
                result = {"ok": True}
                operation.succeed(result)
                wrapped = operation.wrap_result(result)

            self.assertTrue(wrapped["_operation"]["operation_id"].startswith("op_"))
            self.assertEqual(wrapped["_operation"]["status"], "succeeded")
            self.assertTrue(Path(wrapped["_operation"]["operation_receipt_uri"]).exists())
            self.assertTrue(Path(wrapped["_operation"]["proof_pack_uri"]).exists())
            summary = operation_summary(root, wrapped["_operation"]["operation_id"])
            self.assertEqual(summary["cursor"]["phase"], "writing")
            self.assertEqual(summary["status"], "succeeded")
            proof = json.loads(Path(summary["proof_pack_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(proof["status"], "succeeded")
            proof_uris = {str(item.get("uri") or item.get("path")).replace("\\", "/") for item in proof["paths"]}
            self.assertIn("run/operation_events/" + wrapped["_operation"]["operation_id"] + ".jsonl", proof_uris)
            self.assertIn("exports/operation_events/" + wrapped["_operation"]["operation_id"] + ".jsonl", proof_uris)
            external_substitutions = [
                item for item in proof["path_substitutions"] if item.get("kind") == "external_file_snapshot"
            ]
            self.assertEqual(len(external_substitutions), 1)
            self.assertEqual(external_substitutions[0]["source"]["uri_base"], "external_original")
            self.assertTrue(external_substitutions[0]["source"]["uri"].startswith("external:"))
            self.assertNotIn(str(source), json.dumps(external_substitutions[0], ensure_ascii=True))
            frozen_uri = external_substitutions[0]["frozen"]["uri"]
            self.assertTrue(any(item.get("sha256") for item in proof["paths"] if item.get("uri") == frozen_uri))
            for item in proof["paths"]:
                if item.get("kind") != "file" or not item.get("sha256"):
                    continue
                actual = hashlib.sha256(proof_item_path(root, item).read_bytes()).hexdigest()
                self.assertEqual(actual, item["sha256"], item["path"])

    def test_operation_receipts_and_proofs_redact_sensitive_metadata_keys_without_regex_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            started = start_operation(
                root,
                operation_type="secret_metadata_key",
                title="Sensitive metadata key",
                intent={"private_key": "raw private material", "token_budget": 1200},
            )
            finish_operation(
                root,
                started["operation_id"],
                status="succeeded",
                result={"client_secret": "short", "resume_token": "mempalace:abc"},
            )
            proof = create_proof_pack(root, started["operation_id"])

            run_receipt_text = (root / proof["run_receipt_uri"]).read_text(encoding="utf-8")
            export_receipt_text = (root / proof["export_receipt_uri"]).read_text(encoding="utf-8")
            proof_text = Path(proof["proof_pack_uri"]).read_text(encoding="utf-8")
            combined = "\n".join([run_receipt_text, export_receipt_text, proof_text])

            self.assertNotIn("raw private material", combined)
            self.assertNotIn('"client_secret": "short"', combined)
            self.assertIn("[REDACTED]", combined)
            self.assertIn("mempalace:abc", combined)
            self.assertIn("1200", combined)
            self.assertTrue(verify_proof_pack(Path(proof["proof_pack_uri"]))["ok"])

    def test_operation_progress_and_error_redact_sensitive_metadata_keys_without_regex_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            started = start_operation(root, operation_type="secret_progress_key", title="Secret progress key")
            record_operation_progress(
                root,
                started["operation_id"],
                phase="collect",
                message="progress metadata",
                detail={"client_secret": "ordinary progress secret", "token_budget": 2400},
            )
            finish_operation(
                root,
                started["operation_id"],
                status="failed",
                error={"private_key": "ordinary error secret", "resume_token": "mempalace:resume"},
            )
            proof = create_proof_pack(root, started["operation_id"])

            run_receipt_text = (root / proof["run_receipt_uri"]).read_text(encoding="utf-8")
            export_receipt_text = (root / proof["export_receipt_uri"]).read_text(encoding="utf-8")
            proof_text = Path(proof["proof_pack_uri"]).read_text(encoding="utf-8")
            combined = "\n".join([run_receipt_text, export_receipt_text, proof_text])

            self.assertNotIn("ordinary progress secret", combined)
            self.assertNotIn("ordinary error secret", combined)
            self.assertIn("[REDACTED]", combined)
            self.assertIn("mempalace:resume", combined)
            self.assertIn("2400", combined)
            self.assertTrue(verify_proof_pack(Path(proof["proof_pack_uri"]))["ok"])

    def test_proof_pack_describes_final_receipt_hashes_without_circular_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            started = start_operation(root, operation_type="proof_hash_test", title="Proof hash test")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})

            proof = create_proof_pack(root, started["operation_id"])

            for item in proof["paths"]:
                item_path = proof_item_path(root, item)
                if item_path not in {Path(proof["run_receipt_uri"]), Path(proof["export_receipt_uri"])}:
                    continue
                actual = hashlib.sha256(item_path.read_bytes()).hexdigest()
                self.assertEqual(actual, item["sha256"])
            summary = operation_summary(root, started["operation_id"])
            self.assertEqual(summary["proof_pack_uri"], proof["proof_pack_uri"])
            self.assertIsNone(summary["proof_pack_hash"])

            verification = verify_proof_pack(Path(proof["proof_pack_uri"]))
            self.assertTrue(verification["ok"])
            self.assertEqual(verification["operation_id"], started["operation_id"])

    def test_proof_pack_retention_keeps_ledgered_artifacts_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            started = start_operation(root, operation_type="retention_ledger", title="Retention ledger")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})
            proof = create_proof_pack(root, started["operation_id"])
            proof_path = Path(proof["proof_pack_uri"])
            old = 946684800
            os.utime(proof_path, (old, old))

            retention = enforce_proof_pack_retention(root)
            verification = verify_root(root, strict=True, verify_recent_proof_packs=10, run_restore_drill=False, scan_secrets=False)

            self.assertEqual(retention["deleted"], 0)
            self.assertEqual(retention["kept_ledgered"], 1)
            self.assertTrue(proof_path.exists())
            self.assertTrue(verification["ok"], verification)

    def test_published_proof_makes_public_operation_ledger_writers_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            started = start_operation(root, operation_type="proof_immutable", title="Proof immutability")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})
            proof = create_proof_pack(root, started["operation_id"])

            receipt = read_operation(root, started["operation_id"])
            receipt["title"] = "mutated after proof"
            with self.assertRaisesRegex(ValueError, "proof pack already exists"):
                write_operation(root, receipt)
            with self.assertRaisesRegex(ValueError, "proof pack already exists"):
                append_operation_event(
                    root,
                    started["operation_id"],
                    event_type="late_mutation",
                    payload={"unexpected": True},
                )

            verification = verify_proof_pack(Path(proof["proof_pack_uri"]), root=root)
            self.assertTrue(verification["ok"], verification["errors"])

    def test_proof_pack_explicit_snapshot_freezes_live_catalog_and_records_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(root, session_id="proof-freeze", event_type="message", role="user", content="freeze db")
            live_catalog = root / "catalog" / "catalog.sqlite3"
            started = start_operation(root, operation_type="freeze_test", title="Freeze live DB")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})

            proof = create_proof_pack(
                root,
                started["operation_id"],
                touched_paths=[live_catalog],
                catalog_proof_mode="snapshot",
            )

            proof_paths = {item.get("uri") or item["path"] for item in proof["paths"]}
            self.assertNotIn(str(live_catalog), proof_paths)
            frozen_paths = [
                proof_item_path(root, item)
                for item in proof["paths"]
                if str(item.get("uri") or item["path"]).endswith("catalog.snapshot.sqlite3")
            ]
            self.assertEqual(len(frozen_paths), 1)
            self.assertTrue(frozen_paths[0].exists())
            self.assertTrue(proof["path_substitutions"])
            self.assertTrue(verify_proof_pack(Path(proof["proof_pack_uri"]))["ok"])

            conn = connect_existing(root)
            try:
                artifact_kinds = {row["kind"] for row in conn.execute("SELECT kind FROM artifacts")}
            finally:
                conn.close()
            self.assertIn("proof_pack", artifact_kinds)
            self.assertIn("proof_input", artifact_kinds)

            proof_path = Path(proof["proof_pack_uri"])
            legacy = json.loads(proof_path.read_text(encoding="utf-8"))
            legacy.pop("catalog_proof_mode")
            legacy["proof_pack_hash"] = _proof_pack_hash(legacy)
            proof_path.write_text(json.dumps(legacy, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            ledger = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            try:
                ledger.execute(
                    "UPDATE artifacts SET sha256 = ?, size_bytes = ? WHERE kind = 'proof_pack' AND operation_id = ?",
                    (hashlib.sha256(proof_path.read_bytes()).hexdigest(), proof_path.stat().st_size, started["operation_id"]),
                )
                ledger.commit()
            finally:
                ledger.close()
            legacy_verification = verify_proof_pack(proof_path, root=root)
            self.assertTrue(legacy_verification["ok"], legacy_verification["errors"])

    def test_proof_pack_freezes_mutable_catalog_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(root, session_id="sidecar-proof", event_type="message", role="user", content="freeze sidecar")
            segment = roll_scroll_segment(root, session_id="sidecar-proof", start_seq=1, end_seq=1)
            sidecar = Path(segment["card_uri"])
            started = start_operation(root, operation_type="sidecar_freeze", title="Freeze mutable sidecar")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})

            proof = create_proof_pack(root, started["operation_id"], touched_paths=[sidecar])
            sidecar.write_text(sidecar.read_text(encoding="utf-8") + "# later mutation\n", encoding="utf-8")

            substitutions = [
                item
                for item in proof["path_substitutions"]
                if item.get("kind") == "mutable_internal_file_snapshot"
            ]
            self.assertEqual(len(substitutions), 1)
            frozen_uri = substitutions[0]["frozen"]["uri"]
            self.assertTrue((root / frozen_uri).exists())
            verification = verify_proof_pack(Path(proof["proof_pack_uri"]), root=root)
            self.assertTrue(verification["ok"], verification["errors"])
            conn = connect_existing(root)
            try:
                live_sidecar_artifacts = conn.execute(
                    "SELECT count(*) AS n FROM artifacts WHERE immutable = 1 AND uri = ?",
                    (root_uri(root, sidecar),),
                ).fetchone()["n"]
            finally:
                conn.close()
            self.assertEqual(live_sidecar_artifacts, 0)

    def test_relocated_catalog_proof_verifies_through_root_bound_archive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "epic-continuum"
            archive = base / "external-proof-archive"
            append_scroll_event(root, session_id="relocated-proof", event_type="message", role="user", content="proof")
            live_catalog = root / "catalog" / "catalog.sqlite3"
            ordinary_evidence = root / "archive" / "ordinary-evidence.txt"
            ordinary_evidence.parent.mkdir(parents=True, exist_ok=True)
            secure_write_text(ordinary_evidence, "root-bound evidence\n")
            started = start_operation(root, operation_type="relocated_proof", title="Relocated proof")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})
            proof = create_proof_pack(
                root,
                started["operation_id"],
                touched_paths=[live_catalog, ordinary_evidence],
                catalog_proof_mode="snapshot",
            )
            proof_path = Path(proof["proof_pack_uri"])
            catalog_item = next(
                item
                for item in proof["paths"]
                if str(item.get("uri") or item.get("path")).endswith("catalog.snapshot.sqlite3")
            )
            original_catalog_proof = proof_item_path(root, catalog_item)

            archived = apply_legacy_catalog_archive(root, archive)
            self.assertTrue(archived["ok"], archived)
            self.assertFalse(original_catalog_proof.exists())

            verification = verify_proof_pack(proof_path, root=root, allowed_roots=[root])
            self.assertTrue(verification["ok"], verification["errors"])
            relocated_checks = [
                check for check in verification["checks"] if check.get("storage") == "external_proof_archive"
            ]
            self.assertEqual(len(relocated_checks), 1)
            self.assertEqual(relocated_checks[0]["path"], str(original_catalog_proof))
            self.assertTrue(
                Path(relocated_checks[0]["resolved_path"]).resolve().is_relative_to(archive.resolve())
            )

            health = doctor(root)
            self.assertTrue(health["ok"], health["checks"])
            artifact_check = next(
                check for check in health["checks"] if check["name"] == "artifact_ledger_portable_and_hashes_match"
            )
            self.assertGreaterEqual(artifact_check["relocated"], 1)
            self.assertTrue(artifact_check["proof_archive"]["ok"])

            ordinary_evidence.unlink()
            missing_unrelated = verify_proof_pack(proof_path, root=root, allowed_roots=[root])
            self.assertFalse(missing_unrelated["ok"])
            ordinary_path_check = next(
                check for check in missing_unrelated["checks"] if check.get("path") == str(ordinary_evidence)
            )
            self.assertNotIn("storage", ordinary_path_check)

    def test_relocated_catalog_proof_and_doctor_fail_closed_on_archive_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "epic-continuum"
            archive = base / "external-proof-archive"
            append_scroll_event(root, session_id="tampered-relocation", event_type="message", role="user", content="proof")
            started = start_operation(root, operation_type="tampered_relocation", title="Tampered relocation")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})
            proof = create_proof_pack(
                root,
                started["operation_id"],
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
                catalog_proof_mode="snapshot",
            )
            proof_path = Path(proof["proof_pack_uri"])
            archived = apply_legacy_catalog_archive(root, archive)
            self.assertTrue(archived["ok"])
            object_path = archive.joinpath(*archived["results"][0]["archive_uri"].split("/"))
            object_bytes = object_path.read_bytes()
            object_path.write_bytes(bytes([object_bytes[0] ^ 1]) + object_bytes[1:])

            object_tamper = verify_proof_pack(proof_path, root=root)
            self.assertFalse(object_tamper["ok"])
            self.assertTrue(
                any(
                    "RelocatedArtifactIntegrityError" in str(error.get("relocation_error"))
                    for error in object_tamper["errors"]
                ),
                object_tamper["errors"],
            )
            object_path.write_bytes(object_bytes)
            self.assertTrue(verify_proof_pack(proof_path, root=root)["ok"])

            ledger_path = archive / "relocations.jsonl"
            record = json.loads(ledger_path.read_text(encoding="utf-8"))
            record["size_bytes"] += 1
            ledger_path.write_text(
                json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

            verification = verify_proof_pack(proof_path, root=root)
            self.assertFalse(verification["ok"])
            self.assertTrue(
                any("RelocationLedgerError" in str(error.get("relocation_error")) for error in verification["errors"]),
                verification["errors"],
            )
            health = doctor(root)
            self.assertFalse(health["ok"])
            artifact_check = next(
                check for check in health["checks"] if check["name"] == "artifact_ledger_portable_and_hashes_match"
            )
            self.assertFalse(artifact_check["proof_archive"]["ok"])

    def test_proof_pack_defaults_to_bounded_catalog_state_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(root, session_id="proof-state", event_type="message", role="user", content="state db")
            live_catalog = root / "catalog" / "catalog.sqlite3"
            started = start_operation(root, operation_type="state_test", title="Witness live DB")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})

            proof = create_proof_pack(root, started["operation_id"], touched_paths=[live_catalog])

            self.assertEqual(proof["catalog_proof_mode"], "state_manifest")
            substitutions = [
                item for item in proof["path_substitutions"] if item.get("kind") == "sqlite_state_manifest"
            ]
            self.assertEqual(len(substitutions), 1)
            state_path = root / substitutions[0]["frozen"]["uri"]
            self.assertTrue(state_path.exists())
            self.assertFalse((state_path.parent / "catalog.snapshot.sqlite3").exists())
            state = json.loads(state_path.read_text(encoding="utf-8"))
            self.assertEqual(state["schema"], "epic_continuum.catalog_state.v1")
            self.assertEqual(state["operation_id"], started["operation_id"])
            self.assertEqual(state["source"]["uri"], "catalog/catalog.sqlite3")
            self.assertEqual(state["assurance"], "non_restorable_catalog_state_telemetry")
            self.assertFalse(state["restorable"])
            self.assertFalse(state["content_binding"]["catalog_bytes_bound"])
            self.assertNotIn("row_count", state["table_state"]["artifacts"])
            self.assertTrue(state["state_hash"])
            verification = verify_proof_pack(Path(proof["proof_pack_uri"]), root=root)
            self.assertTrue(verification["ok"], verification["errors"])

            state["table_state"]["artifacts"]["rowid_high_water"] += 1
            state_path.write_text(json.dumps(state, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            tampered = verify_proof_pack(Path(proof["proof_pack_uri"]), root=root)
            self.assertFalse(tampered["ok"])
            self.assertTrue(any(error.get("check") == "catalog_state_manifest_0_semantic" for error in tampered["errors"]))

    def test_repeated_catalog_proofs_do_not_copy_catalog_per_operation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            live_catalog = root / "catalog" / "catalog.sqlite3"
            for index in range(20):
                with OperationGuard(
                    root,
                    operation_type="bounded_catalog_proof",
                    title=f"Bounded catalog proof {index}",
                    touched_paths=[live_catalog],
                ) as operation:
                    append_scroll_event(
                        root,
                        session_id="bounded-proof",
                        event_type="message",
                        role="user",
                        content=f"bounded proof event {index}",
                    )
                    operation.succeed({"ok": True, "index": index})

            proof_artifacts = root / "exports" / "proof_artifacts"
            state_manifests = list(proof_artifacts.rglob("catalog.state.json"))
            catalog_copies = list(proof_artifacts.rglob("catalog.snapshot.sqlite3"))
            self.assertEqual(len(state_manifests), 20)
            self.assertEqual(catalog_copies, [])
            self.assertLess(sum(path.stat().st_size for path in state_manifests), 1024 * 1024)

    def test_cli_high_risk_catalog_commands_force_snapshot_proofs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            commands = (
                ["prune-memory", "--root", str(root), "--all"],
                ["redact-legacy-secrets", "--root", str(root), "--apply", "--limit", "1"],
            )
            for command in commands:
                with self.subTest(command=command[0]):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        exit_code = cli_main(command)
                    self.assertEqual(exit_code, 0, output.getvalue())
                    result = json.loads(output.getvalue())
                    proof = json.loads(Path(result["_operation"]["proof_pack_uri"]).read_text(encoding="utf-8"))
                    self.assertEqual(proof["catalog_proof_mode"], "snapshot")
                    self.assertIn("sqlite_backup", [item.get("kind") for item in proof["path_substitutions"]])

    def test_doctor_reports_healthy_initialized_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            started = start_operation(root, operation_type="doctor_test", title="Doctor test")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})
            create_proof_pack(root, started["operation_id"])

            result = doctor(root)

            self.assertTrue(result["ok"])
            self.assertGreater(result["check_count"], 0)
            self.assertGreaterEqual(len(result["verified_proof_packs"]), 1)

    def test_verify_root_strict_suite_can_skip_restore_drill_for_fast_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)

            result = verify_root(root, strict=True, run_restore_drill=False, verify_recent_proof_packs=0)

            self.assertTrue(result["ok"], result["checks"])
            self.assertIn("doctor", result["sections"])
            self.assertIn("secret_audit", result["sections"])
            self.assertFalse(result["run_restore_drill"])

    def test_verify_root_can_skip_secret_scan_without_touching_secret_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            secure_write_text(root / "api_key=supersecretvalue123.txt", "api_key=supersecretvalue123\n")

            result = verify_root(
                root,
                strict=True,
                run_restore_drill=False,
                verify_recent_proof_packs=0,
                scan_secrets=False,
            )

            self.assertTrue(result["ok"], result["checks"])
            self.assertTrue(result["sections"]["secret_audit"]["skipped"])
            self.assertTrue(any(check["name"] == "secret_audit_skipped" for check in result["checks"]))

    def test_secret_audit_treats_large_sqlite_as_structurally_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)

            result = audit_secrets(root, max_file_bytes=100_000)

            self.assertTrue(result["ok"], result)
            self.assertTrue(result["complete"], result)
            sqlite_skips = [
                item
                for item in result["skipped"]
                if item.get("reason") == "sqlite_raw_bytes_skipped_after_structured_scan"
            ]
            self.assertTrue(sqlite_skips)

    def test_recover_stale_operations_marks_interrupted_and_writes_packet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            started = start_operation(root, operation_type="stale_test", title="Stale test")
            record_operation_progress(root, started["operation_id"], phase="work", message="half complete")
            update_operation_cursor(root, started["operation_id"], {"phase": "work", "step": 1})

            recovered = recover_stale_operations(root, older_than_seconds=-1)

            self.assertEqual(len(recovered["recovered"]), 1)
            item = recovered["recovered"][0]
            self.assertEqual(item["status"], "interrupted")
            self.assertTrue(Path(item["recovery_packet_uri"]).exists())
            self.assertTrue(Path(item["recovery_packet_json_uri"]).exists())
            self.assertTrue(Path(item["proof_pack_uri"]).exists())
            summary = operation_summary(root, started["operation_id"])
            self.assertEqual(summary["status"], "interrupted")
            self.assertEqual(summary["cursor"]["step"], 1)
            machine_packet = json.loads(Path(summary["recovery_packet_json_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(machine_packet["operation_id"], started["operation_id"])
            self.assertEqual(machine_packet["cursor"]["step"], 1)
            verification = verify_proof_pack(Path(item["proof_pack_uri"]))
            self.assertTrue(verification["ok"], verification["errors"])
            proof = json.loads(Path(item["proof_pack_uri"]).read_text(encoding="utf-8"))
            proof_paths = {entry.get("uri") or entry["path"] for entry in proof["paths"]}
            self.assertIn(root_uri(root, summary["recovery_packet_uri"]), proof_paths)
            self.assertIn(root_uri(root, summary["recovery_packet_json_uri"]), proof_paths)
            run_receipt_before = Path(summary["run_receipt_uri"]).read_bytes()
            self.assertTrue(verify_proof_pack(Path(item["proof_pack_uri"]))["ok"])
            self.assertEqual(run_receipt_before, Path(summary["run_receipt_uri"]).read_bytes())

    def test_proof_pack_uses_root_relative_paths_for_internal_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            started = start_operation(root, operation_type="portable_paths", title="Portable paths")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})

            proof = create_proof_pack(root, started["operation_id"])

            self.assertFalse(Path(proof["run_receipt_uri"]).is_absolute())
            self.assertFalse(Path(proof["export_receipt_uri"]).is_absolute())
            internal_uris = {proof["run_receipt_uri"].replace("\\", "/"), proof["export_receipt_uri"].replace("\\", "/")}
            internal_items = [item for item in proof["paths"] if item.get("uri") in internal_uris]
            self.assertEqual(len(internal_items), 2)
            for item in internal_items:
                self.assertEqual(item["uri_base"], "continuum_root")
                self.assertFalse(Path(item["path"]).is_absolute())
            stored_receipt = json.loads((root / proof["run_receipt_uri"]).read_text(encoding="utf-8"))
            self.assertFalse(Path(stored_receipt["run_receipt_uri"]).is_absolute())
            self.assertFalse(Path(stored_receipt["export_receipt_uri"]).is_absolute())
            self.assertFalse(Path(stored_receipt["proof_pack_uri"]).is_absolute())
            stored_proof = json.loads(Path(proof["proof_pack_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(stored_proof["root"], "continuum_root")
            self.assertFalse(Path(stored_proof["proof_pack_uri"]).is_absolute())

    def test_cli_verify_proof_pack_infers_root_without_root_argument(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            started = start_operation(root, operation_type="cli_verify", title="CLI verify")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})
            proof = create_proof_pack(root, started["operation_id"])

            output = io.StringIO()
            with redirect_stdout(output):
                exit_code = cli_main(["verify-proof-pack", str(root / proof["proof_pack_uri"])])

            self.assertEqual(exit_code, 0)
            payload = json.loads(output.getvalue())
            self.assertTrue(payload["ok"], payload["errors"])
            self.assertTrue(payload["verification_root_inferred"])

    def test_strict_proof_verifier_rejects_fake_empty_and_malformed_proofs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            claim_writer(root)
            fake = root / "exports" / "proof_packs" / "fake.json"
            fake.parent.mkdir(parents=True)
            fake.write_text(
                json.dumps({"schema": "epic_continuum.proof_pack.v1", "operation_id": "fake", "paths": []}),
                encoding="utf-8",
            )

            result = verify_proof_pack(fake, root=root)

            self.assertFalse(result["ok"], result)
            self.assertIn("proof_pack_hash_present", {item["check"] for item in result["errors"]})
            self.assertIn("paths_present", {item["check"] for item in result["errors"]})

            evidence = root / "evidence.txt"
            evidence.write_text("hash shape proof", encoding="utf-8")
            malformed = {
                "schema": "epic_continuum.proof_pack.v1",
                "operation_id": "fake2",
                "paths": [
                    {
                        "path": "evidence.txt",
                        "uri": "evidence.txt",
                        "uri_base": "continuum_root",
                        "exists": True,
                        "kind": "file",
                    }
                ],
            }
            malformed["proof_pack_hash"] = _proof_pack_hash(malformed)
            malformed_path = fake.parent / "fake2.json"
            malformed_path.write_text(json.dumps(malformed, ensure_ascii=True, indent=2), encoding="utf-8")

            malformed_result = verify_proof_pack(malformed_path, root=root)

            self.assertFalse(malformed_result["ok"], malformed_result)
            self.assertIn("file_entry_hash_shape", {item["check"] for item in malformed_result["errors"]})

            syntactic = {
                "schema": "epic_continuum.proof_pack.v1",
                "operation_id": "fake3",
                "operation_type": "fake",
                "title": "Self-consistent fake",
                "status": "succeeded",
                "operation_receipt_hash": "0" * 64,
                "run_receipt_uri": "run/operations/fake3.json",
                "export_receipt_uri": "exports/operation_receipts/fake3.json",
                "paths": [
                    {
                        "path": "run/operations/fake3.json",
                        "uri": "run/operations/fake3.json",
                        "uri_base": "continuum_root",
                        "exists": False,
                        "kind": "missing",
                    },
                    {
                        "path": "exports/operation_receipts/fake3.json",
                        "uri": "exports/operation_receipts/fake3.json",
                        "uri_base": "continuum_root",
                        "exists": False,
                        "kind": "missing",
                    },
                ],
            }
            syntactic["proof_pack_hash"] = _proof_pack_hash(syntactic)
            syntactic_path = fake.parent / "fake3.json"
            syntactic_path.write_text(json.dumps(syntactic, ensure_ascii=True, indent=2), encoding="utf-8")

            syntactic_result = verify_proof_pack(syntactic_path, root=root)

            self.assertFalse(syntactic_result["ok"], syntactic_result)
            self.assertIn("run_receipt_loads", {item["check"] for item in syntactic_result["errors"]})

            init_db(root)
            forged_operation_id = "fake4"
            forged_paths = {
                "run": root / "run" / "operations" / f"{forged_operation_id}.json",
                "export": root / "exports" / "operation_receipts" / f"{forged_operation_id}.json",
            }
            forged_proof_path = fake.parent / "fake4.json"
            forged_receipt = {
                "schema": "epic_continuum.operation_receipt.v1",
                "operation_id": forged_operation_id,
                "operation_type": "forged",
                "title": "Forged matching receipts",
                "actor": "test",
                "status": "succeeded",
                "principle": "No one said we could not back it up while building it.",
                "intent": {},
                "cursor": None,
                "preflight_snapshots": [],
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-01T00:00:00+00:00",
                "finished_at": "2026-01-01T00:00:00+00:00",
                "progress": [],
                "result": {"ok": True},
                "error": None,
                "run_receipt_uri": f"run/operations/{forged_operation_id}.json",
                "export_receipt_uri": f"exports/operation_receipts/{forged_operation_id}.json",
                "proof_pack_uri": "exports/proof_packs/fake4.json",
            }
            forged_receipt["receipt_hash"] = _stable_json_hash(forged_receipt)
            for forged_receipt_path in forged_paths.values():
                forged_receipt_path.parent.mkdir(parents=True, exist_ok=True)
                forged_receipt_path.write_text(json.dumps(forged_receipt, ensure_ascii=True, indent=2), encoding="utf-8")
            forged_proof = {
                "schema": "epic_continuum.proof_pack.v1",
                "operation_id": forged_operation_id,
                "operation_type": "forged",
                "title": "Forged matching receipts",
                "status": "succeeded",
                "root": "continuum_root",
                "operation_receipt_hash": forged_receipt["receipt_hash"],
                "run_receipt_uri": forged_receipt["run_receipt_uri"],
                "export_receipt_uri": forged_receipt["export_receipt_uri"],
                "intent": {},
                "cursor": None,
                "result": {"ok": True},
                "error": None,
                "paths": [
                    describe
                    for describe in (
                        {
                            "path": f"run/operations/{forged_operation_id}.json",
                            "uri": f"run/operations/{forged_operation_id}.json",
                            "uri_base": "continuum_root",
                            "exists": True,
                            "kind": "file",
                            "size_bytes": forged_paths["run"].stat().st_size,
                            "sha256": hashlib.sha256(forged_paths["run"].read_bytes()).hexdigest(),
                        },
                        {
                            "path": f"exports/operation_receipts/{forged_operation_id}.json",
                            "uri": f"exports/operation_receipts/{forged_operation_id}.json",
                            "uri_base": "continuum_root",
                            "exists": True,
                            "kind": "file",
                            "size_bytes": forged_paths["export"].stat().st_size,
                            "sha256": hashlib.sha256(forged_paths["export"].read_bytes()).hexdigest(),
                        },
                    )
                ],
            }
            forged_proof["proof_pack_uri"] = "exports/proof_packs/fake4.json"
            forged_proof["proof_pack_hash"] = _proof_pack_hash(forged_proof)
            forged_proof_path.write_text(json.dumps(forged_proof, ensure_ascii=True, indent=2), encoding="utf-8")

            forged_result = verify_proof_pack(forged_proof_path, root=root)

            self.assertFalse(forged_result["ok"], forged_result)
            self.assertIn("artifact_ledger_proof_pack_bound", {item["check"] for item in forged_result["errors"]})

            started = start_operation(root, operation_type="proof_tamper", title="Proof tamper")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})
            real_proof = create_proof_pack(root, started["operation_id"])
            real_proof_path = Path(real_proof["proof_pack_uri"])
            tampered = json.loads(real_proof_path.read_text(encoding="utf-8"))
            tampered["operation_receipt_hash"] = "f" * 64
            tampered["proof_pack_hash"] = _proof_pack_hash(tampered)
            real_proof_path.write_text(json.dumps(tampered, ensure_ascii=True, indent=2), encoding="utf-8")

            tampered_result = verify_proof_pack(real_proof_path, root=root)

            self.assertFalse(tampered_result["ok"], tampered_result)
            self.assertIn("operation_receipt_hash_matches_receipt", {item["check"] for item in tampered_result["errors"]})

    def test_doctor_rejects_recent_syntactic_fake_proof_pack(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            proof_dir = root / "exports" / "proof_packs"
            proof_dir.mkdir(parents=True)
            fake = {
                "schema": "epic_continuum.proof_pack.v1",
                "operation_id": "fake_doctor",
                "operation_receipt_hash": "0" * 64,
                "paths": [
                    {
                        "path": "run/operations/fake_doctor.json",
                        "uri": "run/operations/fake_doctor.json",
                        "uri_base": "continuum_root",
                        "exists": False,
                        "kind": "missing",
                    }
                ],
            }
            fake["proof_pack_hash"] = _proof_pack_hash(fake)
            fake_path = proof_dir / "fake_doctor.json"
            fake_path.write_text(json.dumps(fake, ensure_ascii=True, indent=2), encoding="utf-8")

            result = doctor(root, verify_recent_proof_packs=1)

            self.assertFalse(result["ok"], result["checks"])
            proof_check = [check for check in result["checks"] if check["name"] == "verify_proof_pack"][0]
            self.assertFalse(proof_check["ok"])

    def test_directory_proof_uses_frozen_manifest_that_survives_later_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            claim_writer(root)
            evidence_dir = root / "archive" / "evidence"
            evidence_dir.mkdir(parents=True)
            nested = evidence_dir / "nested" / "item.txt"
            nested.parent.mkdir()
            nested.write_text("recursive proof evidence", encoding="utf-8")
            started = start_operation(root, operation_type="directory_hash", title="Directory hash")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})

            proof = create_proof_pack(root, started["operation_id"], touched_paths=[evidence_dir])

            substitutions = [
                item for item in proof["path_substitutions"] if item.get("kind") == "directory_manifest_snapshot"
            ]
            self.assertEqual(len(substitutions), 1)
            self.assertEqual(substitutions[0]["source"]["uri"], root_uri(root, evidence_dir))
            manifest_item = [
                item for item in proof["paths"] if item.get("uri") == substitutions[0]["frozen"]["uri"]
            ][0]
            self.assertEqual(manifest_item["uri_base"], "continuum_root")
            manifest = json.loads(proof_item_path(root, manifest_item).read_text(encoding="utf-8"))
            self.assertTrue(manifest["tree"]["tree_sha256"])
            self.assertIn("nested/item.txt", {entry["path"] for entry in manifest["tree"]["entries"]})
            self.assertTrue(verify_proof_pack(Path(proof["proof_pack_uri"]), root=root)["ok"])

            nested.write_text("changed recursive proof evidence", encoding="utf-8")
            verification = verify_proof_pack(Path(proof["proof_pack_uri"]), root=root)
            self.assertTrue(verification["ok"], verification)

    def test_init_proof_survives_later_config_update(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            started = start_operation(root, operation_type="init_proof", title="Init proof")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})
            proof = create_proof_pack(root, started["operation_id"])

            config = load_config(root)
            config["context"]["default_token_budget"] = 32123
            write_config(root, config)

            verification = verify_proof_pack(Path(proof["proof_pack_uri"]), root=root)
            self.assertTrue(verification["ok"], verification["errors"])
            substitutions = [item["kind"] for item in proof["path_substitutions"]]
            self.assertIn("config_snapshot", substitutions)

    def test_ingest_proof_survives_source_delete_and_second_ingest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "epic-continuum"
            first_source = tmp_path / "first-source.txt"
            second_source = tmp_path / "second-source.txt"
            first_source.write_text("First external source should not be a live proof dependency.", encoding="utf-8")
            second_source.write_text("Second ingest mutates the catalog after the first proof.", encoding="utf-8")

            with OperationGuard(
                root,
                operation_type="ingest_regression",
                title="First guarded ingest",
                touched_paths=[root / "catalog" / "catalog.sqlite3", first_source],
            ) as operation:
                first = ingest_file(root, path=first_source, title="First Source")
                operation.succeed(
                    first,
                    touched_paths=[path for path in [first["card_uri"], first["original_uri"], first["reader_uri"]] if path],
                )
                first_proof = Path(operation.wrap_result(first)["_operation"]["proof_pack_uri"])

            first_source.unlink()
            with OperationGuard(
                root,
                operation_type="ingest_regression",
                title="Second guarded ingest",
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
            ) as operation:
                second = ingest_file(root, path=second_source, title="Second Source")
                operation.succeed(
                    second,
                    touched_paths=[path for path in [second["card_uri"], second["original_uri"], second["reader_uri"]] if path],
                )

            verification = verify_proof_pack(first_proof, root=root)
            self.assertTrue(verification["ok"], verification["errors"])
            proof = json.loads(first_proof.read_text(encoding="utf-8"))
            self.assertIn("external_file_snapshot", [item["kind"] for item in proof["path_substitutions"]])
            conn = connect_existing(root)
            try:
                artifact_uris = [row["uri"] for row in conn.execute("SELECT uri FROM artifacts")]
            finally:
                conn.close()
            self.assertTrue(artifact_uris)
            self.assertFalse(any(Path(uri).is_absolute() and str(root) in uri for uri in artifact_uris))
            health = doctor(root, verify_recent_proof_packs=10)
            self.assertTrue(health["ok"], health["checks"])

    def test_roll_and_snapshot_proofs_survive_later_rolls_and_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            for index in range(1, 5):
                append_scroll_event(
                    root,
                    session_id="proof-rot",
                    event_type="message",
                    role="user",
                    content=f"Proof rot regression event {index}",
                )

            with OperationGuard(
                root,
                operation_type="roll_regression",
                title="First roll",
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
            ) as operation:
                first_roll = roll_scroll_segment(root, session_id="proof-rot", start_seq=1, end_seq=2)
                operation.succeed(first_roll, touched_paths=[first_roll["card_uri"]] if first_roll["card_uri"] else [])
                roll_proof = Path(operation.wrap_result(first_roll)["_operation"]["proof_pack_uri"])

            with OperationGuard(
                root,
                operation_type="snapshot_regression",
                title="First snapshot",
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
            ) as operation:
                first_snapshot = snapshot(root, reason="proof_rot_first_snapshot")
                operation.succeed(
                    first_snapshot,
                    touched_paths=[first_snapshot["snapshot_uri"], first_snapshot["card_sidecars_uri"]],
                )
                snapshot_proof = Path(operation.wrap_result(first_snapshot)["_operation"]["proof_pack_uri"])

            roll_scroll_segment(root, session_id="proof-rot", start_seq=3, end_seq=4)
            snapshot(root, reason="proof_rot_later_snapshot")

            roll_verification = verify_proof_pack(roll_proof, root=root)
            snapshot_verification = verify_proof_pack(snapshot_proof, root=root)
            self.assertTrue(roll_verification["ok"], roll_verification["errors"])
            self.assertTrue(snapshot_verification["ok"], snapshot_verification["errors"])

    def test_copied_root_proof_verifies_after_original_root_is_deleted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "epic-continuum"
            append_scroll_event(root, session_id="portable", event_type="message", role="user", content="copy me")
            started = start_operation(root, operation_type="copy_portable", title="Copy portable")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})
            proof = create_proof_pack(root, started["operation_id"])
            proof_rel = Path(proof["proof_pack_uri"]).relative_to(root)
            copied_root = tmp_path / "epic-continuum-copy"

            shutil.copytree(root, copied_root)
            shutil.rmtree(root)

            copied_proof = copied_root / proof_rel
            verification = verify_proof_pack(copied_proof)
            self.assertTrue(verification["ok"], verification["errors"])
            self.assertTrue(verification["verification_root_inferred"])
            copied_summary = operation_summary(copied_root, started["operation_id"])
            self.assertTrue(str(copied_summary["run_receipt_uri"]).startswith(str(copied_root)))
            self.assertTrue(str(copied_summary["export_receipt_uri"]).startswith(str(copied_root)))
            self.assertTrue(str(copied_summary["proof_pack_uri"]).startswith(str(copied_root)))
            self.assertNotEqual(Path(copied_summary["run_receipt_uri"]), root / Path(copied_summary["run_receipt_uri"]).relative_to(copied_root))
            health = doctor(copied_root, verify_recent_proof_packs=1)
            self.assertTrue(health["ok"], health["checks"])

    def test_operation_guard_redacts_secret_metadata_even_when_inner_action_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"

            with self.assertRaisesRegex(ValueError, "secret scan blocked session_id before partition lookup"):
                with OperationGuard(
                    root,
                    operation_type="secret_guard_test",
                    title="Append api_key=supersecretvalue123",
                    intent={"session_id": "api_key=supersecretvalue123"},
                    actor="test",
                ) as operation:
                    append_scroll_event(
                        root,
                        session_id="api_key=supersecretvalue123",
                        event_type="message",
                        role="user",
                        content="safe content",
                    )
                    operation.succeed({"ok": True})

            self.assertTrue(audit_secrets(root)["ok"])
            raw_hits = [
                path.relative_to(root).as_posix()
                for path in root.rglob("*")
                if path.is_file() and b"supersecretvalue123" in path.read_bytes()
            ]
            self.assertEqual(raw_hits, [])
            proof_path = next((root / "exports" / "proof_packs").glob("*.json"))
            verification = verify_proof_pack(proof_path, root=root)
            self.assertTrue(verification["ok"], verification["errors"])

    def test_recover_stale_operations_dry_run_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            started = start_operation(root, operation_type="dry_run_stale", title="Dry run stale")
            before_paths = sorted(str(path.relative_to(root)) for path in root.rglob("*"))

            recovered = recover_stale_operations(root, older_than_seconds=-1, mark=False)

            after_paths = sorted(str(path.relative_to(root)) for path in root.rglob("*"))
            self.assertEqual(before_paths, after_paths)
            self.assertEqual(recovered["recovered"][0]["status"], "running")
            self.assertTrue(recovered["recovered"][0]["would_recover"])
            self.assertIsNone(recovered["recovered"][0]["recovery_packet_uri"])
            self.assertEqual(operation_summary(root, started["operation_id"])["status"], "running")

    def test_cancelled_status_is_not_exposed_without_cancel_operation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            started = start_operation(root, operation_type="status_test", title="Status test")

            with self.assertRaisesRegex(ValueError, "status must be succeeded, failed, or interrupted"):
                finish_operation(root, started["operation_id"], status="cancelled")

            summary = operation_summary(root, started["operation_id"])
            self.assertEqual(summary["status"], "running")

    def test_read_operation_rejects_hash_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            started = start_operation(root, operation_type="hash_test", title="Hash test")
            run_receipt = Path(started["run_receipt_uri"])
            payload = json.loads(run_receipt.read_text(encoding="utf-8"))
            payload["title"] = "Tampered title"
            run_receipt.write_text(json.dumps(payload, ensure_ascii=True, indent=2), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "receipt hash mismatch"):
                operation_summary(root, started["operation_id"])

            listed = list_operations(root)
            self.assertEqual(listed["operations"], [])
            self.assertEqual(listed["skipped_corrupt"], 1)

    def test_operations_are_ordered_by_receipt_updated_at_not_file_mtime(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            older = start_operation(root, operation_type="order_test", title="Older")
            newer = start_operation(root, operation_type="order_test", title="Newer")

            older_path = Path(older["run_receipt_uri"])
            newer_path = Path(newer["run_receipt_uri"])
            older_payload = json.loads(older_path.read_text(encoding="utf-8"))
            newer_payload = json.loads(newer_path.read_text(encoding="utf-8"))
            older_payload["updated_at"] = "2026-01-01T00:00:00+00:00"
            newer_payload["updated_at"] = "2026-01-02T00:00:00+00:00"

            from continuum.core.operations import _stable_json_hash

            older_payload["receipt_hash"] = _stable_json_hash(older_payload)
            newer_payload["receipt_hash"] = _stable_json_hash(newer_payload)
            older_path.write_text(json.dumps(older_payload, ensure_ascii=True, indent=2), encoding="utf-8")
            newer_path.write_text(json.dumps(newer_payload, ensure_ascii=True, indent=2), encoding="utf-8")

            listed = list_operations(root)

            self.assertEqual(listed["operations"][0]["operation_id"], newer["operation_id"])
            self.assertEqual(listed["operations"][1]["operation_id"], older["operation_id"])

    def test_recovery_drill_proves_interruption_recovery_loop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"

            result = recovery_drill(root)

            self.assertTrue(result["ok"])
            self.assertTrue(Path(result["receipt_uri"]).exists())
            self.assertEqual(result["summary"]["status"], "interrupted")
            self.assertTrue(Path(result["summary"]["recovery_packet_uri"]).exists())
            self.assertTrue(Path(result["summary"]["recovery_packet_json_uri"]).exists())
            self.assertTrue(result["proof_verification"]["ok"], result["proof_verification"].get("errors"))
            stored = json.loads(Path(result["receipt_uri"]).read_text(encoding="utf-8"))
            rendered = json.dumps(stored, ensure_ascii=True, sort_keys=True)
            self.assertNotIn(str(root), rendered)
            self.assertEqual(stored["receipt_uri"], root_uri(root, result["receipt_uri"]))
            receipt = read_operation(Path(result["drill_root"]), result["operation_id"])
            self.assertEqual(receipt["intent"]["parent_root"], "<continuum-root>")

    def test_operation_recovery_packet_fences_markdown_in_operation_title(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            injected_title = "safe title\n\n```\n## INJECTED_RECOVERY_HEADING\nFOLLOW_THIS_TEXT\n```"
            started = start_operation(root, operation_type="title_injection", title=injected_title)

            recovered = recover_stale_operations(root, older_than_seconds=0, mark=True, limit=1)

            packet_path = Path(recovered["recovered"][0]["recovery_packet_uri"])
            packet = packet_path.read_text(encoding="utf-8")
            self.assertIn("## Operation Metadata", packet)
            self.assertIn("INJECTED_RECOVERY_HEADING", packet)
            self.assertIn("````json", packet)
            self.assertNotIn("\n## INJECTED_RECOVERY_HEADING\n", packet)
            machine_packet = json.loads(Path(recovered["recovered"][0]["recovery_packet_json_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(machine_packet["operation_id"], started["operation_id"])

    def test_restore_drill_restores_snapshot_into_disposable_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(root, session_id="restore-test", event_type="message", role="user", content="restore me")
            started = start_operation(root, operation_type="restore_proof_source", title="Restore proof source")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})
            proof = create_proof_pack(root, started["operation_id"])
            snap = snapshot(root, reason="unit_test_restore_drill")

            result = restore_drill(root, snapshot_uri=snap["snapshot_uri"])

            self.assertTrue(result["ok"], result["checks"])
            self.assertTrue(Path(result["receipt_uri"]).exists())
            self.assertTrue(Path(result["restored_db_uri"]).exists())
            self.assertIn("run", result["drill_root"])
            self.assertEqual(result["status"]["scroll_events"], 1)
            checks = {check["name"]: check for check in result["checks"]}
            self.assertTrue(checks["schema_version_matches"]["ok"])
            self.assertTrue(checks["recovery_packet_generated"]["ok"])
            self.assertTrue(result["recovery_probe"]["ok"])
            self.assertIn("artifact_ledger", result)
            self.assertIn("run/operations", result["copied_durable_paths"])
            self.assertIn("run/operation_events", result["copied_durable_paths"])
            self.assertIn("exports/operation_receipts", result["copied_durable_paths"])
            self.assertIn("exports/operation_events", result["copied_durable_paths"])
            self.assertTrue(result["recent_proof_packs"]["ok"], result["recent_proof_packs"])
            copied_proof = Path(result["drill_root"]) / Path(proof["proof_pack_uri"]).relative_to(root)
            copied_verification = verify_proof_pack(copied_proof)
            self.assertTrue(copied_verification["ok"], copied_verification["errors"])
            self.assertEqual(
                Path(copied_verification["verification_root"]).resolve(strict=False),
                Path(result["drill_root"]).resolve(strict=False),
            )

    def test_restore_drill_uses_source_bound_archive_without_transplanting_machine_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "epic-continuum"
            archive = base / "external-proof-archive"
            append_scroll_event(root, session_id="relocated-restore", event_type="message", role="user", content="proof")
            started = start_operation(root, operation_type="relocated_restore", title="Relocated restore")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})
            create_proof_pack(
                root,
                started["operation_id"],
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
                catalog_proof_mode="snapshot",
            )
            archived = apply_legacy_catalog_archive(root, archive)
            self.assertTrue(archived["ok"], archived)

            result = restore_drill(root, verify_recent_proof_packs=0)

            self.assertTrue(result["ok"], result["checks"])
            self.assertGreaterEqual(result["artifact_ledger"]["relocated"], 1)
            self.assertEqual(
                Path(result["artifact_ledger"]["relocation_evidence_root"]).resolve(strict=False),
                root.resolve(strict=False),
            )
            self.assertEqual(
                set(result["removed_machine_local_config"]),
                {"proof-archive.json", "writer-claim.json"},
            )
            drill_root = Path(result["drill_root"])
            self.assertIsNone(configured_archive_root(drill_root))
            self.assertTrue(result["restored_writer_claim"]["compatible"])

    def test_restore_drill_refuses_linked_output_parent_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "epic-continuum"
            outside = tmp_path / "outside-restore-drills"
            outside.mkdir()
            append_scroll_event(root, session_id="restore-link", event_type="message", role="user", content="restore link")
            snap = snapshot(root, reason="restore_link_guard")
            target_parent = root / "run"
            target_parent.mkdir(parents=True, exist_ok=True)
            linked_output = target_parent / "restore_drills"
            make_link_like_dir(self, linked_output, outside)

            result = restore_drill(root, snapshot_uri=snap["snapshot_uri"], verify_recent_proof_packs=0)

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "unsafe_restore_drill_output_paths")
            self.assertIsNone(result["receipt_uri"])
            self.assertEqual(list(outside.iterdir()), [])
            findings = result["restore_drill_output_paths"]["findings"]
            self.assertTrue(any(item["relative_path"] == "run/restore_drills" for item in findings))

    def test_verify_root_strict_short_circuits_restore_drill_on_linked_output_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "epic-continuum"
            outside = tmp_path / "outside-verify-drills"
            outside.mkdir()
            append_scroll_event(root, session_id="verify-link", event_type="message", role="user", content="verify link")
            target_parent = root / "run"
            target_parent.mkdir(parents=True, exist_ok=True)
            linked_output = target_parent / "restore_drills"
            make_link_like_dir(self, linked_output, outside)

            result = verify_root(root, strict=True, verify_recent_proof_packs=0, scan_secrets=False)

            self.assertFalse(result["ok"], result)
            self.assertEqual(list(outside.iterdir()), [])
            restore_section = result["sections"]["restore_drill"]
            self.assertEqual(restore_section["reason"], "unsafe_restore_drill_output_paths")
            check_names = {check["name"]: check for check in result["checks"]}
            self.assertFalse(check_names["restore_drill_output_paths_safe"]["ok"])

    def test_verify_root_strict_refuses_linked_restore_source_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "epic-continuum"
            outside = tmp_path / "outside-archive-source"
            outside.mkdir()
            (outside / "outside_secret_marker.txt").write_text("must not be copied", encoding="utf-8")
            append_scroll_event(root, session_id="source-link", event_type="message", role="user", content="source link")
            source_parent = root / "archive" / "originals"
            source_parent.mkdir(parents=True, exist_ok=True)
            linked_source = source_parent / "hot"
            if linked_source.exists() and not linked_source.is_symlink():
                shutil.rmtree(linked_source)
            make_link_like_dir(self, linked_source, outside)

            result = verify_root(root, strict=True, verify_recent_proof_packs=0, scan_secrets=False)

            self.assertFalse(result["ok"], result)
            restore_section = result["sections"]["restore_drill"]
            self.assertEqual(restore_section["reason"], "unsafe_restore_drill_source_paths")
            source_findings = result["sections"]["restore_drill_source_paths"]["findings"]
            self.assertTrue(any("archive/originals/hot" in item["relative_path"] for item in source_findings))
            copied_markers = list((root / "run" / "restore_drills").glob("**/outside_secret_marker.txt"))
            self.assertEqual(copied_markers, [])

    def test_restore_drill_cli_preflight_refuses_linked_run_parent_before_operation_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "epic-continuum"
            outside = tmp_path / "outside-run"
            append_scroll_event(root, session_id="run-link", event_type="message", role="user", content="run link")
            snap = snapshot(root, reason="run_link_guard")
            shutil.rmtree(root / "run")
            make_link_like_dir(self, root / "run", outside)

            output = io.StringIO()
            with redirect_stdout(output):
                rc = cli_main(
                    [
                        "restore-drill",
                        "--root",
                        str(root),
                        "--snapshot-uri",
                        snap["snapshot_uri"],
                        "--verify-recent-proof-packs",
                        "0",
                    ]
                )

            self.assertEqual(rc, 1)
            result = json.loads(output.getvalue())
            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "unsafe_restore_drill_output_paths")
            self.assertEqual(list(outside.iterdir()), [])

    def test_restore_drill_preserves_custom_card_sidecar_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            config = load_config(root)
            config["atomic_memory"]["card_sidecar_dir"] = "catalog/custom-cards"
            write_config(root, config)
            append_scroll_event(root, session_id="custom-sidecar", event_type="message", role="user", content="custom sidecar restore")
            roll_scroll_segment(root, session_id="custom-sidecar", start_seq=1, end_seq=1)

            snap = snapshot(root, reason="custom_sidecar_restore")
            result = restore_drill(root, snapshot_uri=snap["snapshot_uri"], verify_recent_proof_packs=0)

            self.assertTrue(result["ok"], result["checks"])
            self.assertTrue((Path(result["drill_root"]) / "catalog" / "custom-cards").exists())
            self.assertTrue(any((Path(result["drill_root"]) / "catalog" / "custom-cards").glob("*.yaml")))
            append_scroll_event(Path(result["drill_root"]), session_id="custom-sidecar", event_type="message", role="user", content="post restore custom config")
            roll_scroll_segment(Path(result["drill_root"]), session_id="custom-sidecar", start_seq=2, end_seq=2)
            self.assertGreaterEqual(len(list((Path(result["drill_root"]) / "catalog" / "custom-cards").glob("*.yaml"))), 2)

    def test_restore_drill_without_snapshot_seeds_current_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "epic-continuum"
            source = tmp_path / "restore-source.txt"
            source.write_text("Restore drill should seed the current book and chunks.", encoding="utf-8")
            append_scroll_event(root, session_id="restore-current", event_type="message", role="user", content="current")
            ingest_file(root, path=source, title="Restore Source")

            result = restore_drill(root, verify_recent_proof_packs=0)

            self.assertTrue(result["ok"], result["checks"])
            self.assertIsNotNone(result["seed_snapshot"])
            checks = {check["name"]: check for check in result["checks"]}
            self.assertTrue(checks["restored_counts_match_snapshot_manifest"]["ok"])
            self.assertEqual(result["status"]["scroll_events"], 1)
            self.assertEqual(result["status"]["books"], 1)
            self.assertEqual(result["status"]["chunks"], 1)
            stored = json.loads(Path(result["receipt_uri"]).read_text(encoding="utf-8"))
            rendered = json.dumps(stored, ensure_ascii=True, sort_keys=True)
            self.assertNotIn(str(root), rendered)
            self.assertEqual(stored["receipt_uri"], root_uri(root, result["receipt_uri"]))

    def test_restore_drill_fails_when_restored_counts_do_not_match_snapshot_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(root, session_id="restore-mismatch", event_type="message", role="user", content="restore me")
            snap = snapshot(root, reason="unit_test_restore_mismatch")
            bad_counts = {table: 0 for table in SNAPSHOT_COUNT_TABLES}
            bad_counts["scroll_events"] = 2
            bad_manifest = {
                "schema": "epic_continuum.snapshot_manifest.v1",
                "snapshot_uri": snap["snapshot_uri"],
                "counts": bad_counts,
                "card_sidecars_uri": snap["card_sidecars_uri"],
                "card_sidecar_count": snap["card_sidecar_count"],
                "semantic_integrity": {"ok": True},
            }

            with patch("continuum.core.operations._snapshot_manifest", return_value=bad_manifest):
                result = restore_drill(root, snapshot_uri=snap["snapshot_uri"], verify_recent_proof_packs=0)

            self.assertFalse(result["ok"], result["checks"])
            checks = {check["name"]: check for check in result["checks"]}
            self.assertFalse(checks["restored_counts_match_snapshot_manifest"]["ok"])

    def test_pre_receipt_v2_snapshot_count_manifest_remains_restorable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(
                root,
                session_id="legacy-snapshot-counts",
                event_type="message",
                role="user",
                content="pre-receipt snapshot compatibility",
            )
            snap = snapshot(root, reason="pre_receipt_count_compatibility")
            snap_path = Path(str(snap["snapshot_uri"]))
            snapshot_conn = sqlite3.connect(snap_path)
            try:
                snapshot_conn.execute("DROP TABLE conflict_resolution_members")
                snapshot_conn.execute("DROP TABLE conflict_resolution_receipts")
                snapshot_conn.commit()
            finally:
                snapshot_conn.close()
            manifest_path = snapshot_manifest_path(snap_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["counts"].pop("conflict_resolution_members")
            manifest["counts"].pop("conflict_resolution_receipts")
            manifest["snapshot"]["sha256"] = store_module.file_sha256(snap_path)
            manifest["snapshot"]["size_bytes"] = snap_path.stat().st_size
            manifest["snapshot_hash"] = manifest["snapshot"]["sha256"]
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            conn = connect(root)
            try:
                conn.execute(
                    """
                    UPDATE snapshots
                    SET snapshot_hash = ?, manifest_hash = ?
                    WHERE id = ?
                    """,
                    (
                        store_module.file_sha256(snap_path),
                        store_module.file_sha256(manifest_path),
                        snap["snapshot_id"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            verification = store_module.verify_snapshot_manifest_for_root(
                snap_path,
                root=root,
                require_catalog_binding=True,
            )
            restored = restore_drill(
                root,
                snapshot_uri=str(snap_path),
                verify_recent_proof_packs=0,
            )

            self.assertTrue(verification["ok"], verification)
            self.assertTrue(restored["ok"], restored)
            checks = {check["name"]: check for check in restored["checks"]}
            count_check = checks["restored_counts_match_snapshot_manifest"]
            self.assertTrue(count_check["ok"], count_check)
            self.assertEqual(
                set(count_check["tolerated_absent_tables"]),
                {
                    "conflict_resolution_members",
                    "conflict_resolution_receipts",
                },
            )

    def test_current_snapshot_cannot_omit_empty_receipt_table_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(
                root,
                session_id="current-snapshot-counts",
                event_type="message",
                role="user",
                content="current snapshot count binding",
            )
            snap = snapshot(root, reason="current_count_binding")
            snap_path = Path(str(snap["snapshot_uri"]))
            manifest_path = snapshot_manifest_path(snap_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["counts"].pop("conflict_resolution_members")
            manifest["counts"].pop("conflict_resolution_receipts")
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True)
                + "\n",
                encoding="utf-8",
            )

            verification = store_module.verify_snapshot_manifest(
                snap_path,
            )

            self.assertFalse(verification["ok"], verification)
            self.assertTrue(
                any(
                    error.get("error") == "snapshot_counts_mismatch"
                    for error in verification["errors"]
                ),
                verification,
            )

    def test_snapshot_creation_rejects_live_scroll_hash_corruption(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(root, session_id="semantic-snapshot", event_type="message", role="user", content="original")
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            try:
                conn.execute("UPDATE scroll_events SET content = ? WHERE seq = 1", ("corrupted without hash update",))
                conn.commit()
            finally:
                conn.close()

            with self.assertRaisesRegex(ValueError, "semantic integrity"):
                snapshot(root, reason="semantic_corruption")

    def test_snapshot_preflight_reads_live_wal_with_writer_still_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(root, session_id="semantic-wal", event_type="message", role="user", content="original")
            writer = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            try:
                writer.execute("PRAGMA journal_mode=WAL")
                writer.execute(
                    "UPDATE scroll_events SET content = ?, content_hash = ? WHERE seq = 1",
                    ("DIRTY_CONTENT_VISIBLE_ONLY_IN_WAL", "WRONG_HASH"),
                )
                writer.commit()

                with self.assertRaisesRegex(ValueError, "semantic integrity"):
                    snapshot(root, reason="semantic_wal_corruption")
            finally:
                writer.close()

    def test_snapshot_rejects_copied_database_sidecar_generation_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(root, session_id="semantic-sidecar-race", event_type="message", role="user", content="original")
            roll_scroll_segment(root, session_id="semantic-sidecar-race", start_seq=1, end_seq=1)
            original_copytree = store_module.secure_copytree

            def corrupt_copied_sidecar(src: Path, dst: Path, *args: object, **kwargs: object) -> object:
                result = original_copytree(src, dst, *args, **kwargs)
                for sidecar in Path(dst).glob("*.yaml"):
                    sidecar.write_text(
                        sidecar.read_text(encoding="utf-8").replace("schema:", "schema_corrupted:", 1),
                        encoding="utf-8",
                    )
                    break
                return result

            with patch("continuum.core.store.secure_copytree", side_effect=corrupt_copied_sidecar):
                with self.assertRaisesRegex(ValueError, "copied snapshot semantic integrity"):
                    snapshot(root, reason="semantic_sidecar_race")

            snapshots = root / "snapshots"
            self.assertFalse(list(snapshots.glob("continuum_catalog_*.sqlite3")))
            self.assertFalse(list(snapshots.glob("continuum_snapshot_*.manifest.json")))
            self.assertFalse(list(snapshots.glob(".staging_*")))

    def test_doctor_reports_semantic_integrity_failures_without_restore_drill(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(root, session_id="doctor-semantic", event_type="message", role="user", content="original")
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            try:
                conn.execute("UPDATE scroll_events SET content = ? WHERE seq = 1", ("doctor semantic corruption",))
                conn.commit()
            finally:
                conn.close()

            result = doctor(root, verify_recent_proof_packs=0)

            self.assertFalse(result["ok"], result)
            checks = {check["name"]: check for check in result["checks"]}
            self.assertFalse(checks["semantic_integrity_clean"]["ok"])
            self.assertEqual(checks["semantic_integrity_clean"]["failing"]["scroll_hash_mismatches"], 1)

    def test_snapshot_creation_rejects_linked_card_sidecar_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "epic-continuum"
            outside = tmp_path / "outside-sidecar-source"
            append_scroll_event(root, session_id="sidecar-link", event_type="message", role="user", content="sidecar link")
            roll_scroll_segment(root, session_id="sidecar-link", start_seq=1, end_seq=1)
            make_link_like_dir(self, root / "catalog" / "cards" / "linked-sidecars", outside)

            with self.assertRaisesRegex(ValueError, "link-like card sidecar"):
                snapshot(root, reason="sidecar_link_guard")

    def test_snapshot_retention_removes_catalog_rows_for_deleted_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(root, session_id="retention-session", event_type="message", role="user", content="retain")

            for index in range(22):
                snapshot(root, reason=f"retention-{index}")
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            try:
                conn.execute(
                    """
                    INSERT INTO snapshots(id, snapshot_uri, reason, source_db_uri, created_at)
                    VALUES('phantom_snapshot', 'snapshots/missing.sqlite3', 'phantom', 'catalog/catalog.sqlite3', '2026-01-01T00:00:00+00:00')
                    """
                )
                conn.commit()
            finally:
                conn.close()
            snapshot(root, reason="retention-cleanup-phantom")

            snapshots = sorted((root / "snapshots").glob("continuum_catalog_*.sqlite3"))
            self.assertEqual(len(snapshots), 20)
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute("SELECT snapshot_uri FROM snapshots").fetchall()
            finally:
                conn.close()
            self.assertEqual(len(rows), 20)
            for row in rows:
                self.assertTrue((root / row["snapshot_uri"]).exists())

    def test_snapshot_retention_preserves_immutable_proof_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            snapshots_dir = root / "snapshots"
            snapshots: list[Path] = []
            base_mtime_ns = 1_700_000_000_000_000_000
            for index in range(22):
                path = snapshots_dir / f"continuum_catalog_snapshot_20260101T0000{index:02d}Z_{index:032x}.sqlite3"
                path.write_bytes(f"snapshot-{index}".encode("utf-8"))
                timestamp = base_mtime_ns + (index * 1_000_000_000)
                os.utime(path, ns=(timestamp, timestamp))
                snapshots.append(path)
            protected = snapshots[0]
            payload = protected.read_bytes()
            conn = connect(root)
            try:
                record_artifact(
                    conn,
                    kind="proof_input",
                    uri=root_uri(root, protected),
                    sha256=hashlib.sha256(payload).hexdigest(),
                    size_bytes=len(payload),
                    immutable=True,
                )
                conn.commit()
            finally:
                conn.close()

            result = enforce_snapshot_retention(root)

            self.assertEqual(result["protected"], 1)
            self.assertTrue(protected.exists())
            self.assertEqual(len(list(snapshots_dir.glob("continuum_catalog_*.sqlite3"))), 21)

    def test_snapshot_restore_preserves_alias_key_for_original_external_identifier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            config = load_config(root)
            config["security"]["secret_scan_action"] = "warn"
            write_config(root, config)
            secret_session = "sk-" + "S" * 40
            marker = "snapshot alias restore marker"
            append_scroll_event(root, session_id=secret_session, event_type="message", role="user", content=marker)
            snap = snapshot(root, reason="alias_restore")

            result = restore_drill(root, snapshot_uri=snap["snapshot_uri"], verify_recent_proof_packs=0)

            self.assertTrue(result["ok"], result["checks"])
            context = compile_context(
                Path(result["drill_root"]),
                session_id=secret_session,
                query=marker,
                token_budget=1000,
                create=False,
            )
            self.assertIn(marker, context["context_text"])
            self.assertTrue(Path(result["restored_partition_alias_key_uri"]).exists())

    def test_restore_drill_rejects_tampered_snapshot_database(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(root, session_id="tamper-session", event_type="message", role="user", content="original")
            snap = snapshot(root, reason="tamper_restore")
            snap_path = Path(snap["snapshot_uri"])
            conn = sqlite3.connect(str(snap_path))
            try:
                conn.execute("UPDATE scroll_events SET content = ? WHERE seq = 1", ("TAMPERED_SNAPSHOT_MARKER",))
                conn.commit()
            finally:
                conn.close()

            result = restore_drill(root, snapshot_uri=str(snap_path), verify_recent_proof_packs=0)

            self.assertFalse(result["ok"], result)
            checks = {check["name"]: check for check in result["checks"]}
            self.assertFalse(checks["snapshot_manifest_verified"]["ok"])
            self.assertTrue(result["snapshot_manifest_verification"]["errors"])

    def test_restore_drill_rejects_tampered_snapshot_even_if_manifest_is_rehashed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(root, session_id="tamper-rehash", event_type="message", role="user", content="original")
            snap = snapshot(root, reason="tamper_rehash_restore")
            snap_path = Path(snap["snapshot_uri"])
            conn = sqlite3.connect(str(snap_path))
            try:
                conn.execute("UPDATE scroll_events SET content = ?, content_hash = ? WHERE seq = 1", ("TAMPERED_REHASH", "forged"))
                conn.commit()
            finally:
                conn.close()
            manifest_path = snapshot_manifest_path(snap_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["snapshot"]["sha256"] = hashlib.sha256(snap_path.read_bytes()).hexdigest()
            manifest["snapshot_hash"] = manifest["snapshot"]["sha256"]
            manifest["counts"]["scroll_events"] = 1
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")

            result = restore_drill(root, snapshot_uri=str(snap_path), verify_recent_proof_packs=0)

            self.assertFalse(result["ok"], result)
            errors = result["snapshot_manifest_verification"]["errors"]
            self.assertTrue(any(error.get("error") == "snapshot_catalog_hash_mismatch" for error in errors), errors)

    def test_invalid_cli_partition_id_fails_before_operation_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            bad_session = "bad\n## injected"

            code = cli_main([
                    "roll-segment",
                    "--root",
                    str(root),
                    "--session-id",
                    bad_session,
                    "--start-seq",
                    "1",
                    "--end-seq",
                    "1",
                ])

            self.assertEqual(code, 1)
            self.assertFalse((root / "run").exists())
            self.assertFalse((root / "exports").exists())

    def test_invalid_cli_roll_range_fails_before_operation_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)

            code = cli_main([
                "roll-segment",
                "--root",
                str(root),
                "--session-id",
                "valid-session",
                "--start-seq",
                "2",
                "--end-seq",
                "1",
            ])

            self.assertEqual(code, 1)
            for rel in (
                "run/operations",
                "run/operation_events",
                "exports/operation_receipts",
                "exports/operation_events",
                "exports/proof_packs",
                "exports/proof_artifacts",
            ):
                self.assertFalse((root / rel).exists(), rel)
            self.assertFalse(any((root / "snapshots").glob("*")))

    def test_invalid_cli_restore_and_reindex_fail_before_operation_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)

            restore_code = cli_main([
                "restore-drill",
                "--root",
                str(root),
                "--snapshot-uri",
                str(root / "snapshots" / "missing.sqlite3"),
            ])
            reindex_code = cli_main([
                "reindex-memory",
                "--root",
                str(root),
                "--after-seq",
                "1",
            ])

            self.assertEqual(restore_code, 1)
            self.assertEqual(reindex_code, 1)
            for rel in (
                "run/operations",
                "run/operation_events",
                "exports/operation_receipts",
                "exports/operation_events",
                "exports/proof_packs",
                "exports/proof_artifacts",
            ):
                self.assertFalse((root / rel).exists(), rel)

    def test_secret_bearing_internal_proof_paths_are_frozen_to_safe_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            config = load_config(root)
            config["security"]["secret_scan_action"] = "warn"
            write_config(root, config)
            secret_dir = root / "archive" / "api_key=supersecretvalue123"
            secret_dir.mkdir(parents=True)
            secret_file = secret_dir / "evidence.txt"
            secret_file.write_text("safe evidence bytes", encoding="utf-8")

            with OperationGuard(
                root,
                operation_type="secret_path_proof",
                title="Proof secret-bearing internal path",
                touched_paths=[secret_file],
            ) as operation:
                operation.succeed({"ok": True}, touched_paths=[secret_file])
                operation_id = operation.operation_id

            proof_path = root / "exports" / "proof_packs" / f"{operation_id}.json"
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            rendered = json.dumps(proof, ensure_ascii=True, sort_keys=True)
            self.assertNotIn("api_key=supersecretvalue123", rendered)
            self.assertIn("redacted_internal", rendered)
            verification = verify_proof_pack(proof_path, root=root)
            self.assertTrue(verification["ok"], verification["errors"])

    def test_operation_guard_does_not_mask_original_error_when_proof_pack_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)

            with self.assertRaisesRegex(ValueError, "original failure"):
                with patch("continuum.core.operations.create_proof_pack", side_effect=RuntimeError("proof exploded")):
                    with OperationGuard(root, operation_type="proof_mask", title="Proof mask"):
                        raise ValueError("original failure")

    def test_operation_guard_records_proof_failure_without_losing_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)

            with patch("continuum.core.operations.create_proof_pack", side_effect=RuntimeError("proof exploded")):
                with OperationGuard(root, operation_type="proof_success", title="Proof success") as operation:
                    receipt = operation.succeed({"ok": True})

            self.assertEqual(receipt["status"], "succeeded")
            phases = [item["phase"] for item in receipt.get("progress", [])]
            self.assertIn("proof_pack_failed", phases)

    def test_cli_top_level_error_redacts_paths_and_secret_fragments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            missing = Path(tmp) / "private" / "api_key=supersecretvalue123.txt"
            stdout = io.StringIO()

            with redirect_stdout(stdout):
                code = cli_main(["ingest-file", "--root", str(root), "--path", str(missing)])

            payload = json.loads(stdout.getvalue())
            rendered = json.dumps(payload, ensure_ascii=True)
            self.assertEqual(code, 1)
            self.assertFalse(payload["ok"])
            self.assertIn("<redacted-path:", payload["error"])
            self.assertNotIn(str(missing), rendered)
            self.assertNotIn("supersecretvalue123", rendered)

    def test_directory_proof_manifests_redact_secret_bearing_child_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            config = load_config(root)
            config["security"]["secret_scan_action"] = "warn"
            write_config(root, config)
            evidence_dir = root / "archive" / "directory-proof"
            evidence_dir.mkdir(parents=True)
            (evidence_dir / "api_key=supersecretvalue123.txt").write_text("safe child bytes", encoding="utf-8")

            with OperationGuard(
                root,
                operation_type="secret_child_directory_proof",
                title="Proof directory with secret-bearing child name",
                touched_paths=[evidence_dir],
            ) as operation:
                operation.succeed({"ok": True}, touched_paths=[evidence_dir])
                operation_id = operation.operation_id

            manifest_paths = list((root / "exports" / "proof_artifacts" / operation_id / "directory_manifests").glob("*.tree.json"))
            self.assertEqual(len(manifest_paths), 1)
            rendered_manifest = manifest_paths[0].read_text(encoding="utf-8")
            self.assertNotIn("api_key=supersecretvalue123", rendered_manifest)
            self.assertIn("path_hash", rendered_manifest)
            proof_path = root / "exports" / "proof_packs" / f"{operation_id}.json"
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            directory_substitutions = [
                item for item in proof.get("path_substitutions", [])
                if item.get("kind") == "directory_manifest_snapshot"
            ]
            self.assertEqual(len(directory_substitutions), 1)
            verification = verify_proof_pack(proof_path, root=root)
            self.assertTrue(verification["ok"], verification["errors"])

    def test_directory_proof_manifests_record_symlinks_without_target_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            config = load_config(root)
            config["security"]["secret_scan_action"] = "warn"
            write_config(root, config)
            outside = Path(tmp) / "api_key=supersecretvalue123.txt"
            outside.write_text("external target secret api_key=supersecretvalue123", encoding="utf-8")
            evidence_dir = root / "archive" / "symlink-proof"
            evidence_dir.mkdir(parents=True)
            link = evidence_dir / "external-link.txt"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")

            with OperationGuard(
                root,
                operation_type="symlink_directory_proof",
                title="Proof directory with external symlink",
                touched_paths=[evidence_dir],
            ) as operation:
                operation.succeed({"ok": True}, touched_paths=[evidence_dir])
                operation_id = operation.operation_id

            manifest_paths = list((root / "exports" / "proof_artifacts" / operation_id / "directory_manifests").glob("*.tree.json"))
            self.assertEqual(len(manifest_paths), 1)
            manifest = json.loads(manifest_paths[0].read_text(encoding="utf-8"))
            rendered_manifest = json.dumps(manifest, ensure_ascii=True, sort_keys=True)
            self.assertNotIn("supersecretvalue123", rendered_manifest)
            symlink_entries = [entry for entry in manifest["tree"]["entries"] if entry.get("kind") == "symlink"]
            self.assertEqual(len(symlink_entries), 1)
            self.assertTrue(symlink_entries[0].get("link_target_redacted"))
            self.assertIn("link_target_hash", symlink_entries[0])
            proof_path = root / "exports" / "proof_packs" / f"{operation_id}.json"
            outside.unlink()
            verification = verify_proof_pack(proof_path, root=root)
            self.assertTrue(verification["ok"], verification["errors"])

    def test_secret_bearing_internal_symlink_paths_are_frozen_to_safe_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            config = load_config(root)
            config["security"]["secret_scan_action"] = "warn"
            write_config(root, config)
            outside = Path(tmp) / "outside-target.txt"
            outside.write_text("safe external target bytes", encoding="utf-8")
            evidence_dir = root / "archive" / "api_key=supersecretvalue123"
            evidence_dir.mkdir(parents=True)
            link = evidence_dir / "external-link.txt"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")

            with OperationGuard(
                root,
                operation_type="secret_symlink_path_proof",
                title="Proof secret-bearing symlink path",
                touched_paths=[link],
            ) as operation:
                operation.succeed({"ok": True}, touched_paths=[link])
                operation_id = operation.operation_id

            proof_path = root / "exports" / "proof_packs" / f"{operation_id}.json"
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            rendered_proof = json.dumps(proof, ensure_ascii=True, sort_keys=True)
            self.assertNotIn("api_key=supersecretvalue123", rendered_proof)
            self.assertIn("redacted_internal_symlinks", rendered_proof)
            substitutions = [
                item for item in proof.get("path_substitutions", [])
                if item.get("kind") == "internal_symlink_manifest_redacted_path"
            ]
            self.assertEqual(len(substitutions), 1)
            manifest_paths = list((root / "exports" / "proof_artifacts" / operation_id / "redacted_internal_symlinks").glob("*.symlink.json"))
            self.assertEqual(len(manifest_paths), 1)
            self.assertNotIn("api_key=supersecretvalue123", manifest_paths[0].read_text(encoding="utf-8"))
            outside.unlink()
            verification = verify_proof_pack(proof_path, root=root)
            self.assertTrue(verification["ok"], verification["errors"])
            policy_verification = verify_proof_pack(proof_path, root=root, allowed_roots=[root])
            self.assertTrue(policy_verification["ok"], policy_verification["errors"])

    def test_direct_symlink_proof_input_tracks_link_not_target_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            config = load_config(root)
            config["security"]["secret_scan_action"] = "warn"
            write_config(root, config)
            outside = Path(tmp) / "api_key=supersecretvalue123.txt"
            outside.write_text("external target secret api_key=supersecretvalue123", encoding="utf-8")
            evidence_dir = root / "archive" / "direct-symlink-proof"
            evidence_dir.mkdir(parents=True)
            link = evidence_dir / "external-link.txt"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")

            with OperationGuard(
                root,
                operation_type="direct_symlink_proof",
                title="Proof direct symlink input",
                touched_paths=[link],
            ) as operation:
                operation.succeed({"ok": True}, touched_paths=[link])
                operation_id = operation.operation_id

            proof_path = root / "exports" / "proof_packs" / f"{operation_id}.json"
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            rendered_proof = json.dumps(proof, ensure_ascii=True, sort_keys=True)
            self.assertNotIn("supersecretvalue123", rendered_proof)
            symlink_entries = [entry for entry in proof["paths"] if entry.get("kind") == "symlink"]
            self.assertEqual(len(symlink_entries), 1)
            expected_link_uri = link.absolute().relative_to(root.absolute()).as_posix()
            self.assertEqual(symlink_entries[0].get("uri"), expected_link_uri)
            self.assertTrue(symlink_entries[0].get("link_target_redacted"))
            self.assertIn("link_target_hash", symlink_entries[0])
            outside.unlink()
            verification = verify_proof_pack(proof_path, root=root)
            self.assertTrue(verification["ok"], verification["errors"])
            policy_verification = verify_proof_pack(proof_path, root=root, allowed_roots=[root])
            self.assertTrue(policy_verification["ok"], policy_verification["errors"])

    def test_strict_proof_verification_rejects_invalid_operation_identifier_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            proof_path = root / "exports" / "proof_packs" / "forged.json"
            proof_path.parent.mkdir(parents=True, exist_ok=True)
            proof = {
                "schema": "epic_continuum.proof_pack.v1",
                "operation_id": "../../../outside/loot",
                "paths": [{"uri": "run/operations/forged.json", "kind": "missing", "exists": False}],
            }
            proof["proof_pack_hash"] = _proof_pack_hash(proof)
            proof_path.write_text(json.dumps(proof), encoding="utf-8")

            result = verify_proof_pack(proof_path, root=root, strict=True)
            self.assertFalse(result["ok"], result)
            self.assertIn("operation_id_valid", {item.get("check") for item in result["errors"]})

    def test_terminal_operation_cannot_be_mutated_after_proof_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            started = start_operation(root, operation_type="immutable_terminal", title="Immutable terminal receipt")
            with self.assertRaisesRegex(ValueError, "terminal operations"):
                create_proof_pack(root, started["operation_id"])

            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})
            proof = create_proof_pack(root, started["operation_id"])
            proof_path = Path(proof["proof_pack_uri"])
            self.assertTrue(verify_proof_pack(proof_path, root=root)["ok"])

            with self.assertRaisesRegex(ValueError, "terminal status"):
                record_operation_progress(
                    root,
                    started["operation_id"],
                    phase="late",
                    message="must not rot the proof",
                )
            with self.assertRaisesRegex(ValueError, "terminal status"):
                update_operation_cursor(root, started["operation_id"], {"late": True})
            with self.assertRaisesRegex(ValueError, "terminal status"):
                finish_operation(root, started["operation_id"], status="failed", error={"late": True})

            self.assertTrue(verify_proof_pack(proof_path, root=root)["ok"])



if __name__ == "__main__":
    unittest.main()
