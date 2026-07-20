from __future__ import annotations

import hashlib
import io
import os
import json
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import continuum.core.store as store_module
import continuum.core.operations as operations_module
import continuum.core.permissions as permissions_module
import continuum.core.review_bridge as review_bridge_module
from continuum.cli import main as cli_main
from continuum.core.config import load_config, write_config
from continuum.core.permissions import secure_write_text
from continuum.core.proof_archive import apply_legacy_catalog_archive, configured_archive_root
from continuum.core.review_bridge import (
    create_review_job,
    review_browser_attempt_start,
    review_job_status,
)
from continuum.core.writer_claim import claim_writer
from continuum.core.store import (
    audit_secrets,
    append_scroll_event,
    compile_context,
    connect,
    connect_existing,
    create_card,
    enforce_snapshot_retention,
    ingest_file,
    init_db,
    record_artifact,
    record_project_state,
    roll_scroll_segment,
    snapshot,
    snapshot_manifest_path,
    sync_card_sidecars_after_commit,
)
from continuum.core.workers import MAX_PRUNE_MEMORY_LIMIT
from continuum.core.operations import (
    OperationGuard,
    SNAPSHOT_COUNT_TABLES,
    _verify_artifact_ledger,
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


def downgrade_snapshot_manifest_to_legacy_without_review_pair(root: Path, snapshot_path: Path) -> dict:
    manifest_path = snapshot_manifest_path(snapshot_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    pair = manifest.pop("review_bridge_jobs")
    pair_path = root / str(pair["uri"])
    if pair_path.exists():
        shutil.rmtree(pair_path)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    conn = connect(root)
    try:
        conn.execute(
            "UPDATE snapshots SET manifest_hash = ? WHERE snapshot_uri = ?",
            (hashlib.sha256(manifest_path.read_bytes()).hexdigest(), root_uri(root, snapshot_path)),
        )
        conn.commit()
    finally:
        conn.close()
    return manifest


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


def seed_snapshot_durability_root(root: Path) -> None:
    init_db(root)
    conn = connect(root)
    try:
        card_id = create_card(
            conn,
            root=root,
            card_type="note",
            title="Snapshot durability member",
            summary="Every copied snapshot member must be durable before authority.",
            source_refs=[],
        )
        conn.commit()
    finally:
        conn.close()
    sync_result = sync_card_sidecars_after_commit(root, [card_id])
    if not sync_result.get("ok"):
        raise AssertionError(sync_result)
    store_module._partition_alias_key(root)
    review_subject = root.parent / "durability-subject.txt"
    secure_write_text(review_subject, "durable review subject\n")
    create_review_job(
        root,
        subject_path=review_subject,
        prompt="Review the durable snapshot fixture.",
        transport="manual",
    )


class SimulatedSnapshotPowerLoss(BaseException):
    pass


class OperationLedgerTest(unittest.TestCase):
    def test_cli_prune_memory_help_renders_literal_metacharacters(self) -> None:
        package_root = Path(store_module.__file__).resolve().parents[2]
        environment = os.environ.copy()
        existing_pythonpath = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = os.pathsep.join(
            part
            for part in (str(package_root), existing_pythonpath)
            if part
        )
        completed = subprocess.run(
            [sys.executable, "-m", "continuum", "prune-memory", "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("(%, _, and \\ are literal)", completed.stdout)

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

    def test_operation_guard_fail_result_preserves_payload_and_proves_failed_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            source = Path(tmp) / "failed-result-evidence.txt"
            source.write_text("backend failure evidence", encoding="utf-8")
            result = {
                "ok": False,
                "status": "install_failed",
                "error": "backend reported failure",
            }

            with OperationGuard(
                root,
                operation_type="guarded_failed_result",
                title="Guarded failed result",
                touched_paths=[source],
            ) as operation:
                operation.cursor({"phase": "install_failed"})
                operation.fail_result(
                    result,
                    error={
                        "type": "BackendResultFailure",
                        "message": "failure detail " * 500,
                        "stage": "install_failed",
                        "component": "hermes_adapter",
                    },
                    proof_extra={"failure_stage": "install_failed"},
                )
                wrapped = operation.wrap_result(result)

            self.assertEqual(
                {key: value for key, value in wrapped.items() if key != "_operation"},
                result,
            )
            self.assertEqual(wrapped["_operation"]["status"], "failed")
            summary = operation_summary(root, wrapped["_operation"]["operation_id"])
            self.assertEqual(summary["status"], "failed")
            self.assertEqual(summary["result"], result)
            self.assertEqual(summary["cursor"], {"phase": "install_failed"})
            self.assertEqual(summary["error"]["type"], "BackendResultFailure")
            self.assertTrue(summary["error"]["truncated"])
            self.assertEqual(summary["error"]["stage"], "install_failed")
            self.assertLessEqual(
                len(json.dumps(summary["error"], ensure_ascii=True, sort_keys=True)),
                4000,
            )
            proof = json.loads(Path(summary["proof_pack_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(proof["status"], "failed")
            self.assertEqual(proof["result"], result)
            self.assertEqual(proof["error"], summary["error"])
            self.assertEqual(proof["extra"]["failure_stage"], "install_failed")
            replayed = replay_operation_event_log(
                Path(summary["operation_event_log_uri"]),
                operation_id=summary["operation_id"],
            )
            self.assertTrue(replayed["ok"], replayed)
            self.assertEqual(replayed["status"], "failed")

    def test_failed_result_error_bound_applies_to_escaped_unicode(self) -> None:
        bounded = operations_module._bounded_operation_failure_error(
            {
                "type": "🔥" * 500,
                "message": "🔥" * 5000,
                "stage": "🔥" * 200,
                "component": "🔥" * 200,
            }
        )

        serialized = json.dumps(bounded, ensure_ascii=True, sort_keys=True)
        self.assertLessEqual(len(serialized), 4000)
        self.assertTrue(bounded["truncated"])
        self.assertEqual(len(bounded["original_sha256"]), 64)

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

    def test_proof_pack_preserves_existing_canonical_artifact_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            artifact_path = root / "exports" / "canonical.json"
            artifact_path.parent.mkdir(parents=True, exist_ok=True)
            artifact_path.write_text('{"canonical":true}\n', encoding="utf-8")
            artifact_uri = root_uri(root, artifact_path)
            artifact_sha256 = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
            canonical_metadata = {"authority": "domain", "revision": 1}
            conn = connect(root)
            try:
                record_artifact(
                    conn,
                    kind="canonical_domain_artifact",
                    uri=artifact_uri,
                    sha256=artifact_sha256,
                    size_bytes=artifact_path.stat().st_size,
                    operation_id="op_domain_authority",
                    immutable=True,
                    source_type="domain_authority",
                    trust_level="local_generated",
                    metadata=canonical_metadata,
                )
                conn.commit()
            finally:
                conn.close()

            started = start_operation(root, operation_type="proof_reference", title="Reference canonical artifact")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})
            create_proof_pack(root, started["operation_id"], touched_paths=[artifact_path])

            conn = connect_existing(root)
            try:
                rows = conn.execute(
                    "SELECT kind, operation_id, source_type, trust_level, metadata_json "
                    "FROM artifacts WHERE uri = ? AND sha256 = ?",
                    (artifact_uri, artifact_sha256),
                ).fetchall()
            finally:
                conn.close()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["kind"], "canonical_domain_artifact")
            self.assertEqual(rows[0]["operation_id"], "op_domain_authority")
            self.assertEqual(rows[0]["source_type"], "domain_authority")
            self.assertEqual(rows[0]["trust_level"], "local_generated")
            self.assertEqual(json.loads(rows[0]["metadata_json"]), canonical_metadata)

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

    @unittest.skipUnless(os.name == "nt", "identity-bound proof source deletion requires Windows")
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

    @unittest.skipUnless(os.name == "nt", "identity-bound proof source deletion requires Windows")
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

    def test_cli_prune_memory_literal_scope_limits_and_protected_failure_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            conn = connect(root)
            try:
                marker_ids = {
                    marker: create_card(
                        conn,
                        root=root,
                        card_type="note",
                        title=f"CLI literal {marker} prune marker",
                        summary=f"Only the {label} CLI Card has this marker.",
                        source_refs=[],
                    )
                    for marker, label in (("%", "percent"), ("_", "underscore"), ("\\", "escape"))
                }
                plain_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="CLI literal plain prune marker",
                    summary="This ordinary Card must remain active.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [*marker_ids.values(), plain_id])

            for marker, expected_id in marker_ids.items():
                with self.subTest(marker=marker):
                    output = io.StringIO()
                    with redirect_stdout(output):
                        code = cli_main(
                            [
                                "prune-memory",
                                "--root",
                                str(root),
                                "--topic",
                                marker,
                                "--dry-run",
                            ]
                        )
                    result = json.loads(output.getvalue())
                    self.assertEqual(code, 0, result)
                    self.assertEqual(result["matching_mode"], "literal_substring")
                    self.assertEqual(result["card_ids"], [expected_id])

            applied_output = io.StringIO()
            with redirect_stdout(applied_output):
                applied_code = cli_main(
                    [
                        "prune-memory",
                        "--root",
                        str(root),
                        "--topic",
                        "%",
                        "--action",
                        "archive",
                    ]
                )
            applied = json.loads(applied_output.getvalue())
            self.assertEqual(applied_code, 0, applied)
            self.assertEqual(applied["card_ids"], [marker_ids["%"]])
            self.assertEqual(applied["_operation"]["status"], "succeeded")

            for arguments, expected_error in (
                (["--topic", "   ", "--all"], "whitespace-only"),
                (
                    ["--topic", "literal", "--limit", str(MAX_PRUNE_MEMORY_LIMIT + 1)],
                    str(MAX_PRUNE_MEMORY_LIMIT),
                ),
            ):
                output = io.StringIO()
                with redirect_stdout(output):
                    code = cli_main(["prune-memory", "--root", str(root), *arguments])
                result = json.loads(output.getvalue())
                self.assertEqual(code, 1, result)
                self.assertFalse(result["ok"])
                self.assertIn(expected_error, result["error"])

            state = record_project_state(
                root,
                session_id="cli-prune-protected-session",
                agent_id="cli-prune-protected-agent",
                project_id="cli-prune-protected-project",
                objective="CLI Protected Authority Marker",
            )
            conn = connect(root)
            try:
                state_before = dict(
                    conn.execute(
                        "SELECT status, supersedes_card_id, superseded_by_card_id, conflict_group FROM cards WHERE id = ?",
                        (state["card_id"],),
                    ).fetchone()
                )
            finally:
                conn.close()
            protected_output = io.StringIO()
            with redirect_stdout(protected_output):
                protected_code = cli_main(
                    [
                        "prune-memory",
                        "--root",
                        str(root),
                        "--topic",
                        "CLI Protected Authority Marker",
                        "--action",
                        "forget",
                    ]
                )
            protected = json.loads(protected_output.getvalue())
            self.assertEqual(protected_code, 1, protected)
            self.assertIn("authority-protected Cards", protected["error"])
            failed = list_operations(root, status="failed", limit=20)
            prune_failures = [
                operation
                for operation in failed["operations"]
                if operation["operation_type"] == "cli_prune_memory"
            ]
            self.assertEqual(len(prune_failures), 1, failed)
            self.assertEqual(prune_failures[0]["status"], "failed")
            conn = connect(root)
            try:
                statuses = {
                    str(row["id"]): str(row["status"])
                    for row in conn.execute("SELECT id, status FROM cards").fetchall()
                }
                state_after = dict(
                    conn.execute(
                        "SELECT status, supersedes_card_id, superseded_by_card_id, conflict_group FROM cards WHERE id = ?",
                        (state["card_id"],),
                    ).fetchone()
                )
            finally:
                conn.close()
            self.assertEqual(statuses[marker_ids["%"]], "archived")
            self.assertEqual(statuses[marker_ids["_"]], "pending_librarian_review")
            self.assertEqual(statuses[marker_ids["\\"]], "pending_librarian_review")
            self.assertEqual(statuses[plain_id], "pending_librarian_review")
            self.assertEqual(state_after, state_before)

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

    @unittest.skipUnless(os.name == "nt", "identity-bound restore cleanup requires Windows")
    def test_disposable_restore_drill_cleans_root_after_late_copy_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(
                root,
                session_id="restore-copy-failure",
                event_type="message",
                role="user",
                content="late copy failure",
            )
            snap = snapshot(root, reason="restore_copy_failure")
            real_copy = operations_module._restore_copy_file

            def copy_then_fail(source_root: Path, source: Path, destination: Path) -> None:
                real_copy(source_root, source, destination)
                if destination.name == "catalog.sqlite3":
                    raise RuntimeError("late restore copy failed")

            with (
                patch(
                    "continuum.core.operations._restore_copy_file",
                    side_effect=copy_then_fail,
                ),
                self.assertRaisesRegex(RuntimeError, "late restore copy failed"),
            ):
                restore_drill(
                    root,
                    snapshot_uri=snap["snapshot_uri"],
                    verify_recent_proof_packs=0,
                    retain_drill_root=False,
                )

            drill_parent = root / "run" / "restore_drills"
            self.assertEqual(list(drill_parent.glob("restore_*")), [])

    def test_retained_restore_drill_keeps_root_after_late_copy_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(
                root,
                session_id="restore-retained-failure",
                event_type="message",
                role="user",
                content="retained late failure",
            )
            snap = snapshot(root, reason="restore_retained_failure")
            real_copy = operations_module._restore_copy_file

            def copy_then_fail(source_root: Path, source: Path, destination: Path) -> None:
                real_copy(source_root, source, destination)
                if destination.name == "catalog.sqlite3":
                    raise RuntimeError("retained restore copy failed")

            with (
                patch(
                    "continuum.core.operations._restore_copy_file",
                    side_effect=copy_then_fail,
                ),
                self.assertRaisesRegex(RuntimeError, "retained restore copy failed"),
            ):
                restore_drill(
                    root,
                    snapshot_uri=snap["snapshot_uri"],
                    verify_recent_proof_packs=0,
                    retain_drill_root=True,
                )

            drill_parent = root / "run" / "restore_drills"
            retained = list(drill_parent.glob("restore_*"))
            self.assertEqual(len(retained), 1)
            self.assertTrue((retained[0] / "catalog" / "catalog.sqlite3").exists())

    @unittest.skipUnless(os.name == "nt", "identity-bound restore cleanup requires Windows")
    def test_disposable_restore_drill_cleans_root_after_late_check_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(
                root,
                session_id="restore-check-failure",
                event_type="message",
                role="user",
                content="late check failure",
            )
            snap = snapshot(root, reason="restore_check_failure")

            with (
                patch(
                    "continuum.core.operations.status",
                    side_effect=RuntimeError("late restore check failed"),
                ),
                self.assertRaisesRegex(RuntimeError, "late restore check failed"),
            ):
                restore_drill(
                    root,
                    snapshot_uri=snap["snapshot_uri"],
                    verify_recent_proof_packs=0,
                    retain_drill_root=False,
                )

            drill_parent = root / "run" / "restore_drills"
            self.assertEqual(list(drill_parent.glob("restore_*")), [])

    def test_cleanup_refusal_does_not_replace_restore_drill_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(
                root,
                session_id="restore-cleanup-refusal",
                event_type="message",
                role="user",
                content="cleanup refusal",
            )
            snap = snapshot(root, reason="restore_cleanup_refusal")
            real_copy = operations_module._restore_copy_file

            def copy_then_fail(source_root: Path, source: Path, destination: Path) -> None:
                real_copy(source_root, source, destination)
                if destination.name == "catalog.sqlite3":
                    raise RuntimeError("original restore failure")

            with (
                patch(
                    "continuum.core.operations._restore_copy_file",
                    side_effect=copy_then_fail,
                ),
                patch(
                    "continuum.core.operations._cleanup_restore_drill_root",
                    side_effect=ValueError("cleanup target refused"),
                ),
                self.assertRaisesRegex(RuntimeError, "original restore failure") as raised,
            ):
                restore_drill(
                    root,
                    snapshot_uri=snap["snapshot_uri"],
                    verify_recent_proof_packs=0,
                    retain_drill_root=False,
                )

            notes = getattr(raised.exception, "__notes__", [])
            self.assertEqual(len(notes), 1)
            self.assertIn("cleanup target refused", notes[0])
            self.assertLessEqual(len(notes[0]), 500)

    def test_restore_drill_collision_is_never_cleaned_as_disposable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(
                root,
                session_id="restore-collision",
                event_type="message",
                role="user",
                content="collision",
            )
            snap = snapshot(root, reason="restore_collision")
            drill_id = "restore_collision_fixture"
            collision = root / "run" / "restore_drills" / drill_id
            collision.mkdir(parents=True)
            marker = collision / "unrelated-marker.txt"
            marker.write_text("must remain", encoding="utf-8")

            with (
                patch("continuum.core.operations.unique_id", return_value=drill_id),
                self.assertRaisesRegex(FileExistsError, "already exists"),
            ):
                restore_drill(
                    root,
                    snapshot_uri=snap["snapshot_uri"],
                    verify_recent_proof_packs=0,
                    retain_drill_root=False,
                )

            self.assertEqual(marker.read_text(encoding="utf-8"), "must remain")

    @unittest.skipUnless(os.name == "nt", "Windows atomic restore-root reservation contract")
    def test_native_reservation_blocks_swap_before_identity_capture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "epic-continuum"
            append_scroll_event(
                root,
                session_id="restore-reservation-swap",
                event_type="message",
                role="user",
                content="reservation swap",
            )
            snap = snapshot(root, reason="restore_reservation_swap")
            drill_id = "restore_atomic_reservation_fixture"
            drill_root = root / "run" / "restore_drills" / drill_id
            parked = drill_root.with_name(drill_root.name + ".parked")
            replacement = base / "unrelated-reservation-replacement"
            replacement.mkdir()
            marker = replacement / "unrelated-marker.txt"
            marker.write_text("must remain", encoding="utf-8")
            real_unique_id = operations_module.unique_id
            real_fstat = review_bridge_module._WindowsNativeConfinement.fstat
            attempted = False

            def fixed_restore_id(prefix: str) -> str:
                return drill_id if prefix == "restore" else real_unique_id(prefix)

            def attempt_swap_before_identity_capture(native: object, handle: int) -> os.stat_result:
                nonlocal attempted
                if drill_root.exists() and not attempted:
                    attempted = True
                    with self.assertRaises(PermissionError):
                        os.rename(drill_root, parked)
                return real_fstat(native, handle)

            with (
                patch(
                    "continuum.core.operations.unique_id",
                    side_effect=fixed_restore_id,
                ),
                patch.object(
                    review_bridge_module._WindowsNativeConfinement,
                    "fstat",
                    new=attempt_swap_before_identity_capture,
                ),
            ):
                result = restore_drill(
                    root,
                    snapshot_uri=snap["snapshot_uri"],
                    verify_recent_proof_packs=0,
                    retain_drill_root=True,
                )

            self.assertTrue(attempted)
            self.assertTrue(result["ok"], result["checks"])
            self.assertEqual(Path(result["drill_root"]), drill_root)
            self.assertEqual(marker.read_text(encoding="utf-8"), "must remain")
            self.assertFalse(parked.exists())

    @unittest.skipUnless(os.name == "nt", "Windows pinned restore-root cleanup contract")
    def test_cleanup_boundary_root_swap_is_blocked_and_original_exception_wins(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "epic-continuum"
            append_scroll_event(
                root,
                session_id="restore-root-swap",
                event_type="message",
                role="user",
                content="root swap",
            )
            snap = snapshot(root, reason="restore_root_swap")
            replacement = base / "unrelated-replacement"
            replacement.mkdir()
            marker = replacement / "unrelated-marker.txt"
            marker.write_text("must remain", encoding="utf-8")
            real_copy = operations_module._restore_copy_file
            real_delete_tree = operations_module._delete_windows_restore_tree
            observed: dict[str, Path] = {}

            def copy_then_fail(
                source_root: Path,
                source: Path,
                destination: Path,
            ) -> None:
                real_copy(source_root, source, destination)
                if destination.name == "catalog.sqlite3":
                    raise RuntimeError("original failure before cleanup boundary")

            def attempt_swap_at_cleanup_boundary(
                reservation: object,
                path: Path,
                handle: int,
            ) -> None:
                if "drill_root" not in observed:
                    parked = path.with_name(path.name + ".parked")
                    with self.assertRaises(PermissionError):
                        os.rename(path, parked)
                    observed.update(drill_root=path, parked=parked)
                real_delete_tree(reservation, path, handle)

            with (
                patch(
                    "continuum.core.operations._restore_copy_file",
                    side_effect=copy_then_fail,
                ),
                patch(
                    "continuum.core.operations._delete_windows_restore_tree",
                    side_effect=attempt_swap_at_cleanup_boundary,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "original failure before cleanup boundary",
                ) as raised,
            ):
                restore_drill(
                    root,
                    snapshot_uri=snap["snapshot_uri"],
                    verify_recent_proof_packs=0,
                    retain_drill_root=False,
                )

            self.assertEqual(marker.read_text(encoding="utf-8"), "must remain")
            self.assertFalse(observed["drill_root"].exists())
            self.assertFalse(observed["parked"].exists())
            notes = getattr(raised.exception, "__notes__", [])
            self.assertEqual(notes, [])

    @unittest.skipUnless(os.name == "nt", "identity-bound restore cleanup requires Windows")
    def test_disposable_restore_drill_normal_cleanup_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(
                root,
                session_id="restore-normal-cleanup",
                event_type="message",
                role="user",
                content="normal cleanup",
            )
            snap = snapshot(root, reason="restore_normal_cleanup")

            result = restore_drill(
                root,
                snapshot_uri=snap["snapshot_uri"],
                verify_recent_proof_packs=0,
                retain_drill_root=False,
            )

            self.assertTrue(result["ok"], result["checks"])
            self.assertFalse(Path(result["drill_root"]).exists())
            checks = {check["name"]: check for check in result["checks"]}
            self.assertTrue(checks["drill_root_cleanup"]["ok"])

    def test_unavailable_identity_cleanup_is_retained_and_reported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(
                root,
                session_id="restore-unavailable-cleanup",
                event_type="message",
                role="user",
                content="retain unavailable cleanup",
            )
            snap = snapshot(root, reason="restore_unavailable_cleanup")

            def reserve_without_delete_binding(
                source_root: Path,
                drill_root: Path,
            ) -> object:
                del source_root
                drill_root.parent.mkdir(parents=True, exist_ok=True)
                os.mkdir(drill_root)
                metadata = os.lstat(drill_root)
                return operations_module._RestoreDrillRootReservation(
                    path=drill_root,
                    identity=operations_module._restore_drill_root_identity(metadata),
                )

            with patch(
                "continuum.core.operations._reserve_restore_drill_root",
                side_effect=reserve_without_delete_binding,
            ):
                result = restore_drill(
                    root,
                    snapshot_uri=snap["snapshot_uri"],
                    verify_recent_proof_packs=0,
                    retain_drill_root=False,
                )

            self.assertFalse(result["ok"], result["checks"])
            self.assertTrue(result["drill_root_retained"])
            self.assertEqual(
                result["drill_root_cleanup_status"],
                "identity_capability_unavailable",
            )
            self.assertTrue(Path(result["drill_root"]).exists())
            checks = {check["name"]: check for check in result["checks"]}
            self.assertEqual(
                checks["drill_root_cleanup"]["status"],
                "identity_capability_unavailable",
            )
            stored = json.loads(Path(result["receipt_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(
                stored["drill_root_cleanup_status"],
                "identity_capability_unavailable",
            )

    def test_restore_cleanup_lstat_failure_is_not_absence(self) -> None:
        with (
            patch.object(
                operations_module.os,
                "lstat",
                side_effect=PermissionError("restore lstat denied"),
            ),
            self.assertRaisesRegex(PermissionError, "restore lstat denied"),
        ):
            operations_module._strict_path_absent(Path("restore_candidate"))

    def test_restore_cleanup_failure_is_distinct_from_missing_capability(self) -> None:
        reservation = operations_module._RestoreDrillRootReservation(
            path=Path("restore_candidate"),
            identity=(1, 2, stat.S_IFDIR),
        )
        with patch.object(
            operations_module,
            "_cleanup_restore_drill_root_impl",
            side_effect=PermissionError("cleanup inspection denied"),
        ):
            cleanup = operations_module._cleanup_restore_drill_root(
                Path("root"),
                reservation.path,
                reservation=reservation,
            )

        self.assertFalse(cleanup["ok"])
        self.assertEqual(cleanup["status"], "cleanup_failed_or_incomplete")
        self.assertIn("cleanup inspection denied", cleanup["error"])

    def test_reservation_close_failure_downgrades_successful_cleanup_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(
                root,
                session_id="restore-close-status",
                event_type="message",
                role="user",
                content="report close failure as incomplete cleanup",
            )
            snap = snapshot(root, reason="restore_close_status")
            real_close = operations_module._close_restore_drill_reservation
            fail_once = True

            def close_then_report_failure(reservation: object) -> None:
                nonlocal fail_once
                real_close(reservation)
                if fail_once:
                    fail_once = False
                    raise OSError("reservation close failed after cleanup")

            with patch.object(
                operations_module,
                "_close_restore_drill_reservation",
                side_effect=close_then_report_failure,
            ):
                result = restore_drill(
                    root,
                    snapshot_uri=snap["snapshot_uri"],
                    verify_recent_proof_packs=0,
                    retain_drill_root=False,
                )

            checks = {check["name"]: check for check in result["checks"]}
            self.assertFalse(result["ok"], result)
            self.assertEqual(
                result["drill_root_cleanup_status"],
                "cleanup_failed_or_incomplete",
            )
            self.assertFalse(checks["drill_root_cleanup"]["ok"])
            self.assertEqual(
                checks["drill_root_cleanup"]["status"],
                "cleanup_failed_or_incomplete",
            )
            self.assertFalse(checks["drill_root_reservation_closed"]["ok"])
            self.assertEqual(
                result["drill_root_cleanup_path_state"],
                "absent" if os.name == "nt" else "bound_inspected_tree_retained",
            )
            self.assertEqual(result["drill_root_retained"], os.name != "nt")
            stored = json.loads(Path(result["receipt_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(
                stored["drill_root_cleanup_status"],
                "cleanup_failed_or_incomplete",
            )

    @unittest.skipIf(os.name == "nt", "POSIX descriptor-relative cleanup lifecycle")
    def test_posix_disposable_restore_drill_inspects_and_preserves_bound_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(
                root,
                session_id="restore-posix-sanitize",
                event_type="message",
                role="user",
                content="sanitize disposable payload",
            )
            snap = snapshot(root, reason="restore_posix_sanitize")

            with patch.object(operations_module.os, "ftruncate") as ftruncate:
                result = restore_drill(
                    root,
                    snapshot_uri=snap["snapshot_uri"],
                    verify_recent_proof_packs=0,
                    retain_drill_root=False,
                )

            drill_root = Path(result["drill_root"])
            self.assertTrue(result["ok"], result["checks"])
            self.assertEqual(
                result["drill_root_cleanup_status"],
                "inspected_root_retained",
            )
            self.assertTrue(result["drill_root_retained"])
            self.assertTrue(drill_root.is_dir())
            retained_files = [path for path in drill_root.rglob("*") if path.is_file()]
            self.assertGreater(len(retained_files), 0)
            self.assertTrue(any(path.stat().st_size > 0 for path in retained_files))
            self.assertFalse(any(path.is_symlink() for path in drill_root.rglob("*")))
            self.assertEqual(
                result["drill_root_retained_file_count"],
                len(retained_files),
            )
            self.assertEqual(
                result["drill_root_retained_bytes"],
                sum(path.stat().st_size for path in retained_files),
            )
            cleanup_check = next(
                check for check in result["checks"] if check["name"] == "drill_root_cleanup"
            )
            self.assertEqual(
                cleanup_check["retained_file_count"],
                result["drill_root_retained_file_count"],
            )
            self.assertEqual(
                cleanup_check["retained_bytes"],
                result["drill_root_retained_bytes"],
            )
            ftruncate.assert_not_called()

    @unittest.skipIf(os.name == "nt", "POSIX pinned-directory rename contract")
    def test_posix_moved_reserved_root_is_inspected_but_never_reported_cleaned(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            drill_root = root / "run" / "restore_drills" / "restore_moved_fixture"
            parked = drill_root.with_name(drill_root.name + ".parked")
            reservation = operations_module._reserve_restore_drill_root(root, drill_root)
            try:
                payload = drill_root / "nested" / "payload.txt"
                payload.parent.mkdir()
                payload.write_text("disposable", encoding="utf-8")
                os.rename(drill_root, parked)

                cleanup = operations_module._cleanup_restore_drill_root(
                    root,
                    drill_root,
                    reservation=reservation,
                )

                self.assertFalse(cleanup["ok"])
                self.assertNotEqual(cleanup["status"], "cleaned")
                self.assertEqual(cleanup["status"], "inspected_root_moved")
                self.assertFalse(os.path.lexists(drill_root))
                self.assertTrue(parked.is_dir())
                self.assertTrue((parked / "nested").is_dir())
                self.assertEqual(
                    (parked / "nested" / "payload.txt").read_text(encoding="utf-8"),
                    "disposable",
                )
            finally:
                operations_module._close_restore_drill_reservation(reservation)
                if parked.exists():
                    shutil.rmtree(parked)

    @unittest.skipIf(os.name == "nt", "POSIX reservation identity race contract")
    def test_posix_reservation_failure_never_removes_unbound_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            drill_root = root / "run" / "restore_drills" / "restore_reservation_race"
            parked = drill_root.with_name(drill_root.name + ".parked")
            real_fstat = os.fstat
            real_lstat = os.lstat
            armed = False
            swapped = False

            def arm_after_fstat(fd: int) -> os.stat_result:
                nonlocal armed
                metadata = real_fstat(fd)
                armed = True
                return metadata

            def swap_before_path_identity(path: object) -> os.stat_result:
                nonlocal swapped
                candidate = Path(path)
                if armed and not swapped and candidate == drill_root:
                    swapped = True
                    os.rename(drill_root, parked)
                    os.mkdir(drill_root)
                return real_lstat(path)

            try:
                with (
                    patch.object(operations_module.os, "fstat", side_effect=arm_after_fstat),
                    patch.object(operations_module.os, "lstat", side_effect=swap_before_path_identity),
                    self.assertRaisesRegex(ValueError, "not a physical directory"),
                ):
                    operations_module._reserve_restore_drill_root(root, drill_root)

                self.assertTrue(swapped)
                self.assertTrue(parked.is_dir())
                self.assertTrue(drill_root.is_dir())
            finally:
                if drill_root.exists():
                    drill_root.rmdir()
                if parked.exists():
                    parked.rmdir()

    @unittest.skipIf(os.name == "nt", "POSIX nonblocking descriptor-open contract")
    def test_posix_cleanup_file_swap_to_fifo_fails_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            payload = directory / "payload.txt"
            payload.write_text("disposable", encoding="utf-8")
            directory_fd = os.open(
                directory,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            real_open = os.open
            real_stat = os.stat
            swapped = False

            def swap_after_first_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
                nonlocal swapped
                metadata = real_stat(path, *args, **kwargs)
                if path == payload.name and not swapped:
                    swapped = True
                    payload.unlink()
                    os.mkfifo(payload)
                return metadata

            def require_nonblocking_open(
                path: object,
                flags: int,
                mode: int = 0o777,
                *,
                dir_fd: int | None = None,
            ) -> int:
                if path == payload.name:
                    self.assertNotEqual(flags & getattr(os, "O_NONBLOCK", 0), 0)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            try:
                with (
                    patch.object(operations_module.os, "stat", side_effect=swap_after_first_stat),
                    patch.object(operations_module.os, "open", side_effect=require_nonblocking_open),
                    self.assertRaisesRegex(ValueError, "changed after descriptor open"),
                ):
                    operations_module._inspect_posix_retained_restore_tree(directory_fd)
                self.assertTrue(swapped)
            finally:
                os.close(directory_fd)
                if os.path.lexists(payload):
                    payload.unlink()

    @unittest.skipIf(os.name == "nt", "POSIX hardlink-preservation contract")
    def test_posix_cleanup_refuses_hardlink_without_reaching_ftruncate_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "epic-continuum"
            init_db(root)
            drill_root = root / "run" / "restore_drills" / "restore_hardlink_fixture"
            reservation = operations_module._reserve_restore_drill_root(root, drill_root)
            outside = base / "outside-hardlink.txt"
            payload = drill_root / "payload.txt"
            original = b"outside hardlink bytes must survive"
            try:
                payload.write_bytes(original)
                os.link(payload, outside)

                with patch.object(operations_module.os, "ftruncate") as ftruncate:
                    cleanup = operations_module._cleanup_restore_drill_root(
                        root,
                        drill_root,
                        reservation=reservation,
                    )

                self.assertFalse(cleanup["ok"], cleanup)
                self.assertEqual(cleanup["status"], "cleanup_failed_or_incomplete")
                self.assertTrue(cleanup["root_retained"])
                self.assertIn("multiply linked", cleanup["error"])
                self.assertEqual(payload.read_bytes(), original)
                self.assertEqual(outside.read_bytes(), original)
                self.assertEqual(payload.stat().st_nlink, 2)
                self.assertEqual(outside.stat().st_nlink, 2)
                ftruncate.assert_not_called()
            finally:
                operations_module._close_restore_drill_reservation(reservation)

    @unittest.skipIf(os.name == "nt", "POSIX hardlink-verification contract")
    def test_posix_retained_tree_inspection_rejects_hardlinked_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            directory = base / "sanitized-root"
            directory.mkdir()
            payload = directory / "payload.txt"
            outside = base / "outside-hardlink.txt"
            payload.write_bytes(b"preserved hardlink payload")
            os.link(payload, outside)
            directory_fd = os.open(
                directory,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                with self.assertRaisesRegex(ValueError, "multiply linked"):
                    operations_module._inspect_posix_retained_restore_tree(directory_fd)
                self.assertEqual(payload.read_bytes(), b"preserved hardlink payload")
                self.assertEqual(outside.read_bytes(), b"preserved hardlink payload")
                self.assertEqual(outside.stat().st_nlink, 2)
            finally:
                os.close(directory_fd)

    @unittest.skipIf(os.name == "nt", "POSIX conservative unlink-boundary contract")
    def test_posix_cleanup_never_deletes_at_unlink_swap_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            payload = directory / "payload.txt"
            parked = directory / "payload.txt.parked"
            payload.write_text("exact original", encoding="utf-8")
            directory_fd = os.open(
                directory,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            real_unlink = os.unlink
            attempted = False

            def swap_inside_unlink(
                path: object,
                *args: object,
                dir_fd: int | None = None,
                **kwargs: object,
            ) -> None:
                nonlocal attempted
                attempted = True
                os.rename(payload, parked)
                payload.write_text("replacement must survive", encoding="utf-8")
                real_unlink(path, *args, dir_fd=dir_fd, **kwargs)

            try:
                with patch.object(
                    operations_module.os,
                    "unlink",
                    side_effect=swap_inside_unlink,
                ):
                    operations_module._inspect_posix_retained_restore_tree(directory_fd)

                self.assertFalse(attempted)
                self.assertFalse(parked.exists())
                self.assertTrue(payload.is_file())
                self.assertEqual(payload.read_text(encoding="utf-8"), "exact original")
                operations_module._inspect_posix_retained_restore_tree(directory_fd)
            finally:
                os.close(directory_fd)

    @unittest.skipIf(os.name == "nt", "POSIX conservative rmdir-boundary contract")
    def test_posix_cleanup_never_deletes_at_rmdir_swap_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            child = directory / "nested"
            parked = directory / "nested.parked"
            child.mkdir()
            directory_fd = os.open(
                directory,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            real_rmdir = os.rmdir
            attempted = False

            def swap_inside_rmdir(
                path: object,
                *args: object,
                dir_fd: int | None = None,
                **kwargs: object,
            ) -> None:
                nonlocal attempted
                attempted = True
                os.rename(child, parked)
                child.mkdir()
                real_rmdir(path, *args, dir_fd=dir_fd, **kwargs)

            try:
                with patch.object(
                    operations_module.os,
                    "rmdir",
                    side_effect=swap_inside_rmdir,
                ):
                    operations_module._inspect_posix_retained_restore_tree(directory_fd)

                self.assertFalse(attempted)
                self.assertFalse(parked.exists())
                self.assertTrue(child.is_dir())
                operations_module._inspect_posix_retained_restore_tree(directory_fd)
            finally:
                os.close(directory_fd)

    def test_unavailable_exception_cleanup_keeps_original_failure_primary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(
                root,
                session_id="restore-unavailable-exception",
                event_type="message",
                role="user",
                content="retain exceptional cleanup",
            )
            snap = snapshot(root, reason="restore_unavailable_exception")
            real_copy = operations_module._restore_copy_file
            observed: dict[str, Path] = {}

            def reserve_without_delete_binding(
                source_root: Path,
                drill_root: Path,
            ) -> object:
                del source_root
                drill_root.parent.mkdir(parents=True, exist_ok=True)
                os.mkdir(drill_root)
                metadata = os.lstat(drill_root)
                observed["drill_root"] = drill_root
                return operations_module._RestoreDrillRootReservation(
                    path=drill_root,
                    identity=operations_module._restore_drill_root_identity(metadata),
                )

            def copy_then_fail(source_root: Path, source: Path, destination: Path) -> None:
                real_copy(source_root, source, destination)
                if destination.name == "catalog.sqlite3":
                    raise RuntimeError("original restore exception")

            with (
                patch(
                    "continuum.core.operations._reserve_restore_drill_root",
                    side_effect=reserve_without_delete_binding,
                ),
                patch(
                    "continuum.core.operations._restore_copy_file",
                    side_effect=copy_then_fail,
                ),
                self.assertRaisesRegex(RuntimeError, "original restore exception") as raised,
            ):
                restore_drill(
                    root,
                    snapshot_uri=snap["snapshot_uri"],
                    verify_recent_proof_packs=0,
                    retain_drill_root=False,
                )

            self.assertTrue(observed["drill_root"].exists())
            notes = getattr(raised.exception, "__notes__", [])
            self.assertEqual(len(notes), 1)
            self.assertIn("identity-bound restore-drill cleanup is unavailable", notes[0])

    def test_cleanup_and_close_failures_do_not_replace_primary_restore_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(
                root,
                session_id="restore-multiple-cleanup-failures",
                event_type="message",
                role="user",
                content="preserve primary cleanup error",
            )
            snap = snapshot(root, reason="restore_multiple_cleanup_failures")
            real_copy = operations_module._restore_copy_file
            real_close = operations_module._close_restore_drill_reservation

            def copy_then_fail(source_root: Path, source: Path, destination: Path) -> None:
                real_copy(source_root, source, destination)
                if destination.name == "catalog.sqlite3":
                    raise RuntimeError("primary restore error")

            def close_then_fail(reservation: object) -> None:
                real_close(reservation)
                raise OSError("reservation close error")

            with (
                patch.object(
                    operations_module,
                    "_restore_copy_file",
                    side_effect=copy_then_fail,
                ),
                patch.object(
                    operations_module,
                    "_cleanup_restore_drill_root",
                    side_effect=ValueError("cleanup refusal error"),
                ),
                patch.object(
                    operations_module,
                    "_close_restore_drill_reservation",
                    side_effect=close_then_fail,
                ),
                self.assertRaisesRegex(RuntimeError, "primary restore error") as raised,
            ):
                restore_drill(
                    root,
                    snapshot_uri=snap["snapshot_uri"],
                    verify_recent_proof_packs=0,
                    retain_drill_root=False,
                )

            notes = getattr(raised.exception, "__notes__", [])
            self.assertEqual(len(notes), 2)
            self.assertIn("cleanup refusal error", notes[0])
            self.assertIn("reservation close error", notes[1])
            self.assertTrue(all(len(note) <= 500 for note in notes))

    def test_restore_drill_preserves_review_bridge_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "epic-continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Restore fixture\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review restore fixture.",
                transport="manual",
            )
            review_artifact = Path(job["packet_uri"])
            payload = review_artifact.read_bytes()
            snap = snapshot(root, reason="review_bridge_restore")

            result = restore_drill(
                root,
                snapshot_uri=snap["snapshot_uri"],
                verify_recent_proof_packs=0,
            )

            self.assertTrue(result["ok"], result["checks"])
            self.assertIn("exports/review_bridge/jobs", result["copied_durable_paths"])
            restored_artifact = (
                Path(result["drill_root"])
                / root_uri(root, review_artifact)
            )
            self.assertEqual(restored_artifact.read_bytes(), payload)
            self.assertTrue(result["artifact_ledger"]["ok"], result["artifact_ledger"])
            self.assertEqual(result["artifact_ledger"]["missing"], 0)

    def test_snapshot_refuses_missing_immutable_artifact_ledger_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            artifact = root / "exports" / "local-proof.txt"
            artifact.parent.mkdir(parents=True, exist_ok=True)
            payload = b"durable proof\n"
            artifact.write_bytes(payload)
            conn = connect(root)
            try:
                record_artifact(
                    conn,
                    kind="local_proof",
                    uri=root_uri(root, artifact),
                    sha256=hashlib.sha256(payload).hexdigest(),
                    size_bytes=len(payload),
                    source_type="local_test",
                    trust_level="local_generated",
                    immutable=True,
                )
                conn.commit()
            finally:
                conn.close()
            artifact.unlink()

            with self.assertRaisesRegex(ValueError, "immutable artifact ledger"):
                snapshot(root, reason="missing_immutable_artifact")

    def test_restore_drill_uses_snapshot_paired_review_jobs_after_later_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "epic-continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Snapshot-paired review\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            review_browser_attempt_start(root, job_id=job["job_id"])
            frozen = snapshot(root, reason="review_pair_before_later_attempts")
            frozen_manifest = json.loads(Path(frozen["snapshot_manifest_uri"]).read_text(encoding="utf-8"))
            paired_jobs = root / str(frozen_manifest["review_bridge_jobs"]["uri"])
            self.assertTrue((paired_jobs / job["job_id"] / "attempts" / "attempt-001.json").is_file())

            review_browser_attempt_start(root, job_id=job["job_id"])
            review_browser_attempt_start(root, job_id=job["job_id"])
            self.assertEqual(review_job_status(root, job_id=job["job_id"])["attempt_count"], 3)

            result = restore_drill(
                root,
                snapshot_uri=frozen["snapshot_uri"],
                verify_recent_proof_packs=0,
            )

            self.assertTrue(result["ok"], result["checks"])
            self.assertEqual(result["review_bridge_jobs_restore"]["mode"], "snapshot_pair")
            self.assertIn("exports/review_bridge/jobs", result["copied_durable_paths"])
            drill_root = Path(result["drill_root"])
            restored_status = review_job_status(drill_root, job_id=job["job_id"])
            self.assertEqual(restored_status["attempt_count"], 1)
            self.assertEqual(Path(restored_status["last_attempt_uri"]).name, "attempt-001.json")
            restored_attempts = drill_root / "exports" / "review_bridge" / "jobs" / job["job_id"] / "attempts"
            self.assertEqual(
                sorted(path.name for path in restored_attempts.glob("attempt-*.json")),
                ["attempt-001.json"],
            )
            self.assertTrue(result["semantic_integrity"]["ok"], result["semantic_integrity"])
            self.assertTrue(result["artifact_ledger"]["ok"], result["artifact_ledger"])

    def test_legacy_snapshot_without_review_evidence_restores_empty_jobs_not_live_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "epic-continuum"
            init_db(root)
            frozen = snapshot(root, reason="legacy_pre_review_snapshot")
            legacy_manifest = downgrade_snapshot_manifest_to_legacy_without_review_pair(
                root,
                Path(frozen["snapshot_uri"]),
            )
            self.assertEqual(legacy_manifest["schema"], "epic_continuum.snapshot_manifest.v2")
            subject = base / "later-subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Later review\n", encoding="utf-8")
            live_job = create_review_job(root, subject_path=subject, prompt="Review later.", transport="manual")
            self.assertTrue(Path(live_job["job_dir"]).is_dir())

            result = restore_drill(
                root,
                snapshot_uri=frozen["snapshot_uri"],
                verify_recent_proof_packs=0,
            )

            self.assertTrue(result["ok"], result["checks"])
            self.assertEqual(result["review_bridge_jobs_restore"]["mode"], "legacy_empty_catalog")
            self.assertNotIn("exports/review_bridge/jobs", result["copied_durable_paths"])
            restored_jobs = Path(result["drill_root"]) / "exports" / "review_bridge" / "jobs"
            self.assertFalse(restored_jobs.exists())

    def test_legacy_snapshot_with_review_evidence_but_no_pair_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "epic-continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Legacy review evidence\n", encoding="utf-8")
            create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            frozen = snapshot(root, reason="legacy_review_snapshot")
            downgrade_snapshot_manifest_to_legacy_without_review_pair(root, Path(frozen["snapshot_uri"]))

            result = restore_drill(
                root,
                snapshot_uri=frozen["snapshot_uri"],
                verify_recent_proof_packs=0,
            )

            self.assertFalse(result["ok"])
            self.assertEqual(result["reason"], "legacy_snapshot_review_bridge_jobs_unbound")
            self.assertGreater(result["frozen_review_bridge_evidence"]["count"], 0)

    def test_snapshot_review_jobs_manifest_rejects_extra_and_missing_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "epic-continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Review tree manifest\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            for mutation in ("extra", "missing"):
                with self.subTest(mutation=mutation):
                    frozen = snapshot(root, reason=f"review_tree_{mutation}")
                    manifest = json.loads(Path(frozen["snapshot_manifest_uri"]).read_text(encoding="utf-8"))
                    paired_jobs = root / str(manifest["review_bridge_jobs"]["uri"])
                    if mutation == "extra":
                        (paired_jobs / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
                    else:
                        (paired_jobs / job["job_id"] / "status.json").unlink()
                    verification = store_module.verify_snapshot_manifest_for_root(
                        Path(frozen["snapshot_uri"]),
                        root=root,
                        require_catalog_binding=True,
                    )
                    self.assertFalse(verification["ok"])
                    self.assertTrue(
                        any(
                            error.get("error") == "review_bridge_jobs_tree_mismatch"
                            for error in verification["errors"]
                        ),
                        verification["errors"],
                    )

    def test_restore_drill_checks_artifact_ledger_beyond_500_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "epic-continuum"
            init_db(root)
            artifact_dir = root / "exports" / "proof_artifacts" / "large-ledger"
            artifact_dir.mkdir(parents=True)
            oldest_artifact: Path | None = None
            oldest_artifact_id: str | None = None
            conn = connect(root)
            try:
                baseline_immutable_count = int(
                    conn.execute(
                        "SELECT COUNT(*) AS count FROM artifacts WHERE immutable = 1"
                    ).fetchone()["count"]
                )
                for index in range(501):
                    artifact = artifact_dir / f"findings-{index + 1:03d}.json"
                    payload = f'{{"finding":{index}}}\n'.encode()
                    artifact.write_bytes(payload)
                    artifact_id = record_artifact(
                        conn,
                        kind="large_ledger_proof",
                        uri=root_uri(root, artifact),
                        sha256=hashlib.sha256(payload).hexdigest(),
                        size_bytes=len(payload),
                        source_type="local_generated",
                        trust_level="local_artifact",
                        metadata={"fixture": "large-ledger", "index": index},
                        immutable=True,
                    )
                    if index == 0:
                        oldest_artifact = artifact
                        oldest_artifact_id = artifact_id
                assert oldest_artifact_id is not None
                conn.execute(
                    "UPDATE artifacts SET created_at = ? WHERE id = ?",
                    ("2000-01-01T00:00:00+00:00", oldest_artifact_id),
                )
                conn.commit()
            finally:
                conn.close()
            snap = snapshot(root, reason="large_artifact_ledger_restore")
            assert oldest_artifact is not None
            oldest_uri = root_uri(root, oldest_artifact)
            oldest_artifact.unlink()

            result = restore_drill(
                root,
                snapshot_uri=snap["snapshot_uri"],
                verify_recent_proof_packs=0,
            )

            self.assertFalse(result["ok"], result["checks"])
            ledger = result["artifact_ledger"]
            self.assertFalse(ledger["ok"], ledger)
            self.assertEqual(ledger["row_count"], baseline_immutable_count + 501)
            self.assertEqual(ledger["missing"], 1)
            self.assertEqual(ledger["missing_artifacts"][0]["uri"], oldest_uri)

            source_ledger = _verify_artifact_ledger(root)
            self.assertFalse(source_ledger["ok"], source_ledger)
            self.assertGreaterEqual(
                source_ledger["row_count"],
                baseline_immutable_count + 501,
            )
            self.assertEqual(source_ledger["missing"], 1)

    @unittest.skipUnless(os.name == "nt", "identity-bound proof source deletion requires Windows")
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

    def test_restore_drill_uses_snapshot_sidecar_directory_after_config_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            snapshot_config = load_config(root)
            snapshot_config["atomic_memory"]["card_sidecar_dir"] = (
                "catalog/cards-a"
            )
            write_config(root, snapshot_config)
            append_scroll_event(
                root,
                session_id="sidecar-config-drift",
                event_type="message",
                role="user",
                content="Snapshot-bound sidecars remain restorable after config drift.",
            )
            roll_scroll_segment(
                root,
                session_id="sidecar-config-drift",
                start_seq=1,
                end_seq=1,
            )
            snap = snapshot(root, reason="sidecar_config_drift")

            live_config = load_config(root)
            live_config["atomic_memory"]["card_sidecar_dir"] = "catalog/cards-b"
            write_config(root, live_config)
            result = restore_drill(
                root,
                snapshot_uri=snap["snapshot_uri"],
                verify_recent_proof_packs=0,
            )

            self.assertTrue(result["ok"], result["checks"])
            self.assertEqual(
                result["restored_card_sidecar_source_uri"],
                "catalog/cards-a",
            )
            drill_root = Path(result["drill_root"])
            restored_config = load_config(drill_root)
            self.assertEqual(
                restored_config["atomic_memory"]["card_sidecar_dir"],
                "catalog/cards-a",
            )
            self.assertTrue(any((drill_root / "catalog" / "cards-a").glob("*.yaml")))

    def test_restore_drill_restores_snapshot_sidecar_write_policy_after_config_drift(self) -> None:
        for snapshot_enabled, live_enabled in ((True, False), (False, True)):
            with self.subTest(
                snapshot_enabled=snapshot_enabled,
                live_enabled=live_enabled,
            ), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "epic-continuum"
                init_db(root)
                snapshot_config = load_config(root)
                snapshot_config["atomic_memory"][
                    "write_card_sidecars"
                ] = snapshot_enabled
                write_config(root, snapshot_config)
                if snapshot_enabled:
                    append_scroll_event(
                        root,
                        session_id="sidecar-policy-snapshot",
                        event_type="message",
                        role="user",
                        content="Bind the enabled sidecar policy to this snapshot.",
                    )
                    roll_scroll_segment(
                        root,
                        session_id="sidecar-policy-snapshot",
                        start_seq=1,
                        end_seq=1,
                    )
                snap = snapshot(root, reason="sidecar_write_policy_drift")
                manifest = json.loads(
                    snapshot_manifest_path(Path(snap["snapshot_uri"])).read_text(
                        encoding="utf-8"
                    )
                )
                self.assertIs(
                    manifest["card_sidecars_write_enabled"],
                    snapshot_enabled,
                )

                live_config = load_config(root)
                live_config["atomic_memory"][
                    "write_card_sidecars"
                ] = live_enabled
                write_config(root, live_config)
                result = restore_drill(
                    root,
                    snapshot_uri=snap["snapshot_uri"],
                    verify_recent_proof_packs=0,
                )

                self.assertTrue(result["ok"], result["checks"])
                drill_root = Path(result["drill_root"])
                restored_config = load_config(drill_root)
                self.assertIs(
                    restored_config["atomic_memory"][
                        "write_card_sidecars"
                    ],
                    snapshot_enabled,
                )
                before = len(
                    list((drill_root / "catalog" / "cards").glob("*.yaml"))
                )
                append_scroll_event(
                    drill_root,
                    session_id="sidecar-policy-post-restore",
                    event_type="message",
                    role="user",
                    content="Exercise the restored write policy.",
                )
                roll_scroll_segment(
                    drill_root,
                    session_id="sidecar-policy-post-restore",
                    start_seq=1,
                    end_seq=1,
                )
                after = len(
                    list((drill_root / "catalog" / "cards").glob("*.yaml"))
                )
                self.assertEqual(after - before, int(snapshot_enabled))

    def test_restore_drill_legacy_manifest_uses_live_sidecar_write_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(
                root,
                session_id="legacy-sidecar-policy",
                event_type="message",
                role="user",
                content="Legacy manifests remain restorable.",
            )
            snap = snapshot(root, reason="legacy_sidecar_write_policy")
            snapshot_path = Path(snap["snapshot_uri"])
            manifest_path = snapshot_manifest_path(snapshot_path)
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest.pop("card_sidecars_write_enabled")
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE snapshots SET manifest_hash = ? WHERE id = ?",
                    (
                        hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                        snap["snapshot_id"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()
            live_config = load_config(root)
            live_config["atomic_memory"]["write_card_sidecars"] = False
            write_config(root, live_config)

            result = restore_drill(
                root,
                snapshot_uri=snap["snapshot_uri"],
                verify_recent_proof_packs=0,
            )

            self.assertTrue(result["ok"], result["checks"])
            self.assertFalse(result["restored_card_sidecars_write_enabled"])
            self.assertFalse(
                load_config(Path(result["drill_root"]))["atomic_memory"][
                    "write_card_sidecars"
                ]
            )

    def test_restore_drill_checks_sidecars_after_overlapping_durable_copy(self) -> None:
        for mutation in ("late_file", "changed_sidecar"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "epic-continuum"
                init_db(root)
                config = load_config(root)
                config["atomic_memory"]["card_sidecar_dir"] = "archive/cards"
                write_config(root, config)
                append_scroll_event(
                    root,
                    session_id="overlapping-sidecar-source",
                    event_type="message",
                    role="user",
                    content="Bind this sidecar before the durable overlay.",
                )
                rolled = roll_scroll_segment(
                    root,
                    session_id="overlapping-sidecar-source",
                    start_seq=1,
                    end_seq=1,
                )
                snap = snapshot(root, reason=f"sidecar_overlay_{mutation}")
                cards_dir = root / "archive" / "cards"
                if mutation == "late_file":
                    (cards_dir / "late.bin").write_bytes(b"not in snapshot")
                else:
                    conn = connect(root)
                    try:
                        conn.execute(
                            "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                            (
                                "Valid live bytes newer than the snapshot.",
                                store_module.utc_now(),
                                rolled["card_id"],
                            ),
                        )
                        store_module.mark_card_sidecar_outbox(
                            conn,
                            [rolled["card_id"]],
                            reason="post_snapshot_durable_overlay",
                        )
                        conn.commit()
                    finally:
                        conn.close()
                    self.assertTrue(
                        sync_card_sidecars_after_commit(
                            root,
                            [rolled["card_id"]],
                        )["ok"]
                    )

                result = restore_drill(
                    root,
                    snapshot_uri=snap["snapshot_uri"],
                    verify_recent_proof_packs=0,
                )

                self.assertFalse(result["ok"], result["checks"])
                checks = {check["name"]: check for check in result["checks"]}
                self.assertFalse(
                    checks[
                        "restored_card_sidecars_match_snapshot_manifest"
                    ]["ok"]
                )

    def test_restore_drill_checks_sidecars_after_recovery_probe(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            config = load_config(root)
            config["atomic_memory"][
                "card_sidecar_dir"
            ] = "run/recovery_drills"
            write_config(root, config)
            append_scroll_event(
                root,
                session_id="sidecars-overlap-recovery-probe",
                event_type="message",
                role="user",
                content="The final inventory must include later drill mutations.",
            )
            roll_scroll_segment(
                root,
                session_id="sidecars-overlap-recovery-probe",
                start_seq=1,
                end_seq=1,
            )
            snap = snapshot(root, reason="sidecars_overlap_recovery_probe")

            result = restore_drill(
                root,
                snapshot_uri=snap["snapshot_uri"],
                verify_recent_proof_packs=0,
            )

            self.assertFalse(result["ok"], result["checks"])
            checks = {check["name"]: check for check in result["checks"]}
            inventory_check = checks[
                "restored_card_sidecars_match_snapshot_manifest"
            ]
            self.assertFalse(inventory_check["ok"])
            self.assertIn("unsupported entry", inventory_check["error"])

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

    def test_restore_drill_rejects_sidecar_tree_changed_after_manifest_precheck(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(
                root,
                session_id="restore-sidecar-toctou",
                event_type="message",
                role="user",
                content="bind the copied sidecar inventory after copy",
            )
            roll_scroll_segment(
                root,
                session_id="restore-sidecar-toctou",
                start_seq=1,
                end_seq=1,
            )
            snap = snapshot(root, reason="restore_sidecar_postcopy_binding")
            snapshot_sidecars = Path(str(snap["card_sidecars_uri"]))
            real_copytree = operations_module._restore_copytree
            injected = False

            def copytree_with_late_sidecar(source_root, source, destination, **kwargs):
                nonlocal injected
                if Path(source) == snapshot_sidecars and not injected:
                    injected = True
                    (snapshot_sidecars / "unmanifested.bin").write_bytes(b"late mutation")
                return real_copytree(source_root, source, destination, **kwargs)

            with patch.object(
                operations_module,
                "_restore_copytree",
                side_effect=copytree_with_late_sidecar,
            ):
                result = restore_drill(
                    root,
                    snapshot_uri=snap["snapshot_uri"],
                    verify_recent_proof_packs=0,
                )

            self.assertTrue(injected)
            self.assertFalse(result["ok"], result["checks"])
            checks = {check["name"]: check for check in result["checks"]}
            self.assertFalse(
                checks["restored_card_sidecars_match_snapshot_manifest"]["ok"]
            )
            self.assertTrue(
                (Path(result["drill_root"]) / "catalog" / "cards" / "unmanifested.bin").is_file()
            )

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
            original_copy_file = store_module.secure_copy_file

            def corrupt_copied_sidecar(
                src: Path,
                dst: Path,
                *args: object,
                **kwargs: object,
            ) -> object:
                result = original_copy_file(src, dst, *args, **kwargs)
                if Path(src).parent == root / "catalog" / "cards":
                    sidecar = Path(dst)
                    sidecar.write_text(
                        sidecar.read_text(encoding="utf-8").replace(
                            "schema:",
                            "schema_corrupted:",
                            1,
                        ),
                        encoding="utf-8",
                    )
                return result

            with patch(
                "continuum.core.store.secure_copy_file",
                side_effect=corrupt_copied_sidecar,
            ):
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

    @unittest.skipUnless(os.name == "posix", "broken sidecar symlinks are POSIX-only")
    def test_snapshot_rejects_broken_configured_sidecar_directory_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            cards_dir = root / "catalog" / "cards"
            cards_dir.rmdir()
            cards_dir.symlink_to(root / "missing-sidecar-target", target_is_directory=True)

            integrity = store_module.semantic_integrity_report(root)
            self.assertFalse(integrity["ok"], integrity)
            self.assertEqual(
                integrity["checks"]["unsafe_card_sidecar_paths"],
                1,
                integrity,
            )
            with self.assertRaisesRegex(ValueError, "link-like card sidecar"):
                snapshot(root, reason="broken_sidecar_link_guard")

    def test_snapshot_binds_empty_review_jobs_pair_and_rootless_manifest_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)

            created = snapshot(root, reason="empty_review_pair")

            snapshot_path = Path(created["snapshot_uri"])
            manifest = json.loads(Path(created["snapshot_manifest_uri"]).read_text(encoding="utf-8"))
            binding = manifest["review_bridge_jobs"]
            pair_path = root / str(binding["uri"])
            self.assertTrue(pair_path.is_dir())
            self.assertEqual(list(pair_path.iterdir()), [])
            self.assertEqual(binding["source_uri"], "exports/review_bridge/jobs")
            self.assertEqual(binding["directory_count"], 0)
            self.assertEqual(binding["file_count"], 0)
            self.assertEqual(binding["directories"], [])
            self.assertEqual(binding["files"], {})
            rootless = store_module.verify_snapshot_manifest(snapshot_path)
            self.assertTrue(rootless["ok"], rootless)

    def test_snapshot_binds_empty_receipt_pair_when_custom_cards_dir_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            config = load_config(root)
            config["atomic_memory"][
                "card_sidecar_dir"
            ] = "catalog/not-created-cards"
            write_config(root, config)
            self.assertFalse((root / "catalog" / "not-created-cards").exists())

            created = snapshot(root, reason="empty_sidecar_receipt_pair")

            snapshot_path = Path(created["snapshot_uri"])
            manifest = json.loads(
                Path(created["snapshot_manifest_uri"]).read_text(
                    encoding="utf-8"
                )
            )
            receipt_binding = manifest["card_sidecar_receipts"]
            self.assertEqual(receipt_binding["file_count"], 0)
            self.assertEqual(receipt_binding["files"], {})
            self.assertTrue(
                (root / str(receipt_binding["uri"])).is_dir()
            )
            self.assertTrue(
                store_module.verify_snapshot_manifest(snapshot_path)["ok"]
            )
            restored = restore_drill(
                root,
                snapshot_uri=created["snapshot_uri"],
                verify_recent_proof_packs=0,
            )
            self.assertTrue(restored["ok"], restored["checks"])

    @unittest.skipUnless(os.name == "nt", "Windows 8.3 aliases are Windows-only")
    def test_restore_drill_accepts_snapshot_through_short_root_alias(self) -> None:
        import ctypes
        from ctypes import wintypes

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum-long-root"
            init_db(root)
            created = snapshot(root, reason="short_root_receipt_pair_alias")
            snapshot_path = Path(str(created["snapshot_uri"]))

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            get_short_path_name = kernel32.GetShortPathNameW
            get_short_path_name.argtypes = [
                wintypes.LPCWSTR,
                wintypes.LPWSTR,
                wintypes.DWORD,
            ]
            get_short_path_name.restype = wintypes.DWORD
            required = int(get_short_path_name(str(root), None, 0))
            if required == 0:
                self.fail(
                    "GetShortPathNameW sizing failed: "
                    f"{ctypes.WinError(ctypes.get_last_error())}"
                )
            buffer = ctypes.create_unicode_buffer(required)
            written = int(get_short_path_name(str(root), buffer, required))
            if written == 0 or written >= required:
                self.fail(
                    "GetShortPathNameW failed to return the sized alias: "
                    f"{ctypes.WinError(ctypes.get_last_error())}"
                )
            short_root = Path(buffer.value)
            if os.path.normcase(os.path.abspath(short_root)) == os.path.normcase(
                os.path.abspath(root)
            ):
                self.skipTest("volume provides no distinct 8.3 alias for the test root")
            self.assertTrue(short_root.samefile(root))

            short_snapshot = short_root / snapshot_path.relative_to(root)
            expected_pair = store_module.snapshot_card_sidecar_receipts_path(
                snapshot_path
            )
            short_pair = store_module.snapshot_card_sidecar_receipts_path(
                short_snapshot
            )
            self.assertNotEqual(short_pair, expected_pair)
            self.assertTrue(short_pair.samefile(expected_pair))

            restored = restore_drill(
                root,
                snapshot_uri=str(short_snapshot),
                verify_recent_proof_packs=0,
            )

            self.assertTrue(restored["ok"], restored["checks"])
            self.assertEqual(
                restored["restored_card_sidecar_receipts_mode"],
                "snapshot_pair",
            )

    def test_restore_drill_rejects_link_like_alias_to_source_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "epic-continuum"
            init_db(root)
            created = snapshot(root, reason="link_like_root_alias")
            snapshot_path = Path(str(created["snapshot_uri"]))
            root_alias = base / "continuum-root-alias"
            make_link_like_dir(self, root_alias, root)
            aliased_snapshot = root_alias / snapshot_path.relative_to(root)

            with self.assertRaisesRegex(
                ValueError,
                "unsafe_restore_drill_source_paths: source outside root",
            ):
                restore_drill(
                    root,
                    snapshot_uri=str(aliased_snapshot),
                    verify_recent_proof_packs=0,
                )

    def test_snapshot_manifest_failure_cleans_moved_catalog_and_review_pair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            observed_pair: Path | None = None

            def fail_after_pair_move(*_args: object, **kwargs: object) -> Path:
                nonlocal observed_pair
                observed_pair = Path(str(kwargs["review_bridge_jobs_path"]))
                self.assertTrue(observed_pair.is_dir())
                raise RuntimeError("synthetic snapshot manifest failure")

            with patch.object(
                store_module,
                "write_snapshot_manifest",
                side_effect=fail_after_pair_move,
            ):
                with self.assertRaisesRegex(RuntimeError, "synthetic snapshot manifest failure"):
                    snapshot(root, reason="manifest_failure_cleanup")

            self.assertIsNotNone(observed_pair)
            assert observed_pair is not None
            self.assertFalse(observed_pair.exists())
            snapshots_dir = root / "snapshots"
            self.assertEqual(list(snapshots_dir.glob("continuum_catalog_*.sqlite3")), [])
            self.assertEqual(list(snapshots_dir.glob("continuum_snapshot_*.manifest.json")), [])
            self.assertEqual(list(snapshots_dir.glob("continuum_cards_*")), [])
            self.assertEqual(
                list(
                    snapshots_dir.glob(
                        "continuum_card_sidecar_receipts_*"
                    )
                ),
                [],
            )
            self.assertEqual(list(snapshots_dir.glob("continuum_review_bridge_jobs_*")), [])
            conn = connect(root)
            try:
                self.assertEqual(conn.execute("SELECT count(*) FROM snapshots").fetchone()[0], 0)
            finally:
                conn.close()

    def test_snapshot_durability_barriers_precede_catalog_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            seed_snapshot_durability_root(root)
            events: list[tuple[str, str]] = []
            flushed_files: list[Path] = []
            real_permission_file_flush = permissions_module.flush_file_strict
            real_stage_flush = store_module.flush_tree_strict
            real_replace = store_module.replace_durable
            real_manifest_write = store_module.write_snapshot_manifest
            real_manifest_file_flush = store_module.flush_file_strict
            real_manifest_directory_flush = store_module.flush_directory_strict
            real_audit_event = store_module.audit_event

            def trace_permission_file_flush(path: Path) -> None:
                flushed_files.append(Path(path))
                real_permission_file_flush(path)

            def trace_stage_flush(path: Path, *, include_parent: bool = False) -> None:
                events.append(("stage_flush_start", Path(path).name))
                real_stage_flush(path, include_parent=include_parent)
                events.append(("stage_flush_complete", Path(path).name))

            def trace_replace(source: Path, destination: Path) -> None:
                events.append(("rename_start", Path(destination).name))
                real_replace(source, destination)
                events.append(("rename_complete", Path(destination).name))

            def trace_manifest_write(*args: object, **kwargs: object) -> Path:
                events.append(("manifest_write", "start"))
                result = real_manifest_write(*args, **kwargs)
                events.append(("manifest_write", "complete"))
                return result

            def trace_manifest_file_flush(path: Path) -> None:
                label = (
                    "manifest_file_flush"
                    if Path(path).name.endswith(".manifest.json")
                    else "published_file_flush"
                )
                events.append((label, Path(path).name))
                real_manifest_file_flush(path)

            def trace_manifest_directory_flush(path: Path) -> None:
                label = (
                    "manifest_directory_flush"
                    if any(event[0] == "manifest_file_flush" for event in events)
                    else "directory_flush"
                )
                events.append((label, Path(path).name))
                real_manifest_directory_flush(path)

            def trace_audit_event(*args: object, **kwargs: object) -> str:
                if kwargs.get("action") == "snapshot":
                    events.append(("snapshot_audit", "catalog"))
                return real_audit_event(*args, **kwargs)

            with patch.object(
                permissions_module,
                "flush_file_strict",
                side_effect=trace_permission_file_flush,
            ), patch.object(
                store_module,
                "flush_tree_strict",
                side_effect=trace_stage_flush,
            ), patch.object(
                store_module,
                "replace_durable",
                side_effect=trace_replace,
            ), patch.object(
                store_module,
                "write_snapshot_manifest",
                side_effect=trace_manifest_write,
            ), patch.object(
                store_module,
                "flush_file_strict",
                side_effect=trace_manifest_file_flush,
            ), patch.object(
                store_module,
                "flush_directory_strict",
                side_effect=trace_manifest_directory_flush,
            ), patch.object(
                store_module,
                "audit_event",
                side_effect=trace_audit_event,
            ):
                created = snapshot(root, reason="durability ordering")

            event_names = [event[0] for event in events]
            stage_names = [
                value for name, value in events if name == "stage_flush_start"
            ]
            self.assertEqual(len(stage_names), 1)
            self.assertRegex(stage_names[0], r"^\.staging_[0-9a-f]{16}$")
            self.assertLess(
                event_names.index("stage_flush_complete"),
                event_names.index("rename_start"),
            )
            self.assertEqual(event_names.count("rename_complete"), 5)
            self.assertLess(
                max(index for index, name in enumerate(event_names) if name == "rename_complete"),
                event_names.index("manifest_write"),
            )
            self.assertLess(
                event_names.index("manifest_file_flush"),
                event_names.index("manifest_directory_flush"),
            )
            self.assertLess(
                event_names.index("manifest_directory_flush"),
                event_names.index("snapshot_audit"),
            )
            flushed_names = {path.name for path in flushed_files}
            self.assertIn("catalog.sqlite3", flushed_names)
            self.assertIn("continuum.config.json", flushed_names)
            self.assertIn("partition_alias.key", flushed_names)
            self.assertIn("request.json", flushed_names)
            self.assertTrue(any(name.endswith(".yaml") for name in flushed_names))
            self.assertTrue(
                any(
                    name.startswith("card_sidecar_write_intent_")
                    and name.endswith(".json")
                    for name in flushed_names
                )
            )
            verification = store_module.verify_snapshot_manifest_for_root(
                Path(str(created["snapshot_uri"])),
                root=root,
                require_catalog_binding=True,
            )
            self.assertTrue(verification["ok"], verification)

    def test_snapshot_ordinary_durability_failures_leave_no_authority_or_outputs(self) -> None:
        failure_cases = ("stage_tree", "manifest_file", "manifest_directory")
        for failure_case in failure_cases:
            with self.subTest(failure_case=failure_case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "epic-continuum"
                seed_snapshot_durability_root(root)
                if failure_case == "stage_tree":
                    failure_patch = patch.object(
                        store_module,
                        "flush_tree_strict",
                        side_effect=OSError("synthetic stage durability failure"),
                    )
                elif failure_case == "manifest_file":
                    real_file_flush = store_module.flush_file_strict

                    def fail_manifest_file(path: Path) -> None:
                        if Path(path).name.endswith(".manifest.json"):
                            raise OSError("synthetic manifest file durability failure")
                        real_file_flush(path)

                    failure_patch = patch.object(
                        store_module,
                        "flush_file_strict",
                        side_effect=fail_manifest_file,
                    )
                else:
                    failure_patch = patch.object(
                        store_module,
                        "flush_directory_strict",
                        side_effect=OSError("synthetic manifest directory durability failure"),
                    )
                with failure_patch, self.assertRaises(OSError):
                    snapshot(root, reason=failure_case)

                conn = connect(root)
                try:
                    self.assertEqual(conn.execute("SELECT count(*) FROM snapshots").fetchone()[0], 0)
                finally:
                    conn.close()
                snapshots_dir = root / "snapshots"
                self.assertEqual(list(snapshots_dir.glob("continuum_*")), [])
                self.assertEqual(list(snapshots_dir.glob(".staging_*")), [])

    def test_snapshot_each_final_rename_failure_cleans_uncommitted_outputs(self) -> None:
        for failure_index in range(1, 6):
            with self.subTest(failure_index=failure_index), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "epic-continuum"
                seed_snapshot_durability_root(root)
                real_replace = store_module.replace_durable
                rename_count = 0

                def fail_after_rename(source: Path, destination: Path) -> None:
                    nonlocal rename_count
                    real_replace(source, destination)
                    rename_count += 1
                    if rename_count == failure_index:
                        raise OSError(f"synthetic rename durability failure {failure_index}")

                with patch.object(
                    store_module,
                    "replace_durable",
                    side_effect=fail_after_rename,
                ), self.assertRaisesRegex(OSError, "synthetic rename durability failure"):
                    snapshot(root, reason=f"rename failure {failure_index}")

                self.assertEqual(rename_count, failure_index)
                conn = connect(root)
                try:
                    self.assertEqual(conn.execute("SELECT count(*) FROM snapshots").fetchone()[0], 0)
                finally:
                    conn.close()
                snapshots_dir = root / "snapshots"
                self.assertEqual(list(snapshots_dir.glob("continuum_*")), [])
                self.assertEqual(list(snapshots_dir.glob(".staging_*")), [])

    def test_snapshot_power_loss_at_rename_or_manifest_never_creates_authority(self) -> None:
        for crash_boundary in ("first_rename", "manifest_directory"):
            with self.subTest(crash_boundary=crash_boundary), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "epic-continuum"
                seed_snapshot_durability_root(root)
                if crash_boundary == "first_rename":
                    real_replace = store_module.replace_durable

                    def crash_after_rename(source: Path, destination: Path) -> None:
                        real_replace(source, destination)
                        raise SimulatedSnapshotPowerLoss("after first durable rename")

                    boundary_patch = patch.object(
                        store_module,
                        "replace_durable",
                        side_effect=crash_after_rename,
                    )
                else:
                    real_directory_flush = store_module.flush_directory_strict

                    def crash_after_manifest_directory(path: Path) -> None:
                        real_directory_flush(path)
                        raise SimulatedSnapshotPowerLoss("after manifest directory flush")

                    boundary_patch = patch.object(
                        store_module,
                        "flush_directory_strict",
                        side_effect=crash_after_manifest_directory,
                    )
                with boundary_patch, self.assertRaises(SimulatedSnapshotPowerLoss):
                    snapshot(root, reason=crash_boundary)

                conn = connect(root)
                try:
                    self.assertEqual(conn.execute("SELECT count(*) FROM snapshots").fetchone()[0], 0)
                finally:
                    conn.close()

    def test_snapshot_power_loss_after_catalog_commit_leaves_verifiable_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            seed_snapshot_durability_root(root)
            with patch.object(
                store_module,
                "enforce_snapshot_retention",
                side_effect=SimulatedSnapshotPowerLoss("after catalog commit"),
            ), self.assertRaises(SimulatedSnapshotPowerLoss):
                snapshot(root, reason="postcommit power loss")

            conn = connect(root)
            try:
                rows = conn.execute("SELECT snapshot_uri FROM snapshots").fetchall()
            finally:
                conn.close()
            self.assertEqual(len(rows), 1)
            snapshot_path = store_module.resolve_stored_uri(root, str(rows[0]["snapshot_uri"]))
            verification = store_module.verify_snapshot_manifest_for_root(
                snapshot_path,
                root=root,
                require_catalog_binding=True,
            )
            self.assertTrue(verification["ok"], verification)

    def test_snapshot_restart_quarantines_precommit_outputs_before_retention(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            seed_snapshot_durability_root(root)

            with patch.object(
                store_module,
                "audit_event",
                side_effect=SimulatedSnapshotPowerLoss("before catalog commit"),
            ), self.assertRaises(SimulatedSnapshotPowerLoss):
                snapshot(root, reason="precommit power loss")

            snapshots_dir = root / "snapshots"
            intent_paths = list(snapshots_dir.glob(".snapshot_publication_*.json"))
            self.assertEqual(len(intent_paths), 1)
            intent = json.loads(intent_paths[0].read_text(encoding="utf-8"))
            interrupted_id = str(intent["snapshot_id"])
            interrupted_catalog = (
                snapshots_dir / f"continuum_catalog_{interrupted_id}.sqlite3"
            )
            self.assertTrue(interrupted_catalog.is_file())

            history_paths: list[Path] = []
            legacy_orphan = (
                snapshots_dir
                / "continuum_catalog_snapshot_20260720T000000Z_ffffffffffffffff.sqlite3"
            )
            legacy_orphan.write_bytes(b"legacy pre-protocol orphan")
            conn = connect(root)
            try:
                for index in range(20):
                    snapshot_id = (
                        f"snapshot_20260101T0000{index:02d}Z_{index:016x}"
                    )
                    path = snapshots_dir / f"continuum_catalog_{snapshot_id}.sqlite3"
                    path.write_bytes(f"valid-history-{index}".encode("utf-8"))
                    timestamp = 1_700_000_000 + index
                    os.utime(path, (timestamp, timestamp))
                    history_paths.append(path)
                    conn.execute(
                        """
                        INSERT INTO snapshots(
                            id, snapshot_uri, reason, source_db_uri, created_at
                        )
                        VALUES(?, ?, ?, 'catalog/catalog.sqlite3', ?)
                        """,
                        (
                            snapshot_id,
                            f"snapshots/{path.name}",
                            "valid retained history",
                            f"2026-01-01T00:00:{index:02d}+00:00",
                        ),
                    )
                conn.commit()
            finally:
                conn.close()

            result = enforce_snapshot_retention(root)

            self.assertEqual(result["orphan_publications_quarantined"], 1)
            self.assertGreaterEqual(result["orphan_outputs_quarantined"], 2)
            self.assertEqual(result["deleted"], 0)
            self.assertEqual(result["unbound_retained"], 1)
            self.assertFalse(interrupted_catalog.exists())
            self.assertTrue(
                (
                    snapshots_dir
                    / (
                        f".orphan_{interrupted_id.rsplit('_', 1)[-1]}_"
                        "catalog.sqlite3"
                    )
                ).is_file()
            )
            self.assertTrue(all(path.is_file() for path in history_paths))
            self.assertTrue(legacy_orphan.is_file())
            self.assertEqual(
                len(list(snapshots_dir.glob("continuum_catalog_*.sqlite3"))),
                21,
            )
            conn = connect(root)
            try:
                rows = conn.execute("SELECT id FROM snapshots").fetchall()
            finally:
                conn.close()
            self.assertEqual(len(rows), 20)

            restarted = enforce_snapshot_retention(root)
            self.assertEqual(restarted["orphan_publications_quarantined"], 0)
            self.assertEqual(restarted["orphan_outputs_quarantined"], 0)
            self.assertEqual(restarted["deleted"], 0)
            self.assertEqual(restarted["unbound_retained"], 1)
            self.assertTrue(all(path.is_file() for path in history_paths))

    def test_snapshot_orphan_quarantine_recovers_every_move_boundary(self) -> None:
        for crash_after_move in range(1, 9):
            with self.subTest(crash_after_move=crash_after_move), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "epic-continuum"
                init_db(root)
                snapshot_id = "snapshot_20260720T000000Z_1234567890abcdef"
                outputs = store_module._snapshot_publication_output_paths(
                    root,
                    snapshot_id,
                )
                directory_indexes = {1, 2, 3, 6}
                for index, output in enumerate(outputs):
                    if index in directory_indexes:
                        output.mkdir(parents=True)
                        (output / "evidence.txt").write_text(
                            f"output-{index}",
                            encoding="utf-8",
                        )
                    else:
                        output.parent.mkdir(parents=True, exist_ok=True)
                        output.write_text(f"output-{index}", encoding="utf-8")
                intent_path = store_module._write_snapshot_publication_intent(
                    root,
                    snapshot_id,
                )

                history_paths: list[Path] = []
                conn = connect(root)
                try:
                    for index in range(20):
                        retained_id = (
                            f"snapshot_20260101T0000{index:02d}Z_{index:016x}"
                        )
                        retained = (
                            root
                            / "snapshots"
                            / f"continuum_catalog_{retained_id}.sqlite3"
                        )
                        retained.write_text(
                            f"retained-{index}",
                            encoding="utf-8",
                        )
                        history_paths.append(retained)
                        conn.execute(
                            """
                            INSERT INTO snapshots(
                                id, snapshot_uri, reason, source_db_uri, created_at
                            )
                            VALUES(?, ?, 'retained', 'catalog/catalog.sqlite3', ?)
                            """,
                            (
                                retained_id,
                                f"snapshots/{retained.name}",
                                f"2026-01-01T00:00:{index:02d}+00:00",
                            ),
                        )
                    conn.commit()
                finally:
                    conn.close()

                real_move = store_module._move_snapshot_publication_output_noclobber
                move_count = 0

                def crash_after_durable_move(source: Path, destination: Path) -> None:
                    nonlocal move_count
                    real_move(source, destination)
                    move_count += 1
                    if move_count == crash_after_move:
                        raise SimulatedSnapshotPowerLoss(
                            f"after quarantine move {crash_after_move}"
                        )

                with patch.object(
                    store_module,
                    "_move_snapshot_publication_output_noclobber",
                    side_effect=crash_after_durable_move,
                ), self.assertRaises(SimulatedSnapshotPowerLoss):
                    enforce_snapshot_retention(root)

                enforce_snapshot_retention(root)
                orphan_paths = store_module._snapshot_orphan_evidence_paths(
                    root,
                    snapshot_id,
                )
                self.assertTrue(all(os.path.lexists(path) for path in orphan_paths))
                self.assertFalse(any(os.path.lexists(path) for path in outputs))
                self.assertFalse(intent_path.exists())
                self.assertTrue(
                    (
                        root
                        / "snapshots"
                        / ".orphan_1234567890abcdef_intent.json"
                    ).is_file()
                )
                self.assertTrue(all(path.is_file() for path in history_paths))

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
            review_job_trees = sorted(
                (root / "snapshots").glob("continuum_review_bridge_jobs_*")
            )
            self.assertEqual(len(review_job_trees), 20)
            sidecar_receipt_trees = sorted(
                (root / "snapshots").glob(
                    "continuum_card_sidecar_receipts_*"
                )
            )
            self.assertEqual(len(sidecar_receipt_trees), 20)
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

            self.assertEqual(result["protected"], 0)
            self.assertEqual(result["unbound_retained"], 22)
            self.assertTrue(protected.exists())
            self.assertEqual(len(list(snapshots_dir.glob("continuum_catalog_*.sqlite3"))), 22)

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
