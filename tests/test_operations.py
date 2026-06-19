from __future__ import annotations

import hashlib
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from continuum.cli import main as cli_main
from continuum.core.config import load_config, write_config
from continuum.core.permissions import secure_write_text
from continuum.core.store import audit_secrets, append_scroll_event, connect_existing, ingest_file, init_db, roll_scroll_segment, snapshot
from continuum.core.operations import (
    OperationGuard,
    SNAPSHOT_COUNT_TABLES,
    _proof_pack_hash,
    _stable_json_hash,
    create_proof_pack,
    doctor,
    finish_operation,
    list_operations,
    operation_summary,
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
)


def proof_item_path(root: Path, item: dict) -> Path:
    if item.get("uri_base") == "continuum_root":
        return root / str(item.get("uri") or item["path"])
    return Path(str(item["path"]))


def root_uri(root: Path, path: str | Path) -> str:
    return Path(path).resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()


class OperationLedgerTest(unittest.TestCase):
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

    def test_proof_pack_freezes_live_catalog_and_records_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            append_scroll_event(root, session_id="proof-freeze", event_type="message", role="user", content="freeze db")
            live_catalog = root / "catalog" / "catalog.sqlite3"
            started = start_operation(root, operation_type="freeze_test", title="Freeze live DB")
            finish_operation(root, started["operation_id"], status="succeeded", result={"ok": True})

            proof = create_proof_pack(root, started["operation_id"], touched_paths=[live_catalog])

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

            with self.assertRaisesRegex(ValueError, "secret scan blocked Scroll event"):
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
            }

            with patch("continuum.core.operations._snapshot_manifest", return_value=bad_manifest):
                result = restore_drill(root, snapshot_uri=snap["snapshot_uri"], verify_recent_proof_packs=0)

            self.assertFalse(result["ok"], result["checks"])
            checks = {check["name"]: check for check in result["checks"]}
            self.assertFalse(checks["restored_counts_match_snapshot_manifest"]["ok"])

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



if __name__ == "__main__":
    unittest.main()
