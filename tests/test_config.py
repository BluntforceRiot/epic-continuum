from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from continuum.core.config import default_config, load_config, optimize_config, should_capture, validate_config, write_config
from continuum.core.safety import redact_text_secrets, redact_value_secrets, scan_text_for_secrets, scan_value_for_secrets
from continuum.core.store import audit_event, audit_secrets, audit_secrets_sarif, append_scroll_event, compile_context, connect, connect_existing, enqueue_job, ingest_file, init_db, recover_thread, redact_legacy_secrets, snapshot
from continuum.core.units import format_size, parse_size
from continuum.integrations.common import record_tool_event, record_turn


class EpicContinuumConfigTest(unittest.TestCase):
    def test_parse_size_accepts_portable_budget_units(self) -> None:
        self.assertEqual(parse_size("512KB"), 512 * 1024)
        self.assertEqual(parse_size("128MB"), 128 * 1024**2)
        self.assertEqual(parse_size("4GB"), 4 * 1024**3)
        self.assertEqual(parse_size("1TB"), 1024**4)
        self.assertEqual(parse_size("1.1TB"), int(1.1 * 1024**4))
        self.assertEqual(parse_size("1048576"), 1024**2)
        with self.assertRaises(ValueError):
            parse_size(float("nan"))

    def test_format_size_round_trips_for_status_display(self) -> None:
        self.assertEqual(format_size(parse_size("512MB")), "512.00MB")
        self.assertEqual(format_size(parse_size("4GB")), "4.00GB")

    def test_default_config_is_written_and_validated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = load_config(root)

            self.assertEqual(config["hardware"]["vram"]["active_pane_budget"], "8GB")
            self.assertEqual(config["hardware"]["system_ram"]["hot_cache_budget"], "4GB")
            self.assertEqual(config["hardware"]["nvme"]["durable_store_budget"], "256GB")
            self.assertEqual(config["capture"]["mode"], "automatic")
            self.assertTrue(config["capture"]["record_user_turns"])
            self.assertEqual(config["capture"]["max_tool_result_bytes"], "256KB")
            self.assertEqual(config["retention"]["prune_policy"], "ask")
            self.assertFalse(config["retention"]["delete_raw_evidence"])
            self.assertTrue((root / "config" / "continuum.config.json").exists())

    def test_capture_policy_can_disable_automatic_adapter_turns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["capture"]["mode"] = "manual"
            write_config(root, config)

            result = record_turn(
                root,
                session_id="manual-capture",
                role="user",
                content="This should not be auto-recorded.",
                source="test",
            )

            self.assertIsNone(result)
            self.assertFalse(should_capture(root, "user_turn"))
            self.assertTrue(should_capture(root, "user_turn", explicit=True))
            explicit = record_turn(
                root,
                session_id="manual-capture",
                role="user",
                content="This deliberate manual capture should be recorded.",
                source="test",
                explicit=True,
            )
            self.assertIsNotNone(explicit)
            context = compile_context(root, session_id="manual-capture", token_budget=800)
            self.assertIn("deliberate manual capture", context["context_text"])

    def test_scroll_deduplicates_retried_events_within_configured_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"

            first = append_scroll_event(root, session_id="dedup", event_type="message", role="user", content="same retry payload")
            second = append_scroll_event(root, session_id="dedup", event_type="message", role="user", content="same retry payload")

            self.assertFalse(first["deduplicated"])
            self.assertTrue(second["deduplicated"])
            self.assertEqual(first["event_id"], second["event_id"])
            conn = connect_existing(root)
            try:
                event_count = conn.execute("SELECT count(*) AS n FROM scroll_events WHERE session_id = 'dedup'").fetchone()["n"]
                dedupe_count = conn.execute("SELECT count(*) AS n FROM audit_events WHERE action = 'dedupe_scroll_event'").fetchone()["n"]
            finally:
                conn.close()
            self.assertEqual(event_count, 1)
            self.assertEqual(dedupe_count, 1)

    def test_adapter_capture_adds_source_trust_labels(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"

            result = record_turn(root, session_id="trust-labels", role="user", content="Trust labels test.", source="codex")

            self.assertIsNotNone(result)
            conn = connect_existing(root)
            try:
                metadata_json = conn.execute("SELECT metadata_json FROM scroll_events WHERE id = ?", (result["event_id"],)).fetchone()["metadata_json"]
            finally:
                conn.close()
            metadata = json.loads(metadata_json)
            self.assertEqual(metadata["source"], "codex")
            self.assertEqual(metadata["source_type"], "adapter_capture")
            self.assertEqual(metadata["trust_level"], "local_user_evidence_non_authoritative")
            self.assertEqual(metadata["instruction_authority"], "user_level_evidence")

    def test_tool_result_capture_is_capped_with_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["capture"]["max_tool_result_bytes"] = "64B"
            write_config(root, config)

            result = record_tool_event(
                root,
                session_id="tool-capture",
                tool_name="huge_tool",
                payload="x" * 512,
                source="test",
                result=True,
            )

            self.assertIsNotNone(result)
            conn = connect_existing(root)
            try:
                row = conn.execute(
                    "SELECT content, metadata_json FROM scroll_events WHERE id = ?",
                    (result["event_id"],),
                ).fetchone()
            finally:
                conn.close()
            self.assertLessEqual(len(row["content"].encode("utf-8")), 64)
            capture = json.loads(row["metadata_json"])["capture"]
            self.assertLessEqual(capture["stored_bytes"], 64)
            context = compile_context(root, session_id="tool-capture", token_budget=800)
            self.assertIn("Continuum capture notice", context["context_text"])
            self.assertIn("test_tool_result", context["context_text"])

    def test_tool_result_secret_scan_runs_before_capture_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["capture"]["max_tool_result_bytes"] = "64B"
            config["security"]["secret_scan_action"] = "block"
            write_config(root, config)

            result = record_tool_event(
                root,
                session_id="tool-secret-after-limit",
                tool_name="huge_tool",
                payload=("x" * 128) + "\napi_key=supersecretvalue123",
                source="test",
                result=True,
            )

            self.assertIsNone(result)
            context = compile_context(root, session_id="tool-secret-after-limit", token_budget=800)
            self.assertNotIn("supersecretvalue123", context["context_text"])
            self.assertNotIn("test_tool_result", context["context_text"])

    def test_tool_result_skip_policy_writes_no_scroll_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["capture"]["max_tool_result_bytes"] = "8B"
            config["capture"]["large_result_policy"] = "skip"
            write_config(root, config)

            result = record_tool_event(
                root,
                session_id="tool-skip",
                tool_name="huge_tool",
                payload="x" * 512,
                source="test",
                result=True,
            )

            self.assertIsNone(result)
            self.assertFalse((root / "catalog" / "catalog.sqlite3").exists())

    def test_tiny_tool_result_cap_is_an_absolute_byte_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["capture"]["max_tool_result_bytes"] = "1B"
            config["capture"]["large_result_policy"] = "truncate_with_notice"
            write_config(root, config)

            result = record_tool_event(
                root,
                session_id="tool-one-byte",
                tool_name="tiny_cap",
                payload="é" * 32,
                source="test",
                result=True,
            )

            self.assertIsNotNone(result)
            conn = connect_existing(root)
            try:
                row = conn.execute(
                    "SELECT content, metadata_json FROM scroll_events WHERE id = ?",
                    (result["event_id"],),
                ).fetchone()
            finally:
                conn.close()
            self.assertLessEqual(len(row["content"].encode("utf-8")), 1)
            self.assertLessEqual(json.loads(row["metadata_json"])["capture"]["stored_bytes"], 1)

    def test_capture_blocks_secret_bearing_turns_and_tool_results_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"

            turn = record_turn(
                root,
                session_id="secret-capture",
                role="user",
                content="Do not persist api_key=supersecretvalue123 in memory.",
                source="test",
            )
            tool = record_tool_event(
                root,
                session_id="secret-capture",
                tool_name="secret_tool",
                payload="password=supersecretvalue123",
                source="test",
                result=True,
            )

            self.assertIsNone(turn)
            self.assertIsNone(tool)
            context = compile_context(root, session_id="secret-capture", token_budget=800)
            self.assertNotIn("supersecretvalue123", context["context_text"])

    def test_capture_warn_policy_redacts_secret_text(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["security"]["secret_scan_action"] = "warn"
            write_config(root, config)

            result = record_tool_event(
                root,
                session_id="secret-warn",
                tool_name="secret_tool",
                payload="api_key=supersecretvalue123",
                source="test",
                result=True,
            )

            self.assertIsNotNone(result)
            context = compile_context(root, session_id="secret-warn", token_budget=800)
            self.assertIn("[REDACTED]", context["context_text"])
            self.assertNotIn("supersecretvalue123", context["context_text"])

    def test_short_sensitive_key_assignments_are_detected_and_redacted(self) -> None:
        findings = scan_text_for_secrets("client_secret: short\nTOKEN_BUDGET: 1000")
        redacted = redact_value_secrets({"notes": "client_secret: short", "token_budget": 1000})

        self.assertTrue(any(finding.get("type") == "sensitive_key_assignment" for finding in findings))
        self.assertNotIn("short", findings[0]["snippet"])
        self.assertEqual(redacted["notes"], "client_secret: [REDACTED]")
        self.assertEqual(redacted["token_budget"], 1000)
        self.assertEqual(redact_text_secrets("OPENAI_API_KEY=short"), "OPENAI_API_KEY=[REDACTED]")

    def test_audit_secrets_detects_yaml_style_sensitive_keys_with_short_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            root.mkdir()
            (root / "config.yaml").write_text("client_secret: short\ntoken_budget: 900\n", encoding="utf-8")

            result = audit_secrets(root, create=False)
            rendered = json.dumps(result, ensure_ascii=True, sort_keys=True)

            self.assertFalse(result["ok"], rendered)
            self.assertNotIn("client_secret: short", rendered)
            self.assertTrue(any(finding.get("type") == "sensitive_key_assignment" for finding in result["findings"]))

    def test_capture_blocks_short_sensitive_key_assignments_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"

            result = record_turn(
                root,
                session_id="short-sensitive-assignment",
                role="user",
                content="client_secret: short",
                source="test",
            )

            self.assertIsNone(result)
            context = compile_context(root, session_id="short-sensitive-assignment", token_budget=800)
            self.assertNotIn("client_secret: short", context["context_text"])

    def test_redact_value_secrets_handles_common_sensitive_metadata_keys(self) -> None:
        payload = {
            "client_secret": "supersecretvalue123",
            "private_key": "raw-private-key-material",
            "auth_token": "abc1234567890xyz",
            "resume_token": "mempalace:import-id",
            "token_budget": 1200,
        }

        findings = scan_value_for_secrets(payload, scope="unit")
        redacted = redact_value_secrets(payload)

        self.assertTrue(any(finding.get("type") == "sensitive_metadata_key" for finding in findings))
        self.assertEqual(redacted["client_secret"], "[REDACTED]")
        self.assertEqual(redacted["private_key"], "[REDACTED]")
        self.assertEqual(redacted["auth_token"], "[REDACTED]")
        self.assertEqual(redacted["resume_token"], "mempalace:import-id")
        self.assertEqual(redacted["token_budget"], 1200)

    def test_queue_and_audit_sinks_redact_common_sensitive_metadata_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                audit_event(
                    conn,
                    action="test_secret_sink",
                    target_type="unit",
                    target_id="client_secret=targetSecret123",
                    payload={"client_secret": "supersecretvalue123", "resume_token": "mempalace:abc"},
                    actor="auth_token=actorSecret123",
                )
                enqueue_job(
                    conn,
                    role="worker",
                    job_type="secret_sink",
                    priority=1,
                    payload={"private_key": "raw-private-key-material", "token_budget": 1200},
                    related_card_ids=["auth_token=relatedSecret123"],
                )
                conn.commit()
                audit_row = conn.execute(
                    "SELECT actor, target_id, payload_json FROM audit_events WHERE action='test_secret_sink'"
                ).fetchone()
                job_row = conn.execute(
                    "SELECT related_card_ids_json, payload_json FROM queue_jobs WHERE job_type='secret_sink'"
                ).fetchone()
            finally:
                conn.close()

            serialized = json.dumps(
                {
                    "audit": dict(audit_row),
                    "job": dict(job_row),
                },
                ensure_ascii=True,
                sort_keys=True,
            )
            self.assertNotIn("supersecretvalue123", serialized)
            self.assertNotIn("raw-private-key-material", serialized)
            self.assertNotIn("actorSecret123", serialized)
            self.assertNotIn("relatedSecret123", serialized)
            self.assertIn("[REDACTED]", serialized)
            self.assertIn("mempalace:abc", serialized)
            self.assertIn("1200", serialized)

    def test_scroll_secret_policy_blocks_identifier_fields_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"

            with self.assertRaisesRegex(ValueError, "secret scan blocked Scroll event"):
                append_scroll_event(
                    root,
                    session_id="api_key=supersecretvalue123",
                    event_type="message",
                    role="user",
                    content="safe content",
                )

            conn = connect_existing(root)
            try:
                count = conn.execute("SELECT COUNT(*) AS n FROM scroll_events").fetchone()["n"]
            finally:
                conn.close()
            self.assertEqual(count, 0)

    def test_scroll_secret_policy_warn_redacts_identifier_and_metadata_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["security"]["secret_scan_action"] = "warn"
            write_config(root, config)

            result = append_scroll_event(
                root,
                session_id="api_key=supersecretvalue123",
                event_type="message",
                role="user",
                content="safe content",
                metadata={"token": "supersecretvalue123"},
            )

            self.assertTrue(result["session_id"].startswith("redacted_session_"))
            conn = connect_existing(root)
            try:
                row = conn.execute("SELECT session_id, metadata_json FROM scroll_events").fetchone()
            finally:
                conn.close()
            serialized = f"{row['session_id']} {row['metadata_json']}"
            self.assertIn("redacted_session_", serialized)
            self.assertIn("[REDACTED]", serialized)
            self.assertNotIn("supersecretvalue123", serialized)

    def test_secret_scanner_only_ignores_exact_redaction_placeholders(self) -> None:
        self.assertEqual(scan_text_for_secrets("api_key=[REDACTED]"), [])
        self.assertTrue(scan_text_for_secrets("api_key=notredactedStillSecret123"))
        self.assertTrue(scan_text_for_secrets("password=redactedButActuallySecret123"))
        self.assertTrue(scan_text_for_secrets("private_token=supersecretvalue123"))
        self.assertTrue(scan_text_for_secrets("access_key=supersecretvalue123"))
        self.assertFalse(scan_text_for_secrets("resume_token=mempalace:import-id"))

    def test_audit_secrets_reports_redacted_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            root.mkdir()
            (root / "notes.txt").write_text("api_key=supersecretvalue123\n", encoding="utf-8")

            audit = audit_secrets(root)

            self.assertFalse(audit["ok"])
            self.assertEqual(audit["finding_count"], 1)
            self.assertNotIn("supersecretvalue123", audit["findings"][0]["snippet"])

    def test_warn_policy_redacts_secret_bearing_metadata_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["security"]["secret_scan_action"] = "warn"
            write_config(root, config)

            append_scroll_event(
                root,
                session_id="metadata-key-redaction",
                event_type="message",
                role="user",
                content="safe content",
                metadata={
                    "api_key=supersecretvalue123": "safe",
                    "nested": {"password=redactedButActuallySecret123": "safe"},
                },
            )

            conn = connect_existing(root)
            try:
                metadata_json = conn.execute("SELECT metadata_json FROM scroll_events").fetchone()["metadata_json"]
            finally:
                conn.close()
            metadata = json.loads(metadata_json)
            serialized = json.dumps(metadata, ensure_ascii=True, sort_keys=True)
            self.assertIn("redacted_key_", serialized)
            self.assertNotIn("supersecretvalue123", serialized)
            self.assertNotIn("redactedButActuallySecret123", serialized)
            self.assertTrue(audit_secrets(root)["ok"])

    def test_audit_secrets_scans_paths_and_redacts_all_same_line_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            root.mkdir()
            secret_path = root / "api_key=supersecretvalue123.txt"
            secret_path.write_text(
                "api_key=firstsecretvalue123 password=secondsecretvalue123\n",
                encoding="utf-8",
            )

            result = audit_secrets(root)

            self.assertFalse(result["ok"])
            self.assertGreaterEqual(result["finding_count"], 1)
            serialized = json.dumps(result["findings"], ensure_ascii=True, sort_keys=True)
            self.assertNotIn("supersecretvalue123", serialized)
            self.assertNotIn("firstsecretvalue123", serialized)
            self.assertNotIn("secondsecretvalue123", serialized)
            self.assertTrue(any(finding.get("scope") == "path" for finding in result["findings"]))

    def test_audit_event_redacts_secret_payloads_before_sqlite_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            conn.row_factory = sqlite3.Row
            try:
                audit_event(
                    conn,
                    action="test_secret_payload",
                    target_type="test",
                    target_id="api_key=supersecretvalue123",
                    payload={"topic": "api_key=supersecretvalue123", "nested": {"token": "supersecretvalue123"}},
                )
                conn.commit()
                row = conn.execute("SELECT target_id, payload_json FROM audit_events WHERE action = 'test_secret_payload'").fetchone()
            finally:
                conn.close()
            serialized = f"{row['target_id']} {row['payload_json']}"
            self.assertIn("[REDACTED]", serialized)
            self.assertNotIn("supersecretvalue123", serialized)
            self.assertTrue(audit_secrets(root)["ok"])

    def test_internal_secret_bearing_source_names_are_redacted_source_refs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["security"]["secret_scan_action"] = "warn"
            write_config(root, config)
            source = root / "run" / "api_key=supersecretvalue123.txt"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("Safe internal source text.\n", encoding="utf-8")

            result = ingest_file(root, path=source, title="safe title")

            conn = connect_existing(root)
            try:
                book = conn.execute("SELECT source_uri FROM books WHERE id = ?", (result["book_id"],)).fetchone()
                card = conn.execute("SELECT source_refs_json FROM cards WHERE id = ?", (result["card_id"],)).fetchone()
            finally:
                conn.close()
            source_refs = json.loads(card["source_refs_json"])
            serialized = json.dumps({"book": dict(book), "refs": source_refs}, ensure_ascii=True, sort_keys=True)
            self.assertIn("redacted_source", serialized)
            self.assertIn('"uri_base": "redacted_source"', serialized)
            self.assertNotIn("supersecretvalue123", serialized)
            source.unlink()
            self.assertTrue(audit_secrets(root)["ok"])

    def test_ingest_warn_redacts_secret_bearing_internal_parent_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["security"]["secret_scan_action"] = "warn"
            write_config(root, config)
            source = root / "imports" / "api_key=supersecretvalue123" / "safe.txt"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("Safe source text that should be archived.\n", encoding="utf-8")

            result = ingest_file(root, path=source, title="Safe title")

            conn = connect_existing(root)
            try:
                book = conn.execute("SELECT source_uri, metadata_json FROM books WHERE id = ?", (result["book_id"],)).fetchone()
                card = conn.execute("SELECT source_refs_json FROM cards WHERE id = ?", (result["card_id"],)).fetchone()
            finally:
                conn.close()
            serialized = json.dumps({"book": dict(book), "refs": json.loads(card["source_refs_json"])}, ensure_ascii=True, sort_keys=True)
            self.assertIn('"uri_base": "redacted_source"', serialized)
            self.assertIn("redacted:internal:", serialized)
            self.assertNotIn("supersecretvalue123", serialized)
            source.unlink()
            self.assertTrue(audit_secrets(root)["ok"])

    def test_ingest_block_rejects_secret_bearing_internal_parent_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            source = root / "imports" / "api_key=supersecretvalue123" / "safe.txt"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("Safe source text.\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "secret scan blocked ingest_file"):
                ingest_file(root, path=source, title="Safe title")

            archived = list((root / "archive").rglob("*")) if (root / "archive").exists() else []
            self.assertFalse([path for path in archived if path.is_file()])

    def test_audit_secrets_scans_sqlite_text_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["security"]["secret_scan_action"] = "off"
            write_config(root, config)
            snapshot(root, reason="api_key=supersecretvalue123")

            result = audit_secrets(root)

            self.assertFalse(result["ok"])
            self.assertTrue(any(str(finding.get("scope", "")).startswith("sqlite:snapshots.reason") for finding in result["findings"]))
            self.assertNotIn("supersecretvalue123", json.dumps(result["findings"], ensure_ascii=True))

    def test_audit_secrets_entropy_allowlist_and_sarif(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            token = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0"
            config = default_config()
            config["security"]["secret_scan_action"] = "off"
            config["security"]["entropy_secret_scan_enabled"] = True
            write_config(root, config)
            target = root / "notes.txt"
            target.write_text(f"opaque={token}\n", encoding="utf-8")

            result = audit_secrets(root)
            sarif = audit_secrets_sarif(result)

            self.assertFalse(result["ok"])
            self.assertTrue(any(finding["type"] == "high_entropy_token" for finding in result["findings"]))
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertGreaterEqual(len(sarif["runs"][0]["results"]), 1)
            self.assertNotIn(token, json.dumps(result, ensure_ascii=True))

            allowlist = root / "security" / "secret_allowlist.jsonl"
            allowlist.parent.mkdir(parents=True, exist_ok=True)
            allowlist.write_text(json.dumps({"secret_hash": result["findings"][0]["secret_hash"], "reason": "test fixture"}) + "\n", encoding="utf-8")
            allowed = audit_secrets(root)

            self.assertTrue(allowed["ok"], allowed)
            self.assertGreaterEqual(allowed["allowlisted_findings"], 1)

    def test_audit_secrets_scans_raw_secret_material_inside_allowlist_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["security"]["secret_scan_action"] = "off"
            config["security"]["entropy_secret_scan_enabled"] = True
            write_config(root, config)
            allowlist = root / "security" / "secret_allowlist.jsonl"
            allowlist.parent.mkdir(parents=True, exist_ok=True)
            allowlist.write_text("api_key=supersecretvalue123\n", encoding="utf-8")

            result = audit_secrets(root)

            self.assertFalse(result["ok"])
            self.assertTrue(any(finding.get("path") == "security/secret_allowlist.jsonl" for finding in result["findings"]))
            self.assertNotIn("supersecretvalue123", json.dumps(result, ensure_ascii=True))

    def test_snapshot_blocks_secret_reason_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"

            with self.assertRaisesRegex(ValueError, "secret scan blocked snapshot reason"):
                snapshot(root, reason="api_key=supersecretvalue123")

            self.assertTrue(audit_secrets(root)["ok"])

    def test_redact_legacy_secrets_dry_run_and_apply(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["security"]["secret_scan_action"] = "off"
            write_config(root, config)
            snapshot(root, reason="api_key=supersecretvalue123")

            dry = redact_legacy_secrets(root, dry_run=True)
            applied = redact_legacy_secrets(root, dry_run=False)
            audited = audit_secrets(root)

            self.assertGreaterEqual(dry["redaction_count"], 1)
            self.assertGreaterEqual(applied["redaction_count"], 1)
            self.assertTrue(audited["ok"], audited)

    def test_redact_legacy_secrets_does_not_rewrite_hashed_scroll_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["security"]["secret_scan_action"] = "off"
            write_config(root, config)
            append_scroll_event(
                root,
                session_id="legacy-redaction-boundary",
                event_type="message",
                role="user",
                content="api_key=supersecretvalue123",
            )
            conn = connect_existing(root)
            try:
                before = conn.execute("SELECT content, content_hash FROM scroll_events").fetchone()
            finally:
                conn.close()

            applied = redact_legacy_secrets(root, dry_run=False)

            conn = connect_existing(root)
            try:
                after = conn.execute("SELECT content, content_hash FROM scroll_events").fetchone()
            finally:
                conn.close()
            self.assertEqual(before["content"], after["content"])
            self.assertEqual(before["content_hash"], after["content_hash"])
            self.assertFalse(any(action["table"] == "scroll_events" for action in applied["actions"]))
            self.assertFalse(audit_secrets(root)["ok"])

    def test_recover_thread_blocks_secret_session_id_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"

            with self.assertRaisesRegex(ValueError, "secret scan blocked recovery session_id"):
                recover_thread(root, session_id="api_key=supersecretvalue123")

            packets = list((root / "exports" / "thread_recovery").glob("*.md")) if (root / "exports" / "thread_recovery").exists() else []
            self.assertEqual(packets, [])
            self.assertTrue(audit_secrets(root)["ok"])

    def test_invalid_capture_and_retention_policies_are_rejected(self) -> None:
        config = default_config()
        config["capture"]["mode"] = "surprise"
        with self.assertRaises(ValueError):
            validate_config(config)

        config = default_config()
        config["retention"]["raw_scroll_hot_days"] = 100
        config["retention"]["raw_scroll_warm_days"] = 30
        with self.assertRaises(ValueError):
            validate_config(config)

        config = default_config()
        config["retention"]["snapshot_retention"] = "last-twenty"
        with self.assertRaises(ValueError):
            validate_config(config)

        config = default_config()
        config["retention"]["proof_pack_retention"] = "ninety-days"
        with self.assertRaises(ValueError):
            validate_config(config)

        config = default_config()
        config["retention"]["prune_policy"] = "auto_prune"
        config["retention"]["delete_raw_evidence"] = True
        with self.assertRaises(ValueError):
            validate_config(config)

        config = default_config()
        config["learning"]["route_decay_min_interval_seconds"] = -1
        with self.assertRaises(ValueError):
            validate_config(config)

        config = default_config()
        config["queues"]["worker_lease_seconds"] = 0
        with self.assertRaises(ValueError):
            validate_config(config)

    def test_root_relative_config_paths_reject_cross_platform_escapes(self) -> None:
        cases = (
            (("atomic_memory", "card_sidecar_dir"), "../../escaped-cards"),
            (("atomic_memory", "card_sidecar_dir"), r"C:\escaped-cards"),
            (("security", "ignore_file"), "/tmp/continuum.ignore"),
            (("security", "ignore_file"), r"\\server\share\continuum.ignore"),
            (("security", "secret_allowlist_file"), "security/../outside.jsonl"),
        )
        for keys, value in cases:
            with self.subTest(keys=keys, value=value):
                config = default_config()
                config[keys[0]][keys[1]] = value
                with self.assertRaises(ValueError):
                    validate_config(config)

        config = default_config()
        config["capture"]["max_tool_result_bytes"] = "0B"
        with self.assertRaisesRegex(ValueError, "max_tool_result_bytes must be positive"):
            validate_config(config)

    def test_configured_internal_paths_reject_existing_symlink_escapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = base / "continuum"
            outside = base / "outside-cards"
            outside.mkdir()
            (root / "catalog").mkdir(parents=True)
            link = root / "catalog" / "linked-cards"
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")

            config = default_config()
            config["atomic_memory"]["card_sidecar_dir"] = "catalog/linked-cards"
            with self.assertRaisesRegex(ValueError, "resolves outside"):
                write_config(root, config)
            self.assertEqual(list(outside.iterdir()), [])

    def test_optimize_config_can_preview_without_writing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            inventory = {
                "vram": {"bytes": 32 * 1024**3, "source": "test"},
                "system_ram": {"bytes": 128 * 1024**3, "source": "test"},
                "drive": {"free_bytes": 2 * 1024**4, "source": "test"},
            }

            result = optimize_config(root, inventory=inventory, profile="balanced", write=False)

            self.assertFalse(result["wrote"])
            recommended = result["recommended_config"]
            self.assertEqual(recommended["hardware"]["vram"]["active_pane_budget"], "8GB")
            self.assertEqual(recommended["hardware"]["system_ram"]["hot_cache_budget"], "8GB")
            self.assertEqual(recommended["hardware"]["system_ram"]["kv_offload_budget"], "16GB")
            self.assertEqual(recommended["context"]["max_token_budget"], 256000)
            self.assertEqual(load_config(root)["hardware"]["system_ram"]["hot_cache_budget"], "4GB")

    def test_optimize_config_can_write_recommendations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            inventory = {
                "vram": {"bytes": 16 * 1024**3, "source": "test"},
                "system_ram": {"bytes": 64 * 1024**3, "source": "test"},
                "drive": {"free_bytes": 1024 * 1024**3, "source": "test"},
            }

            result = optimize_config(root, inventory=inventory, profile="conservative", write=True)
            written = load_config(root)

            self.assertTrue(result["wrote"])
            self.assertEqual(written["hardware"], result["recommended_config"]["hardware"])
            self.assertEqual(written["context"], result["recommended_config"]["context"])

    def test_enqueue_job_redacts_secret_payloads_at_durable_sink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            conn = connect(root)
            try:
                job_id = enqueue_job(
                    conn,
                    role="scribe",
                    job_type="custom",
                    priority=1,
                    payload={"api_key": "supersecretvalue123", "safe": "kept"},
                    related_card_ids=["card-api_key=supersecretvalue123"],
                )
                conn.commit()
                row = conn.execute("SELECT payload_json, related_card_ids_json FROM queue_jobs WHERE id = ?", (job_id,)).fetchone()
            finally:
                conn.close()
            rendered = row["payload_json"] + row["related_card_ids_json"]
            self.assertNotIn("supersecretvalue123", rendered)
            self.assertIn("[REDACTED]", rendered)


    def test_audit_secrets_scans_and_redacts_sqlite_schema_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            root.mkdir()
            db_path = root / "external.sqlite3"
            conn = sqlite3.connect(db_path)
            try:
                conn.execute('CREATE TABLE "api_key=supersecretvalue123" ("password=supersecretvalue123" TEXT)')
                conn.commit()
            finally:
                conn.close()

            result = audit_secrets(root, create=False)
            rendered = json.dumps(result, ensure_ascii=True, sort_keys=True)
            self.assertFalse(result["ok"])
            self.assertNotIn("supersecretvalue123", rendered)
            self.assertTrue(any(finding.get("scope") == "sqlite_schema:table" for finding in result["findings"]))
            self.assertTrue(any(finding.get("scope") == "sqlite_schema:column" for finding in result["findings"]))

    def test_audit_secrets_detects_sensitive_sqlite_column_values_with_short_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            root.mkdir()
            db_path = root / "external.sqlite3"
            conn = sqlite3.connect(db_path)
            try:
                conn.execute("CREATE TABLE app_config (id INTEGER PRIMARY KEY, client_secret TEXT, normal TEXT)")
                conn.execute("INSERT INTO app_config(client_secret, normal) VALUES (?, ?)", ("short", "safe"))
                conn.commit()
            finally:
                conn.close()

            result = audit_secrets(root, create=False)
            rendered = json.dumps(result, ensure_ascii=True, sort_keys=True)

            self.assertFalse(result["ok"], rendered)
            self.assertNotIn('"client_secret": "short"', rendered)
            self.assertTrue(any(str(finding.get("scope", "")).startswith("sqlite_sensitive_column:") for finding in result["findings"]))
            self.assertTrue(any(finding.get("scope") == "sqlite_schema:column_sensitive_key" for finding in result["findings"]))

    def test_audit_secrets_skips_symlink_targets_instead_of_following_them(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            outside = Path(tmp) / "outside_secret.txt"
            outside.write_text("api_key=supersecretvalue123", encoding="utf-8")
            link = root / "archive" / "originals" / "hot" / "linked-secret.txt"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")

            result = audit_secrets(root, create=False)

            rendered = json.dumps(result, ensure_ascii=True, sort_keys=True)
            self.assertTrue(result["ok"], rendered)
            self.assertNotIn("supersecretvalue123", rendered)
            self.assertNotIn(str(outside), rendered)
            self.assertTrue(any(item.get("reason") == "symlink_skipped" for item in result["skipped"]))



    def test_audit_secrets_detects_sensitive_keys_in_json_files_with_short_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            root.mkdir()
            (root / "evidence.json").write_text(
                json.dumps({"client_secret": "short", "resume_token": "safe-resume", "token_budget": 900}),
                encoding="utf-8",
            )

            result = audit_secrets(root, create=False)
            rendered = json.dumps(result, ensure_ascii=True, sort_keys=True)

            self.assertFalse(result["ok"], rendered)
            self.assertNotIn('"client_secret": "short"', rendered)
            self.assertTrue(any(finding.get("type") == "sensitive_metadata_key" for finding in result["findings"]))

    def test_audit_secrets_detects_short_sensitive_keys_in_malformed_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            payload = root / "archive" / "malformed.json"
            payload.parent.mkdir(parents=True, exist_ok=True)
            payload.write_text(
                '{"client_secret":"short","value":NaN trailing}\n',
                encoding="utf-8",
            )

            result = audit_secrets(root, create=False)
            self.assertFalse(result["ok"], result)
            rendered = json.dumps(result)
            self.assertIn("sensitive_key_assignment", rendered)
            self.assertNotIn('"client_secret":"short"', rendered)

    def test_audit_secrets_detects_duplicate_sensitive_json_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            payload = root / "archive" / "ambiguous.json"
            payload.parent.mkdir(parents=True, exist_ok=True)
            payload.write_text(
                '{"client_secret":"short","client_secret":"[REDACTED]"}\n',
                encoding="utf-8",
            )

            result = audit_secrets(root, create=False)
            self.assertFalse(result["ok"], result)
            self.assertGreaterEqual(result["finding_count"], 1)
            self.assertIn("sensitive_metadata_key", json.dumps(result))
            self.assertNotIn('"client_secret":"short"', json.dumps(result))

    def test_audit_secrets_detects_sensitive_keys_in_jsonl_files_with_short_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            root.mkdir()
            (root / "events.jsonl").write_text(
                "\n".join(
                    [
                        json.dumps({"event": "safe", "resume_token": "safe-resume"}),
                        json.dumps({"session_token": "tiny", "token_budget": 900}),
                    ]
                ),
                encoding="utf-8",
            )

            result = audit_secrets(root, create=False)
            rendered = json.dumps(result, ensure_ascii=True, sort_keys=True)

            self.assertFalse(result["ok"], rendered)
            self.assertNotIn('"session_token": "tiny"', rendered)
            self.assertTrue(any(finding.get("scope") == "file_json" and finding.get("line") == 2 for finding in result["findings"]))

    def test_audit_secrets_detects_sensitive_keys_in_sqlite_json_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            conn = connect(root)
            try:
                conn.execute(
                    "INSERT INTO audit_events(id, created_at, action, actor, target_type, target_id, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        "legacy_sensitive_json",
                        "2026-06-17T00:00:00+00:00",
                        "legacy",
                        "test",
                        "unit",
                        "target",
                        json.dumps({"private_key": "short", "resume_token": "safe-resume"}),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            result = audit_secrets(root, create=False)
            rendered = json.dumps(result, ensure_ascii=True, sort_keys=True)

            self.assertFalse(result["ok"], rendered)
            self.assertNotIn('"private_key": "short"', rendered)
            self.assertTrue(any(str(finding.get("scope", "")).startswith("sqlite_json:") for finding in result["findings"]))

    def test_redact_legacy_secrets_redacts_sensitive_keys_in_sqlite_json_columns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "epic-continuum"
            init_db(root)
            conn = connect(root)
            try:
                conn.execute(
                    "INSERT INTO audit_events(id, created_at, action, actor, target_type, target_id, payload_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        "legacy_redact_json",
                        "2026-06-17T00:00:00+00:00",
                        "legacy",
                        "test",
                        "unit",
                        "target",
                        json.dumps({"client_secret": "short", "resume_token": "safe-resume"}),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            dry = redact_legacy_secrets(root, dry_run=True)
            self.assertEqual(dry["redaction_count"], 1)
            applied = redact_legacy_secrets(root, dry_run=False)
            self.assertGreaterEqual(applied["redaction_count"], 1)
            conn = connect_existing(root)
            try:
                text = conn.execute("SELECT payload_json FROM audit_events WHERE id = ?", ("legacy_redact_json",)).fetchone()["payload_json"]
            finally:
                conn.close()
            self.assertNotIn('"client_secret": "short"', text)
            self.assertIn("[REDACTED]", text)
            self.assertIn("safe-resume", text)


if __name__ == "__main__":
    unittest.main()
