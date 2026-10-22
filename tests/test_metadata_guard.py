from __future__ import annotations

import copy
import json
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from continuum.core.config import default_config, write_config
from continuum.core.operations import _apply_persistent_secret_policy
from continuum.core.safety import redact_value_secrets, scan_value_for_secrets
from continuum.core.store import (
    _scan_serialized_json_value_for_secrets,
    append_scroll_event,
    audit_secrets_sarif,
    connect,
    create_card,
    init_db,
)
from continuum.integrations.common import _apply_capture_secret_policy


# Synthetic values exercising existing patterns, never usable credentials.
SAMPLES = (
    "api_key=" + "sample-not-real-value",
    "password=" + "sample-not-real-value",
    "sk-" + "A1b2C3d4" * 4,
    "ghp_" + "A1b2C3d4" * 4,
)
SEPARATORS = (
    "\n", "\r", "\r\n", "\t", "\v", "\f", "\x1c", "\x1d", "\x1e",
    "\x85", "\u2028", "\u2029", "\xa0",
)


class MetadataGuardTest(unittest.TestCase):
    def make_root(self) -> Path:
        temporary = tempfile.TemporaryDirectory(prefix="continuum-metadata-guard-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "metadata-guard-root"
        init_db(root)
        return root

    def test_native_metadata_boundaries(self) -> None:
        for sample in SAMPLES:
            for separator in SEPARATORS:
                with self.subTest(sample=sample, separator=repr(separator)):
                    value = {"notes": "safe heading" + separator + sample}
                    before = copy.deepcopy(value)
                    findings = scan_value_for_secrets(value, scope="metadata")
                    self.assertTrue(findings)
                    self.assertTrue(all(item["scope"] == "metadata" for item in findings))
                    self.assertNotIn(sample, json.dumps(findings))
                    self.assertNotIn(sample, json.dumps(redact_value_secrets(value)))
                    self.assertEqual(value, before)

    def test_native_strings_in_all_supported_containers(self) -> None:
        text = "heading\n" + SAMPLES[2]
        values = {
            "root": text,
            "value": {"notes": text},
            "nested": {"notes": [{"body": text}]},
            "tuple": (text,),
            "key": {text: "safe"},
            "nested_key": {"notes": [{text: "safe"}]},
        }
        for shape, value in values.items():
            with self.subTest(shape=shape):
                before = copy.deepcopy(value)
                findings = scan_value_for_secrets(value, scope="metadata")
                self.assertTrue(findings)
                self.assertNotIn(SAMPLES[2], json.dumps(findings))
                self.assertEqual(value, before)

    def test_native_findings_respect_limit(self) -> None:
        value = {"notes": ["heading\n" + SAMPLES[2]] * 30}
        for limit in (1, 2, 5, 20):
            with self.subTest(limit=limit):
                self.assertEqual(
                    len(scan_value_for_secrets(value, scope="metadata", max_findings=limit)),
                    limit,
                )

    def test_safe_metadata_and_literal_backslashes_are_not_reinterpreted(self) -> None:
        value = {
            "notes": "Use the approved local helper.\nIt handles the existing login binding.",
            "literal": r"heading\n" + SAMPLES[2],
            "token_budget": 1200,
            "resume_token": "import:job-id",
            "clientSecret": "[REDACTED]",
            "authorization": "",
        }
        self.assertEqual(scan_value_for_secrets(value, scope="metadata"), [])
        self.assertEqual(redact_value_secrets(value), value)

    def test_wire_escape_forms_scan_after_json_decode(self) -> None:
        for wire_break in (r"\n", r"\u000a"):
            with self.subTest(wire_break=wire_break):
                value = json.loads('{"notes":"heading' + wire_break + SAMPLES[2] + '"}')
                self.assertTrue(scan_value_for_secrets(value, scope="metadata"))

    def test_native_newlines_do_not_shift_physical_jsonl_audit_lines(self) -> None:
        for prefix_lines in (0, 2):
            with self.subTest(prefix_lines=prefix_lines):
                wire = (json.dumps({"notes": "safe"}) + "\n") * prefix_lines
                wire += json.dumps({"notes": "heading\n\n" + SAMPLES[2]})
                findings = _scan_serialized_json_value_for_secrets(
                    wire, scope="file", max_findings=20
                )
                self.assertTrue(findings)
                self.assertEqual({item["line"] for item in findings}, {prefix_lines + 1})
                sarif = audit_secrets_sarif(
                    {"findings": [dict(item, path="fixture.jsonl") for item in findings]}
                )
                for result in sarif["runs"][0]["results"]:
                    region = result["locations"][0]["physicalLocation"]["region"]
                    self.assertEqual(region["startLine"], prefix_lines + 1)

    def test_existing_policy_modes_preserved(self) -> None:
        for action, enabled, expect_redacted in (
            ("warn", True, True), ("off", True, False), ("block", False, False)
        ):
            with self.subTest(action=action, enabled=enabled):
                root = self.make_root()
                config = default_config()
                config["security"]["secret_scan_action"] = action
                config["security"]["secret_scan_enabled"] = enabled
                write_config(root, config)
                metadata = {"notes": "heading\n" + SAMPLES[2]}
                result = append_scroll_event(
                    root, session_id="guard", role="user", event_type="message",
                    content="safe", metadata=metadata,
                )
                with closing(connect(root)) as conn:
                    stored = conn.execute(
                        "SELECT metadata_json FROM scroll_events WHERE id=?",
                        (result["event_id"],),
                    ).fetchone()[0]
                self.assertIs(SAMPLES[2] not in stored, expect_redacted)
                captured = _apply_capture_secret_policy(root, "safe", metadata)
                self.assertIsNotNone(captured)
                self.assertIs(SAMPLES[2] not in json.dumps(captured), expect_redacted)
                receipt = _apply_persistent_secret_policy(root, metadata, scope="receipt")
                self.assertIs(SAMPLES[2] not in json.dumps(receipt), expect_redacted)

    def test_card_capture_and_receipt_use_shared_guard(self) -> None:
        root = self.make_root()
        metadata = {"notes": [{"body": "heading\n" + SAMPLES[2]}]}
        with closing(connect(root)) as conn:
            with self.assertRaisesRegex(ValueError, "secret scan blocked"):
                create_card(
                    conn, root=root, card_type="note", title="safe", summary="safe",
                    source_refs=[], metadata=metadata,
                )
            self.assertEqual(conn.execute("SELECT count(*) FROM cards").fetchone()[0], 0)
        self.assertIsNone(_apply_capture_secret_policy(root, "safe", metadata))
        receipt = _apply_persistent_secret_policy(root, metadata, scope="receipt")
        self.assertNotIn(SAMPLES[2], json.dumps(receipt))
        self.assertTrue(receipt["secret_findings"])


if __name__ == "__main__":
    unittest.main()
