from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from continuum import mcp_server
from continuum.core.config import load_config
from continuum.core.store import (
    append_scroll_event,
    connect,
    connect_existing,
    create_card,
    cue_recall,
    init_db,
)


PILOT_NOTE = {
    "title": "SamplePortal approved login usage",
    "content": (
        "The synthetic account's SamplePortal login is available through the approved "
        "local sampleportal-helper adapter; use sampleportal-helper get home. The helper "
        "reads the local binding internally. No credential value or "
        "credential-file path belongs in the answer."
    ),
    "relevance_cue": "",
}
SAFE_VARIANTS = [
    PILOT_NOTE,
    {
        "title": "SamplePortal login binding",
        "content": (
            "Your SamplePortal login is available through the approved local "
            "sampleportal-helper adapter; use sampleportal-helper get home."
        ),
        "relevance_cue": "sampleportal login; sampleportal account; saved sampleportal access",
    },
    {
        "title": "SamplePortal access helper",
        "content": "Run sampleportal-helper get home.",
        "relevance_cue": "saved sampleportal access; sampleportal account",
    },
    {
        "title": "SamplePortal local login usage",
        "content": (
            "Use sampleportal-helper get home. The local sampleportal-helper handles "
            "SamplePortal login. Never expose secrets or credential-file paths."
        ),
        "relevance_cue": "sampleportal login",
    },
    {
        **PILOT_NOTE,
        "title": "  SAMPLEPORTAL  APPROVED LOGIN USAGE  ",
        "content": PILOT_NOTE["content"].replace("; ", ".\n").upper(),
    },
    {
        "title": "SamplePortal login",
        "content": (
            "The adapter uses the existing local binding internally; "
            "my SamplePortal access is handled by the local sampleportal-helper; "
            "run sampleportal-helper get home; do not store credential bytes."
        ),
        "relevance_cue": "",
    },
]

# Synthetic values only, exercising formats blocked by the existing policy.
BLOCKED_VALUES = [
    "api_key=" + "sample-not-real-value",
    "password=" + "sample-not-real-value",
    "Authorization: Bearer " + "A1b2C3d4" * 4,
    "sk-" + "A1b2C3d4" * 4,
    "ghp_" + "A1b2C3d4" * 4,
    "-----BEGIN PRIVATE KEY-----",
]


def append(root: Path, fields: dict[str, str]) -> dict:
    return append_scroll_event(
        root,
        session_id="shared-safe-note-test",
        event_type="message",
        role="agent",
        content=fields["content"],
        metadata={"title": fields["title"], "relevance_cue": fields["relevance_cue"]},
    )


def mcp_process(root: Path, calls: list[tuple[str, dict]]) -> list[dict]:
    env = os.environ.copy()
    env["CONTINUUM_ROOT"] = str(root)
    env["CONTINUUM_ALLOWED_ROOTS"] = str(root)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # Bind the subprocess to the same source or installed package under test.
    env["PYTHONPATH"] = str(Path(mcp_server.__file__).resolve().parents[1])
    requests = [
        {
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": mcp_server.PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "safe-note-regression", "version": "1"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]
    requests.extend(
        {"jsonrpc": "2.0", "id": index + 2, "method": "tools/call",
         "params": {"name": name, "arguments": args}}
        for index, (name, args) in enumerate(calls)
    )
    process = subprocess.run(
        [sys.executable, "-B", "-m", "continuum.mcp_server"],
        env=env, cwd=root.parent,
        input="\n".join(json.dumps(request) for request in requests) + "\n",
        capture_output=True, text=True, check=True, timeout=90,
    )
    responses = [json.loads(line) for line in process.stdout.splitlines()]
    if len(responses) != len(calls) + 1:
        raise AssertionError("Unexpected number of MCP responses")
    return responses[1:]


class SharedSafeNoteTest(unittest.TestCase):
    def make_root(self) -> Path:
        temporary = tempfile.TemporaryDirectory(prefix="continuum-safe-note-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "shared-safe-note-disposable"
        init_db(root)
        security = load_config(root)["security"]
        self.assertIs(security["secret_scan_enabled"], True)
        self.assertEqual(security["secret_scan_action"], "block")
        return root

    def test_shared_safe_note_admission_persistence_and_recall(self) -> None:
        for index, fields in enumerate(SAFE_VARIANTS):
            with self.subTest(variant=index):
                root = self.make_root()
                result = append(root, fields)
                with closing(connect_existing(root)) as conn:
                    row = conn.execute(
                        "SELECT content,metadata_json FROM scroll_events WHERE id=?",
                        (result["event_id"],),
                    ).fetchone()
                    self.assertEqual(row["content"], fields["content"])
                    self.assertEqual(json.loads(row["metadata_json"])["title"], fields["title"])
                    self.assertEqual(
                        json.loads(row["metadata_json"])["relevance_cue"], fields["relevance_cue"]
                    )
                recalled = cue_recall(root, cue="SamplePortal", session_id="shared-safe-note-test")
                self.assertIn(result["event_id"], json.dumps(recalled))
                self.assertIn("sampleportal-helper", json.dumps(recalled).lower())

    def test_shared_card_admits_same_safe_note(self) -> None:
        for index, fields in enumerate(SAFE_VARIANTS):
            with self.subTest(variant=index):
                root = self.make_root()
                with closing(connect(root)) as conn:
                    card_id = create_card(
                        conn,
                        root=root,
                        card_type="note",
                        title=fields["title"],
                        summary=fields["content"],
                        source_refs=[],
                        metadata={"relevance_cue": fields["relevance_cue"]},
                    )
                    conn.commit()
                    row = conn.execute(
                        "SELECT title,summary FROM cards WHERE id=?", (card_id,)
                    ).fetchone()
                    self.assertEqual(row["title"], fields["title"])
                    self.assertEqual(row["summary"], fields["content"])

    def test_safe_note_does_not_exempt_credential_values(self) -> None:
        for field in ("title", "content", "relevance_cue"):
            for value in BLOCKED_VALUES:
                with self.subTest(field=field, value=value):
                    root = self.make_root()
                    fields = dict(PILOT_NOTE)
                    fields[field] += "\n" + value
                    with self.assertRaises(ValueError) as raised:
                        append(root, fields)
                    self.assertNotIn(value, str(raised.exception))
                    with closing(connect_existing(root)) as conn:
                        self.assertEqual(
                            conn.execute("SELECT count(*) FROM scroll_events").fetchone()[0], 0
                        )

    def test_structured_credentials_still_block(self) -> None:
        root = self.make_root()
        with self.assertRaises(ValueError):
            append_scroll_event(
                root,
                session_id="shared-safe-note-test",
                event_type="message",
                role="agent",
                content=PILOT_NOTE["content"],
                metadata={"authorization": "synthetic-only"},
            )

    def test_actual_mcp_fresh_process_capture_reopen_and_credential_block(self) -> None:
        root = self.make_root()
        response = mcp_process(root, [("continuum_append_event", {
            "session_id": "shared-safe-note-test", "role": "agent",
            "content": PILOT_NOTE["content"],
            "metadata": {"title": PILOT_NOTE["title"]},
        })])[0]
        self.assertNotIn("error", response)
        self.assertFalse(response["result"].get("isError"))
        recalled = mcp_process(root, [("continuum_cue_recall", {
            "session_id": "shared-safe-note-test", "cue": "SamplePortal",
        })])[0]
        self.assertNotIn("error", recalled)
        self.assertFalse(recalled["result"].get("isError"))
        self.assertIn("sampleportal-helper get home", json.dumps(recalled))
        rejected = mcp_process(root, [("continuum_append_event", {
            "session_id": "shared-safe-note-test", "role": "agent",
            "content": PILOT_NOTE["content"] + "\n" + BLOCKED_VALUES[0],
        })])[0]
        self.assertTrue("error" in rejected or rejected["result"].get("isError"))
        with closing(connect_existing(root)) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM scroll_events").fetchone()[0], 1)

    def test_actual_mcp_blocks_newline_prefixed_metadata_credential(self) -> None:
        root = self.make_root()
        response = mcp_process(root, [("continuum_append_event", {
            "session_id": "shared-safe-note-test", "role": "agent",
            "content": PILOT_NOTE["content"],
            "metadata": {"title": PILOT_NOTE["title"] + "\n" + BLOCKED_VALUES[3]},
        })])[0]
        self.assertTrue("error" in response or response["result"].get("isError"))
        with closing(connect_existing(root)) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM scroll_events").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
