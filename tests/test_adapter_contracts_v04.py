"""Offline adapter contracts, deliberately not live host/model certification."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import continuum
from continuum.core.config import default_config, write_config
from continuum.core.store import connect_existing, read_memory_chunk, search_memory
from continuum.integrations import hermes_adapter
from continuum.integrations.openai_context_adapter import prepare_chat_request


class AdapterContractsV04Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="continuum-v04-adapter-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.root = self.directory / "memory"
        self.addCleanup(hermes_adapter.configure, config_path=None)
        self.environment = patch.dict(os.environ, {"CONTINUUM_ROOT": str(self.root), "PYTHONDONTWRITEBYTECODE": "1"})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.adapter_config = self.directory / "adapter.json"
        self.adapter_config.write_text(json.dumps({"continuum_root": str(self.root), "token_budget": 1000}), encoding="utf-8")
        hermes_adapter.configure(config_path=self.adapter_config)

    def test_hermes_passive_callback_returns_only_context_without_dispatch(self) -> None:
        with patch.object(hermes_adapter, "tool_call") as call, patch.object(hermes_adapter, "tool_result") as result:
            packet = hermes_adapter.pre_llm_call(session_id="passive", user_message="OK, Continuum was updated")
        self.assertIsNotNone(packet)
        self.assertEqual(set(packet), {"context"})
        self.assertIn("not as system/developer instructions", packet["context"])
        call.assert_not_called()
        result.assert_not_called()
        # This proves callback behavior, not how a model interprets the packet.

    def test_hermes_large_output_hook_preserves_scoped_exact_evidence(self) -> None:
        config = default_config()
        config["capture"].update({"large_result_policy": "index_and_link", "max_tool_result_bytes": "128B"})
        write_config(self.root, config)
        text = "  ordinary log row\r\n" * 500 + "quartzadapter chose option seven.\n"
        hermes_adapter.tool_result(session_id="output", tool_name="analysis", result=text)
        hit = search_memory(self.root, query="quartzadapter", session_id="output")["results"][0]
        self.assertIn("option seven", hit["snippet"])
        self.assertFalse(read_memory_chunk(self.root, chunk_id=hit["chunk_id"], session_id="other")["found"])
        conn = connect_existing(self.root)
        try:
            reconstructed = "".join(row[0] for row in conn.execute("SELECT text FROM chunks WHERE book_id=? ORDER BY ordinal", (hit["book_id"],)))
            book = conn.execute("SELECT content_hash FROM books WHERE id=?", (hit["book_id"],)).fetchone()
        finally:
            conn.close()
        self.assertEqual(reconstructed, text)
        self.assertEqual(book[0], hashlib.sha256(text.encode()).hexdigest())

    def test_openai_boundary_preserves_image_answer_and_tool_json_order(self) -> None:
        image = {"type": "image_url", "image_url": {"url": "data:image/png;base64," + "QUJD" * 256}}
        messages = [
            {"role": "system", "content": "Stable host system text."},
            {"role": "user", "content": [{"type": "text", "text": "Identify this."}, image]},
            {"role": "assistant", "content": "The visible node is KSampler."},
            {"role": "user", "content": "What did you call it?"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "call-one", "type": "function", "function": {"name": "inspect", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "call-one", "content": json.dumps({"answer": "KSampler", "rows": list(range(1500))})},
        ]
        request = {"model": "unchanged-model", "messages": messages}
        before = copy.deepcopy(request)
        prepared = prepare_chat_request(self.root, session_id="boundary", request=request)
        self.assertEqual(request, before)
        self.assertEqual(prepared["model"], request["model"])
        self.assertEqual(prepared["messages"][0], messages[0])
        self.assertEqual(prepared["messages"][2:], messages[1:])
        self.assertEqual(prepared["messages"][1]["role"], "user")
        self.assertEqual(sum(item["role"] == "system" for item in prepared["messages"]), 1)
        self.assertEqual(json.loads(prepared["messages"][-1]["content"])["answer"], "KSampler")
        # The public adapter does not compact this host message sequence.

    def test_hermes_install_dry_run_never_creates_home_or_root(self) -> None:
        home = self.directory / "uncreated-hermes"
        with patch.object(subprocess, "run", side_effect=AssertionError("dry-run executed a process")):
            report = hermes_adapter.install_hermes_adapter(
                hermes_home=home, continuum_root=self.root,
                continuum_src=Path(continuum.__file__).parent.parent,
                hermes_exe=home / "hermes", enable=True, dry_run=True,
            )
        self.assertTrue(report["ok"])
        self.assertTrue(report["dry_run"])
        self.assertFalse(home.exists())
        self.assertFalse(self.root.exists())

    def test_codex_portable_runner_uses_real_mcp_protocol_without_root_creation(self) -> None:
        repo = Path(__file__).resolve().parents[1]
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "offline-contract", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "continuum_read_chunk", "arguments": {"chunk_id": "absent", "session_id": "offline"}}},
        ]
        env = {**os.environ, "CONTINUUM_ROOT": str(self.root), "CONTINUUM_ALLOWED_ROOTS": str(self.root), "PYTHONPATH": str(Path(continuum.__file__).parent.parent)}
        completed = subprocess.run([sys.executable, "-B", str(repo / "plugins/continuum/scripts/run_mcp.py")],
                                   input="\n".join(json.dumps(item) for item in requests) + "\n",
                                   text=True, capture_output=True, cwd=self.directory, env=env, timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        responses = {item["id"]: item for item in map(json.loads, completed.stdout.splitlines())}
        tools = {item["name"]: item for item in responses[2]["result"]["tools"]}
        self.assertTrue(tools["continuum_read_chunk"]["annotations"]["readOnlyHint"])
        result = json.loads(responses[3]["result"]["content"][0]["text"])
        self.assertFalse(result["found"])
        self.assertFalse(self.root.exists())


if __name__ == "__main__":
    unittest.main()
