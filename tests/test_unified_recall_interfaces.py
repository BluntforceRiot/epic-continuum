from __future__ import annotations

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
from continuum.core.recall import read_memory_source, recall_memory
from continuum.core.store import append_scroll_event
from continuum.mcp_server import PROTOCOL_VERSION, TOOLS, _McpSessionState, dispatch, tool_annotations


def call_tool(name: str, arguments: dict) -> dict:
    state = _McpSessionState()
    dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
        "clientInfo": {"name": "recall-test", "version": "1"},
    }}, state)
    dispatch({"jsonrpc": "2.0", "method": "notifications/initialized"}, state)
    response = dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                         "params": {"name": name, "arguments": arguments}}, state)
    assert response is not None
    if "error" in response or response["result"].get("isError"):
        raise ValueError("MCP call rejected")
    result = response["result"]
    value = json.loads(result["content"][0]["text"])
    assert result["structuredContent"] == value
    return value


class UnifiedRecallInterfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="continuum-recall-interface-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.root = self.directory / "memory"
        self.text = "The cedarwalrus decision is to use amber." * 3
        self.event = append_scroll_event(self.root, session_id="testing", event_type="message",
                                         role="user", content=self.text)
        self.env = {**os.environ, "PYTHONPATH": str(Path(continuum.__file__).parent.parent),
                    "PYTHONDONTWRITEBYTECODE": "1", "CONTINUUM_ROOT": str(self.directory / "unused"),
                    "CONTINUUM_ALLOWED_ROOTS": str(self.root)}

    def cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-B", "-m", "continuum", *args], env=self.env,
                              cwd=self.directory, capture_output=True, text=True, timeout=60)

    def stdio(self, name: str, arguments: dict) -> dict:
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                "clientInfo": {"name": "recall-wire-test", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
             "params": {"name": name, "arguments": {"root": str(self.root), **arguments}}},
        ]
        completed = subprocess.run([sys.executable, "-B", "-m", "continuum.mcp_server"],
                                    input="".join(json.dumps(row) + "\n" for row in requests),
                                    env=self.env, cwd=self.directory, capture_output=True, text=True, timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        replies = {row["id"]: row for line in completed.stdout.splitlines() if (row := json.loads(line))}
        return replies[2]

    def test_cli_recall_and_hash_bound_exact_read(self) -> None:
        result = self.cli("recall", "--root", str(self.root), "--query", "cedarwalrus", "--session-id", "testing")
        self.assertEqual(result.returncode, 0, result.stderr)
        hit = json.loads(result.stdout)["results"][0]
        self.assertEqual(hit["kind"], "scroll_event")
        detail = self.cli("read-source", "--root", str(self.root), "--kind", hit["kind"], "--source-id", hit["id"],
                          "--content-hash", hit["content_hash"], "--session-id", "testing", "--offset", "4", "--limit", "17")
        self.assertEqual(detail.returncode, 0, detail.stderr)
        self.assertEqual(json.loads(detail.stdout)["content"], self.text[4:21])
        self.assertFalse((self.directory / "unused").exists())

    def test_cli_semantic_file_paraphrase(self) -> None:
        query = "What color was selected?"
        value = {"model": "synthetic-vectors", "query_hash": hashlib.sha256(query.encode()).hexdigest(),
                 "query_vector": [1, 0], "items": [{"kind": "scroll_event", "id": self.event["event_id"],
                  "content_hash": hashlib.sha256(self.text.encode()).hexdigest(), "vector": [1, 0]}]}
        source = self.directory / "vectors.json"
        source.write_text(json.dumps(value), encoding="utf-8")
        result = self.cli("recall", "--root", str(self.root), "--query", query, "--session-id", "testing",
                          "--semantic-input", str(source))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["results"][0]["ranks"]["semantic"], 1)

    def test_cli_rejects_oversized_or_invalid_semantic_file(self) -> None:
        source = self.directory / "vectors.json"
        for text in ("[", " " * (2 * 1024 * 1024 + 1)):
            source.write_text(text, encoding="utf-8")
            result = self.cli("recall", "--root", str(self.root), "--query", "cedarwalrus",
                              "--semantic-input", str(source))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("semantic input file", json.loads(result.stdout)["error"])

    def test_real_stdio_fractional_semantic_vectors_match_python(self) -> None:
        query = "What hue was picked?"
        semantic = {"model": "synthetic-vectors", "query_hash": hashlib.sha256(query.encode()).hexdigest(),
                    "query_vector": [0.8, 0.2], "items": [{"kind": "scroll_event", "id": self.event["event_id"],
                    "content_hash": hashlib.sha256(self.text.encode()).hexdigest(), "vector": [0.7, 0.3]}]}
        direct = recall_memory(self.root, query=query, semantic=semantic, session_id="testing")
        response = self.stdio("continuum_recall", {"query": query, "semantic": semantic, "session_id": "testing"})
        self.assertFalse(response["result"]["isError"], response)
        self.assertEqual(response["result"]["structuredContent"], direct)
        self.assertEqual(direct["results"][0]["ranks"]["semantic"], 1)

    def test_empty_constraints_rejected_by_api_cli_and_stdio(self) -> None:
        for field in ("created_after", "created_before"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    recall_memory(self.root, query="cedarwalrus", **{field: ""})
                cli = self.cli("recall", "--root", str(self.root), "--query", "cedarwalrus", "--" + field.replace("_", "-"), "")
                self.assertNotEqual(cli.returncode, 0)
                wire = self.stdio("continuum_recall", {"query": "cedarwalrus", field: ""})
                self.assertTrue("error" in wire or wire["result"]["isError"], wire)
        args = {"kind": "scroll_event", "source_id": self.event["event_id"], "session_id": "testing", "content_hash": ""}
        with self.assertRaises(ValueError):
            read_memory_source(self.root, **args)
        cli = self.cli("read-source", "--root", str(self.root), "--kind", "scroll_event", "--source-id",
                       self.event["event_id"], "--session-id", "testing", "--content-hash", "")
        self.assertNotEqual(cli.returncode, 0)
        wire = self.stdio("continuum_read_source", args)
        self.assertTrue("error" in wire or wire["result"]["isError"], wire)

    def test_mcp_real_dispatch_scope_readonly_and_schema(self) -> None:
        with patch.dict(os.environ, self.env):
            result = call_tool("continuum_recall", {"root": str(self.root), "query": "cedarwalrus", "session_id": "testing"})
            hit = result["results"][0]
            detail = call_tool("continuum_read_source", {"root": str(self.root), "kind": hit["kind"],
                                "source_id": hit["id"], "session_id": "testing", "limit": 7.0})
            denied = call_tool("continuum_read_source", {"root": str(self.root), "kind": hit["kind"], "source_id": hit["id"]})
        self.assertEqual(detail["content"], self.text[:7])
        self.assertFalse(denied["found"])
        for name in ("continuum_recall", "continuum_read_source"):
            self.assertTrue(tool_annotations(name)["readOnlyHint"])
            self.assertFalse(TOOLS[name][1]["additionalProperties"])

    def test_mcp_rejects_malformed_selectors_and_unknown_fields(self) -> None:
        with patch.dict(os.environ, self.env):
            for extra in ({"limit": True}, {"token_budget": 1}, {"bogus": "value"}, {"created_after": "2026-01-01"}):
                with self.subTest(extra=extra), self.assertRaises(ValueError):
                    call_tool("continuum_recall", {"root": str(self.root), "query": "cedarwalrus", **extra})
            with self.assertRaises(ValueError):
                call_tool("continuum_read_source", {"root": str(self.root), "kind": "chunk", "source_id": "../bad"})


if __name__ == "__main__":
    unittest.main()
