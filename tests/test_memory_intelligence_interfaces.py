from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from continuum.core.config import default_config, write_config
from continuum.core.store import append_scroll_event, init_db
from continuum.mcp_server import TOOLS, tool_annotations


class MemoryIntelligenceInterfacesTests(unittest.TestCase):
    """Real subprocess CLI/stdio and loopback HTTP; never an operator model."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="continuum-intelligence-")
        self.addCleanup(temp.cleanup)
        self.directory = Path(temp.name)
        self.root = self.directory / "memory"
        self.source = self.directory / "source"
        self.source.mkdir()
        config = default_config()
        config["capture"]["mode"] = "manual"
        config["local_inference"]["enabled"] = False
        write_config(self.root, config)
        init_db(self.root)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("CONTINUUM_")}
        self.env.update(CONTINUUM_ROOT=str(self.root), CONTINUUM_ALLOWED_ROOTS=str(self.source), PYTHONDONTWRITEBYTECODE="1")

    def cli(self, name, *args, ok=True):
        result = subprocess.run([sys.executable, "-B", "-m", "continuum", name, "--root", str(self.root), *args],
                                env=self.env, capture_output=True, text=True, encoding="utf-8", timeout=30)
        self.assertEqual(result.returncode, 0 if ok else 1, result.stderr + result.stdout)
        return json.loads(result.stdout)

    def mcp(self, name, arguments, ok=True):
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "fixture", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": name, "arguments": {"root": str(self.root), **arguments}}},
        ]
        result = subprocess.run([sys.executable, "-B", "-m", "continuum.mcp_server"],
                                input="".join(json.dumps(item) + "\n" for item in requests),
                                env=self.env, capture_output=True, text=True, encoding="utf-8", timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        reply = [json.loads(line) for line in result.stdout.splitlines() if line.strip()][-1]
        if "error" in reply:
            self.assertFalse(ok, reply)
            return reply
        self.assertEqual(reply["result"]["isError"], not ok, reply)
        return reply["result"]["structuredContent"]

    def provider(self):
        calls = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                calls.append((self.path, request))
                raw = json.dumps({"model": request["model"], "data": [
                    {"index": index, "embedding": [1.0, 0.25]} for index, _ in enumerate(request["input"])
                ]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}/v1", calls

    def test_temporal_cli_to_mcp_correction_and_history(self):
        first = self.cli("record-fact", "--project-id", "p", "--session-id", "s", "--subject", "service",
                         "--predicate", "route", "--value", "amber", "--valid-from", "2025-01-01T00:00:00Z")
        second = self.mcp("continuum_record_fact", {"project_id": "p", "session_id": "s", "subject": "service",
                           "predicate": "route", "value": "blue", "valid_from": "2025-01-01T00:00:00Z", "corrects": first["id"]})
        self.assertIn("_operation", first)
        self.assertIn("_operation", second)
        current = self.mcp("continuum_query_facts", {"project_id": "p"})
        self.assertEqual([item["value"] for item in current["results"]], ["blue"])
        history = self.cli("query-facts", "--project-id", "p", "--include-history")
        self.assertEqual(history["result_count"], 2)
        self.assertEqual(history["results"][1]["corrected_by"], second["id"])
        self.assertEqual(self.mcp("continuum_query_facts", {"project_id": "other"})["results"], [])

    def test_project_files_links_change_and_mcp_path_boundary(self):
        source = self.source / "module.py"
        source.write_text("import json\n\ndef parse(value):\n    return json.loads(value)\n", encoding="utf-8")
        indexed = self.cli("index-project-files", "--project-id", "p", "--session-id", "s",
                           "--source-root", str(self.source), "--path", "module.py")
        link = {"relation": "tests", "target_id": indexed["files"][0]["id"]}
        note = self.mcp("continuum_record_project_knowledge", {"project_id": "p", "session_id": "s", "kind": "test",
                        "title": "Parser fixture", "summary": "The parser consumes JSON", "links": [link]})
        packet = self.cli("project-context", "--project-id", "p", "--source-root", str(self.source))
        self.assertFalse(next(row for row in packet["results"] if row["id"] == note["id"])["needs_review"])
        source.write_text("def parse(value):\n    return value\n", encoding="utf-8")
        packet = self.mcp("continuum_project_context", {"project_id": "p", "source_root": str(self.source)})
        self.assertTrue(next(row for row in packet["results"] if row["id"] == note["id"])["needs_review"])
        again = self.mcp("continuum_index_project_files", {"project_id": "p", "session_id": "s",
                         "source_root": str(self.source), "paths": ["module.py"]})
        self.assertEqual(again["files"][0]["version"], 2)
        self.mcp("continuum_project_context", {"project_id": "p", "source_root": str(self.directory)}, ok=False)
        self.mcp("continuum_index_project_files", {"project_id": "p", "session_id": "s",
                 "source_root": str(self.source), "paths": ["../outside.py"]}, ok=False)

    def test_explicit_http_index_reuse_and_both_recall_interfaces(self):
        endpoint, calls = self.provider()
        append_scroll_event(self.root, session_id="s", event_type="message", role="user", content="amber router evidence",
                            metadata={"visibility_scope": "project", "project_id": "p"})
        database = self.root / "catalog" / "catalog.sqlite3"
        before = hashlib.sha256(database.read_bytes()).hexdigest()
        first = self.cli("index-embeddings", "--project-id", "p", "--endpoint", endpoint, "--model", "fixture-embed")
        self.assertEqual(first["status"], "refreshed")
        count = len(calls)
        self.assertGreater(count, 0)
        self.mcp("continuum_index_embeddings", {"project_id": "p", "endpoint": endpoint, "model": "fixture-embed"})
        self.assertEqual(len(calls), count)
        packet = self.cli("recall-indexed", "--project-id", "p", "--endpoint", endpoint, "--model", "fixture-embed", "--query", "router")
        self.assertTrue(packet["results"])
        packet = self.mcp("continuum_recall_indexed", {"project_id": "p", "endpoint": endpoint, "model": "fixture-embed", "query": "router"})
        self.assertTrue(packet["results"])
        self.assertEqual(before, hashlib.sha256(database.read_bytes()).hexdigest())
        self.assertTrue(all(path == "/v1/embeddings" for path, _ in calls))

    def test_fact_credentials_blocked_through_both_transports(self):
        value = "\n" + "fixture-sensitive-value-123456789"
        self.cli("record-fact", "--project-id", "p", "--session-id", "s", "--subject", "service", "--predicate", "api_key",
                 "--value", value, "--valid-from", "2025-01-01T00:00:00Z", ok=False)
        self.mcp("continuum_record_fact", {"project_id": "p", "session_id": "s", "subject": "service", "predicate": "api_key",
                 "value": value, "valid_from": "2025-01-01T00:00:00Z"}, ok=False)
        self.assertEqual(self.cli("query-facts", "--project-id", "p")["results"], [])

    def test_annotations_schemas_and_missing_root_reads(self):
        for name in ("continuum_recall_indexed", "continuum_query_facts", "continuum_project_context"):
            self.assertTrue(tool_annotations(name)["readOnlyHint"])
        self.assertFalse(tool_annotations("continuum_index_embeddings")["readOnlyHint"])
        self.assertTrue(tool_annotations("continuum_recall_indexed")["openWorldHint"])
        self.assertEqual(TOOLS["continuum_index_embeddings"][1]["properties"]["max_sources"]["maximum"], 5000)
        self.root = self.directory / "missing"
        self.env["CONTINUUM_ROOT"] = str(self.root)
        self.assertEqual(self.cli("query-facts", "--project-id", "p")["results"], [])
        self.assertEqual(self.mcp("continuum_project_context", {"project_id": "p"})["results"], [])
        self.assertFalse(self.root.exists())


if __name__ == "__main__":
    unittest.main()
