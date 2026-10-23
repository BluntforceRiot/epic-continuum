from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from continuum.core.capability_api import (
    CAPABILITIES, MAX_REQUEST_BYTES, READ_ACTIONS, WRITE_ACTIONS,
    parse_request_json, prepare_capability, validate_request,
)
from continuum.core.config import default_config, write_config
from continuum.core.knowledge_records import read_records
from continuum.core.store import append_scroll_event, connect, init_db
from continuum.mcp_server import TOOLS, tool_annotations


class CapabilityTransportTests(unittest.TestCase):
    """Real subprocess CLI and stdio MCP, always disposable explicit roots."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="continuum-capability-transport-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve(strict=True)
        self.root = self.directory / "memory"
        self.source = self.directory / "inputs"
        self.source.mkdir()
        self.destinations = self.directory / "outputs"
        self.destinations.mkdir()
        config = default_config()
        config["capture"]["mode"] = "manual"
        config["local_inference"]["enabled"] = False
        config["capture"]["dedup_window_seconds"] = 0
        write_config(self.root, config)
        init_db(self.root)
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("CONTINUUM_")}
        self.env.update(CONTINUUM_ROOT=str(self.root),
                        CONTINUUM_ALLOWED_ROOTS=os.pathsep.join([str(self.source), str(self.destinations)]),
                        PYTHONDONTWRITEBYTECODE="1")

    def cli(self, action: str, request: dict | None = None, *, raw: str | None = None,
            root: Path | str | None = None, ok: bool = True) -> dict:
        process = subprocess.run([sys.executable, "-B", "-m", "continuum", "knowledge", "--root",
            str(self.root if root is None else root), "--action", action, "--request-json",
            json.dumps(request) if raw is None else raw],
            env=self.env, capture_output=True, text=True, encoding="utf-8", timeout=45)
        if ok:
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        else:
            self.assertNotEqual(process.returncode, 0, process.stdout + process.stderr)
        return json.loads(process.stdout) if process.stdout.strip() else {"stderr": process.stderr}

    def rpc(self, call: dict | str) -> dict:
        initialize = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "fixture", "version": "1"}}}
        notification = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        wire = json.dumps(initialize) + "\n" + json.dumps(notification) + "\n"
        wire += (call if isinstance(call, str) else json.dumps(call)) + "\n"
        process = subprocess.run([sys.executable, "-B", "-m", "continuum.mcp_server"], input=wire,
            env=self.env, capture_output=True, text=True, encoding="utf-8", timeout=45)
        self.assertEqual(process.returncode, 0, process.stderr)
        return [json.loads(line) for line in process.stdout.splitlines() if line.strip()][-1]

    def mcp(self, action: str, request: dict, *, write: bool = False, root: Path | None = None, ok: bool = True) -> dict:
        reply = self.rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "continuum_knowledge_write" if write else "continuum_knowledge_read",
            "arguments": {"root": str(self.root if root is None else root), "action": action, "request": request}}})
        if "error" in reply:
            self.assertFalse(ok, reply)
            return reply
        self.assertEqual(reply["result"]["isError"], not ok, reply)
        return reply["result"]["structuredContent"]

    def source_citation(self, text: str = "The focused parser check passed.") -> dict:
        event = append_scroll_event(self.root, session_id="s", event_type="message", role="user", content=text,
            metadata={"project_id": "p", "visibility_scope": "project", "continuum_disable_exact_memory": True})
        return {"kind": "scroll_event", "id": event["event_id"], "content_hash": hashlib.sha256(text.encode()).hexdigest()}

    def db_hash(self, root: Path | None = None) -> str:
        return hashlib.sha256(((root or self.root) / "catalog" / "catalog.sqlite3").read_bytes()).hexdigest()

    def test_dispatch_rejects_nonplain_nonfinite_deep_and_oversized_inputs(self) -> None:
        for raw in ('{"project_id":"p","project_id":"other"}', '{"x":{"a":1,"a":2}}',
                    '{"x":NaN}', '{"x":Infinity}', '{"x":1e400}', '[1]', 'null',
                    '{"x":' + '[' * 24 + '0' + ']' * 24 + '}', '{"x":"' + 'a' * MAX_REQUEST_BYTES + '"}'):
            with self.subTest(raw=raw[:80]), self.assertRaises(ValueError):
                parse_request_json(raw)
        for request in ({"value": object()}, {"value": float("nan")}, {"value": 2**64},
                        {str(index): 1 for index in range(65)}, {"value": "bad\x00text"}):
            with self.subTest(request=repr(request)[:80]), self.assertRaises(ValueError):
                validate_request(request)
        request = {"project_id": "p", "query": "é" * 100}
        self.assertEqual(parse_request_json(json.dumps(request)), request)

    def test_registry_is_finite_and_read_write_annotations_match(self) -> None:
        self.assertFalse(set(READ_ACTIONS) & set(WRITE_ACTIONS))
        self.assertEqual(set(READ_ACTIONS) | set(WRITE_ACTIONS), set(CAPABILITIES))
        for name, actions, read in (("continuum_knowledge_read", READ_ACTIONS, True),
                                    ("continuum_knowledge_write", WRITE_ACTIONS, False)):
            schema = TOOLS[name][1]
            self.assertEqual(set(schema["required"]), {"root", "action", "request"})
            self.assertEqual(schema["properties"]["action"]["enum"], list(actions))
            self.assertEqual(tool_annotations(name)["readOnlyHint"], read)
            self.assertEqual(tool_annotations(name)["idempotentHint"], read)
        for action in ("os.system", "__import__", "record_project_state"):
            with self.assertRaisesRegex(ValueError, "unsupported"):
                prepare_capability(action, {})

    def test_cli_malformed_json_unknown_arguments_and_missing_root_do_not_mutate(self) -> None:
        absent = self.destinations / "missing"
        for raw in ('{"project_id":"p","project_id":"q"}', '{"project_id":"p","x":NaN}',
                    '{"project_id":"p","root":"override"}', '{"project_id":"p","unknown":1}'):
            self.cli("query_handoffs", raw=raw, root=absent, ok=False)
            self.assertFalse(absent.exists())
        self.cli("query_handoffs", {"project_id": "p"}, root="relative-root", ok=False)
        self.assertEqual(self.cli("query_handoffs", {"project_id": "p"}, root=absent)["results"], [])
        self.assertEqual(self.mcp("query_collections", {"project_id": "p"}, root=absent)["results"], [])
        self.assertFalse(absent.exists())

    def test_mcp_duplicate_keys_required_root_and_mutability_fail_before_capture(self) -> None:
        request = {"project_id": "p", "session_id": "s", "objective": "Run focused check", "actor": "operator"}
        before = self.db_hash()
        self.mcp("create_handoff", request, write=False, ok=False)
        self.mcp("query_handoffs", {"project_id": "p"}, write=True, ok=False)
        reply = self.rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "continuum_knowledge_read", "arguments": {"action": "query_handoffs", "request": {"project_id": "p"}}}})
        self.assertTrue(reply["result"]["isError"])
        wire = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
            "name": "continuum_knowledge_read", "arguments": {"root": str(self.root), "action": "query_handoffs",
            "request": {"project_id": "p"}}}}).replace('"project_id": "p"', '"project_id": "p", "project_id": "q"')
        self.assertIn("error", self.rpc(wire))
        self.assertEqual(before, self.db_hash())

    def test_handoff_cli_write_mcp_transition_and_read_only_status(self) -> None:
        handoff = self.cli("create_handoff", {"project_id": "p", "session_id": "s", "objective": "Run focused check", "actor": "operator"})
        self.assertIn("_operation", handoff)
        claim = self.mcp("transition_handoff", {"project_id": "p", "session_id": "s", "handoff_id": handoff["id"],
            "expected_head": handoff["id"], "action": "claim", "actor": "worker", "lease_seconds": 300}, write=True)
        self.assertIn("_operation", claim)
        before = self.db_hash()
        packet = self.cli("query_handoffs", {"project_id": "p", "include_history": True})
        self.assertEqual(packet["results"][0]["head"], claim["id"])
        self.assertEqual(packet["results"][0]["owner"], "worker")
        self.assertEqual(before, self.db_hash())
        complete = self.mcp("transition_handoff", {"project_id": "p", "session_id": "s", "handoff_id": handoff["id"],
            "expected_head": claim["id"], "action": "complete", "actor": "worker"}, write=True)
        self.assertEqual(self.mcp("query_handoffs", {"project_id": "p"})["results"][0]["head"], complete["id"])

    def test_collection_disclosure_rechecks_scope_and_hash(self) -> None:
        citation = self.source_citation()
        collection = self.cli("create_collection", {"project_id": "p", "session_id": "s", "title": "Checks",
            "summary": "Recorded parser checks", "overview": "Exact source below", "members": [citation]})
        request = {"project_id": "p", "collection_id": collection["id"], "detail": "full", "member_index": 0}
        self.assertIn("source", self.mcp("query_collections", request)["results"][0]["members"][0])
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE scroll_events SET visibility_scope='private' WHERE id=?", (citation["id"],))
            conn.commit()
        item = self.cli("query_collections", request)["results"][0]["members"][0]
        self.assertEqual(item["source_state"], "stale_or_unavailable")
        self.assertNotIn("source", item)

    def test_investigation_paths_notebook_export_and_read_nonmutation(self) -> None:
        (self.source / "fixture.bin").write_bytes(b"isolated fixture bytes")
        asset = self.cli("register_analysis_asset", {"project_id": "p", "session_id": "s", "source_root": str(self.source),
            "path": "fixture.bin", "asset_kind": "binary", "build_id": "fixture-build"})
        finding = self.mcp("record_analysis_finding", {"project_id": "p", "session_id": "s", "asset_id": asset["id"],
            "asset_hash": asset["payload"]["source_hash"], "title": "Parser hypothesis", "text": "Inspect the boundary.",
            "analyst": "operator", "function": "parse_frame"}, write=True)
        self.mcp("record_notebook_entry", {"project_id": "p", "session_id": "s", "notebook_id": "parser-note",
            "entry_kind": "observation", "title": "Boundary observation", "text": "A supplied finding needs verification.",
            "links": [{"relation": "supports", "target_id": finding["id"], "content_hash": finding["content_hash"]}]}, write=True)
        before = self.db_hash()
        exported = self.cli("export_investigation_notebook", {"project_id": "p", "notebook_id": "parser-note", "source_root": str(self.source)})
        self.assertIn("Boundary observation", json.dumps(exported))
        self.mcp("query_investigation", {"project_id": "p", "source_root": str(self.source)})
        self.assertEqual(before, self.db_hash())
        self.mcp("query_investigation", {"project_id": "p", "source_root": str(self.directory)}, ok=False)
        self.mcp("register_analysis_asset", {"project_id": "p", "session_id": "s", "source_root": str(self.directory),
            "path": "fixture.bin", "asset_kind": "binary", "build_id": "fixture"}, write=True, ok=False)
        self.assertEqual(before, self.db_hash())

    def test_experience_failure_success_proposal_and_explicit_acceptance(self) -> None:
        citation = self.source_citation()
        other_citation = self.source_citation("An independent parser fixture also passed.")
        base = {"project_id": "p", "session_id": "s", "goal": "Validate parser", "approach": "bounded fixtures",
                "prerequisites": {"format": "frame-v1"}, "steps": ["Run isolated checks"], "observed_result": "Observed fixture result"}
        self.cli("record_experience", {**base, "outcome": "failure"})
        first = self.cli("record_experience", {**base, "outcome": "success", "verification": [citation]})
        second = self.mcp("record_experience", {**base, "outcome": "success", "verification": [other_citation]}, write=True)
        procedure = self.cli("propose_procedure", {"project_id": "p", "session_id": "s",
            "experience_ids": [first["id"], second["id"]], "title": "Reusable parser check"})
        self.mcp("review_procedure", {"project_id": "p", "session_id": "s", "procedure_id": procedure["id"],
            "decision": "accept", "reviewer": "operator", "reason": "Verified matching local results"}, write=True)
        packet = self.cli("find_reusable_lessons", {"source_projects": ["p"], "goal": "parser", "prerequisites": {"format": "frame-v1"}})
        self.assertEqual(packet["result_count"], 1)
        self.assertFalse(packet["results"][0]["auto_apply"])
        history = self.mcp("query_experiences", {"project_id": "p"})
        self.assertIn("failure", [row["payload"].get("outcome") for row in history["results"]])

    def test_task_pack_impact_and_debugger_use_read_only_transports(self) -> None:
        record = self.cli("create_handoff", {"project_id": "p", "session_id": "s", "objective": "Parser boundary investigation", "actor": "operator"})
        before = self.db_hash()
        args = {"project_id": "p", "record_ids": [record["id"]], "purpose": "review"}
        pack = self.cli("compile_task_pack", args)
        self.assertEqual(pack["results"][0]["record"]["id"], record["id"])
        self.assertEqual(pack["packet_sha256"], self.mcp("compile_task_pack", args)["packet_sha256"])
        impact = self.mcp("change_impact", {"project_id": "p", "changed_record_ids": [record["id"]]})
        self.assertEqual(impact["results"][0]["id"], record["id"])
        diagnostic = self.cli("explain_memory", {"project_id": "p", "query": "Parser", "source_id": record["id"]})
        self.assertIn("reason", diagnostic)
        self.assertEqual(before, self.db_hash())

    def test_credentials_are_rejected_by_both_write_transports(self) -> None:
        secret = "sk-" + "b" * 48
        args = {"project_id": "p", "session_id": "s", "objective": secret, "actor": "operator"}
        self.cli("create_handoff", args, ok=False)
        self.mcp("create_handoff", args, write=True, ok=False)
        self.assertEqual(read_records(self.root, project_id="p"), [])
        self.assertNotIn(secret, (self.root / "catalog" / "catalog.sqlite3").read_bytes().decode("latin-1"))

    def test_workspace_export_import_replay_and_target_only_adoption(self) -> None:
        handoff = self.cli("create_handoff", {"project_id": "p", "session_id": "s", "objective": "Parser boundary investigation", "actor": "operator"})
        before = self.db_hash()
        capsule = self.mcp("export_workspace", {"project_id": "p", "record_ids": [handoff["id"]], "workspace_id": "fixture-share"})
        self.assertEqual(before, self.db_hash())
        target = self.destinations / "target"
        planned = self.mcp("plan_workspace_import", {"project_id": "target-p", "capsule": capsule,
            "expected_snapshot_hash": capsule["snapshot_hash"]}, root=target)
        self.assertTrue(planned["can_import"])
        self.assertFalse(target.exists())
        imported = self.cli("import_workspace", {"project_id": "target-p", "session_id": "s", "capsule": capsule,
            "expected_snapshot_hash": capsule["snapshot_hash"]}, root=target)
        self.assertIn("_operation", imported)
        destination = self.destinations / "experiment"
        experiment = self.mcp("create_memory_experiment", {"project_id": "p", "record_ids": [handoff["id"]],
            "workspace_id": "fixture-experiment", "destination": str(destination)}, write=True)
        self.assertNotIn("_operation", experiment)
        self.assertEqual(before, self.db_hash())
        replay_args = {"experiment_root": str(destination), "queries": ["Parser"], "expected_manifest_hash": experiment["manifest_sha256"]}
        replay = self.mcp("replay_memory_experiment", replay_args)
        compared = self.cli("compare_experiment_replays", {"before": replay, "after": replay})
        self.assertFalse(compared["queries"][0]["results_changed"])
        adopter = self.destinations / "adopter"
        adopted = self.mcp("adopt_experiment_records", {"experiment_root": str(destination), "target_root": str(adopter),
            "record_ids": [experiment["mapping"][0]["id"]], "project_id": "adopted", "session_id": "s",
            "workspace_id": "fixture-adoption", "expected_manifest_hash": experiment["manifest_sha256"]}, write=True)
        self.assertIn("_operation", adopted)
        self.assertTrue(Path(adopted["_operation"]["operation_receipt_uri"]).is_relative_to(adopter))
        self.assertEqual(before, self.db_hash())

    def test_mcp_checks_every_explicit_workspace_path_before_mutation(self) -> None:
        before = self.db_hash()
        self.mcp("create_memory_experiment", {"project_id": "p", "record_ids": ["missing"], "workspace_id": "fixture",
            "destination": str(self.directory / "forbidden")}, write=True, ok=False)
        self.mcp("replay_memory_experiment", {"experiment_root": str(self.directory), "queries": ["x"],
            "expected_manifest_hash": "0" * 64}, ok=False)
        self.mcp("adopt_experiment_records", {"experiment_root": str(self.destinations), "target_root": str(self.directory / "forbidden"),
            "record_ids": ["missing"], "project_id": "p", "session_id": "s", "workspace_id": "fixture",
            "expected_manifest_hash": "0" * 64}, write=True, ok=False)
        self.assertFalse((self.directory / "forbidden").exists())
        self.assertEqual(before, self.db_hash())


if __name__ == "__main__":
    unittest.main()
