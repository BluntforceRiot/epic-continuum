from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum.core.operations import _proof_pack_hash
from continuum.mcp_server import TOOLS, dispatch


def call_tool(name: str, arguments: dict) -> dict:
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert response is not None
    result = response["result"]
    assert result["isError"] is False
    parsed = json.loads(result["content"][0]["text"])
    assert result["structuredContent"] == parsed
    return parsed


def call_tool_raw(name: str, arguments: dict) -> dict:
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert response is not None
    return response["result"]


class EpicContinuumMcpServerTest(unittest.TestCase):
    def test_initialize_and_list_tools(self) -> None:
        response = dispatch({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})

        self.assertIsNotNone(response)
        assert response is not None
        self.assertEqual(response["result"]["serverInfo"]["name"], "epic-continuum")
        self.assertEqual(response["result"]["protocolVersion"], "2025-11-25")
        self.assertEqual(response["result"]["serverInfo"]["supportedProtocolVersions"], ["2025-11-25"])
        self.assertIn("tools", response["result"]["capabilities"])

        negotiated = dispatch(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "initialize",
                "params": {"protocolVersion": "2025-11-25"},
            }
        )
        self.assertIsNotNone(negotiated)
        assert negotiated is not None
        self.assertEqual(negotiated["result"]["protocolVersion"], "2025-11-25")

        listed = dispatch({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})

        self.assertIsNotNone(listed)
        assert listed is not None
        names = {tool["name"] for tool in listed["result"]["tools"]}
        self.assertIn("continuum_append_event", names)
        self.assertIn("continuum_recover_thread", names)
        self.assertIn("continuum_optimize_config", names)
        self.assertIn("continuum_import_mempalace", names)
        self.assertIn("continuum_restore_drill", names)
        tools = {tool["name"]: tool for tool in listed["result"]["tools"]}
        self.assertTrue(tools["continuum_status"]["annotations"]["readOnlyHint"])
        self.assertTrue(tools["continuum_compile_context"]["annotations"]["readOnlyHint"])
        self.assertTrue(tools["continuum_audit_search_index"]["annotations"]["readOnlyHint"])
        self.assertFalse(tools["continuum_append_event"]["annotations"]["readOnlyHint"])
        self.assertFalse(tools["continuum_import_mempalace"]["annotations"]["readOnlyHint"])
        self.assertTrue(tools["continuum_init"]["annotations"]["idempotentHint"])
        self.assertTrue(tools["continuum_rebuild_search_index"]["annotations"]["idempotentHint"])
        self.assertTrue(tools["continuum_repair_permissions"]["annotations"]["idempotentHint"])
        self.assertFalse(tools["continuum_append_event"]["annotations"]["destructiveHint"])
        self.assertFalse(tools["continuum_import_mempalace"]["annotations"]["destructiveHint"])
        self.assertFalse(tools["continuum_rebuild_search_index"]["annotations"]["destructiveHint"])
        self.assertTrue(tools["continuum_prune_memory"]["annotations"]["destructiveHint"])
        self.assertFalse(tools["continuum_status"]["annotations"]["openWorldHint"])
        self.assertFalse(tools["continuum_doctor"]["annotations"]["openWorldHint"])
        self.assertTrue(tools["continuum_import_mempalace"]["annotations"]["openWorldHint"])
        self.assertFalse(tools["continuum_repair_permissions"]["annotations"]["openWorldHint"])
        self.assertIn("continuum_list_operations", names)
        self.assertIn("continuum_operation_summary", names)
        self.assertIn("continuum_recover_operations", names)
        self.assertIn("continuum_recovery_drill", names)
        self.assertIn("continuum_doctor", names)
        self.assertIn("continuum_verify_proof_pack", names)
        self.assertIn("continuum_verify_root", names)
        self.assertIn("continuum_pack_root", names)
        self.assertIn("continuum_verify_bundle", names)
        self.assertIn("continuum_replay_operation_log", names)
        self.assertIn("continuum_redact_legacy_secrets", names)
        self.assertIn("continuum_search", names)
        self.assertIn("continuum_audit_search_index", names)
        self.assertIn("continuum_rebuild_search_index", names)
        first_tool = listed["result"]["tools"][0]
        self.assertIn("outputSchema", first_tool)
        self.assertIn("title", first_tool)
        self.assertTrue(tools["continuum_pack_root"]["annotations"]["openWorldHint"])
        self.assertTrue(tools["continuum_verify_bundle"]["annotations"]["openWorldHint"])

    def test_tool_calls_append_status_and_recovery_packet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = str(Path(tmp) / "continuum")
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                event = call_tool(
                    "continuum_append_event",
                    {
                        "root": root,
                        "session_id": "mcp-flow",
                        "role": "user",
                        "content": "Epic Continuum MCP should recover this thread after a crash.",
                        "metadata": {"source": "test"},
                    },
                )

                self.assertEqual(event["seq"], 1)
                self.assertIn("_operation", event)
                self.assertEqual(event["_operation"]["status"], "succeeded")
                self.assertTrue(Path(event["_operation"]["proof_pack_uri"]).exists())

                proof_check = call_tool("continuum_verify_proof_pack", {"path": event["_operation"]["proof_pack_uri"]})
                self.assertTrue(proof_check["ok"])

                state = call_tool("continuum_status", {"root": root})
                self.assertEqual(state["scroll_events"], 1)

                doctor = call_tool("continuum_doctor", {"root": root, "verify_recent_proof_packs": 0})
                self.assertTrue(doctor["ok"])

                rolled = call_tool(
                    "continuum_roll_segment",
                    {"root": root, "session_id": "mcp-flow", "start_seq": 1, "end_seq": 1},
                )
                self.assertTrue(Path(rolled["card_uri"]).exists())
                proof = json.loads(Path(rolled["_operation"]["proof_pack_uri"]).read_text(encoding="utf-8"))
                sidecar_paths = {
                    str(Path(root) / str(item.get("uri") or item["path"]))
                    if item.get("uri_base") == "continuum_root"
                    else item["path"]: item
                    for item in proof["paths"]
                    if item.get("kind") == "file"
                }
                self.assertIn(rolled["card_uri"], sidecar_paths)
                self.assertIn("sha256", sidecar_paths[rolled["card_uri"]])

                recovery = call_tool(
                    "continuum_recover_thread",
                    {"root": root, "session_id": "mcp-flow", "query": "recover crash"},
                )
                self.assertTrue(Path(recovery["packet_uri"]).exists())
                self.assertIn("Epic Continuum Thread Recovery: mcp-flow", recovery["packet_text"])

    def test_repair_permissions_mcp_tool_dispatches_successfully(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = str(Path(tmp) / "continuum")
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                call_tool("continuum_init", {"root": root})
                repaired = call_tool("continuum_repair_permissions", {"root": root})

            self.assertTrue(repaired["ok"], repaired)
            self.assertEqual(repaired["_operation"]["status"], "succeeded")

    def test_every_advertised_mcp_tool_dispatches_without_runtime_handler_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            root = str(base / "continuum")
            source = base / "source.txt"
            source.write_text("MCP smoke content for Epic Continuum.\n", encoding="utf-8")
            prebundle = str(base / "prebundle.zip")
            smoke_bundle = str(base / "smoke-bundle.zip")
            missing_palace = str(base / "missing-mempalace")

            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                call_tool("continuum_init", {"root": root})
                event = call_tool(
                    "continuum_append_event",
                    {"root": root, "session_id": "mcp-smoke", "content": "smoke event"},
                )
                operation_id = event["_operation"]["operation_id"]
                proof_path = event["_operation"]["proof_pack_uri"]
                event_log = str(Path(root) / "exports" / "operation_events" / f"{operation_id}.jsonl")
                call_tool(
                    "continuum_pack_root",
                    {"root": root, "out_path": prebundle, "profile": "portable", "run_restore_drill": False},
                )

                smoke_args: dict[str, dict] = {
                    name: {"root": root}
                    for name, (_description, schema, _handler) in TOOLS.items()
                    if "root" in schema.get("properties", {})
                }
                smoke_args.update(
                    {
                        "continuum_append_event": {
                            "root": root,
                            "session_id": "mcp-smoke",
                            "content": "second smoke event",
                        },
                        "continuum_roll_segment": {
                            "root": root,
                            "session_id": "mcp-smoke",
                            "start_seq": 1,
                            "end_seq": 1,
                        },
                        "continuum_ingest_file": {"root": root, "path": str(source)},
                        "continuum_compile_context": {"root": root, "session_id": "mcp-smoke"},
                        "continuum_recover_thread": {"root": root, "session_id": "mcp-smoke"},
                        "continuum_search": {"root": root, "query": "smoke"},
                        "continuum_doctor": {"root": root, "verify_recent_proof_packs": 0, "scan_secrets": False},
                        "continuum_tier_storage": {"root": root, "dry_run": True},
                        "continuum_prune_memory": {"root": root, "dry_run": True, "all": True},
                        "continuum_verify_proof_pack": {"root": root, "path": proof_path},
                        "continuum_verify_root": {
                            "root": root,
                            "verify_recent_proof_packs": 0,
                            "run_restore_drill": False,
                            "scan_secrets": False,
                        },
                        "continuum_pack_root": {
                            "root": root,
                            "out_path": smoke_bundle,
                            "profile": "portable",
                            "run_restore_drill": False,
                        },
                        "continuum_verify_bundle": {"path": prebundle, "verify_embedded_root": False},
                        "continuum_replay_operation_log": {"path": event_log, "operation_id": operation_id},
                        "continuum_redact_legacy_secrets": {"root": root, "limit": 1},
                        "continuum_import_mempalace": {"root": root, "palace_path": missing_palace},
                        "continuum_operation_summary": {"root": root, "operation_id": operation_id},
                        "continuum_recover_operations": {"root": root, "dry_run": True},
                        "continuum_recovery_drill": {"root": root, "name": "mcp-smoke-recovery"},
                        "continuum_restore_drill": {
                            "root": root,
                            "name": "mcp-smoke-restore",
                            "verify_recent_proof_packs": 0,
                        },
                    }
                )

                missing = set(TOOLS) - set(smoke_args)
                self.assertFalse(missing, f"missing MCP smoke args for: {sorted(missing)}")

                with patch("continuum.mcp_server.traceback.print_exc"):
                    for name in sorted(TOOLS):
                        with self.subTest(tool=name):
                            result = call_tool_raw(name, smoke_args[name])
                            payload = json.loads(result["content"][0]["text"])
                            if result["isError"]:
                                error = str(payload.get("error", ""))
                                self.assertNotIn("not defined", error)
                                self.assertNotIn("NameError", error)
                                self.assertNotIn("AttributeError", error)

    def test_read_only_status_does_not_initialize_missing_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "missing-continuum"

            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                state = call_tool("continuum_status", {"root": str(root)})

            self.assertFalse(state["initialized"])
            self.assertFalse(root.exists())

    def test_mcp_rejects_roots_and_files_outside_allowed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as allowed, tempfile.TemporaryDirectory() as denied:
            denied_root = Path(denied) / "continuum"
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": allowed}):
                response = dispatch(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "continuum_status",
                            "arguments": {"root": str(denied_root)},
                        },
                    }
                )
                assert response is not None
                self.assertTrue(response["result"]["isError"])
                payload = json.loads(response["result"]["content"][0]["text"])
                self.assertIn("outside this MCP server's allowed roots", payload["error"])

            allowed_root = Path(allowed) / "continuum"
            denied_file = Path(denied) / "secret.txt"
            denied_file.write_text("do not ingest", encoding="utf-8")
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": allowed}):
                response = dispatch(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {
                            "name": "continuum_ingest_file",
                            "arguments": {"root": str(allowed_root), "path": str(denied_file)},
                        },
                    }
                )
                assert response is not None
                self.assertTrue(response["result"]["isError"])
                payload = json.loads(response["result"]["content"][0]["text"])
                self.assertIn("ingest source path is outside", payload["error"])

            denied_proof = Path(denied) / "fake-proof.json"
            denied_proof.write_text("{}", encoding="utf-8")
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": allowed}):
                response = dispatch(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {
                            "name": "continuum_verify_proof_pack",
                            "arguments": {"path": str(denied_proof)},
                        },
                    }
                )
                assert response is not None
                self.assertTrue(response["result"]["isError"])
                payload = json.loads(response["result"]["content"][0]["text"])
                self.assertIn("proof pack path is outside", payload["error"])

            allowed_proof = Path(allowed) / "fake-proof.json"
            allowed_proof.write_text("{}", encoding="utf-8")
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": allowed}):
                response = dispatch(
                    {
                        "jsonrpc": "2.0",
                        "id": 4,
                        "method": "tools/call",
                        "params": {
                            "name": "continuum_verify_proof_pack",
                            "arguments": {"path": str(allowed_proof), "root": str(denied_root)},
                        },
                    }
                )
                assert response is not None
                self.assertTrue(response["result"]["isError"])
                payload = json.loads(response["result"]["content"][0]["text"])
                self.assertIn("verification root path is outside", payload["error"])

    def test_mcp_verify_proof_pack_rejects_entries_outside_allowed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as allowed, tempfile.TemporaryDirectory() as denied:
            root = str(Path(allowed) / "continuum")
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": allowed}):
                event = call_tool(
                    "continuum_append_event",
                    {
                        "root": root,
                        "session_id": "mcp-proof-boundary",
                        "role": "user",
                        "content": "Create a proof pack.",
                    },
                )

            denied_file = Path(denied) / "secret.txt"
            denied_file.write_text("outside allowed roots", encoding="utf-8")
            proof_path = Path(event["_operation"]["proof_pack_uri"])
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            proof["paths"].append(
                {
                    "path": str(denied_file),
                    "uri": str(denied_file),
                    "exists": True,
                    "kind": "file",
                    "sha256": hashlib.sha256(denied_file.read_bytes()).hexdigest(),
                    "size_bytes": denied_file.stat().st_size,
                }
            )
            proof["proof_pack_hash"] = _proof_pack_hash(proof)
            proof_path.write_text(json.dumps(proof, ensure_ascii=True, indent=2), encoding="utf-8")

            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": allowed}):
                verification = call_tool("continuum_verify_proof_pack", {"path": str(proof_path)})

            self.assertFalse(verification["ok"])
            path_allowed_errors = [error for error in verification["errors"] if error.get("check") == "path_allowed"]
            self.assertEqual(len(path_allowed_errors), 1)
            denied_path_checks = [check for check in verification["checks"] if check.get("path") == str(denied_file)]
            self.assertFalse(any("actual_sha256" in check for check in denied_path_checks))

    def test_mcp_doctor_and_verify_root_confine_recent_proof_entries(self) -> None:
        with tempfile.TemporaryDirectory() as allowed, tempfile.TemporaryDirectory() as denied:
            root = str(Path(allowed) / "continuum")
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": allowed}):
                event = call_tool(
                    "continuum_append_event",
                    {
                        "root": root,
                        "session_id": "mcp-root-boundary",
                        "role": "user",
                        "content": "Create a proof pack for root-level verification.",
                    },
                )

            denied_file = Path(denied) / "outside.txt"
            denied_file.write_text("outside allowed roots", encoding="utf-8")
            proof_path = Path(event["_operation"]["proof_pack_uri"])
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            proof["paths"].append(
                {
                    "path": str(denied_file),
                    "uri": str(denied_file),
                    "exists": True,
                    "kind": "file",
                    "sha256": hashlib.sha256(denied_file.read_bytes()).hexdigest(),
                    "size_bytes": denied_file.stat().st_size,
                }
            )
            proof["proof_pack_hash"] = _proof_pack_hash(proof)
            proof_path.write_text(json.dumps(proof, ensure_ascii=True, indent=2), encoding="utf-8")

            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": allowed}):
                doctor = call_tool("continuum_doctor", {"root": root, "verify_recent_proof_packs": 1})
                verify_root_result = call_tool(
                    "continuum_verify_root",
                    {
                        "root": root,
                        "verify_recent_proof_packs": 1,
                        "run_restore_drill": False,
                        "scan_secrets": False,
                    },
                )

            self.assertFalse(doctor["ok"])
            doctor_errors = doctor["verified_proof_packs"][0]["errors"]
            self.assertTrue(any(error.get("check") == "path_allowed" for error in doctor_errors))
            self.assertFalse(verify_root_result["ok"])
            proof_errors = verify_root_result["sections"]["proof_packs"]["results"][0]["errors"]
            self.assertTrue(any(error.get("check") == "path_allowed" for error in proof_errors))
            proof_checks = verify_root_result["sections"]["proof_packs"]["results"][0]["checks"]
            denied_path_checks = [check for check in proof_checks if check.get("path") == str(denied_file)]
            self.assertFalse(any("actual_sha256" in check for check in denied_path_checks))

    def test_mcp_restore_drill_confines_recent_proof_entries(self) -> None:
        with tempfile.TemporaryDirectory() as allowed, tempfile.TemporaryDirectory() as denied:
            root = str(Path(allowed) / "continuum")
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": allowed}):
                event = call_tool(
                    "continuum_append_event",
                    {
                        "root": root,
                        "session_id": "mcp-restore-boundary",
                        "role": "user",
                        "content": "Create a proof pack for restore-drill verification.",
                    },
                )

            denied_file = Path(denied) / "outside-restore.txt"
            denied_file.write_text("outside allowed roots for restore drill", encoding="utf-8")
            proof_path = Path(event["_operation"]["proof_pack_uri"])
            proof = json.loads(proof_path.read_text(encoding="utf-8"))
            proof["paths"].append(
                {
                    "path": str(denied_file),
                    "uri": str(denied_file),
                    "exists": True,
                    "kind": "file",
                    "sha256": hashlib.sha256(denied_file.read_bytes()).hexdigest(),
                    "size_bytes": denied_file.stat().st_size,
                }
            )
            proof["proof_pack_hash"] = _proof_pack_hash(proof)
            proof_path.write_text(json.dumps(proof, ensure_ascii=True, indent=2), encoding="utf-8")

            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": allowed}):
                restore_result = call_tool(
                    "continuum_restore_drill",
                    {
                        "root": root,
                        "name": "mcp-restore-boundary",
                        "verify_recent_proof_packs": 10,
                    },
                )

            self.assertFalse(restore_result["ok"])
            recent_results = restore_result["recent_proof_packs"]["results"]
            self.assertTrue(
                any(
                    any(error.get("check") == "path_allowed" for error in result.get("errors", []))
                    for result in recent_results
                ),
                recent_results,
            )
            denied_path_checks = [
                check
                for result in recent_results
                for check in result.get("checks", [])
                if check.get("path") == str(denied_file)
            ]
            self.assertFalse(any("actual_sha256" in check for check in denied_path_checks))

    def test_mcp_verify_proof_pack_rejects_proof_root_outside_allowed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as allowed, tempfile.TemporaryDirectory() as denied:
            proof_path = Path(allowed) / "fake-proof.json"
            proof = {
                "schema": "epic_continuum.proof_pack.v1",
                "operation_id": "op_denied_root",
                "root": str(Path(denied) / "continuum"),
                "operation_receipt_hash": "missing",
                "paths": [
                    {
                        "uri": "run/operations/op_denied_root.json",
                        "uri_base": "continuum_root",
                        "path": "run/operations/op_denied_root.json",
                        "exists": False,
                        "kind": "file",
                    }
                ],
            }
            proof["proof_pack_hash"] = _proof_pack_hash(proof)
            proof_path.write_text(json.dumps(proof, ensure_ascii=True, indent=2), encoding="utf-8")

            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": allowed}):
                verification = call_tool("continuum_verify_proof_pack", {"path": str(proof_path)})

            self.assertFalse(verification["ok"])
            self.assertTrue(any(error.get("check") == "verification_root_allowed" for error in verification["errors"]))

    def test_mcp_restore_drill_rejects_snapshot_uri_outside_allowed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as allowed, tempfile.TemporaryDirectory() as denied:
            root = Path(allowed) / "continuum"
            denied_snapshot = Path(denied) / "catalog.sqlite3"
            denied_snapshot.write_text("not a real snapshot", encoding="utf-8")
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": allowed}):
                call_tool("continuum_init", {"root": str(root)})
                response = dispatch(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "continuum_restore_drill",
                            "arguments": {"root": str(root), "snapshot_uri": str(denied_snapshot)},
                        },
                    }
                )

            assert response is not None
            self.assertTrue(response["result"]["isError"])
            payload = json.loads(response["result"]["content"][0]["text"])
            self.assertIn("snapshot path is outside", payload["error"])

    def test_mcp_optional_int_rejects_json_boolean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                call_tool("continuum_init", {"root": str(root)})
                response = dispatch(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "continuum_search",
                            "arguments": {"root": str(root), "query": "anything", "limit": True},
                        },
                    }
                )

            assert response is not None
            self.assertTrue(response["result"]["isError"])
            payload = json.loads(response["result"]["content"][0]["text"])
            self.assertIn("limit must be an integer", payload["error"])

    def test_mcp_allow_stop_requires_explicit_process_permission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            palace = Path(tmp) / "palace"
            palace.mkdir()
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}, clear=False):
                response = dispatch(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "continuum_import_mempalace",
                            "arguments": {"root": str(root), "palace_path": str(palace), "allow_stop": True},
                        },
                    }
                )
            assert response is not None
            self.assertTrue(response["result"]["isError"])
            payload = json.loads(response["result"]["content"][0]["text"])
            self.assertIn("CONTINUUM_MCP_ALLOW_PROCESS_STOP", payload["error"])

    def test_tool_errors_are_returned_as_mcp_tool_errors(self) -> None:
        response = dispatch(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "continuum_append_event", "arguments": {"session_id": "bad"}},
            }
        )

        self.assertIsNotNone(response)
        assert response is not None
        result = response["result"]
        self.assertTrue(result["isError"])
        payload = json.loads(result["content"][0]["text"])
        self.assertIn("content must be a non-empty string", payload["error"])


if __name__ == "__main__":
    unittest.main()
