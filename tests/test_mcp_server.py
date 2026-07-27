from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing, redirect_stderr
from pathlib import Path
from typing import Any
from unittest.mock import patch

import continuum.core.store as store_module
import continuum.core.workers as worker_module
from continuum.core.config import default_config, write_config
from continuum.core.operations import (
    _proof_pack_hash,
    list_operations,
    verify_proof_pack,
)
from continuum.core.store import (
    MAX_RECENT_EVENT_LIMIT,
    _backfill_partition_aliases,
    append_scroll_event,
    connect,
    create_card,
    ingest_file,
    init_db,
    record_project_state,
    recover_thread,
    sync_card_sidecars_after_commit,
)
from continuum.core.workers import MAX_PRUNE_MEMORY_LIMIT
import continuum.mcp_server as mcp_server_module
from continuum.mcp_server import MAX_MCP_REQUEST_BYTES, TOOLS, dispatch


def ready_session_state() -> mcp_server_module._McpSessionState:
    state = mcp_server_module._McpSessionState()
    initialized = dispatch(
        {
            "jsonrpc": "2.0",
            "id": "test-initialize",
            "method": "initialize",
            "params": {
                "protocolVersion": mcp_server_module.PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
        },
        state,
    )
    assert initialized is not None and "result" in initialized
    assert (
        dispatch(
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            state,
        )
        is None
    )
    assert state.phase == "ready"
    return state


def dispatch_ready(request: dict[str, Any]) -> dict[str, Any] | None:
    return dispatch(request, ready_session_state())


def call_tool(name: str, arguments: dict) -> dict:
    response = dispatch_ready(
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
    response = dispatch_ready(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert response is not None
    return response["result"]


def tree_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    if not root.exists():
        return digest.hexdigest()
    catalog_path = root / "catalog" / "catalog.sqlite3"
    if catalog_path.exists():
        # Read-only access to a live WAL catalog may create empty SQLite
        # runtime sidecars.  Compare the logical database instead of treating
        # those files as durable state, while still detecting real SQL writes.
        conn = sqlite3.connect(f"{catalog_path.resolve().as_uri()}?mode=ro", uri=True)
        try:
            digest.update(b"catalog-logical\0")
            for pragma in ("application_id", "user_version", "page_size", "auto_vacuum"):
                digest.update(pragma.encode("ascii"))
                digest.update(b"=")
                digest.update(str(conn.execute(f"PRAGMA {pragma}").fetchone()[0]).encode("ascii"))
                digest.update(b"\0")
            for statement in conn.iterdump():
                digest.update(statement.encode("utf-8"))
                digest.update(b"\0")
        finally:
            conn.close()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        rel = path.relative_to(root).as_posix()
        if path == catalog_path or rel in {"catalog/catalog.sqlite3-wal", "catalog/catalog.sqlite3-shm"}:
            continue
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def valid_initialize_params() -> dict[str, Any]:
    return {
        "protocolVersion": mcp_server_module.PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "continuum-test-client", "version": "1.0.0"},
    }


def stdio_handshake_requests(*, initialize_id: int = 900) -> list[dict[str, Any]]:
    return [
        {
            "jsonrpc": "2.0",
            "id": initialize_id,
            "method": "initialize",
            "params": valid_initialize_params(),
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]


class EpicContinuumMcpServerTest(unittest.TestCase):
    def test_run_workers_wrapper_preserves_bounded_sidecar_ownership_and_proof(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                for index in range(60):
                    token = hashlib.sha256(
                        f"mcp-worker-sidecar:{index}".encode()
                    ).hexdigest()
                    create_card(
                        conn,
                        root=root,
                        card_type="note",
                        title=token,
                        summary=hashlib.sha256(
                            f"mcp-worker-summary:{index}".encode()
                        ).hexdigest(),
                        source_refs=[],
                    )
                intent_row = conn.execute(
                    "SELECT * FROM cards ORDER BY id LIMIT 1"
                ).fetchone()
                intent_card_id = str(intent_row["id"])
                intent_state_hash = str(
                    store_module._card_sidecar_payload_for_row(intent_row)[
                        "state_hash"
                    ]
                )
                conn.execute("DELETE FROM queue_jobs")
                conn.commit()
            finally:
                conn.close()
            _intent_id, intent_path = (
                store_module._write_card_sidecar_write_intent(
                    root,
                    card_id=intent_card_id,
                    target_uri=f"catalog/cards/{intent_card_id}.yaml",
                    expected_state_hash=intent_state_hash,
                )
            )

            with (
                patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}),
                patch.object(
                    store_module,
                    "sync_pending_card_sidecars",
                    wraps=store_module.sync_pending_card_sidecars,
                ) as generic_recovery,
                patch.object(
                    worker_module,
                    "reconcile_card_sidecar_write_intents",
                    wraps=store_module.reconcile_card_sidecar_write_intents,
                ) as generic_intent_recovery,
            ):
                deferred = call_tool(
                    "continuum_run_workers",
                    {
                        "root": str(root),
                        "limit": 1,
                        "no_maintenance": True,
                    },
                )
                conn = connect(root)
                try:
                    deferred_pending = int(
                        conn.execute(
                            "SELECT count(*) AS n FROM card_sidecar_outbox"
                        ).fetchone()["n"]
                    )
                finally:
                    conn.close()
                generic_intent_recovery.assert_not_called()
                self.assertTrue(intent_path.is_file())
                bounded = call_tool(
                    "continuum_run_workers",
                    {"root": str(root), "limit": 1},
                )

            self.assertTrue(deferred["ok"], deferred)
            self.assertEqual(deferred_pending, 60, deferred)
            self.assertTrue(bounded["ok"], bounded)
            self.assertEqual(bounded["maintenance"]["sidecars"]["pending"], 50)
            self.assertEqual(bounded["maintenance"]["sidecars"]["synced"], 50)
            generic_recovery.assert_not_called()
            conn = connect(root)
            try:
                remaining = int(
                    conn.execute(
                        "SELECT count(*) AS n FROM card_sidecar_outbox"
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(remaining, 10, bounded)
            for result in (deferred, bounded):
                self.assertEqual(result["_operation"]["status"], "succeeded")
                proof_path = Path(result["_operation"]["proof_pack_uri"])
                self.assertTrue(proof_path.is_file())
                self.assertTrue(
                    verify_proof_pack(
                        proof_path,
                        root=root,
                        allowed_roots=[root],
                    )["ok"]
                )

    def test_run_workers_failure_keeps_sidecars_and_marks_operation_failed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="mcp-worker-failure",
                    summary="The failed bounded drain must remain pending.",
                    source_refs=[],
                )
                conn.execute("DELETE FROM queue_jobs")
                conn.commit()
            finally:
                conn.close()
            failed_sync = {
                "ok": False,
                "synced": 0,
                "failed": 1,
                "failures": [{"error": "simulated MCP worker drain failure"}],
            }

            with (
                patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}),
                patch.object(
                    worker_module,
                    "sync_card_sidecars_after_commit",
                    return_value=failed_sync,
                ),
                patch.object(
                    store_module,
                    "sync_pending_card_sidecars",
                    wraps=store_module.sync_pending_card_sidecars,
                ) as generic_recovery,
            ):
                result = call_tool(
                    "continuum_run_workers",
                    {"root": str(root), "limit": 1},
                )

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["_operation"]["status"], "failed")
            generic_recovery.assert_not_called()
            conn = connect(root)
            try:
                pending = (
                    conn.execute(
                        "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                        (card_id,),
                    ).fetchone()
                    is not None
                )
            finally:
                conn.close()
            self.assertTrue(pending, result)
            proof_path = Path(result["_operation"]["proof_pack_uri"])
            self.assertTrue(proof_path.is_file())
            self.assertTrue(
                verify_proof_pack(
                    proof_path,
                    root=root,
                    allowed_roots=[root],
                )["ok"]
            )

    def test_mcp_resume_migrates_authority_indexes_before_discovery(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="mcp-upgrade-session",
                agent_id="codex-sol",
                project_id="mcp-upgrade-project",
                objective="Migrate before MCP resume discovery.",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "DROP INDEX idx_graph_edge_sources_card_id_authority"
                )
                conn.execute(
                    "DROP INDEX "
                    "idx_graph_edge_sources_source_ref_key_authority"
                )
                conn.commit()
            finally:
                conn.close()
            store_module._INIT_DB_CACHE.discard(
                str(root.resolve(strict=False))
            )

            with patch.dict(
                "os.environ",
                {"CONTINUUM_ALLOWED_ROOTS": tmp},
            ):
                result = call_tool(
                    "continuum_resume_latest",
                    {
                        "root": str(root),
                        "project_id": "mcp-upgrade-project",
                        "model_assist": False,
                    },
                )

            self.assertTrue(result["ok"], result)
            conn = connect(root)
            try:
                indexes = {
                    str(row["name"])
                    for row in conn.execute(
                        "PRAGMA index_list(graph_edge_sources)"
                    ).fetchall()
                }
            finally:
                conn.close()
            self.assertTrue(
                store_module.RESUME_AUTHORITY_INDEX_NAMES.issubset(
                    indexes
                ),
                indexes,
            )

    def test_stdio_allows_ping_before_and_during_initialize(self) -> None:
        requests = (
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            *stdio_handshake_requests(initialize_id=2)[:1],
            {"jsonrpc": "2.0", "id": 3, "method": "ping"},
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {"_meta": {"progressToken": 0.5, "client": "ready"}},
            },
            {"jsonrpc": "2.0", "id": 4, "method": "ping"},
        )
        stdin = io.StringIO("\n".join(json.dumps(request) for request in requests) + "\n")
        stdout = io.StringIO()

        with (
            patch.object(mcp_server_module.sys, "stdin", stdin),
            patch.object(mcp_server_module.sys, "stdout", stdout),
        ):
            self.assertEqual(mcp_server_module.serve(), 0)

        responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual([response["id"] for response in responses], [1, 2, 3, 4])
        for response in (responses[0], responses[2], responses[3]):
            self.assertEqual(response["result"], {})
        self.assertEqual(responses[1]["result"]["protocolVersion"], mcp_server_module.PROTOCOL_VERSION)

    def test_stdio_rejects_malformed_envelopes_and_recovers_with_ping(self) -> None:
        malformed: list[tuple[str, int]] = []
        for request in (
            {"id": 1, "method": "ping"},
            {"jsonrpc": "1.0", "id": 2, "method": "ping"},
            {"jsonrpc": 2.0, "id": 3, "method": "ping"},
            {"jsonrpc": "2.0", "id": 4, "method": None},
            {"jsonrpc": "2.0", "id": 5, "method": ""},
            {"jsonrpc": "2.0", "id": 6, "method": 1},
            {"jsonrpc": "2.0", "id": 7, "method": []},
            {"jsonrpc": "2.0", "id": 8, "method": {}},
        ):
            malformed.append((json.dumps(request), -32600))
        for index, params in enumerate((None, False, 0, 0.0, "", []), start=10):
            malformed.append(
                (
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": index,
                            "method": "ping",
                            "params": params,
                        }
                    ),
                    -32602,
                )
            )
        malformed.extend(
            (
                ('{"jsonrpc":"2.0","id":20,"method":"ping","method":"tools/list"}', -32700),
                ('{"jsonrpc":"2.0","id":NaN,"method":"ping"}', -32700),
                ('{"jsonrpc":"2.0","id":Infinity,"method":"ping"}', -32700),
                ('{"jsonrpc":"2.0","id":-Infinity,"method":"ping"}', -32700),
                ('{"jsonrpc":"2.0","id":1e400,"method":"ping"}', -32700),
            )
        )
        malformed.append(
            (
                '{"jsonrpc":"2.0","id":'
                + "1" * (mcp_server_module.MAX_MCP_JSON_INTEGER_DIGITS + 1)
                + ',"method":"ping"}',
                -32700,
            )
        )
        recovery = [
            *stdio_handshake_requests(),
            {"jsonrpc": "2.0", "id": 99, "method": "ping"},
        ]
        stdin = io.StringIO(
            "\n".join(line for line, _code in malformed)
            + "\n"
            + "\n".join(json.dumps(request) for request in recovery)
            + "\n"
        )
        stdout = io.StringIO()

        with (
            patch.object(mcp_server_module.sys, "stdin", stdin),
            patch.object(mcp_server_module.sys, "stdout", stdout),
        ):
            self.assertEqual(mcp_server_module.serve(), 0)

        responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(len(responses), len(malformed) + 2)
        self.assertEqual(
            [response["error"]["code"] for response in responses[: len(malformed)]],
            [code for _line, code in malformed],
        )
        for response in responses[14 : len(malformed)]:
            self.assertNotIn("id", response)
        self.assertEqual(responses[-2]["id"], 900)
        self.assertEqual(responses[-1], {"jsonrpc": "2.0", "id": 99, "result": {}})

    def test_dispatch_rejects_invalid_request_ids(self) -> None:
        for request_id in (
            None,
            True,
            False,
            1.5,
            [],
            {},
            float("nan"),
            float("inf"),
            float("-inf"),
        ):
            with self.subTest(request_id=request_id):
                response = dispatch_ready(
                    {
                        "jsonrpc": "2.0",
                        "id": request_id,
                        "method": "ping",
                    }
                )
                assert response is not None
                self.assertNotIn("id", response)
                self.assertEqual(response["error"]["code"], -32600)

        for request_id in (0, -1, 1.0, -0.0, "request-id"):
            with self.subTest(valid_request_id=request_id):
                response = dispatch_ready({"jsonrpc": "2.0", "id": request_id, "method": "ping"})
                assert response is not None
                self.assertEqual(response, {"jsonrpc": "2.0", "id": request_id, "result": {}})

    def test_real_stdio_process_preserves_exact_integral_ids_and_rejects_fractional_ids(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        env["PYTHONPATH"] = os.pathsep.join(
            part
            for part in (str(repo_root / "src"), env.get("PYTHONPATH", ""))
            if part
        )
        stdin = "\n".join(
            (
                '{"jsonrpc":"2.0","id":9007199254740993.0,"method":"ping"}',
                '{"jsonrpc":"2.0","id":1.0000000000000001,"method":"ping"}',
                '{"jsonrpc":"2.0","id":1e-4000,"method":"ping"}',
                '{"jsonrpc":"2.0","id":7,"method":"ping"}',
                "",
            )
        )

        process = subprocess.run(
            [sys.executable, "-m", "continuum.mcp_server"],
            cwd=repo_root,
            env=env,
            input=stdin,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )

        self.assertEqual(process.returncode, 0, process.stderr)
        responses = [json.loads(line) for line in process.stdout.splitlines()]
        self.assertEqual(
            responses[0],
            {"jsonrpc": "2.0", "id": 9007199254740993, "result": {}},
        )
        for response in responses[1:3]:
            self.assertNotIn("id", response)
            self.assertEqual(response["error"]["code"], -32600)
        self.assertEqual(responses[3], {"jsonrpc": "2.0", "id": 7, "result": {}})

    def test_stdio_open_metadata_numbers_remain_serializable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            tool_request = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {
                        "name": "continuum_append_event",
                        "arguments": {
                            "root": str(root),
                            "session_id": "numeric-metadata",
                            "content": "Preserve serializable open metadata.",
                            "metadata": {
                                "ratio": "__RATIO__",
                                "rounded": "__ROUNDED__",
                                "tiny": "__TINY__",
                            },
                        },
                    },
                },
                separators=(",", ":"),
            )
            tool_request = (
                tool_request.replace('"__RATIO__"', "0.5")
                .replace('"__ROUNDED__"', "1.0000000000000001")
                .replace('"__TINY__"', "1e-4000")
            )
            stdin = io.StringIO(
                "\n".join(
                    [
                        *(json.dumps(request) for request in stdio_handshake_requests()),
                        tool_request,
                        "",
                    ]
                )
            )
            stdout = io.StringIO()

            with (
                patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}),
                patch.object(mcp_server_module.sys, "stdin", stdin),
                patch.object(mcp_server_module.sys, "stdout", stdout),
            ):
                self.assertEqual(mcp_server_module.serve(), 0)

            responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
            self.assertEqual([response["id"] for response in responses], [900, 5])
            self.assertFalse(responses[1]["result"]["isError"], responses[1])
            conn = connect(root)
            try:
                row = conn.execute(
                    "SELECT metadata_json FROM scroll_events WHERE session_id = ?",
                    ("numeric-metadata",),
                ).fetchone()
            finally:
                conn.close()
            self.assertIsNotNone(row)
            metadata = json.loads(row["metadata_json"])
            self.assertEqual(metadata["ratio"], 0.5)
            self.assertEqual(metadata["rounded"], 1.0)
            self.assertEqual(metadata["tiny"], 0.0)

    def test_notifications_do_not_respond_or_execute_request_methods(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            default_root = base / "default-root"
            requests = (
                {"jsonrpc": "2.0", "method": "ping"},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "method": "ping", "params": None},
                {"jsonrpc": "2.0", "method": "tools/call", "params": []},
                {
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {"name": "continuum_init", "arguments": {}},
                },
                {"jsonrpc": "2.0", "id": 60, "method": "notifications/initialized"},
                *stdio_handshake_requests(initialize_id=70),
                {"jsonrpc": "2.0", "id": 61, "method": "ping"},
            )
            stdin = io.StringIO("\n".join(json.dumps(request) for request in requests) + "\n")
            stdout = io.StringIO()

            with (
                patch.dict(
                    "os.environ",
                    {
                        "CONTINUUM_ROOT": str(default_root),
                        "CONTINUUM_ALLOWED_ROOTS": str(base),
                    },
                ),
                patch.object(mcp_server_module.sys, "stdin", stdin),
                patch.object(mcp_server_module.sys, "stdout", stdout),
            ):
                self.assertEqual(mcp_server_module.serve(), 0)

            responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
            self.assertEqual(len(responses), 3)
            self.assertEqual(responses[0]["id"], 60)
            self.assertEqual(responses[0]["error"]["code"], -32600)
            self.assertEqual(responses[1]["id"], 70)
            self.assertEqual(responses[2], {"jsonrpc": "2.0", "id": 61, "result": {}})
            self.assertFalse(default_root.exists())
            self.assertEqual(list(base.iterdir()), [])

    def test_invalid_request_metadata_cannot_unlock_or_execute(self) -> None:
        state = mcp_server_module._McpSessionState()
        initialize = dispatch(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": valid_initialize_params(),
            },
            state,
        )
        self.assertIsNotNone(initialize)
        self.assertEqual(state.phase, "initializing")

        self.assertIsNone(
            dispatch(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {"_meta": False},
                },
                state,
            )
        )
        self.assertEqual(state.phase, "initializing")
        blocked = dispatch(
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            state,
        )
        assert blocked is not None
        self.assertEqual(blocked["error"]["code"], -32600)

        self.assertIsNone(
            dispatch(
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {"_meta": {"client": "ready", "progressToken": 0.5}},
                },
                state,
            )
        )
        self.assertEqual(state.phase, "ready")

        with patch.object(mcp_server_module, "tool_specs") as tool_specs:
            for request_id, metadata, expected_error in (
                (3, False, "params._meta must be an object"),
                (4, {"progressToken": 0.5}, "params._meta.progressToken must be string or integer"),
            ):
                with self.subTest(metadata=metadata):
                    response = dispatch(
                        {
                            "jsonrpc": "2.0",
                            "id": request_id,
                            "method": "tools/list",
                            "params": {"_meta": metadata},
                        },
                        state,
                    )
                    assert response is not None
                    self.assertEqual(response["error"]["code"], -32602)
                    self.assertIn(expected_error, response["error"]["message"])
            tool_specs.assert_not_called()

        handler_calls: list[dict[str, Any]] = []

        def handler(arguments: dict[str, Any]) -> dict[str, Any]:
            handler_calls.append(arguments)
            return {"called": True}

        with patch.dict(
            mcp_server_module.TOOLS,
            {
                "continuum_metadata_probe": (
                    "Metadata validation probe.",
                    {"type": "object", "additionalProperties": False},
                    handler,
                )
            },
        ):
            tool_response = dispatch(
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {
                        "_meta": False,
                        "name": "continuum_metadata_probe",
                        "arguments": {},
                    },
                },
                state,
            )
        assert tool_response is not None
        self.assertEqual(tool_response["error"]["code"], -32602)
        self.assertEqual(handler_calls, [])

        accepted = dispatch(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "ping",
                "params": {"_meta": {"progressToken": "progress-5"}},
            },
            state,
        )
        self.assertEqual(accepted, {"jsonrpc": "2.0", "id": 5, "result": {}})

    def test_list_methods_reject_unissued_or_malformed_cursors(self) -> None:
        state = ready_session_state()
        for method in ("tools/list", "resources/list", "prompts/list"):
            for cursor in (False, 1, [], {}):
                with self.subTest(method=method, cursor=cursor):
                    response = dispatch(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": method,
                            "params": {"cursor": cursor},
                        },
                        state,
                    )
                    assert response is not None
                    self.assertEqual(response["error"]["code"], -32602)
                    self.assertIn("params.cursor must be a string", response["error"]["message"])

            response = dispatch(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": method,
                    "params": {"cursor": "never-issued"},
                },
                state,
            )
            assert response is not None
            self.assertEqual(response["error"]["code"], -32602)
            self.assertIn("did not issue a nextCursor", response["error"]["message"])

    def test_stdio_enforces_initialize_sequence_before_tool_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            default_root = base / "default-root"
            intended_root = base / "intended-root"
            requests = (
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "continuum_init", "arguments": {}},
                },
                *stdio_handshake_requests(initialize_id=2)[:1],
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "continuum_init", "arguments": {}},
                },
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "initialize",
                    "params": valid_initialize_params(),
                },
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": []},
                {
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {"name": "continuum_init", "arguments": {}},
                },
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {
                    "jsonrpc": "2.0",
                    "id": 6,
                    "method": "tools/call",
                    "params": {
                        "name": "continuum_init",
                        "arguments": {"root": str(intended_root)},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": "initialize",
                    "params": valid_initialize_params(),
                },
                {"jsonrpc": "2.0", "id": 7, "method": "ping"},
            )
            stdin = io.StringIO("\n".join(json.dumps(request) for request in requests) + "\n")
            stdout = io.StringIO()

            with (
                patch.dict(
                    "os.environ",
                    {
                        "CONTINUUM_ROOT": str(default_root),
                        "CONTINUUM_ALLOWED_ROOTS": str(base),
                    },
                ),
                patch.object(mcp_server_module.sys, "stdin", stdin),
                patch.object(mcp_server_module.sys, "stdout", stdout),
            ):
                self.assertEqual(mcp_server_module.serve(), 0)

            responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
            self.assertEqual([response["id"] for response in responses], [1, 2, 3, 4, 5, 6, 8, 7])
            for index in (0, 2, 3, 4, 6):
                self.assertEqual(responses[index]["error"]["code"], -32600)
            self.assertFalse(responses[5]["result"]["isError"])
            self.assertEqual(responses[7], {"jsonrpc": "2.0", "id": 7, "result": {}})
            self.assertFalse(default_root.exists())
            self.assertTrue(intended_root.is_dir())

    def test_stdio_rejects_malformed_init_arguments_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            default_root = base / "default-root"
            intended_root = base / "intended-root"
            requests = [json.dumps(request) for request in stdio_handshake_requests()]
            requests.extend(
                [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": index,
                        "method": "tools/call",
                        "params": {
                            "name": "continuum_init",
                            "arguments": arguments,
                        },
                    }
                )
                for index, arguments in enumerate((None, False, 0, 0.0, "", []), start=1)
                ]
            )
            intended_root_json = json.dumps(str(intended_root))
            requests.append(
                '{"jsonrpc":"2.0","id":7,"method":"tools/call",'
                '"params":{"name":"continuum_init",'
                f'"arguments":{{"root":{intended_root_json}}},"arguments":[]}}'
            )
            requests.append(json.dumps({"jsonrpc": "2.0", "id": 8, "method": "ping"}))
            stdin = io.StringIO("\n".join(requests) + "\n")
            stdout = io.StringIO()

            with (
                patch.dict(
                    "os.environ",
                    {
                        "CONTINUUM_ROOT": str(default_root),
                        "CONTINUUM_ALLOWED_ROOTS": str(base),
                    },
                ),
                patch.object(mcp_server_module.sys, "stdin", stdin),
                patch.object(mcp_server_module.sys, "stdout", stdout),
            ):
                self.assertEqual(mcp_server_module.serve(), 0)

            responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
            self.assertEqual(responses[0]["id"], 900)
            self.assertEqual([item["error"]["code"] for item in responses[1:7]], [-32602] * 6)
            self.assertEqual(responses[7]["error"]["code"], -32700)
            self.assertEqual(responses[8], {"jsonrpc": "2.0", "id": 8, "result": {}})
            self.assertFalse(default_root.exists())
            self.assertFalse(intended_root.exists())
            self.assertEqual(list(base.iterdir()), [])

    def test_stdio_recovers_after_unexpected_dispatch_exception(self) -> None:
        request_items = [
            *stdio_handshake_requests(),
            *(
                {"jsonrpc": "2.0", "id": request_id, "method": "ping"}
                for request_id in (40, 41)
            ),
        ]
        requests = "\n".join(json.dumps(request) for request in request_items)
        stdin = io.StringIO(requests + "\n")
        stdout = io.StringIO()
        stderr = io.StringIO()
        real_dispatch = mcp_server_module.dispatch
        def controlled_dispatch(
            request: dict[str, Any],
            session_state: mcp_server_module._McpSessionState,
        ) -> dict[str, Any] | None:
            if request.get("id") == 40:
                raise RuntimeError("synthetic dispatch failure")
            return real_dispatch(request, session_state)

        with (
            patch.object(mcp_server_module.sys, "stdin", stdin),
            patch.object(mcp_server_module.sys, "stdout", stdout),
            patch.object(mcp_server_module, "dispatch", side_effect=controlled_dispatch),
            redirect_stderr(stderr),
        ):
            self.assertEqual(mcp_server_module.serve(), 0)

        responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(responses[0]["id"], 900)
        self.assertEqual(responses[1]["id"], 40)
        self.assertEqual(responses[1]["error"], {"code": -32603, "message": "internal error"})
        self.assertEqual(responses[2], {"jsonrpc": "2.0", "id": 41, "result": {}})
        self.assertEqual(
            stderr.getvalue().strip(),
            "Epic Continuum MCP diagnostic: event=dispatch_failed; "
            "error=RuntimeError; details redacted",
        )

    def test_stdio_fails_closed_on_nonfinite_response_and_recovers(self) -> None:
        request_items = [
            *stdio_handshake_requests(),
            *(
                {"jsonrpc": "2.0", "id": request_id, "method": "ping"}
                for request_id in (50, 51)
            ),
        ]
        requests = "\n".join(json.dumps(request) for request in request_items)
        stdin = io.StringIO(requests + "\n")
        stdout = io.StringIO()
        stderr = io.StringIO()
        real_dispatch = mcp_server_module.dispatch

        def controlled_dispatch(
            request: dict[str, Any],
            session_state: mcp_server_module._McpSessionState,
        ) -> dict[str, Any] | None:
            if request.get("id") == 50:
                return mcp_server_module.rpc_result(50, {"bad": float("nan")})
            return real_dispatch(request, session_state)

        with (
            patch.object(mcp_server_module.sys, "stdin", stdin),
            patch.object(mcp_server_module.sys, "stdout", stdout),
            patch.object(mcp_server_module, "dispatch", side_effect=controlled_dispatch),
            redirect_stderr(stderr),
        ):
            self.assertEqual(mcp_server_module.serve(), 0)

        output = stdout.getvalue()
        self.assertNotIn("NaN", output)
        responses = [json.loads(line) for line in output.splitlines()]
        self.assertEqual(responses[0]["id"], 900)
        self.assertEqual(responses[1]["id"], 50)
        self.assertEqual(responses[1]["error"], {"code": -32603, "message": "internal error"})
        self.assertEqual(responses[2], {"jsonrpc": "2.0", "id": 51, "result": {}})
        self.assertEqual(
            stderr.getvalue().strip(),
            "Epic Continuum MCP diagnostic: event=response_encoding_failed; "
            "error=ValueError; details redacted",
        )

    def test_mutating_tool_reports_succeeded_receipt_when_result_is_unavailable(self) -> None:
        class FailingDiagnosticStream(io.StringIO):
            def write(self, value: str) -> int:
                super().write(value)
                raise OSError("stderr unavailable")

        for bad_kind in ("nan", "path", "cycle"):
            with self.subTest(bad_kind=bad_kind), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                session_id = f"result-unavailable-{bad_kind}"
                real_append = mcp_server_module.append_scroll_event

                def append_with_bad_result(*args: Any, **kwargs: Any) -> dict[str, Any]:
                    result = real_append(*args, **kwargs)
                    if bad_kind == "nan":
                        result["unencodable"] = float("nan")
                    elif bad_kind == "path":
                        result["unencodable"] = Path("not-json")
                    else:
                        result["unencodable"] = result
                    return result

                state = ready_session_state()
                stderr = FailingDiagnosticStream() if bad_kind == "nan" else io.StringIO()
                with (
                    patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}),
                    patch.object(
                        mcp_server_module,
                        "append_scroll_event",
                        side_effect=append_with_bad_result,
                    ),
                    redirect_stderr(stderr),
                ):
                    response = dispatch(
                        {
                            "jsonrpc": "2.0",
                            "id": 80,
                            "method": "tools/call",
                            "params": {
                                "name": "continuum_append_event",
                                "arguments": {
                                    "root": str(root),
                                    "session_id": session_id,
                                    "content": "Commit exactly once before result encoding.",
                                },
                            },
                        },
                        state,
                    )
                    recovery = dispatch(
                        {"jsonrpc": "2.0", "id": 81, "method": "ping"},
                        state,
                    )

                assert response is not None
                result = response["result"]
                self.assertFalse(result["isError"], result)
                payload = json.loads(result["content"][0]["text"])
                self.assertEqual(result["structuredContent"], payload)
                self.assertTrue(payload["ok"])
                self.assertEqual(payload["operation_outcome"], "succeeded_result_unavailable")
                self.assertFalse(payload["result_available"])
                self.assertEqual(payload["retry_advice"], "do_not_retry_automatically")
                self.assertEqual(
                    payload["warning"]["code"],
                    mcp_server_module.MCP_RESULT_UNAVAILABLE_AFTER_COMPLETED_ACTION,
                )
                self.assertEqual(payload["_operation"]["status"], "succeeded")
                self.assertEqual(
                    stderr.getvalue().strip(),
                    "Epic Continuum MCP diagnostic: "
                    "event=completed_action_result_unavailable; "
                    f"error={'TypeError' if bad_kind == 'path' else 'ValueError'}; "
                    "details redacted",
                )
                self.assertEqual(recovery, {"jsonrpc": "2.0", "id": 81, "result": {}})

                with closing(connect(root)) as conn:
                    event_count = conn.execute(
                        "SELECT COUNT(*) FROM scroll_events WHERE session_id = ?",
                        (session_id,),
                    ).fetchone()[0]
                self.assertEqual(event_count, 1)

                receipt_path = Path(payload["_operation"]["operation_receipt_uri"])
                receipt_text = receipt_path.read_text(encoding="utf-8")
                self.assertNotIn("NaN", receipt_text)
                receipt = json.loads(receipt_text)
                self.assertEqual(receipt["status"], "succeeded")
                self.assertEqual(
                    receipt["result"]["operation_outcome"],
                    "succeeded_result_unavailable",
                )

    def test_stdio_rejects_oversized_frame_before_parsing_and_recovers(self) -> None:
        oversized = "x" * (MAX_MCP_REQUEST_BYTES + 1) + "\n"
        recovery = [*stdio_handshake_requests(), {"jsonrpc": "2.0", "id": 7, "method": "ping"}]
        stdin = io.StringIO(
            oversized + "\n".join(json.dumps(request) for request in recovery) + "\n"
        )
        stdout = io.StringIO()

        with (
            patch.object(mcp_server_module.sys, "stdin", stdin),
            patch.object(mcp_server_module.sys, "stdout", stdout),
        ):
            self.assertEqual(mcp_server_module.serve(), 0)

        responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(len(responses), 3)
        self.assertEqual(responses[0]["error"]["code"], -32700)
        self.assertIn("request exceeds maximum", responses[0]["error"]["message"])
        self.assertEqual(responses[1]["id"], 900)
        self.assertEqual(responses[2], {"jsonrpc": "2.0", "id": 7, "result": {}})

    def test_stdio_rejects_over_nested_json_and_recovers(self) -> None:
        depth = mcp_server_module.MAX_MCP_JSON_DEPTH + 1
        nested = "[" * depth + "0" + "]" * depth
        deep_value: object = 0
        for _ in range(depth):
            deep_value = [deep_value]
        requests = (
            {
                "jsonrpc": "2.0",
                "id": 17,
                "method": "ping",
                "params": {"vendor": deep_value},
            },
            {
                "jsonrpc": "2.0",
                "id": None,
                "method": "ping",
                "params": {"vendor": deep_value},
            },
            stdio_handshake_requests()[0],
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {"_meta": {"vendor": deep_value}},
            },
            {"jsonrpc": "2.0", "id": 18, "method": "tools/list"},
            stdio_handshake_requests()[1],
            {"jsonrpc": "2.0", "id": 8, "method": "ping"},
        )
        stdin = io.StringIO(nested + "\n" + "\n".join(json.dumps(item) for item in requests) + "\n")
        stdout = io.StringIO()

        with (
            patch.object(mcp_server_module.sys, "stdin", stdin),
            patch.object(mcp_server_module.sys, "stdout", stdout),
        ):
            self.assertEqual(mcp_server_module.serve(), 0)

        responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(len(responses), 6)
        self.assertEqual(responses[0]["error"]["code"], -32600)
        self.assertNotIn("id", responses[0])
        self.assertEqual(responses[1]["id"], 17)
        self.assertEqual(responses[1]["error"]["code"], -32600)
        self.assertNotIn("id", responses[2])
        self.assertEqual(responses[2]["error"]["code"], -32600)
        self.assertEqual(responses[3]["id"], 900)
        self.assertEqual(responses[4]["id"], 18)
        self.assertIn("handshake is incomplete", responses[4]["error"]["message"])
        self.assertEqual(responses[5], {"jsonrpc": "2.0", "id": 8, "result": {}})

    def test_parsed_request_json_has_an_explicit_depth_limit(self) -> None:
        value: object = 0
        for _ in range(mcp_server_module.MAX_MCP_JSON_DEPTH + 1):
            value = [value]

        error = mcp_server_module._request_json_depth_error(value)

        self.assertIsNotNone(error)
        self.assertIn("maximum depth", str(error))

    def test_stdio_recovers_after_parser_recursion_error(self) -> None:
        first = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "ping"})
        recovery = [*stdio_handshake_requests(), {"jsonrpc": "2.0", "id": 10, "method": "ping"}]
        stdin = io.StringIO(
            first + "\n" + "\n".join(json.dumps(request) for request in recovery) + "\n"
        )
        stdout = io.StringIO()
        real_loads = json.loads
        call_count = 0

        def controlled_loads(payload: str, **kwargs: Any) -> object:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RecursionError("synthetic parser depth failure")
            return real_loads(payload, **kwargs)

        with (
            patch.object(mcp_server_module.sys, "stdin", stdin),
            patch.object(mcp_server_module.sys, "stdout", stdout),
            patch.object(mcp_server_module.json, "loads", side_effect=controlled_loads),
        ):
            self.assertEqual(mcp_server_module.serve(), 0)

        responses = [real_loads(line) for line in stdout.getvalue().splitlines()]
        self.assertEqual(len(responses), 3)
        self.assertEqual(responses[0]["error"]["code"], -32700)
        self.assertEqual(responses[1]["id"], 900)
        self.assertEqual(responses[2]["id"], 10)

    def test_project_state_limits_reject_before_operation_or_root_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                response = call_tool_raw(
                    "continuum_record_project_state",
                    {
                        "root": str(root),
                        "session_id": "bounded-session",
                        "agent_id": "bounded-agent",
                        "project_id": "bounded-project",
                        "open_tasks": ["x" * 2000 for _ in range(70)],
                    },
                )

            self.assertTrue(response["isError"], response)
            payload = json.loads(response["content"][0]["text"])
            self.assertIn("open_tasks must contain at most 64 items", payload["error"])
            self.assertFalse(root.exists())

        schema = TOOLS["continuum_record_project_state"][1]
        properties = schema["properties"]
        self.assertEqual(properties["open_tasks"]["maxItems"], 64)
        self.assertNotIn("maxLength", json.dumps(schema, sort_keys=True))
        self.assertIn("maxProperties", properties["metadata"])

    def test_mcp_project_state_metadata_schema_boundary_is_usable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            metadata = {
                "agent_type": "codex",
                "client_name": "continuum-tests",
                "client_version": "0.3.0",
                "hook_event_name": "checkpoint",
                "model": "local-model",
                "platform": "windows",
                "source": "test",
                "task_id": "metadata-task",
                "turn_id": "metadata-turn",
            }
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                recorded = call_tool(
                    "continuum_record_project_state",
                    {
                        "root": str(root),
                        "session_id": "mcp-metadata-session",
                        "agent_id": "mcp-metadata-agent",
                        "project_id": "mcp-metadata-project",
                        "metadata": metadata,
                    },
                )
                resumed = call_tool(
                    "continuum_resume_latest",
                    {
                        "root": str(root),
                        "project_id": "mcp-metadata-project",
                        "token_budget": 8192,
                        "model_assist": False,
                    },
                )
            self.assertTrue(recorded["ok"], recorded)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                recorded["card_id"],
            )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                response = call_tool_raw(
                    "continuum_record_project_state",
                    {
                        "root": str(root),
                        "session_id": "mcp-metadata-overflow-session",
                        "agent_id": "mcp-metadata-overflow-agent",
                        "project_id": "mcp-metadata-overflow-project",
                        "metadata": {"caller_defined_control": "not accepted"},
                    },
                )
            self.assertTrue(response["isError"], response)
            self.assertFalse(root.exists())

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                response = call_tool_raw(
                    "continuum_record_project_state",
                    {
                        "root": str(root),
                        "session_id": "mcp-metadata-type-session",
                        "agent_id": "mcp-metadata-type-agent",
                        "project_id": "mcp-metadata-type-project",
                        "metadata": {"source": {"nested": ["not", "a string"]}},
                    },
                )
            self.assertTrue(response["isError"], response)
            payload = json.loads(response["content"][0]["text"])
            self.assertIn("metadata.source must be string", payload["error"])
            self.assertFalse(root.exists())

        schema = TOOLS["continuum_record_project_state"][1]["properties"]["metadata"]
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["properties"]), set(metadata))
        self.assertEqual(schema["maxProperties"], len(metadata))

    def test_initialize_and_list_tools(self) -> None:
        response = dispatch(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": valid_initialize_params(),
            },
            mcp_server_module._McpSessionState(),
        )

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
                "params": valid_initialize_params(),
            },
            mcp_server_module._McpSessionState(),
        )
        self.assertIsNotNone(negotiated)
        assert negotiated is not None
        self.assertEqual(negotiated["result"]["protocolVersion"], "2025-11-25")

        listed = dispatch_ready({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})

        self.assertIsNotNone(listed)
        assert listed is not None
        names = {tool["name"] for tool in listed["result"]["tools"]}
        self.assertIn("continuum_append_event", names)
        self.assertIn("continuum_recover_thread", names)
        self.assertIn("continuum_resume_latest", names)
        self.assertIn("continuum_repair_project_state_checkpoints", names)
        self.assertIn("continuum_yarn_health", names)
        self.assertIn("continuum_resolve_conflict", names)
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
        self.assertTrue(tools["continuum_reindex_memory"]["annotations"]["idempotentHint"])
        self.assertTrue(tools["continuum_repair_permissions"]["annotations"]["idempotentHint"])
        self.assertFalse(tools["continuum_append_event"]["annotations"]["destructiveHint"])
        self.assertFalse(tools["continuum_import_mempalace"]["annotations"]["destructiveHint"])
        self.assertFalse(tools["continuum_rebuild_search_index"]["annotations"]["destructiveHint"])
        self.assertTrue(tools["continuum_prune_memory"]["annotations"]["destructiveHint"])
        self.assertTrue(
            tools["continuum_repair_project_state_checkpoints"]["annotations"][
                "destructiveHint"
            ]
        )
        self.assertFalse(tools["continuum_status"]["annotations"]["openWorldHint"])
        self.assertFalse(tools["continuum_doctor"]["annotations"]["openWorldHint"])
        self.assertTrue(tools["continuum_import_mempalace"]["annotations"]["openWorldHint"])
        self.assertTrue(tools["continuum_resume_latest"]["annotations"]["openWorldHint"])
        self.assertTrue(tools["continuum_yarn_health"]["annotations"]["openWorldHint"])
        self.assertTrue(tools["continuum_yarn_health"]["annotations"]["readOnlyHint"])
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
        self.assertIn("continuum_cue_recall", names)
        self.assertIn("continuum_record_project_state", names)
        self.assertIn("continuum_audit_search_index", names)
        self.assertIn("continuum_rebuild_search_index", names)
        self.assertIn("continuum_reindex_memory", names)
        first_tool = listed["result"]["tools"][0]
        self.assertIn("outputSchema", first_tool)
        self.assertIn("title", first_tool)
        self.assertTrue(tools["continuum_pack_root"]["annotations"]["openWorldHint"])
        self.assertTrue(tools["continuum_verify_bundle"]["annotations"]["openWorldHint"])

    def test_initialize_rejects_missing_or_invalid_required_params(self) -> None:
        invalid_params: tuple[dict[str, Any] | None, ...] = (
            None,
            {},
            {"protocolVersion": 1, "capabilities": {}, "clientInfo": {}},
            {"protocolVersion": "2025-11-25", "clientInfo": {}},
            {"protocolVersion": "2025-11-25", "capabilities": [], "clientInfo": {}},
            {"protocolVersion": "2025-11-25", "capabilities": {}},
            {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": []},
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"version": "1.0.0"},
            },
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test-client"},
            },
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {"roots": {"listChanged": "yes"}},
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {"sampling": {"context": []}},
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {"experimental": {"vendor": []}},
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {
                    "tasks": {"requests": {"sampling": {"createMessage": False}}},
                },
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0", "title": 1},
            },
            {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0", "icons": [{}]},
            },
            {
                "_meta": {"progressToken": True},
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
        )
        for index, params in enumerate(invalid_params, start=1):
            with self.subTest(params=params):
                request: dict[str, Any] = {
                    "jsonrpc": "2.0",
                    "id": index,
                    "method": "initialize",
                }
                if params is not None:
                    request["params"] = params
                response = dispatch(request, mcp_server_module._McpSessionState())
                assert response is not None
                self.assertEqual(response["error"]["code"], -32602)
                self.assertNotIn("result", response)

    def test_initialize_accepts_valid_nested_capabilities_and_extensions(self) -> None:
        params = valid_initialize_params()
        params["_meta"] = {"progressToken": 1.0, "vendor": {"trace": True}}
        params["capabilities"] = {
            "roots": {"listChanged": True, "vendor": "extension"},
            "sampling": {"context": {"mode": "all"}, "tools": {}},
            "elicitation": {"form": {}, "url": {"version": 1}},
            "experimental": {"vendor.feature": {"enabled": True}},
            "tasks": {
                "list": {},
                "cancel": {},
                "requests": {
                    "sampling": {"createMessage": {}},
                    "elicitation": {"create": {}},
                },
            },
            "vendorCapability": {"enabled": True},
        }
        params["clientInfo"] = {
            "name": "test-client",
            "title": "Test Client",
            "version": "1.0.0",
            "description": "MCP compatibility fixture",
            "websiteUrl": "https://example.invalid/client",
            "icons": [
                {
                    "src": "data:image/png;base64,AA==",
                    "mimeType": "image/png",
                    "sizes": ["16x16", "any"],
                    "theme": "dark",
                }
            ],
        }

        response = dispatch(
            {
                "jsonrpc": "2.0",
                "id": "initialize-valid",
                "method": "initialize",
                "params": params,
            },
            mcp_server_module._McpSessionState(),
        )

        assert response is not None
        self.assertEqual(response["id"], "initialize-valid")
        self.assertEqual(response["result"]["protocolVersion"], "2025-11-25")

    def test_tool_call_schema_and_unknown_tool_use_protocol_errors(self) -> None:
        invalid_params: tuple[dict[str, Any] | None, ...] = (
            None,
            {},
            {"name": 1},
            {"name": "continuum_init", "arguments": []},
            {"name": "not-a-continuum-tool", "arguments": {}},
        )
        for index, params in enumerate(invalid_params, start=1):
            with self.subTest(params=params):
                request: dict[str, Any] = {
                    "jsonrpc": "2.0",
                    "id": index,
                    "method": "tools/call",
                }
                if params is not None:
                    request["params"] = params
                response = dispatch_ready(request)
                assert response is not None
                self.assertEqual(response["error"]["code"], -32602)
                self.assertNotIn("result", response)

    def test_tool_argument_schemas_block_invalid_handlers_without_mutation(self) -> None:
        cases = (
            ("continuum_init", {"root": None}, "arguments.root must be string"),
            ("continuum_init", {"unexpected": 1}, "arguments.unexpected is not allowed"),
            (
                "continuum_append_event",
                {"session_id": "schema-session"},
                "arguments.content is required",
            ),
            (
                "continuum_ingest_file",
                {"path": "missing.txt", "storage_tier": "invalid"},
                "arguments.storage_tier must be one of",
            ),
            (
                "continuum_run_workers",
                {"roles": [1]},
                "arguments.roles[0] must be string",
            ),
            (
                "continuum_search",
                {"query": ""},
                "arguments.query must contain at least 1 characters",
            ),
            (
                "continuum_review_prepare",
                {
                    "subject": "missing-subject",
                    "prompt": "review",
                    "reviewer_id": "\U0001f40d"
                    * (mcp_server_module.REVIEW_MAX_REVIEWER_ID_BYTES // 4 + 1),
                },
                "arguments.reviewer_id must contain at most 256 UTF-8 bytes",
            ),
            (
                "continuum_review_prepare",
                {
                    "subject": "missing-subject",
                    "prompt": "review",
                    "secret_allowlist_patterns": [""],
                },
                "arguments.secret_allowlist_patterns[0] must contain at least 1 characters",
            ),
            (
                "continuum_review_run",
                {"job_id": "schema-job", "operation_id": "A\n"},
                "arguments.operation_id does not match the required pattern",
            ),
            (
                "continuum_review_run",
                {"job_id": "schema-job", "operation_id": "CON.txt"},
                "arguments.operation_id does not match the required pattern",
            ),
            (
                "continuum_review_run",
                {"job_id": "schema-job", "operation_id": "operation."},
                "arguments.operation_id does not match the required pattern",
            ),
            (
                "continuum_review_run",
                {"job_id": "A\n"},
                "arguments.job_id does not match the required pattern",
            ),
            (
                "continuum_review_ingest",
                {"job_id": "a/b", "content": "review"},
                "arguments.job_id does not match the required pattern",
            ),
            (
                "continuum_review_status",
                {"job_id": "\u00e9"},
                "arguments.job_id does not match the required pattern",
            ),
            (
                "continuum_review_check_current",
                {"job_id": "j" * 129},
                "arguments.job_id must contain at most 128 characters",
            ),
            (
                "continuum_review_browser_attempt_start",
                {"job_id": "CON"},
                "arguments.job_id does not match the required pattern",
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            default_root = Path(tmp) / "default-root"
            with patch.dict(
                "os.environ",
                {
                    "CONTINUUM_ROOT": str(default_root),
                    "CONTINUUM_ALLOWED_ROOTS": tmp,
                },
            ):
                for index, (name, arguments, expected_error) in enumerate(cases, start=1):
                    with self.subTest(tool=name, arguments=arguments):
                        response = dispatch_ready(
                            {
                                "jsonrpc": "2.0",
                                "id": index,
                                "method": "tools/call",
                                "params": {"name": name, "arguments": arguments},
                            }
                        )
                        assert response is not None
                        result = response["result"]
                        self.assertTrue(result["isError"], result)
                        payload = json.loads(result["content"][0]["text"])
                        self.assertIn(expected_error, payload["error"])
                        self.assertFalse(default_root.exists())

    def test_tool_schemas_mark_required_strings_nonempty(self) -> None:
        for name, (_description, schema, _handler) in TOOLS.items():
            properties = schema.get("properties", {})
            for key in schema.get("required", []):
                property_schema = properties.get(key, {})
                if property_schema.get("type") == "string":
                    with self.subTest(tool=name, argument=key):
                        self.assertEqual(property_schema.get("minLength"), 1)

    def test_integral_json_schema_numbers_are_normalized_for_integer_handlers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                result = call_tool(
                    "continuum_search",
                    {"root": str(root), "query": "no matches", "limit": 1.0},
                )

        self.assertIsInstance(result, dict)

    def test_mutating_review_handlers_validate_job_id_before_operation_guard(self) -> None:
        cases = (
            (mcp_server_module.tool_review_run, {"job_id": "A\n"}),
            (
                mcp_server_module.tool_review_ingest,
                {"job_id": "a/b", "content": "review"},
            ),
            (
                mcp_server_module.tool_review_browser_attempt_start,
                {"job_id": "CON"},
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with (
                patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}),
                patch.object(mcp_server_module, "guarded_tool") as guarded,
            ):
                for handler, arguments in cases:
                    with self.subTest(handler=handler.__name__), self.assertRaisesRegex(
                        ValueError,
                        "job_id must be a safe portable filename component",
                    ):
                        handler({"root": str(root), **arguments})
                guarded.assert_not_called()
            self.assertFalse(root.exists())

    def test_browser_attempt_validates_operation_id_before_operation_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with (
                patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}),
                patch.object(mcp_server_module, "guarded_tool") as guarded,
                self.assertRaisesRegex(
                    ValueError,
                    "operation_id must be a safe portable filename component",
                ),
            ):
                mcp_server_module.tool_review_browser_attempt_start(
                    {
                        "root": str(root),
                        "job_id": "valid-job",
                        "operation_id": "CON",
                    }
                )
            guarded.assert_not_called()
            self.assertFalse(root.exists())

    def test_review_handlers_validate_simple_controls_before_operation_guard(self) -> None:
        invalid_text = "\ud800"
        cases = (
            (
                mcp_server_module.tool_review_prepare,
                {"include_diff": "yes"},
                "include_diff must be a boolean",
            ),
            (
                mcp_server_module.tool_review_ingest,
                {"job_id": "valid-job", "content": invalid_text},
                "inline review response is not valid UTF-8 text",
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with (
                patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}),
                patch.object(mcp_server_module, "guarded_tool") as guarded,
            ):
                for handler, arguments, expected_error in cases:
                    with self.subTest(handler=handler.__name__), self.assertRaisesRegex(
                        ValueError,
                        expected_error,
                    ):
                        handler({"root": str(root), **arguments})
                guarded.assert_not_called()
            self.assertFalse(root.exists())

    def test_mcp_catalog_proof_policy_separates_routine_and_high_risk_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                init_db(root)
                append_scroll_event(
                    root,
                    session_id="proof-policy",
                    event_type="message",
                    role="user",
                    content="policy event",
                )
                routine = call_tool(
                    "continuum_reindex_memory",
                    {"root": str(root), "dry_run": False, "limit": 10, "batch_size": 10},
                )
                routine_proof = json.loads(Path(routine["_operation"]["proof_pack_uri"]).read_text(encoding="utf-8"))
                self.assertEqual(routine_proof["catalog_proof_mode"], "state_manifest")
                self.assertIn(
                    "sqlite_state_manifest",
                    [item.get("kind") for item in routine_proof["path_substitutions"]],
                )

                for tool_name, arguments in (
                    ("continuum_prune_memory", {"root": str(root), "all": True, "limit": 1}),
                    ("continuum_redact_legacy_secrets", {"root": str(root), "apply": True, "limit": 1}),
                ):
                    with self.subTest(tool=tool_name):
                        result = call_tool(tool_name, arguments)
                        proof = json.loads(Path(result["_operation"]["proof_pack_uri"]).read_text(encoding="utf-8"))
                        self.assertEqual(proof["catalog_proof_mode"], "snapshot")
                        self.assertIn("sqlite_backup", [item.get("kind") for item in proof["path_substitutions"]])

    def test_project_and_reindex_mcp_schemas_match_supported_arguments(self) -> None:
        recover_props = TOOLS["continuum_recover_thread"][1]["properties"]
        resume_props = TOOLS["continuum_resume_latest"][1]["properties"]
        compile_props = TOOLS["continuum_compile_context"][1]["properties"]
        search_props = TOOLS["continuum_search"][1]["properties"]
        reindex_props = TOOLS["continuum_reindex_memory"][1]["properties"]
        prune_props = TOOLS["continuum_prune_memory"][1]["properties"]
        repair_props = TOOLS["continuum_repair_project_state_checkpoints"][1][
            "properties"
        ]

        self.assertIn("project_id", recover_props)
        self.assertNotIn("model_assist", recover_props)
        self.assertIn("model_assist", resume_props)
        self.assertEqual(recover_props["recent_event_limit"]["minimum"], 0)
        self.assertEqual(resume_props["recent_event_limit"]["minimum"], 0)
        self.assertEqual(
            recover_props["recent_event_limit"]["maximum"],
            MAX_RECENT_EVENT_LIMIT,
        )
        self.assertEqual(
            resume_props["recent_event_limit"]["maximum"],
            MAX_RECENT_EVENT_LIMIT,
        )
        self.assertIn("project_id", compile_props)
        self.assertIn("session_id", search_props)
        self.assertIn("project_id", search_props)
        self.assertEqual(list(compile_props).count("project_id"), 1)
        for key in ("session_id", "after_seq", "after_rowid", "limit", "batch_size", "dry_run", "promote_exact_memory"):
            self.assertIn(key, reindex_props)
        self.assertEqual(prune_props["topic"]["minLength"], 1)
        self.assertEqual(prune_props["limit"]["minimum"], 1)
        self.assertEqual(prune_props["limit"]["maximum"], MAX_PRUNE_MEMORY_LIMIT)
        self.assertEqual(prune_props["limit"]["default"], 100)
        for key in (
            "project_id",
            "session_id",
            "all",
            "include_session_scoped",
            "include_private",
            "apply",
            "limit",
        ):
            self.assertIn(key, repair_props)
        self.assertEqual(repair_props["limit"]["minimum"], 1)
        self.assertEqual(
            repair_props["limit"]["maximum"],
            mcp_server_module.MAX_PROJECT_STATE_REPAIR_LIMIT,
        )
        self.assertEqual(repair_props["limit"]["default"], 100)

    def test_mcp_checkpoint_repair_requires_explicit_scope_before_artifacts(
        self,
    ) -> None:
        cases = (
            ({"apply": True}, "requires project_id, session_id, or explicit all=true"),
            (
                {"all": True, "project_id": "ambiguous-project", "apply": True},
                "all=true cannot be combined",
            ),
            (
                {"project_id": "bounded-project", "limit": 1001, "apply": True},
                "limit must be at most 1000",
            ),
        )
        for arguments, expected_error in cases:
            with self.subTest(arguments=arguments), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                    response = call_tool_raw(
                        "continuum_repair_project_state_checkpoints",
                        {"root": str(root), **arguments},
                    )

                self.assertTrue(response["isError"], response)
                payload = json.loads(response["content"][0]["text"])
                self.assertIn(expected_error, payload["error"])
                self.assertFalse(root.exists())

    def test_mcp_checkpoint_repair_preview_apply_share_scope_and_receipt_flags(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            mock_result = {
                "ok": True,
                "quarantined_count": 0,
                "quarantined": [],
            }
            common_args = {
                "root": str(root),
                "all": True,
                "include_session_scoped": True,
                "include_private": True,
                "limit": 37,
            }
            with (
                patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}),
                patch.object(
                    mcp_server_module,
                    "repair_invalid_project_state_checkpoints",
                    return_value=mock_result,
                ) as repair,
            ):
                preview = call_tool(
                    "continuum_repair_project_state_checkpoints",
                    common_args,
                )
                applied = call_tool(
                    "continuum_repair_project_state_checkpoints",
                    {**common_args, "apply": True},
                )

            self.assertNotIn("_operation", preview)
            self.assertEqual(applied["_operation"]["status"], "succeeded")
            self.assertEqual(repair.call_count, 2)
            preview_kwargs = repair.call_args_list[0].kwargs
            apply_kwargs = repair.call_args_list[1].kwargs
            self.assertTrue(preview_kwargs.pop("dry_run"))
            self.assertFalse(apply_kwargs.pop("dry_run"))
            self.assertEqual(preview_kwargs, apply_kwargs)
            self.assertEqual(
                preview_kwargs,
                {
                    "project_id": None,
                    "session_id": None,
                    "all_projects": True,
                    "include_session_scoped": True,
                    "include_private": True,
                    "limit": 37,
                },
            )
            operation = next(
                item
                for item in list_operations(root)["operations"]
                if item["operation_type"]
                == "mcp_repair_project_state_checkpoints"
            )
            receipt = json.loads(
                Path(operation["export_receipt_uri"]).read_text(encoding="utf-8")
            )
            self.assertEqual(
                receipt["intent"],
                {
                    "session_id": None,
                    "project_id": None,
                    "all_projects": True,
                    "include_session_scoped": True,
                    "include_private": True,
                    "apply": True,
                    "limit": 37,
                    "preflight_snapshot_policy": "auto",
                    "preflight_snapshot_reason": (
                        "checkpoint quarantine changes Card authority pointers"
                    ),
                },
            )

    def test_mcp_checkpoint_repair_refusal_fails_guarded_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            with (
                patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}),
                patch.object(
                    mcp_server_module,
                    "repair_invalid_project_state_checkpoints",
                    return_value={
                        "ok": False,
                        "catalog_repair_committed": False,
                        "authority_topology_issue_count": 1,
                    },
                ),
            ):
                response = call_tool_raw(
                    "continuum_repair_project_state_checkpoints",
                    {
                        "root": str(root),
                        "project_id": "refused-project",
                        "apply": True,
                    },
                )

            self.assertTrue(response["isError"], response)
            payload = json.loads(response["content"][0]["text"])
            self.assertIn("repair refused", payload["error"])
            operation = next(
                item
                for item in list_operations(root, status="failed")["operations"]
                if item["operation_type"]
                == "mcp_repair_project_state_checkpoints"
            )
            self.assertEqual(operation["status"], "failed")
            self.assertEqual(
                operation["cursor"]["phase"],
                "project_state_repair_refused",
            )
            self.assertFalse(operation["cursor"]["catalog_repair_committed"])

    def test_mcp_prune_memory_uses_literal_topics_and_bounded_limits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                percent_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="MCP literal % prune marker",
                    summary="Only this Card has the percent marker.",
                    source_refs=[],
                )
                plain_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="MCP literal plain prune marker",
                    summary="This Card must remain active.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [percent_id, plain_id])

            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                result = call_tool(
                    "continuum_prune_memory",
                    {"root": str(root), "topic": "%", "action": "archive"},
                )
                blank = call_tool_raw(
                    "continuum_prune_memory",
                    {"root": str(root), "topic": "   ", "all": True},
                )
                nul_topic = call_tool_raw(
                    "continuum_prune_memory",
                    {"root": str(root), "topic": "\x00"},
                )
                oversized = call_tool_raw(
                    "continuum_prune_memory",
                    {
                        "root": str(root),
                        "topic": "literal",
                        "limit": MAX_PRUNE_MEMORY_LIMIT + 1,
                    },
                )

            self.assertEqual(result["matching_mode"], "literal_substring")
            self.assertEqual(result["card_ids"], [percent_id])
            self.assertEqual(result["_operation"]["status"], "succeeded")
            self.assertTrue(blank["isError"])
            self.assertIn("whitespace-only", blank["content"][0]["text"])
            self.assertTrue(nul_topic["isError"])
            self.assertIn("NUL", nul_topic["content"][0]["text"])
            self.assertTrue(oversized["isError"])
            self.assertIn(str(MAX_PRUNE_MEMORY_LIMIT), oversized["content"][0]["text"])
            conn = connect(root)
            try:
                statuses = {
                    str(row["id"]): str(row["status"])
                    for row in conn.execute(
                        "SELECT id, status FROM cards WHERE id IN (?, ?)",
                        (percent_id, plain_id),
                    ).fetchall()
                }
            finally:
                conn.close()
            self.assertEqual(statuses[percent_id], "archived")
            self.assertEqual(statuses[plain_id], "pending_librarian_review")

    def test_mcp_prune_memory_protected_failure_records_failed_operation_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="mcp-prune-protected-session",
                agent_id="mcp-prune-protected-agent",
                project_id="mcp-prune-protected-project",
                objective="MCP Protected Authority Marker",
            )
            conn = connect(root)
            try:
                before = dict(
                    conn.execute(
                        "SELECT status, supersedes_card_id, superseded_by_card_id, conflict_group FROM cards WHERE id = ?",
                        (state["card_id"],),
                    ).fetchone()
                )
            finally:
                conn.close()

            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                result = call_tool_raw(
                    "continuum_prune_memory",
                    {
                        "root": str(root),
                        "topic": "MCP Protected Authority Marker",
                        "action": "forget",
                    },
                )

            self.assertTrue(result["isError"])
            self.assertIn("authority-protected Cards", result["content"][0]["text"])
            failed = list_operations(root, status="failed", limit=20)
            prune_operations = [
                operation
                for operation in failed["operations"]
                if operation["operation_type"] == "mcp_prune_memory"
            ]
            self.assertEqual(len(prune_operations), 1, failed)
            self.assertEqual(prune_operations[0]["status"], "failed")
            conn = connect(root)
            try:
                card = dict(
                    conn.execute(
                        "SELECT status, supersedes_card_id, superseded_by_card_id, conflict_group FROM cards WHERE id = ?",
                        (state["card_id"],),
                    ).fetchone()
                )
            finally:
                conn.close()
            self.assertEqual(card, before)

    def test_mcp_secret_partition_block_fails_before_durable_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            before = tree_fingerprint(root)
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                result = call_tool_raw(
                    "continuum_append_event",
                    {
                        "root": str(root),
                        "session_id": "api_key=supersecretvalue123",
                        "role": "user",
                        "content": "safe content",
                    },
                )

            self.assertTrue(result["isError"], result)
            payload = json.loads(result["content"][0]["text"])
            self.assertIn("secret scan blocked session_id before operation receipt", payload["error"])
            self.assertEqual(before, tree_fingerprint(root))
            for rel in ("catalog", "run", "exports", "snapshots"):
                self.assertFalse((root / rel).exists(), rel)

    def test_recovery_tools_reject_out_of_range_recent_event_limits_before_artifacts(self) -> None:
        for tool_name, arguments in (
            (
                "continuum_recover_thread",
                {"session_id": "bounded-session"},
            ),
            ("continuum_resume_latest", {}),
        ):
            for invalid_limit in (-1, MAX_RECENT_EVENT_LIMIT + 1):
                with (
                    self.subTest(tool=tool_name, recent_event_limit=invalid_limit),
                    tempfile.TemporaryDirectory() as tmp,
                ):
                    root = Path(tmp) / "continuum"
                    with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                        result = call_tool_raw(
                            tool_name,
                            {
                                "root": str(root),
                                **arguments,
                                "recent_event_limit": invalid_limit,
                            },
                        )

                    self.assertTrue(result["isError"], result)
                    payload = json.loads(result["content"][0]["text"])
                    self.assertIn("recent_event_limit", payload["error"])
                    self.assertFalse(root.exists())

    def test_resolve_conflict_rejects_explicit_null_or_non_array_peers(self) -> None:
        for invalid in (None, False, 0, "", {}):
            with self.subTest(value=invalid), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                    result = call_tool_raw(
                        "continuum_resolve_conflict",
                        {
                            "root": str(root),
                            "card_id": "winner-card",
                            "superseded_card_ids": invalid,
                        },
                    )

                self.assertTrue(result["isError"], result)
                payload = json.loads(result["content"][0]["text"])
                self.assertIn("superseded_card_ids must be array", payload["error"])
                self.assertFalse(root.exists())

    def test_mcp_resolves_complete_compatible_authority_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                first_peer = record_project_state(
                    root,
                    session_id="mcp-authority-peer-a",
                    agent_id="agent-a",
                    project_id="mcp-authority-project",
                    objective="Prepare release notes",
                )
                second_peer = record_project_state(
                    root,
                    session_id="mcp-authority-peer-b",
                    agent_id="agent-b",
                    project_id="mcp-authority-project",
                    objective="Prepare package metadata",
                )
                winner = record_project_state(
                    root,
                    session_id="mcp-authority-winner",
                    agent_id="agent-c",
                    project_id="mcp-authority-project",
                    objective="Prepare final review bundle",
                )
                missing = call_tool_raw(
                    "continuum_resolve_conflict",
                    {
                        "root": str(root),
                        "card_id": winner["card_id"],
                    },
                )
                resolved = call_tool(
                    "continuum_resolve_conflict",
                    {
                        "root": str(root),
                        "card_id": winner["card_id"],
                        "superseded_card_ids": [
                            first_peer["card_id"],
                            second_peer["card_id"],
                        ],
                    },
                )
                resumed = call_tool(
                    "continuum_resume_latest",
                    {
                        "root": str(root),
                        "project_id": "mcp-authority-project",
                        "model_assist": False,
                    },
                )

            self.assertTrue(missing["isError"], missing)
            missing_payload = json.loads(missing["content"][0]["text"])
            self.assertIn(first_peer["card_id"], missing_payload["error"])
            self.assertIn(second_peer["card_id"], missing_payload["error"])
            self.assertTrue(resolved["ok"], resolved)
            self.assertEqual(
                resolved["resolution_scope"],
                "project_state_authority_boundary",
            )
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                winner["card_id"],
            )

    def test_mcp_secret_partition_warn_and_off_alias_without_crashing(self) -> None:
        for action in ("warn", "off"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                config = default_config()
                config["security"]["secret_scan_action"] = action
                write_config(root, config)

                with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                    result = call_tool(
                        "continuum_append_event",
                        {
                            "root": str(root),
                            "session_id": "api_key=supersecretvalue123",
                            "role": "user",
                            "content": f"{action} mode safe content",
                        },
                    )

                self.assertTrue(result["session_id"].startswith("ec_session_"), result)
                with closing(connect(root)) as conn:
                    count = conn.execute("SELECT count(*) AS n FROM scroll_events").fetchone()["n"]
                self.assertEqual(count, 1)

    def test_mcp_append_event_strips_exact_memory_trust_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = str(Path(tmp) / "continuum")
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                call_tool(
                    "continuum_append_event",
                    {
                        "root": root,
                        "session_id": "mcp-exact-boundary",
                        "role": "assistant",
                        "content": "remember this exactly: MCP metadata must not promote this",
                        "metadata": {
                            "dismissed_conflict_components": [
                                {"fingerprint": "f" * 64}
                            ],
                            "explicit_memory_request": True,
                            "supersedes_card_id": "caller-selected-card",
                            "trusted_explicit_memory_request": True,
                        },
                    },
                )
                call_tool(
                    "continuum_append_event",
                    {
                        "root": root,
                        "session_id": "mcp-exact-boundary",
                        "content": "remember this exactly: MCP omitted role must not promote this",
                    },
                )
                call_tool(
                    "continuum_append_event",
                    {
                        "root": root,
                        "session_id": "mcp-exact-boundary",
                        "role": "user",
                        "content": "remember this exactly: MCP user role must not promote this either",
                    },
                )

            conn = sqlite3.connect(str(Path(root) / "catalog" / "catalog.sqlite3"))
            try:
                count = conn.execute("SELECT COUNT(*) FROM cards WHERE card_type = 'exact_memory'").fetchone()[0]
                metadata_rows = [
                    json.loads(row[0])
                    for row in conn.execute(
                        "SELECT metadata_json FROM scroll_events ORDER BY seq"
                    )
                ]
            finally:
                conn.close()
            self.assertEqual(count, 0)
            for metadata in metadata_rows:
                self.assertNotIn("dismissed_conflict_components", metadata)
                self.assertNotIn("supersedes_card_id", metadata)

    def test_mcp_project_state_rejects_unadvertised_trust_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                result = call_tool_raw(
                    "continuum_record_project_state",
                    {
                        "root": str(root),
                        "session_id": "mcp-project-state-exact",
                        "agent_id": "codex",
                        "project_id": "public-mcp-project",
                        "objective": "remember this exactly: MCP project state must not promote",
                        "metadata": {
                            "trusted_explicit_memory_request": True,
                            "explicit_memory_request": True,
                            "instruction_authority": "system",
                            "trust_level": "trusted",
                            "protected": True,
                        },
                    },
                )
            self.assertTrue(result["isError"], result)
            payload = json.loads(result["content"][0]["text"])
            self.assertIn("arguments.metadata.trusted_explicit_memory_request is not allowed", payload["error"])
            self.assertFalse(root.exists())

    def test_mcp_project_state_rejects_conflict_dismissal_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target_root = base / "target"
            forged_metadata = {
                "dismissed_conflict_components": [
                    {
                        "fingerprint": "f" * 64,
                        "member_count": 2,
                        "dismissed_at": "caller-value",
                    }
                ]
            }
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                result = call_tool_raw(
                    "continuum_record_project_state",
                    {
                        "root": str(target_root),
                        "session_id": "session-agent-a",
                        "agent_id": "agent-a",
                        "project_id": "authority-project",
                        "objective": "Choose deployment routing",
                        "decisions": ["Use alpha routing for deployment"],
                        "metadata": forged_metadata,
                    },
                )
            self.assertTrue(result["isError"], result)
            payload = json.loads(result["content"][0]["text"])
            self.assertIn("arguments.metadata.dismissed_conflict_components is not allowed", payload["error"])
            self.assertFalse(target_root.exists())

    def test_core_project_state_rejects_reserved_temporal_metadata_before_root_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with self.assertRaisesRegex(
                ValueError,
                "Continuum-reserved temporal field",
            ):
                record_project_state(
                    root,
                    session_id="reserved-session",
                    agent_id="reserved-agent",
                    project_id="reserved-project",
                    metadata={"dismissed_conflict_components": []},
                )
            self.assertFalse(root.exists())

    def test_mcp_invalid_partition_ids_fail_before_durable_side_effects(self) -> None:
        cases = {
            "continuum_roll_segment": {
                "session_id": "bad\n## injected",
                "start_seq": 1,
                "end_seq": 1,
            },
            "continuum_recover_thread": {"session_id": "bad\n## injected"},
            "continuum_record_project_state": {
                "session_id": "good-session",
                "agent_id": "codex",
                "project_id": "bad\n## injected",
                "objective": "should not write",
            },
            "continuum_reindex_memory": {"session_id": "bad\n## injected", "dry_run": False},
        }
        for tool_name, args in cases.items():
            with self.subTest(tool_name=tool_name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                arguments = {"root": str(root), **args}
                with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                    result = call_tool_raw(tool_name, arguments)

                self.assertTrue(result["isError"], result)
                payload = json.loads(result["content"][0]["text"])
                self.assertIn("invalid", payload["error"])
                for rel in ("catalog", "run", "exports", "snapshots"):
                    self.assertFalse((root / rel).exists(), f"{tool_name} created {rel}")

    def test_mcp_invalid_roll_range_fails_before_durable_side_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                result = call_tool_raw(
                    "continuum_roll_segment",
                    {"root": str(root), "session_id": "valid-session", "start_seq": 2, "end_seq": 1},
                )

            self.assertTrue(result["isError"], result)
            payload = json.loads(result["content"][0]["text"])
            self.assertIn("end_seq", payload["error"])
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
                self.assertIsNone(event["_operation"]["proof_pack_uri"])
                self.assertFalse((Path(root) / "exports" / "proof_packs").exists())

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
                self.assertNotIn(rolled["card_uri"], sidecar_paths)
                sidecar_substitution = next(
                    item
                    for item in proof["path_substitutions"]
                    if item.get("kind") == "mutable_internal_file_snapshot"
                )
                frozen_sidecar = str(Path(root) / sidecar_substitution["frozen"]["uri"])
                self.assertIn(frozen_sidecar, sidecar_paths)
                self.assertIn("sha256", sidecar_paths[frozen_sidecar])

                recovery = call_tool(
                    "continuum_recover_thread",
                    {"root": root, "session_id": "mcp-flow", "query": "recover crash"},
                )
                self.assertTrue(Path(recovery["packet_uri"]).exists())
                self.assertIn("# Epic Continuum Thread Recovery", recovery["packet_text"])
                self.assertIn('"session_id": "mcp-flow"', recovery["packet_text"])

                project_state = call_tool(
                    "continuum_record_project_state",
                    {
                        "root": root,
                        "session_id": "mcp-flow",
                        "agent_id": "codex",
                        "project_id": "mcp-project",
                        "objective": "prove shared project state",
                        "decisions": ["MCP tools should share durable state"],
                        "open_tasks": ["Run cue recall"],
                    },
                )
                self.assertTrue(project_state["ok"])

                recall = call_tool(
                    "continuum_cue_recall",
                    {"root": root, "cue": "shared project state", "project_id": "mcp-project"},
                )
                self.assertGreaterEqual(recall["result_count"], 1)
                self.assertIn("shared", json.dumps(recall).lower())

    def test_mcp_append_event_accepts_migrated_legacy_invalid_session_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            event = append_scroll_event(
                root,
                session_id="mcp-legacy-safe",
                event_type="message",
                role="user",
                content="seed",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE scroll_events SET session_id = ? WHERE id = ?",
                    ("legacy mcp session with spaces", event["event_id"]),
                )
                _backfill_partition_aliases(root, conn)
                conn.commit()
            finally:
                conn.close()

            marker = "mcp legacy spaced session continuation"
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                result = call_tool(
                    "continuum_append_event",
                    {"root": str(root), "session_id": "legacy mcp session with spaces", "content": marker},
                )
            recovery = recover_thread(root, session_id="legacy mcp session with spaces", query=marker)

            self.assertIn("event_id", result)
            self.assertIn(marker, recovery["packet_text"])

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
                init_result = call_tool("continuum_init", {"root": root})
                event = call_tool(
                    "continuum_append_event",
                    {"root": root, "session_id": "mcp-smoke", "content": "smoke event"},
                )
                operation_id = event["_operation"]["operation_id"]
                proof_path = init_result["_operation"]["proof_pack_uri"]
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
                        "continuum_cue_recall": {"root": root, "cue": "smoke"},
                        "continuum_record_project_state": {
                            "root": root,
                            "session_id": "mcp-smoke",
                            "agent_id": "codex",
                            "project_id": "mcp-smoke-project",
                            "objective": "smoke shared project state",
                        },
                        "continuum_doctor": {"root": root, "verify_recent_proof_packs": 0, "scan_secrets": False},
                        "continuum_tier_storage": {"root": root, "dry_run": True},
                        "continuum_prune_memory": {"root": root, "dry_run": True, "all": True},
                        "continuum_repair_project_state_checkpoints": {
                            "root": root,
                            "all": True,
                        },
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

                with patch.object(mcp_server_module, "_emit_mcp_diagnostic"):
                    for name in sorted(TOOLS):
                        with self.subTest(tool=name):
                            result = call_tool_raw(name, smoke_args[name])
                            payload = json.loads(result["content"][0]["text"])
                            if result["isError"]:
                                error = str(payload.get("error", ""))
                                self.assertNotIn("not defined", error)
                                self.assertNotIn("NameError", error)
                                self.assertNotIn("AttributeError", error)

    def test_mcp_operation_summary_rejects_path_traversal_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                call_tool("continuum_init", {"root": str(root)})
                response = dispatch_ready(
                    {
                        "jsonrpc": "2.0",
                        "id": 9,
                        "method": "tools/call",
                        "params": {
                            "name": "continuum_operation_summary",
                            "arguments": {"root": str(root), "operation_id": "../../../outside"},
                        },
                    }
                )

            assert response is not None
            self.assertTrue(response["result"]["isError"])
            payload = json.loads(response["result"]["content"][0]["text"])
            self.assertIn("arguments.operation_id does not match the required pattern", payload["error"])

    def test_read_only_status_does_not_initialize_missing_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "missing-continuum"

            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                state = call_tool("continuum_status", {"root": str(root)})

            self.assertFalse(state["initialized"])
            self.assertFalse(root.exists())

    def test_read_only_memory_health_does_not_write_missing_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            config_path = root / "config" / "continuum.config.json"
            config_path.unlink()
            before = tree_fingerprint(root)

            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                result = call_tool("continuum_memory_health", {"root": str(root)})

            self.assertIn("checks", result)
            self.assertFalse(config_path.exists())
            self.assertEqual(before, tree_fingerprint(root))

    def test_read_only_yarn_health_does_not_initialize_missing_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "missing-continuum"

            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                result = call_tool("continuum_yarn_health", {"root": str(root)})

            self.assertFalse(result["enabled"])
            self.assertEqual(result["reason"], "disabled")
            self.assertFalse(root.exists())

    def test_resume_model_assist_false_overrides_enabled_personal_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="mcp-resume-session",
                agent_id="codex-sol",
                project_id="mcp-resume-project",
                objective="Verify explicit model consent",
            )
            config = default_config()
            config["local_inference"]["enabled"] = True
            config["personal_profile"]["assist_on_resume"] = True
            write_config(root, config)

            with (
                patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}),
                patch("continuum.core.local_model._http_json", side_effect=AssertionError("HTTP must remain disabled")),
            ):
                result = call_tool(
                    "continuum_resume_latest",
                    {"root": str(root), "project_id": "mcp-resume-project", "model_assist": False},
                )

            self.assertTrue(result["ok"], result)
            self.assertFalse(result["model_assist"]["used"])
            self.assertEqual(result["model_assist"]["reason"], "not_requested")

    def test_read_only_mcp_tools_do_not_mutate_existing_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                init_result = call_tool("continuum_init", {"root": str(root)})
                event = call_tool(
                    "continuum_append_event",
                    {
                        "root": str(root),
                        "session_id": "mcp-read-only-seed",
                        "role": "user",
                        "content": "MCP read-only tools must not mutate the root.",
                    },
                )
                operation_id = event["_operation"]["operation_id"]
                proof_path = init_result["_operation"]["proof_pack_uri"]
                event_log = str(root / "exports" / "operation_events" / f"{operation_id}.jsonl")

                read_only_args = {
                    "continuum_status": {"root": str(root)},
                    "continuum_compile_context": {
                        "root": str(root),
                        "session_id": "sk-" + "test-missing-readonly-session",
                        "project_id": "ghp_" + "missingReadonlyProject1234567890",
                    },
                    "continuum_search": {"root": str(root), "query": "read-only"},
                    "continuum_cue_recall": {
                        "root": str(root),
                        "cue": "read-only",
                        "session_id": "sk-" + "test-missing-cue-session",
                        "project_id": "ghp_" + "missingCueProject1234567890",
                    },
                    "continuum_audit_search_index": {"root": str(root)},
                    "continuum_audit": {"root": str(root)},
                    "continuum_audit_secrets": {"root": str(root), "max_findings": 10},
                    "continuum_memory_health": {"root": str(root)},
                    "continuum_verify_proof_pack": {"root": str(root), "path": proof_path},
                    "continuum_replay_operation_log": {"path": event_log, "operation_id": operation_id},
                    "continuum_list_operations": {"root": str(root)},
                    "continuum_operation_summary": {"root": str(root), "operation_id": operation_id},
                }
                self.assertEqual(set(read_only_args), TOOLS.keys() & {
                    name for name, (_description, _schema, _handler) in TOOLS.items()
                    if name in {
                        "continuum_status",
                        "continuum_compile_context",
                        "continuum_search",
                        "continuum_cue_recall",
                        "continuum_audit_search_index",
                        "continuum_audit",
                        "continuum_audit_secrets",
                        "continuum_memory_health",
                        "continuum_verify_proof_pack",
                        "continuum_replay_operation_log",
                        "continuum_list_operations",
                        "continuum_operation_summary",
                    }
                })

                for tool_name, args in read_only_args.items():
                    with self.subTest(tool=tool_name):
                        before = tree_fingerprint(root)
                        result = call_tool_raw(tool_name, args)
                        if result["isError"]:
                            self.assertIn(tool_name, {"continuum_compile_context", "continuum_cue_recall"}, result)
                            payload = json.loads(result["content"][0]["text"])
                            self.assertIn("secret scan blocked", payload["error"])
                        self.assertEqual(before, tree_fingerprint(root), f"{tool_name} mutated the root")

    def test_mcp_rejects_roots_and_files_outside_allowed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as allowed, tempfile.TemporaryDirectory() as denied:
            denied_root = Path(denied) / "continuum"
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": allowed}):
                response = dispatch_ready(
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
                response = dispatch_ready(
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
                response = dispatch_ready(
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
                response = dispatch_ready(
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
                event = call_tool("continuum_init", {"root": root})

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
                event = call_tool("continuum_init", {"root": root})

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
                event = call_tool("continuum_init", {"root": root})

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
            conn = connect(Path(root))
            try:
                updated = conn.execute(
                    "UPDATE artifacts SET sha256 = ?, size_bytes = ? "
                    "WHERE kind = 'proof_pack' AND operation_id = ?",
                    (
                        hashlib.sha256(proof_path.read_bytes()).hexdigest(),
                        proof_path.stat().st_size,
                        event["_operation"]["operation_id"],
                    ),
                )
                self.assertEqual(updated.rowcount, 1)
                conn.commit()
            finally:
                conn.close()

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
                response = dispatch_ready(
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
                response = dispatch_ready(
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
            self.assertIn("arguments.limit must be integer", payload["error"])

    def test_mcp_search_exposes_session_and_project_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            marker = "MCP_SCOPED_SEARCH_MARKER_8QL"
            visible_file = Path(tmp) / "visible-mcp.txt"
            hidden_file = Path(tmp) / "hidden-mcp.txt"
            visible_file.write_text(f"Visible scoped MCP library note {marker}", encoding="utf-8")
            hidden_file.write_text(f"Hidden scoped MCP library note {marker}", encoding="utf-8")
            visible = ingest_file(root, path=visible_file, title="Visible MCP library")
            hidden = ingest_file(root, path=hidden_file, title="Hidden MCP library")
            with closing(connect(root)) as conn:
                visible_metadata = json.loads(
                    conn.execute("SELECT metadata_json FROM books WHERE id = ?", (visible["book_id"],)).fetchone()["metadata_json"]
                )
                visible_metadata.update({"visibility_scope": "project", "session_id": "mcp-search-session", "project_id": "mcp-project"})
                hidden_metadata = json.loads(
                    conn.execute("SELECT metadata_json FROM books WHERE id = ?", (hidden["book_id"],)).fetchone()["metadata_json"]
                )
                hidden_metadata.update({"visibility_scope": "project", "session_id": "other-mcp-search", "project_id": "hidden-mcp-project"})
                conn.execute("UPDATE books SET metadata_json = ? WHERE id = ?", (json.dumps(visible_metadata), visible["book_id"]))
                conn.execute("UPDATE books SET metadata_json = ? WHERE id = ?", (json.dumps(hidden_metadata), hidden["book_id"]))
                conn.commit()

            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                result = call_tool(
                    "continuum_search",
                    {
                        "root": str(root),
                        "query": marker,
                        "limit": 1,
                        "session_id": "mcp-search-session",
                        "project_id": "mcp-project",
                    },
                )

            self.assertEqual(result["result_count"], 1)
            self.assertEqual(result["results"][0]["book_id"], visible["book_id"])

    def test_mcp_allow_stop_requires_explicit_process_permission(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            palace = Path(tmp) / "palace"
            palace.mkdir()
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}, clear=False):
                response = dispatch_ready(
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
        response = dispatch_ready(
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
        self.assertIn("arguments.content is required", payload["error"])

    def test_tool_handler_errors_redact_spaced_absolute_paths(self) -> None:
        def failing_handler(_arguments: dict[str, Any]) -> Any:
            raise ValueError(
                'cannot open "C:\\Private Folder\\Sensitive Final Name.txt"'
            )

        test_tool = (
            "Test shared handler error redaction.",
            {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            failing_handler,
        )
        with patch.dict(mcp_server_module.TOOLS, {"continuum_redaction_test": test_tool}):
            response = dispatch_ready(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "continuum_redaction_test",
                        "arguments": {},
                    },
                }
            )

        self.assertIsNotNone(response)
        assert response is not None
        result = response["result"]
        self.assertTrue(result["isError"])
        payload = json.loads(result["content"][0]["text"])
        self.assertIn("<redacted-path:Sensitive Final Name.txt>", payload["error"])
        self.assertNotIn("Private Folder", json.dumps(result, ensure_ascii=True))

    def test_tool_handler_errors_redact_quoted_ambiguous_path_field_after_uri(self) -> None:
        message = "endpoint=https://example.com/status,file='/ Private Folder/secret.txt'"

        def failing_handler(_arguments: dict[str, Any]) -> Any:
            raise ValueError(message)

        test_tool = (
            "Test shared compact-field path redaction.",
            {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            failing_handler,
        )
        with patch.dict(
            mcp_server_module.TOOLS,
            {"continuum_compact_field_redaction_test": test_tool},
        ):
            response = dispatch_ready(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "continuum_compact_field_redaction_test",
                        "arguments": {},
                    },
                }
            )

        self.assertIsNotNone(response)
        assert response is not None
        result = response["result"]
        self.assertTrue(result["isError"])
        payload = json.loads(result["content"][0]["text"])
        self.assertEqual(
            payload["error"],
            "endpoint=https://example.com/status,file='<redacted-path:secret.txt>'",
        )
        self.assertNotIn("Private Folder", json.dumps(result, ensure_ascii=True))

    def test_tool_handler_errors_parse_fields_after_outer_single_quoted_uri(self) -> None:
        cases = (
            (
                "endpoint='https://example.com/status',path=relative/file;"
                "cwd='/ Private Folder/secret.txt'; retry",
                "endpoint='https://example.com/status',path=relative/file;"
                "cwd='<redacted-path:secret.txt>'; retry",
            ),
            (
                "endpoint='https://[v1.a'b]:8443/status',path=relative/file;"
                "cwd='/ Private Folder/secret.txt'; retry",
                "endpoint='https://[v1.a'b]:8443/status',path=relative/file;"
                "cwd='<redacted-path:secret.txt>'; retry",
            ),
        )
        for message, expected in cases:
            with self.subTest(message=message):
                def failing_handler(_arguments: dict[str, Any]) -> Any:
                    raise ValueError(message)

                test_tool = (
                    "Test shared quoted-URI field tokenization.",
                    {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                    failing_handler,
                )
                with patch.dict(
                    mcp_server_module.TOOLS,
                    {"continuum_quoted_uri_field_test": test_tool},
                ):
                    response = dispatch_ready(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {
                                "name": "continuum_quoted_uri_field_test",
                                "arguments": {},
                            },
                        }
                    )

                self.assertIsNotNone(response)
                assert response is not None
                result = response["result"]
                self.assertTrue(result["isError"])
                payload = json.loads(result["content"][0]["text"])
                self.assertEqual(payload["error"], expected)
                self.assertNotIn("Private Folder", json.dumps(result, ensure_ascii=True))

    def test_runtime_tool_handler_error_redacts_json_and_stderr(self) -> None:
        def failing_handler(_arguments: dict[str, Any]) -> Any:
            raise RuntimeError(
                'cannot open "C:\\Private Folder\\api_key=supersecretvalue123.txt"'
            )

        test_tool = (
            "Test shared runtime handler error redaction.",
            {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            failing_handler,
        )
        stderr = io.StringIO()
        with patch.dict(
            mcp_server_module.TOOLS,
            {"continuum_runtime_redaction_test": test_tool},
        ), redirect_stderr(stderr):
            response = dispatch_ready(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "continuum_runtime_redaction_test",
                        "arguments": {},
                    },
                }
            )

        self.assertIsNotNone(response)
        assert response is not None
        rendered = json.dumps(response, ensure_ascii=True)
        diagnostic = stderr.getvalue()
        self.assertTrue(response["result"]["isError"])
        self.assertIn("<redacted-path", rendered)
        for forbidden in (
            "Private Folder",
            "supersecretvalue123",
            str(Path(__file__).resolve()),
        ):
            self.assertNotIn(forbidden, rendered)
            self.assertNotIn(forbidden, diagnostic)
        self.assertEqual(
            diagnostic.strip(),
            "Epic Continuum MCP diagnostic: event=tool_handler_failed; "
            "error=RuntimeError; details redacted",
        )


if __name__ == "__main__":
    unittest.main()
