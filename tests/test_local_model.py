from __future__ import annotations

import json
import multiprocessing
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock

from continuum.core import local_model
from continuum.core.config import (
    load_config,
    validate_config,
    validate_inference_base_url,
    validate_yarn_token_budgets,
)
from continuum.core.local_model import (
    DEFAULT_YARN_MODEL,
    assist_resume,
    configure_yarn,
    local_model_health,
)
from continuum.core.store import record_project_state, resume_latest


SAFE_RESOURCES = {
    "safe": True,
    "system_ram": {"free_bytes": 16 * 1024**3, "safe": True},
    "vram": {"free_bytes": 8 * 1024**3, "safe": True},
    "unknown_resources_are_advisory": False,
}


def _fork_disabled_assist_probe(root: str, sender: Any) -> None:
    try:
        started = time.monotonic()
        result = assist_resume(
            Path(root),
            context_text="forked disabled evidence",
            session_id="forked-session",
            project_id=None,
        )
        elapsed = time.monotonic() - started
        runner_threads = sum(
            thread.name == "continuum-local-stage-runner" and thread.is_alive()
            for thread in threading.enumerate()
        )
        sender.send(
            {
                "result": result,
                "elapsed": elapsed,
                "runner_threads": runner_threads,
                "runner_created": local_model._LOCAL_STAGE_RUNNER is not None,
            }
        )
    except BaseException as exc:
        sender.send({"error": repr(exc)})
    finally:
        sender.close()


class _ModelHandler(BaseHTTPRequestHandler):
    model = DEFAULT_YARN_MODEL
    last_request: dict[str, object] | None = None
    response_model: str | None = None
    citation_override: list[str] | None = None
    summary_override: str | None = None
    health_status = 200
    content_encoding: str | None = None
    malformed_content_length = False
    content_override: str | None = None
    outer_response_override: str | None = None
    served_models_override: list[str] | None = None
    response_delays: dict[str, float] = {}

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _send(self, payload: dict[str, object], *, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if self.content_encoding:
            self.send_header("Content-Encoding", self.content_encoding)
        self.send_header(
            "Content-Length",
            "bogus" if self.malformed_content_length else str(len(body)),
        )
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _delay(self, stage: str) -> None:
        delay = float(type(self).response_delays.get(stage, 0.0))
        if delay > 0:
            time.sleep(delay)

    def do_GET(self) -> None:
        if self.path.endswith("/health"):
            self._delay("health")
            self._send({"status": "ok"}, status=self.health_status)
        else:
            self._delay("models")
            model_ids = self.served_models_override or [self.model]
            self._send(
                {
                    "object": "list",
                    "data": [
                        {"id": model_id, "object": "model"} for model_id in model_ids
                    ],
                }
            )

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        request = json.loads(self.rfile.read(length).decode("utf-8"))
        type(self).last_request = request
        self._delay("completion")
        if self.outer_response_override is not None:
            body = self.outer_response_override.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        messages = request["messages"]
        user_payload = json.loads(messages[1]["content"])
        briefing = {
            "schema_version": "continuum.yarn_briefing.v1",
            "request_id": user_payload["request_id"],
            "context_sha256": user_payload["context_sha256"],
            "model_id": self.response_model or self.model,
            "citations": self.citation_override
            if self.citation_override is not None
            else user_payload.get("allowed_evidence_ids", [])[:1],
            "summary": self.summary_override or "Resume the verified Continuum work.",
            "decisions": ["Keep deterministic memory authoritative."],
            "next_actions": ["Run the release gates."],
            "risks": ["Treat model synthesis as advisory."],
            "confidence": "high",
        }
        content = (
            self.content_override
            if self.content_override is not None
            else json.dumps(briefing)
        )
        self._send(
            {
                "id": "chatcmpl-test",
                "model": self.response_model or self.model,
                "choices": [
                    {
                        "index": 0,
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": content},
                    }
                ],
            }
        )


class _Server:
    def __enter__(self) -> tuple[ThreadingHTTPServer, str]:
        _ModelHandler.last_request = None
        _ModelHandler.response_model = None
        _ModelHandler.citation_override = None
        _ModelHandler.summary_override = None
        _ModelHandler.health_status = 200
        _ModelHandler.content_encoding = None
        _ModelHandler.malformed_content_length = False
        _ModelHandler.content_override = None
        _ModelHandler.outer_response_override = None
        _ModelHandler.served_models_override = None
        _ModelHandler.response_delays = {}
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _ModelHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        return self.server, f"http://{host}:{port}/v1"

    def __exit__(self, *_args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class _BlockingResponse:
    status = 200

    def __init__(self, connection: _BlockingConnection, stage: str) -> None:
        self.connection = connection
        self.stage = stage
        self.read_count = 0

    def getheader(self, name: str) -> str | None:
        if name == "Content-Type":
            return "application/json"
        if name == "Content-Length":
            return "2"
        return None

    def read(self, _size: int) -> bytes:
        if self.stage == "body":
            self.connection.closed.wait(timeout=2)
            return b""
        self.read_count += 1
        return b"{}" if self.read_count == 1 else b""

    def close(self) -> None:
        return


class _BlockingConnection:
    sock = None

    def __init__(self, stage: str) -> None:
        self.stage = stage
        self.closed = threading.Event()

    def request(self, *_args: object, **_kwargs: object) -> None:
        if self.stage == "request":
            self.closed.wait(timeout=2)

    def getresponse(self) -> _BlockingResponse:
        if self.stage == "headers":
            self.closed.wait(timeout=2)
        return _BlockingResponse(self, self.stage)

    def close(self) -> None:
        self.closed.set()


class _CloseFailingResponse(_BlockingResponse):
    def close(self) -> None:
        raise OSError("response close failed")


class _CloseFailingConnection(_BlockingConnection):
    def getresponse(self) -> _BlockingResponse:
        return _CloseFailingResponse(self, self.stage)

    def close(self) -> None:
        self.closed.set()
        raise OSError("connection close failed")


class LocalModelTests(unittest.TestCase):
    def setUp(self) -> None:
        with local_model._CIRCUIT_LOCK:
            local_model._CIRCUITS.clear()

    def test_feature_defaults_off_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with mock.patch("continuum.core.local_model._http_json") as http_json:
                health = local_model_health(root)
                result = assist_resume(
                    root, context_text="evidence", session_id="s", project_id=None
                )
            self.assertFalse(health["enabled"])
            self.assertFalse(result["used"])
            self.assertEqual(result["fallback"], "deterministic")
            http_json.assert_not_called()
            self.assertFalse(root.exists())

    def test_cli_and_mcp_imports_do_not_start_yarn_stage_runner(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        env = os.environ.copy()
        python_path = [str(repo_root / "src")]
        if env.get("PYTHONPATH"):
            python_path.append(env["PYTHONPATH"])
        env["PYTHONPATH"] = os.pathsep.join(python_path)
        probe = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import json, threading; "
                    "import continuum.cli, continuum.mcp_server; "
                    "from continuum.core import local_model; "
                    "print(json.dumps({"
                    "'runner_created': local_model._LOCAL_STAGE_RUNNER is not None, "
                    "'runner_threads': sum(t.name == 'continuum-local-stage-runner' "
                    "and t.is_alive() for t in threading.enumerate())"
                    "}))"
                ),
            ],
            cwd=repo_root,
            env=env,
            text=True,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(probe.returncode, 0, probe.stdout + probe.stderr)
        payload = json.loads(probe.stdout)
        self.assertFalse(payload["runner_created"], payload)
        self.assertEqual(payload["runner_threads"], 0, payload)

    @unittest.skipUnless(
        hasattr(os, "fork") and hasattr(os, "register_at_fork"),
        "requires POSIX fork callbacks",
    )
    def test_forked_child_lazily_recreates_exactly_one_stage_runner(self) -> None:
        context = multiprocessing.get_context("fork")
        receiver, sender = context.Pipe(duplex=False)
        with tempfile.TemporaryDirectory() as tmp:
            process = context.Process(
                target=_fork_disabled_assist_probe,
                args=(str(Path(tmp) / "continuum"), sender),
            )
            process.start()
            sender.close()
            payload: dict[str, Any] | None = None
            try:
                self.assertTrue(receiver.poll(5), "forked child did not return")
                payload = receiver.recv()
                process.join(timeout=5)
            finally:
                receiver.close()
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)

        self.assertEqual(process.exitcode, 0)
        assert payload is not None
        self.assertNotIn("error", payload, payload)
        result = payload["result"]
        self.assertEqual(result["reason"], "disabled", result)
        self.assertFalse(result["used"], result)
        self.assertLess(
            payload["elapsed"],
            local_model.CONFIGURATION_BOOTSTRAP_SECONDS,
            payload,
        )
        self.assertTrue(payload["runner_created"], payload)
        self.assertEqual(payload["runner_threads"], 1, payload)

    def test_endpoint_validation_is_loopback_by_default(self) -> None:
        self.assertEqual(
            validate_inference_base_url("http://127.0.0.1:8080/v1"),
            "http://127.0.0.1:8080/v1",
        )
        for value in (
            "file:///tmp/model",
            "http://127.0.0.1:8080",
            "http://0.0.0.0:8080/v1",
            "http://169.254.169.254/latest",
            "http://example.com/v1",
            "http://localhost:8080/v1",
            "http://user:secret@127.0.0.1:8080/v1",
            "http://127.0.0.1:8080/v1?target=other",
            "http://127.0.0.1:8080/v1/../admin",
            "http://127.0.0.1:8080/v%31",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_inference_base_url(value)
        self.assertEqual(
            validate_inference_base_url(
                "https://models.example.com/v1", allow_remote=True
            ),
            "https://models.example.com/v1",
        )

    def test_configure_yarn_enables_safe_personal_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            result = configure_yarn(root, enabled=True)
            config = load_config(root)
            self.assertTrue(result["ok"])
            self.assertTrue(config["local_inference"]["enabled"])
            self.assertEqual(config["local_inference"]["model"], DEFAULT_YARN_MODEL)
            self.assertEqual(
                config["personal_profile"]["safe_context_ceiling"],
                local_model._automatic_safe_context_ceiling(
                    config["local_inference"],
                    context_maximum=config["context"]["max_token_budget"],
                ),
            )
            self.assertTrue(config["personal_profile"]["assist_on_resume"])

            configure_yarn(root, enabled=True, max_input_tokens=32768)
            raised_config = load_config(root)
            self.assertEqual(
                raised_config["local_inference"]["max_input_tokens"], 32768
            )
            self.assertEqual(
                raised_config["personal_profile"]["safe_context_ceiling"],
                local_model._automatic_safe_context_ceiling(
                    raised_config["local_inference"],
                    context_maximum=raised_config["context"]["max_token_budget"],
                ),
            )

    def test_automatic_ceiling_accounts_for_input_and_transport_overhead(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, max_input_tokens=128000)
            config = load_config(root)
            settings = config["local_inference"]
            ceiling = config["personal_profile"]["safe_context_ceiling"]
            evidence_id_limit = local_model._automatic_yarn_evidence_id_limit(
                settings
            )
            evidence_ids = [
                f"evidence-{index}" for index in range(evidence_id_limit)
            ]

            payload, _aliases = local_model._build_resume_request_payload(
                settings,
                safe_context=local_model._representative_serialized_markdown_context(
                    ceiling
                ),
                session_id="session",
                project_id="project",
                evidence_ids=evidence_ids,
                request_id="0" * 32,
                context_sha256="0" * 64,
                max_output_tokens=settings["max_output_tokens"],
            )
            request_bytes, estimated_input_tokens = local_model._request_metrics(payload)

            self.assertLessEqual(request_bytes, local_model.MAX_HTTP_REQUEST_BYTES)
            self.assertLessEqual(
                estimated_input_tokens,
                settings["max_input_tokens"] - settings["max_output_tokens"],
            )
            self.assertLess(ceiling, 128000 - settings["max_output_tokens"])

            oversized_payload, _aliases = local_model._build_resume_request_payload(
                settings,
                safe_context=local_model._representative_serialized_markdown_context(
                    ceiling + 1
                ),
                session_id="session",
                project_id="project",
                evidence_ids=evidence_ids,
                request_id="0" * 32,
                context_sha256="0" * 64,
                max_output_tokens=settings["max_output_tokens"],
            )
            oversized_bytes, oversized_tokens = local_model._request_metrics(
                oversized_payload
            )
            self.assertTrue(
                oversized_bytes > local_model.MAX_HTTP_REQUEST_BYTES
                or oversized_tokens
                > settings["max_input_tokens"] - settings["max_output_tokens"]
            )

    def test_small_yarn_window_adapts_evidence_alias_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = load_config(Path(tmp) / "continuum")["local_inference"]
            settings["max_input_tokens"] = 3000

            evidence_id_limit = local_model._automatic_yarn_evidence_id_limit(
                settings
            )
            ceiling = local_model._automatic_safe_context_ceiling(
                settings,
                context_maximum=128000,
            )

            self.assertGreater(evidence_id_limit, 0)
            self.assertLess(evidence_id_limit, local_model.MAX_YARN_EVIDENCE_IDS)
            self.assertGreaterEqual(ceiling, 256)
            self.assertTrue(
                local_model._representative_request_fits(
                    settings,
                    context_tokens=ceiling,
                    evidence_id_count=evidence_id_limit,
                    max_input_tokens=settings["max_input_tokens"],
                    max_output_tokens=settings["max_output_tokens"],
                )
            )

    def test_advertised_ceiling_accepts_generated_json_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, base_url=base_url)
            config = load_config(root)
            settings = config["local_inference"]
            ceiling = config["personal_profile"]["safe_context_ceiling"]
            evidence_id_limit = local_model._automatic_yarn_evidence_id_limit(
                settings
            )

            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                result = assist_resume(
                    root,
                    context_text=local_model._representative_serialized_markdown_context(
                        ceiling
                    ),
                    session_id="ceiling-session",
                    project_id="ceiling-project",
                    evidence_ids=[
                        f"evidence-{index}"
                        for index in range(evidence_id_limit)
                    ],
                )

            self.assertTrue(result["used"], result)
            self.assertEqual(result["evidence_id_limit"], evidence_id_limit)
            self.assertEqual(result["evidence_ids_omitted"], 0)

    def test_at_ceiling_escape_dense_context_is_trimmed_to_exact_request_budget(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, base_url=base_url)
            config = load_config(root)
            settings = config["local_inference"]
            ceiling = config["personal_profile"]["safe_context_ceiling"]
            escaped_json_block = (
                "## recent_scroll\n```json\n{\"content\":\""
                + ('\\\\"' * 32)
                + "\"}\n```\n"
            )
            dense_context = (
                escaped_json_block
                * (((ceiling * 4) // len(escaped_json_block)) + 1)
            )[: ceiling * 4]

            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                result = assist_resume(
                    root,
                    context_text=dense_context,
                    session_id="dense-session",
                    project_id="dense-project",
                    evidence_ids=["dense-evidence"],
                )

            self.assertTrue(result["used"], result)
            self.assertTrue(result["input_truncated"], result)
            self.assertGreater(result["input_chars_omitted"], 0)
            self.assertEqual(result["original_estimated_tokens"], ceiling)
            self.assertLessEqual(
                result["estimated_input_tokens"],
                settings["max_input_tokens"] - settings["max_output_tokens"],
            )
            self.assertLessEqual(
                result["request_bytes"],
                local_model.MAX_HTTP_REQUEST_BYTES,
            )
            self.assertIsNotNone(_ModelHandler.last_request)

    def test_large_window_escape_dense_context_is_trimmed_to_transport_limit(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            configure_yarn(
                root,
                enabled=True,
                base_url=base_url,
                max_input_tokens=128000,
            )
            config = load_config(root)
            ceiling = config["personal_profile"]["safe_context_ceiling"]
            dense_context = ('\\\\"' * ((ceiling * 2) + 1))[: ceiling * 4]

            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                result = assist_resume(
                    root,
                    context_text=dense_context,
                    session_id="large-dense-session",
                    project_id="large-dense-project",
                    evidence_ids=["large-dense-evidence"],
                )

            self.assertTrue(result["used"], result)
            self.assertTrue(result["input_truncated"], result)
            self.assertGreater(result["input_chars_omitted"], 0)
            self.assertLessEqual(
                result["request_bytes"],
                local_model.MAX_HTTP_REQUEST_BYTES,
            )

    def test_resume_schema_allows_an_empty_evidence_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True)
            settings = load_config(root)["local_inference"]

            payload, aliases = local_model._build_resume_request_payload(
                settings,
                safe_context="bounded context",
                session_id="session",
                project_id=None,
                evidence_ids=[],
                request_id="0" * 32,
                context_sha256="0" * 64,
                max_output_tokens=settings["max_output_tokens"],
            )

            citations = payload["response_format"]["json_schema"]["schema"]["properties"]["citations"]
            self.assertEqual(aliases, {})
            self.assertEqual(citations["items"], {"type": "string"})
            self.assertEqual(citations["maxItems"], 0)

    def test_assist_checks_transformed_context_and_request_bytes_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, max_input_tokens=4096)
            raw_context = "/a\n" * 2000

            with mock.patch("continuum.core.local_model._http_json") as http_json:
                transformed = assist_resume(
                    root,
                    context_text=raw_context,
                    session_id="session",
                    project_id=None,
                )

            self.assertFalse(transformed["used"])
            self.assertEqual(transformed["reason"], "input_budget_exceeded")
            self.assertGreater(transformed["estimated_tokens"], (len(raw_context) + 3) // 4)
            http_json.assert_not_called()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, max_input_tokens=128000)

            with mock.patch("continuum.core.local_model._http_json") as http_json:
                oversized = assist_resume(
                    root,
                    context_text="x" * 300000,
                    session_id="session",
                    project_id=None,
                )

            self.assertFalse(oversized["used"])
            self.assertEqual(oversized["reason"], "input_budget_exceeded")
            self.assertEqual(oversized["detail"], "serialized_request_byte_budget_exceeded")
            self.assertGreater(oversized["request_bytes"], local_model.MAX_HTTP_REQUEST_BYTES)
            http_json.assert_not_called()

    def test_yarn_token_budgets_reject_boolean_and_fractional_values(self) -> None:
        cases = (
            ("max_input_tokens", True, 768),
            ("max_input_tokens", 16384.5, 768),
            ("max_output_tokens", 16384, True),
            ("max_output_tokens", 16384, 768.5),
        )
        for field, max_input_tokens, max_output_tokens in cases:
            with self.subTest(field=field, value=(max_input_tokens, max_output_tokens)):
                with self.assertRaises(ValueError) as validator_error:
                    validate_yarn_token_budgets(
                        max_input_tokens,
                        max_output_tokens,
                    )
                self.assertIn(field, str(validator_error.exception))

                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp) / "continuum"
                    with self.assertRaises(ValueError) as configure_error:
                        configure_yarn(
                            root,
                            enabled=True,
                            max_input_tokens=max_input_tokens,
                            max_output_tokens=max_output_tokens,
                        )
                    self.assertIn(field, str(configure_error.exception))
                    self.assertFalse(root.exists())

    def test_yarn_token_budgets_preserve_usable_briefing_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = load_config(root)
            config["local_inference"]["max_input_tokens"] = 256
            config["local_inference"]["max_output_tokens"] = 768
            with self.assertRaisesRegex(ValueError, "usable context"):
                validate_config(config)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with self.assertRaisesRegex(ValueError, "usable context"):
                configure_yarn(
                    root,
                    enabled=True,
                    max_input_tokens=256,
                    max_output_tokens=768,
                )
            self.assertFalse(root.exists())

        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            configure_yarn(
                root,
                enabled=True,
                base_url=base_url,
                max_input_tokens=4096,
                max_output_tokens=768,
            )
            config = load_config(root)
            self.assertGreaterEqual(config["personal_profile"]["safe_context_ceiling"], 256)
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                result = assist_resume(
                    root,
                    context_text="x" * 1024,
                    session_id="boundary-session",
                    project_id=None,
                )
            self.assertTrue(result["used"], result)

    def test_temperature_must_be_strictly_greater_than_point_three(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(Path(tmp) / "continuum")
            for value in (0.3, float("nan"), float("inf")):
                with self.subTest(value=value):
                    config["local_inference"]["temperature"] = value
                    with self.assertRaises(ValueError):
                        validate_config(config)
            config["local_inference"]["temperature"] = 0.300001
            validate_config(config)

    def test_sampling_floats_must_be_finite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(Path(tmp) / "continuum")
            for key in ("top_p", "repeat_penalty"):
                original = config["local_inference"][key]
                for value in (float("nan"), float("inf"), float("-inf")):
                    with self.subTest(key=key, value=value):
                        config["local_inference"][key] = value
                        with self.assertRaises(ValueError):
                            validate_config(config)
                config["local_inference"][key] = original
            validate_config(config)

    def test_invalid_yarn_configuration_is_rejected_before_root_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with self.assertRaises(ValueError):
                configure_yarn(
                    root, enabled=True, base_url="http://user:secret@127.0.0.1:8080/v1"
                )
            for model in (
                "N:\\Private Models\\qwythos.gguf",
                "/private/models/qwythos.gguf",
                "//private-server/models/qwythos.gguf",
                "file:///N:/Private%20Models/qwythos.gguf",
                "../private/qwythos.gguf",
                "models/Private Models/qwythos.gguf",
                "models\\qwythos.gguf",
                "qwythos.gguf",
            ):
                with self.subTest(model=model), self.assertRaises(ValueError):
                    configure_yarn(root, enabled=True, model=model)
            self.assertFalse(root.exists())

    def test_hand_edited_config_rejects_path_like_model_identifier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = load_config(Path(tmp) / "continuum")
            for model in (
                "/private/models/qwythos.gguf",
                "models/qwythos.gguf",
                "qwythos.gguf",
            ):
                with self.subTest(model=model):
                    config["local_inference"]["model"] = model
                    with self.assertRaises(ValueError):
                        validate_config(config)

    def test_health_and_bound_resume_briefing_succeed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, base_url=base_url)
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                health = local_model_health(root)
                result = assist_resume(
                    root,
                    context_text="Decision: preserve deterministic evidence.",
                    session_id="session-a",
                    project_id="project-a",
                )
            self.assertTrue(health["ready"], health)
            self.assertTrue(result["used"], result)
            self.assertEqual(result["authority"], "non_authoritative_inference")
            self.assertEqual(result["briefing"]["confidence"], "high")
            self.assertIsNotNone(_ModelHandler.last_request)

    def test_resume_briefing_bounds_outbound_evidence_identifiers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, base_url=base_url)
            evidence_ids = [
                f"evidence-{index}"
                for index in range(local_model.MAX_YARN_EVIDENCE_IDS + 50)
            ]
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                result = assist_resume(
                    root,
                    context_text="Bound the evidence aliases.",
                    session_id="session-a",
                    project_id="project-a",
                    evidence_ids=evidence_ids,
                )

            self.assertTrue(result["used"], result)
            self.assertEqual(result["evidence_ids_omitted"], 50)
            request = _ModelHandler.last_request
            self.assertIsNotNone(request)
            assert request is not None
            messages = request.get("messages")
            assert isinstance(messages, list)
            user_message = messages[1]
            assert isinstance(user_message, dict)
            content = user_message.get("content")
            assert isinstance(content, str)
            user_payload = json.loads(content)
            self.assertEqual(
                len(user_payload["allowed_evidence_ids"]),
                local_model.MAX_YARN_EVIDENCE_IDS,
            )

    def test_resource_guard_refuses_inference_before_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True)
            with (
                mock.patch.dict(
                    "os.environ",
                    {
                        "CONTINUUM_AVAILABLE_SYSTEM_RAM": "1GB",
                        "CONTINUUM_FREE_VRAM": "512MB",
                    },
                ),
                mock.patch("continuum.core.local_model._http_json") as http_json,
            ):
                health = local_model_health(root)
                result = assist_resume(
                    root, context_text="safe evidence", session_id="s", project_id=None
                )
            self.assertFalse(health["ready"])
            self.assertEqual(health["reason"], "insufficient_resource_headroom")
            self.assertFalse(result["used"])
            http_json.assert_not_called()

    def test_secret_is_redacted_before_the_local_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, base_url=base_url)
            secret = "sk-" + ("A" * 40)
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                result = assist_resume(
                    root,
                    context_text=f"Use this evidence; leaked token={secret}",
                    session_id="session-a",
                    project_id="project-a",
                )
            self.assertTrue(result["used"], result)
            self.assertNotIn(secret, json.dumps(_ModelHandler.last_request))

    def test_absolute_local_paths_are_removed_before_the_local_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, base_url=base_url)
            local_references = (
                "N:\\Private Folder\\secret file.txt",
                "N:/Private Folder\\mixed/secret file.txt",
                "\\\\private-server\\Private Share\\secret file.txt",
                "//private-server/Private Share/secret file.txt",
                "/home/private user/secret file.txt",
                "/private/Secret Folder/secret file.txt",
                "/models/Private Models/secret model.gguf",
                "/run/private service/secret.sock",
                "~/Private Folder/secret file.txt",
                "file:///N:/Private%20Folder/secret%20model.gguf",
            )
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                result = assist_resume(
                    root,
                    context_text="\n".join(
                        f"Evidence lives at {value}" for value in local_references
                    ),
                    session_id="session-a",
                    project_id="project-a",
                )
            request = _ModelHandler.last_request
            self.assertIsInstance(request, dict)
            messages = request.get("messages") if request is not None else None
            self.assertIsInstance(messages, list)
            user_message = messages[1] if isinstance(messages, list) else None
            self.assertIsInstance(user_message, dict)
            user_payload = json.loads(str(user_message["content"]))
            request_text = str(user_payload["evidence"])
            self.assertTrue(result["used"], result)
            for value in local_references:
                self.assertNotIn(value, request_text)
            self.assertNotIn("Private Folder", request_text)
            self.assertNotIn("private user", request_text)
            self.assertNotIn("Folder\\secret file.txt", request_text)
            self.assertNotIn("Folder\\mixed/secret file.txt", request_text)
            self.assertNotIn("Private Share\\secret file.txt", request_text)
            self.assertNotIn("Private Share/secret file.txt", request_text)
            self.assertNotIn("user/secret file.txt", request_text)
            self.assertNotIn("Secret Folder/secret file.txt", request_text)
            self.assertNotIn("Private Models/secret model.gguf", request_text)
            self.assertNotIn("private service/secret.sock", request_text)
            self.assertIn("local-path-redacted", request_text)

    def test_outbound_identifiers_are_pseudonymous_and_citations_map_back(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, base_url=base_url)
            session_id = "C:\\Session Folder\\thread state.json"
            project_id = "file:///N:/Project%20Folder/private%20state.json"
            evidence_id = "scroll:C:/Evidence Folder/private item.json:17"
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                result = assist_resume(
                    root,
                    context_text="safe evidence",
                    session_id=session_id,
                    project_id=project_id,
                    evidence_ids=[evidence_id],
                )
            request_text = json.dumps(_ModelHandler.last_request)
            self.assertTrue(result["used"], result)
            self.assertNotIn("Session Folder", request_text)
            self.assertNotIn("Project%20Folder", request_text)
            self.assertNotIn("Evidence Folder", request_text)
            self.assertEqual(result["briefing"]["citations"], [evidence_id])

    def test_health_sanitizes_path_like_served_model_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, base_url=base_url)
            leaked_model_paths = [
                "N:\\Private Models\\qwythos secret.gguf",
                "/private/Private Models/qwythos secret.gguf",
                "//private-server/Private Models/qwythos secret.gguf",
                "models/Private Models/qwythos secret.gguf",
                "models\\qwythos-secret.gguf",
                "qwythos-secret.gguf",
            ]
            _ModelHandler.served_models_override = [
                DEFAULT_YARN_MODEL,
                *leaked_model_paths,
            ]
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                health = local_model_health(root)
            rendered = json.dumps(health)
            self.assertTrue(health["ready"], health)
            for leaked_model_path in leaked_model_paths:
                self.assertNotIn(leaked_model_path, rendered)
            self.assertNotIn("Private Models", rendered)
            self.assertIn("local-model-id-redacted", rendered)

    def test_identity_mismatch_falls_back(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, base_url=base_url)
            _ModelHandler.response_model = "wrong-model"
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                result = assist_resume(
                    root, context_text="evidence", session_id="s", project_id=None
                )
            self.assertFalse(result["used"])
            self.assertEqual(result["fallback"], "deterministic")

    def test_excessively_nested_model_json_falls_back_without_changing_context(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="nested-session",
                agent_id="codex-sol",
                project_id="nested-project",
                objective="Keep deterministic recovery intact",
            )
            baseline = resume_latest(
                root, project_id="nested-project", token_budget=900, model_assist=False
            )
            configure_yarn(root, enabled=True, base_url=base_url)
            _ModelHandler.content_override = "[" * 2000 + "0" + "]" * 2000
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                assisted = resume_latest(
                    root,
                    project_id="nested-project",
                    token_budget=900,
                    model_assist=True,
                )
            self.assertEqual(
                baseline["context"]["context_text"], assisted["context"]["context_text"]
            )
            self.assertFalse(assisted["model_assist"]["used"])
            self.assertEqual(assisted["model_assist"]["fallback"], "deterministic")
            self.assertIn("nesting", assisted["model_assist"]["detail"].casefold())

    def test_excessively_nested_outer_http_json_falls_back(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="outer-nested-session",
                agent_id="codex-sol",
                project_id="outer-nested-project",
                objective="Keep outer-envelope fallback deterministic",
            )
            baseline = resume_latest(
                root,
                project_id="outer-nested-project",
                token_budget=900,
                model_assist=False,
            )
            configure_yarn(root, enabled=True, base_url=base_url)
            _ModelHandler.outer_response_override = (
                '{"padding":' + "[" * 2000 + "0" + "]" * 2000 + "}"
            )
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                assisted = resume_latest(
                    root,
                    project_id="outer-nested-project",
                    token_budget=900,
                    model_assist=True,
                )
            self.assertEqual(
                baseline["context"]["context_text"], assisted["context"]["context_text"]
            )
            self.assertFalse(assisted["model_assist"]["used"])
            self.assertEqual(assisted["model_assist"]["fallback"], "deterministic")
            self.assertEqual(assisted["model_assist"]["error_type"], "LocalModelError")

    def test_health_probes_do_not_mutate_the_inference_circuit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, base_url=base_url)
            _ModelHandler.health_status = 503
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                failed_probes = [local_model_health(root) for _ in range(4)]
                _ModelHandler.health_status = 200
                result = assist_resume(
                    root, context_text="safe evidence", session_id="s", project_id=None
                )
            self.assertTrue(all(not probe["ready"] for probe in failed_probes))
            self.assertTrue(result["used"], result)

    def test_failed_assist_health_preflights_open_the_inference_circuit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, base_url=base_url)
            _ModelHandler.health_status = 503
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                attempts = [
                    assist_resume(
                        root,
                        context_text="safe evidence",
                        session_id="s",
                        project_id=None,
                    )
                    for _ in range(3)
                ]
                blocked = assist_resume(
                    root, context_text="safe evidence", session_id="s", project_id=None
                )
            self.assertTrue(
                all(attempt["reason"] != "circuit_open" for attempt in attempts)
            )
            self.assertEqual(blocked["reason"], "circuit_open")

    def test_circuit_is_scoped_by_canonical_root_profile_model_and_origin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "root"
            settings = {
                "base_url": "http://127.0.0.1:8080/v1",
                "profile": "profile-a",
                "model": "model-a",
            }
            key = local_model._circuit_key(root, settings)
            self.assertEqual(
                key, local_model._circuit_key(root / "child" / "..", settings)
            )
            self.assertNotEqual(
                key, local_model._circuit_key(Path(tmp) / "other", settings)
            )
            self.assertNotEqual(
                key,
                local_model._circuit_key(root, {**settings, "profile": "profile-b"}),
            )
            self.assertNotEqual(
                key, local_model._circuit_key(root, {**settings, "model": "model-b"})
            )
            self.assertNotEqual(
                key,
                local_model._circuit_key(
                    root, {**settings, "base_url": "http://127.0.0.1:8081/v1"}
                ),
            )

    def test_health_distinguishes_endpoint_readiness_from_an_open_circuit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, base_url=base_url)
            settings = local_model._settings(root)
            for _ in range(3):
                local_model._record_failure(root, settings)
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                probed = local_model_health(root, probe=True)
                unprobed = local_model_health(root, probe=False)
            self.assertTrue(probed["endpoint_ready"], probed)
            self.assertTrue(probed["circuit_open"], probed)
            self.assertFalse(probed["ready"], probed)
            self.assertFalse(probed["ok"], probed)
            self.assertEqual(probed["reason"], "circuit_open")
            self.assertFalse(unprobed["ready"], unprobed)
            self.assertFalse(unprobed["ok"], unprobed)
            self.assertEqual(unprobed["reason"], "circuit_open")

    def test_circuit_failure_in_one_root_does_not_block_another_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root_a = Path(tmp) / "root-a"
            root_b = Path(tmp) / "root-b"
            configure_yarn(root_a, enabled=True, base_url=base_url)
            configure_yarn(root_b, enabled=True, base_url=base_url)
            _ModelHandler.response_model = "wrong-model"
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                failures = [
                    assist_resume(
                        root_a,
                        context_text="safe evidence",
                        session_id="s",
                        project_id=None,
                    )
                    for _ in range(3)
                ]
                _ModelHandler.response_model = None
                result = assist_resume(
                    root_b,
                    context_text="safe evidence",
                    session_id="s",
                    project_id=None,
                )
            self.assertTrue(all(not failure["used"] for failure in failures))
            self.assertTrue(result["used"], result)

    def test_http_deadline_covers_request_headers_and_body(self) -> None:
        for stage in ("request", "headers", "body"):
            with self.subTest(stage=stage):
                connection = _BlockingConnection(stage)
                started = time.monotonic()
                with mock.patch(
                    "continuum.core.local_model.http.client.HTTPConnection",
                    return_value=connection,
                ):
                    with self.assertRaisesRegex(
                        local_model.LocalModelError, "total deadline"
                    ):
                        local_model._http_json(
                            method="GET",
                            url="http://127.0.0.1:8080/v1/health",
                            timeout_seconds=1,
                        )
                elapsed = time.monotonic() - started
                self.assertLess(
                    elapsed,
                    1.5,
                    f"{stage} exceeded the wall-clock deadline: {elapsed:.3f}s",
                )

    def test_http_cleanup_failures_preserve_success_and_deadline_outcomes(self) -> None:
        successful = _CloseFailingConnection("response-close")
        with mock.patch(
            "continuum.core.local_model.http.client.HTTPConnection",
            return_value=successful,
        ):
            self.assertEqual(
                local_model._http_json(
                    method="GET",
                    url="http://127.0.0.1:8080/v1/health",
                    timeout_seconds=1,
                ),
                {},
            )
        self.assertTrue(successful.closed.is_set())

        blocked = _CloseFailingConnection("request")
        try:
            with mock.patch(
                "continuum.core.local_model.http.client.HTTPConnection",
                return_value=blocked,
            ):
                with self.assertRaisesRegex(
                    local_model.LocalModelError,
                    "total deadline",
                ):
                    local_model._http_json(
                        method="GET",
                        url="http://127.0.0.1:8080/v1/health",
                        timeout_seconds=0.05,
                    )
        finally:
            self.assertTrue(local_model._local_stage_runner().wait_idle(2))
        self.assertTrue(blocked.closed.is_set())

    def test_blocked_http_requests_use_one_runner_without_thread_growth(self) -> None:
        release = threading.Event()
        stage_runner = local_model._local_stage_runner()
        self.assertTrue(stage_runner.wait_idle(2))

        class IgnoringCloseConnection:
            sock = None

            def __init__(self, *_args: object, **_kwargs: object) -> None:
                return

            def request(self, *_args: object, **_kwargs: object) -> None:
                release.wait(timeout=5)

            def close(self) -> None:
                return

        http_threads_before = sum(
            thread.name == "continuum-local-http" and thread.is_alive()
            for thread in threading.enumerate()
        )
        stage_threads_before = sum(
            thread.name == "continuum-local-stage-runner" and thread.is_alive()
            for thread in threading.enumerate()
        )
        elapsed_times: list[float] = []
        try:
            with mock.patch(
                "continuum.core.local_model.http.client.HTTPConnection",
                IgnoringCloseConnection,
            ):
                for _ in range(3):
                    started = time.monotonic()
                    with self.assertRaisesRegex(
                        local_model.LocalModelError,
                        "total deadline",
                    ):
                        local_model._http_json(
                            method="GET",
                            url="http://127.0.0.1:9/health",
                            timeout_seconds=0.05,
                        )
                    elapsed_times.append(time.monotonic() - started)
        finally:
            release.set()
            self.assertTrue(stage_runner.wait_idle(2))

        http_threads_after = sum(
            thread.name == "continuum-local-http" and thread.is_alive()
            for thread in threading.enumerate()
        )
        stage_threads_after = sum(
            thread.name == "continuum-local-stage-runner" and thread.is_alive()
            for thread in threading.enumerate()
        )
        self.assertEqual(http_threads_after, http_threads_before)
        self.assertEqual(stage_threads_before, 1)
        self.assertEqual(stage_threads_after, stage_threads_before)
        for elapsed in elapsed_times:
            self.assertLess(elapsed, 0.5)

    def test_assist_uses_one_deadline_across_preflight_and_completion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            configure_yarn(
                root,
                enabled=True,
                base_url=base_url,
                timeout_seconds=1,
            )
            _ModelHandler.response_delays = {
                "health": 0.25,
                "models": 0.25,
                "completion": 0.75,
            }
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                started = time.monotonic()
                result = assist_resume(
                    root,
                    context_text="deadline evidence",
                    session_id="s",
                    project_id="p",
                )
                elapsed = time.monotonic() - started

            self.assertFalse(result["used"], result)
            self.assertEqual(result["reason"], "model_request_failed")
            self.assertEqual(result["fallback"], "deterministic")
            self.assertIn("total deadline", result["detail"])
            self.assertIsNotNone(_ModelHandler.last_request)
            self.assertLess(
                elapsed,
                1.5,
                f"full Yarn operation exceeded its deadline: {elapsed:.3f}s",
            )

    def test_assist_deadline_includes_slow_context_preprocessing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, timeout_seconds=1)
            stage_runner = local_model._local_stage_runner()
            self.assertTrue(stage_runner.wait_idle(2))
            release = threading.Event()
            stage_threads_before = [
                thread
                for thread in threading.enumerate()
                if thread.name == "continuum-local-stage-runner" and thread.is_alive()
            ]

            def slow_portable_text(_root: Path, text: str) -> str:
                release.wait(timeout=5)
                return text

            try:
                with mock.patch(
                    "continuum.core.local_model._portable_model_text",
                    side_effect=slow_portable_text,
                ):
                    started = time.monotonic()
                    result = assist_resume(
                        root,
                        context_text="deadline preprocessing evidence",
                        session_id="s",
                        project_id="p",
                    )
                    elapsed = time.monotonic() - started
            finally:
                release.set()
                self.assertTrue(stage_runner.wait_idle(2))

            stage_threads_after = [
                thread
                for thread in threading.enumerate()
                if thread.name == "continuum-local-stage-runner" and thread.is_alive()
            ]
            self.assertEqual(len(stage_threads_before), 1)
            self.assertEqual(len(stage_threads_after), len(stage_threads_before))
            self.assertFalse(result["used"], result)
            self.assertEqual(result["reason"], "model_request_failed")
            self.assertEqual(result["detail"], local_model.TOTAL_DEADLINE_ERROR)
            self.assertLess(
                elapsed,
                1.5,
                f"preprocessing exceeded the wall-clock deadline: {elapsed:.3f}s",
            )

    def test_assist_deadline_is_anchored_before_slow_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, timeout_seconds=1)
            stage_runner = local_model._local_stage_runner()
            self.assertTrue(stage_runner.wait_idle(2))
            original_configuration = local_model._configuration
            preprocessing_started = threading.Event()
            release = threading.Event()

            def slow_configuration(current_root: Path) -> dict[str, object]:
                time.sleep(0.65)
                return original_configuration(current_root)

            def blocked_portable_text(_root: Path, text: str) -> str:
                preprocessing_started.set()
                release.wait(timeout=5)
                return text

            try:
                with (
                    mock.patch(
                        "continuum.core.local_model._configuration",
                        side_effect=slow_configuration,
                    ) as configuration,
                    mock.patch(
                        "continuum.core.local_model._portable_model_text",
                        side_effect=blocked_portable_text,
                    ),
                ):
                    started = time.monotonic()
                    result = assist_resume(
                        root,
                        context_text="configuration deadline evidence",
                        session_id="s",
                        project_id="p",
                    )
                    elapsed = time.monotonic() - started
            finally:
                release.set()
                self.assertTrue(stage_runner.wait_idle(2))

            self.assertEqual(configuration.call_count, 1)
            self.assertTrue(preprocessing_started.is_set())
            self.assertFalse(result["used"], result)
            self.assertEqual(result["reason"], "model_request_failed")
            self.assertEqual(result["detail"], local_model.TOTAL_DEADLINE_ERROR)
            self.assertLess(
                elapsed,
                1.5,
                f"configuration was excluded from the assist deadline: {elapsed:.3f}s",
            )

    def test_repeated_blocked_resource_checks_do_not_grow_threads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, timeout_seconds=1)
            stage_runner = local_model._local_stage_runner()
            self.assertTrue(stage_runner.wait_idle(2))
            releases = [threading.Event() for _ in range(3)]
            resource_calls = 0
            stage_threads_before = [
                thread
                for thread in threading.enumerate()
                if thread.name == "continuum-local-stage-runner" and thread.is_alive()
            ]

            def blocked_resource_guard(_settings: dict[str, object]) -> dict[str, object]:
                nonlocal resource_calls
                release = releases[resource_calls]
                resource_calls += 1
                release.wait(timeout=5)
                return SAFE_RESOURCES

            results: list[dict[str, object]] = []
            elapsed_times: list[float] = []
            try:
                with mock.patch(
                    "continuum.core.local_model._resource_guard",
                    side_effect=blocked_resource_guard,
                ):
                    for release in releases:
                        started = time.monotonic()
                        results.append(
                            assist_resume(
                                root,
                                context_text="resource deadline evidence",
                                session_id="s",
                                project_id="p",
                            )
                        )
                        elapsed_times.append(time.monotonic() - started)
                        release.set()
                        self.assertTrue(stage_runner.wait_idle(2))
            finally:
                for release in releases:
                    release.set()
                self.assertTrue(stage_runner.wait_idle(2))

            stage_threads_after = [
                thread
                for thread in threading.enumerate()
                if thread.name == "continuum-local-stage-runner" and thread.is_alive()
            ]
            self.assertEqual(resource_calls, len(releases))
            self.assertEqual(len(stage_threads_before), 1)
            self.assertEqual(len(stage_threads_after), len(stage_threads_before))
            for result, elapsed in zip(results, elapsed_times, strict=True):
                self.assertFalse(result["used"], result)
                self.assertEqual(result["reason"], "model_request_failed")
                self.assertIn("total deadline", str(result["detail"]))
                self.assertLess(
                    elapsed,
                    1.5,
                    f"resource check exceeded the deadline: {elapsed:.3f}s",
                )

    def test_repeated_assists_do_not_queue_behind_one_blocked_stage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, timeout_seconds=1)
            stage_runner = local_model._local_stage_runner()
            self.assertTrue(stage_runner.wait_idle(2))
            original_configuration = local_model._configuration
            release = threading.Event()
            resource_started = threading.Event()
            resource_calls = 0
            stage_threads_before = [
                thread
                for thread in threading.enumerate()
                if thread.name == "continuum-local-stage-runner" and thread.is_alive()
            ]

            def blocked_resource_guard(_settings: dict[str, object]) -> dict[str, object]:
                nonlocal resource_calls
                resource_calls += 1
                resource_started.set()
                release.wait(timeout=10)
                return SAFE_RESOURCES

            results: list[dict[str, object]] = []
            elapsed_times: list[float] = []
            try:
                with (
                    mock.patch(
                        "continuum.core.local_model._configuration",
                        wraps=original_configuration,
                    ) as configuration,
                    mock.patch(
                        "continuum.core.local_model._resource_guard",
                        side_effect=blocked_resource_guard,
                    ),
                ):
                    for _ in range(3):
                        started = time.monotonic()
                        results.append(
                            assist_resume(
                                root,
                                context_text="blocked runner deadline evidence",
                                session_id="s",
                                project_id="p",
                            )
                        )
                        elapsed_times.append(time.monotonic() - started)
                    self.assertTrue(resource_started.is_set())
                    self.assertEqual(resource_calls, 1)
                    self.assertEqual(configuration.call_count, 1)
            finally:
                release.set()
                self.assertTrue(stage_runner.wait_idle(2))

            stage_threads_after = [
                thread
                for thread in threading.enumerate()
                if thread.name == "continuum-local-stage-runner" and thread.is_alive()
            ]
            self.assertEqual(resource_calls, 1)
            self.assertEqual(configuration.call_count, 1)
            self.assertEqual(len(stage_threads_before), 1)
            self.assertEqual(len(stage_threads_after), len(stage_threads_before))
            for result, elapsed in zip(results, elapsed_times, strict=True):
                self.assertFalse(result["used"], result)
                self.assertEqual(result["reason"], "model_request_failed")
                self.assertEqual(result["detail"], local_model.TOTAL_DEADLINE_ERROR)
                self.assertLess(
                    elapsed,
                    1.5,
                    f"blocked runner call exceeded its deadline: {elapsed:.3f}s",
                )

    def test_health_deadline_result_uses_stable_request_failure_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, timeout_seconds=5)
            with mock.patch(
                "continuum.core.local_model._local_model_health",
                return_value={
                    "ok": False,
                    "ready": False,
                    "reason": local_model.TOTAL_DEADLINE_ERROR,
                    "error_type": local_model.LocalModelError.__name__,
                },
            ):
                result = assist_resume(
                    root,
                    context_text="health deadline classification evidence",
                    session_id="s",
                    project_id="p",
                )

            self.assertFalse(result["used"], result)
            self.assertEqual(result["reason"], "model_request_failed")
            self.assertEqual(result["detail"], local_model.TOTAL_DEADLINE_ERROR)
            self.assertEqual(result["error_type"], "LocalModelError")

    def test_unknown_evidence_citation_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, base_url=base_url)
            _ModelHandler.citation_override = ["unknown-evidence"]
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                result = assist_resume(
                    root,
                    context_text="known evidence",
                    session_id="s",
                    project_id="p",
                    evidence_ids=["known-evidence"],
                )
            self.assertFalse(result["used"])
            self.assertEqual(result["reason"], "model_request_failed")
            self.assertIn("citations", result["detail"])

    def test_secret_echo_from_model_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            configure_yarn(root, enabled=True, base_url=base_url)
            _ModelHandler.summary_override = "secret sk-" + ("Z" * 40)
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                result = assist_resume(
                    root, context_text="safe evidence", session_id="s", project_id=None
                )
            self.assertFalse(result["used"])
            self.assertEqual(result["fallback"], "deterministic")

    def test_redirect_compression_and_malformed_length_fail_closed(self) -> None:
        for mode in ("redirect", "compressed", "length"):
            with (
                self.subTest(mode=mode),
                tempfile.TemporaryDirectory() as tmp,
                _Server() as (_server, base_url),
            ):
                root = Path(tmp) / "continuum"
                configure_yarn(root, enabled=True, base_url=base_url)
                if mode == "redirect":
                    _ModelHandler.health_status = 302
                elif mode == "compressed":
                    _ModelHandler.content_encoding = "gzip"
                else:
                    _ModelHandler.malformed_content_length = True
                with mock.patch(
                    "continuum.core.local_model._resource_guard",
                    return_value=SAFE_RESOURCES,
                ):
                    health = local_model_health(root)
                self.assertFalse(health["ready"], health)

    def test_cross_project_honeytoken_never_reaches_yarn(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, _Server() as (_server, base_url):
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="session-a",
                agent_id="codex-sol",
                project_id="project-a",
                objective="Allowed project evidence",
            )
            honeytoken = "PROJECT_B_HONEYTOKEN_7F3D"
            record_project_state(
                root,
                session_id="session-b",
                agent_id="codex-sol",
                project_id="project-b",
                objective=honeytoken,
            )
            configure_yarn(root, enabled=True, base_url=base_url)
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                result = resume_latest(
                    root, project_id="project-a", token_budget=900, model_assist=True
                )
            self.assertTrue(result["model_assist"]["used"], result)
            self.assertNotIn(honeytoken, json.dumps(_ModelHandler.last_request))

    def test_resume_keeps_deterministic_context_when_endpoint_is_offline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="resume-session",
                agent_id="codex-sol",
                project_id="resume-project",
                objective="Recover safely",
                decisions=["Deterministic evidence wins"],
            )
            baseline = resume_latest(root, token_budget=900, model_assist=False)
            configure_yarn(root, enabled=True, base_url="http://127.0.0.1:9/v1")
            with mock.patch(
                "continuum.core.local_model._resource_guard",
                return_value=SAFE_RESOURCES,
            ):
                assisted = resume_latest(root, token_budget=900, model_assist=True)
            self.assertEqual(
                baseline["context"]["context_text"], assisted["context"]["context_text"]
            )
            self.assertFalse(assisted["model_assist"]["used"])
            self.assertEqual(assisted["model_assist"]["fallback"], "deterministic")


if __name__ == "__main__":
    unittest.main()
