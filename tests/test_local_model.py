from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from continuum.core import local_model
from continuum.core.config import (
    YARN_BRIEFING_PROTOCOL_RESERVE_TOKENS,
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
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path.endswith("/health"):
            self._send({"status": "ok"}, status=self.health_status)
        else:
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
                config["local_inference"]["max_input_tokens"]
                - config["local_inference"]["max_output_tokens"]
                - YARN_BRIEFING_PROTOCOL_RESERVE_TOKENS,
            )
            self.assertTrue(config["personal_profile"]["assist_on_resume"])

            configure_yarn(root, enabled=True, max_input_tokens=32768)
            raised_config = load_config(root)
            self.assertEqual(
                raised_config["local_inference"]["max_input_tokens"], 32768
            )
            self.assertEqual(
                raised_config["personal_profile"]["safe_context_ceiling"],
                raised_config["local_inference"]["max_input_tokens"]
                - raised_config["local_inference"]["max_output_tokens"]
                - YARN_BRIEFING_PROTOCOL_RESERVE_TOKENS,
            )

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
                max_input_tokens=1536,
                max_output_tokens=768,
            )
            config = load_config(root)
            self.assertEqual(config["personal_profile"]["safe_context_ceiling"], 256)
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
