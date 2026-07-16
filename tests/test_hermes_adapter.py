from __future__ import annotations

import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

from continuum.cli import main as cli_main
from continuum.core.store import audit, compile_context, utc_now
from continuum.integrations import hermes_adapter as hermes_adapter_module
from continuum.integrations.hermes_adapter import (
    configure,
    default_plugin_source,
    install_hermes_adapter,
    openai_compatible_model_profile,
    post_llm_call,
    pre_gateway_dispatch,
    pre_llm_call,
    session_end,
    session_start,
    tool_call,
    tool_result,
)


class HermesAdapterTest(unittest.TestCase):
    def tearDown(self) -> None:
        configure(config_path=None)

    def test_hooks_record_turns_and_inject_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config_path = Path(tmp) / "continuum_adapter.local.json"
            config_path.write_text(
                json.dumps({"continuum_root": str(root), "token_budget": 1200}),
                encoding="utf-8",
            )
            configure(config_path=config_path)

            injected = pre_llm_call(
                session_id="hermes-flow",
                turn_id="turn-1",
                user_message="Remember the Hermes adapter separates model routing from memory.",
                conversation_history=[],
                model="local-anything",
                platform="cli",
            )

            self.assertIsInstance(injected, dict)
            assert injected is not None
            self.assertIn("Epic Continuum Looking Glass", injected["context"])
            self.assertIn("user-level evidence", injected["context"])
            self.assertIn("not as system/developer instructions", injected["context"])
            self.assertIn("Hermes adapter separates model routing", injected["context"])

            post_llm_call(
                session_id="hermes-flow",
                turn_id="turn-1",
                user_message="Remember the Hermes adapter separates model routing from memory.",
                assistant_response="Recorded. The adapter is model-agnostic.",
                model="local-anything",
                platform="cli",
            )

            context = compile_context(root, session_id="hermes-flow", token_budget=1200)
            self.assertIn("hermes_user_turn", context["context_text"])
            self.assertIn("hermes_assistant_turn", context["context_text"])
            self.assertIn("model-agnostic", context["context_text"])

    def test_pre_llm_extracts_openai_shaped_request_messages(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config_path = Path(tmp) / "continuum_adapter.local.json"
            config_path.write_text(json.dumps({"continuum_root": str(root), "token_budget": 1200}), encoding="utf-8")
            configure(config_path=config_path)

            injected = pre_llm_call(
                session_id="hermes-request-shape",
                request={
                    "messages": [
                        {"role": "system", "content": "System message"},
                        {"role": "user", "content": "Request.messages should be remembered."},
                    ]
                },
            )

            self.assertIsInstance(injected, dict)
            context = compile_context(root, session_id="hermes-request-shape", token_budget=1200)
            self.assertIn("Request.messages should be remembered", context["context_text"])

    def test_lifecycle_hooks_record_roll_and_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config_path = Path(tmp) / "continuum_adapter.local.json"
            config_path.write_text(json.dumps({"continuum_root": str(root), "token_budget": 1200}), encoding="utf-8")
            configure(config_path=config_path)

            session_start(session_id="hermes-life", model="local-anything")
            pre_gateway_dispatch(session_id="hermes-life", model="local-anything")
            session_end(session_id="hermes-life", model="local-anything")

            context = compile_context(root, session_id="hermes-life", token_budget=1200)
            self.assertIn("hermes_session_start", context["context_text"])
            self.assertIn("hermes_pre_gateway_dispatch", context["context_text"])
            self.assertIn("hermes_session_end", context["context_text"])
            state = audit(root)
            self.assertGreaterEqual(state["snapshots"], 2)
            self.assertGreaterEqual(state["scroll_segments"], 1)

    def test_missing_hermes_session_uses_dated_fallback_and_logs_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config_path = Path(tmp) / "continuum_adapter.local.json"
            config_path.write_text(
                json.dumps({"continuum_root": str(root), "token_budget": 1200}),
                encoding="utf-8",
            )
            configure(config_path=config_path)

            injected = pre_llm_call(user_message="This payload has no stable Hermes session id.")

            self.assertIsInstance(injected, dict)
            log_path = root / "run" / "integrations" / "hermes_adapter.log"
            self.assertTrue(log_path.exists())
            self.assertIn("stable session identifier", log_path.read_text(encoding="utf-8"))

            fallback_session_id = f"hermes-session-{utc_now()[:10].replace('-', '')}"
            context = compile_context(root, session_id=fallback_session_id, token_budget=1200)
            self.assertIn("no stable Hermes session id", context["context_text"])

    def test_tool_hooks_record_calls_and_capped_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config_path = Path(tmp) / "continuum_adapter.local.json"
            config_path.write_text(
                json.dumps(
                    {
                        "continuum_root": str(root),
                        "token_budget": 1200,
                    }
                ),
                encoding="utf-8",
            )
            configure(config_path=config_path)
            continuum_config = root / "config" / "continuum.config.json"

            tool_call(
                session_id="hermes-tools",
                tool_name="search",
                arguments={"query": "recover thread"},
            )
            config = json.loads(continuum_config.read_text(encoding="utf-8"))
            config["capture"]["max_tool_result_bytes"] = "64B"
            continuum_config.write_text(json.dumps(config, ensure_ascii=True, indent=2), encoding="utf-8")
            tool_result(
                session_id="hermes-tools",
                tool_name="search",
                result="x" * 512,
            )

            context = compile_context(root, session_id="hermes-tools", token_budget=1200)
            self.assertIn("hermes_tool_call", context["context_text"])
            self.assertIn("recover thread", context["context_text"])
            self.assertIn("hermes_tool_result", context["context_text"])
            self.assertIn("Continuum capture notice", context["context_text"])

    def test_callback_configuration_failures_never_escape(self) -> None:
        callbacks = (
            ("pre_llm_call", lambda: pre_llm_call(session_id="s", user_message="x")),
            ("post_llm_call", lambda: post_llm_call(session_id="s", response="x")),
            ("tool_call", lambda: tool_call(session_id="s", tool_name="search")),
            ("tool_result", lambda: tool_result(session_id="s", tool_name="search")),
            (
                "lifecycle_event",
                lambda: hermes_adapter_module.lifecycle_event("session_start", session_id="s"),
            ),
        )
        with mock.patch.object(
            hermes_adapter_module,
            "load_adapter_config",
            side_effect=RuntimeError("configuration unavailable"),
        ), mock.patch.object(hermes_adapter_module, "_log_error") as log_error:
            for phase, callback in callbacks:
                with self.subTest(phase=phase):
                    self.assertIsNone(callback())
        self.assertEqual(log_error.call_count, len(callbacks))

    def test_callback_capture_storage_and_roll_failures_never_escape(self) -> None:
        config = {"continuum_root": "C:/nonexistent/continuum-test-root"}
        callbacks = (
            ("tool_call", lambda: tool_call(session_id="s", tool_name="search")),
            ("tool_result", lambda: tool_result(session_id="s", tool_name="search")),
        )
        failure_stages = (
            ("capture", "should_capture"),
            ("storage", "record_tool_event"),
            ("roll", "_maybe_roll_session"),
        )
        for callback_name, callback in callbacks:
            for stage_name, failing_name in failure_stages:
                with self.subTest(callback=callback_name, stage=stage_name), mock.patch.object(
                    hermes_adapter_module,
                    "load_adapter_config",
                    return_value=config,
                ), mock.patch.object(
                    hermes_adapter_module,
                    "should_capture",
                    return_value=True,
                ), mock.patch.object(
                    hermes_adapter_module,
                    "record_tool_event",
                ), mock.patch.object(
                    hermes_adapter_module,
                    "_maybe_roll_session",
                ), mock.patch.object(
                    hermes_adapter_module,
                    failing_name,
                    side_effect=RuntimeError(f"{stage_name} failed"),
                ), mock.patch.object(hermes_adapter_module, "_log_error") as log_error:
                    self.assertIsNone(callback())
                    log_error.assert_called_once()

    def test_turn_and_lifecycle_capture_failures_never_escape(self) -> None:
        config = {"continuum_root": "C:/nonexistent/continuum-test-root"}
        callbacks = (
            lambda: pre_llm_call(session_id="s", user_message="x"),
            lambda: post_llm_call(session_id="s", response="x"),
            lambda: hermes_adapter_module.lifecycle_event("session_start", session_id="s"),
        )
        for callback in callbacks:
            with self.subTest(callback=callback), mock.patch.object(
                hermes_adapter_module,
                "load_adapter_config",
                return_value=config,
            ), mock.patch.object(
                hermes_adapter_module,
                "should_capture",
                side_effect=RuntimeError("capture failed"),
            ), mock.patch.object(hermes_adapter_module, "_log_error") as log_error:
                self.assertIsNone(callback())
                log_error.assert_called_once()

    def test_shell_hook_returns_zero_when_tool_storage_fails(self) -> None:
        payload = json.dumps(
            {"event": "tool_call", "session_id": "s", "tool_name": "search"}
        )
        with mock.patch.object(sys, "stdin", StringIO(payload)), mock.patch.object(
            hermes_adapter_module,
            "load_adapter_config",
            return_value={"continuum_root": "C:/nonexistent/continuum-test-root"},
        ), mock.patch.object(
            hermes_adapter_module,
            "should_capture",
            return_value=True,
        ), mock.patch.object(
            hermes_adapter_module,
            "record_tool_event",
            side_effect=RuntimeError("storage failed"),
        ), mock.patch.object(hermes_adapter_module, "_log_error"):
            self.assertEqual(hermes_adapter_module.shell_hook_main(), 0)

    def test_error_logger_is_best_effort_even_before_config_load(self) -> None:
        with mock.patch.object(
            hermes_adapter_module,
            "default_continuum_root",
            side_effect=RuntimeError("home unavailable"),
        ):
            self.assertIsNone(
                hermes_adapter_module._log_error(
                    None,
                    "test",
                    RuntimeError("primary failure"),
                )
            )

    def test_error_logger_bounds_large_utf8_payload_and_redacts_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            log_path = root / "run" / "integrations" / "hermes_adapter.log"
            secret = "client_secret=supersecretvalue123456789"
            try:
                raise RuntimeError(secret + " " + ("\N{FIRE}" * 100_000))
            except RuntimeError as exc:
                hermes_adapter_module._log_error(
                    {
                        "continuum_root": str(root),
                        "log_path": str(log_path),
                    },
                    "oversized-phase-" + ("\N{FIRE}" * 1_000),
                    exc,
                )

            rendered = log_path.read_text(encoding="utf-8")
            payload = json.loads(rendered)
            self.assertNotIn("supersecretvalue123456789", rendered)
            self.assertIn("[REDACTED]", rendered)
            self.assertLessEqual(
                len(payload["phase"].encode("utf-8")),
                hermes_adapter_module.MAX_ADAPTER_LOG_PHASE_BYTES,
            )
            self.assertLessEqual(
                len(payload["error"].encode("utf-8")),
                hermes_adapter_module.MAX_ADAPTER_LOG_ERROR_BYTES,
            )
            self.assertLessEqual(
                len(payload["traceback"].encode("utf-8")),
                hermes_adapter_module.MAX_ADAPTER_LOG_TRACEBACK_BYTES,
            )
            self.assertIn(
                hermes_adapter_module.ADAPTER_LOG_TRUNCATION_NOTICE,
                payload["error"],
            )

    def test_error_logger_redacts_credentials_across_every_byte_boundary(self) -> None:
        tokens = (
            "AIza" + ("A" * 35),
            "AKIA" + ("A" * 16),
        )

        for token in tokens:
            with self.subTest(token_prefix=token[:4]), tempfile.TemporaryDirectory() as tmp:
                log_path = Path(tmp) / "hermes-adapter.log"

                def boundary_value(limit: int, prefix_bytes: int = 0) -> str:
                    filler_bytes = limit - prefix_bytes - 5
                    self.assertGreaterEqual(filler_bytes, 0)
                    return ("x" * filler_bytes) + "\N{FIRE}" + token

                error_prefix_bytes = len("RuntimeError: ".encode("utf-8"))
                phase = boundary_value(
                    hermes_adapter_module.MAX_ADAPTER_LOG_PHASE_BYTES
                )
                error_message = boundary_value(
                    hermes_adapter_module.MAX_ADAPTER_LOG_ERROR_BYTES,
                    prefix_bytes=error_prefix_bytes,
                )
                traceback_text = boundary_value(
                    hermes_adapter_module.MAX_ADAPTER_LOG_TRACEBACK_BYTES
                )
                with mock.patch.object(
                    hermes_adapter_module.traceback,
                    "format_exc",
                    return_value=traceback_text,
                ):
                    hermes_adapter_module._log_error(
                        {"log_path": str(log_path)},
                        phase,
                        RuntimeError(error_message),
                    )

                payload = json.loads(log_path.read_text(encoding="utf-8"))
                serialized = json.dumps(payload, ensure_ascii=True)
                self.assertNotIn(token, serialized)
                self.assertNotIn(token[:-1], serialized)
                for key, limit in (
                    ("phase", hermes_adapter_module.MAX_ADAPTER_LOG_PHASE_BYTES),
                    ("error", hermes_adapter_module.MAX_ADAPTER_LOG_ERROR_BYTES),
                    (
                        "traceback",
                        hermes_adapter_module.MAX_ADAPTER_LOG_TRACEBACK_BYTES,
                    ),
                ):
                    with self.subTest(key=key):
                        self.assertLessEqual(
                            len(payload[key].encode("utf-8")),
                            limit,
                        )

    def test_error_logger_redacts_open_quoted_assignments_beyond_lookahead(
        self,
    ) -> None:
        def open_assignment(limit: int, *, prefix_bytes: int = 0) -> str:
            start_before_limit = 160
            multibyte_prefix = "\N{FIRE}"
            filler_bytes = (
                limit
                - prefix_bytes
                - len(multibyte_prefix.encode("utf-8"))
                - start_before_limit
            )
            self.assertGreaterEqual(filler_bytes, 0)
            long_value = (
                "alpha beta "
                + (
                    "z"
                    * (
                        hermes_adapter_module.MAX_ADAPTER_LOG_REDACTION_LOOKAHEAD_BYTES
                        + 512
                    )
                )
                + '"'
            )
            return (
                multibyte_prefix
                + ("x" * filler_bytes)
                + ' client_secret="'
                + long_value
            )

        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "hermes-adapter.log"
            error_prefix_bytes = len("RuntimeError: ".encode("utf-8"))
            phase = open_assignment(
                hermes_adapter_module.MAX_ADAPTER_LOG_PHASE_BYTES
            )
            error_message = open_assignment(
                hermes_adapter_module.MAX_ADAPTER_LOG_ERROR_BYTES,
                prefix_bytes=error_prefix_bytes,
            )
            traceback_text = open_assignment(
                hermes_adapter_module.MAX_ADAPTER_LOG_TRACEBACK_BYTES
            )
            with mock.patch.object(
                hermes_adapter_module.traceback,
                "format_exc",
                return_value=traceback_text,
            ):
                hermes_adapter_module._log_error(
                    {"log_path": str(log_path)},
                    phase,
                    RuntimeError(error_message),
                )

            payload = json.loads(log_path.read_text(encoding="utf-8"))
            for key, limit in (
                ("phase", hermes_adapter_module.MAX_ADAPTER_LOG_PHASE_BYTES),
                ("error", hermes_adapter_module.MAX_ADAPTER_LOG_ERROR_BYTES),
                (
                    "traceback",
                    hermes_adapter_module.MAX_ADAPTER_LOG_TRACEBACK_BYTES,
                ),
            ):
                with self.subTest(key=key):
                    self.assertIn("[REDACTED]", payload[key])
                    self.assertNotIn("alpha", payload[key])
                    self.assertNotIn("beta", payload[key])
                    self.assertLessEqual(len(payload[key].encode("utf-8")), limit)

    def test_error_logger_redacts_unbounded_token_crossing_lookahead(self) -> None:
        limit = hermes_adapter_module.MAX_ADAPTER_LOG_ERROR_BYTES
        filler = "x" * (limit - len("RuntimeError: ") - 97)
        open_token = "sk-" + (
            "A"
            * (
                hermes_adapter_module.MAX_ADAPTER_LOG_REDACTION_LOOKAHEAD_BYTES
                + 512
            )
        )
        bounded = hermes_adapter_module._bounded_log_text(
            f"RuntimeError: {filler} {open_token}",
            max_bytes=limit,
        )

        self.assertIn("[REDACTED]", bounded)
        self.assertNotIn("sk-", bounded)
        self.assertLessEqual(len(bounded.encode("utf-8")), limit)

    def test_error_logger_redacts_truly_unterminated_sensitive_quotes(self) -> None:
        def beyond_cap_without_closing_quote(
            limit: int,
            *,
            prefix_bytes: int = 0,
        ) -> str:
            target_bytes = limit + 100 - prefix_bytes
            assignment = ' client_secret="alpha beta omega '
            assignment_start = limit - prefix_bytes - 160
            prefix = "\N{FIRE}" + (
                "x"
                * (
                    assignment_start
                    - len("\N{FIRE}".encode("utf-8"))
                )
            )
            suffix_bytes = (
                target_bytes
                - len(prefix.encode("utf-8"))
                - len(assignment.encode("utf-8"))
            )
            self.assertGreater(suffix_bytes, 0)
            return prefix + assignment + ("z" * suffix_bytes)

        cases = (
            (
                "under-cap",
                "\N{FIRE} client_secret=\"alpha beta omega",
                "\N{FIRE} client_secret=\"alpha beta omega",
                "\N{FIRE} client_secret=\"alpha beta omega",
            ),
            (
                "between-cap-and-lookahead",
                beyond_cap_without_closing_quote(
                    hermes_adapter_module.MAX_ADAPTER_LOG_PHASE_BYTES
                ),
                beyond_cap_without_closing_quote(
                    hermes_adapter_module.MAX_ADAPTER_LOG_ERROR_BYTES,
                    prefix_bytes=len("RuntimeError: ".encode("utf-8")),
                ),
                beyond_cap_without_closing_quote(
                    hermes_adapter_module.MAX_ADAPTER_LOG_TRACEBACK_BYTES
                ),
            ),
        )

        for name, phase, error_message, traceback_text in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                log_path = Path(tmp) / "hermes-adapter.log"
                with mock.patch.object(
                    hermes_adapter_module.traceback,
                    "format_exc",
                    return_value=traceback_text,
                ):
                    hermes_adapter_module._log_error(
                        {"log_path": str(log_path)},
                        phase,
                        RuntimeError(error_message),
                    )

                payload = json.loads(log_path.read_text(encoding="utf-8"))
                for key, limit in (
                    ("phase", hermes_adapter_module.MAX_ADAPTER_LOG_PHASE_BYTES),
                    ("error", hermes_adapter_module.MAX_ADAPTER_LOG_ERROR_BYTES),
                    (
                        "traceback",
                        hermes_adapter_module.MAX_ADAPTER_LOG_TRACEBACK_BYTES,
                    ),
                ):
                    with self.subTest(name=name, key=key):
                        self.assertIn("[REDACTED]", payload[key])
                        self.assertNotIn("alpha", payload[key])
                        self.assertNotIn("beta", payload[key])
                        self.assertNotIn("omega", payload[key])
                        self.assertLessEqual(
                            len(payload[key].encode("utf-8")),
                            limit,
                        )

    def test_error_logger_preserves_safe_suffix_after_complete_sensitive_quote(
        self,
    ) -> None:
        bounded = hermes_adapter_module._bounded_log_text(
            'RuntimeError: client_secret="alpha beta" safe suffix',
            max_bytes=hermes_adapter_module.MAX_ADAPTER_LOG_ERROR_BYTES,
        )

        self.assertIn("[REDACTED]", bounded)
        self.assertNotIn("alpha", bounded)
        self.assertNotIn("beta", bounded)
        self.assertIn("safe suffix", bounded)

        unterminated_json_style = hermes_adapter_module._bounded_log_text(
            'RuntimeError: "client_secret": "alpha beta',
            max_bytes=hermes_adapter_module.MAX_ADAPTER_LOG_ERROR_BYTES,
        )
        self.assertIn("[REDACTED]", unterminated_json_style)
        self.assertNotIn("alpha", unterminated_json_style)
        self.assertNotIn("beta", unterminated_json_style)

    def test_error_logger_redacts_multiline_and_escaped_sensitive_quotes(
        self,
    ) -> None:
        cases = (
            (
                "multiline-double-quote",
                'client_secret="alpha\nbeta" safe suffix',
            ),
            (
                "backslash-escaped-single-quote",
                "client_secret='alpha\\' beta' safe suffix",
            ),
        )

        for name, sensitive_text in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                log_path = Path(tmp) / "hermes-adapter.log"
                with mock.patch.object(
                    hermes_adapter_module.traceback,
                    "format_exc",
                    return_value=sensitive_text,
                ):
                    hermes_adapter_module._log_error(
                        {"log_path": str(log_path)},
                        sensitive_text,
                        RuntimeError(sensitive_text),
                    )

                payload = json.loads(log_path.read_text(encoding="utf-8"))
                for key in ("phase", "error", "traceback"):
                    with self.subTest(name=name, key=key):
                        self.assertIn("[REDACTED]", payload[key])
                        self.assertNotIn("alpha", payload[key])
                        self.assertNotIn("beta", payload[key])
                        self.assertIn("safe suffix", payload[key])

    def test_error_logger_redacts_camelcase_sensitive_assignments(self) -> None:
        keys = ("clientSecret", "accessToken", "privateKey", "clientIDToken")
        for key in keys:
            cases = (
                ("complete", f'{key}="alpha beta" safe suffix'),
                ("unterminated-json", f'"{key}": "alpha beta'),
            )
            for name, diagnostic in cases:
                with self.subTest(key=key, name=name):
                    bounded = hermes_adapter_module._bounded_log_text(
                        diagnostic,
                        max_bytes=hermes_adapter_module.MAX_ADAPTER_LOG_ERROR_BYTES,
                    )
                    self.assertIn("[REDACTED]", bounded)
                    self.assertNotIn("alpha", bounded)
                    self.assertNotIn("beta", bounded)
                    if name == "complete":
                        self.assertIn("safe suffix", bounded)

        limit = hermes_adapter_module.MAX_ADAPTER_LOG_ERROR_BYTES
        assignment = ' clientIDToken="alpha beta '
        prefix_bytes = limit - 160
        prefix = "\N{FIRE}" + (
            "x" * (prefix_bytes - len("\N{FIRE}".encode("utf-8")))
        )
        crossing = prefix + assignment + (
            "z"
            * (
                hermes_adapter_module.MAX_ADAPTER_LOG_REDACTION_LOOKAHEAD_BYTES
                + 512
            )
        )
        bounded = hermes_adapter_module._bounded_log_text(
            crossing,
            max_bytes=limit,
        )
        self.assertIn("[REDACTED]", bounded)
        self.assertNotIn("alpha", bounded)
        self.assertNotIn("beta", bounded)
        self.assertLessEqual(len(bounded.encode("utf-8")), limit)

    def test_installer_reports_and_stops_on_requested_command_failures(self) -> None:
        completed_ok = mock.Mock(returncode=0, stdout="", stderr="")
        completed_enable_failure = mock.Mock(
            returncode=19,
            stdout="",
            stderr="enable failed",
        )
        completed_config_failure = mock.Mock(
            returncode=23,
            stdout="",
            stderr="config failed",
        )
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            common = {
                "hermes_home": base / "hermes",
                "continuum_root": base / "continuum",
                "continuum_src": Path(__file__).resolve().parents[1] / "src",
                "hermes_exe": base / "hermes.exe",
            }
            with mock.patch.object(
                hermes_adapter_module.subprocess,
                "run",
                return_value=completed_enable_failure,
            ) as run:
                enable_result = install_hermes_adapter(
                    **common,
                    model_name="local-model",
                    base_url="http://127.0.0.1:9999/v1",
                    set_default_model=True,
                )

            self.assertFalse(enable_result["ok"], enable_result)
            self.assertEqual(enable_result["command_failure_count"], 1)
            self.assertTrue(enable_result["commands_aborted_after_failure"])
            self.assertEqual(run.call_count, 1)

            with mock.patch.object(
                hermes_adapter_module.subprocess,
                "run",
                side_effect=[completed_ok, completed_ok, completed_config_failure],
            ) as run:
                config_result = install_hermes_adapter(
                    **common,
                    model_name="local-model",
                    base_url="http://127.0.0.1:9999/v1",
                    set_default_model=True,
                )

            self.assertFalse(config_result["ok"], config_result)
            self.assertEqual(config_result["command_failure_count"], 1)
            self.assertTrue(config_result["commands_aborted_after_failure"])
            self.assertEqual(run.call_count, 3)

    def test_installer_copies_plugin_and_writes_local_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hermes_home = Path(tmp) / "hermes"
            root = Path(tmp) / "continuum"
            continuum_src = Path(__file__).resolve().parents[1] / "src"

            result = install_hermes_adapter(
                hermes_home=hermes_home,
                continuum_root=root,
                continuum_src=continuum_src,
                token_budget=900,
                enable=False,
            )

            plugin_target = hermes_home / "plugins" / "epic_continuum"
            local_config = plugin_target / "continuum_adapter.local.json"
            self.assertTrue((plugin_target / "plugin.yaml").exists())
            self.assertTrue((plugin_target / "__init__.py").exists())
            self.assertTrue(local_config.exists())
            loaded = json.loads(local_config.read_text(encoding="utf-8"))
            self.assertEqual(loaded["continuum_root"], str(root))
            self.assertEqual(loaded["token_budget"], 900)
            self.assertEqual(result["plugin_target_ref"]["uri_base"], "external_source")
            self.assertFalse(Path(result["plugin_target"]).is_absolute())

    def test_installer_redacts_api_key_from_return_payload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hermes_home = Path(tmp) / "hermes"
            root = Path(tmp) / "continuum"
            continuum_src = Path(__file__).resolve().parents[1] / "src"

            result = install_hermes_adapter(
                hermes_home=hermes_home,
                continuum_root=root,
                continuum_src=continuum_src,
                enable=True,
                dry_run=True,
                hermes_exe=Path(tmp) / "hermes.exe",
                model_alias="secret-model",
                model_name="secret-model",
                base_url="http://127.0.0.1:9999/v1",
                api_key="sk-" + "secretvalue12345678901234567890",
                set_default_model=True,
            )
            serialized = json.dumps(result, ensure_ascii=True)

            self.assertNotIn("sk-" + "secretvalue12345678901234567890", serialized)
            self.assertNotIn(str(hermes_home), serialized)
            self.assertNotIn(str(continuum_src), serialized)
            self.assertIn("[REDACTED]", serialized)

    def test_manual_mode_can_explicitly_capture_hermes_tool_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config_path = Path(tmp) / "continuum_adapter.local.json"
            config_path.write_text(json.dumps({"continuum_root": str(root), "token_budget": 1200}), encoding="utf-8")
            configure(config_path=config_path)
            continuum_config = root / "config" / "continuum.config.json"
            tool_call(session_id="manual-hermes-tools", tool_name="search", arguments={"query": "not recorded"})
            config = json.loads(continuum_config.read_text(encoding="utf-8"))
            config["capture"]["mode"] = "manual"
            continuum_config.write_text(json.dumps(config, ensure_ascii=True, indent=2), encoding="utf-8")

            suppressed = tool_result(
                session_id="manual-hermes-tools",
                tool_name="search",
                result="manual mode should suppress this",
            )
            explicit = tool_result(
                session_id="manual-hermes-tools",
                tool_name="search",
                result="explicit manual tool capture",
                explicit_capture=True,
            )

            self.assertIsNone(suppressed)
            self.assertIsNone(explicit)
            context = compile_context(root, session_id="manual-hermes-tools", token_budget=1200)
            self.assertIn("explicit manual tool capture", context["context_text"])
            self.assertNotIn("manual mode should suppress this", context["context_text"])

    def test_cli_hermes_install_receipts_do_not_leak_host_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            root = tmp_path / "continuum"
            hermes_home = tmp_path / "Sensitive Hermes Home"
            continuum_src = tmp_path / "Sensitive Continuum Src"
            hermes_exe = tmp_path / "Sensitive Hermes Bin" / "hermes.exe"

            output = StringIO()
            with redirect_stdout(output):
                exit_code = cli_main(
                    [
                        "install-hermes-adapter",
                        "--root",
                        str(root),
                        "--hermes-home",
                        str(hermes_home),
                        "--continuum-src",
                        str(continuum_src),
                        "--hermes-exe",
                        str(hermes_exe),
                        "--dry-run",
                    ]
                )

            self.assertEqual(exit_code, 0)
            generated_text = "\n".join(
                path.read_text(encoding="utf-8")
                for directory in (root / "run" / "operations", root / "exports" / "proof_packs")
                for path in directory.glob("*.json")
            )
            self.assertNotIn(str(hermes_home), generated_text)
            self.assertNotIn(str(continuum_src), generated_text)
            self.assertNotIn(str(hermes_exe), generated_text)
            self.assertIn("external:Sensitive_Hermes_Home", generated_text)

    def test_cli_hermes_install_rejects_secret_api_key_argument(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = StringIO()
            with redirect_stdout(output):
                exit_code = cli_main(
                    [
                        "install-hermes-adapter",
                        "--root",
                        str(Path(tmp) / "continuum"),
                        "--hermes-home",
                        str(Path(tmp) / "hermes"),
                        "--api-key",
                        "sk-" + "test-secret-value-1234567890",
                        "--dry-run",
                    ]
                )

            self.assertEqual(exit_code, 1)
            rendered = output.getvalue()
            self.assertIn("Refusing --api-key", rendered)
            self.assertNotIn("sk-" + "test-secret-value", rendered)

    def test_hermes_plugin_source_is_packaged_asset(self) -> None:
        source = default_plugin_source()

        self.assertTrue((source / "plugin.yaml").exists())
        self.assertTrue((source / "__init__.py").exists())
        self.assertIn("assets", source.as_posix())

    def test_openai_compatible_profile_is_model_agnostic(self) -> None:
        snippet = openai_compatible_model_profile(
            alias="local-test",
            model_name="any-openai-compatible-model",
            base_url="http://127.0.0.1:9999/v1",
            context_length=32768,
            max_tokens=4096,
        )

        self.assertIn("provider: \"custom\"", snippet)
        self.assertIn("any-openai-compatible-model", snippet)
        self.assertIn("local-test", snippet)
        self.assertNotIn("qwen", snippet.lower())

    def test_openai_compatible_profile_escapes_yaml_scalars(self) -> None:
        snippet = openai_compatible_model_profile(
            alias='local"alias\nnext',
            model_name='model"name\nnext',
            base_url='http://127.0.0.1:9999/"\nnext',
            api_key='key"value\nnext',
        )

        self.assertIn('\\"', snippet)
        self.assertIn("\\n", snippet)
        self.assertNotIn("alias\nnext", snippet)
        self.assertNotIn("key\"value\nnext", snippet)


if __name__ == "__main__":
    unittest.main()
