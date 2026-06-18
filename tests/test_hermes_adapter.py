from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from continuum.cli import main as cli_main
from continuum.core.store import audit, compile_context, utc_now
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
                api_key="sk-secretvalue12345678901234567890",
                set_default_model=True,
            )
            serialized = json.dumps(result, ensure_ascii=True)

            self.assertNotIn("sk-secretvalue12345678901234567890", serialized)
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
