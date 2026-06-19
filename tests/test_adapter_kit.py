from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum.core.store import compile_context
from continuum.integrations.adapter_manifest import adapter_index
from continuum.integrations.claude_code_adapter import handle_hook
from continuum.integrations.openai_context_adapter import prepare_chat_request, record_chat_response
from continuum.integrations.openclaw_adapter import build_openclaw_mission_card
from continuum.mcp_server import TOOLS


class AdapterKitTest(unittest.TestCase):
    def test_adapter_manifest_has_wide_first_party_index(self) -> None:
        adapters = adapter_index()
        names = {entry["name"] for entry in adapters}

        self.assertGreaterEqual(len(adapters), 15)
        for required in {"Codex", "Hermes Agent", "Claude Code", "OpenClaw", "Ollama"}:
            self.assertIn(required, names)

    def test_checked_in_codex_plugin_uses_portable_package_mode(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        plugin_mcp = repo_root / "plugins" / "continuum" / ".mcp.json"
        runner = repo_root / "plugins" / "continuum" / "scripts" / "run_mcp.py"

        payload = json.loads(plugin_mcp.read_text(encoding="utf-8"))

        server = payload["mcpServers"]["continuum"]
        self.assertEqual(server["command"], "python")
        self.assertEqual(server["args"], ["scripts/run_mcp.py"])
        self.assertTrue(runner.exists())
        env = server.get("env") or {}
        self.assertNotIn("PYTHONPATH", env)
        self.assertNotIn("CONTINUUM_ROOT", env)

    def test_codex_plugin_marketplace_is_packaged_with_repo(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        marketplace = repo_root / ".agents" / "plugins" / "marketplace.json"

        payload = json.loads(marketplace.read_text(encoding="utf-8"))

        self.assertEqual(payload["name"], "epic-continuum")
        entries = {entry["name"]: entry for entry in payload["plugins"]}
        self.assertIn("continuum", entries)
        self.assertEqual(entries["continuum"]["source"]["path"], "./plugins/continuum")
        self.assertEqual(entries["continuum"]["policy"]["installation"], "AVAILABLE")

    def test_codex_docs_list_the_complete_mcp_tool_surface(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        docs = (repo_root / "docs" / "integrations" / "codex-plugin.md").read_text(encoding="utf-8")
        skill = (repo_root / "plugins" / "continuum" / "skills" / "continuum-memory" / "SKILL.md").read_text(encoding="utf-8")

        for tool_name in TOOLS:
            with self.subTest(tool_name=tool_name):
                self.assertIn(f"`{tool_name}`", docs)
        for expected in (
            "continuum_run_workers",
            "continuum_memory_health",
            "continuum_pack_root",
            "continuum_verify_bundle",
            "continuum_audit_secrets",
            "continuum_redact_legacy_secrets",
        ):
            with self.subTest(skill_tool=expected):
                self.assertIn(expected, skill)

    def test_openai_compatible_adapter_records_and_injects_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            request = {
                "model": "local-model",
                "messages": [
                    {"role": "system", "content": "You are concise."},
                    {"role": "user", "content": "Remember the adapter wraps OpenAI-shaped requests."},
                ],
            }

            wrapped = prepare_chat_request(
                root,
                session_id="openai-flow",
                request=request,
                source="test-openai",
                token_budget=800,
            )

            self.assertEqual(wrapped["messages"][0]["role"], "system")
            self.assertEqual(wrapped["messages"][0]["content"], "You are concise.")
            self.assertEqual(wrapped["messages"][1]["role"], "user")
            self.assertIn("user-level evidence", wrapped["messages"][1]["content"])
            self.assertIn("Epic Continuum Looking Glass", wrapped["messages"][1]["content"])
            self.assertIn("OpenAI-shaped requests", wrapped["messages"][1]["content"])
            self.assertEqual(wrapped["messages"][2]["role"], "user")

            record_chat_response(
                root,
                session_id="openai-flow",
                source="test-openai",
                response={
                    "model": "local-model",
                    "choices": [{"message": {"role": "assistant", "content": "Recorded."}}],
                },
            )
            context = compile_context(root, session_id="openai-flow", token_budget=800)
            self.assertIn("test-openai_user_turn", context["context_text"])
            self.assertIn("test-openai_assistant_turn", context["context_text"])

    def test_openclaw_mission_card_keeps_execution_advisory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            request = {
                "model": "local-model",
                "messages": [{"role": "user", "content": "OpenClaw should receive evidence and gates."}],
            }
            prepare_chat_request(root, session_id="openclaw-flow", request=request, source="test-openclaw")

            card = build_openclaw_mission_card(
                root,
                session_id="openclaw-flow",
                query="Need OpenClaw handoff.",
            )

            self.assertEqual(card["schema"], "epic_continuum.openclaw_mission_card.v1")
            self.assertEqual(card["decision"], "review_only_context_handoff")
            self.assertIn("gate", card)
            self.assertIn("proof_boundary", card)
            self.assertIn("OpenClaw should receive evidence", card["continuum"]["context_text"])

    def test_claude_code_hook_records_prompt_and_returns_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with patch.dict(
                "os.environ",
                {
                    "CONTINUUM_ROOT": str(root),
                    "CONTINUUM_TOKEN_BUDGET": "800",
                },
            ):
                result = handle_hook(
                    {
                        "hook_event_name": "UserPromptSubmit",
                        "session_id": "claude-flow",
                        "prompt": "Use Continuum to recover this Claude Code thread.",
                        "cwd": str(root),
                    }
                )

            self.assertIsInstance(result, dict)
            assert result is not None
            hook_output = result["hookSpecificOutput"]
            self.assertEqual(hook_output["hookEventName"], "UserPromptSubmit")
            self.assertIn("Epic Continuum Looking Glass", hook_output["additionalContext"])
            self.assertIn("recover this Claude Code thread", hook_output["additionalContext"])


if __name__ == "__main__":
    unittest.main()
