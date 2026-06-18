from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any

from continuum.core.store import utc_now
from continuum.integrations.common import (
    DEFAULT_TOKEN_BUDGET,
    adapter_metadata,
    as_text,
    compile_context_packet,
    default_continuum_root,
    record_turn,
    session_id_from_payload,
)


SOURCE = "claude_code"


def _token_budget() -> int:
    try:
        return int(os.environ.get("CONTINUUM_TOKEN_BUDGET", str(DEFAULT_TOKEN_BUDGET)))
    except ValueError:
        return DEFAULT_TOKEN_BUDGET


def _root() -> Path:
    return default_continuum_root()


def _log_error(exc: BaseException, *, phase: str) -> None:
    try:
        log_path = _root() / "run" / "integrations" / "claude_code_adapter.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "created_at": utc_now(),
            "phase": phase,
            "error": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(limit=8),
        }
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n")
    except OSError:
        return


def _additional_context(event_name: str, context_packet: str) -> dict[str, Any] | None:
    if not context_packet.strip():
        return None
    return {
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "additionalContext": context_packet,
        }
    }


def handle_hook(payload: dict[str, Any]) -> dict[str, Any] | None:
    event_name = str(payload.get("hook_event_name") or "")
    session_id = session_id_from_payload(payload, default="claude-code-session")
    metadata = adapter_metadata(SOURCE, payload)

    if event_name == "UserPromptSubmit":
        prompt = as_text(payload.get("prompt")).strip()
        record_turn(
            _root(),
            session_id=session_id,
            role="user",
            content=prompt,
            source=SOURCE,
            event_type="claude_code_user_prompt",
            metadata=metadata,
        )
        packet = compile_context_packet(
            _root(),
            session_id=session_id,
            query=prompt,
            token_budget=_token_budget(),
        )
        return _additional_context(event_name, packet)

    if event_name == "SessionStart":
        query = f"Claude Code session start: {payload.get('source', 'startup')}"
        packet = compile_context_packet(
            _root(),
            session_id=session_id,
            query=query,
            token_budget=_token_budget(),
        )
        return _additional_context(event_name, packet)

    if event_name == "Stop":
        record_turn(
            _root(),
            session_id=session_id,
            role="assistant",
            content=payload.get("last_assistant_message"),
            source=SOURCE,
            event_type="claude_code_assistant_turn",
            metadata=metadata,
        )
        return None

    return None


def main() -> int:
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        result = handle_hook(payload if isinstance(payload, dict) else {})
        if result:
            print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except Exception as exc:
        _log_error(exc, phase="hook_main")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

