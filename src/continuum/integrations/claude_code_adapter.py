from __future__ import annotations

import json
import math
import os
import sys
import traceback
from pathlib import Path
from typing import Any

from continuum.core.store import utc_now
from continuum.integrations.common import (
    DEFAULT_TOKEN_BUDGET,
    MAX_CAPTURE_TURN_UTF8_BYTES,
    adapter_metadata,
    append_adapter_log,
    as_text,
    compile_context_packet,
    default_continuum_root,
    record_turn,
    session_id_from_payload,
)


SOURCE = "claude_code"
MAX_HOOK_STDIN_BYTES = 1024 * 1024
MAX_HOOK_JSON_DEPTH = 32
MAX_HOOK_JSON_NODES = 10_000


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate hook JSON key")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite hook JSON number: {value}")


def _read_hook_payload() -> dict[str, Any]:
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    frame = stream.read(MAX_HOOK_STDIN_BYTES + 1)
    if isinstance(frame, str):
        frame = frame.encode("utf-8")
    if len(frame) > MAX_HOOK_STDIN_BYTES:
        raise ValueError("hook event exceeds byte limit")
    payload = json.loads(
        frame.decode("utf-8") or "{}",
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_nonfinite,
    )
    if not isinstance(payload, dict):
        return {}
    nodes = 0
    pending: list[tuple[Any, int]] = [(payload, 1)]
    while pending:
        value, depth = pending.pop()
        nodes += 1
        if nodes > MAX_HOOK_JSON_NODES or depth > MAX_HOOK_JSON_DEPTH:
            raise ValueError("hook event exceeds JSON structure limit")
        if isinstance(value, dict):
            pending.extend((child, depth + 1) for child in value.values())
        elif isinstance(value, list):
            pending.extend((child, depth + 1) for child in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise ValueError("non-finite hook JSON number")
    return payload


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
        payload = {
            "created_at": utc_now(),
            "phase": phase,
            "error": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc(limit=8),
        }
        append_adapter_log(log_path, payload)
    except (OSError, ValueError):
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
        if len(prompt.encode("utf-8")) > MAX_CAPTURE_TURN_UTF8_BYTES:
            return None
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
        result = handle_hook(_read_hook_payload())
        if result:
            print(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except Exception as exc:
        _log_error(exc, phase="hook_main")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

