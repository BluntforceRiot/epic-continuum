from __future__ import annotations

from pathlib import Path
from typing import Any

from continuum.integrations.common import (
    DEFAULT_TOKEN_BUDGET,
    adapter_metadata,
    attach_openai_context_message,
    compile_context_packet,
    latest_user_message,
    record_turn,
)


def prepare_chat_request(
    root: Path | str | None,
    *,
    session_id: str,
    request: dict[str, Any],
    source: str = "openai_compatible",
    token_budget: int = DEFAULT_TOKEN_BUDGET,
    record_user: bool = True,
) -> dict[str, Any]:
    messages = request.get("messages")
    if not isinstance(messages, list):
        raise ValueError("request must contain a messages list")

    typed_messages = [message for message in messages if isinstance(message, dict)]
    query = latest_user_message(typed_messages)
    if record_user and query:
        record_turn(
            root,
            session_id=session_id,
            role="user",
            content=query,
            source=source,
            metadata=adapter_metadata(source, {"model": request.get("model")}),
        )

    packet = compile_context_packet(
        root,
        session_id=session_id,
        query=query,
        token_budget=token_budget,
    )
    wrapped = dict(request)
    wrapped["messages"] = attach_openai_context_message(typed_messages, packet)
    return wrapped


def record_chat_response(
    root: Path | str | None,
    *,
    session_id: str,
    response: dict[str, Any],
    source: str = "openai_compatible",
) -> dict[str, Any] | None:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    first = choices[0]
    if not isinstance(first, dict):
        return None
    message = first.get("message")
    content = message.get("content") if isinstance(message, dict) else first.get("text")
    return record_turn(
        root,
        session_id=session_id,
        role="assistant",
        content=content,
        source=source,
        metadata=adapter_metadata(source, {"model": response.get("model")}),
    )
