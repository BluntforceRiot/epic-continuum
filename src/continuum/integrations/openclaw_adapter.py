from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from continuum.core.store import compile_context, utc_now
from continuum.integrations.common import DEFAULT_TOKEN_BUDGET, as_text


def build_openclaw_mission_card(
    root: Path | str,
    *,
    session_id: str,
    query: str,
    owner: str = "operator",
    gate: str = "operator approval",
    token_budget: int = DEFAULT_TOKEN_BUDGET,
) -> dict[str, Any]:
    context = compile_context(
        Path(root),
        session_id=session_id,
        token_budget=int(token_budget),
        query=as_text(query).strip() or None,
    )
    fingerprint = hashlib.sha256(
        f"{session_id}\n{query}\n{context.get('estimated_tokens')}".encode("utf-8")
    ).hexdigest()[:16]
    return {
        "schema": "epic_continuum.openclaw_mission_card.v1",
        "mission_id": f"continuum-{fingerprint}",
        "created_at": utc_now(),
        "decision": "review_only_context_handoff",
        "evidence": [
            "Epic Continuum Scroll/Card context compiled from durable local state.",
            f"session_id={session_id}",
            f"estimated_tokens={context.get('estimated_tokens')}",
        ],
        "next_action": "Use the attached Looking Glass context to plan or stress-review the mission; do not mutate systems without the gate.",
        "owner": owner,
        "gate": gate,
        "proof_boundary": "This card is advisory context. Execution remains outside Epic Continuum unless a separate tool call writes a receipt.",
        "continuum": {
            "session_id": session_id,
            "token_budget": context.get("token_budget"),
            "estimated_tokens": context.get("estimated_tokens"),
            "context_text": context.get("context_text", ""),
        },
    }

