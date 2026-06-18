from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .permissions import secure_write_text


def yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=True)


def yaml_key(key: str) -> str:
    if key.replace("_", "").replace("-", "").isalnum() and key[:1].isalpha():
        return key
    return json.dumps(key, ensure_ascii=True)


def dump_yaml(value: Any, indent: int = 0) -> str:
    prefix = " " * indent
    if isinstance(value, dict):
        if not value:
            return f"{prefix}{{}}"
        lines: list[str] = []
        for key, item in value.items():
            rendered_key = yaml_key(str(key))
            if isinstance(item, (dict, list)) and item:
                lines.append(f"{prefix}{rendered_key}:")
                lines.append(dump_yaml(item, indent + 2))
            elif isinstance(item, (dict, list)):
                lines.append(f"{prefix}{rendered_key}: {dump_yaml(item, 0)}")
            else:
                lines.append(f"{prefix}{rendered_key}: {yaml_scalar(item)}")
        return "\n".join(lines)
    if isinstance(value, list):
        if not value:
            return f"{prefix}[]"
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}-")
                lines.append(dump_yaml(item, indent + 2))
            else:
                lines.append(f"{prefix}- {yaml_scalar(item)}")
        return "\n".join(lines)
    return f"{prefix}{yaml_scalar(value)}"


def write_atomic_yaml(path: Path, payload: dict[str, Any]) -> None:
    text = dump_yaml(payload).rstrip() + "\n"
    secure_write_text(path, text)


def atomic_memory_card(
    *,
    card_id: str,
    card_type: str,
    title: str,
    summary: str,
    source_refs: list[dict[str, Any]],
    entities: list[str],
    topics: list[str],
    decisions: list[str],
    open_tasks: list[str],
    salience: float,
    confidence: float,
    metadata: dict[str, Any],
    created_at: str,
    updated_at: str,
    summary_hash: str,
) -> dict[str, Any]:
    return {
        "schema": "continuum.atomic_memory.v1",
        "kind": "card",
        "card_id": card_id,
        "id": card_id,
        "card_type": card_type,
        "title": title,
        "summary": summary,
        "summary_hash": summary_hash,
        "status": "pending_librarian_review",
        "source_refs": source_refs,
        "entities": entities,
        "topics": topics,
        "decisions": decisions,
        "open_tasks": open_tasks,
        "salience": salience,
        "confidence": confidence,
        "metadata": metadata,
        "created_at": created_at,
        "updated_at": updated_at,
    }
