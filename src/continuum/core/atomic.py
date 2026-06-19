from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

from .permissions import secure_write_text


def yaml_scalar(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("atomic YAML cannot encode NaN or infinite floats")
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


def _parse_scalar(raw: str) -> Any:
    text = raw.strip()
    if text == "null":
        return None
    if text == "true":
        return True
    if text == "false":
        return False
    if text == "{}":
        return {}
    if text == "[]":
        return []
    if text.startswith('"') or text.startswith("'"):
        return json.loads(text)
    try:
        if any(char in text for char in ".eE"):
            number = float(text)
            if not math.isfinite(number):
                raise ValueError("atomic YAML cannot decode NaN or infinite floats")
            return number
        return int(text)
    except ValueError:
        return text


def _parse_key(raw: str) -> str:
    text = raw.strip()
    if text.startswith('"') or text.startswith("'"):
        return str(json.loads(text))
    return text


def _yaml_lines(text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        lines.append((indent, line.strip()))
    return lines


def _parse_block(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[Any, int]:
    if index >= len(lines):
        return {}, index
    current_indent, current = lines[index]
    if current_indent < indent:
        return {}, index
    if current.startswith("-"):
        items: list[Any] = []
        while index < len(lines):
            line_indent, content = lines[index]
            if line_indent != indent or not content.startswith("-"):
                break
            item_text = content[1:].strip()
            index += 1
            if item_text:
                items.append(_parse_scalar(item_text))
            else:
                item, index = _parse_block(lines, index, indent + 2)
                items.append(item)
        return items, index

    mapping: dict[str, Any] = {}
    while index < len(lines):
        line_indent, content = lines[index]
        if line_indent != indent or content.startswith("-"):
            break
        if ":" not in content:
            raise ValueError(f"invalid atomic YAML line: {content!r}")
        key_text, value_text = content.split(":", 1)
        key = _parse_key(key_text)
        value_text = value_text.strip()
        index += 1
        if value_text:
            mapping[key] = _parse_scalar(value_text)
        else:
            value, index = _parse_block(lines, index, indent + 2)
            mapping[key] = value
    return mapping, index


def load_atomic_yaml(text: str) -> Any:
    """Parse the small deterministic YAML subset emitted by ``dump_yaml``."""
    lines = _yaml_lines(text)
    if not lines:
        return {}
    result, index = _parse_block(lines, 0, lines[0][0])
    if index != len(lines):
        raise ValueError("invalid trailing atomic YAML content")
    return result


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
