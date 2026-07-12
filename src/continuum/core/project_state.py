from __future__ import annotations

import json
import math
from typing import Any


MAX_PROJECT_STATE_BYTES = 12 * 1024
MAX_PROJECT_STATE_OBJECTIVE_BYTES = 4 * 1024
MAX_PROJECT_STATE_NOTES_BYTES = 8 * 1024
MAX_PROJECT_STATE_REPO_PATH_BYTES = 4 * 1024
MAX_PROJECT_STATE_BRANCH_BYTES = 512
MAX_PROJECT_STATE_COMMIT_BYTES = 256
MAX_PROJECT_STATE_DECISIONS = 64
MAX_PROJECT_STATE_OPEN_TASKS = 64
MAX_PROJECT_STATE_CHANGED_FILES = 256
MAX_PROJECT_STATE_ITEM_BYTES = 2 * 1024
MAX_PROJECT_STATE_CHANGED_FILE_BYTES = 1024
MAX_PROJECT_STATE_METADATA_BYTES = 8 * 1024
MAX_STORED_PROJECT_STATE_METADATA_BYTES = 12 * 1024
MAX_PROJECT_STATE_METADATA_DEPTH = 8
MAX_PROJECT_STATE_METADATA_MEMBERS = 128
MAX_PROJECT_STATE_METADATA_CONTAINER_MEMBERS = 64
# Stored checkpoint metadata includes a small, fixed set of Continuum-owned
# provenance and integrity fields in addition to the caller's schema-limited
# object. Keep that reserve explicit and bounded.
MAX_STORED_PROJECT_STATE_METADATA_MEMBERS = 160
MAX_STORED_PROJECT_STATE_METADATA_CONTAINER_MEMBERS = 80
MAX_PROJECT_STATE_METADATA_KEY_BYTES = 128
MAX_PROJECT_STATE_METADATA_STRING_BYTES = 2 * 1024
MAX_PROJECT_STATE_TITLE_BYTES = 512
PROJECT_STATE_RESERVED_METADATA_KEYS = frozenset(
    {
        "conflict_group",
        "conflict_resolution_id",
        "conflict_resolution_members",
        "conflict_resolution_receipt_id",
        "conflict_resolution_receipts",
        "dismissed_conflict_components",
        "superseded_by_card_id",
        "supersedes_card_id",
    }
)
# Stored checkpoints deliberately retain both immutable Scroll evidence and
# structured Card fields. Keep their bounded materialization envelope wider
# than the caller acceptance cap so every accepted checkpoint can be resumed.
MAX_STORED_PROJECT_STATE_BYTES = 48 * 1024


def _utf8_size(value: str) -> int:
    return len(value.encode("utf-8", errors="strict"))


def _validate_optional_text(value: Any, *, field: str, maximum: int) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string when provided")
    size = _utf8_size(value)
    if size > maximum:
        raise ValueError(f"{field} exceeds maximum of {maximum} UTF-8 bytes")


def _validate_string_list(
    value: Any,
    *,
    field: str,
    maximum_items: int,
    maximum_item_bytes: int,
) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a list of strings")
    if len(value) > maximum_items:
        raise ValueError(f"{field} exceeds maximum of {maximum_items} items")
    for index, item in enumerate(value):
        if _utf8_size(item) > maximum_item_bytes:
            raise ValueError(
                f"{field}[{index}] exceeds maximum of {maximum_item_bytes} UTF-8 bytes"
            )
    return list(value)


def validate_project_state_metadata(
    value: Any,
    *,
    enriched: bool = False,
) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("metadata must be an object")
    if not enriched:
        reserved = sorted(
            str(key)
            for key in value
            if isinstance(key, str)
            and key.casefold() in PROJECT_STATE_RESERVED_METADATA_KEYS
        )
        if reserved:
            raise ValueError(
                "metadata contains Continuum-reserved temporal field(s): "
                + ", ".join(reserved)
            )

    maximum_members = (
        MAX_STORED_PROJECT_STATE_METADATA_MEMBERS
        if enriched
        else MAX_PROJECT_STATE_METADATA_MEMBERS
    )
    maximum_container_members = (
        MAX_STORED_PROJECT_STATE_METADATA_CONTAINER_MEMBERS
        if enriched
        else MAX_PROJECT_STATE_METADATA_CONTAINER_MEMBERS
    )
    members = 0
    stack: list[tuple[Any, int, frozenset[int]]] = [(value, 1, frozenset())]
    while stack:
        current, depth, ancestors = stack.pop()
        if depth > MAX_PROJECT_STATE_METADATA_DEPTH:
            raise ValueError(
                f"metadata exceeds maximum depth of {MAX_PROJECT_STATE_METADATA_DEPTH}"
            )
        if isinstance(current, (dict, list)):
            identity = id(current)
            if identity in ancestors:
                raise ValueError("metadata must not contain cycles")
            next_ancestors = ancestors | {identity}
            if len(current) > maximum_container_members:
                raise ValueError(
                    "metadata container exceeds maximum of "
                    f"{maximum_container_members} members"
                )
            members += len(current)
            if members > maximum_members:
                raise ValueError(
                    f"metadata exceeds maximum of {maximum_members} total members"
                )
            if isinstance(current, dict):
                for key, child in current.items():
                    if not isinstance(key, str):
                        raise ValueError("metadata object keys must be strings")
                    if _utf8_size(key) > MAX_PROJECT_STATE_METADATA_KEY_BYTES:
                        raise ValueError(
                            "metadata key exceeds maximum of "
                            f"{MAX_PROJECT_STATE_METADATA_KEY_BYTES} UTF-8 bytes"
                        )
                    stack.append((child, depth + 1, next_ancestors))
            else:
                for child in current:
                    stack.append((child, depth + 1, next_ancestors))
            continue
        if isinstance(current, str):
            if _utf8_size(current) > MAX_PROJECT_STATE_METADATA_STRING_BYTES:
                raise ValueError(
                    "metadata string exceeds maximum of "
                    f"{MAX_PROJECT_STATE_METADATA_STRING_BYTES} UTF-8 bytes"
                )
        elif current is None or isinstance(current, bool):
            continue
        elif isinstance(current, int):
            if current.bit_length() > 256:
                raise ValueError("metadata integer exceeds 256-bit limit")
        elif isinstance(current, float):
            if not math.isfinite(current):
                raise ValueError("metadata numbers must be finite")
        else:
            raise ValueError(f"metadata contains unsupported value type: {type(current).__name__}")

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise ValueError("metadata must be a finite JSON object") from exc
    maximum_metadata_bytes = (
        MAX_STORED_PROJECT_STATE_METADATA_BYTES
        if enriched
        else MAX_PROJECT_STATE_METADATA_BYTES
    )
    if len(encoded) > maximum_metadata_bytes:
        raise ValueError(
            f"metadata exceeds maximum of {maximum_metadata_bytes} serialized bytes"
        )
    return dict(value)


def validate_project_state_input(
    *,
    session_id: Any,
    agent_id: Any,
    project_id: Any,
    objective: Any = None,
    repo_path: Any = None,
    branch: Any = None,
    commit: Any = None,
    dirty: Any = None,
    changed_files: Any = None,
    decisions: Any = None,
    open_tasks: Any = None,
    notes: Any = None,
    metadata: Any = None,
    metadata_is_enriched: bool = False,
) -> dict[str, Any]:
    for field, value in (
        ("session_id", session_id),
        ("agent_id", agent_id),
        ("project_id", project_id),
    ):
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field} must be a non-empty string")
    _validate_optional_text(
        objective,
        field="objective",
        maximum=MAX_PROJECT_STATE_OBJECTIVE_BYTES,
    )
    _validate_optional_text(
        repo_path,
        field="repo_path",
        maximum=MAX_PROJECT_STATE_REPO_PATH_BYTES,
    )
    _validate_optional_text(
        branch,
        field="branch",
        maximum=MAX_PROJECT_STATE_BRANCH_BYTES,
    )
    _validate_optional_text(
        commit,
        field="commit",
        maximum=MAX_PROJECT_STATE_COMMIT_BYTES,
    )
    _validate_optional_text(notes, field="notes", maximum=MAX_PROJECT_STATE_NOTES_BYTES)
    if dirty is not None and not isinstance(dirty, bool):
        raise ValueError("dirty must be a boolean when provided")
    normalized_changed_files = _validate_string_list(
        changed_files,
        field="changed_files",
        maximum_items=MAX_PROJECT_STATE_CHANGED_FILES,
        maximum_item_bytes=MAX_PROJECT_STATE_CHANGED_FILE_BYTES,
    )
    normalized_decisions = _validate_string_list(
        decisions,
        field="decisions",
        maximum_items=MAX_PROJECT_STATE_DECISIONS,
        maximum_item_bytes=MAX_PROJECT_STATE_ITEM_BYTES,
    )
    normalized_open_tasks = _validate_string_list(
        open_tasks,
        field="open_tasks",
        maximum_items=MAX_PROJECT_STATE_OPEN_TASKS,
        maximum_item_bytes=MAX_PROJECT_STATE_ITEM_BYTES,
    )
    normalized_metadata = validate_project_state_metadata(
        metadata,
        enriched=metadata_is_enriched,
    )
    payload = {
        "agent_id": agent_id,
        "branch": branch,
        "changed_files": normalized_changed_files,
        "commit": commit,
        "decisions": normalized_decisions,
        "dirty": dirty,
        "metadata": normalized_metadata,
        "notes": notes,
        "objective": objective,
        "open_tasks": normalized_open_tasks,
        "project_id": project_id,
        "repo_path": repo_path,
        "session_id": session_id,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    maximum_payload_bytes = (
        MAX_STORED_PROJECT_STATE_BYTES
        if metadata_is_enriched
        else MAX_PROJECT_STATE_BYTES
    )
    if len(encoded) > maximum_payload_bytes:
        raise ValueError(
            f"project state exceeds maximum of {maximum_payload_bytes} serialized bytes"
        )
    return {
        **payload,
        "serialized_bytes": len(encoded),
    }


def stored_project_state_limit_error(
    *,
    summary: Any,
    decisions: Any,
    open_tasks: Any,
    metadata: Any,
    source_content: Any = None,
) -> str | None:
    try:
        _validate_optional_text(
            summary,
            field="summary",
            maximum=MAX_PROJECT_STATE_NOTES_BYTES,
        )
        normalized_decisions = _validate_string_list(
            decisions,
            field="decisions",
            maximum_items=MAX_PROJECT_STATE_DECISIONS,
            maximum_item_bytes=MAX_PROJECT_STATE_ITEM_BYTES,
        )
        normalized_open_tasks = _validate_string_list(
            open_tasks,
            field="open_tasks",
            maximum_items=MAX_PROJECT_STATE_OPEN_TASKS,
            maximum_item_bytes=MAX_PROJECT_STATE_ITEM_BYTES,
        )
        normalized_metadata = validate_project_state_metadata(
            metadata,
            enriched=True,
        )
        _validate_optional_text(
            source_content,
            field="source_content",
            maximum=MAX_STORED_PROJECT_STATE_BYTES,
        )
        encoded = json.dumps(
            {
                "decisions": normalized_decisions,
                "metadata": normalized_metadata,
                "open_tasks": normalized_open_tasks,
                "source_content": source_content,
                "summary": summary,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded) > MAX_STORED_PROJECT_STATE_BYTES:
            raise ValueError(
                "stored project state exceeds maximum of "
                f"{MAX_STORED_PROJECT_STATE_BYTES} serialized bytes"
            )
    except (TypeError, ValueError, RecursionError) as exc:
        return str(exc)
    return None
