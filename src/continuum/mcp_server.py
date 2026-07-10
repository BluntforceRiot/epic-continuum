from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any, Callable, overload

from . import __version__
from .core.bundle import pack_root, verify_root_bundle
from .core.config import config_path, default_config, load_config, optimize_config, write_default_config
from .core.evals import run_memory_quality_evals
from .core.hardware import PROFILES
from .core.mempalace_import import default_mempalace_path, import_mempalace
from .core.safety import redact_text_secrets, scan_text_for_secrets
from .core.operations import (
    OperationGuard,
    doctor,
    list_operations,
    operation_summary,
    recover_stale_operations,
    recovery_drill,
    repair_permissions,
    replay_operation_event_log,
    restore_drill,
    verify_root,
    verify_proof_pack,
)
from .core.review_bridge import (
    DEFAULT_REVIEW_BASE_URL,
    DEFAULT_REVIEW_MODEL,
    DEFAULT_REVIEW_TRANSPORT,
    SUPPORTED_TRANSPORTS,
    create_review_job,
    ingest_review_result,
    review_browser_attempt_start,
    review_check_current,
    review_job_status,
    run_review_job,
)
from .core.store import (
    append_scroll_event,
    audit,
    audit_search_index,
    audit_secrets,
    compile_context,
    cue_recall,
    ingest_file,
    init_db,
    recover_thread,
    record_project_state,
    rebuild_search_index,
    redact_legacy_secrets,
    reindex_memory,
    roll_scroll_segment,
    search_memory,
    snapshot,
    source_file_reference,
    status,
    canonical_partition_identifier,
    validate_partition_identifier,
)
from .core.workers import (
    apply_storage_tiering,
    decay_graph_routes,
    detect_conflicts,
    memory_health,
    prune_memory,
    run_worker_pass,
)


JSON = dict[str, Any]
ToolHandler = Callable[[JSON], Any]
PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = (PROTOCOL_VERSION,)


def default_root() -> Path:
    env_root = os.environ.get("CONTINUUM_ROOT")
    if env_root:
        return Path(env_root)
    return Path.home() / ".continuum"


def env_truthy(name: str) -> bool:
    return str(os.environ.get(name) or "").casefold() in {"1", "true", "yes", "on"}


def _split_env_paths(value: str) -> list[Path]:
    paths: list[Path] = []
    for raw in value.replace("\n", os.pathsep).split(os.pathsep):
        raw = raw.strip().strip('"')
        if raw:
            paths.append(Path(raw))
    return paths


def allowed_roots() -> list[Path]:
    roots = [default_root()]
    extra = os.environ.get("CONTINUUM_ALLOWED_ROOTS")
    if extra:
        roots.extend(_split_env_paths(extra))
    return roots


def path_is_within(path: Path, parent: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(parent.resolve(strict=False))
        return True
    except (OSError, ValueError):
        return False


def validate_allowed_path(path: Path, *, purpose: str) -> Path:
    if env_truthy("CONTINUUM_MCP_ALLOW_ANY_PATH"):
        return path
    roots = allowed_roots()
    if any(path_is_within(path, root) for root in roots):
        return path
    allowed = ", ".join(str(root) for root in roots)
    raise ValueError(
        f"{purpose} path is outside this MCP server's allowed roots: {path}. "
        f"Allowed roots: {allowed or '(none)'}. Set CONTINUUM_ROOT or CONTINUUM_ALLOWED_ROOTS to include it."
    )


def root_arg(args: JSON) -> Path:
    raw = args.get("root")
    if raw is None or raw == "":
        return validate_allowed_path(default_root(), purpose="root")
    if not isinstance(raw, str):
        raise ValueError("root must be a string path")
    return validate_allowed_path(Path(raw), purpose="root")


def file_arg(args: JSON, key: str, *, purpose: str) -> Path:
    return validate_allowed_path(Path(require_str(args, key)), purpose=purpose)


def require_str(args: JSON, key: str) -> str:
    value = args.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} must be a non-empty string")
    return value


def optional_str(args: JSON, key: str) -> str | None:
    value = args.get(key)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"{key} must be a string")
    return value


def optional_str_list(args: JSON, key: str) -> list[str]:
    value = args.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{key} must be a list of non-empty strings")
    return value


@overload
def optional_int(args: JSON, key: str, default: int) -> int: ...


@overload
def optional_int(args: JSON, key: str, default: None) -> int | None: ...


def optional_int(args: JSON, key: str, default: int | None) -> int | None:
    value = args.get(key, default)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{key} must be an integer")
    return value


def optional_bool(args: JSON, key: str, default: bool = False) -> bool:
    value = args.get(key, default)
    if not isinstance(value, bool):
        raise ValueError(f"{key} must be a boolean")
    return value


def optional_metadata(args: JSON) -> JSON | None:
    value = args.get("metadata")
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("metadata must be an object")
    return value


PUBLIC_METADATA_FORBIDDEN_FRAGMENTS = (
    "authority",
    "exact_memory",
    "explicit_memory",
    "protect",
    "trust",
)
PUBLIC_METADATA_FORBIDDEN_KEYS = {"session_id", "project_id", "visibility_scope"}


def public_metadata(args: JSON, *, disable_exact_memory: bool = False) -> JSON:
    metadata = dict(optional_metadata(args) or {})
    for key in list(metadata):
        normalized = key.casefold()
        if normalized in PUBLIC_METADATA_FORBIDDEN_KEYS:
            raise ValueError(f"metadata.{key} is not accepted; pass partition fields as top-level tool arguments")
        if normalized == "continuum_disable_exact_memory" or any(fragment in normalized for fragment in PUBLIC_METADATA_FORBIDDEN_FRAGMENTS):
            metadata.pop(key, None)
    if disable_exact_memory:
        metadata["continuum_disable_exact_memory"] = True
    return metadata


def validate_public_partition_arg(root: Path, kind: str, value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value)
    if scan_text_for_secrets(text, max_findings=1):
        security = (load_config(root) if config_path(root).exists() else default_config()).get("security", {})
        if bool(security.get("secret_scan_enabled", True)) and str(security.get("secret_scan_action") or "block") == "block":
            raise ValueError(f"secret scan blocked {kind} before operation receipt")
        return text
    if canonical_partition_identifier(root, kind, text, lookup=True) != text:
        return text
    clean = validate_partition_identifier(kind, text)
    return clean


def public_partition_label(value: str | None) -> str | None:
    if value is None:
        return None
    return redact_text_secrets(value) if scan_text_for_secrets(value, max_findings=1) else value


def tool_result(value: Any, *, is_error: bool = False) -> JSON:
    structured = value if isinstance(value, dict) else {"result": value}
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True),
            }
        ],
        "structuredContent": structured,
        "isError": is_error,
    }


def negotiated_protocol_version(params: JSON | None) -> str:
    requested = params.get("protocolVersion") if isinstance(params, dict) else None
    return requested if requested in SUPPORTED_PROTOCOL_VERSIONS else PROTOCOL_VERSION


def guarded_tool(
    root: Path,
    *,
    operation_type: str,
    title: str,
    intent: JSON | None = None,
    snapshot_policy: str = "none",
    snapshot_reason: str | None = None,
    touched_paths: list[Path | str] | None = None,
    result_touched_paths: Callable[[Any], list[Path | str]] | None = None,
    proof: bool = True,
    catalog_proof_mode: str | None = None,
    action: Callable[[OperationGuard], Any],
) -> Any:
    with OperationGuard(
        root,
        operation_type=operation_type,
        title=title,
        intent=intent,
        actor=f"mcp:{operation_type}",
        snapshot_policy=snapshot_policy,
        snapshot_reason=snapshot_reason,
        touched_paths=touched_paths,
        proof=proof,
        catalog_proof_mode=catalog_proof_mode,
    ) as operation:
        result = action(operation)
        extra_paths = result_touched_paths(result) if result_touched_paths else []
        operation.succeed(result if isinstance(result, dict) else {"result": result}, touched_paths=extra_paths)
        return operation.wrap_result(result)


def tool_init(args: JSON) -> Any:
    root = root_arg(args)
    def action(operation: OperationGuard) -> JSON:
        init_db(root)
        operation.cursor({"phase": "initialized", "root": str(root)})
        return {"ok": True, "root": str(root)}

    return guarded_tool(
        root,
        operation_type="mcp_init",
        title="Initialize Epic Continuum root",
        intent={"root": str(root)},
        snapshot_policy="none",
        snapshot_reason="new root initialization",
        touched_paths=[root / "catalog" / "catalog.sqlite3", config_path(root)],
        action=action,
    )


def tool_status(args: JSON) -> Any:
    return status(root_arg(args), create=False)


def tool_config(args: JSON) -> Any:
    root = root_arg(args)
    def action(operation: OperationGuard) -> JSON:
        write_default_config(root)
        operation.cursor({"phase": "config_written", "config_path": str(config_path(root))})
        return load_config(root)

    return guarded_tool(
        root,
        operation_type="mcp_config",
        title="Create or show Epic Continuum config",
        intent={"root": str(root)},
        snapshot_policy="none",
        snapshot_reason="config bootstrap is reversible from defaults",
        touched_paths=[config_path(root)],
        action=action,
    )


def tool_optimize_config(args: JSON) -> Any:
    profile = optional_str(args, "profile") or "balanced"
    if profile not in PROFILES:
        raise ValueError(f"profile must be one of: {', '.join(sorted(PROFILES))}")
    root = root_arg(args)
    write = optional_bool(args, "write")

    def action(operation: OperationGuard) -> JSON:
        result = optimize_config(
            root,
            profile=profile,
            write=write,
            vram=optional_str(args, "vram"),
            system_ram=optional_str(args, "system_ram"),
            drive_free=optional_str(args, "drive_free"),
        )
        operation.cursor({"phase": "optimized_config", "wrote": result["wrote"], "config_path": result["config_path"]})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_optimize_config",
        title="Optimize Epic Continuum hardware config",
        intent={"profile": profile, "write": write},
        snapshot_policy="none",
        snapshot_reason="config recommendation/write uses proof pack hash",
        touched_paths=[config_path(root)],
        action=action,
    )


def tool_append_event(args: JSON) -> Any:
    root = root_arg(args)
    session_id = str(validate_public_partition_arg(root, "session_id", require_str(args, "session_id")))
    safe_session_id = public_partition_label(session_id)
    event_type = optional_str(args, "event_type") or "message"
    role = optional_str(args, "role") or "agent"
    content = require_str(args, "content")
    # Public MCP callers control metadata, so trust/authority/protection and
    # exact-memory elevation fields are never accepted from generic tools.
    metadata = public_metadata(args, disable_exact_memory=True)

    def action(operation: OperationGuard) -> JSON:
        result = append_scroll_event(
            root,
            session_id=session_id,
            event_type=event_type,
            role=role,
            content=content,
            metadata=metadata,
        )
        operation.cursor({"phase": "event_appended", "session_id": result["session_id"], "seq": result["seq"]})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_append_event",
        title=f"Append Scroll event for {safe_session_id}",
        intent={"session_id": safe_session_id, "event_type": event_type, "role": role},
        snapshot_policy="none",
        snapshot_reason="append-only Scroll event",
        touched_paths=[root / "catalog" / "catalog.sqlite3"],
        proof=False,
        action=action,
    )


def tool_roll_segment(args: JSON) -> Any:
    root = root_arg(args)
    session_id = str(validate_public_partition_arg(root, "session_id", require_str(args, "session_id")))
    safe_session_id = public_partition_label(session_id)
    start_seq = optional_int(args, "start_seq", 1)
    end_seq = optional_int(args, "end_seq", 1)
    if start_seq < 1 or end_seq < start_seq:
        raise ValueError("start_seq must be >= 1 and end_seq must be >= start_seq")

    def action(operation: OperationGuard) -> JSON:
        operation.cursor({"phase": "before_roll", "session_id": safe_session_id, "start_seq": start_seq, "end_seq": end_seq})
        result = roll_scroll_segment(root, session_id=session_id, start_seq=start_seq, end_seq=end_seq)
        operation.cursor({"phase": "segment_rolled", "segment_id": result["segment_id"], "card_id": result["card_id"]})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_roll_segment",
        title=f"Roll Scroll segment {safe_session_id}:{start_seq}-{end_seq}",
        intent={"session_id": safe_session_id, "start_seq": start_seq, "end_seq": end_seq},
        snapshot_policy="auto",
        snapshot_reason="roll segment mutates catalog/cards/graph",
        touched_paths=[root / "catalog" / "catalog.sqlite3"],
        result_touched_paths=lambda result: [result["card_uri"]] if result.get("card_uri") else [],
        action=action,
    )


def tool_ingest_file(args: JSON) -> Any:
    root = root_arg(args)
    source_path = file_arg(args, "path", purpose="ingest source")
    title = optional_str(args, "title")
    storage_tier = optional_str(args, "storage_tier") or "hot"
    source_ref = source_file_reference(root, source_path)

    def action(operation: OperationGuard) -> JSON:
        operation.cursor({"phase": "before_ingest", "source": source_ref, "storage_tier": storage_tier})
        result = ingest_file(root, path=source_path, title=title, storage_tier=storage_tier)
        operation.cursor({"phase": "file_ingested", "book_id": result["book_id"], "card_id": result["card_id"]})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_ingest_file",
        title=f"Ingest file {source_ref['name']}",
        intent={"source": source_ref, "title": title, "storage_tier": storage_tier},
        snapshot_policy="auto",
        snapshot_reason="file ingest mutates Library/catalog",
        touched_paths=[root / "catalog" / "catalog.sqlite3"],
        result_touched_paths=lambda result: [
            path for path in [result.get("card_uri"), result.get("original_uri"), result.get("reader_uri")] if path
        ],
        action=action,
    )


def tool_compile_context(args: JSON) -> Any:
    # Intentionally unguarded: this is a read-only context compilation.
    root = root_arg(args)
    session_id = str(validate_public_partition_arg(root, "session_id", require_str(args, "session_id")))
    project_id = validate_public_partition_arg(root, "project_id", optional_str(args, "project_id"))
    return compile_context(
        root,
        session_id=session_id,
        token_budget=optional_int(args, "token_budget", 0),
        query=optional_str(args, "query"),
        card_scope=optional_str(args, "card_scope"),
        project_id=project_id,
        include_cue_recall=optional_bool(args, "include_cue_recall"),
        cue_recall_limit=optional_int(args, "cue_recall_limit", 4),
        create=False,
    )


def tool_recover_thread(args: JSON) -> Any:
    root = root_arg(args)
    session_id = str(validate_public_partition_arg(root, "session_id", require_str(args, "session_id")))
    project_id = validate_public_partition_arg(root, "project_id", optional_str(args, "project_id"))
    safe_session_id = public_partition_label(session_id)
    safe_project_id = public_partition_label(project_id)

    def action(operation: OperationGuard) -> JSON:
        result = recover_thread(
            root,
            session_id=session_id,
            project_id=project_id,
            query=optional_str(args, "query"),
            token_budget=optional_int(args, "token_budget", 0),
            recent_event_limit=optional_int(args, "recent_event_limit", 24),
        )
        operation.cursor({"phase": "thread_recovered", "session_id": safe_session_id, "packet_uri": result["packet_uri"]})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_recover_thread",
        title=f"Recover thread {safe_session_id}",
        intent={"session_id": safe_session_id, "project_id": safe_project_id, "query": optional_str(args, "query")},
        snapshot_policy="none",
        snapshot_reason="recovery packet is an export over existing evidence",
        result_touched_paths=lambda result: [result["packet_uri"]] if result.get("packet_uri") else [],
        action=action,
    )


def tool_search(args: JSON) -> Any:
    root = root_arg(args)
    session_id = validate_public_partition_arg(root, "session_id", optional_str(args, "session_id"))
    project_id = validate_public_partition_arg(root, "project_id", optional_str(args, "project_id"))
    return search_memory(
        root,
        query=require_str(args, "query"),
        limit=optional_int(args, "limit", 10),
        session_id=session_id,
        project_id=project_id,
        create=False,
    )


def tool_cue_recall(args: JSON) -> Any:
    root = root_arg(args)
    session_id = validate_public_partition_arg(root, "session_id", optional_str(args, "session_id"))
    project_id = validate_public_partition_arg(root, "project_id", optional_str(args, "project_id"))
    return cue_recall(
        root,
        cue=require_str(args, "cue"),
        session_id=session_id,
        project_id=project_id,
        limit=optional_int(args, "limit", 8),
        max_associations=optional_int(args, "max_associations", 16),
        create=False,
    )


def tool_record_project_state(args: JSON) -> Any:
    root = root_arg(args)
    session_id = str(validate_public_partition_arg(root, "session_id", require_str(args, "session_id")))
    agent_id = str(validate_public_partition_arg(root, "agent_id", require_str(args, "agent_id")))
    project_id = str(validate_public_partition_arg(root, "project_id", require_str(args, "project_id")))
    safe_session_id = public_partition_label(session_id)
    safe_agent_id = public_partition_label(agent_id)
    safe_project_id = public_partition_label(project_id)
    dirty_value = args.get("dirty")
    if dirty_value is not None and not isinstance(dirty_value, bool):
        raise ValueError("dirty must be a boolean when provided")
    changed_files = args.get("changed_files") or []
    decisions = args.get("decisions") or []
    open_tasks = args.get("open_tasks") or []
    if not isinstance(changed_files, list) or not all(isinstance(item, str) for item in changed_files):
        raise ValueError("changed_files must be a list of strings")
    if not isinstance(decisions, list) or not all(isinstance(item, str) for item in decisions):
        raise ValueError("decisions must be a list of strings")
    if not isinstance(open_tasks, list) or not all(isinstance(item, str) for item in open_tasks):
        raise ValueError("open_tasks must be a list of strings")

    def action(operation: OperationGuard) -> JSON:
        result = record_project_state(
            root,
            session_id=session_id,
            agent_id=agent_id,
            project_id=project_id,
            objective=optional_str(args, "objective"),
            repo_path=optional_str(args, "repo_path"),
            branch=optional_str(args, "branch"),
            commit=optional_str(args, "commit"),
            dirty=dirty_value,
            changed_files=changed_files,
            decisions=decisions,
            open_tasks=open_tasks,
            notes=optional_str(args, "notes"),
            metadata=public_metadata(args, disable_exact_memory=True),
        )
        operation.cursor({"phase": "project_state_recorded", "card_id": result.get("card_id"), "project_id": safe_project_id})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_record_project_state",
        title=f"Record shared project state for {safe_project_id}",
        intent={"project_id": safe_project_id, "agent_id": safe_agent_id, "session_id": safe_session_id},
        snapshot_policy="auto",
        snapshot_reason="shared project-state checkpoint mutates Scroll/Cards/Constellation",
        touched_paths=[root / "catalog" / "catalog.sqlite3"],
        action=action,
    )


def tool_audit_search_index(args: JSON) -> Any:
    return audit_search_index(root_arg(args), create=False)


def tool_rebuild_search_index(args: JSON) -> Any:
    root = root_arg(args)

    def action(operation: OperationGuard) -> JSON:
        result = rebuild_search_index(root)
        operation.cursor(
            {
                "phase": "search_index_rebuilt",
                "chunks": result.get("chunks"),
                "fts_rows": result.get("fts_rows"),
                "ok": result.get("ok"),
            }
        )
        return result

    return guarded_tool(
        root,
        operation_type="mcp_rebuild_search_index",
        title="Rebuild Library chunk search index",
        intent={"root": str(root)},
        snapshot_policy="auto",
        snapshot_reason="search index rebuild mutates derived catalog FTS state",
        touched_paths=[root / "catalog" / "catalog.sqlite3"],
        action=action,
    )


def tool_reindex_memory(args: JSON) -> Any:
    root = root_arg(args)
    dry_run = optional_bool(args, "dry_run", True)
    promote_exact_memory = optional_bool(args, "promote_exact_memory", True)
    session_id = validate_public_partition_arg(root, "session_id", optional_str(args, "session_id"))
    after_seq = optional_int(args, "after_seq", 0)
    after_rowid = optional_int(args, "after_rowid", 0)
    limit = optional_int(args, "limit", 500)
    batch_size = optional_int(args, "batch_size", 100)
    if after_seq and not session_id:
        raise ValueError("after_seq can only be used with session_id; use after_rowid for root-wide reindex")
    safe_session_id = public_partition_label(session_id)

    def run_reindex(*, dry_run: bool) -> JSON:
        return reindex_memory(
            root,
            session_id=session_id,
            after_seq=after_seq,
            after_rowid=after_rowid,
            limit=limit,
            batch_size=batch_size,
            dry_run=dry_run,
            promote_exact_memory=promote_exact_memory,
        )

    if dry_run:
        return run_reindex(dry_run=True)

    def action(operation: OperationGuard) -> JSON:
        result = run_reindex(dry_run=False)
        operation.cursor(
            {
                "phase": "memory_reindexed",
                "processed_count": result.get("processed_count"),
                "edge_delta": result.get("edge_delta"),
                "exact_memory_cards": result.get("exact_memory_cards"),
                "next_cursor": result.get("next_cursor"),
                "has_more": result.get("has_more"),
            }
        )
        return result

    return guarded_tool(
        root,
        operation_type="mcp_reindex_memory",
        title="Reindex Epic Continuum Scroll associations",
        intent={
            "session_id": safe_session_id,
            "after_seq": after_seq,
            "after_rowid": after_rowid,
            "limit": limit,
            "batch_size": batch_size,
            "promote_exact_memory": promote_exact_memory,
        },
        snapshot_policy="auto",
        snapshot_reason="memory reindex mutates derived graph/card state",
        touched_paths=[root / "catalog" / "catalog.sqlite3"],
        action=action,
    )


def tool_audit(args: JSON) -> Any:
    # Intentionally unguarded: audit reads state and reports consistency checks.
    return audit(root_arg(args), create=False)


def tool_doctor(args: JSON) -> Any:
    entry_allowed_roots = None if env_truthy("CONTINUUM_MCP_ALLOW_ANY_PATH") else allowed_roots()
    return doctor(
        root_arg(args),
        verify_recent_proof_packs=optional_int(args, "verify_recent_proof_packs", 1),
        scan_secrets=optional_bool(args, "scan_secrets", False),
        allowed_roots=entry_allowed_roots,
    )


def tool_repair_permissions(args: JSON) -> Any:
    root = root_arg(args)

    def action(operation: OperationGuard) -> dict[str, Any]:
        result = repair_permissions(root)
        operation.cursor(
            {
                "phase": "permissions_repaired",
                "ok": result.get("ok"),
                "changed": (result.get("repair") or {}).get("changed"),
            }
        )
        return result

    return guarded_tool(
        root,
        operation_type="mcp_repair_permissions",
        title="Repair Epic Continuum private root permissions",
        intent={"root": str(root)},
        snapshot_policy="none",
        snapshot_reason="permission repair changes filesystem modes only",
        touched_paths=[root],
        action=action,
    )


def tool_audit_secrets(args: JSON) -> Any:
    return audit_secrets(
        root_arg(args),
        create=False,
        max_findings=optional_int(args, "max_findings", None),
        max_file_bytes=optional_int(args, "max_file_bytes", None),
    )


def tool_run_workers(args: JSON) -> Any:
    roles_value = args.get("roles")
    roles = roles_value if isinstance(roles_value, list) else None
    if roles is not None and not all(role in {"scribe", "librarian", "archivist"} for role in roles):
        raise ValueError("roles must contain only scribe, librarian, or archivist")
    root = root_arg(args)
    limit = optional_int(args, "limit", 50)
    maintenance = not optional_bool(args, "no_maintenance", False)

    def action(operation: OperationGuard) -> JSON:
        result = run_worker_pass(root, roles=roles, limit=limit, maintenance=maintenance)
        operation.cursor({"phase": "workers_ran", "processed_count": result.get("processed_count"), "ok": result.get("ok")})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_run_workers",
        title="Run Epic Continuum worker pass",
        intent={"roles": roles, "limit": limit, "maintenance": maintenance},
        snapshot_policy="auto",
        snapshot_reason="worker pass may mutate queue/catalog/cards/graph",
        touched_paths=[root / "catalog" / "catalog.sqlite3"],
        action=action,
    )


def tool_memory_health(args: JSON) -> Any:
    return memory_health(root_arg(args))


def tool_tier_storage(args: JSON) -> Any:
    root = root_arg(args)
    dry_run = optional_bool(args, "dry_run", False)
    limit = optional_int(args, "limit", 100)
    if dry_run:
        return apply_storage_tiering(root, dry_run=True, limit=limit)

    def action(operation: OperationGuard) -> JSON:
        result = apply_storage_tiering(root, dry_run=False, limit=limit)
        operation.cursor({"phase": "storage_tiering_applied", "action_count": result.get("action_count")})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_tier_storage",
        title="Apply Epic Continuum storage tiering",
        intent={"limit": limit},
        snapshot_policy="auto",
        snapshot_reason="storage tiering mutates catalog book metadata",
        touched_paths=[root / "catalog" / "catalog.sqlite3"],
        action=action,
    )


def tool_prune_memory(args: JSON) -> Any:
    root = root_arg(args)
    topic = optional_str(args, "topic")
    action_name = optional_str(args, "action") or "archive"
    dry_run = optional_bool(args, "dry_run", False)
    limit = optional_int(args, "limit", 100)
    allow_global = optional_bool(args, "all", False)
    if dry_run:
        return prune_memory(root, topic=topic, action=action_name, dry_run=True, limit=limit, allow_global=allow_global)

    def action(operation: OperationGuard) -> JSON:
        result = prune_memory(root, topic=topic, action=action_name, dry_run=False, limit=limit, allow_global=allow_global)
        operation.cursor({"phase": "memory_pruned", "action": result.get("action"), "card_count": result.get("card_count")})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_prune_memory",
        title="Prune Epic Continuum memory cards",
        intent={"topic": topic, "action": action_name, "limit": limit, "allow_global": allow_global},
        snapshot_policy="auto",
        snapshot_reason="pruning mutates card status/projection state",
        touched_paths=[root / "catalog" / "catalog.sqlite3"],
        catalog_proof_mode="snapshot",
        action=action,
    )


def tool_detect_conflicts(args: JSON) -> Any:
    root = root_arg(args)
    card_id = optional_str(args, "card_id")
    limit = optional_int(args, "limit", 50)

    def action(operation: OperationGuard) -> JSON:
        result = detect_conflicts(root, card_id=card_id, limit=limit)
        operation.cursor({"phase": "conflicts_detected", "conflict_count": result.get("conflict_count")})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_detect_conflicts",
        title="Detect Epic Continuum card conflicts",
        intent={"card_id": card_id, "limit": limit},
        snapshot_policy="auto",
        snapshot_reason="conflict detection may annotate cards",
        touched_paths=[root / "catalog" / "catalog.sqlite3"],
        action=action,
    )


def tool_decay_routes(args: JSON) -> Any:
    root = root_arg(args)
    limit = optional_int(args, "limit", 200)
    prune_threshold = optional_int(args, "prune_threshold", 3)

    def action(operation: OperationGuard) -> JSON:
        result = decay_graph_routes(root, limit=limit, prune_threshold=prune_threshold)
        operation.cursor({"phase": "routes_decayed", "decayed": result.get("decayed"), "pruned": result.get("pruned")})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_decay_routes",
        title="Apply Epic Continuum route decay",
        intent={"limit": limit, "prune_threshold": prune_threshold},
        snapshot_policy="auto",
        snapshot_reason="route decay mutates graph edge weights/status",
        touched_paths=[root / "catalog" / "catalog.sqlite3"],
        action=action,
    )


def tool_run_evals(args: JSON) -> Any:
    root = root_arg(args)
    keep_artifacts = optional_bool(args, "keep_artifacts", False)

    def action(operation: OperationGuard) -> JSON:
        result = run_memory_quality_evals(root, keep_artifacts=keep_artifacts)
        operation.cursor({"phase": "evals_ran", "eval_id": result.get("eval_id"), "ok": result.get("ok")})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_run_evals",
        title="Run Epic Continuum memory quality evals",
        intent={"keep_artifacts": keep_artifacts},
        snapshot_policy="none",
        snapshot_reason="evals use disposable nested roots",
        touched_paths=[root / "catalog" / "catalog.sqlite3"],
        result_touched_paths=lambda result: [result["eval_root"]] if result.get("eval_root") and not result.get("eval_root_removed") else [],
        action=action,
    )


def tool_verify_proof_pack(args: JSON) -> Any:
    proof_path = validate_allowed_path(Path(require_str(args, "path")), purpose="proof pack")
    root = optional_str(args, "root")
    verification_root = validate_allowed_path(Path(root), purpose="verification root") if root else None
    entry_allowed_roots = None if env_truthy("CONTINUUM_MCP_ALLOW_ANY_PATH") else allowed_roots()
    return verify_proof_pack(proof_path, root=verification_root, strict=True, allowed_roots=entry_allowed_roots)


def tool_verify_root(args: JSON) -> Any:
    entry_allowed_roots = None if env_truthy("CONTINUUM_MCP_ALLOW_ANY_PATH") else allowed_roots()
    return verify_root(
        root_arg(args),
        strict=optional_bool(args, "strict", True),
        verify_recent_proof_packs=optional_int(args, "verify_recent_proof_packs", 5),
        run_restore_drill=optional_bool(args, "run_restore_drill", True),
        scan_secrets=optional_bool(args, "scan_secrets", True),
        allowed_roots=entry_allowed_roots,
    )


def tool_pack_root(args: JSON) -> Any:
    root = root_arg(args)
    out_path = validate_allowed_path(Path(require_str(args, "out_path")), purpose="bundle output")
    profile = optional_str(args, "profile") or "portable"
    symlink_policy = optional_str(args, "symlink_policy") or "fail"
    return pack_root(
        root,
        out_path=out_path,
        profile=profile,
        symlink_policy=symlink_policy,
        run_restore_drill=optional_bool(args, "run_restore_drill", True),
        force=optional_bool(args, "force", False),
    )


def tool_verify_bundle(args: JSON) -> Any:
    bundle_path = validate_allowed_path(Path(require_str(args, "path")), purpose="bundle")
    return verify_root_bundle(
        bundle_path,
        verify_embedded_root=optional_bool(args, "verify_embedded_root", True),
    )


def tool_replay_operation_log(args: JSON) -> Any:
    log_path = validate_allowed_path(Path(require_str(args, "path")), purpose="operation event log")
    return replay_operation_event_log(log_path, operation_id=optional_str(args, "operation_id"))


def tool_redact_legacy_secrets(args: JSON) -> Any:
    root = root_arg(args)
    limit = optional_int(args, "limit", 500)
    apply = optional_bool(args, "apply", False)
    if not apply:
        return redact_legacy_secrets(root, dry_run=True, limit=limit)

    def action(operation: OperationGuard) -> JSON:
        result = redact_legacy_secrets(root, dry_run=False, limit=limit)
        operation.cursor({"phase": "legacy_secrets_redacted", "redaction_count": result.get("redaction_count")})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_redact_legacy_secrets",
        title="Redact legacy secret-like catalog text",
        intent={"limit": limit},
        snapshot_policy="auto",
        snapshot_reason="legacy secret cleanup mutates catalog text columns",
        touched_paths=[root / "catalog" / "catalog.sqlite3"],
        catalog_proof_mode="snapshot",
        action=action,
    )


def tool_snapshot(args: JSON) -> Any:
    root = root_arg(args)
    reason = optional_str(args, "reason") or "manual_snapshot"

    def action(operation: OperationGuard) -> JSON:
        result = snapshot(root, reason=reason)
        operation.cursor({"phase": "snapshot_created", "snapshot_uri": result["snapshot_uri"]})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_snapshot",
        title="Snapshot Epic Continuum catalog",
        intent={"reason": reason},
        snapshot_policy="none",
        snapshot_reason="snapshot command is itself the preflight protection",
        touched_paths=[root / "catalog" / "catalog.sqlite3"],
        result_touched_paths=lambda result: [
            path for path in [result.get("snapshot_uri"), result.get("card_sidecars_uri")] if path
        ],
        action=action,
    )


def tool_import_mempalace(args: JSON) -> Any:
    palace = optional_str(args, "palace_path")
    palace_path = validate_allowed_path(
        Path(palace) if palace else default_mempalace_path(),
        purpose="MemPalace source",
    )
    allow_stop = optional_bool(args, "allow_stop", False)
    if allow_stop and not env_truthy("CONTINUUM_MCP_ALLOW_PROCESS_STOP"):
        raise ValueError("allow_stop requires CONTINUUM_MCP_ALLOW_PROCESS_STOP=1 for MCP callers")
    return import_mempalace(
        root_arg(args),
        palace_path=palace_path,
        include_closets=optional_bool(args, "include_closets", True),
        include_kg=optional_bool(args, "include_kg", True),
        allow_stop=allow_stop,
    )


def tool_list_operations(args: JSON) -> Any:
    return list_operations(
        root_arg(args),
        status=optional_str(args, "status"),
        limit=optional_int(args, "limit", 20),
    )


def tool_operation_summary(args: JSON) -> Any:
    return operation_summary(root_arg(args), require_str(args, "operation_id"))


def tool_recover_operations(args: JSON) -> Any:
    return recover_stale_operations(
        root_arg(args),
        older_than_seconds=optional_int(args, "older_than_seconds", 300),
        mark=not optional_bool(args, "dry_run", False),
        limit=optional_int(args, "limit", 20),
    )


def tool_recovery_drill(args: JSON) -> Any:
    root = root_arg(args)
    name = optional_str(args, "name") or "epic-continuum-recovery-drill"

    def action(operation: OperationGuard) -> JSON:
        result = recovery_drill(root, drill_name=name)
        operation.cursor({"phase": "drill_complete", "drill_id": result["drill_id"], "ok": result["ok"]})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_recovery_drill",
        title=f"Run recovery drill {name}",
        intent={"drill_name": name},
        snapshot_policy="none",
        snapshot_reason="drill uses disposable nested root",
        result_touched_paths=lambda result: [result["receipt_uri"]] if result.get("receipt_uri") else [],
        action=action,
    )


def tool_restore_drill(args: JSON) -> Any:
    root = root_arg(args)
    name = optional_str(args, "name") or "epic-continuum-restore-drill"
    raw_snapshot_uri = optional_str(args, "snapshot_uri")
    snapshot_uri = None
    if raw_snapshot_uri:
        raw_snapshot_path = Path(raw_snapshot_uri)
        snapshot_candidate = raw_snapshot_path if raw_snapshot_path.is_absolute() else root / raw_snapshot_path
        snapshot_uri = str(validate_allowed_path(snapshot_candidate, purpose="snapshot"))
    verify_recent = optional_int(args, "verify_recent_proof_packs", 1)
    entry_allowed_roots = None if env_truthy("CONTINUUM_MCP_ALLOW_ANY_PATH") else allowed_roots()

    def action(operation: OperationGuard) -> JSON:
        result = restore_drill(
            root,
            snapshot_uri=snapshot_uri,
            drill_name=name,
            verify_recent_proof_packs=verify_recent,
            allowed_roots=entry_allowed_roots,
        )
        operation.cursor({"phase": "restore_drill_complete", "drill_id": result["drill_id"], "ok": result["ok"]})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_restore_drill",
        title=f"Run restore drill {name}",
        intent={"drill_name": name, "snapshot_uri": snapshot_uri, "verify_recent_proof_packs": verify_recent},
        snapshot_policy="none",
        snapshot_reason="restore drill uses disposable nested root",
        result_touched_paths=lambda result: [result["receipt_uri"]] if result.get("receipt_uri") else [],
        action=action,
    )


def tool_review_prepare(args: JSON) -> Any:
    root = root_arg(args)
    subject = validate_allowed_path(Path(require_str(args, "subject")), purpose="review subject")
    prompt = require_str(args, "prompt")
    transport = optional_str(args, "transport") or DEFAULT_REVIEW_TRANSPORT
    if transport not in SUPPORTED_TRANSPORTS:
        raise ValueError(f"transport must be one of: {', '.join(sorted(SUPPORTED_TRANSPORTS))}")
    secret_allowlist_patterns = optional_str_list(args, "secret_allowlist_patterns")
    secret_allowlist_files = [
        validate_allowed_path(Path(path), purpose="review secret allowlist file")
        for path in optional_str_list(args, "secret_allowlist_files")
    ]

    def action(operation: OperationGuard) -> JSON:
        result = create_review_job(
            root,
            subject_path=subject,
            prompt=prompt,
            reviewer_id=optional_str(args, "reviewer_id") or "local-reviewer",
            transport=transport,
            model=optional_str(args, "model") or DEFAULT_REVIEW_MODEL,
            base_url=optional_str(args, "base_url") or DEFAULT_REVIEW_BASE_URL,
            include_diff=optional_bool(args, "include_diff", True),
            max_packet_bytes=optional_int(args, "max_packet_bytes", 512_000),
            max_file_bytes=optional_int(args, "max_file_bytes", 64_000),
            max_files=optional_int(args, "max_files", 300),
            secret_allowlist_patterns=secret_allowlist_patterns,
            secret_allowlist_files=secret_allowlist_files,
            operation_id=operation.operation_id,
        )
        operation.cursor({"phase": "review_job_created", "job_id": result["job_id"], "packet_sha256": result["packet_sha256"]})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_review_prepare",
        title=f"Prepare review relay job for {subject.name}",
        intent={
            "subject": str(subject),
            "transport": transport,
            "secret_allowlist_pattern_count": len(secret_allowlist_patterns),
            "secret_allowlist_file_count": len(secret_allowlist_files),
        },
        snapshot_policy="none",
        snapshot_reason="review preparation writes export artifacts only",
        result_touched_paths=lambda result: [
            path
            for path in [
                result.get("job_dir"),
                result.get("request_uri"),
                result.get("packet_uri"),
                result.get("prompt_uri"),
                result.get("schema_uri"),
                result.get("subject_manifest_uri"),
                result.get("subject_archive_uri"),
                result.get("review_capsule_uri"),
                result.get("manual_handoff_uri"),
                result.get("browser_handoff_uri"),
                result.get("secret_allowlist_report_uri"),
            ]
            if path
        ],
        action=action,
    )


def tool_review_run(args: JSON) -> Any:
    root = root_arg(args)
    transport = optional_str(args, "transport")
    if transport is not None and transport not in SUPPORTED_TRANSPORTS:
        raise ValueError(f"transport must be one of: {', '.join(sorted(SUPPORTED_TRANSPORTS))}")

    def action(operation: OperationGuard) -> JSON:
        result = run_review_job(
            root,
            job_id=require_str(args, "job_id"),
            transport=transport,
            model=optional_str(args, "model"),
            base_url=optional_str(args, "base_url"),
            timeout_seconds=optional_int(args, "timeout_seconds", 900),
            max_tokens=optional_int(args, "max_tokens", 4096),
            operation_id=operation.operation_id,
        )
        operation.cursor({"phase": "review_job_ran", "job_id": args.get("job_id"), "status": result.get("status")})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_review_run",
        title=f"Run review relay job {args.get('job_id')}",
        intent={"job_id": args.get("job_id"), "transport": transport},
        snapshot_policy="none",
        snapshot_reason="review run writes export artifacts only",
        result_touched_paths=lambda result: [
            path
            for path in [
                result.get("raw_response_uri"),
                result.get("reviewer_content_uri"),
                (result.get("ingest") or {}).get("findings_uri") if isinstance(result.get("ingest"), dict) else None,
                (result.get("ingest") or {}).get("findings_markdown_uri") if isinstance(result.get("ingest"), dict) else None,
                (result.get("ingest") or {}).get("ingest_receipt_uri") if isinstance(result.get("ingest"), dict) else None,
            ]
            if path
        ],
        action=action,
    )


def tool_review_ingest(args: JSON) -> Any:
    root = root_arg(args)
    result_path = optional_str(args, "result_path")
    content = optional_str(args, "content")
    if not result_path and content is None:
        raise ValueError("result_path or content is required")
    validated_result_path = validate_allowed_path(Path(result_path), purpose="review result") if result_path else None

    def action(operation: OperationGuard) -> JSON:
        result = ingest_review_result(
            root,
            job_id=require_str(args, "job_id"),
            result_path=validated_result_path,
            content=content,
            operation_id=operation.operation_id,
        )
        operation.cursor({"phase": "review_result_ingested", "job_id": args.get("job_id"), "verdict": result.get("verdict")})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_review_ingest",
        title=f"Ingest review result {args.get('job_id')}",
        intent={"job_id": args.get("job_id"), "result_path": result_path},
        snapshot_policy="none",
        snapshot_reason="review ingest writes export artifacts and artifact ledger rows",
        result_touched_paths=lambda result: [
            path
            for path in [
                result.get("raw_response_uri"),
                result.get("response_uri"),
                result.get("findings_uri"),
                result.get("findings_markdown_uri"),
                result.get("ingest_receipt_uri"),
            ]
            if path
        ],
        action=action,
    )


def tool_review_status(args: JSON) -> Any:
    return review_job_status(root_arg(args), job_id=require_str(args, "job_id"))


def tool_review_check_current(args: JSON) -> Any:
    return review_check_current(root_arg(args), job_id=require_str(args, "job_id"))


def tool_review_browser_attempt_start(args: JSON) -> Any:
    root = root_arg(args)

    def action(operation: OperationGuard) -> JSON:
        result = review_browser_attempt_start(root, job_id=require_str(args, "job_id"))
        operation.cursor({"phase": "review_browser_attempt_reserved", "job_id": args.get("job_id"), "attempt": result.get("attempt")})
        return result

    return guarded_tool(
        root,
        operation_type="mcp_review_browser_attempt_start",
        title=f"Reserve browser review response path {args.get('job_id')}",
        intent={"job_id": args.get("job_id")},
        snapshot_policy="none",
        snapshot_reason="browser attempt reservation writes review export artifacts only",
        result_touched_paths=lambda result: [
            path
            for path in [result.get("response_uri"), result.get("attempt_uri"), result.get("browser_handoff_uri")]
            if path
        ],
        action=action,
    )


TOOLS: dict[str, tuple[str, JSON, ToolHandler]] = {
    "continuum_init": (
        "Initialize an Epic Continuum root and database.",
        {"type": "object", "properties": {"root": {"type": "string"}}, "additionalProperties": False},
        tool_init,
    ),
    "continuum_status": (
        "Show Epic Continuum root status, counts, pending jobs, and active budgets.",
        {
            "type": "object",
            "properties": {"root": {"type": "string"}},
            "additionalProperties": False,
        },
        tool_status,
    ),
    "continuum_config": (
        "Create or return the Epic Continuum root config.",
        {"type": "object", "properties": {"root": {"type": "string"}}, "additionalProperties": False},
        tool_config,
    ),
    "continuum_optimize_config": (
        "Preview or write hardware-aware memory budgets.",
        {
            "type": "object",
            "properties": {
                "root": {"type": "string"},
                "profile": {"type": "string", "enum": sorted(PROFILES)},
                "write": {"type": "boolean"},
                "vram": {"type": "string"},
                "system_ram": {"type": "string"},
                "drive_free": {"type": "string"},
            },
            "additionalProperties": False,
        },
        tool_optimize_config,
    ),
    "continuum_append_event": (
        "Append a raw event to the ordered Scroll.",
        {
            "type": "object",
            "required": ["session_id", "content"],
            "properties": {
                "root": {"type": "string"},
                "session_id": {"type": "string"},
                "event_type": {"type": "string"},
                "role": {"type": "string"},
                "content": {"type": "string"},
                "metadata": {"type": "object"},
            },
            "additionalProperties": False,
        },
        tool_append_event,
    ),
    "continuum_roll_segment": (
        "Roll a Scroll event range into a compact Card and queue follow-up review.",
        {
            "type": "object",
            "required": ["session_id", "start_seq", "end_seq"],
            "properties": {
                "root": {"type": "string"},
                "session_id": {"type": "string"},
                "start_seq": {"type": "integer"},
                "end_seq": {"type": "integer"},
            },
            "additionalProperties": False,
        },
        tool_roll_segment,
    ),
    "continuum_ingest_file": (
        "Ingest a local file as a Library book, reader edition, chunks, and Card.",
        {
            "type": "object",
            "required": ["path"],
            "properties": {
                "root": {"type": "string"},
                "path": {"type": "string"},
                "title": {"type": "string"},
                "storage_tier": {"type": "string", "enum": ["hot", "warm", "cold", "vault"]},
            },
            "additionalProperties": False,
        },
        tool_ingest_file,
    ),
    "continuum_compile_context": (
        "Build a token-bounded Looking Glass context packet for a session.",
        {
            "type": "object",
            "required": ["session_id"],
            "properties": {
                "root": {"type": "string"},
                "session_id": {"type": "string"},
                "project_id": {"type": "string"},
                "query": {"type": "string"},
                "token_budget": {"type": "integer"},
                "card_scope": {"type": "string", "enum": ["session", "global", "session_then_global", "project"]},
                "include_cue_recall": {"type": "boolean"},
                "cue_recall_limit": {"type": "integer", "minimum": 1, "maximum": 20},
            },
            "additionalProperties": False,
        },
        tool_compile_context,
    ),
    "continuum_recover_thread": (
        "Create a Markdown crash-recovery packet for a session.",
        {
            "type": "object",
            "required": ["session_id"],
            "properties": {
                "root": {"type": "string"},
                "session_id": {"type": "string"},
                "project_id": {"type": "string"},
                "query": {"type": "string"},
                "token_budget": {"type": "integer"},
                "recent_event_limit": {"type": "integer"},
            },
            "additionalProperties": False,
        },
        tool_recover_thread,
    ),
    "continuum_search": (
        "Search Library chunks with SQLite FTS5 or LIKE fallback.",
        {
            "type": "object",
            "required": ["query"],
            "properties": {
                "root": {"type": "string"},
                "query": {"type": "string"},
                "limit": {"type": "integer"},
                "session_id": {"type": "string"},
                "project_id": {"type": "string"},
            },
            "additionalProperties": False,
        },
        tool_search,
    ),
    "continuum_cue_recall": (
        "Recover buried ideas from loose associative cues across Scroll, Cards, Library, and graph routes.",
        {
            "type": "object",
            "required": ["cue"],
            "properties": {
                "root": {"type": "string"},
                "cue": {"type": "string"},
                "session_id": {"type": "string"},
                "project_id": {"type": "string"},
                "limit": {"type": "integer"},
                "max_associations": {"type": "integer"},
            },
            "additionalProperties": False,
        },
        tool_cue_recall,
    ),
    "continuum_record_project_state": (
        "Record a durable shared project-state checkpoint for cross-agent handoff.",
        {
            "type": "object",
            "required": ["session_id", "agent_id", "project_id"],
            "properties": {
                "root": {"type": "string"},
                "session_id": {"type": "string"},
                "agent_id": {"type": "string"},
                "project_id": {"type": "string"},
                "objective": {"type": "string"},
                "repo_path": {"type": "string"},
                "branch": {"type": "string"},
                "commit": {"type": "string"},
                "dirty": {"type": "boolean"},
                "changed_files": {"type": "array", "items": {"type": "string"}},
                "decisions": {"type": "array", "items": {"type": "string"}},
                "open_tasks": {"type": "array", "items": {"type": "string"}},
                "notes": {"type": "string"},
                "metadata": {"type": "object"},
            },
            "additionalProperties": False,
        },
        tool_record_project_state,
    ),
    "continuum_audit_search_index": (
        "Audit Library chunk FTS index consistency.",
        {"type": "object", "properties": {"root": {"type": "string"}}, "additionalProperties": False},
        tool_audit_search_index,
    ),
    "continuum_rebuild_search_index": (
        "Rebuild Library chunk FTS index from canonical chunks.",
        {"type": "object", "properties": {"root": {"type": "string"}}, "additionalProperties": False},
        tool_rebuild_search_index,
    ),
    "continuum_reindex_memory": (
        "Backfill Scroll association routes and trusted exact-memory Cards without duplicating graph weights.",
        {
            "type": "object",
            "properties": {
                "root": {"type": "string"},
                "session_id": {"type": "string"},
                "after_seq": {"type": "integer"},
                "after_rowid": {"type": "integer"},
                "limit": {"type": "integer"},
                "batch_size": {"type": "integer"},
                "dry_run": {"type": "boolean"},
                "promote_exact_memory": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
        tool_reindex_memory,
    ),
    "continuum_audit": (
        "Run an Epic Continuum integrity and queue audit.",
        {"type": "object", "properties": {"root": {"type": "string"}}, "additionalProperties": False},
        tool_audit,
    ),
    "continuum_doctor": (
        "Run package, catalog, and proof-pack diagnostics.",
        {
            "type": "object",
            "properties": {
                "root": {"type": "string"},
                "verify_recent_proof_packs": {"type": "integer"},
                "scan_secrets": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
        tool_doctor,
    ),
    "continuum_repair_permissions": (
        "Tighten private Epic Continuum root permissions on POSIX systems.",
        {"type": "object", "properties": {"root": {"type": "string"}}, "additionalProperties": False},
        tool_repair_permissions,
    ),
    "continuum_audit_secrets": (
        "Scan an Epic Continuum root for obvious secret patterns without initializing a missing root.",
        {
            "type": "object",
            "properties": {
                "root": {"type": "string"},
                "max_findings": {"type": "integer"},
                "max_file_bytes": {"type": "integer"},
            },
            "additionalProperties": False,
        },
        tool_audit_secrets,
    ),
    "continuum_run_workers": (
        "Run one Scribe/Librarian/Archivist worker pass over pending jobs and maintenance.",
        {
            "type": "object",
            "properties": {
                "root": {"type": "string"},
                "roles": {"type": "array", "items": {"type": "string", "enum": ["scribe", "librarian", "archivist"]}},
                "limit": {"type": "integer"},
                "no_maintenance": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
        tool_run_workers,
    ),
    "continuum_memory_health": (
        "Report Epic Continuum capture, queue, storage, and learning health.",
        {"type": "object", "properties": {"root": {"type": "string"}}, "additionalProperties": False},
        tool_memory_health,
    ),
    "continuum_tier_storage": (
        "Apply Archivist storage tiering policy.",
        {
            "type": "object",
            "properties": {"root": {"type": "string"}, "dry_run": {"type": "boolean"}, "limit": {"type": "integer"}},
            "additionalProperties": False,
        },
        tool_tier_storage,
    ),
    "continuum_prune_memory": (
        "Archive, summarize-only, or prune cards by topic.",
        {
            "type": "object",
            "properties": {
                "root": {"type": "string"},
                "topic": {"type": "string"},
                "action": {"type": "string", "enum": ["archive", "summarize_only", "forget"]},
                "dry_run": {"type": "boolean"},
                "all": {"type": "boolean", "description": "Allow pruning across all topics when topic is omitted."},
                "limit": {"type": "integer"},
            },
            "additionalProperties": False,
        },
        tool_prune_memory,
    ),
    "continuum_detect_conflicts": (
        "Detect likely conflicting cards and mark conflict groups.",
        {
            "type": "object",
            "properties": {"root": {"type": "string"}, "card_id": {"type": "string"}, "limit": {"type": "integer"}},
            "additionalProperties": False,
        },
        tool_detect_conflicts,
    ),
    "continuum_decay_routes": (
        "Apply Librarian route decay and synaptic pruning.",
        {
            "type": "object",
            "properties": {"root": {"type": "string"}, "limit": {"type": "integer"}, "prune_threshold": {"type": "integer"}},
            "additionalProperties": False,
        },
        tool_decay_routes,
    ),
    "continuum_run_evals": (
        "Run deterministic memory quality evals in a disposable nested root.",
        {
            "type": "object",
            "properties": {"root": {"type": "string"}, "keep_artifacts": {"type": "boolean"}},
            "additionalProperties": False,
        },
        tool_run_evals,
    ),
    "continuum_verify_proof_pack": (
        "Verify a proof pack manifest and recorded file hashes.",
        {
            "type": "object",
            "required": ["path"],
            "properties": {"path": {"type": "string"}, "root": {"type": "string"}},
            "additionalProperties": False,
        },
        tool_verify_proof_pack,
    ),
    "continuum_verify_root": (
        "Run strict root invariants: doctor, proofs, ledger, search, secrets, and optional restore drill.",
        {
            "type": "object",
            "properties": {
                "root": {"type": "string"},
                "strict": {"type": "boolean"},
                "verify_recent_proof_packs": {"type": "integer"},
                "run_restore_drill": {"type": "boolean"},
                "scan_secrets": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
        tool_verify_root,
    ),
    "continuum_pack_root": (
        "Create a policy-checked portable ZIP bundle from a Continuum root.",
        {
            "type": "object",
            "required": ["out_path"],
            "properties": {
                "root": {"type": "string"},
                "out_path": {"type": "string"},
                "profile": {"type": "string", "enum": ["portable", "shareable"]},
                "symlink_policy": {"type": "string", "enum": ["fail", "skip"]},
                "run_restore_drill": {"type": "boolean"},
                "force": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
        tool_pack_root,
    ),
    "continuum_verify_bundle": (
        "Verify a packed Continuum ZIP manifest and every member hash.",
        {
            "type": "object",
            "required": ["path"],
            "properties": {
                "path": {"type": "string"},
                "verify_embedded_root": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
        tool_verify_bundle,
    ),
    "continuum_replay_operation_log": (
        "Replay a hash-chained operation event JSONL log into reconstructed operation state.",
        {
            "type": "object",
            "required": ["path"],
            "properties": {"path": {"type": "string"}, "operation_id": {"type": "string"}},
            "additionalProperties": False,
        },
        tool_replay_operation_log,
    ),
    "continuum_redact_legacy_secrets": (
        "Dry-run or apply redaction for legacy secret-like catalog text.",
        {
            "type": "object",
            "properties": {"root": {"type": "string"}, "limit": {"type": "integer"}, "apply": {"type": "boolean"}},
            "additionalProperties": False,
        },
        tool_redact_legacy_secrets,
    ),
    "continuum_snapshot": (
        "Create a catalog database snapshot.",
        {
            "type": "object",
            "properties": {"root": {"type": "string"}, "reason": {"type": "string"}},
            "additionalProperties": False,
        },
        tool_snapshot,
    ),
    "continuum_import_mempalace": (
        "Import MemPalace drawers, closets, and knowledge graph records into Epic Continuum.",
        {
            "type": "object",
            "properties": {
                "root": {"type": "string"},
                "palace_path": {"type": "string"},
                "include_closets": {"type": "boolean"},
                "include_kg": {"type": "boolean"},
                "allow_stop": {
                    "type": "boolean",
                    "description": "Stop mempalace-readonly-mcp if the live Chroma DB is locked.",
                },
            },
            "additionalProperties": False,
        },
        tool_import_mempalace,
    ),
    "continuum_list_operations": (
        "List Epic Continuum operation receipts written while work is in progress.",
        {
            "type": "object",
            "properties": {
                "root": {"type": "string"},
                "status": {"type": "string", "enum": ["running", "succeeded", "failed", "interrupted"]},
                "limit": {"type": "integer"},
            },
            "additionalProperties": False,
        },
        tool_list_operations,
    ),
    "continuum_operation_summary": (
        "Read one Epic Continuum operation receipt summary.",
        {
            "type": "object",
            "required": ["operation_id"],
            "properties": {
                "root": {"type": "string"},
                "operation_id": {"type": "string"},
            },
            "additionalProperties": False,
        },
        tool_operation_summary,
    ),
    "continuum_recover_operations": (
        "Recover stale running Epic Continuum operations, or report them without writes when dry_run is true.",
        {
            "type": "object",
            "properties": {
                "root": {"type": "string"},
                "older_than_seconds": {"type": "integer"},
                "limit": {"type": "integer"},
                "dry_run": {"type": "boolean"},
            },
            "additionalProperties": False,
        },
        tool_recover_operations,
    ),
    "continuum_recovery_drill": (
        "Run an Epic Continuum interruption/recovery drill on a disposable nested root.",
        {
            "type": "object",
            "properties": {
                "root": {"type": "string"},
                "name": {"type": "string"},
            },
            "additionalProperties": False,
        },
        tool_recovery_drill,
    ),
    "continuum_restore_drill": (
        "Restore a catalog snapshot into a disposable root and verify status/audit.",
        {
            "type": "object",
            "properties": {
                "root": {"type": "string"},
                "snapshot_uri": {"type": "string"},
                "name": {"type": "string"},
                "verify_recent_proof_packs": {"type": "integer"},
            },
            "additionalProperties": False,
        },
        tool_restore_drill,
    ),
    "continuum_review_prepare": (
        "Create a hash-bound review relay job for a repo, package, or file.",
        {
            "type": "object",
            "required": ["subject", "prompt"],
            "properties": {
                "root": {"type": "string"},
                "subject": {"type": "string"},
                "prompt": {"type": "string"},
                "reviewer_id": {"type": "string"},
                "transport": {"type": "string", "enum": sorted(SUPPORTED_TRANSPORTS)},
                "model": {"type": "string"},
                "base_url": {"type": "string"},
                "include_diff": {"type": "boolean"},
                "max_packet_bytes": {"type": "integer"},
                "max_file_bytes": {"type": "integer"},
                "max_files": {"type": "integer"},
                "secret_allowlist_patterns": {"type": "array", "items": {"type": "string"}},
                "secret_allowlist_files": {"type": "array", "items": {"type": "string"}},
            },
            "additionalProperties": False,
        },
        tool_review_prepare,
    ),
    "continuum_review_run": (
        "Run a review relay job through a direct OpenAI-compatible endpoint or prepare a manual/Hermes handoff.",
        {
            "type": "object",
            "required": ["job_id"],
            "properties": {
                "root": {"type": "string"},
                "job_id": {"type": "string"},
                "transport": {"type": "string", "enum": sorted(SUPPORTED_TRANSPORTS)},
                "model": {"type": "string"},
                "base_url": {"type": "string"},
                "timeout_seconds": {"type": "integer"},
                "max_tokens": {"type": "integer"},
            },
            "additionalProperties": False,
        },
        tool_review_run,
    ),
    "continuum_review_ingest": (
        "Ingest a completed review result after verifying its job and artifact hashes.",
        {
            "type": "object",
            "required": ["job_id"],
            "properties": {
                "root": {"type": "string"},
                "job_id": {"type": "string"},
                "result_path": {"type": "string"},
                "content": {"type": "string"},
            },
            "additionalProperties": False,
        },
        tool_review_ingest,
    ),
    "continuum_review_status": (
        "Show review relay job status and artifact paths.",
        {
            "type": "object",
            "required": ["job_id"],
            "properties": {"root": {"type": "string"}, "job_id": {"type": "string"}},
            "additionalProperties": False,
        },
        tool_review_status,
    ),
    "continuum_review_check_current": (
        "Check whether the reviewed source still matches the active subject before applying findings.",
        {
            "type": "object",
            "required": ["job_id"],
            "properties": {"root": {"type": "string"}, "job_id": {"type": "string"}},
            "additionalProperties": False,
        },
        tool_review_check_current,
    ),
    "continuum_review_browser_attempt_start": (
        "Reserve a unique append-only response path before a browser-only Pro review attempt.",
        {
            "type": "object",
            "required": ["job_id"],
            "properties": {"root": {"type": "string"}, "job_id": {"type": "string"}},
            "additionalProperties": False,
        },
        tool_review_browser_attempt_start,
    ),
}


READ_ONLY_TOOLS = {
    "continuum_status",
    "continuum_compile_context",
    "continuum_search",
    "continuum_cue_recall",
    "continuum_audit_search_index",
    "continuum_audit",
    "continuum_audit_secrets",
    "continuum_memory_health",
    "continuum_verify_proof_pack",
    "continuum_replay_operation_log",
    "continuum_list_operations",
    "continuum_operation_summary",
    "continuum_review_status",
    "continuum_review_check_current",
}


IDEMPOTENT_MUTATING_TOOLS = {
    "continuum_init",
    "continuum_rebuild_search_index",
    "continuum_reindex_memory",
    "continuum_repair_permissions",
}


DESTRUCTIVE_TOOLS = {
    "continuum_prune_memory",
    "continuum_redact_legacy_secrets",
    "continuum_tier_storage",
}


OPEN_WORLD_TOOLS = {
    "continuum_ingest_file",
    "continuum_import_mempalace",
    "continuum_pack_root",
    "continuum_verify_bundle",
    "continuum_review_prepare",
    "continuum_review_run",
    "continuum_review_ingest",
}


def tool_annotations(name: str) -> JSON:
    read_only = name in READ_ONLY_TOOLS
    return {
        "readOnlyHint": read_only,
        "destructiveHint": name in DESTRUCTIVE_TOOLS,
        "idempotentHint": read_only or name in IDEMPOTENT_MUTATING_TOOLS,
        "openWorldHint": name in OPEN_WORLD_TOOLS,
    }


def tool_specs() -> list[JSON]:
    return [
        {
            "name": name,
            "title": name.replace("_", " ").title(),
            "description": description,
            "inputSchema": schema,
            "outputSchema": {"type": "object", "additionalProperties": True},
            "annotations": tool_annotations(name),
        }
        for name, (description, schema, _handler) in TOOLS.items()
    ]


def rpc_result(request_id: Any, result: Any) -> JSON:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def rpc_error(request_id: Any, code: int, message: str, data: Any | None = None) -> JSON:
    error: JSON = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def dispatch(request: JSON) -> JSON | None:
    request_id = request.get("id")
    method = request.get("method")
    if not method:
        return rpc_error(request_id, -32600, "missing method")

    if method.startswith("notifications/"):
        return None

    if method == "initialize":
        return rpc_result(
            request_id,
            {
                "protocolVersion": negotiated_protocol_version(request.get("params")),
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "epic-continuum",
                    "version": __version__,
                    "supportedProtocolVersions": list(SUPPORTED_PROTOCOL_VERSIONS),
                },
            },
        )
    if method == "ping":
        return rpc_result(request_id, {})
    if method == "tools/list":
        return rpc_result(request_id, {"tools": tool_specs()})
    if method == "resources/list":
        return rpc_result(request_id, {"resources": []})
    if method == "prompts/list":
        return rpc_result(request_id, {"prompts": []})
    if method == "tools/call":
        params = request.get("params") or {}
        if not isinstance(params, dict):
            return rpc_error(request_id, -32602, "params must be an object")
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or name not in TOOLS:
            return rpc_result(request_id, tool_result({"error": f"unknown tool: {name}"}, is_error=True))
        if not isinstance(arguments, dict):
            return rpc_result(request_id, tool_result({"error": "arguments must be an object"}, is_error=True))
        try:
            _description, _schema, handler = TOOLS[name]
            return rpc_result(request_id, tool_result(handler(arguments)))
        except Exception as exc:
            if not isinstance(exc, ValueError):
                traceback.print_exc(file=sys.stderr)
            return rpc_result(
                request_id,
                tool_result({"error": str(exc), "tool": name}, is_error=True),
            )

    return rpc_error(request_id, -32601, f"method not found: {method}")


def serve() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        response: JSON | None
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            response = rpc_error(None, -32700, "parse error", str(exc))
        else:
            if not isinstance(request, dict):
                response = rpc_error(None, -32600, "request must be an object")
            else:
                response = dispatch(request)
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=True, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    return 0


def main() -> int:
    return serve()


if __name__ == "__main__":
    raise SystemExit(main())
