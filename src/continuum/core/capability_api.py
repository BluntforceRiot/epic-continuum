"""Finite, bounded JSON dispatch for the optional 0.4 knowledge capabilities.

This is a transport adapter, not dynamic module loading or agent instruction
execution. Public domain functions remain the validators for their semantics.
"""
from __future__ import annotations

import inspect
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

MAX_REQUEST_BYTES = 512 * 1024
MAX_REQUEST_NODES = 65536
MAX_REQUEST_DEPTH = 20


@dataclass(frozen=True)
class Capability:
    effect: str
    paths: tuple[str, ...] = ()
    guard_root_field: str | None = None


# Exact action names only. No request-controlled module, function or attribute
# lookup exists; adding a public action requires an explicit registry change.
CAPABILITIES = {
    "register_analysis_asset": Capability("memory", ("source_root",)),
    "record_analysis_finding": Capability("memory"),
    "record_media_annotation": Capability("memory"),
    "record_notebook_entry": Capability("memory"),
    "query_investigation": Capability("read", ("source_root",)),
    "export_investigation_notebook": Capability("read", ("source_root",)),
    "record_experience": Capability("memory"),
    "propose_procedure": Capability("memory"),
    "review_procedure": Capability("memory"),
    "query_experiences": Capability("read"),
    "find_reusable_lessons": Capability("read"),
    "create_handoff": Capability("memory"),
    "transition_handoff": Capability("memory"),
    "query_handoffs": Capability("read"),
    "create_collection": Capability("memory"),
    "revise_collection": Capability("memory"),
    "query_collections": Capability("read"),
    "change_impact": Capability("read"),
    "compile_task_pack": Capability("read"),
    "explain_memory": Capability("read"),
    "export_workspace": Capability("read"),
    "plan_workspace_import": Capability("read"),
    "import_workspace": Capability("memory"),
    "resolve_workspace_conflict": Capability("memory"),
    "create_memory_experiment": Capability("derived", ("destination",)),
    "replay_memory_experiment": Capability("read", ("experiment_root",)),
    "compare_experiment_replays": Capability("read"),
    "adopt_experiment_records": Capability("memory", ("experiment_root", "target_root"), "target_root"),
}
READ_ACTIONS = tuple(sorted(name for name, spec in CAPABILITIES.items() if spec.effect == "read"))
WRITE_ACTIONS = tuple(sorted(name for name, spec in CAPABILITIES.items() if spec.effect != "read"))


def _replay_experiment(root: Path, *, experiment_root: Path, queries: list[str],
                       expected_manifest_hash: str, limit: int = 8, token_budget: int = 2400) -> dict[str, Any]:
    from .workspaces import replay_memory_experiment
    return replay_memory_experiment(experiment_root, queries=queries, expected_manifest_hash=expected_manifest_hash,
                                    limit=limit, token_budget=token_budget)


def _compare_replays(root: Path, *, before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    from .workspaces import compare_experiment_replays
    return compare_experiment_replays(before, after)


def _adopt_experiment(root: Path, *, experiment_root: Path, record_ids: list[str], target_root: Path,
                      project_id: str, session_id: str, workspace_id: str, expected_manifest_hash: str,
                      allow_fork: bool = False) -> dict[str, Any]:
    from .workspaces import adopt_experiment_records
    return adopt_experiment_records(experiment_root, record_ids=record_ids, target_root=target_root,
                                    project_id=project_id, session_id=session_id, workspace_id=workspace_id,
                                    expected_manifest_hash=expected_manifest_hash, allow_fork=allow_fork)


def _handler(action: str) -> Callable[..., dict[str, Any]]:
    # Imports are lazy so ordinary commands need not initialize optional domain
    # modules. Each branch lists the only callable values it can return.
    handlers: dict[str, Callable[..., dict[str, Any]]]
    if action in {"register_analysis_asset", "record_analysis_finding", "record_media_annotation",
                  "record_notebook_entry", "query_investigation", "export_investigation_notebook"}:
        from .investigation import (
            export_investigation_notebook, query_investigation, record_analysis_finding,
            record_media_annotation, record_notebook_entry, register_analysis_asset,
        )
        handlers = {"register_analysis_asset": register_analysis_asset, "record_analysis_finding": record_analysis_finding,
                "record_media_annotation": record_media_annotation, "record_notebook_entry": record_notebook_entry,
                "query_investigation": query_investigation, "export_investigation_notebook": export_investigation_notebook}
        return handlers[action]
    if action in {"record_experience", "propose_procedure", "review_procedure", "query_experiences", "find_reusable_lessons"}:
        from .experience import find_reusable_lessons, propose_procedure, query_experiences, record_experience, review_procedure
        handlers = {"record_experience": record_experience, "propose_procedure": propose_procedure,
                "review_procedure": review_procedure, "query_experiences": query_experiences,
                "find_reusable_lessons": find_reusable_lessons}
        return handlers[action]
    if action in {"create_handoff", "transition_handoff", "query_handoffs", "create_collection", "revise_collection", "query_collections"}:
        from .coordination import (
            create_collection, create_handoff, query_collections, query_handoffs, revise_collection, transition_handoff,
        )
        handlers = {"create_handoff": create_handoff, "transition_handoff": transition_handoff,
                "query_handoffs": query_handoffs, "create_collection": create_collection,
                "revise_collection": revise_collection, "query_collections": query_collections}
        return handlers[action]
    if action in {"change_impact", "compile_task_pack", "explain_memory"}:
        from .working_context import change_impact, compile_task_pack, explain_memory
        handlers = {"change_impact": change_impact, "compile_task_pack": compile_task_pack, "explain_memory": explain_memory}
        return handlers[action]
    if action in {"export_workspace", "plan_workspace_import", "import_workspace", "resolve_workspace_conflict",
                  "create_memory_experiment", "replay_memory_experiment", "compare_experiment_replays", "adopt_experiment_records"}:
        from .workspaces import (
            create_memory_experiment, export_workspace, import_workspace, plan_workspace_import, resolve_workspace_conflict,
        )
        handlers = {"export_workspace": export_workspace, "plan_workspace_import": plan_workspace_import,
                "import_workspace": import_workspace, "resolve_workspace_conflict": resolve_workspace_conflict,
                "create_memory_experiment": create_memory_experiment, "replay_memory_experiment": _replay_experiment,
                "compare_experiment_replays": _compare_replays, "adopt_experiment_records": _adopt_experiment}
        return handlers[action]
    raise ValueError("unsupported knowledge action")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON object keys are not permitted")
        value[key] = item
    return value


def _constant(_value: str) -> Any:
    raise ValueError("non-finite JSON numbers are not permitted")


def _json_shape(value: Any, depth: int = 0, count: list[int] | None = None) -> None:
    count = [0] if count is None else count
    count[0] += 1
    if depth > MAX_REQUEST_DEPTH or count[0] > MAX_REQUEST_NODES:
        raise ValueError("knowledge request structure exceeds its bounds")
    if value is None or type(value) is bool:
        return
    if type(value) is str:
        if len(value) > MAX_REQUEST_BYTES or "\x00" in value:
            raise ValueError("knowledge request text exceeds its bounds or contains NUL")
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("knowledge request text must be valid UTF-8") from None
        return
    if type(value) is int:
        if abs(value) > 2**63 - 1:
            raise ValueError("knowledge request integer exceeds its bounds")
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is list and len(value) <= 16384:
        for item in value:
            _json_shape(item, depth + 1, count)
        return
    if type(value) is dict and len(value) <= 16384:
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError("knowledge request keys must be strings")
            _json_shape(key, depth + 1, count)
            _json_shape(item, depth + 1, count)
        return
    raise ValueError("knowledge request must contain finite plain JSON values")


def validate_request(request: Any) -> dict[str, Any]:
    if type(request) is not dict or len(request) > 64:
        raise ValueError("knowledge request must be an object with at most 64 arguments")
    _json_shape(request)
    encoded = json.dumps(request, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_REQUEST_BYTES:
        raise ValueError("knowledge request exceeds 524288 UTF-8 bytes")
    # A detached plain copy prevents callers from changing arguments after path
    # validation, or while a governed write waits for the writer claim.
    return json.loads(encoded)


def parse_request_json(raw: str) -> dict[str, Any]:
    if type(raw) is not str:
        raise ValueError("knowledge request JSON must be a string")
    try:
        if len(raw.encode("utf-8")) > MAX_REQUEST_BYTES:
            raise ValueError("knowledge request exceeds 524288 UTF-8 bytes")
        value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=_constant)
        return validate_request(value)
    except (UnicodeError, RecursionError, OverflowError):
        raise ValueError("knowledge request must be bounded UTF-8 JSON") from None


def explicit_path(value: Any, name: str) -> Path:
    if type(value) is not str or not value.strip() or len(value) > 4096 or "\x00" in value:
        raise ValueError(f"{name} must be an explicit bounded absolute path")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError(f"{name} must be valid UTF-8 text") from None
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{name} must be an explicit absolute path")
    return path


@dataclass(frozen=True)
class PreparedCapability:
    action: str
    spec: Capability
    request: dict[str, Any]
    handler: Callable[..., dict[str, Any]]

    def operation_root(self, root: Path) -> Path | None:
        if self.spec.effect != "memory":
            return None
        return root if self.spec.guard_root_field is None else self.request[self.spec.guard_root_field]


def prepare_capability(
    action: str, request: Any, *, write: bool | None = None,
    path_validator: Callable[[Path, str], Path] | None = None,
) -> PreparedCapability:
    """Validate finite dispatch, exact parameters and all explicit path arguments."""
    if type(action) is not str or action not in CAPABILITIES:
        raise ValueError("unsupported knowledge action")
    if write is not None and type(write) is not bool:
        raise ValueError("write must be a boolean when provided")
    spec = CAPABILITIES[action]
    if write is not None and write != (spec.effect != "read"):
        raise ValueError("knowledge action is not permitted by this read/write interface")
    options = validate_request(request)
    if "root" in options:
        raise ValueError("root must be supplied explicitly outside the request")
    handler = _handler(action)
    try:
        inspect.signature(handler).bind(Path("."), **options)
    except TypeError as exc:
        raise ValueError(f"invalid arguments for knowledge action: {exc}") from None
    for name in spec.paths:
        if name in options and options[name] is not None:
            path = explicit_path(options[name], name)
            options[name] = path if path_validator is None else path_validator(path, name)
    return PreparedCapability(action, spec, options, handler)


def dispatch_capability(root: Path, prepared: PreparedCapability) -> dict[str, Any]:
    """Invoke an already prepared fixed-domain function; no transport side effects."""
    return prepared.handler(root, **prepared.request)
