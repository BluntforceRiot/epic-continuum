"""Opt-in, host-neutral context selection and evidence-backed task packets.

This module never sends a request, calls a model, or modifies stored evidence.
Its token estimates are planning estimates, not a provider tokenizer. The caller
must refuse a non-fitting mandatory boundary instead of silently truncating it.
"""
from __future__ import annotations

import hashlib
import json
import math
from collections import deque
from pathlib import Path
from typing import Any

from .knowledge_records import bounded_results, read_records, require_text, validate_evidence
from .recall import SOURCE_KINDS, read_memory_source, recall_memory

_MEDIA_TYPES = frozenset({"image", "image_url", "input_image", "input_audio", "audio", "video"})


def _integer(value: object, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def _structure(value: object, depth: int = 0, nodes: list[int] | None = None) -> None:
    """Validate without serializing media bytes into a second giant string."""
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if depth > 32 or nodes[0] > 200000:
        raise ValueError("message structure exceeds its bounds")
    if value is None or type(value) is bool:
        return
    if type(value) is str:
        if len(value) > 32 * 1024 * 1024 or "\x00" in value:
            raise ValueError("message string exceeds its bounds or contains NUL")
        # Do not allocate a second copy of a large ASCII data URL.
        if not value.isascii():
            try:
                value.encode("utf-8")
            except UnicodeEncodeError:
                raise ValueError("messages must contain valid UTF-8") from None
        return
    if type(value) is int and abs(value) <= 2**63 - 1:
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is list and len(value) <= 10000:
        for item in value:
            _structure(item, depth + 1, nodes)
        return
    if type(value) is dict and len(value) <= 4096 and all(type(key) is str for key in value):
        for key, item in value.items():
            _structure(key, depth + 1, nodes)
            _structure(item, depth + 1, nodes)
        return
    raise ValueError("messages must contain bounded plain JSON values")


def _tokens(value: Any, image_tokens: int) -> int:
    if isinstance(value, str):
        if value.startswith(("data:image/", "data:audio/", "data:video/")):
            return image_tokens
        return (len(value) + 3) // 4
    if isinstance(value, list):
        return 2 + sum(_tokens(item, image_tokens) for item in value)
    if isinstance(value, dict):
        if type(value.get("type")) is str and value["type"] in _MEDIA_TYPES:
            # Count surrounding captions/labels but not encoded media metadata.
            return image_tokens + sum(_tokens(value[key], image_tokens)
                                      for key in ("text", "caption", "alt") if key in value)
        return 2 + sum(_tokens(key, image_tokens) + _tokens(item, image_tokens)
                       for key, item in value.items())
    return 1


def _groups(messages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[list[dict[str, Any]]]]:
    prefix: list[dict[str, Any]] = []
    groups: list[list[dict[str, Any]]] = []
    pending: set[str] = set()
    used: set[str] = set()
    for message in messages:
        role = message.get("role")
        if type(role) is not str or role not in {"system", "developer", "user", "assistant", "tool"}:
            raise ValueError("unsupported message role")
        if role in {"system", "developer"}:
            if groups:
                raise ValueError("system/developer messages must form a leading stable prefix")
            prefix.append(message)
            continue
        if role == "user":
            if pending:
                raise ValueError("a user boundary cannot split an assistant call/result group")
            groups.append([])
        if not groups:
            raise ValueError("conversation must begin with a user group")
        if role == "tool":
            identity = message.get("tool_call_id")
            if type(identity) is not str or identity not in pending:
                raise ValueError("orphaned or duplicate tool result")
            pending.remove(identity)
        else:
            if pending:
                raise ValueError("assistant call/result group is incomplete")
            calls = message.get("tool_calls")
            if calls is not None:
                if role != "assistant" or type(calls) is not list or not 1 <= len(calls) <= 64:
                    raise ValueError("tool_calls must be a bounded assistant call group")
                for call in calls:
                    if type(call) is not dict:
                        raise ValueError("invalid assistant tool call")
                    identity = require_text(call.get("id"), "tool call id", 256)
                    function = call.get("function")
                    if call.get("type", "function") != "function" or type(function) is not dict:
                        raise ValueError("only structured function tool calls are supported")
                    require_text(function.get("name"), "tool name", 256)
                    if type(function.get("arguments")) is not str or identity in used:
                        raise ValueError("tool calls require unique ids and string arguments")
                    used.add(identity)
                    pending.add(identity)
        groups[-1].append(message)
    if pending:
        raise ValueError("assistant call/result group is incomplete")
    return prefix, groups


def select_working_context(
    messages: list[dict[str, Any]], *, context_tokens: int,
    reserve_tokens: int = 2048, image_tokens: int = 1024,
) -> dict[str, Any]:
    """Keep the stable prefix, latest user group and preceding complete group.

    Add contiguous older groups when they fit. Never slice tool JSON or image
    messages. Media costs default to 1024 estimated tokens per structured media
    block/data URL and can be supplied by the host. On overflow, return the
    intact mandatory boundary with fits=False; do not send it automatically.
    """
    context_tokens = _integer(context_tokens, "context_tokens", 256, 2**24)
    reserve_tokens = _integer(reserve_tokens, "reserve_tokens", 0, context_tokens - 1)
    image_tokens = _integer(image_tokens, "image_tokens", 1, 65536)
    if type(messages) is not list or not 1 <= len(messages) <= 10000 or any(type(item) is not dict for item in messages):
        raise ValueError("messages must contain 1 to 10000 plain message objects")
    _structure(messages)
    prefix, groups = _groups(messages)
    if not groups:
        raise ValueError("a current user group is required")
    costs = [sum(_tokens(message, image_tokens) + 4 for message in group) for group in groups]
    prefix_cost = sum(_tokens(message, image_tokens) + 4 for message in prefix)
    start = max(0, len(groups) - 2)
    mandatory_cost = prefix_cost + sum(costs[start:])
    selected_cost = mandatory_cost
    budget = context_tokens - reserve_tokens
    if selected_cost <= budget:
        while start > 0 and selected_cost + costs[start - 1] <= budget:
            start -= 1
            selected_cost += costs[start]
    selected = [*prefix, *(message for group in groups[start:] for message in group)]
    return {
        "schema_version": 1, "messages": selected, "fits": mandatory_cost <= budget,
        "status": "ready" if mandatory_cost <= budget else "mandatory_boundary_exceeds_budget",
        "action": "caller_may_send" if mandatory_cost <= budget else "defer_or_increase_context",
        "input_estimated_tokens": prefix_cost + sum(costs), "output_estimated_tokens": selected_cost,
        "mandatory_estimated_tokens": mandatory_cost, "available_tokens": budget,
        "dropped_groups": start, "preserved_groups": len(groups) - start,
        "estimator": "text_chars_div_4_plus_structured_media_cost", "media_tokens": image_tokens,
        "mutated": False, "sent": False,
    }


def prepare_working_chat_request(
    request: dict[str, Any], *, context_tokens: int,
    reserve_tokens: int = 2048, image_tokens: int = 1024,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Pure opt-in adapter. All non-message request fields remain untouched."""
    if type(request) is not dict:
        raise ValueError("request must be an object")
    messages = request.get("messages")
    if not isinstance(messages, list):
        raise ValueError("request must contain a messages array")
    selected = select_working_context(messages, context_tokens=context_tokens,
                                      reserve_tokens=reserve_tokens, image_tokens=image_tokens)
    if not selected["fits"]:
        raise ValueError("mandatory context does not fit; defer or increase the context budget")
    result = dict(request)
    result["messages"] = selected["messages"]
    return result, {key: value for key, value in selected.items() if key != "messages"}


def _ids(value: object, name: str, maximum: int = 32) -> list[str]:
    if value is None:
        return []
    if type(value) is not list or len(value) > maximum:
        raise ValueError(f"{name} must contain at most {maximum} identifiers")
    result = [require_text(item, name, 256) for item in value]
    if len(set(result)) != len(result):
        raise ValueError(f"{name} must contain unique identifiers")
    return result


def _references(record: dict[str, Any]) -> list[dict[str, str]]:
    """Only explicit reference fields are edges; never infer links from prose."""
    payload = record["payload"]
    references = []
    for field in ("evidence", "verification", "members"):
        for item in payload.get(field, []):
            if type(item) is not dict or set(item) != {"kind", "id", "content_hash"}:
                raise ValueError("stored knowledge citation is malformed")
            references.append(item)
    for link in payload.get("links", []):
        references.append({"kind": "scroll_event", "id": link["target_id"],
                           "content_hash": link.get("content_hash", "")})
    for support in payload.get("support", []):
        references.append({"kind": "scroll_event", **support})
    if payload.get("asset_id"):
        # asset_hash binds original file bytes, not the enclosing Scroll record.
        references.append({"kind": "scroll_event", "id": payload["asset_id"], "content_hash": ""})
    if payload.get("source_symbol"):
        source = payload["source_symbol"]
        references.append({"kind": "scroll_event", "id": source["record_id"], "content_hash": source["content_hash"]})
    # State-head links are provenance edges as well as domain CAS identities.
    for field in ("procedure_id", "handoff_id", "collection_id"):
        if payload.get(field):
            references.append({"kind": "scroll_event", "id": payload[field], "content_hash": ""})
    return references


def _impact(root: Path, project_id: str, changed: list[str]) -> list[dict[str, Any]]:
    records = read_records(root, project_id=project_id)
    by_id = {record["id"]: record for record in records}
    if any(identity not in by_id for identity in changed):
        raise ValueError("changed record is unavailable in this project")
    stale: dict[str, set[str]] = {identity: set() for identity in by_id}
    latest: dict[tuple[str, str], str] = {}
    corrected: dict[str, str] = {}
    for record in records:
        if record["kind"] in {"project_file", "analysis_asset"}:
            latest[(record["kind"], record["payload"]["path"])] = record["id"]
        if record["kind"] in {"experience", "temporal_fact"} and record["payload"].get("corrects"):
            corrected[record["payload"]["corrects"]] = record["kind"]
    dependents: dict[str, set[str]] = {}
    source_cache: dict[tuple[str, str, str], bool] = {}
    for record in records:
        identity = record["id"]
        if identity in changed:
            stale[identity].add("explicit_change_signal")
        if identity in corrected:
            stale[identity].add("corrected_" + corrected[identity])
        if record["payload"].get("asset_id"):
            asset = by_id.get(record["payload"]["asset_id"])
            if (asset is None or asset["kind"] != "analysis_asset"
                    or asset["payload"]["source_hash"] != record["payload"]["asset_hash"]):
                stale[identity].add("asset_binding_unavailable_or_changed")
        if record["kind"] in {"project_file", "analysis_asset"} and latest[(record["kind"], record["payload"]["path"])] != identity:
            stale[identity].add("newer_recorded_input_version")
        for citation in _references(record):
            kind, target, digest = citation["kind"], citation["id"], citation["content_hash"]
            if kind == "scroll_event" and target in by_id:
                if digest and by_id[target]["content_hash"] != digest:
                    stale[identity].add("evidence_hash_changed")
                dependents.setdefault(target, set()).add(identity)
            else:
                key = (kind, target, digest)
                if key not in source_cache:
                    found = read_memory_source(root, kind=kind, source_id=target, content_hash=digest or None,
                                               project_id=project_id, limit=1)
                    source_cache[key] = found["found"]
                if not source_cache[key]:
                    stale[identity].add("evidence_unavailable")
    pending = deque(identity for identity, reasons in stale.items() if reasons)
    while pending:
        identity = pending.popleft()
        for dependent in sorted(dependents.get(identity, set())):
            if not stale[dependent]:
                pending.append(dependent)
            stale[dependent].add("linked_evidence_needs_review")
    return [{**record, "needs_review": bool(stale[record["id"]]),
             "review_reasons": sorted(stale[record["id"]])} for record in records]


def change_impact(
    root: Path, *, project_id: str, changed_record_ids: list[str] | None = None,
    token_budget: int = 2400,
) -> dict[str, Any]:
    """Propagate recorded-version/citation changes, without changing any claim."""
    changed = _ids(changed_record_ids, "changed_record_ids")
    records = _impact(root, project_id, changed)
    return bounded_results([record for record in reversed(records) if record["needs_review"]],
                           token_budget=token_budget,
                           extra={"project_id": project_id, "records_checked": len(records),
                                  "freshness": "recorded_versions_only", "auto_edit": False})


def compile_task_pack(
    root: Path, *, project_id: str, purpose: str = "resume",
    record_ids: list[str] | None = None, citations: list[dict[str, str]] | None = None,
    token_budget: int = 2400, expand_collections: bool = True,
) -> dict[str, Any]:
    """Compile explicitly selected evidence into stable, whole-record packets."""
    if type(purpose) is not str or purpose not in {"resume", "investigation", "review", "release"}:
        raise ValueError("unsupported task pack purpose")
    if type(expand_collections) is not bool:
        raise ValueError("expand_collections must be a boolean")
    identities = _ids(record_ids, "record_ids")
    exact = validate_evidence(root, project_id, citations)
    if not identities and not exact:
        raise ValueError("select at least one record or exact source citation")
    records = {record["id"]: record for record in _impact(root, project_id, [])}
    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for identity in identities:
        record = records.get(identity)
        if record is None:
            raise ValueError("selected record is unavailable in this project")
        validate_evidence(root, project_id, [{"kind": "scroll_event", "id": identity,
                                             "content_hash": record["content_hash"]}])
        selected.append({"record": {key: value for key, value in record.items() if key not in {"session_id", "order"}},
                         "citation": {"kind": "scroll_event", "id": identity, "content_hash": record["content_hash"]}})
        seen.add(("scroll_event", identity))
        if expand_collections and record["kind"] in {"collection", "collection_revision"}:
            for citation in validate_evidence(root, project_id, record["payload"]["members"]):
                if citation not in exact:
                    exact.append(citation)
            if len(exact) > 64:
                raise ValueError("select fewer collections; task packs support at most 64 expanded citations")
    for citation in exact:
        key = (citation["kind"], citation["id"])
        if key in seen:
            continue
        source = read_memory_source(root, kind=citation["kind"], source_id=citation["id"],
                                    content_hash=citation["content_hash"], project_id=project_id, limit=4000)
        if not source["found"]:
            raise ValueError("selected evidence changed during packet assembly")
        selected.append({"source": source, "citation": citation})
        seen.add(key)
    packet = bounded_results(selected, token_budget=token_budget,
                             extra={"project_id": project_id, "purpose": purpose,
                                    "freshness": "recorded_versions_only", "expanded_collections": expand_collections,
                                    "packet_sha256": "0" * 64})
    packet["packet_sha256"] = hashlib.sha256(json.dumps(
        {key: value for key, value in packet.items() if key != "packet_sha256"},
        sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
    return packet


def explain_memory(
    root: Path, *, project_id: str, query: str, source_id: str | None = None,
    kind: str = "scroll_event", limit: int = 8, token_budget: int = 2400,
) -> dict[str, Any]:
    """Explain a bounded retrieval, without exposing other projects' existence.

    A wider diagnostic candidate window distinguishes rank from packet budget.
    No-match outside that window is not proof that a source was never captured.
    """
    require_text(project_id, "project_id", 256)
    if type(kind) is not str or kind not in SOURCE_KINDS:
        raise ValueError("unsupported source kind")
    if source_id is not None:
        require_text(source_id, "source_id", 256)
    packet = recall_memory(root, query=query, project_id=project_id, limit=limit, token_budget=token_budget)
    diagnostics: dict[str, Any] = {"query_hash": hashlib.sha256(query.encode()).hexdigest(),
                                  "project_id": project_id, "reason": "retrieval_summary",
                                  "reason_scope": "requested_recall_packet",
                                  "retrieval": {key: value for key, value in packet.items() if key != "results"}}
    if source_id is not None:
        source = read_memory_source(root, kind=kind, source_id=source_id, project_id=project_id, limit=1)
        if not source["found"]:
            diagnostics["reason"] = "not_available_in_scope"
        elif any(item["id"] == source_id and item["kind"] == kind for item in packet["results"]):
            diagnostics["reason"] = "included"
        else:
            wide = recall_memory(root, query=query, project_id=project_id, limit=50, token_budget=32768)
            position = next((index for index, item in enumerate(wide["results"])
                             if item["id"] == source_id and item["kind"] == kind), None)
            if position is None:
                diagnostics["reason"] = "outside_diagnostic_window_or_no_match"
            elif position >= limit:
                diagnostics["reason"] = "ranked_below_limit"
            else:
                diagnostics["reason"] = "excluded_by_packet_budget"
            diagnostics["diagnostic_rank"] = None if position is None else position + 1
        if source["found"] and kind == "scroll_event":
            typed = next((row for row in _impact(root, project_id, []) if row["id"] == source_id), None)
            if typed is not None:
                diagnostics["needs_review"] = typed["needs_review"]
                diagnostics["review_reasons"] = typed["review_reasons"]
                diagnostics["source_state"] = ("superseded_recorded_evidence"
                    if any(reason.startswith(("newer_", "corrected_")) for reason in typed["review_reasons"])
                    else "retained_recorded_evidence")
    return bounded_results(packet["results"], token_budget=token_budget, extra=diagnostics)
