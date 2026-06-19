from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from .hardware import apply_inventory_overrides, detect_hardware, recommend_config
from .permissions import secure_mkdir, secure_write_text
from .units import parse_size


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[1] / "config.default.json"
CAPTURE_MODES = {"manual", "assisted", "automatic", "paranoid"}
CAPTURE_FLAG_BY_KIND = {
    "user_turn": "record_user_turns",
    "assistant_turn": "record_assistant_turns",
    "tool_call": "record_tool_calls",
    "tool_result": "record_tool_results",
}
# `summarize_and_link` is accepted only as a legacy alias for older configs.
LARGE_RESULT_POLICIES = {"truncate_with_notice", "summarize_and_link", "truncate", "skip"}
PRUNE_POLICIES = {"ask", "manual", "auto_tier_only", "auto_prune"}
SNAPSHOT_RETENTION_POLICIES = {"last_20", "keep_all"}
PROOF_PACK_RETENTION_POLICIES = {"keep_successful_90_days", "keep_all"}


def deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    result = deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def default_config() -> dict[str, Any]:
    return json.loads(DEFAULT_CONFIG_PATH.read_text(encoding="utf-8"))


def config_path(root: Path) -> Path:
    return root / "config" / "continuum.config.json"


def write_config(root: Path, config: dict[str, Any]) -> Path:
    validate_config(config)
    path = config_path(root)
    secure_write_text(
        path,
        json.dumps(config, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def write_default_config(root: Path) -> Path:
    config_dir = root / "config"
    secure_mkdir(root)
    secure_mkdir(config_dir)
    path = config_path(root)
    if not path.exists():
        secure_write_text(
            path,
            json.dumps(default_config(), ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return path


def load_config(root: Path) -> dict[str, Any]:
    path = write_default_config(root)
    user_config = json.loads(path.read_text(encoding="utf-8"))
    config = deep_merge(default_config(), user_config)
    validate_config(config)
    return config


def optimize_config(
    root: Path,
    *,
    profile: str = "balanced",
    write: bool = False,
    inventory: dict[str, Any] | None = None,
    vram: str | None = None,
    system_ram: str | None = None,
    drive_free: str | None = None,
) -> dict[str, Any]:
    current = load_config(root)
    detected = inventory if inventory is not None else detect_hardware(root)
    detected = apply_inventory_overrides(detected, vram=vram, system_ram=system_ram, drive_free=drive_free)
    recommendation = recommend_config(current, detected, profile=profile)
    optimized = deep_merge(current, recommendation["overrides"])
    validate_config(optimized)
    path = config_path(root)
    if write:
        write_config(root, optimized)
    return {
        "ok": True,
        "wrote": write,
        "profile": profile,
        "config_path": str(path),
        "detected_hardware": detected,
        "notes": recommendation["notes"],
        "recommended_config": optimized,
    }


def capture_policy(root: Path) -> dict[str, Any]:
    return deepcopy(load_config(root).get("capture", {}))


def retention_policy(root: Path) -> dict[str, Any]:
    return deepcopy(load_config(root).get("retention", {}))


def should_capture(root: Path, kind: str, *, explicit: bool = False) -> bool:
    capture = capture_policy(root)
    mode = str(capture.get("mode", "automatic"))
    if mode == "manual" and not explicit:
        return False
    flag = CAPTURE_FLAG_BY_KIND.get(kind)
    if flag and not bool(capture.get(flag, True)):
        return False
    if mode == "assisted" and kind in {"tool_call", "tool_result"} and not explicit:
        return False
    return True


def trim_tool_result_for_capture(root: Path, text: str) -> tuple[str, dict[str, Any]]:
    capture = capture_policy(root)
    max_bytes = parse_size(capture.get("max_tool_result_bytes", "256KB"))
    encoded = text.encode("utf-8")
    requested_policy = str(capture.get("large_result_policy", "truncate_with_notice"))
    policy = "truncate_with_notice" if requested_policy == "summarize_and_link" else requested_policy
    base_meta = {
        "original_bytes": len(encoded),
        "original_sha256": hashlib.sha256(encoded).hexdigest(),
        "large_result_policy": policy,
    }
    if requested_policy != policy:
        base_meta["legacy_large_result_policy"] = requested_policy
    if len(encoded) <= max_bytes:
        return text, {**base_meta, "truncated": False, "stored_bytes": len(encoded)}
    if policy == "skip":
        return "", {**base_meta, "truncated": True, "skipped": True, "stored_bytes": 0}
    if policy == "truncate":
        stored = encoded[:max_bytes].decode("utf-8", errors="ignore")
        stored_bytes = stored.encode("utf-8")
        while len(stored_bytes) > max_bytes:
            stored = stored[:-1]
            stored_bytes = stored.encode("utf-8")
        return stored, {**base_meta, "truncated": True, "stored_bytes": len(stored_bytes)}

    suffix = "\n\n[Continuum capture notice: truncated]"
    suffix_bytes = suffix.encode("utf-8")
    if max_bytes <= len(suffix_bytes):
        stored = suffix_bytes[:max_bytes].decode("utf-8", errors="ignore")
    else:
        clipped = encoded[: max_bytes - len(suffix_bytes)].decode("utf-8", errors="ignore")
        stored = f"{clipped}{suffix}"
    stored_bytes = stored.encode("utf-8")
    while len(stored_bytes) > max_bytes:
        stored = stored[:-1]
        stored_bytes = stored.encode("utf-8")
    return stored, {**base_meta, "truncated": True, "stored_bytes": len(stored_bytes)}


def validate_config(config: dict[str, Any]) -> None:
    hardware = config.get("hardware", {})
    for tier_name in ("vram", "system_ram", "nvme"):
        for key, value in hardware.get(tier_name, {}).items():
            if key == "notes":
                continue
            parse_size(value)
    context = config.get("context", {})
    default_budget = int(context.get("default_token_budget", 0))
    max_budget = int(context.get("max_token_budget", 0))
    reserve = int(context.get("reserve_output_tokens", 0))
    scroll_event_fetch_limit = int(context.get("scroll_event_fetch_limit", 0))
    if default_budget <= 0 or max_budget <= 0 or reserve < 0:
        raise ValueError("context token budgets must be positive")
    if scroll_event_fetch_limit <= 0:
        raise ValueError("context.scroll_event_fetch_limit must be positive")
    if context.get("card_recall_scope", "session_then_global") not in {"session", "global", "session_then_global", "project"}:
        raise ValueError("context.card_recall_scope must be session, global, session_then_global, or project")
    if default_budget > max_budget:
        raise ValueError("default_token_budget cannot exceed max_token_budget")
    capture = config.get("capture", {})
    mode = str(capture.get("mode", "automatic"))
    if mode not in CAPTURE_MODES:
        raise ValueError("capture.mode must be manual, assisted, automatic, or paranoid")
    for key in (
        "record_user_turns",
        "record_assistant_turns",
        "record_tool_calls",
        "record_tool_results",
        "snapshot_on_task_start",
        "snapshot_on_task_finish",
    ):
        if key in capture and not isinstance(capture[key], bool):
            raise ValueError(f"capture.{key} must be true or false")
    roll_segments_every_events = int(capture.get("roll_segments_every_events", 0))
    if roll_segments_every_events <= 0:
        raise ValueError("capture.roll_segments_every_events must be positive")
    if int(capture.get("dedup_window_seconds", 0)) < 0:
        raise ValueError("capture.dedup_window_seconds must be non-negative")
    if "max_tool_result_bytes" in capture:
        parse_size(capture["max_tool_result_bytes"])
    if capture.get("large_result_policy", "truncate_with_notice") not in LARGE_RESULT_POLICIES:
        raise ValueError("capture.large_result_policy must be truncate_with_notice, truncate, or skip")
    retention = config.get("retention", {})
    for key in ("raw_scroll_hot_days", "raw_scroll_warm_days"):
        if int(retention.get(key, 0)) < 0:
            raise ValueError(f"retention.{key} must be non-negative")
    if int(retention.get("raw_scroll_warm_days", 0)) < int(retention.get("raw_scroll_hot_days", 0)):
        raise ValueError("retention.raw_scroll_warm_days must be >= raw_scroll_hot_days")
    for key in ("keep_cards_forever", "delete_raw_evidence"):
        if key in retention and not isinstance(retention[key], bool):
            raise ValueError(f"retention.{key} must be true or false")
    if "max_root_size" in retention:
        parse_size(retention["max_root_size"])
    if retention.get("prune_policy", "ask") not in PRUNE_POLICIES:
        raise ValueError("retention.prune_policy must be ask, manual, auto_tier_only, or auto_prune")
    if retention.get("snapshot_retention", "last_20") not in SNAPSHOT_RETENTION_POLICIES:
        raise ValueError("retention.snapshot_retention must be last_20 or keep_all")
    if retention.get("proof_pack_retention", "keep_successful_90_days") not in PROOF_PACK_RETENTION_POLICIES:
        raise ValueError("retention.proof_pack_retention must be keep_successful_90_days or keep_all")
    if retention.get("delete_raw_evidence") and retention.get("prune_policy") not in {"ask", "manual"}:
        raise ValueError("retention.delete_raw_evidence requires ask or manual prune_policy")
    learning = config.get("learning", {})
    if int(learning.get("route_decay_min_interval_seconds", 0)) < 0:
        raise ValueError("learning.route_decay_min_interval_seconds must be non-negative")
    for key in ("route_decay_weight_factor", "route_decay_floor", "route_prune_weight_threshold"):
        if key in learning:
            value = float(learning[key])
            if value < 0 or value > 1:
                raise ValueError(f"learning.{key} must be between 0 and 1")
    storage = config.get("storage", {})
    if "max_ingest_bytes" in storage:
        parse_size(storage["max_ingest_bytes"])
    security = config.get("security", {})
    if security.get("secret_scan_action", "block") not in {"warn", "block", "off"}:
        raise ValueError("security.secret_scan_action must be warn, block, or off")
    if "secret_audit_max_file_bytes" in security:
        parse_size(security["secret_audit_max_file_bytes"])
    if int(security.get("secret_audit_max_findings", 1)) <= 0:
        raise ValueError("security.secret_audit_max_findings must be positive")
    if int(security.get("entropy_min_length", 32)) <= 0:
        raise ValueError("security.entropy_min_length must be positive")
    if float(security.get("entropy_min_bits_per_char", 4.5)) <= 0:
        raise ValueError("security.entropy_min_bits_per_char must be positive")
    if security.get("redaction_profile", "portable") not in {"private", "portable", "shareable"}:
        raise ValueError("security.redaction_profile must be private, portable, or shareable")
    queues = config.get("queues", {})
    if int(queues.get("worker_lease_seconds", 300)) <= 0:
        raise ValueError("queues.worker_lease_seconds must be positive")
