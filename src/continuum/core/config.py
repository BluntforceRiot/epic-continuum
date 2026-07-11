from __future__ import annotations

import hashlib
import ipaddress
import json
import math
from copy import deepcopy
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit

from .hardware import apply_inventory_overrides, detect_hardware, recommend_config
from .permissions import secure_mkdir, secure_write_text
from .units import parse_size
from .writer_claim import ensure_writer_claim


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[1] / "config.default.json"
CAPTURE_MODES = {"manual", "assisted", "automatic", "paranoid"}
CAPTURE_FLAG_BY_KIND = {
    "user_turn": "record_user_turns",
    "assistant_turn": "record_assistant_turns",
    "tool_call": "record_tool_calls",
    "tool_result": "record_tool_results",
}
# `summarize_and_link` is accepted only as a legacy alias for older configs.
LARGE_RESULT_POLICIES = {
    "truncate_with_notice",
    "summarize_and_link",
    "truncate",
    "skip",
}
PRUNE_POLICIES = {"ask", "manual", "auto_tier_only", "auto_prune"}
SNAPSHOT_RETENTION_POLICIES = {"last_20", "keep_all"}
PROOF_PACK_RETENTION_POLICIES = {"keep_successful_90_days", "keep_all"}
CATALOG_PROOF_MODES = {"state_manifest", "snapshot"}
YARN_BRIEFING_PROTOCOL_RESERVE_TOKENS = 512
MIN_YARN_USABLE_CONTEXT_TOKENS = 256
MIN_YARN_INPUT_TOKENS = 256
MAX_YARN_INPUT_TOKENS = 1_000_000
MIN_YARN_OUTPUT_TOKENS = 1
MAX_YARN_OUTPUT_TOKENS = 32768


def _integral_token_budget(value: Any, *, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if math.isfinite(value) and value.is_integer():
            return int(value)
        raise ValueError(f"{field} must be an integer")
    if isinstance(value, str):
        text = value.strip()
        digits = text[1:] if text.startswith(("+", "-")) else text
        if digits.isdigit():
            return int(text)
    raise ValueError(f"{field} must be an integer")


def validate_inference_base_url(value: Any, *, allow_remote: bool = False) -> str:
    text = str(value or "").strip().rstrip("/")
    if any(char in text for char in ("\r", "\n", "\x00")):
        raise ValueError(
            "local_inference.base_url contains a forbidden control character"
        )
    parsed = urlsplit(text)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("local_inference.base_url must be an HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(
            "local_inference.base_url must not contain credentials, query, or fragment"
        )
    try:
        parsed_port = parsed.port
    except ValueError:
        raise ValueError("local_inference.base_url has an invalid port") from None
    if parsed_port is not None and not 1 <= parsed_port <= 65535:
        raise ValueError("local_inference.base_url has an invalid port")
    if parsed.path != "/v1":
        raise ValueError("local_inference.base_url path must be /v1")
    hostname = parsed.hostname.casefold()
    try:
        address = ipaddress.ip_address(hostname)
        loopback = address.is_loopback and not getattr(address, "ipv4_mapped", None)
    except ValueError:
        loopback = False
    if not loopback and not allow_remote:
        raise ValueError(
            "local_inference.base_url must use a literal loopback address unless allow_remote_endpoint is true"
        )
    if not loopback and parsed.scheme != "https":
        raise ValueError("remote local_inference endpoints require HTTPS")
    return text


def validate_inference_model_identifier(value: Any) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 512 or any(ord(char) < 32 for char in text):
        raise ValueError(
            "local_inference.model must be a non-empty printable model identifier"
        )
    windows = PureWindowsPath(text)
    posix = PurePosixPath(text.replace("\\", "/"))
    local_uri = text.casefold().startswith(("file:", "vscode:", "vscode-insiders:"))
    relative_path = text.startswith(("./", "../", ".\\", "..\\"))
    model_file = text.casefold().endswith(
        (".gguf", ".ggml", ".safetensors", ".onnx", ".pth", ".pt", ".bin")
    )
    separator_path = "\\" in text or (
        "/" in text and any(char.isspace() for char in text)
    )
    if (
        windows.drive
        or windows.root
        or posix.is_absolute()
        or local_uri
        or relative_path
        or model_file
        or separator_path
    ):
        raise ValueError(
            "local_inference.model must be an alias, not a local path or file URI"
        )
    return text


def validate_yarn_token_budgets(
    max_input_tokens: Any,
    max_output_tokens: Any,
) -> tuple[int, int]:
    """Validate the local-model request budget and return normalized values."""
    input_tokens = _integral_token_budget(
        max_input_tokens,
        field="local_inference.max_input_tokens",
    )
    output_tokens = _integral_token_budget(
        max_output_tokens,
        field="local_inference.max_output_tokens",
    )
    if input_tokens < MIN_YARN_INPUT_TOKENS or input_tokens > MAX_YARN_INPUT_TOKENS:
        raise ValueError(
            "local_inference.max_input_tokens must be between "
            f"{MIN_YARN_INPUT_TOKENS} and {MAX_YARN_INPUT_TOKENS}"
        )
    if output_tokens < MIN_YARN_OUTPUT_TOKENS or output_tokens > MAX_YARN_OUTPUT_TOKENS:
        raise ValueError(
            "local_inference.max_output_tokens must be between "
            f"{MIN_YARN_OUTPUT_TOKENS} and {MAX_YARN_OUTPUT_TOKENS}"
        )
    minimum_input_tokens = (
        output_tokens
        + YARN_BRIEFING_PROTOCOL_RESERVE_TOKENS
        + MIN_YARN_USABLE_CONTEXT_TOKENS
    )
    if input_tokens < minimum_input_tokens:
        raise ValueError(
            "local_inference.max_input_tokens must leave at least "
            f"{MIN_YARN_USABLE_CONTEXT_TOKENS} usable context tokens after the "
            f"{YARN_BRIEFING_PROTOCOL_RESERVE_TOKENS}-token briefing reserve and "
            "max_output_tokens"
        )
    return input_tokens, output_tokens


def normalize_root_relative_config_path(value: Any, *, field: str) -> str:
    """Validate and normalize a configurable path that must remain under a root.

    Config files are portable between POSIX and Windows.  Treat both slash styles
    as separators and reject drive-qualified, UNC, absolute, empty, and parent-
    traversing paths on every platform rather than only on the host that happens
    to load the config.
    """
    text = str(value or "").strip()
    if not text or "\x00" in text:
        raise ValueError(f"{field} must be a non-empty root-relative path")
    windows = PureWindowsPath(text)
    normalized = text.replace("\\", "/")
    posix = PurePosixPath(normalized)
    if windows.is_absolute() or bool(windows.drive) or posix.is_absolute():
        raise ValueError(f"{field} must be root-relative")
    parts = posix.parts
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise ValueError(
            f"{field} must not contain empty, current, or parent path components"
        )
    return posix.as_posix()


def resolve_root_config_path(root: Path, value: Any, *, field: str) -> Path:
    """Resolve one validated config path and reject existing symlink escapes."""
    normalized = normalize_root_relative_config_path(value, field=field)
    candidate = root.joinpath(*PurePosixPath(normalized).parts)
    try:
        candidate.resolve(strict=False).relative_to(root.resolve(strict=False))
    except (OSError, ValueError):
        raise ValueError(f"{field} resolves outside the Continuum root") from None
    return candidate


def validate_config_root_paths(root: Path, config: dict[str, Any]) -> None:
    """Validate configured internal files against one concrete Continuum root."""
    atomic_memory = config.get("atomic_memory", {})
    resolve_root_config_path(
        root,
        atomic_memory.get("card_sidecar_dir", "catalog/cards"),
        field="atomic_memory.card_sidecar_dir",
    )
    security = config.get("security", {})
    resolve_root_config_path(
        root,
        security.get("ignore_file", ".continuumignore"),
        field="security.ignore_file",
    )
    resolve_root_config_path(
        root,
        security.get("secret_allowlist_file", "security/secret_allowlist.jsonl"),
        field="security.secret_allowlist_file",
    )


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
    validate_config_root_paths(root, config)
    ensure_writer_claim(root)
    path = config_path(root)
    secure_write_text(
        path,
        json.dumps(config, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def write_default_config(root: Path) -> Path:
    config_dir = root / "config"
    path = config_path(root)
    if not path.exists():
        ensure_writer_claim(root)
        secure_mkdir(root, secure_existing=True)
        secure_mkdir(config_dir, secure_existing=True)
        secure_write_text(
            path,
            json.dumps(default_config(), ensure_ascii=True, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
    return path


def load_config(root: Path) -> dict[str, Any]:
    path = write_default_config(root)
    user_config = json.loads(path.read_text(encoding="utf-8"))
    config = deep_merge(default_config(), user_config)
    validate_config(config)
    validate_config_root_paths(root, config)
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
    detected = apply_inventory_overrides(
        detected, vram=vram, system_ram=system_ram, drive_free=drive_free
    )
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


def configure_personal_profile(
    root: Path,
    *,
    name: str | None = None,
    safe_context_ceiling: int | None = None,
    resume_mode: str | None = None,
    default_project_id: str | None = None,
    clear_default_project: bool = False,
    assist_on_resume: bool | None = None,
) -> dict[str, Any]:
    config = load_config(root)
    profile = dict(config.get("personal_profile", {}))
    if name is not None:
        profile["name"] = str(name).strip()
    if safe_context_ceiling is not None:
        profile["safe_context_ceiling"] = int(safe_context_ceiling)
    if resume_mode is not None:
        profile["resume_mode"] = str(resume_mode)
    if clear_default_project:
        profile["default_project_id"] = None
    elif default_project_id is not None:
        profile["default_project_id"] = str(default_project_id).strip()
    if assist_on_resume is not None:
        profile["assist_on_resume"] = bool(assist_on_resume)
    config["personal_profile"] = profile
    write_config(root, config)
    return {"ok": True, "configured": True, "personal_profile": profile}


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
    policy = (
        "truncate_with_notice"
        if requested_policy == "summarize_and_link"
        else requested_policy
    )
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
        return stored, {
            **base_meta,
            "truncated": True,
            "stored_bytes": len(stored_bytes),
        }

    suffix = "\n\n[Continuum capture notice: truncated]"
    suffix_bytes = suffix.encode("utf-8")
    if max_bytes <= len(suffix_bytes):
        stored = suffix_bytes[:max_bytes].decode("utf-8", errors="ignore")
    else:
        clipped = encoded[: max_bytes - len(suffix_bytes)].decode(
            "utf-8", errors="ignore"
        )
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
    if context.get("card_recall_scope", "session") not in {
        "session",
        "global",
        "session_then_global",
        "project",
    }:
        raise ValueError(
            "context.card_recall_scope must be session, global, session_then_global, or project"
        )
    if default_budget > max_budget:
        raise ValueError("default_token_budget cannot exceed max_token_budget")
    local_inference = config.get("local_inference", {})
    for key in (
        "enabled",
        "allow_remote_endpoint",
        "assist_on_resume",
        "redact_secrets",
    ):
        if key in local_inference and not isinstance(local_inference[key], bool):
            raise ValueError(f"local_inference.{key} must be true or false")
    if local_inference.get("provider", "openai_compatible") != "openai_compatible":
        raise ValueError("local_inference.provider must be openai_compatible")
    validate_inference_model_identifier(local_inference.get("model", ""))
    validate_inference_base_url(
        local_inference.get("base_url", "http://127.0.0.1:8080/v1"),
        allow_remote=bool(local_inference.get("allow_remote_endpoint", False)),
    )
    validate_yarn_token_budgets(
        local_inference.get("max_input_tokens", MIN_YARN_INPUT_TOKENS),
        local_inference.get("max_output_tokens", MIN_YARN_OUTPUT_TOKENS),
    )
    for key, minimum, maximum in (
        ("timeout_seconds", 1, 3600),
        ("health_timeout_seconds", 1, 60),
        ("queue_wait_seconds", 0, 300),
        ("circuit_breaker_failures", 1, 100),
        ("circuit_breaker_cooldown_seconds", 1, 86400),
    ):
        value = int(local_inference.get(key, minimum))
        if value < minimum or value > maximum:
            raise ValueError(
                f"local_inference.{key} must be between {minimum} and {maximum}"
            )
    temperature = float(local_inference.get("temperature", 0.6))
    top_p = float(local_inference.get("top_p", 0.95))
    top_k = int(local_inference.get("top_k", 20))
    repeat_penalty = float(local_inference.get("repeat_penalty", 1.05))
    if not math.isfinite(temperature) or temperature <= 0.3 or temperature > 2.0:
        raise ValueError(
            "local_inference.temperature must be greater than 0.3 and at most 2.0"
        )
    if not math.isfinite(top_p) or top_p <= 0 or top_p > 1:
        raise ValueError("local_inference.top_p must be greater than 0 and at most 1")
    if top_k < 1 or top_k > 1000:
        raise ValueError("local_inference.top_k must be between 1 and 1000")
    if (
        not math.isfinite(repeat_penalty)
        or repeat_penalty < 0.5
        or repeat_penalty > 2.0
    ):
        raise ValueError("local_inference.repeat_penalty must be between 0.5 and 2.0")
    for key in ("min_free_system_ram", "min_free_vram"):
        if parse_size(local_inference.get(key, "1GB")) < 0:
            raise ValueError(f"local_inference.{key} must be non-negative")
    personal_profile = config.get("personal_profile", {})
    profile_name = str(personal_profile.get("name", "default")).strip()
    if not profile_name or len(profile_name) > 128:
        raise ValueError("personal_profile.name must be 1-128 characters")
    safe_context_ceiling = int(personal_profile.get("safe_context_ceiling", 32768))
    if safe_context_ceiling < 256 or safe_context_ceiling > max_budget:
        raise ValueError(
            "personal_profile.safe_context_ceiling must be between 256 and context.max_token_budget"
        )
    if personal_profile.get("resume_mode", "latest") not in {
        "latest",
        "latest_project",
        "explicit",
    }:
        raise ValueError(
            "personal_profile.resume_mode must be latest, latest_project, or explicit"
        )
    if "assist_on_resume" in personal_profile and not isinstance(
        personal_profile["assist_on_resume"], bool
    ):
        raise ValueError("personal_profile.assist_on_resume must be true or false")
    default_project = personal_profile.get("default_project_id")
    if default_project is not None and (
        not isinstance(default_project, str) or not default_project.strip()
    ):
        raise ValueError(
            "personal_profile.default_project_id must be null or a non-empty string"
        )
    capture = config.get("capture", {})
    mode = str(capture.get("mode", "automatic"))
    if mode not in CAPTURE_MODES:
        raise ValueError(
            "capture.mode must be manual, assisted, automatic, or paranoid"
        )
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
        if parse_size(capture["max_tool_result_bytes"]) <= 0:
            raise ValueError("capture.max_tool_result_bytes must be positive")
    if (
        capture.get("large_result_policy", "truncate_with_notice")
        not in LARGE_RESULT_POLICIES
    ):
        raise ValueError(
            "capture.large_result_policy must be truncate_with_notice, truncate, or skip"
        )
    retention = config.get("retention", {})
    for key in ("raw_scroll_hot_days", "raw_scroll_warm_days"):
        if int(retention.get(key, 0)) < 0:
            raise ValueError(f"retention.{key} must be non-negative")
    if int(retention.get("raw_scroll_warm_days", 0)) < int(
        retention.get("raw_scroll_hot_days", 0)
    ):
        raise ValueError(
            "retention.raw_scroll_warm_days must be >= raw_scroll_hot_days"
        )
    for key in ("keep_cards_forever", "delete_raw_evidence"):
        if key in retention and not isinstance(retention[key], bool):
            raise ValueError(f"retention.{key} must be true or false")
    if "max_root_size" in retention:
        parse_size(retention["max_root_size"])
    if retention.get("prune_policy", "ask") not in PRUNE_POLICIES:
        raise ValueError(
            "retention.prune_policy must be ask, manual, auto_tier_only, or auto_prune"
        )
    if (
        retention.get("snapshot_retention", "last_20")
        not in SNAPSHOT_RETENTION_POLICIES
    ):
        raise ValueError("retention.snapshot_retention must be last_20 or keep_all")
    if (
        retention.get("proof_pack_retention", "keep_successful_90_days")
        not in PROOF_PACK_RETENTION_POLICIES
    ):
        raise ValueError(
            "retention.proof_pack_retention must be keep_successful_90_days or keep_all"
        )
    if retention.get("delete_raw_evidence") and retention.get("prune_policy") not in {
        "ask",
        "manual",
    }:
        raise ValueError(
            "retention.delete_raw_evidence requires ask or manual prune_policy"
        )
    learning = config.get("learning", {})
    if int(learning.get("route_decay_min_interval_seconds", 0)) < 0:
        raise ValueError(
            "learning.route_decay_min_interval_seconds must be non-negative"
        )
    for key in (
        "route_decay_weight_factor",
        "route_decay_floor",
        "route_prune_weight_threshold",
    ):
        if key in learning:
            value = float(learning[key])
            if value < 0 or value > 1:
                raise ValueError(f"learning.{key} must be between 0 and 1")
    storage = config.get("storage", {})
    if "max_ingest_bytes" in storage:
        parse_size(storage["max_ingest_bytes"])
    atomic_memory = config.get("atomic_memory", {})
    if "write_card_sidecars" in atomic_memory and not isinstance(
        atomic_memory["write_card_sidecars"], bool
    ):
        raise ValueError("atomic_memory.write_card_sidecars must be true or false")
    normalize_root_relative_config_path(
        atomic_memory.get("card_sidecar_dir", "catalog/cards"),
        field="atomic_memory.card_sidecar_dir",
    )
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
    if security.get("redaction_profile", "portable") not in {
        "private",
        "portable",
        "shareable",
    }:
        raise ValueError(
            "security.redaction_profile must be private, portable, or shareable"
        )
    normalize_root_relative_config_path(
        security.get("ignore_file", ".continuumignore"),
        field="security.ignore_file",
    )
    normalize_root_relative_config_path(
        security.get("secret_allowlist_file", "security/secret_allowlist.jsonl"),
        field="security.secret_allowlist_file",
    )
    queues = config.get("queues", {})
    if int(queues.get("worker_lease_seconds", 300)) <= 0:
        raise ValueError("queues.worker_lease_seconds must be positive")
    epic_continuity = config.get("epic_continuity", {})
    if (
        epic_continuity.get("catalog_proof_mode", "state_manifest")
        not in CATALOG_PROOF_MODES
    ):
        raise ValueError(
            "epic_continuity.catalog_proof_mode must be state_manifest or snapshot"
        )
