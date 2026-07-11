from __future__ import annotations

import hashlib
import http.client
import json
import os
import re
import secrets
import socket
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .config import (
    YARN_BRIEFING_PROTOCOL_RESERVE_TOKENS,
    load_config,
    validate_inference_base_url,
    validate_inference_model_identifier,
    validate_yarn_token_budgets,
    write_config,
)
from .hardware import detect_available_system_ram_bytes, detect_free_vram_bytes
from .safety import redact_text_secrets, scan_text_for_secrets
from .units import format_size, parse_size


DEFAULT_YARN_MODEL = "continuum-qwythos-q4"
YARN_MODEL_SOURCE = "empero-ai/Qwythos-9B-Claude-Mythos-5-1M-GGUF:Q4_K_M"
DEFAULT_YARN_BASE_URL = "http://127.0.0.1:8080/v1"
MAX_HTTP_RESPONSE_BYTES = 128 * 1024
MAX_HTTP_REQUEST_BYTES = 256 * 1024
MAX_JSON_NESTING = 64


class LocalModelError(RuntimeError):
    pass


_CircuitKey = tuple[str, str, str, str]
_CIRCUITS: dict[_CircuitKey, dict[str, float | int]] = {}
_CIRCUIT_LOCK = threading.Lock()
_INFERENCE_GATE = threading.BoundedSemaphore(1)


def _settings(root: Path) -> dict[str, Any]:
    from .config import config_path, deep_merge, default_config, validate_config

    path = config_path(root)
    config = default_config()
    if path.exists():
        try:
            user_config = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LocalModelError(
                "Continuum configuration is unavailable or invalid"
            ) from exc
        if not isinstance(user_config, dict):
            raise LocalModelError("Continuum configuration must be a JSON object")
        config = deep_merge(config, user_config)
    validate_config(config)
    return dict(config.get("local_inference", {}))


def _safe_settings(settings: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in settings.items()
        if key not in {"api_key", "authorization", "token"}
    }


def _portable_model_text(root: Path, text: str) -> str:
    root_variants = {str(root)}
    try:
        root_variants.add(str(root.expanduser().resolve(strict=False)))
    except OSError:
        pass
    root_patterns = [
        re.escape(value)
        for value in root_variants
        if value and value not in {".", ".."}
    ]
    root_alternative = "|".join(sorted(root_patterns, key=len, reverse=True))
    root_branch = rf"(?:{root_alternative})[^\r\n\"'<>|]*|" if root_alternative else ""
    local_reference = re.compile(
        rf"""(?ix)
        (?<![A-Za-z0-9_])
        (?:
            {root_branch}(?:file|vscode|vscode-insiders):(?://)?[^\r\n\"'<>|]*
            |[A-Z]:[\\/][^\r\n\"'<>|]*
            |\\\\[^\r\n\"'<>|]*
            |(?<!http:)(?<!https:)//[^\r\n\"'<>|]*
            |(?<!/)/(?!/)[^\r\n\"'<>|]*
            |~(?:[A-Za-z0-9_.-]+)?[\\/][^\r\n\"'<>|]*
        )
        """,
    )
    return local_reference.sub("<local-path-redacted>", str(text))


def _safe_model_identifier(root: Path, value: Any) -> str:
    text = str(value)
    try:
        validate_inference_model_identifier(text)
    except ValueError:
        return "<local-model-id-redacted>"
    return redact_text_secrets(_portable_model_text(root, text))


def _pseudonymous_outbound_id(request_id: str, kind: str, value: str) -> str:
    digest = hashlib.sha256(
        f"{request_id}\x00{kind}\x00{value}".encode("utf-8")
    ).hexdigest()
    return f"{kind}_{digest[:24]}"


def configure_yarn(
    root: Path,
    *,
    enabled: bool,
    base_url: str = DEFAULT_YARN_BASE_URL,
    model: str = DEFAULT_YARN_MODEL,
    max_input_tokens: int = 16384,
    max_output_tokens: int = 768,
    timeout_seconds: int = 90,
    allow_remote_endpoint: bool = False,
    assist_on_resume: bool = True,
) -> dict[str, Any]:
    validated_base_url = validate_inference_base_url(
        base_url, allow_remote=allow_remote_endpoint
    )
    model = validate_inference_model_identifier(model)
    if scan_text_for_secrets(model, max_findings=1):
        raise ValueError("Yarn model alias must not contain secret-like text")
    max_input_tokens, max_output_tokens = validate_yarn_token_budgets(
        max_input_tokens,
        max_output_tokens,
    )
    config = load_config(root)
    config["local_inference"] = {
        **dict(config.get("local_inference", {})),
        "enabled": bool(enabled),
        "profile": "yarn-qwythos-v3",
        "provider": "openai_compatible",
        "base_url": validated_base_url,
        "model": model,
        "max_input_tokens": max_input_tokens,
        "max_output_tokens": max_output_tokens,
        "timeout_seconds": int(timeout_seconds),
        "allow_remote_endpoint": bool(allow_remote_endpoint),
    }
    personal_profile = dict(config.get("personal_profile", {}))
    personal_profile["assist_on_resume"] = bool(enabled and assist_on_resume)
    context_maximum = int(
        dict(config.get("context", {})).get("max_token_budget", max_input_tokens)
    )
    usable_input_tokens = (
        max_input_tokens - max_output_tokens - YARN_BRIEFING_PROTOCOL_RESERVE_TOKENS
    )
    personal_profile["safe_context_ceiling"] = min(
        usable_input_tokens,
        context_maximum,
    )
    config["personal_profile"] = personal_profile
    write_config(root, config)
    return {
        "ok": True,
        "configured": True,
        "settings": _safe_settings(dict(config["local_inference"])),
    }


def _circuit_key(root: Path, settings: dict[str, Any]) -> _CircuitKey:
    try:
        canonical_root = root.expanduser().resolve(strict=False)
    except OSError:
        canonical_root = root.expanduser().absolute()
    root_key = os.path.normcase(os.path.normpath(str(canonical_root)))
    parsed = urlsplit(str(settings["base_url"]))
    hostname = str(parsed.hostname or "").casefold()
    if ":" in hostname:
        hostname = f"[{hostname}]"
    port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
    origin = f"{parsed.scheme.casefold()}://{hostname}:{port}"
    return (
        root_key,
        str(settings.get("profile", "yarn-qwythos-v3")),
        str(settings.get("model", "")),
        origin,
    )


def _circuit_status(root: Path, settings: dict[str, Any]) -> tuple[bool, int]:
    key = _circuit_key(root, settings)
    cooldown = max(1, int(settings.get("circuit_breaker_cooldown_seconds", 120)))
    with _CIRCUIT_LOCK:
        state = dict(_CIRCUITS.get(key, {}))
    opened_at = float(state.get("opened_at", 0.0))
    if not opened_at:
        return True, 0
    remaining = max(0, int(cooldown - (time.monotonic() - opened_at)))
    if remaining <= 0:
        with _CIRCUIT_LOCK:
            _CIRCUITS.pop(key, None)
        return True, 0
    return False, remaining


def _record_success(root: Path, settings: dict[str, Any]) -> None:
    with _CIRCUIT_LOCK:
        _CIRCUITS.pop(_circuit_key(root, settings), None)


def _record_failure(root: Path, settings: dict[str, Any]) -> None:
    key = _circuit_key(root, settings)
    threshold = max(1, int(settings.get("circuit_breaker_failures", 3)))
    with _CIRCUIT_LOCK:
        state = _CIRCUITS.setdefault(key, {"failures": 0, "opened_at": 0.0})
        failures = int(state.get("failures", 0)) + 1
        state["failures"] = failures
        if failures >= threshold and not float(state.get("opened_at", 0.0)):
            state["opened_at"] = time.monotonic()


def _http_json(
    *,
    method: str,
    url: str,
    timeout_seconds: int,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data: bytes | None = None
    headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode(
            "utf-8"
        )
        if len(data) > MAX_HTTP_REQUEST_BYTES:
            raise LocalModelError("local model request exceeds the byte safety ceiling")
        headers["Content-Type"] = "application/json"
    api_key = str(os.environ.get("CONTINUUM_LOCAL_MODEL_API_KEY") or "").strip()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.query
        or parsed.fragment
    ):
        raise LocalModelError("local model request URL is invalid")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    connection_class = (
        http.client.HTTPSConnection
        if parsed.scheme == "https"
        else http.client.HTTPConnection
    )
    timeout = max(1, int(timeout_seconds))
    connection = connection_class(parsed.hostname, port, timeout=timeout)
    deadline = time.monotonic() + timeout
    cancelled = threading.Event()
    outcome: list[dict[str, Any] | Exception] = []

    def remaining_timeout() -> float:
        remaining = deadline - time.monotonic()
        if cancelled.is_set() or remaining <= 0:
            raise LocalModelError("local model endpoint exceeded the total deadline")
        return max(0.001, remaining)

    def request_once() -> None:
        response: http.client.HTTPResponse | None = None
        try:
            connection.request(method, parsed.path or "/", body=data, headers=headers)
            remaining_timeout()
            if connection.sock is not None:
                connection.sock.settimeout(remaining_timeout())
            response = connection.getresponse()
            remaining_timeout()
            if response.status != 200:
                raise LocalModelError(
                    f"local model endpoint returned HTTP {response.status}"
                )
            content_type = (
                str(response.getheader("Content-Type") or "")
                .split(";", 1)[0]
                .strip()
                .casefold()
            )
            if content_type != "application/json":
                raise LocalModelError(
                    "local model endpoint returned a non-JSON content type"
                )
            content_encoding = (
                str(response.getheader("Content-Encoding") or "identity")
                .strip()
                .casefold()
            )
            if content_encoding not in {"", "identity"}:
                raise LocalModelError("compressed local model responses are refused")
            content_length = response.getheader("Content-Length")
            if content_length:
                try:
                    declared_length = int(content_length)
                except ValueError as exc:
                    raise LocalModelError(
                        "local model response has an invalid Content-Length"
                    ) from exc
                if declared_length < 0 or declared_length > MAX_HTTP_RESPONSE_BYTES:
                    raise LocalModelError(
                        "local model response exceeds the byte safety ceiling"
                    )
            chunks: list[bytes] = []
            total = 0
            while True:
                if connection.sock is not None:
                    connection.sock.settimeout(remaining_timeout())
                else:
                    remaining_timeout()
                chunk = response.read(min(65536, MAX_HTTP_RESPONSE_BYTES + 1 - total))
                remaining_timeout()
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_HTTP_RESPONSE_BYTES:
                    raise LocalModelError(
                        "local model response exceeds the byte safety ceiling"
                    )
            body = b"".join(chunks)
            try:
                decoded = body.decode("utf-8", errors="strict")
                result = _strict_json_loads(decoded)
            except (
                UnicodeDecodeError,
                json.JSONDecodeError,
                RecursionError,
                ValueError,
            ) as exc:
                raise LocalModelError(
                    "local model endpoint returned invalid UTF-8 JSON"
                ) from exc
            if not isinstance(result, dict):
                raise LocalModelError(
                    "local model endpoint returned a non-object response"
                )
            outcome.append(result)
        except LocalModelError as exc:
            outcome.append(exc)
        except (http.client.HTTPException, socket.timeout, TimeoutError, OSError):
            if cancelled.is_set() or time.monotonic() >= deadline:
                outcome.append(
                    LocalModelError("local model endpoint exceeded the total deadline")
                )
            else:
                outcome.append(
                    LocalModelError("local model endpoint is unavailable or timed out")
                )
        except (
            Exception
        ) as exc:  # Preserve unexpected implementation errors in the calling thread.
            outcome.append(exc)
        finally:
            if response is not None:
                response.close()
            connection.close()

    worker = threading.Thread(
        target=request_once, name="continuum-local-http", daemon=True
    )
    worker.start()
    worker.join(timeout=max(0.0, deadline - time.monotonic()))
    if worker.is_alive():
        cancelled.set()
        connection.close()
        raise LocalModelError("local model endpoint exceeded the total deadline")
    if not outcome:
        raise LocalModelError("local model endpoint is unavailable or timed out")
    result_or_error = outcome[0]
    if isinstance(result_or_error, Exception):
        raise result_or_error
    return result_or_error


def _strict_json_loads(text: str) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant: {value}")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_NESTING:
                raise ValueError(
                    f"JSON nesting exceeds the safety ceiling of {MAX_JSON_NESTING}"
                )
        elif character in "]}":
            depth = max(0, depth - 1)
    try:
        return json.loads(
            text, parse_constant=reject_constant, object_pairs_hook=unique_object
        )
    except RecursionError as exc:
        raise ValueError(
            f"JSON nesting exceeds the safety ceiling of {MAX_JSON_NESTING}"
        ) from exc


def _resource_guard(settings: dict[str, Any]) -> dict[str, Any]:
    free_ram, ram_source = detect_available_system_ram_bytes()
    free_vram, vram_source = detect_free_vram_bytes()
    required_ram = parse_size(settings.get("min_free_system_ram", "4GB"))
    required_vram = parse_size(settings.get("min_free_vram", "1GB"))
    ram_safe = free_ram is None or free_ram >= required_ram
    vram_safe = free_vram is None or free_vram >= required_vram
    return {
        "safe": ram_safe and vram_safe,
        "system_ram": {
            "free_bytes": free_ram,
            "free_display": format_size(free_ram) if free_ram is not None else None,
            "minimum_bytes": required_ram,
            "source": ram_source,
            "safe": ram_safe,
        },
        "vram": {
            "free_bytes": free_vram,
            "free_display": format_size(free_vram) if free_vram is not None else None,
            "minimum_bytes": required_vram,
            "source": vram_source,
            "safe": vram_safe,
        },
        "unknown_resources_are_advisory": True,
    }


def _model_ids(payload: dict[str, Any]) -> list[str]:
    rows = payload.get("data")
    if not isinstance(rows, list):
        return []
    return [
        str(row.get("id")) for row in rows if isinstance(row, dict) and row.get("id")
    ]


def local_model_health(root: Path, *, probe: bool = True) -> dict[str, Any]:
    settings = _settings(root)
    enabled = bool(settings.get("enabled", False))
    result: dict[str, Any] = {
        "ok": True,
        "enabled": enabled,
        "ready": False,
        "endpoint_ready": False,
        "profile": settings.get("profile", "yarn-qwythos-v3"),
        "provider": settings.get("provider", "openai_compatible"),
        "base_url": settings.get("base_url"),
        "configured_model": _safe_model_identifier(root, settings.get("model")),
        "fallback": "deterministic",
    }
    if not enabled:
        result["reason"] = "disabled"
        return result
    available, cooldown = _circuit_status(root, settings)
    result["circuit_open"] = not available
    result["retry_after_seconds"] = cooldown
    resources = _resource_guard(settings)
    result["resource_guard"] = resources
    if not resources["safe"]:
        result.update(
            {
                "ok": False,
                "reason": "insufficient_resource_headroom",
            }
        )
        return result
    if not probe:
        result.update(
            {
                "ok": available,
                "reason": "probe_not_requested" if available else "circuit_open",
            }
        )
        return result
    try:
        health = _http_json(
            method="GET",
            url=f"{str(settings['base_url']).rstrip('/')}/health",
            timeout_seconds=int(settings.get("health_timeout_seconds", 3)),
        )
        if health.get("status") != "ok":
            raise LocalModelError("local model health endpoint did not report ready")
        models = _http_json(
            method="GET",
            url=f"{str(settings['base_url']).rstrip('/')}/models",
            timeout_seconds=int(settings.get("health_timeout_seconds", 3)),
        )
        ids = _model_ids(models)
        configured_model = str(settings.get("model") or "")
        identity_verified = configured_model in ids
        inference_ready = identity_verified and available
        result.update(
            {
                "reachable": True,
                "served_models": [
                    _safe_model_identifier(root, model_id) for model_id in ids[:20]
                ],
                "identity_verified": identity_verified,
                "endpoint_ready": identity_verified,
                "ready": inference_ready,
                "ok": inference_ready,
                "reason": (
                    "configured_model_not_advertised"
                    if not identity_verified
                    else (None if available else "circuit_open")
                ),
            }
        )
        return result
    except LocalModelError as exc:
        result.update(
            {
                "ok": False,
                "reachable": False,
                "reason": str(exc),
                "error_type": type(exc).__name__,
            }
        )
        return result


def _extract_message_content(response: dict[str, Any]) -> str:
    choices = response.get("choices")
    if (
        not isinstance(choices, list)
        or len(choices) != 1
        or not isinstance(choices[0], dict)
    ):
        raise LocalModelError(
            "local model response must contain exactly one completion choice"
        )
    if choices[0].get("finish_reason") != "stop":
        raise LocalModelError("local model response did not finish cleanly")
    message = choices[0].get("message")
    if isinstance(message, dict) and (
        message.get("tool_calls") or message.get("function_call")
    ):
        raise LocalModelError("local model response attempted a tool call")
    content = (
        message.get("content") if isinstance(message, dict) else choices[0].get("text")
    )
    if not isinstance(content, str) or not content.strip():
        raise LocalModelError("local model response has no text content")
    return content.strip()


def _validate_resume_briefing(
    payload: Any,
    *,
    request_id: str,
    context_sha256: str,
    model_id: str,
    allowed_evidence_ids: set[str],
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise LocalModelError("Yarn briefing must be a JSON object")
    if (
        payload.get("request_id") != request_id
        or payload.get("context_sha256") != context_sha256
    ):
        raise LocalModelError("Yarn briefing failed request binding validation")
    if (
        payload.get("schema_version") != "continuum.yarn_briefing.v1"
        or payload.get("model_id") != model_id
    ):
        raise LocalModelError("Yarn briefing failed schema or model binding validation")
    expected_keys = {
        "schema_version",
        "request_id",
        "context_sha256",
        "model_id",
        "citations",
        "summary",
        "decisions",
        "next_actions",
        "risks",
        "confidence",
    }
    if set(payload) != expected_keys:
        raise LocalModelError("Yarn briefing contains missing or unexpected fields")
    summary = payload.get("summary")
    confidence = payload.get("confidence")
    if not isinstance(summary, str) or not summary.strip() or len(summary) > 4000:
        raise LocalModelError("Yarn briefing summary is invalid")
    if confidence not in {"low", "medium", "high"}:
        raise LocalModelError("Yarn briefing confidence is invalid")
    result: dict[str, Any] = {
        "schema_version": "continuum.yarn_briefing.v1",
        "request_id": request_id,
        "context_sha256": context_sha256,
        "model_id": model_id,
        "summary": summary.strip(),
        "confidence": confidence,
    }
    citations = payload.get("citations")
    if (
        not isinstance(citations, list)
        or len(citations) > 100
        or not all(isinstance(value, str) for value in citations)
        or len(citations) != len(set(citations))
        or any(value not in allowed_evidence_ids for value in citations)
        or (allowed_evidence_ids and not citations)
    ):
        raise LocalModelError("Yarn briefing citations are invalid")
    result["citations"] = citations
    for key in ("decisions", "next_actions", "risks"):
        values = payload.get(key)
        if (
            not isinstance(values, list)
            or len(values) > 20
            or not all(
                isinstance(value, str) and len(value) <= 1000 for value in values
            )
        ):
            raise LocalModelError(f"Yarn briefing {key} is invalid")
        result[key] = [value.strip() for value in values if value.strip()]
    return result


def assist_resume(
    root: Path,
    *,
    context_text: str,
    session_id: str,
    project_id: str | None,
    evidence_ids: list[str] | None = None,
) -> dict[str, Any]:
    settings = _settings(root)
    if not bool(settings.get("enabled", False)):
        return {
            "ok": False,
            "used": False,
            "reason": "disabled",
            "fallback": "deterministic",
        }
    available, cooldown = _circuit_status(root, settings)
    if not available:
        return {
            "ok": False,
            "used": False,
            "reason": "circuit_open",
            "retry_after_seconds": cooldown,
            "fallback": "deterministic",
        }
    max_input_tokens, max_output_tokens = validate_yarn_token_budgets(
        settings.get("max_input_tokens", 32768),
        settings.get("max_output_tokens", 768),
    )
    usable_input_tokens = (
        max_input_tokens - max_output_tokens - YARN_BRIEFING_PROTOCOL_RESERVE_TOKENS
    )
    estimated_tokens = (len(context_text) + 3) // 4
    if estimated_tokens > usable_input_tokens:
        return {
            "ok": False,
            "used": False,
            "reason": "input_budget_exceeded",
            "estimated_tokens": estimated_tokens,
            "max_input_tokens": max_input_tokens,
            "usable_input_tokens": usable_input_tokens,
            "fallback": "deterministic",
        }
    safe_context = _portable_model_text(root, context_text)
    safe_context = (
        redact_text_secrets(safe_context)
        if bool(settings.get("redact_secrets", True))
        else safe_context
    )
    if scan_text_for_secrets(safe_context, max_findings=1):
        return {
            "ok": False,
            "used": False,
            "reason": "outbound_secret_detected",
            "fallback": "deterministic",
        }
    gate_acquired = _INFERENCE_GATE.acquire(
        timeout=max(0, int(settings.get("queue_wait_seconds", 2)))
    )
    if not gate_acquired:
        return {
            "ok": False,
            "used": False,
            "reason": "inference_busy",
            "fallback": "deterministic",
        }
    context_sha256 = hashlib.sha256(safe_context.encode("utf-8")).hexdigest()
    request_id = secrets.token_hex(16)
    unique_evidence_ids = list(
        dict.fromkeys(str(value) for value in (evidence_ids or []))
    )
    evidence_aliases: dict[str, str] = {}
    for index, evidence_id in enumerate(unique_evidence_ids, start=1):
        alias = _pseudonymous_outbound_id(request_id, f"evidence_{index}", evidence_id)
        evidence_aliases[alias] = evidence_id
    outbound_evidence_ids = list(evidence_aliases)
    system_prompt = (
        "You are Yarn, an optional non-authoritative briefing layer for Epic Continuum. "
        "Use only the supplied evidence. Never invent facts, IDs, decisions, or tasks. "
        "Cite only allowed_evidence_ids. Return exactly one schema-valid JSON object with all requested fields."
    )
    user_payload = {
        "schema_version": "continuum.yarn_briefing.v1",
        "request_id": request_id,
        "context_sha256": context_sha256,
        "session_id": _pseudonymous_outbound_id(request_id, "session", session_id),
        "project_id": (
            _pseudonymous_outbound_id(request_id, "project", project_id)
            if project_id is not None
            else None
        ),
        "allowed_evidence_ids": outbound_evidence_ids,
        "evidence": safe_context,
    }
    briefing_schema = {
        "type": "object",
        "required": [
            "schema_version",
            "request_id",
            "context_sha256",
            "model_id",
            "citations",
            "summary",
            "decisions",
            "next_actions",
            "risks",
            "confidence",
        ],
        "properties": {
            "schema_version": {"type": "string", "const": "continuum.yarn_briefing.v1"},
            "request_id": {"type": "string", "const": request_id},
            "context_sha256": {"type": "string", "const": context_sha256},
            "model_id": {"type": "string", "const": str(settings["model"])},
            "citations": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": outbound_evidence_ids,
                },
                "uniqueItems": True,
                "maxItems": 100,
            },
            "summary": {"type": "string", "maxLength": 4000},
            "decisions": {
                "type": "array",
                "items": {"type": "string", "maxLength": 1000},
                "maxItems": 20,
            },
            "next_actions": {
                "type": "array",
                "items": {"type": "string", "maxLength": 1000},
                "maxItems": 20,
            },
            "risks": {
                "type": "array",
                "items": {"type": "string", "maxLength": 1000},
                "maxItems": 20,
            },
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
        },
        "additionalProperties": False,
    }
    request_payload = {
        "model": settings["model"],
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=True)},
        ],
        "temperature": float(settings.get("temperature", 0.6)),
        "top_p": float(settings.get("top_p", 0.95)),
        "top_k": int(settings.get("top_k", 20)),
        "repeat_penalty": float(settings.get("repeat_penalty", 1.05)),
        "max_tokens": max_output_tokens,
        "n": 1,
        "stream": False,
        "seed": 0,
        "chat_template_kwargs": {"enable_thinking": False},
        "parse_tool_calls": False,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "continuum_resume_briefing",
                "strict": True,
                "schema": briefing_schema,
            },
        },
    }
    try:
        health = local_model_health(root, probe=True)
        if not health.get("ready"):
            if health.get("reason") not in {
                "insufficient_resource_headroom",
                "probe_not_requested",
                "circuit_open",
            }:
                _record_failure(root, settings)
            return {
                "ok": False,
                "used": False,
                "reason": str(health.get("reason") or "model_not_ready"),
                "fallback": "deterministic",
                "health": health,
            }
        response = _http_json(
            method="POST",
            url=f"{str(settings['base_url']).rstrip('/')}/chat/completions",
            timeout_seconds=int(settings.get("timeout_seconds", 90)),
            payload=request_payload,
        )
        response_model = str(response.get("model") or "")
        if response_model != str(settings["model"]):
            raise LocalModelError(
                "local model response identity does not match the configured model"
            )
        content = _extract_message_content(response)
        try:
            parsed = _strict_json_loads(content)
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            if (
                isinstance(exc, RecursionError)
                or "nesting exceeds" in str(exc).casefold()
            ):
                raise LocalModelError(
                    "Yarn briefing exceeded the JSON nesting safety ceiling"
                ) from exc
            raise LocalModelError("Yarn briefing is not valid JSON") from exc
        briefing = _validate_resume_briefing(
            parsed,
            request_id=request_id,
            context_sha256=context_sha256,
            model_id=str(settings["model"]),
            allowed_evidence_ids=set(outbound_evidence_ids),
        )
        if scan_text_for_secrets(
            json.dumps(briefing, ensure_ascii=True), max_findings=1
        ):
            raise LocalModelError("Yarn briefing contained secret-like output")
        briefing["citations"] = [
            evidence_aliases[citation] for citation in briefing["citations"]
        ]
        _record_success(root, settings)
        return {
            "ok": True,
            "used": True,
            "profile": settings.get("profile", "yarn-qwythos-v3"),
            "model": response_model,
            "authority": "non_authoritative_inference",
            "briefing": briefing,
            "fallback": None,
        }
    except (LocalModelError, RecursionError) as exc:
        error = (
            exc
            if isinstance(exc, LocalModelError)
            else LocalModelError(
                "Yarn briefing exceeded the JSON nesting safety ceiling"
            )
        )
        _record_failure(root, settings)
        return {
            "ok": False,
            "used": False,
            "reason": "model_request_failed",
            "detail": str(error),
            "error_type": type(error).__name__,
            "fallback": "deterministic",
        }
    finally:
        _INFERENCE_GATE.release()
