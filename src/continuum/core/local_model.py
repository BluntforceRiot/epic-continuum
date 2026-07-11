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
from typing import Any, Callable, TypeVar, cast
from urllib.parse import urlsplit

from .config import (
    MIN_YARN_USABLE_CONTEXT_TOKENS,
    load_config,
    merge_user_config,
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
MAX_YARN_EVIDENCE_IDS = 100
YARN_INPUT_TRUNCATION_NOTICE = (
    "\n\n[Continuum Yarn input truncated to fit serialized request limits.]"
)
TOTAL_DEADLINE_ERROR = "local model operation exceeded the total deadline"
CONFIGURATION_BOOTSTRAP_SECONDS = 1.0


_T = TypeVar("_T")


def _estimate_tokens(text: str) -> int:
    return (len(text) + 3) // 4


def _serialize_request_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


class LocalModelError(RuntimeError):
    pass


def _remaining_deadline_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise LocalModelError(TOTAL_DEADLINE_ERROR)
    return remaining


class _LocalStageRunner:
    """Run deadline-bound local work without creating a thread per timeout."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._pending: tuple[
            Callable[[], Any],
            threading.Event,
            list[Any],
            list[Exception],
        ] | None = None
        self._active = False
        self._thread = threading.Thread(
            target=self._work,
            name="continuum-local-stage-runner",
            daemon=True,
        )
        self._thread.start()

    def _work(self) -> None:
        while True:
            with self._condition:
                while self._pending is None:
                    self._condition.wait()
                callback, completed, results, errors = self._pending
                self._pending = None
                self._active = True
            try:
                results.append(callback())
            except Exception as exc:
                errors.append(exc)
            finally:
                with self._condition:
                    self._active = False
                    completed.set()
                    self._condition.notify_all()

    def run(self, deadline: float, callback: Callable[[], _T]) -> _T:
        """Run one stage, waiting at most until the absolute deadline."""
        completed = threading.Event()
        results: list[Any] = []
        errors: list[Exception] = []
        with self._condition:
            while self._active or self._pending is not None:
                self._condition.wait(
                    timeout=_remaining_deadline_seconds(deadline)
                )
            _remaining_deadline_seconds(deadline)
            self._pending = (callback, completed, results, errors)
            self._condition.notify()
        if not completed.wait(timeout=_remaining_deadline_seconds(deadline)):
            raise LocalModelError(TOTAL_DEADLINE_ERROR)
        _remaining_deadline_seconds(deadline)
        if errors:
            raise errors[0]
        if not results:
            raise LocalModelError("local model deadline stage returned no result")
        return cast(_T, results[0])

    def wait_idle(self, timeout_seconds: float) -> bool:
        """Wait for test or shutdown coordination without accepting more work."""
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        with self._condition:
            while self._active or self._pending is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(timeout=remaining)
            return True


_CircuitKey = tuple[str, str, str, str]
_CIRCUITS: dict[_CircuitKey, dict[str, float | int]] = {}
_CIRCUIT_LOCK = threading.Lock()
_INFERENCE_GATE = threading.BoundedSemaphore(1)
_LOCAL_STAGE_RUNNER_GUARD = threading.Lock()
_LOCAL_STAGE_RUNNER: _LocalStageRunner | None = None


def _local_stage_runner() -> _LocalStageRunner:
    """Return the one deadline-stage runner owned by this process."""

    global _LOCAL_STAGE_RUNNER
    runner = _LOCAL_STAGE_RUNNER
    if runner is not None:
        return runner
    with _LOCAL_STAGE_RUNNER_GUARD:
        runner = _LOCAL_STAGE_RUNNER
        if runner is None:
            runner = _LocalStageRunner()
            _LOCAL_STAGE_RUNNER = runner
        return runner


def _reset_local_model_after_fork() -> None:
    """Discard thread-backed parent state without starting threads in the child."""

    global _CIRCUIT_LOCK, _INFERENCE_GATE, _LOCAL_STAGE_RUNNER_GUARD
    global _LOCAL_STAGE_RUNNER
    _CIRCUIT_LOCK = threading.Lock()
    _INFERENCE_GATE = threading.BoundedSemaphore(1)
    _LOCAL_STAGE_RUNNER_GUARD = threading.Lock()
    _LOCAL_STAGE_RUNNER = None


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_local_model_after_fork)


def _configuration(root: Path) -> dict[str, Any]:
    from .config import config_path, validate_config

    path = config_path(root)
    user_config: dict[str, Any] = {}
    if path.exists():
        try:
            user_config = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LocalModelError(
                "Continuum configuration is unavailable or invalid"
            ) from exc
        if not isinstance(user_config, dict):
            raise LocalModelError("Continuum configuration must be a JSON object")
    config = merge_user_config(user_config)
    validate_config(config)
    return config


def _settings(root: Path) -> dict[str, Any]:
    config = _configuration(root)
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


def _integral_timeout(value: Any) -> int:
    if isinstance(value, bool):
        raise ValueError("local_inference.timeout_seconds must be an integer")
    if isinstance(value, int):
        timeout = value
    elif isinstance(value, float) and value.is_integer():
        timeout = int(value)
    elif isinstance(value, str):
        text = value.strip()
        digits = text[1:] if text.startswith(("+", "-")) else text
        if not digits.isdigit():
            raise ValueError("local_inference.timeout_seconds must be an integer")
        timeout = int(text)
    else:
        raise ValueError("local_inference.timeout_seconds must be an integer")
    if timeout < 1 or timeout > 3600:
        raise ValueError("local_inference.timeout_seconds must be between 1 and 3600")
    return timeout


def resolve_yarn_configuration(
    root: Path,
    *,
    base_url: str | None = None,
    model: str | None = None,
    max_input_tokens: int | None = None,
    max_output_tokens: int | None = None,
    timeout_seconds: int | None = None,
    allow_remote_endpoint: bool | None = None,
) -> dict[str, Any]:
    """Resolve optional Yarn overrides without creating or changing a root."""
    settings = _settings(root)
    if allow_remote_endpoint is not None and not isinstance(allow_remote_endpoint, bool):
        raise ValueError("local_inference.allow_remote_endpoint must be true or false")
    resolved_remote = (
        bool(settings.get("allow_remote_endpoint", False))
        if allow_remote_endpoint is None
        else allow_remote_endpoint
    )
    resolved_base_url = validate_inference_base_url(
        settings.get("base_url", DEFAULT_YARN_BASE_URL) if base_url is None else base_url,
        allow_remote=resolved_remote,
    )
    resolved_model = validate_inference_model_identifier(
        settings.get("model", DEFAULT_YARN_MODEL) if model is None else model
    )
    if scan_text_for_secrets(resolved_model, max_findings=1):
        raise ValueError("Yarn model alias must not contain secret-like text")
    resolved_input, resolved_output = validate_yarn_token_budgets(
        settings.get("max_input_tokens", 16384) if max_input_tokens is None else max_input_tokens,
        settings.get("max_output_tokens", 768) if max_output_tokens is None else max_output_tokens,
    )
    resolved_timeout = _integral_timeout(
        settings.get("timeout_seconds", 90) if timeout_seconds is None else timeout_seconds
    )
    return {
        "base_url": resolved_base_url,
        "model": resolved_model,
        "max_input_tokens": resolved_input,
        "max_output_tokens": resolved_output,
        "timeout_seconds": resolved_timeout,
        "allow_remote_endpoint": resolved_remote,
    }


def configure_yarn(
    root: Path,
    *,
    enabled: bool,
    base_url: str | None = None,
    model: str | None = None,
    max_input_tokens: int | None = None,
    max_output_tokens: int | None = None,
    timeout_seconds: int | None = None,
    allow_remote_endpoint: bool | None = None,
    assist_on_resume: bool | None = None,
) -> dict[str, Any]:
    configuration_changed = any(
        value is not None
        for value in (
            base_url,
            model,
            max_input_tokens,
            max_output_tokens,
            timeout_seconds,
            allow_remote_endpoint,
        )
    )
    resolved = resolve_yarn_configuration(
        root,
        base_url=base_url,
        model=model,
        max_input_tokens=max_input_tokens,
        max_output_tokens=max_output_tokens,
        timeout_seconds=timeout_seconds,
        allow_remote_endpoint=allow_remote_endpoint,
    )
    preview = _configuration(root)
    context_maximum = int(
        dict(preview.get("context", {})).get("max_token_budget", resolved["max_input_tokens"])
    )
    prospective_settings = {
        **dict(preview.get("local_inference", {})),
        **resolved,
        "enabled": bool(enabled),
        "profile": "yarn-qwythos-v3",
        "provider": "openai_compatible",
    }
    if not enabled and not configuration_changed:
        safe_context_ceiling = int(
            dict(preview.get("personal_profile", {})).get("safe_context_ceiling", context_maximum)
        )
    else:
        safe_context_ceiling = _automatic_safe_context_ceiling(
            prospective_settings,
            context_maximum=context_maximum,
        )
        if safe_context_ceiling < MIN_YARN_USABLE_CONTEXT_TOKENS:
            raise ValueError(
                "local_inference token and transport budgets must leave at least "
                f"{MIN_YARN_USABLE_CONTEXT_TOKENS} usable context tokens after "
                "serialized Yarn request overhead"
            )
    config = load_config(root)
    config["local_inference"] = {
        **dict(config.get("local_inference", {})),
        "enabled": bool(enabled),
        "profile": "yarn-qwythos-v3",
        "provider": "openai_compatible",
        **resolved,
    }
    personal_profile = dict(config.get("personal_profile", {}))
    personal_profile["assist_on_resume"] = bool(
        enabled and (True if assist_on_resume is None else assist_on_resume)
    )
    personal_profile["safe_context_ceiling"] = safe_context_ceiling
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
    timeout_seconds: float,
    payload: dict[str, Any] | None = None,
    deadline: float | None = None,
) -> dict[str, Any]:
    request_deadline = time.monotonic() + max(0.001, float(timeout_seconds))
    if deadline is not None:
        request_deadline = min(request_deadline, deadline)
    _remaining_deadline_seconds(request_deadline)
    data: bytes | None = None
    headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
    if payload is not None:
        data = _serialize_request_payload(payload)
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
    connection = connection_class(
        parsed.hostname,
        port,
        timeout=_remaining_deadline_seconds(request_deadline),
    )
    cancelled = threading.Event()
    outcome: list[dict[str, Any] | Exception] = []

    def remaining_timeout() -> float:
        if cancelled.is_set():
            raise LocalModelError(TOTAL_DEADLINE_ERROR)
        return _remaining_deadline_seconds(request_deadline)

    def request_once() -> None:
        response: http.client.HTTPResponse | None = None
        try:
            remaining_timeout()
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
            remaining_timeout()
            outcome.append(result)
        except LocalModelError as exc:
            outcome.append(exc)
        except (http.client.HTTPException, socket.timeout, TimeoutError, OSError):
            if cancelled.is_set() or time.monotonic() >= request_deadline:
                outcome.append(LocalModelError(TOTAL_DEADLINE_ERROR))
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

    try:
        _local_stage_runner().run(request_deadline, request_once)
    except LocalModelError:
        cancelled.set()
        connection.close()
        raise
    _remaining_deadline_seconds(request_deadline)
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
    return _local_model_health(root, settings=_settings(root), probe=probe)


def _local_model_health(
    root: Path,
    *,
    settings: dict[str, Any],
    probe: bool,
    deadline: float | None = None,
) -> dict[str, Any]:
    if deadline is not None:
        _remaining_deadline_seconds(deadline)
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
    try:
        resources = (
            _resource_guard(settings)
            if deadline is None
            else _local_stage_runner().run(
                deadline,
                lambda: _resource_guard(settings),
            )
        )
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
        health_timeout = float(settings.get("health_timeout_seconds", 3))
        health_remaining = (
            health_timeout
            if deadline is None
            else min(health_timeout, _remaining_deadline_seconds(deadline))
        )
        health = _http_json(
            method="GET",
            url=f"{str(settings['base_url']).rstrip('/')}/health",
            timeout_seconds=health_remaining,
            deadline=deadline,
        )
        if deadline is not None:
            _remaining_deadline_seconds(deadline)
        if health.get("status") != "ok":
            raise LocalModelError("local model health endpoint did not report ready")
        model_remaining = (
            health_timeout
            if deadline is None
            else min(health_timeout, _remaining_deadline_seconds(deadline))
        )
        models = _http_json(
            method="GET",
            url=f"{str(settings['base_url']).rstrip('/')}/models",
            timeout_seconds=model_remaining,
            deadline=deadline,
        )
        if deadline is not None:
            _remaining_deadline_seconds(deadline)
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


def _bounded_evidence_ids(
    evidence_ids: list[str] | None,
    *,
    limit: int = MAX_YARN_EVIDENCE_IDS,
) -> list[str]:
    bounded_limit = max(0, min(int(limit), MAX_YARN_EVIDENCE_IDS))
    return list(dict.fromkeys(str(value) for value in (evidence_ids or [])))[
        :bounded_limit
    ]


def _build_resume_request_payload(
    settings: dict[str, Any],
    *,
    safe_context: str,
    session_id: str,
    project_id: str | None,
    evidence_ids: list[str],
    request_id: str,
    context_sha256: str,
    max_output_tokens: int,
) -> tuple[dict[str, Any], dict[str, str]]:
    evidence_aliases: dict[str, str] = {}
    for index, evidence_id in enumerate(evidence_ids, start=1):
        alias = _pseudonymous_outbound_id(request_id, f"evidence_{index}", evidence_id)
        evidence_aliases[alias] = evidence_id
    outbound_evidence_ids = list(evidence_aliases)
    citation_items: dict[str, Any] = {"type": "string"}
    if outbound_evidence_ids:
        citation_items["enum"] = outbound_evidence_ids
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
                "items": citation_items,
                "uniqueItems": True,
                "maxItems": len(outbound_evidence_ids),
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
    return (
        {
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
        },
        evidence_aliases,
    )


def _request_metrics(payload: dict[str, Any]) -> tuple[int, int]:
    serialized = _serialize_request_payload(payload)
    return len(serialized), _estimate_tokens(serialized.decode("ascii"))


def _representative_serialized_markdown_context(context_tokens: int) -> str:
    """Return representative escape-heavy generated Looking Glass evidence."""
    token_count = max(0, int(context_tokens))
    if token_count == 0:
        return ""
    target_chars = token_count * 4
    representative_block = (
        "## recent_scroll\n"
        "```json\n"
        '{"authority":"non_authoritative_evidence",'
        '"content":"Decision: preserve value\\\\with\\\\slashes and '
        '\\"quoted\\" JSON.",'
        '"created_at":"2026-07-10T12:34:56+00:00",'
        '"event_type":"message","project_id":"project","role":"user",'
        '"seq":1,"session_id":"session","source":"scroll_event",'
        '"visibility_scope":"project"}\n'
        "```\n"
    )
    repeat_count = (target_chars + len(representative_block) - 1) // len(
        representative_block
    )
    return (representative_block * repeat_count)[:target_chars]


def _representative_evidence_ids(count: int) -> list[str]:
    return [f"evidence-{index}" for index in range(max(0, int(count)))]


def _representative_request_fits(
    settings: dict[str, Any],
    *,
    context_tokens: int,
    evidence_id_count: int,
    max_input_tokens: int,
    max_output_tokens: int,
) -> bool:
    payload, _aliases = _build_resume_request_payload(
        settings,
        safe_context=_representative_serialized_markdown_context(context_tokens),
        session_id="session",
        project_id="project",
        evidence_ids=_representative_evidence_ids(evidence_id_count),
        request_id="0" * 32,
        context_sha256="0" * 64,
        max_output_tokens=max_output_tokens,
    )
    request_bytes, estimated_input_tokens = _request_metrics(payload)
    return (
        request_bytes <= MAX_HTTP_REQUEST_BYTES
        and estimated_input_tokens <= max_input_tokens - max_output_tokens
    )


def _automatic_yarn_evidence_id_limit(settings: dict[str, Any]) -> int:
    """Return the largest alias count that preserves the minimum safe context."""
    max_input_tokens, max_output_tokens = validate_yarn_token_budgets(
        settings.get("max_input_tokens", 16384),
        settings.get("max_output_tokens", 768),
    )
    low = 0
    high = MAX_YARN_EVIDENCE_IDS
    while low < high:
        candidate = (low + high + 1) // 2
        if _representative_request_fits(
            settings,
            context_tokens=MIN_YARN_USABLE_CONTEXT_TOKENS,
            evidence_id_count=candidate,
            max_input_tokens=max_input_tokens,
            max_output_tokens=max_output_tokens,
        ):
            low = candidate
        else:
            high = candidate - 1
    return low


def _automatic_safe_context_ceiling(
    settings: dict[str, Any],
    *,
    context_maximum: int,
) -> int:
    max_input_tokens, max_output_tokens = validate_yarn_token_budgets(
        settings.get("max_input_tokens", 16384),
        settings.get("max_output_tokens", 768),
    )
    input_allowance = max_input_tokens - max_output_tokens
    upper = max(
        0,
        min(context_maximum, input_allowance, MAX_HTTP_REQUEST_BYTES // 4),
    )
    evidence_id_limit = _automatic_yarn_evidence_id_limit(settings)

    def fits(context_tokens: int) -> bool:
        return _representative_request_fits(
            settings,
            context_tokens=context_tokens,
            evidence_id_count=evidence_id_limit,
            max_input_tokens=max_input_tokens,
            max_output_tokens=max_output_tokens,
        )

    low = 0
    high = upper
    while low < high:
        candidate = (low + high + 1) // 2
        if fits(candidate):
            low = candidate
        else:
            high = candidate - 1
    return low


def assist_resume(
    root: Path,
    *,
    context_text: str,
    session_id: str,
    project_id: str | None,
    evidence_ids: list[str] | None = None,
) -> dict[str, Any]:
    operation_started = time.monotonic()

    def deadline_failure(exc: LocalModelError) -> dict[str, Any]:
        return {
            "ok": False,
            "used": False,
            "reason": "model_request_failed",
            "detail": str(exc),
            "error_type": type(exc).__name__,
            "fallback": "deterministic",
        }

    try:
        config = _local_stage_runner().run(
            operation_started + CONFIGURATION_BOOTSTRAP_SECONDS,
            lambda: _configuration(root),
        )
    except LocalModelError as exc:
        if str(exc) != TOTAL_DEADLINE_ERROR:
            raise
        return deadline_failure(exc)
    settings = dict(config.get("local_inference", {}))
    operation_deadline = operation_started + _integral_timeout(
        settings.get("timeout_seconds", 90)
    )
    try:
        _remaining_deadline_seconds(operation_deadline)
    except LocalModelError as exc:
        return deadline_failure(exc)
    if not bool(settings.get("enabled", False)):
        return {
            "ok": False,
            "used": False,
            "reason": "disabled",
            "fallback": "deterministic",
        }

    def prepare_inputs() -> tuple[str, dict[str, Any]]:
        available, cooldown = _circuit_status(root, settings)
        if not available:
            return (
                "result",
                {
                    "ok": False,
                    "used": False,
                    "reason": "circuit_open",
                    "retry_after_seconds": cooldown,
                    "fallback": "deterministic",
                },
            )
        safe_context_ceiling = int(
            dict(config.get("personal_profile", {})).get(
                "safe_context_ceiling",
                config["context"]["max_token_budget"],
            )
        )
        max_input_tokens, max_output_tokens = validate_yarn_token_budgets(
            settings.get("max_input_tokens", 32768),
            settings.get("max_output_tokens", 768),
        )
        requested_estimated_tokens = _estimate_tokens(str(context_text))
        safe_context = _portable_model_text(root, context_text)
        safe_context = (
            redact_text_secrets(safe_context)
            if bool(settings.get("redact_secrets", True))
            else safe_context
        )
        if scan_text_for_secrets(safe_context, max_findings=1):
            return (
                "result",
                {
                    "ok": False,
                    "used": False,
                    "reason": "outbound_secret_detected",
                    "fallback": "deterministic",
                },
            )
        original_safe_context = safe_context
        original_estimated_tokens = _estimate_tokens(safe_context)
        unique_evidence_ids = list(
            dict.fromkeys(str(value) for value in (evidence_ids or []))
        )
        evidence_id_limit = _automatic_yarn_evidence_id_limit(settings)
        bounded_evidence_ids = _bounded_evidence_ids(
            unique_evidence_ids,
            limit=evidence_id_limit,
        )
        request_id = secrets.token_hex(16)
        input_token_allowance = max_input_tokens - max_output_tokens

        def prepare_request(
            candidate_context: str,
        ) -> tuple[dict[str, Any], dict[str, str], str, int, int]:
            candidate_hash = hashlib.sha256(
                candidate_context.encode("utf-8")
            ).hexdigest()
            candidate_payload, candidate_aliases = _build_resume_request_payload(
                settings,
                safe_context=candidate_context,
                session_id=session_id,
                project_id=project_id,
                evidence_ids=bounded_evidence_ids,
                request_id=request_id,
                context_sha256=candidate_hash,
                max_output_tokens=max_output_tokens,
            )
            candidate_bytes, candidate_tokens = _request_metrics(candidate_payload)
            return (
                candidate_payload,
                candidate_aliases,
                candidate_hash,
                candidate_bytes,
                candidate_tokens,
            )

        (
            request_payload,
            evidence_aliases,
            context_sha256,
            request_bytes,
            estimated_input_tokens,
        ) = prepare_request(safe_context)
        input_truncated = False
        input_chars_omitted = 0
        exceeds_serialized_budget = (
            estimated_input_tokens > input_token_allowance
            or request_bytes > MAX_HTTP_REQUEST_BYTES
        )
        if (
            exceeds_serialized_budget
            and requested_estimated_tokens <= safe_context_ceiling
            and original_safe_context
        ):
            low = 0
            high = len(original_safe_context) - 1
            best: tuple[
                str,
                int,
                dict[str, Any],
                dict[str, str],
                str,
                int,
                int,
            ] | None = None
            while low <= high:
                prefix_length = (low + high) // 2
                candidate_context = (
                    original_safe_context[:prefix_length]
                    + YARN_INPUT_TRUNCATION_NOTICE
                )
                (
                    candidate_payload,
                    candidate_aliases,
                    candidate_hash,
                    candidate_bytes,
                    candidate_tokens,
                ) = prepare_request(candidate_context)
                if (
                    candidate_tokens <= input_token_allowance
                    and candidate_bytes <= MAX_HTTP_REQUEST_BYTES
                ):
                    best = (
                        candidate_context,
                        prefix_length,
                        candidate_payload,
                        candidate_aliases,
                        candidate_hash,
                        candidate_bytes,
                        candidate_tokens,
                    )
                    low = prefix_length + 1
                else:
                    high = prefix_length - 1
            if best is not None:
                (
                    safe_context,
                    retained_chars,
                    request_payload,
                    evidence_aliases,
                    context_sha256,
                    request_bytes,
                    estimated_input_tokens,
                ) = best
                input_truncated = True
                input_chars_omitted = len(original_safe_context) - retained_chars
                exceeds_serialized_budget = False

        if (
            requested_estimated_tokens > safe_context_ceiling
            or exceeds_serialized_budget
        ):
            if request_bytes > MAX_HTTP_REQUEST_BYTES:
                detail = "serialized_request_byte_budget_exceeded"
            elif estimated_input_tokens > input_token_allowance:
                detail = "serialized_input_token_budget_exceeded"
            else:
                detail = "configured_safe_context_ceiling_exceeded"
            return (
                "result",
                {
                    "ok": False,
                    "used": False,
                    "reason": "input_budget_exceeded",
                    "detail": detail,
                    "estimated_tokens": original_estimated_tokens,
                    "estimated_input_tokens": estimated_input_tokens,
                    "safe_context_ceiling": safe_context_ceiling,
                    "max_input_tokens": max_input_tokens,
                    "max_output_tokens": max_output_tokens,
                    "usable_input_tokens": input_token_allowance,
                    "request_bytes": request_bytes,
                    "max_request_bytes": MAX_HTTP_REQUEST_BYTES,
                    "evidence_id_count": len(bounded_evidence_ids),
                    "evidence_id_limit": evidence_id_limit,
                    "evidence_ids_omitted": (
                        len(unique_evidence_ids) - len(bounded_evidence_ids)
                    ),
                    "fallback": "deterministic",
                },
            )
        return (
            "prepared",
            {
                "safe_context": safe_context,
                "original_estimated_tokens": original_estimated_tokens,
                "requested_estimated_tokens": requested_estimated_tokens,
                "unique_evidence_ids": unique_evidence_ids,
                "evidence_id_limit": evidence_id_limit,
                "bounded_evidence_ids": bounded_evidence_ids,
                "request_id": request_id,
                "request_payload": request_payload,
                "evidence_aliases": evidence_aliases,
                "context_sha256": context_sha256,
                "request_bytes": request_bytes,
                "estimated_input_tokens": estimated_input_tokens,
                "input_truncated": input_truncated,
                "input_chars_omitted": input_chars_omitted,
            },
        )

    try:
        preparation_kind, preparation = _local_stage_runner().run(
            operation_deadline, prepare_inputs
        )
    except LocalModelError as exc:
        if str(exc) == TOTAL_DEADLINE_ERROR:
            return deadline_failure(exc)
        raise
    if preparation_kind == "result":
        return preparation
    safe_context = str(preparation["safe_context"])
    original_estimated_tokens = int(preparation["original_estimated_tokens"])
    requested_estimated_tokens = int(preparation["requested_estimated_tokens"])
    unique_evidence_ids = list(preparation["unique_evidence_ids"])
    evidence_id_limit = int(preparation["evidence_id_limit"])
    bounded_evidence_ids = list(preparation["bounded_evidence_ids"])
    request_id = str(preparation["request_id"])
    request_payload = dict(preparation["request_payload"])
    evidence_aliases = dict(preparation["evidence_aliases"])
    context_sha256 = str(preparation["context_sha256"])
    request_bytes = int(preparation["request_bytes"])
    estimated_input_tokens = int(preparation["estimated_input_tokens"])
    input_truncated = bool(preparation["input_truncated"])
    input_chars_omitted = int(preparation["input_chars_omitted"])
    outbound_evidence_ids = list(evidence_aliases)
    try:
        gate_wait = min(
            max(0.0, float(settings.get("queue_wait_seconds", 2))),
            _remaining_deadline_seconds(operation_deadline),
        )
    except LocalModelError as exc:
        return deadline_failure(exc)
    gate_acquired = _INFERENCE_GATE.acquire(timeout=gate_wait)
    if not gate_acquired:
        if time.monotonic() >= operation_deadline:
            return {
                "ok": False,
                "used": False,
                "reason": "model_request_failed",
                "detail": TOTAL_DEADLINE_ERROR,
                "error_type": LocalModelError.__name__,
                "fallback": "deterministic",
            }
        return {
            "ok": False,
            "used": False,
            "reason": "inference_busy",
            "fallback": "deterministic",
        }
    try:
        _remaining_deadline_seconds(operation_deadline)
        health = _local_model_health(
            root,
            settings=settings,
            probe=True,
            deadline=operation_deadline,
        )
        _remaining_deadline_seconds(operation_deadline)
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
            timeout_seconds=_remaining_deadline_seconds(operation_deadline),
            payload=request_payload,
            deadline=operation_deadline,
        )
        _remaining_deadline_seconds(operation_deadline)

        def parse_and_validate() -> tuple[str, dict[str, Any]]:
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
            return response_model, briefing

        response_model, briefing = _local_stage_runner().run(
            operation_deadline, parse_and_validate
        )
        _remaining_deadline_seconds(operation_deadline)
        _record_success(root, settings)
        return {
            "ok": True,
            "used": True,
            "profile": settings.get("profile", "yarn-qwythos-v3"),
            "model": response_model,
            "authority": "non_authoritative_inference",
            "briefing": briefing,
            "input_truncated": input_truncated,
            "input_chars_omitted": input_chars_omitted,
            "original_estimated_tokens": requested_estimated_tokens,
            "transformed_estimated_tokens": original_estimated_tokens,
            "sent_estimated_tokens": _estimate_tokens(safe_context),
            "estimated_input_tokens": estimated_input_tokens,
            "request_bytes": request_bytes,
            "evidence_id_limit": evidence_id_limit,
            "evidence_ids_omitted": len(unique_evidence_ids) - len(bounded_evidence_ids),
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
