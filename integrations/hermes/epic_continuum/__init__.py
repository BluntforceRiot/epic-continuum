from __future__ import annotations

import json
import os
import sys
import traceback
from pathlib import Path


LOCAL_CONFIG = Path(__file__).with_name("continuum_adapter.local.json")


def _local_config() -> dict:
    if not LOCAL_CONFIG.exists():
        return {}
    try:
        loaded = json.loads(LOCAL_CONFIG.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _log_import_error(exc: BaseException) -> None:
    try:
        log_path = Path(__file__).with_name("continuum_adapter.error.log")
        log_path.write_text(
            f"{type(exc).__name__}: {exc}\n\n{traceback.format_exc(limit=8)}",
            encoding="utf-8",
        )
    except OSError:
        return


def _load_adapter():
    config = _local_config()
    continuum_src = os.environ.get("CONTINUUM_SRC") or config.get("continuum_src")
    if continuum_src and continuum_src not in sys.path:
        sys.path.insert(0, continuum_src)
    try:
        from continuum.integrations import hermes_adapter
    except Exception as exc:
        _log_import_error(exc)
        return None
    hermes_adapter.configure(config_path=LOCAL_CONFIG)
    return hermes_adapter


def _disabled_hook(**_kwargs):
    return None


def _register_hook(ctx, name, hook):
    try:
        ctx.register_hook(name, hook)
    except Exception:
        return


def register(ctx):
    adapter = _load_adapter()
    if adapter is None:
        _register_hook(ctx, "pre_llm_call", _disabled_hook)
        _register_hook(ctx, "post_llm_call", _disabled_hook)
        return
    _register_hook(ctx, "pre_llm_call", adapter.pre_llm_call)
    _register_hook(ctx, "post_llm_call", adapter.post_llm_call)
    for name in ("tool_call", "pre_tool_call", "pre_tool_use"):
        _register_hook(ctx, name, adapter.tool_call)
    for name in ("tool_result", "post_tool_call", "post_tool_use"):
        _register_hook(ctx, name, adapter.tool_result)
    lifecycle_hooks = {
        "session_start": adapter.session_start,
        "on_session_start": adapter.session_start,
        "session_end": adapter.session_end,
        "on_session_end": adapter.session_end,
        "session_finalize": adapter.session_finalize,
        "on_session_finalize": adapter.session_finalize,
        "session_reset": adapter.session_reset,
        "on_session_reset": adapter.session_reset,
        "subagent_stop": adapter.subagent_stop,
        "on_subagent_stop": adapter.subagent_stop,
        "pre_gateway_dispatch": adapter.pre_gateway_dispatch,
        "on_pre_gateway_dispatch": adapter.pre_gateway_dispatch,
    }
    for name, hook in lifecycle_hooks.items():
        _register_hook(ctx, name, hook)
