from __future__ import annotations

import json
import os
import sys
import hashlib
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
    """Record a private, non-sensitive import failure marker.

    This bootstrap module runs precisely when importing Continuum may have
    failed, so it cannot rely on the main redaction helpers.  Never persist the
    exception message or traceback here: both can contain API keys, paths, or
    user content.  A deterministic digest still allows repeated failures to be
    correlated without storing the raw material.
    """
    try:
        log_path = Path(__file__).with_name("continuum_adapter.error.log")
        if log_path.is_symlink():
            return
        raw = f"{type(exc).__name__}: {exc}".encode("utf-8", errors="replace")
        message = (
            "Continuum adapter import failed.\n"
            f"error_type={type(exc).__name__}\n"
            f"error_hash={hashlib.sha256(raw).hexdigest()}\n"
        ).encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(log_path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600) if hasattr(os, "fchmod") else None
            os.write(fd, message)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.chmod(log_path, 0o600)
        except OSError:
            pass
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
