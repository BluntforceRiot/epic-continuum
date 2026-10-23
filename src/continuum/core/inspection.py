"""Read-only operator facts; never initialize a root or execute host commands."""

from __future__ import annotations

import datetime as dt
import importlib.metadata
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import tomllib
from typing import Any

import continuum

from .store import SCHEMA_VERSION, connect_existing
from .writer_claim import WriterClaimError


_MAX_CONFIG_BYTES = 256 * 1024
_QUEUE_COLUMNS = {
    "status", "retry_pending", "retry_order", "created_at", "finished_at",
    "lease_owner", "lease_expires_at", "heartbeat_at",
}


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed.astimezone(dt.UTC)
    except (ValueError, OverflowError):
        return None


def _warning(warnings: list[dict[str, Any]], code: str, message: str) -> None:
    warnings.append({"code": code, "message": message})


def _runtime_facts() -> dict[str, Any]:
    module_path = Path(continuum.__file__).resolve()
    result: dict[str, Any] = {
        "active_version": continuum.__version__,
        "module_path": str(module_path),
        "python_executable": str(Path(sys.executable).resolve()),
        "distribution_name": "epic-continuum-memory",
        "distribution_version": None,
        "distribution_module_path": None,
        "distribution_matches_active_module": None,
    }
    try:
        distribution = importlib.metadata.distribution("epic-continuum-memory")
    except importlib.metadata.PackageNotFoundError:
        return result
    distribution_module = Path(str(distribution.locate_file("continuum/__init__.py"))).resolve()
    result.update(
        distribution_version=distribution.version,
        distribution_module_path=str(distribution_module),
        distribution_matches_active_module=distribution_module == module_path,
    )
    return result


def _read_config(path: Path) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Bounded parsing without loader defaults, values, or exception text in output."""
    facts: dict[str, Any] = {"path": str(path), "state": "unreadable"}
    try:
        if not stat.S_ISREG(path.stat().st_mode):
            facts["state"] = "not_regular_file"
            return facts, None
        with path.open("rb") as handle:
            raw = handle.read(_MAX_CONFIG_BYTES + 1)
        if len(raw) > _MAX_CONFIG_BYTES:
            facts["state"] = "too_large"
            return facts, None
        text = raw.decode("utf-8-sig")
        data = tomllib.loads(text) if path.suffix.lower() == ".toml" else json.loads(text)
        if not isinstance(data, dict):
            facts["state"] = "invalid_object"
            return facts, None
    except FileNotFoundError:
        facts["state"] = "missing"
        return facts, None
    except (OSError, UnicodeError, ValueError, RecursionError):
        return facts, None
    facts["state"] = "parsed"
    return facts, data


def _declared_path(value: Any, expected: Path) -> dict[str, Any]:
    # Relative paths depend on a host's working directory. Do not expand host
    # environment variables, resolve PATH commands, or echo arbitrary strings.
    result: dict[str, Any] = {"state": "unresolved", "normalized_path": None, "matches": None}
    if value is None:
        result["state"] = "unspecified"
        return result
    if (
        not isinstance(value, str) or not value or len(value) > 4096
        or any(ord(char) < 32 for char in value)
        or any(char in value for char in ("$", "%")) or value.startswith("~")
        or "://" in value
    ):
        return result
    try:
        path = Path(value)
        if not path.is_absolute():
            return result
        normalized = path.resolve(strict=False)
    except (OSError, ValueError, RuntimeError):
        return result
    matches = normalized == expected
    # Only repeat already-known inspection paths. An arbitrary mismatching
    # value may actually contain a credential-bearing command or URL fragment.
    result.update(state="absolute", normalized_path=str(expected) if matches else None, matches=matches)
    return result


def _connection_facts(
    path: Path, *, kind: str, root: Path, runtime: dict[str, Any], warnings: list[dict[str, Any]],
) -> dict[str, Any]:
    facts, data = _read_config(path)
    facts.update(kind=kind, live_connection_verified=False, commands_executed=False)
    if data is None:
        _warning(warnings, f"{kind}_config_unavailable", "The explicitly selected connection file could not be parsed.")
        return facts
    source_dir = Path(runtime["module_path"]).parent.parent
    if kind == "hermes":
        root_value = data.get("continuum_root")
        source_value = data.get("continuum_src")
        facts["environment_overrides"] = "not_evaluated; CONTINUUM_ROOT and CONTINUUM_SRC can override this file"
    else:
        container = data.get("mcp_servers" if path.suffix.lower() == ".toml" else "mcpServers")
        server = container.get("continuum") if isinstance(container, dict) else None
        if not isinstance(server, dict):
            facts["state"] = "continuum_entry_missing"
            _warning(warnings, "codex_entry_missing", "No supported continuum MCP entry was found in the selected file.")
            return facts
        environment = server.get("env")
        environment = environment if isinstance(environment, dict) else {}
        root_value = environment.get("CONTINUUM_ROOT")
        source_value = environment.get("PYTHONPATH")
        facts["launch_shape"] = (
            "python_module" if server.get("args") == ["-m", "continuum.mcp_server"] else "unrecognized"
        )
        facts["python_binding"] = _declared_path(server.get("command"), Path(runtime["python_executable"]))
        if facts["launch_shape"] != "python_module":
            _warning(warnings, "codex_launch_unverified", "The command is not the supported direct Python-module launch shape; nothing was executed.")
        if facts["python_binding"]["matches"] is not True:
            _warning(warnings, "codex_python_unverified", "The declared executable does not identify this inspecting Python runtime.")
        facts["environment_overrides"] = "host environment, working directory, and plugin runner not evaluated"
    facts["root_binding"] = _declared_path(root_value, root)
    facts["source_binding"] = (
        {"state": "unresolved", "normalized_path": None, "matches": None}
        if kind == "codex" and isinstance(source_value, str) and os.pathsep in source_value
        else _declared_path(source_value, source_dir)
    )
    for binding in ("root", "source"):
        value = facts[f"{binding}_binding"]
        if value["matches"] is False:
            _warning(warnings, f"{kind}_{binding}_mismatch", f"The declared {binding} differs from this inspection's {binding}.")
        elif value["matches"] is None:
            _warning(warnings, f"{kind}_{binding}_unverified", f"The declared {binding} is absent or depends on host path/environment resolution.")
    return facts


def _queue_facts(conn: sqlite3.Connection, now: dt.datetime, warnings: list[dict[str, Any]]) -> tuple[dict[str, Any], dict[str, Any]]:
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(queue_jobs)")}
    missing = sorted(_QUEUE_COLUMNS - columns)
    if missing:
        _warning(warnings, "queue_schema_incomplete", "Queue facts require schema columns absent from this catalog; no migration was run.")
        return {"available": False, "counts": None, "missing_columns": missing}, {"available": False, "service_liveness": "not_checked"}
    counts = dict.fromkeys(("pending", "running", "retrying", "failed", "completed", "skipped", "unknown"), 0)
    retry_running = invalid_retry = stale_running = invalid_waiting = future_waiting = invalid_finished = 0
    latest_heartbeat = latest_completed = oldest_waiting = None
    recent_completions = 0
    for row in conn.execute(
        "SELECT status, retry_pending, retry_order, created_at, finished_at, "
        "lease_owner, lease_expires_at, heartbeat_at FROM queue_jobs"
    ):
        status, retry, order = row["status"], row["retry_pending"], row["retry_order"]
        valid_retry = type(retry) is int and type(order) is int and (
            (retry == 0 and order == 0) or (retry == 1 and order > 0 and status in {"pending", "running"})
        )
        invalid_retry += not valid_retry
        if not valid_retry:
            counts["unknown"] += 1
            continue
        elif status == "pending":
            counts["retrying" if retry else "pending"] += 1
        elif status == "succeeded":
            counts["completed"] += 1
        elif status in {"running", "failed", "skipped"}:
            counts[status] += 1
        else:
            counts["unknown"] += 1
        if status == "pending":
            created = _timestamp(row["created_at"])
            invalid_waiting += created is None
            future_waiting += created is not None and created > now
            if created is not None and created <= now:
                oldest_waiting = min(oldest_waiting, created) if oldest_waiting else created
        elif status == "running":
            retry_running += retry == 1 and valid_retry
            heartbeat = _timestamp(row["heartbeat_at"])
            expiry = _timestamp(row["lease_expires_at"])
            owner = row["lease_owner"]
            stale_running += (
                not isinstance(owner, str) or not owner.strip() or expiry is None or expiry <= now
                or heartbeat is None or heartbeat > now
            )
            if heartbeat is not None and heartbeat <= now:
                latest_heartbeat = max(latest_heartbeat, heartbeat) if latest_heartbeat else heartbeat
        elif status == "succeeded":
            finished = _timestamp(row["finished_at"])
            invalid_finished += finished is None or finished > now
            if finished is not None and finished <= now:
                latest_completed = max(latest_completed, finished) if latest_completed else finished
                recent_completions += (now - finished).total_seconds() < 86400
    oldest_waiting_age = (now - oldest_waiting).total_seconds() if oldest_waiting else None
    queue = {
        "available": True, "counts": counts, "total": sum(counts.values()),
        "running_retry_jobs": retry_running, "invalid_retry_rows": invalid_retry,
        "oldest_waiting_job_at": oldest_waiting.isoformat() if oldest_waiting else None,
        "oldest_waiting_job_age_seconds": oldest_waiting_age,
        "invalid_waiting_timestamps": invalid_waiting, "future_waiting_timestamps": future_waiting,
    }
    worker = {
        "available": True, "service_liveness": "not_checked", "progress_since_previous_inspection": "not_measured",
        "stale_running_jobs": stale_running,
        "latest_running_job_heartbeat_at": latest_heartbeat.isoformat() if latest_heartbeat else None,
        "latest_successful_completion_at": latest_completed.isoformat() if latest_completed else None,
        "successful_completions_last_24h": recent_completions,
        "invalid_successful_completion_timestamps": invalid_finished,
    }
    for condition, code, message in (
        (counts["failed"], "failed_jobs", "Failed jobs remain recorded; inspection did not retry them."),
        (counts["unknown"], "unclassified_jobs", "Some jobs have unknown status or invalid retry authority; they were not counted as healthy work."),
        (stale_running, "stale_running_jobs", "Running rows have expired/missing leases, missing owners, or invalid/future heartbeats."),
        (invalid_waiting or future_waiting, "waiting_timestamp_invalid", "Some waiting-job timestamps are invalid or in the future; the valid-subset age is not a complete queue-age assessment."),
        (invalid_finished, "completion_timestamp_invalid", "Some succeeded rows lack a valid past completion timestamp; recent progress is not proven for those rows."),
        (oldest_waiting_age is not None and oldest_waiting_age >= 86400, "old_waiting_jobs", "At least one waiting job is 24 hours old or older."),
        (counts["pending"] + counts["retrying"] and not counts["running"], "backlog_without_running_jobs", "Work is waiting with no running job recorded; this does not establish whether a worker service is stopped."),
    ):
        if condition:
            _warning(warnings, code, message)
    return queue, worker


def inspect_runtime(
    root: Path, *, hermes_adapter_config: Path | None = None, codex_mcp_config: Path | None = None,
) -> dict[str, Any]:
    """Inspect one explicitly supplied root and optional connection files.

    ``ok`` means catalog facts could be read, not that a host or upgrade is
    certified. Only existing durable data is read. SQLite may create or update
    transient WAL/SHM coordination files while maintaining a WAL-aware snapshot.
    """
    root = Path(root).resolve(strict=False)
    now = _now()
    warnings: list[dict[str, Any]] = []
    runtime = _runtime_facts()
    config, _ = _read_config(root / "config" / "continuum.config.json")
    result: dict[str, Any] = {
        "ok": False, "report_version": 1, "checked_at": now.isoformat(),
        "root": str(root), "root_exists": root.is_dir(), "runtime": runtime,
        "config": config, "catalog": {"path": str(root / "catalog" / "catalog.sqlite3"), "available": False},
        "queue": {"available": False, "counts": None},
        "workers": {"available": False, "service_liveness": "not_checked"},
        "connections": [], "warnings": warnings,
        "upgrade": {
            "dry_run": True, "target_version": None, "migration_certified": False,
            "live_host_certified": False, "installed_or_changed": False,
            "required_before_upgrade": ["preserve a verified backup", "review target release migrations", "stop or coordinate all writers", "test the intended host and interpreter after installation"],
        },
        "limitations": [
            "SQLite mode=ro keeps durable catalog content read-only but may create/update transient WAL/SHM coordination files.",
            "Catalog facts share one read transaction; configuration and runtime facts are not an atomic host snapshot.",
            "Job heartbeats and completed rows are recorded activity, not worker-service liveness or a measured progress delta.",
            "No model, network, subprocess, adapter hook, install, migration, or repair is performed.",
        ],
    }
    if config["state"] != "parsed":
        _warning(warnings, "root_config_unavailable", "The root configuration is missing or unreadable; no defaults were written.")
    if runtime["distribution_matches_active_module"] is False:
        _warning(warnings, "distribution_module_mismatch", "Installed distribution metadata describes a different module location; active_version and module_path identify this process.")
    for kind, selected in (("hermes", hermes_adapter_config), ("codex", codex_mcp_config)):
        if selected is not None:
            result["connections"].append(_connection_facts(Path(selected).resolve(strict=False), kind=kind, root=root, runtime=runtime, warnings=warnings))
    conn = None
    try:
        conn = connect_existing(root)
        conn.execute("PRAGMA query_only = ON")
        conn.execute("BEGIN")
        tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        schema_row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone() if "meta" in tables else None
        schema = schema_row[0] if schema_row and isinstance(schema_row[0], str) and re.fullmatch(r"\d+\.\d+\.\d+", schema_row[0]) else None
        result["catalog"].update(available=True, recorded_schema_version=schema, expected_schema_version=SCHEMA_VERSION)
        if schema != SCHEMA_VERSION:
            _warning(warnings, "schema_version_unverified", "The recorded schema version does not match this runtime; inspection does not establish migration compatibility.")
        if "queue_jobs" not in tables:
            _warning(warnings, "queue_table_missing", "No queue_jobs table exists; no initialization or migration was attempted.")
        else:
            result["queue"], result["workers"] = _queue_facts(conn, now, warnings)
            result["ok"] = result["queue"]["available"]
    except FileNotFoundError:
        result["reason"] = "catalog_missing"
        _warning(warnings, "catalog_missing", "The selected root has no catalog; inspection left it uninitialized.")
    except WriterClaimError:
        result["reason"] = "writer_claim_incompatible"
        _warning(warnings, "writer_claim_incompatible", "This runtime cannot safely read the live WAL; inspect from its owning runtime or a separately frozen snapshot.")
    except (sqlite3.Error, OSError):
        result["reason"] = "catalog_unreadable"
        _warning(warnings, "catalog_unreadable", "The selected catalog could not be read; no repair was attempted.")
    finally:
        if conn is not None:
            conn.close()
    result["health"] = "attention" if warnings else "no_recorded_warning"
    return result
