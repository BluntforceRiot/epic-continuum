from __future__ import annotations

import datetime as dt
import json
import os
import platform
import re
import socket
import stat
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping

from .permissions import PRIVATE_FILE_MODE, fsync_parent, secure_mkdir, secure_write_text


WRITER_CLAIM_SCHEMA = "epic_continuum.writer_claim.v1"
WRITER_CLAIM_NAME = "writer-claim.json"
SUPPORTED_WRITER_RUNTIMES = {"windows", "wsl", "linux", "macos"}
WSL_WINDOWS_MOUNT_RE = re.compile(r"^/mnt/[a-z](?:/|$)", re.IGNORECASE)


class WriterClaimError(RuntimeError):
    """Raised when this runtime is not allowed to mutate a Continuum root."""


def _utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()


def _normalized_host(value: str | None) -> str:
    host = str(value or "").strip().casefold()
    if not host or len(host) > 255 or any(ord(char) < 32 for char in host):
        return "unknown-host"
    return host


def _linux_osrelease() -> str:
    try:
        return Path("/proc/sys/kernel/osrelease").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return platform.release()


def detect_runtime_identity(
    *,
    system: str | None = None,
    environ: Mapping[str, str] | None = None,
    osrelease: str | None = None,
    hostname: str | None = None,
) -> dict[str, str]:
    """Return the writer identity that owns catalog mutations on this host.

    WSL is intentionally a distinct runtime from Windows even when both access
    the same NTFS volume. SQLite does not support one WAL being coordinated by
    the Windows and DrvFs locking implementations at the same time.
    """
    env = os.environ if environ is None else environ
    system_name = str(system if system is not None else platform.system()).strip().casefold()
    release = str(osrelease if osrelease is not None else (_linux_osrelease() if system_name == "linux" else platform.release()))
    release_folded = release.casefold()
    if system_name == "windows":
        runtime = "windows"
    elif system_name == "linux" and (
        bool(env.get("WSL_INTEROP"))
        or bool(env.get("WSL_DISTRO_NAME"))
        or "microsoft" in release_folded
        or "wsl" in release_folded
    ):
        runtime = "wsl"
    elif system_name == "linux":
        runtime = "linux"
    elif system_name == "darwin":
        runtime = "macos"
    else:
        runtime = "unsupported"
    detected_host = hostname or socket.gethostname() or env.get("COMPUTERNAME") or env.get("HOSTNAME")
    return {"runtime": runtime, "host": _normalized_host(detected_host)}


def writer_claim_path(root: Path) -> Path:
    return Path(root).resolve(strict=False) / "config" / WRITER_CLAIM_NAME


def _is_link_like(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
    except OSError:
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction):
        try:
            if is_junction():
                return True
        except OSError:
            return True
    try:
        item_stat = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(item_stat, "st_file_attributes", 0)
    return bool(reparse_flag and attributes & reparse_flag)


def _safe_claim_path(root: Path, *, create: bool) -> Path:
    canonical_root = Path(root).resolve(strict=False)
    config_dir = canonical_root / "config"
    marker = config_dir / WRITER_CLAIM_NAME
    if create:
        secure_mkdir(canonical_root)
    if config_dir.exists() and (_is_link_like(config_dir) or not config_dir.is_dir()):
        raise WriterClaimError(f"refusing unsafe writer-claim config directory: {config_dir}")
    if create:
        secure_mkdir(config_dir)
        if _is_link_like(config_dir) or not config_dir.is_dir():
            raise WriterClaimError(f"refusing unsafe writer-claim config directory: {config_dir}")
    if marker.exists() or marker.is_symlink():
        if _is_link_like(marker) or not marker.is_file():
            raise WriterClaimError(f"refusing unsafe writer-claim marker: {marker}")
    return marker


def _validate_claim(payload: Any) -> dict[str, str]:
    if not isinstance(payload, dict):
        raise WriterClaimError("writer-claim marker must contain a JSON object")
    schema = payload.get("schema")
    runtime = payload.get("runtime")
    host = payload.get("host")
    claimed_at = payload.get("claimed_at")
    if schema != WRITER_CLAIM_SCHEMA:
        raise WriterClaimError(f"unsupported writer-claim schema: {schema!r}")
    if runtime not in SUPPORTED_WRITER_RUNTIMES:
        raise WriterClaimError(f"invalid writer-claim runtime: {runtime!r}")
    if not isinstance(host, str) or _normalized_host(host) != host:
        raise WriterClaimError("writer-claim host must be a normalized non-empty hostname")
    if not isinstance(claimed_at, str):
        raise WriterClaimError("writer-claim claimed_at must be an ISO-8601 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(claimed_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise WriterClaimError("writer-claim claimed_at must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise WriterClaimError("writer-claim claimed_at must include a UTC offset")
    return {
        "schema": WRITER_CLAIM_SCHEMA,
        "runtime": runtime,
        "host": host,
        "claimed_at": claimed_at,
    }


def _load_claim(marker: Path) -> dict[str, str]:
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            return _validate_claim(json.loads(marker.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, json.JSONDecodeError, WriterClaimError) as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(0.01)
    if isinstance(last_error, WriterClaimError):
        raise last_error
    raise WriterClaimError(f"unable to read writer-claim marker: {last_error}")


def _claim_text(claim: dict[str, str]) -> str:
    return json.dumps(claim, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write while creating writer-claim marker")
        view = view[written:]


def _create_claim_exclusive(marker: Path, claim: dict[str, str]) -> bool:
    """Publish a complete marker without replacing a concurrent claimant."""
    data = _claim_text(claim).encode("utf-8")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{WRITER_CLAIM_NAME}.", suffix=".tmp", dir=marker.parent)
    tmp_path = Path(tmp_name)
    try:
        if hasattr(os, "fchmod"):
            try:
                os.fchmod(fd, PRIVATE_FILE_MODE)
            except OSError:
                pass
        _write_all(fd, data)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        try:
            os.link(tmp_path, marker, follow_symlinks=False)
        except FileExistsError:
            return False
        except OSError:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_NOFOLLOW", 0)
            direct_fd = -1
            try:
                direct_fd = os.open(str(marker), flags, PRIVATE_FILE_MODE)
                _write_all(direct_fd, data)
                os.fsync(direct_fd)
            except FileExistsError:
                return False
            finally:
                if direct_fd >= 0:
                    os.close(direct_fd)
        fsync_parent(marker)
        return True
    finally:
        if fd >= 0:
            os.close(fd)
        tmp_path.unlink(missing_ok=True)


def _root_has_existing_state(root: Path) -> bool:
    canonical = Path(root).resolve(strict=False)
    if not canonical.exists():
        return False
    if not canonical.is_dir():
        return True
    # "Existing" means an existing Continuum state tree, not merely a caller
    # placing an import file, configuration, or a bootstrap lock below the
    # directory before first initialization. Config and run/lock paths do not
    # contain the live catalog whose mixed-runtime writes this claim prevents.
    durable_markers = (
        canonical / "catalog" / "catalog.sqlite3",
        canonical / "archive",
        canonical / "scroll",
        canonical / "graph",
        canonical / "queues",
        canonical / "snapshots",
        canonical / "exports",
    )
    try:
        return any(path.exists() or path.is_symlink() for path in durable_markers)
    except OSError:
        return True


def _is_wsl_windows_mount(root: Path) -> bool:
    lexical = str(root).replace("\\", "/")
    resolved = str(Path(root).resolve(strict=False)).replace("\\", "/")
    return any(WSL_WINDOWS_MOUNT_RE.match(candidate) is not None for candidate in (lexical, resolved))


def _identity_matches(claim: Mapping[str, str], identity: Mapping[str, str]) -> bool:
    return claim.get("runtime") == identity.get("runtime") and claim.get("host") == identity.get("host")


def writer_claim_status(
    root: Path,
    *,
    identity: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    current = dict(identity or detect_runtime_identity())
    result: dict[str, Any] = {
        "ok": True,
        "marker_uri": str(writer_claim_path(root)),
        "current": current,
        "claimed": False,
        "compatible": None,
        "claim": None,
        "root_has_existing_state": _root_has_existing_state(root),
    }
    try:
        marker = _safe_claim_path(root, create=False)
        if not marker.exists():
            result["auto_claim_allowed"] = (
                not result["root_has_existing_state"]
                and current.get("runtime") in SUPPORTED_WRITER_RUNTIMES
                and not (current.get("runtime") == "wsl" and _is_wsl_windows_mount(root))
            )
            return result
        claim = _load_claim(marker)
    except WriterClaimError as exc:
        result.update({"ok": False, "compatible": False, "error": str(exc), "auto_claim_allowed": False})
        return result
    result.update(
        {
            "claimed": True,
            "compatible": _identity_matches(claim, current),
            "claim": claim,
            "auto_claim_allowed": False,
        }
    )
    return result


def _claim_command(root: Path, *, force: bool = False) -> str:
    suffix = " --force --acknowledge-writers-stopped" if force else ""
    return f"continuum writer-claim --root \"{root}\"{suffix}"


def claim_writer(
    root: Path,
    *,
    force: bool = False,
    acknowledge_writers_stopped: bool = False,
    identity: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    current = dict(identity or detect_runtime_identity())
    if current.get("runtime") not in SUPPORTED_WRITER_RUNTIMES:
        raise WriterClaimError(f"unsupported writer runtime: {current.get('runtime')!r}")
    current["host"] = _normalized_host(current.get("host"))
    marker = _safe_claim_path(root, create=True)
    claim = {
        "schema": WRITER_CLAIM_SCHEMA,
        "runtime": str(current["runtime"]),
        "host": str(current["host"]),
        "claimed_at": _utc_now(),
    }
    if marker.exists():
        try:
            previous = _load_claim(marker)
        except WriterClaimError:
            previous = None
        if previous is not None and _identity_matches(previous, current):
            return {**writer_claim_status(root, identity=current), "changed": False}
        if not force or not acknowledge_writers_stopped:
            raise WriterClaimError(
                "writer claim belongs to another runtime/host or is malformed; stop every Continuum writer first, "
                f"then run `{_claim_command(root, force=True)}`"
            )
        _safe_claim_path(root, create=False)
        secure_write_text(marker, _claim_text(claim))
        return {**writer_claim_status(root, identity=current), "changed": True, "previous_claim": previous}
    created = _create_claim_exclusive(marker, claim)
    if not created:
        existing = _load_claim(_safe_claim_path(root, create=False))
        if not _identity_matches(existing, current):
            raise WriterClaimError(
                "another runtime/host claimed this Continuum root concurrently; "
                f"inspect with `continuum writer-status --root \"{root}\"`"
            )
    return {**writer_claim_status(root, identity=current), "changed": created}


def ensure_writer_claim(
    root: Path,
    *,
    identity: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    current = dict(identity or detect_runtime_identity())
    status = writer_claim_status(root, identity=current)
    if status.get("claimed"):
        if status.get("ok") and status.get("compatible"):
            return status
        claim = status.get("claim") or {}
        raise WriterClaimError(
            "Continuum root is write-claimed by "
            f"{claim.get('runtime', 'unknown')}@{claim.get('host', 'unknown')}; current writer is "
            f"{current.get('runtime')}@{current.get('host')}. Use read-only commands here, or stop every writer and "
            f"transfer ownership with `{_claim_command(root, force=True)}`."
        )
    if not status.get("ok"):
        raise WriterClaimError(
            f"writer-claim marker is unsafe or malformed: {status.get('error')}. Stop every writer, then repair it with "
            f"`{_claim_command(root, force=True)}`."
        )
    if current.get("runtime") not in SUPPORTED_WRITER_RUNTIMES:
        raise WriterClaimError(f"unsupported writer runtime: {current.get('runtime')!r}")
    if status.get("root_has_existing_state"):
        raise WriterClaimError(
            "existing Continuum root has no writer claim; inspect it read-only, then explicitly claim it with "
            f"`{_claim_command(root)}`"
        )
    if current.get("runtime") == "wsl" and _is_wsl_windows_mount(root):
        raise WriterClaimError(
            "WSL will not auto-claim a new Continuum root on /mnt/<drive>; choose one writer runtime, then explicitly "
            f"claim it with `{_claim_command(root)}`"
        )
    return claim_writer(root, identity=current)
