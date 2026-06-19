from __future__ import annotations

import os
import shutil
import stat
import tempfile
from pathlib import Path
from functools import lru_cache
from typing import Any


PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


def _probe_directory(path: Path | None = None) -> Path | None:
    candidate = Path(tempfile.gettempdir()) if path is None else Path(path)
    if candidate.exists() and candidate.is_file():
        candidate = candidate.parent
    while not candidate.exists() and candidate != candidate.parent:
        candidate = candidate.parent
    if not candidate.exists() or not candidate.is_dir():
        return None
    return candidate


@lru_cache(maxsize=256)
def _posix_permissions_supported_in(directory: str) -> bool:
    if os.name != "posix":
        return False
    fd = -1
    tmp_path: Path | None = None
    try:
        fd, tmp_name = tempfile.mkstemp(prefix=".continuum-perm-probe.", dir=directory)
        tmp_path = Path(tmp_name)
        os.chmod(tmp_path, PRIVATE_FILE_MODE, follow_symlinks=False)
        return stat.S_IMODE(os.lstat(tmp_path).st_mode) == PRIVATE_FILE_MODE
    except OSError:
        return False
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)


def posix_permissions_supported(path: Path | None = None) -> bool:
    directory = _probe_directory(path)
    if directory is None:
        return False
    return _posix_permissions_supported_in(str(directory.resolve(strict=False)))


def _chmod(path: Path, mode: int) -> None:
    if not posix_permissions_supported(path):
        return
    os.chmod(path, mode, follow_symlinks=False)


def secure_mkdir(path: Path) -> None:
    missing: list[Path] = []
    candidate = path
    while not candidate.exists():
        missing.append(candidate)
        if candidate.parent == candidate:
            break
        candidate = candidate.parent
    path.mkdir(parents=True, exist_ok=True)
    for created in reversed(missing):
        _chmod(created, PRIVATE_DIR_MODE)
    _chmod(path, PRIVATE_DIR_MODE)


def fsync_parent(path: Path) -> None:
    """Best-effort fsync for the containing directory after atomic renames."""
    if os.name != "posix":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd = -1
    try:
        fd = os.open(str(path.parent), flags)
        os.fsync(fd)
    except OSError:
        return
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def secure_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    secure_mkdir(path.parent)
    data = text.encode(encoding)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        if posix_permissions_supported(tmp_path):
            os.fchmod(fd, PRIVATE_FILE_MODE)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        _chmod(path, PRIVATE_FILE_MODE)
        fsync_parent(path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        tmp_path.unlink(missing_ok=True)
        raise


def secure_file(path: Path) -> None:
    if path.exists() and path.is_file():
        _chmod(path, PRIVATE_FILE_MODE)


def secure_copy_file(source: Path, destination: Path) -> None:
    secure_mkdir(destination.parent)
    shutil.copyfile(source, destination)
    secure_file(destination)
    fsync_parent(destination)


def secure_move_file(source: Path, destination: Path) -> None:
    secure_mkdir(destination.parent)
    try:
        if source.resolve(strict=False) == destination.resolve(strict=False):
            secure_file(destination)
            return
    except OSError:
        pass
    os.replace(source, destination)
    secure_file(destination)
    fsync_parent(destination)
    fsync_parent(source)


def secure_tree(path: Path) -> None:
    if not path.exists() or path.is_symlink():
        return
    if path.is_dir():
        _chmod(path, PRIVATE_DIR_MODE)
        for child in path.rglob("*"):
            if child.is_symlink():
                continue
            if child.is_dir():
                _chmod(child, PRIVATE_DIR_MODE)
            elif child.is_file():
                _chmod(child, PRIVATE_FILE_MODE)
    elif path.is_file():
        _chmod(path, PRIVATE_FILE_MODE)


def secure_copytree(source: Path, destination: Path, *, dirs_exist_ok: bool = False, symlinks: bool = False) -> None:
    secure_mkdir(destination.parent)
    shutil.copytree(source, destination, dirs_exist_ok=dirs_exist_ok, symlinks=symlinks)
    secure_tree(destination)


def secure_sqlite_files(db_path: Path) -> None:
    for candidate in (db_path, Path(f"{db_path}-wal"), Path(f"{db_path}-shm")):
        secure_file(candidate)


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def audit_private_permissions(root: Path, *, max_findings: int = 100) -> dict[str, Any]:
    if not posix_permissions_supported(root):
        return {
            "ok": True,
            "supported": False,
            "reason": "posix_permissions_unavailable",
            "checked": 0,
            "unsafe_count": 0,
            "findings": [],
        }
    if not root.exists():
        return {
            "ok": False,
            "supported": True,
            "reason": "root_missing",
            "checked": 0,
            "unsafe_count": 1,
            "findings": [{"path": str(root), "reason": "root_missing"}],
        }

    checked = 0
    unsafe_count = 0
    findings: list[dict[str, Any]] = []

    def inspect(path: Path) -> None:
        nonlocal checked, unsafe_count
        try:
            mode = stat.S_IMODE(os.lstat(path).st_mode)
            is_dir = path.is_dir()
            is_file = path.is_file()
            is_link = path.is_symlink()
        except OSError as exc:
            unsafe_count += 1
            if len(findings) < max_findings:
                findings.append({"path": _relative(path, root), "reason": "stat_failed", "error": str(exc)})
            return
        checked += 1
        if is_link:
            unsafe_count += 1
            if len(findings) < max_findings:
                findings.append({"path": _relative(path, root), "mode": oct(mode), "reason": "symlink_in_private_root"})
            return
        if not (is_dir or is_file):
            return
        if mode & 0o077:
            unsafe_count += 1
            if len(findings) < max_findings:
                findings.append(
                    {
                        "path": "." if path == root else _relative(path, root),
                        "mode": oct(mode),
                        "expected": "no group/other permissions",
                    }
                )

    inspect(root)
    for path in root.rglob("*"):
        inspect(path)

    return {
        "ok": unsafe_count == 0,
        "supported": True,
        "checked": checked,
        "unsafe_count": unsafe_count,
        "findings": findings,
        "repair_hint": "Run `continuum repair-permissions --root <root>` to set directories to 0700 and files to 0600.",
    }


def repair_private_permissions(root: Path) -> dict[str, Any]:
    if not posix_permissions_supported(root):
        return {"ok": True, "supported": False, "reason": "posix_permissions_unavailable", "changed": 0}
    if not root.exists():
        raise FileNotFoundError(str(root))
    changed = 0
    for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_symlink():
            continue
        if path.is_dir():
            os.chmod(path, PRIVATE_DIR_MODE, follow_symlinks=False)
            changed += 1
        elif path.is_file():
            os.chmod(path, PRIVATE_FILE_MODE, follow_symlinks=False)
            changed += 1
    os.chmod(root, PRIVATE_DIR_MODE, follow_symlinks=False)
    changed += 1
    return {"ok": True, "supported": True, "changed": changed, "dir_mode": oct(PRIVATE_DIR_MODE), "file_mode": oct(PRIVATE_FILE_MODE)}
