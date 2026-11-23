from __future__ import annotations

import ctypes
import errno
import os
import secrets
import shutil
import stat
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from functools import lru_cache
from typing import Any


PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600
_EXPERIMENT_EVIDENCE_DIR = ".experiment"


@dataclass(frozen=True)
class PinnedDirectory:
    """An absolute directory kept open across a security-sensitive operation."""

    requested_path: Path
    path: Path
    identity: tuple[int, int]
    fd: int | None = None


def _link_like_metadata(path: Path, metadata: os.stat_result) -> bool:
    is_junction = getattr(path, "is_junction", None)
    try:
        junction = bool(callable(is_junction) and is_junction())
    except OSError:
        return True
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return (
        stat.S_ISLNK(metadata.st_mode)
        or junction
        or bool(int(getattr(metadata, "st_file_attributes", 0)) & reparse_flag)
    )


def _pinned_identity(metadata: os.stat_result) -> tuple[int, int]:
    return int(metadata.st_dev), int(metadata.st_ino)


def _resolved_path_beneath(
    path: Path,
    roots: list[Path] | None,
) -> tuple[Path, Path, tuple[int, int], tuple[int, int]]:
    requested = Path(path)
    if not requested.is_absolute():
        raise ValueError("a pinned filesystem path must be absolute")
    try:
        resolved = requested.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError(f"pinned filesystem path is unavailable: {requested}") from exc
    candidates = list(roots) if roots is not None else [Path(resolved.anchor)]
    contained_by: list[tuple[Path, tuple[int, int]]] = []
    for root in candidates:
        try:
            resolved_root = Path(root).resolve(strict=True)
            root_stat = resolved_root.lstat()
            if not stat.S_ISDIR(root_stat.st_mode) or _link_like_metadata(resolved_root, root_stat):
                continue
            resolved.relative_to(resolved_root)
        except (OSError, RuntimeError, ValueError):
            continue
        contained_by.append((resolved_root, _pinned_identity(root_stat)))
    if not contained_by:
        raise ValueError(f"pinned filesystem path is outside its allowed roots: {requested}")
    root, root_identity = max(contained_by, key=lambda item: len(item[0].parts))
    observed = resolved.lstat()
    if _link_like_metadata(resolved, observed):
        raise ValueError(f"pinned filesystem path changed while resolving: {requested}")
    return resolved, root, root_identity, _pinned_identity(observed)


def _open_posix_directory_fd(
    path: Path,
    *,
    approved: tuple[Path, tuple[int, int]],
) -> int:
    nofollow = int(getattr(os, "O_NOFOLLOW", 0))
    directory = int(getattr(os, "O_DIRECTORY", 0))
    if not nofollow or not directory:
        raise OSError(
            errno.ENOTSUP,
            "descriptor-relative no-follow traversal is unavailable",
            str(path),
        )
    flags = os.O_RDONLY | nofollow | directory
    current_fd = -1
    try:
        current = Path(path.anchor)
        current_fd = os.open(path.anchor, flags)
        if current == approved[0] and _pinned_identity(os.fstat(current_fd)) != approved[1]:
            raise ValueError("approved directory changed before opening")
        for component in path.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
            current = current / component
            if current == approved[0] and _pinned_identity(os.fstat(current_fd)) != approved[1]:
                raise ValueError("approved directory changed before opening")
        metadata = os.fstat(current_fd)
        if not stat.S_ISDIR(metadata.st_mode):
            raise OSError(errno.ENOTDIR, "pinned path is not a directory", str(path))
        result = current_fd
        current_fd = -1
        return result
    finally:
        if current_fd >= 0:
            os.close(current_fd)


@contextmanager
def _open_windows_path_handles(
    path: Path,
    *,
    final_directory: bool,
    approved: tuple[Path, tuple[int, int]],
) -> Iterator[tuple[int, tuple[int, int], Any, Any, list[int]]]:
    from ctypes import wintypes

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("file_attributes", wintypes.DWORD),
            ("creation_time", wintypes.FILETIME),
            ("last_access_time", wintypes.FILETIME),
            ("last_write_time", wintypes.FILETIME),
            ("volume_serial_number", wintypes.DWORD),
            ("file_size_high", wintypes.DWORD),
            ("file_size_low", wintypes.DWORD),
            ("number_of_links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    file_read_attributes = 0x00000080
    generic_read = 0x80000000
    share_read = 0x00000001
    share_write = 0x00000002
    open_existing = 3
    file_attribute_normal = 0x00000080
    backup_semantics = 0x02000000
    open_reparse_point = 0x00200000
    invalid_handle = ctypes.c_void_p(-1).value
    handles: list[int] = []
    final_handle = 0
    final_identity = (0, 0)
    current = Path(path.anchor)
    try:
        for index, component in enumerate(path.parts):
            if index:
                current = current / component
            is_final = index == len(path.parts) - 1
            is_directory = not is_final or final_directory
            handle = kernel32.CreateFileW(
                str(current),
                file_read_attributes if is_directory else generic_read,
                (share_read | share_write) if is_directory else share_read,
                None,
                open_existing,
                (backup_semantics if is_directory else file_attribute_normal)
                | open_reparse_point,
                None,
            )
            handle_value = int(getattr(handle, "value", handle) or 0)
            if handle_value in {0, invalid_handle}:
                raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
            handles.append(handle_value)
            information = _ByHandleFileInformation()
            if not kernel32.GetFileInformationByHandle(
                wintypes.HANDLE(handle_value),
                ctypes.byref(information),
            ):
                raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
            attributes = int(information.file_attributes)
            file_index = (
                int(information.file_index_high) << 32
            ) | int(information.file_index_low)
            metadata = os.lstat(current)
            if (
                bool(attributes & 0x10) != is_directory
                or bool(attributes & 0x400)
                or _link_like_metadata(current, metadata)
                or stat.S_ISDIR(metadata.st_mode) != is_directory
                or int(metadata.st_ino) != file_index
                or (current == approved[0] and _pinned_identity(metadata) != approved[1])
            ):
                raise OSError(
                    errno.ESTALE,
                    "pinned Windows path changed while opening",
                    str(current),
                )
            if is_final:
                final_handle = handle_value
                final_identity = (int(metadata.st_dev), int(metadata.st_ino))
        yield final_handle, final_identity, kernel32, wintypes, handles
    finally:
        for handle_value in reversed(handles):
            kernel32.CloseHandle(wintypes.HANDLE(handle_value))


@contextmanager
def open_directory_beneath(
    path: Path,
    *,
    roots: list[Path] | None,
) -> Iterator[PinnedDirectory]:
    """Pin an existing directory reached beneath one of the approved roots."""

    requested = path.absolute()
    resolved, root, root_identity, expected = _resolved_path_beneath(requested, roots)
    approved = (root, root_identity)
    if os.name == "nt":
        with _open_windows_path_handles(
            resolved,
            final_directory=True,
            approved=approved,
        ) as (_handle, identity, _kernel32, _wintypes, _handles):
            if identity != expected:
                raise ValueError("approved directory changed before opening")
            yield PinnedDirectory(requested, resolved, identity)
        return
    if os.name != "posix":
        raise OSError(errno.ENOTSUP, "directory pinning is unsupported", str(path))
    fd = _open_posix_directory_fd(resolved, approved=approved)
    try:
        metadata = os.fstat(fd)
        if _pinned_identity(metadata) != expected:
            raise ValueError("approved directory changed before opening")
        yield PinnedDirectory(
            requested,
            resolved,
            (int(metadata.st_dev), int(metadata.st_ino)),
            fd,
        )
    finally:
        os.close(fd)


@contextmanager
def open_regular_file_beneath(
    path: Path,
    *,
    roots: list[Path] | None,
) -> Iterator[int]:
    """Open one approved regular file without reopening its pathname."""

    requested = path.absolute()
    resolved, root, root_identity, expected = _resolved_path_beneath(requested, roots)
    relative = resolved.relative_to(root)
    if not relative.parts:
        raise ValueError(f"pinned filesystem path is not a regular file: {requested}")
    if os.name == "nt":
        import msvcrt

        with _open_windows_path_handles(
            resolved,
            final_directory=False,
            approved=(root, root_identity),
        ) as (handle, _identity, _kernel32, _wintypes, handles):
            fd = msvcrt.open_osfhandle(  # type: ignore[attr-defined]
                handle,
                os.O_RDONLY | int(getattr(os, "O_BINARY", 0)),
            )
            handles.remove(handle)
            try:
                metadata = os.fstat(fd)
                if not stat.S_ISREG(metadata.st_mode):
                    raise ValueError(f"pinned filesystem path is not a regular file: {requested}")
                if _pinned_identity(metadata) != expected:
                    raise ValueError("approved file changed before opening")
                yield fd
            finally:
                os.close(fd)
        return
    if os.name != "posix":
        raise OSError(errno.ENOTSUP, "regular-file pinning is unsupported", str(path))
    directory_fd = _open_posix_directory_fd(root, approved=(root, root_identity))
    file_fd = -1
    try:
        directory_flags = (
            os.O_RDONLY
            | int(getattr(os, "O_DIRECTORY", 0))
            | int(getattr(os, "O_NOFOLLOW", 0))
        )
        for component in relative.parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_flags = (
            os.O_RDONLY
            | int(getattr(os, "O_BINARY", 0))
            | int(getattr(os, "O_NOFOLLOW", 0))
            | int(getattr(os, "O_NONBLOCK", 0))
        )
        file_fd = os.open(relative.parts[-1], file_flags, dir_fd=directory_fd)
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"pinned filesystem path is not a regular file: {requested}")
        if _pinned_identity(metadata) != expected:
            raise ValueError("approved file changed before opening")
        yield file_fd
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(directory_fd)


def pinned_directory_is_current(directory: PinnedDirectory) -> bool:
    """Return whether the pinned object still occupies its approved pathname."""

    try:
        metadata = os.lstat(directory.path)
        if (
            _link_like_metadata(directory.path, metadata)
            or not stat.S_ISDIR(metadata.st_mode)
            or (int(metadata.st_dev), int(metadata.st_ino)) != directory.identity
        ):
            return False
        if directory.fd is not None:
            opened = os.fstat(directory.fd)
            return (int(opened.st_dev), int(opened.st_ino)) == directory.identity
        return True
    except OSError:
        return False


def _copy_regular_file_to_fd(source: Path, destination_fd: int) -> None:
    source_flags = (
        os.O_RDONLY
        | int(getattr(os, "O_BINARY", 0))
        | int(getattr(os, "O_NOFOLLOW", 0))
        | int(getattr(os, "O_NONBLOCK", 0))
    )
    source_fd = os.open(source, source_flags)
    try:
        before = os.fstat(source_fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"private tree source is not a regular file: {source}")
        copied = 0
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            remaining = memoryview(chunk)
            while remaining:
                written = os.write(destination_fd, remaining)
                if written <= 0:
                    raise OSError("private tree copy made no forward progress")
                remaining = remaining[written:]
            copied += len(chunk)
        after = os.fstat(source_fd)
        before_identity = (
            int(before.st_dev),
            int(before.st_ino),
            int(before.st_size),
            int(before.st_mtime_ns),
            int(before.st_ctime_ns),
        )
        after_identity = (
            int(after.st_dev),
            int(after.st_ino),
            int(after.st_size),
            int(after.st_mtime_ns),
            int(after.st_ctime_ns),
        )
        if before_identity != after_identity or copied != int(after.st_size):
            raise ValueError(f"private tree source changed while copying: {source}")
        os.fsync(destination_fd)
    finally:
        os.close(source_fd)


def _copy_private_tree_posix(source: Path, destination_fd: int, *, omit: str | None = None) -> None:
    with os.scandir(source) as scanned:
        entries = sorted(scanned, key=lambda item: item.name)
    for entry in entries:
        if entry.name == omit:
            continue
        source_path = Path(entry.path)
        metadata = os.lstat(source_path)
        if _link_like_metadata(source_path, metadata):
            raise ValueError(f"private tree source contains a link-like entry: {source_path}")
        if stat.S_ISDIR(metadata.st_mode):
            os.mkdir(entry.name, PRIVATE_DIR_MODE, dir_fd=destination_fd)
            child_fd = os.open(
                entry.name,
                os.O_RDONLY
                | int(getattr(os, "O_DIRECTORY", 0))
                | int(getattr(os, "O_NOFOLLOW", 0)),
                dir_fd=destination_fd,
            )
            try:
                _copy_private_tree_posix(source_path, child_fd)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(metadata.st_mode):
            child_fd = os.open(
                entry.name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | int(getattr(os, "O_BINARY", 0))
                | int(getattr(os, "O_NOFOLLOW", 0)),
                PRIVATE_FILE_MODE,
                dir_fd=destination_fd,
            )
            try:
                _copy_regular_file_to_fd(source_path, child_fd)
            finally:
                os.close(child_fd)
        else:
            raise ValueError(f"private tree source contains an unsupported entry: {source_path}")
    os.fsync(destination_fd)


def _copy_private_tree_windows(
    source: Path, native: Any, destination_handle: int, *, omit: str | None = None,
) -> None:
    import msvcrt

    with os.scandir(source) as scanned:
        entries = sorted(scanned, key=lambda item: item.name)
    for entry in entries:
        if entry.name == omit:
            continue
        source_path = Path(entry.path)
        metadata = os.lstat(source_path)
        if _link_like_metadata(source_path, metadata):
            raise ValueError(f"private tree source contains a link-like entry: {source_path}")
        if stat.S_ISDIR(metadata.st_mode):
            child = native.open_relative(
                destination_handle, entry.name, directory=True, disposition=native._FILE_CREATE,
                share_access=native._FILE_SHARE_READ | native._FILE_SHARE_WRITE,
            )
            try:
                _copy_private_tree_windows(source_path, native, child)
            finally:
                native.close(child)
        elif stat.S_ISREG(metadata.st_mode):
            child = native.open_relative(
                destination_handle, entry.name, directory=False, disposition=native._FILE_CREATE,
                desired_access=native._FILE_WRITE_DATA | native._FILE_READ_ATTRIBUTES | native._SYNCHRONIZE,
            )
            try:
                descriptor = msvcrt.open_osfhandle(child, os.O_WRONLY | int(getattr(os, "O_BINARY", 0)))
            except BaseException:
                native.close(child)
                raise
            try:
                _copy_regular_file_to_fd(source_path, descriptor)
            finally:
                os.close(descriptor)
        else:
            raise ValueError(f"private tree source contains an unsupported entry: {source_path}")


def _rename_posix_directory_noclobber(parent: int, source: str, target: str) -> None:
    """Rename within the admitted directory without ever replacing a sibling."""

    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform.startswith("linux"):
        rename = getattr(libc, "renameat2", None)
        no_replace = 1
    elif sys.platform == "darwin":
        rename = getattr(libc, "renameatx_np", None)
        no_replace = 0x00000004
    else:
        rename = None
        no_replace = 0
    if rename is None:
        raise OSError(errno.ENOTSUP, "descriptor-relative no-clobber directory rename unavailable", target)
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent, os.fsencode(source), parent, os.fsencode(target), no_replace) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), target)


def _reserve_private_posix_directory(parent: int, name: str) -> int:
    """Bind a fresh private directory, without reopening through the process cwd."""

    os.mkdir(name, PRIVATE_DIR_MODE, dir_fd=parent)
    expected = os.stat(name, dir_fd=parent, follow_symlinks=False)
    descriptor = os.open(
        name,
        os.O_RDONLY | int(getattr(os, "O_DIRECTORY", 0)) | int(getattr(os, "O_NOFOLLOW", 0)),
        dir_fd=parent,
    )
    try:
        opened = os.fstat(descriptor)
        if (
            not os.path.samestat(expected, opened)
            or not stat.S_ISDIR(opened.st_mode)
            or opened.st_dev != os.fstat(parent).st_dev
            or opened.st_uid != getattr(os, "geteuid", lambda: -1)()
            or stat.S_IMODE(opened.st_mode) & 0o077
            or os.listdir(descriptor)
        ):
            raise ValueError("private experiment directory changed before copying")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _assert_posix_directory_binding(parent: int, name: str, opened: int) -> None:
    if not os.path.samestat(os.fstat(opened), os.stat(name, dir_fd=parent, follow_symlinks=False)):
        raise ValueError("experiment directory identity differs from its opened object")


def publish_private_tree(
    source: Path,
    destination_parent: PinnedDirectory,
    name: str,
    *,
    leaf_only: bool = False,
) -> Path:
    """Publish a new experiment through the admitted directory only.

    With approval for just the new leaf, copy into that exclusive reservation and
    publish the evidence directory last. No operation requires a sibling or a
    rename between volumes. An interrupted reservation is not a completed experiment.
    """

    if not name or Path(name).name != name or name in {".", ".."}:
        raise ValueError("private tree destination must be one path component")
    source_metadata = os.lstat(source)
    if _link_like_metadata(source, source_metadata) or not stat.S_ISDIR(source_metadata.st_mode):
        raise ValueError("private tree source must be a plain directory")
    if not pinned_directory_is_current(destination_parent):
        raise ValueError("experiment destination parent changed before publication")
    destination = destination_parent.path / name
    staged_evidence = source / _EXPERIMENT_EVIDENCE_DIR
    if leaf_only:
        evidence_metadata = staged_evidence.lstat()
        if _link_like_metadata(staged_evidence, evidence_metadata) or not stat.S_ISDIR(evidence_metadata.st_mode):
            raise ValueError("the private experiment stage must contain its plain evidence directory")
    private_name = ".continuum-experiment-stage-" + secrets.token_hex(16)
    staging = name if leaf_only else private_name
    # On failure, leave the private stage/reservation instead of deleting a path
    # that may no longer name our object. The evidence directory is the commit.
    if os.name == "nt":
        from .review_bridge import _open_windows_plain_directory

        copy_error: OSError | None = None
        with _open_windows_plain_directory(destination_parent.path) as (native, parent):
            if _pinned_identity(native.fstat(parent)) != destination_parent.identity:
                raise ValueError("experiment destination parent changed before publication")
            stage_handle = native.open_relative(
                parent, staging, directory=True, disposition=native._FILE_CREATE,
                desired_access=(
                    native._DELETE | native._FILE_LIST_DIRECTORY | native._FILE_TRAVERSE
                    | native._FILE_READ_ATTRIBUTES | native._SYNCHRONIZE
                ),
                share_access=native._FILE_SHARE_READ | native._FILE_SHARE_WRITE,
            )
            try:
                if leaf_only:
                    _copy_private_tree_windows(source, native, stage_handle, omit=_EXPERIMENT_EVIDENCE_DIR)
                    evidence_handle = native.open_relative(
                        stage_handle, private_name, directory=True, disposition=native._FILE_CREATE,
                        desired_access=(
                            native._DELETE | native._FILE_LIST_DIRECTORY | native._FILE_TRAVERSE
                            | native._FILE_READ_ATTRIBUTES | native._SYNCHRONIZE
                        ),
                        share_access=native._FILE_SHARE_READ | native._FILE_SHARE_WRITE,
                    )
                    try:
                        _copy_private_tree_windows(staged_evidence, native, evidence_handle)
                        if not pinned_directory_is_current(destination_parent):
                            raise ValueError("experiment destination parent changed before publication")
                        native.rename_relative(evidence_handle, stage_handle, _EXPERIMENT_EVIDENCE_DIR, replace=False)
                    finally:
                        native.close(evidence_handle)
                else:
                    _copy_private_tree_windows(source, native, stage_handle)
                    if not pinned_directory_is_current(destination_parent):
                        raise ValueError("experiment destination parent changed before publication")
                    native.rename_relative(stage_handle, parent, name, replace=False)
            except OSError as exc:
                # The directory context translates its own open errors.
                # Keep ordinary copy/publication failures distinct.
                copy_error = exc
            finally:
                native.close(stage_handle)
        if copy_error is not None:
            raise copy_error
    elif os.name == "posix" and destination_parent.fd is not None:
        parent_fd = destination_parent.fd
        stage_fd = _reserve_private_posix_directory(parent_fd, staging)
        try:
            if leaf_only:
                _copy_private_tree_posix(source, stage_fd, omit=_EXPERIMENT_EVIDENCE_DIR)
                evidence_fd = _reserve_private_posix_directory(stage_fd, private_name)
                try:
                    _copy_private_tree_posix(staged_evidence, evidence_fd)
                    if not pinned_directory_is_current(destination_parent):
                        raise ValueError("experiment destination parent changed before publication")
                    _assert_posix_directory_binding(parent_fd, name, stage_fd)
                    _assert_posix_directory_binding(stage_fd, private_name, evidence_fd)
                    _rename_posix_directory_noclobber(stage_fd, private_name, _EXPERIMENT_EVIDENCE_DIR)
                    _assert_posix_directory_binding(stage_fd, _EXPERIMENT_EVIDENCE_DIR, evidence_fd)
                    os.fsync(stage_fd)
                finally:
                    os.close(evidence_fd)
            else:
                _copy_private_tree_posix(source, stage_fd)
                if not pinned_directory_is_current(destination_parent):
                    raise ValueError("experiment destination parent changed before publication")
                _assert_posix_directory_binding(parent_fd, staging, stage_fd)
                _rename_posix_directory_noclobber(parent_fd, staging, name)
            _assert_posix_directory_binding(parent_fd, name, stage_fd)
        finally:
            os.close(stage_fd)
        os.fsync(parent_fd)
    else:
        raise OSError(
            errno.ENOTSUP,
            "descriptor-relative private tree publication is unavailable",
            str(destination),
        )
    if not pinned_directory_is_current(destination_parent):
        raise ValueError("experiment destination parent changed during publication")
    return destination


def _flush_windows_handle_strict(
    kernel32: Any,
    wintypes: Any,
    handle_value: int,
) -> None:
    """Flush one already-open Windows handle without reopening its path."""

    kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    kernel32.FlushFileBuffers.restype = wintypes.BOOL
    if not kernel32.FlushFileBuffers(wintypes.HANDLE(handle_value)):
        raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]


@contextmanager
def guard_windows_file_disposition(
    *,
    namespace_directories: list[Path],
    terminal_path: Path,
    queue_path: Path,
) -> Iterator[dict[str, int] | None]:
    """Fence Windows namespaces and expose exact file handles for retirement.

    Directory and terminal handles omit delete sharing, so their namespace
    objects cannot be renamed or replaced while the caller validates and
    retires the queue file.  The queue handle itself has DELETE access and is
    shared for reads only.  On non-Windows platforms the caller receives
    ``None`` and must use its portable fallback.
    """

    if os.name != "nt":
        yield None
        return

    import msvcrt
    from ctypes import wintypes

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("file_attributes", wintypes.DWORD),
            ("creation_time", wintypes.FILETIME),
            ("last_access_time", wintypes.FILETIME),
            ("last_write_time", wintypes.FILETIME),
            ("volume_serial_number", wintypes.DWORD),
            ("file_size_high", wintypes.DWORD),
            ("file_size_low", wintypes.DWORD),
            ("number_of_links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    file_read_attributes = 0x00000080
    generic_read = 0x80000000
    generic_write = 0x40000000
    delete_access = 0x00010000
    share_read = 0x00000001
    share_write = 0x00000002
    open_existing = 3
    file_attribute_normal = 0x00000080
    backup_semantics = 0x02000000
    open_reparse_point = 0x00200000
    invalid_handle = ctypes.c_void_p(-1).value
    raw_handles: list[int] = []
    directory_records: list[
        tuple[Path, int, tuple[int, int, bool, bool]]
    ] = []
    terminal_fd = -1
    queue_fd = -1

    def open_handle(
        path: Path,
        *,
        desired_access: int,
        share_mode: int,
        directory: bool,
    ) -> int:
        handle = kernel32.CreateFileW(
            str(path),
            desired_access,
            share_mode,
            None,
            open_existing,
            (
                (backup_semantics if directory else file_attribute_normal)
                | open_reparse_point
            ),
            None,
        )
        handle_value = int(getattr(handle, "value", handle) or 0)
        if handle_value in {0, invalid_handle}:
            raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
        raw_handles.append(handle_value)
        return handle_value

    def handle_identity(
        handle_value: int,
    ) -> tuple[int, int, bool, bool]:
        information = _ByHandleFileInformation()
        if not kernel32.GetFileInformationByHandle(
            wintypes.HANDLE(handle_value),
            ctypes.byref(information),
        ):
            raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
        attributes = int(information.file_attributes)
        return (
            int(information.volume_serial_number),
            (
                int(information.file_index_high) << 32
                | int(information.file_index_low)
            ),
            bool(attributes & 0x10),
            bool(attributes & 0x400),
        )

    def verify_namespace_binding(
        path: Path,
        *,
        expected: tuple[int, int, bool, bool],
        directory: bool,
    ) -> None:
        metadata = os.lstat(path)
        is_junction = getattr(path, "is_junction", None)
        junction = bool(callable(is_junction) and is_junction())
        reparse_flag = int(
            getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
        reparse = bool(
            int(getattr(metadata, "st_file_attributes", 0))
            & reparse_flag
        )
        namespace_is_directory = stat.S_ISDIR(metadata.st_mode)
        namespace_is_file = stat.S_ISREG(metadata.st_mode)
        if (
            stat.S_ISLNK(metadata.st_mode)
            or junction
            or reparse
            or expected[2] != directory
            or expected[3]
            or namespace_is_directory != directory
            or namespace_is_file == directory
            or int(metadata.st_ino) != expected[1]
        ):
            raise OSError(
                errno.ESTALE,
                "guarded Windows namespace identity changed",
                str(path),
            )

    try:
        for directory in namespace_directories:
            handle_value = open_handle(
                directory,
                desired_access=file_read_attributes | generic_write,
                share_mode=share_read | share_write,
                directory=True,
            )
            directory_records.append(
                (
                    directory,
                    handle_value,
                    handle_identity(handle_value),
                )
            )
        terminal_handle = open_handle(
            terminal_path,
            desired_access=generic_read | generic_write,
            share_mode=share_read,
            directory=False,
        )
        terminal_identity = handle_identity(terminal_handle)
        queue_handle = open_handle(
            queue_path,
            desired_access=generic_read | delete_access,
            share_mode=share_read,
            directory=False,
        )
        queue_identity = handle_identity(queue_handle)

        for path, handle_value, expected in directory_records:
            if handle_identity(handle_value) != expected:
                raise OSError(
                    errno.ESTALE,
                    "guarded Windows directory handle changed",
                    str(path),
                )
            verify_namespace_binding(
                path,
                expected=expected,
                directory=True,
            )
        if handle_identity(terminal_handle) != terminal_identity:
            raise OSError(
                errno.ESTALE,
                "guarded Windows terminal handle changed",
                str(terminal_path),
            )
        verify_namespace_binding(
            terminal_path,
            expected=terminal_identity,
            directory=False,
        )
        if handle_identity(queue_handle) != queue_identity:
            raise OSError(
                errno.ESTALE,
                "guarded Windows queue handle changed",
                str(queue_path),
            )
        verify_namespace_binding(
            queue_path,
            expected=queue_identity,
            directory=False,
        )

        # Strictly flush the exact terminal inode and the exact guarded
        # namespace handles. Reopening by path here would accept a byte-equal
        # replacement that was never made durable.
        _flush_windows_handle_strict(
            kernel32,
            wintypes,
            terminal_handle,
        )
        for _path, handle_value, _expected in directory_records:
            _flush_windows_handle_strict(
                kernel32,
                wintypes,
                handle_value,
            )

        for path, handle_value, expected in directory_records:
            if handle_identity(handle_value) != expected:
                raise OSError(
                    errno.ESTALE,
                    "guarded Windows directory handle changed during flush",
                    str(path),
                )
            verify_namespace_binding(
                path,
                expected=expected,
                directory=True,
            )
        if handle_identity(terminal_handle) != terminal_identity:
            raise OSError(
                errno.ESTALE,
                "guarded Windows terminal handle changed during flush",
                str(terminal_path),
            )
        verify_namespace_binding(
            terminal_path,
            expected=terminal_identity,
            directory=False,
        )
        if handle_identity(queue_handle) != queue_identity:
            raise OSError(
                errno.ESTALE,
                "guarded Windows queue handle changed during terminal flush",
                str(queue_path),
            )
        verify_namespace_binding(
            queue_path,
            expected=queue_identity,
            directory=False,
        )

        terminal_fd = msvcrt.open_osfhandle(  # type: ignore[attr-defined]
            terminal_handle,
            os.O_RDWR | int(getattr(os, "O_BINARY", 0)),
        )
        raw_handles.remove(terminal_handle)
        queue_fd = msvcrt.open_osfhandle(  # type: ignore[attr-defined]
            queue_handle,
            os.O_RDONLY | int(getattr(os, "O_BINARY", 0)),
        )
        raw_handles.remove(queue_handle)
        yield {
            "terminal_fd": terminal_fd,
            "queue_fd": queue_fd,
            "queue_handle": queue_handle,
        }
    finally:
        if queue_fd >= 0:
            try:
                os.close(queue_fd)
            except OSError:
                pass
        if terminal_fd >= 0:
            try:
                os.close(terminal_fd)
            except OSError:
                pass
        for handle_value in reversed(raw_handles):
            try:
                kernel32.CloseHandle(wintypes.HANDLE(handle_value))
            except Exception:
                pass


def set_windows_delete_disposition(handle: int) -> None:
    """Mark one exact Windows file handle for deletion on close."""

    if os.name != "nt":
        raise OSError(
            errno.ENOTSUP,
            "Windows handle disposition is unavailable",
        )

    from ctypes import wintypes

    class _FileDispositionInfo(ctypes.Structure):
        _fields_ = [("delete_file", wintypes.BOOLEAN)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    kernel32.SetFileInformationByHandle.restype = wintypes.BOOL
    disposition = _FileDispositionInfo(True)
    if not kernel32.SetFileInformationByHandle(
        wintypes.HANDLE(handle),
        4,
        ctypes.byref(disposition),
        ctypes.sizeof(disposition),
    ):
        raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]


def retire_exact_windows_file(
    path: Path,
    *,
    expected_identity: tuple[int, int, int, int, int, int],
) -> bool:
    """Delete one exact Windows file object by handle, never by final pathname.

    ``False`` means the caller is on a non-Windows platform and must use its
    bounded non-deleting retirement slot.
    """

    if os.name != "nt":
        return False

    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    generic_read = 0x80000000
    file_read_attributes = 0x00000080
    delete_access = 0x00010000
    share_read = 0x00000001
    open_existing = 3
    file_attribute_normal = 0x00000080
    open_reparse_point = 0x00200000
    invalid_handle = ctypes.c_void_p(-1).value
    raw_handle = kernel32.CreateFileW(
        str(path),
        generic_read | file_read_attributes | delete_access,
        share_read,
        None,
        open_existing,
        file_attribute_normal | open_reparse_point,
        None,
    )
    handle_value = int(getattr(raw_handle, "value", raw_handle) or 0)
    if handle_value in {0, invalid_handle}:
        raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
    fd = -1
    try:
        fd = msvcrt.open_osfhandle(  # type: ignore[attr-defined]
            handle_value,
            os.O_RDONLY | int(getattr(os, "O_BINARY", 0)),
        )
        handle_value = 0
        opened = os.fstat(fd)
        reparse_flag = int(
            getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        )
        if (
            not stat.S_ISREG(opened.st_mode)
            or bool(
                int(getattr(opened, "st_file_attributes", 0))
                & reparse_flag
            )
            or int(opened.st_dev) != expected_identity[0]
            or int(opened.st_ino) != expected_identity[1]
            or stat.S_IFMT(opened.st_mode) != expected_identity[2]
            or int(opened.st_size) != expected_identity[3]
            or int(opened.st_mtime_ns) != expected_identity[4]
        ):
            raise OSError(
                errno.ESTALE,
                "exact Windows retirement handle identity changed",
                str(path),
            )
        current = os.lstat(path)
        current_identity = (
            int(current.st_dev),
            int(current.st_ino),
            stat.S_IFMT(current.st_mode),
            int(current.st_size),
            int(current.st_mtime_ns),
            int(current.st_ctime_ns),
        )
        if current_identity != expected_identity:
            raise OSError(
                errno.ESTALE,
                "exact Windows retirement namespace identity changed",
                str(path),
            )
        set_windows_delete_disposition(
            int(msvcrt.get_osfhandle(fd)),  # type: ignore[attr-defined]
        )
    finally:
        if fd >= 0:
            os.close(fd)
        elif handle_value not in {0, invalid_handle}:
            kernel32.CloseHandle(wintypes.HANDLE(handle_value))
    if os.path.lexists(path):
        raise OSError(
            errno.ESTALE,
            "exact Windows retirement path remained after handle deletion",
            str(path),
        )
    return True


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
    target = path
    if path.is_symlink():
        try:
            target = path.resolve(strict=True)
        except OSError:
            return
    if not posix_permissions_supported(target):
        return
    try:
        os.chmod(target, mode, follow_symlinks=False)
    except (OSError, NotImplementedError):
        return


def secure_mkdir(path: Path, *, secure_existing: bool = False) -> None:
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
    if secure_existing and path.exists():
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


def _durability_stat(path: Path, *, require_directory: bool) -> os.stat_result:
    """Return one plain file/directory stat suitable for a strict flush."""

    metadata = os.lstat(path)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(metadata, "st_file_attributes", 0)
    if stat.S_ISLNK(metadata.st_mode) or bool(
        reparse_flag and attributes & reparse_flag
    ):
        raise OSError(errno.ELOOP, "durability target is link-like", str(path))
    expected_type = stat.S_ISDIR if require_directory else stat.S_ISREG
    if not expected_type(metadata.st_mode):
        label = "directory" if require_directory else "regular file"
        raise OSError(errno.EINVAL, f"durability target is not a {label}", str(path))
    return metadata


def _durability_identity(metadata: os.stat_result) -> tuple[int, int]:
    return int(metadata.st_dev), int(metadata.st_ino)


def _flush_windows_path_strict(
    path: Path,
    *,
    expected: os.stat_result,
    require_directory: bool,
) -> None:
    """Flush one identity-checked Windows file or directory handle."""

    from ctypes import wintypes

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("file_attributes", wintypes.DWORD),
            ("creation_time", wintypes.FILETIME),
            ("last_access_time", wintypes.FILETIME),
            ("last_write_time", wintypes.FILETIME),
            ("volume_serial_number", wintypes.DWORD),
            ("file_size_high", wintypes.DWORD),
            ("file_size_low", wintypes.DWORD),
            ("number_of_links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    kernel32.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel32.FlushFileBuffers.argtypes = [wintypes.HANDLE]
    kernel32.FlushFileBuffers.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    generic_write = 0x40000000
    share_read_write_delete = 0x00000001 | 0x00000002 | 0x00000004
    open_existing = 3
    backup_semantics = 0x02000000 if require_directory else 0
    open_reparse_point = 0x00200000
    invalid_handle = ctypes.c_void_p(-1).value
    handle = kernel32.CreateFileW(
        str(path),
        generic_write,
        share_read_write_delete,
        None,
        open_existing,
        backup_semantics | open_reparse_point,
        None,
    )
    handle_value = int(getattr(handle, "value", handle) or 0)
    if handle_value in {0, invalid_handle}:
        raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]

    primary: BaseException | None = None
    try:
        information = _ByHandleFileInformation()
        if not kernel32.GetFileInformationByHandle(
            wintypes.HANDLE(handle_value),
            ctypes.byref(information),
        ):
            raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
        attributes = int(information.file_attributes)
        handle_is_directory = bool(attributes & 0x10)
        handle_file_index = (
            int(information.file_index_high) << 32
        ) | int(information.file_index_low)
        if (
            handle_is_directory != require_directory
            or bool(attributes & 0x400)
            or handle_file_index != int(expected.st_ino)
        ):
            raise OSError(errno.ESTALE, "durability target identity changed", str(path))
        if not kernel32.FlushFileBuffers(wintypes.HANDLE(handle_value)):
            raise ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if not kernel32.CloseHandle(wintypes.HANDLE(handle_value)):
            close_error = ctypes.WinError(ctypes.get_last_error())  # type: ignore[attr-defined]
            if primary is None:
                raise close_error
            primary.add_note(
                "Closing the strict durability handle also failed: "
                f"{type(close_error).__name__}: {close_error}"
            )


def _flush_posix_path_strict(
    path: Path,
    *,
    expected: os.stat_result,
    require_directory: bool,
) -> None:
    flags = os.O_RDONLY | int(getattr(os, "O_NOFOLLOW", 0))
    if require_directory:
        flags |= int(getattr(os, "O_DIRECTORY", 0))
    descriptor = os.open(str(path), flags)
    primary: BaseException | None = None
    try:
        opened = os.fstat(descriptor)
        expected_type = stat.S_ISDIR if require_directory else stat.S_ISREG
        if (
            not expected_type(opened.st_mode)
            or _durability_identity(opened) != _durability_identity(expected)
        ):
            raise OSError(errno.ESTALE, "durability target identity changed", str(path))
        os.fsync(descriptor)
    except BaseException as exc:
        primary = exc
        raise
    finally:
        try:
            os.close(descriptor)
        except OSError as close_error:
            if primary is None:
                raise
            primary.add_note(
                "Closing the strict durability descriptor also failed: "
                f"{type(close_error).__name__}: {close_error}"
            )


def _flush_path_strict(
    path: Path,
    *,
    require_directory: bool,
    expected_identity: tuple[int, int] | None = None,
) -> None:
    absolute = path.absolute()
    expected = _durability_stat(absolute, require_directory=require_directory)
    if (
        expected_identity is not None
        and _durability_identity(expected) != expected_identity
    ):
        raise OSError(
            errno.ESTALE,
            "durability target identity changed before flush",
            str(absolute),
        )
    if os.name == "nt":
        _flush_windows_path_strict(
            absolute,
            expected=expected,
            require_directory=require_directory,
        )
    elif os.name == "posix":
        _flush_posix_path_strict(
            absolute,
            expected=expected,
            require_directory=require_directory,
        )
    else:
        raise OSError(
            errno.ENOTSUP,
            "strict durability flush is unsupported on this platform",
            str(absolute),
        )
    current = _durability_stat(absolute, require_directory=require_directory)
    if _durability_identity(current) != _durability_identity(expected):
        raise OSError(errno.ESTALE, "durability target changed after flush", str(absolute))
    if not require_directory and int(current.st_size) != int(expected.st_size):
        raise OSError(errno.ESTALE, "durability target size changed after flush", str(absolute))


def flush_file_strict(
    path: Path,
    *,
    expected_identity: tuple[int, int] | None = None,
) -> None:
    """Fail unless one plain regular file is durably flushed."""

    _flush_path_strict(
        Path(path),
        require_directory=False,
        expected_identity=expected_identity,
    )


def flush_directory_strict(path: Path) -> None:
    """Fail unless one plain directory namespace is durably flushed."""

    _flush_path_strict(Path(path), require_directory=True)


def flush_tree_strict(path: Path, *, include_parent: bool = False) -> None:
    """Flush all regular files, then directories from deepest to shallowest."""

    root = Path(path).absolute()
    _durability_stat(root, require_directory=True)
    files: list[Path] = []
    directories = [root]
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda item: item.name)
        for entry in entries:
            candidate = Path(entry.path)
            metadata = _durability_stat(
                candidate,
                require_directory=entry.is_dir(follow_symlinks=False),
            )
            if stat.S_ISDIR(metadata.st_mode):
                directories.append(candidate)
                pending.append(candidate)
            elif stat.S_ISREG(metadata.st_mode):
                files.append(candidate)
            else:  # pragma: no cover - _durability_stat rejects other types
                raise OSError(
                    errno.EINVAL,
                    "durability tree contains an unsupported entry",
                    str(candidate),
                )
    for candidate in sorted(files, key=lambda item: item.as_posix()):
        flush_file_strict(candidate)
    for directory in sorted(
        directories,
        key=lambda item: (-len(item.parts), item.as_posix()),
    ):
        flush_directory_strict(directory)
    if include_parent:
        flush_directory_strict(root.parent)


def replace_durable(source: Path, destination: Path) -> None:
    """Atomically replace a path and strictly flush both affected namespaces."""

    source = Path(source)
    destination = Path(destination)
    source_parent = source.parent.absolute()
    destination_parent = destination.parent.absolute()
    os.replace(source, destination)
    flush_directory_strict(destination_parent)
    if source_parent != destination_parent:
        flush_directory_strict(source_parent)


def secure_write_bytes(path: Path, data: bytes) -> None:
    secure_mkdir(path.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        if posix_permissions_supported(tmp_path):
            os.fchmod(fd, PRIVATE_FILE_MODE)  # type: ignore[attr-defined]  # POSIX-only API
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


def secure_write_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    secure_mkdir(path.parent)
    data = text.encode(encoding)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        if posix_permissions_supported(tmp_path):
            os.fchmod(fd, PRIVATE_FILE_MODE)  # type: ignore[attr-defined]  # POSIX-only API
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


def secure_write_text_exclusive(
    path: Path,
    text: str,
    *,
    encoding: str = "utf-8",
) -> None:
    """Durably publish a private file only when its final name is absent.

    The fully written temporary file is moved into the destination namespace
    with the platform's atomic no-replace primitive.  This is used for new
    content-addressed names where replacing a concurrently-created entry would
    destroy evidence that this writer never inspected.
    """

    secure_mkdir(path.parent)
    data = text.encode(encoding)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    tmp_path = Path(tmp_name)
    # Capture the file identity before any operation that can fail.  Cleanup
    # must stay bound to the exact mkstemp entry even when chmod, write, flush,
    # or fsync raises before publication begins.
    metadata = os.fstat(fd)
    tmp_identity: tuple[int, int] | None = (
        int(metadata.st_dev),
        int(metadata.st_ino),
    )
    try:
        if posix_permissions_supported(tmp_path):
            os.fchmod(fd, PRIVATE_FILE_MODE)  # type: ignore[attr-defined]  # POSIX-only API
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            metadata = os.fstat(handle.fileno())
            if (int(metadata.st_dev), int(metadata.st_ino)) != tmp_identity:
                raise OSError(f"exclusive temporary identity changed: {tmp_path}")
        fd = -1

        # The destination is created in one namespace operation and an existing
        # path is never replaced.  Refuse to claim success unless the published
        # entry is the exact file that was flushed above.
        replace_file_noclobber(tmp_path, path)
        published = os.lstat(path)
        if (int(published.st_dev), int(published.st_ino)) != tmp_identity:
            raise OSError(f"exclusive publication identity changed: {path}")
        _chmod(path, PRIVATE_FILE_MODE)
        fsync_parent(path)
    except Exception:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        raise
    finally:
        # Never unlink a namespace entry that no longer denotes our temporary
        # file.  A stale private temp is safer than deleting replacement bytes.
        current_identity: tuple[int, int] | None
        try:
            current = os.lstat(tmp_path)
            current_identity = (int(current.st_dev), int(current.st_ino))
        except OSError:
            current_identity = None
        if tmp_identity is not None and current_identity == tmp_identity:
            tmp_path.unlink(missing_ok=True)


def replace_file_noclobber(source: Path, destination: Path) -> None:
    """Atomically move ``source`` to an absent ``destination``.

    Windows rename already has no-replace semantics.  Linux exposes the same
    operation as ``renameat2(RENAME_NOREPLACE)``, while macOS exposes
    ``renamex_np(RENAME_EXCL)``.  Refuse the operation on a platform that
    cannot provide that primitive; copying followed by unlinking would
    introduce both a clobber window and an identity-unbound deletion.
    """

    secure_mkdir(destination.parent)
    if os.name == "nt":
        os.rename(source, destination)
    elif sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise OSError(
                errno.ENOTSUP,
                "atomic no-clobber rename is unavailable",
                str(destination),
            )
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        at_fdcwd = -100
        rename_noreplace = 1
        if (
            renameat2(
                at_fdcwd,
                os.fsencode(source),
                at_fdcwd,
                os.fsencode(destination),
                rename_noreplace,
            )
            != 0
        ):
            error_number = ctypes.get_errno()
            raise OSError(
                error_number,
                os.strerror(error_number),
                str(destination),
            )
    elif sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        renamex_np = getattr(libc, "renamex_np", None)
        if renamex_np is None:
            raise OSError(
                errno.ENOTSUP,
                "atomic no-clobber rename is unavailable",
                str(destination),
            )
        renamex_np.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renamex_np.restype = ctypes.c_int
        rename_excl = 0x00000004
        if (
            renamex_np(
                os.fsencode(source),
                os.fsencode(destination),
                rename_excl,
            )
            != 0
        ):
            error_number = ctypes.get_errno()
            raise OSError(
                error_number,
                os.strerror(error_number),
                str(destination),
            )
    else:
        raise OSError(
            errno.ENOTSUP,
            "atomic no-clobber rename is unsupported on this platform",
            str(destination),
        )
    fsync_parent(destination)


def secure_append_text(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Append text to a private regular file without following symlinks.

    Adapter diagnostics are durable local state too.  Creating them with the
    process umask can leave secrets or tracebacks world-readable, while normal
    ``open(..., 'a')`` will follow a substituted symlink.  Use one append-only
    descriptor, request ``0600`` at creation, and tighten existing files.
    """
    secure_mkdir(path.parent)
    try:
        if path.is_symlink():
            raise ValueError(f"refusing to append through symlink: {path}")
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            raise ValueError(f"refusing to append through junction: {path}")
    except OSError as exc:
        raise ValueError(f"unable to validate append target: {path}") from exc

    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow:
        flags |= nofollow
    fd = os.open(str(path), flags, PRIVATE_FILE_MODE)
    try:
        if posix_permissions_supported(path):
            os.fchmod(fd, PRIVATE_FILE_MODE)  # type: ignore[attr-defined]  # POSIX-only API
        data = text.encode(encoding)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write while appending private text")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    _chmod(path, PRIVATE_FILE_MODE)


def secure_file(path: Path) -> None:
    if path.exists() and path.is_file():
        _chmod(path, PRIVATE_FILE_MODE)


def secure_copy_file(source: Path, destination: Path) -> None:
    secure_mkdir(destination.parent)
    shutil.copyfile(source, destination)
    secure_file(destination)
    flush_file_strict(destination)
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
    flush_tree_strict(destination, include_parent=True)


def secure_sqlite_files(db_path: Path) -> None:
    for candidate in (db_path, Path(f"{db_path}-wal"), Path(f"{db_path}-shm")):
        secure_file(candidate)


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def audit_private_permissions(
    root: Path,
    *,
    max_findings: int = 100,
    allow_symlinks: bool = False,
) -> dict[str, Any]:
    if root.is_symlink():
        try:
            root = root.resolve(strict=True)
        except OSError as exc:
            return {
                "ok": False,
                "supported": posix_permissions_supported(root),
                "reason": "root_symlink_unresolved",
                "checked": 0,
                "unsafe_count": 1,
                "findings": [{"path": str(root), "reason": "root_symlink_unresolved", "error": str(exc)}],
            }
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
    symlink_count = 0
    findings: list[dict[str, Any]] = []

    def inspect(path: Path) -> None:
        nonlocal checked, unsafe_count, symlink_count
        try:
            stat_result = os.lstat(path)
            mode = stat.S_IMODE(stat_result.st_mode)
            is_link = stat.S_ISLNK(stat_result.st_mode)
            is_junction = getattr(path, "is_junction", None)
            if callable(is_junction):
                try:
                    is_link = is_link or bool(is_junction())
                except OSError:
                    pass
            reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            attributes = getattr(stat_result, "st_file_attributes", 0)
            is_link = is_link or bool(reparse_flag and attributes & reparse_flag)
        except OSError as exc:
            unsafe_count += 1
            if len(findings) < max_findings:
                findings.append({"path": _relative(path, root), "reason": "stat_failed", "error": str(exc)})
            return
        checked += 1
        if is_link:
            symlink_count += 1
            if not allow_symlinks:
                unsafe_count += 1
                if len(findings) < max_findings:
                    findings.append({"path": _relative(path, root), "mode": oct(mode), "reason": "symlink_in_private_root"})
            return
        is_dir = stat.S_ISDIR(stat_result.st_mode)
        is_file = stat.S_ISREG(stat_result.st_mode)
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
        "symlink_count": symlink_count,
        "symlinks_allowed": allow_symlinks,
        "findings": findings,
        "repair_hint": "Run `continuum repair-permissions --root <root>` to set directories to 0700 and files to 0600.",
    }


def repair_private_permissions(root: Path) -> dict[str, Any]:
    if root.is_symlink():
        root = root.resolve(strict=True)
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
