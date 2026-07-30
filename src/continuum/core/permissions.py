from __future__ import annotations

import ctypes
import errno
import os
import shutil
import stat
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from functools import lru_cache
from typing import Any


PRIVATE_DIR_MODE = 0o700
PRIVATE_FILE_MODE = 0o600


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
    operation as ``renameat2(RENAME_NOREPLACE)``.  Refuse the operation on a
    platform that cannot provide that primitive; copying followed by unlinking
    would introduce both a clobber window and an identity-unbound deletion.
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
