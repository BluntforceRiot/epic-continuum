from __future__ import annotations

import gzip
import io
import os
import tarfile
import tempfile
from pathlib import Path

from setuptools import setup
from setuptools.command.sdist import sdist as _sdist


DEFAULT_SOURCE_DATE_EPOCH = 0
MAX_GZIP_MTIME = (1 << 32) - 1
PAX_TIME_HEADERS = ("mtime", "atime", "ctime")


class NormalizedSdist(_sdist):
    """Normalize sdist tar metadata on Windows and POSIX builds."""

    def make_archive(self, base_name, format, root_dir=None, base_dir=None, owner=None, group=None):
        archive_path = Path(super().make_archive(base_name, format, root_dir, base_dir, owner, group))
        if format in {"gztar", "tar"}:
            _normalize_tar_modes(archive_path, gzipped=(format == "gztar"))
        return str(archive_path)


def _normalized_mode(member: tarfile.TarInfo) -> int:
    if member.isdir():
        return 0o755
    if member.isfile() and member.name.endswith(".sh"):
        return 0o755
    return 0o644


def _source_date_epoch() -> int:
    """Return SOURCE_DATE_EPOCH, falling back deterministically to the Unix epoch."""
    raw_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    try:
        epoch = int(raw_epoch) if raw_epoch is not None else DEFAULT_SOURCE_DATE_EPOCH
    except ValueError:
        return DEFAULT_SOURCE_DATE_EPOCH
    if not 0 <= epoch <= MAX_GZIP_MTIME:
        return DEFAULT_SOURCE_DATE_EPOCH
    return epoch


def _copy_normalized_members(source: tarfile.TarFile, target: tarfile.TarFile, *, epoch: int) -> None:
    for member in source.getmembers():
        member.mode = _normalized_mode(member)
        member.uid = 0
        member.gid = 0
        member.uname = ""
        member.gname = ""
        member.mtime = epoch
        for header in PAX_TIME_HEADERS:
            if header in member.pax_headers:
                member.pax_headers[header] = str(epoch)
        extracted = source.extractfile(member) if member.isfile() else None
        if extracted is None:
            target.addfile(member)
        else:
            target.addfile(member, io.BytesIO(extracted.read()))


def _normalize_tar_modes(path: Path, *, gzipped: bool) -> None:
    read_mode = "r:gz" if gzipped else "r:"
    epoch = _source_date_epoch()
    with tempfile.NamedTemporaryFile(delete=False, suffix=path.suffix, dir=path.parent) as handle:
        temp_path = Path(handle.name)
    try:
        with tarfile.open(path, read_mode) as source:
            if gzipped:
                with (
                    temp_path.open("wb") as raw_target,
                    gzip.GzipFile(filename="", mode="wb", fileobj=raw_target, mtime=epoch) as compressed,
                    tarfile.open(fileobj=compressed, mode="w:", format=tarfile.PAX_FORMAT) as target,
                ):
                    _copy_normalized_members(source, target, epoch=epoch)
            else:
                with tarfile.open(temp_path, "w:", format=tarfile.PAX_FORMAT) as target:
                    _copy_normalized_members(source, target, epoch=epoch)
        temp_path.replace(path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


setup(cmdclass={"sdist": NormalizedSdist})
