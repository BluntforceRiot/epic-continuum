from __future__ import annotations

import io
import tarfile
import tempfile
from pathlib import Path

from setuptools import setup
from setuptools.command.sdist import sdist as _sdist


class NormalizedSdist(_sdist):
    """Normalize sdist tar modes on Windows and POSIX builds."""

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


def _normalize_tar_modes(path: Path, *, gzipped: bool) -> None:
    read_mode = "r:gz" if gzipped else "r:"
    write_mode = "w:gz" if gzipped else "w:"
    with tempfile.NamedTemporaryFile(delete=False, suffix=path.suffix, dir=path.parent) as handle:
        temp_path = Path(handle.name)
    try:
        with tarfile.open(path, read_mode) as source, tarfile.open(temp_path, write_mode) as target:
            for member in source.getmembers():
                member.mode = _normalized_mode(member)
                member.uid = 0
                member.gid = 0
                member.uname = ""
                member.gname = ""
                extracted = source.extractfile(member) if member.isfile() else None
                if extracted is None:
                    target.addfile(member)
                else:
                    data = extracted.read()
                    target.addfile(member, io.BytesIO(data))
        temp_path.replace(path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


setup(cmdclass={"sdist": NormalizedSdist})
