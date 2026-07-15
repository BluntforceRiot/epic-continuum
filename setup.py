from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

from setuptools import setup
from setuptools.command.bdist_wheel import bdist_wheel as _bdist_wheel
from setuptools.command.sdist import sdist as _sdist


_NORMALIZER_PATH = Path(__file__).resolve().parent / "scripts" / "canonicalize_distributions.py"
_NORMALIZER_SPEC = importlib.util.spec_from_file_location(
    "epic_continuum_distribution_normalizer",
    _NORMALIZER_PATH,
)
if _NORMALIZER_SPEC is None or _NORMALIZER_SPEC.loader is None:
    raise RuntimeError(f"could not load distribution normalizer from {_NORMALIZER_PATH}")
_NORMALIZER = importlib.util.module_from_spec(_NORMALIZER_SPEC)
_NORMALIZER_SPEC.loader.exec_module(_NORMALIZER)
normalize_sdist = _NORMALIZER.normalize_sdist
normalize_wheel = _NORMALIZER.normalize_wheel


# ZIP-based wheels cannot represent years before 1980. The normalizer clamps
# only that year while preserving the authoritative epoch's month, day, and time.
DEFAULT_SOURCE_DATE_EPOCH = 315532800
MAX_GZIP_MTIME = (1 << 32) - 1


class NormalizedSdist(_sdist):
    """Normalize sdist tar metadata on Windows and POSIX builds."""

    def make_archive(self, base_name, format, root_dir=None, base_dir=None, owner=None, group=None):
        archive_path = Path(super().make_archive(base_name, format, root_dir, base_dir, owner, group))
        if format in {"gztar", "tar"}:
            normalize_sdist(
                archive_path,
                gzipped=(format == "gztar"),
                epoch=_source_date_epoch(),
            )
        return str(archive_path)


class NormalizedBdistWheel(_bdist_wheel):
    """Normalize the completed wheel independently of its build platform."""

    def run(self) -> None:
        super().run()
        wheel_paths = [
            Path(path)
            for command, _python_version, path in self.distribution.dist_files
            if command == "bdist_wheel"
        ]
        if not wheel_paths:
            raise RuntimeError("bdist_wheel did not register its output archive")
        normalize_wheel(wheel_paths[-1], epoch=_source_date_epoch())


def _source_date_epoch() -> int:
    """Resolve an explicit or release-provenance distribution build epoch."""
    raw_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    try:
        epoch = int(raw_epoch) if raw_epoch is not None else None
    except ValueError:
        epoch = None
    if epoch is not None and 0 <= epoch <= MAX_GZIP_MTIME:
        return epoch

    provenance_path = (
        Path(__file__).resolve().parent
        / "src"
        / "continuum"
        / "assets"
        / "RELEASE_PROVENANCE.json"
    )
    try:
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        embedded_epoch = int(provenance["source_date_epoch"])
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return DEFAULT_SOURCE_DATE_EPOCH
    if not 0 <= embedded_epoch <= MAX_GZIP_MTIME:
        return DEFAULT_SOURCE_DATE_EPOCH
    return embedded_epoch


os.environ["SOURCE_DATE_EPOCH"] = str(_source_date_epoch())


setup(cmdclass={"bdist_wheel": NormalizedBdistWheel, "sdist": NormalizedSdist})
