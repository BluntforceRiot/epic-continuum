"""Epic Continuum persistent-memory substrate."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import tomllib


def _source_tree_version() -> str:
    pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
    if not pyproject.exists():
        return "0+unknown"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    return str(data["project"]["version"])


try:
    __version__ = version("epic-continuum-memory")
except PackageNotFoundError:
    __version__ = _source_tree_version()
