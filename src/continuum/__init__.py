"""Epic Continuum persistent-memory substrate."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
import tomllib


def _source_tree_version() -> str | None:
    package_dir = Path(__file__).resolve().parent
    source_dir = package_dir.parent
    if package_dir.name != "continuum" or source_dir.name != "src":
        return None
    pyproject = source_dir.parent / "pyproject.toml"
    if not pyproject.exists():
        return None
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    project = data.get("project")
    if not isinstance(project, dict) or project.get("name") != "epic-continuum-memory":
        return None
    project_version = project.get("version")
    return str(project_version) if project_version is not None else None


_checkout_version = _source_tree_version()
if _checkout_version is not None:
    __version__ = _checkout_version
else:
    try:
        __version__ = version("epic-continuum-memory")
    except PackageNotFoundError:
        __version__ = "0+unknown"
