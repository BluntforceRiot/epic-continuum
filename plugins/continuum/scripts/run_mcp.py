from __future__ import annotations

import runpy
import sys
from pathlib import Path


def add_source_checkout_to_path() -> None:
    plugin_root = Path(__file__).resolve().parents[1]
    repo_root = plugin_root.parent.parent
    source_root = repo_root / "src"
    if (source_root / "continuum").is_dir():
        sys.path.insert(0, str(source_root))


def main() -> int:
    add_source_checkout_to_path()
    try:
        runpy.run_module("continuum.mcp_server", run_name="__main__")
    except ModuleNotFoundError as exc:
        if exc.name == "continuum":
            sys.stderr.write(
                "Epic Continuum could not import the continuum package. "
                "Install epic-continuum-memory or run this plugin from the "
                "portable source checkout that contains ../../src.\n"
            )
            return 1
        raise
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
