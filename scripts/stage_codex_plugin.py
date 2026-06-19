from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any


EXCLUDED_PARTS = {"__pycache__", ".pytest_cache"}
EXCLUDED_SUFFIXES = {".pyc", ".pyo"}


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _plugin_tree_digest(plugin_source: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(plugin_source.rglob("*"), key=lambda item: item.as_posix()):
        rel = path.relative_to(plugin_source)
        if any(part in EXCLUDED_PARTS for part in rel.parts) or path.suffix in EXCLUDED_SUFFIXES:
            continue
        digest.update(rel.as_posix().encode("utf-8"))
        if path.is_file():
            digest.update(b"\0file\0")
            digest.update(path.read_bytes())
        elif path.is_dir():
            digest.update(b"\0dir\0")
    return digest.hexdigest()


def _local_mcp_payload(*, command: str, continuum_src: Path, root: Path) -> dict[str, Any]:
    return {
        "mcpServers": {
            "continuum": {
                "command": command,
                "args": ["-m", "continuum.mcp_server"],
                "env": {
                    "PYTHONPATH": str(continuum_src),
                    "CONTINUUM_ROOT": str(root),
                },
            }
        }
    }


def _cachebuster(*, plugin_source: Path, mcp_payload: dict[str, Any] | None) -> str:
    digest = hashlib.sha256()
    digest.update(_plugin_tree_digest(plugin_source).encode("ascii"))
    digest.update(b"\0mcp\0")
    digest.update(_json_bytes(mcp_payload or {"local_mcp_config": "skipped"}))
    return digest.hexdigest()[:16]


def _is_direct_child(child: Path, parent: Path) -> bool:
    try:
        return child.resolve(strict=False).parent == parent.resolve(strict=False)
    except OSError:
        return False


def stage_codex_plugin(
    *,
    repo_root: Path,
    root: Path,
    python_cmd: str,
    stage_base: Path,
    skip_local_mcp_config: bool = False,
) -> Path:
    repo_root = repo_root.resolve()
    marketplace_json = repo_root / ".agents" / "plugins" / "marketplace.json"
    plugin_source = repo_root / "plugins" / "continuum"
    continuum_src = repo_root / "src"

    if not marketplace_json.is_file():
        raise FileNotFoundError(f"Marketplace file not found: {marketplace_json}")
    if not plugin_source.is_dir():
        raise FileNotFoundError(f"Plugin source not found: {plugin_source}")

    mcp_payload = None if skip_local_mcp_config else _local_mcp_payload(
        command=python_cmd,
        continuum_src=continuum_src,
        root=root,
    )
    cache = _cachebuster(plugin_source=plugin_source, mcp_payload=mcp_payload)
    stage_base.mkdir(parents=True, exist_ok=True)
    stage_root = stage_base / f"continuum-{cache}"
    if stage_root.exists():
        if not _is_direct_child(stage_root, stage_base) or not stage_root.name.startswith("continuum-"):
            raise ValueError(f"refusing to remove unsafe stage path: {stage_root}")
        shutil.rmtree(stage_root)

    stage_agents = stage_root / ".agents" / "plugins"
    stage_plugins = stage_root / "plugins"
    stage_plugin = stage_plugins / "continuum"
    stage_agents.mkdir(parents=True, exist_ok=True)
    stage_plugins.mkdir(parents=True, exist_ok=True)
    shutil.copy2(marketplace_json, stage_agents / "marketplace.json")
    shutil.copytree(plugin_source, stage_plugin, symlinks=False)

    if mcp_payload is not None:
        (stage_plugin / ".mcp.json").write_bytes(_json_bytes(mcp_payload))

    manifest_path = stage_plugin / ".codex-plugin" / "plugin.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    base_version = str(manifest.get("version", "0.0.0"))
    manifest["version"] = f"{base_version}.local.{cache[:12]}"
    manifest_path.write_bytes(_json_bytes(manifest))
    return stage_root


def main() -> int:
    parser = argparse.ArgumentParser(description="Stage the Epic Continuum Codex plugin marketplace safely.")
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--python", default="python")
    parser.add_argument("--stage-base", type=Path, required=True)
    parser.add_argument("--skip-local-mcp-config", action="store_true")
    args = parser.parse_args()

    stage_root = stage_codex_plugin(
        repo_root=args.repo_root,
        root=args.root,
        python_cmd=args.python,
        stage_base=args.stage_base,
        skip_local_mcp_config=args.skip_local_mcp_config,
    )
    print(stage_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
