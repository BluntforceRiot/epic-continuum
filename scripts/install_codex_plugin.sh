#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
root="${CONTINUUM_ROOT:-$HOME/.continuum}"
python_cmd="${CONTINUUM_PYTHON:-python3}"
stage_root="${CONTINUUM_CODEX_MARKETPLACE_STAGE:-$HOME/.cache/epic-continuum/codex-marketplace}"
skip_local_mcp_config=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root)
      repo_root="$2"
      shift 2
      ;;
    --root)
      root="$2"
      shift 2
      ;;
    --python)
      python_cmd="$2"
      shift 2
      ;;
    --stage-root)
      stage_root="$2"
      shift 2
      ;;
    --skip-local-mcp-config)
      skip_local_mcp_config=1
      shift
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

marketplace_json="$repo_root/.agents/plugins/marketplace.json"
plugin_source="$repo_root/plugins/continuum"
continuum_src="$repo_root/src"

[[ -f "$marketplace_json" ]] || {
  printf 'Marketplace file not found: %s\n' "$marketplace_json" >&2
  exit 1
}
[[ -d "$plugin_source" ]] || {
  printf 'Plugin source not found: %s\n' "$plugin_source" >&2
  exit 1
}

rm -rf "$stage_root"
mkdir -p "$stage_root/.agents/plugins" "$stage_root/plugins"
cp "$marketplace_json" "$stage_root/.agents/plugins/marketplace.json"
cp -R "$plugin_source" "$stage_root/plugins/continuum"

if [[ "$skip_local_mcp_config" == "0" ]]; then
  "$python_cmd" - "$stage_root/plugins/continuum/.mcp.json" "$python_cmd" "$continuum_src" "$root" <<'PY'
import json
import sys
from pathlib import Path

path, command, src, root = sys.argv[1:5]
payload = {
    "mcpServers": {
        "continuum": {
            "command": command,
            "args": ["-m", "continuum.mcp_server"],
            "env": {"PYTHONPATH": src, "CONTINUUM_ROOT": root},
        }
    }
}
Path(path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
fi

codex plugin marketplace add "$stage_root"
codex plugin add continuum@epic-continuum

printf 'Epic Continuum Codex plugin installed from staged marketplace: %s\n' "$stage_root/.agents/plugins/marketplace.json"
printf 'Epic Continuum root: %s\n' "$root"
