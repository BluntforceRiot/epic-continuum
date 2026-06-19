#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
root="${CONTINUUM_ROOT:-$HOME/.continuum}"
python_cmd="${CONTINUUM_PYTHON:-python3}"
stage_base="${CONTINUUM_CODEX_MARKETPLACE_STAGE:-$HOME/.cache/epic-continuum/codex-marketplace}"
skip_local_mcp_config=0
stage_only=0

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
      stage_base="$2"
      shift 2
      ;;
    --skip-local-mcp-config)
      skip_local_mcp_config=1
      shift
      ;;
    --stage-only)
      stage_only=1
      shift
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

stage_args=(
  "$repo_root/scripts/stage_codex_plugin.py"
  --repo-root "$repo_root"
  --root "$root"
  --python "$python_cmd"
  --stage-base "$stage_base"
)
if [[ "$skip_local_mcp_config" == "1" ]]; then
  stage_args+=(--skip-local-mcp-config)
fi

stage_root="$("$python_cmd" "${stage_args[@]}")"

if [[ "$stage_only" == "0" ]]; then
  codex plugin marketplace add "$stage_root"
  codex plugin add continuum@epic-continuum
fi

printf 'Epic Continuum Codex plugin installed from staged marketplace: %s\n' "$stage_root/.agents/plugins/marketplace.json"
printf 'Epic Continuum root: %s\n' "$root"
