#!/usr/bin/env bash
set -Eeuo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
root="${CONTINUUM_ROOT:-$HOME/.continuum}"
hermes_home="${HERMES_HOME:-$HOME/.hermes}"
python_cmd="${CONTINUUM_PYTHON:-python3}"
token_budget=1800
extra_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      root="$2"
      shift 2
      ;;
    --hermes-home)
      hermes_home="$2"
      shift 2
      ;;
    --python)
      python_cmd="$2"
      shift 2
      ;;
    --token-budget)
      token_budget="$2"
      shift 2
      ;;
    --skip-enable|--dry-run|--set-default-model)
      extra_args+=("$1")
      shift
      ;;
    --api-key)
      case "${2:-}" in
        ""|none|null|false)
          extra_args+=("$1" "$2")
          ;;
        *)
          printf 'Refusing --api-key with a secret-looking value; use --api-key-env NAME or Hermes protected secrets instead.\n' >&2
          exit 2
          ;;
      esac
      shift 2
      ;;
    --model-alias|--model-name|--model-provider|--base-url|--api-key-env|--context-length|--max-tokens)
      extra_args+=("$1" "$2")
      shift 2
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

continuum_src="$repo_root/src"
export PYTHONPATH="$continuum_src"

"$python_cmd" -m continuum install-hermes-adapter \
  --root "$root" \
  --hermes-home "$hermes_home" \
  --continuum-src "$continuum_src" \
  --token-budget "$token_budget" \
  "${extra_args[@]}"
