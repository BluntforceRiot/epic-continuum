# Codex Integration

Epic Continuum ships its durable logic in the Python package and exposes that logic
through a tiny stdio MCP server:

```powershell
$env:REPO_ROOT = "$PWD"
$env:PYTHONPATH = "$env:REPO_ROOT\src"
$env:CONTINUUM_ROOT = "$HOME\.continuum"
python -m continuum.mcp_server
```

```bash
export REPO_ROOT="$PWD"
export PYTHONPATH="$REPO_ROOT/src"
export CONTINUUM_ROOT="$HOME/.continuum"
python -m continuum.mcp_server
```

## Preferred: Codex MCP Server

Register the server with Codex's MCP configuration first. With the Codex CLI:

```powershell
$env:REPO_ROOT = "$PWD"
$env:CONTINUUM_ROOT = "$HOME\.continuum"
codex mcp add continuum --env PYTHONPATH="$env:REPO_ROOT\src" --env CONTINUUM_ROOT="$env:CONTINUUM_ROOT" -- python -m continuum.mcp_server
```

```bash
export REPO_ROOT="$PWD"
export CONTINUUM_ROOT="$HOME/.continuum"
codex mcp add continuum --env PYTHONPATH="$REPO_ROOT/src" --env CONTINUUM_ROOT="$CONTINUUM_ROOT" -- python -m continuum.mcp_server
```

Equivalent `~/.codex/config.toml` MCP entries are also fine when you manage
Codex configuration directly. The server currently supports MCP protocol
`2025-11-25`. Stdio request frames are limited to 256 KiB; an oversized or
invalid UTF-8 frame returns a parse error and the server resumes at the next
newline-delimited request. `continuum_record_project_state` mirrors the core
checkpoint field, item-count, and metadata limits described in
[Shared Agent State](../shared-agent-state.md). Project-state metadata accepts
only string values under the benign integration keys `agent_type`, `client_name`, `client_version`,
`hook_event_name`, `model`, `platform`, `source`, `task_id`, and `turn_id`.
Temporal authority, conflict membership, dismissal, and supersession fields are
owned by Continuum and cannot be supplied through the public MCP surface.

MCP roots and file inputs are restricted by default to `CONTINUUM_ROOT` plus
paths listed in `CONTINUUM_ALLOWED_ROOTS`. Add the repo, workspace, or evidence
folder there before asking Codex to ingest files outside the durable Continuum
root. Process-stopping MemPalace imports require
`CONTINUUM_MCP_ALLOW_PROCESS_STOP=1`.

The optional local Codex plugin is intentionally thin. It installs from the
dedicated marketplace id `epic-continuum` as `continuum@epic-continuum`, so new
threads can ask Epic Continuum for status, append Scroll events, recover old
sessions, ingest files, snapshot the catalog, and optimize hardware budgets.
The checked-in `.mcp.json` uses a tiny plugin-local runner. The runner adds
`<repo-root>/src` when the portable source tree is present and otherwise falls
back to an installed Python package, using the server's default `~/.continuum`
root. The installer scripts create a staged marketplace copy with generated
local source/root paths before Codex caches the plugin; they do not rewrite the
tracked checkout. Treat `.codex-plugin` packaging as a convenience wrapper, not
the durable memory contract itself.

Mutating MCP tools return their normal JSON payload plus an `_operation` object
with the operation receipt and proof-pack paths.

## Included Skills

The plugin includes two Codex skills:

- `continuum-memory` for persistent memory, crash recovery, context packets,
  Cue Recall, shared project state, and ordinary review-relay use.
- `pro-review-relay` for the private browser-only review loop where Codex
  prepares one `review-capsule.zip`, a signed-in reviewer returns JSON, and
  Continuum ingests the hash-bound result before Codex applies findings.

## Configurable Paths

Epic Continuum should not assume a specific drive or username. Set
`CONTINUUM_ROOT` to choose where durable Scroll, Library, Card, graph, queue,
snapshot, and export state live. Set `PYTHONPATH` or install the package so the
MCP process can import `continuum`.

If you want the plugin wrapper too, install it with:

```powershell
.\scripts\install_codex_plugin.ps1 -Root "$env:CONTINUUM_ROOT"
```

```bash
./scripts/install_codex_plugin.sh --root "$CONTINUUM_ROOT"
```

The portable repo includes `.agents/plugins/marketplace.json`. The installer
stages that marketplace before registration so generated local paths do not
modify the source checkout. The staged marketplace path is stable:

```text
<stage-base>/epic-continuum
```

Only the generated plugin version changes when the Continuum root, Python path,
or plugin content changes. That keeps Codex's marketplace source stable while
still forcing its plugin cache to refresh. Manual registration should therefore
use the staged path printed by the installer or helper, not the tracked repo
root:

```powershell
$stage = python .\scripts\stage_codex_plugin.py --repo-root "$PWD" --root "$env:CONTINUUM_ROOT" --python python --stage-base "$HOME\.cache\epic-continuum\codex-marketplace"
codex plugin marketplace add $stage
codex plugin add continuum@epic-continuum
```

```bash
stage="$(python3 ./scripts/stage_codex_plugin.py --repo-root "$PWD" --root "$CONTINUUM_ROOT" --python python3 --stage-base "$HOME/.cache/epic-continuum/codex-marketplace")"
codex plugin marketplace add "$stage"
codex plugin add continuum@epic-continuum
```

## Recovery Command Pattern

When a Codex or Hermes thread crashes, use `continuum_recover_thread` with a
known session id. When it is unknown, use `continuum_resume_latest` with the
best-known project id. The returned `packet_text` is a ready-to-paste recovery
packet, and the same packet is written to:

```text
<continuum-root>\exports\thread_recovery\*.md
```

If the requested authority boundary has multiple validated independent-agent
heads, `continuum_resume_latest` returns `authority_ambiguous` with
`resolution_required=true` and writes no packet. Resolve or merge the competing
component before retrying; timestamp recency is not an authority decision. For
compatible independent heads that were not grouped by conflict detection, call
`continuum_resolve_conflict` once with only the selected `card_id`; it fails
closed and reports the complete required peer list because the resume result
contains only a bounded sample. Repeat every reported ID in
`superseded_card_ids`. The complete boundary is required.

## Tool Surface

- `continuum_init`
- `continuum_status`
- `continuum_config`
- `continuum_optimize_config`
- `continuum_append_event`
- `continuum_roll_segment`
- `continuum_ingest_file`
- `continuum_compile_context`
- `continuum_recover_thread`
- `continuum_resume_latest`
- `continuum_cue_recall`
- `continuum_record_project_state`
- `continuum_search`
- `continuum_audit_search_index`
- `continuum_rebuild_search_index`
- `continuum_reindex_memory`
- `continuum_audit`
- `continuum_doctor`
- `continuum_repair_permissions`
- `continuum_audit_secrets`
- `continuum_run_workers`
- `continuum_memory_health`
- `continuum_yarn_health`
- `continuum_tier_storage`
- `continuum_prune_memory`
- `continuum_detect_conflicts`
- `continuum_resolve_conflict`
- `continuum_decay_routes`
- `continuum_run_evals`
- `continuum_verify_proof_pack`
- `continuum_verify_root`
- `continuum_pack_root`
- `continuum_verify_bundle`
- `continuum_replay_operation_log`
- `continuum_redact_legacy_secrets`
- `continuum_snapshot`
- `continuum_import_mempalace`
- `continuum_list_operations`
- `continuum_operation_summary`
- `continuum_recover_operations`
- `continuum_recovery_drill`
- `continuum_restore_drill`
- `continuum_review_prepare`
- `continuum_review_run`
- `continuum_review_ingest`
- `continuum_review_status`
- `continuum_review_check_current`
- `continuum_review_browser_attempt_start`

`continuum_review_prepare` accepts the same narrow secret-scan exceptions as
the CLI: `secret_allowlist_files` for UTF JSONL files containing exact
source/line/type/secret-hash/line-hash fingerprints. The legacy
`secret_allowlist_patterns` argument remains only for non-hashed false
positives; hashed token and private-key findings require exact fingerprints.
The public review capsule records only counts, not local allowlist file paths.

## MemPalace Import

Epic Continuum can migrate the existing MemPalace palace into its Library and graph:

```powershell
python -m continuum import-mempalace --root $env:CONTINUUM_ROOT --palace-path "$HOME\.mempalace\palace" --allow-stop
```

The importer first tries a SQLite snapshot. If the live Chroma database is
locked and `--allow-stop` is present, it stops `mempalace-readonly-mcp`, snapshots
the palace, imports drawers/closets/KG records, and writes a JSON receipt to:

```text
<continuum-root>\exports\imports\
```

Long imports also mirror operation receipts while they run:

```text
<continuum-root>\run\operations\
<continuum-root>\exports\operation_receipts\
```
