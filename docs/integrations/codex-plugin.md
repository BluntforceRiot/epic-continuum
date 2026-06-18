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
`2025-11-25`.

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
modify the source checkout. Manual registration uses the staged or repo root:

```powershell
codex plugin marketplace add "$env:REPO_ROOT"
codex plugin add continuum@epic-continuum
```

## Recovery Command Pattern

When a Codex or Hermes thread crashes, use the MCP tool
`continuum_recover_thread` with the session id that was used while recording the
Scroll. The returned `packet_text` is a ready-to-paste recovery packet, and the
same packet is written to:

```text
<continuum-root>\exports\thread_recovery\*.md
```

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
- `continuum_search`
- `continuum_audit_search_index`
- `continuum_rebuild_search_index`
- `continuum_audit`
- `continuum_doctor`
- `continuum_repair_permissions`
- `continuum_verify_proof_pack`
- `continuum_snapshot`
- `continuum_import_mempalace`
- `continuum_list_operations`
- `continuum_operation_summary`
- `continuum_recover_operations`
- `continuum_recovery_drill`
- `continuum_restore_drill`

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
