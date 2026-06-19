<p align="center">
  <img src="https://raw.githubusercontent.com/BluntforceRiot/epic-continuum/main/assets/epic-continuum-logo.svg" alt="Epic Continuum logo" width="220" />
</p>

<h1 align="center">Epic Continuum</h1>

<p align="center">
  Durable context continuity, memory, and crash recovery for local AI agents.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-f4c76a?style=flat-square&labelColor=05070d"></a>
  <a href="pyproject.toml"><img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11+-79f0ff?style=flat-square&labelColor=05070d&logo=python&logoColor=79f0ff"></a>
  <a href="docs/integrations/adapter-kit.md"><img alt="Adapters" src="https://img.shields.io/badge/adapters-Codex%20%7C%20Hermes%20%7C%20MCP-99a7ff?style=flat-square&labelColor=05070d"></a>
  <a href="https://github.com/BluntforceRiot/epic-continuum/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/BluntforceRiot/epic-continuum/actions/workflows/ci.yml/badge.svg"></a>
  <a href="CHANGELOG.md"><img alt="Release: 0.1.0" src="https://img.shields.io/badge/release-0.1.0-8df3ff?style=flat-square&labelColor=05070d"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a>
  &middot; <a href="#thread-recovery">Thread Recovery</a>
  &middot; <a href="#mcp-server">MCP Server</a>
  &middot; <a href="#adapter-kit">Adapter Kit</a>
  &middot; <a href="docs/audits/RELEASE_AUDIT_SUMMARY.md">Audit Summary</a>
  &middot; <a href="docs/GLOSSARY.md">Glossary</a>
</p>

> [!IMPORTANT]
> Epic Continuum does not make a model's native context window literally
> infinite. It gives agents a durable continuity layer around finite context:
> ordered events, compact Cards, searchable evidence, operation receipts, and
> recovery packets.

> [!NOTE]
> Epic Continuum is not a MemPalace takedown, fork, or rewrite. It grew out of
> real use of memory tools, including MemPalace, and takes a different
> architecture: a Scroll that rolls into a Library instead of a palace of rooms
> and drawers.

## What It Is

Epic Continuum is a standalone persistent-memory substrate for agents. It turns
long-running work into an ordered Scroll, lets the model operate through a
token-limited Looking Glass, rolls older spans into structured Cards, preserves
raw evidence in a local Library, and gives agents a way to recover after context
compression, crashes, restarts, or handoffs.

The project is local-first, inspectable, and adapter-friendly. The core contract
lives in the Python CLI/MCP package; Codex, Hermes, Claude Code, OpenClaw, and
other agent surfaces plug into that shared memory layer rather than each keeping
their own isolated history.

## Why It Exists

Most agent failures are ordinary continuity failures: a thread gets too long, a
desktop app restarts, an operation is interrupted, the model forgets a decision,
or the next agent cannot tell which artifact is current. Epic Continuum is built
to make those failures recoverable with boring local evidence:

- the Scroll keeps order;
- Cards keep compact meaning;
- the Library keeps originals and reader editions;
- receipts keep long operations inspectable while they run;
- proof packs keep important artifacts verifiable;
- recovery packets make resume state explicit.

## Core Metaphor

```text
Scroll          append-only ordered event log
Looking Glass   token-limited active pane over the scroll
Scribe          writes events, chunks scroll spans, creates cards
Library         content-addressed archive of books and reader editions
Cards           compact structured summaries and placement records
Librarian       recall/ranking/placement role; basic heuristics implemented now
Archivist       integrity, snapshots, storage tiers, restore role
Constellation   weighted association graph
```

## Design Rule

The system may compact context and prune routes. It must not destroy evidence.

```text
raw event stays
book stays
card stays hot/searchable
atomic YAML sidecar stays portable
route may reinforce, decay, or tombstone
location may move hot -> warm -> cold -> vault
```

## Feature Preview

1. **Capture**
   Append user, assistant, tool, and operation events into a local Scroll.
2. **Compact**
   Roll older spans into structured Cards without deleting raw evidence.
3. **Recall**
   Compile context from Cards, Scroll events, recent work, and Library state;
   search currently queries Library chunks/books.
4. **Recover**
   Generate crash/thread recovery packets for Codex, Hermes, and other agents.
5. **Verify**
   Write operation receipts, proof packs, restore drills, and portable bundles.
6. **Share**
   Use a thin adapter kit for MCP-compatible clients and local agent runtimes.

## Project Status

This repo is the new standalone direction. The earlier MemGalaxy plugin inside
Neuroforge is useful prior art, but Epic Continuum owns the cleaner ground-up
architecture.

For a quick release-audit overview, see [docs/audits/RELEASE_AUDIT_SUMMARY.md](docs/audits/RELEASE_AUDIT_SUMMARY.md).
For terms, see [docs/GLOSSARY.md](docs/GLOSSARY.md).
For project direction, see [ROADMAP.md](ROADMAP.md).
For hardware budget design, see [docs/architecture/0004-hardware-budgets.md](docs/architecture/0004-hardware-budgets.md).
For configurable paths, see [docs/configuration.md](docs/configuration.md).
For Codex integration, see [docs/integrations/codex-plugin.md](docs/integrations/codex-plugin.md).
For the adapter kit, see [docs/integrations/adapter-kit.md](docs/integrations/adapter-kit.md).
For Hermes integration, see [docs/integrations/hermes-adapter.md](docs/integrations/hermes-adapter.md).

## Implemented Now

| Capability | Current status | Notes |
|---|---|---|
| Scroll/event log | Implemented | SQLite-backed ordered events per session. |
| Catalog Cards | Implemented | Basic summaries and portable YAML sidecars. |
| Library ingest | Implemented | Copies originals, writes reader editions, chunks text, size-guarded by config. |
| Looking Glass context | Implemented | Strict estimated-token budget, truncation metadata, read-only compile mode, and configurable card visibility scopes. |
| Card recall | Implemented | Defaults to `session_then_global`; callers can request `session`, `global`, or `project` recall. |
| Graph memory | Implemented heuristic | Nodes/edges are written, recalled Cards reinforce routes, and Librarian decay is interval-gated before pruning stale unpinned routes. |
| Library search | Implemented for ingested books/chunks | `continuum search` and MCP `continuum_search` query Library chunks/books with SQLite FTS5 when available and LIKE fallback. Use `compile-context`/`recover-thread` for Card and Scroll recall. |
| Import safety | Implemented | `.continuumignore`-style blocking and lightweight secret blocking are enabled by default for file ingest and MemPalace import; warning mode is configurable. |
| Proof packs | Implemented foundation | Manifest hashes frozen touched files, operation event logs, and receipt files after proof URI is written; live catalog DB paths are backed up before hashing. |
| Snapshots | Implemented | Catalog and card sidecars are copied with collision-resistant IDs. |
| Operation recovery | Implemented | Interrupted operations emit Markdown and `.recovery.json` packets; restore drills verify snapshots, copied recent proofs, artifact hashes, and recovery packet generation inside disposable roots. |
| MCP server | Implemented | Stdio server with JSON text plus `structuredContent`, generic `outputSchema`, and tool annotations. |
| Codex/Hermes/Claude adapters | Implemented scaffold | Thin adapters route turns through the CLI/MCP/Python core. |
| Capture policy | Implemented | Manual/assisted/automatic/paranoid modes, per-event category gates, tool-result byte caps, and adapter-facing snapshot hints. |
| Event deduplication | Implemented | Retries inside `capture.dedup_window_seconds` reuse the existing Scroll event and write an audit event. |
| Retention policy | Implemented heuristic | Hot/warm timing, storage tiering, topic pruning controls, max-root-size health checks, and pruning guardrails are configurable; destructive raw-evidence deletion is disabled by default. |
| MemPalace import | Implemented | Imports current Chroma/graph records with unique receipts, import-addressed evidence, import-state resume cursors, and catalog backup proof packs; paged row resume is planned. |
| Role workers | Implemented | `run-workers` and MCP `continuum_run_workers` process Scribe/Librarian/Archivist queues; `serve` runs the background loop. |
| Retrieval planner | Implemented heuristic | Current planner is lexical/FTS plus visibility and salience, not vector/LLM reranking. |
| Storage-tier movement | Implemented heuristic | Archivist tiering can move eligible books hot -> warm -> cold by retention age. |
| Memory quality evals | Implemented | `run-evals` runs deterministic recall/recovery/search checks in a disposable nested root. |
| Artifact schemas | Implemented | JSON schemas for receipts, proof packs, operation events, recovery packets, and atomic cards ship as package data. |
| Root handoff bundles | Implemented | `pack-root` creates a self-verifying ZIP after strict root, proof, artifact, secret, portability, and symlink-policy checks; `verify-bundle` validates the canonical ZIP envelope, reconstructs the embedded root, and reruns its current semantic health checks. |

## Quick Start

PowerShell:

```powershell
git clone https://github.com/BluntforceRiot/epic-continuum.git epic-continuum
cd epic-continuum
$env:PYTHONPATH = "$PWD\src"
$env:CONTINUUM_ROOT = "$HOME\.continuum"
python -m continuum init --root $env:CONTINUUM_ROOT
python -m continuum append-event --root $env:CONTINUUM_ROOT --session-id design --role user --type message --content "Epic Continuum starts as a scroll that rolls into a library."
python -m continuum status --root $env:CONTINUUM_ROOT
python -m continuum optimize-config --root $env:CONTINUUM_ROOT --profile balanced
python -m continuum run-workers --root $env:CONTINUUM_ROOT
python -m continuum memory-health --root $env:CONTINUUM_ROOT
python -m continuum recover-thread --root $env:CONTINUUM_ROOT --session-id design
Set-Content -Path .\continuum-note.txt -Value "Design note: Epic Continuum library search works over ingested files."
python -m continuum ingest-file --root $env:CONTINUUM_ROOT --path .\continuum-note.txt --title "Continuum design note"
python -m continuum search --root $env:CONTINUUM_ROOT --query "library search"
```

Bash:

```bash
git clone https://github.com/BluntforceRiot/epic-continuum.git epic-continuum
cd epic-continuum
export PYTHONPATH="$PWD/src"
export CONTINUUM_ROOT="$HOME/.continuum"
python -m continuum init --root "$CONTINUUM_ROOT"
python -m continuum append-event --root "$CONTINUUM_ROOT" --session-id design --role user --type message --content "Epic Continuum starts as a scroll that rolls into a library."
python -m continuum status --root "$CONTINUUM_ROOT"
python -m continuum optimize-config --root "$CONTINUUM_ROOT" --profile balanced
python -m continuum run-workers --root "$CONTINUUM_ROOT"
python -m continuum memory-health --root "$CONTINUUM_ROOT"
python -m continuum recover-thread --root "$CONTINUUM_ROOT" --session-id design
printf 'Design note: Epic Continuum library search works over ingested files.\n' > ./continuum-note.txt
python -m continuum ingest-file --root "$CONTINUUM_ROOT" --path ./continuum-note.txt --title "Continuum design note"
python -m continuum search --root "$CONTINUUM_ROOT" --query "library search"
```

Editable install:

```bash
python -m pip install -e .
```

## Hardware Budgets

Epic Continuum keeps durable memory on disk and uses RAM/VRAM as adjustable runtime
budgets. After `init`, edit the config under your selected state root:

```text
<continuum-root>\config\continuum.config.json
```

Budget values accept bytes or friendly units such as `512KB`, `128MB`, `4GB`,
and `1TB`.

Use `optimize-config` to detect GPU VRAM, system RAM, and root drive free space,
then preview recommended limits. Add `--write` to update the config file:

```powershell
python -m continuum optimize-config --root $env:CONTINUUM_ROOT --profile balanced --write
```

## Portable Root Bundles

Create a policy-checked handoff ZIP outside the Continuum root:

```bash
python -m continuum pack-root \
  --root "$CONTINUUM_ROOT" \
  --profile shareable \
  --out ./epic-continuum-root.zip
python -m continuum verify-bundle --path ./epic-continuum-root.zip
```

`pack-root` verifies every current proof pack and immutable artifact ledger row,
runs strict root and secret checks, rejects incomplete scans and allowlisted
secret-like findings for the `shareable` profile, and checks durable JSON, JSONL,
card YAML, and every actual SQLite database for raw local paths. The portability
audit includes config/state files, nested import snapshots, path-bearing key/value
metadata, camelCase path keys, file URIs, home-relative references, and Windows
drive/root-relative forms. Shareable bundles also fail on symlinks, unsupported
file types, unsafe archive names, and case/Unicode filename collisions that would
overwrite each other on another platform.

The command stages the root, backs up the live SQLite catalog through SQLite's
backup API, excludes process-local SQLite WAL/SHM/journal sidecars outside the
immutable `archive/` evidence namespace, verifies the staged copy, writes a
manifest containing every durable member SHA-256, size, and mode as exact UTF-8
with canonical LF newlines, normalizes ZIP timestamps, creates the archive, and
verifies the finished ZIP envelope again. External `verify-bundle` calls also
extract only manifest-bound members into a temporary directory and independently
rerun portability, secret, root, proof, and full artifact-ledger checks instead
of trusting self-rehashed preflight claims. Archived evidence is not silently
discarded merely because a nested name resembles `build`, `*.egg-info`, `*.pyc`,
`*.db-wal`, or `.name.tmp`. Bundle verification also rejects duplicate or
non-finite JSON, secret-bearing or nonportable manifest metadata, contradictory
policy/preflight claims, noncanonical manifest serialization, ZIP preambles or
trailing bytes, archive/member comments, unapproved extra fields, unnecessary or
malformed Zip64 records, noncanonical local headers, malformed member streams,
and bytes hidden after a valid DEFLATE end marker. `--force` preserves the
previously valid bundle/checksum pair and restores it if publication fails.
Non-force publication uses an atomic no-clobber path so a concurrent publisher is
not overwritten.

The output receives a sibling `.sha256` receipt only after final verification.
Extract the single `epic-continuum-root/` directory with a trusted ZIP tool, then
run `verify-root` on the extracted root. Use `--no-restore-drill` for a faster
bundle when a restore drill was already completed separately. `portable` bundles
may use `--symlink-policy skip`; `shareable` bundles require `fail` so evidence
is not silently omitted. Verification and audit CLI commands return a nonzero
exit status when their reported `ok` result is false or an audit is incomplete.

## Privacy And Storage

Epic Continuum stores memory locally under the state root you choose. On POSIX
systems, private directories are created as `0700` and sensitive state files,
SQLite files, receipts, snapshots, and configuration are tightened to `0600`;
`doctor` reports unsafe modes and `repair-permissions` can fix them.

The store is not encrypted at rest. Use an encrypted filesystem, disk
encryption, or an encrypted container when your Scroll, Library, or imported
evidence needs protection from someone with filesystem access to the machine.

## Thread Recovery

`recover-thread` builds a crash-recovery packet from the Scroll, Cards, pending
jobs, recent books, and open tasks. The output is written to
`exports/thread_recovery/*.md` and also returned by the CLI so it can be pasted
directly into Codex, Hermes, or another agent shell.

## MCP Server

Epic Continuum can run as a stdio MCP server for Codex, Claude Code, Cursor,
Windsurf, Claude Desktop, OpenClaw, Hermes, or other local
agents:

```powershell
$env:PYTHONPATH = "$PWD\src"
$env:CONTINUUM_ROOT = "$HOME\.continuum"
python -m continuum.mcp_server
```

```bash
export PYTHONPATH="$PWD/src"
export CONTINUUM_ROOT="$HOME/.continuum"
python -m continuum.mcp_server
```

The MCP surface mirrors the CLI: initialize/status/config, append Scroll events,
roll segments into Cards, ingest files, compile/search context, recover a
thread, audit, doctor, verify proof packs, snapshot, run recovery/restore
drills, import MemPalace, and optimize hardware budgets.

The server currently supports and advertises MCP protocol `2025-11-25`.
Tool responses include JSON text, `structuredContent`, generic `outputSchema`,
titles, and per-tool annotations.

For MCP callers, roots and file inputs are restricted by default to
`CONTINUUM_ROOT` plus any paths listed in `CONTINUUM_ALLOWED_ROOTS`. Set
`CONTINUUM_ALLOWED_ROOTS` when you want Codex or another MCP client to operate
on a repo or evidence folder outside the durable Epic Continuum root. Process-stopping
MemPalace imports require `CONTINUUM_MCP_ALLOW_PROCESS_STOP=1`.

## Adapter Kit

The repository includes first-party adapter material for:

```text
Codex, Hermes Agent, Claude Code, OpenClaw, Ollama,
OpenAI-compatible runtimes, Claude Desktop, Cursor, Windsurf, Continue.dev,
LangChain, LlamaIndex, CrewAI, AutoGen, Semantic Kernel, Haystack, and Aider.
```

The deeper rule is simple: adapters stay thin, and the durable memory contract
stays in the core CLI/MCP/Python package.

## MemPalace Import

Epic Continuum can import a MemPalace Chroma palace into the Library and graph:

```powershell
python -m continuum import-mempalace --root $env:CONTINUUM_ROOT --palace-path "$HOME\.mempalace\palace" --allow-stop
```

The command shows progress on stderr and returns a JSON receipt on stdout. It
serializes concurrent imports with a lock, snapshots the palace first, writes
per-import evidence under `archive/originals/hot/mempalace/by-import/`, and
proofs a frozen receipt, originals manifest, and `catalog.snapshot.sqlite3`
backup rather than the live catalog database. If the live palace database is
locked, `--allow-stop` lets Epic Continuum stop `mempalace-readonly-mcp` before
retrying the snapshot.

Every import also writes `<continuum-root>\run\import_state\<import_id>.json`
with phase, last embedding row, counts, error summaries, receipt/proof paths,
and a `mempalace:<import_id>` resume token. Imported text is scanned for obvious
secrets and marked as local evidence rather than authoritative instructions.

## Epic Continuity

Epic Continuum follows the rule: "No one said we could not back it up while
building it." Mutating CLI and MCP actions are guarded by default: they write
intent, progress, cursor, final status, and proof metadata while work happens.
Long-running operations write mirrored receipts while they run:

```text
<continuum-root>\run\operations\*.json
<continuum-root>\run\operation_events\*.jsonl
<continuum-root>\exports\operation_receipts\*.json
<continuum-root>\exports\operation_events\*.jsonl
```

Use the operation ledger and append-only operation event logs to recover or
inspect work that was interrupted:

```powershell
python -m continuum operations --root $env:CONTINUUM_ROOT
python -m continuum recover-operations --root $env:CONTINUUM_ROOT
python -m continuum recovery-drill --root $env:CONTINUUM_ROOT
python -m continuum restore-drill --root $env:CONTINUUM_ROOT
python -m continuum doctor --root $env:CONTINUUM_ROOT
```

Guarded results keep their normal JSON fields and add `_operation` with the
receipt and proof-pack paths. Stale `running` receipts can be marked
`interrupted` and turned into Markdown operation recovery packets. Operation
events are hash-chained JSONL entries and are included in proof packs.

Proof packs can be verified directly:

```powershell
python -m continuum verify-proof-pack <path-to-proof-pack.json>
```

The MCP server exposes the same diagnostics as `continuum_doctor` and
`continuum_verify_proof_pack`, with both JSON text and structured content in
tool responses.

When a proof request includes `<continuum-root>\catalog\catalog.sqlite3`, Epic
Continuum creates an immutable SQLite backup under
`exports\proof_artifacts\<operation_id>\catalog.snapshot.sqlite3` and hashes
that backup instead of the live WAL database.

## Atomic YAML Memory

Epic Continuum uses SQLite for indexed memory and atomic YAML sidecars for portable
memory units. Card sidecars live under `catalog/cards/*.yaml` by default. They
are meant for human review, git diffs, Hermes handoff, and rebuild/recovery
workflows. The bundled atomic YAML reader handles the deterministic subset Epic
Continuum writes, keeping sidecar rebuilds dependency-light.

## Storage Layout

```text
continuum-root/
  archive/
    originals/
      hot/
      warm/
      cold/
      vault/
    reader_editions/
      hot/
      warm/
      cold/
  catalog/
    catalog.sqlite3
    cards/*.yaml
  scroll/
    segments/
  graph/
  queues/
  snapshots/
  exports/
    thread_recovery/
    operation_receipts/
    proof_packs/
    operation_recovery/
    recovery_drills/
  config/
  run/
    operations/
    recovery_drills/
```
