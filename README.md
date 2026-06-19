<p align="center">
  <img src="https://raw.githubusercontent.com/BluntforceRiot/epic-continuum/main/assets/epic-continuum-logo.svg" alt="Epic Continuum logo" width="220" />
</p>

<h1 align="center">Epic Continuum</h1>

<p align="center">
  Persistent memory, bounded context, and crash recovery for local AI agents.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-f4c76a?style=flat-square&labelColor=05070d"></a>
  <a href="pyproject.toml"><img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11+-79f0ff?style=flat-square&labelColor=05070d&logo=python&logoColor=79f0ff"></a>
  <a href="docs/integrations/adapter-kit.md"><img alt="MCP and agent adapters" src="https://img.shields.io/badge/integrations-MCP%20%7C%20Codex%20%7C%20Claude%20%7C%20Hermes-99a7ff?style=flat-square&labelColor=05070d"></a>
  <a href="https://github.com/BluntforceRiot/epic-continuum/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/BluntforceRiot/epic-continuum/actions/workflows/ci.yml/badge.svg"></a>
  <a href="CHANGELOG.md"><img alt="Release: 0.1.0" src="https://img.shields.io/badge/release-0.1.0-8df3ff?style=flat-square&labelColor=05070d"></a>
</p>

<p align="center">
  <a href="#the-problem">The Problem</a>
  &middot; <a href="#how-memory-works">Memory</a>
  &middot; <a href="#how-the-context-window-works">Context Window</a>
  &middot; <a href="#what-this-looks-like-in-agents">Agent Flow</a>
  &middot; <a href="#how-continuum-keeps-work-from-being-lost">Recovery</a>
  &middot; <a href="#quick-start">Quick Start</a>
  &middot; <a href="#mcp-and-agent-integrations">Integrations</a>
</p>

> [!IMPORTANT]
> Epic Continuum does not make a model's native context window infinite. It keeps durable memory outside the model, then assembles the most useful subset into a bounded context packet for the work happening now.

## The Problem

A language model only sees what fits inside its current context window. That window is fast and useful, but finite and disposable.

During long-running work:

- early decisions fall out of context;
- summaries replace details;
- tool results become difficult to trace;
- a crash or restart can erase the active thread;
- a new agent may inherit files without knowing what happened;
- the model may remember the conclusion but lose the evidence behind it.

Epic Continuum separates **durable memory** from **active context**.

The complete history and evidence live on disk. The model receives a smaller, task-relevant working set that fits its current token budget. When the task restarts, Continuum rebuilds that working set from durable state rather than hoping the conversation survived.

```text
Model context window     fast, limited, temporary working memory
Epic Continuum root      durable, searchable, recoverable memory
Looking Glass packet     selected memory brought back into the model
```

The goal is not to put everything into every prompt. The goal is to preserve what matters, retrieve what is relevant, and make interrupted work resumable.

## How Memory Works

Epic Continuum uses several memory layers instead of treating all history as one giant transcript.

### 1. The Scroll captures experience in order

Every captured user message, assistant response, tool event, and operation event becomes an ordered Scroll entry.

```text
session: build-release
  101 user[message]       Verify the portable bundle before publishing.
  102 assistant[message]  I will run the strict root checks first.
  103 tool[call]          continuum_verify_root(...)
  104 tool[result]        root verification passed
```

The Scroll is the episodic record. Sequence matters because later summaries are easier to trust when the original order still exists.

Scroll events include durable identifiers, timestamps, roles, event types, content hashes, token estimates, and metadata. Secret policy is applied before persistence.

### 2. Cards preserve compact meaning

Recent events are useful, but a model cannot reread an unlimited transcript every turn. Older spans can be rolled into **Cards**.

A Card is a compact structured memory unit that can contain:

- a title and summary;
- decisions;
- open tasks;
- entities and topics;
- salience and recall history;
- source and session references;
- links to related memory objects.

Cards are stored in SQLite and as portable YAML sidecars. They are summaries and routing objects, not replacements for the underlying evidence.

### 3. The Library preserves source evidence

Files and imported material become Library books. Continuum keeps:

- an archived original;
- a normalized reader edition;
- searchable chunks;
- content hashes and provenance;
- storage-tier and integrity metadata.

SQLite FTS5 provides lexical search when available, with a simpler fallback otherwise.

```bash
continuum search \
  --root "$CONTINUUM_ROOT" \
  --query "release restore drill"
```

The Library answers, "Where is the evidence?" Cards answer, "What is important about it?" The Scroll answers, "What happened, and in what order?"

### 4. The Constellation records associations

Cards and other memory objects can be connected through weighted graph relationships. Recall reinforces useful routes. Maintenance workers can decay routes that are no longer used.

The graph helps related memory become easier to find without making the graph itself the source of truth. Preserved evidence remains authoritative.

### 5. Operations preserve work in progress

Long or mutating actions are recorded as guarded operations with:

- intent and status;
- progress updates;
- append-only operation event logs;
- result and error records;
- receipts;
- frozen proof artifacts;
- proof packs.

This is operational memory. It answers, "What was the agent doing when it stopped?"

## How the Context Window Works

The model's native context remains finite. Epic Continuum works around that limit by compiling a **Looking Glass** packet.

The Looking Glass is not the entire memory store. It is a bounded view over durable memory.

Think of the model context as the agent's current working set. It is fast, but it has a hard size limit and disappears when the session is gone. Continuum is the durable state beside it: Scroll entries, Cards, Library evidence, operations, receipts, and snapshots. The Looking Glass is the selected slice of that durable state that gets brought back into the model for the next turn.

That means Continuum does not make a 16K, 64K, or 200K model internally larger. Instead, it gives the agent a fast external memory loop:

```text
conversation/tool activity
        |
        v
capture to durable Scroll and operations
        |
        v
compact into Cards and searchable Library evidence
        |
        v
retrieve the relevant subset
        |
        v
compile a token-bounded Looking Glass packet
        |
        v
agent receives only what it needs right now
```

The context window still has a budget. Continuum makes that budget repeatable, inspectable, and recoverable.

### Current context-compilation flow

When `compile-context` runs, Continuum:

1. applies the requested token budget and the configured maximum;
2. loads the newest Scroll events for the selected session;
3. preserves chronological order in the emitted packet;
4. extracts terms from an optional query;
5. recalls matching Cards within the selected session, project, or global scope;
6. orders Card candidates by salience and recency;
7. adds material until the usable budget is exhausted;
8. truncates the final item safely when needed;
9. reports estimated tokens, remaining budget, and every truncation.

```bash
continuum compile-context \
  --root "$CONTINUUM_ROOT" \
  --session-id build-release \
  --query "current release blockers and next action" \
  --token-budget 4000
```

The returned packet includes machine-readable budget information and a plain `context_text` section that can be passed to the agent.

```text
Durable memory on disk
        |
        +---- recent Scroll events
        +---- query-matched Cards
        +---- session/project/global scope
        |
        v
Token-budgeted Looking Glass
        |
        v
Model's active context window
```

Current context compilation directly emphasizes recent Scroll events and matching Cards. Deeper Library evidence is retrieved through `search`, while thread recovery also gathers recent books, pending jobs, decisions, and open tasks.

This is deliberate. Recent work stays close. Compact meaning is recalled when relevant. Full evidence remains available without being stuffed into every prompt.

### Why this is safer than an ever-growing prompt

An ever-growing prompt eventually forces silent truncation, aggressive summarization, or both. That creates two different failure modes:

- information disappears without a durable record;
- compressed conclusions survive while their evidence vanishes.

Continuum keeps the durable record outside the prompt. Context can be rebuilt repeatedly without deleting the source history.

## What This Looks Like In Agents

Epic Continuum is useful because the memory is not trapped inside one chat application, one model, or one agent runtime.

Codex can use it through the local Codex plugin and MCP server. Claude Code and other MCP-capable tools can use the same server pattern. Hermes Agent and local LLM setups can use the Hermes adapter or the generic CLI/OpenAI-compatible adapter pattern. The model can be a hosted model, a local Qwen/vLLM route, another OpenAI-compatible endpoint, or a smaller model running on local hardware.

The important part is that they can point at the same Continuum root.

```text
Codex thread
        |
Claude Code session ----> shared Epic Continuum root
        |
Hermes/local LLM
```

Each agent can write events, read recovery packets, search Library evidence, and compile a bounded Looking Glass from the same durable state. That makes Continuum a shared memory layer rather than a per-client transcript.

In practice, the loop feels simple:

```text
You: Remember that the release blocker is the Windows reparse-point health bug.
Agent: writes that event into the Scroll through Continuum.

You: What were we doing before the restart?
Agent: asks Continuum for status and recovery context.
Continuum: returns recent events, Cards, open tasks, and operation receipts.
Agent: answers with the current state instead of starting cold.
```

The memory is stored in the configured Continuum root. A restarted Codex thread, a Claude Code session, Hermes, or another MCP-compatible agent can point at that same root and recover the same project state.

This is why a useful memory can appear "a few seconds later": the agent is not waiting for a model to retrain or for a giant transcript to be pasted back in. It writes a small structured event locally, then retrieves or compiles that local state when it is needed.

This helps in a few concrete ways:

- **Cross-agent handoff:** Codex can do implementation work, Claude Code can review it later, and both can see the same recovery packets and operation receipts.
- **Local model continuity:** a local LLM with a smaller native context can still use durable project memory by receiving only the relevant Looking Glass packet for the current turn.
- **Fair model comparison:** different models can be tested against the same saved context instead of relying on whatever one chat happened to remember.
- **Crash recovery:** if a desktop client, terminal, or model server dies, the next agent can recover from disk-backed Scroll events, Cards, and receipts.
- **Less prompt stuffing:** large evidence stays in the Library and only selected summaries or search results enter the model context.

Typical agent commands are conversational:

```text
"Remember this decision."
"Recover the thread from yesterday."
"Check Continuum status before we continue."
"Compile the current release context."
"Write a recovery packet before we switch tasks."
```

Under the hood those requests map to tools such as `continuum_append_event`, `continuum_status`, `continuum_compile_context`, `continuum_recover_thread`, and `continuum_snapshot`. For local LLMs, Continuum does not increase the model server's native context length; it improves the effective working memory around that limit by retrieving and compressing the right durable context before inference.

## How Continuum Keeps Work From Being Lost

Continuum protects work at several boundaries.

### During the conversation

Adapters or MCP tools capture turns and tool activity into the Scroll. The memory does not depend on one client preserving one chat transcript.

### During long operations

Guarded operations write receipts and append-only event logs as work progresses. A crash does not have to erase every intermediate step.

```bash
continuum operations --root "$CONTINUUM_ROOT"
continuum recover-operations --root "$CONTINUUM_ROOT"
```

### At context boundaries

Older Scroll spans can be rolled into Cards while the source events remain available.

```bash
continuum roll-segment \
  --root "$CONTINUUM_ROOT" \
  --session-id build-release
```

Background workers can perform compaction and maintenance automatically:

```bash
continuum run-workers --root "$CONTINUUM_ROOT"
```

### At restart or handoff

`recover-thread` creates a recovery packet containing:

- a fresh Looking Glass context;
- recent Scroll events;
- recalled Cards;
- explicit decisions and open tasks;
- pending worker jobs;
- recent Library books;
- a resume instruction.

```bash
continuum recover-thread \
  --root "$CONTINUUM_ROOT" \
  --session-id build-release \
  --query "resume release validation"
```

The packet is written under `exports/thread_recovery/` so another model, another client, or a later session can resume from durable state.

### At the filesystem boundary

Snapshots, proof packs, artifact hashes, restore drills, and strict root verification test whether the stored state is actually usable.

```bash
continuum snapshot --root "$CONTINUUM_ROOT" --reason "before release"
continuum restore-drill --root "$CONTINUUM_ROOT"
continuum verify-root --root "$CONTINUUM_ROOT" --strict
```

### At the handoff boundary

A shareable root bundle is verified before publication:

```bash
continuum pack-root \
  --root "$CONTINUUM_ROOT" \
  --profile shareable \
  --out ./epic-continuum-root.zip

continuum verify-bundle \
  --path ./epic-continuum-root.zip
```

The bundle workflow checks root health, secrets, portability, proof packs, artifact hashes, archive safety, and restore behavior. The goal is not merely to copy files. It is to produce a handoff object that can prove what it contains.

## Recommended Operating Pattern

For the best continuity, use this lifecycle:

```text
1. Initialize one Continuum root.
2. Give every meaningful task a stable session or project identity.
3. Capture user, assistant, and tool events continuously.
4. Ingest important source files into the Library.
5. Compile a bounded Looking Glass before or during major turns.
6. Roll older spans into Cards or run background workers.
7. Record mutating work as guarded operations.
8. Generate a recovery packet at task boundaries and before handoff.
9. Run strict verification before backup, transfer, or release.
10. Pack a shareable bundle instead of copying a live root blindly.
```

The minimum practical rule is simple:

> Capture before compaction, preserve before pruning, and verify before handoff.

## Quick Start

### Install

```bash
git clone https://github.com/BluntforceRiot/epic-continuum.git
cd epic-continuum
python -m venv .venv
```

PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install .
$env:CONTINUUM_ROOT = "$HOME\.continuum"
```

Linux, macOS, or WSL:

```bash
source .venv/bin/activate
python -m pip install .
export CONTINUUM_ROOT="$HOME/.continuum"
```

### Initialize and record a session

```bash
continuum init --root "$CONTINUUM_ROOT"

continuum append-event \
  --root "$CONTINUUM_ROOT" \
  --session-id demo \
  --role user \
  --type message \
  --content "Keep this deployment task recoverable across restarts."
```

### Compile working context

```bash
continuum compile-context \
  --root "$CONTINUUM_ROOT" \
  --session-id demo \
  --query "deployment status and next step" \
  --token-budget 3000
```

### Recover later

```bash
continuum recover-thread \
  --root "$CONTINUUM_ROOT" \
  --session-id demo
```

Run `continuum --help` for the complete CLI.

## MCP and Agent Integrations

Epic Continuum includes a stdio MCP server so multiple agent clients can use the same durable memory root.

```bash
export CONTINUUM_ROOT="$HOME/.continuum"
python -m continuum.mcp_server
```

PowerShell:

```powershell
$env:CONTINUUM_ROOT = "$HOME\.continuum"
python -m continuum.mcp_server
```

The MCP surface covers event capture, context compilation, search, file ingestion, recovery, snapshots, proof verification, health checks, workers, and maintenance.

MCP file access is confined by default to `CONTINUUM_ROOT` and explicitly allowed paths.

Integration guides:

- [Codex](docs/integrations/codex-plugin.md)
- [Hermes Agent](docs/integrations/hermes-adapter.md)
- [Adapter kit and supported clients](docs/integrations/adapter-kit.md)

## Health, Privacy, and Maintenance

```bash
continuum status --root "$CONTINUUM_ROOT"
continuum memory-health --root "$CONTINUUM_ROOT"
continuum doctor --root "$CONTINUUM_ROOT"
continuum audit-secrets --root "$CONTINUUM_ROOT"
continuum audit-search-index --root "$CONTINUUM_ROOT"
continuum repair-permissions --root "$CONTINUUM_ROOT"
```

Epic Continuum is local-first and does not require a hosted service. It is not encrypted at rest. Use filesystem, volume, or disk encryption when stored evidence is sensitive.

Secret scanning is conservative and heuristic. Review findings before sharing a root, and use the shareable bundle workflow for handoff.

## Storage Layout

```text
continuum-root/
  archive/                 preserved originals and reader editions
  catalog/
    catalog.sqlite3        Cards, chunks, graph, operations, and indexes
    cards/                 portable YAML Card sidecars
  scroll/                  rolled Scroll segments
  graph/                   association data
  queues/                  durable worker queues
  snapshots/               catalog and sidecar snapshots
  exports/
    thread_recovery/       recovery packets
    operation_receipts/    mirrored operation receipts
    operation_events/      append-only operation logs
    proof_packs/           verification manifests
    proof_artifacts/       frozen proof inputs
  config/                  root configuration
  run/                     active operation and service state
```

## Current Status

Epic Continuum `0.1.0` is a beta release. The core CLI, Python package, stdio MCP server, memory layers, recovery system, proof pipeline, portable bundle workflow, adapters, and workers are implemented.

Current context compilation uses recent Scroll events plus query-matched Cards under a strict token budget. Library search is lexical through SQLite FTS5 when available. Ranking, graph routing, placement, retention, and consolidation include heuristic behavior that will continue to evolve.

See the [roadmap](ROADMAP.md) for planned work and the [release audit summary](docs/audits/RELEASE_AUDIT_SUMMARY.md) for release-gate evidence.

## Documentation

- [Configuration](docs/configuration.md)
- [Glossary](docs/GLOSSARY.md)
- [Project charter](PROJECT_CHARTER.md)
- [Roadmap](ROADMAP.md)
- [Release audit summary](docs/audits/RELEASE_AUDIT_SUMMARY.md)
- [Codex integration](docs/integrations/codex-plugin.md)
- [Hermes integration](docs/integrations/hermes-adapter.md)
- [Adapter kit](docs/integrations/adapter-kit.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## Contributing

Bug reports, focused fixes, portability testing, adapter improvements, and documentation corrections are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## License

Epic Continuum is released under the [MIT License](LICENSE).
