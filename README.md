<p align="center">
  <img src="https://raw.githubusercontent.com/BluntforceRiot/epic-continuum/main/assets/epic-continuum-header.png" alt="Epic Continuum neon horizon header" width="100%" />
</p>

<h1 align="center">Epic Continuum</h1>

<p align="center">
  Durable local memory for AI agents, with bounded context reconstruction, crash recovery, and verifiable handoff bundles.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-f4c76a?style=flat-square&labelColor=05070d"></a>
  <a href="pyproject.toml"><img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11+-79f0ff?style=flat-square&labelColor=05070d&logo=python&logoColor=79f0ff"></a>
  <a href="docs/integrations/adapter-kit.md"><img alt="MCP and agent adapters" src="https://img.shields.io/badge/integrations-MCP%20%7C%20CLI%20%7C%20Python-99a7ff?style=flat-square&labelColor=05070d"></a>
  <a href="https://github.com/BluntforceRiot/epic-continuum/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/BluntforceRiot/epic-continuum/actions/workflows/ci.yml/badge.svg"></a>
  <a href="CHANGELOG.md"><img alt="Release: 0.3.0" src="https://img.shields.io/badge/release-0.3.0-8df3ff?style=flat-square&labelColor=05070d"></a>
</p>

<p align="center">
  <a href="#the-problem">Problem</a>
  &middot; <a href="#whats-new-in-03">0.3 Update</a>
  &middot; <a href="#how-memory-works">Memory</a>
  &middot; <a href="#how-the-context-window-works">Context</a>
  &middot; <a href="#cue-recall">Cue Recall</a>
  &middot; <a href="#shared-agent-state">Agent State</a>
  &middot; <a href="#review-relay">Review Relay</a>
  &middot; <a href="#how-work-is-not-lost">Recovery</a>
  &middot; <a href="#quick-start">Quick Start</a>
  &middot; <a href="#benchmarks">Benchmarks</a>
  &middot; <a href="#documentation">Docs</a>
</p>

> [!IMPORTANT]
> Epic Continuum does not claim infinite context. It keeps durable memory outside the model, then rebuilds a bounded context packet for the work happening now.

## What's New In 0.3

Epic Continuum 0.3 turns durable memory into a safer daily recovery system:

- **Automatic resume** discovers the newest durable project/session checkpoint;
  an internal thread ID is optional, only the newest same-agent checkpoint
  remains current, and unresolved independent-agent heads fail closed as
  `authority_ambiguous` instead of being chosen by timestamp.
- **Looking Glass planner v2** balances Scroll, Cards, and Cue Recall, preserves
  authority labels, excludes contested/superseded current candidates, and emits
  an explainable selection trace under a hard token budget.
- **Temporal memory review** can explicitly supersede an old Card or dismiss a
  false-positive conflict while retaining historical evidence. System-owned
  receipts bind every resolved member, its authority boundary, and the audit
  event in the same transaction.
- **Immutable, crash-recoverable Card sidecars** use content-addressed
  copy-on-write generations, durable write/transition intents, paired recovery
  receipts, and exact snapshot/restore inventories so historical proof bytes
  are preserved without losing the catalog-selected current state. Managed
  filename aliases remain portable across case-sensitive and case-insensitive
  filesystems, while case-colliding IDs or filenames fail closed.
- **Yarn/Qwythos local assistance** can produce citation-bound, non-authoritative
  recovery briefings through a loopback llama.cpp endpoint. It is optional and
  fails back to the deterministic packet.
- **Homelab Guardian controls** enforce measurable resource headroom, a
  process-local inference gate backed by the recommended one-slot server,
  request/response limits, one end-to-end wall-clock deadline, model identity,
  secret redaction, circuit breaking, and a conservative context ceiling.
- **Personal profiles** remember safe context, preferred project resume, and
  whether Yarn should assist recovery.
- **Expanded health telemetry** reports queue age, running-job heartbeat, Scroll
  segmentation lag, sidecar backlog, snapshots, and live WAL state.

The 0.2 foundations remain: Cue Recall, shared project state, hash-bound review,
persistent workers, proof storage, external proof archives, and writer claims.

The Scroll remains the ordered source of truth. Cards, graph routes, indexes,
and sidecars are derived recall structures; proof packs, snapshots, and bundles
remain separately verifiable evidence.

## The Problem

AI agents do useful work inside a finite, temporary context window. That creates a practical failure mode:

- old messages eventually fall out of the active window or get compressed;
- applications restart or crash;
- one agent hands work to another agent;
- decisions, paths, artifacts, and next actions can be lost;
- replaying a whole transcript is expensive, noisy, and often impossible.

Epic Continuum treats memory as local infrastructure instead of a chat feature. The model thinks inside the current window. Continuum remembers outside it.

## How Memory Works

Epic Continuum stores several kinds of memory because a transcript, a summary, and a verified artifact are not the same thing.

- **Scroll:** the ordered event history of user turns, assistant turns, tool activity, and operation events.
- **Cards:** compact durable meaning extracted from older work, including decisions, open tasks, topics, and source references.
- **Library:** source material, ingested files, reader editions, searchable chunks, hashes, and provenance.
- **Constellation:** relationships between memory objects, including associations that can strengthen through use or decay when stale.
- **Looking Glass:** the selected memory packet that fits the next model context budget.
- **Continuity evidence:** operation ledgers, receipts, snapshots, proof packs, recovery packets, and portable bundles.

Raw evidence and compact recall objects have different jobs. The Scroll and Library preserve what happened and where evidence lives. Cards and graph routes make recall faster. Receipts, snapshots, proof packs, and bundles make recovery and handoff inspectable.

```mermaid
flowchart TD
    A["Agent / User / Tools"] --> B["Scroll: ordered events"]
    B --> C["Recent events"]
    B --> D["Scribe compaction"]
    D --> E["Cards: compact meaning"]
    E --> F["Library + Constellation"]
    C --> G["Looking Glass selection"]
    F --> G
    G --> H["Token budget"]
    H --> I["Context packet for the model"]
    B --> J["Continuity / evidence path"]
    J --> K["Receipts"]
    J --> L["Snapshots"]
    J --> M["Proof packs"]
    J --> N["Recovery packets"]
    J --> O["Portable bundles"]
```

## How The Context Window Works

The model still has a finite token budget. Continuum does not make a model server attend to more tokens than it supports.

Instead, context reconstruction follows a repeatable pattern:

1. The agent provides the current session, task, and optional query.
2. By default, `compile_context` gathers recent Scroll events and matching Cards. When an agent explicitly asks for it with `include_cue_recall` / `--include-cue-recall`, the direct compiler can also add a budgeted `cue_recall_candidates` section from Cue Recall. Library search, operation receipts, proof artifacts, and bundles remain durable queryable evidence, but they are not silently inserted into every direct context packet.
3. The direct compiler filters by visibility, project/session scope, textual relevance, recency, and Card salience.
4. Recovery uses `planner_profile=resume`: Looking Glass balances sources, excludes superseded or contested current Cards, labels authority, and records why each candidate was included or rejected.
5. The model sees that packet, not the entire memory root.
6. Durable memory stays outside the model and can be queried again later.

Context compilation must never silently exceed the requested budget. If material does not fit, it must be excluded or explicitly truncated with metadata.

## How Work Is Not Lost

Epic Continuum records work while it happens:

- conversation and tool events are appended to the Scroll;
- long operations receive durable operation state;
- progress and cursor state are written during execution;
- important artifacts can be hashed and described;
- snapshots preserve restorable state;
- recovery packets identify current state and next actions;
- portable bundles support verified handoff.

The system separates:

- **remembered conversation:** what was said and done;
- **searchable evidence:** source files, chunks, and provenance;
- **current task state:** decisions, open work, operation status, and next actions;
- **verified artifacts:** files and receipts with hashes;
- **restorable system state:** snapshots and bundles that can be checked later.

## Agent Flow

Epic Continuum is useful because memory is not trapped inside one chat application, one model, or one agent runtime.

Codex can use it through the local plugin and MCP server. Claude Code and other MCP-capable tools can use the same server pattern. Local LLM setups can use the CLI, Python API, MCP server, or adapter patterns. The important part is that they can point at the same Continuum root.

> [!WARNING]
> A live Continuum root must have exactly one writer runtime and host. New empty
> roots are claimed automatically on their first mutation. Existing unclaimed
> roots must be claimed explicitly. Do not run Windows and WSL writers against
> the same root, even when both can see the same files.

```text
Codex thread
        |
Claude Code session ----> shared Epic Continuum root
        |
Local LLM / agent runtime
```

A typical flow:

```text
You: Remember that the release blocker is the Windows reparse-point health bug.
Agent: writes that event into the Scroll through Continuum.

You: What were we doing before the restart?
Agent: asks Continuum for recovery context.
Continuum: returns recent events, Cards, open tasks, receipts, and relevant evidence.
Agent: resumes from durable state instead of starting cold.
```

### Resume Without Remembering A Thread ID

The v0.3 resume path discovers the newest current project-state checkpoint,
builds a bounded Looking Glass packet, and records the recovery as a guarded
operation with a proof receipt:

```powershell
continuum resume --root "$HOME\.continuum"

continuum configure-profile `
  --root "$HOME\.continuum" `
  --resume-mode latest_project `
  --default-project-id epic-continuum `
  --safe-context-ceiling 16384
```

`latest_project` refuses to drift into an unrelated project when no supplied or
configured project exists. `explicit` mode requires a session or project ID.
Superseded and unresolved contested Cards remain historical evidence but are not
eligible to become the current resume checkpoint. Same-agent project checkpoints
form one temporal chain, so an older task list cannot re-enter the operational
packet merely because it remains preserved in the Scroll. If one authority
boundary still has multiple validated independent-agent heads, automatic resume
returns `authority_ambiguous` and no packet; an explicit supersession or merge
must establish the operational head.

### Resolve Temporal Memory Conflicts

Conflict detection groups connected competing Cards into one stable review
unit. Resolution promotes one current Card and preserves the others as
historical evidence; dismissing clears a false-positive group without deleting
anything. Each resolution writes a system-owned receipt that binds the exact
component fingerprint, member set, authority boundary, selected Card, and audit
event atomically. Periodic detection honors that receipt only while every
binding still matches; caller-supplied Card metadata cannot dismiss a conflict.
Compatible independent project-state heads may not form a text-conflict group.
Resolve that ambiguity by naming the winner and explicitly repeating every
other current head in the authority boundary; partial boundary resolution is
rejected.

```powershell
continuum detect-conflicts --root "$HOME\.continuum"
continuum resolve-conflict --root "$HOME\.continuum" --card-id <winner-card-id>
continuum resolve-conflict --root "$HOME\.continuum" --card-id <winner-card-id> `
  --superseded-card-id <peer-card-id> --superseded-card-id <other-peer-card-id>
```

### Optional Yarn / Qwythos Briefings

Version 0.3 can use the Qwythos v3 GGUF through a local llama.cpp server. Yarn is
an advisory layer over an already-scoped deterministic packet; it never writes
model claims back into Scroll or Cards and it cannot replace recovery evidence.

```powershell
continuum yarn-configure --root "$HOME\.continuum" --enable
continuum yarn-health --root "$HOME\.continuum"
continuum resume --root "$HOME\.continuum" --model-assist
```

See [Local Yarn/Qwythos with llama.cpp](docs/integrations/local-llamacpp.md) for
the recommended model alias, one-slot server command, context limits, and the
RTX 5090-oriented 32K option.

## Cue Recall

Sometimes the problem is not a crash. Sometimes the idea is still in memory, but buried so deeply that neither the user nor the next agent remembers the exact words.

Cue Recall is for loose prompts like:

```text
remember that local-agent upgrade idea?
the fake big context thing
what did Codex leave for review?
```

Continuum preserves the exact Scroll, extracts useful terms, dampens common filler words, traverses meaningful associations in the Constellation, and returns likely candidate memories with related terms and evidence trails. If a user says `remember this exactly`, Continuum also creates a protected exact-memory Card while keeping the original Scroll event intact.

```bash
continuum cue-recall \
  --root ./.continuum-demo \
  --project-id epic-continuum \
  --cue "what did codex leave for review"
```

Cue Recall returns candidates, not commandments. It is meant to help an agent find the right thought, cite why it looks related, and admit when several nearby ideas are plausible.

## Shared Agent State

Epic Continuum is strongest when project continuity belongs to the project, not to one chat window.

Agents can record durable project-state checkpoints into the same root:

```bash
continuum record-project-state \
  --root ./.continuum-demo \
  --session-id codex-session-1 \
  --agent-id codex \
  --project-id epic-continuum \
  --objective "Prepare Cue Recall for review" \
  --branch main \
  --dirty \
  --changed-file src/continuum/core/store.py \
  --decision "Keep raw Scroll evidence intact" \
  --open-task "Have another agent review the package"
```

Another agent can later recover that state through Cue Recall, `recover-thread --project-id`, or a bounded Looking Glass packet. A newer project-scoped checkpoint from the same agent supersedes its older checkpoint even across sessions; session/private checkpoints stay bound to the same project and session, and other agents keep independent current heads. This is the core design claim: agents should share durable local project state instead of trapping memory inside separate chats.

## Review Relay

Epic Continuum can also act as an auditable bridge between a builder agent and a reviewer agent. The bridge creates a frozen snapshot, a packet, a subject artifact, a request JSON, an expected response schema, and one uploadable `review-capsule.zip`. Review results are rejected unless they match the exact job id, packet hash, capsule hash, subject hash, completion flag, and sentinel.

This supports a few workflows:

- Codex builds a candidate and asks a local OpenAI-compatible model to review it.
- Hermes receives the packet paths in one-shot mode and returns schema-bound findings when the selected model follows the JSON contract.
- A human or GUI relay uploads the single capsule to a separate review model, saves the JSON response, and Continuum verifies it before Codex acts on it.

The capsule is the only upload artifact, but it cannot contain its own final SHA-256 without changing itself. Give the reviewer the capsule hash from `manual-handoff.md`, `review-status`, or the `review-prepare` output and require it in `review_capsule_sha256`.

For strict unattended loops, the OpenAI-compatible/vLLM path is the preferred automated reviewer, but it is a packet-only review unless the reviewer also has file access. Hermes remains supported, but invalid or partial Hermes output is marked `review_failed` and kept as evidence instead of being ingested. Before applying external findings after a long review, use `review-check-current` to prove the active subject still matches the frozen snapshot.

Review preparation is streaming, resource-bounded, and crash-recoverably published: it uses a bounded identity-bound directory walk with an early combined entry ceiling, preserves empty directories in the frozen snapshot, source manifest, source archive, capsule, and currentness fingerprint, confines regular-file snapshots to the enumerated identities, preflights bounded ZIP central-directory headers and exact ZIP64 locator geometry before allocating member metadata, accepts only stored or deflated ZIP members, checks exact manifest-to-capsule hashes, applies a total subject budget, caps live Git capture, and shares CLI/MCP hard maxima. After capsule construction it re-enumerates and rehashes the live source, including modes, before publication. Prompt files stop at the same 4,000,000-byte ceiling used by the packet, and invalid public controls or an unsafe link-like subject path are refused before the Continuum root is initialized. A tri-state catalog-bound journal preserves ambiguous publication authority and reconciles an interruption before or after the final staging rename without admitting a partial job; every staged file and directory is durably flushed before the journal gains authority, and its authority-changing SQLite commits use full synchronization. Oversized `review-run` model or base-URL overrides fail before an attempt reservation. Hermes stdout/stderr is capped while the process runs, and direct endpoint work runs in the same contained-process model so one deadline covers connection, headers, and body. Windows uses fail-closed Job Object containment; POSIX uses process-group cleanup on timeout, overflow, or launcher exit. See the detailed limit table in the Review Relay guide.

Review preparation scans decodable files, UTF-8/UTF-16 text, ZIP contents and metadata, generated request text, and the completed capsule boundary for obvious secrets; narrow anchored literal `--secret-allowlist-pattern` entries (optional edge `.*` only) or exact `--secret-allowlist-file` fixture lists can suppress known false-positive lines without recording the raw matchers or local file paths in the capsule.

```bash
continuum review-prepare \
  --root ./.continuum-demo \
  --subject . \
  --prompt "Do a harsh release-boundary review." \
  --transport manual

continuum review-browser-attempt-start \
  --root ./.continuum-demo \
  --job-id review_...

continuum review-ingest \
  --root ./.continuum-demo \
  --job-id review_... \
  --result-path "<reserved response path printed by review-browser-attempt-start>"

continuum review-check-current \
  --root ./.continuum-demo \
  --job-id review_...
```

For local model review through a vLLM/OpenAI-compatible endpoint:

```bash
continuum review-prepare \
  --root ./.continuum-demo \
  --subject . \
  --prompt "Do a harsh release-boundary review." \
  --transport direct-openai \
  --model local-reviewer \
  --base-url http://127.0.0.1:8020/v1

continuum review-run \
  --root ./.continuum-demo \
  --job-id review_... \
  --operation-id local-review-001
```

See [docs/review-relay.md](docs/review-relay.md) for the file layout, validation rules, and MCP tool names.

## Quick Start

From a cloned checkout:

```bash
python -m pip install .
continuum init --root ./.continuum-demo
continuum writer-status --root ./.continuum-demo
```

Run exactly one persistent worker service for the root in a second terminal:

```bash
continuum serve \
  --root ./.continuum-demo \
  --interval-seconds 5 \
  --maintenance-interval-seconds 300
```

Capture commands durably enqueue follow-up work; the persistent service
processes that work. It holds a per-root lock, so a second service fails closed
instead of competing for the same queue.

Back in the first terminal:

```bash
continuum append-event --root ./.continuum-demo --session-id demo --role user --type message --content "Decision: use Epic Continuum to preserve agent work across restarts."
continuum append-event --root ./.continuum-demo --session-id demo --role assistant --type message --content "Next action: compile a recovery packet before switching tasks."
continuum status --root ./.continuum-demo
continuum compile-context --root ./.continuum-demo --session-id demo --query "decision next action" --token-budget 1000
continuum recover-thread --root ./.continuum-demo --session-id demo --query "resume the demo task"
```

For offline or `--no-index` installs, use a built wheel or preinstall the build
backend requirements from `pyproject.toml` such as `setuptools>=77`; otherwise
pip build isolation may fail before Epic Continuum itself is installed.

Trimmed output from the tested flow:

```json
{"initialized": true, "scroll_events": 2, "cards": 0}
{"session_id": "demo", "token_budget": 1000, "section_count": 1}
{"session_id": "demo", "recent_event_count": 2}
```

## Interruption / Recovery Walkthrough

1. Record a decision: "use Epic Continuum to preserve agent work."
2. Record the next action: "compile a recovery packet before switching tasks."
3. Start a fresh agent session with no active transcript.
4. Ask Continuum to recover the `demo` session.
5. The recovery packet returns the recent Scroll, compiled context, decisions or tasks found in Cards, recent Library books, pending jobs, and a resume instruction.

The result is not magic model memory. It is local durable state that can be read by the next agent.

## Upgrade And Repair

### Operational Upgrade Checklist

Before mutating an existing root, choose its sole writer runtime:

```bash
continuum writer-status --root ./.continuum-demo
continuum writer-claim --root ./.continuum-demo
```

Inspect and then repair a legacy worker backlog:

```bash
continuum reconcile-workers --root ./.continuum-demo
continuum reconcile-workers --root ./.continuum-demo --apply
```

Preview and quarantine an invalid legacy project-state head before resuming its
predecessor:

```bash
continuum repair-project-state-checkpoints --root ./.continuum-demo --project-id epic-continuum
continuum repair-project-state-checkpoints --root ./.continuum-demo --project-id epic-continuum --apply
```

Checkpoint repair always requires a project, session, or explicit `--all` scope.
Project/root scope does not inspect session-scoped or private checkpoints unless
`--include-session-scoped` or `--include-private` is supplied. MCP agents have
the same guarded preview/apply capability through
`continuum_repair_project_state_checkpoints`.

See [Recovery And Continuity](docs/recovery-and-continuity.md) for the failure
and repair behavior.

Reconciliation is dry-run by default. Applied reconciliation preserves queue
evidence, marks redundant pending notifications as skipped with an audit reason,
activates only graph-placed legacy Cards, and leaves genuine reviews for the
worker.

If older operations created many full catalog proof snapshots, inspect and then
apply relocation to a separate, non-overlapping archive:

```bash
continuum archive-proofs \
  --root ./.continuum-demo \
  --archive-root ../continuum-proof-archive \
  --keep-latest 3

continuum archive-proofs \
  --root ./.continuum-demo \
  --archive-root ../continuum-proof-archive \
  --keep-latest 3 \
  --apply

continuum verify-proof-archive --root ./.continuum-demo
```

The archive is content-addressed and bound to the originating root. Continuum
records and verifies the external copy before removing the in-root source. Keep
the archive with the root's recovery materials; deleting either part breaks
verification of relocated evidence.

Finish with the normal strict verifier:

```bash
continuum verify-root --root ./.continuum-demo
```

> [!NOTE]
> These safeguards prevent new evidence loss; they cannot recreate bytes already
> deleted or changed by an older installation. An upgraded root may retain
> explicit historical audit exceptions for missing legacy proof inputs or
> previously mutable sidecars. Restore those bytes from an independent backup
> when one exists. Otherwise preserve the exception as part of the audit record;
> do not fabricate replacement evidence or silently suppress the finding.

### Memory Index Backfill

Roots created before Cue Recall can still contain useful Scroll history that has not been indexed into the Constellation graph. Use `reindex-memory` to backfill derived associations and trusted exact-memory Cards without replaying the whole chat into a model:

```bash
continuum reindex-memory --root ./.continuum-demo --dry-run
continuum reindex-memory --root ./.continuum-demo --limit 500 --batch-size 100
```

The command is designed to be repeatable. It rebuilds derived routes with non-incrementing graph merges so rerunning it does not teach the same event twice.

When a root-wide backfill returns `next_cursor.after_rowid`, pass that value back
as `--after-rowid` for the next page. `--after-seq` is session-local and is only
valid together with `--session-id`.

### Safe Card Pruning

`prune-memory` matches a literal topic substring; `%`, `_`, and `\` are ordinary
characters rather than wildcards. A global topic scope requires `--all`, and the
bounded `--limit` accepts values from 1 through 1000.

```bash
continuum prune-memory --root ./.continuum-demo --topic "obsolete draft" --dry-run
continuum prune-memory --root ./.continuum-demo --topic "obsolete draft" --action archive
```

Generic pruning cannot change project-state Cards, unresolved conflict-group
members, or Cards participating in supersession. Move authority with
`record-project-state`, reconcile a complete boundary with `resolve-conflict`,
or repair an invalid checkpoint with `repair-project-state-checkpoints`; v0.3
does not provide an incidental or text-matched way to retire project authority.

## Benchmarks

Benchmark suite under active validation. No public performance claim is made without committed methodology, commands, configuration, and per-case results.

This repository includes an initial deterministic, CPU-only, no-network benchmark called **ContinuityBench**. It tests offline retrieval and context reconstruction behavior over synthetic interruption cases. Results are written as JSON and JSONL so they can be inspected, reproduced, and compared without paid APIs.

Run quick mode:

```bash
python benchmarks/runners/continuitybench.py --quick --output-dir "${TMPDIR:-/tmp}/continuitybench-local-quick"
```

It also includes **EricMemoryBench**, a small comparison suite for the practical
question: when does durable memory help beyond a default recent-context agent or
a manually curated QMD-style note? The quick run is deterministic and local. A
reviewer can optionally add a live OpenAI-compatible model endpoint or real
Hermes/OpenClaw command template; unconfigured live surfaces are reported as
skipped, not simulated.

```bash
python benchmarks/runners/eric_memory_bench.py --quick --output-dir "${TMPDIR:-/tmp}/eric-memory-local-quick"
```

See [benchmarks/BENCHMARKS.md](benchmarks/BENCHMARKS.md) for methodology, metrics, limitations, and reproduction notes.

## Integrations

The durable core is available through:

- CLI: `continuum ...`
- Python package APIs under `continuum.core`
- stdio MCP server: `python -m continuum.mcp_server`
- thin client adapters described in [docs/integrations/adapter-kit.md](docs/integrations/adapter-kit.md)

Adapters should stay thin. The durable contract belongs to the core memory root, not to one client.

## Privacy And Evidence

Epic Continuum stores memory locally under the root you choose. It does not provide built-in encryption at rest. Use disk, volume, or filesystem encryption when local evidence is sensitive.

Secret scanning is heuristic. Treat findings as a safety net, not a guarantee. Shareable bundles run stricter checks than ordinary local roots.

Imported or retrieved text is evidence. It is not automatically authoritative instruction.

## Documentation

- [How memory works](docs/how-memory-works.md)
- [Cue Recall](docs/cue-recall.md)
- [Shared agent state](docs/shared-agent-state.md)
- [Context window behavior](docs/context-window.md)
- [Recovery and continuity](docs/recovery-and-continuity.md)
- [Evidence and proof](docs/evidence-and-proof.md)
- [Worker operations](docs/worker-operations.md)
- [Writer claims](docs/writer-claims.md)
- [Review relay](docs/review-relay.md)
- [Benchmark documentation](benchmarks/BENCHMARKS.md)
- [Configuration](docs/configuration.md)
- [Glossary](docs/GLOSSARY.md)
- [Roadmap](ROADMAP.md)
- [Release audit summary](docs/audits/RELEASE_AUDIT_SUMMARY.md)
- [Codex integration](docs/integrations/codex-plugin.md)
- [Agent adapter kit](docs/integrations/adapter-kit.md)
- [Security policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## License

Epic Continuum is released under the [MIT License](LICENSE).
