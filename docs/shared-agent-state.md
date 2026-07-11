# Shared Agent State

Epic Continuum is strongest when memory belongs to the project instead of one chat window.

Shared Agent State gives Codex, Claude Code, Hermes, local LLM workers, and other tools a common way to record what they are doing into the same Continuum root.

## What Gets Recorded

An agent can write a project-state checkpoint containing:

- project id;
- agent id;
- session id;
- current objective;
- repository reference;
- branch and commit;
- dirty-tree status;
- changed files;
- decisions;
- open tasks;
- notes.

The checkpoint is written to the Scroll as an ordered event and to a project-scoped Card for recall. The Constellation links the project, agent, event, and Card so Cue Recall and context compilation can find it later.

## Authority And Limits

Project-scoped checkpoints from one agent form a single temporal chain across
sessions. Recording a new checkpoint atomically makes every older same-agent
head historical, while preserving those Cards and Scroll events as evidence.
Session/private checkpoints supersede only within the same session. Checkpoints
from different agents retain independent current heads so disagreement remains
visible instead of being silently overwritten.

One checkpoint is limited to 12 KiB of canonical serialized state so every
accepted checkpoint, including escape-dense content, fits the supported
8,192-token recovery boundary without discarding its raw Scroll evidence.
Objectives are limited to 4 KiB, notes and metadata to 8 KiB each, repository
paths to 4 KiB, branches to 512 bytes, and commits to 256 bytes. Decisions and
open tasks allow up to 64 entries each at 2 KiB per item; changed files allow up
to 256 entries at 1 KiB each. Metadata is bounded to eight levels, 64 members
per container, and 128 total members. Limits are measured as UTF-8 bytes by the
core even when a client schema expresses the same ceiling as string length.

## CLI Example

```bash
continuum record-project-state \
  --root ./.continuum-demo \
  --session-id codex-session-1 \
  --agent-id codex \
  --project-id epic-continuum \
  --objective "Prepare Cue Recall for review" \
  --branch main \
  --commit abc123 \
  --dirty \
  --changed-file src/continuum/core/store.py \
  --decision "Keep raw Scroll evidence intact" \
  --open-task "Have another agent review the package"
```

Later, another agent can ask:

```bash
continuum cue-recall \
  --root ./.continuum-demo \
  --project-id epic-continuum \
  --cue "what did codex leave for review"
```

Or build a recovery packet that includes project-scoped Cards:

```bash
continuum recover-thread \
  --root ./.continuum-demo \
  --session-id codex-session-1 \
  --project-id epic-continuum \
  --query "resume project handoff"
```

## Why This Matters

Without shared project state, each agent sees only its own conversation. After a crash, restart, model swap, or handoff, important state can be buried in an old thread.

With shared project state:

- one agent can leave a durable checkpoint;
- another agent can resume without the original chat;
- the current objective and next action survive restarts;
- failed attempts and avoided approaches can be remembered;
- review packets can cite evidence rather than rely on vague summaries.

## Scope

Project-state Cards use project scope by default. That keeps shared work visible to agents working on the same project while avoiding accidental global recall.

Adapters that deliberately pass `visibility_scope=private` keep both the Scroll
event and derived project-state Card private. Derived artifacts must never become
more visible than their source evidence.

Shared state is still evidence, not authority. Agents should treat it as a cited local report and check underlying artifacts before making risky changes.
