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
