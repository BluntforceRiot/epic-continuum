# Recovery And Continuity

Epic Continuum is designed for interrupted work. The goal is not only to remember facts, but to recover the current state of work after a session, app, or process stops.

## What Gets Preserved

Continuity state can include:

- Scroll events;
- Cards with decisions and open tasks;
- project-state checkpoints from multiple agents;
- Library books and chunks;
- operation receipts;
- operation event logs;
- proof packs;
- snapshots;
- recovery packets;
- portable root bundles.

## Recovery Packet

`recover-thread` creates a Markdown packet and structured result for a session. It includes a resume instruction, Looking Glass context, recent Scroll events, recalled Cards, decisions, open tasks, pending jobs, and recent books.

Example:

```bash
continuum recover-thread \
  --root ./.continuum-demo \
  --session-id demo \
  --query "resume current work"
```

The packet is written under:

```text
<continuum-root>/exports/thread_recovery/
```

## Operation Recovery

Mutating work can be wrapped in guarded operations. Operation state records intent, progress, cursor updates, result, errors, receipts, and proof metadata.

If a process stops mid-operation, `recover-operations` can mark stale work as interrupted and generate recovery material.

## Snapshots And Restore

Snapshots copy restorable catalog and sidecar state. Restore drills prove that a snapshot can be restored into a disposable root and inspected.

This matters because a backup is only useful if it can actually be restored.

## Handoff Bundles

`pack-root` creates a verified portable bundle. `verify-bundle` checks the archive envelope, manifest, hashes, portability, proof state, and semantic root health.

Bundles are intended for handoff, audit, and transport. They are stricter than ordinary local working roots.

## Cross-Agent Recovery

`record-project-state` lets an agent write a durable checkpoint with objective,
repo details, decisions, changed files, notes, and open tasks. A later Codex,
Hermes, Claude Code, or local-agent session can ask for that same project through
`cue-recall`, `recover-thread --project-id`, or `compile-context --project-id`
instead of relying on the previous chat window still being alive.

New checkpoints include a canonical digest of the complete decision and
open-task arrays in the immutable source event. Resume recomputes that digest
before accepting the selected Card; legacy checkpoints without the marker remain
readable, while a marked checkpoint with divergent structured state fails closed.

Same-agent project-scoped checkpoints form one atomic temporal chain across
sessions. Only the newest head is operational; its predecessors remain
historical evidence and are excluded from recent Scroll and Cue Recall sections
of a resume packet. Session/private chains remain session-bound, and different
agents keep independent current heads.

Recovery packets only include evidence visible to the requested session/project
scope. Pending queue jobs are included only when their referenced Card, segment,
or Scroll event is visible to that same scope; jobs with incomplete provenance
fail closed instead of appearing in unrelated recovery packets.

Automatic `resume` keeps the caller's requested visibility capability separate
from the coordinates of the checkpoint it discovers. A project-only request
cannot acquire session-visible evidence, and a session-only request cannot use a
discovered project identifier to read project-visible evidence. Checkpoint
selection applies the same rule before any recovery packet is built.

The selected checkpoint is a mandatory Planner candidate. Its identifier,
title/content, summary, decisions, open tasks, scope, and source references are
reserved before optional Cards, Scroll events, or Cue Recall evidence. When that
complete minimum cannot fit, resume returns `checkpoint_did_not_fit` and writes
no misleading recovery packet.

For query-guided resume, Card relevance is scored before the bounded candidate
window is selected. After the mandatory checkpoint is reserved, the optional
source with the strongest direct query relevance is considered first. This keeps
a buried Cue Recall or Card match from being crowded out solely by source order
when the remaining context budget is tight.

## Invalid Checkpoint Repair

Current releases bound project-state size and structure before accepting a new
checkpoint. A legacy or externally damaged latest head that violates those
limits or its source-binding integrity checks returns
`invalid_project_state_checkpoint`, writes no recovery packet, and does not
silently fall back to an older state.

Preview the affected heads, then apply the quarantine when the result is
correct:

```bash
continuum repair-project-state-checkpoints \
  --root ./.continuum-demo \
  --project-id epic-continuum

continuum repair-project-state-checkpoints \
  --root ./.continuum-demo \
  --project-id epic-continuum \
  --apply
```

Apply mode preserves the invalid Card as historical evidence and restores only
a reciprocal, same-authority predecessor. Run it again while `has_more` is true.

## Upgrade Backfill

`reindex-memory` backfills derived Scroll associations for older roots. It is
intended for upgrades where old events exist but the Constellation graph or
trusted exact-memory Cards were not created at append time.

```bash
continuum reindex-memory --root ./.continuum-demo --dry-run
continuum reindex-memory --root ./.continuum-demo --limit 500 --batch-size 100
```

For root-wide backfills that require pagination, resume with the returned
`next_cursor.after_rowid`. `after_seq` is session-local and is only valid when
`--session-id` is also supplied.

The operation is repeatable: it uses non-incrementing graph merges during
backfill so running it again does not duplicate edge weight.
