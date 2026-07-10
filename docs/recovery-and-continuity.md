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

Recovery packets only include evidence visible to the requested session/project
scope. Pending queue jobs are included only when their referenced Card, segment,
or Scroll event is visible to that same scope; jobs with incomplete provenance
fail closed instead of appearing in unrelated recovery packets.

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
