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

Snapshot preflight and restore verification validate the complete temporal
authority state, not only file hashes. Current and historical project-state
payload bindings, reciprocal same-boundary supersession links, acyclic lineage,
same-agent head uniqueness, conflict-group closure, and exact resolution
receipts must all agree before the state is accepted.

Snapshots also pair the frozen catalog with the exact Review Relay jobs tree
that existed at snapshot time. The manifest binds every directory and file in
that sibling tree, and retention removes the pair together. Restore drills do
not borrow Review Relay files from the current live root. A legacy snapshot
without this pair restores an empty jobs tree only when its frozen catalog has
no Review Relay evidence; otherwise restore fails because the matching evidence
cannot be reconstructed safely.

## Handoff Bundles

`pack-root` creates a verified portable bundle. `verify-bundle` checks the archive envelope, manifest, hashes, portability, proof state, and semantic root health, including the temporal authority checks applied to snapshots and restores.

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
of a resume packet. Session/private chains remain bound to the same project and
session boundary, and different agents keep independent current heads.

## Ambiguous Authority

Independent-agent heads remain visible for review, but recency alone does not
make one authoritative. If automatic resume validates more than one current
head at the requested project/session boundary, it returns
`authority_ambiguous`, sets `resolution_required`, and writes no recovery
packet. Explicitly supersede or merge the competing component, then retry
resume. Before classifying those heads, resume reconstructs the complete raw
authority boundary in bounded database pages. Invalid checkpoint payloads,
asymmetric or
cross-boundary links, unsupported edges, incomplete conflict relationships,
and invalid receipts fail closed and write no recovery packet. The complete
boundary is read in bounded pages, so page size does not cap valid history.
Boundary or topology corruption, including an invalid competing or hidden
member, returns `authority_corrupt` and sets `repair_required`. For compatibility,
a selected latest head that itself fails checkpoint validation retains the more
specific `invalid_project_state_checkpoint` result described below. A damaged
Card cannot disappear from the decision merely because its pointers or payload
are malformed.
Boundary membership is also recovered from the exact bounded project-state
Scroll source, including legacy session/sequence references, so changing only a
Card's scope, project, session, or declared type cannot hide it from resume or
repair. For modern checkpoints, matching Scroll and graph bindings also expose a
missing derived Card as authority corruption instead of silently erasing it.
Modern source identity does not depend on the graph surviving: canonical Scroll
payload markers and durable operation/audit evidence reconstruct the expected
Card identity when Cards and graph rows disappear together. That state is
authority corruption and blocks strict verification, snapshots, restores, and
portable bundles.
Official v0.2.1 project-state sources are recognized without modern payload
markers only when the legacy deterministic Card identity, exact librarian
placement job, and system append audit all agree. The placement footprint must
have the canonical opaque queue dedupe key, exact five-field payload, and exact
single related-Card list; role, payload, dedupe, or related-ID drift is not
official derivation evidence. A missing legacy Card then fails closed as the
same orphan authority corruption; it is not recreated.

Recovery packets only include evidence visible to the requested session/project
scope. Pending queue jobs are included only when their referenced Card, segment,
or Scroll event is visible to that same scope; jobs with incomplete provenance
fail closed instead of appearing in unrelated recovery packets.

Automatic `resume` keeps the caller's requested visibility capability separate
from the coordinates of the checkpoint it discovers. A project-only request
cannot acquire session-visible evidence, and a session-only request cannot use a
discovered project identifier to read project-visible evidence. Checkpoint
selection applies the same rule before any recovery packet is built.
When one requested capability exposes several independent boundaries, selection
ranks their live boundary candidates only after bounded pages have exhausted
every eligible project-state candidate. A newer clean boundary with no current
head cannot hide a usable live checkpoint in another boundary, and an older
ambiguous or corrupt boundary cannot be skipped merely because newer historical
checkpoints filled an interactive page. Generic Scroll fallback excludes
project-state events; if authority verification cannot complete, resume returns
an explicit incomplete result and writes no recovery packet.

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

Preview the complete raw requested boundary, then apply the quarantine when the
result is correct:

```bash
continuum repair-project-state-checkpoints \
  --root ./.continuum-demo \
  --project-id epic-continuum

continuum repair-project-state-checkpoints \
  --root ./.continuum-demo \
  --project-id epic-continuum \
  --apply
```

Repair requires `--project-id`, `--session-id`, or explicit `--all`; an omitted
scope is rejected before operation artifacts are created. `--all` cannot be
combined with a project or session selector. Project and root-wide scopes inspect
project-visible checkpoints by default. Expand them deliberately with
`--include-session-scoped` and, separately, `--include-private`. An exact
`--session-id` authorizes that session boundary, including its session/private
checkpoint evidence; combine it with `--project-id` when both coordinates are
known.

For explicit maintenance across the entire root, preview and apply the identical
capability scope:

```bash
continuum repair-project-state-checkpoints \
  --root ./.continuum-demo \
  --all \
  --include-session-scoped \
  --include-private

continuum repair-project-state-checkpoints \
  --root ./.continuum-demo \
  --all \
  --include-session-scoped \
  --include-private \
  --apply
```

MCP callers use `continuum_repair_project_state_checkpoints` with the same
`project_id`, `session_id`, `all`, `include_session_scoped`, `include_private`,
`limit`, and `apply` fields. Omit `apply` or set it to false for preview. Applied
CLI and MCP operation receipts record every scope and expansion flag.

Repair never begins from the current-head predicate it is trying to validate.
It reports hidden, invalid, current, and topology-linked Cards from the bounded
raw boundary. Apply mode refuses an unrepairable topology or a limit too small
to close the invalid set atomically; its guarded receipt is failed and the Card
rows remain unchanged. A successful mutation must pass the semantic catalog
postcondition in the same transaction.

Authorization is reconstructed from the narrowest surviving durable boundary.
When the bound source row is missing, Card metadata, source references, audit
records, repair/conflict receipts, and sidecar evidence are considered before a
candidate can be mutated. Any surviving session/private signal excludes it from
project-only repair. Missing or contradictory boundary evidence is reported as
an unrepairable redacted candidate and requires exact session/private or
deliberate administrative scope; an empty source set is never authorization.
The same check is repeated for every Card reached while expanding a boundary,
supersession link, conflict group, or resolution receipt. A narrower or missing
member is omitted from scoped output and mutation; an authorized Card that
points outward still fails closed with only a redacted target count or marker.

Catalog authority changes commit before their derived Card sidecars are
refreshed. If that post-commit refresh or the full semantic postflight fails,
repair returns `ok: false` with `catalog_repair_committed: true`, the
`sidecar_sync` result, and `post_repair_semantic_integrity`; the guarded CLI
receipt is failed and explicitly records that this was not an atomic refusal.
The durable sidecar outbox remains available for normal worker maintenance;
after reconciliation, run strict root verification before resuming.

`authority_boundaries` describes the inspected pre-repair state. Preview and
apply both disclose any additional non-direct predecessors that would be retired
through `retired_peer_count`, `retired_peer_card_ids`, and `retired_peers`, and
any unproven current peers whose bad link would be removed through
`detached_peer_count`, `detached_peer_card_ids`, and `detached_peers`. Successful
apply also returns the verified clean state in
`post_repair_authority_boundaries`; dry-run leaves that field empty. The guarded
operation receipt preserves the same result fields.

An unreceipted non-current project-state topological head is authority
corruption. Repair converts it to an exact pointerless historical quarantine
receipt and, when safe, reactivates its reciprocal predecessor.

When exact source identity proves that a checkpoint Card's declared type drifted,
repair restores the source-proven project-state type as part of placing that Card
in historical quarantine; it never promotes the damaged Card. A strongly proven
modern source whose derived Card is missing is reported as unrepairable, because
repair cannot safely invent the deleted authority payload.

Successful apply mode preserves the invalid Card as historical evidence and
restores only a reciprocal, same-authority predecessor. The repair writes a system audit that
hash-binds the exact pointerless quarantined Card authority/payload state, its
bound Scroll source event, and the original integrity error. Derived placement,
recall, and sidecar-location fields remain maintainable, so semantic
verification and snapshots can proceed while any later mutation of
that evidence fails closed again. Any related receipt, member, and original
resolution-audit rows are included in the quarantine binding. Remaining
incoming links are partitioned by durable evidence. Only a receipt- or
audit-proven non-direct predecessor is retired and quarantined. An unproven
current peer has the bad pointer detached while remaining current authority, so
resume can expose any resulting ambiguity; an unproven non-current peer causes
an atomic refusal because its prior status cannot be reconstructed safely. Exact
conflict receipts that contain the quarantined Card remain preserved but are
treated as retired evidence. If a preview reports `has_more` solely because the
requested limit is too small, increase `--limit` (up to 1000) so the complete
invalid set can be quarantined together. A reported topology refusal cannot be
cleared by increasing the limit. Authority scans page through the complete
eligible scope instead of treating catalog size as corruption.

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
