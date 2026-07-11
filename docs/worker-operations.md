# Worker operations

Epic Continuum captures work durably before its Scribe, Librarian, and
Archivist jobs run. A root therefore needs one persistent worker service in
addition to any MCP or capture processes.

Run the service directly with:

```console
python -m continuum serve --root PATH --interval-seconds 5 --maintenance-interval-seconds 300
```

`serve` holds a per-root process lock, so a second service fails closed instead
of processing the same queue concurrently. Maintenance runs on startup and at
the configured cadence rather than on every idle poll.

Every claimed queue job has a background lease renewer. Durable processor
transactions re-check the unexpired owner token before committing and write a
versioned effect receipt in the same transaction. If a process stops after that
commit but before finishing the queue row, the reclaimed job returns the prior
receipt instead of repeating database-visible work. Card sidecar synchronization
holds a per-Card SQLite writer lock across the durable snapshot, atomic file
replacement, and generation-specific outbox acknowledgement. A process exit
after replacement therefore cannot allow an older writer to overtake a newer
Card update. Each Scribe segment also holds one writer transaction from its
frontier read through its segment, Card, queue, audit effects, and committed-step
receipt, with live ownership checked at entry and immediately before commit. If
the process exits before the final job receipt, replay aggregates the exact
committed segments instead of reporting zero work. Bounded MemPalace review
batches read an indexed `LIMIT + 1` candidate window, expose remaining work as a
lower bound, atomically record their per-job effect receipt, and enqueue a
same-import continuation with the same batch limit. A partial batch is therefore
a successful resumable step (`complete=false`) rather than a failed terminal
job, and replaying its receipt cannot strand the continuation's tail.

Periodic conflict maintenance uses one explicit work budget for candidate Cards,
pair comparisons, component members, Card mutations, and transaction time. A
pass that exhausts any dimension reports `partial`, `has_more`, budget usage, and
continuation details. Unscoped passes advance a durable circular rowid cursor;
components that do not fit the member or mutation ceiling are deferred whole,
never partially assigned. Group, title, boundary, and supersession closure use
capped indexed probes rather than scans proportional to the full catalog. A
deadline interrupt rolls the complete writer transaction back. Targeted scans
require room for the requested Card and at least one advancing peer. If an exact
title or durable group is larger than the entire candidate window, continuation
metadata reports
`required_candidate_cards_lower_bound` with `requires_larger_budget=true`
instead of promising progress that the current window cannot make. Targeted
cursors stay fixed in that case; unscoped cursors still advance their fair
anchor. Every pass loads the anchor's exact-title/durable-group closure before
optional cursor noise, so a whole component that exactly equals the ceiling is
not fragmented. A lower bound above the hard automatic ceiling additionally
returns `manual_review_required=true` and
`component_exceeds_automatic_candidate_limit`. Targeted optional boundary rows
are used only when that entire boundary fits the same pass; they are not cycled
across calls as if non-accumulating pages could eventually prove one component.
If optional fuzzy evidence overflows, the result requests a larger one-pass
window and reports
`optional_fuzzy_evidence_deferred=true`. Normalized boundary/title indexes keep
capped candidate queries in index order without sorting the full boundary.
An incomplete targeted closure or boundary performs no Card, group, or audit
mutation; the caller must retry with the reported one-pass lower bound (or use
manual review above the automatic ceiling).
Routine maintenance performs at most one additional hard-cap conflict pass. If
that pass is still incomplete, it records one fixed-size, deduplicated
`librarian_conflict_review_required` audit signal for explicit review. Later
passes may retry the same bounded escalation so a changed component can recover,
but they reuse rather than duplicate its durable signal.

For a legacy backlog, inspect first and then apply the bounded reconciliation:

```console
python -m continuum reconcile-workers --root PATH
python -m continuum reconcile-workers --root PATH --apply
```

Reconciliation never deletes queue evidence. It marks redundant pending
Scroll notifications as skipped with an audit reason, keeps the newest pending
signal for each session, and activates only legacy pending cards that already
have graph placement. Genuine pending or running Librarian reviews are left to
the worker.

On Windows, `scripts/run_continuum_workers.ps1` is suitable as a Task Scheduler
action. Pass the root, source checkout, and Python executable explicitly. The
wrapper appends service output to `run/logs/continuum-workers.log` under the
root. Configure Task Scheduler to run only one instance and restart the task on
failure.
