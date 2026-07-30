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
the configured cadence rather than on every idle poll. A failed job or
maintenance pass exits the service with a failed result so its supervisor can
alert or restart it instead of masking the failure.

Claims normally preserve strict numeric priority. After eight consecutive
claims that bypass the oldest eligible job, the next claim serves that oldest
job and resets the durable fairness counter. This bounds starvation without
discarding priority ordering during normal operation. A bounded Scribe drain
inherits its parent job's priority when it leaves a continuation. If a
same-session pending generation already arrived while the parent was running,
the continuation refreshes that exact pending row instead of retaining its
default priority. Status-first priority and creation-order indexes serve
unrestricted lanes. Role-first priority and creation-order indexes serve each
selected role; a multi-role worker reads one indexed candidate per allowed role
and chooses the exact global winner instead of scanning excluded-role backlog.
A running-only dedupe index keeps eligibility checks off the full
active/pending history. A separate unique pending-only dedupe index makes one
pending generation authoritative even when producers race.

Every claimed queue job has a background lease renewer. Durable processor
transactions re-check the unexpired owner token before committing and write a
versioned effect receipt in the same transaction. If a process stops after that
commit but before finishing the queue row, the reclaimed job returns the prior
receipt instead of repeating database-visible work. Card sidecar synchronization
uses the sidecar operation lock to serialize publishers. It commits a short
database snapshot, builds the immutable-artifact path index outside a writer
transaction, and binds that index to both an artifact-only catalog epoch and the
SQLite schema authority version. Exact insert, URI/immutability-update, and
delete triggers maintain the epoch. A short writer transaction rechecks the
trigger definitions, epoch, and schema authority before publishing a durable
global reservation and before any selected target is replaced. If artifact or
trigger authority changed, the publisher rebuilds the index and reselects
instead of using the stale path.
An artifact-index query failure is an authority failure, never an empty index,
so direct publication and intent recovery both preserve possibly immutable
bytes and leave retry evidence pending.
While the reservation exists, schema triggers reject both helper-based and raw
SQL immutable-artifact registration, including conversion of a mutable row to
immutable.

After committing the reservation, synchronization writes its unique durable
intent, chooses a copy-on-write generation when the prior path is
artifact-bound, atomically writes the YAML, and flushes the file and directory.
A second short writer transaction acknowledges the exact outbox generation
only when the Card location and state hash still match the snapshot, then
removes the reservation; otherwise it preserves newer outbox authority while
still releasing the completed publisher fence. A crash leaves the reservation
visible as initial recovery authority and normally also leaves the outbox or
intent pending. An active reservation makes initialization unready. The next
holder of the sidecar operation lock validates its Card identity, atomically
rearms that Card's outbox, audits the recovery, and only then retires the
reservation. This converts even a crash in the narrow location-less backfill
window before intent creation into ordinary worker-retryable outbox authority.
An artifact registrar never needs to acquire the operation lock while holding a
database writer.

Crash-left publisher temporary files are inventoried with exact path identities
under the per-root sidecar operation lock. Reconciliation alternates across the
active-intent and retirement namespaces within an explicit entry limit, then
retires only the captured publisher-temporary identities; a same-name
replacement fails the identity check. Nonempty selected-Card passes perform a
second bounded, read-only inventory before declaring completion so authority
that appeared reentrantly during processing remains visible as pending. Results
report the initial and postflight observation limits and counts separately.
Inventory, publisher-temporary retirement, and their directory flushes do not
hold a SQLite writer transaction. Worker sidecar jobs use this same
after-commit path rather than writing files from their effect transaction.

Normal post-write reconciliation captures Cards, sidecar outbox rows, immutable
artifact authority, their two monotonic epochs, and the SQLite schema authority
version in one WAL read snapshot.
It then validates target, recovery, and committed-receipt files without holding
a SQLite writer transaction. Exact triggers advance the sidecar authority epoch
for every Card or outbox insert, update, and delete. Before publishing a new
terminal receipt, a short writer compare-and-swap verifies both trigger sets,
the two epochs, and the schema authority version in constant work; catalog or
trigger-definition drift rebuilds the snapshot instead of publishing stale
authority. After that commit, reconciliation reopens the exact file identities,
durably publishes the receipt, and retires the intent. A crash between the
compare-and-swap and receipt publication therefore leaves the intent replayable.

Only a destructive quarantine decision receives a separate durable reservation.
A short `BEGIN IMMEDIATE` compare-and-swap binds the full Card/outbox/artifact
authority token, exact raw intent evidence, target identity and hash, and the
target/recovery names. Exact triggers then reject Card and sidecar-outbox
inserts, updates, and deletes plus every immutable-artifact insert, transition,
URI update, or delete until that reservation is released. Queue, Scroll, audit,
and mutable-artifact-only writers remain available. The target move, file and
directory flushes, recovery receipt publication, and intent retirement all run
after the reservation commits and with no SQLite transaction open. A final
short transaction compare-deletes the exact reservation only after the durable
intent-bound quarantine receipt exists.

The next sidecar-operation-lock holder resumes a crash before the move from the
reserved target identity, a crash after the move from the exact recovery
identity, or a crash after receipt publication by replaying the receipt and
intent retirement. A malformed reservation, changed intent, target or recovery
identity drift, both names existing, or both names missing remains fenced and
fails closed for operator-visible recovery; it is never guessed away. Trigger
repair likewise refuses to rewrite a nonexact protected set while a reservation
is active. Normal adoption, immutable preservation, no-file completion, receipt
replay, and terminal receipt publication perform their filesystem work outside
writer transactions. Reconciliation adopts only bytes bound to the committed
Card, preserves immutable bytes, quarantines uncommitted bytes without deleting
them, and requeues any incomplete result.

Post-commit sidecar work is part of queue completion authority. Scribe,
Librarian placement (including nested conflict updates), MemPalace migration,
and Archivist sidecar jobs remain `pending` with a durable retry reason whenever
materialization or intent reconciliation is incomplete. They do not write a
terminal worker-effect receipt or enter failed-job history while that durable
work can still be repaired and retried.

Maintenance also repairs failed rows left by older workers that recorded this
post-commit condition as terminal. After draining sidecar work, one pass
examines at most 50 failed candidates and requeues only a row whose latest
effect (or exact effectless post-commit authority), queue failure envelope, job
payload, committed core or Scribe step receipts, live Card identities, and
expected worker role all match the known sidecar-only failure protocol. A
pending or running dedupe peer blocks requeue. Every exact authority receives
one immutable requeued or rejected disposition, so malformed older evidence
cannot starve later candidates and an old effect cannot cause a requeue loop.
Large Scribe histories validate at most 64 committed steps per maintenance
call. A durable `validating` receipt binds the full queue/effect snapshot and
the cumulative receipt chain; finalization rechecks the complete receipt/live
authority set in the same writer transaction as the requeue. A validation-only
pass reports incomplete work rather than a false completion. Explicit business
failures remain failed.

Disabling future sidecar writes leaves existing locations readable and pending
refresh work unacknowledged until writes are re-enabled. Cards that never had a
sidecar are intentional skips while disabled and are backfilled by pending sync
after re-enable. Hash-suffixed generations are immutable by content-addressed
name even before artifact registration; moving to a later state selects a new
hash name. Detached generations remain non-authoritative and audit-clean only
when a validated adopted-write or prepared-transition receipt binds the exact
path and hash. A legacy current hash without such evidence receives a durable
transition receipt before detachment. A case-renamed current hash likewise gets
an exact-spelling transition receipt so a copied snapshot remains self-contained
on a case-sensitive host. A missing, changed, linked, or unreferenced target
leaves the intent unresolved instead of emitting a self-invalid receipt. Each
Scribe segment also holds one writer transaction from its
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
