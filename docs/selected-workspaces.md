# Selected portable workspaces and deterministic memory replay

These isolated 0.4 APIs move **explicitly selected project evidence**, not entire
memories. They do not synchronize conversations, traverse source references,
export private/session/global records, activate copied instructions, call a model,
or replace database schemas. There is no network transport.

## Portable evidence capsules

- `export_workspace(root, *, project_id, record_ids, workspace_id)` reads exactly
  1–32 project-visible typed record IDs. It produces a stable canonical capsule
  with original source IDs, kinds, timestamps, exact Scroll content/hashes and a
  `snapshot_hash`. Input order does not change the capsule. References remain
  references: their targets are not silently included.
- `plan_workspace_import(root, *, project_id, capsule, expected_snapshot_hash,
  allow_fork=False)` validates the **entire** supplied capsule before reporting
  `import`, `unchanged`, `conflict`, or explicit `fork` for each origin. This is a
  nonmutating read even when the target root does not exist. An origin already
  holding 32 variants reports `capacity_exceeded` for a new fork, making the
  whole import inadmissible before any write; an identical existing variant
  remains idempotently admissible at that limit. `record_capacity` also reports
  the unchanged 10,000-row project typed-record read limit, current count and
  genuinely new import/fork count. If the whole capsule would exceed that limit,
  `can_import` is false and no rows are written. Unchanged origins consume no
  additional capacity, including at the limit.
- `import_workspace(root, *, project_id, session_id, capsule,
  expected_snapshot_hash, allow_fork=False)` appends only `shared_knowledge`
  records. Their nested source records remain inert accepted evidence—not active
  facts, procedures, leases, collection heads, or independently verified truth.
  Identical `(workspace_id, source_project, source_record_id, source_hash)` is
  idempotent. A changed hash for the same origin is a visible conflict. Explicit
  `allow_fork=True` retains both variants; no imported row is overwritten.
- `resolve_workspace_conflict(root, *, project_id, session_id, origin,
  variant_hashes, selected_hash, reviewer, reason, expected_decision_id=None)`
  appends a caller-attributed choice against the exact current variant set and
  decision head. It neither deletes other variants nor activates the chosen
  payload. A later variant makes that prior choice visibly out of date. Reviewer
  names are attribution, not a new authentication system.

Capsules are at most 512 KiB. Each original source envelope is at most 48 KiB;
the resulting shared-evidence payload must fit 60,000 bytes before the ordinary
65,536-byte typed-record envelope. Oversized inputs fail explicitly, not by
silently clipping evidence. Strict shape, duplicate-key, nested credential and
exact hash checks run before writes. All known conflicts are preflighted.
Individual rows use the existing serialized capture transaction. A **later
concurrent conflict or capacity change** may stop a multi-record import after earlier rows committed;
retry safely reports those earlier identical rows as unchanged. Each origin is
bounded to 32 preserved variants.

The capsule hash proves consistency with the caller-selected bytes, not authorship
or the original claims' truth. Importing from another machine is explicit local
acceptance. Source project identifiers describe provenance; local target-project
visibility governs the imported evidence.

## Isolated experiments and replay

`create_memory_experiment(root, *, project_id, record_ids, workspace_id,
destination)` requires an absolute **new, non-link, disjoint** destination with an
existing non-link parent. It seeds only the selected capsule into a new manual,
no-inference working root. It then backs up that new catalog to
`.experiment/snapshot.sqlite3`, preserves the seed capsule/configuration and
hash-bound source mapping, and returns `manifest_sha256`. The source root remains
read-only. No existing destination is reused or overwritten. A failed creation
may leave its newly created incomplete directory for inspection; it is not a
completed experiment until a valid manifest exists.
The manifest separately binds the source's canonical `source_project` and the
isolated seed's `project_id`; a persisted alias from the source is not interpreted
as a local alias in the new root. Original citation mappings always retain the
source's canonical project authority, while replay/adoption query the actual seed
partition recorded in the manifest and returned as `project_id`. If the canonical
source identifier is in a reserved internal namespace, the seed receives a stable
`workspace-<digest>` ordinary partition instead. No source alias table/key or
possibly sensitive external alias spelling is copied into the experiment.

`replay_memory_experiment(experiment_root, *, queries, expected_manifest_hash,
limit=8, token_budget=2400)` verifies that immutable manifest anchor and the frozen
catalog/capsule/configuration hashes. It copies the snapshot into a disposable
temporary root and runs the **real `recall_memory`** there without semantic
provider input. It never queries the subsequently edited working catalog. Output
contains deterministic query/packet/result/replay hashes and maps every ranked
result back to exact original source citations. It contains no temporary paths
or current timestamps. Stable snapshot IDs are preserved rather than replacing
UUID generation. Bounds: 1–16 unique queries, 1,024 characters per query, limit
1–32, packet budget 512–32,768 estimated tokens, frozen catalog at most 64 MiB.
The snapshot is immutable by checked hash; filesystem tampering is rejected,
not treated as a new valid baseline. This is a focused retrieval fixture, not a
held-out practical quality evaluation or a claim of real-model performance.

`compare_experiment_replays(before, after)` validates both replay evidence packets
and requires the same query hashes and retrieval options. It reports deterministic
rank additions/removals/moves and packet/result changes, not a quality judgement.

`adopt_experiment_records(experiment_root, *, record_ids, target_root, project_id,
session_id, workspace_id, expected_manifest_hash, allow_fork=False)` explicitly
selects records from the **working** experiment root and imports just those into
the named target project as inert shared evidence. It validates the original
experiment anchor but does not pretend later working changes belonged to the
frozen seed. No bulk synchronization or automatic adoption is performed.
