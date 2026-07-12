# Changelog

## 0.3.0 - 2026-07-11

- Added automatic latest-state resume discovery for the CLI and MCP surface,
  with strict personal resume modes, canonical partition lookup, immutable
  checkpoint ordering, guarded CLI recovery receipts, and discovery limited to
  project/session state that the recovery packet can actually render.
- Made same-agent project-state checkpoints one atomic temporal authority chain:
  only the newest checkpoint is current, while predecessors remain historical
  evidence. Added bounded checkpoint/MCP inputs, explicit invalid-checkpoint
  quarantine and repair, and recovery filtering that excludes superseded state.
  The canonical input envelope is 12 KiB, proven resumable at the supported
  8,192-token boundary while retaining the wider bounded stored-evidence envelope.
- Kept local Yarn briefing budgets coherent by reserving usable context after
  output and protocol overhead, rejecting non-integral token settings, and made
  recovery recent-event limits explicitly bounded across the core API, CLI,
  and MCP surface.
- Added the Looking Glass planner profile with source balancing, authority labels,
  complete non-current/contested lineage exclusion, ordered and configuration-
  bounded Scroll evidence, and explainable planner traces.
- Expanded memory health telemetry with queue age, segmentation lag, running-job
  heartbeat and lease validity, sidecar backlog, snapshot, and WAL diagnostics.
- Added planner-aware ContinuityBench coverage and recovery-focused regression tests.
- Added stable connected temporal conflict groups and acyclic whole-group
  resolution. Current Cards can supersede historical peers, while system-owned,
  exact-member dismissal receipts prevent periodic detection from undoing a
  reviewed false positive. Resolution receipts bind the complete component,
  authority boundary, selected Card, audit event, and member evidence in the
  same transaction; caller metadata cannot create or preserve resolution state.
  Sequential same-agent project checkpoints remain resumable, while multiple
  validated independent-agent heads at one boundary return
  `authority_ambiguous` until an explicit supersession or merge establishes one
  authority.
- Added an optional Yarn/Qwythos v3 adapter for a loopback llama.cpp server,
  including schema- and hash-bound cited briefings, strict model identity,
  measurable resource headroom, process-local concurrency plus a recommended
  one-slot server, wall-clock deadline, bounded JSON, pseudonymous outbound
  identifiers, path/secret redaction, and root-scoped circuit gates.
- Added personal resume profiles with safe context ceilings, default project
  selection, and opt-in model-assisted recovery.
- Made final source-archive builds require a fully clean Git worktree, including
  non-ignored untracked files, so new release inputs cannot be omitted silently.
- Bounded the complete daily resume packet, not only its Looking Glass section,
  preserved actionable task/decision/job/book details, and fail closed if a
  selected checkpoint is no longer the exact newest state while the packet is
  assembled. Tiny budgets now return valid compact envelopes or a clean error;
  unscoped fallback skips stale checkpoint partitions.
- Preserved the caller's original session/project visibility capability during
  automatic discovery and recovery. Selected checkpoints are authorized before
  selection, bypass evidence-count windows as mandatory candidates, retain their
  complete resumable state, and return `checkpoint_did_not_fit` rather than an
  ID-only success when the configured packet ceiling is too small. Query scoring
  now runs before the bounded Card candidate limit, and the most relevant
  optional source is considered first when a tight packet budget cannot fit one
  item from every source.
- Isolated project-state checkpoints from derived-card conflict groups and made
  malformed pending-job timestamps an explicit unhealthy queue condition. New
  project-state events hash-bind their complete decision and open-task arrays;
  selected checkpoints fail closed if those structured fields later diverge.
- Extended semantic root verification across current and historical temporal
  authority state, including checkpoint payload bindings, reciprocal and
  same-boundary supersession links, acyclic lineage, one same-agent current
  head, conflict-group closure, and exact resolution receipts. Snapshot,
  restore-drill, pack-root, and embedded bundle verification now reject temporal
  authority divergence before producing or accepting recovery artifacts.
- Bound repaired invalid-checkpoint quarantine to the exact pointerless
  historical Card and system audit record. A verified quarantine preserves the
  damaged evidence without keeping semantic verification permanently unhealthy,
  while any later mutation fails closed again. Repair severs remaining incoming
  authority links without promoting unproven alternatives and classifies an
  otherwise exact conflict receipt containing that quarantined member as
  retired evidence, never as live conflict or resume authority.
- Added background lease renewal for every queue job type plus unexpired-owner
  commit fencing and durable per-job effect receipts. Reclaimed or replayed jobs
  cannot duplicate database-visible effects. Card sidecar snapshot, atomic file
  replacement, and generation-specific outbox acknowledgement are serialized so
  a process exit after replacement cannot let an older writer overtake newer
  Card state. Scribe frontier reads, segment/Card writes, roll audit emission,
  and per-segment committed-step receipts now share one lease-fenced writer
  transaction, including when an expired attempt overlaps its reclaimed
  successor; a replay reconstructs the final job receipt from those steps.
  Bounded MemPalace review batches use an indexed `LIMIT + 1` window, report
  remaining work as a lower bound, receipt each completed step, and atomically
  enqueue a same-import, same-limit continuation so a durable partial batch
  cannot strand its tail.
- Made conflict maintenance explicitly bounded across candidate Cards, pair
  comparisons, component members, mutations, and transaction time. Exhausted
  passes return continuation metadata and advance a durable circular cursor
  without partially assigning an oversized component. Closure checks use
  capped indexed probes, targeted scans reject non-advancing one-Card pages,
  and an expired transaction deadline rolls back every Card and outbox change.
  Fair anchors now reserve their whole exact-title/durable-group closure before
  optional cursor noise; oversized closures request a larger budget, and groups
  beyond the hard automatic ceiling require explicit review. Targeted fuzzy
  evidence that cannot fit one pass is explicitly deferred instead of cycling
  or reporting false completion, while normalized boundary/title indexes keep
  capped candidate queries in index order. Incomplete targeted closures and
  boundaries now return without Card, group, or audit mutation. Automatic
  maintenance attempts at most one hard-cap escalation, then emits a
  deduplicated durable review signal. Later passes remain bounded while still
  allowing changed components to recover without an acknowledgement deadlock.
- Sized Yarn briefings from the transformed, fully serialized request under both
  token and transport limits, exact-fit trimmed unusually escape-dense input,
  bounded evidence aliases, preserved omitted CLI settings, and kept legacy
  low-budget profiles upgrade-compatible.
- Applied one absolute monotonic Yarn deadline from assist entry through
  configuration loading, input transformation and sizing, inference-gate
  waiting, resource and endpoint preflights, completion transfer, parsing, and
  validation. Deadline-bound local stages share one fixed runner instead of
  accumulating abandoned worker threads after timeouts, including a connection
  that refuses to unblock when closed. POSIX fork children
  discard inherited thread/lock references and lazily create one child-local
  runner on first use. CLI and MCP imports now remain thread-free because the
  runner itself is constructed only when Yarn is first used.
- Made CI wheel and source-distribution artifacts reproducible builds of the
  provenance-bearing release archive, with duplicate-member, version-parity,
  clean-source, and mid-build worktree-change checks plus an embedded build
  epoch and pinned distribution-toolchain recipe.
- Added a canonical distribution finalizer that requires the exact Python/build
  toolchain and wheel generator, validates the complete wheel `RECORD`, binds
  exact source/wheel/sdist package manifests, rebuilds twice from separate
  canonical source-ZIP extractions, and closes the uploaded directory with a v2
  hash receipt. Download verification is build-tool independent, and the wheel
  and sdist suites run on both Linux and Windows CI.
- Kept the catalog capability schema at `0.2.0`; these features are additive and do not
  require a destructive migration or downgrade of existing catalogs.

## 0.2.1 - 2026-07-10

- Fixed live read-only catalog connections so status, search, recall, health,
  verification, and recovery paths observe committed SQLite WAL data instead of
  silently reading a stale main database file.
- Fixed deduplicated Scribe notifications so one job drains every due Scroll
  segment window, yields after a bounded amount of work, and leaves an atomic
  same-session continuation when more eligible events remain.
- Added per-segment Scribe lease renewal and ownership fencing so a slow,
  high-boundary drain cannot be reclaimed and run concurrently by another worker.
- Prevented a pending same-session queue generation from running concurrently
  with the active generation that produced it.
- Refused WAL-aware reads from an incompatible writer runtime when committed
  live WAL frames are present; use the owning runtime or a frozen snapshot.
- Added focused regressions for live WAL visibility, read-only enforcement,
  complete and bounded Scribe draining, continuation lifecycle, queue ordering,
  and logical no-mutation checks for read-only tools.
- Kept the catalog capability schema at `0.2.0`; this patch requires no database
  migration.

## 0.2.0 - 2026-07-09

- Added Cue Recall for loose, associative recovery of buried ideas from vague
  prompts while preserving exact Scroll evidence.
- Added Scroll-time association indexing, exact-memory Card protection for
  "remember this exactly" requests, and graph route reinforcement for meaningful
  terms.
- Added shared project-state capture so Codex, Hermes, Claude Code, local LLM
  agents, and other adapters can record durable handoff checkpoints into the
  same root.
- Added CLI and MCP tools for `cue-recall` and `record-project-state`.
- Added `reindex-memory` for idempotent upgrade backfill of Scroll association
  routes and trusted exact-memory Cards.
- Added Cue Recall and shared-agent-state documentation, plus updated Codex
  plugin skill guidance for cross-agent memory use.
- Hardened project/session/private visibility boundaries across recovery packets,
  Cue Recall, context compilation, project-state Cards, Scroll segment
  compaction, event deduplication, and pending queue jobs.
- Hardened exact-memory trust so assistant/tool text and generic MCP callers
  cannot self-promote into protected memory without a trusted explicit adapter
  path.
- Hardened upgrade backfill with a root-global `after_rowid` cursor so
  root-wide `reindex-memory` pagination cannot skip interleaved sessions.
- Hardened recovery identifier handling by applying secret policy checks to
  project IDs as well as session IDs before recovery packets are written.
- Hardened benchmark publication behavior by removing ground-truth ranking
  leakage, adding safe output-directory handling, scrubbing local path metadata,
  excluding generated results from release artifacts, and documenting packet-level
  metric limits.
- Added high-entropy ScaleBench pressure coverage for graph write amplification.
- Added the hash-bound review relay for Big Brother/Claude/Hermes/local reviewer
  loops, including review capsules, browser handoff prompts, schema-bound ingest,
  append-only findings receipts, freshness checks, and fail-closed secret/package
  validation.
- Hardened review relay boundaries for capsule hash binding, full-capsule versus
  packet-only review surfaces, blocked-scan cleanup, file-limit refusal, malformed
  response preservation, append-only ingest, Git snapshot stability, and source
  mode metadata binding.
- Added one-per-root persistent worker services with process locking, bounded
  maintenance cadence, Windows Task Scheduler support, and operational guidance.
- Added pending-only queue deduplication and bounded backlog reconciliation that
  preserves audit history while repairing redundant notifications, stale Cards,
  missing Librarian reviews, and previously no-op MemPalace import reviews.
- Added explicit writer claims that prevent Windows, WSL/Linux, macOS, or another
  host from concurrently mutating the same SQLite root and require an acknowledged
  stopped-writer handoff before forced transfer.
- Added compact catalog-state proof manifests for routine operations and a
  verified external proof archive with a root-bound, hash-chained relocation
  ledger for legacy full catalog snapshots.
- Hardened evidence retention by protecting immutable referenced snapshots,
  freezing mutable Card sidecars before proof hashing, and resolving relocated
  proof inputs only through verified archive records.
- Hardened restore drills, SQLite audit behavior, secret-scan coverage reporting,
  generated fixture allowlisting, release packaging, and static-analysis CI.

## 0.1.0 - 2026-06-19

Initial public release.

- Added the Scroll, Card, Library, graph, queue, and snapshot storage substrate.
- Added CLI and MCP tools for capture, recall, recovery, verification, bundle
  export, restore drills, MemPalace import, and worker maintenance.
- Added Codex, Hermes Agent, Claude Code, OpenClaw, OpenAI-compatible, and
  broader adapter-kit scaffolding.
- Added operation receipts, proof packs, root bundles, semantic bundle
  verification, secret auditing, and recovery packets.
- Added configurable hardware budgets, retention policy, capture policy, and
  privacy-mode defaults.
- Hardened public-release behavior for POSIX file modes, Hermes secret handling,
  FTS fallback health, hard tool-result byte caps, plugin namespace isolation,
  and clean release packaging.
- Added root-confined configurable paths, portable operation identifiers,
  cross-process operation-receipt locking, URI-safe read-only SQLite access,
  private redacted adapter logs, and link-safe public release assembly.
- Finalized release boundaries with proofed-ledger immutability, portable recovery
  packets, bounded recovery filenames, strict tool-result skip/byte-cap semantics,
  portable symlink-skip export, and secret-safe packaged adapter diagnostics.
