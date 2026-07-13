# Release Audit Summary

This file curates the release-gate evidence for Epic Continuum `0.3.0` without
shipping the full internal build-review history.

## Scope

The release gate focused on:

- durable memory privacy and POSIX permissions;
- crash recovery, operation receipts, and proof packs;
- root bundle canonicality, portability, and semantic verification;
- secret scanning and legacy redaction;
- Codex/Hermes adapter installation behavior;
- Debian/Ubuntu/Windows portability;
- release package reproducibility and installer wrapper safety.

## Current Gate

The current source patch completed its fresh Windows and WSL verification
loop. Earlier 0.2 release-candidate work also exercised the durability foundation on disposable
Debian 12 and Debian 13 systems. The public source package intentionally keeps
this as a summary rather than bundling full local run logs; the repository CI
matrix remains the cross-platform release gate for the final v0.3 commit.

The current pre-promotion Windows patch ran two disjoint pytest partitions. The
complete Review Relay file passed 210 tests with 6 environment- or
optional-feature skips and 171 subtests. The other 31 test files passed 778
tests with 20 explicit skips and 450 subtests. The unique Windows aggregate is
therefore 988 passed, 26 skipped, and 621 subtests. After the cross-platform
gate exposed three POSIX proof mismatches, the affected cases passed on both
Windows and WSL, and WSL/Python 3.12.3 then reran the complete Review Relay file:
215 passed, 1 explicit skip, and 171 subtests.

Repository-wide Ruff, mypy across 31 source files, compileall, fixture-allowlist
validation at 165 exact fingerprints, Git diff integrity, and mixed-line-ending
checks passed. Independent blind review found no remaining code defect; its
only HOLD was the then-unrun release evidence recorded above and the immutable
artifact/installed-distribution gates. Artifact reproduction and clean-install
evidence remain explicitly pending until this source patch is committed and can
be built from an immutable Git snapshot; no artifact pass is implied here.

Release review hardening included:

- private directory/file modes and a `repair-permissions` command;
- Hermes secret-key handling that avoids subprocess argv;
- direct Hermes CLI rejection for secret-looking `--api-key` values;
- hard `max_tool_result_bytes` enforcement;
- healthy-degraded FTS5 fallback reporting;
- the unique Codex marketplace namespace `epic-continuum`;
- explicit MCP tool annotations;
- curated source/release package contents.
- bundle Zip64 threshold and central/local header canonicality hardening;
- portable bundle refusal for link-like catalog databases;
- manifest member mode binding;
- release builder refusal for tracked dirty-tree builds;
- safe Codex plugin staging under a generated child directory;
- BOM-less generated Codex `.mcp.json` files;
- Codex plugin cachebuster versions for generated local stages.
- root-confined configurable paths and portable operation identifiers;
- cross-thread and cross-process operation-ledger serialization;
- immutable public ledger APIs after proof publication;
- private secret-redacted adapter and bootstrap diagnostic logs;
- absolute tool-result byte caps and true no-event skip semantics;
- portable recovery packets and bounded recovery filenames;
- link-safe release assembly and coherent portable symlink-skip behavior.
- Cue Recall associative recovery with scoped project/session visibility;
- shared project-state recording for multi-agent handoff;
- corrected benchmark methodology, safer benchmark output directories, and
  unpublished local benchmark results;
- refreshed public documentation for context-window behavior, Cue Recall,
  recovery, evidence/proof, and shared agent state.
- hash-bound review relay packaging with browser handoffs, schema-bound ingest,
  append-only response/findings receipts, full-capsule versus packet-only review
  surface checks, and fresh-source verification before applying review findings.
- review2 boundary hardening for private project-state derivatives, mixed-scope
  Scroll segment compaction, queue-job provenance, generic MCP exact-memory
  provenance, root-wide reindex cursors, visibility-aware deduplication, and
  secret policy checks on project identifiers.
- restore-drill source and output path hardening so strict root verification
  and direct restore drills refuse symlink, junction, or reparse-point
  redirection before copying source trees or writing disposable drill output,
  with restore-drill tree copies walked by Continuum's guarded copy loop rather
  than delegated to whole-tree `shutil.copytree`.
- WAL-aware live read-only catalog access so committed data is never hidden in
  SQLite's write-ahead log from status, retrieval, health, or recovery calls.
- bounded complete Scribe backlog draining with durable continuation jobs and
  same-session generation ordering, plus per-segment lease renewal and fencing.
- incompatible-runtime live WAL refusal so Windows and WSL/Linux do not join the
  same shared-memory locking protocol.
- automatic latest-state discovery and source-balanced Looking Glass recovery
  with explainable planner traces and hard context budgets;
- explicit temporal conflict resolution that retains superseded evidence;
- optional Yarn/Qwythos v3 recovery briefings behind loopback, model identity,
  resource, concurrency, deadline, byte, redaction, citation, and circuit gates;
- personal safe-context/resume profiles and expanded operational health telemetry.
- adversarial follow-up hardening for persistent conflict dismissals, fair
  bounded conflict scans, coherent orphan cleanup, one-way supersession lineage,
  lifecycle authority, total-deadline enforcement, circuit isolation, and
  outbound path/model-identifier privacy.
- final functional follow-up fixes for recoverable-scope resume discovery,
  configured Scroll fetch limits, sequential checkpoint stability, expired
  worker leases, exact Yarn context ceilings, bounded recovery event requests,
  and clean-build rejection of forgotten untracked release inputs.
- blind integration follow-up fixes for checkpoint-consistent bounded resume
  packets that preserve actionable details, exact latest-state revalidation,
  project-state conflict isolation, serialized Yarn request sizing and
  configuration preservation, malformed queue timestamps, immutable Git-blob
  release snapshots, and provenance-bound reproducible distribution builds.
- final external-review fixes for caller-authorized resume discovery, mandatory
  complete checkpoint envelopes, pre-limit query relevance, universal worker
  lease renewal, crash-reconstructable Scribe receipts, serialized sidecar
  generations, indexed bounded MemPalace continuations, globally budgeted
  conflict maintenance, one total Yarn deadline, and exact-toolchain
  distribution receipts verified again after CI artifact download on Linux and
  Windows.
- final follow-up fixes for one-current-head same-agent checkpoint authority,
  bounded and explicitly repairable legacy project state, resilient bounded MCP
  frames, thread-free CLI/MCP imports, and receipt-v2 distributions rebuilt
  twice from the exact canonical source ZIP.
- final authority-review fixes that refuse timestamp-based selection among
  unresolved independent-agent heads, replace caller-influenced dismissal state
  with transactional exact-member resolution receipts, and extend semantic
  snapshot, restore, pack, and embedded-bundle verification across the complete
  project-state lineage and payload bindings.

The Python package version is `0.3.0`, and the catalog capability
`SCHEMA_VERSION` remains `0.2.0`. This feature release uses additive in-place
catalog extensions and requires no destructive migration or capability-version
bump. The 0.2 cycle includes additive catalog migrations for
durable Scroll visibility fields, source-scoped graph edge contributions,
partition aliases, snapshot integrity bindings, sidecar synchronization queues,
and proof/bundle hardening. Existing roots are upgraded in place, with legacy
partition identifiers rewritten across SQL text fields, graph provenance, and
card sidecars before sharing or strict verification.

See `MAINTAINABILITY_HOTSPOTS.md` for the non-blocking large-function
refactor map identified during release review.

## Remaining Security Boundary

Epic Continuum is local-first, not encrypted-at-rest software. Operators should
use filesystem or disk encryption for sensitive roots and should run
`continuum doctor` before publishing or handing off a root bundle.
