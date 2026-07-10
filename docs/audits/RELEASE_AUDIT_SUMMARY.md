# Release Audit Summary

This file curates the release-gate evidence for Epic Continuum `0.2.1` without
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

The core test suite passed on Windows during this package build and in prior
Linux release-candidate review. Internal review notes also reported disposable
Debian 12 and Debian 13 validation with the same passing test count as the local
suite. The public source package intentionally keeps this as a summary rather
than bundling the full local run logs.

Review hardening after the final private review pass added:

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

The Python package version is `0.2.1`, and the catalog capability
`SCHEMA_VERSION` remains `0.2.0`. The patch release adds no catalog migration.
The 0.2 cycle includes additive catalog migrations for
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
