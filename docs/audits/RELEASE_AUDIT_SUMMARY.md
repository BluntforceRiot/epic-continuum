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

On 2026-07-15, the narrow replacement candidate based on immutable reviewed
commit `c5f6fb8d98fbb8bab93fe3c48af9824bf5fef64a` completed fresh Windows and
WSL source verification after repairing strict MCP request handling and the
slow-host test fixture. Earlier 0.2 release-candidate work also exercised the
durability foundation on disposable Debian 12 and Debian 13 systems. The public
source package intentionally keeps this as a summary rather than bundling full
local run logs; the repository CI matrix remains the cross-platform publication
gate for the final v0.3 commit.

Static pytest discovery collected 1,134 test methods across 32 files: 304 in
`tests/test_review_bridge.py` and 830 in the other 31 files. Fresh Windows runs
reported 296 passed, 8 skipped, and 289 subtests for the complete Review Relay
file, plus 812 passed, 20 skipped, and 655 subtests for the other 31 files.
Fresh WSL/Python 3.12.3 runs under the pinned distribution toolchain reported
300 passed, 4 skipped, and 308 subtests for Review Relay, plus 829 passed,
1 skipped, and 657 subtests for the other files. These are the exact pytest
command summaries; pytest-subtests includes skipped subtests in its skipped
result total, so those result counts are not a second method-discovery count.

The repaired MCP boundary was also replayed directly on Windows and WSL, plus
through an actual Windows stdio subprocess. The matrix rejects malformed
versions and methods; boolean, fractional, container, or nonfinite request IDs;
invalid nested initialization capabilities and client metadata; malformed
tool-call names, parameters, arguments, and advertised input-schema values;
duplicate object keys; nonfinite constants; and overflowing finite-number
syntax. Integral numeric IDs remain interoperable under JSON Schema 2020-12
and preserve their exact value beyond binary64's safe-integer boundary, while
fractional spellings that would round or underflow to an integer remain
rejected. A real child-process regression proves exact echo of
`9007199254740993.0`, rejection of `1.0000000000000001` and `1e-4000`, and
recovery on the next frame.
It proves ID-less notifications receive no response or tool execution, the
initialize/initialized lifecycle completes before any tool handler can run,
valid `ping` requests work before, during, and after initialization, repeated or
out-of-order initialization is rejected, malformed tool inputs create no
default root or receipt, unknown tools use protocol errors, and a valid `ping`
is still answered after parse, dispatch, or response serialization failure.
Advertised schemas now normalize JSON-Schema integral numbers for integer
handlers, reject empty required strings, enforce explicit UTF-8 byte-bound
annotations before handlers, and share exact portable operation and review-job
identifier constraints. Mutating Review Relay tools validate job identifiers
and caller operation identifiers before an operation receipt can start;
simple boolean and inline-text controls are likewise validated before the
guard. Generic request metadata is validated before lifecycle transitions or
method execution, request progress tokens accept only strings or integers,
initialized-notification `_meta` remains open extension metadata, and errors
whose request ID cannot be recovered omit the optional `id` member. Parsed
over-depth requests preserve a readable valid ID, while equally deep
notifications remain silent and cannot advance lifecycle state. List methods
reject malformed or unissued cursors because this server advertises no
`nextCursor`. The complete MCP file passed 66 tests and 175 subtests on both
Windows and WSL. The former clean-filter timeout case
passed all five subtests on both platforms with its test-local Git and
preparation deadlines widened to 30 seconds; the product's 120-second
preparation default is unchanged.

Repository-wide Ruff, mypy across 31 source files, compileall, the four-test
fixture-allowlist gate, and Git diff integrity passed. The fixture allowlist has
166 parsed fingerprints and 169 physical lines, including its three header
lines. These results supersede this file's historical 210/778/988 test counts
and 165-fingerprint claim.

The externally reviewed `c5f6fb8` five-file artifact set, checksums, archive
audits, finalizer proof, and clean-install behavior all passed and remain
immutable historical evidence. That exact candidate was held for the MCP
boundary defect now repaired here. A fresh three-way blind review of the
replacement then found exact numeric-ID parsing and one pre-guard Review Relay
validation gap; both are repaired and covered by regressions here. A subsequent
blind pass found malformed request metadata could still unlock initialization
or reach a tool method; request `_meta` and progress-token validation now runs
before either path. A final protocol-focused pass then found request-only
progress-token typing applied to initialized notifications and unknown request
IDs serialized as `null`; notification metadata and error response IDs now
match the protocol's separate schemas. Its fresh re-review found parsed
over-depth requests still lost readable IDs and over-depth notifications still
received responses; both correlation and notification silence are now covered
through lifecycle recovery. Two byte-pinned independent re-reviews passed with
no residual actionable defect. Promotion now requires an immutable replacement
commit, reproducible
source/wheel/sdist rebuilding, exact five-file finalization, installed-artifact
runtime checks, and final build-cycle and Continuum receipts. The release
receipt, rather than this non-self-referential source summary, is authoritative
for the final commit and artifact hashes.

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
- final MCP boundary fixes that reject malformed JSON-RPC envelopes before tool
  dispatch, preserve missing-versus-falsy parameter semantics, fail closed on
  duplicate or nonfinite JSON, and continue serving after bounded per-frame
  errors without creating default-root state.
- final MCP lifecycle and contract fixes that allow `ping` throughout
  initialization, align advertised integer/string/UTF-8 limits with handler
  behavior, and reject nonportable operation or review-job identifiers before
  any mutating operation starts.
- final blind-review fixes that preserve exact integral request IDs across JSON
  decimal parsing, reject rounded or underflowed fractional IDs, recover after
  integer-limit failures, and validate browser-review identity and simple Relay
  controls before any guarded mutation, followed by strict request-metadata
  validation before lifecycle transitions or method execution.

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
