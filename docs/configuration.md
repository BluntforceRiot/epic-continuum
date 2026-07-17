# Configuration

Epic Continuum keeps code and durable memory separate.

## State Root

Set `CONTINUUM_ROOT` to choose where the Scroll, Library, Cards, graph, queues,
snapshots, and exports live.

```bash
export CONTINUUM_ROOT="$HOME/.continuum"
```

```powershell
$env:CONTINUUM_ROOT = "$HOME\.continuum"
```

If `CONTINUUM_ROOT` is not set, runtime helpers default to `~/.continuum`.

## Source Path

During editable local development, set `PYTHONPATH` to the repo `src` directory:

```bash
export REPO_ROOT="$PWD"
export PYTHONPATH="$REPO_ROOT/src"
```

```powershell
$env:REPO_ROOT = "$PWD"
$env:PYTHONPATH = "$env:REPO_ROOT\src"
```

For installed packages, no `PYTHONPATH` is required:

```bash
python -m pip install -e .
```

## Context Limits

`context.default_token_budget` and `context.max_token_budget` control the
estimated-token budget used by the Looking Glass. `compile_context` enforces the
selected budget and returns truncation metadata when a recalled event or card is
cut to fit.

`context.scroll_event_fetch_limit` caps how many recent Scroll rows SQLite
returns before Python applies the token budget. This keeps long sessions from
turning every context request into an unbounded session scan.

`context.reserve_output_tokens` is a runtime hint for adapters and model routes.
The core compiler reports it, but treats the requested `token_budget` as the
context packet budget so adapter-provided budgets remain predictable.

## Personal Resume Profile

`personal_profile.safe_context_ceiling` caps automatic recovery even when a
caller requests a larger packet. `default_project_id` selects the preferred
project for `latest_project` mode, and `assist_on_resume` controls whether the
optional Yarn briefing is requested when a caller does not explicitly choose.
`yarn-configure` derives the ceiling from `context.max_token_budget`, the model's
input window after its output allowance, and the 256 KiB request limit. The
calculation includes the serialized briefing schema and a bounded evidence-ID
list. It sizes against an escape-heavy representative generated JSON/Markdown
block through both serialization layers; smaller model windows also reduce the
alias limit below 100 when needed to preserve usable context. The adapter then
rechecks the transformed context and exact serialized request before every call.
If input at or below the advertised ceiling expands past either serialized
limit, it trims the evidence with an explicit notice to the largest exact fit.
Input above the configured ceiling, or a request whose fixed envelope cannot
fit, falls back deterministically.

Resume modes are intentionally strict:

- `latest` discovers the newest current durable checkpoint across the allowed
  scope.
- `latest_project` uses a supplied project or the configured default and refuses
  an unscoped fallback when neither exists.
- `explicit` requires a supplied session or project identifier.

Use `continuum configure-profile` to change these fields. Supplied partition
identifiers are canonicalized before lookup, while external secret-like labels
remain redacted in receipts and discovery output.

## Local Yarn Inference

`local_inference` configures the optional Qwythos/llama.cpp advisory layer. It is
disabled by default. The endpoint must use an exact `/v1` path; loopback is the
default boundary, while a remote endpoint requires explicit opt-in and HTTPS.
Model output never becomes memory authority and deterministic recovery remains
available on every refusal or failure. See
[Local Yarn/Qwythos with llama.cpp](integrations/local-llamacpp.md) for the
recommended one-slot launch command and resource/deadline controls.

## Capture Policy

`capture.mode` controls how eagerly adapters write the live conversation Scroll:

| Mode | Behavior |
|---|---|
| `manual` | Only explicit capture calls should write events. |
| `assisted` | User and assistant turns are captured; tool calls/results require an explicit capture call. |
| `automatic` | User turns, assistant turns, tool calls, and tool results are eligible for capture. |
| `paranoid` | Same capture surface as automatic, intended for operators who also enable frequent snapshots. |

The per-event booleans under `capture` can still disable a category. Adapter
environment variables, such as `CONTINUUM_RECORD_USER_TURNS=false`, override the
local adapter config when present.

`capture.max_tool_result_bytes` is a hard cap on stored tool-result payloads.
When a result is too large, `capture.large_result_policy` decides whether the
adapter uses `truncate_with_notice`, plain `truncate`, or `skip`. The default
`truncate_with_notice` reserves room for the notice inside the configured byte
cap. Exact large evidence should be archived through file ingest so the Scroll
can link to it without bloating every context compile.

`capture.roll_segments_every_events` is a policy hint for scribe workers and
adapters that compact older Scroll ranges into Cards. The core never deletes the
raw Scroll merely because a segment was rolled.

`capture.snapshot_on_task_start` and `capture.snapshot_on_task_finish` are
adapter-facing hints for crash recovery. They let a caller preserve state before
and after substantial tasks without assuming one hard-coded workflow.

Captured adapter turns and tool results also pass through the security secret
scanner. With the default `security.secret_scan_action=block`, secret-bearing
payloads are not written to the Scroll. With `warn`, the captured text is
redacted before storage and findings are stored in event metadata.

## Retention Policy

`retention` describes storage pressure behavior separately from capture:

- `raw_scroll_hot_days` and `raw_scroll_warm_days` describe when evidence is
  eligible to move between hot, warm, and cold tiers. `tier-storage` updates the
  catalog and moves internal archived originals/reader editions into the
  matching tier directories.
- `keep_cards_forever` keeps compact memory cards recallable even when raw
  evidence moves to colder storage.
- `max_root_size` is the operator's preferred storage ceiling surfaced by
  `memory-health`.
- `snapshot_retention` accepts `last_20` or `keep_all`.
- `proof_pack_retention` accepts `keep_successful_90_days` or `keep_all`.
- `prune_policy` defaults to `ask`, so destructive pruning requires operator
  review.
- `delete_raw_evidence` defaults to `false`. Setting it to `true` is rejected
  unless the prune policy remains `ask` or `manual`.

`tier-storage` applies the current Archivist tiering policy. It relocates
internal archive files and leaves any legacy external URI untouched. `prune-memory`
archives, marks summary-only, or prunes Cards by topic. These commands write
audit events; they do not delete raw evidence unless a future destructive policy
explicitly allows it.

`prune-memory --action forget` prunes ordinary Card projections from active
recall. Topic matching is a normalized literal substring across the Card title,
summary, and decoded topic values; `%`, `_`, and `\` have no wildcard meaning.
Empty or whitespace-only topics are rejected. Omitting `--topic` requires `--all`, so a
true global topic scope is always explicit. The `limit` is bounded from 1 through
1000 in the core API, CLI, and MCP schema/handler, and dry-run results identify
the matching mode and normalized topic.

Generic pruning cannot change project-state Cards, unresolved conflict-group
members, or any Card participating in a supersession relationship. A targeted
topic that matches one of those protected Cards is blocked atomically; global
scope excludes and reports protected matches. Use the dedicated project-state
and conflict operations for temporal authority changes. Every applied prune
starts from a clean semantic-integrity report and must pass its catalog and
sidecar postconditions before its public operation can succeed. It does not
erase Scroll rows, Library originals, reader editions, or proof evidence.

## Learning Policy

`learning` controls graph-route adaptation:

- `route_decay_min_interval_seconds` prevents a fast worker service from aging
  the same route repeatedly in a tight loop.
- `route_decay_weight_factor`, `route_decay_floor`, and
  `route_prune_weight_threshold` control deterministic synaptic pruning.

Recall resets a route's decay counter and decay clock before the next Librarian
maintenance pass.

## Queue Policy

`queues.worker_lease_seconds` controls how long a claimed Scribe, Librarian, or
Archivist queue job may remain `running` before a later worker pass can reclaim
it. Claimed jobs record `lease_owner`, `lease_expires_at`, and `heartbeat_at`.
When a worker process dies, the next worker pass can return an expired
preemptible job to `pending` and finish it instead of leaving it stranded.
Run one persistent service per root; see [Worker operations](worker-operations.md)
for service, backlog-reconciliation, and Windows Task Scheduler guidance.

## Ingest Limits

`storage.max_ingest_bytes` guards `ingest_file` before the file is read into
memory. Increase it for trusted large text archives; keep it conservative for
agent-facing folders that may contain logs, databases, or binary files.

## Safety

Filesystem locations configured by `atomic_memory.card_sidecar_dir`,
`security.ignore_file`, and `security.secret_allowlist_file` must be portable,
root-relative paths. Absolute, drive-qualified, UNC, and parent-traversing paths
are rejected, and existing link-like components may not resolve outside the
Continuum root.

The configured Card directory can contain multiple immutable generations for
one Card. `cards.location_uri` selects the current generation; operators should
not assume `<card>.yaml` is current. Do not manually delete `.uncommitted`
recovery files or their JSON recovery receipts. They are paired evidence used
by semantic verification and safe reconciliation. Setting
`atomic_memory.write_card_sidecars` to false stops new materialization but does
not erase or exempt already-recorded sidecars from integrity checks; refresh
work for an existing location remains pending until writes are enabled again.
A Card created while writes are disabled has no promised sidecar and does not
block snapshots. When writes are enabled later, pending synchronization
backfills every such null-location Card before semantic and snapshot checks.
Card ids used for sidecars are restricted to one portable filename component;
path traversal, Windows device names, and link/`..` parent aliases are refused.
Managed sidecar basenames use one portable case-insensitive grammar so a frozen
Windows snapshot remains readable on a case-sensitive host. This never folds or
aliases the parent directory. Casefold-colliding Card ids or sidecar filenames
are ambiguous for portable handoff, fail semantic verification, and block a
snapshot before it can be sealed.

`security.ignore_file` defaults to `.continuumignore`. `ingest_file` combines
built-in ignore rules with patterns from that file and refuses ignored paths such
as `.env`, private keys, virtual environments, `node_modules`, and `.git`.

`security.secret_scan_enabled` and `security.secret_scan_action` control the
lightweight secret scanner. The default action is `block`, which refuses files
or MemPalace records with findings before they are archived or indexed. Set the
action to `warn` to allow ingest while returning redacted `secret_findings`, or
`off` to disable the scan.

`security.entropy_secret_scan_enabled` adds opt-in high-entropy token detection
for `audit-secrets`. It is disabled by default to avoid noisy local scans.
Tune it with `security.entropy_min_length` and
`security.entropy_min_bits_per_char`.

`security.secret_allowlist_file` points to a local JSONL/line-based receipt file
containing SHA-256 `secret_hash` values copied from audit findings. Allowlisted
findings are counted as `allowlisted_findings` but are not reported as active
failures. The allowlist stores hashes only, not raw secret text.

`audit-secrets --sarif-output <path>` writes SARIF 2.1.0 in addition to the
normal JSON result. `redact-legacy-secrets` dry-runs or applies redaction to
legacy secret-like text already persisted in SQLite catalog columns.

`audit-secrets` does not follow symlink targets. It scans the symlink path and
target string for obvious secret patterns, records the link as skipped, and
redacts absolute target paths to a hashed external reference. This keeps a root
audit from silently reading files outside the Continuum root through a link.

`security.redaction_profile` accepts `private`, `portable`, or `shareable`.
Current defaults favor portable/shareable metadata: local source paths are
represented by root-relative URIs where possible or hashes/redacted references
when paths are sensitive.

## Root Verification

`continuum verify-root --root PATH` is the one-command reviewer check. Strict
verification is the default. It composes doctor,
recent proof-pack verification, artifact-ledger verification, search-index
audit, secret audit, stale-operation dry-run, and an optional restore drill.
Use `--no-restore-drill` for fast checks that avoid disposable restore-drill
artifacts.

Restore-drill receipts expose an explicit `drill_root_cleanup_status`:

- `cleaned` means the reserved Windows root was removed through its pinned
  native handle and its final pathname was proven absent.
- `inspected_root_retained` means POSIX cleanup deliberately performed no
  delete, truncate, or other payload mutation. The retained tree was inspected
  through read-only pinned descriptors and found to contain only stable physical
  directories and stable, single-link regular files. Payload bytes remain in
  place. This is an accepted non-destructive disposition for strict
  `verify-root`, not a claim that disk space was reclaimed.
- `retained_by_request` means the caller requested the complete drill tree.
- `identity_capability_unavailable` means no pinned inspection primitive was
  available, so Continuum conservatively reports the tree retained.
- `cleanup_failed_or_incomplete` means cleanup capability existed but an
  inspection, descriptor close, or final-postcondition check failed.

If a POSIX reserved root is renamed while its descriptor remains open,
Continuum still performs a read-only inspection of the pinned tree but reports
`inspected_root_moved`, `inspected_root_unlinked`, or
`inspected_root_moved_or_replaced`; it never calls a missing original pathname
`cleaned`. Successful postconditions are checked again before the receipt is
written.

On POSIX, `retain_drill_root=false` therefore retains a complete restored tree.
Repeated drills can consume substantial disk space under `run/restore_drills`.
Receipts expose the exact retained path plus `drill_root_retained_file_count`
and `drill_root_retained_bytes` so operators can review and remove old
disposable roots through their normal maintenance process. Version 0.3.0 does
not impose an automatic POSIX retained-root count or byte cap and does not
remove those bytes without an identity-bound deletion primitive.

## Catalog Proof Mode

`epic_continuity.catalog_proof_mode` controls how operation proof packs represent
the mutable SQLite catalog:

- `state_manifest` (default) writes small, non-restorable catalog-state telemetry.
- `snapshot` writes a complete immutable `catalog.snapshot.sqlite3` backup.

The default is intended for routine capture and maintenance operations. Select
snapshot mode deliberately for high-risk migrations, destructive changes, or
checkpoint operations that require restorable catalog bytes. This setting does
not alter older proof packs; verifiers accept both evidence forms.
The state-manifest hash covers only the telemetry document; it is not a hash of
the complete SQLite database. Keep periodic explicit snapshots for content-bound
restore evidence.

The CLI and MCP wrappers force snapshot proof mode for applied `prune-memory`
and `redact-legacy-secrets` operations even when the root default is
`state_manifest`. MemPalace import writes and proofs its own full catalog backup.
Routine capture, worker maintenance, and `reindex-memory` keep the bounded
state-manifest default.

This setting governs operation proof creation; it is not a pre-migration backup
gate. Before installing code that may upgrade the catalog schema, create and
verify a snapshot or root bundle with the currently installed version.

## Root Bundle Export

`pack-root --profile shareable` is the release/handoff gate. It requires an
initialized root, a complete secret audit, no active or allowlisted secret-like
findings, portable JSON/JSONL/card-YAML metadata, portable metadata in every
actual SQLite database (including nested import snapshots and key/value metadata
tables), valid proof packs, a valid immutable artifact ledger, a consistent
search index, no stale running operations, and no symlinks or unsupported file
types. The live catalog is copied with SQLite's backup API rather than by copying
WAL files. Portability checks recognize snake_case and camelCase path keys, file
URIs, home-directory references, parent traversal, and Windows absolute,
drive-relative, or root-relative paths.

```bash
continuum pack-root --root <root> --profile shareable --out continuum-root.zip
continuum verify-bundle --path continuum-root.zip
```

Bundle verification applies host-resource ceilings before materializing the ZIP
central directory or inflating members. Defaults are 100,000 entries, 64 GiB of
expanded bytes, 256 MiB of central-directory bytes, a 1,000:1 compression ratio,
and a one-hour monotonic verification deadline. The raw preflight walks and
counts central records (including strict adjacent Zip64 end records) before
`ZipFile` can materialize them, and one pinned regular-file handle is used for
the preflight, archive hash, envelope parser, and member reads. Semantic
verification also requires temporary free space for the manifest-declared root
plus a 1 GiB reserve and bounded control/result overhead; the reserve is
rechecked during extraction and while the semantic audit runs. Semantic audits execute in a separately reaped process, so
the deadline can terminate a stalled catalog or evidence check rather than
waiting for a cooperative return. Worker output is capped at 1 MiB. Use
`--max-entries`, `--max-expanded-bytes`, `--max-member-bytes`,
`--max-compression-ratio`, `--max-central-directory-bytes`, and
`--timeout-seconds` only for a trusted larger archive; expanded/member overrides
remain capped at the absolute 1 TiB boundary. `--envelope-only` skips temporary
reconstruction and therefore the free-space preflight, while retaining every ZIP,
manifest, hash, and resource limit. The MCP `continuum_verify_bundle` tool exposes
the same controls as JSON properties.

Portable-metadata verification reads regular JSON with a 20 MiB whole-file
ceiling. JSONL, integration logs, and card YAML stream record by record, so an
ordinary file may exceed 20 MiB while each record remains bounded; the audit also
caps total streamed bytes, record count, detailed errors, findings, and derived
finding-field sizes. SQLite metadata applies its connection length ceiling before
the first query, caps schema and scan work, checks individual text/blob values at
20 MiB, and reads path columns singly or key/value pairs so two valid cells do not
fail merely because their aggregate row is larger than one cell.

`secret_audit_max_file_bytes` is a safety boundary during export. Files larger
than that limit are reported as an incomplete audit, and strict verification or
bundle creation fails rather than treating an unscanned file as clean. Raise the
limit deliberately when a trusted large evidence file must be included.

The `portable` bundle profile can skip symlinks only when explicitly requested.
The `shareable` profile always fails on symlinks so the archive cannot silently
omit evidence or traverse outside the root. Bundle creation and verification also
reject path traversal, Windows-reserved names, non-regular ZIP members, and
case/Unicode filename collisions. SQLite WAL/SHM/journal sidecars are treated as
transient process state outside `archive/`, even when staged verification creates
them beside nested snapshot or proof databases. The immutable archive namespace
preserves evidence whose names happen to resemble build directories, Python
bytecode, temporary files, egg-info, or SQLite sidecars. ZIP timestamps are
normalized, while member content hashes, byte sizes, POSIX modes, copy-summary
counts, and healthy preflight policy claims are bound by the manifest. The
manifest is emitted as exact UTF-8 with canonical LF newlines on every host.
Verification rejects duplicate or non-finite JSON, secret-bearing or nonportable
manifest metadata, noncanonical manifest serialization or member ordering,
self-consistent manifests that contradict policy claims, ZIP preambles/trailing
bytes, comments, unapproved extra fields, unnecessary or malformed Zip64 records,
noncanonical local metadata, corrupt compressed streams, and bytes after a valid
DEFLATE end marker. By default `verify-bundle` then reconstructs only the
manifest-listed root in a temporary directory and reruns current portability,
secret, root, proof, and full immutable-artifact checks. A self-rehashed archive
with a corrupt catalog or newly inserted secret therefore does not verify merely
because its ZIP envelope is internally consistent.
Forced publication rolls back to the previous valid bundle and checksum if final
verification fails. Non-force publication is no-clobber even if another process
creates the destination during the publication window; filesystems without hard
link support use an exclusive reservation fallback.

`verify-root`, `verify-bundle`, `verify-proof-pack`, `doctor`, `audit-search-index`,
`audit-secrets`, and `replay-operation-log` return a nonzero process status when
their verification result is not healthy. This makes the JSON output usable in
CI without separately parsing `ok`.

## Writer runtime

Each live root has a host/runtime claim under `config/writer-claim.json` so
Windows and WSL/Linux cannot mutate the same SQLite catalog. See
[Writer claims](writer-claims.md) before claiming an existing root or moving a
writer between runtimes.

## Search

`continuum search` and the `continuum_search` MCP tool query Library
chunks/books created by `ingest-file` or import workflows. They use SQLite FTS5
when the local SQLite build supports it. If FTS5 is unavailable, Epic Continuum
falls back to simple `LIKE` search so the package remains dependency-light and
portable. Use `compile-context` or `recover-thread` when you want Card, Scroll,
and recent-work recall.

## MemPalace Import

MemPalace migration is optional. Use `--palace-path` or set `MEMPALACE_PATH`.

```powershell
python -m continuum import-mempalace --root $env:CONTINUUM_ROOT --palace-path "$HOME\.mempalace\palace"
```

## Local Adapter Installers

The Codex and Hermes installer scripts accept explicit paths so a clone on any
drive can use any state root:

```powershell
.\scripts\install_codex_plugin.ps1 -Root "$env:CONTINUUM_ROOT"
.\scripts\install_hermes_adapter.ps1 -Root "$env:CONTINUUM_ROOT"
```

```bash
./scripts/install_codex_plugin.sh --root "$CONTINUUM_ROOT"
./scripts/install_hermes_adapter.sh --root "$CONTINUUM_ROOT"
```
