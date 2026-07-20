# Review Relay

Epic Continuum's review relay is a deterministic bridge between a builder agent and a reviewer agent.
It is designed for the workflow where Codex builds a package, another model reviews it harshly, and Codex
then patches every finding without losing track of which artifact was reviewed.

The relay does not require a hosted API. It can be used with a local OpenAI-compatible endpoint, a Hermes
one-shot reviewer, or a manual reviewer flow where the user uploads one review capsule to a separate model
and saves the JSON result.

For strict unattended automation, the OpenAI-compatible transport is the preferred path because it receives
and returns raw JSON over HTTP. The Hermes transport is supported for agent-mediated review, but it is still
held to the same schema and hash checks. If its response fits the byte limit but contains prose, partial JSON,
or a tool-loop question, Continuum marks the job `review_failed` and preserves the raw response for diagnosis.

## Job Layout

`review-prepare` validates the prompt, cross-field limits, transport, and the lexical subject path before it
initializes the Continuum root. The subject and every existing path component must be a plain directory or
regular file; a symlink, junction, or reparse-point component is rejected. `review-check-current` repeats the
same path check and reports an unsafe source as non-current.

Every selected subject basename and every discovered relative path component must be NFC-normalized and
must not contain Unicode control, format, or surrogate code points. The same rule applies to ZIP member
paths. On every host, publication names also reject trailing dots or spaces, the Win32-forbidden characters
`< > : " / \\ | ? *`, reserved device stems (including aliases such as `CON .txt`), and NFC/casefold
collisions. ZIP validation applies this rule to implicit ancestor directories as well as complete member
names: distinct spellings cannot merge into one portable directory, a file cannot be an ancestor, and a
file cannot replace an already implied directory. Preparation rejects an invalid name before publishing a packet or capsule, including invalid
names that would otherwise be ignored; a name added after preparation makes `review-check-current` fail
closed.

Preparation copies the subject into a frozen snapshot under a private staging directory. The packet,
manifest, subject archive, and capsule are all generated from that snapshot, not from later reads of the
live worktree. Snapshot inputs are opened component by component without following links, must remain
regular files with stable identity and size, and are copied through the already-open descriptor. Capsule
construction consumes the exact snapshot file list and rechecks every member against its manifest hash; it
does not rediscover files with a second tree walk. A link, FIFO, file-identity substitution, or snapshot
mutation aborts preparation. POSIX opens start at the filesystem anchor and pin every absolute ancestor;
Windows validates the complete ancestor chain both before and after opening the file. The subject's original
file/directory type and filesystem identity are frozen at preflight and rechecked after snapshotting. After
the capsule is complete, Continuum re-enumerates the live subject and compares the complete inventory,
exclusions, identities, sizes, modes, timestamps, and file hashes to the frozen snapshot immediately before
publication authority is created.

The complete staged job is renamed into `exports/review_bridge/jobs` only after all artifacts, scans,
handoffs, mutable subdirectories, and the final deadline check succeed. Publication is serialized per root.
Before creating journal authority, Continuum flushes every staged file, then every staged directory from
deepest to shallowest, and finally the staging parent. A flush failure aborts preparation without a published
job or marker. Marker creation and the final rename also flush their affected parent directories.
Before the rename, Continuum writes and catalogs a sibling `tmp/<job-id>.ready.json` journal containing the
exact sorted artifact plan. The artifact rows and retirement of that journal authority commit in one SQLite
transaction with `synchronous=FULL` after the published tree passes the existing exact tree/catalog integrity grammar. On the next
prepare, an interrupted bound staging tree or renamed tree is finalized deterministically; incomplete
unbound staging is rolled back, a leftover post-commit journal file is removed without changing the durable
job, and conflicting or drifted evidence is preserved and refused. The journal never enters the job tree or
the review capsule.

It creates one job under the Continuum root:

```text
exports/review_bridge/jobs/review_.../
  request.json
  status.json
  review-packet.md
  review-prompt.md
  expected-response.schema.json
  source-manifest.json
  inner-archive-manifest.json   # present when the subject is a ZIP
  subject.zip
  review-capsule.zip
  manual-handoff.md
  browser-handoff.md
  browser-handoffs/
  attempts/
  attempt-receipts/
  secret-allowlist-report.json
  responses/
  findings/
  receipts/
  snapshot/
    subject/...
```

The `exports/review_bridge/jobs` tree is durable recovery evidence. Each new
catalog snapshot freezes an exact sibling copy of that tree and binds its full
directory set, file set, sizes, hashes, and aggregate tree digest in the
snapshot manifest. Restore drills use only the pair belonging to the selected
catalog snapshot, never the current live jobs tree, and verify every immutable
artifact-ledger binding before the rehearsal can succeed. A legacy snapshot
without a paired jobs tree is restorable only when its frozen catalog contains
no Review Relay evidence; in that case the restored jobs tree is empty. Legacy
snapshots whose catalog does contain Review Relay evidence fail closed because
their matching filesystem evidence cannot be proven. Internal job references
are stored relative to the Continuum root and are resolved only through the
active job directory. A restored job can therefore reserve a new browser
attempt and ingest its response after the original root is gone.
Legacy absolute job references are rebased only when the same in-job evidence
exists under the active root (and its recorded hash matches when available);
they are never used to read or write through the old root.

The job tree, artifact catalog, and `source-manifest.json` are one exact
authority boundary. Integrity checks enumerate the complete bounded job tree,
reject unexpected directories/files and unbound dynamic evidence, and require
each immutable job artifact to have its canonical catalog kind, URI, stable
identity, provenance, size, hash, and metadata. The source manifest separately
governs the frozen `snapshot/subject/` tree: its subject identity, complete file
and directory sets, and every member size and SHA-256 must match. The manifest
itself is an immutable catalog-bound artifact. A missing catalog-backed job,
missing or extra subject member, unbound response, changed manifest, or catalog
drift therefore fails the same semantic, snapshot, restore, and bundle gates.

Every internal reference also has an exact path class. Attempt references may
name only `attempts/attempt-NNN.json`, raw responses only
`responses/response-NNN.raw.txt`, numbered handoffs only
`browser-handoffs/handoff-NNN.md`, and findings/receipts only their respective
directories. Mutable status cannot redirect one class onto packet, capsule,
request, subject, schema, or manifest evidence. Semantic root verification and
snapshot/restore/bundle gates reject a job whose stored references violate this
grammar or whose attempt identity/hash no longer matches.

Attempt, response, and handoff directories are checked component by component
before any write. Link-like or redirected job paths are refused without creating
or replacing a file. Attempt records use exclusive creation, and numbering
advances from the greatest valid existing number so gaps cannot select an older
record for overwrite.

Every finalized attempt has a matching append-only record under
`attempt-receipts/`. The receipt binds the exact attempt bytes, job identity,
attempt number, final state, and completion time; the receipt itself is entered
in the immutable artifact ledger. Only the current unfinished browser attempt
is bound through the complete current/last status tuple instead. Verification
requires a contiguous `1..attempt_count` history, a receipt for every finalized
attempt, the exact reserved lifecycle for the current attempt, and coherent
status/ingest counters and terminal references. Semantic, snapshot, restore,
and bundle gates all use this same certification.

Browser reservation is DB-first. Before the response placeholder, attempt file,
numbered handoff, mutable latest handoff, status, or artifact rows are relied on,
Continuum commits one immutable reservation phase that binds their exact target
bytes and status. A retry with the same explicit operation ID reconciles any
missing materialization and returns the already-bound attempt and response path;
it does not allocate another sequence. A reconciled reservation is returned only
while the persisted job is still `pending_browser_upload` and its current attempt,
response, and handoff pointers match that phase. If the job has progressed through
ingest, reconciliation may restore missing historical artifact rows but reports
the terminal reservation as unusable instead of reactivating it. A different
operation ID is a deliberate new reservation and supersedes the current unfinished
attempt before allocating the next number. Replaying an operation after it has
been superseded validates the historical phase, ledger rows, response placeholder,
attempt record, and immutable numbered handoff, then reports that the reservation
is no longer usable.

New reservation phases also bind the exact browser-handoff renderer version.
That renderer uses root-relative artifact references and `--root .`, so run its
commands from the active Continuum root. This keeps committed handoff bytes
stable if the Continuum root is relocated. Pre-version phases remain replayable
from their already hash-bound embedded handoff text; replay does not reinterpret
those historical bytes through the current renderer. Existing handoff files are
size-gated before replay reads them.

Each accepted ingest additionally records an exact `browser_reserved`,
`automated`, or `untracked` claim. The claim binds the raw response hash and
timestamp, deterministic output paths, the presence and value of the operation
ID, and the mode-specific attempt context. Its ingest receipt is bound in the
immutable artifact ledger. Tracked terminal ingests must resolve to the matching
finalized attempt and attempt receipt; an untracked direct ingest may have no
attempt.

For a single-file subject, Continuum copies the file unchanged instead of wrapping it in another ZIP. That
keeps the reviewed package SHA-256 equal to the original file SHA-256.

The review capsule is the intended manual upload artifact:

```text
review-capsule.zip
  REVIEW_INSTRUCTIONS.md
  request.json
  expected-response.schema.json
  source-manifest.json
  inner-archive-manifest.json   # present when a ZIP subject is expanded
  review-packet.md
  original/release.zip          # original ZIP subject, when applicable
  subject/...
```

When the subject is a ZIP file, Continuum requires the central-directory members to account exactly and
contiguously for every byte before the central directory. Concatenated prefixes, gaps, orphan local records,
and other unbound raw regions fail closed. Continuum then computes an inner member manifest, preserves the
original archive under `original/`, and expands reviewable members directly under `subject/`. The manifest's
member count includes every central-directory file and explicit directory record; explicit directories and
their portable modes are reproduced in the expanded capsule. A full-capsule review result for such jobs must
echo both `inner_archive_manifest_sha256` and `inner_archive_member_count`.

`review-packet.md` uses fixed Markdown headings with complete JSON evidence objects. Paths, sampled file
content, Git metadata, and Git diff text are JSON string values rather than Markdown control text. Each JSON
object is enclosed by a fence longer than every backtick run in that serialized object. Subject files remain
available byte-for-byte under `subject/` for full manual review; the packet is only the bounded excerpt view.

The capsule cannot contain its own final SHA-256 because that would change the ZIP. The final capsule hash is
reported in `status.json`, `manual-handoff.md`, the mutable latest `browser-handoff.md`, `review-status`, and
`review-prepare` output. The reviewer must echo that hash in `review_capsule_sha256`. Browser-only Pro relays
should use the immutable numbered handoff returned as `browser_handoff_uri` after `review-browser-attempt-start`.

Only `review-capsule.zip` is intended to be uploaded or shared with the reviewer. The local job files
(`request.json`, `status.json`, and `manual-handoff.md`) may identify the original external subject so
`review-check-current` can compare it when it remains available. References to copied Review Relay
evidence are root-relative and relocatable. The capsule's public request and source manifest use
path-neutral `subject/` references instead.

The absolute `root` value in `request.json` is origin provenance only and is
never resolved to access job evidence. `subject_path` deliberately names the
external source so `review-check-current` can perform an optional live-source
comparison; attempt reservation and result ingest depend only on the frozen,
root-confined job evidence.

The packet contains the review objective, Git snapshot, file manifest, selected text excerpts, coverage
metadata, and optional diff material. Direct OpenAI-compatible review is a packet-only review. If the packet
is truncated or critical files are omitted, Continuum downgrades a clean packet-only pass to
`coverage_limited` during ingest. A browser/manual reviewer that inspected the uploaded capsule should return
`review_surface: "full_capsule"` and `subject_inspected: true`; that full-capsule signal is not downgraded
only because the packet excerpts were limited.

Review preparation scans every snapshot file with a raw-byte credential pass, decodable UTF-8/UTF-16/UTF-32
text, ZIP member contents, ZIP metadata, generated request/instruction text, and the completed capsule
boundary for obvious secret-like material before publishing a capsule hash. ZIP scans enforce nesting, member
count, per-member size, cumulative uncompressed size, and compression-ratio limits. Invalid or unscanned
archive material fails closed.

Use `--secret-allowlist-file` for synthetic review fixtures that intentionally contain fake credentials. The
preferred file format is JSONL with exact finding fingerprints:

```json
{"source":"tests/test_fixture.py","line":12,"finding_type":"openai_key","secret_sha256":"...","line_sha256":"...","reason":"synthetic fixture"}
```

The fingerprint must match the canonical scanner source, line number, finding type, matched secret SHA-256,
and full line SHA-256. Replacing the fixture value with a different token invalidates the exception. The
`--secret-allowlist-pattern` route remains only for non-hashed false positives and accepts an anchored
`source:line:text` literal with optional leading or trailing `.*`; general regular expressions are rejected so
matching remains linear. Hashed findings are never suppressed by a source-line literal alone. Raw allowlist file paths are not written into the
public capsule; only counts are recorded. Suppressed findings are written to the local
`secret-allowlist-report.json` with redacted snippets and stable hashes. If the scan blocks, Continuum removes
the temporary preparation directory and does not leave an uploadable capsule or subject archive behind.

Maintainers reconcile the repository fixture allowlist with
`python scripts/generate_review_fixture_allowlist.py --check`. After deliberately reviewing and adding an exact
fingerprint for any new synthetic fixture, run the script with `--write`. It relocates existing approvals when
only line numbers change, removes and reports obsolete approvals, and refuses to write if any scanned finding
does not match an approved source/type/secret/line fingerprint.

Directory subjects must fit under `--max-files`. Enumeration counts every directory entry, including empty
directories and ignored candidates, against
`min(16,000, max(1,000, max_files * 8))`; it checks the shared deadline while reading each entry. This keeps
both `review-prepare` and `review-check-current` bounded even when few or no regular files are selected. The
combined included file/directory inventory also stops at 2,000 entries during enumeration, before snapshot
copying. If the file, combined-entry, or traversal limit is reached, a custom `.continuumignore` rule excludes subject files, the subject
is inside the Continuum root, or a non-empty subject produces an empty snapshot, `review-prepare` fails
rather than silently claiming full coverage. Every included directory is identity-bound during enumeration,
preserved explicitly in the snapshot, manifest, subject ZIP, capsule, and source fingerprint, and checked by
`review-check-current`; adding or removing an empty directory therefore makes the prior review stale. For large release reviews, pass the already-built release ZIP
as the subject.

Preparation also has one shared resource budget. File copies, hashes, excerpts, archive inspection, ZIP
creation, capsule creation, generated temporary data, and elapsed time consume that budget; sampling reads
only the requested bytes plus one, and Git output is drained while Git is running. Archive and temporary
ceilings reserve space for the maximum accepted trusted objective, its redacted public-request form, the
packet, and fixed capsule records independently of subject size, so a small subject does not make an otherwise
valid maximum-size objective unrepresentable. For Git subjects, temporary capacity additionally reserves one
complete supported private metadata copy. Work capacity reserves the conservative worst case for every
private copy and repeated config, index, reference, and object binding: sixteen metadata-limit units during
preparation (three complete state replays plus diff evidence) and fifteen during currentness (three complete
state replays). These are capacity ceilings, not eager allocations, so non-Git and small repositories do not
consume the reserve. Git evidence comes from a
confined direct `.git` directory, raw HEAD/index plumbing, and staged HEAD-to-index plus unstaged
index-to-snapshot comparisons with the frozen subject snapshot. Configuration, the object database, and the index are copied through confined no-follow readers
into a bounded private metadata snapshot; Git receives only those private paths. The live repository's Git
metadata is rechecked after each evidence-producing pass and again immediately after the final subject replay,
before any review artifact is published. Review preparation and currentness never ask Git to inspect or
convert working-tree files. They therefore do not invoke clean, smudge, process, required, text-conversion,
external-diff, or file-system-monitor helpers configured by the reviewed repository. Linked worktrees,
redirected worktrees, configuration includes (including `includeIf`), alternate or effective partial-clone
object stores, intent-to-add entries, sparse/unmerged or split/shared indexes, gitlinks, link-like metadata,
and other unsupported repository geometries fail before publication. An unborn repository without an index is deliberately
unsupported and fails closed; ordinary packed references and supported SHA-1/SHA-256 object formats remain
capturable. Private object graphs are checked with the private HEAD, refs, and index as roots so missing or
corrupt staged objects fail closed as well as committed objects. Every unique parsed index OID is also checked
in bounded batches against the private object store and must name that exact blob object. The live object-store bytes are rebound,
then authority, HEAD, and index are rechecked after that binding. Newly prepared jobs bind the branch, HEAD, raw index entries, verified
object-graph semantics, worktree comparison, and these semantics as source-fingerprint version 4; older Git jobs require re-preparation before currentness can be
certified. The public CLI and MCP surface use the same defaults and hard maxima. Waiting for the root-wide
preparation/publication lock consumes the same elapsed-time budget:

Packet budgeting is structural. Manifest rows are included whole, and sampled content is shortened as a raw
string value before the enclosing JSON object is serialized. A variable evidence section is appended only
when its complete JSON and closing fence fit. Continuum never obtains the hard byte limit by slicing rendered
JSON or a rendered Markdown fence. Coverage warnings identify omitted or shortened evidence.

| Control | Default | Hard maximum |
| --- | ---: | ---: |
| `max_packet_bytes` | 512,000 | 4,000,000 |
| `max_file_bytes` | 64,000 | 4,000,000 |
| `max_files` | 300 | 2,000 |
| `max_subject_file_bytes` | 32,000,000 | 32,000,000 |
| `max_subject_bytes` | 64,000,000 | 256,000,000 |
| `prepare_timeout_seconds` | 120 | 600 |

The CLI spellings for the last three are `--max-subject-file-bytes`, `--max-subject-bytes`, and
`--prepare-timeout-seconds`. The review prompt is non-empty UTF-8 text with a literal 4,000,000-byte ceiling;
a `--prompt-file` read stops at that ceiling plus one byte. The complete accepted prompt is carried into the
trusted review objective after normal secret redaction and is never silently length-truncated; an oversized
prompt is rejected. Values outside
the published range, a per-file subject limit greater than the total subject limit, and invalid prompts are
rejected before the CLI/MCP operation guard or a review job is created.

Reviewer IDs, models, and base URLs are single-line UTF-8 controls capped at 256, 512, and 2,048 bytes.
Operation IDs use one portable filename component of at most 128 characters. Preparation accepts at most 32
allowlist files, 1,000,000 bytes per file, 4,000,000 aggregate file bytes, 5,000 total entries, 4,096 bytes per
entry, and 1,000,000 aggregate entry bytes. `review-run` applies the same model and base-URL caps to runtime
overrides. CLI and MCP reject invalid controls before opening their operation guard; the direct core rejects
them before it validates job storage or reserves an attempt.

ZIP member count is established from bounded EOCD/ZIP64 and fixed central-directory headers before Python's
ZIP object is constructed. The central directory is capped at 16,000,000 bytes and member names at 4,096
bytes, so a forged count cannot defer the 2,000-member rejection until after metadata allocation. ZIP64 uses
the fixed end record supported by Python's parser, and the locator offset must bind that exact record. Local
records must begin at byte zero, agree with their central records, and end contiguously at the central
directory. Canonical ZIP64 local size records are supported; data-descriptor layouts and other local extra
fields are deliberately unsupported. Only stored and deflated ZIP members are accepted. Other compression
methods are rejected before their Python decoder can be allocated, both during inspection and when expanding
a subject ZIP into the capsule. Every stored regular member must declare equal compressed and uncompressed
sizes. Every deflated regular member is replayed with bounded streaming and must reach exact deflate EOF at
the declared compressed boundary, with no trailing or unconsumed bytes; its decoded size and CRC must also
match. Manifest inspection and capsule expansion repeat this proof, and malformed decoder state is translated
into a normal review-bridge validation failure rather than leaking a raw decoder exception.

## Validation

`review-ingest` fails closed unless the returned JSON proves it belongs to the exact job:

- `job_id` or its accepted alias `review_id` must match the request; accepted responses normalize both names
  to the canonical job ID. When both are supplied, each must independently match.
- `packet_sha256` must match `review-packet.md`.
- `review_capsule_sha256` must match `review-capsule.zip`.
- `subject_archive_sha256` or its accepted alias `package_sha256` must match `subject.zip` or the unchanged
  single-file subject copy when an archive exists; normalized evidence records the canonical
  `subject_archive_sha256` value. When both are supplied, each must independently match.
- `review_complete` must be `true`.
- `sentinel` must match `CONTINUUM_REVIEW_COMPLETE:<job_id>:<packet_sha256>`.

Continuum re-hashes the actual `review-packet.md`, review capsule, and subject artifact at ingest time. It
does not trust `request.json` alone as the source of truth for artifact binding.

Every reviewer-controlled response must be valid UTF-8 and no larger than
exactly 4,000,000 encoded bytes. The same predicate covers the direct endpoint's
transport wrapper and extracted reviewer content, Hermes output, inline ingest,
reserved browser files, external result paths, and every durable resume read.
The exact raw response is preserved once as immutable evidence. Normalized JSON and rendered findings are
separate derived artifacts with a 16,000,000-byte ceiling, allowing the full accepted response plus bounded
normalization overhead without embedding a second copy of the raw payload.
The response schema accepts at most 2,000 findings. Schema validation retains at
most 64 error details, and durable failure diagnostics are capped at 64,000 bytes,
so malformed arrays cannot amplify a bounded response into unbounded error state.
The published schema carries the same acceptance rules as manual ingest:
`review_complete` is exactly `true`; full-capsule and local-file reviews require
`subject_inspected=true` plus a non-empty capsule challenge; packet-only surfaces
require `subject_inspected=false`; and an unknown surface cannot return a clean
verdict. Either documented job-ID field and either documented archive-hash field
satisfy the corresponding required binding before canonical normalization.
External and network reads stop after the limit plus one byte; Hermes output is
drained through bounded pipes while the child runs. Continuum terminates the
Hermes process tree as soon as stdout, diagnostic stderr, or their combined
ceiling is crossed, and does the same on timeout. Direct endpoint work runs in
one contained child with bounded stdout/stderr, so connection, headers, and body
share one forcibly enforced elapsed-time limit instead of receiving a fresh
timeout per socket read. Direct transport validates both the wrapper and
reviewer content before writing either one. `review-run`
uses the same CLI/MCP hard bounds: `timeout_seconds` defaults to 900 and is at
most 3,600; `max_tokens` defaults to 4,096 and is at most 65,536.

On Windows, the child is created suspended and attached to a kill-on-close Job
Object before any child code is resumed. If that containment cannot be
established, the suspended process is terminated and the review run fails. On
POSIX, the child starts in a dedicated process group, and Continuum terminates
that complete group on timeout, output limit, or launcher exit even when a
descendant closed the captured pipes. POSIX descendants that deliberately
create a new session or process group are outside this portable containment
contract; reviewer launchers must not detach them.

For a fresh oversized automated response, Continuum finalizes the existing
reservation as `transport_failed`, stores only the bounded error evidence, and
does not persist the oversized body. Retrying the same explicit operation ID,
whether the first failure completed cleanly or stopped during terminalization,
replays that terminal failure without another transport call or attempt number.
The lookup remains sticky across intervening operations, so an A/B/A retry still
replays A; a genuinely different operation may reserve the next attempt. An
oversized browser, inline, or external-path response is rejected before ingest
status, catalog rows, or output files change, leaving an existing browser
reservation available for corrected content. Automated API calls without an
explicit operation ID retain append-only clean retry behavior rather than
claiming historical operation replay.

This prevents stale copied reviews, mismatched uploads, and accidental "Review7 source with Review8 receipt"
style collisions from being ingested as current evidence.

## CLI Flow

Prepare a manual review capsule:

```bash
continuum review-prepare \
  --root ./.continuum-demo \
  --subject . \
  --prompt "Do a harsh release-boundary review." \
  --transport manual
```

If a fixture or documentation line trips the review secret scanner, prefer an exact fingerprint allowlist file.
Anchored literal patterns with optional edge `.*` can only suppress non-hashed findings:

```bash
continuum review-prepare \
  --root ./.continuum-demo \
  --subject . \
  --prompt "Do a harsh release-boundary review." \
  --transport manual \
  --secret-allowlist-pattern "^tests/test_fixture.py:12:.*example_fixture_token"
```

```bash
continuum review-prepare \
  --root ./.continuum-demo \
  --subject ./epic-continuum-0.3.0.zip \
  --prompt "Do a harsh release-boundary review." \
  --transport manual \
  --secret-allowlist-file docs/review-fixture-secret-allowlist.jsonl
```

For a browser-only reviewer, reserve a response path before each attempt. Upload `review-capsule.zip` to the
reviewer, paste the exact short prompt from the numbered handoff returned as `browser_handoff_uri`, save the
reviewer JSON to the reserved path, and ingest that exact file:

```bash
continuum review-browser-attempt-start \
  --root ./.continuum-demo \
  --job-id review_20260624T000000Z_example \
  --operation-id browser-review-001

continuum review-ingest \
  --root ./.continuum-demo \
  --job-id review_20260624T000000Z_example \
  --result-path ./.continuum-demo/exports/review_bridge/jobs/review_20260624T000000Z_example/responses/response-001.raw.txt
```

Treat `--operation-id` as the stable identity of one logical reservation. If the
process stops at any reservation boundary, rerun with the same value to recover
and receive the exact same attempt. Use a new value only when intentionally
superseding that unfinished attempt and reserving the next response number.

If the reviewer returns malformed JSON, keep that raw response, run
`review-browser-attempt-start` again with a new operation ID, and use the newly
reserved `response-002.raw.txt` path. Continuum writes immutable per-attempt
handoffs under `browser-handoffs/` and keeps `browser-handoff.md` as a mutable
latest pointer. Continuum rejects reused or consumed browser response paths, so
a failed `response-001.raw.txt` remains evidence rather than becoming a retry
slot.

If a process stops after validation while status is `ingesting`, rerun `review-ingest` with the same reserved
response path. The pending response hash and deterministic output paths make that continuation idempotent;
changing the raw response during recovery is rejected. If the ingest receipt
was already made durable, retry first certifies its exact immutable artifact
binding and mode-specific claim before writing any output or catalog row.

Check status:

```bash
continuum review-status \
  --root ./.continuum-demo \
  --job-id review_20260624T000000Z_example
```

Roots created by an earlier local 0.3 development build may have one completed
attempt without the new identity fields, last-attempt hash, or finalization
receipt. Inspect the explicit one-time upgrade without changing the root, then
apply it only if the dry run reports `upgrade_available`:

```bash
continuum review-upgrade-integrity \
  --root ./.continuum-demo \
  --job-id review_20260624T000000Z_example \
  --dry-run

continuum review-upgrade-integrity \
  --root ./.continuum-demo \
  --job-id review_20260624T000000Z_example
```

The guarded upgrade accepts only a finalized single-attempt legacy job. It
canonicalizes that attempt and binds its current bytes to a new immutable
receipt transactionally. It does not run from `review-status` or semantic
verification, and the upgrader itself still refuses active and multi-attempt
histories.

Two exact pre-0.3 browser shapes instead have a preservation path: the authentic
active single-attempt reservation with no durable phase/receipt history, and a
contiguous 2-20-attempt `review_failed` history with the known development-era
attempt identity/receipt omissions and missing final-attempt hash. First prepare
a distinct replacement job that passes current Review Relay integrity. Then
inspect quarantine eligibility without changing either job:

```bash
continuum review-quarantine-legacy \
  --root ./.continuum-demo \
  --job-id review_legacy_example \
  --replacement-job-id review_replacement_example
```

Only an exact recognized shape reports `quarantine_available`. Apply the same
binding explicitly:

```bash
continuum review-quarantine-legacy \
  --root ./.continuum-demo \
  --job-id review_legacy_example \
  --replacement-job-id review_replacement_example \
  --apply
```

Apply rechecks both jobs under their operation locks, commits a compact immutable
DB-first catalog receipt, and then materializes `receipts/legacy-quarantine.json`.
The receipt binds the replacement job, operation identity, complete old-tree and
catalog-binding counts/digests, and an exact counter/digest of the accepted known
findings; it does not duplicate the full inventory. If the process stops after
the catalog commit, the same receipt file is reconstructed on retry. The old job
then reports `quarantined_legacy`, remains immutable historical evidence, and is
still included in integrity, snapshot, restore, and bundle verification behind
the clean replacement. Upgradeable jobs, contradictory histories, partial
bindings, or additional unexplained defects are refused rather than generalized
into quarantine.

For a preserved development root whose legacy job has only the separately
scoped malformed-record or attempt-record reasons reported by the integrity
auditor, an operator can request an exact-evidence preview. This path is not an
automatic repair and does not rewrite, delete, or validate the malformed bytes:

- `review_bridge_malformed_records`: only `invalid_status_lifecycle`,
  `job_artifact_binding_invalid`, `subject_manifest_member_set_mismatch`,
  `unexpected_job_tree_directory`, or `unexpected_job_tree_file`;
- `review_bridge_invalid_attempt_records`: only
  `attempt_job_binding_mismatch` or `attempt_receipt_sequence_mismatch`.

Every other reason or integrity class, including link, reference, or content-hash
failure, is refused even when the operator supplies the authorization flag.

```bash
continuum review-quarantine-legacy \
  --root ./.continuum-demo \
  --job-id review_legacy_exact \
  --replacement-job-id review_clean_replacement \
  --authorize-exact-malformed-evidence
```

The preview returns three independent SHA-256 bindings: the complete legacy job
tree, its catalog artifact rows, and the exact integrity-finding multiset. Apply
requires the operator to repeat all three values explicitly:

```bash
continuum review-quarantine-legacy \
  --root ./.continuum-demo \
  --job-id review_legacy_exact \
  --replacement-job-id review_clean_replacement \
  --authorize-exact-malformed-evidence \
  --expected-tree-inventory-sha256 <preview-tree-sha256> \
  --expected-artifact-bindings-sha256 <preview-artifacts-sha256> \
  --expected-integrity-findings-sha256 <preview-findings-sha256> \
  --apply
```

Apply also requires the distinct clean replacement to bind the same subject
archive/package bytes. It fails if any byte, catalog binding, finding, subject
binding, or the replacement's integrity changes. The bounded receipt records the
explicit authorization and digests, while the original evidence stays
byte-for-byte in its original job tree and becomes immutable historical
evidence. Verification suppresses only the exact receipt-bound finding
multiset; later drift makes the root fail again.

Before applying findings from a long-running external review, check that the active subject still matches
the frozen review snapshot:

```bash
continuum review-check-current \
  --root ./.continuum-demo \
  --job-id review_20260624T000000Z_example
```

If `current` is false, create a new review job instead of patching stale findings. A legacy or damaged job
whose stored preparation limits are invalid reports `reason: stored_review_limits_invalid` rather than
raising an unstructured validation error.

Run a local OpenAI-compatible reviewer directly:

```bash
continuum review-prepare \
  --root ./.continuum-demo \
  --subject . \
  --prompt "Do a harsh release-boundary review." \
  --transport direct-openai \
  --model local-reviewer \
  --base-url http://127.0.0.1:8020/v1

continuum review-run \
  --root ./.continuum-demo \
  --job-id review_20260624T000000Z_example \
  --operation-id direct-review-001
```

For direct OpenAI-compatible review, Continuum puts the operator objective, response schema, artifact hashes,
and binding rules in the system-priority message. The endpoint receives one separate user message labeled as
untrusted review evidence; its JSON envelope contains packet coverage and `review-packet.md`. Filenames, file
content, diffs, and apparent instructions inside that evidence cannot replace the system review controls.
Compatible endpoints must preserve the supplied system/user message roles. The child request carries this
payload as structured `body_json` and serializes it exactly once for HTTP, so quote- and backslash-heavy
evidence does not consume a second escaping layer or cross the transport bound spuriously.

`review-run --operation-id` and the MCP `continuum_review_run.operation_id`
name one logical automated reservation. Reuse the same value after an
interruption to reconcile or replay that exact attempt without another model
call. Use a different value only when intentionally starting the next attempt.

Run through Hermes Agent:

```bash
continuum review-prepare \
  --root ./.continuum-demo \
  --subject . \
  --prompt "Do a harsh release-boundary review." \
  --transport hermes \
  --model local-reviewer

continuum review-run \
  --root ./.continuum-demo \
  --job-id review_20260624T000000Z_example \
  --operation-id hermes-review-001
```

The Hermes path passes file locations, hashes, and a pre-filled response template to
`hermes chat --quiet --source tool`; it does not put the entire review packet on the command line. Continuum
still validates the returned JSON before recording it.

## Private Pro Review Relay

The personal GPT-5.5 Pro web workflow is intentionally modeled as a GUI airlock, not as a generic API
transport. The deterministic Python code owns snapshots, hashes, schemas, state, and ingest validation. A
private Codex skill or future Computer Use tool should own only the narrow browser steps:

1. run `review-prepare`;
2. run `review-browser-attempt-start` to reserve an append-only response path;
3. upload the single `review-capsule.zip` to the dedicated signed-in review thread;
4. paste the handoff prompt;
5. capture the final JSON response to the reserved path;
6. run `review-ingest`;
7. run `review-check-current` before applying findings.

When no browser automation tool is available, this remains a manual capsule upload. The package should not
claim a fully unattended ChatGPT Pro relay unless the caller can actually control the signed-in browser.

## MCP Tools

MCP-capable agents can use the same workflow without shelling out:

- `continuum_review_prepare`
- `continuum_review_run`
- `continuum_review_ingest`
- `continuum_review_status`
- `continuum_review_check_current`
- `continuum_review_browser_attempt_start`

`continuum_review_prepare` and `continuum_review_run` are marked open-world because they can package paths
outside the memory root and call external or local model endpoints. Configure `CONTINUUM_ALLOWED_ROOTS` so
the MCP server can access the intended repository or review-result path. Supply the same non-empty
`operation_id` to `continuum_review_run` when recovering one interrupted automated attempt.

## What This Solves

The relay is meant for review loops where the artifact matters as much as the words:

```text
builder agent -> package + hashes -> reviewer agent -> bound findings -> builder agent
```

The important property is not that every reviewer is automated. The important property is that the review
is versioned, hash-bound, replayable, and rejected when it does not match the thing being patched.
