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

`review-prepare` first copies the subject into a frozen snapshot under the job directory. The packet,
manifest, subject archive, and capsule are all generated from that snapshot, not from later reads of the
live worktree.

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
it does not allocate another sequence. A different operation ID is a deliberate
new reservation and supersedes the current unfinished attempt before allocating
the next number.

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

When the subject is a ZIP file, Continuum validates the ZIP, computes an inner member manifest, preserves the
original archive under `original/`, and expands reviewable members directly under `subject/`. A full-capsule
review result for such jobs must echo both `inner_archive_manifest_sha256` and `inner_archive_member_count`.

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
and full line SHA-256. Replacing the fixture value with a different token invalidates the exception. The legacy
`--secret-allowlist-pattern` route remains only for non-hashed false positives; hashed token and private-key
findings are never suppressed by a source-line regex alone. Raw allowlist file paths are not written into the
public capsule; only counts are recorded. Suppressed findings are written to the local
`secret-allowlist-report.json` with redacted snippets and stable hashes. If the scan blocks, Continuum removes
the temporary preparation directory and does not leave an uploadable capsule or subject archive behind.

Maintainers reconcile the repository fixture allowlist with
`python scripts/generate_review_fixture_allowlist.py --check`. After deliberately reviewing and adding an exact
fingerprint for any new synthetic fixture, run the script with `--write`. It relocates existing approvals when
only line numbers change, removes and reports obsolete approvals, and refuses to write if any scanned finding
does not match an approved source/type/secret/line fingerprint.

Directory subjects must fit under `--max-files`. If the file limit is reached, a custom `.continuumignore`
rule excludes subject files, the subject is inside the Continuum root, or a non-empty subject produces an
empty snapshot, `review-prepare` fails rather than silently claiming full coverage. For large release reviews,
pass the already-built release ZIP as the subject.

## Validation

`review-ingest` fails closed unless the returned JSON proves it belongs to the exact job:

- `job_id` or `review_id` must match the request.
- `packet_sha256` must match `review-packet.md`.
- `review_capsule_sha256` must match `review-capsule.zip`.
- `subject_archive_sha256` or `package_sha256` must match `subject.zip` or the unchanged single-file subject
  copy when an archive exists.
- `review_complete` must be `true`.
- `sentinel` must match `CONTINUUM_REVIEW_COMPLETE:<job_id>:<packet_sha256>`.

Continuum re-hashes the actual `review-packet.md`, review capsule, and subject artifact at ingest time. It
does not trust `request.json` alone as the source of truth for artifact binding.

Every reviewer-controlled response must be valid UTF-8 and no larger than
exactly 4,000,000 encoded bytes. The same predicate covers the direct endpoint's
transport wrapper and extracted reviewer content, Hermes output, inline ingest,
reserved browser files, external result paths, and every durable resume read.
External and network reads stop after the limit plus one byte; Hermes output is
captured through a file-backed bounded read. Direct transport validates both the
wrapper and reviewer content before writing either one.

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
Legacy regex patterns can only suppress non-hashed findings:

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

Before applying findings from a long-running external review, check that the active subject still matches
the frozen review snapshot:

```bash
continuum review-check-current \
  --root ./.continuum-demo \
  --job-id review_20260624T000000Z_example
```

If `current` is false, create a new review job instead of patching stale findings.

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
  --job-id review_20260624T000000Z_example
```

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
  --job-id review_20260624T000000Z_example
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
the MCP server can access the intended repository or review-result path.

## What This Solves

The relay is meant for review loops where the artifact matters as much as the words:

```text
builder agent -> package + hashes -> reviewer agent -> bound findings -> builder agent
```

The important property is not that every reviewer is automated. The important property is that the review
is versioned, hash-bound, replayable, and rejected when it does not match the thing being patched.
