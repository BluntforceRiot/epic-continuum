# Review Relay

Epic Continuum's review relay is a deterministic bridge between a builder agent and a reviewer agent.
It is designed for the workflow where Codex builds a package, another model reviews it harshly, and Codex
then patches every finding without losing track of which artifact was reviewed.

The relay does not require a hosted API. It can be used with a local OpenAI-compatible endpoint, a Hermes
one-shot reviewer, or a manual reviewer flow where the user uploads one review capsule to a separate model
and saves the JSON result.

For strict unattended automation, the OpenAI-compatible transport is the preferred path because it receives
and returns raw JSON over HTTP. The Hermes transport is supported for agent-mediated review, but it is still
held to the same schema and hash checks; if Hermes or the selected model returns prose, partial JSON, or a
tool-loop question, Continuum marks the job `review_failed` and preserves the raw response for diagnosis.

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
  subject.zip
  review-capsule.zip
  manual-handoff.md
  browser-handoff.md
  secret-allowlist-report.json
  responses/
  findings/
  receipts/
  snapshot/
    subject/...
```

For a single-file subject, Continuum copies the file unchanged instead of wrapping it in another ZIP. That
keeps the reviewed package SHA-256 equal to the original file SHA-256.

The review capsule is the intended manual upload artifact:

```text
review-capsule.zip
  REVIEW_INSTRUCTIONS.md
  request.json
  expected-response.schema.json
  source-manifest.json
  review-packet.md
  subject/...
```

The capsule cannot contain its own final SHA-256 because that would change the ZIP. The final capsule hash is
reported in `status.json`, `manual-handoff.md`, `browser-handoff.md`, `review-status`, and `review-prepare`
output. The reviewer must echo that hash in `review_capsule_sha256`. `browser-handoff.md` is generated only
after the capsule exists, so it is the source of truth for browser-only Pro relays.

Only `review-capsule.zip` is intended to be uploaded or shared with the reviewer. The local job files
(`request.json`, `status.json`, and `manual-handoff.md`) may contain local paths so Codex can resume,
ingest, and run `review-check-current` on the original machine. The capsule's public request and source
manifest use path-neutral `subject/` references instead.

The packet contains the review objective, Git snapshot, file manifest, selected text excerpts, coverage
metadata, and optional diff material. Direct OpenAI-compatible review is a packet-only review. If the packet
is truncated or critical files are omitted, Continuum downgrades a clean packet-only pass to
`coverage_limited` during ingest. A browser/manual reviewer that inspected the uploaded capsule should return
`review_surface: "full_capsule"` and `subject_inspected: true`; that full-capsule signal is not downgraded
only because the packet excerpts were limited.

Review preparation scans every decodable snapshot file, UTF-8/UTF-16 text, ZIP member contents, ZIP metadata,
generated request/instruction text, and the completed capsule boundary for obvious secret-like material before
publishing a capsule hash. Use
`--secret-allowlist-pattern` only for known false-positive lines in review fixtures or documentation. Patterns
must be anchored to Continuum's `source:line:text` target, such as
`^tests/test_fixture.py:12:.*synthetic_token`. The source path and line number are treated as exact targets;
wildcards in the source or line are rejected, and only the text tail is a regex. The patterns are not written
into the public capsule; only the count is recorded. Suppressed findings are written to the local
`secret-allowlist-report.json` with redacted snippets and stable hashes. If the scan blocks,
Continuum removes the temporary preparation directory and does not leave an uploadable capsule or subject
archive behind.

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

If a fixture or documentation line trips the review secret scanner, suppress only that line with a narrow
regex:

```bash
continuum review-prepare \
  --root ./.continuum-demo \
  --subject . \
  --prompt "Do a harsh release-boundary review." \
  --transport manual \
  --secret-allowlist-pattern "^tests/test_fixture.py:12:.*example_fixture_token"
```

For a browser-only reviewer, reserve a response path before each attempt. Upload `review-capsule.zip` to the
reviewer, paste the exact short prompt from `browser-handoff.md`, save the reviewer JSON to the reserved path,
and ingest that exact file:

```bash
continuum review-browser-attempt-start \
  --root ./.continuum-demo \
  --job-id review_20260624T000000Z_example

continuum review-ingest \
  --root ./.continuum-demo \
  --job-id review_20260624T000000Z_example \
  --result-path ./.continuum-demo/exports/review_bridge/jobs/review_20260624T000000Z_example/responses/response-001.raw.txt
```

If the reviewer returns malformed JSON, keep that raw response, run `review-browser-attempt-start` again, and
use the newly reserved `response-002.raw.txt` path. Do not overwrite an earlier response file.

Check status:

```bash
continuum review-status \
  --root ./.continuum-demo \
  --job-id review_20260624T000000Z_example
```

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
