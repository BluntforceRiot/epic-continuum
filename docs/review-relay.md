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
reported in `status.json`, `manual-handoff.md`, `review-status`, and `review-prepare` output. The reviewer
must echo that hash in `review_capsule_sha256`.

The packet contains the review objective, Git snapshot, file manifest, selected text excerpts, coverage
metadata, and optional diff material. Direct OpenAI-compatible review is a packet-only review. If the packet
is truncated or critical files are omitted, Continuum downgrades a clean pass to `coverage_limited` during
ingest.

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

Upload `review-capsule.zip` to the reviewer and paste the short instructions from `manual-handoff.md`.
Save the reviewer JSON and ingest it:

```bash
continuum review-ingest \
  --root ./.continuum-demo \
  --job-id review_20260624T000000Z_example \
  --result-path ./review-result.json
```

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
2. upload the single `review-capsule.zip` to the dedicated signed-in review thread;
3. paste the handoff prompt;
4. capture the final JSON response;
5. run `review-ingest`;
6. run `review-check-current` before applying findings.

When no browser automation tool is available, this remains a manual capsule upload. The package should not
claim a fully unattended ChatGPT Pro relay unless the caller can actually control the signed-in browser.

## MCP Tools

MCP-capable agents can use the same workflow without shelling out:

- `continuum_review_prepare`
- `continuum_review_run`
- `continuum_review_ingest`
- `continuum_review_status`
- `continuum_review_check_current`

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
