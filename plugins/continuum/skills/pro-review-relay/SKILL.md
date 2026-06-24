---
name: pro-review-relay
description: "Use when Codex needs to run the private Epic Continuum review loop through a signed-in ChatGPT Pro or other browser-only reviewer: prepare one hash-bound capsule, drive or guide the browser upload, ingest the JSON result, and check the source is still current before applying findings."
---

# Pro Review Relay

Use this skill for the user's personal "Big Brother" review loop when the desired reviewer is a browser-only model such as a signed-in ChatGPT Pro thread. Do not use loose screenshots, partial packets, or unbound pasted prose when Epic Continuum can create a review job.

## Core Rule

Continuum owns evidence. Browser automation owns only the GUI airlock.

The deterministic part must:

- create the frozen review job;
- produce one `review-capsule.zip`;
- preserve `request.json`, `status.json`, schema, packet, manifest, source hash, capsule hash, and sentinel;
- ingest only schema-valid JSON;
- run `review-check-current` before applying findings.

The browser part must not mutate source files or decide whether findings are valid.

## Workflow

1. Prepare the job:

```bash
python -m continuum review-prepare \
  --root "$CONTINUUM_ROOT" \
  --subject "$SUBJECT" \
  --prompt "$PROMPT" \
  --transport manual
```

2. Read the `review_capsule_uri`, `review_capsule_sha256`, and `manual_handoff_uri` from the JSON output or `review-status`.
3. If a reliable Computer Use or browser tool is available, open the dedicated signed-in review browser/thread, upload the single capsule, paste the short handoff prompt, and wait for the final JSON object.
4. If no browser-control tool is available, tell the user the capsule path and ask them to upload it manually. Do not claim the Pro relay is automated.
5. Save the returned JSON to the job directory or another local file.
6. Ingest it:

```bash
python -m continuum review-ingest \
  --root "$CONTINUUM_ROOT" \
  --job-id "$JOB_ID" \
  --result-path "$RESULT_JSON"
```

7. Check freshness before patching:

```bash
python -m continuum review-check-current \
  --root "$CONTINUUM_ROOT" \
  --job-id "$JOB_ID"
```

If `current` is false, stop and prepare a fresh review job. Do not apply stale findings.

## Browser Guardrails

- Use one dedicated review thread per job unless the user explicitly asks otherwise.
- Upload only `review-capsule.zip` unless troubleshooting requires separate files.
- Paste the handoff prompt without adding extra instructions that weaken the schema or hash binding.
- Capture the final JSON exactly. If the model returns prose around JSON, save the raw output and let `review-ingest` extract or reject it.
- Preserve browser, upload, timeout, and copy failures as resumable work state instead of silently retrying with a different artifact.

## Acceptance

A successful run ends with:

- `review-ingest` accepted the response;
- the ingested findings path exists;
- `review-check-current` reports `current: true`;
- Codex has read the findings in the originating thread;
- no push, tag, release, or remote operation occurred unless the user explicitly authorized it.
