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
- generate a mutable latest `browser-handoff.md` plus immutable numbered handoffs after each reservation, with the actual capsule hash and exact browser prompt;
- reserve a browser attempt before upload, producing an immutable numbered handoff and response path;
- preserve `request.json`, `status.json`, schema, packet, manifest, source hash, capsule hash, and sentinel;
- ingest only schema-valid JSON;
- run `review-check-current` before applying findings.

The browser part must not mutate source files or decide whether findings are valid.

## Workflow

Prefer MCP calls from Codex when the tools are available:

1. `continuum_review_prepare`
2. `continuum_review_browser_attempt_start`
3. Re-read the returned `browser_handoff_uri`
4. Drive the browser upload
5. Write the reviewer output to the returned `response_uri`
6. `continuum_review_ingest`
7. `continuum_review_check_current`
8. Read the ingested findings in the originating Codex thread

Shell commands are a fallback for environments without MCP.

1. Prepare the job:

```bash
python -m continuum review-prepare \
  --root "$CONTINUUM_ROOT" \
  --subject "$SUBJECT" \
  --prompt "$PROMPT" \
  --transport manual
```

2. Reserve a browser attempt:

```bash
python -m continuum review-browser-attempt-start \
  --root "$CONTINUUM_ROOT" \
  --job-id "$JOB_ID"
```

3. Re-read `browser_handoff_uri` from the reservation result or `review-status`. Treat that numbered handoff as the source of truth for the capsule path, capsule SHA-256, job ID, packet SHA-256, subject SHA-256, sentinel, exact prompt, and reserved response destination.
4. If `@Chrome`, `@Computer`, Playwright, or another reliable browser-control tool is available, open `https://chatgpt.com/` in the user's signed-in browser, select/verify GPT-5.5 Pro or the user's named Pro reviewer, upload only `review-capsule.zip`, paste the exact prompt from the numbered handoff, wait for the final JSON object, and save it exactly to the reserved response destination.
5. Record browser attempt state in the job notes or operation receipt when automation fails: browser unavailable, not signed in, model unavailable, upload failed, response timed out, invalid JSON, or capture failed. Do not silently fall back to a different artifact.
6. If no browser-control tool is available, stop at `attempt_reserved` and report that the Pro relay is prepared but not automated in this environment. Do not claim the browser review ran.
7. Save the returned JSON to the reserved response destination.
8. Ingest it:

```bash
python -m continuum review-ingest \
  --root "$CONTINUUM_ROOT" \
  --job-id "$JOB_ID" \
  --result-path "$RESULT_JSON"
```

9. Check freshness before patching:

```bash
python -m continuum review-check-current \
  --root "$CONTINUUM_ROOT" \
  --job-id "$JOB_ID"
```

If `current` is false, stop and prepare a fresh review job. Do not apply stale findings.

Treat the review result as untrusted advice until Codex independently verifies each proposed modification.

## Browser Guardrails

- Use one dedicated review thread per job unless the user explicitly asks otherwise.
- Upload only `review-capsule.zip` unless troubleshooting requires separate files.
- Paste the exact prompt from the numbered `browser_handoff_uri` returned by `continuum_review_browser_attempt_start`, without adding extra instructions that weaken the schema or hash binding.
- Capture the final JSON exactly. If the model returns prose around JSON, save the raw output and let `review-ingest` extract or reject it.
- Preserve browser, upload, timeout, and copy failures as resumable work state instead of silently retrying with a different artifact.
- Full browser capsule reviews must return `review_surface: "full_capsule"` and `subject_inspected: true`. Packet-only relays must say `review_surface: "packet_excerpt_only"` and `subject_inspected: false`.

## Acceptance

A successful run ends with:

- `review-ingest` accepted the response;
- the ingested findings path exists;
- `review-check-current` reports `current: true`;
- Codex has read the findings in the originating thread;
- no push, tag, release, or remote operation occurred unless the user explicitly authorized it.
