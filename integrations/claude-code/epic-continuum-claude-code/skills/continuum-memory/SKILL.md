---
name: continuum-memory
description: Use Epic Continuum from Claude Code for persistent memory, Looking Glass context, automatic resume, temporal conflict handling, operation receipts, and session handoff.
---

# Epic Continuum Memory

Epic Continuum is a local persistent-memory substrate. Prefer the bundled MCP
tools when available:

- `continuum_status`
- `continuum_append_event`
- `continuum_compile_context`
- `continuum_recover_thread`
- `continuum_resume_latest` when a known session id is unavailable
- `continuum_repair_project_state_checkpoints` to preview and explicitly apply
  a scoped repair when resume reports `repair_required`
- `continuum_cue_recall` for vague memory prompts
- `continuum_record_project_state` before a handoff or risky change
- `continuum_memory_health` to inspect queue, capture, storage, and learning state
- `continuum_prune_memory` only for bounded literal-topic lifecycle changes to
  ordinary Cards, never project-state, conflict-group, or supersession authority
- `continuum_detect_conflicts` and `continuum_resolve_conflict` for complete temporal conflict groups or explicitly confirmed project-state authority boundaries
- `continuum_yarn_health` before using the optional local Yarn/Qwythos briefing layer
- `continuum_list_operations`
- `continuum_recover_operations`
- `continuum_recovery_drill`
- `continuum_restore_drill`

If MCP is unavailable, use the configured CLI environment:

```bash
python -m continuum status --root "$CONTINUUM_ROOT"
python -m continuum resume --root "$CONTINUUM_ROOT" --project-id "<project>" --no-model-assist
python -m continuum memory-health --root "$CONTINUUM_ROOT"
```

When a session id is known, use `continuum_recover_thread`. Otherwise use
`continuum_resume_latest` with the best-known project id. Respect the configured
resume mode: explicit mode requires a supplied session or project, while latest
project mode uses only its configured project scope.

Checkpoint repair requires a project id, session id, or explicit `all=true`.
Never turn an omitted scope into root-wide repair. Project/root repair sees only
project-visible checkpoints unless `include_session_scoped` or
`include_private` is separately enabled; an exact session id authorizes that
session boundary. Preview first, reuse the same flags with `apply=true`, and
verify the guarded receipt before retrying resume.

Resume must inspect the complete requested project-state authority boundary and
fail closed if a malformed payload, link, group, unsupported edge, exact
source-bound Card-type mismatch, or proven missing derived Card would make a
competing Card disappear. Use project-state replacement, complete conflict
resolution, or checkpoint repair for authority changes; generic topic pruning is
not an authority-retirement operation.

Treat the Scroll as the ordered source of prior work. Cards and recovery packets
are compact views over it, not replacements for it. For a handoff, record a
project state with the project id, agent id, branch, commit, changed files,
decisions, and open tasks.

Yarn/Qwythos briefings are optional and advisory. Check `continuum_yarn_health`
when readiness is uncertain. If the local endpoint is unavailable, keep the
deterministic recovery packet unchanged and continue without model assistance.

Resolve a temporal conflict as one complete group: promote the intended current
Card or dismiss the false positive as a group. Do not partially resolve one pair
inside a larger group.
