# Working context, task packs and memory debugging

These are opt-in Python/CLI/MCP capabilities. They do not change an installed
host's prompts, model settings, runtime, or memory roots.

`select_working_context(messages, context_tokens=..., reserve_tokens=...)`
keeps the stable leading system/developer prefix, the current user group, and
the preceding complete user/assistant group. Older groups are retained as a
contiguous suffix when they fit. Assistant calls and all their results are
atomic; invalid, orphaned or unfinished call/result groups fail closed. No
message content, JSON result or image is sliced. If the mandatory boundary
cannot fit, the returned messages remain intact, `fits` is false, and the caller
must defer or increase the budget. `prepare_working_chat_request` enforces that
rule and returns a new request plus separate metrics without sending anything.

The estimator counts text characters / 4 plus framing and a bounded media cost
(default 1024 per structured image/audio/video block or whole data URL). It
does not JSON-serialize encoded images into token text. Hosts should supply
their own visual-cost contract and retain real tokenizer/preflight checks. This
is a deterministic planning estimate, not measured inference performance.

`compile_task_pack` takes explicit project record IDs and/or exact citations,
with purposes resume, investigation, review or release. Records are whole;
external source pages have exact hashes and continuation offsets. Missing or
out-of-project selections fail closed, not silently widened searches. Packets
have stable SHA-256 identifiers, no instruction authority, and explicit omitted
counts. Selected collections expand one level into only their exact scoped
member citations (at most 64 in a pack); `expand_collections=False` keeps only
the selected collection records. A small budget may omit a whole large record: expand its exact citation
through `read_memory_source`, rather than treating a truncated JSON fragment as
evidence. Purposes label the caller's selection; they do not invent a task plan.

`change_impact` follows explicit evidence/asset/symbol/member links, current
recorded input versions and caller-supplied change IDs. It marks dependents for
review without editing them. It does not crawl source files or assume an old
record's existence means its underlying input is unchanged on disk. The domain
investigation/project readers additionally offer explicit source-root checks.

`explain_memory` reports the actual requested retrieval's scope, channel counts,
rank and output-budget effects. A wider bounded diagnostic window can distinguish
ranking from packet omission and labels visible corrected/superseded typed
evidence separately from retained current records. `outside_diagnostic_window_or_no_match` is not
proof of absence. `not_available_in_scope` deliberately does not distinguish a
missing record from another project's/private record. Diagnostic output is
itself bounded; `reason_scope` identifies the requested recall packet, not an
assurance that its entire contents fit in the explanation.

All operations here are read-only and model-free. Local synthetic context-size
and replay checks do not certify a real host's prompt/cache/tokenizer behavior.
