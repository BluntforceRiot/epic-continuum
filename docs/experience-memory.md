# Recorded experience and reusable procedure suggestions

This isolated 0.4 capability retains successful **and failed** attempts using the
existing append-only, project-scoped Scroll. It does not execute steps, rewrite
agent instructions, invoke a model, or promote a report into verified truth.

## Python API

`record_experience(root, *, project_id, session_id, goal, approach, prerequisites,
steps, outcome, observed_result, verification=None, corrects=None)` records an
actual reported attempt. `outcome` is exactly `success` or `failure`. A success
requires at least one exact current project citation (`kind`, `id`,
`content_hash`); failure may omit citations. Verification means an attributed
source is available with that exact hash, **not** that Continuum independently
ran or confirmed its assertions. `prerequisites` is a mapping of declared names
to values. Corrections append a new attempt against a current same-goal leaf;
the old failure or success remains available in history.

`propose_procedure(root, *, project_id, session_id, experience_ids, title)` accepts
2–16 distinct current successes with exactly matching goal, approach,
prerequisites, and steps. The combined evidence must contain 2–16 distinct exact
verification sources. Repeating one reported result cannot create repeated
verification. A proposal copies only those recorded steps and links every
supporting attempt/hash; it is explicitly an inference, initially unreviewed.
This is deterministic evidence grouping, not an LLM-generated generalization.

`review_procedure(root, *, project_id, session_id, procedure_id, decision,
reviewer, reason, expected_review_id=None)` appends an explicit `accept` or
`reject`. For the first review the expected head is `None`; every later review
must supply the exact latest review ID. Concurrent reviews serialize through
the ordinary capture transaction: only one may advance a given head. Acceptance
requires current supporting evidence. Rejection remains possible after evidence
becomes stale. The reviewer name is local caller attribution, not authentication.
Neither decision makes the proposal executable or authoritative instructions.

`query_experiences(root, *, project_id, query=None, include_history=True,
token_budget=2400)` returns complete attempts, proposals and review records.
History defaults on so corrected failures remain visible. `include_history=False`
omits corrected attempts, not failed current attempts or review history. Text
query is a case-insensitive substring of the recorded payload. Results contain
exact provenance, declared-outcome labels and current evidence-review warnings.

`find_reusable_lessons(root, *, source_projects, goal, prerequisites,
accepted_only=True, token_budget=2400)` searches only 1–16 explicitly selected
projects. It shortlists goal-substring-matching proposals and reports matching,
missing, differing, and extra prerequisite names. By default only explicitly
accepted proposals appear. Stale accepted proposals remain visible with
`needs_review`; acceptance is never rewritten retrospectively. Results do not
contain session IDs or private/session/global source content and are never copied
or applied to another project. Explicit project selection is not a new multiuser
access-control layer; normal local project authority still applies.

## Freshness, bounds and preservation

Every query rechecks the exact project citations. Corrected supporting attempts,
newer recorded project-file versions and temporal-fact correction markers warn
that historical evidence needs review even when its original Scroll bytes remain
readable. Registered binary/media asset replacements and linked investigation
findings use the investigation reader's existing recorded-version authority, so
superseded builds cannot remain fresh procedure support through a still-readable
historical envelope. Proposal and acceptance gates apply the same warnings.
Checks concern **current recorded evidence only**: they do not inspect
an external source tree, verify test execution, infer the truth of a claim, or
transitively certify arbitrary third-party conclusions. An accepted procedure
with changed evidence stays accepted in recorded review history but stale in the
current view. Re-review or a new proposal requires an explicit caller action.

Goals/approaches are bounded to 512 characters; prerequisites to 16 entries
(64-character names, 256-character values); steps to 1–32 entries of at most
1,024 characters; observed results to 4,000 characters; evidence to 16 exact
citations. Ordinary typed-record limits cap every record at 65,536 UTF-8 bytes.
All mutation paths retain credential rejection, exact citation hashes and project
scope. Reads of a missing root do not initialize it. Queries keep entire JSON
records or omit them with counts within 512–32,768 estimated-token budgets.

No live setup, model, external endpoint, database schema or existing memory is
changed by enabling these APIs. Removing the module does not delete recorded
evidence; rollback of an isolated build is only its source/artifact rollback.
