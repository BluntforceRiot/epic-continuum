# Claimable handoffs and source collections

These optional Python, CLI and MCP surfaces keep local project coordination in
the existing append-only Scroll. They do not message another agent, grant remote
access, run work, change model settings or make recorded instructions binding.
Actor names are caller attribution, **not authentication**. All writes retain
the normal capture, writer and credential-blocking policies.

## Handoffs

`create_handoff` records an objective, the creating actor, accepted decisions,
unfinished work and up to 16 exact project-visible evidence citations. A citation
is `{kind, id, content_hash}` for an existing Scroll event, Card or Library chunk;
paths and loose IDs are not substituted for source authority. Decisions and work
items are explicit text, not model-generated conclusions. Their bounds are 16
decisions and 32 unfinished items, each at most 2,048 characters; the complete
typed record must also fit the existing 65,536-byte envelope.

`query_handoffs` returns the current append `head`, lease state and original work.
It also rechecks every original evidence citation against current project scope
and exact source hash. `evidence_states` indexes the retained `evidence` array:
each entry is `current` or `stale_or_unavailable`, without distinguishing private,
missing, obsolete or changed content. `unavailable_count`, `needs_review` and
`review_reasons` warn when support can no longer be verified. No source text is
revealed by this check. Lease/head/history fields retain their ownership meaning;
they do not certify evidence freshness, and a completed handoff can still need
evidence review. These checks apply with or without history and never write an
expiry, correction or replacement record.

`transition_handoff` requires that exact `expected_head` and one action:

- `claim`: acquire an open/released handoff or recover an expired one.
- `renew`: replace the current owner's still-active lease with a new duration.
- `release`: relinquish an active lease without completing the work.
- `complete`: mark an actively owned handoff terminal; it cannot be reclaimed.

Claims and renewals default to 300 seconds and accept 1–86,400 seconds. Expiry
uses the local aware UTC wall clock and half-open intervals: at `lease_until` the
old owner no longer holds the lease. Recovery is an explicit new claim, not a
background process. Reads never append expiry events or mutate the database.
History is available with `include_history=True` and retains every accepted
transition. The owner name is deliberately not a bearer secret; callers with
write access must not mistake it for an access-control mechanism.

Head matching, topology, active-owner checks and the new transition are checked
inside the capture transaction. Two same-head claims cannot both commit. A late
old owner cannot complete a recovered lease. Lease time is rechecked after
waiting for the writer; a lease that expires before commit is rejected. Clock
rollback fails closed for transitions. Operators should keep the local clock
correct; this is not a distributed clock/consensus protocol. Invalid/stale-head
operations return an error, not automatic retries or implicit ownership changes.

## Collections and progressive disclosure

`create_collection` records a title (256 characters), summary (1,024), overview
(8,192) and at most 16 explicit exact source citations. Empty collections are
allowed. `revise_collection` replaces that complete view with an append-only
revision, requiring the current `expected_head`; revisions start at one and
advance exactly once. Previous revisions remain browsable, not overwritten.
Source membership is checked at admission and again inside the transaction.

`query_collections` supports three detail levels:

- `summary`: title, summary, revision identity and current member states.
- `overview`: adds the explicit overview; it still does not expose source text.
- `full`: adds exact source pages only for currently visible, hash-matching
  members. `member_index` selects one member of one current collection;
  `member_offset` and `member_limit` (1–8,000 characters) page that exact source.

All levels revalidate every member against current project scope and source
hash. A missing, private, obsolete or changed member is reported as
`stale_or_unavailable`, with no replacement text or hidden-scope detail. Original
summaries/overviews are recorded claims and may therefore outlive their cited
source; `unavailable_count` makes that condition visible. Historical revisions
are checked against today's source visibility too. No query expands membership,
follows filesystem paths, searches across projects or treats source text as
instructions. Full disclosure does not recursively expand citations inside a
member's content. Each source is checked at its read time, not a claim of a
cross-source distributed snapshot.

Packets are complete structured JSON. The default budget is 2,400 estimated
tokens (512–32,768 allowed), measured conservatively as compact ASCII JSON
characters divided by four. When needed, complete result rows are omitted and
reported in `excluded_by_budget`; content is never sliced into invalid JSON.
For a large collection, use an exact `member_index` and a smaller `member_limit`
or a larger budget. A whole oversized row may be omitted, rather than returning
unverified/truncated metadata. Missing-root queries do not initialize storage.

These are local runtime contracts. The isolated tests use disposable roots and
patched clocks; they are not evidence of real-host autonomous collaboration,
distributed ownership, or model reasoning quality.
