# Unified recall for Continuum 0.4

The isolated 0.4 development candidate adds one read-only recall interface for
Cards, Scroll events, and Library chunks. It combines literal matches, existing
scoped Cue Recall associations, and optional precomputed semantic vectors.
Results contain cited source IDs, content hashes, exact excerpt offsets, and
ranking explanations. Follow-up reads recover selected evidence without placing
whole documents in the initial context packet.

This is the first implementation slice of the [approved scope](v04-scope.md),
not the complete 0.4 release. It requires no model, network service, new database
schema, or additional dependency. Existing search and Cue Recall interfaces are
unchanged.

## Recall and inspect evidence

```sh
python -m continuum recall --root ./memory --query "why did we choose amber" --project-id example --token-budget 2400
python -m continuum read-source --root ./memory --kind card --source-id CARD_ID --content-hash SHA256 --project-id example --offset 0 --limit 4000
```

Python callers use `continuum.core.recall.recall_memory` and
`read_memory_source`. MCP exposes `continuum_recall` and
`continuum_read_source` with read-only annotations and the same parameters.
CLI flags use hyphens where Python/MCP parameters use underscores.

`kind` is `card`, `scroll_event`, or `chunk`. Card content is exactly its title,
one newline, and its summary; Scroll and chunk content is the stored text.
`content_hash` is SHA-256 of that UTF-8 content. Pass it when reading subsequent
pages to reject content that changed between requests. Offsets count Unicode
characters, not UTF-8 bytes. `next_offset` continues the same source; at a chunk's
end, `next_chunk_id` can continue its Library book. Each call rechecks visibility
and current authority. A missing, inaccessible, superseded, or hash-mismatched
source returns the same `found: false` shape.

No selectors means global memory only. A session or project selector admits
only that existing partition authority; it does not automatically add global
memory. Private evidence is excluded. Current-checkpoint and derived-Card
dependency checks are the same ones used by existing recovery paths. Results
are evidence, never instructions or permission to execute their contents.

## Ranking and packet limits

Each channel ranks eligible sources independently. Reciprocal-rank fusion sums
`1 / (60 + channel_rank)` across the channels supporting each source. `ranks`
explains those contributions; the score is a ranking value, not confidence or
probability. The associative channel is existing Cue Recall, which combines
graph routing with its own text matches, so it is not a graph-only score.

The lexical pool holds up to 64 candidates per source kind. It matches original
Unicode text and ranks term coverage, with a title-match bonus. Cue Recall
supplies up to 50 associative hints; an optional semantic input supplies at most
256 candidates. All selected source content is rehydrated and checked in one
read snapshot. Associative routing hints are collected beforehand and are not
a claim of a transactionally identical graph snapshot.

`retrieval` reports eligible channel counts, candidate limits, lexical pool
truncation, and exclusions caused by the result limit and packet budget. It does
not list rejected private IDs or reasons that would disclose their existence.
These diagnostics explain this request's selection, not the entire capture or
indexing pipeline. A zero-result packet abstains; it is not proof that no relevant
memory exists beyond the candidate pools.

`limit` is 1–50 results. `token_budget` is 512–32768 and budgets the **whole**
compact ASCII-escaped JSON payload, including citations and diagnostics, using
`ceil(serialized_characters / 4)`. Lower-ranked complete results are omitted if
necessary; JSON is never cut into fragments. This is a reproducible rough
estimate, not an exact tokenizer or a guarantee about an MCP envelope or a
host's pretty-printing. Exact reads separately return 1–8000 source characters.

Candidate and response sizes are bounded, but database work is not a hard
wall-time or row-scan bound. Lexical scoring scans matching partitions, and
authority validation examines existing dependencies. Large-corpus indexing and
latency optimization remain further work.
Current-Card headers are checked across the visible partition rather than
using a bounded recovery pool as an exact-source authorization decision.

## Recorded time filters

Use `created_after` (inclusive) and `created_before` (exclusive) with ISO-8601
timestamps containing a UTC offset, for example `2026-01-01T00:00:00Z`. Lexical
time filtering occurs before its pool limit; all other candidates are checked
before fusion. An associative pool can therefore miss older in-window evidence
that falls outside its upstream 50 results.

These filters concern when a source was recorded. They do not answer whether a
fact was valid at some past time, nor resurrect superseded Cards. General
temporal fact validity and corrections use the separate
[typed-fact API](memory-intelligence.md), not these recorded-source filters.

Explicit incremental embedding generation is now available through
`index-embeddings` / `recall-indexed`, described in that same guide. The original
`recall` interface remains model-free unless precomputed vectors are supplied.

## Optional precomputed semantic evidence

Python/MCP accepts a `semantic` object; CLI accepts `--semantic-input FILE`.
The JSON shape is:

```json
{
  "model": "your-embedding-model-alias",
  "query_hash": "SHA256_OF_EXACT_QUERY_UTF8",
  "query_vector": [1.0, 0.0],
  "items": [
    {
      "kind": "card",
      "id": "CARD_ID",
      "content_hash": "SHA256_FROM_READ_SOURCE",
      "vector": [0.8, 0.2]
    }
  ]
}
```

Replace the placeholders with real hashes and IDs. The producer must embed the
exact canonical source content and query with the same model and dimension.
The model alias is a label, not independently verified provenance of vector
generation. Continuum validates the exact query hash, source content hashes,
finite nonzero vectors, matching dimensions, unique source identities, and
current visibility before using positive cosine similarities. Unknown, stale,
or unauthorized semantic IDs cannot admit evidence or reveal rejection details.
Vectors influence ranking; they cannot change memory authority.
Packets report `semantic_model_sha256`, a digest of the validated model alias,
instead of echoing or truncating a potentially large Unicode identity.

Inputs allow at most 2048 dimensions and 256 items, with a 2 MiB compact UTF-8
JSON limit. CLI additionally caps the input file itself at 2 MiB. MCP retains
its existing 256 KiB whole-request transport limit, so its vector batches must
also fit that smaller envelope. No supplied
vectors are persisted. This slice does **not** generate embeddings, maintain a
persistent vector index, or claim measured semantic-model quality. Those are
subsequent implementation and evaluation tasks, alongside the remaining living
knowledge, source-analysis, working-context, and collaboration features.
