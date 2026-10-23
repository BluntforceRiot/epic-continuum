# Retrieval and large outputs (0.4 candidate)

This is an opt-in source candidate for the next release, not a live configuration
change. It uses the existing SQLite Library and standard-library code. No model,
embedding service, new database, or copied competitor implementation is required.

## Search, then read selected evidence

`continuum search --root ROOT --query "retry delay" --session-id SESSION`
returns bounded query-centered snippets, chunk IDs, and source character offsets.
Ranking combines FTS5/BM25 rank (LIKE fallback if unavailable) with literal
coverage, title matches, and phrases using reciprocal-rank fusion with k=60.
Only visible candidates enter reranking; at most max(50, limit*10) are reranked.
This is lexical retrieval, not semantic/vector search or an answer generator.

`continuum read-chunk --root ROOT --chunk-id CHUNK --session-id SESSION --limit 4000`
returns exact content, its hash, and `next_offset` when more of that chunk remains.
Offsets and limits count Unicode characters, not bytes or model tokens. Limit is
1–8000 (default 4000). At the end, `next_chunk_id` permits an explicit next-chunk
read. No automatic follow-up loop is created. Missing and out-of-scope IDs have
the same empty response. Project-scoped evidence requires its project selector.

Python: `search_memory`, `read_memory_chunk`. MCP: `continuum_search`,
`continuum_read_chunk`. Both preserve the existing scope and non-authoritative
evidence rules. Scroll cue excerpts are query-centered too; checkpoint authority
and supersession selection are unchanged.

## Preserve oversized adapter results

The default remains `capture.large_result_policy = "truncate_with_notice"`.
To opt in on a separately approved configuration, set it to `"index_and_link"`.
This acts only on results already allowed by the existing capture flags/mode.

When approved text exceeds `capture.max_tool_result_bytes`:

1. The complete text and metadata pass the existing credential policy first.
   Default blocking remains blocking; `warn` archives only the redacted text.
2. A content-addressed archive and exact ordered Library chunks retain the text.
   Structured payloads use the adapter's existing JSON serialization. String
   payloads retain whitespace. The Library inherits the canonical Scroll scope.
3. Scroll receives only a byte-bounded reference, with the book ID and capture
   hash in metadata. Library and Scroll catalog rows commit together. Interrupted
   writes can leave an unreferenced archive, as with ordinary file ingestion.
4. Search retrieves excerpts; callers explicitly read only selected chunks.

`storage.max_ingest_bytes` (default 50MB) is also the preservation ceiling.
Above it, capture falls back to bounded truncation and reports
`index_skipped_reason`; it does not claim full preservation. This is not a host
tool interceptor: a host that already sends full tool output to its model must
separately opt into a bounded-output integration. No Hermes routing changes are
part of this patch.

Existing skip, truncate, and legacy summarize_and_link behavior is unchanged.
No memory is migrated or deleted. Existing readers can still read the catalog.

## Evaluation boundary

`benchmarks/fixtures/retrieval_v04_cases.json` is a small synthetic corpus frozen
before implementation. It covers ranking, a buried decision, short identifiers,
Unicode, and a no-answer case. It is not a held-out benchmark or evidence of
superiority over another product. Vector retrieval, model answer quality, and
live Hermes latency remain separate opt-in evaluation work.
