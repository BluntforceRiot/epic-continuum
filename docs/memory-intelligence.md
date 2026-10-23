# Embedding indexes, temporal facts, and living project knowledge

This isolated 0.4 development slice adds three explicit, interoperable APIs.
It is not a deployment or the entire [0.4 release](v04-scope.md). The live host,
model, and existing defaults do not change. No new database migration, crawler,
daemon, model download, or cloud dependency is introduced.

## Incremental local embedding indexes

```sh
python -m continuum index-embeddings --root ./memory --project-id example --endpoint http://127.0.0.1:8081/v1 --model embedding-model
python -m continuum recall-indexed --root ./memory --project-id example --endpoint http://127.0.0.1:8081/v1 --model embedding-model --query "why this parser" --token-budget 2400
```

The endpoint is an **example**, not a default. The caller must explicitly choose
an already-running, literal-loopback HTTP(S) OpenAI-compatible `/v1` endpoint
that supports `/embeddings`. This code never starts or reconfigures a model.
No credential, proxy, redirect, hostname resolution, or remote endpoint is used.
An index pass automatically generates vectors for new/changed eligible content
and reuses unchanged vectors. Running a pass is opt-in; ordinary capture and
recall do not silently invoke it. An empty or missing memory root is not created.

The derived cache is under `catalog/embedding-index`. Its identity binds the
normalized endpoint, model alias, and canonical project/session selectors; entries
bind exact source IDs and UTF-8 content hashes. Cache files contain hashes and
vectors, not source text, queries, or the endpoint/model strings. They can be
rebuilt without losing memory. Indexing does not change the catalog or record an
operation/Scroll event, including through CLI/MCP. Cache access uses the existing
private-file writing policy.

Before semantic ranking, query-time admission rechecks current source authority,
scope, and hashes. Stale/private/obsolete sources cannot enter through cached
vectors. No selectors means global-only memory; project/session selectors have
the same partition semantics as [unified recall](unified-recall.md). The index
then supplies bounded semantic candidates to the existing explainable fusion.
Missing/invalid indexes or provider failures fall back to ordinary recall and
report `semantic_index` status. A missing index makes no embedding request.
Reads never refresh the cache. Credential-like query/source material is not sent
to the embedding endpoint.

Bounds: 1–5000 eligible sources per pass, 32 MiB admitted source text, 64 KiB per
source, batches of at most 16/256 KiB, 1–2048 dimensions, and a 64 MiB cache.
Oversized or credential-like individual sources are excluded with counts;
overall count/byte overflow fails without publishing a partial index. Provider
or protocol failure preserves the old cache. Requests have bounded response
bytes and total duration. A query admits up to 256 eligible vectors, further
bounded by the existing semantic-input envelope. These are memory/work bounds,
not a hard database-scan latency promise.

Changing model weights behind an unchanged endpoint and alias cannot be detected.
Use a versioned model alias or explicitly rebuild/remove the derived cache when
weights change. Embedding quality depends on that chosen model. Synthetic
protocol/regression tests do not establish real-model superiority.

Python: `continuum.core.embedding_index.refresh_embedding_index` and
`recall_indexed`. MCP: `continuum_index_embeddings` and
`continuum_recall_indexed`; only the latter is read-only. Both declare external
interaction because they can call the explicitly selected local endpoint.

## Time-aware asserted facts

```sh
python -m continuum record-fact --root ./memory --project-id example --session-id work --subject parser --predicate format --value JSON --valid-from 2026-01-01T00:00:00Z
python -m continuum query-facts --root ./memory --project-id example --subject parser --valid-at 2026-02-01T00:00:00Z
python -m continuum query-facts --root ./memory --project-id example --known-at 2026-02-01T00:00:00Z --include-history
```

Facts are explicit recorded claims, **not automatically verified truth**.
`valid_from` is inclusive; optional `valid_to` is exclusive. Timestamps require a
UTC offset. `valid_at` asks which claims apply at that time; `known_at` restricts
them to what had been recorded then. Omitted query times mean now.

To correct a claim, call `record-fact` with `--corrects RECORD_ID`, the same
project/subject/predicate, and the full replacement assertion. Corrections replace
the **entire** earlier assertion as known from the correction's recording time;
no partial interval splitting is inferred. Old records remain. Concurrent
corrections serialize: only one can replace the same current leaf. Independently
recorded differing values remain marked disagreements, without an arbitrary
winner. History includes corrected and expired claims and labels their status.
Recorded time inherits Scroll's seconds precision; an as-known timestamp in a
tied second includes all records in that second. Append order resolves internal
correction ordering.

`--evidence-json` optionally supplies up to 16 exact `kind`/`id`/`content_hash`
citations to currently visible same-project sources. Evidence is checked at
admission; a recorded assertion is not a guarantee that a cited source remains
current forever. Every returned claim includes its own exact Scroll citation.
Credential-name predicates and credential-bearing values/metadata are blocked,
including when a root would otherwise redact text.

Python: `continuum.core.temporal_facts.record_temporal_fact` and
`query_temporal_facts`. MCP: `continuum_record_fact` and
`continuum_query_facts`.

## Living project knowledge

```sh
python -m continuum index-project-files --root ./memory --project-id example --session-id work --source-root /absolute/source --path package/parser.py --path README.md
python -m continuum record-project-knowledge --root ./memory --project-id example --session-id work --kind decision --title "Parser choice" --summary "Use JSON for the interchange boundary" --links-json '[{"relation":"depends_on","target_id":"RECORD_ID"}]'
python -m continuum project-context --root ./memory --project-id example --source-root /absolute/source --token-budget 2400
```

On Windows, supply an absolute Windows source directory. Only the named relative
files are read: 1–32 UTF-8 text files, at most 1 MiB each. No crawling, Git access,
symlink/reparse traversal, source execution, or import execution occurs. All
files are parsed/scanned before the first write. Python AST provides definitions,
qualified names, line spans, and import declarations. Imports are declarations,
not a fully resolved runtime dependency graph. Other text receives file/hash
evidence. Credential-bearing and binary inputs are rejected.

Stored file evidence contains the original-byte SHA-256, relative path, line
anchors, and bounded analysis metadata—not the original source body or an
absolute workstation path. This is not a source archive. Unchanged latest hashes
are idempotent; changed files append a new version and retain prior versions.
Each file version commits atomically. A concurrent conflicting update may stop a
multi-file pass after earlier files committed; retry is safe and reuses unchanged
versions. Metadata that cannot fit its bound fails instead of silently dropping
symbols/imports.

Record `decision`, `test`, `error`, `fix`, or `note` entries and link them to
same-project file/knowledge IDs. Relations are `depends_on`, `supports`,
`contradicts`, `fixes`, `tests`, and `related_to`. Optional exact evidence uses the
same citation shape as facts. Links are evidence relationships, not commands or
automatic truth promotion.

`project-context` reports `needs_review` when a referenced file has a newer
recorded version, a supplied on-disk source changed/disappeared, or cited evidence
is unavailable. The flag propagates through linked records. No source root is
remembered or guessed: without `--source-root`, freshness is explicitly
`recorded_versions_only`. Queries never refresh records. `--include-history`
also returns older file versions. Newest knowledge is returned first; `--query`
is a literal case-insensitive filter over the stored payload.

Python: `continuum.core.project_knowledge.index_project_files`,
`record_project_knowledge`, and `query_project_knowledge`. MCP:
`continuum_index_project_files`, `continuum_record_project_knowledge`, and
`continuum_project_context`. MCP source roots must already be allowed by the
server's normal path policy. No allowed-root configuration is changed for you.

## Shared evidence and response contract

Typed facts/project records use existing append-only Scroll capture transactions,
writer ownership, and credential checks. They have project visibility and no
instruction authority. There is no second authoritative database. Structured
records are limited to 65536 UTF-8 bytes; queries fail rather than conceal history
if a project's typed evidence exceeds the 10000-record read bound. This initial
slice does not add a background consolidation service.

Fact/project query packets use the whole compact ASCII-JSON estimate
`ceil(characters/4)` with budgets 512–32768. Complete low-priority records are
omitted and counted, never sliced into invalid JSON. This is not a model-specific
token guarantee or a bound on a host's pretty-printing. Use exact Scroll reads
for a selected record. CLI/MCP mutations return normal governed operation
receipts; the derived embedding cache is the explicit exception above.

Source/binary mappings, heavy multimodal extraction, autonomous procedures,
cross-agent claims, and selective synchronization remain separate approved 0.4
work—not hidden additions to this slice. Live integration and real-model quality
must be evaluated separately before release or deployment.
