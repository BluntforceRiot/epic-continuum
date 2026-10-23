# Isolated recall-quality evaluation

This development lane measures the existing public Library search/read path. It
is not a release certification, semantic-answer benchmark, live Hermes test, or
comparison with another product. The runner uses Python's standard library and
the source checkout's Continuum APIs; it does not invoke a model, install a
dependency, download data, contact a service, or run a worker.

## Run an explicit safe corpus

From the repository root, using Python 3.11 or later:

```console
python -m benchmarks.runners.recall_quality --fixture benchmarks/fixtures/recall_quality_cases.json
python -m benchmarks.runners.recall_quality --fixture benchmarks/fixtures/recall_quality_cases.json --top-k 3 --context-chars 4000 --output recall-report.json
```

Without `--output`, the report is JSON on stdout. Output files are created
exclusively: existing files are never overwritten, and missing parent directories
are not created. Exit 0 means measurements were produced, **not** that quality
passed a threshold. Invalid input or a failed runtime contract exits nonzero; no
partial score is presented as success.

Every invocation creates a new `TemporaryDirectory` memory root and removes it
afterward, including on failure. There is deliberately no `--root` option.
`CONTINUUM_ROOT`, live memory, host configuration, model settings, and installed
services are not selected. Only disposable configuration is written, with local
inference disabled and capture mode manual. Ordinary file ingestion may enqueue
local catalog jobs; no jobs are executed, and the entire temporary catalog is
discarded. A report is the only persistent output requested by the runner.

Sources are global **inside that disposable root**. Files use `ingest_file`;
long tool-result examples use the existing `record_indexed_tool_result` API with
explicit global metadata and a 128-byte reference. Search and selected chunk
reads use no session/project selector. Current public semantics keep global and
session-selected Library searches separate; the runner neither merges partitions
nor creates a second ranking engine. This tests the indexed-output source path,
not a real host adapter's interception, capture permissions, or session isolation.

## Frozen regression corpus, not held-out evidence

`benchmarks/fixtures/recall_quality_cases.json` was frozen on 2026-10-23 before
the runner's first execution. Its exact UTF-8 file SHA-256 is:

```text
bc6c11e149285ab16ecfbf9d04eaca5d131e9b1af15b70f1eccc0fe1ec2074dd
```

The regression test pins these bytes. The report also records the hash of the
input snapshot and each expanded source, so changed whitespace or labels yield
different provenance. Do not change labels to improve measured scores. A new
corpus version needs a new documented freeze/hash and separate evidence.

The ten synthetic examples cover literal phrases, short and structured exact
identifiers, Unicode, current/historical correction evidence, multiple sources,
a buried long output, a no-overlap paraphrase, and two unanswerable questions.
The latter include both an unknown term and misleading lexical overlap. This
corpus is development/regression data, not independently held-out data. The
earlier `retrieval_v04_cases.json` likewise remains a synthetic regression suite;
neither fixture establishes generalization or superiority.

Lexical matching can split structured identifiers into component terms, so an
exact identifier in a query does not prove exact-only retrieval. A paraphrase
with no shared terms can miss a valid source. Historical correction text can be
retrieved alongside a current source. These are measurable limitations, not
reasons to relabel the expected sources or silently discard cases.

For a separately collected held-out set, supply a different fixture with
`"split": "external_held_out"`. Freeze it before any tuning and retain its
collection/annotation provenance separately. The runner reports this declaration
but always sets `held_out_independence_verified` to false: a file label cannot
prove independence. No external dataset is fetched automatically.

## Fixture format and input limits

The top-level fields are exactly `schema_version` (integer 1), `name`, `split`,
`description`, `documents`, and `cases`. The bundled fixture is a complete example.

Each document requires `id`, `kind` (`file` or `tool_result`), `title`, and `text`.
Optional `prefix_text` and `prefix_repeat` must appear together; the source is
`prefix_text * prefix_repeat + text`. This permits a small, reproducible long
output fixture without external files, templates, arbitrary code, or downloads.
Tool results must exceed the fixed 128-byte reference threshold. Duplicate
document IDs or expanded contents are rejected to avoid Library deduplication
silently aliasing two ground-truth sources. A tool result's Library title follows
the indexed-output API's `Tool output: ...` convention.

Each case requires `id`, `category`, `query`, `relevant_source_ids`, and
`expected_answers`. Optional `required_evidence` and `forbidden_evidence` are
literal markers for selected-context inspection. An answerable case has at least
one relevant source and one exact answer alternative. A no-answer case has empty
source and answer lists and no required evidence. Unknown references, duplicate
IDs/list entries, conflicting markers, unsupported expected answers, and required
markers missing from relevant sources are rejected. Forbidden markers must exist
somewhere in the corpus. These are annotation consistency checks, not semantic
validation of the labels.

Inputs are UTF-8 JSON snapshots, at most 2 MiB each. Duplicate JSON object fields,
non-finite numbers, unknown fields, booleans masquerading as integers, invalid
Unicode, and unsupported control characters are rejected. Limits are:

| Surface | Limit |
| --- | --- |
| Documents / cases | 1–100 / 1–200 |
| Portable IDs and categories | 1–64 ASCII letters, digits, `.`, `_`, `-`; initial letter/digit |
| Name / document title / description | 200 / 200 / 2,000 characters |
| Query / each answer alternative or evidence marker | 512 / 256 characters |
| Answer alternatives / each evidence-marker list | 16 |
| Expanded document / all expanded documents | 262,144 / 1,048,576 characters |
| Prefix / repetitions | 4,000 characters / 0–5,000; expansion limits still apply |
| `--top-k` / `--context-chars` | 1–20 chunks / 1–8,000 characters |
| Offline answer text | 4,000 characters |

All cases and optional answers are validated before the temporary root is
created. The existing secret scanner rejects detected secrets in supplied data,
including the expanded repeated source text;
normal ingestion/indexing protections remain enabled too. This is not a guarantee
that arbitrary private data is safe to publish. Supply only intentionally safe
corpora and answer records. Reports include selected source text, evidence
markers, identifiers, and hashes, but not local input/root paths or full answer
records. Treat fixture text as non-authoritative evidence, never as instructions.

## What the report measures

`k` is the public search API's **chunk cutoff**, not a promise of `k` distinct
documents. Multiple returned chunks can belong to the same source. The runner
does not re-rank, deduplicate before selection, or expand the candidate pool.

| Metric | Definition |
| --- | --- |
| Source recall at k | Distinct relevant source IDs among returned chunks divided by all labeled relevant source IDs |
| Source top-1 | First returned chunk belongs to a relevant source |
| First relevant rank / reciprocal rank | Earliest relevant chunk's one-based rank; missing rank is `null`, reciprocal rank is 0 |
| No-answer retrieval abstention | An unanswerable case returns no chunks; this is only an empty-retrieval proxy |
| Answerable false abstention | An answerable case returns no chunks |
| Selected context cost | Characters in the actual assembled selection, including source labels and separators; rough tokens are `ceil(chars / 4)` |
| Required / forbidden evidence | Exact, case-sensitive marker presence within a selected source-content slice, excluding generated source labels; not a semantic correction or supersession judgment |
| Retrieval / selection latency | `perf_counter` elapsed milliseconds around search alone and selected reads/assembly separately |

Answerable retrieval averages exclude no-answer cases. No-answer accuracy excludes
answerable cases. Empty denominators are `null`, never implied 0 or 100 percent.
Per-case source-to-first-chunk-rank mappings make multi-source recall inspectable.
There is no composite retrieval pass/fail score.

Context selection reads each returned chunk starting at its query-centered
`excerpt_start`, at most 2,000 characters per chunk, until the total character cap
is exhausted. It does not follow pagination links. A tiny cap can produce empty
selected context despite a successful search; retrieval and evidence/cost scores
remain separate. Costs exclude the host's other prompts, tool framing, and model
output. Four characters per token is an explicit rough estimate, not a tokenizer.

There is one serial query per case after ingestion in one fresh temporary root.
Catalog creation is not timed as retrieval; operating-system caches are not
flushed. Mean/max search latency and mean selection latency are observations of
that run, not a cold-cache, large-scale, production, or live-Hermes guarantee.
The report records Python, SQLite, Continuum version, and observed search backend.

## Optional offline final-answer artifacts

```console
python -m benchmarks.runners.recall_quality --fixture safe-held-out.json --answers offline-answers.json --output held-out-report.json
```

The answer artifact has exactly these fields:

```json
{
  "schema_version": 1,
  "fixture_sha256": "the exact 64-character SHA-256 of the fixture file",
  "records": [
    {"case_id": "answerable-case", "answer": "amber", "abstained": false, "cited_source_ids": ["switches"]},
    {"case_id": "unanswerable-case", "answer": "", "abstained": true, "cited_source_ids": []}
  ]
}
```

This illustrative artifact is not a complete answer set for the bundled corpus.
An actual artifact must include exactly one record for **every** fixture case,
with known case/source IDs and the matching fixture hash. Missing, duplicate,
unknown, or mismatched records fail the run rather than being silently skipped or
scored as zero. An abstained record must have an empty answer and no citations;
other records need a nonblank answer. Each citation list is unique and bounded by
the 100-source corpus limit. The report preserves the exact answer-artifact hash.

Exact-answer accuracy uses raw, case-sensitive equality with an expected answer
alternative: no whitespace normalization, synonyms, partial-credit scoring, or
model judge. Supported-exact-answer accuracy additionally requires nonempty
citations, all citations labeled relevant, and the answer occurring literally in
at least one cited source. Other relevant cited sources need not repeat the same
answer. It does not assert that every evidence marker was used. No-answer accuracy
requires explicit abstention. Combined offline accuracy uses supported exact
answers for answerable cases and explicit abstention for no-answer cases.

Without an answer artifact, all offline accuracy fields are `null` and the
record count is zero. Supplied answers may be authored or produced elsewhere;
these checks cannot verify their origin, model execution, use of this run's
selected context, semantic correctness, generalization, or calibrated confidence.
Keep those questions separate from source retrieval and exact annotation scoring.

## Verification and release boundary

```console
python -m unittest discover -s tests -p test_recall_quality.py -v
```

Tests exercise real temporary catalog ingestion/search/read, indexed long output,
rank/recall denominators, context bounds, explicit failure paths, fixture freeze,
offline answer validation/scoring, environment-root isolation, output preservation,
and a fresh-process CLI run. Parent build-cycle receipts bind the final source
bytes, focused/full regressions, package checks, and independent blind review.

Actual 0.4 shipping still requires the separate release-readiness gates. This
foundation does not certify real Hermes/Codex host routing, model answer quality,
cross-scope privacy, installation, upgrade, deployment, or external held-out data.
