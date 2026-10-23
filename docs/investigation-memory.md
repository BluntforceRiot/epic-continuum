# Evidence-linked investigations

Investigation memory retains source/binary findings, supplied media annotations,
and linked notebook entries on the existing project-scoped, append-only Scroll.
It does not run binaries, Ghidra, REA, source code, extraction tools, or a model.
No component is downloaded, no directory is crawled, and Git is not required.

## Assets and binary findings

`register_analysis_asset(root, project_id=..., session_id=..., source_root=...,
path=..., asset_kind=..., build_id=...)` hashes one explicitly selected regular
file of at most 32 MiB. `source_root` must be an absolute existing directory;
`path` is a portable relative path. Links/reparse points and parent escapes are
rejected. The original bytes and absolute source directory are never stored.
The retained metadata is relative path, SHA-256, byte count, declared kind,
operator-supplied build identifier, and version. Kinds are `binary`, `image`,
`pdf`, `audio`, `video`, `table`, and `transcript`; a declared kind is not a claim
that a file format has been parsed or authenticated.

The returned record includes `id`, `content_hash`, `payload`, and a `status` of
`registered` or `unchanged`. The original file hash is `payload.source_hash`;
the record's `content_hash` binds its complete typed envelope. These hashes are
different and serve different citation purposes. The same path/hash/kind/build
is idempotent, including concurrent registration. Changed bytes, kind, or build
append a version. On supported filesystems, aliases of the same file continue
one version history; two genuinely distinct case-sensitive files remain distinct.
Concurrent conflicting updates can return a retryable conflict rather than
silently replacing another version.

`record_analysis_finding` requires an exact `asset_id` and `asset_hash` (the
original file SHA-256), a title/text, analyst attribution, and a function name
or `0x` hexadecimal address of at most 64 bits. It copies the build identifier
from the referenced binary asset. The optional `source_symbol` is:

```json
{"record_id":"exact-project-file-record-id","content_hash":"64-lowercase-hex-digits","symbol":"Parser.read","line":42}
```

The `project_file` must already exist in the same project, with that envelope
hash and indexed Python symbol. `line` is optional only when the symbol name is
unique in that exact file version. The source record retains its original file
hash and symbol line/end-line anchors. Arbitrary source names are not accepted
as verified mappings.

The default finding status is `hypothesis`. `operator_confirmed` requires at
least one valid evidence citation and remains an attributed operator assertion,
not independent verification by Continuum. There is no automatic promotion to
truth, no instruction authority, and no rewriting of an older finding.

## Supplied multimodal evidence

`record_media_annotation` requires exact media `asset_id`/`asset_hash`, title,
supplied text, and at least one of these bounded anchors:

```json
{
  "page": 3,
  "region": [0.1, 0.2, 0.8, 0.9],
  "table": {"row_start": 1, "row_end": 4, "column_start": 2, "column_end": 5},
  "time": {"start_ms": 1200, "end_ms": 3500}
}
```

Page numbers and inclusive table indices start at one. Regions use normalized
left/top/right/bottom coordinates with positive area. Timestamps are ordered
nonnegative integer milliseconds. Only relevant anchors need be supplied.
Coordinate existence within the original media is supplied evidence, not checked
by an extractor. Original media stays outside the memory/model packet. Binary
assets use findings, not media annotations.

## Linked notebooks

`record_notebook_entry` appends a `notebook_id`, title/text, and an `entry_kind`
of `observation`, `experiment`, `hypothesis`, `competing_explanation`, or
`conclusion`. Optional links bind exact same-project typed record envelopes:

```json
{"relation":"supports","target_id":"exact-record-id","content_hash":"64-lowercase-hex-digits"}
```

Relations are `observed_from`, `tests`, `supports`, `contradicts`, `explains`,
and `related_to`. Links may point to other typed knowledge, not just investigation
entries. A conclusion can retain both supporting and competing explanations;
its kind does not confer truth. Up to 16 unique links and 16 evidence citations
are allowed. Evidence uses the existing exact citation shape
`{kind, id, content_hash}` and is rechecked at admission and query.

`export_investigation_notebook` returns a Markdown string, not a file write.
It includes entry text, exact IDs/hashes, links/evidence, and review warnings.
Markdown/HTML metacharacters in supplied text are escaped. The default ceiling
is 32,768 characters (allowed range 1,024–131,072). Entries are kept whole;
omitted counts are explicit. An envelope that cannot fit is an error, not a
truncated or oversized export. Exporting does not create destination files or
overwrite anything.

## Querying and changed-input warnings

`query_investigation(root, project_id=..., query=None, notebook_id=None,
source_root=None, include_history=False, token_budget=2400)` returns complete
typed records with exact citations and `needs_review`/`review_reasons`.
`query` is a bounded literal substring filter. `notebook_id` selects that
notebook's entries. Without `include_history`, older asset versions are omitted
from the displayed assets but their findings/annotations/notebooks remain.
They are marked when linked evidence needs review, never silently deleted.

Freshness without `source_root` means **recorded versions only**. Newer asset or
indexed-source versions make their dependent findings/annotations stale; stale
findings propagate through notebook links. An explicit source root additionally
checks recorded relative assets/source files for changed bytes, missing files,
or unreadable/unsafe inputs. No absolute location is remembered or guessed.
Cross-domain notebook links retain exact citation validity; freshness semantics
of other domains are handled by their own queries or the assembled task pack.

Default output is bounded at 2,400 estimated tokens (512–32,768 allowed), using
the existing conservative ASCII-JSON character estimate. Whole records are
removed to fit and `excluded_by_budget` reports omissions. Queries and exports
of a missing memory root return empty evidence without initializing a database.

## Admission, preservation, and limits

All supplied strings, structures, hashes, anchors, links, and kinds are bounded
and validated. Existing credential guards reject credential-like metadata and
text. Input-file text is checked with the existing raw/structured JSON guards;
ambiguous duplicate JSON keys and resource-limit decoding failures fail closed.
Binary bytes are hashed only, not stored or decoded into generated annotations.
These checks do not claim to identify every credential encoding in arbitrary
binary data. The caller must only register approved files and safe relative
locators. Titles are limited to 240 characters and supplied text to 8,000;
the existing 65,536-byte typed-record ceiling remains in force.

This is a local memory capability, not binary analysis, OCR, transcription,
multimodal inference, or evidence authentication. Heavy extraction is optional
future integration. No service, host, model configuration, private root,
credential binding, or live setup is changed by these APIs.
