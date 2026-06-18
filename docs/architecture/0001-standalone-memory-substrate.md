# ADR 0001: Standalone Memory Substrate

Date: 2026-06-15

Status: accepted

## Decision

Epic Continuum is a new standalone repository and memory substrate. It does not use
MemPalace internally.

MemPalace and the MemGalaxy plugin provided useful lessons, but Epic Continuum is
designed around:

- a Scroll: append-only ordered event log
- a Looking Glass: the active context pane over the Scroll
- a Scribe: event capture, chunking, and card creation
- a Library: persistent content-addressed evidence store
- Cards: structured compact summaries and placement records
- a Librarian: retrieval, ranking, placement, reinforcement, pruning
- an Archivist: integrity, snapshots, restore, and storage tiers
- a Constellation: weighted association graph

## Rationale

The new design is not trying to rebuild a palace metaphor. It is trying to solve
finite model context by rolling active context into durable structured memory,
then retrieving the right pieces when needed.

The core optimization is not making the model context physically infinite. It is
making continuity loss-managed:

```text
raw scroll event -> segment -> card -> indexed library -> recall into active pane
```

## Non-Goals

- Do not depend on MemPalace.
- Do not make disk or RAM pretend to be true transformer attention.
- Do not delete evidence because a route decays.
- Do not make one giant scroll file.

## Hardware Boundaries

Epic Continuum maps the memory model onto explicit hardware tiers:

- VRAM carries the active Looking Glass, request-local retrieval pack, and
  KV/session runtime. It is pressure-sensitive and not durable.
- System RAM carries hot rebuildable caches: recent Scroll spans, hot Cards,
  reader edition pages, graph neighborhoods, and queue buffers.
- NVMe carries the durable substrate: Scroll tables, Library originals and
  reader editions, Constellation graph, snapshots, queue journals, and exports.

Runtime pressure may reduce context, evict cache, or move Books between storage
tiers. It must not erase recoverable evidence or make a decayed route look like
deleted source material.

## Consequences

- Epic Continuum owns its own persistent storage.
- Storage must be rebuildable from originals, reader editions, cards, and audit
  events.
- SQLite and files form the durable core. Vector, KV, and session-cache
  integrations remain bounded runtime layers.
