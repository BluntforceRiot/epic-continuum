# ADR 0003: Storage Formats

Date: 2026-06-15

Status: accepted

## Decision

Epic Continuum uses a format stack rather than one universal file type.

```text
Original book       exact source file, immutable when possible
Reader edition      normalized Markdown or text
Catalog/card data   SQLite rows plus atomic YAML card sidecars
Scroll events       SQLite WAL first, segment exports later
Graph/routes        SQLite graph tables first
Human reports       Markdown recovery packets, CSV, or XLSX as needed
```

## Rationale

Spreadsheets are useful for audit reports and evals, but they are not the right
core memory substrate. Markdown is readable, but not enough for queue state,
indexes, graph weights, storage tiers, and audit events. JSON is portable, but
less convenient for indexed query. Atomic YAML is useful for memory receipts,
handoffs, and human review, but it should not be the only query engine.

SQLite is the best durable core because it is local, indexed, inspectable,
portable, and requires no service.

## Physical Layout

```text
archive/originals/{hot,warm,cold,vault}
archive/reader_editions/{hot,warm,cold}
catalog/catalog.sqlite3
catalog/cards/*.yaml
scroll/segments
graph
queues
snapshots
exports
```

## Hardware Mapping

The physical layout maps to hardware tiers:

| Hardware tier | Storage role | Main paths or stores |
| --- | --- | --- |
| VRAM | active pane and KV/session runtime | not durable storage; rebuilt from Looking Glass inputs |
| System RAM | hot cache and queue working set | hot Cards, recent Scroll spans, reader pages, graph neighborhoods |
| NVMe | durable substrate | `catalog/catalog.sqlite3`, `catalog/cards/*.yaml`, `archive/`, `scroll/`, `graph/`, `queues/`, `snapshots/`, `exports/` |

## Atomic YAML Memory

Atomic YAML is the portable memory unit format. SQLite remains the fast catalog,
but every Card can also be written as a small `.yaml` sidecar with the card id,
type, title, summary, source references, topics, decisions, open tasks, hashes,
and timestamps.

Hermes and other agent shells can use this as an interchange format:

- Hermes can emit atomic YAML; Epic Continuum can ingest and index it.
- Epic Continuum can emit atomic YAML; Hermes can read it for handoff or recovery.
- The Archivist can rebuild catalog rows from sidecars if the SQLite catalog is
  damaged. The core package includes a minimal reader for the deterministic YAML
  subset it emits, so this rebuild path does not depend on a separate YAML
  runtime.

## Thread Recovery Packets

Thread recovery packets are Markdown exports assembled from the Scroll, Cards,
pending jobs, open tasks, and recent books. They are designed to be pasted into
Codex, Hermes, or another agent after a crash so the agent can continue from
the durable Epic Continuum state.

## Budget Units

Capacity settings keep stable field names and state their unit in the value:

```text
512KB  small payloads, card bodies, reader chunks
128MB  cache pools, queue buffers, recall packs
4GB    Library tiers, graph stores, snapshots, runtime KV cache
```

Unqualified byte budgets are not accepted in public config examples unless raw
bytes are intentional.
