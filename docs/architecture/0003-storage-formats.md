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
visibility scope, session/project ownership, lifecycle status, placement, tier,
and timestamps.

Hermes and other agent shells can use this as an interchange format:

- Hermes can emit atomic YAML; Epic Continuum can ingest and index it.
- Epic Continuum can emit atomic YAML; Hermes can read it for handoff or recovery.
- The core package includes a minimal reader for the deterministic YAML subset
  it emits, so sidecars can be audited, diffed, and used as portable evidence
  without a separate YAML runtime.
- Lifecycle workers refresh sidecars after committed placement, recall, and
  pruning changes. A mutable current sidecar may be replaced atomically, but an
  artifact-bound immutable sidecar is retained and the new state is written to
  `<card>.live.yaml` or `<card>.live-<state_hash>.yaml`. Consumers must follow
  the Card row's `location_uri`; `<card>.yaml` can be a historical generation.
  A hash-suffixed filename is content-addressed and is never overwritten with a
  different state, even before artifact registration. Detached hash-named bytes
  remain non-authoritative history only when an adopted-write or
  prepared-transition receipt and the independently parsed payload bind the
  same managed path and state hash. Snapshot pairs carry those receipts with the
  sidecars that require them.
- Managed sidecar basenames and receipt targets use the same case-insensitive
  portable grammar on every runtime, but parent-directory identity remains
  native and exact. Casefold-colliding Card ids or filenames are rejected rather
  than selected arbitrarily, so a Windows-created snapshot can be verified and
  restored on a case-sensitive host without weakening path confinement. The
  actual directory-entry spelling is recorded before a hash generation is
  detached; a case-only rename therefore receives a prepared-transition receipt
  whose URI remains exact after copying to a case-sensitive host.
- A managed leaf must remain the same regular, no-follow namespace entry while
  it is indexed, read, hashed, classified, or bound to a receipt. Symlinks,
  junctions, reparse points, non-files, and entries replaced across those
  boundaries do not inherit authority from their targets.
- Each newly created sidecar target is preceded by a unique durable intent and is
  closed by a recovery receipt. A process interruption cannot silently bless
  uncommitted bytes: reconciliation either adopts the catalog-bound state,
  leaves retry authority pending, or preserves the bytes in a receipted
  `.uncommitted` quarantine.
- A damaged SQLite catalog is recovered from snapshots and bundles today.
  Sidecar-driven catalog rebuild/import is an explicit tool boundary, not an
  implied automatic recovery path.

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
