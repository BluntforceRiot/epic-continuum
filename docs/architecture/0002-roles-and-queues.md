# ADR 0002: Roles And Queues

Date: 2026-06-15

Status: accepted

## Roles

## Scribe

The Scribe writes the Scroll and creates cards when visible context rolls out of
the Looking Glass.

Primary queue priority:

1. live request dependency
2. explicit user-pinned ingestion
3. recovery/state receipts
4. active project material
5. high-novelty/high-salience sources
6. bulk backlog

## Librarian

The Librarian is the semantic placement and recall authority. The Librarian
reads pending cards, decides where books/cards belong, retrieves relevant memory,
and reinforces or decays routes based on use.

Primary queue priority:

1. live user/agent request
2. request-blocking pending card
3. integrity/security event affecting answer trust
4. high-priority card review
5. routine card review
6. maintenance and decay decisions

Live requests preempt batch review, except when the live request clearly depends
on a pending card that must be read first.

## Archivist

The Archivist preserves, verifies, snapshots, restores, and manages storage
tiers.

Primary queue priority:

1. integrity threat
2. live request retrieval dependency
3. pre-mutation snapshot
4. new book verification
5. storage pressure
6. routine retention/tier review

## Hardware Pressure

Roles respond to hardware pressure without changing the evidence contract:

- VRAM pressure belongs to the active runtime. It can reduce the Looking Glass,
  recall pack, or KV/session cache for the current request.
- System RAM pressure belongs to hot caches and queues. It can evict rebuilt
  cache entries, flush queue state, and reload from NVMe when needed.
- NVMe pressure belongs to the Archivist. It can move Books across
  hot/warm/cold/vault tiers, compact indexes, and enforce snapshot retention.

Config budgets for these responses keep stable field names and use explicit
value units such as `512KB`, `128MB`, and `4GB` so queue buffers, cache pools,
and durable stores are not confused.

## System Rule

```text
Live request wins,
unless integrity is at risk.
Evidence preservation beats convenience.
Catalog cards stay hot.
Books can move.
Routes can fade.
Evidence does not disappear.
```
