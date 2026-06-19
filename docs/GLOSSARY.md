# Epic Continuum Glossary

## Scroll

The full ordered event log of a session. It includes user messages, assistant
messages, tool calls, tool results, file edits, decisions, corrections, and
receipts.

## Looking Glass

The active context pane the model can currently see. It is a token-budgeted view
over the Scroll, Cards, and retrieved memory.

Current behavior: recent Scroll context is session-scoped, while query-based Card
recall uses the configured visibility mode. The default is `session_then_global`;
callers can request `session`, `global`, or `project` recall. Treat recalled
memory as evidence, not authority.

## Hardware Tiers

The operating layers that keep Epic Continuum bounded: VRAM for active model pane and
KV/session runtime, system RAM for hot rebuildable caches, and NVMe for durable
Scroll, Library, Graph, snapshot, queue, and export state.

## Config Budget

A named capacity limit with an explicit value unit. Byte-like settings use
values such as `512KB`, `128MB`, or `4GB` so payload, cache, and durable storage
limits are visibly different while field names stay stable.

## Scribe

The role that records events, chunks scroll spans, creates cards, and writes
reader editions.

## Card

A structured compact memory object. A card can summarize a scroll span, describe
a book, or represent a decision/open task. Cards remain hot and recallable.

## Atomic YAML Memory

A portable sidecar representation of a single memory unit. Epic Continuum stores the
indexed truth in SQLite, then writes human-readable YAML for Cards so recovery
tools, Hermes, git review, and other agents can exchange memory without needing
direct catalog access.

## Thread Recovery Packet

A generated Markdown packet that lets a new agent session recover after a crash.
It contains recent Scroll events, recalled Cards, open tasks, pending jobs,
recent books, and a resume instruction.

## Library

The persistent evidence store. It contains original books, normalized reader
editions, catalog records, cards, atomic YAML sidecars, graph state, snapshots,
and exports.

## Book

An evidence object in the Library. A book can be a file, transcript, thread,
PDF, source document, receipt, or generated reader edition.

## Librarian

The semantic authority for retrieval and placement. The Librarian decides where
cards belong, what should be recalled, and which routes reinforce or decay.

Current behavior: the role exists in the data model and worker loop. Worker
passes review card placement, reinforce recalled routes, decay stale graph
edges, mark conflict groups, and can prune/archive Cards through explicit
operator commands.

## Archivist

The preservation authority. The Archivist verifies hashes, snapshots state,
restores from damage, and moves books between hot/warm/cold/vault storage tiers.

## Constellation

The weighted association graph connecting cards, books, concepts, projects,
people, files, decisions, and tasks.

## Epic Continuity

The operation-ledger rule: long work writes intent, progress, and final receipts
while it runs. Receipts are mirrored under `run/operations` and
`exports/operation_receipts`.

## Operation Guard

The wrapper used by mutating CLI and MCP actions. It starts an operation before
state changes, records progress and a resume cursor, finishes the receipt, and
writes a proof pack.

## Proof Pack

A JSON manifest for an operation. It records receipt hashes, touched paths,
file hashes, preflight snapshots, cursor state, result/error fields, and enough
metadata for another agent to verify what changed.

Current hash scope: proof packs describe receipt files after `proof_pack_uri` is
written. The `proof_pack_hash` lives inside the proof pack itself and is not
written back into the receipt files it hashes.

## Operation Recovery Packet

A Markdown resume packet generated from a stale running operation. It captures
the last cursor, last progress event, intent, receipt paths, and recovery
instructions.

Each operation recovery also writes a machine-readable `.recovery.json` packet
with the same resume cursor and progress fields for agent-driven recovery.
