# Epic Continuum Project Charter

## One-Line Purpose

Epic Continuum gives agents durable continuity across finite context windows.

## Problem

LLMs do not have infinite active context. Long threads, tool work, files,
decisions, and user preferences eventually fall out of the model's visible
window. Existing memory systems often act like search indexes or note stores,
but they do not fully model the ordered lived thread or the handoff between
short-term context and long-term memory.

## Core Idea

Epic Continuum treats a session as a Scroll: an append-only ordered event log. The
model sees only a Looking Glass over part of the Scroll. When that visible pane
gets too long, the Scribe rolls the old pane into structured Cards, the Library
preserves evidence, and the Librarian can bring relevant past material back into
view later.

## Hardware Contract

Epic Continuum treats hardware tiers as part of the memory model:

- VRAM is for the active model pane and KV/session runtime. It holds the current
  Looking Glass and request-local retrieval pack, not the permanent archive.
- System RAM is for hot, rebuildable caches: recent Scroll spans, pending queue
  state, hot Cards, graph neighborhoods, and reader edition pages.
- NVMe is for durable memory: the Scroll database, Library originals, reader
  editions, Constellation graph, snapshots, queue journals, and exports.

Configuration budgets that represent byte-like capacity keep stable field names
and carry explicit value units such as `512KB`, `128MB`, or `4GB` so reviewers
can see whether a limit belongs to payloads, caches, or durable stores.

## Design Principles

- Preserve evidence before optimizing recall.
- Compact context, but keep pointers to raw source.
- Cards stay hot and searchable even when books move cold.
- Routes may reinforce, decay, or tombstone.
- Evidence does not disappear because a route decays.
- Back up while building: long operations write intent, progress, and final
  receipts as they run.
- Mutating tool calls are operation-guarded and leave proof packs.
- Stale running work can be marked interrupted and turned into a recovery
  packet.
- Live requests preempt background memory maintenance unless integrity is at
  risk.
- The system should be inspectable with boring local tools first.

## Foundation Product Slice

- SQLite-backed Scroll and catalog.
- Local filesystem Library layout.
- Scribe queue seeded from appended events.
- Structured Cards and graph schema.
- CLI for init, append-event, and status.
- Tests and architecture docs.
- Hardware tiers and config budget documentation.
- Operation receipts mirrored under `run/operations` and
  `exports/operation_receipts`.
- Proof packs, stale-operation recovery, and recovery drill command.

## Follow-On Product Slices

- Context compiler for the Looking Glass.
- Scribe card generation.
- Librarian recall and placement review.
- Archivist snapshot/tier manager.
- Full-text and vector indexes.
- MCP server for Codex/Hermes/local agents.
- Runtime integrations for KV cache/session cache orchestration.
