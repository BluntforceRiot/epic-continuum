# Changelog

## 0.2.0 - 2026-06-20

- Added Cue Recall for loose, associative recovery of buried ideas from vague
  prompts while preserving exact Scroll evidence.
- Added Scroll-time association indexing, exact-memory Card protection for
  "remember this exactly" requests, and graph route reinforcement for meaningful
  terms.
- Added shared project-state capture so Codex, Hermes, Claude Code, local LLM
  agents, and other adapters can record durable handoff checkpoints into the
  same root.
- Added CLI and MCP tools for `cue-recall` and `record-project-state`.
- Added `reindex-memory` for idempotent upgrade backfill of Scroll association
  routes and trusted exact-memory Cards.
- Added Cue Recall and shared-agent-state documentation, plus updated Codex
  plugin skill guidance for cross-agent memory use.
- Hardened project/session/private visibility boundaries across recovery packets,
  Cue Recall, context compilation, project-state Cards, Scroll segment
  compaction, event deduplication, and pending queue jobs.
- Hardened exact-memory trust so assistant/tool text and generic MCP callers
  cannot self-promote into protected memory without a trusted explicit adapter
  path.
- Hardened upgrade backfill with a root-global `after_rowid` cursor so
  root-wide `reindex-memory` pagination cannot skip interleaved sessions.
- Hardened recovery identifier handling by applying secret policy checks to
  project IDs as well as session IDs before recovery packets are written.
- Hardened benchmark publication behavior by removing ground-truth ranking
  leakage, adding safe output-directory handling, scrubbing local path metadata,
  excluding generated results from release artifacts, and documenting packet-level
  metric limits.
- Added high-entropy ScaleBench pressure coverage for graph write amplification.

## 0.1.0 - 2026-06-19

Initial public release.

- Added the Scroll, Card, Library, graph, queue, and snapshot storage substrate.
- Added CLI and MCP tools for capture, recall, recovery, verification, bundle
  export, restore drills, MemPalace import, and worker maintenance.
- Added Codex, Hermes Agent, Claude Code, OpenClaw, OpenAI-compatible, and
  broader adapter-kit scaffolding.
- Added operation receipts, proof packs, root bundles, semantic bundle
  verification, secret auditing, and recovery packets.
- Added configurable hardware budgets, retention policy, capture policy, and
  privacy-mode defaults.
- Hardened public-release behavior for POSIX file modes, Hermes secret handling,
  FTS fallback health, hard tool-result byte caps, plugin namespace isolation,
  and clean release packaging.
- Added root-confined configurable paths, portable operation identifiers,
  cross-process operation-receipt locking, URI-safe read-only SQLite access,
  private redacted adapter logs, and link-safe public release assembly.
- Finalized release boundaries with proofed-ledger immutability, portable recovery
  packets, bounded recovery filenames, strict tool-result skip/byte-cap semantics,
  portable symlink-skip export, and secret-safe packaged adapter diagnostics.
