# Epic Continuum Roadmap

## Current 0.2 Focus: Shared State, Cue Recall, And Trust Boundaries

The 0.2 line delivers durable project state shared across agents, associative Cue Recall for buried ideas, exact-memory capture, and stricter release-boundary checks.

- Deepen Codex, Claude Code, Hermes, and local-agent capture around the same Continuum root.
- Record project identity, repository, branch, changed files, test failures, decisions, avoided approaches, and next actions as durable state.
- Maintain Cue Recall: vague prompts such as "that local-agent upgrade idea" should return ranked candidate idea clusters with evidence.
- Preserve exact user prompts in the Scroll, protect explicit "remember this exactly" memories, and build a damped association graph over important terms, paths, tools, models, people, and concepts.
- Downweight saturated/common terms, preserve rare distinctive ideas when they are connected to active projects or user emphasis, and decay weak/noisy routes rather than deleting raw evidence.
- Explain recall results: show direct matches, associated terms, timeline anchors, evidence references, and uncertainty when multiple candidate memories are plausible.
- Keep project/session/private visibility boring and strict across Scroll, Cards, Library references, jobs, recovery packets, and MCP schemas.
- Backfill upgraded roots with `reindex-memory` so older Scroll events can participate in Cue Recall without duplicating graph weights.

## Next Release Focus

- Deeper Looking Glass planning that can deliberately pull Library search, Cue Recall candidates, operation receipts, and project checkpoints into one budgeted context packet.
- More scale testing for high-entropy tool output and long-running shared-agent projects.
- Background Librarian/Scribe scheduling so indexing, decay, card review, and verification continue without an agent babysitting every pass.
- Better human review tools for pruning by project, topic, time range, sensitivity, and confidence.
- More adapter proofs for Codex, Claude Code, Hermes, and local OpenAI-compatible model servers.

## Foundation Slice

- Repository structure
- SQLite schema
- Scroll event append
- Scribe queue seed
- Status command
- Architecture docs
- Hardware tiers and unit-bearing config budgets
- Epic Continuity operation receipts
- Operation Guard for mutating CLI/MCP actions
- Proof packs, stale operation recovery, and recovery drill
- Smoke test

## Scribe Slice

- Scroll segmentation
- Card generation
- Summary/citation fields
- Raw segment hashing
- Reader edition writer
- Payload limits documented as KB/MB budget values

## Librarian Slice

- Pending card review queue
- Placement decisions
- Hybrid recall over cards, events, and books
- Looking Glass context compiler
- Route reinforcement and decay policy
- Recall pack budgets for VRAM and RAM pressure

## Archivist Slice

- Snapshot manager
- Integrity manifests
- Hot/warm/cold/vault tier moves
- Restore tests
- Storage pressure policy
- Snapshot, graph, and Library budgets as GB values

## Agent Integration Slice

- MCP server
- Codex/Hermes tool schemas
- Local home bot session adapter
- Event hooks for tool calls, file edits, and compaction receipts

## Release Criteria

- Rebuildable from archive and audit events
- No evidence loss from route decay
- Tests for scroll compaction and recovery
- Clear install docs
- Clear hardware profiles for laptop, workstation, and home server use
- Config examples use KB/MB/GB values for byte-like budgets
- Demonstrated improvement on long-thread recovery tasks
- Recovery drill passes on a disposable nested root
- Shareable root bundle passes strict preflight, portable-metadata audit, cross-platform name checks, and every archived member hash
- CI passes Python 3.11/3.13 on Linux and Windows plus clean build/install/bundle smoke
