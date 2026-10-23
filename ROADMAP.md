# Epic Continuum Roadmap

## Current 0.3 Focus: Automatic Recovery, Temporal Truth, And Local Intelligence

The 0.3 line turns the 0.2 durability foundation into a daily recovery system.

- Discover and resume the latest durable state without requiring a remembered thread ID.
- Balance Scroll, Cards, and Cue Recall through an explainable bounded planner.
- Resolve temporal Card conflicts without deleting historical evidence.
- Provide a guarded, optional Qwythos v3 briefing layer through local llama.cpp.
- Protect the workstation with conservative context, resource, concurrency, timeout,
  identity, privacy, and deterministic-fallback gates.
- Persist personal defaults for context safety and project-oriented resume.
- Surface queue, worker, segmentation, sidecar, snapshot, and WAL health in one report.

## Next Release Focus (0.4)

The [approved 0.4 scope](docs/v04-scope.md) expands Continuum into a headless,
local-first memory and working-context platform. One shared core serves Hermes,
Codex, and other supported hosts through adapters and profiles. A separate
private Vanta product branch is no longer a target; private memory scopes remain.

- Semantic, exact, relational, and temporal recall with evidence and bounded cost.
- Living project knowledge, including source and binary-analysis findings,
  change-impact tracking, and evidence-linked investigation notebooks.
- Real host context management for large outputs and multimodal conversations.
- Time-aware facts, corrections, verified experience, and reusable procedures.
- Cross-agent continuity, claimable handoffs, and task-ready context packs.
- Browsable collections, disposable memory experiments and replay, cross-project
  transfer of verified lessons, and selective cross-machine sharing.
- Headless memory debugging and operator diagnostics through CLI, MCP, and APIs.

Memory Studio and all new graphical/dashboard interfaces are excluded. A
productized practical evaluation lab is deferred pending a separate decision;
ordinary tests, representative quality checks, and release validation remain
required. Neither exclusion removes existing test utilities.

The reviewed retrieval/output/inspection work is foundation evidence only, not
completion of this expanded scope. Follow the [readiness gates](docs/v04-readiness.md)
for each assembled candidate. Live deployment and publication remain separate
decisions; optional model-assisted features must not become a mandatory cloud
dependency or cause Continuum to control the user's model lifecycle.

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
