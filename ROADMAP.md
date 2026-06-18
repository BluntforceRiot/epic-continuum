# Epic Continuum Roadmap

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
