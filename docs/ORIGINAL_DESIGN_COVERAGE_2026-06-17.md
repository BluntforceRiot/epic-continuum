# Epic Continuum Original Design Coverage

Date: 2026-06-17

This matrix maps the original operator design to the current package behavior.

| Original idea | Current status | Notes |
|---|---|---|
| Scroll as full ordered event log | Included | `scroll_events` stores ordered session events with deduplication and secret policy. |
| Looking Glass / active pane | Included | `compile-context` builds token-bounded context with Scroll, Cards, Books, and graph-aware recall. |
| Compactor rolls older context into Cards | Included | `roll-segment`, Scribe worker auto-roll, and adapter maintenance hooks compact Scroll spans. |
| Scribe writes and chunks | Included | Scribe queue jobs write Scroll events, roll segments, and create Card projections. |
| Library of Books | Included | File ingest creates originals, reader editions, chunks, FTS rows, and artifact ledger entries. |
| Catalog Cards / card handoff | Included | Cards store summaries, source refs, topics, decisions, salience, scope, and atomic YAML sidecars. |
| Librarian reads cards and places them | Included | Worker reviews pending Cards, assigns shelves, writes graph routes, and marks Cards active. |
| Librarian recall priority | Included | Live context compilation is read/recall-oriented; batch worker work is explicit and bounded. |
| Synaptic reinforcement | Included | Recalled Cards increment recall counts, increase salience, reinforce graph edges, and reset decay counters. |
| Synaptic pruning | Included | Route decay is interval-gated and can tombstone stale unpinned routes. Card projection pruning is explicit. |
| Archivist preserves originals | Included | Originals/readers stay durable; pruning does not delete raw evidence by default. |
| Archivist verifies evidence | Included | Book and segment integrity checks, proof packs, restore drills, and artifact ledger verification exist. |
| Storage tiers | Included | Hot/warm/cold/vault paths plus `tier-storage` and retention config. |
| Thread recovery magic command | Included | `recover-thread`, operation recovery packets, recovery drill, restore drill, and plugin skill instructions. |
| Codex integration | Included | MCP server, local plugin, marketplace metadata, plugin-local MCP runner, and Codex skill. |
| Hermes integration | Included | Hermes plugin assets, model profiles, installer, and adapter hooks. |
| Other agent adapters | Included scaffold | Claude Code, OpenAI-compatible, OpenClaw, Ollama, Cursor, Continue, LangChain, LlamaIndex, CrewAI, AutoGen, Semantic Kernel, Haystack, Aider listed/templates. |
| MemPalace migration | Included | Importer handles drawers, closets, KG, Chroma snapshots, receipts, proof packs, and resume-state metadata. |
| Configurable hardware budgets | Included | VRAM/RAM/NVMe budgets plus `optimize-config`; no personal drive assumptions in package defaults. |
| Operation receipts while building | Included | OperationGuard writes receipts, proof packs, recovery packets, and hash-chained operation event JSONL. |
| Portable/shareable root handoff | Included | `pack-root` stages and strictly verifies a root, writes a member-hash manifest and `.sha256` receipt, and `verify-bundle` validates the completed ZIP. |
| Infinite context window | Superseded honestly | Epic Continuum does not extend transformer attention/KV cache directly. It supplies durable memory, compaction, retrieval, and reinjection so effective continuity can exceed one native context window. |
| Vector/neural recall | Superseded for first release | Deterministic FTS5 plus graph routes is the baseline. Optional embeddings can be added later without replacing the core. |
| Full event-sourced rewrite | Superseded for first release | Receipts/proofs remain stable projections; hash-chained operation events provide replayable append-only evidence where it matters most now. |
