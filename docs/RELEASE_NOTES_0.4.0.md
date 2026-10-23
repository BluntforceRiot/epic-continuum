# Epic Continuum 0.4.0 candidate

This is a candidate release description, not an assertion that publication or
live-host certification has occurred. Exact gate results belong to the final
hash-bound build receipt; [readiness](v04-readiness.md) distinguishes local
engineering proof from hosted CI and practical host/model proof.

## What changes

The reviewed slices assemble one shared, headless memory core:

- [Unified recall](unified-recall.md): cited lexical, relationship and time-aware
  evidence with explainable ranking, search/output budgets and model-free use.
- [Memory intelligence](memory-intelligence.md): explicit incremental local
  embeddings, validity/as-known fact history and corrections, and living project
  files/symbols/decisions with change propagation. Embedding quality depends on
  the already-running provider chosen by the operator.
- [Large outputs](retrieval-and-large-outputs.md) and [working context](working-context.md):
  preserve approved full results, return focused excerpts/exact reads and keep
  whole recent multimodal/tool groups. Oversized mandatory groups remain intact
  with overflow reported; token estimates are not provider-tokenizer guarantees.
- [Investigations](investigation-memory.md): binary/build/function/address/source
  anchors, supplied image-region/page/table/timestamp annotations and notebooks
  linking hypotheses, experiments, observations and conclusions.
- [Experience](experience-memory.md): unsuccessful approaches and supported
  successes, repeated-success procedure proposals, explicit review and selected
  cross-project lessons. A stored claim is not independently established truth.
- [Coordination](coordination-memory.md): claimable handoffs, atomic lease/head
  transitions, interruption recovery and progressively disclosed collections.
- [Workspaces](selected-workspaces.md): hash-bound selected capsules, explicit
  sharing, attribution, idempotent imports/forks/conflicts, fixed-snapshot replay
  and selective adoption. Imports remain inert evidence, not instructions.
- [Capability API](capability-api.md): 28 fixed actions through Python/CLI and
  separate read/write MCP dispatchers, alongside dedicated recall/index/fact/
  project commands. No arbitrary command or import dispatch is added.

## Compatibility and defaults

Python 3.11+ remains required; runtime dependencies remain empty. Existing Scroll,
Card, Library, graph, proof, recovery and bundle mechanisms are reused. No new
core schema migration is part of this candidate. Derived indexes are rebuildable;
original evidence remains authoritative. Git is not required for memory use.

New model/embedding work is opt-in against an explicit already-running local
endpoint. No cloud account, model download, daemon start, host reconnect or live
configuration edit is performed by installation alone. Existing hosts still
need their separately tested integration and explicit configuration.

All 0.3.1 fixes remain included: SQLite lock recovery for persistent workers,
accurate due-work health, preservation of historical tiered proof artifacts and
native metadata credential scanning. Credential blocking and visibility rules
are not relaxed by safe notes, export/import or new typed knowledge.

## Deliberate limits

Media annotations are caller-supplied; this candidate does not install OCR,
transcription or binary analysis tools. It does not execute learned procedures,
automatically rewrite prompts, synchronize whole conversations, add a GUI or
provide a productized evaluation service. Local actor labels are attribution,
not authentication. Concurrent writes can cause per-row partial import after
capacity preflight; explicit idempotent retry remains the recovery path.

Host-neutral context tests and synthetic engineering cases do not establish
real Hermes/Codex prompt savings, model answer quality or superiority over other
memory projects. Those claims require their own measured evidence.

## Preparing and installing

Follow [upgrade and rollback](upgrade-0.4.md). Development archives whose
provenance says allow_dirty=true are review artifacts, not final publication
artifacts. Ship only the exact reviewed clean commit after the required hosted
matrix and remaining practical gates pass. No PyPI publication is implied.
