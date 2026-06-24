# Context Window Behavior

A model's native context window is finite. Epic Continuum does not change that internal limit. It builds a bounded external memory packet so the model sees the most useful durable context for the current turn.

## Context Reconstruction Pipeline

The intended pipeline is:

1. Receive the session, task, query, and token budget.
2. Gather candidate memory from recent Scroll events, Cards, Library search, Cue Recall associations, active operation state, and related project checkpoints where available.
3. Apply visibility, project/session scope, relevance, recency, salience, and review metadata.
4. Rank and filter candidates.
5. Assemble a Looking Glass packet within the configured budget.
6. Return estimated token use, remaining budget, sections, and truncation metadata.

The model sees the packet, not the whole memory root.

## Budget Rule

Context compilation must not silently exceed the requested budget. If material cannot fit, the compiler should exclude it or truncate it with explicit metadata.

The current core compiler reports:

- requested and usable token budgets;
- estimated tokens used;
- remaining budget;
- section count;
- truncation status;
- truncated item metadata.

## Current Implementation Notes

The current `compile-context` command emphasizes recent Scroll events and matching Cards. It enforces visibility and project/session scope, then ranks direct text matches by relevance, recency, and salience. Library evidence is available through `search`, loose associative recall is available through `cue-recall`, and shared handoff checkpoints are available through project-state Cards.

This distinction matters for accurate public claims:

- `compile-context` builds the direct Looking Glass packet.
- `search` retrieves Library chunks and source evidence.
- `cue-recall` searches associative routes for vague prompts and returns ranked candidates.
- `recover-thread` gathers recent events, Cards, recent books, pending jobs, and a resume instruction.

Future planner work can make Library and graph expansion more deeply integrated into direct context compilation.

## Why Not Replay Everything?

Full transcript replay can be useful for small jobs, but it breaks down as projects grow:

- the transcript may exceed the model window;
- irrelevant detail competes with current evidence;
- old mistakes can be reintroduced;
- the user may not have the transcript after a crash or handoff;
- replay cost grows with every turn.

Continuum keeps the durable record outside the prompt and reconstructs a smaller working set when needed.
