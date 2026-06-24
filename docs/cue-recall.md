# Cue Recall

Cue Recall is Epic Continuum's buried-idea recovery path.

Normal search asks for exact words. Cue Recall is for the messier human request:

```text
remember that local-agent upgrade idea?
the fake big context thing we talked about
that approach where another agent could pick up the work
```

The goal is not to pretend the system is certain when it is not. The goal is to return likely idea clusters with evidence, related terms, and enough context for an agent or human to recognize the right thread.

## Architecture

Cue Recall follows the original Continuum memory design:

- **Scroll:** preserves the exact prompt, response, tool result, or project-state event.
- **Scribe:** extracts useful terms and phrases from new events without deleting the raw event.
- **Librarian:** builds and traverses the association graph, then ranks likely memories.
- **Archivist:** decays weak/noisy routes while preserving raw evidence and protected memories.
- **Constellation:** stores terms, events, Cards, projects, agents, and their associations.

The system intentionally does not correlate every word equally. Common filler words are ignored, saturated words are damped, and distinctive terms are treated as stronger anchors.

## Exact Memory

When a user says `remember this exactly`, the raw Scroll event is still preserved, and Continuum also creates a protected high-salience `exact_memory` Card. That Card is not a replacement for the raw event; it is a recall object pointing back to the evidence.

Example:

```bash
continuum append-event \
  --root ./.continuum-demo \
  --session-id demo \
  --role user \
  --content "Remember this exactly: the local agent should use vLLM, not Ollama."
```

Generic MCP append calls are evidence capture, not user-approval channels. They
cannot mint protected exact-memory Cards merely by supplying metadata or omitting
the role.

## Associative Recall

Cue Recall starts with the user's cue, extracts important terms, finds matching graph nodes, expands through active associations, and returns ranked candidate memories.

```bash
continuum cue-recall \
  --root ./.continuum-demo \
  --cue "that fake big context upgrade idea" \
  --project-id local-agent-v2
```

The result includes:

- original cue terms;
- related terms discovered through associations;
- ranked candidate Cards, Scroll events, and Library snippets;
- reasons each candidate was found;
- session or project scope when available;
- a reminder that candidates are evidence trails, not automatic truth claims.

## Pruning Policy

Pruning should not mean "rare ideas disappear."

Continuum should:

- ignore filler terms such as `the`, `and`, `you`, and `want`;
- damp generic terms such as `file`, `code`, `project`, and `context`;
- preserve distinctive terms such as model names, paths, tools, repos, and unusual phrases;
- protect explicit exact memories;
- strengthen routes when retrieval/review workflows explicitly reinforce useful Cards or maintenance workers update route use;
- decay weak, noisy, stale routes;
- preserve raw Scroll and Library evidence even when graph routes decay.

This makes Cue Recall closer to "help me find the thought we lost" than "search these exact words."

The `cue-recall` command itself is intentionally read-only. It returns candidate evidence trails. It does not silently rewrite the graph just because a vague query happened to match.
