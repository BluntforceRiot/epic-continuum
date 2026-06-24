# How Epic Continuum Memory Works

Epic Continuum stores durable memory outside the model. The model receives a bounded packet for the current turn, while the complete memory root remains on disk for future recall, inspection, and recovery.

## Memory Layers

### Scroll

The Scroll is the ordered event history. It records user messages, assistant messages, tool activity, and operation events with sequence numbers, timestamps, hashes, token estimates, and metadata.

The Scroll answers:

- What happened?
- In what order?
- Which session did it belong to?
- What was the raw local evidence?

### Cards

Cards are compact durable meaning extracted from older work. They can record summaries, decisions, open tasks, topics, entities, salience, confidence, and source references.

Cards answer:

- What mattered?
- Which decisions remain relevant?
- Which tasks are open?
- Which older material should be recalled quickly?

Cards do not replace raw evidence. They point back to source material.

### Library

The Library preserves files and imported material. It stores originals, reader editions, chunks, hashes, provenance, and storage-tier metadata.

The Library answers:

- Where is the source evidence?
- What file or artifact supports a claim?
- Which chunks match a search query?

### Constellation

The Constellation is the association layer. Cards, Scroll events, project checkpoints, agents, and extracted terms can be connected through weighted relationships. Useful routes can be reinforced by recall. Stale routes can decay and eventually be pruned.

This is the practical version of the original neural inspiration: memory paths that are repeatedly useful become easier to traverse, while unused associations become less prominent. The preserved evidence remains intact even if a route weakens.

Cue Recall uses this layer for loose memory search. The Scroll keeps the exact prompt. The Scribe extracts useful terms while dampening common filler. The Librarian traverses nearby associations and returns candidate memories with evidence trails. The Archivist can later decay or prune weak routes without deleting the underlying event or source material.

### Looking Glass

The Looking Glass is the selected memory packet for the next model call. It is bounded by the configured token budget and should report truncation or exclusion instead of silently exceeding that budget.

The Looking Glass answers:

- What should the model see now?
- Which recent events, Cards, and evidence are relevant to the current task?
- How much context budget remains?

## Evidence Versus Recall

Epic Continuum intentionally separates raw evidence from recall objects.

| Layer | Purpose | Durable source of truth? |
|---|---|---|
| Scroll | Ordered activity | Yes |
| Library | Source files and chunks | Yes |
| Cards | Compact recall | No, but source-linked |
| Constellation | Associations | No, routing only |
| Looking Glass | Current model packet | No, generated view |
| Receipts/proofs | Operation evidence | Yes |

This separation lets the system compact and rank memory without destroying the underlying record.

## Synaptic Pruning In Practice

Epic Continuum does not modify model weights. Its pruning is external memory maintenance.

The association graph can track route use, route decay, and route status. A route that is repeatedly used may become stronger. A route that stops helping can decay. A decayed route can be marked inactive or pruned while the underlying Scroll events, Cards, and Library evidence remain available.

The goal is brain-like recall behavior without pretending the memory store is a biological brain or a neural model.

Very common terms are intentionally dampened so they do not dominate recall. Rare but important associations are preserved through source-linked Cards, Scroll references, and protected exact-memory Cards when a user explicitly asks to remember something exactly.
