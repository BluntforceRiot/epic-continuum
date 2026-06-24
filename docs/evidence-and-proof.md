# Evidence And Proof

Epic Continuum keeps evidence separate from model output. Retrieved text and imported material are local evidence, not automatically trusted instruction.

## Local Storage

The memory root stores Scroll events, catalog data, Library material, snapshots, receipts, proof packs, and exports. The store is local-first and does not require a hosted service.

Epic Continuum does not provide built-in encryption at rest. Use disk, volume, or filesystem encryption when the stored evidence is sensitive.

## Secret Scanning

Secret scanning is heuristic. It can catch obvious secret-like strings, but it is not a formal data-loss-prevention system.

Before sharing a root or bundle:

```bash
continuum audit-secrets --root <continuum-root>
continuum verify-root --root <continuum-root>
```

Shareable bundles apply stricter checks than ordinary local roots.

## Proof Packs

Proof packs record hashes for selected operation artifacts and receipts. They are meant to answer:

- Which files were touched?
- What did they hash to?
- Was the proof input frozen before hashing?
- Does verification still pass?

Live SQLite databases are backed up before proof hashing where needed so mutable WAL behavior does not produce unstable proof material.

## Portability

Portable bundle checks guard against unsafe archive names, hidden bytes, unsupported symlink policy, path leakage, case collisions, malformed JSON, and other handoff hazards.

The intent is not only to zip a directory. The intent is to create a handoff artifact that can be verified elsewhere.
