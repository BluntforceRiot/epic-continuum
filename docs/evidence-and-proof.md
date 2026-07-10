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

By default, a proof that touches the live SQLite catalog records a bounded
`catalog.state.json` telemetry artifact instead of copying the entire database.
It records the operation id, catalog/schema metadata, table row-id high-water
marks, SQLite page metadata, and a canonical hash of that telemetry document.
It is explicitly **not** a restorable database snapshot, and its state hash does
not bind the full SQLite catalog bytes.

Set `epic_continuity.catalog_proof_mode` to `snapshot`, or pass the equivalent
explicit core API option, when an operation needs a complete immutable SQLite
backup. Snapshot mode retains the previous `catalog.snapshot.sqlite3` proof
artifact behavior. Use it for migrations, destructive maintenance, imports, and
release or disaster-recovery checkpoints rather than every routine event append.
Existing snapshot-backed proof packs remain valid and verify unchanged.
Operators should keep periodic explicit snapshots even when routine operations
use state-manifest mode.

Applied pruning and legacy-secret redaction force snapshot proof mode through
both CLI and MCP entry points. MemPalace import already creates a dedicated full
catalog backup and binds it into the import proof. Routine append, worker, and
reindex operations keep bounded telemetry unless a caller explicitly overrides
the policy.

The default state-witness mode prevents proof storage from growing by one full
catalog copy for every mutation. Full integrity and restore claims still belong
to `verify-root`, explicit snapshots, restore drills, and verified root bundles.

### External archive for legacy catalog proofs

Older roots can contain many full `catalog.snapshot.sqlite3` proof inputs. The
legacy-proof archive workflow can move eligible, immutable copies to an external
content-addressed archive without invalidating their proof packs. It writes a
root-bound locator at `config/proof-archive.json` and a hash-chained relocation
ledger before removing each verified source copy.

Verification still evaluates the original root-relative proof URI first. If and
only if that exact legacy catalog proof is absent, the verifier may follow the
configured locator. It validates the root binding, archive manifest, complete
relocation chain, expected SHA-256, and expected byte size before accepting the
external object. External paths are never added to the verifier's general
allowed-root set, and unrelated missing evidence is not redirected. Locator,
ledger, or object tampering therefore fails closed in proof-pack, artifact-ledger,
doctor, and root verification.

Keep the external archive with the root's recovery material. Moving or deleting
it makes relocated legacy proof inputs unavailable; restoring one proof input
copies it back while retaining the external object.

## Portability

Portable bundle checks guard against unsafe archive names, hidden bytes, unsupported symlink policy, path leakage, case collisions, malformed JSON, and other handoff hazards.

The intent is not only to zip a directory. The intent is to create a handoff artifact that can be verified elsewhere.
