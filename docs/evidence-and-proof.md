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

### POSIX restore-drill retention

Disposable restore-drill cleanup is platform-specific. Windows can delete the
reserved tree through pinned native handles. POSIX does not provide the same
portable identity-bound recursive deletion operation, and a link-count check
cannot safely authorize a later truncate because a hardlink can appear between
those operations. Continuum therefore opens POSIX drill-tree entries read-only,
recursively checks physical type, descriptor/path identity, stable metadata,
and single-link regular files, and retains every payload byte unchanged.

The receipt status `inspected_root_retained` is a successful non-destructive
postcondition, so strict `verify-root` can pass while also reporting
`drill_root_retained: true`, the retained file count, and retained byte count.
It is not a storage-cleanup claim. Repeated POSIX drills retain full copies
under `run/restore_drills`; v0.3.0 has no automatic retained-root count or byte
cap. Operators should use the receipt paths and metrics in their normal
disk-retention maintenance. Any inspection, identity, hardlink, or
final-postcondition failure remains non-successful.

### External archive for legacy catalog proofs

Older roots can contain many full `catalog.snapshot.sqlite3` proof inputs. The
legacy-proof archive workflow can move eligible, immutable copies to an external
content-addressed archive without invalidating their proof packs. It writes a
root-bound locator at `config/proof-archive.json` and a hash-chained relocation
ledger before removing each verified source copy.

Source removal is fail-closed. On Windows, Continuum deletes only through the
same native handle whose bytes and identity were verified, and that handle does
not share write access between the final hash and deletion disposition.
The containing directory is then opened with native write access and flushed
with `FlushFileBuffers`; an open, flush, or handle-close failure is surfaced as
an incomplete durability result rather than being treated as best effort.
Platforms without an equivalent identity-bound delete operation retain the
original source and return `ok: false`; the archive object and relocation record
remain available, but the source is not reported as removed.

If a verified archive copy fails, that copy or integrity error remains the
primary exception. Descriptor-close and temporary-file cleanup failures are
attempted independently and recorded as bounded exception notes rather than
replacing the failure that caused the copy to stop.

Archive results separate exact disposition from later housekeeping.
`source_removed: true` and `source_disposition_status: removed_exact_handle`
remain truthful if the verified object was deleted but quarantine-directory
cleanup or a durability flush later fails. In that case
`quarantine_cleanup_status` or `source_durability_status` reports the incomplete
step and the aggregate result remains false. Path inspection counts as absence
only when `lstat` returns `FileNotFoundError`; permission and other inspection
errors are reported rather than converted into success.

Every disposition path verifies the content-addressed destination immediately
before it can report success. This includes an already-absent source and a retry
that reuses an existing relocation record. A missing or modified destination
therefore makes both the item and aggregate archive result false, even when the
source pathname is already absent.

Every later plan and apply pass also inventories leftover
`.catalog.snapshot.sqlite3.archive-quarantine-*` entries. A surviving quarantine
appears under `retained_quarantines`, contributes to
`retained_quarantine_count`, and produces a non-successful
`retained_quarantine` result instead of an empty success. The relocation ledger
can confirm URI and content identity, but older records do not identify the
exact object moved into quarantine. A retry therefore reports and preserves the
quarantine even when every retained file has matching bytes; it does not delete
by pathname or content match alone.

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
