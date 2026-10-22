# Epic Continuum 0.3.1

A maintenance release containing reviewed worker, memory-health, proof-file
preservation and metadata credential-scanning repairs. No private downstream
agent features, new model requirements or memory migration are included.

## Changes

- The persistent worker waits out SQLite BUSY/LOCKED contention using 5, 10,
  20, 40, then at most 60 seconds between retries. It preserves normal job
  ownership, retry ordering and deduplication. Non-lock failures are not hidden.
- Health reports distinguish ordinary short session tails from overdue
  segmentation and uncovered historical gaps.
- Tiering retains historical files bound by immutable artifact records while
  updating current Book storage locations.
- Metadata strings and keys are checked before JSON escaping. Credential
  blocking stays enabled by the existing policy; harmless helper instructions
  remain valid memory. JSON/JSONL audit locations stay accurate.
- A timing-sensitive deadline test is deterministic without relaxing the
  production deadline contract or removing real transport coverage.

## Upgrade and verification

Use the normal source, wheel, or source-distribution installation route. This
release does not change the memory schema or automatically edit host service
registration. Restart/reconnect your own Continuum processes after an upgrade
to load the new code. No model restart or configuration change is required.

These fixes do not reconstruct missing historical snapshots or certify an
existing root's backup integrity. Keep normal backups and use the existing
verification tools for your root.

The distribution manifest and SHA256SUMS identify the exact source ZIP, wheel
and sdist. A prepared local candidate is not evidence of a published release
or a new successful GitHub CI run.
