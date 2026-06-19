# Maintainability Hotspots

This audit records the large workflow functions reviewers flagged during the
release-readiness pass. They are not release blockers for `0.1.0` because the
current behavior is covered by regression tests and package smoke tests, but
they are the first refactor targets after the release boundary.

## Hotspots

- `src/continuum/cli.py:build_parser`
  - Split by command family: core root commands, context/search commands,
    worker/maintenance commands, verification/bundle commands, integration
    commands.
- `src/continuum/cli.py:_main`
  - Split into command handlers that return result dictionaries plus exit
    codes through the shared `emit_result` path.
- `src/continuum/core/mempalace_import.py:_import_mempalace_locked`
  - Split into source discovery, snapshot/open, drawer import, closet import,
    KG import, receipt finalization, and resume-state phases.
- `src/continuum/core/bundle.py:_zip_envelope_errors`
  - Split into EOCD parsing, Zip64 locator validation, central directory
    validation, local header validation, and member metadata comparison.
- `src/continuum/core/bundle.py:verify_root_bundle`
  - Split into archive safety, manifest loading, member hash checks,
    embedded-root verification, and portable metadata audit phases.
- `src/continuum/core/bundle.py:pack_root`
  - Split into preflight policy checks, staging, staged verification, manifest
    generation, archive write, publication, and final verification phases.
- `src/continuum/core/store.py:audit_secrets`
  - Split into candidate discovery, file scanning, SQLite scanning,
    allowlist matching, truncation/incomplete accounting, and SARIF projection.
- `src/continuum/core/store.py:ingest_file`
  - Split into source normalization, digest/reader edition write, chunking,
    card creation, queueing, and proof artifact registration.

## Release Gate

The release gate for these hotspots is regression coverage, not immediate
rewrites. Broad refactors must keep:

- Windows, Linux, and package-extracted tests passing.
- Bundle hash and envelope invariants unchanged unless the manifest version
  changes.
- Operation receipts and proof packs backward-readable.
- No new external dependencies for core workflows.

