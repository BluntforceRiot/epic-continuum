# Release Audit Summary

This file curates the release-gate evidence for Epic Continuum `0.1.0` without
shipping the full internal build-review history.

## Scope

The release gate focused on:

- durable memory privacy and POSIX permissions;
- crash recovery, operation receipts, and proof packs;
- root bundle canonicality, portability, and semantic verification;
- secret scanning and legacy redaction;
- Codex/Hermes adapter installation behavior;
- Debian/Ubuntu/Windows portability.

## Current Gate

The core test suite passed on Windows and Linux during release-candidate review.
Disposable Debian 12 and Debian 13 validation both completed with the same
passing test count as the local suite.

Review hardening after the final private review pass added:

- private directory/file modes and a `repair-permissions` command;
- Hermes secret-key handling that avoids subprocess argv;
- hard `max_tool_result_bytes` enforcement;
- healthy-degraded FTS5 fallback reporting;
- the unique Codex marketplace namespace `epic-continuum`;
- explicit MCP tool annotations;
- curated source/release package contents.

## Remaining Security Boundary

Epic Continuum is local-first, not encrypted-at-rest software. Operators should
use filesystem or disk encryption for sensitive roots and should run
`continuum doctor` before publishing or handing off a root bundle.
