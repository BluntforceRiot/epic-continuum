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
- Debian/Ubuntu/Windows portability;
- release package reproducibility and installer wrapper safety.

## Current Gate

The core test suite passed on Windows and Linux during release-candidate review.
Disposable Debian 12 and Debian 13 validation both completed with the same
passing test count as the local suite.

Review hardening after the final private review pass added:

- private directory/file modes and a `repair-permissions` command;
- Hermes secret-key handling that avoids subprocess argv;
- direct Hermes CLI rejection for secret-looking `--api-key` values;
- hard `max_tool_result_bytes` enforcement;
- healthy-degraded FTS5 fallback reporting;
- the unique Codex marketplace namespace `epic-continuum`;
- explicit MCP tool annotations;
- curated source/release package contents.
- bundle Zip64 threshold and central/local header canonicality hardening;
- portable bundle refusal for link-like catalog databases;
- manifest member mode binding;
- release builder refusal for tracked dirty-tree builds;
- safe Codex plugin staging under a generated child directory;
- BOM-less generated Codex `.mcp.json` files;
- Codex plugin cachebuster versions for generated local stages.
- root-confined configurable paths and portable operation identifiers;
- cross-thread and cross-process operation-ledger serialization;
- immutable public ledger APIs after proof publication;
- private secret-redacted adapter and bootstrap diagnostic logs;
- absolute tool-result byte caps and true no-event skip semantics;
- portable recovery packets and bounded recovery filenames;
- link-safe release assembly and coherent portable symlink-skip behavior.

See `MAINTAINABILITY_HOTSPOTS.md` for the non-blocking large-function
refactor map identified during release review.

## Remaining Security Boundary

Epic Continuum is local-first, not encrypted-at-rest software. Operators should
use filesystem or disk encryption for sensitive roots and should run
`continuum doctor` before publishing or handing off a root bundle.
