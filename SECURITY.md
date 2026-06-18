# Security Policy

Epic Continuum is local-first memory software. It stores conversation history,
tool evidence, imports, operation receipts, snapshots, and proof artifacts under
the configured Continuum root.

## Supported Version

Security fixes target the current `0.1.x` release line.

## Reporting A Vulnerability

Before a public issue, contact the maintainer privately through the repository
owner profile or the GitHub security advisory flow once enabled. Include:

- the affected version or commit;
- the operating system and Python version;
- exact commands or API calls that reproduce the issue;
- whether the issue exposes private memory, secrets, filesystem paths, or
  cross-root data.

## Local Storage Boundary

On POSIX systems, Epic Continuum creates private directories as `0700` and
sensitive files as `0600`. Run:

```bash
continuum doctor --root "$CONTINUUM_ROOT"
continuum repair-permissions --root "$CONTINUUM_ROOT"
```

to detect and repair unsafe modes.

The store is not encrypted at rest. Use full-disk encryption, an encrypted
filesystem, or an encrypted container for roots that contain sensitive material.

## Secret Handling

Secret-bearing captured text is blocked by default. Redaction and audit commands
exist for legacy state, but operators should still avoid routing credentials,
private keys, or cloud tokens through prompts, tool results, or adapter config.

Hermes integration does not pass real API keys to subprocess argv. Prefer
environment-variable or protected secret-store flows for any model provider key.
