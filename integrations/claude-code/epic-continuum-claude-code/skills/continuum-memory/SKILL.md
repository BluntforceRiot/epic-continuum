---
name: continuum-memory
description: Use Epic Continuum from Claude Code for persistent memory, Looking Glass context, crash recovery, operation receipts, and session handoff.
---

# Epic Continuum Memory

Epic Continuum is a local persistent-memory substrate. Prefer the bundled MCP
tools when available:

- `continuum_status`
- `continuum_append_event`
- `continuum_compile_context`
- `continuum_recover_thread`
- `continuum_list_operations`
- `continuum_recover_operations`
- `continuum_recovery_drill`

If MCP is unavailable, use the CLI:

```bash
python -m continuum status --root "$CONTINUUM_ROOT"
python -m continuum recover-thread --root "$CONTINUUM_ROOT" --session-id "<session>"
```

Treat the Scroll as the ordered evidence source. Cards and recovery packets are
compact views over that evidence, not replacements for it.
