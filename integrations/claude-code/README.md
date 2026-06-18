# Claude Code Adapter

Epic Continuum ships a Claude Code plugin skeleton at:

```text
integrations/claude-code/epic-continuum-claude-code
```

It provides:

- a plugin manifest
- a stdio MCP server definition for `python -m continuum.mcp_server`
- hook wiring for `SessionStart`, `UserPromptSubmit`, and `Stop`
- a Claude Code skill that explains the recovery pattern

Before enabling it, make sure the environment has:

```bash
export CONTINUUM_ROOT=/path/to/continuum-root
export CONTINUUM_PYTHONPATH=/path/to/continuum/src
```

Windows example:

```powershell
$env:REPO_ROOT = "$PWD"
$env:CONTINUUM_ROOT = "$HOME\.continuum"
$env:CONTINUUM_PYTHONPATH = "$env:REPO_ROOT\src"
```

Claude Code hook support is intentionally light. The durable integration surface
is still the MCP server; hooks only capture turns and add Looking Glass context.

References checked while building this adapter:

- Claude Code hooks support `SessionStart`, `UserPromptSubmit`, and `Stop` hook events with `additionalContext`.
- Claude Code plugins can bundle MCP server definitions in `.mcp.json`.
