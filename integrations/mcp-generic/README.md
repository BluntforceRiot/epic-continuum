# Generic MCP Adapter

Epic Continuum's lowest-friction integration surface is its stdio MCP server:

```bash
CONTINUUM_ROOT=/path/to/continuum-root \
PYTHONPATH=/path/to/continuum/src \
python -m continuum.mcp_server
```

Use this with MCP-capable clients such as Claude Desktop, Cursor, Windsurf, and
other editor or desktop agents.

Minimal MCP config shape:

```json
{
  "mcpServers": {
    "continuum": {
      "command": "python",
      "args": ["-m", "continuum.mcp_server"],
      "env": {
        "CONTINUUM_ROOT": "/path/to/continuum-root",
        "PYTHONPATH": "/path/to/continuum/src"
      }
    }
  }
}
```

The MCP tool surface is the contract. Adapter-specific plugins should stay thin.
