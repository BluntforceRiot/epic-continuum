# Adapter Kit

Epic Continuum is designed as a memory substrate with thin adapters around it.
The core contract is:

```text
append event -> compile context -> call model/agent -> append response
```

Top integration targets currently included:

1. Codex
2. Hermes Agent
3. Claude Code
4. Claude Desktop
5. Cursor
6. Windsurf
7. Continue.dev
8. OpenClaw
9. Ollama
10. OpenAI-compatible runtimes
11. LangChain
12. LlamaIndex
13. CrewAI
14. AutoGen
15. Semantic Kernel
16. Haystack
17. Aider

The list is intentionally a little wider than 15 because several clients share
the same generic MCP or OpenAI-compatible adapter.

## Integration Classes

Native adapters:

- Codex plugin and MCP server
- Hermes Agent hook plugin
- Claude Code plugin skeleton with hooks and MCP

Provider/runtime adapters:

- OpenAI-compatible request wrapper
- Ollama guidance through the OpenAI-compatible route

Framework templates:

- LangChain
- LlamaIndex
- CrewAI
- AutoGen
- Semantic Kernel
- Haystack

Generic MCP clients:

- Claude Desktop
- Cursor
- Windsurf
- Aider and other tool shells where MCP or CLI calls are available

OpenClaw installs can vary widely, so Epic Continuum exports an advisory
mission-card bridge instead of assuming a universal OpenClaw plugin API.
