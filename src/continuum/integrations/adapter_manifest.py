from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AdapterEntry:
    name: str
    path: str
    surface: str
    status: str
    notes: str


ADAPTERS: tuple[AdapterEntry, ...] = (
    AdapterEntry("Codex", "plugins/continuum", "Codex plugin + stdio MCP", "packaged", "Current working adapter."),
    AdapterEntry("Hermes Agent", "integrations/hermes", "Hermes plugin hooks", "packaged", "Records turns and injects Looking Glass context."),
    AdapterEntry("Claude Code", "integrations/claude-code", "Claude Code plugin + MCP + hooks", "packaged", "Uses UserPromptSubmit, SessionStart, and Stop hooks."),
    AdapterEntry("Claude Desktop", "integrations/mcp-generic", "stdio MCP config", "template", "Uses the generic MCP server config."),
    AdapterEntry("Cursor", "integrations/mcp-generic", "stdio MCP config", "template", "Use as an MCP memory server from the IDE."),
    AdapterEntry("Windsurf", "integrations/mcp-generic", "stdio MCP config", "template", "Use as an MCP memory server from the IDE."),
    AdapterEntry("Continue.dev", "integrations/openai-compatible", "context gateway pattern", "template", "Best through an OpenAI-compatible gateway or MCP tool call."),
    AdapterEntry("OpenClaw", "integrations/openclaw", "MCP + mission card handoff", "packaged", "Maps context to OpenClaw decision/evidence/gate cards."),
    AdapterEntry("Ollama", "integrations/ollama", "OpenAI-compatible wrapper + Modelfile guidance", "packaged", "Best used through an agent or gateway."),
    AdapterEntry("OpenAI-compatible runtimes", "integrations/openai-compatible", "request wrapper", "packaged", "For vLLM, LM Studio, llama.cpp server, LocalAI, and similar endpoints."),
    AdapterEntry("LangChain", "integrations/langchain", "retriever/memory shim", "template", "Uses the CLI/MCP surface as the durable store."),
    AdapterEntry("LlamaIndex", "integrations/llamaindex", "query engine/memory shim", "template", "Treats Continuum context as a retrievable pack."),
    AdapterEntry("CrewAI", "integrations/crewai", "tool adapter", "template", "Expose recover/context/append as crew tools."),
    AdapterEntry("AutoGen", "integrations/autogen", "tool adapter", "template", "Expose Continuum as a shared agent memory tool."),
    AdapterEntry("Semantic Kernel", "integrations/semantic-kernel", "memory/plugin template", "template", "Map compile-context and append-event to SK functions."),
    AdapterEntry("Haystack", "integrations/haystack", "component template", "template", "Use Continuum as a durable memory component."),
    AdapterEntry("Aider", "integrations/mcp-generic", "MCP/CLI recovery pattern", "template", "Use CLI recovery packets and optional MCP where available."),
)


def adapter_index() -> list[dict[str, str]]:
    return [entry.__dict__.copy() for entry in ADAPTERS]
