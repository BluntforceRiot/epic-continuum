# LlamaIndex Adapter Template

Treat Epic Continuum as a persistent memory source that can produce compact
context packets and recovery packets.

Suggested mapping:

- Use MCP or CLI `compile-context` as a retriever-like preprocessor.
- Use `ingest-file` for durable Library books.
- Use `recover-thread` for session restoration.

Keep large source documents in Continuum's Library and pass only bounded Looking
Glass context into LlamaIndex prompts.
