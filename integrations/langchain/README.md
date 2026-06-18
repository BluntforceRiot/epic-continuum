# LangChain Adapter Template

Use Epic Continuum as durable memory, not as another transient prompt buffer.

Suggested mapping:

- `append-event` records user, assistant, and tool turns.
- `compile-context` returns a Looking Glass packet before model calls.
- `recover-thread` returns a crash-recovery packet for resumed chains.

The OpenAI-compatible helper in `continuum.integrations.openai_context_adapter`
is the fastest path for LangChain apps that already call a chat model.
