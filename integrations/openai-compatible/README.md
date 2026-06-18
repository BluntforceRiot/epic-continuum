# OpenAI-Compatible Adapter

This adapter is for clients that can send chat completions to an OpenAI-shaped
endpoint: vLLM, LM Studio, llama.cpp server, LocalAI, Ollama, and similar local
or cloud gateways.

The adapter does not own the model. It prepares the request:

1. record the latest user message to the Scroll
2. compile a token-bounded Looking Glass packet
3. attach that packet to the request as non-authoritative memory context
4. let the caller send the request to its normal model endpoint
5. record the assistant response after the model returns

If the request already has a system message, Continuum appends the memory packet
to that existing message instead of prepending a second system message. The packet
explicitly says current user/developer/system instructions win over stale memory.

Python helper:

```python
from continuum.integrations.openai_context_adapter import (
    prepare_chat_request,
    record_chat_response,
)
```

This is the cleanest route for a Neuroforge direct gateway because it keeps Epic
Continuum model-neutral while letting Qwen, Llama, Mistral, or any future model
remain behind a normal OpenAI-compatible endpoint.
