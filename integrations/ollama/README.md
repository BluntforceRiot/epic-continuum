# Ollama Adapter

Ollama is best used through an agent shell or gateway that can call Epic
Continuum before it calls the model.

Recommended path:

```text
agent/client -> Epic Continuum OpenAI-compatible wrapper -> Ollama /v1 endpoint
```

Ollama exposes an OpenAI-compatible API on many recent installs:

```text
http://127.0.0.1:11434/v1
```

The reusable Python helper is:

```python
from continuum.integrations.openai_context_adapter import prepare_chat_request

request = prepare_chat_request(
    root="/path/to/continuum-root",
    session_id="ollama-session",
    source="ollama",
    request={
        "model": "qwen2.5-coder:latest",
        "messages": [{"role": "user", "content": "Where were we?"}],
    },
)
```

Do not put secrets or personal memory directly into an Ollama Modelfile. Keep
durable memory in Continuum and inject only the bounded Looking Glass packet per
request.
