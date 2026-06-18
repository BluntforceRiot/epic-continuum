# Semantic Kernel Adapter Template

Map Epic Continuum operations to plugin functions:

- `status(root)`
- `append_event(root, session_id, role, content)`
- `compile_context(root, session_id, query, token_budget)`
- `recover_thread(root, session_id)`

Use Continuum for durable storage and let Semantic Kernel remain the orchestration
surface.
