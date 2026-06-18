# OpenClaw Adapter

OpenClaw is treated as a mission-card consumer, not as a normal chat plugin.

Generic OpenClaw-style systems can ask Epic Continuum for a Looking Glass packet
through MCP, then wrap that packet as a mission card with:

```python
from continuum.integrations.openclaw_adapter import build_openclaw_mission_card

card = build_openclaw_mission_card(
    "/path/to/continuum-root",
    session_id="example",
    query="Recover the current project context",
)
```

The card shape follows the local doctrine:

- decision
- evidence
- next_action
- owner
- gate
- proof_boundary

## OpenClaw Note

OpenClaw installs can vary widely. Keep the Continuum adapter advisory unless
the operator explicitly asks to wire OpenClaw into live execution.

For this repo, the OpenClaw adapter therefore exports context and proof language.
It does not start services, mutate OpenClaw config, or assume credentials.
