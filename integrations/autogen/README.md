# AutoGen Adapter Template

Use Epic Continuum as shared memory between AutoGen agents.

Recommended pattern:

- append each agent turn to the Scroll with role and agent metadata
- compile context before a planning or execution turn
- roll long spans into Cards when the conversation exceeds the native model budget
- recover sessions with `recover-thread` after crashes
