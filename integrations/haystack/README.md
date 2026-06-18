# Haystack Adapter Template

Use Epic Continuum as a memory component that returns a bounded context packet
before generation.

Recommended flow:

```text
query -> Continuum compile-context -> prompt builder -> generator
```

Use `ingest-file` for durable source evidence and `recover-thread` for crash
recovery.
