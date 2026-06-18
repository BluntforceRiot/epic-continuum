# 0004: Hardware Budgets

## Status

Accepted

## Context

Epic Continuum is meant to run on very different machines: a compact home server, a
normal desktop, a GPU workstation, or a larger local server. The memory system
should not hard-code one user's hardware profile.

The system also needs to be honest about what belongs in each memory tier.
Epic Continuum can help with context continuity, retrieval, compaction, and durable
state, but it should not pretend that VRAM is long-term memory.

## Decision

Epic Continuum uses explicit hardware budgets in `config/continuum.config.json`.
Budget fields keep stable names, and the value carries the unit.

Supported size examples:

```text
512KB
128MB
4GB
1TB
1048576
```

Unit-bearing strings are preferred for human-authored config. Raw byte values
are accepted for generated config where the unit is already known.

The default profile is:

```json
{
  "hardware": {
    "vram": {
      "active_pane_budget": "8GB"
    },
    "system_ram": {
      "hot_cache_budget": "4GB",
      "sqlite_cache_budget": "512MB",
      "kv_offload_budget": "16GB"
    },
    "nvme": {
      "durable_store_budget": "256GB",
      "snapshot_budget": "64GB",
      "segment_target_size": "16MB"
    }
  }
}
```

## Tier Responsibilities

VRAM is a runtime budget for the model's active pane, KV cache, and any
model-side acceleration. Epic Continuum does not treat VRAM as durable storage.

System RAM is the hot working area. It can hold recent retrieval results,
ranking state, SQLite cache, local embeddings, and optional model/runtime
offload buffers. It is fast but disposable.

NVMe storage is the durable institution. The configured root holds the Scroll,
Library, Cards, Graph, queues, audit log, snapshots, reader editions, and
originals.

## Consequences

Portable installs can ship with a conservative config, then users can tune the
budgets without changing code.

The `optimize-config` command can detect GPU VRAM, system RAM, and root drive
free space, then preview or write recommended budgets. It uses conservative
headroom by default, and accepts manual overrides when hardware detection is not
available.

The Archivist should enforce storage pressure policies. The Librarian should
choose what stays hot in RAM-level indexes and caches. The model runtime should
respect the active pane and KV/offload hints.

Evidence must remain durable even when hot caches are evicted or graph routes
decay.
