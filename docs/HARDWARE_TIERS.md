# Hardware Tiers And Budgets

Epic Continuum separates active model attention, hot operational cache, and durable
memory. Each tier has a different job, failure mode, and budget unit. The
system should remain useful on modest local hardware while scaling cleanly on a
workstation or home server.

## Tier Roles

| Tier | Primary job | Epic Continuum data | Pressure response |
| --- | --- | --- | --- |
| VRAM | Active model pane and KV runtime | Looking Glass tokens, runtime KV/session cache, request-local retrieval pack | Shrink active pane, reduce recall pack size, evict runtime cache |
| System RAM | Hot rebuildable cache | recent Scroll spans, hot Cards, queue state, graph neighborhoods, reader edition pages | Evict least-useful cache entries, flush queues, reload from NVMe on demand |
| NVMe | Durable memory substrate | Scroll database, Library originals, reader editions, Constellation graph, snapshots, exports | Move books across hot/warm/cold/vault layouts, compact indexes, require retention policy |

VRAM is the scarce attention-adjacent tier. It should be reserved for the model
runtime, the current Looking Glass, and any KV/session cache needed to continue
the active request. It is not the archive.

System RAM is the hot working tier. It should make recent work fast, but all RAM
state must be reconstructable from durable records. Losing a RAM cache should
cost time, not evidence.

NVMe is the durable tier. The Scroll, Library, Graph, queues, snapshots, and
exports must be recoverable from NVMe records and audit events. Storage tiering
changes where evidence lives; it must not remove the catalog trail that makes
evidence findable.

## Machine Profiles

These profiles are guidance for sizing budgets, not product limits.

| Profile | VRAM | System RAM | NVMe | Expected use |
| --- | ---: | ---: | ---: | --- |
| Local laptop | 8 GB to 12 GB | 32 GB | 512 GB to 1,024 GB | focused single-agent sessions, small Library |
| Workstation | 16 GB to 24 GB | 64 GB to 128 GB | 1,024 GB to 4,096 GB | long project threads, larger Card and reader caches |
| Home server | 24 GB to 48 GB | 128 GB to 256 GB | 2,048 GB to 8,192 GB | shared agent memory, frequent snapshots, broad Library |

## Config Budget Units

Configuration fields that represent byte-like capacity keep stable names, and
the value carries the unit. Public examples should use one of these units:

- `KB` for small payloads, chunk targets, row limits, and card bodies.
- `MB` for hot caches, queue buffers, recall packs, and temporary workspaces.
- `GB` for durable stores, snapshot pools, Library tiers, and runtime KV cache.
- `TB` for large durable store or snapshot budgets.

A config review should be able to see the intended magnitude without reading
implementation code, but scripts should not need to learn a new key name when a
budget moves from MB to GB.

The parser can accept raw byte values for generated config, but human-facing
docs should prefer unit-bearing strings.

Example budget shape:

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

Token budgets are still allowed for model-facing context decisions, but they
should sit beside byte budgets rather than replace them. For example, a Looking
Glass compiler can enforce both `active_token_budget` and
`active_pane_budget`.

## Operating Rules

- VRAM pressure changes the active view; it must not delete durable memory.
- RAM pressure evicts rebuildable caches; it must not orphan queued work.
- NVMe pressure invokes retention and tiering policy; it must not erase evidence
  outside an explicit user-approved deletion flow.
- Catalog Cards stay hot enough to route retrieval even when Books move to
  colder Library tiers.
- Snapshot budgets must account for the Scroll, Library catalog, Graph, queue
  journals, and enough manifests to prove restore integrity.
