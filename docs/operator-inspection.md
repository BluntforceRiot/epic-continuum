# Read-only operator inspection

`continuum.core.inspection.inspect_runtime(root, *, hermes_adapter_config=None,
codex_mcp_config=None)` returns a compact JSON-compatible report for one explicit
root. It does not select a default root, initialize a missing root, run workers,
change configuration, install software, or call a model or external service.

```python
from pathlib import Path
from continuum.core.inspection import inspect_runtime

report = inspect_runtime(Path("/explicit/continuum-root"))
```

The active package version, imported module location, and Python executable
identify the inspecting process. Separately reported distribution metadata can
describe a different installation when a source checkout shadows an installed
package. It is not substituted for the active module's version.

## Reading queue and worker facts

The mutually exclusive counts use the existing queue authority:

| Report count | Catalog rows |
| --- | --- |
| `pending` | `pending`, with `retry_pending = 0` |
| `retrying` | `pending`, with `retry_pending = 1` |
| `running` | `running`, including running retry attempts |
| `failed` | `failed` |
| `completed` | `succeeded` |
| `skipped` | `skipped`; not silently called a successful completion |
| `unknown` | Unknown statuses or invalid retry markers |

`running_retry_jobs` is a subset of `running`, not an additional count. The
retry-order invariant is checked on observed rows. Required missing columns
make queue counts unavailable (`null`), not zero. This narrow shape check does
not certify all migration markers, triggers, or the rest of the schema.

Worker facts report recorded running-job heartbeats and successful completion
timestamps. Missing owners, missing/expired leases, and invalid/future running
heartbeats are flagged. Timestamp comparisons use timezone-aware UTC values;
future or malformed waiting/completion times do not become evidence of recent
progress. Waiting age describes only valid timestamps when the timestamp warning
is present. A terminal row's heartbeat is never called a running-job heartbeat.

One observation cannot prove a service is running, prove jobs are progressing,
or show that a deployment is healthy. `service_liveness` is always `not_checked`
and a progress delta is `not_measured`. `ok` means catalog/queue facts could be
read; consult `health` and `warnings` separately. An empty queue is not a service
health certificate. A historical failed row remains visible even after other
work succeeds.

## Dry-run connection and upgrade facts

Only explicitly supplied connection files are read. Supported forms are Hermes'
`continuum_adapter.local.json`, Codex JSON `mcpServers.continuum`, and Codex TOML
`mcp_servers.continuum`. Files are bounded to 256 KiB. No default Hermes or Codex
home is discovered, and no configured command is executed.

The report compares declared absolute root/source paths with this inspection and,
for direct Codex `-m continuum.mcp_server` launches, the declared absolute Python
executable with the inspecting interpreter. Relative paths, environment expansion,
PATH resolution, multi-entry `PYTHONPATH`, plugin runner launches, aliases other
than `continuum`, and target-host environment overrides remain unverified. Hermes
can override the file through `CONTINUUM_ROOT` and `CONTINUUM_SRC`; matching file
values alone do not prove the host uses them. Credentials, model routes, arbitrary
environment entries, command arguments, and job payload/error text are not
returned. A normalized binding path is emitted only when it matches an
already-known inspection path; mismatching values are suppressed. Explicit local
paths in the report may themselves be private. Only regular config files are read.

Upgrade inspection reports facts and a manual preflight checklist only. It does
not select a target release, promise compatibility, certify a migration, or
validate a real Hermes/Codex connection. Backups, target release review, writer
coordination, and intended-host testing are still required before deployment.

## Read-only boundary

The catalog uses the existing `connect_existing` opener with SQLite `mode=ro`,
normal WAL change detection, and one read transaction. It does **not** use
`immutable=1` on a live root. The writer-claim compatibility guard still applies.
SQLite may create/update transient `-wal`/`-shm` coordination files; this is not a
byte-for-byte filesystem immutability guarantee. Inspection does not write durable
catalog rows, config, jobs, claims, operations, or receipts. Configuration/runtime
facts are read separately and are not an atomic snapshot of the whole host.
