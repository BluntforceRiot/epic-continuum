# Worker operations

Epic Continuum captures work durably before its Scribe, Librarian, and
Archivist jobs run. A root therefore needs one persistent worker service in
addition to any MCP or capture processes.

Run the service directly with:

```console
python -m continuum serve --root PATH --interval-seconds 5 --maintenance-interval-seconds 300
```

`serve` holds a per-root process lock, so a second service fails closed instead
of processing the same queue concurrently. Maintenance runs on startup and at
the configured cadence rather than on every idle poll.

For a legacy backlog, inspect first and then apply the bounded reconciliation:

```console
python -m continuum reconcile-workers --root PATH
python -m continuum reconcile-workers --root PATH --apply
```

Reconciliation never deletes queue evidence. It marks redundant pending
Scroll notifications as skipped with an audit reason, keeps the newest pending
signal for each session, and activates only legacy pending cards that already
have graph placement. Genuine pending or running Librarian reviews are left to
the worker.

On Windows, `scripts/run_continuum_workers.ps1` is suitable as a Task Scheduler
action. Pass the root, source checkout, and Python executable explicitly. The
wrapper appends service output to `run/logs/continuum-workers.log` under the
root. Configure Task Scheduler to run only one instance and restart the task on
failure.
