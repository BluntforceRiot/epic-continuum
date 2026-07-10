# Writer claims

Epic Continuum permits only one operating-system runtime and host to mutate a
root. This prevents Windows SQLite and WSL/Linux SQLite from coordinating the
same WAL through incompatible filesystem-locking implementations.

The claim is stored at `config/writer-claim.json` and records its schema,
runtime (`windows`, `wsl`, `linux`, or `macos`), normalized host name, and UTC
claim timestamp. `status`, `writer-status`, `doctor`, and read-only root
verification remain available from a different runtime. Strict verification
automatically skips its mutating restore drill when the current runtime does not
own the claim.

New empty roots are claimed automatically during their first mutation. Existing
unclaimed roots require an explicit choice:

```powershell
python -m continuum writer-status --root N:\path\to\continuum-root
python -m continuum writer-claim --root N:\path\to\continuum-root
```

WSL never auto-claims a root under `/mnt/<drive>`, even when it is empty. Run the
explicit claim command only after deciding that WSL, rather than Windows, will
be the writer.

## Transferring a claim

Stop every Continuum CLI, MCP server, adapter, worker, and other process that
can write the root. Confirm no Windows or WSL process still has the catalog
open. Then transfer the claim from the runtime that will become the sole writer:

```powershell
python -m continuum writer-claim --root N:\path\to\continuum-root `
  --force --acknowledge-writers-stopped
```

```bash
python -m continuum writer-claim --root /mnt/n/path/to/continuum-root \
  --force --acknowledge-writers-stopped
```

`--force` without `--acknowledge-writers-stopped` is rejected. A force transfer
does not stop processes or repair a catalog; the acknowledgement means the
operator already stopped all writers. Never use force merely to get past a
claim error while another runtime is running.

Writer claims are live-machine state and are omitted from portable root bundles.
An extracted bundle must be claimed explicitly before its first mutation.

## Errors

- `existing Continuum root has no writer claim`: inspect it read-only, stop any
  legacy writers, and run `writer-claim` once from the chosen runtime.
- `write-claimed by ...`: continue with read-only commands, or perform the
  stopped-writer transfer above.
- `unsafe or malformed`: do not delete or replace the file through a symlink or
  junction. Stop writers, inspect `config`, and use the acknowledged force
  transfer only after the path is known to be a normal directory.
