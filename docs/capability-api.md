# Scoped 0.4 capability transports

The Python domain APIs are also available through one bounded CLI command and
two explicitly separated MCP tools. These adapters do not choose a memory root,
invoke a model, message another thread, execute source files, or automatically
apply a recorded procedure.

## CLI

```text
continuum knowledge --root <ABSOLUTE_MEMORY_ROOT> --action query_handoffs --request-json '{"project_id":"example"}'
```

`--root`, `--action` and `--request-json` are mandatory. The request is a JSON
object containing the named Python function's keyword arguments, without its
root argument. Action names are the exact names below; there is no import path,
shell command, expression, arbitrary attribute lookup or fallback action.
Existing individual CLI commands remain available and unchanged.

Requests are bounded to 512 KiB of UTF-8 JSON, at most 64 top-level arguments,
20 levels and 65,536 structural nodes. Duplicate keys, non-finite numbers,
out-of-range integers, invalid Unicode, NULs, unsupported actions and unknown or
missing arguments are rejected. Domain-specific limits still apply. Host shell
command-line limits may be smaller than 512 KiB. MCP retains its existing
256-KiB ceiling for the entire stdio frame, including JSON escaping and protocol
fields. Use the Python API for capsules exceeding either transport's limit;
never split or truncate their structured contents.

## MCP

- `continuum_knowledge_read`: only the registered read actions.
- `continuum_knowledge_write`: only append-only memory mutations or explicit
  isolated experiment creation.

Both require `{root, action, request}`. `root` is an absolute path, never an
implicit default. The action enums reflect mutability and are also enforced at
runtime. The read tool is marked read-only/idempotent; the write tool is not.
Both are marked open-world because some actions inspect explicit local files or
directories, not because either can access a network or model.

The MCP allowlist is checked for the top-level root and every explicit path
parameter: `source_root`, `destination`, `experiment_root`, and `target_root`
where supported by that action. Domain checks still enforce relative input
selection, disjoint experiment destinations, source hashes and visibility.
Putting another root in `request.root` or an unsupported extra argument is an
error. Embedded evidence text and capsule fields are data, not path expansion
or authorization to operate on referenced locations.

## Fixed action registry

| Domain | Read actions | Write actions |
| --- | --- | --- |
| Investigations | `query_investigation`, `export_investigation_notebook` | `register_analysis_asset`, `record_analysis_finding`, `record_media_annotation`, `record_notebook_entry` |
| Experience | `query_experiences`, `find_reusable_lessons` | `record_experience`, `propose_procedure`, `review_procedure` |
| Coordination | `query_handoffs`, `query_collections` | `create_handoff`, `transition_handoff`, `create_collection`, `revise_collection` |
| Working knowledge | `change_impact`, `compile_task_pack`, `explain_memory` | None |
| Workspaces | `export_workspace`, `plan_workspace_import`, `replay_memory_experiment`, `compare_experiment_replays` | `import_workspace`, `resolve_workspace_conflict`, `create_memory_experiment`, `adopt_experiment_records` |

The host-neutral working-message selector remains a Python API because it works
on a host's in-memory request, not a stored root. Ordinary embedding/indexing,
temporal fact and project-knowledge commands retain their existing dedicated
interfaces.

## Source versus destination authority

Read/export/plan/replay/compare actions do not create operation receipts or
initialize the source root. Notebook export returns Markdown as data; workspace
export returns a hash-bound capsule. Neither writes an unspecified output file.
Replay uses an explicitly named experiment root and its expected manifest hash;
comparison uses supplied replay objects. These two actions still require the
top-level transport root, but their data source is the explicit `experiment_root`
or the supplied objects, respectively.

Memory writes use the existing governed operation/capture path. Normal actions
write to the explicit top-level root. `adopt_experiment_records` instead takes
both an explicit `experiment_root` and `target_root`: it writes and records its
operation **only in the target root**, never the experiment/source root.

`create_memory_experiment` is classified as a write because it creates one new,
disjoint destination. Its existing domain manifest and snapshot hashes are the
derivation receipt. No source-root operation guard is opened, and no destination
guard pre-creates the directory before the domain's new-directory check. The
source stays unchanged. A failed incomplete experiment is not silently reused
or overwritten; inspect its evidence before choosing a new destination.

All domain credential guards, exact citations, lease/head checks, output budgets,
selective import rules and caller-attribution limits remain in force. Transport
tests use disposable roots and real CLI/MCP subprocesses; they do not establish
live host/model performance or authorize deployment.
