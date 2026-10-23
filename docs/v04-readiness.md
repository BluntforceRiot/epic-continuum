# 0.4 readiness and foundation certification boundary

This source is the assembled 0.4.0 candidate, not a released distribution. Keep the live
0.3.1 runtime and memories unchanged until a separately approved deployment.

The [approved scope](v04-scope.md) is broader than the current foundations and
uses one shared core with host adapters, without a separate private Vanta product
branch. The foundation slice includes retrieval relevance and query-centered excerpts, exact
on-demand Library reads, opt-in preservation of large captured results, compact
operator inspection, connection/upgrade preflight, and a reproducible recall
test utility. The foundation slice alone is not the expanded release.

The Memory Studio UI is excluded. A productized practical evaluation lab is
deferred pending a separate decision; normal engineering tests and representative
quality checks remain required. Existing evaluation fixtures/utilities are kept.

The isolated [memory-intelligence slice](memory-intelligence.md) adds
explicit incremental local embedding indexes, ordinary valid/as-known fact
assertions and corrections, and file/symbol-linked project evidence with
staleness propagation.

The following isolated capability assembly adds explicit source/binary and media
anchors, linked investigation notebooks, successful/failed experiences and
reviewed procedure proposals, CAS handoff leases, progressive collections,
whole-group working-context selection, task packets and change diagnostics, and
selected knowledge capsules with fixed-snapshot replay and explicit adoption.
See the [capability API](capability-api.md) and its domain references. These are
headless, model-free APIs. They do not enable themselves in a live host, extract
image/audio contents, execute procedures, synchronize whole conversations, or
claim learned truth. Encoded media stays outside token text; complete fresh
message/tool groups are preserved or explicitly reported as too large.

## Proof ladder

| Gate | What it establishes | What it does not establish |
|---|---|---|
| Source unit/regression suite | API behavior, scope, credential blocking, durable evidence | Live host or model quality |
| Offline Hermes callback contracts | Public hooks, exact large-output preservation, no callback dispatch on passive text | Model-generated tool routing or private HCE activation |
| OpenAI-shaped message boundary | Prior image/answer and current tool JSON remain ordered and unchanged | Host-specific compaction or visual understanding |
| Fresh Codex portable MCP runner | Initialization, schemas, read-only bounded reads | Codex app registration or reconnect |
| Installer dry-run | Proposed Hermes action without filesystem/process mutation | Successful installation |
| Clean wheel/sdist install | Packaged source/assets and fresh-process API/protocol behavior | Every OS/Python combination |
| Frozen corpus evaluation | Exactly measured retrieval/abstention/context costs | General superiority or unseen-answer quality |
| Independent frozen review | No unresolved actionable findings at exact hashes | Approval of later changed bytes |
| Governed receipts | Bound source, test, review, package and promotion evidence | Deployment authorization |

Run offline adapter contracts with:

```text
python -m unittest discover -s tests -p test_adapter_contracts_v04.py -v
```

## Still required for actual 0.4 shipping

- Verify the assembled capabilities against [the scope](v04-scope.md), with each
  implementation limit visible. Passing isolated API gates alone is not the
  expanded release's practical quality or host certification.
- Assemble only reviewed slices; bind all changed paths and package hashes.
- Run the entire existing suite, static/credential-fixture checks and independent
  review against the assembled candidate. Repeat reproducible wheel/sdist builds.
- Run the hosted OS/Python CI matrix on that exact candidate after push approval.
- Evaluate a separately held-out representative corpus; retain unanswerable cases.
  Synthetic regression success alone is not a practical quality claim.
- With separate authorization, test installed Hermes and Codex connections. For
  Hermes include normal conversation, passive update, explicit factual recall,
  image follow-up and structured call/result preservation across real compaction.
  Record provider/tool counts, context costs and exact source/runtime versions.
- Perform a stopped-state, backed-up upgrade/rollback rehearsal on a disposable
  copy of representative memory. Preserve all memories and credential blocking.
- Review version/release notes and approve deployment/publication separately.

Historical private Vanta HCE work is not activated or bulk-imported by these
foundations. Shared-core/adaptor reuse requires individual review; retiring the
private product fork does not remove private memory boundaries or authorize
live changes.
The public adapter leaves host messages intact; host compaction/loop behavior
must be proven in its real integration before claiming loop-free Vanta behavior.
