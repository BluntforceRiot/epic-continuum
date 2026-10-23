# Continuum 0.4 scope

Continuum 0.4 targets a headless, local-first memory and working-context platform.
This is the accepted feature scope, not a statement that these capabilities are
already implemented. The isolated retrieval, large-output, and inspection work
forms the initial foundation.

## Architecture and boundaries

One shared Continuum core serves Hermes, Codex, and other supported hosts through
thin adapters and profiles. A separate private Vanta product branch is retired
as a future direction. Personal, project, and agent memory scopes remain distinct.
Retiring the fork does not delete branches, publish private code, merge memories,
or replace a live runtime. Useful historical private work requires individual
review before inclusion in the shared core or a host adapter.

Build on Scroll, Cards, Library, graph, recovery, and portable-bundle mechanisms.
Preserve original evidence, credential blocking, and explicit sharing boundaries.
Keep Git optional. Optional extraction, embedding, reranking, or inference
components must not require a cloud account or automatically start, stop,
download, or reconfigure a user's model. Retrieved content remains evidence,
not instruction authority; inferred lessons remain distinct from verified facts.

Interfaces are CLI, MCP, and programmatic APIs. Browsing a collection, reading a
timeline, inspecting relationships, or debugging memory does not imply a GUI.

## Accepted capabilities

Numbers retain the identifiers from the feature proposal; item 10 is excluded.

| ID | Capability | Intended result |
|---|---|---|
| 1 | Semantic, relational, and temporal recall | Fuse exact identifiers, semantic matches, relationships, and time constraints; return cited evidence and ranking explanations within a budget, with a usable model-free fallback. |
| 2 | Living project knowledge | Connect files, symbols, dependencies, decisions, tests, errors, and fixes; recover why an implementation exists and which evidence supports it. Git is optional. |
| 3 | Source and binary-analysis memory | Bind REA/Ghidra findings to the exact binary/build, function/address, source symbol, and evidence. Separate hypotheses from confirmed mappings and flag stale findings. |
| 4 | Real working-context management | Keep approved large outputs outside active prompts, provide useful excerpts and exact expansion, preserve recent multimodal turns and complete call/result groups, and measure actual host prompt reduction. |
| 5 | Time-aware facts and corrections | Answer current and historical questions with validity periods, correction chains, disagreements, and superseded evidence retained. Extend checkpoint mechanisms to ordinary knowledge. |
| 6 | Experience and procedure memory | Record verified successes, failed approaches, prerequisites, and outcomes. Propose reusable procedures from repeated success without automatically promoting inference to fact or rewriting agent instructions. |
| 7 | Cross-agent work continuity | Carry objectives, accepted decisions, unfinished work, artifacts, and evidence between supported hosts. Use claimable handoffs to prevent duplicate ownership and support interruption recovery. |
| 8 | Multimodal memory | Retrieve screenshots, diagrams, PDFs, tables, and transcripts alongside text, with original page, image-region, or timestamp anchors. Heavy extraction components remain optional. |
| 9 | Browsable knowledge collections | Navigate scoped collections through summaries, overviews, and full evidence; compose task context from selected collections without mixing unrelated private data. |
| 11 | Memory experiments and replay | Use disposable memory workspaces, fixed-snapshot replay, result comparisons, and selective adoption of accepted knowledge. This remains separate from a productized evaluation lab. |
| 12 | Portable shared workspaces | Extend portable bundles toward selective cross-machine synchronization, explicit sharing, attribution, and conflict handling without sharing all conversations or private memory. |

## Additional accepted capabilities

| Capability | Intended result |
|---|---|
| Memory debugger | Explain whether a missed memory was not captured, excluded by scope, superseded, ranked too low, or removed by a context budget. Expose the explanation through headless interfaces. |
| Change-impact memory | Identify conclusions and procedures that need rechecking when source files, binaries, dependencies, or configuration change. |
| Evidence-linked investigation notebooks | Connect hypotheses, experiments, observations, competing explanations, and conclusions, including source/binary analysis. Notebooks are structured records and readable exports, not a graphical notebook application. |
| Cross-project transfer of verified lessons | Retrieve potentially reusable fixes with matching prerequisites, differences, and verification evidence; preserve project boundaries and avoid automatic application. |
| Task-ready context packs | Compile reproducible, bounded packets for resuming an investigation, reviewing a change, or preparing a release, including unresolved questions and failed approaches. |

## Excluded and deferred

- **Excluded: item 10, Memory Studio.** No new web/desktop UI, dashboard, graphical
  viewer, or visual timeline/graph application. Headless inspection and debugging
  remain in scope.
- **Deferred pending a separate decision: practical evaluation lab.** Do not
  build a productized evaluation platform, benchmark-management interface, or
  separate evaluation service as part of the active 0.4 scope. The user's
  uncertainty is not approval and is not a permanent rejection.
- **Retained engineering validation:** unit/regression tests, representative
  held-out quality checks where needed, latency/context measurements, packaging,
  adapter tests, and release checks. Existing evaluation utilities and fixtures
  remain intact. These checks do not require an evaluation-lab product.
- No database replacement, bulk private-code import, autonomous prompt rewriting,
  or broad connector rollout is implied. Any interface or schema work must serve
  a named accepted capability and include compatible preservation/upgrade proof.

## Design lessons to incorporate

Use the researched ideas selectively within the accepted capabilities:

- [ai-memory](https://github.com/akitaonrails/ai-memory): typed handoffs,
  cross-agent continuity, readable knowledge, reversible consolidation, and
  lightweight operation.
- [context-mode](https://github.com/mksglu/context-mode): intercept large data
  before prompt expansion, retain full approved output, and return focused reads.
- [Hindsight](https://hindsight.vectorize.io/developer/retrieval): complementary
  retrieval strategies and separate search-effort/output budgets.
- [Graphiti](https://github.com/getzep/graphiti): temporal validity and provenance.
- [Cognee](https://github.com/topoteretes/cognee): connected code, documents, and
  accepted session lessons.
- [Claude-Mem](https://github.com/thedotmack/claude-mem): progressive disclosure,
  citations, and cost visibility, without adopting its viewer/UI direction.
- [OpenViking](https://github.com/volcengine/OpenViking): navigable collections and
  summary-to-source loading, without adopting a graphical studio.
- [MemOS](https://github.com/MemTensor/MemOS): composable memory, corrections,
  multimodal context, and experience-to-procedure workflows.

Design inspiration is not imported code. Any direct component reuse requires
source/version pinning, applicable license review, and integration evidence.
Competitor benchmark claims are not Continuum performance results.

## Implementation sequence and completion

1. **Memory intelligence:** hybrid recall, temporal knowledge, collections,
   corrections, and evidence tracking.
2. **Working intelligence:** host context management, project/source/binary
   knowledge, multimodal continuity, experience, and reusable procedures.
3. **Headless collaboration and operations:** cross-agent handoffs, context packs,
   memory debugging, replay, selective synchronization, and shared workspaces.

Change-impact tracking, investigation notebooks, and cross-project lesson reuse
connect these milestones. The sequence orders work; it does not silently defer
accepted features beyond 0.4. Any later scope reduction needs an explicit decision.

The integrated acceptance scenario is to resume a source/binary investigation in
another supported agent, recover evidence and failed approaches, identify changed
inputs, and continue with bounded context. Tests must verify exact citations,
scope preservation, structured/multimodal context, sharing boundaries, and the
failure/recovery behavior of the features involved.

The [readiness requirements](v04-readiness.md) apply to the final assembled
candidate. Foundation test results certify their exact slice, not the expanded
feature set. Scope approval does not itself authorize live migrations, model
operations, publication, or deployment.
