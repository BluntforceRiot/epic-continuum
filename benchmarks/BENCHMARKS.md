# Epic Continuum Benchmark Methodology

## Purpose

Epic Continuum benchmarks measure whether durable memory can be retrieved and reconstructed after context loss, interruption, or agent handoff.

They do not prove general intelligence, model answer quality, or superiority over another system unless the compared systems use the same dataset, split, top-k definition, metric, and reranking conditions.

## ContinuityBench

`ContinuityBench` is an Epic Continuum project benchmark. It is not an industry standard.

The initial suite uses deterministic synthetic cases that include:

- user decisions;
- assistant responses;
- tool outputs;
- files and artifacts;
- current and superseded decisions;
- unresolved questions;
- explicit next actions;
- irrelevant distractors;
- conflicting facts;
- facts separated across multiple sessions.

## Modes

The runner evaluates:

- `no_memory`;
- `last_n_events`;
- `recent_scroll`;
- `cards_only`;
- `library_fts`;
- `scroll_cards`;
- `scroll_cards_library`;
- `full_transcript`;
- `looking_glass`.

The `looking_glass` mode calls the production `compile_context` API. The combined modes use production persisted Scroll, Card, and Library data with deterministic ranking in the benchmark runner.

## FaultBench

`FaultBench` is a deterministic local recovery benchmark. It uses production operation and recovery APIs to check:

- interruption after operation start;
- interruption after progress and cursor writes;
- snapshot restore;
- proof-pack tamper detection;
- copied-root recovery.

It reports committed Scroll events lost, duplicate events, correctly classified interrupted operations, generated recovery packets, restore success, proof tampering detected, false tamper alarms, and correct next-action recovery.

Run:

```bash
python benchmarks/runners/faultbench.py --quick --output-dir "${TMPDIR:-/tmp}/faultbench-local-quick"
```

## ScaleBench

`ScaleBench` creates synthetic roots and measures append throughput, Library FTS latency, context compilation latency, worker-pass duration, database/root growth, snapshot time, restore time, pack-root time, verify-bundle time, and peak Python allocation observed by `tracemalloc`.

Quick mode is intended for local validation:

```bash
python benchmarks/runners/scale_bench.py --quick --output-dir "${TMPDIR:-/tmp}/scalebench-local-quick"
```

Quick mode uses small smoke counts (`10,100`) so it can be part of a release
gate on ordinary developer machines. It skips bundle pack/verify timing by
default; add `--with-bundle` when you explicitly want that slower measurement.
Use `--event-counts 100,1000` or `--full` when you want heavier pressure-test
numbers instead of a fast validation pass.

High-entropy mode uses mostly unique tool/log-style terms to expose graph write
amplification that repeated vocabulary can hide:

```bash
python benchmarks/runners/scale_bench.py --event-counts 100 --high-entropy --skip-bundle --output-dir "${TMPDIR:-/tmp}/scalebench-local-high"
```

ScaleBench records `graph_edges`, `graph_edges_per_event`, and
`database_bytes_per_event` for this reason. These are local pressure-test
measurements, not cross-machine product claims.

Full mode is manual and can be expensive:

```bash
python benchmarks/runners/scale_bench.py --full --output-dir "${TMPDIR:-/tmp}/scalebench-local-full"
```

The 1,000,000-event mode is opt-in only:

```bash
python benchmarks/runners/scale_bench.py --full --include-million --output-dir "${TMPDIR:-/tmp}/scalebench-local-million"
```

## EricMemoryBench

`EricMemoryBench` is a small comparison runner inspired by the practical review
question: "where does durable memory help beyond default recent context or QMD
notes, and in what scenarios?"

It is intentionally not a universal benchmark for Hermes Agent, OpenClaw, or any
model family. The deterministic quick suite compares four context strategies:

- `hermes_recent_context`: a default-agent baseline where only recent active
  conversation turns are visible under the token budget;
- `openclaw_qmd_notes`: a QMD-style markdown note / mission-card baseline that
  works when a human or agent keeps notes current and can fail when notes are
  stale, missing, or globally overbroad;
- `epic_continuum_auto_capture`: Epic Continuum Looking Glass context plus Cue
  Recall over automatically captured Scroll, project state, and graph
  associations, without injecting answer-bearing fixture Cards;
- `epic_continuum_card_assisted`: the same Epic Continuum retrieval surface with
  manually seeded fixture Cards, reported separately so card-assisted recall is
  not confused with automatic capture.

The runner covers buried decisions, manually curated-note success, stale notes,
cross-agent handoff, and project-scope separation. Evidence labels are used only
for scoring whether context or a live answer cited the needed fact; they are not
used as ranking bonuses.

Quick deterministic run:

```bash
python benchmarks/runners/eric_memory_bench.py --quick --output-dir "${TMPDIR:-/tmp}/eric-memory-local-quick"
```

Optional live model answer check through a local OpenAI-compatible endpoint:

```bash
python benchmarks/runners/eric_memory_bench.py \
  --quick \
  --model Qwen/Qwen2.5-7B-Instruct \
  --live-base-url http://127.0.0.1:8000/v1 \
  --output-dir "${TMPDIR:-/tmp}/eric-memory-live-qwen25-7b"
```

Optional Hermes/OpenClaw command-template checks can be added when a real CLI or
wrapper exists on the review machine:

```bash
python benchmarks/runners/eric_memory_bench.py \
  --quick \
  --model Qwen/Qwen2.5-7B-Instruct \
  --hermes-command 'hermes --model {model} --prompt-file {prompt_file} --output-file {output_file}' \
  --openclaw-command 'openclaw run --model {model} --prompt-file {prompt_file} --output-file {output_file}' \
  --output-dir "${TMPDIR:-/tmp}/eric-memory-live-agents"
```

Those templates are examples, not assumed universal interfaces. If Hermes or
OpenClaw uses a different command surface, pass the local wrapper command that
actually runs on that machine. The benchmark records whether live commands were
configured; unconfigured live surfaces are skipped rather than faked.

## Budgets

Default context budgets:

- 128 tokens;
- 256 tokens;
- 512 tokens;
- 1,000 tokens.

Pass `--budgets 128,256,512,1000,2000,4000` when you want the longer
2K/4K comparison run.

Each case records whether the generated context stayed within budget.

## Metrics

ContinuityBench reports candidate-ranking metrics where a mode produces ranked
candidates. EricMemoryBench and packet-style modes report context evidence
quality instead, because they produce one bounded prompt packet rather than a
ranked list of independent hits.

| Metric | Meaning | Does not prove |
|---|---|---|
| `recall_at_1/5/10` | ContinuityBench ranked-candidate evidence hit rate at top-k | Final answer correctness |
| `mrr` | ContinuityBench reciprocal rank of the first candidate containing required evidence; omitted for packet-level modes | Semantic quality |
| `ndcg_at_10` | ContinuityBench ranked usefulness of top-10 candidates; omitted for packet-level modes | Human preference |
| `required_evidence_rate` | EricMemoryBench fraction of fixture-required evidence labels present in the bounded context packet | Final answer correctness |
| `forbidden_evidence_rate` | EricMemoryBench fraction of forbidden evidence labels present in the bounded context packet | Whether the model would actually use it |
| `context_contains_superseded_evidence` | EricMemoryBench diagnostic list of historical evidence labels that remain visible in the bounded context packet | Staleness by itself; append-only memory may preserve old evidence |
| `superseded_error_rate` | EricMemoryBench deterministic current-answer supersession error rate. It stays `0.0` unless the deterministic evaluator can prove the current selection used old evidence as authoritative | Whether historical evidence was merely retained |
| `context_tokens_used` / `context_tokens_used_mean` | Estimated context tokens | Exact tokenizer count |
| `budget_respected_rate` | Whether contexts fit configured budget | Native model safety |
| `evidence_density` / `evidence_density_mean` | Required evidence-token estimate divided by total context-token estimate | Human readability |
| `live_answer_required_evidence_rate` | Optional live answer evidence-label hit rate for the configured local model/agent | General model quality |
| `live_answer_forbidden_evidence_rate` | Optional live answer inclusion of forbidden/superseded evidence | Whether the agent would always act safely |
| `live_answer_superseded_error_rate` | Optional live answer inclusion/use of evidence marked superseded by the fixture | Whether stale evidence was only visible or actually used |
| latency p50/p95 | Runtime on this machine | Cross-machine performance |

## Result Files

Each run writes:

- `summary.json`: aggregate metrics by mode and budget;
- `cases.jsonl`: one record per case, mode, and budget;
- `environment.json`: OS, Python, CPU, RAM, git state, config hash, seed, and command;
- `commands.txt`: exact command line.

Environment metadata is intentionally runner-specific. ContinuityBench records the Epic Continuum version, git commit, dirty-worktree flag, OS, Python, CPU, RAM when available, storage type, sanitized command, timestamps, cache state, trial count, model/provider fields, prompt hash field, and zero API cost/token usage for no-LLM runs. FaultBench, ScaleBench, and EricMemoryBench record the subset relevant to their job. EricMemoryBench also records whether live endpoint or command-template checks were configured. All benchmark commands are sanitized before writing `commands.txt`, so local output paths, endpoint URLs, API-key environment names, and command templates are redacted by design rather than preserved verbatim.

## Known Weaknesses

- Synthetic evidence tags make deterministic scoring possible but simpler than real project text.
- `compile_context` currently emphasizes recent Scroll events and matching Cards; Library expansion is measured separately and in combined benchmark modes.
- No LLM answer-generation score is included in quick mode.
- No paid API is called.
- No large external dataset is downloaded.
- ScaleBench `tracemalloc` peak memory is Python allocation, not whole-process RSS.
- ScaleBench high-entropy mode is a synthetic stress shape for graph fanout; it does not represent normal conversational language.
- Quick-mode scale counts are fast validation checks, not capacity claims.
- EricMemoryBench quick mode is a local scenario suite, not a product shootout.
  Live Hermes, OpenClaw, or model results must be labeled with the exact model,
  endpoint or command, hardware, timeout, and whether Continuum was installed in
  that agent.

## Dataset Provenance And License

The repository currently commits only synthetic local fixtures owned by this project. Third-party datasets must not be committed until their source, license, size, split, checksum, and redistribution terms are documented.

Planned no-LLM adapters begin with LongMemEval and LoCoMo. Their results must be labeled by dataset, split, metric, top-k definition, reranking conditions, and whether any tuning happened after inspecting misses.

## Failed Approaches And Tuning History

No benchmark tuning has been promoted as a public result in this pass. The current synthetic runner favors transparent evidence tags so the scoring rules can be audited. If future tuning changes retrieval behavior, keep the original run, record the patch, and evaluate on a frozen held-out split before promoting the new score.

## Held-Out Methodology

The initial 20-case ContinuityBench fixture is not a held-out benchmark. For public claims, create a frozen held-out split before tuning retrieval logic, then report raw baseline, tuned development results, and held-out results separately.

## Future Work

Recommended future runners:

- fault-injection and operation recovery benchmark;
- copied-root and bundle-corruption benchmark;
- scale benchmark at 10K, 100K, and optional 1M events;
- no-LLM retrieval adapters for LongMemEval and LoCoMo;
- optional LLM answer-quality runner with explicit cost approval.

## Reproduction

```bash
python benchmarks/runners/continuitybench.py --quick --output-dir "${TMPDIR:-/tmp}/continuitybench-local-quick"
```

Set `PYTHONPATH=src` when running from an environment that has not installed the package.
