# Epic Continuum Benchmarks

Benchmarks in this directory are local, reproducible checks for memory retrieval, context reconstruction, and recovery behavior.

The first benchmark is `ContinuityBench`, a deterministic CPU-only suite that creates a synthetic Continuum root and evaluates recall under interruption-style cases. It does not use a network connection, external datasets, or paid APIs.

Additional local runners cover:

- `FaultBench`: deterministic interruption, operation recovery, snapshot restore, proof tamper, and copied-root recovery checks.
- `ScaleBench`: synthetic append, FTS, context compilation, worker-pass, snapshot/restore, and optional bundle pack/verify timings; quick mode skips bundle timing unless requested.
- `EricMemoryBench`: small comparison cases for the practical question "when does durable memory help beyond default recent context or QMD-style notes?" It compares recent-context, QMD-style notes, Epic Continuum automatic capture, and Epic Continuum card-assisted recall as separate modes, with optional live model/agent answer checks.

## Quick Run

```bash
python benchmarks/runners/continuitybench.py --quick --output-dir "${TMPDIR:-/tmp}/continuitybench-local-quick"
python benchmarks/runners/faultbench.py --quick --output-dir "${TMPDIR:-/tmp}/faultbench-local-quick"
python benchmarks/runners/scale_bench.py --quick --output-dir "${TMPDIR:-/tmp}/scalebench-local-quick"
python benchmarks/runners/eric_memory_bench.py --quick --output-dir "${TMPDIR:-/tmp}/eric-memory-local-quick"
```

Outputs:

```text
<chosen-output-dir>/
  summary.json
  cases.jsonl
  environment.json
  commands.txt
```

## Policy

- Do not publish headline benchmark claims without committed methodology, per-case results, environment metadata, and exact commands.
- Do not run paid API evaluations without explicit approval.
- Do not download large datasets without first reporting size, source, license, and expected storage.
- Keep raw baseline, tuned mode, and held-out results separate.
- Label live Hermes/OpenClaw/model runs by exact command, model, endpoint, hardware, and timeout. If a command is not configured, report it as skipped instead of simulating it.

See [BENCHMARKS.md](BENCHMARKS.md) for metric definitions and limitations.
