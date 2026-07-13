from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import sqlite3
import subprocess
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from statistics import mean
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from continuum.core.bundle import pack_root, verify_root_bundle  # noqa: E402
from continuum.core.store import append_scroll_event, compile_context, ingest_file, init_db, search_memory, snapshot  # noqa: E402
from continuum.core.workers import run_worker_pass  # noqa: E402
from continuum.core.operations import restore_drill  # noqa: E402

try:  # noqa: E402
    from ._common import prepare_output_dir, sanitize_command
except ImportError:  # pragma: no cover - script execution path
    from _common import prepare_output_dir, sanitize_command  # type: ignore


QUICK_EVENT_COUNTS = [10, 100]
FULL_EVENT_COUNTS = [10_000, 100_000]


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n")


def run_git(args: list[str]) -> str | None:
    try:
        return subprocess.check_output(["git", *args], cwd=REPO_ROOT, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def project_version() -> str:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("version"):
            return line.split("=", 1)[1].strip().strip('"')
    return "unknown"


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = (len(ordered) - 1) * pct
    lower = int(index)
    upper = min(len(ordered) - 1, lower + 1)
    if lower == upper:
        return float(ordered[lower])
    return float(ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower))


def directory_size(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for item in path.rglob("*"):
        try:
            if item.is_file() and not item.is_symlink():
                total += item.stat().st_size
        except OSError:
            continue
    return total


def environment(command: str, trial_count: int, suite_mode: str) -> dict[str, Any]:
    dirty = run_git(["status", "--short"])
    return {
        "api_cost_usd": 0,
        "api_token_usage": {"completion_tokens": 0, "prompt_tokens": 0, "total_tokens": 0},
        "benchmark": "ScaleBench",
        "benchmark_version": "0.2.0",
        "cache_state": "cold-and-warm-recorded-per-row",
        "command": command,
        "cpu": platform.processor() or platform.machine(),
        "dataset_checksum": None,
        "dataset_name": "ScaleBench synthetic local corpus",
        "dataset_split": suite_mode,
        "dataset_version": "0.2.0",
        "epic_continuum_version": project_version(),
        "finish_timestamp": None,
        "git_commit": run_git(["rev-parse", "HEAD"]),
        "git_dirty": bool(dirty),
        "mode": suite_mode,
        "model_name": None,
        "model_provider": None,
        "os": platform.platform(),
        "prompt_hash": None,
        "python": sys.version,
        "random_seed": 1337,
        "storage_type": "local-filesystem",
        "trial_count": trial_count,
    }


def timed(callable_: Any) -> tuple[Any, float]:
    started = time.perf_counter()
    result = callable_()
    return result, time.perf_counter() - started


def timed_repeated(callable_: Any, count: int = 5) -> tuple[list[Any], dict[str, float]]:
    values = []
    durations = []
    for _ in range(count):
        result, elapsed = timed(callable_)
        values.append(result)
        durations.append(elapsed)
    return values, {"p50_seconds": percentile(durations, 0.50), "p95_seconds": percentile(durations, 0.95), "mean_seconds": mean(durations)}


def graph_edge_count(root: Path) -> int:
    db_path = root / "catalog" / "catalog.sqlite3"
    if not db_path.exists():
        return 0
    conn = sqlite3.connect(str(db_path))
    try:
        return int(conn.execute("SELECT COUNT(*) FROM graph_edges").fetchone()[0])
    finally:
        conn.close()


def build_root(root: Path, event_count: int, *, high_entropy: bool = False) -> float:
    init_db(root)
    started = time.perf_counter()
    for index in range(event_count):
        if high_entropy:
            terms = " ".join(f"uniq{index:05d}_{slot:02d}" for slot in range(24))
            content = f"ScaleBench high entropy event {index} {terms} EVID:SCALE-HIGH-{index}."
        else:
            content = f"ScaleBench event {index} EVID:SCALE-{index % 17} current decision remains active."
        append_scroll_event(
            root,
            session_id="scale",
            event_type="message",
            role="assistant" if index % 2 else "user",
            content=content,
            metadata={"benchmark": "ScaleBench", "index": index, "high_entropy": high_entropy},
        )
    return time.perf_counter() - started


def run_one(root: Path, output_dir: Path, event_count: int, *, skip_bundle: bool, high_entropy: bool = False) -> dict[str, Any]:
    tracemalloc.start()
    append_seconds = build_root(root, event_count, high_entropy=high_entropy)
    source = root.parent / f"scale-source-{event_count}.txt"
    source.write_text("\n".join(f"Library evidence EVID:SCALE-LIB-{i} for event count {event_count}." for i in range(20)), encoding="utf-8")
    _, ingest_seconds = timed(lambda: ingest_file(root, path=source, title=f"ScaleBench {event_count} source"))
    _, fts_cold = timed_repeated(lambda: search_memory(root, query="Library evidence SCALE-LIB", limit=5, create=False), count=1)
    _, fts_warm = timed_repeated(lambda: search_memory(root, query="Library evidence SCALE-LIB", limit=5, create=False), count=5)
    contexts, context_warm = timed_repeated(lambda: compile_context(root, session_id="scale", query="current decision active evidence", token_budget=2000, create=False), count=5)
    _, worker_seconds = timed(lambda: run_worker_pass(root, roles=["scribe", "librarian", "archivist"], limit=10, maintenance=True))
    snap, snapshot_seconds = timed(lambda: snapshot(root, reason=f"scale_bench_{event_count}"))
    restored, restore_seconds = timed(lambda: restore_drill(root, snapshot_uri=str(snap["snapshot_uri"]), drill_name=f"scale-bench-{event_count}", verify_recent_proof_packs=1))
    bundle_seconds = 0.0
    verify_bundle_seconds = 0.0
    bundle_ok = None
    if not skip_bundle:
        bundle_path = output_dir / f"scale-root-{event_count}.zip"
        bundle, bundle_seconds = timed(lambda: pack_root(root, out_path=bundle_path, profile="shareable", run_restore_drill=False, force=True))
        verified, verify_bundle_seconds = timed(lambda: verify_root_bundle(Path(str(bundle["bundle_uri"]))))
        bundle_ok = bool(verified.get("ok"))
    _, peak_bytes = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    context_tokens = [int(item.get("estimated_tokens") or 0) for item in contexts]
    root_bytes = directory_size(root)
    edges = graph_edge_count(root)
    return {
        "event_count": event_count,
        "high_entropy": high_entropy,
        "append_seconds": append_seconds,
        "append_events_per_second": event_count / append_seconds if append_seconds else 0.0,
        "fts_cold": fts_cold,
        "fts_warm": fts_warm,
        "context_compilation_warm": context_warm,
        "context_tokens_mean": mean(context_tokens) if context_tokens else 0.0,
        "database_growth_bytes": root_bytes,
        "graph_edges": edges,
        "graph_edges_per_event": edges / event_count if event_count else 0.0,
        "database_bytes_per_event": root_bytes / event_count if event_count else 0.0,
        "ingest_seconds": ingest_seconds,
        "worker_pass_seconds": worker_seconds,
        "snapshot_seconds": snapshot_seconds,
        "restore_seconds": restore_seconds,
        "restore_ok": bool(restored.get("ok")),
        "pack_root_seconds": bundle_seconds,
        "verify_bundle_seconds": verify_bundle_seconds,
        "bundle_ok": bundle_ok,
        "peak_python_memory_bytes": peak_bytes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run synthetic Epic Continuum scale and performance checks.")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--quick", action="store_true", help="Run small local counts suitable for developer validation.")
    parser.add_argument("--full", action="store_true", help="Run larger local counts. Does not include 1M unless --include-million is set.")
    parser.add_argument("--include-million", action="store_true", help="Add a 1,000,000-event count. Requires explicit opt-in.")
    parser.add_argument("--event-counts", help="Comma-separated override, for example 100,1000,10000.")
    parser.add_argument("--skip-bundle", action="store_true", help="Skip pack-root and verify-bundle timing.")
    parser.add_argument("--with-bundle", action="store_true", help="Include pack-root and verify-bundle timing even in quick mode.")
    parser.add_argument("--high-entropy", action="store_true", help="Use mostly unique terms to expose graph write amplification.")
    args = parser.parse_args(argv)
    if args.skip_bundle and args.with_bundle:
        parser.error("--skip-bundle and --with-bundle cannot be used together")

    if args.event_counts:
        event_counts = [int(item.strip()) for item in args.event_counts.split(",") if item.strip()]
        suite_mode = "custom"
    elif args.full:
        event_counts = list(FULL_EVENT_COUNTS)
        suite_mode = "full"
    else:
        event_counts = list(QUICK_EVENT_COUNTS)
        suite_mode = "quick"
    if args.include_million and 1_000_000 not in event_counts:
        event_counts.append(1_000_000)
    skip_bundle = bool(args.skip_bundle or (suite_mode == "quick" and not args.with_bundle))

    output_dir = prepare_output_dir(args.output_dir, benchmark="ScaleBench")
    command = sanitize_command([Path(sys.executable).name, *(argv if argv is not None else sys.argv[1:])])
    rows_out: list[dict[str, Any]] = []
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="scale-bench-") as tmp:
        base = Path(tmp)
        for count in event_counts:
            suffix = "high" if args.high_entropy else "normal"
            rows_out.append(
                run_one(
                    base / f"root-{count}-{suffix}",
                    output_dir,
                    count,
                    skip_bundle=skip_bundle,
                    high_entropy=args.high_entropy,
                )
            )

    env = environment(command, len(rows_out), suite_mode)
    env["finish_timestamp"] = utc_now()
    summary = {
        "benchmark": "ScaleBench",
        "benchmark_version": "0.2.0",
        "elapsed_seconds": time.perf_counter() - started,
        "event_counts": event_counts,
        "high_entropy": bool(args.high_entropy),
        "bundle_skipped": skip_bundle,
        "environment_file": "environment.json",
        "cases_file": "cases.jsonl",
        "ok": all(row["restore_ok"] and (row["bundle_ok"] is not False) for row in rows_out),
        "rows": rows_out,
    }
    write_json(output_dir / "environment.json", env)
    write_json(output_dir / "summary.json", summary)
    append_jsonl(output_dir / "cases.jsonl", rows_out)
    (output_dir / "commands.txt").write_text(command + "\n", encoding="utf-8")
    print(json.dumps({"ok": summary["ok"], "output_dir": str(output_dir), "event_counts": event_counts}, sort_keys=True))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
