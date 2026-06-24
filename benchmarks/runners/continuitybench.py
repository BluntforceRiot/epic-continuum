from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import hashlib
import json
import math
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from statistics import mean
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from continuum.core.config import config_path  # noqa: E402
from continuum.core.store import (  # noqa: E402
    append_scroll_event,
    compile_context,
    connect,
    connect_existing,
    create_card,
    estimate_tokens,
    ingest_file,
    init_db,
    search_memory,
)

try:  # noqa: E402
    from ._common import prepare_output_dir, sanitize_command
except ImportError:  # pragma: no cover - script execution path
    from _common import prepare_output_dir, sanitize_command  # type: ignore


DEFAULT_BUDGETS = [128, 256, 512, 1000, 2000, 4000]
MODES = [
    "no_memory",
    "last_n_events",
    "recent_scroll",
    "cards_only",
    "library_fts",
    "scroll_cards",
    "scroll_cards_library",
    "full_transcript",
    "looking_glass",
]
TOKEN_RE = re.compile(r"[A-Za-z0-9:_-]+")


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def run_git(args: list[str]) -> str | None:
    try:
        return subprocess.check_output(["git", *args], cwd=REPO_ROOT, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def total_ram_bytes() -> int | None:
    if platform.system() == "Windows":
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(status)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.ullTotalPhys)
        return None
    if hasattr(os, "sysconf"):
        try:
            return int(os.sysconf("SC_PAGE_SIZE")) * int(os.sysconf("SC_PHYS_PAGES"))
        except (OSError, ValueError):
            return None
    return None


def environment(command: str, fixture: Path, root: Path, seed: int, *, cache_state: str, trial_count: int) -> dict[str, Any]:
    dirty = run_git(["status", "--short"])
    cfg = config_path(root)
    return {
        "benchmark": "ContinuityBench",
        "benchmark_version": read_json(fixture).get("version"),
        "api_cost_usd": 0,
        "api_token_usage": {"completion_tokens": 0, "prompt_tokens": 0, "total_tokens": 0},
        "cache_state": cache_state,
        "command": command,
        "continuum_config_hash": file_sha256(cfg) if cfg.exists() else None,
        "cpu": platform.processor() or platform.machine(),
        "dataset_checksum": file_sha256(fixture),
        "dataset_name": "ContinuityBench",
        "dataset_split": "synthetic-local",
        "dataset_version": read_json(fixture).get("version"),
        "epic_continuum_version": project_version(),
        "finish_timestamp": None,
        "git_commit": run_git(["rev-parse", "HEAD"]),
        "git_dirty": bool(dirty),
        "mode": "quick-offline",
        "model_name": None,
        "model_provider": None,
        "prompt_hash": None,
        "os": platform.platform(),
        "python": sys.version,
        "random_seed": seed,
        "ram_bytes": total_ram_bytes(),
        "start_timestamp": utc_now(),
        "storage_type": "local-filesystem",
        "trial_count": trial_count,
    }


def project_version() -> str:
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', pyproject)
    return match.group(1) if match else "unknown"


def lexical_terms(text: str) -> set[str]:
    return {token.lower() for token in TOKEN_RE.findall(text)}


def lexical_score(query: str, text: str) -> float:
    q = lexical_terms(query)
    if not q:
        return 0.0
    t = lexical_terms(text)
    overlap = len(q & t)
    return overlap / len(q)


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = (len(ordered) - 1) * pct
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return float(ordered[int(index)])
    return float(ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower))


def build_corpus(root: Path, source_dir: Path, cases: list[dict[str, Any]]) -> None:
    init_db(root)
    source_dir.mkdir(parents=True, exist_ok=True)
    for case in cases:
        session_id = case["id"]
        for event in case["events"]:
            role = "user" if event.startswith(("Decision", "Requirement", "Policy", "Step", "Fact")) else "assistant"
            append_scroll_event(
                root,
                session_id=session_id,
                event_type="message",
                role=role,
                content=event,
                metadata={"benchmark_case": case["id"], "benchmark": "ContinuityBench"},
            )
        conn = connect(root)
        try:
            for index, card_text in enumerate(case["cards"]):
                create_card(
                    conn,
                    root=root,
                    card_type="benchmark_memory",
                    title=f"{case['id']} card {index + 1}",
                    summary=card_text,
                    source_refs=[{"benchmark_case": case["id"], "source": "fixture"}],
                    topics=[case["id"], "ContinuityBench"],
                    decisions=[card_text] if "Decision" in card_text or "Current" in card_text else [],
                    open_tasks=[card_text] if "Next" in card_text else [],
                    salience=0.8,
                    confidence=0.9,
                    metadata={"session_id": session_id, "benchmark_case": case["id"]},
                    visibility_scope="session",
                    session_id=session_id,
                )
            conn.commit()
        finally:
            conn.close()
        for index, text in enumerate(case["library"]):
            source = source_dir / f"{case['id']}_{index + 1}.txt"
            source.write_text(text + "\n", encoding="utf-8")
            ingest_file(root, path=source, title=f"{case['id']} source {index + 1}")


def rows(root: Path, sql: str, params: tuple[Any, ...]) -> list[sqlite3.Row]:
    conn = connect_existing(root)
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def scroll_candidates(root: Path, case: dict[str, Any], *, limit: int | None = None) -> list[dict[str, Any]]:
    query = case["query"]
    sql = """
        SELECT seq, role, event_type, content
        FROM scroll_events
        WHERE session_id = ?
        ORDER BY seq DESC
    """
    selected = rows(root, sql, (case["id"],))
    if limit is not None:
        selected = selected[:limit]
    candidates = []
    for rank, row in enumerate(selected, start=1):
        text = f"{row['seq']} {row['role']}[{row['event_type']}]: {row['content']}"
        candidates.append(
            {
                "id": f"scroll:{case['id']}:{row['seq']}",
                "kind": "scroll",
                "score": lexical_score(query, text) + (1.0 / (1000 + rank)),
                "text": text,
            }
        )
    return sorted(candidates, key=lambda item: item["score"], reverse=True)


def card_candidates(root: Path, case: dict[str, Any]) -> list[dict[str, Any]]:
    query = case["query"]
    selected = rows(
        root,
        """
        SELECT id, title, summary, salience
        FROM cards
        WHERE session_id = ? OR metadata_json LIKE ?
        ORDER BY salience DESC, updated_at DESC
        """,
        (case["id"], f"%{case['id']}%"),
    )
    candidates = []
    for row in selected:
        text = f"{row['title']}: {row['summary']}"
        candidates.append(
            {
                "id": f"card:{row['id']}",
                "kind": "card",
                "score": lexical_score(query, text) + float(row["salience"]),
                "text": text,
            }
        )
    return sorted(candidates, key=lambda item: item["score"], reverse=True)


def library_candidates(root: Path, case: dict[str, Any]) -> list[dict[str, Any]]:
    started = time.perf_counter()
    result = search_memory(root, query=case["query"], limit=10, create=False)
    elapsed = time.perf_counter() - started
    candidates = []
    for item in result.get("results", []):
        text = f"{item.get('title', '')}: {item.get('snippet', '')}"
        candidates.append(
            {
                "id": f"library:{item.get('chunk_id') or item.get('book_id')}",
                "kind": "library",
                "score": lexical_score(case["query"], text),
                "text": text,
                "retrieval_latency_seconds": elapsed,
            }
        )
    return sorted(candidates, key=lambda item: item["score"], reverse=True)


def dedupe_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for candidate in sorted(candidates, key=lambda item: item["score"], reverse=True):
        key = candidate["id"]
        if key in seen:
            continue
        seen.add(key)
        output.append(candidate)
    return output


def candidates_for_mode(root: Path, case: dict[str, Any], mode: str) -> tuple[list[dict[str, Any]], float]:
    started = time.perf_counter()
    if mode == "no_memory":
        return [], time.perf_counter() - started
    if mode == "last_n_events":
        return scroll_candidates(root, case, limit=4), time.perf_counter() - started
    if mode == "recent_scroll":
        return scroll_candidates(root, case, limit=10), time.perf_counter() - started
    if mode == "cards_only":
        return card_candidates(root, case), time.perf_counter() - started
    if mode == "library_fts":
        return library_candidates(root, case), time.perf_counter() - started
    if mode == "scroll_cards":
        return dedupe_candidates(scroll_candidates(root, case, limit=10) + card_candidates(root, case)), time.perf_counter() - started
    if mode == "scroll_cards_library":
        return (
            dedupe_candidates(scroll_candidates(root, case, limit=10) + card_candidates(root, case) + library_candidates(root, case)),
            time.perf_counter() - started,
        )
    if mode == "full_transcript":
        transcript = "\n".join(candidate["text"] for candidate in reversed(scroll_candidates(root, case, limit=None)))
        return [
            {
                "id": f"transcript:{case['id']}",
                "kind": "transcript",
                "score": lexical_score(case["query"], transcript),
                "text": transcript,
            }
        ], time.perf_counter() - started
    raise ValueError(f"unsupported mode: {mode}")


def assemble_context(candidates: list[dict[str, Any]], budget: int) -> tuple[str, list[dict[str, Any]]]:
    selected = []
    lines = []
    used = 0
    for rank, candidate in enumerate(candidates, start=1):
        line = f"[{candidate['kind']} rank={rank} id={candidate['id']}]\n{candidate['text']}"
        cost = estimate_tokens(line)
        if used + cost > budget:
            continue
        used += cost
        selected.append({**candidate, "rank": rank, "estimated_tokens": cost})
        lines.append(line)
    return "\n\n".join(lines), selected


def looking_glass_context(root: Path, case: dict[str, Any], budget: int) -> tuple[str, list[dict[str, Any]], float, dict[str, Any]]:
    started = time.perf_counter()
    result = compile_context(
        root,
        session_id=case["id"],
        token_budget=budget,
        query=case["query"],
        create=False,
        card_scope="session",
    )
    elapsed = time.perf_counter() - started
    text = result.get("context_text", "")
    candidate = {
        "id": f"looking_glass:{case['id']}",
        "kind": "looking_glass",
        "rank": 1,
        "score": lexical_score(case["query"], text),
        "text": text,
        "estimated_tokens": estimate_tokens(text),
        "packet_level": True,
    }
    return text, [candidate] if text else [], elapsed, result


def first_rank_for(evidence: str, selected: list[dict[str, Any]]) -> int | None:
    for candidate in selected:
        if evidence in candidate["text"]:
            return int(candidate.get("rank", 0)) or None
    return None


def dcg(relevances: list[float]) -> float:
    return sum(rel / math.log2(index + 2) for index, rel in enumerate(relevances))


def reciprocal_rank(selected: list[dict[str, Any]], required: list[str]) -> float | None:
    if not required or any(candidate.get("packet_level") for candidate in selected):
        return None
    for index, candidate in enumerate(selected, start=1):
        if any(token in candidate["text"] for token in required):
            return 1.0 / index
    return 0.0


def ndcg_at_10(selected: list[dict[str, Any]], required: list[str]) -> float | None:
    if not required or any(candidate.get("packet_level") for candidate in selected):
        return None
    relevances = [
        len([token for token in required if token in candidate["text"]])
        for candidate in selected[:10]
    ]
    ideal = sorted(relevances, reverse=True)
    ideal_dcg = dcg(ideal)
    return 0.0 if ideal_dcg == 0 else dcg(relevances) / ideal_dcg


def evaluate_case(root: Path, case: dict[str, Any], mode: str, budget: int) -> dict[str, Any]:
    if mode == "looking_glass":
        context_text, selected, latency, raw_result = looking_glass_context(root, case, budget)
        retrieval_latency = 0.0
        compilation_latency = latency
    else:
        candidates, retrieval_latency = candidates_for_mode(root, case, mode)
        started = time.perf_counter()
        context_text, selected = assemble_context(candidates, budget)
        compilation_latency = time.perf_counter() - started
        raw_result = {}

    required = list(case["required_evidence"])
    forbidden = list(case.get("forbidden_evidence", []))
    required_in_context = [token for token in required if token in context_text]
    forbidden_in_context = [token for token in forbidden if token in context_text]

    def recall_at(k: int) -> float:
        if not required:
            return 1.0
        top_text = "\n".join(candidate["text"] for candidate in selected[:k])
        return len([token for token in required if token in top_text]) / len(required)

    mrr = reciprocal_rank(selected, required)
    ndcg = ndcg_at_10(selected, required)
    total_tokens = estimate_tokens(context_text)
    irrelevant_tokens = sum(
        int(candidate.get("estimated_tokens", estimate_tokens(candidate["text"])))
        for candidate in selected
        if not any(token in candidate["text"] for token in required)
    )
    required_evidence_tokens = sum(estimate_tokens(token) for token in required_in_context)

    return {
        "budget": budget,
        "budget_respected": total_tokens <= budget,
        "case_id": case["id"],
        "compilation_latency_seconds": compilation_latency,
        "context_tokens_used": total_tokens,
        "forbidden_evidence_included": forbidden_in_context,
        "interruption": case["interruption"],
        "irrelevant_context_rate": 0.0 if total_tokens == 0 else irrelevant_tokens / total_tokens,
        "mode": mode,
        "mrr": mrr,
        "ndcg_at_10": ndcg,
        "rank_metrics_applicable": mrr is not None and ndcg is not None,
        "query": case["query"],
        "recall_at_1": recall_at(1),
        "recall_at_5": recall_at(5),
        "recall_at_10": recall_at(10),
        "required_evidence": required,
        "required_evidence_found": required_in_context,
        "retrieval_latency_seconds": retrieval_latency,
        "selected_count": len(selected),
        "selected_ids": [candidate["id"] for candidate in selected[:10]],
        "superseded_error": bool(forbidden_in_context),
        "useful_evidence_density": 0.0 if total_tokens == 0 else required_evidence_tokens / total_tokens,
        "looking_glass_raw": {
            key: raw_result.get(key)
            for key in ("token_budget", "estimated_tokens", "remaining_budget", "section_count", "truncated")
            if key in raw_result
        },
    }


def aggregate(rows_: list[dict[str, Any]]) -> dict[str, Any]:
    def mean_present(items: list[dict[str, Any]], key: str) -> float | None:
        values = [float(item[key]) for item in items if item.get(key) is not None]
        return mean(values) if values else None

    groups: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for row in rows_:
        groups.setdefault((row["mode"], int(row["budget"])), []).append(row)
    by_group = []
    for (mode, budget), items in sorted(groups.items()):
        by_group.append(
            {
                "mode": mode,
                "budget": budget,
                "case_count": len(items),
                "recall_at_1": mean(item["recall_at_1"] for item in items),
                "recall_at_5": mean(item["recall_at_5"] for item in items),
                "recall_at_10": mean(item["recall_at_10"] for item in items),
                "mrr": mean_present(items, "mrr"),
                "ndcg_at_10": mean_present(items, "ndcg_at_10"),
                "rank_metric_case_count": sum(1 for item in items if item.get("rank_metrics_applicable")),
                "superseded_error_rate": mean(1.0 if item["superseded_error"] else 0.0 for item in items),
                "irrelevant_context_rate": mean(item["irrelevant_context_rate"] for item in items),
                "budget_respected_rate": mean(1.0 if item["budget_respected"] else 0.0 for item in items),
                "useful_evidence_density": mean(item["useful_evidence_density"] for item in items),
                "context_tokens_used_mean": mean(item["context_tokens_used"] for item in items),
                "retrieval_latency_p50_seconds": percentile([item["retrieval_latency_seconds"] for item in items], 0.50),
                "retrieval_latency_p95_seconds": percentile([item["retrieval_latency_seconds"] for item in items], 0.95),
                "context_compilation_latency_p50_seconds": percentile([item["compilation_latency_seconds"] for item in items], 0.50),
                "context_compilation_latency_p95_seconds": percentile([item["compilation_latency_seconds"] for item in items], 0.95),
            }
        )
    return {"groups": by_group}


def parse_budgets(raw: str | None) -> list[int]:
    if not raw:
        return DEFAULT_BUDGETS
    return [int(item.strip()) for item in raw.split(",") if item.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run deterministic Epic Continuum continuity benchmarks.")
    parser.add_argument("--fixture", type=Path, default=REPO_ROOT / "benchmarks" / "fixtures" / "continuitybench_cases.json")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--budgets", help="Comma-separated token budgets; default is 128,256,512,1000,2000,4000")
    parser.add_argument("--quick", action="store_true", help="Run the deterministic quick suite. This is currently the default suite.")
    parser.add_argument("--cache-state", choices=("cold", "warm"), default="cold", help="Record whether the run is intended as a cold-cache or warm-cache benchmark.")
    parser.add_argument("--keep-root", action="store_true", help="Keep the disposable benchmark Continuum root under the output directory.")
    args = parser.parse_args(argv)

    fixture = args.fixture.resolve()
    data = read_json(fixture)
    cases = data["cases"]
    budgets = parse_budgets(args.budgets)
    output_dir = prepare_output_dir(args.output_dir, benchmark="ContinuityBench")
    command = sanitize_command([Path(sys.executable).name, *(argv if argv is not None else sys.argv[1:])])
    rows_out: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="continuitybench-") as tmp:
        temp_root = Path(tmp)
        root = output_dir / "continuum-root" if args.keep_root else temp_root / "continuum-root"
        source_dir = temp_root / "sources"
        build_corpus(root, source_dir, cases)
        trial_count = len(budgets) * len(MODES) * len(cases)
        env = environment(command, fixture, root, int(data.get("seed", 1337)), cache_state=args.cache_state, trial_count=trial_count)

        for budget in budgets:
            for mode in MODES:
                for case in cases:
                    rows_out.append(evaluate_case(root, case, mode, budget))

        env["finish_timestamp"] = utc_now()
        if args.keep_root:
            shutil.copytree(root, output_dir / "continuum-root-copy", dirs_exist_ok=True)

    summary = {
        "benchmark": data["name"],
        "benchmark_version": data["version"],
        "case_count": len(cases),
        "budgets": budgets,
        "modes": MODES,
        "environment_file": "environment.json",
        "cases_file": "cases.jsonl",
        **aggregate(rows_out),
    }
    write_json(output_dir / "environment.json", env)
    write_json(output_dir / "summary.json", summary)
    append_jsonl(output_dir / "cases.jsonl", rows_out)
    (output_dir / "commands.txt").write_text(command + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "output_dir": str(output_dir), "case_count": len(cases), "record_count": len(rows_out)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
