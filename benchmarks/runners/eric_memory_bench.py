from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from statistics import mean
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from continuum.core.store import (  # noqa: E402
    append_scroll_event,
    compile_context,
    connect,
    create_card,
    cue_recall,
    estimate_tokens,
    init_db,
    record_project_state,
    sync_card_sidecar,
)

try:  # noqa: E402
    from ._common import prepare_output_dir, sanitize_command
except ImportError:  # pragma: no cover - script execution path
    from _common import prepare_output_dir, sanitize_command  # type: ignore


DEFAULT_BUDGETS = [128, 256, 512, 1000]
DEFAULT_MODEL = "Qwen/Qwen2.5-7B-Instruct"
MODES = [
    "hermes_recent_context",
    "openclaw_qmd_notes",
    "epic_continuum_auto_capture",
    "epic_continuum_card_assisted",
]
TOKEN_RE = re.compile(r"[A-Za-z0-9:_-]+")


def utc_now() -> str:
    import datetime as dt

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


def parse_budgets(raw: str | None) -> list[int]:
    if not raw:
        return DEFAULT_BUDGETS
    budgets = [int(item.strip()) for item in raw.split(",") if item.strip()]
    if not budgets:
        raise ValueError("at least one budget is required")
    if any(budget <= 0 for budget in budgets):
        raise ValueError("budgets must be positive integers")
    return budgets


def project_version() -> str:
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version\s*=\s*"([^"]+)"', pyproject)
    return match.group(1) if match else "unknown"


def lexical_terms(text: str) -> set[str]:
    return {token.lower() for token in TOKEN_RE.findall(text)}


def lexical_score(query: str, text: str) -> float:
    terms = lexical_terms(query)
    if not terms:
        return 0.0
    return len(terms & lexical_terms(text)) / len(terms)


def trim_to_budget(lines: list[str], budget: int) -> str:
    selected: list[str] = []
    used = 0
    for line in lines:
        cost = estimate_tokens(line)
        if used + cost > budget:
            continue
        selected.append(line)
        used += cost
    while selected and estimate_tokens("\n\n".join(selected)) > budget:
        selected.pop()
    return "\n\n".join(selected)


def build_corpus(root: Path, cases: list[dict[str, Any]], *, include_fixture_cards: bool = False) -> None:
    init_db(root)
    for case in cases:
        session_id = str(case["session_id"])
        project_id = str(case.get("project_id") or case["id"])
        for event in case.get("events", []):
            append_scroll_event(
                root,
                session_id=session_id,
                event_type="message",
                role="user" if str(event).startswith(("Decision", "Correction", "Project", "Agent")) else "assistant",
                content=str(event),
                metadata={
                    "benchmark": "EricMemoryBench",
                    "benchmark_case": case["id"],
                    "project_id": project_id,
                    "visibility_scope": "project",
                },
            )
        for extra in case.get("extra_project_events", []):
            append_scroll_event(
                root,
                session_id=str(extra["session_id"]),
                event_type="message",
                role="user",
                content=str(extra["content"]),
                metadata={
                    "benchmark": "EricMemoryBench",
                    "benchmark_case": case["id"],
                    "project_id": str(extra["project_id"]),
                    "visibility_scope": "project",
                },
            )
        if case.get("project_state"):
            state = dict(case["project_state"])
            record_project_state(
                root,
                session_id=session_id,
                agent_id=str(state.get("agent_id") or "codex"),
                project_id=project_id,
                objective=str(state.get("objective") or ""),
                open_tasks=[str(item) for item in state.get("open_tasks", [])],
                decisions=[str(item) for item in state.get("decisions", [])],
                metadata={"benchmark": "EricMemoryBench", "benchmark_case": case["id"]},
            )
        conn = connect(root)
        try:
            created_cards: list[str] = []
            for index, card_text in enumerate(case.get("cards", []) if include_fixture_cards else [], start=1):
                created_cards.append(
                    create_card(
                        conn,
                        root=root,
                        card_type="benchmark_memory",
                        title=f"{case['id']} memory {index}",
                        summary=str(card_text),
                        source_refs=[{"benchmark_case": case["id"], "source": "manual_fixture_card"}],
                        topics=[case["id"], project_id, "EricMemoryBench"],
                        decisions=[str(card_text)] if "Decision" in str(card_text) or "policy" in str(card_text).lower() else [],
                        open_tasks=[str(card_text)] if "task" in str(card_text).lower() else [],
                        salience=0.85,
                        confidence=0.9,
                        metadata={
                            "session_id": session_id,
                            "project_id": project_id,
                            "benchmark_case": case["id"],
                            "manual_fixture_card": True,
                        },
                        visibility_scope="project",
                        session_id=session_id,
                        project_id=project_id,
                    )
                )
            conn.commit()
            if created_cards:
                for card_id in created_cards:
                    sync_card_sidecar(root, conn, card_id)
                conn.commit()
        finally:
            conn.close()


def recent_context(case: dict[str, Any], budget: int) -> str:
    lines = [
        "[Hermes/default recent-context baseline]",
        "This simulates an agent that can only see the most recent conversation turns within the active window.",
    ]
    for index, event in enumerate(reversed(case.get("events", [])), start=1):
        lines.append(f"[recent rank={index}] {event}")
    return trim_to_budget(lines, budget)


def qmd_context(case: dict[str, Any], budget: int) -> str:
    lines = [
        "[OpenClaw/QMD-style notes baseline]",
        "schema: openclaw.qmd_style_context.v1",
        "decision: review_only_context",
        "note: QMD-style notes succeed when manually current and fail when stale or overbroad.",
        f"query: {case['query']}",
        *str(case.get("qmd_note", "")).splitlines(),
    ]
    return trim_to_budget(lines, budget)


def continuum_context(root: Path, case: dict[str, Any], budget: int) -> str:
    started_budget = max(1, int(budget))
    looking_glass_budget = max(64, int(started_budget * 0.75))
    compiled = compile_context(
        root,
        session_id=str(case["session_id"]),
        token_budget=looking_glass_budget,
        query=str(case["query"]),
        create=False,
        project_id=str(case.get("project_id") or ""),
        card_scope="project",
    )
    recall = cue_recall(
        root,
        cue=str(case["query"]),
        session_id=str(case["session_id"]),
        project_id=str(case.get("project_id") or ""),
        limit=4,
        create=False,
    )
    recall_lines = ["[Epic Continuum Cue Recall candidates]"]
    for index, item in enumerate(recall.get("results", []), start=1):
        recall_lines.append(
            f"[cue rank={index} kind={item.get('kind')} score={item.get('score')} id={item.get('id')}]\n"
            f"{item.get('title') or item.get('label') or item.get('content') or item.get('summary') or ''}\n"
            f"{item.get('summary') or item.get('content') or ''}"
        )
    lines = [
        "[Epic Continuum Looking Glass + Cue Recall]",
        "[Looking Glass]",
        *str(compiled.get("context_text") or "").splitlines(),
        "[Cue Recall]",
        *recall_lines,
    ]
    return trim_to_budget(lines, budget)


def context_for_mode(root: Path, case: dict[str, Any], mode: str, budget: int) -> tuple[str, float]:
    started = time.perf_counter()
    if mode == "hermes_recent_context":
        context = recent_context(case, budget)
    elif mode == "openclaw_qmd_notes":
        context = qmd_context(case, budget)
    elif mode in {"epic_continuum_auto_capture", "epic_continuum_card_assisted"}:
        context = continuum_context(root, case, budget)
    else:
        raise ValueError(f"unsupported mode: {mode}")
    return context, time.perf_counter() - started


def endpoint_for_base_url(base_url: str) -> str:
    stripped = base_url.rstrip("/")
    if stripped.endswith("/chat/completions"):
        return stripped
    if stripped.endswith("/v1"):
        return f"{stripped}/chat/completions"
    return f"{stripped}/v1/chat/completions"


def call_openai_compatible(
    *,
    base_url: str,
    model: str,
    prompt: str,
    api_key_env: str | None,
    timeout_seconds: float,
) -> dict[str, Any]:
    headers = {"Content-Type": "application/json"}
    if api_key_env and os.environ.get(api_key_env):
        headers["Authorization"] = f"Bearer {os.environ[api_key_env]}"
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "Answer from the provided context only. If an evidence label supports the answer, "
                    "include that exact EVID: label. If the answer is missing, say MISSING."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0,
        "max_tokens": 160,
    }
    data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
    request = urllib.request.Request(endpoint_for_base_url(base_url), data=data, headers=headers, method="POST")
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            body = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {
            "attempted": True,
            "ok": False,
            "backend": "openai_compatible",
            "latency_seconds": time.perf_counter() - started,
            "error_type": type(exc).__name__,
        }
    choice = (body.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    return {
        "attempted": True,
        "ok": True,
        "backend": "openai_compatible",
        "latency_seconds": time.perf_counter() - started,
        "answer": str(message.get("content") or ""),
        "finish_reason": choice.get("finish_reason"),
    }


def replace_template_parts(parts: list[str], replacements: dict[str, str]) -> list[str]:
    output = []
    for part in parts:
        value = part
        for key, replacement in replacements.items():
            value = value.replace("{" + key + "}", replacement)
        output.append(value)
    return output


def call_command_template(
    *,
    command_template: str,
    prompt: str,
    output_dir: Path,
    case_id: str,
    mode: str,
    budget: int,
    model: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    live_dir = output_dir / "live-command-io"
    live_dir.mkdir(parents=True, exist_ok=True)
    safe_stem = re.sub(r"[^A-Za-z0-9_.-]+", "-", f"{case_id}-{mode}-{budget}").strip("-")
    prompt_path = live_dir / f"{safe_stem}.prompt.txt"
    output_path = live_dir / f"{safe_stem}.answer.txt"
    prompt_path.write_text(prompt, encoding="utf-8")
    parts = shlex.split(command_template)
    argv = replace_template_parts(
        parts,
        {
            "prompt_file": str(prompt_path),
            "output_file": str(output_path),
            "model": model,
            "case_id": case_id,
            "mode": mode,
            "budget": str(budget),
        },
    )
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            argv,
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "attempted": True,
            "ok": False,
            "backend": "command",
            "latency_seconds": time.perf_counter() - started,
            "error_type": type(exc).__name__,
        }
    answer = output_path.read_text(encoding="utf-8") if output_path.exists() else completed.stdout
    return {
        "attempted": True,
        "ok": completed.returncode == 0,
        "backend": "command",
        "latency_seconds": time.perf_counter() - started,
        "answer": answer.strip(),
        "returncode": completed.returncode,
        "stderr_tail": completed.stderr[-500:] if completed.stderr else "",
    }


def live_answer(
    *,
    mode: str,
    prompt: str,
    args: argparse.Namespace,
    output_dir: Path,
    case_id: str,
    budget: int,
) -> dict[str, Any]:
    if args.hermes_command and mode == "hermes_recent_context":
        return call_command_template(
            command_template=args.hermes_command,
            prompt=prompt,
            output_dir=output_dir,
            case_id=case_id,
            mode=mode,
            budget=budget,
            model=args.model,
            timeout_seconds=args.live_timeout,
        ) | {"agent_surface": "hermes"}
    if args.openclaw_command and mode == "openclaw_qmd_notes":
        return call_command_template(
            command_template=args.openclaw_command,
            prompt=prompt,
            output_dir=output_dir,
            case_id=case_id,
            mode=mode,
            budget=budget,
            model=args.model,
            timeout_seconds=args.live_timeout,
        ) | {"agent_surface": "openclaw"}
    if args.live_base_url:
        return call_openai_compatible(
            base_url=args.live_base_url,
            model=args.model,
            prompt=prompt,
            api_key_env=args.api_key_env,
            timeout_seconds=args.live_timeout,
        ) | {"agent_surface": "openai_compatible_model"}
    return {"attempted": False, "ok": None, "backend": None, "agent_surface": None}


def prompt_for_case(case: dict[str, Any], mode: str, context_text: str) -> str:
    return (
        f"Benchmark case: {case['id']}\n"
        f"Context mode: {mode}\n"
        f"Question: {case['query']}\n\n"
        "Use only this context:\n"
        "----- BEGIN CONTEXT -----\n"
        f"{context_text}\n"
        "----- END CONTEXT -----\n\n"
        "Give a concise answer and include exact evidence labels when present."
    )


def explicitly_superseded_tokens(case: dict[str, Any]) -> set[str]:
    """Return old evidence labels that the fixture explicitly marks superseded."""
    tokens: set[str] = set()
    mapping = case.get("superseded_by_evidence")
    if isinstance(mapping, dict):
        for old_token, new_token in mapping.items():
            if old_token and new_token:
                tokens.add(str(old_token))
    for item in case.get("supersession_pairs", []) or []:
        if isinstance(item, dict) and item.get("old") and item.get("new"):
            tokens.add(str(item["old"]))
    return tokens


def evaluate_case(root: Path, case: dict[str, Any], mode: str, budget: int, args: argparse.Namespace, output_dir: Path) -> dict[str, Any]:
    context_text, context_latency = context_for_mode(root, case, mode, budget)
    required = [str(item) for item in case.get("required_evidence", [])]
    forbidden = [str(item) for item in case.get("forbidden_evidence", [])]
    superseded = [str(item) for item in case.get("superseded_evidence", [])]
    superseded_error_candidates = [token for token in superseded if token in explicitly_superseded_tokens(case)]
    context_forbidden_candidates = [token for token in forbidden if token not in superseded]
    required_found = [token for token in required if token in context_text]
    forbidden_found = [token for token in context_forbidden_candidates if token in context_text]
    superseded_found = [token for token in superseded_error_candidates if token in context_text]
    prompt = prompt_for_case(case, mode, context_text)
    answer_result = live_answer(mode=mode, prompt=prompt, args=args, output_dir=output_dir, case_id=case["id"], budget=budget)
    answer = str(answer_result.get("answer") or "")
    answer_required = [token for token in required if token in answer]
    answer_forbidden = [token for token in context_forbidden_candidates if token in answer]
    answer_superseded = [token for token in superseded_error_candidates if token in answer]
    tokens = estimate_tokens(context_text)
    return {
        "answer_contains_forbidden_evidence": answer_forbidden,
        "answer_contains_required_evidence": answer_required,
        "budget": budget,
        "budget_respected": tokens <= budget,
        "case_id": case["id"],
        "context_contains_forbidden_evidence": forbidden_found,
        "context_contains_required_evidence": required_found,
        "context_contains_superseded_evidence": superseded_found,
        "context_latency_seconds": context_latency,
        "context_tokens_used": tokens,
        "evidence_density": 0.0 if tokens == 0 else sum(estimate_tokens(token) for token in required_found) / tokens,
        "forbidden_evidence": forbidden,
        "superseded_evidence": superseded,
        "explicitly_superseded_evidence": superseded_error_candidates,
        "live_answer_attempted": bool(answer_result.get("attempted")),
        "live_answer_backend": answer_result.get("backend"),
        "live_answer_ok": answer_result.get("ok"),
        "live_answer_latency_seconds": answer_result.get("latency_seconds"),
        "live_agent_surface": answer_result.get("agent_surface"),
        "live_error_type": answer_result.get("error_type"),
        "mode": mode,
        "query": case["query"],
        "required_evidence": required,
        "required_evidence_rate": 1.0 if not required else len(required_found) / len(required),
        "forbidden_evidence_rate": 0.0 if not forbidden else len(forbidden_found) / len(forbidden),
        # Append-only memory is allowed to preserve old evidence. Supersession
        # errors are about selecting or presenting the old evidence as current,
        # not about its historical presence in retrieved context.
        "superseded_error_rate": 0.0,
        "live_answer_required_evidence_rate": None if not answer_result.get("attempted") else (1.0 if not required else len(answer_required) / len(required)),
        "live_answer_forbidden_evidence_rate": None if not answer_result.get("attempted") else (0.0 if not forbidden else len(answer_forbidden) / len(forbidden)),
        "live_answer_superseded_error_rate": None if not answer_result.get("attempted") else (0.0 if not superseded_error_candidates else len(answer_superseded) / len(superseded_error_candidates)),
    }


def average(items: list[float]) -> float | None:
    return mean(items) if items else None


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    groups: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault((row["mode"], int(row["budget"])), []).append(row)
    output = []
    for (mode, budget), items in sorted(groups.items()):
        live_required = [float(item["live_answer_required_evidence_rate"]) for item in items if item["live_answer_required_evidence_rate"] is not None]
        live_forbidden = [float(item["live_answer_forbidden_evidence_rate"]) for item in items if item["live_answer_forbidden_evidence_rate"] is not None]
        live_superseded = [float(item["live_answer_superseded_error_rate"]) for item in items if item["live_answer_superseded_error_rate"] is not None]
        live_latency = [float(item["live_answer_latency_seconds"]) for item in items if item.get("live_answer_latency_seconds") is not None]
        output.append(
            {
                "mode": mode,
                "budget": budget,
                "case_count": len(items),
                "required_evidence_rate": mean(float(item["required_evidence_rate"]) for item in items),
                "forbidden_evidence_rate": mean(float(item["forbidden_evidence_rate"]) for item in items),
                "superseded_error_rate": mean(float(item["superseded_error_rate"]) for item in items),
                "budget_respected_rate": mean(1.0 if item["budget_respected"] else 0.0 for item in items),
                "context_tokens_used_mean": mean(float(item["context_tokens_used"]) for item in items),
                "context_latency_mean_seconds": mean(float(item["context_latency_seconds"]) for item in items),
                "evidence_density_mean": mean(float(item["evidence_density"]) for item in items),
                "live_answer_attempted_count": sum(1 for item in items if item["live_answer_attempted"]),
                "live_answer_ok_count": sum(1 for item in items if item["live_answer_ok"] is True),
                "live_answer_required_evidence_rate": average(live_required),
                "live_answer_forbidden_evidence_rate": average(live_forbidden),
                "live_answer_superseded_error_rate": average(live_superseded),
                "live_answer_latency_mean_seconds": average(live_latency),
            }
        )
    return {"groups": output}


def environment(command: str, fixture: Path, args: argparse.Namespace, trial_count: int) -> dict[str, Any]:
    return {
        "api_cost_usd": 0,
        "api_key_env": args.api_key_env if args.api_key_env else None,
        "benchmark": "EricMemoryBench",
        "benchmark_version": read_json(fixture).get("version"),
        "command": command,
        "default_model_reason": (
            "Qwen/Qwen2.5-7B-Instruct is a small, common consumer-card class model with official long-context support; "
            "override --model for Llama, Mistral, a local fine-tune, or another local route."
        ),
        "epic_continuum_version": project_version(),
        "finish_timestamp": None,
        "hermes_command_configured": bool(args.hermes_command),
        "live_base_url_configured": bool(args.live_base_url),
        "live_timeout_seconds": args.live_timeout,
        "model_name": args.model,
        "model_provider": "local-openai-compatible-or-agent-command" if (args.live_base_url or args.hermes_command or args.openclaw_command) else None,
        "openclaw_command_configured": bool(args.openclaw_command),
        "os": platform.platform(),
        "python": sys.version,
        "start_timestamp": utc_now(),
        "trial_count": trial_count,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run EricMemoryBench: recent-context vs QMD-style notes vs Epic Continuum, "
            "with optional live model/agent answer checks."
        )
    )
    parser.add_argument("--fixture", type=Path, default=REPO_ROOT / "benchmarks" / "fixtures" / "eric_memory_cases.json")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--budgets", help="Comma-separated token budgets; default is 128,256,512,1000")
    parser.add_argument("--quick", action="store_true", help="Run the small local comparison suite. This is currently the default.")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Live model name to record/use; default {DEFAULT_MODEL}")
    parser.add_argument("--live-base-url", help="Optional OpenAI-compatible base URL, for example http://127.0.0.1:8000/v1")
    parser.add_argument("--api-key-env", help="Optional env var name containing an API key for the live OpenAI-compatible endpoint.")
    parser.add_argument("--hermes-command", help="Optional Hermes command template. Supports {prompt_file}, {output_file}, {model}, {case_id}, {mode}, {budget}.")
    parser.add_argument("--openclaw-command", help="Optional OpenClaw command template. Supports {prompt_file}, {output_file}, {model}, {case_id}, {mode}, {budget}.")
    parser.add_argument("--live-timeout", type=float, default=120.0, help="Seconds before one live model/agent call is marked failed.")
    args = parser.parse_args(argv)

    fixture = args.fixture.resolve()
    data = read_json(fixture)
    cases = list(data["cases"])
    budgets = parse_budgets(args.budgets)
    output_dir = prepare_output_dir(args.output_dir, benchmark="EricMemoryBench")
    command = sanitize_command([Path(sys.executable).name, *(argv if argv is not None else sys.argv[1:])])
    rows: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="eric-memory-bench-") as tmp:
        trial_count = len(cases) * len(budgets) * len(MODES)
        env = environment(command, fixture, args, trial_count)
        for budget in budgets:
            for mode in MODES:
                for case in cases:
                    root = Path(tmp) / f"{case['id']}-{mode}-{budget}"
                    if mode.startswith("epic_continuum"):
                        build_corpus(root, [case], include_fixture_cards=mode == "epic_continuum_card_assisted")
                    rows.append(evaluate_case(root, case, mode, int(budget), args, output_dir))
        env["finish_timestamp"] = utc_now()

    summary = {
        "benchmark": data["name"],
        "benchmark_version": data["version"],
        "case_count": len(cases),
        "budgets": budgets,
        "modes": MODES,
        "environment_file": "environment.json",
        "cases_file": "cases.jsonl",
        "live_runs_are_optional": True,
        "live_run_note": (
            "Rows without --live-base-url, --hermes-command, or --openclaw-command are deterministic context-quality checks. "
            "Live rows measure answer behavior for the configured local model/agent only."
        ),
        **aggregate(rows),
    }
    write_json(output_dir / "environment.json", env)
    write_json(output_dir / "summary.json", summary)
    append_jsonl(output_dir / "cases.jsonl", rows)
    (output_dir / "commands.txt").write_text(command + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "output_dir": str(output_dir), "case_count": len(cases), "record_count": len(rows)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
