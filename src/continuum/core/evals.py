from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from .permissions import secure_mkdir, secure_write_text
from .store import append_scroll_event, compile_context, ingest_file, recover_thread, roll_scroll_segment, search_memory, unique_id


def _score_contains(text: str, expected: list[str], forbidden: list[str]) -> dict[str, Any]:
    lowered = text.casefold()
    hits = [item for item in expected if item.casefold() in lowered]
    misses = [item for item in expected if item.casefold() not in lowered]
    forbidden_hits = [item for item in forbidden if item.casefold() in lowered]
    possible = max(1, len(expected) + len(forbidden))
    score = (len(hits) + (len(forbidden) - len(forbidden_hits))) / possible
    return {
        "score": round(score, 4),
        "hits": hits,
        "misses": misses,
        "forbidden_hits": forbidden_hits,
        "ok": not misses and not forbidden_hits,
    }


def run_memory_quality_evals(root: Path, *, keep_artifacts: bool = False) -> dict[str, Any]:
    """Run deterministic recall/recovery evals in a disposable nested root."""
    eval_id = unique_id("eval")
    eval_root = root / "run" / "evals" / eval_id / "root"
    secure_mkdir(eval_root.parent)
    session_id = "eval-aurora"
    append_scroll_event(
        eval_root,
        session_id=session_id,
        event_type="message",
        role="user",
        content="Project Aurora decision: keep blue reactor notes hot and verify copper gasket tasks.",
    )
    append_scroll_event(
        eval_root,
        session_id=session_id,
        event_type="message",
        role="assistant",
        content="Open task: run the copper gasket verification before archiving Aurora notes.",
    )
    roll_scroll_segment(eval_root, session_id=session_id, start_seq=1, end_seq=2)
    source = eval_root / "run" / "eval_source" / "aurora-notes.txt"
    secure_write_text(source, "Aurora copper gasket verification belongs in the hot project notes.\n")
    ingest_file(eval_root, path=source, title="Aurora Eval Notes")
    context = compile_context(
        eval_root,
        session_id=session_id,
        query="Aurora copper gasket verification",
        token_budget=1600,
        card_scope="session_then_global",
    )
    recovery = recover_thread(
        eval_root,
        session_id=session_id,
        query="Aurora copper gasket verification",
        token_budget=1600,
    )
    search = search_memory(eval_root, query="Aurora copper gasket", limit=5, create=False)
    context_score = _score_contains(
        context["context_text"],
        ["Aurora", "copper gasket", "verify"],
        ["unrelated forbidden marker"],
    )
    recovery_score = _score_contains(
        recovery["packet_text"],
        ["Aurora", "copper gasket", "Open task"],
        ["unrelated forbidden marker"],
    )
    search_score = {
        "ok": bool(search.get("results")),
        "score": 1.0 if search.get("results") else 0.0,
        "result_count": search.get("result_count", 0),
    }
    scores = {
        "context": context_score,
        "recovery": recovery_score,
        "search": search_score,
    }
    ok = all(item.get("ok", False) for item in scores.values())
    result = {
        "ok": ok,
        "eval_id": eval_id,
        "eval_root": str(eval_root),
        "scores": scores,
        "overall_score": round(sum(float(item.get("score", 0.0)) for item in scores.values()) / len(scores), 4),
        "context_estimated_tokens": context.get("estimated_tokens"),
        "recovery_packet_uri": recovery.get("packet_uri"),
    }
    if not keep_artifacts:
        shutil.rmtree(eval_root.parent, ignore_errors=True)
        result["eval_root_removed"] = True
    else:
        result["eval_root_removed"] = False
    return result
