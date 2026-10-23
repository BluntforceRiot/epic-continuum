"""Offline, temporary-root evaluation of Continuum's public lexical retrieval APIs."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from continuum import __version__  # noqa: E402
from continuum.core.config import default_config, write_config  # noqa: E402
from continuum.core.safety import scan_value_for_secrets  # noqa: E402
from continuum.core.store import ingest_file, read_memory_chunk, search_memory  # noqa: E402
from continuum.core.tool_outputs import record_indexed_tool_result  # noqa: E402


MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_DOCUMENT_CHARS = 256 * 1024
MAX_CORPUS_CHARS = 1024 * 1024
SESSION_ID = "recall-quality-isolated"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


def _object(value: Any, required: set[str], optional: set[str], label: str) -> dict:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise ValueError(f"{label}: missing, unknown, or invalid object fields")
    return value


def _text(value: Any, label: str, maximum: int, *, empty: bool = False) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip()):
        raise ValueError(f"{label}: expected {'possibly empty ' if empty else ''}text of at most {maximum} characters")
    if any(ord(char) < 32 and char not in "\r\n\t" for char in value):
        raise ValueError(f"{label}: control characters are not supported")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError(f"{label}: invalid Unicode") from exc
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"{label}: expected a 1-64 character portable identifier")
    return value


def _integer(value: Any, label: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{label}: expected an integer from {low} to {high}")
    return value


def _list(value: Any, label: str, maximum: int, *, minimum: int = 0) -> list:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ValueError(f"{label}: expected {minimum}-{maximum} entries")
    return value


def _strings(value: Any, label: str, maximum: int = 16, *, identifiers: bool = False) -> list[str]:
    items = _list(value, label, maximum)
    for item in items:
        _identifier(item, label) if identifiers else _text(item, label, 256)
    if len(set(items)) != len(items):
        raise ValueError(f"{label}: duplicate entries")
    return items


def _unique_object(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON contains a duplicate object field")
        result[key] = value
    return result


def _invalid_constant(_value: str) -> None:
    raise ValueError("JSON must not contain non-finite numbers")


def _read_json(path: Path) -> tuple[Any, str]:
    # Read a bounded snapshot once; the hash always describes the bytes evaluated.
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError(f"JSON input exceeds {MAX_JSON_BYTES} bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Input must be bounded, valid UTF-8 JSON") from exc
    return value, hashlib.sha256(raw).hexdigest()


def load_fixture(path: Path) -> tuple[dict, str]:
    """Validate all labels before creating a memory root; never coerce malformed data."""
    value, digest = _read_json(path)
    _object(value, {"schema_version", "name", "split", "description", "documents", "cases"}, set(), "fixture")
    _integer(value["schema_version"], "schema_version", 1, 1)
    _text(value["name"], "name", 200)
    _text(value["description"], "description", 2000)
    if value["split"] not in ("synthetic_regression", "external_held_out"):
        raise ValueError("split must be synthetic_regression or external_held_out")
    documents, content_hashes, total = {}, set(), 0
    for doc in _list(value["documents"], "documents", 100, minimum=1):
        _object(doc, {"id", "kind", "title", "text"}, {"prefix_text", "prefix_repeat"}, "document")
        source_id = _identifier(doc["id"], "document.id")
        if source_id in documents:
            raise ValueError("document.id: duplicate identifier")
        if doc["kind"] not in ("file", "tool_result"):
            raise ValueError("document.kind must be file or tool_result")
        _text(doc["title"], "document.title", 200)
        body = _text(doc["text"], "document.text", MAX_DOCUMENT_CHARS)
        if ("prefix_text" in doc) != ("prefix_repeat" in doc):
            raise ValueError("prefix_text and prefix_repeat must be supplied together")
        prefix = _text(doc.get("prefix_text", ""), "prefix_text", 4000, empty=True)
        repeat = _integer(doc.get("prefix_repeat", 0), "prefix_repeat", 0, 5000)
        size = len(prefix) * repeat + len(body)
        total += size
        if size > MAX_DOCUMENT_CHARS or total > MAX_CORPUS_CHARS:
            raise ValueError("expanded document or corpus character limit exceeded")
        expanded = prefix * repeat + body
        if doc["kind"] == "tool_result" and len(expanded.encode("utf-8")) <= 128:
            raise ValueError("tool_result must exceed the isolated 128-byte capture threshold")
        content_hash = hashlib.sha256(expanded.encode("utf-8")).hexdigest()
        if content_hash in content_hashes:
            raise ValueError("duplicate document content would alias a public Library source")
        content_hashes.add(content_hash)
        documents[source_id] = {**doc, "text": expanded, "sha256": content_hash}
    case_ids = set()
    for case in _list(value["cases"], "cases", 200, minimum=1):
        _object(case, {"id", "category", "query", "relevant_source_ids", "expected_answers"},
                {"required_evidence", "forbidden_evidence"}, "case")
        case_id = _identifier(case["id"], "case.id")
        if case_id in case_ids:
            raise ValueError("case.id: duplicate identifier")
        case_ids.add(case_id)
        _identifier(case["category"], "case.category")
        _text(case["query"], "case.query", 512)
        relevant = _strings(case["relevant_source_ids"], "relevant_source_ids", 100, identifiers=True)
        if set(relevant) - documents.keys():
            raise ValueError("case references unknown relevant sources")
        answers = _strings(case["expected_answers"], "expected_answers")
        required = _strings(case.get("required_evidence", []), "required_evidence")
        forbidden = _strings(case.get("forbidden_evidence", []), "forbidden_evidence")
        if bool(relevant) != bool(answers) or (not relevant and required):
            raise ValueError("answerable cases need sources and answers; no-answer cases need neither")
        if any(not any(answer in documents[source]["text"] for source in relevant) for answer in answers + required):
            raise ValueError("expected answers and required evidence must occur literally in a relevant source")
        if any(not any(marker in doc["text"] for doc in documents.values()) for marker in forbidden):
            raise ValueError("forbidden evidence must occur literally in the corpus")
        if set(required) & set(forbidden):
            raise ValueError("required and forbidden evidence overlap")
    normalized = {**value, "documents": list(documents.values())}
    if scan_value_for_secrets(normalized, scope="recall_fixture", max_findings=1):
        raise ValueError("fixture secret scan blocked evaluation; supply safe data only")
    return normalized, digest


def load_answers(path: Path, fixture: dict, fixture_sha256: str) -> tuple[dict[str, dict], str]:
    value, digest = _read_json(path)
    _object(value, {"schema_version", "fixture_sha256", "records"}, set(), "answers")
    _integer(value["schema_version"], "answers.schema_version", 1, 1)
    if value["fixture_sha256"] != fixture_sha256:
        raise ValueError("answer artifact fixture_sha256 does not match evaluated bytes")
    source_ids = {doc["id"] for doc in fixture["documents"]}
    case_ids = {case["id"] for case in fixture["cases"]}
    records = {}
    for record in _list(value["records"], "answer records", 200, minimum=1):
        _object(record, {"case_id", "answer", "abstained", "cited_source_ids"}, set(), "answer record")
        case_id = _identifier(record["case_id"], "answer.case_id")
        if case_id not in case_ids or case_id in records:
            raise ValueError("answer records contain an unknown or duplicate case")
        answer = _text(record["answer"], "answer", 4000, empty=True)
        if type(record["abstained"]) is not bool:
            raise ValueError("abstained must be boolean")
        cited = _strings(record["cited_source_ids"], "cited_source_ids", 100, identifiers=True)
        if set(cited) - source_ids:
            raise ValueError("answer references unknown cited sources")
        if record["abstained"] and (answer != "" or cited):
            raise ValueError("abstained records require an empty answer and no citations")
        if not record["abstained"] and not answer.strip():
            raise ValueError("non-abstained records require a nonempty answer")
        records[case_id] = record
    if records.keys() != case_ids:
        raise ValueError("answer artifact must contain exactly one record for every case")
    if scan_value_for_secrets(value, scope="recall_answers", max_findings=1):
        raise ValueError("answer artifact secret scan blocked evaluation")
    return records, digest


def _offline_score(case: dict, record: dict, documents: dict[str, dict]) -> dict:
    relevant = set(case["relevant_source_ids"])
    exact = not record["abstained"] and record["answer"] in case["expected_answers"]
    cited = set(record["cited_source_ids"])
    supported = exact and bool(cited) and cited <= relevant and any(
        record["answer"] in documents[source]["text"] for source in cited
    )
    return {
        "exact_answer_match": bool(exact) if relevant else None,
        "supported_exact_answer": bool(supported) if relevant else None,
        "abstention_correct": record["abstained"] if not relevant else None,
        "correct": bool(supported) if relevant else record["abstained"],
    }


def _average(rows: list[dict], field: str) -> float | None:
    values = [row[field] for row in rows if row[field] is not None]
    return mean(values) if values else None


def _evaluate_case(root: Path, case: dict, sources: dict[str, str], top_k: int, context_chars: int) -> dict:
    start = time.perf_counter()
    result = search_memory(root, query=case["query"], limit=top_k)
    retrieval_ms = (time.perf_counter() - start) * 1000
    if not result.get("initialized"):
        raise RuntimeError("evaluation corpus unexpectedly uninitialized")
    hits = result["results"]
    if result["result_count"] != len(hits) or len(hits) > top_k:
        raise RuntimeError("search result count violated the public API contract")
    ranks = {}
    for rank, hit in enumerate(hits, 1):
        if hit["book_id"] not in sources:
            raise RuntimeError("search returned a source outside the isolated corpus")
        ranks.setdefault(sources[hit["book_id"]], rank)
    relevant = set(case["relevant_source_ids"])
    first_rank = min((rank for source, rank in ranks.items() if source in relevant), default=None)
    context, selections, selected_texts = "", [], []
    start = time.perf_counter()
    for hit in hits:
        source = sources[hit["book_id"]]
        header = ("\n\n" if context else "") + f"[source:{source}]\n"
        remaining = context_chars - len(context) - len(header)
        if remaining <= 0:
            break
        detail = read_memory_chunk(root, chunk_id=hit["chunk_id"], offset=hit["excerpt_start"],
                                   limit=min(2000, remaining))
        if not detail.get("found") or detail["book_id"] != hit["book_id"] or not detail["content"]:
            raise RuntimeError("selected evidence was missing or mismatched")
        if len(detail["content"]) > min(2000, remaining):
            raise RuntimeError("selected evidence exceeded the read limit")
        context += header + detail["content"]
        selected_texts.append(detail["content"])
        selections.append({"source_id": source, "chunk_id": hit["chunk_id"],
                           "offset": detail["offset"], "content_chars": len(detail["content"])})
    selection_ms = (time.perf_counter() - start) * 1000
    required = case.get("required_evidence", [])
    forbidden = case.get("forbidden_evidence", [])
    required_found = [marker for marker in required if any(marker in text for text in selected_texts)]
    forbidden_found = [marker for marker in forbidden if any(marker in text for text in selected_texts)]
    return {
        "case_id": case["id"], "category": case["category"], "answerable": bool(relevant),
        "backend": result["backend"], "returned_chunks": len(hits), "source_first_chunk_ranks": ranks,
        "source_recall_at_k": len(relevant & ranks.keys()) / len(relevant) if relevant else None,
        "source_top1_correct": bool(first_rank == 1) if relevant else None,
        "first_relevant_chunk_rank": first_rank,
        "reciprocal_rank_at_k": (1 / first_rank if first_rank else 0.0) if relevant else None,
        "retrieval_abstained": not hits,
        "no_answer_abstention_correct": not hits if not relevant else None,
        "answerable_false_abstention": not hits if relevant else None,
        "selected_context": context, "selected_context_chars": len(context),
        "selected_context_rough_tokens": (len(context) + 3) // 4,
        "selections": selections,
        "required_evidence_found": required_found,
        "required_evidence_rate": len(required_found) / len(required) if required else None,
        "forbidden_evidence_found": forbidden_found,
        "retrieval_latency_ms": retrieval_ms, "selection_latency_ms": selection_ms,
    }


def evaluate(fixture_path: Path, *, answers_path: Path | None = None, top_k: int = 3,
             context_chars: int = 4000) -> dict:
    """Run in a fresh disposable root only. No root override, network, model or worker run."""
    _integer(top_k, "top_k", 1, 20)
    _integer(context_chars, "context_chars", 1, 8000)
    fixture, fixture_hash = load_fixture(fixture_path)
    records, answer_hash = load_answers(answers_path, fixture, fixture_hash) if answers_path else ({}, None)
    documents = {doc["id"]: doc for doc in fixture["documents"]}
    rows = []
    with tempfile.TemporaryDirectory(prefix="continuum-recall-quality-") as directory:
        workspace = Path(directory)
        root = workspace / "memory"
        config = default_config()
        config["local_inference"]["enabled"] = False
        config["capture"].update({"mode": "manual", "large_result_policy": "index_and_link", "max_tool_result_bytes": "128B"})
        write_config(root, config)
        sources = {}
        for index, doc in enumerate(documents.values()):
            if doc["kind"] == "file":
                path = workspace / f"source-{index}.txt"
                path.write_text(doc["text"], encoding="utf-8", newline="")
                ingested = ingest_file(root, path=path, title=doc["title"])
            else:
                # File ingestion is global. Use the indexed-result API's explicit
                # global scope too, without widening or merging search partitions.
                ingested = record_indexed_tool_result(
                    root, session_id=SESSION_ID, event_type="recall_quality_tool_result", text=doc["text"],
                    metadata={"visibility_scope": "global", "tool_name": doc["title"]}, max_reference_bytes=128,
                )
                if not ingested or not ingested.get("output_preserved"):
                    raise RuntimeError("tool-result fixture was not preserved by the indexed-result API")
            book_id = ingested["book_id"]
            if book_id in sources:
                raise RuntimeError("public ingestion unexpectedly aliased two fixture sources")
            sources[book_id] = doc["id"]
        for case in fixture["cases"]:
            row = _evaluate_case(root, case, sources, top_k, context_chars)
            row["offline_answer"] = _offline_score(case, records[case["id"]], documents) if records else None
            rows.append(row)
    offline = [row["offline_answer"] for row in rows if row["offline_answer"] is not None]
    return {
        "schema_version": 1, "benchmark": "ContinuumRecallQuality", "status": "measured",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "fixture": {"name": fixture["name"], "split": fixture["split"], "sha256": fixture_hash,
                    "held_out_independence_verified": False,
                    "documents": [{"id": doc["id"], "kind": doc["kind"], "expanded_sha256": doc["sha256"],
                                   "chars": len(doc["text"])} for doc in documents.values()]},
        "answers_sha256": answer_hash,
        "runtime": {"continuum_version": __version__, "python_version": platform.python_version(),
                    "sqlite_version": sqlite3.sqlite_version, "temporary_root_only": True,
                    "model_calls": 0, "network_calls": 0},
        "parameters": {"top_k_chunks": top_k, "context_chars": context_chars,
                       "per_chunk_read_chars": 2000, "scope": "global_in_disposable_root",
                       "rough_token_method": "ceil(characters / 4)"},
        "summary": {
            "case_count": len(rows), "answerable_count": sum(row["answerable"] for row in rows),
            "no_answer_count": sum(not row["answerable"] for row in rows),
            "mean_source_recall_at_k": _average(rows, "source_recall_at_k"),
            "source_top1_accuracy": _average(rows, "source_top1_correct"),
            "mean_reciprocal_rank_at_k": _average(rows, "reciprocal_rank_at_k"),
            "no_answer_retrieval_abstention_accuracy": _average(rows, "no_answer_abstention_correct"),
            "answerable_false_abstention_rate": _average(rows, "answerable_false_abstention"),
            "mean_selected_context_chars": _average(rows, "selected_context_chars"),
            "mean_selected_context_rough_tokens": _average(rows, "selected_context_rough_tokens"),
            "mean_required_evidence_rate": _average(rows, "required_evidence_rate"),
            "cases_with_forbidden_context_evidence": sum(bool(row["forbidden_evidence_found"]) for row in rows),
            "mean_retrieval_latency_ms": _average(rows, "retrieval_latency_ms"),
            "max_retrieval_latency_ms": max(row["retrieval_latency_ms"] for row in rows),
            "mean_selection_latency_ms": _average(rows, "selection_latency_ms"),
            "offline_answer_record_count": len(offline),
            "offline_exact_answer_accuracy": _average(offline, "exact_answer_match"),
            "offline_supported_exact_answer_accuracy": _average(offline, "supported_exact_answer"),
            "offline_no_answer_abstention_accuracy": _average(offline, "abstention_correct"),
            "offline_combined_accuracy": _average(offline, "correct"),
        },
        "cases": rows,
        "limitations": [
            "Synthetic regression examples are not held-out evidence; external split labels are caller declarations.",
            "Lexical source retrieval is not semantic answer correctness or authoritative correction selection.",
            "Empty retrieval is only a retrieval abstention proxy, not an agent refusal or calibrated confidence.",
            "Offline answers use literal whitelist/citation checks, not semantic grading or proof of model execution.",
            "Context excludes the host prompt and output; rough tokens are not model tokenizer counts.",
            "One serial in-process query per case after ingestion; latency is not live-host or cold-cache certification.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True, type=Path, help="Explicit safe JSON corpus; never a live memory root")
    parser.add_argument("--answers", type=Path, help="Optional complete, fixture-hash-bound offline answer JSON")
    parser.add_argument("--top-k", type=int, default=3, help="Returned chunk cutoff (1-20)")
    parser.add_argument("--context-chars", type=int, default=4000, help="Selected context character cap (1-8000)")
    parser.add_argument("--output", type=Path, help="New JSON report file; existing files are never overwritten")
    args = parser.parse_args(argv)
    try:
        if args.output is not None and args.output.exists():
            raise ValueError("output already exists; choose a new report path")
        report = evaluate(args.fixture, answers_path=args.answers, top_k=args.top_k, context_chars=args.context_chars)
        text = json.dumps(report, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
        if args.output is None:
            print(text, end="")
        else:
            with args.output.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(text)
    except (ValueError, OSError, RuntimeError) as exc:
        parser.exit(2, f"recall-quality: {type(exc).__name__}: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
