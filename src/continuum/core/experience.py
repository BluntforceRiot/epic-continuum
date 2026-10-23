"""Recorded attempts and explicitly reviewed procedure suggestions.

Success is the caller's reported outcome, never a claim that Continuum executed
or independently verified a procedure. Exact citations establish provenance and
current availability; accepting a proposal confers no instruction authority.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from .investigation import _evaluated as _evaluated_investigation
from .knowledge_records import (
    append_record,
    bounded_results,
    read_records,
    require_text,
    validate_evidence,
)
from .safety import scan_value_for_secrets
from .store import canonical_partition_identifier

_KINDS = ("experience", "procedure", "procedure_review")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_MATCH_FIELDS = ("goal", "approach", "prerequisites", "steps")


def _identifier(value: Any, name: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(f"{name} must be a portable identifier of at most 128 characters")
    return value


def _project(root: Path, value: Any) -> str:
    require_text(value, "project_id", 256)
    project = canonical_partition_identifier(root, "project_id", value, lookup=True)
    if not project:
        raise ValueError("project_id is required")
    return project


def _prerequisites(value: Any) -> dict[str, str]:
    if type(value) is not dict or len(value) > 16:
        raise ValueError("prerequisites must be an object with at most 16 text entries")
    result = {}
    for key, item in value.items():
        require_text(key, "prerequisite name", 64)
        result[key] = require_text(item, "prerequisite value", 256)
    if scan_value_for_secrets(result, scope="experience prerequisites"):
        raise ValueError("prerequisites must not contain credential-like material")
    return result


def _steps(value: Any) -> list[str]:
    if type(value) is not list or not 1 <= len(value) <= 32:
        raise ValueError("steps must contain between 1 and 32 actual text steps")
    return [require_text(item, "step", 1024) for item in value]


def _citations(value: Any, *, required: bool = False) -> list[dict[str, str]]:
    if type(value) is not list or not int(required) <= len(value) <= 16:
        raise ValueError("verification must contain at most 16 exact citations")
    seen: set[tuple[str, str]] = set()
    for item in value:
        if type(item) is not dict or set(item) != {"kind", "id", "content_hash"}:
            raise ValueError("verification requires exact source citations")
        if type(item["kind"]) is not str or item["kind"] not in ("card", "chunk", "scroll_event"):
            raise ValueError("unsupported verification source kind")
        _identifier(item["id"], "verification source id")
        if type(item["content_hash"]) is not str or _HASH.fullmatch(item["content_hash"]) is None:
            raise ValueError("verification requires a SHA-256 content hash")
        identity = item["kind"], item["id"]
        if identity in seen:
            raise ValueError("verification citations must be unique")
        seen.add(identity)
    return value


def _payload(value: Any, kind: str) -> dict[str, Any]:
    if type(value) is not dict or type(value.get("schema")) is not int or value["schema"] != 1:
        raise ValueError("unsupported experience payload")
    if kind == "experience":
        if set(value) != {"schema", *_MATCH_FIELDS, "outcome", "observed_result", "verification", "corrects"}:
            raise ValueError("invalid experience fields")
        if type(value["outcome"]) is not str or value["outcome"] not in ("success", "failure"):
            raise ValueError("outcome must be success or failure")
        require_text(value["observed_result"], "observed_result", 4000)
        _citations(value["verification"], required=value["outcome"] == "success")
        if value["corrects"] is not None:
            _identifier(value["corrects"], "corrects")
    elif kind == "procedure":
        if set(value) != {"schema", *_MATCH_FIELDS, "title", "support", "verification"}:
            raise ValueError("invalid procedure fields")
        require_text(value["title"], "title", 240)
        support = value["support"]
        if type(support) is not list or not 2 <= len(support) <= 16:
            raise ValueError("procedures require 2 to 16 distinct supporting attempts")
        seen = set()
        for item in support:
            if type(item) is not dict or set(item) != {"id", "content_hash"}:
                raise ValueError("invalid supporting attempt citation")
            _identifier(item["id"], "support id")
            if type(item["content_hash"]) is not str or _HASH.fullmatch(item["content_hash"]) is None:
                raise ValueError("invalid supporting attempt hash")
            if item["id"] in seen:
                raise ValueError("supporting attempts must be distinct")
            seen.add(item["id"])
        _citations(value["verification"], required=True)
        if len(value["verification"]) < 2:
            raise ValueError("procedures require at least two distinct verification sources")
    elif kind == "procedure_review":
        if set(value) != {"schema", "procedure_id", "decision", "reviewer", "reason", "previous_review_id"}:
            raise ValueError("invalid procedure review fields")
        _identifier(value["procedure_id"], "procedure_id")
        if type(value["decision"]) is not str or value["decision"] not in ("accept", "reject"):
            raise ValueError("decision must be accept or reject")
        require_text(value["reviewer"], "reviewer", 128)
        require_text(value["reason"], "reason", 2000)
        if value["previous_review_id"] is not None:
            _identifier(value["previous_review_id"], "previous_review_id")
    else:
        raise ValueError("unsupported experience record kind")
    if kind != "procedure_review":
        require_text(value["goal"], "goal", 512)
        require_text(value["approach"], "approach", 512)
        _prerequisites(value["prerequisites"])
        _steps(value["steps"])
    if scan_value_for_secrets(value, scope="experience"):
        raise ValueError("experience records must not contain credential-like material")
    return value


def _union_verification(records: list[dict[str, Any]]) -> list[dict[str, str]]:
    merged: dict[tuple[str, str], dict[str, str]] = {}
    for record in records:
        for item in record["payload"]["verification"]:
            key = item["kind"], item["id"]
            if key in merged and merged[key] != item:
                raise ValueError("supporting attempts cite conflicting source versions")
            merged[key] = dict(item)
    result = sorted(merged.values(), key=lambda item: (item["kind"], item["id"]))
    if not 2 <= len(result) <= 16:
        raise ValueError("procedures require 2 to 16 distinct verification sources")
    return result


def _matching(records: list[dict[str, Any]]) -> None:
    first = records[0]["payload"]
    if any(record["payload"]["outcome"] != "success" or any(
        record["payload"][field] != first[field] for field in _MATCH_FIELDS
    ) for record in records):
        raise ValueError("supporting attempts must be matching recorded successes")


def _history(
    root: Path, project_id: str, connection: sqlite3.Connection | None = None,
) -> tuple[list[dict[str, Any]], dict[str, str], dict[str, dict[str, Any]]]:
    records = read_records(root, project_id=project_id, kinds=_KINDS, connection=connection)
    earlier: dict[str, dict[str, Any]] = {}
    corrected: dict[str, str] = {}
    reviews: dict[str, dict[str, Any]] = {}
    for record in records:
        payload = _payload(record["payload"], record["kind"])
        _identifier(record["id"], "record id")
        if record["id"] in earlier:
            raise ValueError("duplicate experience record")
        if record["kind"] == "experience" and payload["corrects"] is not None:
            target = earlier.get(payload["corrects"])
            if (target is None or target["kind"] != "experience"
                    or target["id"] in corrected or target["order"] >= record["order"]
                    or target["payload"]["goal"] != payload["goal"]):
                raise ValueError("correction requires an earlier current attempt with the same goal")
            corrected[target["id"]] = record["id"]
        elif record["kind"] == "procedure":
            sources = []
            for citation in payload["support"]:
                source = earlier.get(citation["id"])
                if (source is None or source["kind"] != "experience" or source["id"] in corrected
                        or source["content_hash"] != citation["content_hash"] or source["order"] >= record["order"]):
                    raise ValueError("procedure support must cite earlier current attempts")
                sources.append(source)
            _matching(sources)
            if (any(payload[field] != sources[0]["payload"][field] for field in _MATCH_FIELDS)
                    or payload["verification"] != _union_verification(sources)):
                raise ValueError("procedure does not match its supporting attempts")
        elif record["kind"] == "procedure_review":
            target = earlier.get(payload["procedure_id"])
            current = reviews.get(payload["procedure_id"])
            expected = None if current is None else current["id"]
            if (target is None or target["kind"] != "procedure" or target["order"] >= record["order"]
                    or payload["previous_review_id"] != expected):
                raise ValueError("procedure review head changed or target is unavailable")
            reviews[payload["procedure_id"]] = record
        earlier[record["id"]] = record
    return records, corrected, reviews


def _freshness(root: Path, project_id: str, records: list[dict[str, Any]], corrected: dict[str, str]) -> dict[str, list[str]]:
    """Check current citations and known append-only replacement markers.

    This checks recorded memory, not external files or the truth of an outcome.
    Historical Scroll citations can remain readable after a file/fact revision;
    their explicit replacement markers therefore also invalidate reuse.
    """
    all_records = read_records(root, project_id=project_id)
    # Reuse investigation's recorded asset/build and linked-finding authority;
    # an old binary envelope can remain hash-readable after its build changed.
    investigation_stale = {row["id"] for row in _evaluated_investigation(root, project_id)
                           if row["needs_review"]}
    superseded = set(corrected)
    files: dict[str, dict[str, Any]] = {}
    for row in all_records:
        payload = row["payload"]
        if row["kind"] == "project_file":
            path, version = payload.get("path"), payload.get("version")
            if type(path) is not str or type(version) is not int or version < 1:
                raise ValueError("invalid recorded file version")
            prior = files.get(path)
            if prior is not None:
                if version <= prior["payload"]["version"]:
                    raise ValueError("ambiguous recorded file versions")
                superseded.add(prior["id"])
            files[path] = row
        elif row["kind"] == "temporal_fact" and payload.get("corrects") is not None:
            superseded.add(_identifier(payload["corrects"], "fact correction"))
    reasons: dict[str, list[str]] = {}
    for record in records:
        payload = record["payload"]
        found: set[str] = set()
        if record["id"] in corrected:
            found.add("corrected_attempt")
        for citation in payload.get("verification", []):
            try:
                validate_evidence(root, project_id, [citation])
            except ValueError:
                found.add("verification_source_unavailable_or_changed")
            if citation["kind"] == "scroll_event" and citation["id"] in superseded:
                found.add("verification_source_superseded")
            if citation["kind"] == "scroll_event" and citation["id"] in investigation_stale:
                found.add("verification_source_needs_review")
        if record["kind"] == "procedure":
            if any(source["id"] in corrected for source in payload["support"]):
                found.add("supporting_attempt_corrected")
            for source in payload["support"]:
                if reasons.get(source["id"]):
                    found.add("supporting_attempt_needs_review")
        reasons[record["id"]] = sorted(found)
    return reasons


def record_experience(
    root: Path, *, project_id: str, session_id: str, goal: str, approach: str,
    prerequisites: dict[str, str], steps: list[str], outcome: str, observed_result: str,
    verification: list[dict[str, str]] | None = None, corrects: str | None = None,
) -> dict[str, Any]:
    """Append a reported attempt; successes require exact verification citations."""
    project_id = _project(root, project_id)
    payload = {"schema": 1, "goal": goal, "approach": approach, "prerequisites": _prerequisites(prerequisites),
               "steps": _steps(steps), "outcome": outcome, "observed_result": observed_result,
               "verification": [] if verification is None else verification, "corrects": corrects}
    _payload(payload, "experience")
    payload["verification"] = validate_evidence(root, project_id, payload["verification"])

    def validate(conn: sqlite3.Connection, inserted: dict[str, Any]) -> None:
        _history(root, project_id, conn)
        validate_evidence(root, project_id, payload["verification"])

    return append_record(root, project_id=project_id, session_id=session_id, kind="experience",
                         payload=payload, validate=validate)


def propose_procedure(
    root: Path, *, project_id: str, session_id: str, experience_ids: list[str], title: str,
) -> dict[str, Any]:
    """Suggest reuse from matching recorded successes, without executing anything."""
    project_id = _project(root, project_id)
    require_text(title, "title", 240)
    if type(experience_ids) is not list or not 2 <= len(experience_ids) <= 16:
        raise ValueError("experience_ids must contain 2 to 16 distinct attempt IDs")
    ids = [_identifier(value, "experience id") for value in experience_ids]
    if len(set(ids)) != len(ids):
        raise ValueError("experience_ids must be distinct")
    records, corrected, _ = _history(root, project_id)
    by_id = {record["id"]: record for record in records if record["kind"] == "experience"}
    if any(source_id not in by_id or source_id in corrected for source_id in ids):
        raise ValueError("supporting attempt is not current in this project")
    sources = [by_id[source_id] for source_id in ids]
    _matching(sources)
    freshness = _freshness(root, project_id, records, corrected)
    if any(freshness[source["id"]] for source in sources):
        raise ValueError("supporting evidence is stale and needs review")
    payload = {"schema": 1, "title": title, **{key: sources[0]["payload"][key] for key in _MATCH_FIELDS},
               "support": [{"id": source["id"], "content_hash": source["content_hash"]} for source in sources],
               "verification": _union_verification(sources)}
    _payload(payload, "procedure")

    def validate(conn: sqlite3.Connection, inserted: dict[str, Any]) -> None:
        current, corrections, _ = _history(root, project_id, conn)
        if _freshness(root, project_id, current, corrections)[inserted["id"]]:
            raise ValueError("supporting evidence changed concurrently")
        validate_evidence(root, project_id, payload["verification"])

    return append_record(root, project_id=project_id, session_id=session_id, kind="procedure",
                         payload=payload, validate=validate)


def review_procedure(
    root: Path, *, project_id: str, session_id: str, procedure_id: str, decision: str,
    reviewer: str, reason: str, expected_review_id: str | None = None,
) -> dict[str, Any]:
    """Append accept/reject against an exact head; attribution is not authentication."""
    project_id = _project(root, project_id)
    payload = {"schema": 1, "procedure_id": procedure_id, "decision": decision,
               "reviewer": reviewer, "reason": reason, "previous_review_id": expected_review_id}
    _payload(payload, "procedure_review")
    records, corrected, _ = _history(root, project_id)
    if decision == "accept":
        freshness = _freshness(root, project_id, records, corrected)
        if procedure_id not in freshness or freshness[procedure_id]:
            raise ValueError("procedure evidence is unavailable or needs review")

    def validate(conn: sqlite3.Connection, inserted: dict[str, Any]) -> None:
        current, corrections, _ = _history(root, project_id, conn)
        proposal = next(row for row in current if row["id"] == procedure_id)
        if decision == "accept":
            if _freshness(root, project_id, current, corrections)[procedure_id]:
                raise ValueError("supporting evidence changed concurrently")
            validate_evidence(root, project_id, proposal["payload"]["verification"])

    return append_record(root, project_id=project_id, session_id=session_id, kind="procedure_review",
                         payload=payload, validate=validate)


def _view(record: dict[str, Any], corrected: dict[str, str], reviews: dict[str, dict[str, Any]],
          freshness: dict[str, list[str]]) -> dict[str, Any]:
    result = {key: record[key] for key in ("id", "project_id", "recorded_at", "kind", "payload")}
    result.update(citation={"kind": "scroll_event", "id": record["id"], "content_hash": record["content_hash"]},
                  needs_review=bool(freshness[record["id"]]), review_reasons=freshness[record["id"]],
                  truth_status="recorded_claim_not_independently_verified")
    if record["kind"] == "experience":
        result["corrected_by"] = corrected.get(record["id"])
    elif record["kind"] == "procedure":
        review = reviews.get(record["id"])
        result.update(inference=True, review_state="proposed" if review is None else review["payload"]["decision"],
                      review_id=None if review is None else review["id"],
                      review_citation=None if review is None else {
                          "kind": "scroll_event", "id": review["id"], "content_hash": review["content_hash"]},
                      auto_apply=False)
    return result


def query_experiences(
    root: Path, *, project_id: str, query: str | None = None,
    include_history: bool = True, token_budget: int = 2400,
) -> dict[str, Any]:
    """Return bounded complete attempts/proposals/reviews, with failed history retained."""
    project_id = _project(root, project_id)
    if type(include_history) is not bool:
        raise ValueError("include_history must be a boolean")
    needle = None if query is None else require_text(query, "query", 1024).casefold()
    records, corrected, reviews = _history(root, project_id)
    freshness = _freshness(root, project_id, records, corrected)
    selected = [_view(row, corrected, reviews, freshness) for row in reversed(records)
                if (include_history or row["id"] not in corrected)
                and (needle is None or needle in json.dumps(row["payload"], ensure_ascii=False).casefold())]
    return bounded_results(selected, token_budget=token_budget,
                           extra={"project_id": project_id, "include_history": include_history,
                                  "freshness": "current_recorded_evidence_only", "executed": False,
                                  "query_hash": None if query is None else hashlib.sha256(query.encode()).hexdigest()})


def find_reusable_lessons(
    root: Path, *, source_projects: list[str], goal: str,
    prerequisites: dict[str, str], accepted_only: bool = True, token_budget: int = 2400,
) -> dict[str, Any]:
    """Shortlist explicit projects' procedures with provenance and applicability differences.

    Never searches other projects or session/private/global memory. The caller
    selects source projects explicitly; results do not copy or apply procedures.
    Stale accepted proposals remain visible as needing review, not reusable proof.
    """
    if type(source_projects) is not list or not 1 <= len(source_projects) <= 16:
        raise ValueError("source_projects must name 1 to 16 explicit projects")
    projects = [_project(root, item) for item in source_projects]
    if len(set(projects)) != len(projects):
        raise ValueError("source_projects must be distinct")
    goal = require_text(goal, "goal", 512)
    wanted = _prerequisites(prerequisites)
    if type(accepted_only) is not bool:
        raise ValueError("accepted_only must be a boolean")
    selected = []
    for project_id in projects:
        records, corrected, reviews = _history(root, project_id)
        freshness = _freshness(root, project_id, records, corrected)
        for record in records:
            if record["kind"] != "procedure" or goal.casefold() not in record["payload"]["goal"].casefold():
                continue
            review = reviews.get(record["id"])
            if accepted_only and (review is None or review["payload"]["decision"] != "accept"):
                continue
            required = record["payload"]["prerequisites"]
            matches = sorted(key for key in required if key in wanted and required[key] == wanted[key])
            missing = sorted(key for key in required if key not in wanted)
            differences = {key: {"required": required[key], "provided": wanted[key]}
                           for key in sorted(required) if key in wanted and required[key] != wanted[key]}
            item = _view(record, corrected, reviews, freshness)
            item["applicability"] = {"matched": matches, "missing": missing, "differences": differences,
                                     "additional": sorted(set(wanted) - set(required)),
                                     "prerequisites_match": not missing and not differences,
                                     "applied": False}
            selected.append(item)
    selected.sort(key=lambda item: (bool(item["needs_review"]), not item["applicability"]["prerequisites_match"],
                                    item["project_id"], item["id"]))
    return bounded_results(selected, token_budget=token_budget,
                           extra={"source_project_count": len(projects), "accepted_only": accepted_only,
                                  "scope": "explicit_projects_only", "auto_apply": False,
                                  "goal_hash": hashlib.sha256(goal.encode()).hexdigest()})
