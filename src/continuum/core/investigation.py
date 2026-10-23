"""Explicit, evidence-bound investigation memory, without extraction or execution.

Assets retain hashes and relative locators, never original bytes. Findings and
annotations are supplied claims, not automatic binary/media analysis or truth.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import stat
from collections import deque
from pathlib import Path
from typing import Any

from .knowledge_records import (
    append_record,
    bounded_results,
    read_records,
    require_text,
    validate_evidence,
)
from .project_knowledge import (
    _equivalent_path,
    _identifier,
    _is_link,
    _project,
    _read_file,
    _relative_path,
    _resolved_relative,
    _source_root,
    _text,
    _validate_payload as _validate_project_payload,
)
from .safety import scan_text_for_secrets

MAX_ASSET_BYTES = 32 * 1024 * 1024
_ASSETS = frozenset({"binary", "image", "pdf", "audio", "video", "table", "transcript"})
_NOTE_KINDS = frozenset(
    {"observation", "experiment", "hypothesis", "competing_explanation", "conclusion"}
)
_RELATIONS = frozenset(
    {"observed_from", "tests", "supports", "contradicts", "explains", "related_to"}
)
_KINDS = ("analysis_asset", "analysis_finding", "media_annotation", "notebook_entry")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_ADDRESS = re.compile(r"0x[0-9a-fA-F]{1,16}\Z")


def _hash(value: Any, name: str) -> str:
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 hash")
    return value


def _integer(value: Any, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def _read_asset(directory: Path, relative: str) -> bytes:
    path = directory.joinpath(*relative.split("/"))
    try:
        for entry in (directory, *path.parents):
            if entry == directory or directory in entry.parents:
                info = entry.lstat()
                if _is_link(info) or not stat.S_ISDIR(info.st_mode):
                    raise ValueError("asset must not traverse links")
        before = path.lstat()
        if _is_link(before) or not stat.S_ISREG(before.st_mode):
            raise ValueError("asset must be a regular non-link file")
        if before.st_size > MAX_ASSET_BYTES:
            raise ValueError("asset exceeds the 32 MiB limit")
        if not path.resolve(strict=True).is_relative_to(directory):
            raise ValueError("asset escapes source_root")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError("asset changed while opening")
            raw = stream.read(MAX_ASSET_BYTES + 1)
            after = os.fstat(stream.fileno())
        final = path.lstat()
        if (
            len(raw) > MAX_ASSET_BYTES
            or (after.st_size, after.st_mtime_ns)
            != (opened.st_size, opened.st_mtime_ns)
            or (final.st_dev, final.st_ino) != (opened.st_dev, opened.st_ino)
            or (final.st_size, final.st_mtime_ns)
            != (opened.st_size, opened.st_mtime_ns)
            or not path.resolve(strict=True).is_relative_to(directory)
        ):
            raise ValueError("asset changed while reading")
        for entry in (path, *path.parents):
            if entry == directory or directory in entry.parents:
                if _is_link(entry.lstat()):
                    raise ValueError("asset changed to a link while reading")
        return raw
    except FileNotFoundError:
        raise FileNotFoundError("asset file is missing") from None
    except OSError:
        raise ValueError("asset is not readable") from None


def _scan_asset(raw: bytes) -> None:
    # No bytes are stored, but do not make credential files into source assets.
    text = raw.decode("utf-8-sig", errors="replace")
    if scan_text_for_secrets(text, max_findings=1):
        raise ValueError("asset contains credential-like data")
    try:
        plain = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return
    if not any(ord(char) < 32 and char not in "\r\n\t\f" for char in plain):
        _text(raw)  # Includes structured JSON/escaped credential checks.


def _anchor(value: Any) -> dict[str, Any]:
    if (
        type(value) is not dict
        or not value
        or set(value) - {"page", "region", "table", "time"}
    ):
        raise ValueError("anchor must contain page, region, table, or time")
    result = dict(value)
    if "page" in value and not _integer(value["page"], 1, 1000000):
        raise ValueError("page must be a positive bounded integer")
    if "region" in value:
        region = value["region"]
        if (
            type(region) is not list
            or len(region) != 4
            or any(
                type(n) not in (int, float) or not 0 <= n <= 1 or not math.isfinite(n)
                for n in region
            )
            or region[0] >= region[2]
            or region[1] >= region[3]
        ):
            raise ValueError("region must be normalized [left, top, right, bottom]")
        result["region"] = list(region)
    if "table" in value:
        table = value["table"]
        if (
            type(table) is not dict
            or set(table) != {"row_start", "row_end", "column_start", "column_end"}
            or any(not _integer(n, 1, 1000000) for n in table.values())
            or table["row_start"] > table["row_end"]
            or table["column_start"] > table["column_end"]
        ):
            raise ValueError("table must contain inclusive positive row/column bounds")
        result["table"] = dict(table)
    if "time" in value:
        timing = value["time"]
        if (
            type(timing) is not dict
            or set(timing) != {"start_ms", "end_ms"}
            or any(not _integer(n, 0, 31536000000) for n in timing.values())
            or timing["start_ms"] > timing["end_ms"]
        ):
            raise ValueError("time must contain ordered integer start_ms and end_ms")
        result["time"] = dict(timing)
    return result


def _evidence_shape(value: Any) -> None:
    if type(value) is not list or len(value) > 16:
        raise ValueError("evidence must contain at most 16 citations")
    seen = set()
    for item in value:
        if type(item) is not dict or set(item) != {"kind", "id", "content_hash"}:
            raise ValueError("evidence must contain exact citations")
        require_text(item["kind"], "evidence kind", 64)
        _identifier(item["id"], "evidence id")
        _hash(item["content_hash"], "content_hash")
        identity = (item["kind"], item["id"])
        if identity in seen:
            raise ValueError("duplicate evidence citation")
        seen.add(identity)


def _links(value: Any) -> list[dict[str, str]]:
    if value is None:
        return []
    if type(value) is not list or len(value) > 16:
        raise ValueError("links must contain at most 16 exact targets")
    result, seen = [], set()
    for item in value:
        if type(item) is not dict or set(item) != {
            "relation",
            "target_id",
            "content_hash",
        }:
            raise ValueError("links require relation, target_id, and content_hash")
        if type(item["relation"]) is not str or item["relation"] not in _RELATIONS:
            raise ValueError("unsupported investigation relation")
        _identifier(item["target_id"], "target_id")
        _hash(item["content_hash"], "content_hash")
        identity = (item["relation"], item["target_id"])
        if identity in seen:
            raise ValueError("duplicate investigation link")
        seen.add(identity)
        result.append(dict(item))
    return result


def _source_shape(value: Any) -> None:
    if value is None:
        return
    if type(value) is not dict or set(value) not in (
        {"record_id", "content_hash", "symbol"},
        {"record_id", "content_hash", "symbol", "line"},
    ):
        raise ValueError(
            "source_symbol requires record_id, content_hash, symbol, and optional line"
        )
    _identifier(value["record_id"], "source record_id")
    _hash(value["content_hash"], "source content_hash")
    require_text(value["symbol"], "source symbol", 512)
    if "line" in value and not _integer(value["line"], 1, 1000000):
        raise ValueError("source symbol line must be a positive bounded integer")


def _validate_payload(payload: Any, kind: str) -> None:
    if (
        type(payload) is not dict
        or type(payload.get("schema")) is not int
        or payload["schema"] != 1
    ):
        raise ValueError("stored investigation record is malformed")
    if kind == "analysis_asset":
        if set(payload) != {
            "schema",
            "path",
            "source_hash",
            "bytes",
            "asset_kind",
            "build_id",
            "version",
        }:
            raise ValueError("malformed asset payload")
        if _relative_path(payload["path"]) != payload["path"]:
            raise ValueError("noncanonical asset path")
        _hash(payload["source_hash"], "source_hash")
        if (
            type(payload["asset_kind"]) is not str
            or payload["asset_kind"] not in _ASSETS
        ):
            raise ValueError("unsupported asset kind")
        require_text(payload["build_id"], "build_id", 128)
        if not _integer(payload["bytes"], 0, MAX_ASSET_BYTES) or not _integer(
            payload["version"], 1, 2**63 - 1
        ):
            raise ValueError("invalid asset bounds")
        return
    common = {"schema", "title", "text", "evidence"}
    expected = {
        "analysis_finding": common
        | {
            "asset_id",
            "asset_hash",
            "build_id",
            "function",
            "address",
            "source_symbol",
            "status",
            "analyst",
        },
        "media_annotation": common | {"asset_id", "asset_hash", "anchor"},
        "notebook_entry": common | {"notebook_id", "entry_kind", "links"},
    }
    if kind not in expected or set(payload) != expected[kind]:
        raise ValueError("malformed investigation payload")
    require_text(payload["title"], "title", 240)
    require_text(payload["text"], "text", 8000)
    _evidence_shape(payload["evidence"])
    if kind in {"analysis_finding", "media_annotation"}:
        _identifier(payload["asset_id"], "asset_id")
        _hash(payload["asset_hash"], "asset_hash")
    if kind == "analysis_finding":
        require_text(payload["build_id"], "build_id", 128)
        require_text(payload["analyst"], "analyst", 128)
        if payload["function"] is not None:
            require_text(payload["function"], "function", 512)
        if payload["address"] is not None and (
            type(payload["address"]) is not str
            or _ADDRESS.fullmatch(payload["address"]) is None
        ):
            raise ValueError("address must be a bounded 0x hexadecimal address")
        if payload["function"] is None and payload["address"] is None:
            raise ValueError("finding needs a function or address anchor")
        _source_shape(payload["source_symbol"])
        if type(payload["status"]) is not str or payload["status"] not in {
            "hypothesis",
            "operator_confirmed",
        }:
            raise ValueError("status must be hypothesis or operator_confirmed")
        if payload["status"] == "operator_confirmed" and not payload["evidence"]:
            raise ValueError("operator-confirmed findings require exact evidence")
    elif kind == "media_annotation":
        _anchor(payload["anchor"])
    else:
        _identifier(payload["notebook_id"], "notebook_id")
        if (
            type(payload["entry_kind"]) is not str
            or payload["entry_kind"] not in _NOTE_KINDS
        ):
            raise ValueError("unsupported notebook entry kind")
        _links(payload["links"])


def _records(
    root: Path, project_id: str, connection: sqlite3.Connection | None = None
) -> list[dict[str, Any]]:
    records = read_records(root, project_id=project_id, connection=connection)
    for record in records:
        if record["kind"] in _KINDS:
            _validate_payload(record["payload"], record["kind"])
        elif record["kind"] == "project_file":
            _validate_project_payload(record["payload"], "project_file")
    return records


def _latest(records: list[dict[str, Any]], kind: str) -> dict[str, dict[str, Any]]:
    result = {}
    for record in records:
        if record["kind"] == kind:
            result[record["payload"]["path"]] = record
    return result


class _AlreadyRegistered(Exception):
    def __init__(self, record: dict[str, Any]):
        self.record = record


def register_analysis_asset(
    root: Path,
    *,
    project_id: str,
    session_id: str,
    source_root: Path | str,
    path: str,
    asset_kind: str,
    build_id: str,
) -> dict[str, Any]:
    """Hash one explicit file (at most 32 MiB); append a version, never bytes."""
    project_id = _project(root, project_id)
    session_id = require_text(session_id, "session_id", 256)
    relative = _relative_path(path)
    directory = _source_root(source_root)
    raw = _read_asset(directory, relative)
    _scan_asset(raw)
    resolved = _resolved_relative(directory, relative)
    latest = _latest(_records(root, project_id), "analysis_asset")
    aliases = [old for old in latest if _equivalent_path(directory, old, resolved)]
    if len(aliases) > 1:
        raise ValueError("recorded asset paths have ambiguous aliases")
    path = aliases[0] if aliases else resolved
    prior = latest.get(path)
    payload = {
        "schema": 1,
        "path": path,
        "source_hash": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "asset_kind": asset_kind,
        "build_id": build_id,
        "version": 1 if prior is None else prior["payload"]["version"] + 1,
    }
    _validate_payload(payload, "analysis_asset")

    def same(record: dict[str, Any]) -> bool:
        return all(
            record["payload"][field] == payload[field]
            for field in ("source_hash", "bytes", "asset_kind", "build_id")
        )

    if prior is not None and same(prior):
        return {**prior, "status": "unchanged"}

    def validate(conn: sqlite3.Connection, inserted: dict[str, Any]) -> None:
        current = _latest(
            [
                row
                for row in _records(root, project_id, conn)
                if row["id"] != inserted["id"]
            ],
            "analysis_asset",
        ).get(path)
        if current is not None and same(current):
            raise _AlreadyRegistered(current)
        expected = 1 if current is None else current["payload"]["version"] + 1
        if expected != payload["version"]:
            raise ValueError("asset changed concurrently; retry registration")

    try:
        record = append_record(
            root,
            project_id=project_id,
            session_id=session_id,
            kind="analysis_asset",
            payload=payload,
            validate=validate,
        )
        return {**record, "status": "registered"}
    except _AlreadyRegistered as existing:
        return {**existing.record, "status": "unchanged"}


def _asset(
    records: list[dict[str, Any]], asset_id: str, asset_hash: str
) -> dict[str, Any]:
    _identifier(asset_id, "asset_id")
    _hash(asset_hash, "asset_hash")
    found = next(
        (
            row
            for row in records
            if row["id"] == asset_id and row["kind"] == "analysis_asset"
        ),
        None,
    )
    if found is None or found["payload"]["source_hash"] != asset_hash:
        raise ValueError("exact asset is unavailable in this project")
    return found


def _source(records: list[dict[str, Any]], value: Any) -> None:
    _source_shape(value)
    if value is None:
        return
    found = next(
        (
            row
            for row in records
            if row["id"] == value["record_id"] and row["kind"] == "project_file"
        ),
        None,
    )
    if found is None or found["content_hash"] != value["content_hash"]:
        raise ValueError("exact indexed source symbol is unavailable in this project")
    matches = [
        symbol
        for symbol in found["payload"]["symbols"]
        if symbol["name"] == value["symbol"]
        and ("line" not in value or symbol["line"] == value["line"])
    ]
    if len(matches) != 1:
        raise ValueError(
            "source symbol is unavailable or ambiguous; supply its exact line"
        )


def _append_claim(
    root: Path, project_id: str, session_id: str, kind: str, payload: dict[str, Any]
) -> dict[str, Any]:
    _validate_payload(payload, kind)

    def validate(conn: sqlite3.Connection, inserted: dict[str, Any]) -> None:
        records = [
            row
            for row in _records(root, project_id, conn)
            if row["id"] != inserted["id"]
        ]
        validate_evidence(root, project_id, payload["evidence"])
        if kind in {"analysis_finding", "media_annotation"}:
            asset = _asset(records, payload["asset_id"], payload["asset_hash"])
            if kind == "analysis_finding":
                if (
                    asset["payload"]["asset_kind"] != "binary"
                    or asset["payload"]["build_id"] != payload["build_id"]
                ):
                    raise ValueError("finding must bind the exact binary/build")
                _source(records, payload["source_symbol"])
            elif asset["payload"]["asset_kind"] == "binary":
                raise ValueError("media annotations require a media asset")
        else:
            by_id = {row["id"]: row for row in records}
            for link in payload["links"]:
                target = by_id.get(link["target_id"])
                if target is None or target["content_hash"] != link["content_hash"]:
                    raise ValueError(
                        "exact notebook link is unavailable in this project"
                    )

    return append_record(
        root,
        project_id=project_id,
        session_id=session_id,
        kind=kind,
        payload=payload,
        validate=validate,
    )


def record_analysis_finding(
    root: Path,
    *,
    project_id: str,
    session_id: str,
    asset_id: str,
    asset_hash: str,
    title: str,
    text: str,
    analyst: str,
    function: str | None = None,
    address: str | None = None,
    source_symbol: dict[str, Any] | None = None,
    status: str = "hypothesis",
    evidence: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Record a supplied binary finding; confirmed means operator-attributed."""
    project_id = _project(root, project_id)
    asset = _asset(_records(root, project_id), asset_id, asset_hash)
    payload = {
        "schema": 1,
        "asset_id": asset_id,
        "asset_hash": asset_hash,
        "build_id": asset["payload"]["build_id"],
        "title": title,
        "text": text,
        "analyst": analyst,
        "function": function,
        "address": address,
        "source_symbol": source_symbol,
        "status": status,
        "evidence": validate_evidence(root, project_id, evidence),
    }
    return _append_claim(root, project_id, session_id, "analysis_finding", payload)


def record_media_annotation(
    root: Path,
    *,
    project_id: str,
    session_id: str,
    asset_id: str,
    asset_hash: str,
    title: str,
    text: str,
    anchor: dict[str, Any],
    evidence: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Attach supplied text to exact media coordinates; no extractor is run."""
    project_id = _project(root, project_id)
    payload = {
        "schema": 1,
        "asset_id": asset_id,
        "asset_hash": asset_hash,
        "title": title,
        "text": text,
        "anchor": _anchor(anchor),
        "evidence": validate_evidence(root, project_id, evidence),
    }
    return _append_claim(root, project_id, session_id, "media_annotation", payload)


def record_notebook_entry(
    root: Path,
    *,
    project_id: str,
    session_id: str,
    notebook_id: str,
    entry_kind: str,
    title: str,
    text: str,
    links: list[dict[str, str]] | None = None,
    evidence: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    project_id = _project(root, project_id)
    payload = {
        "schema": 1,
        "notebook_id": notebook_id,
        "entry_kind": entry_kind,
        "title": title,
        "text": text,
        "links": _links(links),
        "evidence": validate_evidence(root, project_id, evidence),
    }
    return _append_claim(root, project_id, session_id, "notebook_entry", payload)


def _evaluated(
    root: Path, project_id: str, source_root: Path | str | None = None
) -> list[dict[str, Any]]:
    directory = None if source_root is None else _source_root(source_root)
    records = _records(root, project_id)
    by_id = {row["id"]: row for row in records}
    latest_assets, latest_files = (
        _latest(records, "analysis_asset"),
        _latest(records, "project_file"),
    )
    stale: dict[str, set[str]] = {row["id"]: set() for row in records}
    dependents: dict[str, set[str]] = {}
    for row in records:
        kind, payload = row["kind"], row["payload"]
        reasons = stale[row["id"]]
        if kind in {"analysis_asset", "project_file"}:
            latest = latest_assets if kind == "analysis_asset" else latest_files
            if latest[payload["path"]]["id"] != row["id"]:
                reasons.add(
                    "newer_asset_version"
                    if kind == "analysis_asset"
                    else "newer_file_version"
                )
            elif directory is not None:
                try:
                    reader = _read_asset if kind == "analysis_asset" else _read_file
                    if (
                        hashlib.sha256(reader(directory, payload["path"])).hexdigest()
                        != payload["source_hash"]
                    ):
                        reasons.add("input_changed")
                except FileNotFoundError:
                    reasons.add("input_missing")
                except ValueError:
                    reasons.add("input_unreadable_or_unsafe")
        if kind not in _KINDS or kind == "analysis_asset":
            continue
        targets = []
        for citation in payload["evidence"]:
            try:
                validate_evidence(root, project_id, [citation])
            except ValueError:
                reasons.add("evidence_unavailable")
            if citation["kind"] == "scroll_event":
                targets.append((citation["id"], citation["content_hash"]))
        if kind in {"analysis_finding", "media_annotation"}:
            try:
                asset = _asset(records, payload["asset_id"], payload["asset_hash"])
                targets.append((asset["id"], asset["content_hash"]))
                if kind == "analysis_finding":
                    if (
                        asset["payload"]["asset_kind"] != "binary"
                        or asset["payload"]["build_id"] != payload["build_id"]
                    ):
                        reasons.add("asset_binding_changed")
                    _source(records, payload["source_symbol"])
                    if payload["source_symbol"] is not None:
                        source = payload["source_symbol"]
                        targets.append((source["record_id"], source["content_hash"]))
                elif asset["payload"]["asset_kind"] == "binary":
                    reasons.add("asset_binding_changed")
            except ValueError:
                reasons.add("asset_or_source_unavailable")
        else:
            targets += [
                (link["target_id"], link["content_hash"]) for link in payload["links"]
            ]
        for target_id, target_hash in targets:
            target = by_id.get(target_id)
            if target is None or target["content_hash"] != target_hash:
                reasons.add("linked_evidence_unavailable")
            else:
                dependents.setdefault(target_id, set()).add(row["id"])
    pending = deque(record_id for record_id, reasons in stale.items() if reasons)
    while pending:
        stale_target = pending.popleft()
        for dependent in dependents.get(stale_target, set()):
            if not stale[dependent]:
                pending.append(dependent)
            stale[dependent].add("linked_evidence_needs_review")
    return [
        {
            **row,
            "needs_review": bool(stale[row["id"]]),
            "review_reasons": sorted(stale[row["id"]]),
        }
        for row in records
        if row["kind"] in _KINDS
    ]


def query_investigation(
    root: Path,
    *,
    project_id: str,
    query: str | None = None,
    notebook_id: str | None = None,
    source_root: Path | str | None = None,
    include_history: bool = False,
    token_budget: int = 2400,
) -> dict[str, Any]:
    project_id = _project(root, project_id)
    if type(include_history) is not bool:
        raise ValueError("include_history must be boolean")
    needle = None if query is None else require_text(query, "query", 1024).casefold()
    if notebook_id is not None:
        _identifier(notebook_id, "notebook_id")
    rows = _evaluated(root, project_id, source_root)
    latest = _latest(rows, "analysis_asset")
    selected = [
        row
        for row in rows
        if (
            include_history
            or row["kind"] != "analysis_asset"
            or latest[row["payload"]["path"]]["id"] == row["id"]
        )
        and (notebook_id is None or row["payload"].get("notebook_id") == notebook_id)
        and (
            needle is None
            or needle in json.dumps(row["payload"], ensure_ascii=False).casefold()
        )
    ]
    selected.reverse()
    return bounded_results(
        selected,
        token_budget=token_budget,
        extra={
            "project_id": project_id,
            "notebook_id": notebook_id,
            "include_history": include_history,
            "freshness": "disk_checked"
            if source_root is not None
            else "recorded_versions_only",
            "asset_bytes_stored": False,
            "claims_are": "supplied_evidence_not_verified_truth",
        },
    )


def _markdown(value: str) -> str:
    value = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return re.sub(r"([\\`*_{}\[\]()#+.!|~-])", r"\\\1", value)


def export_investigation_notebook(
    root: Path,
    *,
    project_id: str,
    notebook_id: str,
    source_root: Path | str | None = None,
    max_chars: int = 32768,
) -> dict[str, Any]:
    """Return bounded readable Markdown; no file or destination is written."""
    project_id = _project(root, project_id)
    notebook_id = _identifier(notebook_id, "notebook_id")
    if not _integer(max_chars, 1024, 131072):
        raise ValueError("max_chars must be an integer from 1024 to 131072")
    records = [
        row
        for row in _evaluated(root, project_id, source_root)
        if row["kind"] == "notebook_entry"
        and row["payload"]["notebook_id"] == notebook_id
    ]
    markdown = f"# Investigation notebook: {_markdown(notebook_id)}\n\nProject: {_markdown(project_id)}\n\nSupplied evidence, not instruction authority or verified truth.\n\n"
    empty_footer = (
        f"\nExported 0 of {len(records)} complete entries; omitted {len(records)}.\n"
    )
    if len(markdown) + len(empty_footer) > max_chars:
        raise ValueError("max_chars cannot hold the notebook envelope")
    count = 0
    for row in records:
        payload = row["payload"]
        block = (
            f"## {_markdown(payload['entry_kind'])}: {_markdown(payload['title'])}\n\n"
        )
        block += (
            "\n".join("> " + _markdown(line) for line in payload["text"].splitlines())
            + "\n\n"
        )
        block += f"Record: {row['id']}\n\nSHA-256: {row['content_hash']}\n\n"
        block += f"Needs review: {str(row['needs_review']).lower()} ({', '.join(row['review_reasons']) or 'none'})\n\n"
        for link in payload["links"]:
            block += f"- {_markdown(link['relation'])}: {link['target_id']} @ {link['content_hash']}\n"
        for citation in payload["evidence"]:
            block += f"- Evidence {_markdown(citation['kind'])}: {citation['id']} @ {citation['content_hash']}\n"
        block += "\n"
        footer = f"\nExported {count + 1} of {len(records)} complete entries; omitted {len(records) - count - 1}.\n"
        if len(markdown) + len(block) + len(footer) > max_chars:
            continue
        markdown += block
        count += 1
    markdown += f"\nExported {count} of {len(records)} complete entries; omitted {len(records) - count}.\n"
    return {
        "schema_version": 1,
        "project_id": project_id,
        "notebook_id": notebook_id,
        "markdown": markdown,
        "result_count": count,
        "matched_count": len(records),
        "excluded_by_budget": len(records) - count,
        "max_chars": max_chars,
        "instruction_authority": "none",
    }
