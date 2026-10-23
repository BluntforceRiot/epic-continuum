"""Explicit, append-only project evidence; never a source crawler or executor.

File records retain a byte hash, line anchors, Python definitions and import
declarations, not the original file body. Import declarations are not a resolved
runtime dependency graph. Queries can recheck explicitly supplied disk inputs;
without a source root, freshness means only the latest recorded file version.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import sqlite3
import stat
from collections import deque
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .knowledge_records import (
    append_record,
    bounded_results,
    read_records,
    require_text,
    validate_evidence,
)
from .safety import scan_text_for_secrets, scan_value_for_secrets
from .store import canonical_partition_identifier

_MAX_FILE_BYTES = 1024 * 1024
_MAX_PATHS = 32
_MAX_ANALYSIS_ITEMS = 256
_MAX_PAYLOAD_BYTES = 60000
_KINDS = frozenset({"decision", "test", "error", "fix", "note"})
_RELATIONS = frozenset(
    {"depends_on", "supports", "contradicts", "fixes", "tests", "related_to"}
)
_RECORD_KINDS = ("project_file", "project_knowledge")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")


def _identifier(value: Any, name: str) -> str:
    value = require_text(value, name, max_chars=128)
    if _ID.fullmatch(value) is None:
        raise ValueError(f"{name} must be a portable identifier")
    return value


def _project(root: Path, value: Any) -> str:
    value = require_text(value, "project_id", max_chars=256)
    canonical = canonical_partition_identifier(root, "project_id", value, lookup=True)
    if not canonical:
        raise ValueError("project_id is required")
    return canonical


def _relative_path(value: Any) -> str:
    value = require_text(value, "path", max_chars=512)
    if scan_text_for_secrets(value, max_findings=1):
        raise ValueError("project file path contains credential-like data")
    portable = value.replace("\\", "/")
    parts = portable.split("/")
    if (
        PureWindowsPath(value).drive
        or PureWindowsPath(value).root
        or PurePosixPath(portable).is_absolute()
        or any(part in {"", ".", ".."} for part in parts)
        or any(":" in part or part.endswith((".", " ")) for part in parts)
        or any(not part.isprintable() for part in parts)
    ):
        raise ValueError("paths must be explicit portable relative file paths")
    return "/".join(parts)


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024)
    )


def _source_root(value: Path | str) -> Path:
    if not isinstance(value, (str, Path)):
        raise ValueError("source_root must be an explicit absolute directory")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("source_root must be an explicit absolute directory")
    try:
        for parent in (path, *path.parents):
            info = parent.lstat()
            if _is_link(info) or not stat.S_ISDIR(info.st_mode):
                raise ValueError("source_root must not traverse links")
        return path.resolve(strict=True)
    except OSError:
        raise ValueError("source_root must be an existing readable directory") from None


def _read_file(source_root: Path, relative: str) -> bytes:
    path = source_root.joinpath(*relative.split("/"))
    try:
        for parent in (source_root, *path.parents):
            if parent == source_root or source_root in parent.parents:
                info = parent.lstat()
                if _is_link(info) or not stat.S_ISDIR(info.st_mode):
                    raise ValueError("project file must not traverse links")
        before = path.lstat()
        if _is_link(before) or not stat.S_ISREG(before.st_mode):
            raise ValueError("project input must be a regular non-link file")
        if before.st_size > _MAX_FILE_BYTES:
            raise ValueError("project file exceeds the 1 MiB limit")
        if not path.resolve(strict=True).is_relative_to(source_root):
            raise ValueError("project file escapes source_root")
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError("project file changed while opening")
            raw = stream.read(_MAX_FILE_BYTES + 1)
            after = os.fstat(stream.fileno())
        if (
            len(raw) > _MAX_FILE_BYTES
            or (after.st_size, after.st_mtime_ns)
            != (opened.st_size, opened.st_mtime_ns)
            or path.lstat().st_ino != opened.st_ino
            or not path.resolve(strict=True).is_relative_to(source_root)
        ):
            raise ValueError("project file changed while reading")
        for parent in (path, *path.parents):
            if parent == source_root or source_root in parent.parents:
                if _is_link(parent.lstat()):
                    raise ValueError("project file changed to a link while reading")
        return raw
    except FileNotFoundError:
        raise FileNotFoundError("project file is missing") from None
    except OSError:
        raise ValueError("project file is not readable") from None


def _resolved_relative(source_root: Path, relative: str) -> str:
    """Get the actual file spelling without persisting its absolute location."""
    path = source_root.joinpath(*relative.split("/"))
    try:
        for entry in (path, *path.parents):
            if entry == source_root or source_root in entry.parents:
                if _is_link(entry.lstat()):
                    raise ValueError("project file must not traverse links")
        resolved = path.resolve(strict=True)
        if not stat.S_ISREG(resolved.stat().st_mode) or not resolved.is_relative_to(
            source_root
        ):
            raise ValueError("project input must be a regular file beneath source_root")
        return _relative_path(resolved.relative_to(source_root).as_posix())
    except OSError:
        raise ValueError("project file changed during path resolution") from None


def _equivalent_path(source_root: Path, left: str, right: str) -> bool:
    """Use real path identity, never a global assumption about case sensitivity.

    Windows resolves actual spelling (including short-name aliases). On hosts
    where realpath preserves case aliases, samefile confirms equivalence before
    folding a case-only variant. Different case-sensitive files stay distinct.
    """
    try:
        first = _resolved_relative(source_root, left)
        second = _resolved_relative(source_root, right)
        if first == second:
            return True
        return first.casefold() == second.casefold() and source_root.joinpath(
            *first.split("/")
        ).samefile(source_root.joinpath(*second.split("/")))
    except (ValueError, OSError):
        return False


class _DuplicateJsonKey(ValueError):
    pass


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _text(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError("project files must contain UTF-8 text") from None
    if any(ord(char) < 32 and char not in "\r\n\t\f" for char in text):
        raise ValueError("binary project files are not supported")
    if scan_text_for_secrets(text, max_findings=1):
        raise ValueError("project file contains credential-like data")
    # Structured JSON values (including escaped line breaks) need the same
    # existing metadata guard as a directly submitted knowledge record.
    try:
        structured = json.loads(text, object_pairs_hook=_json_object)
    except _DuplicateJsonKey:
        raise ValueError(
            "project JSON contains ambiguous duplicate object keys"
        ) from None
    except json.JSONDecodeError:
        structured = None
    except (ValueError, RecursionError):
        # Resource/decoder limits do not establish that an input is ordinary
        # non-JSON text. Fail closed rather than bypass structured scanning.
        raise ValueError("project JSON exceeds analysis limits") from None
    if structured is not None and scan_value_for_secrets(
        structured, scope="project_file", max_findings=1
    ):
        raise ValueError("project file contains credential-like data")
    return text


class _PythonFacts(ast.NodeVisitor):
    def __init__(self) -> None:
        self.scope: list[str] = []
        self.symbols: list[dict[str, Any]] = []
        self.imports: list[dict[str, Any]] = []

    def _definition(self, node: Any, kind: str) -> None:
        name = require_text(".".join([*self.scope, node.name]), "symbol", max_chars=512)
        self.symbols.append(
            {
                "name": name,
                "kind": kind,
                "line": node.lineno,
                "end_line": node.end_lineno,
            }
        )
        if len(self.symbols) > _MAX_ANALYSIS_ITEMS:
            raise ValueError("Python file exceeds the 256-symbol analysis limit")
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._definition(node, "class")

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._definition(node, "function")

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._definition(node, "async_function")

    def _import(self, node: Any, module: str, name: str, alias: str | None) -> None:
        self.imports.append(
            {
                "module": module,
                "name": name,
                "alias": alias,
                "line": node.lineno,
                "end_line": node.end_lineno,
            }
        )
        if len(self.imports) > _MAX_ANALYSIS_ITEMS:
            raise ValueError("Python file exceeds the 256-import analysis limit")

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._import(node, alias.name, alias.name, alias.asname)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            self._import(
                node, "." * node.level + (node.module or ""), alias.name, alias.asname
            )


def _file_payload(source_root: Path, relative: str) -> dict[str, Any]:
    try:
        raw = _read_file(source_root, relative)
    except FileNotFoundError:
        raise ValueError("project file is missing") from None
    text = _text(raw)
    facts = _PythonFacts()
    python = PurePosixPath(relative).suffix.lower() == ".py"
    if python:
        try:
            syntax = ast.parse(text)
            if sum(1 for _ in ast.walk(syntax)) > 100000:
                raise ValueError("Python file exceeds the bounded analysis size")
            facts.visit(syntax)
        except (SyntaxError, RecursionError, MemoryError):
            raise ValueError(
                "Python file could not be parsed within analysis limits"
            ) from None
    payload = {
        "schema": 1,
        "path": relative,
        "source_hash": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "line_count": len(text.splitlines()),
        "language": "python" if python else "text",
        "symbols": facts.symbols,
        "imports": facts.imports,
        "version": 1,
    }
    if (
        len(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
        )
        > _MAX_PAYLOAD_BYTES
    ):
        raise ValueError("project file analysis exceeds the 60000-byte metadata limit")
    return payload


def _integer(value: Any, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def _validate_payload(payload: Any, kind: str) -> None:
    """Do not let a generic typed envelope confer file/link schema authority."""
    try:
        if (
            type(payload) is not dict
            or type(payload.get("schema")) is not int
            or payload["schema"] != 1
        ):
            raise ValueError
        if kind == "project_file":
            if set(payload) != {
                "schema",
                "path",
                "source_hash",
                "bytes",
                "line_count",
                "language",
                "symbols",
                "imports",
                "version",
            }:
                raise ValueError
            if _relative_path(payload["path"]) != payload["path"]:
                raise ValueError
            if (
                type(payload["source_hash"]) is not str
                or _HASH.fullmatch(payload["source_hash"]) is None
            ):
                raise ValueError
            if not _integer(payload["version"], 1, 2**63 - 1) or not _integer(
                payload["bytes"], 0, _MAX_FILE_BYTES
            ):
                raise ValueError
            if not _integer(payload["line_count"], 0, _MAX_FILE_BYTES) or payload[
                "language"
            ] not in ("python", "text"):
                raise ValueError
            for key in ("symbols", "imports"):
                if (
                    type(payload[key]) is not list
                    or len(payload[key]) > _MAX_ANALYSIS_ITEMS
                ):
                    raise ValueError
                for item in payload[key]:
                    fields = (
                        {"name", "kind", "line", "end_line"}
                        if key == "symbols"
                        else {"module", "name", "alias", "line", "end_line"}
                    )
                    if type(item) is not dict or set(item) != fields:
                        raise ValueError
                    require_text(item["name"], "stored symbol name", max_chars=512)
                    if not _integer(
                        item["line"], 1, payload["line_count"]
                    ) or not _integer(
                        item["end_line"], item["line"], payload["line_count"]
                    ):
                        raise ValueError
                    if key == "symbols":
                        if item["kind"] not in ("class", "function", "async_function"):
                            raise ValueError
                    else:
                        require_text(
                            item["module"], "stored import module", max_chars=512
                        )
                        if item["alias"] is not None:
                            require_text(
                                item["alias"], "stored import alias", max_chars=512
                            )
            if payload["language"] == "text" and (
                payload["symbols"] or payload["imports"]
            ):
                raise ValueError
        elif kind == "project_knowledge":
            if set(payload) != {
                "schema",
                "kind",
                "title",
                "summary",
                "links",
                "evidence",
            }:
                raise ValueError
            if type(payload["kind"]) is not str or payload["kind"] not in _KINDS:
                raise ValueError
            require_text(payload["title"], "stored title", max_chars=240)
            require_text(payload["summary"], "stored summary", max_chars=8000)
            _links(payload["links"])
            if type(payload["evidence"]) is not list or len(payload["evidence"]) > 16:
                raise ValueError
            for item in payload["evidence"]:
                if type(item) is not dict or set(item) != {
                    "kind",
                    "id",
                    "content_hash",
                }:
                    raise ValueError
                if item["kind"] not in ("card", "scroll_event", "chunk"):
                    raise ValueError
                _identifier(item["id"], "stored evidence ID")
                if (
                    type(item["content_hash"]) is not str
                    or _HASH.fullmatch(item["content_hash"]) is None
                ):
                    raise ValueError
        else:
            raise ValueError
        if (
            len(
                json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
                    "utf-8"
                )
            )
            > _MAX_PAYLOAD_BYTES
        ):
            raise ValueError
    except (ValueError, TypeError, KeyError):
        raise ValueError(
            "project knowledge payload is malformed or exceeds analysis limits"
        ) from None


def _records(
    root: Path, project_id: str, connection: sqlite3.Connection | None = None
) -> list[dict[str, Any]]:
    records = read_records(
        root, project_id=project_id, kinds=_RECORD_KINDS, connection=connection
    )
    for record in records:
        _validate_payload(record["payload"], record["kind"])
    return records


def _files(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for record in records:
        if record["kind"] != "project_file":
            continue
        payload = record["payload"]
        path = payload["path"]
        prior = latest.get(path)
        if prior is None or payload["version"] > prior["payload"]["version"]:
            latest[path] = record
        elif payload["version"] == prior["payload"]["version"]:
            raise ValueError("project file history contains ambiguous versions")
    return latest


class _AlreadyIndexed(Exception):
    def __init__(self, record: dict[str, Any]) -> None:
        self.record = record


def index_project_files(
    root: Path,
    *,
    project_id: str,
    session_id: str,
    source_root: Path | str,
    paths: list[str],
) -> dict[str, Any]:
    """Index only supplied files; preflight all inputs before the first write.

    Versions are append-only and individually transaction-serialized. A rare
    concurrent conflicting update can fail a pass after earlier files committed;
    retry is safe because unchanged latest file hashes are idempotent.
    """
    project_id = _project(root, project_id)
    session_id = require_text(session_id, "session_id", max_chars=256)
    if type(paths) is not list or not 1 <= len(paths) <= _MAX_PATHS:
        raise ValueError("paths must contain between 1 and 32 explicit files")
    relative = [_relative_path(path) for path in paths]
    if len(set(relative)) != len(relative):
        raise ValueError("paths must not contain duplicates")
    directory = _source_root(source_root)
    payloads = [_file_payload(directory, path) for path in relative]
    for payload in payloads:
        _validate_payload(payload, "project_file")
    existing = _records(root, project_id)
    latest = _files(existing)
    canonical: list[str] = []
    for payload in payloads:
        resolved = _resolved_relative(directory, payload["path"])
        if any(_equivalent_path(directory, resolved, earlier) for earlier in canonical):
            raise ValueError("paths must not contain aliases of the same file")
        canonical.append(resolved)
        previous_paths = [
            path for path in latest if _equivalent_path(directory, path, resolved)
        ]
        if len(previous_paths) > 1:
            raise ValueError("recorded project paths have ambiguous file aliases")
        # Preserve the spelling of already-recorded evidence while continuing
        # its one version chain. New files use the resolved relative spelling.
        payload["path"] = previous_paths[0] if previous_paths else resolved
    results = []
    written = 0
    for payload in payloads:
        prior = latest.get(payload["path"])
        if prior and prior["payload"]["source_hash"] == payload["source_hash"]:
            record = prior
            status = "unchanged"
        else:
            payload["version"] = 1 if prior is None else prior["payload"]["version"] + 1

            def validate(conn: sqlite3.Connection, inserted: dict[str, Any]) -> None:
                rows = _records(root, project_id, conn)
                current = _files(
                    [row for row in rows if row["id"] != inserted["id"]]
                ).get(payload["path"])
                if (
                    current
                    and current["payload"]["source_hash"] == payload["source_hash"]
                ):
                    raise _AlreadyIndexed(current)
                expected = 1 if current is None else current["payload"]["version"] + 1
                if expected != payload["version"]:
                    raise ValueError(
                        "project file changed concurrently; retry the index pass"
                    )

            try:
                record = append_record(
                    root,
                    project_id=project_id,
                    session_id=session_id,
                    kind="project_file",
                    payload=payload,
                    validate=validate,
                )
                written += 1
                status = "indexed"
            except _AlreadyIndexed as same:
                record = same.record
                status = "unchanged"
        latest[payload["path"]] = record
        results.append(
            {
                "id": record["id"],
                "path": payload["path"],
                "source_hash": payload["source_hash"],
                "version": record["payload"]["version"],
                "status": status,
            }
        )
    return {
        "project_id": project_id,
        "indexed": written,
        "unchanged": len(results) - written,
        "files": results,
        "source_text_stored": False,
    }


def _links(value: Any) -> list[dict[str, str]]:
    if value is None:
        return []
    if type(value) is not list or len(value) > 16:
        raise ValueError("links must be an array of at most 16 typed targets")
    result = []
    seen = set()
    for item in value:
        if type(item) is not dict or set(item) != {"relation", "target_id"}:
            raise ValueError("each link must contain only relation and target_id")
        relation = item["relation"]
        if type(relation) is not str or relation not in _RELATIONS:
            raise ValueError("unsupported project link relation")
        target = _identifier(item["target_id"], "target_id")
        if (relation, target) in seen:
            raise ValueError("duplicate project knowledge link")
        seen.add((relation, target))
        result.append({"relation": relation, "target_id": target})
    return result


def record_project_knowledge(
    root: Path,
    *,
    project_id: str,
    session_id: str,
    kind: str,
    title: str,
    summary: str,
    links: list[dict[str, str]] | None = None,
    evidence: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Append attributed knowledge; no link promotes a claim into truth."""
    project_id = _project(root, project_id)
    session_id = require_text(session_id, "session_id", max_chars=256)
    if type(kind) is not str or kind not in _KINDS:
        raise ValueError("kind must be decision, test, error, fix, or note")
    payload: dict[str, Any] = {
        "schema": 1,
        "kind": kind,
        "title": require_text(title, "title", max_chars=240),
        "summary": require_text(summary, "summary", max_chars=8000),
        "links": _links(links),
        "evidence": validate_evidence(root, project_id, evidence),
    }
    _validate_payload(payload, "project_knowledge")

    def validate(conn: sqlite3.Connection, inserted: dict[str, Any]) -> None:
        records = _records(root, project_id, conn)
        allowed = {record["id"] for record in records if record["id"] != inserted["id"]}
        if any(link["target_id"] not in allowed for link in payload["links"]):
            raise ValueError("project link target is unavailable in this project")

    return append_record(
        root,
        project_id=project_id,
        session_id=session_id,
        kind="project_knowledge",
        payload=payload,
        validate=validate,
    )


def query_project_knowledge(
    root: Path,
    *,
    project_id: str,
    query: str | None = None,
    source_root: Path | str | None = None,
    include_history: bool = False,
    token_budget: int = 2400,
) -> dict[str, Any]:
    """Read complete bounded records, preserving stale evidence for review.

    All relation types propagate staleness; none silently deletes a decision.
    No source root is remembered or guessed. Disk checks read only recorded
    relative paths and never crawl or update memory.
    """
    project_id = _project(root, project_id)
    if type(include_history) is not bool:
        raise ValueError("include_history must be a boolean")
    needle = (
        None
        if query is None
        else require_text(query, "query", max_chars=1024).casefold()
    )
    directory = None if source_root is None else _source_root(source_root)
    records = _records(root, project_id)
    latest = _files(records)
    by_id = {record["id"]: record for record in records}
    stale: dict[str, set[str]] = {}
    for record in records:
        reasons: set[str] = set()
        if record["kind"] == "project_file":
            payload = record["payload"]
            if latest[payload["path"]]["id"] != record["id"]:
                reasons.add("newer_file_version")
            elif directory is not None:
                try:
                    raw = _read_file(directory, _relative_path(payload["path"]))
                    if hashlib.sha256(raw).hexdigest() != payload["source_hash"]:
                        reasons.add("file_changed")
                except FileNotFoundError:
                    reasons.add("file_missing")
                except ValueError:
                    reasons.add("file_unreadable_or_unsafe")
        else:
            for item in record["payload"]["evidence"]:
                try:
                    validate_evidence(root, project_id, [item])
                except ValueError:
                    reasons.add("evidence_unavailable")
        stale[record["id"]] = reasons
    # IDs point backwards at creation. Queue-based propagation also tolerates
    # imported cycles in O(records + links), without recursive traversal.
    dependents: dict[str, set[str]] = {}
    for record in records:
        if record["kind"] != "project_knowledge":
            continue
        targets = [link["target_id"] for link in record["payload"]["links"]]
        targets += [
            item["id"]
            for item in record["payload"]["evidence"]
            if item["kind"] == "scroll_event" and item["id"] in by_id
        ]
        for target in targets:
            if target not in by_id:
                stale[record["id"]].add("linked_evidence_needs_review")
            else:
                dependents.setdefault(target, set()).add(record["id"])
    pending = deque(record_id for record_id, reasons in stale.items() if reasons)
    while pending:
        target = pending.popleft()
        for dependent in dependents.get(target, set()):
            was_stale = bool(stale[dependent])
            stale[dependent].add("linked_evidence_needs_review")
            if not was_stale:
                pending.append(dependent)
    selected = []
    for record in records:
        if (
            not include_history
            and record["kind"] == "project_file"
            and latest[record["payload"]["path"]]["id"] != record["id"]
        ):
            continue
        if (
            needle is not None
            and needle
            not in json.dumps(record["payload"], ensure_ascii=False).casefold()
        ):
            continue
        selected.append(
            {
                **record,
                "needs_review": bool(stale[record["id"]]),
                "review_reasons": sorted(stale[record["id"]]),
            }
        )
    selected.reverse()
    return bounded_results(
        selected,
        token_budget=token_budget,
        extra={
            "project_id": project_id,
            "include_history": include_history,
            "freshness": "disk_checked"
            if directory is not None
            else "recorded_versions_only",
            "query_hash": None
            if query is None
            else hashlib.sha256(query.encode("utf-8")).hexdigest(),
        },
    )
