"""Explicit incremental embedding passes and read-only indexed recall.

The sidecar is rebuildable derived data, not memory authority. This adapter
deliberately reuses recall._Catalog, _scope and _fit_packet: every ID and exact
text hash is revalidated under the same visibility/checkpoint contract before
semantic admission. No source text, query, endpoint or model alias is persisted.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from .embeddings import (
    MAX_BATCH_BYTES,
    MAX_BATCH_SIZE,
    MAX_TEXT_BYTES,
    EmbeddingError,
    _invalid_constant,
    _json_object,
    embed_texts,
    embedding_identity,
    embedding_text_blocked,
)
from .permissions import secure_write_text
from .recall import (
    _Catalog,
    _Source,
    _fit_packet,
    _integer,
    _scope,
    _source_key,
    _time_filter,
    recall_memory,
)
from .semantic_vectors import _normalized_vector, cosine_similarity
from .store import _visible_card_clause, _visible_scroll_clause, is_initialized

MAX_SOURCES = 5000
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_CACHE_BYTES = 64 * 1024 * 1024
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _identity(root: Path, endpoint: str, model: str, session_id: str | None,
              project_id: str | None) -> tuple[str, str, str | None, str | None, str]:
    endpoint, model = embedding_identity(endpoint, model)
    session_id, project_id = _scope(root, session_id, project_id)
    identity = _digest(json.dumps([endpoint, model, session_id, project_id],
                                  ensure_ascii=True, separators=(",", ":")))
    return endpoint, model, session_id, project_id, identity


def _cache_path(root: Path, identity: str) -> Path:
    """Reject redirected cache components; never create paths during reads."""
    resolved = root.resolve()
    path = resolved / "catalog" / "embedding-index" / f"{identity}.json"
    for candidate in (path.parent.parent, path.parent, path):
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISLNK(metadata.st_mode)
                or getattr(metadata, "st_file_attributes", 0) & 0x400
                or (candidate != path and not stat.S_ISDIR(metadata.st_mode))
                or (candidate == path and not stat.S_ISREG(metadata.st_mode))):
            raise ValueError("embedding cache path must use ordinary local files and directories")
    if not path.resolve(strict=False).is_relative_to(resolved):
        raise ValueError("embedding cache path is outside the explicit memory root")
    return path


def _load_index(root: Path, identity: str) -> tuple[dict[str, Any] | None, str]:
    try:
        path = _cache_path(root, identity)
        if not path.exists():
            return None, "missing"
        if path.stat().st_size > MAX_CACHE_BYTES:
            return None, "invalid"
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return None, "invalid"
            raw = handle.read(MAX_CACHE_BYTES + 1)
        if len(raw) > MAX_CACHE_BYTES:
            return None, "invalid"
        data = json.loads(raw, object_pairs_hook=_json_object, parse_constant=_invalid_constant)
        if type(data) is not dict or set(data) != {"schema_version", "identity_sha256", "dimensions", "entries"}:
            return None, "invalid"
        if type(data["schema_version"]) is not int or data["schema_version"] != 1 or data["identity_sha256"] != identity:
            return None, "invalid"
        dimensions = data["dimensions"]
        entries = data["entries"]
        if type(dimensions) is not int or not 0 <= dimensions <= 2048:
            return None, "invalid"
        if type(entries) is not list or len(entries) > MAX_SOURCES or bool(entries) != bool(dimensions):
            return None, "invalid"
        seen = set()
        for entry in entries:
            if type(entry) is not dict or set(entry) != {"kind", "id", "content_hash", "vector"}:
                return None, "invalid"
            key = _source_key(entry["kind"], entry["id"])
            if key in seen or type(entry["content_hash"]) is not str or not _SHA256.fullmatch(entry["content_hash"]):
                return None, "invalid"
            seen.add(key)
            vector = _normalized_vector(entry["vector"])
            if len(vector) != dimensions:
                return None, "invalid"
        return data, "ready"
    except (OSError, ValueError, TypeError, RecursionError, OverflowError):
        return None, "invalid"


def _source_rows(catalog: _Catalog, maximum: int) -> list[tuple[str, str, int]]:
    """Bound eligible source headers before loading any potentially large text."""
    conn = catalog.conn
    conn.create_function("embedding_card", 1, catalog.card_current)
    conn.create_function("embedding_event", 2, lambda event, kind: kind != "project_state" or event in catalog.events)
    conn.create_function("embedding_metadata", 3, catalog.visible_metadata)
    card_clause, card_params = _visible_card_clause(session_id=catalog.session_id, project_id=catalog.project_id)
    event_clause, event_params = _visible_scroll_clause(session_id=catalog.session_id, project_id=catalog.project_id)
    queries = [
        ("card", f"""SELECT id, length(CAST(title AS BLOB))+1+length(CAST(summary AS BLOB)) AS bytes
            FROM cards WHERE {card_clause} AND embedding_card(id) ORDER BY id LIMIT ?""", card_params),
        ("scroll_event", f"""SELECT id, length(CAST(content AS BLOB)) AS bytes FROM scroll_events
            WHERE {event_clause} AND embedding_event(id,event_type)
            AND embedding_metadata(metadata_json,session_id,0) ORDER BY id LIMIT ?""", event_params),
        ("chunk", """SELECT c.id, length(CAST(c.text AS BLOB)) AS bytes FROM chunks c
            JOIN books b ON b.id=c.book_id WHERE embedding_metadata(b.metadata_json,NULL,1)
            ORDER BY c.id LIMIT ?""", []),
    ]
    result: list[tuple[str, str, int]] = []
    for kind, sql, params in queries:
        rows = conn.execute(sql, (*params, maximum + 1)).fetchall()
        result.extend((kind, str(row["id"]), int(row["bytes"] or 0)) for row in rows)
        if len(result) > maximum:
            raise ValueError("embedding source count exceeds max_sources; no partial index was published")
    return result


def _source_bytes(catalog: _Catalog, kind: str, source_id: str) -> int | None:
    queries = {
        "card": "SELECT length(CAST(title AS BLOB))+1+length(CAST(summary AS BLOB)) FROM cards WHERE id=?",
        "scroll_event": "SELECT length(CAST(content AS BLOB)) FROM scroll_events WHERE id=?",
        "chunk": "SELECT length(CAST(text AS BLOB)) FROM chunks WHERE id=?",
    }
    row = catalog.conn.execute(queries[kind], (source_id,)).fetchone()
    return int(row[0] or 0) if row is not None else None


def _source_credentials_blocked(catalog: _Catalog, source: _Source) -> bool:
    if embedding_text_blocked(source.content):
        return True
    if source.kind == "card":
        # Canonical Card text concatenates title + newline + summary. Screen
        # each original field too: a JSON summary ceases to be a whole JSON
        # document after that concatenation, but remains structured evidence.
        row = catalog.conn.execute("SELECT title, summary FROM cards WHERE id=?", (source.source_id,)).fetchone()
        return row is None or any(embedding_text_blocked(row[field]) for field in ("title", "summary"))
    return False


def _sources(root: Path, session_id: str | None, project_id: str | None,
             maximum: int) -> tuple[list[_Source], dict[str, int]]:
    catalog = _Catalog(root, session_id, project_id)
    counters = {"eligible_sources": 0, "skipped_oversize": 0, "skipped_credentials": 0,
                "skipped_invalid": 0, "source_bytes": 0}
    result = []
    try:
        rows = _source_rows(catalog, maximum)
        counters["eligible_sources"] = len(rows)
        for kind, source_id, size in rows:
            if size > MAX_TEXT_BYTES:
                counters["skipped_oversize"] += 1
                continue
            try:
                _source_key(kind, source_id)
                source = catalog.source(kind, source_id)
            except (ValueError, UnicodeError):
                source = None
            if source is None or not source.content.strip():
                counters["skipped_invalid"] += 1
                continue
            if _source_credentials_blocked(catalog, source):
                counters["skipped_credentials"] += 1
                continue
            counters["source_bytes"] += len(source.content.encode("utf-8"))
            if counters["source_bytes"] > MAX_SOURCE_BYTES:
                raise ValueError("embedding sources exceed 32 MiB; no partial index was published")
            result.append(source)
        return result, counters
    finally:
        catalog.conn.close()


def refresh_embedding_index(
    root: Path, *, endpoint: str, model: str, project_id: str | None = None,
    session_id: str | None = None, max_sources: int = 5000, batch_size: int = 16,
) -> dict[str, Any]:
    """Explicitly generate/reuse an all-or-nothing derived index snapshot.

    Max 5000 eligible sources, 32 MiB admitted UTF-8, 64 KiB/source, 2048 vector
    dimensions and 64 MiB cache. Oversize/credential/invalid sources are counted,
    never truncated. A provider/limit failure leaves the previous cache intact.
    Concurrent passes may last-writer-win; every query revalidates live authority.
    """
    _integer(max_sources, "max_sources", 1, MAX_SOURCES)
    _integer(batch_size, "batch_size", 1, MAX_BATCH_SIZE)
    endpoint, model, session_id, project_id, identity = _identity(root, endpoint, model, session_id, project_id)
    if not is_initialized(root):
        raise ValueError("embedding refresh requires an initialized explicit memory root")
    path = _cache_path(root, identity)
    sources, counters = _sources(root, session_id, project_id, max_sources)
    previous, previous_status = _load_index(root, identity)
    old_entries = {(entry["kind"], entry["id"]): entry for entry in previous["entries"]} if previous else {}
    entries = []
    pending = []
    reused = 0
    for source in sources:
        old = old_entries.get((source.kind, source.source_id))
        if old is not None and old["content_hash"] == source.content_hash:
            entries.append(old)
            reused += 1
        else:
            pending.append(source)
    dimensions = previous["dimensions"] if reused and previous else 0
    batches = 0
    position = 0
    while position < len(pending):
        batch: list[_Source] = []
        size = 0
        while position < len(pending) and len(batch) < batch_size:
            source = pending[position]
            next_size = len(source.content.encode("utf-8"))
            if batch and size + next_size > MAX_BATCH_BYTES:
                break
            batch.append(source)
            size += next_size
            position += 1
        vectors = embed_texts(endpoint=endpoint, model=model, texts=[source.content for source in batch])
        if dimensions and len(vectors[0]) != dimensions:
            raise EmbeddingError("embedding dimensions changed; previous index was preserved")
        dimensions = len(vectors[0])
        entries.extend({"kind": source.kind, "id": source.source_id, "content_hash": source.content_hash,
                        "vector": list(vector)} for source, vector in zip(batch, vectors))
        batches += 1
    entries.sort(key=lambda entry: (entry["kind"], entry["id"]))
    payload = {"schema_version": 1, "identity_sha256": identity, "dimensions": dimensions, "entries": entries}
    text = json.dumps(payload, ensure_ascii=True, allow_nan=False, separators=(",", ":")) + "\n"
    if len(text) > MAX_CACHE_BYTES:
        raise ValueError("embedding cache exceeds 64 MiB; previous index was preserved")
    # Recheck the path after provider I/O before the existing private atomic write.
    if _cache_path(root, identity) != path:
        raise ValueError("embedding cache path changed")
    secure_write_text(path, text)
    return {"schema_version": 1, "status": "refreshed", "identity_sha256": identity,
            "indexed_sources": len(entries), "embedded_sources": len(pending), "reused_sources": reused,
            "removed_sources": len(set(old_entries) - {(source.kind, source.source_id) for source in sources}),
            "provider_batches": batches, "dimensions": dimensions, "previous_index": previous_status,
            "cache_sha256": _digest(text), **counters, "instruction_authority": "none"}


def recall_indexed(
    root: Path, *, query: str, endpoint: str, model: str, project_id: str | None = None,
    session_id: str | None = None, limit: int = 8, token_budget: int = 2400,
    created_after: str | None = None, created_before: str | None = None,
) -> dict[str, Any]:
    """Fuse an existing index; never refresh/persist or start a model implicitly.

    All cached sources are revalidated before the top 256 positive cosine ranks
    are admitted. Missing/invalid/empty caches or provider failure give explicit
    lexical/associative fallback. Semantic status is inside the whole-packet
    budget. Querying an absent/fully stale cache makes no provider request.
    """
    endpoint, model, session_id, project_id, identity = _identity(root, endpoint, model, session_id, project_id)
    if type(query) is not str or not query.strip() or len(query) > 8192:
        raise ValueError("query must contain 1..8192 characters and non-whitespace text")
    _integer(limit, "limit", 1, 50)
    _integer(token_budget, "token_budget", 512, 32768)
    after, before = _time_filter(created_after, "created_after"), _time_filter(created_before, "created_before")
    if after is not None and before is not None and after >= before:
        raise ValueError("created_after must precede created_before")
    # Validate UTF-8 before any network access and without disclosing the query.
    try:
        query_hash = _digest(query)
    except UnicodeEncodeError:
        raise ValueError("query must be UTF-8 text") from None
    metadata: dict[str, Any] = {"status": "missing", "used": False, "validated_sources": 0,
                                "stale_excluded": 0, "credential_excluded": 0,
                                "semantic_candidates": 0, "candidates_truncated": False}
    semantic = None
    index, metadata["status"] = _load_index(root, identity) if is_initialized(root) else (None, "missing")
    if embedding_text_blocked(query):
        metadata["status"] = "query_blocked"
    elif index is not None:
        eligible = []
        catalog = _Catalog(root, session_id, project_id)
        try:
            for entry in index["entries"]:
                size = _source_bytes(catalog, entry["kind"], entry["id"])
                if size is None or size > MAX_TEXT_BYTES:
                    metadata["stale_excluded"] += 1
                    continue
                source = catalog.source(entry["kind"], entry["id"])
                if (source is None or source.content_hash != entry["content_hash"]
                        or (after is not None and source.created_at < after)
                        or (before is not None and source.created_at >= before)
                        or len(source.content.encode("utf-8")) > MAX_TEXT_BYTES):
                    metadata["stale_excluded"] += 1
                    continue
                if _source_credentials_blocked(catalog, source):
                    metadata["credential_excluded"] += 1
                    continue
                eligible.append(entry)
        finally:
            catalog.conn.close()
        metadata["validated_sources"] = len(eligible)
        if not eligible:
            metadata["status"] = "empty" if not index["entries"] else "no_eligible_sources"
        else:
            try:
                query_vector = embed_texts(endpoint=endpoint, model=model, texts=[query])[0]
                if len(query_vector) != index["dimensions"]:
                    raise EmbeddingError("embedding dimensions changed")
                ranked = [(cosine_similarity(query_vector, tuple(entry["vector"])), entry) for entry in eligible]
                ranked = [pair for pair in ranked if pair[0] > 0]
                ranked.sort(key=lambda pair: (-pair[0], pair[1]["kind"], pair[1]["id"]))
                selected: list[dict[str, Any]] = []
                semantic = {"model": model, "query_hash": query_hash, "query_vector": list(query_vector), "items": selected}
                # The established semantic interface also has a 2 MiB JSON
                # ceiling. Preserve highest ranks without overflowing it when
                # providers use the supported maximum vector dimension.
                encoded_bytes = len(json.dumps(semantic, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
                for _, entry in ranked[:256]:
                    item_bytes = len(json.dumps(entry, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
                    addition = item_bytes + bool(selected)
                    if encoded_bytes + addition > 2 * 1024 * 1024:
                        break
                    selected.append(entry)
                    encoded_bytes += addition
                metadata.update(status="ready", used=True, semantic_candidates=len(selected),
                                candidates_truncated=len(ranked) > len(selected))
            except EmbeddingError:
                metadata["status"] = "unavailable"
    packet = recall_memory(root, query=query, limit=limit, token_budget=token_budget,
                           created_after=created_after, created_before=created_before,
                           semantic=semantic, session_id=session_id, project_id=project_id)
    packet["semantic_index"] = metadata
    return _fit_packet(packet, token_budget)
