"""Read-only, explainable recall over the existing memory authority.

Vectors are optional caller-supplied evidence, never an embedding-service request.
Ranked candidate pools are bounded; database scan time is not. The packet budget
uses compact ASCII JSON characters / 4, not a model-specific token guarantee.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .retrieval import query_excerpt, query_terms
from .semantic_vectors import cosine_similarity, parse_semantic_input
from .store import (
    _card_row_visible,
    _card_sources_are_operational,
    _current_card_authority_clause,
    _current_project_state_source_references,
    _metadata_scope_visible,
    _valid_visible_current_project_state_ids,
    _visible_card_clause,
    _visible_scroll_clause,
    canonical_partition_identifier,
    connect_existing,
    cue_recall,
    is_initialized,
)

SOURCE_KINDS = ("card", "scroll_event", "chunk")
LEXICAL_POOL = 64
ASSOCIATIVE_POOL = 50
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


def _integer(value: int, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(f"{name} must be an integer from {low} to {high}")
    return value


def _source_key(kind: str, source_id: str) -> tuple[str, str]:
    if not isinstance(kind, str) or kind not in SOURCE_KINDS:
        raise ValueError("kind must be card, scroll_event, or chunk")
    if not isinstance(source_id, str) or not _ID.fullmatch(source_id):
        raise ValueError("source_id must be a portable identifier of at most 128 characters")
    return kind, source_id


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) > 64:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.astimezone(timezone.utc) if result.tzinfo is not None else None
    except (ValueError, OverflowError):
        return None


def _time_filter(value: str | None, name: str) -> datetime | None:
    if value is None:
        return None
    result = _timestamp(value)
    if result is None:
        raise ValueError(f"{name} must be an ISO-8601 timestamp with a UTC offset")
    return result


def _metadata(raw: str, *, library: bool = False) -> dict[str, Any] | None:
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return None
    if not isinstance(value, dict):
        return None
    # Preserve the Library's pre-partition global metadata convention.
    if library and "visibility_scope" not in value and not value.get("project_id"):
        value = {**value, "visibility_scope": "global"}
    return value


@dataclass(frozen=True)
class _Source:
    kind: str
    source_id: str
    title: str
    content: str
    created_at: datetime
    content_hash: str
    book_id: str | None = None
    ordinal: int | None = None


class _Catalog:
    """One read snapshot; all channels must rehydrate through this authority."""

    def __init__(self, root: Path, session_id: str | None, project_id: str | None):
        self.conn = connect_existing(root)
        self.session_id, self.project_id = session_id, project_id
        try:
            self.conn.execute("BEGIN")
            self.states = _valid_visible_current_project_state_ids(
                self.conn, session_id=session_id, project_id=project_id,
            )
            self.events, _ = _current_project_state_source_references(
                self.conn, session_id=session_id, project_id=project_id, valid_card_ids=self.states,
            )
            clause, params = _visible_card_clause(session_id=session_id, project_id=project_id)
            # A recovery pool cutoff is not proof that an exact ID is absent.
            # Load only current visible headers, then validate dependencies on
            # demand using the unchanged authority validator. No recovery limit
            # or existing store interface is widened by this read API.
            rows = self.conn.execute(
                f"""SELECT id, length(CAST(source_refs_json AS BLOB)) AS refs_bytes FROM cards
                    WHERE card_type != 'project_state' AND {clause}
                      AND {_current_card_authority_clause()}""", params,
            ).fetchall()
            self._card_sizes = {str(row["id"]): int(row["refs_bytes"] or 0) for row in rows}
            self._eligible_cards = set(self._card_sizes)
            self._card_memo: dict[str, bool] = {}
            self._event_id_cache: dict[str, tuple[str, str] | None] = {}
            self._event_coordinate_cache: dict[tuple[str, int], tuple[str, str] | None] = {}
        except BaseException:
            self.conn.close()
            raise

    def visible_metadata(self, raw: str, session: str | None, library: bool = False) -> bool:
        metadata = _metadata(raw, library=library)
        return metadata is not None and _metadata_scope_visible(
            metadata, candidate_session_id=metadata.get("session_id") if library else session,
            session_id=self.session_id, project_id=self.project_id,
        )

    def card_current(self, source_id: str) -> bool:
        if source_id in self.states:
            return True
        if source_id not in self._eligible_cards:
            return False
        return _card_sources_are_operational(
            self.conn, card_id=source_id, source_refs_bytes_by_card_id=self._card_sizes,
            eligible_non_project_card_ids=self._eligible_cards,
            valid_project_state_card_ids=self.states, valid_project_state_event_ids=self.events,
            memo=self._card_memo, visiting=set(), event_id_cache=self._event_id_cache,
            event_coordinate_cache=self._event_coordinate_cache,
        )

    def source(self, kind: str, source_id: str) -> _Source | None:
        row: sqlite3.Row | None
        book_id, ordinal = None, None
        if kind == "card":
            if not self.card_current(source_id):
                return None
            row = self.conn.execute("SELECT * FROM cards WHERE id=?", (source_id,)).fetchone()
            if row is None or not _card_row_visible(row, session_id=self.session_id, project_id=self.project_id):
                return None
            title, content = row["title"], row["title"] + "\n" + row["summary"]
        elif kind == "scroll_event":
            clause, params = _visible_scroll_clause(session_id=self.session_id, project_id=self.project_id)
            row = self.conn.execute(f"SELECT * FROM scroll_events WHERE id=? AND {clause}", (source_id, *params)).fetchone()
            if row is None or not self.visible_metadata(row["metadata_json"], row["session_id"]):
                return None
            if row["event_type"] == "project_state" and source_id not in self.events:
                return None
            title, content = str(row["event_type"]), row["content"]
        else:
            row = self.conn.execute(
                "SELECT c.*, b.title, b.metadata_json FROM chunks c JOIN books b ON b.id=c.book_id WHERE c.id=?",
                (source_id,),
            ).fetchone()
            if row is None or not self.visible_metadata(row["metadata_json"], None, True):
                return None
            title, content = row["title"], row["text"]
            book_id, ordinal = str(row["book_id"]), int(row["ordinal"])
        created = _timestamp(row["created_at"])
        if created is None or not isinstance(content, str) or not isinstance(title, str):
            return None
        return _Source(kind, source_id, title, content, created,
                       hashlib.sha256(content.encode("utf-8")).hexdigest(), book_id, ordinal)


def _scope(root: Path, session_id: str | None, project_id: str | None) -> tuple[str | None, str | None]:
    return (
        canonical_partition_identifier(root, "session_id", session_id, lookup=True),
        canonical_partition_identifier(root, "project_id", project_id, lookup=True),
    )


def read_memory_source(
    root: Path, *, kind: str, source_id: str, offset: int = 0, limit: int = 4000,
    content_hash: str | None = None, session_id: str | None = None, project_id: str | None = None,
) -> dict[str, Any]:
    """Read exact current evidence. A hash pins pagination to unchanged content.

    Cards use title + newline + summary; Scroll and chunks use their exact stored
    text. Missing, inaccessible, obsolete and hash-mismatched IDs are identical.
    """
    _source_key(kind, source_id)
    _integer(offset, "offset", 0, 2**63 - 1)
    _integer(limit, "limit", 1, 8000)
    if content_hash is not None and (not isinstance(content_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", content_hash)):
        raise ValueError("content_hash must be a lowercase SHA-256 digest")
    session_id, project_id = _scope(root, session_id, project_id)
    missing = {"found": False, "content": "", "next_offset": None}
    if not is_initialized(root):
        return missing
    catalog = _Catalog(root, session_id, project_id)
    try:
        source = catalog.source(kind, source_id)
        if source is None or (content_hash is not None and source.content_hash != content_hash):
            return missing
        if offset > len(source.content):
            raise ValueError("offset exceeds source length")
        end = min(len(source.content), offset + limit)
        next_chunk = None
        if source.book_id is not None and end == len(source.content):
            row = catalog.conn.execute(
                "SELECT id FROM chunks WHERE book_id=? AND ordinal>? ORDER BY ordinal, id LIMIT 1",
                (source.book_id, source.ordinal),
            ).fetchone()
            next_chunk = row["id"] if row else None
        return {
            "found": True, "kind": kind, "id": source_id, "title": source.title[:160],
            "content": source.content[offset:end], "offset": offset,
            "next_offset": end if end < len(source.content) else None,
            "total_chars": len(source.content), "content_hash": source.content_hash,
            "book_id": source.book_id, "next_chunk_id": next_chunk,
            "instruction_authority": "none",
        }
    finally:
        catalog.conn.close()


def _lexical(
    catalog: _Catalog, query: str, after: datetime | None, before: datetime | None,
) -> tuple[list[tuple[str, str]], bool]:
    patterns = [re.compile(r"(?<!\w)" + re.escape(term) + r"(?!\w)", re.IGNORECASE) for term in query_terms(query)]
    if not patterns:
        return [], False

    def score(title: str, content: str) -> int:
        return sum(4 * bool(p.search(content)) + bool(p.search(title)) for p in patterns)

    def in_time(value: str) -> bool:
        parsed = _timestamp(value)
        return parsed is not None and (after is None or parsed >= after) and (before is None or parsed < before)

    conn = catalog.conn
    conn.create_function("recall_score", 2, score, deterministic=True)
    conn.create_function("recall_time", 1, in_time, deterministic=True)
    conn.create_function("recall_card", 1, catalog.card_current, deterministic=True)
    conn.create_function("recall_event", 2, lambda event, kind: kind != "project_state" or event in catalog.events, deterministic=True)
    conn.create_function("recall_metadata", 3, catalog.visible_metadata, deterministic=True)
    card_clause, card_params = _visible_card_clause(session_id=catalog.session_id, project_id=catalog.project_id)
    event_clause, event_params = _visible_scroll_clause(session_id=catalog.session_id, project_id=catalog.project_id)
    queries = [
        ("card", f"""SELECT id, recall_score(title, summary) AS score FROM cards
             WHERE {card_clause} AND recall_card(id) AND recall_time(created_at) AND score>0
             ORDER BY score DESC, created_at DESC, id LIMIT ?""", card_params),
        ("scroll_event", f"""SELECT id, recall_score('', content) AS score FROM scroll_events
             WHERE {event_clause} AND recall_event(id, event_type)
               AND recall_metadata(metadata_json, session_id, 0) AND recall_time(created_at) AND score>0
             ORDER BY score DESC, created_at DESC, id LIMIT ?""", event_params),
        ("chunk", """SELECT c.id, recall_score(b.title, c.text) AS score FROM chunks c
             JOIN books b ON b.id=c.book_id WHERE recall_metadata(b.metadata_json, NULL, 1)
               AND recall_time(c.created_at) AND score>0
             ORDER BY score DESC, c.created_at DESC, c.id LIMIT ?""", []),
    ]
    candidates: list[tuple[int, str, str]] = []
    truncated = False
    for kind, sql, params in queries:
        rows = conn.execute(sql, (*params, LEXICAL_POOL + 1)).fetchall()
        truncated = truncated or len(rows) > LEXICAL_POOL
        candidates.extend((int(row["score"]), kind, str(row["id"])) for row in rows[:LEXICAL_POOL])
    candidates.sort(key=lambda value: (-value[0], value[1], value[2]))
    return [(kind, source_id) for _, kind, source_id in candidates], truncated


def _packet_size(packet: dict[str, Any]) -> int:
    return len(json.dumps(packet, ensure_ascii=True, separators=(",", ":")))


def _fit_packet(packet: dict[str, Any], budget: int) -> dict[str, Any]:
    # Include the size field itself, even when its decimal representation grows.
    while True:
        for _ in range(8):
            estimate = (_packet_size(packet) + 3) // 4
            if packet["budget"]["estimated_tokens"] == estimate:
                break
            packet["budget"]["estimated_tokens"] = estimate
        if _packet_size(packet) <= budget * 4:
            return packet
        if not packet["results"]:
            raise ValueError("token_budget cannot hold the recall envelope")
        packet["results"].pop()
        packet["retrieval"]["excluded_by_budget"] += 1
        packet["result_count"] = len(packet["results"])
        packet["abstained"] = not packet["results"]
        packet["budget"]["estimated_tokens"] = 0


def recall_memory(
    root: Path, *, query: str, limit: int = 8, token_budget: int = 2400,
    created_after: str | None = None, created_before: str | None = None,
    semantic: object = None, session_id: str | None = None, project_id: str | None = None,
) -> dict[str, Any]:
    """Fuse bounded lexical/associative/vector ranks, rechecking every source.

    Creation-time filters are [after, before), not historical fact validity.
    The associative channel supplies scoped routing hints from existing Cue
    Recall; selected payloads and vector hashes are checked in one read snapshot.
    """
    if not isinstance(query, str) or not query.strip() or len(query) > 8192:
        raise ValueError("query must contain 1..8192 characters and non-whitespace text")
    _integer(limit, "limit", 1, 50)
    _integer(token_budget, "token_budget", 512, 32768)
    after, before = _time_filter(created_after, "created_after"), _time_filter(created_before, "created_before")
    if after is not None and before is not None and after >= before:
        raise ValueError("created_after must precede created_before")
    vectors = parse_semantic_input(semantic, query=query)
    session_id, project_id = _scope(root, session_id, project_id)
    initialized = is_initialized(root)
    packet: dict[str, Any] = {
        "schema_version": 1, "initialized": initialized,
        "query_hash": hashlib.sha256(query.encode("utf-8")).hexdigest(),
        "results": [], "result_count": 0, "abstained": True,
        "instruction_authority": "none",
        "recorded_time": {"after": after.isoformat() if after else None, "before": before.isoformat() if before else None},
        "retrieval": {
            "method": "rrf_60", "channels": {"lexical": 0, "associative": 0, "semantic": 0},
            "semantic_model_sha256": hashlib.sha256(vectors.model.encode("utf-8")).hexdigest() if vectors else None,
            "candidate_limits": {"lexical_per_kind": LEXICAL_POOL, "associative": ASSOCIATIVE_POOL, "semantic": 256},
            "lexical_truncated": False, "candidate_count": 0,
            "excluded_by_limit": 0, "excluded_by_budget": 0,
        },
        "budget": {"requested_tokens": token_budget, "estimated_tokens": 0, "method": "compact_ascii_json_chars_div_4"},
    }
    if not initialized:
        return _fit_packet(packet, token_budget)
    hints = cue_recall(root, cue=query, session_id=session_id, project_id=project_id,
                       limit=ASSOCIATIVE_POOL, max_associations=16, create=False)
    catalog = _Catalog(root, session_id, project_id)
    try:
        sources: dict[tuple[str, str], _Source | None] = {}

        def eligible(key: tuple[str, str]) -> _Source | None:
            if key not in sources:
                source = catalog.source(*key)
                if source is not None and ((after is not None and source.created_at < after) or
                                           (before is not None and source.created_at >= before)):
                    source = None
                sources[key] = source
            return sources[key]

        lexical, truncated = _lexical(catalog, query, after, before)
        associative = []
        for hint in hints["results"]:
            kind = "chunk" if hint["kind"] == "library" else hint["kind"]
            key = _source_key(kind, hint["id"])
            if key not in associative and eligible(key) is not None:
                associative.append(key)
        semantic_ranks = []
        if vectors is not None:
            for item in vectors.items:
                key = (item.kind, item.source_id)
                source = eligible(key)
                if source is not None and source.content_hash == item.content_hash:
                    similarity = cosine_similarity(vectors.query_vector, item.vector)
                    if similarity > 0:
                        semantic_ranks.append((similarity, key))
        semantic_ranks.sort(key=lambda item: (-item[0], item[1]))
        channels = {"lexical": [key for key in lexical if eligible(key) is not None],
                    "associative": associative, "semantic": [key for _, key in semantic_ranks]}
        ranks: dict[tuple[str, str], dict[str, int]] = {}
        for channel, keys in channels.items():
            for rank, key in enumerate(keys, 1):
                ranks.setdefault(key, {})[channel] = rank
        scores = {key: sum(1 / (60 + rank) for rank in values.values()) for key, values in ranks.items()}
        ordered = sorted(ranks, key=lambda key: (-scores[key], key))
        packet["retrieval"].update(channels={name: len(keys) for name, keys in channels.items()},
                                    lexical_truncated=truncated, candidate_count=len(ordered),
                                    excluded_by_limit=max(0, len(ordered) - limit))
        for key in ordered[:limit]:
            source = sources[key]
            assert source is not None
            excerpt = query_excerpt(source.content, query, limit=480)
            packet["results"].append({
                "kind": key[0], "id": key[1], "title": source.title[:160],
                "content_hash": source.content_hash, "created_at": source.created_at.isoformat(),
                "excerpt": excerpt["text"], "excerpt_start": excerpt["start"], "excerpt_end": excerpt["end"],
                "total_chars": len(source.content), "ranks": ranks[key], "score": round(scores[key], 8),
            })
        packet["result_count"] = len(packet["results"])
        packet["abstained"] = not packet["results"]
        return _fit_packet(packet, token_budget)
    finally:
        catalog.conn.close()
