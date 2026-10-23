"""Small deterministic lexical reranker and query-centered evidence windows.

No model, index migration, or third-party ranking implementation is required.
Reciprocal-rank fusion combines ranks, not incompatible raw BM25/coverage scores.
"""
from __future__ import annotations

import re
from typing import Any


_WORDS = re.compile(r"[^\W_]+(?:[_.:/\\-][^\W_]+)*", re.UNICODE)
_STOP = frozenset("a an and are as at be by did do does for from how i in is it my of on or the to was were what where which who with you".split())


def query_terms(query: str) -> list[str]:
    terms: list[str] = []
    for match in _WORDS.finditer(query[:8192]):
        # FTS and regex matching need the original spelling: casefold expands
        # characters such as ß and İ, changing both tokens and source offsets.
        value = match.group()
        for term in [value, *re.split(r"[_.:/\\-]+", value)]:
            if len(term) >= 2 and term.casefold() not in _STOP and term not in terms:
                terms.append(term)
                if len(terms) == 16:
                    return terms
    return terms


def _hits(text: str, terms: list[str]) -> list[tuple[int, int, str]]:
    hits = []
    for term in terms:
        # Original-text offsets remain valid even for non-ASCII evidence.
        pattern = re.compile(r"(?<!\w)" + re.escape(term) + r"(?!\w)", re.IGNORECASE)
        for index, match in enumerate(pattern.finditer(text)):
            if index == 64:
                break
            hits.append((match.start(), match.end(), term))
    return sorted(hits)


def query_excerpt(text: str, query: str, *, limit: int = 360) -> dict[str, Any]:
    """Return a bounded excerpt plus character offsets into the unchanged source."""
    limit = max(8, int(limit))
    width = limit - 6  # reserve both ellipses; they are not source bytes
    hits = [hit for hit in _hits(text, query_terms(query)) if hit[1] - hit[0] <= width]
    start = 0
    if hits and len(text) > limit:
        counts: dict[str, int] = {}
        right = 0
        best: tuple[int, int, int] = (-1, -1, -len(text))
        for left, (position, _end, term) in enumerate(hits):
            while right < len(hits) and hits[right][1] <= position + width:
                key = hits[right][2]
                counts[key] = counts.get(key, 0) + 1
                right += 1
            span = hits[right - 1][1] - position if right > left else width
            quality = (len(counts), -span, -position)
            if quality > best:
                best = quality
                start = max(0, position - min(64, max(0, width - span) // 2))
            if term in counts:
                counts[term] -= 1
                if not counts[term]:
                    del counts[term]
    if len(text) <= limit:
        end = len(text)
    else:
        start = min(start, max(0, len(text) - width))
        end = min(len(text), start + width)
    return {
        "text": ("..." if start else "") + text[start:end] + ("..." if end < len(text) else ""),
        "start": start,
        "end": end,
    }


def rank_library_candidates(candidates: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    """Fuse upstream FTS rank and literal evidence rank over visible candidates only."""
    terms = query_terms(query)
    phrase = " ".join(query.casefold().split())[:512]
    for rank, item in enumerate(candidates, 1):
        text, title = str(item["text"]), str(item["title"])
        hits = _hits(text, terms)
        title_hits = _hits(title, terms)
        coverage = len({hit[2] for hit in hits}) / max(1, len(terms))
        title_coverage = len({hit[2] for hit in title_hits}) / max(1, len(terms))
        body_phrase = bool(phrase and phrase in " ".join(text.casefold().split()))
        title_phrase = bool(phrase and phrase in " ".join(title.casefold().split()))
        item["_literal_score"] = 4 * coverage + title_coverage + 2 * body_phrase + 2 * title_phrase
        item["_index_rank"] = rank
    literal_order = sorted(candidates, key=lambda item: (-item["_literal_score"], item["_index_rank"], item["chunk_id"]))
    for rank, item in enumerate(literal_order, 1):
        item["ranking"] = {"index_rank": item["_index_rank"], "literal_rank": rank, "method": "rrf_60"}
        item["ranking_score"] = 1 / (60 + item["_index_rank"]) + 1 / (60 + rank)
    return sorted(candidates, key=lambda item: (-item["ranking_score"], -item["_literal_score"], item["_index_rank"], item["chunk_id"]))
