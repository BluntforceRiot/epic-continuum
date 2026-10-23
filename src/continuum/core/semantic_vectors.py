"""Pure validation and scoring of explicitly supplied semantic evidence.

This module neither generates embeddings nor grants authority to source IDs.
Callers must separately revalidate source visibility, currentness, and hashes.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass

from .config import validate_inference_model_identifier


_MAX_ITEMS = 256
_MAX_DIMENSIONS = 2048
_MAX_SERIALIZED_BYTES = 2 * 1024 * 1024
_INPUT_FIELDS = frozenset({"model", "query_hash", "query_vector", "items"})
_ITEM_FIELDS = frozenset({"kind", "id", "content_hash", "vector"})
_KINDS = frozenset({"card", "scroll_event", "chunk"})
_SOURCE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class VectorEvidence:
    kind: str
    source_id: str
    content_hash: str
    vector: tuple[float, ...]


@dataclass(frozen=True)
class SemanticInput:
    model: str
    query_vector: tuple[float, ...]
    items: tuple[VectorEvidence, ...]


def _require_fields(value: object, fields: frozenset[str]) -> dict:
    # Only ordinary JSON objects/arrays are accepted. In particular, do not
    # invoke an arbitrary Mapping, iterator, or scalar coercion supplied by a
    # Python caller, even if it masquerades as a built-in container.
    if type(value) is not dict or len(value) != len(fields):
        raise ValueError("semantic object must contain exactly its supported fields")
    if any(type(key) is not str or key not in fields for key in value):
        raise ValueError("semantic object must contain exactly its supported fields")
    return value


def _normalized_vector(
    value: object, *, tuple_input: bool = False
) -> tuple[float, ...]:
    expected_type = tuple if tuple_input else list
    if type(value) is not expected_type or not 1 <= len(value) <= _MAX_DIMENSIONS:
        raise ValueError("semantic vector must contain between 1 and 2048 numbers")
    numbers = []
    for component in value:
        if type(component) not in (int, float):
            raise ValueError("semantic vector components must be finite numbers")
        try:
            number = float(component)
        except OverflowError:
            raise ValueError(
                "semantic vector components must be finite numbers"
            ) from None
        if not math.isfinite(number):
            raise ValueError("semantic vector components must be finite numbers")
        numbers.append(number)
    scale = max(abs(number) for number in numbers)
    if scale == 0:
        raise ValueError("semantic vector must not be zero")
    # Scale first: both squaring huge numbers and a norm of subnormal numbers
    # can otherwise overflow or underflow. At least one scaled value is +/-1.
    scaled = tuple(number / scale for number in numbers)
    norm = math.hypot(*scaled)
    return tuple(number / norm for number in scaled)


def _check_serialized_size(value: dict) -> None:
    # Run only after the exact, bounded JSON schema and finite numeric scalars
    # have been validated. Streaming avoids materializing an oversized JSON
    # string; even the largest remaining scalar is bounded (finite float/int).
    encoder = json.JSONEncoder(
        ensure_ascii=False, allow_nan=False, separators=(",", ":")
    )
    size = 0
    for fragment in encoder.iterencode(value):
        size += len(fragment.encode("utf-8"))
        if size > _MAX_SERIALIZED_BYTES:
            raise ValueError("semantic input exceeds the 2 MiB serialized size limit")


def parse_semantic_input(value: object, *, query: str) -> SemanticInput | None:
    """Validate plain JSON data and return detached, unit-length vectors.

    ``None`` disables semantic evidence. Other inputs must have exactly the
    documented fields and a SHA256 of the exact UTF-8 query (without trimming or
    Unicode normalization). The size cap measures compact UTF-8 JSON, not the
    whitespace or escape choices of a transport serialization. Errors contain
    no input values. No I/O, inference, or caller-data mutation occurs here.
    """
    if value is None:
        return None
    data = _require_fields(value, _INPUT_FIELDS)
    model = data["model"]
    if type(model) is not str or not 1 <= len(model) <= 128 or not model.isprintable():
        raise ValueError(
            "semantic model must be a printable alias of at most 128 characters"
        )
    try:
        model = validate_inference_model_identifier(model)
    except ValueError:
        raise ValueError(
            "semantic model must be a printable alias of at most 128 characters"
        ) from None

    query_hash = data["query_hash"]
    if type(query_hash) is not str or _SHA256.fullmatch(query_hash) is None:
        raise ValueError("semantic query hash must be a lowercase SHA256 digest")
    if type(query) is not str:
        raise ValueError("semantic query must be UTF-8 text")
    try:
        expected_hash = hashlib.sha256(query.encode("utf-8")).hexdigest()
    except UnicodeEncodeError:
        raise ValueError("semantic query must be UTF-8 text") from None
    if query_hash != expected_hash:
        raise ValueError("semantic query hash does not match the query")

    raw_items = data["items"]
    if type(raw_items) is not list or len(raw_items) > _MAX_ITEMS:
        raise ValueError("semantic items must be an array of at most 256 entries")
    query_vector = _normalized_vector(data["query_vector"])
    items = []
    seen = set()
    for raw_item in raw_items:
        item = _require_fields(raw_item, _ITEM_FIELDS)
        kind = item["kind"]
        if type(kind) is not str or len(kind) > 12 or kind not in _KINDS:
            raise ValueError("semantic item kind is unsupported")
        source_id = item["id"]
        if type(source_id) is not str or _SOURCE_ID.fullmatch(source_id) is None:
            raise ValueError(
                "semantic source ID must be a portable identifier of at most 128 characters"
            )
        content_hash = item["content_hash"]
        if type(content_hash) is not str or _SHA256.fullmatch(content_hash) is None:
            raise ValueError("semantic content hash must be a lowercase SHA256 digest")
        identity = (kind, source_id)
        if identity in seen:
            raise ValueError(
                "semantic items must not contain duplicate source identities"
            )
        seen.add(identity)
        vector = _normalized_vector(item["vector"])
        if len(vector) != len(query_vector):
            raise ValueError("semantic vectors must have matching dimensions")
        items.append(VectorEvidence(kind, source_id, content_hash, vector))
    _check_serialized_size(data)
    return SemanticInput(model, query_vector, tuple(items))


def cosine_similarity(left: tuple[float, ...], right: tuple[float, ...]) -> float:
    """Return stable cosine similarity in [-1, 1] for nonzero finite vectors.

    Inputs need not already have unit length. Invalid, empty, mismatched, or
    oversized vectors raise ``ValueError``, without disclosing their values.
    """
    normalized_left = _normalized_vector(left, tuple_input=True)
    normalized_right = _normalized_vector(right, tuple_input=True)
    if len(normalized_left) != len(normalized_right):
        raise ValueError("semantic vectors must have matching dimensions")
    score = math.fsum(a * b for a, b in zip(normalized_left, normalized_right))
    return max(-1.0, min(1.0, score))
