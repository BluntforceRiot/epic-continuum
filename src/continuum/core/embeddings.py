"""Explicit, bounded loopback embedding requests; never starts a model.

Only a caller-selected literal loopback HTTP(S) /v1 endpoint is accepted. Direct
http.client connections do not use proxy environment variables or redirects.
No credentials, configuration defaults, downloads or background work are used.
"""
from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import threading
import time
from urllib.parse import urlsplit

from .config import validate_inference_base_url, validate_inference_model_identifier
from .safety import scan_text_for_secrets, scan_value_for_secrets
from .semantic_vectors import _normalized_vector

MAX_BATCH_SIZE = 16
MAX_TEXT_BYTES = 64 * 1024
MAX_BATCH_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
HTTP_TIMEOUT_SECONDS = 10.0
TOTAL_TIMEOUT_SECONDS = 30.0


class EmbeddingError(RuntimeError):
    """Sanitized provider/protocol failure; contains no input or response data."""


def embedding_identity(endpoint: str, model: str) -> tuple[str, str]:
    """Canonicalize an explicit endpoint and model without I/O."""
    if type(endpoint) is not str or len(endpoint) > 256 or not endpoint.isprintable():
        raise ValueError("embedding endpoint must be an explicit loopback /v1 URL")
    try:
        parsed = urlsplit(validate_inference_base_url(endpoint))
        address = ipaddress.ip_address(parsed.hostname or "")
        if getattr(address, "scope_id", None) is not None:
            raise ValueError("scoped addresses are unsupported")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        raise ValueError("embedding endpoint must be an explicit loopback /v1 URL") from None
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    canonical = f"{parsed.scheme}://{host}:{port}/v1"
    if type(model) is not str or not 1 <= len(model) <= 128 or not model.isprintable():
        raise ValueError("embedding model must be a printable alias of at most 128 characters")
    try:
        checked = validate_inference_model_identifier(model)
    except ValueError:
        raise ValueError("embedding model must be a printable alias of at most 128 characters") from None
    if checked != model or scan_text_for_secrets(model, max_findings=1):
        raise ValueError("embedding model must be a non-sensitive canonical alias")
    return canonical, model


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(value: str) -> None:
    raise ValueError("non-finite JSON number")


def embedding_text_blocked(text: str) -> bool:
    """Apply existing credential guards before any embedding transmission.

    JSON escaping can hide a plaintext detector's word boundary. For valid JSON
    text (with an optional leading BOM), also scan decoded keys/values with the
    existing structured guard. Reject duplicate keys rather than losing an
    earlier sensitive value. Plain non-JSON notes keep their existing plaintext
    treatment; ambiguous or overly deep structured values fail closed without
    echoing their contents. This is a whole-JSON boundary check, not a parser for
    arbitrary embedded fragments or a claim to detect every possible secret.
    """
    if scan_text_for_secrets(text, max_findings=1):
        return True
    try:
        value = json.loads(text.removeprefix("\ufeff"), object_pairs_hook=_json_object,
                           parse_constant=_invalid_constant)
    except json.JSONDecodeError:
        return False
    except (ValueError, RecursionError, OverflowError):
        return True
    try:
        return bool(scan_value_for_secrets(value, scope="embedding_input", max_findings=1))
    except (ValueError, RecursionError, OverflowError):
        return True


def embed_texts(*, endpoint: str, model: str, texts: list[str]) -> list[tuple[float, ...]]:
    """Embed exact safe UTF-8 strings, returning detached unit-length vectors.

    Inputs are never truncated. Batches contain 1..16 texts, each <=64 KiB and
    together <=256 KiB UTF-8. Response vectors are finite, nonzero, consistently
    dimensioned (1..2048), indexed exactly once, and bound to the requested model.
    Both response bytes and total request lifetime are bounded. Any failure has
    a fixed error message without provider body, model alias or input content.
    """
    endpoint, model = embedding_identity(endpoint, model)
    if type(texts) is not list or not 1 <= len(texts) <= MAX_BATCH_SIZE:
        raise ValueError("embedding batch must contain 1..16 texts")
    total = 0
    for text in texts:
        if type(text) is not str or not text.strip():
            raise ValueError("embedding inputs must be nonempty UTF-8 text")
        try:
            size = len(text.encode("utf-8"))
        except UnicodeEncodeError:
            raise ValueError("embedding inputs must be UTF-8 text") from None
        if size > MAX_TEXT_BYTES:
            raise ValueError("embedding input exceeds 64 KiB; it was not truncated")
        if embedding_text_blocked(text):
            raise ValueError("embedding input blocked by credential policy")
        total += size
    if total > MAX_BATCH_BYTES:
        raise ValueError("embedding batch exceeds 256 KiB")
    payload = json.dumps({"model": model, "input": texts, "encoding_format": "float"},
                         ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    # Escaped control characters can expand the UTF-8 input. The source/batch
    # caps above imply a finite payload; keep a separate explicit wire ceiling.
    if len(payload) > 2 * 1024 * 1024:
        raise ValueError("embedding serialized request exceeds 2 MiB")
    parsed = urlsplit(endpoint)
    connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(parsed.hostname or "", parsed.port, timeout=HTTP_TIMEOUT_SECONDS)
    timer: threading.Timer | None = None
    deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    try:
        connection.connect()
        transport = connection.sock
        assert transport is not None

        def expire() -> None:
            # Retain the original socket: getresponse() may detach it from the
            # connection for Connection: close responses. This also interrupts
            # slowly dripped headers/bodies, not just an idle socket read.
            try:
                transport.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            transport.close()

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise EmbeddingError("embedding provider request failed")
        timer = threading.Timer(remaining, expire)
        timer.daemon = True
        timer.start()
        connection.request("POST", "/v1/embeddings", body=payload,
                           headers={"Content-Type": "application/json", "Accept": "application/json"})
        response = connection.getresponse()
        if response.status != 200 or response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise EmbeddingError("embedding provider request failed")
        length = response.getheader("Content-Length")
        if length is not None and (not length.isdecimal() or int(length) > MAX_RESPONSE_BYTES):
            raise EmbeddingError("embedding provider response is invalid")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES or time.monotonic() >= deadline:
            raise EmbeddingError("embedding provider response is invalid")
        data = json.loads(raw, object_pairs_hook=_json_object, parse_constant=_invalid_constant)
        if type(data) is not dict or data.get("model") != model:
            raise ValueError("model mismatch")
        rows = data.get("data")
        if type(rows) is not list or len(rows) != len(texts):
            raise ValueError("invalid response item count")
        indexed: dict[int, tuple[float, ...]] = {}
        dimensions = 0
        for row in rows:
            if type(row) is not dict:
                raise ValueError("invalid response item")
            index = row.get("index")
            if type(index) is not int or not 0 <= index < len(texts) or index in indexed:
                raise ValueError("invalid response index")
            vector = _normalized_vector(row.get("embedding"))
            if dimensions and len(vector) != dimensions:
                raise ValueError("inconsistent response dimensions")
            dimensions = len(vector)
            indexed[index] = vector
        return [indexed[index] for index in range(len(texts))]
    except EmbeddingError:
        raise
    except (OSError, http.client.HTTPException, ValueError, TypeError, RecursionError, OverflowError):
        raise EmbeddingError("embedding provider response is invalid or unavailable") from None
    finally:
        if timer is not None:
            timer.cancel()
        connection.close()
