"""Opt-in Library preservation of already-scanned adapter tool results."""
from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any

from .config import load_config
from .permissions import secure_mkdir
from .store import (
    _apply_scroll_secret_policy,
    append_scroll_event, atomic_write_text_file, audit_event, content_hash,
    continuum_uri, estimate_tokens, index_chunk_fts, json_dumps, json_loads,
    stable_id, utc_now,
)
from .units import parse_size


def record_indexed_tool_result(
    root: Path, *, session_id: str, event_type: str, text: str,
    metadata: dict[str, Any], max_reference_bytes: int,
) -> dict[str, Any]:
    """Preserve full evidence under the same secret policy as Scroll capture.

    Library rows and the Scroll reference commit together. The archive is written
    before that commit, as for ingest_file; an interrupted transaction may leave
    an unreferenced content-addressed archive, never a false successful reference.
    """
    session_id, event_type, _role, text, metadata = _apply_scroll_secret_policy(
        root, session_id=session_id, event_type=event_type, role="tool",
        content=text, metadata=metadata,
    )
    encoded = text.encode("utf-8")
    maximum = parse_size(load_config(root).get("storage", {}).get("max_ingest_bytes", "50MB"))
    if len(encoded) > maximum:
        raise ValueError("tool result exceeds storage.max_ingest_bytes")
    digest = content_hash(text)
    book_id = stable_id("book", "tool_output", session_id, json_dumps(metadata), digest)
    reference = f"[Continuum tool output indexed: {book_id}; {len(encoded)} bytes. Search Library, then read selected chunks.]"
    reference = reference.encode("utf-8")[:max_reference_bytes].decode("utf-8", errors="ignore")
    event_metadata = {
        **metadata,
        "capture": {
            "large_result_policy": "index_and_link", "truncated": True,
            "reference_only": True, "output_preserved": True, "book_id": book_id,
            "original_bytes": len(encoded), "original_sha256": digest,
            "stored_bytes": len(reference.encode("utf-8")),
        },
    }

    def preserve(conn: sqlite3.Connection, event: dict[str, Any]) -> None:
        # The committed Scroll row, not caller metadata, owns Library visibility.
        row = conn.execute("SELECT * FROM scroll_events WHERE id = ?", (event["event_id"],)).fetchone()
        if row is None:
            raise ValueError("tool output source event is missing")
        existing = conn.execute("SELECT content_hash FROM books WHERE id = ?", (book_id,)).fetchone()
        if existing is None:
            archive = root / "archive" / "originals" / "hot" / f"{book_id}.txt"
            secure_mkdir(archive.parent)
            if archive.exists():
                if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
                    raise ValueError("tool output archive hash mismatch")
            else:
                atomic_write_text_file(archive, text)
            uri = continuum_uri(root, archive)
            now = utc_now()
            title = "Tool output: " + str(metadata.get("tool_name") or "tool")[:160]
            book_metadata = {
                "source_type": "adapter_tool_output", "source_event_id": row["id"],
                "session_id": row["session_id"], "visibility_scope": row["visibility_scope"],
                "project_id": row["project_id"],
                "trust_level": "local_tool_evidence_non_authoritative",
                "instruction_authority": "user_level_evidence",
                "source_metadata": json_loads(row["metadata_json"], {}),
            }
            conn.execute(
                """INSERT INTO books(id,title,source_uri,original_uri,reader_uri,content_hash,
                       storage_tier,location_uri,status,metadata_json,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,'hot',?,'active',?,?,?)""",
                (book_id, title, f"scroll:{row['id']}", uri, uri, digest, uri, json_dumps(book_metadata), now, now),
            )
            # Exact, non-overlapping text slices: joining ordinal chunks recovers
            # the complete approved text, including whitespace and Unicode.
            start, ordinal = 0, 0
            while start < len(text):
                end = min(len(text), start + 4096)
                if end < len(text):
                    # Avoid splitting ordinary words at the indexing boundary;
                    # keep separators in the source slice for exact reconstruction.
                    split = max(text.rfind(separator, max(start, end - 256), end) for separator in (" ", "\n", "\t"))
                    if split >= start:
                        end = split + 1
                chunk = text[start:end]
                chunk_id = stable_id("chunk", book_id, str(ordinal), content_hash(chunk))
                conn.execute(
                    "INSERT INTO chunks(id,book_id,ordinal,text,content_hash,token_estimate,created_at) VALUES(?,?,?,?,?,?,?)",
                    (chunk_id, book_id, ordinal, chunk, content_hash(chunk), estimate_tokens(chunk), now),
                )
                index_chunk_fts(conn, chunk_id=chunk_id, book_id=book_id, title=title, text=chunk)
                start, ordinal = end, ordinal + 1
            audit_event(conn, action="index_tool_output", target_type="book", target_id=book_id,
                        payload={"event_id": row["id"], "content_hash": digest, "bytes": len(encoded)})
        elif existing["content_hash"] != digest:
            raise ValueError("tool output Library hash mismatch")
        event.update({"book_id": book_id, "output_preserved": True})

    return append_scroll_event(root, session_id=session_id, event_type=event_type, role="tool",
                               content=reference, metadata=event_metadata, transaction_effect=preserve)
