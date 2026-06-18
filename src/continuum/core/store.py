from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import sqlite3
import uuid
from pathlib import Path
from typing import Any

from .atomic import atomic_memory_card, write_atomic_yaml
from .config import config_path, default_config, load_config, write_default_config
from .permissions import secure_copy_file, secure_copytree, secure_mkdir, secure_sqlite_files, secure_write_text
from .safety import (
    is_ignored_path,
    redact_text_secrets,
    redact_value_secrets,
    scan_text_for_entropy_secrets,
    scan_text_for_secrets,
    scan_value_for_secrets,
)
from .units import format_size, parse_size


SCHEMA_VERSION = "0.1.0"
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = Path(__file__).with_name("schema.sql")
WORD_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/\\-]{1,}")
INDEX_DDL_MARKER = "\nCREATE INDEX"


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()


def stable_id(prefix: str, *parts: str) -> str:
    material = "\x1f".join(str(part) for part in parts).encode("utf-8", errors="replace")
    return f"{prefix}_{hashlib.sha1(material).hexdigest()[:24]}"


def unique_id(prefix: str) -> str:
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}_{timestamp}_{uuid.uuid4().hex[:16]}"


def safe_external_name(value: str, limit: int = 96) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return (cleaned or "source")[:limit]


def safe_source_name(value: str, *, fallback_digest: str | None = None, limit: int = 96) -> str:
    """Return a display/storage-safe source name without preserving secret-bearing filenames."""
    if scan_text_for_secrets(value):
        suffix = f"_{fallback_digest[:12]}" if fallback_digest else ""
        return f"redacted_source{suffix}"
    return safe_external_name(value, limit=limit)


def _secret_action(root: Path) -> str:
    try:
        security = load_config(root).get("security", {})
    except Exception:
        return "block"
    if not bool(security.get("secret_scan_enabled", True)):
        return "off"
    return str(security.get("secret_scan_action") or "block")


def enforce_text_secret_policy(root: Path, value: str, *, scope: str) -> str:
    """Apply root secret policy to a single durable text field before persistence."""
    action = _secret_action(root)
    if action == "off" or not value:
        return value
    findings = scan_text_for_secrets(value, max_findings=5)
    if not findings:
        return value
    if action == "block":
        raise ValueError(f"secret scan blocked {scope} before persistence: {len(findings)} finding(s)")
    return redact_text_secrets(value)


def redacted_identifier(value: str, *, prefix: str) -> str:
    return f"redacted_{prefix}_{content_hash(value)[:16]}"


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_write_text_file(path: Path, text: str) -> None:
    secure_write_text(path, text)


def continuum_uri(root: Path, path: Path | str) -> str:
    """Return a root-relative URI for files inside an Epic Continuum root."""
    candidate = Path(path)
    try:
        return candidate.resolve(strict=False).relative_to(root.resolve(strict=False)).as_posix()
    except (OSError, ValueError):
        return str(path)


def lexical_continuum_uri(root: Path, path: Path | str) -> str:
    """Return a root-relative URI without dereferencing symlinks when possible."""
    candidate = Path(path)
    try:
        return candidate.absolute().relative_to(root.absolute()).as_posix()
    except (OSError, ValueError):
        return continuum_uri(root, candidate)


def resolve_stored_uri(root: Path, uri: str | Path) -> Path:
    """Resolve a catalog URI, accepting both legacy absolute and root-relative values."""
    candidate = Path(str(uri))
    return candidate if candidate.is_absolute() else root / candidate


def is_internal_absolute_uri(root: Path, uri: str | Path) -> bool:
    candidate = Path(str(uri))
    if not candidate.is_absolute():
        return False
    try:
        candidate.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except (OSError, ValueError):
        return False


def _redact_scroll_identifier(field: str, value: str) -> str:
    prefixes = {
        "session_id": "redacted_session",
        "event_type": "redacted_event",
        "role": "redacted_role",
    }
    return f"{prefixes.get(field, 'redacted_identifier')}_{content_hash(value)[:16]}"


def _scan_scroll_identifiers(
    *,
    session_id: str,
    event_type: str,
    role: str,
    max_findings: int,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for field, value in {"session_id": session_id, "event_type": event_type, "role": role}.items():
        remaining = max_findings - len(findings)
        if remaining <= 0:
            break
        for item in scan_text_for_secrets(str(value), max_findings=remaining):
            findings.append(dict(item, scope=field))
            if len(findings) >= max_findings:
                break
    return findings


def _apply_scroll_secret_policy(
    root: Path,
    *,
    session_id: str,
    event_type: str,
    role: str,
    content: str,
    metadata: dict[str, Any],
) -> tuple[str, str, str, str, dict[str, Any]]:
    """Apply the root secret policy before any Scroll field is persisted."""
    security = load_config(root).get("security", {})
    if not bool(security.get("secret_scan_enabled", True)):
        return session_id, event_type, role, content, metadata
    action = str(security.get("secret_scan_action") or "block")
    if action == "off":
        return session_id, event_type, role, content, metadata

    findings = [dict(item, scope="content") for item in scan_text_for_secrets(content, max_findings=10)]
    remaining = max(0, 20 - len(findings))
    if remaining:
        findings.extend(scan_value_for_secrets(metadata, scope="metadata", max_findings=remaining))
    remaining = max(0, 20 - len(findings))
    if remaining:
        findings.extend(
            _scan_scroll_identifiers(
                session_id=session_id,
                event_type=event_type,
                role=role,
                max_findings=remaining,
            )
        )
    if not findings:
        return session_id, event_type, role, content, metadata
    if action == "block":
        raise ValueError(f"secret scan blocked Scroll event before persistence: {len(findings)} finding(s)")

    sanitized_metadata = redact_value_secrets(dict(metadata))
    sanitized_metadata["secret_scan_action"] = action
    sanitized_metadata["secret_findings"] = findings
    sanitized_session_id = _redact_scroll_identifier("session_id", session_id) if scan_text_for_secrets(session_id) else session_id
    sanitized_event_type = _redact_scroll_identifier("event_type", event_type) if scan_text_for_secrets(event_type) else event_type
    sanitized_role = _redact_scroll_identifier("role", role) if scan_text_for_secrets(role) else role
    return sanitized_session_id, sanitized_event_type, sanitized_role, redact_text_secrets(content), sanitized_metadata


def source_file_reference(root: Path, path: Path, *, digest: str | None = None, size_bytes: int | None = None) -> dict[str, Any]:
    display_name = safe_source_name(path.name or "source", fallback_digest=digest)
    name_redacted = display_name.startswith("redacted_source") and display_name != safe_external_name(path.name or "source")
    rel = continuum_uri(root, path)
    if rel != str(path):
        path_secret = bool(scan_text_for_secrets(rel, max_findings=1))
        if name_redacted or path_secret:
            return {
                "uri_base": "redacted_source",
                "uri": f"redacted:internal:{content_hash(rel)[:16]}",
                "name": display_name,
                "name_redacted": bool(name_redacted),
                "path_redacted": bool(path_secret),
                "path_hash": content_hash(rel),
                "content_hash": digest,
                "size_bytes": size_bytes,
            }
        return {
            "uri_base": "continuum_root",
            "uri": rel,
            "name": display_name,
            "name_redacted": False,
            "path_redacted": False,
            "content_hash": digest,
            "size_bytes": size_bytes,
        }
    external_text = str(path.resolve(strict=False))
    path_redacted = bool(scan_text_for_secrets(external_text, max_findings=1))
    return {
        "uri_base": "external_source",
        "uri": f"external:{display_name}",
        "name": display_name,
        "name_redacted": name_redacted,
        "path_redacted": path_redacted,
        "path_hash": content_hash(external_text),
        "content_hash": digest,
        "size_bytes": size_bytes,
    }


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def json_loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def estimate_tokens(text: str) -> int:
    """Return a fast planning estimate, not a tokenizer-exact count.

    The len/4 heuristic intentionally favors speed and zero dependencies. Adapters
    with access to a provider tokenizer can override budgets before model calls.
    """
    return max(1, len(text) // 4) if text else 0


def summarize_text(text: str, limit: int = 520) -> str:
    cleaned = " ".join(line.strip() for line in text.splitlines() if line.strip())
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3].rstrip() + "..."


def extract_terms(text: str, limit: int = 16) -> list[str]:
    counts: dict[str, int] = {}
    for raw in WORD_RE.findall(text):
        cleaned = raw.strip("`.,;:()[]{}<>\"'").casefold()
        parts = [cleaned]
        parts.extend(part for part in re.split(r"[_.:/\\-]+", cleaned) if part)
        for term in parts:
            if len(term) < 4 or term.isdigit():
                continue
            counts[term] = counts.get(term, 0) + 1
    return [term for term, _count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]]


def chunk_text(text: str, max_chars: int = 5000, overlap: int = 400) -> list[str]:
    if len(text) <= max_chars:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + max_chars)
        if end < len(text):
            split_at = text.rfind("\n\n", start, end)
            if split_at > start + (max_chars // 2):
                end = split_at
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end >= len(text):
            break
        start = max(0, end - overlap)
    return chunks


def truncate_to_token_budget(text: str, token_budget: int) -> tuple[str, bool]:
    if not text or token_budget <= 0:
        return "", bool(text)
    if estimate_tokens(text) <= token_budget:
        return text, False
    char_limit = max(1, token_budget * 4)
    suffix = "..."
    if char_limit <= len(suffix):
        return suffix[:char_limit], True
    return text[: char_limit - len(suffix)].rstrip() + suffix, True


def connect(root: Path) -> sqlite3.Connection:
    db_path = root / "catalog" / "catalog.sqlite3"
    secure_mkdir(root)
    secure_mkdir(db_path.parent)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    secure_sqlite_files(db_path)
    return conn


def connect_existing(root: Path) -> sqlite3.Connection:
    db_path = root / "catalog" / "catalog.sqlite3"
    if not db_path.exists():
        raise FileNotFoundError(str(db_path))
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def is_initialized(root: Path) -> bool:
    return (root / "catalog" / "catalog.sqlite3").exists()


def _status_config(root: Path, *, create: bool) -> dict[str, Any]:
    if create or config_path(root).exists():
        return load_config(root)
    return default_config()


def card_sidecar_path(root: Path, card_id: str) -> Path | None:
    config = load_config(root)
    atomic_config = config.get("atomic_memory", {})
    if not atomic_config.get("write_card_sidecars", True):
        return None
    return root / atomic_config.get("card_sidecar_dir", "catalog/cards") / f"{card_id}.yaml"


def init_layout(root: Path) -> None:
    secure_mkdir(root)
    dirs = [
        "archive/originals/hot",
        "archive/originals/warm",
        "archive/originals/cold",
        "archive/originals/vault",
        "archive/reader_editions/hot",
        "archive/reader_editions/warm",
        "archive/reader_editions/cold",
        "catalog/cards",
        "scroll/segments",
        "graph",
        "queues",
        "snapshots",
        "exports",
        "config",
        "run",
    ]
    for rel in dirs:
        secure_mkdir(root / rel)


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})")}


def _add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> bool:
    if column in _table_columns(conn, table):
        return False
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
    return True


def _schema_table_ddl() -> str:
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    index_at = schema.find(INDEX_DDL_MARKER)
    return schema if index_at < 0 else schema[:index_at]


def apply_schema_migrations(conn: sqlite3.Connection) -> list[str]:
    """Apply additive SQLite migrations for catalogs created by earlier builds."""
    applied: list[str] = []
    migrations = [
        ("books", "verification_status", "verification_status TEXT NOT NULL DEFAULT 'pending'"),
        ("books", "last_verified_at", "last_verified_at TEXT"),
        ("books", "last_tiered_at", "last_tiered_at TEXT"),
        ("cards", "visibility_scope", "visibility_scope TEXT NOT NULL DEFAULT 'global'"),
        ("cards", "session_id", "session_id TEXT"),
        ("cards", "project_id", "project_id TEXT"),
        ("cards", "recall_count", "recall_count INTEGER NOT NULL DEFAULT 0"),
        ("cards", "last_recalled_at", "last_recalled_at TEXT"),
        ("cards", "conflict_group", "conflict_group TEXT"),
        ("cards", "supersedes_card_id", "supersedes_card_id TEXT"),
        ("cards", "superseded_by_card_id", "superseded_by_card_id TEXT"),
        ("queue_jobs", "attempt_count", "attempt_count INTEGER NOT NULL DEFAULT 0"),
        ("queue_jobs", "error_json", "error_json TEXT"),
        ("queue_jobs", "lease_owner", "lease_owner TEXT"),
        ("queue_jobs", "lease_expires_at", "lease_expires_at TEXT"),
        ("queue_jobs", "heartbeat_at", "heartbeat_at TEXT"),
        ("graph_edges", "last_decay_at", "last_decay_at TEXT"),
    ]
    for table, column, ddl in migrations:
        if _add_column_if_missing(conn, table, column, ddl):
            applied.append(f"{table}.{column}")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cards_visibility ON cards(visibility_scope, session_id, project_id, salience DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_queue_role_priority ON queue_jobs(role, status, priority, created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_queue_lease_expiry ON queue_jobs(status, lease_expires_at)")
    conn.execute("PRAGMA user_version = 2")
    return applied


def init_db(root: Path) -> None:
    init_layout(root)
    write_default_config(root)
    conn = connect(root)
    try:
        conn.executescript(_schema_table_ddl())
        applied = apply_schema_migrations(conn)
        conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)", (SCHEMA_VERSION,))
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('schema_user_version', ?)", ("2",))
        if applied:
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('last_migration_at', ?)", (utc_now(),))
        conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('created_at', ?)", (utc_now(),))
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('fts5_available', ?)", ("1" if ensure_fts(conn) else "0",))
        conn.commit()
    finally:
        conn.close()


def record_artifact(
    conn: sqlite3.Connection,
    *,
    kind: str,
    uri: str,
    sha256: str,
    size_bytes: int,
    operation_id: str | None = None,
    immutable: bool = True,
    source_type: str | None = None,
    trust_level: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> str:
    artifact_id = stable_id("artifact", kind, uri, sha256)
    conn.execute(
        """
        INSERT INTO artifacts(
            id, kind, uri, sha256, size_bytes, created_at, operation_id,
            immutable, source_type, trust_level, metadata_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(uri, sha256) DO UPDATE SET
            operation_id = COALESCE(artifacts.operation_id, excluded.operation_id),
            source_type = COALESCE(artifacts.source_type, excluded.source_type),
            trust_level = COALESCE(artifacts.trust_level, excluded.trust_level),
            metadata_json = excluded.metadata_json
        """,
        (
            artifact_id,
            kind,
            uri,
            sha256,
            int(size_bytes),
            utc_now(),
            operation_id,
            1 if immutable else 0,
            source_type,
            trust_level,
            json_dumps(metadata or {}),
        ),
    )
    row = conn.execute("SELECT id FROM artifacts WHERE uri = ? AND sha256 = ?", (uri, sha256)).fetchone()
    return str(row["id"] if row else artifact_id)


def ensure_fts(conn: sqlite3.Connection) -> bool:
    try:
        conn.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts
            USING fts5(chunk_id UNINDEXED, book_id UNINDEXED, title, text)
            """
        )
    except sqlite3.OperationalError:
        return False
    return True


def delete_book_fts(conn: sqlite3.Connection, book_id: str) -> bool:
    if not ensure_fts(conn):
        return False
    conn.execute("DELETE FROM chunks_fts WHERE book_id = ?", (book_id,))
    return True


def index_chunk_fts(
    conn: sqlite3.Connection,
    *,
    chunk_id: str,
    book_id: str,
    title: str,
    text: str,
) -> bool:
    if not ensure_fts(conn):
        return False
    conn.execute(
        "INSERT INTO chunks_fts(chunk_id, book_id, title, text) VALUES(?, ?, ?, ?)",
        (chunk_id, book_id, title, text),
    )
    return True


def audit_search_index(root: Path, *, create: bool = False) -> dict[str, Any]:
    if not create and not (root / "catalog" / "catalog.sqlite3").exists():
        return {
            "ok": False,
            "initialized": False,
            "fts_available": False,
            "chunks": 0,
            "fts_rows": 0,
            "missing_chunks": 0,
            "orphan_fts_rows": 0,
            "reason": "catalog_missing",
        }
    if create:
        init_db(root)
        conn = connect(root)
    else:
        conn = connect_existing(root)
    try:
        if create:
            fts_available = ensure_fts(conn)
        else:
            fts_available = bool(
                conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'chunks_fts'"
                ).fetchone()
            )
        chunks = conn.execute("SELECT COUNT(*) AS n FROM chunks").fetchone()["n"]
        if not fts_available:
            return {
                "ok": True,
                "degraded": True,
                "initialized": True,
                "fts_available": False,
                "chunks": chunks,
                "fts_rows": 0,
                "missing_chunks": 0,
                "orphan_fts_rows": 0,
                "reason": "fts5_unavailable_like_fallback",
            }
        fts_rows = conn.execute("SELECT COUNT(*) AS n FROM chunks_fts").fetchone()["n"]
        missing_chunks = conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM chunks c
            WHERE NOT EXISTS (
                SELECT 1 FROM chunks_fts f WHERE f.chunk_id = c.id
            )
            """
        ).fetchone()["n"]
        orphan_fts_rows = conn.execute(
            """
            SELECT COUNT(*) AS n
            FROM chunks_fts f
            WHERE NOT EXISTS (
                SELECT 1 FROM chunks c WHERE c.id = f.chunk_id
            )
            """
        ).fetchone()["n"]
        ok = (
            fts_available
            and chunks == fts_rows
            and missing_chunks == 0
            and orphan_fts_rows == 0
        )
        return {
            "ok": ok,
            "initialized": True,
            "fts_available": fts_available,
            "chunks": chunks,
            "fts_rows": fts_rows,
            "missing_chunks": missing_chunks,
            "orphan_fts_rows": orphan_fts_rows,
            "reason": "ok" if ok else "search_index_inconsistent",
        }
    finally:
        conn.close()


def rebuild_search_index(root: Path) -> dict[str, Any]:
    init_db(root)
    conn = connect(root)
    try:
        if not ensure_fts(conn):
            return {
                "ok": True,
                "degraded": True,
                "fts_available": False,
                "chunks": conn.execute("SELECT COUNT(*) AS n FROM chunks").fetchone()["n"],
                "fts_rows": 0,
                "reason": "fts5_unavailable_like_fallback",
            }
        conn.execute("DELETE FROM chunks_fts")
        conn.execute(
            """
            INSERT INTO chunks_fts(chunk_id, book_id, title, text)
            SELECT c.id, c.book_id, b.title, c.text
            FROM chunks c
            JOIN books b ON b.id = c.book_id
            ORDER BY c.book_id, c.ordinal
            """
        )
        conn.commit()
    finally:
        conn.close()
    audit = audit_search_index(root, create=False)
    return {
        "ok": audit["ok"],
        "fts_available": audit["fts_available"],
        "chunks": audit["chunks"],
        "fts_rows": audit["fts_rows"],
        "missing_chunks": audit["missing_chunks"],
        "orphan_fts_rows": audit["orphan_fts_rows"],
        "reason": audit["reason"],
    }


SQLITE_SECRET_AUDIT_SUFFIXES = {".sqlite", ".sqlite3", ".db"}
LEGACY_SECRET_REDACTION_COLUMNS: dict[str, set[str]] = {
    "audit_events": {"actor", "target_id", "payload_json"},
    "snapshots": {"reason"},
}


def _secret_allowlist_path(root: Path, security: dict[str, Any]) -> Path:
    configured = str(security.get("secret_allowlist_file") or "security/secret_allowlist.jsonl")
    candidate = Path(configured)
    return candidate if candidate.is_absolute() else root / candidate


def _load_secret_allowlist_hashes(root: Path, security: dict[str, Any]) -> set[str]:
    path = _secret_allowlist_path(root, security)
    if not path.exists():
        return set()
    hashes: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = stripped
        if isinstance(payload, dict):
            value = payload.get("secret_hash") or payload.get("finding_hash") or payload.get("hash")
        else:
            value = payload
        if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value):
            hashes.add(value.casefold())
    return hashes


def _finding_is_allowlisted(finding: dict[str, Any], allowlist_hashes: set[str]) -> bool:
    secret_hash = finding.get("secret_hash")
    return isinstance(secret_hash, str) and secret_hash.casefold() in allowlist_hashes


def _quote_sqlite_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _scan_sqlite_identifier_for_sensitive_key(identifier: str, *, scope: str, max_findings: int) -> list[dict[str, Any]]:
    """Detect schema identifiers such as client_secret even when they have no value attached."""
    if max_findings <= 0:
        return []
    findings: list[dict[str, Any]] = []
    # scan_value_for_secrets uses the structured sensitive-key classifier, while
    # scan_text_for_secrets only sees token-shaped or assignment-shaped strings.
    for finding in scan_value_for_secrets({identifier: "__present__"}, scope=scope, max_findings=max_findings):
        if finding.get("type") != "sensitive_metadata_key":
            continue
        scoped = dict(finding)
        scoped["secret_hash"] = content_hash(identifier)
        findings.append(scoped)
        if len(findings) >= max_findings:
            break
    return findings


def _scan_sqlite_sensitive_column_value(column: str, value: Any, *, scope: str, max_findings: int) -> list[dict[str, Any]]:
    """Detect ordinary-looking values persisted under sensitive SQLite column names."""
    if max_findings <= 0 or value in (None, "", False):
        return []
    findings: list[dict[str, Any]] = []
    for finding in scan_value_for_secrets({column: value}, scope=scope, max_findings=max_findings):
        if finding.get("type") != "sensitive_metadata_key":
            continue
        findings.append(dict(finding))
        if len(findings) >= max_findings:
            break
    return findings


def _json_loads_preserving_duplicate_keys(text: str) -> Any:
    """Parse JSON for auditing without letting later duplicate keys hide earlier values.

    JSON objects are represented as lists of one-key dictionaries.  The existing
    recursive secret scanner understands both lists and dictionaries, so every
    occurrence remains visible while no ambiguous object is normalized into a
    misleading last-key-wins mapping.
    """

    def preserve_pairs(pairs: list[tuple[str, Any]]) -> list[dict[str, Any]]:
        return [{key: value} for key, value in pairs]

    def reject_nonfinite(value: str) -> Any:
        raise ValueError(f"non-finite JSON number is not allowed: {value}")

    return json.loads(text, object_pairs_hook=preserve_pairs, parse_constant=reject_nonfinite)


def _scan_serialized_json_value_for_secrets(text: str, *, scope: str, max_findings: int) -> list[dict[str, Any]]:
    """Scan JSON/JSONL payloads for sensitive metadata keys with ordinary-looking values."""
    if max_findings <= 0:
        return []
    stripped = text.strip()
    if not stripped:
        return []
    findings: list[dict[str, Any]] = []

    def add_payload(payload: Any, *, line_offset: int) -> None:
        nonlocal findings
        remaining = max_findings - len(findings)
        if remaining <= 0:
            return
        for finding in scan_value_for_secrets(payload, scope=scope, max_findings=remaining):
            scoped = dict(finding)
            try:
                scoped["line"] = int(scoped.get("line") or 1) + max(0, line_offset - 1)
            except (TypeError, ValueError):
                scoped["line"] = line_offset
            scoped.setdefault("scope", scope)
            findings.append(scoped)
            if len(findings) >= max_findings:
                return

    try:
        add_payload(_json_loads_preserving_duplicate_keys(stripped), line_offset=1)
        return findings[:max_findings]
    except (json.JSONDecodeError, TypeError, ValueError):
        pass

    for line_number, line in enumerate(text.splitlines(), start=1):
        if len(findings) >= max_findings:
            break
        candidate = line.strip()
        if not candidate or candidate[0] not in "[{":
            continue
        try:
            payload = _json_loads_preserving_duplicate_keys(candidate)
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
        add_payload(payload, line_offset=line_number)
    return findings[:max_findings]


def _redact_serialized_json_text_secrets(text: str) -> str:
    """Redact JSON/JSONL sensitive metadata values while preserving text when parsing fails."""
    stripped = text.strip()
    if not stripped:
        return redact_text_secrets(text)
    try:
        payload = json.loads(stripped)
    except (json.JSONDecodeError, TypeError, ValueError):
        payload = None
    if payload is not None:
        return json.dumps(redact_value_secrets(payload), ensure_ascii=True, sort_keys=True)

    changed = False
    out_lines: list[str] = []
    for line in text.splitlines():
        candidate = line.strip()
        if candidate and candidate[0] in "[{":
            try:
                payload = json.loads(candidate)
            except (json.JSONDecodeError, TypeError, ValueError):
                out_lines.append(redact_text_secrets(line))
            else:
                out_lines.append(json.dumps(redact_value_secrets(payload), ensure_ascii=True, sort_keys=True))
                changed = True
        else:
            out_lines.append(redact_text_secrets(line))
    result = "\n".join(out_lines)
    return result if changed else redact_text_secrets(text)


def _scan_sqlite_text_for_secrets(path: Path, *, max_findings: int) -> list[dict[str, Any]]:
    """Best-effort logical scan of SQLite text columns; bounded by max_findings.

    A file extension is not proof that a file is SQLite. Archived evidence may
    legitimately use ``.db`` for an unrelated format, so reject non-SQLite
    signatures before opening and keep this audit path fail-safe.
    """
    if max_findings <= 0 or path.suffix.casefold() not in SQLITE_SECRET_AUDIT_SUFFIXES:
        return []
    try:
        with path.open("rb") as handle:
            if handle.read(16) != b"SQLite format 3\x00":
                return []
    except OSError:
        return []
    findings: list[dict[str, Any]] = []
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=2)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error:
        return []
    try:
        tables = [
            str(row["name"])
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            if row["name"] and not str(row["name"]).startswith("sqlite_")
        ]
        for table in tables:
            if len(findings) >= max_findings:
                break
            table_text_findings = scan_text_for_secrets(table, max_findings=max_findings - len(findings))
            safe_table = redact_text_secrets(table) if table_text_findings else table
            table_redacted = safe_table != table
            table_findings = list(table_text_findings)
            if len(table_findings) < max_findings - len(findings):
                table_findings.extend(
                    _scan_sqlite_identifier_for_sensitive_key(
                        table,
                        scope="sqlite_schema:table_sensitive_key",
                        max_findings=max_findings - len(findings) - len(table_findings),
                    )
                )
            for finding in table_findings:
                scoped = dict(finding)
                scoped["scope"] = scoped.get("scope") or "sqlite_schema:table"
                scoped["sqlite_table"] = safe_table
                scoped["sqlite_table_redacted"] = table_redacted
                if table_redacted:
                    scoped["sqlite_table_hash"] = content_hash(table)
                elif scoped.get("type") == "sensitive_metadata_key":
                    scoped["sqlite_table_hash"] = content_hash(table)
                findings.append(scoped)
                if len(findings) >= max_findings:
                    break
            if len(findings) >= max_findings:
                break
            try:
                columns = [
                    str(row["name"])
                    for row in conn.execute(f"PRAGMA table_info({_quote_sqlite_identifier(table)})")
                    if row["name"]
                ]
            except sqlite3.Error:
                continue
            if not columns:
                continue
            safe_columns: dict[str, tuple[str, bool]] = {}
            for column in columns:
                column_text_findings = scan_text_for_secrets(column, max_findings=max_findings - len(findings))
                safe_column = redact_text_secrets(column) if column_text_findings else column
                column_redacted = safe_column != column
                safe_columns[column] = (safe_column, column_redacted)
                column_findings = list(column_text_findings)
                if len(column_findings) < max_findings - len(findings):
                    column_findings.extend(
                        _scan_sqlite_identifier_for_sensitive_key(
                            column,
                            scope="sqlite_schema:column_sensitive_key",
                            max_findings=max_findings - len(findings) - len(column_findings),
                        )
                    )
                for finding in column_findings:
                    scoped = dict(finding)
                    scoped["scope"] = scoped.get("scope") or "sqlite_schema:column"
                    scoped["sqlite_table"] = safe_table
                    scoped["sqlite_table_redacted"] = table_redacted
                    if table_redacted:
                        scoped["sqlite_table_hash"] = content_hash(table)
                    scoped["sqlite_column"] = safe_column
                    scoped["sqlite_column_redacted"] = column_redacted
                    if column_redacted or scoped.get("type") == "sensitive_metadata_key":
                        scoped["sqlite_column_hash"] = content_hash(column)
                    findings.append(scoped)
                    if len(findings) >= max_findings:
                        break
                if len(findings) >= max_findings:
                    break
            if len(findings) >= max_findings:
                break
            select_cols = ", ".join(_quote_sqlite_identifier(column) for column in columns)
            try:
                rows = conn.execute(f"SELECT rowid AS __rowid__, {select_cols} FROM {_quote_sqlite_identifier(table)} LIMIT 10000")
            except sqlite3.Error:
                continue
            for row in rows:
                if len(findings) >= max_findings:
                    break
                rowid = row["__rowid__"] if "__rowid__" in row.keys() else None
                for column in columns:
                    value = row[column]
                    if value is None:
                        continue
                    if isinstance(value, bytes):
                        text = value.decode("utf-8", errors="replace")
                    else:
                        text = str(value)
                    if not text:
                        continue
                    remaining = max_findings - len(findings)
                    safe_column, column_redacted = safe_columns.get(column, (column, False))
                    row_findings = scan_text_for_secrets(text, max_findings=remaining)
                    if len(row_findings) < remaining:
                        row_findings.extend(
                            _scan_serialized_json_value_for_secrets(
                                text,
                                scope=f"sqlite_json:{safe_table}.{safe_column}",
                                max_findings=remaining - len(row_findings),
                            )
                        )
                    if not row_findings and len(row_findings) < remaining:
                        row_findings.extend(
                            _scan_sqlite_sensitive_column_value(
                                column,
                                value,
                                scope=f"sqlite_sensitive_column:{safe_table}.{safe_column}",
                                max_findings=remaining - len(row_findings),
                            )
                        )
                    for finding in row_findings:
                        scoped = dict(finding)
                        scoped["scope"] = scoped.get("scope") or f"sqlite:{safe_table}.{safe_column}"
                        scoped["sqlite_table"] = safe_table
                        scoped["sqlite_table_redacted"] = table_redacted
                        if table_redacted:
                            scoped["sqlite_table_hash"] = content_hash(table)
                        scoped["sqlite_column"] = safe_column
                        scoped["sqlite_column_redacted"] = column_redacted
                        if column_redacted:
                            scoped["sqlite_column_hash"] = content_hash(column)
                        scoped["sqlite_rowid"] = rowid
                        findings.append(scoped)
                        if len(findings) >= max_findings:
                            break
    finally:
        conn.close()
    return findings


def audit_secrets(
    root: Path,
    *,
    create: bool = False,
    max_findings: int | None = None,
    max_file_bytes: int | None = None,
) -> dict[str, Any]:
    """Scan an Epic Continuum root for obvious secret patterns without initializing missing roots."""
    if create:
        init_db(root)
    elif not root.exists():
        return {
            "ok": False,
            "initialized": False,
            "root": str(root),
            "files_scanned": 0,
            "files_skipped": 0,
            "complete": False,
            "incomplete_skip_count": 0,
            "incomplete_skips": [],
            "finding_count": 0,
            "findings": [],
            "skipped": [],
            "reason": "root_missing",
        }

    config = _status_config(root, create=create)
    security = config.get("security", {})
    if max_findings is None:
        max_findings = int(security.get("secret_audit_max_findings", 200))
    if max_file_bytes is None:
        max_file_bytes = parse_size(security.get("secret_audit_max_file_bytes", "20MB"))
    max_findings = max(1, int(max_findings))
    max_file_bytes = max(1, int(max_file_bytes))
    entropy_enabled = bool(security.get("entropy_secret_scan_enabled", False))
    entropy_min_length = int(security.get("entropy_min_length", 32))
    entropy_min_bits = float(security.get("entropy_min_bits_per_char", 4.5))
    allowlist_path = _secret_allowlist_path(root, security)
    allowlist_hashes = _load_secret_allowlist_hashes(root, security)

    findings: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    allowlisted_findings = 0
    files_scanned = 0
    files_skipped = 0

    def append_finding(finding: dict[str, Any], *, use_allowlist: bool = True) -> bool:
        nonlocal allowlisted_findings
        if use_allowlist and _finding_is_allowlisted(finding, allowlist_hashes):
            allowlisted_findings += 1
            return False
        findings.append(finding)
        return True

    candidates = sorted(root.rglob("*"), key=lambda item: item.as_posix()) if root.exists() else []
    for path in candidates:
        if not path.is_file() and not path.is_symlink():
            continue
        is_allowlist_file = path.resolve(strict=False) == allowlist_path.resolve(strict=False)
        try:
            rel = lexical_continuum_uri(root, path) if path.is_symlink() else continuum_uri(root, path)
            path_findings = scan_text_for_secrets(rel, max_findings=5)
            safe_rel = redact_text_secrets(rel) if path_findings else rel
            path_redacted = safe_rel != rel
            if path.is_symlink():
                try:
                    link_target = os.readlink(path)
                except OSError as exc:
                    link_target = ""
                    link_error = str(exc)
                else:
                    link_error = None
                try:
                    size = path.lstat().st_size
                except OSError:
                    size = 0
                remaining = max_findings - len(findings)
                if remaining <= 0:
                    break
                target_findings = scan_text_for_secrets(link_target, max_findings=remaining) if link_target else []
                target_is_absolute = bool(link_target and Path(link_target).is_absolute())
                if target_is_absolute:
                    safe_target = f"external:{safe_source_name(Path(link_target).name or 'symlink_target', fallback_digest=content_hash(link_target))}"
                else:
                    safe_target = redact_text_secrets(link_target) if target_findings else link_target
                for finding in path_findings[:remaining]:
                    scoped = dict(finding)
                    scoped["path"] = safe_rel
                    scoped["path_redacted"] = path_redacted
                    if path_redacted:
                        scoped["path_hash"] = content_hash(rel)
                    scoped["scope"] = "symlink_path"
                    scoped["size_bytes"] = size
                    append_finding(scoped, use_allowlist=not is_allowlist_file)
                    if len(findings) >= max_findings:
                        break
                remaining = max_findings - len(findings)
                for finding in target_findings[:remaining]:
                    scoped = dict(finding)
                    scoped["path"] = safe_rel
                    scoped["path_redacted"] = path_redacted
                    if path_redacted:
                        scoped["path_hash"] = content_hash(rel)
                    scoped["scope"] = "symlink_target"
                    scoped["link_target"] = safe_target
                    scoped["link_target_redacted"] = safe_target != link_target
                    scoped["link_target_hash"] = content_hash(link_target)
                    scoped["size_bytes"] = size
                    append_finding(scoped, use_allowlist=not is_allowlist_file)
                    if len(findings) >= max_findings:
                        break
                files_skipped += 1
                skipped.append(
                    {
                        "path": safe_rel,
                        "path_redacted": path_redacted,
                        **({"path_hash": content_hash(rel)} if path_redacted else {}),
                        "reason": "symlink_skipped",
                        "link_target": safe_target,
                        "link_target_redacted": safe_target != link_target,
                        "link_target_absolute": target_is_absolute,
                        **({"link_target_hash": content_hash(link_target)} if link_target else {}),
                        **({"error": link_error} if link_error else {}),
                    }
                )
                continue
            size = path.stat().st_size
            remaining = max_findings - len(findings)
            if remaining <= 0:
                break
            for finding in path_findings[:remaining]:
                scoped = dict(finding)
                scoped["path"] = safe_rel
                scoped["path_redacted"] = path_redacted
                if path_redacted:
                    scoped["path_hash"] = content_hash(rel)
                scoped["scope"] = "path"
                scoped["size_bytes"] = size
                append_finding(scoped, use_allowlist=not is_allowlist_file)
                if len(findings) >= max_findings:
                    break
            if len(findings) >= max_findings:
                break
            sqlite_remaining = max_findings - len(findings)
            for finding in _scan_sqlite_text_for_secrets(path, max_findings=sqlite_remaining):
                scoped = dict(finding)
                scoped["path"] = safe_rel
                scoped["path_redacted"] = path_redacted
                if path_redacted:
                    scoped["path_hash"] = content_hash(rel)
                scoped["size_bytes"] = size
                append_finding(scoped, use_allowlist=not is_allowlist_file)
                if len(findings) >= max_findings:
                    break
            if len(findings) >= max_findings:
                break
            if size > max_file_bytes and not is_allowlist_file:
                files_skipped += 1
                skipped.append(
                    {
                        "path": safe_rel,
                        "path_redacted": path_redacted,
                        **({"path_hash": content_hash(rel)} if path_redacted else {}),
                        "reason": "too_large",
                        "size_bytes": size,
                        "max_file_bytes": max_file_bytes,
                    }
                )
                continue
            data = path.read_bytes()
        except OSError as exc:
            files_skipped += 1
            rel = continuum_uri(root, path)
            path_findings = scan_text_for_secrets(rel, max_findings=1)
            safe_rel = redact_text_secrets(rel) if path_findings else rel
            skipped.append(
                {
                    "path": safe_rel,
                    "path_redacted": safe_rel != rel,
                    **({"path_hash": content_hash(rel)} if safe_rel != rel else {}),
                    "reason": "unreadable",
                    "error": str(exc),
                }
            )
            continue
        files_scanned += 1
        remaining = max_findings - len(findings)
        if remaining <= 0:
            break
        text = data.decode("utf-8", errors="replace")
        text_findings = scan_text_for_secrets(text, max_findings=remaining)
        if len(text_findings) < remaining:
            text_findings.extend(
                _scan_serialized_json_value_for_secrets(
                    text,
                    scope="file_json",
                    max_findings=remaining - len(text_findings),
                )
            )
        if entropy_enabled and not is_allowlist_file and len(text_findings) < remaining:
            text_findings.extend(
                scan_text_for_entropy_secrets(
                    text,
                    min_length=entropy_min_length,
                    min_entropy=entropy_min_bits,
                    max_findings=remaining - len(text_findings),
                )
            )
        for finding in text_findings:
            scoped = dict(finding)
            scoped["path"] = safe_rel
            scoped["path_redacted"] = path_redacted
            if path_redacted:
                scoped["path_hash"] = content_hash(rel)
            scoped["scope"] = scoped.get("scope") or "content"
            scoped["size_bytes"] = size
            append_finding(scoped, use_allowlist=not is_allowlist_file)
            if len(findings) >= max_findings:
                break

    truncated = len(findings) >= max_findings
    incomplete_skips = [
        item for item in skipped
        if str(item.get("reason") or "") in {"too_large", "unreadable"}
    ]
    complete = not truncated and not incomplete_skips
    return {
        "ok": not findings,
        "complete": complete,
        "initialized": is_initialized(root),
        "root": str(root),
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "incomplete_skip_count": len(incomplete_skips),
        "incomplete_skips": incomplete_skips[:100],
        "finding_count": len(findings),
        "findings": findings,
        "allowlisted_findings": allowlisted_findings,
        "allowlist_hash_count": len(allowlist_hashes),
        "allowlist_uri": str(allowlist_path),
        "entropy_secret_scan_enabled": entropy_enabled,
        "skipped": skipped[:100],
        "truncated": truncated,
        "max_findings": max_findings,
        "max_file_bytes": max_file_bytes,
        "reason": (
            "secret_findings_detected" if findings
            else "scan_incomplete" if not complete
            else "ok"
        ),
    }


def audit_secrets_sarif(result: dict[str, Any]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []
    for finding in result.get("findings") or []:
        rule_id = str(finding.get("type") or "secret")
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f"Epic Continuum secret audit finding: {rule_id}"},
                "helpUri": "https://github.com/topics/secret-scanning",
            },
        )
        artifact_uri = str(finding.get("path") or result.get("root") or "")
        location: dict[str, Any] = {"physicalLocation": {"artifactLocation": {"uri": artifact_uri}}}
        if finding.get("line"):
            location["physicalLocation"]["region"] = {"startLine": int(finding["line"])}
        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": str(finding.get("snippet") or "Secret-like material detected")},
                "locations": [location],
                "properties": {
                    key: value
                    for key, value in finding.items()
                    if key not in {"snippet", "path"} and value is not None
                },
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Epic Continuum audit-secrets",
                        "informationUri": "https://github.com/topics/persistent-memory",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def redact_legacy_secrets(root: Path, *, dry_run: bool = True, limit: int = 500) -> dict[str, Any]:
    """Redact obvious legacy secret strings already persisted in catalog text columns."""
    if not is_initialized(root):
        return {"ok": False, "initialized": False, "root": str(root), "dry_run": dry_run, "reason": "catalog_missing", "redaction_count": 0}
    conn = connect(root) if not dry_run else connect_existing(root)
    conn.row_factory = sqlite3.Row
    actions: list[dict[str, Any]] = []
    try:
        tables = [
            str(row["name"])
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            if row["name"] and not str(row["name"]).startswith("sqlite_")
        ]
        for table in tables:
            if len(actions) >= limit:
                break
            try:
                table_info = list(conn.execute(f"PRAGMA table_info({_quote_sqlite_identifier(table)})"))
            except sqlite3.Error:
                continue
            allowed_columns = LEGACY_SECRET_REDACTION_COLUMNS.get(table, set())
            columns = [
                str(row["name"])
                for row in table_info
                if row["name"] in allowed_columns
                and ("TEXT" in str(row["type"] or "").upper() or str(row["type"] or "") == "")
            ]
            if not columns:
                continue
            select_cols = ", ".join(_quote_sqlite_identifier(column) for column in columns)
            try:
                rows = conn.execute(f"SELECT rowid AS __rowid__, {select_cols} FROM {_quote_sqlite_identifier(table)} LIMIT 10000")
            except sqlite3.Error:
                continue
            for row in rows:
                if len(actions) >= limit:
                    break
                rowid = row["__rowid__"]
                updates: dict[str, str] = {}
                for column in columns:
                    value = row[column]
                    if not isinstance(value, str):
                        continue
                    lexical_findings = scan_text_for_secrets(value, max_findings=1)
                    structured_findings = [] if lexical_findings else _scan_serialized_json_value_for_secrets(value, scope="legacy_sqlite_json", max_findings=1)
                    if not lexical_findings and not structured_findings:
                        continue
                    updates[column] = _redact_serialized_json_text_secrets(value)
                    actions.append({"table": table, "column": column, "rowid": rowid})
                    if len(actions) >= limit:
                        break
                if updates and not dry_run:
                    assignments = ", ".join(f"{_quote_sqlite_identifier(column)} = ?" for column in updates)
                    conn.execute(
                        f"UPDATE {_quote_sqlite_identifier(table)} SET {assignments} WHERE rowid = ?",
                        [*updates.values(), rowid],
                    )
        if not dry_run:
            audit_event(
                conn,
                action="redact_legacy_secrets",
                target_type="root",
                target_id=str(root),
                payload={"redaction_count": len(actions), "truncated": len(actions) >= limit},
            )
            conn.commit()
        return {
            "ok": True,
            "initialized": True,
            "root": str(root),
            "dry_run": dry_run,
            "redaction_count": len(actions),
            "truncated": len(actions) >= limit,
            "safe_column_policy": {table: sorted(columns) for table, columns in LEGACY_SECRET_REDACTION_COLUMNS.items()},
            "actions": actions[:100],
        }
    finally:
        conn.close()


def audit_event(
    conn: sqlite3.Connection,
    *,
    action: str,
    target_type: str,
    target_id: str | None,
    payload: dict[str, Any] | None = None,
    actor: str = "system",
) -> str:
    now = utc_now()
    event_id = unique_id("audit")
    safe_payload = redact_value_secrets(payload or {})
    safe_target_id = redact_text_secrets(target_id) if target_id else None
    safe_actor = redact_text_secrets(actor)
    conn.execute(
        """
        INSERT INTO audit_events(id, actor, action, target_type, target_id, payload_json, created_at)
        VALUES(?, ?, ?, ?, ?, ?, ?)
        """,
        (event_id, safe_actor, action, target_type, safe_target_id, json_dumps(safe_payload), now),
    )
    return event_id


def enqueue_job(
    conn: sqlite3.Connection,
    *,
    role: str,
    job_type: str,
    priority: int,
    payload: dict[str, Any],
    related_card_ids: list[str] | None = None,
    preemptible: bool = True,
) -> str:
    # Queue rows are a durable sink too. Most call sites only pass generated IDs,
    # but direct/API use can otherwise smuggle secrets into payload_json. Redact
    # unconditionally here because this helper does not know the root config.
    safe_payload = redact_value_secrets(payload)
    safe_related_card_ids = redact_value_secrets(related_card_ids or [])
    safe_role = redact_text_secrets(str(role))
    safe_job_type = redact_text_secrets(str(job_type))
    now = utc_now()
    job_id = unique_id("job")
    conn.execute(
        """
        INSERT INTO queue_jobs(
            id, role, job_type, priority, status, preemptible,
            related_card_ids_json, payload_json, created_at, updated_at
        )
        VALUES(?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)
        """,
        (
            job_id,
            safe_role,
            safe_job_type,
            priority,
            1 if preemptible else 0,
            json_dumps(safe_related_card_ids),
            json_dumps(safe_payload),
            now,
            now,
        ),
    )
    return job_id


def create_card(
    conn: sqlite3.Connection,
    *,
    root: Path | None = None,
    card_type: str,
    title: str,
    summary: str,
    source_refs: list[dict[str, Any]],
    entities: list[str] | None = None,
    topics: list[str] | None = None,
    decisions: list[str] | None = None,
    open_tasks: list[str] | None = None,
    salience: float = 0.5,
    confidence: float = 0.7,
    metadata: dict[str, Any] | None = None,
    visibility_scope: str = "global",
    session_id: str | None = None,
    project_id: str | None = None,
) -> str:
    now = utc_now()
    summary_hash = content_hash(summary)
    card_id = stable_id("card", card_type, title, summary_hash, json_dumps(source_refs))
    card_entities = entities or []
    card_topics = topics or []
    card_decisions = decisions or []
    card_open_tasks = open_tasks or []
    card_metadata = metadata or {}
    if visibility_scope not in {"global", "session", "project", "private"}:
        visibility_scope = "global"
    location_uri = None
    if root is not None:
        config = load_config(root)
        atomic_config = config.get("atomic_memory", {})
        if atomic_config.get("write_card_sidecars", True):
            sidecar_dir = root / atomic_config.get("card_sidecar_dir", "catalog/cards")
            sidecar_path = sidecar_dir / f"{card_id}.yaml"
            write_atomic_yaml(
                sidecar_path,
                atomic_memory_card(
                    card_id=card_id,
                    card_type=card_type,
                    title=title,
                    summary=summary,
                    source_refs=source_refs,
                    entities=card_entities,
                    topics=card_topics,
                    decisions=card_decisions,
                    open_tasks=card_open_tasks,
                    salience=salience,
                    confidence=confidence,
                    metadata=card_metadata,
                    created_at=now,
                    updated_at=now,
                    summary_hash=summary_hash,
                ),
            )
            location_uri = continuum_uri(root, sidecar_path)
    conn.execute(
        """
        INSERT INTO cards(
            id, card_type, title, summary, status, source_refs_json,
            entities_json, topics_json, decisions_json, open_tasks_json,
            salience, confidence, metadata_json, visibility_scope, session_id, project_id,
            location_uri, created_at, updated_at
        )
        VALUES(?, ?, ?, ?, 'pending_librarian_review', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            title = excluded.title,
            summary = excluded.summary,
            source_refs_json = excluded.source_refs_json,
            entities_json = excluded.entities_json,
            topics_json = excluded.topics_json,
            decisions_json = excluded.decisions_json,
            open_tasks_json = excluded.open_tasks_json,
            salience = excluded.salience,
            confidence = excluded.confidence,
            metadata_json = excluded.metadata_json,
            visibility_scope = excluded.visibility_scope,
            session_id = excluded.session_id,
            project_id = excluded.project_id,
            location_uri = coalesce(excluded.location_uri, cards.location_uri),
            updated_at = excluded.updated_at
        """,
        (
            card_id,
            card_type,
            title,
            summary,
            json_dumps(source_refs),
            json_dumps(card_entities),
            json_dumps(card_topics),
            json_dumps(card_decisions),
            json_dumps(card_open_tasks),
            salience,
            confidence,
            json_dumps(card_metadata),
            visibility_scope,
            session_id,
            project_id,
            location_uri,
            now,
            now,
        ),
    )
    return card_id


def upsert_graph_node(
    conn: sqlite3.Connection,
    *,
    kind: str,
    label: str,
    card_id: str | None = None,
    book_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> str:
    now = utc_now()
    canonical = f"{kind}:{label.casefold()}"
    node_id = stable_id("node", canonical)
    conn.execute(
        """
        INSERT INTO graph_nodes(id, kind, label, canonical_key, card_id, book_id, metadata_json, created_at, updated_at)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(canonical_key) DO UPDATE SET
            card_id = coalesce(excluded.card_id, graph_nodes.card_id),
            book_id = coalesce(excluded.book_id, graph_nodes.book_id),
            metadata_json = excluded.metadata_json,
            updated_at = excluded.updated_at
        """,
        (node_id, kind, label, canonical, card_id, book_id, json_dumps(metadata or {}), now, now),
    )
    return node_id


def add_graph_edge(
    conn: sqlite3.Connection,
    *,
    source_node_id: str,
    relation: str,
    target_node_id: str,
    weight: float,
    confidence: float,
    source_refs: list[dict[str, Any]],
) -> str:
    now = utc_now()
    edge_id = stable_id("edge", source_node_id, relation, target_node_id)
    # Reinforcement and decay columns are reserved in the schema; active recall
    # updates will own those counters once the librarian scoring loop lands.
    conn.execute(
        """
        INSERT INTO graph_edges(
            id, source_node_id, relation, target_node_id, weight, confidence,
            source_refs_json, created_at, updated_at
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(source_node_id, relation, target_node_id) DO UPDATE SET
            weight = max(graph_edges.weight, excluded.weight),
            confidence = max(graph_edges.confidence, excluded.confidence),
            source_refs_json = excluded.source_refs_json,
            status = 'active',
            updated_at = excluded.updated_at
        """,
        (
            edge_id,
            source_node_id,
            relation,
            target_node_id,
            weight,
            confidence,
            json_dumps(source_refs),
            now,
            now,
        ),
    )
    return edge_id


def append_scroll_event(
    root: Path,
    *,
    session_id: str,
    event_type: str,
    role: str,
    content: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    init_db(root)
    session_id, event_type, role, content, metadata = _apply_scroll_secret_policy(
        root,
        session_id=session_id,
        event_type=event_type,
        role=role,
        content=content,
        metadata=dict(metadata or {}),
    )
    metadata.setdefault("source_type", "scroll_event")
    metadata.setdefault("trust_level", "local_evidence_non_authoritative")
    metadata.setdefault("instruction_authority", "user_level_evidence")
    conn = connect(root)
    try:
        conn.execute("BEGIN IMMEDIATE")
        config = load_config(root)
        dedup_window = int(config.get("capture", {}).get("dedup_window_seconds", 0))
        digest = content_hash(content)
        if dedup_window > 0:
            cutoff = (dt.datetime.now(dt.UTC) - dt.timedelta(seconds=dedup_window)).replace(microsecond=0).isoformat()
            existing = conn.execute(
                """
                SELECT id, seq, created_at
                FROM scroll_events
                WHERE session_id = ?
                  AND event_type = ?
                  AND role = ?
                  AND content_hash = ?
                  AND created_at >= ?
                ORDER BY seq DESC
                LIMIT 1
                """,
                (session_id, event_type, role, digest, cutoff),
            ).fetchone()
            if existing is not None:
                audit_event(
                    conn,
                    action="dedupe_scroll_event",
                    target_type="scroll_event",
                    target_id=existing["id"],
                    payload={"session_id": session_id, "seq": existing["seq"], "dedup_window_seconds": dedup_window},
                )
                conn.commit()
                return {
                    "event_id": existing["id"],
                    "session_id": session_id,
                    "seq": int(existing["seq"]),
                    "scribe_job_id": None,
                    "deduplicated": True,
                }
        row = conn.execute(
            "SELECT coalesce(max(seq), 0) + 1 AS next_seq FROM scroll_events WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        seq = int(row["next_seq"])
        now = utc_now()
        event_id = stable_id("evt", session_id, str(seq), digest)
        conn.execute(
            """
            INSERT INTO scroll_events(
                id, session_id, seq, event_type, role, content, token_estimate,
                content_hash, metadata_json, created_at
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                session_id,
                seq,
                event_type,
                role,
                content,
                estimate_tokens(content),
                digest,
                json_dumps(metadata),
                now,
            ),
        )
        job_id = enqueue_job(
            conn,
            role="scribe",
            job_type="scroll_event_ingested",
            priority=100,
            payload={"event_id": event_id, "session_id": session_id, "seq": seq},
        )
        audit_event(
            conn,
            action="append_scroll_event",
            target_type="scroll_event",
            target_id=event_id,
            payload={"session_id": session_id, "seq": seq},
        )
        conn.commit()
        return {"event_id": event_id, "session_id": session_id, "seq": seq, "scribe_job_id": job_id, "deduplicated": False}
    finally:
        conn.close()


def segment_hash_material(events: list[sqlite3.Row] | tuple[sqlite3.Row, ...], *, legacy: bool = False) -> str:
    if legacy:
        return "\n".join(f"{row['seq']}:{row['content_hash']}" for row in events)
    return "\n".join(
        f"{row['seq']}:{row['role']}:{row['event_type']}:{row['content_hash']}"
        for row in events
    )


def roll_scroll_segment(root: Path, *, session_id: str, start_seq: int, end_seq: int) -> dict[str, Any]:
    init_db(root)
    conn = connect(root)
    try:
        events = conn.execute(
            """
            SELECT id, seq, event_type, role, content, token_estimate, content_hash, created_at
            FROM scroll_events
            WHERE session_id = ? AND seq BETWEEN ? AND ?
            ORDER BY seq
            """,
            (session_id, start_seq, end_seq),
        ).fetchall()
        if not events:
            raise ValueError("no scroll events found for requested range")
        now = utc_now()
        segment_material = segment_hash_material(events)
        segment_hash = content_hash(segment_material)
        segment_id = stable_id("seg", session_id, str(start_seq), str(end_seq), segment_hash)
        token_total = sum(int(row["token_estimate"]) for row in events)
        raw_text = "\n".join(f"{row['seq']} {row['role']}: {row['content']}" for row in events)
        summary = summarize_text(raw_text)
        source_refs = [{"event_id": row["id"], "seq": row["seq"]} for row in events]
        title = f"{session_id} scroll {start_seq}-{end_seq}"
        card_id = create_card(
            conn,
            root=root,
            card_type="scroll_segment",
            title=title,
            summary=summary,
            source_refs=source_refs,
            entities=extract_terms(raw_text),
            topics=extract_terms(raw_text, limit=8),
            metadata={
                "session_id": session_id,
                "start_seq": start_seq,
                "end_seq": end_seq,
                "segment_hash": segment_hash,
                "token_estimate": token_total,
            },
            visibility_scope="session",
            session_id=session_id,
            salience=0.65,
            confidence=0.75,
        )
        conn.execute(
            """
            INSERT INTO scroll_segments(
                id, session_id, start_seq, end_seq, status, summary_card_id,
                token_estimate, segment_hash, created_at, updated_at
            )
            VALUES(?, ?, ?, ?, 'carded', ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                status = 'carded',
                summary_card_id = excluded.summary_card_id,
                token_estimate = excluded.token_estimate,
                segment_hash = excluded.segment_hash,
                updated_at = excluded.updated_at
            """,
            (segment_id, session_id, start_seq, end_seq, card_id, token_total, segment_hash, now, now),
        )
        card_node = upsert_graph_node(conn, kind="card", label=title, card_id=card_id)
        for term in extract_terms(raw_text, limit=12):
            term_node = upsert_graph_node(conn, kind="term", label=term)
            add_graph_edge(
                conn,
                source_node_id=card_node,
                relation="mentions",
                target_node_id=term_node,
                weight=0.45,
                confidence=0.7,
                source_refs=[{"card_id": card_id, "segment_id": segment_id}],
            )
        librarian_job = enqueue_job(
            conn,
            role="librarian",
            job_type="review_card_placement",
            priority=75,
            payload={"card_id": card_id, "segment_id": segment_id},
            related_card_ids=[card_id],
        )
        archivist_job = enqueue_job(
            conn,
            role="archivist",
            job_type="verify_segment_integrity",
            priority=90,
            payload={"segment_id": segment_id, "segment_hash": segment_hash},
            related_card_ids=[card_id],
        )
        audit_event(
            conn,
            action="roll_scroll_segment",
            target_type="scroll_segment",
            target_id=segment_id,
            payload={"card_id": card_id, "event_count": len(events)},
        )
        conn.commit()
        sidecar_path = card_sidecar_path(root, card_id)
        return {
            "segment_id": segment_id,
            "card_id": card_id,
            "card_uri": str(sidecar_path) if sidecar_path and sidecar_path.exists() else None,
            "event_count": len(events),
            "token_estimate": token_total,
            "librarian_job_id": librarian_job,
            "archivist_job_id": archivist_job,
        }
    finally:
        conn.close()


def ingest_file(root: Path, *, path: Path, title: str | None = None, storage_tier: str = "hot") -> dict[str, Any]:
    init_db(root)
    config = load_config(root)
    if storage_tier not in {"hot", "warm", "cold", "vault"}:
        raise ValueError("storage_tier must be hot, warm, cold, or vault")
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(str(path))
    security_config = config.get("security", {})
    ignored, ignore_pattern = is_ignored_path(
        root,
        path,
        ignore_file_name=str(security_config.get("ignore_file") or ".continuumignore"),
    )
    if ignored:
        raise ValueError(f"path matches Continuum ignore rule {ignore_pattern!r}: {path}")
    max_ingest_bytes = parse_size(config.get("storage", {}).get("max_ingest_bytes", "50MB"))
    source_size = path.stat().st_size
    if source_size > max_ingest_bytes:
        raise ValueError(
            f"file too large for ingest_file: {format_size(source_size)} exceeds "
            f"storage.max_ingest_bytes={format_size(max_ingest_bytes)}"
        )
    raw_bytes = path.read_bytes()
    digest = hashlib.sha256(raw_bytes).hexdigest()
    text = raw_bytes.decode("utf-8", errors="replace")
    source_ref = source_file_reference(root, path, digest=digest, size_bytes=source_size)
    source_uri = str(source_ref["uri"])
    requested_title = title or path.stem or str(source_ref.get("name") or "source")
    secret_findings: list[dict[str, Any]] = []
    secret_action = str(security_config.get("secret_scan_action") or "block")
    title_secret_findings: list[dict[str, Any]] = []
    if security_config.get("secret_scan_enabled", True) and secret_action != "off":
        secret_findings = [dict(item, scope="content") for item in scan_text_for_secrets(text)]
        for item in scan_text_for_secrets(path.name, max_findings=5):
            secret_findings.append(dict(item, scope="source_name"))
        for item in scan_text_for_secrets(str(path), max_findings=5):
            secret_findings.append(dict(item, scope="source_path"))
        title_secret_findings = [dict(item, scope="title") for item in scan_text_for_secrets(requested_title, max_findings=5)]
        secret_findings.extend(title_secret_findings)
        remaining = max(0, 20 - len(secret_findings))
        if remaining:
            secret_findings.extend(scan_value_for_secrets(source_ref, scope="source_ref", max_findings=remaining))
        if secret_findings and secret_action == "block":
            raise ValueError(f"secret scan blocked ingest_file before archiving: {len(secret_findings)} finding(s)")
    if title_secret_findings and secret_action != "off":
        if title is None and source_ref.get("name_redacted"):
            book_title = "Redacted source"
        else:
            book_title = redact_text_secrets(requested_title).strip() or "Redacted source"
    else:
        book_title = requested_title
    source_display_name = str(source_ref.get("name") or safe_source_name(path.name, fallback_digest=digest))
    safe_name = f"{digest[:16]}_{safe_source_name(path.name, fallback_digest=digest)}"
    original_dir = root / "archive" / "originals" / storage_tier
    secure_mkdir(original_dir)
    original_path = original_dir / safe_name
    if not original_path.exists():
        secure_copy_file(path, original_path)
    reader_dir = root / "archive" / "reader_editions" / ("cold" if storage_tier == "vault" else storage_tier)
    secure_mkdir(reader_dir)
    reader_path = reader_dir / f"{safe_name}.txt"
    atomic_write_text_file(reader_path, text)
    original_uri = continuum_uri(root, original_path)
    reader_uri = continuum_uri(root, reader_path)

    conn = connect(root)
    try:
        now = utc_now()
        book_id = stable_id("book", "file", digest)
        current_source = {
            "ingested_at": now,
            "source_uri": source_uri,
            "source_ref": source_ref,
            "original_uri": original_uri,
            "reader_uri": reader_uri,
            "content_hash": digest,
        }
        existing_book = conn.execute("SELECT metadata_json FROM books WHERE id = ?", (book_id,)).fetchone()
        source_history = [current_source]
        first_ingested_at = now
        if existing_book:
            existing_metadata = json_loads(existing_book["metadata_json"], {})
            first_ingested_at = str(existing_metadata.get("first_ingested_at") or existing_metadata.get("ingested_at") or now)
            prior_history = existing_metadata.get("source_history")
            source_history = prior_history if isinstance(prior_history, list) else []
            if not any(
                isinstance(entry, dict)
                and entry.get("source_uri") == source_uri
                and entry.get("content_hash") == digest
                for entry in source_history
            ):
                source_history.append(current_source)
        metadata_json = {
            "source_name": source_display_name,
            "source_uri": source_uri,
            "source_ref": source_ref,
            "source_history": source_history,
            "source_history_count": len(source_history),
            "first_ingested_at": first_ingested_at,
            "latest_ingested_at": now,
            "secret_findings": len(secret_findings),
        }
        conn.execute(
            """
            INSERT INTO books(
                id, title, source_uri, original_uri, reader_uri, content_hash,
                storage_tier, location_uri, status, metadata_json, created_at, updated_at
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                title = excluded.title,
                source_uri = excluded.source_uri,
                reader_uri = excluded.reader_uri,
                storage_tier = excluded.storage_tier,
                location_uri = excluded.location_uri,
                metadata_json = excluded.metadata_json,
                updated_at = excluded.updated_at
            """,
            (
                book_id,
                book_title,
                source_uri,
                original_uri,
                reader_uri,
                digest,
                storage_tier,
                original_uri,
                json_dumps(metadata_json),
                now,
                now,
            ),
        )
        chunks = chunk_text(text)
        conn.execute("DELETE FROM chunks WHERE book_id = ?", (book_id,))
        fts_enabled = delete_book_fts(conn, book_id)
        for ordinal, chunk in enumerate(chunks):
            chunk_id = stable_id("chunk", book_id, str(ordinal), content_hash(chunk))
            conn.execute(
                """
                INSERT INTO chunks(id, book_id, ordinal, text, content_hash, token_estimate, created_at)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    chunk_id,
                    book_id,
                    ordinal,
                    chunk,
                    content_hash(chunk),
                    estimate_tokens(chunk),
                    now,
                ),
            )
            if fts_enabled:
                index_chunk_fts(conn, chunk_id=chunk_id, book_id=book_id, title=book_title, text=chunk)
        card_id = create_card(
            conn,
            root=root,
            card_type="book",
            title=book_title,
            summary=summarize_text(text),
            source_refs=[{"book_id": book_id, "source_uri": source_uri, "source_ref": source_ref, "original_uri": original_uri}],
            entities=extract_terms(text),
            topics=extract_terms(text, limit=8),
            metadata={"book_id": book_id, "chunk_count": len(chunks), "content_hash": digest},
            salience=0.6,
            confidence=0.8,
        )
        book_node = upsert_graph_node(conn, kind="book", label=book_title, book_id=book_id)
        card_node = upsert_graph_node(conn, kind="card", label=book_title, card_id=card_id)
        add_graph_edge(
            conn,
            source_node_id=card_node,
            relation="describes",
            target_node_id=book_node,
            weight=0.8,
            confidence=0.9,
            source_refs=[{"card_id": card_id, "book_id": book_id}],
        )
        librarian_job = enqueue_job(
            conn,
            role="librarian",
            job_type="review_card_placement",
            priority=70,
            payload={"card_id": card_id, "book_id": book_id},
            related_card_ids=[card_id],
        )
        archivist_job = enqueue_job(
            conn,
            role="archivist",
            job_type="verify_book_integrity",
            priority=80,
            payload={"book_id": book_id, "content_hash": digest},
            related_card_ids=[card_id],
        )
        audit_event(
            conn,
            action="ingest_file",
            target_type="book",
            target_id=book_id,
            payload={"card_id": card_id, "chunk_count": len(chunks), "source_uri": source_uri, "source_ref": source_ref},
        )
        conn.commit()
        sidecar_path = card_sidecar_path(root, card_id)
        return {
            "book_id": book_id,
            "card_id": card_id,
            "card_uri": str(sidecar_path) if sidecar_path and sidecar_path.exists() else None,
            "chunk_count": len(chunks),
            "original_uri": str(original_path),
            "reader_uri": str(reader_path),
            "librarian_job_id": librarian_job,
            "archivist_job_id": archivist_job,
            "secret_findings": secret_findings,
        }
    finally:
        conn.close()


def _card_scope_filter(card_scope: str, session_id: str, project_id: str | None = None) -> tuple[str, list[Any]]:
    if card_scope == "session":
        return " AND visibility_scope = 'session' AND session_id = ?", [session_id]
    if card_scope == "global":
        return " AND visibility_scope = 'global'", []
    if card_scope == "project":
        if project_id:
            return " AND (visibility_scope = 'global' OR (visibility_scope = 'project' AND project_id = ?))", [project_id]
        return " AND visibility_scope = 'global'", []
    return " AND (visibility_scope = 'global' OR (visibility_scope = 'session' AND session_id = ?))", [session_id]


def reinforce_card_recall(conn: sqlite3.Connection, *, card_ids: list[str], now: str | None = None) -> int:
    if not card_ids:
        return 0
    now = now or utc_now()
    updated = 0
    for card_id in dict.fromkeys(card_ids):
        conn.execute(
            """
            UPDATE cards
            SET recall_count = coalesce(recall_count, 0) + 1,
                last_recalled_at = ?,
                salience = min(1.0, salience + 0.02),
                updated_at = ?
            WHERE id = ?
            """,
            (now, now, card_id),
        )
        row = conn.execute("SELECT id FROM graph_nodes WHERE card_id = ?", (card_id,)).fetchone()
        if row:
            conn.execute(
                """
                UPDATE graph_edges
                SET use_count = use_count + 1,
                    weight = min(1.0, weight + 0.03),
                    decay_count = 0,
                    last_used_at = ?,
                    last_decay_at = ?,
                    updated_at = ?
                WHERE status = 'active'
                  AND (source_node_id = ? OR target_node_id = ?)
                """,
                (now, now, now, row["id"], row["id"]),
            )
        updated += 1
    return updated


def compile_context(
    root: Path,
    *,
    session_id: str,
    token_budget: int = 3000,
    query: str | None = None,
    create: bool = True,
    card_scope: str | None = None,
    project_id: str | None = None,
) -> dict[str, Any]:
    if create:
        init_db(root)
    elif not is_initialized(root):
        return {
            "session_id": session_id,
            "initialized": False,
            "token_budget": token_budget,
            "estimated_tokens": 0,
            "remaining_budget": max(0, token_budget),
            "section_count": 0,
            "context_text": "",
        }
    config = _status_config(root, create=create)
    card_scope = card_scope or str(config.get("context", {}).get("card_recall_scope", "session_then_global"))
    if card_scope not in {"session", "global", "session_then_global", "project"}:
        card_scope = "session_then_global"
    max_budget = int(config["context"]["max_token_budget"])
    configured_event_limit = int(config["context"].get("scroll_event_fetch_limit", 500))
    reserve_output_tokens = int(config["context"].get("reserve_output_tokens", 0))
    if token_budget <= 0:
        token_budget = int(config["context"]["default_token_budget"])
    token_budget = min(token_budget, max_budget)
    usable_context_budget = token_budget
    event_fetch_limit = max(1, min(configured_event_limit, max(24, token_budget // 10)))
    conn = connect(root) if create else connect_existing(root)
    try:
        remaining = usable_context_budget
        sections: list[dict[str, Any]] = []
        truncated_items: list[dict[str, Any]] = []
        recent_events = conn.execute(
            """
            SELECT seq, role, event_type, content, token_estimate
            FROM scroll_events
            WHERE session_id = ?
            ORDER BY seq DESC
            LIMIT ?
            """,
            (session_id, event_fetch_limit),
        ).fetchall()
        event_lines: list[str] = []
        for row in recent_events:
            line = f"{row['seq']} {row['role']}[{row['event_type']}]: {row['content']}"
            cost = estimate_tokens(line)
            if remaining <= 0:
                break
            if remaining - cost < 0:
                truncated_line, was_truncated = truncate_to_token_budget(line, remaining)
                included_cost = estimate_tokens(truncated_line)
                if truncated_line and included_cost <= remaining:
                    event_lines.append(truncated_line)
                    remaining -= included_cost
                    if was_truncated:
                        truncated_items.append(
                            {
                                "kind": "scroll_event",
                                "seq": row["seq"],
                                "original_estimated_tokens": cost,
                                "included_estimated_tokens": included_cost,
                            }
                        )
                break
            event_lines.append(line)
            remaining -= cost
        if event_lines:
            sections.append({"kind": "recent_scroll", "text": "\n".join(reversed(event_lines))})

        if query and remaining > 100:
            terms = extract_terms(query, limit=8)
            matches: list[sqlite3.Row] = []
            scope_clause, scope_params = _card_scope_filter(card_scope, session_id, project_id=project_id)
            for term in terms:
                rows = conn.execute(
                    f"""
                    SELECT id, title, summary, salience
                    FROM cards
                    WHERE status != 'pruned'
                      AND (title LIKE ? OR summary LIKE ? OR entities_json LIKE ? OR topics_json LIKE ?)
                      {scope_clause}
                    ORDER BY salience DESC, updated_at DESC
                    LIMIT 4
                    """,
                    (f"%{term}%", f"%{term}%", f"%{term}%", f"%{term}%", *scope_params),
                ).fetchall()
                matches.extend(rows)
            seen: set[str] = set()
            card_lines: list[str] = []
            for row in matches:
                if row["id"] in seen:
                    continue
                seen.add(row["id"])
                line = f"- {row['title']}: {row['summary']} (card:{row['id']})"
                cost = estimate_tokens(line)
                if remaining - cost < 0:
                    truncated_line, was_truncated = truncate_to_token_budget(line, remaining)
                    included_cost = estimate_tokens(truncated_line)
                    if truncated_line and included_cost <= remaining:
                        card_lines.append(truncated_line)
                        remaining -= included_cost
                        if was_truncated:
                            truncated_items.append(
                                {
                                    "kind": "card",
                                    "card_id": row["id"],
                                    "original_estimated_tokens": cost,
                                    "included_estimated_tokens": included_cost,
                                }
                            )
                    break
                card_lines.append(line)
                remaining -= cost
            if card_lines:
                sections.append({"kind": "recalled_cards", "text": "\n".join(card_lines)})
            if create and seen:
                reinforce_card_recall(conn, card_ids=list(seen))
                conn.commit()

        context_text = "\n\n".join(f"## {section['kind']}\n{section['text']}" for section in sections)
        context_truncated = False
        if estimate_tokens(context_text) > usable_context_budget:
            context_text, context_truncated = truncate_to_token_budget(context_text, usable_context_budget)
            remaining = max(0, usable_context_budget - estimate_tokens(context_text))
        return {
            "session_id": session_id,
            "token_budget": token_budget,
            "usable_context_budget": usable_context_budget,
            "reserve_output_tokens": reserve_output_tokens,
            "estimated_tokens": estimate_tokens(context_text),
            "remaining_budget": remaining,
            "section_count": len(sections),
            "recent_scroll_fetch_limit": event_fetch_limit,
            "card_recall_scope": card_scope,
            "truncated": context_truncated or bool(truncated_items),
            "truncated_items": truncated_items,
            "context_text": context_text,
        }
    finally:
        conn.close()


def search_memory(
    root: Path,
    *,
    query: str,
    limit: int = 10,
    create: bool = False,
) -> dict[str, Any]:
    if create:
        init_db(root)
    elif not is_initialized(root):
        return {
            "query": query,
            "initialized": False,
            "backend": "none",
            "result_count": 0,
            "results": [],
        }
    conn = connect(root) if create else connect_existing(root)
    try:
        terms = extract_terms(query, limit=8)
        bounded_limit = max(1, min(int(limit), 100))
        has_fts = bool(
            conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'chunks_fts'"
            ).fetchone()
        )
        if has_fts and terms:
            fts_query = " OR ".join(terms)
            try:
                rows = conn.execute(
                    """
                    SELECT
                        f.chunk_id,
                        f.book_id,
                        f.title,
                        snippet(chunks_fts, 3, '[', ']', '...', 18) AS snippet,
                        bm25(chunks_fts) AS score
                    FROM chunks_fts f
                    WHERE chunks_fts MATCH ?
                    ORDER BY score ASC
                    LIMIT ?
                    """,
                    (fts_query, bounded_limit),
                ).fetchall()
                results = [
                    {
                        "kind": "chunk",
                        "chunk_id": row["chunk_id"],
                        "book_id": row["book_id"],
                        "title": row["title"],
                        "snippet": row["snippet"],
                        "score": row["score"],
                        "reason": ["fts5_match"],
                    }
                    for row in rows
                ]
                return {
                    "query": query,
                    "initialized": True,
                    "backend": "fts5",
                    "result_count": len(results),
                    "results": results,
                }
            except sqlite3.OperationalError:
                pass

        like_terms = terms or [query]
        clauses = " OR ".join(["c.text LIKE ? OR b.title LIKE ?" for _term in like_terms])
        params: list[Any] = []
        for term in like_terms:
            needle = f"%{term}%"
            params.extend([needle, needle])
        params.append(bounded_limit)
        rows = conn.execute(
            f"""
            SELECT c.id AS chunk_id, c.book_id, b.title, c.text
            FROM chunks c
            JOIN books b ON b.id = c.book_id
            WHERE {clauses}
            ORDER BY c.created_at DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
        results = [
            {
                "kind": "chunk",
                "chunk_id": row["chunk_id"],
                "book_id": row["book_id"],
                "title": row["title"],
                "snippet": summarize_text(row["text"], limit=240),
                "score": None,
                "reason": ["like_match"],
            }
            for row in rows
        ]
        return {
            "query": query,
            "initialized": True,
            "backend": "like",
            "result_count": len(results),
            "results": results,
        }
    finally:
        conn.close()


def recover_thread(
    root: Path,
    *,
    session_id: str,
    query: str | None = None,
    token_budget: int = 0,
    recent_event_limit: int = 24,
) -> dict[str, Any]:
    init_db(root)
    display_session_id = enforce_text_secret_policy(root, session_id, scope="recovery session_id")
    if display_session_id != session_id:
        display_session_id = redacted_identifier(session_id, prefix="session")
    config = load_config(root)
    if token_budget <= 0:
        token_budget = int(config["context"]["default_token_budget"])
    context = compile_context(root, session_id=session_id, token_budget=token_budget, query=query or session_id)
    conn = connect(root)
    try:
        metadata_needle = f'"session_id":"{session_id}"'
        recent_events = [
            dict(row)
            for row in conn.execute(
                """
                SELECT seq, role, event_type, content, created_at
                FROM scroll_events
                WHERE session_id = ?
                ORDER BY seq DESC
                LIMIT ?
                """,
                (session_id, recent_event_limit),
            )
        ]
        recent_events.reverse()
        cards = [
            dict(row)
            for row in conn.execute(
                """
                SELECT id, card_type, title, summary, location_uri, decisions_json, open_tasks_json, updated_at
                FROM cards
                WHERE metadata_json LIKE ?
                   OR title LIKE ?
                   OR summary LIKE ?
                ORDER BY salience DESC, updated_at DESC
                LIMIT 12
                """,
                (f"%{metadata_needle}%", f"%{session_id}%", f"%{session_id}%"),
            )
        ]
        decisions: list[str] = []
        open_tasks: list[str] = []
        for card in cards:
            decisions.extend(json_loads(card.get("decisions_json"), []))
            open_tasks.extend(json_loads(card.get("open_tasks_json"), []))
        pending_jobs = [
            dict(row)
            for row in conn.execute(
                """
                SELECT role, job_type, priority, related_card_ids_json, payload_json, created_at
                FROM queue_jobs
                WHERE status = 'pending'
                ORDER BY priority ASC, created_at ASC
                LIMIT 20
                """
            )
        ]
        recent_books = [
            dict(row)
            for row in conn.execute(
                """
                SELECT id, title, source_uri, reader_uri, storage_tier, updated_at
                FROM books
                WHERE status = 'active'
                ORDER BY updated_at DESC
                LIMIT 10
                """
            )
        ]

        now = utc_now()
        recovery_id = unique_id("recovery")
        lines = [
            f"# Epic Continuum Thread Recovery: {display_session_id}",
            "",
            f"- Recovery id: `{recovery_id}`",
            f"- Generated: `{now}`",
            f"- Epic Continuum root: `{root}`",
            "",
            "## Resume Instruction",
            "",
            "Restore this thread from Epic Continuum. Treat the Scroll as the ordered source of truth, "
            "use Cards as compact memory, preserve open tasks, and continue from the latest event.",
            "",
            "## Looking Glass",
            "",
            context["context_text"] or "_No context compiled._",
            "",
            "## Recent Scroll",
            "",
        ]
        if recent_events:
            lines.extend(f"- {row['seq']} {row['role']}[{row['event_type']}]: {row['content']}" for row in recent_events)
        else:
            lines.append("_No Scroll events found for this session._")
        lines.extend(["", "## Recalled Cards", ""])
        if cards:
            for card in cards:
                location = f" sidecar={card['location_uri']}" if card.get("location_uri") else ""
                lines.append(f"- {card['title']} (`{card['id']}` {card['card_type']}{location}): {card['summary']}")
        else:
            lines.append("_No Cards matched this session yet._")
        lines.extend(["", "## Decisions", ""])
        if decisions:
            lines.extend(f"- {item}" for item in decisions)
        else:
            lines.append("_No explicit decisions listed._")
        lines.extend(["", "## Open Tasks", ""])
        if open_tasks:
            lines.extend(f"- {item}" for item in open_tasks)
        else:
            lines.append("_No explicit open tasks listed._")
        lines.extend(["", "## Pending Jobs", ""])
        if pending_jobs:
            for job in pending_jobs:
                lines.append(f"- {job['role']}:{job['job_type']} priority={job['priority']} payload={job['payload_json']}")
        else:
            lines.append("_No pending jobs._")
        lines.extend(["", "## Recent Books", ""])
        if recent_books:
            for book in recent_books:
                lines.append(f"- {book['title']} (`{book['id']}` {book['storage_tier']}): {book['reader_uri']}")
        else:
            lines.append("_No active books found._")
        packet_text = "\n".join(lines).rstrip() + "\n"

        safe_session_source = display_session_id if display_session_id != session_id else session_id
        safe_session = re.sub(r"[^A-Za-z0-9_.-]+", "_", safe_session_source).strip("_") or "thread"
        packet_path = root / "exports" / "thread_recovery" / f"{safe_session}_{recovery_id}.md"
        secure_mkdir(packet_path.parent)
        atomic_write_text_file(packet_path, packet_text)
        audit_event(
            conn,
            action="recover_thread",
            target_type="thread",
            target_id=session_id,
            payload={"recovery_id": recovery_id, "packet_uri": str(packet_path)},
        )
        conn.commit()
        return {
            "recovery_id": recovery_id,
            "session_id": display_session_id,
            "session_id_redacted": display_session_id != session_id,
            "packet_uri": str(packet_path),
            "packet_hash": content_hash(packet_text),
            "context": context,
            "recent_event_count": len(recent_events),
            "card_count": len(cards),
            "pending_job_count": len(pending_jobs),
            "book_count": len(recent_books),
            "packet_text": packet_text,
        }
    finally:
        conn.close()


def audit(root: Path, *, create: bool = True) -> dict[str, Any]:
    state = status(root, create=create)
    if not state.get("initialized", True):
        state.update(
            {
                "pending_librarian_cards": 0,
                "orphan_chunks": 0,
                "orphan_card_sidecars": 0,
                "active_graph_edges": 0,
                "pruned_graph_edges": 0,
            }
        )
        return state
    conn = connect(root) if create else connect_existing(root)
    try:
        pending_cards = conn.execute(
            "SELECT count(*) FROM cards WHERE status = 'pending_librarian_review'"
        ).fetchone()[0]
        orphan_chunks = conn.execute(
            """
            SELECT count(*)
            FROM chunks c
            LEFT JOIN books b ON b.id = c.book_id
            WHERE b.id IS NULL
            """
        ).fetchone()[0]
        state.update(
            {
                "pending_librarian_cards": pending_cards,
                "orphan_chunks": orphan_chunks,
                "orphan_card_sidecars": count_orphan_card_sidecars(root, conn),
                "active_graph_edges": conn.execute(
                    "SELECT count(*) FROM graph_edges WHERE status = 'active'"
                ).fetchone()[0],
                "pruned_graph_edges": conn.execute(
                    "SELECT count(*) FROM graph_edges WHERE status = 'pruned'"
                ).fetchone()[0],
            }
        )
        return state
    finally:
        conn.close()


def count_orphan_card_sidecars(root: Path, conn: sqlite3.Connection) -> int:
    cards_dir = root / "catalog" / "cards"
    if not cards_dir.exists():
        return 0
    known_paths = {
        str(resolve_stored_uri(root, row["location_uri"]).resolve())
        for row in conn.execute("SELECT location_uri FROM cards WHERE location_uri IS NOT NULL")
        if row["location_uri"]
    }
    orphan_count = 0
    for path in cards_dir.glob("*.yaml"):
        try:
            resolved = str(path.resolve())
        except OSError:
            resolved = str(path)
        if resolved not in known_paths:
            orphan_count += 1
    return orphan_count


def snapshot(root: Path, *, reason: str = "manual_snapshot") -> dict[str, Any]:
    init_db(root)
    reason = enforce_text_secret_policy(root, str(reason), scope="snapshot reason")
    conn = connect(root)
    source_db = root / "catalog" / "catalog.sqlite3"
    snapshot_id = unique_id("snapshot")
    out_path = root / "snapshots" / f"continuum_catalog_{snapshot_id}.sqlite3"
    cards_source = root / "catalog" / "cards"
    cards_out = root / "snapshots" / f"continuum_cards_{snapshot_id}"
    out_uri = continuum_uri(root, out_path)
    source_db_uri = continuum_uri(root, source_db)
    cards_out_uri = continuum_uri(root, cards_out)
    secure_mkdir(out_path.parent)
    dest = sqlite3.connect(str(out_path))
    try:
        conn.backup(dest)
    finally:
        dest.close()
    secure_sqlite_files(out_path)
    card_sidecar_count = 0
    if cards_source.exists():
        secure_copytree(cards_source, cards_out, dirs_exist_ok=True, symlinks=True)
        card_sidecar_count = sum(1 for item in cards_out.glob("*.yaml"))
    try:
        now = utc_now()
        conn.execute(
            """
            INSERT INTO snapshots(id, snapshot_uri, reason, source_db_uri, created_at)
            VALUES(?, ?, ?, ?, ?)
            """,
            (snapshot_id, out_uri, reason, source_db_uri, now),
        )
        audit_event(
            conn,
            action="snapshot",
            target_type="snapshot",
            target_id=snapshot_id,
            payload={
                "snapshot_uri": out_uri,
                "card_sidecars_uri": cards_out_uri,
                "card_sidecar_count": card_sidecar_count,
                "reason": reason,
            },
        )
        conn.commit()
        return {
            "snapshot_id": snapshot_id,
            "snapshot_uri": str(out_path),
            "source_db_uri": str(source_db),
            "card_sidecars_uri": str(cards_out),
            "card_sidecar_count": card_sidecar_count,
        }
    finally:
        conn.close()


def status(root: Path, *, create: bool = True) -> dict[str, Any]:
    initialized = is_initialized(root)
    if create:
        init_db(root)
        initialized = True
    elif not initialized:
        return {
            "root": str(root),
            "initialized": False,
            "schema_version": SCHEMA_VERSION,
            "config": {
                "path": str(config_path(root)),
                "exists": config_path(root).exists(),
            },
            "pending_jobs": [],
        }
    config = _status_config(root, create=create)
    conn = connect(root) if create else connect_existing(root)
    try:
        tables = [
            "scroll_events",
            "scroll_segments",
            "books",
            "chunks",
            "cards",
            "queue_jobs",
            "graph_nodes",
            "graph_edges",
            "audit_events",
            "snapshots",
            "artifacts",
        ]
        payload: dict[str, Any] = {
            "root": str(root),
            "initialized": initialized,
            "schema_version": SCHEMA_VERSION,
            "config": {
                "path": str(root / "config" / "continuum.config.json"),
                "vram_active_pane_budget": format_size(parse_size(config["hardware"]["vram"]["active_pane_budget"])),
                "system_ram_hot_cache_budget": format_size(parse_size(config["hardware"]["system_ram"]["hot_cache_budget"])),
                "nvme_durable_store_budget": format_size(parse_size(config["hardware"]["nvme"]["durable_store_budget"])),
                "default_token_budget": config["context"]["default_token_budget"],
            },
        }
        existing_tables = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
            if row["name"]
        }
        missing_tables: list[str] = []
        for table in tables:
            if table not in existing_tables:
                payload[table] = 0
                missing_tables.append(table)
                continue
            payload[table] = conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
        if missing_tables:
            payload["missing_tables"] = missing_tables
        payload["pending_jobs"] = [
            dict(row)
            for row in conn.execute(
                """
                SELECT role, job_type, count(*) AS count, min(priority) AS highest_priority
                FROM queue_jobs
                WHERE status = 'pending'
                GROUP BY role, job_type
                ORDER BY highest_priority ASC, role, job_type
                """
            )
        ]
        return payload
    finally:
        conn.close()
