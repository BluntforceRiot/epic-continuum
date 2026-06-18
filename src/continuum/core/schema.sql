PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scroll_events (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    role TEXT NOT NULL,
    content TEXT NOT NULL,
    token_estimate INTEGER NOT NULL DEFAULT 0,
    content_hash TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    UNIQUE(session_id, seq)
);

CREATE TABLE IF NOT EXISTS scroll_segments (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    start_seq INTEGER NOT NULL,
    end_seq INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    summary_card_id TEXT,
    token_estimate INTEGER NOT NULL DEFAULT 0,
    segment_hash TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS books (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    source_uri TEXT NOT NULL,
    original_uri TEXT,
    reader_uri TEXT,
    content_hash TEXT NOT NULL,
    storage_tier TEXT NOT NULL DEFAULT 'hot',
    location_uri TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    verification_status TEXT NOT NULL DEFAULT 'pending',
    last_verified_at TEXT,
    last_tiered_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chunks (
    id TEXT PRIMARY KEY,
    book_id TEXT NOT NULL REFERENCES books(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    text TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    token_estimate INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE(book_id, ordinal)
);

CREATE TABLE IF NOT EXISTS cards (
    id TEXT PRIMARY KEY,
    card_type TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending_librarian_review',
    placement_collection TEXT,
    shelf TEXT,
    storage_tier TEXT,
    visibility_scope TEXT NOT NULL DEFAULT 'global',
    session_id TEXT,
    project_id TEXT,
    recall_count INTEGER NOT NULL DEFAULT 0,
    last_recalled_at TEXT,
    conflict_group TEXT,
    supersedes_card_id TEXT,
    superseded_by_card_id TEXT,
    location_uri TEXT,
    source_refs_json TEXT NOT NULL DEFAULT '[]',
    entities_json TEXT NOT NULL DEFAULT '[]',
    topics_json TEXT NOT NULL DEFAULT '[]',
    decisions_json TEXT NOT NULL DEFAULT '[]',
    open_tasks_json TEXT NOT NULL DEFAULT '[]',
    salience REAL NOT NULL DEFAULT 0.5,
    confidence REAL NOT NULL DEFAULT 0.7,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS queue_jobs (
    id TEXT PRIMARY KEY,
    role TEXT NOT NULL,
    job_type TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 500,
    status TEXT NOT NULL DEFAULT 'pending',
    preemptible INTEGER NOT NULL DEFAULT 1,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    error_json TEXT,
    lease_owner TEXT,
    lease_expires_at TEXT,
    heartbeat_at TEXT,
    related_card_ids_json TEXT NOT NULL DEFAULT '[]',
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS graph_nodes (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    label TEXT NOT NULL,
    canonical_key TEXT NOT NULL UNIQUE,
    card_id TEXT REFERENCES cards(id) ON DELETE SET NULL,
    book_id TEXT REFERENCES books(id) ON DELETE SET NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS graph_edges (
    id TEXT PRIMARY KEY,
    source_node_id TEXT NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    relation TEXT NOT NULL,
    target_node_id TEXT NOT NULL REFERENCES graph_nodes(id) ON DELETE CASCADE,
    weight REAL NOT NULL DEFAULT 0.25,
    confidence REAL NOT NULL DEFAULT 0.7,
    use_count INTEGER NOT NULL DEFAULT 0,
    decay_count INTEGER NOT NULL DEFAULT 0,
    pinned INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    source_refs_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_used_at TEXT,
    last_decay_at TEXT,
    UNIQUE(source_node_id, relation, target_node_id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS snapshots (
    id TEXT PRIMARY KEY,
    snapshot_uri TEXT NOT NULL,
    reason TEXT NOT NULL,
    source_db_uri TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    uri TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    operation_id TEXT,
    immutable INTEGER NOT NULL DEFAULT 1,
    source_type TEXT,
    trust_level TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE(uri, sha256)
);

CREATE INDEX IF NOT EXISTS idx_scroll_events_session_seq ON scroll_events(session_id, seq);
CREATE INDEX IF NOT EXISTS idx_cards_status ON cards(status, salience DESC);
CREATE INDEX IF NOT EXISTS idx_cards_visibility ON cards(visibility_scope, session_id, project_id, salience DESC);
CREATE INDEX IF NOT EXISTS idx_books_tier ON books(storage_tier, status);
CREATE INDEX IF NOT EXISTS idx_queue_role_priority ON queue_jobs(role, status, priority, created_at);
CREATE INDEX IF NOT EXISTS idx_graph_edges_source ON graph_edges(source_node_id, status, weight DESC);
CREATE INDEX IF NOT EXISTS idx_graph_edges_target ON graph_edges(target_node_id, status, weight DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_action ON audit_events(action, created_at);
CREATE INDEX IF NOT EXISTS idx_artifacts_kind ON artifacts(kind, created_at);
CREATE INDEX IF NOT EXISTS idx_artifacts_operation ON artifacts(operation_id);
