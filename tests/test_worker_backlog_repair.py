from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum.core.atomic import load_atomic_yaml
from continuum.core import workers as worker_module
from continuum.core.store import (
    add_graph_edge,
    append_scroll_event,
    connect,
    connect_existing,
    create_card,
    enqueue_job,
    init_db,
    resolve_stored_uri,
    upsert_graph_node,
)
from continuum.core.workers import reconcile_worker_backlog, review_mempalace_import, run_worker_pass, serve_workers


def graph_place_card(conn, card_id: str, *, label: str) -> None:
    card_node = upsert_graph_node(conn, kind="card", label=label, card_id=card_id)
    shelf_node = upsert_graph_node(conn, kind="term", label=f"{label} shelf")
    add_graph_edge(
        conn,
        source_node_id=card_node,
        relation="placed_in",
        target_node_id=shelf_node,
        weight=0.75,
        confidence=0.9,
        source_refs=[{"card_id": card_id, "test": True}],
    )


def seed_legacy_scribe_notifications(conn, *, session_id: str, count: int) -> None:
    """Create pre-dedupe pending notifications for backlog-repair coverage."""
    for index in range(count):
        enqueue_job(
            conn,
            role="scribe",
            job_type="scroll_event_ingested",
            priority=100,
            payload={"event_id": f"legacy-{session_id}-{index}", "session_id": session_id, "seq": index + 1000},
        )


class WorkerBacklogRepairTest(unittest.TestCase):
    def test_reconcile_enqueues_real_review_for_unplaced_legacy_card(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="project_state",
                    title="Legacy unplaced project state",
                    summary="This predates automatic Librarian queueing.",
                    source_refs=[],
                    topics=["Continuum"],
                    metadata={"project_id": "continuum", "agent_id": "codex"},
                    visibility_scope="project",
                    session_id="legacy-session",
                    project_id="continuum",
                )
                conn.commit()
            finally:
                conn.close()

            dry_run = reconcile_worker_backlog(root)
            self.assertEqual(dry_run["cards"]["unqueued_reviews_before"], 1)
            self.assertEqual(dry_run["cards"]["review_jobs_enqueued"], 0)

            applied = reconcile_worker_backlog(root, dry_run=False)
            self.assertEqual(applied["cards"]["review_jobs_enqueued"], 1)
            self.assertEqual(applied["cards"]["unqueued_reviews_remaining"], 0)

            conn = connect_existing(root)
            try:
                review = conn.execute(
                    """
                    SELECT id, dedupe_key
                    FROM queue_jobs
                    WHERE status = 'pending' AND job_type = 'review_card_placement'
                      AND json_extract(payload_json, '$.card_id') = ?
                    """,
                    (card_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertIsNotNone(review)
            self.assertTrue(review["dedupe_key"])

            processed = run_worker_pass(root, roles=["librarian"], limit=5, maintenance=False)
            self.assertTrue(processed["ok"], processed)
            conn = connect_existing(root)
            try:
                card = conn.execute("SELECT status FROM cards WHERE id = ?", (card_id,)).fetchone()
            finally:
                conn.close()
            self.assertEqual(card["status"], "active")

    def test_reconcile_is_dry_run_first_preserves_rows_and_protects_real_reviews(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            for seq in range(3):
                append_scroll_event(
                    root,
                    session_id="alpha-session",
                    event_type="message",
                    role="user",
                    content=f"alpha backlog event {seq}",
                )
            for seq in range(2):
                append_scroll_event(
                    root,
                    session_id="beta-session",
                    event_type="message",
                    role="user",
                    content=f"beta backlog event {seq}",
                )

            conn = connect(root)
            try:
                seed_legacy_scribe_notifications(conn, session_id="alpha-session", count=2)
                seed_legacy_scribe_notifications(conn, session_id="beta-session", count=1)
                project_card = create_card(
                    conn,
                    root=root,
                    card_type="project_state",
                    title="Alpha project state",
                    summary="Alpha is ready for its next checkpoint.",
                    source_refs=[],
                    topics=["Alpha"],
                    metadata={"project_id": "alpha", "agent_id": "codex"},
                    visibility_scope="project",
                    session_id="alpha-session",
                    project_id="alpha",
                )
                graph_place_card(conn, project_card, label="Alpha project state")
                mempalace_card = create_card(
                    conn,
                    root=root,
                    card_type="mempalace_drawer",
                    title="Imported drawer",
                    summary="Imported operator evidence.",
                    source_refs=[],
                    metadata={
                        "import_id": "import-alpha",
                        "mempalace_wing": "operator",
                        "mempalace_room": "runbooks",
                    },
                )
                graph_place_card(conn, mempalace_card, label="Imported drawer")
                protected_card = create_card(
                    conn,
                    root=root,
                    card_type="project_state",
                    title="Protected project state",
                    summary="This card has a genuine queued Librarian review.",
                    source_refs=[],
                    topics=["Protected"],
                    metadata={"project_id": "protected", "agent_id": "codex"},
                    visibility_scope="project",
                    session_id="protected-session",
                    project_id="protected",
                )
                graph_place_card(conn, protected_card, label="Protected project state")
                protected_job = enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_card_placement",
                    priority=75,
                    payload={"card_id": protected_card},
                    related_card_ids=[protected_card],
                )
                conn.execute(
                    "UPDATE queue_jobs SET status = 'running', lease_owner = 'active-worker' WHERE id = ?",
                    (protected_job,),
                )
                conn.commit()
            finally:
                conn.close()

            dry_run = reconcile_worker_backlog(root)

            self.assertTrue(dry_run["ok"], dry_run)
            self.assertTrue(dry_run["dry_run"])
            self.assertEqual(dry_run["queue"]["redundant_before"], 3)
            self.assertEqual(dry_run["queue"]["changed"], 0)
            self.assertEqual(dry_run["cards"]["eligible_before"], 2)
            self.assertEqual(dry_run["cards"]["changed"], 0)
            self.assertEqual(dry_run["cards"]["genuine_pending_reviews_before"], 1)
            conn = connect_existing(root)
            try:
                queue_total_before = conn.execute("SELECT count(*) AS n FROM queue_jobs").fetchone()["n"]
                pending_scribe_before = conn.execute(
                    "SELECT count(*) AS n FROM queue_jobs WHERE status = 'pending' AND job_type = 'scroll_event_ingested'"
                ).fetchone()["n"]
                statuses_before = {
                    row["id"]: row["status"]
                    for row in conn.execute("SELECT id, status FROM cards WHERE id IN (?, ?, ?)", (project_card, mempalace_card, protected_card))
                }
            finally:
                conn.close()
            self.assertEqual(pending_scribe_before, 5)
            self.assertEqual(set(statuses_before.values()), {"pending_librarian_review"})

            applied = reconcile_worker_backlog(root, dry_run=False)

            self.assertTrue(applied["ok"], applied)
            self.assertEqual(applied["queue"]["changed"], 3)
            self.assertEqual(applied["queue"]["remaining_redundant"], 0)
            self.assertEqual(applied["cards"]["changed"], 2)
            self.assertEqual(applied["cards"]["remaining_eligible"], 0)
            self.assertEqual(applied["cards"]["genuine_pending_reviews_after"], 1)
            conn = connect_existing(root)
            try:
                queue_total_after = conn.execute("SELECT count(*) AS n FROM queue_jobs").fetchone()["n"]
                pending_scribe_after = conn.execute(
                    "SELECT count(*) AS n FROM queue_jobs WHERE status = 'pending' AND job_type = 'scroll_event_ingested'"
                ).fetchone()["n"]
                skipped_rows = conn.execute(
                    "SELECT error_json FROM queue_jobs WHERE status = 'skipped' AND job_type = 'scroll_event_ingested'"
                ).fetchall()
                card_rows = {
                    row["id"]: dict(row)
                    for row in conn.execute(
                        "SELECT id, status, placement_collection, shelf, location_uri FROM cards WHERE id IN (?, ?, ?)",
                        (project_card, mempalace_card, protected_card),
                    )
                }
                audit_counts = {
                    row["action"]: row["n"]
                    for row in conn.execute(
                        """
                        SELECT action, count(*) AS n
                        FROM audit_events
                        WHERE action IN ('supersede_redundant_scribe_notification', 'reconcile_graph_placed_card')
                        GROUP BY action
                        """
                    )
                }
            finally:
                conn.close()
            self.assertEqual(queue_total_after, queue_total_before)
            self.assertEqual(pending_scribe_after, 2)
            self.assertEqual(len(skipped_rows), 3)
            for skipped in skipped_rows:
                result = json.loads(skipped["error_json"])["result"]
                self.assertEqual(result["reason"], "superseded_pending_scroll_notification")
                self.assertTrue(result["keeper_job_id"])
            self.assertEqual(card_rows[project_card]["status"], "active")
            self.assertEqual(card_rows[project_card]["placement_collection"], "projects")
            self.assertEqual(card_rows[mempalace_card]["status"], "active")
            self.assertEqual(card_rows[mempalace_card]["shelf"], "operator/runbooks")
            self.assertEqual(card_rows[protected_card]["status"], "pending_librarian_review")
            self.assertEqual(audit_counts["supersede_redundant_scribe_notification"], 3)
            self.assertEqual(audit_counts["reconcile_graph_placed_card"], 2)
            for card_id in (project_card, mempalace_card):
                sidecar = load_atomic_yaml(resolve_stored_uri(root, card_rows[card_id]["location_uri"]).read_text(encoding="utf-8"))
                self.assertEqual(sidecar["status"], "active")

            repeated = reconcile_worker_backlog(root, dry_run=False)
            self.assertEqual(repeated["queue"]["changed"], 0)
            self.assertEqual(repeated["cards"]["changed"], 0)

    def test_reconcile_limit_is_bounded_and_resumable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            for seq in range(3):
                append_scroll_event(
                    root,
                    session_id="bounded-session",
                    event_type="message",
                    role="user",
                    content=f"bounded event {seq}",
                )
            conn = connect(root)
            try:
                seed_legacy_scribe_notifications(conn, session_id="bounded-session", count=2)
                conn.commit()
            finally:
                conn.close()

            first = reconcile_worker_backlog(root, dry_run=False, queue_limit=1, card_limit=1)
            second = reconcile_worker_backlog(root, dry_run=False, queue_limit=1, card_limit=1)

            self.assertEqual(first["queue"]["changed"], 1)
            self.assertEqual(first["queue"]["remaining_redundant"], 1)
            self.assertFalse(first["queue"]["complete"])
            self.assertEqual(second["queue"]["changed"], 1)
            self.assertEqual(second["queue"]["remaining_redundant"], 0)
            self.assertTrue(second["queue"]["complete"])

    def test_mempalace_review_activates_only_the_requested_import(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_ids: dict[str, list[str]] = {"import-alpha": [], "import-beta": []}
                for import_id, count in (("import-alpha", 2), ("import-beta", 1)):
                    for index in range(count):
                        card_id = create_card(
                            conn,
                            root=root,
                            card_type="mempalace_drawer",
                            title=f"{import_id} drawer {index}",
                            summary="Imported drawer evidence.",
                            source_refs=[],
                            metadata={
                                "import_id": import_id,
                                "mempalace_wing": "operator",
                                "mempalace_room": import_id,
                            },
                        )
                        graph_place_card(conn, card_id, label=f"{import_id} drawer {index}")
                        card_ids[import_id].append(card_id)
                conn.commit()
            finally:
                conn.close()

            result = review_mempalace_import(root, import_id="import-alpha")

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["reviewed_cards"], 2)
            conn = connect_existing(root)
            try:
                statuses = {
                    row["id"]: row["status"]
                    for row in conn.execute("SELECT id, status FROM cards WHERE card_type = 'mempalace_drawer'")
                }
            finally:
                conn.close()
            self.assertTrue(all(statuses[card_id] == "active" for card_id in card_ids["import-alpha"]))
            self.assertTrue(all(statuses[card_id] == "pending_librarian_review" for card_id in card_ids["import-beta"]))
            repeated = review_mempalace_import(root, import_id="import-alpha")
            self.assertTrue(repeated["ok"], repeated)
            self.assertEqual(repeated["reviewed_cards"], 0)

    def test_mempalace_worker_job_performs_the_import_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="mempalace_closet",
                    title="Worker-reviewed closet",
                    summary="Imported closet evidence.",
                    source_refs=[],
                    metadata={
                        "import_id": "import-worker",
                        "mempalace_wing": "operator",
                        "mempalace_room": "preferences",
                    },
                )
                graph_place_card(conn, card_id, label="Worker-reviewed closet")
                job_id = enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_mempalace_import",
                    priority=65,
                    payload={"import_id": "import-worker"},
                )
                conn.commit()
            finally:
                conn.close()

            result = run_worker_pass(root, roles=["librarian"], limit=1, maintenance=False)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["processed"][0]["result"]["reviewed_cards"], 1)
            conn = connect_existing(root)
            try:
                card_status = conn.execute("SELECT status FROM cards WHERE id = ?", (card_id,)).fetchone()["status"]
                job_status = conn.execute("SELECT status FROM queue_jobs WHERE id = ?", (job_id,)).fetchone()["status"]
            finally:
                conn.close()
            self.assertEqual(card_status, "active")
            self.assertEqual(job_status, "succeeded")

    def test_bounded_mempalace_worker_receipts_resume_until_complete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            import_id = "bounded-worker-import"
            conn = connect(root)
            card_ids: list[str] = []
            try:
                for index in range(3):
                    card_id = create_card(
                        conn,
                        root=root,
                        card_type="mempalace_drawer",
                        title=f"Bounded worker drawer {index}",
                        summary="Each bounded placement batch remains resumable.",
                        source_refs=[],
                        metadata={
                            "import_id": import_id,
                            "mempalace_wing": "operator",
                            "mempalace_room": "bounded",
                        },
                    )
                    graph_place_card(
                        conn,
                        card_id,
                        label=f"Bounded worker drawer {index}",
                    )
                    card_ids.append(card_id)
                initial_job_id = enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_mempalace_import",
                    priority=65,
                    payload={"import_id": import_id, "limit": 1},
                    dedupe_key=f"import:{import_id}",
                )
                conn.commit()
            finally:
                conn.close()

            first = run_worker_pass(
                root,
                roles=["librarian"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(first["ok"], first)
            first_result = first["processed"][0]["result"]
            self.assertFalse(first_result["complete"], first_result)
            self.assertTrue(first_result["resumable"], first_result)
            self.assertEqual(first_result["reviewed_cards"], 1)
            self.assertEqual(first_result["remaining_eligible"], 1)
            self.assertTrue(first_result["remaining_eligible_is_lower_bound"])
            self.assertEqual(first_result["limit"], 1)
            second_job_id = str(first_result["continuation_job_id"])
            self.assertTrue(second_job_id)

            conn = connect_existing(root)
            try:
                continuation = conn.execute(
                    "SELECT status, role, dedupe_key, payload_json FROM queue_jobs WHERE id = ?",
                    (second_job_id,),
                ).fetchone()
                initial_dedupe_key = str(
                    conn.execute(
                        "SELECT dedupe_key FROM queue_jobs WHERE id = ?",
                        (initial_job_id,),
                    ).fetchone()["dedupe_key"]
                )
                first_receipts = int(
                    conn.execute(
                        """
                        SELECT count(*) AS n FROM audit_events
                        WHERE action = 'worker_job_effect_committed'
                          AND target_id = ?
                        """,
                        (initial_job_id,),
                    ).fetchone()["n"]
                )
                first_effects = int(
                    conn.execute(
                        """
                        SELECT count(*) AS n FROM audit_events
                        WHERE action = 'reconcile_graph_placed_card'
                          AND json_extract(payload_json, '$.reason') = 'reviewed_mempalace_import'
                        """
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(continuation["status"], "pending")
            self.assertEqual(continuation["role"], "librarian")
            self.assertEqual(continuation["dedupe_key"], initial_dedupe_key)
            self.assertEqual(json.loads(continuation["payload_json"])["limit"], 1)
            self.assertEqual(first_receipts, 1)
            self.assertEqual(first_effects, 1)

            # Re-run the committed first job to model a crash after its effect
            # receipt but before the queue row became terminal. Its durable
            # receipt must win without consuming the pending continuation.
            conn = connect(root)
            try:
                conn.execute(
                    """
                    UPDATE queue_jobs
                    SET status = 'pending', started_at = NULL, finished_at = NULL,
                        lease_owner = NULL, lease_expires_at = NULL,
                        heartbeat_at = NULL, error_json = NULL, dedupe_key = NULL
                    WHERE id = ?
                    """,
                    (initial_job_id,),
                )
                conn.commit()
            finally:
                conn.close()
            replay = run_worker_pass(
                root,
                roles=["librarian"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(replay["ok"], replay)
            replay_result = replay["processed"][0]["result"]
            self.assertTrue(replay_result["idempotent_replay"], replay_result)
            self.assertEqual(replay_result["continuation_job_id"], second_job_id)

            conn = connect(root)
            try:
                replay_counts = {
                    "receipts": int(
                        conn.execute(
                            """
                            SELECT count(*) AS n FROM audit_events
                            WHERE action = 'worker_job_effect_committed'
                            """
                        ).fetchone()["n"]
                    ),
                    "effects": int(
                        conn.execute(
                            """
                            SELECT count(*) AS n FROM audit_events
                            WHERE action = 'reconcile_graph_placed_card'
                              AND json_extract(payload_json, '$.reason') = 'reviewed_mempalace_import'
                            """
                        ).fetchone()["n"]
                    ),
                }
                conn.execute(
                    """
                    UPDATE queue_jobs
                    SET status = 'running', started_at = coalesce(started_at, ?),
                        lease_owner = 'expired-worker',
                        lease_expires_at = '2000-01-01T00:00:00+00:00',
                        heartbeat_at = '2000-01-01T00:00:00+00:00'
                    WHERE id = ? AND status = 'pending'
                    """,
                    ("2000-01-01T00:00:00+00:00", second_job_id),
                )
                conn.commit()
            finally:
                conn.close()
            self.assertEqual(replay_counts, {"receipts": 1, "effects": 1})

            recovered = run_worker_pass(
                root,
                roles=["librarian"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(recovered["ok"], recovered)
            self.assertEqual(recovered["reclaimed_expired_jobs"], 1)
            recovered_result = recovered["processed"][0]["result"]
            self.assertFalse(recovered_result["complete"], recovered_result)
            self.assertEqual(recovered_result["reviewed_cards"], 1)
            self.assertEqual(recovered_result["remaining_eligible"], 1)
            self.assertTrue(recovered_result["remaining_eligible_is_lower_bound"])
            self.assertEqual(recovered_result["limit"], 1)
            third_job_id = str(recovered_result["continuation_job_id"])

            completed = run_worker_pass(
                root,
                roles=["librarian"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(completed["ok"], completed)
            completed_result = completed["processed"][0]["result"]
            self.assertTrue(completed_result["complete"], completed_result)
            self.assertFalse(completed_result["resumable"], completed_result)
            self.assertEqual(completed_result["reviewed_cards"], 1)
            self.assertEqual(completed_result["remaining_eligible"], 0)
            self.assertFalse(completed_result["remaining_eligible_is_lower_bound"])
            self.assertIsNone(completed_result["continuation_job_id"])

            conn = connect_existing(root)
            try:
                statuses = {
                    str(row["status"])
                    for row in conn.execute(
                        f"SELECT status FROM cards WHERE id IN ({','.join('?' for _ in card_ids)})",
                        card_ids,
                    )
                }
                receipt_rows = conn.execute(
                    """
                    SELECT target_id, count(*) AS n
                    FROM audit_events
                    WHERE action = 'worker_job_effect_committed'
                    GROUP BY target_id
                    """
                ).fetchall()
                effect_count = int(
                    conn.execute(
                        """
                        SELECT count(*) AS n FROM audit_events
                        WHERE action = 'reconcile_graph_placed_card'
                          AND json_extract(payload_json, '$.reason') = 'reviewed_mempalace_import'
                        """
                    ).fetchone()["n"]
                )
                pending_continuations = int(
                    conn.execute(
                        """
                        SELECT count(*) AS n FROM queue_jobs
                        WHERE job_type = 'review_mempalace_import' AND status = 'pending'
                        """
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(statuses, {"active"})
            self.assertEqual(
                {str(row["target_id"]): int(row["n"]) for row in receipt_rows},
                {initial_job_id: 1, second_job_id: 1, third_job_id: 1},
            )
            self.assertEqual(effect_count, len(card_ids))
            self.assertEqual(pending_continuations, 0)

    def test_mempalace_partial_refreshes_reused_pending_continuation_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            import_id = "reused-bounded-import"
            conn = connect(root)
            try:
                for index in range(3):
                    card_id = create_card(
                        conn,
                        root=root,
                        card_type="mempalace_drawer",
                        title=f"Reused bounded drawer {index}",
                        summary="A reused continuation retains the active batch limit.",
                        source_refs=[],
                        metadata={
                            "import_id": import_id,
                            "mempalace_wing": "operator",
                            "mempalace_room": "bounded",
                        },
                    )
                    graph_place_card(conn, card_id, label=f"Reused bounded drawer {index}")
                pending_job_id = enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_mempalace_import",
                    priority=12,
                    payload={
                        "import_id": import_id,
                        "limit": 2,
                        "reason": "concurrent_pending_job",
                    },
                    dedupe_key=f"import:{import_id}",
                )
                conn.commit()
            finally:
                conn.close()

            result = review_mempalace_import(root, import_id=import_id, limit=1)

            self.assertFalse(result["complete"], result)
            self.assertEqual(result["limit"], 1)
            self.assertEqual(result["continuation_job_id"], pending_job_id)
            conn = connect_existing(root)
            try:
                pending = conn.execute(
                    """
                    SELECT priority, status, payload_json
                    FROM queue_jobs
                    WHERE id = ?
                    """,
                    (pending_job_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(pending["status"], "pending")
            self.assertEqual(pending["priority"], 65)
            self.assertEqual(
                json.loads(pending["payload_json"]),
                {
                    "import_id": import_id,
                    "limit": 1,
                    "reason": "bounded_mempalace_import_continuation",
                },
            )

    def test_mempalace_candidate_window_uses_indexed_bounded_work(self) -> None:
        def measured_steps(card_count: int) -> int:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                init_db(root)
                conn = connect(root)
                try:
                    now = "2026-01-01T00:00:00+00:00"
                    import_id = "bounded-plan-import"
                    metadata_json = json.dumps(
                        {"import_id": import_id},
                        separators=(",", ":"),
                    )
                    conn.executemany(
                        """
                        INSERT INTO cards(
                            id, card_type, title, summary, status,
                            source_refs_json, entities_json, topics_json,
                            decisions_json, open_tasks_json, metadata_json,
                            visibility_scope, session_id, created_at, updated_at
                        )
                        VALUES(?, 'mempalace_drawer', ?, ?,
                               'pending_librarian_review', '[]', '[]', '[]',
                               '[]', '[]', ?, 'session', 'bounded-session', ?, ?)
                        """,
                        [
                            (
                                f"bounded-mempalace-card-{index:05d}",
                                f"Bounded drawer {index:05d}",
                                f"Bounded drawer summary {index:05d}",
                                metadata_json,
                                now,
                                now,
                            )
                            for index in range(card_count)
                        ],
                    )
                    conn.execute(
                        """
                        INSERT INTO graph_nodes(
                            id, kind, label, canonical_key, metadata_json,
                            created_at, updated_at
                        )
                        VALUES('bounded-shelf-node', 'term', 'bounded shelf',
                               'term:bounded-shelf', '{}', ?, ?)
                        """,
                        (now, now),
                    )
                    conn.executemany(
                        """
                        INSERT INTO graph_nodes(
                            id, kind, label, canonical_key, card_id,
                            metadata_json, created_at, updated_at
                        )
                        VALUES(?, 'card', ?, ?, ?, '{}', ?, ?)
                        """,
                        [
                            (
                                f"bounded-card-node-{index:05d}",
                                f"Bounded card node {index:05d}",
                                f"card:bounded-mempalace-card-{index:05d}",
                                f"bounded-mempalace-card-{index:05d}",
                                now,
                                now,
                            )
                            for index in range(card_count)
                        ],
                    )
                    conn.executemany(
                        """
                        INSERT INTO graph_edges(
                            id, source_node_id, relation, target_node_id,
                            status, source_refs_json, created_at, updated_at
                        )
                        VALUES(?, ?, 'placed_in', 'bounded-shelf-node',
                               'active', '[]', ?, ?)
                        """,
                        [
                            (
                                f"bounded-edge-{index:05d}",
                                f"bounded-card-node-{index:05d}",
                                now,
                                now,
                            )
                            for index in range(card_count)
                        ],
                    )
                    conn.commit()

                    where_clause, params = worker_module._legacy_card_where(
                        import_id=import_id
                    )
                    plan = " ".join(
                        str(row["detail"])
                        for row in conn.execute(
                            f"""
                            EXPLAIN QUERY PLAN
                            SELECT c.id, c.card_type, c.project_id,
                                   c.metadata_json, c.created_at
                            FROM cards c
                            WHERE {where_clause}
                            ORDER BY c.created_at, c.id
                            LIMIT ?
                            """,
                            (*params, 2),
                        )
                    )
                    self.assertIn(
                        "idx_cards_mempalace_import_pending_created",
                        plan,
                    )
                    self.assertIn("idx_graph_nodes_card_id", plan)
                    self.assertIn("idx_queue_job_type_status", plan)
                    self.assertNotIn("TEMP B-TREE", plan)

                    steps = 0

                    def count_step() -> int:
                        nonlocal steps
                        steps += 1
                        return 0

                    conn.set_progress_handler(count_step, 1)
                    rows = worker_module._legacy_card_candidates(
                        conn,
                        limit=2,
                        import_id=import_id,
                    )
                    conn.set_progress_handler(None, 0)
                    self.assertEqual(len(rows), 2)
                    return steps
                finally:
                    conn.close()

        small_steps = measured_steps(100)
        large_steps = measured_steps(5_000)
        self.assertLess(large_steps, (small_steps * 4) + 500)

    def test_service_runs_maintenance_on_cadence_not_every_idle_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            calls: list[bool] = []

            def fake_pass(_root, *, roles, limit, maintenance):
                calls.append(maintenance)
                return {"ok": True, "processed_count": 0}

            with patch("continuum.core.workers.run_worker_pass", side_effect=fake_pass), patch("continuum.core.workers.time.sleep"):
                result = serve_workers(
                    root,
                    limit=3,
                    interval_seconds=0.1,
                    maintenance_interval_seconds=3600,
                )

            self.assertEqual(calls, [True, False, False])
            self.assertEqual(result["maintenance_passes"], 1)

    def test_service_returns_failed_pass_instead_of_reporting_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            failed_pass = {
                "ok": False,
                "processed_count": 0,
                "maintenance": {
                    "sidecars": {
                        "ok": False,
                        "pending": 1,
                        "synced": 0,
                        "failed": 1,
                    }
                },
            }
            with (
                patch(
                    "continuum.core.workers.run_worker_pass",
                    return_value=failed_pass,
                ) as run_pass,
                patch("continuum.core.workers.time.sleep") as sleep,
            ):
                result = serve_workers(
                    root,
                    limit=3,
                    interval_seconds=0.1,
                )

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "worker_pass_failed")
            self.assertEqual(result["passes"], 1)
            self.assertEqual(result["failed_pass"], failed_pass)
            run_pass.assert_called_once()
            sleep.assert_not_called()

    def test_service_rejects_a_second_service_for_the_same_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"

            def fake_pass(_root, *, roles, limit, maintenance):
                with self.assertRaisesRegex(RuntimeError, "already running"):
                    serve_workers(root, limit=1, interval_seconds=0.1)
                return {"ok": True, "processed_count": 0}

            with patch("continuum.core.workers.run_worker_pass", side_effect=fake_pass):
                outer = serve_workers(root, limit=1, interval_seconds=0.1)

            self.assertTrue(outer["ok"])


if __name__ == "__main__":
    unittest.main()
