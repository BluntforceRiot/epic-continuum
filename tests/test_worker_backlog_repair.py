from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum.core.atomic import load_atomic_yaml
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
