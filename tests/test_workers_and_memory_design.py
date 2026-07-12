from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum.core.atomic import load_atomic_yaml
from continuum.core import store as store_module
from continuum.core import workers as worker_module
from continuum.core.config import default_config, write_config
from continuum.core.evals import run_memory_quality_evals
from continuum.core.store import (
    append_scroll_event,
    add_graph_edge,
    audit,
    compile_context,
    connect,
    connect_existing,
    create_card,
    enqueue_job,
    init_db,
    ingest_file,
    record_project_state,
    resolve_stored_uri,
    roll_scroll_segment,
    semantic_integrity_report,
    sync_card_sidecars_after_commit,
    upsert_graph_node,
)
from continuum.core.workers import (
    apply_storage_tiering,
    decay_graph_routes,
    detect_conflicts,
    drain_card_sidecar_outbox,
    memory_health,
    prune_memory,
    resolve_conflict,
    run_worker_pass,
    verify_book_integrity,
    verify_segment_integrity,
)
from continuum.integrations.common import record_turn


class EpicContinuumWorkerDesignTest(unittest.TestCase):
    def test_conflict_resolution_marks_temporal_authority_and_syncs_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                previous = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Yarn Context Ceiling",
                    summary="Use a one million token default.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="temporal-a",
                    project_id="continuum",
                )
                current = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Yarn Context Ceiling",
                    summary="Do not use a one million token default; cap it safely.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="temporal-b",
                    project_id="continuum",
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [previous, current])
            detected = detect_conflicts(root, card_id=current)
            self.assertEqual(detected["conflict_count"], 1)

            result = resolve_conflict(root, card_id=current, action="supersede")

            self.assertTrue(result["ok"], result)
            conn = connect_existing(root)
            try:
                rows = {
                    row["id"]: dict(row)
                    for row in conn.execute(
                        "SELECT id, conflict_group, supersedes_card_id, superseded_by_card_id FROM cards WHERE id IN (?, ?)",
                        (previous, current),
                    )
                }
            finally:
                conn.close()
            self.assertIsNone(rows[current]["conflict_group"])
            self.assertEqual(rows[current]["supersedes_card_id"], previous)
            self.assertEqual(rows[previous]["superseded_by_card_id"], current)
            self.assertEqual(audit(root)["stale_card_sidecars"], 0)

    def test_conflict_resolution_can_dismiss_false_positive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                first = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Shared Route",
                    summary="Use the shared route.",
                    source_refs=[],
                    session_id="dismiss-session",
                )
                second = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Shared Route",
                    summary="Do not use the shared route.",
                    source_refs=[],
                    session_id="dismiss-session",
                )
                conn.commit()
            finally:
                conn.close()
            detect_conflicts(root, card_id=first)

            result = resolve_conflict(root, card_id=first, action="dismiss")

            self.assertEqual(result["action"], "dismiss")
            conn = connect_existing(root)
            try:
                values = [
                    row["conflict_group"]
                    for row in conn.execute("SELECT conflict_group FROM cards WHERE id IN (?, ?)", (first, second))
                ]
            finally:
                conn.close()
            self.assertEqual(values, [None, None])

    def test_conflict_detection_respects_project_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                alpha = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Copper Routing",
                    summary="Use copper routing for the alpha project.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="shared-session",
                    project_id="alpha",
                )
                beta = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Copper Routing",
                    summary="Do not use copper routing for the beta project.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="shared-session",
                    project_id="beta",
                )
                conn.commit()
            finally:
                conn.close()

            result = detect_conflicts(root, card_id=alpha)

            self.assertEqual(result["conflict_count"], 0)
            conn = connect(root)
            try:
                rows = conn.execute(
                    "SELECT id, conflict_group FROM cards WHERE id IN (?, ?) ORDER BY id",
                    (alpha, beta),
                ).fetchall()
            finally:
                conn.close()
            self.assertEqual([row["conflict_group"] for row in rows], [None, None])

    def test_conflict_detection_finds_same_project_conflicts_across_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                alpha = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Lantern Routing",
                    summary="Use lantern routing for the alpha project.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="agent-a-session",
                    project_id="alpha",
                )
                beta = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Lantern Routing",
                    summary="Do not use lantern routing for the alpha project.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="agent-b-session",
                    project_id="alpha",
                )
                conn.commit()
            finally:
                conn.close()

            result = detect_conflicts(root, card_id=alpha)

            self.assertEqual(result["conflict_count"], 1)
            conn = connect(root)
            try:
                groups = {
                    row["id"]: row["conflict_group"]
                    for row in conn.execute("SELECT id, conflict_group FROM cards WHERE id IN (?, ?)", (alpha, beta))
                }
            finally:
                conn.close()
            self.assertTrue(groups[alpha])
            self.assertEqual(groups[alpha], groups[beta])

    def test_conflict_detection_syncs_sidecars_after_committed_update(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                alpha = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Lantern Plan",
                    summary="Use lantern staging for the shared session.",
                    source_refs=[],
                    visibility_scope="session",
                    session_id="conflict-session",
                )
                beta = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Lantern Plan",
                    summary="Do not use lantern staging for the shared session.",
                    source_refs=[],
                    visibility_scope="session",
                    session_id="conflict-session",
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [alpha, beta])

            result = detect_conflicts(root, card_id=alpha)

            self.assertEqual(result["conflict_count"], 1)
            self.assertEqual(audit(root)["stale_card_sidecars"], 0)
            conn = connect_existing(root)
            try:
                rows = conn.execute(
                    "SELECT id, conflict_group, location_uri FROM cards WHERE id IN (?, ?)",
                    (alpha, beta),
                ).fetchall()
            finally:
                conn.close()
            groups = {row["id"]: row["conflict_group"] for row in rows}
            self.assertTrue(groups[alpha])
            self.assertEqual(groups[alpha], groups[beta])
            for row in rows:
                sidecar = load_atomic_yaml(
                    resolve_stored_uri(root, row["location_uri"]).read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(sidecar["conflict_group"], row["conflict_group"])

    def test_sidecar_sync_serializes_file_replace_through_crash_and_newer_update(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="Sidecar generation race",
                    summary="OLD-SIDECAR-SUMMARY",
                    source_refs=[],
                    visibility_scope="session",
                    session_id="sidecar-generation-session",
                )
                conn.commit()
            finally:
                conn.close()

            old_file_replaced = threading.Event()
            allow_simulated_crash = threading.Event()
            original_write = store_module.write_card_sidecar_from_values

            def crash_after_old_write(*args: object, **kwargs: object) -> str | None:
                result = original_write(*args, **kwargs)
                if kwargs.get("summary") == "OLD-SIDECAR-SUMMARY":
                    old_file_replaced.set()
                    allow_simulated_crash.wait(timeout=5)
                    raise SystemExit("simulated process death after sidecar replace")
                return result

            first_errors: list[BaseException] = []
            newer_update_committed = threading.Event()
            newer_sync_results: list[dict[str, object]] = []

            def run_old_sync() -> None:
                try:
                    sync_card_sidecars_after_commit(root, [card_id])
                except BaseException as exc:
                    first_errors.append(exc)

            def update_and_sync_newer_card() -> None:
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                        ("NEW-SIDECAR-SUMMARY", store_module.utc_now(), card_id),
                    )
                    store_module.mark_card_sidecar_outbox(
                        conn,
                        [card_id],
                        reason="concurrent_card_update",
                    )
                    conn.commit()
                    newer_update_committed.set()
                finally:
                    conn.close()
                newer_sync_results.append(
                    sync_card_sidecars_after_commit(root, [card_id])
                )

            with patch.object(
                store_module,
                "write_card_sidecar_from_values",
                side_effect=crash_after_old_write,
            ):
                old_thread = threading.Thread(target=run_old_sync)
                old_thread.start()
                self.assertTrue(old_file_replaced.wait(timeout=5))
                newer_thread = threading.Thread(target=update_and_sync_newer_card)
                newer_thread.start()
                self.assertFalse(newer_update_committed.wait(timeout=0.1))
                allow_simulated_crash.set()
                old_thread.join(timeout=5)
                newer_thread.join(timeout=5)
                self.assertFalse(old_thread.is_alive())
                self.assertFalse(newer_thread.is_alive())

            self.assertEqual(len(first_errors), 1)
            self.assertIsInstance(first_errors[0], SystemExit)
            self.assertTrue(newer_update_committed.is_set())
            self.assertTrue(newer_sync_results[0]["ok"], newer_sync_results)
            conn = connect_existing(root)
            try:
                row = conn.execute(
                    "SELECT summary, location_uri FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                pending_after_drain = int(
                    conn.execute(
                        "SELECT count(*) AS n FROM card_sidecar_outbox WHERE card_id = ?",
                        (card_id,),
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            sidecar_path = resolve_stored_uri(root, str(row["location_uri"]))
            sidecar = load_atomic_yaml(sidecar_path.read_text(encoding="utf-8"))
            self.assertEqual(row["summary"], "NEW-SIDECAR-SUMMARY")
            self.assertEqual(sidecar["summary"], "NEW-SIDECAR-SUMMARY")
            self.assertEqual(pending_after_drain, 0)

    def test_sidecar_outbox_survives_commit_until_worker_drains_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Crash Window Sidecar",
                    summary="Sidecar should sync after a crash-window commit.",
                    source_refs=[],
                    visibility_scope="session",
                    session_id="sidecar-crash-window",
                )
                conn.commit()
                outbox_count = conn.execute("SELECT count(*) AS n FROM card_sidecar_outbox WHERE card_id = ?", (card_id,)).fetchone()["n"]
                location_uri = conn.execute("SELECT location_uri FROM cards WHERE id = ?", (card_id,)).fetchone()["location_uri"]
            finally:
                conn.close()
            self.assertEqual(outbox_count, 1)
            self.assertFalse(resolve_stored_uri(root, location_uri).exists())

            drained = drain_card_sidecar_outbox(root)

            self.assertTrue(drained["ok"], drained)
            self.assertEqual(drained["synced"], 1)
            conn = connect(root)
            try:
                remaining = conn.execute("SELECT count(*) AS n FROM card_sidecar_outbox WHERE card_id = ?", (card_id,)).fetchone()["n"]
                location_uri = conn.execute("SELECT location_uri FROM cards WHERE id = ?", (card_id,)).fetchone()["location_uri"]
            finally:
                conn.close()
            self.assertEqual(remaining, 0)
            self.assertTrue(resolve_stored_uri(root, location_uri).exists())

    def test_worker_pass_reviews_cards_and_verifies_segment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            append_scroll_event(root, session_id="worker-flow", event_type="message", role="user", content="Aurora worker notes.")
            append_scroll_event(root, session_id="worker-flow", event_type="message", role="assistant", content="Decision: keep Aurora worker notes hot.")
            segment = roll_scroll_segment(root, session_id="worker-flow", start_seq=1, end_seq=2)

            result = run_worker_pass(root, limit=20, maintenance=False)

            self.assertGreaterEqual(result["processed_count"], 3)
            conn = connect_existing(root)
            try:
                card = conn.execute("SELECT status, shelf, visibility_scope, session_id, project_id, location_uri FROM cards WHERE id = ?", (segment["card_id"],)).fetchone()
                jobs = conn.execute("SELECT status, count(*) AS n FROM queue_jobs GROUP BY status").fetchall()
            finally:
                conn.close()
            self.assertEqual(card["status"], "active")
            self.assertTrue(card["shelf"])
            sidecar = load_atomic_yaml(resolve_stored_uri(root, card["location_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(sidecar["schema"], "continuum.atomic_memory.v2")
            self.assertEqual(sidecar["status"], "active")
            self.assertEqual(sidecar["shelf"], card["shelf"])
            self.assertEqual(sidecar["visibility_scope"], card["visibility_scope"])
            self.assertEqual(sidecar["session_id"], card["session_id"])
            self.assertEqual(sidecar["project_id"], card["project_id"])
            self.assertTrue(any(row["status"] == "succeeded" for row in jobs))

    def test_automatic_capture_rolls_mixed_project_windows_by_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["capture"]["roll_segments_every_events"] = 2
            write_config(root, config)

            alpha = record_turn(
                root,
                session_id="shared-capture-session",
                role="user",
                content="Alpha scoped automatic capture segment.",
                source="codex",
                project_id="alpha",
            )
            beta = record_turn(
                root,
                session_id="shared-capture-session",
                role="user",
                content="Beta scoped automatic capture segment.",
                source="codex",
                project_id="beta",
            )

            self.assertIsNotNone(alpha)
            self.assertIsNotNone(beta)
            conn = connect_existing(root)
            try:
                cards = conn.execute(
                    """
                    SELECT visibility_scope, project_id, summary
                    FROM cards
                    WHERE card_type = 'scroll_segment'
                    ORDER BY project_id
                    """
                ).fetchall()
            finally:
                conn.close()
            self.assertEqual(len(cards), 2)
            self.assertEqual([card["project_id"] for card in cards], ["alpha", "beta"])
            self.assertTrue(all(card["visibility_scope"] == "project" for card in cards))
            self.assertIn("Alpha scoped", cards[0]["summary"])
            self.assertIn("Beta scoped", cards[1]["summary"])

    def test_scoped_recall_and_reinforcement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            append_scroll_event(root, session_id="alpha", event_type="message", role="user", content="Alpha needs copper gasket work.")
            roll_scroll_segment(root, session_id="alpha", start_seq=1, end_seq=1)

            alpha_context = compile_context(root, session_id="alpha", query="copper gasket", token_budget=1200, card_scope="session")
            beta_context = compile_context(root, session_id="beta", query="copper gasket", token_budget=1200, card_scope="session")

            self.assertIn("copper gasket", alpha_context["context_text"])
            self.assertNotIn("copper gasket", beta_context["context_text"])
            conn = connect_existing(root)
            try:
                recalled = conn.execute("SELECT recall_count FROM cards WHERE session_id = 'alpha'").fetchone()["recall_count"]
            finally:
                conn.close()
            self.assertGreaterEqual(recalled, 1)

    def test_archivist_book_integrity_uses_original_bytes_for_non_utf8_ingests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            source = Path(tmp) / "binary-ish.bin"
            source.write_bytes(b"hello\xffworld\x00raw-bytes")

            result = ingest_file(root, path=source, title="Binaryish evidence")
            verified = verify_book_integrity(root, book_id=result["book_id"])

            self.assertTrue(verified["ok"], verified)
            self.assertTrue(verified["checked_original"])
            self.assertFalse(verified["checked_reader"])

    def test_segment_integrity_detects_tamper_and_failed_worker_marks_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            append_scroll_event(root, session_id="integrity", event_type="message", role="user", content="Original evidence line.")
            append_scroll_event(root, session_id="integrity", event_type="message", role="assistant", content="Original reply line.")
            segment = roll_scroll_segment(root, session_id="integrity", start_seq=1, end_seq=2)

            good = verify_segment_integrity(root, segment_id=segment["segment_id"])
            self.assertTrue(good["ok"], good)

            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            try:
                conn.execute(
                    "UPDATE scroll_events SET content = ? WHERE session_id = ? AND seq = 1",
                    ("Tampered evidence line.", "integrity"),
                )
                conn.commit()
            finally:
                conn.close()

            bad = verify_segment_integrity(root, segment_id=segment["segment_id"])
            self.assertFalse(bad["ok"], bad)
            self.assertEqual(bad["reason"], "scroll_event_hash_mismatch")

            result = run_worker_pass(root, limit=20, maintenance=False)
            self.assertFalse(result["ok"], result)
            conn = connect_existing(root)
            try:
                verify_job = conn.execute(
                    "SELECT status, error_json FROM queue_jobs WHERE job_type = 'verify_segment_integrity' ORDER BY updated_at DESC LIMIT 1"
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(verify_job["status"], "failed")
            self.assertIn("scroll_event_hash_mismatch", verify_job["error_json"])

    def test_worker_pass_reclaims_expired_running_job_lease(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            try:
                now = "2026-01-01T00:00:00+00:00"
                conn.execute(
                    """
                    INSERT INTO queue_jobs(
                        id, role, job_type, priority, status, preemptible, attempt_count,
                        error_json, lease_owner, lease_expires_at, heartbeat_at,
                        related_card_ids_json, payload_json, created_at, updated_at, started_at
                    )
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "job_expired",
                        "archivist",
                        "review_mempalace_import",
                        1,
                        "running",
                        1,
                        0,
                        None,
                        "dead-worker",
                        "2000-01-01T00:00:00+00:00",
                        "2000-01-01T00:00:00+00:00",
                        "[]",
                        json.dumps({"import_id": "legacy"}),
                        now,
                        now,
                        now,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            result = run_worker_pass(root, roles=["archivist"], limit=1, maintenance=False)

            self.assertEqual(result["reclaimed_expired_jobs"], 1)
            self.assertEqual(result["processed_count"], 1)
            conn = connect_existing(root)
            try:
                row = conn.execute("SELECT status, lease_owner, lease_expires_at, heartbeat_at, attempt_count FROM queue_jobs WHERE id = 'job_expired'").fetchone()
            finally:
                conn.close()
            self.assertEqual(row["status"], "succeeded")
            self.assertIsNone(row["lease_owner"])
            self.assertIsNone(row["lease_expires_at"])
            self.assertIsNotNone(row["heartbeat_at"])
            self.assertEqual(row["attempt_count"], 1)

    def test_conflict_maintenance_escalates_once_then_deduplicates_review_signal(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            base = {
                "ok": True,
                "scan": {
                    "anchor_card_id": "card_maintenance_anchor",
                    "anchor_identity_hash": "a" * 64,
                },
                "continuation": {
                    "required": True,
                    "requires_larger_budget": True,
                    "required_candidate_cards_lower_bound": 201,
                    "manual_review_required": False,
                    "manual_review_reason": None,
                },
            }
            escalated = {
                "ok": True,
                "scan": {
                    "anchor_card_id": "card_maintenance_anchor",
                    "anchor_identity_hash": "a" * 64,
                },
                "continuation": {
                    "required": True,
                    "requires_larger_budget": True,
                    "required_candidate_cards_lower_bound": 513,
                    "manual_review_required": True,
                    "manual_review_reason": (
                        "targeted_fuzzy_boundary_exceeds_automatic_candidate_limit"
                    ),
                },
            }
            maintenance_stub = {"ok": True}
            with (
                patch.object(
                    worker_module,
                    "detect_conflicts",
                    side_effect=[base, escalated],
                ) as detected,
                patch.object(
                    worker_module,
                    "drain_card_sidecar_outbox",
                    return_value=maintenance_stub,
                ),
                patch.object(
                    worker_module,
                    "decay_graph_routes",
                    return_value=maintenance_stub,
                ),
                patch.object(
                    worker_module,
                    "apply_storage_tiering",
                    return_value=maintenance_stub,
                ),
            ):
                first = run_worker_pass(root, limit=1, maintenance=True)

            self.assertEqual(detected.call_count, 2)
            escalation_kwargs = detected.call_args_list[1].kwargs
            self.assertEqual(
                escalation_kwargs["candidate_card_limit"],
                worker_module.MAX_CONFLICT_CANDIDATE_CARDS,
            )
            self.assertEqual(
                escalation_kwargs["comparison_limit"],
                worker_module.MAX_CONFLICT_COMPARISONS,
            )
            signal = first["maintenance"]["conflict_review_required"]
            self.assertTrue(signal["created"], signal)
            self.assertTrue(signal["manual_review_required"], signal)

            with (
                patch.object(
                    worker_module,
                    "detect_conflicts",
                    return_value=base,
                ) as repeated_detection,
                patch.object(
                    worker_module,
                    "drain_card_sidecar_outbox",
                    return_value=maintenance_stub,
                ),
                patch.object(
                    worker_module,
                    "decay_graph_routes",
                    return_value=maintenance_stub,
                ),
                patch.object(
                    worker_module,
                    "apply_storage_tiering",
                    return_value=maintenance_stub,
                ),
            ):
                repeated = run_worker_pass(root, limit=1, maintenance=True)

            self.assertEqual(repeated_detection.call_count, 2)
            self.assertFalse(
                repeated["maintenance"]["conflict_review_required"]["created"]
            )
            resolved = {
                "ok": True,
                "scan": base["scan"],
                "continuation": {
                    "required": False,
                    "requires_larger_budget": False,
                    "required_candidate_cards_lower_bound": 0,
                    "manual_review_required": False,
                    "manual_review_reason": None,
                },
            }
            with (
                patch.object(
                    worker_module,
                    "detect_conflicts",
                    side_effect=[base, resolved],
                ) as recovered_detection,
                patch.object(
                    worker_module,
                    "drain_card_sidecar_outbox",
                    return_value=maintenance_stub,
                ),
                patch.object(
                    worker_module,
                    "decay_graph_routes",
                    return_value=maintenance_stub,
                ),
                patch.object(
                    worker_module,
                    "apply_storage_tiering",
                    return_value=maintenance_stub,
                ),
            ):
                recovered = run_worker_pass(root, limit=1, maintenance=True)

            self.assertEqual(recovered_detection.call_count, 2)
            self.assertIn("conflict_escalation", recovered["maintenance"])
            self.assertNotIn("conflict_review_required", recovered["maintenance"])
            conn = connect_existing(root)
            try:
                review_audits = int(
                    conn.execute(
                        """
                        SELECT count(*) AS n
                        FROM audit_events
                        WHERE action = 'librarian_conflict_review_required'
                        """
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(review_audits, 1)

    def test_worker_pass_does_not_finish_job_after_lease_owner_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            try:
                now = "2026-01-01T00:00:00+00:00"
                conn.execute(
                    """
                    INSERT INTO queue_jobs(
                        id, role, job_type, priority, status, preemptible, attempt_count,
                        error_json, related_card_ids_json, payload_json, created_at, updated_at
                    )
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "job_lease_stolen",
                        "archivist",
                        "review_mempalace_import",
                        1,
                        "pending",
                        1,
                        0,
                        None,
                        "[]",
                        json.dumps({"import_id": "lease-stolen"}),
                        now,
                        now,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            def steal_lease(_root: Path, job: dict) -> dict:
                stolen = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
                try:
                    stolen.execute(
                        "UPDATE queue_jobs SET lease_owner = ?, lease_expires_at = ? WHERE id = ?",
                        ("new-worker", "2099-01-01T00:00:00+00:00", job["id"]),
                    )
                    stolen.commit()
                finally:
                    stolen.close()
                return {"ok": True, "reviewed_import": "lease-stolen"}

            with patch("continuum.core.workers._process_job", side_effect=steal_lease):
                result = run_worker_pass(root, roles=["archivist"], limit=1, maintenance=False)

            self.assertFalse(result["ok"])
            self.assertIn("worker lease lost", result["processed"][0]["error"])
            conn = connect_existing(root)
            try:
                row = conn.execute("SELECT status, lease_owner, finished_at FROM queue_jobs WHERE id = 'job_lease_stolen'").fetchone()
            finally:
                conn.close()
            self.assertEqual(row["status"], "running")
            self.assertEqual(row["lease_owner"], "new-worker")
            self.assertIsNone(row["finished_at"])

    def test_non_scribe_worker_renews_lease_while_processor_is_running(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                enqueue_job(
                    conn,
                    role="archivist",
                    job_type="renewal_probe",
                    priority=1,
                    payload={},
                )
                conn.commit()
            finally:
                conn.close()

            def slow_processor(_root: Path, _job: dict, **_kwargs: object) -> dict:
                time.sleep(0.08)
                return {"ok": True}

            with (
                patch.object(worker_module, "_lease_renewal_interval", return_value=0.01),
                patch.object(
                    worker_module,
                    "_heartbeat_job",
                    wraps=worker_module._heartbeat_job,
                ) as heartbeat,
                patch.object(worker_module, "_process_job", side_effect=slow_processor),
            ):
                result = run_worker_pass(
                    root,
                    roles=["archivist"],
                    limit=1,
                    maintenance=False,
                )

            self.assertTrue(result["ok"], result)
            # One call is made by the fenced finisher; additional calls prove
            # the generic background renewer ran for a non-Scribe processor.
            self.assertGreaterEqual(heartbeat.call_count, 2)

    def test_scribe_mid_effect_expiry_replays_durable_step_without_duplicate_effects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            config = default_config()
            config["capture"]["roll_segments_every_events"] = 1
            write_config(root, config)
            session_id = "scribe-mid-effect-expiry"
            append_scroll_event(
                root,
                session_id=session_id,
                event_type="message",
                role="user",
                content="Scribe mid-effect lease fencing evidence.",
            )
            conn = connect(root)
            try:
                conn.execute("DELETE FROM queue_jobs")
                job_id = enqueue_job(
                    conn,
                    role="scribe",
                    job_type="scroll_event_ingested",
                    priority=1,
                    payload={"session_id": session_id},
                )
                conn.commit()
            finally:
                conn.close()

            original_roll = worker_module.roll_scroll_segment

            def commit_then_expire(*args: object, **kwargs: object) -> dict:
                result = original_roll(*args, **kwargs)
                expiry_conn = connect(root)
                try:
                    cursor = expiry_conn.execute(
                        """
                        UPDATE queue_jobs
                        SET lease_expires_at = '2000-01-01T00:00:00+00:00',
                            heartbeat_at = '2000-01-01T00:00:00+00:00'
                        WHERE id = ? AND status = 'running'
                        """,
                        (job_id,),
                    )
                    expiry_conn.commit()
                    self.assertEqual(cursor.rowcount, 1)
                finally:
                    expiry_conn.close()
                return result

            with patch.object(
                worker_module,
                "roll_scroll_segment",
                side_effect=commit_then_expire,
            ):
                expired = run_worker_pass(
                    root,
                    roles=["scribe"],
                    limit=1,
                    maintenance=False,
                )

            self.assertFalse(expired["ok"], expired)
            self.assertIn("worker lease lost", expired["processed"][0]["error"])
            conn = connect_existing(root)
            try:
                before = {
                    "segments": int(
                        conn.execute(
                            "SELECT count(*) AS n FROM scroll_segments WHERE session_id = ?",
                            (session_id,),
                        ).fetchone()["n"]
                    ),
                    "cards": int(
                        conn.execute(
                            "SELECT count(*) AS n FROM cards WHERE card_type = 'scroll_segment'"
                        ).fetchone()["n"]
                    ),
                    "roll_audits": int(
                        conn.execute(
                            "SELECT count(*) AS n FROM audit_events WHERE action = 'roll_scroll_segment'"
                        ).fetchone()["n"]
                    ),
                    "intents": int(
                        conn.execute(
                            """
                            SELECT count(*) AS n FROM audit_events
                            WHERE action = 'worker_scribe_segment_step_intent'
                              AND target_id = ?
                            """,
                            (job_id,),
                        ).fetchone()["n"]
                    ),
                    "receipts": int(
                        conn.execute(
                            """
                            SELECT count(*) AS n FROM audit_events
                            WHERE action = 'worker_job_effect_committed'
                              AND target_id = ?
                            """,
                            (job_id,),
                        ).fetchone()["n"]
                    ),
                }
            finally:
                conn.close()
            self.assertEqual(
                before,
                {
                    "segments": 1,
                    "cards": 1,
                    "roll_audits": 1,
                    "intents": 1,
                    "receipts": 0,
                },
            )

            recovered = run_worker_pass(
                root,
                roles=["scribe"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(recovered["ok"], recovered)
            self.assertEqual(recovered["reclaimed_expired_jobs"], 1)
            conn = connect_existing(root)
            try:
                after = {
                    "segments": int(
                        conn.execute(
                            "SELECT count(*) AS n FROM scroll_segments WHERE session_id = ?",
                            (session_id,),
                        ).fetchone()["n"]
                    ),
                    "cards": int(
                        conn.execute(
                            "SELECT count(*) AS n FROM cards WHERE card_type = 'scroll_segment'"
                        ).fetchone()["n"]
                    ),
                    "roll_audits": int(
                        conn.execute(
                            "SELECT count(*) AS n FROM audit_events WHERE action = 'roll_scroll_segment'"
                        ).fetchone()["n"]
                    ),
                    "intents": int(
                        conn.execute(
                            """
                            SELECT count(*) AS n FROM audit_events
                            WHERE action = 'worker_scribe_segment_step_intent'
                              AND target_id = ?
                            """,
                            (job_id,),
                        ).fetchone()["n"]
                    ),
                    "receipts": int(
                        conn.execute(
                            """
                            SELECT count(*) AS n FROM audit_events
                            WHERE action = 'worker_job_effect_committed'
                              AND target_id = ?
                            """,
                            (job_id,),
                        ).fetchone()["n"]
                    ),
                }
            finally:
                conn.close()
            self.assertEqual(
                after,
                {
                    "segments": 1,
                    "cards": 1,
                    "roll_audits": 1,
                    "intents": 1,
                    "receipts": 1,
                },
            )

    def test_scribe_final_receipt_failure_replays_committed_step_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            config = default_config()
            config["capture"]["roll_segments_every_events"] = 1
            write_config(root, config)
            session_id = "scribe-final-receipt-replay"
            append_scroll_event(
                root,
                session_id=session_id,
                event_type="message",
                role="user",
                content="The committed Scribe step must survive a final receipt crash.",
            )
            conn = connect(root)
            try:
                conn.execute("DELETE FROM queue_jobs")
                job_id = enqueue_job(
                    conn,
                    role="scribe",
                    job_type="scroll_event_ingested",
                    priority=1,
                    payload={"session_id": session_id},
                )
                conn.commit()
            finally:
                conn.close()

            with patch.object(
                worker_module,
                "_record_worker_effect",
                side_effect=RuntimeError("forced final Scribe receipt failure"),
            ):
                interrupted = run_worker_pass(
                    root,
                    roles=["scribe"],
                    limit=1,
                    maintenance=False,
                )
            self.assertFalse(interrupted["ok"], interrupted)

            conn = connect(root)
            try:
                segment_id = str(
                    conn.execute(
                        "SELECT id FROM scroll_segments WHERE session_id = ?",
                        (session_id,),
                    ).fetchone()["id"]
                )
                self.assertEqual(
                    int(
                        conn.execute(
                            """
                            SELECT count(*) AS n FROM audit_events
                            WHERE action = 'worker_scribe_segment_step_committed'
                              AND target_id = ?
                            """,
                            (job_id,),
                        ).fetchone()["n"]
                    ),
                    1,
                )
                self.assertEqual(
                    int(
                        conn.execute(
                            """
                            SELECT count(*) AS n FROM audit_events
                            WHERE action = 'worker_job_effect_committed'
                              AND target_id = ?
                            """,
                            (job_id,),
                        ).fetchone()["n"]
                    ),
                    0,
                )
                conn.execute(
                    """
                    UPDATE queue_jobs
                    SET status = 'pending', started_at = NULL, finished_at = NULL,
                        lease_owner = NULL, lease_expires_at = NULL,
                        heartbeat_at = NULL, error_json = NULL
                    WHERE id = ?
                    """,
                    (job_id,),
                )
                conn.commit()
            finally:
                conn.close()

            replayed = run_worker_pass(
                root,
                roles=["scribe"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(replayed["ok"], replayed)
            replay_result = replayed["processed"][0]["result"]
            self.assertEqual(replay_result["rolled_count"], 1)
            self.assertEqual(replay_result["rolled"][0]["segment_id"], segment_id)

            conn = connect_existing(root)
            try:
                self.assertEqual(
                    int(
                        conn.execute(
                            "SELECT count(*) AS n FROM scroll_segments WHERE session_id = ?",
                            (session_id,),
                        ).fetchone()["n"]
                    ),
                    1,
                )
                self.assertEqual(
                    int(
                        conn.execute(
                            "SELECT count(*) AS n FROM audit_events WHERE action = 'roll_scroll_segment'"
                        ).fetchone()["n"]
                    ),
                    1,
                )
                receipt = conn.execute(
                    """
                    SELECT payload_json FROM audit_events
                    WHERE action = 'worker_job_effect_committed'
                      AND target_id = ?
                    ORDER BY rowid DESC LIMIT 1
                    """,
                    (job_id,),
                ).fetchone()
            finally:
                conn.close()
            receipt_payload = json.loads(receipt["payload_json"])
            self.assertEqual(receipt_payload["result"]["rolled_count"], 1)
            self.assertEqual(
                receipt_payload["result"]["rolled"][0]["segment_id"],
                segment_id,
            )

    def test_scribe_final_transaction_guard_rolls_back_step_and_segment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            session_id = "scribe-final-guard-rollback"
            append_scroll_event(
                root,
                session_id=session_id,
                event_type="message",
                role="user",
                content="A lost lease must roll back every Scribe segment effect.",
            )
            owner = "scribe-final-guard-owner"
            expires_at = (
                dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)
            ).isoformat()
            conn = connect(root)
            try:
                conn.execute("DELETE FROM queue_jobs")
                job_id = enqueue_job(
                    conn,
                    role="scribe",
                    job_type="scroll_event_ingested",
                    priority=1,
                    payload={"session_id": session_id},
                )
                conn.execute(
                    """
                    UPDATE queue_jobs
                    SET status = 'running', lease_owner = ?, lease_expires_at = ?,
                        heartbeat_at = ?, started_at = ?
                    WHERE id = ?
                    """,
                    (owner, expires_at, expires_at, expires_at, job_id),
                )
                conn.commit()
            finally:
                conn.close()

            lease = worker_module._JobLease(root, job_id, owner, 300)
            guard_calls = 0

            def fail_final_guard(transaction_conn: sqlite3.Connection) -> None:
                nonlocal guard_calls
                guard_calls += 1
                lease.assert_owned(transaction_conn)
                if guard_calls == 2:
                    raise RuntimeError("forced final Scribe guard failure")

            def record_step(
                transaction_conn: sqlite3.Connection,
                step_result: dict[str, object],
            ) -> None:
                worker_module._record_scribe_step_committed(
                    transaction_conn,
                    lease,
                    session_id=session_id,
                    start_seq=1,
                    end_seq=1,
                    batch_number=1,
                    result=step_result,
                )

            with self.assertRaisesRegex(RuntimeError, "forced final Scribe guard"):
                roll_scroll_segment(
                    root,
                    session_id=session_id,
                    start_seq=1,
                    end_seq=1,
                    transaction_guard=fail_final_guard,
                    transaction_effect=record_step,
                )

            conn = connect_existing(root)
            try:
                counts = {
                    "segments": int(
                        conn.execute("SELECT count(*) AS n FROM scroll_segments").fetchone()["n"]
                    ),
                    "cards": int(
                        conn.execute(
                            "SELECT count(*) AS n FROM cards WHERE card_type = 'scroll_segment'"
                        ).fetchone()["n"]
                    ),
                    "roll_audits": int(
                        conn.execute(
                            "SELECT count(*) AS n FROM audit_events WHERE action = 'roll_scroll_segment'"
                        ).fetchone()["n"]
                    ),
                    "step_receipts": int(
                        conn.execute(
                            """
                            SELECT count(*) AS n FROM audit_events
                            WHERE action = 'worker_scribe_segment_step_committed'
                              AND target_id = ?
                            """,
                            (job_id,),
                        ).fetchone()["n"]
                    ),
                    "child_jobs": int(
                        conn.execute(
                            "SELECT count(*) AS n FROM queue_jobs WHERE role IN ('librarian', 'archivist')"
                        ).fetchone()["n"]
                    ),
                }
            finally:
                conn.close()
            self.assertEqual(
                counts,
                {
                    "segments": 0,
                    "cards": 0,
                    "roll_audits": 0,
                    "step_receipts": 0,
                    "child_jobs": 0,
                },
            )

    def test_reclaimed_scribe_attempt_cannot_overlap_segment_effect_transaction(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            config = default_config()
            config["capture"]["roll_segments_every_events"] = 1
            write_config(root, config)
            session_id = "scribe-overlapping-reclaim"
            append_scroll_event(
                root,
                session_id=session_id,
                event_type="message",
                role="user",
                content="Only the live Scribe lease may commit this segment.",
            )
            conn = connect(root)
            try:
                conn.execute("DELETE FROM queue_jobs")
                job_id = enqueue_job(
                    conn,
                    role="scribe",
                    job_type="scroll_event_ingested",
                    priority=1,
                    payload={"session_id": session_id},
                )
                conn.commit()
            finally:
                conn.close()

            original_roll = worker_module.roll_scroll_segment
            both_attempts_ready = threading.Barrier(2)
            first_attempt_ready = threading.Event()
            results: dict[str, dict] = {}

            def collide_before_store(*args: object, **kwargs: object) -> dict:
                first_attempt_ready.set()
                both_attempts_ready.wait(timeout=5.0)
                return original_roll(*args, **kwargs)

            def run_worker(name: str) -> None:
                results[name] = run_worker_pass(
                    root,
                    roles=["scribe"],
                    limit=1,
                    maintenance=False,
                )

            with patch.object(
                worker_module,
                "roll_scroll_segment",
                side_effect=collide_before_store,
            ):
                old_worker = threading.Thread(
                    target=run_worker,
                    args=("old",),
                    daemon=True,
                )
                old_worker.start()
                self.assertTrue(first_attempt_ready.wait(5.0))
                conn = connect(root)
                try:
                    expired = conn.execute(
                        """
                        UPDATE queue_jobs
                        SET lease_expires_at = '2000-01-01T00:00:00+00:00',
                            heartbeat_at = '2000-01-01T00:00:00+00:00'
                        WHERE id = ? AND status = 'running'
                        """,
                        (job_id,),
                    )
                    conn.commit()
                    self.assertEqual(expired.rowcount, 1)
                finally:
                    conn.close()
                new_worker = threading.Thread(
                    target=run_worker,
                    args=("new",),
                    daemon=True,
                )
                new_worker.start()
                old_worker.join(10.0)
                new_worker.join(10.0)

            self.assertFalse(old_worker.is_alive())
            self.assertFalse(new_worker.is_alive())
            self.assertFalse(results["old"]["ok"], results)
            self.assertIn("worker lease lost", results["old"]["processed"][0]["error"])
            self.assertTrue(results["new"]["ok"], results)

            conn = connect_existing(root)
            try:
                job = conn.execute(
                    "SELECT status, attempt_count FROM queue_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()
                counts = {
                    "segments": int(
                        conn.execute(
                            "SELECT count(*) AS n FROM scroll_segments WHERE session_id = ?",
                            (session_id,),
                        ).fetchone()["n"]
                    ),
                    "cards": int(
                        conn.execute(
                            "SELECT count(*) AS n FROM cards WHERE card_type = 'scroll_segment'"
                        ).fetchone()["n"]
                    ),
                    "roll_audits": int(
                        conn.execute(
                            "SELECT count(*) AS n FROM audit_events WHERE action = 'roll_scroll_segment'"
                        ).fetchone()["n"]
                    ),
                    "intents": int(
                        conn.execute(
                            """
                            SELECT count(*) AS n FROM audit_events
                            WHERE action = 'worker_scribe_segment_step_intent'
                              AND target_id = ?
                            """,
                            (job_id,),
                        ).fetchone()["n"]
                    ),
                    "receipts": int(
                        conn.execute(
                            """
                            SELECT count(*) AS n FROM audit_events
                            WHERE action = 'worker_job_effect_committed'
                              AND target_id = ?
                            """,
                            (job_id,),
                        ).fetchone()["n"]
                    ),
                }
            finally:
                conn.close()
            self.assertEqual(job["status"], "succeeded")
            self.assertEqual(job["attempt_count"], 2)
            self.assertEqual(
                counts,
                {
                    "segments": 1,
                    "cards": 1,
                    "roll_audits": 1,
                    "intents": 1,
                    "receipts": 1,
                },
            )

    def test_forced_expiry_and_durable_replay_are_fenced_for_every_job_type(self) -> None:
        job_types = (
            "scroll_event_ingested",
            "review_card_placement",
            "verify_book_integrity",
            "verify_segment_integrity",
            "sync_card_sidecar",
            "review_mempalace_import",
        )

        def prepare_case(root: Path, job_type: str) -> dict[str, object]:
            init_db(root)
            if job_type == "scroll_event_ingested":
                config = default_config()
                config["capture"]["roll_segments_every_events"] = 1
                write_config(root, config)
                session_id = "forced-expiry-scroll"
                append_scroll_event(
                    root,
                    session_id=session_id,
                    event_type="message",
                    role="user",
                    content="Forced expiry Scroll evidence.",
                )
                role = "scribe"
                payload = {"session_id": session_id}
                marker_sql = "SELECT count(*) AS n FROM scroll_segments WHERE session_id = ?"
                marker_params = (session_id,)
            elif job_type == "review_card_placement":
                conn = connect(root)
                try:
                    card_id = create_card(
                        conn,
                        root=root,
                        card_type="decision",
                        title="Forced expiry placement",
                        summary="Use fenced placement for durable worker effects.",
                        source_refs=[],
                        topics=["fencing"],
                    )
                    conn.commit()
                finally:
                    conn.close()
                role = "librarian"
                payload = {"card_id": card_id}
                marker_sql = (
                    "SELECT count(*) AS n FROM audit_events "
                    "WHERE action = 'librarian_review_card' AND target_id = ?"
                )
                marker_params = (card_id,)
            elif job_type == "verify_book_integrity":
                source = root.parent / "forced-expiry-book.txt"
                source.write_text("Durable book integrity evidence.\n", encoding="utf-8")
                ingested = ingest_file(root, path=source)
                book_id = str(ingested["book_id"])
                conn = connect(root)
                try:
                    expected_hash = str(
                        conn.execute(
                            "SELECT content_hash FROM books WHERE id = ?",
                            (book_id,),
                        ).fetchone()["content_hash"]
                    )
                finally:
                    conn.close()
                role = "archivist"
                payload = {"book_id": book_id, "content_hash": expected_hash}
                marker_sql = (
                    "SELECT count(*) AS n FROM audit_events "
                    "WHERE action = 'archivist_verify_book' AND target_id = ?"
                )
                marker_params = (book_id,)
            elif job_type == "verify_segment_integrity":
                session_id = "forced-expiry-segment"
                append_scroll_event(
                    root,
                    session_id=session_id,
                    event_type="message",
                    role="user",
                    content="Durable segment integrity evidence.",
                )
                segment = roll_scroll_segment(
                    root,
                    session_id=session_id,
                    start_seq=1,
                    end_seq=1,
                )
                segment_id = str(segment["segment_id"])
                conn = connect(root)
                try:
                    expected_hash = str(
                        conn.execute(
                            "SELECT segment_hash FROM scroll_segments WHERE id = ?",
                            (segment_id,),
                        ).fetchone()["segment_hash"]
                    )
                finally:
                    conn.close()
                role = "archivist"
                payload = {"segment_id": segment_id, "segment_hash": expected_hash}
                marker_sql = (
                    "SELECT count(*) AS n FROM audit_events "
                    "WHERE action = 'archivist_verify_segment' AND target_id = ?"
                )
                marker_params = (segment_id,)
            elif job_type == "sync_card_sidecar":
                conn = connect(root)
                try:
                    card_id = create_card(
                        conn,
                        root=root,
                        card_type="note",
                        title="Forced expiry sidecar",
                        summary="Sidecar writes converge across durable replay.",
                        source_refs=[],
                    )
                    conn.commit()
                finally:
                    conn.close()
                role = "archivist"
                payload = {"card_id": card_id}
                marker_sql = (
                    "SELECT count(*) AS n FROM audit_events "
                    "WHERE action = 'card_sidecar_synced' AND target_id = ?"
                )
                marker_params = (card_id,)
            else:
                import_id = "forced-expiry-import"
                conn = connect(root)
                try:
                    card_id = create_card(
                        conn,
                        root=root,
                        card_type="mempalace_drawer",
                        title="Forced expiry MemPalace card",
                        summary="Graph-placed imported memory.",
                        source_refs=[],
                        metadata={"import_id": import_id},
                    )
                    card_node = upsert_graph_node(
                        conn,
                        kind="card",
                        label="Forced expiry MemPalace card",
                        card_id=card_id,
                    )
                    term_node = upsert_graph_node(conn, kind="term", label="mempalace")
                    add_graph_edge(
                        conn,
                        source_node_id=card_node,
                        relation="mentions",
                        target_node_id=term_node,
                        weight=0.5,
                        confidence=0.8,
                        source_refs=[{"card_id": card_id}],
                    )
                    conn.commit()
                finally:
                    conn.close()
                role = "archivist"
                payload = {"import_id": import_id}
                marker_sql = (
                    "SELECT count(*) AS n FROM audit_events "
                    "WHERE action = 'reconcile_graph_placed_card' AND target_id = ?"
                )
                marker_params = (card_id,)

            conn = connect(root)
            try:
                conn.execute("DELETE FROM queue_jobs")
                job_id = enqueue_job(
                    conn,
                    role=role,
                    job_type=job_type,
                    priority=1,
                    payload=payload,
                )
                conn.commit()
            finally:
                conn.close()
            return {
                "role": role,
                "job_id": job_id,
                "marker_sql": marker_sql,
                "marker_params": marker_params,
            }

        def durable_counts(root: Path, case: dict[str, object]) -> tuple[int, int]:
            conn = connect_existing(root)
            try:
                receipt_count = int(
                    conn.execute(
                        """
                        SELECT count(*) AS n
                        FROM audit_events
                        WHERE action = 'worker_job_effect_committed'
                          AND target_type = 'queue_job'
                          AND target_id = ?
                        """,
                        (case["job_id"],),
                    ).fetchone()["n"]
                )
                marker_count = int(
                    conn.execute(
                        str(case["marker_sql"]),
                        tuple(case["marker_params"]),
                    ).fetchone()["n"]
                )
                return receipt_count, marker_count
            finally:
                conn.close()

        for job_type in job_types:
            with self.subTest(job_type=job_type), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                case = prepare_case(root, job_type)
                before_receipts, before_markers = durable_counts(root, case)
                self.assertEqual(before_receipts, 0)
                conn = connect_existing(root)
                try:
                    schema_before = int(conn.execute("PRAGMA user_version").fetchone()[0])
                    tables_before = {
                        str(row["name"])
                        for row in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type = 'table'"
                        )
                    }
                finally:
                    conn.close()

                entered_processor = threading.Event()
                release_processor = threading.Event()
                worker_result: dict[str, object] = {}
                original_process_job = worker_module._process_job

                def pause_after_claim(
                    worker_root: Path,
                    job: dict,
                    **kwargs: object,
                ) -> dict:
                    entered_processor.set()
                    if not release_processor.wait(5.0):
                        raise TimeoutError("test did not release claimed worker")
                    return original_process_job(worker_root, job, **kwargs)

                def run_expiring_worker() -> None:
                    worker_result["result"] = run_worker_pass(
                        root,
                        roles=[str(case["role"])],
                        limit=1,
                        maintenance=False,
                    )

                with patch.object(
                    worker_module,
                    "_process_job",
                    side_effect=pause_after_claim,
                ):
                    thread = threading.Thread(target=run_expiring_worker, daemon=True)
                    thread.start()
                    self.assertTrue(entered_processor.wait(5.0), job_type)
                    conn = connect(root)
                    try:
                        cursor = conn.execute(
                            """
                            UPDATE queue_jobs
                            SET lease_expires_at = '2000-01-01T00:00:00+00:00',
                                heartbeat_at = '2000-01-01T00:00:00+00:00'
                            WHERE id = ? AND status = 'running'
                            """,
                            (case["job_id"],),
                        )
                        conn.commit()
                        self.assertEqual(cursor.rowcount, 1)
                    finally:
                        conn.close()
                    release_processor.set()
                    thread.join(10.0)
                    self.assertFalse(thread.is_alive(), job_type)

                expired_result = worker_result["result"]
                self.assertFalse(expired_result["ok"], expired_result)
                self.assertIn(
                    "worker lease lost",
                    expired_result["processed"][0]["error"],
                )
                self.assertEqual(
                    durable_counts(root, case),
                    (0, before_markers),
                    expired_result,
                )

                recovered = run_worker_pass(
                    root,
                    roles=[str(case["role"])],
                    limit=1,
                    maintenance=False,
                )
                self.assertTrue(recovered["ok"], recovered)
                self.assertEqual(recovered["reclaimed_expired_jobs"], 1)
                self.assertEqual(
                    durable_counts(root, case),
                    (1, before_markers + 1),
                    recovered,
                )

                # Simulate a crash after the fenced effect transaction committed
                # but before the queue row reached its terminal state.
                conn = connect(root)
                try:
                    conn.execute("DELETE FROM queue_jobs WHERE id != ?", (case["job_id"],))
                    conn.execute(
                        """
                        UPDATE queue_jobs
                        SET status = 'pending', started_at = NULL, finished_at = NULL,
                            lease_owner = NULL, lease_expires_at = NULL,
                            heartbeat_at = NULL, error_json = NULL
                        WHERE id = ?
                        """,
                        (case["job_id"],),
                    )
                    conn.commit()
                finally:
                    conn.close()

                replayed = run_worker_pass(
                    root,
                    roles=[str(case["role"])],
                    limit=1,
                    maintenance=False,
                )
                self.assertTrue(replayed["ok"], replayed)
                self.assertTrue(
                    replayed["processed"][0]["result"]["idempotent_replay"],
                    replayed,
                )
                self.assertEqual(
                    durable_counts(root, case),
                    (1, before_markers + 1),
                    replayed,
                )

                conn = connect_existing(root)
                try:
                    self.assertEqual(
                        int(conn.execute("PRAGMA user_version").fetchone()[0]),
                        schema_before,
                    )
                    tables_after = {
                        str(row["name"])
                        for row in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type = 'table'"
                        )
                    }
                finally:
                    conn.close()
                self.assertEqual(tables_after, tables_before)
                self.assertIn("audit_events", tables_after)

    def test_prune_memory_requires_topic_or_explicit_global_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            conn.row_factory = sqlite3.Row
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="Global Prune Candidate",
                    summary="A low salience global prune candidate.",
                    source_refs=[],
                    topics=["Global"],
                    salience=0.1,
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [card_id])

            with self.assertRaisesRegex(ValueError, "requires a topic"):
                prune_memory(root, action="archive")

            result = prune_memory(root, action="archive", allow_global=True)
            self.assertEqual(result["card_ids"], [card_id])

    def test_prune_memory_treats_metacharacters_as_literal_substrings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_ids: dict[str, list[str]] = {}
                for marker, label in (("%", "percent"), ("_", "underscore"), ("\\", "escape")):
                    card_ids[marker] = [
                        create_card(
                            conn,
                            root=root,
                            card_type="note",
                            title=f"Literal title {marker} marker",
                            summary=f"Only the {label} title Card contains its marker.",
                            source_refs=[],
                            topics=[f"Literal {label} title"],
                        ),
                        create_card(
                            conn,
                            root=root,
                            card_type="note",
                            title=f"Literal {label} summary Card",
                            summary=f"Literal summary {marker} marker",
                            source_refs=[],
                            topics=[f"Literal {label} summary"],
                        ),
                        create_card(
                            conn,
                            root=root,
                            card_type="note",
                            title=f"Literal {label} topic Card",
                            summary=f"Only the {label} topics Card contains its marker.",
                            source_refs=[],
                            topics=[f"Literal topic {marker} marker"],
                        ),
                    ]
                plain_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="Literal prune marker plain",
                    summary="This Card has no literal metacharacter marker.",
                    source_refs=[],
                    topics=["Literal plain"],
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(
                root,
                [plain_id, *(card_id for marker_ids in card_ids.values() for card_id in marker_ids)],
            )

            for marker, expected_ids in card_ids.items():
                with self.subTest(marker=marker):
                    result = prune_memory(root, topic=f"  {marker}  ", dry_run=True)
                    self.assertEqual(result["matching_mode"], "literal_substring")
                    self.assertEqual(result["normalized_topic"], marker)
                    self.assertEqual(set(result["card_ids"]), set(expected_ids))

            applied = prune_memory(root, topic="%", action="archive")
            self.assertEqual(set(applied["card_ids"]), set(card_ids["%"]), applied)
            conn = connect_existing(root)
            try:
                statuses = {
                    str(row["id"]): str(row["status"])
                    for row in conn.execute("SELECT id, status FROM cards").fetchall()
                }
            finally:
                conn.close()
            for card_id in card_ids["%"]:
                self.assertEqual(statuses[card_id], "archived")
            for card_id in [*card_ids["_"], *card_ids["\\"]]:
                self.assertEqual(statuses[card_id], "pending_librarian_review")
            self.assertEqual(statuses[plain_id], "pending_librarian_review")

    def test_prune_memory_matches_decoded_topic_values_not_json_escapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            topic_values = {
                "café": "unicode",
                'quote"here': "quote",
                "line\nhere": "newline",
                "back\\slash": "backslash",
            }
            conn = connect(root)
            try:
                card_ids = {
                    topic: create_card(
                        conn,
                        root=root,
                        card_type="note",
                        title=f"Decoded topic {label} Card",
                        summary=f"Only the decoded {label} topic carries its value.",
                        source_refs=[],
                        topics=[topic],
                    )
                    for topic, label in topic_values.items()
                }
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, list(card_ids.values()))

            for topic, card_id in card_ids.items():
                with self.subTest(topic=repr(topic)):
                    result = prune_memory(root, topic=topic, dry_run=True)
                    self.assertEqual(result["card_ids"], [card_id])

            self.assertEqual(
                prune_memory(root, topic="\\", dry_run=True)["card_ids"],
                [card_ids["back\\slash"]],
            )
            self.assertEqual(prune_memory(root, topic="\\u", dry_run=True)["card_ids"], [])
            self.assertEqual(prune_memory(root, topic="\\n", dry_run=True)["card_ids"], [])

    def test_prune_memory_rejects_blank_topics_and_out_of_range_limits(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            for blank in ("", "   ", "\t\r\n"):
                with self.subTest(topic=repr(blank)):
                    with self.assertRaisesRegex(ValueError, "must not be empty or whitespace-only"):
                        prune_memory(root, topic=blank, allow_global=True)
            with self.assertRaisesRegex(ValueError, "NUL"):
                prune_memory(root, topic="\x00")
            for invalid_limit in (0, worker_module.MAX_PRUNE_MEMORY_LIMIT + 1, True):
                with self.subTest(limit=invalid_limit):
                    with self.assertRaisesRegex(ValueError, "prune-memory limit"):
                        prune_memory(root, topic="literal", limit=invalid_limit)
            self.assertFalse(root.exists())

    def test_prune_memory_rejects_unclean_prestate_without_mutating_cards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="Unclean Preflight Prune Marker",
                    summary="The pending sidecar makes this preflight incomplete.",
                    source_refs=[],
                )
                before = dict(
                    conn.execute(
                        "SELECT status, metadata_json, updated_at FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()
                )
                conn.commit()
            finally:
                conn.close()

            with self.assertRaisesRegex(ValueError, "semantic integrity is not clean"):
                prune_memory(root, topic="Unclean Preflight", action="forget")

            conn = connect_existing(root)
            try:
                after = dict(
                    conn.execute(
                        "SELECT status, metadata_json, updated_at FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()
                )
            finally:
                conn.close()
            self.assertEqual(after, before)

    def test_prune_memory_protects_project_state_conflicts_and_global_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="prune-protected-session",
                agent_id="prune-protected-agent",
                project_id="prune-protected-project",
                objective="Protected Authority Predecessor Marker",
            )
            current_state = record_project_state(
                root,
                session_id="prune-protected-session",
                agent_id="prune-protected-agent",
                project_id="prune-protected-project",
                objective="Protected Authority Current Marker",
            )
            conn = connect(root)
            try:
                conflict_a = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Protected Live Conflict Alpha Marker",
                    summary="Opposing live conflict member alpha.",
                    source_refs=[],
                    session_id="conflict-session",
                )
                conflict_b = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Protected Live Conflict Beta Marker",
                    summary="Opposing live conflict member beta.",
                    source_refs=[],
                    session_id="conflict-session",
                )
                ordinary = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="Ordinary Global Prune Marker",
                    summary="Eligible ordinary Card.",
                    source_refs=[],
                )
                supersession_predecessor = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Protected Ordinary Supersession Predecessor Marker",
                    summary="Historical ordinary authority predecessor.",
                    source_refs=[],
                    session_id="ordinary-authority-session",
                )
                supersession_successor = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Protected Ordinary Supersession Successor Marker",
                    summary="Current ordinary authority successor.",
                    source_refs=[],
                    session_id="ordinary-authority-session",
                )
                group = "conflict_prune_protection"
                conn.execute(
                    "UPDATE cards SET conflict_group = ? WHERE id IN (?, ?)",
                    (group, conflict_a, conflict_b),
                )
                conn.execute(
                    """
                    UPDATE cards
                    SET status = 'superseded', superseded_by_card_id = ?
                    WHERE id = ?
                    """,
                    (supersession_successor, supersession_predecessor),
                )
                conn.execute(
                    "UPDATE cards SET supersedes_card_id = ? WHERE id = ?",
                    (supersession_predecessor, supersession_successor),
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(
                root,
                [
                    conflict_a,
                    conflict_b,
                    ordinary,
                    supersession_predecessor,
                    supersession_successor,
                ],
            )
            self.assertTrue(semantic_integrity_report(root)["ok"])
            protected_card_ids = [
                state["card_id"],
                current_state["card_id"],
                conflict_a,
                conflict_b,
                supersession_predecessor,
                supersession_successor,
            ]
            conn = connect_existing(root)
            try:
                protected_before = {
                    str(row["id"]): dict(row)
                    for row in conn.execute(
                        f"""
                        SELECT id, status, conflict_group, supersedes_card_id, superseded_by_card_id
                        FROM cards
                        WHERE id IN ({','.join('?' for _ in protected_card_ids)})
                        """,
                        protected_card_ids,
                    ).fetchall()
                }
            finally:
                conn.close()

            state_dry_run = prune_memory(root, topic="Protected Authority Current Marker", dry_run=True)
            self.assertTrue(state_dry_run["blocked"])
            self.assertIn(current_state["card_id"], state_dry_run["protected_card_ids"])
            with self.assertRaisesRegex(ValueError, "authority-protected Cards"):
                prune_memory(root, topic="Protected Authority Current Marker", action="forget")
            with self.assertRaisesRegex(ValueError, "authority-protected Cards"):
                prune_memory(root, topic="Protected Live Conflict Alpha Marker", action="archive")
            with self.assertRaisesRegex(ValueError, "authority-protected Cards"):
                prune_memory(root, topic="Protected Ordinary Supersession Successor Marker", action="archive")
            with self.assertRaisesRegex(ValueError, "authority-protected Cards"):
                prune_memory(root, topic="Protected Ordinary Supersession Predecessor Marker", action="archive")

            global_result = prune_memory(root, action="archive", allow_global=True)
            self.assertEqual(global_result["matching_mode"], "explicit_global")
            self.assertGreaterEqual(global_result["protected_card_count"], 6)
            self.assertEqual(global_result["card_ids"], [ordinary])
            conn = connect_existing(root)
            try:
                rows = {
                    str(row["id"]): dict(row)
                    for row in conn.execute(
                        """
                        SELECT id, status, conflict_group, supersedes_card_id, superseded_by_card_id
                        FROM cards
                        WHERE id IN (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            state["card_id"],
                            current_state["card_id"],
                            conflict_a,
                            conflict_b,
                            ordinary,
                            supersession_predecessor,
                            supersession_successor,
                        ),
                    ).fetchall()
                }
            finally:
                conn.close()
            for card_id in protected_card_ids:
                self.assertEqual(rows[card_id], protected_before[card_id])
            self.assertEqual(rows[ordinary]["status"], "archived")
            self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_prune_memory_compensates_postflight_and_sidecar_sync_failures(self) -> None:
        for failure_mode in (
            "postflight",
            "postflight_exception",
            "sidecar_sync",
            "sidecar_sync_exception",
            "rollback_sync_failure",
        ):
            with self.subTest(failure_mode=failure_mode), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                init_db(root)
                conn = connect(root)
                try:
                    card_id = create_card(
                        conn,
                        root=root,
                        card_type="note",
                        title=f"Compensating Prune {failure_mode}",
                        summary="The original row and sidecar must survive a failed prune.",
                        source_refs=[],
                    )
                    conn.commit()
                finally:
                    conn.close()
                sync_card_sidecars_after_commit(root, [card_id])
                conn = connect_existing(root)
                try:
                    original = dict(
                        conn.execute(
                            "SELECT status, metadata_json, updated_at, location_uri FROM cards WHERE id = ?",
                            (card_id,),
                        ).fetchone()
                    )
                finally:
                    conn.close()

                if failure_mode.startswith("postflight"):
                    real_report = worker_module.semantic_integrity_report
                    report_calls = 0

                    def report_with_failed_postflight(*args, **kwargs):
                        nonlocal report_calls
                        report_calls += 1
                        if report_calls == 3:
                            if failure_mode == "postflight_exception":
                                raise RuntimeError("simulated postflight exception")
                            return {"ok": False, "failing": {"simulated_postflight": 1}}
                        return real_report(*args, **kwargs)

                    failure_patch = patch.object(
                        worker_module,
                        "semantic_integrity_report",
                        side_effect=report_with_failed_postflight,
                    )
                else:
                    real_sync = worker_module.sync_card_sidecars_after_commit
                    sync_calls = 0

                    def sync_with_first_failure(*args, **kwargs):
                        nonlocal sync_calls
                        sync_calls += 1
                        if failure_mode == "rollback_sync_failure" and sync_calls <= 2:
                            return {"ok": False, "synced": 0, "deferred": 1, "failed": 1, "failures": []}
                        if sync_calls == 1:
                            if failure_mode == "sidecar_sync_exception":
                                raise RuntimeError("simulated sidecar sync exception")
                            return {"ok": False, "synced": 0, "deferred": 1, "failed": 1, "failures": []}
                        return real_sync(*args, **kwargs)

                    failure_patch = patch.object(
                        worker_module,
                        "sync_card_sidecars_after_commit",
                        side_effect=sync_with_first_failure,
                    )

                expected_message = (
                    "restored, but rollback verification did not complete"
                    if failure_mode == "rollback_sync_failure"
                    else "Card mutations were rolled back"
                )
                with failure_patch, self.assertRaisesRegex(RuntimeError, expected_message):
                    prune_memory(root, topic=failure_mode, action="forget")

                conn = connect_existing(root)
                try:
                    restored = dict(
                        conn.execute(
                            "SELECT status, metadata_json, updated_at, location_uri FROM cards WHERE id = ?",
                            (card_id,),
                        ).fetchone()
                    )
                finally:
                    conn.close()
                self.assertEqual(restored, original)
                self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_prune_memory_compensation_does_not_overwrite_an_intervening_writer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="Prune Compensation CAS Marker",
                    summary="An intervening writer must win over compensation.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [card_id])

            real_report = worker_module.semantic_integrity_report
            report_calls = 0

            def report_with_intervening_write(*args, **kwargs):
                nonlocal report_calls
                report_calls += 1
                if report_calls == 3:
                    writer = connect(root)
                    try:
                        row = writer.execute(
                            "SELECT metadata_json FROM cards WHERE id = ?",
                            (card_id,),
                        ).fetchone()
                        metadata = json.loads(str(row["metadata_json"]))
                        metadata["intervening_writer"] = "preserve-me"
                        writer.execute(
                            "UPDATE cards SET metadata_json = ?, updated_at = ? WHERE id = ?",
                            (json.dumps(metadata, sort_keys=True), "2999-01-01T00:00:00Z", card_id),
                        )
                        writer.commit()
                    finally:
                        writer.close()
                    return {"ok": False, "failing": {"simulated_postflight": 1}}
                return real_report(*args, **kwargs)

            with (
                patch.object(
                    worker_module,
                    "semantic_integrity_report",
                    side_effect=report_with_intervening_write,
                ),
                self.assertRaisesRegex(RuntimeError, "were not rolled back because their committed state changed"),
            ):
                prune_memory(root, topic="CAS Marker", action="forget")

            conn = connect_existing(root)
            try:
                row = conn.execute(
                    "SELECT status, metadata_json, updated_at FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(row["status"], "pruned")
            self.assertEqual(row["updated_at"], "2999-01-01T00:00:00Z")
            self.assertEqual(json.loads(str(row["metadata_json"]))["intervening_writer"], "preserve-me")

    def test_route_decay_respects_minimum_interval(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            append_scroll_event(root, session_id="decay-interval", event_type="message", role="user", content="Aurora route decay interval evidence.")
            segment = roll_scroll_segment(root, session_id="decay-interval", start_seq=1, end_seq=1)
            run_worker_pass(root, limit=10, maintenance=False)

            first = decay_graph_routes(root, limit=20, prune_threshold=99)
            second = decay_graph_routes(root, limit=20, prune_threshold=99)

            self.assertGreaterEqual(first["decayed"], 1)
            self.assertEqual(second["decayed"], 0)
            conn = connect_existing(root)
            try:
                card = conn.execute("SELECT recall_count FROM cards WHERE id = ?", (segment["card_id"],)).fetchone()
                edge = conn.execute("SELECT last_decay_at FROM graph_edges WHERE last_decay_at IS NOT NULL LIMIT 1").fetchone()
            finally:
                conn.close()
            self.assertEqual(card["recall_count"], 0)
            self.assertIsNotNone(edge)

    def test_hidden_project_activity_does_not_reset_other_project_decay_schedule(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            alpha_session = "alpha-session"
            beta_session = "beta-session"
            content = "local-agent lattice route calibration marker"
            append_scroll_event(
                root,
                session_id=alpha_session,
                event_type="message",
                role="user",
                content=content,
                metadata={"project_id": "alpha", "visibility_scope": "project"},
            )
            old_time = (dt.datetime.now(dt.UTC) - dt.timedelta(hours=4)).replace(microsecond=0).isoformat()
            now_time = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE graph_edge_sources SET last_decay_at = ?, decay_count = 0 WHERE source_ref_json LIKE ?",
                    (old_time, f"%{alpha_session}%"),
                )
                conn.commit()
            finally:
                conn.close()

            append_scroll_event(
                root,
                session_id=beta_session,
                event_type="message",
                role="user",
                content=content,
                metadata={"project_id": "beta", "visibility_scope": "project"},
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE graph_edge_sources SET last_decay_at = ?, decay_count = 0 WHERE source_ref_json LIKE ?",
                    (now_time, f"%{beta_session}%"),
                )
                conn.commit()
            finally:
                conn.close()

            result = decay_graph_routes(root, limit=100, prune_threshold=99)

            self.assertGreater(result["decayed"], 0)
            conn = connect_existing(root)
            try:
                alpha_decay = conn.execute(
                    "SELECT max(decay_count) AS n FROM graph_edge_sources WHERE source_ref_json LIKE ?",
                    (f"%{alpha_session}%",),
                ).fetchone()["n"]
                beta_decay = conn.execute(
                    "SELECT max(decay_count) AS n FROM graph_edge_sources WHERE source_ref_json LIKE ?",
                    (f"%{beta_session}%",),
                ).fetchone()["n"]
            finally:
                conn.close()
            self.assertGreaterEqual(int(alpha_decay or 0), 1)
            self.assertEqual(int(beta_decay or 0), 0)

    def test_route_decay_uses_fair_per_domain_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            old_time = (dt.datetime.now(dt.UTC) - dt.timedelta(hours=4)).replace(microsecond=0).isoformat()
            for index in range(5):
                append_scroll_event(
                    root,
                    session_id=f"beta-backlog-{index}",
                    event_type="message",
                    role="user",
                    content=f"shared fairness term beta backlog {index}",
                    metadata={"project_id": "beta", "visibility_scope": "project"},
                )
            append_scroll_event(
                root,
                session_id="alpha-fairness",
                event_type="message",
                role="user",
                content="shared fairness term alpha should progress",
                metadata={"project_id": "alpha", "visibility_scope": "project"},
            )
            conn = connect(root)
            try:
                conn.execute("UPDATE graph_edge_sources SET last_decay_at = ?, decay_count = 0", (old_time,))
                conn.commit()
            finally:
                conn.close()

            result = decay_graph_routes(root, limit=2, prune_threshold=99)

            self.assertGreaterEqual(result["domains"], 2)
            self.assertLessEqual(result["processed"], 2)
            self.assertEqual(result["processed"], 2)
            conn = connect_existing(root)
            try:
                alpha_decay = conn.execute(
                    "SELECT max(decay_count) AS n FROM graph_edge_sources WHERE source_ref_json LIKE '%\"project_id\":\"alpha\"%'"
                ).fetchone()["n"]
                beta_decay = conn.execute(
                    "SELECT max(decay_count) AS n FROM graph_edge_sources WHERE source_ref_json LIKE '%\"project_id\":\"beta\"%'"
                ).fetchone()["n"]
            finally:
                conn.close()
            self.assertGreaterEqual(int(alpha_decay or 0), 1)
            self.assertGreaterEqual(int(beta_decay or 0), 1)

    def test_route_decay_resolves_card_source_refs_to_project_domains(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            old_time = (dt.datetime.now(dt.UTC) - dt.timedelta(hours=4)).replace(microsecond=0).isoformat()
            conn = connect(root)
            try:
                shared_term = upsert_graph_node(conn, kind="term", label="card-origin-fairness")
                for index in range(20):
                    beta_card = create_card(
                        conn,
                        root=root,
                        card_type="note",
                        title=f"Beta card source {index}",
                        summary=f"Beta card source backlog {index}",
                        source_refs=[],
                        visibility_scope="project",
                        session_id="beta-card-session",
                        project_id="beta-card-project",
                    )
                    beta_node = upsert_graph_node(conn, kind="card", label=f"Beta card source {index}", card_id=beta_card)
                    add_graph_edge(
                        conn,
                        source_node_id=shared_term,
                        relation="mentions",
                        target_node_id=beta_node,
                        weight=0.4,
                        confidence=0.8,
                        source_refs=[{"card_id": beta_card}],
                    )
                alpha_card = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="Alpha card source",
                    summary="Alpha card source must still decay under card-only provenance.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="alpha-card-session",
                    project_id="alpha-card-project",
                )
                alpha_node = upsert_graph_node(conn, kind="card", label="Alpha card source", card_id=alpha_card)
                add_graph_edge(
                    conn,
                    source_node_id=shared_term,
                    relation="mentions",
                    target_node_id=alpha_node,
                    weight=0.4,
                    confidence=0.8,
                    source_refs=[{"card_id": alpha_card}],
                )
                conn.execute("UPDATE graph_edge_sources SET last_decay_at = ?, decay_count = 0", (old_time,))
                conn.commit()
            finally:
                conn.close()

            result = decay_graph_routes(root, limit=2, prune_threshold=99)

            self.assertGreaterEqual(result["domains"], 2)
            self.assertLessEqual(result["processed"], 2)
            conn = connect_existing(root)
            try:
                alpha_decay = conn.execute(
                    """
                    SELECT max(ges.decay_count) AS n
                    FROM graph_edge_sources ges
                    JOIN cards c ON ges.source_ref_json LIKE '%' || c.id || '%'
                    WHERE c.project_id = 'alpha-card-project'
                    """
                ).fetchone()["n"]
                beta_decay = conn.execute(
                    """
                    SELECT max(ges.decay_count) AS n
                    FROM graph_edge_sources ges
                    JOIN cards c ON ges.source_ref_json LIKE '%' || c.id || '%'
                    WHERE c.project_id = 'beta-card-project'
                    """
                ).fetchone()["n"]
            finally:
                conn.close()
            self.assertGreaterEqual(int(alpha_decay or 0), 1)
            self.assertGreaterEqual(int(beta_decay or 0), 1)

    def test_route_decay_limit_is_global_not_per_domain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            old_time = (dt.datetime.now(dt.UTC) - dt.timedelta(hours=4)).replace(microsecond=0).isoformat()
            for index in range(7):
                append_scroll_event(
                    root,
                    session_id=f"global-cap-{index}",
                    event_type="message",
                    role="user",
                    content=f"global decay cap evidence {index}",
                    metadata={"project_id": f"project-{index}", "visibility_scope": "project"},
                )
            conn = connect(root)
            try:
                conn.execute("UPDATE graph_edge_sources SET last_decay_at = ?, decay_count = 0", (old_time,))
                conn.commit()
            finally:
                conn.close()

            result = decay_graph_routes(root, limit=1, prune_threshold=99)

            self.assertGreaterEqual(result["domains"], 7)
            self.assertEqual(result["processed"], 1)

    def test_decay_and_prune_memory_controls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            conn.row_factory = sqlite3.Row
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Prune Target",
                    summary="A low-salience topic about Zephyr pruning.",
                    source_refs=[],
                    topics=["Zephyr"],
                    salience=0.1,
                )
                conn.commit()
            finally:
                conn.close()
            sync_card_sidecars_after_commit(root, [card_id])

            dry = prune_memory(root, topic="Zephyr", action="archive", dry_run=True)
            actual = prune_memory(root, topic="Zephyr", action="archive")
            decay = decay_graph_routes(root, limit=10, prune_threshold=1)

            self.assertEqual(dry["card_count"], 1)
            self.assertEqual(actual["card_ids"], [card_id])
            self.assertTrue(decay["ok"])
            conn = connect_existing(root)
            try:
                status = conn.execute("SELECT status FROM cards WHERE id = ?", (card_id,)).fetchone()["status"]
            finally:
                conn.close()
            self.assertEqual(status, "archived")

    def test_storage_tiering_health_and_evals(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["retention"]["raw_scroll_hot_days"] = 0
            write_config(root, config)
            source = Path(tmp) / "tier-source.txt"
            source.write_text("Tiering source evidence for Archivist.\n", encoding="utf-8")
            from continuum.core.store import ingest_file

            book = ingest_file(root, path=source, storage_tier="hot")
            old_original = Path(book["original_uri"])
            old_reader = Path(book["reader_uri"])
            tiered = apply_storage_tiering(root)
            health = memory_health(root)
            evals = run_memory_quality_evals(root)

            self.assertTrue(tiered["ok"])
            self.assertGreaterEqual(tiered["action_count"], 1)
            self.assertTrue(health["initialized"])
            self.assertTrue(evals["ok"], evals["scores"])
            conn = connect_existing(root)
            try:
                row = conn.execute("SELECT storage_tier, original_uri, reader_uri FROM books WHERE id = ?", (book["book_id"],)).fetchone()
            finally:
                conn.close()
            self.assertEqual(row["storage_tier"], "warm")
            self.assertIn("archive/originals/warm/", row["original_uri"])
            self.assertIn("archive/reader_editions/warm/", row["reader_uri"])
            self.assertFalse(old_original.exists())
            self.assertFalse(old_reader.exists())
            self.assertTrue((root / row["original_uri"]).exists())
            self.assertTrue((root / row["reader_uri"]).exists())

    def test_memory_health_skips_inaccessible_reparse_like_directories(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            exports = root / "exports"
            readable = exports / "readable"
            blocked = exports / "blocked-reparse-point"
            readable.mkdir(parents=True)
            blocked.mkdir(parents=True)
            (readable / "note.txt").write_text("healthy bytes\n", encoding="utf-8")
            real_scandir = os.scandir

            def guarded_scandir(path):
                if Path(path) == blocked:
                    raise OSError("simulated inaccessible Windows reparse point")
                return real_scandir(path)

            with patch("continuum.core.workers.os.scandir", side_effect=guarded_scandir):
                health = memory_health(root)

            self.assertTrue(health["initialized"])
            self.assertIn("root_size_bytes", health)

    def test_non_preemptible_expired_worker_lease_is_failed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            expired = (dt.datetime.now(dt.UTC) - dt.timedelta(seconds=30)).replace(microsecond=0).isoformat()
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            try:
                conn.execute(
                    """
                    INSERT INTO queue_jobs(
                        id, role, job_type, priority, status, preemptible, attempt_count,
                        lease_owner, lease_expires_at, heartbeat_at, related_card_ids_json,
                        payload_json, created_at, updated_at, started_at
                    )
                    VALUES(
                        'job_stale_nonpreemptible', 'archivist', 'verify_book_integrity', 10,
                        'running', 0, 1, 'dead-worker', ?, ?, '[]', '{}', ?, ?, ?
                    )
                    """,
                    (expired, expired, expired, expired, expired),
                )
                conn.commit()
            finally:
                conn.close()

            result = run_worker_pass(root, roles=["archivist"], limit=1, maintenance=False)

            self.assertEqual(result["reclaimed_expired_jobs"], 1)
            conn = connect_existing(root)
            try:
                row = conn.execute("SELECT status, error_json FROM queue_jobs WHERE id = 'job_stale_nonpreemptible'").fetchone()
            finally:
                conn.close()
            self.assertEqual(row["status"], "failed")
            self.assertIn("non_preemptible_worker_lease_expired", row["error_json"])

    def test_conflict_detection_marks_related_cards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = sqlite3.connect(root / "catalog" / "catalog.sqlite3")
            conn.row_factory = sqlite3.Row
            try:
                first = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Hermes Route",
                    summary="Decision: use Hermes route for local model.",
                    source_refs=[],
                    topics=["Hermes"],
                )
                second = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Hermes Route",
                    summary="Decision: do not use Hermes route for local model.",
                    source_refs=[],
                    topics=["Hermes"],
                )
                conn.commit()
            finally:
                conn.close()

            result = detect_conflicts(root)

            self.assertGreaterEqual(result["conflict_count"], 1)
            conn = connect_existing(root)
            try:
                rows = conn.execute("SELECT conflict_group FROM cards WHERE id IN (?, ?)", (first, second)).fetchall()
            finally:
                conn.close()
            self.assertTrue(all(row["conflict_group"] for row in rows))


if __name__ == "__main__":
    unittest.main()
