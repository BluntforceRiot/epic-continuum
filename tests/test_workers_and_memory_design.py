from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager, nullcontext
from pathlib import Path
from unittest.mock import patch

from continuum.core.atomic import load_atomic_yaml
from continuum.core import permissions as permissions_module
from continuum.core import store as store_module
from continuum.core import workers as worker_module
from continuum.core.config import default_config, write_config
from continuum.core.evals import run_memory_quality_evals
from continuum.core.operations import restore_drill
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
    @staticmethod
    def _create_pending_sidecar_cards(
        root: Path,
        *,
        count: int,
        namespace: str,
    ) -> list[str]:
        init_db(root)
        card_ids: list[str] = []
        conn = connect(root)
        try:
            for index in range(count):
                title_token = hashlib.sha256(
                    f"{namespace}:title:{index}".encode()
                ).hexdigest()
                summary_token = hashlib.sha256(
                    f"{namespace}:summary:{index}".encode()
                ).hexdigest()
                card_ids.append(
                    create_card(
                        conn,
                        root=root,
                        card_type="note",
                        title=title_token,
                        summary=summary_token,
                        source_refs=[],
                        metadata={"test_namespace": namespace, "index": index},
                    )
                )
            conn.execute("DELETE FROM queue_jobs")
            conn.commit()
        finally:
            conn.close()
        return card_ids

    @staticmethod
    def _running_sidecar_job_lease(
        root: Path,
        card_id: str,
        *,
        suffix: str,
    ) -> tuple[str, worker_module._JobLease]:
        owner = f"sidecar-fence-owner-{suffix}"
        now = store_module.utc_now()
        future = (
            dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)
        ).isoformat()
        conn = connect(root)
        try:
            job_id = enqueue_job(
                conn,
                role="archivist",
                job_type="sync_card_sidecar",
                priority=1,
                payload={"card_id": card_id},
                related_card_ids=[card_id],
                dedupe_key=f"sidecar-fence:{suffix}",
            )
            conn.execute(
                """
                UPDATE queue_jobs
                SET status = 'running', lease_owner = ?, lease_expires_at = ?,
                    heartbeat_at = ?, started_at = ?
                WHERE id = ?
                """,
                (owner, future, now, now, job_id),
            )
            conn.commit()
        finally:
            conn.close()
        return job_id, worker_module._JobLease(root, job_id, owner, 300)

    @staticmethod
    def _prepare_committed_only_scribe_failure(
        root: Path,
        *,
        run_count: int,
        namespace: str,
    ) -> tuple[str, str, dict[str, object]]:
        init_db(root)
        config = default_config()
        config["capture"]["roll_segments_every_events"] = run_count
        write_config(root, config)
        session_id = f"{namespace}-session"
        for index in range(run_count):
            event_metadata: dict[str, object] | None = None
            if run_count > 1:
                event_metadata = {
                    "visibility_scope": "project",
                    "project_id": f"{namespace}-project-{index % 2}",
                }
            append_scroll_event(
                root,
                session_id=session_id,
                event_type="message",
                role="user",
                content=f"{namespace} committed Scribe step {index}",
                metadata=event_metadata,
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
                dedupe_key=f"{namespace}:{session_id}",
            )
            conn.commit()
        finally:
            conn.close()
        with patch.object(
            store_module,
            "sync_card_sidecars_after_commit",
            return_value={
                "ok": False,
                "synced": 0,
                "failed": 1,
                "failures": [
                    {
                        "error": (
                            f"{namespace} simulated committed-only "
                            "sidecar failure"
                        )
                    }
                ],
            },
        ):
            deferred = run_worker_pass(
                root,
                roles=["scribe"],
                limit=1,
                maintenance=False,
            )
        return job_id, session_id, deferred["processed"][0]["result"]

    @staticmethod
    def _seed_legacy_failed_worker_effect(
        root: Path,
        *,
        job_id: str,
        job_type: str,
        deferred_result: dict[str, object],
    ) -> tuple[str, dict[str, object]]:
        failed_result = dict(deferred_result)
        failed_result.pop("reason", None)
        failed_result.pop("retry_pending", None)
        failed_result.pop("idempotent_replay", None)
        now = store_module.utc_now()
        conn = connect(root)
        try:
            effect_event_id = store_module.audit_event(
                conn,
                action=worker_module._WORKER_EFFECT_ACTION,
                target_type="queue_job",
                target_id=job_id,
                payload={
                    "schema": worker_module._WORKER_EFFECT_SCHEMA,
                    "job_type": job_type,
                    "post_phase_complete": True,
                    "result": failed_result,
                },
            )
            cursor = conn.execute(
                """
                UPDATE queue_jobs
                SET status = 'failed', finished_at = ?, updated_at = ?,
                    lease_owner = NULL, lease_expires_at = NULL,
                    heartbeat_at = NULL, error_json = ?
                WHERE id = ? AND status = 'pending'
                """,
                (
                    now,
                    now,
                    store_module.json_dumps(
                        {
                            "error": "worker result reported ok=false",
                            "result": failed_result,
                        }
                    ),
                    job_id,
                ),
            )
            if int(cursor.rowcount or 0) != 1:
                raise AssertionError("legacy failed effect seed did not bind")
            conn.commit()
        finally:
            conn.close()
        return effect_event_id, failed_result

    @staticmethod
    def _seed_multi_role_claim_backlog(
        root: Path,
        *,
        namespace: str,
        excluded_count: int = 5_000,
    ) -> dict[str, str]:
        init_db(root)
        conn = connect(root)
        try:
            conn.executemany(
                """
                INSERT INTO queue_jobs(
                    id, role, job_type, priority, status, preemptible,
                    related_card_ids_json, payload_json,
                    created_at, updated_at
                )
                VALUES(
                    ?, 'scribe', 'excluded_role_claim_probe', 0,
                    'pending', 1, '[]', '{}', ?, ?
                )
                """,
                [
                    (
                        f"{namespace}-excluded-{index:05d}",
                        "2026-01-01T00:00:00+00:00",
                        "2026-01-01T00:00:00+00:00",
                    )
                    for index in range(excluded_count)
                ],
            )
            blocked_dedupe = f"{namespace}-active-dedupe"
            conn.execute(
                """
                INSERT INTO queue_jobs(
                    id, role, job_type, priority, status, preemptible,
                    dedupe_key, related_card_ids_json, payload_json,
                    created_at, updated_at
                )
                VALUES(
                    ?, 'scribe', 'active_dedupe_claim_probe', 0,
                    'running', 1, ?, '[]', '{}', ?, ?
                )
                """,
                (
                    f"{namespace}-active-dedupe",
                    blocked_dedupe,
                    "2025-12-01T00:00:00+00:00",
                    "2025-12-01T00:00:00+00:00",
                ),
            )
            blocked_id = f"{namespace}-blocked-librarian"
            conn.execute(
                """
                INSERT INTO queue_jobs(
                    id, role, job_type, priority, status, preemptible,
                    dedupe_key, related_card_ids_json, payload_json,
                    created_at, updated_at
                )
                VALUES(
                    ?, 'librarian', 'blocked_dedupe_claim_probe', 0,
                    'pending', 1, ?, '[]', '{}', ?, ?
                )
                """,
                (
                    blocked_id,
                    blocked_dedupe,
                    "2025-12-02T00:00:00+00:00",
                    "2025-12-02T00:00:00+00:00",
                ),
            )
            oldest_librarian_id = f"{namespace}-oldest-librarian"
            oldest_archivist_id = f"{namespace}-oldest-archivist"
            strict_archivist_id = f"{namespace}-strict-archivist"
            strict_librarian_id = f"{namespace}-strict-librarian"
            conn.executemany(
                """
                INSERT INTO queue_jobs(
                    id, role, job_type, priority, status, preemptible,
                    related_card_ids_json, payload_json,
                    created_at, updated_at
                )
                VALUES(?, ?, 'multi_role_claim_probe', ?, 'pending', 1,
                       '[]', '{}', ?, ?)
                """,
                [
                    (
                        oldest_librarian_id,
                        "librarian",
                        900,
                        "2026-02-01T00:00:00+00:00",
                        "2026-02-01T00:00:00+00:00",
                    ),
                    (
                        oldest_archivist_id,
                        "archivist",
                        900,
                        "2026-02-01T00:00:00+00:00",
                        "2026-02-01T00:00:00+00:00",
                    ),
                    (
                        strict_archivist_id,
                        "archivist",
                        1,
                        "2026-03-01T00:00:00+00:00",
                        "2026-03-01T00:00:00+00:00",
                    ),
                    (
                        strict_librarian_id,
                        "librarian",
                        1,
                        "2026-03-01T00:00:00+00:00",
                        "2026-03-01T00:00:00+00:00",
                    ),
                ],
            )
            conn.commit()
            conn.execute("ANALYZE")
            conn.commit()
        finally:
            conn.close()
        return {
            "blocked": blocked_id,
            "strict": strict_archivist_id,
            "strict_tie_loser": strict_librarian_id,
            "oldest": oldest_librarian_id,
            "oldest_tie_loser": oldest_archivist_id,
        }

    @unittest.skipUnless(os.name == "nt", "Windows path aliases are Windows-only")
    def test_scribe_replay_resolves_long_alias_for_managed_card_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            session_id = "scribe-windows-sidecar-alias"
            append_scroll_event(
                root,
                session_id=session_id,
                event_type="message",
                role="user",
                content="Replay one committed Scribe step through a path alias.",
            )
            rolled = roll_scroll_segment(
                root,
                session_id=session_id,
                start_seq=1,
                end_seq=1,
            )
            card_id = str(rolled["card_id"])
            job_id = "job_scribe_windows_sidecar_alias"
            conn = connect(root)
            try:
                location_uri = str(
                    conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()["location_uri"]
                )
                short_path = resolve_stored_uri(root, location_uri)
                long_path = short_path.resolve()
                if os.path.normcase(os.path.abspath(short_path)) == os.path.normcase(
                    os.path.abspath(long_path)
                ):
                    self.skipTest("temporary root has no distinct short/long spelling")
                conn.execute(
                    "UPDATE cards SET location_uri = ? WHERE id = ?",
                    (str(long_path), card_id),
                )
                store_module.audit_event(
                    conn,
                    action=worker_module._SCRIBE_STEP_COMMITTED_ACTION,
                    target_type="queue_job",
                    target_id=job_id,
                    payload={
                        "schema": "continuum.worker_scribe_segment_step_committed.v1",
                        "step_key": f"{session_id}:1:1",
                        "session_id": session_id,
                        "start_seq": 1,
                        "end_seq": 1,
                        "batch_number": 1,
                        "result": rolled,
                    },
                )
                conn.commit()
            finally:
                conn.close()

            committed, max_batch = worker_module._committed_scribe_steps(
                root,
                worker_module._JobLease(root, job_id, "alias-owner", 30),
            )
            self.assertEqual(max_batch, 1)
            self.assertEqual(len(committed), 1)
            self.assertEqual(Path(str(committed[0]["card_uri"])).resolve(), long_path)

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

    def test_sidecar_sync_releases_db_writer_but_serializes_newer_file_replace(
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
                self.assertTrue(newer_update_committed.wait(timeout=5))
                self.assertEqual(newer_sync_results, [])
                self.assertTrue(newer_thread.is_alive())
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
            self.assertFalse(
                list((root / "run" / "card_sidecar_write_intents").glob("*.json"))
            )
            receipts = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (
                    root / "exports" / "card_sidecar_recovery_receipts"
                ).glob("*.json")
            ]
            self.assertTrue(
                any(
                    receipt.get("status") == "superseded_by_newer_state"
                    for receipt in receipts
                ),
                receipts,
            )
            content_addressed_integrity = semantic_integrity_report(root)
            self.assertTrue(
                content_addressed_integrity["ok"],
                content_addressed_integrity,
            )

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

    def test_worker_maintenance_sidecar_drain_keeps_its_declared_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            self._create_pending_sidecar_cards(
                root,
                count=51,
                namespace="bounded-worker-maintenance",
            )
            with patch.object(
                store_module,
                "sync_pending_card_sidecars",
                wraps=store_module.sync_pending_card_sidecars,
            ) as generic_recovery:
                result = run_worker_pass(
                    root,
                    limit=1,
                    maintenance=True,
                )

            self.assertTrue(result["maintenance"]["sidecars"]["ok"], result)
            self.assertEqual(result["maintenance"]["sidecars"]["pending"], 50)
            self.assertEqual(result["maintenance"]["sidecars"]["synced"], 50)
            generic_recovery.assert_not_called()
            conn = connect_existing(root)
            try:
                remaining = int(
                    conn.execute(
                        "SELECT count(*) AS n FROM card_sidecar_outbox"
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(remaining, 1, result)

    def test_worker_outbox_and_intent_maintenance_share_one_resolution_budget(
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
                    title="shared-worker-intent-budget",
                    summary=(
                        "Outbox materialization and crash recovery must share "
                        "one bounded intent budget."
                    ),
                    source_refs=[],
                )
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                payload = store_module._card_sidecar_payload_for_row(row)
                target_uri = str(row["location_uri"])
                conn.commit()
            finally:
                conn.close()
            for _index in range(51):
                store_module._write_card_sidecar_write_intent(
                    root,
                    card_id=card_id,
                    target_uri=target_uri,
                    expected_state_hash=str(payload["state_hash"]),
                )

            reconciliation_calls: list[dict[str, object]] = []
            real_reconcile = (
                worker_module.reconcile_card_sidecar_write_intents
            )

            def capture_reconciliation(
                *args: object,
                **kwargs: object,
            ) -> dict[str, object]:
                result = real_reconcile(*args, **kwargs)
                reconciliation_calls.append(
                    {
                        "kwargs": dict(kwargs),
                        "selected": int(result.get("selected", 0)),
                        "processed": int(result.get("processed", 0)),
                    }
                )
                return result

            with patch.object(
                worker_module,
                "reconcile_card_sidecar_write_intents",
                side_effect=capture_reconciliation,
            ):
                worker = run_worker_pass(
                    root,
                    limit=1,
                    maintenance=True,
                )

            intent_result = worker["maintenance"]["sidecar_intents"]
            self.assertTrue(worker["ok"], worker)
            self.assertEqual(
                worker["maintenance"]["sidecars"]["synced"],
                1,
            )
            self.assertEqual(len(reconciliation_calls), 1)
            self.assertEqual(
                reconciliation_calls[0]["kwargs"].get("limit"),
                worker_module.WORKER_SIDECAR_INTENT_LIMIT,
            )
            self.assertNotIn(
                "card_ids",
                reconciliation_calls[0]["kwargs"],
            )
            self.assertLessEqual(
                sum(
                    int(call["selected"])
                    for call in reconciliation_calls
                ),
                worker_module.WORKER_SIDECAR_INTENT_LIMIT,
            )
            self.assertLessEqual(
                sum(
                    int(call["processed"])
                    for call in reconciliation_calls
                ),
                worker_module.WORKER_SIDECAR_INTENT_LIMIT,
            )
            self.assertEqual(intent_result["selected"], 50)
            self.assertEqual(intent_result["processed"], 50)
            self.assertEqual(intent_result["enumerated"], 51)
            self.assertEqual(intent_result["remaining"], 1)
            self.assertTrue(intent_result["remaining_is_lower_bound"])
            self.assertFalse(intent_result["complete"])
            self.assertTrue(intent_result["has_more"])

    def test_card_filtered_scope_stays_incomplete_with_unrelated_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            card_ids = self._create_pending_sidecar_cards(
                root,
                count=2,
                namespace="card-filtered-intent-limit",
            )
            with (
                patch.object(
                    store_module,
                    "reconcile_card_sidecar_write_intents",
                    side_effect=SystemExit(
                        "simulated process death before intent reconciliation"
                    ),
                ),
                self.assertRaises(SystemExit),
            ):
                sync_card_sidecars_after_commit(root, card_ids)

            selected_card_id = card_ids[1]
            with self.assertRaisesRegex(
                ValueError,
                "cannot use a global limit",
            ):
                store_module.reconcile_card_sidecar_write_intents(
                    root,
                    card_ids=[selected_card_id],
                    limit=1,
                )
            reconciled = (
                store_module.reconcile_card_sidecar_write_intents(
                    root,
                    card_ids=[selected_card_id],
                )
            )

            self.assertTrue(reconciled["ok"], reconciled)
            self.assertEqual(reconciled["selected"], 1)
            self.assertEqual(reconciled["processed"], 1)
            self.assertEqual(
                reconciled["results"][0]["card_id"],
                selected_card_id,
            )
            self.assertTrue(reconciled["scope_filtered"])
            self.assertFalse(reconciled["scope_complete"])
            self.assertEqual(reconciled["remaining"], 1)
            self.assertFalse(reconciled["complete"])

    def test_card_filtered_scope_rejects_concurrent_matching_arrival(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_ids = [
                    create_card(
                        conn,
                        root=root,
                        card_type="note",
                        title=f"filtered-arrival-{index}",
                        summary="A concurrent matching intent must retain retry.",
                        source_refs=[],
                    )
                    for index in range(2)
                ]
                rows = {
                    str(row["id"]): row
                    for row in conn.execute(
                        "SELECT * FROM cards WHERE id IN (?, ?)",
                        card_ids,
                    ).fetchall()
                }
                conn.execute("DELETE FROM card_sidecar_outbox")
                conn.commit()
            finally:
                conn.close()
            unrelated_card_id, selected_card_id = card_ids
            unrelated_payload = store_module._card_sidecar_payload_for_row(
                rows[unrelated_card_id]
            )
            selected_payload = store_module._card_sidecar_payload_for_row(
                rows[selected_card_id]
            )
            store_module._write_card_sidecar_write_intent(
                root,
                card_id=unrelated_card_id,
                target_uri=str(rows[unrelated_card_id]["location_uri"]),
                expected_state_hash=str(
                    unrelated_payload["state_hash"]
                ),
            )
            real_inventory = (
                store_module._bounded_card_sidecar_intent_inventory
            )
            injected = False

            def inject_after_initial_inventory(
                intent_dir: Path,
                retirement_dir: Path | None,
                *,
                entry_limit: int,
                **inventory_kwargs: object,
            ) -> tuple[list[Path], list[Path], bool, int]:
                nonlocal injected
                inventory = real_inventory(
                    intent_dir,
                    retirement_dir,
                    entry_limit=entry_limit,
                    **inventory_kwargs,
                )
                if not injected:
                    injected = True
                    store_module._write_card_sidecar_write_intent(
                        root,
                        card_id=selected_card_id,
                        target_uri=str(
                            rows[selected_card_id]["location_uri"]
                        ),
                        expected_state_hash=str(
                            selected_payload["state_hash"]
                        ),
                    )
                return inventory

            with patch.object(
                store_module,
                "_bounded_card_sidecar_intent_inventory",
                side_effect=inject_after_initial_inventory,
            ):
                reconciled = (
                    store_module.reconcile_card_sidecar_write_intents(
                        root,
                        card_ids=[selected_card_id],
                    )
                )

            self.assertTrue(injected)
            self.assertTrue(reconciled["ok"], reconciled)
            self.assertEqual(reconciled["selected"], 0)
            self.assertEqual(reconciled["processed"], 0)
            self.assertEqual(reconciled["remaining"], 2)
            self.assertFalse(reconciled["complete"])
            self.assertFalse(reconciled["scope_complete"])

    def test_reconciliation_postflight_waits_for_db_bound_intent_publisher(
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
                    title="postflight-db-publisher",
                    summary="The final scan must wait for a publishing transaction.",
                    source_refs=[],
                )
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                payload = store_module._card_sidecar_payload_for_row(row)
                conn.execute("DELETE FROM card_sidecar_outbox")
                conn.commit()
            finally:
                conn.close()
            intent_state = store_module._validated_card_sidecar_state_dir(
                root,
                purpose="intent",
                create=True,
            )
            self.assertIsNotNone(intent_state)

            initial_inventory_seen = threading.Event()
            publisher_written = threading.Event()
            allow_publisher_commit = threading.Event()
            postflight_scan_started = threading.Event()
            reconciliation_done = threading.Event()
            errors: list[BaseException] = []
            results: list[dict[str, object]] = []
            real_inventory = (
                store_module._bounded_card_sidecar_intent_inventory
            )
            real_retire_captured = (
                store_module
                ._retire_captured_card_sidecar_publisher_temps
            )
            inventory_calls = 0
            retirement_calls = 0

            def gate_inventory(
                intent_dir: Path,
                retirement_dir: Path | None,
                *,
                entry_limit: int,
                **inventory_kwargs: object,
            ) -> tuple[list[Path], list[Path], bool, int]:
                nonlocal inventory_calls
                inventory = real_inventory(
                    intent_dir,
                    retirement_dir,
                    entry_limit=entry_limit,
                    **inventory_kwargs,
                )
                inventory_calls += 1
                if inventory_calls == 1:
                    initial_inventory_seen.set()
                elif inventory_calls == 2:
                    postflight_scan_started.set()
                return inventory

            def gate_after_initial_inventory(
                *args: object,
                **kwargs: object,
            ) -> None:
                nonlocal retirement_calls
                real_retire_captured(*args, **kwargs)
                retirement_calls += 1
                if retirement_calls == 1 and not publisher_written.wait(
                    timeout=10.0
                ):
                    raise TimeoutError("publisher did not write its intent")

            def publish() -> None:
                publisher_conn = connect(root)
                try:
                    if not initial_inventory_seen.wait(timeout=10.0):
                        raise TimeoutError("initial inventory did not run")
                    publisher_conn.execute("BEGIN IMMEDIATE")
                    store_module._write_card_sidecar_write_intent(
                        root,
                        card_id=card_id,
                        target_uri=str(row["location_uri"]),
                        expected_state_hash=str(payload["state_hash"]),
                        conn=publisher_conn,
                    )
                    publisher_written.set()
                    if not allow_publisher_commit.wait(timeout=10.0):
                        raise TimeoutError("publisher commit was not released")
                    publisher_conn.commit()
                except BaseException as exc:
                    if publisher_conn.in_transaction:
                        publisher_conn.rollback()
                    errors.append(exc)
                finally:
                    publisher_conn.close()

            def reconcile() -> None:
                try:
                    results.append(
                        store_module.reconcile_card_sidecar_write_intents(
                            root,
                            limit=1,
                        )
                    )
                except BaseException as exc:
                    errors.append(exc)
                finally:
                    reconciliation_done.set()

            publisher_thread = threading.Thread(target=publish, daemon=True)
            reconciliation_thread = threading.Thread(
                target=reconcile,
                daemon=True,
            )
            with (
                patch.object(
                    store_module,
                    "_bounded_card_sidecar_intent_inventory",
                    side_effect=gate_inventory,
                ),
                patch.object(
                    store_module,
                    "_retire_captured_card_sidecar_publisher_temps",
                    side_effect=gate_after_initial_inventory,
                ),
            ):
                publisher_thread.start()
                reconciliation_thread.start()
                self.assertTrue(publisher_written.wait(timeout=10.0))
                self.assertFalse(
                    postflight_scan_started.wait(timeout=0.25),
                    "postflight scan crossed an active publisher transaction",
                )
                self.assertFalse(reconciliation_done.is_set())
                allow_publisher_commit.set()
                publisher_thread.join(timeout=10.0)
                reconciliation_thread.join(timeout=10.0)

            self.assertFalse(publisher_thread.is_alive())
            self.assertFalse(reconciliation_thread.is_alive())
            self.assertFalse(errors, errors)
            self.assertEqual(len(results), 1)
            reconciled = results[0]
            self.assertTrue(reconciled["ok"], reconciled)
            self.assertEqual(reconciled["processed"], 0)
            self.assertEqual(reconciled["remaining"], 1)
            self.assertFalse(reconciled["complete"])
            self.assertTrue(postflight_scan_started.is_set())

    def test_private_intent_publisher_cannot_cross_reconciliation_scan(
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
                    title="private-publisher-fence",
                    summary="Private publishers share the reconciler lock.",
                    source_refs=[],
                )
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                payload = store_module._card_sidecar_payload_for_row(row)
                conn.execute("DELETE FROM card_sidecar_outbox")
                conn.commit()
            finally:
                conn.close()
            store_module._write_card_sidecar_write_intent(
                root,
                card_id=card_id,
                target_uri=str(row["location_uri"]),
                expected_state_hash=str(payload["state_hash"]),
            )

            postflight_inventory_held = threading.Event()
            release_postflight_inventory = threading.Event()
            publisher_entered = threading.Event()
            publisher_done = threading.Event()
            errors: list[BaseException] = []
            results: list[dict[str, object]] = []
            real_inventory = (
                store_module._bounded_card_sidecar_intent_inventory
            )
            inventory_calls = 0

            def hold_postflight_inventory(
                intent_dir: Path,
                retirement_dir: Path | None,
                *,
                entry_limit: int,
                **inventory_kwargs: object,
            ) -> tuple[list[Path], list[Path], bool, int]:
                nonlocal inventory_calls
                inventory = real_inventory(
                    intent_dir,
                    retirement_dir,
                    entry_limit=entry_limit,
                    **inventory_kwargs,
                )
                inventory_calls += 1
                if inventory_calls == 2:
                    postflight_inventory_held.set()
                    if not release_postflight_inventory.wait(timeout=10.0):
                        raise TimeoutError("postflight inventory was not released")
                return inventory

            def publish() -> None:
                try:
                    publisher_entered.set()
                    store_module._write_card_sidecar_write_intent(
                        root,
                        card_id=card_id,
                        target_uri=str(row["location_uri"]),
                        expected_state_hash=str(payload["state_hash"]),
                    )
                except BaseException as exc:
                    errors.append(exc)
                finally:
                    publisher_done.set()

            def reconcile() -> None:
                try:
                    results.append(
                        store_module.reconcile_card_sidecar_write_intents(
                            root,
                            limit=1,
                        )
                    )
                except BaseException as exc:
                    errors.append(exc)

            reconciliation_thread = threading.Thread(
                target=reconcile,
                daemon=True,
            )
            publisher_thread = threading.Thread(target=publish, daemon=True)
            with patch.object(
                store_module,
                "_bounded_card_sidecar_intent_inventory",
                side_effect=hold_postflight_inventory,
            ):
                reconciliation_thread.start()
                self.assertTrue(postflight_inventory_held.wait(timeout=10.0))
                publisher_thread.start()
                self.assertTrue(publisher_entered.wait(timeout=10.0))
                self.assertFalse(
                    publisher_done.wait(timeout=0.25),
                    "private publisher escaped the reconciler operation lock",
                )
                release_postflight_inventory.set()
                reconciliation_thread.join(timeout=10.0)
                publisher_thread.join(timeout=10.0)

            self.assertFalse(reconciliation_thread.is_alive())
            self.assertFalse(publisher_thread.is_alive())
            self.assertFalse(errors, errors)
            self.assertEqual(len(results), 1)
            self.assertTrue(results[0]["ok"], results[0])
            self.assertTrue(results[0]["complete"], results[0])
            self.assertEqual(
                len(
                    list(
                        (
                            root / "run" / "card_sidecar_write_intents"
                        ).glob("*.json")
                    )
                ),
                1,
            )

    def test_reconciliation_postflight_db_fence_failure_is_nonterminal(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            intent_state = store_module._validated_card_sidecar_state_dir(
                root,
                purpose="intent",
                create=True,
            )
            self.assertIsNotNone(intent_state)
            real_connect = store_module.connect
            connect_calls = 0

            def fail_postflight_connect(path: Path) -> sqlite3.Connection:
                nonlocal connect_calls
                connect_calls += 1
                if connect_calls == 2:
                    raise sqlite3.OperationalError(
                        "synthetic postflight writer fence failure"
                    )
                return real_connect(path)

            with patch.object(
                store_module,
                "connect",
                side_effect=fail_postflight_connect,
            ):
                reconciled = (
                    store_module.reconcile_card_sidecar_write_intents(
                        root,
                        limit=1,
                    )
                )

            self.assertFalse(reconciled["ok"], reconciled)
            self.assertIsNone(reconciled["remaining"])
            self.assertTrue(reconciled["remaining_is_lower_bound"])
            self.assertFalse(reconciled["complete"])
            self.assertTrue(reconciled["has_more"])

    def test_uninitialized_reconciliation_does_not_cross_into_unlocked_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with (
                patch.object(
                    store_module,
                    "is_initialized",
                    side_effect=[False, True],
                ),
                patch.object(
                    store_module,
                    "_reconcile_card_sidecar_write_intents_unlocked",
                    wraps=(
                        store_module
                        ._reconcile_card_sidecar_write_intents_unlocked
                    ),
                ) as unlocked,
            ):
                reconciled = (
                    store_module.reconcile_card_sidecar_write_intents(
                        root,
                        limit=1,
                    )
                )

            self.assertTrue(reconciled["ok"], reconciled)
            self.assertTrue(reconciled["complete"], reconciled)
            self.assertEqual(reconciled["processed"], 0)
            self.assertEqual(reconciled["enumerated"], 0)
            unlocked.assert_not_called()

    def test_failed_worker_sidecar_drain_is_not_retried_by_maintenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            self._create_pending_sidecar_cards(
                root,
                count=51,
                namespace="failed-worker-maintenance",
            )
            failed_drain = {
                "ok": False,
                "synced": 0,
                "failed": 50,
                "failures": [{"error": "simulated bounded drain failure"}],
            }
            with (
                patch.object(
                    worker_module,
                    "sync_card_sidecars_after_commit",
                    return_value=failed_drain,
                ) as explicit_sync,
                patch.object(
                    store_module,
                    "sync_pending_card_sidecars",
                    wraps=store_module.sync_pending_card_sidecars,
                ) as generic_recovery,
            ):
                result = run_worker_pass(
                    root,
                    limit=1,
                    maintenance=True,
                )

            self.assertFalse(result["ok"], result)
            self.assertFalse(result["maintenance"]["sidecars"]["ok"], result)
            self.assertEqual(result["maintenance"]["sidecars"]["pending"], 50)
            self.assertEqual(result["maintenance"]["sidecars"]["synced"], 0)
            self.assertEqual(result["maintenance"]["sidecars"]["failed"], 50)
            explicit_sync.assert_called_once()
            generic_recovery.assert_not_called()
            conn = connect_existing(root)
            try:
                remaining = int(
                    conn.execute(
                        "SELECT count(*) AS n FROM card_sidecar_outbox"
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(remaining, 51, result)

    def test_worker_reconciles_bounded_orphan_intents_after_crash_window(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            card_ids = self._create_pending_sidecar_cards(
                root,
                count=51,
                namespace="worker-orphan-intent-crash-window",
            )
            with (
                patch.object(
                    store_module,
                    "reconcile_card_sidecar_write_intents",
                    side_effect=SystemExit(
                        "simulated process death before intent reconciliation"
                    ),
                ),
                self.assertRaisesRegex(
                    SystemExit,
                    "before intent reconciliation",
                ),
            ):
                sync_card_sidecars_after_commit(root, card_ids)

            intent_dir = root / "run" / "card_sidecar_write_intents"
            self.assertEqual(len(list(intent_dir.glob("*.json"))), 51)
            conn = connect_existing(root)
            try:
                self.assertEqual(
                    int(
                        conn.execute(
                            "SELECT count(*) AS n FROM card_sidecar_outbox"
                        ).fetchone()["n"]
                    ),
                    0,
                )
            finally:
                conn.close()

            with patch.object(
                store_module,
                "sync_pending_card_sidecars",
                wraps=store_module.sync_pending_card_sidecars,
            ) as generic_recovery:
                first = run_worker_pass(
                    root,
                    limit=1,
                    maintenance=True,
                )

            first_intents = first["maintenance"]["sidecar_intents"]
            self.assertTrue(first["ok"], first)
            self.assertTrue(first_intents["ok"], first)
            self.assertEqual(first_intents["processed"], 50)
            self.assertEqual(first_intents["pending"], 0)
            self.assertEqual(first_intents["selected"], 50)
            self.assertEqual(first_intents["remaining"], 1)
            self.assertTrue(first_intents["remaining_is_lower_bound"])
            self.assertFalse(first_intents["complete"])
            self.assertTrue(first_intents["has_more"])
            self.assertEqual(first_intents["remaining_lower_bound"], 1)
            self.assertTrue(first_intents["batch_truncated"])
            self.assertFalse(first_intents["overflow"])
            self.assertEqual(first_intents["status_counts"], {"adopted": 50})
            self.assertEqual(len(list(intent_dir.glob("*.json"))), 1)
            generic_recovery.assert_not_called()

            second = run_worker_pass(
                root,
                limit=1,
                maintenance=True,
            )

            second_intents = second["maintenance"]["sidecar_intents"]
            self.assertTrue(second["ok"], second)
            self.assertEqual(second_intents["processed"], 1)
            self.assertEqual(second_intents["selected"], 1)
            self.assertEqual(second_intents["remaining"], 0)
            self.assertTrue(second_intents["complete"])
            self.assertFalse(second_intents["has_more"])
            self.assertEqual(second_intents["remaining_lower_bound"], 0)
            self.assertFalse(second_intents["batch_truncated"])
            self.assertFalse(second_intents["overflow"])
            self.assertEqual(second_intents["status_counts"], {"adopted": 1})
            self.assertFalse(list(intent_dir.glob("*.json")))

    def test_concurrent_orphan_intent_reconciliation_is_idempotent(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            card_ids = self._create_pending_sidecar_cards(
                root,
                count=1,
                namespace="concurrent-orphan-intent-reconciliation",
            )
            with (
                patch.object(
                    store_module,
                    "reconcile_card_sidecar_write_intents",
                    side_effect=SystemExit(
                        "simulated process death before intent reconciliation"
                    ),
                ),
                self.assertRaisesRegex(
                    SystemExit,
                    "before intent reconciliation",
                ),
            ):
                sync_card_sidecars_after_commit(root, card_ids)

            intent_dir = root / "run" / "card_sidecar_write_intents"
            self.assertEqual(len(list(intent_dir.glob("*.json"))), 1)
            start_barrier = threading.Barrier(2)
            results: list[dict[str, object]] = []
            errors: list[BaseException] = []
            result_lock = threading.Lock()

            def reconcile() -> None:
                try:
                    start_barrier.wait(timeout=10.0)
                    result = store_module.reconcile_card_sidecar_write_intents(
                        root,
                        limit=1,
                    )
                    with result_lock:
                        results.append(result)
                except BaseException as exc:
                    with result_lock:
                        errors.append(exc)

            threads = [
                threading.Thread(target=reconcile, daemon=True)
                for _index in range(2)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=15.0)

            self.assertFalse(
                any(thread.is_alive() for thread in threads),
                "concurrent reconciliation threads did not finish",
            )
            self.assertFalse(errors, errors)
            self.assertEqual(len(results), 2, results)
            self.assertTrue(all(result["ok"] for result in results), results)
            self.assertEqual(
                sorted(int(result["processed"]) for result in results),
                [0, 1],
            )
            reconciliation_results = [
                reconciliation_result
                for result in results
                for reconciliation_result in result["results"]
            ]
            self.assertEqual(
                1,
                len(reconciliation_results),
            )
            self.assertEqual(
                reconciliation_results[0]["status"],
                "adopted",
            )
            self.assertFalse(
                reconciliation_results[0]["concurrent_completion"],
            )
            self.assertFalse(list(intent_dir.glob("*.json")))
            self.assertEqual(
                len(
                    list(
                        (
                            root
                            / "exports"
                            / "card_sidecar_resolved_intents"
                        ).glob("*.json")
                    )
                ),
                1,
            )

    def test_single_prepublication_flush_failure_preserves_retry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            card_ids = self._create_pending_sidecar_cards(
                root,
                count=1,
                namespace="single-retirement-directory-flush",
            )
            with (
                patch.object(
                    store_module,
                    "reconcile_card_sidecar_write_intents",
                    side_effect=SystemExit(
                        "simulated process death before intent reconciliation"
                    ),
                ),
                self.assertRaises(SystemExit),
            ):
                sync_card_sidecars_after_commit(root, card_ids)

            intent_dir = root / "run" / "card_sidecar_write_intents"
            intent_path = next(intent_dir.glob("*.json"))
            receipt_dir = (
                root / "exports" / "card_sidecar_recovery_receipts"
            )
            real_flush_directory = store_module.flush_directory_strict
            retirement_flush_calls = 0

            def fail_first_retirement_flush(path: Path) -> None:
                nonlocal retirement_flush_calls
                if (
                    Path(path) == intent_dir
                    and receipt_dir.is_dir()
                    and not intent_path.exists()
                ):
                    retirement_flush_calls += 1
                    if retirement_flush_calls == 1:
                        raise OSError(
                            "synthetic first retirement flush failure"
                        )
                real_flush_directory(Path(path))

            with patch.object(
                store_module,
                "flush_directory_strict",
                side_effect=fail_first_retirement_flush,
            ):
                interrupted = (
                    store_module.reconcile_card_sidecar_write_intents(
                        root,
                        limit=1,
                    )
                )

            self.assertFalse(interrupted["ok"], interrupted)
            retirement_dir = (
                root / "run" / "card_sidecar_retirement_intents"
            )
            self.assertFalse(intent_path.exists())
            self.assertEqual(
                len(list(retirement_dir.glob("*.json"))),
                1,
            )
            self.assertFalse(
                list(
                    (
                        root
                        / "exports"
                        / "card_sidecar_resolved_intents"
                    ).glob("*.json")
                )
            )

            resumed = store_module.reconcile_card_sidecar_write_intents(
                root,
                limit=1,
            )

            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["processed"], 1)
            self.assertFalse(intent_path.exists())
            self.assertFalse(list(retirement_dir.glob("*.json")))
            self.assertEqual(
                len(
                    list(
                        (
                            root
                            / "exports"
                            / "card_sidecar_resolved_intents"
                        ).glob("*.json")
                    )
                ),
                1,
            )

    def test_concurrent_retirement_reproves_failed_directory_flush(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            card_ids = self._create_pending_sidecar_cards(
                root,
                count=1,
                namespace="concurrent-retirement-directory-flush",
            )
            with (
                patch.object(
                    store_module,
                    "reconcile_card_sidecar_write_intents",
                    side_effect=SystemExit(
                        "simulated process death before intent reconciliation"
                    ),
                ),
                self.assertRaises(SystemExit),
            ):
                sync_card_sidecars_after_commit(root, card_ids)

            intent_dir = root / "run" / "card_sidecar_write_intents"
            intent_path = next(intent_dir.glob("*.json"))
            receipt_dir = (
                root / "exports" / "card_sidecar_recovery_receipts"
            )
            real_flush_directory = store_module.flush_directory_strict
            start_barrier = threading.Barrier(2)
            result_lock = threading.Lock()
            flush_lock = threading.Lock()
            retirement_flush_calls = 0
            results: list[dict[str, object]] = []
            errors: list[BaseException] = []

            def fail_first_retirement_flush(path: Path) -> None:
                nonlocal retirement_flush_calls
                if (
                    Path(path) == intent_dir
                    and receipt_dir.is_dir()
                    and not intent_path.exists()
                ):
                    with flush_lock:
                        retirement_flush_calls += 1
                        if retirement_flush_calls == 1:
                            raise OSError(
                                "synthetic first retirement flush failure"
                            )
                real_flush_directory(Path(path))

            def reconcile() -> None:
                try:
                    start_barrier.wait(timeout=10.0)
                    result = (
                        store_module.reconcile_card_sidecar_write_intents(
                            root,
                            limit=1,
                        )
                    )
                    with result_lock:
                        results.append(result)
                except BaseException as exc:
                    with result_lock:
                        errors.append(exc)

            threads = [
                threading.Thread(target=reconcile, daemon=True)
                for _index in range(2)
            ]
            with patch.object(
                store_module,
                "flush_directory_strict",
                side_effect=fail_first_retirement_flush,
            ):
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=15.0)

            self.assertFalse(
                any(thread.is_alive() for thread in threads),
                "concurrent reconciliation threads did not finish",
            )
            self.assertFalse(errors, errors)
            self.assertEqual(len(results), 2, results)
            self.assertGreaterEqual(retirement_flush_calls, 1, results)
            self.assertTrue(
                any(not result["ok"] for result in results),
                results,
            )
            resumed = store_module.reconcile_card_sidecar_write_intents(
                root,
                limit=1,
            )
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["remaining"], 0)
            self.assertFalse(intent_path.exists())
            self.assertEqual(
                len(
                    list(
                        (
                            root
                            / "exports"
                            / "card_sidecar_resolved_intents"
                        ).glob("*.json")
                    )
                ),
                1,
            )

    def test_prepublication_failure_leaves_replayable_retirement_queue(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            card_ids = self._create_pending_sidecar_cards(
                root,
                count=1,
                namespace="failed-retirement-restoration-queue",
            )
            with (
                patch.object(
                    store_module,
                    "reconcile_card_sidecar_write_intents",
                    side_effect=SystemExit(
                        "simulated process death before intent reconciliation"
                    ),
                ),
                self.assertRaises(SystemExit),
            ):
                sync_card_sidecars_after_commit(root, card_ids)

            intent_dir = root / "run" / "card_sidecar_write_intents"
            intent_path = next(intent_dir.glob("*.json"))
            receipt_dir = (
                root / "exports" / "card_sidecar_recovery_receipts"
            )
            retirement_dir = (
                root / "run" / "card_sidecar_retirement_intents"
            )
            real_flush_directory = store_module.flush_directory_strict
            source_flush_failed = False

            def fail_source_flush_once(path: Path) -> None:
                nonlocal source_flush_failed
                if (
                    Path(path) == intent_dir
                    and receipt_dir.is_dir()
                    and not intent_path.exists()
                    and not source_flush_failed
                ):
                    source_flush_failed = True
                    raise OSError("synthetic source namespace flush failure")
                real_flush_directory(Path(path))

            with patch.object(
                store_module,
                "flush_directory_strict",
                side_effect=fail_source_flush_once,
            ):
                interrupted = (
                    store_module.reconcile_card_sidecar_write_intents(
                        root,
                        limit=1,
                    )
                )

            self.assertTrue(source_flush_failed)
            self.assertFalse(interrupted["ok"], interrupted)
            self.assertFalse(intent_path.exists())
            pending_retirements = list(retirement_dir.glob("*.json"))
            self.assertEqual(len(pending_retirements), 1)
            pending_integrity = semantic_integrity_report(root)
            self.assertFalse(pending_integrity["ok"], pending_integrity)
            self.assertEqual(
                pending_integrity["checks"][
                    "unresolved_card_sidecar_retirement_intents"
                ],
                1,
            )

            resumed = store_module.reconcile_card_sidecar_write_intents(
                root,
                limit=1,
            )

            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["processed"], 1)
            self.assertEqual(resumed["remaining"], 0)
            self.assertTrue(resumed["complete"])
            self.assertFalse(pending_retirements[0].exists())
            self.assertEqual(
                len(
                    list(
                        (
                            root
                            / "exports"
                            / "card_sidecar_resolved_intents"
                        ).glob("*.json")
                    )
                ),
                1,
            )

    def test_terminal_retirement_flush_failures_restore_retry_authority(
        self,
    ) -> None:
        for boundary in ("resolved_destination",):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                card_ids = self._create_pending_sidecar_cards(
                    root,
                    count=1,
                    namespace=f"terminal-retirement-{boundary}",
                )
                with (
                    patch.object(
                        store_module,
                        "reconcile_card_sidecar_write_intents",
                        side_effect=SystemExit(
                            "simulated process death before intent reconciliation"
                        ),
                    ),
                    self.assertRaises(SystemExit),
                ):
                    sync_card_sidecars_after_commit(root, card_ids)

                intent_dir = root / "run" / "card_sidecar_write_intents"
                retirement_dir = (
                    root / "run" / "card_sidecar_retirement_intents"
                )
                resolved_dir = (
                    root / "exports" / "card_sidecar_resolved_intents"
                )
                real_flush_directory = store_module.flush_directory_strict
                injected_failure = False

                def fail_terminal_boundary_once(path: Path) -> None:
                    nonlocal injected_failure
                    requested_path = Path(path)
                    boundary_path = (
                        resolved_dir
                        if boundary == "resolved_destination"
                        else retirement_dir
                    )
                    if (
                        requested_path == boundary_path
                        and not injected_failure
                        and any(resolved_dir.glob("*.json"))
                        and (
                            boundary == "resolved_destination"
                            or not any(retirement_dir.glob("*.json"))
                        )
                    ):
                        injected_failure = True
                        raise OSError(
                            f"synthetic {boundary} strict flush failure"
                        )
                    real_flush_directory(requested_path)

                with patch.object(
                    store_module,
                    "flush_directory_strict",
                    side_effect=fail_terminal_boundary_once,
                ):
                    interrupted = (
                        store_module.reconcile_card_sidecar_write_intents(
                            root,
                            limit=1,
                        )
                    )

                self.assertTrue(injected_failure)
                active_paths = list(intent_dir.glob("*.json"))
                retirement_paths = list(retirement_dir.glob("*.json"))
                self.assertFalse(interrupted["ok"], interrupted)
                self.assertEqual(interrupted["remaining"], 1, interrupted)
                self.assertFalse(interrupted["complete"], interrupted)
                self.assertTrue(interrupted["has_more"], interrupted)
                self.assertEqual(
                    len(active_paths) + len(retirement_paths),
                    1,
                    (active_paths, retirement_paths),
                )
                self.assertTrue(retirement_paths)
                resumed = (
                    store_module.reconcile_card_sidecar_write_intents(
                        root,
                        limit=1,
                    )
                )
                self.assertTrue(resumed["ok"], resumed)
                self.assertEqual(resumed["processed"], 1)
                self.assertEqual(resumed["remaining"], 0)
                self.assertTrue(resumed["complete"])
                self.assertFalse(list(intent_dir.glob("*.json")))
                self.assertFalse(list(retirement_dir.glob("*.json")))
                self.assertEqual(
                    len(list(resolved_dir.glob("*.json"))),
                    1,
                )

    def test_init_readiness_replays_pending_retirement_queue(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            card_ids = self._create_pending_sidecar_cards(
                root,
                count=1,
                namespace="init-readiness-retirement-queue",
            )
            with (
                patch.object(
                    store_module,
                    "reconcile_card_sidecar_write_intents",
                    side_effect=SystemExit(
                        "simulated process death before intent reconciliation"
                    ),
                ),
                self.assertRaises(SystemExit),
            ):
                sync_card_sidecars_after_commit(root, card_ids)

            intent_dir = root / "run" / "card_sidecar_write_intents"
            intent_path = next(intent_dir.glob("*.json"))
            receipt_dir = (
                root / "exports" / "card_sidecar_recovery_receipts"
            )
            retirement_dir = (
                root / "run" / "card_sidecar_retirement_intents"
            )
            real_flush_directory = store_module.flush_directory_strict
            source_flush_failed = False

            def fail_source_flush_once(path: Path) -> None:
                nonlocal source_flush_failed
                if (
                    Path(path) == intent_dir
                    and receipt_dir.is_dir()
                    and not intent_path.exists()
                    and not source_flush_failed
                ):
                    source_flush_failed = True
                    raise OSError("synthetic source namespace flush failure")
                real_flush_directory(Path(path))

            with patch.object(
                store_module,
                "flush_directory_strict",
                side_effect=fail_source_flush_once,
            ):
                interrupted = (
                    store_module.reconcile_card_sidecar_write_intents(
                        root,
                        limit=1,
                    )
                )

            self.assertFalse(interrupted["ok"], interrupted)
            self.assertEqual(len(list(retirement_dir.glob("*.json"))), 1)
            cache_key = str(root.resolve(strict=False))
            store_module._INIT_DB_CACHE.add(cache_key)
            self.assertFalse(store_module._init_db_durable_ready(root))

            with patch.object(
                store_module,
                "reconcile_card_sidecar_write_intents",
                wraps=store_module.reconcile_card_sidecar_write_intents,
            ) as recovery:
                init_db(root)

            self.assertGreaterEqual(recovery.call_count, 1)
            self.assertFalse(list(intent_dir.glob("*.json")))
            self.assertFalse(list(retirement_dir.glob("*.json")))
            self.assertTrue(store_module._init_db_durable_ready(root))
            self.assertIn(cache_key, store_module._INIT_DB_CACHE)

    def test_resolved_intent_retirement_preserves_racing_replacements(
        self,
    ) -> None:
        for boundary in ("leaf", "directory"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                init_db(root)
                conn = connect(root)
                try:
                    card_id = create_card(
                        conn,
                        root=root,
                        card_type="note",
                        title=f"retirement-{boundary}-replacement",
                        summary="A racing replacement must never be deleted.",
                        source_refs=[],
                    )
                    row = conn.execute(
                        "SELECT * FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()
                    payload = store_module._card_sidecar_payload_for_row(row)
                    conn.commit()
                finally:
                    conn.close()
                _intent_id, intent_path = (
                    store_module._write_card_sidecar_write_intent(
                        root,
                        card_id=card_id,
                        target_uri=f"catalog/cards/{card_id}.yaml",
                        expected_state_hash=str(payload["state_hash"]),
                    )
                )
                intent = json.loads(intent_path.read_text(encoding="utf-8"))
                intent_identity = (
                    store_module._plain_card_sidecar_state_path_identity(
                        intent_path,
                        directory=False,
                    )
                )
                original_bytes = intent_path.read_bytes()
                replacement_bytes = (
                    b'{"replacement":"must remain preserved"}\n'
                )
                real_replace = store_module.replace_file_noclobber
                swapped = False
                if boundary == "leaf":
                    preserved_original = intent_path.with_suffix(
                        ".original"
                    )
                else:
                    original_intent_dir = intent_path.parent
                    preserved_dir = original_intent_dir.with_name(
                        f"{original_intent_dir.name}-original"
                    )
                    preserved_original = preserved_dir / intent_path.name

                def swap_then_move(
                    source: Path,
                    destination: Path,
                ) -> None:
                    nonlocal swapped
                    if Path(source) == intent_path and not swapped:
                        swapped = True
                        if boundary == "leaf":
                            os.replace(intent_path, preserved_original)
                        else:
                            os.rename(intent_path.parent, preserved_dir)
                            intent_path.parent.mkdir()
                        intent_path.write_bytes(replacement_bytes)
                    real_replace(Path(source), Path(destination))

                with (
                    patch.object(
                        store_module,
                        "replace_file_noclobber",
                        side_effect=swap_then_move,
                    ),
                    self.assertRaises(ValueError),
                ):
                    store_module._retire_card_sidecar_write_intent(
                        root,
                        intent_path=intent_path,
                        intent=intent,
                        intent_entry_identity=intent_identity,
                    )

                self.assertTrue(swapped)
                self.assertEqual(
                    preserved_original.read_bytes(),
                    original_bytes,
                )
                replacement_locations = [
                    path
                    for path in (
                        intent_path,
                        *(
                            root
                            / "run"
                            / "card_sidecar_retirement_intents"
                        ).glob("*.json"),
                    )
                    if path.is_file()
                ]
                self.assertIn(
                    replacement_bytes,
                    [path.read_bytes() for path in replacement_locations],
                )

    def test_portable_retirement_archives_final_racing_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            card_ids = self._create_pending_sidecar_cards(
                root,
                count=1,
                namespace="portable-final-retirement-race",
            )
            with (
                patch.object(
                    store_module,
                    "reconcile_card_sidecar_write_intents",
                    side_effect=SystemExit(
                        "simulated process death before intent reconciliation"
                    ),
                ),
                self.assertRaises(SystemExit),
            ):
                sync_card_sidecars_after_commit(root, card_ids)

            active_dir = root / "run" / "card_sidecar_write_intents"
            original_active = next(active_dir.glob("*.json"))
            original_bytes = original_active.read_bytes()
            original_metadata = os.lstat(original_active)
            original_identity = (
                int(original_metadata.st_dev),
                int(original_metadata.st_ino),
            )
            detached_original = (
                root / "exports" / "portable-detached-original.json"
            )
            real_replace = store_module.replace_file_noclobber
            swapped = False
            replacement_identity: tuple[int, int] | None = None
            replacement_archive: Path | None = None

            def swap_at_final_move(
                source: Path,
                destination: Path,
            ) -> None:
                nonlocal swapped
                nonlocal replacement_identity
                nonlocal replacement_archive
                source = Path(source)
                destination = Path(destination)
                if destination.name.endswith(".retired") and not swapped:
                    swapped = True
                    os.replace(source, detached_original)
                    source.write_bytes(original_bytes)
                    replacement_metadata = os.lstat(source)
                    replacement_identity = (
                        int(replacement_metadata.st_dev),
                        int(replacement_metadata.st_ino),
                    )
                    replacement_archive = destination
                real_replace(source, destination)

            with (
                patch.object(
                    store_module,
                    "guard_windows_file_disposition",
                    side_effect=lambda **_kwargs: nullcontext(None),
                ),
                patch.object(
                    store_module,
                    "replace_file_noclobber",
                    side_effect=swap_at_final_move,
                ),
            ):
                interrupted = (
                    store_module.reconcile_card_sidecar_write_intents(
                        root,
                        limit=1,
                    )
                )

            self.assertTrue(swapped)
            self.assertNotEqual(replacement_identity, original_identity)
            self.assertFalse(interrupted["ok"], interrupted)
            self.assertFalse(interrupted["complete"], interrupted)
            self.assertTrue(interrupted["has_more"], interrupted)
            self.assertEqual(interrupted["remaining"], 1, interrupted)
            self.assertEqual(detached_original.read_bytes(), original_bytes)
            self.assertIsNotNone(replacement_archive)
            assert replacement_archive is not None
            self.assertEqual(
                replacement_archive.read_bytes(),
                original_bytes,
            )
            archived_metadata = os.lstat(replacement_archive)
            self.assertEqual(
                (
                    int(archived_metadata.st_dev),
                    int(archived_metadata.st_ino),
                ),
                replacement_identity,
            )
            fresh_intents = list(active_dir.glob("*.json"))
            self.assertEqual(len(fresh_intents), 1, interrupted)
            self.assertNotEqual(fresh_intents[0].name, original_active.name)

            resumed = store_module.reconcile_card_sidecar_write_intents(
                root,
                limit=1,
            )

            self.assertTrue(resumed["ok"], resumed)
            self.assertTrue(resumed["complete"], resumed)
            self.assertEqual(resumed["remaining"], 0, resumed)
            self.assertFalse(list(active_dir.glob("*.json")))
            self.assertEqual(
                replacement_archive.read_bytes(),
                original_bytes,
            )

    def test_portable_final_move_disappearance_publishes_fresh_retry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            card_ids = self._create_pending_sidecar_cards(
                root,
                count=1,
                namespace="portable-final-move-disappearance",
            )
            with (
                patch.object(
                    store_module,
                    "reconcile_card_sidecar_write_intents",
                    side_effect=SystemExit(
                        "simulated process death before intent reconciliation"
                    ),
                ),
                self.assertRaises(SystemExit),
            ):
                sync_card_sidecars_after_commit(root, card_ids)

            active_dir = root / "run" / "card_sidecar_write_intents"
            original_active = next(active_dir.glob("*.json"))
            original_bytes = original_active.read_bytes()
            detached = root / "exports" / "portable-vanished-queue.json"
            real_replace = store_module.replace_file_noclobber
            disappeared = False

            def disappear_at_final_move(
                source: Path,
                destination: Path,
            ) -> None:
                nonlocal disappeared
                source = Path(source)
                destination = Path(destination)
                if destination.name.endswith(".retired") and not disappeared:
                    disappeared = True
                    os.replace(source, detached)
                    raise FileNotFoundError(
                        "synthetic final portable move disappearance"
                    )
                real_replace(source, destination)

            with (
                patch.object(
                    store_module,
                    "guard_windows_file_disposition",
                    side_effect=lambda **_kwargs: nullcontext(None),
                ),
                patch.object(
                    store_module,
                    "replace_file_noclobber",
                    side_effect=disappear_at_final_move,
                ),
            ):
                interrupted = (
                    store_module.reconcile_card_sidecar_write_intents(
                        root,
                        limit=1,
                    )
                )

            self.assertTrue(disappeared)
            self.assertFalse(interrupted["ok"], interrupted)
            self.assertFalse(interrupted["complete"], interrupted)
            self.assertEqual(interrupted["remaining"], 1, interrupted)
            self.assertEqual(detached.read_bytes(), original_bytes)
            fresh_intents = list(active_dir.glob("*.json"))
            self.assertEqual(len(fresh_intents), 1, interrupted)
            self.assertNotEqual(fresh_intents[0].name, original_active.name)

    @unittest.skipUnless(
        os.name == "nt",
        "Windows exact-handle durability is required for this regression",
    )
    def test_windows_guard_flushes_byte_equal_terminal_replacement(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            card_ids = self._create_pending_sidecar_cards(
                root,
                count=1,
                namespace="windows-terminal-replacement-flush",
            )
            with (
                patch.object(
                    store_module,
                    "reconcile_card_sidecar_write_intents",
                    side_effect=SystemExit(
                        "simulated process death before intent reconciliation"
                    ),
                ),
                self.assertRaises(SystemExit),
            ):
                sync_card_sidecars_after_commit(root, card_ids)

            real_guard = store_module.guard_windows_file_disposition
            swapped = False
            replacement_identity: tuple[int, int] | None = None

            @contextmanager
            def replace_terminal_then_guard(
                **kwargs: object,
            ):
                nonlocal swapped
                nonlocal replacement_identity
                terminal_path = Path(str(kwargs["terminal_path"]))
                terminal_bytes = terminal_path.read_bytes()
                preserved = terminal_path.with_name(
                    f"{terminal_path.name}.preflush"
                )
                os.replace(terminal_path, preserved)
                terminal_path.write_bytes(terminal_bytes)
                metadata = os.lstat(terminal_path)
                replacement_identity = (
                    int(metadata.st_dev),
                    int(metadata.st_ino),
                )
                swapped = True
                with real_guard(**kwargs) as guarded:
                    yield guarded

            with (
                patch.object(
                    store_module,
                    "guard_windows_file_disposition",
                    side_effect=replace_terminal_then_guard,
                ),
                patch.object(
                    permissions_module,
                    "_flush_windows_handle_strict",
                    wraps=(
                        permissions_module
                        ._flush_windows_handle_strict
                    ),
                ) as exact_flush,
            ):
                reconciled = (
                    store_module.reconcile_card_sidecar_write_intents(
                        root,
                        limit=1,
                    )
                )

            self.assertTrue(swapped)
            self.assertIsNotNone(replacement_identity)
            self.assertGreaterEqual(exact_flush.call_count, 2)
            self.assertTrue(reconciled["ok"], reconciled)
            self.assertTrue(reconciled["complete"], reconciled)
            self.assertEqual(reconciled["remaining"], 0)
            self.assertFalse(
                list(
                    (
                        root
                        / "run"
                        / "card_sidecar_retirement_intents"
                    ).glob("*.json")
                )
            )

    @unittest.skipUnless(
        os.name == "nt",
        "Windows namespace guards are required for this regression",
    )
    def test_retirement_disposition_failure_preserves_guarded_retry_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            card_ids = self._create_pending_sidecar_cards(
                root,
                count=1,
                namespace="resolved-directory-swap-retry",
            )
            with (
                patch.object(
                    store_module,
                    "reconcile_card_sidecar_write_intents",
                    side_effect=SystemExit(
                        "simulated process death before intent reconciliation"
                    ),
                ),
                self.assertRaises(SystemExit),
            ):
                sync_card_sidecars_after_commit(root, card_ids)

            intent_dir = root / "run" / "card_sidecar_write_intents"
            active_intent_path = next(intent_dir.glob("*.json"))
            active_intent_metadata = os.lstat(active_intent_path)
            original_queue_identity = (
                int(active_intent_metadata.st_dev),
                int(active_intent_metadata.st_ino),
            )
            original_queue_bytes = active_intent_path.read_bytes()
            retirement_dir = (
                root / "run" / "card_sidecar_retirement_intents"
            )
            resolved_dir = (
                root / "exports" / "card_sidecar_resolved_intents"
            )
            preserved_resolved_dir = resolved_dir.with_name(
                f"{resolved_dir.name}-detached"
            )
            disposition_attempted = False
            rename_blocked = False
            observed_queue_identity: tuple[int, int] | None = None

            def fail_guarded_disposition(_handle: int) -> None:
                nonlocal disposition_attempted
                nonlocal rename_blocked
                nonlocal observed_queue_identity
                disposition_attempted = True
                queue_paths = list(retirement_dir.glob("*.json"))
                if len(queue_paths) != 1:
                    raise AssertionError(
                        "guarded retirement queue is not singular"
                    )
                queue_path = queue_paths[0]
                queue_metadata = os.lstat(queue_path)
                observed_queue_identity = (
                    int(queue_metadata.st_dev),
                    int(queue_metadata.st_ino),
                )
                try:
                    os.rename(resolved_dir, preserved_resolved_dir)
                except OSError:
                    rename_blocked = True
                else:
                    raise AssertionError(
                        "resolved intent directory escaped its Windows guard"
                    )
                raise OSError("synthetic guarded disposition failure")

            with patch.object(
                store_module,
                "set_windows_delete_disposition",
                side_effect=fail_guarded_disposition,
            ):
                interrupted = (
                    store_module.reconcile_card_sidecar_write_intents(
                        root,
                        limit=1,
                    )
                )

            self.assertTrue(disposition_attempted)
            self.assertTrue(rename_blocked)
            self.assertFalse(interrupted["ok"], interrupted)
            self.assertEqual(interrupted["remaining"], 1, interrupted)
            self.assertFalse(interrupted["complete"], interrupted)
            self.assertTrue(interrupted["has_more"], interrupted)
            queue_paths = list(retirement_dir.glob("*.json"))
            self.assertEqual(len(queue_paths), 1)
            queue_metadata = os.lstat(queue_paths[0])
            self.assertEqual(
                (
                    int(queue_metadata.st_dev),
                    int(queue_metadata.st_ino),
                ),
                observed_queue_identity,
            )
            self.assertEqual(observed_queue_identity, original_queue_identity)
            self.assertEqual(queue_paths[0].read_bytes(), original_queue_bytes)
            self.assertFalse(preserved_resolved_dir.exists())
            self.assertEqual(len(list(resolved_dir.glob("*.json"))), 1)
            self.assertFalse(list(resolved_dir.glob("*.retired")))

            resumed = store_module.reconcile_card_sidecar_write_intents(
                root,
                limit=1,
            )

            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["processed"], 1)
            self.assertEqual(resumed["remaining"], 0)
            self.assertTrue(resumed["complete"])
            self.assertFalse(list(retirement_dir.glob("*.json")))
            self.assertEqual(len(list(resolved_dir.glob("*.json"))), 1)

    @unittest.skipUnless(
        os.name == "nt",
        "Windows handle disposition is required for this regression",
    )
    def test_successful_retirement_disposition_has_no_postcommit_gate(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            card_ids = self._create_pending_sidecar_cards(
                root,
                count=1,
                namespace="retirement-one-way-commit",
            )
            with (
                patch.object(
                    store_module,
                    "reconcile_card_sidecar_write_intents",
                    side_effect=SystemExit(
                        "simulated process death before intent reconciliation"
                    ),
                ),
                self.assertRaises(SystemExit),
            ):
                sync_card_sidecars_after_commit(root, card_ids)

            retirement_dir = (
                root / "run" / "card_sidecar_retirement_intents"
            )
            resolved_dir = (
                root / "exports" / "card_sidecar_resolved_intents"
            )
            real_disposition = (
                store_module.set_windows_delete_disposition
            )
            real_flush_directory = store_module.flush_directory_strict
            committed = False

            def commit_disposition(handle: int) -> None:
                nonlocal committed
                real_disposition(handle)
                committed = True

            def reject_postcommit_flush(path: Path) -> None:
                if committed:
                    raise AssertionError(
                        "fallible directory proof ran after retirement commit"
                    )
                real_flush_directory(Path(path))

            with (
                patch.object(
                    store_module,
                    "set_windows_delete_disposition",
                    side_effect=commit_disposition,
                ),
                patch.object(
                    store_module,
                    "flush_directory_strict",
                    side_effect=reject_postcommit_flush,
                ),
            ):
                reconciled = (
                    store_module.reconcile_card_sidecar_write_intents(
                        root,
                        limit=1,
                    )
                )

            self.assertTrue(committed)
            self.assertTrue(reconciled["ok"], reconciled)
            self.assertEqual(reconciled["remaining"], 0)
            self.assertTrue(reconciled["complete"])
            self.assertFalse(list(retirement_dir.glob("*.json")))
            self.assertEqual(len(list(resolved_dir.glob("*.json"))), 1)

    def test_intent_retirement_access_error_is_not_reported_missing(
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
                    title="retirement-access-error",
                    summary="An inaccessible intent remains unresolved authority.",
                    source_refs=[],
                )
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                payload = store_module._card_sidecar_payload_for_row(row)
                conn.commit()
            finally:
                conn.close()
            _intent_id, intent_path = (
                store_module._write_card_sidecar_write_intent(
                    root,
                    card_id=card_id,
                    target_uri=f"catalog/cards/{card_id}.yaml",
                    expected_state_hash=str(payload["state_hash"]),
                )
            )
            intent = json.loads(intent_path.read_text(encoding="utf-8"))
            intent_identity = (
                store_module._plain_card_sidecar_state_path_identity(
                    intent_path,
                    directory=False,
                )
            )
            real_lstat = store_module.os.lstat

            def deny_intent_lstat(path: object) -> os.stat_result:
                if Path(path) == intent_path:
                    raise PermissionError("intent metadata unavailable")
                return real_lstat(path)

            with (
                patch.object(
                    store_module.os,
                    "lstat",
                    side_effect=deny_intent_lstat,
                ),
                self.assertRaisesRegex(
                    ValueError,
                    "absence check failed",
                ),
            ):
                store_module._retire_card_sidecar_write_intent(
                    root,
                    intent_path=intent_path,
                    intent=intent,
                    intent_entry_identity=intent_identity,
                )

            self.assertTrue(intent_path.is_file())

    def test_receipt_cannot_spoof_concurrent_completion(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            card_ids = self._create_pending_sidecar_cards(
                root,
                count=1,
                namespace="receipt-concurrent-completion-spoof",
            )
            with (
                patch.object(
                    store_module,
                    "reconcile_card_sidecar_write_intents",
                    side_effect=SystemExit(
                        "simulated process death before intent reconciliation"
                    ),
                ),
                self.assertRaises(SystemExit),
            ):
                sync_card_sidecars_after_commit(root, card_ids)
            with patch.object(
                store_module,
                "_retire_card_sidecar_write_intent",
                side_effect=OSError("stop after durable receipt publication"),
            ):
                interrupted = (
                    store_module.reconcile_card_sidecar_write_intents(
                        root,
                        limit=1,
                    )
                )
            self.assertFalse(interrupted["ok"], interrupted)
            intent_paths = list(
                (
                    root / "run" / "card_sidecar_write_intents"
                ).glob("*.json")
            )
            receipt_paths = list(
                (
                    root
                    / "exports"
                    / "card_sidecar_recovery_receipts"
                ).glob("*.json")
            )
            self.assertEqual(len(intent_paths), 1)
            self.assertEqual(len(receipt_paths), 1)
            receipt = json.loads(
                receipt_paths[0].read_text(encoding="utf-8")
            )
            receipt["concurrent_completion"] = True
            receipt_paths[0].write_text(
                json.dumps(receipt, sort_keys=True) + "\n",
                encoding="utf-8",
            )

            resumed = store_module.reconcile_card_sidecar_write_intents(
                root,
                limit=1,
            )

            self.assertTrue(resumed["ok"], resumed)
            self.assertFalse(
                resumed["results"][0]["concurrent_completion"],
                resumed,
            )
            self.assertFalse(intent_paths[0].exists())

    def test_worker_reports_final_intent_state_after_outbox_recovery(
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
                    title="worker-outbox-intent-ordering",
                    summary="Initial sidecar state.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            initial_sync = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(initial_sync["ok"], initial_sync)

            conn = connect(root)
            try:
                default_uri = str(
                    conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()["location_uri"]
                )
                default_path = resolve_stored_uri(root, default_uri)
                default_bytes = default_path.read_bytes()
                store_module.record_artifact(
                    conn,
                    kind="proof_input",
                    uri=default_uri,
                    sha256=hashlib.sha256(default_bytes).hexdigest(),
                    size_bytes=len(default_bytes),
                    source_type="worker_outbox_intent_ordering",
                    trust_level="local_generated",
                    immutable=True,
                )
                conn.execute(
                    "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                    (
                        "Outbox must resolve the durable write before final intent status.",
                        store_module.utc_now(),
                        card_id,
                    ),
                )
                store_module.mark_card_sidecar_outbox(
                    conn,
                    [card_id],
                    reason="worker_outbox_intent_ordering",
                )
                conn.commit()
            finally:
                conn.close()

            observation: dict[str, object] = {}
            conn = connect(root)
            try:
                conn.execute("BEGIN IMMEDIATE")
                artifact_index = store_module._immutable_artifact_path_index(
                    root,
                    conn,
                )
                store_module.sync_card_sidecar(
                    root,
                    conn,
                    card_id,
                    artifact_index=artifact_index,
                    write_observation=observation,
                )
                self.assertTrue(observation.get("write_completed"))
                conn.rollback()
            finally:
                conn.close()

            intent_dir = root / "run" / "card_sidecar_write_intents"
            self.assertEqual(len(list(intent_dir.glob("*.json"))), 1)
            conn = connect_existing(root)
            try:
                self.assertEqual(
                    int(
                        conn.execute(
                            "SELECT count(*) AS n FROM card_sidecar_outbox "
                            "WHERE card_id = ?",
                            (card_id,),
                        ).fetchone()["n"]
                    ),
                    1,
                )
            finally:
                conn.close()

            worker = run_worker_pass(
                root,
                limit=1,
                maintenance=True,
            )

            self.assertTrue(worker["ok"], worker)
            self.assertEqual(worker["maintenance"]["sidecars"]["synced"], 1)
            final_intents = worker["maintenance"]["sidecar_intents"]
            self.assertTrue(final_intents["ok"], worker)
            self.assertEqual(final_intents["pending"], 0)
            self.assertEqual(final_intents["remaining"], 0)
            self.assertTrue(final_intents["complete"])
            self.assertFalse(final_intents["has_more"])
            self.assertFalse(list(intent_dir.glob("*.json")))

    def test_worker_continues_bounded_outbox_backed_intent_retry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            self._create_pending_sidecar_cards(
                root,
                count=50,
                namespace="worker-bounded-outbox-intent-retry",
            )
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="worker-bounded-outbox-intent-retry-tail",
                    summary="Initial tail sidecar state.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            initial_sync = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(initial_sync["ok"], initial_sync)

            conn = connect(root)
            try:
                default_uri = str(
                    conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()["location_uri"]
                )
                default_path = resolve_stored_uri(root, default_uri)
                default_bytes = default_path.read_bytes()
                store_module.record_artifact(
                    conn,
                    kind="proof_input",
                    uri=default_uri,
                    sha256=hashlib.sha256(default_bytes).hexdigest(),
                    size_bytes=len(default_bytes),
                    source_type="worker_bounded_outbox_intent_retry",
                    trust_level="local_generated",
                    immutable=True,
                )
                conn.execute(
                    "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                    (
                        "The bounded tail remains durable continuation work.",
                        store_module.utc_now(),
                        card_id,
                    ),
                )
                store_module.mark_card_sidecar_outbox(
                    conn,
                    [card_id],
                    reason="worker_bounded_outbox_intent_retry",
                )
                conn.commit()
            finally:
                conn.close()

            observation: dict[str, object] = {}
            conn = connect(root)
            try:
                conn.execute("BEGIN IMMEDIATE")
                store_module.sync_card_sidecar(
                    root,
                    conn,
                    card_id,
                    artifact_index=store_module._immutable_artifact_path_index(
                        root,
                        conn,
                    ),
                    write_observation=observation,
                )
                self.assertTrue(observation.get("write_completed"))
                conn.rollback()
            finally:
                conn.close()

            first = run_worker_pass(
                root,
                limit=1,
                maintenance=True,
            )

            first_intents = first["maintenance"]["sidecar_intents"]
            self.assertTrue(first["ok"], first)
            self.assertEqual(first["maintenance"]["sidecars"]["synced"], 50)
            self.assertTrue(first_intents["ok"], first)
            self.assertEqual(first_intents["selected"], 50)
            self.assertEqual(first_intents["processed"], 50)
            self.assertIn(first_intents["pending"], {0, 1})
            self.assertEqual(
                sum(first_intents["status_counts"].values()),
                50,
            )
            self.assertEqual(
                first_intents["status_counts"].get(
                    "pending_retry",
                    0,
                ),
                first_intents["pending"],
            )
            self.assertEqual(first_intents["remaining"], 1)
            self.assertTrue(first_intents["remaining_is_lower_bound"])
            self.assertFalse(first_intents["complete"])
            self.assertTrue(first_intents["has_more"])

            service = worker_module.serve_workers(
                root,
                limit=2,
                interval_seconds=0.1,
                maintenance_interval_seconds=1.0,
                maintenance_on_start=True,
            )

            self.assertTrue(service["ok"], service)
            conn = connect_existing(root)
            try:
                self.assertEqual(
                    int(
                        conn.execute(
                            "SELECT count(*) AS n FROM card_sidecar_outbox"
                        ).fetchone()["n"]
                    ),
                    0,
                )
            finally:
                conn.close()
            self.assertFalse(
                list(
                    (
                        root / "run" / "card_sidecar_write_intents"
                    ).glob("*.json")
                )
            )

    def test_malformed_orphan_intent_fails_worker_and_service_truthfully(
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
                    title="malformed-worker-orphan-intent",
                    summary="Malformed recovery evidence must fail closed.",
                    source_refs=[],
                )
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                payload = store_module._card_sidecar_payload_for_row(row)
                conn.execute(
                    "DELETE FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                )
                conn.execute("DELETE FROM queue_jobs")
                conn.commit()
            finally:
                conn.close()
            _intent_id, intent_path = (
                store_module._write_card_sidecar_write_intent(
                    root,
                    card_id=card_id,
                    target_uri=f"catalog/cards/{card_id}.yaml",
                    expected_state_hash=str(payload["state_hash"]),
                )
            )
            intent_path.write_text("{", encoding="utf-8")

            worker = run_worker_pass(
                root,
                limit=1,
                maintenance=True,
            )

            intent_result = worker["maintenance"]["sidecar_intents"]
            self.assertFalse(worker["ok"], worker)
            self.assertFalse(intent_result["ok"], worker)
            self.assertEqual(intent_result["failure_count"], 1)
            self.assertTrue(intent_path.is_file())

            service = worker_module.serve_workers(
                root,
                limit=3,
                interval_seconds=0.1,
            )

            self.assertFalse(service["ok"], service)
            self.assertEqual(service["reason"], "worker_pass_failed")
            self.assertEqual(service["passes"], 1)
            self.assertFalse(service["failed_pass"]["ok"])
            self.assertTrue(intent_path.is_file())

    def test_sidecar_intent_unknown_count_has_zero_lower_bound(
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
                    title="unknown-intent-count",
                    summary="An unavailable scan must not invent pending work.",
                    source_refs=[],
                )
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                payload = store_module._card_sidecar_payload_for_row(row)
                conn.commit()
            finally:
                conn.close()
            store_module._write_card_sidecar_write_intent(
                root,
                card_id=card_id,
                target_uri=f"catalog/cards/{card_id}.yaml",
                expected_state_hash=str(payload["state_hash"]),
            )

            with patch.object(
                store_module,
                "_bounded_card_sidecar_intent_inventory",
                side_effect=OSError("intent namespace unavailable"),
            ):
                result = store_module.reconcile_card_sidecar_write_intents(
                    root,
                    limit=50,
                )

            self.assertFalse(result["ok"], result)
            self.assertIsNone(result["remaining"])
            self.assertTrue(result["remaining_is_lower_bound"])
            self.assertEqual(result["remaining_lower_bound"], 0)
            self.assertFalse(result["complete"])
            self.assertTrue(result["has_more"])

    def test_worker_intent_scan_exception_does_not_invent_pending_work(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)

            with patch.object(
                worker_module,
                "reconcile_card_sidecar_write_intents",
                side_effect=OSError("intent scan unavailable"),
            ):
                result = run_worker_pass(
                    root,
                    limit=1,
                    maintenance=True,
                )

            intent_result = result["maintenance"]["sidecar_intents"]
            self.assertFalse(result["ok"], result)
            self.assertFalse(intent_result["ok"], result)
            self.assertEqual(intent_result["pending"], 0)
            self.assertIsNone(intent_result["remaining"])
            self.assertTrue(intent_result["remaining_is_lower_bound"])
            self.assertEqual(intent_result["remaining_lower_bound"], 0)
            self.assertFalse(intent_result["complete"])
            self.assertTrue(intent_result["has_more"])
            self.assertEqual(intent_result["failure_count"], 1)
            self.assertEqual(intent_result["enumerated"], 0)

    def test_worker_card_review_does_not_recover_unrelated_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            card_ids = self._create_pending_sidecar_cards(
                root,
                count=2,
                namespace="bounded-librarian-review",
            )
            target_id, unrelated_id = card_ids
            conn = connect(root)
            try:
                enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_card_placement",
                    priority=1,
                    payload={"card_id": target_id},
                    related_card_ids=[target_id],
                    dedupe_key=f"bounded-review:{target_id}",
                )
                locations = {
                    str(row["id"]): str(row["location_uri"])
                    for row in conn.execute(
                        "SELECT id, location_uri FROM cards WHERE id IN (?, ?)",
                        (target_id, unrelated_id),
                    )
                }
                conn.commit()
            finally:
                conn.close()

            with patch.object(
                store_module,
                "sync_pending_card_sidecars",
                wraps=store_module.sync_pending_card_sidecars,
            ) as generic_recovery:
                result = run_worker_pass(
                    root,
                    roles=["librarian"],
                    limit=1,
                    maintenance=False,
                )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["processed_count"], 1)
            generic_recovery.assert_not_called()
            conn = connect_existing(root)
            try:
                pending_ids = {
                    str(row["card_id"])
                    for row in conn.execute(
                        "SELECT card_id FROM card_sidecar_outbox"
                    )
                }
            finally:
                conn.close()
            self.assertNotIn(target_id, pending_ids)
            self.assertIn(unrelated_id, pending_ids)
            self.assertTrue(resolve_stored_uri(root, locations[target_id]).exists())
            self.assertFalse(
                resolve_stored_uri(root, locations[unrelated_id]).exists()
            )

    def test_worker_pass_requeues_review_deferred_after_prior_job_uses_intent_budget(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                first_card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="Budget leader",
                    summary="This review consumes the shared intent budget.",
                    source_refs=[],
                )
                deferred_card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="Budget follower",
                    summary="This review must retain queue retry authority.",
                    source_refs=[],
                )
                first_row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (first_card_id,),
                ).fetchone()
                first_payload = store_module._card_sidecar_payload_for_row(
                    first_row
                )
                conn.execute("DELETE FROM queue_jobs")
                first_job_id = enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_card_placement",
                    priority=1,
                    payload={"card_id": first_card_id},
                    related_card_ids=[first_card_id],
                )
                deferred_job_id = enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_card_placement",
                    priority=2,
                    payload={"card_id": deferred_card_id},
                    related_card_ids=[deferred_card_id],
                )
                conn.commit()
            finally:
                conn.close()

            for _index in range(49):
                store_module._write_card_sidecar_write_intent(
                    root,
                    card_id=first_card_id,
                    target_uri=str(first_row["location_uri"]),
                    expected_state_hash=str(first_payload["state_hash"]),
                )

            first_pass = run_worker_pass(
                root,
                roles=["librarian"],
                limit=2,
                maintenance=False,
            )

            self.assertFalse(first_pass["ok"], first_pass)
            self.assertEqual(
                first_pass["sidecar_intent_budget"]["remaining"],
                0,
                first_pass,
            )
            self.assertEqual(
                [item["job_id"] for item in first_pass["processed"]],
                [first_job_id, deferred_job_id],
                first_pass,
            )
            self.assertEqual(
                first_pass["processed"][0]["status"],
                "succeeded",
                first_pass,
            )
            deferred = first_pass["processed"][1]
            self.assertEqual(deferred["status"], "pending", deferred)
            self.assertFalse(deferred["result"]["ok"], deferred)
            self.assertTrue(deferred["result"]["retry_pending"], deferred)
            self.assertEqual(
                deferred["result"]["reason"],
                worker_module.POST_COMMIT_SIDECAR_RETRY_REASON,
            )

            conn = connect_existing(root)
            try:
                queue_row = conn.execute(
                    """
                    SELECT status, attempt_count, finished_at, lease_owner,
                           error_json
                    FROM queue_jobs
                    WHERE id = ?
                    """,
                    (deferred_job_id,),
                ).fetchone()
                pending_outbox = conn.execute(
                    "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                    (deferred_card_id,),
                ).fetchone()
                terminal_receipts = int(
                    conn.execute(
                        """
                        SELECT count(*) AS n
                        FROM audit_events
                        WHERE action = 'worker_job_effect_committed'
                          AND target_id = ?
                        """,
                        (deferred_job_id,),
                    ).fetchone()["n"]
                )
                failed_jobs = int(
                    conn.execute(
                        "SELECT count(*) AS n FROM queue_jobs WHERE status = 'failed'"
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(queue_row["status"], "pending")
            self.assertEqual(queue_row["attempt_count"], 1)
            self.assertIsNone(queue_row["finished_at"])
            self.assertIsNone(queue_row["lease_owner"])
            self.assertTrue(json.loads(queue_row["error_json"])["retry_pending"])
            self.assertIsNotNone(pending_outbox)
            self.assertEqual(terminal_receipts, 0)
            self.assertEqual(failed_jobs, 0)

            recovered = run_worker_pass(
                root,
                roles=["librarian"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(recovered["ok"], recovered)
            self.assertEqual(recovered["processed"][0]["job_id"], deferred_job_id)
            self.assertEqual(recovered["processed"][0]["status"], "succeeded")

    def test_worker_card_review_uses_global_intent_resolution_limit(
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
                    title="bounded-card-review-intents",
                    summary="Every worker alias must honor the same budget.",
                    source_refs=[],
                )
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                payload = store_module._card_sidecar_payload_for_row(row)
                enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_card_placement",
                    priority=1,
                    payload={"card_id": card_id},
                    related_card_ids=[card_id],
                    dedupe_key=f"bounded-review-intents:{card_id}",
                )
                conn.commit()
            finally:
                conn.close()
            for _index in range(51):
                store_module._write_card_sidecar_write_intent(
                    root,
                    card_id=card_id,
                    target_uri=str(row["location_uri"]),
                    expected_state_hash=str(payload["state_hash"]),
                )

            reconciliation_calls: list[dict[str, object]] = []
            real_reconcile = (
                store_module.reconcile_card_sidecar_write_intents
            )

            def capture_reconciliation(
                *args: object,
                **kwargs: object,
            ) -> dict[str, object]:
                result = real_reconcile(*args, **kwargs)
                reconciliation_calls.append(
                    {
                        "kwargs": dict(kwargs),
                        "selected": int(result.get("selected", 0)),
                        "processed": int(result.get("processed", 0)),
                    }
                )
                return result

            with patch.object(
                store_module,
                "reconcile_card_sidecar_write_intents",
                side_effect=capture_reconciliation,
            ):
                worker = run_worker_pass(
                    root,
                    roles=["librarian"],
                    limit=1,
                    maintenance=False,
                )

            self.assertFalse(worker["ok"], worker)
            self.assertEqual(worker["processed_count"], 1)
            self.assertEqual(len(reconciliation_calls), 1)
            for call in reconciliation_calls:
                self.assertEqual(
                    call["kwargs"].get("limit"),
                    worker_module.WORKER_SIDECAR_INTENT_LIMIT,
                )
                self.assertNotIn("card_ids", call["kwargs"])
                self.assertLessEqual(
                    int(call["selected"]),
                    worker_module.WORKER_SIDECAR_INTENT_LIMIT,
                )
                self.assertLessEqual(
                    int(call["processed"]),
                    worker_module.WORKER_SIDECAR_INTENT_LIMIT,
                )
            self.assertGreaterEqual(
                len(
                    list(
                        (
                            root
                            / "run"
                            / "card_sidecar_write_intents"
                        ).glob("*.json")
                    )
                )
                + len(
                    list(
                        (
                            root
                            / "run"
                            / "card_sidecar_retirement_intents"
                        ).glob("*.json")
                    )
                ),
                2,
            )

    def test_worker_pass_caps_nested_review_and_conflict_reconciliation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                previous = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Nested Worker Budget",
                    summary="Use the nested worker budget.",
                    source_refs=[],
                    visibility_scope="project",
                    project_id="continuum",
                    session_id="budget-a",
                )
                current = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Nested Worker Budget",
                    summary="Do not use the nested worker budget.",
                    source_refs=[],
                    visibility_scope="project",
                    project_id="continuum",
                    session_id="budget-b",
                )
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (current,),
                ).fetchone()
                payload = store_module._card_sidecar_payload_for_row(row)
                enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_card_placement",
                    priority=1,
                    payload={"card_id": current},
                    related_card_ids=[current],
                    dedupe_key=f"nested-worker-budget:{current}",
                )
                conn.execute("DELETE FROM card_sidecar_outbox")
                conn.commit()
            finally:
                conn.close()
            for _index in range(101):
                store_module._write_card_sidecar_write_intent(
                    root,
                    card_id=current,
                    target_uri=str(row["location_uri"]),
                    expected_state_hash=str(payload["state_hash"]),
                )

            calls: list[dict[str, int]] = []
            real_reconcile = (
                store_module.reconcile_card_sidecar_write_intents
            )

            def capture_reconciliation(
                *args: object,
                **kwargs: object,
            ) -> dict[str, object]:
                result = real_reconcile(*args, **kwargs)
                calls.append(
                    {
                        "limit": int(kwargs.get("limit", 0)),
                        "inspected": int(result.get("inspected", 0)),
                        "selected": int(result.get("selected", 0)),
                        "processed": int(result.get("processed", 0)),
                    }
                )
                return result

            with patch.object(
                store_module,
                "reconcile_card_sidecar_write_intents",
                side_effect=capture_reconciliation,
            ):
                worker = run_worker_pass(
                    root,
                    roles=["librarian"],
                    limit=1,
                    maintenance=False,
                )

            budget = worker["sidecar_intent_budget"]
            self.assertFalse(worker["ok"], worker)
            self.assertEqual(worker["processed_count"], 1)
            self.assertGreaterEqual(len(calls), 1)
            self.assertLessEqual(
                sum(call["inspected"] for call in calls),
                worker_module.WORKER_SIDECAR_INTENT_LIMIT,
            )
            self.assertLessEqual(
                sum(call["selected"] for call in calls),
                worker_module.WORKER_SIDECAR_INTENT_LIMIT,
            )
            self.assertLessEqual(
                sum(call["processed"] for call in calls),
                worker_module.WORKER_SIDECAR_INTENT_LIMIT,
            )
            self.assertTrue(
                all(
                    0 < call["limit"]
                    <= worker_module.WORKER_SIDECAR_INTENT_LIMIT
                    for call in calls
                ),
                calls,
            )
            self.assertEqual(
                budget["limit"],
                worker_module.WORKER_SIDECAR_INTENT_LIMIT,
            )
            self.assertLessEqual(
                budget["used"],
                worker_module.WORKER_SIDECAR_INTENT_LIMIT,
            )
            self.assertEqual(budget["remaining"], 0)
            conn = connect_existing(root)
            try:
                pending_outbox = {
                    str(pending["card_id"])
                    for pending in conn.execute(
                        "SELECT card_id FROM card_sidecar_outbox"
                    )
                }
            finally:
                conn.close()
            self.assertIn(current, pending_outbox)
            self.assertIn(previous, pending_outbox)
            self.assertGreaterEqual(
                len(
                    list(
                        (
                            root
                            / "run"
                            / "card_sidecar_write_intents"
                        ).glob("*.json")
                    )
                )
                + len(
                    list(
                        (
                            root
                            / "run"
                            / "card_sidecar_retirement_intents"
                        ).glob("*.json")
                    )
                ),
                51,
            )

    def test_worker_scribe_uses_shared_intent_budget_and_reports_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["capture"]["roll_segments_every_events"] = 1
            write_config(root, config)
            unrelated_id = self._create_pending_sidecar_cards(
                root,
                count=1,
                namespace="scribe-shared-intent-budget",
            )[0]
            conn = connect(root)
            try:
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (unrelated_id,),
                ).fetchone()
                payload = store_module._card_sidecar_payload_for_row(row)
                conn.execute("DELETE FROM card_sidecar_outbox")
                conn.commit()
            finally:
                conn.close()
            session_id = "scribe-shared-budget-session"
            append_scroll_event(
                root,
                session_id=session_id,
                event_type="message",
                role="user",
                content="Scribe must share the global recovery budget.",
            )
            for _index in range(101):
                store_module._write_card_sidecar_write_intent(
                    root,
                    card_id=unrelated_id,
                    target_uri=str(row["location_uri"]),
                    expected_state_hash=str(payload["state_hash"]),
                )

            calls: list[dict[str, int]] = []
            real_reconcile = (
                store_module.reconcile_card_sidecar_write_intents
            )

            def capture_reconciliation(
                *args: object,
                **kwargs: object,
            ) -> dict[str, object]:
                result = real_reconcile(*args, **kwargs)
                calls.append(
                    {
                        "enumerated": int(result.get("enumerated", 0)),
                        "inspected": int(result.get("inspected", 0)),
                        "selected": int(result.get("selected", 0)),
                        "processed": int(result.get("processed", 0)),
                        "budget_charged": int(
                            result.get("budget_charged", 0)
                        ),
                    }
                )
                return result

            with patch.object(
                store_module,
                "reconcile_card_sidecar_write_intents",
                side_effect=capture_reconciliation,
            ):
                worker = run_worker_pass(
                    root,
                    roles=["scribe"],
                    limit=1,
                    maintenance=False,
                )

            self.assertFalse(worker["ok"], worker)
            self.assertEqual(worker["processed_count"], 1)
            self.assertEqual(len(calls), 1, calls)
            self.assertLessEqual(
                sum(call["inspected"] for call in calls),
                worker_module.WORKER_SIDECAR_INTENT_LIMIT,
            )
            self.assertLessEqual(
                sum(call["selected"] for call in calls),
                worker_module.WORKER_SIDECAR_INTENT_LIMIT,
            )
            self.assertLessEqual(
                sum(call["processed"] for call in calls),
                worker_module.WORKER_SIDECAR_INTENT_LIMIT,
            )
            self.assertLessEqual(
                sum(call["enumerated"] for call in calls),
                worker_module.WORKER_SIDECAR_INTENT_LIMIT + 1,
            )
            budget = worker["sidecar_intent_budget"]
            self.assertEqual(
                budget["used"],
                sum(call["budget_charged"] for call in calls),
            )
            self.assertEqual(budget["remaining"], 0)
            processed = worker["processed"][0]
            self.assertEqual(processed["status"], "pending", processed)
            self.assertFalse(processed["result"]["ok"], processed)
            self.assertTrue(processed["result"]["retry_pending"], processed)
            self.assertEqual(
                processed["result"]["reason"],
                worker_module.POST_COMMIT_SIDECAR_RETRY_REASON,
            )
            self.assertTrue(
                processed["result"]["sidecar_failures"],
                processed,
            )
            conn = connect_existing(root)
            try:
                segment_card_id = str(
                    conn.execute(
                        """
                        SELECT summary_card_id
                        FROM scroll_segments
                        WHERE session_id = ?
                        """,
                        (session_id,),
                    ).fetchone()["summary_card_id"]
                )
                retry_pending = (
                    conn.execute(
                        """
                        SELECT 1
                        FROM card_sidecar_outbox
                        WHERE card_id = ?
                        """,
                        (segment_card_id,),
                    ).fetchone()
                    is not None
                )
                failed_jobs = int(
                    conn.execute(
                        "SELECT count(*) AS n FROM queue_jobs WHERE status = 'failed'"
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertTrue(retry_pending, worker)
            self.assertEqual(failed_jobs, 0)

    def test_nested_conflict_budget_failure_propagates_after_exact_first_window(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                previous = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Exact Nested Budget",
                    summary="Use the exact nested budget.",
                    source_refs=[],
                    visibility_scope="project",
                    project_id="continuum",
                    session_id="exact-budget-a",
                )
                current = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Exact Nested Budget",
                    summary="Do not use the exact nested budget.",
                    source_refs=[],
                    visibility_scope="project",
                    project_id="continuum",
                    session_id="exact-budget-b",
                )
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (current,),
                ).fetchone()
                payload = store_module._card_sidecar_payload_for_row(row)
                enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_card_placement",
                    priority=1,
                    payload={"card_id": current},
                    related_card_ids=[current],
                    dedupe_key=f"exact-nested-budget:{current}",
                )
                conn.execute("DELETE FROM card_sidecar_outbox")
                conn.commit()
            finally:
                conn.close()
            for _index in range(49):
                store_module._write_card_sidecar_write_intent(
                    root,
                    card_id=current,
                    target_uri=str(row["location_uri"]),
                    expected_state_hash=str(payload["state_hash"]),
                )

            worker = run_worker_pass(
                root,
                roles=["librarian"],
                limit=1,
                maintenance=False,
            )

            self.assertFalse(worker["ok"], worker)
            self.assertEqual(worker["processed_count"], 1)
            self.assertEqual(
                worker["sidecar_intent_budget"]["used"],
                worker_module.WORKER_SIDECAR_INTENT_LIMIT,
            )
            processed = worker["processed"][0]
            review = processed["result"]
            self.assertEqual(processed["status"], "pending", processed)
            self.assertTrue(review["sidecars"]["ok"], review)
            self.assertFalse(review["conflicts"]["ok"], review)
            self.assertFalse(review["ok"], review)
            self.assertTrue(review["retry_pending"], review)
            self.assertEqual(
                review["reason"],
                worker_module.POST_COMMIT_SIDECAR_RETRY_REASON,
            )
            conn = connect_existing(root)
            try:
                pending_outbox = {
                    str(pending["card_id"])
                    for pending in conn.execute(
                        "SELECT card_id FROM card_sidecar_outbox"
                    )
                }
                failed_jobs = int(
                    conn.execute(
                        "SELECT count(*) AS n FROM queue_jobs WHERE status = 'failed'"
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertIn(previous, pending_outbox)
            self.assertIn(current, pending_outbox)
            self.assertEqual(failed_jobs, 0)

    def test_worker_scribe_does_not_recover_unrelated_sidecars(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["capture"]["roll_segments_every_events"] = 1
            write_config(root, config)
            session_id = "bounded-scribe-sidecar-recovery"
            append_scroll_event(
                root,
                session_id=session_id,
                event_type="message",
                role="user",
                content="Scribe must leave unrelated sidecar ownership alone.",
            )
            unrelated_id = self._create_pending_sidecar_cards(
                root,
                count=1,
                namespace="bounded-scribe-unrelated",
            )[0]
            conn = connect(root)
            try:
                enqueue_job(
                    conn,
                    role="scribe",
                    job_type="scroll_event_ingested",
                    priority=1,
                    payload={"session_id": session_id},
                    related_card_ids=[],
                    dedupe_key=f"bounded-scribe:{session_id}",
                )
                unrelated_location = str(
                    conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (unrelated_id,),
                    ).fetchone()["location_uri"]
                )
                conn.commit()
            finally:
                conn.close()

            with patch.object(
                store_module,
                "sync_pending_card_sidecars",
                wraps=store_module.sync_pending_card_sidecars,
            ) as generic_recovery:
                result = run_worker_pass(
                    root,
                    roles=["scribe"],
                    limit=1,
                    maintenance=False,
                )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["processed_count"], 1)
            generic_recovery.assert_not_called()
            conn = connect_existing(root)
            try:
                segment_count = int(
                    conn.execute(
                        "SELECT count(*) AS n FROM scroll_segments WHERE session_id = ?",
                        (session_id,),
                    ).fetchone()["n"]
                )
                unrelated_pending = (
                    conn.execute(
                        "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                        (unrelated_id,),
                    ).fetchone()
                    is not None
                )
            finally:
                conn.close()
            self.assertEqual(segment_count, 1, result)
            self.assertTrue(unrelated_pending, result)
            self.assertFalse(resolve_stored_uri(root, unrelated_location).exists())

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

    def test_multi_role_worker_pass_selects_exact_strict_and_oldest_winners(
        self,
    ) -> None:
        roles = {"archivist", "librarian"}
        with tempfile.TemporaryDirectory() as tmp:
            for forced_oldest in (False, True):
                with self.subTest(forced_oldest=forced_oldest):
                    root = Path(tmp) / (
                        "forced-oldest" if forced_oldest else "strict"
                    )
                    identities = self._seed_multi_role_claim_backlog(
                        root,
                        namespace=(
                            "public-oldest"
                            if forced_oldest
                            else "public-strict"
                        ),
                    )
                    if forced_oldest:
                        conn = connect(root)
                        try:
                            worker_module._set_queue_priority_bypass_count(
                                conn,
                                roles,
                                worker_module
                                .MAX_CONSECUTIVE_PRIORITY_BYPASSES,
                            )
                            conn.commit()
                        finally:
                            conn.close()

                    result = run_worker_pass(
                        root,
                        roles=["librarian", "archivist"],
                        limit=1,
                        maintenance=False,
                    )

                    expected_id = identities[
                        "oldest" if forced_oldest else "strict"
                    ]
                    self.assertEqual(result["processed_count"], 1, result)
                    self.assertEqual(
                        result["processed"][0]["job_id"],
                        expected_id,
                        result,
                    )
                    conn = connect_existing(root)
                    try:
                        states = {
                            str(row["id"]): (
                                str(row["status"]),
                                int(row["attempt_count"]),
                            )
                            for row in conn.execute(
                                """
                                SELECT id, status, attempt_count
                                FROM queue_jobs
                                WHERE id IN (?, ?, ?, ?, ?)
                                """,
                                (
                                    identities["blocked"],
                                    identities["strict"],
                                    identities["strict_tie_loser"],
                                    identities["oldest"],
                                    identities["oldest_tie_loser"],
                                ),
                            ).fetchall()
                        }
                        excluded_pending = int(
                            conn.execute(
                                """
                                SELECT count(*) AS n
                                FROM queue_jobs
                                WHERE role = 'scribe'
                                  AND status = 'pending'
                                  AND job_type =
                                      'excluded_role_claim_probe'
                                """
                            ).fetchone()["n"]
                        )
                        fairness_counter = conn.execute(
                            "SELECT value FROM meta WHERE key = ?",
                            (
                                worker_module._queue_fairness_meta_key(
                                    roles
                                ),
                            ),
                        ).fetchone()
                    finally:
                        conn.close()
                    self.assertEqual(
                        states[expected_id],
                        ("skipped", 1),
                    )
                    self.assertEqual(
                        states[identities["blocked"]],
                        ("pending", 0),
                    )
                    for identity_name in (
                        "strict",
                        "strict_tie_loser",
                        "oldest",
                        "oldest_tie_loser",
                    ):
                        candidate_id = identities[identity_name]
                        if candidate_id != expected_id:
                            self.assertEqual(
                                states[candidate_id],
                                ("pending", 0),
                            )
                    self.assertEqual(excluded_pending, 5_000)
                    if forced_oldest:
                        self.assertIsNone(fairness_counter)
                    else:
                        self.assertEqual(
                            int(fairness_counter["value"]),
                            1,
                        )

    def test_multi_role_claim_uses_role_first_indexes_with_bounded_work(
        self,
    ) -> None:
        roles = {"archivist", "librarian"}
        with tempfile.TemporaryDirectory() as tmp:
            for forced_oldest in (False, True):
                with self.subTest(forced_oldest=forced_oldest):
                    root = Path(tmp) / (
                        "targeted-oldest"
                        if forced_oldest
                        else "targeted-strict"
                    )
                    identities = self._seed_multi_role_claim_backlog(
                        root,
                        namespace=(
                            "targeted-oldest"
                            if forced_oldest
                            else "targeted-strict"
                        ),
                    )
                    conn = connect(root)
                    try:
                        if forced_oldest:
                            worker_module._set_queue_priority_bypass_count(
                                conn,
                                roles,
                                worker_module
                                .MAX_CONSECUTIVE_PRIORITY_BYPASSES,
                            )
                            conn.commit()
                        for oldest, index_name in (
                            (False, "idx_queue_role_priority"),
                            (True, "idx_queue_role_created"),
                        ):
                            plan = " ".join(
                                str(row["detail"])
                                for row in conn.execute(
                                    "EXPLAIN QUERY PLAN "
                                    + worker_module
                                    ._role_filtered_candidate_sql(
                                        oldest=oldest
                                    ),
                                    ("archivist", "pending"),
                                ).fetchall()
                            )
                            self.assertIn(index_name, plan)
                            self.assertNotIn(
                                "idx_queue_status_",
                                plan,
                            )
                            self.assertNotIn("TEMP B-TREE", plan)
                        if not forced_oldest:
                            for oldest, index_name in (
                                (False, "idx_queue_status_priority"),
                                (True, "idx_queue_status_created"),
                            ):
                                all_roles_trace: list[str] = []
                                conn.set_trace_callback(
                                    all_roles_trace.append
                                )
                                try:
                                    worker_module._eligible_job_candidate(
                                        conn,
                                        None,
                                        oldest=oldest,
                                    )
                                finally:
                                    conn.set_trace_callback(None)
                                all_roles_select = next(
                                    statement
                                    for statement in all_roles_trace
                                    if (
                                        "FROM queue_jobs AS pending_job"
                                        in statement
                                    )
                                )
                                all_roles_plan = " ".join(
                                    str(row["detail"])
                                    for row in conn.execute(
                                        "EXPLAIN QUERY PLAN "
                                        + all_roles_select
                                    ).fetchall()
                                )
                                self.assertIn(
                                    index_name,
                                    all_roles_plan,
                                )
                                self.assertNotIn(
                                    "idx_queue_role_",
                                    all_roles_plan,
                                )

                        instruction_count = 0
                        traced_sql: list[str] = []

                        def count_instruction() -> int:
                            nonlocal instruction_count
                            instruction_count += 1
                            return 0

                        conn.execute("BEGIN IMMEDIATE")
                        conn.set_trace_callback(traced_sql.append)
                        conn.set_progress_handler(count_instruction, 1)
                        try:
                            claimed = worker_module._claim_job(
                                conn,
                                roles,
                                lease_owner=(
                                    "targeted-oldest-owner"
                                    if forced_oldest
                                    else "targeted-strict-owner"
                                ),
                                lease_seconds=300,
                            )
                        finally:
                            conn.set_progress_handler(None, 0)
                            conn.set_trace_callback(None)
                            conn.rollback()
                    finally:
                        conn.close()

                    expected_id = identities[
                        "oldest" if forced_oldest else "strict"
                    ]
                    self.assertEqual(claimed["id"], expected_id)
                    self.assertLess(instruction_count, 1_500)
                    normalized_trace = [
                        statement.lower() for statement in traced_sql
                    ]
                    self.assertEqual(
                        sum(
                            "indexed by idx_queue_role_priority"
                            in statement
                            for statement in normalized_trace
                        ),
                        len(roles),
                    )
                    self.assertEqual(
                        sum(
                            "indexed by idx_queue_role_created"
                            in statement
                            for statement in normalized_trace
                        ),
                        len(roles),
                    )
                    self.assertFalse(
                        any(
                            "pending_job.role in"
                            in statement
                            for statement in normalized_trace
                        ),
                        traced_sql,
                    )

    def test_worker_priority_burst_serves_oldest_job_after_bounded_bypasses(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                with patch.object(
                    store_module,
                    "utc_now",
                    return_value="2026-07-28T00:00:00+00:00",
                ):
                    oldest_job_id = enqueue_job(
                        conn,
                        role="archivist",
                        job_type="fairness_low_priority_probe",
                        priority=900,
                        payload={},
                    )
                conn.commit()
            finally:
                conn.close()

            for index in range(
                worker_module.MAX_CONSECUTIVE_PRIORITY_BYPASSES
            ):
                conn = connect(root)
                try:
                    with patch.object(
                        store_module,
                        "utc_now",
                        return_value="2026-07-28T00:00:00+00:00",
                    ):
                        high_job_id = enqueue_job(
                            conn,
                            role="archivist",
                            job_type="fairness_high_priority_probe",
                            priority=1,
                            payload={"index": index},
                        )
                    conn.commit()
                finally:
                    conn.close()
                claimed = run_worker_pass(
                    root,
                    roles=["archivist"],
                    limit=1,
                    maintenance=False,
                )
                self.assertEqual(
                    claimed["processed"][0]["job_id"],
                    high_job_id,
                    claimed,
                )

            conn = connect(root)
            try:
                with patch.object(
                    store_module,
                    "utc_now",
                    return_value="2026-07-28T00:00:00+00:00",
                ):
                    next_high_job_id = enqueue_job(
                        conn,
                        role="archivist",
                        job_type="fairness_high_priority_probe",
                        priority=1,
                        payload={"index": "after-bound"},
                    )
                conn.commit()
            finally:
                conn.close()

            fairness_claim = run_worker_pass(
                root,
                roles=["archivist"],
                limit=1,
                maintenance=False,
            )
            self.assertEqual(
                fairness_claim["processed"][0]["job_id"],
                oldest_job_id,
                fairness_claim,
            )
            conn = connect_existing(root)
            try:
                state = {
                    str(row["id"]): (
                        str(row["status"]),
                        int(row["attempt_count"]),
                    )
                    for row in conn.execute(
                        """
                        SELECT id, status, attempt_count
                        FROM queue_jobs
                        WHERE id IN (?, ?)
                        """,
                        (oldest_job_id, next_high_job_id),
                    ).fetchall()
                }
                fairness_counter = conn.execute(
                    "SELECT value FROM meta WHERE key = ?",
                    (
                        worker_module._queue_fairness_meta_key(
                            {"archivist"}
                        ),
                    ),
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(state[oldest_job_id], ("skipped", 1))
            self.assertEqual(state[next_high_job_id], ("pending", 0))
            self.assertIsNone(fairness_counter)

            resumed_priority = run_worker_pass(
                root,
                roles=["archivist"],
                limit=1,
                maintenance=False,
            )
            self.assertEqual(
                resumed_priority["processed"][0]["job_id"],
                next_high_job_id,
                resumed_priority,
            )

    def test_worker_priority_bypass_counter_rolls_back_with_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                enqueue_job(
                    conn,
                    role="archivist",
                    job_type="fairness_rollback_low",
                    priority=900,
                    payload={},
                )
                high_job_id = enqueue_job(
                    conn,
                    role="archivist",
                    job_type="fairness_rollback_high",
                    priority=1,
                    payload={},
                )
                conn.commit()
                conn.execute("BEGIN IMMEDIATE")
                claimed = worker_module._claim_job(
                    conn,
                    {"archivist"},
                    lease_owner="rollback-owner",
                    lease_seconds=300,
                )
                self.assertEqual(claimed["id"], high_job_id)
                self.assertEqual(
                    worker_module._queue_priority_bypass_count(
                        conn,
                        {"archivist"},
                    ),
                    1,
                )
                conn.rollback()
            finally:
                conn.close()

            conn = connect_existing(root)
            try:
                states = conn.execute(
                    "SELECT status, attempt_count FROM queue_jobs"
                ).fetchall()
                counter = conn.execute(
                    "SELECT value FROM meta WHERE key = ?",
                    (
                        worker_module._queue_fairness_meta_key(
                            {"archivist"}
                        ),
                    ),
                ).fetchone()
            finally:
                conn.close()
            self.assertTrue(
                all(
                    row["status"] == "pending"
                    and int(row["attempt_count"]) == 0
                    for row in states
                ),
                states,
            )
            self.assertIsNone(counter)

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
            self.assertFalse(
                detected.call_args_list[0].kwargs[
                    "recover_pending_card_sidecars"
                ]
            )
            self.assertFalse(
                detected.call_args_list[1].kwargs[
                    "recover_pending_card_sidecars"
                ]
            )
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
            self.assertTrue(
                all(
                    call.kwargs["recover_pending_card_sidecars"] is False
                    for call in repeated_detection.call_args_list
                )
            )
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
            self.assertTrue(
                all(
                    call.kwargs["recover_pending_card_sidecars"] is False
                    for call in recovered_detection.call_args_list
                )
            )
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
            interrupted_job = interrupted["processed"][0]
            self.assertEqual(interrupted_job["status"], "pending")
            self.assertEqual(
                interrupted_job["result"]["reason"],
                worker_module.POST_COMMIT_EXCEPTION_RETRY_REASON,
            )
            self.assertTrue(interrupted_job["result"]["retry_pending"])
            self.assertEqual(
                interrupted_job["result"]["post_commit_authority"]["kind"],
                "scribe_committed_step",
            )

            conn = connect_existing(root)
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
                retry_row = conn.execute(
                    """
                    SELECT status, attempt_count, finished_at, lease_owner,
                           lease_expires_at, heartbeat_at, error_json
                    FROM queue_jobs
                    WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(retry_row["status"], "pending")
            self.assertEqual(retry_row["attempt_count"], 1)
            self.assertIsNone(retry_row["finished_at"])
            self.assertIsNone(retry_row["lease_owner"])
            self.assertIsNone(retry_row["lease_expires_at"])
            self.assertIsNone(retry_row["heartbeat_at"])
            self.assertTrue(
                json.loads(retry_row["error_json"])["retry_pending"]
            )

            conn = connect(root)
            try:
                now = store_module.utc_now()
                cursor = conn.execute(
                    """
                    UPDATE queue_jobs
                    SET status = 'failed', finished_at = ?, updated_at = ?,
                        heartbeat_at = NULL, error_json = ?
                    WHERE id = ? AND status = 'pending'
                    """,
                    (
                        now,
                        now,
                        store_module.json_dumps(
                            {
                                "error": (
                                    "legacy Scribe final receipt exception"
                                ),
                                "result": {},
                            }
                        ),
                        job_id,
                    ),
                )
                self.assertEqual(cursor.rowcount, 1)
                conn.commit()
            finally:
                conn.close()
            legacy_recovery = (
                worker_module._recover_failed_post_phase_sidecar_jobs(root)
            )
            self.assertEqual(legacy_recovery["requeued"], 1)
            self.assertEqual(legacy_recovery["rejected"], 0)
            self.assertEqual(
                legacy_recovery["dispositions"][0]["effect_event_id"],
                worker_module._FAILED_SIDECAR_EFFECTLESS_KEY,
            )

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

    def test_scribe_sidecar_failure_requeues_until_live_authority_clears(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            config = default_config()
            config["capture"]["roll_segments_every_events"] = 1
            write_config(root, config)
            session_id = "scribe-sidecar-failure-replay"
            append_scroll_event(
                root,
                session_id=session_id,
                event_type="message",
                role="user",
                content="A failed sidecar phase must retain retry authority.",
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

            sidecar_failure = {
                "ok": False,
                "synced": 0,
                "failed": 1,
                "failures": [{"error": "forced bounded sidecar failure"}],
            }
            with patch.object(
                store_module,
                "sync_card_sidecars_after_commit",
                return_value=sidecar_failure,
            ):
                deferred = run_worker_pass(
                    root,
                    roles=["scribe"],
                    limit=1,
                    maintenance=False,
                )
            self.assertFalse(deferred["ok"], deferred)
            deferred_job = deferred["processed"][0]
            self.assertEqual(deferred_job["status"], "pending", deferred)
            self.assertTrue(deferred_job["result"]["retry_pending"], deferred)
            self.assertEqual(
                deferred_job["result"]["reason"],
                worker_module.POST_COMMIT_SIDECAR_RETRY_REASON,
            )

            conn = connect_existing(root)
            try:
                receipt_counts = {
                    str(row["action"]): int(row["n"])
                    for row in conn.execute(
                        """
                        SELECT action, count(*) AS n
                        FROM audit_events
                        WHERE target_type = 'queue_job' AND target_id = ?
                          AND action IN (
                              'worker_scribe_segment_step_committed',
                              'worker_scribe_segment_step_completed',
                              'worker_job_effect_committed'
                          )
                        GROUP BY action
                        """,
                        (job_id,),
                    ).fetchall()
                }
                queue_row = conn.execute(
                    """
                    SELECT status, attempt_count, finished_at, lease_owner,
                           error_json
                    FROM queue_jobs
                    WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone()
                segment_card_id = str(
                    conn.execute(
                        """
                        SELECT summary_card_id
                        FROM scroll_segments
                        WHERE session_id = ?
                        """,
                        (session_id,),
                    ).fetchone()["summary_card_id"]
                )
                pending_outbox = conn.execute(
                    "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                    (segment_card_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(
                receipt_counts,
                {"worker_scribe_segment_step_committed": 1},
            )
            self.assertEqual(queue_row["status"], "pending")
            self.assertEqual(queue_row["attempt_count"], 1)
            self.assertIsNone(queue_row["finished_at"])
            self.assertIsNone(queue_row["lease_owner"])
            self.assertTrue(json.loads(queue_row["error_json"])["retry_pending"])
            self.assertIsNotNone(pending_outbox)

            repairing = run_worker_pass(
                root,
                roles=["scribe"],
                limit=1,
                maintenance=True,
            )
            self.assertFalse(repairing["ok"], repairing)
            self.assertEqual(repairing["processed"][0]["status"], "pending")
            self.assertTrue(repairing["maintenance"]["sidecars"]["ok"])
            conn = connect_existing(root)
            try:
                repaired_outbox = conn.execute(
                    "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                    (segment_card_id,),
                ).fetchone()
                repaired_row = conn.execute(
                    "SELECT status, attempt_count FROM queue_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertIsNone(repaired_outbox)
            self.assertEqual(repaired_row["status"], "pending")
            self.assertEqual(repaired_row["attempt_count"], 2)

            recovered = run_worker_pass(
                root,
                roles=["scribe"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(recovered["ok"], recovered)
            recovered_job = recovered["processed"][0]
            self.assertEqual(recovered_job["job_id"], job_id)
            self.assertEqual(recovered_job["status"], "succeeded")
            self.assertTrue(recovered_job["result"]["ok"])
            self.assertTrue(
                recovered_job["result"]["rolled"][0]["sidecars"]["ok"]
            )
            conn = connect_existing(root)
            try:
                final_row = conn.execute(
                    "SELECT status, attempt_count FROM queue_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()
                final_counts = {
                    str(row["action"]): int(row["n"])
                    for row in conn.execute(
                        """
                        SELECT action, count(*) AS n
                        FROM audit_events
                        WHERE target_type = 'queue_job' AND target_id = ?
                          AND action IN (
                              'worker_scribe_segment_step_committed',
                              'worker_scribe_segment_step_completed',
                              'worker_job_effect_committed'
                          )
                        GROUP BY action
                        """,
                        (job_id,),
                    ).fetchall()
                }
                failed_jobs = int(
                    conn.execute(
                        "SELECT count(*) AS n FROM queue_jobs WHERE status = 'failed'"
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(final_row["status"], "succeeded")
            self.assertEqual(final_row["attempt_count"], 3)
            self.assertEqual(
                final_counts,
                {
                    "worker_job_effect_committed": 1,
                    "worker_scribe_segment_step_committed": 1,
                },
            )
            self.assertEqual(failed_jobs, 0)

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
            lease_sensitive_sidecar_card_id: str | None = None
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
                conn = connect(root)
                try:
                    lease_sensitive_sidecar_card_id = create_card(
                        conn,
                        root=root,
                        card_type="note",
                        title="Forced expiry unrelated sidecar",
                        summary="A lost Scribe lease must not recover unrelated sidecars.",
                        source_refs=[],
                    )
                    conn.commit()
                finally:
                    conn.close()
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
                lease_sensitive_sidecar_card_id = card_id
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
                "lease_sensitive_sidecar_card_id": lease_sensitive_sidecar_card_id,
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
                lease_sensitive_sidecar_card_id = case[
                    "lease_sensitive_sidecar_card_id"
                ]
                if lease_sensitive_sidecar_card_id is not None:
                    conn = connect_existing(root)
                    try:
                        sidecar_sync_markers = int(
                            conn.execute(
                                """
                                SELECT count(*) AS n
                                FROM audit_events
                                WHERE action = 'card_sidecar_synced'
                                  AND target_id = ?
                                """,
                                (lease_sensitive_sidecar_card_id,),
                            ).fetchone()["n"]
                        )
                        pending_sidecars = int(
                            conn.execute(
                                """
                                SELECT count(*) AS n
                                FROM card_sidecar_outbox
                                WHERE card_id = ?
                                """,
                                (lease_sensitive_sidecar_card_id,),
                            ).fetchone()["n"]
                        )
                    finally:
                        conn.close()
                    self.assertEqual(sidecar_sync_markers, 0, expired_result)
                    self.assertEqual(pending_sidecars, 1, expired_result)

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

    def test_card_review_core_phase_retries_sidecar_before_terminal_receipt(
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
                    card_type="decision",
                    title="Placement phase replay",
                    summary="Post-core failures must remain authoritative.",
                    source_refs=[],
                    topics=["placement-phase"],
                )
                conn.execute("DELETE FROM queue_jobs")
                job_id = enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_card_placement",
                    priority=1,
                    payload={"card_id": card_id},
                    related_card_ids=[card_id],
                )
                conn.commit()
            finally:
                conn.close()

            sidecar_failure = {
                "ok": False,
                "synced": 0,
                "failed": 1,
                "failures": [{"error": "forced sidecar failure"}],
            }
            conflict_failure = {
                "ok": False,
                "reason": "forced conflict failure",
            }
            with (
                patch.object(
                    worker_module,
                    "_sync_worker_card_sidecars",
                    return_value=sidecar_failure,
                ),
                patch.object(
                    worker_module,
                    "detect_conflicts",
                    return_value=conflict_failure,
                ),
            ):
                deferred = run_worker_pass(
                    root,
                    roles=["librarian"],
                    limit=1,
                    maintenance=False,
                )
            self.assertFalse(deferred["ok"], deferred)
            deferred_job = deferred["processed"][0]
            self.assertEqual(deferred_job["status"], "pending", deferred)
            self.assertTrue(deferred_job["result"]["retry_pending"], deferred)
            self.assertEqual(
                deferred_job["result"]["reason"],
                worker_module.POST_COMMIT_SIDECAR_RETRY_REASON,
            )

            conn = connect_existing(root)
            try:
                phase_count = int(
                    conn.execute(
                        """
                        SELECT count(*) AS n
                        FROM audit_events
                        WHERE action = 'worker_job_phase_committed'
                          AND target_id = ?
                          AND json_extract(payload_json, '$.job_type')
                              = 'review_card_placement'
                          AND json_extract(payload_json, '$.phase') = 'core'
                        """,
                        (job_id,),
                    ).fetchone()["n"]
                )
                terminal_count = int(
                    conn.execute(
                        """
                        SELECT count(*) AS n
                        FROM audit_events
                        WHERE action = 'worker_job_effect_committed'
                          AND target_id = ?
                        """,
                        (job_id,),
                    ).fetchone()["n"]
                )
                pending_row = conn.execute(
                    """
                    SELECT status, attempt_count, finished_at, lease_owner,
                           error_json
                    FROM queue_jobs
                    WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone()
                pending_outbox = conn.execute(
                    "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(phase_count, 1)
            self.assertEqual(terminal_count, 0)
            self.assertEqual(pending_row["status"], "pending")
            self.assertEqual(pending_row["attempt_count"], 1)
            self.assertIsNone(pending_row["finished_at"])
            self.assertIsNone(pending_row["lease_owner"])
            self.assertTrue(
                json.loads(pending_row["error_json"])["retry_pending"]
            )
            self.assertIsNotNone(pending_outbox)

            repairing = run_worker_pass(
                root,
                roles=["archivist"],
                limit=1,
                maintenance=True,
            )
            self.assertTrue(repairing["ok"], repairing)
            self.assertEqual(repairing["processed_count"], 0)
            self.assertTrue(repairing["maintenance"]["sidecars"]["ok"])
            conn = connect_existing(root)
            try:
                repaired_outbox = conn.execute(
                    "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                ).fetchone()
                still_pending = conn.execute(
                    "SELECT status, attempt_count FROM queue_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertIsNone(repaired_outbox)
            self.assertEqual(still_pending["status"], "pending")
            self.assertEqual(still_pending["attempt_count"], 1)

            recovered = run_worker_pass(
                root,
                roles=["librarian"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(recovered["ok"], recovered)
            recovered_job = recovered["processed"][0]
            self.assertEqual(recovered_job["job_id"], job_id)
            self.assertEqual(recovered_job["status"], "succeeded")
            self.assertTrue(recovered_job["result"]["ok"])
            conn = connect_existing(root)
            try:
                final_counts = {
                    str(row["action"]): int(row["n"])
                    for row in conn.execute(
                        """
                        SELECT action, count(*) AS n
                        FROM audit_events
                        WHERE target_id = ?
                          AND action IN (
                              'worker_job_phase_committed',
                              'worker_job_effect_committed'
                          )
                        GROUP BY action
                        """,
                        (job_id,),
                    ).fetchall()
                }
                final_row = conn.execute(
                    "SELECT status, attempt_count FROM queue_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()
                failed_jobs = int(
                    conn.execute(
                        "SELECT count(*) AS n FROM queue_jobs WHERE status = 'failed'"
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(final_row["status"], "succeeded")
            self.assertEqual(final_row["attempt_count"], 2)
            self.assertEqual(
                final_counts,
                {
                    "worker_job_effect_committed": 1,
                    "worker_job_phase_committed": 1,
                },
            )
            self.assertEqual(failed_jobs, 0)

    def test_mempalace_core_phase_retries_sidecar_before_terminal_receipt(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            import_id = "mempalace-phase-replay"
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="mempalace_drawer",
                    title="MemPalace phase replay",
                    summary="The imported Card keeps post-core failure truth.",
                    source_refs=[],
                    metadata={"import_id": import_id},
                )
                card_node = upsert_graph_node(
                    conn,
                    kind="card",
                    label="MemPalace phase replay",
                    card_id=card_id,
                )
                term_node = upsert_graph_node(
                    conn,
                    kind="term",
                    label="mempalace",
                )
                add_graph_edge(
                    conn,
                    source_node_id=card_node,
                    relation="mentions",
                    target_node_id=term_node,
                    weight=0.5,
                    confidence=0.8,
                    source_refs=[{"card_id": card_id}],
                )
                conn.execute("DELETE FROM queue_jobs")
                job_id = enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_mempalace_import",
                    priority=1,
                    payload={"import_id": import_id},
                    related_card_ids=[card_id],
                )
                conn.commit()
            finally:
                conn.close()

            sidecar_failure = {
                "ok": False,
                "synced": 0,
                "failed": 1,
                "failures": [{"error": "forced imported sidecar failure"}],
            }
            with patch.object(
                worker_module,
                "_sync_worker_card_sidecars",
                return_value=sidecar_failure,
            ):
                deferred = run_worker_pass(
                    root,
                    roles=["librarian"],
                    limit=1,
                    maintenance=False,
                )
            self.assertFalse(deferred["ok"], deferred)
            deferred_job = deferred["processed"][0]
            self.assertEqual(deferred_job["status"], "pending", deferred)
            self.assertTrue(deferred_job["result"]["retry_pending"], deferred)
            self.assertEqual(
                deferred_job["result"]["reason"],
                worker_module.POST_COMMIT_SIDECAR_RETRY_REASON,
            )

            conn = connect_existing(root)
            try:
                phase_payload = json.loads(
                    conn.execute(
                        """
                        SELECT payload_json
                        FROM audit_events
                        WHERE action = 'worker_job_phase_committed'
                          AND target_id = ?
                          AND json_extract(payload_json, '$.job_type')
                              = 'review_mempalace_import'
                          AND json_extract(payload_json, '$.phase') = 'core'
                        ORDER BY rowid DESC
                        LIMIT 1
                        """,
                        (job_id,),
                    ).fetchone()["payload_json"]
                )
                pending_row = conn.execute(
                    """
                    SELECT status, attempt_count, finished_at, lease_owner,
                           error_json
                    FROM queue_jobs
                    WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone()
                pending_outbox = conn.execute(
                    "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                ).fetchone()
                terminal_count = int(
                    conn.execute(
                        """
                        SELECT count(*) AS n
                        FROM audit_events
                        WHERE action = 'worker_job_effect_committed'
                          AND target_id = ?
                        """,
                        (job_id,),
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(
                phase_payload["result"]["changed_cards"],
                [card_id],
            )
            self.assertEqual(
                phase_payload["result"]["core_result"]["reviewed_cards"],
                1,
            )
            self.assertEqual(pending_row["status"], "pending")
            self.assertEqual(pending_row["attempt_count"], 1)
            self.assertIsNone(pending_row["finished_at"])
            self.assertIsNone(pending_row["lease_owner"])
            self.assertTrue(
                json.loads(pending_row["error_json"])["retry_pending"]
            )
            self.assertIsNotNone(pending_outbox)
            self.assertEqual(terminal_count, 0)

            repairing = run_worker_pass(
                root,
                roles=["archivist"],
                limit=1,
                maintenance=True,
            )
            self.assertTrue(repairing["ok"], repairing)
            self.assertEqual(repairing["processed_count"], 0)
            self.assertTrue(repairing["maintenance"]["sidecars"]["ok"])
            conn = connect_existing(root)
            try:
                repaired_outbox = conn.execute(
                    "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                ).fetchone()
                still_pending = conn.execute(
                    "SELECT status, attempt_count FROM queue_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertIsNone(repaired_outbox)
            self.assertEqual(still_pending["status"], "pending")
            self.assertEqual(still_pending["attempt_count"], 1)

            recovered = run_worker_pass(
                root,
                roles=["librarian"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(recovered["ok"], recovered)
            recovered_job = recovered["processed"][0]
            self.assertEqual(recovered_job["job_id"], job_id)
            self.assertEqual(recovered_job["status"], "succeeded")
            self.assertEqual(recovered_job["result"]["reviewed_cards"], 1)
            conn = connect_existing(root)
            try:
                final_row = conn.execute(
                    "SELECT status, attempt_count FROM queue_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()
                final_counts = {
                    str(row["action"]): int(row["n"])
                    for row in conn.execute(
                        """
                        SELECT action, count(*) AS n
                        FROM audit_events
                        WHERE target_id = ?
                          AND action IN (
                              'worker_job_phase_committed',
                              'worker_job_effect_committed'
                          )
                        GROUP BY action
                        """,
                        (job_id,),
                    ).fetchall()
                }
                failed_jobs = int(
                    conn.execute(
                        "SELECT count(*) AS n FROM queue_jobs WHERE status = 'failed'"
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(final_row["status"], "succeeded")
            self.assertEqual(final_row["attempt_count"], 2)
            self.assertEqual(
                final_counts,
                {
                    "worker_job_effect_committed": 1,
                    "worker_job_phase_committed": 1,
                },
            )
            self.assertEqual(failed_jobs, 0)

    def test_worker_pass_requeues_legacy_mempalace_until_sidecar_authority_clears(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            import_id = "legacy-mempalace-sidecar-retry"
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="mempalace_drawer",
                    title="Legacy MemPalace retry",
                    summary="Pending sidecar authority must retain queue ownership.",
                    source_refs=[],
                    metadata={"import_id": import_id},
                )
                conn.execute("DELETE FROM queue_jobs")
                job_id = enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_mempalace_import",
                    priority=1,
                    payload={"import_id": import_id},
                    related_card_ids=[card_id],
                )
                store_module.audit_event(
                    conn,
                    action=worker_module._WORKER_EFFECT_ACTION,
                    target_type="queue_job",
                    target_id=job_id,
                    payload={
                        "schema": worker_module._WORKER_EFFECT_SCHEMA,
                        "job_type": "review_mempalace_import",
                        "result": {
                            "ok": True,
                            "reviewed_import": import_id,
                            "reviewed_cards": 1,
                        },
                    },
                )
                conn.commit()
            finally:
                conn.close()

            deferred = run_worker_pass(
                root,
                roles=["librarian"],
                limit=1,
                maintenance=True,
            )
            self.assertFalse(deferred["ok"], deferred)
            self.assertEqual(deferred["processed_count"], 1)
            deferred_job = deferred["processed"][0]
            self.assertEqual(deferred_job["job_id"], job_id)
            self.assertEqual(deferred_job["status"], "pending")
            self.assertTrue(deferred_job["result"]["retry_pending"])
            self.assertEqual(
                deferred_job["result"]["reason"],
                worker_module.POST_COMMIT_SIDECAR_RETRY_REASON,
            )
            self.assertTrue(deferred["maintenance"]["sidecars"]["ok"])

            conn = connect_existing(root)
            try:
                pending_row = conn.execute(
                    """
                    SELECT status, attempt_count, finished_at, lease_owner,
                           error_json
                    FROM queue_jobs
                    WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone()
                pending_outbox = conn.execute(
                    "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                ).fetchone()
                legacy_receipts = int(
                    conn.execute(
                        """
                        SELECT count(*) AS n
                        FROM audit_events
                        WHERE action = 'worker_job_effect_committed'
                          AND target_id = ?
                        """,
                        (job_id,),
                    ).fetchone()["n"]
                )
                failed_jobs = int(
                    conn.execute(
                        "SELECT count(*) AS n FROM queue_jobs WHERE status = 'failed'"
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(pending_row["status"], "pending")
            self.assertEqual(pending_row["attempt_count"], 1)
            self.assertIsNone(pending_row["finished_at"])
            self.assertIsNone(pending_row["lease_owner"])
            self.assertTrue(
                json.loads(pending_row["error_json"])["retry_pending"]
            )
            self.assertIsNone(pending_outbox)
            self.assertEqual(legacy_receipts, 1)
            self.assertEqual(failed_jobs, 0)

            recovered = run_worker_pass(
                root,
                roles=["librarian"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(recovered["ok"], recovered)
            self.assertEqual(recovered["processed"][0]["job_id"], job_id)
            self.assertEqual(recovered["processed"][0]["status"], "succeeded")
            conn = connect_existing(root)
            try:
                recovered_row = conn.execute(
                    "SELECT status, attempt_count FROM queue_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()
                terminal_receipts = int(
                    conn.execute(
                        """
                        SELECT count(*) AS n
                        FROM audit_events
                        WHERE action = 'worker_job_effect_committed'
                          AND target_id = ?
                        """,
                        (job_id,),
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(recovered_row["status"], "succeeded")
            self.assertEqual(recovered_row["attempt_count"], 2)
            self.assertEqual(terminal_receipts, 2)

    def test_worker_maintenance_recovers_exact_failed_post_phase_sidecars(
        self,
    ) -> None:
        def seed_failed_terminal_effect(
            root: Path,
            *,
            job_id: str,
            job_type: str,
            deferred_result: dict[str, object],
        ) -> tuple[str, dict[str, object]]:
            failed_result = dict(deferred_result)
            failed_result.pop("reason", None)
            failed_result.pop("retry_pending", None)
            failed_result.pop("idempotent_replay", None)
            now = store_module.utc_now()
            conn = connect(root)
            try:
                effect_event_id = store_module.audit_event(
                    conn,
                    action=worker_module._WORKER_EFFECT_ACTION,
                    target_type="queue_job",
                    target_id=job_id,
                    payload={
                        "schema": worker_module._WORKER_EFFECT_SCHEMA,
                        "job_type": job_type,
                        "post_phase_complete": True,
                        "result": failed_result,
                    },
                )
                cursor = conn.execute(
                    """
                    UPDATE queue_jobs
                    SET status = 'failed', finished_at = ?, updated_at = ?,
                        lease_owner = NULL, lease_expires_at = NULL,
                        heartbeat_at = NULL, error_json = ?
                    WHERE id = ? AND status = 'pending'
                    """,
                    (
                        now,
                        now,
                        store_module.json_dumps(
                            {
                                "error": str(
                                    failed_result.get("reason")
                                    or failed_result.get("error")
                                    or "worker result reported ok=false"
                                ),
                                "result": failed_result,
                            }
                        ),
                        job_id,
                    ),
                )
                self.assertEqual(cursor.rowcount, 1)
                conn.commit()
            finally:
                conn.close()
            return effect_event_id, failed_result

        def prepare_placement(
            root: Path,
        ) -> tuple[str, str, dict[str, object]]:
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Recover failed placement sidecar",
                    summary="The old failed terminal receipt must be replayable.",
                    source_refs=[],
                    topics=["failed-sidecar-recovery"],
                )
                conn.execute("DELETE FROM queue_jobs")
                job_id = enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_card_placement",
                    priority=1,
                    payload={"card_id": card_id},
                    related_card_ids=[card_id],
                    dedupe_key=f"failed-placement:{card_id}",
                )
                conn.commit()
            finally:
                conn.close()
            with patch.object(
                worker_module,
                "_sync_worker_card_sidecars",
                return_value={
                    "ok": False,
                    "synced": 0,
                    "failed": 1,
                    "failures": [
                        {
                            "card_id": card_id,
                            "error": "simulated old placement sidecar failure",
                        }
                    ],
                },
            ):
                deferred = run_worker_pass(
                    root,
                    roles=["librarian"],
                    limit=1,
                    maintenance=False,
                )
            self.assertEqual(
                deferred["processed"][0]["status"],
                "pending",
                deferred,
            )
            return (
                job_id,
                "review_card_placement",
                deferred["processed"][0]["result"],
            )

        def prepare_mempalace(
            root: Path,
        ) -> tuple[str, str, dict[str, object]]:
            init_db(root)
            import_id = "failed-mempalace-sidecar-recovery"
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="mempalace_drawer",
                    title="Recover failed MemPalace sidecar",
                    summary="Imported authority must survive an old failure.",
                    source_refs=[],
                    metadata={"import_id": import_id},
                )
                card_node = upsert_graph_node(
                    conn,
                    kind="card",
                    label="Recover failed MemPalace sidecar",
                    card_id=card_id,
                )
                term_node = upsert_graph_node(
                    conn,
                    kind="term",
                    label="mempalace",
                )
                add_graph_edge(
                    conn,
                    source_node_id=card_node,
                    relation="mentions",
                    target_node_id=term_node,
                    weight=0.5,
                    confidence=0.8,
                    source_refs=[{"card_id": card_id}],
                )
                conn.execute("DELETE FROM queue_jobs")
                job_id = enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_mempalace_import",
                    priority=1,
                    payload={"import_id": import_id},
                    related_card_ids=[card_id],
                    dedupe_key=f"failed-import:{import_id}",
                )
                conn.commit()
            finally:
                conn.close()
            with patch.object(
                worker_module,
                "_sync_worker_card_sidecars",
                return_value={
                    "ok": False,
                    "synced": 0,
                    "failed": 1,
                    "failures": [
                        {
                            "card_id": card_id,
                            "error": "simulated old MemPalace sidecar failure",
                        }
                    ],
                },
            ):
                deferred = run_worker_pass(
                    root,
                    roles=["librarian"],
                    limit=1,
                    maintenance=False,
                )
            self.assertEqual(
                deferred["processed"][0]["status"],
                "pending",
                deferred,
            )
            return (
                job_id,
                "review_mempalace_import",
                deferred["processed"][0]["result"],
            )

        def prepare_scribe(
            root: Path,
        ) -> tuple[str, str, dict[str, object]]:
            init_db(root)
            config = default_config()
            config["capture"]["roll_segments_every_events"] = 1
            write_config(root, config)
            session_id = "failed-scribe-sidecar-recovery"
            append_scroll_event(
                root,
                session_id=session_id,
                event_type="message",
                role="user",
                content="Recover an old failed Scribe completion receipt.",
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
                    dedupe_key=f"failed-scribe:{session_id}",
                )
                conn.commit()
            finally:
                conn.close()
            with patch.object(
                store_module,
                "sync_card_sidecars_after_commit",
                return_value={
                    "ok": False,
                    "synced": 0,
                    "failed": 1,
                    "failures": [
                        {
                            "error": "simulated old Scribe sidecar failure",
                        }
                    ],
                },
            ):
                deferred = run_worker_pass(
                    root,
                    roles=["scribe"],
                    limit=1,
                    maintenance=False,
                )
            self.assertEqual(
                deferred["processed"][0]["status"],
                "pending",
                deferred,
            )
            deferred_result = deferred["processed"][0]["result"]
            self.assertEqual(len(deferred_result["rolled"]), 1)
            failed_step = deferred_result["rolled"][0]
            conn = connect(root)
            try:
                committed_payload = json.loads(
                    conn.execute(
                        """
                        SELECT payload_json
                        FROM audit_events
                        WHERE action = ?
                          AND target_type = 'queue_job'
                          AND target_id = ?
                        ORDER BY rowid DESC
                        LIMIT 1
                        """,
                        (
                            worker_module._SCRIBE_STEP_COMMITTED_ACTION,
                            job_id,
                        ),
                    ).fetchone()["payload_json"]
                )
                store_module.audit_event(
                    conn,
                    action=worker_module._SCRIBE_STEP_COMPLETED_ACTION,
                    target_type="queue_job",
                    target_id=job_id,
                    payload={
                        "schema": (
                            "continuum."
                            "worker_scribe_segment_step_completed.v1"
                        ),
                        "step_key": committed_payload["step_key"],
                        "session_id": committed_payload["session_id"],
                        "start_seq": committed_payload["start_seq"],
                        "end_seq": committed_payload["end_seq"],
                        "batch_number": committed_payload["batch_number"],
                        "result": failed_step,
                    },
                )
                conn.commit()
            finally:
                conn.close()
            return (
                job_id,
                "scroll_event_ingested",
                deferred_result,
            )

        cases = (
            ("placement", "librarian", prepare_placement),
            ("mempalace", "librarian", prepare_mempalace),
            ("scribe", "scribe", prepare_scribe),
        )
        for name, role, prepare in cases:
            with (
                self.subTest(job_type=name),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp) / "continuum"
                job_id, job_type, deferred_result = prepare(root)
                old_effect_id, failed_result = seed_failed_terminal_effect(
                    root,
                    job_id=job_id,
                    job_type=job_type,
                    deferred_result=deferred_result,
                )

                maintenance = run_worker_pass(
                    root,
                    roles=["no-recovery-jobs"],
                    limit=1,
                    maintenance=True,
                )
                self.assertTrue(maintenance["ok"], maintenance)
                self.assertEqual(maintenance["processed_count"], 0)
                recovery = maintenance["maintenance"][
                    "failed_sidecar_jobs"
                ]
                self.assertEqual(recovery["selected"], 1, recovery)
                self.assertEqual(recovery["requeued"], 1, recovery)
                self.assertEqual(recovery["rejected"], 0, recovery)
                self.assertFalse(recovery["has_more"], recovery)

                conn = connect_existing(root)
                try:
                    retry_row = conn.execute(
                        """
                        SELECT status, attempt_count, finished_at,
                               lease_owner, lease_expires_at, heartbeat_at,
                               error_json
                        FROM queue_jobs
                        WHERE id = ?
                        """,
                        (job_id,),
                    ).fetchone()
                    old_effect = json.loads(
                        conn.execute(
                            """
                            SELECT payload_json
                            FROM audit_events
                            WHERE id = ?
                            """,
                            (old_effect_id,),
                        ).fetchone()["payload_json"]
                    )
                    dispositions = int(
                        conn.execute(
                            """
                            SELECT count(*) AS n
                            FROM audit_events
                            WHERE action = ? AND target_id = ?
                            """,
                            (
                                worker_module
                                ._FAILED_SIDECAR_RECOVERY_ACTION,
                                job_id,
                            ),
                        ).fetchone()["n"]
                    )
                finally:
                    conn.close()
                self.assertEqual(retry_row["status"], "pending")
                self.assertEqual(retry_row["attempt_count"], 1)
                self.assertIsNone(retry_row["finished_at"])
                self.assertIsNone(retry_row["lease_owner"])
                self.assertIsNone(retry_row["lease_expires_at"])
                self.assertIsNone(retry_row["heartbeat_at"])
                self.assertTrue(
                    json.loads(retry_row["error_json"])["retry_pending"]
                )
                self.assertEqual(old_effect["result"], failed_result)
                self.assertEqual(dispositions, 1)

                recovered = run_worker_pass(
                    root,
                    roles=[role],
                    limit=1,
                    maintenance=False,
                )
                self.assertTrue(recovered["ok"], recovered)
                self.assertEqual(recovered["processed_count"], 1)
                recovered_job = recovered["processed"][0]
                self.assertEqual(recovered_job["job_id"], job_id)
                self.assertEqual(recovered_job["status"], "succeeded")
                self.assertTrue(recovered_job["result"]["ok"])

                conn = connect_existing(root)
                try:
                    final_row = conn.execute(
                        """
                        SELECT status, attempt_count
                        FROM queue_jobs
                        WHERE id = ?
                        """,
                        (job_id,),
                    ).fetchone()
                    effects = [
                        json.loads(row["payload_json"])
                        for row in conn.execute(
                            """
                            SELECT payload_json
                            FROM audit_events
                            WHERE action = ? AND target_id = ?
                            ORDER BY rowid
                            """,
                            (
                                worker_module._WORKER_EFFECT_ACTION,
                                job_id,
                            ),
                        ).fetchall()
                    ]
                finally:
                    conn.close()
                self.assertEqual(final_row["status"], "succeeded")
                self.assertEqual(final_row["attempt_count"], 2)
                self.assertEqual(len(effects), 2)
                self.assertEqual(effects[0]["result"], failed_result)
                self.assertTrue(effects[-1]["result"]["ok"])
                self.assertEqual(memory_health(root)["failed_jobs"], 0)

                repeated = run_worker_pass(
                    root,
                    roles=["no-recovery-jobs"],
                    limit=1,
                    maintenance=True,
                )
                self.assertEqual(
                    repeated["maintenance"]["failed_sidecar_jobs"][
                        "requeued"
                    ],
                    0,
                    repeated,
                )

    def test_committed_only_scribe_recovery_rearms_missing_sidecar_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            job_id, session_id, deferred_result = (
                self._prepare_committed_only_scribe_failure(
                    root,
                    run_count=1,
                    namespace="committed-only-rearm",
                )
            )
            self.assertEqual(deferred_result["rolled_count"], 1)
            deferred_step = deferred_result["rolled"][0]
            self.assertTrue(
                deferred_step["sidecars"]["completion_receipt_missing"]
            )
            self.assertTrue(deferred_step["sidecars"]["pending_outbox"])
            card_id = str(deferred_step["card_id"])
            conn = connect(root)
            try:
                location_uri = str(
                    conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()["location_uri"]
                )
                conn.execute(
                    "DELETE FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                )
                before = {
                    "segments": int(
                        conn.execute(
                            """
                            SELECT count(*) FROM scroll_segments
                            WHERE session_id = ?
                            """,
                            (session_id,),
                        ).fetchone()[0]
                    ),
                    "rolls": int(
                        conn.execute(
                            """
                            SELECT count(*) FROM audit_events
                            WHERE action = 'roll_scroll_segment'
                            """
                        ).fetchone()[0]
                    ),
                    "completed": int(
                        conn.execute(
                            """
                            SELECT count(*) FROM audit_events
                            WHERE action = ? AND target_id = ?
                            """,
                            (
                                worker_module._SCRIBE_STEP_COMPLETED_ACTION,
                                job_id,
                            ),
                        ).fetchone()[0]
                    ),
                }
                conn.commit()
            finally:
                conn.close()
            sidecar_path = resolve_stored_uri(root, location_uri)
            if sidecar_path.exists():
                sidecar_path.unlink()
            self._seed_legacy_failed_worker_effect(
                root,
                job_id=job_id,
                job_type="scroll_event_ingested",
                deferred_result=deferred_result,
            )

            recovery = (
                worker_module._recover_failed_post_phase_sidecar_jobs(root)
            )
            self.assertEqual(recovery["requeued"], 1, recovery)
            self.assertEqual(recovery["rejected"], 0, recovery)

            rearmed = run_worker_pass(
                root,
                roles=["scribe"],
                limit=1,
                maintenance=False,
            )
            self.assertFalse(rearmed["ok"], rearmed)
            self.assertEqual(rearmed["processed"][0]["status"], "pending")
            self.assertTrue(
                rearmed["processed"][0]["result"]["retry_pending"]
            )
            conn = connect_existing(root)
            try:
                outbox = conn.execute(
                    """
                    SELECT reason FROM card_sidecar_outbox
                    WHERE card_id = ?
                    """,
                    (card_id,),
                ).fetchone()
                after_rearm = {
                    "segments": int(
                        conn.execute(
                            """
                            SELECT count(*) FROM scroll_segments
                            WHERE session_id = ?
                            """,
                            (session_id,),
                        ).fetchone()[0]
                    ),
                    "rolls": int(
                        conn.execute(
                            """
                            SELECT count(*) FROM audit_events
                            WHERE action = 'roll_scroll_segment'
                            """
                        ).fetchone()[0]
                    ),
                    "completed": int(
                        conn.execute(
                            """
                            SELECT count(*) FROM audit_events
                            WHERE action = ? AND target_id = ?
                            """,
                            (
                                worker_module._SCRIBE_STEP_COMPLETED_ACTION,
                                job_id,
                            ),
                        ).fetchone()[0]
                    ),
                }
            finally:
                conn.close()
            self.assertIsNotNone(outbox)
            self.assertEqual(
                outbox["reason"],
                "scribe_committed_step_sidecar_authority_missing",
            )
            self.assertEqual(after_rearm, before)

            drained = drain_card_sidecar_outbox(root, limit=50)
            self.assertTrue(drained["ok"], drained)
            completed = run_worker_pass(
                root,
                roles=["scribe"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(completed["ok"], completed)
            self.assertEqual(
                completed["processed"][0]["status"],
                "succeeded",
            )
            self.assertEqual(
                completed["processed"][0]["result"]["rolled"][0][
                    "segment_id"
                ],
                deferred_step["segment_id"],
            )

    def test_failed_scribe_recovery_validates_65_security_runs_in_two_passes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            job_id, session_id, deferred_result = (
                self._prepare_committed_only_scribe_failure(
                    root,
                    run_count=65,
                    namespace="bounded-65-run-recovery",
                )
            )
            self.assertEqual(deferred_result["rolled_count"], 65)
            self.assertEqual(deferred_result["batches_processed"], 1)
            self.assertEqual(
                {
                    item["sidecars"]["completion_receipt_missing"]
                    for item in deferred_result["rolled"]
                },
                {True},
            )
            self._seed_legacy_failed_worker_effect(
                root,
                job_id=job_id,
                job_type="scroll_event_ingested",
                deferred_result=deferred_result,
            )

            first = (
                worker_module._recover_failed_post_phase_sidecar_jobs(root)
            )
            self.assertEqual(first["validating"], 1, first)
            self.assertEqual(first["requeued"], 0, first)
            self.assertEqual(first["rejected"], 0, first)
            self.assertTrue(first["has_more"], first)
            self.assertFalse(first["complete"], first)
            conn = connect_existing(root)
            try:
                first_status = conn.execute(
                    "SELECT status FROM queue_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()["status"]
                progress_state = json.loads(
                    conn.execute(
                        """
                        SELECT payload_json FROM audit_events
                        WHERE action = ? AND target_id = ?
                          AND json_extract(
                              payload_json,
                              '$.decision'
                          ) = 'validating'
                        ORDER BY rowid DESC LIMIT 1
                        """,
                        (
                            worker_module
                            ._FAILED_SIDECAR_RECOVERY_ACTION,
                            job_id,
                        ),
                    ).fetchone()["payload_json"]
                )["validation_state"]
            finally:
                conn.close()
            self.assertEqual(first_status, "failed")
            self.assertEqual(progress_state["validated_count"], 64)
            self.assertEqual(progress_state["batch_numbers"], [1])

            second = (
                worker_module._recover_failed_post_phase_sidecar_jobs(root)
            )
            self.assertEqual(second["validating"], 0, second)
            self.assertEqual(second["requeued"], 1, second)
            self.assertEqual(second["rejected"], 0, second)
            self.assertFalse(second["has_more"], second)
            self.assertTrue(second["complete"], second)

            for _ in range(2):
                drained = drain_card_sidecar_outbox(root, limit=50)
                self.assertTrue(drained["ok"], drained)
            recovered = run_worker_pass(
                root,
                roles=["scribe"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(recovered["ok"], recovered)
            self.assertEqual(
                recovered["processed"][0]["status"],
                "succeeded",
            )
            conn = connect_existing(root)
            try:
                evidence = {
                    "segments": int(
                        conn.execute(
                            """
                            SELECT count(*) FROM scroll_segments
                            WHERE session_id = ?
                            """,
                            (session_id,),
                        ).fetchone()[0]
                    ),
                    "distinct_segments": int(
                        conn.execute(
                            """
                            SELECT count(DISTINCT id) FROM scroll_segments
                            WHERE session_id = ?
                            """,
                            (session_id,),
                        ).fetchone()[0]
                    ),
                    "cards": int(
                        conn.execute(
                            """
                            SELECT count(*) FROM cards
                            WHERE card_type = 'scroll_segment'
                              AND session_id = ?
                            """,
                            (session_id,),
                        ).fetchone()[0]
                    ),
                    "rolls": int(
                        conn.execute(
                            """
                            SELECT count(*) FROM audit_events
                            WHERE action = 'roll_scroll_segment'
                            """
                        ).fetchone()[0]
                    ),
                    "committed": int(
                        conn.execute(
                            """
                            SELECT count(*) FROM audit_events
                            WHERE action = ? AND target_id = ?
                            """,
                            (
                                worker_module._SCRIBE_STEP_COMMITTED_ACTION,
                                job_id,
                            ),
                        ).fetchone()[0]
                    ),
                    "completed": int(
                        conn.execute(
                            """
                            SELECT count(*) FROM audit_events
                            WHERE action = ? AND target_id = ?
                            """,
                            (
                                worker_module._SCRIBE_STEP_COMPLETED_ACTION,
                                job_id,
                            ),
                        ).fetchone()[0]
                    ),
                    "batches": int(
                        conn.execute(
                            """
                            SELECT count(DISTINCT json_extract(
                                payload_json,
                                '$.batch_number'
                            ))
                            FROM audit_events
                            WHERE action = ? AND target_id = ?
                            """,
                            (
                                worker_module._SCRIBE_STEP_COMMITTED_ACTION,
                                job_id,
                            ),
                        ).fetchone()[0]
                    ),
                }
            finally:
                conn.close()
            self.assertEqual(
                evidence,
                {
                    "segments": 65,
                    "distinct_segments": 65,
                    "cards": 65,
                    "rolls": 65,
                    "committed": 65,
                    "completed": 0,
                    "batches": 1,
                },
            )

    def test_failed_scribe_final_validation_rechecks_early_child_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            progressed_root = Path(tmp) / "progressed"
            job_id, _session_id, deferred_result = (
                self._prepare_committed_only_scribe_failure(
                    progressed_root,
                    run_count=65,
                    namespace="early-child-final-authority",
                )
            )
            self._seed_legacy_failed_worker_effect(
                progressed_root,
                job_id=job_id,
                job_type="scroll_event_ingested",
                deferred_result=deferred_result,
            )
            first = (
                worker_module._recover_failed_post_phase_sidecar_jobs(
                    progressed_root
                )
            )
            self.assertEqual(first["validating"], 1, first)
            self.assertEqual(first["requeued"], 0, first)
            self.assertEqual(first["rejected"], 0, first)

            conn = connect_existing(progressed_root)
            try:
                first_receipt = conn.execute(
                    """
                    SELECT payload_json
                    FROM audit_events
                    WHERE action = ? AND target_id = ?
                    ORDER BY rowid
                    LIMIT 1
                    """,
                    (
                        worker_module._SCRIBE_STEP_COMMITTED_ACTION,
                        job_id,
                    ),
                ).fetchone()
            finally:
                conn.close()
            early_librarian_id = str(
                json.loads(first_receipt["payload_json"])["result"][
                    "librarian_job_id"
                ]
            )

            for variant in (
                "wrong_shaped_dedupe",
                "extra_payload_field",
                "null_required_payload",
            ):
                with self.subTest(variant=variant):
                    root = Path(tmp) / variant
                    shutil.copytree(progressed_root, root)
                    conn = connect(root)
                    try:
                        child = conn.execute(
                            """
                            SELECT payload_json
                            FROM queue_jobs
                            WHERE id = ?
                            """,
                            (early_librarian_id,),
                        ).fetchone()
                        self.assertIsNotNone(child)
                        if variant == "wrong_shaped_dedupe":
                            conn.execute(
                                """
                                UPDATE queue_jobs
                                SET dedupe_key = ?
                                WHERE id = ?
                                """,
                                (
                                    "queue_v1_not-a-canonical-digest",
                                    early_librarian_id,
                                ),
                            )
                        else:
                            payload = json.loads(child["payload_json"])
                            if variant == "extra_payload_field":
                                payload["unexpected_authority"] = True
                            else:
                                payload["visibility_scope"] = None
                            conn.execute(
                                """
                                UPDATE queue_jobs
                                SET payload_json = ?
                                WHERE id = ?
                                """,
                                (
                                    store_module.json_dumps(payload),
                                    early_librarian_id,
                                ),
                            )
                        conn.commit()
                    finally:
                        conn.close()

                    second = (
                        worker_module
                        ._recover_failed_post_phase_sidecar_jobs(root)
                    )
                    self.assertEqual(second["validating"], 0, second)
                    self.assertEqual(second["requeued"], 0, second)
                    self.assertEqual(second["rejected"], 1, second)
                    self.assertFalse(second["has_more"], second)
                    self.assertTrue(second["complete"], second)
                    self.assertEqual(
                        second["dispositions"][0]["reason"],
                        (
                            "scribe_final_committed_or_live_"
                            "authority_drift"
                        ),
                    )
                    conn = connect_existing(root)
                    try:
                        status = conn.execute(
                            """
                            SELECT status
                            FROM queue_jobs
                            WHERE id = ?
                            """,
                            (job_id,),
                        ).fetchone()["status"]
                    finally:
                        conn.close()
                    self.assertEqual(status, "failed")

    def test_failed_archivist_terminal_replay_is_migrated_and_replayed(
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
                    title="Recover old Archivist terminal replay",
                    summary=(
                        "A clean terminal effect remains authoritative after "
                        "an old reconciliation replay was misclassified."
                    ),
                    source_refs=[],
                )
                conn.execute("DELETE FROM queue_jobs")
                job_id = enqueue_job(
                    conn,
                    role="archivist",
                    job_type="sync_card_sidecar",
                    priority=1,
                    payload={"card_id": card_id},
                    related_card_ids=[card_id],
                    dedupe_key=f"old-archivist-replay:{card_id}",
                )
                conn.commit()
            finally:
                conn.close()
            first = run_worker_pass(
                root,
                roles=["archivist"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(first["ok"], first)
            self.assertEqual(first["processed"][0]["status"], "succeeded")

            conn = connect(root)
            try:
                effect_row = conn.execute(
                    """
                    SELECT id, payload_json
                    FROM audit_events
                    WHERE action = ? AND target_id = ?
                    ORDER BY rowid DESC LIMIT 1
                    """,
                    (
                        worker_module._WORKER_EFFECT_ACTION,
                        job_id,
                    ),
                ).fetchone()
                effect_payload = json.loads(effect_row["payload_json"])
                terminal_result = effect_payload["result"]
                failed_reconciliation = {
                    "ok": False,
                    "processed": 0,
                    "pending": 1,
                    "complete": False,
                    "scope_complete": False,
                    "failures": [
                        {
                            "card_id": card_id,
                            "error": "simulated old reconciliation failure",
                        }
                    ],
                }
                failed_replay = {
                    **terminal_result,
                    "ok": False,
                    "idempotent_replay": True,
                    "intent_reconciliation": failed_reconciliation,
                }
                phase_id = store_module.audit_event(
                    conn,
                    action=worker_module._SIDECAR_WORKER_PHASE_ACTION,
                    target_type="queue_job",
                    target_id=job_id,
                    payload={
                        "schema": (
                            worker_module._SIDECAR_WORKER_PHASE_SCHEMA
                        ),
                        "job_type": "sync_card_sidecar",
                        "phase": "reconciliation_deferred",
                        "result": failed_replay,
                    },
                )
                now = store_module.utc_now()
                cursor = conn.execute(
                    """
                    UPDATE queue_jobs
                    SET status = 'failed', finished_at = ?, updated_at = ?,
                        lease_owner = NULL, lease_expires_at = NULL,
                        error_json = ?
                    WHERE id = ? AND status = 'succeeded'
                    """,
                    (
                        now,
                        now,
                        store_module.json_dumps(
                            {
                                "error": (
                                    "worker result reported ok=false"
                                ),
                                "result": failed_replay,
                            }
                        ),
                        job_id,
                    ),
                )
                self.assertEqual(cursor.rowcount, 1)
                conn.commit()
            finally:
                conn.close()

            recovery = (
                worker_module._recover_failed_post_phase_sidecar_jobs(root)
            )
            self.assertEqual(recovery["requeued"], 1, recovery)
            self.assertEqual(recovery["rejected"], 0, recovery)
            disposition = recovery["dispositions"][0]
            self.assertEqual(disposition["effect_event_id"], effect_row["id"])

            replayed = run_worker_pass(
                root,
                roles=["archivist"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(replayed["ok"], replayed)
            replayed_job = replayed["processed"][0]
            self.assertEqual(replayed_job["status"], "succeeded")
            self.assertTrue(replayed_job["result"]["idempotent_replay"])
            self.assertTrue(
                replayed_job["result"]["intent_reconciliation"]["ok"]
            )
            conn = connect_existing(root)
            try:
                final_row = conn.execute(
                    """
                    SELECT status, attempt_count FROM queue_jobs
                    WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone()
                effect_count = int(
                    conn.execute(
                        """
                        SELECT count(*) FROM audit_events
                        WHERE action = ? AND target_id = ?
                        """,
                        (
                            worker_module._WORKER_EFFECT_ACTION,
                            job_id,
                        ),
                    ).fetchone()[0]
                )
                preserved_phase = conn.execute(
                    "SELECT 1 FROM audit_events WHERE id = ?",
                    (phase_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(final_row["status"], "succeeded")
            self.assertEqual(final_row["attempt_count"], 2)
            self.assertEqual(effect_count, 1)
            self.assertIsNotNone(preserved_phase)

    def test_failed_scribe_progress_rechecks_early_live_authority(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            job_id, _session_id, deferred_result = (
                self._prepare_committed_only_scribe_failure(
                    root,
                    run_count=65,
                    namespace="progress-antidrift",
                )
            )
            self._seed_legacy_failed_worker_effect(
                root,
                job_id=job_id,
                job_type="scroll_event_ingested",
                deferred_result=deferred_result,
            )
            first = (
                worker_module._recover_failed_post_phase_sidecar_jobs(root)
            )
            self.assertEqual(first["validating"], 1, first)
            self.assertEqual(first["rejected"], 0, first)

            conn = connect(root)
            try:
                first_core = json.loads(
                    conn.execute(
                        """
                        SELECT payload_json FROM audit_events
                        WHERE action = ? AND target_id = ?
                        ORDER BY rowid LIMIT 1
                        """,
                        (
                            worker_module._SCRIBE_STEP_COMMITTED_ACTION,
                            job_id,
                        ),
                    ).fetchone()["payload_json"]
                )["result"]
                conn.execute(
                    """
                    UPDATE scroll_segments
                    SET token_estimate = token_estimate + 1
                    WHERE id = ?
                    """,
                    (first_core["segment_id"],),
                )
                conn.commit()
            finally:
                conn.close()

            second = (
                worker_module._recover_failed_post_phase_sidecar_jobs(root)
            )
            self.assertEqual(second["validating"], 0, second)
            self.assertEqual(second["requeued"], 0, second)
            self.assertEqual(second["rejected"], 1, second)
            self.assertEqual(
                second["dispositions"][0]["reason"],
                "scribe_final_committed_or_live_authority_drift",
            )
            conn = connect_existing(root)
            try:
                status = conn.execute(
                    "SELECT status FROM queue_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()["status"]
            finally:
                conn.close()
            self.assertEqual(status, "failed")

    def test_failed_scribe_recovery_rejects_forged_stale_and_duplicate_authority(
        self,
    ) -> None:
        scenarios = {
            "completed_core_mismatch": {
                "reasons": {
                    "scribe_completed_identity_mismatch",
                    "scribe_completed_result_mismatch",
                }
            },
            "duplicate_committed": {
                "reasons": {
                    "scribe_committed_range_not_contiguous",
                    "scribe_terminal_result_missing_step",
                }
            },
            "receipt_after_effect": {
                "reasons": {"scribe_receipt_after_terminal_effect"}
            },
            "committed_core_forgery": {
                "reasons": {
                    "scribe_live_child_job_missing",
                    "scribe_terminal_core_mismatch",
                }
            },
            "live_token_drift": {
                "reasons": {
                    "scribe_live_segment_identity_mismatch",
                    "scribe_live_event_or_token_mismatch",
                }
            },
            "child_job_forgery": {
                "reasons": {"scribe_live_child_job_identity_mismatch"}
            },
            "cross_boundary_forgery": {
                "reasons": {"scribe_live_security_boundary_mismatch"}
            },
        }
        for scenario, expectation in scenarios.items():
            with (
                self.subTest(scenario=scenario),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp) / "continuum"
                job_id, _session_id, deferred_result = (
                    self._prepare_committed_only_scribe_failure(
                        root,
                        run_count=1,
                        namespace=f"forged-{scenario}",
                    )
                )
                conn = connect(root)
                try:
                    committed_row = conn.execute(
                        """
                        SELECT id, payload_json
                        FROM audit_events
                        WHERE action = ? AND target_id = ?
                        ORDER BY rowid LIMIT 1
                        """,
                        (
                            worker_module._SCRIBE_STEP_COMMITTED_ACTION,
                            job_id,
                        ),
                    ).fetchone()
                    committed_payload = json.loads(
                        committed_row["payload_json"]
                    )
                    if scenario == "completed_core_mismatch":
                        completed_result = dict(
                            deferred_result["rolled"][0]
                        )
                        completed_result["token_estimate"] += 1
                        store_module.audit_event(
                            conn,
                            action=(
                                worker_module
                                ._SCRIBE_STEP_COMPLETED_ACTION
                            ),
                            target_type="queue_job",
                            target_id=job_id,
                            payload={
                                "schema": (
                                    "continuum."
                                    "worker_scribe_segment_step_completed.v1"
                                ),
                                "step_key": committed_payload["step_key"],
                                "session_id": (
                                    committed_payload["session_id"]
                                ),
                                "start_seq": (
                                    committed_payload["start_seq"]
                                ),
                                "end_seq": committed_payload["end_seq"],
                                "batch_number": (
                                    committed_payload["batch_number"]
                                ),
                                "result": completed_result,
                            },
                        )
                    elif scenario == "duplicate_committed":
                        store_module.audit_event(
                            conn,
                            action=(
                                worker_module
                                ._SCRIBE_STEP_COMMITTED_ACTION
                            ),
                            target_type="queue_job",
                            target_id=job_id,
                            payload=committed_payload,
                        )
                    elif scenario == "committed_core_forgery":
                        committed_payload["result"][
                            "librarian_job_id"
                        ] = "job_forged_missing_librarian"
                        conn.execute(
                            """
                            UPDATE audit_events SET payload_json = ?
                            WHERE id = ?
                            """,
                            (
                                store_module.json_dumps(
                                    committed_payload
                                ),
                                committed_row["id"],
                            ),
                        )
                    conn.commit()
                finally:
                    conn.close()
                self._seed_legacy_failed_worker_effect(
                    root,
                    job_id=job_id,
                    job_type="scroll_event_ingested",
                    deferred_result=deferred_result,
                )
                if scenario in {
                    "receipt_after_effect",
                    "live_token_drift",
                    "child_job_forgery",
                    "cross_boundary_forgery",
                }:
                    conn = connect(root)
                    try:
                        if scenario == "receipt_after_effect":
                            store_module.audit_event(
                                conn,
                                action=(
                                    worker_module
                                    ._SCRIBE_STEP_COMPLETED_ACTION
                                ),
                                target_type="queue_job",
                                target_id=job_id,
                                payload={
                                    "schema": (
                                        "continuum."
                                        "worker_scribe_segment_step_completed.v1"
                                    ),
                                    "step_key": (
                                        committed_payload["step_key"]
                                    ),
                                    "session_id": (
                                        committed_payload["session_id"]
                                    ),
                                    "start_seq": (
                                        committed_payload["start_seq"]
                                    ),
                                    "end_seq": (
                                        committed_payload["end_seq"]
                                    ),
                                    "batch_number": (
                                        committed_payload["batch_number"]
                                    ),
                                    "result": (
                                        deferred_result["rolled"][0]
                                    ),
                                },
                            )
                        elif scenario == "live_token_drift":
                            conn.execute(
                                """
                                UPDATE scroll_segments
                                SET token_estimate = token_estimate + 1
                                WHERE id = ?
                                """,
                                (
                                    committed_payload["result"][
                                        "segment_id"
                                    ],
                                ),
                            )
                        elif scenario == "child_job_forgery":
                            conn.execute(
                                """
                                UPDATE queue_jobs SET payload_json = '{}'
                                WHERE id = ?
                                """,
                                (
                                    committed_payload["result"][
                                        "librarian_job_id"
                                    ],
                                ),
                            )
                        else:
                            card_id = committed_payload["result"][
                                "card_id"
                            ]
                            conn.execute(
                                """
                                UPDATE cards
                                SET visibility_scope = 'project',
                                    project_id = 'forged-project'
                                WHERE id = ?
                                """,
                                (card_id,),
                            )
                            for child_key in (
                                "librarian_job_id",
                                "archivist_job_id",
                            ):
                                child_id = committed_payload["result"][
                                    child_key
                                ]
                                child_payload = json.loads(
                                    conn.execute(
                                        """
                                        SELECT payload_json FROM queue_jobs
                                        WHERE id = ?
                                        """,
                                        (child_id,),
                                    ).fetchone()["payload_json"]
                                )
                                child_payload["visibility_scope"] = (
                                    "project"
                                )
                                child_payload["project_id"] = (
                                    "forged-project"
                                )
                                conn.execute(
                                    """
                                    UPDATE queue_jobs SET payload_json = ?
                                    WHERE id = ?
                                    """,
                                    (
                                        store_module.json_dumps(
                                            child_payload
                                        ),
                                        child_id,
                                    ),
                                )
                        conn.commit()
                    finally:
                        conn.close()

                recovery = (
                    worker_module
                    ._recover_failed_post_phase_sidecar_jobs(root)
                )
                self.assertEqual(recovery["requeued"], 0, recovery)
                self.assertEqual(recovery["rejected"], 1, recovery)
                self.assertIn(
                    recovery["dispositions"][0]["reason"],
                    expectation["reasons"],
                )
                conn = connect_existing(root)
                try:
                    failed_status = conn.execute(
                        "SELECT status FROM queue_jobs WHERE id = ?",
                        (job_id,),
                    ).fetchone()["status"]
                finally:
                    conn.close()
                self.assertEqual(failed_status, "failed")
                repeated = (
                    worker_module
                    ._recover_failed_post_phase_sidecar_jobs(root)
                )
                self.assertEqual(repeated["selected"], 0, repeated)

    def test_post_commit_exceptions_and_legacy_effectless_rows_retry(
        self,
    ) -> None:
        for job_type in (
            "review_card_placement",
            "review_mempalace_import",
        ):
            with (
                self.subTest(job_type=job_type),
                tempfile.TemporaryDirectory() as tmp,
            ):
                root = Path(tmp) / "continuum"
                init_db(root)
                conn = connect(root)
                try:
                    if job_type == "review_card_placement":
                        role = "librarian"
                        card_id = create_card(
                            conn,
                            root=root,
                            card_type="decision",
                            title="Effectless placement recovery",
                            summary=(
                                "The exact committed core phase must retain "
                                "retry authority."
                            ),
                            source_refs=[],
                        )
                        payload = {"card_id": card_id}
                        related_card_ids = [card_id]
                    else:
                        role = "librarian"
                        import_id = "effectless-mempalace-recovery"
                        card_id = create_card(
                            conn,
                            root=root,
                            card_type="mempalace_drawer",
                            title="Effectless MemPalace recovery",
                            summary=(
                                "A migrated drawer survives a final receipt "
                                "exception."
                            ),
                            source_refs=[],
                            metadata={"import_id": import_id},
                        )
                        card_node = upsert_graph_node(
                            conn,
                            kind="card",
                            label="Effectless MemPalace recovery",
                            card_id=card_id,
                        )
                        term_node = upsert_graph_node(
                            conn,
                            kind="term",
                            label="effectless-mempalace",
                        )
                        add_graph_edge(
                            conn,
                            source_node_id=card_node,
                            relation="mentions",
                            target_node_id=term_node,
                            weight=0.5,
                            confidence=0.8,
                            source_refs=[{"card_id": card_id}],
                        )
                        payload = {"import_id": import_id}
                        related_card_ids = [card_id]
                    conn.execute("DELETE FROM queue_jobs")
                    job_id = enqueue_job(
                        conn,
                        role=role,
                        job_type=job_type,
                        priority=1,
                        payload=payload,
                        related_card_ids=related_card_ids,
                        dedupe_key=f"effectless:{job_type}:{card_id}",
                    )
                    conn.commit()
                finally:
                    conn.close()

                with patch.object(
                    worker_module,
                    "_commit_worker_effect_result",
                    side_effect=RuntimeError(
                        "forced post-commit final receipt exception"
                    ),
                ):
                    interrupted = run_worker_pass(
                        root,
                        roles=[role],
                        limit=1,
                        maintenance=False,
                    )
                self.assertFalse(interrupted["ok"], interrupted)
                interrupted_job = interrupted["processed"][0]
                self.assertEqual(interrupted_job["status"], "pending")
                self.assertEqual(
                    interrupted_job["result"]["reason"],
                    worker_module.POST_COMMIT_EXCEPTION_RETRY_REASON,
                )
                self.assertTrue(
                    interrupted_job["result"]["retry_pending"]
                )

                conn = connect(root)
                try:
                    phase_count = int(
                        conn.execute(
                            """
                            SELECT count(*) FROM audit_events
                            WHERE action = ? AND target_id = ?
                            """,
                            (
                                worker_module._WORKER_PHASE_ACTION,
                                job_id,
                            ),
                        ).fetchone()[0]
                    )
                    effect_count = int(
                        conn.execute(
                            """
                            SELECT count(*) FROM audit_events
                            WHERE action = ? AND target_id = ?
                            """,
                            (
                                worker_module._WORKER_EFFECT_ACTION,
                                job_id,
                            ),
                        ).fetchone()[0]
                    )
                    now = store_module.utc_now()
                    cursor = conn.execute(
                        """
                        UPDATE queue_jobs
                        SET status = 'failed', finished_at = ?,
                            updated_at = ?, error_json = ?,
                            lease_owner = NULL, lease_expires_at = NULL,
                            heartbeat_at = NULL
                        WHERE id = ? AND status = 'pending'
                        """,
                        (
                            now,
                            now,
                            store_module.json_dumps(
                                {
                                    "error": (
                                        "legacy final receipt exception"
                                    ),
                                    "result": {},
                                }
                            ),
                            job_id,
                        ),
                    )
                    self.assertEqual(cursor.rowcount, 1)
                    conn.commit()
                finally:
                    conn.close()
                self.assertEqual(phase_count, 1)
                self.assertEqual(effect_count, 0)

                recovery = (
                    worker_module
                    ._recover_failed_post_phase_sidecar_jobs(root)
                )
                self.assertEqual(recovery["requeued"], 1, recovery)
                self.assertEqual(recovery["rejected"], 0, recovery)
                self.assertEqual(
                    recovery["dispositions"][0]["effect_event_id"],
                    worker_module._FAILED_SIDECAR_EFFECTLESS_KEY,
                )

                replayed = run_worker_pass(
                    root,
                    roles=[role],
                    limit=1,
                    maintenance=False,
                )
                self.assertTrue(replayed["ok"], replayed)
                self.assertEqual(
                    replayed["processed"][0]["status"],
                    "succeeded",
                )
                conn = connect_existing(root)
                try:
                    final_row = conn.execute(
                        """
                        SELECT status, attempt_count FROM queue_jobs
                        WHERE id = ?
                        """,
                        (job_id,),
                    ).fetchone()
                    final_phase_count = int(
                        conn.execute(
                            """
                            SELECT count(*) FROM audit_events
                            WHERE action = ? AND target_id = ?
                            """,
                            (
                                worker_module._WORKER_PHASE_ACTION,
                                job_id,
                            ),
                        ).fetchone()[0]
                    )
                    final_effect_count = int(
                        conn.execute(
                            """
                            SELECT count(*) FROM audit_events
                            WHERE action = ? AND target_id = ?
                            """,
                            (
                                worker_module._WORKER_EFFECT_ACTION,
                                job_id,
                            ),
                        ).fetchone()[0]
                    )
                finally:
                    conn.close()
                self.assertEqual(final_row["status"], "succeeded")
                self.assertEqual(final_row["attempt_count"], 2)
                self.assertEqual(final_phase_count, 1)
                self.assertEqual(final_effect_count, 1)

    def test_failed_recovery_reports_incomplete_when_snapshot_races(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            job_id, _session_id, deferred_result = (
                self._prepare_committed_only_scribe_failure(
                    root,
                    run_count=1,
                    namespace="recovery-snapshot-race",
                )
            )
            self._seed_legacy_failed_worker_effect(
                root,
                job_id=job_id,
                job_type="scroll_event_ingested",
                deferred_result=deferred_result,
            )
            real_candidates = (
                worker_module._all_failed_sidecar_recovery_candidates
            )
            call_count = 0

            def race_after_snapshot(conn, *, limit, job_id=None):
                nonlocal call_count
                call_count += 1
                candidates = real_candidates(
                    conn,
                    limit=limit,
                    job_id=job_id,
                )
                if call_count == 1 and candidates:
                    now = store_module.utc_now()
                    conn.execute(
                        """
                        UPDATE queue_jobs
                        SET status = 'pending', finished_at = NULL,
                            updated_at = ?, error_json = NULL
                        WHERE id = ? AND status = 'failed'
                        """,
                        (now, candidates[0]["id"]),
                    )
                    conn.commit()
                return candidates

            with patch.object(
                worker_module,
                "_all_failed_sidecar_recovery_candidates",
                side_effect=race_after_snapshot,
            ):
                recovery = (
                    worker_module
                    ._recover_failed_post_phase_sidecar_jobs(root)
                )
            self.assertEqual(recovery["selected"], 1, recovery)
            self.assertEqual(recovery["requeued"], 0, recovery)
            self.assertEqual(recovery["rejected"], 0, recovery)
            self.assertEqual(recovery["changed_during_scan"], 1, recovery)
            self.assertTrue(recovery["has_more"], recovery)
            self.assertFalse(recovery["complete"], recovery)

    def test_failed_sidecar_recovery_preserves_explicit_business_failure(
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
                    card_type="decision",
                    title="Do not revive mixed business failure",
                    summary="A sidecar symptom cannot erase an explicit failure.",
                    source_refs=[],
                )
                conn.execute("DELETE FROM queue_jobs")
                job_id = enqueue_job(
                    conn,
                    role="librarian",
                    job_type="review_card_placement",
                    priority=1,
                    payload={"card_id": card_id},
                    related_card_ids=[card_id],
                    dedupe_key=f"business-failure:{card_id}",
                )
                core_result = {
                    "ok": True,
                    "card_id": card_id,
                    "shelf": "business-control",
                    "term_edges": 0,
                }
                store_module.audit_event(
                    conn,
                    action=worker_module._WORKER_PHASE_ACTION,
                    target_type="queue_job",
                    target_id=job_id,
                    payload={
                        "schema": worker_module._WORKER_PHASE_SCHEMA,
                        "job_type": "review_card_placement",
                        "phase": "core",
                        "result": {"core_result": core_result},
                    },
                )
                failed_result = {
                    **core_result,
                    "ok": False,
                    "reason": "explicit_business_failure",
                    "sidecars": {
                        "ok": False,
                        "synced": 0,
                        "failed": 1,
                    },
                    "conflicts": {
                        "ok": True,
                        "sidecars": {
                            "ok": True,
                            "synced": 0,
                            "failed": 0,
                        },
                    },
                }
                effect_event_id = store_module.audit_event(
                    conn,
                    action=worker_module._WORKER_EFFECT_ACTION,
                    target_type="queue_job",
                    target_id=job_id,
                    payload={
                        "schema": worker_module._WORKER_EFFECT_SCHEMA,
                        "job_type": "review_card_placement",
                        "post_phase_complete": True,
                        "result": failed_result,
                    },
                )
                now = store_module.utc_now()
                conn.execute(
                    """
                    UPDATE queue_jobs
                    SET status = 'failed', finished_at = ?, updated_at = ?,
                        error_json = ?
                    WHERE id = ?
                    """,
                    (
                        now,
                        now,
                        store_module.json_dumps(
                            {
                                "error": "explicit_business_failure",
                                "result": failed_result,
                            }
                        ),
                        job_id,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            recovery = worker_module._recover_failed_post_phase_sidecar_jobs(
                root
            )

            self.assertTrue(recovery["ok"], recovery)
            self.assertEqual(recovery["selected"], 1)
            self.assertEqual(recovery["requeued"], 0)
            self.assertEqual(recovery["rejected"], 1)
            self.assertEqual(
                recovery["dispositions"][0]["reason"],
                "not_exclusive_sidecar_failure",
            )
            conn = connect_existing(root)
            try:
                row = conn.execute(
                    "SELECT status, error_json FROM queue_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()
                preserved_effect = conn.execute(
                    "SELECT 1 FROM audit_events WHERE id = ?",
                    (effect_event_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(row["status"], "failed")
            self.assertEqual(
                json.loads(row["error_json"])["result"],
                failed_result,
            )
            self.assertIsNotNone(preserved_effect)
            repeated = worker_module._recover_failed_post_phase_sidecar_jobs(
                root
            )
            self.assertEqual(repeated["selected"], 0, repeated)
            self.assertEqual(repeated["requeued"], 0, repeated)

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

                    def controlled_failure_result(sync_root, card_ids):
                        evidence_conn = connect_existing(sync_root)
                        try:
                            rows = []
                            for evidence_card_id in card_ids:
                                evidence_row = evidence_conn.execute(
                                    """
                                    SELECT card.location_uri,
                                           outbox.generation AS sidecar_generation
                                    FROM cards AS card
                                    LEFT JOIN card_sidecar_outbox AS outbox
                                      ON outbox.card_id = card.id
                                    WHERE card.id = ?
                                    """,
                                    (evidence_card_id,),
                                ).fetchone()
                                self.assertIsNotNone(evidence_row)
                                rows.append(
                                    {
                                        "card_id": evidence_card_id,
                                        "location_uri": evidence_row["location_uri"],
                                        "sidecar_generation": evidence_row[
                                            "sidecar_generation"
                                        ],
                                    }
                                )
                        finally:
                            evidence_conn.close()
                        return {
                            "ok": False,
                            "synced": 0,
                            "deferred": 1,
                            "failed": 1,
                            "failures": [],
                            "compensation_cas_complete": True,
                            "compensation_cas_rows": rows,
                        }

                    def sync_with_first_failure(*args, **kwargs):
                        nonlocal sync_calls
                        sync_calls += 1
                        if failure_mode == "rollback_sync_failure" and sync_calls <= 2:
                            return controlled_failure_result(*args, **kwargs)
                        if sync_calls == 1:
                            if failure_mode == "sidecar_sync_exception":
                                raise RuntimeError("simulated sidecar sync exception")
                            return controlled_failure_result(*args, **kwargs)
                        return real_sync(*args, **kwargs)

                    failure_patch = patch.object(
                        worker_module,
                        "sync_card_sidecars_after_commit",
                        side_effect=sync_with_first_failure,
                    )

                expected_message = (
                    "restored, but rollback verification did not complete"
                    if failure_mode == "rollback_sync_failure"
                    else "sidecar compensation evidence was unavailable"
                    if failure_mode == "sidecar_sync_exception"
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
                if failure_mode == "sidecar_sync_exception":
                    self.assertEqual(restored["status"], "pruned")
                    self.assertNotEqual(restored, original)
                    self.assertFalse(semantic_integrity_report(root)["ok"])
                else:
                    self.assertEqual(restored, original)
                    self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_sidecar_sync_builds_one_immutable_index_per_bounded_phase(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_ids = [
                    create_card(
                        conn,
                        root=root,
                        card_type="note",
                        title=f"bounded-index-{index}",
                        summary="A multi-Card sync must not rescan the artifact ledger per Card.",
                        source_refs=[],
                    )
                    for index in range(8)
                ]
                for index in range(64):
                    store_module.record_artifact(
                        conn,
                        kind="proof_input",
                        uri=f"continuum://proofs/unrelated-{index}.bin",
                        sha256="0" * 64,
                        size_bytes=0,
                        source_type="bounded_index_regression",
                        trust_level="local_generated",
                        immutable=True,
                    )
                conn.commit()
            finally:
                conn.close()

            real_index = store_module._immutable_artifact_path_index
            real_card_index = store_module._card_intent_batch_index
            with patch.object(
                store_module,
                "_immutable_artifact_path_index",
                wraps=real_index,
            ) as index_builder, patch.object(
                store_module,
                "_card_intent_batch_index",
                wraps=real_card_index,
            ) as card_index_builder:
                result = sync_card_sidecars_after_commit(root, card_ids)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["synced"], len(card_ids))
            self.assertEqual(
                index_builder.call_count,
                2,
                "one ledger scan is allowed for the sync batch and one for its intent batch",
            )
            self.assertEqual(
                card_index_builder.call_count,
                1,
                "all intent resolutions must share one Card-location/outbox index",
            )

    def test_sidecar_write_intent_adopts_crash_completed_copy_on_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="crash-complete-sidecar",
                    summary="The frozen default is the first durable state.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            first_sync = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(first_sync["ok"], first_sync)

            conn = connect(root)
            try:
                default_uri = str(
                    conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()["location_uri"]
                )
                default_path = resolve_stored_uri(root, default_uri)
                default_bytes = default_path.read_bytes()
                store_module.record_artifact(
                    conn,
                    kind="proof_input",
                    uri=default_uri,
                    sha256=hashlib.sha256(default_bytes).hexdigest(),
                    size_bytes=len(default_bytes),
                    source_type="crash_complete_default",
                    trust_level="local_generated",
                    immutable=True,
                )
                conn.execute(
                    "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                    (
                        "The copy-on-write state survives a process death before catalog commit.",
                        store_module.utc_now(),
                        card_id,
                    ),
                )
                store_module.mark_card_sidecar_outbox(
                    conn,
                    [card_id],
                    reason="crash_complete_copy_on_write",
                )
                conn.commit()
            finally:
                conn.close()

            conn = connect(root)
            observation: dict[str, object] = {}
            try:
                conn.execute("BEGIN IMMEDIATE")
                artifact_index = store_module._immutable_artifact_path_index(root, conn)
                live_uri = store_module.sync_card_sidecar(
                    root,
                    conn,
                    card_id,
                    artifact_index=artifact_index,
                    write_observation=observation,
                )
                self.assertIsNotNone(live_uri)
                self.assertTrue(observation.get("write_completed"))
                conn.rollback()
            finally:
                conn.close()

            live_path = resolve_stored_uri(root, str(observation["target_uri"]))
            intent_paths = list((root / "run" / "card_sidecar_write_intents").glob("*.json"))
            self.assertEqual(len(intent_paths), 1)
            self.assertTrue(live_path.is_file())
            pending = store_module.reconcile_card_sidecar_write_intents(root)
            self.assertTrue(pending["ok"], pending)
            self.assertEqual(pending["pending"], 1)
            self.assertEqual(pending["results"][0]["status"], "pending_retry")

            adopted = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(adopted["ok"], adopted)
            self.assertTrue(
                any(
                    result.get("ok") and result.get("status") == "adopted"
                    for result in adopted["intent_reconciliation_results"]
                ),
                adopted,
            )
            self.assertFalse(
                list((root / "run" / "card_sidecar_write_intents").glob("*.json"))
            )
            receipts = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (root / "exports" / "card_sidecar_recovery_receipts").glob("*.json")
            ]
            self.assertTrue(
                any(receipt.get("status") == "adopted" for receipt in receipts),
                receipts,
            )
            self.assertEqual(default_path.read_bytes(), default_bytes)
            self.assertEqual(audit(root)["orphan_card_sidecars"], 0)
            self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_direct_copy_on_write_requires_durable_observation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="durable-observation-required",
                    summary="The default state is frozen before direct copy-on-write.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])

            conn = connect(root)
            try:
                default_uri = str(
                    conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()["location_uri"]
                )
                default_path = resolve_stored_uri(root, default_uri)
                default_bytes = default_path.read_bytes()
                store_module.record_artifact(
                    conn,
                    kind="proof_input",
                    uri=default_uri,
                    sha256=hashlib.sha256(default_bytes).hexdigest(),
                    size_bytes=len(default_bytes),
                    source_type="durable_observation_default",
                    trust_level="local_generated",
                    immutable=True,
                )
                conn.execute(
                    "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                    (
                        "A new copy-on-write target needs a durable intent.",
                        store_module.utc_now(),
                        card_id,
                    ),
                )
                store_module.mark_card_sidecar_outbox(
                    conn,
                    [card_id],
                    reason="durable_observation_required",
                )
                conn.commit()
                conn.execute("BEGIN IMMEDIATE")
                with self.assertRaisesRegex(RuntimeError, "durable write observation"):
                    store_module.sync_card_sidecar(root, conn, card_id)
                conn.rollback()
            finally:
                conn.close()

            self.assertFalse((default_path.parent / f"{card_id}.live.yaml").exists())
            self.assertFalse(
                list((root / "run" / "card_sidecar_write_intents").glob("*.json"))
            )
            wrapped = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(wrapped["ok"], wrapped)
            self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_sync_failure_requeues_when_intent_receipt_cannot_finalize(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="receipt-finalization-retry",
                    summary="The initial state becomes immutable.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])

            receipt_dir = root / "exports" / "card_sidecar_recovery_receipts"
            for receipt_path in receipt_dir.glob("*"):
                receipt_path.unlink()
            receipt_dir.rmdir()
            receipt_dir.write_text("blocked", encoding="utf-8")

            conn = connect(root)
            try:
                default_uri = str(
                    conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()["location_uri"]
                )
                default_path = resolve_stored_uri(root, default_uri)
                default_bytes = default_path.read_bytes()
                store_module.record_artifact(
                    conn,
                    kind="proof_input",
                    uri=default_uri,
                    sha256=hashlib.sha256(default_bytes).hexdigest(),
                    size_bytes=len(default_bytes),
                    source_type="receipt_retry_default",
                    trust_level="local_generated",
                    immutable=True,
                )
                conn.execute(
                    "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                    (
                        "Receipt finalization is deliberately unavailable.",
                        store_module.utc_now(),
                        card_id,
                    ),
                )
                store_module.mark_card_sidecar_outbox(
                    conn,
                    [card_id],
                    reason="receipt_finalization_retry",
                )
                conn.commit()
            finally:
                conn.close()

            failed = sync_card_sidecars_after_commit(root, [card_id])
            self.assertFalse(failed["ok"], failed)
            self.assertFalse(failed["intent_reconciliation"]["ok"], failed)
            conn = connect_existing(root)
            try:
                self.assertEqual(
                    conn.execute(
                        "SELECT count(*) FROM card_sidecar_outbox WHERE card_id = ?",
                        (card_id,),
                    ).fetchone()[0],
                    1,
                )
            finally:
                conn.close()
            self.assertTrue(
                list((root / "run" / "card_sidecar_write_intents").glob("*.json"))
            )
            self.assertFalse(semantic_integrity_report(root)["ok"])

            receipt_dir.unlink()
            recovered = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(recovered["ok"], recovered)
            self.assertFalse(
                list((root / "run" / "card_sidecar_write_intents").glob("*.json"))
            )
            self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_sidecar_recovery_refuses_non_file_and_existing_destinations(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="recovery-destination-boundary",
                    summary="Recovery must never overwrite or bless an unexpected destination.",
                    source_refs=[],
                )
                row = conn.execute("SELECT * FROM cards WHERE id = ?", (card_id,)).fetchone()
                payload = store_module._card_sidecar_payload_for_row(row)
                conn.commit()
            finally:
                conn.close()

            target_path = store_module.card_sidecar_path(root, card_id)
            self.assertIsNotNone(target_path)
            target_path = Path(target_path)
            target_uri = store_module.continuum_uri(root, target_path)
            expected_state_hash = str(payload["state_hash"])
            intent_id, intent_path = store_module._write_card_sidecar_write_intent(
                root,
                card_id=card_id,
                target_uri=target_uri,
                expected_state_hash=expected_state_hash,
            )
            recovery_path = target_path.with_name(
                f".{target_path.name}.{intent_id}.uncommitted"
            )
            recovery_path.mkdir(parents=True)

            non_file = store_module.reconcile_card_sidecar_write_intents(root)
            self.assertFalse(non_file["ok"], non_file)
            self.assertEqual(non_file["results"][0]["status"], "link_or_non_file_recovery")
            self.assertTrue(intent_path.is_file())
            self.assertTrue(recovery_path.is_dir())

            recovery_path.rmdir()
            recovery_path.write_bytes(b"\xffnot-utf8")
            malformed = store_module.reconcile_card_sidecar_write_intents(root)
            self.assertFalse(malformed["ok"], malformed)
            self.assertEqual(malformed["results"][0]["status"], "invalid_recovery")
            self.assertTrue(intent_path.is_file())
            self.assertEqual(recovery_path.read_bytes(), b"\xffnot-utf8")

            recovery_path.unlink()
            with recovery_path.open("wb") as oversized_handle:
                oversized_handle.truncate(
                    store_module.MAX_VERIFIED_CARD_SIDECAR_BYTES + 1
                )
            oversized = store_module.reconcile_card_sidecar_write_intents(root)
            self.assertFalse(oversized["ok"], oversized)
            self.assertEqual(oversized["results"][0]["status"], "invalid_recovery")
            self.assertTrue(intent_path.is_file())
            self.assertEqual(
                recovery_path.stat().st_size,
                store_module.MAX_VERIFIED_CARD_SIDECAR_BYTES + 1,
            )

            recovery_path.unlink()
            initial_sync = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(initial_sync["ok"], initial_sync)
            live_path = target_path.with_name(f"{card_id}.live.yaml")
            live_uri = store_module.continuum_uri(root, live_path)
            live_intent_id, live_intent_path = store_module._write_card_sidecar_write_intent(
                root,
                card_id=card_id,
                target_uri=live_uri,
                expected_state_hash=expected_state_hash,
            )
            store_module.write_atomic_yaml(live_path, payload)
            live_recovery_path = live_path.with_name(
                f".{live_path.name}.{live_intent_id}.uncommitted"
            )
            live_recovery_path.write_bytes(b"do-not-overwrite")
            existing = store_module.reconcile_card_sidecar_write_intents(root)
            self.assertFalse(existing["ok"], existing)
            self.assertEqual(existing["results"][0]["status"], "recovery_target_exists")
            self.assertEqual(live_recovery_path.read_bytes(), b"do-not-overwrite")
            self.assertTrue(live_path.is_file())
            self.assertTrue(live_intent_path.is_file())

    def test_sidecar_intent_reference_index_detects_hardlink_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                referenced_card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="hardlink-reference-owner",
                    summary="This Card location aliases another inode name.",
                    source_refs=[],
                )
                intent_card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="hardlink-intent-owner",
                    summary="This Card payload is the pending intent target.",
                    source_refs=[],
                )
                intent_row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (intent_card_id,),
                ).fetchone()
                intent_payload = store_module._card_sidecar_payload_for_row(intent_row)
                referenced_path = Path(
                    store_module.card_sidecar_path(root, referenced_card_id)
                )
                intent_path = Path(store_module.card_sidecar_path(root, intent_card_id))
                conn.execute(
                    "UPDATE cards SET location_uri = NULL WHERE id = ?",
                    (intent_card_id,),
                )
                conn.commit()
            finally:
                conn.close()

            store_module.write_atomic_yaml(intent_path, intent_payload)
            try:
                os.link(intent_path, referenced_path)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation unavailable: {exc}")
            intent_id, durable_intent_path = (
                store_module._write_card_sidecar_write_intent(
                    root,
                    card_id=intent_card_id,
                    target_uri=store_module.continuum_uri(root, intent_path),
                    expected_state_hash=str(intent_payload["state_hash"]),
                )
            )

            reconciled = store_module.reconcile_card_sidecar_write_intents(root)

            self.assertFalse(reconciled["ok"], reconciled)
            self.assertEqual(
                reconciled["results"][0]["status"],
                "referenced_target_mismatch",
            )
            self.assertEqual(
                reconciled["results"][0]["referenced_by"],
                [referenced_card_id],
            )
            self.assertEqual(
                durable_intent_path.name,
                f"{intent_id}.json",
            )
            self.assertTrue(durable_intent_path.is_file())
            self.assertTrue(intent_path.samefile(referenced_path))

    @unittest.skipUnless(os.name == "posix", "real sidecar symlinks are POSIX-only")
    def test_sidecar_intent_rechecks_card_reference_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="reference-replacement-boundary",
                    summary="The catalog reference remains the selected generation.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])

            conn = connect_existing(root)
            try:
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                reference_uri = str(row["location_uri"])
                reference_path = resolve_stored_uri(root, reference_uri)
                payload = store_module._card_sidecar_payload_for_row(row)
            finally:
                conn.close()
            reference_bytes = reference_path.read_bytes()
            target_path = reference_path.with_name(
                f"{card_id}.live-{payload['state_hash']}.yaml"
            )
            store_module.write_atomic_yaml(target_path, payload)
            target_bytes = target_path.read_bytes()
            intent_id, intent_path = store_module._write_card_sidecar_write_intent(
                root,
                card_id=card_id,
                target_uri=store_module.continuum_uri(root, target_path),
                expected_state_hash=str(payload["state_hash"]),
            )
            receipt_path = (
                root
                / "exports"
                / "card_sidecar_recovery_receipts"
                / f"{intent_id}.json"
            )
            preserved_reference = Path(tmp) / "preserved-reference.yaml"
            real_identity = store_module._sidecar_nofollow_path_identity
            reference_checks = 0

            def replace_reference_on_recheck(
                path: Path,
                *,
                allow_missing: bool = False,
            ):
                nonlocal reference_checks
                if path == reference_path:
                    reference_checks += 1
                    if reference_checks == 2:
                        reference_path.replace(preserved_reference)
                        reference_path.symlink_to(target_path)
                return real_identity(path, allow_missing=allow_missing)

            with patch.object(
                store_module,
                "_sidecar_nofollow_path_identity",
                side_effect=replace_reference_on_recheck,
            ):
                reconciled = store_module.reconcile_card_sidecar_write_intents(root)

            self.assertFalse(reconciled["ok"], reconciled)
            self.assertEqual(
                reconciled["results"][0]["status"],
                "card_reference_unstable",
            )
            self.assertGreaterEqual(reference_checks, 2)
            self.assertTrue(reference_path.is_symlink())
            self.assertEqual(preserved_reference.read_bytes(), reference_bytes)
            self.assertEqual(target_path.read_bytes(), target_bytes)
            self.assertTrue(intent_path.is_file())
            self.assertFalse(receipt_path.exists())
            conn = connect_existing(root)
            try:
                self.assertEqual(
                    conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()["location_uri"],
                    reference_uri,
                )
            finally:
                conn.close()

    @unittest.skipUnless(os.name == "posix", "real sidecar symlinks are POSIX-only")
    def test_immutable_index_rechecks_source_entry_before_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="immutable-index-replacement-boundary",
                    summary="The initial default generation is mutable.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])

            conn = connect(root)
            try:
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                original_uri = str(row["location_uri"])
                default_path = resolve_stored_uri(root, original_uri)
                original_bytes = default_path.read_bytes()
                artifact_alias = root / "archive" / "immutable-sidecar-alias.yaml"
                artifact_alias.parent.mkdir(parents=True, exist_ok=True)
                try:
                    os.link(default_path, artifact_alias)
                except (NotImplementedError, OSError) as exc:
                    self.skipTest(f"hardlink creation unavailable: {exc}")
                store_module.record_artifact(
                    conn,
                    kind="sidecar_proof",
                    uri=store_module.continuum_uri(root, artifact_alias),
                    sha256=hashlib.sha256(original_bytes).hexdigest(),
                    size_bytes=len(original_bytes),
                    immutable=True,
                    source_type="immutable_index_replacement_boundary",
                    trust_level="local_evidence",
                )
                conn.execute(
                    "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                    (
                        "A changed artifact entry must not freeze this mutable default.",
                        store_module.utc_now(),
                        card_id,
                    ),
                )
                store_module.mark_card_sidecar_outbox(
                    conn,
                    [card_id],
                    reason="immutable_index_source_replaced",
                )
                conn.commit()
            finally:
                conn.close()

            preserved_alias = Path(tmp) / "preserved-immutable-alias.yaml"
            real_identity = store_module._sidecar_nofollow_path_identity
            alias_checks = 0

            def replace_alias_on_recheck(
                path: Path,
                *,
                allow_missing: bool = False,
            ):
                nonlocal alias_checks
                if path == artifact_alias:
                    alias_checks += 1
                    if alias_checks == 2:
                        artifact_alias.replace(preserved_alias)
                        artifact_alias.symlink_to(default_path)
                return real_identity(path, allow_missing=allow_missing)

            with patch.object(
                store_module,
                "_sidecar_nofollow_path_identity",
                side_effect=replace_alias_on_recheck,
            ):
                updated = sync_card_sidecars_after_commit(root, [card_id])

            self.assertTrue(updated["ok"], updated)
            self.assertGreaterEqual(alias_checks, 2)
            self.assertTrue(artifact_alias.is_symlink())
            self.assertEqual(preserved_alias.read_bytes(), original_bytes)
            self.assertNotEqual(default_path.read_bytes(), original_bytes)
            self.assertFalse(
                (default_path.parent / f"{card_id}.live.yaml").exists()
            )
            conn = connect_existing(root)
            try:
                self.assertEqual(
                    conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()["location_uri"],
                    original_uri,
                )
            finally:
                conn.close()

    @unittest.skipUnless(os.name == "posix", "real sidecar symlinks are POSIX-only")
    def test_immutable_verifier_rechecks_candidate_and_artifact_entries(self) -> None:
        for boundary in ("candidate", "artifact"):
            for phase in ("before_read", "after_hash"):
                with self.subTest(
                    boundary=boundary,
                    phase=phase,
                ), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp) / "continuum"
                    init_db(root)
                    conn = connect(root)
                    try:
                        card_id = create_card(
                            conn,
                            root=root,
                            card_type="note",
                            title=f"immutable-verifier-{boundary}-{phase}-boundary",
                            summary=(
                                "Only stable regular entries may become immutable evidence."
                            ),
                            source_refs=[],
                        )
                        conn.commit()
                    finally:
                        conn.close()
                    self.assertTrue(
                        sync_card_sidecars_after_commit(root, [card_id])["ok"]
                    )

                    conn = connect(root)
                    try:
                        row = conn.execute(
                            "SELECT * FROM cards WHERE id = ?",
                            (card_id,),
                        ).fetchone()
                        candidate_path = resolve_stored_uri(
                            root,
                            str(row["location_uri"]),
                        )
                        candidate_bytes = candidate_path.read_bytes()
                        artifact_alias = (
                            root / "archive" / f"{boundary}-{phase}-alias.yaml"
                        )
                        artifact_alias.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            os.link(candidate_path, artifact_alias)
                        except (NotImplementedError, OSError) as exc:
                            self.skipTest(f"hardlink creation unavailable: {exc}")
                        store_module.record_artifact(
                            conn,
                            kind="sidecar_proof",
                            uri=store_module.continuum_uri(root, artifact_alias),
                            sha256=hashlib.sha256(candidate_bytes).hexdigest(),
                            size_bytes=len(candidate_bytes),
                            immutable=True,
                            source_type=(
                                f"immutable_verifier_{boundary}_{phase}_replacement"
                            ),
                            trust_level="local_evidence",
                        )
                        conn.commit()

                        replaced_path = (
                            candidate_path
                            if boundary == "candidate"
                            else artifact_alias
                        )
                        link_target = (
                            artifact_alias
                            if boundary == "candidate"
                            else candidate_path
                        )
                        preserved_path = (
                            Path(tmp) / f"preserved-{boundary}-{phase}.yaml"
                        )
                        real_identity = store_module._sidecar_nofollow_path_identity
                        real_hash = store_module.file_sha256
                        entry_checks = 0
                        hash_completed = False

                        def replace_entry() -> None:
                            if not replaced_path.is_symlink():
                                replaced_path.replace(preserved_path)
                                replaced_path.symlink_to(link_target)

                        def replace_entry_on_recheck(
                            path: Path,
                            *,
                            allow_missing: bool = False,
                        ):
                            nonlocal entry_checks
                            if path == replaced_path:
                                entry_checks += 1
                                if entry_checks == 2:
                                    replace_entry()
                            return real_identity(path, allow_missing=allow_missing)

                        def replace_entry_after_hash(path: Path) -> str:
                            nonlocal hash_completed
                            digest = real_hash(path)
                            replace_entry()
                            hash_completed = True
                            return digest

                        if phase == "before_read":
                            with patch.object(
                                store_module,
                                "_sidecar_nofollow_path_identity",
                                side_effect=replace_entry_on_recheck,
                            ):
                                verified, uncertain = (
                                    store_module._verified_immutable_card_sidecars(
                                        root,
                                        conn,
                                        candidate_path.parent,
                                    )
                                )
                        else:
                            with patch.object(
                                store_module,
                                "file_sha256",
                                side_effect=replace_entry_after_hash,
                            ):
                                verified, uncertain = (
                                    store_module._verified_immutable_card_sidecars(
                                        root,
                                        conn,
                                        candidate_path.parent,
                                    )
                                )
                    finally:
                        conn.close()

                    if phase == "before_read":
                        self.assertGreaterEqual(entry_checks, 2)
                    else:
                        self.assertTrue(hash_completed)
                    self.assertNotIn(card_id, verified)
                    self.assertIn(card_id, uncertain)
                    self.assertTrue(replaced_path.is_symlink())
                    self.assertEqual(preserved_path.read_bytes(), candidate_bytes)

    @unittest.skipUnless(os.name == "posix", "real sidecar symlinks are POSIX-only")
    def test_orphan_audit_rechecks_entry_before_classification(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="orphan-audit-replacement-boundary",
                    summary="The expected Card remains stable during orphan review.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])
            conn = connect_existing(root)
            try:
                current_path = resolve_stored_uri(
                    root,
                    str(
                        conn.execute(
                            "SELECT location_uri FROM cards WHERE id = ?",
                            (card_id,),
                        ).fetchone()["location_uri"]
                    ),
                )
            finally:
                conn.close()
            orphan_path = current_path.parent / "card_orphan.yaml"
            orphan_bytes = b"schema: intentionally-orphaned\n"
            orphan_path.write_bytes(orphan_bytes)
            preserved_orphan = Path(tmp) / "preserved-orphan.yaml"
            real_identity = store_module._sidecar_nofollow_path_identity
            orphan_checks = 0

            def replace_orphan_on_recheck(
                path: Path,
                *,
                allow_missing: bool = False,
            ):
                nonlocal orphan_checks
                if path == orphan_path:
                    orphan_checks += 1
                    if orphan_checks == 2:
                        orphan_path.replace(preserved_orphan)
                        orphan_path.symlink_to(current_path)
                return real_identity(path, allow_missing=allow_missing)

            conn = connect_existing(root)
            try:
                with patch.object(
                    store_module,
                    "_sidecar_nofollow_path_identity",
                    side_effect=replace_orphan_on_recheck,
                ):
                    state = store_module.audit_card_sidecars(root, conn)
            finally:
                conn.close()

            self.assertGreaterEqual(orphan_checks, 2)
            self.assertEqual(state["unsafe_card_sidecar_paths"], 1, state)
            self.assertEqual(state["orphan_card_sidecars"], 0, state)
            self.assertTrue(orphan_path.is_symlink())
            self.assertEqual(preserved_orphan.read_bytes(), orphan_bytes)

    @unittest.skipUnless(os.name == "posix", "real sidecar symlinks are POSIX-only")
    def test_history_receipt_binding_rechecks_current_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="history-receipt-replacement-boundary",
                    summary="The mutable default becomes the first generation.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])

            def current() -> tuple[str, Path]:
                current_conn = connect_existing(root)
                try:
                    uri = str(
                        current_conn.execute(
                            "SELECT location_uri FROM cards WHERE id = ?",
                            (card_id,),
                        ).fetchone()["location_uri"]
                    )
                finally:
                    current_conn.close()
                return uri, resolve_stored_uri(root, uri)

            def freeze_current(source_type: str) -> None:
                uri, path = current()
                artifact_conn = connect(root)
                try:
                    store_module.record_artifact(
                        artifact_conn,
                        kind="sidecar_proof",
                        uri=uri,
                        sha256=store_module.file_sha256(path),
                        size_bytes=path.stat().st_size,
                        immutable=True,
                        source_type=source_type,
                        trust_level="local_evidence",
                    )
                    artifact_conn.commit()
                finally:
                    artifact_conn.close()

            def advance(summary: str, reason: str) -> tuple[str, Path]:
                update_conn = connect(root)
                try:
                    update_conn.execute(
                        "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                        (summary, store_module.utc_now(), card_id),
                    )
                    store_module.mark_card_sidecar_outbox(
                        update_conn,
                        [card_id],
                        reason=reason,
                    )
                    update_conn.commit()
                finally:
                    update_conn.close()
                result = sync_card_sidecars_after_commit(root, [card_id])
                self.assertTrue(result["ok"], result)
                return current()

            freeze_current("history_receipt_default")
            _live_uri, live_path = advance(
                "The stable live generation becomes current.",
                "history_receipt_live",
            )
            self.assertEqual(live_path.name, f"{card_id}.live.yaml")
            freeze_current("history_receipt_live")
            current_uri, current_path = advance(
                "The content-addressed generation becomes current.",
                "history_receipt_hash",
            )
            self.assertIn(".live-", current_path.name)
            current_bytes = current_path.read_bytes()

            update_conn = connect(root)
            try:
                update_conn.execute(
                    "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                    (
                        "The next state must not inherit a replaced history entry.",
                        store_module.utc_now(),
                        card_id,
                    ),
                )
                store_module.mark_card_sidecar_outbox(
                    update_conn,
                    [card_id],
                    reason="history_receipt_entry_replaced",
                )
                update_conn.commit()
            finally:
                update_conn.close()

            receipt_dir = root / "exports" / "card_sidecar_recovery_receipts"
            intent_dir = root / "run" / "card_sidecar_write_intents"
            cards_dir = current_path.parent
            receipts_before = {path.name for path in receipt_dir.glob("*.json")}
            intents_before = {path.name for path in intent_dir.glob("*.json")}
            sidecars_before = {path.name for path in cards_dir.glob("*.yaml")}
            preserved_current = Path(tmp) / "preserved-current-generation.yaml"
            real_binder = store_module._history_receipt_binds_card_sidecar
            real_identity = store_module._sidecar_nofollow_path_identity
            replaced = False
            binder_identity_checks = 0

            receipt_index = store_module._validated_card_sidecar_history_receipt_index(
                root
            )
            current_payload = load_atomic_yaml(
                current_path.read_text(encoding="utf-8")
            )
            self.assertTrue(
                real_binder(
                    current_path,
                    card_id=card_id,
                    state_hash=str(current_payload["state_hash"]),
                    receipt_index=receipt_index,
                )
            )

            def replace_before_binding(path: Path, **kwargs):
                def replace_on_binder_recheck(
                    candidate: Path,
                    *,
                    allow_missing: bool = False,
                ):
                    nonlocal replaced, binder_identity_checks
                    if candidate == current_path:
                        binder_identity_checks += 1
                        if binder_identity_checks == 2:
                            current_path.replace(preserved_current)
                            current_path.symlink_to(preserved_current)
                            replaced = True
                    return real_identity(candidate, allow_missing=allow_missing)

                with patch.object(
                    store_module,
                    "_sidecar_nofollow_path_identity",
                    side_effect=replace_on_binder_recheck,
                ):
                    return real_binder(path, **kwargs)

            with patch.object(
                store_module,
                "_history_receipt_binds_card_sidecar",
                side_effect=replace_before_binding,
            ):
                failed = sync_card_sidecars_after_commit(root, [card_id])

            self.assertTrue(replaced)
            self.assertGreaterEqual(binder_identity_checks, 2)
            self.assertFalse(failed["ok"], failed)
            self.assertTrue(
                any(
                    "changed during receipt binding"
                    in str(failure.get("error") or "")
                    for failure in failed["failures"]
                ),
                failed,
            )
            self.assertTrue(current_path.is_symlink())
            self.assertEqual(preserved_current.read_bytes(), current_bytes)
            self.assertEqual(
                {path.name for path in receipt_dir.glob("*.json")},
                receipts_before,
            )
            self.assertEqual(
                {path.name for path in intent_dir.glob("*.json")},
                intents_before,
            )
            self.assertEqual(
                {path.name for path in cards_dir.glob("*.yaml")},
                sidecars_before,
            )
            conn = connect_existing(root)
            try:
                self.assertEqual(
                    conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()["location_uri"],
                    current_uri,
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT count(*) FROM card_sidecar_outbox WHERE card_id = ?",
                        (card_id,),
                    ).fetchone()[0],
                    1,
                )
            finally:
                conn.close()

    def test_compensation_intent_terminalizes_when_rollback_never_committed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="rollback-not-committed",
                    summary="The referenced candidate remains the committed state.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])
            conn = connect_existing(root)
            try:
                row = conn.execute("SELECT * FROM cards WHERE id = ?", (card_id,)).fetchone()
                target_uri = str(row["location_uri"])
                payload = store_module._card_sidecar_payload_for_row(row)
            finally:
                conn.close()
            target_path = resolve_stored_uri(root, target_uri)
            target_bytes = target_path.read_bytes()
            store_module.register_card_sidecar_compensation_intents(
                root,
                [
                    {
                        "card_id": card_id,
                        "uri": target_uri,
                        "state_hash": payload["state_hash"],
                    }
                ],
            )

            reconciled = store_module.reconcile_card_sidecar_write_intents(root)
            self.assertTrue(reconciled["ok"], reconciled)
            self.assertEqual(reconciled["pending"], 0)
            self.assertEqual(reconciled["results"][0]["status"], "rollback_not_committed")
            self.assertEqual(target_path.read_bytes(), target_bytes)
            self.assertFalse(
                list((root / "run" / "card_sidecar_write_intents").glob("*.json"))
            )
            self.assertTrue(semantic_integrity_report(root)["ok"])

    @unittest.skipUnless(os.name == "posix", "real state-directory symlinks are POSIX-only")
    def test_sidecar_intent_and_receipt_paths_reject_redirects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            card_id = "card_redirect_regression"
            target_path = root / "catalog" / "cards" / f"{card_id}.yaml"
            target_uri = store_module.continuum_uri(root, target_path)
            expected_state_hash = "a" * 64
            intent_dir = root / "run" / "card_sidecar_write_intents"
            external_intents = Path(tmp) / "external-intents"
            external_intents.mkdir()
            intent_dir.symlink_to(external_intents, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "link-like"):
                store_module._write_card_sidecar_write_intent(
                    root,
                    card_id=card_id,
                    target_uri=target_uri,
                    expected_state_hash=expected_state_hash,
                )
            self.assertFalse(list(external_intents.iterdir()))
            intent_dir.unlink()

            prior_umask = os.umask(0o022)
            try:
                _intent_id, intent_path = store_module._write_card_sidecar_write_intent(
                    root,
                    card_id=card_id,
                    target_uri=target_uri,
                    expected_state_hash=expected_state_hash,
                )
            finally:
                os.umask(prior_umask)
            self.assertEqual(intent_dir.stat().st_mode & 0o077, 0)

            receipt_dir = root / "exports" / "card_sidecar_recovery_receipts"
            external_receipts = Path(tmp) / "external-receipts"
            external_receipts.mkdir()
            receipt_dir.symlink_to(external_receipts, target_is_directory=True)
            redirected_receipt = store_module.reconcile_card_sidecar_write_intents(root)
            self.assertFalse(redirected_receipt["ok"], redirected_receipt)
            self.assertTrue(intent_path.is_file())
            self.assertFalse(list(external_receipts.iterdir()))
            receipt_dir.unlink()

            external_intent_file = external_intents / intent_path.name
            intent_path.replace(external_intent_file)
            external_bytes = external_intent_file.read_bytes()
            intent_path.symlink_to(external_intent_file)
            redirected_entry = store_module.reconcile_card_sidecar_write_intents(root)
            self.assertFalse(redirected_entry["ok"], redirected_entry)
            self.assertEqual(external_intent_file.read_bytes(), external_bytes)
            integrity = semantic_integrity_report(root)
            self.assertFalse(integrity["ok"], integrity)
            self.assertGreater(
                integrity["checks"]["unsafe_card_sidecar_write_intent_paths"],
                0,
            )

    def test_forged_card_sidecar_recovery_receipt_is_not_authority(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="forged-recovery-receipt",
                    summary="Only a bound recovery receipt may legitimize quarantine bytes.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])
            conn = connect_existing(root)
            try:
                row = conn.execute("SELECT * FROM cards WHERE id = ?", (card_id,)).fetchone()
                target_uri = str(row["location_uri"])
                payload = store_module._card_sidecar_payload_for_row(row)
            finally:
                conn.close()
            target_path = resolve_stored_uri(root, target_uri)
            forged_intent_id = "forged_receipt_authority"
            recovery_path = target_path.with_name(
                f".{target_path.name}.{forged_intent_id}.uncommitted"
            )
            recovery_path.write_bytes(target_path.read_bytes())
            receipt = {
                "ok": True,
                "schema": store_module.CARD_SIDECAR_RECOVERY_RECEIPT_SCHEMA,
                "intent_id": forged_intent_id,
                "card_id": card_id,
                "target_uri": target_uri,
                "expected_state_hash": payload["state_hash"],
                "mode": "write",
                "status": "quarantined",
                "resolved_at": store_module.utc_now(),
                "recovery_uri": store_module.continuum_uri(root, recovery_path),
                "recovery_sha256": hashlib.sha256(recovery_path.read_bytes()).hexdigest(),
                "recovery_size_bytes": recovery_path.stat().st_size,
            }
            receipt_path = (
                root
                / "exports"
                / "card_sidecar_recovery_receipts"
                / f"{forged_intent_id}.json"
            )
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

            integrity = semantic_integrity_report(root)
            self.assertFalse(integrity["ok"], integrity)
            self.assertGreater(
                integrity["checks"]["malformed_card_sidecar_recovery_receipts"],
                0,
            )

    def test_superseded_recovery_receipt_requires_write_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="superseded-receipt-mode",
                    summary="Superseded recovery receipts are valid only for writes.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])
            conn = connect_existing(root)
            try:
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                target_uri = str(row["location_uri"])
                state_hash = str(
                    store_module._card_sidecar_payload_for_row(row)["state_hash"]
                )
            finally:
                conn.close()

            mode = "compensation_cleanup"
            attempt_id = store_module.unique_id("card_sidecar_attempt")
            intent_id = store_module.stable_id(
                "card_sidecar_write_intent",
                mode,
                card_id,
                target_uri,
                state_hash,
                attempt_id,
            )
            receipt = {
                "ok": True,
                "schema": store_module.CARD_SIDECAR_RECOVERY_RECEIPT_SCHEMA,
                "intent_id": intent_id,
                "card_id": card_id,
                "target_uri": target_uri,
                "expected_state_hash": state_hash,
                "mode": mode,
                "attempt_id": attempt_id,
                "status": "superseded_by_newer_state",
                "resolved_at": store_module.utc_now(),
                "recovery_uri": None,
                "recovery_sha256": None,
                "recovery_size_bytes": None,
            }
            receipt_path = (
                root
                / "exports"
                / "card_sidecar_recovery_receipts"
                / f"{intent_id}.json"
            )
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

            integrity = semantic_integrity_report(root)
            self.assertFalse(integrity["ok"], integrity)
            self.assertGreater(
                integrity["checks"]["malformed_card_sidecar_recovery_receipts"],
                0,
            )

    def test_reused_sidecar_intent_coordinates_keep_prior_recovery_receipted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="reused-intent-coordinates",
                    summary="Each physical write attempt has a distinct durable identity.",
                    source_refs=[],
                )
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                payload = store_module._card_sidecar_payload_for_row(row)
                conn.execute(
                    "UPDATE cards SET location_uri = NULL WHERE id = ?",
                    (card_id,),
                )
                conn.execute(
                    "DELETE FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                )
                conn.commit()
            finally:
                conn.close()

            target_path = root / "catalog" / "cards" / f"{card_id}.live.yaml"
            target_uri = store_module.continuum_uri(root, target_path)
            state_hash = str(payload["state_hash"])
            first_id, _first_path = store_module._write_card_sidecar_write_intent(
                root,
                card_id=card_id,
                target_uri=target_uri,
                expected_state_hash=state_hash,
            )
            store_module.write_atomic_yaml(target_path, payload)
            first = store_module.reconcile_card_sidecar_write_intents(root)
            self.assertTrue(first["ok"], first)
            self.assertEqual(first["results"][0]["status"], "quarantined")
            first_recovery = target_path.with_name(
                f".{target_path.name}.{first_id}.uncommitted"
            )
            self.assertTrue(first_recovery.is_file())

            second_id, _second_path = store_module._write_card_sidecar_write_intent(
                root,
                card_id=card_id,
                target_uri=target_uri,
                expected_state_hash=state_hash,
            )
            self.assertNotEqual(first_id, second_id)
            store_module.write_atomic_yaml(target_path, payload)
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET location_uri = ? WHERE id = ?",
                    (target_uri, card_id),
                )
                conn.commit()
            finally:
                conn.close()
            second = store_module.reconcile_card_sidecar_write_intents(root)
            self.assertTrue(second["ok"], second)
            self.assertEqual(second["results"][0]["status"], "adopted")

            receipts = {
                path.stem: json.loads(path.read_text(encoding="utf-8"))
                for path in (
                    root / "exports" / "card_sidecar_recovery_receipts"
                ).glob("*.json")
            }
            self.assertEqual(receipts[first_id]["status"], "quarantined")
            self.assertEqual(receipts[second_id]["status"], "adopted")
            self.assertTrue(first_recovery.is_file())
            integrity = semantic_integrity_report(root)
            self.assertTrue(integrity["ok"], integrity)

    def test_hardlink_alias_artifact_preserves_and_audits_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="hardlink-artifact-sidecar",
                    summary="A differently named hardlink still binds immutable bytes.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            initial = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(initial["ok"], initial)
            original_path = root / "catalog" / "cards" / f"{card_id}.yaml"
            alias_path = root / "proofs" / "sidecar-proof.bin"
            alias_path.parent.mkdir(parents=True)
            try:
                os.link(original_path, alias_path)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"hardlink creation unavailable: {exc}")

            conn = connect(root)
            try:
                store_module.record_artifact(
                    conn,
                    kind="sidecar_proof",
                    uri=store_module.continuum_uri(root, alias_path),
                    sha256=store_module.file_sha256(alias_path),
                    size_bytes=alias_path.stat().st_size,
                    immutable=True,
                    source_type="local_generated",
                    trust_level="local_evidence",
                )
                conn.execute(
                    "UPDATE cards SET status = ?, updated_at = ? WHERE id = ?",
                    ("archived", store_module.utc_now(), card_id),
                )
                store_module.mark_card_sidecar_outbox(
                    conn,
                    [card_id],
                    reason="hardlink_alias_state_change",
                )
                conn.commit()
            finally:
                conn.close()

            updated = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(updated["ok"], updated)
            conn = connect_existing(root)
            try:
                current_uri = conn.execute(
                    "SELECT location_uri FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()["location_uri"]
            finally:
                conn.close()
            self.assertNotEqual(
                store_module.resolve_stored_uri(root, current_uri),
                original_path,
            )
            self.assertTrue(original_path.samefile(alias_path))
            integrity = semantic_integrity_report(root)
            self.assertTrue(integrity["ok"], integrity)

    def test_hash_named_sidecar_generations_are_content_addressed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="content-addressed-sidecar-generations",
                    summary="The default generation is mutable before freezing.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])

            def freeze_current(source_type: str) -> Path:
                artifact_conn = connect(root)
                try:
                    location_uri = artifact_conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()["location_uri"]
                    path = resolve_stored_uri(root, location_uri)
                    store_module.record_artifact(
                        artifact_conn,
                        kind="sidecar_proof",
                        uri=location_uri,
                        sha256=store_module.file_sha256(path),
                        size_bytes=path.stat().st_size,
                        immutable=True,
                        source_type=source_type,
                        trust_level="local_evidence",
                    )
                    artifact_conn.commit()
                    return path
                finally:
                    artifact_conn.close()

            def update_and_sync(summary: str, reason: str) -> Path:
                update_conn = connect(root)
                try:
                    update_conn.execute(
                        "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                        (summary, store_module.utc_now(), card_id),
                    )
                    store_module.mark_card_sidecar_outbox(
                        update_conn,
                        [card_id],
                        reason=reason,
                    )
                    update_conn.commit()
                finally:
                    update_conn.close()
                sync = sync_card_sidecars_after_commit(root, [card_id])
                self.assertTrue(sync["ok"], sync)
                current_conn = connect_existing(root)
                try:
                    location_uri = current_conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()["location_uri"]
                finally:
                    current_conn.close()
                return resolve_stored_uri(root, location_uri)

            freeze_current("content_addressed_default")
            live_path = update_and_sync(
                "The stable live generation is mutable before freezing.",
                "content_addressed_live",
            )
            self.assertEqual(live_path.name, f"{card_id}.live.yaml")
            freeze_current("content_addressed_live")
            hashed_s2 = update_and_sync(
                "The first hash-named generation is content addressed.",
                "content_addressed_s2",
            )
            payload_s2 = load_atomic_yaml(hashed_s2.read_text(encoding="utf-8"))
            bytes_s2 = hashed_s2.read_bytes()
            self.assertEqual(
                hashed_s2.name,
                f"{card_id}.live-{payload_s2['state_hash']}.yaml",
            )
            hashed_s2_uri = store_module.continuum_uri(root, hashed_s2)
            removed_adopted_receipts = 0
            for receipt_path in (
                root / "exports" / "card_sidecar_recovery_receipts"
            ).glob("*.json"):
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                if (
                    receipt.get("mode") == "write"
                    and receipt.get("status") == "adopted"
                    and receipt.get("target_uri") == hashed_s2_uri
                ):
                    receipt_path.unlink()
                    removed_adopted_receipts += 1
            self.assertEqual(removed_adopted_receipts, 1)
            self.assertTrue(semantic_integrity_report(root)["ok"])

            hashed_s3 = update_and_sync(
                "A later state must select its own hash-named generation.",
                "content_addressed_s3",
            )
            payload_s3 = load_atomic_yaml(hashed_s3.read_text(encoding="utf-8"))

            self.assertNotEqual(hashed_s3, hashed_s2)
            self.assertEqual(hashed_s2.read_bytes(), bytes_s2)
            self.assertEqual(
                hashed_s3.name,
                f"{card_id}.live-{payload_s3['state_hash']}.yaml",
            )
            content_addressed_integrity = semantic_integrity_report(root)
            self.assertTrue(
                content_addressed_integrity["ok"],
                content_addressed_integrity,
            )
            transition_receipts = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (
                    root / "exports" / "card_sidecar_recovery_receipts"
                ).glob("*.json")
            ]
            self.assertTrue(
                any(
                    receipt.get("mode") == "history_transition"
                    and receipt.get("status") == "transition_prepared"
                    and receipt.get("target_uri") == hashed_s2_uri
                    for receipt in transition_receipts
                ),
                transition_receipts,
            )

            snap = store_module.snapshot(
                root,
                reason="multi-generation content-addressed sidecar recovery",
            )
            snapshot_path = Path(str(snap["snapshot_uri"]))
            manifest = store_module.load_snapshot_manifest(snapshot_path)
            self.assertGreaterEqual(
                manifest["card_sidecar_receipts"]["file_count"],
                2,
            )
            self.assertTrue(
                store_module.verify_snapshot_manifest(snapshot_path)["ok"]
            )
            restored = restore_drill(
                root,
                snapshot_uri=snap["snapshot_uri"],
                verify_recent_proof_packs=0,
            )
            self.assertTrue(restored["ok"], restored["checks"])
            restored_checks = {
                check["name"]: check for check in restored["checks"]
            }
            self.assertTrue(
                restored_checks[
                    "restored_card_sidecar_receipts_match_snapshot_manifest"
                ]["ok"]
            )

            unreceipted_payload = dict(payload_s3)
            unreceipted_payload["summary"] = (
                "A self-consistent injected generation has no terminal receipt."
            )
            unreceipted_payload["state_hash"] = (
                store_module._atomic_card_state_hash(unreceipted_payload)
            )
            unreceipted_path = hashed_s3.with_name(
                f"{card_id}.live-{unreceipted_payload['state_hash']}.yaml"
            )
            store_module.write_atomic_yaml(
                unreceipted_path,
                unreceipted_payload,
            )
            unreceipted_integrity = semantic_integrity_report(root)
            self.assertFalse(unreceipted_integrity["ok"])
            self.assertEqual(
                unreceipted_integrity["checks"]["orphan_card_sidecars"],
                1,
            )
            unreceipted_path.unlink()
            self.assertTrue(semantic_integrity_report(root)["ok"])

            bad_hash_path = hashed_s3.with_name(
                f"{card_id}.live-{'0' * 64}.yaml"
            )
            bad_hash_path.write_bytes(hashed_s3.read_bytes())
            conn = connect(root)
            try:
                store_module.record_artifact(
                    conn,
                    kind="sidecar_proof",
                    uri=store_module.continuum_uri(root, bad_hash_path),
                    sha256=store_module.file_sha256(bad_hash_path),
                    size_bytes=bad_hash_path.stat().st_size,
                    immutable=True,
                    source_type="mismatched_content_addressed_name",
                    trust_level="local_evidence",
                )
                verified, uncertain = (
                    store_module._verified_immutable_card_sidecars(
                        root,
                        conn,
                        bad_hash_path.parent,
                    )
                )
                conn.execute(
                    "UPDATE cards SET location_uri = ? WHERE id = ?",
                    (
                        store_module.continuum_uri(root, bad_hash_path),
                        card_id,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
            self.assertIn(card_id, uncertain)
            self.assertFalse(
                any(path == bad_hash_path for path, _payload in verified.get(card_id, []))
            )
            mismatched = semantic_integrity_report(root)
            self.assertFalse(mismatched["ok"], mismatched)
            self.assertGreaterEqual(
                mismatched["checks"]["divergent_card_sidecars"],
                1,
            )

    @unittest.skipUnless(os.name == "nt", "NTFS case aliases are Windows-only")
    def test_case_renamed_hash_generation_with_lower_catalog_uri_is_portable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="windows-case-content-addressed-generation",
                    summary="The default generation begins mutable.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])

            def current_path() -> Path:
                current_conn = connect_existing(root)
                try:
                    uri = current_conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()["location_uri"]
                finally:
                    current_conn.close()
                return resolve_stored_uri(root, uri)

            def freeze_current(source_type: str) -> None:
                path = current_path()
                artifact_conn = connect(root)
                try:
                    store_module.record_artifact(
                        artifact_conn,
                        kind="sidecar_proof",
                        uri=store_module.continuum_uri(root, path),
                        sha256=store_module.file_sha256(path),
                        size_bytes=path.stat().st_size,
                        immutable=True,
                        source_type=source_type,
                        trust_level="local_evidence",
                    )
                    artifact_conn.commit()
                finally:
                    artifact_conn.close()

            def advance(summary: str, reason: str) -> Path:
                update_conn = connect(root)
                try:
                    update_conn.execute(
                        "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                        (summary, store_module.utc_now(), card_id),
                    )
                    store_module.mark_card_sidecar_outbox(
                        update_conn,
                        [card_id],
                        reason=reason,
                    )
                    update_conn.commit()
                finally:
                    update_conn.close()
                sync = sync_card_sidecars_after_commit(root, [card_id])
                self.assertTrue(sync["ok"], sync)
                return current_path()

            freeze_current("windows_case_default")
            live_path = advance(
                "The stable live generation is now selected.",
                "windows_case_live",
            )
            self.assertEqual(live_path.name, f"{card_id}.live.yaml")
            freeze_current("windows_case_live")
            hash_path = advance(
                "The first content-addressed generation is current.",
                "windows_case_hash",
            )
            self.assertIn(".live-", hash_path.name)
            lower_location_uri = store_module.continuum_uri(root, hash_path)
            self.assertEqual(
                Path(lower_location_uri.removeprefix("continuum://")).name,
                hash_path.name,
            )
            hop = hash_path.with_name(f".{hash_path.name}.case-hop")
            uppercase_path = hash_path.with_name(hash_path.name.upper())
            os.replace(hash_path, hop)
            os.replace(hop, uppercase_path)
            conn = connect(root)
            try:
                stored_location_uri = str(
                    conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()["location_uri"]
                )
            finally:
                conn.close()
            self.assertEqual(stored_location_uri, lower_location_uri)
            self.assertTrue(semantic_integrity_report(root)["ok"])

            next_path = advance(
                "The uppercase historical generation remains receipted.",
                "windows_case_next_hash",
            )

            self.assertNotEqual(next_path.name.casefold(), uppercase_path.name.casefold())
            self.assertTrue(uppercase_path.is_file())
            self.assertTrue(semantic_integrity_report(root)["ok"])
            transition_receipts = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (
                    root / "exports" / "card_sidecar_recovery_receipts"
                ).glob("*.json")
            ]
            uppercase_payload = load_atomic_yaml(
                uppercase_path.read_text(encoding="utf-8")
            )
            history_index = (
                store_module._validated_card_sidecar_history_receipt_index(root)
            )
            self.assertTrue(
                any(
                    receipt.get("mode") == "history_transition"
                    and receipt.get("status") == "transition_prepared"
                    and Path(str(receipt.get("target_uri") or "")).name
                    == uppercase_path.name
                    for receipt in transition_receipts
                ),
                transition_receipts,
            )
            self.assertTrue(
                store_module._history_receipt_binds_card_sidecar(
                    uppercase_path,
                    card_id=card_id,
                    state_hash=str(uppercase_payload["state_hash"]),
                    receipt_index=history_index,
                ),
                transition_receipts,
            )
            snap = store_module.snapshot(
                root,
                reason="windows case-renamed hash generation",
            )
            snapshot_path = Path(str(snap["snapshot_uri"]))
            manifest = store_module.load_snapshot_manifest(snapshot_path)
            self.assertGreaterEqual(
                manifest["card_sidecar_receipts"]["file_count"],
                1,
            )
            self.assertTrue(
                store_module.verify_snapshot_manifest(snapshot_path)["ok"]
            )
            restored = restore_drill(
                root,
                snapshot_uri=snap["snapshot_uri"],
                verify_recent_proof_packs=0,
            )
            self.assertTrue(restored["ok"], restored["checks"])

    def test_portable_uppercase_historical_generation_and_receipt_restore(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="portable-case-alias",
                    summary="The default sidecar begins mutable.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])

            def current_path() -> Path:
                current_conn = connect_existing(root)
                try:
                    location_uri = str(
                        current_conn.execute(
                            "SELECT location_uri FROM cards WHERE id = ?",
                            (card_id,),
                        ).fetchone()["location_uri"]
                    )
                finally:
                    current_conn.close()
                return resolve_stored_uri(root, location_uri)

            def freeze_current(source_type: str) -> None:
                path = current_path()
                artifact_conn = connect(root)
                try:
                    store_module.record_artifact(
                        artifact_conn,
                        kind="sidecar_proof",
                        uri=store_module.continuum_uri(root, path),
                        sha256=store_module.file_sha256(path),
                        size_bytes=path.stat().st_size,
                        immutable=True,
                        source_type=source_type,
                        trust_level="local_evidence",
                    )
                    artifact_conn.commit()
                finally:
                    artifact_conn.close()

            def advance(summary: str, reason: str) -> Path:
                update_conn = connect(root)
                try:
                    update_conn.execute(
                        "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                        (summary, store_module.utc_now(), card_id),
                    )
                    store_module.mark_card_sidecar_outbox(
                        update_conn,
                        [card_id],
                        reason=reason,
                    )
                    update_conn.commit()
                finally:
                    update_conn.close()
                sync = sync_card_sidecars_after_commit(root, [card_id])
                self.assertTrue(sync["ok"], sync)
                return current_path()

            freeze_current("portable_case_default")
            live_path = advance(
                "The stable live sidecar is now selected.",
                "portable_case_live",
            )
            self.assertEqual(live_path.name, f"{card_id}.live.yaml")
            freeze_current("portable_case_live")
            historical_path = advance(
                "The first content-addressed generation is current.",
                "portable_case_first_hash",
            )
            historical_uri = store_module.continuum_uri(root, historical_path)
            current_generation = advance(
                "A second content-addressed generation becomes current.",
                "portable_case_second_hash",
            )
            self.assertNotEqual(current_generation, historical_path)

            hop = historical_path.with_name(f".{historical_path.name}.case-hop")
            uppercase_path = historical_path.with_name(historical_path.name.upper())
            os.replace(historical_path, hop)
            os.replace(hop, uppercase_path)
            receipt_dir = root / "exports" / "card_sidecar_recovery_receipts"
            historical_receipt_path: Path | None = None
            historical_receipt: dict[str, object] | None = None
            for receipt_path in receipt_dir.glob("*.json"):
                receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                if (
                    receipt.get("target_uri") == historical_uri
                    and receipt.get("mode") == "write"
                    and receipt.get("status") == "adopted"
                ):
                    historical_receipt_path = receipt_path
                    historical_receipt = receipt
                    break
            self.assertIsNotNone(historical_receipt_path)
            self.assertIsNotNone(historical_receipt)
            assert historical_receipt_path is not None
            assert historical_receipt is not None
            uppercase_uri = store_module.continuum_uri(root, uppercase_path)
            historical_receipt["target_uri"] = uppercase_uri
            replacement_intent_id = store_module.stable_id(
                "card_sidecar_write_intent",
                str(historical_receipt["mode"]),
                str(historical_receipt["card_id"]),
                uppercase_uri,
                str(historical_receipt["expected_state_hash"]),
                str(historical_receipt["attempt_id"]),
            )
            historical_receipt["intent_id"] = replacement_intent_id
            replacement_receipt_path = receipt_dir / f"{replacement_intent_id}.json"
            store_module.secure_write_text(
                replacement_receipt_path,
                store_module.json_dumps(historical_receipt) + "\n",
            )
            if replacement_receipt_path != historical_receipt_path:
                historical_receipt_path.unlink()

            portable_integrity = semantic_integrity_report(root)
            self.assertTrue(portable_integrity["ok"], portable_integrity)
            snap = store_module.snapshot(
                root,
                reason="portable uppercase historical Card generation",
            )
            snapshot_path = Path(str(snap["snapshot_uri"]))
            self.assertTrue(
                store_module.verify_snapshot_manifest(snapshot_path)["ok"]
            )
            restored = restore_drill(
                root,
                snapshot_uri=snap["snapshot_uri"],
                verify_recent_proof_packs=0,
            )
            self.assertTrue(restored["ok"], restored["checks"])

    @unittest.skipUnless(os.name == "posix", "case-distinct files require POSIX")
    def test_snapshot_rejects_portable_sidecar_filename_collision(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="portable-name-collision",
                    summary="A sidecar name must be unique under case folding.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])
            sidecar = store_module.card_sidecar_path(root, card_id)
            assert sidecar is not None
            uppercase = sidecar.with_name(sidecar.name.upper())
            uppercase.write_bytes(sidecar.read_bytes())
            integrity = semantic_integrity_report(root)
            self.assertEqual(
                integrity["checks"]["nonportable_card_sidecar_name_collisions"],
                1,
            )
            with self.assertRaisesRegex(
                ValueError,
                "nonportable_card_sidecar_name_collisions|portable filename collision",
            ):
                store_module.snapshot(root, reason="reject portable name collision")

    def test_snapshot_rejects_casefold_colliding_card_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            config = store_module.load_config(root)
            config["atomic_memory"]["write_card_sidecars"] = False
            write_config(root, config)
            conn = connect(root)
            try:
                first_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="portable-id-one",
                    summary="The first portable Card identifier.",
                    source_refs=[],
                )
                second_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="portable-id-two",
                    summary="The second identifier is replaced for the probe.",
                    source_refs=[],
                )
                conn.execute(
                    "DELETE FROM card_sidecar_outbox WHERE card_id = ?",
                    (second_id,),
                )
                conn.execute(
                    "UPDATE cards SET id = ? WHERE id = ?",
                    (first_id.upper(), second_id),
                )
                conn.commit()
                integrity = semantic_integrity_report(root, conn=conn)
            finally:
                conn.close()
            self.assertEqual(
                integrity["checks"]["nonportable_card_id_collisions"],
                1,
            )
            self.assertFalse(integrity["ok"], integrity)
            with self.assertRaisesRegex(
                ValueError,
                "snapshot preflight failed: .*semantic integrity",
            ):
                store_module.snapshot(root, reason="reject colliding Card ids")

    def test_disabled_sidecar_writes_remain_pending_until_reenabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="disabled-sidecar-retry",
                    summary="The first committed sidecar state.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            initial = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(initial["ok"], initial)

            config = store_module.load_config(root)
            config["atomic_memory"]["write_card_sidecars"] = False
            write_config(root, config)
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                    (
                        "The committed Card now requires a later sidecar state.",
                        store_module.utc_now(),
                        card_id,
                    ),
                )
                store_module.mark_card_sidecar_outbox(
                    conn,
                    [card_id],
                    reason="disabled_sidecar_update",
                )
                conn.commit()
            finally:
                conn.close()

            disabled = sync_card_sidecars_after_commit(root, [card_id])
            self.assertFalse(disabled["ok"], disabled)
            conn = connect_existing(root)
            try:
                self.assertIsNotNone(
                    conn.execute(
                        "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                        (card_id,),
                    ).fetchone()
                )
            finally:
                conn.close()

            worker_disabled = worker_module.sync_card_sidecar_job(
                root,
                card_id=card_id,
            )
            self.assertFalse(worker_disabled["ok"], worker_disabled)
            self.assertEqual(worker_disabled["reason"], "sidecars_disabled")
            conn = connect_existing(root)
            try:
                self.assertIsNotNone(
                    conn.execute(
                        "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                        (card_id,),
                    ).fetchone()
                )
            finally:
                conn.close()

            config = store_module.load_config(root)
            config["atomic_memory"]["write_card_sidecars"] = True
            write_config(root, config)
            recovered = store_module.sync_pending_card_sidecars(root)
            self.assertTrue(recovered["ok"], recovered)
            conn = connect_existing(root)
            try:
                self.assertIsNone(
                    conn.execute(
                        "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                        (card_id,),
                    ).fetchone()
                )
            finally:
                conn.close()
            integrity = semantic_integrity_report(root)
            self.assertTrue(integrity["ok"], integrity)

    def test_disabled_sidecar_worker_effect_retries_same_job_after_reenable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="disabled-worker-reclaim",
                    summary="Initial sidecar state before a disabled worker attempt.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])

            config = store_module.load_config(root)
            config["atomic_memory"]["write_card_sidecars"] = False
            write_config(root, config)
            first_owner = "disabled-sidecar-owner-one"
            future = (
                dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)
            ).isoformat()
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                    (
                        "A reclaimed worker must write this later state.",
                        store_module.utc_now(),
                        card_id,
                    ),
                )
                store_module.mark_card_sidecar_outbox(
                    conn,
                    [card_id],
                    reason="disabled_worker_reclaim",
                )
                job_id = enqueue_job(
                    conn,
                    role="archivist",
                    job_type="sync_card_sidecar",
                    priority=1,
                    payload={"card_id": card_id},
                    related_card_ids=[card_id],
                    dedupe_key=f"card:{card_id}",
                )
                conn.execute(
                    """
                    UPDATE queue_jobs
                    SET status = 'running', lease_owner = ?, lease_expires_at = ?,
                        heartbeat_at = ?, started_at = ?
                    WHERE id = ?
                    """,
                    (first_owner, future, future, future, job_id),
                )
                conn.commit()
            finally:
                conn.close()

            first_lease = worker_module._JobLease(
                root,
                job_id,
                first_owner,
                300,
            )
            first_token = worker_module._CURRENT_JOB_LEASE.set(first_lease)
            try:
                disabled = worker_module.sync_card_sidecar_job(
                    root,
                    card_id=card_id,
                )
            finally:
                worker_module._CURRENT_JOB_LEASE.reset(first_token)
            self.assertFalse(disabled["ok"], disabled)
            conn = connect_existing(root)
            try:
                disabled_effect_count = int(
                    conn.execute(
                        """
                        SELECT count(*) FROM audit_events
                        WHERE action = 'worker_job_effect_committed'
                          AND target_id = ?
                        """,
                        (job_id,),
                    ).fetchone()[0]
                )
            finally:
                conn.close()
            self.assertEqual(disabled_effect_count, 0)

            config = store_module.load_config(root)
            config["atomic_memory"]["write_card_sidecars"] = True
            write_config(root, config)
            second_owner = "disabled-sidecar-owner-two"
            conn = connect(root)
            try:
                conn.execute(
                    """
                    UPDATE queue_jobs
                    SET status = 'running', lease_owner = ?, lease_expires_at = ?,
                        heartbeat_at = ?
                    WHERE id = ?
                    """,
                    (second_owner, future, future, job_id),
                )
                conn.commit()
            finally:
                conn.close()
            second_lease = worker_module._JobLease(
                root,
                job_id,
                second_owner,
                300,
            )
            second_token = worker_module._CURRENT_JOB_LEASE.set(second_lease)
            try:
                recovered = worker_module.sync_card_sidecar_job(
                    root,
                    card_id=card_id,
                )
            finally:
                worker_module._CURRENT_JOB_LEASE.reset(second_token)
            self.assertTrue(recovered["ok"], recovered)
            conn = connect_existing(root)
            try:
                recovered_effect_count = int(
                    conn.execute(
                        """
                        SELECT count(*) FROM audit_events
                        WHERE action = 'worker_job_effect_committed'
                          AND target_id = ?
                        """,
                        (job_id,),
                    ).fetchone()[0]
                )
                pending_outbox = conn.execute(
                    "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(recovered_effect_count, 1)
            self.assertIsNone(pending_outbox)
            integrity = semantic_integrity_report(root)
            self.assertTrue(integrity["ok"], integrity)

    def test_worker_pass_requeues_deferred_sidecar_without_failed_job(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="worker-pass-deferred-sidecar",
                    summary="Initial materialized state.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])

            config = store_module.load_config(root)
            config["atomic_memory"]["write_card_sidecars"] = False
            write_config(root, config)
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                    ("Deferred until writes are enabled.", store_module.utc_now(), card_id),
                )
                store_module.mark_card_sidecar_outbox(
                    conn,
                    [card_id],
                    reason="worker_pass_deferred_sidecar",
                )
                job_id = enqueue_job(
                    conn,
                    role="archivist",
                    job_type="sync_card_sidecar",
                    priority=1,
                    payload={"card_id": card_id},
                    related_card_ids=[card_id],
                    dedupe_key=f"card:{card_id}",
                )
                conn.commit()
            finally:
                conn.close()

            deferred = run_worker_pass(
                root,
                roles=["archivist"],
                limit=1,
                maintenance=False,
            )
            self.assertFalse(deferred["ok"], deferred)
            self.assertEqual(deferred["processed"][0]["job_id"], job_id)
            self.assertEqual(deferred["processed"][0]["status"], "pending")
            conn = connect_existing(root)
            try:
                deferred_row = conn.execute(
                    "SELECT status, lease_owner FROM queue_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()
                failed_jobs = int(
                    conn.execute(
                        "SELECT count(*) FROM queue_jobs WHERE status = 'failed'"
                    ).fetchone()[0]
                )
            finally:
                conn.close()
            self.assertEqual(dict(deferred_row), {"status": "pending", "lease_owner": None})
            self.assertEqual(failed_jobs, 0)
            self.assertEqual(memory_health(root)["failed_jobs"], 0)

            config = store_module.load_config(root)
            config["atomic_memory"]["write_card_sidecars"] = True
            write_config(root, config)
            recovered = run_worker_pass(
                root,
                roles=["archivist"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(recovered["ok"], recovered)
            self.assertEqual(recovered["processed"][0]["job_id"], job_id)
            self.assertEqual(recovered["processed"][0]["status"], "succeeded")
            conn = connect_existing(root)
            try:
                recovered_status = conn.execute(
                    "SELECT status FROM queue_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()["status"]
                pending_outbox = conn.execute(
                    "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(recovered_status, "succeeded")
            self.assertIsNone(pending_outbox)
            self.assertEqual(memory_health(root)["failed_jobs"], 0)

    def test_sidecar_worker_expiry_after_materialization_replays_idempotently(
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
                    title="sidecar-first-commit-fence",
                    summary="A lease must still be owned at the first sidecar commit.",
                    source_refs=[],
                )
                before = dict(
                    conn.execute(
                        """
                        SELECT card.location_uri,
                               outbox.generation AS sidecar_generation
                        FROM cards AS card
                        LEFT JOIN card_sidecar_outbox AS outbox
                          ON outbox.card_id = card.id
                        WHERE card.id = ?
                        """,
                        (card_id,),
                    ).fetchone()
                )
                conn.commit()
            finally:
                conn.close()
            job_id, lease = self._running_sidecar_job_lease(
                root,
                card_id,
                suffix="materialized",
            )
            real_commit = worker_module._commit_sidecar_worker_phase

            def expire_at_first_commit(transaction_conn, active_lease, **kwargs):
                transaction_conn.execute(
                    """
                    UPDATE queue_jobs
                    SET lease_expires_at = '2000-01-01T00:00:00+00:00'
                    WHERE id = ?
                    """,
                    (job_id,),
                )
                return real_commit(
                    transaction_conn,
                    active_lease,
                    **kwargs,
                )

            token = worker_module._CURRENT_JOB_LEASE.set(lease)
            try:
                with patch.object(
                    worker_module,
                    "_commit_sidecar_worker_phase",
                    side_effect=expire_at_first_commit,
                ), self.assertRaisesRegex(RuntimeError, "worker lease lost"):
                    worker_module.sync_card_sidecar_job(root, card_id=card_id)
            finally:
                worker_module._CURRENT_JOB_LEASE.reset(token)

            conn = connect_existing(root)
            try:
                after = dict(
                    conn.execute(
                        """
                        SELECT card.location_uri,
                               outbox.generation AS sidecar_generation
                        FROM cards AS card
                        LEFT JOIN card_sidecar_outbox AS outbox
                          ON outbox.card_id = card.id
                        WHERE card.id = ?
                        """,
                        (card_id,),
                    ).fetchone()
                )
                phase_count = int(
                    conn.execute(
                        "SELECT count(*) FROM audit_events WHERE target_id = ? AND action = ?",
                        (job_id, worker_module._SIDECAR_WORKER_PHASE_ACTION),
                    ).fetchone()[0]
                )
                effect_count = int(
                    conn.execute(
                        "SELECT count(*) FROM audit_events WHERE target_id = ? AND action = ?",
                        (job_id, worker_module._WORKER_EFFECT_ACTION),
                    ).fetchone()[0]
                )
            finally:
                conn.close()
            self.assertIsNotNone(before["sidecar_generation"])
            self.assertEqual(after["location_uri"], before["location_uri"])
            self.assertIsNone(after["sidecar_generation"])
            self.assertEqual(phase_count, 0)
            self.assertEqual(effect_count, 0)
            self.assertTrue(
                resolve_stored_uri(root, str(after["location_uri"])).exists()
            )

            conn = connect(root)
            try:
                conn.execute(
                    """
                    UPDATE queue_jobs
                    SET lease_expires_at = '2000-01-01T00:00:00+00:00',
                        heartbeat_at = '2000-01-01T00:00:00+00:00'
                    WHERE id = ?
                    """,
                    (job_id,),
                )
                conn.commit()
            finally:
                conn.close()
            recovered = run_worker_pass(
                root,
                roles=["archivist"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(recovered["ok"], recovered)
            self.assertEqual(recovered["reclaimed_expired_jobs"], 1)
            self.assertEqual(recovered["processed"][0]["job_id"], job_id)
            self.assertEqual(recovered["processed"][0]["status"], "succeeded")
            conn = connect_existing(root)
            try:
                final_row = conn.execute(
                    "SELECT status, attempt_count FROM queue_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()
                final_effect_count = int(
                    conn.execute(
                        """
                        SELECT count(*) FROM audit_events
                        WHERE target_id = ? AND action = ?
                        """,
                        (job_id, worker_module._WORKER_EFFECT_ACTION),
                    ).fetchone()[0]
                )
            finally:
                conn.close()
            self.assertEqual(final_row["status"], "succeeded")
            self.assertEqual(final_row["attempt_count"], 1)
            self.assertEqual(final_effect_count, 1)

    def test_sidecar_worker_expiry_fences_disabled_retry_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="sidecar-disabled-commit-fence",
                    summary="Initial materialized state.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])
            config = store_module.load_config(root)
            config["atomic_memory"]["write_card_sidecars"] = False
            write_config(root, config)
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                    ("This update remains pending while disabled.", store_module.utc_now(), card_id),
                )
                store_module.mark_card_sidecar_outbox(
                    conn,
                    [card_id],
                    reason="disabled_commit_fence",
                )
                before = dict(
                    conn.execute(
                        """
                        SELECT generation, attempt_count, last_error
                        FROM card_sidecar_outbox
                        WHERE card_id = ?
                        """,
                        (card_id,),
                    ).fetchone()
                )
                conn.commit()
            finally:
                conn.close()
            job_id, lease = self._running_sidecar_job_lease(
                root,
                card_id,
                suffix="disabled",
            )
            real_commit = worker_module._commit_sidecar_worker_phase

            def expire_at_disabled_commit(transaction_conn, active_lease, **kwargs):
                transaction_conn.execute(
                    """
                    UPDATE queue_jobs
                    SET lease_expires_at = '2000-01-01T00:00:00+00:00'
                    WHERE id = ?
                    """,
                    (job_id,),
                )
                return real_commit(transaction_conn, active_lease, **kwargs)

            token = worker_module._CURRENT_JOB_LEASE.set(lease)
            try:
                with patch.object(
                    worker_module,
                    "_commit_sidecar_worker_phase",
                    side_effect=expire_at_disabled_commit,
                ), self.assertRaisesRegex(RuntimeError, "worker lease lost"):
                    worker_module.sync_card_sidecar_job(root, card_id=card_id)
            finally:
                worker_module._CURRENT_JOB_LEASE.reset(token)

            conn = connect_existing(root)
            try:
                after = dict(
                    conn.execute(
                        """
                        SELECT generation, attempt_count, last_error
                        FROM card_sidecar_outbox
                        WHERE card_id = ?
                        """,
                        (card_id,),
                    ).fetchone()
                )
                phase_count = int(
                    conn.execute(
                        "SELECT count(*) FROM audit_events WHERE target_id = ? AND action = ?",
                        (job_id, worker_module._SIDECAR_WORKER_PHASE_ACTION),
                    ).fetchone()[0]
                )
            finally:
                conn.close()
            self.assertEqual(after, before)
            self.assertEqual(phase_count, 0)

    def test_sidecar_worker_reconciliation_commit_is_fenced_and_phase_bound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="sidecar-reconciliation-commit-fence",
                    summary="The materialized phase must survive a later lost lease.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            job_id, lease = self._running_sidecar_job_lease(
                root,
                card_id,
                suffix="reconciliation",
            )
            real_commit = worker_module._commit_sidecar_worker_phase
            commit_calls = 0

            def expire_at_second_commit(transaction_conn, active_lease, **kwargs):
                nonlocal commit_calls
                commit_calls += 1
                if commit_calls == 2:
                    transaction_conn.execute(
                        """
                        UPDATE queue_jobs
                        SET lease_expires_at = '2000-01-01T00:00:00+00:00'
                        WHERE id = ?
                        """,
                        (job_id,),
                    )
                return real_commit(transaction_conn, active_lease, **kwargs)

            token = worker_module._CURRENT_JOB_LEASE.set(lease)
            try:
                with (
                    patch.object(
                        worker_module,
                        "reconcile_card_sidecar_write_intents",
                        return_value={
                            "ok": False,
                            "pending": 1,
                            "failures": [{"error": "forced reconciliation delay"}],
                            "results": [],
                        },
                    ),
                    patch.object(
                        worker_module,
                        "_commit_sidecar_worker_phase",
                        side_effect=expire_at_second_commit,
                    ),
                    self.assertRaisesRegex(RuntimeError, "worker lease lost"),
                ):
                    worker_module.sync_card_sidecar_job(root, card_id=card_id)
            finally:
                worker_module._CURRENT_JOB_LEASE.reset(token)

            conn = connect_existing(root)
            try:
                location_uri = conn.execute(
                    "SELECT location_uri FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()[0]
                pending = conn.execute(
                    "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                ).fetchone()
                phase_rows = list(
                    conn.execute(
                        """
                        SELECT payload_json FROM audit_events
                        WHERE target_id = ? AND action = ?
                        ORDER BY created_at, id
                        """,
                        (job_id, worker_module._SIDECAR_WORKER_PHASE_ACTION),
                    )
                )
                effect_count = int(
                    conn.execute(
                        "SELECT count(*) FROM audit_events WHERE target_id = ? AND action = ?",
                        (job_id, worker_module._WORKER_EFFECT_ACTION),
                    ).fetchone()[0]
                )
            finally:
                conn.close()
            self.assertIsNotNone(location_uri)
            self.assertIsNone(pending)
            self.assertEqual(len(phase_rows), 1)
            self.assertEqual(
                json.loads(phase_rows[0]["payload_json"])["phase"],
                "materialized_pending_reconciliation",
            )
            self.assertEqual(effect_count, 0)

    def test_sidecar_worker_requeues_when_fresh_reconciliation_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="sidecar-fresh-reconciliation-exception",
                    summary="A transient reconciliation exception must retain retry authority.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            job_id, lease = self._running_sidecar_job_lease(
                root,
                card_id,
                suffix="fresh-reconciliation-exception",
            )
            token = worker_module._CURRENT_JOB_LEASE.set(lease)
            try:
                with patch.object(
                    worker_module,
                    "reconcile_card_sidecar_write_intents",
                    side_effect=OSError("forced fresh reconciliation failure"),
                ):
                    result = worker_module.sync_card_sidecar_job(
                        root,
                        card_id=card_id,
                    )
            finally:
                worker_module._CURRENT_JOB_LEASE.reset(token)

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "intent_reconciliation_incomplete")
            self.assertTrue(result["intent_reconciliation"]["raised"])
            self.assertIn(
                "forced fresh reconciliation failure",
                result["intent_reconciliation"]["error"],
            )
            conn = connect_existing(root)
            try:
                pending = conn.execute(
                    "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                ).fetchone()
                phase_count = int(
                    conn.execute(
                        "SELECT count(*) FROM audit_events WHERE target_id = ? AND action = ?",
                        (job_id, worker_module._SIDECAR_WORKER_PHASE_ACTION),
                    ).fetchone()[0]
                )
                effect_count = int(
                    conn.execute(
                        "SELECT count(*) FROM audit_events WHERE target_id = ? AND action = ?",
                        (job_id, worker_module._WORKER_EFFECT_ACTION),
                    ).fetchone()[0]
                )
            finally:
                conn.close()
            self.assertIsNotNone(pending)
            self.assertEqual(phase_count, 2)
            self.assertEqual(effect_count, 0)
            self.assertTrue(
                list((root / "run" / "card_sidecar_write_intents").glob("*.json"))
            )

    def test_sidecar_worker_requeues_when_terminal_replay_reconciliation_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="sidecar-terminal-replay-exception",
                    summary="A terminal replay must still retain reconciliation retry authority.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            job_id, lease = self._running_sidecar_job_lease(
                root,
                card_id,
                suffix="terminal-replay-exception",
            )
            token = worker_module._CURRENT_JOB_LEASE.set(lease)
            try:
                first = worker_module.sync_card_sidecar_job(root, card_id=card_id)
                self.assertTrue(first["ok"], first)
                with patch.object(
                    worker_module,
                    "reconcile_card_sidecar_write_intents",
                    side_effect=OSError("forced terminal replay reconciliation failure"),
                ):
                    replay = worker_module.sync_card_sidecar_job(
                        root,
                        card_id=card_id,
                    )
            finally:
                worker_module._CURRENT_JOB_LEASE.reset(token)

            self.assertFalse(replay["ok"], replay)
            self.assertTrue(replay["idempotent_replay"])
            self.assertEqual(replay["reason"], "intent_reconciliation_incomplete")
            self.assertTrue(replay["retry_pending"])
            self.assertTrue(replay["intent_reconciliation"]["raised"])
            self.assertIn(
                "forced terminal replay reconciliation failure",
                replay["intent_reconciliation"]["error"],
            )
            conn = connect_existing(root)
            try:
                pending = conn.execute(
                    "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                ).fetchone()
                phase_count = int(
                    conn.execute(
                        "SELECT count(*) FROM audit_events WHERE target_id = ? AND action = ?",
                        (job_id, worker_module._SIDECAR_WORKER_PHASE_ACTION),
                    ).fetchone()[0]
                )
                effect_count = int(
                    conn.execute(
                        "SELECT count(*) FROM audit_events WHERE target_id = ? AND action = ?",
                        (job_id, worker_module._WORKER_EFFECT_ACTION),
                    ).fetchone()[0]
                )
            finally:
                conn.close()
            self.assertIsNotNone(pending)
            self.assertEqual(phase_count, 2)
            self.assertEqual(effect_count, 1)

    def test_worker_pass_requeues_terminal_replay_until_reconciliation_is_clean(
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
                    title="public-terminal-replay-retry",
                    summary=(
                        "The public worker must preserve retry authority while "
                        "maintenance repairs sidecar state."
                    ),
                    source_refs=[],
                )
                job_id = enqueue_job(
                    conn,
                    role="archivist",
                    job_type="sync_card_sidecar",
                    priority=1,
                    payload={"card_id": card_id},
                    related_card_ids=[card_id],
                    dedupe_key=f"public-terminal-replay:{card_id}",
                )
                conn.commit()
            finally:
                conn.close()

            first = run_worker_pass(
                root,
                roles=["archivist"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(first["ok"], first)
            self.assertEqual(first["processed"][0]["job_id"], job_id)
            self.assertEqual(first["processed"][0]["status"], "succeeded")

            conn = connect(root)
            try:
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

            real_reconciliation = store_module.reconcile_card_sidecar_write_intents
            reconciliation_calls = 0

            def fail_terminal_replay_once(*args, **kwargs):
                nonlocal reconciliation_calls
                reconciliation_calls += 1
                if reconciliation_calls == 1:
                    raise OSError("forced terminal replay reconciliation failure")
                return real_reconciliation(*args, **kwargs)

            with patch.object(
                worker_module,
                "reconcile_card_sidecar_write_intents",
                side_effect=fail_terminal_replay_once,
            ):
                replayed = run_worker_pass(
                    root,
                    roles=["archivist"],
                    limit=1,
                    maintenance=True,
                )

            self.assertFalse(replayed["ok"], replayed)
            self.assertEqual(replayed["processed_count"], 1)
            replayed_job = replayed["processed"][0]
            self.assertEqual(replayed_job["job_id"], job_id)
            self.assertEqual(replayed_job["status"], "pending")
            self.assertFalse(replayed_job["ok"])
            replayed_result = replayed_job["result"]
            self.assertTrue(replayed_result["idempotent_replay"])
            self.assertEqual(
                replayed_result["reason"],
                "intent_reconciliation_incomplete",
            )
            self.assertTrue(replayed_result["retry_pending"])
            self.assertTrue(replayed_result["intent_reconciliation"]["raised"])
            self.assertEqual(reconciliation_calls, 2)
            self.assertTrue(replayed["maintenance"]["sidecars"]["ok"])
            self.assertEqual(replayed["maintenance"]["sidecars"]["synced"], 1)
            self.assertTrue(replayed["maintenance"]["sidecar_intents"]["ok"])
            self.assertEqual(
                replayed["maintenance"]["sidecar_intents"]["pending"],
                0,
            )

            conn = connect_existing(root)
            try:
                retry_row = conn.execute(
                    """
                    SELECT status, attempt_count, finished_at, lease_owner,
                           lease_expires_at, heartbeat_at, error_json
                    FROM queue_jobs
                    WHERE id = ?
                    """,
                    (job_id,),
                ).fetchone()
                failed_jobs = int(
                    conn.execute(
                        "SELECT count(*) FROM queue_jobs WHERE status = 'failed'"
                    ).fetchone()[0]
                )
                pending_outbox = conn.execute(
                    "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                ).fetchone()
            finally:
                conn.close()

            self.assertEqual(retry_row["status"], "pending")
            self.assertEqual(retry_row["attempt_count"], 2)
            self.assertIsNone(retry_row["finished_at"])
            self.assertIsNone(retry_row["lease_owner"])
            self.assertIsNone(retry_row["lease_expires_at"])
            self.assertIsNone(retry_row["heartbeat_at"])
            retry_receipt = json.loads(retry_row["error_json"])
            self.assertIsNone(retry_receipt["error"])
            self.assertTrue(retry_receipt["retry_pending"])
            stored_result = retry_receipt["result"]
            self.assertFalse(stored_result["ok"])
            self.assertEqual(
                stored_result["reason"],
                "intent_reconciliation_incomplete",
            )
            self.assertTrue(stored_result["retry_pending"])
            self.assertEqual(failed_jobs, 0)
            self.assertIsNone(pending_outbox)
            self.assertEqual(memory_health(root)["failed_jobs"], 0)

            recovered = run_worker_pass(
                root,
                roles=["archivist"],
                limit=1,
                maintenance=False,
            )
            self.assertTrue(recovered["ok"], recovered)
            self.assertEqual(recovered["processed"][0]["job_id"], job_id)
            self.assertEqual(recovered["processed"][0]["status"], "succeeded")
            self.assertTrue(
                recovered["processed"][0]["result"]["idempotent_replay"]
            )
            conn = connect_existing(root)
            try:
                recovered_row = conn.execute(
                    "SELECT status, attempt_count FROM queue_jobs WHERE id = ?",
                    (job_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(recovered_row["status"], "succeeded")
            self.assertEqual(recovered_row["attempt_count"], 3)

    def test_terminal_sidecar_receipts_do_not_share_active_intent_count_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            with patch.object(
                store_module,
                "MAX_CARD_SIDECAR_WRITE_INTENTS",
                2,
            ):
                for index in range(3):
                    conn = connect(root)
                    try:
                        card_id = create_card(
                            conn,
                            root=root,
                            card_type="note",
                            title=f"receipt-history-{index}",
                            summary=f"Successful sidecar write {index}.",
                            source_refs=[],
                        )
                        conn.commit()
                    finally:
                        conn.close()
                    sync = sync_card_sidecars_after_commit(root, [card_id])
                    self.assertTrue(sync["ok"], sync)

                receipt_paths = list(
                    (
                        root / "exports" / "card_sidecar_recovery_receipts"
                    ).glob("*.json")
                )
                self.assertEqual(len(receipt_paths), 3)
                integrity = semantic_integrity_report(root)
                self.assertTrue(integrity["ok"], integrity)
                self.assertEqual(
                    integrity["checks"]["card_sidecar_recovery_scan_overflow"],
                    0,
                )

    def test_active_sidecar_intent_scans_retain_only_bounded_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="bounded-intent-scan",
                    summary="Active recovery work must have a real scan bound.",
                    source_refs=[],
                )
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                payload = store_module._card_sidecar_payload_for_row(row)
                conn.commit()
            finally:
                conn.close()
            target_uri = f"catalog/cards/{card_id}.yaml"
            for _index in range(3):
                store_module._write_card_sidecar_write_intent(
                    root,
                    card_id=card_id,
                    target_uri=target_uri,
                    expected_state_hash=str(payload["state_hash"]),
                )
            intent_dir = root / "run" / "card_sidecar_write_intents"

            with patch.object(
                store_module,
                "MAX_CARD_SIDECAR_WRITE_INTENTS",
                2,
            ):
                bounded_paths, overflow, enumerated = (
                    store_module._bounded_card_sidecar_intent_paths(intent_dir)
                )
                reconciled = store_module.reconcile_card_sidecar_write_intents(
                    root,
                    card_ids=["not-the-card"],
                )
                integrity = semantic_integrity_report(root)

            self.assertTrue(overflow)
            self.assertEqual(len(bounded_paths), 2)
            self.assertEqual(enumerated, 3)
            self.assertTrue(reconciled["overflow"], reconciled)
            self.assertEqual(reconciled["processed"], 0)
            self.assertEqual(
                integrity["checks"]["card_sidecar_write_intent_scan_overflow"],
                1,
            )
            self.assertEqual(
                integrity["checks"]["unresolved_card_sidecar_write_intents"],
                2,
            )

    def test_active_and_retirement_debris_share_one_enumeration_cap(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            intent_state = store_module._validated_card_sidecar_state_dir(
                root,
                purpose="intent",
                create=True,
            )
            retirement_state = (
                store_module._validated_card_sidecar_state_dir(
                    root,
                    purpose="retirement_intent",
                    create=True,
                )
            )
            self.assertIsNotNone(intent_state)
            self.assertIsNotNone(retirement_state)
            assert intent_state is not None
            assert retirement_state is not None
            for index in range(4):
                (retirement_state[0] / f"retirement-debris-{index}").write_text(
                    "debris",
                    encoding="utf-8",
                )
                (intent_state[0] / f"intent-debris-{index}").write_text(
                    "debris",
                    encoding="utf-8",
                )

            with patch.object(
                store_module,
                "MAX_CARD_SIDECAR_WRITE_INTENTS",
                2,
            ):
                (
                    intent_paths,
                    retirement_paths,
                    truncated,
                    enumerated,
                ) = store_module._bounded_card_sidecar_intent_inventory(
                    intent_state[0],
                    retirement_state[0],
                    entry_limit=2,
                )
                reconciled = (
                    store_module.reconcile_card_sidecar_write_intents(
                        root,
                        limit=2,
                    )
                )

            self.assertEqual(intent_paths, [])
            self.assertEqual(retirement_paths, [])
            self.assertTrue(truncated)
            self.assertEqual(enumerated, 3)
            self.assertEqual(reconciled["enumerated"], 3, reconciled)
            self.assertTrue(reconciled["batch_truncated"], reconciled)
            self.assertTrue(reconciled["overflow"], reconciled)
            self.assertFalse(reconciled["complete"], reconciled)

    def test_retirement_debris_cannot_starve_active_sidecar_intent(
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
                    title="Active intent fairness",
                    summary="Retirement debris cannot hide active authority.",
                    source_refs=[],
                )
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                payload = store_module._card_sidecar_payload_for_row(row)
                conn.execute(
                    "DELETE FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                )
                conn.commit()
            finally:
                conn.close()
            _intent_id, intent_path = (
                store_module._write_card_sidecar_write_intent(
                    root,
                    card_id=card_id,
                    target_uri=str(row["location_uri"]),
                    expected_state_hash=str(payload["state_hash"]),
                )
            )
            retirement_state = (
                store_module._validated_card_sidecar_state_dir(
                    root,
                    purpose="retirement_intent",
                    create=True,
                )
            )
            self.assertIsNotNone(retirement_state)
            assert retirement_state is not None
            debris_paths = [
                retirement_state[0] / f"stable-retirement-debris-{index}"
                for index in range(2)
            ]
            for debris_path in debris_paths:
                debris_path.write_text("debris", encoding="utf-8")

            reconciled = (
                store_module.reconcile_card_sidecar_write_intents(
                    root,
                    limit=2,
                )
            )

            self.assertTrue(reconciled["ok"], reconciled)
            self.assertEqual(reconciled["enumerated"], 3, reconciled)
            self.assertEqual(reconciled["inspected"], 1, reconciled)
            self.assertEqual(reconciled["selected"], 1, reconciled)
            self.assertEqual(reconciled["processed"], 1, reconciled)
            self.assertTrue(reconciled["batch_truncated"], reconciled)
            self.assertFalse(intent_path.exists())
            self.assertTrue(all(path.is_file() for path in debris_paths))

    def test_active_debris_reports_bounded_progress_blocked(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            intent_state = store_module._validated_card_sidecar_state_dir(
                root,
                purpose="intent",
                create=True,
            )
            self.assertIsNotNone(intent_state)
            assert intent_state is not None
            debris_paths = [
                intent_state[0] / f"000-stable-active-debris-{index}"
                for index in range(2)
            ]
            for debris_path in debris_paths:
                debris_path.write_text("debris", encoding="utf-8")
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="Active debris progress",
                    summary="A blocked scan must never report false success.",
                    source_refs=[],
                )
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                payload = store_module._card_sidecar_payload_for_row(row)
                conn.execute(
                    "DELETE FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                )
                conn.commit()
            finally:
                conn.close()
            _intent_id, intent_path = (
                store_module._write_card_sidecar_write_intent(
                    root,
                    card_id=card_id,
                    target_uri=str(row["location_uri"]),
                    expected_state_hash=str(payload["state_hash"]),
                )
            )

            attempts = [
                store_module.reconcile_card_sidecar_write_intents(
                    root,
                    limit=2,
                )
                for _index in range(3)
            ]

            for reconciled in attempts:
                self.assertFalse(reconciled["ok"], reconciled)
                self.assertTrue(
                    reconciled["progress_blocked"],
                    reconciled,
                )
                self.assertEqual(reconciled["enumerated"], 3, reconciled)
                self.assertEqual(reconciled["inspected"], 0, reconciled)
                self.assertEqual(reconciled["selected"], 0, reconciled)
                self.assertEqual(reconciled["processed"], 0, reconciled)
                self.assertTrue(
                    any(
                        failure.get("reason")
                        == "bounded_inventory_progress_blocked"
                        for failure in reconciled["failures"]
                    ),
                    reconciled,
                )
            self.assertTrue(intent_path.is_file())
            self.assertTrue(all(path.is_file() for path in debris_paths))

    def test_disabled_unmaterialized_card_review_does_not_block_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            config = store_module.load_config(root)
            config["atomic_memory"]["write_card_sidecars"] = False
            write_config(root, config)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="disabled-unmaterialized-review",
                    summary="No sidecar was promised while writes were disabled.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()

            reviewed = worker_module.review_card_placement(
                root,
                card_id=card_id,
            )

            self.assertTrue(reviewed["ok"], reviewed)
            conn = connect_existing(root)
            try:
                card_row = conn.execute(
                    "SELECT location_uri FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                pending = conn.execute(
                    "SELECT 1 FROM card_sidecar_outbox WHERE card_id = ?",
                    (card_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertIsNone(card_row["location_uri"])
            self.assertIsNone(pending)
            self.assertTrue(semantic_integrity_report(root)["ok"])
            snap = store_module.snapshot(
                root,
                reason="disabled unmaterialized Card remains snapshot compatible",
            )
            self.assertTrue(
                store_module.verify_snapshot_manifest(
                    Path(str(snap["snapshot_uri"]))
                )["ok"]
            )

    def test_reenable_backfills_unmaterialized_disabled_card_before_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            config = store_module.load_config(root)
            config["atomic_memory"]["write_card_sidecars"] = False
            write_config(root, config)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="reenable-unmaterialized-backfill",
                    summary="Re-enabling writes must backfill this Card.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(semantic_integrity_report(root)["ok"])

            config = store_module.load_config(root)
            config["atomic_memory"]["write_card_sidecars"] = True
            write_config(root, config)
            backfill = store_module.sync_pending_card_sidecars(root)

            self.assertTrue(backfill["ok"], backfill)
            self.assertEqual(backfill["synced"], 1)
            conn = connect_existing(root)
            try:
                location_uri = conn.execute(
                    "SELECT location_uri FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()["location_uri"]
            finally:
                conn.close()
            self.assertTrue(resolve_stored_uri(root, location_uri).is_file())
            self.assertTrue(semantic_integrity_report(root)["ok"])
            snap = store_module.snapshot(
                root,
                reason="reenabled Cards are backfilled before snapshot",
            )
            self.assertTrue(
                store_module.verify_snapshot_manifest(
                    Path(str(snap["snapshot_uri"]))
                )["ok"]
            )

    def test_traversal_card_id_intent_is_rejected_without_moving_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                source_card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="intent-card-id-confinement",
                    summary="A forged Card id must not escape the configured directory.",
                    source_refs=[],
                )
                source_row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (source_card_id,),
                ).fetchone()
                payload = store_module._card_sidecar_payload_for_row(source_row)
                conn.commit()
            finally:
                conn.close()

            malicious_card_id = "../../escaped"
            payload["id"] = malicious_card_id
            payload["card_id"] = malicious_card_id
            payload["state_hash"] = store_module._atomic_card_state_hash(payload)
            target_path = root / "escaped.yaml"
            store_module.write_atomic_yaml(target_path, payload)
            target_bytes = target_path.read_bytes()
            target_uri = store_module.continuum_uri(root, target_path)
            with self.assertRaisesRegex(ValueError, "invalid Card id"):
                store_module._write_card_sidecar_write_intent(
                    root,
                    card_id=malicious_card_id,
                    target_uri=target_uri,
                    expected_state_hash=str(payload["state_hash"]),
                )

            attempt_id = store_module.unique_id("card_sidecar_attempt")
            intent_id = store_module.stable_id(
                "card_sidecar_write_intent",
                "write",
                malicious_card_id,
                target_uri,
                str(payload["state_hash"]),
                attempt_id,
            )
            intent_state = store_module._validated_card_sidecar_state_dir(
                root,
                purpose="intent",
                create=True,
            )
            self.assertIsNotNone(intent_state)
            intent_path = intent_state[0] / f"{intent_id}.json"
            intent_path.write_text(
                json.dumps(
                    {
                        "schema": store_module.CARD_SIDECAR_WRITE_INTENT_SCHEMA,
                        "intent_id": intent_id,
                        "card_id": malicious_card_id,
                        "target_uri": target_uri,
                        "expected_state_hash": payload["state_hash"],
                        "mode": "write",
                        "attempt_id": attempt_id,
                        "created_at": store_module.utc_now(),
                    }
                ),
                encoding="utf-8",
            )

            reconciled = store_module.reconcile_card_sidecar_write_intents(root)
            self.assertFalse(reconciled["ok"], reconciled)
            self.assertEqual(reconciled["results"][0]["status"], "invalid_intent")
            self.assertTrue(target_path.is_file())
            self.assertEqual(target_path.read_bytes(), target_bytes)
            self.assertFalse(list(root.glob(".escaped.yaml.*.uncommitted")))
            self.assertFalse(
                store_module._is_managed_card_sidecar_path(
                    root / "catalog" / "cards" / malicious_card_id / "escaped.yaml",
                    target_path,
                    card_id=malicious_card_id,
                )
            )

    @unittest.skipUnless(os.name == "posix", "real parent symlinks are POSIX-only")
    def test_sidecar_intent_rejects_symlink_parent_dotdot_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            outside = Path(tmp) / "outside"
            (outside / "child").mkdir(parents=True)
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="parent-alias-confinement",
                    summary="A lexical parent alias must not become authority.",
                    source_refs=[],
                )
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                payload = store_module._card_sidecar_payload_for_row(row)
                conn.commit()
            finally:
                conn.close()
            link = root / "catalog" / "cards" / "link"
            link.symlink_to(outside / "child", target_is_directory=True)
            outside_target = outside / f"{card_id}.yaml"
            store_module.write_atomic_yaml(outside_target, payload)
            original_bytes = outside_target.read_bytes()
            forged_uri = f"catalog/cards/link/../{card_id}.yaml"
            store_module._write_card_sidecar_write_intent(
                root,
                card_id=card_id,
                target_uri=forged_uri,
                expected_state_hash=str(payload["state_hash"]),
            )

            reconciled = store_module.reconcile_card_sidecar_write_intents(root)

            self.assertFalse(reconciled["ok"], reconciled)
            self.assertEqual(reconciled["results"][0]["status"], "unmanaged_target")
            self.assertEqual(outside_target.read_bytes(), original_bytes)
            self.assertFalse(
                list(outside.glob(f".{card_id}.yaml.*.uncommitted"))
            )

    @unittest.skipUnless(os.name == "posix", "real parent symlinks are POSIX-only")
    def test_symlink_parent_dotdot_artifact_does_not_bind_default_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            outside = Path(tmp) / "outside"
            (outside / "child").mkdir(parents=True)
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="false-immutable-alias",
                    summary="The default sidecar is still mutable.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])
            conn = connect(root)
            try:
                default_uri = conn.execute(
                    "SELECT location_uri FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()["location_uri"]
                default_path = resolve_stored_uri(root, default_uri)
                original_bytes = default_path.read_bytes()
                outside_target = outside / f"{card_id}.yaml"
                outside_target.write_bytes(original_bytes)
                link = root / "catalog" / "cards" / "link"
                link.symlink_to(outside / "child", target_is_directory=True)
                forged_uri = f"catalog/cards/link/../{card_id}.yaml"
                store_module.record_artifact(
                    conn,
                    kind="sidecar_proof",
                    uri=forged_uri,
                    sha256=store_module.file_sha256(outside_target),
                    size_bytes=outside_target.stat().st_size,
                    immutable=True,
                    source_type="false_parent_alias",
                    trust_level="local_evidence",
                )
                artifact_index = store_module._immutable_artifact_path_index(
                    root,
                    conn,
                )
                self.assertFalse(
                    store_module._immutable_artifact_binds_path(
                        root,
                        conn,
                        default_path,
                        artifact_index=artifact_index,
                    )
                )
                conn.execute(
                    "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                    (
                        "The default sidecar receives the newer mutable state.",
                        store_module.utc_now(),
                        card_id,
                    ),
                )
                store_module.mark_card_sidecar_outbox(
                    conn,
                    [card_id],
                    reason="false_immutable_alias_update",
                )
                conn.commit()
            finally:
                conn.close()

            updated = sync_card_sidecars_after_commit(root, [card_id])

            self.assertTrue(updated["ok"], updated)
            self.assertNotEqual(default_path.read_bytes(), original_bytes)
            self.assertEqual(outside_target.read_bytes(), original_bytes)
            conn = connect_existing(root)
            try:
                current_uri = conn.execute(
                    "SELECT location_uri FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()["location_uri"]
            finally:
                conn.close()
            self.assertEqual(resolve_stored_uri(root, current_uri), default_path)
            self.assertFalse(
                (default_path.parent / f"{card_id}.live.yaml").exists()
            )
            self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_history_transition_intent_requires_current_physical_reference(self) -> None:
        for scenario, expected_status in (
            ("unreferenced", "history_transition_unreferenced"),
            ("missing", "history_transition_target_missing"),
            ("changed", "history_transition_target_mismatch"),
        ):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                init_db(root)
                conn = connect(root)
                try:
                    card_id = create_card(
                        conn,
                        root=root,
                        card_type="note",
                        title=f"history-transition-{scenario}",
                        summary="Only the DB-selected physical generation may transition.",
                        source_refs=[],
                    )
                    conn.commit()
                finally:
                    conn.close()
                self.assertTrue(
                    sync_card_sidecars_after_commit(root, [card_id])["ok"]
                )
                conn = connect_existing(root)
                try:
                    row = conn.execute(
                        "SELECT * FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()
                    payload = store_module._card_sidecar_payload_for_row(row)
                finally:
                    conn.close()
                expected_state_hash = str(payload["state_hash"])
                target = (
                    root
                    / "catalog"
                    / "cards"
                    / f"{card_id}.live-{expected_state_hash}.yaml"
                )
                if scenario != "missing":
                    target_payload = dict(payload)
                    if scenario == "changed":
                        target_payload["summary"] = "Changed after intent creation."
                        target_payload["state_hash"] = (
                            store_module._atomic_card_state_hash(target_payload)
                        )
                    store_module.write_atomic_yaml(target, target_payload)
                intent_id, intent_path = (
                    store_module._write_card_sidecar_write_intent(
                        root,
                        card_id=card_id,
                        target_uri=store_module.continuum_uri(root, target),
                        expected_state_hash=expected_state_hash,
                        mode="history_transition",
                    )
                )

                reconciled = store_module.reconcile_card_sidecar_write_intents(
                    root
                )

                self.assertFalse(reconciled["ok"], reconciled)
                self.assertEqual(
                    reconciled["results"][0]["status"],
                    expected_status,
                )
                self.assertTrue(intent_path.is_file())
                self.assertFalse(
                    (
                        root
                        / "exports"
                        / "card_sidecar_recovery_receipts"
                        / f"{intent_id}.json"
                    ).exists()
                )
                recovery_audit = (
                    store_module._card_sidecar_recovery_evidence_audit(root)
                )
                self.assertEqual(
                    recovery_audit[
                        "malformed_card_sidecar_recovery_receipts"
                    ],
                    0,
                )

    def test_interrupted_history_transition_recovers_selected_legacy_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="legacy-current-hash-transition",
                    summary="This hash generation predates transition receipts.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])
            conn = connect(root)
            try:
                row = conn.execute(
                    "SELECT * FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()
                payload = store_module._card_sidecar_payload_for_row(row)
                default_path = resolve_stored_uri(root, row["location_uri"])
                legacy_hash_path = default_path.with_name(
                    f"{card_id}.live-{payload['state_hash']}.yaml"
                )
                os.replace(default_path, legacy_hash_path)
                conn.execute(
                    "UPDATE cards SET location_uri = ? WHERE id = ?",
                    (
                        store_module.continuum_uri(root, legacy_hash_path),
                        card_id,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(semantic_integrity_report(root)["ok"])
            _intent_id, intent_path = (
                store_module._write_card_sidecar_write_intent(
                    root,
                    card_id=card_id,
                    target_uri=store_module.continuum_uri(
                        root,
                        legacy_hash_path,
                    ),
                    expected_state_hash=str(payload["state_hash"]),
                    mode="history_transition",
                )
            )

            reconciled = store_module.reconcile_card_sidecar_write_intents(root)

            self.assertTrue(reconciled["ok"], reconciled)
            self.assertEqual(
                reconciled["results"][0]["status"],
                "transition_prepared",
            )
            self.assertFalse(intent_path.exists())
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                    (
                        "The next state detaches the receipted legacy hash.",
                        store_module.utc_now(),
                        card_id,
                    ),
                )
                store_module.mark_card_sidecar_outbox(
                    conn,
                    [card_id],
                    reason="legacy_hash_transition_recovered",
                )
                conn.commit()
            finally:
                conn.close()
            updated = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(updated["ok"], updated)
            self.assertTrue(legacy_hash_path.is_file())
            self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_prune_compensation_quarantines_new_unbound_sidecar_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="copy-on-write-cleanup",
                    summary="The original immutable versions must survive compensation.",
                    source_refs=[],
                    topics=["copy-on-write-cleanup"],
                )
                conn.commit()
            finally:
                conn.close()
            first_sync = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(first_sync["ok"], first_sync)

            conn = connect(root)
            try:
                default_uri = conn.execute(
                    "SELECT location_uri FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()["location_uri"]
                default_path = resolve_stored_uri(root, default_uri)
                default_bytes = default_path.read_bytes()
                store_module.record_artifact(
                    conn,
                    kind="proof_input",
                    uri=default_uri,
                    sha256=hashlib.sha256(default_bytes).hexdigest(),
                    size_bytes=len(default_bytes),
                    source_type="prune_cow_default",
                    trust_level="local_generated",
                    immutable=True,
                )
                conn.execute(
                    "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                    (
                        "The live immutable version becomes the rollback authority.",
                        store_module.utc_now(),
                        card_id,
                    ),
                )
                store_module.mark_card_sidecar_outbox(
                    conn,
                    [card_id],
                    reason="prune_cow_live_version",
                )
                conn.commit()
            finally:
                conn.close()
            second_sync = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(second_sync["ok"], second_sync)

            conn = connect(root)
            try:
                live_uri = conn.execute(
                    "SELECT location_uri FROM cards WHERE id = ?",
                    (card_id,),
                ).fetchone()["location_uri"]
                live_path = resolve_stored_uri(root, live_uri)
                live_bytes = live_path.read_bytes()
                store_module.record_artifact(
                    conn,
                    kind="proof_input",
                    uri=live_uri,
                    sha256=hashlib.sha256(live_bytes).hexdigest(),
                    size_bytes=len(live_bytes),
                    source_type="prune_cow_live",
                    trust_level="local_generated",
                    immutable=True,
                )
                conn.commit()
                original = dict(
                    conn.execute(
                        "SELECT status, metadata_json, updated_at, location_uri "
                        "FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()
                )
            finally:
                conn.close()

            real_report = worker_module.semantic_integrity_report
            report_calls = 0

            def fail_normal_postflight(*args, **kwargs):
                nonlocal report_calls
                report_calls += 1
                if report_calls == 3:
                    return {"ok": False, "failing": {"simulated_postflight": 1}}
                return real_report(*args, **kwargs)

            with patch.object(
                worker_module,
                "semantic_integrity_report",
                side_effect=fail_normal_postflight,
            ), self.assertRaisesRegex(RuntimeError, "Card mutations were rolled back"):
                prune_memory(
                    root,
                    topic="copy-on-write-cleanup",
                    action="forget",
                )

            conn = connect_existing(root)
            try:
                restored = dict(
                    conn.execute(
                        "SELECT status, metadata_json, updated_at, location_uri "
                        "FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()
                )
            finally:
                conn.close()
            self.assertEqual(restored, original)
            self.assertEqual(default_path.read_bytes(), default_bytes)
            self.assertEqual(live_path.read_bytes(), live_bytes)
            self.assertEqual(audit(root)["orphan_card_sidecars"], 0)
            self.assertTrue(semantic_integrity_report(root)["ok"])
            self.assertFalse(
                list((root / "run" / "card_sidecar_write_intents").glob("*.json"))
            )
            recovery_files = list((root / "catalog" / "cards").glob(".*.uncommitted"))
            self.assertEqual(len(recovery_files), 1)
            receipts = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (root / "exports" / "card_sidecar_recovery_receipts").glob("*.json")
            ]
            self.assertTrue(
                any(receipt.get("status") == "quarantined" for receipt in receipts),
                receipts,
            )
            recovery_bytes = recovery_files[0].read_bytes()
            recovery_files[0].write_bytes(b"TAMPERED")
            tampered_recovery = semantic_integrity_report(root)
            self.assertFalse(tampered_recovery["ok"], tampered_recovery)
            self.assertEqual(
                tampered_recovery["checks"]["mismatched_card_sidecar_recoveries"],
                1,
            )
            recovery_files[0].write_bytes(recovery_bytes)
            self.assertTrue(semantic_integrity_report(root)["ok"])
            recovery_files[0].unlink()
            missing_recovery = semantic_integrity_report(root)
            self.assertFalse(missing_recovery["ok"], missing_recovery)
            self.assertEqual(
                missing_recovery["checks"]["missing_card_sidecar_recoveries"],
                1,
            )
            recovery_files[0].write_bytes(recovery_bytes)
            self.assertTrue(semantic_integrity_report(root)["ok"])
            snap = store_module.snapshot(root, reason="bind quarantined Card sidecar bytes")
            snapshot_path = Path(str(snap["snapshot_uri"]))
            snapshot_recovery = Path(str(snap["card_sidecars_uri"])) / recovery_files[0].name
            self.assertFalse(snapshot_recovery.exists())
            self.assertTrue(store_module.verify_snapshot_manifest(snapshot_path)["ok"])

    def test_prune_compensates_crash_completed_adopted_sidecar_version(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="adopt-rollback",
                    summary="The default immutable state precedes a live immutable state.",
                    source_refs=[],
                    topics=["adopt-rollback"],
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])

            conn = connect(root)
            try:
                default_uri = str(
                    conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()["location_uri"]
                )
                default_path = resolve_stored_uri(root, default_uri)
                default_bytes = default_path.read_bytes()
                store_module.record_artifact(
                    conn,
                    kind="proof_input",
                    uri=default_uri,
                    sha256=hashlib.sha256(default_bytes).hexdigest(),
                    size_bytes=len(default_bytes),
                    source_type="adopt_rollback_default",
                    trust_level="local_generated",
                    immutable=True,
                )
                conn.execute(
                    "UPDATE cards SET summary = ?, updated_at = ? WHERE id = ?",
                    (
                        "The live immutable state is the rollback authority.",
                        store_module.utc_now(),
                        card_id,
                    ),
                )
                store_module.mark_card_sidecar_outbox(
                    conn,
                    [card_id],
                    reason="adopt_rollback_live",
                )
                conn.commit()
            finally:
                conn.close()
            self.assertTrue(sync_card_sidecars_after_commit(root, [card_id])["ok"])

            conn = connect(root)
            try:
                live_uri = str(
                    conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()["location_uri"]
                )
                live_path = resolve_stored_uri(root, live_uri)
                live_bytes = live_path.read_bytes()
                store_module.record_artifact(
                    conn,
                    kind="proof_input",
                    uri=live_uri,
                    sha256=hashlib.sha256(live_bytes).hexdigest(),
                    size_bytes=len(live_bytes),
                    source_type="adopt_rollback_live",
                    trust_level="local_generated",
                    immutable=True,
                )
                conn.commit()
                original = dict(
                    conn.execute(
                        "SELECT status, metadata_json, updated_at, location_uri "
                        "FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()
                )
            finally:
                conn.close()

            real_sync = worker_module.sync_card_sidecars_after_commit
            seeded_target: Path | None = None
            adopted_sync: dict[str, object] | None = None

            def seed_crash_completed_target(sync_root, card_ids):
                nonlocal seeded_target, adopted_sync
                if seeded_target is None:
                    seed_conn = connect(sync_root)
                    try:
                        row = seed_conn.execute(
                            "SELECT * FROM cards WHERE id = ?",
                            (card_id,),
                        ).fetchone()
                        payload = store_module._card_sidecar_payload_for_row(row)
                        artifact_index = store_module._immutable_artifact_path_index(
                            sync_root,
                            seed_conn,
                        )
                        target = store_module._card_sidecar_write_target(
                            sync_root,
                            seed_conn,
                            row,
                            payload,
                            artifact_index=artifact_index,
                        )
                        self.assertIsNotNone(target)
                        seeded_target = Path(target)
                        target_uri = store_module.continuum_uri(sync_root, seeded_target)
                        store_module._write_card_sidecar_write_intent(
                            sync_root,
                            card_id=card_id,
                            target_uri=target_uri,
                            expected_state_hash=str(payload["state_hash"]),
                        )
                        store_module.write_atomic_yaml(seeded_target, payload)
                    finally:
                        seed_conn.close()
                sync_result = real_sync(sync_root, card_ids)
                if adopted_sync is None:
                    adopted_sync = sync_result
                return sync_result

            real_report = worker_module.semantic_integrity_report
            report_calls = 0

            def fail_normal_postflight(*args, **kwargs):
                nonlocal report_calls
                report_calls += 1
                if report_calls == 3:
                    return {"ok": False, "failing": {"simulated_postflight": 1}}
                return real_report(*args, **kwargs)

            with patch.object(
                worker_module,
                "sync_card_sidecars_after_commit",
                side_effect=seed_crash_completed_target,
            ), patch.object(
                worker_module,
                "semantic_integrity_report",
                side_effect=fail_normal_postflight,
            ), self.assertRaisesRegex(RuntimeError, "Card mutations were rolled back"):
                prune_memory(root, topic="adopt-rollback", action="forget")

            self.assertIsNotNone(seeded_target)
            self.assertIsNotNone(adopted_sync)
            self.assertTrue(
                any(
                    candidate["uri"]
                    == store_module.continuum_uri(root, Path(seeded_target))
                    for candidate in adopted_sync["generated_sidecar_candidates"]
                ),
                adopted_sync,
            )
            conn = connect_existing(root)
            try:
                restored = dict(
                    conn.execute(
                        "SELECT status, metadata_json, updated_at, location_uri "
                        "FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()
                )
            finally:
                conn.close()
            self.assertEqual(restored, original)
            self.assertFalse(Path(seeded_target).exists())
            self.assertEqual(audit(root)["orphan_card_sidecars"], 0)
            self.assertTrue(semantic_integrity_report(root)["ok"])
            self.assertEqual(
                len(list((root / "catalog" / "cards").glob(".*.uncommitted"))),
                1,
            )

    def test_prune_compensation_uses_post_reconciliation_outbox_generation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="prune-reconciliation-generation",
                    summary="The original Card row must survive receipt finalization failure.",
                    source_refs=[],
                    topics=["prune-reconciliation-generation"],
                )
                conn.commit()
            finally:
                conn.close()
            initial_sync = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(initial_sync["ok"], initial_sync)

            conn = connect(root)
            try:
                original = dict(
                    conn.execute(
                        """
                        SELECT status, metadata_json, updated_at, location_uri
                        FROM cards WHERE id = ?
                        """,
                        (card_id,),
                    ).fetchone()
                )
                sidecar_path = resolve_stored_uri(root, str(original["location_uri"]))
                sidecar_bytes = sidecar_path.read_bytes()
                store_module.record_artifact(
                    conn,
                    kind="proof_input",
                    uri=str(original["location_uri"]),
                    sha256=hashlib.sha256(sidecar_bytes).hexdigest(),
                    size_bytes=len(sidecar_bytes),
                    source_type="prune_reconciliation_generation",
                    trust_level="local_generated",
                    immutable=True,
                )
                conn.commit()
            finally:
                conn.close()

            real_finish = store_module._finish_card_sidecar_write_intent
            finish_calls = 0

            def fail_first_receipt_finalization(*args, **kwargs):
                nonlocal finish_calls
                finish_calls += 1
                if finish_calls == 1:
                    raise OSError("forced first receipt finalization failure")
                return real_finish(*args, **kwargs)

            with (
                patch.object(
                    store_module,
                    "_finish_card_sidecar_write_intent",
                    side_effect=fail_first_receipt_finalization,
                ),
                self.assertRaisesRegex(RuntimeError, "Card mutations were rolled back"),
            ):
                prune_memory(
                    root,
                    topic="prune-reconciliation-generation",
                    action="archive",
                )

            conn = connect_existing(root)
            try:
                restored = dict(
                    conn.execute(
                        """
                        SELECT status, metadata_json, updated_at, location_uri
                        FROM cards WHERE id = ?
                        """,
                        (card_id,),
                    ).fetchone()
                )
            finally:
                conn.close()
            self.assertGreaterEqual(finish_calls, 2)
            self.assertEqual(restored, original)
            self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_prune_compensation_rejects_writer_after_sync_returns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="prune-post-sync-writer",
                    summary="A later outbox writer must survive failed prune compensation.",
                    source_refs=[],
                    topics=["prune-post-sync-writer"],
                )
                conn.commit()
            finally:
                conn.close()
            initial_sync = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(initial_sync["ok"], initial_sync)

            real_sync = worker_module.sync_card_sidecars_after_commit
            injected_generation: str | None = None

            def sync_then_intervene(sync_root, card_ids):
                nonlocal injected_generation
                result = real_sync(sync_root, card_ids)
                if injected_generation is None:
                    writer = connect(sync_root)
                    try:
                        store_module.mark_card_sidecar_outbox(
                            writer,
                            [card_id],
                            reason="independent_intervening_writer",
                        )
                        injected_generation = str(
                            writer.execute(
                                """
                                SELECT generation FROM card_sidecar_outbox
                                WHERE card_id = ?
                                """,
                                (card_id,),
                            ).fetchone()[0]
                        )
                        writer.commit()
                    finally:
                        writer.close()
                return result

            real_report = worker_module.semantic_integrity_report
            report_calls = 0

            def fail_postflight(*args, **kwargs):
                nonlocal report_calls
                report_calls += 1
                if report_calls == 3:
                    return {"ok": False, "failing": {"simulated_postflight": 1}}
                return real_report(*args, **kwargs)

            with (
                patch.object(
                    worker_module,
                    "sync_card_sidecars_after_commit",
                    side_effect=sync_then_intervene,
                ),
                patch.object(
                    worker_module,
                    "semantic_integrity_report",
                    side_effect=fail_postflight,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "were not rolled back because their committed state changed",
                ),
            ):
                prune_memory(
                    root,
                    topic="prune-post-sync-writer",
                    action="archive",
                )

            self.assertIsNotNone(injected_generation)
            conn = connect_existing(root)
            try:
                card_status = str(
                    conn.execute(
                        "SELECT status FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()[0]
                )
                outbox = conn.execute(
                    """
                    SELECT reason, generation FROM card_sidecar_outbox
                    WHERE card_id = ?
                    """,
                    (card_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(card_status, "archived")
            self.assertIsNotNone(outbox)
            self.assertEqual(outbox["reason"], "independent_intervening_writer")
            self.assertEqual(outbox["generation"], injected_generation)

    def test_prune_compensation_rejects_writer_during_sync_failure_gap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="prune-sync-failure-gap-writer",
                    summary="A writer between failure transactions must survive.",
                    source_refs=[],
                    topics=["prune-sync-failure-gap-writer"],
                )
                conn.commit()
            finally:
                conn.close()
            initial_sync = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(initial_sync["ok"], initial_sync)
            injected_generation: str | None = None

            class FailureGapError(RuntimeError):
                def __str__(self) -> str:
                    nonlocal injected_generation
                    if injected_generation is None:
                        writer = connect(root)
                        try:
                            store_module.mark_card_sidecar_outbox(
                                writer,
                                [card_id],
                                reason="independent_failure_gap_writer",
                            )
                            injected_generation = str(
                                writer.execute(
                                    """
                                    SELECT generation FROM card_sidecar_outbox
                                    WHERE card_id = ?
                                    """,
                                    (card_id,),
                                ).fetchone()[0]
                            )
                            writer.commit()
                        finally:
                            writer.close()
                    return "forced sync failure after rollback"

            with (
                patch.object(
                    store_module,
                    "sync_card_sidecar",
                    side_effect=FailureGapError(),
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "sidecar compensation evidence was unavailable",
                ),
            ):
                prune_memory(
                    root,
                    topic="prune-sync-failure-gap-writer",
                    action="archive",
                )

            self.assertIsNotNone(injected_generation)
            conn = connect_existing(root)
            try:
                status = str(
                    conn.execute(
                        "SELECT status FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()[0]
                )
                outbox = conn.execute(
                    """
                    SELECT reason, generation FROM card_sidecar_outbox
                    WHERE card_id = ?
                    """,
                    (card_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertEqual(status, "archived")
            self.assertIsNotNone(outbox)
            self.assertEqual(outbox["reason"], "independent_failure_gap_writer")
            self.assertEqual(outbox["generation"], injected_generation)

    def test_sidecar_failure_evidence_rejects_null_outbox_gap_writer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="sidecar-null-outbox-gap-writer",
                    summary="An absent outbox cannot authorize a later row.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            initial_sync = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(initial_sync["ok"], initial_sync)
            injected_generation: str | None = None

            class NullOutboxGapError(RuntimeError):
                def __str__(self) -> str:
                    nonlocal injected_generation
                    if injected_generation is None:
                        writer = connect(root)
                        try:
                            store_module.mark_card_sidecar_outbox(
                                writer,
                                [card_id],
                                reason="independent_null_outbox_writer",
                            )
                            injected_generation = str(
                                writer.execute(
                                    """
                                    SELECT generation FROM card_sidecar_outbox
                                    WHERE card_id = ?
                                    """,
                                    (card_id,),
                                ).fetchone()[0]
                            )
                            writer.commit()
                        finally:
                            writer.close()
                    return "forced null-outbox sync failure"

            with patch.object(
                store_module,
                "sync_card_sidecar",
                side_effect=NullOutboxGapError(),
            ):
                result = sync_card_sidecars_after_commit(root, [card_id])

            self.assertFalse(result["ok"], result)
            self.assertFalse(result["compensation_cas_complete"], result)
            self.assertEqual(result["compensation_cas_rows"], [])
            conn = connect_existing(root)
            try:
                outbox = conn.execute(
                    """
                    SELECT reason, generation FROM card_sidecar_outbox
                    WHERE card_id = ?
                    """,
                    (card_id,),
                ).fetchone()
            finally:
                conn.close()
            self.assertIsNotNone(outbox)
            self.assertEqual(outbox["reason"], "independent_null_outbox_writer")
            self.assertEqual(outbox["generation"], injected_generation)

    def test_sidecar_failure_evidence_rejects_location_gap_writer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="sidecar-location-gap-writer",
                    summary="A changed location cannot be adopted as sync evidence.",
                    source_refs=[],
                )
                conn.commit()
            finally:
                conn.close()
            initial_sync = sync_card_sidecars_after_commit(root, [card_id])
            self.assertTrue(initial_sync["ok"], initial_sync)
            independent_uri = "continuum://catalog/cards/independent-gap-writer.yaml"
            location_changed = False

            class LocationGapError(RuntimeError):
                def __str__(self) -> str:
                    nonlocal location_changed
                    if not location_changed:
                        writer = connect(root)
                        try:
                            writer.execute(
                                "UPDATE cards SET location_uri = ? WHERE id = ?",
                                (independent_uri, card_id),
                            )
                            writer.commit()
                            location_changed = True
                        finally:
                            writer.close()
                    return "forced location-gap sync failure"

            with patch.object(
                store_module,
                "sync_card_sidecar",
                side_effect=LocationGapError(),
            ):
                result = sync_card_sidecars_after_commit(root, [card_id])

            self.assertFalse(result["ok"], result)
            self.assertFalse(result["compensation_cas_complete"], result)
            self.assertEqual(result["compensation_cas_rows"], [])
            conn = connect_existing(root)
            try:
                location_uri = str(
                    conn.execute(
                        "SELECT location_uri FROM cards WHERE id = ?",
                        (card_id,),
                    ).fetchone()[0]
                )
            finally:
                conn.close()
            self.assertTrue(location_changed)
            self.assertEqual(location_uri, independent_uri)

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
