from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from continuum.core import workers as worker_module
from continuum.core.store import (
    audit,
    audit_event,
    connect,
    create_card,
    init_db,
    record_project_state,
)
from continuum.core.workers import detect_conflicts, resolve_conflict


def _create_decision(
    conn,
    *,
    root: Path,
    title: str,
    summary: str,
    session_id: str = "temporal-session",
    project_id: str = "continuum",
) -> str:
    return create_card(
        conn,
        root=root,
        card_type="decision",
        title=title,
        summary=summary,
        source_refs=[],
        visibility_scope="project",
        session_id=session_id,
        project_id=project_id,
    )


def _card_rows(root: Path, card_ids: list[str]) -> dict[str, dict]:
    conn = connect(root)
    try:
        placeholders = ",".join("?" for _ in card_ids)
        return {
            str(row["id"]): dict(row)
            for row in conn.execute(
                f"SELECT * FROM cards WHERE id IN ({placeholders}) ORDER BY id",
                card_ids,
            )
        }
    finally:
        conn.close()


def _assert_temporal_dag(test: unittest.TestCase, rows: dict[str, dict]) -> None:
    edges = {card_id: set() for card_id in rows}
    for card_id, row in rows.items():
        if row["superseded_by_card_id"]:
            edges[card_id].add(str(row["superseded_by_card_id"]))
        if row["supersedes_card_id"]:
            edges[str(row["supersedes_card_id"])].add(card_id)
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(card_id: str) -> None:
        test.assertNotIn(card_id, visiting, f"cycle reached {card_id}")
        if card_id in visited:
            return
        visiting.add(card_id)
        for successor in edges[card_id]:
            visit(successor)
        visiting.remove(card_id)
        visited.add(card_id)

    for card_id in sorted(edges):
        visit(card_id)


class TemporalConflictIntegrityTest(unittest.TestCase):
    def test_connected_three_card_group_is_stable_and_repeat_detection_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                alpha = _create_decision(
                    conn,
                    root=root,
                    title="Alpha Route",
                    summary="Use alpha routing for deployment.",
                )
                bridge = _create_decision(
                    conn,
                    root=root,
                    title="Alpha Beta Route",
                    summary="Do not use alpha beta routing for deployment.",
                )
                conn.commit()
            finally:
                conn.close()

            first = detect_conflicts(root, card_id=alpha)
            self.assertEqual(first["conflict_count"], 1, first)
            first_group = first["conflicts"][0]["conflict_group"]
            self.assertEqual(set(first["conflicts"][0]["card_ids"]), {alpha, bridge})

            # A later Card joins through bridge, not through alpha. The connected
            # component grows without changing its durable group identity.
            conn = connect(root)
            try:
                beta = _create_decision(
                    conn,
                    root=root,
                    title="Beta Route",
                    summary="Use beta routing for deployment.",
                )
                conn.commit()
            finally:
                conn.close()
            expanded = detect_conflicts(root, card_id=alpha)
            self.assertEqual(expanded["conflict_count"], 1, expanded)
            self.assertEqual(expanded["conflicts"][0]["conflict_group"], first_group)
            self.assertEqual(set(expanded["conflicts"][0]["card_ids"]), {alpha, bridge, beta})

            conn = connect(root)
            try:
                before_rows = {
                    str(row["id"]): (row["conflict_group"], row["updated_at"])
                    for row in conn.execute(
                        "SELECT id, conflict_group, updated_at FROM cards WHERE id IN (?, ?, ?)",
                        (alpha, bridge, beta),
                    )
                }
                before_audits = conn.execute(
                    "SELECT count(*) AS n FROM audit_events WHERE action = 'librarian_detect_conflict'"
                ).fetchone()["n"]
            finally:
                conn.close()

            repeated = detect_conflicts(root, card_id=bridge)

            conn = connect(root)
            try:
                after_rows = {
                    str(row["id"]): (row["conflict_group"], row["updated_at"])
                    for row in conn.execute(
                        "SELECT id, conflict_group, updated_at FROM cards WHERE id IN (?, ?, ?)",
                        (alpha, bridge, beta),
                    )
                }
                after_audits = conn.execute(
                    "SELECT count(*) AS n FROM audit_events WHERE action = 'librarian_detect_conflict'"
                ).fetchone()["n"]
            finally:
                conn.close()

            self.assertEqual(repeated["conflict_count"], 1, repeated)
            self.assertEqual(repeated["changed_card_count"], 0, repeated)
            self.assertEqual(repeated["conflicts"][0]["conflict_group"], first_group)
            self.assertEqual(after_rows, before_rows)
            self.assertEqual(after_audits, before_audits)

    def test_dismissal_suppresses_exact_component_but_content_change_reconsiders_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                first = _create_decision(
                    conn,
                    root=root,
                    title="Dismiss Route",
                    summary="Use dismiss routing for deployment.",
                )
                second = _create_decision(
                    conn,
                    root=root,
                    title="Dismiss Route",
                    summary="Do not use dismiss routing for deployment.",
                )
                conn.commit()
            finally:
                conn.close()
            detected = detect_conflicts(root, card_id=first)
            self.assertEqual(detected["conflict_count"], 1, detected)

            dismissed = resolve_conflict(root, card_id=first, action="dismiss")
            unchanged = detect_conflicts(root, card_id=first)

            self.assertTrue(dismissed["dismissal_fingerprint"])
            self.assertEqual(unchanged["conflict_count"], 0, unchanged)
            self.assertEqual(unchanged["suppressed_component_count"], 1, unchanged)
            rows = _card_rows(root, [first, second])
            self.assertTrue(all(row["conflict_group"] is None for row in rows.values()))
            for row in rows.values():
                self.assertNotIn(
                    "dismissed_conflict_components",
                    json.loads(row["metadata_json"]),
                )
            conn = connect(root)
            try:
                receipt = conn.execute(
                    "SELECT * FROM conflict_resolution_receipts WHERE id = ?",
                    (dismissed["resolution_id"],),
                ).fetchone()
                member_rows = conn.execute(
                    """
                    SELECT card_id, member_ordinal, member_binding_hash
                    FROM conflict_resolution_members
                    WHERE receipt_id = ?
                    ORDER BY member_ordinal
                    """,
                    (dismissed["resolution_id"],),
                ).fetchall()
            finally:
                conn.close()
            self.assertIsNotNone(receipt)
            assert receipt is not None
            self.assertEqual(receipt["action"], "dismiss")
            self.assertEqual(
                receipt["component_fingerprint"],
                dismissed["dismissal_fingerprint"],
            )
            self.assertEqual(receipt["selected_card_id"], first)
            self.assertEqual(receipt["member_count"], 2)
            self.assertEqual(
                [row["card_id"] for row in member_rows],
                sorted([first, second]),
            )
            self.assertEqual(
                [row["member_ordinal"] for row in member_rows],
                [0, 1],
            )
            self.assertTrue(
                all(row["member_binding_hash"] for row in member_rows)
            )

            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = ? WHERE id = ?",
                    ("Never use dismiss routing for deployment after review.", second),
                )
                conn.commit()
            finally:
                conn.close()

            reconsidered = detect_conflicts(root, card_id=first)

            self.assertEqual(reconsidered["conflict_count"], 1, reconsidered)
            self.assertEqual(reconsidered["suppressed_component_count"], 0, reconsidered)

    def test_matching_card_metadata_without_resolution_receipt_never_suppresses(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                first = _create_decision(
                    conn,
                    root=root,
                    title="Metadata-only Route",
                    summary="Use metadata-only routing for deployment.",
                )
                second = _create_decision(
                    conn,
                    root=root,
                    title="Metadata-only Route",
                    summary="Do not use metadata-only routing for deployment.",
                )
                conn.commit()
                rows = conn.execute(
                    "SELECT * FROM cards WHERE id IN (?, ?) ORDER BY id",
                    (first, second),
                ).fetchall()
                by_id = {str(row["id"]): row for row in rows}
                fingerprint = worker_module._conflict_component_fingerprint(
                    by_id,
                    [first, second],
                )
                metadata = {
                    "dismissed_conflict_components": [
                        {
                            "fingerprint": fingerprint,
                            "member_count": 2,
                            "dismissed_at": "caller-value",
                        }
                    ]
                }
                conn.execute(
                    "UPDATE cards SET metadata_json = ? WHERE id = ?",
                    (json.dumps(metadata), first),
                )
                conn.commit()
            finally:
                conn.close()

            detected = detect_conflicts(root, card_id=first)

            self.assertEqual(detected["conflict_count"], 1, detected)
            self.assertEqual(detected["suppressed_component_count"], 0, detected)
            conn = connect(root)
            try:
                receipt_count = conn.execute(
                    "SELECT count(*) AS n FROM conflict_resolution_receipts"
                ).fetchone()["n"]
            finally:
                conn.close()
            self.assertEqual(receipt_count, 0)

    def test_dismissal_receipt_is_exact_to_audit_and_complete_member_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                first = _create_decision(
                    conn,
                    root=root,
                    title="Exact Receipt Route",
                    summary="Use exact receipt routing for deployment.",
                )
                second = _create_decision(
                    conn,
                    root=root,
                    title="Exact Receipt Route",
                    summary="Do not use exact receipt routing for deployment.",
                )
                conn.commit()
            finally:
                conn.close()
            detect_conflicts(root, card_id=first)
            dismissed = resolve_conflict(root, card_id=first, action="dismiss")

            conn = connect(root)
            try:
                receipt = conn.execute(
                    "SELECT audit_event_id FROM conflict_resolution_receipts WHERE id = ?",
                    (dismissed["resolution_id"],),
                ).fetchone()
                assert receipt is not None
                audit_payload = json.loads(
                    conn.execute(
                        "SELECT payload_json FROM audit_events WHERE id = ?",
                        (receipt["audit_event_id"],),
                    ).fetchone()["payload_json"]
                )
                audit_payload["member_count"] = 99
                conn.execute(
                    "UPDATE audit_events SET payload_json = ? WHERE id = ?",
                    (json.dumps(audit_payload), receipt["audit_event_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            mismatched_audit = detect_conflicts(root, card_id=first)
            self.assertEqual(mismatched_audit["conflict_count"], 1, mismatched_audit)
            self.assertEqual(
                mismatched_audit["suppressed_component_count"],
                0,
                mismatched_audit,
            )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                first = _create_decision(
                    conn,
                    root=root,
                    title="Expanded Receipt Route",
                    summary="Use expanded receipt routing for deployment.",
                )
                second = _create_decision(
                    conn,
                    root=root,
                    title="Expanded Receipt Route",
                    summary="Do not use expanded receipt routing for deployment.",
                )
                conn.commit()
            finally:
                conn.close()
            detect_conflicts(root, card_id=first)
            resolve_conflict(root, card_id=first, action="dismiss")
            conn = connect(root)
            try:
                third = _create_decision(
                    conn,
                    root=root,
                    title="Expanded Receipt Route",
                    summary="Never disable expanded receipt routing for deployment.",
                )
                conn.commit()
            finally:
                conn.close()

            expanded = detect_conflicts(root, card_id=first)
            self.assertEqual(expanded["conflict_count"], 1, expanded)
            self.assertEqual(expanded["suppressed_component_count"], 0, expanded)
            self.assertEqual(
                set(expanded["conflicts"][0]["card_ids"]),
                {first, second, third},
            )

    def test_resolution_receipt_failure_rolls_back_card_and_audit_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                first = _create_decision(
                    conn,
                    root=root,
                    title="Rollback Receipt Route",
                    summary="Use rollback receipt routing for deployment.",
                )
                second = _create_decision(
                    conn,
                    root=root,
                    title="Rollback Receipt Route",
                    summary="Do not use rollback receipt routing for deployment.",
                )
                conn.commit()
            finally:
                conn.close()
            detect_conflicts(root, card_id=first)
            before = _card_rows(root, [first, second])
            original_binding_hash = worker_module._conflict_member_binding_hash
            binding_calls = 0

            def fail_after_first_member(card):
                nonlocal binding_calls
                binding_calls += 1
                if binding_calls == 2:
                    raise RuntimeError("receipt member write failed")
                return original_binding_hash(card)

            with (
                patch.object(
                    worker_module,
                    "_conflict_member_binding_hash",
                    side_effect=fail_after_first_member,
                ),
                self.assertRaisesRegex(RuntimeError, "receipt member write failed"),
            ):
                resolve_conflict(root, card_id=first, action="dismiss")

            self.assertEqual(binding_calls, 2)
            self.assertEqual(_card_rows(root, [first, second]), before)
            conn = connect(root)
            try:
                receipt_count = conn.execute(
                    "SELECT count(*) AS n FROM conflict_resolution_receipts"
                ).fetchone()["n"]
                member_count = conn.execute(
                    "SELECT count(*) AS n FROM conflict_resolution_members"
                ).fetchone()["n"]
                resolution_audit_count = conn.execute(
                    """
                    SELECT count(*) AS n FROM audit_events
                    WHERE action = 'librarian_resolve_conflict'
                    """
                ).fetchone()["n"]
            finally:
                conn.close()
            self.assertEqual(receipt_count, 0)
            self.assertEqual(member_count, 0)
            self.assertEqual(resolution_audit_count, 0)

    def test_unscoped_limit_one_progresses_across_ungrouped_components(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                amber_use = _create_decision(
                    conn,
                    root=root,
                    title="Amber Valve",
                    summary="Use amber valves for deployment.",
                )
                amber_no = _create_decision(
                    conn,
                    root=root,
                    title="Amber Valve",
                    summary="Do not use amber valves for deployment.",
                )
                cobalt_use = _create_decision(
                    conn,
                    root=root,
                    title="Cobalt Latch",
                    summary="Use cobalt latches for deployment.",
                )
                cobalt_no = _create_decision(
                    conn,
                    root=root,
                    title="Cobalt Latch",
                    summary="Do not use cobalt latches for deployment.",
                )
                conn.commit()
            finally:
                conn.close()

            first_pass = detect_conflicts(root, limit=1)
            second_pass = detect_conflicts(root, limit=1)

            self.assertEqual(first_pass["conflict_count"], 1, first_pass)
            self.assertEqual(second_pass["conflict_count"], 1, second_pass)
            first_ids = set(first_pass["conflicts"][0]["card_ids"])
            second_ids = set(second_pass["conflicts"][0]["card_ids"])
            expected_pairs = [{amber_use, amber_no}, {cobalt_use, cobalt_no}]
            self.assertIn(first_ids, expected_pairs)
            self.assertIn(second_ids, expected_pairs)
            self.assertNotEqual(first_ids, second_ids)

    def test_dense_scan_obeys_every_global_work_budget_and_reports_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                for index in range(40):
                    _create_decision(
                        conn,
                        root=root,
                        title="Dense bounded route",
                        summary=(
                            f"Do not use dense route variant {index}."
                            if index % 2
                            else f"Use dense route variant {index}."
                        ),
                    )
                conn.commit()
                schema_before = int(conn.execute("PRAGMA user_version").fetchone()[0])
                tables_before = {
                    str(row["name"])
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
            finally:
                conn.close()

            result = detect_conflicts(
                root,
                limit=1,
                candidate_card_limit=12,
                comparison_limit=15,
                component_member_limit=4,
                mutation_limit=3,
                transaction_seconds=1.0,
            )

            limits = result["work_budget"]["limits"]
            used = result["work_budget"]["used"]
            exhausted = result["work_budget"]["exhausted"]
            for dimension in (
                "candidate_cards",
                "comparisons",
                "component_members",
                "card_mutations",
                "transaction_seconds",
            ):
                self.assertLessEqual(used[dimension], limits[dimension], result)
            # The comparison cap shrinks the candidate page to a size whose
            # complete pair scan is guaranteed to fit (6 choose 2 == 15).
            self.assertEqual(limits["candidate_cards"], 6)
            self.assertEqual(used["comparisons"], 15)
            self.assertTrue(exhausted["candidate_cards"], result)
            self.assertTrue(exhausted["component_members"], result)
            self.assertTrue(result["partial"], result)
            self.assertTrue(result["has_more"], result)
            self.assertTrue(result["continuation"]["required"], result)
            self.assertEqual(
                result["continuation"]["strategy"],
                "circular_rowid_cursor",
            )
            self.assertIn(
                "component_members",
                result["continuation"]["budget_exhausted"],
            )
            self.assertTrue(result["continuation"]["requires_larger_budget"])

            conn = connect(root)
            try:
                cursor_events = int(
                    conn.execute(
                        """
                        SELECT count(*) AS n
                        FROM audit_events
                        WHERE action = 'librarian_conflict_scan_cursor'
                        """
                    ).fetchone()["n"]
                )
                schema_after = int(conn.execute("PRAGMA user_version").fetchone()[0])
                tables_after = {
                    str(row["name"])
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
            finally:
                conn.close()
            self.assertEqual(cursor_events, 1)
            self.assertEqual(schema_after, schema_before)
            self.assertEqual(tables_after, tables_before)
            self.assertIn("audit_events", tables_after)

    def test_conflict_candidate_read_precedes_writer_and_closure_queries_use_indexes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                first = _create_decision(
                    conn,
                    root=root,
                    title="Indexed closure route",
                    summary="Use the indexed closure route.",
                )
                second = _create_decision(
                    conn,
                    root=root,
                    title="Indexed closure route",
                    summary="Do not use the indexed closure route.",
                )
                conn.execute(
                    "UPDATE cards SET conflict_group = 'indexed-group' WHERE id IN (?, ?)",
                    (first, second),
                )
                conn.commit()
            finally:
                conn.close()

            candidate_transactions: list[bool] = []
            original_loader = worker_module._bounded_conflict_rows

            def observe_candidate_phase(conn, **kwargs):
                candidate_transactions.append(bool(conn.in_transaction))
                return original_loader(conn, **kwargs)

            with patch.object(
                worker_module,
                "_bounded_conflict_rows",
                side_effect=observe_candidate_phase,
            ):
                result = detect_conflicts(root, limit=1)

            self.assertEqual(candidate_transactions, [False])
            self.assertTrue(result["index_setup"]["outside_scan_budget"])
            conn = connect(root)
            try:
                group_plan = " ".join(
                    str(row["detail"])
                    for row in conn.execute(
                        """
                        EXPLAIN QUERY PLAN
                        SELECT conflict_group, count(*) AS n
                        FROM cards
                        WHERE conflict_group IN (?)
                        GROUP BY conflict_group
                        """,
                        ("indexed-group",),
                    )
                )
                title_plan = " ".join(
                    str(row["detail"])
                    for row in conn.execute(
                        """
                        EXPLAIN QUERY PLAN
                        SELECT rowid AS card_rowid, *
                        FROM cards
                        WHERE lower(trim(title)) = ?
                          AND coalesce(visibility_scope, 'session') = 'project'
                          AND coalesce(project_id, '') = ?
                        ORDER BY coalesce(session_id, ''), rowid
                        LIMIT 9
                        """,
                        ("indexed closure route", "continuum"),
                    )
                )
                optional_plan = " ".join(
                    str(row["detail"])
                    for row in conn.execute(
                        """
                        EXPLAIN QUERY PLAN
                        SELECT rowid AS card_rowid, *
                        FROM cards
                        WHERE coalesce(visibility_scope, 'session') = 'project'
                          AND coalesce(project_id, '') = ?
                          AND rowid > 0
                          AND id NOT IN (?)
                        ORDER BY coalesce(session_id, ''), rowid
                        LIMIT 9
                        """,
                        ("continuum", first),
                    )
                )
            finally:
                conn.close()
            self.assertIn("idx_cards_conflict_group", group_plan)
            self.assertIn(
                "idx_cards_conflict_title_boundary_normalized",
                title_plan,
            )
            self.assertNotIn("TEMP B-TREE", title_plan)
            self.assertIn("idx_cards_conflict_boundary", optional_plan)
            self.assertNotIn("TEMP B-TREE", optional_plan)

    def test_unscoped_bounded_scan_resumes_from_durable_fair_cursor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                for index in range(24):
                    _create_decision(
                        conn,
                        root=root,
                        title=f"Unique cursor route {index:02d}",
                        summary=f"Use unique cursor route variant {index:02d}.",
                    )
                conn.commit()
            finally:
                conn.close()

            kwargs = {
                "limit": 1,
                "candidate_card_limit": 8,
                "comparison_limit": 28,
                "component_member_limit": 8,
                "mutation_limit": 8,
                "transaction_seconds": 1.0,
            }
            first = detect_conflicts(root, **kwargs)
            second = detect_conflicts(root, **kwargs)
            third = detect_conflicts(root, **kwargs)

            self.assertEqual(first["scan"]["cursor"], 0)
            self.assertEqual(second["scan"]["cursor"], first["scan"]["next_cursor"])
            self.assertEqual(third["scan"]["cursor"], second["scan"]["next_cursor"])
            self.assertGreater(first["scan"]["next_cursor"], 0)
            self.assertGreater(
                second["scan"]["next_cursor"],
                first["scan"]["next_cursor"],
            )
            self.assertGreater(
                third["scan"]["next_cursor"],
                second["scan"]["next_cursor"],
            )
            for result in (first, second, third):
                self.assertLessEqual(
                    result["work_budget"]["used"]["candidate_cards"],
                    result["work_budget"]["limits"]["candidate_cards"],
                )
                self.assertTrue(result["continuation"]["required"], result)
                self.assertFalse(
                    result["continuation"]["requires_larger_budget"],
                    result,
                )

    def test_targeted_incomplete_group_requires_larger_budget_without_false_progress(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                target = _create_decision(
                    conn,
                    root=root,
                    title="Wide durable group",
                    summary="Use the wide durable group route.",
                )
                peer_one = _create_decision(
                    conn,
                    root=root,
                    title="Wide durable group",
                    summary="Do not use the wide durable group route.",
                )
                peer_two = _create_decision(
                    conn,
                    root=root,
                    title="Wide durable group",
                    summary="Never use the wide durable group route.",
                )
                conn.execute(
                    """
                    UPDATE cards SET conflict_group = 'durable-wide-group'
                    WHERE id IN (?, ?, ?)
                    """,
                    (target, peer_one, peer_two),
                )
                for index in range(5):
                    _create_decision(
                        conn,
                        root=root,
                        title=f"Targeted cursor noise {index}",
                        summary=f"Use targeted cursor noise {index}.",
                    )
                conn.commit()
            finally:
                conn.close()

            kwargs = {
                "card_id": target,
                "limit": 1,
                "candidate_card_limit": 2,
                "comparison_limit": 1,
                "component_member_limit": 2,
                "mutation_limit": 2,
                "transaction_seconds": 1.0,
            }
            first = detect_conflicts(root, **kwargs)
            second = detect_conflicts(root, **kwargs)
            third = detect_conflicts(root, **kwargs)

            self.assertEqual(first["scan"]["cursor"], 0)
            self.assertEqual(second["scan"]["cursor"], 0)
            self.assertEqual(third["scan"]["cursor"], 0)
            self.assertEqual(first["scan"]["next_cursor"], 0)
            self.assertEqual(second["scan"]["next_cursor"], 0)
            self.assertEqual(first["changed_card_count"], 0, first)
            self.assertEqual(second["changed_card_count"], 0, second)
            self.assertGreaterEqual(first["deferred_components"], 1, first)
            self.assertEqual(
                first["continuation"]["strategy"],
                "targeted_rowid_cursor",
            )
            self.assertTrue(first["continuation"]["requires_larger_budget"], first)
            self.assertEqual(
                first["continuation"]["required_candidate_cards_lower_bound"],
                3,
            )
            rows = _card_rows(root, [target, peer_one, peer_two])
            self.assertEqual(
                {rows[card_id]["conflict_group"] for card_id in rows},
                {"durable-wide-group"},
            )

    def test_targeted_exact_title_over_cap_reports_larger_budget_without_livelock(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                target = _create_decision(
                    conn,
                    root=root,
                    title="Three-card targeted closure",
                    summary="Use the three-card targeted closure.",
                )
                peer_one = _create_decision(
                    conn,
                    root=root,
                    title="Three-card targeted closure",
                    summary="Do not use the three-card targeted closure.",
                )
                peer_two = _create_decision(
                    conn,
                    root=root,
                    title="Three-card targeted closure",
                    summary="Never use the three-card targeted closure.",
                )
                audit_event(
                    conn,
                    action="librarian_conflict_scan_cursor",
                    target_type="conflict_scan",
                    target_id=target,
                    payload={
                        "schema": "continuum.conflict_scan_cursor.v1",
                        "next_rowid": 99,
                    },
                )
                conn.commit()
            finally:
                conn.close()

            kwargs = {
                "card_id": target,
                "limit": 1,
                "candidate_card_limit": 2,
                "comparison_limit": 1,
                "component_member_limit": 2,
                "mutation_limit": 2,
                "transaction_seconds": 1.0,
            }
            first = detect_conflicts(root, **kwargs)
            second = detect_conflicts(root, **kwargs)

            for result in (first, second):
                self.assertEqual(result["conflict_count"], 0, result)
                self.assertEqual(result["changed_card_count"], 0, result)
                self.assertEqual(result["scan"]["cursor"], 0, result)
                self.assertEqual(result["scan"]["next_cursor"], 0, result)
                self.assertTrue(
                    result["continuation"]["requires_larger_budget"],
                    result,
                )
                self.assertEqual(
                    result["continuation"][
                        "required_candidate_cards_lower_bound"
                    ],
                    3,
                )
            rows = _card_rows(root, [target, peer_one, peer_two])
            self.assertEqual(
                {rows[card_id]["conflict_group"] for card_id in rows},
                {None},
            )
            conn = connect(root)
            try:
                cursor_audits = int(
                    conn.execute(
                        """
                        SELECT count(*) AS n
                        FROM audit_events
                        WHERE action = 'librarian_conflict_scan_cursor'
                          AND target_id = ?
                        """,
                        (target,),
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(cursor_audits, 1)

    def test_targeted_title_expansion_is_not_starved_by_other_projects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                noise_ids = [
                    _create_decision(
                        conn,
                        root=root,
                        title="Shared setting",
                        summary=f"Use unrelated project setting {index}.",
                        session_id=f"noise-session-{index}",
                        project_id=f"noise-project-{index}",
                    )
                    for index in range(20)
                ]
                target_ids = [
                    _create_decision(
                        conn,
                        root=root,
                        title="Shared setting",
                        summary=f"Use contradictory target setting {index}.",
                        session_id="target-session",
                        project_id="target-project",
                    )
                    for index in range(5)
                ]
                conn.commit()
            finally:
                conn.close()

            kwargs = {
                "card_id": target_ids[0],
                "limit": 1,
                "candidate_card_limit": 8,
                "comparison_limit": 28,
                "component_member_limit": 8,
                "mutation_limit": 8,
                "transaction_seconds": 1.0,
            }
            results = [detect_conflicts(root, **kwargs) for _ in range(8)]

            self.assertEqual(results[0]["conflict_count"], 1, results[0])
            self.assertEqual(results[0]["changed_card_count"], 5, results[0])
            for result in results:
                self.assertFalse(
                    result["continuation"]["requires_larger_budget"],
                    result,
                )
                self.assertEqual(
                    result["continuation"][
                        "required_candidate_cards_lower_bound"
                    ],
                    0,
                )
                self.assertLessEqual(
                    result["work_budget"]["used"]["candidate_cards"],
                    8,
                )
            target_rows = _card_rows(root, target_ids)
            target_groups = {
                target_rows[card_id]["conflict_group"] for card_id in target_ids
            }
            self.assertEqual(len(target_groups), 1)
            self.assertNotIn(None, target_groups)
            noise_rows = _card_rows(root, noise_ids)
            self.assertEqual(
                {noise_rows[card_id]["conflict_group"] for card_id in noise_ids},
                {None},
            )

    def test_targeted_anchor_closure_equal_to_cap_displaces_interleaved_noise(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            component_ids: list[str] = []
            try:
                component_ids.append(
                    _create_decision(
                        conn,
                        root=root,
                        title="Exact-cap anchor closure",
                        summary="Use the exact-cap anchor closure.",
                    )
                )
                for peer_index in range(7):
                    for noise_index in range(3):
                        _create_decision(
                            conn,
                            root=root,
                            title=f"Interleaved target noise {peer_index}-{noise_index}",
                            summary="Use unrelated same-project noise.",
                        )
                    component_ids.append(
                        _create_decision(
                            conn,
                            root=root,
                            title="Exact-cap anchor closure",
                            summary=f"Do not use exact-cap route {peer_index}.",
                        )
                    )
                conn.commit()
            finally:
                conn.close()

            result = detect_conflicts(
                root,
                card_id=component_ids[0],
                limit=1,
                candidate_card_limit=8,
                comparison_limit=28,
                component_member_limit=8,
                mutation_limit=8,
                transaction_seconds=1.0,
            )

            self.assertEqual(result["conflict_count"], 0, result)
            self.assertEqual(result["changed_card_count"], 0, result)
            self.assertTrue(result["continuation"]["required"], result)
            self.assertTrue(
                result["continuation"]["requires_larger_budget"], result
            )
            self.assertTrue(
                result["continuation"]["optional_fuzzy_evidence_deferred"],
                result,
            )
            self.assertEqual(
                result["continuation"]["required_candidate_cards_lower_bound"],
                9,
            )
            rows = _card_rows(root, component_ids)
            groups = {rows[card_id]["conflict_group"] for card_id in component_ids}
            self.assertEqual(groups, {None})

    def test_unscoped_anchor_eventually_closes_exact_cap_component_amid_noise(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            component_ids: list[str] = []
            try:
                for noise_index in range(3):
                    _create_decision(
                        conn,
                        root=root,
                        title=f"Leading global noise {noise_index}",
                        summary="Use leading unrelated global-page noise.",
                    )
                component_ids.append(
                    _create_decision(
                        conn,
                        root=root,
                        title="Global exact-cap anchor closure",
                        summary="Use the global exact-cap anchor closure.",
                    )
                )
                for peer_index in range(7):
                    for noise_index in range(3):
                        _create_decision(
                            conn,
                            root=root,
                            title=f"Interleaved global noise {peer_index}-{noise_index}",
                            summary="Use unrelated global-page noise.",
                        )
                    component_ids.append(
                        _create_decision(
                            conn,
                            root=root,
                            title="Global exact-cap anchor closure",
                            summary=f"Do not use global exact-cap route {peer_index}.",
                        )
                    )
                conn.commit()
            finally:
                conn.close()

            kwargs = {
                "limit": 1,
                "candidate_card_limit": 8,
                "comparison_limit": 28,
                "component_member_limit": 8,
                "mutation_limit": 8,
                "transaction_seconds": 1.0,
            }
            results = [detect_conflicts(root, **kwargs) for _ in range(8)]

            resolving = [result for result in results if result["conflict_count"]]
            self.assertTrue(resolving, results)
            self.assertEqual(
                set(resolving[0]["conflicts"][0]["card_ids"]),
                set(component_ids),
            )
            rows = _card_rows(root, component_ids)
            groups = {rows[card_id]["conflict_group"] for card_id in component_ids}
            self.assertEqual(len(groups), 1)
            self.assertNotIn(None, groups)

    def test_targeted_optional_noise_does_not_create_endless_cursor_cycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            component_ids: list[str] = []
            try:
                for index in range(8):
                    component_ids.append(
                        _create_decision(
                            conn,
                            root=root,
                            title="Targeted optional-cycle closure",
                            summary=(
                                "Use the targeted optional-cycle closure."
                                if index == 0
                                else f"Do not use optional-cycle route {index}."
                            ),
                        )
                    )
                    for noise_index in range(3):
                        _create_decision(
                            conn,
                            root=root,
                            title=f"Optional-cycle noise {index}-{noise_index}",
                            summary="Use unrelated optional-cycle noise.",
                        )
                conn.commit()
            finally:
                conn.close()

            kwargs = {
                "card_id": component_ids[0],
                "limit": 1,
                "candidate_card_limit": 9,
                "comparison_limit": 36,
                "component_member_limit": 9,
                "mutation_limit": 9,
                "transaction_seconds": 1.0,
            }
            first = detect_conflicts(root, **kwargs)
            second = detect_conflicts(root, **kwargs)

            self.assertEqual(first["conflict_count"], 0, first)
            self.assertEqual(first["changed_card_count"], 0, first)
            for result in (first, second):
                self.assertTrue(result["continuation"]["required"], result)
                self.assertTrue(
                    result["continuation"]["requires_larger_budget"], result
                )
                self.assertTrue(
                    result["continuation"]["optional_fuzzy_evidence_deferred"],
                    result,
                )
                self.assertEqual(result["scan"]["next_cursor"], 0, result)
                self.assertEqual(
                    result["continuation"][
                        "required_candidate_cards_lower_bound"
                    ],
                    10,
                )
            rows = _card_rows(root, component_ids)
            groups = {rows[card_id]["conflict_group"] for card_id in component_ids}
            self.assertEqual(groups, {None})

    def test_targeted_exact_subset_does_not_false_complete_before_fuzzy_peer(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                alpha = _create_decision(
                    conn,
                    root=root,
                    title="Alpha Route",
                    summary="Use alpha routing for deployment.",
                )
                exact_peer = _create_decision(
                    conn,
                    root=root,
                    title="Alpha Route",
                    summary="Do not use alpha routing for deployment.",
                )
                fuzzy_peer = _create_decision(
                    conn,
                    root=root,
                    title="Alpha Beta Route",
                    summary="Never use alpha beta routing for deployment.",
                )
                _create_decision(
                    conn,
                    root=root,
                    title="Noise Route",
                    summary="Keep unrelated noise unchanged.",
                )
                conn.commit()
            finally:
                conn.close()

            bounded = detect_conflicts(
                root,
                card_id=alpha,
                limit=1,
                candidate_card_limit=2,
                comparison_limit=1,
                component_member_limit=2,
                mutation_limit=2,
                transaction_seconds=1.0,
            )

            self.assertEqual(bounded["conflict_count"], 0, bounded)
            self.assertEqual(bounded["changed_card_count"], 0, bounded)
            self.assertTrue(bounded["continuation"]["required"], bounded)
            self.assertTrue(
                bounded["continuation"]["requires_larger_budget"], bounded
            )
            self.assertEqual(
                bounded["continuation"]["required_candidate_cards_lower_bound"],
                3,
            )
            self.assertEqual(
                {row["conflict_group"] for row in _card_rows(root, [alpha, exact_peer, fuzzy_peer]).values()},
                {None},
            )

            expanded = detect_conflicts(
                root,
                card_id=alpha,
                limit=1,
                candidate_card_limit=4,
                comparison_limit=6,
                component_member_limit=4,
                mutation_limit=4,
                transaction_seconds=1.0,
            )

            self.assertEqual(expanded["conflict_count"], 1, expanded)
            self.assertEqual(
                set(expanded["conflicts"][0]["card_ids"]),
                {alpha, exact_peer, fuzzy_peer},
            )

    def test_targeted_fuzzy_overflow_requests_larger_single_pass_then_resolves(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                target = _create_decision(
                    conn,
                    root=root,
                    title="Alpha Route",
                    summary="Use alpha routing for deployment.",
                )
                peer = _create_decision(
                    conn,
                    root=root,
                    title="Alpha Beta Route",
                    summary="Do not use alpha beta routing for deployment.",
                )
                for index in range(20):
                    _create_decision(
                        conn,
                        root=root,
                        title=f"Unrelated fuzzy overflow noise {index}",
                        summary=f"Keep unrelated item {index} unchanged.",
                    )
                conn.commit()
            finally:
                conn.close()

            bounded = detect_conflicts(
                root,
                card_id=target,
                limit=1,
                candidate_card_limit=8,
                comparison_limit=28,
                component_member_limit=8,
                mutation_limit=8,
                transaction_seconds=1.0,
            )

            self.assertEqual(bounded["conflict_count"], 0, bounded)
            self.assertEqual(bounded["changed_card_count"], 0, bounded)
            self.assertTrue(bounded["continuation"]["required"], bounded)
            self.assertTrue(
                bounded["continuation"]["requires_larger_budget"], bounded
            )
            self.assertTrue(
                bounded["continuation"]["optional_fuzzy_evidence_deferred"],
                bounded,
            )
            self.assertEqual(
                bounded["continuation"]["required_candidate_cards_lower_bound"],
                9,
            )
            self.assertEqual(bounded["scan"]["next_cursor"], 0, bounded)

            expanded = detect_conflicts(
                root,
                card_id=target,
                limit=1,
                candidate_card_limit=32,
                comparison_limit=496,
                component_member_limit=32,
                mutation_limit=32,
                transaction_seconds=1.0,
            )

            self.assertEqual(expanded["conflict_count"], 1, expanded)
            self.assertIn(target, expanded["conflicts"][0]["card_ids"])
            self.assertIn(peer, expanded["conflicts"][0]["card_ids"])
            self.assertFalse(expanded["continuation"]["required"], expanded)

    def test_unscoped_oversized_anchor_advances_and_requests_larger_budget(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            card_ids: list[str] = []
            try:
                for index in range(3):
                    card_ids.append(
                        _create_decision(
                            conn,
                            root=root,
                            title="Oversized global closure",
                            summary=(
                                "Use the oversized global closure."
                                if index == 0
                                else f"Do not use oversized global route {index}."
                            ),
                        )
                    )
                conn.commit()
            finally:
                conn.close()

            kwargs = {
                "limit": 1,
                "candidate_card_limit": 2,
                "comparison_limit": 1,
                "component_member_limit": 2,
                "mutation_limit": 2,
                "transaction_seconds": 1.0,
            }
            first = detect_conflicts(root, **kwargs)
            second = detect_conflicts(root, **kwargs)

            for result in (first, second):
                self.assertEqual(result["changed_card_count"], 0, result)
                self.assertTrue(
                    result["continuation"]["requires_larger_budget"], result
                )
                self.assertEqual(
                    result["continuation"][
                        "required_candidate_cards_lower_bound"
                    ],
                    3,
                )
                self.assertFalse(
                    result["continuation"]["manual_review_required"], result
                )
            self.assertGreater(first["scan"]["next_cursor"], 0)
            self.assertGreater(
                second["scan"]["next_cursor"],
                first["scan"]["next_cursor"],
            )
            rows = _card_rows(root, card_ids)
            self.assertEqual(
                {rows[card_id]["conflict_group"] for card_id in card_ids},
                {None},
            )

    def test_component_above_hard_candidate_cap_requires_manual_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                for index in range(worker_module.MAX_CONFLICT_CANDIDATE_CARDS + 1):
                    _create_decision(
                        conn,
                        root=root,
                        title="Beyond automatic conflict closure",
                        summary=f"Use beyond-cap route {index}.",
                    )
                conn.commit()
            finally:
                conn.close()

            result = detect_conflicts(
                root,
                limit=1,
                candidate_card_limit=worker_module.MAX_CONFLICT_CANDIDATE_CARDS,
                comparison_limit=worker_module.MAX_CONFLICT_COMPARISONS,
                component_member_limit=worker_module.MAX_CONFLICT_COMPONENT_MEMBERS,
                mutation_limit=worker_module.MAX_CONFLICT_CARD_MUTATIONS,
                transaction_seconds=worker_module.MAX_CONFLICT_TRANSACTION_SECONDS,
            )

            self.assertEqual(result["changed_card_count"], 0, result)
            self.assertTrue(result["continuation"]["requires_larger_budget"], result)
            self.assertTrue(result["continuation"]["manual_review_required"], result)
            self.assertEqual(
                result["continuation"]["manual_review_reason"],
                "component_exceeds_automatic_candidate_limit",
            )
            self.assertEqual(
                result["continuation"]["required_candidate_cards_lower_bound"],
                worker_module.MAX_CONFLICT_CANDIDATE_CARDS + 1,
            )

    def test_targeted_scan_rejects_candidate_budget_that_cannot_advance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                target = _create_decision(
                    conn,
                    root=root,
                    title="Targeted minimum budget",
                    summary="Use an advancing targeted conflict page.",
                )
                _create_decision(
                    conn,
                    root=root,
                    title="Targeted minimum budget",
                    summary="Do not use a stalled targeted conflict page.",
                )
                conn.commit()
            finally:
                conn.close()

            with self.assertRaisesRegex(
                ValueError,
                "targeted conflict scans require candidate_card_limit >= 2",
            ):
                detect_conflicts(
                    root,
                    card_id=target,
                    limit=1,
                    candidate_card_limit=1,
                )

    def test_targeted_structural_deferral_never_returns_nonactionable_cursor(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                target = _create_decision(
                    conn,
                    root=root,
                    title="Structural deferral route",
                    summary="Use the structural deferral route.",
                )
                _create_decision(
                    conn,
                    root=root,
                    title="Structural deferral route",
                    summary="Do not use the structural deferral route.",
                )
                conn.commit()
            finally:
                conn.close()

            with (
                patch.object(
                    worker_module,
                    "_complete_conflict_boundaries",
                    return_value=set(),
                ),
                patch.object(
                    worker_module,
                    "_complete_conflict_titles",
                    return_value=set(),
                ),
            ):
                result = detect_conflicts(
                    root,
                    card_id=target,
                    limit=1,
                    candidate_card_limit=4,
                    comparison_limit=6,
                    component_member_limit=4,
                    mutation_limit=4,
                    transaction_seconds=1.0,
                )

            self.assertTrue(result["continuation"]["required"], result)
            self.assertEqual(result["continuation"]["next_cursor"], 0, result)
            self.assertTrue(
                result["continuation"]["requires_larger_budget"], result
            )
            self.assertEqual(
                result["continuation"]["required_candidate_cards_lower_bound"],
                5,
            )

    def test_closure_probe_work_does_not_scale_with_total_boundary_size(self) -> None:
        def measured_vm_steps(card_count: int) -> int:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                init_db(root)
                conn = connect(root)
                try:
                    now = "2026-01-01T00:00:00+00:00"
                    conn.executemany(
                        """
                        INSERT INTO cards(
                            id, card_type, title, summary, status,
                            source_refs_json, entities_json, topics_json,
                            decisions_json, open_tasks_json, metadata_json,
                            visibility_scope, project_id, session_id,
                            created_at, updated_at
                        )
                        VALUES(?, 'note', ?, ?, 'active', '[]', '[]', '[]',
                               '[]', '[]', '{}', 'project', 'bounded-project',
                               'bounded-session', ?, ?)
                        """,
                        [
                            (
                                f"bounded-card-{index:05d}",
                                f"Unique bounded title {index:05d}",
                                f"Unique bounded summary {index:05d}",
                                now,
                                now,
                            )
                            for index in range(card_count)
                        ],
                    )
                    conn.commit()
                finally:
                    conn.close()

                vm_steps = 0
                original_connect = worker_module.connect

                def counted_connect(path: Path):
                    nonlocal vm_steps
                    counted = original_connect(path)

                    def count_step() -> int:
                        nonlocal vm_steps
                        vm_steps += 1
                        return 0

                    counted.set_progress_handler(count_step, 1)
                    return counted

                with (
                    patch.object(
                        worker_module,
                        "connect",
                        side_effect=counted_connect,
                    ),
                    patch.object(
                        worker_module,
                        "_install_conflict_deadline_progress",
                        return_value=None,
                    ),
                ):
                    result = detect_conflicts(
                        root,
                        limit=1,
                        candidate_card_limit=1,
                        comparison_limit=1,
                        component_member_limit=1,
                        mutation_limit=1,
                        transaction_seconds=1.0,
                    )
                self.assertEqual(
                    result["work_budget"]["used"]["candidate_cards"],
                    1,
                )
                return vm_steps

        small_steps = measured_vm_steps(50)
        large_steps = measured_vm_steps(2_000)

        # B-tree lookup depth may grow, but closure proof must not scan every
        # Card sharing the selected Card's visibility boundary.
        self.assertLess(large_steps, (small_steps * 5) + 500)

    def test_candidate_title_and_optional_limit_queries_do_not_sort_full_boundary(
        self,
    ) -> None:
        def measured_vm_steps(card_count: int, *, same_title: bool) -> int:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                init_db(root)
                conn = connect(root)
                try:
                    now = "2026-01-01T00:00:00+00:00"
                    rows = []
                    for index in range(card_count):
                        title = (
                            "Shared bounded candidate title"
                            if same_title
                            else (
                                "Unique bounded candidate anchor"
                                if index == 0
                                else f"Unique bounded candidate noise {index:05d}"
                            )
                        )
                        rows.append(
                            (
                                "bounded-candidate-target"
                                if index == 0
                                else f"bounded-candidate-{index:05d}",
                                title,
                                f"Bounded candidate summary {index:05d}",
                                f"bounded-session-{index:05d}",
                                now,
                                now,
                            )
                        )
                    conn.executemany(
                        """
                        INSERT INTO cards(
                            id, card_type, title, summary, status,
                            source_refs_json, entities_json, topics_json,
                            decisions_json, open_tasks_json, metadata_json,
                            visibility_scope, project_id, session_id,
                            created_at, updated_at
                        )
                        VALUES(?, 'note', ?, ?, 'active', '[]', '[]', '[]',
                               '[]', '[]', '{}', 'project', 'bounded-project',
                               ?, ?, ?)
                        """,
                        rows,
                    )
                    conn.commit()
                    vm_steps = 0

                    def count_step() -> int:
                        nonlocal vm_steps
                        vm_steps += 1
                        return 0

                    conn.set_progress_handler(count_step, 1)
                    budget = worker_module._conflict_work_budget(
                        1,
                        candidate_card_limit=8,
                        comparison_limit=28,
                        component_member_limit=8,
                        mutation_limit=8,
                        transaction_seconds=1.0,
                    )
                    budget.start_transaction()
                    candidate_rows, _scan = worker_module._bounded_conflict_rows(
                        conn,
                        card_id="bounded-candidate-target",
                        cursor=0,
                        budget=budget,
                    )
                    conn.set_progress_handler(None, 0)
                    self.assertLessEqual(len(candidate_rows), 8)
                    return vm_steps
                finally:
                    conn.close()

        for same_title in (False, True):
            with self.subTest(same_title=same_title):
                small_steps = measured_vm_steps(100, same_title=same_title)
                large_steps = measured_vm_steps(5_000, same_title=same_title)
                self.assertLess(large_steps, (small_steps * 4) + 500)

    def test_indexed_unicode_exact_title_uses_the_sql_normalization_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                target = _create_decision(
                    conn,
                    root=root,
                    title="Straße Route",
                    summary="Use the Straße route.",
                )
                for index in range(20):
                    _create_decision(
                        conn,
                        root=root,
                        title=f"Unicode boundary noise {index}",
                        summary=f"Keep Unicode boundary noise {index} unchanged.",
                    )
                peer = _create_decision(
                    conn,
                    root=root,
                    title="Straße Route",
                    summary="Do not use the Straße route.",
                )
                conn.commit()
                budget = worker_module._conflict_work_budget(
                    1,
                    candidate_card_limit=2,
                    comparison_limit=1,
                    component_member_limit=2,
                    mutation_limit=2,
                    transaction_seconds=1.0,
                )
                budget.start_transaction()
                candidate_rows, scan = worker_module._bounded_conflict_rows(
                    conn,
                    card_id=target,
                    cursor=0,
                    budget=budget,
                )
            finally:
                conn.close()

            self.assertEqual(
                {str(row["id"]) for row in candidate_rows},
                {target, peer},
            )
            self.assertTrue(scan["optional_boundary_overflow"], scan)

    def test_deadline_abort_rolls_back_conflict_mutations_and_outbox(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                first = _create_decision(
                    conn,
                    root=root,
                    title="Deadline rollback route",
                    summary="Use the deadline rollback route.",
                )
                second = _create_decision(
                    conn,
                    root=root,
                    title="Deadline rollback route",
                    summary="Do not use the deadline rollback route.",
                )
                conn.execute("DELETE FROM card_sidecar_outbox")
                conn.commit()
            finally:
                conn.close()

            original_mark_outbox = worker_module.mark_card_sidecar_outbox
            reached_outbox = False

            def slow_outbox(*args, **kwargs):
                nonlocal reached_outbox
                reached_outbox = True
                result = original_mark_outbox(*args, **kwargs)
                time.sleep(0.08)
                return result

            with patch.object(
                worker_module,
                "mark_card_sidecar_outbox",
                side_effect=slow_outbox,
            ):
                result = detect_conflicts(
                    root,
                    limit=1,
                    candidate_card_limit=4,
                    comparison_limit=6,
                    component_member_limit=4,
                    mutation_limit=4,
                    transaction_seconds=0.05,
                )

            self.assertTrue(reached_outbox)
            self.assertTrue(result["deadline_aborted"], result)
            self.assertTrue(result["partial"], result)
            self.assertTrue(
                result["continuation"]["requires_larger_budget"],
                result,
            )
            self.assertEqual(result["changed_card_count"], 0, result)
            self.assertEqual(
                result["work_budget"]["used"]["card_mutations"],
                0,
                result,
            )
            self.assertLessEqual(
                result["work_budget"]["used"]["transaction_seconds"],
                result["work_budget"]["limits"]["transaction_seconds"],
                result,
            )
            rows = _card_rows(root, [first, second])
            self.assertIsNone(rows[first]["conflict_group"])
            self.assertIsNone(rows[second]["conflict_group"])
            conn = connect(root)
            try:
                outbox_count = int(
                    conn.execute(
                        "SELECT count(*) AS n FROM card_sidecar_outbox"
                    ).fetchone()["n"]
                )
            finally:
                conn.close()
            self.assertEqual(outbox_count, 0)

    def test_mutation_and_time_exhaustion_are_explicit_and_non_partial_writes_defer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "mutation-budget"
            init_db(root)
            conn = connect(root)
            try:
                first = _create_decision(
                    conn,
                    root=root,
                    title="Atomic mutation route",
                    summary="Use the atomic mutation route.",
                )
                second = _create_decision(
                    conn,
                    root=root,
                    title="Atomic mutation route",
                    summary="Do not use the atomic mutation route.",
                )
                conn.commit()
            finally:
                conn.close()

            mutation_limited = detect_conflicts(
                root,
                limit=1,
                candidate_card_limit=4,
                comparison_limit=6,
                component_member_limit=4,
                mutation_limit=1,
                transaction_seconds=1.0,
            )

            self.assertEqual(mutation_limited["conflict_count"], 0)
            self.assertEqual(
                mutation_limited["work_budget"]["used"]["card_mutations"],
                0,
            )
            self.assertTrue(
                mutation_limited["work_budget"]["exhausted"]["card_mutations"],
                mutation_limited,
            )
            self.assertTrue(
                mutation_limited["continuation"]["requires_larger_budget"],
                mutation_limited,
            )
            rows = _card_rows(root, [first, second])
            self.assertIsNone(rows[first]["conflict_group"])
            self.assertIsNone(rows[second]["conflict_group"])

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "time-budget"
            init_db(root)
            conn = connect(root)
            try:
                _create_decision(
                    conn,
                    root=root,
                    title="Timed route",
                    summary="Use the timed route.",
                )
                _create_decision(
                    conn,
                    root=root,
                    title="Timed route",
                    summary="Do not use the timed route.",
                )
                conn.commit()
            finally:
                conn.close()

            clock = {"value": 0.0}

            def advance_clock() -> float:
                clock["value"] += 0.02
                return clock["value"]

            with patch.object(worker_module.time, "monotonic", side_effect=advance_clock):
                time_limited = detect_conflicts(
                    root,
                    limit=1,
                    candidate_card_limit=4,
                    comparison_limit=6,
                    component_member_limit=4,
                    mutation_limit=4,
                    transaction_seconds=0.01,
                )

            self.assertTrue(time_limited["partial"], time_limited)
            self.assertTrue(time_limited["work_budget"]["time_exhausted"])
            self.assertTrue(
                time_limited["work_budget"]["exhausted"]["transaction_seconds"]
            )
            self.assertIn(
                "transaction_seconds",
                time_limited["continuation"]["budget_exhausted"],
            )
            self.assertEqual(time_limited["work_budget"]["used"]["card_mutations"], 0)

    def test_existing_group_membership_keeps_prior_three_card_component_connected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                first = _create_decision(
                    conn,
                    root=root,
                    title="Prior Route",
                    summary="Use prior routing for deployment.",
                )
                second = _create_decision(
                    conn,
                    root=root,
                    title="Prior Route",
                    summary="Do not use prior routing for deployment.",
                )
                third = _create_decision(
                    conn,
                    root=root,
                    title="Unrelated Ledger",
                    summary="Keep the unrelated ledger for accounting evidence.",
                )
                conn.execute(
                    "UPDATE cards SET conflict_group = 'prior-three-card-group' WHERE id IN (?, ?, ?)",
                    (first, second, third),
                )
                conn.commit()
            finally:
                conn.close()

            result = detect_conflicts(root, card_id=first)

            self.assertEqual(result["conflict_count"], 1, result)
            self.assertEqual(result["changed_card_count"], 0, result)
            self.assertEqual(result["conflicts"][0]["conflict_group"], "prior-three-card-group")
            self.assertEqual(set(result["conflicts"][0]["card_ids"]), {first, second, third})
            rows = _card_rows(root, [first, second, third])
            self.assertEqual(
                {row["conflict_group"] for row in rows.values()},
                {"prior-three-card-group"},
            )

    def test_historical_superseded_and_orphan_groups_are_cleared_and_excluded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                current = _create_decision(
                    conn,
                    root=root,
                    title="Obelisk Route",
                    summary="Use obelisk routing for deployment.",
                )
                superseded = _create_decision(
                    conn,
                    root=root,
                    title="Obelisk Route",
                    summary="Do not use obelisk routing for deployment.",
                )
                archived = _create_decision(
                    conn,
                    root=root,
                    title="Obelisk Route",
                    summary="Never use obelisk routing for deployment.",
                )
                orphan = _create_decision(
                    conn,
                    root=root,
                    title="Quartz Ledger",
                    summary="Use the quartz ledger for reports.",
                )
                conn.execute(
                    "UPDATE cards SET superseded_by_card_id = ?, conflict_group = 'stale-group' WHERE id = ?",
                    (current, superseded),
                )
                conn.execute(
                    "UPDATE cards SET supersedes_card_id = ? WHERE id = ?",
                    (superseded, current),
                )
                conn.execute(
                    "UPDATE cards SET status = 'archived', conflict_group = 'stale-group' WHERE id = ?",
                    (archived,),
                )
                conn.execute(
                    "UPDATE cards SET conflict_group = 'orphan-group' WHERE id = ?",
                    (orphan,),
                )
                conn.commit()
            finally:
                conn.close()

            result = detect_conflicts(root, card_id=current)

            self.assertEqual(result["conflict_count"], 0, result)
            self.assertEqual(result["orphan_groups_cleared"], 2, result)
            rows = _card_rows(root, [current, superseded, archived, orphan])
            self.assertIsNone(rows[superseded]["conflict_group"])
            self.assertIsNone(rows[archived]["conflict_group"])
            self.assertIsNone(rows[orphan]["conflict_group"])
            self.assertIsNone(rows[current]["conflict_group"])

    def test_existing_group_cannot_bridge_visibility_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                alpha = _create_decision(
                    conn,
                    root=root,
                    title="Boundary Route",
                    summary="Use boundary routing for deployment.",
                    project_id="alpha",
                )
                beta = _create_decision(
                    conn,
                    root=root,
                    title="Boundary Route",
                    summary="Do not use boundary routing for deployment.",
                    project_id="beta",
                )
                alpha_peer = _create_decision(
                    conn,
                    root=root,
                    title="Boundary Route",
                    summary="Do not use boundary routing for deployment.",
                    project_id="alpha",
                )
                conn.execute(
                    "UPDATE cards SET conflict_group = 'cross-project-group' WHERE id IN (?, ?)",
                    (alpha, beta),
                )
                conn.commit()
            finally:
                conn.close()

            result = detect_conflicts(root, card_id=alpha)

            self.assertEqual(result["conflict_count"], 1, result)
            self.assertEqual(result["orphan_groups_cleared"], 1, result)
            rows = _card_rows(root, [alpha, beta, alpha_peer])
            result_group = result["conflicts"][0]["conflict_group"]
            self.assertEqual(set(result["conflicts"][0]["card_ids"]), {alpha, alpha_peer})
            self.assertEqual(rows[alpha]["conflict_group"], result_group)
            self.assertEqual(rows[alpha_peer]["conflict_group"], result_group)
            self.assertIsNone(rows[beta]["conflict_group"])
            conn = connect(root)
            try:
                detect_audits = conn.execute(
                    """
                    SELECT target_id, payload_json
                    FROM audit_events
                    WHERE action = 'librarian_detect_conflict'
                    """
                ).fetchall()
                cleanup_audits = conn.execute(
                    "SELECT count(*) AS n FROM audit_events WHERE action = 'librarian_clear_orphan_conflicts'"
                ).fetchone()["n"]
            finally:
                conn.close()
            self.assertEqual(cleanup_audits, 1)
            self.assertEqual(len(detect_audits), 1)
            self.assertEqual(detect_audits[0]["target_id"], result_group)
            self.assertEqual(set(json.loads(detect_audits[0]["payload_json"])["card_ids"]), {alpha, alpha_peer})

    def test_exact_title_closure_expands_transitively_through_peer_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                alpha = _create_decision(
                    conn,
                    root=root,
                    title="Transitive Boundary Route",
                    summary="Use transitive boundary routing.",
                    project_id="alpha",
                )
                alpha_peer = _create_decision(
                    conn,
                    root=root,
                    title="Transitive Boundary Route",
                    summary="Do not use transitive boundary routing.",
                    project_id="alpha",
                )
                beta_group_peer = _create_decision(
                    conn,
                    root=root,
                    title="Other Group Route",
                    summary="Keep the other group route.",
                    project_id="beta",
                )
                conn.execute(
                    "UPDATE cards SET conflict_group = 'cross-peer-group' WHERE id IN (?, ?)",
                    (alpha_peer, beta_group_peer),
                )
                conn.commit()
            finally:
                conn.close()

            bounded = detect_conflicts(
                root,
                card_id=alpha,
                limit=1,
                candidate_card_limit=2,
                comparison_limit=1,
                component_member_limit=2,
                mutation_limit=2,
                transaction_seconds=1.0,
            )
            self.assertTrue(bounded["continuation"]["requires_larger_budget"], bounded)
            self.assertEqual(
                bounded["continuation"]["required_candidate_cards_lower_bound"],
                3,
            )
            self.assertEqual(bounded["changed_card_count"], 0, bounded)

            expanded = detect_conflicts(
                root,
                card_id=alpha,
                limit=1,
                candidate_card_limit=4,
                comparison_limit=6,
                component_member_limit=4,
                mutation_limit=4,
                transaction_seconds=1.0,
            )

            self.assertEqual(expanded["conflict_count"], 1, expanded)
            self.assertEqual(expanded["orphan_groups_cleared"], 1, expanded)
            self.assertEqual(
                set(expanded["conflicts"][0]["card_ids"]),
                {alpha, alpha_peer},
            )
            rows = _card_rows(root, [alpha, alpha_peer, beta_group_peer])
            self.assertEqual(
                rows[alpha]["conflict_group"],
                rows[alpha_peer]["conflict_group"],
            )
            self.assertIsNone(rows[beta_group_peer]["conflict_group"])

    def test_optional_fuzzy_peer_expands_transitively_through_durable_group(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                alpha = _create_decision(
                    conn,
                    root=root,
                    title="Alpha Route",
                    summary="Use alpha routing for deployment.",
                    project_id="alpha",
                )
                fuzzy_peer = _create_decision(
                    conn,
                    root=root,
                    title="Alpha Beta Route",
                    summary="Do not use alpha beta routing for deployment.",
                    project_id="alpha",
                )
                beta_group_peer = _create_decision(
                    conn,
                    root=root,
                    title="Other Route",
                    summary="Keep the other route.",
                    project_id="beta",
                )
                conn.execute(
                    "UPDATE cards SET conflict_group = 'optional-peer-group' WHERE id IN (?, ?)",
                    (fuzzy_peer, beta_group_peer),
                )
                conn.commit()
            finally:
                conn.close()

            result = detect_conflicts(
                root,
                card_id=alpha,
                limit=1,
                candidate_card_limit=4,
                comparison_limit=6,
                component_member_limit=4,
                mutation_limit=4,
                transaction_seconds=1.0,
            )

            self.assertEqual(result["conflict_count"], 1, result)
            self.assertEqual(result["orphan_groups_cleared"], 1, result)
            self.assertFalse(result["continuation"]["required"], result)
            self.assertEqual(
                set(result["conflicts"][0]["card_ids"]),
                {alpha, fuzzy_peer},
            )
            rows = _card_rows(root, [alpha, fuzzy_peer, beta_group_peer])
            self.assertEqual(
                rows[alpha]["conflict_group"],
                rows[fuzzy_peer]["conflict_group"],
            )
            self.assertIsNone(rows[beta_group_peer]["conflict_group"])

    def test_review_identity_deduplicates_durable_group_across_anchor_titles(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                first = _create_decision(
                    conn,
                    root=root,
                    title="First durable review title",
                    summary="Use the first durable review route.",
                    project_id="alpha",
                )
                second = _create_decision(
                    conn,
                    root=root,
                    title="Second durable review title",
                    summary="Use the second durable review route.",
                    project_id="beta",
                )
                conn.execute(
                    "UPDATE cards SET conflict_group = 'one-durable-review-group' WHERE id IN (?, ?)",
                    (first, second),
                )
                conn.commit()
                identity_hashes: list[str] = []
                for card_id in (first, second):
                    budget = worker_module._conflict_work_budget(
                        1,
                        candidate_card_limit=2,
                        comparison_limit=1,
                        component_member_limit=2,
                        mutation_limit=2,
                        transaction_seconds=1.0,
                    )
                    budget.start_transaction()
                    _rows, scan = worker_module._bounded_conflict_rows(
                        conn,
                        card_id=card_id,
                        cursor=0,
                        budget=budget,
                    )
                    identity_hashes.append(str(scan["anchor_identity_hash"]))
            finally:
                conn.close()

            self.assertEqual(len(set(identity_hashes)), 1)

    def test_mixed_type_group_cannot_supersede_project_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="mixed-type-session",
                agent_id="codex-sol",
                project_id="mixed-type-project",
                objective="Keep the checkpoint current",
            )
            conn = connect(root)
            try:
                decision = _create_decision(
                    conn,
                    root=root,
                    title="Mixed Type Route",
                    summary="Use a derived decision instead of the checkpoint.",
                    session_id="mixed-type-session",
                    project_id="mixed-type-project",
                )
                conn.execute(
                    "UPDATE cards SET conflict_group = 'mixed-type-group' WHERE id IN (?, ?)",
                    (state["card_id"], decision),
                )
                conn.commit()
            finally:
                conn.close()
            before = _card_rows(root, [state["card_id"], decision])

            with self.assertRaisesRegex(
                ValueError,
                "project_state conflict groups cannot include non-project_state",
            ):
                resolve_conflict(root, card_id=decision, action="supersede")

            self.assertEqual(
                _card_rows(root, [state["card_id"], decision]),
                before,
            )
            dismissed = resolve_conflict(root, card_id=decision, action="dismiss")
            self.assertTrue(dismissed["ok"], dismissed)
            rows = _card_rows(root, [state["card_id"], decision])
            self.assertTrue(
                all(row["conflict_group"] is None for row in rows.values())
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET conflict_group = 'legacy-mixed-type-group' WHERE id IN (?, ?)",
                    (state["card_id"], decision),
                )
                conn.commit()
            finally:
                conn.close()
            cleaned = detect_conflicts(root, card_id=state["card_id"])
            self.assertEqual(cleaned["conflict_count"], 0, cleaned)
            self.assertEqual(cleaned["orphan_groups_cleared"], 1, cleaned)

    def test_same_created_at_predecessor_uses_rowid_not_hash_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                first_peer = _create_decision(
                    conn,
                    root=root,
                    title="Row Order Route",
                    summary="Use row order routing for deployment.",
                )
                second_peer = _create_decision(
                    conn,
                    root=root,
                    title="Row Order Route",
                    summary="Do not use row order routing for deployment.",
                )
                winner = _create_decision(
                    conn,
                    root=root,
                    title="Row Order Route",
                    summary="Never disable reviewed row order routing for deployment.",
                )
                lexical_small, lexical_large = sorted((first_peer, second_peer))
                conn.execute("UPDATE cards SET rowid = 100001 WHERE id = ?", (lexical_small,))
                conn.execute("UPDATE cards SET rowid = 100000 WHERE id = ?", (lexical_large,))
                conn.execute(
                    "UPDATE cards SET created_at = '2026-01-01T00:00:00+00:00' WHERE id IN (?, ?, ?)",
                    (first_peer, second_peer, winner),
                )
                conn.commit()
            finally:
                conn.close()

            detect_conflicts(root, card_id=winner)
            resolved = resolve_conflict(root, card_id=winner, action="supersede")

            self.assertTrue(resolved["ok"], resolved)
            rows = _card_rows(root, [first_peer, second_peer, winner])
            self.assertEqual(rows[winner]["supersedes_card_id"], lexical_small)

    def test_partial_resolution_rolls_back_then_whole_group_resolves_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                alpha = _create_decision(
                    conn,
                    root=root,
                    title="Alpha Route",
                    summary="Use alpha routing for deployment.",
                )
                winner = _create_decision(
                    conn,
                    root=root,
                    title="Alpha Beta Route",
                    summary="Do not use alpha beta routing for deployment.",
                )
                beta = _create_decision(
                    conn,
                    root=root,
                    title="Beta Route",
                    summary="Use beta routing for deployment.",
                )
                conn.commit()
            finally:
                conn.close()
            detect_conflicts(root, card_id=winner)
            before = _card_rows(root, [alpha, winner, beta])

            with self.assertRaisesRegex(ValueError, "partial conflict resolution"):
                resolve_conflict(
                    root,
                    card_id=winner,
                    action="supersede",
                    superseded_card_ids=[alpha],
                )

            after_rejected = _card_rows(root, [alpha, winner, beta])
            for card_id in (alpha, winner, beta):
                self.assertEqual(after_rejected[card_id]["conflict_group"], before[card_id]["conflict_group"])
                self.assertEqual(after_rejected[card_id]["superseded_by_card_id"], before[card_id]["superseded_by_card_id"])
                self.assertEqual(after_rejected[card_id]["supersedes_card_id"], before[card_id]["supersedes_card_id"])

            resolved = resolve_conflict(root, card_id=winner, action="supersede")

            self.assertTrue(resolved["ok"], resolved)
            self.assertTrue(resolved["whole_group"])
            self.assertEqual(set(resolved["resolved_peer_ids"]), {alpha, beta})
            rows = _card_rows(root, [alpha, winner, beta])
            self.assertTrue(all(row["conflict_group"] is None for row in rows.values()))
            self.assertEqual(rows[alpha]["superseded_by_card_id"], winner)
            self.assertEqual(rows[beta]["superseded_by_card_id"], winner)
            self.assertIn(rows[winner]["supersedes_card_id"], {alpha, beta})
            _assert_temporal_dag(self, rows)
            conn = connect(root)
            try:
                receipt = conn.execute(
                    "SELECT * FROM conflict_resolution_receipts WHERE id = ?",
                    (resolved["resolution_id"],),
                ).fetchone()
                receipt_members = conn.execute(
                    """
                    SELECT card_id FROM conflict_resolution_members
                    WHERE receipt_id = ? ORDER BY member_ordinal
                    """,
                    (resolved["resolution_id"],),
                ).fetchall()
            finally:
                conn.close()
            self.assertIsNotNone(receipt)
            assert receipt is not None
            self.assertEqual(receipt["action"], "supersede")
            self.assertEqual(receipt["selected_card_id"], winner)
            self.assertEqual(receipt["member_count"], 3)
            self.assertEqual(
                [row["card_id"] for row in receipt_members],
                sorted([alpha, winner, beta]),
            )
            self.assertEqual(audit(root)["stale_card_sidecars"], 0)

            repeated_detection = detect_conflicts(root, card_id=winner)
            self.assertEqual(repeated_detection["conflict_count"], 0, repeated_detection)

    def test_reversal_and_preexisting_cycles_are_rejected_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                former = _create_decision(
                    conn,
                    root=root,
                    title="Reverse Route",
                    summary="Use reverse routing for deployment.",
                )
                current = _create_decision(
                    conn,
                    root=root,
                    title="Reverse Route",
                    summary="Do not use reverse routing for deployment.",
                )
                conn.execute(
                    "UPDATE cards SET superseded_by_card_id = ?, conflict_group = 'manual-reversal' WHERE id = ?",
                    (current, former),
                )
                conn.execute(
                    "UPDATE cards SET supersedes_card_id = ?, conflict_group = 'manual-reversal' WHERE id = ?",
                    (former, current),
                )
                conn.commit()
            finally:
                conn.close()
            before = _card_rows(root, [former, current])

            with self.assertRaisesRegex(ValueError, "historical or superseded"):
                resolve_conflict(root, card_id=former, action="supersede")

            self.assertEqual(_card_rows(root, [former, current]), before)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "cycle-root"
            init_db(root)
            conn = connect(root)
            try:
                first = _create_decision(
                    conn,
                    root=root,
                    title="Cycle Route",
                    summary="Use cycle routing for deployment.",
                )
                second = _create_decision(
                    conn,
                    root=root,
                    title="Cycle Route",
                    summary="Do not use cycle routing for deployment.",
                )
                conn.execute(
                    "UPDATE cards SET superseded_by_card_id = ? WHERE id = ?",
                    (second, first),
                )
                conn.execute(
                    "UPDATE cards SET superseded_by_card_id = ? WHERE id = ?",
                    (first, second),
                )
                conn.commit()
            finally:
                conn.close()

            with self.assertRaisesRegex(ValueError, "must be acyclic"):
                detect_conflicts(root)


if __name__ == "__main__":
    unittest.main()
