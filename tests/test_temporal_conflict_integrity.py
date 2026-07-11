from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from continuum.core.store import audit, connect, create_card, init_db
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
                entries = json.loads(row["metadata_json"])["dismissed_conflict_components"]
                self.assertLessEqual(len(entries), 8)
                self.assertEqual(entries[-1]["fingerprint"], dismissed["dismissal_fingerprint"])

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
