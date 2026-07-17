from __future__ import annotations

import json
import sqlite3
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path

from continuum.core.bundle import (
    BUNDLE_MANIFEST_NAME,
    BUNDLE_ROOT_NAME,
    _manifest_hash,
    _write_zip_member,
    pack_root,
    verify_root_bundle,
)
from continuum.core.operations import restore_drill, verify_root
from continuum.core.store import (
    connect,
    create_card,
    file_sha256,
    init_db,
    record_project_state,
    repair_invalid_project_state_checkpoints,
    semantic_integrity_report,
    snapshot,
    snapshot_alias_key_path,
    snapshot_card_sidecar_receipts_path,
    sync_card_sidecar,
    write_snapshot_manifest,
)
from continuum.core.temporal_authority import conflict_boundary
from continuum.core.workers import detect_conflicts, resolve_conflict


def _record_two_states(
    root: Path,
    *,
    project_id: str = "authority-project",
    first_agent: str = "agent-a",
    second_agent: str | None = None,
) -> tuple[dict[str, object], dict[str, object]]:
    first = record_project_state(
        root,
        session_id="authority-session-a",
        agent_id=first_agent,
        project_id=project_id,
        objective="First authority checkpoint",
        decisions=["FIRST_AUTHORITY_DECISION"],
        open_tasks=["FIRST_AUTHORITY_TASK"],
    )
    second = record_project_state(
        root,
        session_id="authority-session-b",
        agent_id=second_agent or first_agent,
        project_id=project_id,
        objective="Second authority checkpoint",
        decisions=["SECOND_AUTHORITY_DECISION"],
        open_tasks=["SECOND_AUTHORITY_TASK"],
    )
    return first, second


def _sync_cards(root: Path, conn: sqlite3.Connection, *card_ids: str) -> None:
    for card_id in card_ids:
        sync_card_sidecar(root, conn, card_id)


def _make_cycle(
    root: Path,
    first_card_id: str,
    second_card_id: str,
) -> None:
    conn = connect(root)
    try:
        conn.execute(
            "UPDATE cards SET supersedes_card_id = ? WHERE id = ?",
            (second_card_id, first_card_id),
        )
        conn.execute(
            "UPDATE cards SET superseded_by_card_id = ? WHERE id = ?",
            (first_card_id, second_card_id),
        )
        _sync_cards(root, conn, first_card_id, second_card_id)
        conn.commit()
    finally:
        conn.close()


def _tamper_project_state_payload(root: Path, card_id: str) -> None:
    conn = connect(root)
    try:
        conn.execute(
            "UPDATE cards SET decisions_json = ? WHERE id = ?",
            (json.dumps(["TAMPERED_RELEASE_AUTHORITY_DECISION"]), card_id),
        )
        _sync_cards(root, conn, card_id)
        conn.commit()
    finally:
        conn.close()


def _tamper_catalog_connection(
    conn: sqlite3.Connection,
    *,
    corruption: str,
    first_card_id: str,
    second_card_id: str,
) -> tuple[str, ...]:
    if corruption == "cycle":
        conn.execute(
            "UPDATE cards SET supersedes_card_id = ? WHERE id = ?",
            (second_card_id, first_card_id),
        )
        conn.execute(
            "UPDATE cards SET superseded_by_card_id = ? WHERE id = ?",
            (first_card_id, second_card_id),
        )
        return (first_card_id, second_card_id)
    conn.execute(
        "UPDATE cards SET decisions_json = ? WHERE id = ?",
        (json.dumps(["TAMPERED_RELEASE_AUTHORITY_DECISION"]), second_card_id),
    )
    return (second_card_id,)


def _write_canonical_bundle_from_root(
    embedded_root: Path,
    destination: Path,
) -> None:
    manifest_path = embedded_root / BUNDLE_MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in manifest["files"]:
        path = embedded_root / str(entry["path"])
        entry["sha256"] = file_sha256(path)
        entry["size_bytes"] = path.stat().st_size
        entry["mode"] = stat.S_IMODE(path.stat().st_mode)
    total_size = sum(int(entry["size_bytes"]) for entry in manifest["files"])
    manifest["total_size_bytes"] = total_size
    manifest["copy"]["copied_bytes"] = total_size
    manifest["manifest_hash"] = _manifest_hash(manifest)
    manifest_path.write_bytes(
        (json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )
    )
    paths = [embedded_root / str(entry["path"]) for entry in manifest["files"]]
    paths.append(manifest_path)
    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=6,
        allowZip64=True,
        strict_timestamps=False,
    ) as archive:
        for path in sorted(
            paths,
            key=lambda item: item.relative_to(embedded_root).as_posix(),
        ):
            relative = path.relative_to(embedded_root).as_posix()
            _write_zip_member(
                archive,
                path,
                arcname=f"{BUNDLE_ROOT_NAME}/{relative}",
                mode_override=0o644 if path == manifest_path else None,
            )


class AuthoritySemanticIntegrityTest(unittest.TestCase):
    def test_conflict_boundary_preserves_empty_project_session_partition(self) -> None:
        self.assertEqual(
            conflict_boundary(
                {
                    "visibility_scope": "project",
                    "project_id": "",
                    "session_id": "legacy-session",
                }
            ),
            ("project", "", "legacy-session"),
        )

    def test_semantic_report_rejects_each_temporal_authority_corruption(self) -> None:
        cases = (
            "missing_reference",
            "asymmetric_link",
            "cross_boundary_link",
            "duplicate_same_agent_heads",
            "mixed_boundary_conflict_group",
        )
        expected_check = {
            "missing_reference": "supersession_missing_references",
            "asymmetric_link": "supersession_asymmetric_links",
            "cross_boundary_link": "supersession_cross_boundary_links",
            "duplicate_same_agent_heads": "multiple_same_agent_project_state_heads",
            "mixed_boundary_conflict_group": "invalid_conflict_groups",
        }
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                if case in {"cross_boundary_link", "mixed_boundary_conflict_group"}:
                    first, _unused = _record_two_states(
                        root,
                        project_id="boundary-project-a",
                    )
                    second = record_project_state(
                        root,
                        session_id="boundary-session-b",
                        agent_id="agent-b",
                        project_id="boundary-project-b",
                        objective="Other boundary checkpoint",
                    )
                else:
                    first, second = _record_two_states(root)
                first_id = str(first["card_id"])
                second_id = str(second["card_id"])
                conn = connect(root)
                try:
                    if case == "missing_reference":
                        conn.execute(
                            "UPDATE cards SET supersedes_card_id = 'missing-card' WHERE id = ?",
                            (second_id,),
                        )
                        _sync_cards(root, conn, second_id)
                    elif case == "asymmetric_link":
                        conn.execute(
                            "UPDATE cards SET superseded_by_card_id = NULL WHERE id = ?",
                            (first_id,),
                        )
                        _sync_cards(root, conn, first_id)
                    elif case == "cross_boundary_link":
                        conn.execute(
                            "UPDATE cards SET superseded_by_card_id = ? WHERE id = ?",
                            (second_id, first_id),
                        )
                        conn.execute(
                            "UPDATE cards SET supersedes_card_id = ? WHERE id = ?",
                            (first_id, second_id),
                        )
                        _sync_cards(root, conn, first_id, second_id)
                    elif case == "duplicate_same_agent_heads":
                        conn.execute(
                            "UPDATE cards SET superseded_by_card_id = NULL WHERE id = ?",
                            (first_id,),
                        )
                        conn.execute(
                            "UPDATE cards SET supersedes_card_id = NULL WHERE id = ?",
                            (second_id,),
                        )
                        _sync_cards(root, conn, first_id, second_id)
                    else:
                        conn.execute(
                            "UPDATE cards SET conflict_group = 'mixed-boundary' WHERE id IN (?, ?)",
                            (first_id, second_id),
                        )
                        _sync_cards(root, conn, first_id, second_id)
                    conn.commit()
                finally:
                    conn.close()

                report = semantic_integrity_report(root)

                self.assertFalse(report["ok"], report)
                self.assertGreater(report["failing"][expected_check[case]], 0)

    def test_semantic_report_validates_every_project_state_payload_binding(self) -> None:
        for case in ("historical_structured_payload", "metadata_payload_hash"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                first, second = _record_two_states(root)
                target = first if case == "historical_structured_payload" else second
                target_id = str(target["card_id"])
                conn = connect(root)
                try:
                    if case == "historical_structured_payload":
                        conn.execute(
                            "UPDATE cards SET decisions_json = ? WHERE id = ?",
                            (json.dumps(["TAMPERED_HISTORICAL_DECISION"]), target_id),
                        )
                    else:
                        metadata = json.loads(
                            str(
                                conn.execute(
                                    "SELECT metadata_json FROM cards WHERE id = ?",
                                    (target_id,),
                                ).fetchone()[0]
                            )
                        )
                        metadata["state_payload_hash"] = "0" * 64
                        conn.execute(
                            "UPDATE cards SET metadata_json = ? WHERE id = ?",
                            (json.dumps(metadata), target_id),
                        )
                    _sync_cards(root, conn, target_id)
                    conn.commit()
                finally:
                    conn.close()

                report = semantic_integrity_report(root)

                self.assertFalse(report["ok"], report)
                self.assertEqual(report["failing"]["invalid_project_state_cards"], 1)
                failures = report["project_state_integrity_failures"]
                self.assertEqual(failures[0]["card_id"], target_id)

    def test_corruption_blocks_snapshot_verify_root_and_pack_root(self) -> None:
        for corruption in ("cycle", "payload"):
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                root = base / "continuum"
                first, second = _record_two_states(root)
                if corruption == "cycle":
                    _make_cycle(
                        root,
                        str(first["card_id"]),
                        str(second["card_id"]),
                    )
                    failing_check = "supersession_cycle_count"
                else:
                    _tamper_project_state_payload(root, str(second["card_id"]))
                    failing_check = "invalid_project_state_cards"

                report = semantic_integrity_report(root)
                verified = verify_root(
                    root,
                    strict=True,
                    verify_recent_proof_packs=0,
                    run_restore_drill=False,
                    scan_secrets=False,
                )

                self.assertEqual(report["failing"][failing_check], 1)
                self.assertFalse(verified["ok"], verified)
                with self.assertRaisesRegex(ValueError, "semantic integrity"):
                    snapshot(root, reason=f"authority_{corruption}")
                with self.assertRaisesRegex(ValueError, "root verification failed"):
                    pack_root(
                        root,
                        out_path=base / "invalid-root.zip",
                        profile="portable",
                        run_restore_drill=False,
                    )

    def test_restore_drill_rejects_rehashed_snapshot_authority_corruption(self) -> None:
        for corruption in ("cycle", "payload"):
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                first, second = _record_two_states(root)
                snap = snapshot(root, reason=f"clean_before_{corruption}")
                snap_path = Path(str(snap["snapshot_uri"]))
                snapshot_conn = sqlite3.connect(snap_path)
                try:
                    _tamper_catalog_connection(
                        snapshot_conn,
                        corruption=corruption,
                        first_card_id=str(first["card_id"]),
                        second_card_id=str(second["card_id"]),
                    )
                    snapshot_conn.commit()
                finally:
                    snapshot_conn.close()
                sidecars_path = Path(str(snap["card_sidecars_uri"]))
                alias_path = snapshot_alias_key_path(snap_path)
                manifest_path = write_snapshot_manifest(
                    root,
                    snapshot_path=snap_path,
                    card_sidecars_path=sidecars_path,
                    alias_key_path=alias_path if alias_path.exists() else None,
                    card_sidecars_source_path=root / "catalog" / "cards",
                    card_sidecar_receipts_path=(
                        snapshot_card_sidecar_receipts_path(snap_path)
                    ),
                    card_sidecar_receipts_source_path=(
                        root
                        / "exports"
                        / "card_sidecar_recovery_receipts"
                    ),
                    semantic_integrity={"ok": True, "failing": {}},
                )
                conn = connect(root)
                try:
                    conn.execute(
                        """
                        UPDATE snapshots
                        SET snapshot_hash = ?, manifest_hash = ?
                        WHERE id = ?
                        """,
                        (
                            file_sha256(snap_path),
                            file_sha256(manifest_path),
                            snap["snapshot_id"],
                        ),
                    )
                    conn.commit()
                finally:
                    conn.close()

                result = restore_drill(
                    root,
                    snapshot_uri=str(snap_path),
                    verify_recent_proof_packs=0,
                    retain_drill_root=False,
                )

                failing_check = (
                    "supersession_cycle_count"
                    if corruption == "cycle"
                    else "invalid_project_state_cards"
                )
                self.assertFalse(result["ok"], result)
                checks = {check["name"]: check for check in result["checks"]}
                self.assertTrue(checks["snapshot_manifest_verified"]["ok"])
                self.assertFalse(checks["semantic_integrity_clean"]["ok"])
                self.assertEqual(
                    result["semantic_integrity"]["failing"][failing_check],
                    1,
                )

    def test_bundle_verifier_rejects_rehashed_embedded_authority_corruption(self) -> None:
        for corruption in ("cycle", "payload"):
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                root = base / "continuum"
                first, second = _record_two_states(root)
                clean_bundle = base / "clean.zip"
                forged_bundle = base / "forged.zip"
                stage = base / "stage"
                pack_root(
                    root,
                    out_path=clean_bundle,
                    profile="portable",
                    run_restore_drill=False,
                )
                with zipfile.ZipFile(clean_bundle) as archive:
                    archive.extractall(stage)
                embedded_root = stage / BUNDLE_ROOT_NAME
                catalog = embedded_root / "catalog" / "catalog.sqlite3"
                conn = sqlite3.connect(catalog)
                conn.row_factory = sqlite3.Row
                try:
                    changed_ids = _tamper_catalog_connection(
                        conn,
                        corruption=corruption,
                        first_card_id=str(first["card_id"]),
                        second_card_id=str(second["card_id"]),
                    )
                    _sync_cards(embedded_root, conn, *changed_ids)
                    conn.commit()
                finally:
                    conn.close()
                _write_canonical_bundle_from_root(embedded_root, forged_bundle)

                envelope_only = verify_root_bundle(
                    forged_bundle,
                    verify_embedded_root=False,
                )
                result = verify_root_bundle(forged_bundle)

                self.assertTrue(envelope_only["ok"], envelope_only)
                self.assertFalse(result["ok"], result)
                self.assertIn(
                    "embedded_root_verification_unhealthy",
                    json.dumps(result["errors"]),
                )

    def test_clean_legacy_same_agent_fork_repair_authorizes_intentional_fan_in(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first, second = _record_two_states(root)
            first_id = str(first["card_id"])
            second_id = str(second["card_id"])
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET superseded_by_card_id = NULL WHERE id = ?",
                    (first_id,),
                )
                conn.execute(
                    "UPDATE cards SET supersedes_card_id = NULL WHERE id = ?",
                    (second_id,),
                )
                _sync_cards(root, conn, first_id, second_id)
                conn.commit()
            finally:
                conn.close()

            repaired = record_project_state(
                root,
                session_id="authority-session-c",
                agent_id="agent-a",
                project_id="authority-project",
                objective="Repair the legacy authority fork",
            )
            report = semantic_integrity_report(root)

            self.assertEqual(
                set(repaired["superseded_card_ids"]),
                {first_id, second_id},
            )
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["checks"]["supersession_asymmetric_links"], 0)
            self.assertEqual(
                report["checks"]["multiple_same_agent_project_state_heads"],
                0,
            )

            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = summary || ' damaged' WHERE id = ?",
                    (repaired["card_id"],),
                )
                _sync_cards(root, conn, str(repaired["card_id"]))
                conn.commit()
            finally:
                conn.close()
            quarantined = repair_invalid_project_state_checkpoints(
                root,
                project_id="authority-project",
                dry_run=False,
            )
            repaired_report = semantic_integrity_report(root)
            direct_predecessor = str(repaired["supersedes_card_id"])
            non_direct_predecessor = (
                first_id if direct_predecessor == second_id else second_id
            )
            conn = connect(root)
            try:
                predecessor_rows = {
                    str(row["id"]): dict(row)
                    for row in conn.execute(
                        """
                        SELECT id, status, superseded_by_card_id
                        FROM cards WHERE id IN (?, ?)
                        """,
                        (first_id, second_id),
                    )
                }
            finally:
                conn.close()

            self.assertEqual(quarantined["quarantined_count"], 1)
            self.assertTrue(repaired_report["ok"], repaired_report)
            self.assertIsNone(
                predecessor_rows[direct_predecessor]["superseded_by_card_id"]
            )
            self.assertNotEqual(
                predecessor_rows[direct_predecessor]["status"],
                "historical",
            )
            self.assertEqual(
                predecessor_rows[non_direct_predecessor]["status"],
                "historical",
            )
            self.assertIsNone(
                predecessor_rows[non_direct_predecessor][
                    "superseded_by_card_id"
                ]
            )
            clean_snapshot = snapshot(
                root,
                reason="quarantined_legacy_fan_in",
            )
            self.assertTrue(Path(str(clean_snapshot["snapshot_uri"])).exists())

    def test_quarantine_retires_exact_conflict_receipts_without_authority(
        self,
    ) -> None:
        for action in ("dismiss", "supersede"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                first = record_project_state(
                    root,
                    session_id="receipt-quarantine-a",
                    agent_id="agent-a",
                    project_id="authority-project",
                    objective="Choose authority routing",
                    decisions=["Use authority routing for deployment"],
                )
                second = record_project_state(
                    root,
                    session_id="receipt-quarantine-b",
                    agent_id="agent-b",
                    project_id="authority-project",
                    objective="Choose authority routing",
                    decisions=["Do not use authority routing for deployment"],
                )
                detected = detect_conflicts(
                    root,
                    card_id=str(first["card_id"]),
                )
                self.assertEqual(detected["conflict_count"], 1, detected)
                resolved = resolve_conflict(
                    root,
                    card_id=str(second["card_id"]),
                    action=action,
                )
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE cards SET summary = summary || ' damaged' WHERE id = ?",
                        (second["card_id"],),
                    )
                    _sync_cards(root, conn, str(second["card_id"]))
                    conn.commit()
                finally:
                    conn.close()

                quarantined = repair_invalid_project_state_checkpoints(
                    root,
                    project_id="authority-project",
                    dry_run=False,
                )
                report = semantic_integrity_report(root)
                conn = connect(root)
                try:
                    first_row = conn.execute(
                        """
                        SELECT status, superseded_by_card_id
                        FROM cards WHERE id = ?
                        """,
                        (first["card_id"],),
                    ).fetchone()
                    receipt_count = int(
                        conn.execute(
                            "SELECT count(*) FROM conflict_resolution_receipts"
                        ).fetchone()[0]
                    )
                finally:
                    conn.close()

                self.assertEqual(quarantined["quarantined_count"], 1)
                self.assertTrue(report["ok"], report)
                self.assertEqual(
                    report["retired_conflict_resolution_receipt_ids"],
                    [resolved["resolution_id"]],
                )
                self.assertEqual(receipt_count, 1)
                self.assertIsNone(first_row["superseded_by_card_id"])
                if action == "supersede":
                    self.assertEqual(first_row["status"], "historical")
                clean_snapshot = snapshot(
                    root,
                    reason=f"quarantined_{action}_receipt",
                )
                self.assertTrue(
                    Path(str(clean_snapshot["snapshot_uri"])).exists()
                )
                conn = connect(root)
                try:
                    conn.execute(
                        """
                        UPDATE conflict_resolution_members
                        SET member_binding_hash = ?
                        WHERE receipt_id = ? AND card_id = ?
                        """,
                        (
                            "0" * 64,
                            resolved["resolution_id"],
                            second["card_id"],
                        ),
                    )
                    conn.commit()
                finally:
                    conn.close()
                divergent = semantic_integrity_report(root)
                self.assertFalse(divergent["ok"], divergent)
                self.assertEqual(
                    divergent["checks"][
                        "invalid_conflict_resolution_receipts"
                    ],
                    1,
                )

    def test_quarantine_can_retire_only_its_own_boundary_divergence(self) -> None:
        for action in ("dismiss", "supersede"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                first = record_project_state(
                    root,
                    session_id="boundary-receipt-a",
                    agent_id="agent-a",
                    project_id="receipt-boundary-project",
                    decisions=["Use alpha routing"],
                )
                second = record_project_state(
                    root,
                    session_id="boundary-receipt-b",
                    agent_id="agent-b",
                    project_id="receipt-boundary-project",
                    decisions=["Do not use alpha routing"],
                )
                detected = detect_conflicts(
                    root,
                    card_id=str(first["card_id"]),
                )
                self.assertEqual(detected["conflict_count"], 1, detected)
                resolved = resolve_conflict(
                    root,
                    card_id=str(second["card_id"]),
                    action=action,
                )
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE cards SET project_id = ? WHERE id = ?",
                        ("moved-receipt-project", second["card_id"]),
                    )
                    _sync_cards(root, conn, str(second["card_id"]))
                    conn.commit()
                    moved_row_before = tuple(
                        conn.execute(
                            "SELECT * FROM cards WHERE id = ?",
                            (second["card_id"],),
                        ).fetchone()
                    )
                finally:
                    conn.close()

                moved_scope = repair_invalid_project_state_checkpoints(
                    root,
                    project_id="moved-receipt-project",
                    dry_run=False,
                )
                conn = connect(root)
                try:
                    moved_row_after = tuple(
                        conn.execute(
                            "SELECT * FROM cards WHERE id = ?",
                            (second["card_id"],),
                        ).fetchone()
                    )
                finally:
                    conn.close()

                self.assertEqual(moved_scope["quarantined_count"], 0)
                self.assertEqual(moved_scope["sidecar_sync"]["synced"], 0)
                self.assertNotIn(
                    str(second["card_id"]),
                    json.dumps(moved_scope, sort_keys=True),
                )
                self.assertEqual(moved_row_after, moved_row_before)

                repaired = repair_invalid_project_state_checkpoints(
                    root,
                    project_id="receipt-boundary-project",
                    dry_run=False,
                )
                report = semantic_integrity_report(root)

                self.assertEqual(repaired["quarantined_count"], 1)
                self.assertTrue(report["ok"], report)
                self.assertEqual(
                    report["retired_conflict_resolution_receipt_ids"],
                    [resolved["resolution_id"]],
                )

    def test_retired_supersede_receipt_cannot_repromote_a_cleaned_peer(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="retired-peer-a",
                agent_id="agent-a",
                project_id="retired-peer-project",
                decisions=["Use alpha routing"],
            )
            second = record_project_state(
                root,
                session_id="retired-peer-b",
                agent_id="agent-b",
                project_id="retired-peer-project",
                decisions=["Do not use alpha routing"],
            )
            detected = detect_conflicts(root, card_id=str(first["card_id"]))
            self.assertEqual(detected["conflict_count"], 1, detected)
            resolve_conflict(
                root,
                card_id=str(second["card_id"]),
                action="supersede",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = summary || ' damaged' WHERE id = ?",
                    (second["card_id"],),
                )
                _sync_cards(root, conn, str(second["card_id"]))
                conn.commit()
            finally:
                conn.close()
            repaired = repair_invalid_project_state_checkpoints(
                root,
                project_id="retired-peer-project",
                dry_run=False,
            )
            self.assertEqual(repaired["quarantined_count"], 1)
            self.assertTrue(semantic_integrity_report(root)["ok"])

            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET status = 'active' WHERE id = ?",
                    (first["card_id"],),
                )
                _sync_cards(root, conn, str(first["card_id"]))
                conn.commit()
            finally:
                conn.close()
            promoted = semantic_integrity_report(root)

            self.assertFalse(promoted["ok"], promoted)
            self.assertEqual(
                promoted["checks"]["invalid_conflict_resolution_receipts"],
                1,
            )

    def test_semantic_report_rejects_a_divergent_resolution_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                first = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Dismissed Authority Route",
                    summary="Use dismissed authority routing.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="dismiss-receipt",
                    project_id="dismiss-receipt-project",
                )
                second = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Dismissed Authority Route",
                    summary="Do not use dismissed authority routing.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="dismiss-receipt",
                    project_id="dismiss-receipt-project",
                )
                conn.commit()
            finally:
                conn.close()
            detected = detect_conflicts(root, card_id=first)
            self.assertEqual(detected["conflict_count"], 1, detected)
            resolved = resolve_conflict(root, card_id=first, action="dismiss")
            self.assertTrue(semantic_integrity_report(root)["ok"])

            conn = connect(root)
            try:
                conn.execute(
                    """
                    UPDATE conflict_resolution_members
                    SET member_binding_hash = ?
                    WHERE receipt_id = ? AND card_id = ?
                    """,
                    ("0" * 64, resolved["resolution_id"], second),
                )
                conn.commit()
            finally:
                conn.close()

            report = semantic_integrity_report(root)

            self.assertFalse(report["ok"], report)
            self.assertEqual(
                report["failing"]["invalid_conflict_resolution_receipts"],
                1,
            )

    def test_three_member_resolution_authorizes_and_binds_complete_fan_in(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_ids = [
                    create_card(
                        conn,
                        root=root,
                        card_type="decision",
                        title="Authority Route",
                        summary=summary,
                        source_refs=[],
                        visibility_scope="project",
                        session_id="authority-resolution",
                        project_id="authority-resolution-project",
                    )
                    for summary in (
                        "Use authority routing for deployment.",
                        "Do not use authority routing for deployment.",
                        "Never disable authority routing for deployment.",
                    )
                ]
                conn.commit()
            finally:
                conn.close()
            detected = detect_conflicts(root, card_id=card_ids[1])
            self.assertEqual(detected["conflict_count"], 1, detected)
            self.assertEqual(set(detected["conflicts"][0]["card_ids"]), set(card_ids))

            resolved = resolve_conflict(
                root,
                card_id=card_ids[1],
                action="supersede",
            )
            report = semantic_integrity_report(root)
            snap = snapshot(root, reason="resolved_authority_receipt")
            manifest = json.loads(
                Path(str(snap["snapshot_manifest_uri"])).read_text(encoding="utf-8")
            )

            self.assertTrue(resolved["ok"], resolved)
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["checks"]["supersession_asymmetric_links"], 0)
            self.assertEqual(
                report["checks"]["invalid_conflict_resolution_receipts"],
                0,
            )
            self.assertEqual(manifest["counts"]["conflict_resolution_receipts"], 1)
            self.assertEqual(manifest["counts"]["conflict_resolution_members"], 3)

            non_direct_peer = card_ids[0]
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET superseded_by_card_id = NULL WHERE id = ?",
                    (non_direct_peer,),
                )
                _sync_cards(root, conn, non_direct_peer)
                conn.commit()
            finally:
                conn.close()

            divergent = semantic_integrity_report(root)
            self.assertFalse(divergent["ok"], divergent)
            self.assertEqual(
                divergent["checks"]["invalid_conflict_resolution_receipts"],
                1,
            )

    def test_cross_agent_project_state_edge_requires_resolution_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first, second = _record_two_states(
                root,
                first_agent="agent-a",
                second_agent="agent-b",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET superseded_by_card_id = ? WHERE id = ?",
                    (second["card_id"], first["card_id"]),
                )
                conn.execute(
                    "UPDATE cards SET supersedes_card_id = ? WHERE id = ?",
                    (first["card_id"], second["card_id"]),
                )
                _sync_cards(
                    root,
                    conn,
                    str(first["card_id"]),
                    str(second["card_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            report = semantic_integrity_report(root)

            self.assertFalse(report["ok"], report)
            self.assertEqual(
                report["checks"][
                    "unproven_cross_agent_project_state_edges"
                ],
                1,
            )

    def test_project_state_supersession_cannot_cross_card_types(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="mixed-edge-session",
                agent_id="mixed-edge-agent",
                project_id="mixed-edge-project",
                objective="Preserve project-state authority type",
            )
            conn = connect(root)
            try:
                decision = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="Mixed authority successor",
                    summary="A generic decision cannot own project-state lineage.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="mixed-edge-session",
                    project_id="mixed-edge-project",
                )
                conn.execute(
                    "UPDATE cards SET supersedes_card_id = ? WHERE id = ?",
                    (state["card_id"], decision),
                )
                conn.execute(
                    "UPDATE cards SET superseded_by_card_id = ? WHERE id = ?",
                    (decision, state["card_id"]),
                )
                _sync_cards(root, conn, str(state["card_id"]), decision)
                conn.commit()
            finally:
                conn.close()

            report = semantic_integrity_report(root)

            self.assertFalse(report["ok"], report)
            self.assertEqual(
                report["checks"]["mixed_project_state_supersession_edges"],
                1,
            )


if __name__ == "__main__":
    unittest.main()
