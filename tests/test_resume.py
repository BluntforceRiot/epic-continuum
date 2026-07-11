from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import continuum.core.store as store_module
from continuum.core.config import configure_personal_profile, default_config, write_config
from continuum.core.store import (
    NON_CURRENT_CARD_STATUSES,
    append_scroll_event,
    compile_context,
    connect,
    create_card,
    cue_recall,
    enqueue_job,
    estimate_tokens,
    ingest_file,
    init_db,
    record_project_state,
    recover_thread,
    reinforce_card_recall,
    resume_latest,
    roll_scroll_segment,
)
from continuum.core.workers import detect_conflicts, prune_memory, run_worker_pass


class ResumeLatestTests(unittest.TestCase):
    def test_resume_discovers_latest_project_state_without_thread_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="resume-session",
                agent_id="codex-sol",
                project_id="resume-project",
                objective="Resume the project",
                open_tasks=["verify the handoff"],
            )

            result = resume_latest(root, token_budget=1200)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["resume_profile"], "latest")
            self.assertEqual(result["session_id"], "resume-session")
            self.assertEqual(result["project_id"], "resume-project")
            self.assertEqual(result["discovery"]["source"], "project_state_card")
            self.assertIn("verify the handoff", result["packet_text"])

    def test_resume_can_discover_latest_state_for_a_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="project-session",
                agent_id="codex-sol",
                project_id="target-project",
                objective="Targeted resume",
            )

            result = resume_latest(root, project_id="target-project", token_budget=800)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["session_id"], "project-session")
            self.assertEqual(result["discovery"]["requested_project_id"], "target-project")

    def test_resume_discovery_skips_private_project_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="visible-session",
                agent_id="codex-sol",
                project_id="visible-project",
                objective="VISIBLE-CHECKPOINT",
            )
            record_project_state(
                root,
                session_id="private-session",
                agent_id="codex-sol",
                project_id="private-project",
                objective="PRIVATE-CHECKPOINT",
                metadata={"visibility_scope": "private"},
            )

            result = resume_latest(root, token_budget=800, model_assist=False)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["session_id"], "visible-session")
            self.assertEqual(result["project_id"], "visible-project")
            self.assertIn("VISIBLE-CHECKPOINT", result["packet_text"])
            self.assertNotIn("PRIVATE-CHECKPOINT", result["packet_text"])

    def test_resume_scroll_fallback_skips_global_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            append_scroll_event(
                root,
                session_id="visible-scroll-session",
                event_type="message",
                role="user",
                content="VISIBLE-SCROLL-EVENT",
                metadata={"visibility_scope": "session"},
            )
            append_scroll_event(
                root,
                session_id="global-scroll-session",
                event_type="message",
                role="user",
                content="GLOBAL-SCROLL-EVENT",
                metadata={"visibility_scope": "global"},
            )

            result = resume_latest(root, token_budget=800, model_assist=False)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["discovery"]["source"], "scroll_event")
            self.assertEqual(result["session_id"], "visible-scroll-session")
            self.assertEqual(result["recent_event_count"], 1)
            self.assertIn("VISIBLE-SCROLL-EVENT", result["packet_text"])
            self.assertNotIn("GLOBAL-SCROLL-EVENT", result["packet_text"])

    def test_unscoped_resume_skips_stale_partitions_without_poisoning_fresh_scroll(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            stale = record_project_state(
                root,
                session_id="stale-session",
                agent_id="codex-sol",
                project_id="stale-project",
                objective="Archived checkpoint",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET status = 'archived' WHERE id = ?",
                    (stale["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()
            append_scroll_event(
                root,
                session_id="fresh-session",
                event_type="message",
                role="user",
                content="FRESH-RECOVERABLE-SCROLL",
                metadata={"visibility_scope": "project", "project_id": "fresh-project"},
            )
            append_scroll_event(
                root,
                session_id="stale-session",
                event_type="message",
                role="user",
                content="NEWER-BUT-STALE-PARTITION",
                metadata={"visibility_scope": "project", "project_id": "stale-project"},
            )

            scoped = resume_latest(root, project_id="stale-project", model_assist=False)
            unscoped = resume_latest(root, model_assist=False)

            self.assertFalse(scoped["ok"], scoped)
            self.assertEqual(scoped["reason"], "no_current_project_state")
            self.assertTrue(unscoped["ok"], unscoped)
            self.assertEqual(unscoped["discovery"]["source"], "scroll_event")
            self.assertEqual(unscoped["session_id"], "fresh-session")
            self.assertEqual(unscoped["project_id"], "fresh-project")
            self.assertIn("FRESH-RECOVERABLE-SCROLL", unscoped["packet_text"])
            self.assertNotIn("NEWER-BUT-STALE-PARTITION", unscoped["packet_text"])

    def test_resume_reports_missing_state_without_writing_a_packet(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)

            result = resume_latest(root)

            self.assertFalse(result["ok"])
            self.assertEqual(result["reason"], "no_resume_state")
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_fails_closed_when_discovered_checkpoint_becomes_contested(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="interleaved-session",
                agent_id="codex-sol",
                project_id="interleaved-project",
                objective="Do not return a mixed checkpoint",
            )
            original_recover = store_module.recover_thread

            def interleaved_recover(*args, **kwargs):
                conn = connect(root)
                try:
                    conn.execute(
                        "UPDATE cards SET conflict_group = 'interleaved-conflict' WHERE id = ?",
                        (state["card_id"],),
                    )
                    conn.commit()
                finally:
                    conn.close()
                return original_recover(*args, **kwargs)

            with patch.object(
                store_module,
                "recover_thread",
                side_effect=interleaved_recover,
            ):
                result = resume_latest(root, model_assist=False)

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "checkpoint_changed_during_resume")
            self.assertEqual(result["discovery"]["checkpoint_id"], state["card_id"])
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_fails_closed_when_a_newer_project_state_arrives_after_discovery(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="old-session",
                agent_id="codex-sol",
                project_id="old-project",
                objective="Older selected checkpoint",
            )
            original_recover = store_module.recover_thread

            def interleaved_recover(*args, **kwargs):
                record_project_state(
                    root,
                    session_id="new-session",
                    agent_id="codex-sol",
                    project_id="new-project",
                    objective="Newer checkpoint inserted after discovery",
                )
                return original_recover(*args, **kwargs)

            with patch.object(
                store_module,
                "recover_thread",
                side_effect=interleaved_recover,
            ):
                result = resume_latest(root, model_assist=False)

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "checkpoint_changed_during_resume")
            self.assertEqual(result["session_id"], "old-session")
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_fails_closed_when_a_newer_scroll_event_arrives_after_discovery(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            old_event = append_scroll_event(
                root,
                session_id="old-scroll-session",
                event_type="message",
                role="user",
                content="Older Scroll fallback",
                metadata={"visibility_scope": "session"},
            )
            original_recover = store_module.recover_thread

            def interleaved_recover(*args, **kwargs):
                append_scroll_event(
                    root,
                    session_id="new-scroll-session",
                    event_type="message",
                    role="user",
                    content="Newer Scroll fallback inserted after discovery",
                    metadata={"visibility_scope": "session"},
                )
                return original_recover(*args, **kwargs)

            with patch.object(
                store_module,
                "recover_thread",
                side_effect=interleaved_recover,
            ):
                result = resume_latest(root, model_assist=False)

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "checkpoint_changed_during_resume")
            self.assertEqual(
                result["discovery"]["checkpoint_id"], old_event["event_id"]
            )
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_recovery_recent_event_limit_is_bounded_and_non_negative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            with self.assertRaisesRegex(ValueError, "recent_event_limit"):
                recover_thread(root, session_id="bounded-session", recent_event_limit=-1)
            with self.assertRaisesRegex(ValueError, "recent_event_limit"):
                resume_latest(root, recent_event_limit=-1)
            self.assertFalse(root.exists())

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="bounded-session",
                agent_id="codex-sol",
                project_id="bounded-project",
                objective="Bound recovery scroll output",
            )
            for index in range(3):
                append_scroll_event(
                    root,
                    session_id="bounded-session",
                    event_type="message",
                    role="user",
                    content=f"recent bounded event {index}",
                    metadata={"project_id": "bounded-project", "visibility_scope": "project"},
                )

            none = recover_thread(
                root,
                session_id="bounded-session",
                project_id="bounded-project",
                recent_event_limit=0,
            )
            one = recover_thread(
                root,
                session_id="bounded-session",
                project_id="bounded-project",
                recent_event_limit=1,
            )

            self.assertEqual(none["recent_event_count"], 0)
            self.assertEqual(one["recent_event_count"], 1)

    def test_resume_packet_budget_bounds_complete_packet_without_raw_duplication(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="bounded-packet-session",
                agent_id="codex-sol",
                project_id="bounded-packet-project",
                objective="Bound the complete recovery packet",
            )
            for index in range(24):
                append_scroll_event(
                    root,
                    session_id="bounded-packet-session",
                    event_type="message",
                    role="user",
                    content=f"LARGE-PACKET-EVENT-{index}:" + ("x" * 4096),
                    metadata={
                        "visibility_scope": "project",
                        "project_id": "bounded-packet-project",
                    },
                )
            configure_personal_profile(root, safe_context_ceiling=256)

            result = resume_latest(
                root,
                project_id="bounded-packet-project",
                recent_event_limit=24,
                model_assist=False,
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["packet_token_budget"], 256)
            self.assertEqual(result["recent_event_count"], 24)
            self.assertLessEqual(result["packet_estimated_tokens"], 256)
            self.assertEqual(
                result["packet_estimated_tokens"],
                estimate_tokens(result["packet_text"]),
            )
            self.assertTrue(result["packet_truncated"], result)
            self.assertIn('"session_id":"bounded-packet-session"', result["packet_text"])
            self.assertIn('"project_id":"bounded-packet-project"', result["packet_text"])
            self.assertIn('"recent_event_count":24', result["packet_text"])
            self.assertNotIn("## Recent Scroll", result["packet_text"])
            self.assertNotIn("## Recalled Cards", result["packet_text"])
            self.assertLessEqual(result["packet_text"].count("LARGE-PACKET-EVENT-23"), 1)

    def test_resume_packet_preserves_actionable_and_operational_details(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["context"]["scroll_event_fetch_limit"] = 2
            write_config(root, config)
            record_project_state(
                root,
                session_id="detail-session",
                agent_id="codex-sol",
                project_id="detail-project",
                objective="X" * 1200,
                decisions=["KEEP-RESTORE-PROOF"],
                open_tasks=["MUST-RUN-RESTORE-DRILL"],
            )
            source = Path(tmp) / "recovery-source.md"
            source.write_text("Recovery source evidence.\n", encoding="utf-8")
            ingested = ingest_file(
                root,
                path=source,
                title="RECOVERY-BOOK-MARKER",
            )
            conn = connect(root)
            try:
                create_card(
                    conn,
                    root=root,
                    card_type="reference",
                    title="Detail project recovery reference",
                    summary="Use the recovery book for the detail project.",
                    source_refs=[{"book_id": ingested["book_id"]}],
                    visibility_scope="project",
                    session_id="detail-session",
                    project_id="detail-project",
                )
                enqueue_job(
                    conn,
                    role="archivist",
                    job_type="RECOVERY-JOB-MARKER",
                    priority=5,
                    payload={
                        "visibility_scope": "project",
                        "session_id": "detail-session",
                        "project_id": "detail-project",
                        "next_step": "PRESERVE-JOB-PAYLOAD",
                    },
                )
                conn.commit()
            finally:
                conn.close()
            for index in range(3):
                append_scroll_event(
                    root,
                    session_id="detail-session",
                    event_type="message",
                    role="user",
                    content=f"newer detail event {index}",
                    metadata={
                        "visibility_scope": "project",
                        "project_id": "detail-project",
                    },
                )

            result = resume_latest(
                root,
                project_id="detail-project",
                token_budget=6000,
                model_assist=False,
            )

            self.assertTrue(result["ok"], result)
            self.assertIn("MUST-RUN-RESTORE-DRILL", result["packet_text"])
            self.assertIn("KEEP-RESTORE-PROOF", result["packet_text"])
            self.assertIn("RECOVERY-JOB-MARKER", result["packet_text"])
            self.assertIn("PRESERVE-JOB-PAYLOAD", result["packet_text"])
            self.assertIn("RECOVERY-BOOK-MARKER", result["packet_text"])
            self.assertNotIn("MUST-RUN-RESTORE-DRILL", result["context"]["context_text"])

    def test_resume_pins_selected_checkpoint_ahead_of_higher_salience_cards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="crowded-session",
                agent_id="codex-sol",
                project_id="crowded-project",
                objective="X" * 20000,
                decisions=["PINNED-CHECKPOINT-DECISION"],
                open_tasks=["PINNED-CHECKPOINT-TASK"],
            )
            conn = connect(root)
            try:
                for index in range(15):
                    create_card(
                        conn,
                        root=root,
                        card_type="reference",
                        title=f"High-salience reference {index}",
                        summary=f"Crowded project reference {index}",
                        source_refs=[],
                        salience=1.0,
                        visibility_scope="project",
                        session_id="crowded-session",
                        project_id="crowded-project",
                    )
                conn.commit()
            finally:
                conn.close()

            result = resume_latest(
                root,
                project_id="crowded-project",
                token_budget=3000,
                model_assist=False,
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["discovery"]["checkpoint_id"], state["card_id"])
            self.assertIn("PINNED-CHECKPOINT-TASK", result["packet_text"])
            self.assertIn("PINNED-CHECKPOINT-DECISION", result["packet_text"])

    def test_resume_respects_a_valid_context_ceiling_below_256_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["context"]["default_token_budget"] = 100
            config["context"]["max_token_budget"] = 100
            config["personal_profile"]["safe_context_ceiling"] = 100
            write_config(root, config)
            record_project_state(
                root,
                session_id="small-budget-session",
                agent_id="codex-sol",
                project_id="small-budget-project",
                objective="Keep the complete packet within the configured ceiling",
            )

            result = resume_latest(root, project_id="small-budget-project", token_budget=1000)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["personal_profile"]["safe_context_ceiling"], 100)
            self.assertEqual(result["packet_token_budget"], 100)
            self.assertLessEqual(result["packet_estimated_tokens"], 100)
            packet_lines = result["packet_text"].strip().splitlines()
            self.assertEqual(packet_lines[0], "```json")
            self.assertEqual(packet_lines[-1], "```")
            metadata = json.loads("\n".join(packet_lines[1:-1]))
            self.assertEqual(
                metadata["packet_estimated_tokens"],
                result["packet_estimated_tokens"],
            )
            self.assertEqual(metadata["packet_token_budget"], 100)
            self.assertTrue(metadata["packet_truncated"])

    def test_resume_refuses_a_budget_smaller_than_the_compact_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["context"]["default_token_budget"] = 1
            config["context"]["max_token_budget"] = 1
            config["personal_profile"]["safe_context_ceiling"] = 1
            write_config(root, config)
            record_project_state(
                root,
                session_id="tiny-session",
                agent_id="codex-sol",
                project_id="tiny-project",
                objective="Do not emit malformed recovery markup",
            )

            result = resume_latest(root, model_assist=False)

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "packet_budget_too_small")
            self.assertEqual(result["packet_token_budget"], 1)
            self.assertGreater(result["minimum_packet_tokens"], 1)
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_planner_balances_sources_and_respects_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="planner-session",
                agent_id="codex-sol",
                project_id="planner-project",
                objective="Planner evidence",
                decisions=["Use source citations"],
            )

            packet = compile_context(
                root,
                session_id="planner-session",
                project_id="planner-project",
                query="source citations",
                token_budget=500,
                planner_profile="resume",
                create=False,
            )

            self.assertTrue(packet["ok"], packet)
            self.assertEqual(packet["planner_profile"], "resume")
            self.assertLessEqual(packet["estimated_tokens"], 500)
            self.assertTrue(packet["planner_trace"])
            self.assertTrue(packet["sections"])

    def test_resume_planner_respects_configured_scroll_fetch_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["context"]["scroll_event_fetch_limit"] = 2
            write_config(root, config)
            for index in range(10):
                append_scroll_event(
                    root,
                    session_id="fetch-cap-session",
                    event_type="message",
                    role="user",
                    content=f"fetch-cap-event-{index}",
                    metadata={"visibility_scope": "session"},
                )

            packet = compile_context(
                root,
                session_id="fetch-cap-session",
                token_budget=6000,
                planner_profile="resume",
                create=False,
            )

            recent = next(
                section
                for section in packet["sections"]
                if section["kind"] == "recent_scroll"
            )
            self.assertEqual(
                recent["ids"],
                ["scroll:fetch-cap-session:10", "scroll:fetch-cap-session:9"],
            )

    def test_sequential_project_state_remains_resumable_but_cross_agent_disagreement_conflicts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="checkpoint-one",
                agent_id="codex-sol",
                project_id="checkpoint-project",
                objective="Continue the release",
                open_tasks=["run focused tests"],
            )
            record_project_state(
                root,
                session_id="checkpoint-two",
                agent_id="codex-sol",
                project_id="checkpoint-project",
                objective="Continue the release",
                open_tasks=["run the full suite"],
            )

            detected = detect_conflicts(root)
            resumed = resume_latest(
                root,
                project_id="checkpoint-project",
                model_assist=False,
            )

            self.assertEqual(detected["conflict_count"], 0, detected)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["session_id"], "checkpoint-two")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="agent-a-session",
                agent_id="agent-a",
                project_id="shared-project",
                objective="Use alpha routing for deployment",
            )
            record_project_state(
                root,
                session_id="agent-b-session",
                agent_id="agent-b",
                project_id="shared-project",
                objective="Do not use alpha routing for deployment",
            )

            detected = detect_conflicts(root)

            self.assertEqual(detected["conflict_count"], 1, detected)

    def test_librarian_does_not_contest_project_state_with_derived_scroll_segment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="normal-session",
                agent_id="codex-sol",
                project_id="alpha-project",
                objective="Use alpha routing",
            )
            append_scroll_event(
                root,
                session_id="normal-session",
                event_type="message",
                role="user",
                content="Do not use alpha routing",
                metadata={"visibility_scope": "project", "project_id": "alpha-project"},
            )
            segment = roll_scroll_segment(
                root,
                session_id="normal-session",
                start_seq=1,
                end_seq=2,
            )

            workers = run_worker_pass(
                root,
                roles=["librarian"],
                limit=10,
                maintenance=False,
            )
            resumed = resume_latest(
                root,
                project_id="alpha-project",
                model_assist=False,
            )

            self.assertTrue(workers["ok"], workers)
            conn = connect(root)
            try:
                groups = {
                    str(row["id"]): row["conflict_group"]
                    for row in conn.execute(
                        "SELECT id, conflict_group FROM cards WHERE id IN (?, ?)",
                        (state["card_id"], segment["card_id"]),
                    )
                }
            finally:
                conn.close()
            self.assertEqual(groups[state["card_id"]], None)
            self.assertEqual(groups[segment["card_id"]], None)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["session_id"], "normal-session")
            self.assertEqual(resumed["project_id"], "alpha-project")

    def test_resume_planner_preserves_descending_scroll_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            for seq in range(1, 16):
                append_scroll_event(
                    root,
                    session_id="ordered-session",
                    event_type="message",
                    role="user",
                    content=f"ordered evidence {seq}",
                    metadata={"project_id": "ordered-project", "visibility_scope": "project"},
                )

            packet = compile_context(
                root,
                session_id="ordered-session",
                project_id="ordered-project",
                token_budget=6000,
                planner_profile="resume",
                create=False,
            )

            recent = next(section for section in packet["sections"] if section["kind"] == "recent_scroll")
            self.assertEqual(
                recent["ids"],
                [f"scroll:ordered-session:{seq}" for seq in range(15, 0, -1)],
            )

    def test_resume_planner_excludes_superseded_and_contested_cue_cards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            superseded = record_project_state(
                root,
                session_id="superseded-session",
                agent_id="codex-sol",
                project_id="cue-project",
                objective="Retire the obsolete quasar protocol",
            )
            contested = record_project_state(
                root,
                session_id="contested-session",
                agent_id="codex-sol",
                project_id="cue-project",
                objective="Resolve the disputed nebula protocol",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET superseded_by_card_id = ? WHERE id = ?",
                    ("replacement-card", superseded["card_id"]),
                )
                conn.execute(
                    "UPDATE cards SET conflict_group = ? WHERE id = ?",
                    ("conflict-group", contested["card_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            packet = compile_context(
                root,
                session_id="superseded-session",
                project_id="cue-project",
                query="obsolete quasar disputed nebula",
                token_budget=6000,
                cue_recall_limit=20,
                planner_profile="resume",
                create=False,
            )

            selected_ids = {
                item_id
                for section in packet["sections"]
                for item_id in section["ids"]
            }
            excluded_cue_ids = {
                item["id"]
                for item in packet["planner_trace"]
                if item.get("source") == "cue_recall"
                and item.get("reason") == "superseded_or_contested"
            }
            expected_cue_ids = {
                f"cue:card:{superseded['card_id']}",
                f"cue:card:{contested['card_id']}",
            }
            self.assertTrue(expected_cue_ids.isdisjoint(selected_ids))
            self.assertTrue(excluded_cue_ids.issubset(expected_cue_ids))

    def test_one_way_lineage_excludes_predecessor_but_keeps_successor_everywhere(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                predecessor = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="One Way Quasar Lineage",
                    summary="ONE-WAY-PREDECESSOR: use the old quasar authority.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="one-way-session",
                    project_id="one-way-project",
                )
                successor = create_card(
                    conn,
                    root=root,
                    card_type="decision",
                    title="One Way Quasar Lineage",
                    summary="ONE-WAY-SUCCESSOR: use the current quasar authority.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="one-way-session",
                    project_id="one-way-project",
                )
                conn.execute(
                    "UPDATE cards SET supersedes_card_id = ? WHERE id = ?",
                    (predecessor, successor),
                )
                conn.commit()
            finally:
                conn.close()

            packet = compile_context(
                root,
                session_id="one-way-session",
                project_id="one-way-project",
                query="one way quasar lineage authority",
                token_budget=6000,
                planner_profile="resume",
                create=False,
            )
            selected_ids = {
                str(item_id)
                for section in packet["sections"]
                for item_id in section.get("ids", [])
            }
            self.assertNotIn(predecessor, selected_ids, packet)
            self.assertIn(successor, selected_ids, packet)
            self.assertNotIn("ONE-WAY-PREDECESSOR", packet["context_text"])
            self.assertIn("ONE-WAY-SUCCESSOR", packet["context_text"])

            recalled = cue_recall(
                root,
                cue="one way quasar lineage authority",
                project_id="one-way-project",
                limit=50,
                max_associations=50,
                create=False,
            )
            recalled_card_ids = {
                str(item["id"])
                for item in recalled["results"]
                if item.get("kind") == "card"
            }
            self.assertNotIn(predecessor, recalled_card_ids, recalled)
            self.assertIn(successor, recalled_card_ids, recalled)

            conn = connect(root)
            try:
                reinforced = reinforce_card_recall(
                    conn,
                    card_ids=[predecessor, successor],
                    root=root,
                )
                conn.commit()
                counts = {
                    str(row["id"]): int(row["recall_count"])
                    for row in conn.execute(
                        "SELECT id, recall_count FROM cards WHERE id IN (?, ?)",
                        (predecessor, successor),
                    )
                }
            finally:
                conn.close()
            self.assertEqual(reinforced, 1)
            self.assertEqual(counts[predecessor], 0)
            self.assertEqual(counts[successor], 1)

    def test_public_planners_and_cue_recall_exclude_every_noncurrent_card_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                card_ids: dict[str, str] = {}
                for status in sorted(NON_CURRENT_CARD_STATUSES):
                    card_id = create_card(
                        conn,
                        root=root,
                        card_type="decision",
                        title=f"Lifecycle Quasar {status}",
                        summary=f"LIFECYCLE-MARKER-{status}: retain this as non-current evidence.",
                        source_refs=[],
                        visibility_scope="project",
                        session_id="lifecycle-session",
                        project_id="lifecycle-project",
                    )
                    if status != "archived":
                        conn.execute("UPDATE cards SET status = ? WHERE id = ?", (status, card_id))
                    card_ids[status] = card_id
                conn.commit()
            finally:
                conn.close()
            archived = prune_memory(
                root,
                topic="Lifecycle Quasar archived",
                action="archive",
            )
            self.assertEqual(archived["card_ids"], [card_ids["archived"]])

            for planner_profile in ("legacy", "resume"):
                packet = compile_context(
                    root,
                    session_id="lifecycle-session",
                    project_id="lifecycle-project",
                    query="lifecycle quasar marker",
                    token_budget=6000,
                    planner_profile=planner_profile,
                    include_cue_recall=True,
                    create=False,
                )
                selected_ids = {
                    str(item_id)
                    for section in packet.get("sections", [])
                    for item_id in (section.get("ids") or section.get("card_ids") or [])
                }
                self.assertTrue(set(card_ids.values()).isdisjoint(selected_ids), packet)
                self.assertNotIn("LIFECYCLE-MARKER", packet["context_text"])

            recalled = cue_recall(
                root,
                cue="lifecycle quasar marker",
                project_id="lifecycle-project",
                limit=50,
                max_associations=50,
                create=False,
            )
            recalled_card_ids = {
                str(item["id"])
                for item in recalled["results"]
                if item.get("kind") == "card"
            }
            self.assertTrue(set(card_ids.values()).isdisjoint(recalled_card_ids), recalled)

    def test_pointerless_historical_and_superseded_state_block_scroll_fallback(self) -> None:
        for status in ("historical", "superseded"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                state = record_project_state(
                    root,
                    session_id=f"{status}-session",
                    agent_id="codex-sol",
                    project_id=f"{status}-project",
                    objective=f"Pointerless {status} checkpoint",
                )
                conn = connect(root)
                try:
                    conn.execute(
                        """
                        UPDATE cards
                        SET status = ?, supersedes_card_id = NULL,
                            superseded_by_card_id = NULL, conflict_group = NULL
                        WHERE id = ?
                        """,
                        (status, state["card_id"]),
                    )
                    conn.commit()
                finally:
                    conn.close()

                result = resume_latest(root, project_id=f"{status}-project")

                self.assertFalse(result["ok"], result)
                self.assertEqual(result["reason"], "no_current_project_state")
                self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_explicit_resume_mode_requires_and_honors_supplied_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="explicit-session",
                agent_id="codex-sol",
                project_id="explicit-project",
                objective="Explicit resume",
            )
            configure_personal_profile(root, resume_mode="explicit")

            missing_scope = resume_latest(root)

            self.assertFalse(missing_scope["ok"])
            self.assertEqual(missing_scope["reason"], "explicit_resume_requires_scope")
            self.assertFalse((root / "exports" / "thread_recovery").exists())

            scoped = resume_latest(root, project_id="explicit-project", token_budget=800)

            self.assertTrue(scoped["ok"], scoped)
            self.assertEqual(scoped["resume_profile"], "explicit")
            self.assertEqual(scoped["session_id"], "explicit-session")

    def test_latest_project_mode_requires_then_uses_default_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="target-session",
                agent_id="codex-sol",
                project_id="target-project",
                objective="Default project state",
            )
            record_project_state(
                root,
                session_id="other-session",
                agent_id="codex-sol",
                project_id="other-project",
                objective="Other project state",
            )
            configure_personal_profile(root, resume_mode="latest_project", clear_default_project=True)

            missing_default = resume_latest(root)

            self.assertFalse(missing_default["ok"])
            self.assertEqual(missing_default["reason"], "latest_project_requires_default_project")
            self.assertFalse((root / "exports" / "thread_recovery").exists())

            configure_personal_profile(root, default_project_id="target-project")
            resumed = resume_latest(root, token_budget=800)

            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["resume_profile"], "latest_project")
            self.assertEqual(resumed["project_id"], "target-project")
            self.assertEqual(resumed["session_id"], "target-session")

    def test_resume_canonicalizes_supplied_partition_aliases_before_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["security"]["secret_scan_action"] = "warn"
            write_config(root, config)
            secret_session = "sk-" + "S" * 40
            secret_project = "sk-" + "P" * 40
            state = record_project_state(
                root,
                session_id=secret_session,
                agent_id="codex-sol",
                project_id=secret_project,
                objective="Alias lookup checkpoint",
            )
            conn = connect(root)
            try:
                row = conn.execute(
                    "SELECT session_id, project_id FROM cards WHERE id = ?",
                    (state["card_id"],),
                ).fetchone()
            finally:
                conn.close()

            result = resume_latest(
                root,
                session_id=secret_session,
                project_id=secret_project,
                token_budget=800,
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["session_id"], row["session_id"])
            self.assertEqual(result["project_id"], row["project_id"])
            self.assertEqual(result["discovery"]["requested_session_id"], row["session_id"])
            self.assertEqual(result["discovery"]["requested_project_id"], row["project_id"])
            self.assertNotEqual(result["session_id"], secret_session)
            self.assertNotEqual(result["project_id"], secret_project)

    def test_resume_orders_current_checkpoints_by_immutable_creation_time(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            older = record_project_state(
                root,
                session_id="older-session",
                agent_id="codex-sol",
                project_id="checkpoint-project",
                objective="Older checkpoint",
            )
            newer = record_project_state(
                root,
                session_id="newer-session",
                agent_id="codex-sol",
                project_id="checkpoint-project",
                objective="Newer checkpoint",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET created_at = ?, updated_at = ? WHERE id = ?",
                    ("2026-01-01T00:00:00+00:00", "2099-01-01T00:00:00+00:00", older["card_id"]),
                )
                conn.execute(
                    "UPDATE cards SET created_at = ?, updated_at = ? WHERE id = ?",
                    ("2026-02-01T00:00:00+00:00", "2000-01-01T00:00:00+00:00", newer["card_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            result = resume_latest(root, project_id="checkpoint-project", token_budget=800)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["session_id"], "newer-session")
            self.assertEqual(result["discovery"]["checkpoint_at"], "2026-02-01T00:00:00+00:00")

    def test_resume_breaks_same_timestamp_ties_by_insertion_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            older = record_project_state(
                root,
                session_id="same-second-older",
                agent_id="codex-sol",
                project_id="same-second-project",
                objective="Earlier insertion",
            )
            newer = record_project_state(
                root,
                session_id="same-second-newer",
                agent_id="codex-sol",
                project_id="same-second-project",
                objective="Later insertion",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET created_at = ? WHERE id IN (?, ?)",
                    ("2026-02-01T00:00:00+00:00", older["card_id"], newer["card_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            result = resume_latest(root, project_id="same-second-project", token_budget=800)

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["session_id"], "same-second-newer")

    def test_resume_does_not_fall_back_to_scroll_when_state_cards_are_not_current(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            superseded = record_project_state(
                root,
                session_id="stale-session",
                agent_id="codex-sol",
                project_id="stale-project",
                objective="Superseded state",
            )
            contested = record_project_state(
                root,
                session_id="contested-session",
                agent_id="codex-sol",
                project_id="stale-project",
                objective="Contested state",
            )
            append_scroll_event(
                root,
                session_id="scroll-fallback-session",
                event_type="message",
                role="user",
                content="This Scroll event must not override stale checkpoint safety.",
                metadata={"project_id": "stale-project", "visibility_scope": "project"},
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET superseded_by_card_id = ? WHERE id = ?",
                    ("replacement-card", superseded["card_id"]),
                )
                conn.execute(
                    "UPDATE cards SET conflict_group = ? WHERE id = ?",
                    ("conflict-group", contested["card_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            result = resume_latest(root, project_id="stale-project")

            self.assertFalse(result["ok"])
            self.assertEqual(result["reason"], "no_current_project_state")
            self.assertFalse((root / "exports" / "thread_recovery").exists())


if __name__ == "__main__":
    unittest.main()
