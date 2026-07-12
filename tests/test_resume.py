from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import tempfile
import threading
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
from continuum.core.workers import (
    detect_conflicts,
    prune_memory,
    resolve_conflict,
    run_worker_pass,
)


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

    def test_unscoped_resume_selects_global_scroll_without_deriving_scope(self) -> None:
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
            self.assertEqual(result["session_id"], "global-scroll-session")
            self.assertEqual(result["project_id"], None)
            self.assertEqual(
                result["visibility_capability"],
                {"session_id": None, "project_id": None},
            )
            self.assertEqual(result["recent_event_count"], 1)
            self.assertIn("GLOBAL-SCROLL-EVENT", result["packet_text"])
            self.assertNotIn("VISIBLE-SCROLL-EVENT", result["packet_text"])

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
            configure_personal_profile(root, safe_context_ceiling=384)

            result = resume_latest(
                root,
                project_id="bounded-packet-project",
                recent_event_limit=24,
                model_assist=False,
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["packet_token_budget"], 384)
            self.assertEqual(result["recent_event_count"], 24)
            self.assertLessEqual(result["packet_estimated_tokens"], 384)
            self.assertEqual(
                result["packet_estimated_tokens"],
                estimate_tokens(result["packet_text"]),
            )
            self.assertTrue(result["packet_truncated"], result)
            self.assertIn('"session_id":"bounded-packet-session"', result["packet_text"])
            self.assertIn('"project_id":"bounded-packet-project"', result["packet_text"])
            self.assertIn("Bound the complete recovery packet", result["packet_text"])
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
            self.assertIn("MUST-RUN-RESTORE-DRILL", result["context"]["context_text"])
            self.assertIn("KEEP-RESTORE-PROOF", result["context"]["context_text"])

    def test_resume_preserves_the_callers_visibility_capability_scope_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            session_state = record_project_state(
                root,
                session_id="matrix-session",
                agent_id="codex-sol",
                project_id="matrix-project",
                objective="SESSION-SCOPED-AUTHORIZED-CHECKPOINT",
                metadata={"visibility_scope": "session"},
            )
            project_state = record_project_state(
                root,
                session_id="matrix-session",
                agent_id="codex-sol",
                project_id="matrix-project",
                objective="NEWER-PROJECT-SCOPED-CHECKPOINT",
            )
            append_scroll_event(
                root,
                session_id="matrix-session",
                event_type="message",
                role="user",
                content="PROJECT-SCROLL-CAPABILITY-MARKER",
                metadata={
                    "visibility_scope": "project",
                    "project_id": "matrix-project",
                },
            )
            append_scroll_event(
                root,
                session_id="matrix-session",
                event_type="message",
                role="user",
                content="SESSION-SCROLL-CAPABILITY-MARKER",
                metadata={"visibility_scope": "session"},
            )
            conn = connect(root)
            try:
                create_card(
                    conn,
                    root=root,
                    card_type="reference",
                    title="PROJECT-CARD-CAPABILITY-MARKER",
                    summary="Evidence authorized only by the project capability.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="matrix-session",
                    project_id="matrix-project",
                )
                create_card(
                    conn,
                    root=root,
                    card_type="reference",
                    title="SESSION-CARD-CAPABILITY-MARKER",
                    summary="Evidence authorized only by the session capability.",
                    source_refs=[],
                    visibility_scope="session",
                    session_id="matrix-session",
                    project_id="matrix-project",
                )
                conn.commit()
            finally:
                conn.close()

            cases = [
                (
                    "session_only",
                    {"session_id": "matrix-session"},
                    {"session_id": "matrix-session", "project_id": None},
                    session_state["card_id"],
                    True,
                    False,
                ),
                (
                    "project_only",
                    {"project_id": "matrix-project"},
                    {"session_id": None, "project_id": "matrix-project"},
                    project_state["card_id"],
                    False,
                    True,
                ),
                (
                    "session_and_project",
                    {
                        "session_id": "matrix-session",
                        "project_id": "matrix-project",
                    },
                    {
                        "session_id": "matrix-session",
                        "project_id": "matrix-project",
                    },
                    project_state["card_id"],
                    True,
                    True,
                ),
                (
                    "unscoped_project_checkpoint",
                    {},
                    {"session_id": None, "project_id": "matrix-project"},
                    project_state["card_id"],
                    False,
                    True,
                ),
            ]
            for (
                name,
                kwargs,
                expected_capability,
                expected_checkpoint_id,
                sees_session,
                sees_project,
            ) in cases:
                with self.subTest(name=name):
                    result = resume_latest(
                        root,
                        token_budget=12000,
                        model_assist=False,
                        **kwargs,
                    )

                    self.assertTrue(result["ok"], result)
                    self.assertEqual(
                        result["visibility_capability"],
                        expected_capability,
                    )
                    self.assertEqual(
                        result["discovery"]["checkpoint_id"],
                        expected_checkpoint_id,
                    )
                    context_text = result["context"]["context_text"]
                    self.assertTrue(result["context"]["mandatory_checkpoint_fit"])
                    self.assertIn(expected_checkpoint_id, context_text)
                    for marker in (
                        session_state["card_id"],
                        "SESSION-SCOPED-AUTHORIZED-CHECKPOINT",
                        "SESSION-CARD-CAPABILITY-MARKER",
                        "SESSION-SCROLL-CAPABILITY-MARKER",
                    ):
                        if sees_session:
                            self.assertIn(marker, context_text)
                        else:
                            self.assertNotIn(marker, context_text)
                    for marker in (
                        project_state["card_id"],
                        "NEWER-PROJECT-SCOPED-CHECKPOINT",
                        "PROJECT-CARD-CAPABILITY-MARKER",
                        "PROJECT-SCROLL-CAPABILITY-MARKER",
                    ):
                        if sees_project:
                            self.assertIn(marker, context_text)
                        else:
                            self.assertNotIn(marker, context_text)

        unauthorized_cases = (
            (
                "session_cannot_select_project_checkpoint",
                {"session_id": "authority-session"},
                "project",
            ),
            (
                "project_cannot_select_session_checkpoint",
                {"project_id": "authority-project"},
                "session",
            ),
        )
        for name, kwargs, checkpoint_scope in unauthorized_cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                record_project_state(
                    root,
                    session_id="authority-session",
                    agent_id="codex-sol",
                    project_id="authority-project",
                    objective="UNAUTHORIZED-CHECKPOINT-MUST-NOT-RETURN",
                    metadata={"visibility_scope": checkpoint_scope},
                )

                result = resume_latest(root, model_assist=False, **kwargs)

                self.assertFalse(result["ok"], result)
                self.assertEqual(result["reason"], "no_resume_state")
                self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_dual_scope_resume_preserves_both_requested_capabilities_for_asymmetric_checkpoints(
        self,
    ) -> None:
        for winner in ("session", "project"):
            with self.subTest(winner=winner), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                if winner == "session":
                    project_state = record_project_state(
                        root,
                        session_id="project-checkpoint-session",
                        agent_id="codex-sol",
                        project_id="requested-project",
                        objective="REQUESTED-PROJECT-CARD-MARKER",
                    )
                    session_state = record_project_state(
                        root,
                        session_id="requested-session",
                        agent_id="codex-sol",
                        project_id="other-project",
                        objective="REQUESTED-SESSION-CARD-MARKER",
                        metadata={"visibility_scope": "session"},
                    )
                    selected_checkpoint_id = session_state["card_id"]
                else:
                    session_state = record_project_state(
                        root,
                        session_id="requested-session",
                        agent_id="codex-sol",
                        project_id="other-project",
                        objective="REQUESTED-SESSION-CARD-MARKER",
                        metadata={"visibility_scope": "session"},
                    )
                    project_state = record_project_state(
                        root,
                        session_id="project-checkpoint-session",
                        agent_id="codex-sol",
                        project_id="requested-project",
                        objective="REQUESTED-PROJECT-CARD-MARKER",
                    )
                    selected_checkpoint_id = project_state["card_id"]

                append_scroll_event(
                    root,
                    session_id="requested-session",
                    event_type="message",
                    role="user",
                    content="REQUESTED-SESSION-SCROLL-MARKER",
                    metadata={"visibility_scope": "session"},
                )
                append_scroll_event(
                    root,
                    session_id="project-evidence-session",
                    event_type="message",
                    role="user",
                    content="REQUESTED-PROJECT-SCROLL-MARKER",
                    metadata={
                        "visibility_scope": "project",
                        "project_id": "requested-project",
                    },
                )

                result = resume_latest(
                    root,
                    session_id="requested-session",
                    project_id="requested-project",
                    token_budget=12000,
                    model_assist=False,
                )

                self.assertTrue(result["ok"], result)
                self.assertEqual(
                    result["visibility_capability"],
                    {
                        "session_id": "requested-session",
                        "project_id": "requested-project",
                    },
                )
                self.assertEqual(
                    result["discovery"]["checkpoint_id"],
                    selected_checkpoint_id,
                )
                context_text = result["context"]["context_text"]
                for marker in (
                    "REQUESTED-SESSION-CARD-MARKER",
                    "REQUESTED-PROJECT-CARD-MARKER",
                    "REQUESTED-SESSION-SCROLL-MARKER",
                    "REQUESTED-PROJECT-SCROLL-MARKER",
                ):
                    self.assertIn(marker, context_text)

    def test_compile_context_rejects_unauthorized_mandatory_checkpoint_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="unauthorized-session",
                agent_id="codex-sol",
                project_id="unauthorized-project",
                objective="UNAUTHORIZED-MANDATORY-CARD-MARKER",
            )
            event = append_scroll_event(
                root,
                session_id="unauthorized-session",
                event_type="message",
                role="user",
                content="UNAUTHORIZED-MANDATORY-SCROLL-MARKER",
                metadata={
                    "visibility_scope": "project",
                    "project_id": "unauthorized-project",
                },
            )
            cases = (
                (
                    "card_with_explicit_capability",
                    {
                        "source": "project_state_card",
                        "checkpoint_id": state["card_id"],
                        "session_id": "unauthorized-session",
                        "project_id": "unauthorized-project",
                        "checkpoint_visibility_scope": "project",
                    },
                    {
                        "visibility_capability": {
                            "session_id": "allowed-session",
                            "project_id": None,
                        }
                    },
                    "UNAUTHORIZED-MANDATORY-CARD-MARKER",
                ),
                (
                    "scroll_with_implicit_session_capability",
                    {
                        "source": "scroll_event",
                        "checkpoint_id": event["event_id"],
                        "session_id": "unauthorized-session",
                        "project_id": "unauthorized-project",
                        "checkpoint_visibility_scope": "project",
                    },
                    {},
                    "UNAUTHORIZED-MANDATORY-SCROLL-MARKER",
                ),
            )
            for name, mandatory_checkpoint, extra_kwargs, marker in cases:
                with self.subTest(name=name):
                    result = compile_context(
                        root,
                        session_id="allowed-session",
                        token_budget=3000,
                        planner_profile="resume",
                        create=False,
                        mandatory_checkpoint=mandatory_checkpoint,
                        **extra_kwargs,
                    )

                    self.assertFalse(result["ok"], result)
                    self.assertFalse(result["mandatory_checkpoint_found"])
                    self.assertFalse(result["mandatory_checkpoint_fit"])
                    self.assertEqual(result["reason"], "checkpoint_missing")
                    self.assertNotIn(marker, result["context_text"])
                    self.assertNotIn(
                        mandatory_checkpoint["checkpoint_id"],
                        result["context_text"],
                    )

    def test_public_context_apis_reject_foreign_visibility_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="declared-session",
                agent_id="codex-sol",
                project_id="declared-project",
                objective="Declared recovery authority",
            )
            forged_capabilities = (
                (
                    "session_id",
                    {"session_id": "foreign-session", "project_id": None},
                ),
                (
                    "project_id",
                    {"session_id": None, "project_id": "foreign-project"},
                ),
            )
            for api_name in ("compile_context", "recover_thread"):
                for field, forged_capability in forged_capabilities:
                    with self.subTest(api=api_name, field=field):
                        with self.assertRaisesRegex(
                            ValueError,
                            rf"visibility_capability {field} must match",
                        ):
                            if api_name == "compile_context":
                                compile_context(
                                    root,
                                    session_id="declared-session",
                                    project_id="declared-project",
                                    token_budget=1000,
                                    planner_profile="resume",
                                    create=False,
                                    visibility_capability=forged_capability,
                                )
                            else:
                                recover_thread(
                                    root,
                                    session_id="declared-session",
                                    project_id="declared-project",
                                    token_budget=1000,
                                    planner_profile="resume",
                                    visibility_capability=forged_capability,
                                )
                with self.subTest(api=api_name, field="empty"):
                    with self.assertRaisesRegex(
                        ValueError,
                        "cannot remove all declared coordinates",
                    ):
                        if api_name == "compile_context":
                            compile_context(
                                root,
                                session_id="declared-session",
                                project_id="declared-project",
                                token_budget=1000,
                                planner_profile="resume",
                                create=False,
                                visibility_capability={
                                    "session_id": None,
                                    "project_id": None,
                                },
                            )
                        else:
                            recover_thread(
                                root,
                                session_id="declared-session",
                                project_id="declared-project",
                                token_budget=1000,
                                planner_profile="resume",
                                visibility_capability={
                                    "session_id": None,
                                    "project_id": None,
                                },
                            )
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_pins_lossless_checkpoint_ahead_of_crowded_windows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["context"]["scroll_event_fetch_limit"] = 2
            write_config(root, config)
            objective_tail = "PINNED-CHECKPOINT-OBJECTIVE-TAIL"
            state = record_project_state(
                root,
                session_id="crowded-session",
                agent_id="codex-sol",
                project_id="crowded-project",
                objective=(
                    "PINNED-CHECKPOINT-OBJECTIVE:"
                    + ("X" * 3200)
                    + objective_tail
                ),
                decisions=["PINNED-CHECKPOINT-DECISION"],
                open_tasks=["PINNED-CHECKPOINT-TASK"],
            )
            for index in range(3):
                append_scroll_event(
                    root,
                    session_id="crowded-session",
                    event_type="message",
                    role="user",
                    content=f"newer capped Scroll event {index}",
                    metadata={
                        "visibility_scope": "project",
                        "project_id": "crowded-project",
                    },
                )
            conn = connect(root)
            try:
                for index in range(90):
                    create_card(
                        conn,
                        root=root,
                        card_type="reference",
                        title=f"High-salience reference {index}",
                        summary=f"Crowded project reference {index}",
                        source_refs=[],
                        salience=1.0,
                        confidence=1.0,
                        visibility_scope="project",
                        session_id="crowded-session",
                        project_id="crowded-project",
                    )
                conn.commit()
            finally:
                conn.close()

            too_small = resume_latest(
                root,
                project_id="crowded-project",
                query="deliberately-unmatched-query",
                token_budget=700,
                model_assist=False,
            )

            self.assertFalse(too_small["ok"], too_small)
            self.assertEqual(too_small["reason"], "checkpoint_did_not_fit")
            self.assertGreater(too_small["minimum_checkpoint_tokens"], 700)
            self.assertFalse((root / "exports" / "thread_recovery").exists())

            result = resume_latest(
                root,
                project_id="crowded-project",
                query="deliberately-unmatched-query",
                token_budget=3000,
                model_assist=False,
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["discovery"]["checkpoint_id"], state["card_id"])
            self.assertTrue(result["context"]["mandatory_checkpoint_fit"])
            self.assertEqual(
                result["context"]["mandatory_checkpoint_id"],
                state["card_id"],
            )
            self.assertIn(state["card_id"], result["context"]["context_text"])
            self.assertIn(state["card_id"], result["packet_text"])
            self.assertIn(state["event_id"], result["context"]["context_text"])
            self.assertIn(objective_tail, result["context"]["context_text"])
            self.assertIn(objective_tail, result["packet_text"])
            self.assertIn("PINNED-CHECKPOINT-TASK", result["packet_text"])
            self.assertIn("PINNED-CHECKPOINT-DECISION", result["packet_text"])

    def test_resume_fails_closed_when_project_state_source_is_invalid(self) -> None:
        for mutation in (
            "missing",
            "session_mismatch",
            "project_mismatch",
            "scope_mismatch",
            "content_mismatch",
            "content_hash_mismatch",
            "non_project_large",
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                state = record_project_state(
                    root,
                    session_id="source-check-session",
                    agent_id="codex-sol",
                    project_id="source-check-project",
                    objective="SOURCE-CHECKPOINT-MUST-FAIL-CLOSED",
                )
                conn = connect(root)
                try:
                    if mutation == "missing":
                        conn.execute(
                            "DELETE FROM scroll_events WHERE id = ?",
                            (state["event_id"],),
                        )
                    elif mutation == "session_mismatch":
                        conn.execute(
                            "UPDATE scroll_events SET session_id = ? WHERE id = ?",
                            ("other-source-session", state["event_id"]),
                        )
                    elif mutation == "project_mismatch":
                        conn.execute(
                            "UPDATE scroll_events SET project_id = ? WHERE id = ?",
                            ("other-source-project", state["event_id"]),
                        )
                    elif mutation == "scope_mismatch":
                        conn.execute(
                            """
                            UPDATE scroll_events
                            SET visibility_scope = 'session', project_id = NULL
                            WHERE id = ?
                            """,
                            (state["event_id"],),
                        )
                    elif mutation == "content_mismatch":
                        conn.execute(
                            "UPDATE scroll_events SET content = ? WHERE id = ?",
                            ("MUTATED-SOURCE-CONTENT", state["event_id"]),
                        )
                    elif mutation == "content_hash_mismatch":
                        conn.execute(
                            "UPDATE scroll_events SET content_hash = ? WHERE id = ?",
                            ("0" * 64, state["event_id"]),
                        )
                    else:
                        conn.execute(
                            """
                            UPDATE scroll_events
                            SET event_type = 'message', content = ?
                            WHERE id = ?
                            """,
                            ("x" * 100_000, state["event_id"]),
                        )
                    conn.commit()
                finally:
                    conn.close()

                result = resume_latest(
                    root,
                    project_id="source-check-project",
                    token_budget=3000,
                    model_assist=False,
                )

                self.assertFalse(result["ok"], result)
                self.assertEqual(result["reason"], "invalid_project_state_checkpoint")
                self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_fails_closed_when_project_state_structured_payload_is_mutated(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            original_decisions = [
                f"ORIGINAL_DECISION_{index}" for index in range(25)
            ]
            original_tasks = [f"ORIGINAL_TASK_{index}" for index in range(25)]
            state = record_project_state(
                root,
                session_id="payload-binding-session",
                agent_id="codex-sol",
                project_id="payload-binding-project",
                objective="PROJECT-STATE-PAYLOAD-BINDING",
                decisions=original_decisions,
                open_tasks=original_tasks,
            )
            tampered_decisions = list(original_decisions)
            tampered_tasks = list(original_tasks)
            tampered_decisions[-1] = "TAMPERED_DECISION_OUTSIDE_RENDERED_WINDOW"
            tampered_tasks[-1] = "TAMPERED_TASK_OUTSIDE_RENDERED_WINDOW"
            conn = connect(root)
            try:
                conn.execute(
                    """
                    UPDATE cards
                    SET decisions_json = ?, open_tasks_json = ?
                    WHERE id = ?
                    """,
                    (
                        json.dumps(tampered_decisions),
                        json.dumps(tampered_tasks),
                        state["card_id"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            result = resume_latest(
                root,
                project_id="payload-binding-project",
                token_budget=3000,
                model_assist=False,
            )

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "invalid_project_state_checkpoint")
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_project_state_payload_marker_ignores_earlier_user_text_collision(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            state = record_project_state(
                root,
                session_id="payload-marker-session",
                agent_id="codex-sol",
                project_id="payload-marker-project",
                objective=(
                    "Normal objective\n"
                    "Continuum-State-Payload-SHA256: user-authored text"
                ),
                decisions=["KEEP_MARKER_COLLISION_DECISION"],
                open_tasks=["KEEP_MARKER_COLLISION_TASK"],
            )

            result = resume_latest(
                root,
                project_id="payload-marker-project",
                token_budget=3000,
                model_assist=False,
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["discovery"]["checkpoint_id"], state["card_id"])
            self.assertIn("KEEP_MARKER_COLLISION_DECISION", result["packet_text"])
            self.assertIn("KEEP_MARKER_COLLISION_TASK", result["packet_text"])

    def test_resume_fails_closed_when_checkpoint_source_is_rebound_within_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            old_state = record_project_state(
                root,
                session_id="rebound-source-session",
                agent_id="codex-sol",
                project_id="rebound-source-project",
                objective="OLD-SOURCE-EVENT-OBJECTIVE",
            )
            new_state = record_project_state(
                root,
                session_id="rebound-source-session",
                agent_id="codex-sol",
                project_id="rebound-source-project",
                objective="NEW-SELECTED-CARD-OBJECTIVE",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET source_refs_json = ? WHERE id = ?",
                    (
                        json.dumps(
                            [
                                {
                                    "event_id": old_state["event_id"],
                                    "session_id": "rebound-source-session",
                                    "seq": old_state["seq"],
                                }
                            ],
                            separators=(",", ":"),
                        ),
                        new_state["card_id"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            result = resume_latest(
                root,
                project_id="rebound-source-project",
                token_budget=3000,
                model_assist=False,
            )

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "invalid_project_state_checkpoint")
            self.assertEqual(
                result["invalid_checkpoint"]["checkpoint_id"],
                new_state["card_id"],
            )
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_resolves_legacy_project_state_source_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            objective_tail = "LEGACY-SOURCE-OBJECTIVE-TAIL"
            state = record_project_state(
                root,
                session_id="legacy-source-session",
                agent_id="codex-sol",
                project_id="legacy-source-project",
                objective=("X" * 1200) + objective_tail,
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET source_refs_json = ? WHERE id = ?",
                    (
                        json.dumps(
                            [
                                {
                                    "session_id": "legacy-source-session",
                                    "seq": state["seq"],
                                }
                            ],
                            separators=(",", ":"),
                        ),
                        state["card_id"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            result = resume_latest(
                root,
                project_id="legacy-source-project",
                token_budget=3000,
                model_assist=False,
            )

            self.assertTrue(result["ok"], result)
            self.assertIn(state["event_id"], result["context"]["context_text"])
            self.assertIn(objective_tail, result["packet_text"])

    def test_resume_pins_selected_scroll_checkpoint_beyond_the_fetch_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["context"]["scroll_event_fetch_limit"] = 2
            write_config(root, config)
            checkpoint = append_scroll_event(
                root,
                session_id="saturated-scroll-session",
                event_type="message",
                role="user",
                content="SATURATED-SCROLL-SELECTED-CHECKPOINT",
                metadata={"visibility_scope": "session"},
            )
            for index in range(3):
                append_scroll_event(
                    root,
                    session_id="saturated-scroll-session",
                    event_type="message",
                    role="user",
                    content=f"newer capped Scroll event {index}",
                    metadata={"visibility_scope": "session"},
                )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE scroll_events SET created_at = ? WHERE id = ?",
                    ("2099-01-01T00:00:00+00:00", checkpoint["event_id"]),
                )
                conn.commit()
            finally:
                conn.close()

            result = resume_latest(
                root,
                session_id="saturated-scroll-session",
                query="deliberately-unmatched-query",
                token_budget=3000,
                model_assist=False,
            )

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["discovery"]["source"], "scroll_event")
            self.assertEqual(
                result["discovery"]["checkpoint_id"],
                checkpoint["event_id"],
            )
            self.assertTrue(result["context"]["mandatory_checkpoint_fit"])
            self.assertIn(checkpoint["event_id"], result["context"]["context_text"])
            self.assertIn(
                "SATURATED-SCROLL-SELECTED-CHECKPOINT",
                result["context"]["context_text"],
            )
            self.assertIn(checkpoint["event_id"], result["packet_text"])

    def test_resume_fails_closed_when_selected_scroll_checkpoint_is_corrupted(
        self,
    ) -> None:
        for mutation in ("content", "content_hash", "sequence"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "continuum"
                checkpoint = append_scroll_event(
                    root,
                    session_id="corrupt-scroll-session",
                    event_type="message",
                    role="user",
                    content="IMMUTABLE-SELECTED-SCROLL-CHECKPOINT",
                    metadata={"visibility_scope": "session"},
                )
                conn = connect(root)
                try:
                    if mutation == "content":
                        conn.execute(
                            "UPDATE scroll_events SET content = ? WHERE id = ?",
                            ("MUTATED-SELECTED-SCROLL-CONTENT", checkpoint["event_id"]),
                        )
                    elif mutation == "content_hash":
                        conn.execute(
                            "UPDATE scroll_events SET content_hash = ? WHERE id = ?",
                            ("0" * 64, checkpoint["event_id"]),
                        )
                    else:
                        conn.execute(
                            "UPDATE scroll_events SET seq = ? WHERE id = ?",
                            ("not-a-sequence", checkpoint["event_id"]),
                        )
                    conn.commit()
                finally:
                    conn.close()

                result = resume_latest(
                    root,
                    session_id="corrupt-scroll-session",
                    token_budget=3000,
                    model_assist=False,
                )

                self.assertFalse(result["ok"], result)
                self.assertEqual(
                    result["reason"],
                    "checkpoint_changed_during_resume",
                )
                self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_does_not_succeed_with_an_id_only_checkpoint_stub(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            config = default_config()
            config["context"]["default_token_budget"] = 300
            config["context"]["max_token_budget"] = 300
            config["personal_profile"]["safe_context_ceiling"] = 300
            write_config(root, config)
            record_project_state(
                root,
                session_id="complete-minimum-session",
                agent_id="codex-sol",
                project_id="complete-minimum-project",
                objective="REQUIRED-CHECKPOINT-STATE:" + ("x" * 4000),
                decisions=["REQUIRED-CHECKPOINT-DECISION"],
                open_tasks=["REQUIRED-CHECKPOINT-TASK"],
            )

            result = resume_latest(
                root,
                project_id="complete-minimum-project",
                token_budget=300,
                model_assist=False,
            )

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "checkpoint_did_not_fit")
            self.assertEqual(result["packet_token_budget"], 300)
            self.assertGreater(result["minimum_checkpoint_tokens"], 300)
            self.assertGreater(result["minimum_packet_tokens"], 300)
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_reports_when_checkpoint_cannot_fit_a_supported_small_ceiling(self) -> None:
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

            self.assertFalse(result["ok"], result)
            self.assertEqual(result["reason"], "checkpoint_did_not_fit")
            self.assertEqual(result["packet_token_budget"], 100)
            self.assertGreater(result["minimum_checkpoint_tokens"], 0)
            self.assertGreater(result["minimum_packet_tokens"], 100)
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_reports_checkpoint_did_not_fit_at_one_token(self) -> None:
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
            self.assertEqual(result["reason"], "checkpoint_did_not_fit")
            self.assertEqual(result["packet_token_budget"], 1)
            self.assertGreater(result["minimum_checkpoint_tokens"], 1)
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

    def test_resume_planner_ranks_query_score_before_card_candidate_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            init_db(root)
            conn = connect(root)
            try:
                target_card_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="zirconium lattice target",
                    summary="The two-term target should outrank one-term noise.",
                    source_refs=[],
                    visibility_scope="session",
                    session_id="query-ranking-session",
                    salience=0.3,
                    confidence=0.3,
                )
                for index in range(90):
                    create_card(
                        conn,
                        root=root,
                        card_type="note",
                        title=f"zirconium noise {index}",
                        summary="A one-term candidate with slightly higher salience.",
                        source_refs=[],
                        visibility_scope="session",
                        session_id="query-ranking-session",
                        salience=0.4,
                        confidence=0.4,
                    )
                conn.commit()
            finally:
                conn.close()

            packet = compile_context(
                root,
                session_id="query-ranking-session",
                query="zirconium lattice",
                token_budget=2000,
                planner_profile="resume",
                create=False,
            )

            current_cards = next(
                section
                for section in packet["sections"]
                if section["kind"] == "current_cards"
            )
            self.assertEqual(current_cards["ids"][0], target_card_id)

    def test_resume_prioritizes_query_cue_under_tight_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            session_id = "query-budget-session"
            project_id = "query-budget-project"
            record_project_state(
                root,
                session_id=session_id,
                agent_id="codex-sol",
                project_id=project_id,
                objective="Initial release state",
            )
            append_scroll_event(
                root,
                session_id=session_id,
                event_type="message",
                role="user",
                content=(
                    "ZIRCONIUM-CUE-TARGET preserves the buried lattice evidence."
                ),
                metadata={
                    "visibility_scope": "project",
                    "project_id": project_id,
                },
            )
            for index in range(110):
                append_scroll_event(
                    root,
                    session_id=session_id,
                    event_type="message",
                    role="user",
                    content=f"ordinary unrelated scroll noise {index}",
                    metadata={
                        "visibility_scope": "project",
                        "project_id": project_id,
                    },
                )
            record_project_state(
                root,
                session_id=session_id,
                agent_id="codex-sol",
                project_id=project_id,
                objective="Continue local release verification",
                open_tasks=["finish deterministic gates"],
            )
            conn = connect(root)
            try:
                create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="High salience unrelated card",
                    summary="ordinary filler " * 1200,
                    source_refs=[],
                    visibility_scope="project",
                    session_id=session_id,
                    project_id=project_id,
                    salience=1.0,
                    confidence=1.0,
                )
                conn.commit()
            finally:
                conn.close()

            resumed = resume_latest(
                root,
                session_id=session_id,
                project_id=project_id,
                query="zirconium lattice evidence",
                token_budget=900,
                model_assist=False,
            )

            self.assertTrue(resumed["ok"], resumed)
            self.assertIn("ZIRCONIUM-CUE-TARGET", resumed["packet_text"])
            optional_inclusions = [
                item
                for item in resumed["context"]["planner_trace"]
                if item.get("included") and not item.get("mandatory")
            ]
            self.assertEqual(optional_inclusions[0]["source"], "cue_recall")

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

    def test_immediate_cross_agent_project_heads_fail_closed_until_resolved(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="agent-a-session",
                agent_id="agent-a",
                project_id="shared-project",
                objective="Prepare deployment routing",
                decisions=["Use alpha routing for deployment"],
            )
            second = record_project_state(
                root,
                session_id="agent-b-session",
                agent_id="agent-b",
                project_id="shared-project",
                objective="Prepare deployment routing",
                decisions=["Do not use alpha routing for deployment"],
            )

            ambiguous = resume_latest(
                root,
                project_id="shared-project",
                model_assist=False,
            )

            self.assertFalse(ambiguous["ok"], ambiguous)
            self.assertEqual(ambiguous["reason"], "authority_ambiguous")
            self.assertTrue(ambiguous["resolution_required"])
            details = ambiguous["authority_ambiguity"]
            self.assertEqual(
                details["boundary"],
                {
                    "visibility_scope": "project",
                    "project_id": "shared-project",
                    "session_id": None,
                },
            )
            self.assertEqual(
                set(details["current_head_ids"]),
                {first["card_id"], second["card_id"]},
            )
            self.assertEqual(details["head_count_at_least"], 2)
            self.assertEqual(details["head_list_limit"], 2)
            self.assertFalse((root / "exports" / "thread_recovery").exists())

            detected = detect_conflicts(root)
            self.assertEqual(detected["conflict_count"], 1, detected)
            grouped_ambiguous = resume_latest(
                root,
                project_id="shared-project",
                model_assist=False,
            )
            self.assertFalse(grouped_ambiguous["ok"], grouped_ambiguous)
            self.assertEqual(
                grouped_ambiguous["reason"],
                "authority_ambiguous",
            )
            self.assertEqual(
                set(
                    grouped_ambiguous["authority_ambiguity"][
                        "contested_head_ids"
                    ]
                ),
                {first["card_id"], second["card_id"]},
            )
            conn = connect(root)
            try:
                before_event_count = int(
                    conn.execute(
                        "SELECT count(*) FROM scroll_events"
                    ).fetchone()[0]
                )
            finally:
                conn.close()
            with self.assertRaisesRegex(ValueError, "unresolved conflict"):
                record_project_state(
                    root,
                    session_id="agent-a-follow-up",
                    agent_id="agent-a",
                    project_id="shared-project",
                    objective="Advance without resolving the disagreement",
                )
            conn = connect(root)
            try:
                self.assertEqual(
                    int(
                        conn.execute(
                            "SELECT count(*) FROM scroll_events"
                        ).fetchone()[0]
                    ),
                    before_event_count,
                )
            finally:
                conn.close()
            resolved = resolve_conflict(
                root,
                card_id=second["card_id"],
                action="supersede",
            )
            self.assertTrue(resolved["ok"], resolved)

            resumed = resume_latest(
                root,
                project_id="shared-project",
                model_assist=False,
            )

            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                second["card_id"],
            )

    def test_compatible_independent_heads_require_complete_explicit_resolution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="compatible-agent-a",
                agent_id="agent-a",
                project_id="compatible-project",
                objective="Prepare release notes",
            )
            second = record_project_state(
                root,
                session_id="compatible-agent-b",
                agent_id="agent-b",
                project_id="compatible-project",
                objective="Prepare package metadata",
            )
            winner = record_project_state(
                root,
                session_id="compatible-agent-c",
                agent_id="agent-c",
                project_id="compatible-project",
                objective="Prepare final review bundle",
            )
            outside = record_project_state(
                root,
                session_id="outside-agent",
                agent_id="outside-agent",
                project_id="outside-project",
                objective="Prepare an unrelated project",
            )

            detected = detect_conflicts(root, card_id=winner["card_id"])
            ambiguous = resume_latest(
                root,
                project_id="compatible-project",
                model_assist=False,
            )

            self.assertEqual(detected["conflict_count"], 0, detected)
            self.assertFalse(ambiguous["ok"], ambiguous)
            self.assertEqual(ambiguous["reason"], "authority_ambiguous")
            with self.assertRaisesRegex(ValueError, "card is not contested"):
                resolve_conflict(
                    root,
                    card_id=winner["card_id"],
                    action="dismiss",
                    superseded_card_ids=[first["card_id"], second["card_id"]],
                )
            with self.assertRaisesRegex(
                ValueError,
                "explicit confirmation",
            ) as missing_confirmation:
                resolve_conflict(root, card_id=winner["card_id"])
            self.assertIn(first["card_id"], str(missing_confirmation.exception))
            self.assertIn(second["card_id"], str(missing_confirmation.exception))
            with self.assertRaisesRegex(ValueError, "whole project-state boundary"):
                resolve_conflict(
                    root,
                    card_id=winner["card_id"],
                    superseded_card_ids=[first["card_id"]],
                )
            with self.assertRaisesRegex(ValueError, "selected boundary"):
                resolve_conflict(
                    root,
                    card_id=winner["card_id"],
                    superseded_card_ids=[
                        first["card_id"],
                        second["card_id"],
                        outside["card_id"],
                    ],
                )

            resolved = resolve_conflict(
                root,
                card_id=winner["card_id"],
                superseded_card_ids=[first["card_id"], second["card_id"]],
            )
            resumed = resume_latest(
                root,
                project_id="compatible-project",
                model_assist=False,
            )

            self.assertTrue(resolved["ok"], resolved)
            self.assertEqual(
                resolved["resolution_scope"],
                "project_state_authority_boundary",
            )
            self.assertEqual(
                set(resolved["resolved_peer_ids"]),
                {first["card_id"], second["card_id"]},
            )
            self.assertTrue(store_module.semantic_integrity_report(root)["ok"])
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                winner["card_id"],
            )

    def test_grouped_project_state_resolution_requires_every_boundary_head(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="grouped-agent-a",
                agent_id="agent-a",
                project_id="grouped-project",
                objective="Prepare deployment routing",
                decisions=["Use alpha routing"],
            )
            winner = record_project_state(
                root,
                session_id="grouped-agent-b",
                agent_id="agent-b",
                project_id="grouped-project",
                objective="Prepare deployment routing",
                decisions=["Do not use alpha routing"],
            )
            detected = detect_conflicts(root)
            self.assertEqual(detected["conflict_count"], 1, detected)
            independent = record_project_state(
                root,
                session_id="grouped-agent-c",
                agent_id="agent-c",
                project_id="grouped-project",
                objective="Prepare release documentation",
            )

            with self.assertRaisesRegex(ValueError, "explicit confirmation"):
                resolve_conflict(root, card_id=winner["card_id"])
            with self.assertRaisesRegex(ValueError, "whole project-state boundary"):
                resolve_conflict(
                    root,
                    card_id=winner["card_id"],
                    superseded_card_ids=[first["card_id"]],
                )

            resolved = resolve_conflict(
                root,
                card_id=winner["card_id"],
                superseded_card_ids=[first["card_id"], independent["card_id"]],
            )
            resumed = resume_latest(
                root,
                project_id="grouped-project",
                model_assist=False,
            )

            self.assertEqual(
                resolved["resolution_scope"],
                "project_state_authority_boundary",
            )
            self.assertTrue(store_module.semantic_integrity_report(root)["ok"])
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                winner["card_id"],
            )

    def test_explicit_authority_resolution_rejects_intersecting_group(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="intersecting-agent-a",
                agent_id="agent-a",
                project_id="intersecting-project",
                objective="Prepare release notes",
            )
            winner = record_project_state(
                root,
                session_id="intersecting-agent-b",
                agent_id="agent-b",
                project_id="intersecting-project",
                objective="Prepare final review bundle",
            )
            conn = connect(root)
            try:
                note_id = create_card(
                    conn,
                    root=root,
                    card_type="note",
                    title="Unrelated project note",
                    summary="Evidence that is not project-state authority.",
                    source_refs=[],
                    visibility_scope="project",
                    session_id="intersecting-note",
                    project_id="intersecting-project",
                )
                conn.execute(
                    "UPDATE cards SET conflict_group = 'legacy-mixed-group' "
                    "WHERE id IN (?, ?)",
                    (first["card_id"], note_id),
                )
                conn.commit()
            finally:
                conn.close()

            with self.assertRaisesRegex(ValueError, "incomplete conflict group"):
                resolve_conflict(
                    root,
                    card_id=winner["card_id"],
                    superseded_card_ids=[first["card_id"]],
                )

            conn = connect(root)
            try:
                rows = {
                    str(row["id"]): row
                    for row in conn.execute(
                        "SELECT id, conflict_group, superseded_by_card_id "
                        "FROM cards WHERE id IN (?, ?, ?)",
                        (first["card_id"], winner["card_id"], note_id),
                    )
                }
            finally:
                conn.close()
            self.assertEqual(
                rows[first["card_id"]]["conflict_group"],
                "legacy-mixed-group",
            )
            self.assertEqual(rows[note_id]["conflict_group"], "legacy-mixed-group")
            self.assertIsNone(rows[first["card_id"]]["superseded_by_card_id"])
            self.assertIsNone(rows[winner["card_id"]]["superseded_by_card_id"])

    def test_explicit_authority_resolution_rejects_invalid_project_state(
        self,
    ) -> None:
        for tampered_member in ("peer", "winner"):
            with self.subTest(tampered_member=tampered_member):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp) / "continuum"
                    peer = record_project_state(
                        root,
                        session_id="invalid-agent-a",
                        agent_id="agent-a",
                        project_id="invalid-resolution-project",
                        objective="Prepare release notes",
                    )
                    winner = record_project_state(
                        root,
                        session_id="invalid-agent-b",
                        agent_id="agent-b",
                        project_id="invalid-resolution-project",
                        objective="Prepare final review bundle",
                    )
                    target_id = (
                        peer["card_id"]
                        if tampered_member == "peer"
                        else winner["card_id"]
                    )
                    conn = connect(root)
                    try:
                        conn.execute(
                            "UPDATE cards SET summary = 'tampered' WHERE id = ?",
                            (target_id,),
                        )
                        conn.commit()
                    finally:
                        conn.close()

                    with self.assertRaisesRegex(
                        ValueError,
                        "failed integrity validation",
                    ):
                        resolve_conflict(
                            root,
                            card_id=winner["card_id"],
                            superseded_card_ids=[peer["card_id"]],
                        )

                    conn = connect(root)
                    try:
                        rows = {
                            str(row["id"]): row
                            for row in conn.execute(
                                "SELECT id, supersedes_card_id, "
                                "superseded_by_card_id FROM cards "
                                "WHERE id IN (?, ?)",
                                (peer["card_id"], winner["card_id"]),
                            )
                        }
                    finally:
                        conn.close()
                    self.assertIsNone(
                        rows[peer["card_id"]]["superseded_by_card_id"]
                    )
                    self.assertIsNone(
                        rows[winner["card_id"]]["supersedes_card_id"]
                    )

    def test_explicit_session_authority_resolution_stays_in_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="shared-authority-session",
                agent_id="agent-a",
                project_id="session-authority-project",
                objective="Prepare release notes",
                metadata={"visibility_scope": "session"},
            )
            winner = record_project_state(
                root,
                session_id="shared-authority-session",
                agent_id="agent-b",
                project_id="session-authority-project",
                objective="Prepare final review bundle",
                metadata={"visibility_scope": "session"},
            )
            outside = record_project_state(
                root,
                session_id="outside-authority-session",
                agent_id="agent-c",
                project_id="session-authority-project",
                objective="Continue an independent session",
                metadata={"visibility_scope": "session"},
            )

            ambiguous = resume_latest(
                root,
                session_id="shared-authority-session",
                model_assist=False,
            )
            self.assertFalse(ambiguous["ok"], ambiguous)
            self.assertEqual(ambiguous["reason"], "authority_ambiguous")
            with self.assertRaisesRegex(ValueError, "selected boundary"):
                resolve_conflict(
                    root,
                    card_id=winner["card_id"],
                    superseded_card_ids=[first["card_id"], outside["card_id"]],
                )

            resolved = resolve_conflict(
                root,
                card_id=winner["card_id"],
                superseded_card_ids=[first["card_id"]],
            )
            shared = resume_latest(
                root,
                session_id="shared-authority-session",
                model_assist=False,
            )
            separate = resume_latest(
                root,
                session_id="outside-authority-session",
                model_assist=False,
            )

            self.assertTrue(resolved["ok"], resolved)
            self.assertTrue(shared["ok"], shared)
            self.assertEqual(
                shared["discovery"]["checkpoint_id"],
                winner["card_id"],
            )
            self.assertTrue(separate["ok"], separate)
            self.assertEqual(
                separate["discovery"]["checkpoint_id"],
                outside["card_id"],
            )

    def test_immediate_cross_agent_session_heads_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="shared-session",
                agent_id="agent-a",
                project_id="session-project",
                decisions=["Use alpha routing for deployment"],
                metadata={"visibility_scope": "session"},
            )
            second = record_project_state(
                root,
                session_id="shared-session",
                agent_id="agent-b",
                project_id="session-project",
                decisions=["Do not use alpha routing for deployment"],
                metadata={"visibility_scope": "session"},
            )

            ambiguous = resume_latest(
                root,
                session_id="shared-session",
                model_assist=False,
            )

            self.assertFalse(ambiguous["ok"], ambiguous)
            self.assertEqual(ambiguous["reason"], "authority_ambiguous")
            details = ambiguous["authority_ambiguity"]
            self.assertEqual(
                details["boundary"],
                {
                    "visibility_scope": "session",
                    "project_id": "session-project",
                    "session_id": "shared-session",
                },
            )
            self.assertEqual(
                set(details["current_head_ids"]),
                {first["card_id"], second["card_id"]},
            )
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_resume_fails_closed_when_selected_boundary_scan_overflows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            invalid_head_ids = []
            for index in range(64):
                state = record_project_state(
                    root,
                    session_id=f"overflow-session-{index}",
                    agent_id=f"overflow-agent-{index}",
                    project_id="overflow-project",
                    objective=f"Historical independent state {index}",
                )
                invalid_head_ids.append(state["card_id"])
            selected = record_project_state(
                root,
                session_id="overflow-selected-session",
                agent_id="overflow-selected-agent",
                project_id="overflow-project",
                objective="VALID OVERFLOW SELECTED CHECKPOINT",
            )
            conn = connect(root)
            try:
                placeholders = ", ".join("?" for _ in invalid_head_ids)
                conn.execute(
                    f"UPDATE cards SET summary = 'invalid' "
                    f"WHERE id IN ({placeholders})",
                    tuple(invalid_head_ids),
                )
                conn.commit()
            finally:
                conn.close()

            ambiguous = resume_latest(
                root,
                project_id="overflow-project",
                model_assist=False,
            )

            self.assertFalse(ambiguous["ok"], ambiguous)
            self.assertEqual(ambiguous["reason"], "authority_ambiguous")
            details = ambiguous["authority_ambiguity"]
            self.assertEqual(details["current_head_ids"], [selected["card_id"]])
            self.assertEqual(details["head_count_at_least"], 1)
            self.assertEqual(details["boundary_scan_limit"], 64)
            self.assertTrue(details["boundary_scan_overflow"])
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_invalid_selected_cross_agent_head_precedes_ambiguity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            record_project_state(
                root,
                session_id="valid-older-session",
                agent_id="valid-older-agent",
                project_id="invalid-selected-project",
                objective="VALID OLDER CHECKPOINT",
            )
            invalid = record_project_state(
                root,
                session_id="invalid-newer-session",
                agent_id="invalid-newer-agent",
                project_id="invalid-selected-project",
                objective="INVALID NEWER CHECKPOINT",
            )
            conn = connect(root)
            try:
                conn.execute(
                    "UPDATE cards SET summary = 'invalid' WHERE id = ?",
                    (invalid["card_id"],),
                )
                conn.commit()
            finally:
                conn.close()

            resumed = resume_latest(
                root,
                project_id="invalid-selected-project",
                model_assist=False,
            )

            self.assertFalse(resumed["ok"], resumed)
            self.assertEqual(resumed["reason"], "invalid_project_state_checkpoint")
            self.assertEqual(
                resumed["invalid_checkpoint"]["checkpoint_id"],
                invalid["card_id"],
            )
            self.assertNotIn("authority_ambiguity", resumed)
            self.assertFalse((root / "exports" / "thread_recovery").exists())

    def test_same_agent_project_state_supersession_keeps_one_operational_head_and_raw_history(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            first = record_project_state(
                root,
                session_id="checkpoint-one",
                agent_id="codex-sol",
                project_id="checkpoint-project",
                objective="OLD_OBJECTIVE_9QQ",
                decisions=["OLD_DECISION_9QQ"],
                open_tasks=["OLD_TASK_9QQ"],
            )
            second = record_project_state(
                root,
                session_id="checkpoint-two",
                agent_id="codex-sol",
                project_id="checkpoint-project",
                objective="MIDDLE_OBJECTIVE_4RR",
                decisions=["MIDDLE_DECISION_4RR"],
                open_tasks=["MIDDLE_TASK_4RR"],
            )
            third = record_project_state(
                root,
                session_id="checkpoint-three",
                agent_id="codex-sol",
                project_id="checkpoint-project",
                objective="NEW_OBJECTIVE_7VV",
                decisions=["NEW_DECISION_7VV"],
                open_tasks=["NEW_TASK_7VV"],
            )

            workers = run_worker_pass(
                root,
                roles=["librarian"],
                limit=10,
                maintenance=False,
            )
            resumed = resume_latest(
                root,
                project_id="checkpoint-project",
                token_budget=5000,
                model_assist=False,
            )

            self.assertTrue(workers["ok"], workers)
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["discovery"]["checkpoint_id"], third["card_id"])
            self.assertEqual(second["supersedes_card_id"], first["card_id"])
            self.assertEqual(third["supersedes_card_id"], second["card_id"])
            for marker in (
                "OLD_OBJECTIVE_9QQ",
                "OLD_DECISION_9QQ",
                "OLD_TASK_9QQ",
                "MIDDLE_OBJECTIVE_4RR",
                "MIDDLE_DECISION_4RR",
                "MIDDLE_TASK_4RR",
            ):
                self.assertNotIn(marker, resumed["packet_text"])
            self.assertIn("NEW_OBJECTIVE_7VV", resumed["packet_text"])
            self.assertIn("NEW_DECISION_7VV", resumed["packet_text"])
            self.assertIn("NEW_TASK_7VV", resumed["packet_text"])

            conn = connect(root)
            try:
                rows = {
                    str(row["id"]): dict(row)
                    for row in conn.execute(
                        """
                        SELECT id, status, decisions_json, open_tasks_json,
                               supersedes_card_id, superseded_by_card_id,
                               conflict_group
                        FROM cards
                        WHERE id IN (?, ?, ?)
                        """,
                        (first["card_id"], second["card_id"], third["card_id"]),
                    )
                }
                current_ids = [
                    str(row["id"])
                    for row in conn.execute(
                        f"""
                        SELECT id
                        FROM cards
                        WHERE card_type = 'project_state'
                          AND {store_module._current_card_authority_clause('cards')}
                        """
                    )
                ]
            finally:
                conn.close()

            self.assertEqual(current_ids, [third["card_id"]])
            self.assertEqual(rows[first["card_id"]]["superseded_by_card_id"], second["card_id"])
            self.assertIsNone(rows[first["card_id"]]["supersedes_card_id"])
            self.assertEqual(rows[second["card_id"]]["supersedes_card_id"], first["card_id"])
            self.assertEqual(rows[second["card_id"]]["superseded_by_card_id"], third["card_id"])
            self.assertEqual(rows[third["card_id"]]["supersedes_card_id"], second["card_id"])
            self.assertIsNone(rows[third["card_id"]]["superseded_by_card_id"])
            self.assertEqual(
                json.loads(rows[first["card_id"]]["decisions_json"]),
                ["OLD_DECISION_9QQ"],
            )

            historical = compile_context(
                root,
                session_id="checkpoint-one",
                project_id="checkpoint-project",
                token_budget=5000,
                planner_profile="legacy",
                create=False,
            )
            self.assertIn("OLD_OBJECTIVE_9QQ", historical["context_text"])
            self.assertIn("OLD_DECISION_9QQ", historical["context_text"])
            self.assertIn("OLD_TASK_9QQ", historical["context_text"])

    def test_concurrent_same_agent_checkpoints_form_one_serialized_head(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            seed = record_project_state(
                root,
                session_id="concurrent-seed",
                agent_id="codex-sol",
                project_id="concurrent-project",
                objective="Seed checkpoint",
            )
            writer_count = 8
            barrier = threading.Barrier(writer_count)

            def write_checkpoint(index: int) -> dict[str, object]:
                barrier.wait()
                return record_project_state(
                    root,
                    session_id=f"concurrent-session-{index}",
                    agent_id="codex-sol",
                    project_id="concurrent-project",
                    objective=f"Concurrent checkpoint {index}",
                    decisions=[f"concurrent-decision-{index}"],
                    open_tasks=[f"concurrent-task-{index}"],
                )

            with ThreadPoolExecutor(max_workers=writer_count) as executor:
                results = list(executor.map(write_checkpoint, range(writer_count)))

            workers = run_worker_pass(
                root,
                roles=["librarian"],
                limit=20,
                maintenance=False,
            )
            self.assertTrue(workers["ok"], workers)
            self.assertEqual(len({str(result["card_id"]) for result in results}), writer_count)

            conn = connect(root)
            try:
                rows = [
                    dict(row)
                    for row in conn.execute(
                        """
                        SELECT rowid AS card_rowid, id, supersedes_card_id,
                               superseded_by_card_id, conflict_group
                        FROM cards
                        WHERE card_type = 'project_state'
                          AND project_id = 'concurrent-project'
                        ORDER BY card_rowid
                        """
                    )
                ]
                head_ids = [
                    str(row["id"])
                    for row in conn.execute(
                        f"""
                        SELECT id
                        FROM cards
                        WHERE card_type = 'project_state'
                          AND project_id = 'concurrent-project'
                          AND {store_module._current_card_authority_clause('cards')}
                        """
                    )
                ]
            finally:
                conn.close()

            self.assertEqual(len(rows), writer_count + 1)
            self.assertEqual(head_ids, [rows[-1]["id"]])
            by_id = {str(row["id"]): row for row in rows}
            self.assertIn(seed["card_id"], by_id)
            for row in rows[:-1]:
                successor_id = str(row["superseded_by_card_id"] or "")
                self.assertIn(successor_id, by_id)
                self.assertEqual(by_id[successor_id]["supersedes_card_id"], row["id"])
                self.assertIsNone(row["conflict_group"])
            self.assertIsNone(rows[-1]["superseded_by_card_id"])
            self.assertIsNone(rows[-1]["conflict_group"])

            detected = detect_conflicts(root)
            self.assertEqual(detected["conflict_count"], 0, detected)

    def test_identical_project_state_calls_create_distinct_acyclic_checkpoints(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            values = {
                "session_id": "identical-session",
                "agent_id": "identical-agent",
                "project_id": "identical-project",
                "objective": "IDENTICAL_CHECKPOINT_OBJECTIVE",
                "decisions": ["IDENTICAL_CHECKPOINT_DECISION"],
                "open_tasks": ["IDENTICAL_CHECKPOINT_TASK"],
            }
            first = record_project_state(root, **values)
            second = record_project_state(root, **values)

            self.assertNotEqual(first["event_id"], second["event_id"])
            self.assertNotEqual(first["card_id"], second["card_id"])
            self.assertEqual(second["supersedes_card_id"], first["card_id"])
            conn = connect(root)
            try:
                rows = [
                    dict(row)
                    for row in conn.execute(
                        """
                        SELECT id, supersedes_card_id, superseded_by_card_id
                        FROM cards WHERE card_type = 'project_state' ORDER BY rowid
                        """
                    )
                ]
                current_ids = [
                    str(row["id"])
                    for row in conn.execute(
                        f"""
                        SELECT id FROM cards
                        WHERE card_type = 'project_state'
                          AND {store_module._current_card_authority_clause('cards')}
                        """
                    )
                ]
            finally:
                conn.close()
            self.assertEqual(current_ids, [second["card_id"]])
            self.assertTrue(
                all(
                    row["id"] != row["supersedes_card_id"]
                    and row["id"] != row["superseded_by_card_id"]
                    for row in rows
                )
            )
            resumed = resume_latest(
                root,
                project_id="identical-project",
                token_budget=3000,
                model_assist=False,
            )
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(
                resumed["discovery"]["checkpoint_id"],
                second["card_id"],
            )

    def test_repeated_older_payload_appends_new_head_without_reversing_chain(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "continuum"
            repeated_values = {
                "session_id": "aba-session",
                "agent_id": "aba-agent",
                "project_id": "aba-project",
                "objective": "ABA_OBJECTIVE_A",
                "decisions": ["ABA_DECISION_A"],
                "open_tasks": ["ABA_TASK_A"],
            }
            first = record_project_state(root, **repeated_values)
            middle = record_project_state(
                root,
                session_id="aba-session",
                agent_id="aba-agent",
                project_id="aba-project",
                objective="ABA_OBJECTIVE_B",
                decisions=["ABA_DECISION_B"],
                open_tasks=["ABA_TASK_B"],
            )
            third = record_project_state(root, **repeated_values)

            self.assertNotEqual(first["event_id"], third["event_id"])
            self.assertNotEqual(first["card_id"], third["card_id"])
            self.assertEqual(middle["supersedes_card_id"], first["card_id"])
            self.assertEqual(third["supersedes_card_id"], middle["card_id"])
            conn = connect(root)
            try:
                rows = {
                    str(row["id"]): dict(row)
                    for row in conn.execute(
                        """
                        SELECT id, supersedes_card_id, superseded_by_card_id
                        FROM cards WHERE card_type = 'project_state'
                        """
                    )
                }
                current_ids = [
                    str(row["id"])
                    for row in conn.execute(
                        f"""
                        SELECT id FROM cards
                        WHERE card_type = 'project_state'
                          AND {store_module._current_card_authority_clause('cards')}
                        """
                    )
                ]
            finally:
                conn.close()
            self.assertEqual(current_ids, [third["card_id"]])
            cursor: str | None = third["card_id"]
            visited: list[str] = []
            while cursor:
                self.assertNotIn(cursor, visited)
                visited.append(cursor)
                cursor = rows[cursor]["supersedes_card_id"]
            self.assertEqual(
                visited,
                [third["card_id"], middle["card_id"], first["card_id"]],
            )
            resumed = resume_latest(
                root,
                project_id="aba-project",
                token_budget=3000,
                model_assist=False,
            )
            self.assertTrue(resumed["ok"], resumed)
            self.assertEqual(resumed["discovery"]["checkpoint_id"], third["card_id"])
            self.assertNotIn("ABA_OBJECTIVE_B", resumed["packet_text"])
            self.assertNotIn("ABA_DECISION_B", resumed["packet_text"])
            self.assertNotIn("ABA_TASK_B", resumed["packet_text"])

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
            self.assertEqual(result["reason"], "authority_ambiguous")
            self.assertTrue(result["resolution_required"])
            self.assertFalse((root / "exports" / "thread_recovery").exists())


if __name__ == "__main__":
    unittest.main()
