from __future__ import annotations

import copy
import hashlib
import json
import socket
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from continuum.core.config import default_config, write_config
from continuum.core.recall import read_memory_source, recall_memory
from continuum.core.store import (
    NON_CURRENT_CARD_STATUSES,
    _current_card_authority_clause,
    add_graph_edge,
    append_scroll_event,
    connect,
    connect_existing,
    create_card,
    ingest_file,
    init_db,
    record_project_state,
    upsert_graph_node,
)
from continuum.core.tool_outputs import record_indexed_tool_result


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class UnifiedRecallTests(unittest.TestCase):
    """Synthetic contract regressions, not embedding-quality measurements."""

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="continuum-unified-recall-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / "memory"
        self.contents: dict[tuple[str, str], str] = {}
        self.prepared = False
        for target in ("urllib.request.urlopen", "continuum.core.local_model._http_json"):
            blocker = patch(target, side_effect=AssertionError("network/model access forbidden"))
            blocker.start()
            self.addCleanup(blocker.stop)
        blocker = patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden"))
        blocker.start()
        self.addCleanup(blocker.stop)

    def prepare(self) -> None:
        if not self.prepared:
            config = default_config()
            config["capture"]["mode"] = "manual"
            config["local_inference"]["enabled"] = False
            write_config(self.root, config)
            init_db(self.root)
            self.prepared = True

    def card(self, text: str, *, title: str = "Evidence card", scope: str = "global",
             session: str = "session-a", project: str | None = None) -> tuple[str, str]:
        self.prepare()
        with closing(connect(self.root)) as conn:
            source_id = create_card(
                conn, root=self.root, card_type="decision", title=title, summary=text,
                source_refs=[], visibility_scope=scope, session_id=session, project_id=project,
            )
            conn.commit()
        key = ("card", source_id)
        self.contents[key] = title + "\n" + text
        return key

    def event(self, text: str, *, scope: str = "global", session: str = "session-a",
              project: str | None = None) -> tuple[str, str]:
        self.prepare()
        metadata = {"visibility_scope": scope, "continuum_disable_exact_memory": True}
        if project is not None:
            metadata["project_id"] = project
        result = append_scroll_event(
            self.root, session_id=session, event_type="message", role="user",
            content=text, metadata=metadata,
        )
        key = ("scroll_event", result["event_id"])
        self.contents[key] = text
        return key

    def chunks(self, text: str, *, scope: str = "global", session: str = "session-a",
               project: str | None = None) -> list[tuple[str, str]]:
        self.prepare()
        metadata = {"visibility_scope": scope, "tool_name": "recall-fixture"}
        if project is not None:
            metadata["project_id"] = project
        result = record_indexed_tool_result(
            self.root, session_id=session, event_type="tool_result", text=text,
            metadata=metadata, max_reference_bytes=128,
        )
        with closing(connect_existing(self.root)) as conn:
            rows = conn.execute(
                "SELECT id, text FROM chunks WHERE book_id=? ORDER BY ordinal", (result["book_id"],)
            ).fetchall()
        keys = [("chunk", row["id"]) for row in rows]
        self.contents.update((key, row["text"]) for key, row in zip(keys, rows))
        return keys

    def sources(self, text: str, **scope) -> list[tuple[str, str]]:
        return [self.card(text, **scope), self.event(text, **scope), *self.chunks(text, **scope)]

    def semantic(self, query: str, keys: list[tuple[str, str]]) -> dict:
        return {
            "model": "fixture-embedding-v1", "query_hash": digest(query), "query_vector": [1.0, 0.0],
            "items": [{"kind": kind, "id": source_id, "content_hash": digest(self.contents[(kind, source_id)]),
                       "vector": [1.0, 0.0]} for kind, source_id in keys],
        }

    def read(self, key: tuple[str, str], **kwargs) -> dict:
        return read_memory_source(self.root, kind=key[0], source_id=key[1], **kwargs)

    def keys(self, packet: dict) -> set[tuple[str, str]]:
        return {(item["kind"], item["id"]) for item in packet["results"]}

    def assert_packet_budget(self, packet: dict, budget: int) -> None:
        encoded = json.dumps(packet, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        self.assertEqual(json.loads(encoded), packet)
        self.assertLessEqual(len(encoded), budget * 4)
        self.assertEqual(packet["budget"]["estimated_tokens"], (len(encoded) + 3) // 4)
        self.assertEqual(packet["budget"]["requested_tokens"], budget)
        self.assertEqual(packet["result_count"], len(packet["results"]))
        self.assertEqual(packet["abstained"], not packet["results"])

    def test_literal_recall_covers_all_sources_and_explains_exact_evidence(self) -> None:
        keys = self.sources("quartzneedle chooses amber.")
        packet = recall_memory(self.root, query="quartzneedle", limit=20, token_budget=5000)
        self.assertTrue(set(keys).issubset(self.keys(packet)), packet)
        self.assertEqual(packet["query_hash"], digest("quartzneedle"))
        self.assertEqual(packet["instruction_authority"], "none")
        self.assertEqual(packet["retrieval"]["method"], "rrf_60")
        for item in packet["results"]:
            key = (item["kind"], item["id"])
            if key not in self.contents:
                continue
            content = self.contents[key]
            self.assertEqual(item["content_hash"], digest(content))
            self.assertEqual(item["total_chars"], len(content))
            self.assertEqual(item["excerpt"], content[item["excerpt_start"]:item["excerpt_end"]])
            self.assertGreaterEqual(item["ranks"]["lexical"], 1)
            self.assertAlmostEqual(item["score"], sum(1 / (60 + rank) for rank in item["ranks"].values()), places=7)
            self.assertNotIn("metadata", item)
        self.assert_packet_budget(packet, 5000)

    def test_legacy_library_metadata_remains_global_only(self) -> None:
        self.prepare()
        source = self.directory / "legacy-library.txt"
        source.write_text("legacyquartz library evidence", encoding="utf-8")
        result = ingest_file(self.root, path=source, title="Legacy Library")
        with closing(connect_existing(self.root)) as conn:
            row = conn.execute("SELECT id FROM chunks WHERE book_id=?", (result["book_id"],)).fetchone()
        key = ("chunk", row["id"])
        self.assertIn(key, self.keys(recall_memory(self.root, query="legacyquartz")))
        for scope in ({"session_id": "session-a"}, {"project_id": "project-a"}):
            with self.subTest(scope=scope):
                self.assertNotIn(key, self.keys(recall_memory(self.root, query="legacyquartz", **scope)))
                self.assertFalse(self.read(key, **scope)["found"])

    def test_scope_matrix_excludes_private_and_global_with_any_selector(self) -> None:
        grouped = {
            "global": self.sources("scopequartz global evidence"),
            "session": self.sources("scopequartz session evidence", scope="session"),
            "project": self.sources("scopequartz project evidence", scope="project", project="project-a"),
            "other": self.sources("scopequartz other evidence", scope="project", project="project-b"),
            "private": self.sources("scopequartz PRIVATE_PAYLOAD", scope="private", project="project-a"),
        }
        cases = [({}, {"global"}), ({"session_id": "session-a"}, {"session"}),
                 ({"project_id": "project-a"}, {"project"}),
                 ({"session_id": "session-a", "project_id": "project-a"}, {"session", "project"}),
                 ({"session_id": "wrong", "project_id": "wrong"}, set())]
        for scope, allowed in cases:
            with self.subTest(scope=scope):
                packet = recall_memory(self.root, query="scopequartz", limit=50, token_budget=10000, **scope)
                actual = self.keys(packet)
                serialized = json.dumps(packet)
                self.assertNotIn("PRIVATE_PAYLOAD", serialized)
                self.assertNotIn(str(self.directory), serialized)
                for group, keys in grouped.items():
                    for key in keys:
                        self.assertEqual(key in actual, group in allowed, (scope, group, packet))
                        self.assertEqual(self.read(key, **scope)["found"], group in allowed)
                        if group not in allowed:
                            self.assertNotIn(key[1], serialized)

    def test_recorded_window_is_utc_aware_half_open_for_every_source_kind(self) -> None:
        groups = [self.sources(f"timequartz evidence {index}") for index in range(4)]
        times = ["2026-10-22T23:59:59+00:00", "2026-10-23T02:00:00+02:00",
                 "2026-10-23T12:00:00+00:00", "2026-10-24T00:00:00Z"]
        tables = {"card": "cards", "scroll_event": "scroll_events", "chunk": "chunks"}
        with closing(connect(self.root)) as conn:
            for keys, timestamp in zip(groups, times):
                for kind, source_id in keys:
                    conn.execute(f"UPDATE {tables[kind]} SET created_at=? WHERE id=?", (timestamp, source_id))
            conn.commit()
        query = "timequartz"
        packet = recall_memory(self.root, query=query, limit=50, token_budget=10000,
                               created_after="2026-10-22T20:00:00-04:00",
                               created_before="2026-10-24T00:00:00Z",
                               semantic=self.semantic(query, [key for group in groups for key in group]))
        self.assertEqual(self.keys(packet), set(groups[1] + groups[2]))
        self.assertEqual(packet["recorded_time"], {"after": "2026-10-23T00:00:00+00:00",
                                                   "before": "2026-10-24T00:00:00+00:00"})
        self.assertEqual(packet["retrieval"]["channels"]["semantic"], 6)

    def test_invalid_stored_timestamps_fail_closed(self) -> None:
        keys = self.sources("invalidtimequartz evidence")
        with closing(connect(self.root)) as conn:
            for table, key, timestamp in zip(("cards", "scroll_events", "chunks"), keys,
                                             ("not-a-time", "2026-10-23T12:00:00", "2026-99-99T00:00:00Z")):
                conn.execute(f"UPDATE {table} SET created_at=? WHERE id=?", (timestamp, key[1]))
            conn.commit()
        packet = recall_memory(self.root, query="invalidtimequartz", semantic=self.semantic("invalidtimequartz", keys))
        self.assertTrue(set(keys).isdisjoint(self.keys(packet)))
        for key in keys:
            self.assertFalse(self.read(key)["found"])

    def test_noncurrent_statuses_conflicts_and_one_way_supersession_are_blocked(self) -> None:
        blocked = []
        for status in sorted(NON_CURRENT_CARD_STATUSES):
            key = self.card("currentquartz retired " + status, title=status)
            with closing(connect(self.root)) as conn:
                conn.execute("UPDATE cards SET status=? WHERE id=?", (status, key[1]))
                conn.commit()
            blocked.append(key)
        conflicted = self.card("currentquartz disputed", title="Disputed")
        predecessor = self.card("currentquartz previous", title="Lineage")
        successor = self.card("currentquartz current", title="Lineage")
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE cards SET conflict_group='fixture-conflict' WHERE id=?", (conflicted[1],))
            # Reuse the one-way-lineage authority regression from test_resume.
            conn.execute("UPDATE cards SET supersedes_card_id=? WHERE id=?", (predecessor[1], successor[1]))
            conn.commit()
        blocked.extend([conflicted, predecessor])
        packet = recall_memory(self.root, query="currentquartz", limit=50,
                               semantic=self.semantic("currentquartz", blocked + [successor]))
        self.assertEqual(self.keys(packet), {successor})
        missing = self.read(("card", "never-existed"))
        for key in blocked:
            self.assertEqual(self.read(key), missing)
            self.assertNotIn(key[1], json.dumps(packet))
        self.assertTrue(self.read(successor)["found"])

    def test_exact_card_and_semantic_authority_extend_beyond_recovery_pool_cutoff(self) -> None:
        self.prepare()
        with closing(connect(self.root)) as conn:
            # Match the independent boundary probe: one real catalog transaction
            # through create_card, without creating 10,001 irrelevant sidecars.
            ids = [create_card(
                conn, card_type="decision", title=f"Boundary card {index}",
                summary="Complete and current evidence", source_refs=[], visibility_scope="global",
            ) for index in range(10001)]
            conn.commit()
            self.assertEqual(len(set(ids)), 10001)
            target = ("card", max(ids))
            eligible = conn.execute(
                f"SELECT id FROM cards WHERE {_current_card_authority_clause()} ORDER BY id"
            ).fetchall()
            self.assertEqual(len(eligible), 10001)
            self.assertEqual(eligible[10000]["id"], target[1])
            row = conn.execute("SELECT title, summary FROM cards WHERE id=?", (target[1],)).fetchone()
            self.contents[target] = row["title"] + "\n" + row["summary"]

        exact = self.read(target, content_hash=digest(self.contents[target]))
        self.assertTrue(exact["found"])
        self.assertEqual(exact["content"], self.contents[target])
        self.assertEqual(exact["content_hash"], digest(self.contents[target]))
        query = "boundarysemanticparaphrasequartz"
        semantic = self.semantic(query, [target])
        packet = recall_memory(self.root, query=query, semantic=semantic)
        self.assertEqual(self.keys(packet), {target})
        self.assertEqual(packet["results"][0]["ranks"], {"semantic": 1})

        missing = {"found": False, "content": "", "next_offset": None}
        for scope in ({"session_id": "session-a"}, {"project_id": "project-a"},
                      {"session_id": "session-a", "project_id": "project-a"}):
            with self.subTest(scope=scope):
                self.assertEqual(self.read(target, **scope), missing)
                scoped = recall_memory(self.root, query=query, semantic=semantic, **scope)
                self.assertEqual(scoped["results"], [])
                self.assertNotIn(target[1], json.dumps(scoped))

        with closing(connect(self.root)) as conn:
            derived_id = create_card(
                conn, card_type="decision", title="Derived boundary authority",
                summary="derivedboundaryquartz depends on the last current source",
                source_refs=[{"card_id": target[1]}], visibility_scope="global",
            )
            conn.commit()
            row = conn.execute("SELECT title, summary FROM cards WHERE id=?", (derived_id,)).fetchone()
        derived = ("card", derived_id)
        self.contents[derived] = row["title"] + "\n" + row["summary"]
        self.assertTrue(self.read(derived)["found"])
        semantic = self.semantic(query, [target, derived])
        packet = recall_memory(self.root, query=query, semantic=semantic)
        self.assertEqual(self.keys(packet), {target, derived})
        self.assertTrue(all(set(item["ranks"]) == {"semantic"} for item in packet["results"]))

        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE cards SET status='superseded' WHERE id=?", (target[1],))
            conn.commit()
        self.assertEqual(self.read(target), missing)
        self.assertEqual(self.read(derived), missing)
        for current_query, evidence in ((query, semantic), ("derivedboundaryquartz", None)):
            with self.subTest(query=current_query):
                packet = recall_memory(self.root, query=current_query, semantic=evidence)
                self.assertEqual(packet["results"], [])
                self.assertNotIn(target[1], json.dumps(packet))
                self.assertNotIn(derived[1], json.dumps(packet))

    def test_project_checkpoints_require_current_payload_bound_authority(self) -> None:
        self.prepare()
        states = [record_project_state(
            self.root, session_id=f"checkpoint-{index}", agent_id="fixture-agent",
            project_id="checkpoint-project", objective=f"checkpointquartz step {index}",
            decisions=[f"decision-{index}"],
        ) for index in range(2)]
        before, current = states
        current_keys = {("card", current["card_id"]), ("scroll_event", current["event_id"])}
        packet = recall_memory(self.root, query="checkpointquartz", project_id="checkpoint-project", limit=20)
        self.assertTrue(current_keys.issubset(self.keys(packet)), packet)
        for kind, field in (("card", "card_id"), ("scroll_event", "event_id")):
            self.assertNotIn((kind, before[field]), self.keys(packet))
            self.assertFalse(self.read((kind, before[field]), project_id="checkpoint-project")["found"])
            self.assertTrue(self.read((kind, current[field]), project_id="checkpoint-project")["found"])
        # This existing authority fixture corrupts the durable payload, not just the view.
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE cards SET decisions_json=? WHERE id=?", ('["tampered"]', current["card_id"]))
            conn.commit()
        packet = recall_memory(self.root, query="checkpointquartz", project_id="checkpoint-project")
        self.assertTrue(current_keys.isdisjoint(self.keys(packet)), packet)
        for key in current_keys:
            self.assertFalse(self.read(key, project_id="checkpoint-project")["found"])

    def test_unicode_exact_pagination_and_content_hash_for_all_kinds(self) -> None:
        text = "  A\r\nStraße İstanbul e\u0301 é 東京 😀\t\n" * 7 + "  end  "
        keys = self.sources(text)
        for key in keys:
            with self.subTest(kind=key[0]):
                expected = self.contents[key]
                offset, pages = 0, []
                for _ in range(len(expected) + 1):
                    page = self.read(key, offset=offset, limit=7, content_hash=digest(expected))
                    self.assertTrue(page["found"])
                    self.assertEqual(page["content"], expected[offset:offset + 7])
                    self.assertEqual(page["content_hash"], digest(expected))
                    self.assertEqual(page["total_chars"], len(expected))
                    self.assertEqual(page["instruction_authority"], "none")
                    pages.append(page["content"])
                    if page["next_offset"] is None:
                        break
                    self.assertGreater(page["next_offset"], offset)
                    offset = page["next_offset"]
                else:
                    self.fail("source pagination did not terminate")
                self.assertEqual("".join(pages), expected)
                self.assertEqual(self.read(key, offset=len(expected))["content"], "")
                with self.assertRaisesRegex(ValueError, "offset"):
                    self.read(key, offset=len(expected) + 1)

    def test_chunk_continuation_roundtrips_one_book_without_crossing_scope(self) -> None:
        text = "αβ 東京 😀\r\n" * 1200
        keys = self.chunks(text, scope="project", project="project-a")
        self.assertGreater(len(keys), 1)
        self.chunks("other project continuation", scope="project", project="project-b")
        key, offset, collected, visited = keys[0], 0, [], []
        for _ in range(100):
            page = self.read(key, project_id="project-a", offset=offset, limit=777,
                             content_hash=digest(self.contents[key]))
            self.assertTrue(page["found"])
            collected.append(page["content"])
            if page["next_offset"] is not None:
                self.assertIsNone(page["next_chunk_id"])
                offset = page["next_offset"]
            else:
                visited.append(key)
                if page["next_chunk_id"] is None:
                    break
                key, offset = ("chunk", page["next_chunk_id"]), 0
        else:
            self.fail("book pagination did not terminate")
        self.assertEqual(visited, keys)
        self.assertEqual("".join(collected), text)
        for key in keys:
            self.assertFalse(self.read(key, project_id="project-b")["found"])

    def test_hash_mismatch_missing_and_inaccessible_are_indistinguishable(self) -> None:
        keys = self.sources("pinquartz original evidence")
        private = self.sources("pinquartz hidden", scope="private")
        for key, secret in zip(keys, private):
            missing = self.read((key[0], "never-existed"))
            self.assertEqual(missing, {"found": False, "content": "", "next_offset": None})
            self.assertEqual(self.read(key, content_hash="0" * 64), missing)
            self.assertEqual(self.read(secret), missing)
        old_hash = digest(self.contents[keys[0]])
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE cards SET summary='Changed source' WHERE id=?", (keys[0][1],))
            conn.commit()
        self.assertFalse(self.read(keys[0], offset=1, content_hash=old_hash)["found"])
        self.assertNotEqual(self.read(keys[0])["content_hash"], old_hash)

    def test_query_centered_unicode_excerpt_offsets_rehydrate_exact_text(self) -> None:
        content = "前置き ordinary. " * 300 + "Straße İstanbul quartzsignal final decision." + " 后续" * 300
        key = self.event(content)
        packet = recall_memory(self.root, query="Straße İstanbul quartzsignal")
        hit = next(item for item in packet["results"] if item["id"] == key[1])
        self.assertIn("quartzsignal", hit["excerpt"])
        self.assertGreater(hit["excerpt_start"], 0)
        exact = content[hit["excerpt_start"]:hit["excerpt_end"]]
        self.assertEqual(hit["excerpt"], "..." + exact + "...")
        page = self.read(key, offset=hit["excerpt_start"], limit=len(exact), content_hash=hit["content_hash"])
        self.assertEqual(page["content"], exact)

    def test_precomputed_semantic_only_paraphrase_requires_no_model(self) -> None:
        key = self.card("Automobile renewal costs become smaller.", title="Transport savings")
        query = "vehicle insurance premium reduction"
        baseline = recall_memory(self.root, query=query)
        self.assertNotIn(key, self.keys(baseline))
        semantic = self.semantic(query, [key])
        original = copy.deepcopy(semantic)
        packet = recall_memory(self.root, query=query, semantic=semantic)
        self.assertEqual(self.keys(packet), {key})
        self.assertEqual(packet["results"][0]["ranks"], {"semantic": 1})
        self.assertEqual(packet["retrieval"]["semantic_model_sha256"], digest("fixture-embedding-v1"))
        self.assertEqual(semantic, original)

    def test_semantic_untrusted_ids_stale_hashes_and_scope_do_not_leak(self) -> None:
        valid = self.sources("Visible transport savings", scope="project", project="project-a")
        private = self.sources("PRIVATE_VECTOR_PAYLOAD", scope="private", project="project-a")
        other = self.sources("OTHER_VECTOR_PAYLOAD", scope="project", project="project-b")
        stale = self.sources("Old visible content", scope="project", project="project-a")
        query = "semanticparaphrasequartz"
        semantic = self.semantic(query, valid + private + other + stale)
        for item in semantic["items"][-len(stale):]:
            item["content_hash"] = "0" * 64
        for kind in ("card", "scroll_event", "chunk"):
            semantic["items"].append({"kind": kind, "id": "provider-invented-id", "content_hash": "0" * 64,
                                      "vector": [1.0, 0.0]})
        packet = recall_memory(self.root, query=query, project_id="project-a", semantic=semantic)
        self.assertEqual(self.keys(packet), set(valid))
        self.assertEqual(packet["retrieval"]["channels"]["semantic"], len(valid))
        self.assertEqual(packet["retrieval"]["candidate_count"], len(valid))
        encoded = json.dumps(packet)
        forbidden = [key[1] for key in private + other + stale]
        forbidden += ["provider-invented-id", "PRIVATE_VECTOR_PAYLOAD", "OTHER_VECTOR_PAYLOAD"]
        for value in forbidden:
            self.assertNotIn(value, encoded)

    def test_semantic_nonpositive_similarity_is_not_a_recall_candidate(self) -> None:
        keys = [self.card(f"Transport evidence {index}") for index in range(3)]
        query = "semanticorthogonalquartz"
        semantic = self.semantic(query, keys)
        semantic["items"][1]["vector"] = [0.0, 1.0]
        semantic["items"][2]["vector"] = [-1.0, 0.0]
        packet = recall_memory(self.root, query=query, semantic=semantic)
        self.assertEqual(self.keys(packet), {keys[0]})
        self.assertEqual(packet["retrieval"]["channels"]["semantic"], 1)
        self.assertEqual(packet["results"][0]["ranks"], {"semantic": 1})

    def test_vector_hash_is_exact_utf8_not_normalized_text(self) -> None:
        key = self.card("Cafe\u0301 transport savings", title="Decomposed")
        query = "semanticquartz"
        semantic = self.semantic(query, [key])
        semantic["items"][0]["content_hash"] = digest(self.contents[key].replace("e\u0301", "é"))
        self.assertNotIn(key, self.keys(recall_memory(self.root, query=query, semantic=semantic)))

    def test_reciprocal_rank_fusion_deduplicates_and_combines_literal_vector_evidence(self) -> None:
        first = self.card("fusionquartz amber", title="Alpha")
        second = self.card("fusionquartz violet", title="Beta")
        semantic = self.semantic("fusionquartz", [first, second])
        semantic["items"][0]["vector"] = [0.5, 0.5]
        packet = recall_memory(self.root, query="fusionquartz", semantic=semantic)
        self.assertEqual(self.keys(packet), {first, second})
        self.assertEqual(packet["result_count"], 2)
        hits = {item["id"]: item for item in packet["results"]}
        self.assertEqual(hits[second[1]]["ranks"]["semantic"], 1)
        self.assertEqual(hits[first[1]]["ranks"]["semantic"], 2)
        for hit in hits.values():
            self.assertIn("lexical", hit["ranks"])
            self.assertAlmostEqual(hit["score"], sum(1 / (60 + rank) for rank in hit["ranks"].values()), places=7)
        expected = sorted(hits.values(), key=lambda hit: (-hit["score"], hit["kind"], hit["id"]))
        self.assertEqual(packet["results"], expected)

    def test_associative_only_route_is_scoped_by_provenance(self) -> None:
        key = self.card("The chosen color is amber", scope="project", project="project-a")
        query = "ZXQJXQ999777"
        with closing(connect(self.root)) as conn:
            term_node = upsert_graph_node(conn, kind="term", label=query)
            card_node = upsert_graph_node(conn, kind="card", label="Graph target", card_id=key[1])
            add_graph_edge(conn, source_node_id=term_node, relation="points_to", target_node_id=card_node,
                           weight=0.9, confidence=0.9, merge_mode="max",
                           source_refs=[{"card_id": key[1], "visibility_scope": "project", "project_id": "project-a"}])
            conn.commit()
        packet = recall_memory(self.root, query=query, project_id="project-a")
        self.assertEqual(self.keys(packet), {key})
        self.assertEqual(packet["results"][0]["ranks"], {"associative": 1})
        for scope in ({}, {"project_id": "project-b"}, {"session_id": "session-a"}):
            with self.subTest(scope=scope):
                self.assertNotIn(key, self.keys(recall_memory(self.root, query=query, **scope)))

    def test_complete_ascii_json_budget_trace_includes_limit_and_budget_exclusions(self) -> None:
        for index in range(12):
            self.card("budgetquartz " + "東京 😀 café " * 200, title=f"Budget {index}")
        for budget in (512, 600, 1000, 2400, 32768):
            with self.subTest(budget=budget):
                packet = recall_memory(self.root, query="budgetquartz", limit=7, token_budget=budget)
                self.assert_packet_budget(packet, budget)
                trace = packet["retrieval"]
                self.assertEqual(trace["candidate_count"], 12)
                self.assertEqual(trace["excluded_by_limit"], 5)
                self.assertEqual(packet["result_count"] + trace["excluded_by_budget"] + trace["excluded_by_limit"], 12)
                if budget == 512:
                    self.assertGreater(trace["excluded_by_budget"], 0)
        self.assertEqual(recall_memory(self.root, query="no-such-evidence")["results"], [])

    def test_maximum_astral_model_alias_fits_minimum_packet_without_echo_or_truncation(self) -> None:
        query = "modelaliasquartz"
        model = "\U0001f600" * 128
        semantic = self.semantic(query, [])
        semantic["model"] = model
        original = copy.deepcopy(semantic)
        after = "2026-10-23T00:00:00.123456+00:00"
        before = "2026-10-24T00:00:00.654321+00:00"
        packet = recall_memory(self.root, query=query, semantic=semantic, token_budget=512,
                               created_after=after, created_before=before)
        self.assert_packet_budget(packet, 512)
        self.assertFalse(packet["initialized"])
        self.assertEqual(packet["results"], [])
        self.assertEqual(packet["recorded_time"], {"after": after, "before": before})
        self.assertEqual(packet["retrieval"]["semantic_model_sha256"], digest(model))
        self.assertNotEqual(packet["retrieval"]["semantic_model_sha256"], digest(model[:-1]))
        self.assertNotIn("semantic_model", packet["retrieval"])
        self.assertNotIn(model[0], json.dumps(packet, ensure_ascii=False))
        self.assertEqual(semantic, original)
        self.assertFalse(self.root.exists())

    def test_lexical_candidate_pool_reports_truncation(self) -> None:
        keys = [self.card(f"poolquartz entry {index}", title=f"Pool {index}") for index in range(65)]
        packet = recall_memory(self.root, query="poolquartz", limit=50, token_budget=32768)
        self.assertTrue(packet["retrieval"]["lexical_truncated"])
        self.assertEqual(packet["retrieval"]["candidate_limits"]["lexical_per_kind"], 64)
        self.assertEqual(packet["retrieval"]["channels"]["lexical"], 64)
        self.assertLessEqual(packet["result_count"], 50)
        self.assert_packet_budget(packet, 32768)
        # Sixty-four newer, out-of-window rows must not crowd the one in-window
        # source out of the lexical pool before the timestamp predicate runs.
        chosen = keys[-1]
        with closing(connect(self.root)) as conn:
            conn.execute("UPDATE cards SET created_at='2026-10-24T00:00:00Z'")
            conn.execute("UPDATE cards SET created_at='2026-10-23T00:00:00Z' WHERE id=?", (chosen[1],))
            conn.commit()
        packet = recall_memory(self.root, query="poolquartz", created_before="2026-10-24T00:00:00Z")
        self.assertEqual(self.keys(packet), {chosen})
        self.assertFalse(packet["retrieval"]["lexical_truncated"])
        self.assertEqual(packet["retrieval"]["channels"]["lexical"], 1)

    def test_missing_roots_are_untouched_and_default_environment_is_ignored(self) -> None:
        unrelated = self.directory / "not-the-requested-root"
        with patch.dict("os.environ", {"CONTINUUM_ROOT": str(unrelated)}):
            for scope in ({}, {"session_id": "session-a", "project_id": "project-a"}):
                packet = recall_memory(self.root, query="anything", token_budget=512, **scope)
                self.assertFalse(packet["initialized"])
                self.assert_packet_budget(packet, 512)
                self.assertFalse(self.read(("card", "missing"), **scope)["found"])
        self.assertFalse(self.root.exists())
        self.assertFalse(unrelated.exists())

    def test_read_paths_leave_durable_catalog_files_counters_and_live_wal_unchanged(self) -> None:
        keys = self.sources("readonlyquartz evidence")
        with closing(connect(self.root)) as writer:
            writer.execute("UPDATE cards SET recall_count=7 WHERE id=?", (keys[0][1],))
            writer.commit()
            before_dump = "\n".join(writer.iterdump())
            before_files = {str(path.relative_to(self.root)): digest_bytes(path.read_bytes())
                            for path in self.root.rglob("*") if path.is_file()
                            and "catalog" not in path.relative_to(self.root).parts}
            with patch("continuum.core.store.init_db", side_effect=AssertionError("no initialization")), patch(
                "continuum.core.store.connect", side_effect=AssertionError("no write connection")
            ):
                packet = recall_memory(self.root, query="readonlyquartz", semantic=self.semantic("readonlyquartz", keys))
                self.assertTrue(set(keys).issubset(self.keys(packet)))
                for key in keys:
                    self.assertTrue(self.read(key, limit=10)["found"])
            self.assertEqual("\n".join(writer.iterdump()), before_dump)
            after_files = {str(path.relative_to(self.root)): digest_bytes(path.read_bytes())
                           for path in self.root.rglob("*") if path.is_file()
                           and "catalog" not in path.relative_to(self.root).parts}
            self.assertEqual(after_files, before_files)

    def test_credentials_still_blocked_before_memory_admission(self) -> None:
        self.prepare()
        secret = "api_" + "key=" + "synthetic-secret-value-123456789"
        with self.assertRaisesRegex(ValueError, "secret scan blocked"):
            self.event("blockedquartz " + secret)
        with self.assertRaisesRegex(ValueError, "secret scan blocked"):
            self.card("blockedquartz " + secret)
        with self.assertRaisesRegex(ValueError, "secret scan blocked"):
            self.chunks("blockedquartz " + secret)
        source = self.directory / "blocked-source.txt"
        source.write_text("blockedquartz " + secret, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "secret scan blocked"):
            ingest_file(self.root, path=source)
        packet = recall_memory(self.root, query="blockedquartz")
        self.assertEqual(packet["result_count"], 0)
        self.assertNotIn(secret, json.dumps(packet))
        with closing(connect_existing(self.root)) as conn:
            for table in ("cards", "scroll_events", "chunks", "books"):
                self.assertEqual(conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)

    def test_invalid_recall_inputs_raise_without_initialization(self) -> None:
        invalid = [{"query": value} for value in (None, 1, True, "", " \t\n", "x" * 8193)]
        invalid += [{"limit": value} for value in (0, 51, True, 1.5, "8")]
        invalid += [{"token_budget": value} for value in (511, 32769, False, 512.0, "512")]
        invalid += [{"created_after": value} for value in ("", "not-a-date", "2026-10-23", "2026-10-23T00:00:00", 1)]
        invalid += [{"created_before": "2026-10-23T00:00:00"},
                    {"created_after": "2026-10-23T00:00:00Z", "created_before": "2026-10-23T00:00:00Z"},
                    {"created_after": "2026-10-24T00:00:00Z", "created_before": "2026-10-23T00:00:00Z"},
                    {"session_id": "bad\nselector"}, {"project_id": "bad[selector]"}]
        for kwargs in invalid:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                recall_memory(self.root, **{"query": "valid", **kwargs})
        self.assertFalse(self.root.exists())

    def test_invalid_source_inputs_raise_without_initialization(self) -> None:
        invalid = [{"kind": value} for value in ("library", "", None, 3)]
        invalid += [{"source_id": value} for value in ("", "../escape", "x" * 129, "bad\nid", None, True)]
        invalid += [{"offset": value} for value in (-1, 2 ** 63, True, 0.5)]
        invalid += [{"limit": value} for value in (0, 8001, False, 1.5)]
        invalid += [{"content_hash": value} for value in ("", "a" * 63, "A" * 64, "g" * 64, 7)]
        for kwargs in invalid:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                read_memory_source(self.root, **{"kind": "card", "source_id": "unknown", **kwargs})
        self.assertFalse(self.root.exists())

    def test_semantic_query_model_shape_and_dimensions_are_validated_before_reads(self) -> None:
        valid = {"model": "fixture-embedding-v1", "query_hash": digest("query"), "query_vector": [1.0, 0.0],
                 "items": [{"kind": "card", "id": "unknown", "content_hash": "0" * 64, "vector": [1.0, 0.0]}]}
        mutations = [lambda value: value.update(query_hash=digest("different")),
                     lambda value: value.update(model=""),
                     lambda value: value.update(query_vector=[0.0, 0.0]),
                     lambda value: value.update(query_vector=[float("nan"), 0.0]),
                     lambda value: value["items"][0].update(vector=[1.0]),
                     lambda value: value["items"][0].update(id="../untrusted"),
                     lambda value: value["items"][0].update(content_hash="not-a-hash"),
                     lambda value: value["items"].append(copy.deepcopy(value["items"][0])),
                     lambda value: value.update(extra="unrecognized")]
        for mutate in mutations:
            semantic = copy.deepcopy(valid)
            mutate(semantic)
            with self.subTest(semantic=semantic), self.assertRaises(ValueError):
                recall_memory(self.root, query="query", semantic=semantic)
        self.assertFalse(self.root.exists())


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


if __name__ == "__main__":
    unittest.main()
