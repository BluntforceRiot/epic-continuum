from __future__ import annotations

import copy
import hashlib
import json
import socket
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from threading import Barrier
from unittest.mock import patch

from continuum.core.config import default_config, write_config
from continuum.core.knowledge_records import append_record, read_records
from continuum.core.store import append_scroll_event, connect_existing, init_db
from continuum.core.temporal_facts import (
    FACT_KIND,
    query_temporal_facts,
    record_temporal_fact,
)


class TemporalFactsTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="continuum-temporal-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / "memory"
        config = default_config()
        config["capture"]["mode"] = "manual"
        config["capture"]["dedup_window_seconds"] = 0
        config["local_inference"]["enabled"] = False
        write_config(self.root, config)
        init_db(self.root)
        blocker = patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden"))
        blocker.start()
        self.addCleanup(blocker.stop)

    def record(self, **changes) -> dict:
        args = {
            "project_id": "project-a", "session_id": "session-a",
            "subject": "Continuum", "predicate": "release", "value": "candidate amber",
            "valid_from": "2025-01-01T00:00:00Z",
        }
        args.update(changes)
        return record_temporal_fact(self.root, **args)

    def query(self, **changes) -> dict:
        args = {"project_id": "project-a", "valid_at": "2025-06-01T00:00:00Z"}
        args.update(changes)
        return query_temporal_facts(self.root, **args)

    def records(self) -> list[dict]:
        return read_records(self.root, project_id="project-a", kinds=[FACT_KIND])

    def snapshot(self) -> dict[str, list[tuple]]:
        with closing(connect_existing(self.root)) as conn:
            tables = [row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )]
            return {name: sorted((tuple(row) for row in conn.execute(f'SELECT * FROM "{name}"')), key=repr)
                    for name in tables}

    def test_explicit_assertion_preserves_values_and_exact_citation(self) -> None:
        fact = self.record()
        packet = self.query()
        self.assertEqual(packet["result_count"], 1)
        self.assertEqual(packet["instruction_authority"], "none")
        item = packet["results"][0]
        self.assertEqual(item["id"], fact["id"])
        self.assertEqual(item["value"], "candidate amber")
        self.assertEqual(item["correction_state"], "current")
        self.assertIsNone(item["corrected_by"])
        self.assertFalse(item["disagreement"])
        self.assertEqual(item["citation"], {
            "kind": "scroll_event", "id": fact["id"], "content_hash": fact["content_hash"],
        })
        with closing(connect_existing(self.root)) as conn:
            row = conn.execute("SELECT content FROM scroll_events WHERE id=?", (fact["id"],)).fetchone()
        self.assertEqual(hashlib.sha256(row["content"].encode()).hexdigest(), fact["content_hash"])

    def test_half_open_validity_and_timezone_normalization(self) -> None:
        fact = self.record(valid_from="2025-01-01T05:00:00+05:00", valid_to="2025-02-01T01:00:00+01:00")
        self.assertEqual(fact["payload"]["valid_from"], "2025-01-01T00:00:00+00:00")
        self.assertEqual(fact["payload"]["valid_to"], "2025-02-01T00:00:00+00:00")
        for moment, expected in (("2024-12-31T23:59:59Z", 0), ("2025-01-01T00:00:00Z", 1),
                                 ("2025-01-31T23:59:59.999999Z", 1), ("2025-02-01T00:00:00Z", 0)):
            with self.subTest(moment=moment):
                self.assertEqual(self.query(valid_at=moment)["result_count"], expected)
        history = self.query(include_history=True)
        self.assertEqual(history["result_count"], 1)
        self.assertFalse(history["results"][0]["valid_at_matches"])

    def test_as_known_restores_old_belief_and_retains_correction_history(self) -> None:
        with patch("continuum.core.store.utc_now", return_value="2025-03-01T00:00:00+00:00"):
            first = self.record()
        with patch("continuum.core.store.utc_now", return_value="2025-04-01T00:00:00+00:00"):
            second = self.record(value="candidate blue", corrects=first["id"])
        self.assertEqual(first["recorded_at"], "2025-03-01T00:00:00+00:00")
        self.assertEqual(self.query(known_at="2025-02-28T23:59:59Z")["result_count"], 0)
        old = self.query(known_at="2025-03-31T23:59:59Z")
        self.assertEqual([row["id"] for row in old["results"]], [first["id"]])
        current = self.query(known_at="2025-04-01T00:00:00Z")
        self.assertEqual([row["id"] for row in current["results"]], [second["id"]])
        history = self.query(known_at="2025-04-01T00:00:00Z", include_history=True)
        self.assertEqual([row["id"] for row in history["results"]], [second["id"], first["id"]])
        self.assertEqual(history["results"][1]["corrected_by"], second["id"])
        self.assertEqual(history["results"][1]["correction_state"], "corrected")
        self.assertEqual(len(self.records()), 2)

    def test_same_second_correction_uses_append_order(self) -> None:
        with patch("continuum.core.store.utc_now", return_value="2025-04-01T00:00:00+00:00"):
            first = self.record()
            second = self.record(value="blue", corrects=first["id"])
            third = self.record(value="green", corrects=second["id"])
        self.assertEqual([row["id"] for row in self.query(known_at="2025-04-01T00:00:00Z")["results"]],
                         [third["id"]])
        self.assertLess(first["order"], second["order"])
        self.assertLess(second["order"], third["order"])
        self.assertEqual(len(self.records()), 3)

    def test_correction_replaces_entire_assertion_without_interval_split(self) -> None:
        first = self.record(valid_from="2025-01-01T00:00:00Z", valid_to="2025-12-01T00:00:00Z")
        second = self.record(value="blue", corrects=first["id"], valid_from="2025-06-01T00:00:00Z")
        self.assertEqual(self.query(valid_at="2025-03-01T00:00:00Z")["result_count"], 0)
        self.assertEqual([row["id"] for row in self.query()["results"]], [second["id"]])
        self.assertEqual(self.query(include_history=True)["matched_count"], 2)

    def test_independent_differing_claims_remain_disagreements(self) -> None:
        first = self.record()
        second = self.record(value="candidate blue")
        self.record(value="candidate amber", predicate="color")
        packet = self.query(predicate="release")
        self.assertEqual({item["id"] for item in packet["results"]}, {first["id"], second["id"]})
        self.assertTrue(all(item["disagreement"] for item in packet["results"]))
        self.assertFalse(self.query(predicate="color")["results"][0]["disagreement"])
        replacement = self.record(value="candidate blue", corrects=first["id"])
        packet = self.query(predicate="release")
        self.assertEqual({item["id"] for item in packet["results"]}, {replacement["id"], second["id"]})
        self.assertTrue(all(not item["disagreement"] for item in packet["results"]))

    def test_corrections_require_current_leaf_and_matching_partition(self) -> None:
        first = self.record()
        before = len(self.records())
        for changes in (
            {"corrects": "not-found"}, {"corrects": first["id"], "subject": "Other"},
            {"corrects": first["id"], "predicate": "status"},
            {"corrects": first["id"], "project_id": "other-project"},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.record(**changes)
        self.assertEqual(len(self.records()), before)
        self.record(value="blue", corrects=first["id"])
        with self.assertRaises(ValueError):
            self.record(value="green", corrects=first["id"])
        self.assertEqual(len(self.records()), before + 1)

    def test_parallel_corrections_commit_one_leaf_only(self) -> None:
        first = self.record()
        barrier = Barrier(2)

        def attempt(color: str) -> tuple[str, str]:
            barrier.wait(timeout=10)
            try:
                return "accepted", self.record(value=color, corrects=first["id"])["id"]
            except ValueError:
                return "rejected", ""

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, ["blue", "green"]))
        self.assertEqual(sorted(item[0] for item in results), ["accepted", "rejected"])
        self.assertEqual(len(self.records()), 2)
        self.assertEqual(self.query()["result_count"], 1)

    def test_project_scope_and_exact_selectors(self) -> None:
        first = self.record()
        self.record(project_id="project-b", value="private other project")
        self.record(subject="Other")
        self.assertEqual([row["id"] for row in self.query(subject="Continuum")["results"]], [first["id"]])
        self.assertEqual(self.query(subject="continuum")["result_count"], 0)
        self.assertEqual(self.query(project_id="missing-project")["result_count"], 0)
        self.assertEqual(self.query(project_id="project-b")["result_count"], 1)

    def test_invalid_inputs_fail_before_append(self) -> None:
        self.record()
        before = len(self.records())
        invalid = [
            {"subject": ""}, {"subject": 3}, {"subject": "x" * 257},
            {"predicate": ""}, {"predicate": "x" * 129}, {"value": "x" * 2049},
            {"valid_from": "2025-01-01"}, {"valid_from": "2025-01-01T00:00:00"},
            {"valid_to": "2025-01-01T00:00:00Z"}, {"valid_to": "2024-01-01T00:00:00Z"},
            {"valid_to": "not-a-date"}, {"corrects": ""}, {"corrects": 3},
        ]
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.record(**changes)
        self.assertEqual(len(self.records()), before)
        for changes in ({"include_history": 1}, {"valid_at": ""}, {"known_at": "not-a-date"},
                        {"subject": ""}, {"predicate": []}, {"token_budget": True}, {"token_budget": 0}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.query(**changes)

    def test_credential_named_predicate_is_blocked_without_storing_value(self) -> None:
        self.record()
        before = self.snapshot()
        material = "example-only-" + "sensitive" + "-binding-12345678901234567890"
        for key in ("api_key", "password", "access_token"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.record(predicate=key, value=material)
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn(material, repr(self.snapshot()))

    def test_credential_text_and_invalid_unicode_are_rejected(self) -> None:
        before = self.snapshot()
        secret = "example-only-" + "binding-" + "123456789012345678901234567890"
        for changes in ({"subject": "api_key=" + secret}, {"value": "password=" + secret},
                        {"value": "bad\x00text"}, {"value": "bad\ud800text"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.record(**changes)
        self.assertEqual(self.snapshot(), before)

    def test_evidence_requires_exact_current_same_project_source(self) -> None:
        text = "Release was agreed in the local review."
        source = append_scroll_event(
            self.root, session_id="session-a", event_type="message", role="user", content=text,
            metadata={"visibility_scope": "project", "project_id": "project-a"},
        )
        citation = {"kind": "scroll_event", "id": source["event_id"],
                    "content_hash": hashlib.sha256(text.encode()).hexdigest()}
        fact = self.record(evidence=[citation])
        self.assertEqual(fact["payload"]["evidence"], [citation])
        for evidence in ([{**citation, "content_hash": "0" * 64}], [citation, citation],
                         [{**citation, "id": "not-found"}], [{**citation, "kind": "command"}]):
            with self.subTest(evidence=evidence), self.assertRaises(ValueError):
                self.record(evidence=evidence)
        with self.assertRaises(ValueError):
            self.record(project_id="project-b", evidence=[citation])
        private = append_scroll_event(
            self.root, session_id="session-a", event_type="message", role="user", content=text,
            metadata={"visibility_scope": "private", "project_id": "project-a"},
        )
        with self.assertRaises(ValueError):
            self.record(evidence=[{**citation, "id": private["event_id"]}])

    def test_query_validates_malformed_fact_even_when_selector_would_hide_it(self) -> None:
        first = self.record()
        payload = copy.deepcopy(first["payload"])
        payload["subject"] = "Other"
        payload["schema"] = True
        append_record(self.root, project_id="project-a", session_id="session-a", kind=FACT_KIND, payload=payload)
        with self.assertRaises(ValueError):
            self.query(subject="Continuum")

    def test_query_rejects_invalid_correction_topology(self) -> None:
        first = self.record()
        payload = copy.deepcopy(first["payload"])
        payload["corrects"] = "missing-fact"
        append_record(self.root, project_id="project-a", session_id="session-a", kind=FACT_KIND, payload=payload)
        with self.assertRaises(ValueError):
            self.query(include_history=True)

    def test_query_rejects_duplicate_corrections_and_invalid_stored_interval(self) -> None:
        first = self.record()
        self.record(value="blue", corrects=first["id"])
        payload = copy.deepcopy(first["payload"])
        payload.update(value="green", corrects=first["id"])
        append_record(self.root, project_id="project-a", session_id="session-a", kind=FACT_KIND, payload=payload)
        with self.assertRaises(ValueError):
            self.query(known_at="2020-01-01T00:00:00Z")
        payload["corrects"] = None
        payload["valid_to"] = payload["valid_from"]
        append_record(self.root, project_id="project-b", session_id="session-a", kind=FACT_KIND, payload=payload)
        with self.assertRaises(ValueError):
            self.query(project_id="project-b")

    def test_empty_missing_root_read_does_not_create_anything(self) -> None:
        absent = self.directory / "absent"
        packet = query_temporal_facts(absent, project_id="project-a")
        self.assertEqual(packet["result_count"], 0)
        self.assertFalse(absent.exists())

    def test_queries_preserve_all_durable_tables_and_config(self) -> None:
        first = self.record()
        self.record(value="blue", corrects=first["id"])
        before = self.snapshot()
        config_files = {path: path.read_bytes() for path in self.root.glob("*.toml")}
        self.query()
        self.query(include_history=True)
        self.query(known_at="2020-01-01T00:00:00Z")
        self.assertEqual(self.snapshot(), before)
        self.assertEqual({path: path.read_bytes() for path in config_files}, config_files)

    def test_whole_packet_budget_retains_complete_results_and_counts(self) -> None:
        for index in range(8):
            self.record(value=("fact " + str(index) + " ") * 40)
        for budget in (512, 800, 2400):
            with self.subTest(budget=budget):
                packet = self.query(token_budget=budget)
                encoded = json.dumps(packet, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
                self.assertLessEqual(len(encoded), budget * 4)
                self.assertEqual(json.loads(encoded), packet)
                self.assertEqual(packet["result_count"], len(packet["results"]))
                self.assertEqual(packet["matched_count"], 8)
                self.assertEqual(packet["excluded_by_budget"], 8 - packet["result_count"])
                for item in packet["results"]:
                    self.assertIn("citation", item)
                    self.assertEqual(item["correction_state"], "current")

    def test_unicode_fact_can_be_omitted_but_never_breaks_minimum_packet(self) -> None:
        self.record(subject="🧠" * 256, predicate="記" * 128, value="📚" * 2048)
        packet = self.query(token_budget=512)
        self.assertEqual(packet["matched_count"], 1)
        self.assertEqual(packet["result_count"], 0)
        self.assertEqual(packet["excluded_by_budget"], 1)
        encoded = json.dumps(packet, ensure_ascii=True, separators=(",", ":"))
        self.assertLessEqual(len(encoded), 2048)
        self.assertEqual(json.loads(encoded), packet)


if __name__ == "__main__":
    unittest.main()
