from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from benchmarks.runners import recall_quality as quality


FROZEN_FIXTURE = Path(__file__).resolve().parents[1] / "benchmarks/fixtures/recall_quality_cases.json"
FROZEN_SHA256 = "bc6c11e149285ab16ecfbf9d04eaca5d131e9b1af15b70f1eccc0fe1ec2074dd"


def fixture_value() -> dict:
    return {
        "schema_version": 1, "name": "Safe unit corpus", "split": "synthetic_regression",
        "description": "Synthetic unit data, not held-out evidence.",
        "documents": [
            {"id": "alpha", "kind": "file", "title": "Cedarwalrus calibration",
             "text": "The cedarwalrus calibration is amber. EVID:CALIBRATION."},
            {"id": "beta", "kind": "file", "title": "Silveribis correction",
             "text": "The silveribis correction is violet. EVID:CORRECTION."},
        ],
        "cases": [
            {"id": "single", "category": "lexical", "query": "cedarwalrus calibration",
             "relevant_source_ids": ["alpha"], "expected_answers": ["amber"],
             "required_evidence": ["EVID:CALIBRATION"]},
            {"id": "multiple", "category": "evidence", "query": "cedarwalrus silveribis",
             "relevant_source_ids": ["alpha", "beta"], "expected_answers": ["amber"]},
            {"id": "absent", "category": "unanswerable", "query": "unknownquartzzeppelin",
             "relevant_source_ids": [], "expected_answers": []},
        ],
    }


class RecallQualityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="recall-quality-tests-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.fixture = self.directory / "fixture.json"
        self.write_json(self.fixture, fixture_value())

    def write_json(self, path: Path, value: object) -> None:
        path.write_text(json.dumps(value, ensure_ascii=True), encoding="utf-8")

    def answer_value(self) -> dict:
        return {
            "schema_version": 1, "fixture_sha256": hashlib.sha256(self.fixture.read_bytes()).hexdigest(),
            "records": [
                {"case_id": "single", "answer": "amber", "abstained": False, "cited_source_ids": ["alpha"]},
                {"case_id": "multiple", "answer": "amber", "abstained": False, "cited_source_ids": ["alpha", "beta"]},
                {"case_id": "absent", "answer": "", "abstained": True, "cited_source_ids": []},
            ],
        }

    def test_frozen_development_fixture_and_real_api_results(self) -> None:
        self.assertEqual(hashlib.sha256(FROZEN_FIXTURE.read_bytes()).hexdigest(), FROZEN_SHA256)
        report = quality.evaluate(FROZEN_FIXTURE)
        self.assertEqual(report["fixture"]["sha256"], FROZEN_SHA256)
        self.assertEqual(report["fixture"]["split"], "synthetic_regression")
        self.assertFalse(report["fixture"]["held_out_independence_verified"])
        self.assertEqual(report["summary"]["case_count"], 10)
        self.assertEqual(report["summary"]["answerable_count"], 8)
        self.assertEqual(report["summary"]["no_answer_count"], 2)
        self.assertIsNone(report["summary"]["offline_combined_accuracy"])
        cases = {row["case_id"]: row for row in report["cases"]}
        for case_id in ("exact-identifier", "short-identifier", "unicode-query", "buried-output"):
            self.assertTrue(cases[case_id]["source_top1_correct"], case_id)
        self.assertIn("EVID:OPALHARBOR", cases["buried-output"]["selected_context"])
        self.assertTrue(cases["no-answer-unique"]["no_answer_abstention_correct"])
        for row in report["cases"]:
            self.assertEqual(row["selected_context_chars"], len(row["selected_context"]))
            self.assertLessEqual(row["selected_context_chars"], 4000)
            self.assertEqual(row["selected_context_rough_tokens"], (len(row["selected_context"]) + 3) // 4)
            self.assertGreaterEqual(row["retrieval_latency_ms"], 0)
            self.assertGreaterEqual(row["selection_latency_ms"], 0)

    def test_measurements_use_denominators_and_bounded_chunk_cutoff(self) -> None:
        report = quality.evaluate(self.fixture, top_k=1, context_chars=80)
        rows = {row["case_id"]: row for row in report["cases"]}
        self.assertEqual(rows["single"]["source_recall_at_k"], 1)
        self.assertEqual(rows["multiple"]["source_recall_at_k"], 0.5)
        self.assertEqual(report["summary"]["mean_source_recall_at_k"], 0.75)
        self.assertIsNone(rows["absent"]["source_recall_at_k"])
        self.assertIsNone(rows["single"]["no_answer_abstention_correct"])
        self.assertEqual(report["summary"]["no_answer_retrieval_abstention_accuracy"], 1)
        self.assertTrue(all(row["returned_chunks"] <= 1 for row in rows.values()))
        self.assertTrue(all(row["selected_context_chars"] <= 80 for row in rows.values()))

    def test_real_source_rank_and_missing_source_score_are_not_silent_success(self) -> None:
        value = fixture_value()
        value["cases"] = [{**value["cases"][0], "query": "unseenparaphrasetoken"}]
        self.write_json(self.fixture, value)
        report = quality.evaluate(self.fixture)
        row = report["cases"][0]
        self.assertEqual(row["source_recall_at_k"], 0)
        self.assertEqual(row["reciprocal_rank_at_k"], 0)
        self.assertIsNone(row["first_relevant_chunk_rank"])
        self.assertEqual(report["summary"]["answerable_false_abstention_rate"], 1)
        self.assertIsNone(report["summary"]["no_answer_retrieval_abstention_accuracy"])
        self.assertEqual(report["status"], "measured")
        self.assertNotIn("passed", report)

    def test_tiny_context_does_not_change_retrieval_rank(self) -> None:
        report = quality.evaluate(self.fixture, context_chars=1)
        self.assertEqual(report["cases"][0]["first_relevant_chunk_rank"], 1)
        self.assertEqual(report["cases"][0]["selected_context_chars"], 0)
        self.assertEqual(report["cases"][0]["required_evidence_rate"], 0)

    def test_generated_source_label_is_not_counted_as_source_evidence(self) -> None:
        value = fixture_value()
        value["documents"] = [{**value["documents"][0], "id": "amber",
                               "text": "cedarwalrus evidence start. " + "ordinary padding. " * 200 + " amber"}]
        value["cases"] = [{**value["cases"][0], "query": "cedarwalrus", "relevant_source_ids": ["amber"],
                           "required_evidence": ["amber"]}]
        self.write_json(self.fixture, value)
        row = quality.evaluate(self.fixture, top_k=1, context_chars=100)["cases"][0]
        self.assertIn("[source:amber]", row["selected_context"])
        self.assertEqual(row["required_evidence_found"], [])
        self.assertEqual(row["required_evidence_rate"], 0)

    def test_expanded_prefix_secret_is_rejected_before_root_creation(self) -> None:
        value = fixture_value()
        value["documents"][0].update(prefix_text="api_" + "key", prefix_repeat=1,
                                      text="=" + "x" * 20 + "\n" + value["documents"][0]["text"])
        self.write_json(self.fixture, value)
        with patch.object(quality.tempfile, "TemporaryDirectory", side_effect=AssertionError("must validate first")):
            with self.assertRaisesRegex(ValueError, "secret scan blocked"):
                quality.evaluate(self.fixture)

    def test_root_is_temporary_cleaned_and_default_environment_ignored(self) -> None:
        live = self.directory / "not-a-runtime"
        live.mkdir()
        sentinel = live / "sentinel.txt"
        sentinel.write_text("preserve", encoding="utf-8")
        roots = []
        write_config = quality.write_config

        def tracked_config(root: Path, config: dict) -> Path:
            roots.append(root)
            self.assertFalse(config["local_inference"]["enabled"])
            self.assertEqual(config["capture"]["mode"], "manual")
            self.assertNotEqual(root, live)
            return write_config(root, config)

        with patch.dict(os.environ, {"CONTINUUM_ROOT": str(live)}), patch.object(
            quality, "write_config", side_effect=tracked_config
        ), patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden")), patch(
            "urllib.request.urlopen", side_effect=AssertionError("network forbidden")
        ):
            report = quality.evaluate(self.fixture)
        self.assertEqual(len(roots), 1)
        self.assertFalse(roots[0].exists())
        self.assertEqual(list(live.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")
        self.assertNotIn(str(self.directory), json.dumps(report))

    def test_offline_exact_supported_answers_and_abstention(self) -> None:
        answers = self.directory / "answers.json"
        self.write_json(answers, self.answer_value())
        report = quality.evaluate(self.fixture, answers_path=answers)
        self.assertEqual(report["answers_sha256"], hashlib.sha256(answers.read_bytes()).hexdigest())
        self.assertEqual(report["summary"]["offline_answer_record_count"], 3)
        self.assertEqual(report["summary"]["offline_exact_answer_accuracy"], 1)
        self.assertEqual(report["summary"]["offline_supported_exact_answer_accuracy"], 1)
        self.assertEqual(report["summary"]["offline_no_answer_abstention_accuracy"], 1)
        self.assertEqual(report["summary"]["offline_combined_accuracy"], 1)

    def test_offline_wrong_missing_support_and_literal_whitespace_are_scored(self) -> None:
        answers = self.directory / "answers.json"
        value = self.answer_value()
        value["records"][0]["cited_source_ids"] = ["beta"]
        value["records"][1]["answer"] = "amber "
        value["records"][2].update(answer="unsupported guess", abstained=False)
        self.write_json(answers, value)
        report = quality.evaluate(self.fixture, answers_path=answers)
        self.assertEqual(report["summary"]["offline_exact_answer_accuracy"], 0.5)
        self.assertEqual(report["summary"]["offline_supported_exact_answer_accuracy"], 0)
        self.assertEqual(report["summary"]["offline_no_answer_abstention_accuracy"], 0)
        self.assertEqual(report["summary"]["offline_combined_accuracy"], 0)

    def test_external_held_out_is_explicit_but_not_verified(self) -> None:
        value = fixture_value()
        value["split"] = "external_held_out"
        self.write_json(self.fixture, value)
        report = quality.evaluate(self.fixture)
        self.assertEqual(report["fixture"]["split"], "external_held_out")
        self.assertFalse(report["fixture"]["held_out_independence_verified"])

    def test_malformed_fixture_preflight_rejects_before_memory_creation(self) -> None:
        mutations = [
            lambda v: v.update(schema_version=True),
            lambda v: v.update(unexpected=True),
            lambda v: v.update(split="held_out"),
            lambda v: v.update(documents=[]),
            lambda v: v.update(cases=[]),
            lambda v: v["documents"].append(copy.deepcopy(v["documents"][0])),
            lambda v: v["documents"][1].update(text=v["documents"][0]["text"]),
            lambda v: v["documents"][0].update(id="../escape"),
            lambda v: v["documents"][0].update(kind="network"),
            lambda v: v["documents"][0].update(kind="tool_result"),
            lambda v: v["documents"][0].update(prefix_text="x"),
            lambda v: v["documents"][0].update(prefix_text="x", prefix_repeat=True),
            lambda v: v["documents"][0].update(prefix_text="x" * 4000, prefix_repeat=5000),
            lambda v: v["documents"][0].update(text="bad\ud800unicode"),
            lambda v: v["cases"].append(copy.deepcopy(v["cases"][0])),
            lambda v: v["cases"][0].update(query=""),
            lambda v: v["cases"][0].update(query="x" * 513),
            lambda v: v["cases"][0].update(relevant_source_ids=["missing"]),
            lambda v: v["cases"][0].update(relevant_source_ids=["alpha", "alpha"]),
            lambda v: v["cases"][0].update(expected_answers=[]),
            lambda v: v["cases"][0].update(expected_answers=["invented"]),
            lambda v: v["cases"][0].update(required_evidence=["invented"]),
            lambda v: v["cases"][0].update(forbidden_evidence=["invented"]),
            lambda v: v["cases"][0].update(forbidden_evidence=["EVID:CALIBRATION"]),
            lambda v: v["cases"][2].update(expected_answers=["amber"]),
            lambda v: v["documents"][0].update(text="api_" + "key=" + "x" * 20),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                value = fixture_value()
                mutate(value)
                self.write_json(self.fixture, value)
                with patch.object(quality.tempfile, "TemporaryDirectory", side_effect=AssertionError("must validate first")):
                    with self.assertRaises(ValueError):
                        quality.evaluate(self.fixture)

    def test_bad_json_duplicate_fields_and_size_limit(self) -> None:
        for content in ("{", '{"a":1,"a":2}', '{"a":NaN}', "[" * 2000, "\ufeff{}"):
            with self.subTest(content=content[:30]):
                self.fixture.write_text(content, encoding="utf-8")
                with self.assertRaises(ValueError):
                    quality.load_fixture(self.fixture)
        self.fixture.write_bytes(b"x" * (quality.MAX_JSON_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "exceeds"):
            quality.load_fixture(self.fixture)

    def test_invalid_offline_artifacts_are_not_missing_zero_scores(self) -> None:
        mutations = [
            lambda v: v.update(fixture_sha256="0" * 64),
            lambda v: v.update(records=v["records"][:-1]),
            lambda v: v["records"].append(copy.deepcopy(v["records"][0])),
            lambda v: v["records"][0].update(case_id="unknown"),
            lambda v: v["records"][0].update(abstained=1),
            lambda v: v["records"][0].update(cited_source_ids=["unknown"]),
            lambda v: v["records"][0].update(answer=""),
            lambda v: v["records"][2].update(answer="guess"),
            lambda v: v["records"][2].update(cited_source_ids=["alpha"]),
            lambda v: v["records"][0].update(answer="api_" + "key=" + "x" * 20),
        ]
        answers = self.directory / "answers.json"
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                value = self.answer_value()
                mutate(value)
                self.write_json(answers, value)
                with patch.object(quality.tempfile, "TemporaryDirectory", side_effect=AssertionError("must validate first")):
                    with self.assertRaises(ValueError):
                        quality.evaluate(self.fixture, answers_path=answers)

    def test_parameters_reject_booleans_and_out_of_range_values(self) -> None:
        for kwargs in ({"top_k": True}, {"top_k": 0}, {"top_k": 21}, {"context_chars": False},
                       {"context_chars": 0}, {"context_chars": 8001}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                quality.evaluate(self.fixture, **kwargs)

    def test_runtime_contract_failures_abort_instead_of_scoring_zero(self) -> None:
        with patch.object(quality, "search_memory", return_value={"initialized": False}):
            with self.assertRaisesRegex(RuntimeError, "uninitialized"):
                quality.evaluate(self.fixture)
        with patch.object(quality, "read_memory_chunk", return_value={"found": False}):
            with self.assertRaisesRegex(RuntimeError, "missing or mismatched"):
                quality.evaluate(self.fixture)

    def test_cli_writes_new_report_and_preserves_existing_outputs(self) -> None:
        output = self.directory / "report.json"
        self.assertEqual(quality.main(["--fixture", str(self.fixture), "--output", str(output)]), 0)
        before = output.read_bytes()
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            quality.main(["--fixture", str(self.fixture), "--output", str(output)])
        self.assertEqual(error.exception.code, 2)
        self.assertEqual(output.read_bytes(), before)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            quality.main(["--fixture", str(self.fixture), "--top-k", "0"])
        self.assertEqual(error.exception.code, 2)

    def test_cli_stdout_and_fresh_process_entrypoint(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            self.assertEqual(quality.main(["--fixture", str(self.fixture)]), 0)
        self.assertEqual(json.loads(stdout.getvalue())["summary"]["case_count"], 3)
        process = subprocess.run(
            [sys.executable, "-m", "benchmarks.runners.recall_quality", "--fixture", str(self.fixture)],
            cwd=quality.REPO_ROOT, capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(json.loads(process.stdout)["summary"]["case_count"], 3)


if __name__ == "__main__":
    unittest.main()
