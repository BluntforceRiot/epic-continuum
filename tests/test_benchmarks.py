from __future__ import annotations

import json
import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import benchmarks.runners.eric_memory_bench as eric_memory_bench
import benchmarks.runners.scale_bench as scale_bench
from benchmarks.runners.continuitybench import main as continuitybench_main
from benchmarks.runners.eric_memory_bench import main as eric_memory_bench_main
from benchmarks.runners.faultbench import main as faultbench_main
from benchmarks.runners.scale_bench import main as scalebench_main
from benchmarks.runners._common import prepare_output_dir


def write_continuity_fixture(path: Path) -> Path:
    payload = {
        "name": "ContinuityBench",
        "version": "smoke",
        "seed": 1337,
        "cases": [
            {
                "id": "cb-smoke",
                "interruption": "smoke",
                "query": "resume alpha release blocker",
                "events": [
                    "Decision EVID:SMOKE-CURRENT alpha blocker is patched.",
                    "Superseded EVID:SMOKE-OLD old blocker was replaced.",
                    "Next action EVID:SMOKE-NEXT rerun review.",
                ],
                "cards": ["Current smoke memory EVID:SMOKE-CURRENT EVID:SMOKE-NEXT"],
                "library": ["Smoke source mentions EVID:SMOKE-CURRENT and EVID:SMOKE-NEXT"],
                "required_evidence": ["EVID:SMOKE-CURRENT", "EVID:SMOKE-NEXT"],
                "forbidden_evidence": ["EVID:SMOKE-OLD"],
            }
        ],
    }
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return path


def write_eric_fixture(path: Path) -> Path:
    payload = {
        "name": "EricMemoryBench",
        "version": "smoke",
        "seed": 20260623,
        "default_live_model": "Qwen/Qwen2.5-7B-Instruct",
        "description": "Tiny local smoke fixture.",
        "cases": [
            {
                "id": "smoke_buried",
                "session_id": "smoke-buried",
                "project_id": "epic-continuum",
                "query": "what was the buried blocker",
                "events": [
                    "Decision: EVID:SMOKE-BLOCKER restore drill source links were blocked.",
                    "Noise: update icon spacing.",
                    "Noise: review old screenshots.",
                    "Noise: sort docs links.",
                    "Next action: rerun tests.",
                ],
                "cards": [
                    "Release memory: EVID:SMOKE-BLOCKER restore drill source links were blocked."
                ],
                "qmd_note": "## Current Notes\nThe README wording needs polish.",
                "required_evidence": ["EVID:SMOKE-BLOCKER"],
                "forbidden_evidence": [],
            }
        ],
    }
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    return path


class TestContinuityBenchSmoke(unittest.TestCase):
    def test_quick_runner_writes_expected_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = write_continuity_fixture(Path(tmp) / "continuity_fixture.json")
            out = Path(tmp) / "continuitybench"
            rc = continuitybench_main(["--quick", "--fixture", str(fixture), "--budgets", "1000", "--output-dir", str(out)])
            self.assertEqual(rc, 0)
            summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
            cases = (out / "cases.jsonl").read_text(encoding="utf-8").splitlines()
            env = json.loads((out / "environment.json").read_text(encoding="utf-8"))

            self.assertEqual(summary["benchmark"], "ContinuityBench")
            self.assertEqual(summary["case_count"], 1)
            self.assertGreater(len(cases), 0)
            self.assertEqual(env["dataset_name"], "ContinuityBench")
            self.assertEqual(env["api_cost_usd"], 0)
            self.assertEqual(env["model_provider"], None)
            self.assertIn("trial_count", env)
            self.assertIn("groups", summary)
            self.assertNotIn("worktree", env)
            self.assertNotIn("git_status_short", env)
            self.assertNotIn(str(out), env["command"])

            rows = [json.loads(line) for line in cases]
            looking_glass = [row for row in rows if row["mode"] == "looking_glass"]
            self.assertTrue(looking_glass)
            self.assertTrue(all(row["mrr"] is None for row in looking_glass))
            self.assertTrue(all(row["ndcg_at_10"] is None for row in looking_glass))
            planner_v2 = [row for row in rows if row["mode"] == "looking_glass_v2"]
            self.assertTrue(planner_v2)
            self.assertTrue(all(row["looking_glass_raw"].get("planner_profile") == "resume" for row in planner_v2))
            self.assertTrue(all(row["budget_respected"] for row in planner_v2))
            self.assertTrue(all(not row["current_candidate_superseded_error"] for row in planner_v2))

    def test_output_dir_refuses_unmarked_existing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "existing"
            out.mkdir()
            sentinel = out / "keep.txt"
            sentinel.write_text("keep\n", encoding="utf-8")

            with self.assertRaises(ValueError):
                continuitybench_main(["--quick", "--budgets", "128", "--output-dir", str(out)])

            self.assertTrue(sentinel.exists())

    def test_marked_output_dir_can_be_reused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = write_continuity_fixture(Path(tmp) / "continuity_fixture.json")
            out = Path(tmp) / "marked"
            prepare_output_dir(out, benchmark="ContinuityBench")
            (out / "stale.json").write_text("{}\n", encoding="utf-8")

            rc = continuitybench_main(["--quick", "--fixture", str(fixture), "--budgets", "128", "--output-dir", str(out)])

            self.assertEqual(rc, 0)
            self.assertFalse((out / "stale.json").exists())
            self.assertTrue((out / "summary.json").exists())


class TestEricMemoryBenchSmoke(unittest.TestCase):
    def test_quick_runner_writes_expected_artifacts_and_pressure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture = write_eric_fixture(Path(tmp) / "eric_fixture.json")
            out = Path(tmp) / "eric-memory"
            rc = eric_memory_bench_main(["--quick", "--fixture", str(fixture), "--budgets", "512", "--output-dir", str(out)])
            self.assertEqual(rc, 0)
            summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
            rows = [json.loads(line) for line in (out / "cases.jsonl").read_text(encoding="utf-8").splitlines()]
            env = json.loads((out / "environment.json").read_text(encoding="utf-8"))

            self.assertEqual(summary["benchmark"], "EricMemoryBench")
            self.assertEqual(summary["case_count"], 1)
            self.assertEqual(env["api_cost_usd"], 0)
            self.assertEqual(env["model_name"], "Qwen/Qwen2.5-7B-Instruct")
            self.assertTrue(summary["live_runs_are_optional"])
            self.assertIn("hermes_recent_context", summary["modes"])
            self.assertIn("openclaw_qmd_notes", summary["modes"])
            self.assertIn("epic_continuum_auto_capture", summary["modes"])
            self.assertIn("epic_continuum_card_assisted", summary["modes"])
            self.assertFalse(any(row["live_answer_attempted"] for row in rows))
            self.assertTrue(all(row["budget_respected"] for row in rows))

            groups = {(item["mode"], item["budget"]): item for item in summary["groups"]}
            self.assertIn(("hermes_recent_context", 512), groups)
            self.assertIn(("openclaw_qmd_notes", 512), groups)
            self.assertLessEqual(
                groups[("epic_continuum_auto_capture", 512)]["required_evidence_rate"],
                groups[("epic_continuum_card_assisted", 512)]["required_evidence_rate"],
            )
            self.assertGreater(groups[("epic_continuum_card_assisted", 512)]["required_evidence_rate"], 0.0)
            self.assertEqual(groups[("epic_continuum_card_assisted", 512)]["forbidden_evidence_rate"], 0.0)
            self.assertIn("superseded_error_rate", groups[("openclaw_qmd_notes", 512)])
            self.assertEqual(groups[("openclaw_qmd_notes", 512)]["superseded_error_rate"], 0.0)

    def test_superseded_scoring_requires_explicit_supersession_and_does_not_double_count(self) -> None:
        base_case = {
            "id": "historical",
            "query": "which policy",
            "required_evidence": ["EVID:CURRENT"],
            "forbidden_evidence": ["EVID:OLD"],
            "superseded_evidence": ["EVID:OLD"],
        }
        args = SimpleNamespace()
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            eric_memory_bench, "context_for_mode", return_value=("EVID:OLD preserved history", 0.0)
        ), patch.object(
            eric_memory_bench,
            "live_answer",
            return_value={
                "attempted": True,
                "ok": True,
                "backend": "fake",
                "agent_surface": "fake",
                "answer": "EVID:OLD",
                "latency_seconds": 0.0,
            },
        ):
            historical = eric_memory_bench.evaluate_case(Path(tmp), base_case, "mode", 128, args, Path(tmp))
            explicit = eric_memory_bench.evaluate_case(
                Path(tmp),
                {**base_case, "superseded_by_evidence": {"EVID:OLD": "EVID:CURRENT"}},
                "mode",
                128,
                args,
                Path(tmp),
            )

        self.assertEqual(historical["superseded_error_rate"], 0.0)
        self.assertEqual(historical["forbidden_evidence_rate"], 0.0)
        self.assertEqual(historical["live_answer_superseded_error_rate"], 0.0)
        self.assertEqual(historical["live_answer_forbidden_evidence_rate"], 0.0)
        self.assertEqual(explicit["superseded_error_rate"], 0.0)
        self.assertEqual(explicit["forbidden_evidence_rate"], 0.0)
        self.assertEqual(explicit["live_answer_superseded_error_rate"], 1.0)
        self.assertEqual(explicit["live_answer_forbidden_evidence_rate"], 0.0)

    def test_command_template_live_smoke_is_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fixture = write_eric_fixture(tmp_path / "eric_fixture.json")
            script = tmp_path / "fake_agent.py"
            script.write_text(
                "from pathlib import Path\n"
                "import re\n"
                "import sys\n"
                "prompt = Path(sys.argv[1]).read_text(encoding='utf-8')\n"
                "match = re.search(r'EVID:[A-Z0-9-]+', prompt)\n"
                "Path(sys.argv[2]).write_text(match.group(0) if match else 'MISSING', encoding='utf-8')\n",
                encoding="utf-8",
            )
            out = tmp_path / "eric-memory-live"
            command = f"{shlex.quote(sys.executable)} {shlex.quote(str(script))} {{prompt_file}} {{output_file}}"

            rc = eric_memory_bench_main(
                [
                    "--quick",
                    "--fixture",
                    str(fixture),
                    "--budgets",
                    "128",
                    "--output-dir",
                    str(out),
                    "--hermes-command",
                    command,
                ]
            )

            self.assertEqual(rc, 0)
            rows = [json.loads(line) for line in (out / "cases.jsonl").read_text(encoding="utf-8").splitlines()]
            hermes_rows = [row for row in rows if row["mode"] == "hermes_recent_context"]
            non_hermes_rows = [row for row in rows if row["mode"] != "hermes_recent_context"]
            command_text = (out / "commands.txt").read_text(encoding="utf-8")
            self.assertTrue(all(row["live_answer_attempted"] for row in hermes_rows))
            self.assertTrue(all(row["live_answer_backend"] == "command" for row in hermes_rows))
            self.assertFalse(any(row["live_answer_attempted"] for row in non_hermes_rows))
            self.assertNotIn(str(script), command_text)
            self.assertIn("--hermes-command <path>", command_text)

    def test_runner_isolates_roots_by_case_mode_and_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "eric-memory-isolation"
            evaluated: list[tuple[str, str, str, int]] = []
            built: list[tuple[str, str, bool]] = []

            def fake_build(root: Path, cases: list[dict[str, object]], include_fixture_cards: bool) -> None:
                built.append((str(root), str(cases[0]["id"]), include_fixture_cards))

            def fake_evaluate(
                root: Path,
                case: dict[str, object],
                mode: str,
                budget: int,
                args: object,
                output_dir: Path,
            ) -> dict[str, object]:
                evaluated.append((str(root), str(case["id"]), mode, int(budget)))
                return {
                    "answer_contains_forbidden_evidence": [],
                    "answer_contains_required_evidence": [],
                    "budget": int(budget),
                    "budget_respected": True,
                    "case_id": str(case["id"]),
                    "context_contains_forbidden_evidence": [],
                    "context_contains_required_evidence": [],
                    "context_contains_superseded_evidence": [],
                    "context_latency_seconds": 0.0,
                    "context_tokens_used": 1,
                    "evidence_density": 0.0,
                    "forbidden_evidence": [],
                    "superseded_evidence": [],
                    "live_answer_attempted": False,
                    "live_answer_backend": None,
                    "live_answer_ok": None,
                    "live_answer_latency_seconds": None,
                    "live_agent_surface": None,
                    "live_error_type": None,
                    "live_answer_required_evidence_rate": None,
                    "live_answer_forbidden_evidence_rate": None,
                    "live_answer_superseded_error_rate": None,
                    "mode": mode,
                    "query": str(case["query"]),
                    "required_evidence": [],
                    "required_evidence_rate": 0.0,
                    "forbidden_evidence_rate": 0.0,
                    "superseded_error_rate": 0.0,
                }

            with patch.object(eric_memory_bench, "build_corpus", side_effect=fake_build), patch.object(
                eric_memory_bench, "evaluate_case", side_effect=fake_evaluate
            ):
                rc = eric_memory_bench.main(["--quick", "--budgets", "128,256", "--output-dir", str(out)])

            self.assertEqual(rc, 0)
            self.assertEqual(len(evaluated), 5 * 2 * len(eric_memory_bench.MODES))
            self.assertEqual(len({root for root, _case_id, _mode, _budget in evaluated}), len(evaluated))
            for root, case_id, mode, budget in evaluated:
                self.assertIn(case_id, root)
                self.assertIn(mode, root)
                self.assertIn(str(budget), root)
            self.assertEqual(len(built), 5 * 2 * 2)
            self.assertTrue(all("epic_continuum_" in root for root, _case_id, _card_assisted in built))


class TestFaultBenchSmoke(unittest.TestCase):
    def test_quick_runner_writes_expected_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "faultbench"
            rc = faultbench_main(["--quick", "--output-dir", str(out)])
            self.assertEqual(rc, 0)
            summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
            cases = (out / "cases.jsonl").read_text(encoding="utf-8").splitlines()
            env = json.loads((out / "environment.json").read_text(encoding="utf-8"))

            self.assertEqual(summary["benchmark"], "FaultBench")
            self.assertTrue(summary["ok"])
            self.assertGreaterEqual(len(cases), 5)
            self.assertEqual(env["api_cost_usd"], 0)
            self.assertNotIn("worktree", env)
            self.assertNotIn("git_status_short", env)


class TestScaleBenchSmoke(unittest.TestCase):
    def test_tiny_runner_writes_expected_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scalebench"
            rc = scalebench_main(["--event-counts", "3", "--skip-bundle", "--output-dir", str(out)])
            self.assertEqual(rc, 0)
            summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
            rows = (out / "cases.jsonl").read_text(encoding="utf-8").splitlines()
            env = json.loads((out / "environment.json").read_text(encoding="utf-8"))

            self.assertEqual(summary["benchmark"], "ScaleBench")
            self.assertTrue(summary["ok"])
            self.assertEqual(len(rows), 1)
            self.assertEqual(env["api_cost_usd"], 0)
            self.assertNotIn("worktree", env)
            self.assertNotIn("git_status_short", env)

    def test_high_entropy_runner_reports_graph_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "scalebench-high"
            rc = scalebench_main(["--event-counts", "3", "--skip-bundle", "--high-entropy", "--output-dir", str(out)])
            self.assertEqual(rc, 0)
            summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
            row = json.loads((out / "cases.jsonl").read_text(encoding="utf-8").splitlines()[0])

            self.assertTrue(summary["high_entropy"])
            self.assertTrue(row["high_entropy"])
            self.assertLessEqual(row["graph_edges_per_event"], 90.0)
            self.assertLess(row["database_growth_bytes"], 5_000_000)

    def test_quick_runner_skips_bundle_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(scale_bench, "QUICK_EVENT_COUNTS", [3]):
            out = Path(tmp) / "scalebench-quick"
            rc = scalebench_main(["--quick", "--output-dir", str(out)])
            self.assertEqual(rc, 0)
            summary = json.loads((out / "summary.json").read_text(encoding="utf-8"))
            row = json.loads((out / "cases.jsonl").read_text(encoding="utf-8").splitlines()[0])

            self.assertEqual(summary["event_counts"], [3])
            self.assertTrue(summary["bundle_skipped"])
            self.assertIsNone(row["bundle_ok"])


if __name__ == "__main__":
    unittest.main()
