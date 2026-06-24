from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from continuum.core.review_bridge import create_review_job, ingest_review_result, review_job_status
from continuum.core import review_bridge as review_bridge_module
from continuum.mcp_server import TOOLS, dispatch


def valid_review_payload(request: dict) -> dict:
    return {
        "schema_version": "0.2",
        "job_id": request["job_id"],
        "review_id": request["job_id"],
        "packet_sha256": request["packet_sha256"],
        "review_capsule_sha256": request.get("review_capsule_sha256"),
        "subject_archive_sha256": request["subject_archive_sha256"],
        "package_sha256": request["package_sha256"],
        "review_complete": True,
        "sentinel": request["sentinel"],
        "summary": "Review complete.",
        "verdict": "hold",
        "confidence": "high",
        "findings": [
            {
                "severity": "high",
                "title": "Example finding",
                "file": "README.md",
                "line": 1,
                "detail": "Synthetic finding used to prove ingestion.",
                "recommendation": "Fix the example.",
            }
        ],
        "open_questions": [],
        "tests_suggested": ["Keep the bridge hash-binding tests."],
    }


def call_tool(name: str, arguments: dict) -> dict:
    response = dispatch(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert response is not None
    result = response["result"]
    assert result["isError"] is False, result
    return json.loads(result["content"][0]["text"])


class ReviewBridgeTest(unittest.TestCase):
    def test_create_and_ingest_hash_bound_review(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n\nUseful review target.\n", encoding="utf-8")

            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            status = review_job_status(root, job_id=job["job_id"])
            payload = valid_review_payload({**request, **status})

            receipt = ingest_review_result(root, job_id=job["job_id"], content=json.dumps(payload))

            self.assertTrue(receipt["ok"], receipt)
            self.assertEqual(receipt["finding_count"], 1)
            self.assertEqual(receipt["severity_counts"], {"high": 1})
            self.assertTrue(Path(receipt["ingest_receipt_uri"]).exists())
            status = review_job_status(root, job_id=job["job_id"])
            self.assertEqual(status["status"], "ingested")
            self.assertTrue(Path(status["ingest_receipt_uri"]).exists())
            self.assertTrue(Path(status["findings_markdown_uri"]).exists())
            self.assertTrue(Path(status["review_capsule_uri"]).exists())

    def test_prepare_excludes_continuum_root_inside_subject(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            subject = base / "repo"
            subject.mkdir()
            root = subject / ".continuum-demo"
            private_file = root / "config" / "continuum.config.json"
            private_file.parent.mkdir(parents=True)
            private_file.write_text('{"private": true}\n', encoding="utf-8")
            (subject / "app.py").write_text("print('ok')\n", encoding="utf-8")

            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            manifest = json.loads(Path(job["subject_manifest_uri"]).read_text(encoding="utf-8"))
            paths = {item["path"] for item in manifest["files"]}
            self.assertIn("app.py", paths)
            self.assertNotIn(".continuum-demo/config/continuum.config.json", paths)
            with zipfile.ZipFile(job["review_capsule_uri"]) as zf:
                names = set(zf.namelist())
            self.assertIn("subject/app.py", names)
            self.assertNotIn("subject/.continuum-demo/config/continuum.config.json", names)

    def test_single_zip_subject_is_bound_without_wrapper_zip(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            release_zip = base / "release.zip"
            with zipfile.ZipFile(release_zip, "w") as zf:
                zf.writestr("README.md", "# Release\n")
            original_hash = review_bridge_module.file_sha256(release_zip)

            job = create_review_job(root, subject_path=release_zip, prompt="Review hard.", transport="manual")

            self.assertEqual(job["subject_archive_sha256"], original_hash)
            self.assertEqual(Path(job["subject_archive_uri"]).name, "release.zip")
            with zipfile.ZipFile(job["review_capsule_uri"]) as zf:
                self.assertIn("subject/release.zip", set(zf.namelist()))

    def test_zip_subject_secret_scan_allows_nested_test_fixtures(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            release_zip = base / "release.zip"
            with zipfile.ZipFile(release_zip, "w") as zf:
                zf.writestr("pkg/tests/test_fixture.py", 'api_key="sk-" + "secretvalue12345678901234567890"\n')
                zf.writestr("pkg/README.md", "# Release\n")

            job = create_review_job(root, subject_path=release_zip, prompt="Review hard.", transport="manual")

            self.assertTrue(job["ok"])
            self.assertEqual(Path(job["subject_archive_uri"]).name, "release.zip")

    def test_archive_candidate_secret_scan_reads_non_text_extension(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "payload.dat").write_text("token = 'sk-" + ("A" * 32) + "'\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

    def test_limited_coverage_pass_is_downgraded(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "a.py").write_text("print('a')\n", encoding="utf-8")
            (subject / "b.py").write_text("print('b')\n", encoding="utf-8")

            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual", max_packet_bytes=220)
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            status = review_job_status(root, job_id=job["job_id"])
            payload = valid_review_payload({**request, **status})
            payload["verdict"] = "pass"
            payload["findings"] = []
            receipt = ingest_review_result(root, job_id=job["job_id"], content=json.dumps(payload))
            findings = json.loads(Path(receipt["findings_uri"]).read_text(encoding="utf-8"))

            self.assertEqual(receipt["verdict"], "coverage_limited")
            self.assertEqual(findings["findings"][0]["title"], "Automated packet review had limited coverage")

    def test_review_check_current_detects_subject_changes(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            target = subject / "app.py"
            target.write_text("print('old')\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

            self.assertTrue(review_bridge_module.review_check_current(root, job_id=job["job_id"])["current"])
            target.write_text("print('new')\n", encoding="utf-8")
            current = review_bridge_module.review_check_current(root, job_id=job["job_id"])
            self.assertFalse(current["current"])
            self.assertEqual(current["reason"], "source_changed_since_review_preparation")

    def test_ingest_rejects_stale_or_mismatched_review(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "app.py").write_text("print('hello')\n", encoding="utf-8")

            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            status = review_job_status(root, job_id=job["job_id"])
            payload = valid_review_payload({**request, **status})

            for key, value in (
                ("job_id", "review_other"),
                ("packet_sha256", "0" * 64),
                ("review_capsule_sha256", "2" * 64),
                ("subject_archive_sha256", "1" * 64),
                ("sentinel", "CONTINUUM_REVIEW_COMPLETE:wrong:hash"),
            ):
                with self.subTest(key=key), self.assertRaisesRegex(ValueError, "stale or malformed review result rejected"):
                    bad = dict(payload)
                    bad[key] = value
                    ingest_review_result(root, job_id=job["job_id"], content=json.dumps(bad))

            with self.assertRaisesRegex(ValueError, "review_complete must be true"):
                bad = dict(payload)
                bad["review_complete"] = False
                ingest_review_result(root, job_id=job["job_id"], content=json.dumps(bad))

            with self.assertRaisesRegex(ValueError, "review_capsule_sha256 mismatch"):
                bad = dict(payload)
                del bad["review_capsule_sha256"]
                ingest_review_result(root, job_id=job["job_id"], content=json.dumps(bad))

    def test_ingest_rehashes_actual_artifacts_before_accepting_review(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")

            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            status = review_job_status(root, job_id=job["job_id"])
            payload = valid_review_payload({**request, **status})
            Path(request["packet_uri"]).write_text("# Mutated packet\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "review-packet.md changed after job creation"):
                ingest_review_result(root, job_id=job["job_id"], content=json.dumps(payload))

    def test_ingest_requires_required_schema_fields(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")

            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            status = review_job_status(root, job_id=job["job_id"])
            payload = valid_review_payload({**request, **status})
            del payload["summary"]

            with self.assertRaisesRegex(ValueError, "review response schema validation failed"):
                ingest_review_result(root, job_id=job["job_id"], content=json.dumps(payload))

    def test_subject_packaging_skips_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            outside = base / "outside-secret.txt"
            outside.write_text("do not package this\n", encoding="utf-8")
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            try:
                os.symlink(outside, subject / "outside-secret.txt")
            except (OSError, NotImplementedError) as exc:
                self.skipTest(f"symlink creation unavailable: {exc}")

            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            manifest = json.loads(Path(job["subject_manifest_uri"]).read_text(encoding="utf-8"))
            manifest_paths = {item["path"] for item in manifest["files"]}
            self.assertNotIn("outside-secret.txt", manifest_paths)
            with zipfile.ZipFile(job["subject_archive_uri"]) as zf:
                self.assertNotIn("outside-secret.txt", zf.namelist())

    def test_mcp_review_tools_are_registered_and_work(self) -> None:
        self.assertIn("continuum_review_prepare", TOOLS)
        self.assertIn("continuum_review_ingest", TOOLS)
        self.assertIn("continuum_review_status", TOOLS)

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# MCP subject\n", encoding="utf-8")
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                job = call_tool(
                    "continuum_review_prepare",
                    {
                        "root": str(root),
                        "subject": str(subject),
                        "prompt": "Review the MCP package.",
                        "transport": "manual",
                    },
                )
                request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
                status = call_tool("continuum_review_status", {"root": str(root), "job_id": job["job_id"]})
                payload = valid_review_payload({**request, **status})
                receipt = call_tool(
                    "continuum_review_ingest",
                    {"root": str(root), "job_id": job["job_id"], "content": json.dumps(payload)},
                )
                status = call_tool("continuum_review_status", {"root": str(root), "job_id": job["job_id"]})

            self.assertTrue(receipt["ok"])
            self.assertEqual(status["status"], "ingested")

    def test_hermes_transport_invokes_oneshot_and_ingests_bound_json(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Hermes subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review through Hermes.", transport="hermes")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            status = review_job_status(root, job_id=job["job_id"])
            payload = valid_review_payload({**request, **status})

            def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                self.assertIn("hermes", command[0])
                self.assertIn("--query", command)
                query = command[command.index("--query") + 1]
                self.assertIn(request["packet_sha256"], query)
                self.assertIn(request["packet_uri"], query)
                self.assertNotIn("# Hermes subject", query)
                return subprocess.CompletedProcess(command, 0, stdout=json.dumps(payload), stderr="")

            with patch.object(review_bridge_module.shutil, "which", return_value="hermes"), patch.object(
                review_bridge_module.subprocess,
                "run",
                side_effect=fake_run,
            ):
                result = review_bridge_module.run_review_job(root, job_id=job["job_id"], transport="hermes")

            self.assertTrue(result["ok"], result)
            self.assertEqual(result["status"], "ingested")
            self.assertEqual(result["ingest"]["verdict"], "hold")
            self.assertTrue(Path(result["ingest"]["ingest_receipt_uri"]).exists())
            status = review_job_status(root, job_id=job["job_id"])
            self.assertEqual(status["status"], "ingested")
            self.assertTrue(Path(status["findings_uri"]).exists())
            self.assertTrue(Path(status["raw_response_uri"]).exists())

    def test_automated_review_failure_preserves_raw_response_status(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Failed review subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review through Hermes.", transport="hermes")

            def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                return subprocess.CompletedProcess(command, 0, stdout="What JSON should I return?", stderr="")

            with patch.object(review_bridge_module.shutil, "which", return_value="hermes"), patch.object(
                review_bridge_module.subprocess,
                "run",
                side_effect=fake_run,
            ):
                with self.assertRaisesRegex(ValueError, "review response did not contain a JSON object"):
                    review_bridge_module.run_review_job(root, job_id=job["job_id"], transport="hermes")

            status = review_job_status(root, job_id=job["job_id"])
            self.assertEqual(status["status"], "review_failed")
            self.assertEqual(status["error_type"], "ReviewBridgeError")
            self.assertTrue(Path(status["raw_response_uri"]).exists())
            self.assertTrue(Path(status["reviewer_content_uri"]).exists())


if __name__ == "__main__":
    unittest.main()
