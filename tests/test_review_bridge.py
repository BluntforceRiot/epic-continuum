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
        "review_surface": "full_capsule",
        "subject_inspected": True,
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
            self.assertTrue(job["packet_coverage"]["coverage_limited"])
            self.assertIn("packet_has_no_text_candidates", job["packet_warnings"])
            with zipfile.ZipFile(job["review_capsule_uri"]) as zf:
                self.assertIn("subject/release.zip", set(zf.namelist()))
                manifest = json.loads(zf.read("source-manifest.json").decode("utf-8"))
                packet = zf.read("review-packet.md").decode("utf-8")
            self.assertEqual(manifest["subject_type"], "file")
            self.assertIn("- Type: file", packet)

    def test_review_capsule_redacts_local_absolute_paths(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n\nReview me.\n", encoding="utf-8")

            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

            local_needles = [str(base), str(root), str(subject), str(Path(job["packet_uri"]).parent)]
            with zipfile.ZipFile(job["review_capsule_uri"]) as zf:
                request = zf.read("request.json").decode("utf-8")
                manifest = zf.read("source-manifest.json").decode("utf-8")
                packet = zf.read("review-packet.md").decode("utf-8")

            for text in (request, manifest, packet):
                for needle in local_needles:
                    with self.subTest(needle=needle):
                        self.assertNotIn(needle, text)
            request_json = json.loads(request)
            manifest_json = json.loads(manifest)
            self.assertTrue(request_json["local_paths_redacted"])
            self.assertEqual(request_json["artifacts"]["review_packet"], "review-packet.md")
            self.assertNotIn("subject_path", request_json)
            self.assertNotIn("packet_uri", request_json)
            self.assertEqual(manifest_json["subject"], "subject/")
            self.assertTrue(manifest_json["local_paths_redacted"])
            self.assertIn("- Path: subject/", packet)

    def test_zip_subject_secret_scan_requires_explicit_nested_fixture_allowlist(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            release_zip = base / "release.zip"
            token = "s" + "k-" + ("S" * 32)
            with zipfile.ZipFile(release_zip, "w") as zf:
                zf.writestr("pkg/tests/test_fixture.py", f'api_key="{token}"\n')
                zf.writestr("pkg/README.md", "# Release\n")

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(root, subject_path=release_zip, prompt="Review hard.", transport="manual")

            job = create_review_job(
                root,
                subject_path=release_zip,
                prompt="Review hard.",
                transport="manual",
                secret_allowlist_patterns=[r"^release.zip!/pkg/tests/test_fixture.py:1:.*api_key"],
            )

            self.assertTrue(job["ok"])
            self.assertEqual(Path(job["subject_archive_uri"]).name, "release.zip")

    def test_source_release_zip_allows_synthetic_fixture_assignments(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            release_zip = base / "source-release.zip"
            with zipfile.ZipFile(release_zip, "w") as zf:
                zf.writestr("pkg/src/module.py", "api_key=args.api_key\n")
                zf.writestr("pkg/docs/example.md", 'api_key: "none"\n')
                zf.writestr("pkg/tests/test_fixture.py", 'self.assertTrue(scan_text_for_secrets("api_key=supersecretvalue123"))\n')

            job = create_review_job(root, subject_path=release_zip, prompt="Review source release.", transport="manual")
            report = json.loads(Path(job["secret_allowlist_report_uri"]).read_text(encoding="utf-8"))

            self.assertTrue(job["ok"])
            self.assertGreaterEqual(report["suppressed_count"], 1)
            self.assertEqual(report.get("blocked_findings", []), [])

    def test_archive_candidate_secret_scan_reads_non_text_extension(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "payload.dat").write_text("token = 'sk-" + ("A" * 32) + "'\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

    def test_review_secret_allowlist_suppresses_specific_false_positive(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "fixture.txt").write_text("review_fixture_token = 'sk-" + ("A" * 32) + "'\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
                secret_allowlist_patterns=[r"^fixture\.txt:1:.*review_fixture_token"],
            )

            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(request["secret_allowlist_pattern_count"], 1)
            with zipfile.ZipFile(job["review_capsule_uri"]) as zf:
                public_request = json.loads(zf.read("request.json").decode("utf-8"))
            self.assertEqual(public_request["secret_allowlist_pattern_count"], 1)

    def test_snapshot_archive_and_packet_ignore_later_live_subject_mutation(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            target = subject / "app.py"
            target.write_text('VERSION = "old"\n', encoding="utf-8")
            original_copy = review_bridge_module._copy_snapshot_files

            def copy_then_mutate(root_arg: Path, subject_arg: Path, files: list[Path], snapshot_subject: Path) -> list[Path]:
                copied = original_copy(root_arg, subject_arg, files, snapshot_subject)
                target.write_text('VERSION = "new"\n', encoding="utf-8")
                return copied

            with patch.object(review_bridge_module, "_copy_snapshot_files", side_effect=copy_then_mutate):
                job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

            packet = Path(job["packet_uri"]).read_text(encoding="utf-8")
            self.assertIn('VERSION = "old"', packet)
            self.assertNotIn('VERSION = "new"', packet)
            with zipfile.ZipFile(job["subject_archive_uri"]) as zf:
                archived = zf.read("app.py").decode("utf-8")
            self.assertIn('VERSION = "old"', archived)
            self.assertNotIn('VERSION = "new"', archived)
            manifest = json.loads(Path(job["subject_manifest_uri"]).read_text(encoding="utf-8"))
            manifest_hash = next(item["sha256"] for item in manifest["files"] if item["path"] == "app.py")
            snapshot_hash = review_bridge_module.file_sha256(Path(job["packet_uri"]).parent / "snapshot" / "subject" / "app.py")
            live_hash = review_bridge_module.file_sha256(target)
            self.assertEqual(manifest_hash, snapshot_hash)
            self.assertNotEqual(manifest_hash, live_hash)

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
            payload["review_surface"] = "packet_excerpt_only"
            payload["subject_inspected"] = False
            receipt = ingest_review_result(root, job_id=job["job_id"], content=json.dumps(payload))
            findings = json.loads(Path(receipt["findings_uri"]).read_text(encoding="utf-8"))

            self.assertEqual(receipt["verdict"], "coverage_limited")
            self.assertEqual(findings["findings"][0]["title"], "Packet-only review is not full artifact approval")

    def test_packet_only_clean_pass_is_downgraded_even_when_packet_is_complete(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n\nTiny file.\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            status = review_job_status(root, job_id=job["job_id"])
            payload = valid_review_payload({**request, **status})
            payload["verdict"] = "pass"
            payload["findings"] = []
            payload["review_surface"] = "packet_only"
            payload["subject_inspected"] = False

            receipt = ingest_review_result(root, job_id=job["job_id"], content=json.dumps(payload))

            self.assertEqual(receipt["verdict"], "coverage_limited")

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

            with self.assertRaisesRegex(ValueError, "review response schema validation failed"):
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

            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual", max_packet_bytes=220)
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            status = review_job_status(root, job_id=job["job_id"])
            payload = valid_review_payload({**request, **status})
            payload["verdict"] = "pass"
            payload["findings"] = []
            payload["review_surface"] = "unknown"
            payload["subject_inspected"] = False

            with self.assertRaisesRegex(ValueError, "review response schema validation failed"):
                ingest_review_result(root, job_id=job["job_id"], content=json.dumps(payload))

    def test_ingest_rejects_contradictory_review_surface_flags(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")

            for surface, inspected in (("full_capsule", False), ("local_files", False), ("packet_excerpt_only", True)):
                with self.subTest(surface=surface, inspected=inspected):
                    job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
                    request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
                    status = review_job_status(root, job_id=job["job_id"])
                    payload = valid_review_payload({**request, **status})
                    payload["review_surface"] = surface
                    payload["subject_inspected"] = inspected

                    with self.assertRaisesRegex(ValueError, "review response schema validation failed"):
                        ingest_review_result(root, job_id=job["job_id"], content=json.dumps(payload))

    def test_ingest_requires_review_surface_contract(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")

            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual", max_packet_bytes=220)
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            status = review_job_status(root, job_id=job["job_id"])
            payload = valid_review_payload({**request, **status})
            payload["verdict"] = "pass"
            payload["findings"] = []
            del payload["review_surface"]

            with self.assertRaisesRegex(ValueError, "review response schema validation failed"):
                ingest_review_result(root, job_id=job["job_id"], content=json.dumps(payload))

    def test_browser_handoff_contains_actual_capsule_hash(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")

            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            prompt = Path(job["prompt_uri"]).read_text(encoding="utf-8")
            handoff = Path(job["browser_handoff_uri"]).read_text(encoding="utf-8")

            self.assertEqual(request["review_capsule_sha256"], job["review_capsule_sha256"])
            self.assertIn(job["review_capsule_sha256"], prompt)
            self.assertIn(job["review_capsule_sha256"], handoff)
            self.assertIn("GPT-5.5 Pro", handoff)
            self.assertIn("Local response destination", handoff)
            schema = json.loads(Path(job["schema_uri"]).read_text(encoding="utf-8"))
            self.assertIn("review_capsule_sha256", schema["required"])
            with zipfile.ZipFile(job["review_capsule_uri"]) as zf:
                public_request = json.loads(zf.read("request.json").decode("utf-8"))
            self.assertIsNone(public_request["review_capsule_sha256"])
            self.assertEqual(public_request["review_capsule_sha256_source"], "browser-handoff.md")

    def test_full_capsule_review_is_not_downgraded_for_packet_limits(self) -> None:
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
            payload["review_surface"] = "full_capsule"
            payload["subject_inspected"] = True

            receipt = ingest_review_result(root, job_id=job["job_id"], content=json.dumps(payload))

            self.assertEqual(receipt["verdict"], "pass")

    def test_direct_transport_cannot_claim_full_capsule_review(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "a.py").write_text("print('a')\n", encoding="utf-8")
            (subject / "b.py").write_text("print('b')\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review through endpoint.",
                transport="direct-openai",
                max_packet_bytes=220,
            )
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            status = review_job_status(root, job_id=job["job_id"])
            payload = valid_review_payload({**request, **status})
            payload["verdict"] = "pass"
            payload["findings"] = []
            payload["review_surface"] = "full_capsule"
            payload["subject_inspected"] = True

            with patch.object(
                review_bridge_module,
                "_openai_chat_completion",
                return_value={"choices": [{"message": {"content": json.dumps(payload)}}]},
            ):
                result = review_bridge_module.run_review_job(root, job_id=job["job_id"], transport="direct-openai")

            self.assertEqual(result["ingest"]["verdict"], "coverage_limited")
            findings = json.loads(Path(result["ingest"]["findings_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(findings["review_surface"], "packet_excerpt_only")
            self.assertFalse(findings["subject_inspected"])

    def test_review_secret_scan_does_not_allowlist_semantic_words(self) -> None:
        probes = [
            'API_KEY = "sk-' + ("A" * 32) + '"  # example\n',
            'API_KEY = "sk-' + ("B" * 32) + '" if True else ""\n',
            'payload = {"api_key": "sk-' + ("C" * 32) + '"}\n',
        ]
        for text in probes:
            with self.subTest(text=text[:20]), tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "config.py").write_text(text, encoding="utf-8")

                with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                    create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

                bridge_root = root / "exports" / "review_bridge"
                leftovers = list(bridge_root.glob("**/config.py")) + list(bridge_root.glob("**/subject.zip"))
                self.assertEqual(leftovers, [])

    def test_review_secret_scan_reads_beyond_large_file_sample(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "large.txt").write_text(
                ("x" * 2_000_001) + '\nOPENAI_API_KEY="sk-' + ("L" * 32) + '"\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

            bridge_root = root / "exports" / "review_bridge"
            self.assertEqual(list(bridge_root.glob("**/large.txt")), [])
            self.assertEqual(list(bridge_root.glob("**/subject.zip")), [])

    def test_review_secret_allowlist_rejects_broad_patterns(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "config.py").write_text('OPENAI_API_KEY="sk-' + ("Z" * 32) + '"\n', encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "allowlist patterns must be anchored"):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                    secret_allowlist_patterns=[r".*"],
                )

            for pattern in (r"^.*:.*", r"^.*:.*:.*", r"^.+:1:.*", r"^config\.py:.*:.*"):
                with self.subTest(pattern=pattern), self.assertRaisesRegex(ValueError, "allowlist"):
                    create_review_job(
                        root,
                        subject_path=subject,
                        prompt="Review hard.",
                        transport="manual",
                        secret_allowlist_patterns=[pattern],
                    )

    def test_review_secret_scan_blocks_raw_secret_in_tests(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            tests_dir = subject / "tests"
            tests_dir.mkdir(parents=True)
            (tests_dir / "test_live_secret.py").write_text(
                'assert token == "sk-' + ("Y" * 32) + '"  # scan_text_for_secrets\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

    def test_review_prepare_fails_loudly_when_file_limit_is_reached(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            for index in range(3):
                (subject / f"file-{index}.txt").write_text(f"{index}\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "file limit exceeded"):
                create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual", max_files=2)

    def test_review_check_current_detects_executable_mode_changes_on_posix(self) -> None:
        if os.name == "nt":
            self.skipTest("POSIX executable mode changes are not meaningful on Windows")
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            script = subject / "tool.sh"
            script.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
            script.chmod(0o644)
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

            self.assertTrue(review_bridge_module.review_check_current(root, job_id=job["job_id"])["current"])
            script.chmod(0o755)
            current = review_bridge_module.review_check_current(root, job_id=job["job_id"])
            self.assertFalse(current["current"])
            self.assertEqual(current["reason"], "source_changed_since_review_preparation")

    def test_invalid_manual_response_is_preserved_and_marks_failed(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

            with self.assertRaisesRegex(ValueError, "review response did not contain a JSON object"):
                ingest_review_result(root, job_id=job["job_id"], content="not json")

            status = review_job_status(root, job_id=job["job_id"])
            self.assertEqual(status["status"], "review_failed")
            self.assertTrue(Path(status["raw_response_uri"]).exists())
            self.assertIn("responses", Path(status["raw_response_uri"]).parts)
            self.assertTrue(Path(status["last_attempt_uri"]).exists())

    def test_repeated_invalid_manual_responses_advance_attempt_ledger(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

            for content in ("not json one", "not json two"):
                with self.subTest(content=content), self.assertRaisesRegex(ValueError, "review response did not contain a JSON object"):
                    ingest_review_result(root, job_id=job["job_id"], content=content)

            job_dir = Path(job["job_dir"])
            responses = sorted((job_dir / "responses").glob("response-*.raw.txt"))
            attempts = sorted((job_dir / "attempts").glob("attempt-*.json"))
            status = review_job_status(root, job_id=job["job_id"])
            stored_status = json.loads((job_dir / review_bridge_module.REVIEW_STATUS_NAME).read_text(encoding="utf-8"))
            attempt_payloads = [json.loads(path.read_text(encoding="utf-8")) for path in attempts]

            self.assertEqual([path.name for path in responses], ["response-001.raw.txt", "response-002.raw.txt"])
            self.assertEqual([path.read_text(encoding="utf-8") for path in responses], ["not json one", "not json two"])
            self.assertEqual([path.name for path in attempts], ["attempt-001.json", "attempt-002.json"])
            self.assertEqual([payload["attempt"] for payload in attempt_payloads], [1, 2])
            self.assertEqual(stored_status["attempt_count"], 2)
            self.assertEqual(Path(status["raw_response_uri"]).name, "response-002.raw.txt")
            self.assertEqual(Path(status["last_attempt_uri"]).name, "attempt-002.json")

    def test_ingest_is_append_only_and_rejects_second_acceptance(self) -> None:
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

            receipt = ingest_review_result(root, job_id=job["job_id"], content=json.dumps(payload))

            self.assertIn("responses", Path(receipt["raw_response_uri"]).parts)
            self.assertEqual(Path(receipt["findings_uri"]).name, "findings-001.json")
            self.assertEqual(Path(receipt["ingest_receipt_uri"]).name, "ingest-001.json")
            with self.assertRaisesRegex(ValueError, "already has an accepted ingest"):
                ingest_review_result(root, job_id=job["job_id"], content=json.dumps(payload))

    def test_git_state_change_during_snapshot_is_rejected(self) -> None:
        if review_bridge_module.shutil.which("git") is None:
            self.skipTest("git executable unavailable")
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "repo"
            subject.mkdir()
            target = subject / "app.py"
            target.write_text('VERSION = "old"\n', encoding="utf-8")
            subprocess.run(["git", "init"], cwd=subject, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=subject, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=subject, check=True)
            subprocess.run(["git", "add", "app.py"], cwd=subject, check=True)
            subprocess.run(["git", "commit", "-m", "init"], cwd=subject, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            original_copy = review_bridge_module._copy_snapshot_files

            def copy_then_mutate(root_arg: Path, subject_arg: Path, files: list[Path], snapshot_subject: Path) -> list[Path]:
                copied = original_copy(root_arg, subject_arg, files, snapshot_subject)
                target.write_text('VERSION = "new"\n', encoding="utf-8")
                return copied

            with patch.object(review_bridge_module, "_copy_snapshot_files", side_effect=copy_then_mutate):
                with self.assertRaisesRegex(ValueError, "git state changed during review preparation"):
                    create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

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

    def test_automated_review_failures_use_append_only_numbered_responses(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Failed review subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review through Hermes.", transport="hermes")
            outputs = iter(["first invalid", "second invalid"])

            def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                return subprocess.CompletedProcess(command, 0, stdout=next(outputs), stderr="")

            with patch.object(review_bridge_module.shutil, "which", return_value="hermes"), patch.object(
                review_bridge_module.subprocess,
                "run",
                side_effect=fake_run,
            ):
                for expected in ("first invalid", "second invalid"):
                    with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, "review response did not contain a JSON object"):
                        review_bridge_module.run_review_job(root, job_id=job["job_id"], transport="hermes")

            job_dir = Path(job["job_dir"])
            responses = sorted((job_dir / "responses").glob("response-*.raw.txt"))
            attempts = sorted((job_dir / "attempts").glob("attempt-*.json"))
            status = review_job_status(root, job_id=job["job_id"])

            self.assertEqual([path.name for path in responses], ["response-001.raw.txt", "response-002.raw.txt"])
            self.assertEqual([path.read_text(encoding="utf-8") for path in responses], ["first invalid", "second invalid"])
            self.assertEqual([path.name for path in attempts], ["attempt-001.json", "attempt-002.json"])
            self.assertEqual(Path(status["raw_response_uri"]).name, "response-002.raw.txt")
            self.assertEqual(Path(status["reviewer_content_uri"]).name, "response-002.raw.txt")

    def test_direct_transport_failure_marks_transport_failed(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Direct failure subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review through endpoint.", transport="direct-openai")

            with patch.object(review_bridge_module, "_openai_chat_completion", side_effect=review_bridge_module.ReviewBridgeError("endpoint refused")):
                with self.assertRaisesRegex(ValueError, "endpoint refused"):
                    review_bridge_module.run_review_job(root, job_id=job["job_id"], transport="direct-openai")

            status = review_job_status(root, job_id=job["job_id"])
            self.assertEqual(status["status"], "transport_failed")
            self.assertEqual(status["error_type"], "ReviewBridgeError")
            self.assertIn("endpoint refused", status["error"])
            self.assertTrue(Path(status["last_attempt_uri"]).exists())


if __name__ == "__main__":
    unittest.main()
