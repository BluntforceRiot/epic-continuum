from __future__ import annotations

import json
import gzip
import hashlib
import io
import os
import stat
import subprocess
import tempfile
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from continuum.core.review_bridge import (
    create_review_job,
    ingest_review_result,
    review_browser_attempt_start,
    review_check_current,
    review_job_status,
)
from continuum.core.permissions import posix_permissions_supported
from continuum.core import review_bridge as review_bridge_module
from continuum.core.operations import _verify_artifact_ledger
from continuum.mcp_server import TOOLS, dispatch


def valid_review_payload(request: dict) -> dict:
    payload = {
        "schema_version": "0.2",
        "job_id": request["job_id"],
        "review_id": request["job_id"],
        "packet_sha256": request["packet_sha256"],
        "review_capsule_sha256": request.get("review_capsule_sha256"),
        "subject_archive_sha256": request["subject_archive_sha256"],
        "package_sha256": request["package_sha256"],
        "capsule_challenge": request["capsule_challenge"],
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
    if request.get("inner_archive_manifest_sha256"):
        payload["inner_archive_manifest_sha256"] = request.get("inner_archive_manifest_sha256")
        payload["inner_archive_member_count"] = request.get("inner_archive_member_count")
    return payload


def exact_secret_allowlist_entry(source: str, text: str, *, index: int = 0) -> dict:
    findings = review_bridge_module._scan_review_text_for_secrets(text, source=source, max_findings=0)
    if not findings:
        raise AssertionError(f"fixture produced no secret findings: {source}")
    finding = findings[index]
    line_number = int(finding["line"])
    line = text.splitlines()[line_number - 1]
    return {
        "source": source,
        "line": line_number,
        "finding_type": finding["type"],
        "secret_sha256": finding["secret_hash"],
        "line_sha256": hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest(),
        "reason": "unit-test synthetic fixture",
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


def ingest_reserved_response(root: Path, job: dict, content: str) -> dict:
    attempt = review_browser_attempt_start(root, job_id=job["job_id"])
    response_path = Path(attempt["response_uri"])
    response_path.write_text(content, encoding="utf-8")
    return ingest_review_result(root, job_id=job["job_id"], result_path=response_path)


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

            receipt = ingest_reserved_response(root, job, json.dumps(payload))

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

    def test_prepare_rejects_symlinked_source_paths_as_incomplete_coverage(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            outside = base / "outside.py"
            outside.write_text("print('outside')\n", encoding="utf-8")
            link = subject / "linked.py"
            try:
                link.symlink_to(outside)
            except (NotImplementedError, OSError) as exc:
                self.skipTest(f"symlinks unavailable: {exc}")

            with self.assertRaisesRegex(ValueError, "cannot be captured safely"):
                create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

    def test_default_policy_exclusions_are_reported_in_coverage(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            (subject / "REVIEW_TRIAGE_secret.md").write_text("local scratch\n", encoding="utf-8")

            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

            coverage = job["packet_coverage"]
            self.assertTrue(coverage["coverage_limited"])
            self.assertIn("subject_policy_exclusions_present", job["packet_warnings"])
            self.assertEqual(coverage["subject_exclusion_count"], 1)
            self.assertEqual(coverage["subject_exclusions"][0]["reason"], "default_exclude_basename")
            self.assertEqual(coverage["subject_exclusions"][0]["path"], "REVIEW_TRIAGE_secret.md")

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
                names = set(zf.namelist())
                self.assertIn("original/release.zip", names)
                self.assertIn("subject/README.md", names)
                self.assertIn("inner-archive-manifest.json", names)
                self.assertNotIn("subject/release.zip", names)
                manifest = json.loads(zf.read("source-manifest.json").decode("utf-8"))
                inner_manifest = json.loads(zf.read("inner-archive-manifest.json").decode("utf-8"))
                packet = zf.read("review-packet.md").decode("utf-8")
            self.assertEqual(manifest["subject_type"], "file")
            self.assertEqual(inner_manifest["member_count"], 1)
            self.assertEqual(job["inner_archive_member_count"], 1)
            self.assertIn("- Type: file", packet)

    def test_directory_subject_does_not_require_inner_archive_binding(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Directory review\n", encoding="utf-8")

            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

            self.assertIsNone(job["inner_archive_manifest_sha256"])
            self.assertIsNone(job["inner_archive_member_count"])
            with zipfile.ZipFile(job["review_capsule_uri"]) as zf:
                names = set(zf.namelist())
            self.assertIn("subject/README.md", names)
            self.assertNotIn("inner-archive-manifest.json", names)
            self.assertFalse(any(name.startswith("original/") for name in names))

    def test_zip_capsule_scan_does_not_double_count_prevalidated_original(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            release_zip = base / "release.zip"
            with zipfile.ZipFile(release_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                for index in range(10):
                    zf.writestr(f"src/module_{index:02d}.py", f"VALUE = {index}\n")

            with patch.object(review_bridge_module, "REVIEW_ZIP_SCAN_MAX_MEMBERS", 10):
                job = create_review_job(root, subject_path=release_zip, prompt="Review hard.", transport="manual")

            self.assertEqual(job["inner_archive_member_count"], 10)
            self.assertTrue(Path(job["review_capsule_uri"]).is_file())

    def test_inner_archive_member_count_requires_exact_json_integer(self) -> None:
        for invalid_count in (True, 1.9, "1"):
            with self.subTest(invalid_count=invalid_count), tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                release_zip = base / "release.zip"
                with zipfile.ZipFile(release_zip, "w") as zf:
                    zf.writestr("README.md", "# Release\n")
                job = create_review_job(root, subject_path=release_zip, prompt="Review hard.", transport="manual")
                request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
                status = review_job_status(root, job_id=job["job_id"])
                payload = valid_review_payload({**request, **status})
                payload["inner_archive_member_count"] = invalid_count

                with self.assertRaisesRegex(ValueError, "inner_archive_member_count must be an integer"):
                    ingest_reserved_response(root, job, json.dumps(payload))

    def test_non_zip_review_rejects_inner_archive_member_count(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Directory review\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            status = review_job_status(root, job_id=job["job_id"])
            payload = valid_review_payload({**request, **status})
            payload["inner_archive_member_count"] = 0

            with self.assertRaisesRegex(ValueError, "inner_archive_member_count must be null"):
                ingest_reserved_response(root, job, json.dumps(payload))

    def test_zip_subject_review_response_must_bind_inner_manifest(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            release_zip = base / "release.zip"
            with zipfile.ZipFile(release_zip, "w") as zf:
                zf.writestr("README.md", "# Release\n")

            job = create_review_job(root, subject_path=release_zip, prompt="Review hard.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            status = review_job_status(root, job_id=job["job_id"])
            payload = valid_review_payload({**request, **status})
            payload.pop("inner_archive_manifest_sha256", None)
            payload.pop("inner_archive_member_count", None)

            with self.assertRaisesRegex(ValueError, "inner_archive_manifest_sha256 mismatch"):
                ingest_reserved_response(root, job, json.dumps(payload))

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
            fixture_text = f'api_key="{token}"\n'
            with zipfile.ZipFile(release_zip, "w") as zf:
                zf.writestr("pkg/tests/test_fixture.py", fixture_text)
                zf.writestr("pkg/README.md", "# Release\n")

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(root, subject_path=release_zip, prompt="Review hard.", transport="manual")

            job = create_review_job(
                root,
                subject_path=release_zip,
                prompt="Review hard.",
                transport="manual",
                secret_allowlist_patterns=[
                    exact_secret_allowlist_entry("release.zip!/pkg/tests/test_fixture.py", fixture_text)
                ],
            )

            self.assertTrue(job["ok"])
            self.assertEqual(Path(job["subject_archive_uri"]).name, "release.zip")

    def test_source_release_zip_requires_explicit_fixture_assignment_allowlist(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            release_zip = base / "source-release.zip"
            fixture_text = 'self.assertTrue(scan_text_for_secrets("api_key=supersecretvalue123"))\n'
            with zipfile.ZipFile(release_zip, "w") as zf:
                zf.writestr("pkg/src/module.py", "api_key=args.api_key\n")
                zf.writestr("pkg/docs/example.md", 'api_key: "none"\n')
                zf.writestr("pkg/tests/test_fixture.py", fixture_text)

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(root, subject_path=release_zip, prompt="Review source release.", transport="manual")

            job = create_review_job(
                root,
                subject_path=release_zip,
                prompt="Review source release.",
                transport="manual",
                secret_allowlist_patterns=[
                    exact_secret_allowlist_entry("source-release.zip!/pkg/tests/test_fixture.py", fixture_text)
                ],
            )
            report = json.loads(Path(job["secret_allowlist_report_uri"]).read_text(encoding="utf-8"))

            self.assertTrue(job["ok"])
            self.assertGreaterEqual(report["suppressed_count"], 1)
            self.assertEqual(report.get("blocked_findings", []), [])

    def test_exact_allowlist_matches_release_and_sdist_root_layouts(self) -> None:
        expected = "tests/test_fixture.py"

        self.assertTrue(
            review_bridge_module._allowlist_source_matches(
                "release.zip!/epic-continuum-0.2.0/tests/test_fixture.py",
                expected,
            )
        )
        self.assertTrue(
            review_bridge_module._allowlist_source_matches(
                "source.tar.zip!/epic_continuum_memory-0.2.0/tests/test_fixture.py",
                expected,
            )
        )
        self.assertTrue(
            review_bridge_module._allowlist_source_matches(
                "epic_continuum_memory-0.2.0-py3-none-any.whl!/continuum/integrations/hermes_adapter.py",
                "src/continuum/integrations/hermes_adapter.py",
            )
        )
        self.assertFalse(
            review_bridge_module._allowlist_source_matches(
                "unrelated-0.2.0-py3-none-any.whl!/continuum/integrations/hermes_adapter.py",
                "src/continuum/integrations/hermes_adapter.py",
            )
        )

    def test_zip_subject_rejects_nonempty_metadata(self) -> None:
        cases = ("archive_comment", "member_comment", "member_extra")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                release_zip = base / "release.zip"
                info = zipfile.ZipInfo("README.md")
                if case == "member_comment":
                    info.comment = b"not allowed"
                if case == "member_extra":
                    info.extra = b"\x01\x00\x01\x00x"
                with zipfile.ZipFile(release_zip, "w") as zf:
                    if case == "archive_comment":
                        zf.comment = b"not allowed"
                    zf.writestr(info, "# Release\n")

                with self.assertRaisesRegex(ValueError, "review secret scan coverage incomplete"):
                    create_review_job(root, subject_path=release_zip, prompt="Review hard.", transport="manual")

    def test_zip_subject_rejects_encrypted_member_flags(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            release_zip = base / "release.zip"
            with zipfile.ZipFile(release_zip, "w") as zf:
                zf.writestr("README.md", "# Release\n")
            archive = bytearray(release_zip.read_bytes())
            local_header = archive.index(b"PK\x03\x04")
            central_header = archive.index(b"PK\x01\x02")
            local_flags = int.from_bytes(archive[local_header + 6 : local_header + 8], "little") | 0x0001
            central_flags = int.from_bytes(archive[central_header + 8 : central_header + 10], "little") | 0x0001
            archive[local_header + 6 : local_header + 8] = local_flags.to_bytes(2, "little")
            archive[central_header + 8 : central_header + 10] = central_flags.to_bytes(2, "little")
            release_zip.write_bytes(archive)

            with self.assertRaisesRegex(ValueError, "review secret scan coverage incomplete"):
                create_review_job(root, subject_path=release_zip, prompt="Review hard.", transport="manual")

    def test_zip_subject_rejects_unsupported_nested_archives(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            release_zip = base / "release.zip"
            with zipfile.ZipFile(release_zip, "w") as zf:
                zf.writestr("README.md", "# Release\n")
                zf.writestr("dist/package.tar.gz", b"\x1f\x8bnot reviewed here")

            with self.assertRaisesRegex(ValueError, "review secret scan coverage incomplete"):
                create_review_job(root, subject_path=release_zip, prompt="Review hard.", transport="manual")

    def test_review_secret_scan_rejects_disguised_gzip_content(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            payload = base / "payload.bin"
            secret_text = 'OPENAI_API_KEY="sk-' + ("G" * 32) + '"\n'
            payload.write_bytes(gzip.compress(secret_text.encode("utf-8")))

            with self.assertRaisesRegex(ValueError, "review secret scan coverage incomplete"):
                create_review_job(root, subject_path=payload, prompt="Review hard.", transport="manual")

            self.assertEqual(list((root / "exports" / "review_bridge" / "jobs").glob("*")), [])

    def test_zip_subject_rejects_windows_ambiguous_paths(self) -> None:
        cases = {
            "dot_component": "./a.txt",
            "trailing_dot": "a.txt.",
            "trailing_space": "a.txt ",
            "ads_colon": "a.txt:evil",
            "reserved_name": "con.txt",
            "unicode_nfc_collision": "cafe\u0301.txt",
        }
        for case, suspicious_name in cases.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                release_zip = base / "release.zip"
                with zipfile.ZipFile(release_zip, "w") as zf:
                    if case == "unicode_nfc_collision":
                        zf.writestr("caf\u00e9.txt", "one\n")
                    zf.writestr(suspicious_name, "two\n")

                with self.assertRaisesRegex(ValueError, "review secret scan coverage incomplete"):
                    create_review_job(root, subject_path=release_zip, prompt="Review hard.", transport="manual")

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
            fixture_text = "review_fixture_token = 'sk-" + ("A" * 32) + "'\n"
            (subject / "fixture.txt").write_text(fixture_text, encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
                secret_allowlist_patterns=[exact_secret_allowlist_entry("fixture.txt", fixture_text)],
            )

            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(request["secret_allowlist_pattern_count"], 0)
            self.assertEqual(request["secret_allowlist_fingerprint_count"], 1)
            with zipfile.ZipFile(job["review_capsule_uri"]) as zf:
                public_request = json.loads(zf.read("request.json").decode("utf-8"))
            self.assertEqual(public_request["secret_allowlist_fingerprint_count"], 1)

    def test_review_secret_allowlist_file_suppresses_specific_false_positive(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            token = "s" + "k-" + ("A" * 32)
            fixture_text = f'review_fixture_token="{token}"\n'
            (subject / "fixture.txt").write_text(fixture_text, encoding="utf-8")
            allowlist_file = base / "review-secret-allowlist.jsonl"
            allowlist_file.write_text(
                json.dumps(exact_secret_allowlist_entry("fixture.txt", fixture_text)) + "\n",
                encoding="utf-8",
            )

            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
                secret_allowlist_files=[allowlist_file],
            )

            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            report = json.loads(Path(job["secret_allowlist_report_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(request["secret_allowlist_pattern_count"], 0)
            self.assertEqual(request["secret_allowlist_fingerprint_count"], 1)
            self.assertEqual(request["secret_allowlist_file_count"], 1)
            self.assertEqual(report["explicit_file_count"], 1)
            with zipfile.ZipFile(job["review_capsule_uri"]) as zf:
                public_request = json.loads(zf.read("request.json").decode("utf-8"))
            self.assertEqual(public_request["secret_allowlist_fingerprint_count"], 1)
            self.assertEqual(public_request["secret_allowlist_file_count"], 1)
            self.assertNotIn(str(allowlist_file), json.dumps(public_request))

    def test_review_secret_allowlist_fingerprint_rejects_replaced_secret(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            original = 'OPENAI_API_KEY="sk-' + ("A" * 32) + '"\n'
            replaced = 'OPENAI_API_KEY="sk-' + ("B" * 32) + '"\n'
            allowlist_file = base / "review-secret-allowlist.jsonl"
            allowlist_file.write_text(
                json.dumps(exact_secret_allowlist_entry("fixture.py", original)) + "\n",
                encoding="utf-8",
            )
            (subject / "fixture.py").write_text(replaced, encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                    secret_allowlist_files=[allowlist_file],
                )

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
            receipt = ingest_reserved_response(root, job, json.dumps(payload))
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

            receipt = ingest_reserved_response(root, job, json.dumps(payload))

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

    def test_directory_subject_preserves_executable_mode_privately_and_stays_current(self) -> None:
        if os.name != "posix" or not posix_permissions_supported(Path(tempfile.gettempdir())):
            self.skipTest("POSIX mode checks require chmod-style permissions")
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            script = subject / "tool.sh"
            script.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
            script.chmod(0o755)
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

            snapshot_script = Path(job["job_dir"]) / "snapshot" / "subject" / "tool.sh"
            manifest = json.loads(Path(job["subject_manifest_uri"]).read_text(encoding="utf-8"))
            zip_mode = next(item["zip_mode"] for item in manifest["files"] if item["path"] == "tool.sh")
            with zipfile.ZipFile(job["review_capsule_uri"]) as zf:
                capsule_mode = (zf.getinfo("subject/tool.sh").external_attr >> 16) & 0o777

            self.assertEqual(stat.S_IMODE(snapshot_script.stat().st_mode), 0o700)
            self.assertEqual(zip_mode, "100755")
            self.assertEqual(capsule_mode, 0o755)
            self.assertTrue(review_check_current(root, job_id=job["job_id"])["current"])

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
                    ingest_reserved_response(root, job, json.dumps(bad))

            with self.assertRaisesRegex(ValueError, "review_complete must be true"):
                bad = dict(payload)
                bad["review_complete"] = False
                ingest_reserved_response(root, job, json.dumps(bad))

            with self.assertRaisesRegex(ValueError, "review response schema validation failed"):
                bad = dict(payload)
                del bad["review_capsule_sha256"]
                ingest_reserved_response(root, job, json.dumps(bad))

    def test_mutable_status_cannot_override_immutable_review_binding(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            status_path = Path(job["job_dir"]) / review_bridge_module.REVIEW_STATUS_NAME
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["review_capsule_sha256"] = "0" * 64
            status_path.write_text(json.dumps(status), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "immutable field mismatch"):
                review_browser_attempt_start(root, job_id=job["job_id"])

    def test_legacy_status_is_migrated_and_full_review_requires_reprepare(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            request_path = Path(job["request_uri"])
            current_request = json.loads(request_path.read_text(encoding="utf-8"))
            legacy_request = dict(current_request)
            legacy_request.pop("capsule_challenge")
            request_path.write_text(json.dumps(legacy_request), encoding="utf-8")
            status_path = Path(job["job_dir"]) / review_bridge_module.REVIEW_STATUS_NAME
            legacy_status = json.loads(status_path.read_text(encoding="utf-8"))
            for key in review_bridge_module.LEGACY_STATUS_IMMUTABLE_KEYS:
                legacy_status[key] = legacy_request[key]
            status_path.write_text(json.dumps(legacy_status), encoding="utf-8")

            status = review_job_status(root, job_id=job["job_id"])
            migrated_status = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertFalse(set(migrated_status) & review_bridge_module.LEGACY_STATUS_IMMUTABLE_KEYS)
            self.assertFalse(status["full_capsule_review_supported"])
            self.assertTrue(status["legacy_job_requires_reprepare"])

            full_payload = valid_review_payload(current_request)
            with self.assertRaisesRegex(ValueError, "legacy_job_requires_reprepare"):
                ingest_reserved_response(root, job, json.dumps(full_payload))

            packet_payload = valid_review_payload(current_request)
            packet_payload.pop("capsule_challenge")
            packet_payload["review_surface"] = "packet_excerpt_only"
            packet_payload["subject_inspected"] = False
            receipt = ingest_reserved_response(root, job, json.dumps(packet_payload))
            self.assertTrue(receipt["ok"])

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
                ingest_reserved_response(root, job, json.dumps(payload))

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
                ingest_reserved_response(root, job, json.dumps(payload))

            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual", max_packet_bytes=220)
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            status = review_job_status(root, job_id=job["job_id"])
            payload = valid_review_payload({**request, **status})
            payload["verdict"] = "pass"
            payload["findings"] = []
            payload["review_surface"] = "unknown"
            payload["subject_inspected"] = False

            with self.assertRaisesRegex(ValueError, "review response schema validation failed"):
                ingest_reserved_response(root, job, json.dumps(payload))

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
                        ingest_reserved_response(root, job, json.dumps(payload))

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
                ingest_reserved_response(root, job, json.dumps(payload))

    def test_browser_handoff_contains_actual_capsule_hash_and_trusted_objective(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")

            job = create_review_job(root, subject_path=subject, prompt="Review the release boundary carefully.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            prompt = Path(job["prompt_uri"]).read_text(encoding="utf-8")
            handoff = Path(job["browser_handoff_uri"]).read_text(encoding="utf-8")

            self.assertEqual(request["review_capsule_sha256"], job["review_capsule_sha256"])
            self.assertIn(job["review_capsule_sha256"], prompt)
            self.assertIn(job["review_capsule_sha256"], handoff)
            self.assertIn("user's requested Pro reviewer", handoff)
            self.assertIn("Reserve next attempt command", handoff)
            self.assertNotIn("response-001.raw.txt", handoff)
            self.assertIn("Review the release boundary carefully.", handoff)
            self.assertIn("Review the release boundary carefully.", prompt)
            schema = json.loads(Path(job["schema_uri"]).read_text(encoding="utf-8"))
            self.assertIn("review_capsule_sha256", schema["required"])
            with zipfile.ZipFile(job["review_capsule_uri"]) as zf:
                public_request = json.loads(zf.read("request.json").decode("utf-8"))
                instructions = zf.read("REVIEW_INSTRUCTIONS.md").decode("utf-8")
            self.assertIsNone(public_request["review_capsule_sha256"])
            self.assertEqual(public_request["review_capsule_sha256_source"], "browser-handoff.md")
            self.assertEqual(public_request["review_objective"], "Review the release boundary carefully.")
            self.assertIn("Review the release boundary carefully.", instructions)
            self.assertNotIn("capsule_challenge", schema["required"])
            self.assertIn("capsule_challenge", schema["properties"])
            self.assertIn("CAPSULE_CHALLENGE.json", instructions)
            self.assertNotIn(request["capsule_challenge"], prompt)
            self.assertNotIn(request["capsule_challenge"], handoff)
            with zipfile.ZipFile(job["review_capsule_uri"]) as zf:
                challenge = json.loads(zf.read("CAPSULE_CHALLENGE.json").decode("utf-8"))
            self.assertEqual(challenge["capsule_challenge"], request["capsule_challenge"])

    def test_generated_shell_commands_single_quote_expansion_characters(self) -> None:
        value = "root'$(touch owned)`whoami`$HOME"

        self.assertEqual(
            review_bridge_module._posix_shell_arg(value),
            "'root'\"'\"'$(touch owned)`whoami`$HOME'",
        )
        self.assertEqual(
            review_bridge_module._powershell_arg(value),
            "'root''$(touch owned)`whoami`$HOME'",
        )

    def test_full_capsule_ingest_requires_capsule_challenge(self) -> None:
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
            del payload["capsule_challenge"]

            with self.assertRaisesRegex(ValueError, "capsule_challenge is required"):
                ingest_reserved_response(root, job, json.dumps(payload))

            payload = valid_review_payload({**request, **status})
            payload["capsule_challenge"] = "wrong"
            with self.assertRaisesRegex(ValueError, "capsule_challenge mismatch"):
                ingest_reserved_response(root, job, json.dumps(payload))

    def test_browser_attempt_reservation_uses_unique_response_paths(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            self.assertTrue(_verify_artifact_ledger(root)["ok"])

            first = review_browser_attempt_start(root, job_id=job["job_id"])
            first_path = Path(first["response_uri"])
            self.assertTrue(_verify_artifact_ledger(root)["ok"])
            self.assertEqual(first_path.name, "response-001.raw.txt")
            self.assertIn("browser-handoffs", Path(first["browser_handoff_uri"]).parts)
            first_path.write_text("not json", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "review response did not contain a JSON object"):
                ingest_review_result(root, job_id=job["job_id"], result_path=first_path)
            self.assertTrue(_verify_artifact_ledger(root)["ok"])
            self.assertEqual(first_path.read_text(encoding="utf-8"), "not json")
            status_after_failure = review_job_status(root, job_id=job["job_id"])
            self.assertIsNone(status_after_failure["browser_response_uri"])
            self.assertIsNone(status_after_failure["browser_attempt_uri"])
            first_path.write_text(json.dumps(valid_review_payload({**request, **status_after_failure})), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "current reserved browser attempt"):
                ingest_review_result(root, job_id=job["job_id"], result_path=first_path)
            failed_attempt = json.loads(Path(status_after_failure["last_attempt_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(failed_attempt["status"], "review_failed")

            second = review_browser_attempt_start(root, job_id=job["job_id"])
            second_path = Path(second["response_uri"])
            self.assertTrue(_verify_artifact_ledger(root)["ok"])
            status = review_job_status(root, job_id=job["job_id"])
            handoff = Path(status["browser_handoff_uri"]).read_text(encoding="utf-8")

            self.assertEqual(second_path.name, "response-002.raw.txt")
            self.assertNotEqual(first_path, second_path)
            self.assertIn(str(second_path), handoff)
            self.assertEqual(Path(status["browser_response_uri"]), second_path)

    def test_concurrent_browser_attempt_reservations_are_serialized(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(lambda _index: review_browser_attempt_start(root, job_id=job["job_id"]), range(2)))

            self.assertEqual({result["attempt"] for result in results}, {1, 2})
            self.assertEqual(
                {Path(result["response_uri"]).name for result in results},
                {"response-001.raw.txt", "response-002.raw.txt"},
            )
            self.assertEqual(len({result["browser_handoff_uri"] for result in results}), 2)
            self.assertTrue(_verify_artifact_ledger(root)["ok"])

    def test_review_capsule_and_reserved_responses_are_private_on_posix(self) -> None:
        if os.name != "posix" or not posix_permissions_supported(Path(tempfile.gettempdir())):
            self.skipTest("POSIX mode checks require chmod-style permissions")
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            attempt = review_browser_attempt_start(root, job_id=job["job_id"])

            self.assertEqual(stat.S_IMODE(Path(job["review_capsule_uri"]).stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(Path(attempt["response_uri"]).stat().st_mode), 0o600)

    def test_repeated_browser_reservation_supersedes_previous_pending_attempt(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

            first = review_browser_attempt_start(root, job_id=job["job_id"])
            second = review_browser_attempt_start(root, job_id=job["job_id"])

            first_attempt = json.loads(Path(first["attempt_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(first_attempt["status"], "browser_attempt_superseded")
            self.assertEqual(first_attempt["superseded_by_attempt"], 2)
            self.assertNotEqual(first["browser_handoff_uri"], second["browser_handoff_uri"])
            self.assertTrue(_verify_artifact_ledger(root)["ok"])

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

            receipt = ingest_reserved_response(root, job, json.dumps(payload))

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

    def test_direct_transport_can_ingest_prompt_bound_result_without_hidden_challenge(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review through endpoint.", transport="direct-openai")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            captured_prompt: dict[str, str] = {}

            def endpoint_response(**kwargs: object) -> dict:
                prompt = str(kwargs["user_prompt"])
                captured_prompt["text"] = prompt

                def binding(name: str) -> str | None:
                    prefix = f"- {name}: "
                    for line in prompt.splitlines():
                        if line.startswith(prefix):
                            value = line[len(prefix) :].strip()
                            return None if value == "null" else value
                    raise AssertionError(f"missing binding in endpoint prompt: {name}")

                archive_hash = binding("subject_archive_sha256")
                payload = {
                    "schema_version": "0.2",
                    "job_id": binding("job_id"),
                    "packet_sha256": binding("packet_sha256"),
                    "review_capsule_sha256": binding("review_capsule_sha256"),
                    "subject_archive_sha256": archive_hash,
                    "package_sha256": archive_hash,
                    "review_complete": True,
                    "sentinel": binding("sentinel"),
                    "summary": "Prompt-only endpoint review complete.",
                    "verdict": "hold",
                    "review_surface": "packet_excerpt_only",
                    "subject_inspected": False,
                    "findings": [],
                    "open_questions": [],
                    "tests_suggested": [],
                }
                return {"choices": [{"message": {"content": json.dumps(payload)}}]}

            with patch.object(review_bridge_module, "_openai_chat_completion", side_effect=endpoint_response):
                result = review_bridge_module.run_review_job(root, job_id=job["job_id"], transport="direct-openai")

            self.assertEqual(result["ingest"]["verdict"], "hold")
            self.assertNotIn(request["capsule_challenge"], captured_prompt["text"])
            stored = json.loads(Path(result["ingest"]["findings_uri"]).read_text(encoding="utf-8"))
            self.assertIsNone(stored["capsule_challenge"])

    def test_concurrent_review_ingests_accept_exactly_one_result(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="direct-openai")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            status = review_job_status(root, job_id=job["job_id"])
            payload = valid_review_payload({**request, **status})
            payload.pop("capsule_challenge", None)
            payload["review_surface"] = "packet_excerpt_only"
            payload["subject_inspected"] = False
            content = json.dumps(payload)

            def attempt_ingest(_index: int) -> tuple[str, object]:
                try:
                    return "accepted", ingest_review_result(root, job_id=job["job_id"], content=content)
                except ValueError as exc:
                    return "rejected", exc

            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = list(executor.map(attempt_ingest, range(2)))

            self.assertEqual([kind for kind, _value in outcomes].count("accepted"), 1)
            self.assertEqual([kind for kind, _value in outcomes].count("rejected"), 1)
            final_status = review_job_status(root, job_id=job["job_id"])
            self.assertEqual(final_status["status"], "ingested")
            self.assertEqual(final_status["accepted_ingest_count"], 1)
            job_dir = Path(job["job_dir"])
            self.assertEqual(len(list((job_dir / "receipts").glob("ingest-*.json"))), 1)

    def test_interrupted_review_ingest_resumes_idempotently(self) -> None:
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
            attempt = review_browser_attempt_start(root, job_id=job["job_id"])
            response_path = Path(attempt["response_uri"])
            response_path.write_text(json.dumps(payload), encoding="utf-8")
            response_json_path = response_path.with_suffix("").with_suffix(".json")
            original_secure_write = review_bridge_module.secure_write_text
            failed_once = False

            def interrupt_after_claim(path: Path, text: str, **kwargs: object) -> None:
                nonlocal failed_once
                if Path(path) == response_json_path and not failed_once:
                    failed_once = True
                    raise OSError("simulated process interruption after ingest claim")
                original_secure_write(path, text, **kwargs)

            with patch.object(review_bridge_module, "secure_write_text", side_effect=interrupt_after_claim):
                with self.assertRaisesRegex(OSError, "simulated process interruption"):
                    ingest_review_result(root, job_id=job["job_id"], result_path=response_path)

            interrupted = review_job_status(root, job_id=job["job_id"])
            interrupted_status = json.loads(Path(interrupted["status_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(interrupted["status"], "ingesting")
            self.assertEqual(interrupted["accepted_ingest_count"], 0)
            self.assertEqual(interrupted_status["pending_response_json_uri"], str(response_json_path))

            receipt = ingest_review_result(root, job_id=job["job_id"], result_path=response_path)
            final_status = review_job_status(root, job_id=job["job_id"])
            stored_status = json.loads(Path(final_status["status_uri"]).read_text(encoding="utf-8"))
            self.assertTrue(receipt["ok"])
            self.assertEqual(final_status["status"], "ingested")
            self.assertEqual(final_status["accepted_ingest_count"], 1)
            self.assertFalse(any(key.startswith("pending_") for key in stored_status))
            self.assertEqual(len(list((Path(job["job_dir"]) / "receipts").glob("ingest-*.json"))), 1)

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

    def test_review_secret_scan_zero_limit_means_uncapped(self) -> None:
        text = (
            'OPENAI_API_KEY="sk-' + ("A" * 32) + '"\n'
            'GITHUB_TOKEN="ghp_' + ("B" * 36) + '"\n'
        )

        findings = review_bridge_module._scan_review_text_for_secrets(text, source="fixture.py", max_findings=0)

        self.assertGreaterEqual(len(findings), 2)

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

    def test_review_secret_allowlist_requires_exact_source_path(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            nested = subject / "pkg" / "tests"
            nested.mkdir(parents=True)
            text = 'OPENAI_API_KEY="sk-' + ("S" * 32) + '"\n'
            (nested / "fixture.py").write_text(text, encoding="utf-8")
            allowlist = exact_secret_allowlist_entry("tests/fixture.py", text)

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                    secret_allowlist_patterns=[allowlist],
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

    def test_review_secret_scan_blocks_underscore_identifier_value(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "config.py").write_text(
                'client_secret = "prod_live_db_password_9F3E7A6B5C4D2E1F"\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

    def test_review_secret_scan_blocks_generic_assignment_in_tests_directory(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            tests_dir = subject / "tests"
            tests_dir.mkdir(parents=True)
            (tests_dir / "test_config.py").write_text(
                'client_secret = "realish_test_password_9F3E7A6B5C4D2E1F"\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

    def test_review_secret_scan_continues_after_suppressed_budget(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            lines = [f"api_key = 'fixture_token_{index:02d}_abcdefghijklmnop'\n" for index in range(20)]
            lines.append('OPENAI_API_KEY="sk-' + ("Q" * 32) + '"\n')
            (subject / "fixture.py").write_text("".join(lines), encoding="utf-8")
            allowlist = [
                rf"^fixture\.py:{index}:.*fixture_token_{index - 1:02d}_abcdefghijklmnop"
                for index in range(1, 21)
            ]

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                    secret_allowlist_patterns=allowlist,
                )

    def test_review_secret_scan_decodes_utf16le_files(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "windows-config.txt").write_bytes(('OPENAI_API_KEY="sk-' + ("U" * 32) + '"\n').encode("utf-16le"))

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

    def test_review_secret_scan_blocks_binary_nul_ascii_secret(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "payload.bin").write_bytes(b"\x00\x01binary\x00sk-" + (b"N" * 32) + b"\x00")

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

    def test_review_secret_scan_decodes_utf32le_files(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "wide-config.txt").write_bytes(('OPENAI_API_KEY="sk-' + ("W" * 32) + '"\n').encode("utf-32le"))

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

    def test_review_prepare_rejects_invalid_zip_subject(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            corrupt_zip = base / "corrupt.zip"
            corrupt_zip.write_bytes(b"not a zip")

            with self.assertRaisesRegex(ValueError, "review secret scan coverage incomplete|not a valid ZIP"):
                create_review_job(root, subject_path=corrupt_zip, prompt="Review hard.", transport="manual")

    def test_review_secret_scan_rejects_nested_zip_members(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            release_zip = base / "release.zip"
            nested_buffer = io.BytesIO()
            with zipfile.ZipFile(nested_buffer, "w", compression=zipfile.ZIP_DEFLATED) as nested:
                nested.writestr("payload.txt", "plain text\n")
            with zipfile.ZipFile(release_zip, "w", compression=zipfile.ZIP_DEFLATED) as outer:
                outer.writestr("nested.zip", nested_buffer.getvalue())

            with self.assertRaisesRegex(ValueError, "review secret scan coverage incomplete"):
                create_review_job(root, subject_path=release_zip, prompt="Review hard.", transport="manual")

    def test_review_secret_scan_rejects_high_compression_ratio_zip_member(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            release_zip = base / "release.zip"
            with zipfile.ZipFile(release_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("huge.txt", "A" * 1_000_000)

            with self.assertRaisesRegex(ValueError, "review secret scan coverage incomplete"):
                create_review_job(root, subject_path=release_zip, prompt="Review hard.", transport="manual")

    def test_review_secret_scan_reads_zip_archive_comment(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            release_zip = base / "release.zip"
            with zipfile.ZipFile(release_zip, "w") as zf:
                zf.writestr("README.md", "# Release\n")
                zf.comment = ('sk-' + ("C" * 32)).encode("utf-8")

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(root, subject_path=release_zip, prompt="Review hard.", transport="manual")

    def test_review_secret_scan_rejects_clean_zip_archive_comment(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            release_zip = base / "release.zip"
            with zipfile.ZipFile(release_zip, "w") as zf:
                zf.writestr("README.md", "# Release\n")
                zf.comment = b"ordinary archive metadata"

            with self.assertRaisesRegex(ValueError, "review secret scan coverage incomplete"):
                create_review_job(root, subject_path=release_zip, prompt="Review hard.", transport="manual")

    def test_review_secret_scan_blocks_generated_request_metadata(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "secret scan blocked review artifact"):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                    model="sk-" + ("M" * 32),
                )
            self.assertEqual(list((root / "exports" / "review_bridge").glob("jobs/*")), [])

    def test_review_prepare_rejects_subject_inside_continuum_root(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = root / "subject"
            subject.mkdir(parents=True)
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "subject must not be inside the Continuum root"):
                create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

    def test_review_prepare_rejects_custom_continuumignore_omissions(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            root.mkdir()
            (root / ".continuumignore").write_text("critical.py\n", encoding="utf-8")
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            (subject / "critical.py").write_text("print('important')\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "custom \\.continuumignore exclusions"):
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
                ingest_reserved_response(root, job, "not json")

            status = review_job_status(root, job_id=job["job_id"])
            self.assertEqual(status["status"], "review_failed")
            self.assertTrue(Path(status["raw_response_uri"]).exists())
            self.assertIn("responses", Path(status["raw_response_uri"]).parts)
            self.assertTrue(Path(status["last_attempt_uri"]).exists())

    def test_manual_ingest_rejects_inline_or_unreserved_response(self) -> None:
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

            with self.assertRaisesRegex(ValueError, "reserved response path"):
                ingest_review_result(root, job_id=job["job_id"], content=json.dumps(payload))

            external = base / "external-response.json"
            external.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "current reserved browser attempt"):
                ingest_review_result(root, job_id=job["job_id"], result_path=external)

            missing_external = base / "missing-response.json"
            with self.assertRaisesRegex(ValueError, "current reserved browser attempt"):
                ingest_review_result(root, job_id=job["job_id"], result_path=missing_external)

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
                    ingest_reserved_response(root, job, content)

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

            receipt = ingest_reserved_response(root, job, json.dumps(payload))

            self.assertIn("responses", Path(receipt["raw_response_uri"]).parts)
            self.assertEqual(Path(receipt["findings_uri"]).name, "findings-001.json")
            self.assertEqual(Path(receipt["ingest_receipt_uri"]).name, "ingest-001.json")
            with self.assertRaisesRegex(ValueError, "already has an accepted ingest"):
                ingest_reserved_response(root, job, json.dumps(payload))

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

    def test_subject_packaging_refuses_symlink_escape(self) -> None:
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

            with self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "strict review prep refuses incomplete coverage",
            ):
                create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

    def test_mcp_review_tools_are_registered_and_work(self) -> None:
        self.assertIn("continuum_review_prepare", TOOLS)
        self.assertIn("continuum_review_ingest", TOOLS)
        self.assertIn("continuum_review_status", TOOLS)
        self.assertIn("continuum_review_browser_attempt_start", TOOLS)

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
                attempt = call_tool("continuum_review_browser_attempt_start", {"root": str(root), "job_id": job["job_id"]})
                Path(attempt["response_uri"]).write_text(json.dumps(payload), encoding="utf-8")
                receipt = call_tool(
                    "continuum_review_ingest",
                    {"root": str(root), "job_id": job["job_id"], "result_path": attempt["response_uri"]},
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
