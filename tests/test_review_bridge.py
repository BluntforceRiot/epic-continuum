from __future__ import annotations

import json
import gzip
import hashlib
import http.server
import io
import os
import signal
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
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
from continuum import cli as cli_module
from continuum import mcp_server as mcp_server_module
from continuum.core.operations import _verify_artifact_ledger, restore_drill
from continuum.core.store import connect, record_artifact, semantic_integrity_report, snapshot
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


def bounded_process_result(
    stdout: str | bytes = b"",
    stderr: str | bytes = b"",
    *,
    returncode: int = 0,
    timed_out: bool = False,
    output_exceeded: bool = False,
    observed_stdout_bytes: int | None = None,
    observed_stderr_bytes: int | None = None,
) -> review_bridge_module.BoundedProcessResult:
    stdout_bytes = stdout.encode("utf-8") if isinstance(stdout, str) else stdout
    stderr_bytes = stderr.encode("utf-8") if isinstance(stderr, str) else stderr
    stdout_seen = len(stdout_bytes) if observed_stdout_bytes is None else observed_stdout_bytes
    stderr_seen = len(stderr_bytes) if observed_stderr_bytes is None else observed_stderr_bytes
    return review_bridge_module.BoundedProcessResult(
        returncode=returncode,
        stdout=stdout_bytes,
        stderr=stderr_bytes,
        timed_out=timed_out,
        output_exceeded=output_exceeded,
        observed_output_bytes=stdout_seen + stderr_seen,
        observed_stdout_bytes=stdout_seen,
        observed_stderr_bytes=stderr_seen,
    )


def wait_for_posix_process_termination(pid: int, *, timeout_seconds: float = 2.0) -> bool:
    """Treat a reparented zombie as terminated while its init process reaps it."""
    process_stat = Path(f"/proc/{pid}/stat")
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            raw = process_stat.read_text(encoding="utf-8")
        except FileNotFoundError:
            return True
        except OSError:
            return False
        suffix = raw.rsplit(")", 1)
        if len(suffix) == 2:
            fields = suffix[1].strip().split()
            if fields and fields[0] in {"Z", "X"}:
                return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.01)


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


def artifact_rows(root: Path) -> list[tuple[object, ...]]:
    conn = connect(root)
    try:
        return [tuple(row) for row in conn.execute("SELECT * FROM artifacts ORDER BY id")]
    finally:
        conn.close()


def stage_completed_review_job_for_recovery(
    root: Path,
    job: dict,
) -> tuple[Path, list[dict]]:
    job_id = str(job["job_id"])
    job_dir = Path(job["job_dir"])
    prefix = review_bridge_module._root_uri(root, job_dir) + "/"
    conn = connect(root)
    try:
        rows = list(
            conn.execute(
                "SELECT * FROM artifacts WHERE uri >= ? AND uri < ? ORDER BY uri, id",
                (prefix, prefix[:-1] + "0"),
            ).fetchall()
        )
        self_contained = [
            (
                row,
                str(row["uri"])[len(prefix) :],
            )
            for row in rows
        ]
        conn.execute(
            "DELETE FROM artifacts WHERE uri >= ? AND uri < ?",
            (prefix, prefix[:-1] + "0"),
        )
        conn.commit()
    finally:
        conn.close()
    staging_dir = review_bridge_module.review_bridge_root(root) / "tmp" / job_id
    staging_dir.parent.mkdir(parents=True, exist_ok=True)
    job_dir.rename(staging_dir)
    entries = [
        (
            staging_dir.joinpath(*Path(relative).parts),
            str(row["kind"]),
            bool(row["immutable"]),
        )
        for row, relative in self_contained
    ]
    return (
        staging_dir,
        review_bridge_module._review_prepare_artifact_plan(
            staging_dir,
            job_id,
            entries,
        ),
    )


def replace_review_request_artifact(
    root: Path,
    *,
    job_id: str,
    request_path: Path,
) -> None:
    request_bytes = request_path.read_bytes()
    request_uri = review_bridge_module._root_uri(root, request_path)
    conn = connect(root)
    try:
        deleted = conn.execute(
            "DELETE FROM artifacts WHERE kind = 'review_request' AND uri = ?",
            (request_uri,),
        )
        if deleted.rowcount != 1:
            raise AssertionError("legacy fixture lacks one exact review_request row")
        record_artifact(
            conn,
            kind="review_request",
            uri=request_uri,
            sha256=hashlib.sha256(request_bytes).hexdigest(),
            size_bytes=len(request_bytes),
            source_type="review_bridge",
            trust_level="local_generated",
            metadata={"job_id": job_id},
            immutable=True,
        )
        conn.commit()
    finally:
        conn.close()


def non_phase_artifact_rows(root: Path) -> list[tuple[object, ...]]:
    return [row for row in artifact_rows(root) if row[1] != "review_phase_envelope"]


def pending_derived_paths(root: Path, job: dict, stored_status: dict) -> tuple[Path, ...]:
    return tuple(
        review_bridge_module._resolve_job_reference(
            root,
            str(job["job_id"]),
            key,
            stored_status[key],
            evidence=stored_status,
        )
        for key in (
            "pending_response_json_uri",
            "pending_findings_uri",
            "pending_findings_markdown_uri",
            "pending_ingest_receipt_uri",
        )
    )


def strip_phase_authority_for_legacy_fixture(root: Path, job_dir: Path) -> None:
    """Turn a current test job into a pre-phase legacy fixture explicitly."""
    conn = connect(root)
    try:
        conn.execute("DROP TRIGGER IF EXISTS protect_review_phase_artifact_updates")
        conn.execute("DROP TRIGGER IF EXISTS protect_review_phase_artifact_deletes")
        conn.execute("DELETE FROM artifacts WHERE kind = 'review_phase_envelope'")
        conn.commit()
    finally:
        conn.close()
    for path in (job_dir / "receipts").glob("phase-*.json"):
        path.unlink()


def make_link_like_directory(testcase: unittest.TestCase, link: Path, target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            testcase.skipTest(f"junction creation unavailable: {completed.stdout} {completed.stderr}")
        return
    try:
        link.symlink_to(target, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        testcase.skipTest(f"directory symlinks unavailable: {exc}")


class CommitThenRaiseConnection:
    """SQLite proxy that reports failure after one durable marker retirement."""

    def __init__(self, connection: object) -> None:
        self._connection = connection
        self._raise_after_commit = False
        self.raised = False

    def execute(self, sql: str, *args: object, **kwargs: object) -> object:
        result = self._connection.execute(sql, *args, **kwargs)  # type: ignore[attr-defined]
        if (
            sql.lstrip().upper().startswith("DELETE FROM ARTIFACTS")
            and review_bridge_module.REVIEW_PREPARE_PUBLICATION_MARKER_KIND
            in repr(args)
        ):
            self._raise_after_commit = True
        return result

    def commit(self) -> None:
        self._connection.commit()  # type: ignore[attr-defined]
        if self._raise_after_commit and not self.raised:
            self.raised = True
            raise RuntimeError("injected ambiguous post-commit failure")

    def __getattr__(self, name: str) -> object:
        return getattr(self._connection, name)


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

    def test_non_git_subject_mutation_after_snapshot_prevents_publication(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            target = subject / "app.py"
            target.write_text('VERSION = "old"\n', encoding="utf-8")
            original_copy = review_bridge_module._copy_snapshot_files

            def copy_then_mutate(
                root_arg: Path,
                subject_arg: Path,
                files: list[Path],
                snapshot_subject: Path,
                **kwargs: object,
            ) -> list[Path]:
                copied = original_copy(
                    root_arg,
                    subject_arg,
                    files,
                    snapshot_subject,
                    **kwargs,
                )
                target.write_text('VERSION = "new"\n', encoding="utf-8")
                return copied

            with patch.object(
                review_bridge_module,
                "_copy_snapshot_files",
                side_effect=copy_then_mutate,
            ), self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "changed after its snapshot",
            ):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                )

            self.assertEqual(target.read_text(encoding="utf-8"), 'VERSION = "new"\n')
            jobs_dir = root / "exports" / "review_bridge" / "jobs"
            self.assertFalse(jobs_dir.exists() and any(jobs_dir.iterdir()))
            self.assertFalse(any(root.rglob(review_bridge_module.REVIEW_CAPSULE_NAME)))

    def test_non_git_subject_mutation_after_capsule_prevents_publication(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            target = subject / "app.py"
            target.write_text('VERSION = "old"\n', encoding="utf-8")
            original_write_capsule = review_bridge_module._write_review_capsule

            def write_capsule_then_mutate(
                *args: object,
                **kwargs: object,
            ) -> tuple[Path, str]:
                result = original_write_capsule(*args, **kwargs)  # type: ignore[arg-type]
                target.write_text('VERSION = "new"\n', encoding="utf-8")
                return result

            with patch.object(
                review_bridge_module,
                "_write_review_capsule",
                side_effect=write_capsule_then_mutate,
            ), self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "changed after its snapshot",
            ):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                )

            self.assertEqual(target.read_text(encoding="utf-8"), 'VERSION = "new"\n')
            bridge_root = root / "exports" / "review_bridge"
            self.assertFalse(
                (bridge_root / "jobs").exists()
                and any((bridge_root / "jobs").iterdir())
            )
            self.assertFalse(any(bridge_root.rglob(review_bridge_module.REVIEW_CAPSULE_NAME)))

    def test_empty_directories_are_bound_across_review_artifacts_and_currentness(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            (subject / "empty" / "deeper").mkdir(parents=True)
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")

            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )

            manifest = json.loads(
                Path(job["subject_manifest_uri"]).read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["directories"], ["empty", "empty/deeper"])
            self.assertEqual(job["packet_coverage"]["manifest_directory_count"], 2)
            self.assertIn(
                "- Directory entries: 2",
                Path(job["packet_uri"]).read_text(encoding="utf-8"),
            )
            snapshot_subject = Path(job["job_dir"]) / "snapshot" / "subject"
            self.assertTrue((snapshot_subject / "empty" / "deeper").is_dir())
            with zipfile.ZipFile(job["subject_archive_uri"]) as archive:
                self.assertIn("empty/", archive.namelist())
                self.assertIn("empty/deeper/", archive.namelist())
            with zipfile.ZipFile(job["review_capsule_uri"]) as capsule:
                self.assertIn("subject/", capsule.namelist())
                self.assertIn("subject/empty/", capsule.namelist())
                self.assertIn("subject/empty/deeper/", capsule.namelist())
            integrity = review_bridge_module.review_bridge_integrity_report(
                root,
                job_id=job["job_id"],
            )
            self.assertTrue(integrity["ok"], integrity)

            (subject / "empty" / "deeper").rmdir()
            self.assertFalse(review_check_current(root, job_id=job["job_id"])["current"])

            (snapshot_subject / "empty" / "deeper").rmdir()
            tampered = review_bridge_module.review_bridge_integrity_report(
                root,
                job_id=job["job_id"],
            )
            self.assertFalse(tampered["ok"])
            reasons = {
                finding.get("reason")
                for findings in tampered.get("samples", {}).values()
                for finding in findings
            }
            self.assertIn("subject_manifest_directory_set_mismatch", reasons)

    def test_pure_empty_directory_prepares_a_bound_empty_archive(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "empty-subject"
            subject.mkdir()

            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review the empty boundary.",
                transport="manual",
            )

            manifest = json.loads(
                Path(job["subject_manifest_uri"]).read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["files"], [])
            self.assertEqual(manifest["directories"], [])
            self.assertEqual(job["packet_coverage"]["manifest_directory_count"], 0)
            with zipfile.ZipFile(job["subject_archive_uri"]) as archive:
                self.assertEqual(archive.namelist(), [])
            with zipfile.ZipFile(job["review_capsule_uri"]) as capsule:
                self.assertIn("subject/", capsule.namelist())
            self.assertTrue(review_check_current(root, job_id=job["job_id"])["current"])

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
            replace_review_request_artifact(
                root,
                job_id=job["job_id"],
                request_path=request_path,
            )
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
            (root / Path(request["packet_uri"])).write_text("# Mutated packet\n", encoding="utf-8")

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

    def test_browser_attempt_rejects_link_like_mutable_directories_without_side_effects(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")

            for subdirectory in ("attempts", "responses"):
                with self.subTest(subdirectory=subdirectory):
                    root = base / f"continuum-{subdirectory}"
                    job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
                    job_dir = Path(job["job_dir"])
                    linked = job_dir / subdirectory
                    linked.rmdir()
                    external = base / f"external-{subdirectory}"
                    external.mkdir()
                    (external / "attempt-001.json").write_text("OUTSIDE ONE", encoding="utf-8")
                    (external / "attempt-003.json").write_text("SENSITIVE OUTSIDE CONTENT", encoding="utf-8")
                    external_before = {path.name: path.read_bytes() for path in external.iterdir()}
                    status_before = (job_dir / review_bridge_module.REVIEW_STATUS_NAME).read_bytes()
                    handoff_before = (job_dir / review_bridge_module.REVIEW_BROWSER_HANDOFF_NAME).read_bytes()
                    internal_before = sorted(
                        path.relative_to(job_dir).as_posix()
                        for path in job_dir.rglob("*")
                        if path.is_file()
                        and not path.is_symlink()
                        and path.relative_to(job_dir).parts[0] != subdirectory
                    )
                    make_link_like_directory(self, linked, external)
                    try:
                        report = review_bridge_module.review_bridge_integrity_report(root)
                        with self.assertRaisesRegex(ValueError, "link-like"):
                            review_browser_attempt_start(root, job_id=job["job_id"])

                        self.assertFalse(report["ok"])
                        self.assertGreater(report["checks"]["review_bridge_link_like_paths"], 0)
                        self.assertEqual(external_before, {path.name: path.read_bytes() for path in external.iterdir()})
                        self.assertEqual(status_before, (job_dir / review_bridge_module.REVIEW_STATUS_NAME).read_bytes())
                        self.assertEqual(handoff_before, (job_dir / review_bridge_module.REVIEW_BROWSER_HANDOFF_NAME).read_bytes())
                        self.assertEqual(
                            internal_before,
                            sorted(
                                path.relative_to(job_dir).as_posix()
                                for path in job_dir.rglob("*")
                                if path.is_file()
                                and not path.is_symlink()
                                and path.relative_to(job_dir).parts[0] != subdirectory
                            ),
                        )
                    finally:
                        if linked.is_symlink():
                            linked.unlink()
                        elif os.path.lexists(linked):
                            os.rmdir(linked)

    def test_gapped_attempt_ledger_fails_before_mutation_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            first = review_browser_attempt_start(root, job_id=job["job_id"])
            job_dir = Path(job["job_dir"])
            gap_path = job_dir / "attempts" / "attempt-003.json"
            gap_path.write_text("SENSITIVE EXISTING ATTEMPT", encoding="utf-8")
            gap_before = gap_path.read_bytes()
            files_before = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file() and not path.is_symlink()
            }

            with self.assertRaisesRegex(ValueError, "not contiguous"):
                review_browser_attempt_start(root, job_id=job["job_id"])

            self.assertEqual(gap_path.read_bytes(), gap_before)
            self.assertEqual(
                files_before,
                {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file() and not path.is_symlink()
                },
            )
            current = json.loads(Path(first["attempt_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(current["status"], "browser_attempt_reserved")
            self.assertNotIn("superseded_by_attempt", current)
            self.assertFalse(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertFalse(semantic_integrity_report(root)["ok"])

    def test_cross_class_status_pointer_is_rejected_without_poisoning_frozen_restore(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            attempt = review_browser_attempt_start(root, job_id=job["job_id"])
            clean_snapshot = snapshot(root, reason="before_bad_review_pointer")
            job_dir = Path(job["job_dir"])
            request_path = Path(job["request_uri"])
            status_path = Path(job["status_uri"])
            request = json.loads(request_path.read_text(encoding="utf-8"))
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["browser_attempt_uri"] = request["packet_uri"]
            status_path.write_text(json.dumps(status), encoding="utf-8")
            packet_path = Path(job["packet_uri"])
            packet_before = packet_path.read_bytes()
            status_before = status_path.read_bytes()
            files_before = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file() and not path.is_symlink()
            }

            with self.assertRaisesRegex(ValueError, "path class"):
                review_browser_attempt_start(root, job_id=job["job_id"])

            report = review_bridge_module.review_bridge_integrity_report(root)
            semantic = semantic_integrity_report(root)
            self.assertFalse(report["ok"])
            self.assertGreater(report["checks"]["review_bridge_invalid_references"], 0)
            self.assertFalse(semantic["ok"])
            self.assertGreater(semantic["checks"]["review_bridge_invalid_references"], 0)
            self.assertEqual(packet_path.read_bytes(), packet_before)
            self.assertEqual(status_path.read_bytes(), status_before)
            self.assertEqual(
                files_before,
                {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file() and not path.is_symlink()
                },
            )
            self.assertEqual(len(list((job_dir / "responses").glob("response-*.raw.txt"))), 1)
            self.assertEqual(Path(attempt["attempt_uri"]).read_text(encoding="utf-8"), files_before["attempts/attempt-001.json"].decode("utf-8"))
            with self.assertRaisesRegex(ValueError, "semantic integrity"):
                snapshot(root, reason="bad_review_pointer_must_fail")
            restored = restore_drill(
                root,
                snapshot_uri=clean_snapshot["snapshot_uri"],
                verify_recent_proof_packs=0,
            )
            self.assertTrue(restored["ok"], restored["checks"])
            self.assertTrue(restored["semantic_integrity"]["ok"])
            restored_root = Path(restored["drill_root"])
            restored_status = review_job_status(restored_root, job_id=job["job_id"])
            self.assertEqual(
                Path(restored_status["browser_attempt_uri"]).name,
                "attempt-001.json",
            )
            self.assertTrue(
                review_bridge_module.review_bridge_integrity_report(restored_root)["ok"]
            )

    def test_incomplete_current_browser_tuple_blocks_ingest_and_recovery_gates(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            for missing_key in (
                "browser_attempt_uri",
                "browser_attempt_sha256",
                "last_attempt_sha256",
            ):
                with self.subTest(missing_key=missing_key):
                    root = base / f"continuum-{missing_key}"
                    job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
                    request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
                    attempt = review_browser_attempt_start(root, job_id=job["job_id"])
                    runtime_status = review_job_status(root, job_id=job["job_id"])
                    response_path = Path(attempt["response_uri"])
                    response_path.write_text(
                        json.dumps(valid_review_payload({**request, **runtime_status})),
                        encoding="utf-8",
                    )
                    status_path = Path(job["status_uri"])
                    stored_status = json.loads(status_path.read_text(encoding="utf-8"))
                    stored_status.pop(missing_key)
                    status_path.write_text(json.dumps(stored_status), encoding="utf-8")
                    job_dir = Path(job["job_dir"])
                    before = {
                        path.relative_to(job_dir).as_posix(): path.read_bytes()
                        for path in job_dir.rglob("*")
                        if path.is_file() and not path.is_symlink()
                    }

                    with self.assertRaisesRegex(ValueError, "lifecycle is invalid"):
                        ingest_review_result(root, job_id=job["job_id"], result_path=response_path)

                    report = review_bridge_module.review_bridge_integrity_report(root)
                    semantic = semantic_integrity_report(root)
                    self.assertFalse(report["ok"])
                    self.assertGreater(report["checks"]["review_bridge_malformed_records"], 0)
                    self.assertFalse(semantic["ok"])
                    self.assertEqual(
                        before,
                        {
                            path.relative_to(job_dir).as_posix(): path.read_bytes()
                            for path in job_dir.rglob("*")
                            if path.is_file() and not path.is_symlink()
                        },
                    )
                    with self.assertRaisesRegex(ValueError, "semantic integrity"):
                        snapshot(root, reason="incomplete_browser_attempt_tuple")

    def test_manual_run_rejects_pending_browser_attempt_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            review_browser_attempt_start(root, job_id=job["job_id"])
            job_dir = Path(job["job_dir"])
            before = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file() and not path.is_symlink()
            }

            with self.assertRaisesRegex(ValueError, "current reserved browser attempt"):
                review_bridge_module.run_review_job(root, job_id=job["job_id"], transport="manual")

            self.assertEqual(
                before,
                {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file() and not path.is_symlink()
                },
            )
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_pending_current_and_last_attempt_bindings_must_match(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            first = review_browser_attempt_start(root, job_id=job["job_id"])
            review_browser_attempt_start(root, job_id=job["job_id"])
            first_path = Path(first["attempt_uri"])
            status_path = Path(job["status_uri"])
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["last_attempt_uri"] = review_bridge_module._job_reference_uri(
                root,
                job["job_id"],
                first_path,
                key="last_attempt_uri",
            )
            status["last_attempt_sha256"] = hashlib.sha256(first_path.read_bytes()).hexdigest()
            status_path.write_text(json.dumps(status), encoding="utf-8")
            job_dir = Path(job["job_dir"])
            before = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file() and not path.is_symlink()
            }

            with self.assertRaisesRegex(ValueError, "current and last|terminal status drifted"):
                review_browser_attempt_start(root, job_id=job["job_id"])

            self.assertFalse(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertFalse(semantic_integrity_report(root)["ok"])
            self.assertEqual(
                before,
                {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file() and not path.is_symlink()
                },
            )

    def test_browser_attempt_rewrite_requires_bound_identity_and_hash(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            attempt = review_browser_attempt_start(root, job_id=job["job_id"])
            attempt_path = Path(attempt["attempt_uri"])
            attempt_record = json.loads(attempt_path.read_text(encoding="utf-8"))
            attempt_record["transport"] = "manual"
            attempt_path.write_text(json.dumps(attempt_record), encoding="utf-8")
            changed_hash = hashlib.sha256(attempt_path.read_bytes()).hexdigest()
            status_path = Path(job["status_uri"])
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["browser_attempt_sha256"] = changed_hash
            status["last_attempt_sha256"] = changed_hash
            status_path.write_text(json.dumps(status), encoding="utf-8")
            job_dir = Path(job["job_dir"])
            before = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file() and not path.is_symlink()
            }

            with self.assertRaisesRegex(ValueError, "identity binding"):
                review_browser_attempt_start(root, job_id=job["job_id"])

            self.assertEqual(
                before,
                {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file() and not path.is_symlink()
                },
            )

    def test_review_bridge_integrity_report_fails_boundedly_on_malformed_status(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            status_path = Path(job["status_uri"])
            clean_status = status_path.read_bytes()

            malformed_count = json.loads(clean_status)
            malformed_count["attempt_count"] = True
            status_path.write_text(json.dumps(malformed_count), encoding="utf-8")
            count_report = review_bridge_module.review_bridge_integrity_report(root)
            self.assertFalse(count_report["ok"])
            self.assertGreater(count_report["checks"]["review_bridge_malformed_records"], 0)

            traversal = json.loads(clean_status)
            traversal["browser_handoff_uri"] = (
                "../../exports/review_bridge/jobs/"
                f"{job['job_id']}/browser-handoff.md"
            )
            status_path.write_text(json.dumps(traversal), encoding="utf-8")
            traversal_report = review_bridge_module.review_bridge_integrity_report(root)
            self.assertFalse(traversal_report["ok"])
            self.assertGreater(traversal_report["checks"]["review_bridge_invalid_references"], 0)

            status_path.write_bytes(b"{" + b" " * (review_bridge_module.REVIEW_INTEGRITY_MAX_RECORD_BYTES + 1))
            oversized_report = review_bridge_module.review_bridge_integrity_report(root)
            self.assertFalse(oversized_report["ok"])
            self.assertGreater(oversized_report["checks"]["review_bridge_malformed_records"], 0)

    def test_noncanonical_attempt_numbers_fail_integrity_and_snapshot(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            attempts_dir = Path(job["job_dir"]) / "attempts"
            for name in ("attempt-000.json", "attempt-01.json", "attempt-0001.json"):
                (attempts_dir / name).write_text(
                    json.dumps(
                        {
                            "schema": "epic-continuum.review-attempt/1",
                            "job_id": job["job_id"],
                            "attempt": int(name.removeprefix("attempt-").removesuffix(".json")),
                            "transport": "browser",
                        }
                    ),
                    encoding="utf-8",
                )

            report = review_bridge_module.review_bridge_integrity_report(root)
            semantic = semantic_integrity_report(root)
            self.assertFalse(report["ok"])
            self.assertEqual(report["checks"]["review_bridge_invalid_attempt_records"], 3)
            self.assertFalse(semantic["ok"])
            with self.assertRaisesRegex(ValueError, "semantic integrity"):
                snapshot(root, reason="noncanonical_attempt_numbers")

    def test_internal_reference_target_kind_must_match_declared_path_class(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")

            file_root = base / "file-class-root"
            file_job = create_review_job(
                file_root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )
            file_job_dir = Path(file_job["job_dir"])
            false_file = file_job_dir / "findings" / "findings-001.json"
            false_file.mkdir()
            file_status_path = Path(file_job["status_uri"])
            file_status = json.loads(file_status_path.read_text(encoding="utf-8"))
            file_status["findings_uri"] = review_bridge_module._job_reference_uri(
                file_root,
                file_job["job_id"],
                false_file,
                key="findings_uri",
            )
            file_status_path.write_text(json.dumps(file_status), encoding="utf-8")
            file_report = review_bridge_module.review_bridge_integrity_report(file_root)
            self.assertFalse(file_report["ok"])
            self.assertGreater(file_report["checks"]["review_bridge_invalid_references"], 0)

            directory_root = base / "directory-class-root"
            directory_job = create_review_job(
                directory_root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )
            snapshot_subject = Path(directory_job["job_dir"]) / "snapshot" / "subject"
            moved_subject = snapshot_subject.with_name("subject-backup")
            snapshot_subject.rename(moved_subject)
            snapshot_subject.write_text("not a directory", encoding="utf-8")
            directory_report = review_bridge_module.review_bridge_integrity_report(directory_root)
            self.assertFalse(directory_report["ok"])
            self.assertGreater(directory_report["checks"]["review_bridge_invalid_references"], 0)

    def test_tampered_completed_attempt_blocks_semantic_and_snapshot_gates(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            attempt = review_browser_attempt_start(root, job_id=job["job_id"])
            response_path = Path(attempt["response_uri"])
            response_path.write_text(
                json.dumps(valid_review_payload({**request, **review_job_status(root, job_id=job["job_id"])})),
                encoding="utf-8",
            )
            ingest_review_result(root, job_id=job["job_id"], result_path=response_path)
            self.assertTrue(semantic_integrity_report(root)["ok"])
            completed_attempt = Path(review_job_status(root, job_id=job["job_id"])["last_attempt_uri"])
            completed_attempt.write_text("{}", encoding="utf-8")

            report = review_bridge_module.review_bridge_integrity_report(root)
            semantic = semantic_integrity_report(root)
            self.assertFalse(report["ok"])
            self.assertGreater(report["checks"]["review_bridge_attempt_hash_mismatches"], 0)
            self.assertFalse(semantic["ok"])
            with self.assertRaisesRegex(ValueError, "semantic integrity"):
                snapshot(root, reason="tampered_completed_review_attempt")

    def test_tampered_superseded_attempt_is_bound_by_immutable_finalization_receipt(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            first = review_browser_attempt_start(root, job_id=job["job_id"])
            review_browser_attempt_start(root, job_id=job["job_id"])
            first_path = Path(first["attempt_uri"])
            receipt_path = Path(job["job_dir"]) / "attempt-receipts" / "attempt-001.json"

            self.assertTrue(receipt_path.is_file())
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(_verify_artifact_ledger(root)["ok"])
            superseded = json.loads(first_path.read_text(encoding="utf-8"))
            superseded["started_at"] = "2000-01-01T00:00:00+00:00"
            first_path.write_text(json.dumps(superseded), encoding="utf-8")

            report = review_bridge_module.review_bridge_integrity_report(root)
            self.assertFalse(report["ok"])
            self.assertGreater(report["checks"]["review_bridge_attempt_hash_mismatches"], 0)
            self.assertFalse(semantic_integrity_report(root)["ok"])
            with self.assertRaisesRegex(ValueError, "semantic integrity"):
                snapshot(root, reason="tampered_superseded_review_attempt")

    def test_status_domain_and_ingest_coherence_tampering_fail_closed(self) -> None:
        cases = (
            ("accepted_bool", {"accepted_ingest_count": True}),
            ("accepted_negative", {"accepted_ingest_count": -1}),
            ("accepted_too_large", {"accepted_ingest_count": 2}),
            ("accepted_string", {"accepted_ingest_count": "not-an-int"}),
            ("prepared_with_accepted", {"accepted_ingest_count": 1}),
            ("ingested_without_acceptance", {"status": "ingested", "accepted_ingest_count": 0}),
            ("ingesting_without_pending_binding", {"status": "ingesting", "accepted_ingest_count": 0}),
            ("unknown_status", {"status": "not_a_state"}),
        )
        for label, updates in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
                job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
                status_path = Path(job["status_uri"])
                status = json.loads(status_path.read_text(encoding="utf-8"))
                status.update(updates)
                status_path.write_text(json.dumps(status), encoding="utf-8")

                with self.assertRaisesRegex(ValueError, "lifecycle"):
                    review_job_status(root, job_id=job["job_id"])
                self.assertFalse(review_bridge_module.review_bridge_integrity_report(root)["ok"])
                self.assertFalse(semantic_integrity_report(root)["ok"])
                with self.assertRaisesRegex(ValueError, "semantic integrity"):
                    snapshot(root, reason=f"invalid_review_status_{label}")

    def test_attempt_count_requires_last_binding_and_contiguous_attempt_files(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            first = review_browser_attempt_start(root, job_id=job["job_id"])
            review_browser_attempt_start(root, job_id=job["job_id"])
            Path(first["attempt_uri"]).unlink()

            report = review_bridge_module.review_bridge_integrity_report(root)
            self.assertFalse(report["ok"])
            self.assertTrue(
                any(
                    sample.get("reason") == "attempt_sequence_not_contiguous"
                    for sample in report["samples"]["review_bridge_invalid_attempt_records"]
                )
            )
            self.assertFalse(semantic_integrity_report(root)["ok"])
            with self.assertRaisesRegex(ValueError, "semantic integrity"):
                snapshot(root, reason="missing_prior_review_attempt")

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            review_browser_attempt_start(root, job_id=job["job_id"])
            status_path = Path(job["status_uri"])
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status.pop("last_attempt_uri")
            status.pop("last_attempt_sha256")
            status_path.write_text(json.dumps(status), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "positive attempt_count"):
                review_job_status(root, job_id=job["job_id"])
            self.assertFalse(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertFalse(semantic_integrity_report(root)["ok"])

    def test_current_reserved_attempt_requires_exact_reserved_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            reserved = review_browser_attempt_start(root, job_id=job["job_id"])
            attempt_path = Path(reserved["attempt_uri"])
            status_path = Path(job["status_uri"])
            attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
            attempt["status"] = "ingested"
            attempt["finished_at"] = "2026-07-13T00:00:00+00:00"
            attempt_path.write_text(json.dumps(attempt), encoding="utf-8")
            changed_hash = hashlib.sha256(attempt_path.read_bytes()).hexdigest()
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["browser_attempt_sha256"] = changed_hash
            status["last_attempt_sha256"] = changed_hash
            status_path.write_text(json.dumps(status), encoding="utf-8")
            before = {
                path.relative_to(Path(job["job_dir"])).as_posix(): path.read_bytes()
                for path in Path(job["job_dir"]).rglob("*")
                if path.is_file() and not path.is_symlink()
            }

            with self.assertRaisesRegex(ValueError, "identity binding"):
                review_browser_attempt_start(root, job_id=job["job_id"])
            self.assertEqual(
                before,
                {
                    path.relative_to(Path(job["job_dir"])).as_posix(): path.read_bytes()
                    for path in Path(job["job_dir"]).rglob("*")
                    if path.is_file() and not path.is_symlink()
                },
            )
            report = review_bridge_module.review_bridge_integrity_report(root)
            self.assertFalse(report["ok"])
            self.assertGreater(report["checks"]["review_bridge_invalid_attempt_records"], 0)
            self.assertFalse(semantic_integrity_report(root)["ok"])

    def test_request_identity_and_required_status_are_rejected_without_job_mutation(self) -> None:
        for label in ("request_identity", "missing_status"):
            with self.subTest(label=label), tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
                job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
                if label == "request_identity":
                    request_path = Path(job["request_uri"])
                    request = json.loads(request_path.read_text(encoding="utf-8"))
                    request["job_id"] = "different_job"
                    request_path.write_text(json.dumps(request), encoding="utf-8")
                    expected_error = "request identity"
                else:
                    Path(job["status_uri"]).unlink()
                    expected_error = "status is missing"
                job_dir = Path(job["job_dir"])
                before = {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file() and not path.is_symlink()
                }

                with self.assertRaisesRegex(ValueError, expected_error):
                    review_browser_attempt_start(root, job_id=job["job_id"])
                self.assertEqual(
                    before,
                    {
                        path.relative_to(job_dir).as_posix(): path.read_bytes()
                        for path in job_dir.rglob("*")
                        if path.is_file() and not path.is_symlink()
                    },
                )
                self.assertFalse(review_bridge_module.review_bridge_integrity_report(root)["ok"])

    def test_explicit_single_attempt_legacy_upgrade_is_dry_runnable_and_bound(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            reserved = review_browser_attempt_start(root, job_id=job["job_id"])
            response_path = Path(reserved["response_uri"])
            response_path.write_text(
                json.dumps(valid_review_payload({**request, **review_job_status(root, job_id=job["job_id"])})),
                encoding="utf-8",
            )
            ingest_review_result(root, job_id=job["job_id"], result_path=response_path)
            job_dir = Path(job["job_dir"])
            strip_phase_authority_for_legacy_fixture(root, job_dir)
            attempt_path = job_dir / "attempts" / "attempt-001.json"
            receipt_path = job_dir / "attempt-receipts" / "attempt-001.json"
            receipt_path.unlink()
            conn = connect(root)
            try:
                conn.execute("DELETE FROM artifacts WHERE kind = 'review_attempt_receipt'")
                conn.commit()
            finally:
                conn.close()
            attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
            attempt.pop("schema")
            attempt.pop("job_id")
            for key in ("raw_response_uri", "response_uri", "findings_uri", "ingest_receipt_uri"):
                if attempt.get(key):
                    attempt[key] = str(root / str(attempt[key]))
            attempt_path.write_text(json.dumps(attempt), encoding="utf-8")
            status_path = Path(job["status_uri"])
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["last_attempt_uri"] = str(attempt_path)
            status.pop("last_attempt_sha256")
            status_path.write_text(json.dumps(status), encoding="utf-8")
            before = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file() and not path.is_symlink()
            }

            planned = review_bridge_module.upgrade_review_job_integrity(
                root,
                job_id=job["job_id"],
                dry_run=True,
            )
            self.assertTrue(planned["would_upgrade"])
            self.assertEqual(
                before,
                {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file() and not path.is_symlink()
                },
            )

            upgraded = review_bridge_module.upgrade_review_job_integrity(root, job_id=job["job_id"])

            self.assertTrue(upgraded["upgraded"])
            upgraded_attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
            self.assertEqual(upgraded_attempt["schema"], "epic-continuum.review-attempt/1")
            self.assertEqual(upgraded_attempt["job_id"], job["job_id"])
            self.assertTrue(receipt_path.is_file())
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])
            self.assertTrue(_verify_artifact_ledger(root)["ok"])
            self.assertTrue(snapshot(root, reason="upgraded_legacy_review_job")["snapshot_uri"])

    def test_legacy_multi_attempt_upgrade_is_rejected_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            review_browser_attempt_start(root, job_id=job["job_id"])
            second = review_browser_attempt_start(root, job_id=job["job_id"])
            Path(second["response_uri"]).write_text("not json", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "did not contain a JSON object"):
                ingest_review_result(root, job_id=job["job_id"], result_path=Path(second["response_uri"]))
            job_dir = Path(job["job_dir"])
            strip_phase_authority_for_legacy_fixture(root, job_dir)
            for receipt in (job_dir / "attempt-receipts").glob("attempt-*.json"):
                receipt.unlink()
            conn = connect(root)
            try:
                conn.execute("DELETE FROM artifacts WHERE kind = 'review_attempt_receipt'")
                conn.commit()
            finally:
                conn.close()
            for attempt_path in (job_dir / "attempts").glob("attempt-*.json"):
                attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
                attempt.pop("schema")
                attempt.pop("job_id")
                attempt_path.write_text(json.dumps(attempt), encoding="utf-8")
            status_path = Path(job["status_uri"])
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status.pop("last_attempt_sha256")
            status_path.write_text(json.dumps(status), encoding="utf-8")
            before = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file() and not path.is_symlink()
            }

            with self.assertRaisesRegex(ValueError, "multi-attempt"):
                review_bridge_module.upgrade_review_job_integrity(
                    root,
                    job_id=job["job_id"],
                    dry_run=True,
                )
            with self.assertRaisesRegex(ValueError, "multi-attempt"):
                review_bridge_module.upgrade_review_job_integrity(root, job_id=job["job_id"])
            self.assertEqual(
                before,
                {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file() and not path.is_symlink()
                },
            )
            self.assertFalse(review_bridge_module.review_bridge_integrity_report(root)["ok"])

            replacement = create_review_job(
                root,
                subject_path=subject,
                prompt="Replacement review job.",
                transport="manual",
            )
            rows_before_dry_run = artifact_rows(root)
            planned = review_bridge_module.quarantine_legacy_review_job(
                root,
                job_id=job["job_id"],
                replacement_job_id=replacement["job_id"],
                dry_run=True,
            )
            self.assertTrue(planned["would_quarantine"])
            self.assertFalse(planned["quarantined"])
            self.assertEqual(rows_before_dry_run, artifact_rows(root))
            self.assertEqual(
                before,
                {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file() and not path.is_symlink()
                },
            )

            quarantined = review_bridge_module.quarantine_legacy_review_job(
                root,
                job_id=job["job_id"],
                replacement_job_id=replacement["job_id"],
                dry_run=False,
                operation_id="op-legacy-quarantine",
            )

            self.assertTrue(quarantined["quarantined"])
            quarantine_receipt = json.loads(
                Path(quarantined["receipt_uri"]).read_text(encoding="utf-8")
            )
            self.assertNotIn("tree_inventory", quarantine_receipt)
            self.assertNotIn("artifact_bindings", quarantine_receipt)
            self.assertNotIn("accepted_integrity_findings", quarantine_receipt)
            self.assertEqual(
                quarantine_receipt["accepted_integrity_finding_count"],
                len(planned["accepted_integrity_findings"]),
            )
            self.assertEqual(
                review_job_status(root, job_id=job["job_id"])["status"],
                "quarantined_legacy",
            )
            integrity = review_bridge_module.review_bridge_integrity_report(root)
            self.assertTrue(integrity["ok"], integrity)
            self.assertEqual(
                [item["job_id"] for item in integrity["quarantined_jobs"]],
                [job["job_id"]],
            )
            self.assertTrue(semantic_integrity_report(root)["ok"])
            self.assertTrue(snapshot(root, reason="quarantined_legacy_review")["snapshot_uri"])
            for mutate in (
                lambda: review_bridge_module.upgrade_review_job_integrity(
                    root,
                    job_id=job["job_id"],
                ),
                lambda: review_browser_attempt_start(root, job_id=job["job_id"]),
                lambda: ingest_review_result(
                    root,
                    job_id=job["job_id"],
                    content="{}",
                ),
            ):
                with self.assertRaisesRegex(ValueError, "quarantined legacy evidence"):
                    mutate()

    def test_legacy_quarantine_DB_commit_reconstructs_receipt_and_detects_drift(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Quarantine retry\n", encoding="utf-8")
            legacy = create_review_job(
                root,
                subject_path=subject,
                prompt="Legacy review.",
                transport="manual",
            )
            review_browser_attempt_start(root, job_id=legacy["job_id"])
            second = review_browser_attempt_start(root, job_id=legacy["job_id"])
            Path(second["response_uri"]).write_text("not json", encoding="utf-8")
            with self.assertRaises(ValueError):
                ingest_review_result(
                    root,
                    job_id=legacy["job_id"],
                    result_path=Path(second["response_uri"]),
                )
            legacy_dir = Path(legacy["job_dir"])
            strip_phase_authority_for_legacy_fixture(root, legacy_dir)
            for receipt in (legacy_dir / "attempt-receipts").glob("attempt-*.json"):
                receipt.unlink()
            conn = connect(root)
            try:
                conn.execute("DELETE FROM artifacts WHERE kind = 'review_attempt_receipt'")
                conn.commit()
            finally:
                conn.close()
            for attempt_path in (legacy_dir / "attempts").glob("attempt-*.json"):
                attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
                attempt.pop("schema")
                attempt.pop("job_id")
                attempt_path.write_text(json.dumps(attempt), encoding="utf-8")
            status_path = Path(legacy["status_uri"])
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status.pop("last_attempt_sha256")
            status_path.write_text(json.dumps(status), encoding="utf-8")
            replacement = create_review_job(
                root,
                subject_path=subject,
                prompt="Replacement review.",
                transport="manual",
            )
            real_write = review_bridge_module._confined_write_text

            def interrupt_receipt_materialization(
                write_root: Path,
                write_job_id: str,
                path: Path | str,
                text: str,
                *,
                exclusive: bool = False,
            ) -> None:
                if Path(path).name == review_bridge_module.REVIEW_LEGACY_QUARANTINE_NAME:
                    raise KeyboardInterrupt
                real_write(
                    write_root,
                    write_job_id,
                    path,
                    text,
                    exclusive=exclusive,
                )

            with patch.object(
                review_bridge_module,
                "_confined_write_text",
                side_effect=interrupt_receipt_materialization,
            ), self.assertRaises(KeyboardInterrupt):
                review_bridge_module.quarantine_legacy_review_job(
                    root,
                    job_id=legacy["job_id"],
                    replacement_job_id=replacement["job_id"],
                    dry_run=False,
                    operation_id="op-quarantine-retry",
                )
            quarantine_path = (
                legacy_dir
                / "receipts"
                / review_bridge_module.REVIEW_LEGACY_QUARANTINE_NAME
            )
            self.assertFalse(quarantine_path.exists())

            recovered = review_bridge_module.quarantine_legacy_review_job(
                root,
                job_id=legacy["job_id"],
                replacement_job_id=replacement["job_id"],
                dry_run=False,
                operation_id="op-quarantine-retry-fresh-guard",
            )
            self.assertTrue(recovered["already_quarantined"])
            self.assertEqual(recovered["operation_id"], "op-quarantine-retry")
            self.assertTrue(quarantine_path.is_file())
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])

            status_path.write_bytes(status_path.read_bytes() + b" ")
            drifted = review_bridge_module.review_bridge_integrity_report(root)
            self.assertFalse(drifted["ok"])
            self.assertTrue(
                any(
                    sample.get("reason") == "legacy_quarantine_binding_invalid"
                    for sample in drifted["samples"]["review_bridge_malformed_records"]
                )
            )
            with self.assertRaisesRegex(ValueError, "snapshot preflight failed"):
                snapshot(root, reason="drifted_legacy_quarantine")

    def test_active_legacy_browser_attempt_can_be_quarantined_behind_replacement(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Active legacy\n", encoding="utf-8")
            legacy = create_review_job(
                root,
                subject_path=subject,
                prompt="Active legacy review.",
                transport="manual",
            )
            reserved = review_browser_attempt_start(root, job_id=legacy["job_id"])
            legacy_dir = Path(legacy["job_dir"])
            strip_phase_authority_for_legacy_fixture(root, legacy_dir)
            attempt_path = Path(reserved["attempt_uri"])
            attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
            attempt.pop("schema")
            attempt.pop("job_id")
            attempt_path.write_text(json.dumps(attempt), encoding="utf-8")
            attempt_sha256 = hashlib.sha256(attempt_path.read_bytes()).hexdigest()
            status_path = Path(legacy["status_uri"])
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["browser_attempt_sha256"] = attempt_sha256
            status["last_attempt_sha256"] = attempt_sha256
            status_path.write_text(json.dumps(status), encoding="utf-8")
            replacement = create_review_job(
                root,
                subject_path=subject,
                prompt="Replacement review.",
                transport="manual",
            )

            self.assertFalse(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            planned = review_bridge_module.quarantine_legacy_review_job(
                root,
                job_id=legacy["job_id"],
                replacement_job_id=replacement["job_id"],
            )
            self.assertTrue(planned["would_quarantine"])
            applied = review_bridge_module.quarantine_legacy_review_job(
                root,
                job_id=legacy["job_id"],
                replacement_job_id=replacement["job_id"],
                dry_run=False,
                operation_id="op-active-legacy-quarantine",
            )
            self.assertTrue(applied["quarantined"])
            self.assertEqual(applied["accepted_integrity_finding_count"], 3)
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])
            self.assertEqual(
                review_job_status(root, job_id=legacy["job_id"])["status"],
                "quarantined_legacy",
            )
            self.assertTrue(snapshot(root, reason="active_legacy_quarantined")["snapshot_uri"])

    def test_legacy_quarantine_refuses_upgradeable_or_contradictory_shapes(self) -> None:
        for attempt_total, identity_mode in ((1, "absent"), (2, "wrong_current")):
            with self.subTest(
                attempt_total=attempt_total,
                identity_mode=identity_mode,
            ), tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "README.md").write_text(
                    "# Refused quarantine\n",
                    encoding="utf-8",
                )
                legacy = create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Legacy review.",
                    transport="manual",
                )
                reserved = None
                for _index in range(attempt_total):
                    reserved = review_browser_attempt_start(
                        root,
                        job_id=legacy["job_id"],
                    )
                assert reserved is not None
                Path(reserved["response_uri"]).write_text("not json", encoding="utf-8")
                with self.assertRaises(ValueError):
                    ingest_review_result(
                        root,
                        job_id=legacy["job_id"],
                        result_path=Path(reserved["response_uri"]),
                    )
                legacy_dir = Path(legacy["job_dir"])
                strip_phase_authority_for_legacy_fixture(root, legacy_dir)
                for receipt in (legacy_dir / "attempt-receipts").glob("attempt-*.json"):
                    receipt.unlink()
                conn = connect(root)
                try:
                    conn.execute(
                        "DELETE FROM artifacts WHERE kind = 'review_attempt_receipt'"
                    )
                    conn.commit()
                finally:
                    conn.close()
                for attempt_path in (legacy_dir / "attempts").glob("attempt-*.json"):
                    attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
                    if identity_mode == "absent":
                        attempt.pop("schema")
                        attempt.pop("job_id")
                    else:
                        attempt["job_id"] = "review_wrong_current_identity"
                    attempt_path.write_text(json.dumps(attempt), encoding="utf-8")
                status_path = Path(legacy["status_uri"])
                status = json.loads(status_path.read_text(encoding="utf-8"))
                status.pop("last_attempt_sha256")
                status_path.write_text(json.dumps(status), encoding="utf-8")
                replacement = create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Replacement review.",
                    transport="manual",
                )
                before_rows = artifact_rows(root)
                before_files = {
                    path.relative_to(legacy_dir).as_posix(): path.read_bytes()
                    for path in legacy_dir.rglob("*")
                    if path.is_file() and not path.is_symlink()
                }

                if attempt_total == 1:
                    upgrade = review_bridge_module.upgrade_review_job_integrity(
                        root,
                        job_id=legacy["job_id"],
                        dry_run=True,
                    )
                    self.assertTrue(upgrade["would_upgrade"])
                with self.assertRaisesRegex(
                    ValueError,
                    "exact failed multi-attempt|known legacy shape",
                ):
                    review_bridge_module.quarantine_legacy_review_job(
                        root,
                        job_id=legacy["job_id"],
                        replacement_job_id=replacement["job_id"],
                    )
                self.assertEqual(before_rows, artifact_rows(root))
                self.assertEqual(
                    before_files,
                    {
                        path.relative_to(legacy_dir).as_posix(): path.read_bytes()
                        for path in legacy_dir.rglob("*")
                        if path.is_file() and not path.is_symlink()
                    },
                )

    def test_review_job_tree_and_catalog_authority_block_snapshot_drift(self) -> None:
        scenarios = (
            ("missing_packet_row", "required_job_artifact_binding_count_mismatch"),
            ("wrong_packet_kind", "job_artifact_binding_invalid"),
            ("unbound_job_file", "unexpected_job_tree_file"),
            ("unbound_response_file", "unbound_dynamic_job_evidence"),
            ("missing_subject_member", "subject_manifest_member_set_mismatch"),
            ("extra_subject_member", "subject_manifest_member_set_mismatch"),
            ("changed_manifest", "job_artifact_content_mismatch"),
            ("noncanonical_packet_uri", "noncanonical_review_artifact_uri"),
        )
        for scenario, expected_reason in scenarios:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory(
                ignore_cleanup_errors=True
            ) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "README.md").write_text("# Exact tree\n", encoding="utf-8")
                job = create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review exact tree.",
                    transport="manual",
                )
                job_dir = Path(job["job_dir"])
                if scenario == "missing_packet_row":
                    conn = connect(root)
                    try:
                        conn.execute("DELETE FROM artifacts WHERE kind = 'review_packet'")
                        conn.commit()
                    finally:
                        conn.close()
                elif scenario == "wrong_packet_kind":
                    conn = connect(root)
                    try:
                        conn.execute(
                            "UPDATE artifacts SET kind = 'review_prompt' "
                            "WHERE kind = 'review_packet'"
                        )
                        conn.commit()
                    finally:
                        conn.close()
                elif scenario == "unbound_job_file":
                    (job_dir / "UNBOUND.bin").write_bytes(b"unbound")
                elif scenario == "unbound_response_file":
                    (job_dir / "responses" / "response-001.raw.txt").write_text(
                        "unbound response",
                        encoding="utf-8",
                    )
                elif scenario == "missing_subject_member":
                    (job_dir / "snapshot" / "subject" / "README.md").unlink()
                elif scenario == "extra_subject_member":
                    (job_dir / "snapshot" / "subject" / "EXTRA.txt").write_text(
                        "extra",
                        encoding="utf-8",
                    )
                elif scenario == "changed_manifest":
                    Path(job["subject_manifest_uri"]).write_text(
                        json.dumps({"files": []}),
                        encoding="utf-8",
                    )
                elif scenario == "noncanonical_packet_uri":
                    conn = connect(root)
                    try:
                        conn.execute(
                            "UPDATE artifacts SET uri = upper(uri) "
                            "WHERE kind = 'review_packet'"
                        )
                        conn.commit()
                    finally:
                        conn.close()

                integrity = review_bridge_module.review_bridge_integrity_report(root)
                self.assertFalse(integrity["ok"], integrity)
                reasons = {
                    sample.get("reason")
                    for sample in integrity["samples"]["review_bridge_malformed_records"]
                }
                self.assertIn(expected_reason, reasons, integrity)
                self.assertFalse(semantic_integrity_report(root)["ok"])
                with self.assertRaisesRegex(ValueError, "snapshot preflight failed"):
                    snapshot(root, reason=f"blocked_{scenario}")

    @unittest.skipUnless(os.name == "posix", "POSIX directory-fd atomicity proof")
    def test_posix_exclusive_confined_write_never_exposes_partial_final_file(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Atomic write\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review atomic write.",
                transport="manual",
            )
            target = Path(job["job_dir"]) / "receipts" / "atomic-exclusive.txt"
            real_write = os.write
            calls = 0

            def partial_then_fail(fd: int, data: bytes | memoryview) -> int:
                nonlocal calls
                if calls == 0:
                    calls += 1
                    real_write(fd, bytes(data[:3]))
                    raise OSError("synthetic mid-write failure")
                return real_write(fd, data)

            with patch.object(
                review_bridge_module.os,
                "write",
                side_effect=partial_then_fail,
            ), self.assertRaisesRegex(OSError, "synthetic mid-write failure"):
                review_bridge_module._confined_write_text(
                    root,
                    job["job_id"],
                    target,
                    "complete-payload",
                    exclusive=True,
                )
            self.assertFalse(target.exists())
            self.assertEqual(
                list(target.parent.glob(".atomic-exclusive.txt.*.tmp")),
                [],
            )
            review_bridge_module._confined_write_text(
                root,
                job["job_id"],
                target,
                "complete-payload",
                exclusive=True,
            )
            self.assertEqual(target.read_text(encoding="utf-8"), "complete-payload")

    def test_already_bound_upgrade_requires_immutable_receipt_artifact_rows(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            review_browser_attempt_start(root, job_id=job["job_id"])
            second = review_browser_attempt_start(root, job_id=job["job_id"])
            Path(second["response_uri"]).write_text("not json", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "did not contain a JSON object"):
                ingest_review_result(root, job_id=job["job_id"], result_path=Path(second["response_uri"]))
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            conn = connect(root)
            try:
                conn.execute("DELETE FROM artifacts WHERE kind = 'review_attempt_receipt'")
                conn.commit()
            finally:
                conn.close()
            job_dir = Path(job["job_dir"])
            before = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file() and not path.is_symlink()
            }

            self.assertFalse(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            for dry_run in (True, False):
                with self.subTest(dry_run=dry_run):
                    with self.assertRaisesRegex(ValueError, "exact receipt|terminal phase is incomplete"):
                        review_bridge_module.upgrade_review_job_integrity(
                            root,
                            job_id=job["job_id"],
                            dry_run=dry_run,
                        )
            self.assertEqual(
                before,
                {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file() and not path.is_symlink()
                },
            )

    def test_legacy_upgrade_rejects_unexpected_receipt_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            reserved = review_browser_attempt_start(root, job_id=job["job_id"])
            response_path = Path(reserved["response_uri"])
            response_path.write_text(
                json.dumps(valid_review_payload({**request, **review_job_status(root, job_id=job["job_id"])})),
                encoding="utf-8",
            )
            ingest_review_result(root, job_id=job["job_id"], result_path=response_path)
            job_dir = Path(job["job_dir"])
            strip_phase_authority_for_legacy_fixture(root, job_dir)
            attempt_path = job_dir / "attempts" / "attempt-001.json"
            receipt_path = job_dir / "attempt-receipts" / "attempt-001.json"
            receipt_path.unlink()
            conn = connect(root)
            try:
                conn.execute("DELETE FROM artifacts WHERE kind = 'review_attempt_receipt'")
                conn.commit()
            finally:
                conn.close()
            attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
            attempt.pop("schema")
            attempt.pop("job_id")
            attempt_path.write_text(json.dumps(attempt), encoding="utf-8")
            status_path = Path(job["status_uri"])
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status.pop("last_attempt_sha256")
            status_path.write_text(json.dumps(status), encoding="utf-8")
            unexpected_receipt = job_dir / "attempt-receipts" / "attempt-002.json"
            unexpected_receipt.write_text("{}\n", encoding="utf-8")
            before = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file() and not path.is_symlink()
            }
            conn = connect(root)
            try:
                artifact_rows_before = [tuple(row) for row in conn.execute("SELECT * FROM artifacts ORDER BY id")]
            finally:
                conn.close()

            for dry_run in (True, False):
                with self.subTest(dry_run=dry_run):
                    with self.assertRaisesRegex(ValueError, "receipt set"):
                        review_bridge_module.upgrade_review_job_integrity(
                            root,
                            job_id=job["job_id"],
                            dry_run=dry_run,
                        )

            self.assertEqual(
                before,
                {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file() and not path.is_symlink()
                },
            )
            conn = connect(root)
            try:
                self.assertEqual(
                    artifact_rows_before,
                    [tuple(row) for row in conn.execute("SELECT * FROM artifacts ORDER BY id")],
                )
            finally:
                conn.close()

    def test_legacy_upgrade_post_certification_failure_rolls_back_exactly(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            reserved = review_browser_attempt_start(root, job_id=job["job_id"])
            response_path = Path(reserved["response_uri"])
            response_path.write_text(
                json.dumps(valid_review_payload({**request, **review_job_status(root, job_id=job["job_id"])})),
                encoding="utf-8",
            )
            ingest_review_result(root, job_id=job["job_id"], result_path=response_path)
            job_dir = Path(job["job_dir"])
            strip_phase_authority_for_legacy_fixture(root, job_dir)
            attempt_path = job_dir / "attempts" / "attempt-001.json"
            receipt_path = job_dir / "attempt-receipts" / "attempt-001.json"
            receipt_path.unlink()
            conn = connect(root)
            try:
                conn.execute("DELETE FROM artifacts WHERE kind = 'review_attempt_receipt'")
                conn.commit()
            finally:
                conn.close()
            attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
            attempt.pop("schema")
            attempt.pop("job_id")
            attempt_path.write_text(json.dumps(attempt), encoding="utf-8")
            status_path = Path(job["status_uri"])
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status.pop("last_attempt_sha256")
            status_path.write_text(json.dumps(status), encoding="utf-8")
            before = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file() and not path.is_symlink()
            }
            with patch.object(
                review_bridge_module,
                "review_bridge_integrity_report",
                return_value={"ok": False},
            ):
                with self.assertRaisesRegex(ValueError, "exact receipt integrity certification"):
                    review_bridge_module.upgrade_review_job_integrity(root, job_id=job["job_id"])

            after_failure = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file() and not path.is_symlink()
            }
            phase_names = {
                name for name in after_failure if name.startswith("receipts/phase-terminal-")
            }
            self.assertEqual(len(phase_names), 1)
            self.assertEqual(before, {name: raw for name, raw in after_failure.items() if name not in phase_names})
            conn = connect(root)
            try:
                self.assertEqual(
                    conn.execute(
                        "SELECT count(*) FROM artifacts WHERE kind = 'review_phase_envelope'"
                    ).fetchone()[0],
                    1,
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT count(*) FROM artifacts WHERE kind = 'review_attempt_receipt'"
                    ).fetchone()[0],
                    0,
                )
            finally:
                conn.close()

            recovered = review_bridge_module.upgrade_review_job_integrity(
                root,
                job_id=job["job_id"],
            )
            self.assertEqual(recovered["status"], "already_bound")
            self.assertTrue(receipt_path.is_file())

    def test_supersede_receipt_artifact_failure_rolls_back_all_job_files(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            review_browser_attempt_start(root, job_id=job["job_id"])
            job_dir = Path(job["job_dir"])
            before = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file() and not path.is_symlink()
            }

            with patch.object(
                review_bridge_module,
                "record_artifact",
                side_effect=RuntimeError("synthetic receipt artifact failure"),
            ):
                with self.assertRaisesRegex(ValueError, "finalization failed and was rolled back"):
                    review_browser_attempt_start(root, job_id=job["job_id"])

            after_failure = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file() and not path.is_symlink()
            }
            phase_names = {
                name for name in after_failure if name.startswith("receipts/phase-terminal-")
            }
            self.assertEqual(len(phase_names), 1)
            self.assertEqual(before, {name: raw for name, raw in after_failure.items() if name not in phase_names})
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])

            recovered = review_browser_attempt_start(root, job_id=job["job_id"])
            self.assertEqual(recovered["attempt"], 2)
            self.assertTrue((job_dir / "attempt-receipts" / "attempt-001.json").is_file())
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])

    def test_browser_ingest_receipt_artifact_failure_restores_resumable_attempt(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            reserved = review_browser_attempt_start(root, job_id=job["job_id"])
            response_path = Path(reserved["response_uri"])
            response_path.write_text(
                json.dumps(valid_review_payload({**request, **review_job_status(root, job_id=job["job_id"])})),
                encoding="utf-8",
            )
            attempt_path = Path(reserved["attempt_uri"])
            attempt_before = attempt_path.read_bytes()
            attempt_receipt = Path(job["job_dir"]) / "attempt-receipts" / "attempt-001.json"

            with patch.object(
                review_bridge_module,
                "_record_attempt_receipt_artifact",
                side_effect=RuntimeError("synthetic receipt catalog failure"),
            ):
                with self.assertRaisesRegex(ValueError, "finalization failed and was rolled back"):
                    ingest_review_result(root, job_id=job["job_id"], result_path=response_path)

            interrupted_status = json.loads(Path(job["status_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(interrupted_status["status"], "ingesting")
            self.assertEqual(interrupted_status["accepted_ingest_count"], 0)
            self.assertEqual(attempt_path.read_bytes(), attempt_before)
            self.assertFalse(attempt_receipt.exists())
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])

            receipt = ingest_review_result(root, job_id=job["job_id"], result_path=response_path)

            self.assertTrue(receipt["ok"])
            self.assertTrue(attempt_receipt.is_file())
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])
            conn = connect(root)
            try:
                self.assertEqual(
                    conn.execute(
                        "SELECT count(*) FROM artifacts WHERE kind = 'review_attempt_receipt'"
                    ).fetchone()[0],
                    1,
                )
            finally:
                conn.close()

    def test_browser_validation_failure_receipt_artifact_failure_restores_pending_attempt(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            reserved = review_browser_attempt_start(root, job_id=job["job_id"])
            response_path = Path(reserved["response_uri"])
            response_path.write_text("not json", encoding="utf-8")
            attempt_path = Path(reserved["attempt_uri"])
            attempt_before = attempt_path.read_bytes()
            attempt_receipt = Path(job["job_dir"]) / "attempt-receipts" / "attempt-001.json"

            with patch.object(
                review_bridge_module,
                "_record_attempt_receipt_artifact",
                side_effect=RuntimeError("synthetic receipt catalog failure"),
            ):
                with self.assertRaisesRegex(ValueError, "did not contain a JSON object"):
                    ingest_review_result(root, job_id=job["job_id"], result_path=response_path)

            pending = review_job_status(root, job_id=job["job_id"])
            self.assertEqual(pending["status"], "pending_browser_upload")
            self.assertEqual(pending["accepted_ingest_count"], 0)
            self.assertEqual(attempt_path.read_bytes(), attempt_before)
            self.assertFalse(attempt_receipt.exists())
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])

            with self.assertRaisesRegex(ValueError, "did not contain a JSON object"):
                ingest_review_result(root, job_id=job["job_id"], result_path=response_path)

            failed = review_job_status(root, job_id=job["job_id"])
            self.assertEqual(failed["status"], "review_failed")
            self.assertTrue(attempt_receipt.is_file())
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])

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
            self.assertEqual(Path(status["browser_response_uri"]).resolve(), second_path.resolve())

    def test_restored_legacy_job_rebases_to_active_root_and_never_mutates_original(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            original_root = base / "original" / "continuum"
            relocated_root = base / "unrelated" / "restored-continuum"
            subject = base / "subject" / "release.zip"
            subject.parent.mkdir(parents=True)
            with zipfile.ZipFile(subject, "w") as archive:
                archive.writestr("README.md", "# Restorable review subject\n")

            job = create_review_job(
                original_root,
                subject_path=subject,
                prompt="Review the restored release evidence.",
                transport="manual",
            )
            first = review_browser_attempt_start(original_root, job_id=job["job_id"])
            self.assertTrue(Path(first["response_uri"]).is_relative_to(original_root))
            request_path = Path(job["request_uri"])
            status_path = Path(job["status_uri"])
            stored_request = json.loads(request_path.read_text(encoding="utf-8"))
            stored_status = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertLessEqual(
                {key for key in review_bridge_module.STATUS_MUTABLE_KEYS if key.endswith("_uri")},
                review_bridge_module.INTERNAL_JOB_REFERENCE_KEYS,
            )
            self.assertLessEqual(
                {"job_dir", "manual_handoff_uri", "snapshot_subject_path", "attempt_uri"},
                review_bridge_module.INTERNAL_JOB_REFERENCE_KEYS,
            )
            self.assertTrue(Path(stored_request["root"]).is_absolute())
            self.assertTrue(Path(stored_request["subject_path"]).is_absolute())
            self.assertFalse(Path(stored_request["snapshot_subject_path"]).is_absolute())
            self.assertNotIn("job_dir", stored_request)
            self.assertNotIn("manual_handoff_uri", stored_request)
            for payload in (stored_request, stored_status):
                for key in review_bridge_module.INTERNAL_JOB_REFERENCE_KEYS:
                    value = payload.get(key)
                    if value not in (None, ""):
                        self.assertFalse(Path(str(value)).is_absolute(), key)

            snap = snapshot(original_root, reason="review_relay_relocation")
            restored = restore_drill(
                original_root,
                snapshot_uri=snap["snapshot_uri"],
                verify_recent_proof_packs=0,
            )
            self.assertTrue(restored["ok"], restored["checks"])
            review_bridge_module.shutil.copytree(Path(restored["drill_root"]), relocated_root)

            relocated_job_dir = review_bridge_module.review_job_dir(relocated_root, job["job_id"])
            relocated_request_path = relocated_job_dir / review_bridge_module.REVIEW_REQUEST_NAME
            relocated_status_path = relocated_job_dir / review_bridge_module.REVIEW_STATUS_NAME
            legacy_request = json.loads(relocated_request_path.read_text(encoding="utf-8"))
            legacy_status = json.loads(relocated_status_path.read_text(encoding="utf-8"))
            for payload_index, payload in enumerate((legacy_request, legacy_status)):
                for key in review_bridge_module.INTERNAL_JOB_REFERENCE_KEYS:
                    value = payload.get(key)
                    if value not in (None, ""):
                        if payload_index == 0:
                            payload[key] = (
                                "/lost/linux/root/"
                                + Path(str(value)).as_posix()
                            )
                        else:
                            payload[key] = str(
                                original_root / Path(str(value))
                            )
            relocated_request_path.write_text(json.dumps(legacy_request), encoding="utf-8")
            relocated_status_path.write_text(json.dumps(legacy_status), encoding="utf-8")
            replace_review_request_artifact(
                relocated_root,
                job_id=job["job_id"],
                request_path=relocated_request_path,
            )

            sealed_original = base / "sealed-original"
            Path(job["job_dir"]).rename(sealed_original)
            original_job_dir = sealed_original
            original_bytes = {
                path.relative_to(original_job_dir).as_posix(): path.read_bytes()
                for path in original_job_dir.rglob("*")
                if path.is_file()
            }

            second = review_browser_attempt_start(relocated_root, job_id=job["job_id"])
            self.assertTrue(Path(second["response_uri"]).is_relative_to(relocated_root))
            request = review_bridge_module._load_request(relocated_root, job["job_id"])
            status = review_job_status(relocated_root, job_id=job["job_id"])
            payload = valid_review_payload({**request, **status})
            Path(second["response_uri"]).write_text(json.dumps(payload), encoding="utf-8")
            receipt = ingest_review_result(
                relocated_root,
                job_id=job["job_id"],
                result_path=Path(second["response_uri"]),
            )

            self.assertTrue(receipt["ok"])
            self.assertTrue(Path(receipt["ingest_receipt_uri"]).is_relative_to(relocated_root))
            self.assertEqual(
                original_bytes,
                {
                    path.relative_to(original_job_dir).as_posix(): path.read_bytes()
                    for path in original_job_dir.rglob("*")
                    if path.is_file()
                },
            )
            final_status = json.loads(relocated_status_path.read_text(encoding="utf-8"))
            for key in review_bridge_module.INTERNAL_JOB_REFERENCE_KEYS:
                value = final_status.get(key)
                if value not in (None, ""):
                    self.assertFalse(Path(str(value)).is_absolute(), key)
            final_runtime_status = review_job_status(relocated_root, job_id=job["job_id"])
            stored_attempt = json.loads(Path(final_runtime_status["last_attempt_uri"]).read_text(encoding="utf-8"))
            stored_receipt = json.loads(Path(receipt["ingest_receipt_uri"]).read_text(encoding="utf-8"))
            for record in (stored_attempt, stored_receipt):
                for key in review_bridge_module.INTERNAL_JOB_REFERENCE_KEYS:
                    value = record.get(key)
                    if value not in (None, ""):
                        self.assertFalse(Path(str(value)).is_absolute(), key)

    def test_relative_root_create_reserve_and_ingest_keeps_internal_references_relocatable(
        self,
    ) -> None:
        previous_cwd = Path.cwd()
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            try:
                os.chdir(base)
                relative_root = Path("relative-continuum")
                subject = Path("subject")
                subject.mkdir()
                (subject / "README.md").write_text(
                    "# Relative-root review subject\n",
                    encoding="utf-8",
                )

                job = create_review_job(
                    relative_root,
                    subject_path=subject,
                    prompt="Review the relative-root release evidence.",
                    transport="manual",
                )
                attempt = review_browser_attempt_start(
                    relative_root,
                    job_id=job["job_id"],
                )
                request = review_bridge_module._load_request(
                    relative_root,
                    job["job_id"],
                )
                status = review_job_status(relative_root, job_id=job["job_id"])
                response_path = Path(attempt["response_uri"])
                response_path.write_text(
                    json.dumps(valid_review_payload({**request, **status})),
                    encoding="utf-8",
                )
                receipt = ingest_review_result(
                    relative_root,
                    job_id=job["job_id"],
                    result_path=response_path,
                )

                active_root = relative_root.resolve()
                self.assertTrue(response_path.resolve().is_relative_to(active_root))
                self.assertTrue(
                    Path(receipt["ingest_receipt_uri"])
                    .resolve()
                    .is_relative_to(active_root)
                )
                job_dir = review_bridge_module.review_job_dir(
                    relative_root,
                    job["job_id"],
                )
                for record_path in (
                    job_dir / review_bridge_module.REVIEW_REQUEST_NAME,
                    job_dir / review_bridge_module.REVIEW_STATUS_NAME,
                    Path(status["last_attempt_uri"]),
                    Path(receipt["ingest_receipt_uri"]),
                ):
                    record = json.loads(record_path.read_text(encoding="utf-8"))
                    for key in review_bridge_module.INTERNAL_JOB_REFERENCE_KEYS:
                        value = record.get(key)
                        if value not in (None, ""):
                            self.assertFalse(Path(str(value)).is_absolute(), key)
            finally:
                os.chdir(previous_cwd)

    def test_browser_reservation_phase_replays_every_hard_boundary_and_supersedes(self) -> None:
        boundaries = (
            "phase_file",
            "response",
            "attempt",
            "attempt_handoff",
            "latest_handoff",
            "status",
            "artifacts",
        )
        for boundary in boundaries:
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory(
                ignore_cleanup_errors=True
            ) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "README.md").write_text(
                    "# Browser reservation boundary subject\n",
                    encoding="utf-8",
                )
                job = create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review the reservation boundary.",
                    transport="manual",
                )
                first = review_browser_attempt_start(
                    root,
                    job_id=job["job_id"],
                    operation_id="browser-reservation-a",
                )
                operation_id = f"browser-reservation-b-{boundary}"

                if boundary == "phase_file":
                    real_materialize = review_bridge_module._materialize_phase_envelope

                    def interrupt_phase_file(
                        phase_root: Path,
                        phase_job_id: str,
                        path: Path,
                        text: str,
                    ) -> None:
                        if path.name == "phase-browser-reservation-002.json":
                            raise KeyboardInterrupt
                        real_materialize(phase_root, phase_job_id, path, text)

                    boundary_patch = patch.object(
                        review_bridge_module,
                        "_materialize_phase_envelope",
                        side_effect=interrupt_phase_file,
                    )
                elif boundary == "status":
                    real_write_status = review_bridge_module._write_status

                    def interrupt_status(
                        status_root: Path,
                        status_job_id: str,
                        status: dict,
                    ) -> None:
                        real_write_status(status_root, status_job_id, status)
                        if (
                            status.get("status") == "pending_browser_upload"
                            and status.get("attempt_count") == 2
                        ):
                            raise KeyboardInterrupt

                    boundary_patch = patch.object(
                        review_bridge_module,
                        "_write_status",
                        side_effect=interrupt_status,
                    )
                else:
                    helper_name = {
                        "response": "_materialize_browser_reservation_response",
                        "attempt": "_materialize_browser_reservation_attempt",
                        "attempt_handoff": (
                            "_materialize_browser_reservation_attempt_handoff"
                        ),
                        "latest_handoff": (
                            "_materialize_browser_reservation_latest_handoff"
                        ),
                        "artifacts": "_persist_browser_reservation_artifacts",
                    }[boundary]
                    real_helper = getattr(review_bridge_module, helper_name)

                    def interrupt_after_write(*args, **kwargs):
                        real_helper(*args, **kwargs)
                        raise KeyboardInterrupt

                    boundary_patch = patch.object(
                        review_bridge_module,
                        helper_name,
                        side_effect=interrupt_after_write,
                    )

                with boundary_patch, self.assertRaises(KeyboardInterrupt):
                    review_browser_attempt_start(
                        root,
                        job_id=job["job_id"],
                        operation_id=operation_id,
                    )

                recovered = review_browser_attempt_start(
                    root,
                    job_id=job["job_id"],
                    operation_id=operation_id,
                )
                repeated = review_browser_attempt_start(
                    root,
                    job_id=job["job_id"],
                    operation_id=operation_id,
                )
                self.assertEqual(recovered, repeated)
                self.assertEqual(recovered["attempt"], 2)
                self.assertNotEqual(first["response_uri"], recovered["response_uri"])
                self.assertEqual(Path(recovered["response_uri"]).read_bytes(), b"")
                self.assertEqual(
                    json.loads(Path(first["attempt_uri"]).read_text(encoding="utf-8"))[
                        "status"
                    ],
                    "browser_attempt_superseded",
                )
                phase_path = (
                    Path(job["job_dir"])
                    / "receipts"
                    / "phase-browser-reservation-002.json"
                )
                phase = json.loads(phase_path.read_text(encoding="utf-8"))
                self.assertEqual(phase["operation_id"]["value"], operation_id)
                self.assertEqual(
                    review_bridge_module._browser_reservation_artifacts_state(
                        root,
                        phase["payload"]["artifacts"],
                    ),
                    "exact",
                )
                self.assertTrue(
                    review_bridge_module.review_bridge_integrity_report(root)["ok"]
                )
                self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_browser_reservation_same_operation_rejects_forged_status_progression(
        self,
    ) -> None:
        forged_statuses = (
            {"status": "pending_browser_upload", "attempt_count": 2},
            {"status": "ingested", "attempt_count": 1},
        )
        for forged_status in forged_statuses:
            with self.subTest(status=forged_status["status"]), tempfile.TemporaryDirectory(
                ignore_cleanup_errors=True
            ) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "README.md").write_text(
                    "# Forged browser progression\n",
                    encoding="utf-8",
                )
                job = create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Reject forged browser progression.",
                    transport="manual",
                )
                review_browser_attempt_start(
                    root,
                    job_id=job["job_id"],
                    operation_id="browser-forged-status-operation",
                )
                Path(job["status_uri"]).write_text(
                    review_bridge_module.json_dumps(forged_status),
                    encoding="utf-8",
                )

                with self.assertRaises(ValueError):
                    review_browser_attempt_start(
                        root,
                        job_id=job["job_id"],
                        operation_id="browser-forged-status-operation",
                    )
                self.assertFalse(
                    review_bridge_module.review_bridge_integrity_report(root)["ok"]
                )

    def test_latest_browser_handoff_phase_binding_blocks_promotion_after_ingest(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text(
                "# Latest handoff phase binding\n",
                encoding="utf-8",
            )
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Bind the latest browser handoff.",
                transport="manual",
            )
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            operation_id = "browser-latest-handoff-operation"
            reserved = review_browser_attempt_start(
                root,
                job_id=job["job_id"],
                operation_id=operation_id,
            )
            response_path = Path(reserved["response_uri"])
            response_path.write_text(
                json.dumps(
                    valid_review_payload(
                        {
                            **request,
                            **review_job_status(root, job_id=job["job_id"]),
                        }
                    )
                ),
                encoding="utf-8",
            )
            ingest_review_result(
                root,
                job_id=job["job_id"],
                result_path=response_path,
                operation_id="browser-latest-handoff-ingest",
            )
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            latest_handoff = Path(reserved["browser_handoff_latest_uri"])
            latest_handoff.write_text("TAMPERED\n", encoding="utf-8")

            self.assertFalse(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertFalse(semantic_integrity_report(root)["ok"])
            with self.assertRaisesRegex(ValueError, "snapshot preflight failed"):
                snapshot(root)
            with self.assertRaisesRegex(ValueError, "latest handoff drifted"):
                review_browser_attempt_start(
                    root,
                    job_id=job["job_id"],
                    operation_id=operation_id,
                )

    def test_browser_reservation_operation_id_flows_through_cli_and_mcp(self) -> None:
        from continuum.cli import main as cli_main

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp) / "continuum"
            root.mkdir()
            with patch(
                "continuum.cli.review_browser_attempt_start",
                return_value={"ok": True},
            ) as cli_reserve, patch(
                "continuum.cli.emit_result",
                return_value=0,
            ), patch(
                "sys.argv",
                [
                    "continuum",
                    "review-browser-attempt-start",
                    "--root",
                    str(root),
                    "--job-id",
                    "review_cli_operation",
                    "--operation-id",
                    "caller-cli-operation",
                ],
            ):
                self.assertEqual(cli_main(), 0)
            self.assertEqual(
                cli_reserve.call_args.kwargs["operation_id"],
                "caller-cli-operation",
            )

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# MCP operation id\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review the MCP operation binding.",
                transport="manual",
            )
            args = {
                "root": str(root),
                "job_id": job["job_id"],
                "operation_id": "caller-mcp-operation-a",
            }
            with patch.dict("os.environ", {"CONTINUUM_ALLOWED_ROOTS": tmp}):
                first = call_tool("continuum_review_browser_attempt_start", args)
                repeated = call_tool("continuum_review_browser_attempt_start", args)
                second = call_tool(
                    "continuum_review_browser_attempt_start",
                    {**args, "operation_id": "caller-mcp-operation-b"},
                )
            self.assertEqual(first["attempt"], 1)
            self.assertEqual(repeated["attempt"], 1)
            self.assertEqual(first["response_uri"], repeated["response_uri"])
            self.assertEqual(second["attempt"], 2)

    def test_automated_review_operation_id_flows_through_cli_and_mcp(self) -> None:
        class StubOperation:
            operation_id = "generated-operation"

            def cursor(self, _value: dict) -> None:
                return None

        def run_guarded_action(_root: Path, **kwargs: object) -> dict:
            action = kwargs["action"]
            assert callable(action)
            return action(StubOperation())

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp) / "continuum-cli"
            with patch.object(
                cli_module,
                "guarded_result",
                side_effect=run_guarded_action,
            ), patch.object(
                cli_module,
                "run_review_job",
                return_value={"ok": True, "status": "ingested"},
            ) as cli_run, patch.object(
                cli_module,
                "emit_result",
                return_value=0,
            ):
                self.assertEqual(
                    cli_module._main(
                        [
                            "review-run",
                            "--root",
                            str(root),
                            "--job-id",
                            "review-cli-operation",
                            "--operation-id",
                            "caller-cli-review-operation",
                        ]
                    ),
                    0,
                )
            self.assertEqual(
                cli_run.call_args.kwargs["operation_id"],
                "caller-cli-review-operation",
            )

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp) / "continuum-mcp"
            with patch.dict(
                os.environ,
                {"CONTINUUM_MCP_ALLOW_ANY_PATH": "1"},
            ), patch.object(
                mcp_server_module,
                "guarded_tool",
                side_effect=run_guarded_action,
            ), patch.object(
                mcp_server_module,
                "run_review_job",
                return_value={"ok": True, "status": "ingested"},
            ) as mcp_run:
                result = mcp_server_module.tool_review_run(
                    {
                        "root": str(root),
                        "job_id": "review-mcp-operation",
                        "operation_id": "caller-mcp-review-operation",
                    }
                )
            self.assertTrue(result["ok"])
            self.assertEqual(
                mcp_run.call_args.kwargs["operation_id"],
                "caller-mcp-review-operation",
            )
            self.assertEqual(
                TOOLS["continuum_review_run"][1]["properties"]["operation_id"],
                {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 128,
                    "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$",
                },
            )

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp) / "continuum-empty-operation"
            with patch.object(cli_module, "guarded_result") as cli_guard, patch.object(
                cli_module,
                "emit",
            ):
                self.assertEqual(
                    cli_module.main(
                        [
                            "review-run",
                            "--root",
                            str(root),
                            "--job-id",
                            "review-empty-operation",
                            "--operation-id",
                            "",
                        ]
                    ),
                    1,
                )
                cli_guard.assert_not_called()

            with patch.dict(
                os.environ,
                {"CONTINUUM_MCP_ALLOW_ANY_PATH": "1"},
            ), patch.object(mcp_server_module, "guarded_tool") as mcp_guard, self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "non-empty string",
            ):
                mcp_server_module.tool_review_run(
                    {
                        "root": str(root),
                        "job_id": "review-empty-operation",
                        "operation_id": "",
                    }
                )
            mcp_guard.assert_not_called()
            self.assertFalse(root.exists())

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

    def test_concurrent_automated_runners_reuse_the_winning_reservation(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Concurrent runner subject\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review through endpoint.",
                transport="direct-openai",
            )
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            payload = valid_review_payload(
                {**request, **review_job_status(root, job_id=job["job_id"])}
            )
            endpoint_entered = threading.Event()
            release_endpoint = threading.Event()
            second_started = threading.Event()
            endpoint_calls: list[int] = []

            def endpoint_response(**_kwargs: object) -> dict:
                endpoint_calls.append(1)
                endpoint_entered.set()
                self.assertTrue(release_endpoint.wait(timeout=10))
                return {"choices": [{"message": {"content": json.dumps(payload)}}]}

            def run_candidate(index: int) -> tuple[str, object]:
                if index == 2:
                    second_started.set()
                try:
                    return (
                        "accepted",
                        review_bridge_module.run_review_job(
                            root,
                            job_id=job["job_id"],
                            transport="direct-openai",
                            operation_id="race-op",
                        ),
                    )
                except ValueError as exc:
                    return "rejected", exc

            with patch.object(
                review_bridge_module,
                "_openai_chat_completion",
                side_effect=endpoint_response,
            ), ThreadPoolExecutor(max_workers=2) as executor:
                first = executor.submit(run_candidate, 1)
                self.assertTrue(endpoint_entered.wait(timeout=10))
                second = executor.submit(run_candidate, 2)
                self.assertTrue(second_started.wait(timeout=10))
                release_endpoint.set()
                outcomes = [first.result(timeout=30), second.result(timeout=30)]

            self.assertEqual(len(endpoint_calls), 1)
            self.assertGreaterEqual(
                sum(kind == "accepted" for kind, _value in outcomes),
                1,
            )
            for kind, value in outcomes:
                if kind == "rejected":
                    self.assertRegex(str(value), "active or accepted ingest|already has an accepted ingest")
            final_status = review_job_status(root, job_id=job["job_id"])
            job_dir = Path(job["job_dir"])
            self.assertEqual(final_status["status"], "ingested")
            self.assertEqual(final_status["attempt_count"], 1)
            self.assertEqual(
                [path.name for path in (job_dir / "responses").glob("transport-response-*.raw.json")],
                ["transport-response-001.raw.json"],
            )
            self.assertEqual(
                [path.name for path in (job_dir / "responses").glob("response-*.raw.txt")],
                ["response-001.raw.txt"],
            )
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])

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
            original_confined_write = review_bridge_module._confined_write_text
            failed_once = False

            def interrupt_after_claim(
                active_root: Path,
                active_job_id: str,
                path: Path,
                text: str,
                **kwargs: object,
            ) -> None:
                nonlocal failed_once
                if Path(path) == response_json_path and not failed_once:
                    failed_once = True
                    raise OSError("simulated process interruption after ingest claim")
                original_confined_write(active_root, active_job_id, path, text, **kwargs)

            with patch.object(review_bridge_module, "_confined_write_text", side_effect=interrupt_after_claim):
                with self.assertRaisesRegex(ValueError, "derived files were restored"):
                    ingest_review_result(root, job_id=job["job_id"], result_path=response_path)

            interrupted = review_job_status(root, job_id=job["job_id"])
            interrupted_status = json.loads(Path(interrupted["status_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(interrupted["status"], "ingesting")
            self.assertEqual(interrupted["accepted_ingest_count"], 0)
            self.assertEqual(
                interrupted_status["pending_response_json_uri"],
                review_bridge_module._job_reference_uri(root, job["job_id"], response_json_path),
            )

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

    def test_review_secret_scan_zero_limit_means_result_uncapped(self) -> None:
        text = (
            'OPENAI_API_KEY="sk-' + ("A" * 32) + '"\n'
            'GITHUB_TOKEN="ghp_' + ("B" * 36) + '"\n'
        )

        findings = review_bridge_module._scan_review_text_for_secrets(text, source="fixture.py", max_findings=0)

        self.assertGreaterEqual(len(findings), 2)

    def test_review_text_scan_streams_result_and_candidate_limits(self) -> None:
        calls: list[int | None] = []

        def one_finding_per_line(
            _text: str,
            *,
            max_findings: int | None = 20,
        ) -> list[dict[str, object]]:
            calls.append(max_findings)
            return [{"type": "synthetic", "line": 1, "snippet": "redacted"}]

        with patch.object(
            review_bridge_module,
            "scan_text_for_secrets",
            side_effect=one_finding_per_line,
        ):
            findings = review_bridge_module._scan_review_text_for_secrets(
                "line\n" * 10_000,
                source="synthetic.txt",
                max_findings=20,
            )

        self.assertEqual(len(findings), 20)
        self.assertEqual(len(calls), 20)
        self.assertTrue(all(value is not None and value > 0 for value in calls))

        suppressed: list[dict] = []
        with patch.object(
            review_bridge_module,
            "REVIEW_SECRET_SCAN_MAX_CANDIDATES",
            3,
        ), patch.object(
            review_bridge_module,
            "scan_text_for_secrets",
            side_effect=one_finding_per_line,
        ), patch.object(
            review_bridge_module,
            "_allowlisted_review_secret_finding",
            return_value="synthetic-allowlist",
        ), self.assertRaisesRegex(
            review_bridge_module.ReviewBridgeError,
            "candidate limit exceeded",
        ):
            review_bridge_module._scan_review_text_for_secrets(
                "line\n" * 4,
                source="synthetic.txt",
                max_findings=20,
                suppressed_findings=suppressed,
            )
        self.assertEqual(len(suppressed), 3)

        budget = review_bridge_module._new_review_preparation_budget(
            max_packet_bytes=1_024,
            max_subject_file_bytes=1_024,
            max_subject_bytes=1_024,
            prepare_timeout_seconds=1,
        )
        budget.deadline = 0.0
        with self.assertRaisesRegex(
            review_bridge_module.ReviewBridgeError,
            "elapsed-time budget",
        ):
            review_bridge_module._scan_review_text_for_secrets(
                "line\n",
                source="synthetic.txt",
                budget=budget,
            )

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
            self.assertEqual(
                list((root / "exports" / "review_bridge").glob("jobs/*")),
                [],
            )

    def test_zip_member_cap_is_enforced_before_zipfile_construction(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            archive_path = Path(tmp) / "over-limit.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                for index in range(
                    review_bridge_module.REVIEW_ZIP_SCAN_MAX_MEMBERS + 1
                ):
                    archive.writestr(f"member-{index:04d}.txt", b"")
            forged = bytearray(archive_path.read_bytes())
            eocd_offset = forged.rfind(b"PK\x05\x06")
            self.assertGreaterEqual(eocd_offset, 0)
            forged[eocd_offset + 8 : eocd_offset + 10] = (1).to_bytes(
                2,
                "little",
            )
            forged[eocd_offset + 10 : eocd_offset + 12] = (1).to_bytes(
                2,
                "little",
            )
            archive_path.write_bytes(forged)
            outcome = review_bridge_module.ScanOutcome()

            with patch.object(
                review_bridge_module.zipfile,
                "ZipFile",
                side_effect=AssertionError("ZipFile must not be constructed"),
            ):
                findings = review_bridge_module._scan_zip_bytes_for_secrets(
                    bytes(forged),
                    archive_name=archive_path.name,
                    outcome=outcome,
                )
                with self.assertRaisesRegex(
                    review_bridge_module.ReviewBridgeError,
                    "too many members",
                ):
                    review_bridge_module._zip_subject_member_manifest(
                        archive_path,
                    )
                with self.assertRaisesRegex(
                    review_bridge_module.ReviewBridgeError,
                    "too many members",
                ):
                    review_bridge_module._write_expanded_zip_subject_to_capsule(
                        object(),  # type: ignore[arg-type]
                        archive_path,
                        {"members": []},
                    )

            self.assertEqual(findings, [])
            self.assertEqual(
                [item["reason"] for item in outcome.limits_hit],
                ["zip_member_count_exceeded"],
            )

    def test_zip64_empty_archive_preflight_is_bounded_and_position_safe(self) -> None:
        zip64_end = struct.pack(
            "<4sQ2H2L4Q",
            b"PK\x06\x06",
            44,
            45,
            45,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, 0, 1)
        end = struct.pack(
            "<4s4H2LH",
            b"PK\x05\x06",
            0,
            0,
            0xFFFF,
            0xFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0,
        )
        stream = io.BytesIO(zip64_end + locator + end)
        stream.seek(7)

        self.assertEqual(
            review_bridge_module._preflight_zip_central_directory(
                stream,
                archive_name="empty-zip64.zip",
                member_limit=review_bridge_module.REVIEW_ZIP_SCAN_MAX_MEMBERS,
            ),
            0,
        )
        self.assertEqual(stream.tell(), 7)
        with zipfile.ZipFile(stream) as archive:
            self.assertEqual(archive.infolist(), [])

    def test_zip64_locator_offset_must_bind_the_preflight_record(self) -> None:
        zip64_end = struct.pack(
            "<4sQ2H2L4Q",
            b"PK\x06\x06",
            44,
            45,
            45,
            0,
            0,
            0,
            0,
            0,
            0,
        )
        locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, 1, 1)
        end = struct.pack(
            "<4s4H2LH",
            b"PK\x05\x06",
            0,
            0,
            0xFFFF,
            0xFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0,
        )

        with self.assertRaisesRegex(
            zipfile.BadZipFile,
            "locator offset does not bind",
        ):
            review_bridge_module._preflight_zip_central_directory(
                io.BytesIO(zip64_end + locator + end),
                archive_name="misbound-zip64.zip",
                member_limit=review_bridge_module.REVIEW_ZIP_SCAN_MAX_MEMBERS,
            )

    def test_zip64_extensible_record_is_rejected_before_zipfile_allocation(self) -> None:
        zip64_end = (
            struct.pack(
                "<4sQ2H2L4Q",
                b"PK\x06\x06",
                45,
                45,
                45,
                0,
                0,
                0,
                0,
                0,
                0,
            )
            + b"X"
        )
        locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, 0, 1)
        end = struct.pack(
            "<4s4H2LH",
            b"PK\x05\x06",
            0,
            0,
            0xFFFF,
            0xFFFF,
            0xFFFFFFFF,
            0xFFFFFFFF,
            0,
        )
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            archive_path = Path(tmp) / "extensible-zip64.zip"
            archive_path.write_bytes(zip64_end + locator + end)

            with patch.object(
                review_bridge_module.zipfile,
                "ZipFile",
                side_effect=AssertionError("ZipFile must not be constructed"),
            ) as zip_constructor, self.assertRaisesRegex(
                zipfile.BadZipFile,
                "unsupported extensible data",
            ):
                with review_bridge_module._open_preflighted_zip_archive(
                    archive_path,
                    member_limit=review_bridge_module.REVIEW_ZIP_SCAN_MAX_MEMBERS,
                ):
                    self.fail("invalid ZIP64 archive unexpectedly opened")

            zip_constructor.assert_not_called()

    def test_zip_lzma_is_rejected_before_decoder_allocation(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            archive_path = Path(tmp) / "lzma-subject.zip"
            with zipfile.ZipFile(
                archive_path,
                "w",
                compression=zipfile.ZIP_LZMA,
            ) as archive:
                archive.writestr("README.md", "# Subject\n")
            outcome = review_bridge_module.ScanOutcome()

            with patch.object(
                review_bridge_module.zipfile,
                "LZMADecompressor",
                side_effect=AssertionError("LZMA decoder must not be allocated"),
            ):
                findings = review_bridge_module._scan_zip_bytes_for_secrets(
                    archive_path.read_bytes(),
                    archive_name=archive_path.name,
                    outcome=outcome,
                )
                with self.assertRaisesRegex(
                    review_bridge_module.ReviewBridgeError,
                    "coverage incomplete",
                ):
                    review_bridge_module._zip_subject_member_manifest(
                        archive_path,
                    )

            self.assertEqual(findings, [])
            self.assertIn(
                "zip_compression_method_not_supported",
                {item["reason"] for item in outcome.errors},
            )

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

            def copy_then_mutate(
                root_arg: Path,
                subject_arg: Path,
                files: list[Path],
                snapshot_subject: Path,
                **kwargs: object,
            ) -> list[Path]:
                copied = original_copy(
                    root_arg,
                    subject_arg,
                    files,
                    snapshot_subject,
                    **kwargs,
                )
                target.write_text('VERSION = "new"\n', encoding="utf-8")
                return copied

            with patch.object(review_bridge_module, "_copy_snapshot_files", side_effect=copy_then_mutate):
                with self.assertRaisesRegex(
                    ValueError,
                    "changed after its snapshot|git state changed during review preparation",
                ):
                    create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")

    def test_git_capture_disables_repository_configured_executable_helpers(self) -> None:
        if review_bridge_module.shutil.which("git") is None:
            self.skipTest("git executable unavailable")
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            for helper_kind in ("fsmonitor", "external", "textconv"):
                with self.subTest(helper_kind=helper_kind):
                    root = base / f"continuum-{helper_kind}"
                    subject = base / f"repo-{helper_kind}"
                    subject.mkdir()
                    marker = base / f"{helper_kind}-executed.txt"
                    helper = subject / "configured-helper.py"
                    helper.write_text(
                        "import pathlib\n"
                        f"marker = pathlib.Path({str(marker)!r})\n"
                        "with marker.open('a', encoding='utf-8') as handle:\n"
                        "    handle.write('executed\\n')\n"
                        "print('converted')\n",
                        encoding="utf-8",
                    )
                    target = subject / "app.py"
                    target.write_text("VALUE = 'old'\n", encoding="utf-8")
                    if helper_kind == "textconv":
                        (subject / ".gitattributes").write_text(
                            "app.py diff=hostile\n",
                            encoding="utf-8",
                        )
                    subprocess.run(
                        ["git", "init"],
                        cwd=subject,
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    subprocess.run(
                        ["git", "config", "user.email", "test@example.invalid"],
                        cwd=subject,
                        check=True,
                    )
                    subprocess.run(
                        ["git", "config", "user.name", "Test"],
                        cwd=subject,
                        check=True,
                    )
                    subprocess.run(["git", "add", "."], cwd=subject, check=True)
                    subprocess.run(
                        ["git", "commit", "-m", "init"],
                        cwd=subject,
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    target.write_text("VALUE = 'new'\n", encoding="utf-8")
                    command = f'"{sys.executable}" "{helper}"'
                    if helper_kind == "fsmonitor":
                        config_key = "core.fsmonitor"
                        probe_command = ["git", "status", "--short"]
                    elif helper_kind == "external":
                        config_key = "diff.external"
                        probe_command = ["git", "diff", "--"]
                    else:
                        config_key = "diff.hostile.textconv"
                        probe_command = ["git", "diff", "--"]
                    subprocess.run(
                        ["git", "config", config_key, command],
                        cwd=subject,
                        check=True,
                    )
                    subprocess.run(
                        probe_command,
                        cwd=subject,
                        check=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                    self.assertTrue(marker.exists(), f"hostile {helper_kind} fixture did not execute")
                    marker.unlink()

                    job = create_review_job(
                        root,
                        subject_path=subject,
                        prompt="Review hard.",
                        transport="manual",
                    )
                    self.assertFalse(marker.exists())
                    current = review_check_current(root, job_id=job["job_id"])
                    self.assertTrue(current["current"], current)
                    self.assertFalse(marker.exists())

    def test_git_diff_capture_stops_at_live_output_budget(self) -> None:
        if review_bridge_module.shutil.which("git") is None:
            self.skipTest("git executable unavailable")
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            subject = Path(tmp) / "repo"
            subject.mkdir()
            target = subject / "large.txt"
            target.write_text("A" * 524_288 + "\n", encoding="utf-8")
            subprocess.run(
                ["git", "init"],
                cwd=subject,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            subprocess.run(
                ["git", "config", "user.email", "test@example.invalid"],
                cwd=subject,
                check=True,
            )
            subprocess.run(
                ["git", "config", "user.name", "Test"],
                cwd=subject,
                check=True,
            )
            subprocess.run(["git", "add", "large.txt"], cwd=subject, check=True)
            subprocess.run(
                ["git", "commit", "-m", "init"],
                cwd=subject,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            target.write_text("B" * 524_288 + "\n", encoding="utf-8")

            capture_limit = 1_024
            captured = review_bridge_module._git_capture(
                subject,
                include_diff=True,
                max_diff_bytes=capture_limit,
            )

            self.assertTrue(captured["diff_truncated"], captured)
            self.assertIn("[diff truncated]", captured["diff"])
            self.assertLessEqual(
                len(captured["diff"].encode("utf-8")),
                capture_limit + len("\n[diff truncated]"),
            )

    def test_git_capture_rejects_nonzero_commands_even_with_bounded_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            subject = Path(tmp) / "repo"
            (subject / ".git").mkdir(parents=True)

            with patch.object(
                review_bridge_module,
                "_run_bounded_process",
                return_value=bounded_process_result(
                    stderr="synthetic bounded git failure",
                    returncode=23,
                ),
            ), self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                r"Git branch failed \(exit 23\): synthetic bounded git failure",
            ):
                review_bridge_module._git_capture(
                    subject,
                    include_diff=False,
                    max_diff_bytes=1_024,
                )

    def test_snapshot_link_swap_fails_before_archive_or_capsule_publication(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            nested = subject / "nested"
            nested.mkdir(parents=True)
            (nested / "readme.txt").write_text("SAFE_ORIGINAL\n", encoding="utf-8")
            outside = base / "outside"
            outside.mkdir()
            outside_marker = "OUTSIDE_HOST_MARKER_4FQ"
            (outside / "readme.txt").write_text(
                outside_marker + "\n",
                encoding="utf-8",
            )
            original_collect = review_bridge_module._collect_subject_files

            def collect_then_swap(*args: object, **kwargs: object) -> object:
                result = original_collect(*args, **kwargs)
                shutil.rmtree(nested)
                make_link_like_directory(self, nested, outside)
                return result

            with patch.object(
                review_bridge_module,
                "_collect_subject_files",
                side_effect=collect_then_swap,
            ), self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "link-like|changed|opened safely|pinned",
            ):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                )

            jobs_dir = root / "exports" / "review_bridge" / "jobs"
            self.assertFalse(jobs_dir.exists() and any(jobs_dir.iterdir()))
            self.assertFalse(any(root.rglob(review_bridge_module.REVIEW_CAPSULE_NAME)))
            self.assertFalse(any(root.rglob("subject.zip")))

    def test_snapshot_plain_file_swap_and_restore_is_rejected_by_identity(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            target = subject / "app.py"
            target.write_text("ORIGINAL\n", encoding="utf-8")
            replacement = base / "replacement.py"
            replacement.write_text("REPLACEMENT\n", encoding="utf-8")
            saved = base / "app-original.py"
            original_collect = review_bridge_module._collect_subject_files
            original_copy = review_bridge_module._copy_snapshot_files

            def collect_then_swap(*args: object, **kwargs: object) -> object:
                result = original_collect(*args, **kwargs)
                target.rename(saved)
                replacement.rename(target)
                return result

            def copy_then_restore(*args: object, **kwargs: object) -> object:
                try:
                    return original_copy(*args, **kwargs)
                finally:
                    if target.exists():
                        target.rename(replacement)
                    if saved.exists():
                        saved.rename(target)

            with patch.object(
                review_bridge_module,
                "_collect_subject_files",
                side_effect=collect_then_swap,
            ), patch.object(
                review_bridge_module,
                "_copy_snapshot_files",
                side_effect=copy_then_restore,
            ), self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "identity|metadata|changed",
            ):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                )

            self.assertEqual(target.read_text(encoding="utf-8"), "ORIGINAL\n")
            self.assertFalse(any(root.rglob(review_bridge_module.REVIEW_CAPSULE_NAME)))

    def test_snapshot_plain_directory_swap_and_restore_is_rejected_by_identity(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            nested = subject / "nested"
            nested.mkdir(parents=True)
            target = nested / "app.py"
            target.write_text("ORIGINAL\n", encoding="utf-8")
            replacement = base / "replacement-nested"
            replacement.mkdir()
            try:
                os.link(target, replacement / "app.py")
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")
            saved = base / "nested-original"
            original_collect = review_bridge_module._collect_subject_files
            original_copy = review_bridge_module._copy_snapshot_files

            def collect_then_swap(*args: object, **kwargs: object) -> object:
                result = original_collect(*args, **kwargs)
                nested.rename(saved)
                replacement.rename(nested)
                return result

            def copy_then_restore(*args: object, **kwargs: object) -> object:
                try:
                    return original_copy(*args, **kwargs)
                finally:
                    if nested.exists():
                        nested.rename(replacement)
                    if saved.exists():
                        saved.rename(nested)

            with patch.object(
                review_bridge_module,
                "_collect_subject_files",
                side_effect=collect_then_swap,
            ), patch.object(
                review_bridge_module,
                "_copy_snapshot_files",
                side_effect=copy_then_restore,
            ), self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "identity|metadata|changed",
            ):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                )

            self.assertEqual((nested / "app.py").read_text(encoding="utf-8"), "ORIGINAL\n")
            self.assertFalse(any(root.rglob(review_bridge_module.REVIEW_CAPSULE_NAME)))

    def test_currentness_plain_file_swap_and_restore_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            target = subject / "app.py"
            target.write_text("SAME-CONTENT\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )
            replacement = base / "replacement.py"
            replacement.write_text("SAME-CONTENT\n", encoding="utf-8")
            saved = base / "app-original.py"
            original_collect = review_bridge_module._collect_subject_files
            original_manifest = review_bridge_module._file_manifest_entry

            def collect_then_swap(*args: object, **kwargs: object) -> object:
                result = original_collect(*args, **kwargs)
                target.rename(saved)
                replacement.rename(target)
                return result

            def manifest_then_restore(*args: object, **kwargs: object) -> object:
                try:
                    return original_manifest(*args, **kwargs)
                finally:
                    if target.exists():
                        target.rename(replacement)
                    if saved.exists():
                        saved.rename(target)

            with patch.object(
                review_bridge_module,
                "_collect_subject_files",
                side_effect=collect_then_swap,
            ), patch.object(
                review_bridge_module,
                "_file_manifest_entry",
                side_effect=manifest_then_restore,
            ):
                current = review_check_current(root, job_id=job["job_id"])

            self.assertFalse(current["current"])
            self.assertEqual(current["reason"], "subject_currentness_check_failed_safely")
            self.assertEqual(target.read_text(encoding="utf-8"), "SAME-CONTENT\n")

    def test_subject_ancestor_link_swap_fails_before_source_open(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            parent = base / "plain-parent"
            subject = parent / "subject"
            subject.mkdir(parents=True)
            (subject / "readme.txt").write_text(
                "SAFE_ORIGINAL\n",
                encoding="utf-8",
            )
            outside_parent = base / "outside-parent"
            outside_subject = outside_parent / "subject"
            outside_subject.mkdir(parents=True)
            outside_marker = "OUTSIDE_ANCESTOR_MARKER_Q7P"
            (outside_subject / "readme.txt").write_text(
                outside_marker + "\n",
                encoding="utf-8",
            )
            original_parent = base / "plain-parent-original"
            original_collect = review_bridge_module._collect_subject_files

            def collect_then_swap(*args: object, **kwargs: object) -> object:
                result = original_collect(*args, **kwargs)
                parent.rename(original_parent)
                make_link_like_directory(self, parent, outside_parent)
                return result

            try:
                with patch.object(
                    review_bridge_module,
                    "_collect_subject_files",
                    side_effect=collect_then_swap,
                ), self.assertRaisesRegex(
                    review_bridge_module.ReviewBridgeError,
                    "link-like|changed|opened safely|pinned",
                ):
                    create_review_job(
                        root,
                        subject_path=subject,
                        prompt="Review hard.",
                        transport="manual",
                    )
            finally:
                if parent.is_symlink():
                    parent.unlink()
                elif parent.exists():
                    os.rmdir(parent)
                if original_parent.exists():
                    original_parent.rename(parent)

            bridge_root = root / "exports" / "review_bridge"
            for directory_name in ("jobs", "tmp"):
                directory = bridge_root / directory_name
                self.assertFalse(directory.exists() and any(directory.iterdir()))
            self.assertFalse(any(root.rglob(review_bridge_module.REVIEW_CAPSULE_NAME)))
            self.assertFalse(any(root.rglob("subject.zip")))

    def test_subject_directory_to_file_swap_during_prepare_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Original\n", encoding="utf-8")
            original_snapshot = review_bridge_module._snapshot_subject

            def snapshot_then_replace(*args: object, **kwargs: object) -> object:
                result = original_snapshot(*args, **kwargs)
                shutil.rmtree(subject)
                subject.write_text("replacement file\n", encoding="utf-8")
                return result

            with patch.object(
                review_bridge_module,
                "_snapshot_subject",
                side_effect=snapshot_then_replace,
            ), self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "type|identity|changed",
            ):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                )

            bridge_root = root / "exports" / "review_bridge"
            for directory_name in ("jobs", "tmp"):
                directory = bridge_root / directory_name
                self.assertFalse(directory.exists() and any(directory.iterdir()))
            self.assertFalse(any(root.rglob(review_bridge_module.REVIEW_CAPSULE_NAME)))

    def test_text_sampling_reads_only_limit_plus_one(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            path = Path(tmp) / "large.txt"
            path.write_text("A" * 524_293, encoding="utf-8")
            real_reader = review_bridge_module._read_regular_file_prefix
            requested_sizes: list[int] = []

            def recording_reader(candidate: Path, max_bytes: int) -> bytes:
                requested_sizes.append(max_bytes)
                return real_reader(candidate, max_bytes)

            with patch.object(
                review_bridge_module,
                "_read_regular_file_prefix",
                side_effect=recording_reader,
            ):
                text, truncated = review_bridge_module._read_text_sample(path, 1)

            self.assertEqual(text, "A")
            self.assertTrue(truncated)
            self.assertEqual(requested_sizes, [2])

    def test_total_subject_budget_rejects_before_publishing_job_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "a.txt").write_bytes(b"A" * 6)
            (subject / "b.txt").write_bytes(b"B" * 6)

            with self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "subject total byte limit exceeded",
            ):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                    max_subject_file_bytes=8,
                    max_subject_bytes=10,
                )

            jobs_dir = root / "exports" / "review_bridge" / "jobs"
            self.assertFalse(jobs_dir.exists() and any(jobs_dir.iterdir()))

    def test_packet_hard_limit_includes_prompt_manifest_and_git_metadata(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            subject = Path(tmp) / "subject"
            subject.mkdir()
            target = subject / "large.txt"
            target.write_text("file-content-" * 100, encoding="utf-8")
            manifest = [
                {
                    "path": "large.txt",
                    "size_bytes": target.stat().st_size,
                    "sha256": "a" * 64,
                    "text_candidate": True,
                }
            ]
            packet_limit = 128

            packet, warnings, coverage = review_bridge_module._build_packet(
                subject=subject,
                manifest=manifest,
                git_info={
                    "is_git_repo": True,
                    "branch": "branch-" * 100,
                    "status": "status-" * 100,
                    "diff": "diff-" * 100,
                },
                prompt="objective-" * 100,
                max_packet_bytes=packet_limit,
                max_file_bytes=64,
            )

            self.assertLessEqual(len(packet.encode("utf-8")), packet_limit)
            self.assertEqual(coverage["packet_bytes"], len(packet.encode("utf-8")))
            self.assertEqual(coverage["packet_limit_bytes"], packet_limit)
            self.assertTrue(warnings)

    def test_late_preparation_failure_removes_published_and_staged_job(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")

            with patch.object(
                review_bridge_module,
                "_write_review_capsule",
                side_effect=review_bridge_module.ReviewBridgeError(
                    "synthetic late preparation failure"
                ),
            ), self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "synthetic late preparation failure",
            ):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                )

            bridge_root = root / "exports" / "review_bridge"
            for directory_name in ("jobs", "tmp"):
                directory = bridge_root / directory_name
                self.assertFalse(directory.exists() and any(directory.iterdir()))
            self.assertFalse(any(root.rglob(review_bridge_module.REVIEW_CAPSULE_NAME)))

    def test_traversal_entry_budget_bounds_prepare_and_currentness(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum-current"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
                max_files=1,
            )

            for index in range(1_000):
                (subject / f"empty-{index:04d}").mkdir()

            current = review_check_current(root, job_id=job["job_id"])
            self.assertFalse(current["current"])
            self.assertEqual(current["reason"], "subject_cannot_be_enumerated_safely")
            self.assertIn("traversal entry limit exceeded", current["detail"])

            prepare_root = base / "continuum-prepare"
            with self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "traversal entry limit exceeded",
            ):
                create_review_job(
                    prepare_root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                    max_files=1,
                )
            jobs_dir = prepare_root / "exports" / "review_bridge" / "jobs"
            self.assertFalse(jobs_dir.exists() and any(jobs_dir.iterdir()))

    def test_currentness_reports_invalid_stored_review_limits(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )
            invalid_job = review_bridge_module._load_job(root, job["job_id"])
            invalid_job["max_files"] = 0

            with patch.object(
                review_bridge_module,
                "_load_job",
                return_value=invalid_job,
            ):
                current = review_check_current(root, job_id=job["job_id"])

            self.assertFalse(current["current"])
            self.assertEqual(current["reason"], "stored_review_limits_invalid")

    def test_combined_entry_ceiling_fails_before_snapshot_copy(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            for index in range(4):
                (subject / f"empty-{index}").mkdir()

            with patch.object(
                review_bridge_module,
                "REVIEW_ZIP_SCAN_MAX_MEMBERS",
                3,
            ), patch.object(
                review_bridge_module,
                "_copy_snapshot_files",
                side_effect=AssertionError("snapshot copy must not begin"),
            ) as copy_snapshot, self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "file and directory entry limit exceeded",
            ):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                )

            copy_snapshot.assert_not_called()
            jobs_dir = root / "exports" / "review_bridge" / "jobs"
            self.assertFalse(jobs_dir.exists() and any(jobs_dir.iterdir()))

    def test_prompt_and_cross_limit_preflight_precede_cli_and_mcp_guards(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            prompt_file = base / "oversized-prompt.txt"
            prompt_file.write_bytes(
                b"A" * (review_bridge_module.REVIEW_MAX_PROMPT_BYTES + 1)
            )

            with patch.object(cli_module, "guarded_result") as cli_guard, patch.object(
                cli_module,
                "emit",
            ):
                self.assertEqual(
                    cli_module.main(
                        [
                            "review-prepare",
                            "--root",
                            str(root),
                            "--subject",
                            str(subject),
                            "--prompt-file",
                            str(prompt_file),
                        ]
                    ),
                    1,
                )
                cli_guard.assert_not_called()

            with patch.object(cli_module, "guarded_result") as cli_guard, patch.object(
                cli_module,
                "emit",
            ):
                self.assertEqual(
                    cli_module.main(
                        [
                            "review-prepare",
                            "--root",
                            str(root),
                            "--subject",
                            str(subject),
                            "--prompt",
                            "Review hard.",
                            "--max-subject-file-bytes",
                            "2",
                            "--max-subject-bytes",
                            "1",
                        ]
                    ),
                    1,
                )
                cli_guard.assert_not_called()

            with patch.dict(
                os.environ,
                {"CONTINUUM_MCP_ALLOW_ANY_PATH": "1"},
            ), patch.object(mcp_server_module, "guarded_tool") as mcp_guard, self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "review prompt exceeds",
            ):
                mcp_server_module.tool_review_prepare(
                    {
                        "root": str(root),
                        "subject": str(subject),
                        "prompt": "A"
                        * (review_bridge_module.REVIEW_MAX_PROMPT_BYTES + 1),
                    }
                )
            mcp_guard.assert_not_called()
            self.assertFalse(root.exists())

    def test_prepare_controls_are_bounded_before_operation_mutation(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            cases = (
                ("slash-operation", {"operation_id": "bad/id"}, "portable"),
                ("reserved-operation", {"operation_id": "CON"}, "portable"),
                ("long-operation", {"operation_id": "a" * 129}, "portable"),
                (
                    "reviewer",
                    {
                        "reviewer_id": "r"
                        * (review_bridge_module.REVIEW_MAX_REVIEWER_ID_BYTES + 1)
                    },
                    "reviewer_id exceeds",
                ),
                (
                    "model",
                    {
                        "model": "m"
                        * (review_bridge_module.REVIEW_MAX_MODEL_BYTES + 1)
                    },
                    "review model exceeds",
                ),
                (
                    "base-url",
                    {
                        "base_url": "b"
                        * (review_bridge_module.REVIEW_MAX_BASE_URL_BYTES + 1)
                    },
                    "base_url exceeds",
                ),
                ("transport-type", {"transport": 0}, "must be text"),
                (
                    "allowlist-files",
                    {
                        "secret_allowlist_files": [base / "unused"]
                        * (review_bridge_module.REVIEW_SECRET_ALLOWLIST_MAX_FILES + 1)
                    },
                    "too many files",
                ),
                (
                    "allowlist-entry-type",
                    {"secret_allowlist_patterns": [0]},
                    "entries must be text or fingerprint objects",
                ),
                (
                    "allowlist-entry-bytes",
                    {
                        "secret_allowlist_patterns": [
                            "x"
                            * (
                                review_bridge_module.REVIEW_SECRET_ALLOWLIST_MAX_ENTRY_BYTES
                                + 1
                            )
                        ]
                    },
                    "entry exceeds its byte limit",
                ),
                (
                    "nonlinear-pattern",
                    {
                        "secret_allowlist_patterns": [
                            r"^fixture\.py:1:(a+)+$"
                        ]
                    },
                    "linear literal",
                ),
            )
            for label, overrides, message in cases:
                with self.subTest(label=label):
                    root = base / f"continuum-{label}"
                    with patch.object(
                        review_bridge_module,
                        "operation_lock",
                        side_effect=AssertionError(
                            "operation lock must not be entered"
                        ),
                    ), self.assertRaisesRegex(
                        review_bridge_module.ReviewBridgeError,
                        message,
                    ):
                        controls = {"transport": "manual", **overrides}
                        create_review_job(
                            root,
                            subject_path=subject,
                            prompt="Review hard.",
                            **controls,
                        )
                    self.assertFalse(root.exists())

            allowlist_a = base / "allowlist-a.txt"
            allowlist_b = base / "allowlist-b.txt"
            allowlist_a.write_text("# a\n", encoding="utf-8")
            allowlist_b.write_text("# b\n", encoding="utf-8")
            aggregate_root = base / "continuum-aggregate"
            with patch.object(
                review_bridge_module,
                "REVIEW_SECRET_ALLOWLIST_MAX_TOTAL_FILE_BYTES",
                6,
            ), patch.object(
                review_bridge_module,
                "operation_lock",
                side_effect=AssertionError("operation lock must not be entered"),
            ), self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "aggregate byte limit",
            ):
                create_review_job(
                    aggregate_root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                    secret_allowlist_files=[allowlist_a, allowlist_b],
                )
            self.assertFalse(aggregate_root.exists())

    def test_cli_and_mcp_prepare_controls_fail_before_guards(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            oversized_reviewer = "r" * (
                review_bridge_module.REVIEW_MAX_REVIEWER_ID_BYTES + 1
            )

            with patch.object(cli_module, "guarded_result") as cli_guard, patch.object(
                cli_module,
                "emit",
            ):
                self.assertEqual(
                    cli_module.main(
                        [
                            "review-prepare",
                            "--root",
                            str(root),
                            "--subject",
                            str(subject),
                            "--prompt",
                            "Review hard.",
                            "--reviewer-id",
                            oversized_reviewer,
                        ]
                    ),
                    1,
                )
                cli_guard.assert_not_called()

            with patch.dict(
                os.environ,
                {"CONTINUUM_MCP_ALLOW_ANY_PATH": "1"},
            ), patch.object(
                mcp_server_module,
                "guarded_tool",
            ) as mcp_guard, self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "reviewer_id exceeds",
            ):
                mcp_server_module.tool_review_prepare(
                    {
                        "root": str(root),
                        "subject": str(subject),
                        "prompt": "Review hard.",
                        "reviewer_id": oversized_reviewer,
                    }
                )
            mcp_guard.assert_not_called()
            self.assertFalse(root.exists())

            malformed_prompt_file = base / "malformed-prompt.txt"
            malformed_prompt_file.write_bytes(b"review\xffprompt")
            with patch.object(cli_module, "guarded_result") as cli_guard, patch.object(
                cli_module,
                "emit",
            ):
                self.assertEqual(
                    cli_module.main(
                        [
                            "review-prepare",
                            "--root",
                            str(root),
                            "--subject",
                            str(subject),
                            "--prompt-file",
                            str(malformed_prompt_file),
                        ]
                    ),
                    1,
                )
                cli_guard.assert_not_called()

            with patch.dict(
                os.environ,
                {"CONTINUUM_MCP_ALLOW_ANY_PATH": "1"},
            ), patch.object(mcp_server_module, "guarded_tool") as mcp_guard, self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "valid UTF-8 text",
            ):
                mcp_server_module.tool_review_prepare(
                    {
                        "root": str(root),
                        "subject": str(subject),
                        "prompt": "review\ud800prompt",
                    }
                )
            mcp_guard.assert_not_called()
            self.assertFalse(root.exists())

    def test_capsule_rejects_snapshot_drift_before_atomic_publication(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("ORIGINAL\n", encoding="utf-8")
            original_write_capsule = review_bridge_module._write_review_capsule

            def mutate_snapshot_before_capsule(
                job_dir: Path,
                job: dict,
                snapshot_subject: Path,
                snapshot_files: list[Path],
                snapshot_directories: list[Path],
                snapshot_manifest: list[dict],
                manifest_path: Path,
                **kwargs: object,
            ) -> tuple[Path, str]:
                jobs_dir = root / "exports" / "review_bridge" / "jobs"
                self.assertFalse(jobs_dir.exists() and any(jobs_dir.iterdir()))
                snapshot_files[0].write_text("MUTATED\n", encoding="utf-8")
                return original_write_capsule(
                    job_dir,
                    job,
                    snapshot_subject,
                    snapshot_files,
                    snapshot_directories,
                    snapshot_manifest,
                    manifest_path,
                    **kwargs,
                )

            with patch.object(
                review_bridge_module,
                "_write_review_capsule",
                side_effect=mutate_snapshot_before_capsule,
            ), self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "no longer matches its manifest",
            ):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                )

            bridge_root = root / "exports" / "review_bridge"
            for directory_name in ("jobs", "tmp"):
                directory = bridge_root / directory_name
                self.assertFalse(directory.exists() and any(directory.iterdir()))
            self.assertFalse(any(root.rglob(review_bridge_module.REVIEW_CAPSULE_NAME)))

    def test_prepare_recovery_rolls_back_unmarked_incomplete_staging(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            review_bridge_module.init_db(root)
            stale = (
                review_bridge_module.review_bridge_root(root)
                / "tmp"
                / "review-interrupted-before-ready"
            )
            stale.mkdir(parents=True)
            (stale / "partial.txt").write_text("partial\n", encoding="utf-8")

            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )

            self.assertFalse(stale.exists())
            self.assertIn(
                "rolled_back_incomplete_staging",
                {
                    item["outcome"]
                    for item in job["reconciled_preparations"]
                },
            )

    def test_prepare_recovery_finalizes_catalog_bound_staging(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            seed = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )
            staging_dir, plan = stage_completed_review_job_for_recovery(
                root,
                seed,
            )
            marker_path, _marker_sha256 = (
                review_bridge_module._catalog_review_prepare_marker(
                    root,
                    staging_dir,
                    job_id=seed["job_id"],
                    operation_id="crashed-prepare-operation",
                    plan=plan,
                )
            )

            replacement = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )

            recovered = [
                item
                for item in replacement["reconciled_preparations"]
                if item.get("job_id") == seed["job_id"]
            ]
            self.assertEqual(
                recovered[0]["outcome"],
                "recovered_staged_publication",
            )
            self.assertFalse(marker_path.exists())
            integrity = review_bridge_module.review_bridge_integrity_report(
                root,
                job_id=seed["job_id"],
            )
            self.assertTrue(integrity["ok"], integrity)
            conn = connect(root)
            try:
                recovered_rows = review_bridge_module._review_job_artifact_rows(
                    root,
                    seed["job_id"],
                    conn=conn,
                )
            finally:
                conn.close()
            self.assertTrue(recovered_rows)
            self.assertEqual(
                {row["operation_id"] for row in recovered_rows},
                {"crashed-prepare-operation"},
            )

    def test_prepare_recovery_finalizes_published_tree_before_catalog_commit(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            seed = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )
            staging_dir, plan = stage_completed_review_job_for_recovery(
                root,
                seed,
            )
            marker_path, _marker_sha256 = (
                review_bridge_module._catalog_review_prepare_marker(
                    root,
                    staging_dir,
                    job_id=seed["job_id"],
                    operation_id="crashed-after-rename-operation",
                    plan=plan,
                )
            )
            published_dir = review_bridge_module.review_job_dir(
                root,
                seed["job_id"],
            )
            staging_dir.rename(published_dir)

            replacement = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )

            recovered = [
                item
                for item in replacement["reconciled_preparations"]
                if item.get("job_id") == seed["job_id"]
            ]
            self.assertEqual(
                recovered[0]["outcome"],
                "recovered_published_catalog",
            )
            self.assertFalse(marker_path.exists())
            integrity = review_bridge_module.review_bridge_integrity_report(
                root,
                job_id=seed["job_id"],
            )
            self.assertTrue(integrity["ok"], integrity)

    def test_prepare_recovery_cleans_only_post_commit_marker(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            seed = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )
            job_dir = Path(seed["job_dir"])
            conn = connect(root)
            try:
                rows = review_bridge_module._review_job_artifact_rows(
                    root,
                    seed["job_id"],
                    conn=conn,
                )
            finally:
                conn.close()
            prefix = review_bridge_module._root_uri(root, job_dir) + "/"
            plan = review_bridge_module._review_prepare_artifact_plan(
                job_dir,
                seed["job_id"],
                [
                    (
                        job_dir.joinpath(
                            *Path(str(row["uri"])[len(prefix) :]).parts
                        ),
                        str(row["kind"]),
                        bool(row["immutable"]),
                    )
                    for row in rows
                ],
            )
            marker_path = review_bridge_module._review_prepare_marker_path(
                root,
                seed["job_id"],
            )
            review_bridge_module.secure_write_text(
                marker_path,
                review_bridge_module.json_dumps(
                    {
                        "schema": review_bridge_module.REVIEW_PREPARE_PUBLICATION_MARKER_SCHEMA,
                        "job_id": seed["job_id"],
                        "producer_operation_id": "committed-prepare-operation",
                        "artifacts": plan,
                    }
                ),
            )
            job_bytes_before = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file()
            }

            replacement = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )

            recovered = [
                item
                for item in replacement["reconciled_preparations"]
                if item.get("job_id") == seed["job_id"]
            ]
            self.assertEqual(
                recovered[0]["outcome"],
                "cleaned_post_commit_marker",
            )
            self.assertFalse(marker_path.exists())
            self.assertEqual(
                {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file()
                },
                job_bytes_before,
            )

    def test_prepare_recovery_preserves_tampered_bound_state(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            seed = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )
            staging_dir, plan = stage_completed_review_job_for_recovery(
                root,
                seed,
            )
            marker_path, _marker_sha256 = (
                review_bridge_module._catalog_review_prepare_marker(
                    root,
                    staging_dir,
                    job_id=seed["job_id"],
                    operation_id="tampered-prepare-operation",
                    plan=plan,
                )
            )
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            marker["artifacts"][0]["sha256"] = "0" * 64
            marker_path.write_text(
                review_bridge_module.json_dumps(marker),
                encoding="utf-8",
            )
            marker_bytes = marker_path.read_bytes()

            with self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "authority drifted",
            ):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                )

            self.assertTrue(staging_dir.is_dir())
            self.assertEqual(marker_path.read_bytes(), marker_bytes)

    def test_prepare_catalog_state_requires_exact_marker_binding(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            seed = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )
            staging_dir, plan = stage_completed_review_job_for_recovery(root, seed)
            marker_path, _marker_sha256 = (
                review_bridge_module._catalog_review_prepare_marker(
                    root,
                    staging_dir,
                    job_id=seed["job_id"],
                    operation_id="marker-binding-operation",
                    plan=plan,
                )
            )

            self.assertEqual(
                review_bridge_module._review_prepare_catalog_state(
                    root,
                    job_id=seed["job_id"],
                    marker_path=marker_path,
                ),
                "uncommitted",
            )
            marker = json.loads(marker_path.read_text(encoding="utf-8"))
            marker["artifacts"][0]["sha256"] = "0" * 64
            marker_path.write_text(
                review_bridge_module.json_dumps(marker),
                encoding="utf-8",
            )
            self.assertEqual(
                review_bridge_module._review_prepare_catalog_state(
                    root,
                    job_id=seed["job_id"],
                    marker_path=marker_path,
                ),
                "unknown",
            )

    def test_concurrent_review_prepares_are_serialized_and_integral(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")

            with ThreadPoolExecutor(max_workers=2) as executor:
                jobs = list(
                    executor.map(
                        lambda index: create_review_job(
                            root,
                            subject_path=subject,
                            prompt=f"Review hard {index}.",
                            transport="manual",
                        ),
                        range(2),
                    )
                )

            self.assertEqual(len({job["job_id"] for job in jobs}), 2)
            for job in jobs:
                integrity = review_bridge_module.review_bridge_integrity_report(
                    root,
                    job_id=job["job_id"],
                )
                self.assertTrue(integrity["ok"], integrity)

    def test_prepare_post_commit_failure_preserves_committed_job(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            original_connect = review_bridge_module.connect
            proxies: list[CommitThenRaiseConnection] = []

            def ambiguous_connect(active_root: Path) -> CommitThenRaiseConnection:
                proxy = CommitThenRaiseConnection(original_connect(active_root))
                proxies.append(proxy)
                return proxy

            with patch.object(
                review_bridge_module,
                "connect",
                side_effect=ambiguous_connect,
            ), self.assertRaisesRegex(
                RuntimeError,
                "ambiguous post-commit",
            ):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                )

            self.assertTrue(any(proxy.raised for proxy in proxies))
            jobs = list(
                (review_bridge_module.review_bridge_root(root) / "jobs").iterdir()
            )
            self.assertEqual(len(jobs), 1)
            job_id = jobs[0].name
            marker_path = review_bridge_module._review_prepare_marker_path(
                root,
                job_id,
            )
            self.assertTrue(marker_path.is_file())
            with self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "publication is not committed yet",
            ):
                review_job_status(root, job_id=job_id)
            conn = connect(root)
            try:
                self.assertFalse(
                    review_bridge_module._review_prepare_marker_rows(
                        conn,
                        root,
                        marker_path,
                    )
                )
                self.assertTrue(
                    review_bridge_module._review_job_artifact_rows(
                        root,
                        job_id,
                        conn=conn,
                    )
                )
            finally:
                conn.close()

            replacement = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard again.",
                transport="manual",
            )
            self.assertIn(
                "cleaned_post_commit_marker",
                {
                    item["outcome"]
                    for item in replacement["reconciled_preparations"]
                    if item.get("job_id") == job_id
                },
            )
            self.assertFalse(marker_path.exists())
            self.assertEqual(review_job_status(root, job_id=job_id)["status"], "prepared")

    def test_prepare_unknown_post_commit_state_preserves_publication_authority(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            original_connect = review_bridge_module.connect
            proxies: list[CommitThenRaiseConnection] = []

            def ambiguous_connect(active_root: Path) -> CommitThenRaiseConnection:
                proxy = CommitThenRaiseConnection(original_connect(active_root))
                proxies.append(proxy)
                return proxy

            with patch.object(
                review_bridge_module,
                "connect",
                side_effect=ambiguous_connect,
            ), patch.object(
                review_bridge_module,
                "_review_prepare_catalog_state",
                return_value="unknown",
            ), self.assertRaisesRegex(
                RuntimeError,
                "ambiguous post-commit",
            ):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                )

            self.assertTrue(any(proxy.raised for proxy in proxies))
            jobs = list(
                (review_bridge_module.review_bridge_root(root) / "jobs").iterdir()
            )
            self.assertEqual(len(jobs), 1)
            marker_path = review_bridge_module._review_prepare_marker_path(
                root,
                jobs[0].name,
            )
            self.assertTrue(jobs[0].is_dir())
            self.assertTrue(marker_path.is_file())

            replacement = create_review_job(
                root,
                subject_path=subject,
                prompt="Recover the ambiguous publication.",
                transport="manual",
            )
            self.assertTrue(replacement["ok"])
            self.assertFalse(marker_path.exists())
            self.assertEqual(
                review_job_status(root, job_id=jobs[0].name)["status"],
                "prepared",
            )

    def test_prepare_post_rename_cleanup_failure_preserves_marker_and_tree(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            original_remove = review_bridge_module._remove_plain_review_prepare_tree

            def fail_finalization(*args: object, **kwargs: object) -> object:
                raise RuntimeError("injected post-rename finalization failure")

            def fail_published_cleanup(
                active_root: Path,
                path: Path,
            ) -> None:
                if Path(path).parent.name == "jobs":
                    raise review_bridge_module.ReviewBridgeError(
                        "injected published cleanup failure"
                    )
                original_remove(active_root, path)

            with patch.object(
                review_bridge_module,
                "_finalize_review_prepare_publication",
                side_effect=fail_finalization,
            ), patch.object(
                review_bridge_module,
                "_remove_plain_review_prepare_tree",
                side_effect=fail_published_cleanup,
            ), self.assertRaisesRegex(
                RuntimeError,
                "post-rename finalization failure",
            ):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                )

            jobs = list(
                (review_bridge_module.review_bridge_root(root) / "jobs").iterdir()
            )
            self.assertEqual(len(jobs), 1)
            marker_path = review_bridge_module._review_prepare_marker_path(
                root,
                jobs[0].name,
            )
            self.assertTrue(jobs[0].is_dir())
            self.assertTrue(marker_path.is_file())
            conn = connect(root)
            try:
                self.assertTrue(
                    review_bridge_module._review_prepare_marker_rows(
                        conn,
                        root,
                        marker_path,
                    )
                )
                self.assertFalse(
                    review_bridge_module._review_job_artifact_rows(
                        root,
                        jobs[0].name,
                        conn=conn,
                    )
                )
            finally:
                conn.close()

    def test_recovered_post_commit_failure_never_reverses_durable_publication(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            seed = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )
            staging_dir, plan = stage_completed_review_job_for_recovery(root, seed)
            marker_path, _marker_sha256 = (
                review_bridge_module._catalog_review_prepare_marker(
                    root,
                    staging_dir,
                    job_id=seed["job_id"],
                    operation_id="recovery-post-commit-operation",
                    plan=plan,
                )
            )
            published_dir = review_bridge_module.review_job_dir(
                root,
                seed["job_id"],
            )
            review_bridge_module._rename_review_prepare_tree(
                root,
                staging_dir,
                published_dir,
            )
            original_connect = review_bridge_module.connect
            proxies: list[CommitThenRaiseConnection] = []

            def ambiguous_connect(active_root: Path) -> CommitThenRaiseConnection:
                proxy = CommitThenRaiseConnection(original_connect(active_root))
                proxies.append(proxy)
                return proxy

            with patch.object(
                review_bridge_module,
                "connect",
                side_effect=ambiguous_connect,
            ), self.assertRaisesRegex(
                RuntimeError,
                "ambiguous post-commit",
            ):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Trigger recovery.",
                    transport="manual",
                )

            self.assertTrue(any(proxy.raised for proxy in proxies))
            self.assertTrue(published_dir.is_dir())
            self.assertFalse(staging_dir.exists())
            self.assertTrue(marker_path.is_file())
            conn = connect(root)
            try:
                self.assertFalse(
                    review_bridge_module._review_prepare_marker_rows(
                        conn,
                        root,
                        marker_path,
                    )
                )
                self.assertTrue(
                    review_bridge_module._review_job_artifact_rows(
                        root,
                        seed["job_id"],
                        conn=conn,
                    )
                )
            finally:
                conn.close()

            replacement = create_review_job(
                root,
                subject_path=subject,
                prompt="Finish recovery.",
                transport="manual",
            )
            self.assertIn(
                "cleaned_post_commit_marker",
                {
                    item["outcome"]
                    for item in replacement["reconciled_preparations"]
                    if item.get("job_id") == seed["job_id"]
                },
            )
            integrity = review_bridge_module.review_bridge_integrity_report(
                root,
                job_id=seed["job_id"],
            )
            self.assertTrue(integrity["ok"], integrity)

    def test_public_job_operations_reject_renamed_uncommitted_job(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            seed = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )
            staging_dir, plan = stage_completed_review_job_for_recovery(root, seed)
            marker_path, _marker_sha256 = (
                review_bridge_module._catalog_review_prepare_marker(
                    root,
                    staging_dir,
                    job_id=seed["job_id"],
                    operation_id="pending-publication-operation",
                    plan=plan,
                )
            )
            published_dir = review_bridge_module.review_job_dir(
                root,
                seed["job_id"],
            )
            review_bridge_module._rename_review_prepare_tree(
                root,
                staging_dir,
                published_dir,
            )
            status_before = (published_dir / "status.json").read_bytes()

            for operation in (
                lambda: review_job_status(root, job_id=seed["job_id"]),
                lambda: review_browser_attempt_start(
                    root,
                    job_id=seed["job_id"],
                ),
            ):
                with self.assertRaisesRegex(
                    review_bridge_module.ReviewBridgeError,
                    "publication is not committed yet",
                ):
                    operation()
            self.assertEqual(
                (published_dir / "status.json").read_bytes(),
                status_before,
            )
            self.assertTrue(marker_path.is_file())

            replacement = create_review_job(
                root,
                subject_path=subject,
                prompt="Recover publication.",
                transport="manual",
            )
            self.assertIn(
                "recovered_published_catalog",
                {
                    item["outcome"]
                    for item in replacement["reconciled_preparations"]
                    if item.get("job_id") == seed["job_id"]
                },
            )

    def test_prepare_reconciles_catalog_marker_when_tmp_is_absent(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            review_bridge_module.init_db(root)
            missing_job_id = "review-missing-marker-file"
            missing_uri = (
                f"exports/review_bridge/tmp/{missing_job_id}.ready.json"
            )
            conn = connect(root)
            try:
                record_artifact(
                    conn,
                    kind=review_bridge_module.REVIEW_PREPARE_PUBLICATION_MARKER_KIND,
                    uri=missing_uri,
                    sha256="0" * 64,
                    size_bytes=1,
                    operation_id="missing-marker-operation",
                    immutable=False,
                    source_type="review_prepare_transaction",
                    trust_level="local_generated",
                    metadata={
                        "job_id": missing_job_id,
                        "schema": review_bridge_module.REVIEW_PREPARE_PUBLICATION_MARKER_SCHEMA,
                    },
                )
                conn.commit()
            finally:
                conn.close()
            self.assertFalse(
                (review_bridge_module.review_bridge_root(root) / "tmp").exists()
            )

            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )

            self.assertIn(
                "retired_missing_marker_authority",
                {
                    item["outcome"]
                    for item in job["reconciled_preparations"]
                    if item.get("job_id") == missing_job_id
                },
            )

    def test_prepare_publication_budget_covers_plan_and_finalization(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            staging = base / "standalone-stage"
            staging.mkdir()
            artifact = staging / "artifact.txt"
            artifact.write_text("artifact\n", encoding="utf-8")
            expired = review_bridge_module.ReviewPreparationBudget(
                max_subject_file_bytes=1_000_000,
                max_subject_bytes=1_000_000,
                max_archive_bytes=1_000_000,
                max_temporary_bytes=1_000_000,
                max_work_bytes=1_000_000,
                deadline=time.monotonic() - 1,
            )
            with self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "elapsed-time budget",
            ):
                review_bridge_module._review_prepare_artifact_plan(
                    staging,
                    "review-expired-plan",
                    [(artifact, "review_packet", True)],
                    budget=expired,
                )

            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            seed = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )
            staging_dir, plan = stage_completed_review_job_for_recovery(root, seed)
            marker_path, _marker_sha256 = (
                review_bridge_module._catalog_review_prepare_marker(
                    root,
                    staging_dir,
                    job_id=seed["job_id"],
                    operation_id="expired-finalize-operation",
                    plan=plan,
                )
            )
            published_dir = review_bridge_module.review_job_dir(
                root,
                seed["job_id"],
            )
            review_bridge_module._rename_review_prepare_tree(
                root,
                staging_dir,
                published_dir,
            )
            with self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "elapsed-time budget",
            ):
                review_bridge_module._finalize_review_prepare_publication(
                    root,
                    job_id=seed["job_id"],
                    marker_path=marker_path,
                    budget=expired,
                )
            conn = connect(root)
            try:
                self.assertTrue(
                    review_bridge_module._review_prepare_marker_rows(
                        conn,
                        root,
                        marker_path,
                    )
                )
                self.assertFalse(
                    review_bridge_module._review_job_artifact_rows(
                        root,
                        seed["job_id"],
                        conn=conn,
                    )
                )
            finally:
                conn.close()

    def test_prepare_durability_flushes_files_and_directories_bottom_up(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            staging = base / "tmp" / "review-stage"
            nested = staging / "nested" / "deeper"
            nested.mkdir(parents=True)
            artifact = nested / "artifact.txt"
            artifact.write_text("artifact\n", encoding="utf-8")
            flushed_files: list[Path] = []
            flushed_directories: list[Path] = []
            budget = review_bridge_module.ReviewPreparationBudget(
                max_subject_file_bytes=1_000_000,
                max_subject_bytes=1_000_000,
                max_archive_bytes=1_000_000,
                max_temporary_bytes=1_000_000,
                max_work_bytes=1_000_000,
                deadline=time.monotonic() + 30,
            )

            with patch.object(
                review_bridge_module,
                "_flush_review_prepare_file",
                side_effect=flushed_files.append,
            ), patch.object(
                review_bridge_module,
                "_flush_review_prepare_directory",
                side_effect=flushed_directories.append,
            ):
                review_bridge_module._durably_flush_review_prepare_tree(
                    staging,
                    budget=budget,
                )

            self.assertEqual(flushed_files, [artifact])
            self.assertEqual(
                flushed_directories,
                [nested, nested.parent, staging, staging.parent],
            )

    def test_prepare_durability_failure_precedes_publication_authority(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")

            with patch.object(
                review_bridge_module,
                "_durably_flush_review_prepare_tree",
                side_effect=review_bridge_module.ReviewBridgeError(
                    "synthetic durability failure"
                ),
            ), patch.object(
                review_bridge_module,
                "_catalog_review_prepare_marker",
            ) as catalog_marker, self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "synthetic durability failure",
            ):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                )

            catalog_marker.assert_not_called()
            bridge_root = root / "exports" / "review_bridge"
            self.assertFalse(
                (bridge_root / "jobs").exists()
                and any((bridge_root / "jobs").iterdir())
            )
            self.assertFalse(
                (bridge_root / "tmp").exists()
                and any((bridge_root / "tmp").iterdir())
            )

    def test_review_publication_authority_uses_full_sqlite_durability(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            original_configure = (
                review_bridge_module._configure_review_prepare_catalog_durability
            )
            observed_levels: list[int] = []

            def configure_and_record(connection: object) -> None:
                self.assertFalse(connection.in_transaction)  # type: ignore[attr-defined]
                original_configure(connection)
                row = connection.execute(  # type: ignore[attr-defined]
                    "PRAGMA synchronous"
                ).fetchone()
                observed_levels.append(int(row[0]))

            with patch.object(
                review_bridge_module,
                "_configure_review_prepare_catalog_durability",
                side_effect=configure_and_record,
            ):
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="manual",
                )

            self.assertEqual(observed_levels, [2, 2])

    def test_known_uncommitted_marker_authority_can_be_durably_discarded(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            seed = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )
            staging_dir, plan = stage_completed_review_job_for_recovery(root, seed)
            marker_path, marker_sha256 = (
                review_bridge_module._catalog_review_prepare_marker(
                    root,
                    staging_dir,
                    job_id=seed["job_id"],
                    operation_id="discard-uncommitted-marker",
                    plan=plan,
                )
            )
            review_bridge_module._remove_plain_review_prepare_tree(
                root,
                staging_dir,
            )

            self.assertTrue(
                review_bridge_module._discard_review_prepare_marker_authority(
                    root,
                    marker_path,
                    marker_sha256,
                )
            )
            self.assertFalse(marker_path.exists())
            conn = connect(root)
            try:
                self.assertEqual(
                    review_bridge_module._review_prepare_marker_rows(
                        conn,
                        root,
                        marker_path,
                    ),
                    [],
                )
            finally:
                conn.close()

    def test_prepare_cleanup_rejects_swapped_tmp_ancestor(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            review_bridge_module.init_db(root)
            tmp_root = review_bridge_module.review_bridge_root(root) / "tmp"
            stale_job_id = "review-interrupted-ancestor-swap"
            stale = tmp_root / stale_job_id
            stale.mkdir(parents=True)
            (stale / "partial.txt").write_text("partial\n", encoding="utf-8")
            saved_tmp = tmp_root.with_name("tmp-original")
            external_tmp = base / "external-tmp"
            external_stale = external_tmp / stale_job_id
            external_stale.mkdir(parents=True)
            sentinel = external_stale / "sentinel.txt"
            sentinel.write_text("preserve me\n", encoding="utf-8")
            original_rows = review_bridge_module._review_job_artifact_rows
            swapped = False

            def swap_before_cleanup(*args: object, **kwargs: object) -> object:
                nonlocal swapped
                if not swapped:
                    tmp_root.rename(saved_tmp)
                    make_link_like_directory(self, tmp_root, external_tmp)
                    swapped = True
                return original_rows(*args, **kwargs)

            try:
                with patch.object(
                    review_bridge_module,
                    "_review_job_artifact_rows",
                    side_effect=swap_before_cleanup,
                ), self.assertRaisesRegex(
                    review_bridge_module.ReviewBridgeError,
                    "link-like|ancestry changed",
                ):
                    create_review_job(
                        root,
                        subject_path=subject,
                        prompt="Review hard.",
                        transport="manual",
                    )
                self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")
                self.assertTrue((saved_tmp / stale_job_id / "partial.txt").is_file())
            finally:
                if swapped and os.path.lexists(tmp_root):
                    if os.name == "nt":
                        os.rmdir(tmp_root)
                    else:
                        tmp_root.unlink()
                if saved_tmp.exists() and not tmp_root.exists():
                    saved_tmp.rename(tmp_root)

    def test_prepare_cleanup_rejects_plain_tmp_swap_and_restore(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            review_bridge_module.init_db(root)
            tmp_root = review_bridge_module.review_bridge_root(root) / "tmp"
            stale_job_id = "review-interrupted-plain-swap"
            stale = tmp_root / stale_job_id
            stale.mkdir(parents=True)
            partial = stale / "partial.txt"
            partial.write_text("partial\n", encoding="utf-8")
            saved_tmp = tmp_root.with_name("tmp-original")
            replacement_tmp = base / "replacement-tmp"
            replacement_stale = replacement_tmp / stale_job_id
            replacement_stale.mkdir(parents=True)
            sentinel = replacement_stale / "sentinel.txt"
            sentinel.write_text("preserve me\n", encoding="utf-8")
            original_open = review_bridge_module._open_plain_directory_fd
            swapped = False

            @contextmanager
            def swap_before_open(
                path: Path,
                **kwargs: object,
            ) -> object:
                nonlocal swapped
                active_path = Path(path)
                if active_path == tmp_root and not swapped:
                    tmp_root.rename(saved_tmp)
                    replacement_tmp.rename(tmp_root)
                    swapped = True
                try:
                    with original_open(active_path, **kwargs) as descriptor:
                        yield descriptor
                finally:
                    if swapped and tmp_root.exists():
                        tmp_root.rename(replacement_tmp)
                    if swapped and saved_tmp.exists() and not tmp_root.exists():
                        saved_tmp.rename(tmp_root)

            with patch.object(
                review_bridge_module,
                "_open_plain_directory_fd",
                side_effect=swap_before_open,
            ), self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "identity changed|frozen plain directory",
            ):
                review_bridge_module._remove_plain_review_prepare_tree(root, stale)

            self.assertTrue(partial.is_file())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")

    def test_snapshot_uses_review_publication_authority(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            root = Path(tmp) / "continuum"
            review_bridge_module.init_db(root)
            captured: list[tuple[Path, str, float]] = []

            @contextmanager
            def capture_lock(
                lock_root: Path,
                operation_id: str,
                *,
                timeout_seconds: float,
            ) -> object:
                captured.append((Path(lock_root), operation_id, timeout_seconds))
                yield

            with patch(
                "continuum.core.operations.operation_lock",
                side_effect=capture_lock,
            ):
                result = snapshot(root, reason="publication-lock-proof")

            self.assertTrue(Path(result["snapshot_uri"]).is_file())
            self.assertIn(
                (root, review_bridge_module.REVIEW_PREPARE_PUBLICATION_LOCK_ID, 600.0),
                captured,
            )

    def test_public_subject_path_rejects_links_and_currentness_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            target_parent = base / "target-parent"
            target = target_parent / "subject"
            target.mkdir(parents=True)
            (target / "README.md").write_text("# Linked target\n", encoding="utf-8")
            linked_parent = base / "linked-parent"
            make_link_like_directory(self, linked_parent, target_parent)
            linked_subject = linked_parent / "subject"
            rejected_root = base / "continuum-rejected"

            with self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "link-like",
            ):
                create_review_job(
                    rejected_root,
                    subject_path=linked_subject,
                    prompt="Review hard.",
                    transport="manual",
                )
            self.assertFalse(rejected_root.exists())

            with patch.object(cli_module, "guarded_result") as cli_guard, patch.object(
                cli_module,
                "emit",
            ):
                self.assertEqual(
                    cli_module.main(
                        [
                            "review-prepare",
                            "--root",
                            str(rejected_root),
                            "--subject",
                            str(linked_subject),
                            "--prompt",
                            "Review hard.",
                        ]
                    ),
                    1,
                )
                cli_guard.assert_not_called()

            with patch.dict(
                os.environ,
                {"CONTINUUM_MCP_ALLOW_ANY_PATH": "1"},
            ), patch.object(mcp_server_module, "guarded_tool") as mcp_guard, self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "link-like",
            ):
                mcp_server_module.tool_review_prepare(
                    {
                        "root": str(rejected_root),
                        "subject": str(linked_subject),
                        "prompt": "Review hard.",
                    }
                )
            mcp_guard.assert_not_called()
            self.assertFalse(rejected_root.exists())

            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Original\n", encoding="utf-8")
            root = base / "continuum-current"
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )
            shutil.rmtree(subject)
            make_link_like_directory(self, subject, target)

            current = review_check_current(root, job_id=job["job_id"])
            self.assertFalse(current["current"])
            self.assertEqual(current["reason"], "subject_path_unsafe")

    @unittest.skipUnless(os.name == "nt", "Windows Job Object containment proof")
    def test_windows_process_never_runs_when_job_containment_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            marker = base / "child-ran.txt"
            child = base / "child.py"
            child.write_text(
                "import pathlib\n"
                f"pathlib.Path({str(marker)!r}).write_text('ran', encoding='utf-8')\n",
                encoding="utf-8",
            )

            with patch.object(
                review_bridge_module,
                "_attach_windows_kill_job",
                return_value=None,
            ), self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "containment could not be established",
            ):
                review_bridge_module._run_bounded_process(
                    [sys.executable, str(child)],
                    cwd=base,
                    env=os.environ.copy(),
                    timeout_seconds=5,
                    stdout_limit=1_024,
                    stderr_limit=1_024,
                    total_limit=2_048,
                )

            self.assertFalse(marker.exists())

    def test_cli_and_mcp_share_hard_review_limit_maxima(self) -> None:
        prepare_limits = {
            "max_packet_bytes": review_bridge_module.REVIEW_MAX_PACKET_BYTES,
            "max_file_bytes": review_bridge_module.REVIEW_MAX_FILE_SAMPLE_BYTES,
            "max_files": review_bridge_module.REVIEW_MAX_FILES,
            "max_subject_file_bytes": review_bridge_module.REVIEW_MAX_SUBJECT_FILE_BYTES,
            "max_subject_bytes": review_bridge_module.REVIEW_MAX_SUBJECT_BYTES,
            "prepare_timeout_seconds": review_bridge_module.REVIEW_MAX_PREPARE_TIMEOUT_SECONDS,
        }
        transport_limits = {
            "timeout_seconds": review_bridge_module.REVIEW_MAX_RUN_TIMEOUT_SECONDS,
            "max_tokens": review_bridge_module.REVIEW_MAX_TOKENS,
        }
        prepare_schema = TOOLS["continuum_review_prepare"][1]
        run_schema = TOOLS["continuum_review_run"][1]
        browser_schema = TOOLS["continuum_review_browser_attempt_start"][1]
        for name, maximum in prepare_limits.items():
            with self.subTest(surface="mcp-prepare", name=name):
                self.assertEqual(
                    prepare_schema["properties"][name],
                    {"type": "integer", "minimum": 1, "maximum": maximum},
                )
        for name, maximum in transport_limits.items():
            with self.subTest(surface="mcp-run", name=name):
                self.assertEqual(
                    run_schema["properties"][name],
                    {"type": "integer", "minimum": 1, "maximum": maximum},
                )
        self.assertEqual(
            prepare_schema["properties"]["prompt"]["maxLength"],
            review_bridge_module.REVIEW_MAX_PROMPT_BYTES,
        )
        self.assertEqual(
            prepare_schema["properties"]["reviewer_id"]["maxLength"],
            review_bridge_module.REVIEW_MAX_REVIEWER_ID_BYTES,
        )
        self.assertEqual(
            prepare_schema["properties"]["model"]["maxLength"],
            review_bridge_module.REVIEW_MAX_MODEL_BYTES,
        )
        self.assertEqual(
            prepare_schema["properties"]["base_url"]["maxLength"],
            review_bridge_module.REVIEW_MAX_BASE_URL_BYTES,
        )
        self.assertEqual(
            run_schema["properties"]["model"]["maxLength"],
            review_bridge_module.REVIEW_MAX_MODEL_BYTES,
        )
        self.assertEqual(
            run_schema["properties"]["base_url"]["maxLength"],
            review_bridge_module.REVIEW_MAX_BASE_URL_BYTES,
        )
        self.assertEqual(
            prepare_schema["properties"]["secret_allowlist_patterns"]["maxItems"],
            review_bridge_module.REVIEW_SECRET_ALLOWLIST_MAX_PATTERNS,
        )
        self.assertEqual(
            prepare_schema["properties"]["secret_allowlist_files"]["maxItems"],
            review_bridge_module.REVIEW_SECRET_ALLOWLIST_MAX_FILES,
        )
        expected_operation_schema = {
            "type": "string",
            "minLength": 1,
            "maxLength": 128,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$",
        }
        self.assertEqual(
            run_schema["properties"]["operation_id"],
            expected_operation_schema,
        )
        self.assertEqual(
            browser_schema["properties"]["operation_id"],
            expected_operation_schema,
        )

        parser = cli_module.build_parser()
        for name, maximum in prepare_limits.items():
            flag = "--" + name.replace("_", "-")
            with self.subTest(surface="cli-prepare", name=name), patch(
                "sys.stderr",
                new=io.StringIO(),
            ), self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "review-prepare",
                        "--root",
                        "root",
                        "--subject",
                        "subject",
                        "--prompt",
                        "review",
                        flag,
                        str(maximum + 1),
                    ]
                )
        for name, maximum in transport_limits.items():
            flag = "--" + name.replace("_", "-")
            with self.subTest(surface="cli-run", name=name), patch(
                "sys.stderr",
                new=io.StringIO(),
            ), self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "review-run",
                        "--root",
                        "root",
                        "--job-id",
                        "review-test",
                        flag,
                        str(maximum + 1),
                    ]
                )
        for flag, maximum in (
            ("--model", review_bridge_module.REVIEW_MAX_MODEL_BYTES),
            ("--base-url", review_bridge_module.REVIEW_MAX_BASE_URL_BYTES),
        ):
            with self.subTest(surface="cli-run", flag=flag), patch(
                "sys.stderr",
                new=io.StringIO(),
            ), self.assertRaises(SystemExit):
                parser.parse_args(
                    [
                        "review-run",
                        "--root",
                        "root",
                        "--job-id",
                        "review-test",
                        flag,
                        "x" * (maximum + 1),
                    ]
                )

    def test_review_run_overrides_fail_before_reservation_or_guards(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Subject\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review through endpoint.",
                transport="direct-openai",
            )
            oversized_controls = (
                ("model", "m" * (review_bridge_module.REVIEW_MAX_MODEL_BYTES + 1)),
                (
                    "base_url",
                    "u" * (review_bridge_module.REVIEW_MAX_BASE_URL_BYTES + 1),
                ),
            )

            for name, value in oversized_controls:
                with self.subTest(surface="direct", name=name), patch.object(
                    review_bridge_module,
                    "_openai_chat_completion",
                ) as endpoint, self.assertRaisesRegex(
                    review_bridge_module.ReviewBridgeError,
                    f"review {name} exceeds",
                ):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport="direct-openai",
                        **{name: value},
                    )
                endpoint.assert_not_called()

            status = review_job_status(root, job_id=job["job_id"])
            self.assertEqual(status["status"], "prepared")
            self.assertEqual(status["attempt_count"], 0)

            for name, value in oversized_controls:
                flag = "--" + name.replace("_", "-")
                with self.subTest(surface="cli", name=name), patch.object(
                    cli_module,
                    "guarded_result",
                ) as cli_guard, patch(
                    "sys.stderr",
                    new=io.StringIO(),
                ), self.assertRaises(SystemExit):
                    cli_module.main(
                        [
                            "review-run",
                            "--root",
                            str(root),
                            "--job-id",
                            job["job_id"],
                            flag,
                            value,
                        ]
                    )
                cli_guard.assert_not_called()

            for name, value in oversized_controls:
                with self.subTest(surface="mcp", name=name), patch.dict(
                    os.environ,
                    {"CONTINUUM_MCP_ALLOW_ANY_PATH": "1"},
                ), patch.object(
                    mcp_server_module,
                    "guarded_tool",
                ) as mcp_guard, self.assertRaisesRegex(
                    review_bridge_module.ReviewBridgeError,
                    f"review {name} exceeds",
                ):
                    mcp_server_module.tool_review_run(
                        {
                            "root": str(root),
                            "job_id": job["job_id"],
                            name: value,
                        }
                    )
                mcp_guard.assert_not_called()

            final_status = review_job_status(root, job_id=job["job_id"])
            self.assertEqual(final_status["status"], "prepared")
            self.assertEqual(final_status["attempt_count"], 0)

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

            def fake_run(
                command: list[str],
                **kwargs: object,
            ) -> review_bridge_module.BoundedProcessResult:
                self.assertIn("hermes", command[0])
                self.assertIn("--query", command)
                query = command[command.index("--query") + 1]
                self.assertIn(request["packet_sha256"], query)
                self.assertIn(str((root / Path(request["packet_uri"])).resolve()), query)
                self.assertNotIn("# Hermes subject", query)
                return bounded_process_result(json.dumps(payload))

            with patch.object(review_bridge_module.shutil, "which", return_value="hermes"), patch.object(
                review_bridge_module,
                "_run_bounded_process",
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

            def fake_run(
                command: list[str],
                **kwargs: object,
            ) -> review_bridge_module.BoundedProcessResult:
                return bounded_process_result("What JSON should I return?")

            with patch.object(review_bridge_module.shutil, "which", return_value="hermes"), patch.object(
                review_bridge_module,
                "_run_bounded_process",
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

            def fake_run(
                command: list[str],
                **kwargs: object,
            ) -> review_bridge_module.BoundedProcessResult:
                return bounded_process_result(next(outputs))

            with patch.object(review_bridge_module.shutil, "which", return_value="hermes"), patch.object(
                review_bridge_module,
                "_run_bounded_process",
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

    def test_direct_transport_failure_receipt_catalog_error_rolls_back_attempt(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Direct failure subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review through endpoint.", transport="direct-openai")
            job_dir = Path(job["job_dir"])

            with patch.object(
                review_bridge_module,
                "_openai_chat_completion",
                side_effect=review_bridge_module.ReviewBridgeError("endpoint refused"),
            ), patch.object(
                review_bridge_module,
                "_record_attempt_receipt_artifact",
                side_effect=RuntimeError("synthetic receipt catalog failure"),
            ):
                with self.assertRaisesRegex(ValueError, "finalization failed and was rolled back"):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport="direct-openai",
                    )

            interrupted = review_job_status(root, job_id=job["job_id"])
            self.assertEqual(interrupted["status"], "submitting")
            self.assertEqual(interrupted["attempt_count"], 0)
            self.assertEqual(list((job_dir / "attempts").iterdir()), [])
            self.assertEqual(list((job_dir / "attempt-receipts").iterdir()), [])
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])

            with patch.object(
                review_bridge_module,
                "_openai_chat_completion",
                side_effect=review_bridge_module.ReviewBridgeError("endpoint refused"),
            ):
                with self.assertRaisesRegex(ValueError, "endpoint refused"):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport="direct-openai",
                    )

            failed = review_job_status(root, job_id=job["job_id"])
            self.assertEqual(failed["status"], "transport_failed")
            self.assertEqual(failed["attempt_count"], 1)
            self.assertTrue((job_dir / "attempts" / "attempt-001.json").is_file())
            self.assertTrue((job_dir / "attempt-receipts" / "attempt-001.json").is_file())
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_direct_success_receipt_catalog_error_keeps_resumable_attempt_context(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Direct success subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review through endpoint.", transport="direct-openai")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            payload = valid_review_payload({**request, **review_job_status(root, job_id=job["job_id"])})
            job_dir = Path(job["job_dir"])

            with patch.object(
                review_bridge_module,
                "_openai_chat_completion",
                return_value={"choices": [{"message": {"content": json.dumps(payload)}}]},
            ), patch.object(
                review_bridge_module,
                "_record_attempt_receipt_artifact",
                side_effect=RuntimeError("synthetic receipt catalog failure"),
            ):
                with self.assertRaisesRegex(ValueError, "finalization failed and was rolled back"):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport="direct-openai",
                    )

            interrupted = review_job_status(root, job_id=job["job_id"])
            stored_status = json.loads(Path(job["status_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(interrupted["status"], "ingesting")
            self.assertEqual(interrupted["accepted_ingest_count"], 0)
            self.assertEqual(stored_status["pending_attempt_number"], 1)
            self.assertEqual(stored_status["pending_attempt_transport"], "direct-openai")
            self.assertTrue(stored_status["pending_attempt_started_at"])
            self.assertEqual(list((job_dir / "attempts").iterdir()), [])
            self.assertEqual(list((job_dir / "attempt-receipts").iterdir()), [])
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])
            conn = connect(root)
            try:
                self.assertEqual(
                    conn.execute(
                        "SELECT count(*) FROM artifacts WHERE kind = 'review_attempt_receipt'"
                    ).fetchone()[0],
                    0,
                )
            finally:
                conn.close()

            receipt = ingest_review_result(
                root,
                job_id=job["job_id"],
                result_path=Path(str(interrupted["raw_response_uri"])),
            )

            final_status = review_job_status(root, job_id=job["job_id"])
            final_stored_status = json.loads(Path(job["status_uri"]).read_text(encoding="utf-8"))
            self.assertTrue(receipt["ok"])
            self.assertEqual(final_status["status"], "ingested")
            self.assertEqual(final_status["accepted_ingest_count"], 1)
            self.assertEqual(final_status["attempt_count"], 1)
            self.assertFalse(any(key.startswith("pending_") for key in final_stored_status))
            self.assertTrue((job_dir / "attempts" / "attempt-001.json").is_file())
            self.assertTrue((job_dir / "attempt-receipts" / "attempt-001.json").is_file())
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])
            conn = connect(root)
            try:
                self.assertEqual(
                    conn.execute(
                        "SELECT count(*) FROM artifacts WHERE kind = 'review_attempt_receipt'"
                    ).fetchone()[0],
                    1,
                )
            finally:
                conn.close()

    def test_automated_reservation_reconciles_each_pre_ingest_hard_boundary(self) -> None:
        for boundary in ("phase_file", "status", "ingest_call"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory(
                ignore_cleanup_errors=True
            ) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "README.md").write_text("# Reservation crash subject\n", encoding="utf-8")
                job = create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review through endpoint.",
                    transport="direct-openai",
                )
                request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
                payload = valid_review_payload(
                    {**request, **review_job_status(root, job_id=job["job_id"])}
                )
                endpoint_patch = patch.object(
                    review_bridge_module,
                    "_openai_chat_completion",
                    return_value={"choices": [{"message": {"content": json.dumps(payload)}}]},
                )
                if boundary == "phase_file":
                    real_materialize = review_bridge_module._materialize_phase_envelope

                    def interrupt_reservation_file(
                        phase_root: Path,
                        phase_job_id: str,
                        path: Path,
                        text: str,
                    ) -> None:
                        if "phase-automated-reservation" in path.name:
                            raise KeyboardInterrupt
                        real_materialize(phase_root, phase_job_id, path, text)

                    boundary_patch = patch.object(
                        review_bridge_module,
                        "_materialize_phase_envelope",
                        side_effect=interrupt_reservation_file,
                    )
                elif boundary == "status":
                    real_write_status = review_bridge_module._write_status

                    def interrupt_reservation_status(
                        status_root: Path,
                        status_job_id: str,
                        status: dict,
                    ) -> None:
                        if status.get("status") == "submitting" and status.get(
                            "pending_attempt_number"
                        ) == 1:
                            raise KeyboardInterrupt
                        real_write_status(status_root, status_job_id, status)

                    boundary_patch = patch.object(
                        review_bridge_module,
                        "_write_status",
                        side_effect=interrupt_reservation_status,
                    )
                else:
                    boundary_patch = patch.object(
                        review_bridge_module,
                        "ingest_review_result",
                        side_effect=KeyboardInterrupt,
                    )

                with endpoint_patch, boundary_patch, self.assertRaises(KeyboardInterrupt):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport="direct-openai",
                    )

                with patch.object(
                    review_bridge_module,
                    "_openai_chat_completion",
                    return_value={"choices": [{"message": {"content": json.dumps(payload)}}]},
                ):
                    result = review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport="direct-openai",
                    )

                final_status = review_job_status(root, job_id=job["job_id"])
                receipt = result["ingest"]
                self.assertEqual(receipt["ingest_mode"], "automated")
                self.assertEqual(final_status["status"], "ingested")
                self.assertEqual(final_status["attempt_count"], 1)
                conn = connect(root)
                try:
                    self.assertEqual(
                        conn.execute(
                            """
                            SELECT count(*) FROM artifacts
                            WHERE kind = 'review_phase_envelope'
                              AND uri LIKE '%phase-automated-reservation-001.json'
                            """
                        ).fetchone()[0],
                        1,
                    )
                finally:
                    conn.close()
                self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
                self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_direct_automated_response_files_recover_without_recalling_endpoint(self) -> None:
        for boundary in ("transport_response", "reviewer_content", "status_binding"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory(
                ignore_cleanup_errors=True
            ) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "README.md").write_text(
                    "# Durable automated response\n",
                    encoding="utf-8",
                )
                job = create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review through endpoint.",
                    transport="direct-openai",
                )
                request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
                payload = valid_review_payload(
                    {**request, **review_job_status(root, job_id=job["job_id"])}
                )
                endpoint_response = {
                    "choices": [{"message": {"content": json.dumps(payload)}}]
                }
                interrupted = False
                real_write_text = review_bridge_module._confined_write_text
                real_write_job = review_bridge_module._write_job

                def interrupt_text_after_write(
                    write_root: Path,
                    write_job_id: str,
                    path: Path | str,
                    text: str,
                    *,
                    exclusive: bool = False,
                ) -> None:
                    nonlocal interrupted
                    real_write_text(
                        write_root,
                        write_job_id,
                        path,
                        text,
                        exclusive=exclusive,
                    )
                    target_name = (
                        "transport-response-001.raw.json"
                        if boundary == "transport_response"
                        else "response-001.raw.txt"
                    )
                    if not interrupted and boundary != "status_binding" and Path(path).name == target_name:
                        interrupted = True
                        raise RuntimeError(f"synthetic {boundary} post-write interruption")

                def interrupt_status_after_write(
                    write_root: Path,
                    status: dict,
                ) -> None:
                    nonlocal interrupted
                    real_write_job(write_root, status)
                    if (
                        not interrupted
                        and boundary == "status_binding"
                        and status.get("status") == "submitting"
                        and status.get("reviewer_content_uri")
                    ):
                        interrupted = True
                        raise RuntimeError("synthetic status binding post-write interruption")

                with patch.object(
                    review_bridge_module,
                    "_openai_chat_completion",
                    return_value=endpoint_response,
                ) as first_endpoint, patch.object(
                    review_bridge_module,
                    "_confined_write_text",
                    side_effect=interrupt_text_after_write,
                ), patch.object(
                    review_bridge_module,
                    "_write_job",
                    side_effect=interrupt_status_after_write,
                ), self.assertRaisesRegex(RuntimeError, "synthetic"):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport="direct-openai",
                        operation_id="op-durable-direct",
                    )
                first_endpoint.assert_called_once()
                self.assertEqual(
                    review_job_status(root, job_id=job["job_id"])["status"],
                    "submitting",
                )

                with patch.object(
                    review_bridge_module,
                    "_openai_chat_completion",
                    side_effect=AssertionError("endpoint must not be called again"),
                ) as retry_endpoint:
                    result = review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport="direct-openai",
                        operation_id="op-durable-direct",
                    )

                retry_endpoint.assert_not_called()
                self.assertEqual(result["status"], "ingested")
                responses = Path(job["job_dir"]) / "responses"
                self.assertEqual(
                    sorted(path.name for path in responses.glob("response-*.raw.txt")),
                    ["response-001.raw.txt"],
                )
                self.assertEqual(
                    sorted(path.name for path in responses.glob("transport-response-*.raw.json")),
                    ["transport-response-001.raw.json"],
                )
                self.assertTrue(
                    review_bridge_module.review_bridge_integrity_report(root)["ok"]
                )
                self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_hermes_automated_content_recovers_without_recalling_transport(self) -> None:
        for boundary in ("reviewer_content", "status_binding"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory(
                ignore_cleanup_errors=True
            ) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "README.md").write_text(
                    "# Durable Hermes response\n",
                    encoding="utf-8",
                )
                job = create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review through Hermes.",
                    transport="hermes",
                )
                request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
                payload = valid_review_payload(
                    {**request, **review_job_status(root, job_id=job["job_id"])}
                )
                content = json.dumps(payload)
                interrupted = False
                real_write_text = review_bridge_module._confined_write_text
                real_write_job = review_bridge_module._write_job

                def interrupt_text_after_write(
                    write_root: Path,
                    write_job_id: str,
                    path: Path | str,
                    text: str,
                    *,
                    exclusive: bool = False,
                ) -> None:
                    nonlocal interrupted
                    real_write_text(
                        write_root,
                        write_job_id,
                        path,
                        text,
                        exclusive=exclusive,
                    )
                    if (
                        not interrupted
                        and boundary == "reviewer_content"
                        and Path(path).name == "response-001.raw.txt"
                    ):
                        interrupted = True
                        raise RuntimeError("synthetic Hermes content post-write interruption")

                def interrupt_status_after_write(
                    write_root: Path,
                    status: dict,
                ) -> None:
                    nonlocal interrupted
                    real_write_job(write_root, status)
                    if (
                        not interrupted
                        and boundary == "status_binding"
                        and status.get("status") == "submitting"
                        and status.get("reviewer_content_uri")
                    ):
                        interrupted = True
                        raise RuntimeError("synthetic Hermes status post-write interruption")

                with patch.object(
                    review_bridge_module,
                    "_run_hermes_oneshot",
                    return_value=content,
                ) as first_transport, patch.object(
                    review_bridge_module,
                    "_confined_write_text",
                    side_effect=interrupt_text_after_write,
                ), patch.object(
                    review_bridge_module,
                    "_write_job",
                    side_effect=interrupt_status_after_write,
                ), self.assertRaisesRegex(RuntimeError, "synthetic Hermes"):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport="hermes",
                        operation_id="op-durable-hermes",
                    )
                first_transport.assert_called_once()

                with patch.object(
                    review_bridge_module,
                    "_run_hermes_oneshot",
                    side_effect=AssertionError("Hermes must not be called again"),
                ) as retry_transport:
                    result = review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport="hermes",
                        operation_id="op-durable-hermes",
                    )

                retry_transport.assert_not_called()
                self.assertEqual(result["status"], "ingested")
                responses = Path(job["job_dir"]) / "responses"
                self.assertEqual(
                    sorted(path.name for path in responses.glob("response-*.raw.txt")),
                    ["response-001.raw.txt"],
                )
                self.assertEqual(
                    list(responses.glob("transport-response-*.raw.json")),
                    [],
                )
                self.assertTrue(
                    review_bridge_module.review_bridge_integrity_report(root)["ok"]
                )

    def test_inline_automated_retry_reuses_unbound_durable_response(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text(
                "# Inline reservation response\n",
                encoding="utf-8",
            )
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review inline.",
                transport="direct-openai",
            )
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            content = json.dumps(
                valid_review_payload(
                    {**request, **review_job_status(root, job_id=job["job_id"])}
                )
            )
            with review_bridge_module.operation_lock(root, job["job_id"]):
                review_bridge_module._ensure_automated_reservation_locked(
                    root,
                    job["job_id"],
                    review_bridge_module._load_job(root, job["job_id"]),
                    transport="direct-openai",
                    operation_id="op-inline-retry",
                )
            real_write_job = review_bridge_module._write_job

            def interrupt_before_binding(write_root: Path, status: dict) -> None:
                if (
                    status.get("status") == "submitting"
                    and status.get("reviewer_content_uri")
                ):
                    raise KeyboardInterrupt
                real_write_job(write_root, status)

            with patch.object(
                review_bridge_module,
                "_write_job",
                side_effect=interrupt_before_binding,
            ), self.assertRaises(KeyboardInterrupt):
                ingest_review_result(
                    root,
                    job_id=job["job_id"],
                    content=content,
                    operation_id="op-inline-retry",
                )

            responses = Path(job["job_dir"]) / "responses"
            self.assertEqual(
                sorted(path.name for path in responses.glob("response-*.raw.txt")),
                ["response-001.raw.txt"],
            )
            with self.assertRaisesRegex(ValueError, "operation binding changed"):
                ingest_review_result(
                    root,
                    job_id=job["job_id"],
                    content=content,
                    operation_id="op-inline-other",
                )
            with self.assertRaisesRegex(ValueError, "differs from its durable"):
                ingest_review_result(
                    root,
                    job_id=job["job_id"],
                    content=content + " ",
                    operation_id="op-inline-retry",
                )

            receipt = ingest_review_result(
                root,
                job_id=job["job_id"],
                content=content,
                operation_id="op-inline-retry",
            )

            self.assertTrue(receipt["ok"])
            self.assertEqual(
                sorted(path.name for path in responses.glob("response-*.raw.txt")),
                ["response-001.raw.txt"],
            )
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_concurrent_inline_automated_retry_commits_one_response(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text(
                "# Concurrent inline response\n",
                encoding="utf-8",
            )
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review inline concurrently.",
                transport="direct-openai",
            )
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            content = json.dumps(
                valid_review_payload(
                    {**request, **review_job_status(root, job_id=job["job_id"])}
                )
            )
            with review_bridge_module.operation_lock(root, job["job_id"]):
                review_bridge_module._ensure_automated_reservation_locked(
                    root,
                    job["job_id"],
                    review_bridge_module._load_job(root, job["job_id"]),
                    transport="direct-openai",
                    operation_id="op-inline-concurrent",
                )

            def ingest_once() -> dict:
                return ingest_review_result(
                    root,
                    job_id=job["job_id"],
                    content=content,
                    operation_id="op-inline-concurrent",
                )

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(lambda _index: ingest_once(), range(2)))

            self.assertTrue(all(result["ok"] for result in results))
            responses = Path(job["job_dir"]) / "responses"
            self.assertEqual(
                sorted(path.name for path in responses.glob("response-*.raw.txt")),
                ["response-001.raw.txt"],
            )
            self.assertEqual(
                review_job_status(root, job_id=job["job_id"])["accepted_ingest_count"],
                1,
            )
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])

    def test_targeted_integrity_bypasses_global_inventory_and_bounds_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Targeted integrity\n", encoding="utf-8")
            first = create_review_job(
                root,
                subject_path=subject,
                prompt="First job.",
                transport="manual",
            )
            target = create_review_job(
                root,
                subject_path=subject,
                prompt="Target job.",
                transport="manual",
            )
            self.assertNotEqual(first["job_id"], target["job_id"])

            with patch.object(review_bridge_module, "REVIEW_INTEGRITY_MAX_JOBS", 1):
                global_report = review_bridge_module.review_bridge_integrity_report(root)
                targeted_report = review_bridge_module.review_bridge_integrity_report(
                    root,
                    job_id=target["job_id"],
                )
            self.assertFalse(global_report["ok"])
            self.assertTrue(targeted_report["ok"])

            conn = connect(root)
            try:
                conn.executemany(
                    """
                    INSERT INTO artifacts(
                        id, kind, uri, sha256, size_bytes, created_at, operation_id,
                        immutable, source_type, trust_level, metadata_json
                    )
                    VALUES(?, 'review_phase_envelope', ?, ?, 0, ?, NULL, 1,
                           'review_bridge', 'local_generated', '{}')
                    """,
                    (
                        (
                            f"foreign-targeted-{index}",
                            f"exports/review_bridge/jobs/foreign-{index}/receipts/phase-terminal-001.json",
                            f"{index + 1:064x}",
                            "2000-01-01T00:00:00+00:00",
                        )
                        for index in range(2)
                    ),
                )
                conn.commit()
                target_prefix = (
                    f"exports/review_bridge/jobs/{target['job_id']}/"
                )
                target_artifact_count = int(
                    conn.execute(
                        "SELECT COUNT(*) AS count FROM artifacts "
                        "WHERE uri >= ? AND uri < ?",
                        (target_prefix, target_prefix[:-1] + "0"),
                    ).fetchone()["count"]
                )
                statements: list[str] = []
                conn.set_trace_callback(statements.append)
                with patch.object(
                    review_bridge_module,
                    "REVIEW_INTEGRITY_MAX_ARTIFACTS_PER_JOB",
                    target_artifact_count,
                ):
                    bounded = review_bridge_module.review_bridge_integrity_report(
                        root,
                        job_id=target["job_id"],
                        artifact_conn=conn,
                    )
            finally:
                conn.close()
            self.assertTrue(bounded["ok"])
            self.assertTrue(
                any(
                    "FROM artifacts" in statement
                    and "uri >=" in statement
                    and target["job_id"] in statement
                    for statement in statements
                )
            )

    def test_catalog_backed_missing_job_directories_block_semantic_integrity_and_snapshot(
        self,
    ) -> None:
        for missing_scope in ("one_job", "whole_tree"):
            with self.subTest(missing_scope=missing_scope), tempfile.TemporaryDirectory(
                ignore_cleanup_errors=True
            ) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "README.md").write_text(
                    "# Missing review evidence\n",
                    encoding="utf-8",
                )
                first = create_review_job(
                    root,
                    subject_path=subject,
                    prompt="First preserved job.",
                    transport="manual",
                )
                create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Second preserved job.",
                    transport="manual",
                )
                if missing_scope == "one_job":
                    shutil.rmtree(first["job_dir"])
                else:
                    shutil.rmtree(root / "exports" / "review_bridge" / "jobs")

                report = review_bridge_module.review_bridge_integrity_report(root)
                semantic = semantic_integrity_report(root)
                closed_conn = connect(root)
                closed_conn.close()
                unreadable_catalog_report = (
                    review_bridge_module.review_bridge_integrity_report(
                        root,
                        artifact_conn=closed_conn,
                    )
                )

                self.assertFalse(report["ok"])
                self.assertFalse(semantic["ok"])
                self.assertFalse(unreadable_catalog_report["ok"])
                self.assertTrue(
                    any(
                        sample.get("reason")
                        == "catalog_review_job_inventory_unreadable"
                        for sample in unreadable_catalog_report["samples"][
                            "review_bridge_malformed_records"
                        ]
                    )
                )
                self.assertGreater(
                    report["checks"]["review_bridge_malformed_records"],
                    0,
                )
                with self.assertRaisesRegex(ValueError, "snapshot preflight failed"):
                    snapshot(root, reason=f"missing_review_{missing_scope}")

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            empty_root = Path(tmp) / "empty-continuum"
            review_bridge_module.init_db(empty_root)
            self.assertTrue(
                review_bridge_module.review_bridge_integrity_report(empty_root)["ok"]
            )

    def test_attempt_and_mutable_inventory_limits_fail_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Bounded inventory\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Bound this job.",
                transport="manual",
            )
            status_path = Path(job["status_uri"])
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status["attempt_count"] = 2
            status_path.write_text(json.dumps(status), encoding="utf-8")
            before = status_path.read_bytes()

            with patch.object(
                review_bridge_module,
                "REVIEW_INTEGRITY_MAX_ATTEMPTS_PER_JOB",
                1,
            ):
                report = review_bridge_module.review_bridge_integrity_report(
                    root,
                    job_id=job["job_id"],
                )
                for dry_run in (True, False):
                    with self.subTest(dry_run=dry_run), self.assertRaisesRegex(
                        ValueError,
                        "attempt_count is invalid",
                    ):
                        review_bridge_module.upgrade_review_job_integrity(
                            root,
                            job_id=job["job_id"],
                            dry_run=dry_run,
                        )
            self.assertFalse(report["ok"])
            self.assertEqual(status_path.read_bytes(), before)

            responses = Path(job["job_dir"]) / "responses"
            for index in range(3):
                (responses / f"foreign-{index}.txt").write_text("x", encoding="utf-8")
            response_snapshot = {
                path.name: path.read_bytes() for path in responses.iterdir()
            }
            with patch.object(
                review_bridge_module,
                "REVIEW_INTEGRITY_MAX_MUTABLE_ENTRIES_PER_JOB",
                2,
            ), self.assertRaisesRegex(ValueError, "entry limit"):
                review_bridge_module._max_existing_number(
                    responses,
                    "response",
                    ".raw.txt",
                )
            self.assertEqual(
                response_snapshot,
                {path.name: path.read_bytes() for path in responses.iterdir()},
            )

    def test_runtime_request_and_status_reads_enforce_exact_byte_limit(self) -> None:
        for record_name in ("request", "status"):
            with self.subTest(record_name=record_name), tempfile.TemporaryDirectory(
                ignore_cleanup_errors=True
            ) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "README.md").write_text(
                    "# Runtime record bound\n",
                    encoding="utf-8",
                )
                job = create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Bound runtime records.",
                    transport="manual",
                )
                request_path = Path(job["request_uri"])
                status_path = Path(job["status_uri"])
                target_path = request_path if record_name == "request" else status_path
                original = target_path.read_bytes()
                limit = max(
                    len(request_path.read_bytes()),
                    len(status_path.read_bytes()),
                ) + 16
                exact = original + b" " * (limit - len(original))
                target_path.write_bytes(exact)

                with patch.object(
                    review_bridge_module,
                    "REVIEW_INTEGRITY_MAX_RECORD_BYTES",
                    limit,
                ):
                    if record_name == "request":
                        loaded = review_bridge_module._load_request(root, job["job_id"])
                    else:
                        loaded = review_bridge_module._load_status(root, job["job_id"])
                    self.assertIsInstance(loaded, dict)
                    target_path.write_bytes(exact + b" ")
                    with self.assertRaisesRegex(ValueError, "integrity byte limit"):
                        if record_name == "request":
                            review_bridge_module._load_request(root, job["job_id"])
                        else:
                            review_bridge_module._load_status(root, job["job_id"])

    def test_ingest_phase_reconciles_DB_file_and_status_hard_boundaries(self) -> None:
        for boundary in ("phase_file", "status"):
            for retry_interface in ("result_path", "content"):
                with self.subTest(
                    boundary=boundary,
                    retry_interface=retry_interface,
                ), tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                    base = Path(tmp)
                    root = base / "continuum"
                    subject = base / "subject"
                    subject.mkdir()
                    (subject / "README.md").write_text(
                        "# Ingest phase crash subject\n",
                        encoding="utf-8",
                    )
                    job = create_review_job(
                        root,
                        subject_path=subject,
                        prompt="Review hard.",
                        transport="direct-openai",
                    )
                    request = json.loads(
                        Path(job["request_uri"]).read_text(encoding="utf-8")
                    )
                    payload = valid_review_payload(
                        {**request, **review_job_status(root, job_id=job["job_id"])}
                    )
                    payload.pop("capsule_challenge", None)
                    payload["review_surface"] = "packet_excerpt_only"
                    payload["subject_inspected"] = False
                    content = json.dumps(payload)
                    if boundary == "phase_file":
                        real_materialize = (
                            review_bridge_module._materialize_phase_envelope
                        )

                        def interrupt_ingest_phase_file(
                            phase_root: Path,
                            phase_job_id: str,
                            path: Path,
                            text: str,
                        ) -> None:
                            if "phase-ingest" in path.name:
                                raise KeyboardInterrupt
                            real_materialize(phase_root, phase_job_id, path, text)

                        boundary_patch = patch.object(
                            review_bridge_module,
                            "_materialize_phase_envelope",
                            side_effect=interrupt_ingest_phase_file,
                        )
                    else:
                        real_write_status = review_bridge_module._write_status

                        def interrupt_ingest_status(
                            status_root: Path,
                            status_job_id: str,
                            status: dict,
                        ) -> None:
                            if status.get("status") == "ingesting":
                                raise KeyboardInterrupt
                            real_write_status(status_root, status_job_id, status)

                        boundary_patch = patch.object(
                            review_bridge_module,
                            "_write_status",
                            side_effect=interrupt_ingest_status,
                        )

                    with boundary_patch, self.assertRaises(KeyboardInterrupt):
                        ingest_review_result(
                            root,
                            job_id=job["job_id"],
                            content=content,
                        )

                    raw_response_path = (
                        Path(job["job_dir"])
                        / "responses"
                        / "response-001.raw.txt"
                    )
                    self.assertTrue(raw_response_path.is_file())
                    retry_kwargs = (
                        {"result_path": raw_response_path}
                        if retry_interface == "result_path"
                        else {"content": content}
                    )
                    receipt = ingest_review_result(
                        root,
                        job_id=job["job_id"],
                        **retry_kwargs,
                    )

                    self.assertTrue(receipt["ok"])
                    self.assertEqual(receipt["ingest_mode"], "untracked")
                    self.assertFalse(
                        (
                            Path(job["job_dir"])
                            / "responses"
                            / "response-002.raw.txt"
                        ).exists()
                    )
                    self.assertEqual(
                        review_job_status(root, job_id=job["job_id"])["status"],
                        "ingested",
                    )
                    self.assertTrue(
                        review_bridge_module.review_bridge_integrity_report(root)["ok"]
                    )
                    self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_terminal_phase_reconciles_all_hard_boundaries_for_automated_and_browser(self) -> None:
        for mode in ("automated", "browser"):
            for boundary in ("phase_file", "attempt", "receipt", "status", "artifact"):
                with self.subTest(mode=mode, boundary=boundary), tempfile.TemporaryDirectory(
                    ignore_cleanup_errors=True
                ) as tmp:
                    base = Path(tmp)
                    root = base / "continuum"
                    subject = base / "subject"
                    subject.mkdir()
                    (subject / "README.md").write_text(
                        "# Terminal crash subject\n",
                        encoding="utf-8",
                    )
                    transport = "direct-openai" if mode == "automated" else "manual"
                    job = create_review_job(
                        root,
                        subject_path=subject,
                        prompt="Review hard.",
                        transport=transport,
                    )
                    request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
                    payload = valid_review_payload(
                        {**request, **review_job_status(root, job_id=job["job_id"])}
                    )
                    if mode == "browser":
                        reserved = review_browser_attempt_start(root, job_id=job["job_id"])
                        result_path = Path(reserved["response_uri"])
                        result_path.write_text(json.dumps(payload), encoding="utf-8")
                    else:
                        result_path = None

                    if boundary == "phase_file":
                        real_materialize = review_bridge_module._materialize_phase_envelope

                        def interrupt_terminal_phase_file(
                            phase_root: Path,
                            phase_job_id: str,
                            path: Path,
                            text: str,
                        ) -> None:
                            if "phase-terminal" in path.name:
                                raise KeyboardInterrupt
                            real_materialize(phase_root, phase_job_id, path, text)

                        boundary_patch = patch.object(
                            review_bridge_module,
                            "_materialize_phase_envelope",
                            side_effect=interrupt_terminal_phase_file,
                        )
                    elif boundary in {"attempt", "receipt"}:
                        real_confined_write = review_bridge_module._confined_write_text

                        def interrupt_terminal_record(
                            write_root: Path,
                            write_job_id: str,
                            path: Path,
                            text: str,
                            *,
                            exclusive: bool = False,
                        ) -> None:
                            real_confined_write(
                                write_root,
                                write_job_id,
                                path,
                                text,
                                exclusive=exclusive,
                            )
                            relative = "/".join(
                                review_bridge_module._job_path_parts(
                                    root,
                                    job["job_id"],
                                    path,
                                )
                            )
                            expected_prefix = (
                                "attempts/attempt-" if boundary == "attempt" else "attempt-receipts/attempt-"
                            )
                            if relative.startswith(expected_prefix):
                                raise KeyboardInterrupt

                        boundary_patch = patch.object(
                            review_bridge_module,
                            "_confined_write_text",
                            side_effect=interrupt_terminal_record,
                        )
                    elif boundary == "status":
                        real_write_status = review_bridge_module._write_status

                        def interrupt_terminal_status(
                            status_root: Path,
                            status_job_id: str,
                            status: dict,
                        ) -> None:
                            real_write_status(status_root, status_job_id, status)
                            if status.get("status") == "ingested":
                                raise KeyboardInterrupt

                        boundary_patch = patch.object(
                            review_bridge_module,
                            "_write_status",
                            side_effect=interrupt_terminal_status,
                        )
                    else:
                        real_persist_receipt = (
                            review_bridge_module._persist_attempt_receipt_artifact
                        )

                        def interrupt_terminal_artifact(*args: object, **kwargs: object) -> None:
                            real_persist_receipt(*args, **kwargs)
                            raise KeyboardInterrupt

                        boundary_patch = patch.object(
                            review_bridge_module,
                            "_persist_attempt_receipt_artifact",
                            side_effect=interrupt_terminal_artifact,
                        )

                    endpoint_patch = patch.object(
                        review_bridge_module,
                        "_openai_chat_completion",
                        return_value={"choices": [{"message": {"content": json.dumps(payload)}}]},
                    )
                    with boundary_patch, endpoint_patch, self.assertRaises(KeyboardInterrupt):
                        if mode == "automated":
                            review_bridge_module.run_review_job(
                                root,
                                job_id=job["job_id"],
                                transport="direct-openai",
                                operation_id="terminal-op",
                            )
                        else:
                            ingest_review_result(
                                root,
                                job_id=job["job_id"],
                                result_path=result_path,
                                operation_id="terminal-op",
                            )

                    stored_status = json.loads(Path(job["status_uri"]).read_text(encoding="utf-8"))
                    bound_response = review_bridge_module._resolve_job_reference(
                        root,
                        job["job_id"],
                        "raw_response_uri",
                        stored_status["raw_response_uri"],
                        evidence=stored_status,
                    )
                    recovered = ingest_review_result(
                        root,
                        job_id=job["job_id"],
                        result_path=bound_response,
                        operation_id="terminal-op",
                    )

                    self.assertTrue(recovered["ok"])
                    self.assertEqual(recovered["ingest_mode"], mode if mode == "automated" else "browser_reserved")
                    final_status = review_job_status(root, job_id=job["job_id"])
                    self.assertEqual(final_status["status"], "ingested")
                    self.assertEqual(final_status["attempt_count"], 1)
                    conn = connect(root)
                    try:
                        self.assertEqual(
                            conn.execute(
                                "SELECT count(*) FROM artifacts WHERE kind = 'review_attempt_receipt'"
                            ).fetchone()[0],
                            1,
                        )
                    finally:
                        conn.close()
                    self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
                    self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_terminal_phase_exact_outputs_reject_drifted_status(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Status drift subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            reserved = review_browser_attempt_start(root, job_id=job["job_id"])
            response_path = Path(reserved["response_uri"])
            response_path.write_text(
                json.dumps(valid_review_payload({**request, **review_job_status(root, job_id=job["job_id"])})),
                encoding="utf-8",
            )
            ingest_review_result(root, job_id=job["job_id"], result_path=response_path)
            status_path = Path(job["status_uri"])
            drifted = json.loads(status_path.read_text(encoding="utf-8"))
            drifted["updated_at"] = "2000-01-01T00:00:00+00:00"
            status_path.write_text(json.dumps(drifted), encoding="utf-8")
            rows_before = artifact_rows(root)
            files_before = {
                path.relative_to(Path(job["job_dir"])).as_posix(): path.read_bytes()
                for path in Path(job["job_dir"]).rglob("*")
                if path.is_file()
            }

            with self.assertRaisesRegex(ValueError, "terminal status drifted"):
                ingest_review_result(root, job_id=job["job_id"], result_path=response_path)

            self.assertEqual(rows_before, artifact_rows(root))
            self.assertEqual(
                files_before,
                {
                    path.relative_to(Path(job["job_dir"])).as_posix(): path.read_bytes()
                    for path in Path(job["job_dir"]).rglob("*")
                    if path.is_file()
                },
            )

    def test_terminal_artifact_commit_then_error_rolls_back_files_and_reconciles(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Commit then error subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            reserved = review_browser_attempt_start(root, job_id=job["job_id"])
            response_path = Path(reserved["response_uri"])
            response_path.write_text(
                json.dumps(valid_review_payload({**request, **review_job_status(root, job_id=job["job_id"])})),
                encoding="utf-8",
            )
            real_persist = review_bridge_module._persist_attempt_receipt_artifact

            def persist_then_error(*args: object, **kwargs: object) -> None:
                real_persist(*args, **kwargs)
                raise RuntimeError("synthetic post-commit terminal failure")

            with patch.object(
                review_bridge_module,
                "_persist_attempt_receipt_artifact",
                side_effect=persist_then_error,
            ), self.assertRaisesRegex(ValueError, "finalization failed and was rolled back"):
                ingest_review_result(root, job_id=job["job_id"], result_path=response_path)

            job_dir = Path(job["job_dir"])
            interrupted = json.loads(Path(job["status_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(interrupted["status"], "ingesting")
            self.assertFalse((job_dir / "attempt-receipts" / "attempt-001.json").exists())
            self.assertEqual(
                json.loads(Path(reserved["attempt_uri"]).read_text(encoding="utf-8"))["status"],
                "browser_attempt_reserved",
            )
            conn = connect(root)
            try:
                self.assertEqual(
                    conn.execute(
                        "SELECT count(*) FROM artifacts WHERE kind = 'review_attempt_receipt'"
                    ).fetchone()[0],
                    1,
                )
            finally:
                conn.close()

            recovered = ingest_review_result(
                root,
                job_id=job["job_id"],
                result_path=response_path,
            )
            self.assertTrue(recovered["ok"])
            self.assertEqual(
                review_job_status(root, job_id=job["job_id"])["status"],
                "ingested",
            )
            self.assertTrue((job_dir / "attempt-receipts" / "attempt-001.json").is_file())
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_review_failure_status_boundary_reconciles_before_retry_error(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Invalid review subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            reserved = review_browser_attempt_start(root, job_id=job["job_id"])
            response_path = Path(reserved["response_uri"])
            response_path.write_text("not json", encoding="utf-8")

            with patch.object(
                review_bridge_module,
                "_persist_attempt_receipt_artifact",
                side_effect=KeyboardInterrupt,
            ), self.assertRaises(KeyboardInterrupt):
                ingest_review_result(root, job_id=job["job_id"], result_path=response_path)

            interrupted = review_job_status(root, job_id=job["job_id"])
            self.assertEqual(interrupted["status"], "review_failed")
            with self.assertRaisesRegex(ValueError, "did not contain a JSON object"):
                ingest_review_result(root, job_id=job["job_id"], result_path=response_path)
            final_status = review_job_status(root, job_id=job["job_id"])
            self.assertEqual(final_status["status"], "review_failed")
            self.assertEqual(final_status["attempt_count"], 1)
            conn = connect(root)
            try:
                self.assertEqual(
                    conn.execute(
                        "SELECT count(*) FROM artifacts WHERE kind = 'review_attempt_receipt'"
                    ).fetchone()[0],
                    1,
                )
            finally:
                conn.close()

    def test_transport_failure_status_boundary_reconciles_both_error_classes(self) -> None:
        for transport_error in (
            review_bridge_module.ReviewBridgeError("endpoint refused"),
            RuntimeError("endpoint runtime failure"),
        ):
            with self.subTest(error_type=type(transport_error).__name__), tempfile.TemporaryDirectory(
                ignore_cleanup_errors=True
            ) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "README.md").write_text(
                    "# Transport failure subject\n",
                    encoding="utf-8",
                )
                job = create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review through endpoint.",
                    transport="direct-openai",
                )
                with patch.object(
                    review_bridge_module,
                    "_openai_chat_completion",
                    side_effect=transport_error,
                ), patch.object(
                    review_bridge_module,
                    "_persist_attempt_receipt_artifact",
                    side_effect=KeyboardInterrupt,
                ), self.assertRaises(KeyboardInterrupt):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport="direct-openai",
                    )

                interrupted = review_job_status(root, job_id=job["job_id"])
                self.assertEqual(interrupted["status"], "transport_failed")
                self.assertEqual(interrupted["error_type"], type(transport_error).__name__)
                with self.assertRaisesRegex(ValueError, str(transport_error)):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport="direct-openai",
                    )
                final_status = review_job_status(root, job_id=job["job_id"])
                self.assertEqual(final_status["status"], "transport_failed")
                self.assertEqual(final_status["attempt_count"], 1)
                conn = connect(root)
                try:
                    self.assertEqual(
                        conn.execute(
                            "SELECT count(*) FROM artifacts WHERE kind = 'review_attempt_receipt'"
                        ).fetchone()[0],
                        1,
                    )
                finally:
                    conn.close()

    def test_supersede_status_boundary_reconciles_before_next_reservation(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Supersede crash subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            first = review_browser_attempt_start(root, job_id=job["job_id"])

            with patch.object(
                review_bridge_module,
                "_persist_attempt_receipt_artifact",
                side_effect=KeyboardInterrupt,
            ), self.assertRaises(KeyboardInterrupt):
                review_browser_attempt_start(root, job_id=job["job_id"])

            self.assertEqual(
                review_job_status(root, job_id=job["job_id"])["status"],
                "handoff_ready",
            )
            second = review_browser_attempt_start(root, job_id=job["job_id"])
            self.assertEqual(second["attempt"], 2)
            self.assertEqual(
                json.loads(Path(first["attempt_uri"]).read_text(encoding="utf-8"))["status"],
                "browser_attempt_superseded",
            )
            self.assertTrue((Path(job["job_dir"]) / "attempt-receipts" / "attempt-001.json").is_file())

    def test_legacy_upgrade_status_boundary_reconciles_to_already_bound(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Upgrade crash subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            reserved = review_browser_attempt_start(root, job_id=job["job_id"])
            response_path = Path(reserved["response_uri"])
            response_path.write_text(
                json.dumps(valid_review_payload({**request, **review_job_status(root, job_id=job["job_id"])})),
                encoding="utf-8",
            )
            ingest_review_result(root, job_id=job["job_id"], result_path=response_path)
            job_dir = Path(job["job_dir"])
            strip_phase_authority_for_legacy_fixture(root, job_dir)
            attempt_path = job_dir / "attempts" / "attempt-001.json"
            receipt_path = job_dir / "attempt-receipts" / "attempt-001.json"
            receipt_path.unlink()
            conn = connect(root)
            try:
                conn.execute("DELETE FROM artifacts WHERE kind = 'review_attempt_receipt'")
                conn.commit()
            finally:
                conn.close()
            attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
            attempt.pop("schema")
            attempt.pop("job_id")
            attempt_path.write_text(json.dumps(attempt), encoding="utf-8")
            status_path = Path(job["status_uri"])
            status = json.loads(status_path.read_text(encoding="utf-8"))
            status.pop("last_attempt_sha256")
            status_path.write_text(json.dumps(status), encoding="utf-8")

            with patch.object(
                review_bridge_module,
                "_persist_attempt_receipt_artifact",
                side_effect=KeyboardInterrupt,
            ), self.assertRaises(KeyboardInterrupt):
                review_bridge_module.upgrade_review_job_integrity(
                    root,
                    job_id=job["job_id"],
                )

            recovered = review_bridge_module.upgrade_review_job_integrity(
                root,
                job_id=job["job_id"],
            )
            self.assertEqual(recovered["status"], "already_bound")
            self.assertTrue(receipt_path.is_file())
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])

    def test_phase_reconciliation_query_is_bounded_to_the_current_job(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Local phase subject\n", encoding="utf-8")
            job = create_review_job(root, subject_path=subject, prompt="Review hard.", transport="manual")
            foreign_count = review_bridge_module.REVIEW_INTEGRITY_MAX_ATTEMPTS_PER_JOB + 1
            conn = connect(root)
            try:
                conn.executemany(
                    """
                    INSERT INTO artifacts(
                        id, kind, uri, sha256, size_bytes, created_at, operation_id,
                        immutable, source_type, trust_level, metadata_json
                    )
                    VALUES(?, 'review_phase_envelope', ?, ?, 0, ?, NULL, 1,
                           'review_bridge', 'local_generated', '{}')
                    """,
                    (
                        (
                            f"foreign-phase-{index:05d}",
                            f"exports/review_bridge/jobs/foreign-{index:05d}/receipts/phase-terminal-001.json",
                            "0" * 64,
                            "2000-01-01T00:00:00+00:00",
                        )
                        for index in range(foreign_count)
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            self.assertEqual(
                review_bridge_module._phase_envelopes_for_job_locked(
                    root,
                    job["job_id"],
                    phase="terminal",
                ),
                [],
            )

    def test_phase_retry_operation_binding_is_exact_in_both_directions(self) -> None:
        for phase in ("automated_reservation", "ingest", "terminal"):
            for initial_operation, retry_operation in (("phase-op", None), (None, "phase-op")):
                with self.subTest(
                    phase=phase,
                    initial_operation=initial_operation,
                    retry_operation=retry_operation,
                ), tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
                    base = Path(tmp)
                    root = base / "continuum"
                    subject = base / "subject"
                    subject.mkdir()
                    (subject / "README.md").write_text(
                        "# Operation binding subject\n",
                        encoding="utf-8",
                    )
                    transport = "manual" if phase == "terminal" else "direct-openai"
                    job = create_review_job(
                        root,
                        subject_path=subject,
                        prompt="Review hard.",
                        transport=transport,
                    )
                    request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
                    payload = valid_review_payload(
                        {**request, **review_job_status(root, job_id=job["job_id"])}
                    )
                    payload.pop("capsule_challenge", None)
                    payload["review_surface"] = "packet_excerpt_only"
                    payload["subject_inspected"] = False
                    result_path: Path | None = None

                    if phase == "automated_reservation":
                        with patch.object(
                            review_bridge_module,
                            "_openai_chat_completion",
                            return_value={"choices": [{"message": {"content": json.dumps(payload)}}]},
                        ), patch.object(
                            review_bridge_module,
                            "ingest_review_result",
                            side_effect=KeyboardInterrupt,
                        ), self.assertRaises(KeyboardInterrupt):
                            review_bridge_module.run_review_job(
                                root,
                                job_id=job["job_id"],
                                transport="direct-openai",
                                operation_id=initial_operation,
                            )
                    elif phase == "ingest":
                        with patch.object(
                            review_bridge_module,
                            "_persist_ingest_derived_evidence",
                            side_effect=KeyboardInterrupt,
                        ), self.assertRaises(KeyboardInterrupt):
                            ingest_review_result(
                                root,
                                job_id=job["job_id"],
                                content=json.dumps(payload),
                                operation_id=initial_operation,
                            )
                        stored_status = json.loads(
                            Path(job["status_uri"]).read_text(encoding="utf-8")
                        )
                        result_path = review_bridge_module._resolve_job_reference(
                            root,
                            job["job_id"],
                            "raw_response_uri",
                            stored_status["raw_response_uri"],
                            evidence=stored_status,
                        )
                    else:
                        reserved = review_browser_attempt_start(root, job_id=job["job_id"])
                        result_path = Path(reserved["response_uri"])
                        result_path.write_text(json.dumps(payload), encoding="utf-8")
                        with patch.object(
                            review_bridge_module,
                            "_persist_attempt_receipt_artifact",
                            side_effect=KeyboardInterrupt,
                        ), self.assertRaises(KeyboardInterrupt):
                            ingest_review_result(
                                root,
                                job_id=job["job_id"],
                                result_path=result_path,
                                operation_id=initial_operation,
                            )

                    job_dir = Path(job["job_dir"])
                    rows_before = artifact_rows(root)
                    files_before = {
                        path.relative_to(job_dir).as_posix(): path.read_bytes()
                        for path in job_dir.rglob("*")
                        if path.is_file()
                    }
                    with self.assertRaisesRegex(ValueError, "operation binding changed"):
                        if phase == "automated_reservation":
                            review_bridge_module.run_review_job(
                                root,
                                job_id=job["job_id"],
                                transport="direct-openai",
                                operation_id=retry_operation,
                            )
                        else:
                            assert result_path is not None
                            ingest_review_result(
                                root,
                                job_id=job["job_id"],
                                result_path=result_path,
                                operation_id=retry_operation,
                            )

                    self.assertEqual(rows_before, artifact_rows(root))
                    self.assertEqual(
                        files_before,
                        {
                            path.relative_to(job_dir).as_posix(): path.read_bytes()
                            for path in job_dir.rglob("*")
                            if path.is_file()
                        },
                    )

    def test_ingest_derived_files_without_rows_reconcile_after_hard_interrupt(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Derived crash subject\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="direct-openai",
            )
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            payload = valid_review_payload(
                {**request, **review_job_status(root, job_id=job["job_id"])}
            )
            payload.pop("capsule_challenge", None)
            payload["review_surface"] = "packet_excerpt_only"
            payload["subject_inspected"] = False
            real_connect = review_bridge_module.connect
            connect_calls = 0

            def interrupt_derived_catalog(value: Path) -> object:
                nonlocal connect_calls
                connect_calls += 1
                if connect_calls == 2:
                    raise KeyboardInterrupt
                return real_connect(value)

            with patch.object(
                review_bridge_module,
                "connect",
                side_effect=interrupt_derived_catalog,
            ), self.assertRaises(KeyboardInterrupt):
                ingest_review_result(
                    root,
                    job_id=job["job_id"],
                    content=json.dumps(payload),
                )

            stored_status = json.loads(Path(job["status_uri"]).read_text(encoding="utf-8"))
            raw_response_path = review_bridge_module._resolve_job_reference(
                root,
                job["job_id"],
                "raw_response_uri",
                stored_status["raw_response_uri"],
                evidence=stored_status,
            )
            derived_paths = pending_derived_paths(root, job, stored_status)
            self.assertEqual(stored_status["status"], "ingesting")
            self.assertTrue(all(path.is_file() for path in derived_paths))
            conn = connect(root)
            try:
                self.assertEqual(
                    conn.execute(
                        "SELECT count(*) FROM artifacts WHERE kind = 'review_ingest_receipt'"
                    ).fetchone()[0],
                    0,
                )
            finally:
                conn.close()
            self.assertFalse(review_bridge_module.review_bridge_integrity_report(root)["ok"])

            receipt = ingest_review_result(
                root,
                job_id=job["job_id"],
                result_path=raw_response_path,
            )

            self.assertTrue(receipt["ok"])
            self.assertEqual(
                review_job_status(root, job_id=job["job_id"])["status"],
                "ingested",
            )
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_DB_phase_claim_rejects_rehashed_automated_downgrade(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Downgrade subject\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review through endpoint.",
                transport="direct-openai",
            )
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            payload = valid_review_payload(
                {**request, **review_job_status(root, job_id=job["job_id"])}
            )
            with patch.object(
                review_bridge_module,
                "_openai_chat_completion",
                return_value={"choices": [{"message": {"content": json.dumps(payload)}}]},
            ), patch.object(
                review_bridge_module,
                "_persist_ingest_derived_evidence",
                side_effect=KeyboardInterrupt,
            ), self.assertRaises(KeyboardInterrupt):
                review_bridge_module.run_review_job(
                    root,
                    job_id=job["job_id"],
                    transport="direct-openai",
                )

            status_path = Path(job["status_uri"])
            downgraded = json.loads(status_path.read_text(encoding="utf-8"))
            raw_response_path = review_bridge_module._resolve_job_reference(
                root,
                job["job_id"],
                "raw_response_uri",
                downgraded["raw_response_uri"],
                evidence=downgraded,
            )
            downgraded["ingest_mode"] = "untracked"
            for key in (
                "pending_attempt_number",
                "pending_attempt_transport",
                "pending_attempt_started_at",
            ):
                downgraded.pop(key)
            downgraded["ingest_claim_sha256"] = (
                review_bridge_module._review_ingest_claim_sha256(
                    downgraded,
                    job_id=job["job_id"],
                )
            )
            status_path.write_text(json.dumps(downgraded), encoding="utf-8")
            files_before = {
                path.relative_to(Path(job["job_dir"])).as_posix(): path.read_bytes()
                for path in Path(job["job_dir"]).rglob("*")
                if path.is_file()
            }
            rows_before = artifact_rows(root)

            self.assertFalse(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            with self.assertRaisesRegex(ValueError, "DB-authoritative phase"):
                ingest_review_result(
                    root,
                    job_id=job["job_id"],
                    result_path=raw_response_path,
                )

            self.assertEqual(rows_before, artifact_rows(root))
            self.assertEqual(
                files_before,
                {
                    path.relative_to(Path(job["job_dir"])).as_posix(): path.read_bytes()
                    for path in Path(job["job_dir"]).rglob("*")
                    if path.is_file()
                },
            )

    def test_ingest_preflight_limits_and_empty_operation_id_are_nonmutating(self) -> None:
        limit = review_bridge_module.REVIEW_INTEGRITY_MAX_RECORD_BYTES
        for delta in (-1, 0, 1):
            with self.subTest(delta=delta):
                texts = {"boundary": "A" * (limit + delta)}
                if delta <= 0:
                    review_bridge_module._preflight_ingest_derived_texts(texts)
                else:
                    with self.assertRaisesRegex(ValueError, "integrity byte limit"):
                        review_bridge_module._preflight_ingest_derived_texts(texts)

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Operation binding subject\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="direct-openai",
            )
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            payload = valid_review_payload(
                {**request, **review_job_status(root, job_id=job["job_id"])}
            )
            payload.pop("capsule_challenge", None)
            payload["review_surface"] = "packet_excerpt_only"
            payload["subject_inspected"] = False
            job_dir = Path(job["job_dir"])
            files_before = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file()
            }
            rows_before = artifact_rows(root)
            status_before = Path(job["status_uri"]).read_bytes()

            with self.assertRaisesRegex(ValueError, "operation id"):
                ingest_review_result(
                    root,
                    job_id=job["job_id"],
                    content=json.dumps(payload),
                    operation_id="",
                )

            self.assertEqual(Path(job["status_uri"]).read_bytes(), status_before)
            self.assertEqual(artifact_rows(root), rows_before)
            self.assertEqual(
                files_before,
                {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file()
                },
            )

    def test_review_response_text_uses_one_utf8_byte_boundary(self) -> None:
        limit = review_bridge_module.REVIEW_INTEGRITY_MAX_RECORD_BYTES
        for delta in (-1, 0):
            with self.subTest(delta=delta):
                text = "A" * (limit + delta)
                self.assertEqual(
                    review_bridge_module._validated_review_response_text(text),
                    text,
                )
        with self.assertRaisesRegex(
            review_bridge_module.ReviewResponseSizeError,
            "UTF-8 response limit",
        ):
            review_bridge_module._validated_review_response_text(
                "A" * (limit + 1)
            )
        with self.assertRaisesRegex(ValueError, "not valid UTF-8"):
            review_bridge_module._validated_review_response_text(b"\xff")

    def test_oversized_automated_response_is_terminal_and_same_operation_is_idempotent(self) -> None:
        limit = review_bridge_module.REVIEW_INTEGRITY_MAX_RECORD_BYTES
        for transport in ("direct-openai", "hermes"):
            with self.subTest(transport=transport), tempfile.TemporaryDirectory(
                ignore_cleanup_errors=True
            ) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "README.md").write_text(
                    "# Oversized automated response\n",
                    encoding="utf-8",
                )
                job = create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review through the configured transport.",
                    transport=transport,
                )
                target = (
                    "_openai_chat_completion"
                    if transport == "direct-openai"
                    else "_run_hermes_oneshot"
                )
                oversized_result: object = (
                    {"padding": "A" * limit}
                    if transport == "direct-openai"
                    else "A" * (limit + 1)
                )
                with patch.object(
                    review_bridge_module,
                    target,
                    return_value=oversized_result,
                ) as first_call, self.assertRaisesRegex(
                    review_bridge_module.ReviewResponseSizeError,
                    "UTF-8 response limit",
                ):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport=transport,
                        operation_id="op-oversized-response",
                    )
                first_call.assert_called_once()

                failed = review_job_status(root, job_id=job["job_id"])
                self.assertEqual(failed["status"], "transport_failed")
                self.assertEqual(failed["attempt_count"], 1)
                self.assertEqual(
                    failed["error_type"],
                    review_bridge_module.ReviewResponseSizeError.__name__,
                )
                self.assertLess(len(failed["error"].encode("utf-8")), 1_000)
                self.assertNotIn("A" * 100, failed["error"])
                responses_dir = Path(job["job_dir"]) / "responses"
                self.assertEqual(list(responses_dir.iterdir()), [])
                self.assertTrue(
                    (Path(job["job_dir"]) / "attempts" / "attempt-001.json").is_file()
                )
                self.assertTrue(
                    (
                        Path(job["job_dir"])
                        / "attempt-receipts"
                        / "attempt-001.json"
                    ).is_file()
                )

                with patch.object(
                    review_bridge_module,
                    target,
                    side_effect=AssertionError("transport must not be called again"),
                ) as retry_call, self.assertRaisesRegex(
                    review_bridge_module.ReviewResponseSizeError,
                    "UTF-8 response limit",
                ):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport=transport,
                        operation_id="op-oversized-response",
                    )
                retry_call.assert_not_called()
                self.assertEqual(
                    review_job_status(root, job_id=job["job_id"])["attempt_count"],
                    1,
                )
                self.assertIsNone(
                    review_bridge_module._load_phase_envelope(
                        root,
                        job["job_id"],
                        phase="automated_reservation",
                        sequence=2,
                    )
                )

                with patch.object(
                    review_bridge_module,
                    target,
                    return_value=oversized_result,
                ) as distinct_call, self.assertRaisesRegex(
                    review_bridge_module.ReviewResponseSizeError,
                    "UTF-8 response limit",
                ):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport=transport,
                        operation_id="op-distinct-response-retry",
                    )
                distinct_call.assert_called_once()
                self.assertEqual(
                    review_job_status(root, job_id=job["job_id"])["attempt_count"],
                    2,
                )

                with patch.object(
                    review_bridge_module,
                    target,
                    side_effect=AssertionError(
                        "historical operation retry must not call transport"
                    ),
                ) as historical_retry, self.assertRaisesRegex(
                    review_bridge_module.ReviewResponseSizeError,
                    "UTF-8 response limit",
                ):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport=transport,
                        operation_id="op-oversized-response",
                    )
                historical_retry.assert_not_called()
                self.assertEqual(
                    review_job_status(root, job_id=job["job_id"])["attempt_count"],
                    2,
                )

                with patch.object(
                    review_bridge_module,
                    target,
                    side_effect=review_bridge_module.ReviewBridgeError(
                        "later distinct operation reached transport"
                    ),
                ) as later_distinct, self.assertRaisesRegex(
                    ValueError,
                    "later distinct operation reached transport",
                ):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport=transport,
                        operation_id="op-later-distinct-response-retry",
                    )
                later_distinct.assert_called_once()
                self.assertEqual(
                    review_job_status(root, job_id=job["job_id"])["attempt_count"],
                    3,
                )

                with patch.object(
                    review_bridge_module,
                    target,
                    side_effect=AssertionError(
                        "generic terminal operation retry must not call transport"
                    ),
                ) as generic_retry, self.assertRaisesRegex(
                    review_bridge_module.ReviewBridgeError,
                    "later distinct operation reached transport",
                ):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport=transport,
                        operation_id="op-later-distinct-response-retry",
                    )
                generic_retry.assert_not_called()
                self.assertEqual(
                    review_job_status(root, job_id=job["job_id"])["attempt_count"],
                    3,
                )

    def test_interrupted_oversized_terminalization_retries_without_transport(self) -> None:
        limit = review_bridge_module.REVIEW_INTEGRITY_MAX_RECORD_BYTES
        for transport in ("direct-openai", "hermes"):
            with self.subTest(transport=transport), tempfile.TemporaryDirectory(
                ignore_cleanup_errors=True
            ) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "README.md").write_text(
                    "# Interrupted oversized response\n",
                    encoding="utf-8",
                )
                job = create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review through the configured transport.",
                    transport=transport,
                )
                target = (
                    "_openai_chat_completion"
                    if transport == "direct-openai"
                    else "_run_hermes_oneshot"
                )
                oversized_result: object = (
                    {"padding": "A" * limit}
                    if transport == "direct-openai"
                    else "A" * (limit + 1)
                )
                with patch.object(
                    review_bridge_module,
                    target,
                    return_value=oversized_result,
                ) as first_call, patch.object(
                    review_bridge_module,
                    "_materialize_terminal_phase",
                    side_effect=KeyboardInterrupt,
                ), self.assertRaises(KeyboardInterrupt):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport=transport,
                        operation_id="op-interrupted-oversized-response",
                    )
                first_call.assert_called_once()

                with patch.object(
                    review_bridge_module,
                    target,
                    side_effect=AssertionError("transport must not be recalled"),
                ) as retry_call, self.assertRaisesRegex(
                    review_bridge_module.ReviewResponseSizeError,
                    "UTF-8 response limit",
                ):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport=transport,
                        operation_id="op-interrupted-oversized-response",
                    )
                retry_call.assert_not_called()
                recovered = review_job_status(root, job_id=job["job_id"])
                self.assertEqual(recovered["status"], "transport_failed")
                self.assertEqual(recovered["attempt_count"], 1)
                self.assertFalse(
                    (Path(job["job_dir"]) / "attempts" / "attempt-002.json").exists()
                )

    def test_oversized_browser_response_rejection_preserves_reservation(self) -> None:
        limit = review_bridge_module.REVIEW_INTEGRITY_MAX_RECORD_BYTES
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text(
                "# Browser response boundary\n",
                encoding="utf-8",
            )
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review through the browser handoff.",
                transport="manual",
            )
            reserved = review_browser_attempt_start(root, job_id=job["job_id"])
            response_path = Path(reserved["response_uri"])
            response_path.write_bytes(b"A" * (limit + 1))
            job_dir = Path(job["job_dir"])
            files_before = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file()
            }
            rows_before = artifact_rows(root)
            status_before = Path(job["status_uri"]).read_bytes()

            with self.assertRaisesRegex(
                review_bridge_module.ReviewResponseSizeError,
                "UTF-8 response limit",
            ):
                ingest_review_result(
                    root,
                    job_id=job["job_id"],
                    result_path=response_path,
                )

            self.assertEqual(Path(job["status_uri"]).read_bytes(), status_before)
            self.assertEqual(artifact_rows(root), rows_before)
            self.assertEqual(
                files_before,
                {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file()
                },
            )
            self.assertEqual(
                review_job_status(root, job_id=job["job_id"])["status"],
                "pending_browser_upload",
            )

    def test_oversized_inline_and_external_responses_are_preflight_nonmutating(self) -> None:
        limit = review_bridge_module.REVIEW_INTEGRITY_MAX_RECORD_BYTES
        for source_kind in ("inline", "external"):
            with self.subTest(source_kind=source_kind), tempfile.TemporaryDirectory(
                ignore_cleanup_errors=True
            ) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "README.md").write_text(
                    "# Ingest response boundary\n",
                    encoding="utf-8",
                )
                job = create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review the response boundary.",
                    transport="direct-openai",
                )
                ingest_arguments: dict[str, object] = {
                    "job_id": job["job_id"],
                }
                if source_kind == "inline":
                    ingest_arguments["content"] = "A" * (limit + 1)
                else:
                    external_path = base / "external-response.txt"
                    external_path.write_bytes(b"A" * (limit + 1))
                    ingest_arguments["result_path"] = external_path
                job_dir = Path(job["job_dir"])
                files_before = {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file()
                }
                rows_before = artifact_rows(root)
                status_before = Path(job["status_uri"]).read_bytes()

                with self.assertRaisesRegex(
                    review_bridge_module.ReviewResponseSizeError,
                    "UTF-8 response limit",
                ):
                    ingest_review_result(root, **ingest_arguments)

                self.assertEqual(Path(job["status_uri"]).read_bytes(), status_before)
                self.assertEqual(artifact_rows(root), rows_before)
                self.assertEqual(
                    files_before,
                    {
                        path.relative_to(job_dir).as_posix(): path.read_bytes()
                        for path in job_dir.rglob("*")
                        if path.is_file()
                    },
                )

    def test_oversized_inline_preflight_does_not_migrate_legacy_status(self) -> None:
        limit = review_bridge_module.REVIEW_INTEGRITY_MAX_RECORD_BYTES
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text(
                "# Legacy response preflight\n",
                encoding="utf-8",
            )
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review the response boundary.",
                transport="direct-openai",
            )
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            status_path = Path(job["status_uri"])
            legacy_status = json.loads(status_path.read_text(encoding="utf-8"))
            copied_legacy_keys = {
                key
                for key in review_bridge_module.LEGACY_STATUS_IMMUTABLE_KEYS
                if key in request
            }
            self.assertTrue(copied_legacy_keys)
            for key in copied_legacy_keys:
                legacy_status[key] = request[key]
            status_path.write_text(
                review_bridge_module.json_dumps(legacy_status),
                encoding="utf-8",
            )
            status_before = status_path.read_bytes()
            rows_before = artifact_rows(root)

            with self.assertRaisesRegex(
                review_bridge_module.ReviewResponseSizeError,
                "UTF-8 response limit",
            ):
                ingest_review_result(
                    root,
                    job_id=job["job_id"],
                    content="A" * (limit + 1),
                )

            self.assertEqual(status_path.read_bytes(), status_before)
            self.assertEqual(artifact_rows(root), rows_before)
            stored_status = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertTrue(copied_legacy_keys.issubset(stored_status))

    def test_endpoint_response_read_stops_at_limit_plus_one(self) -> None:
        limit = review_bridge_module.REVIEW_INTEGRITY_MAX_RECORD_BYTES
        with patch.object(
            review_bridge_module,
            "_run_bounded_process",
            return_value=bounded_process_result(
                stdout=b"A" * (limit + 1),
                output_exceeded=True,
                observed_stdout_bytes=limit + 1,
            ),
        ) as run_process, self.assertRaisesRegex(
            review_bridge_module.ReviewResponseSizeError,
            "UTF-8 response limit",
        ):
            review_bridge_module._openai_chat_completion(
                base_url="http://127.0.0.1:8020/v1",
                model="test-model",
                system_prompt="Review.",
                user_prompt="Review.",
                timeout_seconds=1,
                max_tokens=1,
            )
        self.assertEqual(
            run_process.call_args.kwargs["stdout_limit"],
            limit,
        )

    def test_endpoint_response_enforces_one_total_elapsed_deadline(self) -> None:
        with patch.object(
            review_bridge_module,
            "_run_bounded_process",
            return_value=bounded_process_result(timed_out=True),
        ) as run_process, self.assertRaisesRegex(
            review_bridge_module.ReviewBridgeError,
            "total elapsed-time limit",
        ):
            review_bridge_module._openai_chat_completion(
                base_url="http://127.0.0.1:8020/v1",
                model="test-model",
                system_prompt="Review.",
                user_prompt="Review.",
                timeout_seconds=1,
                max_tokens=1,
            )
        self.assertEqual(run_process.call_args.kwargs["timeout_seconds"], 1)

    def test_endpoint_total_deadline_terminates_real_dribbling_child(self) -> None:
        class DribblingHandler(http.server.BaseHTTPRequestHandler):
            def log_message(self, _format: str, *args: object) -> None:
                return None

            def do_POST(self) -> None:
                content_length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(content_length)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "1000000")
                self.end_headers()
                try:
                    for _index in range(100):
                        self.wfile.write(b"{")
                        self.wfile.flush()
                        time.sleep(0.1)
                except (BrokenPipeError, ConnectionResetError):
                    return

        server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0),
            DribblingHandler,
        )
        server.daemon_threads = True
        server_thread = threading.Thread(
            target=server.serve_forever,
            name="continuum-test-dribbling-endpoint",
            daemon=True,
        )
        server_thread.start()
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(
                review_bridge_module.ReviewBridgeError,
                "total elapsed-time limit",
            ):
                review_bridge_module._openai_chat_completion(
                    base_url=f"http://127.0.0.1:{server.server_port}/v1",
                    model="test-model",
                    system_prompt="Review.",
                    user_prompt="Review.",
                    timeout_seconds=1,
                    max_tokens=1,
                )
        finally:
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=5)
        self.assertLess(time.monotonic() - started, 5)

    def test_hermes_response_capture_terminates_live_producer_near_limit(self) -> None:
        limit = review_bridge_module.REVIEW_INTEGRITY_MAX_RECORD_BYTES
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            counter = base / "producer-bytes.txt"
            producer_pid_path = base / "producer-pid.txt"
            launcher_script = base / "chat"
            producer_script = base / "producer.py"
            producer_script.write_text(
                "import os, pathlib, sys\n"
                f"counter = pathlib.Path({str(counter)!r})\n"
                f"pathlib.Path({str(producer_pid_path)!r}).write_text(str(os.getpid()), encoding='utf-8')\n"
                "chunk = b'A' * 65536\n"
                "total = 0\n"
                "with counter.open('w', encoding='utf-8') as handle:\n"
                "    while True:\n"
                "        try:\n"
                "            written = os.write(sys.stdout.fileno(), chunk)\n"
                "        except BrokenPipeError:\n"
                "            break\n"
                "        total += written\n"
                "        handle.seek(0)\n"
                "        handle.write(str(total))\n"
                "        handle.truncate()\n"
                "        handle.flush()\n",
                encoding="utf-8",
            )
            launcher_script.write_text(
                "import subprocess, sys\n"
                "raise SystemExit(subprocess.call(\n"
                f"    [sys.executable, {str(producer_script)!r}]\n"
                "))\n",
                encoding="utf-8",
            )
            job = {
                "job_id": "review-test",
                "packet_sha256": "a" * 64,
                "review_capsule_sha256": "b" * 64,
                "subject_archive_sha256": "c" * 64,
                "sentinel": "sentinel",
                "request_uri": "request.json",
                "prompt_uri": "review-prompt.md",
                "schema_uri": "expected-response.schema.json",
                "packet_uri": "review-packet.md",
            }
            previous_cwd = Path.cwd()
            try:
                os.chdir(base)
                with patch.dict(
                    os.environ,
                    {"CONTINUUM_HERMES_EXE": sys.executable},
                ), self.assertRaisesRegex(
                    review_bridge_module.ReviewResponseSizeError,
                    "UTF-8 response limit",
                ):
                    review_bridge_module._run_hermes_oneshot(
                        job=job,
                        model="test-model",
                        timeout_seconds=10,
                    )
            finally:
                os.chdir(previous_cwd)
            produced = int(counter.read_text(encoding="utf-8") or "0")
            producer_pid = int(producer_pid_path.read_text(encoding="utf-8"))
            overshoot_allowance = review_bridge_module.REVIEW_PROCESS_READ_CHUNK_BYTES * 8
            self.assertGreater(produced, limit - review_bridge_module.REVIEW_PROCESS_READ_CHUNK_BYTES)
            self.assertLessEqual(produced, limit + overshoot_allowance)
            if os.name == "nt":
                tasklist = subprocess.run(
                    [
                        "tasklist",
                        "/FI",
                        f"PID eq {producer_pid}",
                        "/FO",
                        "CSV",
                        "/NH",
                    ],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertNotIn(f'"{producer_pid}"', tasklist.stdout)
            else:
                self.assertTrue(wait_for_posix_process_termination(producer_pid))

    def test_bounded_process_terminates_descendant_after_launcher_exits(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            producer_pid_path = base / "producer-pid.txt"
            completion_path = base / "producer-completed.txt"
            producer_script = base / "producer.py"
            launcher_script = base / "launcher.py"
            producer_script.write_text(
                "import os, pathlib, time\n"
                f"pathlib.Path({str(producer_pid_path)!r}).write_text(str(os.getpid()), encoding='utf-8')\n"
                "time.sleep(30)\n"
                f"pathlib.Path({str(completion_path)!r}).write_text('completed', encoding='utf-8')\n",
                encoding="utf-8",
            )
            launcher_script.write_text(
                "import pathlib, subprocess, sys, time\n"
                f"pid_path = pathlib.Path({str(producer_pid_path)!r})\n"
                f"subprocess.Popen([sys.executable, {str(producer_script)!r}], "
                "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
                "for _ in range(200):\n"
                "    if pid_path.exists():\n"
                "        break\n"
                "    time.sleep(0.01)\n",
                encoding="utf-8",
            )

            producer_pid: int | None = None
            try:
                result = review_bridge_module._run_bounded_process(
                    [sys.executable, str(launcher_script)],
                    cwd=base,
                    env=os.environ.copy(),
                    timeout_seconds=5,
                    stdout_limit=1_024,
                    stderr_limit=1_024,
                    total_limit=2_048,
                )
                self.assertEqual(result.returncode, 0)
                self.assertTrue(producer_pid_path.exists())
                producer_pid = int(producer_pid_path.read_text(encoding="utf-8"))
                self.assertFalse(completion_path.exists())
                if os.name == "nt":
                    tasklist = subprocess.run(
                        [
                            "tasklist",
                            "/FI",
                            f"PID eq {producer_pid}",
                            "/FO",
                            "CSV",
                            "/NH",
                        ],
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertNotIn(f'"{producer_pid}"', tasklist.stdout)
                else:
                    self.assertTrue(wait_for_posix_process_termination(producer_pid))
            finally:
                if producer_pid is not None:
                    if os.name == "nt":
                        subprocess.run(
                            ["taskkill", "/PID", str(producer_pid), "/T", "/F"],
                            check=False,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                    else:
                        try:
                            os.kill(producer_pid, getattr(signal, "SIGKILL", signal.SIGTERM))
                        except ProcessLookupError:
                            pass

    def test_automated_valid_response_enforces_integrated_derived_size_boundary(self) -> None:
        limit = review_bridge_module.REVIEW_INTEGRITY_MAX_RECORD_BYTES
        for delta in (-1, 0, 1):
            with self.subTest(delta=delta), tempfile.TemporaryDirectory(
                ignore_cleanup_errors=True
            ) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "README.md").write_text(
                    "# Oversized response subject\n",
                    encoding="utf-8",
                )
                job = create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review through endpoint.",
                    transport="direct-openai",
                )
                request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
                payload = valid_review_payload(
                    {**request, **review_job_status(root, job_id=job["job_id"])}
                )
                payload.pop("capsule_challenge", None)
                payload["review_surface"] = "packet_excerpt_only"
                payload["subject_inspected"] = False
                payload["boundary_padding"] = "A"
                runtime_job = review_bridge_module._load_job(root, job["job_id"])
                baseline = review_bridge_module._apply_coverage_guard(
                    runtime_job,
                    review_bridge_module._normalize_review_result(payload),
                )
                baseline_max = max(
                    len(review_bridge_module.json_dumps(baseline).encode("utf-8")),
                    len(
                        review_bridge_module._findings_markdown(
                            baseline,
                            job_id=job["job_id"],
                        ).encode("utf-8")
                    ),
                )
                padding_size = 1 + (limit + delta - baseline_max)
                self.assertGreater(padding_size, 0)
                payload["boundary_padding"] = "A" * padding_size
                normalized = review_bridge_module._apply_coverage_guard(
                    runtime_job,
                    review_bridge_module._normalize_review_result(payload),
                )
                self.assertEqual(
                    max(
                        len(review_bridge_module.json_dumps(normalized).encode("utf-8")),
                        len(
                            review_bridge_module._findings_markdown(
                                normalized,
                                job_id=job["job_id"],
                            ).encode("utf-8")
                        ),
                    ),
                    limit + delta,
                )

                endpoint_patch = patch.object(
                    review_bridge_module,
                    "_openai_chat_completion",
                    return_value={"choices": [{"message": {"content": json.dumps(payload)}}]},
                )
                if delta <= 0:
                    with endpoint_patch:
                        result = review_bridge_module.run_review_job(
                            root,
                            job_id=job["job_id"],
                            transport="direct-openai",
                        )
                    self.assertEqual(result["status"], "ingested")
                    self.assertEqual(result["ingest"]["ingest_mode"], "automated")
                else:
                    with endpoint_patch, self.assertRaisesRegex(
                        ValueError,
                        "integrity byte limit",
                    ):
                        review_bridge_module.run_review_job(
                            root,
                            job_id=job["job_id"],
                            transport="direct-openai",
                        )
                    stored_status = json.loads(
                        Path(job["status_uri"]).read_text(encoding="utf-8")
                    )
                    self.assertEqual(stored_status["status"], "submitting")
                    self.assertEqual(stored_status["attempt_count"], 0)
                    self.assertEqual(stored_status["pending_attempt_number"], 1)
                    conn = connect(root)
                    try:
                        self.assertEqual(
                            conn.execute(
                                """
                                SELECT count(*) FROM artifacts
                                WHERE kind = 'review_phase_envelope'
                                  AND uri LIKE '%phase-automated-reservation-001.json'
                                """
                            ).fetchone()[0],
                            1,
                        )
                        self.assertEqual(
                            conn.execute(
                                """
                                SELECT count(*) FROM artifacts
                                WHERE kind = 'review_phase_envelope'
                                  AND uri LIKE '%phase-ingest-%'
                                """
                            ).fetchone()[0],
                            0,
                        )
                        self.assertEqual(
                            conn.execute(
                                """
                                SELECT count(*) FROM artifacts
                                WHERE kind IN ('review_ingest_receipt', 'review_attempt_receipt')
                                """
                            ).fetchone()[0],
                            0,
                        )
                    finally:
                        conn.close()

    def test_untracked_ingest_catalog_failures_restore_new_derived_files_and_retry(self) -> None:
        for source_kind, failure_kind in (
            ("content", "record"),
            ("result_path", "commit"),
        ):
            with self.subTest(source_kind=source_kind, failure_kind=failure_kind), tempfile.TemporaryDirectory(
                ignore_cleanup_errors=True
            ) as tmp:
                base = Path(tmp)
                root = base / "continuum"
                subject = base / "subject"
                subject.mkdir()
                (subject / "README.md").write_text("# Untracked rollback subject\n", encoding="utf-8")
                job = create_review_job(
                    root,
                    subject_path=subject,
                    prompt="Review hard.",
                    transport="direct-openai",
                )
                request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
                payload = valid_review_payload(
                    {**request, **review_job_status(root, job_id=job["job_id"])}
                )
                payload.pop("capsule_challenge", None)
                payload["review_surface"] = "packet_excerpt_only"
                payload["subject_inspected"] = False
                content = json.dumps(payload)
                kwargs: dict[str, object]
                if source_kind == "content":
                    kwargs = {"content": content}
                else:
                    external_result = base / "review-result.json"
                    external_result.write_text(content, encoding="utf-8")
                    kwargs = {"result_path": external_result}
                rows_before = non_phase_artifact_rows(root)

                if failure_kind == "record":
                    real_record_artifact = review_bridge_module.record_artifact

                    def fail_last_record(conn: object, **record_kwargs: object) -> str:
                        if record_kwargs.get("kind") == "review_ingest_receipt":
                            raise RuntimeError("synthetic ingest receipt record failure")
                        return real_record_artifact(conn, **record_kwargs)  # type: ignore[arg-type]

                    failure_patch = patch.object(
                        review_bridge_module,
                        "record_artifact",
                        side_effect=fail_last_record,
                    )
                else:
                    real_connect = review_bridge_module.connect

                    class CommitFailingConnection:
                        def __init__(self, inner: object) -> None:
                            self.inner = inner

                        def __getattr__(self, name: str) -> object:
                            return getattr(self.inner, name)

                        def commit(self) -> None:
                            raise RuntimeError("synthetic ingest catalog commit failure")

                    connect_calls = 0

                    def fail_derived_commit(value: Path) -> object:
                        nonlocal connect_calls
                        connect_calls += 1
                        connection = real_connect(value)
                        if connect_calls == 1:
                            return connection
                        return CommitFailingConnection(connection)

                    failure_patch = patch.object(
                        review_bridge_module,
                        "connect",
                        side_effect=fail_derived_commit,
                    )

                with failure_patch, self.assertRaisesRegex(
                    ValueError,
                    "review ingest artifact catalog transaction failed",
                ):
                    ingest_review_result(root, job_id=job["job_id"], **kwargs)

                interrupted = review_job_status(root, job_id=job["job_id"])
                stored_status = json.loads(Path(job["status_uri"]).read_text(encoding="utf-8"))
                raw_response_path = Path(str(interrupted["raw_response_uri"]))
                self.assertEqual(interrupted["status"], "ingesting")
                self.assertEqual(interrupted["accepted_ingest_count"], 0)
                self.assertEqual(interrupted["attempt_count"], 0)
                self.assertEqual(stored_status["ingest_mode"], "untracked")
                self.assertTrue(stored_status["ingest_claim_sha256"])
                self.assertEqual(raw_response_path.read_text(encoding="utf-8"), content)
                derived_paths = pending_derived_paths(root, job, stored_status)
                self.assertTrue(all(not path.exists() for path in derived_paths))
                self.assertEqual(non_phase_artifact_rows(root), rows_before)
                self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
                self.assertTrue(semantic_integrity_report(root)["ok"])

                receipt = ingest_review_result(
                    root,
                    job_id=job["job_id"],
                    result_path=raw_response_path,
                )

                final_status = review_job_status(root, job_id=job["job_id"])
                self.assertTrue(receipt["ok"])
                self.assertEqual(final_status["status"], "ingested")
                self.assertEqual(final_status["accepted_ingest_count"], 1)
                self.assertEqual(final_status["attempt_count"], 0)
                self.assertTrue(all(path.is_file() for path in derived_paths))
                self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
                self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_automated_ingest_catalog_failure_restores_new_derived_files_and_retry(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Automated rollback subject\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review through endpoint.",
                transport="direct-openai",
            )
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            payload = valid_review_payload(
                {**request, **review_job_status(root, job_id=job["job_id"])}
            )
            rows_before = non_phase_artifact_rows(root)
            real_record_artifact = review_bridge_module.record_artifact

            def fail_last_record(conn: object, **record_kwargs: object) -> str:
                if record_kwargs.get("kind") == "review_ingest_receipt":
                    raise RuntimeError("synthetic automated ingest record failure")
                return real_record_artifact(conn, **record_kwargs)  # type: ignore[arg-type]

            with patch.object(
                review_bridge_module,
                "_openai_chat_completion",
                return_value={"choices": [{"message": {"content": json.dumps(payload)}}]},
            ), patch.object(
                review_bridge_module,
                "record_artifact",
                side_effect=fail_last_record,
            ), self.assertRaisesRegex(
                ValueError,
                "review ingest artifact catalog transaction failed",
            ):
                review_bridge_module.run_review_job(
                    root,
                    job_id=job["job_id"],
                    transport="direct-openai",
                )

            interrupted = review_job_status(root, job_id=job["job_id"])
            stored_status = json.loads(Path(job["status_uri"]).read_text(encoding="utf-8"))
            raw_response_path = Path(str(interrupted["raw_response_uri"]))
            self.assertEqual(interrupted["status"], "ingesting")
            self.assertEqual(interrupted["accepted_ingest_count"], 0)
            self.assertEqual(interrupted["attempt_count"], 0)
            self.assertEqual(stored_status["ingest_mode"], "automated")
            self.assertEqual(stored_status["pending_attempt_number"], 1)
            self.assertEqual(stored_status["pending_attempt_transport"], "direct-openai")
            self.assertTrue(raw_response_path.is_file())
            derived_paths = pending_derived_paths(root, job, stored_status)
            self.assertTrue(all(not path.exists() for path in derived_paths))
            self.assertEqual(non_phase_artifact_rows(root), rows_before)
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])

            receipt = ingest_review_result(
                root,
                job_id=job["job_id"],
                result_path=raw_response_path,
            )

            final_status = review_job_status(root, job_id=job["job_id"])
            self.assertTrue(receipt["ok"])
            self.assertEqual(final_status["status"], "ingested")
            self.assertEqual(final_status["accepted_ingest_count"], 1)
            self.assertEqual(final_status["attempt_count"], 1)
            self.assertTrue((Path(job["job_dir"]) / "attempts" / "attempt-001.json").is_file())
            self.assertTrue(
                (Path(job["job_dir"]) / "attempt-receipts" / "attempt-001.json").is_file()
            )
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_browser_ingest_catalog_failure_restores_new_derived_files_and_retry(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Browser rollback subject\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="manual",
            )
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            reserved = review_browser_attempt_start(root, job_id=job["job_id"])
            response_path = Path(reserved["response_uri"])
            response_path.write_text(
                json.dumps(
                    valid_review_payload(
                        {**request, **review_job_status(root, job_id=job["job_id"])}
                    )
                ),
                encoding="utf-8",
            )
            attempt_path = Path(reserved["attempt_uri"])
            attempt_before = attempt_path.read_bytes()
            rows_before = non_phase_artifact_rows(root)
            real_record_artifact = review_bridge_module.record_artifact

            def fail_last_record(conn: object, **record_kwargs: object) -> str:
                if record_kwargs.get("kind") == "review_ingest_receipt":
                    raise RuntimeError("synthetic browser ingest record failure")
                return real_record_artifact(conn, **record_kwargs)  # type: ignore[arg-type]

            with patch.object(
                review_bridge_module,
                "record_artifact",
                side_effect=fail_last_record,
            ), self.assertRaisesRegex(
                ValueError,
                "review ingest artifact catalog transaction failed",
            ):
                ingest_review_result(root, job_id=job["job_id"], result_path=response_path)

            interrupted = review_job_status(root, job_id=job["job_id"])
            stored_status = json.loads(Path(job["status_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(interrupted["status"], "ingesting")
            self.assertEqual(interrupted["accepted_ingest_count"], 0)
            self.assertEqual(stored_status["ingest_mode"], "browser_reserved")
            self.assertEqual(attempt_path.read_bytes(), attempt_before)
            self.assertTrue(Path(str(interrupted["raw_response_uri"])).samefile(response_path))
            derived_paths = pending_derived_paths(root, job, stored_status)
            self.assertTrue(all(not path.exists() for path in derived_paths))
            self.assertEqual(non_phase_artifact_rows(root), rows_before)
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])

            receipt = ingest_review_result(
                root,
                job_id=job["job_id"],
                result_path=response_path,
            )

            final_status = review_job_status(root, job_id=job["job_id"])
            self.assertTrue(receipt["ok"])
            self.assertEqual(final_status["status"], "ingested")
            self.assertEqual(final_status["accepted_ingest_count"], 1)
            self.assertTrue((Path(job["job_dir"]) / "attempt-receipts" / "attempt-001.json").is_file())
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_resumed_durable_ingest_catalog_failure_preserves_exact_evidence_and_retry(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Durable rollback subject\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review through endpoint.",
                transport="direct-openai",
            )
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            payload = valid_review_payload(
                {**request, **review_job_status(root, job_id=job["job_id"])}
            )
            with patch.object(
                review_bridge_module,
                "_openai_chat_completion",
                return_value={"choices": [{"message": {"content": json.dumps(payload)}}]},
            ), patch.object(
                review_bridge_module,
                "_record_attempt_receipt_artifact",
                side_effect=RuntimeError("synthetic finalization catalog failure"),
            ), self.assertRaisesRegex(ValueError, "finalization failed and was rolled back"):
                review_bridge_module.run_review_job(
                    root,
                    job_id=job["job_id"],
                    transport="direct-openai",
                )

            interrupted = review_job_status(root, job_id=job["job_id"])
            raw_response_path = Path(str(interrupted["raw_response_uri"]))
            stored_status = json.loads(Path(job["status_uri"]).read_text(encoding="utf-8"))
            derived_paths = pending_derived_paths(root, job, stored_status)
            derived_before = {path: path.read_bytes() for path in derived_paths}
            real_record_artifact = review_bridge_module.record_artifact

            def fail_last_record(conn: object, **record_kwargs: object) -> str:
                if record_kwargs.get("kind") == "review_ingest_receipt":
                    raise RuntimeError("synthetic resumed ingest record failure")
                return real_record_artifact(conn, **record_kwargs)  # type: ignore[arg-type]

            with patch.object(
                review_bridge_module,
                "record_artifact",
                side_effect=fail_last_record,
            ):
                receipt = ingest_review_result(
                    root,
                    job_id=job["job_id"],
                    result_path=raw_response_path,
                )

            self.assertTrue(receipt["ok"])
            self.assertEqual({path: path.read_bytes() for path in derived_paths}, derived_before)
            self.assertTrue(raw_response_path.is_file())
            self.assertEqual(
                review_job_status(root, job_id=job["job_id"])["status"],
                "ingested",
            )
            self.assertEqual(
                [path.name for path in (Path(job["job_dir"]) / "attempts").iterdir()],
                ["attempt-001.json"],
            )
            self.assertEqual(
                [
                    path.name
                    for path in (Path(job["job_dir"]) / "attempt-receipts").iterdir()
                ],
                ["attempt-001.json"],
            )
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])

    def test_automated_ingest_claim_cannot_be_downgraded_before_retry(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Direct claim subject\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review through endpoint.",
                transport="direct-openai",
            )
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            payload = valid_review_payload(
                {**request, **review_job_status(root, job_id=job["job_id"])}
            )
            job_dir = Path(job["job_dir"])

            with patch.object(
                review_bridge_module,
                "_openai_chat_completion",
                return_value={"choices": [{"message": {"content": json.dumps(payload)}}]},
            ), patch.object(
                review_bridge_module,
                "_record_attempt_receipt_artifact",
                side_effect=RuntimeError("synthetic receipt catalog failure"),
            ):
                with self.assertRaisesRegex(ValueError, "finalization failed and was rolled back"):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport="direct-openai",
                    )

            status_path = Path(job["status_uri"])
            interrupted_status = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(interrupted_status["status"], "ingesting")
            self.assertEqual(interrupted_status["ingest_mode"], "automated")
            original_claim_hash = interrupted_status["ingest_claim_sha256"]
            self.assertEqual(
                original_claim_hash,
                review_bridge_module._review_ingest_claim_sha256(
                    interrupted_status,
                    job_id=job["job_id"],
                ),
            )
            without_operation = dict(interrupted_status)
            without_operation.pop("pending_operation_id")
            with_string_operation = dict(interrupted_status)
            with_string_operation["pending_operation_id"] = "op_different"
            self.assertNotEqual(
                review_bridge_module._review_ingest_claim_sha256(
                    without_operation,
                    job_id=job["job_id"],
                ),
                original_claim_hash,
            )
            self.assertNotEqual(
                review_bridge_module._review_ingest_claim_sha256(
                    with_string_operation,
                    job_id=job["job_id"],
                ),
                original_claim_hash,
            )

            for key in (
                "pending_attempt_number",
                "pending_attempt_transport",
                "pending_attempt_started_at",
            ):
                interrupted_status.pop(key)
            status_path.write_text(json.dumps(interrupted_status), encoding="utf-8")

            self.assertFalse(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertFalse(semantic_integrity_report(root)["ok"])
            with self.assertRaisesRegex(ValueError, "lifecycle is invalid|terminal status drifted"):
                review_job_status(root, job_id=job["job_id"])

            before_files = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file() and not path.is_symlink()
            }
            conn = connect(root)
            try:
                before_rows = [
                    tuple(row) for row in conn.execute("SELECT * FROM artifacts ORDER BY id")
                ]
            finally:
                conn.close()
            with self.assertRaisesRegex(ValueError, "lifecycle is invalid|terminal status drifted"):
                ingest_review_result(
                    root,
                    job_id=job["job_id"],
                    result_path=Path(str(interrupted_status["raw_response_uri"])),
                )
            self.assertEqual(
                before_files,
                {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file() and not path.is_symlink()
                },
            )
            conn = connect(root)
            try:
                self.assertEqual(
                    before_rows,
                    [tuple(row) for row in conn.execute("SELECT * FROM artifacts ORDER BY id")],
                )
            finally:
                conn.close()
            self.assertEqual(list((job_dir / "attempts").iterdir()), [])
            self.assertEqual(list((job_dir / "attempt-receipts").iterdir()), [])

    def test_standalone_pending_operation_id_invalidates_status_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Pending operation subject\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="direct-openai",
            )
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            payload = valid_review_payload(
                {**request, **review_job_status(root, job_id=job["job_id"])}
            )
            payload.pop("capsule_challenge", None)
            payload["review_surface"] = "packet_excerpt_only"
            payload["subject_inspected"] = False
            status_path = Path(job["status_uri"])
            stored_status = json.loads(status_path.read_text(encoding="utf-8"))
            stored_status["pending_operation_id"] = "op_unbound"
            status_path.write_text(json.dumps(stored_status), encoding="utf-8")
            job_dir = Path(job["job_dir"])

            self.assertFalse(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertFalse(semantic_integrity_report(root)["ok"])
            with self.assertRaisesRegex(ValueError, "lifecycle is invalid"):
                review_job_status(root, job_id=job["job_id"])
            before = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file() and not path.is_symlink()
            }
            with self.assertRaisesRegex(ValueError, "lifecycle is invalid"):
                ingest_review_result(
                    root,
                    job_id=job["job_id"],
                    content=json.dumps(payload),
                )
            self.assertEqual(
                before,
                {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file() and not path.is_symlink()
                },
            )

    def test_durable_pending_receipt_blocks_recomputed_mode_downgrade(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Durable claim subject\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review through endpoint.",
                transport="direct-openai",
            )
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            payload = valid_review_payload(
                {**request, **review_job_status(root, job_id=job["job_id"])}
            )
            job_dir = Path(job["job_dir"])
            with patch.object(
                review_bridge_module,
                "_openai_chat_completion",
                return_value={"choices": [{"message": {"content": json.dumps(payload)}}]},
            ), patch.object(
                review_bridge_module,
                "_record_attempt_receipt_artifact",
                side_effect=RuntimeError("synthetic attempt receipt catalog failure"),
            ):
                with self.assertRaisesRegex(ValueError, "finalization failed and was rolled back"):
                    review_bridge_module.run_review_job(
                        root,
                        job_id=job["job_id"],
                        transport="direct-openai",
                    )

            interrupted = review_job_status(root, job_id=job["job_id"])
            raw_response_path = Path(str(interrupted["raw_response_uri"]))
            status_path = Path(job["status_uri"])
            original_status = json.loads(status_path.read_text(encoding="utf-8"))
            pending_receipt_path = review_bridge_module._resolve_job_reference(
                root,
                job["job_id"],
                "pending_ingest_receipt_uri",
                original_status["pending_ingest_receipt_uri"],
                evidence=original_status,
            )
            self.assertTrue(pending_receipt_path.is_file())
            conn = connect(root)
            try:
                self.assertEqual(
                    conn.execute(
                        "SELECT count(*) FROM artifacts WHERE kind = 'review_ingest_receipt'"
                    ).fetchone()[0],
                    1,
                )
            finally:
                conn.close()
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])

            unknown_status = dict(original_status)
            unknown_status["ingest_mode"] = "unknown"
            unknown_status["ingest_claim_sha256"] = (
                review_bridge_module._review_ingest_claim_sha256(
                    unknown_status,
                    job_id=job["job_id"],
                )
            )
            status_path.write_text(json.dumps(unknown_status), encoding="utf-8")
            self.assertFalse(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            with self.assertRaisesRegex(ValueError, "exact ingest mode"):
                review_job_status(root, job_id=job["job_id"])

            downgraded_status = dict(original_status)
            downgraded_status["ingest_mode"] = "untracked"
            for key in (
                "pending_attempt_number",
                "pending_attempt_transport",
                "pending_attempt_started_at",
            ):
                downgraded_status.pop(key)
            downgraded_status["ingest_claim_sha256"] = (
                review_bridge_module._review_ingest_claim_sha256(
                    downgraded_status,
                    job_id=job["job_id"],
                )
            )
            status_path.write_text(json.dumps(downgraded_status), encoding="utf-8")

            self.assertFalse(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertFalse(semantic_integrity_report(root)["ok"])
            with self.assertRaisesRegex(
                ValueError,
                "pending ingest binding is invalid|terminal status drifted",
            ):
                review_job_status(root, job_id=job["job_id"])
            before_files = {
                path.relative_to(job_dir).as_posix(): path.read_bytes()
                for path in job_dir.rglob("*")
                if path.is_file() and not path.is_symlink()
            }
            conn = connect(root)
            try:
                before_rows = [
                    tuple(row) for row in conn.execute("SELECT * FROM artifacts ORDER BY id")
                ]
            finally:
                conn.close()
            with self.assertRaisesRegex(
                ValueError,
                "pending ingest binding is invalid|terminal status drifted",
            ):
                ingest_review_result(
                    root,
                    job_id=job["job_id"],
                    result_path=raw_response_path,
                )
            self.assertEqual(
                before_files,
                {
                    path.relative_to(job_dir).as_posix(): path.read_bytes()
                    for path in job_dir.rglob("*")
                    if path.is_file() and not path.is_symlink()
                },
            )
            conn = connect(root)
            try:
                self.assertEqual(
                    before_rows,
                    [tuple(row) for row in conn.execute("SELECT * FROM artifacts ORDER BY id")],
                )
            finally:
                conn.close()
            self.assertEqual(list((job_dir / "attempts").iterdir()), [])
            self.assertEqual(list((job_dir / "attempt-receipts").iterdir()), [])

    def test_terminal_ingest_receipt_prevents_mode_downgrade(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Terminal claim subject\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review through endpoint.",
                transport="direct-openai",
            )
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            legacy_request = dict(request)
            legacy_request.pop("ingest_binding_schema")
            legacy_request_text = review_bridge_module.json_dumps(legacy_request)
            request_path = Path(job["request_uri"])
            request_path.write_text(legacy_request_text, encoding="utf-8")
            replace_review_request_artifact(
                root,
                job_id=job["job_id"],
                request_path=request_path,
            )
            payload = valid_review_payload(
                {**request, **review_job_status(root, job_id=job["job_id"])}
            )
            with patch.object(
                review_bridge_module,
                "_openai_chat_completion",
                return_value={"choices": [{"message": {"content": json.dumps(payload)}}]},
            ):
                review_bridge_module.run_review_job(
                    root,
                    job_id=job["job_id"],
                    transport="direct-openai",
                    operation_id="op_automated_review",
                )

            status_path = Path(job["status_uri"])
            terminal_status = json.loads(status_path.read_text(encoding="utf-8"))
            receipt_path = Path(
                review_bridge_module._resolve_job_reference(
                    root,
                    job["job_id"],
                    "ingest_receipt_uri",
                    terminal_status["ingest_receipt_uri"],
                    evidence=terminal_status,
                )
            )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertEqual(receipt["ingest_mode"], "automated")
            self.assertEqual(receipt["ingest_claim"]["attempt"]["attempt"], 1)
            self.assertEqual(
                receipt["ingest_claim"]["operation_id"],
                {"present": True, "value": "op_automated_review"},
            )

            forged_claim = dict(receipt["ingest_claim"])
            forged_claim["mode"] = "untracked"
            forged_claim["attempt"] = None
            terminal_status["ingest_mode"] = "untracked"
            terminal_status["ingest_claim_sha256"] = review_bridge_module.content_hash(
                json.dumps(forged_claim, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            )
            status_path.write_text(json.dumps(terminal_status), encoding="utf-8")

            self.assertFalse(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertFalse(semantic_integrity_report(root)["ok"])
            with self.assertRaisesRegex(ValueError, "terminal ingest binding is invalid"):
                review_job_status(root, job_id=job["job_id"])

    def test_untracked_direct_ingest_remains_certified_without_attempt(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            base = Path(tmp)
            root = base / "continuum"
            subject = base / "subject"
            subject.mkdir()
            (subject / "README.md").write_text("# Untracked ingest subject\n", encoding="utf-8")
            job = create_review_job(
                root,
                subject_path=subject,
                prompt="Review hard.",
                transport="direct-openai",
            )
            request = json.loads(Path(job["request_uri"]).read_text(encoding="utf-8"))
            payload = valid_review_payload(
                {**request, **review_job_status(root, job_id=job["job_id"])}
            )
            payload.pop("capsule_challenge", None)
            payload["review_surface"] = "packet_excerpt_only"
            payload["subject_inspected"] = False

            ingest_review_result(
                root,
                job_id=job["job_id"],
                content=json.dumps(payload),
            )

            status = review_job_status(root, job_id=job["job_id"])
            stored_status = json.loads(Path(job["status_uri"]).read_text(encoding="utf-8"))
            receipt = json.loads(Path(status["ingest_receipt_uri"]).read_text(encoding="utf-8"))
            self.assertEqual(status["status"], "ingested")
            self.assertEqual(status["attempt_count"], 0)
            self.assertEqual(stored_status["ingest_mode"], "untracked")
            self.assertEqual(receipt["ingest_mode"], "untracked")
            self.assertIsNone(receipt["ingest_claim"]["attempt"])
            self.assertEqual(
                receipt["ingest_claim"]["operation_id"],
                {"present": True, "value": None},
            )
            self.assertEqual(list((Path(job["job_dir"]) / "attempts").iterdir()), [])
            self.assertEqual(list((Path(job["job_dir"]) / "attempt-receipts").iterdir()), [])
            self.assertTrue(review_bridge_module.review_bridge_integrity_report(root)["ok"])
            self.assertTrue(semantic_integrity_report(root)["ok"])


if __name__ == "__main__":
    unittest.main()
