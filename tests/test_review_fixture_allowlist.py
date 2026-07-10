from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "generate_review_fixture_allowlist.py"
SPEC = importlib.util.spec_from_file_location("continuum_review_fixture_allowlist_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)


class ReviewFixtureAllowlistGateTests(unittest.TestCase):
    def _record(self, *, line: int, line_hash: str, secret_hash: str) -> dict[str, object]:
        return {
            "finding_type": "synthetic_fixture",
            "line": line,
            "line_sha256": line_hash,
            "reason": "reviewed synthetic fixture",
            "secret_sha256": secret_hash,
            "source": "approved.py",
        }

    def test_relocates_approval_and_checks_exact_canonical_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "approved.py"
            source.write_text("fixture line\n", encoding="utf-8")
            line_hash = hashlib.sha256(b"fixture line").hexdigest()
            secret_hash = hashlib.sha256(b"reviewed synthetic value").hexdigest()
            allowlist = root / "allowlist.jsonl"
            allowlist.write_bytes(
                gate.canonical_text(
                    [self._record(line=99, line_hash=line_hash, secret_hash=secret_hash)]
                ).encode("utf-8")
            )
            finding = {
                "line": 1,
                "type": "synthetic_fixture",
                "secret_hash": secret_hash,
                "source": "approved.py",
            }

            with (
                mock.patch.object(gate, "_scan_review_text_for_secrets", return_value=[finding]),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                self.assertEqual(gate.run(allowlist=allowlist, repo_root=root, write=False), 1)
                self.assertEqual(gate.run(allowlist=allowlist, repo_root=root, write=True), 0)
                self.assertEqual(gate.run(allowlist=allowlist, repo_root=root, write=False), 0)

                allowlist.write_bytes(allowlist.read_bytes().replace(b"\n", b"\r\n"))
                self.assertEqual(gate.run(allowlist=allowlist, repo_root=root, write=False), 1)

            rows = [
                json.loads(line)
                for line in allowlist.read_text(encoding="utf-8").splitlines()
                if line and not line.startswith("#")
            ]
            self.assertEqual(rows[0]["line"], 1)

    def test_unapproved_finding_refuses_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "approved.py"
            source.write_text("fixture line\n", encoding="utf-8")
            line_hash = hashlib.sha256(b"fixture line").hexdigest()
            approved_hash = hashlib.sha256(b"reviewed synthetic value").hexdigest()
            unapproved_hash = hashlib.sha256(b"different synthetic value").hexdigest()
            allowlist = root / "allowlist.jsonl"
            allowlist.write_bytes(
                gate.canonical_text(
                    [self._record(line=1, line_hash=line_hash, secret_hash=approved_hash)]
                ).encode("utf-8")
            )
            before = allowlist.read_bytes()
            finding = {
                "line": 1,
                "type": "synthetic_fixture",
                "secret_hash": unapproved_hash,
                "source": "approved.py",
            }

            with (
                mock.patch.object(gate, "_scan_review_text_for_secrets", return_value=[finding]),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()) as errors,
            ):
                self.assertEqual(gate.run(allowlist=allowlist, repo_root=root, write=True), 2)

            self.assertEqual(allowlist.read_bytes(), before)
            self.assertIn("unapproved findings: 1", errors.getvalue())
            self.assertIn("obsolete approvals: 1", errors.getvalue())

    def test_missing_source_is_reported_as_obsolete_and_can_be_removed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            allowlist = root / "allowlist.jsonl"
            allowlist.write_bytes(
                gate.canonical_text(
                    [self._record(line=1, line_hash="a" * 64, secret_hash="b" * 64)]
                ).encode("utf-8")
            )

            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()) as errors,
            ):
                self.assertEqual(gate.run(allowlist=allowlist, repo_root=root, write=False), 1)
                self.assertEqual(gate.run(allowlist=allowlist, repo_root=root, write=True), 0)
                self.assertEqual(gate.run(allowlist=allowlist, repo_root=root, write=False), 0)

            self.assertIn("obsolete approvals: 1", errors.getvalue())
            self.assertEqual(allowlist.read_text(encoding="utf-8"), gate.HEADER)

    def test_rejects_approval_source_escape(self) -> None:
        record = self._record(line=1, line_hash="a" * 64, secret_hash="b" * 64)
        record["source"] = "../outside.py"
        with self.assertRaisesRegex(gate.AllowlistGateError, "normalized relative path"):
            gate._validate_record(record, location="fixture")


if __name__ == "__main__":
    unittest.main()
