from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest import mock
import zipfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
FINALIZER_PATH = REPO_ROOT / "scripts" / "finalize_release_distributions.py"
TEST_PACKAGE_FILES = {
    "continuum/__init__.py": b'"""Canonical package fixture."""\n',
}


def _load_finalizer():
    spec = importlib.util.spec_from_file_location(
        "release_distribution_finalizer_under_test", FINALIZER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load release distribution finalizer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _finalize(finalizer: Any, **kwargs: Any) -> dict[str, Any]:
    verification = finalizer._source_build_verification_descriptor(
        source_zip=Path(kwargs["source_zip"]),
        wheel_path=Path(kwargs["wheel_path"]),
        sdist_path=Path(kwargs["sdist_path"]),
    )
    with mock.patch.object(
        finalizer,
        "_rebuild_and_verify_from_source",
        return_value=verification,
    ):
        return finalizer.finalize_distributions(**kwargs)


def _provenance_bytes(toolchain: dict[str, str]) -> bytes:
    manifest_rows = [
        {
            "kind": "file",
            "mode": "100644",
            "path": f"epic-continuum-0.3.0/src/{path}",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }
        for path, payload in sorted(TEST_PACKAGE_FILES.items())
    ]
    manifest_bytes = (
        json.dumps(manifest_rows, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    return (
        json.dumps(
            {
                "schema": "epic-continuum.release_provenance.v1",
                "package": "epic-continuum-0.3.0",
                "version": "0.3.0",
                "builder": "scripts/build_release_package.py",
                "source": "git",
                "allow_dirty": False,
                "git_commit": "a" * 40,
                "git_dirty": False,
                "git_status_short_count": 0,
                "git_status_short_sha256": None,
                "source_date_epoch": 1_700_000_000,
                "distribution_build_toolchain": toolchain,
                "member_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "member_count_without_root_or_provenance": len(manifest_rows),
                "member_count_with_root_and_provenance": len(manifest_rows) + 3,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _write_source_zip(path: Path, provenance: bytes) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        root = zipfile.ZipInfo("epic-continuum-0.3.0/")
        root.create_system = 3
        root.external_attr = 0o40755 << 16
        archive.writestr(root, b"")
        for name, payload in {
            "epic-continuum-0.3.0/RELEASE_PROVENANCE.json": provenance,
            "epic-continuum-0.3.0/src/continuum/assets/RELEASE_PROVENANCE.json": provenance,
            **{
                f"epic-continuum-0.3.0/src/{package_path}": package_payload
                for package_path, package_payload in TEST_PACKAGE_FILES.items()
            },
        }.items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, payload)


def _write_wheel(
    path: Path,
    provenance: bytes,
    *,
    generator: str,
    name: str = "epic-continuum-memory",
    version: str = "0.3.0",
    package_files: dict[str, bytes] | None = None,
    extra_dist_info_files: dict[str, bytes] | None = None,
) -> None:
    files = {
        **(TEST_PACKAGE_FILES if package_files is None else package_files),
        "continuum/assets/RELEASE_PROVENANCE.json": provenance,
        "epic_continuum_memory-0.3.0.dist-info/WHEEL": (
            f"Wheel-Version: 1.0\nGenerator: {generator}\n"
            "Root-Is-Purelib: true\nTag: py3-none-any\n"
        ).encode(),
        "epic_continuum_memory-0.3.0.dist-info/METADATA": (
            f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n"
        ).encode(),
        **{
            f"epic_continuum_memory-0.3.0.dist-info/{relative_path}": payload
            for relative_path, payload in (extra_dist_info_files or {}).items()
        },
    }
    record_name = "epic_continuum_memory-0.3.0.dist-info/RECORD"
    record_buffer = io.StringIO(newline="")
    record_writer = csv.writer(record_buffer, lineterminator="\n")
    for member_name, payload in files.items():
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(payload).digest())
            .rstrip(b"=")
            .decode()
        )
        record_writer.writerow((member_name, f"sha256={digest}", str(len(payload))))
    record_writer.writerow((record_name, "", ""))
    files[record_name] = record_buffer.getvalue().encode()
    with zipfile.ZipFile(path, "w") as archive:
        for member_name, payload in files.items():
            archive.writestr(member_name, payload)


def _write_sdist(
    path: Path,
    provenance: bytes,
    *,
    name: str = "epic-continuum-memory",
    version: str = "0.3.0",
    package_files: dict[str, bytes] | None = None,
) -> None:
    provenance_name = (
        "epic_continuum_memory-0.3.0/src/continuum/assets/RELEASE_PROVENANCE.json"
    )
    metadata_name = "epic_continuum_memory-0.3.0/PKG-INFO"
    metadata = f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n".encode()
    provenance_info = tarfile.TarInfo(provenance_name)
    provenance_info.size = len(provenance)
    metadata_info = tarfile.TarInfo(metadata_name)
    metadata_info.size = len(metadata)
    with tarfile.open(path, "w:gz") as archive:
        archive.addfile(provenance_info, io.BytesIO(provenance))
        archive.addfile(metadata_info, io.BytesIO(metadata))
        for package_path, payload in (
            TEST_PACKAGE_FILES if package_files is None else package_files
        ).items():
            source_info = tarfile.TarInfo(
                f"epic_continuum_memory-0.3.0/src/{package_path}"
            )
            source_info.size = len(payload)
            archive.addfile(source_info, io.BytesIO(payload))


class ReleaseDistributionFinalizerTest(unittest.TestCase):
    def test_build_boundary_and_ci_use_the_canonical_finalizer(self) -> None:
        finalizer = _load_finalizer()
        pyproject = tomllib.loads(
            (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )
        self.assertEqual(
            pyproject["build-system"]["requires"],
            ["setuptools==80.9.0", "wheel==0.45.1"],
        )

        builder_path = REPO_ROOT / "scripts" / "build_release_package.py"
        builder_spec = importlib.util.spec_from_file_location(
            "release_builder_toolchain_under_test", builder_path
        )
        self.assertIsNotNone(builder_spec)
        assert builder_spec is not None
        self.assertIsNotNone(builder_spec.loader)
        assert builder_spec.loader is not None
        builder = importlib.util.module_from_spec(builder_spec)
        builder_spec.loader.exec_module(builder)
        self.assertEqual(
            finalizer.CANONICAL_TOOLCHAIN, builder.REPRODUCIBLE_DISTRIBUTION_TOOLCHAIN
        )

        workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("python scripts/finalize_release_distributions.py", workflow)
        self.assertIn("--receipt-out dist/RELEASE_DISTRIBUTIONS.json", workflow)
        self.assertIn("--checksums-out dist/SHA256SUMS", workflow)
        self.assertIn("installed-artifact-tests:", workflow)
        self.assertIn("os: [ubuntu-24.04, windows-2025]", workflow)
        self.assertIn("distribution: [wheel, sdist]", workflow)
        self.assertIn("run: python -m unittest discover -s tests -v", workflow)
        installed_job = workflow.split("installed-artifact-tests:", 1)[1]
        self.assertLess(
            installed_job.index(
                "Verify downloaded artifact receipt without build dependencies"
            ),
            installed_job.index("Install exact test and build tooling"),
        )

    def test_finalizer_binds_reproducible_artifacts_and_provenance(self) -> None:
        finalizer = _load_finalizer()
        canonical = dict(finalizer.CANONICAL_TOOLCHAIN)
        provenance = _provenance_bytes(canonical)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            release = base / "release"
            release.mkdir()
            source_zip = release / "epic-continuum-0.3.0.zip"
            wheel = release / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = release / "epic_continuum_memory-0.3.0.tar.gz"
            comparison = base / "comparison"
            comparison.mkdir()
            _write_source_zip(source_zip, provenance)
            _write_wheel(wheel, provenance, generator="setuptools (80.9.0)")
            _write_sdist(sdist, provenance)
            shutil.copy2(wheel, comparison / wheel.name)
            shutil.copy2(sdist, comparison / sdist.name)
            receipt_path = release / "RELEASE_DISTRIBUTIONS.json"
            checksums_path = release / "SHA256SUMS"

            receipt = _finalize(
                finalizer,
                source_zip=source_zip,
                wheel_path=wheel,
                sdist_path=sdist,
                comparison_dir=comparison,
                receipt_out=receipt_path,
                checksums_out=checksums_path,
                actual_toolchain=canonical,
            )

            self.assertEqual(receipt["distribution_build_toolchain"], canonical)
            self.assertEqual(receipt["wheel_generator"], "setuptools (80.9.0)")
            self.assertEqual(
                receipt["source_provenance_sha256"],
                hashlib.sha256(provenance).hexdigest(),
            )
            self.assertEqual(
                receipt["reproducibility"],
                {"independent_build_count": 2, "byte_identical": True},
            )
            self.assertEqual(
                receipt["schema"],
                "epic_continuum.release_distribution_receipt.v2",
            )
            content_manifests = receipt["content_manifests"]
            source_manifest = content_manifests["canonical_package_source"]
            self.assertEqual(source_manifest["file_count"], len(TEST_PACKAGE_FILES) + 1)
            self.assertEqual(content_manifests["wheel_package"], source_manifest)
            self.assertEqual(content_manifests["sdist_package_source"], source_manifest)
            self.assertEqual(
                content_manifests["generated_package_file_allowance"][0]["path"],
                "continuum/assets/RELEASE_PROVENANCE.json",
            )
            source_build_verification = receipt["source_build_verification"]
            self.assertEqual(
                source_build_verification["method"],
                "two_separate_source_zip_extractions_rebuilt_by_finalizer",
            )
            self.assertEqual(
                source_build_verification["separately_extracted_source_tree_count"],
                2,
            )
            parsed_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(parsed_receipt, receipt)
            checksum_lines = checksums_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(checksum_lines), 4)
            self.assertTrue(
                any(line.endswith(f"  {receipt_path.name}") for line in checksum_lines)
            )
            self.assertEqual(
                finalizer.verify_bound_release(release, actual_toolchain=canonical),
                receipt,
            )
            with mock.patch.object(
                finalizer,
                "installed_toolchain",
                side_effect=AssertionError(
                    "verification attempted to inspect build tools"
                ),
            ):
                self.assertEqual(finalizer.verify_bound_release(release), receipt)

            # Download verification must independently enforce the canonical
            # wheel generator even when every mutable binding is rewritten to
            # agree with a non-canonical wheel.
            original_wheel = wheel.read_bytes()
            original_receipt = receipt_path.read_bytes()
            original_checksums = checksums_path.read_bytes()
            _write_wheel(wheel, provenance, generator="setuptools (79.0.1)")
            tampered_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            wheel_row = next(
                row for row in tampered_receipt["artifacts"] if row["kind"] == "wheel"
            )
            wheel_bytes = wheel.read_bytes()
            wheel_row["sha256"] = hashlib.sha256(wheel_bytes).hexdigest()
            wheel_row["size_bytes"] = len(wheel_bytes)
            tampered_receipt["wheel_generator"] = "setuptools (79.0.1)"
            tampered_receipt_bytes = finalizer._stable_json_bytes(tampered_receipt)
            receipt_path.write_bytes(tampered_receipt_bytes)
            checksums_path.write_text(
                "\n".join(
                    [
                        *(
                            f"{row['sha256']}  {row['filename']}"
                            for row in tampered_receipt["artifacts"]
                        ),
                        f"{hashlib.sha256(tampered_receipt_bytes).hexdigest()}  {receipt_path.name}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "wheel generator"):
                finalizer.verify_bound_release(release, actual_toolchain=canonical)

            wheel.write_bytes(original_wheel)
            receipt_path.write_bytes(original_receipt)
            checksums_path.write_bytes(original_checksums)
            extra = release / "epic-continuum-0.3.0.zip.sha256"
            extra.write_text("contradictory unbound sidecar\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "unbound or missing"):
                finalizer.verify_bound_release(release, actual_toolchain=canonical)
            extra.unlink()

            original_manifest = checksums_path.read_bytes()
            checksums_path.write_text("0" * 64 + f"  {wheel.name}\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "SHA256SUMS"):
                finalizer.verify_bound_release(release, actual_toolchain=canonical)
            checksums_path.write_bytes(original_manifest)

            (comparison / wheel.name).write_bytes(b"different independent build")
            with self.assertRaisesRegex(
                RuntimeError, "independent canonical builds differ"
            ):
                _finalize(
                    finalizer,
                    source_zip=source_zip,
                    wheel_path=wheel,
                    sdist_path=sdist,
                    comparison_dir=comparison,
                    receipt_out=receipt_path,
                    checksums_out=checksums_path,
                    actual_toolchain=canonical,
                )

    def test_finalizer_rejects_valid_identical_but_source_divergent_distributions(
        self,
    ) -> None:
        finalizer = _load_finalizer()
        canonical = dict(finalizer.CANONICAL_TOOLCHAIN)
        provenance = _provenance_bytes(canonical)
        divergent = {
            **TEST_PACKAGE_FILES,
            "continuum/__init__.py": b'"""Source-divergent package fixture."""\n',
        }
        cases: tuple[tuple[str, dict[str, bytes], dict[str, bytes], str], ...] = (
            ("wheel-changed", divergent, TEST_PACKAGE_FILES, "wheel.*changed"),
            ("sdist-changed", TEST_PACKAGE_FILES, divergent, "sdist.*changed"),
            ("wheel-missing", {}, TEST_PACKAGE_FILES, "wheel.*missing"),
            (
                "sdist-extra",
                TEST_PACKAGE_FILES,
                {**TEST_PACKAGE_FILES, "continuum/extra.py": b"extra = True\n"},
                "sdist.*extra",
            ),
        )
        for label, wheel_files, sdist_files, error_pattern in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp)
                release = base / "release"
                comparison = base / "comparison"
                release.mkdir()
                comparison.mkdir()
                source_zip = release / "epic-continuum-0.3.0.zip"
                wheel = release / "epic_continuum_memory-0.3.0-py3-none-any.whl"
                sdist = release / "epic_continuum_memory-0.3.0.tar.gz"
                _write_source_zip(source_zip, provenance)
                _write_wheel(
                    wheel,
                    provenance,
                    generator="setuptools (80.9.0)",
                    package_files=wheel_files,
                )
                _write_sdist(sdist, provenance, package_files=sdist_files)
                shutil.copy2(wheel, comparison / wheel.name)
                shutil.copy2(sdist, comparison / sdist.name)

                with self.assertRaisesRegex(RuntimeError, error_pattern):
                    _finalize(
                        finalizer,
                        source_zip=source_zip,
                        wheel_path=wheel,
                        sdist_path=sdist,
                        comparison_dir=comparison,
                        receipt_out=release / "RELEASE_DISTRIBUTIONS.json",
                        checksums_out=release / "SHA256SUMS",
                        actual_toolchain=canonical,
                    )

    def test_finalizer_validates_wheel_record_before_source_correspondence(
        self,
    ) -> None:
        finalizer = _load_finalizer()
        canonical = dict(finalizer.CANONICAL_TOOLCHAIN)
        provenance = _provenance_bytes(canonical)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            release = base / "release"
            comparison = base / "comparison"
            release.mkdir()
            comparison.mkdir()
            source_zip = release / "epic-continuum-0.3.0.zip"
            wheel = release / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = release / "epic_continuum_memory-0.3.0.tar.gz"
            _write_source_zip(source_zip, provenance)
            _write_wheel(wheel, provenance, generator="setuptools (80.9.0)")
            _write_sdist(sdist, provenance)
            with zipfile.ZipFile(wheel) as archive:
                members = {name: archive.read(name) for name in archive.namelist()}
            members["continuum/__init__.py"] += b"# changed without RECORD update\n"
            with zipfile.ZipFile(wheel, "w") as archive:
                for name, payload in members.items():
                    archive.writestr(name, payload)
            shutil.copy2(wheel, comparison / wheel.name)
            shutil.copy2(sdist, comparison / sdist.name)

            with self.assertRaisesRegex(
                RuntimeError, "RECORD does not match member bytes"
            ):
                _finalize(
                    finalizer,
                    source_zip=source_zip,
                    wheel_path=wheel,
                    sdist_path=sdist,
                    comparison_dir=comparison,
                    receipt_out=release / "RELEASE_DISTRIBUTIONS.json",
                    checksums_out=release / "SHA256SUMS",
                    actual_toolchain=canonical,
                )

    def test_verification_cli_does_not_require_site_build_dependencies(self) -> None:
        finalizer = _load_finalizer()
        canonical = dict(finalizer.CANONICAL_TOOLCHAIN)
        provenance = _provenance_bytes(canonical)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            release = base / "release"
            comparison = base / "comparison"
            release.mkdir()
            comparison.mkdir()
            source_zip = release / "epic-continuum-0.3.0.zip"
            wheel = release / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = release / "epic_continuum_memory-0.3.0.tar.gz"
            _write_source_zip(source_zip, provenance)
            _write_wheel(wheel, provenance, generator="setuptools (80.9.0)")
            _write_sdist(sdist, provenance)
            shutil.copy2(wheel, comparison / wheel.name)
            shutil.copy2(sdist, comparison / sdist.name)
            _finalize(
                finalizer,
                source_zip=source_zip,
                wheel_path=wheel,
                sdist_path=sdist,
                comparison_dir=comparison,
                receipt_out=release / "RELEASE_DISTRIBUTIONS.json",
                checksums_out=release / "SHA256SUMS",
                actual_toolchain=canonical,
            )

            completed = subprocess.run(
                [
                    sys.executable,
                    "-S",
                    str(FINALIZER_PATH),
                    "--verify-directory",
                    str(release),
                ],
                check=False,
                capture_output=True,
                cwd=base,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn(finalizer.RECEIPT_SCHEMA, completed.stdout)

    def test_finalizer_rebuilds_two_separate_source_trees_and_rejects_injected_metadata(
        self,
    ) -> None:
        finalizer = _load_finalizer()
        canonical = dict(finalizer.CANONICAL_TOOLCHAIN)
        provenance = _provenance_bytes(canonical)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            release = base / "release"
            comparison = base / "comparison"
            release.mkdir()
            comparison.mkdir()
            source_zip = release / "epic-continuum-0.3.0.zip"
            wheel = release / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = release / "epic_continuum_memory-0.3.0.tar.gz"
            _write_source_zip(source_zip, provenance)
            _write_wheel(wheel, provenance, generator="setuptools (80.9.0)")
            _write_sdist(sdist, provenance)
            canonical_wheel = wheel.read_bytes()
            canonical_sdist = sdist.read_bytes()
            shutil.copy2(wheel, comparison / wheel.name)
            shutil.copy2(sdist, comparison / sdist.name)
            source_trees: list[Path] = []

            def fake_build(
                command: list[str], **kwargs: Any
            ) -> subprocess.CompletedProcess[str]:
                source_trees.append(Path(kwargs["cwd"]))
                output_dir = Path(command[command.index("--outdir") + 1])
                (output_dir / wheel.name).write_bytes(canonical_wheel)
                (output_dir / sdist.name).write_bytes(canonical_sdist)
                return subprocess.CompletedProcess(command, 0, "", "")

            with mock.patch.object(
                finalizer.subprocess,
                "run",
                side_effect=fake_build,
            ):
                receipt = finalizer.finalize_distributions(
                    source_zip=source_zip,
                    wheel_path=wheel,
                    sdist_path=sdist,
                    comparison_dir=comparison,
                    receipt_out=release / "RELEASE_DISTRIBUTIONS.json",
                    checksums_out=release / "SHA256SUMS",
                    actual_toolchain=canonical,
                )
            self.assertEqual(len(source_trees), 2)
            self.assertNotEqual(source_trees[0], source_trees[1])
            self.assertEqual(
                receipt["source_build_verification"][
                    "separately_extracted_source_tree_count"
                ],
                2,
            )

            _write_wheel(
                wheel,
                provenance,
                generator="setuptools (80.9.0)",
                extra_dist_info_files={
                    "entry_points.txt": b"[console_scripts]\nother = continuum.cli:main\n"
                },
            )
            shutil.copy2(wheel, comparison / wheel.name)
            with (
                mock.patch.object(
                    finalizer.subprocess,
                    "run",
                    side_effect=fake_build,
                ),
                self.assertRaisesRegex(
                    RuntimeError,
                    "supplied artifact does not match canonical source rebuild",
                ),
            ):
                finalizer.finalize_distributions(
                    source_zip=source_zip,
                    wheel_path=wheel,
                    sdist_path=sdist,
                    comparison_dir=comparison,
                    receipt_out=release / "RELEASE_DISTRIBUTIONS.json",
                    checksums_out=release / "SHA256SUMS",
                    actual_toolchain=canonical,
                )

    def test_finalizer_rejects_hardlinked_comparison_artifacts(self) -> None:
        finalizer = _load_finalizer()
        canonical = dict(finalizer.CANONICAL_TOOLCHAIN)
        provenance = _provenance_bytes(canonical)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            release = base / "release"
            comparison = base / "comparison"
            release.mkdir()
            comparison.mkdir()
            source_zip = release / "epic-continuum-0.3.0.zip"
            wheel = release / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = release / "epic_continuum_memory-0.3.0.tar.gz"
            _write_source_zip(source_zip, provenance)
            _write_wheel(wheel, provenance, generator="setuptools (80.9.0)")
            _write_sdist(sdist, provenance)
            try:
                os.link(wheel, comparison / wheel.name)
                os.link(sdist, comparison / sdist.name)
            except OSError as exc:
                self.skipTest(f"hard links unavailable: {exc}")

            with self.assertRaisesRegex(RuntimeError, "aliases the primary artifact"):
                _finalize(
                    finalizer,
                    source_zip=source_zip,
                    wheel_path=wheel,
                    sdist_path=sdist,
                    comparison_dir=comparison,
                    receipt_out=release / "RELEASE_DISTRIBUTIONS.json",
                    checksums_out=release / "SHA256SUMS",
                    actual_toolchain=canonical,
                )

    def test_finalizer_rejects_noncanonical_generator_and_toolchain(self) -> None:
        finalizer = _load_finalizer()
        canonical = dict(finalizer.CANONICAL_TOOLCHAIN)
        with self.assertRaisesRegex(
            RuntimeError, "non-canonical distribution build toolchain"
        ):
            finalizer.require_canonical_toolchain({**canonical, "setuptools": "79.0.1"})

        provenance = _provenance_bytes(canonical)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            release = base / "release"
            comparison = base / "comparison"
            release.mkdir()
            comparison.mkdir()
            source_zip = release / "epic-continuum-0.3.0.zip"
            wheel = release / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = release / "epic_continuum_memory-0.3.0.tar.gz"
            _write_source_zip(source_zip, provenance)
            _write_wheel(wheel, provenance, generator="setuptools (79.0.1)")
            _write_sdist(sdist, provenance)
            shutil.copy2(wheel, comparison / wheel.name)
            shutil.copy2(sdist, comparison / sdist.name)
            receipt_path = release / "RELEASE_DISTRIBUTIONS.json"
            checksums_path = release / "SHA256SUMS"
            receipt_path.write_text("existing receipt sentinel", encoding="utf-8")
            checksums_path.write_text("existing checksums sentinel", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "wheel generator"):
                _finalize(
                    finalizer,
                    source_zip=source_zip,
                    wheel_path=wheel,
                    sdist_path=sdist,
                    comparison_dir=comparison,
                    receipt_out=receipt_path,
                    checksums_out=checksums_path,
                    actual_toolchain=canonical,
                )
            self.assertEqual(
                receipt_path.read_text(encoding="utf-8"), "existing receipt sentinel"
            )
            self.assertEqual(
                checksums_path.read_text(encoding="utf-8"),
                "existing checksums sentinel",
            )

            _write_wheel(
                wheel,
                provenance,
                generator="setuptools (80.9.0)",
                version="9.9.9",
            )
            shutil.copy2(wheel, comparison / wheel.name)
            with self.assertRaisesRegex(RuntimeError, "METADATA Version"):
                _finalize(
                    finalizer,
                    source_zip=source_zip,
                    wheel_path=wheel,
                    sdist_path=sdist,
                    comparison_dir=comparison,
                    receipt_out=release / "RELEASE_DISTRIBUTIONS.json",
                    checksums_out=release / "SHA256SUMS",
                    actual_toolchain=canonical,
                )

            _write_wheel(wheel, provenance, generator="setuptools (80.9.0)")
            _write_sdist(sdist, provenance, version="9.9.9")
            shutil.copy2(wheel, comparison / wheel.name)
            shutil.copy2(sdist, comparison / sdist.name)
            with self.assertRaisesRegex(RuntimeError, "PKG-INFO Version"):
                _finalize(
                    finalizer,
                    source_zip=source_zip,
                    wheel_path=wheel,
                    sdist_path=sdist,
                    comparison_dir=comparison,
                    receipt_out=receipt_path,
                    checksums_out=checksums_path,
                    actual_toolchain=canonical,
                )

    def test_finalizer_rejects_path_aliases_without_touching_inputs(self) -> None:
        finalizer = _load_finalizer()
        canonical = dict(finalizer.CANONICAL_TOOLCHAIN)
        provenance = _provenance_bytes(canonical)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            release = base / "release"
            comparison = base / "comparison"
            release.mkdir()
            comparison.mkdir()
            source_zip = release / "epic-continuum-0.3.0.zip"
            wheel = release / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = release / "epic_continuum_memory-0.3.0.tar.gz"
            _write_source_zip(source_zip, provenance)
            _write_wheel(wheel, provenance, generator="setuptools (80.9.0)")
            _write_sdist(sdist, provenance)
            shutil.copy2(wheel, comparison / wheel.name)
            shutil.copy2(sdist, comparison / sdist.name)
            original_hashes = {
                path: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (source_zip, wheel, sdist, comparison / wheel.name)
            }

            collisions = (
                (release / "same-output", release / "same-output"),
                (source_zip, release / "SHA256SUMS"),
                (release / "RELEASE_DISTRIBUTIONS.json", wheel),
                (comparison / wheel.name, release / "SHA256SUMS"),
            )
            for receipt_out, checksums_out in collisions:
                with self.subTest(receipt_out=receipt_out, checksums_out=checksums_out):
                    with self.assertRaisesRegex(RuntimeError, "pairwise distinct"):
                        _finalize(
                            finalizer,
                            source_zip=source_zip,
                            wheel_path=wheel,
                            sdist_path=sdist,
                            comparison_dir=comparison,
                            receipt_out=receipt_out,
                            checksums_out=checksums_out,
                            actual_toolchain=canonical,
                        )

            for path, digest in original_hashes.items():
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_finalizer_rejects_split_release_directory_without_writes(self) -> None:
        finalizer = _load_finalizer()
        canonical = dict(finalizer.CANONICAL_TOOLCHAIN)
        provenance = _provenance_bytes(canonical)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            release = base / "release"
            release.mkdir()
            source_zip = release / "epic-continuum-0.3.0.zip"
            wheel = release / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = release / "epic_continuum_memory-0.3.0.tar.gz"
            comparison = base / "comparison"
            comparison.mkdir()
            _write_source_zip(source_zip, provenance)
            _write_wheel(wheel, provenance, generator="setuptools (80.9.0)")
            _write_sdist(sdist, provenance)
            shutil.copy2(wheel, comparison / wheel.name)
            shutil.copy2(sdist, comparison / sdist.name)
            outputs = base / "outputs"
            outputs.mkdir()
            receipt_out = outputs / "RELEASE_DISTRIBUTIONS.json"
            checksums_out = outputs / "SHA256SUMS"
            receipt_out.write_text("receipt sentinel", encoding="utf-8")
            checksums_out.write_text("checksums sentinel", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "share one release directory"):
                _finalize(
                    finalizer,
                    source_zip=source_zip,
                    wheel_path=wheel,
                    sdist_path=sdist,
                    comparison_dir=comparison,
                    receipt_out=receipt_out,
                    checksums_out=checksums_out,
                    actual_toolchain=canonical,
                )

            self.assertEqual(
                receipt_out.read_text(encoding="utf-8"), "receipt sentinel"
            )
            self.assertEqual(
                checksums_out.read_text(encoding="utf-8"), "checksums sentinel"
            )

    def test_finalizer_rejects_extra_release_entries_before_build_or_writes(
        self,
    ) -> None:
        finalizer = _load_finalizer()
        canonical = dict(finalizer.CANONICAL_TOOLCHAIN)
        provenance = _provenance_bytes(canonical)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            release = base / "release"
            comparison = base / "comparison"
            release.mkdir()
            comparison.mkdir()
            source_zip = release / "epic-continuum-0.3.0.zip"
            wheel = release / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = release / "epic_continuum_memory-0.3.0.tar.gz"
            receipt_out = release / "RELEASE_DISTRIBUTIONS.json"
            checksums_out = release / "SHA256SUMS"
            _write_source_zip(source_zip, provenance)
            _write_wheel(wheel, provenance, generator="setuptools (80.9.0)")
            _write_sdist(sdist, provenance)
            shutil.copy2(wheel, comparison / wheel.name)
            shutil.copy2(sdist, comparison / sdist.name)
            receipt_out.write_text("receipt sentinel", encoding="utf-8")
            checksums_out.write_text("checksums sentinel", encoding="utf-8")
            extra = release / "review.txt"
            extra.write_text("unbound review", encoding="utf-8")

            with (
                mock.patch.object(
                    finalizer, "require_canonical_toolchain"
                ) as toolchain,
                mock.patch.object(
                    finalizer, "_rebuild_and_verify_from_source"
                ) as rebuild,
                self.assertRaisesRegex(RuntimeError, "canonical five-file set"),
            ):
                finalizer.finalize_distributions(
                    source_zip=source_zip,
                    wheel_path=wheel,
                    sdist_path=sdist,
                    comparison_dir=comparison,
                    receipt_out=receipt_out,
                    checksums_out=checksums_out,
                    actual_toolchain=canonical,
                )
            toolchain.assert_not_called()
            rebuild.assert_not_called()
            self.assertEqual(
                receipt_out.read_text(encoding="utf-8"), "receipt sentinel"
            )
            self.assertEqual(
                checksums_out.read_text(encoding="utf-8"), "checksums sentinel"
            )

            extra.unlink()
            receipt = _finalize(
                finalizer,
                source_zip=source_zip,
                wheel_path=wheel,
                sdist_path=sdist,
                comparison_dir=comparison,
                receipt_out=receipt_out,
                checksums_out=checksums_out,
                actual_toolchain=canonical,
            )
            self.assertEqual(finalizer.verify_bound_release(release), receipt)
            self.assertEqual(
                {entry.name for entry in release.iterdir()},
                {
                    source_zip.name,
                    wheel.name,
                    sdist.name,
                    receipt_out.name,
                    checksums_out.name,
                },
            )

    def test_finalizer_rejects_non_file_output_before_build_or_partial_write(
        self,
    ) -> None:
        finalizer = _load_finalizer()
        canonical = dict(finalizer.CANONICAL_TOOLCHAIN)
        provenance = _provenance_bytes(canonical)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            release = base / "release"
            comparison = base / "comparison"
            release.mkdir()
            comparison.mkdir()
            source_zip = release / "epic-continuum-0.3.0.zip"
            wheel = release / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = release / "epic_continuum_memory-0.3.0.tar.gz"
            receipt_out = release / "RELEASE_DISTRIBUTIONS.json"
            checksums_out = release / "SHA256SUMS"
            _write_source_zip(source_zip, provenance)
            _write_wheel(wheel, provenance, generator="setuptools (80.9.0)")
            _write_sdist(sdist, provenance)
            shutil.copy2(wheel, comparison / wheel.name)
            shutil.copy2(sdist, comparison / sdist.name)
            receipt_out.write_text("receipt sentinel", encoding="utf-8")
            checksums_out.mkdir()

            with (
                mock.patch.object(
                    finalizer, "require_canonical_toolchain"
                ) as toolchain,
                mock.patch.object(
                    finalizer, "_rebuild_and_verify_from_source"
                ) as rebuild,
                self.assertRaisesRegex(RuntimeError, "regular files"),
            ):
                finalizer.finalize_distributions(
                    source_zip=source_zip,
                    wheel_path=wheel,
                    sdist_path=sdist,
                    comparison_dir=comparison,
                    receipt_out=receipt_out,
                    checksums_out=checksums_out,
                    actual_toolchain=canonical,
                )
            toolchain.assert_not_called()
            rebuild.assert_not_called()
            self.assertEqual(
                receipt_out.read_text(encoding="utf-8"), "receipt sentinel"
            )
            self.assertTrue(checksums_out.is_dir())

    def test_finalizer_rejects_noncanonical_output_names_without_writes(self) -> None:
        finalizer = _load_finalizer()
        canonical = dict(finalizer.CANONICAL_TOOLCHAIN)
        provenance = _provenance_bytes(canonical)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            release = base / "release"
            comparison = base / "comparison"
            release.mkdir()
            comparison.mkdir()
            source_zip = release / "epic-continuum-0.3.0.zip"
            wheel = release / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = release / "epic_continuum_memory-0.3.0.tar.gz"
            _write_source_zip(source_zip, provenance)
            _write_wheel(wheel, provenance, generator="setuptools (80.9.0)")
            _write_sdist(sdist, provenance)
            shutil.copy2(wheel, comparison / wheel.name)
            shutil.copy2(sdist, comparison / sdist.name)
            original_hashes = {
                path: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (source_zip, wheel, sdist, comparison / wheel.name)
            }

            invalid_outputs = (
                (release / "receipt.json", release / "SHA256SUMS"),
                (release / "RELEASE_DISTRIBUTIONS.json", release / "checksums.txt"),
            )
            for receipt_out, checksums_out in invalid_outputs:
                with self.subTest(receipt_out=receipt_out, checksums_out=checksums_out):
                    receipt_out.write_text("receipt sentinel", encoding="utf-8")
                    checksums_out.write_text("checksums sentinel", encoding="utf-8")
                    with self.assertRaisesRegex(RuntimeError, "canonical filenames"):
                        _finalize(
                            finalizer,
                            source_zip=source_zip,
                            wheel_path=wheel,
                            sdist_path=sdist,
                            comparison_dir=comparison,
                            receipt_out=receipt_out,
                            checksums_out=checksums_out,
                            actual_toolchain=canonical,
                        )
                    self.assertEqual(
                        receipt_out.read_text(encoding="utf-8"), "receipt sentinel"
                    )
                    self.assertEqual(
                        checksums_out.read_text(encoding="utf-8"),
                        "checksums sentinel",
                    )

            for path, digest in original_hashes.items():
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_finalizer_recomputes_the_source_member_manifest(self) -> None:
        finalizer = _load_finalizer()
        canonical = dict(finalizer.CANONICAL_TOOLCHAIN)
        provenance = _provenance_bytes(canonical)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            release = base / "release"
            comparison = base / "comparison"
            release.mkdir()
            comparison.mkdir()
            source_zip = release / "epic-continuum-0.3.0.zip"
            wheel = release / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = release / "epic_continuum_memory-0.3.0.tar.gz"
            _write_source_zip(source_zip, provenance)
            with zipfile.ZipFile(source_zip, "a") as archive:
                tampered = zipfile.ZipInfo("epic-continuum-0.3.0/tampered.py")
                tampered.create_system = 3
                tampered.external_attr = 0o100644 << 16
                archive.writestr(tampered, b"print('not in provenance')\n")
            _write_wheel(wheel, provenance, generator="setuptools (80.9.0)")
            _write_sdist(sdist, provenance)
            shutil.copy2(wheel, comparison / wheel.name)
            shutil.copy2(sdist, comparison / sdist.name)

            with self.assertRaisesRegex(
                RuntimeError, "provenance does not match its members"
            ):
                _finalize(
                    finalizer,
                    source_zip=source_zip,
                    wheel_path=wheel,
                    sdist_path=sdist,
                    comparison_dir=comparison,
                    receipt_out=release / "RELEASE_DISTRIBUTIONS.json",
                    checksums_out=release / "SHA256SUMS",
                    actual_toolchain=canonical,
                )


if __name__ == "__main__":
    unittest.main()
