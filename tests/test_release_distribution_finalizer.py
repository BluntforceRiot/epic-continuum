from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import shutil
import tarfile
import tempfile
import tomllib
import unittest
import zipfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
FINALIZER_PATH = REPO_ROOT / "scripts" / "finalize_release_distributions.py"


def _load_finalizer():
    spec = importlib.util.spec_from_file_location("release_distribution_finalizer_under_test", FINALIZER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load release distribution finalizer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _provenance_bytes(toolchain: dict[str, str]) -> bytes:
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
                "member_manifest_sha256": hashlib.sha256(b"[]\n").hexdigest(),
                "member_count_without_root_or_provenance": 0,
                "member_count_with_root_and_provenance": 3,
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
        archive.writestr("epic-continuum-0.3.0/RELEASE_PROVENANCE.json", provenance)
        archive.writestr(
            "epic-continuum-0.3.0/src/continuum/assets/RELEASE_PROVENANCE.json",
            provenance,
        )


def _write_wheel(
    path: Path,
    provenance: bytes,
    *,
    generator: str,
    name: str = "epic-continuum-memory",
    version: str = "0.3.0",
) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("continuum/assets/RELEASE_PROVENANCE.json", provenance)
        archive.writestr(
            "epic_continuum_memory-0.3.0.dist-info/WHEEL",
            f"Wheel-Version: 1.0\nGenerator: {generator}\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr(
            "epic_continuum_memory-0.3.0.dist-info/METADATA",
            f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n",
        )


def _write_sdist(
    path: Path,
    provenance: bytes,
    *,
    name: str = "epic-continuum-memory",
    version: str = "0.3.0",
) -> None:
    provenance_name = "epic_continuum_memory-0.3.0/src/continuum/assets/RELEASE_PROVENANCE.json"
    metadata_name = "epic_continuum_memory-0.3.0/PKG-INFO"
    metadata = f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n".encode()
    provenance_info = tarfile.TarInfo(provenance_name)
    provenance_info.size = len(provenance)
    metadata_info = tarfile.TarInfo(metadata_name)
    metadata_info.size = len(metadata)
    with tarfile.open(path, "w:gz") as archive:
        archive.addfile(provenance_info, io.BytesIO(provenance))
        archive.addfile(metadata_info, io.BytesIO(metadata))


class ReleaseDistributionFinalizerTest(unittest.TestCase):
    def test_build_boundary_and_ci_use_the_canonical_finalizer(self) -> None:
        finalizer = _load_finalizer()
        pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(
            pyproject["build-system"]["requires"],
            ["setuptools==80.9.0", "wheel==0.45.1"],
        )

        builder_path = REPO_ROOT / "scripts" / "build_release_package.py"
        builder_spec = importlib.util.spec_from_file_location(
            "release_builder_toolchain_under_test", builder_path
        )
        self.assertIsNotNone(builder_spec)
        self.assertIsNotNone(builder_spec.loader)
        assert builder_spec is not None and builder_spec.loader is not None
        builder = importlib.util.module_from_spec(builder_spec)
        builder_spec.loader.exec_module(builder)
        self.assertEqual(finalizer.CANONICAL_TOOLCHAIN, builder.REPRODUCIBLE_DISTRIBUTION_TOOLCHAIN)

        workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        self.assertIn("python scripts/finalize_release_distributions.py", workflow)
        self.assertIn("--receipt-out dist/RELEASE_DISTRIBUTIONS.json", workflow)
        self.assertIn("--checksums-out dist/SHA256SUMS", workflow)
        self.assertIn("installed-artifact-tests:", workflow)
        self.assertIn("os: [ubuntu-24.04, windows-2025]", workflow)
        self.assertIn("distribution: [wheel, sdist]", workflow)
        self.assertIn("run: python -m unittest discover -s tests -v", workflow)

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

            receipt = finalizer.finalize_distributions(
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
                receipt["source_provenance_sha256"], hashlib.sha256(provenance).hexdigest()
            )
            self.assertEqual(
                receipt["reproducibility"],
                {"independent_build_count": 2, "byte_identical": True},
            )
            parsed_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(parsed_receipt, receipt)
            checksum_lines = checksums_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(checksum_lines), 4)
            self.assertTrue(any(line.endswith(f"  {receipt_path.name}") for line in checksum_lines))
            self.assertEqual(
                finalizer.verify_bound_release(release, actual_toolchain=canonical),
                receipt,
            )

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
            with self.assertRaisesRegex(RuntimeError, "independent canonical builds differ"):
                finalizer.finalize_distributions(
                    source_zip=source_zip,
                    wheel_path=wheel,
                    sdist_path=sdist,
                    comparison_dir=comparison,
                    receipt_out=receipt_path,
                    checksums_out=checksums_path,
                    actual_toolchain=canonical,
                )

    def test_finalizer_rejects_noncanonical_generator_and_toolchain(self) -> None:
        finalizer = _load_finalizer()
        canonical = dict(finalizer.CANONICAL_TOOLCHAIN)
        with self.assertRaisesRegex(RuntimeError, "non-canonical distribution build toolchain"):
            finalizer.require_canonical_toolchain({**canonical, "setuptools": "79.0.1"})

        provenance = _provenance_bytes(canonical)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source_zip = base / "epic-continuum-0.3.0.zip"
            wheel = base / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = base / "epic_continuum_memory-0.3.0.tar.gz"
            comparison = base / "comparison"
            comparison.mkdir()
            _write_source_zip(source_zip, provenance)
            _write_wheel(wheel, provenance, generator="setuptools (79.0.1)")
            _write_sdist(sdist, provenance)
            shutil.copy2(wheel, comparison / wheel.name)
            shutil.copy2(sdist, comparison / sdist.name)
            receipt_path = base / "RELEASE_DISTRIBUTIONS.json"
            checksums_path = base / "SHA256SUMS"
            receipt_path.write_text("existing receipt sentinel", encoding="utf-8")
            checksums_path.write_text("existing checksums sentinel", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "wheel generator"):
                finalizer.finalize_distributions(
                    source_zip=source_zip,
                    wheel_path=wheel,
                    sdist_path=sdist,
                    comparison_dir=comparison,
                    receipt_out=receipt_path,
                    checksums_out=checksums_path,
                    actual_toolchain=canonical,
                )
            self.assertEqual(receipt_path.read_text(encoding="utf-8"), "existing receipt sentinel")
            self.assertEqual(checksums_path.read_text(encoding="utf-8"), "existing checksums sentinel")

            _write_wheel(
                wheel,
                provenance,
                generator="setuptools (80.9.0)",
                version="9.9.9",
            )
            shutil.copy2(wheel, comparison / wheel.name)
            with self.assertRaisesRegex(RuntimeError, "METADATA Version"):
                finalizer.finalize_distributions(
                    source_zip=source_zip,
                    wheel_path=wheel,
                    sdist_path=sdist,
                    comparison_dir=comparison,
                    receipt_out=base / "RELEASE_DISTRIBUTIONS.json",
                    checksums_out=base / "SHA256SUMS",
                    actual_toolchain=canonical,
                )

            _write_wheel(wheel, provenance, generator="setuptools (80.9.0)")
            _write_sdist(sdist, provenance, version="9.9.9")
            shutil.copy2(wheel, comparison / wheel.name)
            shutil.copy2(sdist, comparison / sdist.name)
            with self.assertRaisesRegex(RuntimeError, "PKG-INFO Version"):
                finalizer.finalize_distributions(
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
            source_zip = base / "epic-continuum-0.3.0.zip"
            wheel = base / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = base / "epic_continuum_memory-0.3.0.tar.gz"
            comparison = base / "comparison"
            comparison.mkdir()
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
                (base / "same-output", base / "same-output"),
                (source_zip, base / "SHA256SUMS"),
                (base / "RELEASE_DISTRIBUTIONS.json", wheel),
                (comparison / wheel.name, base / "SHA256SUMS"),
            )
            for receipt_out, checksums_out in collisions:
                with self.subTest(receipt_out=receipt_out, checksums_out=checksums_out):
                    with self.assertRaisesRegex(RuntimeError, "pairwise distinct"):
                        finalizer.finalize_distributions(
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

    def test_finalizer_rejects_noncanonical_output_names_without_writes(self) -> None:
        finalizer = _load_finalizer()
        canonical = dict(finalizer.CANONICAL_TOOLCHAIN)
        provenance = _provenance_bytes(canonical)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source_zip = base / "epic-continuum-0.3.0.zip"
            wheel = base / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = base / "epic_continuum_memory-0.3.0.tar.gz"
            comparison = base / "comparison"
            comparison.mkdir()
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
                (base / "receipt.json", base / "SHA256SUMS"),
                (base / "RELEASE_DISTRIBUTIONS.json", base / "checksums.txt"),
            )
            for receipt_out, checksums_out in invalid_outputs:
                with self.subTest(receipt_out=receipt_out, checksums_out=checksums_out):
                    receipt_out.write_text("receipt sentinel", encoding="utf-8")
                    checksums_out.write_text("checksums sentinel", encoding="utf-8")
                    with self.assertRaisesRegex(RuntimeError, "canonical filenames"):
                        finalizer.finalize_distributions(
                            source_zip=source_zip,
                            wheel_path=wheel,
                            sdist_path=sdist,
                            comparison_dir=comparison,
                            receipt_out=receipt_out,
                            checksums_out=checksums_out,
                            actual_toolchain=canonical,
                        )
                    self.assertEqual(receipt_out.read_text(encoding="utf-8"), "receipt sentinel")
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
            source_zip = base / "epic-continuum-0.3.0.zip"
            wheel = base / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = base / "epic_continuum_memory-0.3.0.tar.gz"
            comparison = base / "comparison"
            comparison.mkdir()
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

            with self.assertRaisesRegex(RuntimeError, "provenance does not match its members"):
                finalizer.finalize_distributions(
                    source_zip=source_zip,
                    wheel_path=wheel,
                    sdist_path=sdist,
                    comparison_dir=comparison,
                    receipt_out=base / "RELEASE_DISTRIBUTIONS.json",
                    checksums_out=base / "SHA256SUMS",
                    actual_toolchain=canonical,
                )


if __name__ == "__main__":
    unittest.main()
