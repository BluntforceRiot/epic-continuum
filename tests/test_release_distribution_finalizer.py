from __future__ import annotations

import base64
import csv
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
import shutil
import struct
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


def _provenance_bytes(
    toolchain: dict[str, str],
    *,
    source_date_epoch: int = 1_700_000_000,
) -> bytes:
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
                "source_date_epoch": source_date_epoch,
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
    provenance_payload = json.loads(provenance)
    source_date_epoch = provenance_payload["source_date_epoch"]
    if isinstance(source_date_epoch, bool) or not isinstance(source_date_epoch, int):
        raise AssertionError("source fixture provenance needs an integer epoch")
    timestamp = dt.datetime.fromtimestamp(source_date_epoch, tz=dt.UTC)
    date_time = (
        max(timestamp.year, 1980),
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        timestamp.second,
    )
    with zipfile.ZipFile(
        path,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as archive:
        root = zipfile.ZipInfo("epic-continuum-0.3.0/", date_time)
        root.create_system = 3
        root.external_attr = 0o40755 << 16
        root.compress_type = zipfile.ZIP_STORED
        archive.writestr(root, b"")
        for name, payload in {
            "epic-continuum-0.3.0/RELEASE_PROVENANCE.json": provenance,
            "epic-continuum-0.3.0/src/continuum/assets/RELEASE_PROVENANCE.json": provenance,
            **{
                f"epic-continuum-0.3.0/src/{package_path}": package_payload
                for package_path, package_payload in TEST_PACKAGE_FILES.items()
            },
        }.items():
            info = zipfile.ZipInfo(name, date_time)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
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
    provenance_payload = json.loads(provenance)
    source_date_epoch = provenance_payload["source_date_epoch"]
    if isinstance(source_date_epoch, bool) or not isinstance(source_date_epoch, int):
        raise AssertionError("wheel fixture provenance needs an integer epoch")
    timestamp = dt.datetime.fromtimestamp(source_date_epoch, tz=dt.UTC)
    date_time = (
        max(timestamp.year, 1980),
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        timestamp.second - (timestamp.second % 2),
    )
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
    for member_name in sorted(files):
        payload = files[member_name]
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(payload).digest())
            .rstrip(b"=")
            .decode()
        )
        record_writer.writerow((member_name, f"sha256={digest}", str(len(payload))))
    record_writer.writerow((record_name, "", ""))
    files[record_name] = record_buffer.getvalue().encode()
    member_names = sorted(name for name in files if name != record_name)
    member_names.append(record_name)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for member_name in member_names:
            info = zipfile.ZipInfo(member_name, date_time=date_time)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.create_version = 20
            info.extract_version = 20
            info.external_attr = 0o100644 << 16
            info.internal_attr = 0
            archive.writestr(info, files[member_name])


def _rewrite_wheel(
    path: Path,
    *,
    info_overrides: dict[str, dict[str, Any]] | None = None,
    member_names: list[str] | None = None,
    payload_overrides: dict[str, bytes] | None = None,
) -> None:
    with zipfile.ZipFile(path) as archive:
        infos = {info.filename: info for info in archive.infolist()}
        payloads = {info.filename: archive.read(info) for info in archive.infolist()}
        original_names = archive.namelist()
    payloads.update(payload_overrides or {})
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in original_names if member_names is None else member_names:
            info = infos[name]
            for attribute, value in (info_overrides or {}).get(name, {}).items():
                setattr(info, attribute, value)
            archive.writestr(info, payloads[name])


def _write_sdist(
    path: Path,
    provenance: bytes,
    *,
    name: str = "epic-continuum-memory",
    version: str = "0.3.0",
    package_files: dict[str, bytes] | None = None,
    extra_files: dict[str, bytes] | None = None,
) -> None:
    root_name = "epic_continuum_memory-0.3.0"
    metadata = f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n".encode()
    files = {
        "src/continuum/assets/RELEASE_PROVENANCE.json": provenance,
        "PKG-INFO": metadata,
        **{
            f"src/{package_path}": payload
            for package_path, payload in (
                TEST_PACKAGE_FILES if package_files is None else package_files
            ).items()
        },
        **(extra_files or {}),
    }
    with tarfile.open(path, "w:gz") as archive:
        for relative_name, payload in files.items():
            info = tarfile.TarInfo(f"{root_name}/{relative_name}")
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))


def _rewrite_zip_member_name_bytes(
    path: Path,
    *,
    original: str,
    replacement: str,
) -> None:
    original_bytes = original.encode("utf-8")
    replacement_bytes = replacement.encode("utf-8")
    if len(original_bytes) != len(replacement_bytes):
        raise AssertionError("ZIP member name rewrite must preserve byte length")
    payload = path.read_bytes()
    if payload.count(original_bytes) != 2:
        raise AssertionError("expected one local and one central ZIP member name")
    path.write_bytes(payload.replace(original_bytes, replacement_bytes))


def _rewrite_first_zip_local_member_name_bytes(
    path: Path,
    *,
    original: str,
    replacement: str,
) -> None:
    original_bytes = original.encode("utf-8")
    replacement_bytes = replacement.encode("utf-8")
    if len(original_bytes) != len(replacement_bytes):
        raise AssertionError("ZIP local member name rewrite must preserve byte length")
    payload = bytearray(path.read_bytes())
    local_header = payload.index(b"PK\x03\x04")
    name_length = int.from_bytes(payload[local_header + 26 : local_header + 28], "little")
    name_start = local_header + 30
    self_name = bytes(payload[name_start : name_start + name_length])
    if self_name != original_bytes:
        raise AssertionError("unexpected first ZIP local member name")
    payload[name_start : name_start + name_length] = replacement_bytes
    path.write_bytes(payload)


def _rewrite_zip_local_u32(
    path: Path,
    *,
    member_name: str,
    field_offset: int,
    value: int,
) -> None:
    with zipfile.ZipFile(path) as archive:
        local_header = archive.getinfo(member_name).header_offset
    payload = bytearray(path.read_bytes())
    if payload[local_header : local_header + 4] != b"PK\x03\x04":
        raise AssertionError("unexpected ZIP local-file header")
    struct.pack_into("<L", payload, local_header + field_offset, value)
    path.write_bytes(payload)


def _rewrite_zip_local_u16(
    path: Path,
    *,
    member_name: str,
    field_offset: int,
    value: int,
) -> None:
    with zipfile.ZipFile(path) as archive:
        local_header = archive.getinfo(member_name).header_offset
    payload = bytearray(path.read_bytes())
    if payload[local_header : local_header + 4] != b"PK\x03\x04":
        raise AssertionError("unexpected ZIP local-file header")
    struct.pack_into("<H", payload, local_header + field_offset, value)
    path.write_bytes(payload)


def _rewrite_zip_member_flags(
    path: Path,
    *,
    member_name: str,
    value: int,
) -> None:
    with zipfile.ZipFile(path) as archive:
        local_header = archive.getinfo(member_name).header_offset
    payload = bytearray(path.read_bytes())
    eocd_offset = payload.rfind(b"PK\x05\x06")
    if eocd_offset < 0:
        raise AssertionError("ZIP end record is missing")
    central_offset = int(struct.unpack_from("<L", payload, eocd_offset + 16)[0])
    position = central_offset
    target = member_name.encode("ascii")
    while position < eocd_offset:
        if payload[position : position + 4] != b"PK\x01\x02":
            raise AssertionError("unexpected ZIP central record")
        filename_size = int(struct.unpack_from("<H", payload, position + 28)[0])
        extra_size = int(struct.unpack_from("<H", payload, position + 30)[0])
        comment_size = int(struct.unpack_from("<H", payload, position + 32)[0])
        filename = bytes(payload[position + 46 : position + 46 + filename_size])
        if filename == target:
            struct.pack_into("<H", payload, position + 8, value)
            break
        position += 46 + filename_size + extra_size + comment_size
    else:
        raise AssertionError("ZIP central member is missing")
    struct.pack_into("<H", payload, local_header + 6, value)
    path.write_bytes(payload)


def _insert_zip_bytes_before_central(path: Path, inserted: bytes) -> None:
    payload = bytearray(path.read_bytes())
    eocd_offset = payload.rfind(b"PK\x05\x06")
    if eocd_offset < 0 or eocd_offset + 22 != len(payload):
        raise AssertionError("expected an uncommented terminal ZIP end record")
    central_offset = int(struct.unpack_from("<L", payload, eocd_offset + 16)[0])
    payload[central_offset:central_offset] = inserted
    struct.pack_into(
        "<L",
        payload,
        eocd_offset + len(inserted) + 16,
        central_offset + len(inserted),
    )
    path.write_bytes(payload)


def _assert_invalid_zip_geometry(finalizer: Any, path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        finalizer._validate_zip_raw_geometry(
            archive,
            archive.infolist(),
            artifact=path,
        )


class ReleaseDistributionFinalizerTest(unittest.TestCase):
    def test_finalizer_rejects_nonportable_archive_paths(self) -> None:
        finalizer = _load_finalizer()
        artifact = Path("fixture.zip")

        for names in (
            ["root/docs/Foo.md", "root/docs/foo.md"],
            ["root/Docs/a.md", "root/docs/b.md"],
            ["root/docs/straße.md", "root/docs/STRASSE.md"],
        ):
            with self.subTest(names=names), self.assertRaisesRegex(
                RuntimeError,
                "portable archive path collision",
            ):
                finalizer._assert_canonical_archive_paths(names, artifact=artifact)

        for names in (
            ["root/node", "root/node/child.txt"],
            ["root/tree/item.txt", "root/tree"],
        ):
            with self.subTest(names=names), self.assertRaisesRegex(
                RuntimeError,
                "file/directory conflict",
            ):
                finalizer._assert_canonical_archive_paths(names, artifact=artifact)

        with self.assertRaisesRegex(RuntimeError, "duplicate logical archive member"):
            finalizer._assert_canonical_archive_paths(
                ["root/dir", "root/dir/"],
                artifact=artifact,
                directory_names={"root/dir", "root/dir/"},
            )

        reserved_components = [
            "CON.txt",
            "CON .txt",
            "PRN",
            "AUX.log",
            "NUL",
            "CLOCK$.txt",
            "CONIN$",
            "CONOUT$.json",
            *(f"COM{index}.txt" for index in range(1, 10)),
            *(f"LPT{index}" for index in range(1, 10)),
            *(f"COM{digit}.txt" for digit in "¹²³"),
            *(f"LPT{digit}" for digit in "¹²³"),
        ]
        invalid_components = [
            "cafe\u0301.md",
            "trailing.",
            "trailing ",
            "alternate:stream",
            "zero\u200bwidth",
            "a" * 256,
            "\u00e9" * 128,
            *reserved_components,
        ]
        for component in invalid_components:
            with self.subTest(component=component), self.assertRaisesRegex(
                RuntimeError,
                "non-portable archive member name",
            ):
                finalizer._validate_archive_member_name(
                    f"root/docs/{component}",
                    artifact=artifact,
                )

        finalizer._assert_canonical_archive_paths(
            ["root", "root/docs/a.md", "root/docs/b.md"],
            artifact=artifact,
            directory_names={"root"},
        )

    def test_finalizer_rejects_portable_collisions_in_all_distribution_readers(
        self,
    ) -> None:
        finalizer = _load_finalizer()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_zip = root / "epic-continuum-0.3.0.zip"
            with zipfile.ZipFile(source_zip, "w") as archive:
                archive.writestr("epic-continuum-0.3.0/Docs/a.md", b"a")
                archive.writestr("epic-continuum-0.3.0/docs/b.md", b"b")

            wheel = root / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("continuum/Foo.py", b"a")
                archive.writestr("continuum/foo.py", b"b")

            sdist = root / "epic_continuum_memory-0.3.0.tar.gz"
            with tarfile.open(sdist, "w:gz") as archive:
                for name in (
                    "epic_continuum_memory-0.3.0/src/continuum/Tree/a.py",
                    "epic_continuum_memory-0.3.0/src/continuum/tree/b.py",
                ):
                    info = tarfile.TarInfo(name)
                    info.size = 1
                    archive.addfile(info, io.BytesIO(b"x"))

            readers: tuple[
                tuple[Any, tuple[Any, ...], dict[str, Any]], ...
            ] = (
                (finalizer._read_source_provenance, (source_zip,), {}),
                (finalizer._read_wheel_provenance, (wheel,), {"version": "0.3.0"}),
                (finalizer._read_sdist_provenance, (sdist,), {"version": "0.3.0"}),
            )
            for reader, args, kwargs in readers:
                with self.subTest(reader=reader.__name__), self.assertRaisesRegex(
                    RuntimeError,
                    "portable archive path collision",
                ):
                    reader(*args, **kwargs)

    def test_zip_readers_reject_names_truncated_at_embedded_nul(self) -> None:
        finalizer = _load_finalizer()
        cases = (
            (
                "source",
                "epic-continuum-0.3.0/badXname.txt",
                "epic-continuum-0.3.0/bad\x00name.txt",
                finalizer._read_source_provenance,
            ),
            (
                "wheel",
                "continuum/badXname.py",
                "continuum/bad\x00name.py",
                finalizer._read_wheel_provenance,
            ),
        )
        for kind, original, replacement, reader in cases:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                suffix = ".zip" if kind == "source" else "-py3-none-any.whl"
                path = Path(tmp) / (
                    "epic-continuum-0.3.0.zip"
                    if kind == "source"
                    else f"epic_continuum_memory-0.3.0{suffix}"
                )
                with zipfile.ZipFile(path, "w") as archive:
                    archive.writestr(original, b"payload")
                _rewrite_zip_member_name_bytes(
                    path,
                    original=original,
                    replacement=replacement,
                )

                kwargs = {} if kind == "source" else {"version": "0.3.0"}
                with self.assertRaisesRegex(
                    RuntimeError,
                    "non-portable archive member name",
                ):
                    reader(path, **kwargs)

    def test_source_reader_rejects_local_central_directory_name_mismatch(self) -> None:
        finalizer = _load_finalizer()
        provenance = _provenance_bytes(dict(finalizer.CANONICAL_TOOLCHAIN))
        with tempfile.TemporaryDirectory() as tmp:
            source_zip = Path(tmp) / "epic-continuum-0.3.0.zip"
            _write_source_zip(source_zip, provenance)
            _rewrite_first_zip_local_member_name_bytes(
                source_zip,
                original="epic-continuum-0.3.0/",
                replacement="epic-continuum-0.3.0X",
            )

            with self.assertRaisesRegex(RuntimeError, "invalid ZIP record geometry"):
                finalizer._read_source_provenance(source_zip)

    def test_source_reader_rejects_local_header_metadata_mismatches(self) -> None:
        finalizer = _load_finalizer()
        provenance = _provenance_bytes(dict(finalizer.CANONICAL_TOOLCHAIN))
        regular_name = "epic-continuum-0.3.0/RELEASE_PROVENANCE.json"
        cases: tuple[tuple[str, str, int, int, int], ...] = (
            ("directory CRC", "epic-continuum-0.3.0/", 32, 14, 1),
            ("regular version", regular_name, 16, 4, 45),
            ("regular flags", regular_name, 16, 6, 0x0800),
            ("regular compression", regular_name, 16, 8, zipfile.ZIP_STORED),
            ("regular time", regular_name, 16, 10, 1),
            ("regular date", regular_name, 16, 12, 1),
            ("regular CRC", regular_name, 32, 14, 1),
            (
                "regular compressed size",
                regular_name,
                32,
                18,
                len(provenance) + 1,
            ),
            (
                "regular uncompressed size",
                regular_name,
                32,
                22,
                len(provenance) + 1,
            ),
        )
        for label, member_name, width, field_offset, value in cases:
            with self.subTest(field=label), tempfile.TemporaryDirectory() as tmp:
                source_zip = Path(tmp) / "epic-continuum-0.3.0.zip"
                _write_source_zip(source_zip, provenance)
                rewrite = (
                    _rewrite_zip_local_u16
                    if width == 16
                    else _rewrite_zip_local_u32
                )
                rewrite(
                    source_zip,
                    member_name=member_name,
                    field_offset=field_offset,
                    value=value,
                )

                with self.assertRaisesRegex(
                    RuntimeError,
                    "ZIP local and central member records disagree",
                ):
                    finalizer._read_source_provenance(source_zip)

    def test_source_reader_rejects_coordinated_noncanonical_builder_metadata(
        self,
    ) -> None:
        finalizer = _load_finalizer()
        provenance = _provenance_bytes(dict(finalizer.CANONICAL_TOOLCHAIN))
        for kind in ("timestamp", "creator", "external attributes"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                source_zip = Path(tmp) / "epic-continuum-0.3.0.zip"
                _write_source_zip(source_zip, provenance)
                payload = bytearray(source_zip.read_bytes())
                local_offset = payload.index(b"PK\x03\x04")
                central_offset = payload.index(b"PK\x01\x02")
                if kind == "timestamp":
                    struct.pack_into("<H", payload, local_offset + 10, 1)
                    struct.pack_into("<H", payload, central_offset + 12, 1)
                elif kind == "creator":
                    payload[central_offset + 5] = 0
                else:
                    external_attr = int(
                        struct.unpack_from("<L", payload, central_offset + 38)[0]
                    )
                    struct.pack_into(
                        "<L", payload, central_offset + 38, external_attr | 1
                    )
                source_zip.write_bytes(payload)

                with self.assertRaisesRegex(
                    RuntimeError,
                    "canonical source builder",
                ):
                    finalizer._read_source_provenance(source_zip)

    def test_zip_geometry_rejects_prefix_gap_and_orphan_local_record(self) -> None:
        finalizer = _load_finalizer()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            template = root / "template.zip"
            with zipfile.ZipFile(template, "w") as archive:
                archive.writestr("payload.txt", b"payload")
            canonical = template.read_bytes()
            eocd_offset = canonical.rfind(b"PK\x05\x06")
            central_offset = int(
                struct.unpack_from("<L", canonical, eocd_offset + 16)[0]
            )
            orphan_record = canonical[:central_offset]

            cases = (
                ("prefix", b"self-extracting-prefix" + canonical),
                ("gap", canonical),
                ("orphan", canonical),
            )
            for kind, payload in cases:
                with self.subTest(kind=kind):
                    candidate = root / f"{kind}.zip"
                    candidate.write_bytes(payload)
                    if kind == "gap":
                        _insert_zip_bytes_before_central(candidate, b"gap")
                    elif kind == "orphan":
                        _insert_zip_bytes_before_central(candidate, orphan_record)

                    with self.assertRaisesRegex(
                        RuntimeError,
                        "invalid ZIP record geometry",
                    ):
                        _assert_invalid_zip_geometry(finalizer, candidate)

    def test_zip_geometry_rejects_extras_descriptors_and_zip64(self) -> None:
        finalizer = _load_finalizer()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            extra = root / "extra.zip"
            with zipfile.ZipFile(extra, "w") as archive:
                info = zipfile.ZipInfo("payload.txt")
                info.extra = struct.pack("<HH", 0x9999, 0)
                archive.writestr(info, b"payload")

            descriptor = root / "descriptor.zip"
            with zipfile.ZipFile(descriptor, "w") as archive:
                archive.writestr("payload.txt", b"payload")
            descriptor_bytes = bytearray(descriptor.read_bytes())
            local_offset = descriptor_bytes.index(b"PK\x03\x04")
            central_offset = descriptor_bytes.index(b"PK\x01\x02")
            local_flags = int(
                struct.unpack_from("<H", descriptor_bytes, local_offset + 6)[0]
            )
            central_flags = int(
                struct.unpack_from("<H", descriptor_bytes, central_offset + 8)[0]
            )
            struct.pack_into(
                "<H", descriptor_bytes, local_offset + 6, local_flags | 0x0008
            )
            struct.pack_into(
                "<H", descriptor_bytes, central_offset + 8, central_flags | 0x0008
            )
            descriptor.write_bytes(descriptor_bytes)

            zip64 = root / "zip64.zip"
            with zipfile.ZipFile(zip64, "w") as archive:
                with archive.open("payload.txt", "w", force_zip64=True) as member:
                    member.write(b"payload")

            for kind, candidate in (
                ("extra", extra),
                ("descriptor", descriptor),
                ("zip64", zip64),
            ):
                with self.subTest(kind=kind), self.assertRaisesRegex(
                    RuntimeError,
                    "invalid ZIP record geometry",
                ):
                    _assert_invalid_zip_geometry(finalizer, candidate)

    def test_source_extraction_preflights_names_before_creating_destination(
        self,
    ) -> None:
        finalizer = _load_finalizer()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_zip = root / "source.zip"
            destination = root / "source-tree"
            with zipfile.ZipFile(source_zip, "w") as archive:
                archive.writestr("epic-continuum-0.3.0/", b"")
                archive.writestr("epic-continuum-0.3.0/Docs/a.md", b"a")
                archive.writestr("epic-continuum-0.3.0/docs/b.md", b"b")

            with self.assertRaisesRegex(RuntimeError, "portable archive path collision"):
                finalizer._extract_canonical_source_tree(
                    source_zip=source_zip,
                    destination=destination,
                    version="0.3.0",
                )
            self.assertFalse(destination.exists())

    def test_source_extraction_never_overwrites_a_competing_file(self) -> None:
        finalizer = _load_finalizer()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_zip = root / "source.zip"
            destination = root / "source-tree"
            with zipfile.ZipFile(source_zip, "w") as archive:
                archive.writestr("epic-continuum-0.3.0/", b"")
                archive.writestr("epic-continuum-0.3.0/README.md", b"archive bytes")

            original_open = Path.open
            injected = False

            def open_with_competing_file(path, mode="r", *args, **kwargs):
                nonlocal injected
                if mode == "xb" and not injected:
                    injected = True
                    with original_open(path, "wb") as handle:
                        handle.write(b"competing bytes")
                return original_open(path, mode, *args, **kwargs)

            with (
                mock.patch.object(Path, "open", new=open_with_competing_file),
                self.assertRaisesRegex(RuntimeError, "extraction target already exists"),
            ):
                finalizer._extract_canonical_source_tree(
                    source_zip=source_zip,
                    destination=destination,
                    version="0.3.0",
                )

            self.assertTrue(injected)
            self.assertEqual((destination / "README.md").read_bytes(), b"competing bytes")

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

    def test_distribution_readers_accept_canonical_metadata_and_tracked_crlf(
        self,
    ) -> None:
        finalizer = _load_finalizer()
        provenance = _provenance_bytes(dict(finalizer.CANONICAL_TOOLCHAIN))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wheel = root / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = root / "epic_continuum_memory-0.3.0.tar.gz"
            _write_wheel(
                wheel,
                provenance,
                generator="setuptools (80.9.0)",
                extra_dist_info_files={"licenses/LICENSE": b"tracked\r\nlicense\r\n"},
            )
            _write_sdist(
                sdist,
                provenance,
                package_files={"continuum/__init__.py": b"tracked\r\nsource\r\n"},
                extra_files={"README.md": b"tracked\r\nreadme\r\n"},
            )

            wheel_provenance, generator, _, _ = finalizer._read_wheel_provenance(
                wheel,
                version="0.3.0",
            )
            sdist_provenance, package_files = finalizer._read_sdist_provenance(
                sdist,
                version="0.3.0",
            )

            self.assertEqual(wheel_provenance, provenance)
            self.assertEqual(sdist_provenance, provenance)
            self.assertEqual(generator, "setuptools (80.9.0)")
            self.assertEqual(
                package_files["continuum/__init__.py"],
                b"tracked\r\nsource\r\n",
            )

    def test_distribution_readers_preserve_pre_1980_epoch_calendar_fields(
        self,
    ) -> None:
        finalizer = _load_finalizer()
        provenance = _provenance_bytes(
            dict(finalizer.CANONICAL_TOOLCHAIN),
            source_date_epoch=86_400,
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_zip = root / "epic-continuum-0.3.0.zip"
            wheel = root / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            sdist = root / "epic_continuum_memory-0.3.0.tar.gz"
            _write_source_zip(source_zip, provenance)
            _write_wheel(
                wheel,
                provenance,
                generator="setuptools (80.9.0)",
            )
            _write_sdist(sdist, provenance)

            source_provenance, _, _ = finalizer._read_source_provenance(source_zip)
            wheel_provenance, _, _, _ = finalizer._read_wheel_provenance(
                wheel,
                version="0.3.0",
            )
            sdist_provenance, _ = finalizer._read_sdist_provenance(
                sdist,
                version="0.3.0",
            )

            self.assertEqual(source_provenance, provenance)
            self.assertEqual(wheel_provenance, provenance)
            self.assertEqual(sdist_provenance, provenance)

    def test_wheel_reader_rejects_noncanonical_builder_metadata(self) -> None:
        finalizer = _load_finalizer()
        provenance = _provenance_bytes(dict(finalizer.CANONICAL_TOOLCHAIN))
        target = "continuum/__init__.py"
        cases = {
            "platform": {"create_system": 0},
            "mode": {"external_attr": 0o100666 << 16},
            "compression": {"compress_type": zipfile.ZIP_DEFLATED},
            "timestamp": {"date_time": (2020, 1, 2, 3, 4, 6)},
            "create version": {"create_version": 10},
            "extract version": {"extract_version": 10},
            "internal attributes": {"internal_attr": 1},
        }
        for label, overrides in cases.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                wheel = (
                    Path(tmp) / "epic_continuum_memory-0.3.0-py3-none-any.whl"
                )
                _write_wheel(
                    wheel,
                    provenance,
                    generator="setuptools (80.9.0)",
                )
                _rewrite_wheel(
                    wheel,
                    info_overrides={target: overrides},
                )

                with self.assertRaisesRegex(
                    RuntimeError,
                    "canonical wheel builder",
                ):
                    finalizer._read_wheel_provenance(wheel, version="0.3.0")

        with tempfile.TemporaryDirectory() as tmp:
            wheel = Path(tmp) / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            _write_wheel(wheel, provenance, generator="setuptools (80.9.0)")
            _rewrite_zip_member_flags(wheel, member_name=target, value=0x0800)
            with self.assertRaisesRegex(RuntimeError, "canonical wheel builder"):
                finalizer._read_wheel_provenance(wheel, version="0.3.0")

    def test_wheel_reader_rejects_noncanonical_member_and_record_order(self) -> None:
        finalizer = _load_finalizer()
        provenance = _provenance_bytes(dict(finalizer.CANONICAL_TOOLCHAIN))
        record_name = "epic_continuum_memory-0.3.0.dist-info/RECORD"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            wheel = root / "epic_continuum_memory-0.3.0-py3-none-any.whl"
            _write_wheel(wheel, provenance, generator="setuptools (80.9.0)")
            with zipfile.ZipFile(wheel) as archive:
                member_names = archive.namelist()
            member_names[0], member_names[1] = member_names[1], member_names[0]
            _rewrite_wheel(wheel, member_names=member_names)
            with self.assertRaisesRegex(RuntimeError, "lexicographic order"):
                finalizer._read_wheel_provenance(wheel, version="0.3.0")

            _write_wheel(wheel, provenance, generator="setuptools (80.9.0)")
            with zipfile.ZipFile(wheel) as archive:
                record_lines = archive.read(record_name).splitlines(keepends=True)
            record_lines[0], record_lines[1] = record_lines[1], record_lines[0]
            _rewrite_wheel(
                wheel,
                payload_overrides={record_name: b"".join(record_lines)},
            )
            with self.assertRaisesRegex(RuntimeError, "RECORD rows are not"):
                finalizer._read_wheel_provenance(wheel, version="0.3.0")

    def test_wheel_reader_rejects_cr_in_generated_dist_info_text(self) -> None:
        finalizer = _load_finalizer()
        provenance = _provenance_bytes(dict(finalizer.CANONICAL_TOOLCHAIN))
        cases = {
            "METADATA": (
                b"Metadata-Version: 2.4\r\n"
                b"Name: epic-continuum-memory\r\nVersion: 0.3.0\r\n"
            ),
            "entry_points.txt": b"[console_scripts]\r\ncontinuum = continuum.cli:main\r\n",
            "direct_url.json": b'{\r\n  "url": "file:///tmp/source"\r\n}\r\n',
        }
        for generated_name, payload in cases.items():
            with (
                self.subTest(generated_name=generated_name),
                tempfile.TemporaryDirectory() as tmp,
            ):
                wheel = (
                    Path(tmp) / "epic_continuum_memory-0.3.0-py3-none-any.whl"
                )
                _write_wheel(
                    wheel,
                    provenance,
                    generator="setuptools (80.9.0)",
                    extra_dist_info_files={generated_name: payload},
                )
                with self.assertRaisesRegex(RuntimeError, "must use LF"):
                    finalizer._read_wheel_provenance(wheel, version="0.3.0")

    def test_sdist_reader_rejects_cr_in_generated_metadata_only(self) -> None:
        finalizer = _load_finalizer()
        provenance = _provenance_bytes(dict(finalizer.CANONICAL_TOOLCHAIN))
        cases = {
            "PKG-INFO": (
                b"Metadata-Version: 2.4\r\n"
                b"Name: epic-continuum-memory\r\nVersion: 0.3.0\r\n"
            ),
            "setup.cfg": b"[egg_info]\r\ntag_build =\r\n",
            "src/epic_continuum_memory.egg-info/SOURCES.txt": (
                b"setup.py\r\nsrc/continuum/__init__.py\r\n"
            ),
        }
        for generated_name, payload in cases.items():
            with (
                self.subTest(generated_name=generated_name),
                tempfile.TemporaryDirectory() as tmp,
            ):
                sdist = Path(tmp) / "epic_continuum_memory-0.3.0.tar.gz"
                _write_sdist(
                    sdist,
                    provenance,
                    extra_files={generated_name: payload},
                )
                with self.assertRaisesRegex(RuntimeError, "must use LF"):
                    finalizer._read_sdist_provenance(sdist, version="0.3.0")

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
            _rewrite_wheel(
                wheel,
                payload_overrides={
                    "continuum/__init__.py": members["continuum/__init__.py"]
                },
            )
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
