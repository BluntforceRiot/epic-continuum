from __future__ import annotations

import base64
import copy
import csv
import gzip
import hashlib
import io
import os
import stat
import tarfile
import tempfile
import time
import zipfile
from pathlib import Path, PurePosixPath


PAX_TIME_HEADERS = ("mtime", "atime", "ctime")
WHEEL_TEXT_FILES = {
    "INSTALLER",
    "METADATA",
    "REQUESTED",
    "WHEEL",
    "direct_url.json",
    "entry_points.txt",
    "top_level.txt",
}


def _normalized_lines(payload: bytes) -> bytes:
    return payload.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def _is_generated_sdist_text(name: str) -> bool:
    parts = PurePosixPath(name).parts
    if len(parts) == 2 and parts[1] in {"PKG-INFO", "setup.cfg"}:
        return True
    return any(part.endswith(".egg-info") for part in parts[:-1])


def _normalized_tar_mode(member: tarfile.TarInfo) -> int:
    if member.isdir():
        return 0o755
    if member.isfile() and member.name.endswith(".sh"):
        return 0o755
    return 0o644


def _copy_sdist_members(
    source: tarfile.TarFile,
    target: tarfile.TarFile,
    *,
    epoch: int,
) -> None:
    for source_member in source.getmembers():
        member = copy.copy(source_member)
        member.pax_headers = dict(source_member.pax_headers)
        member.mode = _normalized_tar_mode(member)
        member.uid = 0
        member.gid = 0
        member.uname = ""
        member.gname = ""
        member.mtime = epoch
        for header in PAX_TIME_HEADERS:
            if header in member.pax_headers:
                member.pax_headers[header] = str(epoch)

        extracted = source.extractfile(source_member) if source_member.isfile() else None
        if extracted is None:
            target.addfile(member)
            continue

        payload = extracted.read()
        if _is_generated_sdist_text(member.name):
            payload = _normalized_lines(payload)
        member.size = len(payload)
        if "size" in member.pax_headers:
            member.pax_headers["size"] = str(member.size)
        target.addfile(member, io.BytesIO(payload))


def normalize_sdist(path: Path, *, gzipped: bool, epoch: int) -> None:
    """Atomically canonicalize an sdist tar archive."""
    read_mode = "r:gz" if gzipped else "r:"
    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=path.suffix,
        dir=path.parent,
    ) as handle:
        temp_path = Path(handle.name)
    try:
        with tarfile.open(path, read_mode) as source:
            if gzipped:
                with (
                    temp_path.open("wb") as raw_target,
                    gzip.GzipFile(
                        filename="",
                        mode="wb",
                        fileobj=raw_target,
                        mtime=epoch,
                    ) as compressed,
                    tarfile.open(
                        fileobj=compressed,
                        mode="w:",
                        format=tarfile.PAX_FORMAT,
                    ) as target,
                ):
                    _copy_sdist_members(source, target, epoch=epoch)
            else:
                with tarfile.open(
                    temp_path,
                    "w:",
                    format=tarfile.PAX_FORMAT,
                ) as target:
                    _copy_sdist_members(source, target, epoch=epoch)
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)


def _wheel_record(payloads: dict[str, bytes], *, record_name: str) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for name in sorted(payloads):
        if name == record_name:
            continue
        payload = payloads[name]
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
        writer.writerow((name, f"sha256={digest.decode('ascii')}", str(len(payload))))
    writer.writerow((record_name, "", ""))
    return output.getvalue().encode("utf-8")


def _wheel_timestamp(epoch: int) -> tuple[int, int, int, int, int, int]:
    timestamp = list(time.gmtime(epoch)[:6])
    timestamp[0] = max(timestamp[0], 1980)
    timestamp[-1] -= timestamp[-1] % 2
    return (
        timestamp[0],
        timestamp[1],
        timestamp[2],
        timestamp[3],
        timestamp[4],
        timestamp[5],
    )


def _write_canonical_wheel(
    path: Path,
    *,
    payloads: dict[str, bytes],
    record_name: str,
    epoch: int,
) -> None:
    timestamp = _wheel_timestamp(epoch)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as target:
        member_names = sorted(name for name in payloads if name != record_name)
        member_names.append(record_name)
        for name in member_names:
            info = zipfile.ZipInfo(name, date_time=timestamp)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.create_version = 20
            info.extract_version = 20
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.internal_attr = 0
            info.extra = b""
            info.comment = b""
            target.writestr(info, payloads[name])


def normalize_wheel(path: Path, *, epoch: int) -> None:
    """Atomically canonicalize a wheel and rebuild its RECORD."""
    with zipfile.ZipFile(path) as source:
        infos = source.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise RuntimeError(f"{path.name} contains duplicate member names")
        if any(info.is_dir() for info in infos):
            raise RuntimeError(f"{path.name} contains a directory member")
        record_names = [name for name in names if name.endswith(".dist-info/RECORD")]
        if len(record_names) != 1:
            raise RuntimeError(
                f"{path.name} must contain exactly one .dist-info/RECORD member"
            )
        record_name = record_names[0]
        payloads = {info.filename: source.read(info) for info in infos}

    for name, payload in tuple(payloads.items()):
        path_parts = PurePosixPath(name).parts
        if (
            len(path_parts) >= 2
            and path_parts[-2].endswith(".dist-info")
            and path_parts[-1] in WHEEL_TEXT_FILES
        ):
            payloads[name] = _normalized_lines(payload)
    payloads[record_name] = _wheel_record(payloads, record_name=record_name)

    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".whl",
        dir=path.parent,
    ) as handle:
        temp_path = Path(handle.name)
    try:
        _write_canonical_wheel(
            temp_path,
            payloads=payloads,
            record_name=record_name,
            epoch=epoch,
        )
        with zipfile.ZipFile(temp_path) as canonical:
            bad_member = canonical.testzip()
            if bad_member is not None:
                raise RuntimeError(f"canonical wheel member failed CRC validation: {bad_member}")
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)
