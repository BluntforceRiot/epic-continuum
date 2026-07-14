from __future__ import annotations

import argparse
import datetime as dt
import fnmatch
import hashlib
import json
import os
import stat
import subprocess
import tomllib
import unicodedata
import zipfile
from pathlib import Path


DEFAULT_ZIP_DT = (1980, 1, 1, 0, 0, 0)
DEFAULT_SOURCE_DATE_EPOCH = 315532800
MAX_SOURCE_DATE_EPOCH = (1 << 32) - 1
REPRODUCIBLE_DISTRIBUTION_TOOLCHAIN = {
    "python": "3.13.5",
    "pip": "25.1.1",
    "setuptools": "80.9.0",
    "wheel": "0.45.1",
    "build": "1.2.2.post1",
    "twine": "6.1.0",
}

EXCLUDED_PARTS = {
    ".git",
    ".venv",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "results",
    "dist",
    "htmlcov",
    "output",
}

EXCLUDED_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".zip",
    ".whl",
}

EXCLUDED_BASENAME_PATTERNS = {
    "BUILD_RECEIPT_*.md",
    "BUILD_CYCLE_RECEIPT_*.md",
    "AI_REVIEW_PACKET_*.md",
    "REVIEW_TRIAGE_*.md",
    "GITHUB_PUBLICATION_DRAFT.md",
    "ERIC_REVIEW_PACKET.md",
    "*.egg-info",
}

INCLUDE_TOP_LEVEL = {
    ".agents",
    ".github",
    "assets",
    "benchmarks",
    "docs",
    "examples",
    "integrations",
    "plugins",
    "scripts",
    "src",
    "tests",
    ".gitattributes",
    ".gitignore",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "MANIFEST.in",
    "PROJECT_CHARTER.md",
    "README.md",
    "ROADMAP.md",
    "SECURITY.md",
    "pyproject.toml",
    "setup.py",
}

GENERATED_PROVENANCE_PATHS = {
    "RELEASE_PROVENANCE.json",
    "src/continuum/assets/RELEASE_PROVENANCE.json",
}

WINDOWS_RESERVED_ARCHIVE_NAMES = {
    "con",
    "conin$",
    "conout$",
    "clock$",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
WINDOWS_RESERVED_SUPERSCRIPT_DIGITS = {"\u00b9", "\u00b2", "\u00b3"}


ReleaseMember = tuple[Path, str, int, str | None]
SnapshotMember = tuple[str, int, bytes | None]


def _is_link_like(path: Path) -> bool:
    """Return true for symlinks and Windows junction/reparse-point entries."""
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        return bool(reparse_flag and attributes & reparse_flag)
    except OSError:
        return False


def _assert_confined_source(path: Path, repo_root: Path) -> None:
    """Reject source members that escape through a link-like path component."""
    rel = path.relative_to(repo_root)
    current = repo_root
    for part in rel.parts:
        current = current / part
        if _is_link_like(current):
            raise RuntimeError(f"refusing to package link-like source path: {rel.as_posix()}")
    try:
        path.resolve(strict=True).relative_to(repo_root.resolve(strict=True))
    except (OSError, ValueError):
        raise RuntimeError(f"refusing to package source outside repository root: {rel.as_posix()}") from None


def project_version(repo_root: Path) -> str:
    pyproject = repo_root / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    return str(data["project"]["version"])


def _git_worktree_is_clean(repo_root: Path) -> bool | None:
    status = _git_status_short(repo_root)
    if status is None:
        return None
    return not status


def _git_command(repo_root: Path, args: list[str]) -> list[str]:
    return ["git", "--no-replace-objects", "-C", str(repo_root), *args]


def _git_environment() -> dict[str, str]:
    environment = {
        name: value
        for name, value in os.environ.items()
        if not name.upper().startswith("GIT_")
    }
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    return environment


def _git_output(repo_root: Path, args: list[str], *, text: bool = True) -> str | None:
    proc = subprocess.run(
        _git_command(repo_root, args),
        check=False,
        capture_output=True,
        text=text,
        env=_git_environment(),
    )
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def _git_repository_matches(repo_root: Path) -> bool:
    discovered = _git_output(repo_root, ["rev-parse", "--show-toplevel"])
    if not discovered:
        return False
    try:
        actual = Path(discovered).resolve(strict=True)
        expected = repo_root.resolve(strict=True)
    except OSError:
        return False
    return os.path.normcase(str(actual)) == os.path.normcase(str(expected))


def _git_status_short(repo_root: Path) -> list[str] | None:
    output = _git_output(
        repo_root,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    )
    if output is None:
        return None
    return [line for line in output.splitlines() if line]


def _parse_source_date_epoch(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    try:
        epoch = int(value)
    except (TypeError, ValueError):
        return None
    if not 0 <= epoch <= MAX_SOURCE_DATE_EPOCH:
        return None
    return epoch


def _release_source_date_epoch(repo_root: Path, git_commit: str | None) -> int:
    raw_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if raw_epoch is not None:
        parsed_epoch = _parse_source_date_epoch(raw_epoch)
        return DEFAULT_SOURCE_DATE_EPOCH if parsed_epoch is None else parsed_epoch
    if git_commit:
        commit_epoch = _git_output(repo_root, ["show", "-s", "--format=%ct", git_commit])
        parsed_commit_epoch = _parse_source_date_epoch(commit_epoch)
        if parsed_commit_epoch is not None:
            return parsed_commit_epoch
    for provenance_path in (
        repo_root / "RELEASE_PROVENANCE.json",
        repo_root / "src" / "continuum" / "assets" / "RELEASE_PROVENANCE.json",
    ):
        try:
            provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        parsed_provenance_epoch = _parse_source_date_epoch(provenance.get("source_date_epoch"))
        if parsed_provenance_epoch is not None:
            return parsed_provenance_epoch
    return DEFAULT_SOURCE_DATE_EPOCH


def reproducible_zip_dt(source_date_epoch: int | None = None) -> tuple[int, int, int, int, int, int]:
    epoch = source_date_epoch
    if epoch is None:
        epoch = _parse_source_date_epoch(os.environ.get("SOURCE_DATE_EPOCH"))
    if epoch is None:
        return DEFAULT_ZIP_DT
    try:
        timestamp = dt.datetime.fromtimestamp(epoch, tz=dt.UTC)
    except (OSError, OverflowError, ValueError):
        return DEFAULT_ZIP_DT
    return (
        max(timestamp.year, 1980),
        timestamp.month,
        timestamp.day,
        timestamp.hour,
        timestamp.minute,
        timestamp.second,
    )


def should_include(path: Path, repo_root: Path) -> bool:
    rel = path.relative_to(repo_root)
    parts = rel.parts
    if not parts:
        return False
    if rel.as_posix() in GENERATED_PROVENANCE_PATHS:
        return False
    if parts[0] not in INCLUDE_TOP_LEVEL:
        return False
    if any(part in EXCLUDED_PARTS for part in parts):
        return False
    if any(fnmatch.fnmatch(part, pattern) for part in parts for pattern in EXCLUDED_BASENAME_PATTERNS):
        return False
    if "".join(path.suffixes[-2:]) == ".tar.gz":
        return False
    if path.suffix in EXCLUDED_SUFFIXES:
        return False
    if rel.parts[0] == "docs":
        allowed_docs = (
            rel.parts[1:2] in (("architecture",), ("integrations",), ("audits",), ("benchmarks",))
            or str(rel).replace("\\", "/")
            in {
                "docs/configuration.md",
                "docs/context-window.md",
                "docs/cue-recall.md",
                "docs/evidence-and-proof.md",
                "docs/GLOSSARY.md",
                "docs/HARDWARE_TIERS.md",
                "docs/how-memory-works.md",
                "docs/ORIGINAL_DESIGN_COVERAGE_2026-06-17.md",
                "docs/recovery-and-continuity.md",
                "docs/review-fixture-secret-allowlist.jsonl",
                "docs/review-relay.md",
                "docs/shared-agent-state.md",
                "docs/worker-operations.md",
                "docs/writer-claims.md",
            }
        )
        if not allowed_docs:
            return False
    return True


def zip_mode(path: Path) -> int:
    if path.is_dir():
        return 0o40755
    if path.suffix == ".sh":
        return 0o100755
    return 0o100644


def write_member(
    zf: zipfile.ZipFile,
    arcname: str,
    data: bytes | None,
    *,
    mode: int,
    source_date_epoch: int | None = None,
) -> None:
    info = zipfile.ZipInfo(arcname, reproducible_zip_dt(source_date_epoch))
    info.create_system = 3
    info.external_attr = mode << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(info, b"" if data is None else data)


def write_bytes_member(
    zf: zipfile.ZipFile,
    arcname: str,
    data: bytes,
    *,
    mode: int = 0o100644,
    source_date_epoch: int | None = None,
) -> None:
    info = zipfile.ZipInfo(arcname, reproducible_zip_dt(source_date_epoch))
    info.create_system = 3
    info.external_attr = mode << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    zf.writestr(info, data)


def _member_manifest_rows(members: list[SnapshotMember]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for arcname, mode, data in members:
        row: dict[str, object] = {
            "path": arcname,
            "mode": f"{mode:o}",
        }
        if data is None:
            row["kind"] = "directory"
        else:
            row["kind"] = "file"
            row["size"] = len(data)
            row["sha256"] = hashlib.sha256(data).hexdigest()
        rows.append(row)
    return rows


def _stable_json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _assert_unique_arcnames(arcnames: list[str]) -> None:
    seen: set[str] = set()
    duplicates: set[str] = set()
    for arcname in arcnames:
        if arcname in seen:
            duplicates.add(arcname)
        seen.add(arcname)
    if duplicates:
        rendered = ", ".join(sorted(duplicates))
        raise RuntimeError(f"refusing to build release archive with duplicate member names: {rendered}")
    _assert_canonical_archive_paths(arcnames)


def _is_windows_reserved_archive_component(component: str) -> bool:
    stem = component.split(".", 1)[0].rstrip(" .").casefold()
    if stem in WINDOWS_RESERVED_ARCHIVE_NAMES:
        return True
    return (
        len(stem) == 4
        and stem[:3] in {"com", "lpt"}
        and stem[3] in WINDOWS_RESERVED_SUPERSCRIPT_DIGITS
    )


def _archive_path_parts(arcname: str) -> tuple[tuple[str, ...], bool]:
    is_directory = arcname.endswith("/")
    candidate = arcname[:-1] if is_directory else arcname
    if (
        not candidate
        or arcname.startswith("/")
        or "\\" in arcname
        or any(part in {"", ".", ".."} for part in candidate.split("/"))
    ):
        raise RuntimeError(
            "refusing to build release archive with a non-portable member name: "
            f"{arcname}"
        )
    parts = tuple(candidate.split("/"))
    for component in parts:
        try:
            windows_code_units = len(component.encode("utf-16-le")) // 2
            portable_name_bytes = len(component.encode("utf-8"))
        except UnicodeEncodeError:
            windows_code_units = 256
            portable_name_bytes = 256
        if (
            unicodedata.normalize("NFC", component) != component
            or windows_code_units > 255
            or portable_name_bytes > 255
            or component.endswith((".", " "))
            or any(character in '<>:"|?*' for character in component)
            or any(
                unicodedata.category(character) in {"Cc", "Cf", "Cs"}
                for character in component
            )
            or _is_windows_reserved_archive_component(component)
        ):
            raise RuntimeError(
                "refusing to build release archive with a non-portable member name: "
                f"{arcname}"
            )
    return parts, is_directory


def _assert_canonical_archive_paths(arcnames: list[str]) -> None:
    portable_paths: dict[str, tuple[str, str]] = {}
    for arcname in arcnames:
        parts, is_directory = _archive_path_parts(arcname)
        for depth in range(1, len(parts) + 1):
            prefix = "/".join(parts[:depth])
            entry_kind = (
                "directory"
                if depth < len(parts) or is_directory
                else "file"
            )
            portable_key = unicodedata.normalize("NFC", prefix).casefold()
            existing = portable_paths.get(portable_key)
            if existing is not None:
                if existing[0] != prefix:
                    raise RuntimeError(
                        "refusing to build release archive with a portable member "
                        f"path collision: {existing[0]} and {prefix}"
                    )
                if existing[1] != entry_kind:
                    raise RuntimeError(
                        "refusing to build release archive with a portable member "
                        f"file/directory conflict: {prefix}"
                    )
            portable_paths[portable_key] = (prefix, entry_kind)


def _provenance_payload(
    package_name: str,
    version: str,
    source: str,
    members: list[SnapshotMember],
    *,
    require_clean: bool,
    git_commit: str | None,
    status_short: list[str] | None,
    source_date_epoch: int,
) -> dict[str, object]:
    manifest_rows = _member_manifest_rows(members)
    manifest_bytes = _stable_json_bytes(manifest_rows)
    status_blob = "\n".join(status_short or []).encode("utf-8")
    return {
        "schema": "epic-continuum.release_provenance.v1",
        "package": package_name,
        "version": version,
        "builder": "scripts/build_release_package.py",
        "source": source,
        "allow_dirty": not require_clean,
        "git_commit": git_commit,
        "git_dirty": None if status_short is None else bool(status_short),
        "git_status_short_count": None if status_short is None else len(status_short),
        "git_status_short_sha256": hashlib.sha256(status_blob).hexdigest() if status_short else None,
        "source_date_epoch": source_date_epoch,
        "distribution_build_toolchain": dict(REPRODUCIBLE_DISTRIBUTION_TOOLCHAIN),
        "member_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "member_count_without_root_or_provenance": len(members),
        "member_count_with_root_and_provenance": len(members) + 3,
        "provenance_notes": [
            "No absolute repository path is recorded.",
            "Dirty development archives are review artifacts, not final public-release provenance.",
        ],
    }


def _git_tracked_members(
    repo_root: Path,
    package_name: str,
    *,
    allow_missing: bool = False,
    include_untracked: bool = False,
    treeish: str | None = None,
) -> list[ReleaseMember] | None:
    git_args = (
        ["ls-tree", "-r", "-z", "--full-tree", treeish]
        if treeish is not None
        else ["ls-files", "--stage", "-z"]
    )
    proc = subprocess.run(
        _git_command(repo_root, git_args),
        check=False,
        capture_output=True,
        env=_git_environment(),
    )
    if proc.returncode != 0:
        return None

    members_by_arcname: dict[str, ReleaseMember] = {}
    directory_arcnames: set[str] = set()
    for raw_record in proc.stdout.split(b"\0"):
        if not raw_record:
            continue
        try:
            raw_header, raw_path = raw_record.split(b"\t", 1)
            if treeish is not None:
                raw_mode, raw_object_type, raw_object_id = raw_header.split()
            else:
                raw_mode, raw_object_id, _raw_stage = raw_header.split()
                raw_object_type = b"blob"
            rel = Path(raw_path.decode("utf-8"))
            mode = int(raw_mode.decode("ascii"), 8)
            object_type = raw_object_type.decode("ascii")
            object_id = raw_object_id.decode("ascii")
        except (IndexError, UnicodeDecodeError, ValueError):
            source_label = "tree" if treeish is not None else "index"
            raise RuntimeError(
                f"unable to parse Git {source_label} record: {raw_record!r}"
            ) from None
        path = repo_root / rel
        if mode == 0o120000:
            if should_include(path, repo_root):
                raise RuntimeError(f"refusing to package tracked symlink: {rel.as_posix()}")
            continue
        if not should_include(path, repo_root):
            continue
        if object_type != "blob" or mode not in {0o100644, 0o100755}:
            raise RuntimeError(
                "refusing to package unsupported Git tree entry: "
                f"{rel.as_posix()} ({raw_mode.decode('ascii', errors='replace')} {object_type})"
            )
        if not path.exists():
            if allow_missing:
                continue
            raise FileNotFoundError(str(path))
        _assert_confined_source(path, repo_root)
        if not stat.S_ISREG(path.lstat().st_mode):
            raise FileNotFoundError(str(path))
        rel_posix = rel.as_posix()
        members_by_arcname[f"{package_name}/{rel_posix}"] = (
            path,
            f"{package_name}/{rel_posix}",
            mode,
            object_id,
        )
        parent = rel.parent
        while parent != Path("."):
            parent_path = repo_root / parent
            if should_include(parent_path, repo_root):
                directory_arcnames.add(f"{package_name}/{parent.as_posix()}/")
            parent = parent.parent

    if include_untracked:
        untracked = subprocess.run(
            _git_command(
                repo_root,
                ["ls-files", "--others", "--exclude-standard", "-z"],
            ),
            check=False,
            capture_output=True,
            env=_git_environment(),
        )
        if untracked.returncode != 0:
            return None
        for raw_path in untracked.stdout.split(b"\0"):
            if not raw_path:
                continue
            try:
                rel = Path(raw_path.decode("utf-8"))
            except UnicodeDecodeError:
                raise RuntimeError(f"unable to parse git untracked path: {raw_path!r}") from None
            path = repo_root / rel
            if not should_include(path, repo_root):
                continue
            if _is_link_like(path):
                raise RuntimeError(f"refusing to package untracked link-like source path: {rel.as_posix()}")
            if not path.exists() or not stat.S_ISREG(path.lstat().st_mode):
                continue
            _assert_confined_source(path, repo_root)
            rel_posix = rel.as_posix()
            members_by_arcname[f"{package_name}/{rel_posix}"] = (
                path,
                f"{package_name}/{rel_posix}",
                zip_mode(path),
                None,
            )
            parent = rel.parent
            while parent != Path("."):
                parent_path = repo_root / parent
                if should_include(parent_path, repo_root):
                    directory_arcnames.add(f"{package_name}/{parent.as_posix()}/")
                parent = parent.parent

    for arcname in directory_arcnames:
        rel_text = arcname.removeprefix(f"{package_name}/").rstrip("/")
        members_by_arcname[arcname] = (
            repo_root / rel_text,
            arcname,
            0o40755,
            None,
        )

    return sorted(members_by_arcname.values(), key=lambda item: item[1])


def _walk_members(repo_root: Path, package_name: str) -> list[ReleaseMember]:
    members: list[ReleaseMember] = []
    for current_root, dir_names, file_names in os.walk(repo_root, followlinks=False):
        current = Path(current_root)
        rel_current = current.relative_to(repo_root)

        retained_dirs: list[str] = []
        for name in sorted(dir_names):
            path = current / name
            if name in EXCLUDED_PARTS or any(
                fnmatch.fnmatch(name, pattern) for pattern in EXCLUDED_BASENAME_PATTERNS
            ):
                continue
            if not rel_current.parts and name not in INCLUDE_TOP_LEVEL:
                continue
            if _is_link_like(path):
                if should_include(path, repo_root):
                    raise RuntimeError(
                        f"refusing to package link-like path from filesystem walk: "
                        f"{path.relative_to(repo_root).as_posix()}"
                    )
                continue
            _assert_confined_source(path, repo_root)
            retained_dirs.append(name)
        dir_names[:] = retained_dirs

        for dir_name in dir_names:
            path = current / dir_name
            if should_include(path, repo_root):
                rel = path.relative_to(repo_root).as_posix()
                members.append((path, f"{package_name}/{rel}/", zip_mode(path), None))

        for file_name in sorted(file_names):
            path = current / file_name
            if _is_link_like(path):
                if should_include(path, repo_root):
                    raise RuntimeError(
                        f"refusing to package link-like path from filesystem walk: "
                        f"{path.relative_to(repo_root).as_posix()}"
                    )
                continue
            if should_include(path, repo_root):
                _assert_confined_source(path, repo_root)
                rel = path.relative_to(repo_root).as_posix()
                members.append((path, f"{package_name}/{rel}", zip_mode(path), None))
    return sorted(members, key=lambda item: item[1])


def _git_blob(repo_root: Path, object_id: str) -> bytes:
    proc = subprocess.run(
        _git_command(repo_root, ["cat-file", "blob", object_id]),
        check=False,
        capture_output=True,
        env=_git_environment(),
    )
    if proc.returncode != 0:
        raise RuntimeError(f"unable to read Git blob {object_id} for release snapshot")
    return proc.stdout


def _snapshot_members(
    repo_root: Path,
    members: list[ReleaseMember],
    *,
    use_git_objects: bool,
) -> list[SnapshotMember]:
    snapshot: list[SnapshotMember] = []
    for source, arcname, mode, object_id in members:
        if arcname.endswith("/"):
            snapshot.append((arcname, mode, None))
            continue
        if use_git_objects:
            if object_id is None:
                raise RuntimeError(f"tracked release member has no Git object ID: {arcname}")
            data = _git_blob(repo_root, object_id)
        else:
            if _is_link_like(source):
                raise RuntimeError(
                    f"refusing to package symlink, junction, or reparse point: {source}"
                )
            data = source.read_bytes()
        snapshot.append((arcname, mode, data))
    return snapshot


def _assert_clean_source_unchanged(repo_root: Path, expected_commit: str) -> None:
    if _git_output(repo_root, ["rev-parse", "HEAD"]) != expected_commit:
        raise RuntimeError(
            "Git HEAD changed during release archive preparation; refusing to build a mixed-snapshot release archive"
        )
    clean = _git_worktree_is_clean(repo_root)
    if clean is None:
        raise RuntimeError("unable to verify git working-tree cleanliness during release archive preparation")
    if clean is False:
        raise RuntimeError(
            "git working tree changed during release archive preparation; "
            "refusing to build a mixed-snapshot release archive"
        )


def build_release(repo_root: Path, out_dir: Path, version: str, *, require_clean: bool = True) -> dict[str, object]:
    if _is_link_like(repo_root):
        raise RuntimeError(f"refusing to package a linked repository root: {repo_root}")
    configured_version = project_version(repo_root)
    if version != configured_version:
        raise ValueError(
            f"release version {version!r} does not match pyproject.toml version {configured_version!r}"
        )
    package_name = f"epic-continuum-{version}"
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / f"{package_name}.zip"
    checksum_path = zip_path.with_suffix(zip_path.suffix + ".sha256")
    source = "git+working-tree" if not require_clean else "git"
    git_commit = _git_output(repo_root, ["rev-parse", "HEAD"])
    source_date_epoch = _release_source_date_epoch(repo_root, git_commit)
    if require_clean:
        clean = _git_worktree_is_clean(repo_root)
        if clean is None:
            raise RuntimeError(
                "unable to verify a Git worktree for a clean release archive; "
                "use --allow-dirty only for a development archive"
            )
        if clean is False:
            raise RuntimeError(
                "refusing to build a git-sourced release archive from tracked working-tree changes "
                "or non-ignored untracked files; commit, add, or stash changes first, or pass "
                "--allow-dirty for a development archive"
            )
        if not git_commit:
            raise RuntimeError("unable to resolve Git HEAD for a clean release archive")
        if not _git_repository_matches(repo_root):
            raise RuntimeError(
                "Git worktree authority does not match the requested repository root"
            )
    members = _git_tracked_members(
        repo_root,
        package_name,
        allow_missing=not require_clean,
        include_untracked=not require_clean,
        treeish=git_commit if require_clean else None,
    )
    if members is None:
        if require_clean:
            raise RuntimeError("unable to enumerate Git-tracked files for a clean release archive")
        source = "walk"
        members = _walk_members(repo_root, package_name)
    snapshot = _snapshot_members(repo_root, members, use_git_objects=require_clean)
    if require_clean:
        assert git_commit is not None
        _assert_clean_source_unchanged(repo_root, git_commit)
        status_short: list[str] | None = []
    else:
        status_short = _git_status_short(repo_root)
    provenance = _provenance_payload(
        package_name,
        version,
        source,
        snapshot,
        require_clean=require_clean,
        git_commit=git_commit,
        status_short=status_short,
        source_date_epoch=source_date_epoch,
    )
    provenance_arcname = f"{package_name}/RELEASE_PROVENANCE.json"
    package_provenance_arcname = f"{package_name}/src/continuum/assets/RELEASE_PROVENANCE.json"
    _assert_unique_arcnames(
        [
            f"{package_name}/",
            *(arcname for arcname, _, _ in snapshot),
            provenance_arcname,
            package_provenance_arcname,
        ]
    )

    if zip_path.exists():
        zip_path.unlink()
    if checksum_path.exists():
        checksum_path.unlink()

    try:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            root_info = zipfile.ZipInfo(
                f"{package_name}/",
                reproducible_zip_dt(source_date_epoch),
            )
            root_info.create_system = 3
            root_info.external_attr = 0o40755 << 16
            root_info.compress_type = zipfile.ZIP_STORED
            zf.writestr(root_info, b"")
            for arcname, mode, data in snapshot:
                write_member(
                    zf,
                    arcname,
                    data,
                    mode=mode,
                    source_date_epoch=source_date_epoch,
                )
            provenance_bytes = _stable_json_bytes(provenance)
            write_bytes_member(
                zf,
                provenance_arcname,
                provenance_bytes,
                source_date_epoch=source_date_epoch,
            )
            write_bytes_member(
                zf,
                package_provenance_arcname,
                provenance_bytes,
                source_date_epoch=source_date_epoch,
            )
        if require_clean:
            assert git_commit is not None
            _assert_clean_source_unchanged(repo_root, git_commit)
    except Exception:
        if zip_path.exists():
            zip_path.unlink()
        raise

    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    checksum_path.write_text(f"{digest}  {zip_path.name}\n", encoding="utf-8", newline="\n")
    return {
        "package": str(zip_path),
        "sha256": digest,
        "checksum": str(checksum_path),
        "members": len(snapshot) + 3,
        "source": source,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the Epic Continuum public release ZIP.")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--version", default=None, help="Release version; must match pyproject.toml exactly.")
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow working-tree changes and intended untracked inputs in a development archive.",
    )
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    out_dir = (args.out_dir or (repo_root / "dist")).resolve()
    result = build_release(repo_root, out_dir, args.version or project_version(repo_root), require_clean=not args.allow_dirty)
    for key, value in result.items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
