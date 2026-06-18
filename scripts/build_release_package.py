from __future__ import annotations

import argparse
import fnmatch
import hashlib
import os
import subprocess
import zipfile
from pathlib import Path


DEFAULT_VERSION = "0.1.0"
FIXED_ZIP_DT = (2026, 6, 18, 0, 0, 0)

EXCLUDED_PARTS = {
    ".git",
    ".venv",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
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
}


def should_include(path: Path, repo_root: Path) -> bool:
    rel = path.relative_to(repo_root)
    parts = rel.parts
    if not parts:
        return False
    if parts[0] not in INCLUDE_TOP_LEVEL:
        return False
    if any(part in EXCLUDED_PARTS for part in parts):
        return False
    name = path.name
    if any(fnmatch.fnmatch(name, pattern) for pattern in EXCLUDED_BASENAME_PATTERNS):
        return False
    if "".join(path.suffixes[-2:]) == ".tar.gz":
        return False
    if path.suffix in EXCLUDED_SUFFIXES:
        return False
    if rel.parts[0] == "docs":
        allowed_docs = (
            rel.parts[1:2] in (("architecture",), ("integrations",), ("audits",))
            or str(rel).replace("\\", "/")
            in {
                "docs/configuration.md",
                "docs/GLOSSARY.md",
                "docs/HARDWARE_TIERS.md",
                "docs/ORIGINAL_DESIGN_COVERAGE_2026-06-17.md",
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


def write_member(zf: zipfile.ZipFile, source: Path, arcname: str, *, mode: int | None = None) -> None:
    info = zipfile.ZipInfo(arcname, FIXED_ZIP_DT)
    info.create_system = 3
    info.external_attr = (mode if mode is not None else zip_mode(source)) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    data = b"" if source.is_dir() else source.read_bytes()
    zf.writestr(info, data)


def _git_tracked_members(repo_root: Path, package_name: str) -> list[tuple[Path, str, int]] | None:
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "ls-files", "--stage", "-z"],
        check=False,
        capture_output=True,
    )
    if proc.returncode != 0:
        return None

    members_by_arcname: dict[str, tuple[Path, str, int]] = {}
    directory_arcnames: set[str] = set()
    for raw_record in proc.stdout.split(b"\0"):
        if not raw_record:
            continue
        try:
            raw_header, raw_path = raw_record.split(b"\t", 1)
            raw_mode = raw_header.split(maxsplit=1)[0]
            rel = Path(raw_path.decode("utf-8"))
            mode = int(raw_mode.decode("ascii"), 8)
        except (IndexError, UnicodeDecodeError, ValueError):
            raise RuntimeError(f"unable to parse git ls-files record: {raw_record!r}") from None
        path = repo_root / rel
        if mode == 0o120000:
            continue
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(str(path))
        if not should_include(path, repo_root):
            continue
        rel_posix = rel.as_posix()
        members_by_arcname[f"{package_name}/{rel_posix}"] = (path, f"{package_name}/{rel_posix}", mode)
        parent = rel.parent
        while parent != Path("."):
            parent_path = repo_root / parent
            if should_include(parent_path, repo_root):
                directory_arcnames.add(f"{package_name}/{parent.as_posix()}/")
            parent = parent.parent

    for arcname in directory_arcnames:
        rel = arcname.removeprefix(f"{package_name}/").rstrip("/")
        members_by_arcname[arcname] = (repo_root / rel, arcname, 0o40755)

    return sorted(members_by_arcname.values(), key=lambda item: item[1])


def _walk_members(repo_root: Path, package_name: str) -> list[tuple[Path, str, int]]:
    members: list[tuple[Path, str, int]] = []
    for current_root, dir_names, file_names in os.walk(repo_root):
        current = Path(current_root)
        rel_current = current.relative_to(repo_root)
        dir_names[:] = sorted(
            name
            for name in dir_names
            if name not in EXCLUDED_PARTS
            and not any(fnmatch.fnmatch(name, pattern) for pattern in EXCLUDED_BASENAME_PATTERNS)
            and (rel_current.parts or name in INCLUDE_TOP_LEVEL)
        )
        for dir_name in dir_names:
            path = current / dir_name
            if should_include(path, repo_root):
                rel = path.relative_to(repo_root).as_posix()
                members.append((path, f"{package_name}/{rel}/", zip_mode(path)))
        for file_name in sorted(file_names):
            path = current / file_name
            if should_include(path, repo_root):
                rel = path.relative_to(repo_root).as_posix()
                members.append((path, f"{package_name}/{rel}", zip_mode(path)))
    return sorted(members, key=lambda item: item[1])


def build_release(repo_root: Path, out_dir: Path, version: str) -> dict[str, object]:
    package_name = f"epic-continuum-{version}"
    out_dir.mkdir(parents=True, exist_ok=True)
    zip_path = out_dir / f"{package_name}.zip"
    checksum_path = zip_path.with_suffix(zip_path.suffix + ".sha256")
    source = "git"
    members = _git_tracked_members(repo_root, package_name)
    if members is None:
        source = "walk"
        members = _walk_members(repo_root, package_name)

    if zip_path.exists():
        zip_path.unlink()
    if checksum_path.exists():
        checksum_path.unlink()

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        root_info = zipfile.ZipInfo(f"{package_name}/", FIXED_ZIP_DT)
        root_info.create_system = 3
        root_info.external_attr = 0o40755 << 16
        root_info.compress_type = zipfile.ZIP_STORED
        zf.writestr(root_info, b"")
        for member_source, arcname, mode in members:
            write_member(zf, member_source, arcname, mode=mode)

    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    checksum_path.write_text(f"{digest}  {zip_path.name}\n", encoding="utf-8", newline="\n")
    return {
        "package": str(zip_path),
        "sha256": digest,
        "checksum": str(checksum_path),
        "members": len(members) + 1,
        "source": source,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the Epic Continuum public release ZIP.")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--version", default=DEFAULT_VERSION)
    args = parser.parse_args()

    repo_root = args.repo_root.resolve()
    out_dir = (args.out_dir or (repo_root / "dist")).resolve()
    result = build_release(repo_root, out_dir, args.version)
    for key, value in result.items():
        print(f"{key}: {value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
