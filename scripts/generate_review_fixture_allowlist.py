#!/usr/bin/env python3
"""Relocate and canonically render approved review-fixture secret findings.

The JSONL file is both a deliberate approval registry and the exact-line
allowlist consumed by the review bridge.  Approval identity intentionally
excludes the line number so routine source edits can be reconciled without
silently approving a new secret-shaped value.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

from continuum.core.review_bridge import _scan_review_text_for_secrets


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ALLOWLIST = REPO_ROOT / "docs" / "review-fixture-secret-allowlist.jsonl"
HEADER = (
    "# Epic Continuum review-relay synthetic fixture fingerprint allowlist.\n"
    "# Approval identity is source/type/secret_sha256/line_sha256; line is generated.\n"
    "# Do not add real secrets. After deliberate review, run this script with --write.\n"
)
HASH_RE = re.compile(r"[0-9a-f]{64}")
REQUIRED_KEYS = {
    "source",
    "line",
    "finding_type",
    "secret_sha256",
    "line_sha256",
    "reason",
}
Identity = tuple[str, str, str, str]


class AllowlistGateError(ValueError):
    """Raised when the approval registry cannot be used safely."""


def _identity(record: dict[str, Any]) -> Identity:
    return (
        str(record["source"]),
        str(record["finding_type"]),
        str(record["secret_sha256"]),
        str(record["line_sha256"]),
    )


def _validate_source(source: object, *, location: str) -> str:
    if not isinstance(source, str) or not source or "\\" in source:
        raise AllowlistGateError(f"{location}: source must be a non-empty POSIX relative path")
    path = PurePosixPath(source)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise AllowlistGateError(f"{location}: source must be a normalized relative path")
    if path.as_posix() != source:
        raise AllowlistGateError(f"{location}: source must be a normalized relative path")
    return source


def _validate_record(raw: object, *, location: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise AllowlistGateError(f"{location}: entry must be a JSON object")
    if set(raw) != REQUIRED_KEYS:
        missing = sorted(REQUIRED_KEYS - set(raw))
        extra = sorted(set(raw) - REQUIRED_KEYS)
        raise AllowlistGateError(f"{location}: invalid fields (missing={missing}, extra={extra})")

    source = _validate_source(raw["source"], location=location)
    line = raw["line"]
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        raise AllowlistGateError(f"{location}: line must be a positive integer")
    finding_type = raw["finding_type"]
    if not isinstance(finding_type, str) or not finding_type:
        raise AllowlistGateError(f"{location}: finding_type must be a non-empty string")
    reason = raw["reason"]
    if not isinstance(reason, str) or not reason.strip():
        raise AllowlistGateError(f"{location}: reason must be a non-empty string")

    hashes: dict[str, str] = {}
    for key in ("secret_sha256", "line_sha256"):
        value = raw[key]
        if not isinstance(value, str) or not HASH_RE.fullmatch(value):
            raise AllowlistGateError(f"{location}: {key} must be a lowercase SHA-256")
        hashes[key] = value

    return {
        "source": source,
        "line": line,
        "finding_type": finding_type,
        "secret_sha256": hashes["secret_sha256"],
        "line_sha256": hashes["line_sha256"],
        "reason": reason.strip(),
    }


def load_approvals(path: Path) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise AllowlistGateError(f"cannot read allowlist {path}: {exc}") from exc

    approvals: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            raw = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise AllowlistGateError(f"{path}:{line_number}: invalid JSON: {exc.msg}") from exc
        approvals.append(_validate_record(raw, location=f"{path}:{line_number}"))
    return approvals


def _source_path(repo_root: Path, source: str) -> Path | None:
    candidate = repo_root.joinpath(*PurePosixPath(source).parts)
    try:
        root = repo_root.resolve(strict=True)
    except OSError as exc:
        raise AllowlistGateError(f"repository root is unavailable: {repo_root}: {exc}") from exc
    if not root.is_dir():
        raise AllowlistGateError(f"repository root is not a directory: {repo_root}")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AllowlistGateError(f"approved source is unavailable: {source}: {exc}") from exc
    if not resolved.is_relative_to(root) or not resolved.is_file() or candidate.is_symlink():
        raise AllowlistGateError(f"approved source must be a regular file inside the repository: {source}")
    return resolved


def reconcile(
    approvals: Iterable[dict[str, Any]], *, repo_root: Path
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Return canonical records, unapproved findings, and obsolete approvals."""
    approval_rows = list(approvals)
    reasons: dict[Identity, str] = {}
    old_rows: dict[Identity, list[dict[str, Any]]] = {}
    for approval in approval_rows:
        identity = _identity(approval)
        prior_reason = reasons.setdefault(identity, str(approval["reason"]))
        if prior_reason != approval["reason"]:
            raise AllowlistGateError(
                f"conflicting reasons for approval {approval['source']}:{approval['finding_type']}"
            )
        old_rows.setdefault(identity, []).append(approval)

    seen_identities: set[Identity] = set()
    canonical_by_location: dict[tuple[Identity, int], dict[str, Any]] = {}
    unapproved: list[dict[str, Any]] = []

    for source in sorted({row["source"] for row in approval_rows}):
        path = _source_path(repo_root, source)
        if path is None:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise AllowlistGateError(f"cannot read approved source {source}: {exc}") from exc
        lines = text.splitlines()
        findings = _scan_review_text_for_secrets(text, source=source, max_findings=0)
        for finding in findings:
            line = finding.get("line")
            finding_type = finding.get("type")
            secret_hash = finding.get("secret_hash")
            if (
                isinstance(line, bool)
                or not isinstance(line, int)
                or line < 1
                or line > len(lines)
                or not isinstance(finding_type, str)
                or not finding_type
                or not isinstance(secret_hash, str)
                or not HASH_RE.fullmatch(secret_hash)
            ):
                raise AllowlistGateError(
                    f"scanner returned a finding that cannot be fingerprinted safely: {source}"
                )
            line_hash = hashlib.sha256(lines[line - 1].encode("utf-8")).hexdigest()
            identity: Identity = (source, finding_type, secret_hash, line_hash)
            if identity not in reasons:
                unapproved.append(
                    {
                        "source": source,
                        "line": line,
                        "finding_type": finding_type,
                        "secret_sha256": secret_hash,
                        "line_sha256": line_hash,
                    }
                )
                continue
            seen_identities.add(identity)
            canonical_by_location[(identity, line)] = {
                "finding_type": finding_type,
                "line": line,
                "line_sha256": line_hash,
                "reason": reasons[identity],
                "secret_sha256": secret_hash,
                "source": source,
            }

    obsolete = [rows[0] for identity, rows in old_rows.items() if identity not in seen_identities]
    canonical = sorted(
        canonical_by_location.values(),
        key=lambda row: (
            row["source"],
            row["line"],
            row["finding_type"],
            row["secret_sha256"],
            row["line_sha256"],
        ),
    )
    unapproved.sort(
        key=lambda row: (row["source"], row["line"], row["finding_type"], row["secret_sha256"])
    )
    obsolete.sort(
        key=lambda row: (row["source"], row["line"], row["finding_type"], row["secret_sha256"])
    )
    return canonical, unapproved, obsolete


def canonical_text(records: Iterable[dict[str, Any]]) -> str:
    body = "".join(
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        for record in records
    )
    return HEADER + body


def _describe(records: Iterable[dict[str, Any]], *, label: str) -> None:
    rows = list(records)
    if not rows:
        return
    print(f"{label}: {len(rows)}", file=sys.stderr)
    for row in rows:
        print(
            f"  {row['source']}:{row['line']} {row['finding_type']} "
            f"secret_sha256={row['secret_sha256'][:12]}... "
            f"line_sha256={row['line_sha256'][:12]}...",
            file=sys.stderr,
        )


def run(*, allowlist: Path, repo_root: Path, write: bool) -> int:
    approvals = load_approvals(allowlist)
    canonical, unapproved, obsolete = reconcile(approvals, repo_root=repo_root)
    _describe(unapproved, label="unapproved findings")
    _describe(obsolete, label="obsolete approvals")
    if unapproved:
        print(
            "Refusing to update: review each new finding and add its exact fingerprint deliberately.",
            file=sys.stderr,
        )
        return 2

    expected = canonical_text(canonical).encode("utf-8")
    try:
        actual = allowlist.read_bytes()
    except OSError as exc:
        raise AllowlistGateError(f"cannot read allowlist {allowlist}: {exc}") from exc

    if write:
        if actual != expected:
            allowlist.write_bytes(expected)
            print(f"updated {allowlist} ({len(canonical)} fingerprints)")
        else:
            print(f"already current: {allowlist} ({len(canonical)} fingerprints)")
        return 0

    if actual != expected:
        print(
            f"allowlist is stale or non-canonical: {allowlist}; run with --write after review",
            file=sys.stderr,
        )
        return 1
    print(f"allowlist is current: {allowlist} ({len(canonical)} fingerprints)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="verify exact canonical content")
    mode.add_argument("--write", action="store_true", help="rewrite relocated canonical content")
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)
    try:
        return run(
            allowlist=args.allowlist.resolve(),
            repo_root=args.repo_root.resolve(),
            write=bool(args.write),
        )
    except AllowlistGateError as exc:
        print(f"allowlist gate failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
