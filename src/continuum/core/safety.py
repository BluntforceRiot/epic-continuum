from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any


DEFAULT_IGNORE_PATTERNS = [
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa",
    "id_ed25519",
    "node_modules/",
    ".venv/",
    "venv/",
    "__pycache__/",
    ".git/",
]

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("bearer_token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "secret_assignment",
        re.compile(
            r"(?i)(?<![A-Za-z0-9_])['\"]?"
            r"((?:[A-Za-z0-9]+[_-])?(?:api[_-]?key|access[_-]?key|auth[_-]?key|private[_-]?key|signing[_-]?key|password|passwd|pwd|secret|authorization|cookie)|"
            r"(?:api|access|auth|bearer|client|csrf|github|gitlab|hf|id|jwt|oauth|openai|private|refresh|session|slack|stripe|webhook)[_-]?token|token)"
            r"\b['\"]?\s*[:=]\s*['\"]?[^'\"\s,}]{8,}"
        ),
    ),
]


def load_ignore_patterns(root: Path, *, ignore_file_name: str = ".continuumignore") -> list[str]:
    patterns = list(DEFAULT_IGNORE_PATTERNS)
    ignore_path = root / ignore_file_name
    if ignore_path.exists():
        for line in ignore_path.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                patterns.append(stripped)
    return patterns


def _normalize_path(path: Path) -> str:
    return str(path).replace("\\", "/")


def ignored_by_pattern(path: Path, patterns: list[str]) -> str | None:
    normalized = _normalize_path(path)
    name = path.name
    parts = normalized.split("/")
    for pattern in patterns:
        cleaned = pattern.strip().replace("\\", "/")
        if not cleaned:
            continue
        directory_pattern = cleaned.endswith("/")
        cleaned = cleaned.rstrip("/")
        if directory_pattern and cleaned in parts:
            return pattern
        if fnmatch.fnmatch(name, cleaned) or fnmatch.fnmatch(normalized, cleaned):
            return pattern
        if "/" not in cleaned and cleaned in parts:
            return pattern
    return None


def is_ignored_path(root: Path, path: Path, *, ignore_file_name: str = ".continuumignore") -> tuple[bool, str | None]:
    pattern = ignored_by_pattern(path, load_ignore_patterns(root, ignore_file_name=ignore_file_name))
    return pattern is not None, pattern


def _redact_line(line: str, match: re.Match[str]) -> str:
    """Return a bounded finding snippet with every recognizable secret redacted."""
    return redact_text_secrets(line).strip()[:240]


def _normalized_assignment_value(value: str) -> str:
    cleaned = value.strip().rstrip(",").strip()
    if len(cleaned) >= 2 and cleaned[0] == cleaned[-1] and cleaned[0] in {"'", '"'}:
        cleaned = cleaned[1:-1]
    return cleaned.strip()


def _sensitive_assignment_line(line: str) -> tuple[str, str] | None:
    match = SENSITIVE_ASSIGNMENT_LINE_RE.match(line)
    if not match:
        return None
    key = match.group(1)
    raw_value = match.group(2)
    value = _normalized_assignment_value(raw_value)
    if not value or _is_redacted_value_placeholder(value):
        return None
    if not _looks_sensitive_key(key):
        return None
    return key, value


def _redact_sensitive_assignment_line(line: str) -> str:
    assignment = _sensitive_assignment_line(line)
    if not assignment:
        return line
    match = SENSITIVE_ASSIGNMENT_LINE_RE.match(line)
    if not match:
        return line
    value_start, value_end = match.span(2)
    suffix = line[value_end:]
    return f"{line[:value_start]}[REDACTED]{suffix}"


def _embedded_sensitive_assignments(line: str) -> list[tuple[re.Match[str], str, str]]:
    assignments: list[tuple[re.Match[str], str, str]] = []
    for match in EMBEDDED_ASSIGNMENT_RE.finditer(line):
        key = match.group("key")
        value = _normalized_assignment_value(match.group("value"))
        if not value or _is_redacted_value_placeholder(value) or not _looks_sensitive_key(key):
            continue
        assignments.append((match, key, value))
    return assignments


def _redact_embedded_sensitive_assignments(line: str) -> str:
    redacted = line
    assignments = _embedded_sensitive_assignments(line)
    for match, _key, _value in reversed(assignments):
        start, end = match.span("value")
        redacted = f"{redacted[:start]}[REDACTED]{redacted[end:]}"
    return redacted


def redact_text_secrets(text: str) -> str:
    redacted_lines: list[str] = []
    for line in text.splitlines():
        redacted = line
        for _name, pattern in SECRET_PATTERNS:
            redacted = pattern.sub("[REDACTED]", redacted)
        redacted = _redact_sensitive_assignment_line(redacted)
        redacted = _redact_embedded_sensitive_assignments(redacted)
        redacted_lines.append(redacted)
    return "\n".join(redacted_lines)


SENSITIVE_METADATA_KEYS = {
    "api_key",
    "apikey",
    "access_key",
    "auth_key",
    "authorization",
    "proxy_authorization",
    "bearer",
    "client_secret",
    "cookie",
    "set_cookie",
    "id_token",
    "jwt",
    "jwt_token",
    "oauth_token",
    "private_key",
    "refresh_token",
    "secret",
    "session_cookie",
    "session_token",
    "signing_key",
    "token",
    "webhook_secret",
    "password",
    "passwd",
    "pwd",
}
SAFE_METADATA_KEY_EXCEPTIONS = {
    "context_token_budget",
    "default_token_budget",
    "estimated_tokens",
    "max_token_budget",
    "remaining_tokens",
    "reserve_output_tokens",
    "resume_token",
    "token_budget",
    "token_count",
    "token_estimate",
    "tokens",
    "tokens_used",
    "secret_audit_max_file_bytes",
    "secret_audit_max_findings",
    "secret_findings",
    "secret_hash",
    "secret_policy_note",
    "secret_scan_action",
    "secret_scan_enabled",
    "entropy_secret_scan_enabled",
}
REDACTED_VALUE_RE = re.compile(r"(?i)(?:\[REDACTED\]|<REDACTED>|REDACTED)")
SENSITIVE_ASSIGNMENT_LINE_RE = re.compile(
    r"^\s*(?:export\s+|set\s+)?(?:-\s*)?['\"]?([A-Za-z0-9_.-]{2,120})['\"]?\s*[:=]\s*(.+?)\s*,?\s*$",
    re.IGNORECASE,
)
EMBEDDED_ASSIGNMENT_RE = re.compile(
    r"(?P<quote>['\"]?)(?P<key>[A-Za-z_][A-Za-z0-9_.-]{1,119})(?P=quote)"
    r"\s*[:=]\s*"
    r"(?P<value>\[[^\]\r\n]*\]|<[^>\r\n]*>|\"(?:\\.|[^\"\\])*\"|'(?:''|[^'])*'|[^,}\]\s]+)",
    re.IGNORECASE,
)


def _normal_sensitive_key_parts(key: Any) -> tuple[str, list[str]]:
    lowered = str(key).strip().casefold()
    normalized = re.sub(r"[^a-z0-9]+", "_", lowered).strip("_")
    return normalized, [part for part in normalized.split("_") if part]


def _looks_sensitive_key(key: Any) -> bool:
    normalized, parts = _normal_sensitive_key_parts(key)
    if not normalized or normalized in SAFE_METADATA_KEY_EXCEPTIONS:
        return False
    if normalized in SENSITIVE_METADATA_KEYS:
        return True
    if normalized.endswith(("_password", "_passwd", "_pwd", "_secret", "_private_key", "_access_key", "_api_key", "_apikey")):
        return True
    if "password" in parts or "passwd" in parts or "pwd" in parts:
        return True
    if "authorization" in parts or "cookie" in parts:
        return True
    if "secret" in parts and any(part in parts for part in {"access", "api", "app", "auth", "client", "jwt", "oauth", "private", "signing", "session", "webhook"}):
        return True
    if "api" in parts and "key" in parts:
        return True
    if "access" in parts and "key" in parts:
        return True
    if "key" in parts and any(part in parts for part in {"auth", "private", "secret", "session", "signing"}):
        return True
    if normalized.endswith("_token") or normalized == "token":
        return True
    return False


def _is_redacted_secret_placeholder(match_text: str) -> bool:
    stripped = match_text.strip().rstrip(",}")
    unquoted = stripped.strip("'\"")
    if REDACTED_VALUE_RE.fullmatch(unquoted):
        return True
    assignment = re.search(r"[:=]\s*['\"]?(\[REDACTED\]|<REDACTED>|REDACTED)['\"]?\s*$", stripped, re.IGNORECASE)
    return assignment is not None


def _is_redacted_value_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        return REDACTED_VALUE_RE.fullmatch(value.strip()) is not None
    if isinstance(value, list):
        return bool(value) and all(_is_redacted_value_placeholder(item) for item in value)
    if isinstance(value, dict):
        return bool(value) and all(_is_redacted_value_placeholder(item) for item in value.values())
    return False


def _redacted_key_name(key: Any) -> Any:
    if not isinstance(key, str):
        return key
    if not scan_text_for_secrets(key, max_findings=1):
        return key
    digest = hashlib.sha256(key.encode("utf-8", errors="replace")).hexdigest()[:16]
    return f"redacted_key_{digest}"


def _secret_hash_payload(secret: str, *, allow_low_entropy_hash: bool = True) -> dict[str, Any]:
    payload = {"secret_hash": hashlib.sha256(secret.encode("utf-8", errors="replace")).hexdigest()}
    if allow_low_entropy_hash or len(secret) >= 20 or _shannon_entropy(secret) >= 3.5:
        return payload
    payload["secret_hash_risk"] = "low_entropy_secret_value"
    payload["secret_hash_note"] = "Stable unsalted hash retained for allowlist compatibility; avoid sharing raw audit output."
    return payload


def redact_value_secrets(value: Any) -> Any:
    """Recursively redact obvious secrets from JSON-like metadata values and keys."""
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, nested in value.items():
            safe_key = _redacted_key_name(key)
            if _looks_sensitive_key(key) and nested not in (None, "", False) and not _is_redacted_value_placeholder(nested):
                redacted[safe_key] = "[REDACTED]"
            else:
                redacted[safe_key] = redact_value_secrets(nested)
        return redacted
    if isinstance(value, list):
        return [redact_value_secrets(nested) for nested in value]
    if isinstance(value, tuple):
        return [redact_value_secrets(nested) for nested in value]
    if isinstance(value, str):
        return redact_text_secrets(value)
    return value


def scan_text_for_secrets(text: str, *, max_findings: int = 20) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        line_had_finding = False
        for name, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                if _is_redacted_secret_placeholder(match.group(0)):
                    continue
                findings.append(
                    {
                        "type": name,
                        "line": line_number,
                        "snippet": _redact_line(line, match),
                        **_secret_hash_payload(match.group(0)),
                    }
                )
                line_had_finding = True
                if len(findings) >= max_findings:
                    return findings
        if not line_had_finding:
            assignment = _sensitive_assignment_line(line)
            if assignment:
                key, value = assignment
                findings.append(
                    {
                        "type": "sensitive_key_assignment",
                        "line": line_number,
                        "snippet": _redact_sensitive_assignment_line(line).strip()[:240],
                        **_secret_hash_payload(value, allow_low_entropy_hash=False),
                        "metadata_path": f"$.{_safe_metadata_path_part(key)}",
                    }
                )
                if len(findings) >= max_findings:
                    return findings
                line_had_finding = True
        if not line_had_finding:
            for _match, key, value in _embedded_sensitive_assignments(line):
                findings.append(
                    {
                        "type": "sensitive_key_assignment",
                        "line": line_number,
                        "snippet": _redact_embedded_sensitive_assignments(line).strip()[:240],
                        **_secret_hash_payload(value, allow_low_entropy_hash=False),
                        "metadata_path": f"$.{_safe_metadata_path_part(key)}",
                    }
                )
                if len(findings) >= max_findings:
                    return findings
    return findings


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def scan_text_for_entropy_secrets(
    text: str,
    *,
    min_length: int = 32,
    min_entropy: float = 4.5,
    max_findings: int = 20,
) -> list[dict[str, Any]]:
    """Find long high-entropy tokens as an opt-in secret audit heuristic."""
    token_re = re.compile(r"[A-Za-z0-9_+/=-]{" + str(max(8, int(min_length))) + r",}")
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for match in token_re.finditer(line):
            token = match.group(0)
            if _is_redacted_secret_placeholder(token):
                continue
            entropy = _shannon_entropy(token)
            if entropy < float(min_entropy):
                continue
            snippet = line.replace(token, "[REDACTED_ENTROPY_SECRET]").strip()[:240]
            findings.append(
                {
                    "type": "high_entropy_token",
                    "line": line_number,
                    "snippet": snippet,
                    **_secret_hash_payload(token),
                    "entropy": round(entropy, 3),
                    "length": len(token),
                }
            )
            if len(findings) >= max_findings:
                return findings
    return findings


def _safe_metadata_path_part(key: Any) -> str:
    text = str(key)
    if scan_text_for_secrets(text, max_findings=1):
        return f"redacted_key_{hashlib.sha256(text.encode('utf-8', errors='replace')).hexdigest()[:16]}"
    return text[:80]


def _scan_sensitive_key_findings(
    value: Any,
    *,
    scope: str,
    path: str = "$",
    max_findings: int = 20,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if max_findings <= 0:
        return findings
    if isinstance(value, dict):
        for key, nested in value.items():
            key_part = _safe_metadata_path_part(key)
            nested_path = f"{path}.{key_part}" if path else key_part
            if _looks_sensitive_key(key) and nested not in (None, "", False) and not _is_redacted_value_placeholder(nested):
                material = json.dumps(nested, ensure_ascii=True, sort_keys=True, default=str)
                findings.append(
                    {
                        "type": "sensitive_metadata_key",
                        "line": 1,
                        "snippet": f"{key_part}=[REDACTED]",
                        **_secret_hash_payload(material, allow_low_entropy_hash=False),
                        "scope": scope,
                        "metadata_path": nested_path,
                    }
                )
                if len(findings) >= max_findings:
                    return findings
            findings.extend(
                _scan_sensitive_key_findings(
                    nested,
                    scope=scope,
                    path=nested_path,
                    max_findings=max_findings - len(findings),
                )
            )
            if len(findings) >= max_findings:
                return findings
    elif isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            findings.extend(
                _scan_sensitive_key_findings(
                    nested,
                    scope=scope,
                    path=f"{path}[{index}]",
                    max_findings=max_findings - len(findings),
                )
            )
            if len(findings) >= max_findings:
                return findings
    return findings


def scan_value_for_secrets(value: Any, *, scope: str, max_findings: int = 20) -> list[dict[str, Any]]:
    """Scan a JSON-like value for secrets and mark findings with a scope."""
    try:
        material = json.dumps(value, ensure_ascii=True, sort_keys=True, default=str)
    except TypeError:
        material = str(value)
    findings: list[dict[str, Any]] = []
    for finding in scan_text_for_secrets(material, max_findings=max_findings):
        scoped = dict(finding)
        scoped["scope"] = scope
        findings.append(scoped)
        if len(findings) >= max_findings:
            return findings
    remaining = max_findings - len(findings)
    if remaining > 0:
        findings.extend(_scan_sensitive_key_findings(value, scope=scope, max_findings=remaining))
    return findings[:max_findings]
