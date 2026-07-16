from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

from .config import resolve_root_config_path


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
]


def load_ignore_patterns(root: Path, *, ignore_file_name: str = ".continuumignore") -> list[str]:
    patterns = list(DEFAULT_IGNORE_PATTERNS)
    ignore_path = resolve_root_config_path(root, ignore_file_name, field="security.ignore_file")
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


TYPE_HINT_VALUE_RE = re.compile(
    r"^(?:"
    r"(?:str|int|float|bool|bytes|Path|Any|None)"
    r"(?:\s*\|\s*(?:str|int|float|bool|bytes|Path|Any|None))*"
    r"|(?:dict|list|tuple|set)\[[^\]]+\]"
    r")$"
)
CODE_REFERENCE_VALUE_RE = re.compile(
    r"^(?:"
    r"(?:args|self|cls|config|settings|model|os|Path|json|str|int|bool|dict|list)\.[A-Za-z_][A-Za-z0-9_.]*(?:\([^)]*\))?"
    r"|[A-Za-z_][A-Za-z0-9_]*\([^)]*\)"
    r")$"
)
NONSECRET_ASSIGNMENT_VALUES = {
    "argument",
    "configured",
    "default",
    "dummy",
    "env",
    "example",
    "false",
    "local",
    "not",
    "none",
    "none_or_nonsecret",
    "null",
    "placeholder",
    "redacted",
    "true",
}


def _is_nonsecret_assignment_value(value: str) -> bool:
    raw = value.strip()
    normalized = raw.strip("'\"").casefold()
    if not normalized or REDACTED_VALUE_RE.fullmatch(normalized):
        return True
    if normalized in NONSECRET_ASSIGNMENT_VALUES:
        return True
    if normalized.startswith(("env:", "your-", "your_", "${", "$env:", "os.environ[")):
        return True
    if normalized.startswith(("f\"env:", "f'env:", "not ")):
        return True
    if normalized.startswith(("args.", "match.", "os.environ", "os.getenv", "getenv(", "bool(", "str(", "int(", "float(", "Path(", "json.dumps(", "yaml_string(")):
        return True
    if " if " in normalized and " else " in normalized:
        return True
    if raw.startswith(("f\"", "f'")) and ("{" in raw or "}" in raw):
        return True
    if raw.startswith("{") and raw.endswith("}") and "(" in raw:
        return True
    if TYPE_HINT_VALUE_RE.fullmatch(value.strip()):
        return True
    if CODE_REFERENCE_VALUE_RE.fullmatch(value.strip()):
        return True
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\s*=\s*['\"]?(?:none|null|false|true)['\"]?", raw, re.IGNORECASE):
        return True
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\[\], ]*(?:\s*\|\s*[A-Za-z_][A-Za-z0-9_\[\], ]*)+\s*=\s*(?:None|null|False|True|0|1)", raw):
        return True
    return False


def _assignment_finding_type(value: str) -> str:
    return "secret_assignment" if len(value) >= 20 else "sensitive_key_assignment"


def _sensitive_assignment_line(line: str) -> tuple[str, str] | None:
    stripped_line = line.strip()
    if stripped_line.startswith(("def ", "class ")):
        return None
    match = SENSITIVE_ASSIGNMENT_LINE_RE.match(line)
    if not match:
        return None
    key = match.group(1)
    raw_value = match.group(2)
    value = _normalized_assignment_value(raw_value)
    if value == key:
        return None
    if not value or _is_redacted_value_placeholder(value) or _is_nonsecret_assignment_value(value):
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
    if line.strip().startswith(("def ", "class ")):
        return []
    assignments: list[tuple[re.Match[str], str, str]] = []
    position = 0
    while position < len(line):
        match = EMBEDDED_ASSIGNMENT_RE.search(line, position)
        if not match:
            break
        position = match.start() + 1
        key_start = match.start("key")
        if key_start > 0 and (line[key_start - 1].isalnum() or line[key_start - 1] == "_"):
            continue
        key = match.group("key")
        value = _normalized_assignment_value(match.group("value"))
        if value == key:
            continue
        if not value or _is_redacted_value_placeholder(value) or _is_nonsecret_assignment_value(value) or not _looks_sensitive_key(key):
            continue
        assignments.append((match, key, value))
        position = match.end()
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


_ERROR_ABSOLUTE_PATH_START_RE = re.compile(
    r"(?i)(?<![A-Z0-9._-])(?:"
    r"\\\\[?.]\\(?:UNC\\)?"
    r"|\\\\"
    r"|\\(?:Device\\|SystemRoot\\|\?\?\\|DosDevices\\)"
    r"|(?P<windows_rooted>\\(?=[^\\/\r\n]+[\\/][^\\/\r\n]))"
    r"|[A-Z]:[\\/]"
    r"|(?P<posix_root>/)"
    r")"
)
_COMPACT_DIAGNOSTIC_FIELD_RE_FRAGMENT = r"\s*[A-Z_][A-Z0-9_.-]*\s*="
_ERROR_AUTHORITY_URI_RE = re.compile(
    r"(?i)\b(?:https?|wss?|ftp)://"
    r"(?:\[(?:[0-9A-F:.]+(?:%25(?:[A-Z0-9._~-]|%[0-9A-F]{2})+)?"
    r"|v[0-9A-F]+\.[A-Z0-9._~!$&'()*+,;=:-]+)\]"
    r"|[A-Z0-9](?:[A-Z0-9._~-]*[A-Z0-9])?)"
    r"(?::[0-9]{1,5})?"
    r"(?:[/?#](?:[^\s\"<>\\';,|]"
    rf"|'(?![\s]|$|[;,|]{_COMPACT_DIAGNOSTIC_FIELD_RE_FRAGMENT})"
    rf"|[;,|](?!{_COMPACT_DIAGNOSTIC_FIELD_RE_FRAGMENT}))*)?"
)


_WINDOWS_ESCAPE_COMPONENT_RE = re.compile(
    r"(?i)^(?:[0-9abdefgknpqrstuvwxyz](?:[+*?]|\{[0-9]+(?:,[0-9]*)?\})?"
    r"|[+.^$(){}\[\]|-])$"
)
_WINDOWS_COMPONENT_INVALID_CHARACTERS = frozenset('<>:"|?*')
_POSIX_PATH_COMPONENT_START_EXCLUSIONS = frozenset(
    [chr(0), *"/\\\\\"'`=+*%<>|&;,:)]}"]
)


def _is_absolute_path_token_boundary(text: str, start: int) -> bool:
    if start <= 0:
        return True
    previous = text[start - 1]
    return previous.isspace() or previous in "\"'([{=:;,>"


def _looks_like_explicit_windows_rooted_path(text: str, start: int) -> bool:
    """Discriminate a multi-component rooted path from regex/escape prose."""

    separators = [
        position
        for position in (text.find("\\", start + 1), text.find("/", start + 1))
        if position >= 0
    ]
    first_separator = min(separators, default=-1)
    if first_separator < 0:
        return False
    later_separators = [
        position
        for position in (
            text.find("\\", first_separator + 1),
            text.find("/", first_separator + 1),
        )
        if position >= 0
    ]
    second_separator = min(later_separators, default=-1)
    line_end = len(text)
    for delimiter in ("\r", "\n", '"', "'"):
        position = text.find(delimiter, first_separator + 1)
        if position >= 0:
            line_end = min(line_end, position)
    second_end = min(second_separator if second_separator >= 0 else line_end, line_end)
    raw_components = (
        text[start + 1 : first_separator],
        text[first_separator + 1 : second_end],
    )
    components: list[str] = []
    for raw_component in raw_components:
        # A component ending in a space or period is not a normal Win32 path
        # component and commonly indicates prose between two escape tokens.
        if raw_component != raw_component.rstrip(" ."):
            return False
        component = raw_component.strip()
        if (
            not component
            or any(ord(character) < 32 for character in component)
            or any(character in _WINDOWS_COMPONENT_INVALID_CHARACTERS for character in component)
        ):
            return False
        components.append(component)

    # ``\d\s`` and similar pairs are diagnostic escape notation.  A real path
    # with one-character leading components is ambiguous and is deliberately
    # left unchanged; namespace-qualified forms remain unambiguous.
    if all(_WINDOWS_ESCAPE_COMPONENT_RE.fullmatch(component) for component in components):
        return False
    return True


def _looks_like_explicit_posix_absolute_path(
    text: str,
    start: int,
    *,
    allow_ambiguous_component_start: bool,
) -> bool:
    """Require a credible component after a diagnostic POSIX root slash."""

    component_start = start
    while component_start < len(text) and text[component_start] == "/":
        component_start += 1
    if component_start >= len(text):
        return False
    first_component_character = text[component_start]
    if (
        not first_component_character.isspace()
        and first_component_character not in _POSIX_PATH_COMPONENT_START_EXCLUSIONS
    ):
        return True
    if (
        first_component_character == "%"
        and component_start + 2 < len(text)
        and all(
            character in "0123456789abcdefABCDEF"
            for character in text[component_start + 1 : component_start + 3]
        )
    ):
        return True
    follows_file_uri_scheme = text[max(0, start - 5) : start].casefold() == "file:"
    if not allow_ambiguous_component_start or (start != 0 and not follows_file_uri_scheme):
        return False

    # Inside a quoted diagnostic, a second separator makes an otherwise
    # punctuation- or whitespace-led first component structurally path-like.
    # This covers valid POSIX names such as ``/+private/secret`` and
    # ``/ Private Folder/secret`` without promoting standalone operators.
    next_separator = text.find("/", component_start + 1)
    if next_separator < 0:
        return False
    first_component = text[component_start:next_separator]
    return bool(first_component.strip()) and not any(
        character in {"\x00", "\r", "\n"} for character in first_component
    )


def _error_uri_spans(text: str) -> list[tuple[int, int]]:
    """Return authority-qualified public URI spans that are not local paths."""
    return [match.span() for match in _ERROR_AUTHORITY_URI_RE.finditer(text)]


def _first_unprotected_absolute_path(
    text: str,
    *,
    allow_ambiguous_posix_components: bool = False,
) -> int | None:
    uri_spans = _error_uri_spans(text)
    uri_index = 0
    for match in _ERROR_ABSOLUTE_PATH_START_RE.finditer(text):
        position = match.start()
        if not _is_absolute_path_token_boundary(text, position):
            continue
        while uri_index < len(uri_spans) and uri_spans[uri_index][1] <= position:
            uri_index += 1
        if (
            uri_index < len(uri_spans)
            and uri_spans[uri_index][0] <= position < uri_spans[uri_index][1]
        ):
            continue
        if match.lastgroup == "windows_rooted" and not _looks_like_explicit_windows_rooted_path(
            text,
            position,
        ):
            continue
        if match.lastgroup == "posix_root" and not _looks_like_explicit_posix_absolute_path(
            text,
            position,
            allow_ambiguous_component_start=allow_ambiguous_posix_components,
        ):
            continue
        return position
    return None


def _redacted_error_path_token(value: str, *, precise: bool) -> str:
    if not precise:
        return "<redacted-path>"
    name = re.split(r"[\\/]", value)[-1]
    if not name:
        return "<redacted-path>"
    safe_name = redact_text_secrets(name)
    if (
        not safe_name
        or any(separator in safe_name for separator in ("/", "\\"))
        or any(character in safe_name for character in ("\r", "\n", "'", '"', "<", ">"))
    ):
        return "<redacted-path>"
    return f"<redacted-path:{safe_name}>"


def _find_closing_error_quote(
    text: str,
    opening: int,
    *,
    protected_spans: list[tuple[int, int]],
) -> tuple[int | None, bool]:
    """Find an unescaped matching quote in linear time."""
    quote = text[opening]
    backslash_run = 0
    saw_escaped_delimiter = False
    span_index = 0
    for index in range(opening + 1, len(text)):
        while span_index < len(protected_spans) and protected_spans[span_index][1] <= index:
            span_index += 1
        if (
            span_index < len(protected_spans)
            and protected_spans[span_index][0] <= index < protected_spans[span_index][1]
        ):
            backslash_run = 0
            continue
        character = text[index]
        if character == "\\":
            backslash_run += 1
            continue
        if character == quote:
            if backslash_run % 2:
                saw_escaped_delimiter = True
            else:
                return index, saw_escaped_delimiter
        backslash_run = 0
    return None, saw_escaped_delimiter


def _redact_quoted_error_paths(line: str) -> str:
    pieces: list[str] = []
    cursor = 0
    index = 0
    uri_spans = _error_uri_spans(line)
    uri_index = 0
    while index < len(line):
        while uri_index < len(uri_spans) and uri_spans[uri_index][1] <= index:
            uri_index += 1
        if (
            uri_index < len(uri_spans)
            and uri_spans[uri_index][0] <= index < uri_spans[uri_index][1]
        ):
            index = uri_spans[uri_index][1]
            continue
        if line[index] not in {"'", '"'}:
            index += 1
            continue
        closing, escaped_delimiter = _find_closing_error_quote(
            line,
            index,
            protected_spans=uri_spans,
        )
        if closing is None:
            candidate = line[index + 1 :]
            path_start = _first_unprotected_absolute_path(
                candidate,
                allow_ambiguous_posix_components=True,
            )
            if path_start is not None:
                pieces.append(line[cursor : index + 1 + path_start])
                pieces.append("<redacted-path>")
                return "".join(pieces)
            break
        candidate = line[index + 1 : closing]
        path_start = _first_unprotected_absolute_path(
            candidate,
            allow_ambiguous_posix_components=True,
        )
        if path_start is not None:
            pieces.append(line[cursor : index + 1])
            pieces.append(
                _redacted_error_path_token(
                    candidate,
                    precise=path_start == 0 and not escaped_delimiter,
                )
            )
            pieces.append(line[closing])
            cursor = closing + 1
        index = closing + 1
    pieces.append(line[cursor:])
    return "".join(pieces)


def redact_error_message_paths(message: str) -> str:
    """Redact local absolute paths in an error without corrupting public URIs.

    Quoted spans use escape-aware delimiters. An unquoted path containing
    whitespace has no trustworthy end boundary, so its line tail is removed
    conservatively. Runtime is linear in the rendered error size.
    """
    secret_redacted = redact_text_secrets(str(message))
    output: list[str] = []
    for raw_line in secret_redacted.split("\n"):
        line = _redact_quoted_error_paths(raw_line)
        path_start = _first_unprotected_absolute_path(line)
        if path_start is None:
            output.append(line)
            continue
        candidate = line[path_start:]
        if any(character.isspace() for character in candidate):
            output.append(line[:path_start] + "<redacted-path>")
            continue
        path_text = candidate.rstrip(".,;:)")
        suffix = candidate[len(path_text) :]
        output.append(
            line[:path_start]
            + _redacted_error_path_token(path_text, precise=True)
            + suffix
        )
    return "\n".join(output)


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
    separated = str(key).strip()
    separated = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", separated)
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", separated)
    lowered = separated.casefold()
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


def scan_text_for_secrets(text: str, *, max_findings: int | None = 20) -> list[dict[str, Any]]:
    limit = int(max_findings) if max_findings and int(max_findings) > 0 else None
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
                if limit is not None and len(findings) >= limit:
                    return findings
        if not line_had_finding:
            assignment = _sensitive_assignment_line(line)
            if assignment:
                key, value = assignment
                findings.append(
                    {
                        "type": _assignment_finding_type(value),
                        "line": line_number,
                        "snippet": _redact_sensitive_assignment_line(line).strip()[:240],
                        **_secret_hash_payload(value, allow_low_entropy_hash=False),
                        "metadata_path": f"$.{_safe_metadata_path_part(key)}",
                    }
                )
                if limit is not None and len(findings) >= limit:
                    return findings
                line_had_finding = True
        if not line_had_finding:
            for _match, key, value in _embedded_sensitive_assignments(line):
                findings.append(
                    {
                        "type": _assignment_finding_type(value),
                        "line": line_number,
                        "snippet": _redact_embedded_sensitive_assignments(line).strip()[:240],
                        **_secret_hash_payload(value, allow_low_entropy_hash=False),
                        "metadata_path": f"$.{_safe_metadata_path_part(key)}",
                    }
                )
                if limit is not None and len(findings) >= limit:
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
