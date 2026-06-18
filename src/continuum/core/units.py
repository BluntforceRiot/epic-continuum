from __future__ import annotations

import re


SIZE_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([KMGT]?B)?\s*$", re.IGNORECASE)
UNITS = {
    None: 1,
    "B": 1,
    "KB": 1024,
    "MB": 1024**2,
    "GB": 1024**3,
    "TB": 1024**4,
}


def parse_size(value: str | int | float) -> int:
    """Parse byte sizes such as 512MB, 4GB, or 1024."""
    if isinstance(value, (int, float)):
        if value < 0:
            raise ValueError("size must be non-negative")
        return int(value)
    match = SIZE_RE.match(value)
    if not match:
        raise ValueError(f"invalid size: {value!r}")
    number = float(match.group(1))
    unit = match.group(2).upper() if match.group(2) else None
    if unit not in UNITS:
        raise ValueError(f"unsupported size unit: {unit}")
    return int(number * UNITS[unit])


def format_size(num_bytes: int) -> str:
    for unit, factor in (("TB", 1024**4), ("GB", 1024**3), ("MB", 1024**2), ("KB", 1024)):
        if num_bytes >= factor:
            return f"{num_bytes / factor:.2f}{unit}"
    return f"{num_bytes}B"
