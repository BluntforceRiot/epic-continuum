from __future__ import annotations

import json
import shutil
from pathlib import Path


OUTPUT_MARKER = ".continuum-benchmark-output"


def sanitize_command(argv: list[str]) -> str:
    """Return a reproducible command line without local output paths."""
    scrubbed: list[str] = []
    skip_next = False
    value_options = {
        "--api-key-env",
        "--fixture",
        "--hermes-command",
        "--live-base-url",
        "--openclaw-command",
        "--output-dir",
    }
    for item in argv:
        if skip_next:
            scrubbed.append("<path>")
            skip_next = False
            continue
        if item in value_options:
            scrubbed.append(item)
            skip_next = True
            continue
        if any(item.startswith(f"{option}=") for option in value_options):
            option = item.split("=", 1)[0]
            scrubbed.append(f"{option}=<path>")
            continue
        scrubbed.append(Path(item).name if item.endswith(".py") else item)
    return " ".join(scrubbed)


def prepare_output_dir(output_dir: Path, *, benchmark: str) -> Path:
    """Create a benchmark output directory without deleting arbitrary user data."""
    resolved = output_dir.resolve()
    dangerous_names = {"", "/", ".", ".."}
    if str(resolved) in dangerous_names:
        raise ValueError(f"refusing unsafe benchmark output directory: {resolved}")
    if resolved.exists():
        children = list(resolved.iterdir())
        marker = resolved / OUTPUT_MARKER
        if children and not marker.is_file():
            raise ValueError(
                "refusing to delete an existing unmarked output directory; "
                f"choose a new path or remove it yourself: {resolved}"
            )
        shutil.rmtree(resolved)
    resolved.mkdir(parents=True, exist_ok=False)
    (resolved / OUTPUT_MARKER).write_text(
        json.dumps({"benchmark": benchmark, "purpose": "epic-continuum-benchmark-output"}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return resolved
