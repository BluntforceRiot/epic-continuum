from __future__ import annotations

import copy
import ctypes
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .units import format_size, parse_size


KB = 1024
MB = 1024**2
GB = 1024**3
TB = 1024**4

PROFILES: dict[str, dict[str, float]] = {
    "conservative": {
        "vram_active": 0.15,
        "ram_hot": 0.04,
        "ram_sqlite": 0.004,
        "ram_kv": 0.08,
        "disk_durable": 0.10,
        "snapshot_of_durable": 0.20,
        "snapshot_of_free": 0.05,
    },
    "balanced": {
        "vram_active": 0.25,
        "ram_hot": 0.0625,
        "ram_sqlite": 0.008,
        "ram_kv": 0.125,
        "disk_durable": 0.20,
        "snapshot_of_durable": 0.25,
        "snapshot_of_free": 0.10,
    },
    "aggressive": {
        "vram_active": 0.33,
        "ram_hot": 0.10,
        "ram_sqlite": 0.015,
        "ram_kv": 0.20,
        "disk_durable": 0.35,
        "snapshot_of_durable": 0.30,
        "snapshot_of_free": 0.15,
    },
}


def entry(num_bytes: int | None, source: str, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "bytes": num_bytes,
        "display": format_size(num_bytes) if num_bytes is not None else None,
        "source": source,
    }
    payload.update(extra)
    return payload


def existing_parent(path: Path) -> Path:
    current = path
    while not current.exists():
        parent = current.parent
        if parent == current:
            return current
        current = parent
    return current


def detect_system_ram_bytes() -> tuple[int | None, str]:
    override = os.getenv("CONTINUUM_SYSTEM_RAM")
    if override:
        return parse_size(override), "CONTINUUM_SYSTEM_RAM"

    system = platform.system().lower()
    if system == "windows":
        class MemoryStatusEx(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MemoryStatusEx()
        status.dwLength = ctypes.sizeof(MemoryStatusEx)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return int(status.ullTotalPhys), "GlobalMemoryStatusEx"

    if system == "linux":
        meminfo = Path("/proc/meminfo")
        if meminfo.exists():
            for line in meminfo.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * KB, "/proc/meminfo"

    if system == "darwin":
        proc = subprocess.run(
            ["sysctl", "-n", "hw.memsize"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip().isdigit():
            return int(proc.stdout.strip()), "sysctl hw.memsize"

    return None, "unknown"


def _parse_memory_tokens(text: str) -> list[int]:
    values: list[int] = []
    for number, unit in re.findall(r"(\d+(?:\.\d+)?)\s*([KMGT]i?B|B)\b", text, flags=re.IGNORECASE):
        normalized = unit.upper().replace("IB", "B")
        try:
            values.append(parse_size(f"{number}{normalized}"))
        except ValueError:
            continue
    for number in re.findall(r"\b(?:VRAM|MEMORY)[^:\n]*\((?:B|BYTES)\)\s*:\s*(\d+)\b", text, flags=re.IGNORECASE):
        try:
            values.append(int(number))
        except ValueError:
            continue
    return values


def _detect_nvidia_vram_bytes() -> tuple[int | None, str]:
    try:
        proc = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return None, "nvidia-smi unavailable"

    if proc.returncode != 0:
        return None, "nvidia-smi failed"

    values: list[int] = []
    for line in proc.stdout.splitlines():
        text = line.strip().split()[0] if line.strip() else ""
        if text.isdigit():
            values.append(int(text) * MB)
    if values:
        return max(values), "nvidia-smi max_gpu_memory"
    return None, "nvidia-smi empty"


def _detect_amd_vram_bytes() -> tuple[int | None, str]:
    for command in (
        ["rocm-smi", "--showmeminfo", "vram"],
        ["rocm-smi", "--showmeminfo", "vram", "--csv"],
    ):
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
        except (FileNotFoundError, subprocess.SubprocessError, OSError):
            continue
        if proc.returncode != 0:
            continue
        values = _parse_memory_tokens(f"{proc.stdout}\n{proc.stderr}")
        if values:
            return max(values), "rocm-smi max_gpu_memory"
    return None, "rocm-smi unavailable"


def _detect_macos_vram_bytes() -> tuple[int | None, str]:
    if platform.system().lower() != "darwin":
        return None, "not macOS"
    try:
        proc = subprocess.run(
            ["system_profiler", "SPDisplaysDataType"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        proc = None
    if proc is not None and proc.returncode == 0:
        vram_lines = "\n".join(line for line in proc.stdout.splitlines() if "VRAM" in line.upper())
        values = _parse_memory_tokens(vram_lines)
        if values:
            return max(values), "system_profiler display_vram"
    machine = platform.machine().lower()
    if machine in {"arm64", "aarch64"}:
        ram, source = detect_system_ram_bytes()
        if ram is not None:
            return ram, f"apple_unified_memory:{source}"
    return None, "macOS VRAM unavailable"


def detect_vram_bytes() -> tuple[int | None, str]:
    override = os.getenv("CONTINUUM_VRAM")
    if override:
        return parse_size(override), "CONTINUUM_VRAM"

    reasons: list[str] = []
    for probe in (_detect_nvidia_vram_bytes, _detect_amd_vram_bytes, _detect_macos_vram_bytes):
        value, source = probe()
        if value is not None:
            return value, source
        reasons.append(source)
    return None, "; ".join(reasons)


def detect_hardware(root: Path) -> dict[str, Any]:
    system_ram, system_ram_source = detect_system_ram_bytes()
    vram, vram_source = detect_vram_bytes()
    drive_path = existing_parent(root)
    usage = shutil.disk_usage(str(drive_path))
    return {
        "vram": entry(vram, vram_source),
        "system_ram": entry(system_ram, system_ram_source),
        "drive": {
            "path": str(drive_path),
            "total_bytes": usage.total,
            "total_display": format_size(usage.total),
            "free_bytes": usage.free,
            "free_display": format_size(usage.free),
            "used_bytes": usage.used,
            "used_display": format_size(usage.used),
            "source": "shutil.disk_usage",
        },
    }


def apply_inventory_overrides(
    inventory: dict[str, Any],
    *,
    vram: str | None = None,
    system_ram: str | None = None,
    drive_free: str | None = None,
) -> dict[str, Any]:
    result = copy.deepcopy(inventory)
    if vram:
        result["vram"] = entry(parse_size(vram), "cli_override")
    if system_ram:
        result["system_ram"] = entry(parse_size(system_ram), "cli_override")
    if drive_free:
        free_bytes = parse_size(drive_free)
        drive = dict(result.get("drive", {}))
        drive["free_bytes"] = free_bytes
        drive["free_display"] = format_size(free_bytes)
        drive["source"] = "cli_override"
        result["drive"] = drive
    return result


def clamp(num_bytes: int, minimum: int, maximum: int) -> int:
    return max(minimum, min(num_bytes, maximum))


def round_down(num_bytes: int, granularity: int) -> int:
    if num_bytes < granularity:
        return granularity
    return (num_bytes // granularity) * granularity


def round_storage(num_bytes: int) -> int:
    if num_bytes >= TB:
        return round_down(num_bytes, 64 * GB)
    if num_bytes >= 64 * GB:
        return round_down(num_bytes, 8 * GB)
    if num_bytes >= GB:
        return round_down(num_bytes, GB)
    return round_down(num_bytes, 128 * MB)


def budget_value(num_bytes: int) -> str:
    for suffix, factor in (("TB", TB), ("GB", GB), ("MB", MB), ("KB", KB)):
        if num_bytes >= factor and num_bytes % factor == 0:
            return f"{num_bytes // factor}{suffix}"
    return str(num_bytes)


def current_budget(config: dict[str, Any], path: tuple[str, ...]) -> int:
    value: Any = config
    for key in path:
        value = value[key]
    return parse_size(value)


def inventory_bytes(inventory: dict[str, Any], key: str) -> int | None:
    value = inventory.get(key, {}).get("bytes")
    return int(value) if value is not None else None


def context_budget_for_vram(vram_bytes: int | None, current_config: dict[str, Any]) -> dict[str, int]:
    if vram_bytes is None:
        return {
            "default_token_budget": int(current_config["context"]["default_token_budget"]),
            "max_token_budget": int(current_config["context"]["max_token_budget"]),
            "reserve_output_tokens": int(current_config["context"]["reserve_output_tokens"]),
        }
    if vram_bytes >= 80 * GB:
        return {"default_token_budget": 16000, "max_token_budget": 512000, "reserve_output_tokens": 4096}
    if vram_bytes >= 32 * GB:
        return {"default_token_budget": 8000, "max_token_budget": 256000, "reserve_output_tokens": 2048}
    if vram_bytes >= 16 * GB:
        return {"default_token_budget": 6000, "max_token_budget": 128000, "reserve_output_tokens": 2048}
    if vram_bytes >= 8 * GB:
        return {"default_token_budget": 3000, "max_token_budget": 64000, "reserve_output_tokens": 1024}
    return {"default_token_budget": 2000, "max_token_budget": 32000, "reserve_output_tokens": 1024}


def recommend_config(
    current_config: dict[str, Any],
    inventory: dict[str, Any],
    profile: str = "balanced",
) -> dict[str, Any]:
    if profile not in PROFILES:
        raise ValueError(f"unknown optimize profile: {profile}")

    factors = PROFILES[profile]
    notes: list[str] = []

    vram_bytes = inventory_bytes(inventory, "vram")
    if vram_bytes is None:
        vram_bytes = current_budget(current_config, ("hardware", "vram", "active_pane_budget")) * 4
        notes.append("VRAM was not detected; kept a conservative estimate derived from the current config.")

    system_ram_bytes = inventory_bytes(inventory, "system_ram")
    if system_ram_bytes is None:
        system_ram_bytes = current_budget(current_config, ("hardware", "system_ram", "hot_cache_budget")) * 16
        notes.append("System RAM was not detected; kept a conservative estimate derived from the current config.")

    drive_free_bytes = inventory.get("drive", {}).get("free_bytes")
    if drive_free_bytes is None:
        drive_free_bytes = current_budget(current_config, ("hardware", "nvme", "durable_store_budget")) * 4
        notes.append("Drive free space was not detected; kept a conservative estimate derived from the current config.")
    drive_free_bytes = int(drive_free_bytes)

    active_pane = round_down(
        clamp(int(vram_bytes * factors["vram_active"]), 512 * MB, 24 * GB),
        512 * MB,
    )
    hot_cache = round_down(
        clamp(int(system_ram_bytes * factors["ram_hot"]), 256 * MB, 32 * GB),
        256 * MB,
    )
    sqlite_cache = round_down(
        clamp(int(system_ram_bytes * factors["ram_sqlite"]), 64 * MB, 4 * GB),
        64 * MB,
    )
    kv_offload = round_down(
        clamp(int(system_ram_bytes * factors["ram_kv"]), 512 * MB, 64 * GB),
        512 * MB,
    )

    durable_min = 1 * GB if drive_free_bytes < 16 * GB else 8 * GB
    snapshot_min = 256 * MB if drive_free_bytes < 16 * GB else 1 * GB
    durable_store = round_storage(
        clamp(int(drive_free_bytes * factors["disk_durable"]), durable_min, 4 * TB)
    )
    snapshot_budget = round_storage(
        clamp(
            int(min(durable_store * factors["snapshot_of_durable"], drive_free_bytes * factors["snapshot_of_free"])),
            snapshot_min,
            2 * TB,
        )
    )
    segment_target = 8 * MB
    if drive_free_bytes >= 512 * GB:
        segment_target = 16 * MB
    if drive_free_bytes >= 2 * TB:
        segment_target = 32 * MB

    return {
        "profile": profile,
        "notes": notes,
        "overrides": {
            "hardware": {
                "vram": {
                    "active_pane_budget": budget_value(active_pane),
                    "notes": current_config["hardware"]["vram"].get("notes", ""),
                },
                "system_ram": {
                    "hot_cache_budget": budget_value(hot_cache),
                    "sqlite_cache_budget": budget_value(sqlite_cache),
                    "kv_offload_budget": budget_value(kv_offload),
                },
                "nvme": {
                    "durable_store_budget": budget_value(durable_store),
                    "snapshot_budget": budget_value(snapshot_budget),
                    "segment_target_size": budget_value(segment_target),
                },
            },
            "context": context_budget_for_vram(inventory_bytes(inventory, "vram"), current_config),
        },
    }
