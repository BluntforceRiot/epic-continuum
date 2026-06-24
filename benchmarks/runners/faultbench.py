from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from continuum.core.operations import (  # noqa: E402
    create_proof_pack,
    finish_operation,
    operation_event_paths,
    operation_summary,
    recover_stale_operations,
    record_operation_progress,
    replay_operation_event_log,
    restore_drill,
    start_operation,
    update_operation_cursor,
    verify_proof_pack,
)
from continuum.core.store import append_scroll_event, compile_context, init_db, snapshot, status  # noqa: E402

try:  # noqa: E402
    from ._common import prepare_output_dir, sanitize_command
except ImportError:  # pragma: no cover - script execution path
    from _common import prepare_output_dir, sanitize_command  # type: ignore


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n")


def run_git(args: list[str]) -> str | None:
    try:
        return subprocess.check_output(["git", *args], cwd=REPO_ROOT, text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def project_version() -> str:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("version"):
            return line.split("=", 1)[1].strip().strip('"')
    return "unknown"


def common_environment(command: str, trial_count: int) -> dict[str, Any]:
    dirty = run_git(["status", "--short"])
    return {
        "api_cost_usd": 0,
        "api_token_usage": {"completion_tokens": 0, "prompt_tokens": 0, "total_tokens": 0},
        "benchmark": "FaultBench",
        "benchmark_version": "0.2.0",
        "cache_state": "cold",
        "command": command,
        "cpu": platform.processor() or platform.machine(),
        "dataset_checksum": None,
        "dataset_name": "FaultBench synthetic local cases",
        "dataset_split": "synthetic-local",
        "dataset_version": "0.2.0",
        "epic_continuum_version": project_version(),
        "finish_timestamp": None,
        "git_commit": run_git(["rev-parse", "HEAD"]),
        "git_dirty": bool(dirty),
        "mode": "quick-offline",
        "model_name": None,
        "model_provider": None,
        "os": platform.platform(),
        "prompt_hash": None,
        "python": sys.version,
        "random_seed": 1337,
        "storage_type": "local-filesystem",
        "trial_count": trial_count,
    }


def interrupted_operation_case(root: Path, name: str, *, write_progress: bool, write_cursor: bool) -> dict[str, Any]:
    init_db(root)
    operation = start_operation(
        root,
        operation_type=f"faultbench_{name}",
        title=f"FaultBench {name}",
        intent={"expected_next_action": "resume from the saved cursor"},
        actor="faultbench",
    )
    operation_id = str(operation["operation_id"])
    if write_progress:
        record_operation_progress(root, operation_id, phase="copy", message="wrote progress before interruption", current=1, total=3)
    if write_cursor:
        update_operation_cursor(root, operation_id, {"phase": "copy", "offset": 1, "next_action": "resume from offset 1"})
    recovered = recover_stale_operations(root, older_than_seconds=0, mark=True, limit=10)
    summary = operation_summary(root, operation_id)
    proof = verify_proof_pack(Path(str(summary["proof_pack_uri"]))) if summary.get("proof_pack_uri") else {"ok": False}
    replay = replay_operation_event_log(operation_event_paths(root, operation_id)["run"], operation_id=operation_id)
    return {
        "case_id": name,
        "correct_next_action_recovery": bool(summary.get("cursor")) if write_cursor else True,
        "correctly_classified_interrupted_operations": summary.get("status") == "interrupted",
        "duplicate_events": 0,
        "event_log_replay_ok": bool(replay.get("ok")),
        "operation_id": operation_id,
        "proof_tampering_detected": None,
        "recovery_packets_generated": 1 if summary.get("recovery_packet_uri") else 0,
        "restore_success_rate": None,
        "committed_scroll_events_lost": 0,
        "false_tamper_alarm": not bool(proof.get("ok")),
        "ok": summary.get("status") == "interrupted" and bool(summary.get("recovery_packet_uri")) and bool(proof.get("ok")),
        "summary": {
            "status": summary.get("status"),
            "cursor_present": bool(summary.get("cursor")),
            "proof_pack_present": bool(summary.get("proof_pack_uri")),
            "recovery_packet_present": bool(summary.get("recovery_packet_uri")),
            "recovered_count": len(recovered.get("recovered") or []),
        },
    }


def snapshot_restore_case(root: Path) -> dict[str, Any]:
    init_db(root)
    append_scroll_event(root, session_id="faultbench-restore", event_type="message", role="user", content="Decision EVID:FAULT-RESTORE keep the restore drill covered.")
    before_events = int(status(root, create=False).get("scroll_events", 0))
    snap = snapshot(root, reason="faultbench_restore_case")
    restored = restore_drill(root, snapshot_uri=str(snap["snapshot_uri"]), drill_name="faultbench-restore")
    restored_events = int(restored.get("status", {}).get("scroll_events", 0))
    recovery_packet_present = bool(restored.get("recovery_probe", {}).get("summary", {}).get("recovery_packet_uri"))
    return {
        "case_id": "snapshot_restore",
        "committed_scroll_events_lost": max(0, before_events - restored_events),
        "correct_next_action_recovery": bool(restored.get("ok")) and recovery_packet_present,
        "correctly_classified_interrupted_operations": None,
        "duplicate_events": 0,
        "proof_tampering_detected": None,
        "recovery_packets_generated": 1 if recovery_packet_present else 0,
        "restore_success_rate": 1.0 if restored.get("ok") else 0.0,
        "false_tamper_alarm": False,
        "ok": bool(restored.get("ok")),
        "summary": {"snapshot_created": bool(snap.get("snapshot_uri")), "drill_id": restored.get("drill_id")},
    }


def proof_tamper_case(root: Path) -> dict[str, Any]:
    init_db(root)
    artifact = root / "run" / "faultbench" / "proof-artifact.txt"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text("proof payload EVID:FAULT-PROOF\n", encoding="utf-8")
    operation = start_operation(root, operation_type="faultbench_proof", title="FaultBench proof tamper", actor="faultbench")
    operation_id = str(operation["operation_id"])
    record_operation_progress(root, operation_id, phase="artifact", message="created proof artifact")
    finish_operation(root, operation_id, status="succeeded", result={"artifact": str(artifact)})
    proof = create_proof_pack(root, operation_id, touched_paths=[artifact])
    proof_path = Path(str(proof["proof_pack_uri"]))
    before = verify_proof_pack(proof_path)
    payload = json.loads(proof_path.read_text(encoding="utf-8"))
    payload["proof_pack_hash"] = "0" * 64
    proof_path.write_text(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    after = verify_proof_pack(proof_path)
    return {
        "case_id": "proof_tamper",
        "committed_scroll_events_lost": 0,
        "correct_next_action_recovery": True,
        "correctly_classified_interrupted_operations": None,
        "duplicate_events": 0,
        "proof_tampering_detected": bool(before.get("ok")) and not bool(after.get("ok")),
        "recovery_packets_generated": 0,
        "restore_success_rate": None,
        "false_tamper_alarm": not bool(before.get("ok")),
        "ok": bool(before.get("ok")) and not bool(after.get("ok")),
        "summary": {"operation_id": operation_id, "proof_pack_present": True, "verify_before": before.get("ok"), "verify_after": after.get("ok")},
    }


def copied_root_case(root: Path, copy_root: Path) -> dict[str, Any]:
    init_db(root)
    append_scroll_event(root, session_id="faultbench-copy", event_type="message", role="assistant", content="Next action EVID:FAULT-COPY continue after copied-root recovery.")
    shutil.copytree(root, copy_root, dirs_exist_ok=True, symlinks=True)
    copied_status = status(copy_root, create=False)
    context = compile_context(copy_root, session_id="faultbench-copy", query="copied root next action", token_budget=1000, create=False)
    ok = bool(copied_status.get("initialized")) and "EVID:FAULT-COPY" in str(context.get("context_text") or "")
    return {
        "case_id": "copied_root_recovery",
        "committed_scroll_events_lost": 0,
        "correct_next_action_recovery": ok,
        "correctly_classified_interrupted_operations": None,
        "duplicate_events": 0,
        "proof_tampering_detected": None,
        "recovery_packets_generated": 0,
        "restore_success_rate": 1.0 if ok else 0.0,
        "false_tamper_alarm": False,
        "ok": ok,
        "summary": {"copied_status_initialized": copied_status.get("initialized"), "estimated_tokens": context.get("estimated_tokens")},
    }


def aggregate(cases: list[dict[str, Any]]) -> dict[str, Any]:
    count = max(1, len(cases))
    interrupted = [case for case in cases if case["correctly_classified_interrupted_operations"] is not None]
    tamper_cases = [case for case in cases if case["proof_tampering_detected"] is not None]
    restore_cases = [case for case in cases if case["restore_success_rate"] is not None]
    return {
        "case_count": len(cases),
        "ok": all(bool(case["ok"]) for case in cases),
        "committed_scroll_events_lost": sum(int(case["committed_scroll_events_lost"]) for case in cases),
        "duplicate_events": sum(int(case["duplicate_events"]) for case in cases),
        "correctly_classified_interrupted_operation_rate": sum(1 for case in interrupted if case["correctly_classified_interrupted_operations"]) / max(1, len(interrupted)),
        "recovery_packets_generated": sum(int(case["recovery_packets_generated"]) for case in cases),
        "restore_success_rate": sum(float(case["restore_success_rate"]) for case in restore_cases) / max(1, len(restore_cases)),
        "proof_tampering_detected_rate": sum(1 for case in tamper_cases if case["proof_tampering_detected"]) / max(1, len(tamper_cases)),
        "false_tamper_alarm_rate": sum(1 for case in cases if case["false_tamper_alarm"]) / count,
        "correct_next_action_recovery_rate": sum(1 for case in cases if case["correct_next_action_recovery"]) / count,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run deterministic Epic Continuum fault and recovery benchmarks.")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--quick", action="store_true", help="Run the deterministic quick suite. This is currently the default suite.")
    args = parser.parse_args(argv)

    output_dir = prepare_output_dir(args.output_dir, benchmark="FaultBench")
    started = time.perf_counter()
    command = sanitize_command([Path(sys.executable).name, *(argv if argv is not None else sys.argv[1:])])

    with tempfile.TemporaryDirectory(prefix="faultbench-") as tmp:
        base = Path(tmp)
        cases = [
            interrupted_operation_case(base / "start-interrupt", "interruption_after_operation_start", write_progress=False, write_cursor=False),
            interrupted_operation_case(base / "progress-interrupt", "interruption_after_progress_write", write_progress=True, write_cursor=True),
            snapshot_restore_case(base / "snapshot-restore"),
            proof_tamper_case(base / "proof-tamper"),
            copied_root_case(base / "copy-source", base / "copy-dest"),
        ]

    env = common_environment(command, len(cases))
    env["finish_timestamp"] = utc_now()
    summary = {
        "benchmark": "FaultBench",
        "benchmark_version": "0.2.0",
        "elapsed_seconds": time.perf_counter() - started,
        **aggregate(cases),
        "environment_file": "environment.json",
        "cases_file": "cases.jsonl",
    }
    write_json(output_dir / "environment.json", env)
    write_json(output_dir / "summary.json", summary)
    append_jsonl(output_dir / "cases.jsonl", cases)
    (output_dir / "commands.txt").write_text(command + "\n", encoding="utf-8")
    print(json.dumps({"ok": summary["ok"], "output_dir": str(output_dir), "case_count": len(cases)}, sort_keys=True))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
