from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable

from .core.config import config_path, load_config, optimize_config, write_default_config
from .core.bundle import pack_root, verify_root_bundle
from .core.evals import run_memory_quality_evals
from .core.hardware import PROFILES
from .core.mempalace_import import default_mempalace_path, import_mempalace, progress_bar
from .core.operations import (
    OperationGuard,
    doctor,
    list_operations,
    operation_summary,
    recover_stale_operations,
    recovery_drill,
    repair_permissions,
    replay_operation_event_log,
    restore_drill,
    verify_root,
    verify_proof_pack,
)
from .core.store import (
    append_scroll_event,
    audit,
    audit_search_index,
    audit_secrets,
    audit_secrets_sarif,
    compile_context,
    ingest_file,
    init_db,
    recover_thread,
    rebuild_search_index,
    redact_legacy_secrets,
    roll_scroll_segment,
    search_memory,
    source_file_reference,
    snapshot,
    status,
)
from .core.workers import (
    apply_storage_tiering,
    decay_graph_routes,
    detect_conflicts,
    memory_health,
    prune_memory,
    run_worker_pass,
    serve_workers,
)
from .integrations.hermes_adapter import install_hermes_adapter


def emit(value: object) -> None:
    print(json.dumps(value, ensure_ascii=True, sort_keys=True))


def guarded_result(
    root: Path,
    *,
    operation_type: str,
    title: str,
    intent: dict[str, Any] | None = None,
    snapshot_policy: str = "none",
    snapshot_reason: str | None = None,
    touched_paths: list[Path | str] | None = None,
    result_touched_paths: Callable[[Any], list[Path | str]] | None = None,
    action: Callable[[OperationGuard], Any],
    actor: str | None = None,
) -> Any:
    with OperationGuard(
        root,
        operation_type=operation_type,
        title=title,
        intent=intent,
        actor=actor or f"cli:{operation_type}",
        snapshot_policy=snapshot_policy,
        snapshot_reason=snapshot_reason,
        touched_paths=touched_paths,
    ) as operation:
        result = action(operation)
        extra_paths = result_touched_paths(result) if result_touched_paths else []
        operation.succeed(result if isinstance(result, dict) else {"result": result}, touched_paths=extra_paths)
        return operation.wrap_result(result)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Epic Continuum persistent-memory substrate")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize an Epic Continuum root")
    p_init.add_argument("--root", required=True)

    p_status = sub.add_parser("status", help="Show root status")
    p_status.add_argument("--root", required=True)

    p_config = sub.add_parser("config", help="Create/show root config")
    p_config.add_argument("--root", required=True)

    p_optimize = sub.add_parser("optimize-config", help="Recommend or write hardware-aware config budgets")
    p_optimize.add_argument("--root", required=True)
    p_optimize.add_argument("--profile", choices=sorted(PROFILES), default="balanced")
    p_optimize.add_argument("--write", action="store_true", help="Write recommendations to continuum.config.json")
    p_optimize.add_argument("--vram", help="Override detected GPU VRAM, for example 32GB")
    p_optimize.add_argument("--system-ram", help="Override detected system RAM, for example 128GB")
    p_optimize.add_argument("--drive-free", help="Override detected free drive space, for example 2TB")

    p_append = sub.add_parser("append-event", help="Append an event to the Scroll")
    p_append.add_argument("--root", required=True)
    p_append.add_argument("--session-id", required=True)
    p_append.add_argument("--type", default="message")
    p_append.add_argument("--role", default="user")
    p_append.add_argument("--content", required=True)

    p_roll = sub.add_parser("roll-segment", help="Roll Scroll events into a Card")
    p_roll.add_argument("--root", required=True)
    p_roll.add_argument("--session-id", required=True)
    p_roll.add_argument("--start-seq", type=int, required=True)
    p_roll.add_argument("--end-seq", type=int, required=True)

    p_ingest = sub.add_parser("ingest-file", help="Ingest a file as a Library book")
    p_ingest.add_argument("--root", required=True)
    p_ingest.add_argument("--path", required=True)
    p_ingest.add_argument("--title")
    p_ingest.add_argument("--storage-tier", default="hot", choices=["hot", "warm", "cold", "vault"])

    p_context = sub.add_parser("compile-context", help="Build a Looking Glass context packet")
    p_context.add_argument("--root", required=True)
    p_context.add_argument("--session-id", required=True)
    p_context.add_argument("--token-budget", type=int, default=0)
    p_context.add_argument("--query")
    p_context.add_argument("--card-scope", choices=["session", "global", "session_then_global", "project"])
    p_context.add_argument("--project-id")

    p_search = sub.add_parser("search", help="Search Library chunks with FTS5 or LIKE fallback")
    p_search.add_argument("--root", required=True)
    p_search.add_argument("--query", required=True)
    p_search.add_argument("--limit", type=int, default=10)

    p_audit_search = sub.add_parser("audit-search-index", help="Audit Library chunk FTS index consistency")
    p_audit_search.add_argument("--root", required=True)

    p_rebuild_search = sub.add_parser("rebuild-search-index", help="Rebuild Library chunk FTS index from chunks")
    p_rebuild_search.add_argument("--root", required=True)

    p_workers = sub.add_parser("run-workers", help="Run one Scribe/Librarian/Archivist worker pass")
    p_workers.add_argument("--root", required=True)
    p_workers.add_argument("--role", action="append", choices=["scribe", "librarian", "archivist"])
    p_workers.add_argument("--limit", type=int, default=50)
    p_workers.add_argument("--no-maintenance", action="store_true")

    p_serve = sub.add_parser("serve", help="Run background Scribe/Librarian/Archivist worker service")
    p_serve.add_argument("--root", required=True)
    p_serve.add_argument("--role", action="append", choices=["scribe", "librarian", "archivist"])
    p_serve.add_argument("--passes", type=int, default=0, help="Number of passes before exit; 0 runs until stopped")
    p_serve.add_argument("--interval-seconds", type=float, default=5.0)

    p_health = sub.add_parser("memory-health", help="Report Epic Continuum capture, queue, storage, and learning health")
    p_health.add_argument("--root", required=True)

    p_tier = sub.add_parser("tier-storage", help="Apply Archivist storage tiering policy")
    p_tier.add_argument("--root", required=True)
    p_tier.add_argument("--dry-run", action="store_true")
    p_tier.add_argument("--limit", type=int, default=100)

    p_prune = sub.add_parser("prune-memory", help="Archive, summarize-only, or prune cards by topic")
    p_prune.add_argument("--root", required=True)
    p_prune.add_argument("--topic")
    p_prune.add_argument("--action", choices=["archive", "summarize_only", "forget"], default="archive")
    p_prune.add_argument("--dry-run", action="store_true")
    p_prune.add_argument("--all", action="store_true", help="Allow pruning across all topics when --topic is omitted")
    p_prune.add_argument("--limit", type=int, default=100)

    p_conflicts = sub.add_parser("detect-conflicts", help="Detect likely conflicting cards")
    p_conflicts.add_argument("--root", required=True)
    p_conflicts.add_argument("--card-id")
    p_conflicts.add_argument("--limit", type=int, default=50)

    p_decay = sub.add_parser("decay-routes", help="Apply Librarian route decay and synaptic pruning")
    p_decay.add_argument("--root", required=True)
    p_decay.add_argument("--limit", type=int, default=200)
    p_decay.add_argument("--prune-threshold", type=int, default=3)

    p_evals = sub.add_parser("run-evals", help="Run deterministic memory quality evals")
    p_evals.add_argument("--root", required=True)
    p_evals.add_argument("--keep-artifacts", action="store_true")

    p_recover = sub.add_parser("recover-thread", help="Build a crash-recovery packet for a session")
    p_recover.add_argument("--root", required=True)
    p_recover.add_argument("--session-id", required=True)
    p_recover.add_argument("--query")
    p_recover.add_argument("--token-budget", type=int, default=0)
    p_recover.add_argument("--recent-event-limit", type=int, default=24)

    p_audit = sub.add_parser("audit", help="Run safety/status audit")
    p_audit.add_argument("--root", required=True)

    p_doctor = sub.add_parser("doctor", help="Run package, catalog, and proof-pack diagnostics")
    p_doctor.add_argument("--root", required=True)
    p_doctor.add_argument("--verify-recent-proof-packs", type=int, default=1)
    p_doctor.add_argument("--scan-secrets", action="store_true", help="Also scan the root for obvious secret patterns")

    p_repair_permissions = sub.add_parser("repair-permissions", help="Tighten private root permissions on POSIX systems")
    p_repair_permissions.add_argument("--root", required=True)

    p_verify_root = sub.add_parser("verify-root", help="Run strict root invariants: doctor, proofs, ledger, search, secrets, and restore drill")
    p_verify_root.add_argument("--root", required=True)
    p_verify_root.add_argument("--verify-recent-proof-packs", type=int, default=5)
    p_verify_root.add_argument("--no-restore-drill", action="store_true")
    p_verify_root.add_argument("--no-secret-scan", action="store_true")
    p_verify_root.add_argument("--non-strict", action="store_true")

    p_pack_root = sub.add_parser("pack-root", help="Create a policy-checked portable ZIP bundle from a Continuum root")
    p_pack_root.add_argument("--root", required=True)
    p_pack_root.add_argument("--out", required=True, help="Output .zip path outside the Continuum root")
    p_pack_root.add_argument("--profile", choices=["portable", "shareable"], default="shareable")
    p_pack_root.add_argument("--symlink-policy", choices=["fail", "skip"], default="fail")
    p_pack_root.add_argument("--no-restore-drill", action="store_true")
    p_pack_root.add_argument("--force", action="store_true", help="Replace an existing output bundle")

    p_verify_bundle = sub.add_parser("verify-bundle", help="Verify a packed Continuum ZIP manifest and every member hash")
    p_verify_bundle.add_argument("--path", required=True)

    p_audit_secrets = sub.add_parser("audit-secrets", help="Scan an Epic Continuum root for obvious secret patterns")
    p_audit_secrets.add_argument("--root", required=True)
    p_audit_secrets.add_argument("--max-findings", type=int)
    p_audit_secrets.add_argument("--max-file-bytes", type=int)
    p_audit_secrets.add_argument("--sarif-output", help="Also write SARIF 2.1.0 results to this path")

    p_redact_legacy = sub.add_parser("redact-legacy-secrets", help="Dry-run or apply redaction for legacy secret-like catalog text")
    p_redact_legacy.add_argument("--root", required=True)
    p_redact_legacy.add_argument("--limit", type=int, default=500)
    p_redact_legacy.add_argument("--apply", action="store_true", help="Apply redactions; default is dry-run")

    p_verify_proof = sub.add_parser("verify-proof-pack", help="Verify a proof pack manifest and recorded file hashes")
    p_verify_proof.add_argument("path")
    p_verify_proof.add_argument("--root", help="Override the continuum root for root-relative proof paths")

    p_replay_op_log = sub.add_parser("replay-operation-log", help="Replay a hash-chained operation event JSONL log")
    p_replay_op_log.add_argument("path")
    p_replay_op_log.add_argument("--operation-id")

    p_snapshot = sub.add_parser("snapshot", help="Snapshot the catalog database")
    p_snapshot.add_argument("--root", required=True)
    p_snapshot.add_argument("--reason", default="manual_snapshot")

    p_import = sub.add_parser("import-mempalace", help="Import MemPalace drawers, closets, and KG into Epic Continuum")
    p_import.add_argument("--root", required=True)
    p_import.add_argument("--palace-path", default=str(default_mempalace_path()))
    p_import.add_argument("--no-closets", action="store_true", help="Skip MemPalace closet/route records")
    p_import.add_argument("--no-kg", action="store_true", help="Skip MemPalace knowledge graph triples")
    p_import.add_argument(
        "--allow-stop",
        action="store_true",
        help="Stop mempalace-readonly-mcp if the live Chroma database is locked",
    )
    p_import.add_argument("--no-progress", action="store_true", help="Do not print progress to stderr")

    p_ops = sub.add_parser("operations", help="List Epic Continuum operation receipts")
    p_ops.add_argument("--root", required=True)
    p_ops.add_argument("--status", choices=["running", "succeeded", "failed", "interrupted"])
    p_ops.add_argument("--limit", type=int, default=20)
    p_ops.add_argument("--operation-id", help="Show one operation receipt summary")

    p_recover_ops = sub.add_parser("recover-operations", help="Mark stale running operations interrupted and write resume packets")
    p_recover_ops.add_argument("--root", required=True)
    p_recover_ops.add_argument("--older-than-seconds", type=int, default=300)
    p_recover_ops.add_argument("--limit", type=int, default=20)
    p_recover_ops.add_argument(
        "--dry-run",
        action="store_true",
        help="Report stale operations without writing recovery packets or changing operation status",
    )

    p_drill = sub.add_parser("recovery-drill", help="Run an interruption/recovery drill on a disposable nested root")
    p_drill.add_argument("--root", required=True)
    p_drill.add_argument("--name", default="epic-continuum-recovery-drill")

    p_restore_drill = sub.add_parser("restore-drill", help="Restore a catalog snapshot into a disposable root and verify it")
    p_restore_drill.add_argument("--root", required=True)
    p_restore_drill.add_argument("--snapshot-uri")
    p_restore_drill.add_argument("--name", default="epic-continuum-restore-drill")
    p_restore_drill.add_argument("--verify-recent-proof-packs", type=int, default=1)

    p_hermes = sub.add_parser("install-hermes-adapter", help="Install the Epic Continuum Hermes plugin adapter")
    p_hermes.add_argument("--root", required=True)
    p_hermes.add_argument("--hermes-home")
    p_hermes.add_argument("--continuum-src")
    p_hermes.add_argument("--token-budget", type=int, default=1800)
    p_hermes.add_argument("--skip-enable", action="store_true", help="Copy the plugin but do not run hermes plugins enable")
    p_hermes.add_argument("--dry-run", action="store_true")
    p_hermes.add_argument("--hermes-exe")
    p_hermes.add_argument("--model-alias", help="Write a model route snippet for this alias")
    p_hermes.add_argument("--model-name", help="Model name served by the provider")
    p_hermes.add_argument("--model-provider", default="custom")
    p_hermes.add_argument("--base-url", help="OpenAI-compatible endpoint, for example http://127.0.0.1:8000/v1")
    p_hermes.add_argument("--api-key", default="none", help="Deprecated for secret values; prefer --api-key-env")
    p_hermes.add_argument("--api-key-env", help="Read an API key from this environment variable without recording it in CLI arguments")
    p_hermes.add_argument("--context-length", type=int)
    p_hermes.add_argument("--max-tokens", type=int)
    p_hermes.add_argument("--set-default-model", action="store_true", help="Use hermes config set to make this model the default")

    return parser


def _main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    root_arg_value = getattr(args, "root", None)
    root = Path(root_arg_value) if root_arg_value else None
    if args.command == "init":
        assert root is not None
        def action(operation: OperationGuard) -> dict[str, Any]:
            init_db(root)
            operation.cursor({"phase": "initialized", "root": str(root)})
            return {"ok": True, "root": str(root)}

        emit(
            guarded_result(
                root,
                operation_type="cli_init",
                title="Initialize Epic Continuum root",
                intent={"root": str(root)},
                snapshot_policy="none",
                snapshot_reason="new root initialization",
                touched_paths=[root / "catalog" / "catalog.sqlite3", config_path(root)],
                action=action,
            )
        )
        return 0

    if args.command == "status":
        assert root is not None
        emit(status(root, create=False))
        return 0

    if args.command == "config":
        assert root is not None
        def action(operation: OperationGuard) -> dict[str, Any]:
            write_default_config(root)
            operation.cursor({"phase": "config_written", "config_path": str(config_path(root))})
            return load_config(root)

        emit(
            guarded_result(
                root,
                operation_type="cli_config",
                title="Create or show Epic Continuum config",
                intent={"root": str(root)},
                snapshot_policy="none",
                snapshot_reason="config bootstrap is reversible from defaults",
                touched_paths=[config_path(root)],
                action=action,
            )
        )
        return 0

    if args.command == "optimize-config":
        assert root is not None
        def action(operation: OperationGuard) -> dict[str, Any]:
            result = optimize_config(
                    root,
                    profile=args.profile,
                    write=args.write,
                    vram=args.vram,
                    system_ram=args.system_ram,
                    drive_free=args.drive_free,
            )
            operation.cursor({"phase": "optimized_config", "wrote": result["wrote"], "config_path": result["config_path"]})
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_optimize_config",
                title="Optimize Epic Continuum hardware config",
                intent={"profile": args.profile, "write": args.write},
                snapshot_policy="none",
                snapshot_reason="config recommendation/write uses proof pack hash",
                touched_paths=[config_path(root)],
                action=action,
            )
        )
        return 0

    if args.command == "append-event":
        assert root is not None
        def action(operation: OperationGuard) -> dict[str, Any]:
            result = append_scroll_event(
                    root,
                    session_id=args.session_id,
                    event_type=args.type,
                    role=args.role,
                    content=args.content,
            )
            operation.cursor({"phase": "event_appended", "session_id": result["session_id"], "seq": result["seq"]})
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_append_event",
                title=f"Append Scroll event for {args.session_id}",
                intent={"session_id": args.session_id, "event_type": args.type, "role": args.role},
                snapshot_policy="none",
                snapshot_reason="append-only Scroll event",
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
                action=action,
            )
        )
        return 0

    if args.command == "roll-segment":
        assert root is not None
        def action(operation: OperationGuard) -> dict[str, Any]:
            operation.cursor({"phase": "before_roll", "session_id": args.session_id, "start_seq": args.start_seq, "end_seq": args.end_seq})
            result = roll_scroll_segment(
                    root,
                    session_id=args.session_id,
                    start_seq=args.start_seq,
                    end_seq=args.end_seq,
            )
            operation.cursor({"phase": "segment_rolled", "segment_id": result["segment_id"], "card_id": result["card_id"]})
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_roll_segment",
                title=f"Roll Scroll segment {args.session_id}:{args.start_seq}-{args.end_seq}",
                intent={"session_id": args.session_id, "start_seq": args.start_seq, "end_seq": args.end_seq},
                snapshot_policy="auto",
                snapshot_reason="roll segment mutates catalog/cards/graph",
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
                result_touched_paths=lambda result: [result["card_uri"]] if result.get("card_uri") else [],
                action=action,
            )
        )
        return 0

    if args.command == "ingest-file":
        assert root is not None
        source_path = Path(args.path)
        source_ref = source_file_reference(root, source_path)

        def action(operation: OperationGuard) -> dict[str, Any]:
            operation.cursor({"phase": "before_ingest", "source": source_ref, "storage_tier": args.storage_tier})
            result = ingest_file(
                    root,
                    path=source_path,
                    title=args.title,
                    storage_tier=args.storage_tier,
            )
            operation.cursor({"phase": "file_ingested", "book_id": result["book_id"], "card_id": result["card_id"]})
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_ingest_file",
                title=f"Ingest file {source_ref['name']}",
                intent={"source": source_ref, "title": args.title, "storage_tier": args.storage_tier},
                snapshot_policy="auto",
                snapshot_reason="file ingest mutates Library/catalog",
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
                result_touched_paths=lambda result: [
                    path for path in [result.get("card_uri"), result.get("original_uri"), result.get("reader_uri")] if path
                ],
                action=action,
            )
        )
        return 0

    if args.command == "compile-context":
        assert root is not None
        emit(
            compile_context(
                root,
                session_id=args.session_id,
                token_budget=args.token_budget,
                query=args.query,
                card_scope=args.card_scope,
                project_id=args.project_id,
                create=False,
            )
        )
        return 0

    if args.command == "recover-thread":
        assert root is not None
        def action(operation: OperationGuard) -> dict[str, Any]:
            result = recover_thread(
                    root,
                    session_id=args.session_id,
                    query=args.query,
                    token_budget=args.token_budget,
                    recent_event_limit=args.recent_event_limit,
            )
            operation.cursor({"phase": "thread_recovered", "session_id": args.session_id, "packet_uri": result["packet_uri"]})
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_recover_thread",
                title=f"Recover thread {args.session_id}",
                intent={"session_id": args.session_id, "query": args.query, "token_budget": args.token_budget},
                snapshot_policy="none",
                snapshot_reason="recovery packet is an export over existing evidence",
                result_touched_paths=lambda result: [result["packet_uri"]] if result.get("packet_uri") else [],
                action=action,
            )
        )
        return 0

    if args.command == "search":
        assert root is not None
        emit(search_memory(root, query=args.query, limit=args.limit, create=False))
        return 0

    if args.command == "audit-search-index":
        assert root is not None
        result = audit_search_index(root, create=False)
        emit(result)
        return 0 if result.get("ok") else 1

    if args.command == "rebuild-search-index":
        assert root is not None
        def action(operation: OperationGuard) -> dict[str, Any]:
            result = rebuild_search_index(root)
            operation.cursor(
                {
                    "phase": "search_index_rebuilt",
                    "chunks": result.get("chunks"),
                    "fts_rows": result.get("fts_rows"),
                    "ok": result.get("ok"),
                }
            )
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_rebuild_search_index",
                title="Rebuild Library chunk search index",
                intent={"root": str(root)},
                snapshot_policy="auto",
                snapshot_reason="search index rebuild mutates derived catalog FTS state",
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
                action=action,
            )
        )
        return 0

    if args.command == "run-workers":
        assert root is not None

        def action(operation: OperationGuard) -> dict[str, Any]:
            result = run_worker_pass(root, roles=args.role, limit=args.limit, maintenance=not args.no_maintenance)
            operation.cursor({"phase": "workers_ran", "processed_count": result.get("processed_count"), "ok": result.get("ok")})
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_run_workers",
                title="Run Epic Continuum worker pass",
                intent={"roles": args.role, "limit": args.limit, "maintenance": not args.no_maintenance},
                snapshot_policy="auto",
                snapshot_reason="worker pass may mutate queue/catalog/cards/graph",
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
                action=action,
            )
        )
        return 0

    if args.command == "serve":
        assert root is not None
        emit(serve_workers(root, roles=args.role, limit=args.passes, interval_seconds=args.interval_seconds))
        return 0

    if args.command == "memory-health":
        assert root is not None
        emit(memory_health(root))
        return 0

    if args.command == "tier-storage":
        assert root is not None
        if args.dry_run:
            emit(apply_storage_tiering(root, dry_run=True, limit=args.limit))
            return 0

        def action(operation: OperationGuard) -> dict[str, Any]:
            result = apply_storage_tiering(root, dry_run=False, limit=args.limit)
            operation.cursor({"phase": "storage_tiering_applied", "action_count": result.get("action_count")})
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_tier_storage",
                title="Apply Epic Continuum storage tiering",
                intent={"limit": args.limit},
                snapshot_policy="auto",
                snapshot_reason="storage tiering mutates catalog book metadata",
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
                action=action,
            )
        )
        return 0

    if args.command == "prune-memory":
        assert root is not None
        if args.dry_run:
            emit(prune_memory(root, topic=args.topic, action=args.action, dry_run=True, limit=args.limit, allow_global=args.all))
            return 0

        def action(operation: OperationGuard) -> dict[str, Any]:
            result = prune_memory(root, topic=args.topic, action=args.action, dry_run=False, limit=args.limit, allow_global=args.all)
            operation.cursor({"phase": "memory_pruned", "action": result.get("action"), "card_count": result.get("card_count")})
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_prune_memory",
                title="Prune Epic Continuum memory cards",
                intent={"topic": args.topic, "action": args.action, "limit": args.limit, "allow_global": args.all},
                snapshot_policy="auto",
                snapshot_reason="pruning mutates card status/projection state",
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
                action=action,
            )
        )
        return 0

    if args.command == "detect-conflicts":
        assert root is not None

        def action(operation: OperationGuard) -> dict[str, Any]:
            result = detect_conflicts(root, card_id=args.card_id, limit=args.limit)
            operation.cursor({"phase": "conflicts_detected", "conflict_count": result.get("conflict_count")})
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_detect_conflicts",
                title="Detect Epic Continuum card conflicts",
                intent={"card_id": args.card_id, "limit": args.limit},
                snapshot_policy="auto",
                snapshot_reason="conflict detection may annotate cards",
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
                action=action,
            )
        )
        return 0

    if args.command == "decay-routes":
        assert root is not None

        def action(operation: OperationGuard) -> dict[str, Any]:
            result = decay_graph_routes(root, limit=args.limit, prune_threshold=args.prune_threshold)
            operation.cursor({"phase": "routes_decayed", "decayed": result.get("decayed"), "pruned": result.get("pruned")})
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_decay_routes",
                title="Apply Epic Continuum route decay",
                intent={"limit": args.limit, "prune_threshold": args.prune_threshold},
                snapshot_policy="auto",
                snapshot_reason="route decay mutates graph edge weights/status",
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
                action=action,
            )
        )
        return 0

    if args.command == "run-evals":
        assert root is not None

        def action(operation: OperationGuard) -> dict[str, Any]:
            result = run_memory_quality_evals(root, keep_artifacts=args.keep_artifacts)
            operation.cursor({"phase": "evals_ran", "eval_id": result.get("eval_id"), "ok": result.get("ok")})
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_run_evals",
                title="Run Epic Continuum memory quality evals",
                intent={"keep_artifacts": args.keep_artifacts},
                snapshot_policy="none",
                snapshot_reason="evals use disposable nested roots",
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
                result_touched_paths=lambda result: [result["eval_root"]] if result.get("eval_root") and not result.get("eval_root_removed") else [],
                action=action,
            )
        )
        return 0

    if args.command == "audit":
        assert root is not None
        emit(audit(root, create=False))
        return 0

    if args.command == "doctor":
        assert root is not None
        result = doctor(root, verify_recent_proof_packs=args.verify_recent_proof_packs, scan_secrets=args.scan_secrets)
        emit(result)
        return 0 if result.get("ok") else 1

    if args.command == "repair-permissions":
        assert root is not None

        def action(operation: OperationGuard) -> dict[str, Any]:
            result = repair_permissions(root)
            operation.cursor(
                {
                    "phase": "permissions_repaired",
                    "ok": result.get("ok"),
                    "changed": (result.get("repair") or {}).get("changed"),
                }
            )
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_repair_permissions",
                title="Repair Epic Continuum private root permissions",
                intent={"root": str(root)},
                snapshot_policy="none",
                snapshot_reason="permission repair changes filesystem modes only",
                touched_paths=[root],
                action=action,
            )
        )
        return 0

    if args.command == "verify-root":
        assert root is not None
        result = verify_root(
            root,
            strict=not args.non_strict,
            verify_recent_proof_packs=args.verify_recent_proof_packs,
            run_restore_drill=not args.no_restore_drill,
            scan_secrets=not args.no_secret_scan,
        )
        emit(result)
        return 0 if result.get("ok") else 1

    if args.command == "pack-root":
        assert root is not None
        result = pack_root(
            root,
            out_path=Path(args.out),
            profile=args.profile,
            symlink_policy=args.symlink_policy,
            run_restore_drill=not args.no_restore_drill,
            force=args.force,
        )
        emit(result)
        return 0 if result.get("ok") else 1

    if args.command == "verify-bundle":
        result = verify_root_bundle(Path(args.path))
        emit(result)
        return 0 if result.get("ok") else 1

    if args.command == "audit-secrets":
        assert root is not None
        result = audit_secrets(root, create=False, max_findings=args.max_findings, max_file_bytes=args.max_file_bytes)
        if args.sarif_output:
            sarif_path = Path(args.sarif_output)
            sarif_path.parent.mkdir(parents=True, exist_ok=True)
            sarif_path.write_text(json.dumps(audit_secrets_sarif(result), ensure_ascii=True, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            result["sarif_output_uri"] = str(sarif_path)
        emit(result)
        return 0 if result.get("ok") and result.get("complete", True) else 1

    if args.command == "redact-legacy-secrets":
        assert root is not None
        if not args.apply:
            emit(redact_legacy_secrets(root, dry_run=True, limit=args.limit))
            return 0

        def action(operation: OperationGuard) -> dict[str, Any]:
            result = redact_legacy_secrets(root, dry_run=False, limit=args.limit)
            operation.cursor({"phase": "legacy_secrets_redacted", "redaction_count": result.get("redaction_count")})
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_redact_legacy_secrets",
                title="Redact legacy secret-like catalog text",
                intent={"limit": args.limit},
                snapshot_policy="auto",
                snapshot_reason="legacy secret cleanup mutates catalog text columns",
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
                action=action,
            )
        )
        return 0

    if args.command == "verify-proof-pack":
        result = verify_proof_pack(Path(args.path), root=root, strict=True)
        emit(result)
        return 0 if result.get("ok") else 1

    if args.command == "replay-operation-log":
        result = replay_operation_event_log(Path(args.path), operation_id=args.operation_id)
        emit(result)
        return 0 if result.get("ok") else 1

    if args.command == "snapshot":
        assert root is not None
        def action(operation: OperationGuard) -> dict[str, Any]:
            result = snapshot(root, reason=args.reason)
            operation.cursor({"phase": "snapshot_created", "snapshot_uri": result["snapshot_uri"]})
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_snapshot",
                title="Snapshot Epic Continuum catalog",
                intent={"reason": args.reason},
                snapshot_policy="none",
                snapshot_reason="snapshot command is itself the preflight protection",
                touched_paths=[root / "catalog" / "catalog.sqlite3"],
                result_touched_paths=lambda result: [
                    path for path in [result.get("snapshot_uri"), result.get("card_sidecars_uri")] if path
                ],
                action=action,
            )
        )
        return 0

    if args.command == "import-mempalace":
        assert root is not None
        emit(
            import_mempalace(
                root,
                palace_path=Path(args.palace_path),
                include_closets=not args.no_closets,
                include_kg=not args.no_kg,
                allow_stop=args.allow_stop,
                progress=None if args.no_progress else progress_bar,
            )
        )
        return 0

    if args.command == "operations":
        assert root is not None
        if args.operation_id:
            emit(operation_summary(root, args.operation_id))
        else:
            emit(list_operations(root, status=args.status, limit=args.limit))
        return 0

    if args.command == "recover-operations":
        assert root is not None
        emit(
            recover_stale_operations(
                root,
                older_than_seconds=args.older_than_seconds,
                mark=not args.dry_run,
                limit=args.limit,
            )
        )
        return 0

    if args.command == "recovery-drill":
        assert root is not None
        def action(operation: OperationGuard) -> dict[str, Any]:
            result = recovery_drill(root, drill_name=args.name)
            operation.cursor({"phase": "drill_complete", "drill_id": result["drill_id"], "ok": result["ok"]})
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_recovery_drill",
                title=f"Run recovery drill {args.name}",
                intent={"drill_name": args.name},
                snapshot_policy="none",
                snapshot_reason="drill uses disposable nested root",
                result_touched_paths=lambda result: [result["receipt_uri"]] if result.get("receipt_uri") else [],
                action=action,
            )
        )
        return 0

    if args.command == "restore-drill":
        assert root is not None
        def action(operation: OperationGuard) -> dict[str, Any]:
            result = restore_drill(
                root,
                snapshot_uri=args.snapshot_uri,
                drill_name=args.name,
                verify_recent_proof_packs=args.verify_recent_proof_packs,
            )
            operation.cursor({"phase": "restore_drill_complete", "drill_id": result["drill_id"], "ok": result["ok"]})
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_restore_drill",
                title=f"Run restore drill {args.name}",
                intent={
                    "drill_name": args.name,
                    "snapshot_uri": args.snapshot_uri,
                    "verify_recent_proof_packs": args.verify_recent_proof_packs,
                },
                snapshot_policy="none",
                snapshot_reason="restore drill uses disposable nested root",
                result_touched_paths=lambda result: [result["receipt_uri"]] if result.get("receipt_uri") else [],
                action=action,
            )
        )
        return 0

    if args.command == "install-hermes-adapter":
        assert root is not None
        def action(operation: OperationGuard) -> dict[str, Any]:
            result = install_hermes_adapter(
                hermes_home=Path(args.hermes_home) if args.hermes_home else None,
                continuum_root=root,
                continuum_src=Path(args.continuum_src) if args.continuum_src else None,
                token_budget=args.token_budget,
                enable=not args.skip_enable,
                dry_run=args.dry_run,
                hermes_exe=Path(args.hermes_exe) if args.hermes_exe else None,
                model_alias=args.model_alias,
                model_name=args.model_name,
                model_provider=args.model_provider,
                base_url=args.base_url,
                api_key=args.api_key,
                api_key_env=args.api_key_env,
                context_length=args.context_length,
                max_tokens=args.max_tokens,
                set_default_model=args.set_default_model,
            )
            operation.cursor(
                {
                    "phase": "hermes_adapter_installed",
                    "plugin_name": result["plugin_name"],
                    "plugin_target": result["plugin_target"],
                    "dry_run": result["dry_run"],
                }
            )
            return result

        emit(
            guarded_result(
                root,
                operation_type="cli_install_hermes_adapter",
                title="Install Epic Continuum Hermes adapter",
                intent={
                    "hermes_home": (
                        source_file_reference(root, Path(args.hermes_home))["uri"] if args.hermes_home else None
                    ),
                    "token_budget": args.token_budget,
                    "enable": not args.skip_enable,
                    "model_alias": args.model_alias,
                    "set_default_model": args.set_default_model,
                },
                snapshot_policy="none",
                snapshot_reason="Hermes adapter install is copy/config outside the Continuum catalog",
                result_touched_paths=lambda _result: [],
                action=action,
            )
        )
        return 0

    parser.error(f"unknown command: {args.command}")
    return 2


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except Exception as exc:
        emit({"ok": False, "error": str(exc), "error_type": type(exc).__name__})
        return 1
