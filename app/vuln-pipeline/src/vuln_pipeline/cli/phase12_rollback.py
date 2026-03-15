from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vuln_pipeline.cli.main import _workspace_root
from vuln_pipeline.cli.phase12_apply_signoff import _dedupe_strings, _load_json
from vuln_pipeline.storage import write_json, write_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build or apply a phase12 rollback plan from promotion receipts.")
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path)
    parser.add_argument("--live-root", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--receipt-dir", type=Path)
    parser.add_argument("--scan-receipt-dir", type=Path)
    parser.add_argument("--manual-receipt-dir", type=Path)
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--md-out", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = execute_phase12_rollback(
        run_root=Path(args.run_root).resolve(),
        workspace_root=Path(args.workspace_root).resolve() if args.workspace_root else None,
        live_root=Path(args.live_root).resolve() if args.live_root else None,
        output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
        receipt_dir=Path(args.receipt_dir).resolve() if args.receipt_dir else None,
        scan_receipt_dir=Path(args.scan_receipt_dir).resolve() if args.scan_receipt_dir else None,
        manual_receipt_dir=Path(args.manual_receipt_dir).resolve() if args.manual_receipt_dir else None,
        plan_only=bool(args.plan_only or not args.apply),
        apply=bool(args.apply),
        overwrite=bool(args.overwrite),
        json_out=Path(args.json_out).resolve() if args.json_out else None,
        md_out=Path(args.md_out).resolve() if args.md_out else None,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if report["status"] in {"blocked", "invalid"} else 0


def execute_phase12_rollback(
    *,
    run_root: Path,
    workspace_root: Path | None,
    live_root: Path | None,
    output_dir: Path | None,
    receipt_dir: Path | None,
    scan_receipt_dir: Path | None,
    manual_receipt_dir: Path | None,
    plan_only: bool,
    apply: bool,
    overwrite: bool,
    json_out: Path | None,
    md_out: Path | None,
) -> dict[str, Any]:
    if plan_only and apply:
        raise ValueError("Choose either plan-only or apply mode, not both.")

    report_data = run_root / "report_data"
    output_dir = output_dir or report_data
    output_dir.mkdir(parents=True, exist_ok=True)
    workspace_root = (workspace_root or _workspace_root()).resolve()
    live_root = (live_root or (workspace_root / "data" / "inputs" / "real")).resolve()

    if receipt_dir:
        scan_receipt_dir = scan_receipt_dir or receipt_dir
        manual_receipt_dir = manual_receipt_dir or receipt_dir
    scan_receipt_dir = scan_receipt_dir or (report_data / "scan_promotion")
    manual_receipt_dir = manual_receipt_dir or (report_data / "manual_promotion")
    scan_receipt_path = scan_receipt_dir / "scan_input_promotion_receipt.json"
    manual_receipt_path = manual_receipt_dir / "manual_promotion_receipt.json"
    scan_receipt = _load_json(scan_receipt_path)
    manual_receipt = _load_json(manual_receipt_path)

    plan = build_rollback_plan(
        run_root=run_root,
        workspace_root=workspace_root,
        live_root=live_root,
        output_dir=output_dir,
        scan_receipt_path=scan_receipt_path,
        scan_receipt=scan_receipt,
        manual_receipt_path=manual_receipt_path,
        manual_receipt=manual_receipt,
    )

    if not apply:
        json_out = json_out or (output_dir / "phase12_rollback_plan.json")
        md_out = md_out or (output_dir / "phase12_rollback_plan.md")
        write_json(json_out, plan)
        write_markdown(md_out, render_rollback_plan_markdown(plan))
        plan["json_out"] = str(json_out)
        plan["md_out"] = str(md_out)
        return plan

    receipt = apply_rollback(plan=plan, output_dir=output_dir, overwrite=overwrite)
    json_out = json_out or (output_dir / "phase12_rollback_receipt.json")
    md_out = md_out or (output_dir / "phase12_rollback_receipt.md")
    write_json(json_out, receipt)
    write_markdown(md_out, render_rollback_receipt_markdown(receipt))
    receipt["json_out"] = str(json_out)
    receipt["md_out"] = str(md_out)
    return receipt


def build_rollback_plan(
    *,
    run_root: Path,
    workspace_root: Path,
    live_root: Path,
    output_dir: Path,
    scan_receipt_path: Path,
    scan_receipt: dict[str, Any] | None,
    manual_receipt_path: Path,
    manual_receipt: dict[str, Any] | None,
) -> dict[str, Any]:
    actions: list[dict[str, Any]] = []
    warnings: list[str] = []
    blockers: list[str] = []

    if not isinstance(scan_receipt, dict) and not isinstance(manual_receipt, dict):
        blockers.append("No scan/manual promotion receipt is available for rollback planning.")

    applied_tools = scan_receipt.get("applied_tools", {}) if isinstance(scan_receipt, dict) else {}
    for tool, item in applied_tools.items() if isinstance(applied_tools, dict) else []:
        if not isinstance(item, dict):
            continue
        target_path = _safe_resolve(Path(item["target_path"]), workspace_root, allow_missing=True)
        restore_source = _pick_scan_restore_source(item=item, workspace_root=workspace_root)
        current_hash = _hash_or_none(target_path)
        before_hash = item.get("before_hash")
        if before_hash and restore_source is None:
            blockers.append(f"{tool}: receipt expects a previous scan file but the archive source is missing.")
        if before_hash is None and restore_source is None:
            warnings.append(f"{tool}: receipt has no before-state archive; rollback cannot recreate an empty previous target automatically.")
        conflict = bool(current_hash and item.get("after_hash") and current_hash != item.get("after_hash"))
        if conflict:
            warnings.append(f"{tool}: current live hash differs from the apply receipt after_hash.")
        actions.append(
            {
                "kind": "scan",
                "name": tool,
                "target_path": str(target_path),
                "restore_source_path": str(restore_source) if restore_source else None,
                "restore_source_exists": bool(restore_source and restore_source.exists()),
                "current_live_hash": current_hash,
                "receipt_before_hash": before_hash,
                "receipt_after_hash": item.get("after_hash"),
                "current_matches_receipt_after_hash": bool(current_hash and current_hash == item.get("after_hash")),
                "would_overwrite_existing_file": target_path.exists(),
                "conflict": conflict,
                "ambiguous": False,
                "missing_backup_or_archive": restore_source is None and before_hash is not None,
            }
        )

    applied_files = manual_receipt.get("applied_files", []) if isinstance(manual_receipt, dict) else []
    for item in applied_files:
        if not isinstance(item, dict) or not item.get("key") or not item.get("after_path"):
            continue
        key = str(item["key"])
        target_path = _safe_resolve(Path(item["after_path"]), workspace_root, allow_missing=True)
        backup_path = _path_or_none(item.get("backup_path"))
        if backup_path is not None:
            backup_path = _safe_resolve_optional(backup_path, workspace_root, allow_missing=False)
        current_hash = _hash_or_none(target_path)
        before_hash = item.get("before_hash")
        if before_hash and (backup_path is None or not backup_path.exists()):
            blockers.append(f"{key}: receipt expects a manual backup but the backup file is missing.")
        if before_hash is None and backup_path is None:
            warnings.append(f"{key}: receipt has no pre-apply backup; rollback cannot recreate an empty previous target automatically.")
        conflict = bool(current_hash and item.get("after_hash") and current_hash != item.get("after_hash"))
        if conflict:
            warnings.append(f"{key}: current live manual hash differs from the apply receipt after_hash.")
        actions.append(
            {
                "kind": "manual",
                "name": key,
                "target_path": str(target_path),
                "restore_source_path": str(backup_path) if backup_path else None,
                "restore_source_exists": bool(backup_path and backup_path.exists()),
                "current_live_hash": current_hash,
                "receipt_before_hash": before_hash,
                "receipt_after_hash": item.get("after_hash"),
                "current_matches_receipt_after_hash": bool(current_hash and current_hash == item.get("after_hash")),
                "would_overwrite_existing_file": target_path.exists(),
                "conflict": conflict,
                "ambiguous": False,
                "missing_backup_or_archive": backup_path is None and before_hash is not None,
            }
        )

    if not actions and not blockers:
        blockers.append("Receipts were present but contained no actionable restore targets.")

    status = "blocked" if blockers else "plan_ready_with_warnings" if warnings else "plan_ready"
    return {
        "status": status,
        "mode": "plan",
        "generated_at": _timestamp(),
        "run_root": str(run_root),
        "workspace_root": str(workspace_root),
        "live_root": str(live_root),
        "output_dir": str(output_dir),
        "scan_receipt": {"path": str(scan_receipt_path), "exists": scan_receipt_path.exists()},
        "manual_receipt": {"path": str(manual_receipt_path), "exists": manual_receipt_path.exists()},
        "actions": actions,
        "warnings": _dedupe_strings(warnings),
        "blockers": _dedupe_strings(blockers),
        "exact_apply_command": (
            "python -m vuln_pipeline.cli.phase12_rollback "
            f"--run-root \"{run_root}\" --workspace-root \"{workspace_root}\" --live-root \"{live_root}\" --apply --overwrite"
        ),
    }


def apply_rollback(*, plan: dict[str, Any], output_dir: Path, overwrite: bool) -> dict[str, Any]:
    blockers = list(plan.get("blockers", []))
    actions = plan.get("actions", [])
    for item in actions:
        if not item.get("restore_source_exists") and item.get("receipt_before_hash") is not None:
            blockers.append(f"{item['name']}: restore source is missing.")
        if item.get("conflict") and not overwrite:
            blockers.append(f"{item['name']}: current live file has drifted since apply; rerun with --overwrite only after review.")
        if item.get("restore_source_path") is None:
            blockers.append(f"{item['name']}: no restore source is available, so apply mode will not delete or blank the live target.")
    if blockers:
        return {
            **plan,
            "status": "blocked",
            "mode": "apply",
            "blockers": _dedupe_strings(blockers),
        }

    restore_backup_dir = output_dir / "phase12_rollback_backups" / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    restore_backup_dir.mkdir(parents=True, exist_ok=True)
    restored: list[dict[str, Any]] = []
    for item in actions:
        target_path = Path(item["target_path"])
        restore_source = Path(item["restore_source_path"])
        current_backup = None
        before_hash = _hash_or_none(target_path)
        if target_path.exists():
            current_backup = restore_backup_dir / f"{target_path.name}.pre_rollback.bak"
            shutil.copy2(target_path, current_backup)
        _atomic_copy_binary(restore_source, target_path)
        restored.append(
            {
                "kind": item["kind"],
                "name": item["name"],
                "restored_target_path": str(target_path),
                "source_backup_or_archive_path": str(restore_source),
                "current_backup_path": str(current_backup) if current_backup else None,
                "before_hash": before_hash,
                "after_hash": _hash_or_none(target_path),
                "restore_timestamp": _timestamp(),
                "originating_run_root": plan["run_root"],
            }
        )
    return {
        "status": "applied",
        "mode": "apply",
        "generated_at": _timestamp(),
        "originating_run_root": plan["run_root"],
        "workspace_root": plan["workspace_root"],
        "live_root": plan["live_root"],
        "restore_backup_dir": str(restore_backup_dir),
        "restored_items": restored,
    }


def render_rollback_plan_markdown(plan: dict[str, Any]) -> str:
    lines = [
        "# Phase12 Rollback Plan",
        "",
        f"- status: `{plan['status']}`",
        f"- run_root: `{plan['run_root']}`",
        f"- live_root: `{plan['live_root']}`",
        "",
        "## Blockers",
    ]
    lines.extend([f"- {item}" for item in plan["blockers"]] or ["- none"])
    lines.extend(["", "## Warnings"])
    lines.extend([f"- {item}" for item in plan["warnings"]] or ["- none"])
    lines.extend(["", "## Restore Actions"])
    for item in plan["actions"]:
        lines.extend(
            [
                f"### {item['kind']}::{item['name']}",
                f"- target_path: `{item['target_path']}`",
                f"- restore_source_path: `{item['restore_source_path']}`",
                f"- restore_source_exists: `{item['restore_source_exists']}`",
                f"- current_live_hash: `{item['current_live_hash']}`",
                f"- receipt_before_hash: `{item['receipt_before_hash']}`",
                f"- receipt_after_hash: `{item['receipt_after_hash']}`",
                f"- current_matches_receipt_after_hash: `{item['current_matches_receipt_after_hash']}`",
                f"- would_overwrite_existing_file: `{item['would_overwrite_existing_file']}`",
                f"- missing_backup_or_archive: `{item['missing_backup_or_archive']}`",
            ]
        )
    lines.extend(["", "## Apply Command", f"- `{plan['exact_apply_command']}`"])
    return "\n".join(lines) + "\n"


def render_rollback_receipt_markdown(receipt: dict[str, Any]) -> str:
    lines = [
        "# Phase12 Rollback Receipt",
        "",
        f"- status: `{receipt['status']}`",
        f"- originating_run_root: `{receipt['originating_run_root']}`",
        f"- restore_backup_dir: `{receipt['restore_backup_dir']}`",
    ]
    for item in receipt.get("restored_items", []):
        lines.extend(
            [
                "",
                f"## {item['kind']}::{item['name']}",
                f"- restored_target_path: `{item['restored_target_path']}`",
                f"- source_backup_or_archive_path: `{item['source_backup_or_archive_path']}`",
                f"- current_backup_path: `{item['current_backup_path']}`",
                f"- before_hash: `{item['before_hash']}`",
                f"- after_hash: `{item['after_hash']}`",
                f"- restore_timestamp: `{item['restore_timestamp']}`",
            ]
        )
    return "\n".join(lines) + "\n"


def _pick_scan_restore_source(*, item: dict[str, Any], workspace_root: Path) -> Path | None:
    target_name = Path(str(item["target_path"])).name
    archived_files = item.get("archived_files", [])
    if isinstance(archived_files, list):
        for archived in archived_files:
            if not isinstance(archived, dict) or not archived.get("archive_path"):
                continue
            archive_path = _safe_resolve_optional(Path(archived["archive_path"]), workspace_root, allow_missing=False)
            if archive_path is None:
                continue
            if archive_path.name == target_name:
                return archive_path
    archive_paths = item.get("archive_paths", [])
    if isinstance(archive_paths, list):
        for value in archive_paths:
            archive_path = _safe_resolve_optional(Path(str(value)), workspace_root, allow_missing=False)
            if archive_path is None:
                continue
            if archive_path.name == target_name:
                return archive_path
    return None


def _safe_resolve(path: Path, root: Path, *, allow_missing: bool) -> Path:
    resolved_root = root.resolve()
    resolved = path.resolve(strict=not allow_missing)
    if not allow_missing and resolved.is_symlink():
        raise ValueError(f"Symlink path is not allowed: {path}")
    resolved.relative_to(resolved_root)
    return resolved


def _safe_resolve_optional(path: Path, root: Path, *, allow_missing: bool) -> Path | None:
    try:
        return _safe_resolve(path, root, allow_missing=allow_missing)
    except Exception:
        return None


def _path_or_none(value: str | None) -> Path | None:
    return Path(value) if value else None


def _hash_or_none(path: Path | None) -> str | None:
    if path is None or not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_copy_binary(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as handle:
        content = handle.read()
    with tempfile.NamedTemporaryFile("wb", dir=target.parent, delete=False) as temp_handle:
        temp_handle.write(content)
        temp_path = Path(temp_handle.name)
    temp_path.replace(target)


def _timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
