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
from vuln_pipeline.parsers.real_inputs import EXCLUDED_NAME_PARTS, REAL_INPUT_RULES, _evaluate_candidate
from vuln_pipeline.storage import write_json, write_markdown


TOOL_ORDER = ("burp", "nuclei", "httpx")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan or apply guarded promotion of real scan exports into live data\\inputs\\real directories."
    )
    parser.add_argument("--incoming-root", type=Path)
    parser.add_argument("--incoming-burp", type=Path)
    parser.add_argument("--incoming-nuclei", type=Path)
    parser.add_argument("--incoming-httpx", type=Path)
    parser.add_argument("--live-root", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--archive-dir", type=Path)
    parser.add_argument("--receipt-out", type=Path)
    parser.add_argument("--target-name-burp", type=str)
    parser.add_argument("--target-name-nuclei", type=str)
    parser.add_argument("--target-name-httpx", type=str)
    parser.add_argument("--workspace-root", type=Path, default=_workspace_root())
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--allow-auto-pick", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    workspace_root = Path(args.workspace_root).resolve()
    live_root = Path(args.live_root).resolve() if args.live_root else workspace_root / "data" / "inputs" / "real"
    summary = execute_scan_input_promotion(
        incoming_root=Path(args.incoming_root).resolve() if args.incoming_root else None,
        incoming_files={
            "burp": Path(args.incoming_burp).resolve() if args.incoming_burp else None,
            "nuclei": Path(args.incoming_nuclei).resolve() if args.incoming_nuclei else None,
            "httpx": Path(args.incoming_httpx).resolve() if args.incoming_httpx else None,
        },
        live_root=live_root,
        output_dir=Path(args.output_dir).resolve(),
        archive_dir=Path(args.archive_dir).resolve() if args.archive_dir else None,
        receipt_out=Path(args.receipt_out).resolve() if args.receipt_out else None,
        target_names={
            "burp": args.target_name_burp,
            "nuclei": args.target_name_nuclei,
            "httpx": args.target_name_httpx,
        },
        plan_only=bool(args.plan_only or not args.apply),
        apply=bool(args.apply),
        overwrite=bool(args.overwrite),
        allow_auto_pick=bool(args.allow_auto_pick),
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 1 if summary["status"] == "blocked" else 0


def execute_scan_input_promotion(
    *,
    incoming_root: Path | None,
    incoming_files: dict[str, Path | None],
    live_root: Path,
    output_dir: Path,
    archive_dir: Path | None,
    receipt_out: Path | None,
    target_names: dict[str, str | None],
    plan_only: bool,
    apply: bool,
    overwrite: bool,
    allow_auto_pick: bool,
) -> dict[str, Any]:
    if plan_only and apply:
        raise ValueError("Choose either plan-only or apply mode, not both.")

    output_dir.mkdir(parents=True, exist_ok=True)
    live_root.mkdir(parents=True, exist_ok=True)

    report = build_scan_promotion_report(
        incoming_root=incoming_root,
        incoming_files=incoming_files,
        live_root=live_root,
        output_dir=output_dir,
        target_names=target_names,
        overwrite=overwrite,
        allow_auto_pick=allow_auto_pick,
    )
    write_json(output_dir / "scan_input_promotion_plan.json", report)
    write_markdown(output_dir / "scan_input_promotion_plan.md", render_scan_promotion_markdown(report))
    write_json(output_dir / "live_scan_inventory.json", report["live_inventory"])
    write_markdown(output_dir / "live_scan_inventory.md", render_live_inventory_markdown(report["live_inventory"]))

    if not apply:
        return report

    receipt = apply_scan_promotion(
        report=report,
        archive_dir=archive_dir or (output_dir / "archive"),
        receipt_out=receipt_out or (output_dir / "scan_input_promotion_receipt.json"),
        overwrite=overwrite,
    )
    write_markdown(output_dir / "scan_input_promotion_receipt.md", render_scan_receipt_markdown(receipt))
    write_json(output_dir / "live_scan_inventory.json", receipt["live_inventory_after"])
    write_markdown(output_dir / "live_scan_inventory.md", render_live_inventory_markdown(receipt["live_inventory_after"]))
    return receipt


def build_scan_promotion_report(
    *,
    incoming_root: Path | None,
    incoming_files: dict[str, Path | None],
    live_root: Path,
    output_dir: Path,
    target_names: dict[str, str | None],
    overwrite: bool,
    allow_auto_pick: bool,
) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []
    tool_reports: dict[str, dict[str, Any]] = {}
    live_inventory = build_live_scan_inventory(live_root=live_root)

    for tool in TOOL_ORDER:
        live_directory = live_root / tool
        live_directory.mkdir(parents=True, exist_ok=True)
        report = _build_tool_promotion_report(
            tool=tool,
            incoming_root=incoming_root,
            explicit_source=incoming_files.get(tool),
            live_dir=live_directory,
            live_inventory=live_inventory["tools"][tool],
            target_name=target_names.get(tool),
            overwrite=overwrite,
            allow_auto_pick=allow_auto_pick,
        )
        tool_reports[tool] = report
        blockers.extend(f"{tool}: {item}" for item in report["blockers"])
        warnings.extend(f"{tool}: {item}" for item in report["warnings"])

    status = "blocked" if blockers else "ready_for_review" if warnings else "ready_to_apply"
    return {
        "status": status,
        "mode": "plan",
        "generated_at": _timestamp(),
        "incoming_root": str(incoming_root) if incoming_root else None,
        "live_root": str(live_root),
        "output_dir": str(output_dir),
        "overwrite_requested": overwrite,
        "allow_auto_pick": allow_auto_pick,
        "tools": tool_reports,
        "live_inventory": live_inventory,
        "blockers": _dedupe_strings(blockers),
        "warnings": _dedupe_strings(warnings),
        "operator_guidance": [
            "Auto-select rules were reused as hard facts; ambiguous incoming candidates stay blocked unless an explicit source or --allow-auto-pick is provided.",
            "When an incoming basename contains sample/fixture/test/realish, a naming decision is required before promotion unless an explicit target name is supplied.",
            "The operating goal is one valid auto-selectable live file per tool. Extra live files are archived during apply, never silently deleted.",
        ],
    }


def build_live_scan_inventory(*, live_root: Path) -> dict[str, Any]:
    tools: dict[str, Any] = {}
    warnings: list[str] = []
    blockers: list[str] = []
    for tool in TOOL_ORDER:
        directory = live_root / tool
        tool_inventory = _build_directory_inventory(tool=tool, directory=directory)
        tools[tool] = tool_inventory
        warnings.extend(f"{tool}: {item}" for item in tool_inventory["warnings"])
        blockers.extend(f"{tool}: {item}" for item in tool_inventory["blockers"])
    status = "blocked" if blockers else "warning" if warnings else "ready"
    return {
        "status": status,
        "generated_at": _timestamp(),
        "live_root": str(live_root),
        "hard_facts": {
            "active_valid_tool_count": sum(1 for tool in TOOL_ORDER if tools[tool]["active_file"]),
            "tool_count": len(TOOL_ORDER),
        },
        "inference": {
            "operational_goal_met": all(
                tools[tool]["active_file"] and tools[tool]["eligible_file_count"] == 1 and not tools[tool]["unexpected_entries"]
                for tool in TOOL_ORDER
            )
        },
        "tools": tools,
        "warnings": _dedupe_strings(warnings),
        "blockers": _dedupe_strings(blockers),
    }


def _build_tool_promotion_report(
    *,
    tool: str,
    incoming_root: Path | None,
    explicit_source: Path | None,
    live_dir: Path,
    live_inventory: dict[str, Any],
    target_name: str | None,
    overwrite: bool,
    allow_auto_pick: bool,
) -> dict[str, Any]:
    rule = REAL_INPUT_RULES[tool]
    source_dir = (incoming_root / tool) if incoming_root else None
    source_mode = "explicit" if explicit_source else "incoming_root" if incoming_root else "not_configured"
    if explicit_source is not None:
        source_files = [explicit_source]
    elif source_dir and source_dir.exists():
        source_files = sorted([item for item in source_dir.iterdir() if item.is_file()], key=lambda item: item.name.lower())
    else:
        source_files = []

    inventory = [_describe_source_candidate(path=path, rule=rule, target_name=target_name) for path in source_files]
    selected_source, selection_reason, selection_blockers, selection_warnings, ambiguous = _select_incoming_candidate(
        tool=tool,
        source_mode=source_mode,
        inventory=inventory,
        explicit_source=explicit_source,
        allow_auto_pick=allow_auto_pick,
    )

    target_validation = _validate_target_name(tool=tool, target_name=target_name)
    target_path = None
    naming_decision_required = False
    if selected_source:
        selected_entry = next(item for item in inventory if item["path"] == str(selected_source))
        if target_validation["blockers"]:
            selection_blockers.extend(target_validation["blockers"])
        if target_name:
            target_path = live_dir / target_name
        elif selected_entry["auto_select_eligible"]:
            target_path = live_dir / selected_source.name
        else:
            naming_decision_required = True
            selection_blockers.append(
                "naming decision required because the selected incoming basename would be excluded by auto-select"
            )

    archive_plan = []
    if target_path:
        for file_info in live_inventory["all_files"]:
            if file_info["path"] != str(target_path):
                archive_plan.append(file_info["path"])

    diff_summary = _build_diff_summary(selected_source=selected_source, target_path=target_path)

    warnings = list(selection_warnings)
    blockers = list(selection_blockers)
    if live_inventory["unexpected_entries"]:
        blockers.append("live directory contains unexpected nested entries or directories")
    if live_inventory["eligible_file_count"] > 1:
        warnings.append("live directory currently contains multiple eligible files; apply will archive extras to reach one active file")
    if archive_plan and not overwrite:
        warnings.append("apply would archive existing live files; rerun with --overwrite to permit live changes")
    if target_name:
        warnings.append("explicit target name was provided by operator; preserve this decision in the receipt")
    if target_path and target_path.exists() and not overwrite:
        warnings.append("target live path already exists; rerun with --overwrite to replace it")
    if target_path and Path(target_path).name.lower() != (selected_source.name.lower() if selected_source else ""):
        warnings.append("target basename differs from source basename because operator-confirmed target naming was applied")

    return {
        "tool": tool,
        "source_mode": source_mode,
        "source_directory": str(source_dir) if source_dir else None,
        "explicit_source": str(explicit_source) if explicit_source else None,
        "incoming_inventory": inventory,
        "selected": {
            "source_path": str(selected_source) if selected_source else None,
            "selection_reason": selection_reason,
            "ambiguous_candidates": ambiguous,
            "target_path": str(target_path) if target_path else None,
            "target_name": target_name,
            "naming_decision_required": naming_decision_required,
        },
        "live_existing_inventory": live_inventory,
        "diff_summary": diff_summary,
        "archive_plan": archive_plan,
        "blockers": _dedupe_strings(blockers),
        "warnings": _dedupe_strings(warnings),
    }


def _build_directory_inventory(*, tool: str, directory: Path) -> dict[str, Any]:
    rule = REAL_INPUT_RULES[tool]
    directory.mkdir(parents=True, exist_ok=True)
    all_files = sorted([item for item in directory.iterdir() if item.is_file()], key=lambda item: item.name.lower())
    entries = [_describe_existing_file(path=file_path, rule=rule) for file_path in all_files]
    eligible = [item for item in entries if item["auto_select_eligible"]]
    eligible_sorted = sorted(
        eligible,
        key=lambda item: (item["modified_epoch"], item["size_bytes"], Path(item["path"]).name.lower()),
        reverse=True,
    )
    selected_path = eligible_sorted[0]["path"] if eligible_sorted else None
    warnings: list[str] = []
    blockers: list[str] = []
    if not eligible_sorted:
        warnings.append("no eligible live file currently auto-selects")
    if len(eligible_sorted) > 1:
        warnings.append("multiple eligible live files exist; only the latest one auto-selects")
    unexpected_entries = sorted(str(item) for item in directory.iterdir() if not item.is_file())
    if unexpected_entries:
        blockers.append("nested directories or non-file entries were found")
    for item in entries:
        item["is_active_auto_select"] = item["path"] == selected_path
    return {
        "directory": str(directory),
        "exists": directory.exists(),
        "active_file": selected_path,
        "eligible_file_count": len(eligible_sorted),
        "all_files": entries,
        "other_files": [item["path"] for item in entries if item["path"] != selected_path],
        "unexpected_entries": unexpected_entries,
        "warnings": warnings,
        "blockers": blockers,
    }


def _describe_existing_file(*, path: Path, rule: dict[str, Any]) -> dict[str, Any]:
    evaluation = _evaluate_candidate(path, rule["extensions"], int(rule["minimum_size"]))
    excluded_keywords = [item for item in EXCLUDED_NAME_PARTS if item in path.name.lower()]
    return {
        "path": str(path),
        "name": path.name,
        "size_bytes": path.stat().st_size,
        "modified_time": evaluation["modified_time"],
        "modified_epoch": path.stat().st_mtime,
        "sha256": evaluation["sha256"],
        "auto_select_eligible": bool(evaluation["eligible"]),
        "status": _inventory_status(evaluation["reasons"]),
        "reasons": evaluation["reasons"],
        "excluded_keywords": excluded_keywords,
    }


def _describe_source_candidate(*, path: Path, rule: dict[str, Any], target_name: str | None) -> dict[str, Any]:
    exists = path.exists()
    if not exists:
        return {
            "path": str(path),
            "name": path.name,
            "exists": False,
            "size_bytes": 0,
            "modified_time": None,
            "modified_epoch": 0.0,
            "sha256": None,
            "auto_select_eligible": False,
            "content_valid": False,
            "promotion_eligible": False,
            "status": "missing",
            "reasons": ["missing"],
            "excluded_keywords": [],
            "naming_decision_required": False,
            "promotion_reason": "source_missing",
            "explicit_target_name": target_name,
        }

    evaluation = _evaluate_candidate(path, rule["extensions"], int(rule["minimum_size"]))
    lower_name = path.name.lower()
    excluded_keywords = [item for item in EXCLUDED_NAME_PARTS if item in lower_name]
    content_valid = path.suffix.lower() in rule["extensions"] and path.stat().st_size >= int(rule["minimum_size"])
    naming_required = bool(excluded_keywords) and not target_name
    promotion_eligible = bool(evaluation["eligible"]) or (content_valid and bool(target_name))
    promotion_reason = "eligible_by_current_rules"
    if not content_valid:
        promotion_reason = "failed_extension_or_size_validation"
    elif excluded_keywords and target_name:
        promotion_reason = "content_valid_but_target_name_required"
    elif excluded_keywords:
        promotion_reason = "naming_decision_required"
    return {
        "path": str(path),
        "name": path.name,
        "exists": True,
        "size_bytes": path.stat().st_size,
        "modified_time": evaluation["modified_time"],
        "modified_epoch": path.stat().st_mtime,
        "sha256": evaluation["sha256"],
        "auto_select_eligible": bool(evaluation["eligible"]),
        "content_valid": content_valid,
        "promotion_eligible": promotion_eligible,
        "status": _inventory_status(evaluation["reasons"]),
        "reasons": evaluation["reasons"],
        "excluded_keywords": excluded_keywords,
        "naming_decision_required": naming_required,
        "promotion_reason": promotion_reason,
        "explicit_target_name": target_name,
    }


def _select_incoming_candidate(
    *,
    tool: str,
    source_mode: str,
    inventory: list[dict[str, Any]],
    explicit_source: Path | None,
    allow_auto_pick: bool,
) -> tuple[Path | None, str, list[str], list[str], list[str]]:
    blockers: list[str] = []
    warnings: list[str] = []
    promotion_ready = [item for item in inventory if item["promotion_eligible"]]
    naming_required = [item for item in inventory if item["content_valid"] and item["naming_decision_required"]]
    ambiguous = [item["path"] for item in promotion_ready]

    if explicit_source is not None:
        if not inventory:
            blockers.append("explicit source was provided but could not be inspected")
            return None, "explicit_missing", blockers, warnings, ambiguous
        chosen = inventory[0]
        if not chosen["promotion_eligible"]:
            blockers.append(
                "explicit source failed validation; check extension, size, excluded keyword, or provide an explicit target name"
            )
            return None, "explicit_invalid", blockers, warnings, ambiguous
        return Path(chosen["path"]), "explicit_source", blockers, warnings, ambiguous

    if source_mode == "not_configured":
        blockers.append("incoming source was not provided; use --incoming-root or a tool-specific --incoming-* option")
        return None, "source_not_configured", blockers, warnings, ambiguous
    if not inventory:
        blockers.append("no incoming files were found")
        return None, "no_incoming_files", blockers, warnings, ambiguous
    if naming_required and not promotion_ready:
        blockers.append("naming decision required before promotion because the incoming basename is excluded by auto-select")
        return Path(naming_required[0]["path"]), "naming_decision_required", blockers, warnings, [item["path"] for item in naming_required]
    if not promotion_ready:
        blockers.append("no incoming file passed validation for promotion")
        return None, "no_promotion_eligible_candidate", blockers, warnings, ambiguous
    if len(promotion_ready) > 1 and not allow_auto_pick:
        blockers.append("multiple promotion-eligible incoming candidates were found; explicit source or --allow-auto-pick is required")
        return None, "ambiguous_incoming_candidates", blockers, warnings, ambiguous

    selected_entry = sorted(
        promotion_ready,
        key=lambda item: (item["modified_epoch"], item["size_bytes"], item["name"].lower()),
        reverse=True,
    )[0]
    if len(promotion_ready) > 1 and allow_auto_pick:
        warnings.append("multiple promotion-eligible incoming candidates were found; the latest one was auto-picked")
        return Path(selected_entry["path"]), "auto_picked_latest_eligible", blockers, warnings, ambiguous
    return Path(selected_entry["path"]), "single_promotion_eligible_candidate", blockers, warnings, ambiguous


def _validate_target_name(*, tool: str, target_name: str | None) -> dict[str, list[str]]:
    blockers: list[str] = []
    if not target_name:
        return {"blockers": blockers}
    target_path = Path(target_name)
    if target_path.name != target_name or target_name.strip() != target_name:
        blockers.append("target name must be a plain filename without path segments")
        return {"blockers": blockers}
    rule = REAL_INPUT_RULES[tool]
    if target_path.suffix.lower() not in rule["extensions"]:
        blockers.append("target name extension does not satisfy the tool rule")
    if any(item in target_name.lower() for item in EXCLUDED_NAME_PARTS):
        blockers.append("target name still contains an excluded keyword")
    return {"blockers": blockers}


def _build_diff_summary(*, selected_source: Path | None, target_path: Path | None) -> dict[str, Any]:
    if not selected_source or not target_path:
        return {
            "has_changes": False,
            "before_exists": bool(target_path and target_path.exists()),
            "after_exists": False,
            "before_hash": sha256_file(target_path) if target_path and target_path.exists() else None,
            "after_hash": sha256_file(selected_source) if selected_source and selected_source.exists() else None,
            "content_changed": False,
        }
    before_hash = sha256_file(target_path) if target_path.exists() else None
    after_hash = sha256_file(selected_source)
    return {
        "has_changes": before_hash != after_hash or not target_path.exists(),
        "before_exists": target_path.exists(),
        "after_exists": True,
        "before_hash": before_hash,
        "after_hash": after_hash,
        "content_changed": before_hash != after_hash,
    }


def apply_scan_promotion(
    *,
    report: dict[str, Any],
    archive_dir: Path,
    receipt_out: Path,
    overwrite: bool,
) -> dict[str, Any]:
    blockers = list(report.get("blockers", []))
    for tool in TOOL_ORDER:
        tool_report = report["tools"][tool]
        if tool_report["selected"]["source_path"] is None:
            blockers.append(f"{tool}: no selected source is available for apply")
        if tool_report["selected"]["naming_decision_required"]:
            blockers.append(f"{tool}: naming decision is still required before apply")
        if (tool_report["archive_plan"] or tool_report["selected"]["target_path"]) and not overwrite:
            blockers.append(f"{tool}: apply would modify live files; rerun with --overwrite")

    if blockers:
        blocked = dict(report)
        blocked["status"] = "blocked"
        blocked["mode"] = "apply"
        blocked["blockers"] = _dedupe_strings(blockers)
        return blocked

    archive_dir.mkdir(parents=True, exist_ok=True)
    apply_receipts: dict[str, Any] = {}
    for tool in TOOL_ORDER:
        tool_report = report["tools"][tool]
        source_path = Path(tool_report["selected"]["source_path"])
        target_path = Path(tool_report["selected"]["target_path"])
        timestamp_dir = archive_dir / tool / datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
        timestamp_dir.mkdir(parents=True, exist_ok=True)
        archived_files = []
        before_hash = sha256_file(target_path) if target_path.exists() else None

        for existing_path in tool_report["archive_plan"]:
            source_existing = Path(existing_path)
            archive_path = timestamp_dir / source_existing.name
            shutil.move(str(source_existing), str(archive_path))
            archived_files.append(
                {
                    "source_path": existing_path,
                    "archive_path": str(archive_path),
                    "sha256": sha256_file(archive_path),
                }
            )

        atomic_copy_binary(source_path, target_path)
        apply_receipts[tool] = {
            "source_path": str(source_path),
            "target_path": str(target_path),
            "before_hash": before_hash,
            "after_hash": sha256_file(target_path),
            "source_size_bytes": source_path.stat().st_size,
            "source_mtime": _format_mtime(source_path),
            "apply_timestamp": _timestamp(),
            "archive_paths": [item["archive_path"] for item in archived_files],
            "selection_reason": tool_report["selected"]["selection_reason"],
            "target_name": target_path.name,
            "archived_files": archived_files,
        }

    live_inventory_after = build_live_scan_inventory(live_root=Path(report["live_root"]))
    receipt = {
        **report,
        "status": "applied",
        "mode": "apply",
        "archive_dir": str(archive_dir),
        "receipt_path": str(receipt_out),
        "applied_tools": apply_receipts,
        "live_inventory_after": live_inventory_after,
    }
    write_json(receipt_out, receipt)
    return receipt


def render_scan_promotion_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Scan Input Promotion Plan",
        "",
        f"- status: `{report['status']}`",
        f"- incoming_root: `{report.get('incoming_root')}`",
        f"- live_root: `{report['live_root']}`",
        f"- allow_auto_pick: `{report['allow_auto_pick']}`",
        f"- overwrite_requested: `{report['overwrite_requested']}`",
        "",
        "## Blockers",
    ]
    lines.extend([f"- {item}" for item in report["blockers"]] or ["- none"])
    lines.extend(["", "## Warnings"])
    lines.extend([f"- {item}" for item in report["warnings"]] or ["- none"])
    for tool in TOOL_ORDER:
        item = report["tools"][tool]
        selected = item["selected"]
        lines.extend(
            [
                "",
                f"## {tool}",
                f"- source_mode: `{item['source_mode']}`",
                f"- selected_source: `{selected['source_path']}`",
                f"- selection_reason: `{selected['selection_reason']}`",
                f"- target_path: `{selected['target_path']}`",
                f"- naming_decision_required: `{selected['naming_decision_required']}`",
                f"- live_active_file: `{item['live_existing_inventory']['active_file']}`",
                f"- archive_plan_count: `{len(item['archive_plan'])}`",
                f"- diff_has_changes: `{item['diff_summary']['has_changes']}`",
                "- incoming_inventory:",
            ]
        )
        if item["incoming_inventory"]:
            for candidate in item["incoming_inventory"]:
                lines.append(
                    f"  - `{candidate['path']}` | auto_select_eligible=`{candidate['auto_select_eligible']}`"
                    f" | promotion_eligible=`{candidate['promotion_eligible']}`"
                    f" | status=`{candidate['status']}` | reasons=`{','.join(candidate['reasons'])}`"
                )
        else:
            lines.append("  - none")
        lines.append("- archive_plan:")
        if item["archive_plan"]:
            for archive_item in item["archive_plan"]:
                lines.append(f"  - `{archive_item}`")
        else:
            lines.append("  - none")
    lines.extend(["", "## Guidance"])
    lines.extend(f"- {item}" for item in report["operator_guidance"])
    return "\n".join(lines) + "\n"


def render_live_inventory_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Live Scan Inventory",
        "",
        f"- status: `{report['status']}`",
        f"- live_root: `{report['live_root']}`",
        f"- active_valid_tool_count: `{report['hard_facts']['active_valid_tool_count']}`",
        f"- operational_goal_met: `{report['inference']['operational_goal_met']}`",
    ]
    for tool in TOOL_ORDER:
        item = report["tools"][tool]
        lines.extend(
            [
                "",
                f"## {tool}",
                f"- active_file: `{item['active_file']}`",
                f"- eligible_file_count: `{item['eligible_file_count']}`",
            ]
        )
        if item["all_files"]:
            for file_info in item["all_files"]:
                lines.append(
                    f"- `{file_info['path']}` | active=`{file_info['is_active_auto_select']}`"
                    f" | status=`{file_info['status']}` | reasons=`{','.join(file_info['reasons'])}`"
                )
        else:
            lines.append("- no files")
        if item["unexpected_entries"]:
            lines.append(f"- unexpected_entries: `{item['unexpected_entries']}`")
    if report["warnings"]:
        lines.extend(["", "## Warnings"])
        lines.extend(f"- {item}" for item in report["warnings"])
    if report["blockers"]:
        lines.extend(["", "## Blockers"])
        lines.extend(f"- {item}" for item in report["blockers"])
    return "\n".join(lines) + "\n"


def render_scan_receipt_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Scan Input Promotion Receipt",
        "",
        f"- status: `{report['status']}`",
        f"- archive_dir: `{report.get('archive_dir')}`",
        f"- receipt_path: `{report.get('receipt_path')}`",
    ]
    for tool in TOOL_ORDER:
        item = report.get("applied_tools", {}).get(tool)
        if not item:
            continue
        lines.extend(
            [
                "",
                f"## {tool}",
                f"- source_path: `{item['source_path']}`",
                f"- target_path: `{item['target_path']}`",
                f"- before_hash: `{item['before_hash']}`",
                f"- after_hash: `{item['after_hash']}`",
                f"- source_size_bytes: `{item['source_size_bytes']}`",
                f"- source_mtime: `{item['source_mtime']}`",
                f"- selection_reason: `{item['selection_reason']}`",
            ]
        )
        if item["archive_paths"]:
            lines.append("- archive_paths:")
            for archive_path in item["archive_paths"]:
                lines.append(f"  - `{archive_path}`")
    return "\n".join(lines) + "\n"


def _inventory_status(reasons: list[str]) -> str:
    if reasons == ["eligible"]:
        return "valid"
    if "excluded_name" in reasons:
        return "excluded"
    if "missing" in reasons:
        return "missing"
    return "invalid"


def atomic_copy_binary(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as handle:
        content = handle.read()
    with tempfile.NamedTemporaryFile("wb", dir=target.parent, delete=False) as temp_handle:
        temp_handle.write(content)
        temp_path = Path(temp_handle.name)
    temp_path.replace(target)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _format_mtime(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).replace(microsecond=0).isoformat()


def _timestamp() -> str:
    return datetime.now(tz=UTC).replace(microsecond=0).isoformat()


def _dedupe_strings(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
