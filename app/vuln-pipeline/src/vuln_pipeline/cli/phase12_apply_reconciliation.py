from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vuln_pipeline.cli.main import _workspace_root
from vuln_pipeline.cli.manual_promotion import DEFAULT_LIVE_FILENAMES
from vuln_pipeline.cli.phase12_apply_signoff import _dedupe_strings, _load_json, _nested_get, _nested_text
from vuln_pipeline.cli.scan_input_promotion import TOOL_ORDER, build_live_scan_inventory
from vuln_pipeline.storage import write_json, write_markdown


MANUAL_KEY_ORDER = ("override_file", "suppression_file", "review_resolution_file")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Reconcile phase12 live state against signoff/apply artifacts.")
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path)
    parser.add_argument("--intent-file", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--previous-run-root", type=Path)
    parser.add_argument("--live-root", type=Path)
    parser.add_argument("--scan-receipt-dir", type=Path)
    parser.add_argument("--manual-receipt-dir", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--md-out", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    report = build_apply_reconciliation(
        run_root=Path(args.run_root).resolve(),
        workspace_root=Path(args.workspace_root).resolve() if args.workspace_root else None,
        intent_file=Path(args.intent_file).resolve() if args.intent_file else None,
        output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
        previous_run_root=Path(args.previous_run_root).resolve() if args.previous_run_root else None,
        live_root=Path(args.live_root).resolve() if args.live_root else None,
        scan_receipt_dir=Path(args.scan_receipt_dir).resolve() if args.scan_receipt_dir else None,
        manual_receipt_dir=Path(args.manual_receipt_dir).resolve() if args.manual_receipt_dir else None,
        json_out=Path(args.json_out).resolve() if args.json_out else None,
        md_out=Path(args.md_out).resolve() if args.md_out else None,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if report["status"] == "reconciliation_failed" else 0


def build_apply_reconciliation(
    *,
    run_root: Path,
    workspace_root: Path | None,
    intent_file: Path | None,
    output_dir: Path | None,
    previous_run_root: Path | None,
    live_root: Path | None,
    scan_receipt_dir: Path | None,
    manual_receipt_dir: Path | None,
    json_out: Path | None,
    md_out: Path | None,
) -> dict[str, Any]:
    report_data = run_root / "report_data"
    output_dir = output_dir or report_data
    output_dir.mkdir(parents=True, exist_ok=True)

    operator_case = _load_json(report_data / "phase12_operator_case.json")
    signoff_review = _load_json(report_data / "phase12_signoff_review.json")
    intent_file = intent_file or (report_data / "phase12_apply_intent.json")
    intent = _load_json(intent_file)
    intent_validation_path = report_data / "phase12_apply_intent_validation.json"
    intent_validation = _load_json(intent_validation_path)
    evidence_pack = _load_json(report_data / "phase12_evidence_pack.json")
    triage = _load_json(report_data / "post_run_triage.json")
    input_preflight = _load_json(report_data / "input_preflight.json")
    selection = _load_json(report_data / "real_input_selection.json")
    readiness = _load_json(report_data / "real_input_readiness.json")
    manual_validation = _load_json(report_data / "manual_validation.json")
    scan_plan = _load_json(report_data / "scan_promotion" / "scan_input_promotion_plan.json")
    live_inventory_snapshot = _load_json(report_data / "scan_promotion" / "live_scan_inventory.json")
    manual_plan = _load_json(report_data / "manual_promotion" / "manual_promotion_plan.json")

    workspace_root = (
        workspace_root
        or _path_from_payload(operator_case, "hard_facts", "workspace_root")
        or _workspace_root().resolve()
    )
    live_root = (
        live_root
        or _path_from_payload(operator_case, "hard_facts", "live_root", "path")
        or (workspace_root / "data" / "inputs" / "real")
    )
    live_manual_dir = (
        _path_from_payload(operator_case, "hard_facts", "live_manual_dir", "path")
        or (live_root / "manual")
    )
    previous_run_root = previous_run_root or _path_from_text(_nested_text(operator_case, "hard_facts", "previous_run_root", "path"))

    scan_receipt_dir = scan_receipt_dir or (report_data / "scan_promotion")
    manual_receipt_dir = manual_receipt_dir or (report_data / "manual_promotion")
    scan_receipt_path = scan_receipt_dir / "scan_input_promotion_receipt.json"
    manual_receipt_path = manual_receipt_dir / "manual_promotion_receipt.json"
    scan_receipt = _load_json(scan_receipt_path)
    manual_receipt = _load_json(manual_receipt_path)

    current_live_inventory = build_live_scan_inventory(live_root=live_root)
    manual_source_assessment = _build_manual_source_assessment(
        input_preflight=input_preflight,
        selection=selection,
        readiness=readiness,
        live_manual_dir=live_manual_dir,
    )
    scan_tool_reconciliation, scan_missing, scan_warnings = _build_scan_tool_reconciliation(
        current_live_inventory=current_live_inventory,
        input_preflight=input_preflight,
        selection=selection,
        scan_plan=scan_plan,
        scan_receipt=scan_receipt,
    )
    manual_reconciliation, manual_missing, manual_warnings = _build_manual_reconciliation(
        manual_receipt=manual_receipt,
        manual_plan=manual_plan,
        manual_validation=manual_validation,
        live_manual_dir=live_manual_dir,
    )

    scan_apply_detected = bool(isinstance(scan_receipt, dict) and scan_receipt.get("status") == "applied" and scan_receipt.get("applied_tools"))
    manual_apply_detected = bool(
        isinstance(manual_receipt, dict) and manual_receipt.get("status") == "applied" and manual_receipt.get("applied_files")
    )
    apply_detected = scan_apply_detected or manual_apply_detected

    readiness_blockers = _collect_readiness_blockers(
        triage=triage,
        signoff_review=signoff_review,
        intent_validation=intent_validation,
        readiness=readiness,
    )
    missing_artifacts = _dedupe_strings(scan_missing + manual_missing + _artifact_gaps(report_data, intent_file))
    warning_items = _dedupe_strings(scan_warnings + manual_warnings)

    status = _determine_reconciliation_status(
        apply_detected=apply_detected,
        missing_artifacts=missing_artifacts,
        warning_items=warning_items,
        scan_reconciliation=scan_tool_reconciliation,
        manual_reconciliation=manual_reconciliation,
    )
    hard_facts = {
        "run_id": run_root.name,
        "run_root": str(run_root),
        "workspace_root": str(workspace_root),
        "previous_run_root": str(previous_run_root) if previous_run_root else None,
        "live_root": str(live_root),
        "live_manual_dir": str(live_manual_dir),
        "apply_detected": apply_detected,
        "scan_promotion_applied": scan_apply_detected,
        "manual_promotion_applied": manual_apply_detected,
        "intent_file": {"path": str(intent_file), "exists": intent_file.exists()},
        "intent_validation_status": _nested_text(intent_validation, "status") or "missing",
        "signoff_review_status": _nested_text(signoff_review, "status") or "missing",
        "run_rollup": _nested_text(triage, "rollup_status") or "unknown",
        "readiness_blockers": readiness_blockers,
        "missing_artifacts": missing_artifacts,
        "scan_reconciliation": scan_tool_reconciliation,
        "manual_reconciliation": manual_reconciliation,
        "current_live_inventory": {
            "status": current_live_inventory["status"],
            "active_valid_tool_count": _nested_get(current_live_inventory, "hard_facts", "active_valid_tool_count"),
            "tools": {
                tool: {
                    "active_file": _nested_get(current_live_inventory, "tools", tool, "active_file"),
                    "eligible_file_count": _nested_get(current_live_inventory, "tools", tool, "eligible_file_count"),
                }
                for tool in TOOL_ORDER
            },
        },
    }
    inference = {
        "manual_source_real_explicit_assessment": manual_source_assessment,
        "reconciliation_summary": _build_summary_text(
            status=status,
            apply_detected=apply_detected,
            scan_apply_detected=scan_apply_detected,
            manual_apply_detected=manual_apply_detected,
            warning_items=warning_items,
            missing_artifacts=missing_artifacts,
        ),
    }
    suggestions = {
        "rerun_command": _build_rerun_command(run_root=run_root, workspace_root=workspace_root, previous_run_root=previous_run_root),
        "rollback_plan_command": _build_rollback_plan_command(run_root=run_root, workspace_root=workspace_root, live_root=live_root),
        "inspect_paths": _build_inspect_paths(
            report_data=report_data,
            intent_file=intent_file,
            scan_receipt_path=scan_receipt_path,
            manual_receipt_path=manual_receipt_path,
        ),
        "exact_next_commands": _dedupe_strings(
            [
                _build_rerun_command(run_root=run_root, workspace_root=workspace_root, previous_run_root=previous_run_root),
                _build_rollback_plan_command(run_root=run_root, workspace_root=workspace_root, live_root=live_root),
            ]
        ),
    }
    artifact_paths = {
        "phase12_signoff_review_json": _artifact(report_data / "phase12_signoff_review.json", signoff_review),
        "phase12_apply_intent_json": _artifact(intent_file, intent),
        "phase12_apply_intent_validation_json": _artifact(intent_validation_path, intent_validation),
        "scan_input_promotion_receipt_json": _artifact(scan_receipt_path, scan_receipt),
        "manual_promotion_receipt_json": _artifact(manual_receipt_path, manual_receipt),
        "live_scan_inventory_json": _artifact(report_data / "scan_promotion" / "live_scan_inventory.json", live_inventory_snapshot),
        "manual_validation_json": _artifact(report_data / "manual_validation.json", manual_validation),
        "input_preflight_json": _artifact(report_data / "input_preflight.json", input_preflight),
        "real_input_selection_json": _artifact(report_data / "real_input_selection.json", selection),
        "phase12_operator_case_json": _artifact(report_data / "phase12_operator_case.json", operator_case),
        "phase12_evidence_pack_json": _artifact(report_data / "phase12_evidence_pack.json", evidence_pack),
        "post_run_triage_json": _artifact(report_data / "post_run_triage.json", triage),
    }
    report = {
        "status": status,
        "generated_at": _timestamp(),
        "hard_facts": hard_facts,
        "inference": inference,
        "artifact_paths": artifact_paths,
        "suggestions": suggestions,
    }
    json_out = json_out or (output_dir / "phase12_apply_reconciliation.json")
    md_out = md_out or (output_dir / "phase12_apply_reconciliation.md")
    write_json(json_out, report)
    write_markdown(md_out, render_apply_reconciliation_markdown(report))
    report["json_out"] = str(json_out)
    report["md_out"] = str(md_out)
    return report


def render_apply_reconciliation_markdown(report: dict[str, Any]) -> str:
    facts = report["hard_facts"]
    lines = [
        "# Phase12 Apply Reconciliation",
        "",
        f"- status: `{report['status']}`",
        f"- run_id: `{facts['run_id']}`",
        f"- run_root: `{facts['run_root']}`",
        f"- apply_detected: `{facts['apply_detected']}`",
        f"- scan_promotion_applied: `{facts['scan_promotion_applied']}`",
        f"- manual_promotion_applied: `{facts['manual_promotion_applied']}`",
        f"- signoff_review_status: `{facts['signoff_review_status']}`",
        f"- intent_validation_status: `{facts['intent_validation_status']}`",
        "",
        "## Hard Facts",
        f"- workspace_root: `{facts['workspace_root']}`",
        f"- previous_run_root: `{facts['previous_run_root']}`",
        f"- live_root: `{facts['live_root']}`",
        f"- live_manual_dir: `{facts['live_manual_dir']}`",
        "",
        "## Readiness Blockers",
    ]
    lines.extend([f"- {item}" for item in facts["readiness_blockers"]] or ["- none"])
    lines.extend(["", "## Missing Artifacts"])
    lines.extend([f"- {item}" for item in facts["missing_artifacts"]] or ["- none"])
    lines.extend(["", "## Scan Reconciliation"])
    for tool in TOOL_ORDER:
        item = facts["scan_reconciliation"][tool]
        lines.extend(
            [
                f"### {tool}",
                f"- receipt_present: `{item['receipt_present']}`",
                f"- receipt_source_path: `{item['receipt_source_path']}`",
                f"- planned_target_path: `{item['planned_target_path']}`",
                f"- current_live_active_path: `{item['current_live_active_path']}`",
                f"- preflight_selected_path: `{item['preflight_selected_path']}`",
                f"- planned_target_matches_current_live: `{item['planned_target_matches_current_live']}`",
                f"- current_live_matches_preflight_selected: `{item['current_live_matches_preflight_selected']}`",
                f"- current_live_hash_matches_receipt_after_hash: `{item['current_live_hash_matches_receipt_after_hash']}`",
                f"- archive_ready: `{item['archive_ready']}`",
            ]
        )
        if item["missing_or_mismatch"]:
            lines.append("- missing_or_mismatch:")
            lines.extend(f"  - {entry}" for entry in item["missing_or_mismatch"])
    lines.extend(["", "## Manual Reconciliation"])
    for key in MANUAL_KEY_ORDER:
        item = facts["manual_reconciliation"][key]
        lines.extend(
            [
                f"### {key}",
                f"- receipt_present: `{item['receipt_present']}`",
                f"- current_live_path: `{item['current_live_path']}`",
                f"- current_live_exists: `{item['current_live_exists']}`",
                f"- current_live_hash: `{item['current_live_hash']}`",
                f"- receipt_after_path: `{item['receipt_after_path']}`",
                f"- current_live_matches_receipt_path: `{item['current_live_matches_receipt_path']}`",
                f"- current_live_hash_matches_receipt_after_hash: `{item['current_live_hash_matches_receipt_after_hash']}`",
                f"- backup_ready: `{item['backup_ready']}`",
            ]
        )
        if item["missing_or_mismatch"]:
            lines.append("- missing_or_mismatch:")
            lines.extend(f"  - {entry}" for entry in item["missing_or_mismatch"])
    lines.extend(
        [
            "",
            "## Inference",
            f"- manual_source_real_explicit_assessment: `{report['inference']['manual_source_real_explicit_assessment']['assessment']}`",
        ]
    )
    lines.extend(
        f"- {item}" for item in report["inference"]["manual_source_real_explicit_assessment"].get("notes", [])
    )
    lines.extend(
        [
            "",
            "## Suggestions",
            f"- rerun_command: `{report['suggestions']['rerun_command']}`",
            f"- rollback_plan_command: `{report['suggestions']['rollback_plan_command']}`",
        ]
    )
    lines.extend(f"- inspect: `{item}`" for item in report["suggestions"]["inspect_paths"])
    return "\n".join(lines) + "\n"


def _build_scan_tool_reconciliation(
    *,
    current_live_inventory: dict[str, Any],
    input_preflight: dict[str, Any] | None,
    selection: dict[str, Any] | None,
    scan_plan: dict[str, Any] | None,
    scan_receipt: dict[str, Any] | None,
) -> tuple[dict[str, Any], list[str], list[str]]:
    output: dict[str, Any] = {}
    missing: list[str] = []
    warnings: list[str] = []
    applied_tools = scan_receipt.get("applied_tools", {}) if isinstance(scan_receipt, dict) else {}
    for tool in TOOL_ORDER:
        current_active = _nested_text(current_live_inventory, "tools", tool, "active_file")
        current_hash = _hash_or_none(_path_from_text(current_active))
        planned_target = _nested_text(scan_plan, "tools", tool, "selected", "target_path")
        receipt_item = applied_tools.get(tool) if isinstance(applied_tools, dict) else None
        receipt_target = _nested_text(receipt_item, "target_path")
        receipt_after_hash = _nested_text(receipt_item, "after_hash")
        receipt_source_path = _nested_text(receipt_item, "source_path")
        receipt_present = isinstance(receipt_item, dict)
        preflight_selected = _first_selected_path(input_preflight, tool) or _nested_text(selection, "tools", tool, "selected_path")
        effective_planned_target = receipt_target or planned_target
        archive_ready = True
        mismatch: list[str] = []
        if receipt_present:
            archived_files = receipt_item.get("archived_files", [])
            for archive in archived_files if isinstance(archived_files, list) else []:
                archive_path = _path_from_text(archive.get("archive_path") if isinstance(archive, dict) else None)
                if archive_path is None or not archive_path.exists():
                    archive_ready = False
                    mismatch.append("archive metadata references a missing archive file")
        if effective_planned_target and current_active and Path(effective_planned_target) != Path(current_active):
            mismatch.append("planned target does not match the current live active file")
        if current_active and preflight_selected and Path(current_active) != Path(preflight_selected):
            mismatch.append("current live active file does not match the preflight/selection file")
        if receipt_present and receipt_after_hash and current_hash and current_hash != receipt_after_hash:
            mismatch.append("current live hash does not match receipt after_hash")
        if receipt_present and not receipt_source_path:
            mismatch.append("receipt source_path is missing")
        output[tool] = {
            "receipt_present": receipt_present,
            "receipt_source_path": receipt_source_path,
            "receipt_target_path": receipt_target,
            "receipt_after_hash": receipt_after_hash,
            "planned_target_path": effective_planned_target,
            "current_live_active_path": current_active,
            "current_live_active_hash": current_hash,
            "preflight_selected_path": preflight_selected,
            "planned_target_matches_current_live": bool(
                effective_planned_target and current_active and Path(effective_planned_target) == Path(current_active)
            ),
            "current_live_matches_preflight_selected": bool(
                current_active and preflight_selected and Path(current_active) == Path(preflight_selected)
            ),
            "current_live_hash_matches_receipt_after_hash": bool(receipt_after_hash and current_hash and current_hash == receipt_after_hash),
            "archive_ready": archive_ready,
            "missing_or_mismatch": mismatch,
        }
        warnings.extend(f"{tool}: {item}" for item in mismatch)
    return output, missing, warnings


def _build_manual_reconciliation(
    *,
    manual_receipt: dict[str, Any] | None,
    manual_plan: dict[str, Any] | None,
    manual_validation: dict[str, Any] | None,
    live_manual_dir: Path,
) -> tuple[dict[str, Any], list[str], list[str]]:
    output: dict[str, Any] = {}
    missing: list[str] = []
    warnings: list[str] = []
    applied_files = manual_receipt.get("applied_files", []) if isinstance(manual_receipt, dict) else []
    receipt_index = {
        str(item.get("key")): item for item in applied_files if isinstance(item, dict) and item.get("key")
    }
    rerun_files = _nested_get(manual_validation, "rerun_live_context", "files") if isinstance(manual_validation, dict) else {}
    for key in MANUAL_KEY_ORDER:
        receipt_item = receipt_index.get(key)
        current_live_path = _nested_text(rerun_files, key, "path")
        fallback_path = live_manual_dir / DEFAULT_LIVE_FILENAMES[key]
        effective_live_path = _path_from_text(current_live_path) or (fallback_path if fallback_path.exists() else None)
        current_hash = _hash_or_none(effective_live_path)
        receipt_present = isinstance(receipt_item, dict)
        receipt_after_path = _nested_text(receipt_item, "after_path")
        receipt_after_hash = _nested_text(receipt_item, "after_hash")
        backup_path = _path_from_text(_nested_text(receipt_item, "backup_path"))
        mismatch: list[str] = []
        if receipt_present and backup_path is not None and not backup_path.exists():
            mismatch.append("backup metadata references a missing backup file")
        if receipt_present and receipt_after_path and effective_live_path and Path(receipt_after_path) != effective_live_path:
            mismatch.append("current live manual path does not match receipt after_path")
        if receipt_present and receipt_after_hash and current_hash and current_hash != receipt_after_hash:
            mismatch.append("current live manual hash does not match receipt after_hash")
        output[key] = {
            "receipt_present": receipt_present,
            "current_live_path": str(effective_live_path) if effective_live_path else None,
            "current_live_exists": bool(effective_live_path and effective_live_path.exists()),
            "current_live_hash": current_hash,
            "receipt_after_path": receipt_after_path,
            "receipt_after_hash": receipt_after_hash,
            "current_live_matches_receipt_path": bool(
                receipt_after_path and effective_live_path and Path(receipt_after_path) == effective_live_path
            ),
            "current_live_hash_matches_receipt_after_hash": bool(
                receipt_after_hash and current_hash and receipt_after_hash == current_hash
            ),
            "backup_ready": bool(backup_path and backup_path.exists()) if receipt_present else False,
            "backup_path": str(backup_path) if backup_path else None,
            "planned_candidate_path": _nested_text(manual_plan, "files", key, "staged_candidate_path"),
            "missing_or_mismatch": mismatch,
        }
        warnings.extend(f"{key}: {item}" for item in mismatch)
    return output, missing, warnings


def _build_manual_source_assessment(
    *,
    input_preflight: dict[str, Any] | None,
    selection: dict[str, Any] | None,
    readiness: dict[str, Any] | None,
    live_manual_dir: Path,
) -> dict[str, Any]:
    notes: list[str] = []
    hard_fact_items: list[str] = []
    preflight_manual = input_preflight.get("manual_inputs", {}) if isinstance(input_preflight, dict) else {}
    readiness_manual = readiness.get("manual_support", {}) if isinstance(readiness, dict) else {}
    selection_manual = selection.get("manual_resolution", {}) if isinstance(selection, dict) else {}
    manual_sources: list[str] = []
    for key in MANUAL_KEY_ORDER:
        source = _nested_text(readiness_manual, key, "manual_source") or _nested_text(preflight_manual, key, "manual_source")
        if source:
            manual_sources.append(source)
            hard_fact_items.append(f"{key}: manual_source=`{source}`")
        effective_execution_path = _nested_text(readiness_manual, key, "effective_execution_path")
        if effective_execution_path:
            hard_fact_items.append(f"{key}: effective_execution_path=`{effective_execution_path}`")
    if manual_sources:
        if all(item == "real_explicit" for item in manual_sources):
            assessment = "hard_fact_real_explicit"
        else:
            assessment = "hard_fact_not_real_explicit"
            notes.append("At least one manual source is not `real_explicit` in readiness/preflight artifacts.")
    else:
        selected_paths = [_nested_text(selection_manual, key, "effective_path") for key in MANUAL_KEY_ORDER]
        selected_paths = [item for item in selected_paths if item]
        if selected_paths and all(str(Path(item)).startswith(str(live_manual_dir)) for item in selected_paths):
            assessment = "inference_live_manual_paths_only"
            notes.append("No explicit manual_source field was found; inference is based on effective paths under live real/manual.")
        else:
            assessment = "operator-confirmation-needed"
            notes.append("manual_source could not be proven from current artifacts.")
    return {
        "assessment": assessment,
        "hard_facts": hard_fact_items,
        "notes": notes,
    }


def _collect_readiness_blockers(
    *,
    triage: dict[str, Any] | None,
    signoff_review: dict[str, Any] | None,
    intent_validation: dict[str, Any] | None,
    readiness: dict[str, Any] | None,
) -> list[str]:
    items: list[str] = []
    for blocker in _nested_get(triage, "hard_facts", "blockers") or []:
        if isinstance(blocker, dict) and blocker.get("message"):
            items.append(str(blocker["message"]))
    items.extend(str(item) for item in (signoff_review.get("blocking_items", []) if isinstance(signoff_review, dict) else []))
    items.extend(str(item) for item in (intent_validation.get("block_reasons", []) if isinstance(intent_validation, dict) else []))
    items.extend(str(item) for item in (readiness.get("blockers", []) if isinstance(readiness, dict) else []))
    return _dedupe_strings(items)


def _artifact_gaps(report_data: Path, intent_file: Path) -> list[str]:
    required_paths = {
        "phase12_operator_case.json": report_data / "phase12_operator_case.json",
        "post_run_triage.json": report_data / "post_run_triage.json",
        "real_input_selection.json": report_data / "real_input_selection.json",
        "input_preflight.json": report_data / "input_preflight.json",
        "manual_validation.json": report_data / "manual_validation.json",
        "phase12_apply_intent.json": intent_file,
    }
    return [name for name, path in required_paths.items() if not path.exists()]


def _determine_reconciliation_status(
    *,
    apply_detected: bool,
    missing_artifacts: list[str],
    warning_items: list[str],
    scan_reconciliation: dict[str, Any],
    manual_reconciliation: dict[str, Any],
) -> str:
    if not apply_detected:
        return "no_apply_detected"
    critical = bool(missing_artifacts)
    critical = critical or any(item["missing_or_mismatch"] for item in scan_reconciliation.values())
    critical = critical or any(item["missing_or_mismatch"] for item in manual_reconciliation.values())
    if critical:
        return "reconciliation_failed"
    if warning_items:
        return "reconciled_with_warnings"
    return "reconciled"


def _build_summary_text(
    *,
    status: str,
    apply_detected: bool,
    scan_apply_detected: bool,
    manual_apply_detected: bool,
    warning_items: list[str],
    missing_artifacts: list[str],
) -> str:
    if not apply_detected:
        return "No apply receipt was detected in this run, so live reconciliation stayed limited to artifact presence and current inventory."
    if status == "reconciled":
        return "Apply receipts, current live inventory, and selection/preflight artifacts are aligned by hard fact."
    if status == "reconciled_with_warnings":
        return "Apply receipts were detected and current live state mostly aligns, but follow-up warnings remain."
    applied_parts = []
    if scan_apply_detected:
        applied_parts.append("scan")
    if manual_apply_detected:
        applied_parts.append("manual")
    return (
        f"Detected {'+'.join(applied_parts)} apply receipts, but reconciliation mismatches or missing artifacts remain: "
        f"{len(warning_items) + len(missing_artifacts)} item(s)."
    )


def _build_rerun_command(*, run_root: Path, workspace_root: Path, previous_run_root: Path | None) -> str:
    wrapper = _workspace_root().resolve() / "app" / "vuln-pipeline" / "scripts" / "run_phase12_iteration.ps1"
    parts = [
        "powershell -ExecutionPolicy Bypass -File",
        f"\"{wrapper}\"",
        f"-RunId \"{run_root.name}\"",
        f"-WorkspaceRoot \"{workspace_root}\"",
        "-GenerateSignoffReview",
    ]
    if previous_run_root:
        parts.append(f"-PreviousRunRoot \"{previous_run_root}\"")
    return " ".join(parts)


def _build_rollback_plan_command(*, run_root: Path, workspace_root: Path, live_root: Path) -> str:
    return (
        "python -m vuln_pipeline.cli.phase12_rollback "
        f"--run-root \"{run_root}\" --workspace-root \"{workspace_root}\" --live-root \"{live_root}\" --plan-only"
    )


def _build_inspect_paths(
    *,
    report_data: Path,
    intent_file: Path,
    scan_receipt_path: Path,
    manual_receipt_path: Path,
) -> list[str]:
    return [
        str(report_data / "phase12_signoff_review.json"),
        str(intent_file),
        str(report_data / "phase12_apply_intent_validation.json"),
        str(scan_receipt_path),
        str(manual_receipt_path),
        str(report_data / "input_preflight.json"),
        str(report_data / "real_input_selection.json"),
        str(report_data / "manual_validation.json"),
    ]


def _artifact(path: Path, payload: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "path": str(path),
        "exists": path.exists(),
        "status": _nested_text(payload, "status") or ("present" if payload else "missing"),
    }


def _first_selected_path(input_preflight: dict[str, Any] | None, tool: str) -> str | None:
    selected = _nested_get(input_preflight, "tool_checks", tool, "selected_files")
    if isinstance(selected, list) and selected:
        first = selected[0]
        if isinstance(first, dict):
            return _nested_text(first, "path")
        return str(first)
    return None


def _path_from_payload(payload: dict[str, Any] | None, *keys: str) -> Path | None:
    value = _nested_text(payload, *keys)
    return _path_from_text(value)


def _path_from_text(value: str | None) -> Path | None:
    return Path(value) if value else None


def _hash_or_none(path: Path | None) -> str | None:
    if path is None or not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
