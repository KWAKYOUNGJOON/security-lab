from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from vuln_pipeline.cli.main import _workspace_root
from vuln_pipeline.cli.manual_promotion import DEFAULT_LIVE_FILENAMES
from vuln_pipeline.cli.phase12_apply_reconciliation import build_apply_reconciliation
from vuln_pipeline.cli.phase12_apply_signoff import _dedupe_strings, _load_json, _nested_get, _nested_text
from vuln_pipeline.cli.real_input_readiness import build_readiness_report, render_markdown as render_readiness_markdown
from vuln_pipeline.cli.scan_input_promotion import TOOL_ORDER, render_live_inventory_markdown
from vuln_pipeline.parsers.real_inputs import (
    EXCLUDED_NAME_PARTS,
    MANUAL_INPUT_FLAGS,
    MANUAL_SELECTION_RULES,
    render_real_input_selection_summary,
)
from vuln_pipeline.report.operations import render_input_preflight_markdown
from vuln_pipeline.storage import write_json, write_markdown


READY_STATUSES = {"ready_for_rehearsal", "ready_for_rehearsal_with_warnings"}
VALID_INTENT_STATUSES = {"valid", "pass"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a strict final real gate before rehearsal.")
    parser.add_argument("--run-id")
    parser.add_argument("--run-root", type=Path)
    parser.add_argument("--workspace-root", type=Path)
    parser.add_argument("--live-root", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--previous-run-root", type=Path)
    parser.add_argument("--intent-file", type=Path)
    parser.add_argument("--preflight-run-id")
    parser.add_argument("--customer-bundle", type=Path)
    parser.add_argument("--branding-file", type=Path)
    parser.add_argument("--readiness-policy", type=Path)
    parser.add_argument("--override-file", type=Path)
    parser.add_argument("--suppression-file", type=Path)
    parser.add_argument("--review-resolution-file", type=Path)
    parser.add_argument("--refresh-preflight", action="store_true")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--md-out", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.run_root is None and not args.run_id:
        raise SystemExit("Either --run-root or --run-id is required.")

    report = build_real_gate(
        run_id=args.run_id,
        run_root=Path(args.run_root).resolve() if args.run_root else None,
        workspace_root=Path(args.workspace_root).resolve() if args.workspace_root else None,
        live_root=Path(args.live_root).resolve() if args.live_root else None,
        output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
        previous_run_root=Path(args.previous_run_root).resolve() if args.previous_run_root else None,
        intent_file=Path(args.intent_file).resolve() if args.intent_file else None,
        preflight_run_id=args.preflight_run_id,
        customer_bundle=Path(args.customer_bundle).resolve() if args.customer_bundle else None,
        branding_file=Path(args.branding_file).resolve() if args.branding_file else None,
        readiness_policy=Path(args.readiness_policy).resolve() if args.readiness_policy else None,
        override_file=Path(args.override_file).resolve() if args.override_file else None,
        suppression_file=Path(args.suppression_file).resolve() if args.suppression_file else None,
        review_resolution_file=Path(args.review_resolution_file).resolve() if args.review_resolution_file else None,
        refresh_preflight=bool(args.refresh_preflight),
        strict=bool(args.strict),
        json_out=Path(args.json_out).resolve() if args.json_out else None,
        md_out=Path(args.md_out).resolve() if args.md_out else None,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] in READY_STATUSES else 1


def build_real_gate(
    *,
    run_id: str | None,
    run_root: Path | None,
    workspace_root: Path | None,
    live_root: Path | None,
    output_dir: Path | None,
    previous_run_root: Path | None,
    intent_file: Path | None,
    preflight_run_id: str | None,
    customer_bundle: Path | None,
    branding_file: Path | None,
    readiness_policy: Path | None,
    override_file: Path | None,
    suppression_file: Path | None,
    review_resolution_file: Path | None,
    refresh_preflight: bool,
    strict: bool,
    json_out: Path | None,
    md_out: Path | None,
) -> dict[str, Any]:
    workspace_root = (workspace_root or _workspace_root()).resolve()
    output_base = workspace_root / "outputs" / "runs"
    if run_root is None:
        if not run_id:
            raise ValueError("run_id is required when run_root is omitted.")
        run_root = (output_base / run_id).resolve()
    run_id = run_id or run_root.name
    report_data_dir = output_dir or (run_root / "report_data")
    report_data_dir.mkdir(parents=True, exist_ok=True)
    live_root = (live_root or (workspace_root / "data" / "inputs" / "real")).resolve()
    live_manual_dir = live_root / "manual"

    operator_case = _load_json(report_data_dir / "phase12_operator_case.json")
    if previous_run_root is None:
        previous_run_root = _path_from_text(_nested_text(operator_case, "hard_facts", "previous_run_root", "path"))
    intent_file = intent_file or (report_data_dir / "phase12_apply_intent.json")

    config_paths = _resolve_gate_config_paths(
        workspace_root=workspace_root,
        live_root=live_root,
        report_data_dir=report_data_dir,
        customer_bundle=customer_bundle,
        branding_file=branding_file,
        readiness_policy=readiness_policy,
        override_file=override_file,
        suppression_file=suppression_file,
        review_resolution_file=review_resolution_file,
    )
    fresh_preflight_required = bool(
        refresh_preflight
        or strict
        or not (report_data_dir / "real_input_readiness.json").exists()
        or not (report_data_dir / "input_preflight.json").exists()
        or not (report_data_dir / "real_input_selection.json").exists()
    )
    freshness = _refresh_gate_artifacts(
        workspace_root=workspace_root,
        report_data_dir=report_data_dir,
        run_id=preflight_run_id or run_id,
        config_paths=config_paths,
        enabled=fresh_preflight_required,
    )

    readiness = _load_json(report_data_dir / "real_input_readiness.json") or {}
    preflight = _load_json(report_data_dir / "input_preflight.json") or {}
    selection = _load_json(report_data_dir / "real_input_selection.json") or {}
    signoff_review = _load_json(report_data_dir / "phase12_signoff_review.json")
    intent_validation = _load_json(report_data_dir / "phase12_apply_intent_validation.json")
    manual_validation = _load_json(report_data_dir / "manual_validation.json")
    rollback_plan = _load_json(report_data_dir / "phase12_rollback_plan.json")
    evidence_pack = _load_json(report_data_dir / "phase12_evidence_pack.json")
    scan_receipt = _load_json(report_data_dir / "scan_promotion" / "scan_input_promotion_receipt.json")
    manual_receipt = _load_json(report_data_dir / "manual_promotion" / "manual_promotion_receipt.json")

    apply_reconciliation = build_apply_reconciliation(
        run_root=run_root,
        workspace_root=workspace_root,
        intent_file=intent_file if intent_file.exists() else None,
        output_dir=report_data_dir,
        previous_run_root=previous_run_root,
        live_root=live_root,
        scan_receipt_dir=report_data_dir / "scan_promotion",
        manual_receipt_dir=report_data_dir / "manual_promotion",
        json_out=report_data_dir / "phase12_apply_reconciliation.json",
        md_out=report_data_dir / "phase12_apply_reconciliation.md",
    )

    live_inventory = readiness.get("live_scan_inventory") if isinstance(readiness, dict) else None
    if not isinstance(live_inventory, dict):
        live_inventory = _load_json(report_data_dir / "scan_promotion" / "live_scan_inventory.json") or {}

    scan_apply_detected = bool(isinstance(scan_receipt, dict) and scan_receipt.get("status") == "applied" and scan_receipt.get("applied_tools"))
    manual_apply_detected = bool(
        isinstance(manual_receipt, dict) and manual_receipt.get("status") == "applied" and manual_receipt.get("applied_files")
    )
    apply_detected = scan_apply_detected or manual_apply_detected

    blockers: list[str] = []
    warnings: list[str] = []
    mismatch_summary: list[str] = []

    preflight_facts = _build_preflight_facts(
        preflight=preflight,
        readiness=readiness,
        fresh_preflight_generated=freshness["generated"],
        refresh_requested=refresh_preflight,
        strict=strict,
    )
    blockers.extend(preflight_facts["blockers"])
    warnings.extend(preflight_facts["warnings"])

    if manual_validation:
        format_valid = bool(_nested_get(manual_validation, "rerun_live_context", "format_valid"))
        validation_status = _nested_text(manual_validation, "status") or "present"
        if validation_status == "invalid" or manual_validation.get("format_valid_for_rerun") is False or not format_valid:
            blockers.append("manual_validation indicates the live manual context is not ready for rerun")
    elif strict:
        blockers.append("manual_validation.json is missing")
    else:
        warnings.append("manual_validation.json is missing")

    signoff_status = _nested_text(signoff_review, "status") or "missing"
    if apply_detected:
        if signoff_status == "missing":
            blockers.append("phase12_signoff_review.json is missing after live apply")
        elif signoff_status == "not_ready_for_apply":
            blockers.append("phase12_signoff_review still reports not_ready_for_apply")
        intent_status = _nested_text(intent_validation, "status") or "missing"
        if intent_status not in VALID_INTENT_STATUSES:
            blockers.append(f"phase12_apply_intent_validation status is `{intent_status}`")
        for reason in intent_validation.get("block_reasons", []) if isinstance(intent_validation, dict) else []:
            blockers.append(f"intent_validation: {reason}")
    elif signoff_status == "missing":
        warnings.append("phase12_signoff_review.json is missing")

    tool_gate: dict[str, Any] = {}
    scan_receipt_items = scan_receipt.get("applied_tools", {}) if isinstance(scan_receipt, dict) else {}
    for tool in TOOL_ORDER:
        tool_report = _build_tool_gate_report(
            tool=tool,
            live_inventory=live_inventory,
            preflight=preflight,
            selection=selection,
            receipt_item=scan_receipt_items.get(tool) if isinstance(scan_receipt_items, dict) else None,
            apply_detected=apply_detected,
        )
        tool_gate[tool] = tool_report
        blockers.extend(f"{tool}: {item}" for item in tool_report["blockers"])
        warnings.extend(f"{tool}: {item}" for item in tool_report["warnings"])
        mismatch_summary.extend(f"{tool}: {item}" for item in tool_report["mismatch_summary"])

    manual_gate: dict[str, Any] = {}
    manual_receipt_items = {
        str(item.get("key")): item
        for item in (manual_receipt.get("applied_files", []) if isinstance(manual_receipt, dict) else [])
        if isinstance(item, dict) and item.get("key")
    }
    proof_statuses: list[str] = []
    proof_notes: list[str] = []
    for key in MANUAL_SELECTION_RULES:
        manual_report = _build_manual_gate_report(
            key=key,
            live_manual_dir=live_manual_dir,
            preflight=preflight,
            readiness=readiness,
            selection=selection,
            receipt_item=manual_receipt_items.get(key),
            strict=strict,
            apply_detected=apply_detected,
        )
        manual_gate[key] = manual_report
        proof_statuses.append(str(manual_report["proof_status"]))
        proof_notes.extend(str(item) for item in manual_report.get("proof_notes", []))
        blockers.extend(f"{key}: {item}" for item in manual_report["blockers"])
        warnings.extend(f"{key}: {item}" for item in manual_report["warnings"])
        mismatch_summary.extend(f"{key}: {item}" for item in manual_report["mismatch_summary"])

    if apply_detected:
        reconciliation_status = _nested_text(apply_reconciliation, "status") or "missing"
        if reconciliation_status == "reconciliation_failed":
            blockers.append("phase12_apply_reconciliation reported reconciliation_failed")
        elif reconciliation_status == "reconciled_with_warnings":
            warnings.append("phase12_apply_reconciliation reported reconciled_with_warnings")
    else:
        warnings.append("no live apply receipt was detected for this run")

    blockers = _dedupe_strings([item for item in blockers if item])
    warnings = _dedupe_strings([item for item in warnings if item and item not in blockers])
    mismatch_summary = _dedupe_strings([item for item in mismatch_summary if item])

    overall_proof_status = _combine_proof_statuses(proof_statuses)
    if not apply_detected:
        status = "no_live_apply_detected"
    elif blockers:
        status = "blocked"
    elif warnings:
        status = "ready_for_rehearsal_with_warnings"
    else:
        status = "ready_for_rehearsal"

    rehearsal_allowed = status in READY_STATUSES
    artifact_paths = {
        "real_input_readiness_json": _artifact(report_data_dir / "real_input_readiness.json", readiness),
        "input_preflight_json": _artifact(report_data_dir / "input_preflight.json", preflight),
        "real_input_selection_json": _artifact(report_data_dir / "real_input_selection.json", selection),
        "live_scan_inventory_json": _artifact(report_data_dir / "scan_promotion" / "live_scan_inventory.json", live_inventory),
        "manual_validation_json": _artifact(report_data_dir / "manual_validation.json", manual_validation),
        "phase12_apply_reconciliation_json": _artifact(report_data_dir / "phase12_apply_reconciliation.json", apply_reconciliation),
        "phase12_signoff_review_json": _artifact(report_data_dir / "phase12_signoff_review.json", signoff_review),
        "phase12_apply_intent_validation_json": _artifact(report_data_dir / "phase12_apply_intent_validation.json", intent_validation),
        "scan_input_promotion_receipt_json": _artifact(report_data_dir / "scan_promotion" / "scan_input_promotion_receipt.json", scan_receipt),
        "manual_promotion_receipt_json": _artifact(report_data_dir / "manual_promotion" / "manual_promotion_receipt.json", manual_receipt),
        "phase12_operator_case_json": _artifact(report_data_dir / "phase12_operator_case.json", operator_case),
        "phase12_evidence_pack_json": _artifact(report_data_dir / "phase12_evidence_pack.json", evidence_pack),
        "phase12_rollback_plan_json": _artifact(report_data_dir / "phase12_rollback_plan.json", rollback_plan),
        "intent_file": {
            "path": str(intent_file),
            "exists": bool(intent_file and intent_file.exists()),
            "status": "present" if intent_file and intent_file.exists() else "missing",
        },
    }

    commands = _build_gate_commands(
        run_id=run_id,
        run_root=run_root,
        workspace_root=workspace_root,
        live_root=live_root,
        previous_run_root=previous_run_root,
        intent_file=intent_file if intent_file.exists() else None,
        operator_case=operator_case,
        config_paths=config_paths,
    )
    report = {
        "status": status,
        "generated_at": _timestamp(),
        "hard_facts": {
            "run_id": run_id,
            "run_root": str(run_root),
            "workspace_root": str(workspace_root),
            "live_root": str(live_root),
            "live_manual_dir": str(live_manual_dir),
            "previous_run_root": str(previous_run_root) if previous_run_root else None,
            "preflight": preflight_facts,
            "apply_detected": apply_detected,
            "scan_apply_detected": scan_apply_detected,
            "manual_apply_detected": manual_apply_detected,
            "signoff_review_status": signoff_status,
            "intent_validation_status": _nested_text(intent_validation, "status") or "missing",
            "apply_reconciliation_status": _nested_text(apply_reconciliation, "status") or "missing",
            "rollback_plan_status": _nested_text(rollback_plan, "status") or "missing",
            "operator_case_status": _nested_text(operator_case, "status") or "missing",
            "evidence_pack_status": _nested_text(evidence_pack, "status") or "missing",
            "tool_gate": tool_gate,
            "manual_gate": manual_gate,
            "mismatch_summary": mismatch_summary,
            "remaining_blockers": blockers,
            "warnings": warnings,
            "fresh_artifacts": freshness,
            "artifact_paths": artifact_paths,
        },
        "inference": {
            "rehearsal_allowed": rehearsal_allowed,
            "real_explicit_proof_status": overall_proof_status,
            "proof_notes": _dedupe_strings(proof_notes),
            "summary": _build_gate_summary(
                status=status,
                rehearsal_allowed=rehearsal_allowed,
                blockers=blockers,
                warnings=warnings,
                apply_detected=apply_detected,
            ),
        },
        "suggestions": commands,
    }

    json_out = json_out or (report_data_dir / "phase12_real_gate.json")
    md_out = md_out or (report_data_dir / "phase12_real_gate.md")
    write_json(json_out, report)
    write_markdown(md_out, render_real_gate_markdown(report))
    report["json_out"] = str(json_out)
    report["md_out"] = str(md_out)
    return report


def render_real_gate_markdown(report: dict[str, Any]) -> str:
    facts = report["hard_facts"]
    inference = report["inference"]
    commands = report["suggestions"]
    lines = [
        "# Phase12 Final Real Gate",
        "",
        f"- status: `{report['status']}`",
        f"- run_id: `{facts['run_id']}`",
        f"- run_root: `{facts['run_root']}`",
        f"- rehearsal_allowed: `{inference['rehearsal_allowed']}`",
        f"- real_explicit_proof_status: `{inference['real_explicit_proof_status']}`",
        "",
        "## Hard Fact Summary",
        f"- fresh_preflight_generated: `{facts['preflight']['fresh_preflight_generated']}`",
        f"- preflight_status: `{facts['preflight']['status']}`",
        f"- preflight_blocker_count: `{facts['preflight']['blocker_count']}`",
        f"- readiness_status: `{facts['preflight']['readiness_status']}`",
        f"- readiness_blocker_count: `{facts['preflight']['readiness_blocker_count']}`",
        f"- manual_sources_ready: `{facts['preflight']['manual_sources_ready']}`",
        f"- apply_detected: `{facts['apply_detected']}`",
        f"- signoff_review_status: `{facts['signoff_review_status']}`",
        f"- intent_validation_status: `{facts['intent_validation_status']}`",
        f"- apply_reconciliation_status: `{facts['apply_reconciliation_status']}`",
        "",
        "## Current Live Active Files",
    ]
    for tool, item in facts["tool_gate"].items():
        lines.append(
            f"- {tool}: active_file=`{item['current_live_active_path']}` eligible_file_count=`{item['eligible_file_count']}`"
        )
    lines.extend(["", "## Current Preflight Selected Files"])
    for tool, item in facts["tool_gate"].items():
        lines.append(
            f"- {tool}: preflight_selected=`{item['preflight_selected_path']}` real_input_selection_selected=`{item['selection_selected_path']}`"
        )
    lines.extend(["", "## Promotion Receipt Convergence"])
    for tool, item in facts["tool_gate"].items():
        lines.append(
            f"- {tool}: receipt_present=`{item['receipt_present']}` current_live_matches_receipt_target=`{item['current_live_matches_receipt_target']}` archive_all_present=`{item['archive_all_present']}`"
        )
    for key, item in facts["manual_gate"].items():
        lines.append(
            f"- {key}: manual_source=`{item['manual_source']}` proof_status=`{item['proof_status']}` receipt_present=`{item['receipt_present']}` backup_present=`{item['backup_present']}`"
        )
    lines.extend(["", "## Remaining Blockers"])
    lines.extend([f"- {item}" for item in facts["remaining_blockers"]] or ["- none"])
    lines.extend(["", "## Warnings"])
    lines.extend([f"- {item}" for item in facts["warnings"]] or ["- none"])
    lines.extend(["", "## Proof Of real_explicit Or Why Not Proven"])
    lines.extend([f"- {item}" for item in inference["proof_notes"]] or ["- all manual sources were proven by hard fact"])
    lines.extend(["", "## Hard Fact / Inference Boundary"])
    lines.append("- hard_facts: current live files, fresh preflight selection, receipt path/hash, manual_source fields, archive/backup existence")
    lines.append("- inference: overall rehearsal_allowed decision and proof status rollup")
    lines.extend(["", "## Exact Next Commands"])
    lines.append(f"- rehearsal_command: `{commands['rehearsal_command']}`")
    lines.append(f"- missing_input_fix_command: `{commands['missing_input_fix_command']}`")
    lines.append(f"- rollback_plan_command: `{commands['rollback_plan_command']}`")
    return "\n".join(lines) + "\n"


def _refresh_gate_artifacts(
    *,
    workspace_root: Path,
    report_data_dir: Path,
    run_id: str,
    config_paths: dict[str, Path],
    enabled: bool,
) -> dict[str, Any]:
    readiness_json = report_data_dir / "real_input_readiness.json"
    readiness_md = report_data_dir / "real_input_readiness.md"
    preflight_json = report_data_dir / "input_preflight.json"
    preflight_md = report_data_dir / "input_preflight.md"
    selection_json = report_data_dir / "real_input_selection.json"
    selection_md = report_data_dir / "real_input_selection.md"
    live_inventory_json = report_data_dir / "scan_promotion" / "live_scan_inventory.json"
    live_inventory_md = report_data_dir / "scan_promotion" / "live_scan_inventory.md"

    if enabled:
        argv = [
            "--workspace-root",
            str(workspace_root),
            "--customer-bundle",
            str(config_paths["customer_bundle"]),
            "--branding-file",
            str(config_paths["branding_file"]),
            "--readiness-policy",
            str(config_paths["readiness_policy"]),
            MANUAL_INPUT_FLAGS["override_file"],
            str(config_paths["override_file"]),
            MANUAL_INPUT_FLAGS["suppression_file"],
            str(config_paths["suppression_file"]),
            MANUAL_INPUT_FLAGS["review_resolution_file"],
            str(config_paths["review_resolution_file"]),
        ]
        args = SimpleNamespace(
            workspace_root=workspace_root,
            customer_bundle=config_paths["customer_bundle"],
            branding_file=config_paths["branding_file"],
            readiness_policy=config_paths["readiness_policy"],
            override_file=config_paths["override_file"],
            suppression_file=config_paths["suppression_file"],
            review_resolution_file=config_paths["review_resolution_file"],
        )
        readiness = build_readiness_report(args=args, argv=argv)
        preflight = readiness["preflight"]
        selection = readiness["selection"]
        write_json(readiness_json, readiness)
        write_markdown(readiness_md, render_readiness_markdown(readiness))
        write_json(preflight_json, preflight)
        write_markdown(preflight_md, render_input_preflight_markdown(preflight))
        write_json(selection_json, selection)
        write_markdown(selection_md, render_real_input_selection_summary(selection, run_id))
        write_json(live_inventory_json, readiness["live_scan_inventory"])
        write_markdown(live_inventory_md, render_live_inventory_markdown(readiness["live_scan_inventory"]))

    return {
        "generated": enabled,
        "readiness_json": str(readiness_json),
        "readiness_md": str(readiness_md),
        "input_preflight_json": str(preflight_json),
        "input_preflight_md": str(preflight_md),
        "real_input_selection_json": str(selection_json),
        "real_input_selection_md": str(selection_md),
        "live_scan_inventory_json": str(live_inventory_json),
        "live_scan_inventory_md": str(live_inventory_md),
    }


def _build_preflight_facts(
    *,
    preflight: dict[str, Any],
    readiness: dict[str, Any],
    fresh_preflight_generated: bool,
    refresh_requested: bool,
    strict: bool,
) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []
    preflight_status = _nested_text(preflight, "status") or "missing"
    readiness_status = _nested_text(readiness, "status") or "missing"
    preflight_blockers = [str(item) for item in preflight.get("blockers", [])] if isinstance(preflight, dict) else []
    readiness_blockers = [str(item) for item in readiness.get("blockers", [])] if isinstance(readiness, dict) else []

    if preflight_status != "ready":
        blockers.append(f"input_preflight status is `{preflight_status}`")
    if preflight.get("blocker_count", len(preflight_blockers)) not in {0, None}:
        blockers.append(f"input_preflight blocker_count is `{preflight.get('blocker_count', len(preflight_blockers))}`")
    if readiness_status == "blocked":
        blockers.append("real_input_readiness is blocked")
    if readiness.get("blocker_count", len(readiness_blockers)) not in {0, None}:
        blockers.append(
            f"real_input_readiness blocker_count is `{readiness.get('blocker_count', len(readiness_blockers))}`"
        )
    if preflight.get("manual_sources_ready") is False:
        blockers.append("input_preflight.manual_sources_ready is false")
    if not fresh_preflight_generated:
        message = "fresh preflight was not regenerated during this gate"
        if strict:
            warnings.append(message)
        elif refresh_requested:
            blockers.append(message)
        else:
            warnings.append(message)

    return {
        "status": preflight_status,
        "blocker_count": int(preflight.get("blocker_count", len(preflight_blockers))) if isinstance(preflight, dict) else 0,
        "blockers": _dedupe_strings(preflight_blockers),
        "manual_sources_ready": bool(preflight.get("manual_sources_ready", False)) if isinstance(preflight, dict) else False,
        "readiness_status": readiness_status,
        "readiness_blocker_count": int(readiness.get("blocker_count", len(readiness_blockers))) if isinstance(readiness, dict) else 0,
        "readiness_blockers": _dedupe_strings(readiness_blockers),
        "selected_run_inputs": [str(item) for item in preflight.get("selected_run_inputs", [])] if isinstance(preflight, dict) else [],
        "fresh_preflight_generated": fresh_preflight_generated,
        "refresh_requested": refresh_requested,
        "strict": strict,
        "blockers": _dedupe_strings(blockers),
        "warnings": _dedupe_strings(warnings),
    }


def _build_tool_gate_report(
    *,
    tool: str,
    live_inventory: dict[str, Any],
    preflight: dict[str, Any],
    selection: dict[str, Any],
    receipt_item: dict[str, Any] | None,
    apply_detected: bool,
) -> dict[str, Any]:
    inventory_tool = _nested_get(live_inventory, "tools", tool) or {}
    active_path = _nested_text(inventory_tool, "active_file")
    eligible_count = int(_nested_get(inventory_tool, "eligible_file_count") or 0)
    active_hash = _hash_or_none(_path_from_text(active_path))
    preflight_selected = _first_selected_path(preflight, tool)
    selection_selected = _nested_text(selection, "tools", tool, "selected_path")
    receipt_target = _nested_text(receipt_item, "target_path")
    receipt_after_hash = _nested_text(receipt_item, "after_hash")
    archived_files = receipt_item.get("archived_files", []) if isinstance(receipt_item, dict) else []
    archive_paths = [
        _path_from_text(item.get("archive_path")) for item in archived_files if isinstance(item, dict)
    ]
    archive_all_present = all(path is not None and path.exists() for path in archive_paths) if archived_files else True

    blockers: list[str] = []
    warnings: list[str] = []
    mismatch_summary: list[str] = []
    if eligible_count != 1:
        blockers.append(f"live eligible_file_count is `{eligible_count}`")
    if not active_path:
        blockers.append("current live active file is missing")
    if active_path and any(part in Path(active_path).name.lower() for part in EXCLUDED_NAME_PARTS):
        blockers.append("current live active basename still matches an excluded keyword")
    if preflight_selected != active_path:
        blockers.append("current live active file does not match input_preflight selected file")
        mismatch_summary.append("live vs input_preflight selected mismatch")
    if selection_selected != active_path:
        blockers.append("current live active file does not match real_input_selection selected file")
        mismatch_summary.append("live vs real_input_selection selected mismatch")
    if apply_detected and receipt_item is None:
        warnings.append("no scan promotion receipt was found for this tool")
    if receipt_target and receipt_target != active_path:
        blockers.append("promotion receipt target_path does not match the current live active file")
        mismatch_summary.append("live vs receipt target mismatch")
    if receipt_after_hash and active_hash and receipt_after_hash != active_hash:
        blockers.append("current live hash does not match the promotion receipt after_hash")
        mismatch_summary.append("live hash vs receipt after_hash mismatch")
    if isinstance(receipt_item, dict) and archived_files and not archive_all_present:
        blockers.append("one or more archive files referenced by the receipt are missing")
        mismatch_summary.append("receipt archive missing")

    return {
        "current_live_active_path": active_path,
        "current_live_active_hash": active_hash,
        "eligible_file_count": eligible_count,
        "preflight_selected_path": preflight_selected,
        "selection_selected_path": selection_selected,
        "receipt_present": isinstance(receipt_item, dict),
        "receipt_target_path": receipt_target,
        "receipt_after_hash": receipt_after_hash,
        "current_live_matches_preflight_selected": bool(active_path and preflight_selected and active_path == preflight_selected),
        "current_live_matches_selection_selected": bool(active_path and selection_selected and active_path == selection_selected),
        "current_live_matches_receipt_target": bool(active_path and receipt_target and active_path == receipt_target),
        "current_live_hash_matches_receipt_after_hash": bool(active_hash and receipt_after_hash and active_hash == receipt_after_hash),
        "archive_all_present": archive_all_present,
        "archive_paths": [str(path) if path else None for path in archive_paths],
        "blockers": _dedupe_strings(blockers),
        "warnings": _dedupe_strings(warnings),
        "mismatch_summary": _dedupe_strings(mismatch_summary),
    }


def _build_manual_gate_report(
    *,
    key: str,
    live_manual_dir: Path,
    preflight: dict[str, Any],
    readiness: dict[str, Any],
    selection: dict[str, Any],
    receipt_item: dict[str, Any] | None,
    strict: bool,
    apply_detected: bool,
) -> dict[str, Any]:
    preflight_item = _nested_get(preflight, "manual_inputs", key) or {}
    readiness_item = _nested_get(readiness, "manual_support", key) or {}
    selection_item = _nested_get(selection, "manual_resolution", key) or {}
    live_path = (
        _path_from_text(preflight_item.get("effective_path"))
        or _path_from_text(readiness_item.get("effective_execution_path"))
        or _path_from_text(selection_item.get("effective_path"))
        or (live_manual_dir / DEFAULT_LIVE_FILENAMES[key])
    )
    live_exists = bool(live_path and live_path.exists())
    live_hash = _hash_or_none(live_path if live_exists else None)
    manual_source = (
        _nested_text(preflight_item, "manual_source")
        or _nested_text(readiness_item, "manual_source")
        or _nested_text(selection_item, "manual_source")
        or "missing"
    )
    receipt_after_path = _nested_text(receipt_item, "after_path")
    receipt_after_hash = _nested_text(receipt_item, "after_hash")
    backup_path = _path_from_text(_nested_text(receipt_item, "backup_path"))
    backup_present = bool(backup_path and backup_path.exists())
    blockers: list[str] = []
    warnings: list[str] = []
    mismatch_summary: list[str] = []

    proof_status = "operator-confirmation-needed"
    proof_notes: list[str] = []
    if manual_source == "real_explicit" and live_exists:
        proof_status = "hard_fact_real_explicit"
        proof_notes.append(f"{key}: manual_source=`real_explicit` and live file exists at `{live_path}`")
    elif manual_source == "legacy_default":
        proof_status = "hard_fact_legacy_default"
        proof_notes.append(f"{key}: manual_source is still `legacy_default`")
    elif live_exists and _is_relative_to(live_path, live_manual_dir):
        proof_status = "path_only_inference"
        proof_notes.append(f"{key}: effective path is under live real/manual, but real_explicit was not proven by manual_source")
    else:
        proof_notes.append(f"{key}: manual_source could not be proven from current artifacts")

    if not live_exists:
        blockers.append("current live manual file is missing")
    if manual_source == "legacy_default":
        blockers.append("manual_source is still `legacy_default`")
    elif manual_source != "real_explicit":
        message = f"manual_source is `{manual_source}` instead of `real_explicit`"
        if strict:
            blockers.append(message)
        else:
            warnings.append(message)
    if apply_detected and receipt_item is None:
        warnings.append("no manual promotion receipt was found for this file")
    if receipt_after_path and str(live_path) != receipt_after_path:
        blockers.append("current live manual path does not match receipt after_path")
        mismatch_summary.append("live path vs receipt after_path mismatch")
    if receipt_after_hash and live_hash and receipt_after_hash != live_hash:
        blockers.append("current live manual hash does not match receipt after_hash")
        mismatch_summary.append("live hash vs receipt after_hash mismatch")
    if isinstance(receipt_item, dict) and not backup_present:
        blockers.append("manual promotion backup referenced by the receipt is missing")
        mismatch_summary.append("manual backup missing")

    return {
        "current_live_path": str(live_path),
        "current_live_exists": live_exists,
        "current_live_hash": live_hash,
        "manual_source": manual_source,
        "proof_status": proof_status,
        "proof_notes": proof_notes,
        "receipt_present": isinstance(receipt_item, dict),
        "receipt_after_path": receipt_after_path,
        "receipt_after_hash": receipt_after_hash,
        "current_live_matches_receipt_path": bool(receipt_after_path and str(live_path) == receipt_after_path),
        "current_live_hash_matches_receipt_after_hash": bool(receipt_after_hash and live_hash and receipt_after_hash == live_hash),
        "backup_path": str(backup_path) if backup_path else None,
        "backup_present": backup_present,
        "blockers": _dedupe_strings(blockers),
        "warnings": _dedupe_strings(warnings),
        "mismatch_summary": _dedupe_strings(mismatch_summary),
    }


def _build_gate_commands(
    *,
    run_id: str,
    run_root: Path,
    workspace_root: Path,
    live_root: Path,
    previous_run_root: Path | None,
    intent_file: Path | None,
    operator_case: dict[str, Any] | None,
    config_paths: dict[str, Path],
) -> dict[str, Any]:
    iteration_wrapper = _workspace_root().resolve() / "app" / "vuln-pipeline" / "scripts" / "run_phase12_iteration.ps1"
    rollback_wrapper = _workspace_root().resolve() / "app" / "vuln-pipeline" / "scripts" / "run_phase12_rollback.ps1"
    output_base = run_root.parent
    working_dir = _nested_text(operator_case, "hard_facts", "working_dir", "path")
    incoming_root = _nested_text(operator_case, "hard_facts", "incoming_root", "path")
    live_manual_dir = _nested_text(operator_case, "hard_facts", "live_manual_dir", "path")

    common_parts = [
        "powershell -ExecutionPolicy Bypass -File",
        f"\"{iteration_wrapper}\"",
        f"-RunId \"{run_id}\"",
        f"-OutputBase \"{output_base}\"",
        f"-LiveRoot \"{live_root}\"",
        f"-GenerateRealGate",
        f"-RequireRealGateForRehearsal",
        f"-RefreshPreflightBeforeGate",
    ]
    if workspace_root:
        common_parts.append(f"-WorkspaceRoot \"{workspace_root}\"")
    if working_dir:
        common_parts.append(f"-WorkingDir \"{working_dir}\"")
    if incoming_root:
        common_parts.append(f"-IncomingScanRoot \"{incoming_root}\"")
    if live_manual_dir:
        common_parts.append(f"-LiveManualDir \"{live_manual_dir}\"")
    if previous_run_root:
        common_parts.append(f"-PreviousRunRoot \"{previous_run_root}\"")
    if intent_file:
        common_parts.append(f"-IntentFile \"{intent_file}\"")
    if config_paths["customer_bundle"]:
        common_parts.append(f"-CustomerBundle \"{config_paths['customer_bundle']}\"")
    if config_paths["branding_file"]:
        common_parts.append(f"-BrandingFile \"{config_paths['branding_file']}\"")
    if config_paths["readiness_policy"]:
        common_parts.append(f"-ReadinessPolicy \"{config_paths['readiness_policy']}\"")

    rollback_plan_command = (
        f"powershell -ExecutionPolicy Bypass -File \"{rollback_wrapper}\" -RunRoot \"{run_root}\" "
        f"-WorkspaceRoot \"{workspace_root}\" -LiveRoot \"{live_root}\""
    )
    return {
        "rehearsal_command": " ".join(common_parts),
        "missing_input_fix_command": " ".join(common_parts + ["-StopAfterRealGate"]),
        "rollback_plan_command": rollback_plan_command,
        "exact_next_commands": _dedupe_strings(
            [
                " ".join(common_parts),
                " ".join(common_parts + ["-StopAfterRealGate"]),
                rollback_plan_command,
            ]
        ),
    }


def _resolve_gate_config_paths(
    *,
    workspace_root: Path,
    live_root: Path,
    report_data_dir: Path,
    customer_bundle: Path | None,
    branding_file: Path | None,
    readiness_policy: Path | None,
    override_file: Path | None,
    suppression_file: Path | None,
    review_resolution_file: Path | None,
) -> dict[str, Path]:
    app_root = workspace_root / "app" / "vuln-pipeline"
    defaults = {
        "customer_bundle": app_root / "configs" / "customer_bundles" / "default_customer_release.yaml",
        "branding_file": app_root / "configs" / "branding" / "customer_branding.yaml",
        "readiness_policy": app_root / "configs" / "readiness" / "customer_release.yaml",
        "override_file": live_root / "manual" / DEFAULT_LIVE_FILENAMES["override_file"],
        "suppression_file": live_root / "manual" / DEFAULT_LIVE_FILENAMES["suppression_file"],
        "review_resolution_file": live_root / "manual" / DEFAULT_LIVE_FILENAMES["review_resolution_file"],
    }
    applied_bundle = _load_json(report_data_dir / "applied_bundle_config.json") or {}
    effective = applied_bundle.get("effective", {}) if isinstance(applied_bundle, dict) else {}
    return {
        "customer_bundle": (customer_bundle or defaults["customer_bundle"]).resolve(),
        "branding_file": (branding_file or _path_from_text(effective.get("branding_file")) or defaults["branding_file"]).resolve(),
        "readiness_policy": (
            readiness_policy or _path_from_text(effective.get("readiness_policy")) or defaults["readiness_policy"]
        ).resolve(),
        "override_file": (override_file or defaults["override_file"]).resolve(),
        "suppression_file": (suppression_file or defaults["suppression_file"]).resolve(),
        "review_resolution_file": (review_resolution_file or defaults["review_resolution_file"]).resolve(),
    }


def _build_gate_summary(
    *,
    status: str,
    rehearsal_allowed: bool,
    blockers: list[str],
    warnings: list[str],
    apply_detected: bool,
) -> str:
    if status == "no_live_apply_detected":
        return "No live apply receipt was detected, so the final gate stayed informational and rehearsal remains blocked."
    if rehearsal_allowed and not warnings:
        return "Current live files, fresh preflight, promotion receipts, and real_explicit manual proof are aligned by hard fact."
    if rehearsal_allowed:
        return f"The gate can allow rehearsal, but {len(warnings)} warning item(s) remain for operator review."
    if apply_detected:
        return f"The gate is blocked by {len(blockers)} hard-fact blocker(s)."
    return "The gate could not verify live convergence yet."


def _combine_proof_statuses(statuses: list[str]) -> str:
    unique = set(statuses)
    if unique == {"hard_fact_real_explicit"}:
        return "hard_fact_real_explicit"
    if "hard_fact_legacy_default" in unique:
        return "hard_fact_not_real_explicit"
    if unique <= {"hard_fact_real_explicit", "path_only_inference"}:
        return "mixed_hard_fact_and_path_inference"
    return "operator-confirmation-needed"


def _artifact(path: Path, payload: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "path": str(path),
        "exists": path.exists(),
        "status": _nested_text(payload, "status") or ("present" if payload else "missing"),
    }


def _first_selected_path(preflight: dict[str, Any], tool: str) -> str | None:
    selected = _nested_get(preflight, "tool_checks", tool, "selected_files")
    if isinstance(selected, list) and selected:
        first = selected[0]
        if isinstance(first, dict):
            return _nested_text(first, "path")
        return str(first)
    return None


def _path_from_text(value: str | Path | None) -> Path | None:
    if value in {None, ""}:
        return None
    return Path(str(value))


def _hash_or_none(path: Path | None) -> str | None:
    if path is None or not path.exists() or not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
