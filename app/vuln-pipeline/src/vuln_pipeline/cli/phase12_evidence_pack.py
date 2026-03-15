from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vuln_pipeline.cli.phase12_apply_signoff import _dedupe_strings, _load_json, _nested_get, _nested_text
from vuln_pipeline.storage import write_json, write_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a phase12 post-run evidence pack.")
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--workspace-root", type=Path)
    parser.add_argument("--previous-run-root", type=Path)
    parser.add_argument("--intent-file", type=Path)
    parser.add_argument("--intent-validation-json", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--md-out", type=Path)
    parser.add_argument("--apply-scan-requested", action="store_true")
    parser.add_argument("--apply-manual-requested", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    pack = build_evidence_pack(
        run_root=Path(args.run_root).resolve(),
        workspace_root=Path(args.workspace_root).resolve() if args.workspace_root else None,
        previous_run_root=Path(args.previous_run_root).resolve() if args.previous_run_root else None,
        intent_file=Path(args.intent_file).resolve() if args.intent_file else None,
        intent_validation_json=Path(args.intent_validation_json).resolve() if args.intent_validation_json else None,
        output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
        json_out=Path(args.json_out).resolve() if args.json_out else None,
        md_out=Path(args.md_out).resolve() if args.md_out else None,
        apply_scan_requested=bool(args.apply_scan_requested),
        apply_manual_requested=bool(args.apply_manual_requested),
    )
    print(json.dumps(pack, ensure_ascii=False, indent=2))
    return 0


def build_evidence_pack(
    *,
    run_root: Path,
    workspace_root: Path | None,
    previous_run_root: Path | None,
    intent_file: Path | None,
    intent_validation_json: Path | None,
    output_dir: Path | None,
    json_out: Path | None,
    md_out: Path | None,
    apply_scan_requested: bool,
    apply_manual_requested: bool,
) -> dict[str, Any]:
    report_data = run_root / "report_data"
    delivery = run_root / "delivery"
    output_dir = output_dir or report_data
    output_dir.mkdir(parents=True, exist_ok=True)

    operator_case = _load_json(report_data / "phase12_operator_case.json")
    signoff_review = _load_json(report_data / "phase12_signoff_review.json")
    intent_validation_path = intent_validation_json or (report_data / "phase12_apply_intent_validation.json")
    intent_validation = _load_json(intent_validation_path)
    triage = _load_json(report_data / "post_run_triage.json")
    manual_validation = _load_json(report_data / "manual_validation.json")
    comparison = _load_json(report_data / "rerun_comparison.json")
    input_preflight = _load_json(report_data / "input_preflight.json")
    real_input_selection = _load_json(report_data / "real_input_selection.json")
    real_gate = _load_json(report_data / "phase12_real_gate.json")
    apply_reconciliation = _load_json(report_data / "phase12_apply_reconciliation.json")
    rollback_plan = _load_json(report_data / "phase12_rollback_plan.json")
    rollback_receipt = _load_json(report_data / "phase12_rollback_receipt.json")
    live_inventory = _load_json(report_data / "scan_promotion" / "live_scan_inventory.json")
    release_readiness = _load_json(report_data / "release_readiness.json")
    submission_gate = _load_json(report_data / "submission_gate.json")
    review_closure = _load_json(report_data / "review_closure_status.json")
    final_manifest = _load_json(delivery / "final_delivery_manifest.json")
    scan_receipt = _load_json(report_data / "scan_promotion" / "scan_input_promotion_receipt.json")
    manual_receipt = _load_json(report_data / "manual_promotion" / "manual_promotion_receipt.json")

    workspace_root = workspace_root or _path_from_case(operator_case, "workspace_root")
    incoming_root = _path_from_case(operator_case, "incoming_root")
    working_dir = _path_from_case(operator_case, "working_dir")
    live_dir = _path_from_case(operator_case, "live_root")
    live_manual_dir = _path_from_case(operator_case, "live_manual_dir")
    customer_zip = _find_latest(delivery, "customer_submission_*.zip")
    internal_zip = _find_latest(delivery, "internal_archive_*.zip")

    hard_facts = {
        "run_id": run_root.name,
        "run_root": str(run_root),
        "previous_run_root": str(previous_run_root) if previous_run_root else _nested_text(comparison, "previous_run_root"),
        "workspace_root": str(workspace_root) if workspace_root else None,
        "incoming_root": str(incoming_root) if incoming_root else None,
        "working_dir": str(working_dir) if working_dir else None,
        "live_dir": str(live_dir) if live_dir else None,
        "live_manual_dir": str(live_manual_dir) if live_manual_dir else None,
        "apply_flags": {
            "scan_promotion_requested": apply_scan_requested or bool(_nested_get(operator_case, "hard_facts", "apply_flags", "scan_promotion_apply_requested")),
            "manual_promotion_requested": apply_manual_requested or bool(_nested_get(operator_case, "hard_facts", "apply_flags", "manual_promotion_apply_requested")),
        },
        "intent_file": {
            "path": str(intent_file) if intent_file else None,
            "exists": bool(intent_file and intent_file.exists()),
        },
        "intent_validation": {
            "status": _nested_text(intent_validation, "status") or "missing",
            "path": str(intent_validation_path),
            "block_reasons": intent_validation.get("block_reasons", []) if isinstance(intent_validation, dict) else [],
        },
        "signoff_review": {
            "status": _nested_text(signoff_review, "status") or "missing",
            "path": str(report_data / "phase12_signoff_review.json"),
        },
        "apply_reconciliation": {
            "status": _nested_text(apply_reconciliation, "status") or "missing",
            "path": str(report_data / "phase12_apply_reconciliation.json"),
        },
        "rollback_plan": {
            "status": _nested_text(rollback_plan, "status") or "missing",
            "path": str(report_data / "phase12_rollback_plan.json"),
        },
        "rollback_receipt": {
            "status": _nested_text(rollback_receipt, "status") or "missing",
            "path": str(report_data / "phase12_rollback_receipt.json"),
        },
        "run_rollup": _nested_text(triage, "rollup_status") or "unknown",
        "blocked_reason_summary": _collect_blocked_reasons(
            triage=triage,
            operator_case=operator_case,
            input_preflight=input_preflight,
            real_gate=real_gate,
        ),
        "missing_artifacts": _nested_get(triage, "hard_facts", "missing_artifacts") or [],
        "current_live_inventory_summary": _build_live_inventory_summary(live_inventory),
        "current_preflight_selection_summary": _build_preflight_selection_summary(
            input_preflight=input_preflight,
            real_input_selection=real_input_selection,
        ),
        "real_gate": _build_real_gate_summary(real_gate),
    }
    artifact_paths = {
        "scan_promotion_receipt_json": _artifact(report_data / "scan_promotion" / "scan_input_promotion_receipt.json", scan_receipt),
        "manual_promotion_receipt_json": _artifact(report_data / "manual_promotion" / "manual_promotion_receipt.json", manual_receipt),
        "input_preflight_json": _artifact(report_data / "input_preflight.json", input_preflight),
        "real_input_selection_json": _artifact(report_data / "real_input_selection.json", real_input_selection),
        "post_run_triage_json": _artifact(report_data / "post_run_triage.json", triage),
        "manual_validation_json": _artifact(report_data / "manual_validation.json", manual_validation),
        "rerun_comparison_json": _artifact(report_data / "rerun_comparison.json", comparison),
        "release_readiness_json": _artifact(report_data / "release_readiness.json", release_readiness),
        "submission_gate_json": _artifact(report_data / "submission_gate.json", submission_gate),
        "review_closure_status_json": _artifact(report_data / "review_closure_status.json", review_closure),
        "final_delivery_manifest_json": _artifact(delivery / "final_delivery_manifest.json", final_manifest),
        "phase12_signoff_review_json": _artifact(report_data / "phase12_signoff_review.json", signoff_review),
        "phase12_apply_intent_validation_json": _artifact(intent_validation_path, intent_validation),
        "phase12_apply_reconciliation_json": _artifact(report_data / "phase12_apply_reconciliation.json", apply_reconciliation),
        "phase12_real_gate_json": _artifact(report_data / "phase12_real_gate.json", real_gate),
        "phase12_rollback_plan_json": _artifact(report_data / "phase12_rollback_plan.json", rollback_plan),
        "phase12_rollback_receipt_json": _artifact(report_data / "phase12_rollback_receipt.json", rollback_receipt),
        "live_scan_inventory_json": _artifact(report_data / "scan_promotion" / "live_scan_inventory.json", live_inventory),
        "customer_zip": {"path": str(customer_zip) if customer_zip else None, "exists": bool(customer_zip)},
        "internal_zip": {"path": str(internal_zip) if internal_zip else None, "exists": bool(internal_zip)},
    }
    suggestions = {
        "next_commands": _dedupe_strings(
            [str(item) for item in _nested_get(signoff_review, "suggestions", "exact_next_commands") or []]
            + [str(item) for item in _nested_get(intent_validation, "next_commands") or []]
            + [str(item) for item in _nested_get(apply_reconciliation, "suggestions", "exact_next_commands") or []]
            + _triage_hint_messages(triage)
        ),
        "rerun_command": _nested_text(apply_reconciliation, "suggestions", "rerun_command"),
        "rollback_plan_command": _nested_text(apply_reconciliation, "suggestions", "rollback_plan_command"),
    }

    pack = {
        "status": "captured",
        "generated_at": _timestamp(),
        "hard_facts": hard_facts,
        "artifact_paths": artifact_paths,
        "suggestions": suggestions,
    }
    json_out = json_out or (output_dir / "phase12_evidence_pack.json")
    md_out = md_out or (output_dir / "phase12_evidence_pack.md")
    write_json(json_out, pack)
    write_markdown(md_out, render_evidence_pack_markdown(pack))
    pack["json_out"] = str(json_out)
    pack["md_out"] = str(md_out)
    return pack


def render_evidence_pack_markdown(pack: dict[str, Any]) -> str:
    facts = pack["hard_facts"]
    lines = [
        "# Phase12 Evidence Pack",
        "",
        f"- run_id: `{facts['run_id']}`",
        f"- run_root: `{facts['run_root']}`",
        f"- previous_run_root: `{facts['previous_run_root']}`",
        f"- run_rollup: `{facts['run_rollup']}`",
        "",
        "## Hard Facts",
        f"- workspace_root: `{facts['workspace_root']}`",
        f"- incoming_root: `{facts['incoming_root']}`",
        f"- working_dir: `{facts['working_dir']}`",
        f"- live_dir: `{facts['live_dir']}`",
        f"- live_manual_dir: `{facts['live_manual_dir']}`",
        f"- scan_promotion_requested: `{facts['apply_flags']['scan_promotion_requested']}`",
        f"- manual_promotion_requested: `{facts['apply_flags']['manual_promotion_requested']}`",
        f"- intent_file_exists: `{facts['intent_file']['exists']}`",
        f"- intent_validation_status: `{facts['intent_validation']['status']}`",
        f"- signoff_review_status: `{facts['signoff_review']['status']}`",
        f"- apply_reconciliation_status: `{facts['apply_reconciliation']['status']}`",
        f"- real_gate_status: `{facts['real_gate']['status']}`",
        f"- real_gate_rehearsal_allowed: `{facts['real_gate']['rehearsal_allowed']}`",
        f"- real_gate_fresh_preflight_generated: `{facts['real_gate']['fresh_preflight_generated']}`",
        f"- real_gate_real_explicit_proof_status: `{facts['real_gate']['real_explicit_proof_status']}`",
        f"- rollback_plan_status: `{facts['rollback_plan']['status']}`",
        f"- rollback_receipt_status: `{facts['rollback_receipt']['status']}`",
        "",
        "## Blocked Reason Summary",
    ]
    lines.extend([f"- {item}" for item in facts["blocked_reason_summary"]] or ["- none"])
    lines.extend(["", "## Missing Artifacts"])
    lines.extend([f"- {item}" for item in facts["missing_artifacts"]] or ["- none"])
    lines.extend(["", "## Current Live Inventory Summary"])
    for tool, item in facts["current_live_inventory_summary"].items():
        lines.append(
            f"- {tool}: active_file=`{item['active_file']}` eligible_file_count=`{item['eligible_file_count']}`"
        )
    lines.extend(["", "## Current Preflight Selection Summary"])
    for tool, item in facts["current_preflight_selection_summary"].items():
        lines.append(
            f"- {tool}: input_preflight=`{item['input_preflight_selected']}` real_input_selection=`{item['real_input_selection_selected']}`"
        )
    lines.extend(["", "## Final Real Gate Summary"])
    lines.extend([f"- {item}" for item in facts["real_gate"]["summary_lines"]] or ["- none"])
    lines.extend(["", "## Artifact Paths"])
    for key, item in pack["artifact_paths"].items():
        lines.append(f"- {key}: exists=`{item['exists']}` path=`{item['path']}`")
    lines.extend(["", "## Suggestions"])
    lines.append(f"- rerun_command: `{pack['suggestions']['rerun_command']}`")
    lines.append(f"- rollback_plan_command: `{pack['suggestions']['rollback_plan_command']}`")
    lines.extend([f"- {item}" for item in pack["suggestions"]["next_commands"]] or ["- none"])
    return "\n".join(lines) + "\n"


def _artifact(path: Path, payload: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "path": str(path),
        "exists": path.exists(),
        "status": _nested_text(payload, "status") or ("present" if payload else "missing"),
    }


def _path_from_case(operator_case: dict[str, Any] | None, key: str) -> Path | None:
    value = _nested_text(operator_case, "hard_facts", key, "path")
    return Path(value) if value else None


def _find_latest(directory: Path, pattern: str) -> Path | None:
    if not directory.exists():
        return None
    matches = [path for path in directory.glob(pattern) if path.is_file()]
    if not matches:
        return None
    return sorted(matches, key=lambda item: (item.stat().st_mtime, item.name.lower()), reverse=True)[0]


def _collect_blocked_reasons(
    *,
    triage: dict[str, Any] | None,
    operator_case: dict[str, Any] | None,
    input_preflight: dict[str, Any] | None,
    real_gate: dict[str, Any] | None,
) -> list[str]:
    items: list[str] = []
    for blocker in _nested_get(triage, "hard_facts", "blockers") or []:
        if isinstance(blocker, dict):
            items.append(f"{blocker.get('source')}: {blocker.get('message')}")
    items.extend(str(item) for item in _nested_get(operator_case, "hard_facts", "blocked_reason_summary") or [])
    items.extend(str(item) for item in (input_preflight.get("blockers", []) if isinstance(input_preflight, dict) else []))
    items.extend(str(item) for item in _nested_get(real_gate, "hard_facts", "remaining_blockers") or [])
    return _dedupe_strings([item for item in items if item])


def _triage_hint_messages(triage: dict[str, Any] | None) -> list[str]:
    hints = []
    for hint in _nested_get(triage, "triage_hints") or []:
        if isinstance(hint, dict) and hint.get("message"):
            hints.append(str(hint["message"]))
    return hints


def _build_live_inventory_summary(live_inventory: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    summary: dict[str, dict[str, Any]] = {}
    for tool in ("burp", "nuclei", "httpx"):
        summary[tool] = {
            "active_file": _nested_text(live_inventory, "tools", tool, "active_file"),
            "eligible_file_count": _nested_get(live_inventory, "tools", tool, "eligible_file_count"),
        }
    return summary


def _build_preflight_selection_summary(
    *,
    input_preflight: dict[str, Any] | None,
    real_input_selection: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    summary: dict[str, dict[str, Any]] = {}
    for tool in ("burp", "nuclei", "httpx"):
        selected_files = _nested_get(input_preflight, "tool_checks", tool, "selected_files")
        summary[tool] = {
            "input_preflight_selected": selected_files[0] if isinstance(selected_files, list) and selected_files else None,
            "real_input_selection_selected": _nested_text(real_input_selection, "tools", tool, "selected_path"),
        }
    return summary


def _build_real_gate_summary(real_gate: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "status": _nested_text(real_gate, "status") or "missing",
        "rehearsal_allowed": bool(_nested_get(real_gate, "inference", "rehearsal_allowed")),
        "fresh_preflight_generated": bool(_nested_get(real_gate, "hard_facts", "preflight", "fresh_preflight_generated")),
        "real_explicit_proof_status": _nested_text(real_gate, "inference", "real_explicit_proof_status") or "missing",
        "summary_lines": _dedupe_strings(
            [str(item) for item in _nested_get(real_gate, "hard_facts", "remaining_blockers") or []]
            + [str(item) for item in _nested_get(real_gate, "hard_facts", "warnings") or []]
            + [str(item) for item in _nested_get(real_gate, "hard_facts", "mismatch_summary") or []]
        ),
    }


def _timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
