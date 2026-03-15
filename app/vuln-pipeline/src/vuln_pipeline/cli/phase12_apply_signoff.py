from __future__ import annotations

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from vuln_pipeline.cli.main import _workspace_root
from vuln_pipeline.storage import write_json, write_markdown


ACK_TEMPLATE = {
    "review_pack_read": False,
    "live_apply_is_explicit": False,
    "non_live_workspace_vs_live_dir_checked": False,
    "draft_candidates_not_auto_approved": False,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate phase12 signoff review artifacts and validate apply intent."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    review = subparsers.add_parser("review", help="Build signoff review json/md and intent template.")
    review.add_argument("--workspace-root", type=Path)
    review.add_argument("--run-id", required=True)
    review.add_argument("--output-dir", type=Path, required=True)
    review.add_argument("--scan-plan-dir", type=Path)
    review.add_argument("--manual-plan-dir", type=Path)
    review.add_argument("--operator-case", type=Path)
    review.add_argument("--previous-run-root", type=Path)
    review.add_argument("--intent-template-out", type=Path)
    review.add_argument("--review-json-out", type=Path)
    review.add_argument("--review-md-out", type=Path)

    validate = subparsers.add_parser("validate-intent", help="Validate an apply intent against the current review.")
    validate.add_argument("--intent-file", type=Path, required=True)
    validate.add_argument("--review-json", type=Path, required=True)
    validate.add_argument("--apply-scan-requested", action="store_true")
    validate.add_argument("--apply-manual-requested", action="store_true")
    validate.add_argument("--validation-json-out", type=Path)
    validate.add_argument("--validation-md-out", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "review":
        review = build_signoff_review(
            workspace_root=Path(args.workspace_root).resolve() if args.workspace_root else None,
            run_id=args.run_id,
            output_dir=Path(args.output_dir).resolve(),
            scan_plan_dir=Path(args.scan_plan_dir).resolve() if args.scan_plan_dir else None,
            manual_plan_dir=Path(args.manual_plan_dir).resolve() if args.manual_plan_dir else None,
            operator_case_path=Path(args.operator_case).resolve() if args.operator_case else None,
            previous_run_root=Path(args.previous_run_root).resolve() if args.previous_run_root else None,
            intent_template_out=Path(args.intent_template_out).resolve() if args.intent_template_out else None,
            review_json_out=Path(args.review_json_out).resolve() if args.review_json_out else None,
            review_md_out=Path(args.review_md_out).resolve() if args.review_md_out else None,
        )
        print(json.dumps(review, ensure_ascii=False, indent=2))
        return 0

    report = validate_apply_intent(
        intent_file=Path(args.intent_file).resolve(),
        review_json=Path(args.review_json).resolve(),
        apply_scan_requested=bool(args.apply_scan_requested),
        apply_manual_requested=bool(args.apply_manual_requested),
        validation_json_out=Path(args.validation_json_out).resolve() if args.validation_json_out else None,
        validation_md_out=Path(args.validation_md_out).resolve() if args.validation_md_out else None,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "valid" else 1


def build_signoff_review(
    *,
    workspace_root: Path | None,
    run_id: str,
    output_dir: Path,
    scan_plan_dir: Path | None,
    manual_plan_dir: Path | None,
    operator_case_path: Path | None,
    previous_run_root: Path | None,
    intent_template_out: Path | None,
    review_json_out: Path | None,
    review_md_out: Path | None,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    operator_case_path = operator_case_path or (output_dir / "phase12_operator_case.json")
    scan_plan_dir = scan_plan_dir or (output_dir / "scan_promotion")
    manual_plan_dir = manual_plan_dir or (output_dir / "manual_promotion")

    operator_case = _load_json(operator_case_path)
    workspace_root = workspace_root or _path_from_payload(operator_case, "hard_facts", "workspace_root") or None
    workspace_manifest_path = (Path(workspace_root) / "phase12_workspace_manifest.json") if workspace_root else None
    scan_plan_path = scan_plan_dir / "scan_input_promotion_plan.json"
    manual_plan_path = manual_plan_dir / "manual_promotion_plan.json"
    live_inventory_path = scan_plan_dir / "live_scan_inventory.json"
    manual_validation_path = output_dir / "manual_validation.json"
    rerun_comparison_path = output_dir / "rerun_comparison.json"
    post_run_triage_path = output_dir / "post_run_triage.json"

    workspace_manifest = _load_json(workspace_manifest_path)
    scan_plan = _load_json(scan_plan_path)
    manual_plan = _load_json(manual_plan_path)
    live_inventory = _load_json(live_inventory_path)
    manual_validation = _load_json(manual_validation_path)
    rerun_comparison = _load_json(rerun_comparison_path)
    post_run_triage = _load_json(post_run_triage_path)

    ambiguous_tools = []
    naming_tools = []
    for tool_name, tool_report in _iter_scan_tools(scan_plan):
        ambiguous = tool_report.get("selected", {}).get("ambiguous_candidates") or []
        if len(ambiguous) > 1 or any("ambiguous" in message.lower() for message in tool_report.get("blockers", [])):
            ambiguous_tools.append(tool_name)
        if tool_report.get("selected", {}).get("naming_decision_required"):
            naming_tools.append(tool_name)
        elif any("naming decision required" in message.lower() for message in tool_report.get("blockers", [])):
            naming_tools.append(tool_name)

    manual_status = str(manual_plan.get("status")) if isinstance(manual_plan, dict) else "missing"
    manual_material_change = bool(_nested_get(manual_plan, "status_flags", "has_material_change"))
    manual_human_selection = bool(_nested_get(manual_plan, "status_flags", "has_human_selection_required")) or manual_status == "human_selection_required"
    readiness_blockers = _collect_readiness_blockers(
        operator_case=operator_case,
        live_inventory=live_inventory,
        post_run_triage=post_run_triage,
    )
    missing_prerequisites = _collect_missing_prerequisites(
        workspace_root=workspace_root,
        workspace_manifest=workspace_manifest,
        operator_case=operator_case,
        scan_plan=scan_plan,
        manual_plan=manual_plan,
    )

    blocking_items = list(missing_prerequisites)
    if ambiguous_tools:
        blocking_items.append(
            f"operator-confirmation-needed: ambiguous incoming candidates remain for {', '.join(sorted(set(ambiguous_tools)))}"
        )
    if naming_tools:
        blocking_items.append(
            f"operator-confirmation-needed: naming decision required remains for {', '.join(sorted(set(naming_tools)))}"
        )
    if manual_human_selection:
        blocking_items.append("operator-confirmation-needed: manual draft_candidates still need human selection before live apply")
    if readiness_blockers:
        blocking_items.extend(f"operator-confirmation-needed: {item}" for item in readiness_blockers)

    review_items = []
    if isinstance(scan_plan, dict):
        review_items.extend(f"scan-plan-warning: {item}" for item in scan_plan.get("warnings", []))
        if scan_plan.get("status") == "ready_for_review":
            review_items.append("scan promotion plan still requires reviewer signoff before live apply")
    if isinstance(manual_plan, dict):
        review_items.extend(f"manual-plan-warning: {item}" for item in manual_plan.get("warnings", []))
        if manual_material_change:
            review_items.append("manual actionable changes are staged and require reviewer signoff before live apply")
        if manual_status == "ready_for_review":
            review_items.append("manual promotion plan is ready_for_review; inspect diff and candidate validation before apply")
    if isinstance(live_inventory, dict):
        review_items.extend(f"live-inventory-warning: {item}" for item in live_inventory.get("warnings", []))
    if isinstance(rerun_comparison, dict) and isinstance(rerun_comparison.get("inference"), dict):
        review_items.append(
            f"rerun comparison summary is `{rerun_comparison['inference'].get('summary')}`; use it as bounded inference only"
        )
    review_items = _dedupe_strings(review_items)
    blocking_items = _dedupe_strings(blocking_items)

    review_status = "not_ready_for_apply" if blocking_items else "review_required" if review_items else "ready_for_apply_consideration"
    fingerprints = {
        "workspace_manifest_hash": _sha256_path(workspace_manifest_path),
        "scan_plan_hash": _sha256_path(scan_plan_path),
        "manual_plan_hash": _sha256_path(manual_plan_path),
        "operator_case_hash": _sha256_path(operator_case_path),
        "live_scan_inventory_hash": _sha256_path(live_inventory_path),
    }
    artifact_paths = {
        "workspace_manifest_json": _artifact_descriptor(workspace_manifest_path, workspace_manifest),
        "operator_case_json": _artifact_descriptor(operator_case_path, operator_case),
        "scan_plan_json": _artifact_descriptor(scan_plan_path, scan_plan),
        "manual_plan_json": _artifact_descriptor(manual_plan_path, manual_plan),
        "live_scan_inventory_json": _artifact_descriptor(live_inventory_path, live_inventory),
        "manual_validation_json": _artifact_descriptor(manual_validation_path, manual_validation),
        "rerun_comparison_json": _artifact_descriptor(rerun_comparison_path, rerun_comparison),
        "post_run_triage_json": _artifact_descriptor(post_run_triage_path, post_run_triage),
    }

    review = {
        "status": review_status,
        "generated_at": _timestamp(),
        "run_id": run_id,
        "review_scope": "phase12_pre_apply_signoff",
        "hard_facts": {
            "workspace_root": str(workspace_root) if workspace_root else None,
            "incoming_root": str(_path_from_payload(workspace_manifest, "directories", "incoming_root"))
            if _path_from_payload(workspace_manifest, "directories", "incoming_root")
            else _nested_text(operator_case, "hard_facts", "incoming_root", "path"),
            "working_dir": _nested_text(operator_case, "hard_facts", "working_dir", "path"),
            "live_dir": _nested_text(operator_case, "hard_facts", "live_root", "path") or _nested_text(scan_plan, "live_root"),
            "live_manual_dir": _nested_text(operator_case, "hard_facts", "live_manual_dir", "path")
            or _nested_text(manual_plan, "live_manual_dir"),
            "previous_run_root": str(previous_run_root) if previous_run_root else _nested_text(operator_case, "hard_facts", "previous_run_root", "path"),
            "run_id": run_id,
            "output_dir": str(output_dir),
            "scan_plan_present": bool(scan_plan),
            "manual_plan_present": bool(manual_plan),
            "ambiguous_candidate_present": bool(ambiguous_tools),
            "ambiguous_tools": sorted(set(ambiguous_tools)),
            "naming_decision_required_present": bool(naming_tools),
            "naming_decision_tools": sorted(set(naming_tools)),
            "manual_actionable_change_present": manual_material_change,
            "manual_human_selection_required": manual_human_selection,
            "readiness_blocker_remaining": bool(readiness_blockers),
            "readiness_blockers": readiness_blockers,
            "missing_prerequisites": missing_prerequisites,
        },
        "blocking_items": blocking_items,
        "review_items": review_items,
        "artifact_paths": artifact_paths,
        "fingerprints": fingerprints,
        "suggestions": {
            "exact_next_commands": build_signoff_next_commands(
                workspace_root=workspace_root,
                output_dir=output_dir,
                scan_plan=scan_plan,
                manual_plan=manual_plan,
                blocking_items=blocking_items,
                review_status=review_status,
                intent_template_path=intent_template_out or (output_dir / "phase12_apply_intent.template.json"),
                previous_run_root=previous_run_root,
                operator_case_path=operator_case_path,
            )
        },
    }
    review["intent_template_defaults"] = build_intent_template_payload(
        run_id=run_id,
        review_status=review_status,
        fingerprints=fingerprints,
        blocking_items=blocking_items,
        review_items=review_items,
    )

    review_json_out = review_json_out or (output_dir / "phase12_signoff_review.json")
    review_md_out = review_md_out or (output_dir / "phase12_signoff_review.md")
    intent_template_out = intent_template_out or (output_dir / "phase12_apply_intent.template.json")
    write_json(review_json_out, review)
    write_markdown(review_md_out, render_signoff_review_markdown(review))
    write_json(intent_template_out, review["intent_template_defaults"])
    review["review_json_out"] = str(review_json_out)
    review["review_md_out"] = str(review_md_out)
    review["intent_template_out"] = str(intent_template_out)
    return review


def build_intent_template_payload(
    *,
    run_id: str,
    review_status: str,
    fingerprints: dict[str, str | None],
    blocking_items: list[str],
    review_items: list[str],
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "run_id": run_id,
        "apply_scan_promotion": False,
        "apply_manual_promotion": False,
        "review_status_seen": review_status,
        "reviewed_by": "",
        "reviewed_at": "",
        "notes": "",
        "expected_workspace_manifest_hash": fingerprints["workspace_manifest_hash"],
        "expected_scan_plan_hash": fingerprints["scan_plan_hash"],
        "expected_manual_plan_hash": fingerprints["manual_plan_hash"],
        "expected_operator_case_hash": fingerprints["operator_case_hash"],
        "expected_live_scan_inventory_hash": fingerprints["live_scan_inventory_hash"],
        "unresolved_items": blocking_items,
        "review_items_seen": review_items,
        "acknowledgements": dict(ACK_TEMPLATE),
    }


def validate_apply_intent(
    *,
    intent_file: Path,
    review_json: Path,
    apply_scan_requested: bool,
    apply_manual_requested: bool,
    validation_json_out: Path | None,
    validation_md_out: Path | None,
) -> dict[str, Any]:
    review = _load_json(review_json)
    intent = _load_json(intent_file)
    reasons: list[str] = []

    if not review:
        reasons.append(f"review json is missing or unreadable: {review_json}")
    if not intent:
        reasons.append(f"intent file is missing or unreadable: {intent_file}")

    stale_fields: list[str] = []
    if isinstance(review, dict):
        if review.get("status") == "not_ready_for_apply":
            reasons.append("signoff review still reports not_ready_for_apply")
        reasons.extend(str(item) for item in review.get("blocking_items", []))

    if isinstance(intent, dict) and isinstance(review, dict):
        expected_map = {
            "expected_workspace_manifest_hash": _nested_text(review, "fingerprints", "workspace_manifest_hash"),
            "expected_scan_plan_hash": _nested_text(review, "fingerprints", "scan_plan_hash"),
            "expected_manual_plan_hash": _nested_text(review, "fingerprints", "manual_plan_hash"),
            "expected_operator_case_hash": _nested_text(review, "fingerprints", "operator_case_hash"),
            "expected_live_scan_inventory_hash": _nested_text(review, "fingerprints", "live_scan_inventory_hash"),
        }
        for key, current_value in expected_map.items():
            if intent.get(key) != current_value:
                stale_fields.append(key)
        if stale_fields:
            reasons.append(f"intent fingerprints are stale: {', '.join(stale_fields)}")
        if apply_scan_requested and not bool(intent.get("apply_scan_promotion")):
            reasons.append("apply_scan_promotion is not acknowledged in the intent file")
        if apply_manual_requested and not bool(intent.get("apply_manual_promotion")):
            reasons.append("apply_manual_promotion is not acknowledged in the intent file")
        if not str(intent.get("reviewed_by") or "").strip():
            reasons.append("reviewed_by is empty in the intent file")
        if not str(intent.get("reviewed_at") or "").strip():
            reasons.append("reviewed_at is empty in the intent file")
        acknowledgements = intent.get("acknowledgements") if isinstance(intent.get("acknowledgements"), dict) else {}
        for key in ACK_TEMPLATE:
            if not bool(acknowledgements.get(key)):
                reasons.append(f"acknowledgement `{key}` is still false")

    report = {
        "status": "valid" if not reasons else "invalid",
        "generated_at": _timestamp(),
        "intent_file": str(intent_file),
        "review_json": str(review_json),
        "apply_scan_requested": apply_scan_requested,
        "apply_manual_requested": apply_manual_requested,
        "stale_fields": stale_fields,
        "block_reasons": _dedupe_strings(reasons),
        "next_commands": _dedupe_strings(
            [str(item) for item in review.get("suggestions", {}).get("exact_next_commands", [])] if isinstance(review, dict) else []
            + [f"Edit the intent file and validate again: `{intent_file}`"]
        ),
    }
    validation_json_out = validation_json_out or (review_json.parent / "phase12_apply_intent_validation.json")
    validation_md_out = validation_md_out or (review_json.parent / "phase12_apply_intent_validation.md")
    write_json(validation_json_out, report)
    write_markdown(validation_md_out, render_intent_validation_markdown(report))
    report["validation_json_out"] = str(validation_json_out)
    report["validation_md_out"] = str(validation_md_out)
    return report


def build_signoff_next_commands(
    *,
    workspace_root: Path | None,
    output_dir: Path,
    scan_plan: dict[str, Any] | None,
    manual_plan: dict[str, Any] | None,
    blocking_items: list[str],
    review_status: str,
    intent_template_path: Path,
    previous_run_root: Path | None,
    operator_case_path: Path,
) -> list[str]:
    repo_root = _workspace_root().resolve()
    wrapper = repo_root / "app" / "vuln-pipeline" / "scripts" / "run_phase12_iteration.ps1"
    run_id = output_dir.parent.name if output_dir.name == "report_data" else output_dir.name
    commands: list[str] = []
    if workspace_root and not (workspace_root / "phase12_workspace_manifest.json").exists():
        commands.append(
            f"bootstrap workspace first: `powershell -ExecutionPolicy Bypass -File \"{wrapper}\" -RunId \"{run_id}\" -WorkspaceRoot \"{workspace_root}\" -InitWorkspace -StopAfterBootstrap`"
        )
    if not isinstance(scan_plan, dict):
        commands.append(
            "generate scan promotion plan first: "
            f"`python -m vuln_pipeline.cli.scan_input_promotion --incoming-root \"{workspace_root / 'incoming' if workspace_root else '<workspace>\\incoming'}\" "
            f"--live-root \"{repo_root / 'data' / 'inputs' / 'real'}\" --output-dir \"{output_dir / 'scan_promotion'}\" --plan-only`"
        )
    if not isinstance(manual_plan, dict):
        commands.append(
            "generate manual promotion plan first: "
            f"`python -m vuln_pipeline.cli.manual_promotion --working-dir \"{workspace_root / 'manual-drafts' if workspace_root else '<workspace>\\manual-drafts'}\" "
            f"--live-manual-dir \"{repo_root / 'data' / 'inputs' / 'real' / 'manual'}\" --output-dir \"{output_dir / 'manual_promotion'}\" --plan-only`"
        )
    if any("ambiguous incoming candidates remain" in item for item in blocking_items):
        commands.append("resolve ambiguous incoming candidates in scan_input_promotion_plan.md before any apply")
    if any("naming decision required remains" in item for item in blocking_items):
        commands.append("set explicit target names for excluded basenames before any scan apply")
    if any("manual draft_candidates still need human selection" in item for item in blocking_items):
        commands.append("promote reviewed rows from draft_candidates into top-level actionable lists before manual apply")
    commands.append(f"read operator case hard facts: `{operator_case_path}`")
    commands.append(f"review and edit the intent template: `{intent_template_path}`")
    if review_status != "not_ready_for_apply":
        apply_parts = [
            f"powershell -ExecutionPolicy Bypass -File \"{wrapper}\"",
            f"-RunId \"{run_id}\"",
        ]
        if workspace_root:
            apply_parts.append(f"-WorkspaceRoot \"{workspace_root}\"")
        if previous_run_root:
            apply_parts.append(f"-PreviousRunRoot \"{previous_run_root}\"")
        apply_parts.extend(
            [
                f"-IntentFile \"{intent_template_path.with_name(intent_template_path.name.replace('.template', ''))}\"",
                "-ApplyScanPromotion",
                "-ApplyPromotion",
            ]
        )
        commands.append(f"when the intent is valid, run wrapper apply: `{' '.join(apply_parts)}`")
    return _dedupe_strings(commands)


def render_signoff_review_markdown(review: dict[str, Any]) -> str:
    hard_facts = review["hard_facts"]
    lines = [
        "# Phase12 Signoff Review",
        "",
        f"- status: `{review['status']}`",
        f"- run_id: `{review['run_id']}`",
        f"- generated_at: `{review['generated_at']}`",
        "",
        "## Hard Facts",
        f"- workspace_root: `{hard_facts['workspace_root']}`",
        f"- incoming_root: `{hard_facts['incoming_root']}`",
        f"- working_dir: `{hard_facts['working_dir']}`",
        f"- live_dir: `{hard_facts['live_dir']}`",
        f"- live_manual_dir: `{hard_facts['live_manual_dir']}`",
        f"- scan_plan_present: `{hard_facts['scan_plan_present']}`",
        f"- manual_plan_present: `{hard_facts['manual_plan_present']}`",
        f"- ambiguous_candidate_present: `{hard_facts['ambiguous_candidate_present']}`",
        f"- naming_decision_required_present: `{hard_facts['naming_decision_required_present']}`",
        f"- manual_actionable_change_present: `{hard_facts['manual_actionable_change_present']}`",
        f"- readiness_blocker_remaining: `{hard_facts['readiness_blocker_remaining']}`",
        "",
        "## Missing Prerequisites",
    ]
    lines.extend([f"- {item}" for item in hard_facts["missing_prerequisites"]] or ["- none"])
    lines.extend(["", "## Blocking Items"])
    lines.extend([f"- {item}" for item in review["blocking_items"]] or ["- none"])
    lines.extend(["", "## Review Items"])
    lines.extend([f"- {item}" for item in review["review_items"]] or ["- none"])
    lines.extend(["", "## Artifact Paths"])
    for key, descriptor in review["artifact_paths"].items():
        lines.append(
            f"- {key}: exists=`{descriptor['exists']}` fingerprint=`{descriptor['fingerprint']}` path=`{descriptor['path']}`"
        )
    lines.extend(["", "## Suggestions"])
    lines.extend(f"- {item}" for item in review["suggestions"]["exact_next_commands"])
    lines.extend(
        [
            "",
            "## Intent Template",
            "- apply defaults stay false until the reviewer edits the intent file.",
            "- fingerprint mismatches after a plan change make the intent stale and block live apply.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_intent_validation_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Phase12 Apply Intent Validation",
        "",
        f"- status: `{report['status']}`",
        f"- intent_file: `{report['intent_file']}`",
        f"- review_json: `{report['review_json']}`",
        f"- apply_scan_requested: `{report['apply_scan_requested']}`",
        f"- apply_manual_requested: `{report['apply_manual_requested']}`",
        "",
        "## Block Reasons",
    ]
    lines.extend([f"- {item}" for item in report["block_reasons"]] or ["- none"])
    lines.extend(["", "## Next Commands"])
    lines.extend([f"- {item}" for item in report["next_commands"]] or ["- none"])
    return "\n".join(lines) + "\n"


def _collect_missing_prerequisites(
    *,
    workspace_root: Path | None,
    workspace_manifest: dict[str, Any] | None,
    operator_case: dict[str, Any] | None,
    scan_plan: dict[str, Any] | None,
    manual_plan: dict[str, Any] | None,
) -> list[str]:
    items: list[str] = []
    if workspace_root and not workspace_manifest:
        items.append("missing prerequisite: phase12_workspace_manifest.json is absent")
    if not operator_case:
        items.append("missing prerequisite: phase12_operator_case.json is absent")
    if not scan_plan:
        items.append("missing prerequisite: scan_input_promotion_plan.json is absent")
    if not manual_plan:
        items.append("missing prerequisite: manual_promotion_plan.json is absent")
    if isinstance(scan_plan, dict) and scan_plan.get("status") == "blocked":
        items.append("missing prerequisite: scan promotion plan is still blocked")
    if isinstance(manual_plan, dict) and str(manual_plan.get("status")) in {"blocked", "invalid", "human_selection_required"}:
        items.append(f"missing prerequisite: manual promotion plan status is `{manual_plan.get('status')}`")
    return _dedupe_strings(items)


def _collect_readiness_blockers(
    *,
    operator_case: dict[str, Any] | None,
    live_inventory: dict[str, Any] | None,
    post_run_triage: dict[str, Any] | None,
) -> list[str]:
    blockers: list[str] = []
    if isinstance(operator_case, dict):
        blockers.extend(str(item) for item in _nested_get(operator_case, "hard_facts", "blocked_reason_summary") or [])
    if isinstance(live_inventory, dict):
        blockers.extend(str(item) for item in live_inventory.get("blockers", []))
    if isinstance(post_run_triage, dict):
        for item in _nested_get(post_run_triage, "hard_facts", "blockers") or []:
            if isinstance(item, dict) and item.get("message"):
                blockers.append(str(item["message"]))
    return [item for item in _dedupe_strings(blockers) if item and "warning" not in item.lower()]


def _iter_scan_tools(scan_plan: dict[str, Any] | None) -> list[tuple[str, dict[str, Any]]]:
    if not isinstance(scan_plan, dict) or not isinstance(scan_plan.get("tools"), dict):
        return []
    return [(str(tool_name), tool_report) for tool_name, tool_report in scan_plan["tools"].items() if isinstance(tool_report, dict)]


def _artifact_descriptor(path: Path | None, payload: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "path": str(path) if path else None,
        "exists": bool(path and path.exists()),
        "status": str(payload.get("status")) if isinstance(payload, dict) and payload.get("status") is not None else ("present" if payload else "missing"),
        "fingerprint": _sha256_path(path),
    }


def _load_json(path: Path | None) -> dict[str, Any] | None:
    if path is None or not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def _nested_get(payload: Any, *keys: str) -> Any:
    current = payload
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _nested_text(payload: Any, *keys: str) -> str | None:
    value = _nested_get(payload, *keys)
    if value is None or value == "":
        return None
    return str(value)


def _path_from_payload(payload: Any, *keys: str) -> Path | None:
    value = _nested_text(payload, *keys)
    return Path(value) if value else None


def _sha256_path(path: Path | None) -> str | None:
    if path is None or not path.exists():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _timestamp() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _dedupe_strings(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        text = str(item)
        if text and text not in seen:
            seen.add(text)
            ordered.append(text)
    return ordered


if __name__ == "__main__":
    raise SystemExit(main())
