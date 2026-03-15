from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from vuln_pipeline.cli.main import _workspace_root
from vuln_pipeline.cli.manual_bootstrap import build_manual_bootstrap
from vuln_pipeline.cli.scan_input_promotion import build_live_scan_inventory
from vuln_pipeline.storage import write_json, write_markdown


WORKING_DRAFT_FILENAMES = (
    "override_working.yaml",
    "suppression_working.yaml",
    "review_resolution_working.yaml",
)
ACTIONABLE_KEYS = {
    "override_working.yaml": "overrides",
    "suppression_working.yaml": "suppressions",
    "review_resolution_working.yaml": "review_resolutions",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Bootstrap a non-live phase12 operator workspace or emit an operator case manifest."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    bootstrap = subparsers.add_parser("bootstrap", help="Create a safe non-live workspace for phase12 operator flow.")
    bootstrap.add_argument("--workspace-root", type=Path, required=True)
    bootstrap.add_argument("--seed-from-run-root", type=Path)
    bootstrap.add_argument("--seed-from-templates", action="store_true")
    bootstrap.add_argument("--output-dir", type=Path)
    bootstrap.add_argument("--manifest-out", type=Path)
    bootstrap.add_argument("--live-root", type=Path)
    bootstrap.add_argument("--live-manual-dir", type=Path)
    bootstrap.add_argument("--run-id", type=str, default="phase12-first-real-run")
    bootstrap.add_argument("--previous-run-root", type=Path)
    bootstrap.add_argument("--overwrite", action="store_true")

    operator_case = subparsers.add_parser("operator-case", help="Write a phase12 operator case manifest.")
    operator_case.add_argument("--case-phase", default="pre-run")
    operator_case.add_argument("--run-id", type=str, required=True)
    operator_case.add_argument("--run-root", type=Path, required=True)
    operator_case.add_argument("--workspace-root", type=Path)
    operator_case.add_argument("--working-dir", type=Path, required=True)
    operator_case.add_argument("--incoming-root", type=Path, required=True)
    operator_case.add_argument("--live-root", type=Path, required=True)
    operator_case.add_argument("--live-manual-dir", type=Path, required=True)
    operator_case.add_argument("--previous-run-root", type=Path)
    operator_case.add_argument("--customer-bundle", type=Path)
    operator_case.add_argument("--branding-file", type=Path)
    operator_case.add_argument("--readiness-policy", type=Path)
    operator_case.add_argument("--wrapper-script", type=Path)
    operator_case.add_argument("--app-root", type=Path)
    operator_case.add_argument("--json-out", type=Path)
    operator_case.add_argument("--markdown-out", type=Path)
    operator_case.add_argument("--apply-scan-promotion", action="store_true")
    operator_case.add_argument("--apply-promotion", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "bootstrap":
        summary = execute_workspace_bootstrap(
            workspace_root=Path(args.workspace_root).resolve(),
            seed_from_run_root=Path(args.seed_from_run_root).resolve() if args.seed_from_run_root else None,
            seed_from_templates=bool(args.seed_from_templates),
            output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
            manifest_out=Path(args.manifest_out).resolve() if args.manifest_out else None,
            live_root=Path(args.live_root).resolve() if args.live_root else None,
            live_manual_dir=Path(args.live_manual_dir).resolve() if args.live_manual_dir else None,
            run_id=args.run_id,
            previous_run_root=Path(args.previous_run_root).resolve() if args.previous_run_root else None,
            overwrite=bool(args.overwrite),
        )
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    summary = execute_operator_case(
        case_phase=args.case_phase,
        run_id=args.run_id,
        run_root=Path(args.run_root).resolve(),
        workspace_root=Path(args.workspace_root).resolve() if args.workspace_root else None,
        working_dir=Path(args.working_dir).resolve(),
        incoming_root=Path(args.incoming_root).resolve(),
        live_root=Path(args.live_root).resolve(),
        live_manual_dir=Path(args.live_manual_dir).resolve(),
        previous_run_root=Path(args.previous_run_root).resolve() if args.previous_run_root else None,
        customer_bundle=Path(args.customer_bundle).resolve() if args.customer_bundle else None,
        branding_file=Path(args.branding_file).resolve() if args.branding_file else None,
        readiness_policy=Path(args.readiness_policy).resolve() if args.readiness_policy else None,
        wrapper_script=Path(args.wrapper_script).resolve() if args.wrapper_script else None,
        app_root=Path(args.app_root).resolve() if args.app_root else None,
        json_out=Path(args.json_out).resolve() if args.json_out else None,
        markdown_out=Path(args.markdown_out).resolve() if args.markdown_out else None,
        apply_scan_promotion=bool(args.apply_scan_promotion),
        apply_promotion=bool(args.apply_promotion),
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def execute_workspace_bootstrap(
    *,
    workspace_root: Path,
    seed_from_run_root: Path | None,
    seed_from_templates: bool,
    output_dir: Path | None,
    manifest_out: Path | None,
    live_root: Path | None,
    live_manual_dir: Path | None,
    run_id: str,
    previous_run_root: Path | None,
    overwrite: bool,
) -> dict[str, Any]:
    repo_workspace_root = _workspace_root().resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)
    output_dir = output_dir or workspace_root
    manifest_base = manifest_out or (output_dir / "phase12_workspace_manifest")
    live_root = live_root or (repo_workspace_root / "data" / "inputs" / "real")
    live_manual_dir = live_manual_dir or (live_root / "manual")

    directories = {
        "workspace_root": workspace_root,
        "incoming_root": workspace_root / "incoming",
        "incoming_burp": workspace_root / "incoming" / "burp",
        "incoming_nuclei": workspace_root / "incoming" / "nuclei",
        "incoming_httpx": workspace_root / "incoming" / "httpx",
        "manual_drafts": workspace_root / "manual-drafts",
        "receipts": workspace_root / "receipts",
        "artifacts": workspace_root / "artifacts",
        "report_data": workspace_root / "report_data",
    }
    created_directories: list[str] = []
    for path in directories.values():
        if not path.exists():
            created_directories.append(str(path))
        path.mkdir(parents=True, exist_ok=True)

    seed_mode = "empty"
    seed_summary: dict[str, Any] | None = None
    if seed_from_run_root:
        seed_mode = "from_run_root"
        seed_summary = build_manual_bootstrap(
            output_dir=directories["manual_drafts"],
            run_root=seed_from_run_root,
            review_queue_path=None,
            workspace_root=repo_workspace_root,
            overwrite=overwrite,
        )
    elif seed_from_templates:
        seed_mode = "from_templates"
        seed_summary = build_manual_bootstrap(
            output_dir=directories["manual_drafts"],
            run_root=None,
            review_queue_path=None,
            workspace_root=repo_workspace_root,
            overwrite=overwrite,
        )

    empty_required_items = [
        "incoming/burp is empty; operator must drop a real Burp export into the non-live workspace before planning scan promotion.",
        "incoming/nuclei is empty; operator must drop a real nuclei export into the non-live workspace before planning scan promotion.",
        "incoming/httpx is empty; operator must drop a real httpx export into the non-live workspace before planning scan promotion.",
    ]
    if seed_mode == "empty":
        empty_required_items.append("manual-drafts does not contain seeded working files yet.")
    else:
        empty_required_items.extend(_manual_draft_empty_items(directories["manual_drafts"]))

    summary = {
        "status": "bootstrapped",
        "generated_at": _timestamp(),
        "workspace_root": str(workspace_root),
        "repo_workspace_root": str(repo_workspace_root),
        "run_id": run_id,
        "previous_run_root": str(previous_run_root) if previous_run_root else None,
        "seed_mode": seed_mode,
        "seed_summary": seed_summary,
        "directories": {key: str(value) for key, value in directories.items()},
        "live_real_dir": str(live_root),
        "live_manual_dir": str(live_manual_dir),
        "created_directories": created_directories,
        "empty_required_items": empty_required_items,
        "operator_confirmation_needed": [
            "Confirm which real incoming exports should be promoted; the bootstrap does not inspect or copy live scan files.",
            "Keep live real directories and this non-live workspace separate. Bootstrap never writes into data\\inputs\\real.",
            "Review draft_candidates manually and copy only approved rows into overrides/suppressions/review_resolutions.",
        ],
        "recommended_next_commands": build_bootstrap_next_commands(
            repo_workspace_root=repo_workspace_root,
            workspace_root=workspace_root,
            run_id=run_id,
            previous_run_root=previous_run_root,
            seed_mode=seed_mode,
        ),
        "notes": [
            "This helper only creates non-live operator workspace structure and optional working drafts.",
            "No sample or dummy scan exports were created in incoming/*.",
            "Live real directories were referenced for guidance only and were not modified.",
        ],
    }

    json_path = manifest_base.with_suffix(".json")
    md_path = manifest_base.with_suffix(".md")
    write_json(json_path, summary)
    write_markdown(md_path, render_workspace_manifest_markdown(summary))
    summary["manifest_json"] = str(json_path)
    summary["manifest_md"] = str(md_path)
    return summary


def execute_operator_case(
    *,
    case_phase: str,
    run_id: str,
    run_root: Path,
    workspace_root: Path | None,
    working_dir: Path,
    incoming_root: Path,
    live_root: Path,
    live_manual_dir: Path,
    previous_run_root: Path | None,
    customer_bundle: Path | None,
    branding_file: Path | None,
    readiness_policy: Path | None,
    wrapper_script: Path | None,
    app_root: Path | None,
    json_out: Path | None,
    markdown_out: Path | None,
    apply_scan_promotion: bool,
    apply_promotion: bool,
) -> dict[str, Any]:
    report_data_dir = run_root / "report_data"
    paths = {
        "scan_plan_json": report_data_dir / "scan_promotion" / "scan_input_promotion_plan.json",
        "scan_receipt_json": report_data_dir / "scan_promotion" / "scan_input_promotion_receipt.json",
        "manual_plan_json": report_data_dir / "manual_promotion" / "manual_promotion_plan.json",
        "manual_receipt_json": report_data_dir / "manual_promotion" / "manual_promotion_receipt.json",
        "readiness_json": report_data_dir / "real_input_readiness.json",
        "input_preflight_json": report_data_dir / "input_preflight.json",
        "real_input_selection_json": report_data_dir / "real_input_selection.json",
        "post_run_triage_json": report_data_dir / "post_run_triage.json",
        "manual_validation_json": report_data_dir / "manual_validation.json",
        "rerun_comparison_json": report_data_dir / "rerun_comparison.json",
        "real_gate_json": report_data_dir / "phase12_real_gate.json",
        "release_readiness_json": report_data_dir / "release_readiness.json",
        "submission_gate_json": report_data_dir / "submission_gate.json",
        "review_closure_json": report_data_dir / "review_closure_status.json",
        "final_delivery_manifest_json": run_root / "delivery" / "final_delivery_manifest.json",
    }
    payloads = {key: _load_json(path) for key, path in paths.items()}
    live_inventory = build_live_scan_inventory(live_root=live_root)
    incoming_state = _describe_incoming_root(incoming_root)
    working_state = _describe_working_dir(working_dir)

    hard_facts = {
        "case_phase": case_phase,
        "run_id": run_id,
        "run_root": str(run_root),
        "report_data_dir": str(report_data_dir),
        "workspace_root": str(workspace_root) if workspace_root else None,
        "working_dir": {**_path_state(working_dir), **working_state},
        "incoming_root": {**_path_state(incoming_root), **incoming_state},
        "live_root": _path_state(live_root),
        "live_manual_dir": _path_state(live_manual_dir),
        "previous_run_root": _path_state(previous_run_root),
        "customer_bundle": _path_state(customer_bundle),
        "branding_file": _path_state(branding_file),
        "readiness_policy": _path_state(readiness_policy),
        "apply_flags": {
            "scan_promotion_apply_requested": apply_scan_promotion,
            "manual_promotion_apply_requested": apply_promotion,
        },
        "artifact_paths": {key: {"path": str(path), "exists": path.exists()} for key, path in paths.items()},
        "artifact_statuses": _artifact_statuses(payloads),
        "scan_live_readiness": {
            "inventory_status": live_inventory["status"],
            "active_valid_tool_count": live_inventory["hard_facts"]["active_valid_tool_count"],
            "operational_goal_met": live_inventory["inference"]["operational_goal_met"],
            "warnings": live_inventory.get("warnings", []),
            "blockers": live_inventory.get("blockers", []),
        },
        "real_gate_summary": _build_real_gate_summary(payloads.get("real_gate_json")),
        "blocked_reason_summary": _collect_blocked_reasons(payloads),
    }

    summary = {
        "status": "captured",
        "generated_at": _timestamp(),
        "hard_facts": hard_facts,
        "suggestions": {
            "operator_confirmation_needed": _collect_operator_confirmation_needed(
                incoming_state=incoming_state,
                working_state=working_state,
                payloads=payloads,
                apply_scan_promotion=apply_scan_promotion,
                apply_promotion=apply_promotion,
            ),
            "exact_next_commands": build_operator_case_commands(
                repo_workspace_root=_workspace_root().resolve(),
                workspace_root=workspace_root,
                run_id=run_id,
                run_root=run_root,
                working_dir=working_dir,
                incoming_root=incoming_root,
                live_root=live_root,
                live_manual_dir=live_manual_dir,
                previous_run_root=previous_run_root,
                wrapper_script=wrapper_script,
                app_root=app_root,
                working_state=working_state,
                incoming_state=incoming_state,
                payloads=payloads,
            ),
        },
    }
    json_path = json_out or (report_data_dir / "phase12_operator_case.json")
    md_path = markdown_out or (report_data_dir / "phase12_operator_case.md")
    write_json(json_path, summary)
    write_markdown(md_path, render_operator_case_markdown(summary))
    summary["json_out"] = str(json_path)
    summary["markdown_out"] = str(md_path)
    return summary


def build_bootstrap_next_commands(
    *,
    repo_workspace_root: Path,
    workspace_root: Path,
    run_id: str,
    previous_run_root: Path | None,
    seed_mode: str,
) -> list[str]:
    wrapper = repo_workspace_root / "app" / "vuln-pipeline" / "scripts" / "run_phase12_iteration.ps1"
    commands = [
        (
            "1. Drop real Burp/nuclei/httpx exports into the non-live incoming directories under "
            f"`{workspace_root / 'incoming'}`. Do not place templates or dummy files there."
        ),
        (
            f"2. `python -m vuln_pipeline.cli.scan_input_promotion --incoming-root \"{workspace_root / 'incoming'}\" "
            f"--live-root \"{repo_workspace_root / 'data' / 'inputs' / 'real'}\" "
            f"--output-dir \"{repo_workspace_root / 'outputs' / 'runs' / run_id / 'report_data' / 'scan_promotion'}\" --plan-only`"
        ),
        (
            f"3. `python -m vuln_pipeline.cli.manual_promotion --working-dir \"{workspace_root / 'manual-drafts'}\" "
            f"--live-manual-dir \"{repo_workspace_root / 'data' / 'inputs' / 'real' / 'manual'}\" "
            f"--output-dir \"{repo_workspace_root / 'outputs' / 'runs' / run_id / 'report_data' / 'manual_promotion'}\" --plan-only`"
        ),
        (
            f"4. `powershell -ExecutionPolicy Bypass -File \"{wrapper}\" -RunId \"{run_id}\" "
            f"-WorkspaceRoot \"{workspace_root}\"{_seed_hint(previous_run_root, seed_mode)} -PreviousRunRoot \"{previous_run_root}\"`"
            if previous_run_root
            else (
                f"4. `powershell -ExecutionPolicy Bypass -File \"{wrapper}\" -RunId \"{run_id}\" "
                f"-WorkspaceRoot \"{workspace_root}\"`"
            )
        ),
        (
            f"5. `python -m vuln_pipeline.cli.phase12_apply_signoff review --workspace-root \"{workspace_root}\" "
            f"--run-id \"{run_id}\" --output-dir \"{repo_workspace_root / 'outputs' / 'runs' / run_id / 'report_data'}\"`"
        ),
        f"6. Read `{workspace_root / 'phase12_workspace_manifest.md'}` and the signoff review before any live apply step.",
    ]
    return commands


def build_operator_case_commands(
    *,
    repo_workspace_root: Path,
    workspace_root: Path | None,
    run_id: str,
    run_root: Path,
    working_dir: Path,
    incoming_root: Path,
    live_root: Path,
    live_manual_dir: Path,
    previous_run_root: Path | None,
    wrapper_script: Path | None,
    app_root: Path | None,
    working_state: dict[str, Any],
    incoming_state: dict[str, Any],
    payloads: dict[str, Any],
) -> list[str]:
    del app_root
    wrapper_script = wrapper_script or (repo_workspace_root / "app" / "vuln-pipeline" / "scripts" / "run_phase12_iteration.ps1")
    commands: list[str] = []

    if workspace_root and (not working_dir.exists() or not incoming_root.exists()):
        bootstrap_parts = [
            f"powershell -ExecutionPolicy Bypass -File \"{wrapper_script}\"",
            f"-RunId \"{run_id}\"",
            f"-WorkspaceRoot \"{workspace_root}\"",
            "-InitWorkspace",
            "-StopAfterBootstrap",
        ]
        if previous_run_root:
            bootstrap_parts.append(f"-PreviousRunRoot \"{previous_run_root}\"")
        if previous_run_root and not working_dir.exists():
            bootstrap_parts.append(f"-SeedManualDraftsFromRunRoot \"{previous_run_root}\"")
        elif not working_dir.exists():
            bootstrap_parts.append("-SeedManualDraftsFromTemplates")
        commands.append(f"1. `{ ' '.join(bootstrap_parts) }`")

    if incoming_state["visible_file_count"] == 0:
        commands.append(
            f"2. Drop the real exports into `{incoming_root}` and rerun "
            f"`python -m vuln_pipeline.cli.scan_input_promotion --incoming-root \"{incoming_root}\" --live-root \"{live_root}\" "
            f"--output-dir \"{run_root / 'report_data' / 'scan_promotion'}\" --plan-only`"
        )
    else:
        commands.append(
            f"2. `python -m vuln_pipeline.cli.scan_input_promotion --incoming-root \"{incoming_root}\" --live-root \"{live_root}\" "
            f"--output-dir \"{run_root / 'report_data' / 'scan_promotion'}\" --plan-only`"
        )

    if not working_state["exists"] or working_state["missing_files"]:
        if workspace_root:
            seed_flag = (
                f"-SeedManualDraftsFromRunRoot \"{previous_run_root}\""
                if previous_run_root
                else "-SeedManualDraftsFromTemplates"
            )
            commands.append(
                f"3. `powershell -ExecutionPolicy Bypass -File \"{wrapper_script}\" -RunId \"{run_id}\" "
                f"-WorkspaceRoot \"{workspace_root}\" -InitWorkspace {seed_flag} -StopAfterBootstrap`"
            )
        else:
            run_root_arg = f" --run-root \"{previous_run_root}\"" if previous_run_root else ""
            commands.append(
                f"3. `python -m vuln_pipeline.cli.manual_bootstrap --workspace-root \"{repo_workspace_root}\" "
                f"--output-dir \"{working_dir}\"{run_root_arg}`"
            )
    else:
        commands.append(
            f"3. Edit the reviewed rows in `{working_dir}` and rerun "
            f"`python -m vuln_pipeline.cli.manual_promotion --working-dir \"{working_dir}\" --live-manual-dir \"{live_manual_dir}\" "
            f"--output-dir \"{run_root / 'report_data' / 'manual_promotion'}\" --plan-only`"
        )

    if payloads["manual_plan_json"] and payloads["manual_plan_json"].get("status") in {"human_selection_required", "ready_for_review"}:
        commands.append(
            "4. Review draft_candidates manually and copy approved rows into the matching top-level actionable list before any apply."
        )
    elif payloads["scan_plan_json"] and payloads["scan_plan_json"].get("status") == "blocked":
        commands.append(
            "4. Resolve scan promotion blockers first. Ambiguous candidate or naming-decision blocker stays operator-confirmation-needed."
        )
    else:
        previous_flag = f" -PreviousRunRoot \"{previous_run_root}\"" if previous_run_root else ""
        commands.append(
            f"4. `powershell -ExecutionPolicy Bypass -File \"{wrapper_script}\" -RunId \"{run_id}\" -WorkingDir \"{working_dir}\" "
            f"-IncomingScanRoot \"{incoming_root}\" -LiveManualDir \"{live_manual_dir}\" -LiveRoot \"{live_root}\"{previous_flag}`"
        )

    commands.append(
        f"5. `python -m vuln_pipeline.cli.phase12_apply_signoff review --run-id \"{run_id}\" --output-dir \"{run_root / 'report_data'}\"`"
    )
    commands.append(
        f"6. Check `{run_root / 'report_data' / 'phase12_operator_case.md'}` plus the signoff review and triage/comparison artifacts before any live apply."
    )
    return commands


def render_workspace_manifest_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Phase12 Workspace Manifest",
        "",
        f"- status: `{summary['status']}`",
        f"- workspace_root: `{summary['workspace_root']}`",
        f"- repo_workspace_root: `{summary['repo_workspace_root']}`",
        f"- live_real_dir: `{summary['live_real_dir']}`",
        f"- live_manual_dir: `{summary['live_manual_dir']}`",
        f"- seed_mode: `{summary['seed_mode']}`",
        "",
        "## Directories",
    ]
    for key, value in summary["directories"].items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(["", "## Empty Required Items"])
    lines.extend(f"- {item}" for item in summary.get("empty_required_items", []))
    lines.extend(["", "## Operator Confirmation Needed"])
    lines.extend(f"- {item}" for item in summary.get("operator_confirmation_needed", []))
    lines.extend(["", "## Recommended Next Commands"])
    lines.extend(f"- {item}" for item in summary.get("recommended_next_commands", []))
    if summary.get("seed_summary"):
        lines.extend(["", "## Seed Summary"])
        lines.append(f"- review_row_count: `{summary['seed_summary'].get('review_row_count', 0)}`")
        lines.append(f"- unresolved_row_count: `{summary['seed_summary'].get('unresolved_row_count', 0)}`")
        for path in summary["seed_summary"].get("written_files", []):
            lines.append(f"- written_file: `{path}`")
    return "\n".join(lines) + "\n"


def render_operator_case_markdown(summary: dict[str, Any]) -> str:
    hard_facts = summary["hard_facts"]
    suggestions = summary["suggestions"]
    lines = [
        "# Phase12 Operator Case",
        "",
        f"- case_phase: `{hard_facts['case_phase']}`",
        f"- run_id: `{hard_facts['run_id']}`",
        f"- run_root: `{hard_facts['run_root']}`",
        f"- report_data_dir: `{hard_facts['report_data_dir']}`",
        "",
        "## Hard Facts",
        f"- working_dir_exists: `{hard_facts['working_dir']['exists']}`",
        f"- working_dir_missing_files: `{hard_facts['working_dir']['missing_files']}`",
        f"- incoming_root_exists: `{hard_facts['incoming_root']['exists']}`",
        f"- incoming_visible_file_count: `{hard_facts['incoming_root']['visible_file_count']}`",
        f"- scan_live_readiness.inventory_status: `{hard_facts['scan_live_readiness']['inventory_status']}`",
        f"- scan_live_readiness.active_valid_tool_count: `{hard_facts['scan_live_readiness']['active_valid_tool_count']}`",
        f"- apply.scan: `{hard_facts['apply_flags']['scan_promotion_apply_requested']}`",
        f"- apply.manual: `{hard_facts['apply_flags']['manual_promotion_apply_requested']}`",
        f"- real_gate.status: `{hard_facts['real_gate_summary']['status']}`",
        f"- real_gate.rehearsal_allowed: `{hard_facts['real_gate_summary']['rehearsal_allowed']}`",
        f"- real_gate.fresh_preflight_generated: `{hard_facts['real_gate_summary']['fresh_preflight_generated']}`",
        f"- real_gate.real_explicit_proof_status: `{hard_facts['real_gate_summary']['real_explicit_proof_status']}`",
        "",
        "## Artifact Paths",
    ]
    for key, value in hard_facts["artifact_paths"].items():
        lines.append(f"- {key}: exists=`{value['exists']}` path=`{value['path']}`")
    lines.extend(["", "## Artifact Statuses"])
    for key, value in hard_facts["artifact_statuses"].items():
        lines.append(f"- {key}: `{value}`")
    lines.extend(["", "## Blocked Reason Summary"])
    if hard_facts["blocked_reason_summary"]:
        lines.extend(f"- {item}" for item in hard_facts["blocked_reason_summary"])
    else:
        lines.append("- none")
    lines.extend(["", "## Real Gate Summary"])
    lines.extend(f"- {item}" for item in hard_facts["real_gate_summary"]["summary_lines"] or ["- none"])
    lines.extend(["", "## Suggestions"])
    lines.extend(f"- operator-confirmation-needed: {item}" for item in suggestions["operator_confirmation_needed"])
    lines.extend(f"- next: {item}" for item in suggestions["exact_next_commands"])
    return "\n".join(lines) + "\n"


def _manual_draft_empty_items(working_dir: Path) -> list[str]:
    items: list[str] = []
    for filename in WORKING_DRAFT_FILENAMES:
        path = working_dir / filename
        payload = _load_yaml(path) if path.exists() else None
        actionable_key = ACTIONABLE_KEYS[filename]
        actionable_count = len(payload.get(actionable_key, [])) if isinstance(payload, dict) and isinstance(payload.get(actionable_key), list) else 0
        items.append(
            f"{filename}: actionable list `{actionable_key}` currently contains `{actionable_count}` approved rows."
        )
    return items


def _describe_working_dir(working_dir: Path) -> dict[str, Any]:
    missing_files = [name for name in WORKING_DRAFT_FILENAMES if not (working_dir / name).exists()]
    actionable_counts: dict[str, int | None] = {}
    for filename in WORKING_DRAFT_FILENAMES:
        path = working_dir / filename
        payload = _load_yaml(path) if path.exists() else None
        key = ACTIONABLE_KEYS[filename]
        if isinstance(payload, dict) and isinstance(payload.get(key), list):
            actionable_counts[filename] = len(payload[key])
        else:
            actionable_counts[filename] = None
    return {
        "exists": working_dir.exists(),
        "missing_files": missing_files,
        "actionable_counts": actionable_counts,
    }


def _describe_incoming_root(incoming_root: Path) -> dict[str, Any]:
    per_tool: dict[str, Any] = {}
    visible_count = 0
    for tool in ("burp", "nuclei", "httpx"):
        directory = incoming_root / tool
        files = sorted(str(item) for item in directory.iterdir() if item.is_file()) if directory.exists() else []
        per_tool[tool] = {
            "path": str(directory),
            "exists": directory.exists(),
            "visible_files": files,
            "visible_file_count": len(files),
        }
        visible_count += len(files)
    return {
        "exists": incoming_root.exists(),
        "visible_file_count": visible_count,
        "tools": per_tool,
    }


def _artifact_statuses(payloads: dict[str, Any]) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for key, payload in payloads.items():
        if payload is None:
            statuses[key] = "missing"
        elif isinstance(payload, dict) and payload.get("status") is not None:
            statuses[key] = str(payload.get("status"))
        elif key == "final_delivery_manifest_json" and isinstance(payload, dict):
            statuses[key] = "final_ready" if payload.get("final_ready") else "not_ready"
        else:
            statuses[key] = "present"
    return statuses


def _build_real_gate_summary(payload: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "status": _nested_text(payload, "status") or "missing",
        "rehearsal_allowed": bool(_nested_get(payload, "inference", "rehearsal_allowed")),
        "fresh_preflight_generated": bool(_nested_get(payload, "hard_facts", "preflight", "fresh_preflight_generated")),
        "real_explicit_proof_status": _nested_text(payload, "inference", "real_explicit_proof_status") or "missing",
        "summary_lines": _dedupe_strings(
            [str(item) for item in _nested_get(payload, "hard_facts", "remaining_blockers") or []]
            + [str(item) for item in _nested_get(payload, "hard_facts", "warnings") or []]
            + [str(item) for item in _nested_get(payload, "hard_facts", "mismatch_summary") or []]
        ),
    }


def _collect_blocked_reasons(payloads: dict[str, Any]) -> list[str]:
    reasons: list[str] = []
    for key in (
        "readiness_json",
        "scan_plan_json",
        "manual_plan_json",
        "input_preflight_json",
        "post_run_triage_json",
        "rerun_comparison_json",
    ):
        payload = payloads.get(key)
        if not isinstance(payload, dict):
            continue
        for item in payload.get("blockers", []):
            reasons.append(f"{key}: {item}")
        hard_facts = payload.get("hard_facts")
        if isinstance(hard_facts, dict):
            for item in hard_facts.get("blockers", []):
                reasons.append(f"{key}: {item}")
            for item in hard_facts.get("remaining_blockers", []):
                reasons.append(f"{key}: {item}")
        if key == "rerun_comparison_json" and isinstance(payload.get("inference"), dict):
            reasons.append(f"{key}: inference summary=`{payload['inference'].get('summary')}`")
    return _dedupe_strings(reasons)


def _collect_operator_confirmation_needed(
    *,
    incoming_state: dict[str, Any],
    working_state: dict[str, Any],
    payloads: dict[str, Any],
    apply_scan_promotion: bool,
    apply_promotion: bool,
) -> list[str]:
    items: list[str] = []
    if incoming_state["visible_file_count"] == 0:
        items.append("incoming real exports are still absent in the non-live workspace.")
    if working_state["missing_files"]:
        items.append("manual working drafts are missing and need bootstrap or operator preparation.")
    manual_plan = payloads.get("manual_plan_json")
    if isinstance(manual_plan, dict) and manual_plan.get("status") in {"human_selection_required", "ready_for_review"}:
        items.append("manual draft_candidates require human review before any apply.")
    scan_plan = payloads.get("scan_plan_json")
    if isinstance(scan_plan, dict):
        for blocker in scan_plan.get("blockers", []):
            if "ambiguous" in blocker or "naming decision required" in blocker:
                items.append(blocker)
    if not apply_scan_promotion:
        items.append("scan live apply was not requested in this run.")
    if not apply_promotion:
        items.append("manual live apply was not requested in this run.")
    return _dedupe_strings(items)


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"status": "invalid_json", "path": str(path)}
    return payload if isinstance(payload, dict) else {"status": "present", "path": str(path)}


def _load_yaml(path: Path) -> dict[str, Any] | None:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
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
    if value in {None, ""}:
        return None
    return str(value)


def _path_state(path: Path | None) -> dict[str, Any]:
    return {
        "path": str(path) if path else None,
        "exists": bool(path and path.exists()),
    }


def _seed_hint(previous_run_root: Path | None, seed_mode: str) -> str:
    if seed_mode == "from_run_root" and previous_run_root:
        return f" -SeedManualDraftsFromRunRoot \"{previous_run_root}\""
    if seed_mode == "from_templates":
        return " -SeedManualDraftsFromTemplates"
    return ""


def _timestamp() -> str:
    return datetime.now(UTC).isoformat()


def _dedupe_strings(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        text = str(item)
        if text not in seen:
            seen.add(text)
            ordered.append(text)
    return ordered


if __name__ == "__main__":
    raise SystemExit(main())
