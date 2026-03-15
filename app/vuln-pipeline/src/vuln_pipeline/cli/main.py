from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from vuln_pipeline.parsers import build_input_intake_manifest, collect_inputs
from vuln_pipeline.parsers.real_inputs import auto_select_real_inputs, render_real_input_selection_summary, resolve_manual_input_paths
from vuln_pipeline.pipeline import run_pipeline
from vuln_pipeline.report import (
    build_git_change_manifest,
    build_input_preflight,
    build_pptx_capability,
    build_real_rehearsal_blocked,
    build_real_rehearsal_result,
    build_release_readiness_summary,
    expected_presentation_paths,
    load_customer_bundle,
    render_commit_prep_summary,
    render_input_preflight_markdown,
    render_pptx_capability_markdown,
)
from vuln_pipeline.storage import write_json, write_markdown
from vuln_pipeline.utils import ensure_directory


def _workspace_root() -> Path:
    return Path(__file__).resolve().parents[5]


def build_parser() -> argparse.ArgumentParser:
    workspace_root = _workspace_root()
    parser = argparse.ArgumentParser(description="Local vulnerability parsing and reporting pipeline.")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--burp", type=Path, nargs="*")
    parser.add_argument("--nuclei", type=Path, nargs="*")
    parser.add_argument("--httpx", type=Path, nargs="*")
    parser.add_argument("--burp-dir", type=Path, default=workspace_root / "data" / "inputs" / "burp")
    parser.add_argument("--nuclei-dir", type=Path, default=workspace_root / "data" / "inputs" / "nuclei")
    parser.add_argument("--httpx-dir", type=Path, default=workspace_root / "data" / "inputs" / "httpx")
    parser.add_argument("--override-file", type=Path, default=workspace_root / "data" / "inputs" / "manual" / "sample_override.yaml")
    parser.add_argument("--suppression-file", type=Path, default=workspace_root / "data" / "inputs" / "manual" / "suppressions.yaml")
    parser.add_argument("--review-resolution-file", type=Path, default=workspace_root / "data" / "inputs" / "manual" / "review_resolution.yaml")
    parser.add_argument("--branding-file", type=Path, default=workspace_root / "app" / "vuln-pipeline" / "configs" / "branding" / "customer_branding.yaml")
    parser.add_argument("--customer-bundle", type=Path)
    parser.add_argument("--output-base", type=Path, default=workspace_root / "outputs" / "runs")
    parser.add_argument("--mapping-config", type=Path, default=workspace_root / "app" / "vuln-pipeline" / "configs" / "mapping_rules.json")
    parser.add_argument("--scoring-config", type=Path, default=workspace_root / "app" / "vuln-pipeline" / "configs" / "scoring_rules.json")
    parser.add_argument("--knowledge-dir", type=Path, default=workspace_root / "app" / "vuln-pipeline" / "configs" / "knowledge")
    parser.add_argument("--report-profile-dir", type=Path, default=workspace_root / "app" / "vuln-pipeline" / "configs" / "report_profiles")
    parser.add_argument("--report-template-dir", type=Path, default=workspace_root / "app" / "vuln-pipeline" / "configs" / "report_templates")
    parser.add_argument("--deliverable-profile-dir", type=Path, default=workspace_root / "app" / "vuln-pipeline" / "configs" / "deliverable_profiles")
    parser.add_argument("--remediation-policy-dir", type=Path, default=workspace_root / "app" / "vuln-pipeline" / "configs" / "remediation_policy")
    parser.add_argument("--readiness-policy", type=Path, default=workspace_root / "app" / "vuln-pipeline" / "configs" / "readiness" / "customer_release.yaml")
    parser.add_argument("--report-profile", choices=["internal", "customer"], default="internal")
    parser.add_argument("--report-template", choices=["default_internal", "default_customer"], default="default_internal")
    parser.add_argument("--deliverable-profile", choices=["internal_pack", "customer_pack", "management_pack"], default="customer_pack")
    parser.add_argument("--package-policy", default="default")
    parser.add_argument("--project-name", default="Web Vulnerability Assessment")
    parser.add_argument("--client-name", default="Internal Client")
    parser.add_argument("--engagement-name", default="Security Review")
    parser.add_argument("--analyst-name", default="Analyst Team")
    parser.add_argument("--organization-name", default="Security Operations")
    parser.add_argument("--report-version", default="v1.0")
    parser.add_argument("--delivery-date", default="")
    parser.add_argument("--approver-name", default="TBD")
    parser.add_argument("--contact-email", default="security@example.local")
    parser.add_argument("--package-output", action="store_true")
    parser.add_argument("--auto-select-real-inputs", action="store_true")
    parser.add_argument("--emit-override-template", action="store_true")
    parser.add_argument("--release-candidate", action="store_true")
    parser.add_argument("--finalize-delivery", action="store_true")
    parser.add_argument("--archive-only", action="store_true")
    parser.add_argument("--stage-real-inputs", action="store_true")
    parser.add_argument("--require-pptx", action="store_true")
    parser.add_argument("--check-pptx-capability", action="store_true")
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--compare-to-run", type=str)
    parser.add_argument("--no-dir-ingest", action="store_true")
    parser.add_argument("--no-docx", action="store_true")
    return parser


def main() -> None:
    argv = sys.argv[1:]
    args = build_parser().parse_args(argv)
    explicit_flags = _explicit_flags(argv)
    _apply_customer_bundle(args, explicit_flags)

    workspace_root = _workspace_root()
    output_root = ensure_directory(args.output_base / args.run_id)
    legacy_manual_dir = workspace_root / "data" / "inputs" / "manual"
    real_input_root = workspace_root / "data" / "inputs" / "real"
    real_roots = {
        "burp": ensure_directory(real_input_root / "burp"),
        "nuclei": ensure_directory(real_input_root / "nuclei"),
        "httpx": ensure_directory(real_input_root / "httpx"),
    }
    real_manual_dir = ensure_directory(real_input_root / "manual")
    default_manual_inputs = {
        "override_file": args.override_file,
        "suppression_file": args.suppression_file,
        "review_resolution_file": args.review_resolution_file,
    }
    explicit = {"burp": args.burp, "nuclei": args.nuclei, "httpx": args.httpx}
    directories = {} if args.no_dir_ingest else {"burp": args.burp_dir, "nuclei": args.nuclei_dir, "httpx": args.httpx_dir}
    inputs, manifest = collect_inputs(explicit=explicit, directories=directories)

    real_input_selection = None
    input_intake_manifest = None
    input_hashes = None
    if args.auto_select_real_inputs:
        selected_inputs, real_input_selection, input_intake_manifest, input_hashes = auto_select_real_inputs(
            primary_roots=real_roots,
            fallback_roots={"burp": args.burp_dir, "nuclei": args.nuclei_dir, "httpx": args.httpx_dir},
            primary_manual_dir=real_manual_dir,
            fallback_manual_dir=legacy_manual_dir,
            snapshot_root=output_root / "input_snapshot",
            stage_selected=args.stage_real_inputs,
        )
        if not any(explicit.values()):
            inputs = selected_inputs
            manifest["ingested"] = {tool: [str(path) for path in paths] for tool, paths in inputs.items()}
    else:
        input_intake_manifest, input_hashes = build_input_intake_manifest(
            inputs=inputs,
            manual_inputs=default_manual_inputs,
            snapshot_root=output_root / "input_snapshot",
            stage_selected=args.stage_real_inputs,
        )

    effective_manual_inputs, manual_input_resolution = resolve_manual_input_paths(
        configured_manual_inputs=default_manual_inputs,
        default_manual_inputs=default_manual_inputs,
        explicit_flags=explicit_flags,
        auto_select_real_inputs=args.auto_select_real_inputs,
        real_input_selection=real_input_selection,
        real_manual_dir=real_manual_dir,
        legacy_manual_dir=legacy_manual_dir,
    )
    if real_input_selection is not None:
        real_input_selection["manual_resolution"] = manual_input_resolution

    write_json(output_root / "report_data" / "real_input_selection.json", real_input_selection or {"status": "not_requested"})
    write_json(output_root / "report_data" / "input_intake_manifest.json", input_intake_manifest)
    write_json(output_root / "report_data" / "input_hashes.json", input_hashes)

    applied_bundle = _build_applied_bundle_config(args)
    write_json(output_root / "report_data" / "applied_bundle_config.json", applied_bundle)

    preflight = build_input_preflight(
        explicit_inputs=explicit,
        resolved_inputs=inputs,
        roots=real_roots if args.auto_select_real_inputs else {"burp": args.burp_dir, "nuclei": args.nuclei_dir, "httpx": args.httpx_dir},
        manual_inputs=effective_manual_inputs,
        manual_metadata=manual_input_resolution,
        auto_select_real_inputs=args.auto_select_real_inputs,
    )
    write_json(output_root / "report_data" / "input_preflight.json", preflight)
    write_markdown(output_root / "report_data" / "input_preflight.md", render_input_preflight_markdown(preflight))

    expected_pptx_path, fallback_pptx_path = expected_presentation_paths(
        deliverables_root=output_root / "deliverables",
        deliverable_profile_dir=args.deliverable_profile_dir,
        deliverable_profile_name=args.deliverable_profile,
        report_version=args.report_version,
    )
    pptx_capability = build_pptx_capability(
        expected_output_path=expected_pptx_path,
        fallback_path=fallback_pptx_path,
        require_pptx=args.require_pptx,
    )
    write_json(output_root / "report_data" / "pptx_capability.json", pptx_capability)
    write_markdown(output_root / "report_data" / "pptx_capability.md", render_pptx_capability_markdown(pptx_capability))

    if args.check_pptx_capability and args.preflight_only:
        print(f"Preflight and PPTX capability complete: {output_root}")
        return
    if args.preflight_only:
        print(f"Preflight complete: {output_root}")
        return
    if args.check_pptx_capability and not any(inputs.values()):
        print(f"PPTX capability complete: {output_root}")
        return

    if not any(inputs.values()):
        if real_input_selection is not None:
            write_markdown(output_root / "deliverables" / "real_data_rehearsal_summary.md", render_real_input_selection_summary(real_input_selection, args.run_id))
            write_markdown(
                output_root / "deliverables" / "real_rehearsal_blocked.md",
                build_real_rehearsal_blocked(
                    run_id=args.run_id,
                    real_input_selection=real_input_selection,
                    preflight=preflight,
                    reason="no eligible real input files were found in data\\inputs\\real\\*",
                ),
            )
            write_markdown(
                output_root / "deliverables" / "release_readiness_summary.md",
                build_release_readiness_summary(
                    baseline_run_id=args.run_id,
                    rehearsal_performed=False,
                    preflight=preflight,
                    readiness=None,
                    submission_gate=None,
                    privacy_audit=None,
                    pptx_capability=pptx_capability,
                    final_delivery_manifest=None,
                    blockers=preflight.get("blockers", []),
                ),
            )
            raise SystemExit("Real-data rehearsal incomplete: no eligible real input files were found.")
        raise SystemExit("At least one valid input file is required.")

    compare_to = args.output_base / args.compare_to_run if args.compare_to_run else None
    run_mode = "batch" if not args.no_dir_ingest else "single"
    effective_package_output = args.package_output or args.release_candidate or args.finalize_delivery or args.archive_only
    bundle = run_pipeline(
        run_id=args.run_id,
        inputs=inputs,
        output_root=output_root,
        mapping_config=args.mapping_config,
        scoring_config=args.scoring_config,
        override_path=effective_manual_inputs["override_file"] if effective_manual_inputs["override_file"] and effective_manual_inputs["override_file"].exists() else None,
        suppressions_path=effective_manual_inputs["suppression_file"] if effective_manual_inputs["suppression_file"] and effective_manual_inputs["suppression_file"].exists() else None,
        review_resolution_path=effective_manual_inputs["review_resolution_file"] if effective_manual_inputs["review_resolution_file"] and effective_manual_inputs["review_resolution_file"].exists() else None,
        compare_to_run=compare_to if compare_to and compare_to.exists() else None,
        ingest_manifest=manifest,
        generate_docx=not args.no_docx,
        report_profile=args.report_profile,
        knowledge_dir=args.knowledge_dir,
        profile_dir=args.report_profile_dir,
        template_dir=args.report_template_dir,
        deliverable_profile_dir=args.deliverable_profile_dir,
        remediation_policy_dir=args.remediation_policy_dir,
        readiness_policy_path=args.readiness_policy,
        report_template=args.report_template,
        deliverable_profile=args.deliverable_profile,
        package_output=effective_package_output,
        emit_override_template=args.emit_override_template,
        release_candidate=args.release_candidate,
        finalize_delivery=args.finalize_delivery,
        archive_only=args.archive_only,
        branding_path=args.branding_file if args.branding_file and args.branding_file.exists() else None,
        require_pptx=args.require_pptx,
        real_input_selection=real_input_selection,
        preflight=preflight,
        pptx_capability=pptx_capability,
        execution_options={
            "run_id": args.run_id,
            "burp_dir": str(args.burp_dir),
            "nuclei_dir": str(args.nuclei_dir),
            "httpx_dir": str(args.httpx_dir),
            "manual_dir": str(legacy_manual_dir),
            "real_burp_dir": str(real_roots["burp"]),
            "real_nuclei_dir": str(real_roots["nuclei"]),
            "real_httpx_dir": str(real_roots["httpx"]),
            "real_manual_dir": str(real_manual_dir),
            "override_file": str(effective_manual_inputs["override_file"]) if effective_manual_inputs["override_file"] else "",
            "suppression_file": str(effective_manual_inputs["suppression_file"]) if effective_manual_inputs["suppression_file"] else "",
            "review_resolution_file": str(effective_manual_inputs["review_resolution_file"]) if effective_manual_inputs["review_resolution_file"] else "",
            "manual_input_resolution": manual_input_resolution,
            "branding_file": str(args.branding_file),
            "readiness_policy": str(args.readiness_policy),
            "compare_to_run": args.compare_to_run or "",
            "report_template": args.report_template,
            "deliverable_profile": args.deliverable_profile,
            "customer_bundle": str(args.customer_bundle) if args.customer_bundle else "",
            "require_pptx": args.require_pptx,
            "archive_only": args.archive_only,
            "stage_real_inputs": args.stage_real_inputs,
            "package_policy": applied_bundle.get("effective", {}).get("package_policy", "default"),
        },
        document_meta={
            "project_name": args.project_name,
            "client_name": args.client_name,
            "engagement_name": args.engagement_name,
            "analyst_name": args.analyst_name,
            "organization_name": args.organization_name,
            "report_version": args.report_version,
            "delivery_date": args.delivery_date,
            "approver_name": args.approver_name,
            "contact_email": args.contact_email,
            "compared_run_id": args.compare_to_run or "N/A",
            "run_mode": run_mode,
        },
    )
    report_data_dir = output_root / "report_data"
    delivery_dir = output_root / "delivery"
    readiness = _load_json_if_exists(report_data_dir / "release_readiness.json")
    submission_gate = _load_json_if_exists(report_data_dir / "submission_gate.json")
    privacy_audit = _load_json_if_exists(report_data_dir / "customer_package_audit.json")
    final_delivery_manifest = _load_json_if_exists(delivery_dir / "final_delivery_manifest.json")
    if args.auto_select_real_inputs:
        write_markdown(
            output_root / "deliverables" / "real_rehearsal_result.md",
                build_real_rehearsal_result(
                    run_id=args.run_id,
                    preflight=preflight,
                    readiness=readiness,
                    submission_gate=submission_gate,
                    privacy_audit=privacy_audit,
                pptx_capability=pptx_capability,
                final_delivery_manifest=final_delivery_manifest,
            ),
        )
    write_markdown(
        output_root / "deliverables" / "release_readiness_summary.md",
        build_release_readiness_summary(
            baseline_run_id=args.run_id,
            rehearsal_performed=bool(args.auto_select_real_inputs),
            preflight=preflight,
            readiness=readiness,
            submission_gate=submission_gate,
            privacy_audit=privacy_audit,
            pptx_capability=pptx_capability,
            final_delivery_manifest=final_delivery_manifest,
            blockers=preflight.get("blockers", []) + ((submission_gate or {}).get("blocking_reasons", []) if submission_gate else []),
        ),
    )
    print(f"Run complete: {output_root}")
    print(f"Findings={bundle.summary['deduped_findings']} Issues={bundle.summary['issues']} Report={output_root / 'reports' / 'report.md'}")


def _explicit_flags(argv: list[str]) -> set[str]:
    return {token.split("=", 1)[0] for token in argv if token.startswith("--")}


def _apply_customer_bundle(args: argparse.Namespace, explicit_flags: set[str]) -> None:
    bundle = load_customer_bundle(args.customer_bundle)
    if not bundle:
        return
    mapping = {
        "branding_file": "branding_file",
        "report_template": "report_template",
        "deliverable_profile": "deliverable_profile",
        "readiness_policy": "readiness_policy",
        "remediation_policy_dir": "remediation_policy_dir",
        "report_profile": "report_profile",
        "require_pptx": "require_pptx",
        "package_policy": "package_policy",
    }
    for bundle_key, arg_name in mapping.items():
        if f"--{arg_name.replace('_', '-')}" in explicit_flags:
            continue
        value = bundle.get(bundle_key)
        if value in {None, ""}:
            continue
        current = getattr(args, arg_name, None)
        if isinstance(current, Path):
            setattr(args, arg_name, Path(value))
        else:
            setattr(args, arg_name, value)


def _build_applied_bundle_config(args: argparse.Namespace) -> dict[str, object]:
    bundle = load_customer_bundle(args.customer_bundle)
    return {
        "bundle_path": str(args.customer_bundle) if args.customer_bundle else None,
        "bundle_values": bundle,
        "effective": {
            "branding_file": str(args.branding_file),
            "report_profile": args.report_profile,
            "report_template": args.report_template,
            "deliverable_profile": args.deliverable_profile,
            "readiness_policy": str(args.readiness_policy),
            "remediation_policy_dir": str(args.remediation_policy_dir),
            "require_pptx": args.require_pptx,
            "package_policy": getattr(args, "package_policy", bundle.get("package_policy", "default")),
        },
    }


def _load_json_if_exists(path: Path) -> dict[str, object] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()
