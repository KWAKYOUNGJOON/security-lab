from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from vuln_pipeline.dedup import cluster_findings
from vuln_pipeline.enrich import (
    apply_finding_overrides,
    apply_issue_overrides,
    apply_issue_suppressions,
    enrich_findings,
    load_overrides,
    load_suppressions,
)
from vuln_pipeline.mapping import RuleEngine
from vuln_pipeline.models import ParsedFinding, ReportBundle
from vuln_pipeline.normalize import normalize_finding
from vuln_pipeline.parsers import parse_burp_xml, parse_httpx_jsonl, parse_nuclei_jsonl
from vuln_pipeline.report import (
    DocxRenderer,
    apply_remediation_policy,
    apply_review_resolutions,
    build_archive_only_manifest,
    build_customer_package_audit,
    build_final_submission_check,
    build_operations_runbook,
    build_pptx_capability,
    build_real_data_onboarding_checklist,
    build_release_runbook,
    build_override_template,
    build_qa_metrics,
    build_review_closure_status,
    build_report_context,
    build_review_queue,
    build_release_readiness,
    compare_runs,
    expected_presentation_paths,
    generate_deliverables,
    load_review_resolutions,
    render_customer_package_audit_markdown,
    render_input_preflight_markdown,
    render_markdown_report,
    render_review_queue_markdown,
    render_run_diff_markdown,
)
from vuln_pipeline.report.finalization import build_submission_gate
from vuln_pipeline.scoring import score_finding
from vuln_pipeline.storage import package_curated_output, package_run_output, write_csv, write_json, write_jsonl, write_markdown
from vuln_pipeline.utils import ensure_directory, now_utc


def run_pipeline(
    run_id: str,
    inputs: dict[str, list[Path]],
    output_root: Path,
    mapping_config: Path,
    scoring_config: Path,
    override_path: Path | None = None,
    suppressions_path: Path | None = None,
    review_resolution_path: Path | None = None,
    compare_to_run: Path | None = None,
    ingest_manifest: dict[str, Any] | None = None,
    generate_docx: bool = True,
    report_profile: str = "internal",
    knowledge_dir: Path | None = None,
    profile_dir: Path | None = None,
    template_dir: Path | None = None,
    deliverable_profile_dir: Path | None = None,
    remediation_policy_dir: Path | None = None,
    readiness_policy_path: Path | None = None,
    report_template: str = "default_internal",
    deliverable_profile: str = "customer_pack",
    package_output: bool = False,
    emit_override_template: bool = False,
    release_candidate: bool = False,
    finalize_delivery: bool = False,
    archive_only: bool = False,
    branding_path: Path | None = None,
    require_pptx: bool = False,
    real_input_selection: dict[str, Any] | None = None,
    document_meta: dict[str, Any] | None = None,
    preflight: dict[str, Any] | None = None,
    pptx_capability: dict[str, Any] | None = None,
    execution_options: dict[str, Any] | None = None,
) -> ReportBundle:
    parsed_dir = ensure_directory(output_root / "parsed")
    normalized_dir = ensure_directory(output_root / "normalized")
    issues_dir = ensure_directory(output_root / "issues")
    report_data_dir = ensure_directory(output_root / "report_data")
    reports_dir = ensure_directory(output_root / "reports")
    deliverables_dir = ensure_directory(output_root / "deliverables")
    artifact_dir = ensure_directory(output_root / "artifacts")
    comparison_dir = ensure_directory(output_root / "comparison")

    manifest = ingest_manifest or {"ingested": {}, "warnings": []}
    parser_warnings: list[dict[str, Any]] = []

    parsed_findings: list[ParsedFinding] = []
    observations: list[ParsedFinding] = []
    for path in inputs.get("burp", []):
        parsed_findings.extend(parse_burp_xml(path, artifact_dir, parser_warnings))
    for path in inputs.get("nuclei", []):
        parsed_findings.extend(parse_nuclei_jsonl(path, artifact_dir, parser_warnings))
    for path in inputs.get("httpx", []):
        observations.extend(parse_httpx_jsonl(path, parser_warnings))

    for warning in parser_warnings:
        manifest.setdefault("warnings", []).append(str(warning))

    write_json(parsed_dir / "parsed_findings.json", parsed_findings)
    write_json(parsed_dir / "observations.json", observations)

    normalized = [normalize_finding(item, run_id, index) for index, item in enumerate(parsed_findings, start=1)]
    rule_engine = RuleEngine(mapping_config)
    mapping_rows: list[dict[str, Any]] = []
    mapped_findings = []
    for item in normalized:
        mapped, decision = rule_engine.apply(item, return_decision=True)
        mapped_findings.append(mapped)
        mapping_rows.append(decision)

    mapped_findings, observation_rows = enrich_findings(mapped_findings, observations)

    scoring_rows: list[dict[str, Any]] = []
    scored_findings = []
    for item in mapped_findings:
        scored, decision = score_finding(item, scoring_config, return_decision=True)
        scored_findings.append(scored)
        scoring_rows.append(decision)

    override_rows: list[dict[str, Any]] = []
    overrides = load_overrides(override_path)
    if overrides:
        scored_findings, finding_override_rows = apply_finding_overrides(scored_findings, overrides)
        override_rows.extend(finding_override_rows)

    write_json(normalized_dir / "normalized_findings.json", scored_findings)

    deduped, issues, cluster_rows = cluster_findings(scored_findings)

    if overrides:
        issues, issue_override_rows = apply_issue_overrides(issues, overrides)
        override_rows.extend(issue_override_rows)

    suppressions = load_suppressions(suppressions_path)
    suppression_rows: list[dict[str, Any]] = []
    suppressed_issues = []
    if suppressions:
        issues, suppressed_issues, suppression_rows = apply_issue_suppressions(issues, suppressions)

    false_positive_findings = [finding for finding in deduped if finding.dedup.false_positive]
    false_positive_issue_ids = set()
    for issue in issues:
        if issue.false_positive:
            false_positive_issue_ids.add(issue.issue_id)
        elif issue.instances and all(
            next((finding.dedup.false_positive for finding in deduped if finding.finding_id == instance), False)
            for instance in issue.instances
        ):
            issue.false_positive = True
            false_positive_issue_ids.add(issue.issue_id)
    active_issues = [issue for issue in issues if not issue.false_positive and not issue.suppressed]
    false_positive_issues = [issue for issue in issues if issue.false_positive]

    remediation_policy = apply_remediation_policy(
        issues + suppressed_issues,
        (remediation_policy_dir or Path(__file__).resolve().parents[2] / "configs" / "remediation_policy") / "owner_mapping.yaml",
        (remediation_policy_dir or Path(__file__).resolve().parents[2] / "configs" / "remediation_policy") / "due_rules.yaml",
    )

    write_json(issues_dir / "issue_clusters.json", issues + suppressed_issues)

    comparison = compare_runs(ReportBundle(
        schema_version="1.2",
        run_id=run_id,
        generated_at=now_utc(),
        input_files=[str(path) for paths in inputs.values() for path in paths],
        findings=deduped,
        issues=active_issues,
    ), compare_to_run)
    if comparison.get("available"):
        write_json(comparison_dir / "run_diff.json", comparison)
        write_markdown(comparison_dir / "run_diff.md", render_run_diff_markdown(comparison))

    run_mode = "batch" if any(len(paths) > 1 for paths in inputs.values()) else "single"
    branding_meta = _load_branding_metadata(branding_path)
    metadata = {
        **branding_meta,
        **(document_meta or {}),
        "compared_run_id": comparison.get("compared_run_id"),
        "run_mode": run_mode,
    }
    metadata.setdefault("run_id", run_id)

    bundle = ReportBundle(
        schema_version="1.2",
        run_id=run_id,
        generated_at=now_utc(),
        input_files=[str(path) for paths in inputs.values() for path in paths],
        findings=deduped,
        issues=active_issues,
        observations=observation_rows,
        summary={
            "parsed_findings": len(parsed_findings),
            "deduped_findings": len(deduped),
            "issues": len(active_issues),
            "observations": len(observation_rows),
            "false_positive_issues": len(false_positive_issues),
            "suppressed_issues": len(suppressed_issues),
        },
        false_positive_findings=false_positive_findings,
        false_positive_issues=false_positive_issues,
        suppressed_issues=suppressed_issues,
        override_summary={
            "applied": len(override_rows),
            "targets": [row["target_id"] for row in override_rows if row.get("target_id")],
        },
        suppression_summary={
            "applied": len(suppression_rows),
            "statuses": [row["status"] for row in suppression_rows if row.get("action") == "suppressed"],
        },
        comparison_summary=comparison,
        report_profile=report_profile,
        report_template=report_template,
        document_meta=metadata,
    )

    review_queue = build_review_queue(bundle, mapping_rows)
    review_resolutions = load_review_resolutions(review_resolution_path)
    review_queue, review_resolution_rows, review_closure_status = apply_review_resolutions(review_queue, review_resolutions)
    qa_metrics = build_qa_metrics(bundle, manifest, mapping_rows, review_queue, package_output, comparison)
    bundle.qa_metrics = qa_metrics

    write_json(report_data_dir / "final_report_bundle.json", bundle)
    write_jsonl(report_data_dir / "mapping_decisions.jsonl", mapping_rows)
    write_jsonl(report_data_dir / "scoring_decisions.jsonl", scoring_rows)
    write_jsonl(report_data_dir / "override_decisions.jsonl", override_rows)
    write_jsonl(report_data_dir / "cluster_decisions.jsonl", cluster_rows)
    write_jsonl(report_data_dir / "suppression_decisions.jsonl", suppression_rows)
    write_json(report_data_dir / "ingest_manifest.json", manifest)
    write_json(report_data_dir / "real_input_selection.json", real_input_selection or {"status": "not_requested"})
    write_jsonl(report_data_dir / "ingest_warnings.jsonl", parser_warnings)
    write_jsonl(report_data_dir / "review_queue.jsonl", review_queue)
    write_csv(
        report_data_dir / "review_queue.csv",
        review_queue,
        [
            "run_id",
            "issue_id",
            "finding_ids",
            "title",
            "weakness_family",
            "primary_cwe",
            "severity_level",
            "confidence_level",
            "review_reason",
            "recommended_action",
            "host",
            "path_pattern",
            "current_status",
            "priority_score",
            "priority_band",
            "suggested_sla",
        ],
    )
    write_markdown(report_data_dir / "review_queue.md", render_review_queue_markdown(review_queue))
    write_json(report_data_dir / "qa_metrics.json", qa_metrics)
    write_json(report_data_dir / "remediation_policy_decisions.json", remediation_policy)
    write_jsonl(report_data_dir / "review_resolution_applied.jsonl", review_resolution_rows)
    write_json(report_data_dir / "review_closure_status.json", review_closure_status)

    if emit_override_template:
        (report_data_dir / "override_template.yaml").write_text(
            yaml.safe_dump(build_override_template(review_queue), sort_keys=False, allow_unicode=True),
            encoding="utf-8",
        )

    report_context = build_report_context(
        bundle=bundle,
        knowledge_dir=knowledge_dir or Path(__file__).resolve().parents[2] / "configs" / "knowledge",
        profile_dir=profile_dir or Path(__file__).resolve().parents[2] / "configs" / "report_profiles",
        profile_name=report_profile,
        report_data_dir=report_data_dir,
        template_dir=template_dir or Path(__file__).resolve().parents[2] / "configs" / "report_templates",
        template_name=report_template,
        document_meta=metadata,
    )
    internal_context = build_report_context(
        bundle=bundle,
        knowledge_dir=knowledge_dir or Path(__file__).resolve().parents[2] / "configs" / "knowledge",
        profile_dir=profile_dir or Path(__file__).resolve().parents[2] / "configs" / "report_profiles",
        profile_name="internal",
        report_data_dir=report_data_dir,
        template_dir=template_dir or Path(__file__).resolve().parents[2] / "configs" / "report_templates",
        template_name="default_internal",
        document_meta=metadata,
    )
    customer_context = build_report_context(
        bundle=bundle,
        knowledge_dir=knowledge_dir or Path(__file__).resolve().parents[2] / "configs" / "knowledge",
        profile_dir=profile_dir or Path(__file__).resolve().parents[2] / "configs" / "report_profiles",
        profile_name="customer",
        report_data_dir=report_data_dir,
        template_dir=template_dir or Path(__file__).resolve().parents[2] / "configs" / "report_templates",
        template_name="default_customer",
        document_meta=metadata,
    )
    write_json(report_data_dir / "report_context.json", report_context)
    markdown = render_markdown_report(report_context)
    write_markdown(reports_dir / "report.md", markdown)
    if generate_docx:
        try:
            DocxRenderer().render(report_context, reports_dir / "report.docx")
        except Exception as exc:
            write_json(report_data_dir / "docx_failure.json", {"error": str(exc)})

    readiness = build_release_readiness(
        bundle=bundle,
        qa_metrics=qa_metrics,
        review_queue=review_queue,
        review_closure_status=review_closure_status,
        package_created=package_output,
        comparison=comparison,
        customer_profile_applied=not customer_context["profile"].get("show_internal_paths", True),
        policy_path=readiness_policy_path or Path(__file__).resolve().parents[2] / "configs" / "readiness" / "customer_release.yaml",
    )
    write_json(report_data_dir / "release_readiness.json", readiness)
    expected_pptx_path, fallback_pptx_path = expected_presentation_paths(
        deliverables_root=deliverables_dir,
        deliverable_profile_dir=deliverable_profile_dir or Path(__file__).resolve().parents[2] / "configs" / "deliverable_profiles",
        deliverable_profile_name=deliverable_profile,
        report_version=metadata.get("report_version", "v1.0"),
    )
    pptx_capability_data = pptx_capability or build_pptx_capability(
        expected_output_path=expected_pptx_path,
        fallback_path=fallback_pptx_path,
        require_pptx=require_pptx,
    )
    write_json(report_data_dir / "pptx_capability.json", pptx_capability_data)

    deliverable_info = generate_deliverables(
        bundle=bundle,
        contexts={"internal": internal_context, "customer": customer_context},
        review_queue=review_queue,
        review_closure_status=review_closure_status,
        readiness=readiness,
        deliverables_root=deliverables_dir,
        deliverable_profile_dir=deliverable_profile_dir or Path(__file__).resolve().parents[2] / "configs" / "deliverable_profiles",
        deliverable_profile_name=deliverable_profile,
        generate_docx=generate_docx,
        final_delivery_included=finalize_delivery and readiness["status"] == "ready",
        real_input_selection=real_input_selection,
    )
    write_json(report_data_dir / "deliverables_manifest.json", deliverable_info)
    if preflight is not None:
        write_json(report_data_dir / "input_preflight.json", preflight)
        write_markdown(report_data_dir / "input_preflight.md", render_input_preflight_markdown(preflight))
    release_candidate_manifest = None
    if release_candidate:
        blocking_reasons = []
        if report_profile != "customer":
            blocking_reasons.append("report_profile_must_be_customer")
        if report_template != "default_customer":
            blocking_reasons.append("report_template_must_be_default_customer")
        if deliverable_profile not in {"customer_pack", "management_pack"}:
            blocking_reasons.append("deliverable_profile_must_be_customer_or_management_pack")
        blocking_reasons.extend(readiness.get("blocker_summary", []))
        candidate_status = "candidate_ready" if readiness["status"] == "ready" and not blocking_reasons else "candidate_blocked" if blocking_reasons else "candidate_with_warnings"
        release_candidate_manifest = {
            "run_id": run_id,
            "candidate_status": candidate_status,
            "readiness_status": readiness["status"],
            "unresolved_review_count": review_closure_status.get("unresolved_review_items", 0),
            "high_severity_count": qa_metrics.get("high_severity_count", 0),
            "compare_to_run": comparison.get("compared_run_id"),
            "package_ref": str(output_root / "delivery" / f"report_bundle_{run_id}.zip") if package_output else None,
            "generated_deliverables": deliverable_info.get("included_files", []),
            "blocking_reasons": blocking_reasons,
        }
        write_json(report_data_dir / "release_candidate_manifest.json", release_candidate_manifest)
    package_info = None
    customer_package_info = None
    internal_archive_info = None
    privacy_audit = None
    if package_output:
        package_info = package_run_output(output_root, run_id, extra_manifest=deliverable_info)
        write_json(report_data_dir / "delivery_package.json", package_info)
        delivery_dir = ensure_directory(output_root / "delivery")
        final_delivery_manifest_path = delivery_dir / "final_delivery_manifest.json"
        provisional_final_delivery = {
            "final_ready": False,
            "readiness_status": readiness["status"],
            "release_candidate_ref": str(report_data_dir / "release_candidate_manifest.json") if release_candidate else None,
            "included_files": deliverable_info.get("included_files", []),
            "excluded_files": deliverable_info.get("excluded_files", []),
            "delivery_version": metadata.get("report_version", "v1.0"),
            "approval_metadata": {
                "approver_name": metadata.get("approver_name"),
                "approver_title": metadata.get("approver_title"),
                "delivery_date": metadata.get("delivery_date"),
                "contact_email": metadata.get("contact_email"),
            },
            "closeout_summary": deliverable_info.get("closeout_summary", {}),
            "review_resolution_file_ref": str(review_resolution_path) if review_resolution_path else None,
            "submission_gate": {"status": "pending"},
            "blocking_reasons": [] if readiness["status"] == "ready" else readiness.get("blocker_summary", []),
        }
        write_json(final_delivery_manifest_path, provisional_final_delivery)
        customer_final_manifest_path = delivery_dir / "customer_final_delivery_manifest.json"
        internal_archive_info = package_curated_output(
            output_root,
            zip_name=f"internal_archive_{metadata.get('report_version', 'v1.0')}.zip",
            include_files=_internal_archive_files(output_root),
            manifest_name="internal_archive_manifest.json",
            checksums_name="internal_archive_checksums.json",
            extra_manifest={
                "package_type": "internal_archive",
                "included_files_policy": "customer outputs plus internal review and trace artifacts",
                "excluded_files": ["artifacts/raw/*"],
            },
        )
        submission_gate = None
        final_delivery = None
        if archive_only:
            write_json(
                report_data_dir / "archive_only_manifest.json",
                build_archive_only_manifest(
                    run_id=run_id,
                    archive_zip_path=internal_archive_info["zip_path"],
                    execution_options=execution_options,
                    regenerated_files=[
                        "delivery/internal_archive_manifest.json",
                        "delivery/internal_archive_checksums.json",
                        f"delivery/internal_archive_{metadata.get('report_version', 'v1.0')}.zip",
                    ],
                ),
            )
        else:
            write_json(customer_final_manifest_path, _customer_safe_final_manifest(provisional_final_delivery, deliverable_info))
            customer_package_info = package_curated_output(
                output_root,
                zip_name=f"customer_submission_{metadata.get('report_version', 'v1.0')}.zip",
                include_files=_customer_package_files(output_root, deliverable_info, customer_final_manifest_path),
                manifest_name="customer_submission_manifest.json",
                checksums_name="customer_submission_checksums.json",
                extra_manifest={
                    "package_type": "customer_submission",
                    "included_files_policy": "customer-facing outputs only",
                    "excluded_files": ["internal-only outputs omitted"],
                },
            )
            privacy_audit = build_customer_package_audit(
                run_root=output_root,
                included_files=customer_package_info["included_files"],
                excluded_files=_customer_exclusions(),
                zip_path=Path(customer_package_info["zip_path"]),
            )
            write_json(report_data_dir / "customer_package_audit.json", privacy_audit)
            write_markdown(report_data_dir / "customer_package_audit.md", render_customer_package_audit_markdown(privacy_audit))
            write_jsonl(report_data_dir / "customer_package_audit_findings.jsonl", privacy_audit.get("findings", []))
            submission_gate = build_submission_gate(
                readiness=readiness,
                review_closure_status=review_closure_status,
                deliverable_info=deliverable_info,
                customer_package_info=customer_package_info,
                final_delivery_manifest_path=final_delivery_manifest_path,
                branding_meta=metadata,
                require_pptx=require_pptx,
                privacy_audit=privacy_audit,
            )
            write_json(report_data_dir / "submission_gate.json", submission_gate)
            final_delivery = {
                "final_ready": readiness["status"] == "ready" and submission_gate["status"] != "fail",
                "readiness_status": readiness["status"],
                "release_candidate_ref": str(report_data_dir / "release_candidate_manifest.json") if release_candidate else None,
                "included_files": deliverable_info.get("included_files", []),
                "excluded_files": deliverable_info.get("excluded_files", []),
                "delivery_version": metadata.get("report_version", "v1.0"),
                "approval_metadata": {
                    "approver_name": metadata.get("approver_name"),
                    "approver_title": metadata.get("approver_title"),
                    "delivery_date": metadata.get("delivery_date"),
                    "contact_email": metadata.get("contact_email"),
                },
                "closeout_summary": deliverable_info.get("closeout_summary", {}),
                "review_resolution_file_ref": str(review_resolution_path) if review_resolution_path else None,
                "submission_gate": submission_gate,
                "customer_submission_zip": customer_package_info["zip_path"],
                "internal_archive_zip": internal_archive_info["zip_path"],
                "privacy_audit": {
                    "audit_result": privacy_audit["audit_result"],
                    "finding_count": len(privacy_audit.get("findings", [])),
                },
                "blocking_reasons": submission_gate["blocking_reasons"] or ([] if readiness["status"] == "ready" else readiness.get("blocker_summary", [])),
            }
            write_json(final_delivery_manifest_path, final_delivery)
            write_json(customer_final_manifest_path, _customer_safe_final_manifest(final_delivery, deliverable_info))
            customer_package_info = package_curated_output(
                output_root,
                zip_name=f"customer_submission_{metadata.get('report_version', 'v1.0')}.zip",
                include_files=_customer_package_files(output_root, deliverable_info, customer_final_manifest_path),
                manifest_name="customer_submission_manifest.json",
                checksums_name="customer_submission_checksums.json",
                extra_manifest={
                    "package_type": "customer_submission",
                    "included_files_policy": "customer-facing outputs only",
                    "excluded_files": ["internal-only outputs omitted"],
                    "submission_gate_status": submission_gate["status"],
                },
            )
            internal_archive_info = package_curated_output(
                output_root,
                zip_name=f"internal_archive_{metadata.get('report_version', 'v1.0')}.zip",
                include_files=_internal_archive_files(output_root),
                manifest_name="internal_archive_manifest.json",
                checksums_name="internal_archive_checksums.json",
                extra_manifest={
                    "package_type": "internal_archive",
                    "included_files_policy": "customer outputs plus internal review and trace artifacts",
                    "excluded_files": ["artifacts/raw/*"],
                    "submission_gate_status": submission_gate["status"],
                },
            )
            write_json(
                report_data_dir / "delivery_split_packages.json",
                {
                    "customer_submission": customer_package_info,
                    "internal_archive": internal_archive_info,
                },
            )
        if require_pptx and not deliverable_info.get("pptx_generated") and not finalize_delivery and not archive_only:
            raise RuntimeError("PPTX output required but python-pptx is unavailable or PPTX validation failed.")
        write_markdown(
            deliverables_dir / "operations_runbook.md",
            build_operations_runbook(
                run_root=output_root,
                execution_options=execution_options or {},
                preflight=preflight or {"status": "not_generated"},
            ),
        )
        write_markdown(
            deliverables_dir / "release_runbook.md",
            build_release_runbook(
                run_root=output_root,
                execution_options=execution_options or {},
                final_delivery_manifest=final_delivery or {"internal_archive_zip": internal_archive_info["zip_path"]},
                submission_gate=submission_gate,
            ),
        )
        write_markdown(
            deliverables_dir / "final_submission_check.md",
            build_final_submission_check(
                preflight=preflight,
                readiness=readiness,
                submission_gate=submission_gate,
                privacy_audit=privacy_audit,
                pptx_capability=pptx_capability_data,
                final_delivery_manifest=final_delivery,
            ),
        )
        write_markdown(
            deliverables_dir / "real_data_onboarding_checklist.md",
            build_real_data_onboarding_checklist(
                execution_options=execution_options or {},
                preflight=preflight,
                pptx_capability=pptx_capability_data,
            ),
        )
    else:
        write_markdown(
            deliverables_dir / "operations_runbook.md",
            build_operations_runbook(
                run_root=output_root,
                execution_options=execution_options or {},
                preflight=preflight or {"status": "not_generated"},
            ),
        )
        write_markdown(
            deliverables_dir / "release_runbook.md",
            build_release_runbook(
                run_root=output_root,
                execution_options=execution_options or {},
                final_delivery_manifest=None,
                submission_gate=None,
            ),
        )
        write_markdown(
            deliverables_dir / "final_submission_check.md",
            build_final_submission_check(
                preflight=preflight,
                readiness=readiness,
                submission_gate=None,
                privacy_audit=None,
                pptx_capability=pptx_capability_data,
                final_delivery_manifest=None,
            ),
        )
        write_markdown(
            deliverables_dir / "real_data_onboarding_checklist.md",
            build_real_data_onboarding_checklist(
                execution_options=execution_options or {},
                preflight=preflight,
                pptx_capability=pptx_capability_data,
            ),
        )
    return bundle


def _load_branding_metadata(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {"branding_applied": False}
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    metadata = {"branding_applied": True, "branding_source": str(path)}
    for key in [
        "cover_title",
        "subtitle",
        "organization_name",
        "client_name",
        "project_name",
        "report_version",
        "delivery_date",
        "approver_name",
        "approver_title",
        "contact_email",
        "footer_notice",
        "logo_path_optional",
    ]:
        if payload.get(key) not in {None, ""}:
            metadata[key] = payload[key]
    return metadata


def _customer_package_files(output_root: Path, deliverable_info: dict[str, Any], customer_manifest_path: Path) -> list[Path]:
    include_paths: list[Path] = []
    for key in ["customer_full_report", "customer_onepager", "customer_tracker", "customer_presentation"]:
        include_paths.extend(Path(path) for path in deliverable_info.get("customer_outputs", {}).get(key, []))
    include_paths.append(customer_manifest_path)
    return _dedupe_existing_paths(include_paths)


def _internal_archive_files(output_root: Path) -> list[Path]:
    include_paths: list[Path] = []
    for folder_name in ["reports", "deliverables", "report_data", "comparison", "delivery"]:
        folder = output_root / folder_name
        if not folder.exists():
            continue
        for path in folder.rglob("*"):
            if path.is_file() and path.suffix.lower() != ".zip":
                include_paths.append(path)
    artifact_dir = output_root / "artifacts"
    if artifact_dir.exists():
        for path in artifact_dir.rglob("*"):
            if path.is_file() and "raw" not in path.parts and path.suffix.lower() != ".zip":
                include_paths.append(path)
    return _dedupe_existing_paths(include_paths)


def _customer_exclusions() -> list[str]:
    return [
        "artifacts/raw/*",
        "report_data/review_queue.*",
        "report_data/override_template.yaml",
        "deliverables/analyst_handoff*",
        "report_data/*decisions*",
        "internal-only appendix",
    ]


def _dedupe_existing_paths(paths: list[Path]) -> list[Path]:
    ordered: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        if not path.exists():
            continue
        key = str(path)
        if key not in seen:
            ordered.append(path)
            seen.add(key)
    return ordered


def _customer_safe_final_manifest(final_delivery: dict[str, Any], deliverable_info: dict[str, Any]) -> dict[str, Any]:
    customer_safe = dict(final_delivery)
    customer_safe["included_files"] = []
    for key in ["customer_full_report", "customer_onepager", "customer_tracker", "customer_presentation"]:
        customer_safe["included_files"].extend(deliverable_info.get("customer_outputs", {}).get(key, []))
    customer_safe["excluded_files"] = ["internal-only outputs omitted"]
    customer_safe.pop("internal_archive_zip", None)
    return customer_safe
