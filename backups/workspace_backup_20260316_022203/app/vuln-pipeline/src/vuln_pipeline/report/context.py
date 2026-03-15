from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from vuln_pipeline.models import ReportBundle
from vuln_pipeline.report.knowledge import KnowledgePack, load_report_profile, load_report_template
from vuln_pipeline.report.narrative import build_issue_narrative


def build_report_context(
    bundle: ReportBundle,
    knowledge_dir: Path,
    profile_dir: Path,
    profile_name: str,
    report_data_dir: Path,
    template_dir: Path | None = None,
    template_name: str | None = None,
    document_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    knowledge_pack = KnowledgePack(knowledge_dir)
    profile = load_report_profile(profile_dir, profile_name)
    resolved_template_dir = template_dir or Path(__file__).resolve().parents[3] / "configs" / "report_templates"
    resolved_template_name = template_name or ("default_customer" if profile_name == "customer" else "default_internal")
    template = load_report_template(resolved_template_dir, resolved_template_name)
    active_issues = [issue for issue in bundle.issues if not issue.false_positive and not issue.suppressed]
    severity_stats = Counter(issue.severity.level for issue in active_issues)
    family_stats = Counter(issue.weakness_family or "Uncategorized" for issue in active_issues)
    asset_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    narratives: list[dict[str, Any]] = []
    artifact_index: list[dict[str, str]] = []

    for issue in active_issues:
        narrative = build_issue_narrative(issue, bundle, knowledge_pack.describe_issue(issue), profile)
        narratives.append({"issue": issue, "narrative": narrative})
        for asset in issue.affected_assets:
            asset_groups[asset].append({"issue_id": issue.issue_id, "title": issue.title, "severity": issue.severity.level})
    for finding in bundle.findings:
        for evidence in finding.evidence:
            if evidence.artifact:
                artifact_index.append(
                    {
                        "finding_id": finding.finding_id,
                        "type": evidence.type,
                        "raw": evidence.artifact.raw_path or "",
                        "redacted": evidence.artifact.redacted_path or "",
                    }
                )

    meta = _build_document_meta(bundle, document_meta or {})
    template = _merge_template_with_branding(template, meta)
    executive_summary = _build_executive_summary(bundle, active_issues, severity_stats, profile, template)
    action_plan = _build_action_plan(narratives)
    remediation_plan = _build_remediation_plan(narratives, template)
    appendix = {
        "override_targets": bundle.override_summary.get("targets", []),
        "false_positive_findings": [{"finding_id": item.finding_id, "title": item.title} for item in bundle.false_positive_findings],
        "suppressed_issues": [
            {
                "issue_id": item.issue_id,
                "title": item.title,
                "status": item.suppression_status,
                "note": item.suppression_note,
            }
            for item in bundle.suppressed_issues
        ],
        "artifact_index": artifact_index,
        "trace_files": _trace_files(report_data_dir, profile),
    }
    return {
        "bundle": bundle,
        "profile": profile,
        "template": template,
        "document_meta": meta,
        "narratives": narratives,
        "severity_stats": severity_stats,
        "family_stats": family_stats,
        "asset_groups": asset_groups,
        "executive_summary": executive_summary,
        "action_plan": action_plan,
        "remediation_plan": remediation_plan,
        "comparison_summary": bundle.comparison_summary,
        "qa_metrics": bundle.qa_metrics,
        "appendix": appendix,
    }


def _build_document_meta(bundle: ReportBundle, overrides: dict[str, Any]) -> dict[str, str]:
    return {
        "project_name": overrides.get("project_name") or "Web Vulnerability Assessment",
        "client_name": overrides.get("client_name") or "Internal Client",
        "engagement_name": overrides.get("engagement_name") or "Security Review",
        "analyst_name": overrides.get("analyst_name") or "Analyst Team",
        "organization_name": overrides.get("organization_name") or "Security Operations",
        "report_version": overrides.get("report_version") or "v1.0",
        "delivery_date": overrides.get("delivery_date") or bundle.generated_at.split("T")[0],
        "approver_name": overrides.get("approver_name") or "TBD",
        "contact_email": overrides.get("contact_email") or "security@example.local",
        "run_id": bundle.run_id,
        "generated_at": bundle.generated_at,
        "compared_run_id": overrides.get("compared_run_id") or bundle.comparison_summary.get("compared_run_id") or "N/A",
        "run_mode": overrides.get("run_mode") or "single",
        "cover_title": overrides.get("cover_title") or "",
        "subtitle": overrides.get("subtitle") or "",
        "footer_notice": overrides.get("footer_notice") or "",
        "logo_path_optional": overrides.get("logo_path_optional") or "",
        "approver_title": overrides.get("approver_title") or "",
        "branding_applied": "true" if overrides.get("branding_applied") else "false",
    }


def _build_executive_summary(
    bundle: ReportBundle,
    active_issues: list[Any],
    severity_stats: Counter[str],
    profile: dict[str, Any],
    template: dict[str, Any],
) -> str:
    if not active_issues:
        return "이번 실행에서는 보고 대상 이슈가 확인되지 않았습니다."
    high_or_above = severity_stats.get("Critical", 0) + severity_stats.get("High", 0)
    top3 = ", ".join(issue.title for issue in active_issues[:3])
    asset_count = len({asset for issue in active_issues for asset in issue.affected_assets})
    fp_note = f"false positive {len(bundle.false_positive_findings)}건은 본문에서 제외했습니다."
    suppression_note = f" suppression {len(bundle.suppressed_issues)}건은 운영 기준에 따라 별도 관리합니다."
    comparison_note = ""
    if bundle.comparison_summary.get("available"):
        comparison_note = (
            f" 이전 실행({bundle.comparison_summary.get('compared_run_id')}) 대비 "
            f"신규 {len(bundle.comparison_summary.get('new_issues', []))}건, "
            f"해결 {len(bundle.comparison_summary.get('resolved_issues', []))}건 변화가 있습니다."
        )
    tone = (
        "추가 근거와 재현 검토를 전제로 해석하는 것이 적절합니다."
        if profile["id"] == "internal"
        else "고객 공유용으로는 핵심 영향과 개선 우선순위 중심으로 정리했습니다."
    )
    return (
        f"{template.get('executive_summary_prefix', '')} "
        f"이번 실행에서는 총 {len(active_issues)}건의 보고 대상 이슈가 확인되었고 "
        f"High 이상은 {high_or_above}건입니다. 우선 조치 대상은 {top3}이며, "
        f"현재 {asset_count}개 자산 범위에서 영향이 확인되었습니다. {fp_note}"
        f"{suppression_note}{comparison_note} 본 결과는 analyst review가 필요한 자동 분석 산출물입니다. {tone}"
    ).strip()


def _build_action_plan(narratives: list[dict[str, Any]]) -> dict[str, list[str]]:
    quick_fix: list[str] = []
    structural_fix: list[str] = []
    validation_after_fix: list[str] = []
    for item in narratives:
        for target, bucket in [
            ("quick_fix", quick_fix),
            ("structural_fix", structural_fix),
            ("validation_after_fix", validation_after_fix),
        ]:
            for value in item["narrative"][target]:
                if value not in bucket:
                    bucket.append(value)
    return {
        "즉시 조치 권고": quick_fix[:5],
        "단기 개선": structural_fix[:5],
        "중장기 개선": validation_after_fix[:5],
    }


def _build_remediation_plan(narratives: list[dict[str, Any]], template: dict[str, Any]) -> list[dict[str, str]]:
    headings = template.get("remediation_headings", {})
    rows: list[dict[str, str]] = []
    for item in narratives:
        issue = item["issue"]
        narrative = item["narrative"]
        rows.append(
            {
                "issue_id": issue.issue_id,
                "title": issue.title,
                "severity": issue.severity.level,
                "immediate": "; ".join(narrative["quick_fix"]),
                "structural": "; ".join(narrative["structural_fix"]),
                "validation": "; ".join(narrative["validation_after_fix"]),
                "owner": "",
                "due": "",
                "immediate_heading": headings.get("immediate", "즉시 조치"),
                "structural_heading": headings.get("structural", "근본 개선"),
                "validation_heading": headings.get("validation", "조치 후 확인사항"),
            }
        )
    return rows


def _trace_files(report_data_dir: Path, profile: dict[str, Any]) -> list[str]:
    paths = [
        report_data_dir / "final_report_bundle.json",
        report_data_dir / "report_context.json",
        report_data_dir / "mapping_decisions.jsonl",
        report_data_dir / "scoring_decisions.jsonl",
        report_data_dir / "override_decisions.jsonl",
        report_data_dir / "cluster_decisions.jsonl",
        report_data_dir / "suppression_decisions.jsonl",
        report_data_dir / "review_queue.jsonl",
        report_data_dir / "review_resolution_applied.jsonl",
        report_data_dir / "review_closure_status.json",
        report_data_dir / "qa_metrics.json",
        report_data_dir / "remediation_policy_decisions.json",
        report_data_dir / "release_readiness.json",
        report_data_dir / "release_candidate_manifest.json",
        report_data_dir / "deliverables_manifest.json",
        report_data_dir / "ingest_manifest.json",
    ]
    existing = [path for path in paths if path.exists()]
    if not profile.get("show_trace_paths"):
        return [path.name for path in existing]
    return [str(path) for path in existing]


def _merge_template_with_branding(template: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any]:
    merged = dict(template)
    if meta.get("cover_title"):
        merged["cover_title"] = meta["cover_title"]
    if meta.get("subtitle"):
        merged["cover_subtitle"] = meta["subtitle"]
    return merged
