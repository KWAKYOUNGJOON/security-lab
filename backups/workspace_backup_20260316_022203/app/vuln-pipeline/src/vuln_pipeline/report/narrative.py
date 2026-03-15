from __future__ import annotations

from typing import Any

from vuln_pipeline.models import IssueCluster, NormalizedFinding, ReportBundle


def build_issue_narrative(
    issue: IssueCluster,
    bundle: ReportBundle,
    knowledge: dict[str, Any],
    profile: dict[str, Any],
) -> dict[str, Any]:
    instances = [finding for finding in bundle.findings if finding.finding_id in issue.instances]
    confidence_low = issue.confidence.level == "Low"
    note = issue.analyst_note or _collect_analyst_note(instances)
    summary = _summary_line(issue, confidence_low)
    overview = note if note and "개요:" in note else knowledge["summary_ko"]
    why_it_matters = knowledge["risk_ko"]
    repro_points = _build_repro_points(instances, profile)
    impact_scope = _impact_scope(issue)
    remediation = _build_remediation(issue, knowledge, instances, note)
    caution = "현재 근거만으로는 최종 판단이 어려우므로 운영 환경에서 재확인이 필요합니다." if confidence_low else "동일 유형 입력 경로와 유사 기능까지 함께 점검하는 것이 좋습니다."
    return {
        "summary_line": summary,
        "overview": overview,
        "why_it_matters": why_it_matters,
        "repro_points": repro_points,
        "impact_scope": impact_scope,
        "quick_fix": remediation["quick_fix"],
        "structural_fix": remediation["structural_fix"],
        "validation_after_fix": remediation["validation_after_fix"],
        "caution": caution,
        "reference_labels": knowledge["references"],
        "analyst_note": note,
    }


def _summary_line(issue: IssueCluster, confidence_low: bool) -> str:
    suffix = "추가 확인이 필요합니다." if confidence_low else "우선 조치가 권고됩니다."
    return f"{issue.title} 이슈가 {', '.join(issue.affected_assets)} 자산에서 확인되었으며 {suffix}"


def _build_repro_points(instances: list[NormalizedFinding], profile: dict[str, Any]) -> list[str]:
    points: list[str] = []
    for finding in instances:
        for evidence in finding.evidence:
            points.extend(evidence.reproduction_steps)
            points.extend([value for value in evidence.highlights[:2] if value])
            if profile.get("show_raw_artifacts"):
                points.extend(evidence.artifact_links[:1])
    cleaned: list[str] = []
    for point in points:
        if point not in cleaned:
            cleaned.append(point)
    if not cleaned:
        cleaned.append("수집된 근거와 동일 경로에서 응답 차이와 필터링 동작을 재확인합니다.")
    if profile.get("repro_detail") == "restrained":
        return [point for point in cleaned if "artifact:" not in point][:3]
    return cleaned[:4]


def _impact_scope(issue: IssueCluster) -> str:
    asset_count = len(issue.affected_assets)
    return f"현재 클러스터 기준으로 {asset_count}개 자산, {issue.affected_instance_count}개 인스턴스에 영향이 있습니다."


def _build_remediation(
    issue: IssueCluster,
    knowledge: dict[str, Any],
    instances: list[NormalizedFinding],
    note: str | None,
) -> dict[str, list[str]]:
    manual = list(issue.remediation)
    for finding in instances:
        manual.extend(finding.remediation)
        override = finding.analyst.get("override", {})
        manual.extend(override.get("manual_remediation", []))
    deduped_manual = []
    for item in manual:
        if item and item not in deduped_manual:
            deduped_manual.append(item)
    base = knowledge["remediation_ko"]
    quick_fix = deduped_manual[:2] or base[:1]
    structural_fix = base[1:3] if len(base) > 1 else base[:1]
    validation_after_fix = knowledge["validation_points_ko"]
    if note and "재현" in note and note not in validation_after_fix:
        validation_after_fix = validation_after_fix + [note]
    return {
        "quick_fix": quick_fix,
        "structural_fix": structural_fix,
        "validation_after_fix": validation_after_fix,
    }


def _collect_analyst_note(instances: list[NormalizedFinding]) -> str | None:
    notes = [finding.analyst.get("note") for finding in instances if finding.analyst.get("note")]
    return " ".join(notes) if notes else None
