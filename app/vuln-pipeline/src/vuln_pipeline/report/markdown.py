from __future__ import annotations

import re


def render_markdown_report(context: dict) -> str:
    bundle = context["bundle"]
    profile = context["profile"]
    template = context["template"]
    meta = context["document_meta"]
    lines = [
        f"# {template['cover_title']} ({profile['title_suffix']})",
        "",
        f"> {template['cover_subtitle']}",
        "> 본 문서는 자동 분석 결과를 기반으로 작성되었으며 최종 제출 전 analyst review가 필요합니다.",
        "",
        "## 1. 표지 및 문서 정보",
    ]
    for field in template.get("info_fields", []):
        lines.append(f"- {field}: `{meta.get(field, '')}`")
    lines.extend(["", "## 2. 실행 정보", f"- 입력 파일 수: {len(bundle.input_files)}"])
    for path in bundle.input_files:
        shown = path if profile["show_internal_paths"] else _mask_path(path)
        lines.append(f"- 입력 파일: `{shown}`")

    if context["comparison_summary"].get("available"):
        diff = context["comparison_summary"]
        lines.extend(
            [
                "",
                "## 3. 이전 실행 대비 변화",
                f"- 비교 기준 run_id: `{diff.get('compared_run_id')}`",
                f"- 신규 이슈: {len(diff.get('new_issues', []))}",
                f"- 해결 이슈: {len(diff.get('resolved_issues', []))}",
                f"- 변경 이슈: {len(diff.get('changed_issues', []))}",
                f"- 유지 이슈: {len(diff.get('unchanged_issues', []))}",
            ]
        )

    lines.extend(["", "## 4. Executive Summary", context["executive_summary"], ""])
    lines.extend(["## 5. Severity 통계", "", "| Level | Count |", "|---|---:|"])
    for level in ["Critical", "High", "Medium", "Low", "Info"]:
        lines.append(f"| {level} | {context['severity_stats'].get(level, 0)} |")

    lines.extend(["", "## 6. Weakness Family 통계", "", "| Weakness Family | Count |", "|---|---:|"])
    for family, count in sorted(context["family_stats"].items()):
        lines.append(f"| {family} | {count} |")

    lines.extend(["", "## 7. 자산별 Findings 요약", "", "| Asset | Issues |", "|---|---|"])
    for asset, issues in sorted(context["asset_groups"].items()):
        labels = ", ".join(f"{item['issue_id']} ({item['severity']})" for item in issues)
        lines.append(f"| {asset} | {labels} |")

    lines.extend(["", "## 8. 조치 우선순위 및 실행 계획"])
    for section, items in context["action_plan"].items():
        lines.append(f"### {section}")
        for item in items or ["해당 항목 없음"]:
            lines.append(f"- {item}")
        lines.append("")

    lines.extend(
        [
            "## 9. Remediation Plan",
            "",
            "| Issue ID | Title | Severity | Immediate Action | Structural Fix | Validation After Fix | Owner | Target Due |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )
    for row in context["remediation_plan"]:
        lines.append(
            f"| {row['issue_id']} | {row['title']} | {row['severity']} | {_inline(row['immediate'])} | {_inline(row['structural'])} | {_inline(row['validation'])} | {row['owner'] or '-'} | {row['due'] or '-'} |"
        )

    lines.extend(["", "## 10. 상세 Findings"])
    for item in context["narratives"]:
        issue = item["issue"]
        narrative = item["narrative"]
        evidence_summary = _sanitize_text("; ".join(issue.evidence_summary) or "수집된 대표 증거가 없습니다.", profile)
        repro_points = "; ".join(_sanitize_text(point, profile) for point in narrative["repro_points"])
        lines.extend(
            [
                f"### {issue.issue_id}. {issue.title}",
                f"- 한 줄 요약: {narrative['summary_line']}",
                f"- 영향 자산: {', '.join(issue.affected_assets)}",
                f"- Severity / Confidence: `{issue.severity.level} ({issue.severity.score}) / {issue.confidence.level} ({issue.confidence.score})`",
                f"- CWE / OWASP / KISA: `{issue.primary_cwe or 'N/A'}` / `{', '.join(issue.classification.owasp_top10_2025) or 'N/A'}` / `{', '.join(issue.classification.kisa_categories) or 'N/A'}`",
                f"- 개요: {narrative['overview']}",
                f"- 왜 문제인지: {narrative['why_it_matters']}",
                f"- 증거 요약: {evidence_summary}",
                f"- 재현/확인 포인트: {repro_points}",
                f"- 영향: {narrative['impact_scope']}",
                f"- {row_heading(context, 'immediate')}: {'; '.join(narrative['quick_fix'])}",
                f"- {row_heading(context, 'structural')}: {'; '.join(narrative['structural_fix'])}",
                f"- {row_heading(context, 'validation')}: {'; '.join(narrative['validation_after_fix'])}",
                f"- 실무 주의사항: {narrative['caution']}",
                f"- Reference Labels: {', '.join(narrative['reference_labels']) or 'N/A'}",
            ]
        )
        if profile.get("show_analyst_note") and narrative.get("analyst_note"):
            lines.append(f"- 비고: {narrative['analyst_note']}")
        lines.append("")

    lines.extend(["## 11. QA Metrics", ""])
    for key, value in context["qa_metrics"].items():
        if key == "qa_warnings":
            continue
        lines.append(f"- {key}: {value}")
    lines.append("- qa_warnings:")
    for warning in context["qa_metrics"].get("qa_warnings", []) or ["none"]:
        lines.append(f"  - {warning}")

    lines.extend(["", "## 12. 부록"])
    appendix = template.get("appendix_sections", [])
    if "override" in appendix:
        lines.append("### Override 적용 내역")
        for target in bundle.override_summary.get("targets", []):
            lines.append(f"- {target}")
        if not bundle.override_summary.get("targets"):
            lines.append("- 적용된 override 없음")
        lines.append("")
    if "false_positive" in appendix:
        lines.append("### False Positive 목록")
        for finding in bundle.false_positive_findings:
            lines.append(f"- `{finding.finding_id}` {finding.title}")
        if not bundle.false_positive_findings:
            lines.append("- 없음")
        lines.append("")
    if "suppressed" in appendix:
        lines.append("### Suppressed / Accepted Risk 목록")
        for suppressed in context["appendix"]["suppressed_issues"]:
            lines.append(f"- `{suppressed['issue_id']}` {suppressed['title']} ({suppressed['status']})")
        if not context["appendix"]["suppressed_issues"]:
            lines.append("- 없음")
        lines.append("")
    if "artifact_index" in appendix:
        lines.append("### Artifact 참조 인덱스")
        for artifact in context["appendix"]["artifact_index"]:
            raw = artifact["raw"] if profile.get("show_raw_artifacts") else _mask_path(artifact["redacted"] or artifact["raw"])
            redacted = artifact["redacted"] if profile.get("show_internal_paths") else _mask_path(artifact["redacted"])
            lines.append(f"- {artifact['finding_id']} {artifact['type']}: raw=`{raw}` redacted=`{redacted}`")
        if not context["appendix"]["artifact_index"]:
            lines.append("- 없음")
        lines.append("")
    if "decision_trace" in appendix:
        lines.append("### Decision Trace 요약")
        for path in context["appendix"]["trace_files"]:
            lines.append(f"- `{path}`")
    return "\n".join(lines) + "\n"


def row_heading(context: dict, key: str) -> str:
    return context["template"].get("remediation_headings", {}).get(
        {"immediate": "immediate", "structural": "structural", "validation": "validation"}[key],
        {"immediate": "즉시 조치", "structural": "근본 개선", "validation": "조치 후 확인사항"}[key],
    )


def _mask_path(value: str) -> str:
    if not value:
        return value
    return value.split("\\")[-1]


def _sanitize_text(value: str, profile: dict) -> str:
    if profile.get("show_internal_paths"):
        return value
    return re.sub(r"[A-Za-z]:\\[^;\s]+", lambda match: _mask_path(match.group(0)), value)


def _inline(value: str) -> str:
    return value.replace("\n", " ").replace("|", "/")
