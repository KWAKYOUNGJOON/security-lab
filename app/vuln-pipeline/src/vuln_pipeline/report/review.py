from __future__ import annotations

from typing import Any

from vuln_pipeline.models import IssueCluster, NormalizedFinding, ReportBundle


def build_review_queue(
    bundle: ReportBundle,
    mapping_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    findings_by_id = {finding.finding_id: finding for finding in bundle.findings}
    mappings_by_id = {row.get("finding_id"): row for row in mapping_rows}
    for issue in bundle.issues:
        review_reason = _review_reasons(issue, findings_by_id, mappings_by_id, bundle.report_profile)
        if not review_reason:
            continue
        host, path_pattern = _extract_host_path(issue)
        priority_score = _priority_score(issue, review_reason)
        rows.append(
            {
                "run_id": bundle.run_id,
                "issue_id": issue.issue_id,
                "finding_ids": issue.instances,
                "title": issue.title,
                "weakness_family": issue.weakness_family,
                "primary_cwe": issue.primary_cwe,
                "severity_level": issue.severity.level,
                "confidence_level": issue.confidence.level,
                "review_reason": review_reason,
                "recommended_action": _recommended_action(issue, review_reason),
                "host": host,
                "path_pattern": path_pattern,
                "current_status": issue.suppression_status or ("false_positive" if issue.false_positive else "open"),
                "priority_score": priority_score,
                "priority_band": _priority_band(priority_score),
                "suggested_sla": _suggested_sla(issue.severity.level),
            }
        )
    return sorted(rows, key=lambda row: row["priority_score"], reverse=True)


def render_review_queue_markdown(rows: list[dict[str, Any]]) -> str:
    lines = [
        "# Review Queue",
        "",
        "| Issue ID | Severity | Confidence | Priority | SLA | Review Reason | Recommended Action |",
        "|---|---|---|---:|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['issue_id']} | {row['severity_level']} | {row['confidence_level']} | "
            f"{row['priority_score']} ({row['priority_band']}) | {row['suggested_sla']} | "
            f"{'; '.join(row['review_reason'])} | {row['recommended_action']} |"
        )
    if not rows:
        lines.append("| - | - | - | 0 | - | No review items | - |")
    return "\n".join(lines) + "\n"


def build_override_template(rows: list[dict[str, Any]]) -> dict[str, Any]:
    overrides: list[dict[str, Any]] = []
    for row in rows:
        overrides.append(
            {
                "issue_id": row["issue_id"],
                "override_title": None,
                "override_primary_cwe": None,
                "override_severity_score": None,
                "override_severity_level": None,
                "override_confidence": None,
                "recommended_owner": None,
                "target_due": None,
                "false_positive": False,
                "analyst_note": f"Review reasons: {', '.join(row['review_reason'])}",
                "manual_remediation": [],
            }
        )
    return {"overrides": overrides}


def _review_reasons(
    issue: IssueCluster,
    findings_by_id: dict[str, NormalizedFinding],
    mappings_by_id: dict[str, dict[str, Any]],
    report_profile: str,
) -> list[str]:
    reasons: list[str] = []
    if not issue.primary_cwe:
        reasons.append("primary_cwe_missing")
    if issue.confidence.level == "Low":
        reasons.append("low_confidence")
    if issue.severity.level in {"Critical", "High"}:
        reasons.append("high_severity_requires_review")
    if not issue.analyst_note:
        reasons.append("override_not_applied")
    if not issue.evidence_summary:
        reasons.append("evidence_missing")
    if report_profile == "customer":
        reasons.append("customer_release_review")
    for finding_id in issue.instances:
        decision = mappings_by_id.get(finding_id, {})
        if decision.get("rejected_rules"):
            reasons.append("rule_conflict_detected")
            break
    deduped: list[str] = []
    for reason in reasons:
        if reason not in deduped:
            deduped.append(reason)
    return deduped


def _recommended_action(issue: IssueCluster, reasons: list[str]) -> str:
    if "primary_cwe_missing" in reasons or "rule_conflict_detected" in reasons:
        return "Validate mapping and update override if needed."
    if "evidence_missing" in reasons:
        return "Collect additional evidence before customer delivery."
    if issue.severity.level in {"Critical", "High"}:
        return "Perform analyst confirmation and assign remediation owner."
    return "Perform analyst triage."


def _extract_host_path(issue: IssueCluster) -> tuple[str, str]:
    parts = issue.cluster_key.split("|")
    host = parts[1] if len(parts) > 1 else ""
    path_pattern = parts[2] if len(parts) > 2 else ""
    return host, path_pattern


def _priority_score(issue: IssueCluster, reasons: list[str]) -> int:
    score = {"Critical": 100, "High": 80, "Medium": 50, "Low": 20, "Info": 5}.get(issue.severity.level, 0)
    if "low_confidence" in reasons:
        score += 20
    if "primary_cwe_missing" in reasons:
        score += 20
    if "evidence_missing" in reasons:
        score += 15
    if "rule_conflict_detected" in reasons:
        score += 15
    if "customer_release_review" in reasons:
        score += 10
    return score


def _priority_band(score: int) -> str:
    if score >= 90:
        return "P1"
    if score >= 70:
        return "P2"
    if score >= 40:
        return "P3"
    return "P4"


def _suggested_sla(severity: str) -> str:
    return {"Critical": "24h", "High": "3d", "Medium": "7d", "Low": "14d", "Info": "Backlog"}.get(severity, "Backlog")
