from __future__ import annotations

from collections import defaultdict
from typing import Any

from vuln_pipeline.fingerprint import build_cluster_key
from vuln_pipeline.models import Classification, ConfidenceInfo, IssueCluster, NormalizedFinding, SeverityInfo


def cluster_findings(findings: list[NormalizedFinding]) -> tuple[list[NormalizedFinding], list[IssueCluster], list[dict[str, Any]]]:
    exact_seen: dict[str, str] = {}
    deduped: list[NormalizedFinding] = []
    decisions: list[dict[str, Any]] = []
    for finding in findings:
        if finding.dedup.exact_fingerprint in exact_seen:
            finding.dedup.is_duplicate = True
            finding.dedup.duplicate_of = exact_seen[finding.dedup.exact_fingerprint]
            decisions.append(
                {
                    "finding_id": finding.finding_id,
                    "action": "dedup_skipped",
                    "duplicate_of": finding.dedup.duplicate_of,
                    "exact_fingerprint": finding.dedup.exact_fingerprint,
                }
            )
            continue
        exact_seen[finding.dedup.exact_fingerprint] = finding.finding_id
        finding.dedup.cluster_key = build_cluster_key(finding)
        deduped.append(finding)
        decisions.append(
            {
                "finding_id": finding.finding_id,
                "action": "cluster_candidate",
                "cluster_key": finding.dedup.cluster_key,
                "false_positive": finding.dedup.false_positive,
            }
        )

    grouped: dict[str, list[NormalizedFinding]] = defaultdict(list)
    for finding in deduped:
        if finding.dedup.false_positive:
            continue
        grouped[finding.dedup.cluster_key or finding.finding_id].append(finding)

    issues: list[IssueCluster] = []
    for index, (cluster_key, members) in enumerate(grouped.items(), start=1):
        representative = sorted(members, key=lambda item: (item.severity.score, item.confidence.score), reverse=True)[0]
        severity = SeverityInfo(
            raw=None,
            score=max(member.severity.score for member in members),
            level=sorted(members, key=lambda item: item.severity.score, reverse=True)[0].severity.level,
            rationale=["cluster=max(member severity)"],
        )
        confidence_average = sum(member.confidence.score for member in members) / len(members)
        confidence = ConfidenceInfo(
            raw=None,
            score=round(confidence_average, 2),
            level="High" if confidence_average >= 0.85 else "Medium" if confidence_average >= 0.55 else "Low",
            rationale=["cluster=average(member confidence)"],
        )
        references = sorted({reference for member in members for reference in member.references})
        remediation = representative.remediation
        evidence_summary = _collect_evidence_summary(members)
        classification = representative.classification if any(member.classification.primary_cwe for member in members) else Classification()
        analyst_note = " | ".join(
            [member.analyst.get("note") for member in members if isinstance(member.analyst.get("note"), str)]
        ) or None
        issue = IssueCluster(
            issue_id=f"I-{index:04d}",
            cluster_key=cluster_key,
            title=representative.title,
            weakness_family=classification.weakness_family,
            affected_assets=sorted({member.asset.host or member.asset.url or "unknown" for member in members}),
            instances=[member.finding_id for member in members],
            primary_cwe=classification.primary_cwe,
            related_cwes=classification.related_cwes,
            severity=severity,
            confidence=confidence,
            evidence_summary=evidence_summary,
            remediation=remediation,
            references=references,
            classification=classification,
            analyst_note=analyst_note,
            affected_instance_count=len(members),
        )
        issues.append(issue)
        decisions.append(
            {
                "issue_id": issue.issue_id,
                "cluster_key": cluster_key,
                "instances": issue.instances,
                "affected_assets": issue.affected_assets,
                "title": issue.title,
            }
        )
    return deduped, issues, decisions


def _collect_evidence_summary(members: list[NormalizedFinding]) -> list[str]:
    summary: list[str] = []
    for member in members:
        for item in member.evidence:
            summary.append(item.summary)
            summary.extend(item.highlights[:2])
            for link in item.artifact_links[:2]:
                summary.append(f"artifact: {link}")
        if len(summary) >= 3:
            break
    return summary[:3]
