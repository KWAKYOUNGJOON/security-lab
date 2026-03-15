from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from vuln_pipeline.models import IssueCluster, NormalizedFinding


def load_overrides(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
    elif path.suffix.lower() in {".yaml", ".yml"}:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    else:
        raise ValueError(f"Unsupported override format: {path}")
    if isinstance(payload, dict):
        return payload.get("overrides", [])
    if isinstance(payload, list):
        return payload
    raise ValueError("Override payload must be a list or {overrides:[...]}.")


def apply_finding_overrides(
    findings: list[NormalizedFinding],
    overrides: list[dict[str, Any]],
) -> tuple[list[NormalizedFinding], list[dict[str, Any]]]:
    decision_rows: list[dict[str, Any]] = []
    by_id = {finding.finding_id: finding for finding in findings}
    for override in overrides:
        target_id = override.get("finding_id")
        if not target_id or target_id not in by_id:
            continue
        finding = by_id[target_id]
        before = {
            "title": finding.title,
            "primary_cwe": finding.classification.primary_cwe,
            "severity_score": finding.severity.score,
            "severity_level": finding.severity.level,
            "confidence": finding.confidence.score,
            "false_positive": finding.dedup.false_positive,
        }
        if override.get("override_title"):
            finding.title = override["override_title"]
        if override.get("override_primary_cwe"):
            finding.classification.primary_cwe = override["override_primary_cwe"]
        if override.get("override_related_cwes") is not None:
            finding.classification.related_cwes = list(override["override_related_cwes"])
        if override.get("override_owasp_top10_2025") is not None:
            finding.classification.owasp_top10_2025 = list(override["override_owasp_top10_2025"])
        if override.get("override_kisa_categories") is not None:
            finding.classification.kisa_categories = list(override["override_kisa_categories"])
        if override.get("override_severity_score") is not None:
            finding.severity.score = float(override["override_severity_score"])
            finding.severity.overridden = True
        if override.get("override_severity_level"):
            finding.severity.level = override["override_severity_level"]
            finding.severity.overridden = True
        if override.get("override_confidence") is not None:
            finding.confidence.score = float(override["override_confidence"])
            finding.confidence.analyst_override = float(override["override_confidence"])
            finding.confidence.overridden = True
        if override.get("false_positive") is not None:
            finding.dedup.false_positive = bool(override["false_positive"])
        if override.get("manual_remediation"):
            finding.remediation = list(override["manual_remediation"])
        if override.get("analyst_note"):
            finding.analyst["note"] = override["analyst_note"]
        finding.analyst["override"] = override
        decision_rows.append(
            {
                "target_type": "finding",
                "target_id": target_id,
                "before": before,
                "after": {
                    "title": finding.title,
                    "primary_cwe": finding.classification.primary_cwe,
                    "severity_score": finding.severity.score,
                    "severity_level": finding.severity.level,
                    "confidence": finding.confidence.score,
                    "false_positive": finding.dedup.false_positive,
                },
            }
        )
    return findings, decision_rows


def apply_issue_overrides(
    issues: list[IssueCluster],
    overrides: list[dict[str, Any]],
) -> tuple[list[IssueCluster], list[dict[str, Any]]]:
    decision_rows: list[dict[str, Any]] = []
    by_id = {issue.issue_id: issue for issue in issues}
    for override in overrides:
        target_id = override.get("issue_id")
        if not target_id or target_id not in by_id:
            continue
        issue = by_id[target_id]
        before = {
            "title": issue.title,
            "primary_cwe": issue.primary_cwe,
            "severity_score": issue.severity.score,
            "severity_level": issue.severity.level,
            "confidence": issue.confidence.score,
            "false_positive": issue.false_positive,
            "recommended_owner": issue.recommended_owner,
            "target_due": issue.target_due,
        }
        if override.get("override_title"):
            issue.title = override["override_title"]
        if override.get("override_primary_cwe"):
            issue.primary_cwe = override["override_primary_cwe"]
            issue.classification.primary_cwe = override["override_primary_cwe"]
        if override.get("override_related_cwes") is not None:
            issue.related_cwes = list(override["override_related_cwes"])
            issue.classification.related_cwes = list(override["override_related_cwes"])
        if override.get("override_owasp_top10_2025") is not None:
            issue.classification.owasp_top10_2025 = list(override["override_owasp_top10_2025"])
        if override.get("override_kisa_categories") is not None:
            issue.classification.kisa_categories = list(override["override_kisa_categories"])
        if override.get("override_severity_score") is not None:
            issue.severity.score = float(override["override_severity_score"])
            issue.severity.overridden = True
        if override.get("override_severity_level"):
            issue.severity.level = override["override_severity_level"]
            issue.severity.overridden = True
        if override.get("override_confidence") is not None:
            issue.confidence.score = float(override["override_confidence"])
            issue.confidence.overridden = True
        if override.get("false_positive") is not None:
            issue.false_positive = bool(override["false_positive"])
        if override.get("analyst_note"):
            issue.analyst_note = override["analyst_note"]
        if override.get("manual_remediation"):
            issue.remediation = list(override["manual_remediation"])
        if override.get("recommended_owner"):
            issue.recommended_owner = override["recommended_owner"]
        if override.get("target_due"):
            issue.target_due = override["target_due"]
        decision_rows.append(
            {
                "target_type": "issue",
                "target_id": target_id,
                "before": before,
                "after": {
                    "title": issue.title,
                    "primary_cwe": issue.primary_cwe,
                    "severity_score": issue.severity.score,
                    "severity_level": issue.severity.level,
                    "confidence": issue.confidence.score,
                    "false_positive": issue.false_positive,
                    "recommended_owner": issue.recommended_owner,
                    "target_due": issue.target_due,
                },
            }
        )
    return issues, decision_rows
