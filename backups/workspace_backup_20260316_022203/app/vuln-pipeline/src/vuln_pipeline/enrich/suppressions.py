from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from vuln_pipeline.models import IssueCluster


def load_suppressions(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
    elif path.suffix.lower() in {".yaml", ".yml"}:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    else:
        raise ValueError(f"Unsupported suppression format: {path}")
    if isinstance(payload, dict):
        return payload.get("suppressions", [])
    if isinstance(payload, list):
        return payload
    raise ValueError("Suppression payload must be a list or {suppressions:[...]}.")


def apply_issue_suppressions(
    issues: list[IssueCluster],
    suppressions: list[dict[str, Any]],
) -> tuple[list[IssueCluster], list[IssueCluster], list[dict[str, Any]]]:
    active: list[IssueCluster] = []
    suppressed: list[IssueCluster] = []
    decision_rows: list[dict[str, Any]] = []
    for issue in issues:
        matched_rule = None
        reasons: list[str] = []
        for rule in suppressions:
            matched, reasons = _match_suppression(issue, rule)
            if matched:
                matched_rule = rule
                break
        if matched_rule:
            issue.suppressed = True
            issue.suppression_status = matched_rule.get("status", "suppressed")
            issue.suppression_note = matched_rule.get("note")
            suppressed.append(issue)
            decision_rows.append(
                {
                    "issue_id": issue.issue_id,
                    "cluster_key": issue.cluster_key,
                    "action": "suppressed",
                    "status": issue.suppression_status,
                    "matched_rule": matched_rule.get("id") or matched_rule.get("title_regex") or matched_rule.get("cluster_key"),
                    "match_reasons": reasons,
                }
            )
        else:
            active.append(issue)
            decision_rows.append(
                {
                    "issue_id": issue.issue_id,
                    "cluster_key": issue.cluster_key,
                    "action": "active",
                    "status": None,
                    "matched_rule": None,
                    "match_reasons": [],
                }
            )
    return active, suppressed, decision_rows


def _match_suppression(issue: IssueCluster, rule: dict[str, Any]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if rule.get("cluster_key") and issue.cluster_key != rule["cluster_key"]:
        return False, []
    if rule.get("cluster_key"):
        reasons.append("cluster_key")
    if rule.get("host") and rule["host"] not in issue.affected_assets:
        return False, []
    if rule.get("host"):
        reasons.append("host")
    if rule.get("path_pattern") and rule["path_pattern"] not in issue.cluster_key:
        return False, []
    if rule.get("path_pattern"):
        reasons.append("path_pattern")
    if rule.get("weakness_family") and issue.weakness_family != rule["weakness_family"]:
        return False, []
    if rule.get("weakness_family"):
        reasons.append("weakness_family")
    if rule.get("primary_cwe") and issue.primary_cwe != rule["primary_cwe"]:
        return False, []
    if rule.get("primary_cwe"):
        reasons.append("primary_cwe")
    if rule.get("title_regex"):
        if not re.search(rule["title_regex"], issue.title, re.IGNORECASE):
            return False, []
        reasons.append("title_regex")
    return bool(reasons), reasons
