from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from vuln_pipeline.models import IssueCluster


def load_yaml_policy(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def apply_remediation_policy(
    issues: list[IssueCluster],
    owner_policy_path: Path,
    due_policy_path: Path,
) -> dict[str, Any]:
    owner_policy = load_yaml_policy(owner_policy_path)
    due_policy = load_yaml_policy(due_policy_path)
    rows: list[dict[str, Any]] = []
    for issue in issues:
        if not issue.recommended_owner:
            issue.recommended_owner = _resolve_owner(issue, owner_policy)
        if not issue.target_due:
            issue.target_due = _resolve_due(issue, due_policy)
        rows.append(
            {
                "issue_id": issue.issue_id,
                "recommended_owner": issue.recommended_owner,
                "target_due": issue.target_due,
                "surface": _surface(issue),
            }
        )
    return {
        "owner_policy": owner_policy.get("policy_name", owner_policy_path.stem),
        "due_policy": due_policy.get("policy_name", due_policy_path.stem),
        "rows": rows,
    }


def _resolve_owner(issue: IssueCluster, policy: dict[str, Any]) -> str:
    surface = _surface(issue)
    for rule in policy.get("rules", []):
        if rule.get("weakness_family") and issue.weakness_family not in rule["weakness_family"]:
            continue
        if rule.get("primary_cwe") and issue.primary_cwe not in rule["primary_cwe"]:
            continue
        if rule.get("severity") and issue.severity.level not in rule["severity"]:
            continue
        if rule.get("surface") and surface not in rule["surface"]:
            continue
        return rule.get("owner", policy.get("default_owner", "AppSec"))
    return policy.get("default_owner", "AppSec")


def _resolve_due(issue: IssueCluster, policy: dict[str, Any]) -> str:
    for rule in policy.get("rules", []):
        if rule.get("severity") and issue.severity.level not in rule["severity"]:
            continue
        return rule.get("due", policy.get("default_due", "TBD"))
    return policy.get("default_due", "TBD")


def _surface(issue: IssueCluster) -> str:
    cluster = issue.cluster_key.lower()
    if "/api/" in cluster:
        return "api"
    if "/admin" in cluster:
        return "admin"
    if any(token in cluster for token in ["static", "files", "download"]):
        return "static"
    return "web"
