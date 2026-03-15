from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vuln_pipeline.models import ReportBundle


def compare_runs(current_bundle: ReportBundle, baseline_run_root: Path | None) -> dict[str, Any]:
    if baseline_run_root is None:
        return {
            "compared_run_id": None,
            "new_issues": [],
            "resolved_issues": [],
            "changed_issues": [],
            "unchanged_issues": [],
            "available": False,
        }
    bundle_path = baseline_run_root / "report_data" / "final_report_bundle.json"
    if not bundle_path.exists():
        return {
            "compared_run_id": baseline_run_root.name,
            "new_issues": [],
            "resolved_issues": [],
            "changed_issues": [],
            "unchanged_issues": [],
            "available": False,
            "warning": f"Baseline bundle not found: {bundle_path}",
        }
    baseline = json.loads(bundle_path.read_text(encoding="utf-8"))
    previous = {item["cluster_key"]: item for item in baseline.get("issues", [])}
    current = {item.cluster_key: item for item in current_bundle.issues}
    diff = {
        "compared_run_id": baseline.get("run_id", baseline_run_root.name),
        "new_issues": [],
        "resolved_issues": [],
        "changed_issues": [],
        "unchanged_issues": [],
        "available": True,
    }
    for cluster_key, issue in current.items():
        before = previous.get(cluster_key)
        if before is None:
            diff["new_issues"].append(_current_issue(issue))
            continue
        changes = _changed_fields(issue, before)
        if changes:
            diff["changed_issues"].append({"issue_id": issue.issue_id, "cluster_key": cluster_key, "changes": changes})
        else:
            diff["unchanged_issues"].append({"issue_id": issue.issue_id, "cluster_key": cluster_key})
    for cluster_key, issue in previous.items():
        if cluster_key not in current:
            diff["resolved_issues"].append(
                {
                    "issue_id": issue.get("issue_id"),
                    "cluster_key": cluster_key,
                    "title": issue.get("title"),
                    "severity_level": issue.get("severity", {}).get("level"),
                }
            )
    return diff


def render_run_diff_markdown(diff: dict[str, Any]) -> str:
    if not diff.get("available"):
        return "# Run Diff\n\n- No comparison baseline available.\n"
    lines = [f"# Run Diff vs {diff['compared_run_id']}", ""]
    for key, title in [
        ("new_issues", "New Issues"),
        ("resolved_issues", "Resolved Issues"),
        ("changed_issues", "Changed Issues"),
        ("unchanged_issues", "Unchanged Issues"),
    ]:
        lines.append(f"## {title}")
        rows = diff.get(key, [])
        if not rows:
            lines.append("- None")
        else:
            for row in rows:
                summary = row.get("title") or row.get("issue_id") or row.get("cluster_key")
                if key == "changed_issues":
                    summary = f"{row['issue_id']}: {', '.join(row['changes'])}"
                lines.append(f"- {summary}")
        lines.append("")
    return "\n".join(lines)


def _current_issue(issue: Any) -> dict[str, Any]:
    return {
        "issue_id": issue.issue_id,
        "cluster_key": issue.cluster_key,
        "title": issue.title,
        "severity_level": issue.severity.level,
        "confidence_level": issue.confidence.level,
    }


def _changed_fields(issue: Any, before: dict[str, Any]) -> list[str]:
    changes: list[str] = []
    if issue.title != before.get("title"):
        changes.append("title")
    if issue.severity.level != before.get("severity", {}).get("level"):
        changes.append("severity")
    if issue.confidence.level != before.get("confidence", {}).get("level"):
        changes.append("confidence")
    if len(issue.affected_assets) != len(before.get("affected_assets", [])):
        changes.append("affected_asset_count")
    if bool(issue.suppression_status) != bool(before.get("suppression_status")):
        changes.append("suppression_status")
    if bool(issue.analyst_note) != bool(before.get("analyst_note")):
        changes.append("override_state")
    return changes
