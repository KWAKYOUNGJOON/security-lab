from __future__ import annotations

from pathlib import Path
from typing import Any

from vuln_pipeline.models import ReportBundle
from vuln_pipeline.report.policy import load_yaml_policy


def build_release_readiness(
    bundle: ReportBundle,
    qa_metrics: dict[str, Any],
    review_queue: list[dict[str, Any]],
    review_closure_status: dict[str, Any],
    package_created: bool,
    comparison: dict[str, Any],
    customer_profile_applied: bool,
    policy_path: Path,
) -> dict[str, Any]:
    policy = load_yaml_policy(policy_path)
    issue_count = max(qa_metrics.get("issue_count", 0), 1)
    unmapped_ratio = qa_metrics.get("unmapped_cwe_count", 0) / issue_count
    confirmed_high_unresolved = any(
        row.get("review_disposition") == "confirmed"
        and not row.get("is_resolved")
        and row.get("severity_level") in {"Critical", "High"}
        for row in review_queue
    )
    checks = [
        _check(
            "high_severity_issue_exists",
            policy.get("allow_high_severity", False) or qa_metrics.get("high_severity_count", 0) == 0,
            "High severity issue exists. Prioritize confirmation and owner assignment.",
            policy.get("high_severity_result", "warn"),
        ),
        _check(
            "low_confidence_unresolved_exists",
            policy.get("allow_low_confidence_unresolved", False) or qa_metrics.get("low_confidence_count", 0) == 0,
            "Low confidence issues remain. Analyst confirmation is required.",
            "warn",
        ),
        _check(
            "unmapped_cwe_ratio_ok",
            unmapped_ratio <= float(policy.get("unmapped_ratio_threshold", 0.2)),
            "Unmapped CWE ratio is above threshold. Mapping quality should be improved.",
            "warn",
        ),
        _check(
            "review_queue_within_limit",
            review_closure_status.get("unresolved_review_items", len(review_queue)) <= int(policy.get("review_queue_allowed_count", 0)),
            "Review queue is above allowed threshold. Remaining review items should be triaged.",
            policy.get("review_queue_result", "warn"),
        ),
        _check(
            "override_provided",
            (not policy.get("override_required", True)) or bundle.override_summary.get("applied", 0) > 0,
            "No overrides provided. Manual validation may still be pending.",
            "warn",
        ),
        _check(
            "compare_baseline_available",
            (not policy.get("compare_baseline_required", False)) or comparison.get("available", False),
            "No comparison baseline available for change tracking.",
            policy.get("compare_baseline_result", "warn"),
        ),
        _check(
            "deferred_items_allowed",
            policy.get("allow_deferred", False) or review_closure_status.get("deferred_items", 0) == 0,
            "Deferred review items remain. Final delivery should be postponed or explicitly approved.",
            "warn",
        ),
        _check(
            "confirmed_high_unresolved",
            policy.get("allow_confirmed_high_untreated", False) or not confirmed_high_unresolved,
            "Confirmed High/Critical item has no closure action recorded.",
            "fail",
        ),
        _check(
            "package_created",
            (not policy.get("package_required", True)) or package_created,
            "Delivery package was not created.",
            "fail",
        ),
        _check(
            "customer_redaction_applied",
            (not policy.get("customer_redaction_required", True)) or customer_profile_applied,
            "Customer redaction profile was not applied.",
            "fail",
        ),
    ]
    failed = [item for item in checks if item["result"] == "fail"]
    warning = [item for item in checks if item["result"] == "warn"]
    status = "not_ready" if failed else "conditionally_ready" if warning else "ready"
    blocker_summary = [item["name"] for item in checks if item["result"] != "pass"]
    return {
        "status": status,
        "policy_name": policy.get("policy_name", policy_path.stem),
        "policy_path": str(policy_path),
        "checks": checks,
        "unresolved_review_items": review_closure_status.get("unresolved_review_items", 0),
        "accepted_risk_items": review_closure_status.get("accepted_risk_items", 0),
        "deferred_items": review_closure_status.get("deferred_items", 0),
        "confirmed_items": review_closure_status.get("confirmed_items", 0),
        "blocker_summary": blocker_summary,
        "summary": {
            "failed_count": len(failed),
            "warning_count": len(warning),
            "recommendation": _recommendation(status),
        },
    }


def _check(name: str, passed: bool, action: str, severity: str) -> dict[str, str]:
    return {
        "name": name,
        "result": "pass" if passed else severity,
        "recommended_action": "" if passed else action,
    }


def _recommendation(status: str) -> str:
    if status == "ready":
        return "Customer delivery can proceed."
    if status == "conditionally_ready":
        return "Delivery is possible after reviewing warning items."
    return "Delivery should be held until blocking items are resolved."
