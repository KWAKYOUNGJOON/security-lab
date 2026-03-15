from __future__ import annotations

from typing import Any

from vuln_pipeline.models import ReportBundle


def build_qa_metrics(
    bundle: ReportBundle,
    ingest_manifest: dict[str, Any],
    mapping_rows: list[dict[str, Any]],
    review_queue: list[dict[str, Any]],
    package_output: bool,
    comparison: dict[str, Any],
) -> dict[str, Any]:
    warnings = list(ingest_manifest.get("warnings", []))
    metrics = {
        "input_file_count": sum(len(values) for values in ingest_manifest.get("ingested", {}).values()),
        "parsed_finding_count": bundle.summary.get("parsed_findings", 0),
        "normalized_finding_count": bundle.summary.get("deduped_findings", 0),
        "issue_count": bundle.summary.get("issues", 0),
        "suppressed_count": len(bundle.suppressed_issues),
        "false_positive_count": len(bundle.false_positive_issues),
        "overridden_count": bundle.override_summary.get("applied", 0),
        "unmapped_cwe_count": sum(1 for issue in bundle.issues if not issue.primary_cwe),
        "low_confidence_count": sum(1 for issue in bundle.issues if issue.confidence.level == "Low"),
        "high_severity_count": sum(1 for issue in bundle.issues if issue.severity.level in {"Critical", "High"}),
        "evidence_missing_count": sum(1 for issue in bundle.issues if not issue.evidence_summary),
        "review_queue_count": sum(1 for row in review_queue if not row.get("is_resolved")),
        "packaging_success": package_output,
        "qa_warnings": warnings,
    }
    if metrics["issue_count"] and metrics["unmapped_cwe_count"] / metrics["issue_count"] > 0.3:
        warnings.append("unmapped ratio too high")
    if metrics["low_confidence_count"]:
        warnings.append("low confidence findings require review")
    if not bundle.override_summary.get("applied"):
        warnings.append("no overrides provided")
    if not comparison.get("available"):
        warnings.append("no comparison baseline available")
    if any(row.get("rejected_rules") for row in mapping_rows):
        warnings.append("rule conflicts observed during mapping")
    metrics["qa_warnings"] = sorted(set(warnings))
    return metrics
