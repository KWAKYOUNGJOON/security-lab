from __future__ import annotations

from pathlib import Path
from typing import Any


def build_submission_gate(
    *,
    readiness: dict[str, Any],
    review_closure_status: dict[str, Any],
    deliverable_info: dict[str, Any],
    customer_package_info: dict[str, Any] | None,
    final_delivery_manifest_path: Path,
    branding_meta: dict[str, Any],
    require_pptx: bool,
    privacy_audit: dict[str, Any] | None = None,
) -> dict[str, Any]:
    required_customer_files = _required_customer_files(deliverable_info)
    customer_files_present = [path for path in required_customer_files if Path(path).exists()]
    customer_files_missing = [path for path in required_customer_files if not Path(path).exists()]
    pptx_generated = bool(deliverable_info.get("pptx_generated"))
    pptx_waived = not require_pptx
    checks = [
        _check("readiness_status_ready", readiness.get("status") == "ready", "fail"),
        _check("unresolved_review_count_zero", review_closure_status.get("unresolved_review_items", 0) == 0, "fail"),
        _check("customer_package_created", bool(customer_package_info and Path(customer_package_info["zip_path"]).exists()), "fail"),
        _check("final_delivery_manifest_exists", final_delivery_manifest_path.exists(), "fail"),
        _check("customer_redaction_applied", bool(deliverable_info.get("customer_redaction_applied")), "fail"),
        _check("required_customer_files_present", not customer_files_missing, "fail"),
        _check("branding_metadata_applied", bool(branding_meta.get("branding_applied")), "warn"),
        _check("pptx_requirement_satisfied_or_waived", pptx_generated or pptx_waived, "fail" if require_pptx else "warn"),
        _check("customer_package_privacy_audit", (privacy_audit or {}).get("audit_result") != "fail", "fail"),
    ]
    failed = [item for item in checks if item["result"] == "fail"]
    warned = [item for item in checks if item["result"] == "warn"]
    status = "fail" if failed else "conditional_pass" if warned else "pass"
    return {
        "status": status,
        "checks": checks,
        "readiness_status": readiness.get("status"),
        "unresolved_review_count": review_closure_status.get("unresolved_review_items", 0),
        "customer_package_created": bool(customer_package_info and Path(customer_package_info["zip_path"]).exists()),
        "required_customer_files": required_customer_files,
        "required_customer_files_present": customer_files_present,
        "required_customer_files_missing": customer_files_missing,
        "customer_redaction_applied": bool(deliverable_info.get("customer_redaction_applied")),
        "branding_metadata_applied": bool(branding_meta.get("branding_applied")),
        "pptx_requirement": {
            "required": require_pptx,
            "pptx_generated": pptx_generated,
            "waived": pptx_waived,
        },
        "privacy_audit": privacy_audit or {"audit_result": "not_generated"},
        "blocking_reasons": [item["name"] for item in failed],
        "warning_reasons": [item["name"] for item in warned],
    }


def _required_customer_files(deliverable_info: dict[str, Any]) -> list[str]:
    files: list[str] = []
    for key in ["customer_full_report", "customer_onepager", "customer_tracker"]:
        for path in deliverable_info.get("customer_outputs", {}).get(key, []):
            files.append(path)
    for path in deliverable_info.get("customer_outputs", {}).get("customer_presentation", []):
        files.append(path)
    return files


def _check(name: str, passed: bool, failure_mode: str) -> dict[str, Any]:
    return {
        "name": name,
        "result": "pass" if passed else failure_mode,
    }
