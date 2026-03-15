from __future__ import annotations

import hashlib
import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from zipfile import ZipFile

import yaml

from vuln_pipeline.parsers.real_inputs import EXCLUDED_NAME_PARTS, MANUAL_SELECTION_RULES, REAL_INPUT_RULES
from vuln_pipeline.report.knowledge import load_deliverable_profile


FORBIDDEN_CUSTOMER_PATTERNS: dict[str, tuple[str, ...]] = {
    "review_queue": ("review_queue",),
    "override_template": ("override_template",),
    "analyst_handoff": ("analyst_handoff",),
    "decision_trace": ("decision", "trace"),
    "raw_artifacts": ("artifacts/raw", "raw_artifact"),
    "internal_only_appendix": ("internal-only", "internal_only", "appendix_internal"),
    "report_data_trace": ("report_data/", "mapping_decisions", "scoring_decisions", "cluster_decisions", "suppression_decisions"),
    "internal_archive": ("internal_archive",),
}
FORBIDDEN_CONTENT_KEYWORDS: dict[str, tuple[str, ...]] = {
    "review_queue": ("review_queue.jsonl", "report_data/review_queue"),
    "override_template": ("override_template.yaml",),
    "analyst_handoff": ("analyst_handoff_", "analyst_handoff."),
    "decision_trace": ("decision trace",),
    "raw_artifacts": ("artifacts/raw", "raw_artifact"),
    "internal_archive": ("internal_archive_",),
    "mapping_decisions": ("mapping_decisions.jsonl",),
    "scoring_decisions": ("scoring_decisions.jsonl",),
    "cluster_decisions": ("cluster_decisions.jsonl",),
    "suppression_decisions": ("suppression_decisions.jsonl",),
}


def load_customer_bundle(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {}
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return payload if isinstance(payload, dict) else {}


def build_input_preflight(
    *,
    explicit_inputs: dict[str, list[Path] | None],
    resolved_inputs: dict[str, list[Path]],
    roots: dict[str, Path | None],
    manual_inputs: dict[str, Path | None],
    manual_metadata: dict[str, dict[str, Any]] | None = None,
    auto_select_real_inputs: bool,
) -> dict[str, Any]:
    tool_results: dict[str, Any] = {}
    selected_paths: list[Path] = []
    warnings: list[str] = []
    blockers: list[str] = []
    fingerprints: dict[str, list[str]] = {}

    for tool, rule in REAL_INPUT_RULES.items():
        paths = list(resolved_inputs.get(tool, []))
        source = "resolved_inputs" if paths else "none"
        if explicit_inputs.get(tool):
            source = "explicit"
        elif auto_select_real_inputs and paths:
            source = "auto_selected"
        evaluations = [_evaluate_input_file(path, tool, rule) for path in paths]
        directory = roots.get(tool)
        eligible_files = 0
        if directory and directory.exists():
            for candidate in directory.iterdir():
                if candidate.is_file() and _is_tool_extension(candidate, rule):
                    eligible_files += 1
        for evaluation in evaluations:
            selected_paths.append(path := Path(evaluation["path"]))
            if evaluation["fingerprint"]:
                fingerprints.setdefault(evaluation["fingerprint"], []).append(str(path))
            warnings.extend(f"{tool}: {item}" for item in evaluation["warnings"])
            blockers.extend(f"{tool}: {item}" for item in evaluation["blockers"])
        tool_results[tool] = {
            "tool": tool,
            "selected_input_count": len(paths),
            "selection_source": source,
            "configured_directory": str(directory) if directory else None,
            "configured_directory_exists": bool(directory and directory.exists()),
            "eligible_file_count_in_directory": eligible_files,
            "selected_files": evaluations,
        }

    duplicate_groups = [paths for paths in fingerprints.values() if len(paths) > 1]
    if duplicate_groups:
        warnings.extend(f"duplicate_file_content: {', '.join(group)}" for group in duplicate_groups)
        duplicate_lookup = {path for group in duplicate_groups for path in group}
        for tool_result in tool_results.values():
            for file_info in tool_result["selected_files"]:
                file_info["duplicate_detected"] = file_info["path"] in duplicate_lookup

    manual_status: dict[str, Any] = {}
    for key in MANUAL_SELECTION_RULES:
        path = manual_inputs.get(key)
        metadata = (manual_metadata or {}).get(key, {})
        exists = bool(path and path.exists())
        manual_source = metadata.get("manual_source", "missing" if path is None else "unclassified")
        manual_status[key] = {
            "configured_path": metadata.get("configured_path", str(path) if path else None),
            "effective_path": metadata.get("effective_path", str(path) if path else None),
            "default_path": metadata.get("default_path"),
            "exists": exists,
            "status": "present" if exists else "missing",
            "manual_source": manual_source,
            "cli_explicit": metadata.get("cli_explicit", False),
            "support_selected_path": metadata.get("support_selected_path"),
            "support_source_priority": metadata.get("support_source_priority"),
        }
        if auto_select_real_inputs and manual_source != "real_explicit":
            blockers.append(f"{key}: manual source is `{manual_source}`; expected `real_explicit` during real rehearsal")
        elif not exists:
            warnings.append(f"{key}: manual input file not found")

    real_selected = [
        info
        for tool_result in tool_results.values()
        for info in tool_result["selected_files"]
        if info["real_candidate"]
    ]
    if not real_selected:
        blockers.append("real scan inputs are not ready")

    status = "blocked" if blockers else "warning" if warnings else "ready"
    return {
        "status": status,
        "auto_select_real_inputs": auto_select_real_inputs,
        "tool_checks": tool_results,
        "manual_inputs": manual_status,
        "manual_sources_ready": all(
            value.get("exists") and value.get("manual_source") == "real_explicit"
            for value in manual_status.values()
        ) if auto_select_real_inputs else all(value.get("exists") for value in manual_status.values()),
        "selected_run_inputs": [str(path) for path in selected_paths],
        "warning_count": len(warnings),
        "blocker_count": len(blockers),
        "warnings": warnings,
        "blockers": blockers,
        "duplicate_groups": duplicate_groups,
    }


def render_input_preflight_markdown(preflight: dict[str, Any]) -> str:
    lines = [
        "# Input Preflight",
        "",
        f"- status: `{preflight['status']}`",
        f"- auto_select_real_inputs: `{preflight['auto_select_real_inputs']}`",
        f"- selected_run_input_count: `{len(preflight.get('selected_run_inputs', []))}`",
        f"- warning_count: `{preflight.get('warning_count', 0)}`",
        f"- blocker_count: `{preflight.get('blocker_count', 0)}`",
        "",
        "## Tool Checks",
    ]
    for tool, result in preflight.get("tool_checks", {}).items():
        lines.append(f"### {tool}")
        lines.append(f"- selection_source: `{result['selection_source']}`")
        lines.append(f"- configured_directory: `{result['configured_directory']}`")
        lines.append(f"- eligible_file_count_in_directory: `{result['eligible_file_count_in_directory']}`")
        if result["selected_files"]:
            for file_info in result["selected_files"]:
                lines.append(
                    f"- `{file_info['path']}` | real_candidate={file_info['real_candidate']} "
                    f"| size={file_info['size_bytes']} | lines={file_info['line_count']} | modified={file_info['modified_at']}"
                )
                if file_info["warnings"]:
                    lines.append(f"  warnings: {', '.join(file_info['warnings'])}")
                if file_info["blockers"]:
                    lines.append(f"  blockers: {', '.join(file_info['blockers'])}")
        else:
            lines.append("- no selected file")
    lines.extend(["", "## Manual Inputs"])
    for key, value in preflight.get("manual_inputs", {}).items():
        lines.append(
            f"- {key}: `{value['status']}` | manual_source=`{value.get('manual_source', 'unclassified')}`"
            f" | effective_path=`{value.get('effective_path')}`"
        )
    if preflight.get("warnings"):
        lines.extend(["", "## Warnings"])
        lines.extend(f"- {item}" for item in preflight["warnings"])
    if preflight.get("blockers"):
        lines.extend(["", "## Blockers"])
        lines.extend(f"- {item}" for item in preflight["blockers"])
    return "\n".join(lines) + "\n"


def build_pptx_capability(
    *,
    expected_output_path: Path,
    fallback_path: Path,
    require_pptx: bool,
) -> dict[str, Any]:
    dependency_found = importlib.util.find_spec("pptx") is not None
    import_check = False
    import_error = ""
    if dependency_found:
        try:
            from pptx import Presentation  # type: ignore

            import_check = Presentation is not None
        except Exception as exc:  # pragma: no cover - import failure depends on local env
            import_error = str(exc)
    else:
        import_error = "python-pptx not installed"
    capability = {
        "dependency_found": dependency_found,
        "import_check": import_check,
        "import_error": import_error,
        "expected_output_path": str(expected_output_path),
        "fallback_path": str(fallback_path),
        "install_hint": "python -m pip install python-pptx",
        "require_pptx_would_block": require_pptx and not (dependency_found and import_check),
        "status": "ready" if dependency_found and import_check else "blocked" if require_pptx else "warning",
    }
    return capability


def render_pptx_capability_markdown(capability: dict[str, Any]) -> str:
    lines = [
        "# PPTX Capability",
        "",
        f"- status: `{capability['status']}`",
        f"- dependency_found: `{capability['dependency_found']}`",
        f"- import_check: `{capability['import_check']}`",
        f"- expected_output_path: `{capability['expected_output_path']}`",
        f"- fallback_path: `{capability['fallback_path']}`",
        f"- require_pptx_would_block: `{capability['require_pptx_would_block']}`",
        f"- install_hint: `{capability['install_hint']}`",
    ]
    if capability.get("import_error"):
        lines.append(f"- import_error: `{capability['import_error']}`")
    return "\n".join(lines) + "\n"


def build_customer_package_audit(
    *,
    run_root: Path,
    included_files: list[str],
    excluded_files: list[str],
    zip_path: Path | None = None,
) -> dict[str, Any]:
    audited_files = sorted(
        set(included_files)
        | {
            "delivery/customer_submission_manifest.json",
            "delivery/customer_submission_checksums.json",
        }
    )
    whitelist_prefixes = (
        "deliverables/full_report_customer",
        "deliverables/executive_onepager",
        "deliverables/remediation_tracker",
        "deliverables/presentation_briefing",
        "delivery/final_delivery_manifest.json",
        "delivery/customer_final_delivery_manifest.json",
        "delivery/customer_submission_manifest.json",
        "delivery/customer_submission_checksums.json",
    )
    forbidden_patterns_detected: list[dict[str, str]] = []
    non_whitelist_files: list[str] = []
    findings: list[dict[str, Any]] = []
    for rel_path in audited_files:
        normalized = rel_path.replace("\\", "/").lower()
        for label, patterns in FORBIDDEN_CUSTOMER_PATTERNS.items():
            if any(pattern in normalized for pattern in patterns):
                finding = {"kind": "path", "file": rel_path, "pattern": label, "severity": "fail"}
                forbidden_patterns_detected.append({"file": rel_path, "pattern": label})
                findings.append(finding)
        if not normalized.startswith(whitelist_prefixes):
            non_whitelist_files.append(rel_path)
            findings.append({"kind": "whitelist", "file": rel_path, "pattern": "non_whitelist_file", "severity": "fail"})

    zip_entries: list[str] = []
    if zip_path and zip_path.exists():
        with ZipFile(zip_path) as archive:
            zip_entries = sorted(archive.namelist())
        for entry in zip_entries:
            normalized = entry.replace("\\", "/").lower()
            for label, patterns in FORBIDDEN_CUSTOMER_PATTERNS.items():
                if any(pattern in normalized for pattern in patterns):
                    findings.append({"kind": "zip_entry", "file": entry, "pattern": label, "severity": "fail"})

    content_findings: list[dict[str, Any]] = []
    for rel_path in audited_files:
        source = run_root / rel_path
        if source.suffix.lower() not in {".md", ".json", ".txt"} or not source.exists():
            continue
        content = source.read_text(encoding="utf-8", errors="ignore").lower()
        for label, patterns in FORBIDDEN_CONTENT_KEYWORDS.items():
            if any(pattern in content for pattern in patterns):
                finding = {"kind": "content", "file": rel_path, "pattern": label, "severity": "fail"}
                content_findings.append(finding)
                findings.append(finding)

    audit_result = "fail" if findings or forbidden_patterns_detected or non_whitelist_files else "pass"
    return {
        "run_root": str(run_root),
        "included_files": audited_files,
        "excluded_files": excluded_files,
        "zip_entries": zip_entries,
        "forbidden_patterns_detected": forbidden_patterns_detected,
        "non_whitelist_files": non_whitelist_files,
        "content_findings": content_findings,
        "findings": findings,
        "audit_result": audit_result,
    }


def render_customer_package_audit_markdown(audit: dict[str, Any]) -> str:
    lines = [
        "# Customer Package Audit",
        "",
        f"- audit_result: `{audit['audit_result']}`",
        f"- included_file_count: `{len(audit.get('included_files', []))}`",
        f"- excluded_file_count: `{len(audit.get('excluded_files', []))}`",
        "",
        "## Included Files",
    ]
    lines.extend(f"- `{item}`" for item in audit.get("included_files", []))
    lines.extend(["", "## Excluded Files"])
    lines.extend(f"- `{item}`" for item in audit.get("excluded_files", []))
    lines.extend(["", "## Forbidden Patterns"])
    if audit.get("forbidden_patterns_detected"):
        lines.extend(f"- `{item['file']}` -> `{item['pattern']}`" for item in audit["forbidden_patterns_detected"])
    else:
        lines.append("- none")
    if audit.get("non_whitelist_files"):
        lines.extend(["", "## Non Whitelist Files"])
        lines.extend(f"- `{item}`" for item in audit["non_whitelist_files"])
    if audit.get("zip_entries"):
        lines.extend(["", "## ZIP Entries"])
        lines.extend(f"- `{item}`" for item in audit["zip_entries"])
    if audit.get("content_findings"):
        lines.extend(["", "## Content Findings"])
        lines.extend(f"- `{item['file']}` -> `{item['pattern']}`" for item in audit["content_findings"])
    return "\n".join(lines) + "\n"


def build_operations_runbook(
    *,
    run_root: Path,
    execution_options: dict[str, Any],
    preflight: dict[str, Any],
) -> str:
    lines = [
        "# Operations Runbook",
        "",
        f"- run_root: `{run_root}`",
        f"- run_id: `{execution_options.get('run_id', '')}`",
        "",
        "## Input Preparation",
        f"- Real Burp input directory: `{execution_options.get('real_burp_dir')}`",
        f"- Real Nuclei input directory: `{execution_options.get('real_nuclei_dir')}`",
        f"- Real httpx input directory: `{execution_options.get('real_httpx_dir')}`",
        f"- Real manual input directory: `{execution_options.get('real_manual_dir')}`",
        f"- Burp input directory: `{execution_options.get('burp_dir')}`",
        f"- Nuclei input directory: `{execution_options.get('nuclei_dir')}`",
        f"- httpx input directory: `{execution_options.get('httpx_dir')}`",
        f"- Manual input directory: `{execution_options.get('manual_dir')}`",
        "",
        "## Preflight Order",
        "1. Run the preflight check and confirm `report_data\\input_preflight.json` is `ready` or expected `warning`.",
        "2. Verify the selected input files are not sample or test fixtures.",
        "3. Confirm manual override, suppression, and review resolution files if they are expected for this release.",
        "",
        "## Review Flow",
        f"1. Apply override file: `{execution_options.get('override_file')}`",
        f"2. Apply suppression file: `{execution_options.get('suppression_file')}`",
        f"3. Apply review resolution file: `{execution_options.get('review_resolution_file')}`",
        "4. Confirm review queue is resolved before customer final packaging.",
        "",
        "## Customer Final",
        f"- report template: `{execution_options.get('report_template')}`",
        f"- deliverable profile: `{execution_options.get('deliverable_profile')}`",
        f"- branding file: `{execution_options.get('branding_file')}`",
        "1. Run package output with finalize-delivery when readiness is acceptable.",
        "2. Check submission gate, privacy audit, and final submission check before handing off the customer ZIP.",
        "",
        "## Internal Archive",
        "1. Use `--archive-only` when only the internal archive needs regeneration.",
        "2. Confirm `delivery\\internal_archive_<version>.zip` is refreshed and `report_data\\archive_only_manifest.json` is present.",
        "3. Confirm customer submission ZIP and customer package manifests were intentionally skipped.",
        "",
        "## Troubleshooting",
        f"- Current preflight status: `{preflight['status']}`",
        "- If preflight is blocked, replace sample, zero-byte, or unsupported files before rerunning.",
        "- If privacy audit fails, remove internal-only outputs from the customer package whitelist.",
        "- If PPTX capability is blocked, install `python-pptx` or proceed with fallback policy.",
    ]
    return "\n".join(lines) + "\n"


def build_release_runbook(
    *,
    run_root: Path,
    execution_options: dict[str, Any],
    final_delivery_manifest: dict[str, Any] | None,
    submission_gate: dict[str, Any] | None,
) -> str:
    lines = [
        "# Release Runbook",
        "",
        f"- run_root: `{run_root}`",
        f"- compare_to_run: `{execution_options.get('compare_to_run')}`",
        f"- readiness_policy: `{execution_options.get('readiness_policy')}`",
        "",
        "## Release Candidate",
        "1. Run with `--release-candidate` to generate the candidate manifest.",
        "2. Check `report_data\\release_candidate_manifest.json` for blocking reasons.",
        "",
        "## Finalize Delivery",
        "1. Run with `--finalize-delivery` after review closure and readiness checks.",
        "2. Verify `delivery\\final_delivery_manifest.json` was updated.",
        "",
        "## Submission Gate",
        f"- current status: `{submission_gate.get('status') if submission_gate else 'not_generated'}`",
        "1. Confirm readiness, unresolved review count, privacy audit, and PPTX requirement checks.",
        "2. Do not send the customer ZIP when submission gate is `fail`.",
        "",
        "## Customer Submission Handoff",
        f"- customer_submission_zip: `{(final_delivery_manifest or {}).get('customer_submission_zip', '')}`",
        "1. Send only the customer submission ZIP after gate and privacy audit pass.",
        "2. Keep final delivery manifest with the delivery record.",
        "",
        "## Internal Archive Retention",
        f"- internal_archive_zip: `{(final_delivery_manifest or {}).get('internal_archive_zip', '')}`",
        "1. Retain the internal archive ZIP with report data and comparison outputs.",
        "2. Use archive-only reruns for internal retention updates without rebuilding customer output.",
        "3. Record that customer submission artifacts were not regenerated during archive-only runs.",
    ]
    return "\n".join(lines) + "\n"


def build_real_data_onboarding_checklist(
    *,
    execution_options: dict[str, Any],
    preflight: dict[str, Any] | None,
    pptx_capability: dict[str, Any] | None,
) -> str:
    lines = [
        "# Real Data Onboarding Checklist",
        "",
        f"- real_burp_dir: `{execution_options.get('real_burp_dir', '')}`",
        f"- real_nuclei_dir: `{execution_options.get('real_nuclei_dir', '')}`",
        f"- real_httpx_dir: `{execution_options.get('real_httpx_dir', '')}`",
        f"- real_manual_dir: `{execution_options.get('real_manual_dir', '')}`",
        "",
        "## Naming Rules",
        "- Do not place sample, fixture, test, or realish files in the real intake directories.",
        "- Use stable customer or date-oriented filenames so the newest file is meaningful.",
        "",
        "## Preflight Conditions",
        f"- current_preflight_status: `{(preflight or {}).get('status', 'not_generated')}`",
        "- Confirm selected files are real, non-zero, supported, and not duplicate content.",
        "",
        "## Manual Inputs",
        f"- override_file: `{execution_options.get('override_file', '')}`",
        f"- suppression_file: `{execution_options.get('suppression_file', '')}`",
        f"- review_resolution_file: `{execution_options.get('review_resolution_file', '')}`",
        "",
        "## Release Flow",
        "- Run preflight first.",
        "- Run customer final after review, suppression, and override validation.",
        "- Use archive-only only when customer submission should remain untouched.",
        "",
        "## PPTX",
        f"- require_pptx: `{execution_options.get('require_pptx', False)}`",
        f"- current_pptx_capability: `{(pptx_capability or {}).get('status', 'not_generated')}`",
    ]
    return "\n".join(lines) + "\n"


def build_real_rehearsal_blocked(
    *,
    run_id: str,
    real_input_selection: dict[str, Any] | None,
    preflight: dict[str, Any] | None,
    reason: str,
) -> str:
    lines = [
        "# Real Rehearsal Blocked",
        "",
        f"- run_id: `{run_id}`",
        f"- reason: `{reason}`",
        f"- preflight_status: `{(preflight or {}).get('status', 'not_generated')}`",
        f"- selection_status: `{(real_input_selection or {}).get('status', 'not_generated')}`",
        "",
        "## Tool Summary",
    ]
    for tool, result in (real_input_selection or {}).get("tools", {}).items():
        lines.append(
            f"- {tool}: selected_path=`{result.get('selected_path')}` "
            f"reason=`{result.get('reason')}` source=`{result.get('source_priority', 'n/a')}`"
        )
    manual_inputs = (preflight or {}).get("manual_inputs", {})
    if manual_inputs:
        lines.extend(["", "## Manual Input Sources"])
        lines.extend(
            f"- {key}: manual_source=`{value.get('manual_source', 'unclassified')}` effective_path=`{value.get('effective_path')}`"
            for key, value in manual_inputs.items()
        )
    if (preflight or {}).get("blockers"):
        lines.extend(["", "## Blockers"])
        lines.extend(f"- {item}" for item in preflight["blockers"])
    lines.extend(["", "## Next Action", "- Place actual Burp, nuclei, and httpx files in `data\\inputs\\real\\*` and rerun the rehearsal."])
    return "\n".join(lines) + "\n"


def build_real_rehearsal_result(
    *,
    run_id: str,
    preflight: dict[str, Any] | None,
    readiness: dict[str, Any] | None,
    submission_gate: dict[str, Any] | None,
    privacy_audit: dict[str, Any] | None,
    pptx_capability: dict[str, Any] | None,
    final_delivery_manifest: dict[str, Any] | None,
) -> str:
    lines = [
        "# Real Rehearsal Result",
        "",
        f"- run_id: `{run_id}`",
        f"- readiness_status: `{(readiness or {}).get('status', 'not_generated')}`",
        f"- submission_gate_status: `{(submission_gate or {}).get('status', 'not_generated')}`",
        f"- privacy_audit_status: `{(privacy_audit or {}).get('audit_result', 'not_generated')}`",
        f"- pptx_capability_status: `{(pptx_capability or {}).get('status', 'not_generated')}`",
        f"- final_delivery_ready: `{(final_delivery_manifest or {}).get('final_ready', False)}`",
        f"- manual_sources_ready: `{(preflight or {}).get('manual_sources_ready', False)}`",
        f"- customer_submission_zip: `{(final_delivery_manifest or {}).get('customer_submission_zip', '')}`",
        f"- internal_archive_zip: `{(final_delivery_manifest or {}).get('internal_archive_zip', '')}`",
    ]
    manual_inputs = (preflight or {}).get("manual_inputs", {})
    if manual_inputs:
        lines.extend(["", "## Manual Input Sources"])
        lines.extend(
            f"- {key}: manual_source=`{value.get('manual_source', 'unclassified')}` effective_path=`{value.get('effective_path')}`"
            for key, value in manual_inputs.items()
        )
    return "\n".join(lines) + "\n"


def build_git_change_manifest(status_lines: list[str]) -> dict[str, Any]:
    tracked_modified: list[str] = []
    new_files: list[str] = []
    deleted_files: list[str] = []
    files_to_ignore: list[str] = []

    for line in status_lines:
        if not line.strip():
            continue
        code = line[:2]
        path = line[3:].strip()
        normalized = path.replace("\\", "/")
        if normalized.startswith(".tmp_run") or normalized.startswith("outputs/runs/"):
            files_to_ignore.append(path)
            continue
        if code == "??":
            new_files.append(path)
        elif "D" in code:
            deleted_files.append(path)
        else:
            tracked_modified.append(path)

    files_to_commit = sorted(set(tracked_modified + new_files + deleted_files))
    suggested_commit_grouping = [
        {"name": "core pipeline", "files": [path for path in files_to_commit if path.startswith("src/")]},
        {"name": "configs and scripts", "files": [path for path in files_to_commit if path.startswith("configs/") or path.startswith("scripts/")]},
        {"name": "tests", "files": [path for path in files_to_commit if path.startswith("tests/")]},
        {"name": "docs", "files": [path for path in files_to_commit if path == "README.md"]},
    ]
    return {
        "tracked_modified_files": tracked_modified,
        "new_files": new_files,
        "deleted_files": deleted_files,
        "files_to_commit": files_to_commit,
        "files_to_ignore": sorted(set(files_to_ignore)),
        "generated_outputs_excluded": True,
        "suggested_commit_grouping": suggested_commit_grouping,
    }


def render_commit_prep_summary(manifest: dict[str, Any]) -> str:
    lines = [
        "# Commit Prep Summary",
        "",
        f"- tracked_modified_count: `{len(manifest.get('tracked_modified_files', []))}`",
        f"- new_file_count: `{len(manifest.get('new_files', []))}`",
        f"- deleted_file_count: `{len(manifest.get('deleted_files', []))}`",
        f"- files_to_commit_count: `{len(manifest.get('files_to_commit', []))}`",
        f"- files_to_ignore_count: `{len(manifest.get('files_to_ignore', []))}`",
        "",
        "## Files To Commit",
    ]
    lines.extend(f"- `{item}`" for item in manifest.get("files_to_commit", []))
    lines.extend(["", "## Files To Ignore"])
    lines.extend(f"- `{item}`" for item in manifest.get("files_to_ignore", []))
    lines.extend(["", "## Suggested Commit Grouping"])
    for group in manifest.get("suggested_commit_grouping", []):
        lines.append(f"- {group['name']}: {len(group.get('files', []))} files")
    return "\n".join(lines) + "\n"


def build_release_readiness_summary(
    *,
    baseline_run_id: str,
    rehearsal_performed: bool,
    preflight: dict[str, Any] | None,
    readiness: dict[str, Any] | None,
    submission_gate: dict[str, Any] | None,
    privacy_audit: dict[str, Any] | None,
    pptx_capability: dict[str, Any] | None,
    final_delivery_manifest: dict[str, Any] | None,
    blockers: list[str] | None = None,
) -> str:
    lines = [
        "# Release Readiness Summary",
        "",
        f"- baseline_run_id: `{baseline_run_id}`",
        f"- real_rehearsal_performed: `{rehearsal_performed}`",
        f"- readiness_status: `{(readiness or {}).get('status', 'not_generated')}`",
        f"- submission_gate_status: `{(submission_gate or {}).get('status', 'not_generated')}`",
        f"- privacy_audit_status: `{(privacy_audit or {}).get('audit_result', 'not_generated')}`",
        f"- pptx_capability_status: `{(pptx_capability or {}).get('status', 'not_generated')}`",
        f"- final_delivery_ready: `{(final_delivery_manifest or {}).get('final_ready', False)}`",
        f"- manual_sources_ready: `{(preflight or {}).get('manual_sources_ready', False)}`",
        "",
        "## Next Recommended Action",
    ]
    if rehearsal_performed:
        lines.append("- Review the final delivery manifest and proceed with customer handoff if there are no remaining blockers.")
    else:
        lines.append("- Add real inputs under `data\\inputs\\real\\*` and rerun the rehearsal.")
    if blockers:
        lines.extend(["", "## Remaining Blockers or Warnings"])
        lines.extend(f"- {item}" for item in blockers)
    manual_inputs = (preflight or {}).get("manual_inputs", {})
    if manual_inputs:
        lines.extend(["", "## Manual Input Sources"])
        lines.extend(
            f"- {key}: manual_source=`{value.get('manual_source', 'unclassified')}` effective_path=`{value.get('effective_path')}`"
            for key, value in manual_inputs.items()
        )
    return "\n".join(lines) + "\n"


def build_final_submission_check(
    *,
    preflight: dict[str, Any] | None,
    readiness: dict[str, Any] | None,
    submission_gate: dict[str, Any] | None,
    privacy_audit: dict[str, Any] | None,
    pptx_capability: dict[str, Any] | None,
    final_delivery_manifest: dict[str, Any] | None,
) -> str:
    customer_zip = (final_delivery_manifest or {}).get("customer_submission_zip", "")
    internal_zip = (final_delivery_manifest or {}).get("internal_archive_zip", "")
    blocker_lines: list[str] = []
    if preflight and preflight.get("blockers"):
        blocker_lines.extend(preflight["blockers"])
    if readiness and readiness.get("blocker_summary"):
        blocker_lines.extend(readiness["blocker_summary"])
    if submission_gate and submission_gate.get("blocking_reasons"):
        blocker_lines.extend(submission_gate["blocking_reasons"])
    if privacy_audit and privacy_audit.get("forbidden_patterns_detected"):
        blocker_lines.extend(item["pattern"] for item in privacy_audit["forbidden_patterns_detected"])

    def state(label: str, value: str, status: str) -> str:
        return f"- [{status}] {label}: {value}"

    lines = [
        "# Final Submission Check",
        "",
        state("Preflight", str((preflight or {}).get("status", "not_generated")), _map_state((preflight or {}).get("status"))),
        state("Readiness", str((readiness or {}).get("status", "not_generated")), _map_state((readiness or {}).get("status"))),
        state("Submission gate", str((submission_gate or {}).get("status", "not_generated")), _map_state((submission_gate or {}).get("status"))),
        state("Privacy audit", str((privacy_audit or {}).get("audit_result", "not_generated")), _map_state((privacy_audit or {}).get("audit_result"))),
        state("PPTX capability", str((pptx_capability or {}).get("status", "not_generated")), _map_state((pptx_capability or {}).get("status"))),
        state("Final delivery manifest", "present" if final_delivery_manifest else "missing", "DONE" if final_delivery_manifest else "BLOCKED"),
        state("Customer ZIP", customer_zip or "not generated", "DONE" if customer_zip else "PENDING"),
        state("Internal archive ZIP", internal_zip or "not generated", "DONE" if internal_zip else "PENDING"),
    ]
    if blocker_lines:
        lines.extend(["", "## Remaining Blockers or Warnings"])
        lines.extend(f"- {item}" for item in blocker_lines)
    return "\n".join(lines) + "\n"


def expected_presentation_paths(
    *,
    deliverables_root: Path,
    deliverable_profile_dir: Path,
    deliverable_profile_name: str,
    report_version: str,
) -> tuple[Path, Path]:
    profile = load_deliverable_profile(deliverable_profile_dir, deliverable_profile_name)
    suffix = f"_{profile['id']}_{report_version}" if profile.get("versioned_filenames") else ""
    return (
        deliverables_root / f"presentation_briefing{suffix}.pptx",
        deliverables_root / f"presentation_briefing{suffix}_fallback.json",
    )


def build_archive_only_manifest(
    *,
    run_id: str,
    archive_zip_path: str,
    execution_options: dict[str, Any] | None,
    regenerated_files: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "archive_only": True,
        "archive_zip_path": archive_zip_path,
        "source_run_id": (execution_options or {}).get("compare_to_run") or run_id,
        "reused_artifacts": ["reports", "deliverables", "report_data", "comparison"],
        "regenerated_files": regenerated_files or [
            "delivery/internal_archive_manifest.json",
            "delivery/internal_archive_checksums.json",
            "delivery/internal_archive_<version>.zip",
        ],
        "skipped_customer_outputs": [
            "delivery/customer_submission_<version>.zip",
            "delivery/customer_submission_manifest.json",
            "delivery/customer_submission_checksums.json",
        ],
        "recorded_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "execution_options": execution_options or {},
    }


def _evaluate_input_file(path: Path, tool: str, rule: dict[str, Any]) -> dict[str, Any]:
    warnings: list[str] = []
    blockers: list[str] = []
    exists = path.exists()
    size = path.stat().st_size if exists else 0
    modified_at = _format_mtime(path) if exists else ""
    line_count = _safe_line_count(path) if exists else 0
    lower_name = path.name.lower()
    extension_valid = path.suffix.lower() in rule["extensions"]
    sample_like = any(part in lower_name for part in EXCLUDED_NAME_PARTS)
    if not exists:
        blockers.append("file_missing")
    if exists and not extension_valid:
        blockers.append("invalid_extension")
    if exists and size == 0:
        blockers.append("zero_size")
    if exists and sample_like:
        blockers.append("sample_or_test_file")
    if exists and size < rule["minimum_size"]:
        warnings.append("smaller_than_recommended")
    if exists and path.suffix.lower() in {".json", ".jsonl"} and line_count and line_count < 2:
        warnings.append("abnormally_low_line_count")
    return {
        "path": str(path),
        "tool": tool,
        "exists": exists,
        "extension_valid": extension_valid,
        "sample_or_test": sample_like,
        "size_bytes": size,
        "modified_at": modified_at,
        "line_count": line_count,
        "warnings": warnings,
        "blockers": blockers,
        "real_candidate": exists and extension_valid and not sample_like and size > 0,
        "fingerprint": _file_fingerprint(path) if exists and size > 0 else "",
        "duplicate_detected": False,
    }


def _safe_line_count(path: Path) -> int:
    try:
        return sum(1 for _ in path.open("r", encoding="utf-8", errors="ignore"))
    except Exception:
        return 0


def _file_fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _format_mtime(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).replace(microsecond=0).isoformat()


def _is_tool_extension(path: Path, rule: dict[str, Any]) -> bool:
    return path.suffix.lower() in rule["extensions"]


def _map_state(value: str | None) -> str:
    if value in {"ready", "pass"}:
        return "DONE"
    if value in {"warning", "conditionally_ready", "conditional_pass"}:
        return "PENDING"
    if value in {"blocked", "fail", "not_ready"}:
        return "BLOCKED"
    return "PENDING"
