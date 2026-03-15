from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

import yaml

from vuln_pipeline.cli.main import _workspace_root
from vuln_pipeline.parsers.real_inputs import MANUAL_SELECTION_RULES, _evaluate_manual_candidate
from vuln_pipeline.storage import write_csv, write_json, write_markdown


DEFAULT_BASELINE_RUN_ID = "phase9-final-demo-v9"
REVIEW_QUEUE_CANDIDATES = ("review_queue.jsonl", "review_queue.json", "review_queue.csv")
MANUAL_FILE_SPECS: dict[str, dict[str, Any]] = {
    "override_file": {
        "expected_key": "overrides",
        "id_fields": ("issue_id", "finding_id"),
        "working_file": "override_working.yaml",
    },
    "suppression_file": {
        "expected_key": "suppressions",
        "id_fields": ("id", "cluster_key", "host", "path_pattern", "weakness_family", "primary_cwe", "title_regex"),
        "match_fields": ("cluster_key", "host", "path_pattern", "weakness_family", "primary_cwe", "title_regex"),
        "working_file": "suppression_working.yaml",
    },
    "review_resolution_file": {
        "expected_key": "review_resolutions",
        "id_fields": ("issue_id",),
        "working_file": "review_resolution_working.yaml",
    },
}
OVERRIDE_REVIEW_REASONS = {"primary_cwe_missing", "rule_conflict_detected", "override_not_applied"}
REVIEW_RESOLUTION_REASONS = {
    "high_severity_requires_review",
    "low_confidence",
    "evidence_missing",
    "customer_release_review",
}
RESOLVED_REVIEW_STATUSES = {"resolved", "closed", "done", "approved"}
NON_CLOSING_DISPOSITIONS = {"", "deferred", "needs_more_evidence"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Summarize phase12 first-run outcomes, generate a rerun worklist, and validate manual inputs."
    )
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--baseline-run-root", type=Path)
    parser.add_argument("--manual-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--md-out", type=Path)
    parser.add_argument("--csv-out", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    run_root = Path(args.run_root).resolve()
    output_paths = resolve_output_paths(
        run_root=run_root,
        output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
        json_out=Path(args.json_out).resolve() if args.json_out else None,
        md_out=Path(args.md_out).resolve() if args.md_out else None,
        csv_out=Path(args.csv_out).resolve() if args.csv_out else None,
    )
    triage_report, manual_validation = build_post_run_triage(
        run_root=run_root,
        baseline_run_root=Path(args.baseline_run_root).resolve() if args.baseline_run_root else None,
        manual_dir=Path(args.manual_dir).resolve() if args.manual_dir else None,
    )
    triage_report["output_paths"] = {key: str(path) for key, path in output_paths.items()}
    triage_report["manual_validation"] = {
        "status": manual_validation["status"],
        "format_valid_for_rerun": manual_validation["rerun_live_context"]["format_valid"],
        "content_assessment_for_rerun": manual_validation["rerun_live_context"]["content_assessment"],
        "json_path": str(output_paths["manual_validation_json"]),
        "md_path": str(output_paths["manual_validation_md"]),
    }

    write_json(output_paths["triage_json"], triage_report)
    write_markdown(output_paths["triage_md"], render_post_run_triage_markdown(triage_report))
    write_csv(output_paths["triage_csv"], triage_report["worklist"]["rows"], worklist_fieldnames())
    write_json(output_paths["manual_validation_json"], manual_validation)
    write_markdown(output_paths["manual_validation_md"], render_manual_validation_markdown(manual_validation))

    print(f"post_run_triage_json: {output_paths['triage_json']}")
    print(f"post_run_triage_md: {output_paths['triage_md']}")
    print(f"post_run_triage_csv: {output_paths['triage_csv']}")
    print(f"manual_validation_json: {output_paths['manual_validation_json']}")
    print(f"manual_validation_md: {output_paths['manual_validation_md']}")
    review_queue_path = triage_report.get("artifacts", {}).get("review_queue", {}).get("path")
    if review_queue_path:
        print(f"review_queue: {review_queue_path}")
    return 1 if should_exit_non_zero(triage_report, manual_validation) else 0


def resolve_output_paths(
    *,
    run_root: Path,
    output_dir: Path | None,
    json_out: Path | None,
    md_out: Path | None,
    csv_out: Path | None,
) -> dict[str, Path]:
    base_dir = (
        output_dir
        or (json_out.parent if json_out else None)
        or (md_out.parent if md_out else None)
        or (csv_out.parent if csv_out else None)
        or (run_root / "report_data")
    )
    return {
        "triage_json": json_out or (base_dir / "post_run_triage.json"),
        "triage_md": md_out or (base_dir / "post_run_triage.md"),
        "triage_csv": csv_out or (base_dir / "post_run_triage_worklist.csv"),
        "manual_validation_json": base_dir / "manual_validation.json",
        "manual_validation_md": base_dir / "manual_validation.md",
    }


def build_post_run_triage(
    *,
    run_root: Path,
    baseline_run_root: Path | None = None,
    manual_dir: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    workspace_root = infer_workspace_root(run_root)
    current_artifacts = load_run_artifacts(run_root)
    baseline_root = resolve_baseline_run_root(run_root=run_root, workspace_root=workspace_root, baseline_run_root=baseline_run_root)
    baseline_snapshot = build_run_snapshot(baseline_root) if baseline_root else None
    current_snapshot = build_run_snapshot(run_root, artifacts=current_artifacts)
    review_queue_rows = current_artifacts["review_queue"]["rows"]
    worklist_rows = build_triage_worklist(review_queue_rows)
    manual_validation = build_manual_validation_report(
        run_root=run_root,
        workspace_root=workspace_root,
        manual_dir=manual_dir,
        review_queue_rows=review_queue_rows,
        artifacts=current_artifacts,
    )

    blockers = collect_blockers(current_artifacts)
    gate_failures = collect_gate_failures(current_artifacts)
    missing_artifacts = [name for name, item in current_artifacts.items() if item["required"] and not item["exists"]]
    rollup_status = determine_rollup_status(current_snapshot)
    triage_hints = build_triage_hints(current_snapshot, worklist_rows, manual_validation)
    report = {
        "run_root": str(run_root),
        "workspace_root": str(workspace_root),
        "baseline_run_root": str(baseline_root) if baseline_root else None,
        "default_baseline_run_id": DEFAULT_BASELINE_RUN_ID,
        "rollup_status": rollup_status,
        "state_flags": {
            "blocked": current_snapshot["blocked"],
            "fail": current_snapshot["fail"],
            "pass": current_snapshot["pass"],
            "ready": current_snapshot["ready"],
            "final_ready": current_snapshot["final_ready"],
        },
        "hard_facts": {
            "release_readiness_status": current_snapshot["release_readiness_status"],
            "submission_gate_status": current_snapshot["submission_gate_status"],
            "input_preflight_status": current_snapshot["input_preflight_status"],
            "real_input_readiness_status": current_snapshot["real_input_readiness_status"],
            "final_ready": current_snapshot["final_ready"],
            "unresolved_review_items": current_snapshot["unresolved_review_items"],
            "missing_artifacts": missing_artifacts,
            "blockers": blockers,
            "gate_failures": gate_failures,
        },
        "triage_hints": triage_hints,
        "artifacts": current_artifacts,
        "worklist": {
            "unresolved_count": len(worklist_rows),
            "bucket_counts": summarize_worklist_buckets(worklist_rows),
            "rows": worklist_rows,
            "hint_policy": "Suggested action buckets are operator hints derived from review queue facts. They do not approve, suppress, or resolve anything automatically.",
        },
        "baseline_comparison": build_baseline_comparison(current_snapshot=current_snapshot, baseline_snapshot=baseline_snapshot),
    }
    return report, manual_validation


def worklist_fieldnames() -> list[str]:
    return [
        "work_item_id",
        "issue_id",
        "finding_ids",
        "title",
        "summary",
        "severity_level",
        "priority_band",
        "priority_score",
        "current_status",
        "resolution_status",
        "review_disposition",
        "suggested_action_bucket",
        "suggested_working_file",
        "bucket_reason",
        "review_reason",
        "recommended_action",
        "reason_or_note",
    ]


def load_review_queue_rows(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        rows: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            payload = json.loads(line)
            if isinstance(payload, dict):
                rows.append(payload)
        return rows
    if suffix == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            return [row for row in payload if isinstance(row, dict)]
        if isinstance(payload, dict):
            for key in ("rows", "review_queue", "items"):
                if isinstance(payload.get(key), list):
                    return [row for row in payload[key] if isinstance(row, dict)]
        return []
    if suffix == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            rows = []
            for row in reader:
                normalized: dict[str, Any] = {}
                for key, value in row.items():
                    normalized[key] = parse_scalar_or_list(value)
                rows.append(normalized)
            return rows
    return []


def build_triage_worklist(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unresolved_rows = [row for row in rows if not bool(row.get("is_resolved"))]
    worklist: list[dict[str, Any]] = []
    for row in unresolved_rows:
        bucket = classify_worklist_bucket(row)
        finding_ids = [str(item) for item in coerce_list(row.get("finding_ids"))]
        review_reason = [str(item) for item in coerce_list(row.get("review_reason"))]
        work_item_id = (
            row.get("issue_id")
            or row.get("cluster_id")
            or row.get("cluster_key")
            or row.get("finding_id")
            or (finding_ids[0] if finding_ids else "unknown")
        )
        summary_parts = [item for item in [row.get("weakness_family"), row.get("host"), row.get("path_pattern")] if item]
        worklist.append(
            {
                "work_item_id": work_item_id,
                "issue_id": row.get("issue_id"),
                "finding_ids": "; ".join(finding_ids),
                "title": row.get("title"),
                "summary": " | ".join(str(item) for item in summary_parts),
                "severity_level": row.get("severity_level"),
                "priority_band": row.get("priority_band"),
                "priority_score": safe_int(row.get("priority_score")),
                "current_status": row.get("current_status"),
                "resolution_status": row.get("resolution_status"),
                "review_disposition": row.get("review_disposition"),
                "suggested_action_bucket": bucket["bucket"],
                "suggested_working_file": bucket["working_file"],
                "bucket_reason": bucket["reason"],
                "review_reason": "; ".join(review_reason),
                "recommended_action": row.get("recommended_action"),
                "reason_or_note": row.get("review_note") or row.get("recommended_action") or bucket["reason"],
            }
        )
    return sorted(worklist, key=lambda row: (-safe_int(row.get("priority_score")), str(row.get("work_item_id"))))


def classify_worklist_bucket(row: dict[str, Any]) -> dict[str, str]:
    review_reason = {str(item) for item in coerce_list(row.get("review_reason"))}
    disposition = str(row.get("review_disposition") or "").lower()
    current_status = str(row.get("current_status") or "").lower()
    resolution_status = str(row.get("resolution_status") or "").lower()

    if disposition == "accepted_risk" or current_status in {"accepted_risk", "suppressed"} or row.get("linked_suppression"):
        return {
            "bucket": "candidate_for_suppression_review",
            "working_file": bucket_to_working_file("candidate_for_suppression_review"),
            "reason": "Current row already carries accepted-risk or suppression-linked signals.",
        }
    if review_reason & OVERRIDE_REVIEW_REASONS:
        reasons = ", ".join(sorted(review_reason & OVERRIDE_REVIEW_REASONS))
        return {
            "bucket": "needs_override_review",
            "working_file": bucket_to_working_file("needs_override_review"),
            "reason": f"review_reason indicates override-oriented triage: {reasons}.",
        }
    if resolution_status or disposition or (review_reason & REVIEW_RESOLUTION_REASONS):
        reasons = ", ".join(sorted(review_reason & REVIEW_RESOLUTION_REASONS)) or "existing review resolution fields are present"
        return {
            "bucket": "needs_review_resolution",
            "working_file": bucket_to_working_file("needs_review_resolution"),
            "reason": f"Review closure signals remain open: {reasons}.",
        }
    return {
        "bucket": "manual_investigation",
        "working_file": bucket_to_working_file("manual_investigation"),
        "reason": "No single manual bucket is strongly indicated by the available review queue fields.",
    }


def bucket_to_working_file(bucket: str) -> str:
    mapping = {
        "needs_override_review": "override_working.yaml",
        "needs_review_resolution": "review_resolution_working.yaml",
        "candidate_for_suppression_review": "suppression_working.yaml",
        "manual_investigation": "review_resolution_working.yaml",
    }
    return mapping.get(bucket, "review_resolution_working.yaml")


def build_manual_validation_report(
    *,
    run_root: Path,
    workspace_root: Path,
    manual_dir: Path | None,
    review_queue_rows: list[dict[str, Any]],
    artifacts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    review_index = build_review_index(review_queue_rows)
    execution_context = validate_manual_context(
        name="execution_context",
        description="Files actually referenced by the current run or preflight artifacts.",
        paths=resolve_execution_manual_paths(artifacts),
        review_index=review_index,
        required=False,
        selection_meta=None,
    )
    live_manual_dir = manual_dir or (workspace_root / "data" / "inputs" / "real" / "manual")
    rerun_selection = describe_live_manual_selection(live_manual_dir)
    rerun_context = validate_manual_context(
        name="rerun_live_context",
        description="Latest eligible files under the live real/manual directory that would be used on the next real rehearsal rerun.",
        paths={key: (Path(item["selected_path"]) if item.get("selected_path") else None) for key, item in rerun_selection.items()},
        review_index=review_index,
        required=True,
        selection_meta=rerun_selection,
    )
    status = "invalid" if not rerun_context["format_valid"] else "valid"
    if rerun_context["content_assessment"] == "has_obvious_issues":
        status = "invalid"
    return {
        "status": status,
        "run_root": str(run_root),
        "manual_dir": str(live_manual_dir),
        "review_queue_reference_count": len(review_queue_rows),
        "note": "Format validity and content assessment are reported separately. Empty actionable lists stay format-valid but still need operator judgment.",
        "execution_context": execution_context,
        "rerun_live_context": rerun_context,
    }


def validate_manual_context(
    *,
    name: str,
    description: str,
    paths: dict[str, Path | None],
    review_index: dict[str, Any],
    required: bool,
    selection_meta: dict[str, dict[str, Any]] | None,
) -> dict[str, Any]:
    files: dict[str, dict[str, Any]] = {}
    parsed_entries: dict[str, list[dict[str, Any]]] = {}
    for key in MANUAL_FILE_SPECS:
        report, entries = validate_manual_file(
            key=key,
            path=paths.get(key),
            review_index=review_index,
            required=required,
            selection_meta=(selection_meta or {}).get(key),
        )
        files[key] = report
        parsed_entries[key] = entries

    override_refs = collect_override_refs(parsed_entries["override_file"])
    suppression_refs = collect_suppression_refs(parsed_entries["suppression_file"])
    cross_check_review_resolution(files["review_resolution_file"], parsed_entries["review_resolution_file"], override_refs, suppression_refs)

    format_valid = all(item["format_valid"] for item in files.values())
    content_assessment = summarize_content_assessment(files.values())
    return {
        "name": name,
        "description": description,
        "required": required,
        "format_valid": format_valid,
        "content_assessment": content_assessment,
        "files": files,
    }


def validate_manual_file(
    *,
    key: str,
    path: Path | None,
    review_index: dict[str, Any],
    required: bool,
    selection_meta: dict[str, Any] | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    spec = MANUAL_FILE_SPECS[key]
    report: dict[str, Any] = {
        "path": str(path) if path else None,
        "exists": bool(path and path.exists()),
        "format_valid": False,
        "format_status": "missing" if required else "unavailable",
        "content_assessment": "human_review_required",
        "expected_key": spec["expected_key"],
        "top_level_kind": None,
        "actionable_count": 0,
        "draft_candidate_count": 0,
        "issues": [],
        "warnings": [],
        "selection": selection_meta or {},
    }
    if path is None:
        if required:
            report["issues"].append("Expected a live manual file but no eligible candidate was selected.")
        return report, []
    if not path.exists():
        report["issues"].append(f"File does not exist: {path}")
        return report, []

    try:
        payload = load_structured_payload(path)
    except Exception as exc:
        report["issues"].append(f"Parse error: {exc}")
        report["format_status"] = "invalid"
        return report, []

    report["top_level_kind"] = type_name(payload)
    entries: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        report["draft_candidate_count"] = len(payload.get("draft_candidates", [])) if isinstance(payload.get("draft_candidates"), list) else 0
        if spec["expected_key"] not in payload:
            report["issues"].append(f"Top-level key `{spec['expected_key']}` is missing.")
            report["format_status"] = "invalid"
            return report, []
        if not isinstance(payload.get(spec["expected_key"]), list):
            report["issues"].append(f"Top-level key `{spec['expected_key']}` must be a list.")
            report["format_status"] = "invalid"
            return report, []
        entries = [row for row in payload.get(spec["expected_key"], []) if isinstance(row, dict)]
        if len(entries) != len(payload.get(spec["expected_key"], [])):
            report["issues"].append(f"`{spec['expected_key']}` contains non-object rows.")
    elif isinstance(payload, list):
        entries = [row for row in payload if isinstance(row, dict)]
        if len(entries) != len(payload):
            report["issues"].append("Top-level list contains non-object rows.")
    else:
        report["issues"].append("Top-level payload must be a mapping or a list.")
        report["format_status"] = "invalid"
        return report, []

    row_issues, row_warnings = validate_manual_entries(key=key, entries=entries, review_index=review_index)
    report["issues"].extend(row_issues)
    report["warnings"].extend(row_warnings)
    report["actionable_count"] = len(entries)
    report["format_valid"] = not report["issues"]
    report["format_status"] = "valid" if report["format_valid"] else "invalid"
    if report["issues"]:
        report["content_assessment"] = "has_obvious_issues"
    elif not entries:
        report["warnings"].append("Actionable list is empty. Format is valid, but operator review is still required before rerun.")
        report["content_assessment"] = "human_review_required"
    elif report["warnings"]:
        report["content_assessment"] = "has_obvious_issues"
    else:
        report["content_assessment"] = "ready_for_operator_review"
    return report, entries


def validate_manual_entries(*, key: str, entries: list[dict[str, Any]], review_index: dict[str, Any]) -> tuple[list[str], list[str]]:
    issues: list[str] = []
    warnings: list[str] = []
    review_rows_available = bool(review_index["rows"])

    duplicate_labels = find_duplicate_entry_labels(key, entries)
    for label in duplicate_labels:
        issues.append(f"Duplicate entry detected: {label}")

    if key == "override_file":
        for index, entry in enumerate(entries, start=1):
            issue_id = text_or_none(entry.get("issue_id"))
            finding_id = text_or_none(entry.get("finding_id"))
            if not issue_id and not finding_id:
                issues.append(f"override[{index}] must include `issue_id` or `finding_id`.")
                continue
            if review_rows_available and issue_id and issue_id not in review_index["issue_ids"]:
                warnings.append(f"override[{index}] references issue_id `{issue_id}` that is not present in the current review_queue.")
            if review_rows_available and finding_id and finding_id not in review_index["finding_ids"]:
                warnings.append(f"override[{index}] references finding_id `{finding_id}` that is not present in the current review_queue.")

    if key == "suppression_file":
        match_fields = MANUAL_FILE_SPECS[key]["match_fields"]
        for index, entry in enumerate(entries, start=1):
            comparable = {field: text_or_none(entry.get(field)) for field in match_fields}
            if not any(comparable.values()):
                issues.append(
                    "suppression[{0}] has no matching criteria. Provide at least one of: {1}.".format(
                        index,
                        ", ".join(match_fields),
                    )
                )
                continue
            if any(comparable[field] for field in ("host", "path_pattern", "weakness_family", "primary_cwe")) and not suppression_matches_review_queue(comparable, review_index):
                warnings.append(
                    "suppression[{0}] does not match any current review_queue row by host/path_pattern/weakness_family/primary_cwe.".format(index)
                )

    if key == "review_resolution_file":
        for index, entry in enumerate(entries, start=1):
            issue_id = text_or_none(entry.get("issue_id"))
            if not issue_id:
                issues.append(f"review_resolutions[{index}] must include `issue_id`.")
                continue
            if review_rows_available and issue_id not in review_index["issue_ids"]:
                warnings.append(f"review_resolutions[{index}] references issue_id `{issue_id}` that is not present in the current review_queue.")
            resolution_status = str(entry.get("resolution_status") or "").lower()
            disposition = str(entry.get("disposition") or "").lower()
            if resolution_status in RESOLVED_REVIEW_STATUSES and disposition == "confirmed":
                if not entry.get("action_taken") and not entry.get("linked_override"):
                    warnings.append(
                        f"review_resolutions[{index}] is marked confirmed/resolved but has neither `action_taken` nor `linked_override`."
                    )
            if resolution_status in RESOLVED_REVIEW_STATUSES and disposition in NON_CLOSING_DISPOSITIONS:
                warnings.append(
                    f"review_resolutions[{index}] uses resolution_status=`{resolution_status}` with disposition=`{disposition or 'empty'}`; the queue will remain unresolved."
                )

    return issues, warnings


def cross_check_review_resolution(
    file_report: dict[str, Any],
    entries: list[dict[str, Any]],
    override_refs: set[str],
    suppression_refs: set[str],
) -> None:
    for index, entry in enumerate(entries, start=1):
        linked_override = text_or_none(entry.get("linked_override"))
        linked_suppression = text_or_none(entry.get("linked_suppression"))
        if linked_override and linked_override not in override_refs:
            file_report["warnings"].append(
                f"review_resolutions[{index}] links override `{linked_override}` but that identifier was not found in the override file."
            )
        if linked_suppression and linked_suppression not in suppression_refs:
            file_report["warnings"].append(
                f"review_resolutions[{index}] links suppression `{linked_suppression}` but that identifier was not found in the suppression file."
            )
    if file_report["format_valid"] and file_report["warnings"] and file_report["content_assessment"] == "ready_for_operator_review":
        file_report["content_assessment"] = "has_obvious_issues"


def describe_live_manual_selection(manual_dir: Path) -> dict[str, dict[str, Any]]:
    selection: dict[str, dict[str, Any]] = {}
    for key, patterns in MANUAL_SELECTION_RULES.items():
        candidates: list[dict[str, Any]] = []
        eligible_paths: list[Path] = []
        if manual_dir.exists():
            for path in sorted(manual_dir.iterdir(), key=lambda item: item.name.lower()):
                if not path.is_file():
                    continue
                evaluation = _evaluate_manual_candidate(path, patterns)
                candidates.append(evaluation)
                if evaluation["eligible"]:
                    eligible_paths.append(path)
        eligible_paths.sort(key=lambda item: (item.stat().st_mtime, item.stat().st_size, item.name.lower()), reverse=True)
        selected = eligible_paths[0] if eligible_paths else None
        selection[key] = {
            "manual_dir": str(manual_dir),
            "exists": manual_dir.exists(),
            "selected_path": str(selected) if selected else None,
            "eligible_candidate_count": len(eligible_paths),
            "eligible_candidates": [str(item) for item in eligible_paths],
            "candidate_count": len(candidates),
            "candidates": candidates,
        }
        if len(eligible_paths) > 1:
            selection[key]["note"] = "Multiple eligible live files were found. Auto-select will use the latest one."
    return selection


def build_review_index(rows: list[dict[str, Any]]) -> dict[str, Any]:
    review_rows = [row for row in rows if isinstance(row, dict)]
    return {
        "rows": review_rows,
        "issue_ids": {str(row.get("issue_id")) for row in review_rows if row.get("issue_id")},
        "finding_ids": {
            str(item)
            for row in review_rows
            for item in coerce_list(row.get("finding_ids"))
            if item not in {None, ""}
        },
    }


def collect_override_refs(entries: list[dict[str, Any]]) -> set[str]:
    refs: set[str] = set()
    for entry in entries:
        for key in ("issue_id", "finding_id"):
            value = text_or_none(entry.get(key))
            if value:
                refs.add(value)
    return refs


def collect_suppression_refs(entries: list[dict[str, Any]]) -> set[str]:
    refs: set[str] = set()
    for entry in entries:
        for key in ("id", "cluster_key", "title_regex"):
            value = text_or_none(entry.get(key))
            if value:
                refs.add(value)
    return refs


def suppression_matches_review_queue(comparable: dict[str, str | None], review_index: dict[str, Any]) -> bool:
    rows = review_index["rows"]
    if not rows:
        return True
    for row in rows:
        if comparable["host"] and comparable["host"] != text_or_none(row.get("host")):
            continue
        if comparable["path_pattern"] and comparable["path_pattern"] != text_or_none(row.get("path_pattern")):
            continue
        if comparable["weakness_family"] and comparable["weakness_family"] != text_or_none(row.get("weakness_family")):
            continue
        if comparable["primary_cwe"] and comparable["primary_cwe"] != text_or_none(row.get("primary_cwe")):
            continue
        return True
    return False


def find_duplicate_entry_labels(key: str, entries: list[dict[str, Any]]) -> list[str]:
    seen: set[str] = set()
    duplicates: list[str] = []
    for entry in entries:
        label = duplicate_label(key, entry)
        if not label:
            continue
        if label in seen and label not in duplicates:
            duplicates.append(label)
        seen.add(label)
    return duplicates


def duplicate_label(key: str, entry: dict[str, Any]) -> str:
    if key == "override_file":
        issue_id = text_or_none(entry.get("issue_id"))
        finding_id = text_or_none(entry.get("finding_id"))
        return issue_id or finding_id or ""
    if key == "review_resolution_file":
        return text_or_none(entry.get("issue_id")) or ""
    if key == "suppression_file":
        fields = MANUAL_FILE_SPECS[key]["match_fields"]
        values = [f"{field}={entry[field]}" for field in fields if text_or_none(entry.get(field))]
        return "|".join(values)
    return ""


def summarize_content_assessment(items: Any) -> str:
    assessments = [item["content_assessment"] for item in items]
    if "has_obvious_issues" in assessments:
        return "has_obvious_issues"
    if "human_review_required" in assessments:
        return "human_review_required"
    return "ready_for_operator_review"


def collect_blockers(artifacts: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    blockers: list[dict[str, str]] = []
    blockers.extend(load_message_rows("real_input_readiness", artifacts["real_input_readiness"]["data"], "blockers"))
    blockers.extend(load_message_rows("input_preflight", artifacts["input_preflight"]["data"], "blockers"))
    blockers.extend(load_check_rows("release_readiness", artifacts["release_readiness"]["data"], {"fail", "warn"}))
    blockers.extend(load_message_rows("submission_gate", artifacts["submission_gate"]["data"], "blocking_reasons"))
    blockers.extend(load_message_rows("submission_gate", artifacts["submission_gate"]["data"], "warning_reasons"))
    blockers.extend(load_message_rows("final_delivery_manifest", artifacts["final_delivery_manifest"]["data"], "blocking_reasons"))
    return dedupe_rows(blockers)


def collect_gate_failures(artifacts: dict[str, dict[str, Any]]) -> list[dict[str, str]]:
    failures: list[dict[str, str]] = []
    failures.extend(load_check_rows("release_readiness", artifacts["release_readiness"]["data"], {"fail", "warn"}))
    failures.extend(load_check_rows("submission_gate", artifacts["submission_gate"]["data"], {"fail", "warn"}))
    return dedupe_rows(failures)


def load_message_rows(source: str, payload: Any, key: str) -> list[dict[str, str]]:
    if not isinstance(payload, dict):
        return []
    return [{"source": source, "severity": "fact", "message": str(item)} for item in coerce_list(payload.get(key))]


def load_check_rows(source: str, payload: Any, severities: set[str]) -> list[dict[str, str]]:
    if not isinstance(payload, dict):
        return []
    rows: list[dict[str, str]] = []
    for item in payload.get("checks", []):
        if not isinstance(item, dict):
            continue
        result = str(item.get("result") or "").lower()
        if result not in severities:
            continue
        recommended_action = text_or_none(item.get("recommended_action"))
        message = item.get("name") or "unnamed_check"
        if recommended_action:
            message = f"{message}: {recommended_action}"
        rows.append({"source": source, "severity": result, "message": str(message)})
    return rows


def dedupe_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: set[tuple[str, str, str]] = set()
    deduped: list[dict[str, str]] = []
    for row in rows:
        key = (row.get("source", ""), row.get("severity", ""), row.get("message", ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)
    return deduped


def determine_rollup_status(snapshot: dict[str, Any]) -> str:
    if snapshot["blocked"]:
        return "blocked"
    if snapshot["fail"]:
        return "fail"
    if snapshot["pass"]:
        return "pass"
    if snapshot["ready"]:
        return "ready"
    return "warning"


def build_triage_hints(
    current_snapshot: dict[str, Any],
    worklist_rows: list[dict[str, Any]],
    manual_validation: dict[str, Any],
) -> list[dict[str, str]]:
    hints: list[dict[str, str]] = []
    if worklist_rows:
        top_bucket = max(summarize_worklist_buckets(worklist_rows).items(), key=lambda item: item[1])[0]
        hints.append(
            {
                "type": "worklist",
                "message": f"Unresolved review items are present. Start with `{bucket_to_working_file(top_bucket)}` for bucket `{top_bucket}`.",
            }
        )
    rerun_needed = not current_snapshot["final_ready"] and not current_snapshot["pass"]
    if rerun_needed and not manual_validation["rerun_live_context"]["format_valid"]:
        hints.append(
            {
                "type": "manual_validation",
                "message": "The live real/manual files are not structurally valid yet. Fix `manual_validation.md` findings before rerun.",
            }
        )
    elif rerun_needed and manual_validation["rerun_live_context"]["content_assessment"] != "ready_for_operator_review":
        hints.append(
            {
                "type": "manual_validation",
                "message": "Manual file structure is valid, but content still requires operator review before rerun.",
            }
        )
    if current_snapshot["blocked"]:
        hints.append(
            {
                "type": "rollup",
                "message": "The current run is blocked. Resolve blockers first, then rerun the rehearsal before expecting release artifacts.",
            }
        )
    elif current_snapshot["fail"]:
        hints.append(
            {
                "type": "rollup",
                "message": "The run reached release gating but still failed. Review gate failures and unresolved review items before rerun.",
            }
        )
    return hints


def summarize_worklist_buckets(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        bucket = str(row.get("suggested_action_bucket") or "manual_investigation")
        counts[bucket] = counts.get(bucket, 0) + 1
    return counts


def should_exit_non_zero(triage_report: dict[str, Any], manual_validation: dict[str, Any]) -> bool:
    flags = triage_report["state_flags"]
    if flags["blocked"] or flags["fail"]:
        return True
    if triage_report["worklist"]["unresolved_count"] > 0 and not flags["final_ready"]:
        return True
    rerun_live = manual_validation["rerun_live_context"]
    if not flags["pass"] and not flags["final_ready"] and not rerun_live["format_valid"]:
        return True
    if not flags["pass"] and rerun_live["content_assessment"] == "has_obvious_issues":
        return True
    return False


def render_post_run_triage_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Post-Run Triage",
        "",
        f"- run_root: `{report['run_root']}`",
        f"- baseline_run_root: `{report.get('baseline_run_root')}`",
        f"- rollup_status: `{report['rollup_status']}`",
        f"- blocked: `{report['state_flags']['blocked']}`",
        f"- fail: `{report['state_flags']['fail']}`",
        f"- pass: `{report['state_flags']['pass']}`",
        f"- ready: `{report['state_flags']['ready']}`",
        f"- final_ready: `{report['state_flags']['final_ready']}`",
        "",
        "## Hard Facts",
        f"- release_readiness_status: `{report['hard_facts']['release_readiness_status']}`",
        f"- submission_gate_status: `{report['hard_facts']['submission_gate_status']}`",
        f"- input_preflight_status: `{report['hard_facts']['input_preflight_status']}`",
        f"- real_input_readiness_status: `{report['hard_facts']['real_input_readiness_status']}`",
        f"- unresolved_review_items: `{report['hard_facts']['unresolved_review_items']}`",
    ]
    lines.extend(["", "## Missing Artifacts"])
    if report["hard_facts"]["missing_artifacts"]:
        lines.extend(f"- {item}" for item in report["hard_facts"]["missing_artifacts"])
    else:
        lines.append("- none")

    lines.extend(["", "## Blockers"])
    if report["hard_facts"]["blockers"]:
        lines.extend(
            f"- [{item['source']}/{item['severity']}] {item['message']}"
            for item in report["hard_facts"]["blockers"]
        )
    else:
        lines.append("- none")

    lines.extend(["", "## Gate Failures"])
    if report["hard_facts"]["gate_failures"]:
        lines.extend(
            f"- [{item['source']}/{item['severity']}] {item['message']}"
            for item in report["hard_facts"]["gate_failures"]
        )
    else:
        lines.append("- none")

    lines.extend(["", "## Triage Hints"])
    if report["triage_hints"]:
        lines.extend(f"- [{item['type']}] {item['message']}" for item in report["triage_hints"])
    else:
        lines.append("- none")

    lines.extend(["", "## Baseline Comparison"])
    baseline = report["baseline_comparison"]
    if not baseline["baseline_available"]:
        lines.append("- baseline comparison not available")
    else:
        lines.append(f"- baseline_exists: `{baseline['baseline_available']}`")
        for diff in baseline["status_differences"]:
            lines.append(
                f"- {diff['field']}: current=`{diff['current']}` | baseline=`{diff['baseline']}` | differs=`{diff['differs']}`"
            )
        for diff in baseline["artifact_differences"]:
            lines.append(
                f"- artifact `{diff['artifact']}`: current=`{diff['current']}` | baseline=`{diff['baseline']}` | differs=`{diff['differs']}`"
            )

    lines.extend(
        [
            "",
            "## Worklist",
            f"- unresolved_count: `{report['worklist']['unresolved_count']}`",
            f"- bucket_counts: `{report['worklist']['bucket_counts']}`",
            "- suggested_action_bucket is a triage hint, not an automated approval/suppression/closeout decision.",
            "",
            "| Work Item | Severity | Priority | Current Status | Suggested Bucket | Suggested Draft | Bucket Reason |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    if report["worklist"]["rows"]:
        for row in report["worklist"]["rows"]:
            lines.append(
                f"| {row['work_item_id']} | {row.get('severity_level') or '-'} | {row.get('priority_band') or '-'} "
                f"| {row.get('current_status') or '-'} | {row['suggested_action_bucket']} "
                f"| {row['suggested_working_file']} | {row['bucket_reason']} |"
            )
    else:
        lines.append("| - | - | - | - | no unresolved review items | - | - |")

    manual_validation = report["manual_validation"]
    lines.extend(
        [
            "",
            "## Manual Validation",
            f"- status: `{manual_validation['status']}`",
            f"- rerun_format_valid: `{manual_validation['format_valid_for_rerun']}`",
            f"- rerun_content_assessment: `{manual_validation['content_assessment_for_rerun']}`",
            f"- manual_validation_json: `{manual_validation['json_path']}`",
            f"- manual_validation_md: `{manual_validation['md_path']}`",
        ]
    )
    return "\n".join(lines) + "\n"


def render_manual_validation_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Manual Validation",
        "",
        f"- status: `{report['status']}`",
        f"- manual_dir: `{report['manual_dir']}`",
        f"- review_queue_reference_count: `{report['review_queue_reference_count']}`",
        f"- note: {report['note']}",
    ]
    for context_key in ("execution_context", "rerun_live_context"):
        context = report[context_key]
        lines.extend(
            [
                "",
                f"## {context['name']}",
                f"- description: {context['description']}",
                f"- required: `{context['required']}`",
                f"- format_valid: `{context['format_valid']}`",
                f"- content_assessment: `{context['content_assessment']}`",
            ]
        )
        for file_key, file_report in context["files"].items():
            lines.extend(
                [
                    "",
                    f"### {file_key}",
                    f"- path: `{file_report.get('path')}`",
                    f"- format_status: `{file_report.get('format_status')}`",
                    f"- format_valid: `{file_report.get('format_valid')}`",
                    f"- content_assessment: `{file_report.get('content_assessment')}`",
                    f"- actionable_count: `{file_report.get('actionable_count')}`",
                    f"- draft_candidate_count: `{file_report.get('draft_candidate_count')}`",
                ]
            )
            selection = file_report.get("selection") or {}
            if selection:
                lines.append(f"- eligible_candidate_count: `{selection.get('eligible_candidate_count', 0)}`")
                if selection.get("note"):
                    lines.append(f"- selection_note: {selection['note']}")
            if file_report["issues"]:
                lines.append("- issues:")
                lines.extend(f"  - {item}" for item in file_report["issues"])
            else:
                lines.append("- issues: none")
            if file_report["warnings"]:
                lines.append("- warnings:")
                lines.extend(f"  - {item}" for item in file_report["warnings"])
            else:
                lines.append("- warnings: none")
    return "\n".join(lines) + "\n"


def infer_workspace_root(run_root: Path) -> Path:
    for candidate in [run_root, *run_root.parents]:
        if (candidate / "app" / "vuln-pipeline").exists():
            return candidate
    return _workspace_root()


def resolve_baseline_run_root(*, run_root: Path, workspace_root: Path, baseline_run_root: Path | None) -> Path | None:
    if baseline_run_root:
        return baseline_run_root if baseline_run_root.exists() else None
    candidate = workspace_root / "outputs" / "runs" / DEFAULT_BASELINE_RUN_ID
    return candidate if candidate.exists() else None


def build_run_snapshot(run_root: Path | None, *, artifacts: dict[str, dict[str, Any]] | None = None) -> dict[str, Any] | None:
    if run_root is None or not run_root.exists():
        return None
    artifact_map = artifacts or load_run_artifacts(run_root)
    release = artifact_map["release_readiness"]["data"] if isinstance(artifact_map["release_readiness"]["data"], dict) else {}
    submission = artifact_map["submission_gate"]["data"] if isinstance(artifact_map["submission_gate"]["data"], dict) else {}
    preflight = artifact_map["input_preflight"]["data"] if isinstance(artifact_map["input_preflight"]["data"], dict) else {}
    readiness = artifact_map["real_input_readiness"]["data"] if isinstance(artifact_map["real_input_readiness"]["data"], dict) else {}
    final_manifest = (
        artifact_map["final_delivery_manifest"]["data"]
        if isinstance(artifact_map["final_delivery_manifest"]["data"], dict)
        else {}
    )
    review_closure = (
        artifact_map["review_closure_status"]["data"]
        if isinstance(artifact_map["review_closure_status"]["data"], dict)
        else {}
    )
    unresolved_review_items = (
        safe_int(review_closure.get("unresolved_review_items"))
        if review_closure
        else sum(1 for row in artifact_map["review_queue"]["rows"] if not row.get("is_resolved"))
    )
    customer_zip = find_latest_path(run_root / "delivery", "customer_submission_*.zip")
    internal_zip = find_latest_path(run_root / "delivery", "internal_archive_*.zip")
    blocked = (
        str(preflight.get("status") or "").lower() == "blocked"
        or str(readiness.get("status") or "").lower() == "blocked"
        or artifact_map["real_rehearsal_blocked"]["exists"]
    )
    fail = (
        str(release.get("status") or "").lower() in {"fail", "not_ready"}
        or str(submission.get("status") or "").lower() == "fail"
        or bool(final_manifest.get("blocking_reasons"))
    )
    return {
        "run_root": str(run_root),
        "release_readiness_status": str(release.get("status") or "missing"),
        "submission_gate_status": str(submission.get("status") or "missing"),
        "input_preflight_status": str(preflight.get("status") or "missing"),
        "real_input_readiness_status": str(readiness.get("status") or "missing"),
        "final_ready": bool(final_manifest.get("final_ready")),
        "unresolved_review_items": unresolved_review_items,
        "blocked": blocked,
        "fail": fail,
        "pass": str(submission.get("status") or "").lower() == "pass",
        "ready": str(release.get("status") or "").lower() == "ready",
        "artifact_presence": {
            name: item["exists"]
            for name, item in artifact_map.items()
            if name != "review_queue"
        }
        | {
            "review_queue": artifact_map["review_queue"]["exists"],
            "customer_submission_zip": bool(customer_zip),
            "internal_archive_zip": bool(internal_zip),
        },
    }


def build_baseline_comparison(current_snapshot: dict[str, Any], baseline_snapshot: dict[str, Any] | None) -> dict[str, Any]:
    if baseline_snapshot is None:
        return {
            "baseline_available": False,
            "baseline_run_root": None,
            "status_differences": [],
            "artifact_differences": [],
        }

    status_fields = [
        "release_readiness_status",
        "submission_gate_status",
        "input_preflight_status",
        "real_input_readiness_status",
        "final_ready",
        "unresolved_review_items",
    ]
    artifact_fields = sorted(
        set(current_snapshot["artifact_presence"].keys()) | set(baseline_snapshot["artifact_presence"].keys())
    )
    return {
        "baseline_available": True,
        "baseline_run_root": baseline_snapshot["run_root"],
        "status_differences": [
            {
                "field": field,
                "current": current_snapshot.get(field),
                "baseline": baseline_snapshot.get(field),
                "differs": current_snapshot.get(field) != baseline_snapshot.get(field),
            }
            for field in status_fields
        ],
        "artifact_differences": [
            {
                "artifact": field,
                "current": current_snapshot["artifact_presence"].get(field, False),
                "baseline": baseline_snapshot["artifact_presence"].get(field, False),
                "differs": current_snapshot["artifact_presence"].get(field, False)
                != baseline_snapshot["artifact_presence"].get(field, False),
            }
            for field in artifact_fields
        ],
    }


def load_run_artifacts(run_root: Path) -> dict[str, dict[str, Any]]:
    report_data = run_root / "report_data"
    deliverables = run_root / "deliverables"
    delivery = run_root / "delivery"
    review_queue_path = find_review_queue_path(run_root)

    return {
        "release_readiness": load_json_artifact(report_data / "release_readiness.json", required=True),
        "submission_gate": load_json_artifact(report_data / "submission_gate.json", required=True),
        "final_delivery_manifest": load_json_artifact(delivery / "final_delivery_manifest.json", required=True),
        "review_closure_status": load_json_artifact(report_data / "review_closure_status.json", required=True),
        "real_rehearsal_blocked": load_markdown_artifact(deliverables / "real_rehearsal_blocked.md", required=False),
        "release_readiness_summary": load_markdown_artifact(deliverables / "release_readiness_summary.md", required=False),
        "input_preflight": load_json_artifact(report_data / "input_preflight.json", required=False),
        "real_input_selection": load_json_artifact(report_data / "real_input_selection.json", required=True),
        "real_input_readiness": load_json_artifact(report_data / "real_input_readiness.json", required=False),
        "review_queue": load_review_queue_artifact(review_queue_path),
    }


def find_review_queue_path(run_root: Path) -> Path | None:
    report_data = run_root / "report_data"
    for name in REVIEW_QUEUE_CANDIDATES:
        candidate = report_data / name
        if candidate.exists():
            return candidate
    return None


def load_json_artifact(path: Path, *, required: bool) -> dict[str, Any]:
    artifact = {
        "path": str(path),
        "exists": path.exists(),
        "required": required,
        "type": "json",
        "data": None,
        "load_error": None,
    }
    if not path.exists():
        return artifact
    try:
        artifact["data"] = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        artifact["load_error"] = str(exc)
    return artifact


def load_markdown_artifact(path: Path, *, required: bool) -> dict[str, Any]:
    artifact = {
        "path": str(path),
        "exists": path.exists(),
        "required": required,
        "type": "markdown",
        "data": None,
        "load_error": None,
        "excerpt": [],
    }
    if not path.exists():
        return artifact
    try:
        content = path.read_text(encoding="utf-8")
        artifact["data"] = content
        artifact["excerpt"] = [line for line in content.splitlines() if line.strip()][:8]
    except Exception as exc:
        artifact["load_error"] = str(exc)
    return artifact


def load_review_queue_artifact(path: Path | None) -> dict[str, Any]:
    artifact = {
        "path": str(path) if path else None,
        "exists": bool(path and path.exists()),
        "required": True,
        "type": "review_queue",
        "rows": [],
        "load_error": None,
    }
    if path is None or not path.exists():
        return artifact
    try:
        artifact["rows"] = load_review_queue_rows(path)
    except Exception as exc:
        artifact["load_error"] = str(exc)
    return artifact


def resolve_execution_manual_paths(artifacts: dict[str, dict[str, Any]]) -> dict[str, Path | None]:
    resolved: dict[str, Path | None] = {}
    readiness = artifacts["real_input_readiness"]["data"] if isinstance(artifacts["real_input_readiness"]["data"], dict) else {}
    preflight = artifacts["input_preflight"]["data"] if isinstance(artifacts["input_preflight"]["data"], dict) else {}
    selection = artifacts["real_input_selection"]["data"] if isinstance(artifacts["real_input_selection"]["data"], dict) else {}
    readiness_manual = readiness.get("manual_support", {}) if isinstance(readiness, dict) else {}
    preflight_manual = preflight.get("manual_inputs", {}) if isinstance(preflight, dict) else {}
    selection_manual = selection.get("manual_resolution", {}) if isinstance(selection, dict) else {}
    for key in MANUAL_SELECTION_RULES:
        candidate = (
            text_or_none(nested_get(readiness_manual, key, "effective_execution_path"))
            or text_or_none(nested_get(preflight_manual, key, "effective_path"))
            or text_or_none(nested_get(preflight_manual, key, "configured_path"))
            or text_or_none(nested_get(selection_manual, key, "effective_path"))
            or text_or_none(nested_get(selection_manual, key, "configured_path"))
        )
        resolved[key] = Path(candidate) if candidate else None
    return resolved


def nested_get(payload: Any, *keys: str) -> Any:
    current = payload
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def find_latest_path(directory: Path, pattern: str) -> Path | None:
    if not directory.exists():
        return None
    matches = [path for path in directory.glob(pattern) if path.is_file()]
    if not matches:
        return None
    return sorted(matches, key=lambda item: (item.stat().st_mtime, item.name.lower()), reverse=True)[0]


def load_structured_payload(path: Path) -> Any:
    if path.suffix.lower() == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def coerce_list(value: Any) -> list[Any]:
    if value is None or value == "":
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text.startswith("[") and text.endswith("]"):
            try:
                parsed = yaml.safe_load(text)
                if isinstance(parsed, list):
                    return parsed
            except Exception:
                pass
        if ";" in text:
            return [item.strip() for item in text.split(";") if item.strip()]
        if "," in text:
            return [item.strip() for item in text.split(",") if item.strip()]
        return [text]
    return [value]


def parse_scalar_or_list(value: str | None) -> Any:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return ""
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = yaml.safe_load(text)
            if isinstance(parsed, list):
                return parsed
        except Exception:
            return text
    if text.isdigit():
        return int(text)
    if text.lower() in {"true", "false"}:
        return text.lower() == "true"
    return text


def type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, dict):
        return "dict"
    if isinstance(value, list):
        return "list"
    return type(value).__name__


def text_or_none(value: Any) -> str | None:
    if value is None or value == "":
        return None
    return str(value)


def safe_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
