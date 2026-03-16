from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from vuln_pipeline.cli.main import _workspace_root
from vuln_pipeline.cli.post_run_triage import (
    MANUAL_FILE_SPECS,
    build_review_index,
    describe_live_manual_selection,
    load_review_queue_rows,
    load_structured_payload,
    text_or_none,
    validate_manual_context,
)
from vuln_pipeline.storage import write_json, write_markdown


DEFAULT_LIVE_FILENAMES = {
    "override_file": "customer_override.yaml",
    "suppression_file": "customer_suppressions.yaml",
    "review_resolution_file": "customer_review_resolution.yaml",
}
WORKING_NAME_TO_KEY = {
    "override_working.yaml": "override_file",
    "suppression_working.yaml": "suppression_file",
    "review_resolution_working.yaml": "review_resolution_file",
}
ALLOWED_WORKING_EXTRA_KEYS = {"draft_candidates", "notes", "bootstrap_metadata"}
ALLOWED_LIVE_EXTRA_KEYS = {"notes"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Plan or apply guarded promotion from working manual drafts into live real/manual files."
    )
    parser.add_argument("--working-dir", type=Path, required=True)
    parser.add_argument("--live-manual-dir", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--backup-dir", type=Path)
    parser.add_argument("--receipt-out", type=Path)
    parser.add_argument("--review-queue", type=Path)
    parser.add_argument("--run-root", type=Path)
    parser.add_argument("--workspace-root", type=Path, default=_workspace_root())
    parser.add_argument("--plan-only", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--allow-empty-explicit-seed", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    summary = execute_manual_promotion(
        working_dir=Path(args.working_dir).resolve(),
        live_manual_dir=(
            Path(args.live_manual_dir).resolve()
            if args.live_manual_dir
            else Path(args.workspace_root).resolve() / "data" / "inputs" / "real" / "manual"
        ),
        output_dir=Path(args.output_dir).resolve(),
        backup_dir=Path(args.backup_dir).resolve() if args.backup_dir else None,
        receipt_out=Path(args.receipt_out).resolve() if args.receipt_out else None,
        review_queue_path=Path(args.review_queue).resolve() if args.review_queue else None,
        run_root=Path(args.run_root).resolve() if args.run_root else None,
        workspace_root=Path(args.workspace_root).resolve(),
        plan_only=bool(args.plan_only or not args.apply),
        apply=bool(args.apply),
        overwrite=args.overwrite,
        allow_empty_explicit_seed=args.allow_empty_explicit_seed,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 1 if summary["status"] in {"blocked", "invalid"} else 0


def execute_manual_promotion(
    *,
    working_dir: Path,
    live_manual_dir: Path,
    output_dir: Path,
    backup_dir: Path | None,
    receipt_out: Path | None,
    review_queue_path: Path | None,
    run_root: Path | None,
    workspace_root: Path,
    plan_only: bool,
    apply: bool,
    overwrite: bool,
    allow_empty_explicit_seed: bool,
) -> dict[str, Any]:
    if plan_only and apply:
        raise ValueError("Choose either plan-only or apply mode, not both.")
    if not working_dir.exists():
        raise FileNotFoundError(f"Working directory does not exist: {working_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)
    live_manual_dir.mkdir(parents=True, exist_ok=True)

    resolved_review_queue = review_queue_path or ((run_root / "report_data" / "review_queue.jsonl") if run_root else None)
    review_rows = load_review_queue_rows(resolved_review_queue) if resolved_review_queue and resolved_review_queue.exists() else []
    review_index = build_review_index(review_rows)

    promotion_report = build_manual_promotion_report(
        working_dir=working_dir,
        live_manual_dir=live_manual_dir,
        output_dir=output_dir,
        review_index=review_index,
        overwrite=overwrite,
        workspace_root=workspace_root,
        review_queue_path=resolved_review_queue,
        run_root=run_root,
    )
    promotion_report["allow_empty_explicit_seed_requested"] = bool(allow_empty_explicit_seed)

    write_json(output_dir / "manual_promotion_plan.json", promotion_report)
    write_markdown(output_dir / "manual_promotion_plan.md", render_manual_promotion_markdown(promotion_report))

    if not apply:
        return promotion_report

    apply_summary = apply_manual_promotion(
        promotion_report=promotion_report,
        backup_dir=backup_dir or (output_dir / "backups"),
        receipt_out=receipt_out or (output_dir / "manual_promotion_receipt.json"),
        allow_empty_explicit_seed=allow_empty_explicit_seed,
    )
    write_markdown(output_dir / "manual_promotion_receipt.md", render_manual_promotion_receipt_markdown(apply_summary))
    return apply_summary


def build_manual_promotion_report(
    *,
    working_dir: Path,
    live_manual_dir: Path,
    output_dir: Path,
    review_index: dict[str, Any],
    overwrite: bool,
    workspace_root: Path,
    review_queue_path: Path | None,
    run_root: Path | None,
) -> dict[str, Any]:
    existing_selection = describe_live_manual_selection(live_manual_dir)
    file_reports: dict[str, dict[str, Any]] = {}
    staged_paths: dict[str, Path] = {}

    for working_name, key in WORKING_NAME_TO_KEY.items():
        file_report = build_file_promotion_report(
            key=key,
            working_path=working_dir / working_name,
            live_manual_dir=live_manual_dir,
            output_dir=output_dir,
            review_index=review_index,
            existing_selection=existing_selection.get(key, {}),
            overwrite=overwrite,
        )
        file_reports[key] = file_report
        staged_paths[key] = Path(file_report["staged_candidate_path"])

    validation = validate_manual_context(
        name="promotion_candidate_context",
        description="Staged live candidates generated from reviewed working drafts.",
        paths={key: staged_paths[key] for key in MANUAL_FILE_SPECS},
        review_index=review_index,
        required=True,
        selection_meta={key: {"selected_path": str(staged_paths[key])} for key in MANUAL_FILE_SPECS},
    )

    blockers: list[str] = []
    warnings: list[str] = []
    for key, item in file_reports.items():
        if item["status"] == "invalid":
            blockers.extend(f"{key}: {message}" for message in item["issues"])
        if item["existing_live"].get("unexpected_structure"):
            blockers.append(
                f"{key}: existing live file has unexpected keys/structure and promotion is blocked until it is reviewed."
            )
        if item["status"] == "human_selection_required":
            warnings.append(
                f"{key}: actionable list is empty while draft_candidates exist. Human selection is still required."
            )
        warnings.extend(f"{key}: {message}" for message in item["warnings"])

    if not validation["format_valid"]:
        blockers.append("staged promotion candidates failed manual validation; check manual_promotion_plan.md")
    elif validation["content_assessment"] != "ready_for_operator_review":
        warnings.append(
            "Staged promotion candidates are structurally valid, but content still needs operator review before rerun."
        )

    has_material_change = any(item["diff_summary"]["has_changes"] for item in file_reports.values())
    if not has_material_change:
        warnings.append("No actionable changes relative to the existing live files were detected.")

    if blockers:
        status = "blocked"
    elif any(item["status"] == "human_selection_required" for item in file_reports.values()) and not has_material_change:
        status = "human_selection_required"
    elif warnings:
        status = "ready_for_review"
    else:
        status = "ready_to_apply"

    return {
        "status": status,
        "mode": "plan",
        "generated_at": _timestamp(),
        "workspace_root": str(workspace_root),
        "working_dir": str(working_dir),
        "live_manual_dir": str(live_manual_dir),
        "output_dir": str(output_dir),
        "review_queue_path": str(review_queue_path) if review_queue_path else None,
        "run_root": str(run_root) if run_root else None,
        "overwrite_requested": overwrite,
        "allow_empty_explicit_seed_requested": False,
        "files": file_reports,
        "candidate_validation": validation,
        "status_flags": {
            "has_material_change": has_material_change,
            "has_human_selection_required": any(item["status"] == "human_selection_required" for item in file_reports.values()),
            "empty_explicit_seed_eligible": _is_empty_explicit_seed_eligible(file_reports),
        },
        "blockers": _dedupe_strings(blockers),
        "warnings": _dedupe_strings(warnings),
        "summary": {
            "material_change_file_count": sum(1 for item in file_reports.values() if item["diff_summary"]["has_changes"]),
            "actionable_entry_count": sum(item["candidate"]["actionable_count"] for item in file_reports.values()),
            "draft_candidate_count": sum(item["working"].get("draft_candidate_count", 0) for item in file_reports.values()),
        },
        "operator_guidance": [
            "draft_candidates are informational only and were not promoted automatically.",
            "Only the top-level actionable lists from the reviewed working drafts were staged.",
            "Apply mode stays blocked when staged candidates fail validation or when existing live files have unexpected structure.",
        ],
    }


def build_file_promotion_report(
    *,
    key: str,
    working_path: Path,
    live_manual_dir: Path,
    output_dir: Path,
    review_index: dict[str, Any],
    existing_selection: dict[str, Any],
    overwrite: bool,
) -> dict[str, Any]:
    spec = MANUAL_FILE_SPECS[key]
    working_summary = summarize_working_file(key=key, working_path=working_path)

    selected_live_path = Path(existing_selection["selected_path"]) if existing_selection.get("selected_path") else None
    target_path = selected_live_path or (live_manual_dir / DEFAULT_LIVE_FILENAMES[key])
    existing_live = summarize_live_file(key=key, live_path=target_path)

    staged_candidate = {spec["expected_key"]: working_summary["actionable_entries"]}
    staged_path = output_dir / f"{target_path.stem}_candidate.yaml"
    staged_path.write_text(yaml.safe_dump(staged_candidate, sort_keys=False, allow_unicode=True), encoding="utf-8")

    diff_summary = build_entry_diff_summary(
        key=key,
        before_entries=existing_live["entries"],
        after_entries=working_summary["actionable_entries"],
    )

    issues = list(working_summary["issues"])
    warnings = list(working_summary["warnings"])
    status = "ready_to_apply"
    if issues:
        status = "invalid"
    elif working_summary["actionable_count"] == 0 and working_summary["draft_candidate_count"] > 0:
        status = "human_selection_required"

    if existing_live["unexpected_structure"]:
        warnings.append(
            "Existing live file has unexpected keys/structure. Plan artifacts were generated, but apply will remain blocked."
        )
    if target_path.exists() and not diff_summary["has_changes"] and not overwrite:
        warnings.append("No material diff was detected against the existing live file.")
    if target_path.exists() and diff_summary["has_changes"] and not overwrite:
        warnings.append("Use --overwrite together with --apply when replacing an existing live file.")

    return {
        "key": key,
        "working_name": working_path.name,
        "status": status,
        "working": working_summary,
        "candidate": {
            "path": str(staged_path),
            "actionable_count": working_summary["actionable_count"],
            "hash": sha256_text(staged_path.read_text(encoding="utf-8")),
        },
        "existing_live": existing_live,
        "target_live_path": str(target_path),
        "staged_candidate_path": str(staged_path),
        "diff_summary": diff_summary,
        "issues": issues,
        "warnings": warnings,
        "overwrite_required": bool(target_path.exists()),
        "overwrite_requested": overwrite,
    }


def summarize_working_file(*, key: str, working_path: Path) -> dict[str, Any]:
    spec = MANUAL_FILE_SPECS[key]
    summary = {
        "path": str(working_path),
        "exists": working_path.exists(),
        "format_valid": False,
        "draft_candidate_count": 0,
        "actionable_count": 0,
        "actionable_entries": [],
        "issues": [],
        "warnings": [],
        "unexpected_keys": [],
    }
    if not working_path.exists():
        summary["issues"].append(f"Working draft file is missing: {working_path}")
        return summary

    try:
        payload = load_structured_payload(working_path)
    except Exception as exc:
        summary["issues"].append(f"Parse error: {exc}")
        return summary

    if not isinstance(payload, dict):
        summary["issues"].append("Working draft must be a mapping so draft_candidates stay metadata-only.")
        return summary

    expected_key = spec["expected_key"]
    unexpected_keys = sorted(set(payload.keys()) - {expected_key} - ALLOWED_WORKING_EXTRA_KEYS)
    summary["unexpected_keys"] = unexpected_keys
    if unexpected_keys:
        summary["warnings"].append(
            f"Unexpected working-draft keys were found and ignored for promotion: {', '.join(unexpected_keys)}"
        )
    if expected_key not in payload:
        summary["issues"].append(f"Top-level key `{expected_key}` is missing.")
        return summary
    if not isinstance(payload.get(expected_key), list):
        summary["issues"].append(f"Top-level key `{expected_key}` must be a list.")
        return summary

    entries = payload.get(expected_key, [])
    actionable_entries = [row for row in entries if isinstance(row, dict)]
    if len(actionable_entries) != len(entries):
        summary["issues"].append(f"`{expected_key}` contains non-object rows.")
    summary["draft_candidate_count"] = len(payload.get("draft_candidates", [])) if isinstance(payload.get("draft_candidates"), list) else 0
    summary["actionable_count"] = len(actionable_entries)
    summary["actionable_entries"] = actionable_entries
    summary["format_valid"] = not summary["issues"]
    return summary


def summarize_live_file(*, key: str, live_path: Path) -> dict[str, Any]:
    spec = MANUAL_FILE_SPECS[key]
    summary = {
        "path": str(live_path),
        "exists": live_path.exists(),
        "hash": sha256_file(live_path) if live_path.exists() else None,
        "entries": [],
        "entry_count": 0,
        "unexpected_keys": [],
        "unexpected_structure": False,
        "top_level_kind": None,
        "issues": [],
    }
    if not live_path.exists():
        return summary

    try:
        payload = load_structured_payload(live_path)
    except Exception as exc:
        summary["unexpected_structure"] = True
        summary["issues"].append(f"Parse error: {exc}")
        return summary

    summary["top_level_kind"] = type(payload).__name__
    if isinstance(payload, dict):
        unexpected_keys = sorted(set(payload.keys()) - {spec["expected_key"]} - ALLOWED_LIVE_EXTRA_KEYS)
        summary["unexpected_keys"] = unexpected_keys
        if unexpected_keys:
            summary["unexpected_structure"] = True
            summary["issues"].append(f"Unexpected keys: {', '.join(unexpected_keys)}")
        entries = payload.get(spec["expected_key"])
        if not isinstance(entries, list):
            summary["unexpected_structure"] = True
            summary["issues"].append(f"Top-level key `{spec['expected_key']}` must be a list.")
            return summary
    elif isinstance(payload, list):
        entries = payload
    else:
        summary["unexpected_structure"] = True
        summary["issues"].append("Top-level payload must be a mapping or a list.")
        return summary

    normalized_entries = [row for row in entries if isinstance(row, dict)]
    if len(normalized_entries) != len(entries):
        summary["unexpected_structure"] = True
        summary["issues"].append("Live payload contains non-object rows.")
    summary["entries"] = normalized_entries
    summary["entry_count"] = len(normalized_entries)
    return summary


def build_entry_diff_summary(*, key: str, before_entries: list[dict[str, Any]], after_entries: list[dict[str, Any]]) -> dict[str, Any]:
    before_map = {entry_identity(key, item): item for item in before_entries if entry_identity(key, item)}
    after_map = {entry_identity(key, item): item for item in after_entries if entry_identity(key, item)}

    changed: list[str] = []
    for identity in sorted(set(before_map) & set(after_map)):
        if canonical_json(before_map[identity]) != canonical_json(after_map[identity]):
            changed.append(identity)

    added = sorted(set(after_map) - set(before_map))
    removed = sorted(set(before_map) - set(after_map))
    return {
        "has_changes": bool(added or removed or changed),
        "before_count": len(before_entries),
        "after_count": len(after_entries),
        "added_count": len(added),
        "removed_count": len(removed),
        "changed_count": len(changed),
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def apply_manual_promotion(
    *,
    promotion_report: dict[str, Any],
    backup_dir: Path,
    receipt_out: Path,
    allow_empty_explicit_seed: bool,
) -> dict[str, Any]:
    blockers = list(promotion_report.get("blockers", []))
    empty_explicit_seed_eligible = bool(promotion_report.get("status_flags", {}).get("empty_explicit_seed_eligible"))
    allow_empty_seed_apply = bool(allow_empty_explicit_seed and empty_explicit_seed_eligible)
    if not promotion_report["status_flags"]["has_material_change"] and not allow_empty_seed_apply:
        blockers.append("No actionable live changes were detected.")
    for key, item in promotion_report["files"].items():
        if item["status"] == "invalid":
            blockers.append(f"{key}: staged working draft is invalid.")
        if item["status"] == "human_selection_required":
            blockers.append(f"{key}: draft_candidates still require manual promotion into the actionable list.")
        if item["existing_live"]["unexpected_structure"]:
            blockers.append(f"{key}: existing live file has unexpected structure.")
        if item["overwrite_required"] and not item["overwrite_requested"]:
            blockers.append(f"{key}: target live file already exists; rerun with --overwrite to replace it.")

    if blockers:
        blocked_report = dict(promotion_report)
        blocked_report["status"] = "blocked"
        blocked_report["mode"] = "apply"
        blocked_report["blockers"] = _dedupe_strings(blockers)
        return blocked_report

    backup_dir.mkdir(parents=True, exist_ok=True)
    receipts: list[dict[str, Any]] = []
    for key, item in promotion_report["files"].items():
        target_path = Path(item["target_live_path"])
        staged_path = Path(item["staged_candidate_path"])
        before_hash = sha256_file(target_path) if target_path.exists() else None
        backup_path = None
        if target_path.exists():
            backup_path = backup_dir / f"{target_path.name}.{datetime.now(tz=UTC).strftime('%Y%m%dT%H%M%SZ')}.bak"
            shutil.copy2(target_path, backup_path)
        atomic_copy(staged_path, target_path)
        after_hash = sha256_file(target_path)
        receipts.append(
            {
                "key": key,
                "source_working_path": item["working"]["path"],
                "candidate_path": str(staged_path),
                "before_path": str(target_path) if before_hash else None,
                "after_path": str(target_path),
                "backup_path": str(backup_path) if backup_path else None,
                "before_hash": before_hash,
                "after_hash": after_hash,
                "before_entry_count": item["diff_summary"]["before_count"],
                "after_entry_count": item["diff_summary"]["after_count"],
                "added_entry_count": item["diff_summary"]["added_count"],
                "removed_entry_count": item["diff_summary"]["removed_count"],
                "changed_entry_count": item["diff_summary"]["changed_count"],
                "timestamp": _timestamp(),
            }
        )

    receipt = {
        **promotion_report,
        "status": "applied",
        "mode": "apply",
        "allow_empty_explicit_seed_requested": bool(allow_empty_explicit_seed),
        "backup_dir": str(backup_dir),
        "receipt_path": str(receipt_out),
        "applied_files": receipts,
    }
    write_json(receipt_out, receipt)
    return receipt


def _is_empty_explicit_seed_eligible(file_reports: dict[str, dict[str, Any]]) -> bool:
    if not file_reports:
        return False
    for item in file_reports.values():
        if item.get("status") == "human_selection_required":
            return False
        if item.get("working", {}).get("actionable_count") != 0:
            return False
        if item.get("working", {}).get("draft_candidate_count") != 0:
            return False
        if item.get("existing_live", {}).get("exists"):
            return False
    return True


def render_manual_promotion_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Manual Promotion Plan",
        "",
        f"- status: `{report['status']}`",
        f"- working_dir: `{report['working_dir']}`",
        f"- live_manual_dir: `{report['live_manual_dir']}`",
        f"- output_dir: `{report['output_dir']}`",
        f"- review_queue_path: `{report.get('review_queue_path')}`",
        f"- material_change_file_count: `{report['summary']['material_change_file_count']}`",
        f"- actionable_entry_count: `{report['summary']['actionable_entry_count']}`",
        f"- allow_empty_explicit_seed_requested: `{report.get('allow_empty_explicit_seed_requested', False)}`",
        f"- empty_explicit_seed_eligible: `{report.get('status_flags', {}).get('empty_explicit_seed_eligible', False)}`",
        "",
        "## Blockers",
    ]
    if report["blockers"]:
        lines.extend(f"- {item}" for item in report["blockers"])
    else:
        lines.append("- none")
    lines.extend(["", "## Warnings"])
    if report["warnings"]:
        lines.extend(f"- {item}" for item in report["warnings"])
    else:
        lines.append("- none")

    lines.extend(["", "## File Plan"])
    for key, item in report["files"].items():
        lines.extend(
            [
                f"### {key}",
                f"- status: `{item['status']}`",
                f"- working_path: `{item['working']['path']}`",
                f"- target_live_path: `{item['target_live_path']}`",
                f"- staged_candidate_path: `{item['staged_candidate_path']}`",
                f"- existing_live_path: `{item['existing_live']['path']}`",
                f"- actionable_count: `{item['working']['actionable_count']}`",
                f"- draft_candidate_count: `{item['working']['draft_candidate_count']}`",
                f"- diff: added=`{item['diff_summary']['added_count']}` removed=`{item['diff_summary']['removed_count']}` changed=`{item['diff_summary']['changed_count']}`",
            ]
        )
        if item["existing_live"]["unexpected_structure"]:
            lines.append(f"- unexpected_live_structure: `{item['existing_live']['issues']}`")
        if item["issues"]:
            lines.append("- issues:")
            lines.extend(f"  - {message}" for message in item["issues"])
        if item["warnings"]:
            lines.append("- warnings:")
            lines.extend(f"  - {message}" for message in item["warnings"])

    lines.extend(
        [
            "",
            "## Candidate Validation",
            f"- format_valid: `{report['candidate_validation']['format_valid']}`",
            f"- content_assessment: `{report['candidate_validation']['content_assessment']}`",
            "",
            "## Guidance",
        ]
    )
    lines.extend(f"- {item}" for item in report["operator_guidance"])
    return "\n".join(lines) + "\n"


def render_manual_promotion_receipt_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Manual Promotion Receipt",
        "",
        f"- status: `{report['status']}`",
        f"- backup_dir: `{report.get('backup_dir')}`",
        f"- receipt_path: `{report.get('receipt_path')}`",
        "",
    ]
    for item in report.get("applied_files", []):
        lines.extend(
            [
                f"## {item['key']}",
                f"- source_working_path: `{item['source_working_path']}`",
                f"- after_path: `{item['after_path']}`",
                f"- backup_path: `{item['backup_path']}`",
                f"- before_hash: `{item['before_hash']}`",
                f"- after_hash: `{item['after_hash']}`",
                f"- added_entry_count: `{item['added_entry_count']}`",
                f"- removed_entry_count: `{item['removed_entry_count']}`",
                f"- changed_entry_count: `{item['changed_entry_count']}`",
            ]
        )
    return "\n".join(lines) + "\n"


def entry_identity(key: str, entry: dict[str, Any]) -> str:
    if key == "override_file":
        return text_or_none(entry.get("issue_id")) or text_or_none(entry.get("finding_id")) or ""
    if key == "review_resolution_file":
        return text_or_none(entry.get("issue_id")) or ""
    if key == "suppression_file":
        parts = []
        for field in MANUAL_FILE_SPECS[key]["match_fields"]:
            value = text_or_none(entry.get(field))
            if value:
                parts.append(f"{field}={value}")
        return "|".join(parts) or text_or_none(entry.get("id")) or ""
    return ""


def atomic_copy(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=target.parent, delete=False) as handle:
        handle.write(source.read_text(encoding="utf-8"))
        temp_path = Path(handle.name)
    temp_path.replace(target)


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _timestamp() -> str:
    return datetime.now(tz=UTC).replace(microsecond=0).isoformat()


def _dedupe_strings(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
