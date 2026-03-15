from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from vuln_pipeline.cli.main import _workspace_root
from vuln_pipeline.cli.post_run_triage import (
    build_manual_validation_report,
    build_run_snapshot,
    collect_blockers,
    determine_rollup_status,
    load_run_artifacts,
)
from vuln_pipeline.storage import write_json, write_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare a previous run and a rerun using hard facts plus bounded inference.")
    parser.add_argument("--current-run-root", type=Path, required=True)
    parser.add_argument("--previous-run-root", type=Path, required=True)
    parser.add_argument("--manual-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--md-out", type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    current_run_root = Path(args.current_run_root).resolve()
    previous_run_root = Path(args.previous_run_root).resolve()
    workspace_root = infer_workspace_root(current_run_root)
    manual_dir = (
        Path(args.manual_dir).resolve()
        if args.manual_dir
        else workspace_root / "data" / "inputs" / "real" / "manual"
    )
    output_dir = Path(args.output_dir).resolve() if args.output_dir else current_run_root / "report_data"
    json_out = Path(args.json_out).resolve() if args.json_out else output_dir / "rerun_comparison.json"
    md_out = Path(args.md_out).resolve() if args.md_out else output_dir / "rerun_comparison.md"

    report = build_rerun_comparison(
        current_run_root=current_run_root,
        previous_run_root=previous_run_root,
        manual_dir=manual_dir,
    )
    write_json(json_out, report)
    write_markdown(md_out, render_rerun_comparison_markdown(report))
    print(f"rerun_comparison_json: {json_out}")
    print(f"rerun_comparison_md: {md_out}")
    return 0


def build_rerun_comparison(
    *,
    current_run_root: Path,
    previous_run_root: Path,
    manual_dir: Path,
) -> dict[str, Any]:
    current_artifacts = load_run_artifacts(current_run_root)
    previous_artifacts = load_run_artifacts(previous_run_root)
    current_snapshot = build_run_snapshot(current_run_root, artifacts=current_artifacts)
    previous_snapshot = build_run_snapshot(previous_run_root, artifacts=previous_artifacts)
    if current_snapshot is None or previous_snapshot is None:
        raise FileNotFoundError("Both current and previous run roots must exist.")

    current_validation = build_manual_validation_report(
        run_root=current_run_root,
        workspace_root=infer_workspace_root(current_run_root),
        manual_dir=manual_dir,
        review_queue_rows=current_artifacts["review_queue"]["rows"],
        artifacts=current_artifacts,
    )
    previous_validation = build_manual_validation_report(
        run_root=previous_run_root,
        workspace_root=infer_workspace_root(previous_run_root),
        manual_dir=manual_dir,
        review_queue_rows=previous_artifacts["review_queue"]["rows"],
        artifacts=previous_artifacts,
    )

    current_rollup = determine_rollup_status(current_snapshot)
    previous_rollup = determine_rollup_status(previous_snapshot)
    current_blocker_count = len(collect_blockers(current_artifacts))
    previous_blocker_count = len(collect_blockers(previous_artifacts))
    current_missing_artifacts = sorted(name for name, item in current_artifacts.items() if item["required"] and not item["exists"])
    previous_missing_artifacts = sorted(name for name, item in previous_artifacts.items() if item["required"] and not item["exists"])
    current_manual = summarize_manual_live_state(current_validation)
    previous_manual = summarize_manual_live_state(previous_validation)

    facts = {
        "rollup_status": compare_scalar(previous_rollup, current_rollup),
        "blocked": compare_scalar(previous_snapshot["blocked"], current_snapshot["blocked"]),
        "pass": compare_scalar(previous_snapshot["pass"], current_snapshot["pass"]),
        "ready": compare_scalar(previous_snapshot["ready"], current_snapshot["ready"]),
        "final_ready": compare_scalar(previous_snapshot["final_ready"], current_snapshot["final_ready"]),
        "blocker_count": compare_scalar(previous_blocker_count, current_blocker_count),
        "missing_artifact_count": compare_scalar(len(previous_missing_artifacts), len(current_missing_artifacts)),
        "missing_artifacts": compare_list(previous_missing_artifacts, current_missing_artifacts),
        "unresolved_review_items": compare_scalar(previous_snapshot["unresolved_review_items"], current_snapshot["unresolved_review_items"]),
        "customer_submission_zip": compare_scalar(
            previous_snapshot["artifact_presence"].get("customer_submission_zip", False),
            current_snapshot["artifact_presence"].get("customer_submission_zip", False),
        ),
        "internal_archive_zip": compare_scalar(
            previous_snapshot["artifact_presence"].get("internal_archive_zip", False),
            current_snapshot["artifact_presence"].get("internal_archive_zip", False),
        ),
        "manual_live": compare_manual_states(previous_manual, current_manual),
    }

    return {
        "previous_run_root": str(previous_run_root),
        "current_run_root": str(current_run_root),
        "manual_dir": str(manual_dir),
        "hard_facts": facts,
        "inference": build_inference(facts=facts, previous_rollup=previous_rollup, current_rollup=current_rollup),
        "previous_snapshot": current_plain(previous_snapshot),
        "current_snapshot": current_plain(current_snapshot),
    }


def render_rerun_comparison_markdown(report: dict[str, Any]) -> str:
    facts = report["hard_facts"]
    lines = [
        "# Rerun Comparison",
        "",
        f"- previous_run_root: `{report['previous_run_root']}`",
        f"- current_run_root: `{report['current_run_root']}`",
        f"- manual_dir: `{report['manual_dir']}`",
        "",
        "## Hard Facts",
        f"- rollup_status: previous=`{facts['rollup_status']['previous']}` current=`{facts['rollup_status']['current']}`",
        f"- blocked: previous=`{facts['blocked']['previous']}` current=`{facts['blocked']['current']}`",
        f"- pass: previous=`{facts['pass']['previous']}` current=`{facts['pass']['current']}`",
        f"- ready: previous=`{facts['ready']['previous']}` current=`{facts['ready']['current']}`",
        f"- final_ready: previous=`{facts['final_ready']['previous']}` current=`{facts['final_ready']['current']}`",
        f"- blocker_count: previous=`{facts['blocker_count']['previous']}` current=`{facts['blocker_count']['current']}` delta=`{facts['blocker_count']['delta']}`",
        f"- missing_artifact_count: previous=`{facts['missing_artifact_count']['previous']}` current=`{facts['missing_artifact_count']['current']}` delta=`{facts['missing_artifact_count']['delta']}`",
        f"- unresolved_review_items: previous=`{facts['unresolved_review_items']['previous']}` current=`{facts['unresolved_review_items']['current']}` delta=`{facts['unresolved_review_items']['delta']}`",
        f"- customer_submission_zip: previous=`{facts['customer_submission_zip']['previous']}` current=`{facts['customer_submission_zip']['current']}`",
        f"- internal_archive_zip: previous=`{facts['internal_archive_zip']['previous']}` current=`{facts['internal_archive_zip']['current']}`",
        "",
        "## Manual Live State",
        f"- overall_format_valid: previous=`{facts['manual_live']['overall_format_valid']['previous']}` current=`{facts['manual_live']['overall_format_valid']['current']}`",
        f"- overall_content_assessment: previous=`{facts['manual_live']['overall_content_assessment']['previous']}` current=`{facts['manual_live']['overall_content_assessment']['current']}`",
    ]
    if facts["manual_live"]["changed_files"]:
        for item in facts["manual_live"]["changed_files"]:
            lines.append(
                f"- {item['key']}: path_changed=`{item['path_changed']}` actionable_count=`{item['actionable_count']['previous']} -> {item['actionable_count']['current']}` format_valid=`{item['format_valid']['previous']} -> {item['format_valid']['current']}`"
            )
    else:
        lines.append("- no manual live file delta detected")
    lines.extend(["", "## Missing Artifact Delta"])
    if facts["missing_artifacts"]["changed"]:
        lines.append(f"- added: `{facts['missing_artifacts']['added']}`")
        lines.append(f"- removed: `{facts['missing_artifacts']['removed']}`")
    else:
        lines.append("- none")
    lines.extend(
        [
            "",
            "## Inference",
            f"- summary: `{report['inference']['summary']}`",
            f"- basis: {report['inference']['basis']}",
        ]
    )
    lines.extend(f"- evidence: {item}" for item in report["inference"]["evidence"])
    return "\n".join(lines) + "\n"


def infer_workspace_root(run_root: Path) -> Path:
    for candidate in [run_root, *run_root.parents]:
        if (candidate / "app" / "vuln-pipeline").exists():
            return candidate
    return _workspace_root()


def summarize_manual_live_state(report: dict[str, Any]) -> dict[str, Any]:
    rerun_context = report["rerun_live_context"]
    files: dict[str, Any] = {}
    for key, item in rerun_context["files"].items():
        files[key] = {
            "path": item.get("path"),
            "actionable_count": item.get("actionable_count", 0),
            "format_valid": item.get("format_valid", False),
            "content_assessment": item.get("content_assessment"),
        }
    return {
        "format_valid": rerun_context["format_valid"],
        "content_assessment": rerun_context["content_assessment"],
        "files": files,
    }


def compare_manual_states(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    changed_files: list[dict[str, Any]] = []
    for key in current["files"]:
        previous_file = previous["files"].get(key, {})
        current_file = current["files"].get(key, {})
        file_change = {
            "key": key,
            "path_changed": previous_file.get("path") != current_file.get("path"),
            "actionable_count": compare_scalar(previous_file.get("actionable_count", 0), current_file.get("actionable_count", 0)),
            "format_valid": compare_scalar(previous_file.get("format_valid", False), current_file.get("format_valid", False)),
            "content_assessment": compare_scalar(previous_file.get("content_assessment"), current_file.get("content_assessment")),
        }
        if (
            file_change["path_changed"]
            or file_change["actionable_count"]["changed"]
            or file_change["format_valid"]["changed"]
            or file_change["content_assessment"]["changed"]
        ):
            changed_files.append(file_change)
    return {
        "overall_format_valid": compare_scalar(previous["format_valid"], current["format_valid"]),
        "overall_content_assessment": compare_scalar(previous["content_assessment"], current["content_assessment"]),
        "changed_files": changed_files,
    }


def build_inference(*, facts: dict[str, Any], previous_rollup: str, current_rollup: str) -> dict[str, Any]:
    evidence: list[str] = []
    score = 0
    if previous_rollup != current_rollup:
        evidence.append(f"rollup_status changed from `{previous_rollup}` to `{current_rollup}`")
        if rank_rollup(current_rollup) > rank_rollup(previous_rollup):
            score += 2
        elif rank_rollup(current_rollup) < rank_rollup(previous_rollup):
            score -= 2
    if facts["blocker_count"]["delta"] < 0:
        evidence.append(f"blocker_count decreased by `{abs(facts['blocker_count']['delta'])}`")
        score += 1
    elif facts["blocker_count"]["delta"] > 0:
        evidence.append(f"blocker_count increased by `{facts['blocker_count']['delta']}`")
        score -= 1
    if facts["missing_artifact_count"]["delta"] < 0:
        evidence.append(f"missing_artifact_count decreased by `{abs(facts['missing_artifact_count']['delta'])}`")
        score += 1
    elif facts["missing_artifact_count"]["delta"] > 0:
        evidence.append(f"missing_artifact_count increased by `{facts['missing_artifact_count']['delta']}`")
        score -= 1
    if facts["unresolved_review_items"]["delta"] < 0:
        evidence.append(f"unresolved_review_items decreased by `{abs(facts['unresolved_review_items']['delta'])}`")
        score += 1
    elif facts["unresolved_review_items"]["delta"] > 0:
        evidence.append(f"unresolved_review_items increased by `{facts['unresolved_review_items']['delta']}`")
        score -= 1
    if facts["final_ready"]["previous"] is False and facts["final_ready"]["current"] is True:
        evidence.append("final_ready changed from false to true")
        score += 2
    if facts["customer_submission_zip"]["previous"] is False and facts["customer_submission_zip"]["current"] is True:
        evidence.append("customer_submission zip is present in the current run")
        score += 1
    if facts["internal_archive_zip"]["previous"] is False and facts["internal_archive_zip"]["current"] is True:
        evidence.append("internal_archive zip is present in the current run")
        score += 1

    if score > 0:
        summary = "improved"
    elif score < 0:
        summary = "regressed"
    else:
        summary = "no_material_change"
    return {
        "summary": summary,
        "basis": "This summary is an inference from hard-fact deltas; it is not an automated approval.",
        "evidence": evidence or ["No high-signal hard-fact delta was detected."],
    }


def compare_scalar(previous: Any, current: Any) -> dict[str, Any]:
    delta = None
    if isinstance(previous, (int, float)) and isinstance(current, (int, float)):
        delta = current - previous
    return {"previous": previous, "current": current, "changed": previous != current, "delta": delta}


def compare_list(previous: list[str], current: list[str]) -> dict[str, Any]:
    previous_set = set(previous)
    current_set = set(current)
    return {
        "previous": previous,
        "current": current,
        "added": sorted(current_set - previous_set),
        "removed": sorted(previous_set - current_set),
        "changed": previous != current,
    }


def rank_rollup(value: str) -> int:
    order = {"blocked": 0, "warning": 1, "fail": 2, "ready": 3, "pass": 4}
    return order.get(value, -1)


def current_plain(payload: dict[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(payload, ensure_ascii=False))


if __name__ == "__main__":
    raise SystemExit(main())
