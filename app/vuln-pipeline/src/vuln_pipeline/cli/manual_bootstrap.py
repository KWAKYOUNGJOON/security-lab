from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

from vuln_pipeline.cli.main import _workspace_root
from vuln_pipeline.cli.post_run_triage import build_triage_worklist, bucket_to_working_file, load_review_queue_rows


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create safe, non-live working drafts for real/manual override, suppression, and review resolution."
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--run-root", type=Path)
    parser.add_argument("--review-queue", type=Path)
    parser.add_argument("--workspace-root", type=Path, default=_workspace_root())
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    summary = build_manual_bootstrap(
        output_dir=Path(args.output_dir),
        run_root=Path(args.run_root).resolve() if args.run_root else None,
        review_queue_path=Path(args.review_queue).resolve() if args.review_queue else None,
        workspace_root=Path(args.workspace_root).resolve(),
        overwrite=args.overwrite,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


def build_manual_bootstrap(
    *,
    output_dir: Path,
    run_root: Path | None,
    review_queue_path: Path | None,
    workspace_root: Path,
    overwrite: bool,
) -> dict[str, Any]:
    templates_dir = workspace_root / "app" / "vuln-pipeline" / "docs" / "examples" / "real_manual_templates"
    resolved_review_queue = review_queue_path or ((run_root / "report_data" / "review_queue.jsonl") if run_root else None)
    review_rows = load_review_queue_rows(resolved_review_queue) if resolved_review_queue and resolved_review_queue.exists() else []
    unresolved_rows = [row for row in review_rows if not row.get("is_resolved")]
    triage_rows = build_triage_worklist(review_rows)
    triage_by_issue_id = {row.get("issue_id"): row for row in triage_rows if row.get("issue_id")}

    payloads = {
        "override_working.yaml": _build_override_payload(unresolved_rows, triage_by_issue_id),
        "suppression_working.yaml": _build_suppression_payload(unresolved_rows, triage_by_issue_id),
        "review_resolution_working.yaml": _build_review_resolution_payload(unresolved_rows, triage_by_issue_id),
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    written_files: list[str] = []
    for name, payload in payloads.items():
        template_path = templates_dir / name.replace("_working", "_template")
        base = yaml.safe_load(template_path.read_text(encoding="utf-8")) or {}
        merged = {
            **base,
            "bootstrap_metadata": {
                "source_run_root": str(run_root) if run_root else None,
                "source_review_queue": str(resolved_review_queue) if resolved_review_queue else None,
                "review_row_count": len(review_rows),
                "unresolved_row_count": len(unresolved_rows),
            },
            "draft_candidates": payload["draft_candidates"],
        }
        target = output_dir / name
        if target.exists() and not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing file: {target}")
        target.write_text(yaml.safe_dump(merged, sort_keys=False, allow_unicode=True), encoding="utf-8")
        written_files.append(str(target))

    bootstrap_worklist_path = output_dir / "bootstrap_worklist.md"
    bootstrap_worklist_path.write_text(render_bootstrap_worklist_markdown(triage_rows), encoding="utf-8")
    written_files.append(str(bootstrap_worklist_path))

    summary = {
        "output_dir": str(output_dir),
        "templates_dir": str(templates_dir),
        "source_run_root": str(run_root) if run_root else None,
        "source_review_queue": str(resolved_review_queue) if resolved_review_queue else None,
        "review_row_count": len(review_rows),
        "unresolved_row_count": len(unresolved_rows),
        "triage_bucket_counts": _bucket_counts(triage_rows),
        "written_files": written_files,
        "notes": [
            "The generated files are safe by default because overrides, suppressions, and review_resolutions stay empty.",
            "Move only reviewed rows from draft_candidates into the actionable top-level list before using them as live manual inputs.",
            "bootstrap_worklist.md maps triage buckets to the working draft file that should be reviewed first.",
        ],
    }
    (output_dir / "bootstrap_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return summary


def _build_override_payload(rows: list[dict[str, Any]], triage_by_issue_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for row in rows:
        triage_hint = _triage_hint(row, triage_by_issue_id)
        candidates.append(
            {
                "issue_id": row.get("issue_id"),
                "override_title": None,
                "override_primary_cwe": None,
                "override_severity_score": None,
                "override_severity_level": None,
                "override_confidence": None,
                "recommended_owner": None,
                "target_due": None,
                "false_positive": None,
                "manual_remediation": [],
                "analyst_note": None,
                "triage_hint": triage_hint,
                "draft_context": {
                    "finding_ids": row.get("finding_ids", []),
                    "priority_band": row.get("priority_band"),
                    "review_reason": row.get("review_reason", []),
                    "recommended_action": row.get("recommended_action"),
                },
            }
        )
    return {"draft_candidates": candidates}


def _build_suppression_payload(rows: list[dict[str, Any]], triage_by_issue_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for row in rows:
        triage_hint = _triage_hint(row, triage_by_issue_id)
        candidates.append(
            {
                "id": f"candidate-{row.get('issue_id', 'unknown')}",
                "cluster_key": None,
                "host": row.get("host"),
                "path_pattern": row.get("path_pattern"),
                "weakness_family": row.get("weakness_family"),
                "primary_cwe": row.get("primary_cwe"),
                "title_regex": None,
                "status": "accepted_risk",
                "note": "Move into suppressions only after analyst approval.",
                "triage_hint": triage_hint,
                "draft_context": {
                    "issue_id": row.get("issue_id"),
                    "priority_band": row.get("priority_band"),
                    "recommended_action": row.get("recommended_action"),
                },
            }
        )
    return {"draft_candidates": candidates}


def _build_review_resolution_payload(rows: list[dict[str, Any]], triage_by_issue_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for row in rows:
        triage_hint = _triage_hint(row, triage_by_issue_id)
        candidates.append(
            {
                "issue_id": row.get("issue_id"),
                "resolution_status": "open",
                "disposition": "needs_more_evidence",
                "reviewer": None,
                "reviewed_at": None,
                "action_taken": None,
                "linked_override": None,
                "linked_suppression": None,
                "note": row.get("recommended_action"),
                "triage_hint": triage_hint,
                "draft_context": {
                    "priority_band": row.get("priority_band"),
                    "review_reason": row.get("review_reason", []),
                },
            }
        )
    return {"draft_candidates": candidates}


def _triage_hint(row: dict[str, Any], triage_by_issue_id: dict[str, dict[str, Any]]) -> dict[str, Any]:
    triage_row = triage_by_issue_id.get(row.get("issue_id"), {})
    bucket = triage_row.get("suggested_action_bucket", "manual_investigation")
    return {
        "suggested_action_bucket": bucket,
        "suggested_working_file": triage_row.get("suggested_working_file", bucket_to_working_file(bucket)),
        "bucket_reason": triage_row.get("bucket_reason"),
        "recommended_action": triage_row.get("recommended_action") or row.get("recommended_action"),
    }


def _bucket_counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        bucket = str(row.get("suggested_action_bucket") or "manual_investigation")
        counts[bucket] = counts.get(bucket, 0) + 1
    return counts


def render_bootstrap_worklist_markdown(rows: list[dict[str, Any]]) -> str:
    lines = [
        "# Bootstrap Worklist",
        "",
        "- suggested_action_bucket is a triage hint only. It does not move any row into live manual inputs.",
        "- Review the working draft named in `suggested_working_file` first, then decide whether anything should move from `draft_candidates` into the actionable list.",
        "- Promotion helper reads only the top-level actionable list: `overrides`, `suppressions`, or `review_resolutions`.",
        "- `draft_candidates` stays informational until a human copies selected rows into the matching actionable list.",
        "- Recommended next step after editing: `python -m vuln_pipeline.cli.manual_promotion --working-dir <draft-dir> --output-dir <plan-dir> --plan-only`",
        "",
    ]
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(str(row.get("suggested_action_bucket") or "manual_investigation"), []).append(row)

    if not grouped:
        lines.append("- No unresolved review_queue rows were available.")
        return "\n".join(lines) + "\n"

    for bucket in (
        "needs_override_review",
        "needs_review_resolution",
        "candidate_for_suppression_review",
        "manual_investigation",
    ):
        bucket_rows = grouped.get(bucket, [])
        if not bucket_rows:
            continue
        lines.extend([f"## {bucket}", f"- suggested_working_file: `{bucket_to_working_file(bucket)}`"])
        actionable_key = {
            "needs_override_review": "overrides",
            "needs_review_resolution": "review_resolutions",
            "candidate_for_suppression_review": "suppressions",
            "manual_investigation": "review_resolutions",
        }.get(bucket, "review_resolutions")
        lines.append(f"- fill_this_actionable_list: `{actionable_key}`")
        for row in bucket_rows:
            lines.append(
                f"- {row.get('work_item_id')}: severity=`{row.get('severity_level')}` priority=`{row.get('priority_band')}` "
                f"reason=`{row.get('bucket_reason')}`"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
