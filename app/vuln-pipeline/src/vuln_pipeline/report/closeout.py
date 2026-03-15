from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml


def load_review_resolutions(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    if path.suffix.lower() == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
    else:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        return payload.get("review_resolutions", [])
    if isinstance(payload, list):
        return payload
    return []


def apply_review_resolutions(
    review_queue: list[dict[str, Any]],
    resolutions: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    by_issue = {row["issue_id"]: row for row in review_queue}
    applied_rows: list[dict[str, Any]] = []
    for resolution in resolutions:
        issue_id = resolution.get("issue_id")
        if not issue_id or issue_id not in by_issue:
            continue
        row = by_issue[issue_id]
        row["resolution_status"] = resolution.get("resolution_status", "open")
        row["review_disposition"] = resolution.get("disposition")
        row["reviewer"] = resolution.get("reviewer")
        row["reviewed_at"] = resolution.get("reviewed_at")
        row["action_taken"] = resolution.get("action_taken")
        row["linked_override"] = resolution.get("linked_override")
        row["linked_suppression"] = resolution.get("linked_suppression")
        row["review_note"] = resolution.get("note")
        row["is_resolved"] = _is_resolved(row)
        row["approval_status"] = _approval_status(row)
        applied_rows.append({"issue_id": issue_id, "applied": resolution, "is_resolved": row["is_resolved"]})
    for row in review_queue:
        row.setdefault("resolution_status", "open")
        row.setdefault("review_disposition", None)
        row.setdefault("reviewer", None)
        row.setdefault("reviewed_at", None)
        row.setdefault("action_taken", None)
        row.setdefault("linked_override", None)
        row.setdefault("linked_suppression", None)
        row.setdefault("review_note", None)
        row.setdefault("is_resolved", False)
        row.setdefault("approval_status", _approval_status(row))
    summary = build_review_closure_status(review_queue)
    return review_queue, applied_rows, summary


def build_review_closure_status(review_queue: list[dict[str, Any]]) -> dict[str, Any]:
    unresolved = [row for row in review_queue if not row.get("is_resolved")]
    return {
        "total_review_items": len(review_queue),
        "unresolved_review_items": len(unresolved),
        "resolved_review_items": len(review_queue) - len(unresolved),
        "remaining_p1": sum(1 for row in unresolved if row.get("priority_band") == "P1"),
        "remaining_p2": sum(1 for row in unresolved if row.get("priority_band") == "P2"),
        "accepted_risk_items": sum(1 for row in review_queue if row.get("review_disposition") == "accepted_risk"),
        "deferred_items": sum(1 for row in review_queue if row.get("review_disposition") == "deferred"),
        "confirmed_items": sum(1 for row in review_queue if row.get("review_disposition") == "confirmed"),
        "needs_more_evidence_items": sum(1 for row in review_queue if row.get("review_disposition") == "needs_more_evidence"),
    }


def _is_resolved(row: dict[str, Any]) -> bool:
    status = str(row.get("resolution_status", "")).lower()
    disposition = str(row.get("review_disposition", "")).lower()
    if status not in {"resolved", "closed", "done", "approved"}:
        return False
    if disposition in {"deferred", "needs_more_evidence", ""}:
        return False
    if disposition == "confirmed":
        return bool(row.get("action_taken") or row.get("linked_override"))
    return True


def _approval_status(row: dict[str, Any]) -> str:
    if row.get("review_disposition") == "accepted_risk" and row.get("linked_suppression"):
        return "approved"
    if row.get("review_disposition") == "false_positive" and row.get("linked_override"):
        return "approved"
    if row.get("is_resolved"):
        return "closed"
    return "pending"
