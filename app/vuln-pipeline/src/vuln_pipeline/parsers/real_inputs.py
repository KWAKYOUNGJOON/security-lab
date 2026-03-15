from __future__ import annotations

import hashlib
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REAL_INPUT_RULES: dict[str, dict[str, Any]] = {
    "burp": {
        "extensions": {".xml"},
        "minimum_size": 256,
    },
    "nuclei": {
        "extensions": {".json", ".jsonl"},
        "minimum_size": 128,
    },
    "httpx": {
        "extensions": {".jsonl"},
        "minimum_size": 128,
    },
}

EXCLUDED_NAME_PARTS = ("sample", "fixture", "test", "realish")
MANUAL_SELECTION_RULES: dict[str, tuple[str, ...]] = {
    "override_file": ("override",),
    "suppression_file": ("suppression", "suppress"),
    "review_resolution_file": ("review_resolution", "resolution", "closeout"),
}
MANUAL_INPUT_FLAGS: dict[str, str] = {
    "override_file": "--override-file",
    "suppression_file": "--suppression-file",
    "review_resolution_file": "--review-resolution-file",
}
TEXT_SCAN_SUFFIXES = {".md", ".markdown", ".json", ".txt", ".yaml", ".yml", ".csv"}
SNAPSHOT_SIZE_LIMIT_BYTES = 25 * 1024 * 1024


def auto_select_real_inputs(
    *,
    roots: dict[str, Path | None] | None = None,
    manual_dir: Path | None = None,
    primary_roots: dict[str, Path | None] | None = None,
    fallback_roots: dict[str, Path | None] | None = None,
    primary_manual_dir: Path | None = None,
    fallback_manual_dir: Path | None = None,
    snapshot_root: Path | None = None,
    stage_selected: bool = False,
) -> tuple[dict[str, list[Path]], dict[str, Any], dict[str, Any], dict[str, Any]]:
    legacy_mode = roots is not None and fallback_roots is None and snapshot_root is None and not stage_selected
    if roots is not None:
        primary_roots = roots
    if manual_dir is not None:
        primary_manual_dir = manual_dir
    primary_roots = primary_roots or {tool: None for tool in REAL_INPUT_RULES}
    selected_inputs: dict[str, list[Path]] = {tool: [] for tool in REAL_INPUT_RULES}
    selection: dict[str, Any] = {
        "status": "pending",
        "tools": {},
        "manual_support": {},
        "selected_run_inputs": [],
        "notes": [],
    }
    intake_entries: list[dict[str, Any]] = []

    for tool, rule in REAL_INPUT_RULES.items():
        source_info = _choose_source_directory(primary_roots.get(tool), (fallback_roots or {}).get(tool))
        result = _select_latest_candidate(tool, source_info["selected_directory"], rule)
        result["source_priority"] = source_info["source_priority"]
        result["fallback_available"] = source_info["fallback_available"]
        selection["tools"][tool] = result
        intake_entries.extend(
            _candidate_to_intake_entry(
                candidate,
                detected_tool=tool,
                selected_path=result.get("selected_path"),
                copied_or_referenced="referenced",
                snapshot_path=None,
                source_category=source_info["source_priority"],
            )
            for candidate in result["evaluated_candidates"]
        )
        if result["selected_path"]:
            path = Path(result["selected_path"])
            selected_inputs[tool] = [path]
            selection["selected_run_inputs"].append(str(path))

    manual_source = _choose_source_directory(primary_manual_dir, fallback_manual_dir)
    manual_selection = _select_manual_support(manual_source["selected_directory"])
    for key, result in manual_selection.items():
        result["source_priority"] = manual_source["source_priority"]
        result["fallback_available"] = manual_source["fallback_available"]
        intake_entries.extend(
            _candidate_to_intake_entry(
                candidate,
                detected_tool=key,
                selected_path=result.get("selected_path"),
                copied_or_referenced="referenced",
                snapshot_path=None,
                source_category=manual_source["source_priority"],
            )
            for candidate in result["evaluated_candidates"]
        )
    selection["manual_support"] = manual_selection

    if stage_selected and snapshot_root is not None:
        _apply_snapshot_to_entries(
            intake_entries=intake_entries,
            snapshot_root=snapshot_root,
            selected_paths=set(selection["selected_run_inputs"]) | {
                value["selected_path"]
                for value in manual_selection.values()
                if value.get("selected_path")
            },
        )

    selection["status"] = "selected" if any(selected_inputs.values()) else "incomplete"
    if not any(selected_inputs.values()):
        selection["notes"].append("No eligible real input files were found in the configured input directories.")
    if primary_manual_dir and not primary_manual_dir.exists() and fallback_manual_dir and not fallback_manual_dir.exists():
        selection["notes"].append("No manual input directory was found in either real or legacy locations.")

    intake_manifest = {
        "entries": intake_entries,
        "selected_run_inputs": selection["selected_run_inputs"],
        "selection_status": selection["status"],
        "stage_real_inputs": stage_selected,
        "snapshot_root": str(snapshot_root) if snapshot_root else None,
    }
    input_hashes = {
        "entries": [
            {
                "source_path": entry["source_path"],
                "sha256": entry["sha256"],
                "snapshot_path": entry["snapshot_path"],
                "selected_for_run": entry["selected_for_run"],
            }
            for entry in intake_entries
        ]
    }
    if legacy_mode:
        return selected_inputs, selection  # type: ignore[return-value]
    return selected_inputs, selection, intake_manifest, input_hashes


def build_input_intake_manifest(
    *,
    inputs: dict[str, list[Path]],
    manual_inputs: dict[str, Path | None],
    snapshot_root: Path | None = None,
    stage_selected: bool = False,
) -> tuple[dict[str, Any], dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    selected_paths: set[str] = set()
    for tool, paths in inputs.items():
        for path in paths:
            selected_paths.add(str(path))
            entries.append(_path_to_intake_entry(path=path, detected_tool=tool, selected_for_run=True))
    for key, path in manual_inputs.items():
        if path is None:
            continue
        selected_paths.add(str(path))
        entries.append(_path_to_intake_entry(path=path, detected_tool=key, selected_for_run=path.exists()))
    if stage_selected and snapshot_root is not None:
        _apply_snapshot_to_entries(intake_entries=entries, snapshot_root=snapshot_root, selected_paths=selected_paths)
    intake_manifest = {
        "entries": entries,
        "selected_run_inputs": sorted(selected_paths),
        "selection_status": "explicit_or_directory_ingest",
        "stage_real_inputs": stage_selected,
        "snapshot_root": str(snapshot_root) if snapshot_root else None,
    }
    input_hashes = {
        "entries": [
            {
                "source_path": entry["source_path"],
                "sha256": entry["sha256"],
                "snapshot_path": entry["snapshot_path"],
                "selected_for_run": entry["selected_for_run"],
            }
            for entry in entries
        ]
    }
    return intake_manifest, input_hashes


def render_real_input_selection_summary(selection: dict[str, Any], run_id: str | None = None) -> str:
    lines = ["# Real Data Rehearsal Summary", ""]
    if run_id:
        lines.append(f"- run_id: `{run_id}`")
    lines.append(f"- selection_status: `{selection.get('status', 'unknown')}`")
    lines.append("")
    lines.append("## Selected Inputs")
    selected_any = False
    for tool, result in selection.get("tools", {}).items():
        path = result.get("selected_path")
        if path:
            selected_any = True
            lines.append(f"- {tool}: `{path}` ({result.get('source_priority', 'unknown')})")
        else:
            lines.append(f"- {tool}: not selected ({result.get('reason', 'no eligible file')})")
    lines.append("")
    lines.append("## Manual Support Files")
    manual_any = False
    for key, value in selection.get("manual_support", {}).items():
        resolution = selection.get("manual_resolution", {}).get(key, {})
        if value.get("selected_path"):
            manual_any = True
            lines.append(
                f"- {key}: `{value['selected_path']}` ({value.get('source_priority', 'unknown')})"
                f" | manual_source=`{resolution.get('manual_source', 'unclassified')}`"
            )
        else:
            lines.append(
                f"- {key}: not selected ({value.get('reason', 'no eligible file')})"
                f" | manual_source=`{resolution.get('manual_source', 'unclassified')}`"
            )
    if not selected_any and not manual_any:
        lines.append("- No real input candidates were selected.")
    if selection.get("notes"):
        lines.extend(["", "## Notes"])
        lines.extend([f"- {note}" for note in selection["notes"]])
    return "\n".join(lines) + "\n"


def resolve_manual_input_paths(
    *,
    configured_manual_inputs: dict[str, Path | None],
    default_manual_inputs: dict[str, Path | None],
    explicit_flags: set[str],
    auto_select_real_inputs: bool,
    real_input_selection: dict[str, Any] | None,
    real_manual_dir: Path | None,
    legacy_manual_dir: Path | None,
) -> tuple[dict[str, Path | None], dict[str, dict[str, Any]]]:
    resolved_inputs: dict[str, Path | None] = {}
    resolution: dict[str, dict[str, Any]] = {}
    manual_support = (real_input_selection or {}).get("manual_support", {})

    for key in MANUAL_SELECTION_RULES:
        configured_path = configured_manual_inputs.get(key)
        default_path = default_manual_inputs.get(key)
        cli_explicit = MANUAL_INPUT_FLAGS[key] in explicit_flags
        support_info = manual_support.get(key, {})
        support_selected_path = support_info.get("selected_path")
        support_priority = support_info.get("source_priority")

        effective_path = configured_path
        manual_source = _classify_manual_source(
            path=configured_path,
            default_path=default_path,
            cli_explicit=cli_explicit,
            real_manual_dir=real_manual_dir,
            legacy_manual_dir=legacy_manual_dir,
        )
        if auto_select_real_inputs and not cli_explicit and support_selected_path and support_priority == "real":
            effective_path = Path(support_selected_path)
            manual_source = "real_explicit"

        resolved_inputs[key] = effective_path
        resolution[key] = {
            "configured_path": str(configured_path) if configured_path else None,
            "effective_path": str(effective_path) if effective_path else None,
            "default_path": str(default_path) if default_path else None,
            "exists": bool(effective_path and effective_path.exists()),
            "cli_explicit": cli_explicit,
            "manual_source": manual_source,
            "support_selected_path": support_selected_path,
            "support_source_priority": support_priority,
        }
    return resolved_inputs, resolution


def _choose_source_directory(primary: Path | None, fallback: Path | None) -> dict[str, Any]:
    primary_has_files = bool(primary and primary.exists() and any(item.is_file() and not item.name.startswith(".") for item in primary.iterdir()))
    fallback_has_files = bool(fallback and fallback.exists() and any(item.is_file() and not item.name.startswith(".") for item in fallback.iterdir()))
    if primary_has_files:
        return {
            "selected_directory": primary,
            "source_priority": "real",
            "fallback_available": fallback_has_files,
        }
    if fallback_has_files:
        return {
            "selected_directory": fallback,
            "source_priority": "legacy_fallback",
            "fallback_available": False,
        }
    return {
        "selected_directory": primary or fallback,
        "source_priority": "real" if primary else "legacy_fallback",
        "fallback_available": bool(fallback),
    }


def _classify_manual_source(
    *,
    path: Path | None,
    default_path: Path | None,
    cli_explicit: bool,
    real_manual_dir: Path | None,
    legacy_manual_dir: Path | None,
) -> str:
    if path is None:
        return "missing"
    if real_manual_dir and _is_relative_to(path, real_manual_dir):
        return "real_explicit"
    if legacy_manual_dir and _is_relative_to(path, legacy_manual_dir):
        if not cli_explicit and default_path and _same_path(path, default_path):
            return "legacy_default"
        return "legacy_explicit" if cli_explicit else "legacy_configured"
    return "explicit_nonreal" if cli_explicit else "configured_nonreal"


def _select_latest_candidate(tool: str, directory: Path | None, rule: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "directory": str(directory) if directory else None,
        "selected_path": None,
        "reason": "",
        "evaluated_candidates": [],
        "selection_rule": {
            "latest_modified_first": True,
            "minimum_size": rule["minimum_size"],
            "allowed_extensions": sorted(rule["extensions"]),
            "excluded_name_parts": list(EXCLUDED_NAME_PARTS),
        },
    }
    if directory is None:
        result["reason"] = "directory_not_configured"
        return result
    if not directory.exists():
        result["reason"] = "directory_not_found"
        return result

    candidates: list[Path] = []
    for path in directory.iterdir():
        if not path.is_file():
            continue
        evaluation = _evaluate_candidate(path, rule["extensions"], rule["minimum_size"])
        result["evaluated_candidates"].append(evaluation)
        if evaluation["eligible"]:
            candidates.append(path)

    if not candidates:
        result["reason"] = "no_eligible_candidates"
        return result

    candidates.sort(key=lambda item: (item.stat().st_mtime, item.stat().st_size, item.name.lower()), reverse=True)
    selected = candidates[0]
    result["selected_path"] = str(selected)
    result["selected_size"] = selected.stat().st_size
    result["selected_modified"] = _format_mtime(selected)
    result["reason"] = "selected_latest_eligible"
    return result


def _select_manual_support(manual_dir: Path | None) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for key, patterns in MANUAL_SELECTION_RULES.items():
        result = {
            "directory": str(manual_dir) if manual_dir else None,
            "selected_path": None,
            "reason": "",
            "evaluated_candidates": [],
        }
        results[key] = result
        if manual_dir is None:
            result["reason"] = "directory_not_configured"
            continue
        if not manual_dir.exists():
            result["reason"] = "directory_not_found"
            continue
        eligible: list[Path] = []
        for path in manual_dir.iterdir():
            if not path.is_file():
                continue
            evaluation = _evaluate_manual_candidate(path, patterns)
            result["evaluated_candidates"].append(evaluation)
            if evaluation["eligible"]:
                eligible.append(path)
        if not eligible:
            result["reason"] = "no_eligible_candidates"
            continue
        eligible.sort(key=lambda item: (item.stat().st_mtime, item.stat().st_size, item.name.lower()), reverse=True)
        selected = eligible[0]
        result["selected_path"] = str(selected)
        result["reason"] = "selected_latest_eligible"
    return results


def _evaluate_candidate(path: Path, extensions: set[str], minimum_size: int) -> dict[str, Any]:
    reasons: list[str] = []
    lower_name = path.name.lower()
    if path.suffix.lower() not in extensions:
        reasons.append("unsupported_extension")
    if any(part in lower_name for part in EXCLUDED_NAME_PARTS):
        reasons.append("excluded_name")
    if path.stat().st_size < minimum_size:
        reasons.append("below_minimum_size")
    return {
        "path": str(path),
        "eligible": not reasons,
        "reasons": reasons or ["eligible"],
        "size": path.stat().st_size,
        "modified_time": _format_mtime(path),
        "sha256": _sha256(path),
        "sample_like": any(part in lower_name for part in EXCLUDED_NAME_PARTS),
    }


def _evaluate_manual_candidate(path: Path, patterns: tuple[str, ...]) -> dict[str, Any]:
    reasons: list[str] = []
    lower_name = path.name.lower()
    if path.suffix.lower() not in {".yaml", ".yml", ".json"}:
        reasons.append("unsupported_extension")
    if any(part in lower_name for part in EXCLUDED_NAME_PARTS):
        reasons.append("excluded_name")
    if not any(pattern in lower_name for pattern in patterns):
        reasons.append("name_pattern_mismatch")
    return {
        "path": str(path),
        "eligible": not reasons,
        "reasons": reasons or ["eligible"],
        "size": path.stat().st_size,
        "modified_time": _format_mtime(path),
        "sha256": _sha256(path),
        "sample_like": any(part in lower_name for part in EXCLUDED_NAME_PARTS),
    }


def _candidate_to_intake_entry(
    candidate: dict[str, Any],
    *,
    detected_tool: str,
    selected_path: str | None,
    copied_or_referenced: str,
    snapshot_path: str | None,
    source_category: str,
) -> dict[str, Any]:
    rejection_reason = None if candidate["path"] == selected_path else ",".join(candidate.get("reasons", []))
    return {
        "source_path": candidate["path"],
        "selected_for_run": candidate["path"] == selected_path,
        "rejection_reason": rejection_reason,
        "detected_tool": detected_tool,
        "file_size": candidate.get("size", 0),
        "modified_time": candidate.get("modified_time"),
        "sha256": candidate.get("sha256", ""),
        "sample_like": candidate.get("sample_like", False),
        "copied_or_referenced": copied_or_referenced,
        "snapshot_path": snapshot_path,
        "source_category": source_category,
    }


def _path_to_intake_entry(path: Path, *, detected_tool: str, selected_for_run: bool) -> dict[str, Any]:
    exists = path.exists()
    return {
        "source_path": str(path),
        "selected_for_run": selected_for_run,
        "rejection_reason": None if selected_for_run and exists else "missing",
        "detected_tool": detected_tool,
        "file_size": path.stat().st_size if exists else 0,
        "modified_time": _format_mtime(path) if exists else None,
        "sha256": _sha256(path) if exists and path.is_file() else "",
        "sample_like": any(part in path.name.lower() for part in EXCLUDED_NAME_PARTS),
        "copied_or_referenced": "referenced",
        "snapshot_path": None,
        "source_category": "explicit_or_directory_ingest",
    }


def _apply_snapshot_to_entries(*, intake_entries: list[dict[str, Any]], snapshot_root: Path, selected_paths: set[str]) -> None:
    snapshot_root.mkdir(parents=True, exist_ok=True)
    for entry in intake_entries:
        if not entry["selected_for_run"] or entry["source_path"] not in selected_paths:
            continue
        source = Path(entry["source_path"])
        if not source.exists() or not source.is_file():
            entry["copied_or_referenced"] = "missing"
            continue
        target_dir = snapshot_root / entry["detected_tool"]
        target_dir.mkdir(parents=True, exist_ok=True)
        target = target_dir / source.name
        if source.stat().st_size > SNAPSHOT_SIZE_LIMIT_BYTES:
            entry["copied_or_referenced"] = "referenced_too_large"
            entry["snapshot_path"] = None
            continue
        if target.exists():
            target = target_dir / f"{source.stem}_{entry['sha256'][:8]}{source.suffix}"
        shutil.copy2(source, target)
        entry["copied_or_referenced"] = "copied"
        entry["snapshot_path"] = str(target)


def _format_mtime(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC).replace(microsecond=0).isoformat()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _same_path(left: Path, right: Path) -> bool:
    return left.resolve() == right.resolve()
