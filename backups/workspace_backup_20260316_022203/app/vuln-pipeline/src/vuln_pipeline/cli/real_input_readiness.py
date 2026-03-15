from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from vuln_pipeline.cli.main import _workspace_root
from vuln_pipeline.cli.scan_input_promotion import build_live_scan_inventory, render_live_inventory_markdown
from vuln_pipeline.parsers.real_inputs import (
    EXCLUDED_NAME_PARTS,
    MANUAL_INPUT_FLAGS,
    MANUAL_SELECTION_RULES,
    REAL_INPUT_RULES,
    _choose_source_directory,
    _evaluate_candidate,
    _evaluate_manual_candidate,
    auto_select_real_inputs,
    resolve_manual_input_paths,
)
from vuln_pipeline.report.operations import build_input_preflight, load_customer_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect phase12 real-input readiness using the pipeline's current auto-select logic."
    )
    parser.add_argument("--workspace-root", type=Path, default=_workspace_root())
    parser.add_argument("--customer-bundle", type=Path)
    parser.add_argument("--branding-file", type=Path)
    parser.add_argument("--readiness-policy", type=Path)
    parser.add_argument("--override-file", type=Path)
    parser.add_argument("--suppression-file", type=Path)
    parser.add_argument("--review-resolution-file", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--markdown-out", type=Path)
    return parser


def main() -> int:
    argv = sys.argv[1:]
    args = build_parser().parse_args(argv)
    report = build_readiness_report(args=args, argv=argv)
    markdown = render_markdown(report)
    print(markdown, end="")
    if args.json_out:
        _write_text(args.json_out, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        live_inventory_path = args.json_out.parent / "live_scan_inventory.json"
        _write_text(live_inventory_path, json.dumps(report["live_scan_inventory"], ensure_ascii=False, indent=2) + "\n")
    if args.markdown_out:
        _write_text(args.markdown_out, markdown)
        live_inventory_md = args.markdown_out.parent / "live_scan_inventory.md"
        _write_text(live_inventory_md, render_live_inventory_markdown(report["live_scan_inventory"]))
    return 1 if report["status"] == "blocked" else 0


def build_readiness_report(*, args: argparse.Namespace, argv: list[str]) -> dict[str, Any]:
    workspace_root = Path(args.workspace_root).resolve()
    app_root = workspace_root / "app" / "vuln-pipeline"
    defaults = _default_paths(workspace_root)
    explicit_flags = _explicit_flags(argv)

    customer_bundle = Path(args.customer_bundle or defaults["customer_bundle"])
    branding_file = Path(args.branding_file or defaults["branding_file"])
    readiness_policy = Path(args.readiness_policy or defaults["readiness_policy"])
    manual_defaults = {
        "override_file": Path(args.override_file or defaults["override_file"]),
        "suppression_file": Path(args.suppression_file or defaults["suppression_file"]),
        "review_resolution_file": Path(args.review_resolution_file or defaults["review_resolution_file"]),
    }

    real_root = workspace_root / "data" / "inputs" / "real"
    legacy_roots = {tool: workspace_root / "data" / "inputs" / tool for tool in REAL_INPUT_RULES}
    real_roots = {tool: real_root / tool for tool in REAL_INPUT_RULES}
    legacy_manual_dir = workspace_root / "data" / "inputs" / "manual"
    real_manual_dir = real_root / "manual"

    # Reuse the pipeline's current auto-selection and manual resolution logic to avoid rule drift.
    selected_inputs, selection, intake_manifest, input_hashes = auto_select_real_inputs(
        primary_roots=real_roots,
        fallback_roots=legacy_roots,
        primary_manual_dir=real_manual_dir,
        fallback_manual_dir=legacy_manual_dir,
        snapshot_root=None,
        stage_selected=False,
    )
    manual_inputs, manual_resolution = resolve_manual_input_paths(
        configured_manual_inputs=manual_defaults,
        default_manual_inputs=manual_defaults,
        explicit_flags=explicit_flags,
        auto_select_real_inputs=True,
        real_input_selection=selection,
        real_manual_dir=real_manual_dir,
        legacy_manual_dir=legacy_manual_dir,
    )
    selection["manual_resolution"] = manual_resolution

    preflight = build_input_preflight(
        explicit_inputs={tool: None for tool in REAL_INPUT_RULES},
        resolved_inputs=selected_inputs,
        roots=real_roots,
        manual_inputs=manual_inputs,
        manual_metadata=manual_resolution,
        auto_select_real_inputs=True,
    )

    config_checks = _build_config_checks(
        customer_bundle=customer_bundle,
        branding_file=branding_file,
        readiness_policy=readiness_policy,
        explicit_flags=explicit_flags,
        bundle=load_customer_bundle(customer_bundle if customer_bundle.exists() else None),
    )
    config_blockers = [item["blocker"] for item in config_checks.values() if item.get("blocker")]
    blockers = [*preflight.get("blockers", []), *config_blockers]
    warnings = list(preflight.get("warnings", []))

    tools = {
        tool: _build_tool_report(
            tool=tool,
            result=selection["tools"][tool],
            primary_dir=real_roots[tool],
            fallback_dir=legacy_roots[tool],
        )
        for tool in REAL_INPUT_RULES
    }
    manual_support = {
        key: _build_manual_report(
            key=key,
            result=selection["manual_support"][key],
            resolution=manual_resolution[key],
            primary_dir=real_manual_dir,
            fallback_dir=legacy_manual_dir,
        )
        for key in MANUAL_SELECTION_RULES
    }
    live_scan_inventory = build_live_scan_inventory(live_root=real_root)

    status = "blocked" if blockers else "warning" if warnings else "ready"
    return {
        "status": status,
        "workspace_root": str(workspace_root),
        "app_root": str(app_root),
        "selection_status": selection.get("status"),
        "selected_run_inputs": selection.get("selected_run_inputs", []),
        "real_scan_inputs_ready": any(selection["tools"][tool].get("selected_path") for tool in REAL_INPUT_RULES),
        "manual_sources_ready": bool(preflight.get("manual_sources_ready", False)),
        "blocker_count": len(blockers),
        "warning_count": len(warnings),
        "blockers": blockers,
        "warnings": warnings,
        "excluded_name_parts": list(EXCLUDED_NAME_PARTS),
        "preflight": preflight,
        "selection": selection,
        "input_intake_manifest": intake_manifest,
        "input_hashes": input_hashes,
        "config_checks": config_checks,
        "tools": tools,
        "manual_support": manual_support,
        "live_scan_inventory": live_scan_inventory,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Real Input Readiness",
        "",
        f"- status: `{report['status']}`",
        f"- selection_status: `{report.get('selection_status', 'unknown')}`",
        f"- real_scan_inputs_ready: `{report.get('real_scan_inputs_ready', False)}`",
        f"- manual_sources_ready: `{report.get('manual_sources_ready', False)}`",
        f"- blocker_count: `{report.get('blocker_count', 0)}`",
        f"- warning_count: `{report.get('warning_count', 0)}`",
        "",
        "## Config Checks",
    ]
    for key, item in report.get("config_checks", {}).items():
        lines.append(
            f"- {key}: exists=`{item.get('exists', False)}` "
            f"| effective_path=`{item.get('effective_path')}`"
        )
    lines.extend(["", "## Tool Selection"])
    for tool, item in report.get("tools", {}).items():
        lines.append(
            f"### {tool}\n"
            f"- selected_by_code: `{item.get('selected_path')}`\n"
            f"- source_priority: `{item.get('source_priority')}`\n"
            f"- reason: `{item.get('reason')}`"
        )
        for directory in item.get("directories", []):
            lines.append(
                f"- directory[{directory['source_category']}]: path=`{directory['path']}` "
                f"| exists=`{directory['exists']}` | visible_file_count=`{directory['visible_file_count']}` "
                f"| selected_by_code=`{directory['selected_by_code']}`"
            )
        for candidate in item.get("candidates", []):
            lines.append(
                f"- candidate[{candidate['source_category']}]: `{candidate['path']}` "
                f"| extension_ok=`{candidate['extension_ok']}` | size_ok=`{candidate['size_ok']}` "
                f"| excluded_name=`{candidate['excluded_name']}` | final_selected=`{candidate['final_selected']}` "
                f"| exclusion_reason=`{candidate['exclusion_reason']}`"
            )
        if not item.get("candidates"):
            lines.append("- candidate: none")
    lines.extend(["", "## Manual Support"])
    for key, item in report.get("manual_support", {}).items():
        lines.append(
            f"### {key}\n"
            f"- effective_execution_path: `{item.get('effective_execution_path')}`\n"
            f"- manual_source: `{item.get('manual_source')}`\n"
            f"- legacy_default: `{item.get('will_resolve_as_legacy_default')}`\n"
            f"- live_manual_source_ready: `{item.get('live_manual_source_ready')}`\n"
            f"- auto_selected_support_path: `{item.get('selected_support_path')}`"
        )
        for directory in item.get("directories", []):
            lines.append(
                f"- directory[{directory['source_category']}]: path=`{directory['path']}` "
                f"| exists=`{directory['exists']}` | visible_file_count=`{directory['visible_file_count']}` "
                f"| selected_by_code=`{directory['selected_by_code']}`"
            )
        for candidate in item.get("candidates", []):
            lines.append(
                f"- candidate[{candidate['source_category']}]: `{candidate['path']}` "
                f"| extension_ok=`{candidate['extension_ok']}` | name_pattern_ok=`{candidate['name_pattern_ok']}` "
                f"| excluded_name=`{candidate['excluded_name']}` | final_selected=`{candidate['final_selected']}` "
                f"| exclusion_reason=`{candidate['exclusion_reason']}`"
            )
        if not item.get("candidates"):
            lines.append("- candidate: none")
    lines.extend(
        [
            "",
            "## Live Scan Inventory",
            f"- status: `{report['live_scan_inventory']['status']}`",
            f"- active_valid_tool_count: `{report['live_scan_inventory']['hard_facts']['active_valid_tool_count']}`",
            f"- operational_goal_met: `{report['live_scan_inventory']['inference']['operational_goal_met']}`",
        ]
    )
    for tool, item in report["live_scan_inventory"]["tools"].items():
        lines.append(
            f"- live[{tool}]: active_file=`{item['active_file']}` | eligible_file_count=`{item['eligible_file_count']}`"
        )
    if report.get("blockers"):
        lines.extend(["", "## Blockers"])
        lines.extend(f"- {item}" for item in report["blockers"])
    if report.get("warnings"):
        lines.extend(["", "## Warnings"])
        lines.extend(f"- {item}" for item in report["warnings"])
    return "\n".join(lines) + "\n"


def _build_tool_report(*, tool: str, result: dict[str, Any], primary_dir: Path, fallback_dir: Path) -> dict[str, Any]:
    rule = REAL_INPUT_RULES[tool]
    source_info = _choose_source_directory(primary_dir, fallback_dir)
    candidates: list[dict[str, Any]] = []
    directories = [
        _describe_directory(primary_dir, "real", result.get("source_priority")),
        _describe_directory(fallback_dir, "legacy_fallback", result.get("source_priority")),
    ]
    for source_category, directory in (("real", primary_dir), ("legacy_fallback", fallback_dir)):
        candidates.extend(
            _normalize_scan_candidate(
                path=path,
                source_category=source_category,
                selected_path=result.get("selected_path"),
                source_priority=result.get("source_priority"),
                rule=rule,
            )
            for path in _sorted_files(directory)
        )
    return {
        "selected_path": result.get("selected_path"),
        "reason": result.get("reason"),
        "source_priority": source_info["source_priority"],
        "directories": directories,
        "candidates": candidates,
    }


def _build_manual_report(
    *,
    key: str,
    result: dict[str, Any],
    resolution: dict[str, Any],
    primary_dir: Path,
    fallback_dir: Path,
) -> dict[str, Any]:
    patterns = MANUAL_SELECTION_RULES[key]
    source_info = _choose_source_directory(primary_dir, fallback_dir)
    candidates: list[dict[str, Any]] = []
    directories = [
        _describe_directory(primary_dir, "real", result.get("source_priority")),
        _describe_directory(fallback_dir, "legacy_fallback", result.get("source_priority")),
    ]
    for source_category, directory in (("real", primary_dir), ("legacy_fallback", fallback_dir)):
        candidates.extend(
            _normalize_manual_candidate(
                path=path,
                source_category=source_category,
                selected_path=result.get("selected_path"),
                source_priority=result.get("source_priority"),
                patterns=patterns,
            )
            for path in _sorted_files(directory)
        )
    return {
        "selected_support_path": result.get("selected_path"),
        "support_reason": result.get("reason"),
        "support_source_priority": source_info["source_priority"],
        "configured_path": resolution.get("configured_path"),
        "effective_execution_path": resolution.get("effective_path"),
        "default_path": resolution.get("default_path"),
        "manual_source": resolution.get("manual_source"),
        "will_resolve_as_legacy_default": resolution.get("manual_source") == "legacy_default",
        "live_manual_source_ready": bool(resolution.get("exists")) and resolution.get("manual_source") == "real_explicit",
        "directories": directories,
        "candidates": candidates,
    }


def _build_config_checks(
    *,
    customer_bundle: Path,
    branding_file: Path,
    readiness_policy: Path,
    explicit_flags: set[str],
    bundle: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    bundle_branding = Path(bundle["branding_file"]) if bundle.get("branding_file") else None
    bundle_readiness = Path(bundle["readiness_policy"]) if bundle.get("readiness_policy") else None
    effective_branding = branding_file if "--branding-file" in explicit_flags or bundle_branding is None else bundle_branding
    effective_readiness = (
        readiness_policy if "--readiness-policy" in explicit_flags or bundle_readiness is None else bundle_readiness
    )
    checks = {
        "customer_bundle": {
            "configured_path": str(customer_bundle),
            "effective_path": str(customer_bundle),
            "exists": customer_bundle.exists(),
        },
        "branding_file": {
            "configured_path": str(branding_file),
            "bundle_path": str(bundle_branding) if bundle_branding else None,
            "effective_path": str(effective_branding),
            "exists": effective_branding.exists(),
        },
        "readiness_policy": {
            "configured_path": str(readiness_policy),
            "bundle_path": str(bundle_readiness) if bundle_readiness else None,
            "effective_path": str(effective_readiness),
            "exists": effective_readiness.exists(),
        },
    }
    for key, item in checks.items():
        if not item["exists"]:
            item["blocker"] = f"{key}: referenced file does not exist at `{item['effective_path']}`"
    return checks


def _normalize_scan_candidate(
    *,
    path: Path,
    source_category: str,
    selected_path: str | None,
    source_priority: str | None,
    rule: dict[str, Any],
) -> dict[str, Any]:
    evaluation = _evaluate_candidate(path, rule["extensions"], int(rule["minimum_size"]))
    extension_ok = path.suffix.lower() in rule["extensions"]
    size_ok = path.stat().st_size >= int(rule["minimum_size"])
    excluded_keywords = [item for item in EXCLUDED_NAME_PARTS if item in path.name.lower()]
    return {
        "path": str(path),
        "source_category": source_category,
        "extension": path.suffix.lower(),
        "size_bytes": path.stat().st_size,
        "minimum_size_bytes": int(rule["minimum_size"]),
        "modified_time": evaluation.get("modified_time"),
        "extension_ok": extension_ok,
        "size_ok": size_ok,
        "excluded_name": bool(excluded_keywords),
        "excluded_keywords": excluded_keywords,
        "eligible": bool(evaluation.get("eligible")),
        "final_selected": str(path) == selected_path,
        "reasons": list(evaluation.get("reasons", [])),
        "exclusion_reason": _candidate_reason(
            reasons=list(evaluation.get("reasons", [])),
            final_selected=str(path) == selected_path,
            source_category=source_category,
            source_priority=source_priority,
        ),
    }


def _normalize_manual_candidate(
    *,
    path: Path,
    source_category: str,
    selected_path: str | None,
    source_priority: str | None,
    patterns: tuple[str, ...],
) -> dict[str, Any]:
    evaluation = _evaluate_manual_candidate(path, patterns)
    lower_name = path.name.lower()
    extension_ok = path.suffix.lower() in {".yaml", ".yml", ".json"}
    excluded_keywords = [item for item in EXCLUDED_NAME_PARTS if item in lower_name]
    name_pattern_ok = any(pattern in lower_name for pattern in patterns)
    return {
        "path": str(path),
        "source_category": source_category,
        "extension": path.suffix.lower(),
        "size_bytes": path.stat().st_size,
        "modified_time": evaluation.get("modified_time"),
        "extension_ok": extension_ok,
        "name_pattern_ok": name_pattern_ok,
        "excluded_name": bool(excluded_keywords),
        "excluded_keywords": excluded_keywords,
        "eligible": bool(evaluation.get("eligible")),
        "final_selected": str(path) == selected_path,
        "reasons": list(evaluation.get("reasons", [])),
        "exclusion_reason": _candidate_reason(
            reasons=list(evaluation.get("reasons", [])),
            final_selected=str(path) == selected_path,
            source_category=source_category,
            source_priority=source_priority,
        ),
    }


def _candidate_reason(
    *,
    reasons: list[str],
    final_selected: bool,
    source_category: str,
    source_priority: str | None,
) -> str:
    if final_selected:
        return "selected_latest_eligible"
    if reasons and reasons != ["eligible"]:
        labels = {
            "unsupported_extension": "unsupported_extension",
            "excluded_name": "excluded_name",
            "below_minimum_size": "below_minimum_size",
            "name_pattern_mismatch": "name_pattern_mismatch",
        }
        return ",".join(labels.get(item, item) for item in reasons)
    if source_priority and source_priority != source_category:
        return f"directory_not_used_by_code:{source_priority}"
    return "newer_eligible_candidate_selected"


def _describe_directory(path: Path, source_category: str, selected_source: str | None) -> dict[str, Any]:
    files = _sorted_files(path)
    visible_files = [item for item in files if not item.name.startswith(".")]
    return {
        "source_category": source_category,
        "path": str(path),
        "exists": path.exists(),
        "file_count": len(files),
        "visible_file_count": len(visible_files),
        "selected_by_code": selected_source == source_category,
    }


def _sorted_files(path: Path) -> list[Path]:
    if not path.exists():
        return []
    files = [item for item in path.iterdir() if item.is_file()]
    return sorted(files, key=lambda item: (item.stat().st_mtime, item.stat().st_size, item.name.lower()), reverse=True)


def _explicit_flags(argv: list[str]) -> set[str]:
    return {token.split("=", 1)[0] for token in argv if token.startswith("--")}


def _default_paths(workspace_root: Path) -> dict[str, Path]:
    app_root = workspace_root / "app" / "vuln-pipeline"
    return {
        "customer_bundle": app_root / "configs" / "customer_bundles" / "default_customer_release.yaml",
        "branding_file": app_root / "configs" / "branding" / "customer_branding.yaml",
        "readiness_policy": app_root / "configs" / "readiness" / "customer_release.yaml",
        "override_file": workspace_root / "data" / "inputs" / "manual" / "sample_override.yaml",
        "suppression_file": workspace_root / "data" / "inputs" / "manual" / "suppressions.yaml",
        "review_resolution_file": workspace_root / "data" / "inputs" / "manual" / "review_resolution.yaml",
    }


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
