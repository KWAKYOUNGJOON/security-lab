from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Dict

from parsers.common import load_json, safe_str, write_report
from parsers.severity_engine import normalize_severity

ALLOWED_OVERRIDE_FIELDS = {
    "title",
    "category",
    "severity",
    "confidence",
    "status",
    "description",
    "impact",
    "severity_reason",
    "reproduction_steps",
    "recommendation",
    "references",
    "manual_verified",
    "duplicate_group",
    "notes",
}


def load_override_file(path: Path | None) -> Dict[str, Any]:
    if path is None:
        return {}
    data = load_json(path)
    if not isinstance(data, dict):
        raise ValueError(f"override 파일은 JSON 객체여야 합니다: {path}")
    return data


def finding_matches(finding: Dict[str, Any], match: Dict[str, Any]) -> bool:
    for key, expected in match.items():
        actual = finding.get(key)
        if isinstance(expected, list):
            if list(actual or []) != expected:
                return False
            continue
        if safe_str(actual, "") != safe_str(expected, ""):
            return False
    return True


def apply_single_override(finding: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    updated = deepcopy(finding)
    for key, value in override.items():
        if key not in ALLOWED_OVERRIDE_FIELDS:
            continue
        if key == "severity":
            updated[key] = normalize_severity(value)
        else:
            updated[key] = value
    return updated


def apply_overrides(report: Dict[str, Any], override_data: Dict[str, Any]) -> Dict[str, Any]:
    if not override_data:
        return report

    updated = deepcopy(report)
    report_meta_override = override_data.get("report_meta")
    if isinstance(report_meta_override, dict):
        updated.setdefault("report_meta", {}).update(report_meta_override)

    finding_overrides = override_data.get("findings")
    if not isinstance(finding_overrides, list):
        return updated

    findings = []
    for finding in updated.get("findings", []):
        current = deepcopy(finding)
        for rule in finding_overrides:
            if not isinstance(rule, dict):
                continue
            match = rule.get("match")
            override = rule.get("override")
            if not isinstance(match, dict) or not isinstance(override, dict):
                continue
            if finding_matches(current, match):
                current = apply_single_override(current, override)
        findings.append(current)
    updated["findings"] = findings
    return updated


def apply_override_file(input_path: Path, output_path: Path, override_path: Path) -> None:
    report = load_json(input_path)
    override_data = load_override_file(override_path)
    write_report(output_path, apply_overrides(report, override_data))
