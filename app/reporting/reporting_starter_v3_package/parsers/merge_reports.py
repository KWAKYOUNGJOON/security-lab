#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List

from common import load_json, write_report


def merge_report_meta(base_meta: Dict[str, Any], new_meta: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base_meta)
    merged["assessment_scope"] = list(
        dict.fromkeys((base_meta.get("assessment_scope") or []) + (new_meta.get("assessment_scope") or []))
    )

    references = dict(base_meta.get("references") or {})
    references.update(new_meta.get("references") or {})
    merged["references"] = references

    for key in ["project_name", "target", "generated_at", "customer", "author", "template"]:
        if not merged.get(key) and new_meta.get(key):
            merged[key] = new_meta[key]

    return merged


def merge_reports(inputs: List[Path]) -> Dict[str, Any]:
    merged: Dict[str, Any] | None = None
    findings: List[Dict[str, Any]] = []

    for path in inputs:
        data = load_json(path)
        if not isinstance(data, dict):
            raise ValueError(f"입력 파일은 JSON 객체여야 합니다: {path}")

        report_meta = data.get("report_meta")
        if not isinstance(report_meta, dict):
            raise ValueError(f"`report_meta`가 누락되었거나 객체가 아닙니다: {path}")

        if merged is None:
            merged = {"report_meta": report_meta, "findings": []}
        else:
            merged["report_meta"] = merge_report_meta(merged["report_meta"], report_meta)

        input_findings = data.get("findings") or []
        if not isinstance(input_findings, list):
            raise ValueError(f"`findings`는 배열이어야 합니다: {path}")
        findings.extend(item for item in input_findings if isinstance(item, dict))

    if merged is None:
        raise ValueError("입력 파일이 없습니다.")

    for idx, finding in enumerate(findings, start=1):
        finding["id"] = f"WEB-{idx:03d}"

    merged["findings"] = findings
    return merged


def main() -> None:
    parser = argparse.ArgumentParser(description="여러 report JSON을 하나로 병합합니다.")
    parser.add_argument("--inputs", nargs="+", required=True, help="입력 JSON 파일 목록")
    parser.add_argument("--output", required=True, help="출력 JSON 파일")
    args = parser.parse_args()

    report = merge_reports([Path(item) for item in args.inputs])
    write_report(Path(args.output), report)
    print(f"[+] 병합 완료: {args.output}")


if __name__ == "__main__":
    main()
