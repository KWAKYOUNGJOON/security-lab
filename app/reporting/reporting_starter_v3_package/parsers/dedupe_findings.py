#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from common import load_json, safe_str, write_report

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
CONFIDENCE_ORDER = {"high": 3, "medium": 2, "low": 1}
DedupeKey = Tuple[str, str, str, str]


def default_dedupe_key(finding: Dict[str, Any]) -> DedupeKey:
    return (
        (safe_str(finding.get("title"), "") or "").lower(),
        (safe_str(finding.get("host"), "") or "").lower(),
        (safe_str(finding.get("url"), "") or "").lower(),
        (safe_str(finding.get("parameter"), "") or "").lower(),
    )


def choose_better(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    severity_a = SEVERITY_ORDER.get((safe_str(a.get("severity"), "info") or "info").lower(), 0)
    severity_b = SEVERITY_ORDER.get((safe_str(b.get("severity"), "info") or "info").lower(), 0)
    if severity_b > severity_a:
        return b
    if severity_a > severity_b:
        return a

    confidence_a = CONFIDENCE_ORDER.get((safe_str(a.get("confidence"), "low") or "low").lower(), 0)
    confidence_b = CONFIDENCE_ORDER.get((safe_str(b.get("confidence"), "low") or "low").lower(), 0)
    if confidence_b > confidence_a:
        return b
    return a


def dedupe_sequence(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped = []
    seen = set()
    for item in items:
        signature = (item.get("type"), item.get("content"), item.get("path"))
        if signature in seen:
            continue
        seen.add(signature)
        deduped.append(item)
    return deduped


def merge_metadata(primary: Dict[str, Any], secondary: Dict[str, Any]) -> Dict[str, Any]:
    merged = primary
    merged["tools"] = list(dict.fromkeys((primary.get("tools") or []) + (secondary.get("tools") or [])))
    merged["raw_source"] = list(dict.fromkeys((primary.get("raw_source") or []) + (secondary.get("raw_source") or [])))
    merged["evidence"] = dedupe_sequence((primary.get("evidence") or []) + (secondary.get("evidence") or []))

    references = dict(primary.get("references") or {})
    for key, values in (secondary.get("references") or {}).items():
        references[key] = list(dict.fromkeys((references.get(key) or []) + (values or [])))
    merged["references"] = references

    for key in ["severity_reason", "reproduction_steps", "recommendation"]:
        merged[key] = list(dict.fromkeys((primary.get(key) or []) + (secondary.get(key) or [])))

    if not merged.get("notes") and secondary.get("notes"):
        merged["notes"] = secondary["notes"]
    merged["manual_verified"] = bool(primary.get("manual_verified") or secondary.get("manual_verified"))
    if not merged.get("duplicate_group") and secondary.get("duplicate_group"):
        merged["duplicate_group"] = secondary["duplicate_group"]
    return merged


def merge_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    bucket: Dict[DedupeKey, Dict[str, Any]] = {}
    for finding in findings:
        key = default_dedupe_key(finding)
        if key not in bucket:
            bucket[key] = finding
            continue

        preferred = choose_better(bucket[key], finding)
        other = finding if preferred is bucket[key] else bucket[key]
        bucket[key] = merge_metadata(preferred, other)

    merged = list(bucket.values())
    for idx, finding in enumerate(merged, start=1):
        finding["id"] = f"WEB-{idx:03d}"
    return merged


def main() -> None:
    parser = argparse.ArgumentParser(description="기본 중복 제거 규칙을 적용합니다.")
    parser.add_argument("--input", required=True, help="입력 report JSON")
    parser.add_argument("--output", required=True, help="출력 report JSON")
    args = parser.parse_args()

    data = load_json(Path(args.input))
    if not isinstance(data, dict):
        raise SystemExit("입력 파일은 JSON 객체여야 합니다.")

    findings = data.get("findings") or []
    if not isinstance(findings, list):
        raise SystemExit("`findings`는 배열이어야 합니다.")

    data["findings"] = merge_findings([item for item in findings if isinstance(item, dict)])
    write_report(Path(args.output), data)
    print(f"[+] 중복 제거 완료: {args.output}")


if __name__ == "__main__":
    main()
